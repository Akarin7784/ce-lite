//! Windows 调试器后端（M3 子集 + 硬件监视点）。
//!
//! 能力：附加调试、软件断点（INT3）、硬件监视点（DR0-DR7）、寄存器读写、等待/继续。
//! 软件断点：INT3 补丁 + 还原原字节 + TF 单步重打。
//! 硬件监视点：利用 x64 调试寄存器，命中后触发 `EXCEPTION_SINGLE_STEP`，由 DR6 判定槽位。

use std::collections::HashMap;
use std::mem::size_of;
use std::os::raw::c_void;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use ce_core::{Address, DebugEvent, Registers, StackFrame};

use windows::Win32::Foundation::{
    CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, EXCEPTION_ACCESS_VIOLATION,
    EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP, HANDLE,
};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, DebugSetProcessKillOnExit,
    GetThreadContext, ReadProcessMemory, SetThreadContext, WaitForDebugEvent, WriteProcessMemory,
    CONTEXT, CONTEXT_CONTROL_AMD64, CONTEXT_DEBUG_REGISTERS_AMD64, CONTEXT_INTEGER_AMD64,
    DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_PROTECTION_FLAGS};
use windows::Win32::System::Threading::{
    OpenProcess, OpenThread, ResumeThread, SuspendThread, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, THREAD_GET_CONTEXT,
    THREAD_QUERY_INFORMATION, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
};

const INT3: u8 = 0xCC;
const TRAP_FLAG: u32 = 0x100;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// Wow64 进程里 32 位代码的断点/单步异常码（64 位内核转换后上报）。
const STATUS_WX86_BREAKPOINT: i32 = 0x4000_001F;
const STATUS_WX86_SINGLE_STEP: i32 = 0x4000_001E;

// ---- Wow64（32 位目标）支持 ----

/// i386 CONTEXT 结构（Windows 头文件布局；仅声明调试器需要的字段）。
#[repr(C)]
struct WOW64_CONTEXT {
    context_flags: u32,
    dr0: u32,
    dr1: u32,
    dr2: u32,
    dr3: u32,
    dr6: u32,
    dr7: u32,
    float_save: [u8; 112],
    seg_gs: u32,
    seg_fs: u32,
    seg_es: u32,
    seg_ds: u32,
    edi: u32,
    esi: u32,
    ebx: u32,
    edx: u32,
    ecx: u32,
    eax: u32,
    ebp: u32,
    eip: u32,
    seg_cs: u32,
    eflags: u32,
    esp: u32,
    seg_ss: u32,
    extended_registers: [u8; 512],
}

const WOW64_CONTEXT_I386: u32 = 0x0001_0000;
const WOW64_CONTEXT_CONTROL: u32 = 0x01;
const WOW64_CONTEXT_INTEGER: u32 = 0x02;
const WOW64_CONTEXT_DEBUG_REGISTERS: u32 = 0x10;

// windows crate 未绑定 Wow64 API；kernel32 直接声明。
#[link(name = "kernel32")]
unsafe extern "system" {
    fn Wow64GetThreadContext(hthread: HANDLE, lpcontext: *mut WOW64_CONTEXT) -> i32;
    fn Wow64SetThreadContext(hthread: HANDLE, lpcontext: *const WOW64_CONTEXT) -> i32;
}

/// 读取 32 位线程上下文（含 DR 寄存器）。
fn get_wow64_context(thread: HANDLE) -> Result<WOW64_CONTEXT, String> {
    let mut ctx: WOW64_CONTEXT = unsafe { std::mem::zeroed() };
    ctx.context_flags = WOW64_CONTEXT_I386
        | WOW64_CONTEXT_CONTROL
        | WOW64_CONTEXT_INTEGER
        | WOW64_CONTEXT_DEBUG_REGISTERS;
    let rc = unsafe { Wow64GetThreadContext(thread, &mut ctx) };
    if rc == 0 {
        return Err("Wow64GetThreadContext failed".to_string());
    }
    Ok(ctx)
}

/// 32 位上下文 → 统一 64 位 CONTEXT（低 32 位有效）。
fn wow64_to_ctx(w: &WOW64_CONTEXT) -> CONTEXT {
    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.ContextFlags = CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64 | CONTEXT_DEBUG_REGISTERS_AMD64;
    ctx.Rip = w.eip as u64;
    ctx.Rax = w.eax as u64;
    ctx.Rbx = w.ebx as u64;
    ctx.Rcx = w.ecx as u64;
    ctx.Rdx = w.edx as u64;
    ctx.Rsi = w.esi as u64;
    ctx.Rdi = w.edi as u64;
    ctx.Rsp = w.esp as u64;
    ctx.Rbp = w.ebp as u64;
    ctx.EFlags = w.eflags;
    ctx.Dr0 = w.dr0 as u64;
    ctx.Dr1 = w.dr1 as u64;
    ctx.Dr2 = w.dr2 as u64;
    ctx.Dr3 = w.dr3 as u64;
    ctx.Dr6 = w.dr6 as u64;
    ctx.Dr7 = w.dr7 as u64;
    ctx
}

/// 统一 64 位 CONTEXT → 32 位上下文（截断到低 32 位）。
fn ctx_to_wow64(ctx: &CONTEXT, w: &mut WOW64_CONTEXT) {
    w.context_flags = WOW64_CONTEXT_I386
        | WOW64_CONTEXT_CONTROL
        | WOW64_CONTEXT_INTEGER
        | WOW64_CONTEXT_DEBUG_REGISTERS;
    w.eip = ctx.Rip as u32;
    w.eax = ctx.Rax as u32;
    w.ebx = ctx.Rbx as u32;
    w.ecx = ctx.Rcx as u32;
    w.edx = ctx.Rdx as u32;
    w.esi = ctx.Rsi as u32;
    w.edi = ctx.Rdi as u32;
    w.esp = ctx.Rsp as u32;
    w.ebp = ctx.Rbp as u32;
    w.eflags = ctx.EFlags;
    w.dr0 = ctx.Dr0 as u32;
    w.dr1 = ctx.Dr1 as u32;
    w.dr2 = ctx.Dr2 as u32;
    w.dr3 = ctx.Dr3 as u32;
    w.dr6 = ctx.Dr6 as u32;
    w.dr7 = ctx.Dr7 as u32;
}

fn set_wow64_context(thread: HANDLE, ctx: &WOW64_CONTEXT) -> Result<(), String> {
    let rc = unsafe { Wow64SetThreadContext(thread, ctx) };
    if rc == 0 {
        return Err("Wow64SetThreadContext failed".to_string());
    }
    Ok(())
}

/// `HANDLE` 含裸指针、默认非 `Send`；跨线程传给事件循环时用安全封装。
#[derive(Clone, Copy)]
struct RawHandle(HANDLE);
unsafe impl Send for RawHandle {}
unsafe impl Sync for RawHandle {}

/// 事件循环线程与 RPC 线程共享的断点表。
type Breakpoints = Arc<Mutex<HashMap<Address, u8>>>;

/// 一个硬件监视点。
#[derive(Clone, Copy)]
struct Watchpoint {
    address: Address,
    size: u8, // 1 | 2 | 4 | 8
    on_read: bool,
    on_write: bool,
}

/// 4 个调试寄存器槽位。
type Watchpoints = Arc<Mutex<[Option<Watchpoint>; 4]>>;

pub struct Debugger {
    pid: u32,
    handle: HANDLE,
    /// 目标是否为 32 位（Wow64）进程：寄存器/DR 访问走 WOW64_CONTEXT。
    wow64: bool,
    event_rx: Receiver<DebugEvent>,
    resume_tx: Sender<()>,
    stop_tx: Sender<()>,
    breakpoints: Breakpoints,
    watchpoints: Watchpoints,
    step_requested: Arc<Mutex<bool>>,
    thread: Option<JoinHandle<()>>,
}

impl Debugger {
    /// 附加到进程并启动事件循环线程。
    pub fn attach(pid: u32) -> Result<Debugger, String> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                false,
                pid,
            )
            .map_err(|e| classify_win32(&e, "OpenProcess"))?
        };

        let (event_tx, event_rx) = channel();
        let (resume_tx, resume_rx) = channel();
        let (stop_tx, stop_rx) = channel();
        let (attach_tx, attach_rx) = channel();
        let breakpoints: Breakpoints = Arc::new(Mutex::new(HashMap::new()));
        let watchpoints: Watchpoints = Arc::new(Mutex::new([None; 4]));
        let step_requested: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

        let bp = breakpoints.clone();
        let wp = watchpoints.clone();
        let st = step_requested.clone();
        let raw = RawHandle(handle);
        // 目标是否 32 位（Wow64）：决定寄存器/DR 用哪套上下文 API。
        let wow64 = crate::winproc::detect_arch(handle, pid)
            .map(|(arch, _)| arch == ce_core::Arch::X86)
            .unwrap_or(false);
        // 注意：DebugActiveProcess 必须与 WaitForDebugEvent 在同一线程。
        let thread = std::thread::spawn(move || {
            let attach_result = unsafe {
                DebugActiveProcess(pid)
                    .map_err(|e| classify_win32(&e, "DebugActiveProcess"))
                    .map(|_| {
                        let _ = DebugSetProcessKillOnExit(false);
                    })
            };
            if let Err(e) = attach_result {
                let _ = attach_tx.send(Err(e));
                return;
            }
            let _ = attach_tx.send(Ok(()));
            event_loop(pid, raw, event_tx, resume_rx, stop_rx, bp, wp, st, wow64);
            unsafe { let _ = DebugActiveProcessStop(pid); }
        });

        match attach_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                unsafe { let _ = CloseHandle(handle); }
                return Err(e);
            }
            Err(_) => {
                unsafe { let _ = CloseHandle(handle); }
                return Err("attach thread died".to_string());
            }
        }

        Ok(Debugger {
            pid,
            handle,
            wow64,
            event_rx,
            resume_tx,
            stop_tx,
            breakpoints,
            watchpoints,
            step_requested,
            thread: Some(thread),
        })
    }

    /// 设置软件断点（写入 INT3，保存原字节）。
    pub fn set_breakpoint(&self, addr: Address) -> Result<(), String> {
        let orig = read_byte(self.handle, addr).ok_or("breakpoint address unreadable")?;
        write_byte(self.handle, addr, INT3)?;
        self.breakpoints.lock().unwrap().insert(addr, orig);
        Ok(())
    }

    /// 清除软件断点（还原原字节）。
    pub fn clear_breakpoint(&self, addr: Address) -> Result<(), String> {
        let orig = self
            .breakpoints
            .lock()
            .unwrap()
            .remove(&addr)
            .ok_or("breakpoint not set")?;
        write_byte(self.handle, addr, orig)
    }

    /// 设置硬件监视点（应用到此进程的所有线程）。
    pub fn set_watchpoint(
        &self,
        address: Address,
        size: u8,
        on_read: bool,
        on_write: bool,
    ) -> Result<(), String> {
        if !matches!(size, 1 | 2 | 4 | 8) {
            return Err("watchpoint size must be 1, 2, 4, or 8".to_string());
        }
        if !on_read && !on_write {
            return Err("watchpoint needs on_read or on_write".to_string());
        }

        let mut wps = self.watchpoints.lock().unwrap();
        let slot = wps
            .iter()
            .position(|w| w.is_none())
            .ok_or("no free watchpoint slot (max 4)")?;
        let wp = Watchpoint {
            address,
            size,
            on_read,
            on_write,
        };
        wps[slot] = Some(wp);
        let snapshot = *wps;
        drop(wps);

        apply_watchpoints_to_all(self.pid, &snapshot, self.wow64);
        Ok(())
    }

    /// 清除硬件监视点。
    pub fn clear_watchpoint(&self, address: Address) -> Result<(), String> {
        let mut wps = self.watchpoints.lock().unwrap();
        let slot = wps
            .iter()
            .position(|w| w.map(|x| x.address) == Some(address))
            .ok_or("watchpoint not set")?;
        wps[slot] = None;
        let snapshot = *wps;
        drop(wps);

        apply_watchpoints_to_all(self.pid, &snapshot, self.wow64);
        Ok(())
    }

    /// 等待下一个调试事件（超时返回 `None`）。
    pub fn wait(&self, timeout_ms: u64) -> Option<DebugEvent> {
        self.event_rx
            .recv_timeout(std::time::Duration::from_millis(timeout_ms))
            .ok()
    }

    /// 继续执行（恢复被冻结的调试进程）。
    pub fn continue_execution(&self) {
        let _ = self.resume_tx.send(());
    }

    /// 单步执行一条指令（置单步标志并继续）。
    ///
    /// 真正的 `SetThreadContext`（置 TF）在事件循环线程执行，因为
    /// `SetThreadContext` 对调试目标线程有线程亲和性（必须与 `WaitForDebugEvent` 同线程）。
    /// 配合 `wait` 获取 `single_step` 事件。
    pub fn single_step(&self, _thread_id: u32) -> Result<(), String> {
        *self.step_requested.lock().unwrap() = true;
        self.continue_execution();
        Ok(())
    }

    /// 读取指定线程的寄存器。
    pub fn registers(&self, thread_id: u32) -> Result<Registers, String> {
        let thread = open_thread(thread_id)?;
        let ctx = if self.wow64 {
            let w = get_wow64_context(thread)?;
            wow64_to_ctx(&w)
        } else {
            get_context(thread)?
        };
        let _ = unsafe { CloseHandle(thread) };
        Ok(registers_from_ctx(&ctx))
    }

    /// 写入指定线程的寄存器。
    pub fn set_registers(&self, thread_id: u32, regs: &Registers) -> Result<(), String> {
        let thread = open_thread(thread_id)?;
        let mut ctx = read_thread_ctx(thread, self.wow64)?;
        apply_registers(&mut ctx, regs);
        write_thread_ctx(thread, &ctx, self.wow64)?;
        let _ = unsafe { CloseHandle(thread) };
        Ok(())
    }

    /// 回溯指定线程的调用栈（RBP 链，尽力而为；要求目标开启帧指针）。
    ///
    /// 每帧记录 RIP/RBP/RSP；栈底（rbp 为 0 / 不再前进 / 不可读）时停止。
    pub fn stack(&self, thread_id: u32, max_frames: usize) -> Result<Vec<StackFrame>, String> {
        let thread = open_thread(thread_id)?;
        let ctx = read_thread_ctx(thread, self.wow64)?;
        let _ = unsafe { CloseHandle(thread) };

        let mut frames = Vec::new();
        let mut rbp = ctx.Rbp;
        let mut rip = ctx.Rip;
        let mut rsp = ctx.Rsp;
        for _ in 0..max_frames {
            frames.push(StackFrame { rip, rbp, rsp });
            let mut next_rbp = 0u64;
            let mut ret = 0u64;
            // [rbp] = 上一帧 rbp；[rbp+8] = 返回地址。
            if read_ptr(self.handle, rbp, &mut next_rbp)
                && read_ptr(self.handle, rbp.wrapping_add(8), &mut ret)
            {
                if next_rbp == 0 || next_rbp <= rbp || ret == 0 {
                    break;
                }
                rbp = next_rbp;
                rip = ret;
                rsp = rbp.wrapping_add(16);
            } else {
                break;
            }
        }
        Ok(frames)
    }
}

impl Drop for Debugger {
    fn drop(&mut self) {
        let _ = self.resume_tx.send(());
        let _ = self.stop_tx.send(());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        // 干净恢复：还原所有断点原字节、清除硬件监视点（不留痕迹）。
        let bps: Vec<(Address, u8)> = self
            .breakpoints
            .lock()
            .unwrap()
            .iter()
            .map(|(a, b)| (*a, *b))
            .collect();
        for (addr, orig) in bps {
            let _ = write_byte(self.handle, addr, orig);
        }
        self.breakpoints.lock().unwrap().clear();
        apply_watchpoints_to_all(self.pid, &[None; 4], self.wow64);
        unsafe { let _ = CloseHandle(self.handle); }
    }
}

// ---- 寄存器映射 ----

fn registers_from_ctx(ctx: &CONTEXT) -> Registers {
    Registers {
        rip: ctx.Rip,
        rax: ctx.Rax,
        rbx: ctx.Rbx,
        rcx: ctx.Rcx,
        rdx: ctx.Rdx,
        rsi: ctx.Rsi,
        rdi: ctx.Rdi,
        rsp: ctx.Rsp,
        rbp: ctx.Rbp,
        r8: ctx.R8,
        r9: ctx.R9,
        r10: ctx.R10,
        r11: ctx.R11,
        r12: ctx.R12,
        r13: ctx.R13,
        r14: ctx.R14,
        r15: ctx.R15,
        eflags: ctx.EFlags,
    }
}

fn apply_registers(ctx: &mut CONTEXT, regs: &Registers) {
    ctx.Rip = regs.rip;
    ctx.Rax = regs.rax;
    ctx.Rbx = regs.rbx;
    ctx.Rcx = regs.rcx;
    ctx.Rdx = regs.rdx;
    ctx.Rsi = regs.rsi;
    ctx.Rdi = regs.rdi;
    ctx.Rsp = regs.rsp;
    ctx.Rbp = regs.rbp;
    ctx.R8 = regs.r8;
    ctx.R9 = regs.r9;
    ctx.R10 = regs.r10;
    ctx.R11 = regs.r11;
    ctx.R12 = regs.r12;
    ctx.R13 = regs.r13;
    ctx.R14 = regs.r14;
    ctx.R15 = regs.r15;
    ctx.EFlags = regs.eflags;
}

// ---- 事件循环 ----

#[allow(clippy::too_many_arguments)]
fn event_loop(
    pid: u32,
    handle: RawHandle,
    event_tx: Sender<DebugEvent>,
    resume_rx: Receiver<()>,
    stop_rx: Receiver<()>,
    breakpoints: Breakpoints,
    watchpoints: Watchpoints,
    step_requested: Arc<Mutex<bool>>,
    wow64: bool,
) {
    let h = handle.0;
    let mut pending_restore: Option<Address> = None;

    loop {
        let mut event = DEBUG_EVENT::default();
        let got = unsafe { WaitForDebugEvent(&mut event, 100) };
        match got {
            Ok(()) => {}
            Err(_) => {
                if stop_rx.try_recv().is_ok() {
                    break;
                }
                continue;
            }
        }

        let thread_id = event.dwThreadId;
        let is_exception = event.dwDebugEventCode.0 == EXCEPTION_DEBUG_EVENT.0;

        if is_exception {
            let info = unsafe { event.u.Exception };
            let code = info.ExceptionRecord.ExceptionCode.0; // i32
            let addr = info.ExceptionRecord.ExceptionAddress as u64;
            // Wow64：32 位代码的 INT3/单步以 WX86 码上报。
            let is_bp_code =
                code == EXCEPTION_BREAKPOINT.0 || (wow64 && code == STATUS_WX86_BREAKPOINT);
            let is_step_code =
                code == EXCEPTION_SINGLE_STEP.0 || (wow64 && code == STATUS_WX86_SINGLE_STEP);

            if is_bp_code {
                let is_mine = breakpoints.lock().unwrap().contains_key(&addr);
                if is_mine {
                    if !handle_breakpoint_hit(pid, h, &breakpoints, thread_id, addr, &event_tx, &resume_rx, &stop_rx, wow64) {
                        break;
                    }
                    pending_restore = Some(addr);
                } else {
                    // 加载器断点或未知断点：直接继续。
                    unsafe { let _ = ContinueDebugEvent(pid, thread_id, DBG_CONTINUE); }
                }
            } else if is_step_code {
                // 先检查硬件监视点（DR6 bits 0-3）。
                if let Some(slot) = read_watchpoint_slot(thread_id, wow64) {
                    let wp = watchpoints.lock().unwrap()[slot];
                    if let Some(wp) = wp {
                        let access = if wp.on_read && wp.on_write {
                            "read_write"
                        } else if wp.on_write {
                            "write"
                        } else {
                            "read_write"
                        };
                        let _ = event_tx.send(DebugEvent {
                            kind: "watchpoint".to_string(),
                            thread_id,
                            address: wp.address,
                            code: code as u32,
                            access: Some(access.to_string()),
                        });
                        clear_dr6(thread_id, wow64);
                        if !wait_resume(&resume_rx, &stop_rx) {
                            break;
                        }
                        apply_step(&step_requested, thread_id, wow64);
                        unsafe { let _ = ContinueDebugEvent(pid, thread_id, DBG_CONTINUE); }
                        continue;
                    }
                }

                // 否则是单步（断点恢复或用户单步）。
                if let Some(bp_addr) = pending_restore.take() {
                    let still_set = breakpoints.lock().unwrap().contains_key(&bp_addr);
                    if still_set {
                        let _ = write_byte(h, bp_addr, INT3);
                    }
                    if let Ok(thread) = open_thread(thread_id) {
                        if let Ok(mut ctx) = read_thread_ctx(thread, wow64) {
                            ctx.EFlags &= !TRAP_FLAG;
                            let _ = write_thread_ctx(thread, &ctx, wow64);
                        }
                        unsafe { let _ = CloseHandle(thread); }
                    }
                    unsafe { let _ = ContinueDebugEvent(pid, thread_id, DBG_CONTINUE); }
                } else {
                    let _ = event_tx.send(DebugEvent {
                        kind: "single_step".to_string(),
                        thread_id,
                        address: addr,
                        code: code as u32,
                        access: None,
                    });
                    if !wait_resume(&resume_rx, &stop_rx) {
                        break;
                    }
                    apply_step(&step_requested, thread_id, wow64);
                    unsafe { let _ = ContinueDebugEvent(pid, thread_id, DBG_CONTINUE); }
                }
            } else {
                // 其它异常（含访问违例）。
                let kind = if code == EXCEPTION_ACCESS_VIOLATION.0 {
                    "access_violation"
                } else {
                    "exception"
                };
                let _ = event_tx.send(DebugEvent {
                    kind: kind.to_string(),
                    thread_id,
                    address: addr,
                    code: code as u32,
                    access: None,
                });
                if !wait_resume(&resume_rx, &stop_rx) {
                    break;
                }
                apply_step(&step_requested, thread_id, wow64);
                unsafe { let _ = ContinueDebugEvent(pid, thread_id, DBG_EXCEPTION_NOT_HANDLED); }
            }
        } else {
            // 线程/模块/进程事件：自动继续。
            unsafe { let _ = ContinueDebugEvent(pid, thread_id, DBG_CONTINUE); }
        }
    }
}

/// 断点命中：回退 RIP、还原原字节、置 TF，报告事件，等待恢复。
#[allow(clippy::too_many_arguments)]
fn handle_breakpoint_hit(
    pid: u32,
    handle: HANDLE,
    breakpoints: &Breakpoints,
    thread_id: u32,
    addr: Address,
    event_tx: &Sender<DebugEvent>,
    resume_rx: &Receiver<()>,
    stop_rx: &Receiver<()>,
    wow64: bool,
) -> bool {
    if let Ok(thread) = open_thread(thread_id) {
        if let Ok(mut ctx) = read_thread_ctx(thread, wow64) {
            ctx.Rip = addr; // 回退到断点指令
            ctx.EFlags |= TRAP_FLAG; // 单步
            let _ = write_thread_ctx(thread, &ctx, wow64);
        }
        unsafe { let _ = CloseHandle(thread); }
    }
    let orig = breakpoints.lock().unwrap().get(&addr).copied().unwrap_or(INT3);
    let _ = write_byte(handle, addr, orig);

    let _ = event_tx.send(DebugEvent {
        kind: "breakpoint".to_string(),
        thread_id,
        address: addr,
        code: EXCEPTION_BREAKPOINT.0 as u32,
        access: None,
    });
    if !wait_resume(resume_rx, stop_rx) {
        return false;
    }
    unsafe { let _ = ContinueDebugEvent(pid, thread_id, DBG_CONTINUE); }
    true
}

/// 阻塞等待恢复信号；若收到停止信号则返回 `false`。
fn wait_resume(resume_rx: &Receiver<()>, stop_rx: &Receiver<()>) -> bool {
    loop {
        match resume_rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(()) => return true,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if stop_rx.try_recv().is_ok() {
                    return false;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return false,
        }
    }
}

/// 若单步请求已置位，则在事件循环（调试）线程上对当前线程置 TF。
/// `SetThreadContext` 对调试目标线程有线程亲和性，必须在此执行。
fn apply_step(step_requested: &Arc<Mutex<bool>>, thread_id: u32, wow64: bool) {
    let mut st = step_requested.lock().unwrap();
    if !*st {
        return;
    }
    *st = false;
    drop(st);

    if let Ok(thread) = open_thread(thread_id) {
        if let Ok(mut ctx) = read_thread_ctx(thread, wow64) {
            ctx.EFlags |= TRAP_FLAG;
            let _ = write_thread_ctx(thread, &ctx, wow64);
        }
        unsafe { let _ = CloseHandle(thread); }
    }
}

// ---- 硬件监视点辅助 ----

/// 读取线程的 DR6，若 bits 0-3 有置位则返回触发的槽位。
fn read_watchpoint_slot(thread_id: u32, wow64: bool) -> Option<usize> {
    let thread = open_thread(thread_id).ok()?;
    let ctx = read_thread_ctx_debug(thread, wow64).ok()?;
    let _ = unsafe { CloseHandle(thread) };
    let dr6 = ctx.Dr6;
    if dr6 & 0xF != 0 {
        Some((dr6 & 0xF).trailing_zeros() as usize)
    } else {
        None
    }
}

/// 清除线程的 DR6（写 0）。
fn clear_dr6(thread_id: u32, wow64: bool) {
    if let Ok(thread) = open_thread(thread_id) {
        if let Ok(mut ctx) = read_thread_ctx_debug(thread, wow64) {
            ctx.Dr6 = 0;
            let _ = write_thread_ctx(thread, &ctx, wow64);
        }
        unsafe { let _ = CloseHandle(thread); }
    }
}

/// 枚举进程的所有线程 ID。
fn list_threads(pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    unsafe {
        if let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
            let mut entry: THREADENTRY32 = std::mem::zeroed();
            entry.dwSize = size_of::<THREADENTRY32>() as u32;
            if Thread32First(snap, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        out.push(entry.th32ThreadID);
                    }
                    if Thread32Next(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snap);
        }
    }
    out
}

/// 把监视点应用到进程的所有线程（挂起 → 写 DR → 恢复）。
fn apply_watchpoints_to_all(pid: u32, wps: &[Option<Watchpoint>; 4], wow64: bool) {
    for tid in list_threads(pid) {
        apply_watchpoints_to_thread(tid, wps, wow64);
    }
}

fn apply_watchpoints_to_thread(thread_id: u32, wps: &[Option<Watchpoint>; 4], wow64: bool) {
    let Ok(thread) = open_thread(thread_id) else {
        return;
    };
    unsafe {
        let _ = SuspendThread(thread);
        if let Ok(mut ctx) = read_thread_ctx_debug(thread, wow64) {
            ctx.Dr0 = wps[0].map(|w| w.address).unwrap_or(0);
            ctx.Dr1 = wps[1].map(|w| w.address).unwrap_or(0);
            ctx.Dr2 = wps[2].map(|w| w.address).unwrap_or(0);
            ctx.Dr3 = wps[3].map(|w| w.address).unwrap_or(0);
            ctx.Dr6 = 0;
            ctx.Dr7 = compute_dr7(wps);
            let _ = write_thread_ctx(thread, &ctx, wow64);
        }
        let _ = ResumeThread(thread);
        let _ = CloseHandle(thread);
    }
}

/// 根据监视点计算 DR7 控制字。
fn compute_dr7(wps: &[Option<Watchpoint>; 4]) -> u64 {
    let mut dr7 = 0u64;
    for (i, wp) in wps.iter().enumerate() {
        if let Some(wp) = wp {
            // x86 不支持纯读；写→01，读写→11。
            let rw: u64 = if wp.on_write && !wp.on_read { 1 } else { 3 };
            let len_code: u64 = match wp.size {
                1 => 0,
                2 => 1,
                4 => 3,
                8 => 2,
                _ => 0,
            };
            dr7 |= 1 << (2 * i); // Ln 使能
            dr7 |= rw << (16 + 4 * i); // RWn
            dr7 |= len_code << (18 + 4 * i); // LENn
        }
    }
    dr7
}

// ---- 底层辅助 ----

/// 把 Win32 错误分类为语义化消息（防护：区分受保护 / 不存在 / 已被调试）。
fn classify_win32(e: &windows::core::Error, action: &str) -> String {
    let code = (e.code().0 as u32) & 0xFFFF;
    match code {
        // ERROR_ACCESS_DENIED：受保护进程（PPL/反作弊）或权限不足。
        5 => format!(
            "{action}: access denied (protected process or needs elevation) [win32 0x{code:x}]"
        ),
        // ERROR_INVALID_PARAMETER：进程不存在，或已被另一调试器附加。
        87 => format!(
            "{action}: invalid parameter (process not found, or already being debugged) [win32 0x{code:x}]"
        ),
        // ERROR_INVALID_HANDLE：进程已退出。
        6 => format!("{action}: invalid handle (process exited) [win32 0x{code:x}]"),
        _ => format!("{action}: {e} [win32 0x{code:x}]"),
    }
}

/// 从目标进程读取 8 字节指针（栈回溯用）。
fn read_ptr(handle: HANDLE, addr: Address, out: &mut u64) -> bool {
    let mut nread = 0usize;
    unsafe {
        ReadProcessMemory(
            handle,
            addr as *const c_void,
            out as *mut u64 as *mut c_void,
            8,
            Some(&mut nread),
        )
        .is_ok()
            && nread == 8
    }
}

fn open_thread(thread_id: u32) -> Result<HANDLE, String> {
    unsafe {
        OpenThread(
            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
            false,
            thread_id,
        )
        .map_err(|e| format!("OpenThread: {e}"))
    }
}

/// 统一读取线程上下文：wow64 目标走 WOW64_CONTEXT，其余走 64 位 CONTEXT。
///
/// 断点/监视点命中后的短暂窗口内 GetThreadContext 可能报 ERROR_NOACCESS
/// （线程上下文切换中），做少量重试。
fn read_thread_ctx(thread: HANDLE, wow64: bool) -> Result<CONTEXT, String> {
    if wow64 {
        let w = get_wow64_context(thread)?;
        return Ok(wow64_to_ctx(&w));
    }
    let mut last = String::new();
    for _ in 0..4 {
        match get_context(thread) {
            Ok(ctx) => return Ok(ctx),
            Err(e) => {
                last = e;
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
    }
    Err(last)
}

/// 统一读取含调试寄存器的线程上下文。
fn read_thread_ctx_debug(thread: HANDLE, wow64: bool) -> Result<CONTEXT, String> {
    if wow64 {
        let w = get_wow64_context(thread)?;
        return Ok(wow64_to_ctx(&w));
    }
    let mut last = String::new();
    for _ in 0..4 {
        match get_context_debug(thread) {
            Ok(ctx) => return Ok(ctx),
            Err(e) => {
                last = e;
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
    }
    Err(last)
}

/// 统一写入线程上下文。
fn write_thread_ctx(thread: HANDLE, ctx: &CONTEXT, wow64: bool) -> Result<(), String> {
    if wow64 {
        let mut w = get_wow64_context(thread)?;
        ctx_to_wow64(ctx, &mut w);
        return set_wow64_context(thread, &w);
    }
    set_context(thread, ctx)
}

fn get_context(thread: HANDLE) -> Result<CONTEXT, String> {
    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.ContextFlags = CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64;
    unsafe {
        GetThreadContext(thread, &mut ctx).map_err(|e| format!("GetThreadContext: {e}"))?;
    }
    Ok(ctx)
}

/// 读取含调试寄存器（DR0-DR7）的上下文。
fn get_context_debug(thread: HANDLE) -> Result<CONTEXT, String> {
    let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
    ctx.ContextFlags =
        CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64 | CONTEXT_DEBUG_REGISTERS_AMD64;
    unsafe {
        GetThreadContext(thread, &mut ctx).map_err(|e| format!("GetThreadContext: {e}"))?;
    }
    Ok(ctx)
}

fn set_context(thread: HANDLE, ctx: &CONTEXT) -> Result<(), String> {
    unsafe { SetThreadContext(thread, ctx).map_err(|e| format!("SetThreadContext: {e}")) }
}

fn read_byte(handle: HANDLE, addr: Address) -> Option<u8> {
    let mut buf = [0u8; 1];
    let mut nread = 0usize;
    unsafe {
        ReadProcessMemory(
            handle,
            addr as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            1,
            Some(&mut nread),
        )
        .ok()?;
    }
    (nread == 1).then_some(buf[0])
}

fn write_byte(handle: HANDLE, addr: Address, byte: u8) -> Result<(), String> {
    unsafe {
        let mut old = PAGE_PROTECTION_FLAGS(0);
        VirtualProtectEx(
            handle,
            addr as *const c_void,
            1,
            PAGE_PROTECTION_FLAGS(PAGE_EXECUTE_READWRITE),
            &mut old,
        )
        .map_err(|e| format!("VirtualProtectEx: {e}"))?;

        let mut written = 0usize;
        let r = WriteProcessMemory(
            handle,
            addr as *const c_void,
            &byte as *const u8 as *const c_void,
            1,
            Some(&mut written),
        );
        let mut dummy = PAGE_PROTECTION_FLAGS(0);
        let _ = VirtualProtectEx(handle, addr as *const c_void, 1, old, &mut dummy);

        r.map_err(|e| format!("WriteProcessMemory: {e}"))?;
        if written != 1 {
            return Err("partial write".to_string());
        }
    }
    Ok(())
}
