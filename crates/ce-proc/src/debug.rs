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
            .map_err(|e| format!("OpenProcess: {e}"))?
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
        // 注意：DebugActiveProcess 必须与 WaitForDebugEvent 在同一线程。
        let thread = std::thread::spawn(move || {
            let attach_result = unsafe {
                DebugActiveProcess(pid)
                    .map_err(|e| format!("DebugActiveProcess: {e}"))
                    .map(|_| {
                        let _ = DebugSetProcessKillOnExit(false);
                    })
            };
            if let Err(e) = attach_result {
                let _ = attach_tx.send(Err(e));
                return;
            }
            let _ = attach_tx.send(Ok(()));
            event_loop(pid, raw, event_tx, resume_rx, stop_rx, bp, wp, st);
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

        apply_watchpoints_to_all(self.pid, &snapshot);
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

        apply_watchpoints_to_all(self.pid, &snapshot);
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
        let ctx = get_context(thread)?;
        let _ = unsafe { CloseHandle(thread) };
        Ok(registers_from_ctx(&ctx))
    }

    /// 写入指定线程的寄存器。
    pub fn set_registers(&self, thread_id: u32, regs: &Registers) -> Result<(), String> {
        let thread = open_thread(thread_id)?;
        let mut ctx = get_context(thread)?;
        apply_registers(&mut ctx, regs);
        set_context(thread, &ctx)?;
        let _ = unsafe { CloseHandle(thread) };
        Ok(())
    }

    /// 回溯指定线程的调用栈（RBP 链，尽力而为；要求目标开启帧指针）。
    ///
    /// 每帧记录 RIP/RBP/RSP；栈底（rbp 为 0 / 不再前进 / 不可读）时停止。
    pub fn stack(&self, thread_id: u32, max_frames: usize) -> Result<Vec<StackFrame>, String> {
        let thread = open_thread(thread_id)?;
        let ctx = get_context(thread)?;
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

            if code == EXCEPTION_BREAKPOINT.0 {
                let is_mine = breakpoints.lock().unwrap().contains_key(&addr);
                if is_mine {
                    if !handle_breakpoint_hit(pid, h, &breakpoints, thread_id, addr, &event_tx, &resume_rx, &stop_rx) {
                        break;
                    }
                    pending_restore = Some(addr);
                } else {
                    // 加载器断点或未知断点：直接继续。
                    unsafe { let _ = ContinueDebugEvent(pid, thread_id, DBG_CONTINUE); }
                }
            } else if code == EXCEPTION_SINGLE_STEP.0 {
                // 先检查硬件监视点（DR6 bits 0-3）。
                if let Some(slot) = read_watchpoint_slot(thread_id) {
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
                        clear_dr6(thread_id);
                        if !wait_resume(&resume_rx, &stop_rx) {
                            break;
                        }
                        apply_step(&step_requested, thread_id);
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
                        if let Ok(mut ctx) = get_context(thread) {
                            ctx.EFlags &= !TRAP_FLAG;
                            let _ = set_context(thread, &ctx);
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
                    apply_step(&step_requested, thread_id);
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
                apply_step(&step_requested, thread_id);
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
) -> bool {
    if let Ok(thread) = open_thread(thread_id) {
        if let Ok(mut ctx) = get_context(thread) {
            ctx.Rip = addr; // 回退到断点指令
            ctx.EFlags |= TRAP_FLAG; // 单步
            let _ = set_context(thread, &ctx);
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
fn apply_step(step_requested: &Arc<Mutex<bool>>, thread_id: u32) {
    let mut st = step_requested.lock().unwrap();
    if !*st {
        return;
    }
    *st = false;
    drop(st);

    if let Ok(thread) = open_thread(thread_id) {
        if let Ok(mut ctx) = get_context(thread) {
            ctx.EFlags |= TRAP_FLAG;
            let _ = set_context(thread, &ctx);
        }
        unsafe { let _ = CloseHandle(thread); }
    }
}

// ---- 硬件监视点辅助 ----

/// 读取线程的 DR6，若 bits 0-3 有置位则返回触发的槽位。
fn read_watchpoint_slot(thread_id: u32) -> Option<usize> {
    let thread = open_thread(thread_id).ok()?;
    let ctx = get_context_debug(thread).ok()?;
    let _ = unsafe { CloseHandle(thread) };
    let dr6 = ctx.Dr6;
    if dr6 & 0xF != 0 {
        Some((dr6 & 0xF).trailing_zeros() as usize)
    } else {
        None
    }
}

/// 清除线程的 DR6（写 0）。
fn clear_dr6(thread_id: u32) {
    if let Ok(thread) = open_thread(thread_id) {
        if let Ok(mut ctx) = get_context_debug(thread) {
            ctx.Dr6 = 0;
            let _ = set_context(thread, &ctx);
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
fn apply_watchpoints_to_all(pid: u32, wps: &[Option<Watchpoint>; 4]) {
    for tid in list_threads(pid) {
        apply_watchpoints_to_thread(tid, wps);
    }
}

fn apply_watchpoints_to_thread(thread_id: u32, wps: &[Option<Watchpoint>; 4]) {
    let Ok(thread) = open_thread(thread_id) else {
        return;
    };
    unsafe {
        let _ = SuspendThread(thread);
        if let Ok(mut ctx) = get_context_debug(thread) {
            ctx.Dr0 = wps[0].map(|w| w.address).unwrap_or(0);
            ctx.Dr1 = wps[1].map(|w| w.address).unwrap_or(0);
            ctx.Dr2 = wps[2].map(|w| w.address).unwrap_or(0);
            ctx.Dr3 = wps[3].map(|w| w.address).unwrap_or(0);
            ctx.Dr6 = 0;
            ctx.Dr7 = compute_dr7(wps);
            let _ = set_context(thread, &ctx);
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
