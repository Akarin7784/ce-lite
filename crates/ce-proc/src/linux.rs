//! Linux 进程后端：`/proc/{pid}/mem` 读写 + `/proc/{pid}/maps` 区域枚举
//! + ptrace 调试器（软断点 / 寄存器 / 单步 / 硬件监视点）。
//!
//! 注意：本文件在 Windows 上不可编译（`cfg(target_os = "linux")`），
//! 用 `cargo check --target x86_64-unknown-linux-gnu` 做类型验证。

use std::fs::File;
use std::os::unix::fs::FileExt;

use ce_core::{Address, Arch, DebugEvent, MemoryRegion, ModuleInfo, ProcessInfo, Registers, StackFrame};

use super::{Process, ProcessError};

/// Linux 进程句柄（`/proc/pid/mem` 的只读 fd；写入走 `pwrite`）。
pub struct LinuxProcess {
    pid: u32,
    mem: File,
    info: ProcessInfo,
}

pub fn open(pid: u32) -> Result<Box<dyn Process>, ProcessError> {
    let mem = File::open(format!("/proc/{pid}/mem"))
        .map_err(|_| ProcessError::AccessDenied { pid })?;
    let name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    Ok(Box::new(LinuxProcess {
        pid,
        mem,
        info: ProcessInfo {
            pid,
            name,
            arch: Arch::X64,
            pointer_size: 8,
        },
    }))
}

pub fn list_processes() -> Result<Vec<ProcessInfo>, ProcessError> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir("/proc").map_err(|e| ProcessError::Platform(e.to_string()))?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if comm.is_empty() {
            continue;
        }
        out.push(ProcessInfo {
            pid,
            name: comm,
            arch: Arch::X64,
            pointer_size: 8,
        });
    }
    Ok(out)
}

impl Process for LinuxProcess {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn info(&self) -> ProcessInfo {
        self.info.clone()
    }

    fn regions(&self) -> Result<Vec<MemoryRegion>, ProcessError> {
        parse_maps(self.pid)
    }

    fn read(&self, address: Address, size: usize) -> Result<Vec<u8>, ProcessError> {
        let mut buf = vec![0u8; size];
        let n = self
            .mem
            .read_at(&mut buf, address)
            .map_err(|e| ProcessError::Read {
                address,
                reason: e.to_string(),
            })?;
        buf.truncate(n);
        Ok(buf)
    }

    fn write(&self, address: Address, bytes: &[u8]) -> Result<usize, ProcessError> {
        // /proc/pid/mem 只读；写入需经 ptrace（PTRACE_POKEDATA）或 process_vm_writev。
        crate::linux::write_via_ptrace(self.pid, address, bytes)
            .map_err(|e| ProcessError::Write {
                address,
                reason: e,
            })
    }

    fn alloc(&self, _size: usize) -> Result<Address, ProcessError> {
        Err(ProcessError::Other(
            "alloc on Linux requires ptrace syscall injection (not implemented)".to_string(),
        ))
    }

    fn modules(&self) -> Result<Vec<ModuleInfo>, ProcessError> {
        Ok(parse_maps(self.pid)?
            .into_iter()
            .filter(|m| m.executable && m.name.is_some())
            .map(|m| ModuleInfo {
                name: m.name.clone().unwrap_or_default(),
                path: m.name.unwrap_or_default(),
                base: m.base,
                size: m.size,
            })
            .collect())
    }
}

/// 解析 `/proc/{pid}/maps` 为内存区域。
fn parse_maps(pid: u32) -> Result<Vec<MemoryRegion>, ProcessError> {
    let text =
        std::fs::read_to_string(format!("/proc/{pid}/maps")).map_err(|e| ProcessError::Platform(e.to_string()))?;
    let mut out = Vec::new();
    for line in text.lines() {
        // 格式: base-end perms offset dev inode [name]
        let mut parts = line.split_whitespace();
        let Some(range) = parts.next() else { continue };
        let Some(perms) = parts.next() else { continue };
        let (base, end) = match range.split_once('-') {
            Some((a, b)) => (u64::from_str_radix(a, 16).ok(), u64::from_str_radix(b, 16).ok()),
            None => (None, None),
        };
        let (Some(base), Some(end)) = (base, end) else { continue };
        // 跳过 /dev/zero、[vvar] 等无意义映射。
        let name = parts.last().map(|s| s.to_string()).filter(|s| !s.starts_with('['));
        out.push(MemoryRegion {
            base,
            size: end - base,
            protection: 0,
            readable: perms.contains('r'),
            writable: perms.contains('w'),
            executable: perms.contains('x'),
            name,
        });
    }
    Ok(out)
}

// ---- ptrace 辅助 ----

/// 经 ptrace（PTRACE_POKEDATA）向目标进程内存写字节。
///
/// 写入前需已 attach（或目标已由本进程 trace）。逐 word 写入。
fn write_via_ptrace(pid: u32, address: Address, bytes: &[u8]) -> Result<usize, String> {
    let mut written = 0usize;
    let mut addr = address;
    for chunk in bytes.chunks(8) {
        let mut word = [0u8; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        let value = u64::from_le_bytes(word);
        // PTRACE_POKEDATA 一次写一个 word（低 3 位对齐）。
        let aligned = addr & !7;
        // 未对齐：先读原 word，改对应字节后再写回。
        if addr % 8 != 0 || chunk.len() < 8 {
            let orig = unsafe { libc::ptrace(libc::PTRACE_PEEKDATA, pid as libc::pid_t, aligned as *mut libc::c_void, std::ptr::null_mut::<libc::c_void>()) };
            let mut merged = (orig as u64).to_le_bytes();
            let start = (addr - aligned) as usize;
            for (i, &b) in chunk.iter().enumerate() {
                if start + i < 8 {
                    merged[start + i] = b;
                }
            }
            let merged = u64::from_le_bytes(merged);
            let rc = unsafe { libc::ptrace(libc::PTRACE_POKEDATA, pid as libc::pid_t, aligned as *mut libc::c_void, merged as *mut libc::c_void) };
            if rc != 0 {
                return Err(format!("PTRACE_POKEDATA failed at 0x{aligned:x}"));
            }
            written += chunk.len();
        } else {
            let rc = unsafe { libc::ptrace(libc::PTRACE_POKEDATA, pid as libc::pid_t, addr as *mut libc::c_void, value as *mut libc::c_void) };
            if rc != 0 {
                return Err(format!("PTRACE_POKEDATA failed at 0x{addr:x}"));
            }
            written += 8;
        }
        addr += chunk.len() as u64;
    }
    Ok(written)
}

/// 读取目标进程 8 字节（ptrace PEEKDATA）。
fn peek_u64(pid: u32, addr: Address) -> Result<u64, String> {
    let v = unsafe { libc::ptrace(libc::PTRACE_PEEKDATA, pid as libc::pid_t, addr as *mut libc::c_void, std::ptr::null_mut::<libc::c_void>()) };
    if v == -1 {
        return Err(format!("PTRACE_PEEKDATA failed at 0x{addr:x}"));
    }
    Ok(v as u64)
}

/// 写入目标进程 8 字节（ptrace POKEDATA）。
fn poke_u64(pid: u32, addr: Address, value: u64) -> Result<(), String> {
    let rc = unsafe { libc::ptrace(libc::PTRACE_POKEDATA, pid as libc::pid_t, addr as *mut libc::c_void, value as *mut libc::c_void) };
    if rc != 0 {
        return Err(format!("PTRACE_POKEDATA failed at 0x{addr:x}"));
    }
    Ok(())
}

// ---- ptrace 调试器 ----

const INT3: u8 = 0xCC;

/// Linux ptrace 调试器（与 Windows `Debugger` 同方法表面，`&self` 风格）。
///
/// 能力：附加（PTRACE_ATTACH）、软断点（INT3）、寄存器（GETREGS/SETREGS）、
/// 单步（SINGLESTEP）、硬件监视点（debug 寄存器 POKEUSER）。
pub struct Debugger {
    pid: u32,
    breakpoints: std::sync::Mutex<std::collections::HashMap<Address, u8>>,
    watchpoints: std::sync::Mutex<[Option<(Address, u8, bool, bool)>; 4]>,
}

impl Debugger {
    pub fn attach(pid: u32) -> Result<Debugger, String> {
        unsafe {
            let rc = libc::ptrace(libc::PTRACE_ATTACH, pid as libc::pid_t, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>());
            if rc != 0 {
                return Err(format!("PTRACE_ATTACH failed (is the process protected, or already traced?)"));
            }
        }
        // 等待 SIGSTOP。
        let mut status = 0;
        let w = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
        if w < 0 {
            return Err(format!("waitpid after attach failed"));
        }
        Ok(Debugger {
            pid,
            breakpoints: std::sync::Mutex::new(std::collections::HashMap::new()),
            watchpoints: std::sync::Mutex::new([None; 4]),
        })
    }

    pub fn set_breakpoint(&self, addr: Address) -> Result<(), String> {
        let orig = peek_u64(self.pid, addr & !7)?;
        let byte = ((orig >> ((addr & 7) * 8)) & 0xFF) as u8;
        self.breakpoints.lock().unwrap().insert(addr, byte);
        let new = (orig & !(0xFFu64 << ((addr & 7) * 8))) | ((INT3 as u64) << ((addr & 7) * 8));
        poke_u64(self.pid, addr & !7, new)
    }

    pub fn clear_breakpoint(&self, addr: Address) -> Result<(), String> {
        let orig = self
            .breakpoints
            .lock()
            .unwrap()
            .remove(&addr)
            .ok_or("breakpoint not set")?;
        let cur = peek_u64(self.pid, addr & !7)?;
        let new = (cur & !(0xFFu64 << ((addr & 7) * 8))) | ((orig as u64) << ((addr & 7) * 8));
        poke_u64(self.pid, addr & !7, new)
    }

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
        let mut wps = self.watchpoints.lock().unwrap();
        let slot = wps
            .iter()
            .position(|w| w.is_none())
            .ok_or("no free watchpoint slot (max 4)")?;
        wps[slot] = Some((address, size, on_read, on_write));
        let snapshot = *wps;
        drop(wps);
        self.apply_watchpoints(&snapshot)
    }

    pub fn clear_watchpoint(&self, address: Address) -> Result<(), String> {
        let mut wps = self.watchpoints.lock().unwrap();
        let slot = wps
            .iter()
            .position(|w| w.map(|x| x.0) == Some(address))
            .ok_or("watchpoint not set")?;
        wps[slot] = None;
        let snapshot = *wps;
        drop(wps);
        self.apply_watchpoints(&snapshot)
    }

    /// 等待下一个调试事件（轮询 waitpid，超时返回 None）。
    pub fn wait(&self, timeout_ms: u64) -> Option<DebugEvent> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        loop {
            let mut status = 0;
            let w = unsafe { libc::waitpid(self.pid as libc::pid_t, &mut status, libc::WNOHANG) };
            if w == self.pid as libc::pid_t {
                if libc::WIFSTOPPED(status) {
                    let sig = libc::WSTOPSIG(status);
                    let thread_id = self.pid;
                    match sig {
                        libc::SIGTRAP => {
                            // 软断点命中（INT3）或单步完成：读 RIP 判定。
                            let Ok(regs) = get_regs(self.pid) else {
                                return None;
                            };
                            let rip = regs.rip;
                            // INT3 不自动回退：若 [rip-1] 是 CC 则为断点。
                            let is_bp = peek_u64(self.pid, (rip - 1) & !7)
                                .map(|w| ((w >> (((rip - 1) & 7) * 8)) & 0xFF) as u8 == INT3)
                                .unwrap_or(false);
                            return Some(DebugEvent {
                                kind: if is_bp { "breakpoint".to_string() } else { "single_step".to_string() },
                                thread_id,
                                address: if is_bp { rip - 1 } else { rip },
                                code: sig as u32,
                                access: None,
                            });
                        }
                        libc::SIGSEGV | libc::SIGBUS => {
                            return Some(DebugEvent {
                                kind: "access_violation".to_string(),
                                thread_id: self.pid,
                                address: 0,
                                code: sig as u32,
                                access: None,
                            });
                        }
                        _ => {
                            return Some(DebugEvent {
                                kind: "exception".to_string(),
                                thread_id: self.pid,
                                address: 0,
                                code: sig as u32,
                                access: None,
                            });
                        }
                    }
                }
                if libc::WIFEXITED(status) {
                    return None;
                }
            }
            if std::time::Instant::now() > deadline {
                return None;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// 继续执行（PTRACE_CONT）。
    pub fn continue_execution(&self) {
        unsafe {
            libc::ptrace(libc::PTRACE_CONT, self.pid as libc::pid_t, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>());
        }
    }

    /// 单步一条指令（PTRACE_SINGLESTEP）。
    pub fn single_step(&self, _thread_id: u32) -> Result<(), String> {
        unsafe {
            libc::ptrace(libc::PTRACE_SINGLESTEP, self.pid as libc::pid_t, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>());
        }
        Ok(())
    }

    pub fn registers(&self, _thread_id: u32) -> Result<Registers, String> {
        Ok(regs_to_ce(get_regs(self.pid)?))
    }

    pub fn set_registers(&self, _thread_id: u32, regs: &Registers) -> Result<(), String> {
        let mut u = get_regs(self.pid)?;
        u.rip = regs.rip;
        u.rax = regs.rax;
        u.rbx = regs.rbx;
        u.rcx = regs.rcx;
        u.rdx = regs.rdx;
        u.rsi = regs.rsi;
        u.rdi = regs.rdi;
        u.rsp = regs.rsp;
        u.rbp = regs.rbp;
        u.r8 = regs.r8;
        u.r9 = regs.r9;
        u.r10 = regs.r10;
        u.r11 = regs.r11;
        u.r12 = regs.r12;
        u.r13 = regs.r13;
        u.r14 = regs.r14;
        u.r15 = regs.r15;
        u.eflags = regs.eflags as u64;
        set_regs(self.pid, &u)
    }

    /// 调用栈回溯（RBP 链）。
    pub fn stack(&self, _thread_id: u32, max_frames: usize) -> Result<Vec<StackFrame>, String> {
        let u = get_regs(self.pid)?;
        let mut frames = Vec::new();
        let mut rbp = u.rbp;
        let mut rip = u.rip;
        let mut rsp = u.rsp;
        for _ in 0..max_frames {
            frames.push(StackFrame { rip, rbp, rsp });
            let (Ok(next_rbp), Ok(ret)) = (peek_u64(self.pid, rbp), peek_u64(self.pid, rbp.wrapping_add(8))) else {
                break;
            };
            if next_rbp == 0 || next_rbp <= rbp || ret == 0 {
                break;
            }
            rbp = next_rbp;
            rip = ret;
            rsp = rbp.wrapping_add(16);
        }
        Ok(frames)
    }

    fn apply_watchpoints(&self, wps: &[Option<(Address, u8, bool, bool)>; 4]) -> Result<(), String> {
        // DR0-DR3 地址，DR7 控制字（x86_64 Linux user 结构偏移）。
        for i in 0..4 {
            let v = wps[i].map(|w| w.0).unwrap_or(0);
            poke_user(self.pid, 0x50 + 8 * i, v)?;
        }
        let mut dr7 = 0u64;
        for (i, wp) in wps.iter().enumerate() {
            if let Some((_, size, on_read, on_write)) = wp {
                let rw: u64 = if *on_write && !*on_read { 1 } else { 3 };
                let len_code: u64 = match size {
                    1 => 0,
                    2 => 1,
                    4 => 3,
                    8 => 2,
                    _ => 0,
                };
                dr7 |= 1 << (2 * i);
                dr7 |= rw << (16 + 4 * i);
                dr7 |= len_code << (18 + 4 * i);
            }
        }
        poke_user(self.pid, 0x88, dr7)?; // DR7
        Ok(())
    }
}

impl Drop for Debugger {
    fn drop(&mut self) {
        // 还原所有断点。
        let bps: Vec<(Address, u8)> = self
            .breakpoints
            .lock()
            .unwrap()
            .iter()
            .map(|(a, b)| (*a, *b))
            .collect();
        for (addr, orig) in bps {
            let base = addr & !7;
            if let Ok(cur) = peek_u64(self.pid, base) {
                let new = (cur & !(0xFFu64 << ((addr & 7) * 8))) | ((orig as u64) << ((addr & 7) * 8));
                let _ = poke_u64(self.pid, base, new);
            }
        }
        self.breakpoints.lock().unwrap().clear();
        // 清除监视点（DR7 = 0）。
        let _ = poke_user(self.pid, 0x88, 0);
        unsafe {
            libc::ptrace(libc::PTRACE_DETACH, self.pid as libc::pid_t, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>());
        }
    }
}

fn get_regs(pid: u32) -> Result<libc::user_regs_struct, String> {
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid as libc::pid_t,
            std::ptr::null_mut::<libc::c_void>(),
            &mut regs as *mut _ as *mut libc::c_void,
        )
    };
    if rc != 0 {
        return Err("PTRACE_GETREGS failed".to_string());
    }
    Ok(regs)
}

fn set_regs(pid: u32, regs: &libc::user_regs_struct) -> Result<(), String> {
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGS,
            pid as libc::pid_t,
            std::ptr::null_mut::<libc::c_void>(),
            regs as *const _ as *mut libc::c_void,
        )
    };
    if rc != 0 {
        return Err("PTRACE_SETREGS failed".to_string());
    }
    Ok(())
}

/// PTRACE_POKEUSER（写 debug 寄存器等用户区字段）。
fn poke_user(pid: u32, offset: usize, value: u64) -> Result<(), String> {
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_POKEUSER,
            pid as libc::pid_t,
            offset as *mut libc::c_void,
            value as *mut libc::c_void,
        )
    };
    if rc != 0 {
        return Err(format!("PTRACE_POKEUSER failed at offset 0x{offset:x}"));
    }
    Ok(())
}

fn regs_to_ce(u: libc::user_regs_struct) -> Registers {
    Registers {
        rip: u.rip,
        rax: u.rax,
        rbx: u.rbx,
        rcx: u.rcx,
        rdx: u.rdx,
        rsi: u.rsi,
        rdi: u.rdi,
        rsp: u.rsp,
        rbp: u.rbp,
        r8: u.r8,
        r9: u.r9,
        r10: u.r10,
        r11: u.r11,
        r12: u.r12,
        r13: u.r13,
        r14: u.r14,
        r15: u.r15,
        eflags: u.eflags as u32,
    }
}
