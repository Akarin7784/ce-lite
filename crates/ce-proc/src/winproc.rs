//! Windows 进程后端（M1）：
//! `OpenProcess` + `ReadProcessMemory`/`WriteProcessMemory` + `VirtualQueryEx`
//! + Toolhelp 进程枚举。

use std::mem::size_of;
use std::os::raw::c_void;

use ce_core::{Address, Arch, MemoryRegion, ModuleInfo, ProcessInfo};

use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    CREATE_TOOLHELP_SNAPSHOT_FLAGS, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION,
    PAGE_PROTECTION_FLAGS, MEM_RELEASE, VIRTUAL_ALLOCATION_TYPE,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, OpenProcess, WaitForSingleObject,
    LPTHREAD_START_ROUTINE, PROCESS_ACCESS_RIGHTS, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

use super::{Process, ProcessError};

// Win32 保护常量（文档值；避免 crate 重复导出的歧义）。
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;

pub struct WindowsProcess {
    pid: u32,
    handle: HANDLE,
    info: ProcessInfo,
    /// 区域枚举缓存（TTL 2 秒，扫描/区域查询复用；内存布局变化不频繁）。
    regions_cache: std::sync::Mutex<Option<(std::time::Instant, Vec<MemoryRegion>)>>,
}

// `HANDLE` 是裸指针包装、默认非 `Send`/`Sync`；Windows 的跨进程内存 API
// （ReadProcessMemory/WriteProcessMemory/VirtualQueryEx）支持并发调用，
// 因此进程句柄可以安全地跨线程共享。
unsafe impl Send for WindowsProcess {}
unsafe impl Sync for WindowsProcess {}

pub fn open(pid: u32) -> Result<Box<dyn Process>, ProcessError> {
    let access =
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
    let handle = unsafe { OpenProcess(access, false, pid) }
        .map_err(|e| classify_open_error(e, pid))?;

    let name = enumerate()
        .ok()
        .and_then(|list| {
            list.into_iter()
                .find(|(p, _)| *p == pid)
                .map(|(_, n)| n)
        })
        .unwrap_or_default();

    // 位宽检测：读主模块 PE 头的机器类型（0x14c = i386，0x8664 = x64）。
    let (arch, pointer_size) = detect_arch(handle, pid).unwrap_or((Arch::X64, 8));

    let info = ProcessInfo {
        pid,
        name,
        arch,
        pointer_size,
    };

    Ok(Box::new(WindowsProcess {
        pid,
        handle,
        info,
        regions_cache: std::sync::Mutex::new(None),
    }))
}

/// 通过主模块 PE 头判定目标位宽（Wow64 进程返回 32 位）。
pub(crate) fn detect_arch(handle: HANDLE, pid: u32) -> Option<(Arch, u8)> {
    unsafe {
        // Toolhelp 拿第一个模块基址（主模块）。
        let snap = CreateToolhelp32Snapshot(
            CREATE_TOOLHELP_SNAPSHOT_FLAGS(TH32CS_SNAPMODULE.0 | TH32CS_SNAPMODULE32.0),
            pid,
        )
        .ok()?;
        let mut entry = MODULEENTRY32W {
            dwSize: size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };
        if Module32FirstW(snap, &mut entry).is_err() {
            let _ = CloseHandle(snap);
            return None;
        }
        let base = entry.modBaseAddr as usize as u64;
        let _ = CloseHandle(snap);

        // 读 DOS 头 → e_lfanew → PE 头 → 机器类型。
        let mut dos = [0u8; 64];
        let mut nread = 0usize;
        ReadProcessMemory(
            handle,
            base as *const c_void,
            dos.as_mut_ptr() as *mut c_void,
            64,
            Some(&mut nread),
        )
        .ok()?;
        if nread < 64 || dos[0] != b'M' || dos[1] != b'Z' {
            return None;
        }
        let pe_off = u32::from_le_bytes(dos[0x3C..0x40].try_into().ok()?);
        let mut pe = [0u8; 8];
        ReadProcessMemory(
            handle,
            (base + pe_off as u64) as *const c_void,
            pe.as_mut_ptr() as *mut c_void,
            8,
            Some(&mut nread),
        )
        .ok()?;
        if nread < 8 || pe[0..4] != [b'P', b'E', 0, 0] {
            return None;
        }
        let machine = u16::from_le_bytes([pe[4], pe[5]]);
        match machine {
            0x14C => Some((Arch::X86, 4)),  // i386
            0x8664 => Some((Arch::X64, 8)), // x86-64
            _ => None,
        }
    }
}

pub fn list_processes() -> Result<Vec<ProcessInfo>, ProcessError> {
    Ok(enumerate()?
        .into_iter()
        .map(|(pid, name)| ProcessInfo {
            pid,
            name,
            arch: Arch::X64,
            pointer_size: 8,
        })
        .collect())
}

/// 枚举全部进程 (pid, 可执行文件名)。
fn enumerate() -> Result<Vec<(u32, String)>, ProcessError> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| ProcessError::Platform(e.to_string()))?;

        let mut out = Vec::new();
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(&entry.szExeFile)
                    .trim_end_matches('\0')
                    .to_string();
                out.push((entry.th32ProcessID, name));
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snap);
        Ok(out)
    }
}

fn is_readable(p: u32) -> bool {
    matches!(
        p & 0xFF,
        PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY
    )
}

fn is_writable(p: u32) -> bool {
    matches!(
        p & 0xFF,
        PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}

fn is_executable(p: u32) -> bool {
    matches!(
        p & 0xFF,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}

impl Process for WindowsProcess {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn info(&self) -> ProcessInfo {
        self.info.clone()
    }

    fn regions(&self) -> Result<Vec<MemoryRegion>, ProcessError> {
        // TTL 缓存：2 秒内复用上次枚举结果。
        if let Ok(guard) = self.regions_cache.lock() {
            if let Some((at, cached)) = guard.as_ref() {
                if at.elapsed() < std::time::Duration::from_secs(2) {
                    return Ok(cached.clone());
                }
            }
        }

        let regions = self.enumerate_regions()?;
        if let Ok(mut guard) = self.regions_cache.lock() {
            *guard = Some((std::time::Instant::now(), regions.clone()));
        }
        Ok(regions)
    }

    fn read(&self, address: Address, size: usize) -> Result<Vec<u8>, ProcessError> {
        let mut buf = vec![0u8; size];
        let mut nread = 0usize;
        unsafe {
            ReadProcessMemory(
                self.handle,
                address as usize as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                size,
                Some(&mut nread),
            )
            .map_err(|e| ProcessError::Read { address, reason: e.to_string() })?;
        }
        buf.truncate(nread);
        Ok(buf)
    }

    fn write(&self, address: Address, bytes: &[u8]) -> Result<usize, ProcessError> {
        let mut nwritten = 0usize;
        unsafe {
            // 临时把页面改为可执行+可写（代码页补丁/内联钩子需要），写完恢复原保护。
            let mut old = PAGE_PROTECTION_FLAGS(0);
            let _ = VirtualProtectEx(
                self.handle,
                address as *const c_void,
                bytes.len(),
                PAGE_PROTECTION_FLAGS(PAGE_EXECUTE_READWRITE),
                &mut old,
            );
            let r = WriteProcessMemory(
                self.handle,
                address as usize as *const c_void,
                bytes.as_ptr() as *const c_void,
                bytes.len(),
                Some(&mut nwritten),
            );
            let mut dummy = PAGE_PROTECTION_FLAGS(0);
            let _ = VirtualProtectEx(
                self.handle,
                address as *const c_void,
                bytes.len(),
                old,
                &mut dummy,
            );
            r.map_err(|e| ProcessError::Write { address, reason: e.to_string() })?;
        }
        Ok(nwritten)
    }

    fn alloc(&self, size: usize) -> Result<Address, ProcessError> {
        let addr = unsafe {
            VirtualAllocEx(
                self.handle,
                None,
                size,
                VIRTUAL_ALLOCATION_TYPE(MEM_COMMIT | MEM_RESERVE),
                PAGE_PROTECTION_FLAGS(PAGE_EXECUTE_READWRITE),
            )
        };
        if addr.is_null() {
            return Err(ProcessError::Alloc("VirtualAllocEx returned null".to_string()));
        }
        Ok(addr as usize as u64)
    }

    fn modules(&self) -> Result<Vec<ModuleInfo>, ProcessError> {
        unsafe {
            let flags =
                CREATE_TOOLHELP_SNAPSHOT_FLAGS(TH32CS_SNAPMODULE.0 | TH32CS_SNAPMODULE32.0);
            let snap = CreateToolhelp32Snapshot(flags, self.pid)
                .map_err(|e| ProcessError::Platform(e.to_string()))?;

            let mut out = Vec::new();
            let mut entry = MODULEENTRY32W {
                dwSize: size_of::<MODULEENTRY32W>() as u32,
                ..Default::default()
            };

            if Module32FirstW(snap, &mut entry).is_ok() {
                loop {
                    let name = String::from_utf16_lossy(&entry.szModule)
                        .trim_end_matches('\0')
                        .to_string();
                    let path = String::from_utf16_lossy(&entry.szExePath)
                        .trim_end_matches('\0')
                        .to_string();
                    out.push(ModuleInfo {
                        name,
                        path,
                        base: entry.modBaseAddr as usize as u64,
                        size: entry.modBaseSize as u64,
                    });
                    if Module32NextW(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snap);
            Ok(out)
        }
    }

    #[cfg(target_os = "windows")]
    fn raw_handle(&self) -> Option<windows::Win32::Foundation::HANDLE> {
        Some(self.handle)
    }
}

impl WindowsProcess {
    /// 无缓存的区域枚举（`regions()` 的底层实现）。
    fn enumerate_regions(&self) -> Result<Vec<MemoryRegion>, ProcessError> {
        let mut regions = Vec::new();
        let mut addr: usize = 0;

        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let n = unsafe {
                VirtualQueryEx(
                    self.handle,
                    Some(addr as *const c_void),
                    &mut mbi,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if n == 0 {
                break;
            }

            let base = mbi.BaseAddress as usize;
            let size = mbi.RegionSize;
            if mbi.State.0 == MEM_COMMIT {
                let p = mbi.Protect.0;
                regions.push(MemoryRegion {
                    base: base as u64,
                    size: size as u64,
                    protection: p,
                    readable: is_readable(p),
                    writable: is_writable(p),
                    executable: is_executable(p),
                    name: None,
                });
            }

            let next = base.checked_add(size);
            match next {
                Some(n) if n > addr => addr = n,
                _ => break,
            }
        }

        Ok(regions)
    }
}

impl Drop for WindowsProcess {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

// ---- 防护：错误分类 ----

/// 把 `OpenProcess` 失败分类为语义化错误（区分不存在 / 权限不足 / 其它）。
fn classify_open_error(e: windows::core::Error, pid: u32) -> ProcessError {
    let code = (e.code().0 as u32) & 0xFFFF;
    match code {
        // ERROR_ACCESS_DENIED：可能是受保护进程（PPL / 反作弊）。
        5 => ProcessError::AccessDenied { pid },
        // ERROR_INVALID_PARAMETER / ERROR_NOT_FOUND：进程不存在或已退出。
        87 | 1168 => ProcessError::NotFound { pid },
        _ => ProcessError::Platform(format!("OpenProcess failed (win32 error {code:#x}): {e}")),
    }
}

// ---- 防护：反作弊感知 ----

/// 已知反作弊清单：(显示名, 用户态进程名, 是否附带内核驱动组件)。
const ANTI_CHEATS: &[(&str, &str, bool)] = &[
    ("EasyAntiCheat", "EasyAntiCheat.exe", true),
    ("EasyAntiCheat", "EasyAntiCheatService.exe", true),
    ("BattlEye", "BEService.exe", true),
    ("BattlEye", "BattlEye.exe", true),
    ("Riot Vanguard", "vgc.exe", true),
    ("Riot Vanguard", "vgtray.exe", true),
    ("Tencent ACE", "ACE-BASE.exe", true),
    ("Tencent ACE", "ACE-GAME.exe", true),
    ("Tencent ACE", "ACENDA.exe", true),
    ("Tencent ACE", "TenProtect.exe", true),
    ("nProtect GameGuard", "GameMon.des", true),
    ("nProtect GameGuard", "npggNT.des", true),
    ("XIGNCODE3", "XIGNCODE3.exe", true),
    ("XIGNCODE3", "XIGNCODE32.exe", true),
    ("PunkBuster", "PnkBstrA.exe", true),
    ("PunkBuster", "PnkBstrB.exe", true),
    ("Denuvo Anti-Cheat", "denuvo-anti-cheat.exe", true),
    ("FACEIT Anti-Cheat", "FACEIT.exe", true),
    ("FACEIT Anti-Cheat", "FACEIT-SDK.exe", true),
];

/// 枚举当前运行的已知反作弊进程（防护：附加目标前先探测）。
pub fn detect_anti_cheats() -> Vec<ce_core::AntiCheatInfo> {
    let Ok(list) = enumerate() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (pid, name) in list {
        let lower = name.to_lowercase();
        for (ac_name, proc_name, kernel) in ANTI_CHEATS {
            if lower == proc_name.to_lowercase() {
                out.push(ce_core::AntiCheatInfo {
                    name: ac_name.to_string(),
                    process: name.clone(),
                    pid,
                    kernel: *kernel,
                });
            }
        }
    }
    out
}

// ---- 分析：远程线程注入 ----

/// 注入所需的进程访问权限（含创建远程线程）。
fn inject_access() -> PROCESS_ACCESS_RIGHTS {
    PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE
}

/// 在已打开的进程句柄上创建远程线程并等待完成。
fn run_remote_thread_on(
    handle: HANDLE,
    routine: LPTHREAD_START_ROUTINE,
    arg: Option<*const c_void>,
    timeout_ms: u64,
) -> Result<ce_core::RemoteThreadResult, ProcessError> {
    let mut thread_id = 0u32;
    let thread = unsafe {
        CreateRemoteThread(handle, None, 0, routine, arg, 0, Some(&mut thread_id)).map_err(|e| {
            ProcessError::Other(format!(
                "CreateRemoteThread failed (win32 error {:#x}): {e}",
                (e.code().0 as u32) & 0xFFFF
            ))
        })?
    };

    let wait = unsafe { WaitForSingleObject(thread, timeout_ms.min(u32::MAX as u64) as u32) };
    let completed = wait.0 == WAIT_OBJECT_0.0;
    let mut exit_code = 0u32;
    if completed {
        let _ = unsafe { GetExitCodeThread(thread, &mut exit_code) };
    }
    unsafe { let _ = CloseHandle(thread); }

    Ok(ce_core::RemoteThreadResult {
        thread_id,
        completed,
        exit_code,
    })
}

/// DLL 注入：远程线程执行目标进程内的 `LoadLibraryW(path)`。
///
/// 依赖 x64 下 kernel32 在所有进程同基址加载（仅支持同位数 x64 目标）。
pub fn inject_dll(
    pid: u32,
    path: &str,
    timeout_ms: u64,
) -> Result<ce_core::RemoteThreadResult, ProcessError> {
    let kernel32 = unsafe { GetModuleHandleW(windows::core::w!("kernel32.dll")) }
        .map_err(|e| ProcessError::Other(format!("GetModuleHandleW(kernel32): {e}")))?;
    let loadlib = unsafe { GetProcAddress(kernel32, windows::core::s!("LoadLibraryW")) };
    let Some(loadlib) = loadlib else {
        return Err(ProcessError::Other(
            "LoadLibraryW not found in kernel32".to_string(),
        ));
    };
    // FARPROC(Option<fn() -> isize>) → LPTHREAD_START_ROUTINE(Option<fn(*mut c_void) -> u32>)。
    let routine: LPTHREAD_START_ROUTINE = unsafe { std::mem::transmute(loadlib) };

    let handle = unsafe { OpenProcess(inject_access(), false, pid) }
        .map_err(|e| classify_open_error(e, pid))?;

    // 远程分配并写入宽字符串路径。
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let size = wide.len() * 2;
    let mem = unsafe {
        VirtualAllocEx(
            handle,
            None,
            size,
            VIRTUAL_ALLOCATION_TYPE(MEM_COMMIT | MEM_RESERVE),
            PAGE_PROTECTION_FLAGS(PAGE_READWRITE),
        )
    };
    if mem.is_null() {
        unsafe { let _ = CloseHandle(handle); }
        return Err(ProcessError::Alloc(
            "VirtualAllocEx for dll path failed".to_string(),
        ));
    }
    let mut written = 0usize;
    unsafe {
        WriteProcessMemory(
            handle,
            mem as *const c_void,
            wide.as_ptr() as *const c_void,
            size,
            Some(&mut written),
        )
        .map_err(|e| ProcessError::Write {
            address: mem as u64,
            reason: format!("WriteProcessMemory for dll path: {e}"),
        })?
    }

    let result = run_remote_thread_on(handle, routine, Some(mem as *const c_void), timeout_ms);
    // 线程完成则释放远程路径内存；超时则保留（线程可能仍在运行）。
    if result.as_ref().map(|r| r.completed).unwrap_or(false) {
        unsafe { let _ = VirtualFreeEx(handle, mem, 0, MEM_RELEASE); }
    }
    unsafe { let _ = CloseHandle(handle); }
    result
}

/// 代码注入：在目标进程内分配可执行内存，写入字节码并以远程线程执行。
///
/// `code` 为 x64 位置无关 shellcode（可用 `ce_asm` 生成），须以 `ret` 结尾；
/// 返回时退出码即线程返回值。线程未在超时内完成时返回 `completed: false`，
/// 分配的内存会保留（线程可能仍在运行），由调用方决定是否重试。
pub fn create_remote(
    pid: u32,
    code: &[u8],
    arg: u64,
    timeout_ms: u64,
) -> Result<ce_core::RemoteThreadResult, ProcessError> {
    let handle = unsafe { OpenProcess(inject_access(), false, pid) }
        .map_err(|e| classify_open_error(e, pid))?;

    let mem = unsafe {
        VirtualAllocEx(
            handle,
            None,
            code.len(),
            VIRTUAL_ALLOCATION_TYPE(MEM_COMMIT | MEM_RESERVE),
            PAGE_PROTECTION_FLAGS(PAGE_EXECUTE_READWRITE),
        )
    };
    if mem.is_null() {
        unsafe { let _ = CloseHandle(handle); }
        return Err(ProcessError::Alloc(
            "VirtualAllocEx for shellcode failed".to_string(),
        ));
    }
    let mut written = 0usize;
    unsafe {
        WriteProcessMemory(
            handle,
            mem as *const c_void,
            code.as_ptr() as *const c_void,
            code.len(),
            Some(&mut written),
        )
        .map_err(|e| ProcessError::Write {
            address: mem as u64,
            reason: format!("WriteProcessMemory for shellcode: {e}"),
        })?
    }

    // 裸指针 → 线程入口函数指针（同为 8 字节，transmute 转换）。
    let routine: LPTHREAD_START_ROUTINE =
        Some(unsafe { std::mem::transmute::<*mut c_void, unsafe extern "system" fn(*mut c_void) -> u32>(mem) });
    let result = run_remote_thread_on(handle, routine, Some(arg as *const c_void), timeout_ms);
    if result.as_ref().map(|r| r.completed).unwrap_or(false) {
        unsafe { let _ = VirtualFreeEx(handle, mem, 0, MEM_RELEASE); }
    }
    unsafe { let _ = CloseHandle(handle); }
    result
}
