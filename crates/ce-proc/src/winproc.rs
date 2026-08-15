//! Windows 进程后端（M1）：
//! `OpenProcess` + `ReadProcessMemory`/`WriteProcessMemory` + `VirtualQueryEx`
//! + Toolhelp 进程枚举。

use std::mem::size_of;
use std::os::raw::c_void;

use ce_core::{Address, Arch, MemoryRegion, ModuleInfo, ProcessInfo};

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    CREATE_TOOLHELP_SNAPSHOT_FLAGS, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_PROTECTION_FLAGS,
    VIRTUAL_ALLOCATION_TYPE,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
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
}

pub fn open(pid: u32) -> Result<Box<dyn Process>, ProcessError> {
    let access =
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
    let handle = unsafe { OpenProcess(access, false, pid) }
        .map_err(|_| ProcessError::AccessDenied { pid })?;

    let name = enumerate()
        .ok()
        .and_then(|list| {
            list.into_iter()
                .find(|(p, _)| *p == pid)
                .map(|(_, n)| n)
        })
        .unwrap_or_default();

    let info = ProcessInfo {
        pid,
        name,
        // M1：值扫描不依赖位宽；arch/pointer_size 在 M2（反汇编）时按目标 PE 判定。
        arch: Arch::X64,
        pointer_size: 8,
    };

    Ok(Box::new(WindowsProcess { pid, handle, info }))
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
            WriteProcessMemory(
                self.handle,
                address as usize as *const c_void,
                bytes.as_ptr() as *const c_void,
                bytes.len(),
                Some(&mut nwritten),
            )
            .map_err(|e| ProcessError::Write { address, reason: e.to_string() })?;
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
}

impl Drop for WindowsProcess {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.handle) };
    }
}
