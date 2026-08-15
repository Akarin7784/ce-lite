//! 进程抽象与平台后端分派。

use ce_core::{Address, MemoryRegion, ModuleInfo, ProcessInfo};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("process {pid} not found")]
    NotFound { pid: u32 },
    #[error("process {pid} is not accessible: access denied (needs elevation, or the process may be PPL/protected by anti-cheat)")]
    AccessDenied { pid: u32 },
    #[error("read failed at 0x{address:x}: {reason}")]
    Read { address: Address, reason: String },
    #[error("write failed at 0x{address:x}: {reason}")]
    Write { address: Address, reason: String },
    #[error("allocate failed: {0}")]
    Alloc(String),
    #[error("platform error: {0}")]
    Platform(String),
    #[error("{0}")]
    Other(String),
}

/// 跨进程访问的统一抽象。
///
/// `Send + Sync`：扫描/分析可能在 rayon 工作线程上并发访问同一个进程句柄；
/// Windows/Linux 的内存读写 API 均支持并发调用。
pub trait Process: Send + Sync {
    fn pid(&self) -> u32;
    fn info(&self) -> ProcessInfo;
    /// 枚举可读内存区域（`VirtualQueryEx` / `/proc/PID/maps`）。
    fn regions(&self) -> Result<Vec<MemoryRegion>, ProcessError>;
    /// 从 `address` 起读取 `size` 字节。
    fn read(&self, address: Address, size: usize) -> Result<Vec<u8>, ProcessError>;
    /// 向 `address` 写入字节，返回实际写入长度。
    fn write(&self, address: Address, bytes: &[u8]) -> Result<usize, ProcessError>;
    /// 在目标进程内分配可执行内存（M2）。
    fn alloc(&self, size: usize) -> Result<Address, ProcessError>;
    /// 枚举目标进程已加载模块（主模块 + DLL）。默认空；平台后端覆盖。
    fn modules(&self) -> Result<Vec<ModuleInfo>, ProcessError> {
        Ok(Vec::new())
    }

    /// 平台原生进程句柄（Windows：HANDLE；供 PDB 符号引擎等原生能力使用）。
    #[cfg(target_os = "windows")]
    fn raw_handle(&self) -> Option<windows::Win32::Foundation::HANDLE> {
        None
    }
}

#[cfg(target_os = "windows")]
pub fn open(pid: u32) -> Result<Box<dyn Process>, ProcessError> {
    crate::winproc::open(pid)
}

#[cfg(target_os = "linux")]
pub fn open(pid: u32) -> Result<Box<dyn Process>, ProcessError> {
    crate::linux::open(pid)
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn open(_pid: u32) -> Result<Box<dyn Process>, ProcessError> {
    Err(ProcessError::Other("unsupported platform".to_string()))
}

#[cfg(target_os = "windows")]
pub fn list_processes() -> Result<Vec<ProcessInfo>, ProcessError> {
    crate::winproc::list_processes()
}

#[cfg(target_os = "linux")]
pub fn list_processes() -> Result<Vec<ProcessInfo>, ProcessError> {
    crate::linux::list_processes()
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn list_processes() -> Result<Vec<ProcessInfo>, ProcessError> {
    Err(ProcessError::Other("unsupported platform".to_string()))
}
