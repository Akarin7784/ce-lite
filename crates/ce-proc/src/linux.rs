//! Linux 进程后端（后续里程碑）：`/proc/{pid}/mem` + `ptrace`。

use ce_core::{Address, MemoryRegion, ProcessInfo};

use super::{Process, ProcessError};

pub fn open(_pid: u32) -> Result<Box<dyn Process>, ProcessError> {
    Err(ProcessError::Other(
        "Linux backend not implemented (M1 is Windows-first)".to_string(),
    ))
}

pub fn list_processes() -> Result<Vec<ProcessInfo>, ProcessError> {
    Err(ProcessError::Other(
        "Linux backend not implemented (M1 is Windows-first)".to_string(),
    ))
}

// 占位：保证 trait 形状在 Linux 上仍可见（实现时填充）。
#[allow(dead_code)]
struct LinuxProcess {
    pid: u32,
    mem_path: std::path::PathBuf,
    _regions: Vec<MemoryRegion>,
    _address: Address,
}
