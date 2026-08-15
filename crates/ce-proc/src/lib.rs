//! `ce-proc` — 平台层：进程打开、内存读写、区域枚举、远端分配。
//!
//! 所有系统 I/O 都经由 `Process` trait，`ce-core` 不感知平台。

pub mod process;

#[cfg(target_os = "windows")]
pub mod winproc;

#[cfg(target_os = "windows")]
pub mod debug;

#[cfg(target_os = "linux")]
pub mod linux;

pub use process::{list_processes, open, Process, ProcessError};

#[cfg(target_os = "windows")]
pub use winproc::{create_remote, detect_anti_cheats, inject_dll};

/// 桥接：任何 `dyn Process`（任意对象生命周期）都可作为 `ce-core` 扫描器的内存源。
impl<'a> ce_core::scan::ScanMemory for dyn Process + 'a {
    fn read_into(&self, addr: ce_core::Address, out: &mut [u8]) -> bool {
        match self.read(addr, out.len()) {
            Ok(bytes) => {
                out.copy_from_slice(&bytes);
                true
            }
            Err(_) => false,
        }
    }

    fn readable_regions(&self) -> Vec<ce_core::MemoryRegion> {
        self.regions().unwrap_or_default()
    }
}
