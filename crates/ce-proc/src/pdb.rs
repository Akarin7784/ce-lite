//! PDB 调试符号解析（Windows DbgHelp）。
//!
//! 通过 `SymInitializeW` + `SymFromAddrW` 把地址解析为函数名，
//! 自动加载 PDB / 符号服务器；地址未命中时返回 `None`。

use std::mem::size_of;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::{
    SymCleanup, SymFromAddrW, SymInitializeW, SymSetOptions, SYMBOL_INFOW,
};

/// 反修饰（把 `?UpdateHealth@@...` 还原成 `Player::UpdateHealth`）。
const SYMOPT_UNDECORATE: u32 = 0x2;
const MAX_NAME: usize = 512;

/// 基于目标进程句柄的符号解析器。
///
/// 持有目标进程句柄（与 `WindowsProcess` 共享同一 HANDLE 值）；析构时 `SymCleanup`。
pub struct SymbolResolver {
    handle: HANDLE,
}

impl SymbolResolver {
    /// 初始化符号引擎（`search_path` 可为空串，DbgHelp 会用默认路径 + 符号服务器）。
    pub fn init(handle: HANDLE, search_path: &str) -> Result<SymbolResolver, String> {
        unsafe {
            SymSetOptions(SYMOPT_UNDECORATE);
            let wide: Vec<u16> = search_path
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            SymInitializeW(handle, windows::core::PCWSTR(wide.as_ptr()), false)
                .map_err(|e| format!("SymInitializeW: {e}"))?;
        }
        Ok(SymbolResolver { handle })
    }

    /// 地址 → 函数名；未解析到时返回 `None`。
    pub fn resolve(&self, address: u64) -> Option<String> {
        let mut buf = vec![0u8; size_of::<SYMBOL_INFOW>() + MAX_NAME * 2];
        let symbol = buf.as_mut_ptr() as *mut SYMBOL_INFOW;
        unsafe {
            (*symbol).SizeOfStruct = size_of::<SYMBOL_INFOW>() as u32;
            (*symbol).MaxNameLen = MAX_NAME as u32;
            let mut displacement = 0u64;
            SymFromAddrW(self.handle, address, Some(&mut displacement), symbol).ok()?;
        }
        let sym = unsafe { &*symbol };
        let name_len = (sym.NameLen as usize).min(MAX_NAME);
        let name = unsafe { std::slice::from_raw_parts(sym.Name.as_ptr(), name_len) };
        let s = String::from_utf16_lossy(name)
            .trim_end_matches('\0')
            .to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
}

impl Drop for SymbolResolver {
    fn drop(&mut self) {
        unsafe {
            let _ = SymCleanup(self.handle);
        }
    }
}
