//! 汇编（mnemonic → 机器码），基于 `keystone-engine`。
//!
//! 纯功能、平台无关（keystone 在构建时从源码编译进本 crate）。
//! 对应 Cheat Engine 的 `Assemblerunit.pas`，但用 keystone 替代手写汇编器。
//!
//! Linux 交叉目标不编译 keystone（其 C 构建脚本无法交叉编译），`assemble`
//! 在 Linux 上返回明确的"不支持"错误；AI 可改用手写字节补丁。

#[cfg(not(target_os = "linux"))]
use keystone_engine::{Arch, Keystone, Mode, OptionType, OptionValue};

/// 把 NASM 语法的汇编代码编码为机器码字节。
///
/// `bitness` 取 32 或 64。
#[cfg(not(target_os = "linux"))]
pub fn assemble(code: &str, bitness: u32) -> Result<Vec<u8>, String> {
    let mode = if bitness == 64 {
        Mode::MODE_64
    } else {
        Mode::MODE_32
    };
    let engine = Keystone::new(Arch::X86, mode).map_err(|e| format!("keystone init: {e}"))?;
    engine
        .option(OptionType::SYNTAX, OptionValue::SYNTAX_NASM)
        .map_err(|e| format!("keystone option: {e}"))?;
    let output = engine
        .asm(code.to_string(), 0)
        .map_err(|e| format!("assemble failed: {e}"))?;
    Ok(output.bytes)
}

/// Linux 目标：keystone 不参与交叉编译，返回明确的平台限制错误。
#[cfg(target_os = "linux")]
pub fn assemble(_code: &str, _bitness: u32) -> Result<Vec<u8>, String> {
    Err("asm not supported on linux (keystone not cross-compiled)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembles_nop_ret() {
        assert_eq!(assemble("nop", 64).unwrap(), vec![0x90]);
        assert_eq!(assemble("ret", 64).unwrap(), vec![0xC3]);
    }

    #[test]
    fn assembles_mov_imm() {
        // mov eax, 0x10 => B8 10 00 00 00
        assert_eq!(assemble("mov eax, 0x10", 64).unwrap(), vec![0xB8, 0x10, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn invalid_instruction_errors() {
        assert!(assemble("this is not an instruction", 64).is_err());
    }
}
