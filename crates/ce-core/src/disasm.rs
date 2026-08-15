//! 反汇编封装：基于 `iced-x86` 的 x86/x64 解码。
//!
//! 纯函数、平台无关。对应 Cheat Engine 手写的 `disassembler.pas`，
//! 但这里用成熟库替代（省去约 1.6 万行手写解码逻辑）。

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};

use crate::{Address, DisasmResult};

/// 从 `code`（起始地址 `ip`）顺序解码，直到耗尽字节。
///
/// `bitness` 取 32 或 64。
pub fn decode(code: &[u8], ip: Address, bitness: u32) -> Vec<DisasmResult> {
    let mut decoder = Decoder::with_ip(bitness, code, ip, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut results = Vec::new();
    let mut text = String::new();

    while decoder.can_decode() {
        let mut instr = Instruction::default();
        decoder.decode_out(&mut instr);
        text.clear();
        formatter.format(&instr, &mut text);

        let len = instr.len();
        let start = (instr.ip() - ip) as usize;
        let end = (start + len).min(code.len());
        results.push(DisasmResult {
            address: instr.ip(),
            bytes: code[start..end].to_vec(),
            text: text.clone(),
        });
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_x64_sequence() {
        // mov eax, 0x10 (B8 10 00 00 00) + ret (C3)
        let code = [0xB8, 0x10, 0x00, 0x00, 0x00, 0xC3];
        let out = decode(&code, 0x400000, 64);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].address, 0x400000);
        assert_eq!(out[0].bytes, vec![0xB8, 0x10, 0x00, 0x00, 0x00]);
        assert!(out[0].text.contains("eax"));
        assert_eq!(out[1].address, 0x400005);
        assert_eq!(out[1].text, "ret");
    }
}
