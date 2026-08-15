//! 反汇编封装：基于 `iced-x86` 的 x86/x64 解码。
//!
//! 纯函数、平台无关。对应 Cheat Engine 手写的 `disassembler.pas`，
//! 但这里用成熟库替代（省去约 1.6 万行手写解码逻辑）。

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter};

use crate::scan::ScanMemory;
use crate::{Address, DisasmResult, FunctionInfo};

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

/// 查找所有直接调用 `target` 的 call 指令（E8 rel32 / FF /2 等）。
///
/// 扫描全部可读可执行区域，按 1 字节滑动解码（不错过未对齐指令），
/// 命中上限 `limit` 即返回。
pub fn xrefs<M: ScanMemory + ?Sized>(
    mem: &M,
    target: Address,
    bitness: u32,
    limit: usize,
) -> Vec<DisasmResult> {
    let mut out = Vec::new();
    let chunk = 64 * 1024usize;
    let mut formatter = IntelFormatter::new();

    for region in mem
        .readable_regions()
        .iter()
        .filter(|r| r.readable && r.executable)
    {
        let start = region.base;
        let size = region.size.min(1 << 30) as usize;
        let mut off = 0usize;
        while off < size {
            let want = (size - off).min(chunk);
            let mut buf = vec![0u8; want];
            if !mem.read_into(start + off as u64, &mut buf) {
                off += chunk;
                continue;
            }
            let mut i = 0usize;
            while i < buf.len() {
                let ip = start + off as u64 + i as u64;
                let mut decoder =
                    Decoder::with_ip(bitness, &buf[i..], ip, DecoderOptions::NONE);
                let mut instr = Instruction::default();
                decoder.decode_out(&mut instr);
                let len = instr.len();
                if len == 0 {
                    i += 1;
                    continue;
                }
                if matches!(instr.flow_control(), FlowControl::Call)
                    && instr.near_branch_target() == target
                {
                    let mut text = String::new();
                    formatter.format(&instr, &mut text);
                    out.push(DisasmResult {
                        address: ip,
                        bytes: buf[i..i + len].to_vec(),
                        text,
                    });
                    if out.len() >= limit {
                        return out;
                    }
                }
                i += len.max(1);
            }
            off += chunk;
        }
    }
    out
}

/// 从 `address` 识别函数边界（尽力而为）。
///
/// 向前回溯 `max_back` 字节找函数起点（最后一个 `ret`/`int3` padding 的下一字节，
/// 或窗口起点），再从起点向后解码直到 `ret` 或 `max_len` 上限。
pub fn function_boundary<M: ScanMemory + ?Sized>(
    mem: &M,
    address: Address,
    bitness: u32,
    max_back: usize,
    max_len: usize,
) -> Option<FunctionInfo> {
    let back = max_back.max(1);
    let window_start = address.saturating_sub(back as u64);

    // 1) 回溯窗口：找最后一个 ret/int3 padding，起点 = 其后一字节。
    let mut win = vec![0u8; back + 1];
    if !mem.read_into(window_start, &mut win) {
        return None;
    }
    let mut start_rel = 0usize;
    for (i, &b) in win.iter().enumerate() {
        if b == 0xC3 || b == 0xCC {
            start_rel = i + 1;
        }
    }
    let start = window_start + start_rel as u64;

    // 2) 从起点向前解码直到 ret。
    let mut code = vec![0u8; max_len];
    if !mem.read_into(start, &mut code) {
        return None;
    }
    let mut decoder = Decoder::with_ip(bitness, &code, start, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut instructions = Vec::new();
    let mut end = start;
    while decoder.can_decode() && instructions.len() < max_len / 2 {
        let mut instr = Instruction::default();
        decoder.decode_out(&mut instr);
        let len = instr.len();
        if len == 0 {
            break;
        }
        let ip = instr.ip();
        let mut text = String::new();
        formatter.format(&instr, &mut text);
        let bytes = code[(ip - start) as usize..(ip - start) as usize + len].to_vec();
        let is_ret = matches!(instr.flow_control(), FlowControl::Return);
        instructions.push(DisasmResult {
            address: ip,
            bytes,
            text,
        });
        if is_ret {
            end = ip + len as u64;
            break;
        }
    }

    Some(FunctionInfo {
        start,
        end,
        size: (end - start) as usize,
        instructions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryRegion;

    struct FakeMem {
        data: Vec<u8>,
        base: Address,
        executable: bool,
    }

    impl ScanMemory for FakeMem {
        fn read_into(&self, addr: Address, out: &mut [u8]) -> bool {
            let off = match addr.checked_sub(self.base) {
                Some(o) => o as usize,
                None => return false,
            };
            if off + out.len() > self.data.len() {
                return false;
            }
            out.copy_from_slice(&self.data[off..off + out.len()]);
            true
        }
        fn readable_regions(&self) -> Vec<MemoryRegion> {
            vec![MemoryRegion {
                base: self.base,
                size: self.data.len() as u64,
                protection: 0,
                readable: true,
                writable: false,
                executable: self.executable,
                name: None,
            }]
        }
    }

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

    #[test]
    fn xrefs_finds_direct_calls() {
        // FakeMem base = 0x1000：data[i] 对应地址 0x1000+i。
        // target @ 0x4000；两条 call target（E8 rel32）。
        // 地址 0x1000（data[0]）: E8 FB 2F 00 00 → 0x1005 + 0x2FFB = 0x4000
        // 地址 0x2000（data[0x1000]）: E8 FB 1F 00 00 → 0x2005 + 0x1FFB = 0x4000
        let mut data = vec![0x90u8; 0x3000];
        data[0x0000..0x0005].copy_from_slice(&[0xE8, 0xFB, 0x2F, 0x00, 0x00]);
        data[0x1000..0x1005].copy_from_slice(&[0xE8, 0xFB, 0x1F, 0x00, 0x00]);
        let mem = FakeMem {
            data,
            base: 0x1000,
            executable: true,
        };
        let found = xrefs(&mem, 0x4000, 64, 100);
        let addrs: Vec<u64> = found.iter().map(|d| d.address).collect();
        assert_eq!(addrs, vec![0x1000, 0x2000]);
    }

    #[test]
    fn function_boundary_finds_prologue_and_ret() {
        // CC padding + push rbp; mov rbp,rsp; sub rsp,0x10; mov eax,1; ret
        let mut data = vec![0xCCu8; 0x3000];
        let start = 0x100;
        data[start] = 0x55; // push rbp
        data[start + 1] = 0x48;
        data[start + 2] = 0x89;
        data[start + 3] = 0xE5; // mov rbp, rsp
        data[start + 4] = 0x48;
        data[start + 5] = 0x83;
        data[start + 6] = 0xEC;
        data[start + 7] = 0x10; // sub rsp, 0x10
        data[start + 8] = 0xB8;
        data[start + 9] = 0x01;
        data[start + 10] = 0x00;
        data[start + 11] = 0x00;
        data[start + 12] = 0x00; // mov eax, 1
        data[start + 13] = 0xC3; // ret

        let mem = FakeMem {
            data,
            base: 0,
            executable: true,
        };
        let info = function_boundary(&mem, start as u64 + 8, 64, 256, 4096).expect("boundary");
        assert_eq!(info.start, start as u64, "start should skip CC padding");
        assert_eq!(info.end, start as u64 + 14);
        assert_eq!(info.size, 14);
        assert_eq!(info.instructions.len(), 5);
        assert_eq!(info.instructions[0].text, "push rbp");
    }
}
