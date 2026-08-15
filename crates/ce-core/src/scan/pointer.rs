//! 指针扫描：找出指向目标地址的指针链。
//!
//! 纯算法、平台无关，对应 Cheat Engine 的 pointerscan 功能。
//! 给定一个值地址（每次启动会变），找到指向它的指针（及其多级上级指针），
//! 再由上层把落在模块内的指针解析成稳定的 `模块 + 偏移`。
//!
//! 去噪手段：
//! 1. **静态过滤**：指针值必须指向已提交的可读内存区域（随机数据落在数值区间
//!    内但不指向有效内存的情况被剔除）。
//! 2. **二次快照**：`chain_stable` 重读每条链各跳的值，只有值不变的才是真指针。

use super::ScanMemory;
use crate::{Address, MemoryRegion, PointerHop};

/// 在可读且非代码的内存区域中，找出指向 `target`（允许 `[target - max_offset, target]`
/// 区间，即带结构体偏移）的指针，并做静态去噪（指针值必须指向有效内存）。
pub fn find_pointers_to<M: ScanMemory + ?Sized>(
    mem: &M,
    target: Address,
    max_offset: u32,
    pointer_size: usize,
) -> Vec<PointerHop> {
    let regions = mem.readable_regions();
    let mut out = Vec::new();

    for region in &regions {
        // 只扫数据区（排除代码区，避免把指令字节误判为指针）。
        if !region.readable || region.executable {
            continue;
        }

        let start = region.base;
        let end = region.base.saturating_add(region.size);
        let mut addr = start;

        while addr.saturating_add(pointer_size as u64) <= end {
            let mut buf = vec![0u8; pointer_size];
            if !mem.read_into(addr, &mut buf) {
                addr = addr.saturating_add(pointer_size as u64);
                continue;
            }
            let pointee = read_little_endian(&buf);
            if pointee <= target
                && target - pointee <= max_offset as u64
                && region_contains(&regions, pointee)
            {
                out.push(PointerHop {
                    pointer_address: addr,
                    offset: (target - pointee) as u32,
                });
            }
            addr = addr.saturating_add(pointer_size as u64);
        }
    }
    out
}

/// 从 `target` 向上做 `max_depth` 层指针扫描，返回所有指针链（含各长度）。
///
/// 每条链是「近目标 → 远」的一串 [`PointerHop`]；`max_chains` 限制结果数量防止爆炸。
pub fn scan<M: ScanMemory + ?Sized>(
    mem: &M,
    target: Address,
    max_offset: u32,
    max_depth: usize,
    pointer_size: usize,
    max_chains: usize,
) -> Vec<Vec<PointerHop>> {
    let mut chains: Vec<Vec<PointerHop>> = Vec::new();
    let mut frontier: Vec<(Address, Vec<PointerHop>)> = vec![(target, Vec::new())];

    for _ in 0..max_depth {
        let mut next_frontier: Vec<(Address, Vec<PointerHop>)> = Vec::new();

        for (t, path) in frontier {
            for hop in find_pointers_to(mem, t, max_offset, pointer_size) {
                let mut new_path = path.clone();
                new_path.push(hop.clone());
                chains.push(new_path.clone());
                next_frontier.push((hop.pointer_address, new_path));

                if chains.len() >= max_chains {
                    return chains;
                }
            }
        }

        frontier = next_frontier;
        if frontier.is_empty() {
            break;
        }
    }

    chains
}

/// 二次快照稳定性检查：重读链上每一跳的指针值，若与扫描时记录的值一致则视为稳定。
///
/// 链 `[hop0, hop1, ...]` 中 `hop0` 指向 `target`、`hop1` 指向 `hop0.pointer_address`……
/// 真指针的值稳定，随机数据在两次读取间会变化，据此去噪。
pub fn chain_stable<M: ScanMemory + ?Sized>(
    mem: &M,
    chain: &[PointerHop],
    target: Address,
    pointer_size: usize,
) -> bool {
    let mut t = target;
    for hop in chain {
        let mut buf = vec![0u8; pointer_size];
        if !mem.read_into(hop.pointer_address, &mut buf) {
            return false;
        }
        let v = read_little_endian(&buf);
        if v != t.saturating_sub(hop.offset as u64) {
            return false;
        }
        t = hop.pointer_address;
    }
    true
}

/// 地址是否落在某个可读的已提交区域内。
fn region_contains(regions: &[MemoryRegion], addr: Address) -> bool {
    regions
        .iter()
        .any(|r| r.readable && addr >= r.base && addr < r.base.saturating_add(r.size))
}

/// 小端读取指针值（4 或 8 字节）。
fn read_little_endian(buf: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, &b) in buf.iter().enumerate() {
        v |= (b as u64) << (8 * i);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 线性内存，base = 0，区域列表可配置（用于构造带空洞的多区域场景）。
    struct FakeMem {
        data: Vec<u8>,
        regions: Vec<MemoryRegion>,
    }

    impl ScanMemory for FakeMem {
        fn read_into(&self, addr: Address, out: &mut [u8]) -> bool {
            let off = addr as usize;
            if off + out.len() > self.data.len() {
                return false;
            }
            out.copy_from_slice(&self.data[off..off + out.len()]);
            true
        }
        fn readable_regions(&self) -> Vec<MemoryRegion> {
            self.regions.clone()
        }
    }

    fn region(base: u64, size: u64) -> MemoryRegion {
        MemoryRegion {
            base,
            size,
            protection: 0x04,
            readable: true,
            writable: true,
            executable: false,
            name: None,
        }
    }

    fn write_u64(data: &mut [u8], off: usize, v: u64) {
        data[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    const TARGET: u64 = 0x2000;

    #[test]
    fn finds_direct_pointers_with_offsets() {
        let mut data = vec![0u8; 0x3000];
        write_u64(&mut data, 0x1000, TARGET); // offset 0
        write_u64(&mut data, 0x1008, TARGET - 4); // offset 4
        write_u64(&mut data, 0x1010, TARGET + 8); // 超出区间，不命中

        let mem = FakeMem {
            data,
            regions: vec![region(0, 0x3000)],
        };
        let hops = find_pointers_to(&mem, TARGET, 0x100, 8);
        let mut addrs: Vec<u64> = hops.iter().map(|h| h.pointer_address).collect();
        addrs.sort_unstable();
        assert_eq!(addrs, vec![0x1000, 0x1008]);
        assert_eq!(hops.iter().find(|h| h.pointer_address == 0x1008).unwrap().offset, 4);
    }

    #[test]
    fn filters_pointers_into_uncommitted_memory() {
        // 两个区域，中间有空洞 [0x2000, 0x3000)
        let regions = vec![region(0x1000, 0x1000), region(0x3000, 0x1000)];
        let mut data = vec![0u8; 0x4000];
        let target = 0x3000u64; // 在区域 B
        // 真指针：*(0x1000) = 0x3000（有效，指向区域 B）
        write_u64(&mut data, 0x1000, target);
        // 假指针：*(0x1008) = 0x2F00（数值在区间内，但落在空洞，非有效内存）
        write_u64(&mut data, 0x1008, target - 0x100);

        let mem = FakeMem { data, regions };
        let hops = find_pointers_to(&mem, target, 0x100, 8);
        let addrs: Vec<u64> = hops.iter().map(|h| h.pointer_address).collect();
        assert_eq!(addrs, vec![0x1000]); // 0x1008 被静态过滤
    }

    #[test]
    fn scans_multi_level_chain() {
        let mut data = vec![0u8; 0x3000];
        write_u64(&mut data, 0x1000, TARGET);
        write_u64(&mut data, 0x0200, 0x1000);

        let mem = FakeMem {
            data,
            regions: vec![region(0, 0x3000)],
        };
        let chains = scan(&mem, TARGET, 0x100, 2, 8, 100);

        assert!(chains.iter().any(|c| c.len() == 1 && c[0].pointer_address == 0x1000));
        assert!(chains
            .iter()
            .any(|c| c.len() == 2 && c[0].pointer_address == 0x1000 && c[1].pointer_address == 0x200));
    }

    #[test]
    fn chain_stable_filters_changed_pointer() {
        let mut data = vec![0u8; 0x3000];
        let target = 0x3000u64;
        // 真指针与假指针一开始都指向 target
        write_u64(&mut data, 0x1000, target);
        write_u64(&mut data, 0x1008, target);

        let mut mem = FakeMem {
            data,
            regions: vec![region(0, 0x3000)],
        };

        let real = vec![PointerHop { pointer_address: 0x1000, offset: 0 }];
        let decoy = vec![PointerHop { pointer_address: 0x1008, offset: 0 }];

        // 二次读取前，两者都稳定
        assert!(chain_stable(&mem, &real, target, 8));
        assert!(chain_stable(&mem, &decoy, target, 8));

        // 模拟假指针变化（随机数据在两次读取间变了）
        write_u64(&mut mem.data, 0x1008, 0x4000);

        assert!(chain_stable(&mem, &real, target, 8)); // 真指针仍稳定
        assert!(!chain_stable(&mem, &decoy, target, 8)); // 假指针被过滤
    }
}
