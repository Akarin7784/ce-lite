//! 内存扫描引擎（值扫描 / AOB 扫描 / 变化收窄）。
//!
//! 纯算法、平台无关：通过 [`ScanMemory`] trait 注入内存源，
//! 由 `ce-proc` 为其进程后端实现该 trait。对应 Cheat Engine 的 `memscan.pas`。

pub mod pointer;
pub mod value;

use crate::{Address, MemoryRegion, ScanResult, ScanType, Value, ValueType};

/// 扫描所需的最小内存源抽象（`ce-proc` 为其 `Process` 实现）。
pub trait ScanMemory {
    /// 读取 `addr` 起 `out.len()` 字节，成功返回 `true`。
    fn read_into(&self, addr: Address, out: &mut [u8]) -> bool;
    /// 可读内存区域（扫描候选集）。
    fn readable_regions(&self) -> Vec<MemoryRegion>;
}

/// 一条当前匹配项：地址 + 上一次比较时的值字节。
struct ScanEntry {
    address: Address,
    prev: Vec<u8>,
}

/// 一次扫描会话。
pub struct Scan {
    value_type: ValueType,
    width: usize,
    entries: Vec<ScanEntry>,
}

impl Scan {
    /// 首扫：在可写区域中查找匹配，建立候选地址集。
    ///
    /// `scan_type` 为 `exact` 时按值过滤；其余（变化类）首扫视为“未知初值”，
    /// 收集全部候选。
    pub fn first<M: ScanMemory + ?Sized>(
        mem: &M,
        value_type: ValueType,
        scan_type: ScanType,
        value: &Value,
    ) -> Scan {
        let width = value::width(value_type, value);
        let mut entries: Vec<ScanEntry> = Vec::new();

        if width == 0 {
            return Scan {
                value_type,
                width,
                entries,
            };
        }

        // 固定宽类型按宽度对齐，字节/AOB 模式逐字节步进。
        let step = if matches!(value_type, ValueType::Bytes | ValueType::String) {
            1usize
        } else {
            width
        };

        for region in mem.readable_regions().iter().filter(|r| r.writable) {
            let start = region.base;
            let end = region.base.saturating_add(region.size);
            let mut addr = start;

            while addr.saturating_add(width as u64) <= end {
                let mut buf = vec![0u8; width];
                if mem.read_into(addr, &mut buf) && matches_first(&buf, value_type, scan_type, value) {
                    entries.push(ScanEntry {
                        address: addr,
                        prev: buf,
                    });
                }
                addr = addr.saturating_add(step as u64);
                if step == 0 {
                    break;
                }
            }
        }

        Scan {
            value_type,
            width,
            entries,
        }
    }

    /// 下一轮收窄：重读每个候选，按 `scan_type` 过滤并更新“上次值”。
    pub fn next<M: ScanMemory + ?Sized>(&mut self, mem: &M, scan_type: ScanType, value: &Value) {
        if self.width == 0 {
            return;
        }
        let width = self.width;
        let vt = self.value_type;

        self.entries.retain_mut(|e| {
            let mut buf = vec![0u8; width];
            if !mem.read_into(e.address, &mut buf) {
                return false;
            }
            let keep = matches_next(&buf, &e.prev, vt, scan_type, value);
            if keep {
                e.prev = buf;
            }
            keep
        });
    }

    /// 当前候选数量。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 分页读取结果。
    pub fn results(&self, offset: usize, limit: usize) -> (u64, Vec<ScanResult>) {
        let total = self.entries.len() as u64;
        let results = self
            .entries
            .iter()
            .skip(offset)
            .take(limit)
            .map(|e| ScanResult {
                address: e.address,
                value: value::from_bytes(&e.prev, self.value_type).unwrap_or(Value::None),
                previous: None,
            })
            .collect();
        (total, results)
    }
}

/// 首扫匹配。
fn matches_first(buf: &[u8], vt: ValueType, scan_type: ScanType, value: &Value) -> bool {
    match scan_type {
        ScanType::Exact => value::equals(buf, vt, value),
        ScanType::BiggerThan => cmp_value(buf, vt, value, |a, b| a > b),
        ScanType::SmallerThan => cmp_value(buf, vt, value, |a, b| a < b),
        // Between 首扫/其余变化类首扫：收集全部（未知初值语义）。
        _ => true,
    }
}

/// 收窄匹配：需要与上一轮值比较。
fn matches_next(cur: &[u8], prev: &[u8], vt: ValueType, scan_type: ScanType, value: &Value) -> bool {
    match scan_type {
        ScanType::Exact => value::equals(cur, vt, value),
        ScanType::BiggerThan => cmp_value(cur, vt, value, |a, b| a > b),
        ScanType::SmallerThan => cmp_value(cur, vt, value, |a, b| a < b),
        ScanType::Changed => cur != prev,
        ScanType::Unchanged => cur == prev,
        ScanType::Increased => cmp_delta(cur, prev, vt, |d| d > 0.0),
        ScanType::Decreased => cmp_delta(cur, prev, vt, |d| d < 0.0),
        ScanType::IncreasedBy => {
            let Some(d) = value::numeric(value) else {
                return false;
            };
            cmp_delta(cur, prev, vt, |x| (x - d).abs() < 1e-9)
        }
        ScanType::DecreasedBy => {
            let Some(d) = value::numeric(value) else {
                return false;
            };
            cmp_delta(prev, cur, vt, |x| (x - d).abs() < 1e-9)
        }
        ScanType::Between => false, // 未实现（M1 之后）
        ScanType::UnknownInitial => true,
    }
}

/// 内存值 vs 目标值的数值比较。
fn cmp_value(buf: &[u8], vt: ValueType, value: &Value, f: impl Fn(f64, f64) -> bool) -> bool {
    let Some(a) = value::numeric_of(buf, vt) else {
        return false;
    };
    let Some(b) = value::numeric(value) else {
        return false;
    };
    f(a, b)
}

/// 当前值相对上一轮的增量比较。
fn cmp_delta(cur: &[u8], prev: &[u8], vt: ValueType, f: impl Fn(f64) -> bool) -> bool {
    let Some(a) = value::numeric_of(cur, vt) else {
        return false;
    };
    let Some(b) = value::numeric_of(prev, vt) else {
        return false;
    };
    f(a - b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 用一段线性可写内存模拟目标进程。
    struct FakeMem {
        data: Vec<u8>,
        base: Address,
    }

    impl FakeMem {
        fn new(data: Vec<u8>) -> Self {
            FakeMem { data, base: 0x1000 }
        }
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
                protection: 0x04,
                readable: true,
                writable: true,
                executable: false,
                name: None,
            }]
        }
    }

    #[test]
    fn exact_int32_first_scan() {
        // 数据：地址 0x1000..0x1010，其中 0x1004 存 100，0x1008 存 200
        let mut data = vec![0u8; 16];
        data[4..8].copy_from_slice(&100i32.to_le_bytes());
        data[8..12].copy_from_slice(&200i32.to_le_bytes());
        let mem = FakeMem::new(data);

        let scan = Scan::first(&mem, ValueType::Int32, ScanType::Exact, &Value::Int(100));
        assert_eq!(scan.len(), 1);
        let (total, results) = scan.results(0, 100);
        assert_eq!(total, 1);
        assert_eq!(results[0].address, 0x1004);
        assert_eq!(results[0].value, Value::Int(100));
    }

    #[test]
    fn next_scan_increased() {
        // 初值 10 @ 0x1000，20 @ 0x1004
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&10i32.to_le_bytes());
        data[4..8].copy_from_slice(&20i32.to_le_bytes());
        let mut mem = FakeMem::new(data);

        let mut scan = Scan::first(&mem, ValueType::Int32, ScanType::UnknownInitial, &Value::None);
        assert_eq!(scan.len(), 2);

        // 两者都增加 5
        mem.data[0..4].copy_from_slice(&15i32.to_le_bytes());
        mem.data[4..8].copy_from_slice(&25i32.to_le_bytes());

        scan.next(&mem, ScanType::Increased, &Value::None);
        assert_eq!(scan.len(), 2);
    }

    #[test]
    fn next_scan_changed_filters_unchanged() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&10i32.to_le_bytes());
        data[4..8].copy_from_slice(&20i32.to_le_bytes());
        let mut mem = FakeMem::new(data);

        let mut scan = Scan::first(&mem, ValueType::Int32, ScanType::UnknownInitial, &Value::None);
        assert_eq!(scan.len(), 2);

        // 只改第一个
        mem.data[0..4].copy_from_slice(&11i32.to_le_bytes());

        scan.next(&mem, ScanType::Changed, &Value::None);
        assert_eq!(scan.len(), 1);
        let (_, results) = scan.results(0, 100);
        assert_eq!(results[0].address, 0x1000);
    }

    #[test]
    fn aob_scan() {
        let data = vec![0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        let mem = FakeMem::new(data);
        let scan = Scan::first(&mem, ValueType::Bytes, ScanType::Exact, &Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(scan.len(), 2);
        let (_, results) = scan.results(0, 100);
        assert_eq!(results[0].address, 0x1001);
        assert_eq!(results[1].address, 0x1006);
    }
}
