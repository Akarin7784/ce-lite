//! 内存扫描引擎（值扫描 / AOB 扫描 / 变化收窄）。
//!
//! 纯算法、平台无关：通过 [`ScanMemory`] trait 注入内存源，
//! 由 `ce-proc` 为其进程后端实现该 trait。对应 Cheat Engine 的 `memscan.pas`。

pub mod pointer;
pub mod value;

use crate::{Address, MemoryRegion, ScanResult, ScanType, Value, ValueType};

use rayon::prelude::*;

/// 扫描所需的最小内存源抽象（`ce-proc` 为其 `Process` 实现）。
///
/// `Sync` 是 rayon 并行扫描的要求（多个工作线程共享同一内存源）。
pub trait ScanMemory: Sync {
    /// 读取 `addr` 起 `out.len()` 字节，成功返回 `true`。
    fn read_into(&self, addr: Address, out: &mut [u8]) -> bool;
    /// 可读内存区域（扫描候选集）。
    fn readable_regions(&self) -> Vec<MemoryRegion>;
}

/// 一次扫描的附加选项（均为可选，对应 CE 的高级扫描）。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScanOpts {
    /// AOB 通配符掩码：`mask[i] == 0xFF` 必须匹配，`0x00` 通配。与 `Bytes` 值等长。
    pub mask: Option<Vec<u8>>,
    /// `between` 扫描下界（含）。
    pub min: Option<f64>,
    /// `between` 扫描上界（含）。
    pub max: Option<f64>,
    /// XOR 扫描密钥：首扫对原始字节逐字节 XOR 后比较/存储（CE XOR 语义）。
    pub xor_key: Option<i64>,
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
    /// 收集全部候选。`opts` 提供 AOB 通配符 / between 区间 / XOR 密钥。
    pub fn first<M: ScanMemory + ?Sized>(
        mem: &M,
        value_type: ValueType,
        scan_type: ScanType,
        value: &Value,
        opts: &ScanOpts,
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

        let per_region: Vec<Vec<ScanEntry>> = mem
            .readable_regions()
            .par_iter()
            .filter(|r| r.writable)
            .map(|region| {
                let mut local = Vec::new();
                let start = region.base;
                let end = region.base.saturating_add(region.size);
                let mut addr = start;

                while addr.saturating_add(width as u64) <= end {
                    let mut buf = vec![0u8; width];
                    if mem.read_into(addr, &mut buf) {
                        // XOR 扫描：先变换再比较，存储变换后的值。
                        let eff = match opts.xor_key {
                            Some(k) => value::xor_bytes(&buf, k),
                            None => buf.clone(),
                        };
                        if matches_first(&eff, value_type, scan_type, value, opts) {
                            local.push(ScanEntry {
                                address: addr,
                                prev: eff,
                            });
                        }
                    }
                    addr = addr.saturating_add(step as u64);
                    if step == 0 {
                        break;
                    }
                }
                local
            })
            .collect();
        for mut v in per_region {
            entries.append(&mut v);
        }

        Scan {
            value_type,
            width,
            entries,
        }
    }

    /// 下一轮收窄：重读每个候选，按 `scan_type` 过滤并更新“上次值”。
    pub fn next<M: ScanMemory + ?Sized>(
        &mut self,
        mem: &M,
        scan_type: ScanType,
        value: &Value,
        opts: &ScanOpts,
    ) {
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
            // XOR 扫描：重读的原始字节同样变换后再比较。
            let eff = match opts.xor_key {
                Some(k) => value::xor_bytes(&buf, k),
                None => buf,
            };
            let keep = matches_next(&eff, &e.prev, vt, scan_type, value, opts);
            if keep {
                e.prev = eff;
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
fn matches_first(buf: &[u8], vt: ValueType, scan_type: ScanType, value: &Value, opts: &ScanOpts) -> bool {
    match scan_type {
        ScanType::Exact => match (vt, value, &opts.mask) {
            // AOB 通配符：带掩码时逐字节比较。
            (ValueType::Bytes | ValueType::Binary, Value::Bytes(b), Some(mask)) => {
                value::equals_masked(buf, b, mask)
            }
            _ => value::equals(buf, vt, value),
        },
        ScanType::BiggerThan => cmp_value(buf, vt, value, |a, b| a > b),
        ScanType::SmallerThan => cmp_value(buf, vt, value, |a, b| a < b),
        ScanType::Between => between(buf, vt, opts),
        ScanType::Rounded => rounded(buf, vt, value),
        // 其余变化类首扫：收集全部（未知初值语义）。
        _ => true,
    }
}

/// 收窄匹配：需要与上一轮值比较。
fn matches_next(
    cur: &[u8],
    prev: &[u8],
    vt: ValueType,
    scan_type: ScanType,
    value: &Value,
    opts: &ScanOpts,
) -> bool {
    match scan_type {
        ScanType::Exact => match (vt, value, &opts.mask) {
            (ValueType::Bytes | ValueType::Binary, Value::Bytes(b), Some(mask)) => {
                value::equals_masked(cur, b, mask)
            }
            _ => value::equals(cur, vt, value),
        },
        ScanType::BiggerThan => cmp_value(cur, vt, value, |a, b| a > b),
        ScanType::SmallerThan => cmp_value(cur, vt, value, |a, b| a < b),
        ScanType::Between => between(cur, vt, opts),
        ScanType::Rounded => rounded(cur, vt, value),
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
        ScanType::UnknownInitial => true,
    }
}

/// `between` 匹配：数值落在 [min, max] 区间。
fn between(buf: &[u8], vt: ValueType, opts: &ScanOpts) -> bool {
    let (Some(lo), Some(hi)) = (opts.min, opts.max) else {
        return false;
    };
    let Some(v) = value::numeric_of(buf, vt) else {
        return false;
    };
    v >= lo && v <= hi
}

/// `rounded` 匹配：数值四舍五入后与目标相等（CE 的 rounded 扫描）。
fn rounded(buf: &[u8], vt: ValueType, value: &Value) -> bool {
    let Some(a) = value::numeric_of(buf, vt) else {
        return false;
    };
    let Some(b) = value::numeric(value) else {
        return false;
    };
    a.round() == b.round()
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

/// 解析 CE 风格 AOB 模式串（如 `"DE ?? BE EF"`）为 `(pattern, mask)`。
///
/// `??`/`?`/`*` 为通配符（掩码位 0），十六进制字节无分隔符要求。
pub fn parse_aob(s: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut pattern = Vec::new();
    let mut mask = Vec::new();
    for tok in s.split_whitespace() {
        if matches!(tok, "??" | "?" | "*") {
            pattern.push(0);
            mask.push(0);
        } else {
            let b = u8::from_str_radix(tok, 16)
                .map_err(|_| format!("bad AOB token '{tok}'"))?;
            pattern.push(b);
            mask.push(0xFF);
        }
    }
    if pattern.is_empty() {
        return Err("empty AOB pattern".to_string());
    }
    Ok((pattern, mask))
}

/// 在全部可读区域（含可执行区）中搜索带掩码的 AOB 模式，返回命中地址。
///
/// 与值扫描不同，这里不限定可写区（代码区也可能命中）。分块读取防止大区域
/// 一次性分配；结果去重后按地址排序。
pub fn aob_search<M: ScanMemory + ?Sized>(
    mem: &M,
    pattern: &[u8],
    mask: &[u8],
    limit: usize,
) -> Vec<Address> {
    let mut out = Vec::new();
    let chunk = 1024 * 1024usize;
    let overlap = pattern.len().saturating_sub(1);

    for region in mem.readable_regions().iter().filter(|r| r.readable) {
        let start = region.base;
        let size = region.size.min(1 << 30) as usize; // 单区域上限 1GB
        let mut off = 0usize;
        while off < size {
            let want = (size - off).min(chunk + overlap);
            let mut buf = vec![0u8; want];
            if !mem.read_into(start + off as u64, &mut buf) {
                off += chunk;
                continue;
            }
            let search_len = buf.len().saturating_sub(overlap);
            for i in 0..search_len {
                if value::equals_masked(&buf[i..], pattern, mask) {
                    out.push(start + off as u64 + i as u64);
                    if out.len() >= limit {
                        out.sort_unstable();
                        out.dedup();
                        return out;
                    }
                }
            }
            off += chunk;
        }
    }
    out.sort_unstable();
    out.dedup();
    out
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

        let scan = Scan::first(
            &mem,
            ValueType::Int32,
            ScanType::Exact,
            &Value::Int(100),
            &ScanOpts::default(),
        );
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

        let mut scan =
            Scan::first(&mem, ValueType::Int32, ScanType::UnknownInitial, &Value::None, &ScanOpts::default());
        assert_eq!(scan.len(), 2);

        // 两者都增加 5
        mem.data[0..4].copy_from_slice(&15i32.to_le_bytes());
        mem.data[4..8].copy_from_slice(&25i32.to_le_bytes());

        scan.next(&mem, ScanType::Increased, &Value::None, &ScanOpts::default());
        assert_eq!(scan.len(), 2);
    }

    #[test]
    fn next_scan_changed_filters_unchanged() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&10i32.to_le_bytes());
        data[4..8].copy_from_slice(&20i32.to_le_bytes());
        let mut mem = FakeMem::new(data);

        let mut scan =
            Scan::first(&mem, ValueType::Int32, ScanType::UnknownInitial, &Value::None, &ScanOpts::default());
        assert_eq!(scan.len(), 2);

        // 只改第一个
        mem.data[0..4].copy_from_slice(&11i32.to_le_bytes());

        scan.next(&mem, ScanType::Changed, &Value::None, &ScanOpts::default());
        assert_eq!(scan.len(), 1);
        let (_, results) = scan.results(0, 100);
        assert_eq!(results[0].address, 0x1000);
    }

    #[test]
    fn aob_scan() {
        let data = vec![0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        let mem = FakeMem::new(data);
        let scan = Scan::first(
            &mem,
            ValueType::Bytes,
            ScanType::Exact,
            &Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            &ScanOpts::default(),
        );
        assert_eq!(scan.len(), 2);
        let (_, results) = scan.results(0, 100);
        assert_eq!(results[0].address, 0x1001);
        assert_eq!(results[1].address, 0x1006);
    }

    #[test]
    fn aob_scan_with_wildcard_mask() {
        // 模式 DE ?? BE EF 应命中 0x1001（AD）与 0x1006（AD）——通配位不参与比较。
        let data = vec![0x00, 0xDE, 0x00, 0xBE, 0xEF, 0x00, 0xDE, 0xFF, 0xBE, 0xEF];
        let mem = FakeMem::new(data);
        let opts = ScanOpts {
            mask: Some(vec![0xFF, 0x00, 0xFF, 0xFF]),
            ..Default::default()
        };
        let scan = Scan::first(
            &mem,
            ValueType::Bytes,
            ScanType::Exact,
            &Value::Bytes(vec![0xDE, 0x00, 0xBE, 0xEF]),
            &opts,
        );
        let (total, results) = scan.results(0, 100);
        assert_eq!(total, 2, "wildcard AOB should match both");
        assert_eq!(results[0].address, 0x1001);
        assert_eq!(results[1].address, 0x1006);
    }

    #[test]
    fn between_scan_filters_range() {
        let mut data = vec![0u8; 12];
        data[0..4].copy_from_slice(&10i32.to_le_bytes());
        data[4..8].copy_from_slice(&50i32.to_le_bytes());
        data[8..12].copy_from_slice(&90i32.to_le_bytes());
        let mem = FakeMem::new(data);
        let opts = ScanOpts {
            min: Some(40.0),
            max: Some(60.0),
            ..Default::default()
        };
        let scan = Scan::first(&mem, ValueType::Int32, ScanType::Between, &Value::None, &opts);
        assert_eq!(scan.len(), 1);
        let (_, results) = scan.results(0, 100);
        assert_eq!(results[0].address, 0x1004);
    }

    #[test]
    fn rounded_scan_matches_nearest_int() {
        // 99.6 四舍五入 = 100，应命中 target 100。
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&99.6f32.to_le_bytes());
        data[4..8].copy_from_slice(&150.2f32.to_le_bytes());
        let mem = FakeMem::new(data);
        let scan = Scan::first(
            &mem,
            ValueType::Float,
            ScanType::Rounded,
            &Value::Int(100),
            &ScanOpts::default(),
        );
        assert_eq!(scan.len(), 1);
        let (_, results) = scan.results(0, 100);
        assert_eq!(results[0].address, 0x1000);
    }

    #[test]
    fn xor_scan_finds_xored_value() {
        // 逐字节 XOR 存储：stored[i] = 777.to_le_bytes()[i] ^ 0x55；
        // 用密钥 0x55 扫 target 777 应命中。
        let mut data = vec![0u8; 4];
        let stored: Vec<u8> = 777i32.to_le_bytes().iter().map(|b| b ^ 0x55).collect();
        data[0..4].copy_from_slice(&stored);
        let mem = FakeMem::new(data);
        let opts = ScanOpts {
            xor_key: Some(0x55),
            ..Default::default()
        };
        let scan = Scan::first(
            &mem,
            ValueType::Int32,
            ScanType::Exact,
            &Value::Int(777),
            &opts,
        );
        assert_eq!(scan.len(), 1);
        let (_, results) = scan.results(0, 100);
        assert_eq!(results[0].address, 0x1000);
        assert_eq!(results[0].value, Value::Int(777));
    }
}
