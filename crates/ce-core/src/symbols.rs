//! PE 符号解析（基于 `goblin`）：从 PE 文件字节提取导出表。
//!
//! 纯函数、平台无关。对应 Cheat Engine 的 `symbolhandler.pas` 中 PE 导出解析部分。

use goblin::pe::PE;

/// 解析 PE 文件的导出表，返回 `(名称, RVA)` 列表。
///
/// 调用方负责提供磁盘上的 PE 文件字节，并把 RVA 换算为绝对地址
/// （`模块基址 + RVA`）。
pub fn parse_exports(pe_bytes: &[u8]) -> Vec<(String, u32)> {
    let Ok(pe) = PE::parse(pe_bytes) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for export in &pe.exports {
        if let Some(name) = &export.name {
            out.push((name.to_string(), export.rva as u32));
        }
    }
    out
}
