//! `ce-core` — 平台无关的领域核心。
//!
//! 只包含纯数据模型与算法（扫描、值解释、反汇编/汇编/符号的抽象），
//! 不做任何系统调用。所有平台 I/O 通过 `ce-proc` 的 trait 注入。

pub mod api;
pub mod asm;
pub mod disasm;
pub mod scan;
pub mod symbols;
pub mod types;

pub use types::*;
