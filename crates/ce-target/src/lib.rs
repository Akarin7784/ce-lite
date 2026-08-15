//! ce-target 库壳：仅为了让 cargo 把 ce-target 视为合法依赖（lib + bin），
//! 使集成测试可以通过 `CARGO_BIN_EXE_ce-target` 找到刚构建的目标进程二进制。
//! 实际逻辑在 `main.rs`（bin）。
