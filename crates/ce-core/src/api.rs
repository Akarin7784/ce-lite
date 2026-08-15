//! JSON-RPC 2.0 接口契约。
//!
//! 这是 AI 代理驱动的机器可读表面。请求/响应为换行分隔的 JSON。

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// 方法名常量（供分发器与客户端共享）。
pub mod method {
    pub const PROCESS_LIST: &str = "process.list";
    pub const PROCESS_ATTACH: &str = "process.attach";
    pub const PROCESS_DETACH: &str = "process.detach";
    pub const MEMORY_REGIONS: &str = "memory.regions";
    pub const MEMORY_READ: &str = "memory.read";
    pub const MEMORY_WRITE: &str = "memory.write";
    pub const MEMORY_ALLOC: &str = "memory.alloc";
    pub const SCAN_NEW: &str = "scan.new";
    pub const SCAN_NEXT: &str = "scan.next";
    pub const SCAN_RESULTS: &str = "scan.results";
    pub const SCAN_CLOSE: &str = "scan.close";
    pub const DISASM: &str = "disasm";
    pub const ASM: &str = "asm";
    pub const SYMBOLS_LIST: &str = "symbols.list";
    pub const SYMBOLS_RESOLVE: &str = "symbols.resolve";
    pub const POINTER_SCAN: &str = "pointer.scan";
    pub const POINTER_SCAN_START: &str = "pointer.scan_start";
    pub const POINTER_RESCAN: &str = "pointer.rescan";
    pub const POINTER_RESULTS: &str = "pointer.results";
    pub const POINTER_CLOSE: &str = "pointer.close";
    pub const DEBUG_ATTACH: &str = "debug.attach";
    pub const DEBUG_DETACH: &str = "debug.detach";
    pub const DEBUG_BREAKPOINT_SET: &str = "debug.breakpoint_set";
    pub const DEBUG_BREAKPOINT_CLEAR: &str = "debug.breakpoint_clear";
    pub const DEBUG_WAIT: &str = "debug.wait";
    pub const DEBUG_CONTINUE: &str = "debug.continue";
    pub const DEBUG_REGISTERS: &str = "debug.registers";
    pub const DEBUG_REGISTERS_SET: &str = "debug.registers_set";
    pub const DEBUG_WATCHPOINT_SET: &str = "debug.watchpoint_set";
    pub const DEBUG_WATCHPOINT_CLEAR: &str = "debug.watchpoint_clear";
    pub const DEBUG_SINGLE_STEP: &str = "debug.single_step";
    pub const MEMORY_SNAPSHOT: &str = "memory.snapshot";
    pub const MEMORY_DIFF: &str = "memory.diff";
    pub const STRUCT_DEFINE: &str = "struct.define";
    pub const STRUCT_READ: &str = "struct.read";
    pub const STRUCT_LIST: &str = "struct.list";
    pub const STRUCT_DELETE: &str = "struct.delete";
}

/// JSON-RPC 请求。
#[derive(Debug, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: JsonValue,
}

/// JSON-RPC 响应。
#[derive(Debug, Serialize)]
pub struct Response {
    pub jsonrpc: &'static str,
    pub id: u64,
    #[serde(flatten)]
    pub body: ResponseBody,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseBody {
    Result(JsonValue),
    Error { code: i64, message: String },
}

/// JSON-RPC 标准错误码。
pub mod error_code {
    pub const PARSE_ERROR: i64 = -32700;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL: i64 = -32603;
    /// 应用层错误（目标进程不存在、内存不可读等）。
    pub const APPLICATION: i64 = -32000;
}

impl Response {
    pub fn ok(id: u64, result: impl Serialize) -> Self {
        Response {
            jsonrpc: "2.0",
            id,
            body: ResponseBody::Result(
                serde_json::to_value(result).unwrap_or(JsonValue::Null),
            ),
        }
    }

    pub fn err(id: u64, code: i64, message: impl Into<String>) -> Self {
        Response {
            jsonrpc: "2.0",
            id,
            body: ResponseBody::Error {
                code,
                message: message.into(),
            },
        }
    }
}

/// M1/M2 各方法的参数类型。
#[derive(Debug, Deserialize)]
pub struct AttachParams {
    pub pid: u32,
}

#[derive(Debug, Deserialize)]
pub struct ReadParams {
    pub address: u64,
    pub size: usize,
}

#[derive(Debug, Deserialize)]
pub struct WriteParams {
    pub address: u64,
    /// base64 编码的待写字节。
    pub bytes: String,
}

#[derive(Debug, Deserialize)]
pub struct ScanNewParams {
    pub value_type: crate::ValueType,
    pub scan_type: crate::ScanType,
    #[serde(default)]
    pub value: crate::Value,
}

#[derive(Debug, Deserialize)]
pub struct ScanNextParams {
    pub scan_id: u64,
    pub scan_type: crate::ScanType,
    #[serde(default)]
    pub value: crate::Value,
}

#[derive(Debug, Deserialize)]
pub struct ScanResultsParams {
    pub scan_id: u64,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    1000
}

#[derive(Debug, Deserialize)]
pub struct ScanIdParams {
    pub scan_id: u64,
}

#[derive(Debug, Deserialize)]
pub struct DisasmParams {
    pub address: u64,
    pub length: usize,
}

#[derive(Debug, Deserialize)]
pub struct AsmParams {
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct AllocParams {
    pub size: usize,
}

#[derive(Debug, Deserialize)]
pub struct SymbolsListParams {
    #[serde(default)]
    pub module: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SymbolsResolveParams {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct PointerScanParams {
    pub address: u64,
    #[serde(default = "default_max_offset")]
    pub max_offset: u32,
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
    #[serde(default = "default_ptr_size")]
    pub pointer_size: usize,
}

fn default_max_offset() -> u32 {
    0x1000
}

fn default_max_depth() -> usize {
    3
}

fn default_ptr_size() -> usize {
    8
}

#[derive(Debug, Deserialize)]
pub struct DebugAttachParams {
    pub pid: u32,
}

#[derive(Debug, Deserialize)]
pub struct BreakpointParams {
    pub address: u64,
}

#[derive(Debug, Deserialize)]
pub struct DebugWaitParams {
    pub timeout_ms: u64,
}

#[derive(Debug, Deserialize)]
pub struct DebugRegistersParams {
    pub thread_id: u32,
}

#[derive(Debug, Deserialize)]
pub struct DebugRegistersSetParams {
    pub thread_id: u32,
    pub registers: crate::Registers,
}

#[derive(Debug, Deserialize)]
pub struct WatchpointSetParams {
    pub address: u64,
    pub size: u8,
    #[serde(default)]
    pub on_read: bool,
    #[serde(default = "default_true")]
    pub on_write: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct SnapshotIdParams {
    pub snapshot_id: u64,
}

#[derive(Debug, Deserialize)]
pub struct StructDefineParams {
    pub name: String,
    pub fields: Vec<crate::StructField>,
}

#[derive(Debug, Deserialize)]
pub struct StructReadParams {
    pub name: String,
    pub address: u64,
}

#[derive(Debug, Deserialize)]
pub struct StructNameParams {
    pub name: String,
}
