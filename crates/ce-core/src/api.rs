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
    pub const POINTER_ANALYZE: &str = "pointer.analyze";
    pub const POINTER_STRUCT_SPAWN: &str = "pointer.struct_spawn";
    pub const DISASM_XREFS: &str = "disasm.xrefs";
    pub const DISASM_FUNCTION: &str = "disasm.function";
    pub const SYMBOLS_PDB_RESOLVE: &str = "symbols.pdb_resolve";
    pub const SESSION_SAVE: &str = "session.save";
    pub const SESSION_LOAD: &str = "session.load";
    pub const DEBUG_ACCESSOR: &str = "debug.accessor";
    pub const MODULE_AOB_SCAN: &str = "module.aob_scan";
    pub const TRAINER_FREEZE: &str = "trainer.freeze";
    pub const TRAINER_UNFREEZE: &str = "trainer.unfreeze";
    pub const TRAINER_LIST: &str = "trainer.list";
    pub const PATCH_EXPORT: &str = "patch.export";
    pub const HOOK_INSTALL: &str = "hook.install";
    pub const HOOK_REMOVE: &str = "hook.remove";
    pub const HOOK_LIST: &str = "hook.list";
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
    pub const PROTECT_STATUS: &str = "protect.status";
    pub const THREAD_INJECT_DLL: &str = "thread.inject_dll";
    pub const THREAD_CREATE_REMOTE: &str = "thread.create_remote";
    pub const DEBUG_STACK: &str = "debug.stack";
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
    /// AOB 通配符掩码：0xFF 必须匹配，0x00 通配。
    #[serde(default)]
    pub mask: Option<Vec<u8>>,
    /// `between` 下界（含）。
    #[serde(default)]
    pub min: Option<f64>,
    /// `between` 上界（含）。
    #[serde(default)]
    pub max: Option<f64>,
    /// XOR 扫描密钥。
    #[serde(default)]
    pub xor_key: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ScanNextParams {
    pub scan_id: u64,
    pub scan_type: crate::ScanType,
    #[serde(default)]
    pub value: crate::Value,
    #[serde(default)]
    pub mask: Option<Vec<u8>>,
    #[serde(default)]
    pub min: Option<f64>,
    #[serde(default)]
    pub max: Option<f64>,
    #[serde(default)]
    pub xor_key: Option<i64>,
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

#[derive(Debug, Deserialize)]
pub struct InjectDllParams {
    pub pid: u32,
    pub path: String,
    /// 等待注入线程完成的最长毫秒数（默认 10000）。
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRemoteParams {
    pub pid: u32,
    /// base64 编码的待执行字节码（x64 位置无关 shellcode，须以 `ret` 结尾）。
    pub code: String,
    /// 传给线程入口的 `lpParameter`（默认 0）。
    #[serde(default)]
    pub arg: Option<u64>,
    /// 等待线程完成的最长毫秒数（默认 10000）。
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct StackParams {
    pub thread_id: u32,
    /// 回溯的最大帧数（默认 16）。
    #[serde(default)]
    pub max_frames: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct ScanIdParams2 {
    pub scan_id: u64,
}

#[derive(Debug, Deserialize)]
pub struct DisasmXrefsParams {
    pub address: u64,
    /// 限定在某个模块内扫描（按名称或路径）；缺省扫全部可执行区域。
    #[serde(default)]
    pub module: Option<String>,
    /// 结果上限（默认 100）。
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct DisasmFunctionParams {
    pub address: u64,
    /// 向前回溯找函数起点的最大字节数（默认 256）。
    #[serde(default)]
    pub max_back: Option<usize>,
    /// 从起点向后反汇编的最大字节数（默认 4096）。
    #[serde(default)]
    pub max_len: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct PdbResolveParams {
    pub address: u64,
}

#[derive(Debug, Deserialize)]
pub struct SessionLoadParams {
    /// base64 编码的 `session.save` 产物。
    pub data: String,
}

#[derive(Debug, Deserialize)]
pub struct ModuleAobScanParams {
    /// AOB 模式串（CE 风格），如 `"DE ?? BE EF"`（`??` 为通配符）。
    pub pattern: String,
    /// 限定模块（按名称或路径）；缺省扫全部可读区域。
    #[serde(default)]
    pub module: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TrainerFreezeParams {
    pub address: u64,
    /// base64 编码的待写回字节。
    pub bytes: String,
    /// 写回间隔毫秒（默认 16）。
    #[serde(default)]
    pub interval_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct TrainerIdParams {
    pub freeze_id: u64,
}

#[derive(Debug, Deserialize)]
pub struct HookInstallParams {
    pub address: u64,
    /// base64 编码的钩子代码（x64，以 `ret` 结尾）。
    pub hook: String,
}
