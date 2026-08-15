//! 领域核心类型：地址、值类型、扫描操作、内存区域、扫描结果。
//!
//! 对应 Cheat Engine 的 `vtByte..vtBinary`（值类型）与
//! `soExactValue..soGrouped`（扫描选项）族，做了面向 JSON API 的归一化。

use serde::{Deserialize, Serialize};

/// 目标进程中的内存地址。
pub type Address = u64;

/// 目标架构。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X86,
    X64,
    Arm,
    Arm64,
}

impl Arch {
    /// 该架构下的指针宽度（字节）。
    pub fn pointer_size(self) -> u8 {
        match self {
            Arch::X86 | Arch::Arm => 4,
            Arch::X64 | Arch::Arm64 => 8,
        }
    }
}

/// 扫描器与值解释器理解的值类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    Byte,
    Int16,
    Int32,
    Int64,
    Float,
    Double,
    String,
    Bytes,
    Binary,
}

impl ValueType {
    /// 该值类型在内存中的宽度（字节）；变长类型返回 `None`。
    pub fn size(self) -> Option<usize> {
        match self {
            ValueType::Byte => Some(1),
            ValueType::Int16 => Some(2),
            ValueType::Int32 | ValueType::Float => Some(4),
            ValueType::Int64 | ValueType::Double => Some(8),
            ValueType::String | ValueType::Bytes | ValueType::Binary => None,
        }
    }
}

/// 一次具体的扫描值。
///
/// `Bytes` 表示 AOB（数组字节）模式，字节序列即匹配模式；
/// `None` 表示本次扫描不携带比较值（如 `changed`/`unchanged`）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(untagged)]
pub enum Value {
    Int(i64),
    Float(f32),
    Double(f64),
    Str(String),
    Bytes(Vec<u8>),
    #[default]
    None,
}

/// 扫描操作，对应 CE 的 `TScanOption` 族。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    Exact,
    Increased,
    Decreased,
    Changed,
    Unchanged,
    IncreasedBy,
    DecreasedBy,
    BiggerThan,
    SmallerThan,
    Between,
    UnknownInitial,
}

/// 目标进程中的一段已枚举内存区域。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base: Address,
    pub size: u64,
    /// 平台保护位（Windows 下为 PAGE_*，由 `ce-proc` 归一化后透传）。
    pub protection: u32,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub name: Option<String>,
}

/// 目标进程描述。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub arch: Arch,
    pub pointer_size: u8,
}

/// 单条扫描结果。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanResult {
    pub address: Address,
    pub value: Value,
    pub previous: Option<Value>,
}

/// 一条反汇编指令。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisasmResult {
    pub address: Address,
    pub bytes: Vec<u8>,
    pub text: String,
}

/// 一条符号记录（模块导出/导入）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub address: Address,
    pub module: String,
}

/// 目标进程的一个已加载模块。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub path: String,
    pub base: Address,
    pub size: u64,
}

/// 指针链上的一跳：指针所在地址 + 相对目标/上级的偏移。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerHop {
    pub pointer_address: Address,
    pub offset: u32,
}

/// x64 通用寄存器快照（调试器断点处读取）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registers {
    pub rip: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub eflags: u32,
}

/// 一次调试事件（断点命中/单步/异常/硬件监视点）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugEvent {
    /// `breakpoint` | `single_step` | `watchpoint` | `access_violation` | `exception`
    pub kind: String,
    pub thread_id: u32,
    /// 断点/单步为指令地址；监视点为被监视的数据地址；访问违例为故障地址。
    pub address: Address,
    /// 异常码。
    pub code: u32,
    /// 监视点访问类型：`write` | `read_write`；其它事件为 `None`。
    pub access: Option<String>,
}

/// 结构体字段定义。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructField {
    pub name: String,
    pub value_type: ValueType,
    /// 相对结构体基址的字节偏移。
    pub offset: u32,
    /// 字符串/字节数组的固定长度；定长数值类型可省略。
    pub size: Option<u32>,
}

/// 结构体定义。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Structure {
    pub name: String,
    pub fields: Vec<StructField>,
}

/// 结构体字段的读取结果。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructFieldValue {
    pub name: String,
    pub offset: u32,
    pub value_type: ValueType,
    pub value: Value,
}

/// 一个已知反作弊（含其内核驱动组件）的检测结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiCheatInfo {
    pub name: String,
    /// 匹配到的用户态进程名。
    pub process: String,
    pub pid: u32,
    /// 该反作弊是否附带内核驱动组件（内核保护更严，风险更高）。
    pub kernel: bool,
}

/// 远程线程执行结果（DLL 注入 / 代码注入）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteThreadResult {
    pub thread_id: u32,
    /// 是否在超时内完成（线程已退出）。
    pub completed: bool,
    /// 线程退出码（`completed` 时有效）。
    pub exit_code: u32,
}

/// 调用栈的一帧（RBP 链回溯，尽力而为）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackFrame {
    pub rip: u64,
    pub rbp: u64,
    pub rsp: u64,
}
