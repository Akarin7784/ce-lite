# ce-lite 架构设计

从 Cheat Engine 裁剪出 AI 真正需要的核心，用 Rust 重写为无 GUI 的 headless 工具。

## 1. 目标与非目标

**目标**
- 提供 AI 代理完成逆向/改值/分析所需的最小能力集，机器可调（JSON-RPC/MCP）。
- 核心算法纯 Rust、平台无关、可单元测试。
- 平台访问层薄封装，Windows 优先。

**非目标（明确不做，v1）**
- GUI / 窗体 / 热键 / 自定义控件（CE 的 `frm*`、`MainUnit`、`betterControls` 等）。
- Lua 脚本引擎与 100+ `Lua*.pas` 绑定 —— AI 用 JSON API，不需要 Lua GUI。
- 内核驱动（DBKKernel）、虚拟机监控器（dbvm / DBVM UEFI）—— 反作弊穿透/主动对抗不做。
- D3D overlay、快照 UI、训练器生成器、音频/音乐、翻译、微交易。
- 对 EAC / BattlEye 等内核保护目标的主动对抗（隐藏/绕过检测）。
- **但要防护**：反作弊系统常霸占内核（hook 系统调用、封锁句柄、占用调试接口），
  会直接干扰用户态工作。应对策略是**共存与容错**而非对抗，见 §8.3。

## 2. 架构

```
┌───────────────────────────────────────────────────────────┐
│ ce-serve (bin)  JSON-RPC 2.0 over stdio / TCP / MCP       │
│   分发器 + 会话状态 + scan_id 注册表                       │
└───────────────┬───────────────────────────────┬───────────┘
                │ ce-core (纯领域，无 I/O)        │ ce-proc (平台层)
                │  ├ scan  (值/AOB/分组扫描)      │  ├ process (枚举/attach)
                │  ├ value (值类型解释/转换)       │  ├ memory (读/写/区域/alloc)
                │  ├ disasm (反汇编抽象)          │  └ debug  (v2: 断点/监视)
                │  ├ asmb  (汇编/编码抽象)
                │  └ symbol (PE/ELF 符号/结构体)
                └───────────────────────────────────────────┘
```

分层规则：`ce-core` 不 import 平台 crate、不做任何系统调用；所有系统 I/O 经
`ce-proc` 的 trait 注入。这样扫描/反汇编/符号算法可以在任何平台单测，也便于
未来加 Linux/macOS 后端。

## 3. CE → Rust 模块映射

| Cheat Engine 源 | 职责 | ce-lite 模块 | 依赖/替代 |
|---|---|---|---|
| `ProcessHandlerUnit.pas` | 进程 attach/架构 | `ce-proc::process` | `sysinfo` + `windows` |
| `processlist.pas` | 进程枚举 | `ce-proc::process` | `sysinfo` |
| `NewKernelHandler.pas` | 内存读写/VirtualQueryEx/区域枚举 | `ce-proc::memory` | `read-process-memory` + `windows` |
| `VirtualMemory.pas` / `RemoteMemoryManager.pas` | 虚拟内存/远端分配 | `ce-proc::memory::alloc` | `VirtualAllocEx` |
| `memscan.pas` | 值/AOB/分组扫描（手写 9k 行） | `ce-core::scan` | 自写 + `rayon` |
| `savedscanhandler.pas` / `SaveFirstScan.pas` | 扫描结果持久化 | `ce-core::scan::store` | `serde` + 文件 |
| `groupscancommandparser.pas` | 分组扫描命令解析 | `ce-core::scan::group` | `nom`/`pest` |
| `byteinterpreter.pas` | 值类型解释/转换 | `ce-core::value` | 自写 |
| `pointerscancontroller.pas` 等 | 指针扫描 | `ce-core::scan::pointer` (v2) | 自写 |
| `disassembler.pas` + `disassemblerarm*.pas` | 反汇编（手写 16.6k 行） | `ce-core::disasm` | **`iced-x86`**（x86/x64）、`capstone`（ARM） |
| `Assemblerunit.pas` / `gnuassembler.pas` | 汇编（手写 7.2k 行） | `ce-core::asmb` | **`keystone`** |
| `autoassembler.pas` | AA 脚本（解析+执行） | `ce-serve::aa` (v2) | `nom` + 上述 |
| `symbolhandler.pas` | 符号/PE/ELF/结构体 | `ce-core::symbol` | **`goblin`** |
| `PEInfoFunctions.pas` | PE 解析 | `ce-core::symbol::pe` | `goblin::pe` |
| `elfsymbols.pas` | ELF 解析 | `ce-core::symbol::elf` | `goblin::elf` |
| `DebuggerInterface.pas` + `WindowsDebugger.pas` | 调试器 | `ce-proc::debug` (v2) | `windows` Debug API / `ptrace` |
| `LuaHandler.pas` + `Lua*.pas` | 脚本 | **裁剪** | JSON API 取代 |
| `MainUnit.pas` / `frm*` / forms | GUI | **裁剪** | — |
| `DBKKernel` / `dbvm` / `DBVM UEFI` | 内核/虚拟化 | **裁剪** | — |

**关键**：CE 的重一半来自手写反汇编/汇编器 + GUI + 内核三件套；AI 工具不需要
后两者，前两者用成熟库替代，重写复杂度远低于 CE 源码体积的暗示。

## 4. 依赖选型

| 能力 | 依赖 | 理由 |
|---|---|---|
| 反汇编 x86/x64 | `iced-x86` | 纯 Rust、无 C 依赖、支持编码/解码 |
| 反汇编 ARM | `capstone` | 成熟 C 库绑定 |
| 汇编（mnemonic→bytes） | `keystone` | LLVM 汇编器，支持多架构 |
| PE/ELF 符号 | `goblin` | 纯 Rust、零拷贝解析 |
| 跨进程内存读（Win） | `read-process-memory` | 稳定、处理 32/64 位 |
| WinAPI | `windows` / `windows-sys` | 官方元数据 crate |
| 扫描并行 | `rayon` | 多线程扫描（CE 强调的能力） |
| JSON | `serde` + `serde_json` | 标准 |
| 守护进程 | std `io`（v1）；`tokio`（TCP/MCP 时） | 先简单后并发 |

## 5. API Schema（JSON-RPC 2.0，newline-delimited JSON over stdio）

请求：`{"jsonrpc":"2.0","id":1,"method":"...","params":{...}}`
响应：`{"jsonrpc":"2.0","id":1,"result":{...}}` 或 `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"..."}}`

### M1（进程 / 内存 / 扫描）

| method | params | result |
|---|---|---|
| `process.list` | `{}` | `ProcessInfo[]` |
| `process.attach` | `{ "pid": u32 }` | `ProcessInfo` |
| `process.detach` | `{}` | `{}` |
| `memory.regions` | `{}` | `MemoryRegion[]` |
| `memory.read` | `{ "address": u64, "size": usize }` | `{ "bytes": base64 }` |
| `memory.write` | `{ "address": u64, "bytes": base64 }` | `{ "written": usize }` |
| `scan.new` | `{ "value_type": ValueType, "scan_type": ScanType, "value": Value }` | `{ "scan_id": u64, "count": u64 }` |
| `scan.next` | `{ "scan_id": u64, "scan_type": ScanType, "value": Value }` | `{ "scan_id": u64, "count": u64 }` |
| `scan.results` | `{ "scan_id": u64, "offset": usize, "limit": usize }` | `{ "total": u64, "results": ScanResult[] }` |
| `scan.close` | `{ "scan_id": u64 }` | `{}` |

### M2（反汇编 / 汇编 / 符号 / 分配）

| method | params | result |
|---|---|---|
| `disasm` | `{ "address": u64, "length": usize }` | `[{ "address", "bytes", "text" }]` |
| `asm` | `{ "code": string }` | `{ "bytes": base64 }` |
| `memory.alloc` | `{ "size": usize }` | `{ "address": u64 }` |
| `symbols.list` | `{ "module": string? }` | `[{ "name", "address", "module" }]` |
| `symbols.resolve` | `{ "name": string }` | `{ "address": u64 }` |

### 领域类型（见 `ce-core/src/types.rs`）

- `ValueType`: `byte | int16 | int32 | int64 | float | double | string | bytes | binary`
- `ScanType`: `exact | increased | decreased | changed | unchanged | increased_by | decreased_by | bigger_than | smaller_than | between | unknown_initial`
- `Value`: `int | float | double | string | bytes(AOB) | null`
- `MemoryRegion`: `{ base, size, protection, readable, writable, executable, name? }`
- `ProcessInfo`: `{ pid, name, arch, pointer_size }`
- `ScanResult`: `{ address, value, previous? }`

## 6. AI 驱动工作流（验证 M1 闭环）

```
1 process.list → 2 process.attach → 3 memory.regions → 4 scan.new(exact)
→ 5 scan.next(changed/increased) → 6 scan.results → 7 memory.read
→ (M2) disasm / symbols.resolve / memory.alloc + memory.write(补丁)
```

## 7. 里程碑

| 里程碑 | 能力 | 依赖 |
|---|---|---|
| M1 | attach + 区域 + 读写 + 值/AOB 扫描 | `ce-core::scan` + `ce-proc::memory` |
| M2 | 反汇编 + 符号 + 汇编补丁 + 远端分配 | `iced-x86` + `goblin` + `keystone` |
| M3 | 调试器子集（断点/监视/单步/寄存器） | `ce-proc::debug` |
| M4 | 指针扫描、ARM、结构体、快照比对 | — |

M1 即覆盖 80% 实用场景（找值→改值→读内存）。

## 8. 风险与边界

1. **平台**：内存扫描价值集中在 Windows；Linux 泛化扫描/注入更弱（`/proc/PID/mem` + `ptrace`）。
2. **权限**：跨进程内存访问需管理员/同用户权限，与宿主沙箱策略冲突时需显式授权。
3. **反作弊（防护而非对抗）**：无内核驱动/虚拟化，无法触及内核保护目标，也不追求绕过。
   反作弊常霸占内核（hook 系统调用、封锁句柄、占用调试接口、注入自身驱动），干扰用户态工作。
   应对策略：
   - **识别与规避**：attach 前检测已知反作弊进程（EAC / BattlEye / Vanguard / ACE 等），
     存在时拒绝附加受保护目标并返回明确原因，避免触发检测、避免白做无用功。
   - **错误分类与容错**：统一错误模型，区分"权限不足 / 句柄被拒 / 受保护页面 / 调试接口被占用"，
     附建议动作；扫描遇到坏页跳过而不是中断。
   - **Debug API 占用检测**：`WaitForDebugEvent`/`DebugActiveProcess` 失败时分类报告
     （另一调试器已附加），不挂死。
   - **干净恢复**：断点/监视点/补丁在 detach、stop、异常退出后自动恢复原字节，不留痕迹。
   - **最小足迹**：副作用严格限于会话内（进程句柄、已改字节），无全局 hook、无常驻线程，
     插件停止后完全无痕。
4. **合规**：定位为个人、离线、教育/逆向分析用途，不承载联机作弊。
5. **许可证**：本仓库为洁净室重写，只复用算法概念与公开接口（不搬运 Pascal 源码），
   规避 CE 缺失顶层 LICENSE 的再分发问题；但概念对齐时仍需注意不要逐行照搬。
