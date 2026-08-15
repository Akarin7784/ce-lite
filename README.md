# ce-lite

一个面向 AI 代理的、无 GUI 的轻量内存逆向工具核心，从 Cheat Engine 的核心能力中
按"AI 真正需要的功能"裁剪并重写而来。

> 目标：把 Cheat Engine 的核心（跨进程内存 + 扫描 + 反汇编 + 符号 + 调试）从
> 庞大的人机交互外壳中剥离，重写成现代化语言（Rust），对外暴露成 JSON/MCP
> 守护进程，由 AI 代理（如 DeepSeek Harness 插件）驱动。

## 设计原则

- **无人类交互**：不做 GUI、不做热键、不做 Lua 脚本 UI、不做训练器/overlay。
- **机器可调**：JSON-RPC 2.0 over stdio（后续加 TCP/MCP），返回结构化数据。
- **核心是纯算法**：扫描、值解释、反汇编、符号解析与平台解耦，可单测。
- **平台层是薄封装**：跨进程内存读写/调试集中在 `ce-proc`，Windows-first。
- **不做反作弊对抗**：不实现内核驱动 / hypervisor 穿透；但要**防护**——反作弊霸占内核
  会干扰用户态工作，通过"识别-规避-容错-干净恢复"与其共存（详见 `docs/roadmap.md`）。

## 工作区结构

```
crates/
  ce-core/   # 平台无关的领域核心：类型、扫描算法、值解释、反汇编/汇编/符号抽象
  ce-proc/   # 平台层：进程打开、内存读写、区域枚举、远端分配（Windows-first）
  ce-serve/  # 守护进程 bin：JSON-RPC over stdio 分发器（后续 MCP/TCP）
docs/
  design.md  # 架构设计、CE→Rust 模块映射、API schema
```

## 构建（需要 Rust 工具链）

```powershell
# 安装 Rust（首次）： https://rustup.rs
cargo build -p ce-serve
```

## 状态

- [x] M1：attach + 区域枚举 + 读/写 + 值/AOB 扫描（已实现 + 端到端验证）
- [x] M2：反汇编(iced-x86) + 符号(goblin) + 远端分配(VirtualAllocEx) + 汇编(keystone)（已实现 + 验证）
- [x] 指针扫描：多层指针链 + 静态过滤（指针须指向有效内存）+ 二次快照去噪（单元 + 集成测试）
- [x] M3：调试器子集——软件断点(INT3) + 寄存器读写 + 继续/等待（集成测试）
- [x] 硬件监视点：DR0-DR7 数据监视（"找出谁在写这个地址"），支持读/写、1/2/4/8 字节，最多 4 个（集成测试）
- [x] 单步执行：`debug.single_step`（配合监视点/断点追踪执行流，集成测试）
- [x] 内存快照/差异：`memory.snapshot` + `memory.diff`（区域监视，找出哪些字节变了，集成测试）
- [x] M4：结构体定义/读取（`struct.define`/`struct.read`/`struct.list`/`struct.delete`，集成测试）
- [x] 防护：反作弊感知（`protect.status` 检测 EAC/BattlEye/Vanguard/ACE 等）+ attach 错误分类
  （区分进程不存在 / 权限不足 / 受保护，集成测试）
- [x] 分析：远程线程注入（`thread.inject_dll` 加载 DLL、`thread.create_remote` 执行任意 shellcode，集成测试）
- [x] 分析：调用栈回溯（`debug.stack`，RBP 链，断点命中后直接呈现调用栈 + 模块标注，集成测试）
- [ ] ARM（按计划暂缓）

验证方式：

```powershell
cargo test                                            # 17 单元测试 + 10 集成测试
cargo test -p ce-serve --test pointer_rescan          # 二次快照去噪（跨进程，含 decoy 翻转）
cargo test -p ce-serve --test debugger                # 调试器：断点命中 + 寄存器读取
cargo test -p ce-serve --test watchpoint              # 硬件监视点：写触发 + 单步
cargo test -p ce-serve --test snapshot                # 内存快照/差异比对
cargo test -p ce-serve --test structure               # 结构体定义/读取字段
cargo test -p ce-serve --test protect                 # 反作弊感知 + attach 错误分类
cargo test -p ce-serve --test inject                  # 远程线程注入（shellcode + DLL）
cargo test -p ce-serve --test stack                   # 调用栈回溯
pwsh -File scripts/smoke-test.ps1                     # M1+M2 跨进程端到端冒烟测试
```

## DeepSeek Harness 集成

ce-lite 已封装为一个 DSH 动态插件（Host 半区），把 ce-serve 的能力暴露为
模型可调用的 39 个工具。源码存档在 `dsh/celit-plugin.js`。

- 插件 ID：`celit-1`（动态插件不随 DSH 重启保留；重启后需用存档重新 `cordis_define`+`cordis_run` 部署）
- 行为：`apply()` 派生 `ce-serve.exe`，在 stdio 上做 JSON-RPC 关联，注册工具
- 核心工具：`ce_process_list`、`ce_attach`、`ce_regions`、`ce_read`、`ce_write`、
  `ce_alloc`、`ce_memory_snapshot`、`ce_memory_diff`、`ce_scan_new`、`ce_scan_next`、
  `ce_scan_results`、`ce_scan_close`、`ce_disasm`、`ce_asm`、`ce_symbols_resolve`
- 防护工具：`ce_protect_status`（attach 前检测已知反作弊，返回 protected/kernel_protection）
- 结构体工具：`ce_struct_define`（name + fields[{name,value_type,offset,size?}]）、
  `ce_struct_read`（按定义在地址处解读各字段）、`ce_struct_list`、`ce_struct_delete`
- 指针扫描工具：`ce_pointer_scan`（一次性）、`ce_pointer_scan_start` + `ce_pointer_rescan`
  + `ce_pointer_results` + `ce_pointer_close`（二次快照去噪流程）
- 调试器工具：`ce_debug_attach`、`ce_debug_breakpoint_set`、`ce_debug_wait`、
  `ce_debug_registers`、`ce_debug_continue`、`ce_debug_breakpoint_clear`、
  `ce_debug_registers_set`、`ce_debug_detach`
- 硬件监视点：`ce_debug_watchpoint_set`（address/size/on_read/on_write）、
  `ce_debug_watchpoint_clear`
- 单步执行：`ce_debug_single_step`；调用栈：`ce_debug_stack`（RBP 链回溯，帧标注 module+offset）
- 注入工具：`ce_thread_inject_dll`（远程线程跑 LoadLibraryW）、`ce_thread_create_remote`
  （远程线程执行任意 x64 shellcode，可用 `ce_asm` 生成）
- 生命周期：插件停止时终止子进程并反注册工具

在 DSH 会话中激活后，模型即可用以下工作流驱动逆向：

```
ce_protect_status → ce_process_list → ce_attach(pid) → ce_scan_new(int32, exact, 100)
→ ce_scan_next(changed) → ce_scan_results → ce_read(address) → ce_disasm(...)
→ ce_pointer_scan_start(address) → (值变化后) ce_pointer_rescan → ce_pointer_results
→ ce_debug_attach(pid) → ce_debug_breakpoint_set(addr) → ce_debug_wait → ce_debug_registers
→ ce_debug_stack(thread_id) → ce_debug_continue                     (断点处看调用栈)
→ ce_debug_watchpoint_set(addr, size, on_write) → ce_debug_wait → ce_debug_registers  (谁在写这个地址)
→ ce_asm("...") → ce_thread_create_remote(pid, code)                (攻击模拟/远程执行)
```

> 注意：插件硬编码了 `ce-serve.exe` 的绝对路径
> （`target\debug\ce-serve.exe`）；换机器需先 `cargo build -p ce-serve`
> 并更新 `dsh/celit-plugin.js` 里的 `CEEXE` 路径。

