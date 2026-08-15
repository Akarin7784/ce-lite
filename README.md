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

## 防护与合规边界（最小足迹声明）

ce-lite 是**纯用户态**工具，设计上不留下可被检测的痕迹，也不提供对抗能力：

- **无内核接触**：不加载驱动、不操作 SSDT/EPROCESS 等内核对象、不 hook 系统调用。
- **副作用严格限于会话内**：所有句柄、已改字节、调试寄存器都归属一次附加会话；
  `detach`/`stop`/异常退出时自动还原断点与补丁原字节、清除硬件监视点、释放远程分配。
- **无全局状态**：不注册全局 hook、不创建隐藏线程、不修改全局注册表/文件；
  进程退出后系统状态与附加前完全一致。
- **识别与规避**：`protect.status` 在附加前检测已知反作弊（EAC / BattlEye / Vanguard /
  ACE / GameGuard 等），受保护目标由调用方决定是否继续——工具本身不做任何绕过。
- **合规定位**：本工具面向个人、离线、教育/逆向分析场景；不提供联机作弊、不提供
  反作弊规避能力，不对受内核保护的目标做对抗。

## 工作区结构

```
crates/
  ce-core/   # 平台无关的领域核心：类型、扫描算法、值解释、反汇编/汇编/符号抽象
  ce-proc/   # 平台层：进程打开、内存读写、区域枚举、远端分配（Windows-first，含 Linux ptrace 后端）
  ce-serve/  # 守护进程：lib（分发器/会话）+ bin（stdio 服务与 --one-shot 模式）
docs/
  design.md  # 架构设计、CE→Rust 模块映射、API schema
  roadmap.md # 开发路线图（防护/分析/平台扩展）
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
- [x] 访问者闭环：`debug.accessor`（命中后直接返回 RIP 指令 + 模块/符号 + 寄存器，"谁在访问这个地址"）
- [x] PDB 符号：`symbols.pdb_resolve`（DbgHelp，地址 → 反修饰函数名）
- [x] 扫描类型补全：AOB 通配符（`??` 掩码）、`between`、`rounded`、XOR 扫描（单元测试）
- [x] 扫描性能：rayon 并行 + 区域缓存（TTL 2s）
- [x] 指针分析：`pointer.analyze`（union 合并 + 偏移聚类）、`pointer.struct_spawn`（结构体自动生成）
- [x] 反汇编工具链：`disasm.xrefs`（CALL 交叉引用）、`disasm.function`（函数边界）+ 反汇编缓存
- [x] 会话持久化：`session.save`/`session.load`（结构体/指针链/补丁/freeze/钩子跨实例恢复）
- [x] 训练器：`trainer.freeze`/`unfreeze`/`list`（后台写回）、`patch.export`（.CT 风格 JSON）
- [x] 内联钩子：`hook.install`（trampoline 自动生成）/`hook.remove`/`hook.list`
- [x] 模块签名：`module.aob_scan`（CE 风格 `"DE ?? BE EF"`，可限定模块）
- [x] CLI 一次性模式：`ce-serve --one-shot "scan:int32:exact:100"`
- [x] 32 位目标（Wow64）：位宽自动检测 + Wow64 上下文调试（WX86 断点/单步码处理，32 位集成测试）
- [x] Linux 后端（ptrace）：`/proc/pid/mem` + ptrace 调试器（`cargo check --target x86_64-unknown-linux-gnu` 编译验证）
- [x] CI：GitHub Actions（fmt + clippy -D warnings + 全量测试含 32 位 target + artifact）
- [ ] ARM（按计划暂缓）；MCP（按用户指示暂缓）

验证方式：

```powershell
cargo build -p ce-target                                             # 测试靶子（64 位）
cargo build -p ce-target --target i686-pc-windows-msvc               # 32 位靶子（Wow64 测试）
cargo test                                                           # 25 单元 + 20 集成测试
cargo test -p ce-serve --test advanced                               # 高级功能（扫描类型/指针分析/钩子/freeze/会话）
cargo test -p ce-serve --test wow64                                  # 32 位目标（attach/扫描/断点/寄存器）
cargo clippy --all-targets                                           # 零警告
pwsh -File scripts/smoke-test.ps1                                    # M1+M2 跨进程端到端冒烟测试
```

## DeepSeek Harness 集成

ce-lite 已封装为一个 DSH 动态插件（Host 半区），把 ce-serve 的能力暴露为
模型可调用的 55 个工具。源码存档在 `dsh/celit-plugin.js`。

- 插件 ID：`celit-1`（动态插件不随 DSH 重启保留；重启后需用存档重新 `cordis_define`+`cordis_run` 部署）
- 行为：`apply()` 派生 `ce-serve.exe`，在 stdio 上做 JSON-RPC 关联，注册工具
- 核心工具：`ce_process_list`、`ce_attach`、`ce_regions`、`ce_read`（hexdump 渲染）、`ce_write`、
  `ce_alloc`、`ce_memory_snapshot`、`ce_memory_diff`、`ce_scan_new`（支持 between/rounded/xor/
  通配掩码）、`ce_scan_next`、`ce_scan_results`、`ce_scan_close`、`ce_disasm`、`ce_asm`、
  `ce_symbols_resolve`、`ce_symbols_pdb_resolve`、`ce_module_aob_scan`
- 防护工具：`ce_protect_status`（attach 前检测已知反作弊，返回 protected/kernel_protection）
- 结构体工具：`ce_struct_define`、`ce_struct_read`、`ce_struct_list`、`ce_struct_delete`、
  `ce_pointer_struct_spawn`（从指针链自动生成候选字段）
- 指针扫描工具：`ce_pointer_scan`（一次性）、`ce_pointer_scan_start` + `ce_pointer_rescan`
  + `ce_pointer_results` + `ce_pointer_close`（二次快照去噪流程）、`ce_pointer_analyze`
  （union 合并 + 偏移聚类）
- 调试器工具：`ce_debug_attach`、`ce_debug_breakpoint_set`、`ce_debug_wait`、
  `ce_debug_registers`、`ce_debug_continue`、`ce_debug_breakpoint_clear`、
  `ce_debug_registers_set`、`ce_debug_detach`
- 硬件监视点：`ce_debug_watchpoint_set`（address/size/on_read/on_write）、
  `ce_debug_watchpoint_clear`
- 执行流：`ce_debug_single_step`、`ce_debug_stack`（RBP 链回溯）、`ce_debug_accessor`
  （命中点 RIP 指令 + 模块/符号 + 寄存器）
- 注入工具：`ce_thread_inject_dll`（远程线程跑 LoadLibraryW）、`ce_thread_create_remote`
  （远程线程执行任意 x64 shellcode，可用 `ce_asm` 生成）
- 训练器：`ce_trainer_freeze`/`ce_trainer_unfreeze`/`ce_trainer_list`（后台写回）、
  `ce_patch_export`（.CT 风格补丁 JSON）
- 内联钩子：`ce_hook_install`（trampoline 自动生成）/`ce_hook_remove`/`ce_hook_list`
- 会话：`ce_session_save`/`ce_session_load`（跨实例恢复分析现场）
- 反汇编工具链：`ce_disasm_xrefs`（CALL 交叉引用）、`ce_disasm_function`（函数边界）
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

