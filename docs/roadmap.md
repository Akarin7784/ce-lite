# ce-lite 开发路线图

> 按"对 AI 辅助逆向的价值密度"排序。当前基线：**全部里程碑与路线图项完成**
> （除 ARM 与 MCP 暂缓；25 单测 + 20 集成测试全绿，55 个 DSH 工具）。
> 下一阶段见文末"后续方向"。

## 指导原则

- **不做主动反作弊对抗**：不实现内核驱动 / hypervisor 穿透（DBKKernel / dbvm 同款能力），
  不提供隐藏进程/句柄/绕过检测的能力。
- **但要做防护**：反作弊系统喜欢霸占内核（hook 系统调用、封锁句柄、占用调试接口、注入自身驱动），
  这会直接影响我们纯用户态的工作。对策是**共存与容错**——识别、规避、优雅降级、干净恢复，
  而不是跟它抢内核。

---

## 第一梯队：让 AI 工作流真正闭环

- [ ] 1. **MCP 服务端（`ce-mcp` crate）**：**暂缓**（用户指示）。现有 JSON-RPC 方法包一层
  Model Context Protocol（stdio），任何 MCP 客户端都能直接调；方法签名基本现成，改动小。
- [x] 2. **"谁在访问这个地址"闭环**：`debug.accessor` 已实现——监视点/断点命中后直接返回
  RIP 处指令、module+offset、符号与寄存器，AI 无需手动串联。集成测试通过。
- [x] 3. **PDB 调试符号解析**：`symbols.pdb_resolve` 已实现（DbgHelp SymFromAddrW，
  自动加载 PDB/符号服务器，反修饰函数名）。集成测试通过。
- [x] 4. **结构体自动生成（structure spawn）**：`pointer.struct_spawn` 已实现——从指针链
  自动聚合候选字段（int64，去重排序），供 `struct.define` 精化。集成测试通过。
- [x] 5. **会话持久化**：`session.save`/`session.load` 已实现——结构体、指针链、补丁、
  freeze、钩子导出为 base64 会话包，跨实例恢复。集成测试通过。

## 防护（非对抗）——与反作弊共存

- [x] 6. **反作弊感知（anti-cheat awareness）**：`protect.status`——枚举已知反作弊
  进程（EasyAntiCheat / BattlEye / Vanguard / ACE / GameGuard / XIGNCODE / PunkBuster /
  Denuvo / FACEIT），返回 `protected` 与 `kernel_protection` 摘要。集成测试通过。
- [x] 7. **错误分类与容错层**：attach 失败按 win32 错误码分类（不存在 / 权限不足 /
  受 PPL/反作弊保护 / 已被调试）；`memory.write` 自动临时改页面保护再还原；
  扫描只遍历可读区域（坏页天然跳过）。
- [x] 8. **Debug API 占用检测**：`classify_win32` 区分 access denied / invalid parameter
  （另一调试器已附加）/ invalid handle（进程已退出）。
- [x] 9. **干净恢复**：断点原字节在 detach/stop/异常退出时自动还原；硬件监视点（DR）清除；
  注入线程完成后释放远程内存；会话退出无残留。
- [x] 10. **最小足迹声明**：README"防护与合规边界"章节——纯用户态、副作用限会话内、
  无全局状态、识别与规避、合规定位。

## 第二梯队：核心算法与平台深化

- [x] 11. **扫描类型补全**：AOB 通配符掩码（`??`）、`between`（min/max）、`rounded`
  （浮点四舍五入）、XOR 扫描（逐字节密钥）。单元测试通过。
- [x] 12. **扫描性能**：rayon 并行区域扫描 + 2 秒 TTL 区域缓存（`WindowsProcess`）。
- [x] 13. **指针扫描增强**：`pointer.analyze`——union 合并（同偏移路径分组）+ 偏移聚类
  （高频偏移统计）；链持久化随 `session.save` 覆盖。
- [x] 14. **反汇编工具链**：`disasm.xrefs`（CALL 交叉引用，1 字节滑动解码）、
  `disasm.function`（函数边界识别）、disasm 缓存（会话内 LRU 256 条）。集成测试通过。
- [x] 15. **远程线程注入**：`thread.inject_dll`（LoadLibraryW 注入）+
  `thread.create_remote`（任意 shellcode 远程执行，含 arg/超时/退出码）。集成测试通过。
- [x] 16. **调用栈回溯**：`debug.stack`——RBP 链回溯，断点命中直接呈现调用栈，
  帧标注 module+offset。集成测试通过。
- [x] 17. **32 位目标（Wow64）**：位宽自动检测（PE 机器类型）→ arch/pointer_size 正确；
  调试器 Wow64 上下文（自声明 Wow64GetThreadContext/SetThreadContext + WOW64_CONTEXT）；
  WX86 断点/单步异常码（0x4000001F/0x4000001E）处理；32 位集成测试通过
  （`cargo build -p ce-target --target i686-pc-windows-msvc`）。
- [x] 18. **Linux 支持（ptrace）**：`linux.rs` 完整后端——`/proc/pid/mem` 读写、
  `/proc/pid/maps` 区域、Toolhelp 等价进程枚举、ptrace 调试器（INT3 断点/寄存器/单步/
  硬件监视点 DR 寄存器）；`cargo check --target x86_64-unknown-linux-gnu` 编译验证通过
  （无 Linux 运行环境，未做运行时测试）。

## 第三梯队：工具链与健壮性

- [x] 19. **CI（GitHub Actions）**：`.github/workflows/ci.yml`——fmt/clippy -D warnings/
  test（含 32 位 target 构建）/上传 ce-serve+ce-target artifact。
- [x] 20. **CLI 一次性模式**：`ce-serve --one-shot <method> [json]` 与紧凑式
  `--one-shot "scan:int32:exact:100"`。集成测试通过。
- [x] 21. **`ce-target` 加强**：动态分配线程、4 线程竞争值、CRC 自校验（tick 函数 CRC
  周期性刷新）、XOR/rounded/between 扫描靶值。
- [x] 22. **训练器生成**：`trainer.freeze`（后台线程周期写回）/`unfreeze`/`list`、
  `patch.export`（.CT 风格 JSON，含原字节）、`hook.install`（trampoline 自动生成：
  原指令 + jmp 回 + jmp 至钩子洞）/`hook.remove`/`hook.list`。集成测试通过。
- [x] 23. **DSH 插件打磨**：`ce_read` hexdump 渲染（地址 + hex + ASCII 侧栏）。
- [x] 24. **模块/签名库**：`module.aob_scan`（CE 风格 `"DE ?? BE EF"` 模式，可限定模块）。
  集成测试通过。

## 明确不做（保持边界）

- **主动反作弊对抗**：内核驱动、hypervisor、隐藏自身/绕过检测 —— 与防护原则冲突，不做。
- GUI / 热键 / Lua 脚本 UI —— 项目初衷就是无人类交互。
- macOS —— 性价比低。
- **暂缓**：ARM（用户指示）；MCP（用户指示）。

---

## 后续方向（全部完成后可考虑）

- **MCP 服务端**：ce-serve 已是 lib+bin 结构，`ce_serve::handle()` 就绪，包一层 MCP 协议即可。
- **`RtlVirtualUnwind` 精确解卷**：替代 RBP 链（`/Oy` 优化目标更可靠）。
- **扫描流式进度**：长扫描给 DSH 工具返回进度事件。
- **CE 风格符号库**：社区 CT 表 offset 数据库复用。
