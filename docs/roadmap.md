# ce-lite 开发路线图

> 按"对 AI 辅助逆向的价值密度"排序。当前基线：M1-M4 ✅ + 防护/分析首批 ✅
> （17 单测 + 10 集成测试全绿，39 个 DSH 工具）。

## 指导原则

- **不做主动反作弊对抗**：不实现内核驱动 / hypervisor 穿透（DBKKernel / dbvm 同款能力），
  不提供隐藏进程/句柄/绕过检测的能力。
- **但要做防护**：反作弊系统喜欢霸占内核（hook 系统调用、封锁句柄、占用调试接口、注入自身驱动），
  这会直接影响我们纯用户态的工作。对策是**共存与容错**——识别、规避、优雅降级、干净恢复，
  而不是跟它抢内核。

---

## 第一梯队：让 AI 工作流真正闭环（建议先做）

1. **MCP 服务端（`ce-mcp` crate）**
   现有 JSON-RPC 方法包一层 Model Context Protocol（stdio），任何 MCP 客户端都能直接调，
   不再绑定 DSH。方法签名基本现成，改动小。
2. **"谁在访问这个地址"闭环（访问断点 → 反汇编 → 报告）**
   硬件监视点触发 → 读 RIP/反汇编触发指令 → 自动标注"写者函数"。AI 直接拿到
   "谁在改这个值"的结论，而不是原始寄存器。CE 最高频用法，AI 化收益最大。
3. **PDB 调试符号解析**
   现有 goblin 只能解析 PE 导出。加 `pdb` crate：地址→函数名，断点命中后直接报
   "命中了 `Player::UpdateHealth`" 而非裸地址。
4. **结构体自动生成（structure spawn）**
   指针扫描出多条链后，自动把各级偏移聚合成候选 `struct.define` 字段。
   让"值扫描→指针→结构"全自动。
5. **会话持久化（save/load JSON）**
   扫描候选、指针链、结构体、断点/监视点、区域缓存可导出/导入。AI 跨会话恢复分析现场。

## 防护（非对抗）——与反作弊共存

- [x] 6. **反作弊感知（anti-cheat awareness）**：`protect.status` 已实现——枚举已知反作弊
  进程（EasyAntiCheat / BattlEye / Vanguard / ACE / GameGuard / XIGNCODE / PunkBuster /
  Denuvo / FACEIT），返回 `protected` 与 `kernel_protection` 摘要。集成测试通过。
- [x] 7. **错误分类与容错层**（首批）：attach 失败已分类——进程不存在 / 权限不足 /
  可能受 PPL/反作弊保护（win32 错误码映射）。待补：扫描坏页跳过、`VirtualProtectEx` 失败重试。
- [ ] 8. **Debug API 占用检测**：`DebugActiveProcess` / `WaitForDebugEvent` 失败分类
  （另一调试器已附加），不挂死。
- [x] 9. **干净恢复**（已有基础）：断点/监视点在 detach、stop、异常退出后自动恢复原字节；
  注入线程完成后自动释放远程内存。待补：异常退出时的全局清理钩子。
- [ ] 10. **最小足迹声明**：文档化"个人/离线/教育/逆向分析"定位与边界（README 已声明，
  待补完整章节）。

## 第二梯队：核心算法与平台深化

11. **扫描类型补全**：AOB 通配符（`??` 掩码）、浮点 rounded/二分扫描、"between"、XOR 扫描。
12. **扫描性能**：candidate 并行（rayon）、SIMD 值比较、区域缓存复用。
13. **指针扫描增强**：多结果合并（union）、偏移聚类（高频偏移）、链持久化。
14. **反汇编工具链**：CALL 目标交叉引用（"谁调用了这个函数"）、函数边界识别、反汇编缓存。
- [x] 15. **远程线程注入**（首批）：`thread.inject_dll`（LoadLibraryW 注入）+
  `thread.create_remote`（任意 shellcode 远程执行，含 arg/超时/退出码）。集成测试通过。
- [x] 16. **调用栈回溯**（首批）：`debug.stack`——RBP 链回溯，断点命中直接呈现调用栈，
  帧标注 module+offset。集成测试通过。待补：`RtlVirtualUnwind` 精确解卷。
17. **32 位目标（Wow64）**：`WOW64_CONTEXT`、DR 寄存器布局、iced-x86 bitness 切换。
18. **Linux 支持（ptrace）**：`/proc/pid/mem` 读写 + ptrace attach + 软断点（`nix` crate）。

## 第三梯队：工具链与健壮性

19. **CI（GitHub Actions）**：`cargo fmt --check` + `cargo clippy` + `cargo test` +
    上传 `ce-serve.exe` artifact。
20. **CLI 一次性模式**：`ce-serve --one-shot "scan:int32:exact:100"`，脚本化调用不写 JSON-RPC。
21. **`ce-target` 加强**：动态分配、多线程竞争、CRC 自校验、混淆值，当更硬的测试靶子。
22. **训练器生成**：freeze 值（每帧写回）+ code cave 注入（alloc + asm 组合成 hook）+
    补丁导出（`.CT` 风格 JSON）。
23. **DSH 插件打磨**：工具结果渲染（十六进制转储表格、ASCII 侧栏）、长扫描流式进度。
24. **模块/签名库**：AOB 签名在已加载模块中匹配 + 社区 CT 表格式读取（offset 数据库复用）。

## 明确不做（保持边界）

- **主动反作弊对抗**：内核驱动、hypervisor、隐藏自身/绕过检测 —— 与防护原则冲突，不做。
- GUI / 热键 / Lua 脚本 UI —— 项目初衷就是无人类交互。
- macOS —— 性价比低。

---

## 推荐执行顺序

**立即**：#1 MCP（打通所有 AI 客户端）、#3 PDB（调试器从"能用"到"好用"）、
#8 Debug API 占用检测 + #9 异常退出清理（防护收尾）、#19 CI（工程质量）。
**紧接着**：#2 访问者闭环、#4 structure spawn、#5 会话持久化 ——
把"扫描→指针→结构→谁在写"串成一条 AI 可自助跑完的流水线。
