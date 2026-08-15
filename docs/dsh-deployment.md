# DSH 插件部署指南（安装 / 启动 / 更新 / 故障恢复）

ce-lite 有两种 DSH 集成形态：

- **会话动态插件**（默认）：插件在 DSH 会话进程内运行，派生 `ce-serve.exe` 子进程
  并通过 stdio JSON-RPC 通信，把 ce-lite 的能力注册为模型可调用的 `ce_*` 工具。
  ⚠️ 不持久：DSH 重启后定义丢失，需重新部署（第 1-4 节）。
- **宿主级插件**（推荐，所有会话共享）：作为 host composition 的一行常驻，
  任何会话（含新开的）开箱即用，**不随 DSH 会话/重启丢失**，且 patch 文件变更会
  **热重载、无需重启 DSH**（第 5 节）。

> 本机已启用宿主级方案（`celit-1` 动态插件已停用并删除）。

## 0. 前置条件

1. **构建 ce-serve**（插件硬编码了绝对路径，先保证二进制存在且最新）：

   ```powershell
   cd C:\Users\xueze\Documents\Plugin-developer\ce-lite
   cargo build -p ce-serve
   # 32 位目标支持（可选，wow64 测试用）：
   cargo build -p ce-target --target i686-pc-windows-msvc
   ```

2. **确认插件源码存档**：`dsh/celit-plugin.js` 是本仓库内唯一权威的插件代码副本。
   部署时模型会从该存档重新提交代码（动态插件 API 无补丁机制，每次部署都提交完整源码）。

3. **确认 ce-serve 未被占用**：如果插件正在运行，`ce-serve.exe` 会被锁定、无法重新编译。
   先执行第 4 步停止插件再构建。

## 1. 安装（首次部署 / DSH 重启后恢复）

在 DSH 会话中对模型说："**部署 ce-lite 插件**"（或直接引用存档文件），模型会执行：

| 步骤 | 工具 | 说明 |
|---|---|---|
| 1 | `cordis_define` | `kind: "new"`，`idPrefix: "celit"`，`code.host` = `dsh/celit-plugin.js` 的 `return { ... }` 部分。成功后返回 `pluginId`（如 `celit-1`）与 `packageId`（如 `pkg-1`） |
| 2 | `cordis_run` | `pluginId` + `packageId`，`mode: "run"`。成功后插件 `apply()` 派生 ce-serve 并注册全部 `ce_*` 工具 |

**验证安装**：

- 会话工具列表里应出现 `ce_process_list` / `ce_attach` / `ce_scan_new` 等 55 个工具；
- 系统进程里应有 `ce-serve.exe`（`Get-Process ce-serve`）。

## 2. 启动已停止的插件

插件被 `cordis_stop` 停止后（定义、包、版本指针都保留），重新激活：

```
cordis_run(pluginId="celit-1", packageId=<当前包>, mode="run")
```

> `mode: "run"` 用于首次激活、重启当前包、回滚；`mode: "update"` 用于切换到另一版本（见第 3 步）。

## 3. 更新插件（新功能 / 修复后重新部署）

代码有变化时（如改了 ce-lite Rust 代码后重建了 ce-serve，或改了插件存档），
需要**定义新包**再切换：

| 步骤 | 工具 | 说明 |
|---|---|---|
| 1 | `cargo build -p ce-serve` | 先重建二进制（插件进程占用时会失败——先 `cordis_stop`） |
| 2 | `cordis_stop` | 停止旧运行，释放 ce-serve.exe（仅当构建被锁时需要） |
| 3 | `cordis_define` | `kind: "existing"`，`pluginId: "celit-1"`，提交**完整**新源码 → 返回新 `packageId`（如 `pkg-3`）。动态插件 API 无补丁机制，必须整段提交 |
| 4 | `cordis_run` | `mode: "update"` 切换到新包。旧运行自动停止、新包启动 |

## 4. 停止 / 删除插件

- **临时停用**（保留定义，可随时重启）：`cordis_stop(pluginId)` → 终止 ce-serve 子进程并反注册工具。
- **永久删除**（清空定义、包、授权）：`cordis_undefine(pluginId)`。删除后 `pluginId` 失效，
  只能重新走第 1 步安装。

## 5. 宿主级插件（推荐：所有会话共享，热重载）

把 ce-lite 挂进 DSH 的 **host composition**（宿主组合），工具对所有会话可见、
不随会话/DSH 重启丢失。本机已启用（`~/.dsh/profiles/web/`）。

### 5.1 文件

| 文件 | 作用 |
|---|---|
| `~/.dsh/profiles/web/ce-lite-plugin.mjs` | 宿主插件本体（ESM：`name`/`inject`/`apply`，经 `ctx.tools.register` 注册 55 个工具）。仓库权威副本：`dsh/ce-lite-host-plugin.mjs` |
| `~/.dsh/profiles/web/cordis.patch.yml` | profile 的 patch 层，`insert` 一行挂载插件 |

### 5.2 挂载（一次性）

在 `cordis.patch.yml` 的数组末尾追加：

```yaml
- insert:
    - id: ce-lite
      name: ./ce-lite-plugin.mjs
```

DSH 通过 `watchUserPatches` 监视该文件——**保存即热重载，无需重启**。
验证：进程列表出现 `ce-serve.exe`（宿主派生的）；任意会话工具列表出现 `ce_*` 工具。

### 5.3 更新插件代码

1. 改 `ce-lite-plugin.mjs`（或先更新仓库 `dsh/ce-lite-host-plugin.mjs` 再拷贝）；
2. 保存后 HMR 重新加载插件：旧子进程被终止、新 apply 派生新 ce-serve（工具先反注册再注册）。
   注意重建 `ce-serve.exe` 前旧子进程可能占用二进制——先等 HMR 完成或手动结束旧进程。

### 5.4 停用 / 回滚

- **停用**：删除（或注释）patch 里的 `insert` 块，保存 → 热重载卸载插件、终止 ce-serve。
- **完整移除**：同时删除 `ce-lite-plugin.mjs`。

### 5.5 与其他会话 / 动态插件的关系

- 宿主工具注册在**全局层**；会话级工具（如动态插件注册的同名工具）会 shadow 全局，不冲突。
- 启用宿主版后，会话动态插件即可停用删除（`cordis_stop` + `cordis_undefine`），避免双份 ce-serve。

## 6. 故障排查

| 现象 | 原因与处理 |
|---|---|
| 工具列表里没有 `ce_*` 工具 | DSH 重启过，插件丢失 → 重新 `cordis_define`(kind:new) + `cordis_run`（第 1 步） |
| `cargo build -p ce-serve` 报"拒绝访问/无法删除 ce-serve.exe" | 插件（或残留进程）占用二进制 → `cordis_stop` 后重试；仍失败则 `Get-Process ce-serve \| Stop-Process -Force` |
| `cordis_run` 返回 `awaiting-approval` | 部署策略要求授权；在 UI 中允许后再继续 |
| 插件启动但工具调用报错 | 检查 ce-serve 是否为新二进制（重建后需重启插件，见第 3 步）；确认目标进程存在且权限足够 |
| 换机器 / 换目录 | `CEEXE` 绝对路径硬编码在 `dsh/celit-plugin.js`（`C:\Users\xueze\...`）→ 更新存档中的路径后重新部署 |

## 7. 工作原理（简要）

```
DSH 宿主进程（宿主插件，常驻）
  └─ apply(ctx)  [inject: tools, subprocess]
       ├─ ctx.subprocess.spawn(ce-serve.exe)          # 持久 stdio 子进程（跨会话共享）
       ├─ stdout 行分隔 JSON-RPC 请求/响应关联（pending Map）
       ├─ defineTool() + ctx.tools.register() 注册 55 个 ce_* 工具
       └─ ctx.effect：插件卸载时 terminate 子进程 + 反注册工具
```

- 工具层做 base64/字节数组转换、hexdump 渲染；方法名直接对应 ce-serve 的 JSON-RPC 方法
  （`ce_scan_new` → `scan.new`，`ce_debug_stack` → `debug.stack`，……）。
- 会话状态（附加的进程、扫描、断点）保存在 ce-serve 进程内；DSH/插件重启会清空，
  可用 `ce_session_save` / `ce_session_load` 跨会话恢复分析现场（仅结构体/指针链/补丁等，不含调试器状态）。
