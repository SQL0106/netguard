# fix-uninstall：卸载时清理 WFP 持久化对象

> 只读审查 + 静态核对结论。**本机未编译**（不跑 cargo build/check/test/clippy/fmt、不跑 rustc），
> 逐行读码并对照 `/opt/winsys/windows-sys-0.59.0/` 的权威签名。
> 改动文件仅两个：`crates/win/src/cli.rs`、`install.ps1`；
> `crates/win/src/wfp.rs` 由另一子代理维护，**只读未改**。

## 1. 规格（原文抄录）

### 缺陷
`install.ps1 -Uninstall` 只删服务、删文件、删数据目录，**不清理 WFP 里的持久化过滤器 /
Provider / 子层**。这些对象带 `FWPM_FILTER_FLAG_PERSISTENT`，会一直留在内核里直到被显式
删除——卸载后机器上仍残留阻断规则，且重装时会与旧对象同名冲突（历史上已因残留的非持久化
Provider/子层触发过 `FWP_E_LIFETIME_MISMATCH`）。

### A. `crates/win/src/cli.rs` 新增子命令 `wfp-purge`
- 打开 WFP 引擎，按本程序 `providerKey` 枚举并删除所有过滤器 → 删子层 → 删 Provider →
  关闭引擎；全程幂等（对象不存在一律当成功）。
- 打印一行中文结果；失败返回非 0。
- GUID 从 `crate::wfp` 引用（`PROVIDER_KEY`/`SUBLAYER_KEY` 为 `pub`；若不可用则本地声明并注明）。
- 枚举模板 `actionMask` 必须能拿到结果（`u32::MAX` 或终止/非终止 FLAG 位）；不要照抄
  `wfp.rs` 里那套有 bug 的写法。
- entries 缓冲区活着时不删过滤器：先收 `filter_id`，`FwpmFreeMemory0` 之后逐条
  `FwpmFilterDeleteById0`。

### B. `install.ps1`
卸载流程里 **停止/删除服务之前**：`sc stop` → 轮询 STOPPED → `netguard.exe wfp-purge`
（二进制不存在只警告、不中断）→ 原有 `sc delete` / 删文件 / 删数据目录。
注释写清「必须先停服务再 purge，否则服务会立刻重建过滤器」。

### C. 静态核对
- `cli.rs` 现有分发结构，新分支需一致。
- 每个 windows-sys 函数精确参数类型，逐条列出。
- `install.ps1` 改动处 PowerShell 语法（引号、`&` 调用、`$LASTEXITCODE`）。
- 确认没有 `unsafe` 块外的裸指针操作、没有漏 `FwpmEngineClose0`。

### 追加要求（第二轮，已落实）
1. `collect_filter_ids()` **改为逐层枚举**：零 `layerKey` 语义未定义，按
   `FWPM_LAYER_ALE_AUTH_CONNECT_V4` / `_V6` 各枚举一遍再合并去重；`actionMask` 用
   `u32::MAX`（MSDN：`0xFFFFFFFF` = 忽略动作类型），不要用三个 FLAG 位拼。
2. `delete_provider_objects()` 遇到 `FWP_E_IN_USE` **不能静默当成功**：打印警告 + 返回非 0，
   让 `install.ps1` 的 `$LASTEXITCODE -ne 0` 走警告路径（不中断卸载）。
3. 报告收尾（本文件）。

## 2. TODO

- [x] 读 `wfp.rs` 确认 `PROVIDER_KEY` / `SUBLAYER_KEY` 可见性与 `Engine` 公开 API
- [x] 查 windows-sys 0.59 中所有相关函数签名与 `FWP_*` 常量
- [x] cli.rs：`wfp-purge` 实现（逐层枚举 → 收集 id → 删除过滤器 → 子层 → Provider → 关引擎）
- [x] cli.rs：`main()` 分派 + `HELP` 文本
- [x] install.ps1：`Invoke-WfpPurge` + `Remove-Installation` 顺序调整
- [x] 静态核对（类型 / FFI / PowerShell 语法 / unsafe 边界）
- [x] 写结论与存疑

## 3. 执行记录

### 3.1 改动位置

| 文件 | 行号 | 内容 |
| --- | --- | --- |
| `crates/win/src/cli.rs` | 1–4 | 模块文档补 `wfp-purge` |
| `crates/win/src/cli.rs` | 6、9 | 新增 `use std::ffi::c_void;`、`use std::ptr;` |
| `crates/win/src/cli.rs` | 14–19 | `GUID`、`Win32::Foundation` 的 7 个 `FWP_E_*`、`...WindowsFilteringPlatform as wfp` |
| `crates/win/src/cli.rs` | 33 | `HELP` 增一行 |
| `crates/win/src/cli.rs` | 56 | `main()` 分派 `Some("wfp-purge") => wfp_purge(),` |
| `crates/win/src/cli.rs` | 162–404 | 新增实现块（见下） |
| `install.ps1` | 250–271 | 新增 `Invoke-WfpPurge` |
| `install.ps1` | 274–294 | `Remove-Installation` 拆成「只停服务 → 轮询 STOPPED → purge → sc delete」 |

`cli.rs` 新实现块细分：

| 行号 | 项 |
| --- | --- |
| 164–169 | `AUTHN_WINNT` / `ERROR_SUCCESS` / `ENUM_BATCH` |
| 171–176 | `PURGE_LAYERS`（两层常量，避免零 `layerKey`） |
| 178–194 | `wfp_error()`、`wfp_missing()`（`FWP_E_*_NOT_FOUND` 家族） |
| 196–236 | `struct PurgeEngine(HANDLE)` + `open()` + `Drop`（`FwpmEngineClose0`） |
| 238–316 | `collect_layer_filter_ids()`（单层枚举，只收 id） |
| 318–327 | `collect_filter_ids()`（逐层调用 + `sort_unstable`/`dedup` 合并） |
| 329–342 | `delete_filters()`（缓冲区已释放后逐条 `FwpmFilterDeleteById0`） |
| 344–379 | `delete_provider_objects()` + `warn_delete_object()`（含 `FWP_E_IN_USE`） |
| 381–404 | `wfp_purge()`（编排 + 结果行 + 非零退出） |

### 3.2 分发结构一致性核对

`main()` 原有形态（未改动）：

```rust
match args.first().map(|value| value.as_str()) {
    Some("service") => crate::svc::run_service(),
    Some("console") => crate::svc::run_console(),
    Some("setup") => setup(&args[1..]),
    Some("status") => status(),
    Some("config") => config_command(&args[1..]),
    ...
    Some(other) => { eprintln!("未知子命令：{other}"); print!("{HELP}"); Err(...) }
}
```

- 分支形式：`Some("字面量") => 函数调用`，返回 `io::Result<()>`；新分支
  `Some("wfp-purge") => wfp_purge()` 完全同形，`wfp_purge() -> io::Result<()>`。
- 参数解析方式：`wfp-purge` 不吃参数，故未用 `parse_flag`，也**不**把 `&args[1..]` 传进去
  （与 `status()` 一致）。
- 失败传播：`bin/netguard.rs` 里 `if let Err(e) = netguard_win::run() { eprintln!; exit(1) }`
  → `wfp_purge` 返回 `Err` 即退出码 1，满足「失败非 0」。
- `HELP` 与模块文档同步更新。

### 3.3 windows-sys 0.59 精确签名（逐条，含行号）

来源：`/opt/winsys/windows-sys-0.59.0/src/Windows/Win32/NetworkManagement/WindowsFilteringPlatform/mod.rs`

| 函数 | 行 | 精确签名 |
| --- | --- | --- |
| `FwpmEngineOpen0` | 35 | `(servername: PCWSTR, authnservice: u32, authidentity: *const SEC_WINNT_AUTH_IDENTITY_W, session: *const FWPM_SESSION0, enginehandle: *mut HANDLE) -> u32` |
| `FwpmEngineClose0` | 29 | `(enginehandle: HANDLE) -> u32` |
| `FwpmFilterCreateEnumHandle0` | 43 | `(enginehandle: HANDLE, enumtemplate: *const FWPM_FILTER_ENUM_TEMPLATE0, enumhandle: *mut HANDLE) -> u32` |
| `FwpmFilterEnum0` | 48 | `(enginehandle: HANDLE, enumhandle: HANDLE, numentriesrequested: u32, entries: *mut *mut *mut FWPM_FILTER0, numentriesreturned: *mut u32) -> u32` |
| `FwpmFilterDeleteById0` | 44 | `(enginehandle: HANDLE, id: u64) -> u32` |
| `FwpmFilterDestroyEnumHandle0` | 46 | `(enginehandle: HANDLE, enumhandle: HANDLE) -> u32` |
| `FwpmSubLayerDeleteByKey0` | 178 | `(enginehandle: HANDLE, key: *const GUID) -> u32` |
| `FwpmProviderDeleteByKey0` | 160 | `(enginehandle: HANDLE, key: *const GUID) -> u32` |
| `FwpmFreeMemory0` | 62 | `(p: *mut *mut core::ffi::c_void)`（返回 `()`） |

要点：

- `FwpmFilterEnum0` 的 `entries` 是**三重指针** `*mut *mut *mut FWPM_FILTER0`。本实现的局部变量
  是 `let mut entries: *mut *mut wfp::FWPM_FILTER0 = ptr::null_mut();`，传 `&mut entries`
  正好得到 `*mut *mut *mut FWPM_FILTER0` ✓（与 `wfp.rs` 同写法）。
- `FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut c_void)` ✓ 与签名一致。
- `FwpmSubLayerDeleteByKey0` / `FwpmProviderDeleteByKey0` 第二个参数是 `*const GUID`，
  传 `&sublayer_key` / `&provider_key`（局部 `GUID` 值）✓。
- `FwpmEngineOpen0` 的 `servername`/`authidentity` 传 `ptr::null()`，`session` 传 `&session`，
  `enginehandle` 传 `&mut handle` ✓；第三个参数类型依赖 `Win32_System_Rpc` 特性，该特性已在
  `crates/win/Cargo.toml` 启用（`wfp.rs` 早已使用同一签名）。

错误码（`.../Win32/Foundation/mod.rs`，均为 `HRESULT = i32`，不带额外 cfg）：

| 常量 | 值 | 行 |
| --- | --- | --- |
| `FWP_E_FILTER_NOT_FOUND` | 0x80320003 | 4974 |
| `FWP_E_PROVIDER_NOT_FOUND` | 0x80320005 | 5013 |
| `FWP_E_NEVER_MATCH` | 0x80320033 | 5004 |
| `FWP_E_NOT_FOUND` | 0x80320008 | 5006 |
| `FWP_E_SUBLAYER_NOT_FOUND` | 0x80320007 | 5017 |
| `FWP_E_LAYER_NOT_FOUND` | 0x80320004 | 5000 |
| `FWP_E_IN_USE` | 0x8032000A | 4995 |

因为它们是 `i32`（HRESULT 高位为 1），比较一律写 `code as i32 == FWP_E_...`，
**没有**手抄数值，也**没有**误用 Win32 的 `ERROR_NOT_FOUND (1168)`。
其他引用常量：`FWPM_LAYER_ALE_AUTH_CONNECT_V4` :535、`_V6` :537（均为 `GUID`）、
`FWP_FILTER_ENUM_FULLY_CONTAINED` :902（`i32 = 0`）。

### 3.4 枚举设计（关键修正）

1. **逐层枚举，不留零 `layerKey`**：零 GUID 的 `layerKey` 语义 MSDN 未定义，改按
   `PURGE_LAYERS = [ALE_AUTH_CONNECT_V4, ALE_AUTH_CONNECT_V6]` 两层各建一次枚举句柄，
   `collect_layer_filter_ids()` 每个层做一遍完整分页，`collect_filter_ids()` 合并后
   `sort_unstable` + `dedup`。NetGuard 的过滤器只可能出现在这两层（`wfp.rs::add_one`
   是唯一创建点），覆盖完整。
2. **`actionMask = u32::MAX`**：MSDN《FWPM_FILTER_ENUM_TEMPLATE0 / actionMask》原文
   "Only filters whose action type contains at least one of the bits in actionMask will be
   returned"，且表中明确 `0xFFFFFFFF` = "Ignore the filter's action type when enumerating"。
   留 0 会恒枚举空（正是旧 `wfp.rs` 每次启动重加一对的根因）。
   **未**采用「三个 FLAG 位拼接」的原因：MSDN 对 `FWP_ACTION_FLAG_CALLOUT` 明确要求
   "calloutKey must not be NULL"，而本命令 `calloutKey` 是空指针（模板只按 provider + 层收窄），
   拼上该位属于无效组合；只拼 `TERMINATING|NON_TERMINATING` 又会漏掉无这两个位的动作类型，
   不如 `0xFFFFFFFF` 干净。
3. **先把 id 收进 `Vec` 再删**：`collect_layer_filter_ids()` 只在 entries 存活期间读
   `(*entry).filterId`，随即 `FwpmFreeMemory0`，然后才由 `delete_filters()` 逐条
   `FwpmFilterDeleteById0` —— 不存在「缓冲区活着时删对象」的悬垂内存风险。
4. **分页终止条件**：`returned < ENUM_BATCH` 或非成功码即结束；非成功码里
   `FWP_E_*_NOT_FOUND` / `FWP_E_NEVER_MATCH` 视为正常结束，其它错误上报（不静默当空集合）。
5. **幂等**：建句柄阶段 `*_NOT_FOUND` / `NEVER_MATCH` / `LAYER_NOT_FOUND` → 空集合；
   删除阶段 `*_NOT_FOUND` 家族 → 视为成功（`delete_filters` 里也计入 `removed`）。

### 3.5 `FWP_E_IN_USE` 处理

`delete_provider_objects()` 顺序：子层 → Provider。每个删除若返回非零且不是「找不到」：

- 调 `warn_delete_object(对象名, code)`：
  - `code as i32 == FWP_E_IN_USE` → `警告：<子层|Provider>仍被过滤器引用（FWP_E_IN_USE，0x8032000A），存在未能删除的过滤器。`
  - 其它 → `警告：删除<子层|Provider>失败（错误码 0x...）。`
- 同时把 `io::Error` 记进 `failure` 返回，`wfp_purge()` 据此打印
  `警告：已清理过滤器 N 条，但仍有 WFP 对象残留。` 并返回 `Err` → `exit(1)`。

过滤器本身删不掉（`delete_filters` 的首个错误）也走同一条失败路径。于是 `install.ps1`
的 `$LASTEXITCODE -ne 0` 触发「警告：WFP 过滤器清理失败（退出码 N），继续卸载」，
**不会静默成功，也不中断卸载**。

### 3.6 unsafe 边界 / 句柄收尾核对

- 裸指针只在三个 `unsafe fn` 内部（`collect_layer_filter_ids` / `delete_filters` /
  `delete_provider_objects`）与 `PurgeEngine::open`、`PurgeEngine::drop` 的 `unsafe {}` 块里；
  非 unsafe 的 `wfp_purge()` 对每个 unsafe 调用都显式包 `unsafe { ... }`。
  `wfp_error` / `wfp_missing` / `warn_delete_object` / `PURGE_LAYERS` 等不出现指针。
- 引擎句柄：`PurgeEngine` 的 `Drop` 里 `FwpmEngineClose0(self.0)`，`wfp_purge()` 中任何
  `?` 提前返回都会析构 `engine` → 关句柄。**WFP 引擎句柄只能用 `FwpmEngineClose0` 关闭**
  （它不是内核对象句柄，`CloseHandle` 不适用，也不应调用），故无 `CloseHandle` 遗漏问题。
- 枚举句柄：`FwpmFilterCreateEnumHandle0` 成功后，唯一的退出路径（循环之后）都会
  `FwpmFilterDestroyEnumHandle0`；提前 `return Ok(Vec::new())` 只发生在建句柄之前或句柄为空时。
- 枚举缓冲：每次 `FwpmFilterEnum0` 后都判断 `!entries.is_null()` 再 `FwpmFreeMemory0`，
  与 `wfp.rs` 的既有写法一致。
- 未新增 `unwrap`/`expect`；`eprintln!`/`println!` 不涉及格式化外部 `String` 的生命周期问题。

### 3.7 install.ps1 语法核对

```powershell
function Invoke-WfpPurge {
    $svc = Get-Service-State $ServiceName
    if ($svc -and $svc.Status -ne 'Stopped') { ... return }
    $exe = Join-Path $InstallDir 'netguard.exe'
    if (-not (Test-Path -LiteralPath $exe)) { Write-Step "警告：未找到 $exe，跳过 WFP 过滤器清理。"; return }
    Write-Step '正在清理 WFP 持久化过滤器。'
    & $exe 'wfp-purge'
    if ($LASTEXITCODE -ne 0) { Write-Step ('警告：WFP 过滤器清理失败（退出码 ' + $LASTEXITCODE + '），继续卸载。') }
}
```

- `& $exe 'wfp-purge'`：`&` 调用运算符 + 变量路径，路径含空格（`C:\Program Files\NetGuard`）
  也安全；参数用单引号字面量，无插值风险。`$LastExitCode`（`$LASTEXITCODE` 为同一变量的
  大小写不敏感写法）由原生进程设置，随后立即比较，中间不再执行其它原生命令 ✓。
- `$exe` 在双引号字符串里插值；含中文的两处单引号字符串内部无引号冲突 ✓。
- 变量名沿用脚本既有习惯：`$ServiceName`、`$InstallDir`、`$DataDir`、`Write-Step`、
  `Get-Service-State`（脚本里没有 `$ExeDir`，故用 `Join-Path $InstallDir 'netguard.exe'`，
  与 `Install-Service`/`Invoke-Setup` 里 `$exe` 的拼法一致）。
- `Remove-Installation` 新顺序：
  1. `Invoke-AsSystem ('& sc.exe stop ...') 'stop'`（本脚本里管理员无服务控制权限，必须经
     SYSTEM 计划任务；`Invoke-AsSystem` 的 `-Tag` 换成 `'stop'` 以免与 `'delete'`/`'purge'`
     的临时文件互相覆盖）；
  2. `for ($i=0; $i -lt 40; $i++) { $svc = Get-Service-State ...; if (-not $svc -or $svc.Status -eq 'Stopped') { break }; Start-Sleep -Milliseconds 500 }`
     —— 每轮重新 `Get-Service` 取新对象，不复用旧 `ServiceController` 的过期 `Status`；
  3. `Invoke-WfpPurge`（服务已停；服务不存在时也会走）；
  4. `if (Get-Service-State $ServiceName) { sc.exe delete ...; 轮询消失 }`；
  5. 原有 `-Purge` 删数据目录、删 `$InstallDir` 保持不动。
- `$ErrorActionPreference = 'Stop'` 不影响原生进程退出码；清理失败只打警告并继续，
  符合「不因 purge 失败而中断卸载」。

## 4. 结论

- `install.ps1 -Uninstall` 现在按「停服务 → 等 STOPPED → `netguard.exe wfp-purge` →
  `sc delete` → 删目录」执行，删掉了服务与二进制后不再残留持久化阻断规则；purge 失败只警告，
  不阻断卸载，但退出码会暴露残留。
- `netguard.exe wfp-purge` 按 provider 逐层枚举（V4/V6，`actionMask = u32::MAX`），收集
  `filter_id` → 释放枚举缓冲 → 逐条删除 → 子层 → Provider；`*_NOT_FOUND` 全当成功，
  `FWP_E_IN_USE` 等非「不存在」错误打印警告并以退出码 1 结束。
- 未触碰 `wfp.rs` / `engine.rs` / `svc.rs` / `http.rs` / `paths.rs` / `etw.rs` / `docs/`，
  未 git add/commit/push，未写 `/tmp`，源码无 `password`/`secret` 字面量。

## 5. 存疑 / 待确认

1. **无法本机验证**：按硬约束未编译。真正的编译校验只有 CI 的 `windows` 作业
   （`cargo build --workspace --release`，windows-latest）。`cargo fmt --check` 与 clippy
   在 CI 里是 `continue-on-error: true`，不阻塞；本文件按 max_width=100 手工排版，
   但个别长调用（如 `FwpmFilterEnum0` 的实参换行）rustfmt 可能会重新排版，属纯格式差异。
2. **对 `wfp.rs` 的耦合**：`cli.rs` 引用 `crate::wfp::{PROVIDER_KEY, SUBLAYER_KEY}`（当前均
   为 `pub const`）。若另一子代理改动这两者的可见性或命名，`cli.rs` 会编译失败——需要同步。
   另：`PurgeEngine` 复制了 `Engine::open()` 的几行（`Engine.handle` 私有、无访问器，
   而本次不允许改 `wfp.rs`），若将来 `wfp.rs` 暴露公开的 purge/句柄接口，可合并。
3. **`-Force` 覆盖安装未加 purge**：`Install-Service` 的 `-Force` 分支仍是
   `sc stop; sc delete` 后直接覆盖安装（不调用 `wfp-purge`）。旧版本残留的过滤器由新
   `wfp.rs::reconcile()` 的去重逻辑自愈（另一子代理的改动），所以不在本次范围；若希望
   重装前也彻底清空，可在该分支同样调 `Invoke-WfpPurge`（用旧 exe，旧 exe 没有该子命令时
   会以非零退出码打一条警告）。本次按规格只改 `-Uninstall`。
4. **服务停不下来时**：`Invoke-WfpPurge` 会跳过并警告，随后仍删除服务与文件，持久化过滤器
   会残留（下次有二进制时再 purge）。这是刻意的降级路径，避免卸载彻底失败。
