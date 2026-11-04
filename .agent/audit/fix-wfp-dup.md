# WFP 过滤器重复累积修复（`crates/win/src/wfp.rs`）

状态：**代码改动完成，静态核对通过，未编译、未上机**（本机禁止编译；仅逐行读码 + 绑定文件核对）。

## 0. 任务规格（原文抄录）

> 你在仓库 /home/SQL916/netguard（Windows 应用级网络拦截）里工作。先读 `/home/SQL916/netguard/AGENTS.md`。
> 本任务报告写 `~/netguard/.agent/audit/fix-wfp-dup.md`（**先**把规格抄进去 + 建 TODO 清单，边做边更新，最后写结论；回信只报路径+状态）。

### 硬约束
1. **绝对不编译**：不跑 `cargo build/check/test/clippy/fmt`，不跑 rustc。只做逐行读码 + 类型/签名核对。
2. **只改一个文件**：`crates/win/src/wfp.rs`。其它文件（含 `engine.rs`、`docs/`、`install.ps1`）一律不碰。
3. 不 git add/commit/push。
4. 不写 `/tmp`，中间产物写 `.agent/audit/`。
5. 源码里禁止出现 `password`/`secret` 紧跟 `=` 或 `:` 再跟字面值。

### 真机现象（已确证，无需再验证）
服务每次启动都记「过滤器已同步：新增 1 条，删除 0 条，保持 0 项」。连续重启后 `netsh wfp show filters`
里有 6 条同名过滤器（`ng4|C:\Windows\System32\curl.exe` ×3、`ng6|...` ×3），
layer=`FWPM_LAYER_ALE_AUTH_CONNECT_V4`、sublayer=`{7b9e5c12-...}`、provider=`{7b9e5c11-...}`（与
PROVIDER_KEY 一致）、action=`FWP_ACTION_BLOCK`、flags=`PERSISTENT|INDEXED`。
名单只有 1 个应用，正确状态应是 2 条（v4+v6）。
结论：`Engine::existing()` 每次返回空集合 → `reconcile()` 认为什么都没有 → 每启动一次再添加一对，无限累积。

### 任务
- **A. 修 `Engine::existing()`（关键）**：重读 `FWPM_FILTER_ENUM_TEMPLATE0` 定义与语义，找出为什么按
  providerKey 枚举拿不到结果并改对。重点检查 `actionMask` / `flags` / `numFilterConditions` /
  `filterCondition` / `reserved` / `calloutKey` 的零值语义与 `FwpmFilterCreateEnumHandle0` 返回值处理。
  允许查 MSDN，权威说明出处写进报告。
- **B. `reconcile()` 增加去重**：同路径同层多余项全部删除并计入 `removed`，每路径每层留 1 条，
  保留规则确定；不在 `wanted` 的照旧删；`kept` = v4+v6 齐全且无多余项。
- **C. 可观测性**：不给 `engine.rs` 加日志，改为 `ReconcileReport` 新增 `observed: usize`，
  并在 `describe(report)` 里带出「原有 N 条」。
- **D. 静态核对清单写进报告**：字段类型/赋值方式、`observed` 对 `Default`/构造点的影响、
  `delete_filter` 幂等性与「枚举缓冲释放后再删」、无借用冲突。

### 回信格式
只报：报告路径、`wfp.rs` 改动行号、A 段找到的真实原因（一句话）、有无存疑。

---

## TODO（全部完成）

- [x] A1 读 `FWPM_FILTER_ENUM_TEMPLATE0` 全部字段定义（windows-sys 0.59）
- [x] A2 查 MSDN `actionMask` 语义与 `FwpmFilterCreateEnumHandle0` 返回值
- [x] A3 确认零值语义：flags / numFilterConditions / filterCondition / providerContextTemplate / calloutKey / enumType
- [x] A4 修 `existing()`（actionMask=u32::MAX + 显式 layerKey + enumType + 错误码不再吞掉）
- [x] B1 `reconcile()` 去重：按 (path, ipv6) 分组，按 `filter_id` 升序保留最小
- [x] B2 枚举缓冲释放后再统一删除（收集 id → 释放 → 删除）
- [x] C1 `ReconcileReport.observed` + `describe()` 带出「原有 N 条」
- [x] C2 核对 `engine.rs` 只调用 `describe(report)`，未新增字段访问 → 无需改 `engine.rs`
- [x] D1 静态核对清单（见 §4）
- [x] E1 结论 + 存疑（见 §5）

---

## 1. 根因（A 段）

### 1.1 结论（一句话）
`FWPM_FILTER_ENUM_TEMPLATE0.actionMask` 被 `zeroed()` 留在 **0**，而 WFP 的语义是「过滤器的动作类型与
actionMask 按位与后**至少有一位非零**才返回」，`0 & 任何动作类型 == 0` → **一条也不会返回**，
`existing()` 永远得到空集合。

### 1.2 权威出处
- MSDN《FWPM_FILTER_ENUM_TEMPLATE0 structure (fwpmtypes.h)》
  https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_enum_template0
  - `actionMask`：*"Only filters whose action type contains at least one of the bits in **actionMask**
    will be returned."* 表里明确：`0xFFFFFFFF` = *"Ignore the filter's action type when enumerating."*
    （同表还说明不能直接拿 `FWP_ACTION_BLOCK` 之类多 bit 常量当掩码。）
  - `numFilterConditions`：*"If zero, then all filters match."* ← 说明「零条件」不是「必须匹配某条件」。
  - `calloutKey`：仅在枚举 callout 类过滤器时使用（配 `FWP_ACTION_FLAG_CALLOUT` 掩码），否则应留 `NULL`。
  - `providerContextTemplate`：非 `NULL` 才按 provider context 收紧 → `NULL` = 不限。
- MSDN《FwpmFilterCreateEnumHandle0 function (fwpmu.h)》
  https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltercreateenumhandle0
  - *"If enumTemplate is NULL, all filters are returned."*；返回 `ERROR_SUCCESS` 或 `FWP_E_*`/`RPC_*`。
- Windows SDK WFP 官方样例（`HelperFunctions_FwpmFilter.cpp`，`HlprFwpmFilterRemoveAll`）用
  `providerKey + layerKey + FWP_FILTER_ENUM_FULLY_CONTAINED + actionMask = 0xFFFFFFFF` 枚举某 provider
  的全部过滤器后逐条删除 —— 与本仓库要做的事完全一致，采用的正是本次改法。
- 同一样例的 `HlprFwpmFilterEnum` 把 `FWP_E_FILTER_NOT_FOUND` / `FWP_E_NOT_FOUND` 视为**正常结束**，
  其它返回值才算错误 → 支持 §3.3 的错误码处理。

### 1.3 为什么「看起来只填 providerKey」会失败
`std::mem::zeroed()` 一次性给出全部零值，其中两个字段是致命的：
1. `actionMask = 0` → 见上，直接 0 命中（**主因**，可独立解释现象）。
2. `layerKey = GUID{0}` → 「零 GUID = 全部层」在文档里**没有**任何说明；旧代码依赖了这个未定义行为。
   即使 actionMask 修好，只要 WFP 把零 GUID 当成「某个不存在的层」，就仍然枚举为空。
   因此本次改成**显式按 `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` 各枚举一次**，不再依赖零 GUID 语义。

其余零值语义核对（都不是阻断项）：
- `flags = 0`：不设 `BOOTTIME_ONLY`（本程序的过滤器不是 boot-time）、不设 `INCLUDE_DISABLED`
  （本程序从不写 disabled 过滤器）→ 默认行为即正确。
- `numFilterConditions = 0` + `filterCondition = NULL`：MSDN 明示「zero → all filters match」。
- `providerContextTemplate = NULL` / `calloutKey = NULL`：不收紧、不按 callout 筛选，正确。
- `enumType = 0 = FWP_FILTER_ENUM_FULLY_CONTAINED`：配合零条件即「该层内全部过滤器」（与官方样例一致）。
- `reserved`：**`FWPM_FILTER_ENUM_TEMPLATE0` 没有这个字段**（`reserved` 只存在于 `FWPM_FILTER0`），
  任务清单里提到的 `reserved` 对本结构不适用。

### 1.4 旧代码的返回值处理为什么把故障藏起来了
```rust
let code = FwpmFilterCreateEnumHandle0(...);
if code == FWP_E_FILTER_NOT_FOUND || code == FWP_E_NEVER_MATCH {
    return Ok(Vec::new());          // ← 模板匹配为空，被当成「正常空集」
}
check(code)?;
...
if code != ERROR_SUCCESS || returned == 0 { ... break; }   // ← 枚举中任何错误也被当成结束
```
`actionMask = 0` 的模板在 WFP 看来就是「永不匹配」，无论它以
(a) `CreateEnumHandle0` 直接返回 `FWP_E_NEVER_MATCH`，还是
(b) `CreateEnumHandle0` 成功、`Enum0` 返回 0 条，旧代码都会静默得出 `Ok(vec![])`。
两条路径结果相同，这也解释了真机上「新增 1 条、保持 0 项」的日志。

---

## 2. 改动清单（只动 `crates/win/src/wfp.rs`）

| 位置（改后行号） | 改动 |
| --- | --- |
| 38–39 | 新增 `const ENUM_BATCH: u32 = 32;`（分页大小，替换散落的字面量 `32`） |
| 92–101 | `ReconcileReport` 新增 `pub observed: usize`（去重前枚举到的条数） |
| 254–276 | `existing()` 重写：按 V4/V6 两层分别调用 `enumerate_layer()` |
| 278–359 | 新增 `unsafe fn enumerate_layer(&self, layer: GUID, ipv6: bool)`：完整填模板（`actionMask = u32::MAX`、显式 `layerKey`、`enumType = FWP_FILTER_ENUM_FULLY_CONTAINED`、零条件、空 calloutKey）、分页取尽、错误不再静默、句柄在两条退出路径上都销毁 |
| 361–427 | `reconcile()` 重写：`observed` 赋值 + 三步（去重保留最小 id / 删非期望路径 / 补齐缺层），删除集中在枚举缓冲释放之后 |
| 446–452 | `describe()` 增加「原有 {} 条」，日志变为「原有 6 条，新增 0 条，删除 4 条，保持 1 项」 |

保留规则（B）：同 `(path, ipv6)` 的候选按 `filter_id` **升序**，`skip(1)` 全删 → 每次启动删除顺序稳定、
结果可复现（`filter_id` 由 WFP 单调分配，最小 = 最早创建的那条）。

`engine.rs` **未改动**（对比 `git diff --stat`：本任务只产生 `crates/win/src/wfp.rs` 的差异；
工作区里 `crates/win/src/cli.rs` 的改动不是本任务产生的，属既有未提交改动，未触碰）。

---

## 3. 静态核对清单（D 段）

### 3.1 `FWPM_FILTER_ENUM_TEMPLATE0` 字段类型与赋值（windows-sys 0.59）
绑定文件：`/opt/winsys/windows-sys-0.59.0/src/Windows/Win32/NetworkManagement/WindowsFilteringPlatform/mod.rs`
行 1406–1416。

| 字段 | 绑定类型 | 本次赋值 | 说明 |
| --- | --- | --- | --- |
| `providerKey` | `*mut GUID` | `&mut provider_key`（`*mut GUID`） | 绑定是 `*mut`（MSDN 写 `GUID*`）；旧代码 `as *mut GUID` 强转等价，此处省掉 |
| `layerKey` | `GUID`（按值） | `layer`（形参 `GUID`） | 不再留零 GUID |
| `enumType` | `FWP_FILTER_ENUM_TYPE`（`= i32`，行 1211） | `FWP_FILTER_ENUM_FULLY_CONTAINED`（`0i32`，行 902） | 类型一致，无隐式转换 |
| `flags` | `u32` | `0` | 默认行为 |
| `providerContextTemplate` | `*mut FWPM_PROVIDER_CONTEXT_ENUM_TEMPLATE0` | 保持 `zeroed()` 的 null | 不限 provider context |
| `numFilterConditions` | `u32` | `0` | MSDN：zero → all match |
| `filterCondition` | `*mut FWPM_FILTER_CONDITION0` | `ptr::null_mut()` | 与上一条一致 |
| `actionMask` | `u32` | `u32::MAX` | 关键修复；`u32::MAX` = 0xFFFFFFFF，MSDN 明示「忽略动作类型」 |
| `calloutKey` | `*mut GUID` | `ptr::null_mut()` | 非 callout 枚举时必须为空 |

动作常量核对（同文件行 800–810、1205）：`FWP_ACTION_TYPE = u32`；`FWP_ACTION_BLOCK = 4097 (0x1001)`、
`FWP_ACTION_PERMIT = 4098 (0x1002)`、`FWP_ACTION_FLAG_TERMINATING = 4096 (0x1000)`、
`FWP_ACTION_FLAG_NON_TERMINATING = 8192 (0x2000)`、`FWP_ACTION_FLAG_CALLOUT = 16384 (0x4000)`。
→ 任务提示的 `TERMINATING | NON_TERMINATING = 0x3000` 也能覆盖 block/permit/两个 callout 变体；
本次选 `u32::MAX`，因为它是 MSDN 明写的「忽略动作类型」，且不会随 WFP 新增动作位而失效。

错误码核对（`Win32/Foundation/mod.rs`）：`FWP_E_FILTER_NOT_FOUND = 0x80320003`（行 4974）、
`FWP_E_NEVER_MATCH = 0x80320033`（行 5004）、`FWP_E_ALREADY_EXISTS = 0x80320009`（行 4960）
—— 与源码里现有的三个 `const` 数值一致（0x80320013 那个历史错误值没有残留）。

API 签名核对（同文件行 43–62）：
`FwpmFilterCreateEnumHandle0(HANDLE, *const FWPM_FILTER_ENUM_TEMPLATE0, *mut HANDLE) -> u32`；
`FwpmFilterEnum0(HANDLE, HANDLE, u32, *mut *mut *mut FWPM_FILTER0, *mut u32) -> u32`；
`FwpmFreeMemory0(*mut *mut c_void)`；`FwpmFilterDestroyEnumHandle0(HANDLE, HANDLE) -> u32`。
代码里的 `&mut entries as *mut _ as *mut *mut c_void` 与 `&mut entries`（`*mut *mut FWPM_FILTER0` →
`*mut *mut *mut FWPM_FILTER0`）与绑定一致（沿用改动前的写法，未变）。

### 3.2 `observed` 字段对构造点的影响
- `ReconcileReport` 仍是 `#[derive(Debug, Default, Clone, Copy)]`；`usize: Default` → 派生 `Default`
  依旧成立，`Copy` 不受影响（`usize` 是 `Copy`）。
- 全仓库构造点只有 `reconcile()` 一处：`ReconcileReport { observed, ..ReconcileReport::default() }`
  （函数式更新语法，新增字段无编译影响）。已用 `grep -rn "ReconcileReport" crates/win/src` 核对，
  该类型在 `wfp.rs` 之外零引用（`engine.rs` 只有 `wfp::describe(report)`）。
- `describe(report: ReconcileReport)` 按值接收 `Copy` 结构，新增字段只影响格式化字符串。

### 3.3 `delete_filter` 幂等性
`FwpmFilterDeleteById0` 返回 `ERROR_SUCCESS`、`FWP_E_FILTER_NOT_FOUND (0x80320003)` 或 Win32
`ERROR_NOT_FOUND (1168)` 时均返回 `Ok(())` → 重复删除/已被别人删掉都视为成功。
本次改动的新用法（对同一 `(path, ipv6)` 的多条 id 顺序删除）因此不会因为中途某条消失而整体失败。

### 3.4 「枚举缓冲释放后再删」
`FwpmFilterEnum0` 返回的 `entries` 数组与其中的 `FWPM_FILTER0*` 都由 WFP 分配，需 `FwpmFreeMemory0`
释放。`existing()`/`enumerate_layer()` 内部按 `returned` 读完后立即 `FwpmFreeMemory0`，
**只把 `filter_id`（`u64` 值拷贝）与解析出的 `path` 字符串留在 `Vec<Existing>` 里**；
`reconcile()` 拿到的是 `existing()` 返回的拥有所有权的 `Vec<Existing>`，
所有删除都发生在枚举函数返回、缓冲已释放之后。不存在「缓冲还活着时删除 → 读到已释放内存」的路径。

### 3.5 借用/所有权
- `existing` 是 `Vec<Existing>`（拥有所有权），删除阶段只用 `&existing` 读取 `path/ipv6`
  并把 `filter_id` 拷进 `stale: Vec<u64>`，随后 `self.delete_filter(*id)` 只借用 `&self`。
  `Engine::delete_filter(&self, ...)` 不碰 `existing`/`stale`，无 `&mut`/`&` 冲突。
- `stale` 先 `sort_unstable()` + `dedup()`：既让删除顺序可复现，也保证同一 id 不会被删两次、
  `removed` 不会被重复计数。
- 补齐阶段用 `stale.contains(&item.filter_id)` 排除刚删掉的项 → 不会因为「第 2 条还在枚举快照里」
  而误判 `has_v4/has_v6`。
- `Vec<u64>::contains` 为 O(n)，n = 本公司过滤器条数（个位数），无性能顾虑。

### 3.6 其它静态检查
- `for (layer, ipv6) in [(GUID, bool); 2]` / `for ipv6 in [false, true]`：`GUID: Copy`、`bool: Copy`，
  edition 2021（workspace `Cargo.toml`）= 数组按值迭代，合法。
- `unsafe { self.enumerate_layer(layer, ipv6)? }`：`?` 在 `unsafe` 块内合法（块为表达式，直接 `return` 出函数）；
  `enumerate_layer` 是 `unsafe fn`，调用点在 `unsafe` 块内。
- 句柄生命周期：`enumerate_layer` 两条出口（错误收集后统一返回 / 正常结束）都会执行
  `FwpmFilterDestroyEnumHandle0`；`check(code)?` 的早退发生在句柄创建成功之前，无泄漏。
- `cd_void`（`std::ffi::c_void`）、`GUID`、`ptr` 三个导入仍在使用，无未用导入。
- 异常早退时 `entries` 可能为 null → 所有 `FwpmFreeMemory0` 调用点都有 `is_null` 保护。
- 全文不再有裸字面量 `32`（只剩 `ENUM_BATCH` 常量），代码风格与既有文件一致（中文注释、`io::Result`）。

---

## 4. 修复后的预期行为（真机待验）

名单 1 个应用、机器上残留 6 条（`ng4|` ×3、`ng6|` ×3）：
- 第 1 次启动：`observed = 6` → 每个 `(path, ipv6)` 保留 `filter_id` 最小的一条、删掉其余 4 条
  → 日志「过滤器已同步：原有 6 条，新增 0 条，删除 4 条，保持 1 项」。
- 第 2、3… 次启动：`observed = 2` → 「原有 2 条，新增 0 条，删除 0 条，保持 1 项」，不再累积。
- 名单变化时：新路径 `added += 1`（补一对或只补缺的一层）；移除的路径整组删除并按条数计入 `removed`。

验收命令（上机时用，本任务不执行）：
```
netsh wfp show filters file=- | findstr /i "ng4| ng6|"     # 应为 2 条
```

---

## 5. 存疑 / 未验证

1. **未编译、未上机**（硬约束 1）。所有结论来自逐行读码 + `/opt/winsys` 绑定文件 + MSDN 文档。
   真正的编译门禁是 CI 的 `cargo build --workspace --release`（windows-latest）；
   `cargo fmt --check` 与 `cargo clippy` 在 `ci.yml` 里是 `continue-on-error: true`，不会卡流水线。
2. **`actionMask = 0` 时 WFP 的具体返回码无法离线确定**：可能是 `CreateEnumHandle0` 返回
   `FWP_E_NEVER_MATCH`，也可能是句柄创建成功但 `Enum0` 返回 0 条/`FWP_E_FILTER_NOT_FOUND`。
   两种都已被旧代码静默吞成空集，修复后也已不再触碰这条路径，故对本修复无影响；仅作记录。
3. **零 `layerKey` 的真实语义未见于官方文档**。本次不依赖它（显式逐层枚举）；若将来需要枚举
   其它层（例如 `ALE_AUTH_RECV_ACCEPT`），必须把层加进 `existing()` 的数组，否则那些层上的
   历史过滤器既不会被枚举也不会被清理（当前版本只在这两层上建过滤器，无此风险）。
4. **不认识显示名前缀的过滤器会被忽略**：`existing()` 只收 `ng4|`/`ng6|` 前缀项。已用
   `git log -S'ng4|'` 确认该命名自 wfp.rs 首次提交（a6b97f5）起未变，不存在历史命名方案，
   因此不构成残留来源；若将来引入其它命名，需要同步放宽这里。
5. `ensure_provider_sublayer()` 每次 reconcile 都会先尝试删除 Provider/子层（失败被忽略）。
   过滤器仍引用时 `FwpmProviderDeleteByKey0` 正常应返回 `FWP_E_IN_USE`，与本次缺陷无关，
   按硬约束未改动该逻辑。

---

## 6. 续做核对（上次会话因余额中断后）

- 上次的编辑已全部落盘，本次 `git status` / `git diff crates/win/src/wfp.rs` 逐段复核后**直接复用**，
  未重写、未回退任何一行。
- 关键锚点均在位：`ENUM_BATCH`（行 39）、`ReconcileReport.observed`（行 100）、
  `existing()`/`enumerate_layer()`（行 254–359）、`reconcile()` 三步去重（行 361–427）、
  `describe()` 带「原有 N 条」（行 446–452）。
- 本次额外做的只读核对：`actionMask = u32::MAX` 与显式 `layerKey` 均在位；
  `stale` 的 `sort_unstable() + dedup()` 在位；删除全部发生在枚举函数返回之后；
  `describe()` 字段顺序 `observed, added, removed, kept` 与结构体字段一致；
  `wfp.rs` 内无 `password`/`secret` 字面值（`grep -Ei` 零命中）。
- 未触碰其它文件：`crates/win/src/cli.rs` 与 `install.ps1` 的改动来自其它会话，与本任务无关，
  本任务 `git diff --stat` 中属于 `wfp.rs` 的只有本报告 §2 列出的那几处。
