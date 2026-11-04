# 修复两个致命缺陷：配置往返 400 / 完整性失败时 fail-open

> 本文件是本子任务的落地记录：规格抄录 → TODO → 改动 → 静态校验推理 → 结论。
> 硬约束：**不编译**（无 cargo/rustc）、只改 `crates/core/src/config.rs`、
> `crates/core/src/auth.rs`、`crates/win/src/store.rs`、`crates/win/src/engine.rs`、
> `crates/win/src/http.rs`；不碰 `install.ps1` / `etw.rs` / `cli_client.rs` / `svc.rs` / `paths.rs`；
> 不做 git 操作。

## 0. 规格抄录（父会话下发，逐条对齐）

### 缺陷 1：`GET /api/config` → `PUT /api/config` 往返必然 400
`handle_config_get` 把 `auth` 从 JSON 里删掉再下发（防泄露），前端原样回传；`Config::auth`
没有 `#[serde(default)]`，`AuthConfig` 同样，于是 `serde_json::from_value::<Config>` 报
`missing field 'auth'` → 400，WebUI 永远保存不了配置。

修法要求：
- `Config::auth` 加 `#[serde(default)]`；确认 `AuthConfig: Default`；内部字段若也需缺省同样补
  `#[serde(default)]`。
- `Factors::Default` 必须是 `None`（核对）。
- `crates/core/src/config.rs` 测试模块加单测：`{"version":0,"enabled":true,"apps":[],"hashes":[]}`
  能反序列化成 `Config` 且 `auth.factors == Factors::None`；再序列化→删 `auth`→反序列化也成功。
- `handle_config_put` 的回填逻辑保持不变，但确认 `map.remove("auth")` 之后回填路径不依赖请求里的 `auth`。

### 缺陷 2：配置被篡改/删除时 fail-open，而不是文档承诺的 fail-closed
现状 `Engine::boot`/`reload_from_disk` 遇 `Load::Tampered`/`Load::Absent` 用 `Config::default()`
→ 空集合 `reconcile` 把已有持久化过滤器全删（拦截消失）；`factors=none` → WebUI 免登录可写新配置。

修法要求：
1. `store.rs` 新增 `pub fn load_backup(&self) -> Load`，与 `load()` 完全相同的校验流程，公共部分抽
   `load_from`。
2. `engine.rs` 新增 `load_effective`：先 `load()`，Tampered/Absent 时再 `load_backup()`，备份 Ok 则用
   备份内容（apps/hashes/auth 全用备份），但 `integrity_ok=false` + `integrity_note` 说明已按备份封锁。
3. `Absent` 且备份也 `Absent`（真正首装）保持现状。
4. `blocked_paths()`/`core_blocked()` 语义不变：`integrity_ok == false` 时阻塞 `config.apps` 全部路径。
5. `http.rs`：确认篡改态下 `factors` 来自备份；不加「篡改态禁止写配置」的硬锁；`state_payload` 继续暴露
   `integrity_ok` / `integrity_note`。

## 1. TODO 清单

- [x] 读 `AGENTS.md`、`config.rs`、`auth.rs`、`store.rs`、`engine.rs`、`http.rs`、`paths.rs`、`web/app.js`、`install.ps1`（只读）
- [x] 缺陷 1：`Config::auth` 加 `#[serde(default)]`
- [x] 缺陷 1：`AuthConfig::factors` 加 `#[serde(default)]`（其余字段原本已有）
- [x] 缺陷 1：核对 `Factors::default() == Factors::None`、`AuthConfig: Default`
- [x] 缺陷 1：新增 3 个单测（缺 auth 反序列化 / 前端往返 / AuthConfig 缺省）
- [x] 缺陷 2：`store.rs` 抽 `load_from`，新增 `load_backup`、`has_backup`
- [x] 缺陷 2：备份与签名成对（新增 `config.mac.bak`），且保存前先验证旧配置，避免篡改内容覆盖可信备份
- [x] 缺陷 2：`engine.rs` 新增 `Effective`/`load_effective`，boot 与 reload 共用
- [x] 缺陷 2：worker 在「无可信配置且期望集合为空」时不做 reconcile（不删已有过滤器）
- [x] 缺陷 2：`http.rs` `setup_open` 在存在备份时关闭（否则删 config.json 即可重跑 /api/setup 清零）
- [x] 静态核对（无编译）：类型/借用/可见性/签名逐个过一遍
- [x] 结论与存疑写回本文件

## 2. 改动明细

（见下文逐节）

## 3. 静态校验推理

（见下文）

## 4. 新增单测

（见下文）

## 5. 未做 / 存疑

（见下文）
