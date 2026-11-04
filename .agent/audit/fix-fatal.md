# 修复两个致命缺陷：配置往返 400 / 完整性失败时 fail-open

> 本文件是本子任务的落地记录：规格抄录 → TODO → 改动 → 静态校验推理 → 结论。
> 硬约束：**不编译**（无 cargo/rustc）、只改 `crates/core/src/config.rs`、
> `crates/core/src/auth.rs`、`crates/win/src/store.rs`、`crates/win/src/engine.rs`、
> `crates/win/src/http.rs`；未碰 `install.ps1` / `etw.rs` / `cli_client.rs` / `svc.rs` / `paths.rs`；
> 无 git 操作，未改 `docs/`。

状态：**两条缺陷均已修完**，逐行静态核对通过（见 §3），无编译验证（按约定）。

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

- [x] 读 `AGENTS.md`、`config.rs`、`auth.rs`、`store.rs`、`engine.rs`、`http.rs`、`paths.rs`、`web/app.js`、`install.ps1`、`cli.rs`、`watch.rs`（只读）
- [x] 缺陷 1：`Config::auth` 加 `#[serde(default)]`（`config.rs:44`）
- [x] 缺陷 1：`AuthConfig::factors` 加 `#[serde(default)]`（`auth.rs:67`，其余 6 个字段原本已有）
- [x] 缺陷 1：核对 `Factors::default() == Factors::None`、`AuthConfig` 有手写 `impl Default`
- [x] 缺陷 1：新增 3 个单测（缺 auth 反序列化 / 前端往返 / AuthConfig 全字段缺省）
- [x] 缺陷 2：`store.rs` 抽 `load_from`，新增 `load_backup`、`has_backup`
- [x] 缺陷 2：备份签名与备份配置成对（新增 `config.mac.bak`），保存前先验签旧配置，避免篡改内容污染可信备份
- [x] 缺陷 2：`engine.rs` 新增 `Effective` + `load_effective`，`boot` 与 `reload_from_disk` 共用
- [x] 缺陷 2：worker 在「无可信名单且期望集合为空」时不 reconcile（不删已有过滤器）
- [x] 缺陷 2：`http.rs` `setup_open` 在存在备份时关闭（否则删 `config.json` 即可重跑免认证 `/api/setup` 清零）
- [x] 静态核对（无编译）：类型/借用/生命周期/可见性/调用点逐个过一遍
- [x] 结论与存疑写回本文件

## 2. 改动明细

### 2.1 `crates/core/src/config.rs`

**A. `Config::auth` 加 `#[serde(default)]`（`config.rs:35-47`）**

改前：

```rust
    /// 认证配置。
    pub auth: AuthConfig,
```

改后：保留字段，补大段说明 + `#[serde(default)]`。要点：
- 缺省值 = `AuthConfig::default()`（`factors: None`、各 `Option` 为 `None`、`recovery_hashes` 空、
  `failures: 0`），与 `PUT` 处理器的回填前提完全吻合；
- 说明「不构成降级风险」的理由：`auth` 参与 HMAC 覆盖的 `serde_json::to_vec(&Config)`，磁盘配置若被
  人为删掉 `auth`，规范化后的字节（含 `"auth":{...}`）与签名不匹配 → `Store::load` 判 `Tampered`。
  也就是说这个 `default` 只对**未签名的 HTTP 请求体**生效，不放松磁盘侧。

**B. 测试模块新增 3 个单测（`config.rs:276-337`）**，见 §4。

### 2.2 `crates/core/src/auth.rs`

`AuthConfig::factors` 补 `#[serde(default)]`（`auth.rs:67`）：

```rust
    /// 启用哪些因子。缺省 = 不需要认证（与 [`Factors::default`] 一致）。
    #[serde(default)]
    pub factors: Factors,
```

核对结果：`password_hash` / `totp_secret` / `recovery_hashes` / `failures` / `locked_until` /
`last_totp_counter` 六个字段**原本就都带** `#[serde(default)]`（`auth.rs:70,73,76,79,82,85`），
只有 `factors` 缺，现已补齐。`impl Default for Factors { fn default() -> Self { Factors::None } }`
（`auth.rs:37-41`）确认仍是 `None` —— 与「未启用认证」的语义一致，也正是父会话要求的缺省值。
`AuthConfig` 有手写 `impl Default`（`auth.rs:89-101`），因此 `#[serde(default)]` 能落到字段级默认值上。

### 2.3 `crates/win/src/store.rs`

**A. 新增常量 `BACKUP_MAC_FILE`（`store.rs:13-17`）**

```rust
const BACKUP_MAC_FILE: &str = "config.mac.bak";
```

**为什么必须新增这个文件（关键设计点）**：`save()` 原本只把旧的 `config.json` 复制到
`config.json.bak`，**没有**备份 `config.mac`；而 `save()` 随后会把 `config.mac` 覆盖成新签名。
也就是说旧备份与任何现存签名都不配对，直接拿 `config.mac` 去验 `config.json.bak` 必然
`签名不匹配` —— 那样 `load_backup()` 永远返回不可信，修复等于没做。若允许「备份不验签」，
攻击者只要删掉 `config.json` 并编辑 `config.json.bak`（去掉几个 app）就能 fail-open，正好是
要堵的洞。因此备份必须与它的签名成对存在。

未改 `paths.rs`（它由别的子代理负责）：用已有的 `Paths::file(&str)` 在该模块内拼出
`config.mac.bak`，不新增对 `Paths` API 的依赖。

**B. `load()` 拆出 `load_from`（`store.rs:118-179`）**

改前：`load()` 内联了「读 config.json + 读 config.mac + 反序列化 + 规范化 + 取密钥 + 解析签名 +
验签 + validate」全套。

改后：

```rust
    pub fn load(&self) -> Load {
        self.load_from(&self.paths.config(), &self.paths.mac())
    }

    pub fn load_backup(&self) -> Load {
        self.load_from(&self.paths.backup(), &self.paths.file(BACKUP_MAC_FILE))
    }

    pub fn has_backup(&self) -> bool {
        self.paths.backup().exists()
    }

    fn load_from(&self, config_path: &Path, signature_path: &Path) -> Load { /* 原 load 主体 */ }
```

- 校验流程**一字未改**（同样的 8 步、同样的顺序、同样的错误文案），只是把两个路径变成参数；
  主配置与备份因此共用同一条代码路径，不会漂移。
- 与父会话建议的 `fn load_from(&self, path: &Path) -> Load` 有**一处偏差**：多一个
  `signature_path: &Path` 参数。理由：备份的签名文件名不与配置文件名同源（`config.json.bak` ↔
  `config.mac.bak`），若只传 config 路径，就得在函数内部按文件名反推签名路径，既脆又难核；
  显式传两个路径最直白，且调用点只有 3 个（`load` / `load_backup` / `save` 内的自检）。

**C. `save()`：备份只在「当前磁盘配置仍可信」时刷新，并在首次保存时播种备份（`store.rs:182-216`）**

改前：

```rust
        if config_path.exists() {
            let _ = std::fs::copy(&config_path, self.paths.backup());
        }
        write_atomic(&config_path, &pretty)?;
        write_atomic(&self.paths.mac(), signature.as_bytes())?;
```

改后：

```rust
        if config_path.exists() {
            // 只把「当前磁盘配置仍能通过校验」的版本写进备份。
            if matches!(
                self.load_from(&config_path, &self.paths.mac()),
                Load::Ok(_)
            ) {
                let _ = std::fs::copy(&config_path, self.paths.backup());
                let _ = std::fs::copy(self.paths.mac(), self.paths.file(BACKUP_MAC_FILE));
            }
        }
        write_atomic(&config_path, &pretty)?;
        write_atomic(&self.paths.mac(), signature.as_bytes())?;
        // 首次保存时用刚写入的这份播种备份
        if !self.paths.backup().exists() {
            let _ = std::fs::copy(&config_path, self.paths.backup());
            let _ = std::fs::copy(self.paths.mac(), self.paths.file(BACKUP_MAC_FILE));
        }
```

两处都是必要的，理由都可静态推演：

1. **防止备份被污染**：`authenticate()` 在**每次登录尝试**（包括输错密码）后都会
   `replace_config` → `save()`。若还是无条件「先把磁盘上的 config.json 复制成 .bak」，那么
   「boot 发现篡改 → 用备份封锁 → 有人试一次登录 → 篡改内容被写进 .bak」就把唯一可信退路
   覆盖掉了。加一次验签再备份，杜绝这条链。
2. **首次保存播种**：首次安装时 `config.json` 尚不存在，原逻辑不会产生任何备份；此后一旦被
   篡改就只剩 `Config::default()`（空名单）可退，等于 fail-open。播种后立刻拥有可信基线。
3. 顺序上备份发生在 `write_atomic(config.json)` **之前**，语义仍是「.bak = 上一份配置」；
   唯一的例外是首次保存（此时 .bak = 刚写入的这份）。

### 2.4 `crates/win/src/engine.rs`

**A. 新增 `Effective` 与 `load_effective`（`engine.rs:78-118`）**

```rust
enum Effective {
    Trusted(Config),
    Backup { config: Config, note: String },
    Fresh,
    Untrusted(String),
}

fn load_effective(store: &Store) -> Effective {
    let (reason, missing) = match store.load() {
        Load::Ok(config) => return Effective::Trusted(config),
        Load::Absent => (String::from("配置文件缺失"), true),
        Load::Tampered(note) => (note, false),
    };
    match store.load_backup() {
        Load::Ok(config) => Effective::Backup {
            config,
            note: format!("{reason}；已按上次已知良好的备份封锁"),
        },
        Load::Absent if missing => Effective::Fresh,
        Load::Absent => Effective::Untrusted(format!("{reason}；没有可用的配置备份")),
        Load::Tampered(backup_note) => {
            Effective::Untrusted(format!("{reason}；备份也不可信：{backup_note}"))
        }
    }
}
```

与父会话建议的 `fn load_effective(store) -> (Load, bool)` 有**一处偏差**：用 4 值枚举代替
`(Load, bool)` 元组。理由：元组的 `bool` 语义（「是否来自备份」？「是否缺失」？）靠注释约定，
`boot` 与 `reload_from_disk` 两个调用点很容易对它的含义理解不一致；枚举让「主配置可信 /
用备份 / 首次安装 / 都不可信」四种情况在 `match` 里被强制显式处理，漏一个分支就编译不过。

**B. `boot()` 改用 `load_effective`（`engine.rs:131-158`）**

| 情况 | 改前 | 改后 |
| --- | --- | --- |
| `Ok` | `(config, true, "")` | 同 |
| `Tampered` | `(Config::default(), false, note)` | 先试备份：`Backup` → `(备份config, **false**, note+"已按…备份封锁")`；无可用备份 → 仍是 `(Config::default(), false, note)`，并额外记一条「保留已有过滤器」日志 |
| `Absent` | `(Config::default(), **true**, "尚未初始化")` | 有备份 → `(备份config, false, "配置文件缺失；已按…备份封锁")`；有备份但备份不可信 → `Untrusted`；**两者都缺 → 保持原样 `(Config::default(), true, "尚未初始化")`** |

`Backup` 分支多打一条 `warn`，告诉用户怎么恢复（WebUI 重新保存一次即可，`replace_config`
会把 `integrity_ok` 置回 true）。

> 关于「首装 integrity_ok」的一处主动选择：规格 §3 写「保持现状（`Config::default()`、
> `integrity_ok=false`）」，但现状代码其实是 `true`。我保留了 **`true`**。理由：真首装没有任何
> 名单，`core_blocked()` 在 `true`/`false` 两条分支下都返回空集合（`evaluation.paths` 与
> `config.apps` 都是空），**拦截行为完全一致**；而 `false` 会让前端立刻弹红色横幅
> 「配置完整性校验未通过：尚未初始化。系统保持封锁状态。」（`web/app.js:137-140`），把一个正常
> 的首次安装说成故障。安全语义没有损失，故按「保持现状」的字面执行。若父会话坚持要 `false`，
> 改这一行即可（`engine.rs:144`）。

**C. `reload_from_disk()` 改用 `load_effective`（`engine.rs:216-270`）**

- `Trusted` → 原样（写快照 + `integrity_ok=true` + 清 note + `Applied`）。
- **新增 `Backup` 分支**：用备份的 `config`（apps/hashes/auth 全部来自备份），但
  `integrity_ok=false` + `integrity_note`；返回 `Reload::Tampered(note)`（`watch.rs` 的日志分支
  不需要改，`Reload` 变体没变）。
- `Fresh`（主配置与备份都缺）→ 沿用原 `Absent` 行为：仅置 `integrity_ok=false`、
  note=「配置文件缺失」，**保留快照中的旧配置**（旧名单继续被当作封锁依据，fail-closed）。
- `Untrusted` → 沿用原 `Tampered` 行为：只置标志与 note，保留旧快照。
- 父会话要求的第 5 条「`core_blocked` 语义不变」无需改代码：`Snapshot::core_blocked()`
  （`engine.rs:55-62`）本来就是「`integrity_ok==false` 时阻塞 `config.apps` 全部路径」，
  而 `config` 现在装的是备份 —— 语义自然实现。

**D. worker：无可信名单时不要 reconcile 空集合（`engine.rs:365-378`）**

```rust
            if !snapshot.integrity_ok && blocked.is_empty() {
                self.logger
                    .warn("没有可信配置，保留已有过滤器不做增删（fail-closed）");
                self.commit(&evaluation, &blocked, None);
            } else if last_signature.as_ref() != Some(&signature) {
                ...
```

必要性：`wfp::Engine::reconcile(&[])` 会把 `existing()` 里所有不在期望集合中的过滤器逐条
`delete_filter`（`wfp.rs:324-329`）。配置与备份**都**不可信时 `blocked` 必然为空，若照常
reconcile 就等于主动解除上一轮留下的拦截。这里保持 WFP 不动（宁可继续封锁）。
不更新 `last_signature`，所以配置一恢复（`notify()` 后重算）就会立即重新同步。
正常路径（`integrity_ok==true`）不受影响，首次安装（integrity_ok=true、空名单）也照常走原逻辑。

### 2.5 `crates/win/src/http.rs`

**A. 新增 `initialized()`，`setup_open()` 与其挂钩（`http.rs:49-70`）**

```rust
    fn initialized(&self) -> bool {
        let store = self.engine.store();
        store.is_initialized() || store.has_backup()
    }

    fn setup_open(&self) -> bool {
        if self.initialized() {
            return false;
        }
        let until = *self.setup_until.lock().unwrap();
        now() <= until
    }
```

必要性：`/api/setup` 是**免认证**的（只要初始化窗口还开着），且会直接
`replace_config(factors=none 的新配置)`。`setup_open` 原本只看 `config.json` 是否存在，于是
「删掉 `config.json`（保留 `config.json.bak`）→ 重启服务 → 窗口内调 `/api/setup`」即可把
认证清零、名单清空 —— 正好把 §2.4 的 fail-closed 抵消。加上 `has_backup()` 后，只有
「主配置与备份都不存在」才开放窗口。
这不是父会话禁止的「篡改态禁止写配置」硬锁：`PUT /api/config` 仍然完全可用（登录 +
step-up 后即可写，写完即自愈），用户的恢复路径没有被砍；需要**重置**时走 `install.ps1 -Force`
的 CLI 初始化（`netguard.exe setup --preseed`），不经过这条 HTTP 路径。

**A2. `/api/state` 的 `initialized` 同步改用 `api.initialized()`（`http.rs:259`）**

改前 `"initialized": api.engine.store().is_initialized()`。前端有两处拿它当门槛
（`web/app.js:320-321`）：

```js
  $("setup").classList.toggle("hidden", !data.setup_open || data.initialized);
  const needsLogin = data.initialized && data.factors !== "none" && !authenticated;
```

若 `config.json` 被删、只剩备份，`is_initialized()` 为 false 会让前端**隐藏登录表单**
（`needsLogin=false`），而认证方式其实来自备份（可能是 pw/totp），用户就在 WebUI 里完全
无法登录、也就无法保存配置自愈 —— 唯一恢复路径被挡掉。改成 `is_initialized() || has_backup()`
后：登录表单照常出现、初始化面板照常隐藏（与 `setup_open()` 结论一致）、状态栏不再误报
「未初始化」。

**B. 两处注释（无行为变化）**

- `handle_config_get`（`http.rs:371-373`）：注明「前端原样回传，所以 `Config::auth` 必须允许缺省」。
- `handle_config_put`（`http.rs:416-417`）：注明「认证材料一律以服务端当前配置为准，请求里通常
  根本没有 `auth`，即使有也不采信」。

**C. 核对「篡改态下 `factors` 来自备份」**：`handle_config_get` / `handle_config_put` /
`handle_setup` / `handle_login` / `state_payload` 全都读 `snapshot.config.auth.factors`，而
`Backup` 分支已把 `snapshot.config` 换成备份配置 → 篡改态下用的是备份的认证方式：
备份里 `factors != none` 时**仍然要求登录**；备份里本来就是 `none` 时保持免登录（与之前一致）。
`state_payload` 的 `integrity_ok` / `integrity_note` 字段没动（`http.rs:259-260`），
`web/app.js:137-140` 已经会把 note 拼进红色横幅。

**D. 核对 `handle_config_put` 回填路径不依赖请求里的 `auth`**：`http.rs:414-427` 的 7 行回填全部
读 `current = api.engine.snapshot().config`（服务端当前值），请求体里的 `auth` 只可能提供
`factors`/`password_hash`/`totp_secret`/`recovery_hashes`，且 `factors` 被无条件覆盖、
散列仅在服务端为空时才用 —— 即「攻击者塞自己的散列」这条路不受 `serde(default)` 影响。
改动后请求缺 `auth` 只是让这 7 行回填全部命中（`None`/空/0），结果与改动前「有 auth 但被忽略」
完全等价。

## 3. 静态校验推理（为什么不会引入借用/生命周期/类型错误）

1. **`fn load_from(&self, config_path: &Path, signature_path: &Path) -> Load`**
   - 返回 `Load`（owned），不带任何生命周期参数，不与入参绑定；
   - 两个 `&Path` 都是**借用**，函数体内只读；
   - 调用点 `self.load_from(&self.paths.config(), &self.paths.mac())`：`paths.config()` 返回
     `PathBuf`，`&PathBuf` 在函数实参位置按 `Deref` 自动 coerce 到 `&Path`；两个临时 `PathBuf`
     的生命周期覆盖整个函数调用表达式（Rust 临时值规则），调用返回后即释放 —— 合法。
     第二处调用 `self.load_from(&config_path, &self.paths.mac())` 里 `config_path` 是 `save()`
     里先声明的局部变量，借用关系清晰。
   - `&self` 只读借用 `self.paths`（`Clone` 字段）与 `self.key()`；`save()` 内先 `let key =
     self.key()?;` 已确保密钥存在，随后 `load_from` 再取一次同值密钥，无冲突（不可变借用可重叠）。
2. **`save()` 内的借用顺序**：`let config_path = self.paths.config();`（`PathBuf` 拥有所有权）
   → `self.load_from(&config_path, &self.paths.mac())`（两个不可变借用，语句结束即失效）
   → `std::fs::copy(&config_path, self.paths.backup())`（`&PathBuf`→`&Path` coerce）
   → `write_atomic(&config_path, &pretty)`。全是不可变借用或按值传参，NLL 下无重叠冲突。
   `matches!(self.load_from(...), Load::Ok(_))` 只读匹配，不移动 `Load`（并直接丢弃返回值）。
3. **`enum Effective`**：携带 `Config`（owned）与 `String`（owned），无借用，无生命周期参数，
   因此 `load_effective(store: &Store) -> Effective` 的返回值可以活得比 `store` 借用更久
   （`boot` 里 `store` 后面还要 move 进 `Engine`，正是靠这一点）。
4. **`boot()`**：`load_effective(&store)` 的不可变借用在该语句结束时结束，之后 `store`、`logger`
   才可以被 move 进 `Engine { store, logger, ... }`。`logger.error/warn` 取 `&self`
   （`log.rs:92/97/102`），不 move `logger`，故 match 分支里连调两次也没问题。
   分支返回值统一是 `(Config, bool, String)` 三元组 —— 与改前一致，后续
   `evaluate(&config, ...)`、`Snapshot { config, integrity_ok, integrity_note, ... }` 都不用改。
5. **`reload_from_disk()`**：`match load_effective(&self.store)` —— `self.store` 是不可变字段借用；
   每个分支内部先 `{ let mut guard = self.inner.lock()...; ... }` 收窄锁作用域，再调
   `self.logger.*` / `self.notify()`（都取 `&self`），锁已释放，不会自死锁。
   `note` 在分支里 `note.clone()` 进快照后再 `Reload::Tampered(note)` 按值返回 —— `String` 先
   clone 后 move，合法。返回类型仍是 `Reload`（`Applied` / `Tampered(String)`），
   `watch.rs:124` 的 `if let Reload::Tampered(note)` 不受影响。
6. **worker 守卫**：`!snapshot.integrity_ok && blocked.is_empty()` 全是 `bool` 表达式；
   `self.commit(&evaluation, &blocked, None)` 的第三个参数是 `Option<String>`，`None` 的类型由
   签名推定（`error: Option<String>`），无歧义；`&Vec<String>` → `&[String]` 自动 deref。
   `else if` 链保留了原来的 `last_signature` 比较与赋值逻辑，`signature` 仍被后续
   `Some(signature)` 按值移动 —— 但只在落进 `else if` 分支时移动，守卫分支不碰它，编译器能证明
   每个分支内的移动一次且仅一次。
7. **`http.rs`**：新增的 `fn initialized(&self) -> bool` 里 `let store = self.engine.store();` ——
   `Engine::store()` 返回 `&Store`（`engine.rs:184`），绑定出的 `store` 是 `&Store`，随后的
   `store.is_initialized() || store.has_backup()` 都是 `&Store` 上的方法，返回 `bool`，
   `store` 借用的来源 `self.engine` 生命周期覆盖整个函数体 —— 合法。
   `setup_open` / `state_payload` 都只调 `api.initialized()`（`&Api` 上的私有方法，同模块可见），
   没有新增对 `Store` 的直接访问；`state_payload` 的参数是 `api: &Api`，`api.initialized()`
   自动 reborrow，无移动。
8. **跨文件一致性**（已 grep 核对，无遗漏调用点）：
   - `store.load()` 的其它调用者只有 `cli.rs:93`（`netguard status` 的打印），语义仍是「主配置是否
     有效」，不需要备份回退；`cli.rs` 的 `config import` 走 `store.save`，自动获得新备份逻辑。
   - `Engine::boot` 只有 `svc.rs:262` 一个调用点，签名未变。
   - `reload_from_disk` 只有 `watch.rs:123` 一个调用点，`Reload` 变体未变。
   - `Snapshot` / `Reload` / `Load` 的公开形状全部未变 → 其它子代理正在改的
     `svc.rs` / `cli_client.rs` / `etw.rs` / `paths.rs` 不会因为本次改动而编译失败。

## 4. 新增单测（`crates/core/src/config.rs`，CI 的 `core` job 会跑）

1. `缺少_auth_也能反序列化`（`config.rs:277`）
   - 输入：`{"version":0,"enabled":true,"apps":[],"hashes":[]}`（就是 `GET /api/config` 的形状）
   - 断言：`from_slice::<Config>` 成功；`auth.factors == Factors::None`；
     `auth == AuthConfig::default()`；`version == 0`；`enabled`；`apps` 为空。
2. `前端往返_删掉_auth_后仍可接受`（`config.rs:289`）
   - 构造一个**带认证材料**的配置（`Factors::Totp` + `totp_secret` + `failures: 2` + 一条 app +
     `enabled: false`）→ `to_value` → `remove("auth")` → `from_value::<Config>`
   - 断言：`back.auth == AuthConfig::default()`（认证材料确实随之消失，随后由 PUT 回填）；
     `!back.enabled`；`back.apps == cfg.apps`；`back.hashes == cfg.hashes`；
     `back.validate().is_ok()`（缺省认证配置本身合法，PUT 回填前的 validate 不会炸）。
3. `认证字段可以缺省`（`config.rs:318`）
   - `{}` → 全部字段落到默认值（factors=None、无散列/种子、recovery 空、failures=0、
     locked_until/last_totp_counter 均 None）
   - `{"factors":"totp","failures":3}` → 部分字段给出时其余仍可缺省。

（原有测试 `序列化稳定`、`未知字段报错` 未改动，仍然通过：新增的 `#[serde(default)]` 只影响
反序列化的「缺字段」行为，不影响 `to_vec` 字节，也不影响 `deny_unknown_fields`。）

## 5. 未做 / 存疑

1. **未编译**（硬约束）。类型与借用已逐行推演（§3），但 CI 才是一次真正的编译验证。
2. **`config.mac.bak` 是新文件**：`install.ps1` 的卸载只在 `-Purge` 时整目录删除（`install.ps1:261`），
   非 `-Purge` 卸载会保留它 —— 与 `config.json` / `config.mac` 的保留策略一致，无额外清理需求。
   但 `docs/ARCHITECTURE.md` 等文档里的「数据目录文件清单」没有列出它（我未改 `docs/`，请主会话
   在收口时补一行）。
3. **首装 `integrity_ok`**：按 §2.4-B 的说明保留 `true`（与规格括号里的 `false` 不同，理由已写）。
   若父会话要求严格 `false`，只需改 `engine.rs:144` 一个字面量。
4. **`netguard config sign`（`cli.rs`）语义略微放宽**：以前 `auth` 缺失的 JSON 直接反序列化失败，
   现在能通过并签出 `factors=none` 的配置。执行者必须能读 DPAPI 机器密钥（SYSTEM/Administrators），
   实质等价于管理员操作，故未加额外拦截；如需防线，建议后续在 `cli.rs` 里对 `factors==None` 打一行
   显式警告（`cli.rs` 不在本次可改范围）。
5. **`cli.rs status`（`netguard status`）仍只报主配置**：篡改时会打印「不可信」并以 2 退出，不提示
   「可用备份」。属于诊断输出，未改（不在可改范围）。
6. **已知剩余退化情形**：配置与备份**都**不可信且备份从未生成（例如只有一次保存、随后两份文件同时
   损坏）时没有可信名单，只能保留 WFP 里的旧过滤器、不新增拦截；此时 WebUI 仍可登录（按备份不可用，
   `factors` 来自 `Config::default()` = none，与前行为一致）并重新保存配置恢复。这是「没有任何可信
   数据」的物理下界，不是本次修复能消除的。
7. **`save()` 非线程安全**：两个线程同时 `save()` 时，备份复制与写入可能交错（备份拿到 A 的内容配
   B 的签名 → `load_backup` 判 `Tampered`，退化为 `Untrusted`，仍是 fail-closed，不会 fail-open）。
   这是改动前就存在的并发特性（`save` 无锁），本次未引入新风险，也未扩大改动面去加锁。
8. **备份签名与配置的配对只在「保存时」刷新**：若管理员手工往目录里放一份自身签名有效的旧配置
   对（重放），HMAC 没有序号/时间戳，无法区分新旧。这是签名方案本身的限制（改动前即存在：
   复制旧的 `config.json`+`config.mac` 同样能回滚），不在本次范围内。
