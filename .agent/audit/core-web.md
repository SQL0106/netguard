# NetGuard 核心 + Web + 安装脚本 逻辑/安全审查

日期：2026-11-04
审查者：子代理（**纯静态审查：未编译、未运行、未上 Windows 真机**）
约束：未修改任何源码；未执行 cargo；未 SSH。下文所有结论均为「静态分析推断」，除标注「已对照 RFC 向量」的算法项外，均未运行验证。

## 一、审查范围（规格抄录）

| 文件 | 行数 | 关注点 |
|---|---|---|
| `crates/core/src/config.rs` | 266 | 配置模型、`Schedule::validate`、`parse_hhmm`、`Config::validate` |
| `crates/core/src/schedule.rs` | 337 | `evaluate`：谁被拦 + `next_change` |
| `crates/core/src/guard.rs` | 170 | 流式哈希、路径规范化、受保护进程名单 |
| `crates/core/src/bootstrap.rs` | 357 | 预置配置 → 正式配置 + 恢复码 |
| `crates/core/src/totp.rs` | 220 | RFC 6238 / HOTP / Base32 / otpauth |
| `web/app.js` + `web/index.html` | 528 + 221 | 前端与接口字段一致性 |
| `install.ps1` | 309 | 安装/卸载/无人值守/ACL/NTP |

辅助对照（只为核对契约，不是结论主体）：`mac.rs`、`auth.rs`、`http.rs`、`engine.rs`、`ticker.rs`、`store.rs`、`wfp.rs`、`etw.rs`、`watch.rs`、`svc.rs`、`cli.rs`、`paths.rs`。

## 二、核查清单

1. `next_change` 严格 > now、对应真实翻转、跨午夜、`end == start`、`days` 掩码、空 `windows`、`enabled=false`、override 到期。
2. 本地时间/UTC、DST、`NaiveDateTime`/`LocalResult`。
3. 绝对路径、时间格式、重复项、`hashes` 格式、`validate()` 兜底。
4. 哈希/签名读写编码对称、`mac.rs` 规范化稳定性。
5. TOTP 时间步、窗口、counter 单调、`otpauth://` 转义。
6. 前端字段与 `http.rs` DTO；`GET /api/config` 不回 `auth` 的后果。
7. `install.ps1` 退出码、`-Force` 顺序、`Invoke-AsSystem` 引号/等待、卸载 WFP。

## 三、结论

### 3.1 汇总

| 严重度 | 条数 |
|---|---|
| 致命 | 3 |
| 高 | 9 |
| 中 | 20 |
| 低 | 15 |
| 非问题 | 16 |

**存在致命项。** 最严重的是：① WebUI 保存配置必然 400；② 配置文件缺失/被改坏时服务不是 fail-closed，而是删除全部过滤器并以「无认证」状态开放 WebUI。

---

### 3.2 `crates/core/src/config.rs`

| 严重度 | 文件:行 | 现象 | 依据 | 建议修法 |
|---|---|---|---|---|
| 致命 | `config.rs:36` + `http.rs:365-368,401` | WebUI 保存配置一定会失败：`GET /api/config` 把 `auth` 整个删掉再下发，前端原样回传，而 `Config.auth` 没有 `#[serde(default)]`，反序列化直接报 `missing field auth` | `Config` 仅 `apps/hashes` 有 `#[serde(default)]`；`AuthConfig` 在 `auth.rs:63-65` 也没有容器级 default，其 `factors` 字段也无 default；`http.rs` 先 `serde_json::from_value::<Config>` 再回填 auth，顺序错了 | 给 `Config.auth` 加 `#[serde(default)]`（`AuthConfig: Default` 已有），或 PUT 时用「合并前的旧 auth」先补进 incoming JSON 再解析；并加一条 `GET→PUT` 往返单测 |
| 高 | `config.rs:179-193` | `validate()` 只查「非空 + 以 .exe 结尾 + 不在保护名单」，**不要求绝对路径**，也不查 `"`、超长、非法字符 | `wfp.rs:170` 用 `FwpmGetAppIdFromFileName0`，它要求完整路径；`wfp.rs:312-322` 对第一条失败路径直接 `?` 返回，导致**整批**应用的过滤器都不再新增（一条坏路径 = 全部放行） | `validate()` 校验盘符/UNC 绝对路径、拒绝 `"` 与控制字符；`reconcile` 改为逐条 `log+continue`，不要让单条失败中断整批 |
| 低 | `config.rs:179-198` | 不拒绝重复 `AppRule.path` / 重复 `hashes`；`name` 允许空 | `wfp.reconcile` 用原始字符串比较，重复路径会各加一对持久化过滤器，且以后每次 reconcile 都保留 | 去重（用 `guard::normalize_path`）或在 `validate()` 报错；`name` 空时回退为路径 |
| 非问题 | `config.rs:194-198` | `hashes` 允许大写（文档写「小写」） | `etw.rs:224` 用 `eq_ignore_ascii_case` 比较，大小写不影响命中 | 无须修；可顺手在保存时统一小写 |
| 非问题 | `config.rs:152-168` | `parse_hhmm` 容忍 `"9:5"`、`"+9:30"`、首尾空格；`24:00`=1440；`format_hhmm` 反向正确 | `u16::from_str` 接受 `+`；`h>24`、`m>59`、`24:01` 均被拒；`1440` 不溢出 | 无须修（宽进严出，落库的是整数） |
| 非问题 | `config.rs:96-115` | `days==0`、`days & !0b111_1111`、`start>=1440`、`end>1440`、`end==start` 全部被拦 | 手算 `0b111_1111 == 127`，bit0=周一 与 `schedule::weekday_index` 一致 | 无须修 |
| 非问题 | `config.rs:21-37` | 序列化稳定性：无 `skip_serializing_if`、无 HashMap、无浮点；字段顺序固定 | 与 `mac.rs:19-27`、`store.rs:152-171` 的签名/校验路径一致（详见 3.8） | 无须修 |

### 3.3 `crates/core/src/schedule.rs`

| 严重度 | 文件:行 | 现象 | 依据 | 建议修法 |
|---|---|---|---|---|
| 高 | `schedule.rs:160-171` | **临时放行到期后，拦截最多晚 59.x 秒才恢复**。`next_change` 只按整分扫描，`override_until` 通常带秒（`set_override` 用 `Local::now().timestamp()+n*60`），到期时刻落在两分钟之间 | 例：now=10:00:50.5、until=10:01:50.5。扫描 t=10:01:00 时 `until > t` 仍放行；t=10:02:00 才发现翻转 → `next_change=10:02:00`。单测 `schedule.rs:303-312` 特意把 `now` 取在整分，掩盖了这个边界 | 把 `override_until.filter(|t| *t > now)` 直接作为候选与自然边界取最小值；`next_change` 允许返回非整分时刻 |
| 中 | `schedule.rs:22,155-172` | override 超过 8 天时，`SCAN_MINUTES` 扫不到它的到期 → 返回 `None`；若所有应用都是「全天封锁」，ticker 退化为 24h 一醒，最长可能晚 24h 才解除放行 | `next_change` 只认「扫描窗口内的变化」；`ticker.rs:59` `None` → 24h 超时 | 同上：override 到期必须显式进候选，不能靠扫描 |
| 低 | `schedule.rs:86-95` | `next_block_start()` 从未被调用；且语义错误——`blocked=false` 时返回的可能是「临时放行到期」而不是「开始封锁」 | `grep` 全仓仅定义处出现 | 删除，或在返回前区分 `evaluation.overridden` |
| 非问题 | `schedule.rs:36-61,121-130` | 空 `windows`=全天封锁、`end<start` 跨午夜、`end==start`（校验层拒绝）、`days` 前一日延续，逐条手算均正确 | 例：周一 22:00→02:00，周二 00:30 命中 `started_yesterday`；周二 22:00 不命中 | 无须修 |
| 非问题 | `schedule.rs:175-182` | `next_minute` 严格 > now（整分时 +1 分钟），不会返回 `<= now` | `truncated > now ? truncated : truncated+1min` | 无须修 |
| 非问题 | `schedule.rs:122-130,160-161` | `enabled=false` 时 `blocked_paths` 恒空、状态恒 false → 扫描 11520 次后返回 `None`，不会 24h 睡死或忙循环 | 与单测 `schedule.rs:220-228` 一致 | 无须修；可在 `enabled=false` 时直接短路返回 `None` 省 1.1 万次分配 |
| 非问题 | `schedule.rs:12-14,169` | 模块只做「墙钟分钟」运算，本身自洽；DST 的坑不在本模块，而在平台侧把 naive 转 `DateTime<Local>` 的实现（见 3.8 的 C2/C3） | `engine.rs:417-427` 用 `from_local_datetime` 处理 `Ambiguous/None` | 无须改本模块；需修平台侧 |

### 3.4 `crates/core/src/guard.rs`

| 严重度 | 文件:行 | 现象 | 依据 | 建议修法 |
|---|---|---|---|---|
| 高 | `guard.rs:3-6` + `etw.rs:179-198` | 哈希黑名单的**设计目标**是防「复制一份改个名」，但 ETW 侧只在**新进程文件名命中 apps 名单**时才哈希 → 改名副本永远不会被哈希、永远不会被拦；只有「同名换目录」的副本被覆盖 | `watch_names()` 只收 `basename(app.path)`，`handle_start` 在 `!contains(&name)` 时直接 return | 去掉文件名预过滤（对每个进程启动都算哈希，或至少按「签名/路径」策略），并补服务启动时对已运行进程的一次扫描 |
| 中 | `guard.rs:88-104,16` | `MAX_HASH_BYTES=512MiB`「防止被超大文件拖死」名不副实：超限判断在读满之后，实际会**读 512MiB+64KiB**，而调用方此时已把目标进程挂起 | `etw.rs:206-219` 先 `NtSuspendProcess` 再 `hash_reader` | 先 `metadata().len() > limit` 直接 `TooLarge`；把上限降到 ~64–128MiB 并记录 |
| 低 | `guard.rs:59-73,71` | `normalize_path`/`same_path` 是**死代码**（全仓只被自己的单测调用），配置去重与 WFP 过滤器的路径比较都直接用原始字符串 → 仅大小写/斜杠不同的同一条目会产生重复持久化过滤器 | `grep` 仅 `guard.rs` 内部出现；`wfp.rs:313,325` 用 `item.path == path` | 在 `Config::validate` 与 `wfp::reconcile` 里统一走 `normalize_path` |
| 低 | `guard.rs:88` + `etw.rs:210-215` | `NtSuspendProcess` 返回值被忽略；挂起失败时仍会「边跑边哈希再补过滤器」，进程可在过滤器生效前完成连接 | `let Some((suspend, _)) = hooks { suspend(target); }` 无检查 | 检查 NTSTATUS；失败时至少要记录并考虑直接按路径拦截 |
| 非问题 | `guard.rs:28-57` | 保护名单 + `.exe` 后缀检查能挡住尾点/尾空格变体（`svchost.exe.` 不以 `.exe` 结尾会被拒）；`basename` 对 `\`/`/`/大小写/尾斜杠处理正确；空文件哈希与 SHA-256 标准值一致 | 手算 `basename` 分支；`hash_bytes` 与 `hash_reader` 都用同一 `to_hex` | 无须修（硬链接/8.3 名的理论绕过需要 TrustedInstaller 权限，可接受） |

### 3.5 `crates/core/src/bootstrap.rs`

| 严重度 | 文件:行 | 现象 | 依据 | 建议修法 |
|---|---|---|---|---|
| 高 | `bootstrap.rs:171-176`（同类：`http.rs:463-479`） | **恢复码全部不可用**：生成时对**带连字符的原文**做 Argon2，校验时先把输入 normalize（去连字符、转大写）再比对 → 永不匹配。这正是「写用 A 编码、读按 B 解析」那一类 bug | `auth.rs:296` 生成的码形如 `ABCDE-FGHIJ`；`auth.rs:244-246` 先 `normalize_recovery_code` 再 `verify_password`；`auth.rs` 自己的测试（第 434 行）正确地哈希了 `normalize_recovery_code(s)`，而 bootstrap/http 没有 | 两处都改成 `hash_password(&auth::normalize_recovery_code(code))`；补一条「bootstrap 生成 → consume 成功」的单测 |
| 中 | `bootstrap.rs:164-177` | `recovery_code_count: Some(0)` 合法 → 生成 0 个恢复码，TOTP 设备丢失即永久锁死；上限 50 又远大于 UI/README 的 10 | `unwrap_or(10).min(50)`，0 原样透传 | 拒绝 0（或把 0 解释为「用默认值」），并设一个合理上限 |
| 低 | `bootstrap.rs:144-159,200-205` | 用户给的 Base32 种子原样存进配置（可能含空格/连字符/小写），`otpauth_url` 又不对 secret 做转义 → 安装脚本/CLI 打印出的二维码链接可能带空格而失效 | `base32_decode` 宽容跳过分隔符，故 `validate()` 通过；`totp.rs:93-103` 直接拼 `secret_b32` | 入库前 `base32_encode(&base32_decode(s)?)` 规范化 |
| 非问题 | `bootstrap.rs:119-141` | `version:0` 视为当前版本；`factors` 优先于 `auth.factors`；缺密码时回退到 `auth.password_hash`；认证为 `none` 时不生成恢复码/密钥 | 与单测 `bootstrap.rs:256-304` 一致 | 无须修 |
| 非问题 | `bootstrap.rs:184-199` | 生成后立即 `Config::validate()`，会校验 PHC 格式、TOTP 种子长度、路径、哈希 | `auth.rs:132-156`、`config.rs:170-201` | 无须修 |

### 3.6 `crates/core/src/totp.rs`

| 严重度 | 文件:行 | 现象 | 依据 | 建议修法 |
|---|---|---|---|---|
| 中 | `totp.rs:93-103` | `otpauth://` 的 label 把 issuer/account 之间的**分隔冒号编码成 `%3A`**（Key URI 规范要求分隔冒号保持字面、仅对 issuer/account 各自编码）；部分认证器/旧版 App 会解析失败。另：secret 未做 percent-encode | 官方示例 `otpauth://totp/Example:alice@google.com?secret=...`；`percent_encode` 对整个 `issuer:account` 生效 | label 用 `enc(issuer)+":"+enc(account)`；secret 先规范化（去 `=`/空格）再拼 |
| 低 | `totp.rs:18-29` | `hotp` 的 `10u32.pow(digits)` 在 `digits>=10` 时溢出（debug 直接 panic，release 取模错误）；公开 API 未限制 | 内部只用 6/8，但函数是 `pub`，单测也用 8 | `digits`  clamp 到 1..=9，或改用 `u64`/查表 |
| 低 | `totp.rs:40-62`（配合 `http.rs:458-470`） | `verify` 本身不做重放（设计如此），但重新生成 TOTP 密钥时**不重置** `last_totp_counter`：新密钥在同一个 30s 时间步内的第一个码会被判「已使用」 | `auth.rs:205-210` 只比较 `counter <= last`；`handle_totp` 换了 secret 却保留旧 counter | 换密钥时把 `last_totp_counter` 置 None |
| 非问题 | `totp.rs:18-34,130-173` | 时间步 `unix/STEP`、±1 步窗口、6 位补零、动态截断、恒定时间比较均正确；RFC 6238 附录 B 与 RFC 4226 附录 D 向量在代码中固定 | `tag[offset..offset+4]`，`offset = last & 0x0f`，`offset+3 <= 18` 不越界 | 无须修（算法本身未运行，按代码与向量逐项核对） |
| 非问题 | `totp.rs:65-90` | Base32 解码：大小写不敏感、跳过分隔符/填充、尾位非零报错；`auth::base32_encode` 无填充；往返测试覆盖 1..40 字节 | 左移只在低 13 位内取用，`buf` 高位溢出不影响结果 | 无须修 |

### 3.7 `web/app.js` + `web/index.html`

| 严重度 | 文件:行 | 现象 | 依据 | 建议修法 |
|---|---|---|---|---|
| 致命 | `app.js:390-402` + `http.rs:365-368,397-404` | 「保存配置」100% 失败：前端把 `GET /api/config` 的对象（无 `auth`）原样塞进 `{config}` 发回，后端 `from_value::<Config>` 因缺 `auth` 报错 → 400「配置格式错误」 | 同 3.2 第 1 行；且后端是先解析再回填 auth，回填发生在解析失败之后 | 后端先为 incoming 补 `auth`（或 `Config.auth` 加 serde default），再解析；前端不必改 |
| 高 | `app.js:416-420` + `http.rs:157-168,439-441` | 「重新生成 TOTP 密钥」恒失败：前端发 `{regenerate:true}`，后端字段是 `regenerate_totp`/`regenerate_recovery`；`ConfigBody` 没有 `deny_unknown_fields`，未知字段被静默忽略 → 两个开关都 false → 400「未指定操作」 | 逐字段对照 DTO | 前端改发 `regenerate_totp:true`（并考虑同时刷新恢复码的提示） |
| 中 | `app.js:483-492` + `http.rs:545` | 事件日志永远显示「（空）」：后端返回 `{"lines": "<字符串>"}`，前端只在 `Array.isArray(result.lines)` 时使用，否则读不存在的 `result.text` | `respond_json(&json!({ "lines": text }))` | 前端改为 `String(result.lines \|\| "")`，或后端返回数组 |
| 中 | `app.js:182-197,240-246` | 星期多选会丢选择：`dayPicker` 的 `onChange` 用**渲染时捕获的 `mask`** 计算，连续点第二个星期会把第一个覆盖掉 | `input.checked ? mask \| (1<<i) : mask & ~(1<<i)`，`mask` 是闭包捕获的旧值，回调里只写 `window.days`，未重渲染 | 回调改为 `window.days = input.checked ? window.days \| (1<<i) : window.days & ~(1<<i)`，或每次变更后 `renderEditor()` |
| 中 | `app.js:42-46,129,144` + `http.rs:251-252` | 「下次切换 / 临时放行至」时间错误：`evaluation.next_change`/`override_until` 是**本地墙钟 naive**，后端用 `and_utc().timestamp()` 当 UTC 发 → UTC+8 时整体偏 8 小时；前端 `fmtTime` 又加一次 `clockOffset`（双重偏移） | `engine.rs:275,284` 全部用 `Local::now().naive_local()`；`and_utc()` 不做时区换算 | 后端改用 `Local.from_local_datetime(...)` 转真实 epoch；前端 `fmtTime` 不再加 `clockOffset`（只用于算剩余秒） |
| 低 | `app.js:268-276` | 结束时间输入 `00:00` 被强制映射为 1440；于是 `00:00–00:00` 从「非法零长窗」静默变成「全天封锁」 | `window.end = value === 0 ? 1440 : value` | 明确区分「到 24:00」与「跨午夜到 00:00」，或在 `start=0,end=0` 时提示拒绝 |
| 低 | `index.html:126,200-217,36,59,135-140` + `app.js:504-524` | `#add-window`（全局「新增时间窗」）没有任何事件绑定 = 死按钮；`#confirm` 对话框及 `confirm-*` 四个控件完全未被使用；口令输入框是 `type="text"`（明文显示） | `bind()` 里没有 `add-window`/`confirm-*`；`setup-pw`/`login-pw`/`auth-pw`/`totp-pw` 均 `type="text"` | 删除死 UI 或接上逻辑；口令改用 `type="password"` |
| 非问题 | `app.js:12-18,96-104,164-177` + `http.rs:137-178` | XSS 安全（全部 `textContent`/`createTextNode`）；除上述两处外，`pw`/`totp`/`recovery`/`minutes`/`regenerate_recovery`/`factors`/`totp_secret` 与 DTO 字段完全一致；`GET /api/config` 不回 `auth` 不会把 `apps` 覆盖成空（因为保存根本没成功——见致命项；修好解析后 `apps/hashes` 会原样保留） | 逐字段比对；`renderEditor` 只在内存中改 `config.apps` | 无须额外处理 |

### 3.8 跨文件（签名/运行时/HTTP，按核查项 4 与 6 补充）

| 严重度 | 文件:行 | 现象 | 依据 | 建议修法 |
|---|---|---|---|---|
| 致命 | `engine.rs:93-107,285-293` + `wfp.rs:324-329` + `http.rs:318-321` | **配置文件被改坏或删除时不是 fail-closed，而是 fail-open + 免认证接管**：`Load::Tampered/Absent` 时用 `Config::default()`（apps 空、auth=none）→ worker 用空集合 `reconcile`，**删除全部持久化过滤器**；WebUI 因 factors=none 无需登录，任何人可提交新配置并通过 `replace_config` 用真密钥重新签名 | `Config::default()` 的 apps/auth 都是空；`reconcile` 的删除循环会清掉所有 `ng4|/ng6|` 过滤器；`handle_login` 对 `Factors::None` 直接建会话 | Tampered 时保留「上次已知良好的过期配置」用于封锁（如 `config.json.bak`），或至少进入「按备份名单封锁 + WebUI 只读」；`Absent` 若存在 `secret.key`/备份，应视为篡改而不是首装；认证失败绝不能降级为 none |
| 高 | `engine.rs:252-264,275-284` | 时区/DST/校时会误判「时钟回拨」并把**所有应用**封死：`now` 是本地墙钟，却用 `and_utc().timestamp()` 当时间戳存水位线。夏令时回拨 1h、改时区 8h、NTP 往回校 >120s 都会触发；而 worker 只在自然边界醒来，封锁可能持续到墙钟重新越过旧水位（1h/8h，若 `next_change=None` 至少 24h 才重算） | `observe_clock(now.and_utc().timestamp())`；`rollback` 时 `blocked = 全部 apps`；`wait_until(evaluation.next_change)` 不因 rollback 缩短 | 水位线一律用真实 epoch（`Local::now().timestamp()`）；DST/时区变更时重置水位线；rollback 期间用短定时器（如 60s）复查 |
| 中 | `engine.rs:410-415` | DST 回拨造成的**歧义本地时间**（一小时出现两次）会让 `override_deadline` 返回 `None` → 临时放行被静默忽略（注释却写「歧义取较早者」） | `Local.timestamp_opt(value,0).single()` 对 `Ambiguous` 返回 None | 改用 `earliest()`/`single().or_else(earliest)`，并补 DST 单测 |
| 中 | `ticker.rs:47-68` + `engine.rs:274-344` | 丢失唤醒：`wait_until` 在**进入等待时**才记录 generation。engine 在 `snapshot()` 之后、`wait_until()` 之前收到的 `notify()`（保存配置、临时放行、电源/时间事件）会被吞掉，必须等下一个自然边界（可能是几天）才生效 | 经典 condvar 竞态；`notify` 在 `wait_until` 锁之前完成则 `start` 已含新 generation | engine 在取快照**之前**记下 generation 并传入 `wait_until`，`if now_generation != before { continue; }` |
| 中 | `http.rs:194-213,588-591` + `auth.rs:171-237` | 并发错误口令可放大尝试次数：每个请求一个线程，`authenticate` 读快照→改 `failures`→整份回写，无互斥/CAS，N 个并行请求会互相覆盖计数（5 次锁定变成「5 轮任意并行数」） | `snapshot()` + `replace_config()` 之间没有锁 | 对认证状态更新加专用 mutex，或用原子计数/单线程队列 |
| 中 | `wfp.rs:307-322` | 一条坏路径终止整批协调（见 3.2 第 2 行）：`add_block_layers(...)?` 让后续路径全部跳过，且旧过滤器不会被删除、新应拦的应用不会加 | `?` 在 for 循环里直接返回 | 逐条 `match`，失败记日志并 `continue`；返回报告里带 failed 列表 |
| 中 | `http.rs:264-309,576-599` | 本地 HTTP 不校验 `Host`/`Origin`：`/api/setup` 只需回环 + 10 分钟窗口、无需 Cookie，DNS rebinding 或 `text/plain` 简单请求即可被外部页面调用，把服务初始化为 `factors=none` | `parse_body` 不看 Content-Type；`dispatch` 不看 Host | 校验 `Host` 只允许 `127.0.0.1:47811`/`localhost`，并检查 `Origin`；setup 额外要求一次性令牌（安装脚本生成、写到仅管理员可读的文件） |
| 低 | `http.rs:323-335,497-526` | 恢复码登录路径忽略 `replace_config` 失败（码未真正消耗/失败计数丢失）；`/api/override` 的 `minutes` 不设上限（u32 × 60 秒 ≈ 8000 年） | `let _ = api.engine.replace_config(config);`；`minutes: u32` 直接乘 | 处理保存错误；限制 `minutes <= 1440` |
| 低 | `watch.rs:121-129` + `store.rs:164-169` | `save()` 先写 `config.json` 再写 `config.mac`，监视器可能读到「新配置 + 旧签名」而短暂把 `integrity_ok=false`（全名单封锁）；300ms 的 SETTLE 通常能兜住，但属于时序依赖 | 两次 `write_atomic` 不是原子的 | 先写 `config.mac.tmp`，与 `config.json` 一起用同一事务/顺序（先 mac 后 json 也会短暂反例，最好写一个合并文件或加「签名与正文」单文件容器） |
| 低 | `engine.rs:233` + `store.rs:28-43` | `RuntimeState.failures/locked_until/last_totp_counter` 与 `AuthConfig` 同名字段重复，但运行期只用 `AuthConfig`（签名配置）里的那份；`note_auth_state` 是死代码，容易误导后续维护（误以为改 state.json 能重置锁定） | `grep` 仅定义处 | 删除 `RuntimeState` 的重复字段与 `note_auth_state`，或统一到一处 |
| 低 | `etw.rs:251-253` + `engine.rs:363-383` | 哈希命中的路径被加成**持久化**过滤器，但 `hash_blocked` 不落盘：服务重启后 `reconcile` 会把它当「不在 wanted」删掉；而进程退出（`handle_stop` 空实现）也不会移除，生命周期不对称 | `handle_stop` 只有 `let _ = (engine, pid);` | 明确策略：要么落盘 hash 命中记录，要么在进程退出时移除；至少注释清楚「重启前一直有效」 |
| 非问题 | `mac.rs:19-27,41-59,62-75` + `store.rs:126-148,152-171` | 签名读写对称：`save` 签 `to_vec(Config)`（紧凑）、写 pretty；`load` 先解析再 `to_vec` 同一结构校验；`v1:<hex>\n` 由 `parse_signature` 剥前缀后交给 `verify_bytes`；`verify` 对十六进制大小写宽容。字段序固定、无 HashMap/浮点/`skip_serializing_if`，`#[serde(default)]` 只影响反序列化且所有字段始终序列化 | 逐行对照 `store.save` 与 `store.load`；`Config`/`AuthConfig` 均为普通 struct | 无须修（这正是之前签名 bug 已修好的状态；勿再引入 `skip_serializing_if`/`flatten`） |

### 3.9 `install.ps1`

| 严重度 | 文件:行 | 现象 | 依据 | 建议修法 |
|---|---|---|---|---|
| 高 | `install.ps1:301-306` | `-Silent` 没被纳入 `$needSetup`：只给 `-Silent` 时脚本打印「未提供初始化参数」并 **exit 0**，装出一个未初始化、且每次服务启动后 10 分钟内 `/api/setup` 免认证开放的服务——与文档「缺少必要参数时以非零退出码结束」直接矛盾 | `$needSetup` 只看 `$Config/$Factors/$Password/...`；`http.rs:41` 每次 `Api::new` 重置 `setup_until=now+600`；`setup_open()` 只要求 `!is_initialized` | `if ($Silent -and -not $needSetup) { Fail 3 ... }`；或静默模式要求显式 `-NoSetup` 才允许未初始化 |
| 高 | `install.ps1:236-242` + `cli.rs:71-87` | 安装永远传 `--quiet`，而恢复码/TOTP 链接只在给了 `-RecoveryOut` 时落盘 → **TOTP/双因子安装完成后用户拿不到 URI 和恢复码**（`--quiet` 连密钥都不打印），尤其在 `-Silent` 下等于装完即锁死 | `$arguments` 固定含 `--quiet`；`cli::setup` 在 quiet 下不打印 secret/uri/codes；`-RecoveryOut` 是可选的 | 当函数 `needs_totp`/`needs_password` 时强制要求 `-RecoveryOut`（否则 `Fail 3`）；或 quiet 下也把 URI 写入一个仅管理员可读的文件 |
| 高 | `install.ps1:160,203,241` | `icacls` 的返回码全部不检查（还用了本地化组名 `Administrators`）→ 收紧失败时 DataDir 保留继承 ACL，普通用户可读 `secret.key`（DPAPI 机器范围）→ 可伪造配置签名；非英文 Windows 上组名解析也会失败 | `& icacls ... \| Out-Null`，`$ErrorActionPreference='Stop'` 对原生命令退出码无效 | 每条 icacls 后检查 `$LASTEXITCODE`，失败 `Fail 5`；用 SID `*S-1-5-32-544`、`*S-1-5-18` 代替名称 |
| 中 | `install.ps1:198-242` | `Invoke-Setup` 先 `icacls ... Administrators:(OI)(CI)F`，但在恢复 RX 之前有多条提前退出路径（`Fail 2` 缺 Config、`Fail 3` 缺口令文件/stdin、`Start-Process` 抛异常）→ 目录停留在 `Administrators:F`，且已写入的 preseed.json 可能残留明文口令 | 恢复语句在 241 行，晚于 208/227 行的 Fail；异常路径完全不执行恢复 | 用 `try/finally` 包住整个 Invoke-Setup，在 finally 里恢复 ACL 并删除 preseed |
| 中 | `install.ps1:116-137` | `Invoke-AsSystem` 的 `/tr` 引号不可靠：`$action` 内含双引号，经 PowerShell 原生参数透传后内层引号可能丢失；`$env:TEMP` 路径含空格时 SYSTEM 任务找不到脚本；`schtasks /create` 退出码不检查，失败只 warn 后继续（还会空等 20 秒） | `$action = 'powershell.exe ... -File "' + $file + '"'`；`& schtasks /create ... \| Out-Null` 无 `$LASTEXITCODE` 检查 | 用 `Register-ScheduledTask`/`New-ScheduledTaskAction -Execute powershell.exe -Argument <args>`；写临时脚本到 `C:\ProgramData\NetGuard\.agent\`（无空格、仅 SYSTEM/管理员可写） |
| 中 | `install.ps1:152-174` | 失败退出码不完整：`sc.exe start` 不检查（1053/1067/2 也继续打印「安装完成」并 exit 0）；`Copy-Item` 在旧服务进程未完全退出时抛异常，未捕获 → 进程退出码 1，不在文档的 2/3/4/5 里 | `& sc.exe start $ServiceName \| Out-Null`；`$ErrorActionPreference='Stop'` + `Copy-Item` 无 try | 启动后 `Get-Service` 校验 `Running`；拷贝加重试/等待文件解锁；统一用 `Fail` 映射退出码 |
| 中 | `install.ps1:207-215` | `-Config` 分支**忽略** `-Password/-PasswordFile/-PasswordStdin/-TotpSecret`（只注入 factors）→ 用户以为设了口令，实际用预置文件里的凭据；若预置无口令且 factors 需要口令，会以 child 的 exit 1 失败 | 该分支只做 `Add-Member factors`；口令读取在 `else` 分支 | 两个分支共用同一段「把命令行凭据合并进预置」的逻辑；冲突时明确报错 |
| 中 | `install.ps1:212-214` | `-Config` + `-Factors` 会用 `Get-Content -Raw \| ConvertFrom-Json \| ConvertTo-Json` 重写 JSON：Windows PowerShell 5.1 对无 BOM 的 UTF-8 按 ANSI 解码 → 中文应用名/路径变乱码；随后 `Set-Content -Encoding UTF8` 写入 BOM | PS 5.1 默认编码行为 | 用 `Get-Content -Raw -Encoding utf8` 读取，或用 `[IO.File]::ReadAllText(path, UTF8)`；不要整份重写，改为在 JSON 文本层注入 |
| 中 | `install.ps1:246-262,292-295` | 卸载：`exit 0` 恒成立（服务删不掉也只 warn）；**不清理持久化 WFP 过滤器**（`FWPM_FILTER_FLAG_PERSISTENT`）→ 卸载后应用仍被拦，重启也不消失，只能靠重装或 `netsh wfp` 手工清 | `Remove-Installation` 无失败返回；`wfp.rs:224` 过滤器持久化；`cli.rs` 无删除 Provider 的子命令 | 增加 `netguard.exe uninstall --purge-filters`（枚举 `PROVIDER_KEY` 下全部过滤器+Provider+子层并删除），卸载脚本调用并把失败反映到退出码 |
| 中 | `install.ps1:59-60,242` | 文档退出码 2/3/4 **实际不会全部出现**：子进程任何初始化失败（解析/校验/缺凭据）都经 `netguard.rs` 统一 `exit 1`；脚本 `Fail $process.ExitCode` → 1；`Fail 4` 从未使用 | `crates/win/src/bin/netguard.rs` 只有 `exit 1`；`Fail 2/3/5` 只覆盖脚本自身的检查 | 让 `bootstrap`/`store` 错误映射到 2/3/4（或在脚本里按错误文本分类），并同步文档 |
| 中 | `cli.rs:58-69` | `setup` 不检查 `is_initialized()`，无条件覆盖 `config.json`/`config.mac` → 在已安装系统上重复执行 `-Config`（无需 `-Force`）会静默重置应用名单、哈希与认证凭据 | `store.save(&bootstrap.config)` 直接写 | `setup` 默认拒绝覆盖（要求 `--replace`），`install.ps1` 仅在 `-Force` 时传 |
| 低 | `install.ps1:103-113,218,292` | `Stop-Target` 是死代码；`$Silent` 的两个分支结果相同（`both`/`both`）；`-Purge` 不配 `-Uninstall` 时被静默忽略；异常中断后可能残留 `NetGuardTask` 计划任务 | 静态阅读 | 删除死代码；`-Purge` 单独给时提示或报错；`Invoke-AsSystem` 用 `try/finally` 删任务 |
| 低 | `install.ps1:265-286` | `-TimeSource` 直接拼进 `w32tm` 参数（本地管理员脚本，风险低）；NTP 同步失败只 warn，而 TOTP 强依赖时钟 | `'/manualpeerlist:' + $peers`；失败仅 `Write-Step 警告` | 校验主机名/允许列表；同步失败时至少把警告升级为显眼提示 |
| 非问题 | `install.ps1:139-175,116-137,246-259` | `-Force` 顺序正确（以 SYSTEM 停/删旧服务→等消失→再拷文件→再注册）；`Invoke-AsSystem` 用 `.done` 标记轮询而非盲等；`-Purge` 用 SYSTEM 删除高 ACL 目录；`sc.exe failure`/`sidtype`/`sdset` 用法正确 | 逐行核对 | 无须修（引号/退出码问题见上） |

---

## 四、建议的修复优先级

1. **P0（致命）**：`Config.auth` 反序列化（WebUI 保存）；启动时 Tampered/Absent 的 fail-closed 逻辑 + 认证不得降级为 none。
2. **P1（高）**：恢复码哈希归一化；`next_change` 纳入 override 到期；`observe_clock` 用真实 epoch；`-Silent` 强制参数；`--quiet` 与恢复码输出；icacls 检查；`regenerate` 字段名；ETW 改名副本。
3. **P2（中）**：时间显示时区、日志契约、星期多选、reconcile 逐条容错、ticker 丢失唤醒、认证并发、卸载 WFP、`-Config` 凭据/编码、Host/Origin。
