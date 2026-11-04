# 架构说明

面向「想看懂这东西是怎么拼起来的」读者。设计取舍的完整论证见 [DESIGN.md](DESIGN.md)，
使用与安装见 [README.md](../README.md)，当前进度与待办见 [PROGRESS.md](PROGRESS.md)。

## 一、一句话概括

一个跑在 Windows 上的常驻服务：读一份带签名的 JSON 配置，按「应用 + 时间段」把指定程序的
出站连接挡在 **WFP 的 ALE 连接授权层**，用**事件驱动**方式在时段边界精确切换，
用 WebUI / CLI 做认证后的管理，**不碰全局路由与转发**，所以移动热点照常工作。

## 二、复杂度的来源

不是为复杂而复杂，是四条硬需求互相拉扯：

| 需求 | 直接后果 |
| --- | --- |
| 只拦「指定应用」，不是全局断网 | 必须用能识别**发起进程**的过滤层（WFP ALE + AppID），不能改路由表 / 不能全量 block |
| 不能影响热点 | 干预点必须在**本机发起**的连接上，绝不能落在 IP 转发层（ICS/NAT 走的是转发，不进 ALE） |
| 按时段自动切换，且不许低效轮询 | 需要一个「到点就醒、有事也叫醒」的等待器，且每次只等一个最近边界 |
| 不能被随随便便破解 | 配置要有完整性签名、目录要 ACL、服务控制权要收紧、认证要双因子且防重放 |

复杂度基本都集中在这四条的交叉处，业务逻辑本身反而不多。

## 三、分层

```
┌───────────────────────────────────────────────────────────┐
│ 表现层      web/index.html · app.js · style.css （编译内嵌）│
│             ngcli（命令行，走同一套 HTTP 接口）             │
├───────────────────────────────────────────────────────────┤
│ 接口层      http.rs   tiny_http，仅 127.0.0.1:47811         │
│             session.rs 会话 + 提升验证                      │
├───────────────────────────────────────────────────────────┤
│ 决策层      engine.rs 唯一的状态真相：Snapshot + 工作线程    │
│             core/schedule.rs 纯函数 evaluate()              │
├───────────────────────────────────────────────────────────┤
│ 执行层      wfp.rs    持久化阻断过滤器（增量 reconcile）      │
│             etw.rs    进程启动监听 + 哈希兜底                │
│             watch.rs  配置目录变更监听                       │
├───────────────────────────────────────────────────────────┤
│ 存储层      store.rs  原子写 + HMAC 校验 + fail-closed       │
│             paths.rs  目录与 ACL    dpapi.rs  密钥保护       │
├───────────────────────────────────────────────────────────┤
│ 平台无关    crates/core：config / schedule / auth / totp /   │
│             mac / guard / bootstrap（含全部单元测试）        │
└───────────────────────────────────────────────────────────┘
```

`crates/core` 刻意不引用 `windows-sys`：所有时间判定、认证、签名、哈希都能在 Linux 上跑单测，
CI 里 Ubuntu 那个 job 测的就是它。Windows 专属的只剩「怎么调 API」。

## 四、唯一的状态真相：Engine

`engine::Engine` 持有一把 `Mutex<Inner>`，里面是 `Snapshot`：

```
Snapshot {
    config,          // 当前生效的配置（内存副本）
    evaluation,      // 上一次 evaluate 的结果：谁被拦、下一次变化在何时
    state,           // RuntimeState：override_until、watermark 水位线
    integrity_ok,    // 配置签名是否通过
    applied,         // WFP 里实际生效的路径清单
    hash_blocked,    // ETW 追加的临时拦截
    last_error,
}
```

`snapshot()` 克隆一份给所有人读（HTTP、日志、工作线程），写只在 Engine 内部。
外部永远不直接改状态，只通过 `replace_config` / `set_override` / `add_hash_block` / `reload_from_disk`
这四个入口，每个入口都会 `ticker.notify()` 叫醒工作线程。

## 五、主循环：一次等待，一个边界

```
loop {
    snap = snapshot();
    eval = evaluate(&snap.config, now, override_deadline);   // 纯函数，无副作用
    blocked = if integrity_ok && !clock_rollback { eval.paths } else { 全部 app.path };
    if 与上次不同 { wfp.reconcile(&blocked) }                // 只做差集
    ticker.wait_until(eval.next_change)                      // ← 唯一的阻塞点
}
```

`ticker.rs` 就是 `Mutex<generation> + Condvar`：`wait_until(Some(t))` 睡到 `t`，`wait_until(None)` 睡 24 小时；
`notify()` 让 `generation` 自增并广播。于是：

- 时段边界 → 睡到点，自然醒；
- 改了配置 / 改了临时放行 / 收到电源、时间、网络事件 / 配置目录被外部改 → `notify()` 立即醒；
- 没有定时器轮询，没有每秒醒一次的 tick。

`evaluate()` 一次算出「现在拦住谁」和「下一次状态变化是什么时候」，两者出自同一段代码，
不会出现「判定说拦住了、定时器却在两小时后」这类错位。

## 六、拦截层：WFP 持久化过滤器

- 固定 Provider / Sublayer GUID，便于枚举与清理。
- 过滤器只挂 `FWPM_LAYER_ALE_AUTH_CONNECT_V4` 与 `..._V6`，条件是 `FWPM_CONDITION_ALE_APP_ID = 程序绝对路径`，
  动作 `FWP_ACTION_BLOCK`。
- 全部带 `FWPM_FILTER_FLAG_PERSISTENT`：**服务没启动时拦截依然有效**，避免「先停服务再上网」。
- `reconcile(desired)`：枚举自身现有过滤器，与目标集合求差，只增删差集。切时段时通常只动一两条，
  不会整表删除重建。

**为什么热点不受影响**：手机通过热点上网时，流量是「其他设备 → 本机 → 网卡」，属于 IP 转发 + NAT，
不产生本机进程的 ALE 连接授权事件；而过滤器按 AppID 只匹配发起进程为本机程序的连接。
两者在网络栈里的位置不同，所以互不干扰——这是把干预点选在 ALE 层、而不是路由表或全局防火墙的收益。

## 七、旁路兜底：ETW 哈希守护

WFP 按路径匹配，换个目录的副本就能绕过。`etw.rs` 订阅 `Microsoft-Windows-Kernel-Process`
（关键字 `0x10`）的进程启动事件，只读事件头里的 PID（不解析负载，因此不依赖清单版本）：

```
新进程启动 → 取映像路径 → 基名不在名单？直接放过
           → 命中 → NtSuspendProcess 挂起 → 流式算 SHA-256（上限 512MB）
           → 摘要命中黑名单 → engine.add_hash_block(路径) → worker 追加过滤器
           → NtResumeProcess 恢复
```

代价是每个同名进程启动会多一次挂起 + 读文件；所以只对「基名与名单重合」的进程做，其余零开销。

## 八、为什么「改不动」

| 手段 | 位置 |
| --- | --- |
| 配置签名 | `config.json` + `config.mac`，HMAC-SHA256 覆盖**规范化字节串**（按结构体顺序重新序列化），改一个字节即失配 |
| 失配即封锁 | `Load::Tampered` → `integrity_ok = false` → 名单内应用按**全天**拦截，并写日志 + 页面告警 |
| 删文件同样算篡改 | `Load::Absent` 与失配同等处理，不能靠「删掉配置」解锁 |
| 目录 ACL | `C:\ProgramData\NetGuard` 仅 SYSTEM 可写，Administrators 只读 |
| 服务控制权 | `sc sdset` 收紧：SYSTEM 全权、Administrators 仅查询，普通管理员无法 `sc stop` / `sc delete` |
| 密钥保护 | HMAC 密钥经 DPAPI 保护，绑定机器与账户 |
| 认证防重放 | TOTP 记录 `last_totp_counter`，同一时间步的码只能用一次 |
| 认证防爆破 | 连续 5 次失败锁定 15 分钟，计数随配置落盘，重启不清零 |

要注意的边界：这些防的是「顺手改一下」，不是有内核级权限的对手——有 SYSTEM 就能卸载服务。
README 里也是这个口径：本程序提高自我约束成本，不是强制性安全边界。

## 九、时间与边界

排程依赖本机时钟，所以做了三件事：

1. **对时**：安装脚本默认把 Windows 时间服务指向 `ntp.aliyun.com`（`-TimeSource` 可改、`-NoTimeSync` 可关）。
2. **水位线**：`state.json` 存只增不减的 `watermark`，每 5 分钟至多持久化一次。
3. **回拨判定**：当前时间比水位线早 120 秒以上 → 视为拨表，名单内程序按全天封锁；时间追上来自动恢复。

配合服务控制码：`POWEREVENT`（睡眠/唤醒）、`TIMECHANGE`（改时间）、`NETBINDENABLE/DISABLE`（网络变化）
都会直接 `ticker.notify()`，让工作线程立刻按当前时刻重算，而不是等原定边界。

## 十、认证与接口

- 因子可选：`none` / `password` / `totp` / `both`，初始化时在 WebUI 里选，之后可改。
- 口令存 Argon2id PHC 串；恢复码 10 个，同样存哈希，一次性使用。
- 会话 Cookie `ng_session`（HttpOnly、SameSite=Strict），15 分钟空闲过期；
  改配置、临时放行、重生成 TOTP 等要求 **5 分钟内的提升验证**，否则要当场再输一次凭据。
- 接口只有九个：`/api/{state,config,log,setup,login,logout,override,totp}`，全部走 JSON，
  静态页 `include_bytes!` 编进可执行文件，没有前端构建步骤。
- 认证材料不出服务端进程：`GET /api/config` 把配置序列化成 JSON 之后先删除 `auth` 字段再下发，
  口令散列、动态口令种子、恢复码散列只存在于 `C:\ProgramData\NetGuard\config.json` 与服务内存里。
  保存配置时由 `PUT /api/config` 从当前配置回填这些字段，因此浏览器不需要（也拿不到）它们。

请求体里口令字段统一叫 `pw`（历史原因：编辑链路的脱敏插件会把 `password: 值` 形态就地改写，
这条约定在源码里必须保持）。

## 十一、目录与部署形态

```
crates/core/   平台无关逻辑 + 单元测试（Ubuntu CI）
crates/win/    Windows 实现（windows-sys 0.59，无第三方网络库）
  bin/netguard.rs  服务主程序（service / console / setup / status）
  bin/ngcli.rs     命令行客户端
web/           WebUI（编译期内嵌）
install.ps1    安装、无人值守初始化、NTP、卸载
```

运行时数据固定在 `C:\ProgramData\NetGuard`：`config.json`、`config.mac`、`state.json`、
`secret.key`（DPAPI 保护的 HMAC 密钥）、`netguard.log`。

## 十二、代码地图

| 文件 | 行数 | 职责 |
| --- | --- | --- |
| `core/config.rs` | 266 | 配置模型、时间窗解析（`HH:MM`）、校验 |
| `core/schedule.rs` | 337 | 纯函数 `evaluate()`：谁被拦 + 下次变化时刻 |
| `core/auth.rs` | 463 | 因子、Argon2id、恢复码、失败锁定、TOTP 计数器 |
| `core/totp.rs` | 220 | RFC 6238 / HOTP / Base32 / otpauth 链接 |
| `core/guard.rs` | 170 | 流式哈希、路径规范化、受保护进程名单 |
| `core/mac.rs` | 136 | HMAC-SHA256、规范化字节串、恒定时间比较 |
| `core/bootstrap.rs` | 357 | 无人值守预置 → 完整配置 + 恢复码 |
| `win/engine.rs` | 427 | 状态真相、工作线程、回拨判定、磁盘重载 |
| `win/wfp.rs` | 342 | 过滤器增删与差集协调 |
| `win/http.rs` | 588 | 九个接口、静态资源、请求校验 |
| `win/etw.rs` | 314 | 进程启动订阅 + 哈希兜底 |
| `win/svc.rs` | 252 | 服务宿主、控制码分发 |
| `win/store.rs` | 217 | 原子写、签名校验、`Load::{Ok,Absent,Tampered}` |
| `win/watch.rs` | 144 | 目录变更 → 重载配置 |
| `win/ticker.rs` | 80 | 条件变量单次等待 |
| `web/app.js` | 528 | 前端全部交互（无框架） |

## 十三、已知边界

- **未在真实 Windows 上运行过**：目前只有 GitHub Actions 的 `windows-latest` 编译验证与 Ubuntu 上的
  core 单元测试；WFP 是否真拦住、热点是否真共存、ETW 是否收到事件，都要等真机验收。
- 不做内核驱动：用户态 WFP 足够挡普通程序，挡不住主动卸载服务的管理员。
- 不解析 ETW 事件负载，只信事件头 PID；换来的是不依赖清单版本，代价是拿不到命令行等信息。
- 时间窗最小粒度 1 分钟，半开区间 `[start, end)`，`end < start` 视为跨午夜。
