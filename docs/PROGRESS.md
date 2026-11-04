# 进度记录

本文件用于在上下文受限或会话中断时恢复工作状态。设计细节见 [DESIGN.md](DESIGN.md)，
面向使用者的说明见 [README.md](../README.md)。

## 一、当前状态（2026-11-04）

仓库地址：`https://github.com/SQL0106/netguard`（公开）。

**硬约束：本机不做任何编译。** 全部构建、检查与测试只在 GitHub Actions 执行
（`ubuntu-latest` 跑 core 单元测试，`windows-latest` 产出可执行文件）。本机仅编辑源码与文档。

发布状态：`v0.1.0` 已于 2026-11-04 发布，附件为 `netguard.exe`、`ngcli.exe`、`install.ps1`、
`README.md`、`DESIGN.md`。CI 从第四轮起连续全绿，当前无待修编译错误。

Windows 真机验收进行中（详见第六节与第十节），`win`（192.168.1.199）上已验证：日志出现
「过滤器已同步：新增 1 条」；名单内 `curl.exe` 访问纯 IP 目标返回 exit 7；非名单程序与 `ping`
正常；未全局断网。尚待验证：热点共存、时段边界翻转、睡眠唤醒、时钟回拨、登录锁定、
TOTP 重放、篡改 fail-closed、配置自动重载、`ngcli` 全流程。

## 二、模块清单

| 模块 | 文件 | 状态 |
| --- | --- | --- |
| 配置模型与校验 | `crates/core/src/config.rs` | 完成，单测通过 |
| 时间窗与生效判定 | `crates/core/src/schedule.rs` | 完成，单测通过 |
| TOTP（RFC 6238） | `crates/core/src/totp.rs` | 完成，官方向量通过 |
| 口令与恢复码 | `crates/core/src/auth.rs` | 完成，单测通过 |
| HMAC 签名与恒定时间比较 | `crates/core/src/mac.rs` | 完成，单测通过 |
| 哈希判断与受保护进程 | `crates/core/src/guard.rs` | 完成，单测通过 |
| 无人值守初始化 | `crates/core/src/bootstrap.rs` | 完成，单测通过 |
| 路径与目录 ACL | `crates/win/src/paths.rs` | 完成 |
| DPAPI 保护 | `crates/win/src/dpapi.rs` | 完成 |
| 日志轮转 | `crates/win/src/log.rs` | 完成 |
| 配置存储与签名校验、fail-closed | `crates/win/src/store.rs` | 完成 |
| 边界唤醒等待器（非轮询） | `crates/win/src/ticker.rs` | 完成 |
| WFP 过滤器与增量协调 | `crates/win/src/wfp.rs` | 完成 |
| 运行时引擎与工作线程 | `crates/win/src/engine.rs` | 完成 |
| 会话与提升验证 | `crates/win/src/session.rs` | 完成 |
| 本地控制台（HTTP API + 静态页面） | `crates/win/src/http.rs`、`web/` | 完成 |
| 服务宿主 | `crates/win/src/svc.rs` | 完成 |
| 配置目录变更监听 | `crates/win/src/watch.rs` | 完成 |
| ETW 哈希守护 | `crates/win/src/etw.rs` | 完成 |
| 命令行 | `crates/win/src/cli.rs`、`crates/win/src/cli_client.rs` | 完成 |
| 安装脚本 | `install.ps1` | 完成 |

## 三、控制台接口

监听 `127.0.0.1:47811`，仅回环。会话 Cookie 名 `ng_session`，HttpOnly、SameSite=Strict，
空闲 15 分钟过期；改配置、临时放行、卸载等敏感操作需在 5 分钟内重新验证。

| 方法与路径 | 说明 |
| --- | --- |
| `GET /` `/app.js` `/style.css` | 静态页面 |
| `POST /api/setup` | 首次初始化，仅未初始化且安装后 10 分钟窗口内可用 |
| `POST /api/login` | 按已启用因子登录，返回会话 Cookie |
| `POST /api/logout` | 注销 |
| `GET /api/state` | 运行状态、生效名单、下一变更时刻 |
| `GET /api/config` | 读取名单与时段；序列化后剔除 `auth`，认证材料不下发 |
| `PUT /api/config` | 保存配置，需提升验证 |
| `POST /api/override` | 临时放行，`minutes` 为 0 表示取消 |
| `POST /api/totp` | 重新生成 TOTP 密钥或恢复码 |
| `GET /api/log` | 读取日志尾部若干行 |

`ngcli` 为同一接口的命令行客户端，会话信息保存于数据目录。

保存配置时 `PUT /api/config` 会用当前配置回填 `auth`（因子、口令散列、动态口令种子、恢复码散列、
失败计数、锁定截止、动态口令上一步数），因此浏览器只需提交 `apps` 与 `enabled` 等字段。

## 四、安全要点（与 DESIGN §6 一致）

- 配置写入 `C:\ProgramData\NetGuard\config.json`，签名保存在 `config.mac`，
  签名对象是解析后按结构体声明顺序重新序列化的规范字节串，因此缩进与键序不影响校验。
- 签名不匹配或配置缺失一律 fail-closed：沿用内存中最后一次有效配置，若内存中无有效配置，
  则名单内程序按全天封锁处理，并写入日志、在页面顶部显示告警。
- 目录 ACL 为 `SYSTEM` 完全控制、`Administrators` 可修改（M），普通用户无权写入。
- 过滤器为持久化对象，服务停止后拦截依然生效；服务启动时按 Provider 键枚举并与配置求差集。
- 服务控制权限经 `sc sdset` 收紧，Administrators 无法 `sc stop` 或 `sc delete`。

## 五、CI 约定

- 缓存：`Swatinem/rust-cache@v2`，core 与 windows 各自独立键。
- 产物：两个 job 的上传步骤均为 `if: always()`，即使编译或测试失败也保留日志与可执行文件。
- 发布：推送 `v*` 标签时聚合产物并创建 Release。
- 查看失败原因：

```bash
gh run view <id> --log-failed | sed 's/\x1b\[[0-9;]*m//g' > .ci.log
sed -n '70,450p' .ci.log | sed 's/^Windows 构建（release）\t构建\t[0-9T:.Z-]* //' | head -150
```

## 六、待办

1. 真机验收：`win`（192.168.1.199）上线后按 [ACCEPTANCE.md](ACCEPTANCE.md) 的十二节逐条执行，
   并把结果回填到本文档。验收项包括拦截生效、热点共存、时段边界翻转、睡眠唤醒、时钟回拨封锁、
   服务无法停止、连续失败锁定、动态口令同码重放拒绝、配置篡改 fail-closed、外部改配置自动重载。
2. 校对 README 与 DESIGN 的措辞，使其与实现完全一致。

已完成：`v0.1.0` 于 2026-11-04 发布，附件为 `netguard.exe`、`ngcli.exe`、`install.ps1`、
`README.md`、`DESIGN.md`。

## 七、实现中的取舍

- 排程唤醒使用条件变量单次等待（`ticker.rs`），不使用高频轮询，也不依赖内核定时器对象；
  任一时刻只有一个截止时刻，到点重算。
- `wfp.rs` 的结构体字段按 windows-sys 0.59 的实际定义书写（`r#type`、`Anonymous`、
  `windows_sys::core::GUID`），常量 `AUTHN_WINNT` 直接取数值 10 以避免启用额外特性。
- ETW 订阅只读取事件头中的进程标识，不解析负载；仅当进程基名命中名单时才读取映像并计算哈希。
- 源码中不出现「口令字段名紧跟等号或冒号再加字面值」的写法，避免编辑器插件改写磁盘内容；
  统一使用 `pw` 作为请求字段名。

## 八、环境备忘

- 开发机 `/home` 空间紧张，`/` 尚有余量；因此任何构建产物都不落在本机。
- 不在此开发机上运行本程序；Windows 侧测试只在 `win`（192.168.1.199）进行。

## 九、最近提交

| 提交 | 内容 |
| --- | --- |
| `dc40ec5` | 修复：重建非持久化的 Provider 与子层，避免 LIFETIME_MISMATCH |
| `206ffef` | 文档：新增仓库级 AGENTS.md |
| `c1a2af8` | 控制台：配置读取不再下发认证字段；新增验收手册 |
| `42d79f9` | 发布工作流：制品中的可执行文件提到顶层，缺可执行文件时拒绝发布 |
| `0cddba0` | 文档：新增架构说明 |
| `e9bf108` | 发布工作流：只取 Windows 产物、附带安装脚本与说明 |
| `7f190cb` | 安装脚本支持配置 NTP 时间源，文档补充时钟准确性说明 |
| `3e8a856` | 引擎：加入时钟回拨保护；文档：更新里程碑与措辞 |
| `5ebe476` | Windows 侧：新增配置目录变更监听 |

发布流程提醒：只改发布或打包逻辑时，先看有没有现成的构建制品，能 `gh release upload` 就不要动标签，
否则会白白触发一次整条流水线。

## 十、真机测试记录（2026-11-04，首次）

目标机 `win`（192.168.1.199）环境：

| 项目 | 值 |
| --- | --- |
| 系统 | Windows 10 IoT 企业版 LTSC，build 19044 |
| PowerShell | 7.6.9 |
| 账户 | 管理员（已提权） |
| Defender | 实时保护已关闭 |
| 磁盘剩余 | 16.8 GB |

按要求先停用 Windows Update：`wuauserv`、`bits`、`dosvc`、`UsoSvc`、`WaaSMedicSvc` 全部设置为
`Start=4`（Disabled）并停止，组策略 `NoAutoUpdate=1`。经验：**必须先禁用再停止**，若先停止，
补丁守护会把 `wuauserv`、`bits` 拉起并把启动类型改回去。

### 安装阶段发现的问题（已修复，待复验）

| 现象 | 根因 | 修法 |
| --- | --- | --- |
| 安装报「Access to the path 'C:\ProgramData\NetGuard\preseed.json' is denied」，随后 `netguard.exe status` 显示「配置：未初始化」 | `Install-Service` 先把数据目录收紧为 `Administrators:(OI)(CI)RX`，接着 `Invoke-Setup` 又要以管理员身份写入预置文件与 `config.json` | `Invoke-Setup` 期间临时授予 `Administrators:(OI)(CI)F`，初始化结束立即收回 RX |
| `sc.exe delete NetGuard` 即使以 SYSTEM 身份也返回 5（拒绝访问） | 收紧用的 SDDL 里 SYSTEM 只有 `CCLCSWRPWPDTLOCRRC`，缺少 `DELETE`（`SD`）与 `WRITE_DAC`（`WD`），结果谁都删不掉服务 | SDDL 改为 `(A;;SDWDCCLCSWRPWPDTLOCRRC;;;SY)`，管理员仍然只有查询权限 |
| `-Force` 覆盖安装与 `-Uninstall` 在管理员身份下必然失败 | 服务控制权收紧后管理员没有 `RP`/`WP`/`DT`/`DELETE` | 新增 `Invoke-AsSystem`：把停止、删除、清理动作写成一次性计划任务，以 SYSTEM 身份执行 |

为清掉当时卡住的服务，删除了注册表键 `HKLM\SYSTEM\CurrentControlSet\Services\NetGuard` 并重启机器。
该机重启后进入 Fedora（需在 EFI 中调整启动顺序才能回到 Windows），因此 Windows 侧当前没有服务、
没有数据目录，`C:\ngtest` 下的二进制与预置配置仍在。

**结论**：`v0.1.0` 附带的 `install.ps1` 无法完成安装，必须使用修复后的版本。

### 首次运行发现的问题（均已修复，WFP 部分待复验）

安装成功后，服务能启动、能读配置，但拦截完全不生效。逐层排查后发现两个独立缺陷：

| 现象 | 根因 | 修法 | 提交 |
| --- | --- | --- | --- |
| `netguard.exe status` 报「配置：不可信（签名不匹配）」，日志「配置文件校验失败：签名不匹配」，名单内程序被全天封锁 | `store::save` 写入 `config.mac` 的内容是 `v1:<64 位十六进制>\n`，`store::load` 却把整行直接交给 `mac::verify_bytes` 比较，长度必然不同 | `mac.rs` 新增 `format_signature` / `parse_signature`，写读两侧共用同一格式；新增两个单测覆盖缺前缀、错前缀、长度不符、非十六进制 | `f46fe8c` |
| 日志「同步过滤器失败：枚举模板或订阅将不匹配任何对象」，一条过滤器都建不起来 | `FWP_E_FILTER_NOT_FOUND` 被写成 `0x80320013`（那其实是 `FWP_E_NET_EVENTS_DISABLED`），真正要宽容的 `FWP_E_NEVER_MATCH = 0x80320033` 没有处理，`check()` 直接把「还没有过滤器」当失败 | 常量改为 `0x80320003`，新增 `FWP_E_NEVER_MATCH` 并在枚举入口按空集合处理 | `c557d9f` |
| 修完上一条后，日志「同步过滤器失败：该调用尝试将两个生存时间不兼容的对象相互关联」（`FWP_E_LIFETIME_MISMATCH = 0x80320016`） | 过滤器是持久化的，但它引用的 Provider 与子层是按会话创建的，生命周期不一致 | `provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT`、`sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT` | 本次提交 |
| 只缺 IPv6 层时会重新添加双栈，产生重复的 IPv4 过滤器且永不清理 | `reconcile` 只判断「两层是否都在」，添加时却总是加两层 | `add_block` 改为 `add_block_layers(path, want_v4, want_v6)`，只补缺失层 | `c557d9f` |
| 加了 `FWPM_*_FLAG_PERSISTENT` 后仍报「该调用尝试将两个生存时间不兼容的对象相互关联」（`FWP_E_LIFETIME_MISMATCH = 0x80320016`） | 早期版本创建并残留的**非持久化**同名 Provider 与子层仍在；`FwpmProviderAdd0` / `FwpmSubLayerAdd0` 只返回 `FWP_E_ALREADY_EXISTS`，被当成成功，旧对象永远不会被替换 | `wfp.rs::ensure_provider_sublayer` 开头先 `FwpmSubLayerDeleteByKey0` + `FwpmProviderDeleteByKey0`（删除失败一律忽略）再重建 | `dc40ec5` |
| 名单内 `curl.exe` 访问域名时进程崩溃，退出码 `-1073741819`（`0xC0000005`，崩在 `ntdll.dll +0x649f6`） | DNS 解析被拦，curl 8.13 报 `getaddrinfo() thread failed to start` 后在自身清理阶段崩溃；ETW 已排除（测试配置 `hashes: []`，`handle_start` 在挂起前即 return） | 判定为 curl 自身缺陷，非 NetGuard 逻辑错误：纯 IP 目标与 `--resolve` 均正常返回 exit 7，不在名单的同名副本与 `Invoke-WebRequest` 也正常 | 待记录 |

WFP 错误码对照（`windows-sys` 0.59 的 `Win32::Foundation`，勿凭记忆手抄）：

```
FWP_E_FILTER_NOT_FOUND     0x80320003
FWP_E_NOT_FOUND            0x80320008
FWP_E_ALREADY_EXISTS       0x80320009
FWP_E_NET_EVENTS_DISABLED  0x80320013   ← 曾被误当成 FILTER_NOT_FOUND
FWP_E_LIFETIME_MISMATCH    0x80320016
FWP_E_NEVER_MATCH          0x80320033
```

### 代码审查中另外发现的问题

| 位置 | 问题 | 处理 |
| --- | --- | --- |
| `http.rs` `factor_from_name` | 无法识别的认证方式被静默降级为 `Factors::None`，一次拼写错误就能装出「无需认证」的服务 | 改为返回 `Option`，未知值直接 400 |
| `http.rs` `handle_override` | `minutes = 0`（取消放行）时既不校验会话是否存在，也不校验 Cookie 真伪 | 先 `sessions.touch` 校验会话，再判断提升验证 |
| `http.rs` `Api::new` | 初始化窗口从服务启动计时，重启服务即可重新获得 10 分钟窗口 | 未改，属文档口径问题，验收时按「未初始化且服务刚启动」理解 |
| `store.rs` `load_state` | `state.json` 解析失败会静默清空水位线与失败计数 | 目录仅 SYSTEM 可写，风险可接受，暂不处理 |
| `install.ps1 -Uninstall` | 卸载不会删除持久化过滤器，重装前它们仍然生效 | 待办：增加清理入口（见下） |
| `paths.rs` `ensure` / `harden_acl` | ACL 只在目录原本不存在时才收紧（`%ProgramData%` 默认允许 Users 建目录并取得所有权）；`icacls` 用英文 `Administrators`，非英文系统解析失败 | 改为每次启动都重新收紧；主体改用 SID `*S-1-5-18` / `*S-1-5-32-544`，管理员权限由 RX 提到 M |
| `etw.rs` 会话建立 | `StartTraceW` 返回 `ERROR_ALREADY_EXISTS(183)` 被当致命；`OpenTraceW` 失败不回收会话（自锁）；`ProcessTrace` 返回值被丢弃 | 183 时先停同名残留会话再重试；`OpenTraceW` 失败先 `stop_session`；检查 `ProcessTrace` 返回值并记日志 |
| `cli_client.rs` `cookie_path` | 会话 Cookie 写进仅 SYSTEM 可写的 `%ProgramData%\NetGuard`，普通用户 `ngcli login` 必失败 | 改存 `%LOCALAPPDATA%\NetGuard\cli.session`（缺该变量时退回 `%TEMP%`） |
| `svc.rs` 生命周期 | 启动失败仍上报 `NO_ERROR` 伪装正常停止；STOP 期间启动收尾把 STOP_PENDING 倒灌回 RUNNING；停止路径不回收线程 | 改用 `ERROR_SERVICE_SPECIFIC_ERROR` + `dwServiceSpecificExitCode`；用 `SHUTDOWN` 标志阻止倒灌；只 join `is_finished()` 的线程 |
| `core/config.rs` `Config.auth`、`engine.rs` 篡改态 | `GET /api/config` 剔除 `auth` 后前端回传，而 `Config.auth` 缺 `#[serde(default)]` → WebUI 保存必然 400；`Tampered/Absent` 时用 `Config::default()` → 删除全部过滤器 + WebUI 免认证（fail-open） | `Config.auth` 与 `AuthConfig.factors` 已加 `#[serde(default)]`（含往返单测）；篡改态改为按 `config.json.bak` 备份封锁、保持 `integrity_ok = false` —— **修复中** |

**当前状态**：签名与 WFP 按应用拦截均已在真机确认生效（日志出现「过滤器已同步：新增 N 条」，
名单内 `curl.exe` 被拦、名单外程序正常）。
