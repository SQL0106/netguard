# 进度记录

本文件用于在上下文受限或会话中断时恢复工作状态。设计细节见 [DESIGN.md](DESIGN.md)，
面向使用者的说明见 [README.md](../README.md)。

## 一、当前状态（2026-11-04）

仓库地址：`https://github.com/SQL0106/netguard`（公开）。

**硬约束：本机不做任何编译。** 全部构建、检查与测试只在 GitHub Actions 执行
（`ubuntu-latest` 跑 core 单元测试，`windows-latest` 产出可执行文件）。本机仅编辑源码与文档。

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
| `GET /api/config` | 读取配置（不含凭据明文） |
| `PUT /api/config` | 保存配置，需提升验证 |
| `POST /api/override` | 临时放行，`minutes` 为 0 表示取消 |
| `POST /api/totp` | 重新生成 TOTP 密钥或恢复码 |
| `GET /api/log` | 读取日志尾部若干行 |

`ngcli` 为同一接口的命令行客户端，会话信息保存于数据目录。

## 四、安全要点（与 DESIGN §6 一致）

- 配置写入 `C:\ProgramData\NetGuard\config.json`，签名保存在 `config.mac`，
  签名对象是解析后按结构体声明顺序重新序列化的规范字节串，因此缩进与键序不影响校验。
- 签名不匹配或配置缺失一律 fail-closed：沿用内存中最后一次有效配置，若内存中无有效配置，
  则名单内程序按全天封锁处理，并写入日志、在页面顶部显示告警。
- 目录 ACL 为 SYSTEM 完全控制、Administrators 只读，普通用户无权写入。
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
