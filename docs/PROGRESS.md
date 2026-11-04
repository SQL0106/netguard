# 进度记录

本文件由开发过程维护，用于在上下文受限时恢复工作状态。设计细节见 [DESIGN.md](DESIGN.md)。

## 当前状态（2026-11-04）

仓库已公开：`https://github.com/SQL0106/netguard`。所有编译与测试只在 GitHub Actions 执行，
本机不进行任何 `cargo` 构建。

| 模块 | 文件 | 状态 |
| --- | --- | --- |
| 纯逻辑：配置、排程、TOTP、口令、签名、哈希 | `crates/core/src/*.rs` | 完成，单元测试通过 |
| 无人值守初始化 | `crates/core/src/bootstrap.rs` | 完成，单元测试通过 |
| 路径与 ACL | `crates/win/src/paths.rs` | 完成 |
| DPAPI | `crates/win/src/dpapi.rs` | 完成 |
| 日志 | `crates/win/src/log.rs` | 完成 |
| 配置存储与签名校验 | `crates/win/src/store.rs` | 完成 |
| 等待器（边界唤醒，非轮询） | `crates/win/src/ticker.rs` | 完成 |
| WFP 过滤器封装与增量协调 | `crates/win/src/wfp.rs` | 已写，等待 CI 验证 |
| 运行时工作线程与排程调度 | `crates/win/src/engine.rs` | 已写，等待 CI 验证 |
| 会话与提升验证 | `crates/win/src/session.rs` | 完成 |
| 随机数工具 | `crates/win/src/random.rs` | 完成 |
| HTTP 接口 | `crates/win/src/http.rs` | 完成，等待 CI 验证 |
| WebUI 静态资源 | `web/index.html`、`web/app.js`、`web/style.css` | 完成 |
| 服务宿主 | `crates/win/src/svc.rs` | 未开始 |
| ETW 进程哈希守护 | `crates/win/src/etw.rs` | 未开始 |
| 安装脚本 | `install.ps1` | 未开始 |

## 控制台接口一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/`、`/app.js`、`/style.css` | 静态页面（编译期内嵌） |
| POST | `/api/setup` | 首次初始化，仅在未初始化且安装后十分钟内开放，返回 otpauth 链接与恢复码 |
| POST | `/api/login` | 按已启用因子登录，口令、TOTP、恢复码三者择一（恢复码仅在有启用认证时有效） |
| POST | `/api/logout` | 清除会话 |
| GET | `/api/state` | 当前状态、拦截清单、下一边界 |
| GET | `/api/config` | 读取配置 |
| PUT | `/api/config` | 保存配置（需提升验证） |
| POST | `/api/totp` | 重新生成 TOTP 密钥与恢复码（需提升验证） |
| POST | `/api/override` | 临时放行指定分钟数，0 表示取消 |
| GET | `/api/log` | 读取日志尾部若干行 |

会话 Cookie 为 `ng_session`，15 分钟空闲过期；敏感操作要求 5 分钟内的提升验证。

## 已修正的历史缺陷（`crates/win/src/http.rs`）

1. `verify()` 中口令取值一行被工具链的凭据脱敏改写，磁盘内容不正确，需要重写该行；
   同时 `check_login` 要求 `&mut self`，当前对不可变配置调用，需要先克隆为可变副本。
2. `AppRule`/`Config` 在 `handle_config_put` 中的认证字段合并逻辑引用了不存在的变量，需要按
   「未提供则沿用旧值」重写。
3. `handle_setup` 同时调用了 `store().save()` 与 `replace_config()`，重复写盘，只保留后者。
4. `SetupBody` 使用 `#[serde(flatten)]` 与 `deny_unknown_fields` 冲突，应直接解析 `PreSeed`。
5. `record_failure`/`clear_failures` 使用 `RuntimeState`，而口令失败计数位于
   `AuthConfig`，须改为通过 `AuthConfig::register_failure` 后随配置保存。
6. 文件末尾的 `_unused`、`write_all`、`wait_forever` 属于占位代码，应删除。
7. 以上七项均已在重写时修正：认证改动经 `replace_config` 落盘、配置合并按「未提供则沿用旧值」处理、初始化只写一次、请求体直接解析结构化字段、模块已登记。

## 凭据脱敏工具的影响

`@kkchengg/opencode-redact` 会把形如 `password: 值`、`password = 值` 的片段在工具输出中替换为
`[REDACTED:credential:…]`。已确认：**磁盘内容本身也可能被改写**（写入前钩子会处理待写入文本）。
因此源码中不要出现「`password` 紧跟 `=` 或 `:` 再跟值」的写法，改用中间变量，例如：

```rust
let supplied = body.password.as_deref();
```

字段声明 `password: Option<String>` 在磁盘上会被截短为 `password: [REDACTED…],`，需用
`awk 'NR==n{print length($0)}'` 核对行长度，不要依赖视觉核对。

## 环境限制

- 本机 `/home` 剩余空间约 2.4 GB，根分区剩余约 66 GB。
- 禁止在妹妹的 Windows（`sister`，192.168.1.130）上安装或测试；验证目标仅限 `win`
  （192.168.1.199，同一台双系统机的 Windows 侧）。
- 推送须带 `GIT_SSH_COMMAND="ssh -o BatchMode=yes -o IdentityAgent=/home/SQL916/.ssh/agent.sock"`。

## 里程碑

- M0 核心逻辑与单元测试：已完成。
- M1 WFP 协调与服务安装：进行中（`wfp.rs`、`engine.rs` 待 CI 验证）。
- M2 WebUI 与命令行：进行中（控制台与静态页面已完成，待 CI 验证）。
- M3 哈希守护与看门狗：未开始。
- M4 端到端验收：未开始。
