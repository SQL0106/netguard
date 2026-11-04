# NetGuard 仓库说明（给后续的 AI 会话）

本文件只写「进仓库必须知道的事实」。面向用户的说明在 `README.md`，设计与取舍在
`docs/DESIGN.md`，架构与代码地图在 `docs/ARCHITECTURE.md`，进度与真机问题在
`docs/PROGRESS.md`，验收手册在 `docs/ACCEPTANCE.md`。

## 一、这是什么

Windows 上的常驻服务：按「指定应用 + 指定时段」把出站连接挡在 WFP 的
`FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` 上，用持久化过滤器防绕过，用事件驱动（条件变量单次等待）
在时段边界切换；WebUI + `ngcli` 管理，支持 TOTP / 口令 / 双因子；不改路由与转发，因此移动热点不受影响。

## 二、硬约束（违反即返工）

1. **本机不做任何编译**：不跑 `cargo build/check/test/clippy/fmt`。所有构建与测试只在
   GitHub Actions（`.github/workflows/ci.yml`：`core` 在 ubuntu-latest 跑单测，`windows`
   在 windows-latest 出 `netguard.exe` / `ngcli.exe`）。本机只编辑源码与文档。
2. **绝不在 sister（192.168.1.130）上安装或测试**。真机只允许 `win`（192.168.1.199）。
3. **绝不对 `win` 下 `Restart-Computer`**：那台是双系统机，重启默认进 Fedora，得改 EFI 才能回来。
   需要重启时先问用户。
4. **源码里禁止出现 `password` / `secret` 紧跟 `=` 或 `:` 再跟字面值**：编辑链路的脱敏插件会就地
   改写导致文件损坏。统一用 `pw` 字段名，或把字面量拼起来；校验用长度/布尔断言，不要肉眼比对。
5. 重要文件不写 `/tmp`，中间产物放仓库内 `.agent/`（`win/` 与 `audit/` 下的构建产物已被 gitignore）。

## 三、目录

```
crates/core/   与平台无关：config / schedule / auth / totp / mac / guard / bootstrap（含单测）
crates/win/    Windows 实现：paths / dpapi / log / store / ticker / wfp / engine /
               session / random / http / svc / etw / watch / cli / cli_client
web/           WebUI（index.html / app.js / style.css，编译期内嵌，无前端构建）
install.ps1    安装、无人值守初始化、NTP、卸载
docs/          DESIGN / ARCHITECTURE / PROGRESS / ACCEPTANCE
.agent/win/    真机辅助脚本（install-all / redeploy / recon / sysrun / stop-wu…）与下载的制品
.agent/audit/  只读审查结论
```

运行时数据固定在 `C:\ProgramData\NetGuard`：`config.json`、`config.mac`、`state.json`、
`secret.key`（DPAPI，机器范围）、`netguard.log`。服务监听 `127.0.0.1:47811`。

## 四、改完怎么验证

```sh
# 1) 提交并推送（会触发 CI）
git -c user.name=SQL0106 -c user.email=liuqiansheng090106@gmail.com commit -m "…"
GIT_SSH_COMMAND="ssh -o BatchMode=yes -o IdentityAgent=$HOME/.ssh/agent.sock" git push
# 2) 看流水线
gh run list --limit 3
# 3) 取产物（制品内路径是 target/release/*.exe）
gh run download <run-id> -n windows-release -D .agent/win/distN
# 4) 上机（只允许 win）
scp -q .agent/win/distN/target/release/*.exe "win:C:/ngtest/"
wsh -f win .agent/win/redeploy.ps1        # install.ps1 -Force，不重复初始化
```

`wsh` 用法是 `wsh -f <host> <本地脚本.ps1>`（**host 在前**），`wsh <host> '<代码>'` 直接跑单行。
局域网单条 `ssh/wsh` 超过 500ms 先怀疑用法不对（裸 ssh 没走 keeper）。

**只改发布/打包逻辑时**，先看有没有现成制品：能 `gh release upload` 就不要重打 tag，
否则会白白触发整条流水线。

## 五、真机验收

按 `docs/ACCEPTANCE.md` 十二节逐条执行，结果回填 `docs/PROGRESS.md`。
最关键的三个观测点：日志出现「过滤器已同步」而不是「同步过滤器失败」；
`C:\Windows\System32\curl.exe` 在拦截时段访问失败而 `Invoke-WebRequest` 正常；
手机连本机热点时上网不受影响。

已知例外：名单内 `curl.exe` 访问**域名**时会因 DNS 被拦而自身崩溃（退出码 `0xC0000005`），
这是 curl 8.13 的缺陷。判断拦截是否生效请用纯 IP 目标（应为 exit 7）或 `curlcopy.exe` 对照。

## 六、已经踩过的坑（改相关代码前必读）

| 症状 | 真正原因 |
| --- | --- |
| 配置永远「签名不匹配」 | `config.mac` 存的是 `v1:<hex>\n`，`load` 未剥离前缀 → 已改 `mac::parse_signature` |
| 首次同步过滤器失败，拦截完全无效 | `FWP_E_FILTER_NOT_FOUND` 被写成 `0x80320013`（那是 `NET_EVENTS_DISABLED`）；真机空集时返回的是 `FWP_E_NEVER_MATCH (0x80320033)` |
| `FWP_E_LIFETIME_MISMATCH (0x80320016)` | 持久化过滤器只能引用持久化的 Provider 与子层，两者都要 `..._FLAG_PERSISTENT` |
| 安装时 `Access denied` 写预置 | 先收紧目录 ACL 再写文件；`Invoke-Setup` 必须临时放开 `Administrators:(F)` |
| 服务删不掉（`sc delete` 返回 5） | SDDL 里 `SY` 缺 `SD`/`WD`；且收紧后只能经 `Invoke-AsSystem`（SYSTEM 计划任务）删除 |
| 只缺单层时过滤器越堆越多 | `reconcile` 要按 v4/v6 分别补齐（`add_block_layers`），不要整对重加 |
| `FWP_E_LIFETIME_MISMATCH` 加完持久化标志仍报 | 早期版本的非持久化同名 Provider/子层残留，「已存在」被当成功 → 必须先 `FwpmSubLayerDeleteByKey0` + `FwpmProviderDeleteByKey0` 再重建（`dc40ec5`） |

WFP 侧权威常量在 `/opt/winsys/windows-sys-0.59.0/src/Windows/Win32/Foundation/mod.rs`
（`FWP_E_*`）与 `.../NetworkManagement/WindowsFilteringPlatform/mod.rs`（`FWPM_*_FLAG_*`），
不要凭记忆手抄数值。

## 七、提交约定

- 提交信息用中文、短句、说清「改了什么」；同类修复合成一条提交。
- 只提交相关文件，绝不提交密钥、口令、下载的制品。
- 文档与代码同步：任何行为变更都要在 `docs/PROGRESS.md` 留一行，安全相关的写进 `docs/DESIGN.md`。
