# 文档同步：PROGRESS.md / AGENTS.md（真机 WFP 生效 + 审查修复落地）

> 硬约束：只改 `docs/PROGRESS.md` 与 `AGENTS.md`；不动源码 / `install.ps1`；不 commit；
> 不写 /tmp；本机不编译。
> 依据：`git log`（HEAD `dc40ec5`）、`git diff --stat`、`.agent/audit/win-runtime.md`、
> `.agent/audit/core-web.md`、`.agent/audit/fix-*.md`。

## 0. 规格抄录

1. PROGRESS 结尾过时句 → 改「签名与 WFP 按应用拦截均已在真机确认生效」。
2. 真机问题表追加 2 行：LIFETIME_MISMATCH 旧非持久化对象残留（`dc40ec5`）；curl 8.13 域名访问崩溃（自身缺陷，待记录）。
3. 代码审查表追加本轮修复：paths / etw / cli_client / svc / config `auth`；engine 篡改态 fail-open 标「修复中」。
4. 「九、最近提交」追加 `dc40ec5`、`206ffef`。
5. 「一、当前状态」补真机验收进度（已验证 / 待验）。
6. AGENTS.md：坑表追加 LIFETIME_MISMATCH 残留行；「五、真机验收」补 curl 例外；RX 措辞改 M。

## 1. TODO

- [x] 核对 HEAD 与 git diff --stat，确认哪些修复已落地
- [x] PROGRESS：结尾状态句
- [x] PROGRESS：真机问题表 +2 行
- [x] PROGRESS：审查表 +5 行（engine 标修复中）
- [x] PROGRESS：最近提交 +2 行
- [x] PROGRESS：当前状态补验收进度
- [x] PROGRESS：§4 ACL 表述改 M（与 paths.rs/install.ps1 一致）
- [x] AGENTS：坑表 +1 行；真机验收 +curl 例外
- [x] 自检 `git diff --stat docs/PROGRESS.md AGENTS.md`

## 2. 改动明细

### docs/PROGRESS.md
1. **§一 当前状态**：删除「唯一未完成的是 Windows 真机验收…」整段，替换为「真机验收进行中」+
   已验证四点（过滤器已同步：新增 1 条 / `curl.exe` 纯 IP exit 7 / 非名单程序与 ping 正常 /
   不全局断网）+ 待验九项（热点共存、时段边界翻转、睡眠唤醒、时钟回拨、登录锁定、TOTP 重放、
   篡改 fail-closed、配置自动重载、ngcli 全流程）。
2. **§四 安全要点**：「Administrators 只读」→「SYSTEM 完全控制、Administrators 可修改（M）」。
3. **§九 最近提交**：表首插入 `dc40ec5`、`206ffef` 两行（按 `git log` 实际标题）。
4. **§十 真机问题表**：追加 2 行（LIFETIME_MISMATCH 残留 → `dc40ec5`；curl.exe 0xC0000005 → 提交「待记录」）。
5. **§十 代码审查表**：追加 5 行：
   - `paths.rs`：每次都收紧 ACL（防 Users 抢建目录）+ icacls 改 SID + Administrators RX→M
   - `etw.rs`：183 先停残留会话再重启；`OpenTraceW` 失败先 `stop_session`；`ProcessTrace` 返回值检查
   - `cli_client.rs`：cookie 改 `%LOCALAPPDATA%\NetGuard\cli.session`（退回 `%TEMP%`）
   - `svc.rs`：`ERROR_SERVICE_SPECIFIC_ERROR` + `dwServiceSpecificExitCode`；SHUTDOWN 防 STOP 倒灌；
     只 join `is_finished()` 线程
   - `core/config.rs`：`Config.auth` / `AuthConfig.factors` 加 `#[serde(default)]`，WebUI 往返不再 400
     （已落地）；`engine.rs` Tampered/Absent 仍用 `Config::default()` → fail-open，**修复中**
6. **结尾**：当前状态句改为「签名与 WFP 按应用拦截均已在真机确认生效（日志出现『过滤器已同步：
   新增 N 条』，名单内 `curl.exe` 被拦、名单外程序正常）。」

### AGENTS.md
1. **§六 坑表**：追加 LIFETIME_MISMATCH 残留行（先 `FwpmSubLayerDeleteByKey0` + `FwpmProviderDeleteByKey0` 再重建，`dc40ec5`）。
2. **§五 真机验收**：补 curl 8.13 已知例外（`0xC0000005`，用纯 IP exit 7 或 `curlcopy.exe` 对照）。
3. RX 措辞：全文检索无「Administrators 只读（RX）」字样，无需改。

## 3. 结论

已按规格完成，自检 `git diff --stat docs/PROGRESS.md AGENTS.md` = 2 files changed, 21 insertions(+),
6 deletions(-)。未改任何源码 / `install.ps1`，未 commit。

## 4. 未做 / 存疑

- `install.ps1` 已把数据目录 ACL 改为 SID + M，但 **PROGRESS §十 安装阶段历史表**仍写
  「Administrators:(OI)(CI)RX」——那是当时现象的历史记录，未改写；当前口径以 §四 为准。
- `engine.rs`/`store.rs`/`http.rs` 的 fail-closed（`config.json.bak` 备份封锁）在
  `.agent/audit/fix-fatal.md` 标记已完成，但 `git status` 显示这三个文件无改动 → 以工作区为准，
  文档写「修复中」，不宣称已落地。
- 未在真机复验文档所述结论；文档只转录已有观测与审查结论。
