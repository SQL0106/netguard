# 验收手册

本文件供在真实 Windows 上逐条核对实现是否符合设计。所有命令在**管理员 PowerShell 7** 中执行，
目标机为 `win`（192.168.1.199）。每次验收前先把 `netguard.exe`、`ngcli.exe`、`install.ps1` 放在同一目录。

记录方式：每条填写「实测结果」与「结论」，失败项附日志片段（`C:\ProgramData\NetGuard\netguard.log`）。

前置条件：`sc.exe query NetGuard` 应返回 1060（服务不存在）；若返回已有服务，先卸载干净再装。
服务控制权限收紧后管理员无法直接停止或删除，`install.ps1` 会把停止、删除、清理动作交给一次性的
SYSTEM 计划任务执行，卸载同样走 `install.ps1 -Uninstall [-Purge]`，不要手工 `sc delete`。

## 零、安装

```powershell
.\install.ps1 -Silent -Config .\preseed.json -RecoveryOut .\codes.txt
sc.exe query NetGuard
netguard.exe status
```

期望：`sc.exe query` 显示 `STATE : 4 RUNNING`；`status` 输出「配置：有效」「总开关：启用」，
并列出受控程序与拦截散列。`codes.txt` 内含恢复码，验收结束后立即销毁。

## 一、静态检查

| 项目 | 命令 | 期望 |
| --- | --- | --- |
| 服务账户 | `sc.exe qc NetGuard` | `SERVICE_START_NAME : LocalSystem`，`BINARY_PATH_NAME` 指向安装目录 |
| 控制权限 | `sc.exe sdshow NetGuard` | 只有 `SY` 持有 `CCLCSWRPWPDTLOCRRC`，`BA` 仅 `CCLCSWLOCRRC` |
| 数据目录 ACL | `icacls "C:\ProgramData\NetGuard"` | `SYSTEM:(OI)(CI)(F)`，`Administrators:(OI)(CI)(RX)`，无 `Users` 写入项 |
| 目录内容 | `Get-ChildItem "C:\ProgramData\NetGuard"` | 含 `config.json`、`config.mac`、`state.json`、`secret.key`、`netguard.log` |
| 过滤器存在 | `netsh wfp show filters file=$env:TEMP\wfp.xml; Select-String -Path $env:TEMP\wfp.xml -Pattern 'NetGuard' \| Select-Object -First 5` | 命中 NetGuard 的 Provider / Sublayer，过滤器层次为 `FWPM_LAYER_ALE_AUTH_CONNECT_V4`（与 V6） |

## 二、只拦指定应用

预置配置里放一个便于观察的程序，例如 `C:\Windows\System32\curl.exe`，时间窗覆盖当前时刻。

```powershell
curl.exe -s -m 5 https://example.com -o NUL; $LASTEXITCODE
Invoke-WebRequest -Uri https://example.com -UseBasicParsing -TimeoutSec 5 | Select-Object StatusCode
```

期望：`curl.exe` 连接失败（退出码非 0、耗时约等于超时），`Invoke-WebRequest`（`pwsh.exe`）返回 200。
判定依据：拦截按发起连接的可执行文件生效，不是全局断网。

## 三、持久化与不可停止

```powershell
Stop-Service NetGuard          # 期望：拒绝访问
sc.exe stop NetGuard           # 期望：拒绝访问（[SC] OpenService 失败 5）
```

绕过检查（模拟攻击者取得 SYSTEM）：用 `psexec -s` 或计划任务以 SYSTEM 停止服务后，`curl.exe` 仍应失败，
因为过滤器带 `FWPM_FILTER_FLAG_PERSISTENT`；随后 `Start-Service NetGuard` 恢复正常。

## 四、不影响移动热点

```powershell
# 开启移动热点，另一台设备（手机）连接该热点
# 在手机上访问任意网站
# 在被拦程序仍处拦截时段的情况下，手机上网应完全正常
```

同时确认本机被拦程序依旧失败：热点共享走 IP 转发层，不进入 ALE 授权层，因此两者不应互相干扰。
此项是本项目的核心承诺，必须实测，不可仅凭设计推断。

## 五、时段边界

把应用时间窗设为「从现在起 2 分钟后开始、持续 5 分钟」：

1. 到点前 30 秒、到点后 30 秒各测一次 `curl.exe`。
2. 观察 WebUI 状态卡片：`当前状态` 应在「正常」与「拦截 N 项」之间翻转，`下次切换` 显示倒计时。
3. `netguard.log` 应出现状态切换记录。

期望：切换发生在分钟边界上，误差不超过一个等待周期（无轮询，由 `next_change` 单次唤醒驱动）。

## 六、睡眠与唤醒

在拦截时段内让系统睡眠 3 分钟（跨越一次边界），唤醒后 5 秒内核对状态与 `curl.exe` 行为。

期望：唤醒事件触发重算，状态与真实时间一致；不需要手动重启服务。

## 七、时钟回拨不解锁

```powershell
Set-Date (Get-Date).AddMinutes(-30)
curl.exe -s -m 5 https://example.com -o NUL   # 期望：失败
Set-Date (Get-Date).AddMinutes(30)
```

期望：回拨超过 120 秒即视为可疑，名单内程序按**全天封锁**处理并写入日志（「检测到系统时间回拨」）；
时间恢复后自动回到按时段判定。判定依据：拨表不能成为解锁手段。

## 八、登录失败锁定

在 WebUI 连续提交 5 次错误口令。

期望：第 6 次起返回「认证已锁定，请在 N 秒后重试」；`Restart-Service NetGuard` 后仍然锁定
（计数持久化在配置中，重启不清零）。锁定到期后可正常登录。

## 九、动态口令不可重放

```powershell
$code = "当前认证器上的 6 位数字"
# 先用该码登录成功
# 不等窗口刷新，立刻用同一个码再登录一次
```

期望：第二次返回 401，且日志记录「动态口令已使用」。判定依据：`last_totp_counter` 单调递增，
同一时间步的码只能成功一次。

## 十、配置篡改（fail-closed）

以 SYSTEM 身份改动配置文件一个字节：

```powershell
$f = "C:\ProgramData\NetGuard\config.json"
$bytes = [IO.File]::ReadAllBytes($f)
$bytes[10] = $bytes[10] -bxor 0xFF
[IO.File]::WriteAllBytes($f, $bytes)
Start-Sleep -Seconds 2
netguard.exe status        # 期望：配置：不可信（…），退出码 2
curl.exe -s -m 5 https://example.com -o NUL   # 期望：失败
```

期望：目录监视在 1 秒内发现变化，WebUI 顶部显示完整性告警，名单内程序一律被拦。
删除 `config.json` 同样按篡改处理。恢复方式：用 `netguard.exe config import --file <备份>` 重新签名写入。

## 十一、外部写入合法配置后自动重载

以 SYSTEM 用 `netguard.exe config import --file new.json` 写入一份**签名正确**的新配置，
把时间窗改成当前不在拦截时段。

期望：无需重启服务，1 秒内 WebUI 状态与 `curl.exe` 行为同步更新；日志出现重载记录。

## 十二、命令行客户端

```powershell
ngcli status
ngcli config
ngcli override --minutes 5
```

期望：`ngcli` 复用本地控制台接口，需要认证时提示输入口令或动态口令；
`override` 成功后 WebUI 显示「临时放行至 …」，到期自动恢复拦截。

## 验收汇总

| 项 | 结果 | 备注 |
| --- | --- | --- |
| 一、静态检查 | | |
| 二、只拦指定应用 | | |
| 三、持久化与不可停止 | | |
| 四、不影响移动热点 | | |
| 五、时段边界 | | |
| 六、睡眠与唤醒 | | |
| 七、时钟回拨 | | |
| 八、登录失败锁定 | | |
| 九、动态口令重放 | | |
| 十、配置篡改 | | |
| 十一、自动重载 | | |
| 十二、命令行客户端 | | |
