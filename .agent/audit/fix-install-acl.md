# install.ps1 目录 ACL 与 paths.rs 对齐

日期：2026-11-04
范围：只改 `install.ps1`。未改动任何 Rust 源码（`crates/win/src/paths.rs` 的现有改动不是本次所为），
未改 `docs/` 与 `AGENTS.md`，未 commit / push。

## 一、对齐依据

`crates/win/src/paths.rs::harden_acl()` 每次服务启动都执行：

```
icacls <dir> /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)M"
```

三个要点：

1. **主体用 SID**（`*S-1-5-18` = SYSTEM，`*S-1-5-32-544` = Administrators）。英文账户名
   `Administrators` 在非英文 Windows 上会被 `icacls` 解析失败（找不到账户），直接导致服务起不来。
2. **每次启动重新收紧**：`%ProgramData%` 默认允许 Users 建目录并取得所有权，只在新建立时设一次
   等于留后门。
3. **Administrators 给 M（修改）而不是 RX（只读）**：管理员跑 `install.ps1` 初始化、
   `netguard.exe config import` 时需要写入；管理员本来就能读 `secret.key` 并用 DPAPI 解密，
   RX 不提供额外保护，只会把正常管理操作弄坏。

## 二、改动清单（改前 → 改后）

### 1. `Install-Service`：建立数据目录（现 159-162 行，原 160 行）

改前：

```powershell
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    & icacls $DataDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)RX' | Out-Null
```

改后：

```powershell
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    # 主体用 SID 而不是英文账户名，否则非英文 Windows 上 icacls 会因找不到账户而失败。
    # 与 crates/win/src/paths.rs 的 harden_acl 保持一致：SYSTEM 完全控制、Administrators 修改。
    & icacls $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)M' | Out-Null
```

- `SYSTEM` → `*S-1-5-18`，`Administrators` → `*S-1-5-32-544`
- 第二条授权 `RX` → `M`
- `/inheritance:r` 与 `/grant:r` 的用法保持不变（`/grant:r` 会替换该主体的既有 ACE）

### 2. `Lock-ServiceControl` 注释（现 180-181 行，原 178 行）

改前：

```powershell
    # 仅授予 SYSTEM 启停与配置权限；Administrators 保留读取，避免随手停止或删除。
```

改后：

```powershell
    # 仅授予 SYSTEM 启停与配置权限；Administrators 在服务控制层面只保留查询（不含启停与删除），
    # 避免随手停止或删除。（与 Install-Service 里数据目录 ACL 的 M 权限是两回事。）
```

- 只改注释，`sc.exe sdset` 的 SDDL 字符串**一字未动**（任务要求）。
- 澄清该注释说的是服务控制权限，不是目录 ACL：SDDL 中 `BA` 的
  `CCLCSWLOCRRC` 只含 QUERY_CONFIG / QUERY_STATUS / ENUMERATE_DEPENDENTS /
  INTERROGATE / READ_CONTROL，确无 START/STOP，故「只保留查询」准确。

### 3. `Invoke-Setup`：临时提权（现 204-207 行，原 201-203 行）

改前：

```powershell
    # 数据目录此前已被收紧为 Administrators 只读，而初始化要以管理员身份写入
    # config.json / config.mac / secret.key，因此在这一步临时放开，结束后收回。
    & icacls $DataDir /grant:r 'Administrators:(OI)(CI)F' | Out-Null
```

改后：

```powershell
    # 数据目录默认已收紧为 SYSTEM 完全控制、Administrators 修改（M），而初始化要以管理员
    # 身份写入 config.json / config.mac / secret.key，部分写入路径还需要完全控制，因此这里
    # 临时提高到 F，结束后收回 M（不是 RX）。
    & icacls $DataDir /grant:r '*S-1-5-32-544:(OI)(CI)F' | Out-Null
```

- 临时提权为 F 的逻辑**保留**（初始化要落 `preseed.json`、`config.json`、`config.mac`、`secret.key`，
  并交给 `netguard.exe setup` 写；F 保证不受后续 ACL 收紧时序影响）。
- 只把账户名换成 SID，步骤语义不变。

### 4. `Invoke-Setup`：收尾收回（现 245 行，原 241 行）

改前：

```powershell
    & icacls $DataDir /grant:r 'Administrators:(OI)(CI)RX' | Out-Null
```

改后：

```powershell
    & icacls $DataDir /grant:r '*S-1-5-32-544:(OI)(CI)M' | Out-Null
```

- 收回目标由 `RX` 改为 `M`，与 `paths.rs::harden_acl()` 的稳态一致；不再出现「只读」说法。
- 仍用 `/grant:r`（替换该主体的 ACE，而不是追加）。

## 三、为什么保留临时提权（而不是直接删掉）

- 默认 M 已能覆盖大多数写入，但初始化阶段会先写 `preseed.json` 再交给子进程；`/grant:r` 到 F
  使这段窗口内的行为与旧版一致，减少回归面。
- 结束时**一定**收回到 M，避免安装完留下 F（那会削弱「管理员不能悄悄篡改配置/密钥」的意图，
  尽管 F 只在管理员会话内有效）。

## 四、自查清单

对 `grep -n "icacls" install.ps1` 逐行核对（结果 4 处 = 3 个调用 + 1 行注释内的表述）：

| 位置 | 内容 | 结论 |
| --- | --- | --- |
| 160-161 | 新增注释（SID 理由 + 与 paths.rs 对齐） | OK |
| 162 | `/inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)M'` | 与 Rust 侧逐字一致 |
| 207 | `/grant:r '*S-1-5-32-544:(OI)(CI)F'` | 临时提权，SID 形式 |
| 245 | `/grant:r '*S-1-5-32-544:(OI)(CI)M'` | 收回 M，非 RX，非英文名 |

- [x] 无残留 `'SYSTEM:(OI)(CI)…'` / `'Administrators:(OI)(CI)…'` 形式的授权写法
      （`grep -n "Administrators\|S-1-5\|RX\|只读" install.ps1` 仅剩注释中的中文说明与 3 个 SID 调用）。
- [x] 无残留 `RX` 权限；无「Administrators 只读」这类过时注释。
- [x] `sc.exe sdset` 的 SDDL 原串未改（`D:(A;;SDWDCCLCSWRPWPDTLOCRRC;;;SY)…`），
      也不应改成 SID 以外的形式——SDDL 里的 `SY`/`BA`/`IU`/`SU` 是 SDDL 别名，属另一套语法。
- [x] PowerShell 静态语法：新增行均为单引号字面量（`'*S-1-5-18:(OI)(CI)F'` 内无 `'`，无需转义），
      仍以 `& icacls …` 调用运算符起头、`| Out-Null` 收尾，括号成对；注释行以 `#` 起头，不影响解析。
- [x] 未触碰 `Invoke-AsSystem` 中的 `schtasks /ru SYSTEM`（那是计划任务账户参数，不是 ACL 主体）。
- [x] 未改任何 Rust 文件、未改 docs/AGENTS.md、未 commit/push。
- 说明：本机不允许编译或运行 PowerShell，以上为静态核对；真机行为待 `win` 上 `wsh -f win .agent/win/redeploy.ps1` 验证。

## 五、残余风险 / 后续建议（不在本次范围）

1. `install.ps1` 只收紧一次，`paths.rs` 每次启动都收紧——两者目前不会冲突（都是同一终态），
   但若将来 Rust 侧改权限，`install.ps1` 需跟进，建议在 `docs/PROGRESS.md` 留一行（另有人负责 docs）。
2. `Invoke-Setup` 若在 `Start-Process` 之后抛异常（如 `-RecoveryOut` 路径非法由程序侧报错），
   收尾的 `icacls` 仍在 `if ($process.ExitCode -ne 0)` 之前执行，不会被跳过；但若
   `Remove-Item $preseedPath` 抛终止错误，收尾会被跳过。可考虑 `try/finally`（未改，避免扩大改动面）。
