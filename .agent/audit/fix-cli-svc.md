# 修复记录：cli_client.rs 会话 Cookie 路径 + svc.rs 生命周期

> 执行者：修复子代理。**未编译**（本机禁 `cargo`），结论全部来自逐行静态核对 +
> 本机离线 `windows-sys 0.59.0` 源码（`/opt/winsys/windows-sys-0.59.0/`）。
> 只改了 `crates/win/src/cli_client.rs` 与 `crates/win/src/svc.rs`，未动其它源码/文档，未 commit。
> 依据：`.agent/audit/win-runtime.md` §2（svc.rs 高 3 条）、§7（cli_client.rs 高 1 条）。

---

## 一、`crates/win/src/cli_client.rs` —— Cookie 落到用户目录

### 位置
- `cookie_path()`：24→**24-49**（重写）
- 新增 `save_cookie()`：**51-66**
- 调用点：`read_cookie()` 读 **69**、`login` 保存 **206**、`logout` 删除 **215**

### 改前
```rust
fn cookie_path() -> std::path::PathBuf {
    crate::paths::Paths::new().file("cli.session")   // C:\ProgramData\NetGuard\cli.session
}
```
`paths.rs` 把 `C:\ProgramData\NetGuard` 收紧成 `SYSTEM:(F)` / `Administrators:(RX)`，
普通用户写进去必然 Access Denied：HTTP 登录其实已成功，cookie 却写不下 → 之后所有
`status/config/log` 退化成未认证请求。等于「CLI 只有管理员能用」。

### 改后
1. `cookie_path()` 按序回退，全部为**每用户**位置：
   - `%LOCALAPPDATA%\NetGuard\cli.session`（`LOCALAPPDATA` 存在且非空）
   - `%TEMP%\NetGuard\cli.session`（同上）
   - `current_dir()\cli.session`；`current_dir()` 都失败时退化为相对路径 `cli.session`
   用 `std::env::var_os` 取环境变量（UTF-16/非 UTF-8 路径安全，避免 `var()` 的非法 UTF-8 失败）。
2. 新增 `save_cookie(pair) -> io::Result<PathBuf>`：先 `create_dir_all(parent)`
   （`ErrorKind::AlreadyExists` 视为成功，并发下 `create_dir_all` 可能报这个），
   再 `std::fs::write`，返回最终路径供打印。父目录为空（相对路径退化分支）时跳过建目录。
3. `login` 分支从「内联 create_dir_all + write」改为 `let path = save_cookie(&pair)?;`，
   `logout` / `read_cookie` 本来就调用 `cookie_path()`，因此三处**全部走同一函数**（已 grep 确认，
   文件里再无字面量 `cli.session` 路径拼接）。

### 为什么
- 用户目录天然只有本用户可读写，**不需要额外设 ACL**（注释已写明）。
- 不引入 `Paths` 依赖，`ngcli` 不再触碰 `C:\ProgramData`，顺带绕开该目录 ACL 抢占问题的
  用户态影响面（服务端路径问题不属本次范围）。

### 未做（明确记录）
- 未改成 `CreateFileW(CREATE_NEW|FILE_FLAG_OPEN_REPARSE_POINT)` 独占创建（审计 §7 中风险项）：
  该风险的主要前提是「管理员身份 + 可抢占的公共目录」，现在路径已挪到用户私有目录，
  优先级下降，且改动量会显著变大。留给后续单独提交。

---

## 二、`crates/win/src/svc.rs` —— 三项生命周期缺陷

### 2.1 启动失败不再伪装成「正常停止」

| 项 | 内容 |
|---|---|
| 位置 | `report()` **79-112**（原 57-77）、`service_main` 失败分支 **206-214**（原 155-161）、常量 **43-47** |
| 改前 | `report(state, accepted, wait_hint)` 里 `dwWin32ExitCode = NO_ERROR`、`dwServiceSpecificExitCode` 恒 0；启动失败只 `report(SERVICE_STOPPED, 0, 0)` |
| 改后 | `report(..., specific_exit_code: u32)`：非 0 时 `dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR`、`dwServiceSpecificExitCode = specific_exit_code`，为 0 时仍 `NO_ERROR`/0。失败分支 `report(SERVICE_STOPPED, 0, 0, START_FAILED_EXIT_CODE)`，其中 `const START_FAILED_EXIT_CODE: u32 = 1` |

**为什么**：`SERVICE_STATUS` 语义要求启动失败必须走 `dwWin32ExitCode = 1066` +
具体退出码，否则 SCM/`sc query`/`net start`/事件日志看到的就是「服务正常停止」，
故障只能靠翻日志。常量取 `windows_sys::Win32::Foundation::ERROR_SERVICE_SPECIFIC_ERROR`
（`Foundation/mod.rs:3774`，`WIN32_ERROR = u32`，`mod.rs:10179`），未手抄数值。

**同批附带（一行级，直接支撑上一条）**：
- `report()` 里 `Mutex::lock()` 由 `Err(_) => return` 改成 `unwrap_or_else(|err| err.into_inner())`
  ——锁中毒时原来的写法会**静默丢弃** STOP_PENDING/STOPPED，服务卡到 SCM 超时；
- `service_main` 里写状态句柄那句 `if let Ok(...)` 同样改为 `unwrap_or_else(into_inner)`，
  否则句柄写不进去，之后所有 `report` 都是空操作；
- `SetServiceStatus` 返回值改为检查，返回 0 时 `logger.warn` 一行
  （原代码丢弃返回值，上报失败完全不可见）。`logger` 调用放在**释放锁之后**，不引入锁顺序问题。

### 2.2 STOP 与启动收尾的竞态

| 项 | 内容 |
|---|---|
| 位置 | `handler` STOP 分支 **125-133**、`service_main` 启动收尾 **190-205** |
| 改前 | handler 置 `SHUTDOWN` → 上报 `STOP_PENDING`；`start_runtime()` 返回后**无条件** `report(SERVICE_RUNNING)`，把 STOP_PENDING 倒灌回 RUNNING（SCM 与本进程状态分裂，且原代码丢弃 `SetServiceStatus` 的 FALSE） |
| 改后 | 复用已有的 `static SHUTDOWN: AtomicBool`（它本来就是「已请求停止」的单一事实来源，在 `report(STOP_PENDING)` **之前**置位，handler 里加了注释说明这个顺序是契约），启动收尾：<br>① `SHUTDOWN == true` → 不上报 RUNNING，保持 STOP_PENDING 直接进停止流程；<br>② 否则 `report(RUNNING)`，随后**再查一次** `SHUTDOWN`，若已置位补报 `report(STOP_PENDING, 0, 5_000, 0)` |

**为什么用 SHUTDOWN 而不是新加 `STOPPING`**：两者语义完全相同（都是「已请求停止」），
再引入一个 `AtomicBool` 会变成必须同步置位的双事实来源，一旦漏置就复现原缺陷。
现有置位顺序（先 store 再 report）已满足「收尾前可见」，故直接复用并在两处注释里
把这个顺序要求写成契约。迁移合法性：`START_PENDING → STOP_PENDING → STOPPED` 与
`START_PENDING → RUNNING → STOP_PENDING → STOPPED` 都是文档允许的合法序列，不会出现
`RUNNING → STOPPED` 的非法跳变。

### 2.3 停止路径：尽力释放、绝不卡死 SCM

| 项 | 内容 |
|---|---|
| 位置 | 新增 `shutdown_runtime()` **229-252**、`service_main` 调用点 **221**、句柄登记 `track()`/`THREADS` **54-69**、`start_runtime` 登记处 **268/270-276/283-289** |
| 改前 | `while !SHUTDOWN { sleep(500ms) }` 之后直接 `report(SERVICE_STOPPED)`；`spawn_worker` 返回的 `JoinHandle` 直接被丢弃，`http`/`watch` 句柄也被丢弃，`etw` 从不 `stop()` |
| 改后 | `shutdown_runtime()`：① `ticker.notify()` 唤醒工作线程；② `crate::etw::stop()`（只置位 `RUNNING=false`，不阻塞）；③ 取走 `THREADS` 里登记的全部句柄，**仅对 `is_finished()` 为真的线程** `join()`，其余 `drop`（分离） |

**为什么不无条件 join / 不显式 drop WFP `Engine`**：按要求**没有改 `engine.rs`**。
`Engine::run_worker` 是 `loop {}`（engine.rs:273-354），退出条件不存在；`http` 线程
只在接受错误时 `break`（http.rs:584-598），`watch` 同理。对它们 `join` 会永久阻塞，
`sc stop` 会一直等到 wait hint 超时（错误 1053），正是「会卡死 SCM 的代码」。
WFP `Engine` 只是 `run_worker` 的局部变量（engine.rs:268、302-311），没有任何
`Drop`/`shutdown` 接口，只能随进程退出由系统回收；函数注释已把这点写清。
`is_finished()` 先判后 join 保证零阻塞（`JoinHandle::is_finished` 稳定于 Rust 1.61，
仓库 MSRV 为 1.75，见根 `Cargo.toml:10`），线程若已自行结束则立即回收，属于「尽力」。

### 未做（明确记录，避免误以为已修）
- `http`/`etw`/`watch` 启动失败仍是 `warn`/`error` 后继续 → 服务照样报 RUNNING（审计 §2 中
  「fail-open」）。把它改成就地失败会改变产品语义（ETW 失效即拒绝启动），属架构决策，
  不在本次「小步修缺陷」范围；失败码上报只覆盖真实返回 `Err` 的路径
  （`store.ensure()` / `store.logger()` / `Engine::boot`）。
- `dwCheckPoint` 自增、INTERROGATE 期间 `dwControlsAccepted = 0`、`NETBINDADD/REMOVE(7/8)`
  未处理、`run_console` 无 Ctrl+C 停止路径：均为审计里的中/低项，未在本次动。
- `docs/PROGRESS.md` 按仓库约定应留一行，但本次任务限定「不动其它文档」，交给主会话合并。

---

## 三、静态核对清单（逐条对照 `windows-sys 0.59.0` 源码）

| # | 检查点 | 结论 |
|---|---|---|
| 1 | `SERVICE_STATUS` 字段名/类型 `dwWin32ExitCode: u32`、`dwServiceSpecificExitCode: u32` | ✔ `Services/mod.rs:509-517` |
| 2 | `ERROR_SERVICE_SPECIFIC_ERROR` 存在且为 `WIN32_ERROR`(=u32) | ✔ `Foundation/mod.rs:3774`、`10179` |
| 3 | `NO_ERROR`(=0u32) 仍可赋给 `dwWin32ExitCode` | ✔ `Foundation/mod.rs:5514` |
| 4 | `SetServiceStatus` 返回 `BOOL`(i32)，`ok == 0` 判失败正确（非 HRESULT） | ✔ `Services/mod.rs:54` |
| 5 | `SERVICE_STATUS_HANDLE = *mut c_void`，`usize as SERVICE_STATUS_HANDLE` 合法 | ✔ `Services/mod.rs:518`；沿用原写法 |
| 6 | `SERVICE_STOPPED/STOP_PENDING/RUNNING/START_PENDING` 数值不变，仍为 `report` 实参 | ✔ 未改常量与 import |
| 7 | `report` 全部调用点都补了第 4 参（5 处业务调用 + 定义） | ✔ grep：129/168/188/198/202/212/226 |
| 8 | `JoinHandle` 类型一致：`thread::JoinHandle<()>`（`std::thread`，`use std::thread;` 已有） | ✔ 与 `engine::spawn_worker`/`http::spawn`/`watch::start` 返回值一致 |
| 9 | `Vec::drain(..)` 需 `mut` guard，`MutexGuard` 自动解引用 | ✔ `let mut guard = ...` |
| 10 | `is_finished()` 在 MSRV 1.75 可用 | ✔（1.61 稳定） |
| 11 | `drop(handle)` 于 `else` 分支：`is_finished` 只借 `&self`，所有权仍在 | ✔ |
| 12 | `handler` 中 `SHUTDOWN.store` 仍在 `report(STOP_PENDING)` 之前 | ✔ 顺序未变，仅加注释 |
| 13 | import 是否有未使用/缺失：`io` 仍用于 `last_os_error`；`AtomicBool/AtomicU32/Mutex/OnceLock/thread/Duration` 均仍被使用 | ✔ 无新增 import，无死 import |
| 14 | `cli_client`：`io` 已 `use std::io::{self, Read, Write};`，`ErrorKind`/`save_cookie` 返回类型可用 | ✔ |
| 15 | `save_cookie(&pair)`：`&String → &str` 解引用强制转换 | ✔ |
| 16 | Cookie 三处调用点（读/写/删）全部经 `cookie_path()` | ✔ grep 唯一路径来源 |
| 17 | `std::env::var_os` 对非 UTF-8 路径安全；空串环境变量被跳过 | ✔ `as_os_str().is_empty()` |
| 18 | 未改 `engine.rs` / `paths.rs` / `etw.rs` / `http.rs` / `watch.rs` | ✔ `git status` 只应见 2 个 .rs + 本报告 |

## 四、残留风险（静态分析，未真机验证）

1. **`is_finished()` 竞态**：判定为 false 后线程恰好结束 → 只是少回收一次，句柄随进程退出释放，无副作用（不阻塞）。
2. **停止流程无等待**：`report(SERVICE_STOPPED)` 时 worker 可能正处在 WFP 事务中，进程退出会硬切；这是审计 §2「高」项的另一半，必须改 `engine.rs` 才能彻底解决（本次被明确禁止）。
3. **`START_FAILED_EXIT_CODE = 1`**：与 `sc start` 的通用错误码区间不冲突（1066 才是分类码，1 只是 specific 值），无歧义。
4. 启动过程中若 `SHUTDOWN` 先置位、随后 `start_runtime()` 又失败：上报 `STOPPED` + 1066/1，状态序列 `START_PENDING → STOP_PENDING → STOPPED` 合法。

## 五、真机复核建议（仅记录，不执行）

1. 普通用户 `ngcli login --password-stdin` 后看 `%LOCALAPPDATA%\NetGuard\cli.session` 是否生成，
   再 `ngcli status` 是否返回 200（修复前是写失败 + 未认证）。
2. 制造启动失败（临时删 `secret.key` 或让配置校验硬失败）后 `sc query NetGuard`，
   确认 `WIN32_EXIT_CODE = 1066` 且 `SERVICE_EXIT_CODE = 1`。
3. `sc start` 与 `sc stop` 紧挨着连发，确认 `sc stop` 在 5s 内返回、无 1053，
   日志里有「服务已停止」。
