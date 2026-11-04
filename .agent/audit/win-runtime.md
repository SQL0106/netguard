# win crate 运行时审查（真机致命项）

> 报告人：审查子代理。**未修改任何源码，未编译**（本机禁编译）。
> 所有结论均为**静态分析推断**，除显式标注外无真机证据。
> 参考依据：本机离线源码 `/opt/winsys/windows-sys-0.59.0/src/Windows/**`（行号见各条）。
> 已核对 CI 记录：HEAD `206ffef` 的祖先 `1b1f593` 在 `windows-latest` 构建成功（`gh run list`），
> 故本次列出的都是「能编译但运行/语义有问题」的项，没有编译错误项。

## 0. 规格（抄录自上游 prompt，作为审查清单）

### 任务
只审查以下文件，找出**会导致真机运行失败或安全语义错误**的问题：
- `crates/win/src/svc.rs`（服务宿主、ServiceMain/HandlerEx、控制码）
- `crates/win/src/etw.rs`（ETW 订阅 Kernel-Process、进程挂起与哈希）
- `crates/win/src/paths.rs`（数据目录与 ACL）
- `crates/win/src/dpapi.rs`（DPAPI 密钥保护）
- `crates/win/src/log.rs`（日志滚动/并发写）
- `crates/win/src/cli_client.rs`（HTTP 客户端）

### 重点核查
1. windows-sys 0.59 的 FFI 用法：结构体字段是否漏设（尤其 flags、providerKey、context）、返回码是否用 `check()` 直接吃掉「正常但非零」的 HRESULT（已踩：`FWP_E_*`、`ERROR_*`）、句柄泄漏或重复关闭。
2. 常量数值：一律对照本机离线源码，不凭记忆，写出核对的行号。
3. 服务生命周期：ServiceMain 是否正确 `RegisterServiceCtrlHandlerExW` + `SetServiceStatus`（START_PENDING → RUNNING → STOP_PENDING → STOPPED）、停止时是否 join 线程/释放 WFP 引擎、`HandlerEx` 返回值语义是否被误用。
4. ETW：`StartTraceW`/`EnableTraceEx2`/`ProcessTrace` 的参数与事件回调签名、是否在服务账户下可用、`OpenProcess`/`NtSuspendProcess` 的权限与错误路径（进程已退出必须忽略，不能把它当致命错误）。
5. 逻辑：锁顺序与死锁、`Arc` 循环、panic 是否会打挂服务（release 已 panic=abort，确认不会在请求线程里 panic）。

### 硬约束
- 不改源码、不 cargo build/check/test。
- 边读边写，读完一个文件追加结论。
- 结论格式：`| 严重度 | 文件:行 | 现象 | 依据 | 建议修法 |`，严重度：致命/高/中/低/非问题。非问题也写。
- 不断言「已验证」；无真机证据写「静态分析推断」。
- 上下文控制 50–100k。

---

## 1. 汇总

| 文件 | 致命 | 高 | 中 | 低 | 非问题 |
|---|---|---|---|---|---|
| svc.rs | 0 | 3 | 6 | 3 | 3 |
| etw.rs | 0 | 3 | 8 | 2 | 3 |
| paths.rs | 0 | 2 | 2 | 1 | 1 |
| dpapi.rs | 0 | 0 | 2 | 2 | 2 |
| log.rs | 0 | 0 | 2 | 4 | 1 |
| cli_client.rs | 0 | 1 | 3 | 4 | 2 |
| **合计** | **0** | **9** | **23** | **16** | **12** |

**结论：本次 6 个文件里没有「一跑就崩/一跑就不工作」的致命项**，但有 9 条高严重度项，
其中 4 条会直接让**功能静默失效**（ETW 起不来却报成功、停止时不释放引擎、普通用户无法登录 CLI、
目录 ACL 可被普通用户抢占），属于「能编译、单测通过、真机照样白做」那一类。

---

## 2. svc.rs

| 严重度 | 文件:行 | 现象 | 依据 | 建议修法 |
|---|---|---|---|---|
| 高 | svc.rs:155-161 + 71 | 启动失败时上报 `SERVICE_STOPPED`，但 `report()` 里 `dwWin32ExitCode` 硬编码 `NO_ERROR`、`dwServiceSpecificExitCode` 恒 0 → SCM/`net start`/`sc query` 看到的是「正常停止」，排查全靠日志。`report()` 也没有 exit_code 形参可传。 | `SERVICE_STATUS`（Services/mod.rs:509-517）语义：启动失败必须 `SERVICE_STOPPED` + `dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR(1066)` + `dwServiceSpecificExitCode`；`SetServiceStatus` 文档明确该字段用于区分失败原因。`ERROR_SERVICE_SPECIFIC_ERROR = 1066`（Foundation/mod.rs:3774）。 | `report()` 增加 `exit_code`/`specific` 参数；失败路径填 1066，并写 `logger.error`。 |
| 高 | svc.rs:164-171（配合 engine.rs:267-400） | 停止时只 `thread::sleep(500ms)` 轮询 `SHUTDOWN`，随后直接 `report(SERVICE_STOPPED)`。**没有** join `netguard-worker` / `netguard-etw` / http 线程，也**没有** drop `wfp::Engine`（它只是 `run_worker` 的局部变量，`run_worker` 是 `loop{}` 无退出条件）。 | `spawn_worker` 返回 `JoinHandle` 被 svc.rs:188 丢弃；`Engine` 无 `shutdown()`。后果：run_worker 可能正处在 WFP 事务/`reconcile` 中间被进程退出硬切，非持久会话内的过滤器/句柄只能靠内核回收；etw 的 `ProcessTrace` 也永远阻塞。 | 给 `Engine` 加 `stop: AtomicBool` + `shutdown()`：置位 → `ticker.notify()` → join 三个句柄 → 显式 drop WFP engine；`service_main` 在报 STOPPED 前调用。 |
| 高 | svc.rs:149-153 | STOP 与启动竞态：`start_runtime()` 期间若收到 STOP（handler 已 `report(SERVICE_STOP_PENDING)` 且置 `SHUTDOWN`），`start_runtime` 返回后主线程**无条件** `report(SERVICE_RUNNING, ...)`，覆盖 STOP_PENDING。 | 文档规定服务状态只能按 START_PENDING→RUNNING→STOP_PENDING→STOPPED 单向推进；`SetServiceStatus` 此时返回 FALSE，而代码把返回值丢弃（svc.rs:74-76），于是服务实际处于「SCM 认为 STOP_PENDING、自己认为 RUNNING」的分裂态。 | `report(SERVICE_RUNNING)` 前检查 `SHUTDOWN`；若已置位直接 `report(SERVICE_STOPPED)` 返回。同时检查 `SetServiceStatus` 返回值并记日志。 |
| 中 | svc.rs:130-132 | INTERROGATE 回 `report(CURRENT_STATE, accepted_controls(), 0)`：STOP_PENDING 期间仍上报「可接受 STOP/SHUTDOWN...」。 | `SetServiceStatus` 文档：进入 STOP_PENDING 后 `dwControlsAccepted` 应为 0（本文件 92 行自己也这么做）。 | 依 `CURRENT_STATE` 决定 accepted：非 RUNNING 时传 0。 |
| 中 | svc.rs:114-129 | 接受了 `SERVICE_ACCEPT_NETBINDCHANGE`，但只处理 `NETBINDENABLE(9)/NETBINDDISABLE(10)`；`SERVICE_CONTROL_NETBINDADD(7)/NETBINDREMOVE(8)` 落到 `_` 分支，只 `let _ = event_data` → 网卡增删不触发重算。 | 控制码取值：Services/mod.rs:134-137（7/8/9/10）；接受 NETBINDCHANGE 后 SCM 会发这四个。 | 把 7/8 并入 114 行分支并 `ticker.notify()`。 |
| 中 | svc.rs:57-76 / 92 / 149 | `dwCheckPoint` 恒为 0，START_PENDING(10s)/STOP_PENDING(5s) 期间不递增。 | `SetServiceStatus` 文档：有 wait hint 时应每次递增 checkpoint，否则 SCM 只能靠 wait hint 超时判定挂死。 | 增加原子 checkpoint 计数器。 |
| 中 | svc.rs:60-63 | `status_handle()` 的 `Mutex::lock()` 返回 `Err`（曾 panic 中毒）时 `report()` 直接 return → handler 的 STOP_PENDING、service_main 的 STOPPED 全部静默丢失，服务会卡到 SCM 超时。 | 同文件其它锁都用 `unwrap_or_else(|e| e.into_inner())`（engine.rs:147 等），唯独这里没有。 | 改成 `unwrap_or_else(|e| e.into_inner())`。 |
| 中 | svc.rs:188 + engine.rs:400-404 | `spawn_worker` 内部 `.expect("无法创建工作线程")`：线程创建失败（内存紧张/handle 上限）会在 `extern "system" fn service_main` 内 panic → `panic=abort` 下进程直接终止，SCM 只看到服务崩溃，且没有任何 SetServiceStatus。 | panic 跨越 FFI 边界本来就是 UB/abort；release 已配 panic=abort。 | `spawn_worker` 改返回 `io::Result`，失败走启动失败路径（上报 STOPPED + 1066）。 |
| 中 | svc.rs:190-203 | http / etw / watch 三个子系统启动失败只 `logger.warn`，服务照样报 RUNNING。ETW 守护失效 = 哈希兜底失效，但 `status` 里只有 `last_error`（且不一定写入）可查。对「fail-closed」产品语义不合适。 | DESIGN 要求异常时 fail-closed；此处是 fail-open。 | 至少把失败写进 `Snapshot.last_error` 并在 `/api/state` 暴露；ETW 失败可考虑降级为「全量拦截」而非静默。 |
| 低 | svc.rs:137 | 未识别控制码返回 `NO_ERROR`。 | HandlerEx 文档建议返回 `ERROR_CALL_NOT_IMPLEMENTED(120)` 表示不支持；SCM 实际忽略该返回值，故无功能影响。 | 可选：`_ => ERROR_CALL_NOT_IMPLEMENTED`。 |
| 低 | svc.rs:233-237 | `StartServiceCtrlDispatcherW` 失败统一返回 `last_os_error()`：交互式直接运行 `netguard.exe service` 会得到 1063，CLI 层若照原样打印会误导。 | `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063`。 | 1063 时提示「请用 console 模式」。 |
| 低 | svc.rs:241-252 | `run_console` 无限 sleep，没有 Ctrl+C 处理，也不复用停止路径；退出时不会 drop Engine。 | 代码。 | 用 `ctrlc` 或 `SetConsoleCtrlHandler`，走同一 `shutdown()`。 |
| 非问题 | svc.rs:88 / 140 / 222-232 | `HandlerEx` 签名 `(u32,u32,*mut c_void,*mut c_void)->u32` 与 windows-sys 0.59 `LPHANDLER_FUNCTION_EX` 完全一致（Services/mod.rs:581）；`SERVICE_TABLE_ENTRYW` 字段名 `lpServiceName/lpServiceProc` 正确（mod.rs:540-545）；`SERVICE_STATUS_HANDLE` 在 0.59 是 `*mut c_void`（mod.rs:518），`is_null()` 与 `as usize`/反向 cast 都合法。 | 已逐行对照。 | — |
| 非问题 | svc.rs:39-41 | 自行硬编码的 `PBT_APMSUSPEND=0x4`、`PBT_APMRESUMESUSPEND=0x7`、`PBT_APMRESUMEAUTOMATIC=0x12` 与 `Win32/UI/WindowsAndMessaging/mod.rs:1568-1574`（18/7/4）一致。注意 `Win32_System_Power` feature 未启用，硬编码是必要的。 | 同上。 | — |
| 非问题 | svc.rs:79-86 | `SERVICE_ACCEPT_*` 1/4/16/8/64 与 Services/mod.rs:100-107 一致；`SERVICE_CONTROL_*` 1/4/5/6/9/10/13/16 与 132-147 一致；`SERVICE_WIN32_OWN_PROCESS=16`（mod.rs:267）、`SERVICE_START_PENDING=2`（192）、`SERVICE_RUNNING=4`（186）、`SERVICE_STOP_PENDING=3`（201）、`SERVICE_STOPPED=1`（200）均正确；`SERVICE_STATUS` 7 个字段全部显式赋值。 | 逐条核行。 | — |

**svc.rs 小结**：FFI 形状与常量全对（这批没再犯 `FWP_E_*` 那种错），问题集中在**生命周期**：
状态机可被竞态倒灌、停止不 join 不释放、启动失败被伪装成正常停止。

---

## 3. etw.rs

| 严重度 | 文件:行 | 现象 | 依据 | 建议修法 |
|---|---|---|---|---|
| 高 | etw.rs:102-105 + 120-123 | `StartTraceW` 只要 `code != 0` 就当致命。上次异常退出（进程被 kill、蓝屏）残留同名实时会话时返回 `ERROR_ALREADY_EXISTS(183)`，于是 ETW 从此永久起不来，而服务只 `warn` 一句继续跑。 | `StartTraceW` 文档：以相同实例名启动已有会话返回 183。静态推断：本模块也没有任何「先停残留会话」的逻辑。 | 183 时先 `ControlTraceW(0, name, props, EVENT_TRACE_CONTROL_STOP)` 再重试一次；仍失败才放弃。 |
| 高 | etw.rs:293-297 | `OpenTraceW` 返回 INVALID 时直接 `return`，**没有** `stop_session` → 刚 `StartTraceW` 建好的会话残留，下次启动必然撞 183（自锁死）。 | 代码路径：286-303 之间只有成功分支会 stop。 | return 前调用 `stop_session(session.control, &mut properties)`。 |
| 高 | etw.rs:298-301 | `ProcessTrace` 返回值被丢弃。若它立即失败（会话被 `logoff`/`logman stop` 杀掉、句柄失效），线程直接走到 `CloseTrace` + `stop_session`，`RUNNING=false`，但服务日志已在 svc.rs:196 打过「进程哈希守护已启动」，之后**无任何重试**。 | `ProcessTrace` 返回 `WIN32_ERROR`（Etw/mod.rs:43）。 | 检查返回值；非 0 时按可重试错误退避重启会话（或用 `EVENT_TRACE_CONTROL_QUERY` 周期探活，但注意设计上「零轮询」）。 |
| 中 | etw.rs:276-308 | `start()` 起线程后只 `sleep(50ms)` 就返回 `Ok(())`；`start_session` 在子线程里失败只 `eprintln!`（服务无控制台，等于丢弃）。调用方（svc）永远看到成功。 | 代码。 | 用 `std::sync::mpsc::sync_channel(1)` 把 session 建立结果同步回 `start()`；失败返回 `Err`。 |
| 中 | etw.rs:311-314 | `stop()` 只 `RUNNING.store(false)`：不 `CloseTrace`、不 `ControlTraceW(STOP)`、不 join。`ProcessTrace` 会一直阻塞到进程退出，线程/会话都无法优雅回收。 | `ProcessTrace` 是阻塞调用，只有会话被停止或 `CloseTrace` 才返回。 | 保存 `PROCESSTRACE_HANDLE` 与 `CONTROLTRACE_HANDLE`：先 `CloseTrace` 再 `ControlTraceW(STOP)`，然后 join 线程。 |
| 中 | etw.rs:132-140 | 用 `EventHeader.ProcessId` 当作「刚启动的进程 PID」（本模块注释也这么写，且明说不解析负载）。对 `Microsoft-Windows-Kernel-Process` 的 header 归属，静态无法确认在所有内核版本上都等于**新进程** PID（可能是触发上下文/父进程）。若取错，会去挂起/哈希一个无关进程（甚至 System），真正的黑名单进程漏检。 | 无真机证据；该提供程序 ProcessStart 负载首字段就是 `ProcessID`。 | 用 TDH（`TdhGetEventInformation`/`TdhGetProperty`）或按已知偏移解析负载里的 ProcessID 与 header 交叉校验；至少在真机上打印两者比对一次并写进 PROGRESS.md。 |
| 中 | etw.rs:190-199 | 每条事件都 `OpenProcess + QueryFullProcessImageNameW`，并且**每个事件**重建一次 `watch_names()`（遍历 apps + HashSet 分配）。系统进程创建高峰时开销大；`channel()` 无界，worker 落后会持续堆积内存。 | 代码（179-198）。 | 名单缓存为 `Arc<HashSet<String>>`（快照变更时整块替换）；队列用 `sync_channel(1024)` + 溢出计数。 |
| 中 | etw.rs:67-71 | `vec![0u8; n]` 的对齐是 1，却被强转成 `*mut EVENT_TRACE_PROPERTIES`（含 u64/GUID，对齐 8）并写入 → 未对齐访问是 UB。x86_64 上 malloc 实际给 16 字节对齐，所以现在能跑。 | Rust 对齐规则；`EVENT_TRACE_PROPERTIES`（Etw/mod.rs:1443）首字段 `WNODE_HEADER` 含 u64。 | 用 `Vec<u64>`/`Box<[u64]>` 或 `#[repr(align(8))] struct Buf([u8;N])` 再切片。 |
| 中 | etw.rs:206-215 | `OpenProcess` 失败（进程已退出/受保护进程/权限不足）静默 `return`；`NtSuspendProcess` 返回值也不检查。进程已退出忽略是**对的**（符合要求），但对「拿到事件却打不开」的失败也一律静默，等于给出绕过面。 | 代码。 | 区分 `ERROR_INVALID_PARAMETER(87)`（进程已退出，忽略）与 `ERROR_ACCESS_DENIED(5)`（记 warn/计数，供 status 显示）。 |
| 中 | etw.rs:217-219 | 进程被挂起期间同步做全文件哈希（上限 `MAX_HASH_BYTES`），网络重定向路径/慢盘会长时间冻结目标进程（用户可见卡死）。 | 代码。 | 加超时（或先读前 N MB + 大小阈值）；失败必须保证 resume（当前 241-245 有保证，✓）。 |
| 中 | etw.rs:251-253 | `handle_stop` 空实现：`hash_blocked` 只增不减，进程退出后仍保留路径 → 长期运行后 `engine.add_hash_block` 名单与 WFP 过滤器持续膨胀。 | 代码；`engine.rs:363-378` 无删除接口。 | 进程退出时若该 path 不在配置名单内则移除（或按「最近使用时间」淘汰）。 |
| 低 | etw.rs:47 / 135 | 启动事件 ID=1 用了常量，停止 ID=2 是魔法数（且 `stop` 分支目前无实际作用）。 | Kernel-Process 事件 ID。 | 提常量并注释来源。 |
| 低 | etw.rs:272-274 | worker 线程优先于 ETW 线程 spawn，失败时 `?` 直接返回，但此时 `QUEUE` 已 set、`RUNNING` 仍 true（272 行的 `?` 会带着 `RUNNING=true` 逃逸）。 | 代码。 | `?` 前复位 `RUNNING`。 |
| 非问题 | etw.rs:289-292 | `logfile.Anonymous1.ProcessTraceMode` / `Anonymous2.EventRecordCallback` 是 union 字段（Etw/mod.rs:1411-1440）。union 字段**写入**在安全代码里是允许的（只有**读取**需要 unsafe），且该代码已在 windows-latest 构建通过（`gh run` 1b1f593 success）→ 不是编译错误，也不是 UB（`zeroed()` 之后写的是活跃变体）。 | 同上 + CI 记录。 | — |
| 非问题 | etw.rs:36-45 / 93 / 291 | Provider GUID `22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716` = `Microsoft-Windows-Kernel-Process`；`KEYWORD_PROCESS=0x10`；`EVENT_TRACE_REAL_TIME_MODE=0x100`（mod.rs:288）；`PROCESS_TRACE_MODE_EVENT_RECORD=0x10000000`（476）；`PROCESS_TRACE_MODE_REAL_TIME=0x100`（478）；`WNODE_FLAG_TRACED_GUID=0x20000`（809）；`EVENT_CONTROL_CODE_ENABLE_PROVIDER=1`（163）；`EVENT_TRACE_CONTROL_STOP=1`（241）；`TRACE_LEVEL_INFORMATION=4` 均为正确取值。 | 逐条核行。 | — |
| 非问题 | etw.rs:294 | `INVALID_PROCESSTRACE_HANDLE` 未在 windows-sys 导出，`handle.Value == u64::MAX` 是正确写法（该常量就是 0xFFFF_FFFF_FFFF_FFFF）。 | Etw/mod.rs 无该常量定义。 | — |

**etw.rs 小结**：参数形状、GUID、关键字、模式位全对；真正的坑在**失败路径不对称**
（OpenTrace 失败不停会话、ProcessTrace 返回值不看、start 假成功）与**未验证的 header→PID 假设**。

---

## 4. paths.rs

| 严重度 | 文件:行 | 现象 | 依据 | 建议修法 |
|---|---|---|---|---|
| 高 | paths.rs:90-97 | 只在 `dir` **原本不存在**时才 `harden_acl()`。`C:\ProgramData` 的默认 ACL 允许 `Users` 创建子目录，且创建者（CREATOR OWNER）对自己的子目录有完全控制 → 普通用户可以先手建 `C:\ProgramData\NetGuard` 并获得所有权。服务（SYSTEM）启动时 `existed==true` 就跳过收紧，于是整份配置/密钥/日志落在攻击者可控目录里：可替换 `config.mac`、可解 `secret.key`（见 dpapi 条）、可用 junction/symlink 让 `write_atomic` 覆盖任意文件。 | Windows 默认 ACL + 本文件 90-97 的单向分支；`Store::key/write_atomic` 均直接写该目录。 | 每次都校验并重设 ACL（`icacls /grant:r` 幂等）；额外校验目录 owner 必须是 `Administrators`/`SYSTEM`，否则拒绝启动（fail-closed）。 |
| 高 | paths.rs:101-107 | `icacls /grant:r SYSTEM:... Administrators:...` 用**英文账户名**。非英文 Windows（德语 `Administratoren`、中文「管理员」等）名称解析失败 → icacls 非 0 → `ensure()` 失败 → 服务启动直接失败。 | icacls 文档要求可解析的账户名；SID 形式用 `*S-1-5-32-544`。 | 改用 `*S-1-5-18:(OI)(CI)F` / `*S-1-5-32-544:(OI)(CI)RX`（SID 形式与语言无关）。 |
| 中 | paths.rs:100-115 | 依赖外部 `icacls.exe`；`Command::new` 未设 `CREATE_NO_WINDOW`（服务无控制台无所谓，但 `run_console`/测试会出现一闪而过的黑窗）；也没检查 icacls 是否被同名恶意可执行体劫持（SYSTEM 下 PATH 以 System32 优先，风险低）。 | 代码。 | 用 `SetNamedSecurityInfoW`/`SetEntriesInAclW` 直接设 DACL；或加 `CREATE_NO_WINDOW`。 |
| 中 | paths.rs:105-106 | 只给 `Administrators:(OI)(CI)RX`。管理员跑 `ngcli`/WebUI 写配置需要提权；普通用户完全不可读写（进而导致 cli_client 的 cookie 无处安放，见 7.1）。 | 与本文件 87-88 的注释一致（有意为之），但与产品「WebUI/CLI 由用户运行」的用法冲突。 | 明确设计：CLI 只走 HTTP 不碰目录；把用户态产物（cookie）移到 `%LOCALAPPDATA%`。 |
| 低 | paths.rs:91-92 | `exists()` 与 `create_dir_all` 之间有 TOCTOU：两步之间被建目录就逃过 ACL 收紧（与第 1 条同源）。 | 代码。 | 并入「总是设 ACL」。 |
| 非问题 | paths.rs:28-33 / 14-24 | 目录与文件名和仓库 AGENTS.md 一致；`ProgramData` 环境变量缺失时回退 `C:\ProgramData\NetGuard` 合理。 | 文档对照。 | — |

---

## 5. dpapi.rs

| 严重度 | 文件:行 | 现象 | 依据 | 建议修法 |
|---|---|---|---|---|
| 中 | dpapi.rs:36-45 / 64-72 | `pOptionalEntropy` 传 NULL：没有应用绑定，同一台机器上任何拿到密文的代码（以 SYSTEM/管理员身份，或 ACL 被绕过后的普通用户）都能 `CryptUnprotectData` 直接解开。 | `CryptProtectData` 文档：entropy 用于增加与调用方绑定的熵。 | 传固定 entropy（如 `b"netguard-key-v1"`）并纳入版本管理。 |
| 中 | dpapi.rs:16 | `CRYPTPROTECT_LOCAL_MACHINE` 是**机器范围**：文档明确「同一台机器上的任何用户都能解密」。当前唯一防线是 paths.rs 的目录 ACL，而该 ACL 可被抢占（见 4.1）。一旦破防 → 密钥泄露 → 可伪造 `config.mac`，完整性保护全废。 | `CryptProtectData` 文档 + 两文件联合分析。 | 先修 paths ACL；要更强的隔离就改用 SYSTEM 专属密钥容器（DPAPI-NG / CNG `NCryptProtectSecret` + 机器密钥）。 |
| 低 | dpapi.rs:49 / 77 | `slice::from_raw_parts(output.pbData, output.cbData)` 未判空：若 DPAPI 返回 `cbData==0 && pbData==null`（理论上不会），构造空 slice 也是 UB。 | Rust 语义（`from_raw_parts` 要求非空对齐指针）。 | 判 `cbData == 0` 直接返回空 Vec。 |
| 低 | dpapi.rs:29-54 | 明文密钥在进程堆里不做清零（`zeroize`），核心转储/挂起进程可捞。 | 代码。 | `zeroize` 敏感缓冲。 |
| 非问题 | dpapi.rs:46 / 74 | 正确按 **BOOL** 判 `== 0`（不是 HRESULT）；`CryptProtectData`/`CryptUnprotectData` 签名与 Cryptography/mod.rs:279/311 一致；`CRYPTPROTECT_LOCAL_MACHINE=4`（2156）、`CRYPTPROTECT_UI_FORBIDDEN=1`（2163）取值正确；`CRYPT_INTEGER_BLOB{cbData:u32,pbData:*mut u8}` 与 6628 一致；`LocalFree` 正确释放（Foundation/mod.rs:8），无泄漏；未传 `ppszDataDescr`（传 null_mut）不会产生需释放的描述字符串。 | 逐条核行。 | — |
| 非问题 | dpapi.rs:94-125 | `from_hex` 偶数长度检查在前，`bytes[index+1]` 不会越界；`strip_prefix` 失败给明确错误；`protect_text/unprotect_text` 的 `dpapi:<hex>` 往返自洽。 | 代码走查。 | — |

---

## 6. log.rs

| 严重度 | 文件:行 | 现象 | 依据 | 建议修法 |
|---|---|---|---|---|
| 中 | log.rs:83-88 | 先判 `size + len > MAX` 再 `rotate()`；`rotate()` 的错误被 `let _ =` 吞掉。若 rename 永久失败（日志被备份软件以无 DELETE 共享打开、目录只读、磁盘满），`size` 继续累加，此后**每写一行**都重试整轮 rename（3 次失败系统调用 + remove），日志无限增长。 | 代码（49-71、83-88）。 | rotate 失败时把 `size` 复位/置位「已告警」标志并退避（例如每 100 行再试一次），同时 stderr 报错。 |
| 中 | log.rs:86-88 | 写入/刷新错误全部丢弃（`let _ =`）。磁盘满时日志静默丢失——本产品的告警、时钟回拨、哈希命中都靠日志取证。 | 代码。 | 至少计数 + 周期向 stderr/事件日志报告一次。 |
| 低 | log.rs:75-78 | 时间戳只用本地时间（无时区/无 UTC），而本产品专门检测时钟回拨；回拨期间日志会「倒流」，时间线不可靠。 | 代码；engine.rs 有 watermark 回拨检测。 | 附带 UTC 或单调计数器。 |
| 低 | log.rs:62-65 | `remove_file`/`rename` 错误忽略；若 `.1/.2/.3` 被外部以独占方式占用，滚动会静默失败（见上条）。 | 代码。 | 记录失败原因。 |
| 低 | log.rs:107-112 | `tail()` 直接 `read_to_string`；与 rotate 并发时可能读到刚被 rename 的旧文件（无害），但整个文件读进内存（上限 1 MiB，可接受）。 | 代码。 | — |
| 低 | log.rs:24-28 | 未显式指定共享模式；Windows 下 Rust std 默认 `FILE_SHARE_READ|WRITE|DELETE`，所以滚动 rename 与 WebUI 读取不会互相打架（这条是确认**不是**问题，但依赖 std 实现细节）。 | Rust std Windows `OpenOptions` 行为。 | 如要强保证，显式用 `OpenOptionsExt::share_mode`。 |
| 非问题 | log.rs:49-71 | 滚动顺序 `3←2←1←当前` 正确，保留 `.1/.2/.3` 三个历史文件（与 `KEEP=3` 一致）；重新 `open_at` 后 `size` 归零；append 模式避免覆盖；`Mutex` + 中毒 `into_inner` 处理正确，多线程写安全。 | 逐行走查。 | — |

---

## 7. cli_client.rs

| 严重度 | 文件:行 | 现象 | 依据 | 建议修法 |
|---|---|---|---|---|
| 高 | cli_client.rs:24-26 + 165-169 | 会话 cookie 存 `%ProgramData%\NetGuard\cli.session`，而该目录 ACL 是 `SYSTEM:F / Administrators:RX`（paths.rs:105-106）→ **普通用户 `ngcli login` 必然 Access Denied**（HTTP 登录其实已成功，但写 cookie 失败）；后续命令 `read_cookie()` 也读不到 → 全部退化成未认证请求。功能上等于 CLI 只有管理员能用。 | 两文件交叉：paths.rs:100-115 与这里。 | 改存 `%LOCALAPPDATA%\NetGuard\cli.session`（每用户一份，天然隔离），并对文件设「仅当前用户」ACL。 |
| 中 | cli_client.rs:169 | `std::fs::write` 跟随符号链接/硬链接且不设 DACL：管理员身份运行 `ngcli login` 时，若该路径被预先布置成指向任意文件的 reparse point，可覆写任意文件（本地提权写入原语）。 | Windows 文件语义 + 目录 ACL 可抢占（4.1）。 | 用 `CreateFileW(CREATE_NEW|FILE_FLAG_OPEN_REPARSE_POINT)` 独占创建，再写；或在 `%LOCALAPPDATA%` 下用同样方式。 |
| 中 | cli_client.rs:133-134 | `ngcli log <count>` 的 `count` 未校验直接拼进请求行：`ngcli log $'50\r\nX-Injected: 1'` 可注入额外头（客户端侧请求走私）。服务端 `http.rs:534-541` 会 `clamp(10,500)` 所以只影响客户端自身。 | 代码（`format!("/api/log?lines={count}")`）。 | 先 `count.parse::<u32>()`，再 clamp 后格式化。 |
| 中 | cli_client.rs:55-72 | 明文 HTTP 打 `127.0.0.1:47811`，**不校验服务端身份**：服务未运行时，任何本机用户可抢绑该端口伪装成 NetGuard，骗取口令与 TOTP（口令+TOTP 双因子同时泄露）。 | 代码；威胁模型含「本机普通用户」。 | 改用命名管道 + 服务端 ACL；至少让服务在 Welcome/CHALLENGE 里带一个 DPAPI 保护的一次性随机数供客户端校验。 |
| 低 | cli_client.rs:56 | 只设了读超时（10s）没设写超时；服务端 accept 后不读时 `write_all` 可能长时间阻塞。 | 代码。 | `set_write_timeout`。 |
| 低 | cli_client.rs:147-158 | `serde_json::to_string(...).unwrap_or_default()`：序列化失败会产出 `"password":,` 这种非法 JSON（实际不会失败，属防御性问题）；另外 JSON 字段名 `password` 与仓库 AGENTS.md「源码禁止 `password` 紧跟 `=`/`:` 再跟字面值」的脱敏禁忌擦边（当前是格式串，不是字面值，安全）。 | 代码 + AGENTS.md 硬约束 4。 | 直接构造 `serde_json::json!` 序列化。 |
| 低 | cli_client.rs:88-95 | `Set-Cookie: ` 前缀大小写敏感（HTTP 头不区分大小写）；服务端 `http.rs:80` 固定写 `Set-Cookie` 所以可用；多条 `Set-Cookie` 取最后一条。 | 代码对照。 | 用 `eq_ignore_ascii_case` 比较头名。 |
| 低 | cli_client.rs:76-87 | 状态行缺失时 `status=0` → 报「HTTP 0」，提示不友好但不会 panic。 | 代码。 | 单独区分「响应格式错误」。 |
| 非问题 | cli_client.rs:55 | `ADDR.parse().expect("固定地址")` 是编译期常量 `127.0.0.1:47811`（endpoint.rs:4），不会 panic。 | 代码。 | — |
| 非问题 | cli_client.rs:103-113 / 176-181 | `(200..300)` 判定正确；logout 忽略错误并清本地 cookie 合理；`--password-stdin` 读入后 `trim()`，口令不进 argv。 | 代码。 | — |

---

## 8. 复核建议（真机上按这个顺序验，别一次全上）

1. **ETW 会话残留**：先 `logman query -ets | findstr NetGuard`，`sc stop` 后强制杀进程，再启动服务，看日志是否出现「无法启动进程事件订阅」和错误码 183。
2. **ETW header→PID**：临时在 `on_event` 里打印 `header.ProcessId` 与负载里的 ProcessID（或用 `wpr -start` 对照），确认真机上是新进程 PID。
3. **服务停止**：`sc stop NetGuard` 后立刻 `logman query -ets`（看会话是否还在）与 `tasklist`（看线程/句柄）；同时确认 `report(STOPPED)` 是否被 SCM 接受（`Get-WinEvent -LogName System` 里 SCM 的 7034/7036）。
4. **目录 ACL 抢占**：普通用户先 `mkdir C:\ProgramData\NetGuard`，再以管理员安装/启动服务，`icacls` 查看 owner 与 DACL 是否被纠正。
5. **CLI 普通用户**：非管理员 `ngcli login --password-stdin`，确认是否写 cookie 失败。
6. **非英文系统**：只用 SID 形式可验；或用 `icacls C:\ProgramData\NetGuard` 看是否报「找不到账户名 Administrators」。

## 9. 审查边界（没查的）

- `wfp.rs`（本次不在清单；那两条已知坑已在别处记录）。
- `http.rs` / `engine.rs` / `store.rs` / `watch.rs`：只在解释本文件结论时读了相关片段，没有独立审查。
