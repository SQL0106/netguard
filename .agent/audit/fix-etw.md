# etw.rs 健壮性修复记录

> 改动范围：仅 `crates/win/src/etw.rs`。**未编译、未运行**（本机禁编译），结论均为静态核对。
> 未改其它源码/文档，未 commit/push。
> 依据：`~/netguard/.agent/audit/win-runtime.md` §3（etw.rs 三条高严重度项），
> 常量与签名逐条对照本机离线源码 `/opt/winsys/windows-sys-0.59.0/`。

## 一、改动总览

| # | 位置（改后行号） | 对应审查项 | 一句话 |
|---|---|---|---|
| 1 | etw.rs:22-24（import）、83-148（`init_session_properties` + `start_session`） | 高（原 102-105） | 183 时先 `ControlTraceW(STOP)` 停同名残留会话，再重试一次 `StartTraceW` |
| 2 | etw.rs:311-327（`start()` 内 `OpenTraceW` 失败分支） | 高（原 293-297） | `OpenTraceW` 失败先 `stop_session`，避免会话泄漏导致下次 183 自锁 |
| 3 | etw.rs:328-342（`start()` 内 `ProcessTrace` 段） | 高（原 298-301） | 检查 `ProcessTrace` 返回值；非成功非取消时记错误日志并停会话；「已建立」日志移到 `OpenTraceW` 成功之后 |

附带（同一函数内、为满足上一条）：`start()` 里 ETW 线程现在持有 `Arc<Engine>`（clone 给 worker），
启动失败由 `eprintln!` 改为 `logger.error`——服务无控制台，`eprintln!` 等于丢弃（审查 §3 第 4 条已指出）。
消息文案不变。

## 二、逐条说明

### 1) `StartTraceW` 返回 183 时不再永久失败

改前（原 102-105）：

```rust
let code = unsafe { StartTraceW(&mut control, name.as_mut_ptr(), properties.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
if code != 0 { return Err(...) }
```

改后（105-127）：

- 抽出 `init_session_properties(&mut [u8], &[u16]) -> *mut EVENT_TRACE_PROPERTIES`（83-101），
  把原来内联的属性初始化整段搬进去，语义不变。
- `StartTraceW` 返回 `ERROR_ALREADY_EXISTS` 时：
  1. `ControlTraceW(CONTROLTRACE_HANDLE { Value: 0 }, name, props, EVENT_TRACE_CONTROL_STOP)`
     —— handle 传 0 表示「按实例名停止」，与 `stop_session` 的 handle 用法（`:79`）一致；
  2. **重新调用 `init_session_properties` 初始化缓冲区**，再重试一次 `StartTraceW`；
  3. 仍非 `ERROR_SUCCESS` 才 `return Err`。

为什么要「先停后启」：`StartTraceW` 对同名实例返回 183，被上一次进程被强杀留下的实时会话占住；
不停掉它，ETW 守护每次启动都失败，进程哈希兜底永久失效（静默 fail-open）。
为什么重试前要重新初始化：`ControlTraceW(STOP)` 会把被停会话的属性写回 `properties` 缓冲区，
其中 `Wnode.BufferSize` 可能被改写；沿用脏缓冲区重试有越界风险，所以重设一遍。

已知边界：若残留会话被 `logman stop` 之外的方式占用（例如另一个进程正在消费），STOP 失败后仍会 183，
此时按规格报错，不做无限重试。

### 2) `OpenTraceW` 失败时停掉刚建的会话

改前（原 293-297）：`handle.Value == u64::MAX` → 置 `RUNNING=false` → `return`，会话残留。

改后（311-327）：

```rust
let handle = unsafe { OpenTraceW(&mut logfile) };
if handle.Value == u64::MAX {
    let err = io::Error::last_os_error();          // 必须在 stop_session 之前取
    let mut properties = session.properties.clone();
    stop_session(session.control, &mut properties); // 关键：先回收会话
    logger.error(&format!("无法打开进程事件跟踪：{err}"));
    RUNNING.store(false, Ordering::SeqCst);
    return;
}
```

`session.control` 是 `u64`（`Copy`），`properties.clone()` 后仍然可以按值取出，不存在部分移动问题。

### 3) 检查 `ProcessTrace` 返回值 + 推迟「已建立」日志

改前（原 298-304）：`ProcessTrace` 结果被丢弃，`CloseTrace` + `stop_session` 之后无条件 `RUNNING=false`；
`start()` 只 `sleep(50ms)` 就返回，调用方（`svc.rs:278`）永远看到成功。
etw.rs 内原本没有任何「已启动」日志（`svc.rs:279` 会打，但那是 `start()` 返回即打，属假成功）。

改后（328-342）：

```rust
// 订阅此时已建立；ProcessTrace 会一直阻塞，直到会话被停止才返回。
logger.info("进程事件订阅已建立");
let processing = unsafe { ProcessTrace(&handle as *const PROCESSTRACE_HANDLE, 1, ptr::null(), ptr::null()) };
unsafe { CloseTrace(handle); }
let mut properties = session.properties.clone();
stop_session(session.control, &mut properties);
RUNNING.store(false, Ordering::SeqCst);
if processing != ERROR_SUCCESS && processing != ERROR_CANCELLED {
    logger.error(&format!("进程事件订阅异常结束（{processing}），等待上层重连"));
}
```

- 日志语义修正：`info` 放在 `OpenTraceW` 成功之后（此时订阅确实生效），并注释说明
  `ProcessTrace` 是阻塞调用，不会「返回即成功」。
- `ProcessTrace` 非 0 且不是 `ERROR_CANCELLED`（会话被正常停止时的合法返回）→ 记 `logger.error`，
  随后关闭句柄、停会话、`RUNNING=false`，不 panic；后续外部再次调用 `start()` 时可重新建立。

## 三、常量与签名核对（对照 `/opt/winsys/windows-sys-0.59.0/`）

| 符号 | 定义位置 | 取值/签名 | 用法核对 |
|---|---|---|---|
| `ERROR_ALREADY_EXISTS` | `Win32/Foundation/mod.rs:971` | `WIN32_ERROR = 183u32` | 与 `StartTraceW` 返回类型 `WIN32_ERROR` 同类型，`==` 合法 |
| `ERROR_CANCELLED` | `Win32/Foundation/mod.rs:1107` | `1223u32` | 同上 |
| `ERROR_SUCCESS` | `Win32/Foundation/mod.rs:3892` | `0u32` | 同上；`StartTraceW`/`ProcessTrace` 均返回 `WIN32_ERROR` |
| `ControlTraceW` | `System/Diagnostics/Etw/mod.rs:3` | `(CONTROLTRACE_HANDLE, PCWSTR, *mut EVENT_TRACE_PROPERTIES, EVENT_TRACE_CONTROL) -> WIN32_ERROR` | 第一参用 `CONTROLTRACE_HANDLE { Value: 0 }`，与文件内 `:79` 写法一致；`name.as_mut_ptr()` 为 `*mut u16`，隐式转 `PCWSTR(*const u16)` |
| `StartTraceW` | `Etw/mod.rs:57` | `(*mut CONTROLTRACE_HANDLE, PCWSTR, *mut EVENT_TRACE_PROPERTIES) -> WIN32_ERROR` | 三个实参类型一致，返回值赋给 `let mut code` |
| `OpenTraceW` | `Etw/mod.rs:42` | `(*mut EVENT_TRACE_LOGFILEW) -> PROCESSTRACE_HANDLE` | 失败判定沿用 `handle.Value == u64::MAX`（`INVALID_PROCESSTRACE_HANDLE` 未由 windows-sys 导出，审查已确认） |
| `ProcessTrace` | `Etw/mod.rs:43` | `(*const PROCESSTRACE_HANDLE, u32, *const FILETIME, *const FILETIME) -> WIN32_ERROR` | `&handle as *const PROCESSTRACE_HANDLE`、`1`、两个 `ptr::null()` 不变；返回值类型 u32，可比较 |
| `EVENT_TRACE_CONTROL_STOP` | `Etw/mod.rs:241` | `EVENT_TRACE_CONTROL = 1u32` | 与 `ControlTraceW` 第四参类型一致 |
| `PROCESSTRACE_HANDLE` / `CONTROLTRACE_HANDLE` | `Etw/mod.rs:1545` / `846` | `#[repr(C)] { Value: u64 }` | 构造方式与文件既有写法一致（`{ Value: 0 }` / `{ Value: control }`） |
| `Logger::info/error` | `crates/win/src/log.rs:92/102` | `&self, &str` | `&format!(...)` 经 deref 转 `&str`，与文件内既有 `logger.warn(&format!(...))` 一致 |

## 四、静态核对清单

- [x] 导入：`ERROR_ALREADY_EXISTS`/`ERROR_CANCELLED`/`ERROR_SUCCESS` 来自 `windows_sys::Win32::Foundation`，
      **没有**手抄数值；三个常量均被使用（无 unused import）。
- [x] `code` 在重试路径需要二次赋值 → 声明为 `let mut code`；仅此一处新增 `mut`。
- [x] `props` 指针在 STOP 与重试之间重新计算（`init_session_properties` 再调用一次），
      不跨 `ControlTraceW` 复用可能被改写的缓冲区。
- [x] `init_session_properties` 内部 `unsafe` 块完整包裹全部解引用写入；`properties.as_mut_ptr()` 与
      `props`（裸指针）之间无借用冲突（裸指针不持有生命周期）。
- [x] `start_session` 内 `properties` 仍以**值**移入 `Session`（`Session { control, properties }`），
      重试分支的 `&mut properties` 在移动之前结束，无 use-after-move。
- [x] `OpenTraceW` 失败分支：`io::Error::last_os_error()` 在任何其它 syscall 之前取，
      不会被 `stop_session` 的 `ControlTraceW` 覆盖 `GetLastError`。
- [x] 该分支 `session.properties.clone()` + `session.control`（`u64: Copy`），`session` 未部分移动；
      分支内 `return` 后不再使用 `session`。
- [x] `ProcessTrace` 段：`processing` 与 `ERROR_SUCCESS`/`ERROR_CANCELLED` 同为 `WIN32_ERROR`；
      先 `CloseTrace` 再 `stop_session`，保持原有顺序。
- [x] 线程闭包：`engine`（`Arc<Engine>`）改为移入 ETW 线程，worker 用 `Arc::clone` 的副本；
      `logger` 是 `&Logger`（对闭包内局部 `engine` 的不可变借用），`Logger` 含 `Mutex`，线程安全。
- [x] `Logger::error/info` 的实参分别为 `&format!(...)` 与 `&'static str`，签名匹配。
- [x] 没有新增 `panic!`/`unwrap`/`expect`；失败路径全部 `return` 或记日志。
- [x] 未改动 `on_event`、`handle_start`、`stop_session`、`stop()` 等无关逻辑。

## 五、遗留（超出本次范围，未改）

1. `svc.rs:278` 只在 `start()` 返回时打一次 `warn`，**没有真正的重连逻辑**；本次修复只是让
   `ProcessTrace` 异常结束时留下明确错误日志并复位 `RUNNING`，可供上层后续加退避重启。
2. `start()` 里 `thread::sleep(50ms)` 仍是「早返回」，`svc.rs` 的「进程哈希守护已启动」仍是
   `start()` 返回即打印；要彻底修正需把 `start_session`/`OpenTraceW` 的结果用 `sync_channel`
   同步回 `start()`（审查 §3 第 4 条），涉及 `svc.rs`，本次不动。
3. `QUEUE` 是 `OnceLock`，`start()` 被二次调用时 `QUEUE.set` 会失败、旧 sender 仍指向已退出 worker 的
   通道；要让「失败后重启」真正可用，需把 `QUEUE` 换成可替换的 `Mutex<Option<Sender>>`（同样超出范围）。
4. `session_property_buffer()` 返回 `Vec<u8>`（对齐 1）却强转 `*mut EVENT_TRACE_PROPERTIES`（对齐 8）
   ——审查 §3 已列为中危 UB（当前 malloc 实际 16 字节对齐）。本次未改，避免扩大 diff。
