//! 进程哈希守护。
//!
//! 通过 ETW 实时订阅 `Microsoft-Windows-Kernel-Process` 的进程启动事件（关键字 0x10）。
//! 仅当新进程的文件名与配置中的应用名单同名时才继续处理：先挂起进程、计算文件哈希、
//! 命中黑名单哈希则为该文件的新路径追加阻断过滤器，然后恢复进程。
//!
//! 说明：本模块不解析事件负载，只使用事件头中的进程标识（即新启动的进程），
//! 因此无需依赖 TDH 解码，也不受清单版本变化影响。

#![cfg(windows)]

use std::collections::HashSet;
use std::io;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

use netguard_core::guard::{basename, hash_reader, HashOutcome};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_CANCELLED, ERROR_SUCCESS, HANDLE,
};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW, CONTROLTRACE_HANDLE,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, PROCESSTRACE_HANDLE,
    EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME,
};

use crate::engine::Engine;

/// `Microsoft-Windows-Kernel-Process` 的提供程序标识。
const PROVIDER: windows_sys::core::GUID = windows_sys::core::GUID {
    data1: 0x22fb_2cd6,
    data2: 0x0e7b,
    data3: 0x422b,
    data4: [0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16],
};

/// `WINEVENT_KEYWORD_PROCESS`：进程创建与退出事件的关键字。
const KEYWORD_PROCESS: u64 = 0x10;
const SESSION_NAME: &str = "NetGuard-Process";
const EVENT_PROCESS_START: u16 = 1;
const MAX_IMAGE_PATH: usize = 4096;

type NtSuspendProcess = unsafe extern "system" fn(HANDLE) -> i32;
type NtResumeProcess = unsafe extern "system" fn(HANDLE) -> i32;

static QUEUE: OnceLock<Sender<(u32, bool)>> = OnceLock::new();
static RUNNING: AtomicBool = AtomicBool::new(false);

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

struct Session {
    control: u64,
    properties: Vec<u8>,
}

unsafe impl Send for Session {}

fn session_property_buffer() -> Vec<u8> {
    let header = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let name = (SESSION_NAME.len() + 1) * 2;
    vec![0u8; header + name]
}

fn stop_session(control: u64, properties: &mut [u8]) {
    let mut name = wide(SESSION_NAME);
    let props = properties.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    unsafe {
        ControlTraceW(CONTROLTRACE_HANDLE { Value: control }, name.as_mut_ptr(), props, EVENT_TRACE_CONTROL_STOP);
    }
}

/// 初始化实时会话属性缓冲区，返回结构体指针（写入会话名）。
fn init_session_properties(properties: &mut [u8], name: &[u16]) -> *mut EVENT_TRACE_PROPERTIES {
    let props = properties.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    unsafe {
        (*props).Wnode.BufferSize = properties.len() as u32;
        (*props).Wnode.Flags = 0x0002_0000; // WNODE_FLAG_TRACED_GUID
        (*props).BufferSize = 16;
        (*props).MinimumBuffers = 2;
        (*props).MaximumBuffers = 8;
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*props).FlushTimer = 1;
        (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        (*props).LogFileNameOffset = 0;
        let offset = (*props).LoggerNameOffset as usize;
        let dest = properties.as_mut_ptr().add(offset) as *mut u16;
        ptr::copy_nonoverlapping(name.as_ptr(), dest, name.len());
    }
    props
}

fn start_session() -> io::Result<Session> {
    let mut name = wide(SESSION_NAME);
    let mut properties = session_property_buffer();
    let mut control = CONTROLTRACE_HANDLE { Value: 0 };
    let props = init_session_properties(&mut properties, &name);

    let mut code = unsafe { StartTraceW(&mut control, name.as_mut_ptr(), props) };
    if code == ERROR_ALREADY_EXISTS {
        // 上次进程被强杀可能留下同名实时会话。先停掉残留会话再重试一次，
        // 否则守护会因 183 永久起不来（Stop 时 handle 传 0 表示按名字停止）。
        unsafe {
            ControlTraceW(
                CONTROLTRACE_HANDLE { Value: 0 },
                name.as_mut_ptr(),
                props,
                EVENT_TRACE_CONTROL_STOP,
            );
        }
        // ControlTraceW 会把会话属性写回缓冲区，重试前重新初始化一遍。
        let props = init_session_properties(&mut properties, &name);
        code = unsafe { StartTraceW(&mut control, name.as_mut_ptr(), props) };
    }
    if code != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(code as i32));
    }

    let control = control.Value;
    let enable = unsafe {
        EnableTraceEx2(
            CONTROLTRACE_HANDLE { Value: control },
            &PROVIDER,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            4, // TRACE_LEVEL_INFORMATION
            KEYWORD_PROCESS,
            0,
            0,
            ptr::null(),
        )
    };
    if enable != 0 {
        stop_session(control, &mut properties);
        return Err(io::Error::from_raw_os_error(enable as i32));
    }

    Ok(Session { control, properties })
}

unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let header = (*record).EventHeader;
    let descriptor = header.EventDescriptor;
    let start = descriptor.Id == EVENT_PROCESS_START;
    let stop = descriptor.Id == 2;
    if !start && !stop {
        return;
    }
    if let Some(queue) = QUEUE.get() {
        let _ = queue.send((header.ProcessId, start));
    }
}

fn process_image(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SUSPEND_RESUME, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut buffer = vec![0u16; MAX_IMAGE_PATH];
        let mut size = MAX_IMAGE_PATH as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size);
        CloseHandle(handle);
        if ok == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&buffer[..size as usize]))
    }
}

fn suspend_targets() -> Option<(NtSuspendProcess, NtResumeProcess)> {
    unsafe {
        let ntdll = GetModuleHandleW(wide("ntdll.dll").as_ptr());
        if ntdll.is_null() {
            return None;
        }
        let suspend = GetProcAddress(ntdll, c"NtSuspendProcess".as_ptr() as *const u8);
        let resume = GetProcAddress(ntdll, c"NtResumeProcess".as_ptr() as *const u8);
        match (suspend, resume) {
            (Some(suspend), Some(resume)) => Some((
                std::mem::transmute::<unsafe extern "system" fn() -> isize, NtSuspendProcess>(suspend),
                std::mem::transmute::<unsafe extern "system" fn() -> isize, NtResumeProcess>(resume),
            )),
            _ => None,
        }
    }
}

fn watch_names(engine: &Engine) -> HashSet<String> {
    engine
        .snapshot()
        .config
        .apps
        .iter()
        .map(|app| basename(&app.path))
        .filter(|name| !name.is_empty())
        .collect()
}

fn handle_start(engine: &Arc<Engine>, pid: u32) {
    let path = match process_image(pid) {
        Some(path) => path,
        None => return,
    };
    let name = basename(&path);
    if !watch_names(engine).contains(&name) {
        return;
    }

    let logger = engine.logger();
    let hashes = engine.snapshot().config.hashes.clone();
    if hashes.is_empty() {
        return;
    }

    let target = unsafe { OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if target.is_null() {
        return;
    }
    let hooks = suspend_targets();
    if let Some((suspend, _)) = hooks {
        unsafe {
            suspend(target);
        }
    }

    let outcome = std::fs::File::open(&path)
        .map_err(|err| err.to_string())
        .and_then(|file| hash_reader(&mut std::io::BufReader::new(file), netguard_core::guard::MAX_HASH_BYTES).map_err(|err| err.to_string()));

    let mut blocked = false;
    match outcome {
        Ok(HashOutcome::Hashed(digest)) => {
            if hashes.iter().any(|item| item.eq_ignore_ascii_case(&digest)) {
                blocked = true;
                logger.warn(&format!("检测到黑名单哈希的程序启动：{path}"));
            }
        }
        Ok(HashOutcome::TooLarge) => {
            logger.warn(&format!("文件过大，跳过哈希校验：{path}"));
        }
        Err(err) => {
            logger.warn(&format!("读取文件失败（{path}）：{err}"));
        }
    }

    if blocked {
        engine.add_hash_block(&path);
    }

    if let Some((_, resume)) = hooks {
        unsafe {
            resume(target);
        }
    }
    unsafe {
        CloseHandle(target);
    }
}

fn handle_stop(engine: &Arc<Engine>, pid: u32) {
    let _ = (engine, pid);
}

fn worker(engine: Arc<Engine>, receiver: std::sync::mpsc::Receiver<(u32, bool)>) {
    for (pid, start) in receiver {
        if start {
            handle_start(&engine, pid);
        } else {
            handle_stop(&engine, pid);
        }
    }
}

/// 启动守护。返回后守护在后台线程运行。
pub fn start(engine: Arc<Engine>) -> io::Result<()> {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let (sender, receiver) = channel();
    let _ = QUEUE.set(sender);
    let worker_engine = Arc::clone(&engine);
    thread::Builder::new()
        .name("netguard-etw-worker".to_string())
        .spawn(move || worker(worker_engine, receiver))?;

    thread::Builder::new()
        .name("netguard-etw".to_string())
        .spawn(move || {
            let logger = engine.logger();
            let session = match start_session() {
                Ok(session) => session,
                Err(err) => {
                    RUNNING.store(false, Ordering::SeqCst);
                    logger.error(&format!("无法启动进程事件订阅：{err}"));
                    return;
                }
            };

            let mut name = wide(SESSION_NAME);
            let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
            logfile.LoggerName = name.as_mut_ptr();
            logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            logfile.Anonymous2.EventRecordCallback = Some(on_event);
            let handle = unsafe { OpenTraceW(&mut logfile) };
            if handle.Value == u64::MAX {
                // 先取 last_os_error：后面 stop_session 的调用会覆盖它。
                let err = io::Error::last_os_error();
                // 必须停掉刚建的会话，否则残留会话会让下次启动撞 ERROR_ALREADY_EXISTS。
                let mut properties = session.properties.clone();
                stop_session(session.control, &mut properties);
                logger.error(&format!("无法打开进程事件跟踪：{err}"));
                RUNNING.store(false, Ordering::SeqCst);
                return;
            }
            // 订阅此时已建立；ProcessTrace 会一直阻塞，直到会话被停止才返回。
            logger.info("进程事件订阅已建立");

            let processing = unsafe {
                ProcessTrace(&handle as *const PROCESSTRACE_HANDLE, 1, ptr::null(), ptr::null())
            };
            unsafe {
                CloseTrace(handle);
            }
            let mut properties = session.properties.clone();
            stop_session(session.control, &mut properties);
            RUNNING.store(false, Ordering::SeqCst);
            if processing != ERROR_SUCCESS && processing != ERROR_CANCELLED {
                logger.error(&format!("进程事件订阅异常结束（{processing}），等待上层重连"));
            }
        })?;

    thread::sleep(Duration::from_millis(50));
    Ok(())
}

/// 停止守护（进程退出时由系统回收，此处仅置位）。
pub fn stop() {
    RUNNING.store(false, Ordering::SeqCst);
}
