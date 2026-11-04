//! 服务宿主。
//!
//! `netguard.exe service` 作为 Windows 服务入口（由 `install.ps1` 注册，账户为 LocalSystem）。
//! 职责：
//! - 向服务控制管理器报告状态，接受停止、关机、电源事件、系统时间变更、网络绑定变更；
//! - 启动运行时引擎（`engine`）、控制台（`http`）与进程哈希守护（`etw`）；
//! - 上述事件发生时唤醒引擎工作线程，令其立即重算边界，而非等待定时器到期。

#![cfg(windows)]

use std::ffi::c_void;
use std::io;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use netguard_core::schedule::evaluate;
use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW, SERVICE_ACCEPT_NETBINDCHANGE,
    SERVICE_ACCEPT_PARAMCHANGE, SERVICE_ACCEPT_POWEREVENT, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_ACCEPT_TIMECHANGE, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_NETBINDENABLE, SERVICE_CONTROL_NETBINDDISABLE,
    SERVICE_CONTROL_PARAMCHANGE,
    SERVICE_CONTROL_POWEREVENT, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_CONTROL_TIMECHANGE,
    SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

use crate::engine::Engine;
use crate::log::Logger;
use crate::store::Store;
use crate::ticker::Ticker;

/// 服务名，须与 `install.ps1` 中注册的名称一致。
pub const SERVICE_NAME: &str = "NetGuard";

const PBT_APMSUSPEND: u32 = 0x0004;
const PBT_APMRESUMESUSPEND: u32 = 0x0007;
const PBT_APMRESUMEAUTOMATIC: u32 = 0x0012;

static CURRENT_STATE: AtomicU32 = AtomicU32::new(SERVICE_START_PENDING);
static STATUS_HANDLE: OnceLock<Mutex<usize>> = OnceLock::new();
static SHUTDOWN: AtomicBool = AtomicBool::new(false);
static TICKER: OnceLock<Ticker> = OnceLock::new();
static LOGGER: OnceLock<std::sync::Arc<Logger>> = OnceLock::new();

fn status_handle() -> &'static Mutex<usize> {
    STATUS_HANDLE.get_or_init(|| Mutex::new(0))
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn report(state: u32, accepted: u32, wait_hint: u32) {
    CURRENT_STATE.store(state, Ordering::SeqCst);
    let handle = status_handle();
    let guard = match handle.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };
    if *guard == 0 {
        return;
    }
    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwControlsAccepted = accepted;
    status.dwWin32ExitCode = NO_ERROR;
    status.dwCheckPoint = 0;
    status.dwWaitHint = wait_hint;
    unsafe {
        SetServiceStatus(*guard as SERVICE_STATUS_HANDLE, &status);
    }
}

fn accepted_controls() -> u32 {
    SERVICE_ACCEPT_STOP
        | SERVICE_ACCEPT_SHUTDOWN
        | SERVICE_ACCEPT_POWEREVENT
        | SERVICE_ACCEPT_TIMECHANGE
        | SERVICE_ACCEPT_NETBINDCHANGE
        | SERVICE_ACCEPT_PARAMCHANGE
}

unsafe extern "system" fn handler(control: u32, event_type: u32, event_data: *mut c_void, _context: *mut c_void) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            SHUTDOWN.store(true, Ordering::SeqCst);
            report(SERVICE_STOP_PENDING, 0, 5_000);
            if let Some(ticker) = TICKER.get() {
                ticker.notify();
            }
        }
        SERVICE_CONTROL_POWEREVENT => {
            let resume = matches!(
                event_type,
                PBT_APMRESUMEAUTOMATIC | PBT_APMRESUMESUSPEND
            );
            let suspend = event_type == PBT_APMSUSPEND;
            if let Some(logger) = LOGGER.get() {
                if resume {
                    logger.info("系统已从睡眠中恢复，重新计算拦截边界");
                } else if suspend {
                    logger.info("系统即将进入睡眠");
                }
            }
            if let Some(ticker) = TICKER.get() {
                ticker.notify();
            }
        }
        SERVICE_CONTROL_TIMECHANGE
        | SERVICE_CONTROL_NETBINDENABLE
        | SERVICE_CONTROL_NETBINDDISABLE
        | SERVICE_CONTROL_PARAMCHANGE => {
            if let Some(logger) = LOGGER.get() {
                let reason = match control {
                    SERVICE_CONTROL_TIMECHANGE => "系统时间已变更",
                    SERVICE_CONTROL_NETBINDENABLE | SERVICE_CONTROL_NETBINDDISABLE => "网络绑定已变更",
                    _ => "服务参数已变更",
                };
                logger.info(reason);
            }
            if let Some(ticker) = TICKER.get() {
                ticker.notify();
            }
        }
        SERVICE_CONTROL_INTERROGATE => {
            report(CURRENT_STATE.load(Ordering::SeqCst), accepted_controls(), 0);
        }
        _ => {
            let _ = event_data;
        }
    }
    NO_ERROR
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let mut name = wide(SERVICE_NAME);
    let handle = RegisterServiceCtrlHandlerExW(name.as_mut_ptr(), Some(handler), ptr::null());
    if handle.is_null() {
        return;
    }
    if let Ok(mut guard) = status_handle().lock() {
        *guard = handle as usize;
    }
    report(SERVICE_START_PENDING, 0, 10_000);

    match start_runtime() {
        Ok(_) => {
            report(SERVICE_RUNNING, accepted_controls(), 0);
        }
        Err(err) => {
            if let Some(logger) = LOGGER.get() {
                logger.error(&format!("服务启动失败：{err}"));
            }
            report(SERVICE_STOPPED, 0, 0);
            return;
        }
    }

    while !SHUTDOWN.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(500));
    }

    if let Some(logger) = LOGGER.get() {
        logger.info("服务已停止");
    }
    report(SERVICE_STOPPED, 0, 0);
}

fn start_runtime() -> io::Result<Arc<Engine>> {
    let store = Store::open_default();
    store.ensure()?;
    let logger = store.logger()?;
    let logger = std::sync::Arc::new(logger);
    let _ = LOGGER.set(logger.clone());
    logger.info("NetGuard 服务正在启动");

    let engine = Engine::boot(store)?;
    let ticker = engine.ticker().clone();
    let _ = TICKER.set(ticker);

    // 启动时先按当前状态套用一次过滤器。
    engine.notify();
    crate::engine::spawn_worker(Arc::clone(&engine));

    match crate::http::spawn(Arc::clone(&engine)) {
        Ok(_) => logger.info("本地控制台已启动"),
        Err(err) => logger.error(&format!("本地控制台启动失败：{err}")),
    }

    match crate::etw::start(Arc::clone(&engine)) {
        Ok(_) => logger.info("进程哈希守护已启动"),
        Err(err) => logger.warn(&format!("进程哈希守护启动失败：{err}")),
    }

    let snapshot = engine.snapshot();
    let evaluation = evaluate(
        &snapshot.config,
        chrono::Local::now().naive_local(),
        crate::engine::override_deadline(snapshot.state.override_until),
    );
    if evaluation.blocked {
        let count = evaluation.paths.len();
        logger.info(&format!("启动时处于拦截时段，当前拦截 {count} 个应用"));
    } else {
        logger.info("启动时不在拦截时段");
    }
    Ok(engine)
}

/// 服务模式入口。由 `netguard.exe service` 调用。
pub fn run_service() -> io::Result<()> {
    let mut name = wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// 控制台模式入口，便于调试：不注册服务，直接运行同一套运行时并阻塞。
pub fn run_console() -> io::Result<()> {
    let engine = start_runtime()?;
    let logger = engine.logger().clone();
    println!("NetGuard 控制台模式已启动，控制台地址 http://127.0.0.1:47811 ，按 Ctrl+C 退出。");
    loop {
        thread::sleep(Duration::from_secs(5));
        let snapshot = engine.snapshot();
        if !snapshot.integrity_ok {
            logger.warn("配置完整性异常，处于封锁状态");
        }
    }
}
