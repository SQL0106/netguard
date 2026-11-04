//! 数据目录监视。
//!
//! 通过 `ReadDirectoryChangesW` 阻塞等待配置目录内的文件变化。它是阻塞调用而非轮询：
//! 线程在没有事件时完全挂起，内核只在目录项发生变化时唤回。
//!
//! 只关心 `config.json` 与 `config.mac`。一次变化通常产生多条记录（写入临时文件、
//! 重命名、属性更新），因此每轮读取后会短暂停顿再做一次重载，避免同一改动被处理多次。

#![cfg(windows)]

use std::ffi::c_void;
use std::io;
use std::ptr;
use std::thread;
use std::time::Duration;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadDirectoryChangesW, FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY, FILE_NOTIFY_INFORMATION,
    FILE_NOTIFY_CHANGE_CREATION, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};

use crate::engine::Engine;

/// 单次读取的通知缓冲区大小。目录事件很小，8 KiB 足够容纳一批记录。
const BUFFER_BYTES: usize = 8 * 1024;
/// 合并同一改动产生的多条记录的等待时间。
const SETTLE: Duration = Duration::from_millis(300);

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn open_directory(path: &std::path::Path) -> io::Result<HANDLE> {
    let name = wide(&path.to_string_lossy());
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    if handle == (-1isize as HANDLE) {
        return Err(io::Error::last_os_error());
    }
    Ok(handle)
}

/// 解析一次返回的通知缓冲区，判断是否涉及配置文件。
fn touches_config(buffer: &[u8], bytes: u32) -> bool {
    let total = bytes as usize;
    if total == 0 || total > buffer.len() {
        return false;
    }
    let mut offset = 0usize;
    loop {
        if offset + std::mem::size_of::<FILE_NOTIFY_INFORMATION>() > total {
            return false;
        }
        let info = unsafe { &*(buffer.as_ptr().add(offset) as *const FILE_NOTIFY_INFORMATION) };
        let name_bytes = info.FileNameLength as usize;
        if name_bytes % 2 == 0 && offset + 12 + name_bytes <= total {
            let raw = unsafe { std::slice::from_raw_parts(info.FileName.as_ptr(), name_bytes / 2) };
            let name = String::from_utf16_lossy(raw).to_ascii_lowercase();
            if name == "config.json" || name == "config.mac" {
                return true;
            }
        }
        if info.NextEntryOffset == 0 {
            return false;
        }
        offset += info.NextEntryOffset as usize;
    }
}

fn worker(engine: std::sync::Arc<Engine>) {
    let directory = engine.store().paths().dir().to_path_buf();
    loop {
        let handle = match open_directory(&directory) {
            Ok(handle) => handle,
            Err(err) => {
                engine
                    .logger()
                    .warn(&format!("无法打开配置目录进行监视：{err}"));
                // 目录可能尚未创建：等一会儿重试，而不是退出后彻底失去监视。
                thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        let mut buffer = vec![0u8; BUFFER_BYTES];
        loop {
            let mut returned: u32 = 0;
            let ok = unsafe {
                ReadDirectoryChangesW(
                    handle,
                    buffer.as_mut_ptr() as *mut c_void,
                    BUFFER_BYTES as u32,
                    0,
                    FILE_NOTIFY_CHANGE_FILE_NAME
                        | FILE_NOTIFY_CHANGE_SIZE
                        | FILE_NOTIFY_CHANGE_LAST_WRITE
                        | FILE_NOTIFY_CHANGE_CREATION,
                    &mut returned,
                    ptr::null_mut(),
                    None,
                )
            };
            if ok == 0 {
                let err = io::Error::last_os_error();
                engine
                    .logger()
                    .warn(&format!("配置目录监视中断，将重新打开：{err}"));
                break;
            }
            if touches_config(&buffer, returned) {
                thread::sleep(SETTLE);
                let verdict = engine.reload_from_disk();
                if let crate::engine::Reload::Tampered(note) = verdict {
                    engine
                        .logger()
                        .error(&format!("配置变更被拒绝：{note}"));
                }
            }
        }

        unsafe {
            CloseHandle(handle);
        }
        thread::sleep(Duration::from_millis(500));
    }
}

/// 启动监视线程。失败时返回错误，由调用方决定是否降级为仅启动时读取。
pub fn start(engine: std::sync::Arc<Engine>) -> io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("netguard-watch".to_string())
        .spawn(move || worker(engine))
}
