//! 简易滚动日志。
//!
//! 单个文件上限 1 MiB，最多保留 3 个历史文件。写入加锁，可从多个线程调用。

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const MAX_BYTES: u64 = 1024 * 1024;
const KEEP: usize = 3;

struct State {
    file: File,
    size: u64,
}

/// 日志写入器。
pub struct Logger {
    path: PathBuf,
    state: Mutex<State>,
}

fn open_at(path: &Path) -> io::Result<(File, u64)> {
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    let size = file.metadata()?.len();
    Ok((file, size))
}

impl Logger {
    /// 打开（或创建）日志文件。
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let (file, size) = open_at(&path)?;
        Ok(Self {
            path,
            state: Mutex::new(State { file, size }),
        })
    }

    /// 日志文件路径。
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn rotate(&self, state: &mut State) -> io::Result<()> {
        // netguard.log.2 -> netguard.log.3，依此类推，最旧的丢弃。
        for index in (1..=KEEP).rev() {
            let from = if index == 1 {
                self.path.clone()
            } else {
                let mut p = self.path.clone().into_os_string();
                p.push(format!(".{}", index - 1));
                PathBuf::from(p)
            };
            let mut to = self.path.clone().into_os_string();
            to.push(format!(".{index}"));
            let to = PathBuf::from(to);
            if from.exists() {
                let _ = std::fs::remove_file(&to);
                let _ = std::fs::rename(&from, &to);
            }
        }
        let (file, size) = open_at(&self.path)?;
        state.file = file;
        state.size = size;
        Ok(())
    }

    /// 写入一行。
    pub fn write(&self, level: &str, message: &str) {
        let line = format!(
            "{} [{level}] {message}\n",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        );
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.size + line.len() as u64 > MAX_BYTES {
            let _ = self.rotate(&mut state);
        }
        let _ = state.file.write_all(line.as_bytes());
        let _ = state.file.flush();
        state.size += line.len() as u64;
    }

    /// 一般信息。
    pub fn info(&self, message: &str) {
        self.write("信息", message);
    }

    /// 告警。
    pub fn warn(&self, message: &str) {
        self.write("告警", message);
    }

    /// 错误。
    pub fn error(&self, message: &str) {
        self.write("错误", message);
    }

    /// 读取末尾若干行，供 WebUI 展示。
    pub fn tail(&self, lines: usize) -> Vec<String> {
        let text = std::fs::read_to_string(&self.path).unwrap_or_default();
        let all: Vec<String> = text.lines().map(|line| line.to_string()).collect();
        let start = all.len().saturating_sub(lines);
        all[start..].to_vec()
    }
}
