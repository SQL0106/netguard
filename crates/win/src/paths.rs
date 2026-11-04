//! 数据目录路径与访问控制。

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// `%ProgramData%\NetGuard` 及其下的固定文件名。
#[derive(Debug, Clone)]
pub struct Paths {
    dir: PathBuf,
}

/// 配置文件名。
pub const CONFIG_FILE: &str = "config.json";
/// 配置签名文件名。
pub const MAC_FILE: &str = "config.mac";
/// 运行时状态文件名（不含签名）。
pub const STATE_FILE: &str = "state.json";
/// 签名密钥文件名（DPAPI 机器范围保护）。
pub const KEY_FILE: &str = "secret.key";
/// 日志文件名。
pub const LOG_FILE: &str = "netguard.log";
/// 配置备份文件名。
pub const BACKUP_FILE: &str = "config.json.bak";

impl Paths {
    /// 默认数据目录。
    pub fn default_dir() -> PathBuf {
        match std::env::var_os("ProgramData") {
            Some(base) => PathBuf::from(base).join("NetGuard"),
            None => PathBuf::from(r"C:\ProgramData\NetGuard"),
        }
    }

    /// 指定目录（主要用于测试与便携部署）。
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// 默认位置。
    pub fn new() -> Self {
        Self::at(Self::default_dir())
    }

    /// 目录本身。
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// 目录内的某个文件。
    pub fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// 配置路径。
    pub fn config(&self) -> PathBuf {
        self.file(CONFIG_FILE)
    }

    /// 签名路径。
    pub fn mac(&self) -> PathBuf {
        self.file(MAC_FILE)
    }

    /// 状态路径。
    pub fn state(&self) -> PathBuf {
        self.file(STATE_FILE)
    }

    /// 密钥路径。
    pub fn key(&self) -> PathBuf {
        self.file(KEY_FILE)
    }

    /// 日志路径。
    pub fn log(&self) -> PathBuf {
        self.file(LOG_FILE)
    }

    /// 备份路径。
    pub fn backup(&self) -> PathBuf {
        self.file(BACKUP_FILE)
    }

    /// 创建目录并收紧访问控制。
    ///
    /// 目录新建时只允许 `SYSTEM` 完全控制、`Administrators` 读取与执行，
    /// 关闭继承以避免普通用户获得访问权。已存在的目录不重复设置，
    /// 以免覆盖运维人员的调整。
    pub fn ensure(&self) -> io::Result<()> {
        let existed = self.dir.exists();
        std::fs::create_dir_all(&self.dir)?;
        if !existed {
            self.harden_acl()?;
        }
        Ok(())
    }

    /// 用 `icacls` 收紧目录权限。
    pub fn harden_acl(&self) -> io::Result<()> {
        let status = Command::new("icacls")
            .arg(&self.dir)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg("SYSTEM:(OI)(CI)F")
            .arg("Administrators:(OI)(CI)RX")
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "icacls 返回失败状态 {status}"
            )))
        }
    }
}

impl Default for Paths {
    fn default() -> Self {
        Self::new()
    }
}
