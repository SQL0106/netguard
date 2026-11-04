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
    /// 只允许 `SYSTEM` 完全控制、`Administrators` 读取与执行，并关闭继承。
    /// 无论目录是否早已存在都重新收紧：`%ProgramData%` 默认允许 `Users` 创建目录并
    /// 取得所有权，若只在「新建时」设置一次，普通用户可以抢先建好同名的宽松目录，
    /// 服务随后沿用它，等于绕过了整条完整性防线。
    pub fn ensure(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        self.harden_acl()
    }

    /// 用 `icacls` 收紧目录权限。
    ///
    /// 主体一律用 SID 而不是英文账户名，否则非英文 Windows 上 `icacls` 会因找不到
    /// `Administrators` 而失败，服务起不来。
    pub fn harden_acl(&self) -> io::Result<()> {
        let status = Command::new("icacls")
            .arg(&self.dir)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg("*S-1-5-18:(OI)(CI)F")
            .arg("*S-1-5-32-544:(OI)(CI)M")
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
