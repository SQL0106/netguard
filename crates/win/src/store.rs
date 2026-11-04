//! 配置文件、签名与运行时状态的读写。

use std::io::{self, Write};
use std::path::Path;

use netguard_core::{mac, Config};
use serde::{Deserialize, Serialize};

use crate::dpapi;
use crate::log::Logger;
use crate::paths::Paths;

/// 加载结果。
#[derive(Debug)]
pub enum Load {
    /// 配置有效。
    Ok(Config),
    /// 尚未初始化。
    Absent,
    /// 存在但无法信任（缺失签名、签名不符、无法解析、密钥不可用）。
    Tampered(String),
}

/// 与签名无关的运行时状态。
///
/// 这些字段随运行变化，若纳入签名会导致每次登录失败都重写配置，
/// 因此单独存放；其可信前提是数据目录的访问控制。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeState {
    /// 已见的最新时间戳，用于识别时钟回拨。
    pub watermark: i64,
    /// 临时放行的截止时间。
    pub override_until: Option<i64>,
    /// 连续认证失败次数。
    pub failures: u32,
    /// 锁定截止时间。
    pub locked_until: Option<i64>,
    /// 最近一次成功使用的动态口令计数器，防止同码重放。
    pub last_totp_counter: Option<u64>,
    /// 最近一次过滤器协调时间。
    pub last_reconcile: Option<i64>,
}

/// 数据目录的读写入口。
#[derive(Debug, Clone)]
pub struct Store {
    paths: Paths,
}

impl Store {
    /// 基于给定路径构造。
    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }

    /// 默认位置 `%ProgramData%\NetGuard`。
    pub fn open_default() -> Self {
        Self::new(Paths::new())
    }

    /// 路径集合。
    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    /// 创建目录并收紧权限。
    pub fn ensure(&self) -> io::Result<()> {
        self.paths.ensure()
    }

    /// 打开日志。
    pub fn logger(&self) -> io::Result<Logger> {
        Logger::open(self.paths.log())
    }

    /// 读取签名密钥；不存在时创建。
    pub fn key(&self) -> io::Result<[u8; 32]> {
        let path = self.paths.key();
        if path.exists() {
            let raw = std::fs::read(&path)?;
            let plain = dpapi::unprotect(&raw).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("签名密钥无法解密：{e}"),
                )
            })?;
            if plain.len() != 32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "签名密钥长度异常",
                ));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&plain);
            Ok(key)
        } else {
            let mut key = [0u8; 32];
            getrandom::getrandom(&mut key)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("随机数失败：{e}")))?;
            let protected = dpapi::protect(&key)?;
            write_atomic(&path, &protected)?;
            Ok(key)
        }
    }

    /// 是否已完成初始化。
    pub fn is_initialized(&self) -> bool {
        self.paths.config().exists()
    }

    /// 读取并校验配置。
    pub fn load(&self) -> Load {
        let config_path = self.paths.config();
        if !config_path.exists() {
            return Load::Absent;
        }
        let (text, signature) = match (
            std::fs::read(&config_path),
            std::fs::read_to_string(self.paths.mac()),
        ) {
            (Ok(text), Ok(sig)) => (text, sig),
            (Err(e), _) => return Load::Tampered(format!("配置无法读取：{e}")),
            (_, Err(e)) => return Load::Tampered(format!("签名无法读取：{e}")),
        };
        let config: Config = match serde_json::from_slice(&text) {
            Ok(config) => config,
            Err(e) => return Load::Tampered(format!("配置无法解析：{e}")),
        };
        let canonical = match serde_json::to_vec(&config) {
            Ok(bytes) => bytes,
            Err(e) => return Load::Tampered(format!("配置无法规范化：{e}")),
        };
        let key = match self.key() {
            Ok(key) => key,
            Err(e) => return Load::Tampered(format!("签名密钥不可用：{e}")),
        };
        if !mac::verify(&key, &canonical, signature.trim()) {
            return Load::Tampered("签名不匹配".to_string());
        }
        if let Err(e) = config.validate() {
            return Load::Tampered(format!("配置内容非法：{e}"));
        }
        Load::Ok(config)
    }

    /// 写入配置及其签名。
    pub fn save(&self, config: &Config) -> io::Result<()> {
        config
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        self.ensure()?;
        let key = self.key()?;
        let canonical = serde_json::to_vec(config)?;
        let pretty = serde_json::to_vec_pretty(config)?;
        let signature = format!("v1:{}\n", mac::sign(&key, &canonical));

        let config_path = self.paths.config();
        if config_path.exists() {
            let _ = std::fs::copy(&config_path, self.paths.backup());
        }
        write_atomic(&config_path, &pretty)?;
        write_atomic(&self.paths.mac(), signature.as_bytes())?;
        Ok(())
    }

    /// 读取运行时状态，损坏时返回默认值。
    pub fn load_state(&self) -> RuntimeState {
        match std::fs::read(self.paths.state()) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => RuntimeState::default(),
        }
    }

    /// 写入运行时状态。
    pub fn save_state(&self, state: &RuntimeState) -> io::Result<()> {
        self.ensure()?;
        let bytes = serde_json::to_vec_pretty(state)?;
        write_atomic(&self.paths.state(), &bytes)
    }

    /// 为任意配置文本计算签名（供 `config sign` 子命令使用）。
    pub fn sign_text(&self, text: &[u8]) -> io::Result<String> {
        let config: Config =
            serde_json::from_slice(text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        config
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let canonical = serde_json::to_vec(&config)?;
        let key = self.key()?;
        Ok(format!("v1:{}\n", mac::sign(&key, &canonical)))
    }
}

/// 原子写入：先写临时文件并刷盘，再替换目标。
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut tmp = path.to_path_buf().into_os_string();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}
