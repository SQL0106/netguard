//! 配置文件、签名与运行时状态的读写。

use std::io::{self, Write};
use std::path::Path;

use netguard_core::{mac, Config};
use serde::{Deserialize, Serialize};

use crate::dpapi;
use crate::log::Logger;
use crate::paths::Paths;

/// 配置备份的签名文件名。
///
/// 与 `paths::BACKUP_FILE`（`config.json.bak`）成对使用：备份自身也必须被签名覆盖，
/// 否则「删掉主配置、改掉备份」就能变成一条绕过完整性校验的捷径。
const BACKUP_MAC_FILE: &str = "config.mac.bak";

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
        self.load_from(&self.paths.config(), &self.paths.mac())
    }

    /// 读取并校验「上一次已知良好」的配置备份。
    ///
    /// 与 `Store::load` 走**完全相同**的校验流程；备份签名与备份配置成对存放
    /// （`config.json.bak` + `config.mac.bak`），因此篡改备份内容同样会验签失败，
    /// 不会成为绕过口子。
    pub fn load_backup(&self) -> Load {
        self.load_from(&self.paths.backup(), &self.paths.file(BACKUP_MAC_FILE))
    }

    /// 是否已经有过一次成功保存（存在配置备份）。
    ///
    /// 用于区分「真正首次安装」与「配置被删但曾初始化过」：前者应打开初始化窗口，
    /// 后者不能，否则删掉 `config.json` 再调一次 `/api/setup` 就能把封锁规则清零。
    pub fn has_backup(&self) -> bool {
        self.paths.backup().exists()
    }

    /// 从一对「配置 + 签名」文件读取并校验。
    ///
    /// 主配置与备份共用这一条路径，避免两边的校验流程漂移（少一步就是绕过）：
    /// 存在性 → 读文件 → 反序列化 → 规范化序列化 → 取密钥 → 解析签名 → 验签 → 结构校验。
    fn load_from(&self, config_path: &Path, signature_path: &Path) -> Load {
        if !config_path.exists() {
            return Load::Absent;
        }
        let (text, signature) = match (
            std::fs::read(config_path),
            std::fs::read_to_string(signature_path),
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
        let hex = match mac::parse_signature(&signature) {
            Some(hex) => hex,
            None => return Load::Tampered("签名格式无法识别".to_string()),
        };
        if !mac::verify_bytes(&key, &canonical, hex) {
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
        let signature = mac::format_signature(
            &mac::sign_bytes(&key, &canonical).map_err(io::Error::other)?,
        );

        let config_path = self.paths.config();
        if config_path.exists() {
            // 只把「当前磁盘配置仍能通过校验」的版本写进备份。
            // 否则配置被篡改后只要触发一次保存（例如一次失败的登录也会落盘失败计数），
            // 坏内容就会覆盖掉最后一份可信备份，fail-closed 的退路当场失效。
            if matches!(
                self.load_from(&config_path, &self.paths.mac()),
                Load::Ok(_)
            ) {
                let _ = std::fs::copy(&config_path, self.paths.backup());
                let _ = std::fs::copy(self.paths.mac(), self.paths.file(BACKUP_MAC_FILE));
            }
        }
        write_atomic(&config_path, &pretty)?;
        write_atomic(&self.paths.mac(), signature.as_bytes())?;
        // 首次保存（此前没有旧配置可备份）时把刚写入的这份作为备份起点：
        // 这样安装完成后立刻被篡改也还有一份可信名单可退，而不是退化到空名单。
        if !self.paths.backup().exists() {
            let _ = std::fs::copy(&config_path, self.paths.backup());
            let _ = std::fs::copy(self.paths.mac(), self.paths.file(BACKUP_MAC_FILE));
        }
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
        Ok(mac::format_signature(
            &mac::sign_bytes(&key, &canonical).map_err(io::Error::other)?,
        ))
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
