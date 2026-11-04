//! 首次初始化：将预置配置转换为正式配置。
//!
//! 预置配置允许携带明文密码与动态口令密钥，本模块负责把明文散列化或加密，
//! 使其不再以明文形式进入运行时配置。该流程与 WebUI 中的初始化等价，
//! 供无人值守安装使用。

use serde::{Deserialize, Serialize};

use crate::auth::{self, Factors};
use crate::config::{AppRule, AuthConfig, Config, CONFIG_VERSION};

/// 单个恢复码的散列计算较为昂贵，限制上限避免误用。
const MAX_RECOVERY_CODES: usize = 50;

/// 初始化过程中的错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapError {
    /// 预置配置无法解析。
    Parse(String),
    /// 所选认证方式需要密码，但未提供。
    PasswordRequired,
    /// 动态口令密钥格式非法。
    InvalidTotpSecret(String),
    /// 生成后的配置未通过校验。
    InvalidConfig(String),
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "预置配置解析失败：{e}"),
            Self::PasswordRequired => write!(f, "所选认证方式需要密码，但未提供"),
            Self::InvalidTotpSecret(e) => write!(f, "动态口令密钥非法：{e}"),
            Self::InvalidConfig(e) => write!(f, "配置校验失败：{e}"),
        }
    }
}

impl std::error::Error for BootstrapError {}

/// 预置配置。
///
/// 与运行时配置的差别在于：认证部分可以只给出方式与明文凭据，
/// 由本模块在安装时补全散列与密钥。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreSeed {
    /// 配置版本，缺省视为当前版本。
    #[serde(default)]
    pub version: u32,
    /// 总开关，缺省为启用。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 受控程序列表。
    #[serde(default)]
    pub apps: Vec<AppRule>,
    /// 需要拦截的文件散列。
    #[serde(default)]
    pub hashes: Vec<String>,
    /// 直接给出完整的认证配置（凭据已散列）。
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    /// 认证方式，覆盖 `auth.factors`。
    #[serde(default)]
    pub factors: Option<Factors>,
    /// 明文密码，安装时被散列。
    #[serde(default)]
    pub password: Option<String>,
    /// Base32 动态口令密钥，缺省时自动生成。
    #[serde(default)]
    pub totp_secret: Option<String>,
    /// 恢复码数量，缺省为推荐值。
    #[serde(default)]
    pub recovery_code_count: Option<usize>,
}

fn default_true() -> bool {
    true
}

/// 初始化结果。
#[derive(Debug, Clone)]
pub struct Bootstrap {
    /// 可直接落盘的正式配置。
    pub config: Config,
    /// 明文恢复码，仅在初始化时出现一次。
    pub recovery_codes: Vec<String>,
    /// 最终使用的动态口令密钥（Base32），用于生成二维码。
    pub totp_secret: Option<String>,
    /// 密钥是否为本次自动生成。
    pub totp_generated: bool,
}

impl PreSeed {
    /// 从 JSON 文本解析。
    pub fn from_json(text: &str) -> Result<Self, BootstrapError> {
        serde_json::from_str(text).map_err(|e| BootstrapError::Parse(e.to_string()))
    }

    /// 从字节解析。
    pub fn from_slice(bytes: &[u8]) -> Result<Self, BootstrapError> {
        serde_json::from_slice(bytes).map_err(|e| BootstrapError::Parse(e.to_string()))
    }

    /// 认证方式：显式字段优先，其次取完整认证配置。
    pub fn effective_factors(&self) -> Factors {
        if let Some(f) = &self.factors {
            return f.clone();
        }
        if let Some(a) = &self.auth {
            return a.factors.clone();
        }
        Factors::None
    }
}

/// 依据预置配置生成正式配置与一次性凭据。
pub fn build(preseed: &PreSeed) -> Result<Bootstrap, BootstrapError> {
    if preseed.version != 0 && preseed.version != CONFIG_VERSION {
        return Err(BootstrapError::InvalidConfig(format!(
            "配置版本 {} 不受支持",
            preseed.version
        )));
    }

    let factors = preseed.effective_factors();
    let previous = preseed.auth.as_ref();

    let password_hash = if factors.needs_password() {
        match preseed.password.as_deref() {
            Some(pw) if !pw.is_empty() => {
                Some(auth::hash_password(pw).map_err(BootstrapError::InvalidConfig)?)
            }
            _ => match previous.and_then(|a| a.password_hash.clone()) {
                Some(h) => Some(h),
                None => return Err(BootstrapError::PasswordRequired),
            },
        }
    } else {
        None
    };

    let mut totp_generated = false;
    let totp_secret = if factors.needs_totp() {
        let secret = match preseed.totp_secret.as_deref() {
            Some(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => {
                totp_generated = true;
                auth::new_totp_secret().map_err(BootstrapError::InvalidTotpSecret)?
            }
        };
        let raw = crate::totp::base32_decode(&secret)
            .map_err(|e| BootstrapError::InvalidTotpSecret(e.to_string()))?;
        if raw.len() < 10 {
            return Err(BootstrapError::InvalidTotpSecret(
                "密钥长度不足 10 字节".to_string(),
            ));
        }
        Some(secret)
    } else {
        None
    };

    let (recovery_codes, recovery_hashes) = if matches!(factors, Factors::None) {
        (Vec::new(), Vec::new())
    } else {
        let count = preseed
            .recovery_code_count
            .unwrap_or(auth::RECOVERY_CODE_COUNT)
            .min(MAX_RECOVERY_CODES);
        let codes = auth::new_recovery_codes(count).map_err(BootstrapError::InvalidConfig)?;
        let mut hashes = Vec::with_capacity(codes.len());
        for code in &codes {
            hashes.push(auth::hash_password(code).map_err(BootstrapError::InvalidConfig)?);
        }
        (codes, hashes)
    };

    let config = Config {
        version: CONFIG_VERSION,
        enabled: preseed.enabled,
        apps: preseed.apps.clone(),
        hashes: preseed.hashes.clone(),
        auth: AuthConfig {
            factors,
            password_hash,
            totp_secret: totp_secret.clone(),
            recovery_hashes,
            failures: 0,
            locked_until: None,
            last_totp_counter: None,
        },
    };

    // 恢复码散列写入配置，校验时由 auth 模块做大小写与分隔符归一。
    config
        .validate()
        .map_err(BootstrapError::InvalidConfig)?;

    Ok(Bootstrap {
        config,
        recovery_codes,
        totp_secret,
        totp_generated,
    })
}

/// 将恢复码排版为可直接保存的文本。
pub fn recovery_text(codes: &[String]) -> String {
    let mut out = String::new();
    for code in codes {
        out.push_str(code);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_preseed() -> PreSeed {
        PreSeed {
            version: CONFIG_VERSION,
            enabled: true,
            apps: Vec::new(),
            hashes: Vec::new(),
            auth: None,
            factors: Some(Factors::Password),
            password: Some("初始密码".to_string()),
            totp_secret: None,
            recovery_code_count: Some(3),
        }
    }

    #[test]
    fn 密码被散列且可校验() {
        let b = build(&base_preseed()).expect("应当成功");
        let phc = b.config.auth.password_hash.as_deref().expect("应有密码散列");
        assert!(auth::verify_password("初始密码", phc));
        assert!(!auth::verify_password("错误密码", phc));

        let json = serde_json::to_string(&b.config).expect("可序列化");
        assert!(!json.contains("初始密码"));
    }

    #[test]
    fn 生成恢复码且数量一致() {
        let b = build(&base_preseed()).expect("应当成功");
        assert_eq!(b.recovery_codes.len(), 3);
        assert_eq!(b.config.auth.recovery_hashes.len(), 3);
        let text = recovery_text(&b.recovery_codes);
        assert_eq!(text.lines().count(), 3);
    }

    #[test]
    fn 缺失密码时报错() {
        let mut p = base_preseed();
        p.password = None;
        assert_eq!(build(&p).unwrap_err(), BootstrapError::PasswordRequired);
    }

    #[test]
    fn 双因子自动生成密钥() {
        let mut p = base_preseed();
        p.factors = Some(Factors::Both);
        let b = build(&p).expect("应当成功");
        assert!(b.totp_generated);
        let secret = b.totp_secret.expect("应生成密钥");
        assert!(crate::totp::base32_decode(&secret).is_ok());
        assert_eq!(b.config.auth.totp_secret.as_deref(), Some(secret.as_str()));
    }

    #[test]
    fn 双因子沿用给定密钥() {
        let mut p = base_preseed();
        p.factors = Some(Factors::Both);
        p.totp_secret = Some("JBSWY3DPEHPK3PXP".to_string());
        let b = build(&p).expect("应当成功");
        assert!(!b.totp_generated);
        assert_eq!(b.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn 非法密钥被拒绝() {
        let mut p = base_preseed();
        p.factors = Some(Factors::Both);
        p.totp_secret = Some("这不是Base32".to_string());
        assert!(matches!(
            build(&p),
            Err(BootstrapError::InvalidTotpSecret(_))
        ));
    }

    #[test]
    fn 无认证时不生成恢复码() {
        let mut p = base_preseed();
        p.factors = Some(Factors::None);
        p.password = None;
        let b = build(&p).expect("应当成功");
        assert!(b.recovery_codes.is_empty());
        assert!(b.config.auth.password_hash.is_none());
        assert!(b.config.auth.totp_secret.is_none());
    }

    #[test]
    fn 版本不匹配被拒绝() {
        let mut p = base_preseed();
        p.version = 99;
        assert!(matches!(
            build(&p),
            Err(BootstrapError::InvalidConfig(_))
        ));
    }

    #[test]
    fn 从文本解析预置配置() {
        let text = r#"{
            "version": 1,
            "apps": [
                {"name": "示例", "path": "C:\\Demo\\demo.exe",
                 "schedule": {"windows": [{"days": 127, "start": 0, "end": 1440}]}}
            ],
            "factors": "totp"
        }"#;
        let p = PreSeed::from_json(text).expect("应当解析成功");
        assert!(matches!(p.effective_factors(), Factors::Totp));
        assert_eq!(p.apps.len(), 1);
        let b = build(&p).expect("应当成功");
        assert!(b.config.auth.password_hash.is_none());
        assert!(b.config.auth.totp_secret.is_some());
        assert_eq!(b.config.apps[0].path, "C:\\Demo\\demo.exe");
    }

    #[test]
    fn 拒绝未知字段() {
        let text = r#"{"version": 1, "未知字段": 1}"#;
        assert!(matches!(
            PreSeed::from_json(text),
            Err(BootstrapError::Parse(_))
        ));
    }

    #[test]
    fn 拒绝非法程序路径() {
        let mut p = base_preseed();
        p.apps.push(AppRule::new(
            "示例",
            "C:\\Demo\\demo.txt",
            crate::config::Schedule::always(),
        ));
        assert!(matches!(
            build(&p),
            Err(BootstrapError::InvalidConfig(_))
        ));
    }
}
