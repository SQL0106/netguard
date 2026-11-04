//! 认证：口令 + TOTP（可选组合）、恢复码、失败锁定。
//!
//! 设计原则：
//! - 口令用 **Argon2id**（19 MiB / t=2 / p=1），存储为 PHC 字符串，不自己拼哈希格式。
//! - TOTP 严格 **RFC 6238**（SHA-1 / 6 位 / 30 秒 / ±1 步容差），保证任何手机 App 都能扫。
//! - 防重放：同一时间步的验证码只能用一次（`last_totp_counter` 单调递增）。
//! - 失败 5 次锁 15 分钟，计数与锁定期都落盘（重启不重置，堵"重启试密码"）。
//!
//! 本模块**不做**会话、不做 HTTP，只做"验证一次凭据"这件的纯逻辑。

use serde::{Deserialize, Serialize};

use crate::mac::ct_eq;
use crate::totp;

/// 失败多少次后锁定。
pub const MAX_FAILURES: u32 = 5;
/// 锁定时长（秒）。
pub const LOCK_SECS: i64 = 900;
/// 默认发放的恢复码数量。
pub const RECOVERY_CODE_COUNT: usize = 10;

/// 启用哪些认证因子。安装时由用户选择，之后改它需要先通过现有因子验证。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Factors {
    /// 完全不要认证（仅回环可访问的桌面场景才建议）。
    None,
    /// 只要密码。
    Password,
    /// 只要 TOTP。
    Totp,
    /// 两者都要。
    Both,
}

impl Default for Factors {
    fn default() -> Self {
        Factors::None
    }
}

impl Factors {
    pub fn needs_password(self) -> bool {
        matches!(self, Factors::Password | Factors::Both)
    }

    pub fn needs_totp(self) -> bool {
        matches!(self, Factors::Totp | Factors::Both)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Factors::None => "none",
            Factors::Password => "password",
            Factors::Totp => "totp",
            Factors::Both => "both",
        }
    }
}

/// 认证配置。随 [`crate::config::Config`] 一起被 HMAC 签名，因此改它必须走正常配置通道。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// 启用哪些因子。缺省 = 不需要认证（与 [`Factors::default`] 一致）。
    #[serde(default)]
    pub factors: Factors,
    /// Argon2id PHC 字符串。
    #[serde(default)]
    pub password_hash: Option<String>,
    /// TOTP 种子，Base32（不含空格）。生产环境由 Windows 层用 DPAPI 机器密钥再包一层。
    #[serde(default)]
    pub totp_secret: Option<String>,
    /// 恢复码的 Argon2id 哈希（存哈希，不存明文）。
    #[serde(default)]
    pub recovery_hashes: Vec<String>,
    /// 连续失败次数（落盘）。
    #[serde(default)]
    pub failures: u32,
    /// 锁定截止时间（Unix 秒，落盘）。
    #[serde(default)]
    pub locked_until: Option<i64>,
    /// 上一次成功使用的 TOTP 时间步，用于拒绝同码二次使用。
    #[serde(default)]
    pub last_totp_counter: Option<u64>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            factors: Factors::None,
            password_hash: None,
            totp_secret: None,
            recovery_hashes: Vec::new(),
            failures: 0,
            locked_until: None,
            last_totp_counter: None,
        }
    }
}

/// 登录失败原因。HTTP 层据此决定状态码与提示文案。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginError {
    /// 锁定中，附带剩余秒数。
    Locked(i64),
    MissingPassword,
    MissingTotp,
    BadPassword,
    BadTotp,
    /// 该验证码的时间步已经被用过（重放）。
    TotpReplayed,
    /// 配置本身损坏，无法验证。
    Corrupt(String),
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoginError::Locked(secs) => write!(f, "尝试次数过多，请 {secs} 秒后再试"),
            LoginError::MissingPassword => write!(f, "需要密码"),
            LoginError::MissingTotp => write!(f, "需要动态验证码"),
            LoginError::BadPassword => write!(f, "密码错误"),
            LoginError::BadTotp => write!(f, "动态验证码错误"),
            LoginError::TotpReplayed => write!(f, "该验证码已使用过，请等下一个"),
            LoginError::Corrupt(e) => write!(f, "认证配置损坏：{e}"),
        }
    }
}

impl std::error::Error for LoginError {}

impl AuthConfig {
    /// 结构校验：要求的因子必须有对应凭据。
    pub fn validate(&self) -> Result<(), String> {
        if self.factors.needs_password() {
            let h = self
                .password_hash
                .as_deref()
                .ok_or("已启用密码认证，但没有设置密码")?;
            argon2::PasswordHash::new(h).map_err(|e| format!("密码哈希无法解析：{e}"))?;
        }
        if self.factors.needs_totp() {
            let s = self
                .totp_secret
                .as_deref()
                .ok_or("已启用 TOTP 认证，但没有绑定验证器")?;
            let raw = totp::base32_decode(s).map_err(|e| format!("TOTP 种子非法：{e}"))?;
            if raw.len() < 10 {
                return Err("TOTP 种子太短（至少 80 位）".into());
            }
        }
        for h in &self.recovery_hashes {
            argon2::PasswordHash::new(h).map_err(|e| format!("恢复码哈希无法解析：{e}"))?;
        }
        Ok(())
    }

    /// 当前是否处于锁定期。
    pub fn is_locked(&self, now: i64) -> Option<i64> {
        match self.locked_until {
            Some(t) if t > now => Some(t - now),
            _ => None,
        }
    }

    /// 验证一次登录。成功会清空失败计数、记录 TOTP 时间步；失败会累加计数并在
    /// 达到 [`MAX_FAILURES`] 时进入锁定。
    ///
    /// 注意：这是**有副作用**的：调用方必须在返回后把整个 `Config`（含本结构）
    /// 落盘，否则重启后可重置计数。
    pub fn check_login(
        &mut self,
        now: i64,
        password: Option<&str>,
        totp_code: Option<&str>,
    ) -> Result<(), LoginError> {
        if let Some(secs) = self.is_locked(now) {
            return Err(LoginError::Locked(secs));
        }

        let mut counter_used: Option<u64> = None;

        if self.factors.needs_password() {
            let pw = password.ok_or(LoginError::MissingPassword)?;
            let hash = self
                .password_hash
                .as_deref()
                .ok_or_else(|| LoginError::Corrupt("缺少密码哈希".into()))?;
            if !verify_password(pw, hash) {
                self.register_failure(now);
                return Err(LoginError::BadPassword);
            }
        }

        if self.factors.needs_totp() {
            let code = totp_code.ok_or(LoginError::MissingTotp)?;
            let secret_b32 = self
                .totp_secret
                .as_deref()
                .ok_or_else(|| LoginError::Corrupt("缺少 TOTP 种子".into()))?;
            let secret = totp::base32_decode(secret_b32)
                .map_err(|e| LoginError::Corrupt(format!("TOTP 种子非法：{e}")))?;
            match totp::verify(&secret, now as u64, code, 1) {
                Some(counter) => {
                    if let Some(last) = self.last_totp_counter {
                        if counter <= last {
                            self.register_failure(now);
                            return Err(LoginError::TotpReplayed);
                        }
                    }
                    counter_used = Some(counter);
                }
                None => {
                    self.register_failure(now);
                    return Err(LoginError::BadTotp);
                }
            }
        }

        // 全部因子通过。
        self.failures = 0;
        self.locked_until = None;
        if let Some(c) = counter_used {
            self.last_totp_counter = Some(c);
        }
        Ok(())
    }

    /// 累加失败计数，必要时锁定。达到上限后计数清零、锁定期开始
    /// （解锁后又是完整的 5 次机会）。
    pub fn register_failure(&mut self, now: i64) {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= MAX_FAILURES {
            self.failures = 0;
            self.locked_until = Some(now + LOCK_SECS);
        }
    }

    /// 用恢复码登录：命中即消耗该码（从列表移除），并清空失败计数。
    pub fn consume_recovery_code(&mut self, code: &str, now: i64) -> Result<(), LoginError> {
        if let Some(secs) = self.is_locked(now) {
            return Err(LoginError::Locked(secs));
        }
        let norm = normalize_recovery_code(code);
        for i in 0..self.recovery_hashes.len() {
            if verify_password(&norm, &self.recovery_hashes[i]) {
                self.recovery_hashes.remove(i);
                self.failures = 0;
                self.locked_until = None;
                return Ok(());
            }
        }
        self.register_failure(now);
        Err(LoginError::BadPassword)
    }
}

/// 生成 Argon2id 哈希（PHC 字符串）。
pub fn hash_password(password: &str) -> Result<String, String> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).map_err(|e| format!("取随机数失败：{e}"))?;
    let salt = SaltString::encode_b64(&salt).map_err(|e| format!("生成盐失败：{e}"))?;
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("计算哈希失败：{e}"))
}

/// 校验口令。
pub fn verify_password(password: &str, phc: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    match PasswordHash::new(phc) {
        Ok(parsed) => argon2::Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// 去掉恢复码里的分隔符/空格并转大写。
pub fn normalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// 生成一批恢复码（明文只返回一次，落盘的是哈希）。
pub fn new_recovery_codes(count: usize) -> Result<Vec<String>, String> {
    let mut out = Vec::with_capacity(count);
    let mut seen = std::collections::BTreeSet::new();
    while out.len() < count {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).map_err(|e| format!("取随机数失败：{e}"))?;
        let raw = base32_encode(&buf);
        let code = format!("{}-{}", &raw[0..5], &raw[5..10]);
        // 极小概率重复；去重后继续补。
        if seen.insert(code.clone()) {
            out.push(code);
        }
    }
    Ok(out)
}

/// 生成 TOTP 种子（Base32，20 字节 = 160 位，标准长度）。
pub fn new_totp_secret() -> Result<String, String> {
    let mut buf = [0u8; 20];
    getrandom::getrandom(&mut buf).map_err(|e| format!("取随机数失败：{e}"))?;
    Ok(base32_encode(&buf))
}

/// Base32 编码（RFC 4648，无填充，大写）。
pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buf: u64 = 0;
    let mut bits = 0;
    for &b in data {
        buf = (buf << 8) | b as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// 恒定时间比较字符串（恢复码兜底路径用）。
pub fn ct_eq_str(a: &str, b: &str) -> bool {
    ct_eq(a.as_bytes(), b.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_password(pw: &str) -> AuthConfig {
        AuthConfig {
            factors: Factors::Password,
            password_hash: Some(hash_password(pw).unwrap()),
            totp_secret: None,
            recovery_hashes: Vec::new(),
            failures: 0,
            locked_until: None,
            last_totp_counter: None,
        }
    }

    #[test]
    fn 密码正确与错误() {
        let mut c = cfg_with_password("hunter2");
        assert!(c.check_login(1000, Some("hunter2"), None).is_ok());
        assert_eq!(
            c.check_login(1000, Some("hunter3"), None),
            Err(LoginError::BadPassword)
        );
    }

    #[test]
    fn 连续五次失败后锁定十五分钟() {
        let mut c = cfg_with_password("pw");
        for _ in 0..MAX_FAILURES {
            let _ = c.check_login(1000, Some("bad"), None);
        }
        assert_eq!(c.check_login(1000, Some("pw"), None), Err(LoginError::Locked(LOCK_SECS)));
        // 锁定期内即使密码正确也拒绝
        assert!(matches!(
            c.check_login(1000 + LOCK_SECS - 1, Some("pw"), None),
            Err(LoginError::Locked(_))
        ));
        // 到期后恢复
        assert!(c.check_login(1000 + LOCK_SECS, Some("pw"), None).is_ok());
        assert_eq!(c.failures, 0);
    }

    #[test]
    fn totp_同码二次使用被拒() {
        let secret = new_totp_secret().unwrap();
        let raw = totp::base32_decode(&secret).unwrap();
        let mut c = AuthConfig {
            factors: Factors::Totp,
            totp_secret: Some(secret),
            ..Default::default()
        };
        let now = 1111111111u64;
        let code = format!("{:06}", totp::totp_code(&raw, now, totp::DIGITS));
        assert!(c.check_login(now as i64, None, Some(&code)).is_ok());
        assert_eq!(
            c.check_login(now as i64, None, Some(&code)),
            Err(LoginError::TotpReplayed)
        );
        // 下一个时间步可用
        let next = now + totp::STEP;
        let code2 = format!("{:06}", totp::totp_code(&raw, next, totp::DIGITS));
        assert!(c.check_login(next as i64, None, Some(&code2)).is_ok());
    }

    #[test]
    fn 双因子都要满足() {
        let secret = new_totp_secret().unwrap();
        let raw = totp::base32_decode(&secret).unwrap();
        let mut c = AuthConfig {
            factors: Factors::Both,
            password_hash: Some(hash_password("pw").unwrap()),
            totp_secret: Some(secret),
            ..Default::default()
        };
        let now = 1200000000u64;
        let code = format!("{:06}", totp::totp_code(&raw, now, totp::DIGITS));
        assert_eq!(
            c.check_login(now as i64, Some("pw"), None),
            Err(LoginError::MissingTotp)
        );
        assert_eq!(
            c.check_login(now as i64, None, Some(&code)),
            Err(LoginError::MissingPassword)
        );
        assert!(c.check_login(now as i64, Some("pw"), Some(&code)).is_ok());
    }

    #[test]
    fn 恢复码一次性() {
        let codes = new_recovery_codes(3).unwrap();
        let mut c = AuthConfig {
            factors: Factors::Password,
            password_hash: Some(hash_password("pw").unwrap()),
            recovery_hashes: codes
                .iter()
                .map(|s| hash_password(&normalize_recovery_code(s)).unwrap())
                .collect(),
            ..Default::default()
        };
        assert!(c.consume_recovery_code(&codes[0], 0).is_ok());
        assert_eq!(c.recovery_hashes.len(), 2);
        assert!(c.consume_recovery_code(&codes[0], 0).is_err());
        // 大小写与分隔符不敏感
        assert!(c.consume_recovery_code(&codes[1].to_lowercase(), 0).is_ok());
    }

    #[test]
    fn 恢复码格式() {
        let codes = new_recovery_codes(RECOVERY_CODE_COUNT).unwrap();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        for c in &codes {
            assert_eq!(c.len(), 11); // 5 + '-' + 5
            assert_eq!(c.matches('-').count(), 1);
        }
    }

    #[test]
    fn 校验要求对应凭据() {
        let c = AuthConfig {
            factors: Factors::Both,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }
}
