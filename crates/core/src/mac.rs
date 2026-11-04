//! 配置完整性：HMAC-SHA256 签名。
//!
//! 威胁模型：有人直接改 `config.json` 把被管应用删掉、把时间窗删掉、把认证关掉。
//! 因为签名密钥只存在 SYSTEM 可读的文件里（Windows 层用 DPAPI 保护），
//! 普通用户/管理员改配置正文后签名即失效 → 服务 **fail-closed**：
//! 保持/进入封锁态并在 WebUI 上显示红条，而不是傻乎乎地按被改过的配置放行。
//!
//! 注意：这不是防御内核级攻击，只是把"记事本改文件"这条最省事的绕过路径堵死。

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::config::Config;

/// 规范化字节：就是 `serde_json::to_vec` 的结果。
///
/// 之所以固定成 JSON 字节而不是"排序后的字段拼接"，是为了让签名与落盘内容
/// **一一对应**：任何人都能用 `sha256`/脚本复现，出了冤枉也好对账。
pub fn canonical_bytes(cfg: &Config) -> Result<Vec<u8>, String> {
    serde_json::to_vec(cfg).map_err(|e| format!("配置序列化失败：{e}"))
}

/// 计算签名，返回小写十六进制。
pub fn sign(key: &[u8], cfg: &Config) -> Result<String, String> {
    let bytes = canonical_bytes(cfg)?;
    sign_bytes(key, &bytes)
}

/// 对任意字节计算 HMAC，返回小写十六进制。
pub fn sign_bytes(key: &[u8], bytes: &[u8]) -> Result<String, String> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|e| format!("HMAC 初始化失败：{e}"))?;
    mac.update(bytes);
    Ok(to_hex(&mac.finalize().into_bytes()))
}

/// 落盘签名行的格式标记。
pub const SIGNATURE_TAG: &str = "v1";

/// 把十六进制摘要包装成落盘格式（含结尾换行）。
pub fn format_signature(hex: &str) -> String {
    format!("{SIGNATURE_TAG}:{hex}\n")
}

/// 解析落盘签名行，取出十六进制摘要部分。
///
/// 落盘格式是 `v1:<64 位十六进制>`；校验时只拿摘要去比，
/// 若直接把它整行丢进 [`verify_bytes`] 会因长度不同而永远失败。
pub fn parse_signature(text: &str) -> Option<&str> {
    let text = text.trim();
    let (tag, hex) = text.split_once(':')?;
    if tag != SIGNATURE_TAG {
        return None;
    }
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(hex)
}

/// 校验签名（恒定时间比较）。
pub fn verify(key: &[u8], cfg: &Config, mac_hex: &str) -> bool {
    match sign(key, cfg) {
        Ok(expect) => ct_eq(expect.as_bytes(), mac_hex.trim().to_ascii_lowercase().as_bytes()),
        Err(_) => false,
    }
}

/// 校验任意字节的签名。
pub fn verify_bytes(key: &[u8], bytes: &[u8], mac_hex: &str) -> bool {
    match sign_bytes(key, bytes) {
        Ok(expect) => ct_eq(expect.as_bytes(), mac_hex.trim().to_ascii_lowercase().as_bytes()),
        Err(_) => false,
    }
}

/// 生成 `n` 字节随机数的十六进制串（配置签名密钥、会话 ID 等）。
pub fn random_hex(n: usize) -> Result<String, String> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).map_err(|e| format!("取随机数失败：{e}"))?;
    Ok(to_hex(&buf))
}

pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// 恒定时间比较。长度不同直接 false（长度不是敏感信息）。
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// SHA-256 摘要（十六进制小写）。
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    to_hex(&h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 签名可复现且可校验() {
        let cfg = Config::default();
        let key = b"0123456789abcdef0123456789abcdef";
        let a = sign(key, &cfg).unwrap();
        let b = sign(key, &cfg).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(verify(key, &cfg, &a));
        assert!(verify(key, &cfg, &a.to_uppercase())); // 宽进
    }

    #[test]
    fn 改一个字节即失效() {
        let key = b"k";
        let cfg = Config::default();
        let mac = sign(key, &cfg).unwrap();
        let mut cfg2 = cfg.clone();
        cfg2.enabled = !cfg2.enabled;
        assert!(!verify(key, &cfg2, &mac));
    }

    #[test]
    fn 换密钥即失效() {
        let cfg = Config::default();
        let mac = sign(b"key1", &cfg).unwrap();
        assert!(!verify(b"key2", &cfg, &mac));
    }

    #[test]
    fn 签名行可往返解析() {
        let hex = "a".repeat(64);
        let line = format_signature(&hex);
        assert_eq!(parse_signature(&line), Some(hex.as_str()));
        assert_eq!(parse_signature(&format!("  v1:{hex}  ")), Some(hex.as_str()));
    }

    #[test]
    fn 无前缀或前缀不符的签名行被拒() {
        let hex = "a".repeat(64);
        assert_eq!(parse_signature(&hex), None); // 只有摘要，缺 v1: 前缀
        assert_eq!(parse_signature(&format!("v2:{hex}")), None);
        assert_eq!(parse_signature(&format!("v1:{}", "a".repeat(63))), None);
        assert_eq!(parse_signature(&format!("v1:{}", "z".repeat(64))), None);
        assert_eq!(parse_signature(""), None);
    }

    #[test]
    fn 恒定时间比较() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn 空签名被拒() {
        let cfg = Config::default();
        assert!(!verify(b"k", &cfg, ""));
        assert!(!verify(b"k", &cfg, "zz"));
    }
}
