//! RFC 6238 TOTP / RFC 4226 HOTP。
//!
//! 参数固定为 **SHA-1 / 6 位 / 30 秒**，与 Google Authenticator、Microsoft
//! Authenticator、1Password、KeePass 等全部兼容——刻意不支持"自定义算法"，
//! 因为那只会让用户无法用手机 App 扫码，安全性并没有提升。
//!
//! 校验时允许 ±1 个时间步（±30 s）的时钟漂移。

use hmac::{Hmac, Mac};
use sha1::Sha1;

/// 时间步长（秒）。
pub const STEP: u64 = 30;
/// 验证码位数。
pub const DIGITS: u32 = 6;

/// HOTP：给定种子与计数器，算出指定位数的验证码。
pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC 接受任意长度密钥");
    mac.update(&counter.to_be_bytes());
    let tag = mac.finalize().into_bytes();
    // 动态截断（RFC 4226 §5.3）
    let offset = (tag[tag.len() - 1] & 0x0f) as usize;
    let bin = ((tag[offset] as u32 & 0x7f) << 24)
        | ((tag[offset + 1] as u32) << 16)
        | ((tag[offset + 2] as u32) << 8)
        | (tag[offset + 3] as u32);
    bin % 10u32.pow(digits)
}

/// TOTP：按 Unix 秒计算验证码。
pub fn totp_code(secret: &[u8], unix: u64, digits: u32) -> u32 {
    hotp(secret, unix / STEP, digits)
}

/// 校验用户输入的验证码。
///
/// 成功返回命中的**时间步**（`unix / STEP`），调用方用它实现"同一时间步只能用一次"。
/// 失败返回 `None`。比较为恒定时间，避免逐位计时旁路。
pub fn verify(secret: &[u8], unix: u64, code: &str, skew_steps: u32) -> Option<u64> {
    let code = code.trim().replace(' ', "");
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let current = unix / STEP;
    let skew = skew_steps as u64;
    for delta in 0..=skew {
        // 先试当前步，再试前一步、后一步……（顺序无关，但避免无谓计算）
        let candidates = if delta == 0 {
            vec![current]
        } else {
            vec![current.saturating_sub(delta), current + delta]
        };
        for counter in candidates {
            let expect = format!("{:0width$}", hotp(secret, counter, DIGITS), width = DIGITS as usize);
            if crate::mac::ct_eq(expect.as_bytes(), code.as_bytes()) {
                return Some(counter);
            }
        }
    }
    None
}

/// 解析 Base32 种子（RFC 4648，可带空格/连字符/`=` 填充，大小写不敏感）。
pub fn base32_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8 + 1);
    for ch in s.chars() {
        if ch == ' ' || ch == '-' || ch == '=' || ch == '\t' || ch == '\n' || ch == '\r' {
            continue;
        }
        let v = match ch.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u8 - b'A',
            c @ '2'..='7' => c as u8 - b'2' + 26,
            other => return Err(format!("非法的 Base32 字符 {other:?}")),
        };
        buf = (buf << 5) | v as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    // 剩余位必须是 0 填充（否则说明种子被截断或写错）
    if bits > 0 && (buf & ((1u64 << bits) - 1)) != 0 {
        return Err("Base32 尾部填充位不为零".into());
    }
    Ok(out)
}

/// 生成 `otpauth://` 链接，供 WebUI 渲染二维码或手动输入。
pub fn otpauth_url(secret_b32: &str, account: &str, issuer: &str) -> String {
    let label = format!("{issuer}:{account}");
    format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        percent_encode(&label),
        secret_b32,
        percent_encode(issuer),
        DIGITS,
        STEP
    )
}

/// 极简 percent-encode（只保留 RFC 3986 unreserved）。
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 附录 B 的种子：ASCII "12345678901234567890"。
    const SEED: &[u8] = b"12345678901234567890";

    fn code8(unix: u64) -> u32 {
        totp_code(SEED, unix, 8)
    }

    #[test]
    fn rfc6238_官方向量() {
        // (时间, 期望的 8 位验证码)
        let vectors: [(u64, u32); 6] = [
            (59, 94_287_082),
            (1_111_111_109, 7_081_804),
            (1_111_111_111, 14_050_471),
            (1_234_567_890, 89_005_924),
            (2_000_000_000, 69_279_037),
            (20_000_000_000, 65_353_130),
        ];
        for (t, expect) in vectors {
            assert_eq!(code8(t), expect, "T={t}");
        }
    }

    #[test]
    fn rfc4226_hotp_向量() {
        // RFC 4226 附录 D，前 4 个
        let expect = [755_224u32, 287_082, 359_152, 969_429];
        for (i, e) in expect.iter().enumerate() {
            assert_eq!(hotp(SEED, i as u64, 6), *e, "counter={i}");
        }
    }

    #[test]
    fn 六位格式化补零() {
        let s = format!("{:06}", totp_code(SEED, 1_111_111_109, 6));
        assert_eq!(s, "081804");
    }

    #[test]
    fn 校验允许正负一个时间步() {
        let t = 1_700_000_000u64;
        let code = format!("{:06}", totp_code(SEED, t, DIGITS));
        assert_eq!(verify(SEED, t, &code, 1), Some(t / STEP));
        // 前一步/后一步的码在容差内也接受（返回其真实时间步）
        let prev = format!("{:06}", totp_code(SEED, t - STEP, DIGITS));
        assert_eq!(verify(SEED, t, &prev, 1), Some(t / STEP - 1));
        let next = format!("{:06}", totp_code(SEED, t + STEP, DIGITS));
        assert_eq!(verify(SEED, t, &next, 1), Some(t / STEP + 1));
        // 容差为 0 时不接受
        assert_eq!(verify(SEED, t, &prev, 0), None);
    }

    #[test]
    fn 拒绝错误长度与非法字符() {
        assert_eq!(verify(SEED, 0, "12345", 1), None);
        assert_eq!(verify(SEED, 0, "1234567", 1), None);
        assert_eq!(verify(SEED, 0, "abcdef", 1), None);
        assert_eq!(verify(SEED, 0, "", 1), None);
    }

    #[test]
    fn base32_往返() {
        for len in 1..40usize {
            let data: Vec<u8> = (0..len as u8).map(|b| b.wrapping_mul(37)).collect();
            let enc = crate::auth::base32_encode(&data);
            assert_eq!(base32_decode(&enc).unwrap(), data, "len={len}");
        }
    }

    #[test]
    fn base32_忽略分隔符与填充() {
        // "12345678901234567890"
        let enc = crate::auth::base32_encode(SEED);
        let spaced = format!("{}======", enc.to_lowercase());
        assert_eq!(base32_decode(&spaced).unwrap(), SEED);
        let grouped: String = enc
            .chars()
            .enumerate()
            .flat_map(|(i, c)| if i > 0 && i % 4 == 0 { vec![' ', c] } else { vec![c] })
            .collect();
        assert_eq!(base32_decode(&grouped).unwrap(), SEED);
    }

    #[test]
    fn base32_拒绝非法字符() {
        assert!(base32_decode("ABC1").is_err());
        assert!(base32_decode("AB!C").is_err());
    }

    #[test]
    fn otpauth_链接格式() {
        let url = otpauth_url("JBSWY3DPEHPK3PXP", "user", "NetGuard");
        assert!(url.starts_with("otpauth://totp/NetGuard%3Auser?secret=JBSWY3DPEHPK3PXP"));
        assert!(url.contains("algorithm=SHA1"));
        assert!(url.contains("digits=6"));
        assert!(url.contains("period=30"));
    }
}
