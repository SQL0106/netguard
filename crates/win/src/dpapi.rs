//! DPAPI（机器范围）加解密封装。
//!
//! 用于保护签名密钥与动态口令种子：即便配置文件被复制到其它机器，
//! 也无法解密其中受保护的部分。

use std::ffi::c_void;
use std::io;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE,
    CRYPTPROTECT_UI_FORBIDDEN,
};

/// 机器范围、禁止弹窗。
const FLAGS: u32 = CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN;

/// 受保护文本的前缀。
pub const PREFIX: &str = "dpapi:";

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    }
}

/// 加密字节串。
pub fn protect(data: &[u8]) -> io::Result<Vec<u8>> {
    let input = blob(data);
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            FLAGS,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData as *mut c_void);
    }
    Ok(bytes)
}

/// 解密字节串。
pub fn unprotect(data: &[u8]) -> io::Result<Vec<u8>> {
    let input = blob(data);
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            FLAGS,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData as *mut c_void);
    }
    Ok(bytes)
}

fn to_hex(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn from_hex(text: &str) -> io::Result<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "十六进制长度不是偶数"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let hi = (bytes[index] as char)
            .to_digit(16)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "非法十六进制字符"))?;
        let lo = (bytes[index + 1] as char)
            .to_digit(16)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "非法十六进制字符"))?;
        out.push(((hi << 4) | lo) as u8);
        index += 2;
    }
    Ok(out)
}

/// 加密并编码为 `dpapi:<hex>`，便于写入 JSON。
pub fn protect_text(data: &[u8]) -> io::Result<String> {
    Ok(format!("{PREFIX}{}", to_hex(&protect(data)?)))
}

/// 解码 `dpapi:<hex>` 并解密。
pub fn unprotect_text(text: &str) -> io::Result<Vec<u8>> {
    let body = text
        .strip_prefix(PREFIX)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "缺少 dpapi 前缀"))?;
    unprotect(&from_hex(body)?)
}

/// 判断文本是否已经是受保护形式。
pub fn is_protected(text: &str) -> bool {
    text.starts_with(PREFIX)
}
