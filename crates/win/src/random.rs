//! 随机数工具：仅供会话标识与盐值使用。

use std::io;

/// 生成 `n` 个随机字节。
pub fn bytes(n: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; n];
    if n == 0 {
        return buffer;
    }
    if getrandom::getrandom(&mut buffer).is_err() {
        // 极端情况下退回系统时间与地址混合，保证不会得到全零标识。
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos() as u64)
            .unwrap_or(0);
        let mut state = seed ^ (&buffer as *const _ as u64);
        for byte in buffer.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *byte = (state >> 33) as u8;
        }
    }
    buffer
}

/// 生成 `n` 字节随机数据的十六进制表示（长度 `2n`）。
pub fn hex(n: usize) -> String {
    let mut out = String::with_capacity(n * 2);
    for byte in bytes(n) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// 便捷包装：把随机错误转成 `io::Error`。
pub fn try_bytes(n: usize) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; n];
    getrandom::getrandom(&mut buffer).map_err(|_| io::Error::other("随机数生成失败"))?;
    Ok(buffer)
}
