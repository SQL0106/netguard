//! 哈希守护与路径辅助。
//!
//! "哈希守护"要解决的问题：用户把被管程序**复制一份改个名**放到别处，
//! 按路径匹配的 WFP 过滤器就失效了。做法是列一份被管程序的 SHA-256，
//! 进程启动时（ETW 事件，或服务启动时对已运行进程做一次扫描）算哈希，
//! 命中黑名单就给**这个新路径**动态加一条过滤器。
//!
//! 本模块只提供纯逻辑（流式哈希、路径归一化、系统进程保护名单），
//! 进程挂起/恢复、ETW 订阅在 `crates/win`。

use std::io::Read;

use sha2::{Digest, Sha256};

/// 单个文件参与哈希的最大字节数（512 MiB）。超过就不算，避免被超大文件拖死。
pub const MAX_HASH_BYTES: u64 = 512 * 1024 * 1024;

/// 绝对不允许进入名单的进程（小写 basename）。
///
/// 误加这些会导致网络栈/登录会话整体失效，甚至开不了机：
/// - `svchost.exe`：承载 DNS/DHCP/BFE/NLA 等大批服务
/// - `lsass.exe`：登录与凭据
/// - `csrss.exe` / `wininit.exe` / `smss.exe` / `winlogon.exe`：会话与启动关键进程
/// - `services.exe`：服务控制管理器
/// - `system`：内核伪进程
///
/// 服务端在 `Config::validate()` 里硬拒，WebUI 也会把选择框置灰。
pub const PROTECTED_PROCESSES: &[&str] = &[
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "system",
    "system idle process",
    "registry",
    "memory compression",
];

/// 取路径最后一段并转小写（兼容 `\` 与 `/`）。
pub fn basename(path: &str) -> String {
    let trimmed = path.trim_end_matches(['\\', '/']);
    let last = trimmed
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(trimmed)
        .to_string();
    last.to_ascii_lowercase()
}

/// 该路径是否指向受保护的系统进程。
pub fn is_protected(path: &str) -> bool {
    let name = basename(path);
    PROTECTED_PROCESSES.contains(&name.as_str())
}

/// 路径归一化，用于"同一个 exe"的比较（大小写不敏感、去尾部斜杠、统一分隔符）。
///
/// 注意：**不**做 `..` 折叠、不解析软链接——Windows 侧的 `FwpmGetAppIdFromFileName0`
/// 才是最终真相，这里只用于配置去重与展示。
pub fn normalize_path(path: &str) -> String {
    path.trim()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

/// 两个路径是否指同一目标（按 [`normalize_path`] 比较）。
pub fn same_path(a: &str, b: &str) -> bool {
    normalize_path(a) == normalize_path(b)
}

/// 流式 SHA-256 的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashOutcome {
    /// 成功，值为小写十六进制。
    Hashed(String),
    /// 文件大于 [`MAX_HASH_BYTES`]，放弃。
    TooLarge,
}

/// 流式哈希一个 reader，最多读 `limit` 字节。
///
/// 用 64 KiB 缓冲，内存占用与文件大小无关——这一点很重要：守护线程会在
/// **进程被挂起**的窗口里跑它，任何大分配都会拉长挂起时间。
pub fn hash_reader<R: Read>(reader: &mut R, limit: u64) -> std::io::Result<HashOutcome> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > limit {
            return Ok(HashOutcome::TooLarge);
        }
        hasher.update(&buf[..n]);
    }
    Ok(HashOutcome::Hashed(crate::mac::to_hex(&hasher.finalize())))
}

/// 对内存中的数据求哈希（测试与小文件用）。
pub fn hash_bytes(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    crate::mac::to_hex(&h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 取文件名() {
        assert_eq!(basename(r"C:\Windows\System32\SVCHOST.EXE"), "svchost.exe");
        assert_eq!(basename("C:/a/b/foo.exe"), "foo.exe");
        assert_eq!(basename("foo.exe"), "foo.exe");
        assert_eq!(basename(r"C:\a\b\"), "b");
    }

    #[test]
    fn 保护名单() {
        assert!(is_protected(r"C:\Windows\System32\svchost.exe"));
        assert!(is_protected(r"C:\Windows\System32\LSASS.EXE"));
        assert!(!is_protected(r"C:\Program Files\Foo\foo.exe"));
        assert!(!is_protected(r"C:\Windows\System32\notepad.exe"));
    }

    #[test]
    fn 路径归一() {
        assert!(same_path(r"C:\A\B.EXE", "c:/a/b.exe"));
        assert!(!same_path(r"C:\A\B.EXE", r"C:\A\C.EXE"));
        assert_eq!(normalize_path(r"C:\A\B\"), r"c:\a\b");
    }

    #[test]
    fn 流式哈希等于一次性哈希() {
        let data = vec![7u8; 200_000];
        let mut cursor = std::io::Cursor::new(data.clone());
        match hash_reader(&mut cursor, MAX_HASH_BYTES).unwrap() {
            HashOutcome::Hashed(h) => assert_eq!(h, hash_bytes(&data)),
            HashOutcome::TooLarge => panic!("不该超限"),
        }
    }

    #[test]
    fn 超限即放弃() {
        let data = vec![1u8; 1000];
        let mut cursor = std::io::Cursor::new(data);
        assert_eq!(
            hash_reader(&mut cursor, 500).unwrap(),
            HashOutcome::TooLarge
        );
    }

    #[test]
    fn 空文件哈希() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        match hash_reader(&mut cursor, MAX_HASH_BYTES).unwrap() {
            HashOutcome::Hashed(h) => {
                assert_eq!(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            }
            HashOutcome::TooLarge => panic!(),
        }
    }
}
