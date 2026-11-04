//! NetGuard 的纯逻辑核心。
//!
//! 这个 crate **不含任何平台 API**，因此可以在 Linux / Windows 上直接 `cargo test`。
//! 所有涉及 Windows 的东西（WFP、服务、ETW、DPAPI、Win32 时间）都在 `crates/win`。
//!
//! 模块划分：
//! - [`config`]   配置模型（同时决定 HMAC 规范化字节）
//! - [`schedule`] 时间窗判定（跨午夜、按周重复、零轮询的下一边界计算）
//! - [`totp`]     RFC 6238 TOTP（SHA-1 / 6 位 / 30 秒，保证手机 App 兼容）
//! - [`auth`]     口令与恢复码（Argon2id）、失败计数与锁定
//! - [`mac`]      配置完整性签名（HMAC-SHA256）
//! - [`guard`]    哈希守护用的辅助函数（SHA-256 流式、系统进程保护名单）

pub mod auth;
pub mod config;
pub mod guard;
pub mod mac;
pub mod schedule;
pub mod totp;

pub use config::{AppRule, AuthConfig, Config, Factors, Schedule, TimeWindow};
