//! NetGuard 的 Windows 侧实现。
//!
//! 纯逻辑部分（排程、TOTP、口令、签名、哈希判断）位于 `netguard-core`，
//! 本 crate 只负责与其交互的系统能力：文件存储、DPAPI、WFP 过滤器、
//! 服务宿主、ETW 订阅与本地 WebUI。
//!
//! 所有模块都只在 Windows 目标上参与编译；在其它平台上本 crate 为空，
//! 以便工作区在 Linux 上仍可直接 `cargo test`。

#[cfg(windows)]
pub mod cli;
#[cfg(windows)]
pub mod cli_client;
#[cfg(windows)]
pub mod dpapi;
#[cfg(windows)]
pub mod endpoint;
#[cfg(windows)]
pub mod http;
#[cfg(windows)]
pub mod engine;
#[cfg(windows)]
pub mod log;
#[cfg(windows)]
pub mod paths;
#[cfg(windows)]
pub mod random;
#[cfg(windows)]
pub mod session;
#[cfg(windows)]
pub mod store;
#[cfg(windows)]
pub mod ticker;
#[cfg(windows)]
pub mod wfp;

/// 进程入口。
#[cfg(windows)]
pub fn run() -> std::io::Result<()> {
    cli::main()
}
