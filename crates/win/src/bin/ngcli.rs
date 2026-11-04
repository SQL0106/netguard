//! `ngcli.exe`：本地 WebUI 的精简命令行客户端。
//!
//! 与服务共享同一套 HTTP 接口，不另开命名管道。

fn main() {
    #[cfg(windows)]
    {
        if let Err(error) = netguard_win::cli::client() {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
    #[cfg(not(windows))]
    {
        eprintln!("NetGuard 仅支持 Windows");
        std::process::exit(1);
    }
}
