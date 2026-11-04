//! `netguard.exe`：服务宿主、控制台运行与初始化命令。

#![cfg_attr(all(windows, not(test)), windows_subsystem = "console")]

fn main() {
    #[cfg(windows)]
    {
        if let Err(error) = netguard_win::run() {
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
