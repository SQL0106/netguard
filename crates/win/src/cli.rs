//! 命令行入口。
//!
//! 子命令：`service` / `console` / `setup` / `status` / `config sign|import` / `help`。

use std::io;
use std::path::PathBuf;

use netguard_core::bootstrap::{self, PreSeed};
use netguard_core::totp;
use netguard_core::{Config, Factors};

use crate::store::{Load, Store};

const HELP: &str = "\
NetGuard 应用级网络访问控制

用法：
  netguard.exe service                 以服务方式运行（由服务控制管理器启动）
  netguard.exe console                 在控制台运行，便于调试
  netguard.exe setup --preseed <文件>  从预置配置完成初始化
  netguard.exe status                  输出当前配置状态
  netguard.exe config sign --file <文件> [--write-mac <文件>]
  netguard.exe config import --file <文件>
  netguard.exe help

参数：
  --preseed <文件>     预置配置（JSON）
  --recovery-out <文件> 恢复码输出路径
  --quiet              不输出恢复码
";

fn parse_flag(args: &[String], name: &str) -> Option<String> {
    let position = args.iter().position(|arg| arg == name)?;
    args.get(position + 1).cloned()
}

/// 分派命令行。
pub fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|value| value.as_str()) {
        Some("service") => crate::svc::run_service(),
        Some("console") => crate::svc::run_console(),
        Some("setup") => setup(&args[1..]),
        Some("status") => status(),
        Some("config") => config_command(&args[1..]),
        Some("help") | Some("--help") | Some("-h") | None => {
            print!("{HELP}");
            Ok(())
        }
        Some(other) => {
            eprintln!("未知子命令：{other}");
            print!("{HELP}");
            Err(io::Error::new(io::ErrorKind::InvalidInput, "未知子命令"))
        }
    }
}

fn setup(args: &[String]) -> io::Result<()> {
    let preseed_path = parse_flag(args, "--preseed")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "缺少 --preseed 参数"))?;
    let text = std::fs::read_to_string(&preseed_path)?;
    let preseed = PreSeed::from_json(&text)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    let bootstrap = bootstrap::build(&preseed)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    let store = Store::open_default();
    store.save(&bootstrap.config)?;

    if let Some(path) = parse_flag(args, "--recovery-out") {
        std::fs::write(&path, bootstrap::recovery_text(&bootstrap.recovery_codes))?;
    }
    if !args.iter().any(|arg| arg == "--quiet") {
        if let Some(secret) = &bootstrap.totp_secret {
            let url = totp::otpauth_url(secret, "NetGuard", "NetGuard");
            println!("动态口令密钥：{secret}");
            println!("动态口令链接：{url}");
        }
        if !bootstrap.recovery_codes.is_empty() {
            println!("恢复码（仅显示一次）：");
            for code in &bootstrap.recovery_codes {
                println!("  {code}");
            }
        }
        println!("配置已写入 {}", store.paths().dir().display());
    }
    Ok(())
}

fn status() -> io::Result<()> {
    let store = Store::open_default();
    match store.load() {
        Load::Ok(config) => {
            println!("配置：有效");
            println!("总开关：{}", if config.enabled { "启用" } else { "停用" });
            println!("认证方式：{}", config.auth.factors.as_str());
            println!("受控程序：{} 个", config.apps.len());
            println!("拦截散列：{} 个", config.hashes.len());
            for app in &config.apps {
                println!("  - {} => {}", app.name, app.path);
            }
        }
        Load::Absent => println!("配置：未初始化"),
        Load::Tampered(reason) => {
            println!("配置：不可信（{reason}）");
            std::process::exit(2);
        }
    }
    Ok(())
}

fn config_command(args: &[String]) -> io::Result<()> {
    match args.first().map(|value| value.as_str()) {
        Some("sign") => {
            let file = parse_flag(args, "--file")
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "缺少 --file 参数"))?;
            let bytes = std::fs::read(&file)?;
            let store = Store::open_default();
            let signature = store.sign_text(&bytes)?;
            match parse_flag(args, "--write-mac") {
                Some(path) => std::fs::write(path, &signature)?,
                None => print!("{signature}"),
            }
            Ok(())
        }
        Some("import") => {
            let file = parse_flag(args, "--file")
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "缺少 --file 参数"))?;
            let bytes = std::fs::read(&file)?;
            let config: Config = serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            let store = Store::open_default();
            store.save(&config)?;
            println!("已导入并重新签名：{}", store.paths().config().display());
            Ok(())
        }
        _ => {
            eprintln!("用法：netguard.exe config sign|import --file <文件>");
            Err(io::Error::new(io::ErrorKind::InvalidInput, "未知 config 子命令"))
        }
    }
}

/// 供后续模块使用的占位，避免未使用导入告警。
#[allow(dead_code)]
fn _factors_name(factors: &Factors) -> &'static str {
    factors.as_str()
}

/// 命令行客户端入口。
pub fn client() -> io::Result<()> {
    crate::cli_client::client()
}

/// 预置配置的默认路径（安装器未指定时使用）。
#[allow(dead_code)]
pub fn default_preseed_path() -> PathBuf {
    PathBuf::from(r"C:\ProgramData\NetGuard\preseed.json")
}
