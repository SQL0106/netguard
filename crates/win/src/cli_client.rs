//! `ngcli.exe` 的客户端实现。

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::endpoint::ADDR;

const HELP: &str = "\
ngcli —— NetGuard 命令行客户端

用法：
  ngcli status                 查看运行状态
  ngcli log [行数]             查看最近日志
  ngcli login                  登录并保存会话
       --password-stdin        从标准输入读取密码
       --totp <六位口令>        动态口令
  ngcli override <分钟>        临时放行
  ngcli config                 查看当前配置
  ngcli logout                 退出并删除本地会话
  ngcli help
";

fn cookie_path() -> std::path::PathBuf {
    crate::paths::Paths::new().file("cli.session")
}

fn read_cookie() -> Option<String> {
    let text = std::fs::read_to_string(cookie_path()).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn parse_arg(args: &[String], name: &str) -> Option<String> {
    let position = args.iter().position(|arg| arg == name)?;
    args.get(position + 1).cloned()
}

struct Response {
    status: u16,
    body: String,
    cookie: Option<String>,
}

fn request(
    method: &str,
    path: &str,
    body: Option<&str>,
    cookie: Option<&str>,
) -> io::Result<Response> {
    let mut stream = TcpStream::connect_timeout(&ADDR.parse().expect("固定地址"), Duration::from_secs(3))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nAccept: application/json\r\n"
    );
    if let Some(value) = cookie {
        head.push_str(&format!("Cookie: {value}\r\n"));
    }
    if let Some(payload) = body {
        head.push_str("Content-Type: application/json\r\n");
        head.push_str(&format!("Content-Length: {}\r\n", payload.len()));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    if let Some(payload) = body {
        stream.write_all(payload.as_bytes())?;
    }
    stream.flush()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw).to_string();
    let (header_part, body_part) = match text.find("\r\n\r\n") {
        Some(index) => (&text[..index], &text[index + 4..]),
        None => (text.as_str(), ""),
    };
    let mut lines = header_part.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let mut cookie = None;
    for line in lines {
        if let Some(rest) = line.strip_prefix("Set-Cookie: ") {
            if let Some((pair, _)) = rest.split_once(';') {
                cookie = Some(pair.to_string());
            }
        }
    }
    Ok(Response {
        status,
        body: body_part.to_string(),
        cookie,
    })
}

fn ensure_ok(response: &Response) -> io::Result<()> {
    if (200..300).contains(&response.status) {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "请求失败（HTTP {}）：{}",
            response.status,
            response.body.trim()
        )))
    }
}

/// 入口。
pub fn client() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cookie = read_cookie();
    match args.first().map(|value| value.as_str()) {
        Some("status") => {
            let response = request("GET", "/api/state", None, cookie.as_deref())?;
            ensure_ok(&response)?;
            println!("{}", response.body);
            Ok(())
        }
        Some("config") => {
            let response = request("GET", "/api/config", None, cookie.as_deref())?;
            ensure_ok(&response)?;
            println!("{}", response.body);
            Ok(())
        }
        Some("log") => {
            let count = args.get(1).cloned().unwrap_or_else(|| "50".to_string());
            let response = request("GET", &format!("/api/log?lines={count}"), None, cookie.as_deref())?;
            ensure_ok(&response)?;
            println!("{}", response.body);
            Ok(())
        }
        Some("login") => {
            let mut password = String::new();
            if args.iter().any(|arg| arg == "--password-stdin") {
                io::stdin().read_to_string(&mut password)?;
            }
            let totp_code = parse_arg(&args, "--totp");
            let mut payload = String::from("{");
            let mut parts: Vec<String> = Vec::new();
            if !password.trim().is_empty() {
                parts.push(format!(
                    "\"password\":{}",
                    serde_json::to_string(password.trim()).unwrap_or_default()
                ));
            }
            if let Some(code) = &totp_code {
                parts.push(format!(
                    "\"totp\":{}",
                    serde_json::to_string(code).unwrap_or_default()
                ));
            }
            payload.push_str(&parts.join(","));
            payload.push('}');
            let response = request("POST", "/api/login", Some(&payload), None)?;
            ensure_ok(&response)?;
            match response.cookie {
                Some(pair) => {
                    let path = cookie_path();
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(&path, pair.as_bytes())?;
                    println!("已登录，会话保存在 {}", path.display());
                }
                None => println!("已登录，但服务未返回会话"),
            }
            Ok(())
        }
        Some("logout") => {
            let _ = request("POST", "/api/logout", Some("{}"), cookie.as_deref());
            let _ = std::fs::remove_file(cookie_path());
            println!("已退出");
            Ok(())
        }
        Some("override") => {
            let minutes: u32 = args
                .get(1)
                .and_then(|value| value.parse().ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "缺少分钟数"))?;
            let payload = format!("{{\"minutes\":{minutes}}}");
            let response = request("POST", "/api/override", Some(&payload), cookie.as_deref())?;
            ensure_ok(&response)?;
            println!("{}", response.body);
            Ok(())
        }
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
