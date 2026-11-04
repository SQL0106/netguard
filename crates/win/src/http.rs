//! 本地 HTTP 接口与 WebUI。
//!
//! 服务只监听回环地址 `127.0.0.1:47811`。除状态查询与登录外，所有接口都需要有效会话；
//! 修改配置、临时放行等敏感操作还要求会话处于「提升验证」有效期内，或在本请求中
//! 重新提供凭据。

#![cfg(windows)]

use std::io;
use std::io::Read;
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server};

use netguard_core::bootstrap::{self, PreSeed};
use netguard_core::{auth, totp, Factors};

use crate::engine::Engine;
use crate::endpoint;
use crate::session::{self, Sessions};

const MAX_BODY: usize = 1 << 20;
const SETUP_WINDOW_SECS: i64 = 600;

const INDEX_HTML: &[u8] = include_bytes!("../../../web/index.html");
const APP_JS: &[u8] = include_bytes!("../../../web/app.js");
const STYLE_CSS: &[u8] = include_bytes!("../../../web/style.css");

pub struct Api {
    engine: Arc<Engine>,
    sessions: Sessions,
    setup_until: std::sync::Mutex<i64>,
}

impl Api {
    pub fn new(engine: Arc<Engine>) -> Api {
        let until = now() + SETUP_WINDOW_SECS;
        Api {
            engine,
            sessions: Sessions::new(),
            setup_until: std::sync::Mutex::new(until),
        }
    }

    fn setup_open(&self) -> bool {
        if self.engine.store().is_initialized() {
            return false;
        }
        let until = *self.setup_until.lock().unwrap();
        now() <= until
    }

    fn close_setup(&self) {
        let mut until = self.setup_until.lock().unwrap();
        *until = 0;
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0)
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("静态响应头")
}

fn respond_json(value: &Value, status: u16, cookie: Option<String>) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    let mut response = Response::from_data(body)
        .with_status_code(status)
        .with_header(header("Content-Type", "application/json; charset=utf-8"));
    if let Some(cookie) = cookie {
        response = response.with_header(header("Set-Cookie", &cookie));
    }
    response
}

fn respond_text(data: &[u8], content_type: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(data.to_vec())
        .with_status_code(200)
        .with_header(header("Content-Type", content_type))
}

fn fail(status: u16, message: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    respond_json(&json!({ "error": message }), status, None)
}

fn ok(message: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    respond_json(&json!({ "ok": true, "message": message }), 200, None)
}

fn read_body(request: &mut Request) -> Result<Vec<u8>, String> {
    let mut buffer = Vec::new();
    let mut reader = request.as_reader();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                if buffer.len() + count > MAX_BODY {
                    return Err("请求体过大".to_string());
                }
                buffer.extend_from_slice(&chunk[..count]);
            }
            Err(err) => return Err(format!("读取请求体失败：{err}")),
        }
    }
    Ok(buffer)
}

fn parse_body<T: for<'de> Deserialize<'de>>(request: &mut Request) -> Result<T, String> {
    let bytes = read_body(request)?;
    if bytes.is_empty() {
        return serde_json::from_str("{}").map_err(|err| format!("请求体格式错误：{err}"));
    }
    serde_json::from_slice(&bytes).map_err(|err| format!("请求体格式错误：{err}"))
}

fn session_id(request: &Request) -> Option<String> {
    for item in request.headers() {
        if item.field.as_str().eq_ignore_ascii_case("cookie") {
            if let Some(value) = session::cookie_value(item.value.as_str(), session::COOKIE_NAME) {
                return Some(value.to_string());
            }
        }
    }
    None
}

#[derive(Deserialize, Default)]
struct LoginBody {
    #[serde(default)]
    pw: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    recovery: Option<String>,
}

#[derive(Deserialize, Default)]
struct OverrideBody {
    #[serde(default)]
    minutes: u32,
    #[serde(default)]
    pw: Option<String>,
    #[serde(default)]
    totp: Option<String>,
}

#[derive(Deserialize, Default)]
struct ConfigBody {
    config: Option<Value>,
    #[serde(default)]
    pw: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    regenerate_totp: bool,
    #[serde(default)]
    regenerate_recovery: bool,
}

#[derive(Deserialize, Default)]
struct SetupBody {
    #[serde(default)]
    factors: Option<String>,
    #[serde(default)]
    pw: Option<String>,
    #[serde(default)]
    totp_secret: Option<String>,
}

fn factor_from_name(name: &str) -> Factors {
    match name {
        "pw" | "password" => Factors::Password,
        "totp" => Factors::Totp,
        "both" => Factors::Both,
        _ => Factors::None,
    }
}

/// 以给定凭据完成一次认证，并把认证状态（失败计数、TOTP 步数）落盘。
fn authenticate(engine: &Engine, supplied: Option<&str>, code: Option<&str>) -> Result<Factors, String> {
    let snapshot = engine.snapshot();
    let mut config = snapshot.config.clone();
    let moment = now();
    let factors = config.auth.factors;

    if let Some(remaining) = config.auth.is_locked(moment) {
        return Err(format!("认证已锁定，请在 {remaining} 秒后重试"));
    }

    let verdict = config.auth.check_login(moment, supplied, code);
    // 无论成功与否都保存认证状态，避免通过重启清除失败计数。
    let persisted = engine.replace_config(config);
    if let Err(err) = persisted {
        engine.logger().warn(&format!("保存认证状态失败：{err}"));
    }
    verdict.map_err(|err| err.to_string())?;
    Ok(factors)
}

fn step_up_ok(api: &Api, id: Option<&str>) -> bool {
    match id {
        Some(id) => api.sessions.touch(id).map(|item| item.fresh()).unwrap_or(false),
        None => false,
    }
}

fn state_payload(api: &Api, authenticated: bool) -> Value {
    let snapshot = api.engine.snapshot();
    let blocked = snapshot.blocked_paths();
    let factors = snapshot.config.auth.factors;
    let evaluation = &snapshot.evaluation;

    let apps: Vec<Value> = snapshot
        .config
        .apps
        .iter()
        .map(|app| {
            json!({
                "name": app.name,
                "path": app.path,
                "blocked": blocked.iter().any(|item| item == &app.path),
                "schedule": app.schedule,
            })
        })
        .collect();

    json!({
        "initialized": api.engine.store().is_initialized(),
        "enabled": snapshot.config.enabled,
        "factors": factors.as_str(),
        "needs_password": factors.needs_password(),
        "needs_totp": factors.needs_totp(),
        "authenticated": authenticated,
        "blocked": blocked,
        "overridden": evaluation.overridden,
        "override_until": evaluation.override_until,
        "next_change": evaluation.next_change.map(|value| value.and_utc().timestamp()),
        "integrity_ok": snapshot.integrity_ok,
        "integrity_note": snapshot.integrity_note,
        "last_error": snapshot.last_error,
        "setup_open": api.setup_open(),
        "step_up_secs": session::STEP_UP_SECS,
        "apps": apps,
        "now": now(),
        "started_at": snapshot.started_at,
    })
}

fn handle_setup(api: &Api, request: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    if !api.setup_open() {
        return fail(403, "初始化窗口已关闭");
    }
    let body: SetupBody = match parse_body(request) {
        Ok(value) => value,
        Err(err) => return fail(400, &err),
    };
    let factors = factor_from_name(body.factors.as_deref().unwrap_or("both"));
    let seed = PreSeed {
        version: 0,
        enabled: true,
        apps: Vec::new(),
        hashes: Vec::new(),
        auth: None,
        factors: Some(factors),
        password: body.pw.clone(),
        totp_secret: body.totp_secret.clone(),
        recovery_code_count: None,
    };
    let built = match bootstrap::build(&seed) {
        Ok(value) => value,
        Err(err) => return fail(400, &err.to_string()),
    };
    if let Err(err) = api.engine.replace_config(built.config.clone()) {
        return fail(500, &format!("保存配置失败：{err}"));
    }
    api.close_setup();
    let uri = built
        .totp_secret
        .as_deref()
        .map(|secret| totp::otpauth_url(secret, "NetGuard", "NetGuard"))
        .unwrap_or_default();
    respond_json(
        &json!({
            "ok": true,
            "uri": uri,
            "recovery_codes": built.recovery_codes,
        }),
        200,
        None,
    )
}

fn handle_login(api: &Api, request: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body: LoginBody = match parse_body(request) {
        Ok(value) => value,
        Err(err) => return fail(400, &err),
    };
    let snapshot = api.engine.snapshot();
    let factors = snapshot.config.auth.factors;
    if factors == Factors::None {
        let created = api.sessions.create(factors);
        return respond_json(&json!({ "ok": true }), 200, Some(session::cookie_header(&created)));
    }

    if let Some(code) = body.recovery.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        let mut config = snapshot.config.clone();
        let moment = now();
        let result = config.auth.consume_recovery_code(code, moment);
        let _ = api.engine.replace_config(config);
        return match result {
            Ok(()) => {
                let created = api.sessions.create(factors);
                respond_json(&json!({ "ok": true }), 200, Some(session::cookie_header(&created)))
            }
            Err(err) => fail(401, &err.to_string()),
        };
    }

    let supplied = body.pw.as_deref();
    let code = body.totp.as_deref();
    match authenticate(&api.engine, supplied, code) {
        Ok(verified) => {
            let created = api.sessions.create(verified);
            respond_json(&json!({ "ok": true }), 200, Some(session::cookie_header(&created)))
        }
        Err(err) => fail(401, &err),
    }
}

fn handle_state(api: &Api, request: &Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let authenticated = session_id(request)
        .and_then(|id| api.sessions.touch(&id))
        .is_some();
    respond_json(&state_payload(api, authenticated), 200, None)
}

fn handle_config_get(api: &Api, request: &Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let id = match session_id(request) {
        Some(value) => value,
        None => {
            if api.engine.snapshot().config.auth.factors != Factors::None {
                return fail(401, "需要登录");
            }
            api.sessions.create(Factors::None)
        }
    };
    if api.sessions.touch(&id).is_none() {
        return fail(401, "会话已失效");
    }
    let snapshot = api.engine.snapshot();
    respond_json(&serde_json::to_value(&snapshot.config).unwrap_or(Value::Null), 200, None)
}

fn handle_config_put(api: &Api, request: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body: ConfigBody = match parse_body(request) {
        Ok(value) => value,
        Err(err) => return fail(400, &err),
    };
    let id = session_id(request);
    let session = match id.as_deref().and_then(|value| api.sessions.touch(value)) {
        Some(value) => value,
        None => return fail(401, "需要登录"),
    };

    let supplied = body.pw.as_deref();
    let code = body.totp.as_deref();
    if !session.fresh() {
        if supplied.is_none() && code.is_none() {
            return fail(403, "该操作需要重新验证");
        }
        if let Err(err) = authenticate(&api.engine, supplied, code) {
            return fail(401, &err);
        }
        if let Some(value) = id.as_deref() {
            api.sessions.step_up(value);
        }
    }

    let incoming = match body.config {
        Some(value) => value,
        None => return fail(400, "缺少配置内容"),
    };
    let mut config: netguard_core::Config = match serde_json::from_value(incoming) {
        Ok(value) => value,
        Err(err) => return fail(400, &format!("配置格式错误：{err}")),
    };

    let current = api.engine.snapshot().config;
    config.version = netguard_core::config::CONFIG_VERSION;
    config.auth.factors = current.auth.factors;
    if config.auth.password_hash.is_none() {
        config.auth.password_hash = current.auth.password_hash.clone();
    }
    if config.auth.totp_secret.is_none() {
        config.auth.totp_secret = current.auth.totp_secret.clone();
    }
    if config.auth.recovery_hashes.is_empty() {
        config.auth.recovery_hashes = current.auth.recovery_hashes.clone();
    }
    config.auth.failures = current.auth.failures;
    config.auth.locked_until = current.auth.locked_until;
    config.auth.last_totp_counter = current.auth.last_totp_counter;

    if let Err(err) = api.engine.replace_config(config) {
        return fail(400, &format!("配置未生效：{err}"));
    }
    ok("配置已保存")
}

fn handle_totp(api: &Api, request: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body: ConfigBody = match parse_body(request) {
        Ok(value) => value,
        Err(err) => return fail(400, &err),
    };
    let id = match session_id(request) {
        Some(value) => value,
        None => return fail(401, "需要登录"),
    };
    let mut config = api.engine.snapshot().config;

    if !body.regenerate_totp && !body.regenerate_recovery {
        return fail(400, "未指定操作");
    }

    if !step_up_ok(api, Some(&id)) {
        let supplied = body.pw.as_deref();
        let code = body.totp.as_deref();
        if supplied.is_none() && code.is_none() {
            return fail(403, "该操作需要重新验证");
        }
        if let Err(err) = authenticate(&api.engine, supplied, code) {
            return fail(401, &err);
        }
        api.sessions.step_up(&id);
    }

    let mut uri = String::new();
    let mut codes: Vec<String> = Vec::new();
    let result: Result<(), String> = (|| {
        if body.regenerate_totp {
            if config.auth.factors.needs_totp() {
                let secret = auth::new_totp_secret();
                uri = totp::otpauth_url(&secret, "NetGuard", "NetGuard");
                config.auth.totp_secret = Some(secret);
                let fresh = auth::new_recovery_codes(auth::RECOVERY_CODE_COUNT);
                config.auth.recovery_hashes = fresh
                    .iter()
                    .map(|code| auth::hash_password(code))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|err| err.to_string())?;
                codes = fresh;
            }
        }
        if body.regenerate_recovery && codes.is_empty() {
            let fresh = auth::new_recovery_codes(auth::RECOVERY_CODE_COUNT);
            config.auth.recovery_hashes = fresh
                .iter()
                .map(|code| auth::hash_password(code))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| err.to_string())?;
            codes = fresh;
        }
        api.engine
            .replace_config(config.clone())
            .map_err(|err| err.to_string())?;
        Ok(())
    })();

    match result {
        Ok(()) => respond_json(
            &json!({ "ok": true, "uri": uri, "recovery_codes": codes }),
            200,
            None,
        ),
        Err(err) => fail(500, &err),
    }
}

fn handle_override(api: &Api, request: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let body: OverrideBody = match parse_body(request) {
        Ok(value) => value,
        Err(err) => return fail(400, &err),
    };
    let id = match session_id(request) {
        Some(value) => value,
        None => return fail(401, "需要登录"),
    };
    if body.minutes > 0 && !step_up_ok(api, Some(&id)) {
        let supplied = body.pw.as_deref();
        let code = body.totp.as_deref();
        if supplied.is_none() && code.is_none() {
            return fail(403, "该操作需要重新验证");
        }
        if let Err(err) = authenticate(&api.engine, supplied, code) {
            return fail(401, &err);
        }
        api.sessions.step_up(&id);
    }
    match api.engine.set_override(body.minutes) {
        Ok(until) => respond_json(&json!({ "ok": true, "until": until }), 200, None),
        Err(err) => fail(500, &format!("设置临时放行失败：{err}")),
    }
}

fn handle_log(api: &Api, request: &Request) -> Response<std::io::Cursor<Vec<u8>>> {
    if session_id(request).and_then(|id| api.sessions.touch(&id)).is_none()
        && api.engine.snapshot().config.auth.factors != Factors::None
    {
        return fail(401, "需要登录");
    }
    let mut lines = 120usize;
    if let Some(query) = request.url().split('?').nth(1) {
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("lines=") {
                if let Ok(parsed) = value.parse::<usize>() {
                    lines = parsed.clamp(10, 500);
                }
            }
        }
    }
    let text = api.engine.logger().tail(lines);
    let payload: Vec<&str> = text.lines().collect();
    respond_json(&json!({ "lines": payload }), 200, None)
}

fn handle_logout(api: &Api, request: &Request) -> Response<std::io::Cursor<Vec<u8>>> {
    if let Some(id) = session_id(request) {
        api.sessions.remove(&id);
    }
    respond_json(&json!({ "ok": true }), 200, Some(session::clear_cookie_header()))
}

fn dispatch(api: &Arc<Api>, request: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let path = request.url().split('?').next().unwrap_or("/").to_string();
    let method = request.method().as_str().to_string();
    match (method.as_str(), path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => respond_text(INDEX_HTML, "text/html; charset=utf-8"),
        ("GET", "/app.js") => respond_text(APP_JS, "application/javascript; charset=utf-8"),
        ("GET", "/style.css") => respond_text(STYLE_CSS, "text/css; charset=utf-8"),
        ("GET", "/api/state") => handle_state(api, request),
        ("GET", "/api/config") => handle_config_get(api, request),
        ("GET", "/api/log") => handle_log(api, request),
        ("POST", "/api/setup") => handle_setup(api, request),
        ("POST", "/api/login") => handle_login(api, request),
        ("POST", "/api/logout") => handle_logout(api, request),
        ("POST", "/api/override") => handle_override(api, request),
        ("POST", "/api/totp") => handle_totp(api, request),
        ("PUT", "/api/config") => handle_config_put(api, request),
        _ => fail(404, "接口不存在"),
    }
}

/// 启动 HTTP 服务线程。
pub fn spawn(engine: Arc<Engine>) -> io::Result<thread::JoinHandle<()>> {
    let server = Server::http(endpoint::ADDR).map_err(|err| io::Error::other(format!("{err}")))?;
    let engine_for_log = engine.clone();
    let handle = thread::Builder::new()
        .name("netguard-http".to_string())
        .spawn(move || {
            let api = Arc::new(Api::new(engine));
            engine_for_log.logger().info(&format!("控制台已就绪：http://{}", endpoint::ADDR));
            loop {
                match server.recv() {
                    Ok(mut request) => {
                        let shared = api.clone();
                        thread::spawn(move || {
                            let response = dispatch(&shared, &mut request);
                            let _ = request.respond(response);
                        });
                    }
                    Err(err) => {
                        engine_for_log.logger().error(&format!("接收请求失败：{err}"));
                        break;
                    }
                }
            }
        })?;
    Ok(handle)
}
