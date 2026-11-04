//! 本地 WebUI 的会话管理。
//!
//! 会话仅保存在内存中，服务重启即失效；标识为 32 位十六进制随机串，
//! 通过 `HttpOnly`、`SameSite=Strict` 的 Cookie 下发。
//!
//! 敏感操作（修改配置、临时放行、修改认证凭据）要求在最近 [`STEP_UP_SECS`]
//! 秒内重新通过一次认证，即「提升验证」。

#![cfg(windows)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use netguard_core::Factors;

/// 空闲超时（秒）。
pub const IDLE_SECS: i64 = 900;
/// 提升验证有效期（秒）。
pub const STEP_UP_SECS: i64 = 300;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0)
}

/// 一个已登录会话。
#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub created_at: i64,
    pub last_seen: i64,
    pub factors: Factors,
    pub stepped_up_at: Option<i64>,
}

impl Session {
    /// 提升验证是否仍然有效。
    pub fn fresh(&self) -> bool {
        match self.stepped_up_at {
            Some(at) => now() - at <= STEP_UP_SECS,
            None => false,
        }
    }
}

/// 会话表。
#[derive(Debug, Default)]
pub struct Sessions {
    inner: Mutex<HashMap<String, Session>>,
}

impl Sessions {
    pub fn new() -> Sessions {
        Sessions::default()
    }

    fn sweep(map: &mut HashMap<String, Session>) {
        let current = now();
        map.retain(|_, session| current - session.last_seen <= IDLE_SECS);
    }

    /// 新建会话，返回会话标识。
    pub fn create(&self, factors: Factors) -> String {
        let id = crate::random::hex(16);
        let current = now();
        let session = Session {
            id: id.clone(),
            created_at: current,
            last_seen: current,
            factors,
            stepped_up_at: None,
        };
        let mut map = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        Self::sweep(&mut map);
        map.insert(id.clone(), session);
        id
    }

    /// 校验并刷新会话。过期或不存在返回 `None`。
    pub fn touch(&self, id: &str) -> Option<Session> {
        let current = now();
        let mut map = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        Self::sweep(&mut map);
        let session = map.get_mut(id)?;
        session.last_seen = current;
        Some(session.clone())
    }

    /// 记录一次成功的提升验证。
    pub fn step_up(&self, id: &str) -> bool {
        let current = now();
        let mut map = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match map.get_mut(id) {
            Some(session) => {
                session.stepped_up_at = Some(current);
                session.last_seen = current;
                true
            }
            None => false,
        }
    }

    /// 主动注销。
    pub fn remove(&self, id: &str) {
        let mut map = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        map.remove(id);
    }

    /// 当前会话数量，供状态接口展示。
    pub fn count(&self) -> usize {
        let map = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        map.len()
    }
}

/// 从 `Cookie` 请求头中取出指定名称的值。
pub fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    for part in header.split(';') {
        let part = part.trim();
        let (key, value) = match part.split_once('=') {
            Some(pair) => pair,
            None => continue,
        };
        if key == name {
            return Some(value);
        }
    }
    None
}

/// 生成下发会话的 `Set-Cookie` 值。
pub fn cookie_header(id: &str) -> String {
    format!("ng_session={id}; Path=/; HttpOnly; SameSite=Strict")
}

/// 生成清除会话的 `Set-Cookie` 值。
pub fn clear_cookie_header() -> String {
    "ng_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 会话可创建并刷新() {
        let sessions = Sessions::new();
        let id = sessions.create(Factors::Password);
        assert_eq!(id.len(), 32);
        let session = sessions.touch(&id).expect("会话应存在");
        assert_eq!(session.factors, Factors::Password);
        assert!(!session.fresh());
    }

    #[test]
    fn 提升验证有有效期() {
        let sessions = Sessions::new();
        let id = sessions.create(Factors::Totp);
        assert!(sessions.step_up(&id));
        assert!(sessions.touch(&id).unwrap().fresh());
    }

    #[test]
    fn 注销后不可用() {
        let sessions = Sessions::new();
        let id = sessions.create(Factors::Both);
        sessions.remove(&id);
        assert!(sessions.touch(&id).is_none());
        assert_eq!(sessions.count(), 0);
    }

    #[test]
    fn 解析 Cookie() {
        assert_eq!(cookie_value("a=1; ng_session=abc; b=2", "ng_session"), Some("abc"));
        assert_eq!(cookie_value("a=1", "ng_session"), None);
    }
}
