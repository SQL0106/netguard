//! 配置模型。
//!
//! 两条硬约束（改字段前务必确认）：
//!
//! 1. **序列化必须稳定**：`mac.rs` 对 `serde_json::to_vec(&Config)` 的字节做 HMAC，
//!    所以这里**不允许**使用 `skip_serializing_if`、不允许依赖 HashMap 的迭代顺序。
//!    任何字段顺序/命名变更都等于"配置签名失效"，需要同步升 [`CONFIG_VERSION`] 并迁移。
//! 2. **未知字段必须报错**：`deny_unknown_fields` 让拼错的键变成显式错误，
//!    而不是"看起来保存成功了但没生效"。

use serde::{Deserialize, Serialize};

pub use crate::auth::{AuthConfig, Factors};

/// 当前配置格式版本。
pub const CONFIG_VERSION: u32 = 1;

/// 一天有 1440 分钟。
pub const MINUTES_PER_DAY: u16 = 1440;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// 配置格式版本，见 [`CONFIG_VERSION`]。
    pub version: u32,
    /// 总开关。`false` = 不拦任何应用（但仍然保留排程和认证配置）。
    pub enabled: bool,
    /// 受管应用名单。空 = 不拦任何人。
    #[serde(default)]
    pub apps: Vec<AppRule>,
    /// 哈希黑名单（小写十六进制 SHA-256）。命中即按"该路径也受管"处理，
    /// 用来防止改名/复制到别处的同一份程序绕过名单。
    #[serde(default)]
    pub hashes: Vec<String>,
    /// 认证配置。
    pub auth: AuthConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            enabled: true,
            apps: Vec::new(),
            hashes: Vec::new(),
            auth: AuthConfig::default(),
        }
    }
}

/// 一条受管应用。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AppRule {
    /// 展示名（WebUI 里显示，不参与匹配）。
    pub name: String,
    /// 完整路径，例如 `C:\Program Files\Foo\foo.exe`。
    /// 大小写不敏感比较（Windows 语义），但保存用户输入的原始大小写。
    pub path: String,
    /// 何时封锁。`Schedule::windows` 为空 = 全天封锁。
    #[serde(default)]
    pub schedule: Schedule,
}

impl AppRule {
    pub fn new(name: impl Into<String>, path: impl Into<String>, schedule: Schedule) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            schedule,
        }
    }
}

/// 按周重复的时间窗集合。
///
/// 语义：`windows` 为空 → **全天封锁**（"这个应用不能上网"的默认形态）；
/// 非空 → 只有落在任一窗口内的时刻才封锁，窗口外放行。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    #[serde(default)]
    pub windows: Vec<TimeWindow>,
}

impl Schedule {
    pub fn always() -> Self {
        Self { windows: Vec::new() }
    }

    pub fn windows(windows: Vec<TimeWindow>) -> Self {
        Self { windows }
    }

    /// 结构校验。返回中文错误信息（直接展示给用户）。
    pub fn validate(&self) -> Result<(), String> {
        for (i, w) in self.windows.iter().enumerate() {
            let n = i + 1;
            if w.days == 0 {
                return Err(format!("第 {n} 个时间窗没有选择任何星期"));
            }
            if w.days & !0b111_1111 != 0 {
                return Err(format!("第 {n} 个时间窗的星期掩码非法：{:#010b}", w.days));
            }
            if w.start >= MINUTES_PER_DAY || w.end > MINUTES_PER_DAY {
                return Err(format!("第 {n} 个时间窗超出 00:00–24:00 范围"));
            }
            if w.start == w.end {
                return Err(format!(
                    "第 {n} 个时间窗起点和终点相同；整天封锁请留空窗口列表"
                ));
            }
        }
        Ok(())
    }
}

/// 一个时间窗。`start`/`end` 是当天分钟数，`[start, end)` 半开区间。
///
/// `end < start` 表示**跨午夜**：窗口属于 `days` 指定的那一天，一直延续到次日 `end`。
/// 例：周一 22:00 → 次日 02:00 = `{ days: 周一, start: 1320, end: 120 }`。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TimeWindow {
    /// 星期掩码：bit0 = 周一 … bit6 = 周日。
    pub days: u8,
    pub start: u16,
    pub end: u16,
}

impl TimeWindow {
    pub fn new(days: u8, start: u16, end: u16) -> Self {
        Self { days, start, end }
    }

    /// 只在周一到周五生效的窗口。
    pub fn weekdays(start: u16, end: u16) -> Self {
        Self::new(0b001_1111, start, end)
    }

    /// 每天生效的窗口。
    pub fn daily(start: u16, end: u16) -> Self {
        Self::new(0b111_1111, start, end)
    }

    pub fn crosses_midnight(&self) -> bool {
        self.end < self.start
    }
}

/// 把 "HH:MM" 解析成当天分钟数。`24:00` 允许（= 1440）。
pub fn parse_hhmm(s: &str) -> Result<u16, String> {
    let s = s.trim();
    let (h, m) = s
        .split_once(':')
        .ok_or_else(|| format!("时间格式应为 HH:MM，收到 {s:?}"))?;
    let h: u16 = h.trim().parse().map_err(|_| format!("小时不是数字：{h:?}"))?;
    let m: u16 = m.trim().parse().map_err(|_| format!("分钟不是数字：{m:?}"))?;
    if h > 24 || m > 59 || (h == 24 && m != 0) {
        return Err(format!("时间超出范围：{s:?}"));
    }
    Ok(h * 60 + m)
}

/// 反向格式化，供 UI 显示。
pub fn format_hhmm(minutes: u16) -> String {
    format!("{:02}:{:02}", minutes / 60, minutes % 60)
}

impl Config {
    /// 整体校验：版本、名单、排程、哈希格式。
    pub fn validate(&self) -> Result<(), String> {
        if self.version != CONFIG_VERSION {
            return Err(format!(
                "配置版本 {} 与本程序支持的版本 {} 不一致",
                self.version, CONFIG_VERSION
            ));
        }
        for app in &self.apps {
            if app.path.trim().is_empty() {
                return Err(format!("应用 {:?} 的路径为空", app.name));
            }
            if !app.path.to_ascii_lowercase().ends_with(".exe") {
                return Err(format!("应用 {:?} 的路径不是 .exe：{}", app.name, app.path));
            }
            if crate::guard::is_protected(&app.path) {
                return Err(format!(
                    "{:?} 是系统关键进程，禁止加入名单（加入会导致系统无法启动）",
                    app.name
                ));
            }
            app.schedule.validate()?;
        }
        for h in &self.hashes {
            if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("哈希格式非法（应为 64 位十六进制）：{h}"));
            }
        }
        self.auth.validate()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 默认配置可通过校验() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn 拒绝非_exe_路径() {
        let mut cfg = Config::default();
        cfg.apps
            .push(AppRule::new("txt", "C:\\a\\b.txt", Schedule::always()));
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn 拒绝系统进程() {
        let mut cfg = Config::default();
        cfg.apps.push(AppRule::new(
            "svc",
            "C:\\Windows\\System32\\svchost.exe",
            Schedule::always(),
        ));
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn 拒绝零长窗口() {
        let s = Schedule::windows(vec![TimeWindow::daily(600, 600)]);
        assert!(s.validate().is_err());
    }

    #[test]
    fn 拒绝空星期() {
        let s = Schedule::windows(vec![TimeWindow::new(0, 600, 700)]);
        assert!(s.validate().is_err());
    }

    #[test]
    fn hhmm_往返() {
        assert_eq!(parse_hhmm("22:00").unwrap(), 1320);
        assert_eq!(parse_hhmm("24:00").unwrap(), 1440);
        assert_eq!(format_hhmm(1320), "22:00");
        assert!(parse_hhmm("24:01").is_err());
        assert!(parse_hhmm("25:00").is_err());
    }

    #[test]
    fn 序列化稳定() {
        let cfg = Config::default();
        let a = serde_json::to_vec(&cfg).unwrap();
        let b = serde_json::to_vec(&serde_json::from_slice::<Config>(&a).unwrap()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn 未知字段报错() {
        let bad = br#"{"version":1,"enabled":true,"auth":{"factors":"none"},"typo":1}"#;
        assert!(serde_json::from_slice::<Config>(bad).is_err());
    }
}
