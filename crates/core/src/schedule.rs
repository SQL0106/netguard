//! 时间窗判定与"下一边界"计算——**零轮询**的核心。
//!
//! 关键设计：本模块**从不睡眠、从不循环等待**。它只回答两个问题：
//!
//! 1. 现在这个时刻，哪些应用该被拦？([`evaluate`])
//! 2. 状态下一次变化发生在哪一刻？([`Evaluation::next_change`])
//!
//! Windows 层拿到 `next_change` 后，只 arm **一个**高精度等待定时器指向它；
//! 到点醒来重新问一遍、再 arm 下一个。所以 CPU 占用与"是否在时间窗内"无关，
//! 也与 30 s/1 s 轮询无关——一年下来唤醒次数等于时间窗边界数。
//!
//! 时区处理：本模块只接受**本地时间** `NaiveDateTime`。本地时间→UTC 的换算、
//! 夏令时的歧义/空洞，由平台层决定（Windows 用 `TzSpecificLocalTimeToSystemTime`，
//! 测试里直接用固定本地时间，从而不需要时区数据库）。

use chrono::{Datelike, Duration, NaiveDateTime, Timelike};

use crate::config::{Config, Schedule};

/// 一次判定最多向后看 8 天（一周 + 一点余量）。一周内必然重复，
/// 因此"8 天内没有变化"等价于"永远不再变化"。
const SCAN_MINUTES: u32 = 8 * 24 * 60;

/// 星期索引：0 = 周一 … 6 = 周日（与 [`crate::config::TimeWindow::days`] 的 bit 对应）。
pub fn weekday_index(dt: NaiveDateTime) -> u8 {
    dt.weekday().num_days_from_monday() as u8
}

/// 当天第几分钟（0..1439）。
pub fn minute_of_day(dt: NaiveDateTime) -> u16 {
    (dt.hour() * 60 + dt.minute()) as u16
}

impl Schedule {
    /// 在"星期 `wd` 的第 `minute` 分钟"这一刻是否应当封锁。
    pub fn is_active(&self, wd: u8, minute: u16) -> bool {
        // 空窗口列表 = 全天封锁（"这个应用不能上网"的默认形态）
        if self.windows.is_empty() {
            return true;
        }
        let prev_day = (wd + 6) % 7;
        for w in &self.windows {
            let starts_today = w.days & (1 << wd) != 0;
            let started_yesterday = w.days & (1 << prev_day) != 0;
            if w.end > w.start {
                // 同一天内：[start, end)
                if starts_today && minute >= w.start && minute < w.end {
                    return true;
                }
            } else {
                // 跨午夜：今天 start 之后，或昨天 start 之后延续到今天 end 之前
                if starts_today && minute >= w.start {
                    return true;
                }
                if started_yesterday && minute < w.end {
                    return true;
                }
            }
        }
        false
    }

    /// 便捷版本：给定本地时间。
    pub fn active_now(&self, now: NaiveDateTime) -> bool {
        self.is_active(weekday_index(now), minute_of_day(now))
    }
}

/// 一次判定结果。字段都是"给人看 + 给定时器用"的成品，UI 直接渲染。
#[derive(Debug, Clone, PartialEq)]
pub struct Evaluation {
    /// 当前**实际生效**的封锁状态（已考虑临时放行）。
    pub blocked: bool,
    /// 按配置顺序列出此刻本该被拦的应用名（即使被临时放行也照列，UI 用来提示）。
    pub apps: Vec<String>,
    /// 同上，对应路径。
    pub paths: Vec<String>,
    /// 状态下一次变化的时间；`None` = 未来一周内不会再变（例如全天封锁）。
    pub next_change: Option<NaiveDateTime>,
    /// 是否正被"临时放行"覆盖。
    pub overridden: bool,
    /// 临时放行的截止时间（若在生效）。
    pub override_until: Option<NaiveDateTime>,
}

impl Evaluation {
    /// 当前没有封锁时，下一次开始封锁的时间（UI 显示"还有多久开始"）。
    pub fn next_block_start(&self) -> Option<NaiveDateTime> {
        if self.blocked {
            None
        } else {
            self.next_change
        }
    }
}

/// 判定此刻状态。
///
/// - `cfg.enabled == false` → 永不封锁。
/// - `override_until`：临时放行截止时刻；`Some(t)` 且 `t > now` 时压过时间窗。
pub fn evaluate(
    cfg: &Config,
    now: NaiveDateTime,
    override_until: Option<NaiveDateTime>,
) -> Evaluation {
    let natural = blocked_paths(cfg, now);
    let blocked = effective_blocked(&natural, override_until, now);
    let overridden = !natural.is_empty() && !blocked;

    Evaluation {
        blocked,
        apps: names_for(cfg, &natural),
        paths: natural,
        next_change: next_change(cfg, now, override_until),
        overridden,
        override_until: override_until.filter(|t| *t > now),
    }
}

/// 自然状态下（忽略临时放行）此刻该被拦的路径。
fn blocked_paths(cfg: &Config, now: NaiveDateTime) -> Vec<String> {
    if !cfg.enabled {
        return Vec::new();
    }
    cfg.apps
        .iter()
        .filter(|a| a.schedule.active_now(now))
        .map(|a| a.path.clone())
        .collect()
}

fn effective_blocked(
    paths: &[String],
    override_until: Option<NaiveDateTime>,
    now: NaiveDateTime,
) -> bool {
    if paths.is_empty() {
        return false;
    }
    match override_until {
        Some(t) if t > now => false,
        _ => true,
    }
}

fn names_for(cfg: &Config, paths: &[String]) -> Vec<String> {
    cfg.apps
        .iter()
        .filter(|a| paths.iter().any(|p| p == &a.path))
        .map(|a| a.name.clone())
        .collect()
}

/// 找到**严格晚于** `now` 的第一分钟，使生效状态或自然名单发生变化。
fn next_change(
    cfg: &Config,
    now: NaiveDateTime,
    override_until: Option<NaiveDateTime>,
) -> Option<NaiveDateTime> {
    let base_paths = blocked_paths(cfg, now);
    let base_blocked = effective_blocked(&base_paths, override_until, now);

    let mut t = next_minute(now);
    for _ in 0..SCAN_MINUTES {
        let paths = blocked_paths(cfg, t);
        if paths != base_paths || effective_blocked(&paths, override_until, t) != base_blocked {
            return Some(t);
        }
        t += Duration::minutes(1);
    }
    None
}

/// 下一分钟整点（严格大于 `now`）。
fn next_minute(now: NaiveDateTime) -> NaiveDateTime {
    let truncated = now.with_second(0).and_then(|d| d.with_nanosecond(0)).unwrap_or(now);
    if truncated > now {
        truncated
    } else {
        truncated + Duration::minutes(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppRule, TimeWindow};
    use chrono::NaiveDate;

    /// 2026-11-02 是周一。
    fn dt(day: u32, h: u32, m: u32, s: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(2026, 11, day)
            .unwrap()
            .and_hms_opt(h, m, s)
            .unwrap()
    }

    fn monday() -> NaiveDateTime {
        let d = dt(2, 0, 0, 0);
        assert_eq!(weekday_index(d), 0, "2026-11-02 应为周一");
        d
    }

    fn cfg_with(schedule: Schedule) -> Config {
        let mut cfg = Config::default();
        cfg.apps
            .push(AppRule::new("测试程序", r"C:\t\a.exe", schedule));
        cfg
    }

    #[test]
    fn 空窗口等于全天封锁() {
        let cfg = cfg_with(Schedule::always());
        let e = evaluate(&cfg, monday(), None);
        assert!(e.blocked);
        assert_eq!(e.apps, vec!["测试程序".to_string()]);
        assert_eq!(e.next_change, None);
    }

    #[test]
    fn 总开关关闭则不拦() {
        let mut cfg = cfg_with(Schedule::always());
        cfg.enabled = false;
        let e = evaluate(&cfg, monday(), None);
        assert!(!e.blocked);
        assert!(e.apps.is_empty());
        assert_eq!(e.next_change, None);
    }

    #[test]
    fn 同一天窗口半开区间() {
        let cfg = cfg_with(Schedule::windows(vec![TimeWindow::weekdays(21 * 60, 22 * 60)]));
        assert!(!evaluate(&cfg, dt(2, 20, 59, 59), None).blocked);
        assert!(evaluate(&cfg, dt(2, 21, 0, 0), None).blocked);
        assert!(evaluate(&cfg, dt(2, 21, 59, 59), None).blocked);
        // 终点是开的
        assert!(!evaluate(&cfg, dt(2, 22, 0, 0), None).blocked);
    }

    #[test]
    fn 跨午夜窗口() {
        // 周一 22:00 → 周二 02:00
        let cfg = cfg_with(Schedule::windows(vec![TimeWindow::new(0b000_0001, 1320, 120)]));
        assert!(!evaluate(&cfg, dt(2, 21, 59, 0), None).blocked, "周一 21:59");
        assert!(evaluate(&cfg, dt(2, 22, 0, 0), None).blocked, "周一 22:00");
        assert!(evaluate(&cfg, dt(3, 0, 30, 0), None).blocked, "周二 00:30");
        assert!(evaluate(&cfg, dt(3, 1, 59, 0), None).blocked, "周二 01:59");
        assert!(!evaluate(&cfg, dt(3, 2, 0, 0), None).blocked, "周二 02:00 解除");
        // 周二 22:00 不该被周一那条窗口覆盖
        assert!(!evaluate(&cfg, dt(3, 22, 0, 0), None).blocked, "周二 22:00 不受周一窗口影响");
        // 周三凌晨也不受影响
        assert!(!evaluate(&cfg, dt(4, 0, 30, 0), None).blocked);
    }

    #[test]
    fn 只有工作日() {
        let cfg = cfg_with(Schedule::windows(vec![TimeWindow::weekdays(9 * 60, 10 * 60)]));
        assert!(evaluate(&cfg, dt(2, 9, 30, 0), None).blocked, "周一");
        assert!(evaluate(&cfg, dt(6, 9, 30, 0), None).blocked, "周五");
        assert!(!evaluate(&cfg, dt(7, 9, 30, 0), None).blocked, "周六");
        assert!(!evaluate(&cfg, dt(8, 9, 30, 0), None).blocked, "周日");
    }

    #[test]
    fn 下一边界落在整分() {
        let cfg = cfg_with(Schedule::windows(vec![TimeWindow::weekdays(21 * 60, 22 * 60)]));
        // 周一 20:59:59 → 21:00:00 开始
        let e = evaluate(&cfg, dt(2, 20, 59, 59), None);
        assert!(!e.blocked);
        assert_eq!(e.next_change, Some(dt(2, 21, 0, 0)));
        // 周一 21:30 → 22:00:00 结束
        let e = evaluate(&cfg, dt(2, 21, 30, 0), None);
        assert!(e.blocked);
        assert_eq!(e.next_change, Some(dt(2, 22, 0, 0)));
        // 周一 22:00 → 下一边界是周二 21:00
        let e = evaluate(&cfg, dt(2, 22, 0, 0), None);
        assert!(!e.blocked);
        assert_eq!(e.next_change, Some(dt(3, 21, 0, 0)));
    }

    #[test]
    fn 多条规则合并取最早边界() {
        let mut cfg = Config::default();
        cfg.apps.push(AppRule::new(
            "a",
            r"C:\t\a.exe",
            Schedule::windows(vec![TimeWindow::daily(9 * 60, 10 * 60)]),
        ));
        cfg.apps.push(AppRule::new(
            "b",
            r"C:\t\b.exe",
            Schedule::always(),
        ));
        let e = evaluate(&cfg, dt(2, 8, 0, 0), None);
        assert!(e.blocked, "b 全天封锁");
        assert_eq!(e.next_change, Some(dt(2, 9, 0, 0)), "9 点 a 也加入");
        let e9 = evaluate(&cfg, dt(2, 9, 0, 0), None);
        assert_eq!(e9.apps.len(), 2);
        assert_eq!(e9.next_change, Some(dt(2, 10, 0, 0)));
    }

    #[test]
    fn 临时放行压过时间窗() {
        let cfg = cfg_with(Schedule::always());
        let now = dt(2, 9, 0, 0);
        let until = now + Duration::minutes(10);
        let e = evaluate(&cfg, now, Some(until));
        assert!(!e.blocked);
        assert!(e.overridden);
        assert_eq!(e.override_until, Some(until));
        assert_eq!(e.next_change, Some(until), "到了截止时刻要恢复封锁");
        assert_eq!(e.apps, vec!["测试程序".to_string()], "名单仍然列出");

        // 过期后自动恢复
        let later = until + Duration::seconds(1);
        let e2 = evaluate(&cfg, later, Some(until));
        assert!(e2.blocked);
        assert!(!e2.overridden);
    }

    #[test]
    fn 无应用时永不封锁() {
        let cfg = Config::default();
        let e = evaluate(&cfg, monday(), None);
        assert!(!e.blocked);
        assert!(e.paths.is_empty());
    }

    #[test]
    fn 一周内必能找到边界() {
        let cfg = cfg_with(Schedule::windows(vec![TimeWindow::new(0b100_0000, 600, 700)]));
        // 周日 12:00 已过窗口 → 下一边界是下周日 10:00
        let e = evaluate(&cfg, dt(8, 12, 0, 0), None);
        assert!(!e.blocked);
        assert_eq!(e.next_change, Some(dt(8, 12, 0, 0) + Duration::days(7) - Duration::hours(2)));
    }
}
