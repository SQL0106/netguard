//! 运行时核心：持有配置快照、协调过滤器、维护排程边界。
//!
//! 线程模型：
//! - 主线程（服务宿主）负责生命周期，调用 [`Engine::boot`] 后进入等待。
//! - 工作线程按排程边界唤醒，仅在「应拦截集合」发生变化时才与 WFP 交互，
//!   不做任何周期性轮询。
//! - HTTP 线程与命令行客户端通过 [`Engine`] 的公开方法读写快照，写操作后调用
//!   [`Engine::notify`] 唤醒工作线程重算。

#![cfg(windows)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use netguard_core::schedule::{evaluate, Evaluation};
use netguard_core::Config;

use crate::log::Logger;
use crate::store::{Load, RuntimeState, Store};
use crate::ticker::Ticker;

/// 允许的时钟回拨容差。系统校时通常只微调数秒，超过此值视为人为回拨。
const CLOCK_SLACK_SECS: i64 = 120;
/// 水位线持久化间隔，避免每次唤醒都写盘。
const WATERMARK_SAVE_SECS: i64 = 300;
use crate::wfp;

/// 配置与运行状态的快照。
#[derive(Clone)]
pub struct Snapshot {
    pub config: Config,
    pub evaluation: Evaluation,
    pub state: RuntimeState,
    pub integrity_ok: bool,
    pub integrity_note: String,
    pub applied: Vec<String>,
    /// 由进程哈希守护追加拦截的路径。
    pub hash_blocked: Vec<String>,
    pub last_error: Option<String>,
    pub started_at: i64,
}

impl Snapshot {
    /// 当前应被拦截的路径集合。
    pub fn blocked_paths(&self) -> Vec<String> {
        let mut paths = self.core_blocked();
        for path in &self.hash_blocked {
            if !paths.iter().any(|item| item == path) {
                paths.push(path.clone());
            }
        }
        paths
    }

    fn core_blocked(&self) -> Vec<String> {
        if self.integrity_ok {
            self.evaluation.paths.clone()
        } else {
            // 配置完整性校验失败时采取失效即封锁策略：名单内程序一律拦截。
            self.config.apps.iter().map(|app| app.path.clone()).collect()
        }
    }
}

/// 磁盘重载的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reload {
    /// 已成功应用新配置。
    Applied,
    /// 配置缺失或校验失败，已转为封锁状态。
    Tampered(String),
}

struct Inner {
    snapshot: Snapshot,
}

/// 磁盘配置的「有效」载入结果：主配置不可信时自动退回到上次已知良好的备份。
///
/// 单拎成一个枚举而不是 `(Load, bool)` 元组，是为了让 [`Engine::boot`] 与
/// [`Engine::reload_from_disk`] 被迫对四种情况都作出显式处理，避免两条路径漂移。
enum Effective {
    /// 主配置与签名均有效。
    Trusted(Config),
    /// 主配置不可信，但备份可用：按备份的内容继续封锁。
    Backup { config: Config, note: String },
    /// 主配置与备份都不存在（真正首次安装）。
    Fresh,
    /// 主配置与备份都不可信：没有任何可依据的名单。
    Untrusted(String),
}

/// 载入当前应采用的配置。
///
/// 优先用主配置；它缺失或校验失败时读备份，备份可用就用备份的内容
/// （`apps`/`hashes`/`auth` 全部来自备份），但调用方必须继续把
/// `integrity_ok` 置为 `false` —— 即「用最后一份可信名单继续封锁」，
/// 而不是退化成空名单（那样 worker 会把已有持久化过滤器全删掉，等于解除拦截）。
fn load_effective(store: &Store) -> Effective {
    // 「主配置缺失」与「主配置不可信」要分开：前者在备份也缺失时才是首次安装。
    let (reason, missing) = match store.load() {
        Load::Ok(config) => return Effective::Trusted(config),
        Load::Absent => (String::from("配置文件缺失"), true),
        Load::Tampered(note) => (note, false),
    };
    match store.load_backup() {
        Load::Ok(config) => Effective::Backup {
            config,
            note: format!("{reason}；已按上次已知良好的备份封锁"),
        },
        // 真首次安装：主配置与备份都不存在。
        Load::Absent if missing => Effective::Fresh,
        Load::Absent => Effective::Untrusted(format!("{reason}；没有可用的配置备份")),
        Load::Tampered(backup_note) => {
            Effective::Untrusted(format!("{reason}；备份也不可信：{backup_note}"))
        }
    }
}

/// 运行时对象。
pub struct Engine {
    store: Store,
    logger: Logger,
    ticker: Ticker,
    inner: Mutex<Inner>,
    hash_blocked: Mutex<std::collections::BTreeSet<String>>,
}

impl Engine {
    /// 载入配置并构造运行时。不会在此阶段访问过滤器引擎。
    pub fn boot(store: Store) -> std::io::Result<Arc<Engine>> {
        store.ensure()?;
        let logger = store.logger()?;

        let (config, integrity_ok, integrity_note) = match load_effective(&store) {
            Effective::Trusted(config) => (config, true, String::new()),
            Effective::Backup { config, note } => {
                logger.error(&format!("配置完整性校验失败：{note}"));
                logger.warn("按上次已知良好的备份继续封锁；请在 WebUI 中重新保存配置以恢复完整性");
                (config, false, note)
            }
            Effective::Fresh => {
                logger.warn("尚未初始化：未找到配置，暂不拦截任何应用");
                (Config::default(), true, String::from("尚未初始化"))
            }
            Effective::Untrusted(note) => {
                logger.error(&format!("配置校验失败：{note}"));
                logger.error("没有任何可信配置，保留已有过滤器（不做增删）");
                (Config::default(), false, note)
            }
        };

        let state = store.load_state();
        let now = chrono::Local::now().naive_local();
        let evaluation = evaluate(&config, now, override_deadline(state.override_until));

        let engine = Arc::new(Engine {
            store,
            logger,
            ticker: Ticker::new(),
            inner: Mutex::new(Inner {
                snapshot: Snapshot {
                    config,
                    evaluation,
                    state,
                    integrity_ok,
                    integrity_note,
                    applied: Vec::new(),
                    hash_blocked: Vec::new(),
                    last_error: None,
                    started_at: chrono::Local::now().timestamp(),
                },
            }),
            hash_blocked: Mutex::new(std::collections::BTreeSet::new()),
        });

        Ok(engine)
    }

    pub fn logger(&self) -> &Logger {
        &self.logger
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// 唤醒工作线程重新计算。
    pub fn notify(&self) {
        self.ticker.notify();
    }

    /// 读取快照。
    pub fn snapshot(&self) -> Snapshot {
        let guard = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        guard.snapshot.clone()
    }

    /// 应用新的配置：先做完整性校验，再落盘并唤醒。
    pub fn replace_config(&self, config: Config) -> std::io::Result<()> {
        config
            .validate()
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        self.store.save(&config)?;
        {
            let mut guard = self.inner.lock().unwrap_or_else(|err| err.into_inner());
            guard.snapshot.config = config;
            guard.snapshot.integrity_ok = true;
            guard.snapshot.integrity_note.clear();
        }
        self.logger.info("配置已更新");
        self.notify();
        Ok(())
    }

    /// 仅从磁盘重新读取配置与签名，不写回。
    ///
    /// 供数据目录监视器使用：外部（例如安装脚本或其他管理工具）替换配置后立即生效。
    /// 校验失败时按失效即封锁处理：主配置不可信则改用上次已知良好的备份（见
    /// `load_effective`），两者都不可信时保留快照中的旧配置与名单用于显示。
    pub fn reload_from_disk(&self) -> Reload {
        match load_effective(&self.store) {
            Effective::Trusted(config) => {
                {
                    let mut guard = self.inner.lock().unwrap_or_else(|err| err.into_inner());
                    guard.snapshot.config = config;
                    guard.snapshot.integrity_ok = true;
                    guard.snapshot.integrity_note.clear();
                }
                self.logger.info("检测到配置变更，已从磁盘重新载入");
                self.notify();
                Reload::Applied
            }
            Effective::Backup { config, note } => {
                {
                    let mut guard = self.inner.lock().unwrap_or_else(|err| err.into_inner());
                    // 用备份的名单继续封锁，但绝不能把完整性标成通过。
                    guard.snapshot.config = config;
                    guard.snapshot.integrity_ok = false;
                    guard.snapshot.integrity_note = note.clone();
                }
                self.logger
                    .error(&format!("配置完整性校验失败：{note}"));
                self.logger
                    .warn("按上次已知良好的备份继续封锁；请在 WebUI 中重新保存配置以恢复完整性");
                self.notify();
                Reload::Tampered(note)
            }
            Effective::Fresh => {
                {
                    let mut guard = self.inner.lock().unwrap_or_else(|err| err.into_inner());
                    guard.snapshot.integrity_ok = false;
                    guard.snapshot.integrity_note = String::from("配置文件缺失");
                }
                self.logger.error("配置文件缺失，按失效即封锁处理");
                self.notify();
                Reload::Tampered(String::from("配置文件缺失"))
            }
            Effective::Untrusted(note) => {
                {
                    let mut guard = self.inner.lock().unwrap_or_else(|err| err.into_inner());
                    guard.snapshot.integrity_ok = false;
                    guard.snapshot.integrity_note = note.clone();
                }
                self.logger
                    .error(&format!("配置完整性校验失败：{note}"));
                self.logger.error("没有任何可信配置，保留已有过滤器（不做增删）");
                self.notify();
                Reload::Tampered(note)
            }
        }
    }

    /// 临时放行指定分钟数；`0` 表示立即取消放行。
    pub fn set_override(&self, minutes: u32) -> std::io::Result<i64> {
        let until = if minutes == 0 {
            0
        } else {
            chrono::Local::now().timestamp() + i64::from(minutes) * 60
        };
        {
            let mut guard = self.inner.lock().unwrap_or_else(|err| err.into_inner());
            guard.snapshot.state.override_until = if until == 0 { None } else { Some(until) };
            let state = guard.snapshot.state.clone();
            drop(guard);
            self.store.save_state(&state)?;
        }
        if minutes == 0 {
            self.logger.info("已取消临时放行");
        } else {
            self.logger
                .info(&format!("已临时放行 {minutes} 分钟"));
        }
        self.notify();
        Ok(until)
    }

    /// 记录一次失败登录并持久化状态。
    pub fn note_auth_state(&self, state: RuntimeState) {
        let mut guard = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        guard.snapshot.state = state.clone();
        drop(guard);
        let _ = self.store.save_state(&state);
    }

    /// 写入运行状态（时钟水位线等）。
    pub fn update_state<F: FnOnce(&mut RuntimeState)>(&self, mutate: F) {
        let mut guard = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        mutate(&mut guard.snapshot.state);
        let state = guard.snapshot.state.clone();
        drop(guard);
        let _ = self.store.save_state(&state);
    }

    /// 观察当前时间戳，返回是否检测到可疑的时钟回拨。
    ///
    /// 水位线只增不减：时间正常前进时按间隔持久化，回拨时保留旧值作为下界。
    fn observe_clock(&self, stamp: i64) -> bool {
        let watermark = {
            let guard = self.inner.lock().unwrap_or_else(|err| err.into_inner());
            guard.snapshot.state.watermark
        };
        if stamp + CLOCK_SLACK_SECS < watermark {
            return true;
        }
        if stamp >= watermark + WATERMARK_SAVE_SECS {
            self.update_state(|state| state.watermark = stamp);
        }
        false
    }

    /// 工作线程主循环：只在边界或显式唤醒时执行。
    pub fn run_worker(self: Arc<Self>) {
        let mut engine: Option<wfp::Engine> = None;
        let mut last_signature: Option<(bool, Vec<String>)> = None;
        let mut retry_at: Option<Instant> = None;
        let mut was_rollback = false;

        loop {
            let snapshot = self.snapshot();
            let now = chrono::Local::now().naive_local();
            let rollback = self.observe_clock(now.and_utc().timestamp());
            if rollback && !was_rollback {
                self.logger
                    .error("检测到系统时间回拨，暂时按全天封锁处理，待时间追上后自动恢复");
            } else if !rollback && was_rollback {
                self.logger.info("系统时间已追上水位线，恢复按排程判定");
            }
            was_rollback = rollback;
            let evaluation = evaluate(&snapshot.config, now, override_deadline(snapshot.state.override_until));
            let mut blocked = if snapshot.integrity_ok && !rollback {
                evaluation.paths.clone()
            } else {
                snapshot.config
                    .apps
                    .iter()
                    .map(|app| app.path.clone())
                    .collect::<Vec<_>>()
            };
            for path in self.hash_paths() {
                if !blocked.iter().any(|item| item == &path) {
                    blocked.push(path);
                }
            }
            let signature = (snapshot.integrity_ok, blocked.clone());

            // 没有任何可信名单（配置与备份都不可信）时不要去 reconcile 空集合：
            // `reconcile(&[])` 会把已有持久化过滤器逐条删掉，等于把拦截解除。
            // 这里保持现有过滤器不动，等配置恢复后下一轮再同步；不记 `last_signature`，
            // 所以配置一恢复就会立即重算。
            if !snapshot.integrity_ok && blocked.is_empty() {
                self.logger
                    .warn("没有可信配置，保留已有过滤器不做增删（fail-closed）");
                self.commit(&evaluation, &blocked, None);
            } else if last_signature.as_ref() != Some(&signature) {
                if engine.is_none() {
                    engine = match wfp::open_logged(&self.logger) {
                        Ok(found) => Some(found),
                        Err(err) => {
                            self.record_error(Some(err.to_string()));
                            retry_at = Some(Instant::now() + Duration::from_secs(30));
                            None
                        }
                    };
                }
                if let Some(wfp) = engine.as_ref() {
                    match wfp.reconcile(&blocked) {
                        Ok(report) => {
                            self.logger.info(&format!("过滤器已同步：{}", wfp::describe(report)));
                            self.commit(&evaluation, &blocked, None);
                            last_signature = Some(signature);
                            retry_at = None;
                        }
                        Err(err) => {
                            self.logger.error(&format!("同步过滤器失败：{err}"));
                            self.record_error(Some(err.to_string()));
                            engine = None;
                            retry_at = Some(Instant::now() + Duration::from_secs(30));
                        }
                    }
                } else {
                    self.commit(&evaluation, &blocked, None);
                }
            } else {
                self.commit(&evaluation, &blocked, None);
            }

            let wait: Option<chrono::DateTime<chrono::Local>> = match retry_at {
                Some(at) => {
                    let left = at.saturating_duration_since(Instant::now());
                    chrono::Duration::from_std(left)
                        .ok()
                        .map(|delta| chrono::Local::now() + delta)
                }
                None => evaluation.next_change.and_then(local_from_naive),
            };

            let woken = self.ticker.wait_until(wait);
            if let Some(at) = retry_at {
                if Instant::now() >= at {
                    retry_at = None;
                    last_signature = None;
                }
            }
            if woken {
                last_signature = None;
            }
        }
    }

    fn record_error(&self, message: Option<String>) {
        let mut guard = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        guard.snapshot.last_error = message;
    }

    /// 进程哈希命中时追加临时拦截路径。
    pub fn add_hash_block(&self, path: &str) -> bool {
        let mut guard = self.hash_blocked.lock().unwrap_or_else(|err| err.into_inner());
        let inserted = guard.insert(path.to_string());
        if inserted {
            self.logger.warn(&format!("已追加哈希拦截：{path}"));
        }
        drop(guard);
        let paths = self.hash_paths();
        {
            let mut inner = self.inner.lock().unwrap_or_else(|err| err.into_inner());
            inner.snapshot.hash_blocked = paths;
        }
        self.ticker.notify();
        inserted
    }

    /// 当前由哈希守护追加的路径集合。
    pub fn hash_paths(&self) -> Vec<String> {
        let guard = self.hash_blocked.lock().unwrap_or_else(|err| err.into_inner());
        guard.iter().cloned().collect()
    }

    pub fn ticker(&self) -> &Ticker {
        &self.ticker
    }

    fn commit(&self, evaluation: &Evaluation, applied: &[String], error: Option<String>) {
        let mut guard = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        guard.snapshot.evaluation = evaluation.clone();
        guard.snapshot.applied = applied.to_vec();
        if error.is_some() {
            guard.snapshot.last_error = error;
        }
    }
}

/// 启动后台工作线程。
pub fn spawn_worker(engine: Arc<Engine>) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name(String::from("netguard-worker"))
        .spawn(move || engine.run_worker())
        .expect("无法创建工作线程")
}

/// 把本地时间（无时区）转换为带时区时刻。
///
/// 夏令时跳变导致该本地时间不存在时，顺延一小时；歧义（回拨）取较早者。
pub(crate) fn override_deadline(stamp: Option<i64>) -> Option<chrono::NaiveDateTime> {
    use chrono::TimeZone;
    stamp
        .and_then(|value| chrono::Local.timestamp_opt(value, 0).single())
        .map(|value| value.naive_local())
}

fn local_from_naive(naive: chrono::NaiveDateTime) -> Option<chrono::DateTime<chrono::Local>> {
    use chrono::TimeZone;
    match chrono::Local.from_local_datetime(&naive) {
        chrono::LocalResult::Single(dt) => Some(dt),
        chrono::LocalResult::Ambiguous(earlier, _) => Some(earlier),
        chrono::LocalResult::None => chrono::Local
            .from_local_datetime(&(naive + chrono::Duration::hours(1)))
            .earliest()
            .or_else(|| Some(chrono::Local::now())),
    }
}
