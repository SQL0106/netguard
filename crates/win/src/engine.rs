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

        let (config, integrity_ok, integrity_note) = match store.load() {
            Load::Ok(config) => (config, true, String::new()),
            Load::Absent => {
                logger.warn("尚未初始化：未找到配置，暂不拦截任何应用");
                (Config::default(), true, String::from("尚未初始化"))
            }
            Load::Tampered(note) => {
                logger.error(&format!("配置校验失败：{note}"));
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
    /// 校验失败时按失效即封锁处理，并保留快照中的旧配置用于显示。
    pub fn reload_from_disk(&self) -> Reload {
        match self.store.load() {
            Load::Ok(config) => {
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
            Load::Absent => {
                {
                    let mut guard = self.inner.lock().unwrap_or_else(|err| err.into_inner());
                    guard.snapshot.integrity_ok = false;
                    guard.snapshot.integrity_note = String::from("配置文件缺失");
                }
                self.logger.error("配置文件缺失，按失效即封锁处理");
                self.notify();
                Reload::Tampered(String::from("配置文件缺失"))
            }
            Load::Tampered(note) => {
                {
                    let mut guard = self.inner.lock().unwrap_or_else(|err| err.into_inner());
                    guard.snapshot.integrity_ok = false;
                    guard.snapshot.integrity_note = note.clone();
                }
                self.logger.error(&format!("配置文件校验失败：{note}"));
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

    /// 工作线程主循环：只在边界或显式唤醒时执行。
    pub fn run_worker(self: Arc<Self>) {
        let mut engine: Option<wfp::Engine> = None;
        let mut last_signature: Option<(bool, Vec<String>)> = None;
        let mut retry_at: Option<Instant> = None;

        loop {
            let snapshot = self.snapshot();
            let now = chrono::Local::now().naive_local();
            let evaluation = evaluate(&snapshot.config, now, override_deadline(snapshot.state.override_until));
            let mut blocked = if snapshot.integrity_ok {
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

            if last_signature.as_ref() != Some(&signature) {
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
