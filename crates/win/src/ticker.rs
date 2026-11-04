//! 单次唤醒的等待器。
//!
//! 排程不使用周期性轮询：服务只在"下一个状态边界"或"需要重新计算"时被唤醒。
//! `notify` 由配置变更、时间变更、电源事件与网络接口变化触发。

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use chrono::{DateTime, Local};

struct Inner {
    generation: Mutex<u64>,
    signal: Condvar,
}

/// 可跨线程共享的等待器。
#[derive(Clone)]
pub struct Ticker {
    inner: Arc<Inner>,
}

impl Ticker {
    /// 新建。
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                generation: Mutex::new(0),
                signal: Condvar::new(),
            }),
        }
    }

    /// 唤醒所有等待者并让它们重新计算。
    pub fn notify(&self) {
        let mut generation = match self.inner.generation.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *generation = generation.wrapping_add(1);
        self.inner.signal.notify_all();
    }

    /// 等待到指定时刻；`None` 表示一直等到下一次唤醒。
    ///
    /// 返回 `true` 表示期间收到过唤醒（应重新计算），
    /// 返回 `false` 表示到达截止时刻。
    pub fn wait_until(&self, deadline: Option<DateTime<Local>>) -> bool {
        let mut generation = match self.inner.generation.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let start = *generation;
        loop {
            let timeout = match deadline {
                Some(at) => {
                    let remaining = at.signed_duration_since(Local::now());
                    remaining.to_std().unwrap_or(Duration::from_millis(0))
                }
                None => Duration::from_secs(24 * 60 * 60),
            };
            let (guard, result) = match self.inner.signal.wait_timeout(generation, timeout) {
                Ok(pair) => pair,
                Err(poisoned) => poisoned.into_inner(),
            };
            generation = guard;
            if *generation != start {
                return true;
            }
            if result.timed_out() {
                return deadline.is_some() && Local::now() >= deadline.unwrap();
            }
        }
    }
}

impl Default for Ticker {
    fn default() -> Self {
        Self::new()
    }
}
