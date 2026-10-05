//! Injectable Clock abstraction.
//!
//! Enables deterministic testing of token expiration, approval timeouts, and clock boundaries.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub trait Clock: Send + Sync {
    /// Returns the current Unix timestamp in seconds.
    fn now_unix(&self) -> u64;
}

/// Standard wall-clock implementation for production runtime.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Deterministic mock clock for tests.
#[derive(Debug, Clone)]
pub struct MockClock {
    now: Arc<AtomicU64>,
}

impl MockClock {
    pub fn new(initial_unix: u64) -> Self {
        Self {
            now: Arc::new(AtomicU64::new(initial_unix)),
        }
    }

    pub fn set_now(&self, timestamp: u64) {
        self.now.store(timestamp, Ordering::SeqCst);
    }

    pub fn advance(&self, seconds: u64) {
        self.now.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl Clock for MockClock {
    fn now_unix(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}
