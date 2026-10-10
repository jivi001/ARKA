//! Resource Governor for Execution Broker workloads.
//!
//! Enforces:
//! - GATE-WORKER-RESOURCE-001 (CTRL-WORKER-RESOURCE-001 / TEST-WORKER-RESOURCE-001)
//! - Pre-execution bounds: concurrency, execution wall-clock timeouts, memory, process limits
//! - Fail-closed rejection when limits or quotas are exhausted
//! - Deterministic RAII resource tracking via `ResourcePermit`

use crate::errors::BrokerError;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Resource limit ceilings governing worker execution.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum concurrent worker executions platform-wide (default: 10).
    pub max_concurrent_workers: usize,
    /// Maximum wall-clock execution duration in seconds (default: 30s).
    pub max_wall_clock_timeout_seconds: u64,
    /// Maximum memory limit in bytes per worker (default: 512 MB).
    pub max_memory_bytes: u64,
    /// Maximum process count spawned per sandbox (default: 32).
    pub max_process_count: u32,
    /// Maximum bytes collected per stdout/stderr stream (default: 16 KB).
    pub max_output_bytes: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_concurrent_workers: 10,
            max_wall_clock_timeout_seconds: 30,
            max_memory_bytes: 512 * 1024 * 1024, // 512 MB
            max_process_count: 32,
            max_output_bytes: 16384, // 16 KB
        }
    }
}

impl ResourceLimits {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_concurrent_workers(mut self, max: usize) -> Self {
        self.max_concurrent_workers = max;
        self
    }

    pub fn with_max_timeout_seconds(mut self, seconds: u64) -> Self {
        self.max_wall_clock_timeout_seconds = seconds;
        self
    }

    pub fn with_max_memory_bytes(mut self, bytes: u64) -> Self {
        self.max_memory_bytes = bytes;
        self
    }

    pub fn with_max_output_bytes(mut self, bytes: usize) -> Self {
        self.max_output_bytes = bytes;
        self
    }
}

/// Active resource governor tracking active workers and enforcing resource quotas.
pub struct ResourceGovernor {
    limits: ResourceLimits,
    active_workers: Arc<AtomicUsize>,
}

impl ResourceGovernor {
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            active_workers: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    pub fn active_worker_count(&self) -> usize {
        self.active_workers.load(Ordering::SeqCst)
    }

    /// Validates requested resource parameters against governance ceilings before dispatch.
    pub fn validate_request(
        &self,
        requested_timeout_seconds: Option<u64>,
        requested_memory_bytes: Option<u64>,
    ) -> Result<(), BrokerError> {
        if let Some(timeout) = requested_timeout_seconds {
            if timeout > self.limits.max_wall_clock_timeout_seconds {
                return Err(BrokerError::ResourceLimitExceeded(format!(
                    "Requested execution timeout of {}s exceeds maximum limit of {}s",
                    timeout, self.limits.max_wall_clock_timeout_seconds
                )));
            }
        }

        if let Some(memory) = requested_memory_bytes {
            if memory > self.limits.max_memory_bytes {
                return Err(BrokerError::ResourceLimitExceeded(format!(
                    "Requested memory allocation of {} bytes exceeds maximum limit of {} bytes",
                    memory, self.limits.max_memory_bytes
                )));
            }
        }

        Ok(())
    }

    /// Acquires a worker execution slot under concurrency limits.
    /// Returns an RAII `ResourcePermit` that releases the slot when dropped.
    pub fn acquire_worker_slot(&self) -> Result<ResourcePermit, BrokerError> {
        loop {
            let current = self.active_workers.load(Ordering::SeqCst);
            if current >= self.limits.max_concurrent_workers {
                return Err(BrokerError::ConcurrencyLimitReached {
                    current,
                    max: self.limits.max_concurrent_workers,
                });
            }

            if self
                .active_workers
                .compare_exchange_weak(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Ok(ResourcePermit {
                    active_counter: self.active_workers.clone(),
                });
            }
        }
    }
}

/// RAII permit representing an active worker allocation.
/// Automatically decrements the active worker counter upon drop.
#[derive(Debug)]
pub struct ResourcePermit {
    active_counter: Arc<AtomicUsize>,
}

impl Drop for ResourcePermit {
    fn drop(&mut self) {
        self.active_counter.fetch_sub(1, Ordering::SeqCst);
    }
}
