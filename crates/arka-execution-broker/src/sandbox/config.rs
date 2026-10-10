//! Rootless container sandbox configuration.
//!
//! Enforces:
//! - Dropped Linux capabilities (`--cap-drop ALL`)
//! - Non-root execution with unprivileged UID/GID mapping
//! - Read-only host filesystem enclosure
//! - Isolated namespaces (User, PID, Net, IPC, UTS)
//! - Hard resource boundaries (timeouts, bounded output, memory/process limits)

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Path to Bubblewrap (`bwrap`) executable.
    pub bwrap_path: PathBuf,
    /// Allow outbound network in the container (defaults to false for loopback-only isolation).
    pub allow_network: bool,
    /// Read-only directory bindings from host into container.
    pub read_only_binds: Vec<(PathBuf, PathBuf)>,
    /// Symlinks to construct inside container rootfs.
    pub symlinks: Vec<(String, PathBuf)>,
    /// Paths to mount as ephemeral in-memory tmpfs.
    pub tmpfs_mounts: Vec<PathBuf>,
    /// Base directory on host where per-execution scratch folders are created.
    pub scratch_base_dir: PathBuf,
    /// Maximum execution wall-clock time in seconds.
    pub max_wall_clock_timeout_seconds: u64,
    /// Hard limit on stdout/stderr bytes collected (default 16 KB).
    pub max_output_bytes: usize,
    /// Grace period in milliseconds before escalating SIGTERM to SIGKILL.
    pub sigkill_grace_ms: u64,
    /// Invariant toggle: production target execution forbidden until formal sign-off.
    pub production_execution_allowed: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            bwrap_path: PathBuf::from("/usr/bin/bwrap"),
            allow_network: false,
            read_only_binds: vec![(PathBuf::from("/usr"), PathBuf::from("/usr"))],
            symlinks: vec![
                ("usr/bin".to_string(), PathBuf::from("/bin")),
                ("usr/lib".to_string(), PathBuf::from("/lib")),
                ("usr/lib64".to_string(), PathBuf::from("/lib64")),
            ],
            tmpfs_mounts: vec![PathBuf::from("/tmp")],
            scratch_base_dir: PathBuf::from("/tmp/arka-sandbox-scratch"),
            max_wall_clock_timeout_seconds: 30,
            max_output_bytes: 16384, // 16 KB per stream
            sigkill_grace_ms: 500,   // 500ms grace
            production_execution_allowed: false,
        }
    }
}

impl SandboxConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_bwrap_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.bwrap_path = path.into();
        self
    }

    pub fn with_allow_network(mut self, allow: bool) -> Self {
        self.allow_network = allow;
        self
    }

    pub fn with_scratch_base_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.scratch_base_dir = dir.into();
        self
    }

    pub fn with_timeout_seconds(mut self, seconds: u64) -> Self {
        self.max_wall_clock_timeout_seconds = seconds;
        self
    }

    pub fn with_max_output_bytes(mut self, bytes: usize) -> Self {
        self.max_output_bytes = bytes;
        self
    }
}
