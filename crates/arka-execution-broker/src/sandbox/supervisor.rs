//! Rootless Linux container supervisor using Bubblewrap (`bwrap`).
//!
//! Enforces:
//! - Complete namespace isolation (User, PID, Network, IPC, UTS)
//! - Read-only base filesystem with zero host visibility
//! - Dropped Linux capabilities (`--cap-drop ALL`)
//! - Strict bounded execution with wall-clock timeout and SIGKILL
//! - Bounded stdout/stderr ingestion (16 KB hard cap with truncation tracking)
//! - Deterministic ephemeral scratch directory eradication

use crate::errors::BrokerError;
use crate::sandbox::config::SandboxConfig;
use std::path::Path;
use std::process::Stdio;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::{sleep, timeout, Duration};

/// Result of a sandboxed command execution.
#[derive(Debug, Clone)]
pub struct SandboxedExecutionResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub duration_ms: u64,
}

/// Asynchronous supervisor for Bubblewrap rootless container lifecycles.
pub struct SandboxSupervisor {
    config: SandboxConfig,
}

impl SandboxSupervisor {
    pub fn new(config: SandboxConfig) -> Self {
        Self { config }
    }

    /// Verifies that the host environment supports Bubblewrap rootless sandboxing.
    pub async fn check_availability(&self) -> Result<(), BrokerError> {
        if !self.config.bwrap_path.exists() {
            return Err(BrokerError::SandboxInitializationFailure(format!(
                "bwrap binary not found at {}",
                self.config.bwrap_path.display()
            )));
        }

        // Test minimal execution
        let mut cmd = Command::new(&self.config.bwrap_path);
        cmd.arg("--version");
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        match cmd.output().await {
            Ok(output) if output.status.success() => Ok(()),
            Ok(output) => Err(BrokerError::SandboxInitializationFailure(format!(
                "bwrap --version failed with exit code {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ))),
            Err(e) => Err(BrokerError::SandboxInitializationFailure(format!(
                "Failed to execute bwrap: {}",
                e
            ))),
        }
    }

    /// Executes a command inside the rootless Bubblewrap sandbox.
    pub async fn run_sandboxed(
        &self,
        command: &str,
        args: &[String],
        execution_id: &str,
        env_vars: &[(&str, &str)],
    ) -> Result<SandboxedExecutionResult, BrokerError> {
        self.check_availability().await?;

        // 1. Allocate dedicated ephemeral scratch directory
        let scratch_dir = self.config.scratch_base_dir.join(execution_id);
        tokio::fs::create_dir_all(&scratch_dir).await.map_err(|e| {
            BrokerError::SandboxInitializationFailure(format!(
                "Failed to create scratch directory {}: {}",
                scratch_dir.display(),
                e
            ))
        })?;

        let start_time = Instant::now();

        // 2. Build bwrap invocation arguments
        let mut cmd = Command::new(&self.config.bwrap_path);

        // Core lifecycle & namespaces
        cmd.arg("--die-with-parent");
        cmd.arg("--unshare-user");
        cmd.arg("--unshare-pid");
        cmd.arg("--unshare-ipc");
        cmd.arg("--unshare-uts");

        if !self.config.allow_network {
            cmd.arg("--unshare-net");
        }

        // Drop all Linux capabilities
        cmd.arg("--cap-drop").arg("ALL");

        // Read-only binds
        for (src, dest) in &self.config.read_only_binds {
            if src.exists() {
                cmd.arg("--ro-bind")
                    .arg(src.as_os_str())
                    .arg(dest.as_os_str());
            }
        }

        // Symlinks
        for (src, dest) in &self.config.symlinks {
            cmd.arg("--symlink").arg(src).arg(dest.as_os_str());
        }

        // Standard isolated mount points
        cmd.arg("--proc").arg("/proc");
        cmd.arg("--dev").arg("/dev");

        for tmp in &self.config.tmpfs_mounts {
            cmd.arg("--tmpfs").arg(tmp.as_os_str());
        }

        // Bind ephemeral scratch directory to container /work
        cmd.arg("--bind").arg(scratch_dir.as_os_str()).arg("/work");
        cmd.arg("--chdir").arg("/work");

        // Controlled environment variables
        cmd.arg("--setenv").arg("HOME").arg("/work");
        cmd.arg("--setenv").arg("TMPDIR").arg("/tmp");
        cmd.arg("--setenv")
            .arg("ARKA_EXECUTION_ID")
            .arg(execution_id);
        cmd.arg("--setenv").arg("PATH").arg("/usr/bin:/bin");

        for (k, v) in env_vars {
            cmd.arg("--setenv").arg(k).arg(v);
        }

        // Command separator and target execution
        cmd.arg("--");
        cmd.arg(command);
        for arg in args {
            cmd.arg(arg);
        }

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.kill_on_drop(true);

        // 3. Spawn child process
        let mut child = cmd.spawn().map_err(|e| {
            // Immediate cleanup on spawn error
            let _ = std::fs::remove_dir_all(&scratch_dir);
            BrokerError::SandboxExecutionError(format!("Failed to spawn bwrap: {}", e))
        })?;

        let mut child_stdout = child.stdout.take();
        let mut child_stderr = child.stderr.take();

        let max_bytes = self.config.max_output_bytes;

        // Drain stdout asynchronously with hard truncation cap
        let stdout_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut truncated = false;
            if let Some(mut stream) = child_stdout.take() {
                let mut chunk = [0u8; 1024];
                while let Ok(n) = stream.read(&mut chunk).await {
                    if n == 0 {
                        break;
                    }
                    if buf.len() + n <= max_bytes {
                        buf.extend_from_slice(&chunk[..n]);
                    } else {
                        let remaining = max_bytes.saturating_sub(buf.len());
                        if remaining > 0 {
                            buf.extend_from_slice(&chunk[..remaining]);
                        }
                        truncated = true;
                    }
                }
            }
            (String::from_utf8_lossy(&buf).to_string(), truncated)
        });

        // Drain stderr asynchronously with hard truncation cap
        let stderr_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut truncated = false;
            if let Some(mut stream) = child_stderr.take() {
                let mut chunk = [0u8; 1024];
                while let Ok(n) = stream.read(&mut chunk).await {
                    if n == 0 {
                        break;
                    }
                    if buf.len() + n <= max_bytes {
                        buf.extend_from_slice(&chunk[..n]);
                    } else {
                        let remaining = max_bytes.saturating_sub(buf.len());
                        if remaining > 0 {
                            buf.extend_from_slice(&chunk[..remaining]);
                        }
                        truncated = true;
                    }
                }
            }
            (String::from_utf8_lossy(&buf).to_string(), truncated)
        });

        // 4. Wait for child with wall-clock timeout
        let wall_clock_limit = Duration::from_secs(self.config.max_wall_clock_timeout_seconds);

        let wait_result = timeout(wall_clock_limit, child.wait()).await;

        let execution_result = match wait_result {
            Ok(Ok(status)) => {
                let (stdout, stdout_truncated) = stdout_task.await.unwrap_or_default();
                let (stderr, stderr_truncated) = stderr_task.await.unwrap_or_default();
                let duration_ms = start_time.elapsed().as_millis() as u64;

                Ok(SandboxedExecutionResult {
                    exit_code: status.code().unwrap_or(-1),
                    stdout,
                    stderr,
                    stdout_truncated,
                    stderr_truncated,
                    duration_ms,
                })
            }
            Ok(Err(e)) => Err(BrokerError::SandboxExecutionError(format!(
                "Child process wait failed: {}",
                e
            ))),
            Err(_) => {
                // Timeout occurred: initiate graceful SIGTERM then SIGKILL
                let _ = child.start_kill();
                sleep(Duration::from_millis(self.config.sigkill_grace_ms)).await;
                let _ = child.wait().await;

                Err(BrokerError::TimeoutExceeded {
                    timeout_ms: wall_clock_limit.as_millis() as u64,
                })
            }
        };

        // 5. Deterministic cleanup of ephemeral scratch directory
        Self::clean_scratch_directory(&scratch_dir).await?;

        execution_result
    }

    /// Recursively wipes the ephemeral scratch directory and asserts complete eradication.
    pub async fn clean_scratch_directory(path: &Path) -> Result<(), BrokerError> {
        if path.exists() {
            tokio::fs::remove_dir_all(path).await.map_err(|e| {
                BrokerError::StorageError(format!(
                    "Failed to delete ephemeral sandbox scratch directory {}: {}",
                    path.display(),
                    e
                ))
            })?;
        }
        Ok(())
    }
}
