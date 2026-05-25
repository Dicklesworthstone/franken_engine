//! Windows x64 worker implementation for RCH worker pools.
//!
//! Provides worker pool management and execution capabilities for Windows x64
//! platforms in the RCH (Remote Compilation Host) system.

#![forbid(unsafe_code)]

use crate::worker_env_capture::{WindowsX64EnvCapture, WorkerEnvCapture, WorkerEnvironment, EnvCaptureError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wait_timeout::ChildExt;

/// Static counter for generating unique worker IDs.
static NEXT_WORKER_ID: AtomicU64 = AtomicU64::new(1);

/// Windows x64 worker instance in the RCH pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsX64Worker {
    /// Unique identifier for this worker instance.
    pub worker_id: String,
    /// Worker status.
    pub status: WorkerStatus,
    /// Environment information captured from this worker.
    pub environment: WorkerEnvironment,
    /// Worker capabilities.
    pub capabilities: WorkerCapabilities,
    /// Worker resource limits.
    pub resource_limits: WorkerResourceLimits,
    /// Timestamp when worker was created.
    pub created_at: String,
    /// Timestamp of last activity.
    pub last_activity_at: String,
}

/// Status of a worker in the pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerStatus {
    /// Worker is initializing.
    Initializing,
    /// Worker is idle and available for work.
    Idle,
    /// Worker is actively executing a job.
    Busy,
    /// Worker is temporarily unavailable due to maintenance.
    Maintenance,
    /// Worker has failed and needs intervention.
    Failed,
    /// Worker is being shut down.
    ShuttingDown,
    /// Worker has been permanently removed.
    Terminated,
}

impl WorkerStatus {
    /// Check if the worker is available for new work.
    pub fn is_available(&self) -> bool {
        matches!(self, WorkerStatus::Idle)
    }

    /// Check if the worker is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, WorkerStatus::Failed | WorkerStatus::Terminated)
    }

    /// Get string representation of the status.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Initializing => "initializing",
            Self::Idle => "idle",
            Self::Busy => "busy",
            Self::Maintenance => "maintenance",
            Self::Failed => "failed",
            Self::ShuttingDown => "shutting_down",
            Self::Terminated => "terminated",
        }
    }
}

/// Worker capabilities configuration for Windows x64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerCapabilities {
    /// Maximum number of concurrent jobs this worker can handle.
    pub max_concurrent_jobs: u32,
    /// Supported target platforms for compilation.
    pub supported_targets: Vec<String>,
    /// Supported Rust toolchain channels.
    pub supported_channels: Vec<String>,
    /// Whether worker supports cross-compilation.
    pub cross_compilation: bool,
    /// Whether worker has network access.
    pub network_access: bool,
}

impl Default for WorkerCapabilities {
    fn default() -> Self {
        Self {
            max_concurrent_jobs: 1,
            supported_targets: vec![
                "x86_64-pc-windows-msvc".to_string(),
                "x86_64-pc-windows-gnu".to_string(),
            ],
            supported_channels: vec![
                "stable".to_string(),
                "beta".to_string(),
                "nightly".to_string(),
            ],
            cross_compilation: true,
            network_access: true,
        }
    }
}

/// Worker resource limits configuration for Windows x64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerResourceLimits {
    /// Maximum CPU usage percentage (0-100).
    pub max_cpu_percent: u32,
    /// Maximum memory usage in bytes.
    pub max_memory_bytes: u64,
    /// Maximum disk usage in bytes.
    pub max_disk_bytes: u64,
    /// Maximum job execution time in seconds.
    pub max_job_time_seconds: u64,
    /// Maximum network bandwidth in bytes per second.
    pub max_network_bytes_per_sec: Option<u64>,
}

impl Default for WorkerResourceLimits {
    fn default() -> Self {
        Self {
            max_cpu_percent: 80,
            max_memory_bytes: 8 * 1024 * 1024 * 1024, // 8GB
            max_disk_bytes: 50 * 1024 * 1024 * 1024,  // 50GB
            max_job_time_seconds: 3600,                // 1 hour
            max_network_bytes_per_sec: None,           // Unlimited
        }
    }
}

/// Configuration for creating Windows x64 workers.
#[derive(Debug, Clone)]
pub struct WindowsX64WorkerConfig {
    /// Worker capabilities.
    pub capabilities: WorkerCapabilities,
    /// Worker resource limits.
    pub resource_limits: WorkerResourceLimits,
    /// Base working directory for the worker.
    pub work_dir: PathBuf,
    /// Whether to enable verbose logging.
    pub verbose: bool,
}

impl Default for WindowsX64WorkerConfig {
    fn default() -> Self {
        Self {
            capabilities: WorkerCapabilities::default(),
            resource_limits: WorkerResourceLimits::default(),
            work_dir: std::env::temp_dir().join("rch_workers"),
            verbose: false,
        }
    }
}

/// Windows x64 worker factory and manager.
#[derive(Debug)]
pub struct WindowsX64WorkerManager {
    /// Configuration for creating workers.
    config: WindowsX64WorkerConfig,
    /// Active workers in the pool.
    workers: BTreeMap<String, WindowsX64Worker>,
    /// Environment capture utility.
    env_capture: WindowsX64EnvCapture,
}

impl WindowsX64WorkerManager {
    /// Create a new worker manager with the given configuration.
    pub fn new(config: WindowsX64WorkerConfig) -> Self {
        Self {
            config,
            workers: BTreeMap::new(),
            env_capture: WindowsX64EnvCapture::new(),
        }
    }

    /// Create a new worker manager with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(WindowsX64WorkerConfig::default())
    }

    /// Create a new worker and add it to the pool.
    pub fn create_worker(&mut self) -> Result<String, WindowsWorkerError> {
        // Generate unique worker ID
        let worker_num = NEXT_WORKER_ID.fetch_add(1, Ordering::SeqCst);
        let worker_id = format!("windows-x64-{}", worker_num);

        // Capture environment information
        let environment = self.env_capture.capture_environment()
            .map_err(WindowsWorkerError::EnvironmentCapture)?;

        // Verify platform compatibility
        if environment.os != "windows" || environment.arch != "x64" {
            return Err(WindowsWorkerError::PlatformMismatch {
                expected: "windows-x64".to_string(),
                actual: format!("{}-{}", environment.os, environment.arch),
            });
        }

        let now = chrono::Utc::now().to_rfc3339();

        let worker = WindowsX64Worker {
            worker_id: worker_id.clone(),
            status: WorkerStatus::Initializing,
            environment,
            capabilities: self.config.capabilities.clone(),
            resource_limits: self.config.resource_limits.clone(),
            created_at: now.clone(),
            last_activity_at: now,
        };

        // Initialize worker workspace
        self.initialize_worker_workspace(&worker_id)?;

        self.workers.insert(worker_id.clone(), worker);

        Ok(worker_id)
    }

    /// Get information about a specific worker.
    pub fn get_worker(&self, worker_id: &str) -> Option<&WindowsX64Worker> {
        self.workers.get(worker_id)
    }

    /// Get mutable reference to a specific worker.
    pub fn get_worker_mut(&mut self, worker_id: &str) -> Option<&mut WindowsX64Worker> {
        self.workers.get_mut(worker_id)
    }

    /// List all workers in the pool.
    pub fn list_workers(&self) -> Vec<&WindowsX64Worker> {
        self.workers.values().collect()
    }

    /// Mark a worker as idle and available for work.
    pub fn mark_worker_idle(&mut self, worker_id: &str) -> Result<(), WindowsWorkerError> {
        let worker = self.workers.get_mut(worker_id)
            .ok_or_else(|| WindowsWorkerError::WorkerNotFound { worker_id: worker_id.to_string() })?;

        worker.status = WorkerStatus::Idle;
        worker.last_activity_at = chrono::Utc::now().to_rfc3339();

        Ok(())
    }

    /// Mark a worker as busy executing a job.
    pub fn mark_worker_busy(&mut self, worker_id: &str) -> Result<(), WindowsWorkerError> {
        let worker = self.workers.get_mut(worker_id)
            .ok_or_else(|| WindowsWorkerError::WorkerNotFound { worker_id: worker_id.to_string() })?;

        worker.status = WorkerStatus::Busy;
        worker.last_activity_at = chrono::Utc::now().to_rfc3339();

        Ok(())
    }

    /// Remove a worker from the pool.
    pub fn remove_worker(&mut self, worker_id: &str) -> Result<WindowsX64Worker, WindowsWorkerError> {
        let worker = self.workers.remove(worker_id)
            .ok_or_else(|| WindowsWorkerError::WorkerNotFound { worker_id: worker_id.to_string() })?;

        // Clean up worker workspace
        self.cleanup_worker_workspace(worker_id)?;

        Ok(worker)
    }

    /// Get the number of available workers.
    pub fn available_worker_count(&self) -> usize {
        self.workers.values()
            .filter(|w| w.status.is_available())
            .count()
    }

    /// Get the total number of workers.
    pub fn total_worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Write environment information to a JSON file for a worker.
    pub fn export_worker_env(&self, worker_id: &str, output_path: &Path) -> Result<(), WindowsWorkerError> {
        let worker = self.workers.get(worker_id)
            .ok_or_else(|| WindowsWorkerError::WorkerNotFound { worker_id: worker_id.to_string() })?;

        let json = serde_json::to_string_pretty(&worker.environment)
            .map_err(|e| WindowsWorkerError::Serialization { details: e.to_string() })?;

        std::fs::write(output_path, json)
            .map_err(|e| WindowsWorkerError::IoError {
                operation: "write_env_json".to_string(),
                path: output_path.to_string_lossy().to_string(),
                error: e.to_string(),
            })?;

        Ok(())
    }

    /// Execute a command on a specific worker.
    pub fn execute_on_worker(
        &mut self,
        worker_id: &str,
        command: &[String],
        working_dir: Option<&Path>,
        timeout_seconds: Option<u64>,
    ) -> Result<WorkerExecutionResult, WindowsWorkerError> {
        let worker = self.workers.get_mut(worker_id)
            .ok_or_else(|| WindowsWorkerError::WorkerNotFound { worker_id: worker_id.to_string() })?;

        if !worker.status.is_available() {
            return Err(WindowsWorkerError::WorkerNotAvailable {
                worker_id: worker_id.to_string(),
                status: worker.status.as_str().to_string(),
            });
        }

        worker.status = WorkerStatus::Busy;

        // Prepare command - use cmd.exe for Windows
        if command.is_empty() {
            return Err(WindowsWorkerError::InvalidCommand { details: "Empty command".to_string() });
        }

        let mut cmd = Command::new("cmd");
        cmd.args(["/C"]);
        cmd.args(command);

        // Set working directory
        let default_work_dir = self.config.work_dir.join(worker_id);
        let work_dir = working_dir.unwrap_or(&default_work_dir);
        cmd.current_dir(work_dir);

        // Configure command execution
        cmd.stdout(Stdio::piped())
           .stderr(Stdio::piped());

        let start_time = SystemTime::now();
        let mut child = cmd.spawn()
            .map_err(|e| WindowsWorkerError::CommandExecution {
                command: command.join(" "),
                error: e.to_string()
            })?;

        // Handle timeout if specified
        let output = if let Some(timeout_secs) = timeout_seconds {
            match child.wait_timeout(Duration::from_secs(timeout_secs)) {
                Ok(Some(status)) => {
                    let mut stdout = Vec::new();
                    let mut stderr = Vec::new();
                    let _ = child.stdout.take().unwrap().read_to_end(&mut stdout);
                    let _ = child.stderr.take().unwrap().read_to_end(&mut stderr);
                    std::process::Output {
                        status,
                        stdout,
                        stderr,
                    }
                }
                Ok(None) => {
                    // Timeout occurred
                    let _ = child.kill();
                    let _ = child.wait(); // Clean up zombie
                    worker.status = WorkerStatus::Idle;
                    return Err(WindowsWorkerError::CommandTimeout {
                        timeout_seconds: timeout_secs,
                        command: command.join(" "),
                    });
                }
                Err(e) => {
                    worker.status = WorkerStatus::Idle;
                    return Err(WindowsWorkerError::CommandExecution {
                        command: command.join(" "),
                        error: e.to_string(),
                    });
                }
            }
        } else {
            child.wait_with_output()
                .map_err(|e| WindowsWorkerError::CommandExecution {
                    command: command.join(" "),
                    error: e.to_string(),
                })?
        };

        let elapsed = start_time.elapsed().unwrap_or(Duration::from_secs(0));
        worker.status = WorkerStatus::Idle;
        worker.last_activity_at = chrono::Utc::now().to_rfc3339();

        Ok(WorkerExecutionResult {
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            elapsed_seconds: elapsed.as_secs(),
            worker_id: worker_id.to_string(),
            command: command.join(" "),
        })
    }

    /// Initialize workspace for a worker.
    fn initialize_worker_workspace(&self, worker_id: &str) -> Result<(), WindowsWorkerError> {
        let workspace_dir = self.config.work_dir.join(worker_id);
        std::fs::create_dir_all(&workspace_dir)
            .map_err(|e| WindowsWorkerError::IoError {
                operation: "create_workspace".to_string(),
                path: workspace_dir.to_string_lossy().to_string(),
                error: e.to_string(),
            })?;

        Ok(())
    }

    /// Clean up workspace for a worker.
    fn cleanup_worker_workspace(&self, worker_id: &str) -> Result<(), WindowsWorkerError> {
        let workspace_dir = self.config.work_dir.join(worker_id);
        if workspace_dir.exists() {
            std::fs::remove_dir_all(&workspace_dir)
                .map_err(|e| WindowsWorkerError::IoError {
                    operation: "cleanup_workspace".to_string(),
                    path: workspace_dir.to_string_lossy().to_string(),
                    error: e.to_string(),
                })?;
        }

        Ok(())
    }
}

/// Result of executing a command on a Windows worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerExecutionResult {
    /// Exit code of the command.
    pub exit_code: Option<i32>,
    /// Standard output from the command.
    pub stdout: String,
    /// Standard error from the command.
    pub stderr: String,
    /// Elapsed time in seconds.
    pub elapsed_seconds: u64,
    /// ID of the worker that executed the command.
    pub worker_id: String,
    /// The command that was executed.
    pub command: String,
}

/// Errors that can occur in Windows x64 worker operations.
#[derive(Debug, thiserror::Error)]
pub enum WindowsWorkerError {
    #[error("Environment capture failed: {0}")]
    EnvironmentCapture(#[from] EnvCaptureError),

    #[error("Platform mismatch: expected {expected}, got {actual}")]
    PlatformMismatch { expected: String, actual: String },

    #[error("Worker not found: {worker_id}")]
    WorkerNotFound { worker_id: String },

    #[error("Worker not available: {worker_id} (status: {status})")]
    WorkerNotAvailable { worker_id: String, status: String },

    #[error("Command execution failed: {command} - {error}")]
    CommandExecution { command: String, error: String },

    #[error("Command timeout after {timeout_seconds}s: {command}")]
    CommandTimeout { timeout_seconds: u64, command: String },

    #[error("Invalid command: {details}")]
    InvalidCommand { details: String },

    #[error("I/O error during {operation} on {path}: {error}")]
    IoError { operation: String, path: String, error: String },

    #[error("Serialization error: {details}")]
    Serialization { details: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_config() -> WindowsX64WorkerConfig {
        let temp_dir = TempDir::new().expect("create temp dir");
        WindowsX64WorkerConfig {
            capabilities: WorkerCapabilities::default(),
            resource_limits: WorkerResourceLimits::default(),
            work_dir: temp_dir.path().to_path_buf(),
            verbose: false,
        }
    }

    #[test]
    fn test_worker_status_methods() {
        assert!(WorkerStatus::Idle.is_available());
        assert!(!WorkerStatus::Busy.is_available());
        assert!(!WorkerStatus::Failed.is_terminal());
        assert!(WorkerStatus::Terminated.is_terminal());

        assert_eq!(WorkerStatus::Idle.as_str(), "idle");
        assert_eq!(WorkerStatus::Busy.as_str(), "busy");
    }

    #[test]
    fn test_worker_capabilities_default() {
        let caps = WorkerCapabilities::default();
        assert_eq!(caps.max_concurrent_jobs, 1);
        assert!(caps.supported_targets.contains(&"x86_64-pc-windows-msvc".to_string()));
        assert!(caps.cross_compilation);
        assert!(caps.network_access);
    }

    #[test]
    fn test_worker_manager_creation() {
        let config = create_test_config();
        let manager = WindowsX64WorkerManager::new(config);
        assert_eq!(manager.total_worker_count(), 0);
        assert_eq!(manager.available_worker_count(), 0);
    }

    #[test]
    fn test_worker_serialization() {
        let worker = WindowsX64Worker {
            worker_id: "test-worker-1".to_string(),
            status: WorkerStatus::Idle,
            environment: WorkerEnvironment {
                os: "windows".to_string(),
                arch: "x64".to_string(),
                os_version: "Windows 11".to_string(),
                rust_toolchain: crate::worker_env_capture::RustToolchainInfo {
                    version: "1.75.0".to_string(),
                    target: "x86_64-pc-windows-msvc".to_string(),
                    commit_hash: None,
                    commit_date: None,
                    channel: "stable".to_string(),
                },
                dev_tools: BTreeMap::new(),
                env_vars: BTreeMap::new(),
                captured_at: "2026-05-21T19:00:00Z".to_string(),
            },
            capabilities: WorkerCapabilities::default(),
            resource_limits: WorkerResourceLimits::default(),
            created_at: "2026-05-21T19:00:00Z".to_string(),
            last_activity_at: "2026-05-21T19:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&worker).expect("serialization should work");
        let deserialized: WindowsX64Worker = serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(worker, deserialized);
    }

    #[test]
    fn test_execution_result_serialization() {
        let result = WorkerExecutionResult {
            exit_code: Some(0),
            stdout: "Hello, world!".to_string(),
            stderr: "".to_string(),
            elapsed_seconds: 1,
            worker_id: "test-worker-1".to_string(),
            command: "echo Hello, world!".to_string(),
        };

        let json = serde_json::to_string(&result).expect("serialization should work");
        let deserialized: WorkerExecutionResult = serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(result, deserialized);
    }

    #[test]
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn test_create_worker_on_windows_x64() {
        let config = create_test_config();
        let mut manager = WindowsX64WorkerManager::new(config);

        let worker_id = manager.create_worker().expect("should create worker on Windows x64");
        assert!(!worker_id.is_empty());
        assert_eq!(manager.total_worker_count(), 1);

        let worker = manager.get_worker(&worker_id).expect("worker should exist");
        assert_eq!(worker.worker_id, worker_id);
        assert_eq!(worker.environment.os, "windows");
        assert_eq!(worker.environment.arch, "x64");
    }

    #[test]
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    fn test_create_worker_wrong_platform() {
        let config = create_test_config();
        let mut manager = WindowsX64WorkerManager::new(config);

        let result = manager.create_worker();
        assert!(result.is_err(), "should fail to create worker on wrong platform");

        match result.unwrap_err() {
            WindowsWorkerError::EnvironmentCapture(EnvCaptureError::UnsupportedPlatform { .. }) => {
                // Expected error
            }
            other => panic!("Expected UnsupportedPlatform error, got: {:?}", other),
        }
    }

    #[test]
    fn test_worker_state_management() {
        let config = create_test_config();
        let mut manager = WindowsX64WorkerManager::new(config);

        // This test will work on any platform since we're not actually creating a worker
        let worker_id = "test-worker".to_string();

        // Manually insert a test worker
        let worker = WindowsX64Worker {
            worker_id: worker_id.clone(),
            status: WorkerStatus::Idle,
            environment: WorkerEnvironment {
                os: "windows".to_string(),
                arch: "x64".to_string(),
                os_version: "Windows 11".to_string(),
                rust_toolchain: crate::worker_env_capture::RustToolchainInfo {
                    version: "1.75.0".to_string(),
                    target: "x86_64-pc-windows-msvc".to_string(),
                    commit_hash: None,
                    commit_date: None,
                    channel: "stable".to_string(),
                },
                dev_tools: BTreeMap::new(),
                env_vars: BTreeMap::new(),
                captured_at: "2026-05-21T19:00:00Z".to_string(),
            },
            capabilities: WorkerCapabilities::default(),
            resource_limits: WorkerResourceLimits::default(),
            created_at: "2026-05-21T19:00:00Z".to_string(),
            last_activity_at: "2026-05-21T19:00:00Z".to_string(),
        };

        manager.workers.insert(worker_id.clone(), worker);

        // Test state transitions
        assert_eq!(manager.available_worker_count(), 1);

        manager.mark_worker_busy(&worker_id).expect("should mark worker busy");
        assert_eq!(manager.available_worker_count(), 0);

        manager.mark_worker_idle(&worker_id).expect("should mark worker idle");
        assert_eq!(manager.available_worker_count(), 1);

        // Test removal
        let removed_worker = manager.remove_worker(&worker_id).expect("should remove worker");
        assert_eq!(removed_worker.worker_id, worker_id);
        assert_eq!(manager.total_worker_count(), 0);
    }
}