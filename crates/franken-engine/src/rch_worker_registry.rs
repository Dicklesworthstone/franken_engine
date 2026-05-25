//! RCH Worker Registry for managing multi-platform worker pools.
//!
//! Provides centralized management of worker pools across different platforms
//! (macOS ARM64, Windows x64, etc.) for the RCH compilation system.

#![forbid(unsafe_code)]

use crate::macos_arm64_worker::{MacOSArm64WorkerManager, MacOSArm64WorkerConfig, MacOSWorkerError, WorkerExecutionResult as MacOSExecutionResult};
use crate::windows_x64_worker::{WindowsX64WorkerManager, WindowsX64WorkerConfig, WindowsWorkerError, WorkerExecutionResult as WindowsExecutionResult};
use crate::worker_env_capture::{WorkerEnvironment, WorkerEnvCapture, MacOSArm64EnvCapture, WindowsX64EnvCapture};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Common execution result for cross-platform worker operations.
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
}

impl From<MacOSExecutionResult> for WorkerExecutionResult {
    fn from(result: MacOSExecutionResult) -> Self {
        Self {
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
            elapsed_seconds: result.elapsed_seconds,
            worker_id: result.worker_id,
        }
    }
}

impl From<WindowsExecutionResult> for WorkerExecutionResult {
    fn from(result: WindowsExecutionResult) -> Self {
        Self {
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
            elapsed_seconds: result.elapsed_seconds,
            worker_id: result.worker_id,
        }
    }
}

/// Supported worker platform types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WorkerPlatform {
    /// macOS ARM64 (Apple Silicon).
    MacOSArm64,
    /// Windows x64.
    WindowsX64,
    /// Linux x64.
    LinuxX64,
    /// Linux ARM64.
    LinuxArm64,
}

impl WorkerPlatform {
    /// Get the string identifier for this platform.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MacOSArm64 => "macos-arm64",
            Self::WindowsX64 => "windows-x64",
            Self::LinuxX64 => "linux-x64",
            Self::LinuxArm64 => "linux-arm64",
        }
    }

    /// Parse platform from string identifier.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "macos-arm64" => Some(Self::MacOSArm64),
            "windows-x64" => Some(Self::WindowsX64),
            "linux-x64" => Some(Self::LinuxX64),
            "linux-arm64" => Some(Self::LinuxArm64),
            _ => None,
        }
    }

    /// Get all supported platforms.
    pub fn all() -> &'static [Self] {
        &[Self::MacOSArm64, Self::WindowsX64, Self::LinuxX64, Self::LinuxArm64]
    }

    /// Check if this platform is currently supported.
    pub fn is_implemented(&self) -> bool {
        matches!(self, Self::MacOSArm64 | Self::WindowsX64)
    }
}

impl std::fmt::Display for WorkerPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Worker pool statistics for a specific platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerPoolStats {
    /// Platform type.
    pub platform: WorkerPlatform,
    /// Total number of workers.
    pub total_workers: usize,
    /// Number of available workers.
    pub available_workers: usize,
    /// Number of busy workers.
    pub busy_workers: usize,
    /// Number of failed workers.
    pub failed_workers: usize,
}

/// Configuration for the RCH worker registry.
#[derive(Debug, Clone)]
pub struct RchWorkerRegistryConfig {
    /// Base directory for worker workspaces.
    pub base_work_dir: PathBuf,
    /// Maximum number of workers per platform.
    pub max_workers_per_platform: usize,
    /// Whether to enable verbose logging.
    pub verbose: bool,
    /// Platform-specific configurations.
    pub platform_configs: BTreeMap<WorkerPlatform, PlatformConfig>,
}

impl Default for RchWorkerRegistryConfig {
    fn default() -> Self {
        let mut platform_configs = BTreeMap::new();

        // macOS ARM64 default config
        platform_configs.insert(
            WorkerPlatform::MacOSArm64,
            PlatformConfig::MacOSArm64(MacOSArm64WorkerConfig::default()),
        );

        // Windows x64 default config
        platform_configs.insert(
            WorkerPlatform::WindowsX64,
            PlatformConfig::WindowsX64(WindowsX64WorkerConfig::default()),
        );

        Self {
            base_work_dir: std::env::temp_dir().join("rch_workers"),
            max_workers_per_platform: 4,
            verbose: false,
            platform_configs,
        }
    }
}

/// Platform-specific worker configuration.
#[derive(Debug, Clone)]
pub enum PlatformConfig {
    /// macOS ARM64 configuration.
    MacOSArm64(MacOSArm64WorkerConfig),
    /// Windows x64 configuration.
    WindowsX64(WindowsX64WorkerConfig),
    /// Linux x64 configuration (placeholder).
    LinuxX64 { work_dir: PathBuf, verbose: bool },
    /// Linux ARM64 configuration (placeholder).
    LinuxArm64 { work_dir: PathBuf, verbose: bool },
}

/// Central registry for managing RCH worker pools across platforms.
pub struct RchWorkerRegistry {
    /// Registry configuration.
    config: RchWorkerRegistryConfig,
    /// macOS ARM64 worker manager.
    macos_arm64_manager: Option<MacOSArm64WorkerManager>,
    /// Windows x64 worker manager.
    windows_x64_manager: Option<WindowsX64WorkerManager>,
    /// Environment capture instances for each platform.
    env_captures: BTreeMap<WorkerPlatform, Box<dyn WorkerEnvCapture>>,
}

impl RchWorkerRegistry {
    /// Create a new worker registry with the given configuration.
    pub fn new(config: RchWorkerRegistryConfig) -> Self {
        let mut registry = Self {
            config,
            macos_arm64_manager: None,
            windows_x64_manager: None,
            env_captures: BTreeMap::new(),
        };

        registry.initialize_platform_managers();
        registry
    }

    /// Create a new worker registry with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(RchWorkerRegistryConfig::default())
    }

    /// Initialize platform-specific worker managers.
    fn initialize_platform_managers(&mut self) {
        // Initialize macOS ARM64 manager if configured
        if let Some(PlatformConfig::MacOSArm64(macos_config)) = self.config.platform_configs.get(&WorkerPlatform::MacOSArm64) {
            let mut config = macos_config.clone();
            config.work_dir = self.config.base_work_dir.join("macos_arm64");
            config.verbose = self.config.verbose;

            self.macos_arm64_manager = Some(MacOSArm64WorkerManager::new(config));
        }

        // Initialize Windows x64 manager if configured
        if let Some(PlatformConfig::WindowsX64(windows_config)) = self.config.platform_configs.get(&WorkerPlatform::WindowsX64) {
            let mut config = windows_config.clone();
            config.work_dir = self.config.base_work_dir.join("windows_x64");
            config.verbose = self.config.verbose;

            self.windows_x64_manager = Some(WindowsX64WorkerManager::new(config));
        }

        // Initialize environment capture instances
        self.env_captures.insert(
            WorkerPlatform::MacOSArm64,
            Box::new(MacOSArm64EnvCapture::new()),
        );
        self.env_captures.insert(
            WorkerPlatform::WindowsX64,
            Box::new(WindowsX64EnvCapture::new()),
        );
    }

    /// Create a new worker on the specified platform.
    pub fn create_worker(&mut self, platform: WorkerPlatform) -> Result<String, RchWorkerError> {
        match platform {
            WorkerPlatform::MacOSArm64 => {
                let manager = self.macos_arm64_manager.as_mut()
                    .ok_or(RchWorkerError::PlatformNotConfigured { platform })?;

                if manager.total_worker_count() >= self.config.max_workers_per_platform {
                    return Err(RchWorkerError::WorkerLimitReached {
                        platform,
                        limit: self.config.max_workers_per_platform,
                    });
                }

                manager.create_worker()
                    .map_err(|e| RchWorkerError::PlatformError {
                        platform,
                        details: e.to_string(),
                    })
            }
            _ => Err(RchWorkerError::PlatformNotImplemented { platform }),
        }
    }

    /// Get worker pool statistics for a platform.
    pub fn get_pool_stats(&self, platform: WorkerPlatform) -> Result<WorkerPoolStats, RchWorkerError> {
        match platform {
            WorkerPlatform::MacOSArm64 => {
                let manager = self.macos_arm64_manager.as_ref()
                    .ok_or(RchWorkerError::PlatformNotConfigured { platform })?;

                let workers = manager.list_workers();
                let total_workers = workers.len();
                let available_workers = workers.iter().filter(|w| w.status.is_available()).count();
                let busy_workers = workers.iter().filter(|w| matches!(w.status, crate::macos_arm64_worker::WorkerStatus::Busy)).count();
                let failed_workers = workers.iter().filter(|w| w.status.is_terminal()).count();

                Ok(WorkerPoolStats {
                    platform,
                    total_workers,
                    available_workers,
                    busy_workers,
                    failed_workers,
                })
            }
            _ => Err(RchWorkerError::PlatformNotImplemented { platform }),
        }
    }

    /// Get statistics for all configured platforms.
    pub fn get_all_pool_stats(&self) -> BTreeMap<WorkerPlatform, WorkerPoolStats> {
        let mut stats = BTreeMap::new();

        for &platform in &[WorkerPlatform::MacOSArm64] {
            if let Ok(platform_stats) = self.get_pool_stats(platform) {
                stats.insert(platform, platform_stats);
            }
        }

        stats
    }

    /// Execute a command on a specific worker.
    pub fn execute_on_worker(
        &mut self,
        platform: WorkerPlatform,
        worker_id: &str,
        command: &[String],
        working_dir: Option<&Path>,
        timeout_seconds: Option<u64>,
    ) -> Result<WorkerExecutionResult, RchWorkerError> {
        match platform {
            WorkerPlatform::MacOSArm64 => {
                let manager = self.macos_arm64_manager.as_mut()
                    .ok_or(RchWorkerError::PlatformNotConfigured { platform })?;

                manager.execute_on_worker(worker_id, command, working_dir, timeout_seconds)
                    .map(WorkerExecutionResult::from)
                    .map_err(|e| RchWorkerError::PlatformError {
                        platform,
                        details: e.to_string(),
                    })
            }
            _ => Err(RchWorkerError::PlatformNotImplemented { platform }),
        }
    }

    /// Export worker environment to JSON file.
    pub fn export_worker_env(
        &self,
        platform: WorkerPlatform,
        worker_id: &str,
        output_path: &Path,
    ) -> Result<(), RchWorkerError> {
        match platform {
            WorkerPlatform::MacOSArm64 => {
                let manager = self.macos_arm64_manager.as_ref()
                    .ok_or(RchWorkerError::PlatformNotConfigured { platform })?;

                manager.export_worker_env(worker_id, output_path)
                    .map_err(|e| RchWorkerError::PlatformError {
                        platform,
                        details: e.to_string(),
                    })
            }
            _ => Err(RchWorkerError::PlatformNotImplemented { platform }),
        }
    }

    /// Remove a worker from the specified platform.
    pub fn remove_worker(&mut self, platform: WorkerPlatform, worker_id: &str) -> Result<(), RchWorkerError> {
        match platform {
            WorkerPlatform::MacOSArm64 => {
                let manager = self.macos_arm64_manager.as_mut()
                    .ok_or(RchWorkerError::PlatformNotConfigured { platform })?;

                manager.remove_worker(worker_id)
                    .map(|_| ())
                    .map_err(|e| RchWorkerError::PlatformError {
                        platform,
                        details: e.to_string(),
                    })
            }
            _ => Err(RchWorkerError::PlatformNotImplemented { platform }),
        }
    }

    /// List all workers across all platforms.
    pub fn list_all_workers(&self) -> BTreeMap<WorkerPlatform, Vec<String>> {
        let mut workers = BTreeMap::new();

        if let Some(manager) = &self.macos_arm64_manager {
            let macos_workers = manager.list_workers()
                .iter()
                .map(|w| w.worker_id.clone())
                .collect();
            workers.insert(WorkerPlatform::MacOSArm64, macos_workers);
        }

        workers
    }

    /// Get environment information for the current platform.
    pub fn get_current_platform_env(&self) -> Result<WorkerEnvironment, RchWorkerError> {
        let current_platform = self.detect_current_platform()?;
        let env_capture = self.env_captures.get(&current_platform)
            .ok_or(RchWorkerError::PlatformNotConfigured { platform: current_platform })?;

        env_capture.capture_environment()
            .map_err(|e| RchWorkerError::EnvironmentCapture { details: e.to_string() })
    }

    /// Detect the current platform.
    pub fn detect_current_platform(&self) -> Result<WorkerPlatform, RchWorkerError> {
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;

        match (os, arch) {
            ("macos", "aarch64") => Ok(WorkerPlatform::MacOSArm64),
            ("windows", "x86_64") => Ok(WorkerPlatform::WindowsX64),
            ("linux", "x86_64") => Ok(WorkerPlatform::LinuxX64),
            ("linux", "aarch64") => Ok(WorkerPlatform::LinuxArm64),
            _ => Err(RchWorkerError::UnsupportedPlatform {
                os: os.to_string(),
                arch: arch.to_string(),
            }),
        }
    }

    /// Get supported platforms that are implemented.
    pub fn get_implemented_platforms(&self) -> Vec<WorkerPlatform> {
        WorkerPlatform::all()
            .iter()
            .filter(|p| p.is_implemented())
            .copied()
            .collect()
    }

    /// Write a registry status report to JSON.
    pub fn export_registry_status(&self, output_path: &Path) -> Result<(), RchWorkerError> {
        let stats = self.get_all_pool_stats();
        let current_platform = self.detect_current_platform().ok();

        let total_workers = stats.values().map(|s| s.total_workers).sum();
        let total_available = stats.values().map(|s| s.available_workers).sum();

        let report = RegistryStatusReport {
            current_platform,
            implemented_platforms: self.get_implemented_platforms(),
            pool_stats: stats,
            total_workers,
            total_available,
        };

        let json = serde_json::to_string_pretty(&report)
            .map_err(|e| RchWorkerError::Serialization { details: e.to_string() })?;

        std::fs::write(output_path, json)
            .map_err(|e| RchWorkerError::IoError {
                operation: "write_registry_status".to_string(),
                path: output_path.to_string_lossy().to_string(),
                error: e.to_string(),
            })?;

        Ok(())
    }
}

/// Registry status report for monitoring and debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryStatusReport {
    /// Current platform (if detectable).
    pub current_platform: Option<WorkerPlatform>,
    /// List of implemented platforms.
    pub implemented_platforms: Vec<WorkerPlatform>,
    /// Per-platform statistics.
    pub pool_stats: BTreeMap<WorkerPlatform, WorkerPoolStats>,
    /// Total workers across all platforms.
    pub total_workers: usize,
    /// Total available workers across all platforms.
    pub total_available: usize,
}

/// Errors that can occur in the RCH worker registry.
#[derive(Debug, thiserror::Error)]
pub enum RchWorkerError {
    #[error("Platform not implemented: {platform}")]
    PlatformNotImplemented { platform: WorkerPlatform },

    #[error("Platform not configured: {platform}")]
    PlatformNotConfigured { platform: WorkerPlatform },

    #[error("Worker limit reached for {platform}: {limit}")]
    WorkerLimitReached { platform: WorkerPlatform, limit: usize },

    #[error("Platform error on {platform}: {details}")]
    PlatformError { platform: WorkerPlatform, details: String },

    #[error("Unsupported platform: {os}-{arch}")]
    UnsupportedPlatform { os: String, arch: String },

    #[error("Environment capture error: {details}")]
    EnvironmentCapture { details: String },

    #[error("I/O error during {operation} on {path}: {error}")]
    IoError { operation: String, path: String, error: String },

    #[error("Serialization error: {details}")]
    Serialization { details: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_platform_string_conversion() {
        assert_eq!(WorkerPlatform::MacOSArm64.as_str(), "macos-arm64");
        assert_eq!(WorkerPlatform::WindowsX64.as_str(), "windows-x64");

        assert_eq!(WorkerPlatform::from_str("macos-arm64"), Some(WorkerPlatform::MacOSArm64));
        assert_eq!(WorkerPlatform::from_str("windows-x64"), Some(WorkerPlatform::WindowsX64));
        assert_eq!(WorkerPlatform::from_str("invalid"), None);
    }

    #[test]
    fn test_worker_platform_implementation_status() {
        assert!(WorkerPlatform::MacOSArm64.is_implemented());
        assert!(WorkerPlatform::WindowsX64.is_implemented());
        assert!(!WorkerPlatform::LinuxX64.is_implemented());
        assert!(!WorkerPlatform::LinuxArm64.is_implemented());
    }

    #[test]
    fn test_registry_creation() {
        let registry = RchWorkerRegistry::with_defaults();
        assert!(registry.macos_arm64_manager.is_some());
        assert_eq!(registry.env_captures.len(), 2); // macOS and Windows
    }

    #[test]
    fn test_pool_stats_serialization() {
        let stats = WorkerPoolStats {
            platform: WorkerPlatform::MacOSArm64,
            total_workers: 4,
            available_workers: 2,
            busy_workers: 1,
            failed_workers: 1,
        };

        let json = serde_json::to_string(&stats).expect("serialization should work");
        let deserialized: WorkerPoolStats = serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(stats, deserialized);
    }

    #[test]
    fn test_registry_status_report_serialization() {
        let mut pool_stats = BTreeMap::new();
        pool_stats.insert(
            WorkerPlatform::MacOSArm64,
            WorkerPoolStats {
                platform: WorkerPlatform::MacOSArm64,
                total_workers: 2,
                available_workers: 1,
                busy_workers: 1,
                failed_workers: 0,
            },
        );

        let report = RegistryStatusReport {
            current_platform: Some(WorkerPlatform::MacOSArm64),
            implemented_platforms: vec![WorkerPlatform::MacOSArm64, WorkerPlatform::WindowsX64],
            pool_stats,
            total_workers: 2,
            total_available: 1,
        };

        let json = serde_json::to_string(&report).expect("serialization should work");
        let deserialized: RegistryStatusReport = serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(report.current_platform, deserialized.current_platform);
        assert_eq!(report.total_workers, deserialized.total_workers);
    }

    #[test]
    fn test_platform_detection() {
        let registry = RchWorkerRegistry::with_defaults();
        let result = registry.detect_current_platform();

        // Should succeed on any supported platform, or fail gracefully on unsupported ones
        match result {
            Ok(platform) => {
                assert!(WorkerPlatform::all().contains(&platform));
            }
            Err(RchWorkerError::UnsupportedPlatform { .. }) => {
                // Expected on unsupported platforms
            }
            Err(other) => panic!("Unexpected error: {:?}", other),
        }
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn test_create_macos_worker() {
        let mut registry = RchWorkerRegistry::with_defaults();
        let result = registry.create_worker(WorkerPlatform::MacOSArm64);

        assert!(result.is_ok(), "Should create worker on macOS arm64");

        let worker_id = result.unwrap();
        assert!(!worker_id.is_empty());

        let stats = registry.get_pool_stats(WorkerPlatform::MacOSArm64).expect("should get stats");
        assert_eq!(stats.total_workers, 1);
    }

    #[test]
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    fn test_create_worker_wrong_platform() {
        let mut registry = RchWorkerRegistry::with_defaults();
        let result = registry.create_worker(WorkerPlatform::MacOSArm64);

        assert!(result.is_err(), "Should fail to create macOS worker on wrong platform");

        match result.unwrap_err() {
            RchWorkerError::PlatformError { platform, .. } => {
                assert_eq!(platform, WorkerPlatform::MacOSArm64);
            }
            other => panic!("Expected PlatformError, got: {:?}", other),
        }
    }
}