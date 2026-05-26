//! Worker environment capture module for RCH worker pools.
//!
//! Captures system environment information including OS version, architecture,
//! Rust toolchain details, and platform-specific development tools.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::process::Command;

/// Environment information captured from a worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerEnvironment {
    /// Operating system identifier (e.g., "macos", "windows", "linux").
    pub os: String,
    /// Architecture identifier (e.g., "arm64", "x64").
    pub arch: String,
    /// OS version string.
    pub os_version: String,
    /// Rust toolchain information.
    pub rust_toolchain: RustToolchainInfo,
    /// Platform-specific development tools.
    pub dev_tools: BTreeMap<String, String>,
    /// Additional environment variables.
    pub env_vars: BTreeMap<String, String>,
    /// Timestamp when environment was captured (RFC3339).
    pub captured_at: String,
}

/// Rust toolchain information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RustToolchainInfo {
    /// Rust version (e.g., "1.75.0-nightly").
    pub version: String,
    /// Target triple (e.g., "aarch64-apple-darwin").
    pub target: String,
    /// Commit hash of the Rust compiler.
    pub commit_hash: Option<String>,
    /// Commit date.
    pub commit_date: Option<String>,
    /// Channel (stable, beta, nightly).
    pub channel: String,
}

/// Platform-specific worker environment capture.
pub trait WorkerEnvCapture {
    /// Capture environment information for this worker.
    fn capture_environment(&self) -> Result<WorkerEnvironment, EnvCaptureError>;

    /// Get the worker's platform identifier.
    fn platform_id(&self) -> String;
}

/// Errors that can occur during environment capture.
#[derive(Debug, thiserror::Error)]
pub enum EnvCaptureError {
    #[error("Failed to execute command: {command}")]
    CommandExecution { command: String },

    #[error("Command failed with exit code {code}: {stderr}")]
    CommandFailed { code: i32, stderr: String },

    #[error("Failed to parse command output: {details}")]
    ParseError { details: String },

    #[error("Environment variable not found: {var}")]
    EnvVarNotFound { var: String },

    #[error("Platform not supported: {platform}")]
    UnsupportedPlatform { platform: String },
}

/// macOS ARM64 worker environment capture implementation.
#[derive(Debug)]
pub struct MacOSArm64EnvCapture;

impl MacOSArm64EnvCapture {
    /// Create a new macOS ARM64 environment capture instance.
    pub fn new() -> Self {
        Self
    }

    /// Get macOS version information.
    fn get_macos_version(&self) -> Result<String, EnvCaptureError> {
        let output = Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .map_err(|_| EnvCaptureError::CommandExecution {
                command: "sw_vers -productVersion".to_string(),
            })?;

        if !output.status.success() {
            return Err(EnvCaptureError::CommandFailed {
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Get Xcode version information.
    fn get_xcode_version(&self) -> Result<String, EnvCaptureError> {
        let output = Command::new("xcodebuild")
            .arg("-version")
            .output()
            .map_err(|_| EnvCaptureError::CommandExecution {
                command: "xcodebuild -version".to_string(),
            })?;

        if !output.status.success() {
            return Err(EnvCaptureError::CommandFailed {
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        // Parse the first line which contains version info
        let version_line = String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .unwrap_or("Unknown")
            .to_string();

        Ok(version_line)
    }

    /// Get Rust toolchain information.
    fn get_rust_toolchain(&self) -> Result<RustToolchainInfo, EnvCaptureError> {
        let output = Command::new("rustc")
            .arg("--version")
            .arg("--verbose")
            .output()
            .map_err(|_| EnvCaptureError::CommandExecution {
                command: "rustc --version --verbose".to_string(),
            })?;

        if !output.status.success() {
            return Err(EnvCaptureError::CommandFailed {
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut version = String::new();
        let mut commit_hash = None;
        let mut commit_date = None;
        let mut target = String::new();
        let mut channel = String::new();

        for line in output_str.lines() {
            if line.starts_with("rustc ") {
                // Parse version from "rustc 1.75.0-nightly (commit 2023-12-01)"
                if let Some(version_part) = line.strip_prefix("rustc ") {
                    if let Some(space_pos) = version_part.find(' ') {
                        version = version_part[..space_pos].to_string();
                    } else {
                        version = version_part.to_string();
                    }

                    // Determine channel from version
                    if version.contains("nightly") {
                        channel = "nightly".to_string();
                    } else if version.contains("beta") {
                        channel = "beta".to_string();
                    } else {
                        channel = "stable".to_string();
                    }
                }
            } else if line.starts_with("commit-hash: ") {
                commit_hash = Some(line.strip_prefix("commit-hash: ").unwrap_or("").to_string());
            } else if line.starts_with("commit-date: ") {
                commit_date = Some(line.strip_prefix("commit-date: ").unwrap_or("").to_string());
            } else if line.starts_with("host: ") {
                target = line.strip_prefix("host: ").unwrap_or("").to_string();
            }
        }

        if version.is_empty() {
            return Err(EnvCaptureError::ParseError {
                details: "Could not parse rustc version".to_string(),
            });
        }

        Ok(RustToolchainInfo {
            version,
            target,
            commit_hash,
            commit_date,
            channel,
        })
    }
}

impl WorkerEnvCapture for MacOSArm64EnvCapture {
    fn capture_environment(&self) -> Result<WorkerEnvironment, EnvCaptureError> {
        // Verify we're on arm64 macOS
        let arch = std::env::consts::ARCH;
        let os = std::env::consts::OS;

        if os != "macos" {
            return Err(EnvCaptureError::UnsupportedPlatform {
                platform: format!("{}-{}", os, arch),
            });
        }

        if arch != "aarch64" {
            return Err(EnvCaptureError::UnsupportedPlatform {
                platform: format!("{}-{}", os, arch),
            });
        }

        let os_version = self.get_macos_version()?;
        let rust_toolchain = self.get_rust_toolchain()?;

        // Capture development tools
        let mut dev_tools = BTreeMap::new();

        // Try to get Xcode version
        match self.get_xcode_version() {
            Ok(xcode_version) => {
                dev_tools.insert("xcode_version".to_string(), xcode_version);
            }
            Err(_) => {
                // Xcode not installed or not available
                dev_tools.insert("xcode_version".to_string(), "Not available".to_string());
            }
        }

        // Capture relevant environment variables
        let mut env_vars = BTreeMap::new();
        let env_var_names = [
            "PATH",
            "RUST_TOOLCHAIN",
            "RUSTFLAGS",
            "CARGO_TARGET_DIR",
            "DEVELOPER_DIR",
        ];

        for var_name in &env_var_names {
            if let Ok(value) = std::env::var(var_name) {
                env_vars.insert(var_name.to_string(), value);
            }
        }

        // Generate timestamp
        let captured_at = chrono::Utc::now().to_rfc3339();

        Ok(WorkerEnvironment {
            os: "macos".to_string(),
            arch: "arm64".to_string(),
            os_version,
            rust_toolchain,
            dev_tools,
            env_vars,
            captured_at,
        })
    }

    fn platform_id(&self) -> String {
        "macos-arm64".to_string()
    }
}

impl Default for MacOSArm64EnvCapture {
    fn default() -> Self {
        Self::new()
    }
}

/// Windows x64 worker environment capture implementation.
#[derive(Debug)]
pub struct WindowsX64EnvCapture;

impl WindowsX64EnvCapture {
    /// Create a new Windows x64 environment capture instance.
    pub fn new() -> Self {
        Self
    }

    /// Get Windows version information.
    fn get_windows_version(&self) -> Result<String, EnvCaptureError> {
        let output = Command::new("cmd")
            .args(["/C", "ver"])
            .output()
            .map_err(|_| EnvCaptureError::CommandExecution {
                command: "cmd /C ver".to_string(),
            })?;

        if !output.status.success() {
            return Err(EnvCaptureError::CommandFailed {
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Get Visual Studio/MSVC version information.
    fn get_msvc_version(&self) -> Result<String, EnvCaptureError> {
        // Try to get MSVC version
        let output =
            Command::new("cl")
                .output()
                .map_err(|_| EnvCaptureError::CommandExecution {
                    command: "cl".to_string(),
                })?;

        // cl returns non-zero when called without args, but still outputs version info
        let output_str = String::from_utf8_lossy(&output.stderr);

        // Parse version from output
        for line in output_str.lines() {
            if line.contains("Microsoft") && line.contains("Compiler") {
                return Ok(line.trim().to_string());
            }
        }

        Ok("Not available".to_string())
    }

    /// Get Rust toolchain information (reuse logic from macOS).
    fn get_rust_toolchain(&self) -> Result<RustToolchainInfo, EnvCaptureError> {
        let output = Command::new("rustc")
            .arg("--version")
            .arg("--verbose")
            .output()
            .map_err(|_| EnvCaptureError::CommandExecution {
                command: "rustc --version --verbose".to_string(),
            })?;

        if !output.status.success() {
            return Err(EnvCaptureError::CommandFailed {
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut version = String::new();
        let mut commit_hash = None;
        let mut commit_date = None;
        let mut target = String::new();
        let mut channel = String::new();

        for line in output_str.lines() {
            if line.starts_with("rustc ") {
                if let Some(version_part) = line.strip_prefix("rustc ") {
                    if let Some(space_pos) = version_part.find(' ') {
                        version = version_part[..space_pos].to_string();
                    } else {
                        version = version_part.to_string();
                    }

                    if version.contains("nightly") {
                        channel = "nightly".to_string();
                    } else if version.contains("beta") {
                        channel = "beta".to_string();
                    } else {
                        channel = "stable".to_string();
                    }
                }
            } else if line.starts_with("commit-hash: ") {
                commit_hash = Some(line.strip_prefix("commit-hash: ").unwrap_or("").to_string());
            } else if line.starts_with("commit-date: ") {
                commit_date = Some(line.strip_prefix("commit-date: ").unwrap_or("").to_string());
            } else if line.starts_with("host: ") {
                target = line.strip_prefix("host: ").unwrap_or("").to_string();
            }
        }

        if version.is_empty() {
            return Err(EnvCaptureError::ParseError {
                details: "Could not parse rustc version".to_string(),
            });
        }

        Ok(RustToolchainInfo {
            version,
            target,
            commit_hash,
            commit_date,
            channel,
        })
    }
}

impl WorkerEnvCapture for WindowsX64EnvCapture {
    fn capture_environment(&self) -> Result<WorkerEnvironment, EnvCaptureError> {
        // Verify we're on x64 Windows
        let arch = std::env::consts::ARCH;
        let os = std::env::consts::OS;

        if os != "windows" {
            return Err(EnvCaptureError::UnsupportedPlatform {
                platform: format!("{}-{}", os, arch),
            });
        }

        if arch != "x86_64" {
            return Err(EnvCaptureError::UnsupportedPlatform {
                platform: format!("{}-{}", os, arch),
            });
        }

        let os_version = self.get_windows_version()?;
        let rust_toolchain = self.get_rust_toolchain()?;

        // Capture development tools
        let mut dev_tools = BTreeMap::new();

        // Try to get MSVC version
        match self.get_msvc_version() {
            Ok(msvc_version) => {
                dev_tools.insert("msvc_version".to_string(), msvc_version);
            }
            Err(_) => {
                dev_tools.insert("msvc_version".to_string(), "Not available".to_string());
            }
        }

        // Capture relevant environment variables
        let mut env_vars = BTreeMap::new();
        let env_var_names = [
            "PATH",
            "RUST_TOOLCHAIN",
            "RUSTFLAGS",
            "CARGO_TARGET_DIR",
            "VCINSTALLDIR",
            "WindowsSdkDir",
        ];

        for var_name in &env_var_names {
            if let Ok(value) = std::env::var(var_name) {
                env_vars.insert(var_name.to_string(), value);
            }
        }

        let captured_at = chrono::Utc::now().to_rfc3339();

        Ok(WorkerEnvironment {
            os: "windows".to_string(),
            arch: "x64".to_string(),
            os_version,
            rust_toolchain,
            dev_tools,
            env_vars,
            captured_at,
        })
    }

    fn platform_id(&self) -> String {
        "windows-x64".to_string()
    }
}

impl Default for WindowsX64EnvCapture {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_arm64_platform_id() {
        let capture = MacOSArm64EnvCapture::new();
        assert_eq!(capture.platform_id(), "macos-arm64");
    }

    #[test]
    fn test_windows_x64_platform_id() {
        let capture = WindowsX64EnvCapture::new();
        assert_eq!(capture.platform_id(), "windows-x64");
    }

    #[test]
    fn test_rust_toolchain_info_serialization() {
        let info = RustToolchainInfo {
            version: "1.75.0-nightly".to_string(),
            target: "aarch64-apple-darwin".to_string(),
            commit_hash: Some("abcd1234".to_string()),
            commit_date: Some("2023-12-01".to_string()),
            channel: "nightly".to_string(),
        };

        let json = serde_json::to_string(&info).expect("serialization should work");
        let deserialized: RustToolchainInfo =
            serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(info, deserialized);
    }

    #[test]
    fn test_worker_environment_serialization() {
        let mut dev_tools = BTreeMap::new();
        dev_tools.insert("xcode_version".to_string(), "Xcode 15.0".to_string());

        let mut env_vars = BTreeMap::new();
        env_vars.insert("PATH".to_string(), "/usr/bin:/bin".to_string());

        let env = WorkerEnvironment {
            os: "macos".to_string(),
            arch: "arm64".to_string(),
            os_version: "14.0".to_string(),
            rust_toolchain: RustToolchainInfo {
                version: "1.75.0".to_string(),
                target: "aarch64-apple-darwin".to_string(),
                commit_hash: None,
                commit_date: None,
                channel: "stable".to_string(),
            },
            dev_tools,
            env_vars,
            captured_at: "2026-05-21T19:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&env).expect("serialization should work");
        let deserialized: WorkerEnvironment =
            serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(env, deserialized);
    }

    #[test]
    #[cfg(target_os = "macos")]
    #[cfg(target_arch = "aarch64")]
    fn test_macos_arm64_environment_capture() {
        let capture = MacOSArm64EnvCapture::new();
        let result = capture.capture_environment();

        // On actual macOS arm64, this should succeed
        assert!(
            result.is_ok(),
            "Environment capture should succeed on macOS arm64"
        );

        let env = result.unwrap();
        assert_eq!(env.os, "macos");
        assert_eq!(env.arch, "arm64");
        assert!(!env.os_version.is_empty());
        assert!(!env.rust_toolchain.version.is_empty());
        assert!(!env.captured_at.is_empty());
    }

    #[test]
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    fn test_macos_arm64_environment_capture_wrong_platform() {
        let capture = MacOSArm64EnvCapture::new();
        let result = capture.capture_environment();

        // On non-macOS arm64 platforms, this should fail
        assert!(
            result.is_err(),
            "Environment capture should fail on wrong platform"
        );

        match result.unwrap_err() {
            EnvCaptureError::UnsupportedPlatform { .. } => {
                // Expected error type
            }
            other => panic!("Expected UnsupportedPlatform error, got: {:?}", other),
        }
    }

    #[test]
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn test_windows_x64_environment_capture() {
        let capture = WindowsX64EnvCapture::new();
        let result = capture.capture_environment();

        // On actual Windows x64, this should succeed
        assert!(
            result.is_ok(),
            "Environment capture should succeed on Windows x64"
        );

        let env = result.unwrap();
        assert_eq!(env.os, "windows");
        assert_eq!(env.arch, "x64");
        assert!(!env.os_version.is_empty());
        assert!(!env.rust_toolchain.version.is_empty());
        assert!(!env.captured_at.is_empty());
    }

    #[test]
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    fn test_windows_x64_environment_capture_wrong_platform() {
        let capture = WindowsX64EnvCapture::new();
        let result = capture.capture_environment();

        // On non-Windows x64 platforms, this should fail
        assert!(
            result.is_err(),
            "Environment capture should fail on wrong platform"
        );

        match result.unwrap_err() {
            EnvCaptureError::UnsupportedPlatform { .. } => {
                // Expected error type
            }
            other => panic!("Expected UnsupportedPlatform error, got: {:?}", other),
        }
    }
}
