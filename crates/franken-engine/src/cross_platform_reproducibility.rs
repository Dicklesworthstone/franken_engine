//! Cross-platform reproducibility testing for RCH worker pools.
//!
//! Verifies that FrankenEngine produces identical content_hash outputs across
//! Linux, macOS, and Windows platforms for the same inputs. This is the
//! load-bearing test for cross-platform determinism in the runtime.

#![forbid(unsafe_code)]

use crate::hash_tiers::ContentHash;
use crate::rch_worker_registry::{RchWorkerRegistry, RchWorkerError, WorkerPlatform};
use crate::worker_env_capture::WorkerEnvironment;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::SystemTime;

/// Test input for cross-platform reproducibility verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproducibilityTestInput {
    /// Unique identifier for this test case.
    pub test_id: String,
    /// Description of what this test verifies.
    pub description: String,
    /// JavaScript/TypeScript source code to execute.
    pub source_code: String,
    /// Expected output type.
    pub output_type: OutputType,
    /// Module type (ES module, CommonJS, script).
    pub module_type: ModuleType,
    /// Additional execution flags.
    pub flags: Vec<String>,
    /// Expected deterministic behavior.
    pub deterministic: bool,
}

/// Type of output expected from test execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputType {
    /// Standard output text.
    Stdout,
    /// Error output.
    Stderr,
    /// Exit code.
    ExitCode,
    /// Compiled bytecode hash.
    BytecodeHash,
    /// Runtime state hash.
    RuntimeStateHash,
    /// Full execution trace hash.
    ExecutionTraceHash,
}

/// Module type for execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleType {
    /// ES Module.
    ESModule,
    /// CommonJS module.
    CommonJS,
    /// Plain script.
    Script,
}

/// Result of cross-platform reproducibility test execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproducibilityTestResult {
    /// Test input that was executed.
    pub test_input: ReproducibilityTestInput,
    /// Results per platform.
    pub platform_results: BTreeMap<WorkerPlatform, PlatformExecutionResult>,
    /// Whether all platforms produced identical results.
    pub reproducible: bool,
    /// Content hash that should be identical across platforms.
    pub expected_content_hash: Option<ContentHash>,
    /// Any divergences found between platforms.
    pub divergences: Vec<PlatformDivergence>,
    /// Timestamp when test was executed.
    pub executed_at: String,
}

/// Execution result from a specific platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformExecutionResult {
    /// Platform this result came from.
    pub platform: WorkerPlatform,
    /// Worker environment details.
    pub worker_env: WorkerEnvironment,
    /// Content hash of the output.
    pub content_hash: ContentHash,
    /// Raw output (if relevant).
    pub raw_output: String,
    /// Exit code.
    pub exit_code: Option<i32>,
    /// Execution time in milliseconds.
    pub execution_time_ms: u64,
    /// Whether execution succeeded.
    pub success: bool,
    /// Error message if execution failed.
    pub error: Option<String>,
}

/// Divergence found between platform results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformDivergence {
    /// Platform that diverged.
    pub platform: WorkerPlatform,
    /// Reference platform for comparison.
    pub reference_platform: WorkerPlatform,
    /// Type of divergence.
    pub divergence_type: DivergenceType,
    /// Description of the divergence.
    pub description: String,
    /// Expected value (from reference platform).
    pub expected_value: String,
    /// Actual value (from divergent platform).
    pub actual_value: String,
}

/// Types of divergences that can occur.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DivergenceType {
    /// Content hash mismatch.
    ContentHashMismatch,
    /// Exit code mismatch.
    ExitCodeMismatch,
    /// Output content mismatch.
    OutputMismatch,
    /// Execution failure on one platform.
    ExecutionFailure,
    /// Performance divergence beyond threshold.
    PerformanceDivergence,
}

/// Configuration for cross-platform reproducibility testing.
#[derive(Debug, Clone)]
pub struct ReproducibilityTestConfig {
    /// Platforms to test across.
    pub target_platforms: Vec<WorkerPlatform>,
    /// Maximum execution time per test.
    pub max_execution_time_seconds: u64,
    /// Whether to capture full execution traces.
    pub capture_traces: bool,
    /// Performance divergence threshold percentage.
    pub performance_threshold_percent: f64,
    /// Number of retry attempts on failure.
    pub retry_attempts: u32,
}

impl Default for ReproducibilityTestConfig {
    fn default() -> Self {
        Self {
            target_platforms: vec![
                WorkerPlatform::MacOSArm64,
                WorkerPlatform::WindowsX64,
                WorkerPlatform::LinuxX64,
            ],
            max_execution_time_seconds: 30,
            capture_traces: true,
            performance_threshold_percent: 25.0, // 25% variance allowed
            retry_attempts: 2,
        }
    }
}

/// Cross-platform reproducibility test harness.
#[derive(Debug)]
pub struct CrossPlatformReproducibilityTester {
    /// Worker registry for cross-platform execution.
    worker_registry: RchWorkerRegistry,
    /// Test configuration.
    config: ReproducibilityTestConfig,
}

impl CrossPlatformReproducibilityTester {
    /// Create a new reproducibility tester.
    pub fn new(
        worker_registry: RchWorkerRegistry,
        config: ReproducibilityTestConfig,
    ) -> Self {
        Self {
            worker_registry,
            config,
        }
    }

    /// Create a tester with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(
            RchWorkerRegistry::with_defaults(),
            ReproducibilityTestConfig::default(),
        )
    }

    /// Execute a reproducibility test across all configured platforms.
    pub fn execute_test(
        &mut self,
        test_input: ReproducibilityTestInput,
    ) -> Result<ReproducibilityTestResult, ReproducibilityTestError> {
        let mut platform_results = BTreeMap::new();
        let mut divergences = Vec::new();

        // Execute test on each platform
        for &platform in &self.config.target_platforms {
            let result = self.execute_on_platform(&test_input, platform)?;
            platform_results.insert(platform, result);
        }

        // Verify reproducibility across platforms
        let reproducible = self.verify_reproducibility(&platform_results, &mut divergences)?;

        // Determine expected content hash (from first successful execution)
        let expected_content_hash = platform_results
            .values()
            .find(|r| r.success)
            .map(|r| r.content_hash.clone());

        Ok(ReproducibilityTestResult {
            test_input,
            platform_results,
            reproducible,
            expected_content_hash,
            divergences,
            executed_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Execute test on a specific platform.
    fn execute_on_platform(
        &mut self,
        test_input: &ReproducibilityTestInput,
        platform: WorkerPlatform,
    ) -> Result<PlatformExecutionResult, ReproducibilityTestError> {
        // Get worker environment for the platform
        let worker_env = self.get_platform_environment(platform)?;

        // Prepare execution command
        let command = self.build_execution_command(test_input, platform)?;

        let start_time = SystemTime::now();

        // Execute with retry logic
        let mut last_error = None;
        for attempt in 0..=self.config.retry_attempts {
            match self.worker_registry.execute_on_worker(
                platform,
                "worker-0", // Use first available worker
                &command,
                None, // Use default working directory
                Some(self.config.max_execution_time_seconds),
            ) {
                Ok(execution_result) => {
                    let execution_time = start_time.elapsed().unwrap_or_default();

                    // Compute content hash of the output
                    let content_hash = ContentHash::compute(execution_result.stdout.as_bytes());

                    return Ok(PlatformExecutionResult {
                        platform,
                        worker_env,
                        content_hash,
                        raw_output: execution_result.stdout,
                        exit_code: execution_result.exit_code,
                        execution_time_ms: execution_time.as_millis() as u64,
                        success: execution_result.exit_code == Some(0),
                        error: if execution_result.exit_code != Some(0) {
                            Some(execution_result.stderr)
                        } else {
                            None
                        },
                    });
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt < self.config.retry_attempts {
                        // Wait before retry
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                }
            }
        }

        // All retries failed
        let execution_time = start_time.elapsed().unwrap_or_default();
        let error_msg = last_error
            .map(|e| e.to_string())
            .unwrap_or_else(|| "Unknown execution failure".to_string());

        Ok(PlatformExecutionResult {
            platform,
            worker_env,
            content_hash: ContentHash::compute(b""), // Empty hash for failed execution
            raw_output: String::new(),
            exit_code: None,
            execution_time_ms: execution_time.as_millis() as u64,
            success: false,
            error: Some(error_msg),
        })
    }

    /// Get environment information for a platform.
    fn get_platform_environment(
        &self,
        platform: WorkerPlatform,
    ) -> Result<WorkerEnvironment, ReproducibilityTestError> {
        // For now, return a mock environment
        // In a real implementation, this would query the actual worker
        Ok(WorkerEnvironment {
            os: match platform {
                WorkerPlatform::MacOSArm64 => "macos".to_string(),
                WorkerPlatform::WindowsX64 => "windows".to_string(),
                WorkerPlatform::LinuxX64 | WorkerPlatform::LinuxArm64 => "linux".to_string(),
            },
            arch: match platform {
                WorkerPlatform::MacOSArm64 | WorkerPlatform::LinuxArm64 => "arm64".to_string(),
                WorkerPlatform::WindowsX64 | WorkerPlatform::LinuxX64 => "x64".to_string(),
            },
            os_version: "test".to_string(),
            rust_toolchain: crate::worker_env_capture::RustToolchainInfo {
                version: "1.75.0".to_string(),
                target: "test-target".to_string(),
                commit_hash: None,
                commit_date: None,
                channel: "stable".to_string(),
            },
            dev_tools: BTreeMap::new(),
            env_vars: BTreeMap::new(),
            captured_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Build execution command for a test input on a specific platform.
    fn build_execution_command(
        &self,
        test_input: &ReproducibilityTestInput,
        platform: WorkerPlatform,
    ) -> Result<Vec<String>, ReproducibilityTestError> {
        let mut command = Vec::new();

        // Use different runtime commands per platform
        match platform {
            WorkerPlatform::WindowsX64 => {
                command.push("powershell".to_string());
                command.push("-Command".to_string());
                command.push(format!("echo '{}' | node -", test_input.source_code));
            }
            _ => {
                command.push("bash".to_string());
                command.push("-c".to_string());
                command.push(format!("echo '{}' | node -", test_input.source_code));
            }
        }

        // Add any additional flags
        for flag in &test_input.flags {
            command.push(flag.clone());
        }

        Ok(command)
    }

    /// Verify reproducibility across platform results.
    fn verify_reproducibility(
        &self,
        platform_results: &BTreeMap<WorkerPlatform, PlatformExecutionResult>,
        divergences: &mut Vec<PlatformDivergence>,
    ) -> Result<bool, ReproducibilityTestError> {
        let successful_results: Vec<_> = platform_results
            .values()
            .filter(|r| r.success)
            .collect();

        if successful_results.is_empty() {
            return Ok(false); // No successful executions
        }

        // Use first successful result as reference
        let reference = successful_results[0];

        let mut reproducible = true;

        // Compare all other results to reference
        for result in &successful_results[1..] {
            if result.content_hash != reference.content_hash {
                reproducible = false;
                divergences.push(PlatformDivergence {
                    platform: result.platform,
                    reference_platform: reference.platform,
                    divergence_type: DivergenceType::ContentHashMismatch,
                    description: "Content hash mismatch between platforms".to_string(),
                    expected_value: reference.content_hash.to_hex(),
                    actual_value: result.content_hash.to_hex(),
                });
            }

            if result.exit_code != reference.exit_code {
                reproducible = false;
                divergences.push(PlatformDivergence {
                    platform: result.platform,
                    reference_platform: reference.platform,
                    divergence_type: DivergenceType::ExitCodeMismatch,
                    description: "Exit code mismatch between platforms".to_string(),
                    expected_value: format!("{:?}", reference.exit_code),
                    actual_value: format!("{:?}", result.exit_code),
                });
            }

            // Check performance divergence
            let performance_diff = if reference.execution_time_ms > 0 {
                ((result.execution_time_ms as f64 - reference.execution_time_ms as f64)
                 / reference.execution_time_ms as f64 * 100.0).abs()
            } else {
                0.0
            };

            if performance_diff > self.config.performance_threshold_percent {
                divergences.push(PlatformDivergence {
                    platform: result.platform,
                    reference_platform: reference.platform,
                    divergence_type: DivergenceType::PerformanceDivergence,
                    description: format!("Performance divergence: {:.1}%", performance_diff),
                    expected_value: format!("{}ms", reference.execution_time_ms),
                    actual_value: format!("{}ms", result.execution_time_ms),
                });
            }
        }

        // Check for platforms that failed execution
        for (platform, result) in platform_results {
            if !result.success {
                reproducible = false;
                divergences.push(PlatformDivergence {
                    platform: *platform,
                    reference_platform: reference.platform,
                    divergence_type: DivergenceType::ExecutionFailure,
                    description: format!("Execution failed on {}", platform.as_str()),
                    expected_value: "success".to_string(),
                    actual_value: result.error.as_ref().unwrap_or(&"unknown error".to_string()).clone(),
                });
            }
        }

        Ok(reproducible)
    }

    /// Generate standard test suite for reproducibility verification.
    pub fn generate_standard_test_suite() -> Vec<ReproducibilityTestInput> {
        vec![
            // Basic arithmetic
            ReproducibilityTestInput {
                test_id: "basic_arithmetic".to_string(),
                description: "Basic arithmetic operations".to_string(),
                source_code: "console.log(1 + 2 * 3)".to_string(),
                output_type: OutputType::Stdout,
                module_type: ModuleType::Script,
                flags: vec![],
                deterministic: true,
            },

            // String operations
            ReproducibilityTestInput {
                test_id: "string_operations".to_string(),
                description: "String concatenation and operations".to_string(),
                source_code: "console.log('Hello' + ' ' + 'World')".to_string(),
                output_type: OutputType::Stdout,
                module_type: ModuleType::Script,
                flags: vec![],
                deterministic: true,
            },

            // Array operations
            ReproducibilityTestInput {
                test_id: "array_operations".to_string(),
                description: "Array creation and manipulation".to_string(),
                source_code: "const arr = [1,2,3]; console.log(arr.map(x => x * 2))".to_string(),
                output_type: OutputType::Stdout,
                module_type: ModuleType::Script,
                flags: vec![],
                deterministic: true,
            },

            // Object operations
            ReproducibilityTestInput {
                test_id: "object_operations".to_string(),
                description: "Object creation and property access".to_string(),
                source_code: "const obj = {a: 1, b: 2}; console.log(obj.a + obj.b)".to_string(),
                output_type: OutputType::Stdout,
                module_type: ModuleType::Script,
                flags: vec![],
                deterministic: true,
            },

            // Function definitions
            ReproducibilityTestInput {
                test_id: "function_definitions".to_string(),
                description: "Function definition and invocation".to_string(),
                source_code: "function add(a, b) { return a + b; } console.log(add(5, 3))".to_string(),
                output_type: OutputType::Stdout,
                module_type: ModuleType::Script,
                flags: vec![],
                deterministic: true,
            },

            // Control flow
            ReproducibilityTestInput {
                test_id: "control_flow".to_string(),
                description: "If/else and loop constructs".to_string(),
                source_code: "let sum = 0; for(let i = 0; i < 5; i++) sum += i; console.log(sum)".to_string(),
                output_type: OutputType::Stdout,
                module_type: ModuleType::Script,
                flags: vec![],
                deterministic: true,
            },

            // Error handling
            ReproducibilityTestInput {
                test_id: "error_handling".to_string(),
                description: "Try/catch error handling".to_string(),
                source_code: "try { throw new Error('test'); } catch(e) { console.log('caught') }".to_string(),
                output_type: OutputType::Stdout,
                module_type: ModuleType::Script,
                flags: vec![],
                deterministic: true,
            },

            // JSON operations
            ReproducibilityTestInput {
                test_id: "json_operations".to_string(),
                description: "JSON stringify/parse operations".to_string(),
                source_code: "const obj = {x: 42}; console.log(JSON.parse(JSON.stringify(obj)).x)".to_string(),
                output_type: OutputType::Stdout,
                module_type: ModuleType::Script,
                flags: vec![],
                deterministic: true,
            },

            // Regular expressions
            ReproducibilityTestInput {
                test_id: "regex_operations".to_string(),
                description: "Regular expression matching".to_string(),
                source_code: "console.log('test123'.match(/\\d+/)[0])".to_string(),
                output_type: OutputType::Stdout,
                module_type: ModuleType::Script,
                flags: vec![],
                deterministic: true,
            },

            // Date operations (deterministic subset)
            ReproducibilityTestInput {
                test_id: "date_operations".to_string(),
                description: "Deterministic date operations".to_string(),
                source_code: "console.log(new Date('2024-01-01').getFullYear())".to_string(),
                output_type: OutputType::Stdout,
                module_type: ModuleType::Script,
                flags: vec![],
                deterministic: true,
            },
        ]
    }

    /// Run the full reproducibility test suite.
    pub fn run_test_suite(&mut self) -> Result<Vec<ReproducibilityTestResult>, ReproducibilityTestError> {
        let test_suite = Self::generate_standard_test_suite();
        let mut results = Vec::new();

        for test_input in test_suite {
            let result = self.execute_test(test_input)?;
            results.push(result);
        }

        Ok(results)
    }

    /// Export test results to JSON file.
    pub fn export_results(
        results: &[ReproducibilityTestResult],
        output_path: &Path,
    ) -> Result<(), ReproducibilityTestError> {
        let json = serde_json::to_string_pretty(results)
            .map_err(|e| ReproducibilityTestError::Serialization { details: e.to_string() })?;

        std::fs::write(output_path, json)
            .map_err(|e| ReproducibilityTestError::IoError {
                operation: "write_results".to_string(),
                path: output_path.to_string_lossy().to_string(),
                error: e.to_string(),
            })?;

        Ok(())
    }
}

/// Errors that can occur during reproducibility testing.
#[derive(Debug, thiserror::Error)]
pub enum ReproducibilityTestError {
    #[error("Worker registry error: {0}")]
    WorkerRegistry(#[from] RchWorkerError),

    #[error("Test execution failed: {details}")]
    ExecutionFailure { details: String },

    #[error("Platform not available: {platform}")]
    PlatformUnavailable { platform: WorkerPlatform },

    #[error("I/O error during {operation} on {path}: {error}")]
    IoError { operation: String, path: String, error: String },

    #[error("Serialization error: {details}")]
    Serialization { details: String },

    #[error("Test configuration error: {details}")]
    Configuration { details: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reproducibility_test_input_serialization() {
        let input = ReproducibilityTestInput {
            test_id: "test1".to_string(),
            description: "Test description".to_string(),
            source_code: "console.log('hello')".to_string(),
            output_type: OutputType::Stdout,
            module_type: ModuleType::Script,
            flags: vec![],
            deterministic: true,
        };

        let json = serde_json::to_string(&input).expect("serialization should work");
        let deserialized: ReproducibilityTestInput = serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(input, deserialized);
    }

    #[test]
    fn test_platform_divergence_types() {
        assert_eq!(DivergenceType::ContentHashMismatch, DivergenceType::ContentHashMismatch);
        assert_ne!(DivergenceType::ContentHashMismatch, DivergenceType::ExitCodeMismatch);
    }

    #[test]
    fn test_generate_standard_test_suite() {
        let tests = CrossPlatformReproducibilityTester::generate_standard_test_suite();
        assert!(tests.len() >= 10); // Should have at least 10 test cases

        // All should be deterministic
        for test in &tests {
            assert!(test.deterministic);
        }

        // Should have unique test IDs
        let mut test_ids = std::collections::HashSet::new();
        for test in &tests {
            assert!(test_ids.insert(test.test_id.clone()), "Duplicate test ID: {}", test.test_id);
        }
    }

    #[test]
    fn test_reproducibility_test_config_default() {
        let config = ReproducibilityTestConfig::default();
        assert_eq!(config.target_platforms.len(), 3);
        assert!(config.target_platforms.contains(&WorkerPlatform::MacOSArm64));
        assert!(config.target_platforms.contains(&WorkerPlatform::WindowsX64));
        assert!(config.target_platforms.contains(&WorkerPlatform::LinuxX64));
    }

    #[test]
    fn test_platform_execution_result_success_detection() {
        let result = PlatformExecutionResult {
            platform: WorkerPlatform::LinuxX64,
            worker_env: WorkerEnvironment {
                os: "linux".to_string(),
                arch: "x64".to_string(),
                os_version: "test".to_string(),
                rust_toolchain: crate::worker_env_capture::RustToolchainInfo {
                    version: "1.75.0".to_string(),
                    target: "x86_64-unknown-linux-gnu".to_string(),
                    commit_hash: None,
                    commit_date: None,
                    channel: "stable".to_string(),
                },
                dev_tools: BTreeMap::new(),
                env_vars: BTreeMap::new(),
                captured_at: "2026-05-21T19:00:00Z".to_string(),
            },
            content_hash: ContentHash::compute(b"test"),
            raw_output: "test output".to_string(),
            exit_code: Some(0),
            execution_time_ms: 100,
            success: true,
            error: None,
        };

        assert!(result.success);
        assert!(result.error.is_none());
    }
}