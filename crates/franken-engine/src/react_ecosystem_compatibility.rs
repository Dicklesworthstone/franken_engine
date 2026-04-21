#![forbid(unsafe_code)]
#![allow(
    clippy::collapsible_if,
    clippy::derivable_impls,
    clippy::needless_borrows_for_generic_args
)]

//! React ecosystem compatibility program for native JSX runtime support.
//!
//! This module coordinates React ecosystem compatibility beyond syntax lowering
//! to handle the actual package and entrygraph surfaces that real React
//! projects use. It orchestrates package cohort validation, SSR/client-entry
//! module graphs, runtime subpath resolution, and compatibility matrix
//! verification across React, ReactDOM, and the broader ecosystem.
//!
//! The compatibility program validates:
//! - Core React package cohort (react, react-dom, jsx-runtime variants)
//! - Module resolution and export maps across ESM/CJS boundaries
//! - SSR and client-entry mode compatibility
//! - Runtime subpath resolution for React ecosystem packages
//! - Compatibility matrix coverage for real-world React project patterns
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for
//! deterministic computation.
//!
//! Reference: [RGC-405], bead bd-1lsy.5.7.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::react_compile_verification::CompileMode;
use crate::react_package_cohort::{
    ExportCondition, ReactPackage, detect_alias_loops, franken_engine_react_cohort_manifest,
    resolve_subpath_with_fallbacks, verify_format_consistency,
};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the React ecosystem compatibility module.
pub const SCHEMA_VERSION: &str = "franken-engine.react-ecosystem-compatibility.v1";

/// Component name for evidence linkage.
pub const COMPONENT: &str = "react_ecosystem_compatibility";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.5.7";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-405";

/// Fixed-point scale: 1_000_000 millionths = 1.0.
const MILLIONTHS: u64 = 1_000_000;

/// Default compatibility coverage threshold: 95% = 950_000 millionths.
pub const DEFAULT_COMPATIBILITY_THRESHOLD: u64 = 950_000;

/// Maximum number of ecosystem patterns to test per run.
const MAX_ECOSYSTEM_PATTERNS: usize = 10_000;

// ---------------------------------------------------------------------------
// EcosystemMode
// ---------------------------------------------------------------------------

/// React ecosystem deployment mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EcosystemMode {
    /// Server-side rendering (SSR) mode.
    ServerSideRendering,
    /// Client-side rendering (CSR) mode.
    ClientSideRendering,
    /// Static site generation (SSG) mode.
    StaticSiteGeneration,
    /// Hybrid rendering mode (SSR + hydration).
    HybridRendering,
}

impl EcosystemMode {
    /// All variants for exhaustive iteration.
    pub const ALL: &[Self] = &[
        Self::ServerSideRendering,
        Self::ClientSideRendering,
        Self::StaticSiteGeneration,
        Self::HybridRendering,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServerSideRendering => "ssr",
            Self::ClientSideRendering => "csr",
            Self::StaticSiteGeneration => "ssg",
            Self::HybridRendering => "hybrid",
        }
    }

    /// Returns whether this mode requires server-side capabilities.
    pub const fn requires_server_capabilities(self) -> bool {
        match self {
            Self::ServerSideRendering | Self::StaticSiteGeneration | Self::HybridRendering => true,
            Self::ClientSideRendering => false,
        }
    }

    /// Returns whether this mode requires client-side hydration.
    pub const fn requires_client_hydration(self) -> bool {
        match self {
            Self::HybridRendering => true,
            Self::ServerSideRendering | Self::ClientSideRendering | Self::StaticSiteGeneration => {
                false
            }
        }
    }
}

impl fmt::Display for EcosystemMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ModuleResolutionStrategy
// ---------------------------------------------------------------------------

/// Strategy for resolving React ecosystem modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleResolutionStrategy {
    /// Node.js-style resolution with package.json exports.
    NodeExports,
    /// Node.js-style resolution with legacy main field.
    NodeLegacy,
    /// Webpack-style resolution with custom conditions.
    WebpackCustom,
    /// Bundler-agnostic ESM-only resolution.
    EsmOnly,
}

impl ModuleResolutionStrategy {
    /// All variants for exhaustive iteration.
    pub const ALL: &[Self] = &[
        Self::NodeExports,
        Self::NodeLegacy,
        Self::WebpackCustom,
        Self::EsmOnly,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NodeExports => "node_exports",
            Self::NodeLegacy => "node_legacy",
            Self::WebpackCustom => "webpack_custom",
            Self::EsmOnly => "esm_only",
        }
    }

    /// Returns the resolution conditions this strategy uses.
    pub const fn resolution_conditions(self) -> &'static [&'static str] {
        match self {
            Self::NodeExports => &["node", "import", "require"],
            Self::NodeLegacy => &["main"],
            Self::WebpackCustom => &["webpack", "browser", "import"],
            Self::EsmOnly => &["import"],
        }
    }
}

impl fmt::Display for ModuleResolutionStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// EcosystemPattern
// ---------------------------------------------------------------------------

/// A React ecosystem usage pattern to validate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EcosystemPattern {
    /// Unique identifier for this pattern.
    pub pattern_id: String,
    /// Human-readable description of the pattern.
    pub description: String,
    /// Primary React packages used in this pattern.
    pub required_packages: Vec<ReactPackage>,
    /// Ecosystem deployment mode.
    pub mode: EcosystemMode,
    /// JSX compilation mode.
    pub compile_mode: CompileMode,
    /// Module resolution strategy.
    pub resolution_strategy: ModuleResolutionStrategy,
    /// Custom package configurations for this pattern.
    pub package_config: BTreeMap<String, String>,
    /// Expected entry points for this pattern.
    pub entry_points: Vec<String>,
    /// Expected subpath imports for this pattern.
    pub subpath_imports: Vec<String>,
}

impl EcosystemPattern {
    /// Creates a new ecosystem pattern.
    pub fn new(
        pattern_id: String,
        description: String,
        mode: EcosystemMode,
        compile_mode: CompileMode,
    ) -> Self {
        Self {
            pattern_id,
            description,
            required_packages: Vec::new(),
            mode,
            compile_mode,
            resolution_strategy: ModuleResolutionStrategy::NodeExports,
            package_config: BTreeMap::new(),
            entry_points: Vec::new(),
            subpath_imports: Vec::new(),
        }
    }

    /// Adds a required package to this pattern.
    pub fn with_package(mut self, package: ReactPackage) -> Self {
        self.required_packages.push(package);
        self.required_packages.sort();
        self.required_packages.dedup();
        self
    }

    /// Sets the module resolution strategy.
    pub fn with_resolution_strategy(mut self, strategy: ModuleResolutionStrategy) -> Self {
        self.resolution_strategy = strategy;
        self
    }

    /// Adds a package configuration entry.
    pub fn with_package_config(mut self, package: String, config: String) -> Self {
        self.package_config.insert(package, config);
        self
    }

    /// Adds an entry point.
    pub fn with_entry_point(mut self, entry_point: String) -> Self {
        self.entry_points.push(entry_point);
        self
    }

    /// Adds a subpath import.
    pub fn with_subpath_import(mut self, subpath: String) -> Self {
        self.subpath_imports.push(subpath);
        self
    }

    /// Validates the pattern configuration.
    pub fn validate(&self) -> Result<(), EcosystemCompatibilityError> {
        if self.pattern_id.is_empty() {
            return Err(EcosystemCompatibilityError::InvalidPattern {
                pattern_id: self.pattern_id.clone(),
                reason: "pattern_id cannot be empty".to_string(),
            });
        }

        if self.required_packages.is_empty() {
            return Err(EcosystemCompatibilityError::InvalidPattern {
                pattern_id: self.pattern_id.clone(),
                reason: "at least one required package must be specified".to_string(),
            });
        }

        if self.entry_points.is_empty() {
            return Err(EcosystemCompatibilityError::InvalidPattern {
                pattern_id: self.pattern_id.clone(),
                reason: "at least one entry point must be specified".to_string(),
            });
        }

        // Validate that SSR patterns include react-dom/server
        if self.mode.requires_server_capabilities() {
            if !self
                .required_packages
                .contains(&ReactPackage::ReactDomServer)
            {
                return Err(EcosystemCompatibilityError::InvalidPattern {
                    pattern_id: self.pattern_id.clone(),
                    reason: "SSR patterns must include ReactDomServer package".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Computes a deterministic hash of this pattern.
    pub fn compute_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(self.pattern_id.as_bytes());
        hasher.update(&[self.mode as u8]);
        hasher.update(&[self.compile_mode as u8]);
        hasher.update(&[self.resolution_strategy as u8]);

        for package in &self.required_packages {
            hasher.update(&[*package as u8]);
        }

        for (key, value) in &self.package_config {
            hasher.update(key.as_bytes());
            hasher.update(value.as_bytes());
        }

        for entry in &self.entry_points {
            hasher.update(entry.as_bytes());
        }

        for subpath in &self.subpath_imports {
            hasher.update(subpath.as_bytes());
        }

        ContentHash::from_bytes(hasher.finalize().into())
    }
}

// ---------------------------------------------------------------------------
// CompatibilityTestResult
// ---------------------------------------------------------------------------

/// Compatibility failure category used for deterministic triage routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityFailureKind {
    /// A required React package was not represented by shipped cohort evidence.
    PackageResolution,
    /// A required entry point did not resolve through shipped export-map rules.
    EntryPointLoading,
    /// A required runtime subpath did not resolve through shipped export-map rules.
    SubpathResolution,
    /// JSX compilation prerequisites or entrygraph resolution failed.
    Compilation,
    /// Runtime-mode prerequisites for SSR/client/hydration failed.
    RuntimeOperation,
}

impl CompatibilityFailureKind {
    const fn owner_route(self) -> &'static str {
        match self {
            Self::PackageResolution => "react-package-cohort",
            Self::EntryPointLoading | Self::SubpathResolution => "react-entrygraph-resolution",
            Self::Compilation => "react-compile-verification",
            Self::RuntimeOperation => "react-runtime-entrygraph",
        }
    }
}

/// Minimal deterministic repro payload for a failed React ecosystem pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimizedReactEcosystemRepro {
    /// Pattern identifier.
    pub pattern_id: String,
    /// Rendering/runtime mode under test.
    pub mode: EcosystemMode,
    /// JSX compile mode under test.
    pub compile_mode: CompileMode,
    /// Export-map resolution strategy under test.
    pub resolution_strategy: ModuleResolutionStrategy,
    /// The smallest concrete specifier tied to the failure, when available.
    pub failing_specifier: Option<String>,
    /// Required package cohort for the repro.
    pub required_packages: Vec<ReactPackage>,
    /// Required entry points for the repro.
    pub entry_points: Vec<String>,
    /// Required runtime subpath imports for the repro.
    pub subpath_imports: Vec<String>,
}

impl MinimizedReactEcosystemRepro {
    fn from_pattern(pattern: &EcosystemPattern, failing_specifier: Option<&str>) -> Self {
        Self {
            pattern_id: pattern.pattern_id.clone(),
            mode: pattern.mode,
            compile_mode: pattern.compile_mode,
            resolution_strategy: pattern.resolution_strategy,
            failing_specifier: failing_specifier.map(str::to_string),
            required_packages: pattern.required_packages.clone(),
            entry_points: pattern.entry_points.clone(),
            subpath_imports: pattern.subpath_imports.clone(),
        }
    }
}

/// Owner routing for a failed compatibility check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactEcosystemOwnerRoute {
    /// Owning compatibility component.
    pub component: String,
    /// Stable route for the subsystem that owns the failure.
    pub route: String,
    /// Bead that owns the compatibility lane.
    pub bead_id: String,
    /// Human-facing owner label for triage.
    pub owner: String,
}

/// Shipped-path status for a failed React ecosystem check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReactShippedPathStatus {
    /// The specifier resolves to a checked-in shipped path.
    Shipped,
    /// The React package is absent from the checked-in cohort matrix.
    MissingPackage,
    /// The specifier is outside the supported React ecosystem surface.
    UnrecognizedSpecifier,
    /// The package exists, but the requested subpath does not resolve.
    UnresolvedSubpath,
    /// A pattern-level prerequisite failed rather than a concrete shipped path.
    RuntimePrerequisite,
}

/// Shipped-path classification attached to an unresolved compatibility failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactShippedPathClassification {
    /// Classification status.
    pub status: ReactShippedPathStatus,
    /// Original specifier, when the failure is tied to one.
    pub specifier: Option<String>,
    /// Parsed React package, when available.
    pub package: Option<ReactPackage>,
    /// Parsed React subpath, when available.
    pub subpath: Option<String>,
    /// Export conditions used for the resolution attempt.
    pub conditions: Vec<ExportCondition>,
    /// Resolved shipped path for failures caused by higher-level prerequisites.
    pub resolved_path: Option<String>,
    /// Deterministic explanation for operator triage.
    pub reason: String,
}

/// Fully routed unresolved React ecosystem failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityFailureTriage {
    /// Failure category.
    pub failure_kind: CompatibilityFailureKind,
    /// User-facing failure message.
    pub failure: String,
    /// Smallest repro payload for this failed pattern.
    pub minimized_repro: MinimizedReactEcosystemRepro,
    /// Owning route for follow-up work.
    pub owner_route: ReactEcosystemOwnerRoute,
    /// Shipped-path classification for the failed specifier or prerequisite.
    pub shipped_path_classification: ReactShippedPathClassification,
}

/// Result of testing an ecosystem pattern for compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityTestResult {
    /// The pattern that was tested.
    pub pattern: EcosystemPattern,
    /// Whether the pattern passed compatibility testing.
    pub passed: bool,
    /// Detailed test metrics.
    pub metrics: CompatibilityMetrics,
    /// Any errors encountered during testing.
    pub errors: Vec<String>,
    /// Structured triage records for unresolved compatibility failures.
    pub unresolved_failures: Vec<CompatibilityFailureTriage>,
    /// Diagnostic messages from the test run.
    pub diagnostics: Vec<String>,
    /// Test execution time in milliseconds.
    pub execution_time_ms: u64,
    /// Hash of the test inputs for reproducibility.
    pub input_hash: ContentHash,
}

impl CompatibilityTestResult {
    /// Creates a new compatibility test result.
    pub fn new(pattern: EcosystemPattern, passed: bool) -> Self {
        let input_hash = pattern.compute_hash();
        Self {
            pattern,
            passed,
            metrics: CompatibilityMetrics::default(),
            errors: Vec::new(),
            unresolved_failures: Vec::new(),
            diagnostics: Vec::new(),
            execution_time_ms: 0,
            input_hash,
        }
    }

    /// Adds an error to the test result.
    pub fn with_error(mut self, error: String) -> Self {
        self.errors.push(error);
        self
    }

    /// Adds an unresolved failure with deterministic repro, owner, and
    /// shipped-path triage metadata.
    pub fn with_unresolved_failure(mut self, failure: CompatibilityFailureTriage) -> Self {
        self.errors.push(failure.failure.clone());
        self.unresolved_failures.push(failure);
        self
    }

    /// Adds a diagnostic message to the test result.
    pub fn with_diagnostic(mut self, diagnostic: String) -> Self {
        self.diagnostics.push(diagnostic);
        self
    }

    /// Sets the execution time.
    pub fn with_execution_time(mut self, time_ms: u64) -> Self {
        self.execution_time_ms = time_ms;
        self
    }

    /// Sets the test metrics.
    pub fn with_metrics(mut self, metrics: CompatibilityMetrics) -> Self {
        self.metrics = metrics;
        self
    }
}

// ---------------------------------------------------------------------------
// CompatibilityMetrics
// ---------------------------------------------------------------------------

/// Detailed metrics from compatibility testing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityMetrics {
    /// Number of packages successfully resolved.
    pub packages_resolved: usize,
    /// Number of entry points successfully loaded.
    pub entry_points_loaded: usize,
    /// Number of subpath imports successfully resolved.
    pub subpaths_resolved: usize,
    /// Number of compilation operations that succeeded.
    pub compilations_successful: usize,
    /// Number of runtime operations that succeeded.
    pub runtime_operations_successful: usize,
    /// Total compatibility score as millionths (0 to 1_000_000).
    pub compatibility_score_millionths: u64,
}

impl Default for CompatibilityMetrics {
    fn default() -> Self {
        Self {
            packages_resolved: 0,
            entry_points_loaded: 0,
            subpaths_resolved: 0,
            compilations_successful: 0,
            runtime_operations_successful: 0,
            compatibility_score_millionths: 0,
        }
    }
}

impl CompatibilityMetrics {
    /// Computes the overall compatibility score.
    pub fn compute_compatibility_score(&self) -> u64 {
        // Simple scoring: equal weight for each category that had any operations attempted
        let mut total_score = 0u64;
        // Count non-zero categories and sum their contributions
        if self.packages_resolved > 0 {
            total_score += MILLIONTHS / 5; // 200,000 millionths per category
        }
        if self.entry_points_loaded > 0 {
            total_score += MILLIONTHS / 5;
        }
        if self.subpaths_resolved > 0 {
            total_score += MILLIONTHS / 5;
        }
        if self.compilations_successful > 0 {
            total_score += MILLIONTHS / 5;
        }
        if self.runtime_operations_successful > 0 {
            total_score += MILLIONTHS / 5;
        }

        total_score
    }
}

// ---------------------------------------------------------------------------
// EcosystemCompatibilityReport
// ---------------------------------------------------------------------------

/// Comprehensive report of React ecosystem compatibility testing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcosystemCompatibilityReport {
    /// Schema version for this report.
    pub schema_version: String,
    /// Security epoch when this report was generated.
    pub security_epoch: SecurityEpoch,
    /// Results for all tested patterns.
    pub test_results: Vec<CompatibilityTestResult>,
    /// Overall compatibility metrics.
    pub overall_metrics: CompatibilityMetrics,
    /// Whether the ecosystem compatibility gate passed.
    pub gate_passed: bool,
    /// Compatibility threshold used for the gate.
    pub compatibility_threshold_millionths: u64,
    /// Total test execution time in milliseconds.
    pub total_execution_time_ms: u64,
    /// Hash of all test inputs for reproducibility.
    pub report_hash: ContentHash,
}

#[derive(Serialize)]
struct EcosystemCompatibilityReportHashView<'a> {
    schema_version: &'a str,
    security_epoch: SecurityEpoch,
    test_results: &'a [CompatibilityTestResult],
    overall_metrics: &'a CompatibilityMetrics,
    gate_passed: bool,
    compatibility_threshold_millionths: u64,
    total_execution_time_ms: u64,
}

impl EcosystemCompatibilityReport {
    /// Creates a new ecosystem compatibility report.
    pub fn new(security_epoch: SecurityEpoch) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            security_epoch,
            test_results: Vec::new(),
            overall_metrics: CompatibilityMetrics::default(),
            gate_passed: false,
            compatibility_threshold_millionths: DEFAULT_COMPATIBILITY_THRESHOLD,
            total_execution_time_ms: 0,
            report_hash: ContentHash::compute(&[]),
        }
    }

    /// Adds a test result to the report.
    pub fn add_test_result(&mut self, result: CompatibilityTestResult) {
        self.test_results.push(result);
    }

    /// Finalizes the report by computing overall metrics and determining gate status.
    pub fn finalize(&mut self) -> Result<(), EcosystemCompatibilityError> {
        if self.test_results.is_empty() {
            return Err(EcosystemCompatibilityError::NoTestResults);
        }

        // Compute overall metrics
        let mut total_packages = 0;
        let mut total_entry_points = 0;
        let mut total_subpaths = 0;
        let mut total_compilations = 0;
        let mut total_runtime_ops = 0;
        let mut total_execution_time = 0;

        for result in &self.test_results {
            total_packages += result.metrics.packages_resolved;
            total_entry_points += result.metrics.entry_points_loaded;
            total_subpaths += result.metrics.subpaths_resolved;
            total_compilations += result.metrics.compilations_successful;
            total_runtime_ops += result.metrics.runtime_operations_successful;
            total_execution_time += result.execution_time_ms;
        }

        self.overall_metrics = CompatibilityMetrics {
            packages_resolved: total_packages,
            entry_points_loaded: total_entry_points,
            subpaths_resolved: total_subpaths,
            compilations_successful: total_compilations,
            runtime_operations_successful: total_runtime_ops,
            compatibility_score_millionths: 0, // Will be computed below
        };

        self.total_execution_time_ms = total_execution_time;

        // Compute overall compatibility score
        let passed_tests = self.test_results.iter().filter(|r| r.passed).count();
        let total_tests = self.test_results.len();

        if total_tests > 0 {
            self.overall_metrics.compatibility_score_millionths =
                (passed_tests as u64 * MILLIONTHS) / total_tests as u64;
        }

        // Determine gate status
        self.gate_passed = self.overall_metrics.compatibility_score_millionths
            >= self.compatibility_threshold_millionths;

        // Compute report hash
        self.report_hash = self.compute_hash();

        Ok(())
    }

    /// Computes a deterministic hash of the report.
    pub fn compute_hash(&self) -> ContentHash {
        let hash_view = EcosystemCompatibilityReportHashView {
            schema_version: &self.schema_version,
            security_epoch: self.security_epoch,
            test_results: &self.test_results,
            overall_metrics: &self.overall_metrics,
            gate_passed: self.gate_passed,
            compatibility_threshold_millionths: self.compatibility_threshold_millionths,
            total_execution_time_ms: self.total_execution_time_ms,
        };

        let encoded = serde_json::to_vec(&hash_view)
            .expect("ecosystem compatibility report hash view must serialize");
        ContentHash::compute(&encoded)
    }

    /// Returns the percentage of tests that passed.
    pub fn pass_percentage(&self) -> f64 {
        if self.test_results.is_empty() {
            return 0.0;
        }

        let passed = self.test_results.iter().filter(|r| r.passed).count();
        (passed as f64 / self.test_results.len() as f64) * 100.0
    }

    /// Returns tests grouped by ecosystem mode.
    pub fn results_by_mode(&self) -> BTreeMap<EcosystemMode, Vec<&CompatibilityTestResult>> {
        let mut by_mode = BTreeMap::new();
        for result in &self.test_results {
            by_mode
                .entry(result.pattern.mode)
                .or_insert_with(Vec::new)
                .push(result);
        }
        by_mode
    }
}

// ---------------------------------------------------------------------------
// EcosystemCompatibilityError
// ---------------------------------------------------------------------------

/// Errors that can occur during ecosystem compatibility testing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EcosystemCompatibilityError {
    /// Invalid ecosystem pattern configuration.
    InvalidPattern { pattern_id: String, reason: String },
    /// No test results to process.
    NoTestResults,
    /// Package resolution failed.
    PackageResolutionFailed { package: String, error: String },
    /// Module compilation failed.
    CompilationFailed { module: String, error: String },
    /// Runtime execution failed.
    RuntimeFailed { operation: String, error: String },
    /// I/O operation failed.
    IoError { operation: String, error: String },
    /// Serialization/deserialization failed.
    SerializationError { context: String, error: String },
}

impl fmt::Display for EcosystemCompatibilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPattern { pattern_id, reason } => {
                write!(f, "Invalid pattern '{}': {}", pattern_id, reason)
            }
            Self::NoTestResults => write!(f, "No test results available"),
            Self::PackageResolutionFailed { package, error } => {
                write!(f, "Failed to resolve package '{}': {}", package, error)
            }
            Self::CompilationFailed { module, error } => {
                write!(f, "Failed to compile module '{}': {}", module, error)
            }
            Self::RuntimeFailed { operation, error } => {
                write!(f, "Runtime operation '{}' failed: {}", operation, error)
            }
            Self::IoError { operation, error } => {
                write!(f, "I/O error during '{}': {}", operation, error)
            }
            Self::SerializationError { context, error } => {
                write!(f, "Serialization error in '{}': {}", context, error)
            }
        }
    }
}

impl std::error::Error for EcosystemCompatibilityError {}

// ---------------------------------------------------------------------------
// EcosystemCompatibilityValidator
// ---------------------------------------------------------------------------

/// Main validator for React ecosystem compatibility.
pub struct EcosystemCompatibilityValidator {
    /// Security epoch for this validation run.
    pub security_epoch: SecurityEpoch,
    /// Compatibility threshold (millionths).
    pub compatibility_threshold_millionths: u64,
    /// Maximum number of patterns to test.
    pub max_patterns: usize,
}

impl EcosystemCompatibilityValidator {
    /// Creates a new ecosystem compatibility validator.
    pub fn new(security_epoch: SecurityEpoch) -> Self {
        Self {
            security_epoch,
            compatibility_threshold_millionths: DEFAULT_COMPATIBILITY_THRESHOLD,
            max_patterns: MAX_ECOSYSTEM_PATTERNS,
        }
    }

    /// Sets the compatibility threshold.
    pub fn with_compatibility_threshold(mut self, threshold_millionths: u64) -> Self {
        self.compatibility_threshold_millionths = threshold_millionths;
        self
    }

    /// Sets the maximum number of patterns to test.
    pub fn with_max_patterns(mut self, max_patterns: usize) -> Self {
        self.max_patterns = max_patterns;
        self
    }

    /// Runs ecosystem compatibility validation for the given patterns.
    pub fn validate_patterns(
        &self,
        patterns: &[EcosystemPattern],
    ) -> Result<EcosystemCompatibilityReport, EcosystemCompatibilityError> {
        let mut report = EcosystemCompatibilityReport::new(self.security_epoch);
        report.compatibility_threshold_millionths = self.compatibility_threshold_millionths;

        // Validate and test each pattern
        let test_patterns = if patterns.len() > self.max_patterns {
            &patterns[..self.max_patterns]
        } else {
            patterns
        };

        for pattern in test_patterns {
            // Validate pattern configuration
            pattern.validate()?;

            // Run compatibility test for this pattern
            let result = self.test_pattern_compatibility(pattern)?;
            report.add_test_result(result);
        }

        // Finalize the report
        report.finalize()?;

        Ok(report)
    }

    /// Tests compatibility for a single ecosystem pattern.
    fn test_pattern_compatibility(
        &self,
        pattern: &EcosystemPattern,
    ) -> Result<CompatibilityTestResult, EcosystemCompatibilityError> {
        let start_time = std::time::Instant::now();

        let mut result = CompatibilityTestResult::new(pattern.clone(), false);
        let mut metrics = CompatibilityMetrics::default();

        // Test package resolution
        for package in &pattern.required_packages {
            if self.test_package_resolution(*package, pattern)? {
                metrics.packages_resolved += 1;
            } else {
                let failure = format!("Package resolution failed: {:?}", package);
                result = result.with_unresolved_failure(compatibility_failure_triage(
                    CompatibilityFailureKind::PackageResolution,
                    pattern,
                    failure,
                    None,
                    Some(*package),
                ));
            }
        }

        // Test entry point loading
        for entry_point in &pattern.entry_points {
            if self.test_entry_point_loading(entry_point, pattern)? {
                metrics.entry_points_loaded += 1;
            } else {
                let failure = format!("Entry point loading failed: {}", entry_point);
                result = result.with_unresolved_failure(compatibility_failure_triage(
                    CompatibilityFailureKind::EntryPointLoading,
                    pattern,
                    failure,
                    Some(entry_point),
                    None,
                ));
            }
        }

        // Test subpath resolution
        for subpath in &pattern.subpath_imports {
            if self.test_subpath_resolution(subpath, pattern)? {
                metrics.subpaths_resolved += 1;
            } else {
                let failure = format!("Subpath resolution failed: {}", subpath);
                result = result.with_unresolved_failure(compatibility_failure_triage(
                    CompatibilityFailureKind::SubpathResolution,
                    pattern,
                    failure,
                    Some(subpath),
                    None,
                ));
            }
        }

        // Test compilation
        if self.test_compilation(pattern)? {
            metrics.compilations_successful += 1;
        } else {
            let failure = "Compilation test failed".to_string();
            result = result.with_unresolved_failure(compatibility_failure_triage(
                CompatibilityFailureKind::Compilation,
                pattern,
                failure,
                failing_compile_specifier(pattern),
                None,
            ));
        }

        // Test runtime operations
        if self.test_runtime_operations(pattern)? {
            metrics.runtime_operations_successful += 1;
        } else {
            let failure = "Runtime operations test failed".to_string();
            result = result.with_unresolved_failure(compatibility_failure_triage(
                CompatibilityFailureKind::RuntimeOperation,
                pattern,
                failure,
                failing_runtime_specifier(pattern),
                None,
            ));
        }

        // Compute final score
        metrics.compatibility_score_millionths = metrics.compute_compatibility_score();

        // Determine if pattern passed (all operations successful)
        let passed = metrics.packages_resolved == pattern.required_packages.len()
            && metrics.entry_points_loaded == pattern.entry_points.len()
            && metrics.subpaths_resolved == pattern.subpath_imports.len()
            && metrics.compilations_successful > 0
            && metrics.runtime_operations_successful > 0;

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        result.passed = passed;
        result = result.with_metrics(metrics);
        result = result.with_execution_time(execution_time_ms);

        Ok(result)
    }

    /// Tests package resolution for a specific package against the checked-in
    /// React cohort export-map matrix.
    fn test_package_resolution(
        &self,
        package: ReactPackage,
        _pattern: &EcosystemPattern,
    ) -> Result<bool, EcosystemCompatibilityError> {
        let matrix = franken_engine_react_cohort_manifest();
        let Some(manifest) = matrix.find_manifest(package) else {
            return Ok(false);
        };

        Ok(manifest.subpath_count() > 0
            && detect_alias_loops(manifest).is_empty()
            && verify_format_consistency(manifest).is_empty())
    }

    /// Tests loading of an entry point through the same export-map rules used by
    /// the React package cohort matrix.
    fn test_entry_point_loading(
        &self,
        entry_point: &str,
        pattern: &EcosystemPattern,
    ) -> Result<bool, EcosystemCompatibilityError> {
        let Some((package, _)) = react_specifier_package_and_subpath(entry_point) else {
            return Ok(false);
        };
        Ok(pattern.required_packages.contains(&package)
            && react_specifier_resolves(entry_point, pattern))
    }

    /// Tests subpath resolution through the same export-map rules used by the
    /// React package cohort matrix.
    fn test_subpath_resolution(
        &self,
        subpath: &str,
        pattern: &EcosystemPattern,
    ) -> Result<bool, EcosystemCompatibilityError> {
        let Some((package, _)) = react_specifier_package_and_subpath(subpath) else {
            return Ok(false);
        };
        Ok(pattern.required_packages.contains(&package)
            && react_specifier_resolves(subpath, pattern))
    }

    /// Tests compile-mode prerequisites and entrygraph resolvability.
    fn test_compilation(
        &self,
        pattern: &EcosystemPattern,
    ) -> Result<bool, EcosystemCompatibilityError> {
        let compile_runtime_available = match pattern.compile_mode {
            CompileMode::Classic => pattern.required_packages.contains(&ReactPackage::React),
            CompileMode::Automatic => {
                let has_runtime_package = pattern.required_packages.iter().any(|package| {
                    matches!(
                        package,
                        ReactPackage::ReactJsxRuntime | ReactPackage::ReactJsxDevRuntime
                    )
                });
                let has_runtime_import = pattern.subpath_imports.iter().any(|subpath| {
                    matches!(
                        subpath.as_str(),
                        "react/jsx-runtime" | "react/jsx-dev-runtime"
                    )
                });
                has_runtime_package && has_runtime_import
            }
        };

        Ok(compile_runtime_available
            && pattern
                .entry_points
                .iter()
                .all(|entry_point| react_specifier_resolves(entry_point, pattern))
            && pattern
                .subpath_imports
                .iter()
                .all(|subpath| react_specifier_resolves(subpath, pattern)))
    }

    /// Tests runtime-mode prerequisites for SSR, CSR, SSG, and hydration-adjacent
    /// React entrygraphs.
    fn test_runtime_operations(
        &self,
        pattern: &EcosystemPattern,
    ) -> Result<bool, EcosystemCompatibilityError> {
        let has_server_runtime = !pattern.mode.requires_server_capabilities()
            || (pattern
                .required_packages
                .contains(&ReactPackage::ReactDomServer)
                && pattern
                    .entry_points
                    .iter()
                    .any(|entry_point| entry_point == "react-dom/server"));
        let has_client_runtime = !pattern.mode.requires_client_hydration()
            || (pattern.required_packages.contains(&ReactPackage::ReactDom)
                && pattern
                    .entry_points
                    .iter()
                    .any(|entry_point| entry_point == "react-dom/client"));

        Ok(has_server_runtime && has_client_runtime)
    }
}

fn compatibility_failure_triage(
    failure_kind: CompatibilityFailureKind,
    pattern: &EcosystemPattern,
    failure: String,
    failing_specifier: Option<&str>,
    package: Option<ReactPackage>,
) -> CompatibilityFailureTriage {
    CompatibilityFailureTriage {
        failure_kind,
        failure,
        minimized_repro: MinimizedReactEcosystemRepro::from_pattern(pattern, failing_specifier),
        owner_route: owner_route_for_failure(failure_kind),
        shipped_path_classification: classify_react_shipped_path(
            failure_kind,
            pattern,
            failing_specifier,
            package,
        ),
    }
}

fn owner_route_for_failure(failure_kind: CompatibilityFailureKind) -> ReactEcosystemOwnerRoute {
    ReactEcosystemOwnerRoute {
        component: COMPONENT.to_string(),
        route: failure_kind.owner_route().to_string(),
        bead_id: BEAD_ID.to_string(),
        owner: format!("{}::{}", COMPONENT, failure_kind.owner_route()),
    }
}

fn classify_react_shipped_path(
    failure_kind: CompatibilityFailureKind,
    pattern: &EcosystemPattern,
    failing_specifier: Option<&str>,
    package: Option<ReactPackage>,
) -> ReactShippedPathClassification {
    let conditions = export_conditions_for_strategy(pattern.resolution_strategy);

    if let Some(specifier) = failing_specifier {
        return classify_specifier_shipped_path(specifier, pattern, conditions);
    }

    if let Some(package) = package {
        return classify_package_shipped_path(package, conditions);
    }

    ReactShippedPathClassification {
        status: ReactShippedPathStatus::RuntimePrerequisite,
        specifier: None,
        package: None,
        subpath: None,
        conditions,
        resolved_path: None,
        reason: format!(
            "{} failed because the pattern-level {:?} prerequisite did not hold",
            pattern.pattern_id, failure_kind
        ),
    }
}

fn classify_specifier_shipped_path(
    specifier: &str,
    pattern: &EcosystemPattern,
    conditions: Vec<ExportCondition>,
) -> ReactShippedPathClassification {
    let Some((package, subpath)) = react_specifier_package_and_subpath(specifier) else {
        return ReactShippedPathClassification {
            status: ReactShippedPathStatus::UnrecognizedSpecifier,
            specifier: Some(specifier.to_string()),
            package: None,
            subpath: None,
            conditions,
            resolved_path: None,
            reason: format!("{specifier} is not part of the declared React ecosystem surface"),
        };
    };

    let matrix = franken_engine_react_cohort_manifest();
    let Some(manifest) = matrix.find_manifest(package) else {
        return ReactShippedPathClassification {
            status: ReactShippedPathStatus::MissingPackage,
            specifier: Some(specifier.to_string()),
            package: Some(package),
            subpath: Some(subpath.to_string()),
            conditions,
            resolved_path: None,
            reason: format!(
                "{} is missing from the checked-in React cohort matrix",
                package
            ),
        };
    };

    match resolve_subpath_with_fallbacks(manifest, subpath, &conditions) {
        Ok(entry) => ReactShippedPathClassification {
            status: ReactShippedPathStatus::Shipped,
            specifier: Some(specifier.to_string()),
            package: Some(package),
            subpath: Some(subpath.to_string()),
            conditions,
            resolved_path: Some(entry.resolved_path.clone()),
            reason: format!(
                "{specifier} resolves to shipped path {} for pattern {}",
                entry.resolved_path, pattern.pattern_id
            ),
        },
        Err(source) => ReactShippedPathClassification {
            status: ReactShippedPathStatus::UnresolvedSubpath,
            specifier: Some(specifier.to_string()),
            package: Some(package),
            subpath: Some(subpath.to_string()),
            conditions,
            resolved_path: None,
            reason: format!(
                "{specifier} did not resolve through shipped export-map evidence: {source}"
            ),
        },
    }
}

fn classify_package_shipped_path(
    package: ReactPackage,
    conditions: Vec<ExportCondition>,
) -> ReactShippedPathClassification {
    let matrix = franken_engine_react_cohort_manifest();
    let Some(manifest) = matrix.find_manifest(package) else {
        return ReactShippedPathClassification {
            status: ReactShippedPathStatus::MissingPackage,
            specifier: None,
            package: Some(package),
            subpath: None,
            conditions,
            resolved_path: None,
            reason: format!(
                "{} is missing from the checked-in React cohort matrix",
                package
            ),
        };
    };

    let alias_loop_count = detect_alias_loops(manifest).len();
    let format_issue_count = verify_format_consistency(manifest).len();
    if manifest.subpath_count() == 0 || alias_loop_count > 0 || format_issue_count > 0 {
        return ReactShippedPathClassification {
            status: ReactShippedPathStatus::UnresolvedSubpath,
            specifier: None,
            package: Some(package),
            subpath: None,
            conditions,
            resolved_path: None,
            reason: format!(
                "{} cohort evidence has subpaths={}, alias_loops={}, format_issues={}",
                package,
                manifest.subpath_count(),
                alias_loop_count,
                format_issue_count
            ),
        };
    }

    ReactShippedPathClassification {
        status: ReactShippedPathStatus::Shipped,
        specifier: None,
        package: Some(package),
        subpath: None,
        conditions,
        resolved_path: None,
        reason: format!("{} has checked-in shipped cohort evidence", package),
    }
}

fn failing_compile_specifier(pattern: &EcosystemPattern) -> Option<&str> {
    if pattern.compile_mode == CompileMode::Automatic {
        if let Some(runtime_import) = pattern.subpath_imports.iter().find(|subpath| {
            matches!(
                subpath.as_str(),
                "react/jsx-runtime" | "react/jsx-dev-runtime"
            ) && !react_specifier_resolves(subpath, pattern)
        }) {
            return Some(runtime_import.as_str());
        }

        if !pattern.subpath_imports.iter().any(|subpath| {
            matches!(
                subpath.as_str(),
                "react/jsx-runtime" | "react/jsx-dev-runtime"
            )
        }) {
            return Some("react/jsx-runtime");
        }
    }

    pattern
        .entry_points
        .iter()
        .chain(pattern.subpath_imports.iter())
        .find(|specifier| !react_specifier_resolves(specifier, pattern))
        .map(String::as_str)
}

fn failing_runtime_specifier(pattern: &EcosystemPattern) -> Option<&str> {
    if pattern.mode.requires_server_capabilities()
        && (!pattern
            .required_packages
            .contains(&ReactPackage::ReactDomServer)
            || !pattern
                .entry_points
                .iter()
                .any(|entry_point| entry_point == "react-dom/server"))
    {
        return Some("react-dom/server");
    }

    if pattern.mode.requires_client_hydration()
        && (!pattern.required_packages.contains(&ReactPackage::ReactDom)
            || !pattern
                .entry_points
                .iter()
                .any(|entry_point| entry_point == "react-dom/client"))
    {
        return Some("react-dom/client");
    }

    None
}

fn react_specifier_resolves(specifier: &str, pattern: &EcosystemPattern) -> bool {
    let Some((package, subpath)) = react_specifier_package_and_subpath(specifier) else {
        return false;
    };
    let matrix = franken_engine_react_cohort_manifest();
    let Some(manifest) = matrix.find_manifest(package) else {
        return false;
    };
    let conditions = export_conditions_for_strategy(pattern.resolution_strategy);
    resolve_subpath_with_fallbacks(manifest, subpath, &conditions).is_ok()
}

fn react_specifier_package_and_subpath(specifier: &str) -> Option<(ReactPackage, &'static str)> {
    match specifier {
        "react" => Some((ReactPackage::React, ".")),
        "react-dom" => Some((ReactPackage::ReactDom, ".")),
        "react-dom/client" => Some((ReactPackage::ReactDom, "./client")),
        "react-dom/server" => Some((ReactPackage::ReactDomServer, ".")),
        "react/jsx-runtime" => Some((ReactPackage::ReactJsxRuntime, ".")),
        "react/jsx-dev-runtime" => Some((ReactPackage::ReactJsxDevRuntime, ".")),
        "scheduler" => Some((ReactPackage::Scheduler, ".")),
        "react-reconciler" => Some((ReactPackage::ReactReconciler, ".")),
        _ => None,
    }
}

fn export_conditions_for_strategy(strategy: ModuleResolutionStrategy) -> Vec<ExportCondition> {
    let mut conditions = Vec::new();
    for condition in strategy.resolution_conditions() {
        let Some(mapped) = export_condition_from_key(condition) else {
            continue;
        };
        if !conditions.contains(&mapped) {
            conditions.push(mapped);
        }
    }
    if !conditions.contains(&ExportCondition::Default) {
        conditions.push(ExportCondition::Default);
    }
    conditions
}

fn export_condition_from_key(condition: &str) -> Option<ExportCondition> {
    match condition {
        "import" => Some(ExportCondition::Import),
        "require" => Some(ExportCondition::Require),
        "default" | "main" => Some(ExportCondition::Default),
        "browser" | "webpack" => Some(ExportCondition::Browser),
        "node" => Some(ExportCondition::Node),
        "react-server" => Some(ExportCondition::ReactServer),
        "react-native" => Some(ExportCondition::ReactNative),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Standard ecosystem patterns
// ---------------------------------------------------------------------------

/// Creates the standard React ecosystem patterns for testing.
pub fn create_standard_ecosystem_patterns() -> Vec<EcosystemPattern> {
    vec![
        // Standard React app with CSR
        EcosystemPattern::new(
            "react_csr_standard".to_string(),
            "Standard React app with client-side rendering".to_string(),
            EcosystemMode::ClientSideRendering,
            CompileMode::Automatic,
        )
        .with_package(ReactPackage::React)
        .with_package(ReactPackage::ReactDom)
        .with_package(ReactPackage::ReactJsxRuntime)
        .with_entry_point("react".to_string())
        .with_entry_point("react-dom".to_string())
        .with_subpath_import("react/jsx-runtime".to_string()),
        // React SSR app
        EcosystemPattern::new(
            "react_ssr_standard".to_string(),
            "React app with server-side rendering".to_string(),
            EcosystemMode::ServerSideRendering,
            CompileMode::Automatic,
        )
        .with_package(ReactPackage::React)
        .with_package(ReactPackage::ReactDom)
        .with_package(ReactPackage::ReactDomServer)
        .with_package(ReactPackage::ReactJsxRuntime)
        .with_entry_point("react".to_string())
        .with_entry_point("react-dom/server".to_string())
        .with_subpath_import("react/jsx-runtime".to_string()),
        // React with classic JSX transform
        EcosystemPattern::new(
            "react_csr_classic".to_string(),
            "React app with classic JSX transform".to_string(),
            EcosystemMode::ClientSideRendering,
            CompileMode::Classic,
        )
        .with_package(ReactPackage::React)
        .with_package(ReactPackage::ReactDom)
        .with_entry_point("react".to_string())
        .with_entry_point("react-dom".to_string()),
        // React with custom renderer
        EcosystemPattern::new(
            "react_custom_renderer".to_string(),
            "React with custom renderer using react-reconciler".to_string(),
            EcosystemMode::ClientSideRendering,
            CompileMode::Automatic,
        )
        .with_package(ReactPackage::React)
        .with_package(ReactPackage::ReactReconciler)
        .with_package(ReactPackage::Scheduler)
        .with_package(ReactPackage::ReactJsxRuntime)
        .with_entry_point("react-reconciler".to_string())
        .with_entry_point("scheduler".to_string())
        .with_subpath_import("react/jsx-runtime".to_string()),
        // Hybrid SSR + hydration
        EcosystemPattern::new(
            "react_hybrid_rendering".to_string(),
            "React with hybrid SSR and client hydration".to_string(),
            EcosystemMode::HybridRendering,
            CompileMode::Automatic,
        )
        .with_package(ReactPackage::React)
        .with_package(ReactPackage::ReactDom)
        .with_package(ReactPackage::ReactDomServer)
        .with_package(ReactPackage::ReactJsxRuntime)
        .with_entry_point("react".to_string())
        .with_entry_point("react-dom".to_string())
        .with_entry_point("react-dom/server".to_string())
        .with_subpath_import("react/jsx-runtime".to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecosystem_mode_capabilities() {
        assert!(EcosystemMode::ServerSideRendering.requires_server_capabilities());
        assert!(!EcosystemMode::ClientSideRendering.requires_server_capabilities());
        assert!(EcosystemMode::StaticSiteGeneration.requires_server_capabilities());
        assert!(EcosystemMode::HybridRendering.requires_server_capabilities());

        assert!(!EcosystemMode::ServerSideRendering.requires_client_hydration());
        assert!(!EcosystemMode::ClientSideRendering.requires_client_hydration());
        assert!(!EcosystemMode::StaticSiteGeneration.requires_client_hydration());
        assert!(EcosystemMode::HybridRendering.requires_client_hydration());
    }

    #[test]
    fn test_module_resolution_strategy_conditions() {
        let node_conditions = ModuleResolutionStrategy::NodeExports.resolution_conditions();
        assert!(node_conditions.contains(&"node"));
        assert!(node_conditions.contains(&"import"));

        let esm_conditions = ModuleResolutionStrategy::EsmOnly.resolution_conditions();
        assert_eq!(esm_conditions, &["import"]);
    }

    #[test]
    fn test_ecosystem_pattern_creation() {
        let pattern = EcosystemPattern::new(
            "test_pattern".to_string(),
            "Test pattern".to_string(),
            EcosystemMode::ClientSideRendering,
            CompileMode::Automatic,
        )
        .with_package(ReactPackage::React)
        .with_entry_point("react".to_string());

        assert_eq!(pattern.pattern_id, "test_pattern");
        assert_eq!(pattern.mode, EcosystemMode::ClientSideRendering);
        assert_eq!(pattern.compile_mode, CompileMode::Automatic);
        assert_eq!(pattern.required_packages, vec![ReactPackage::React]);
        assert_eq!(pattern.entry_points, vec!["react".to_string()]);
    }

    #[test]
    fn test_ecosystem_pattern_validation() {
        // Valid pattern
        let valid_pattern = EcosystemPattern::new(
            "valid".to_string(),
            "Valid pattern".to_string(),
            EcosystemMode::ClientSideRendering,
            CompileMode::Automatic,
        )
        .with_package(ReactPackage::React)
        .with_entry_point("react".to_string());

        assert!(valid_pattern.validate().is_ok());

        // Invalid pattern: empty pattern_id
        let invalid_pattern = EcosystemPattern::new(
            "".to_string(),
            "Invalid pattern".to_string(),
            EcosystemMode::ClientSideRendering,
            CompileMode::Automatic,
        );

        assert!(invalid_pattern.validate().is_err());

        // Invalid pattern: no packages
        let no_packages_pattern = EcosystemPattern::new(
            "no_packages".to_string(),
            "No packages".to_string(),
            EcosystemMode::ClientSideRendering,
            CompileMode::Automatic,
        )
        .with_entry_point("react".to_string());

        assert!(no_packages_pattern.validate().is_err());

        // Invalid pattern: SSR without ReactDomServer
        let invalid_ssr_pattern = EcosystemPattern::new(
            "invalid_ssr".to_string(),
            "Invalid SSR pattern".to_string(),
            EcosystemMode::ServerSideRendering,
            CompileMode::Automatic,
        )
        .with_package(ReactPackage::React)
        .with_entry_point("react".to_string());

        assert!(invalid_ssr_pattern.validate().is_err());
    }

    #[test]
    fn test_ecosystem_pattern_hash_deterministic() {
        let pattern1 = EcosystemPattern::new(
            "test".to_string(),
            "Test".to_string(),
            EcosystemMode::ClientSideRendering,
            CompileMode::Automatic,
        )
        .with_package(ReactPackage::React);

        let pattern2 = EcosystemPattern::new(
            "test".to_string(),
            "Test".to_string(),
            EcosystemMode::ClientSideRendering,
            CompileMode::Automatic,
        )
        .with_package(ReactPackage::React);

        assert_eq!(pattern1.compute_hash(), pattern2.compute_hash());
    }

    #[test]
    fn test_compatibility_metrics_score_computation() {
        let metrics = CompatibilityMetrics {
            packages_resolved: 5,
            entry_points_loaded: 3,
            subpaths_resolved: 2,
            compilations_successful: 1,
            runtime_operations_successful: 1,
            ..Default::default()
        };

        let score = metrics.compute_compatibility_score();

        // Each category gets 1/5 weight, so total should be meaningful
        assert!(score > 0);
        assert!(score <= MILLIONTHS);
    }

    #[test]
    fn test_compatibility_test_result_creation() {
        let pattern = EcosystemPattern::new(
            "test".to_string(),
            "Test".to_string(),
            EcosystemMode::ClientSideRendering,
            CompileMode::Automatic,
        );

        let result = CompatibilityTestResult::new(pattern.clone(), true)
            .with_error("test error".to_string())
            .with_diagnostic("test diagnostic".to_string())
            .with_execution_time(1000);

        assert!(result.passed);
        assert_eq!(result.errors, vec!["test error".to_string()]);
        assert_eq!(result.diagnostics, vec!["test diagnostic".to_string()]);
        assert_eq!(result.execution_time_ms, 1000);
        assert_eq!(result.pattern, pattern);
    }

    #[test]
    fn test_ecosystem_compatibility_validator_creation() {
        let epoch = SecurityEpoch::from_raw(1);
        let validator = EcosystemCompatibilityValidator::new(epoch)
            .with_compatibility_threshold(900_000)
            .with_max_patterns(100);

        assert_eq!(validator.security_epoch, epoch);
        assert_eq!(validator.compatibility_threshold_millionths, 900_000);
        assert_eq!(validator.max_patterns, 100);
    }

    #[test]
    fn test_standard_ecosystem_patterns_creation() {
        let patterns = create_standard_ecosystem_patterns();

        assert!(!patterns.is_empty());

        // Verify all patterns are valid
        for pattern in &patterns {
            assert!(pattern.validate().is_ok());
        }

        // Check that we have different ecosystem modes represented
        let modes: Vec<_> = patterns.iter().map(|p| p.mode).collect();
        assert!(modes.contains(&EcosystemMode::ClientSideRendering));
        assert!(modes.contains(&EcosystemMode::ServerSideRendering));
        assert!(modes.contains(&EcosystemMode::HybridRendering));
    }

    #[test]
    fn test_ecosystem_compatibility_report_finalization() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut report = EcosystemCompatibilityReport::new(epoch);

        // Add some test results
        let pattern = EcosystemPattern::new(
            "test".to_string(),
            "Test".to_string(),
            EcosystemMode::ClientSideRendering,
            CompileMode::Automatic,
        );

        let metrics = CompatibilityMetrics {
            packages_resolved: 1,
            ..Default::default()
        };

        let result = CompatibilityTestResult::new(pattern, true).with_metrics(metrics);

        report.add_test_result(result);

        assert!(report.finalize().is_ok());
        assert_eq!(report.test_results.len(), 1);
        assert!(report.gate_passed); // Single passing test should pass gate
    }

    #[test]
    fn test_ecosystem_compatibility_error_display() {
        let error = EcosystemCompatibilityError::InvalidPattern {
            pattern_id: "test".to_string(),
            reason: "missing packages".to_string(),
        };

        let display = format!("{}", error);
        assert!(display.contains("test"));
        assert!(display.contains("missing packages"));
    }

    #[test]
    fn test_hydration_requires_react_dom_client_entrypoint() {
        // Regression test for bd-1lsy.5.7.4: Patterns requiring client hydration
        // should fail validation if ReactDom package is present but react-dom/client
        // entrypoint is missing.

        // Pattern with ReactDom package but missing react-dom/client entrypoint
        let invalid_hydration_pattern = EcosystemPattern::new(
            "invalid_hydration".to_string(),
            "Hydration pattern missing client entrypoint".to_string(),
            EcosystemMode::HybridRendering, // requires client hydration
            CompileMode::Automatic,
        )
        .with_package(ReactPackage::React)
        .with_package(ReactPackage::ReactDom) // Package present
        .with_package(ReactPackage::ReactDomServer)
        .with_entry_point("react".to_string())
        .with_entry_point("react-dom".to_string())
        .with_entry_point("react-dom/server".to_string());
        // Missing: react-dom/client entrypoint

        // Should fail validation
        assert!(invalid_hydration_pattern.validate().is_err());

        // failing_runtime_specifier should report react-dom/client
        assert_eq!(
            failing_runtime_specifier(&invalid_hydration_pattern),
            Some("react-dom/client")
        );

        // Valid pattern should include react-dom/client entrypoint
        let valid_hydration_pattern = EcosystemPattern::new(
            "valid_hydration".to_string(),
            "Valid hydration pattern with client entrypoint".to_string(),
            EcosystemMode::HybridRendering, // requires client hydration
            CompileMode::Automatic,
        )
        .with_package(ReactPackage::React)
        .with_package(ReactPackage::ReactDom)
        .with_package(ReactPackage::ReactDomServer)
        .with_entry_point("react".to_string())
        .with_entry_point("react-dom".to_string())
        .with_entry_point("react-dom/server".to_string())
        .with_entry_point("react-dom/client".to_string()); // Required for hydration

        // Should pass validation
        assert!(valid_hydration_pattern.validate().is_ok());

        // failing_runtime_specifier should return None
        assert_eq!(failing_runtime_specifier(&valid_hydration_pattern), None);
    }
}
