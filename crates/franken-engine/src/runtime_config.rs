//! Centralized runtime configuration for FrankenEngine.
//!
//! All formerly hard-coded constants are accessible through [`RuntimeConfig`],
//! loaded from an optional `franken-engine.toml` file.  When no configuration
//! file is provided, `RuntimeConfig::default()` produces values that are
//! byte-identical to the prior compile-time constants.
//!
//! Validation is performed at load time via [`RuntimeConfig::validate`], which
//! returns all constraint violations at once so operators can fix everything
//! in a single pass.
//!
//! See: bd-8ahge.1.1 — Define RuntimeConfig struct with nested section types

use std::path::Path;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Fixed-point constant (shared across all config sections)
// ---------------------------------------------------------------------------

/// One million — the unit for fixed-point millionths (1_000_000 = 1.0).
pub const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// ConfigError
// ---------------------------------------------------------------------------

/// Errors arising from configuration loading or validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigError {
    /// File I/O failure.
    IoError { detail: String },
    /// TOML parse failure.
    ParseError { detail: String },
    /// One or more validation constraints violated.
    ValidationFailed { errors: Vec<ConfigValidationError> },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError { detail } => write!(f, "config I/O error: {detail}"),
            Self::ParseError { detail } => write!(f, "config parse error: {detail}"),
            Self::ValidationFailed { errors } => {
                write!(f, "config validation failed ({} errors):", errors.len())?;
                for e in errors {
                    write!(f, "\n  - [{}.{}] {}", e.section, e.field, e.message)?;
                }
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ConfigValidationError
// ---------------------------------------------------------------------------

/// A single validation constraint violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigValidationError {
    /// Config section (e.g. "guardplane.priors").
    pub section: String,
    /// Field name (e.g. "benign_millionths").
    pub field: String,
    /// Human-readable description of the violation.
    pub message: String,
}

// ---------------------------------------------------------------------------
// ExecutionConfig
// ---------------------------------------------------------------------------

/// Execution budget and limit configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecutionConfig {
    /// Instruction budget for the deterministic profile.
    pub deterministic_budget: u64,
    /// Instruction budget for the throughput profile.
    pub throughput_budget: u64,
    /// Maximum register count for the deterministic profile.
    pub deterministic_max_registers: u32,
    /// Maximum register count for the throughput profile.
    pub throughput_max_registers: u32,
    /// Maximum call-stack depth.
    pub max_call_depth: usize,
    /// Maximum prototype-chain walk depth.
    pub max_prototype_chain_depth: u32,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            deterministic_budget: 100_000,
            throughput_budget: 1_000_000,
            deterministic_max_registers: 256,
            throughput_max_registers: 4096,
            max_call_depth: 256,
            max_prototype_chain_depth: 64,
        }
    }
}

// ---------------------------------------------------------------------------
// OrchestratorConfig
// ---------------------------------------------------------------------------

/// Configuration for the execution orchestrator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OrchestratorConfig {
    /// Adaptive router exploration rate (fixed-point millionths, 0..=1_000_000).
    pub adaptive_router_gamma_millionths: i64,
    /// CUSUM anomaly detection threshold (fixed-point millionths).
    pub stopping_cusum_threshold_millionths: i64,
    /// CUSUM reference value (fixed-point millionths).
    pub stopping_cusum_reference_millionths: i64,
    /// Budget (ms) for cell close / shutdown.
    pub cell_close_budget_ms: u64,
    /// Drain deadline in ticks.
    pub drain_deadline_ticks: u64,
    /// Maximum concurrent sagas.
    pub max_concurrent_sagas: usize,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            adaptive_router_gamma_millionths: 100_000,
            stopping_cusum_threshold_millionths: 5_000_000,
            stopping_cusum_reference_millionths: 500_000,
            cell_close_budget_ms: 10_000,
            drain_deadline_ticks: 10_000,
            max_concurrent_sagas: 4,
        }
    }
}

// ---------------------------------------------------------------------------
// BayesianPriorsConfig
// ---------------------------------------------------------------------------

/// Default Bayesian prior probabilities (fixed-point millionths, must sum to 1_000_000).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BayesianPriorsConfig {
    /// Prior probability of benign behavior (millionths).
    pub benign_millionths: i64,
    /// Prior probability of anomalous behavior (millionths).
    pub anomalous_millionths: i64,
    /// Prior probability of malicious behavior (millionths).
    pub malicious_millionths: i64,
    /// Prior probability of unknown behavior (millionths).
    pub unknown_millionths: i64,
    /// Minimum probability mass floor to prevent zero-probability states.
    pub floor_mass: i64,
}

impl Default for BayesianPriorsConfig {
    fn default() -> Self {
        Self {
            benign_millionths: 850_000,
            anomalous_millionths: 40_000,
            malicious_millionths: 10_000,
            unknown_millionths: 100_000,
            floor_mass: 100,
        }
    }
}

// ---------------------------------------------------------------------------
// DecisionThresholdsConfig
// ---------------------------------------------------------------------------

/// Confidence and regime-shift thresholds for containment decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DecisionThresholdsConfig {
    /// Tail confidence level (millionths, e.g. 900_000 = 90%).
    pub tail_confidence_millionths: i64,
    /// Elevated p-value threshold (millionths).
    pub elevated_pvalue_millionths: i64,
    /// Critical p-value threshold (millionths, must be <= elevated).
    pub critical_pvalue_millionths: i64,
    /// Elevated regime-shift sigma (millionths, e.g. 2_500_000 = 2.5 sigma).
    pub elevated_regime_shift_millionths: i64,
    /// Critical regime-shift sigma (millionths, must be >= elevated).
    pub critical_regime_shift_millionths: i64,
}

impl Default for DecisionThresholdsConfig {
    fn default() -> Self {
        Self {
            tail_confidence_millionths: 900_000,
            elevated_pvalue_millionths: 100_000,
            critical_pvalue_millionths: 50_000,
            elevated_regime_shift_millionths: 2_500_000,
            critical_regime_shift_millionths: 4_000_000,
        }
    }
}

// ---------------------------------------------------------------------------
// ContainmentConfig
// ---------------------------------------------------------------------------

/// Timeouts for containment actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ContainmentConfig {
    /// Grace period for cooperative shutdown (nanoseconds).
    pub grace_period_ns: u64,
    /// Challenge response timeout (nanoseconds).
    pub challenge_timeout_ns: u64,
}

impl Default for ContainmentConfig {
    fn default() -> Self {
        Self {
            grace_period_ns: 5_000_000_000,
            challenge_timeout_ns: 10_000_000_000,
        }
    }
}

// ---------------------------------------------------------------------------
// GuardplaneConfig
// ---------------------------------------------------------------------------

/// Combined guardplane configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuardplaneConfig {
    /// Bayesian prior probabilities.
    pub priors: BayesianPriorsConfig,
    /// Decision thresholds.
    pub thresholds: DecisionThresholdsConfig,
    /// Containment timeouts.
    pub containment: ContainmentConfig,
}

// ---------------------------------------------------------------------------
// GovernanceConfig
// ---------------------------------------------------------------------------

/// Governance thresholds for coverage claims and hole tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GovernanceConfig {
    /// Maximum persistent holes allowed in a surface.
    pub max_persistent_holes: u64,
    /// Minimum coverage for supremacy claims (millionths).
    pub min_supremacy_coverage_millionths: u64,
    /// Minimum coverage for parity claims (millionths).
    pub min_parity_coverage_millionths: u64,
    /// Maximum structural holes (zero = zero tolerance).
    pub max_structural_holes: u64,
    /// Coverage ratchet decay rate per epoch (millionths).
    pub ratchet_decay_millionths: u64,
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            max_persistent_holes: 5,
            min_supremacy_coverage_millionths: 900_000,
            min_parity_coverage_millionths: 800_000,
            max_structural_holes: 0,
            ratchet_decay_millionths: 50_000,
        }
    }
}

// ---------------------------------------------------------------------------
// GatesConfig
// ---------------------------------------------------------------------------

/// Release gate and workload verification thresholds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GatesConfig {
    /// Minimum test pass rate for release (millionths).
    pub min_pass_rate_millionths: u64,
    /// Maximum allowed regression (millionths).
    pub max_regression_millionths: u64,
    /// Maximum unresolved issues for release.
    pub max_unresolved: u64,
    /// Workload health minimum pass rate (millionths).
    pub workload_min_pass_rate_millionths: u64,
    /// Maximum mutation contract violations.
    pub max_mutation_violations: usize,
    /// Escalation observability cost budget (millionths of per-run budget).
    pub escalation_cost_budget_millionths: u64,
}

impl Default for GatesConfig {
    fn default() -> Self {
        Self {
            min_pass_rate_millionths: 1_000_000,
            max_regression_millionths: 50_000,
            max_unresolved: 0,
            workload_min_pass_rate_millionths: 950_000,
            max_mutation_violations: 0,
            escalation_cost_budget_millionths: 100_000,
        }
    }
}

// ---------------------------------------------------------------------------
// OptimizationConfig
// ---------------------------------------------------------------------------

/// Optimization engine limits and thresholds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OptimizationConfig {
    /// Maximum rules per rewrite pack.
    pub max_rules_per_pack: usize,
    /// Maximum interference tracking entries.
    pub max_interference_entries: usize,
    /// Maximum fields for scalar replacement.
    pub max_scalar_fields: usize,
    /// Maximum decomposition nesting depth.
    pub max_decomposition_depth: u32,
    /// Maximum transforms per scope.
    pub max_transforms_per_scope: usize,
    /// Minimum confidence for optimization (millionths).
    pub min_confidence_millionths: u64,
}

impl Default for OptimizationConfig {
    fn default() -> Self {
        Self {
            max_rules_per_pack: 256,
            max_interference_entries: 1024,
            max_scalar_fields: 64,
            max_decomposition_depth: 4,
            max_transforms_per_scope: 128,
            min_confidence_millionths: 600_000,
        }
    }
}

// ---------------------------------------------------------------------------
// ExtensionHostConfig
// ---------------------------------------------------------------------------

/// Extension manifest field limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExtensionHostConfig {
    /// Maximum extension name length.
    pub max_name_len: usize,
    /// Maximum version string length.
    pub max_version_len: usize,
    /// Maximum entrypoint path length.
    pub max_entrypoint_len: usize,
    /// Maximum trust chain reference length.
    pub max_trust_chain_ref_len: usize,
}

impl Default for ExtensionHostConfig {
    fn default() -> Self {
        Self {
            max_name_len: 128,
            max_version_len: 64,
            max_entrypoint_len: 1024,
            max_trust_chain_ref_len: 256,
        }
    }
}

// ---------------------------------------------------------------------------
// RuntimeConfig — top-level configuration
// ---------------------------------------------------------------------------

/// Top-level runtime configuration.
///
/// All sections use `#[serde(default)]` so that partial TOML files work:
/// any missing section or field falls back to the compiled default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeConfig {
    /// Execution budgets and limits.
    pub execution: ExecutionConfig,
    /// Orchestrator parameters.
    pub orchestrator: OrchestratorConfig,
    /// Guardplane (Bayesian priors, decision thresholds, containment timeouts).
    pub guardplane: GuardplaneConfig,
    /// Governance coverage and hole thresholds.
    pub governance: GovernanceConfig,
    /// Release gate and workload verification thresholds.
    pub gates: GatesConfig,
    /// Optimization engine limits.
    pub optimization: OptimizationConfig,
    /// Extension host manifest limits.
    pub extension_host: ExtensionHostConfig,
}

impl RuntimeConfig {
    /// Load configuration from a TOML file.
    ///
    /// If the file does not exist, returns `Ok(Self::default())`.
    /// If the file exists but is invalid, returns an error.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(e) => {
                return Err(ConfigError::IoError {
                    detail: e.to_string(),
                });
            }
        };

        let config: Self = toml::from_str(&contents).map_err(|e| ConfigError::ParseError {
            detail: e.to_string(),
        })?;

        config.validate()?;
        Ok(config)
    }

    /// Load from a TOML string (useful for testing and embedded configs).
    pub fn from_toml(toml_str: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(toml_str).map_err(|e| ConfigError::ParseError {
            detail: e.to_string(),
        })?;

        config.validate()?;
        Ok(config)
    }

    /// Validate all configuration constraints.
    ///
    /// Returns all violations at once so operators can fix everything
    /// in a single pass.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errors = Vec::new();

        // -- Execution --
        self.validate_execution(&mut errors);
        // -- Orchestrator --
        self.validate_orchestrator(&mut errors);
        // -- Guardplane --
        self.validate_guardplane(&mut errors);
        // -- Governance --
        self.validate_governance(&mut errors);
        // -- Gates --
        self.validate_gates(&mut errors);
        // -- Optimization --
        self.validate_optimization(&mut errors);
        // -- Extension host --
        self.validate_extension_host(&mut errors);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::ValidationFailed { errors })
        }
    }

    fn validate_execution(&self, errors: &mut Vec<ConfigValidationError>) {
        let s = "execution";
        if self.execution.deterministic_budget == 0 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "deterministic_budget".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if self.execution.throughput_budget == 0 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "throughput_budget".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if self.execution.deterministic_max_registers == 0 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "deterministic_max_registers".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if self.execution.throughput_max_registers == 0 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "throughput_max_registers".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if self.execution.max_call_depth == 0 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "max_call_depth".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if self.execution.max_call_depth > 10_000 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "max_call_depth".to_string(),
                message: "must be <= 10_000 (sanity bound)".to_string(),
            });
        }
        if self.execution.max_prototype_chain_depth == 0 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "max_prototype_chain_depth".to_string(),
                message: "must be > 0".to_string(),
            });
        }
    }

    fn validate_orchestrator(&self, errors: &mut Vec<ConfigValidationError>) {
        let s = "orchestrator";
        let o = &self.orchestrator;
        if o.adaptive_router_gamma_millionths < 0 || o.adaptive_router_gamma_millionths > MILLION {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "adaptive_router_gamma_millionths".to_string(),
                message: format!("must be in [0, {MILLION}]"),
            });
        }
        if o.stopping_cusum_threshold_millionths <= 0 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "stopping_cusum_threshold_millionths".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if o.stopping_cusum_reference_millionths <= 0 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "stopping_cusum_reference_millionths".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if o.cell_close_budget_ms == 0 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "cell_close_budget_ms".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if o.max_concurrent_sagas == 0 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "max_concurrent_sagas".to_string(),
                message: "must be > 0".to_string(),
            });
        }
    }

    fn validate_guardplane(&self, errors: &mut Vec<ConfigValidationError>) {
        let p = &self.guardplane.priors;
        let ps = "guardplane.priors";

        // Floor mass bounds.
        if p.floor_mass <= 0 {
            errors.push(ConfigValidationError {
                section: ps.to_string(),
                field: "floor_mass".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if p.floor_mass >= 10_000 {
            errors.push(ConfigValidationError {
                section: ps.to_string(),
                field: "floor_mass".to_string(),
                message: "must be < 10_000".to_string(),
            });
        }

        // Each prior >= floor_mass.
        for (name, val) in [
            ("benign_millionths", p.benign_millionths),
            ("anomalous_millionths", p.anomalous_millionths),
            ("malicious_millionths", p.malicious_millionths),
            ("unknown_millionths", p.unknown_millionths),
        ] {
            if val < p.floor_mass {
                errors.push(ConfigValidationError {
                    section: ps.to_string(),
                    field: name.to_string(),
                    message: format!("must be >= floor_mass ({})", p.floor_mass),
                });
            }
        }

        // Sum must equal MILLION.
        let sum = p.benign_millionths
            + p.anomalous_millionths
            + p.malicious_millionths
            + p.unknown_millionths;
        if sum != MILLION {
            errors.push(ConfigValidationError {
                section: ps.to_string(),
                field: "(sum)".to_string(),
                message: format!("priors must sum to {MILLION}, got {sum}"),
            });
        }

        // Thresholds.
        let t = &self.guardplane.thresholds;
        let ts = "guardplane.thresholds";

        if t.tail_confidence_millionths <= 0 || t.tail_confidence_millionths > MILLION {
            errors.push(ConfigValidationError {
                section: ts.to_string(),
                field: "tail_confidence_millionths".to_string(),
                message: format!("must be in (0, {MILLION}]"),
            });
        }
        if t.elevated_pvalue_millionths <= 0 || t.elevated_pvalue_millionths > MILLION {
            errors.push(ConfigValidationError {
                section: ts.to_string(),
                field: "elevated_pvalue_millionths".to_string(),
                message: format!("must be in (0, {MILLION}]"),
            });
        }
        if t.critical_pvalue_millionths <= 0 || t.critical_pvalue_millionths > MILLION {
            errors.push(ConfigValidationError {
                section: ts.to_string(),
                field: "critical_pvalue_millionths".to_string(),
                message: format!("must be in (0, {MILLION}]"),
            });
        }
        if t.critical_pvalue_millionths > t.elevated_pvalue_millionths {
            errors.push(ConfigValidationError {
                section: ts.to_string(),
                field: "critical_pvalue_millionths".to_string(),
                message: "must be <= elevated_pvalue_millionths".to_string(),
            });
        }
        if t.elevated_regime_shift_millionths <= 0 {
            errors.push(ConfigValidationError {
                section: ts.to_string(),
                field: "elevated_regime_shift_millionths".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if t.critical_regime_shift_millionths <= 0 {
            errors.push(ConfigValidationError {
                section: ts.to_string(),
                field: "critical_regime_shift_millionths".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if t.critical_regime_shift_millionths < t.elevated_regime_shift_millionths {
            errors.push(ConfigValidationError {
                section: ts.to_string(),
                field: "critical_regime_shift_millionths".to_string(),
                message: "must be >= elevated_regime_shift_millionths".to_string(),
            });
        }

        // Containment timeouts.
        let c = &self.guardplane.containment;
        let cs = "guardplane.containment";

        if c.grace_period_ns == 0 {
            errors.push(ConfigValidationError {
                section: cs.to_string(),
                field: "grace_period_ns".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if c.challenge_timeout_ns == 0 {
            errors.push(ConfigValidationError {
                section: cs.to_string(),
                field: "challenge_timeout_ns".to_string(),
                message: "must be > 0".to_string(),
            });
        }
    }

    fn validate_governance(&self, errors: &mut Vec<ConfigValidationError>) {
        let s = "governance";
        let g = &self.governance;
        if g.min_supremacy_coverage_millionths > 1_000_000 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "min_supremacy_coverage_millionths".to_string(),
                message: "must be <= 1_000_000".to_string(),
            });
        }
        if g.min_parity_coverage_millionths > 1_000_000 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "min_parity_coverage_millionths".to_string(),
                message: "must be <= 1_000_000".to_string(),
            });
        }
        if g.min_supremacy_coverage_millionths < g.min_parity_coverage_millionths {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "min_supremacy_coverage_millionths".to_string(),
                message: "must be >= min_parity_coverage_millionths".to_string(),
            });
        }
        if g.ratchet_decay_millionths > 1_000_000 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "ratchet_decay_millionths".to_string(),
                message: "must be <= 1_000_000".to_string(),
            });
        }
    }

    fn validate_gates(&self, errors: &mut Vec<ConfigValidationError>) {
        let s = "gates";
        let g = &self.gates;
        if g.min_pass_rate_millionths > 1_000_000 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "min_pass_rate_millionths".to_string(),
                message: "must be <= 1_000_000".to_string(),
            });
        }
        if g.max_regression_millionths > 1_000_000 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "max_regression_millionths".to_string(),
                message: "must be <= 1_000_000".to_string(),
            });
        }
        if g.workload_min_pass_rate_millionths > 1_000_000 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "workload_min_pass_rate_millionths".to_string(),
                message: "must be <= 1_000_000".to_string(),
            });
        }
        if g.escalation_cost_budget_millionths > 1_000_000 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "escalation_cost_budget_millionths".to_string(),
                message: "must be <= 1_000_000".to_string(),
            });
        }
    }

    fn validate_optimization(&self, errors: &mut Vec<ConfigValidationError>) {
        let s = "optimization";
        let o = &self.optimization;
        if o.max_rules_per_pack == 0 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "max_rules_per_pack".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if o.max_interference_entries == 0 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "max_interference_entries".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if o.max_scalar_fields == 0 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "max_scalar_fields".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if o.max_decomposition_depth == 0 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "max_decomposition_depth".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if o.max_transforms_per_scope == 0 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "max_transforms_per_scope".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if o.min_confidence_millionths > 1_000_000 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "min_confidence_millionths".to_string(),
                message: "must be <= 1_000_000".to_string(),
            });
        }
    }

    fn validate_extension_host(&self, errors: &mut Vec<ConfigValidationError>) {
        let s = "extension_host";
        let e = &self.extension_host;
        if e.max_name_len == 0 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "max_name_len".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if e.max_version_len == 0 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "max_version_len".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if e.max_entrypoint_len == 0 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "max_entrypoint_len".to_string(),
                message: "must be > 0".to_string(),
            });
        }
        if e.max_trust_chain_ref_len == 0 {
            errors.push(ConfigValidationError {
                section: s.to_string(),
                field: "max_trust_chain_ref_len".to_string(),
                message: "must be > 0".to_string(),
            });
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Default equivalence
    // -----------------------------------------------------------------------

    #[test]
    fn default_passes_validation() {
        RuntimeConfig::default().validate().unwrap();
    }

    #[test]
    fn default_execution_matches_prior_constants() {
        let e = ExecutionConfig::default();
        assert_eq!(e.deterministic_budget, 100_000);
        assert_eq!(e.throughput_budget, 1_000_000);
        assert_eq!(e.deterministic_max_registers, 256);
        assert_eq!(e.throughput_max_registers, 4096);
        assert_eq!(e.max_call_depth, 256);
        assert_eq!(e.max_prototype_chain_depth, 64);
    }

    #[test]
    fn default_orchestrator_matches_prior_constants() {
        let o = OrchestratorConfig::default();
        assert_eq!(o.adaptive_router_gamma_millionths, 100_000);
        assert_eq!(o.stopping_cusum_threshold_millionths, 5_000_000);
        assert_eq!(o.stopping_cusum_reference_millionths, 500_000);
        assert_eq!(o.cell_close_budget_ms, 10_000);
        assert_eq!(o.drain_deadline_ticks, 10_000);
        assert_eq!(o.max_concurrent_sagas, 4);
    }

    #[test]
    fn default_priors_match_prior_constants() {
        let p = BayesianPriorsConfig::default();
        assert_eq!(p.benign_millionths, 850_000);
        assert_eq!(p.anomalous_millionths, 40_000);
        assert_eq!(p.malicious_millionths, 10_000);
        assert_eq!(p.unknown_millionths, 100_000);
        assert_eq!(p.floor_mass, 100);
    }

    #[test]
    fn default_priors_sum_to_million() {
        let p = BayesianPriorsConfig::default();
        let sum = p.benign_millionths
            + p.anomalous_millionths
            + p.malicious_millionths
            + p.unknown_millionths;
        assert_eq!(sum, MILLION);
    }

    #[test]
    fn default_thresholds_match_prior_constants() {
        let t = DecisionThresholdsConfig::default();
        assert_eq!(t.tail_confidence_millionths, 900_000);
        assert_eq!(t.elevated_pvalue_millionths, 100_000);
        assert_eq!(t.critical_pvalue_millionths, 50_000);
        assert_eq!(t.elevated_regime_shift_millionths, 2_500_000);
        assert_eq!(t.critical_regime_shift_millionths, 4_000_000);
    }

    #[test]
    fn default_containment_matches_prior_constants() {
        let c = ContainmentConfig::default();
        assert_eq!(c.grace_period_ns, 5_000_000_000);
        assert_eq!(c.challenge_timeout_ns, 10_000_000_000);
    }

    #[test]
    fn default_governance_matches_prior_constants() {
        let g = GovernanceConfig::default();
        assert_eq!(g.max_persistent_holes, 5);
        assert_eq!(g.min_supremacy_coverage_millionths, 900_000);
        assert_eq!(g.min_parity_coverage_millionths, 800_000);
        assert_eq!(g.max_structural_holes, 0);
        assert_eq!(g.ratchet_decay_millionths, 50_000);
    }

    #[test]
    fn default_gates_matches_prior_constants() {
        let g = GatesConfig::default();
        assert_eq!(g.min_pass_rate_millionths, 1_000_000);
        assert_eq!(g.max_regression_millionths, 50_000);
        assert_eq!(g.max_unresolved, 0);
        assert_eq!(g.workload_min_pass_rate_millionths, 950_000);
        assert_eq!(g.max_mutation_violations, 0);
        assert_eq!(g.escalation_cost_budget_millionths, 100_000);
    }

    #[test]
    fn default_optimization_matches_prior_constants() {
        let o = OptimizationConfig::default();
        assert_eq!(o.max_rules_per_pack, 256);
        assert_eq!(o.max_interference_entries, 1024);
        assert_eq!(o.max_scalar_fields, 64);
        assert_eq!(o.max_decomposition_depth, 4);
        assert_eq!(o.max_transforms_per_scope, 128);
        assert_eq!(o.min_confidence_millionths, 600_000);
    }

    #[test]
    fn default_extension_host_matches_prior_constants() {
        let e = ExtensionHostConfig::default();
        assert_eq!(e.max_name_len, 128);
        assert_eq!(e.max_version_len, 64);
        assert_eq!(e.max_entrypoint_len, 1024);
        assert_eq!(e.max_trust_chain_ref_len, 256);
    }

    // -----------------------------------------------------------------------
    // Serde round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn toml_roundtrip_default() {
        let config = RuntimeConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        let restored: RuntimeConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config, restored);
    }

    #[test]
    fn json_roundtrip_default() {
        let config = RuntimeConfig::default();
        let json_str = serde_json::to_string(&config).unwrap();
        let restored: RuntimeConfig = serde_json::from_str(&json_str).unwrap();
        assert_eq!(config, restored);
    }

    // -----------------------------------------------------------------------
    // Partial TOML (missing sections use defaults)
    // -----------------------------------------------------------------------

    #[test]
    fn empty_toml_produces_default() {
        let config = RuntimeConfig::from_toml("").unwrap();
        assert_eq!(config, RuntimeConfig::default());
    }

    #[test]
    fn partial_toml_fills_defaults() {
        let toml_str = r#"
[execution]
deterministic_budget = 50000
"#;
        let config = RuntimeConfig::from_toml(toml_str).unwrap();
        assert_eq!(config.execution.deterministic_budget, 50_000);
        // All other fields should be defaults.
        assert_eq!(config.execution.throughput_budget, 1_000_000);
        assert_eq!(config.orchestrator, OrchestratorConfig::default());
        assert_eq!(config.guardplane, GuardplaneConfig::default());
    }

    #[test]
    fn partial_nested_toml_fills_defaults() {
        let toml_str = r#"
[guardplane.containment]
grace_period_ns = 1000000000
"#;
        let config = RuntimeConfig::from_toml(toml_str).unwrap();
        assert_eq!(config.guardplane.containment.grace_period_ns, 1_000_000_000);
        assert_eq!(
            config.guardplane.containment.challenge_timeout_ns,
            10_000_000_000
        );
        // Priors should still be defaults.
        assert_eq!(config.guardplane.priors, BayesianPriorsConfig::default());
    }

    // -----------------------------------------------------------------------
    // Validation: priors
    // -----------------------------------------------------------------------

    #[test]
    fn validation_rejects_priors_wrong_sum() {
        let mut config = RuntimeConfig::default();
        config.guardplane.priors.benign_millionths = 800_000; // sum = 950_000
        let err = config.validate().unwrap_err();
        if let ConfigError::ValidationFailed { errors } = &err {
            assert!(errors.iter().any(|e| e.field == "(sum)"));
        } else {
            panic!("expected ValidationFailed, got {err:?}");
        }
    }

    #[test]
    fn validation_rejects_prior_below_floor() {
        let mut config = RuntimeConfig::default();
        config.guardplane.priors.malicious_millionths = 50; // below floor_mass=100
        config.guardplane.priors.benign_millionths = 850_050; // keep sum = MILLION
        let err = config.validate().unwrap_err();
        if let ConfigError::ValidationFailed { errors } = &err {
            assert!(errors.iter().any(|e| e.field == "malicious_millionths"));
        } else {
            panic!("expected ValidationFailed");
        }
    }

    #[test]
    fn validation_rejects_zero_floor_mass() {
        let mut config = RuntimeConfig::default();
        config.guardplane.priors.floor_mass = 0;
        let err = config.validate().unwrap_err();
        if let ConfigError::ValidationFailed { errors } = &err {
            assert!(errors.iter().any(|e| e.field == "floor_mass"));
        } else {
            panic!("expected ValidationFailed");
        }
    }

    #[test]
    fn validation_rejects_floor_mass_too_large() {
        let mut config = RuntimeConfig::default();
        config.guardplane.priors.floor_mass = 10_000;
        let err = config.validate().unwrap_err();
        if let ConfigError::ValidationFailed { errors } = &err {
            assert!(errors.iter().any(|e| e.field == "floor_mass"));
        } else {
            panic!("expected ValidationFailed");
        }
    }

    // -----------------------------------------------------------------------
    // Validation: thresholds
    // -----------------------------------------------------------------------

    #[test]
    fn validation_rejects_critical_pvalue_greater_than_elevated() {
        let mut config = RuntimeConfig::default();
        config.guardplane.thresholds.critical_pvalue_millionths = 200_000;
        config.guardplane.thresholds.elevated_pvalue_millionths = 100_000;
        let err = config.validate().unwrap_err();
        if let ConfigError::ValidationFailed { errors } = &err {
            assert!(
                errors
                    .iter()
                    .any(|e| e.field == "critical_pvalue_millionths")
            );
        } else {
            panic!("expected ValidationFailed");
        }
    }

    #[test]
    fn validation_rejects_critical_sigma_less_than_elevated() {
        let mut config = RuntimeConfig::default();
        config
            .guardplane
            .thresholds
            .critical_regime_shift_millionths = 1_000_000;
        config
            .guardplane
            .thresholds
            .elevated_regime_shift_millionths = 2_000_000;
        let err = config.validate().unwrap_err();
        if let ConfigError::ValidationFailed { errors } = &err {
            assert!(
                errors
                    .iter()
                    .any(|e| e.field == "critical_regime_shift_millionths")
            );
        } else {
            panic!("expected ValidationFailed");
        }
    }

    // -----------------------------------------------------------------------
    // Validation: execution
    // -----------------------------------------------------------------------

    #[test]
    fn validation_rejects_zero_budget() {
        let mut config = RuntimeConfig::default();
        config.execution.deterministic_budget = 0;
        let err = config.validate().unwrap_err();
        if let ConfigError::ValidationFailed { errors } = &err {
            assert!(errors.iter().any(|e| e.field == "deterministic_budget"));
        } else {
            panic!("expected ValidationFailed");
        }
    }

    #[test]
    fn validation_rejects_excessive_call_depth() {
        let mut config = RuntimeConfig::default();
        config.execution.max_call_depth = 20_000;
        let err = config.validate().unwrap_err();
        if let ConfigError::ValidationFailed { errors } = &err {
            assert!(errors.iter().any(|e| e.field == "max_call_depth"));
        } else {
            panic!("expected ValidationFailed");
        }
    }

    // -----------------------------------------------------------------------
    // Validation: orchestrator
    // -----------------------------------------------------------------------

    #[test]
    fn validation_rejects_negative_gamma() {
        let mut config = RuntimeConfig::default();
        config.orchestrator.adaptive_router_gamma_millionths = -1;
        let err = config.validate().unwrap_err();
        if let ConfigError::ValidationFailed { errors } = &err {
            assert!(
                errors
                    .iter()
                    .any(|e| e.field == "adaptive_router_gamma_millionths")
            );
        } else {
            panic!("expected ValidationFailed");
        }
    }

    #[test]
    fn validation_rejects_zero_concurrent_sagas() {
        let mut config = RuntimeConfig::default();
        config.orchestrator.max_concurrent_sagas = 0;
        let err = config.validate().unwrap_err();
        if let ConfigError::ValidationFailed { errors } = &err {
            assert!(errors.iter().any(|e| e.field == "max_concurrent_sagas"));
        } else {
            panic!("expected ValidationFailed");
        }
    }

    // -----------------------------------------------------------------------
    // Validation: governance
    // -----------------------------------------------------------------------

    #[test]
    fn validation_rejects_supremacy_below_parity() {
        let mut config = RuntimeConfig::default();
        config.governance.min_supremacy_coverage_millionths = 700_000;
        config.governance.min_parity_coverage_millionths = 800_000;
        let err = config.validate().unwrap_err();
        if let ConfigError::ValidationFailed { errors } = &err {
            assert!(
                errors
                    .iter()
                    .any(|e| e.field == "min_supremacy_coverage_millionths")
            );
        } else {
            panic!("expected ValidationFailed");
        }
    }

    // -----------------------------------------------------------------------
    // Validation: multi-error batch reporting
    // -----------------------------------------------------------------------

    #[test]
    fn validation_reports_all_errors_at_once() {
        let mut config = RuntimeConfig::default();
        config.execution.deterministic_budget = 0;
        config.execution.throughput_budget = 0;
        config.orchestrator.max_concurrent_sagas = 0;
        let err = config.validate().unwrap_err();
        if let ConfigError::ValidationFailed { errors } = &err {
            assert!(
                errors.len() >= 3,
                "expected >= 3 errors, got {}",
                errors.len()
            );
        } else {
            panic!("expected ValidationFailed");
        }
    }

    // -----------------------------------------------------------------------
    // Load from missing file
    // -----------------------------------------------------------------------

    #[test]
    fn load_missing_file_returns_default() {
        let config = RuntimeConfig::load(Path::new("/nonexistent/path/config.toml")).unwrap();
        assert_eq!(config, RuntimeConfig::default());
    }

    // -----------------------------------------------------------------------
    // Display for ConfigError
    // -----------------------------------------------------------------------

    #[test]
    fn config_error_display() {
        let err = ConfigError::ValidationFailed {
            errors: vec![ConfigValidationError {
                section: "execution".to_string(),
                field: "deterministic_budget".to_string(),
                message: "must be > 0".to_string(),
            }],
        };
        let s = err.to_string();
        assert!(s.contains("1 errors"));
        assert!(s.contains("execution.deterministic_budget"));
    }

    // -----------------------------------------------------------------------
    // Custom valid config via TOML
    // -----------------------------------------------------------------------

    #[test]
    fn custom_priors_via_toml() {
        let toml_str = r#"
[guardplane.priors]
benign_millionths = 700000
anomalous_millionths = 150000
malicious_millionths = 50000
unknown_millionths = 100000
floor_mass = 100
"#;
        let config = RuntimeConfig::from_toml(toml_str).unwrap();
        assert_eq!(config.guardplane.priors.benign_millionths, 700_000);
        assert_eq!(config.guardplane.priors.anomalous_millionths, 150_000);
        assert_eq!(config.guardplane.priors.malicious_millionths, 50_000);
    }
}
