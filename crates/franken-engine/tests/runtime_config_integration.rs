//! Integration tests for the `runtime_config` module.
//!
//! Validates TOML loading, default fallback, validation constraints,
//! serde roundtrips, and cross-section consistency.

use frankenengine_engine::runtime_config::*;

// ---------------------------------------------------------------------------
// Default construction
// ---------------------------------------------------------------------------

#[test]
fn default_config_validates_successfully() {
    let config = RuntimeConfig::default();
    config.validate().expect("default config must validate");
}

#[test]
fn default_execution_config_values() {
    let cfg = ExecutionConfig::default();
    assert_eq!(cfg.deterministic_budget, 100_000);
    assert_eq!(cfg.throughput_budget, 1_000_000);
    assert_eq!(cfg.deterministic_max_registers, 256);
    assert_eq!(cfg.throughput_max_registers, 4096);
    assert_eq!(cfg.max_call_depth, 256);
    assert_eq!(cfg.max_prototype_chain_depth, 64);
}

#[test]
fn default_orchestrator_config_values() {
    let cfg = OrchestratorConfig::default();
    assert_eq!(cfg.adaptive_router_gamma_millionths, 100_000);
    assert_eq!(cfg.cell_close_budget_ms, 10_000);
    assert_eq!(cfg.drain_deadline_ticks, 10_000);
    assert_eq!(cfg.max_concurrent_sagas, 4);
}

#[test]
fn default_bayesian_priors_sum_to_million() {
    let priors = BayesianPriorsConfig::default();
    let sum = priors.benign_millionths
        + priors.anomalous_millionths
        + priors.malicious_millionths
        + priors.unknown_millionths;
    assert_eq!(sum, MILLION);
}

#[test]
fn default_decision_thresholds_ordering() {
    let t = DecisionThresholdsConfig::default();
    assert!(t.critical_pvalue_millionths <= t.elevated_pvalue_millionths);
    assert!(t.critical_regime_shift_millionths >= t.elevated_regime_shift_millionths);
    assert!(t.critical_cvar_ratio_millionths >= t.elevated_cvar_ratio_millionths);
}

#[test]
fn default_containment_config_positive() {
    let c = ContainmentConfig::default();
    assert!(c.grace_period_ns > 0);
    assert!(c.challenge_timeout_ns > 0);
}

#[test]
fn default_governance_config_values() {
    let g = GovernanceConfig::default();
    assert!(g.min_supremacy_coverage_millionths > 0);
    assert!(g.min_parity_coverage_millionths > 0);
    assert_eq!(g.max_structural_holes, 0);
}

#[test]
fn default_gates_config_pass_rate() {
    let g = GatesConfig::default();
    assert_eq!(g.min_pass_rate_millionths, 1_000_000);
    assert_eq!(g.max_unresolved, 0);
    assert_eq!(g.max_mutation_violations, 0);
}

#[test]
fn default_optimization_config_values() {
    let o = OptimizationConfig::default();
    assert!(o.max_rules_per_pack > 0);
    assert!(o.max_scalar_fields > 0);
    assert!(o.min_confidence_millionths > 0);
}

// ---------------------------------------------------------------------------
// TOML loading
// ---------------------------------------------------------------------------

#[test]
fn from_toml_empty_string_returns_defaults() {
    let config = RuntimeConfig::from_toml("").expect("empty TOML should parse");
    assert_eq!(config, RuntimeConfig::default());
}

#[test]
fn from_toml_partial_override() {
    let toml = r#"
[execution]
deterministic_budget = 200000
"#;
    let config = RuntimeConfig::from_toml(toml).expect("partial TOML should parse");
    assert_eq!(config.execution.deterministic_budget, 200_000);
    // Other fields should be defaults
    assert_eq!(
        config.execution.throughput_budget,
        ExecutionConfig::default().throughput_budget
    );
}

#[test]
fn from_toml_all_sections() {
    let toml = r#"
[execution]
deterministic_budget = 50000
throughput_budget = 500000
deterministic_max_registers = 128
throughput_max_registers = 2048
max_call_depth = 128
max_prototype_chain_depth = 32

[orchestrator]
adaptive_router_gamma_millionths = 50000
cell_close_budget_ms = 5000
drain_deadline_ticks = 5000
max_concurrent_sagas = 8

[guardplane.priors]
benign_millionths = 800000
anomalous_millionths = 80000
malicious_millionths = 20000
unknown_millionths = 100000
floor_mass = 200

[guardplane.thresholds]
tail_confidence_millionths = 950000
elevated_pvalue_millionths = 100000
critical_pvalue_millionths = 50000
elevated_regime_shift_millionths = 2500000
critical_regime_shift_millionths = 4000000

[guardplane.containment]
grace_period_ns = 3000000000
challenge_timeout_ns = 8000000000
"#;
    let config = RuntimeConfig::from_toml(toml).expect("all sections should parse");
    assert_eq!(config.execution.deterministic_budget, 50_000);
    assert_eq!(config.orchestrator.max_concurrent_sagas, 8);
    assert_eq!(config.guardplane.priors.benign_millionths, 800_000);
    assert_eq!(
        config.guardplane.thresholds.tail_confidence_millionths,
        950_000
    );
    assert_eq!(config.guardplane.containment.grace_period_ns, 3_000_000_000);
}

#[test]
fn from_toml_invalid_syntax_returns_parse_error() {
    let bad = "not valid toml [[[";
    let err = RuntimeConfig::from_toml(bad).unwrap_err();
    assert!(matches!(err, ConfigError::ParseError { .. }));
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

#[test]
fn validation_rejects_zero_execution_budget() {
    let mut config = RuntimeConfig::default();
    config.execution.deterministic_budget = 0;
    let err = config.validate().unwrap_err();
    if let ConfigError::ValidationFailed { errors } = err {
        assert!(errors.iter().any(|e| e.field == "deterministic_budget"));
    } else {
        panic!("expected ValidationFailed");
    }
}

#[test]
fn validation_rejects_zero_registers() {
    let mut config = RuntimeConfig::default();
    config.execution.deterministic_max_registers = 0;
    config.execution.throughput_max_registers = 0;
    let err = config.validate().unwrap_err();
    if let ConfigError::ValidationFailed { errors } = err {
        assert!(errors.len() >= 2);
    } else {
        panic!("expected ValidationFailed");
    }
}

#[test]
fn validation_rejects_priors_not_summing_to_million() {
    let mut config = RuntimeConfig::default();
    config.guardplane.priors.benign_millionths = 500_000;
    // Sum is now 500_000 + 40_000 + 10_000 + 100_000 = 650_000 ≠ 1_000_000
    let err = config.validate().unwrap_err();
    if let ConfigError::ValidationFailed { errors } = err {
        assert!(
            errors
                .iter()
                .any(|e| e.section.contains("guardplane") || e.section.contains("priors"))
        );
    } else {
        panic!("expected ValidationFailed");
    }
}

#[test]
fn validation_collects_multiple_errors() {
    let mut config = RuntimeConfig::default();
    config.execution.deterministic_budget = 0;
    config.execution.throughput_budget = 0;
    config.execution.deterministic_max_registers = 0;
    let err = config.validate().unwrap_err();
    if let ConfigError::ValidationFailed { errors } = err {
        assert!(
            errors.len() >= 3,
            "should collect 3+ errors, got {}",
            errors.len()
        );
    } else {
        panic!("expected ValidationFailed");
    }
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn runtime_config_json_serde_roundtrip() {
    let config = RuntimeConfig::default();
    let json = serde_json::to_string_pretty(&config).unwrap();
    let decoded: RuntimeConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, decoded);
}

#[test]
fn execution_config_json_serde_roundtrip() {
    let cfg = ExecutionConfig {
        deterministic_budget: 42,
        throughput_budget: 84,
        deterministic_max_registers: 16,
        throughput_max_registers: 32,
        max_call_depth: 8,
        max_prototype_chain_depth: 4,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let decoded: ExecutionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, decoded);
}

#[test]
fn guardplane_config_json_serde_roundtrip() {
    let cfg = GuardplaneConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let decoded: GuardplaneConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, decoded);
}

// ---------------------------------------------------------------------------
// TOML roundtrip (default -> serialize -> parse)
// ---------------------------------------------------------------------------

#[test]
fn runtime_config_toml_roundtrip() {
    let original = RuntimeConfig::default();
    let toml_str = toml::to_string(&original).unwrap();
    let roundtripped = RuntimeConfig::from_toml(&toml_str).unwrap();
    assert_eq!(original, roundtripped);
}

// ---------------------------------------------------------------------------
// Error display
// ---------------------------------------------------------------------------

#[test]
fn config_error_display_io_error() {
    let err = ConfigError::IoError {
        detail: "permission denied".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("I/O"));
    assert!(msg.contains("permission denied"));
}

#[test]
fn config_error_display_parse_error() {
    let err = ConfigError::ParseError {
        detail: "unexpected token".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("parse"));
    assert!(msg.contains("unexpected token"));
}

#[test]
fn config_error_display_validation_failed() {
    let err = ConfigError::ValidationFailed {
        errors: vec![ConfigValidationError {
            section: "execution".into(),
            field: "budget".into(),
            message: "must be > 0".into(),
        }],
    };
    let msg = err.to_string();
    assert!(msg.contains("validation"));
    assert!(msg.contains("execution"));
    assert!(msg.contains("budget"));
}

// ---------------------------------------------------------------------------
// File loading
// ---------------------------------------------------------------------------

#[test]
fn load_nonexistent_file_returns_defaults() {
    let path = std::path::Path::new("/tmp/franken_engine_test_nonexistent_config.toml");
    let config = RuntimeConfig::load(path).expect("missing file should return defaults");
    assert_eq!(config, RuntimeConfig::default());
}

// ---------------------------------------------------------------------------
// Cross-section consistency
// ---------------------------------------------------------------------------

#[test]
fn throughput_budget_exceeds_deterministic() {
    let cfg = RuntimeConfig::default();
    assert!(cfg.execution.throughput_budget > cfg.execution.deterministic_budget);
}

#[test]
fn throughput_registers_exceed_deterministic() {
    let cfg = RuntimeConfig::default();
    assert!(cfg.execution.throughput_max_registers > cfg.execution.deterministic_max_registers);
}

#[test]
fn million_constant_is_correct() {
    assert_eq!(MILLION, 1_000_000);
}
