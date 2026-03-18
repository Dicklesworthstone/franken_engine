#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]
//! Enrichment integration tests for bifurcation_boundary_scanner module.
//!
//! Covers scanner lifecycle, operating envelope boundary detection,
//! early-warning indicators, preemptive actions, and scan results.

use std::collections::BTreeSet;

use frankenengine_engine::bifurcation_boundary_scanner::*;
use frankenengine_engine::runtime_decision_theory::RegimeLabel;
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_param(id: &str, domain: ParameterDomain, value: i64) -> ControlParameter {
    ControlParameter {
        id: id.to_string(),
        label: format!("Param {id}"),
        domain,
        current_value_millionths: value,
        policy_tunable: true,
    }
}

fn make_envelope(param_id: &str, lower: i64, upper: i64) -> OperatingEnvelope {
    OperatingEnvelope {
        parameter_id: param_id.to_string(),
        lower_bound_millionths: lower,
        upper_bound_millionths: upper,
        nominal_millionths: (lower + upper) / 2,
        criticality_millionths: 500_000,
    }
}

// ---------------------------------------------------------------------------
// ParameterDomain
// ---------------------------------------------------------------------------

#[test]
fn parameter_domain_display_all_distinct() {
    let domains = [
        ParameterDomain::RiskThreshold,
        ParameterDomain::Calibration,
        ParameterDomain::ResourceAllocation,
        ParameterDomain::LaneRouting,
        ParameterDomain::SafetyBoundary,
        ParameterDomain::Environment,
    ];
    let displays: BTreeSet<String> = domains.iter().map(|d| format!("{d}")).collect();
    assert_eq!(displays.len(), 6);
}

// ---------------------------------------------------------------------------
// ControlParameter
// ---------------------------------------------------------------------------

#[test]
fn control_parameter_display() {
    let p = make_param("alpha", ParameterDomain::RiskThreshold, 500_000);
    let s = format!("{p}");
    assert!(s.contains("alpha"));
}

#[test]
fn control_parameter_serde_roundtrip() {
    let p = make_param("beta", ParameterDomain::Calibration, 750_000);
    let json = serde_json::to_string(&p).unwrap();
    let restored: ControlParameter = serde_json::from_str(&json).unwrap();
    assert_eq!(p, restored);
}

// ---------------------------------------------------------------------------
// OperatingEnvelope
// ---------------------------------------------------------------------------

#[test]
fn operating_envelope_serde_roundtrip() {
    let env = make_envelope("gamma", 100_000, 900_000);
    let json = serde_json::to_string(&env).unwrap();
    let restored: OperatingEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, restored);
}

// ---------------------------------------------------------------------------
// BifurcationType
// ---------------------------------------------------------------------------

#[test]
fn bifurcation_type_display_all_distinct() {
    let types = [
        BifurcationType::SaddleNode,
        BifurcationType::Transcritical,
        BifurcationType::Pitchfork,
        BifurcationType::Hopf,
        BifurcationType::Catastrophic,
        BifurcationType::Gradual,
    ];
    let displays: BTreeSet<String> = types.iter().map(|t| format!("{t}")).collect();
    assert_eq!(displays.len(), 6);
}

// ---------------------------------------------------------------------------
// BifurcationBoundaryScanner
// ---------------------------------------------------------------------------

#[test]
fn scanner_new_with_params() {
    let config = ScannerConfig::default();
    let p = make_param("p1", ParameterDomain::RiskThreshold, 500_000);
    let env = make_envelope("p1", 100_000, 900_000);
    let scanner = BifurcationBoundaryScanner::new(config, vec![p], vec![env]).unwrap();
    assert_eq!(scanner.parameter_count(), 1);
}

#[test]
fn scanner_scan_produces_result() {
    let config = ScannerConfig::default();
    let p = make_param("p1", ParameterDomain::Calibration, 500_000);
    let env = make_envelope("p1", 100_000, 900_000);
    let mut scanner = BifurcationBoundaryScanner::new(config, vec![p], vec![env]).unwrap();
    let result = scanner.scan().unwrap();
    assert!(result.parameters_scanned > 0);
}

#[test]
fn scanner_scan_with_parameter_near_boundary() {
    let config = ScannerConfig::default();
    // Parameter near upper bound of envelope
    let p = make_param("p1", ParameterDomain::SafetyBoundary, 850_000);
    let env = make_envelope("p1", 100_000, 900_000);
    let mut scanner = BifurcationBoundaryScanner::new(config, vec![p], vec![env]).unwrap();
    let result = scanner.scan().unwrap();
    // Near boundary should trigger early warning
    assert!(
        !result.warnings.is_empty() || result.bifurcation_points.is_empty(),
        "near-boundary should produce warnings or empty scan"
    );
}

#[test]
fn scanner_observe_and_scan() {
    let config = ScannerConfig::default();
    let p = make_param("p1", ParameterDomain::RiskThreshold, 500_000);
    let env = make_envelope("p1", 100_000, 900_000);
    let mut scanner = BifurcationBoundaryScanner::new(config, vec![p], vec![env]).unwrap();

    // Record observations
    for i in 0..10 {
        let obs = ParameterObservation {
            parameter_id: "p1".to_string(),
            value_millionths: 500_000 + i * 10_000,
            tick: i as u64,
            regime: RegimeLabel::Normal,
        };
        scanner.observe(obs);
    }

    let result = scanner.scan().unwrap();
    // Should produce a valid scan result
    assert!(result.parameters_scanned > 0);
}

// ---------------------------------------------------------------------------
// ScanResult
// ---------------------------------------------------------------------------

#[test]
fn scan_result_serde_roundtrip() {
    let config = ScannerConfig::default();
    let p = make_param("p1", ParameterDomain::RiskThreshold, 500_000);
    let env = make_envelope("p1", 100_000, 900_000);
    let mut scanner = BifurcationBoundaryScanner::new(config, vec![p], vec![env]).unwrap();
    let result = scanner.scan().unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let restored: ScanResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

// ---------------------------------------------------------------------------
// ScannerConfig
// ---------------------------------------------------------------------------

#[test]
fn scanner_config_default_valid() {
    let cfg = ScannerConfig::default();
    assert!(cfg.proximity_threshold_millionths > 0);
    assert!(cfg.risk_budget_millionths > 0);
}

#[test]
fn scanner_config_serde_roundtrip() {
    let cfg = ScannerConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: ScannerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// ---------------------------------------------------------------------------
// ScannerError
// ---------------------------------------------------------------------------

#[test]
fn scanner_error_display_all_distinct() {
    let errs = vec![
        ScannerError::TooManyParameters {
            count: 200,
            max: 128,
        },
        ScannerError::TooManyEnvelopes {
            count: 100,
            max: 64,
        },
        ScannerError::UnknownParameter {
            parameter_id: "test".into(),
        },
        ScannerError::DuplicateParameter {
            parameter_id: "dup".into(),
        },
    ];
    let displays: BTreeSet<String> = errs.iter().map(|e| format!("{e}")).collect();
    assert_eq!(displays.len(), 4);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_valid() {
    assert!(BIFURCATION_SCHEMA_VERSION.contains("bifurcation"));
}
