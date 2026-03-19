#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

//! Enrichment integration tests for `cold_start_aot_governance`.

use std::collections::BTreeSet;

use frankenengine_engine::cold_start_aot_governance::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn ev(path: StartupPathKind, baseline: u64, candidate: u64, samples: u64) -> ColdStartEvidence {
    ColdStartEvidence::new(path, baseline, candidate, samples, ep(10))
}

fn parity(kind: ParityCheckKind, passed: bool, div: u64) -> ParityResult {
    ParityResult::new(kind, passed, div, b"enrichment-evidence")
}

fn cfg() -> GovernanceConfig {
    GovernanceConfig::default()
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_schema_version_has_v1() {
    assert!(SCHEMA_VERSION.contains("v1"));
}

#[test]
fn constants_component_name() {
    assert_eq!(COMPONENT, "cold_start_aot_governance");
}

#[test]
fn constants_bead_id() {
    assert_eq!(BEAD_ID, "bd-1lsy.7.10.3");
}

#[test]
fn constants_policy_id() {
    assert_eq!(POLICY_ID, "RGC-610C");
}

#[test]
fn constants_fixed_one() {
    assert_eq!(FIXED_ONE, 1_000_000);
}

#[test]
fn constants_defaults_are_sensible() {
    assert!(DEFAULT_MIN_BENCHMARK_SAMPLES > 0);
    assert!(DEFAULT_MAX_REGRESSION_MILLIONTHS <= FIXED_ONE);
    assert!(DEFAULT_MAX_STALENESS_EPOCHS > 0);
    assert!(DEFAULT_MIN_SPEEDUP_THRESHOLD > 0);
    assert!(DEFAULT_MAX_DIVERGENCE > 0);
}

// ---------------------------------------------------------------------------
// StartupPathKind
// ---------------------------------------------------------------------------

#[test]
fn startup_path_kind_all_has_5() {
    assert_eq!(StartupPathKind::ALL.len(), 5);
}

#[test]
fn startup_path_kind_display_distinct() {
    let displays: BTreeSet<String> = StartupPathKind::ALL.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), StartupPathKind::ALL.len());
}

#[test]
fn startup_path_kind_as_str_matches_display() {
    for kind in StartupPathKind::ALL {
        assert_eq!(kind.as_str(), kind.to_string());
    }
}

#[test]
fn startup_path_kind_cold_start_not_optimised() {
    assert!(!StartupPathKind::ColdStart.is_optimised());
}

#[test]
fn startup_path_kind_non_cold_are_optimised() {
    for kind in &StartupPathKind::ALL[1..] {
        assert!(kind.is_optimised(), "{kind} should be optimised");
    }
}

#[test]
fn startup_path_kind_serde_roundtrip() {
    for kind in StartupPathKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: StartupPathKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ---------------------------------------------------------------------------
// BenchmarkVerdict
// ---------------------------------------------------------------------------

#[test]
fn benchmark_verdict_all_has_4() {
    assert_eq!(BenchmarkVerdict::ALL.len(), 4);
}

#[test]
fn benchmark_verdict_display_distinct() {
    let displays: BTreeSet<String> = BenchmarkVerdict::ALL
        .iter()
        .map(|v| v.to_string())
        .collect();
    assert_eq!(displays.len(), BenchmarkVerdict::ALL.len());
}

#[test]
fn benchmark_verdict_as_str_matches_display() {
    for v in BenchmarkVerdict::ALL {
        assert_eq!(v.as_str(), v.to_string());
    }
}

#[test]
fn benchmark_verdict_only_faster_supports_win() {
    assert!(BenchmarkVerdict::Faster.supports_win_claim());
    assert!(!BenchmarkVerdict::Slower.supports_win_claim());
    assert!(!BenchmarkVerdict::Equivalent.supports_win_claim());
    assert!(!BenchmarkVerdict::Inconclusive.supports_win_claim());
}

#[test]
fn benchmark_verdict_serde_roundtrip() {
    for v in BenchmarkVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: BenchmarkVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// ParityCheckKind
// ---------------------------------------------------------------------------

#[test]
fn parity_check_kind_all_has_3() {
    assert_eq!(ParityCheckKind::ALL.len(), 3);
}

#[test]
fn parity_check_kind_display_distinct() {
    let displays: BTreeSet<String> = ParityCheckKind::ALL.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), ParityCheckKind::ALL.len());
}

#[test]
fn parity_check_kind_serde_roundtrip() {
    for k in ParityCheckKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: ParityCheckKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ---------------------------------------------------------------------------
// ParityResult
// ---------------------------------------------------------------------------

#[test]
fn parity_result_new_sets_fields() {
    let p = parity(ParityCheckKind::SemanticParity, true, 100);
    assert_eq!(p.check_kind, ParityCheckKind::SemanticParity);
    assert!(p.passed);
    assert_eq!(p.divergence_millionths, 100);
}

#[test]
fn parity_result_display_contains_kind() {
    let p = parity(ParityCheckKind::BehavioralParity, false, 0);
    let display = format!("{p}");
    assert!(display.contains("behavioral_parity"));
}

#[test]
fn parity_result_serde_roundtrip() {
    let p = parity(ParityCheckKind::PerformanceParity, true, 500);
    let json = serde_json::to_string(&p).unwrap();
    let back: ParityResult = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn parity_result_deterministic_hash() {
    let p1 = ParityResult::new(ParityCheckKind::SemanticParity, true, 0, b"same-data");
    let p2 = ParityResult::new(ParityCheckKind::SemanticParity, true, 0, b"same-data");
    assert_eq!(p1.evidence_hash, p2.evidence_hash);
}

#[test]
fn parity_result_different_data_different_hash() {
    let p1 = ParityResult::new(ParityCheckKind::SemanticParity, true, 0, b"data-a");
    let p2 = ParityResult::new(ParityCheckKind::SemanticParity, true, 0, b"data-b");
    assert_ne!(p1.evidence_hash, p2.evidence_hash);
}

// ---------------------------------------------------------------------------
// RollbackTrigger
// ---------------------------------------------------------------------------

#[test]
fn rollback_trigger_all_has_5() {
    assert_eq!(RollbackTrigger::ALL.len(), 5);
}

#[test]
fn rollback_trigger_display_distinct() {
    let displays: BTreeSet<String> = RollbackTrigger::ALL.iter().map(|t| t.to_string()).collect();
    assert_eq!(displays.len(), RollbackTrigger::ALL.len());
}

#[test]
fn rollback_trigger_critical_checks() {
    assert!(RollbackTrigger::SemanticDrift.is_critical());
    assert!(RollbackTrigger::IntegrityFailure.is_critical());
    assert!(RollbackTrigger::PolicyViolation.is_critical());
    assert!(!RollbackTrigger::PerformanceRegression.is_critical());
    assert!(!RollbackTrigger::ObservabilityMismatch.is_critical());
}

#[test]
fn rollback_trigger_serde_roundtrip() {
    for t in RollbackTrigger::ALL {
        let json = serde_json::to_string(t).unwrap();
        let back: RollbackTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

// ---------------------------------------------------------------------------
// GovernanceConfig
// ---------------------------------------------------------------------------

#[test]
fn governance_config_default_matches_constants() {
    let c = cfg();
    assert_eq!(c.min_benchmark_samples, DEFAULT_MIN_BENCHMARK_SAMPLES);
    assert_eq!(
        c.max_regression_millionths,
        DEFAULT_MAX_REGRESSION_MILLIONTHS
    );
    assert_eq!(c.max_staleness_epochs, DEFAULT_MAX_STALENESS_EPOCHS);
    assert_eq!(c.min_speedup_threshold, DEFAULT_MIN_SPEEDUP_THRESHOLD);
    assert_eq!(c.max_divergence, DEFAULT_MAX_DIVERGENCE);
    assert!(c.require_semantic_parity);
    assert!(!c.require_observability_proof);
}

#[test]
fn governance_config_display() {
    let c = cfg();
    let display = format!("{c}");
    assert!(display.contains("GovernanceConfig"));
}

#[test]
fn governance_config_serde_roundtrip() {
    let c = cfg();
    let json = serde_json::to_string(&c).unwrap();
    let back: GovernanceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// GovernanceVerdict
// ---------------------------------------------------------------------------

#[test]
fn governance_verdict_approved_allows_publication() {
    let v = GovernanceVerdict::Approved;
    assert!(v.allows_publication());
    assert!(!v.requires_rollback());
}

#[test]
fn governance_verdict_blocked_does_not_allow() {
    let v = GovernanceVerdict::Blocked {
        reasons: vec!["reason".into()],
    };
    assert!(!v.allows_publication());
    assert!(!v.requires_rollback());
}

#[test]
fn governance_verdict_rollback_requires_rollback() {
    let v = GovernanceVerdict::Rollback {
        triggers: vec![RollbackTrigger::SemanticDrift],
    };
    assert!(!v.allows_publication());
    assert!(v.requires_rollback());
}

#[test]
fn governance_verdict_display_distinct() {
    let verdicts = [
        GovernanceVerdict::Approved,
        GovernanceVerdict::Blocked {
            reasons: vec!["r".into()],
        },
        GovernanceVerdict::Rollback {
            triggers: vec![RollbackTrigger::SemanticDrift],
        },
    ];
    let displays: BTreeSet<String> = verdicts.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), verdicts.len());
}

#[test]
fn governance_verdict_serde_roundtrip() {
    let verdicts = [
        GovernanceVerdict::Approved,
        GovernanceVerdict::Blocked {
            reasons: vec!["r".into()],
        },
        GovernanceVerdict::Rollback {
            triggers: vec![RollbackTrigger::IntegrityFailure],
        },
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: GovernanceVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// GovernanceError
// ---------------------------------------------------------------------------

#[test]
fn governance_error_as_str_distinct() {
    let errors = [
        GovernanceError::EmptyEvidence,
        GovernanceError::InvalidConfig {
            reason: "test".into(),
        },
        GovernanceError::StaleEvidence { age_epochs: 5 },
        GovernanceError::InsufficientSamples { have: 1, need: 30 },
    ];
    let strs: BTreeSet<&str> = errors.iter().map(|e| e.as_str()).collect();
    assert_eq!(strs.len(), errors.len());
}

#[test]
fn governance_error_display_nonempty() {
    let errors = [
        GovernanceError::EmptyEvidence,
        GovernanceError::InvalidConfig {
            reason: "bad".into(),
        },
        GovernanceError::StaleEvidence { age_epochs: 5 },
        GovernanceError::InsufficientSamples { have: 1, need: 30 },
    ];
    for e in &errors {
        assert!(!format!("{e}").is_empty());
    }
}

#[test]
fn governance_error_serde_roundtrip() {
    let e = GovernanceError::InsufficientSamples { have: 10, need: 30 };
    let json = serde_json::to_string(&e).unwrap();
    let back: GovernanceError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// ColdStartEvidence
// ---------------------------------------------------------------------------

#[test]
fn cold_start_evidence_speedup_positive_when_faster() {
    let e = ev(StartupPathKind::WarmCache, 1000, 500, 50);
    assert!(e.speedup_millionths > 0);
}

#[test]
fn cold_start_evidence_speedup_negative_when_slower() {
    let e = ev(StartupPathKind::WarmCache, 500, 1000, 50);
    assert!(e.speedup_millionths < 0);
}

#[test]
fn cold_start_evidence_speedup_zero_when_equal() {
    let e = ev(StartupPathKind::ColdStart, 1000, 1000, 50);
    assert_eq!(e.speedup_millionths, 0);
}

#[test]
fn cold_start_evidence_deterministic_hash() {
    let e1 = ev(StartupPathKind::AotRestored, 1000, 500, 50);
    let e2 = ev(StartupPathKind::AotRestored, 1000, 500, 50);
    assert_eq!(e1.evidence_hash, e2.evidence_hash);
}

#[test]
fn cold_start_evidence_different_inputs_different_hash() {
    let e1 = ev(StartupPathKind::AotRestored, 1000, 500, 50);
    let e2 = ev(StartupPathKind::AotRestored, 1000, 600, 50);
    assert_ne!(e1.evidence_hash, e2.evidence_hash);
}

#[test]
fn cold_start_evidence_verdict_faster() {
    let e = ev(StartupPathKind::WarmCache, 1000, 500, 50);
    assert_eq!(e.verdict(&cfg()), BenchmarkVerdict::Faster);
}

#[test]
fn cold_start_evidence_verdict_slower() {
    let e = ev(StartupPathKind::WarmCache, 500, 1000, 50);
    assert_eq!(e.verdict(&cfg()), BenchmarkVerdict::Slower);
}

#[test]
fn cold_start_evidence_verdict_equivalent() {
    let e = ev(StartupPathKind::WarmCache, 1000, 999, 50);
    assert_eq!(e.verdict(&cfg()), BenchmarkVerdict::Equivalent);
}

#[test]
fn cold_start_evidence_verdict_inconclusive_low_samples() {
    let e = ev(StartupPathKind::WarmCache, 1000, 500, 1);
    assert_eq!(e.verdict(&cfg()), BenchmarkVerdict::Inconclusive);
}

#[test]
fn cold_start_evidence_display() {
    let e = ev(StartupPathKind::PrewarmedPool, 1000, 500, 50);
    let display = format!("{e}");
    assert!(display.contains("ColdStartEvidence"));
    assert!(display.contains("prewarmed_pool"));
}

#[test]
fn cold_start_evidence_serde_roundtrip() {
    let e = ev(StartupPathKind::ZygoteFork, 2000, 1000, 100);
    let json = serde_json::to_string(&e).unwrap();
    let back: ColdStartEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn decision_receipt_deterministic_hash() {
    let r1 = DecisionReceipt::new(ep(10), GovernanceVerdict::Approved, vec![], vec![]);
    let r2 = DecisionReceipt::new(ep(10), GovernanceVerdict::Approved, vec![], vec![]);
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn decision_receipt_component_matches_constant() {
    let r = DecisionReceipt::new(ep(5), GovernanceVerdict::Approved, vec![], vec![]);
    assert_eq!(r.component, COMPONENT);
}

#[test]
fn decision_receipt_display() {
    let r = DecisionReceipt::new(ep(5), GovernanceVerdict::Approved, vec![], vec![]);
    let display = format!("{r}");
    assert!(display.contains("DecisionReceipt"));
}

#[test]
fn decision_receipt_serde_roundtrip() {
    let hash = ContentHash::compute(b"test-data");
    let r = DecisionReceipt::new(ep(5), GovernanceVerdict::Approved, vec![hash], vec![]);
    let json = serde_json::to_string(&r).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// compute_speedup
// ---------------------------------------------------------------------------

#[test]
fn compute_speedup_zero_baseline_returns_zero() {
    assert_eq!(compute_speedup(0, 100), 0);
}

#[test]
fn compute_speedup_half_latency_is_500k() {
    assert_eq!(compute_speedup(1000, 500), 500_000);
}

#[test]
fn compute_speedup_double_latency_is_negative() {
    assert_eq!(compute_speedup(500, 1000), -1_000_000);
}

// ---------------------------------------------------------------------------
// validate_config
// ---------------------------------------------------------------------------

#[test]
fn validate_config_default_ok() {
    assert!(validate_config(&cfg()).is_ok());
}

#[test]
fn validate_config_zero_samples_err() {
    let mut c = cfg();
    c.min_benchmark_samples = 0;
    assert!(validate_config(&c).is_err());
}

#[test]
fn validate_config_regression_too_large_err() {
    let mut c = cfg();
    c.max_regression_millionths = 2_000_000;
    assert!(validate_config(&c).is_err());
}

#[test]
fn validate_config_zero_staleness_err() {
    let mut c = cfg();
    c.max_staleness_epochs = 0;
    assert!(validate_config(&c).is_err());
}

#[test]
fn validate_config_speedup_threshold_too_large_err() {
    let mut c = cfg();
    c.min_speedup_threshold = 2_000_000;
    assert!(validate_config(&c).is_err());
}

#[test]
fn validate_config_divergence_too_large_err() {
    let mut c = cfg();
    c.max_divergence = 2_000_000;
    assert!(validate_config(&c).is_err());
}

// ---------------------------------------------------------------------------
// check_rollback_needed
// ---------------------------------------------------------------------------

#[test]
fn check_rollback_none_when_no_regression() {
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 500, 50)];
    let triggers = check_rollback_needed(&evidence, &cfg());
    assert!(triggers.is_empty());
}

#[test]
fn check_rollback_regression_triggers() {
    let evidence = vec![ev(StartupPathKind::WarmCache, 500, 1000, 50)];
    let triggers = check_rollback_needed(&evidence, &cfg());
    assert!(triggers.contains(&RollbackTrigger::PerformanceRegression));
}

// ---------------------------------------------------------------------------
// evaluate_cold_start
// ---------------------------------------------------------------------------

#[test]
fn evaluate_cold_start_approved_when_faster() {
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 500, 50)];
    let par = vec![parity(ParityCheckKind::SemanticParity, true, 0)];
    let verdict = evaluate_cold_start(&evidence, &par, &cfg()).unwrap();
    assert!(verdict.allows_publication());
}

#[test]
fn evaluate_cold_start_empty_evidence_err() {
    let result = evaluate_cold_start(&[], &[], &cfg());
    assert!(result.is_err());
}

#[test]
fn evaluate_cold_start_insufficient_samples_err() {
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 500, 1)];
    let result = evaluate_cold_start(&evidence, &[], &cfg());
    assert!(result.is_err());
}

#[test]
fn evaluate_cold_start_rollback_on_severe_regression() {
    let evidence = vec![ev(StartupPathKind::WarmCache, 500, 1000, 50)];
    let par = vec![parity(ParityCheckKind::SemanticParity, true, 0)];
    let verdict = evaluate_cold_start(&evidence, &par, &cfg()).unwrap();
    assert!(verdict.requires_rollback());
}

#[test]
fn evaluate_cold_start_blocked_when_no_speedup() {
    // Both baseline and candidate are the same, so no speedup
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 1000, 50)];
    let par = vec![parity(ParityCheckKind::SemanticParity, true, 0)];
    let verdict = evaluate_cold_start(&evidence, &par, &cfg()).unwrap();
    assert!(!verdict.allows_publication());
}

#[test]
fn evaluate_cold_start_blocked_missing_semantic_parity() {
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 500, 50)];
    let par: Vec<ParityResult> = vec![];
    let verdict = evaluate_cold_start(&evidence, &par, &cfg()).unwrap();
    assert!(!verdict.allows_publication());
}
