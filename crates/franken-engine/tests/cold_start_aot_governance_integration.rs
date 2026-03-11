#![forbid(unsafe_code)]

//! Integration tests for `cold_start_aot_governance` (RGC-610C, bd-1lsy.7.10.3).

use frankenengine_engine::cold_start_aot_governance::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn ev(path: StartupPathKind, baseline: u64, candidate: u64, samples: u64) -> ColdStartEvidence {
    ColdStartEvidence::new(path, baseline, candidate, samples, ep(10))
}

fn parity(kind: ParityCheckKind, passed: bool, div: u64) -> ParityResult {
    ParityResult::new(kind, passed, div, b"integration-evidence")
}

fn cfg() -> GovernanceConfig {
    GovernanceConfig::default()
}

// ============================================================================
// Constants
// ============================================================================

#[test]
fn test_schema_version_contains_name() {
    assert!(SCHEMA_VERSION.contains("cold-start-aot-governance"));
}

#[test]
fn test_schema_version_contains_v1() {
    assert!(SCHEMA_VERSION.contains("v1"));
}

#[test]
fn test_component_name() {
    assert_eq!(COMPONENT, "cold_start_aot_governance");
}

#[test]
fn test_bead_id() {
    assert_eq!(BEAD_ID, "bd-1lsy.7.10.3");
}

#[test]
fn test_policy_id() {
    assert_eq!(POLICY_ID, "RGC-610C");
}

#[test]
fn test_fixed_one_value() {
    assert_eq!(FIXED_ONE, 1_000_000);
}

#[test]
fn test_default_constants_sensible() {
    assert!(DEFAULT_MIN_BENCHMARK_SAMPLES > 0);
    assert!(DEFAULT_MAX_REGRESSION_MILLIONTHS > 0);
    assert!(DEFAULT_MAX_REGRESSION_MILLIONTHS <= FIXED_ONE);
    assert!(DEFAULT_MAX_STALENESS_EPOCHS > 0);
    assert!(DEFAULT_MIN_SPEEDUP_THRESHOLD > 0);
    assert!(DEFAULT_MAX_DIVERGENCE > 0);
}

// ============================================================================
// StartupPathKind
// ============================================================================

#[test]
fn test_startup_path_kind_all_length() {
    assert_eq!(StartupPathKind::ALL.len(), 5);
}

#[test]
fn test_startup_path_kind_display_all() {
    let expected = [
        "cold_start",
        "warm_cache",
        "aot_restored",
        "zygote_fork",
        "prewarmed_pool",
    ];
    for (kind, exp) in StartupPathKind::ALL.iter().zip(expected.iter()) {
        assert_eq!(kind.to_string(), *exp);
    }
}

#[test]
fn test_startup_path_kind_as_str_matches_display() {
    for kind in StartupPathKind::ALL {
        assert_eq!(kind.as_str(), kind.to_string());
    }
}

#[test]
fn test_startup_path_kind_is_optimised() {
    assert!(!StartupPathKind::ColdStart.is_optimised());
    for kind in &StartupPathKind::ALL[1..] {
        assert!(kind.is_optimised(), "{kind} should be optimised");
    }
}

#[test]
fn test_startup_path_kind_serde_roundtrip() {
    for kind in StartupPathKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: StartupPathKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn test_startup_path_kind_ord() {
    assert!(StartupPathKind::ColdStart < StartupPathKind::WarmCache);
    assert!(StartupPathKind::WarmCache < StartupPathKind::AotRestored);
}

// ============================================================================
// BenchmarkVerdict
// ============================================================================

#[test]
fn test_benchmark_verdict_all_length() {
    assert_eq!(BenchmarkVerdict::ALL.len(), 4);
}

#[test]
fn test_benchmark_verdict_display() {
    assert_eq!(BenchmarkVerdict::Faster.to_string(), "faster");
    assert_eq!(BenchmarkVerdict::Slower.to_string(), "slower");
    assert_eq!(BenchmarkVerdict::Equivalent.to_string(), "equivalent");
    assert_eq!(BenchmarkVerdict::Inconclusive.to_string(), "inconclusive");
}

#[test]
fn test_benchmark_verdict_supports_win_claim() {
    assert!(BenchmarkVerdict::Faster.supports_win_claim());
    assert!(!BenchmarkVerdict::Slower.supports_win_claim());
    assert!(!BenchmarkVerdict::Equivalent.supports_win_claim());
    assert!(!BenchmarkVerdict::Inconclusive.supports_win_claim());
}

#[test]
fn test_benchmark_verdict_serde_roundtrip() {
    for v in BenchmarkVerdict::ALL {
        let j = serde_json::to_string(v).unwrap();
        let back: BenchmarkVerdict = serde_json::from_str(&j).unwrap();
        assert_eq!(*v, back);
    }
}

// ============================================================================
// ParityCheckKind
// ============================================================================

#[test]
fn test_parity_check_kind_all_length() {
    assert_eq!(ParityCheckKind::ALL.len(), 3);
}

#[test]
fn test_parity_check_kind_display() {
    assert_eq!(
        ParityCheckKind::SemanticParity.to_string(),
        "semantic_parity"
    );
    assert_eq!(
        ParityCheckKind::BehavioralParity.to_string(),
        "behavioral_parity"
    );
    assert_eq!(
        ParityCheckKind::PerformanceParity.to_string(),
        "performance_parity"
    );
}

#[test]
fn test_parity_check_kind_serde_roundtrip() {
    for k in ParityCheckKind::ALL {
        let j = serde_json::to_string(k).unwrap();
        let back: ParityCheckKind = serde_json::from_str(&j).unwrap();
        assert_eq!(*k, back);
    }
}

// ============================================================================
// ParityResult
// ============================================================================

#[test]
fn test_parity_result_passing() {
    let p = parity(ParityCheckKind::SemanticParity, true, 0);
    assert!(p.passed);
    assert_eq!(p.divergence_millionths, 0);
    assert_eq!(p.check_kind, ParityCheckKind::SemanticParity);
}

#[test]
fn test_parity_result_failing() {
    let p = parity(ParityCheckKind::BehavioralParity, false, 500_000);
    assert!(!p.passed);
    assert_eq!(p.divergence_millionths, 500_000);
}

#[test]
fn test_parity_result_display() {
    let p = parity(ParityCheckKind::PerformanceParity, true, 1000);
    let s = p.to_string();
    assert!(s.contains("ParityResult"));
    assert!(s.contains("performance_parity"));
    assert!(s.contains("true"));
}

#[test]
fn test_parity_result_hash_deterministic() {
    let p1 = parity(ParityCheckKind::SemanticParity, true, 0);
    let p2 = parity(ParityCheckKind::SemanticParity, true, 0);
    assert_eq!(p1.evidence_hash, p2.evidence_hash);
}

#[test]
fn test_parity_result_hash_varies_on_kind() {
    let p1 = parity(ParityCheckKind::SemanticParity, true, 0);
    let p2 = parity(ParityCheckKind::BehavioralParity, true, 0);
    assert_ne!(p1.evidence_hash, p2.evidence_hash);
}

#[test]
fn test_parity_result_hash_varies_on_passed() {
    let p1 = parity(ParityCheckKind::SemanticParity, true, 0);
    let p2 = parity(ParityCheckKind::SemanticParity, false, 0);
    assert_ne!(p1.evidence_hash, p2.evidence_hash);
}

// ============================================================================
// RollbackTrigger
// ============================================================================

#[test]
fn test_rollback_trigger_all_length() {
    assert_eq!(RollbackTrigger::ALL.len(), 5);
}

#[test]
fn test_rollback_trigger_display_all() {
    let expected = [
        "semantic_drift",
        "performance_regression",
        "integrity_failure",
        "policy_violation",
        "observability_mismatch",
    ];
    for (t, e) in RollbackTrigger::ALL.iter().zip(expected.iter()) {
        assert_eq!(t.to_string(), *e);
    }
}

#[test]
fn test_rollback_trigger_is_critical() {
    let critical = [
        RollbackTrigger::SemanticDrift,
        RollbackTrigger::IntegrityFailure,
        RollbackTrigger::PolicyViolation,
    ];
    let non_critical = [
        RollbackTrigger::PerformanceRegression,
        RollbackTrigger::ObservabilityMismatch,
    ];
    for t in &critical {
        assert!(t.is_critical(), "{t} should be critical");
    }
    for t in &non_critical {
        assert!(!t.is_critical(), "{t} should not be critical");
    }
}

#[test]
fn test_rollback_trigger_serde_roundtrip() {
    for t in RollbackTrigger::ALL {
        let j = serde_json::to_string(t).unwrap();
        let back: RollbackTrigger = serde_json::from_str(&j).unwrap();
        assert_eq!(*t, back);
    }
}

// ============================================================================
// GovernanceConfig
// ============================================================================

#[test]
fn test_config_default_values() {
    let c = cfg();
    assert_eq!(c.min_benchmark_samples, DEFAULT_MIN_BENCHMARK_SAMPLES);
    assert_eq!(
        c.max_regression_millionths,
        DEFAULT_MAX_REGRESSION_MILLIONTHS
    );
    assert!(c.require_semantic_parity);
    assert!(!c.require_observability_proof);
    assert_eq!(c.max_staleness_epochs, DEFAULT_MAX_STALENESS_EPOCHS);
    assert_eq!(c.min_speedup_threshold, DEFAULT_MIN_SPEEDUP_THRESHOLD);
    assert_eq!(c.max_divergence, DEFAULT_MAX_DIVERGENCE);
}

#[test]
fn test_config_display() {
    let c = cfg();
    let s = c.to_string();
    assert!(s.contains("GovernanceConfig"));
    assert!(s.contains("min_samples="));
}

#[test]
fn test_config_serde_roundtrip() {
    let c = cfg();
    let j = serde_json::to_string(&c).unwrap();
    let back: GovernanceConfig = serde_json::from_str(&j).unwrap();
    assert_eq!(c, back);
}

// ============================================================================
// validate_config
// ============================================================================

#[test]
fn test_validate_config_default_ok() {
    assert!(validate_config(&cfg()).is_ok());
}

#[test]
fn test_validate_config_zero_samples() {
    let mut c = cfg();
    c.min_benchmark_samples = 0;
    assert!(validate_config(&c).is_err());
}

#[test]
fn test_validate_config_regression_above_one() {
    let mut c = cfg();
    c.max_regression_millionths = FIXED_ONE + 1;
    assert!(validate_config(&c).is_err());
}

#[test]
fn test_validate_config_zero_staleness() {
    let mut c = cfg();
    c.max_staleness_epochs = 0;
    assert!(validate_config(&c).is_err());
}

#[test]
fn test_validate_config_speedup_above_one() {
    let mut c = cfg();
    c.min_speedup_threshold = FIXED_ONE + 1;
    assert!(validate_config(&c).is_err());
}

#[test]
fn test_validate_config_divergence_above_one() {
    let mut c = cfg();
    c.max_divergence = FIXED_ONE + 1;
    assert!(validate_config(&c).is_err());
}

#[test]
fn test_validate_config_boundary_regression_at_one() {
    let mut c = cfg();
    c.max_regression_millionths = FIXED_ONE;
    assert!(validate_config(&c).is_ok());
}

// ============================================================================
// compute_speedup
// ============================================================================

#[test]
fn test_compute_speedup_faster() {
    assert_eq!(compute_speedup(100, 80), 200_000); // 20% faster
}

#[test]
fn test_compute_speedup_slower() {
    assert_eq!(compute_speedup(100, 120), -200_000); // 20% slower
}

#[test]
fn test_compute_speedup_equal() {
    assert_eq!(compute_speedup(100, 100), 0);
}

#[test]
fn test_compute_speedup_zero_baseline() {
    assert_eq!(compute_speedup(0, 100), 0);
}

#[test]
fn test_compute_speedup_zero_candidate() {
    assert_eq!(compute_speedup(100, 0), FIXED_ONE as i64); // 100% faster
}

#[test]
fn test_compute_speedup_half() {
    assert_eq!(compute_speedup(1000, 500), 500_000); // 50% faster
}

#[test]
fn test_compute_speedup_double() {
    assert_eq!(compute_speedup(1000, 2000), -1_000_000); // 100% slower
}

#[test]
fn test_compute_speedup_large_values() {
    // Should not overflow using i128 internally.
    let s = compute_speedup(u64::MAX / 2, u64::MAX / 4);
    assert!(s > 0);
}

// ============================================================================
// ColdStartEvidence
// ============================================================================

#[test]
fn test_evidence_speedup_computed() {
    let e = ev(StartupPathKind::AotRestored, 200, 150, 50);
    assert_eq!(e.speedup_millionths, 250_000); // 25% faster
}

#[test]
fn test_evidence_verdict_faster() {
    let c = cfg();
    let e = ev(StartupPathKind::WarmCache, 1000, 800, 50);
    assert_eq!(e.verdict(&c), BenchmarkVerdict::Faster);
}

#[test]
fn test_evidence_verdict_slower() {
    let c = cfg();
    let e = ev(StartupPathKind::WarmCache, 1000, 1200, 50);
    assert_eq!(e.verdict(&c), BenchmarkVerdict::Slower);
}

#[test]
fn test_evidence_verdict_equivalent() {
    let c = cfg();
    let e = ev(StartupPathKind::WarmCache, 10000, 9995, 50);
    assert_eq!(e.verdict(&c), BenchmarkVerdict::Equivalent);
}

#[test]
fn test_evidence_verdict_inconclusive_few_samples() {
    let c = cfg();
    let e = ev(StartupPathKind::WarmCache, 1000, 800, 5);
    assert_eq!(e.verdict(&c), BenchmarkVerdict::Inconclusive);
}

#[test]
fn test_evidence_hash_deterministic() {
    let e1 = ev(StartupPathKind::AotRestored, 100, 80, 50);
    let e2 = ev(StartupPathKind::AotRestored, 100, 80, 50);
    assert_eq!(e1.evidence_hash, e2.evidence_hash);
}

#[test]
fn test_evidence_hash_varies_path() {
    let e1 = ev(StartupPathKind::AotRestored, 100, 80, 50);
    let e2 = ev(StartupPathKind::WarmCache, 100, 80, 50);
    assert_ne!(e1.evidence_hash, e2.evidence_hash);
}

#[test]
fn test_evidence_hash_varies_baseline() {
    let e1 = ev(StartupPathKind::WarmCache, 100, 80, 50);
    let e2 = ev(StartupPathKind::WarmCache, 200, 80, 50);
    assert_ne!(e1.evidence_hash, e2.evidence_hash);
}

#[test]
fn test_evidence_display() {
    let e = ev(StartupPathKind::ZygoteFork, 100, 80, 50);
    let s = e.to_string();
    assert!(s.contains("ColdStartEvidence"));
    assert!(s.contains("zygote_fork"));
    assert!(s.contains("100ns"));
}

#[test]
fn test_evidence_serde_roundtrip() {
    let e = ev(StartupPathKind::PrewarmedPool, 500, 300, 100);
    let j = serde_json::to_string(&e).unwrap();
    let back: ColdStartEvidence = serde_json::from_str(&j).unwrap();
    assert_eq!(e, back);
}

// ============================================================================
// GovernanceVerdict
// ============================================================================

#[test]
fn test_verdict_approved_allows_publication() {
    let v = GovernanceVerdict::Approved;
    assert!(v.allows_publication());
    assert!(!v.requires_rollback());
}

#[test]
fn test_verdict_blocked_blocks_publication() {
    let v = GovernanceVerdict::Blocked {
        reasons: vec!["bad".into()],
    };
    assert!(!v.allows_publication());
    assert!(!v.requires_rollback());
}

#[test]
fn test_verdict_rollback_blocks_and_rollbacks() {
    let v = GovernanceVerdict::Rollback {
        triggers: vec![RollbackTrigger::SemanticDrift],
    };
    assert!(!v.allows_publication());
    assert!(v.requires_rollback());
}

#[test]
fn test_verdict_display_approved() {
    assert_eq!(GovernanceVerdict::Approved.to_string(), "approved");
}

#[test]
fn test_verdict_display_blocked() {
    let v = GovernanceVerdict::Blocked {
        reasons: vec!["a".into(), "b".into()],
    };
    assert!(v.to_string().contains("blocked"));
    assert!(v.to_string().contains("2"));
}

#[test]
fn test_verdict_display_rollback() {
    let v = GovernanceVerdict::Rollback {
        triggers: vec![RollbackTrigger::IntegrityFailure],
    };
    assert!(v.to_string().contains("rollback"));
}

#[test]
fn test_verdict_serde_roundtrip() {
    let verdicts = vec![
        GovernanceVerdict::Approved,
        GovernanceVerdict::Blocked {
            reasons: vec!["r1".into(), "r2".into()],
        },
        GovernanceVerdict::Rollback {
            triggers: vec![
                RollbackTrigger::PolicyViolation,
                RollbackTrigger::PerformanceRegression,
            ],
        },
    ];
    for v in &verdicts {
        let j = serde_json::to_string(v).unwrap();
        let back: GovernanceVerdict = serde_json::from_str(&j).unwrap();
        assert_eq!(*v, back);
    }
}

// ============================================================================
// GovernanceError
// ============================================================================

#[test]
fn test_error_empty_evidence_display() {
    assert_eq!(
        GovernanceError::EmptyEvidence.to_string(),
        "no evidence provided"
    );
}

#[test]
fn test_error_invalid_config_display() {
    let e = GovernanceError::InvalidConfig {
        reason: "bad thing".into(),
    };
    assert!(e.to_string().contains("bad thing"));
}

#[test]
fn test_error_stale_evidence_display() {
    let e = GovernanceError::StaleEvidence { age_epochs: 42 };
    assert!(e.to_string().contains("42"));
}

#[test]
fn test_error_insufficient_samples_display() {
    let e = GovernanceError::InsufficientSamples { have: 5, need: 30 };
    let s = e.to_string();
    assert!(s.contains("5"));
    assert!(s.contains("30"));
}

#[test]
fn test_error_as_str() {
    assert_eq!(GovernanceError::EmptyEvidence.as_str(), "empty_evidence");
    assert_eq!(
        GovernanceError::InvalidConfig { reason: "x".into() }.as_str(),
        "invalid_config"
    );
    assert_eq!(
        GovernanceError::StaleEvidence { age_epochs: 1 }.as_str(),
        "stale_evidence"
    );
    assert_eq!(
        GovernanceError::InsufficientSamples { have: 1, need: 2 }.as_str(),
        "insufficient_samples"
    );
}

#[test]
fn test_error_serde_roundtrip() {
    let errors = vec![
        GovernanceError::EmptyEvidence,
        GovernanceError::InvalidConfig {
            reason: "test".into(),
        },
        GovernanceError::StaleEvidence { age_epochs: 5 },
        GovernanceError::InsufficientSamples { have: 3, need: 30 },
    ];
    for e in &errors {
        let j = serde_json::to_string(e).unwrap();
        let back: GovernanceError = serde_json::from_str(&j).unwrap();
        assert_eq!(*e, back);
    }
}

// ============================================================================
// check_rollback_needed
// ============================================================================

#[test]
fn test_no_rollback_faster_evidence() {
    let c = cfg();
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 800, 50)];
    assert!(check_rollback_needed(&evidence, &c).is_empty());
}

#[test]
fn test_rollback_on_performance_regression() {
    let c = cfg();
    // 60% regression, way beyond 5% threshold
    let evidence = vec![ev(StartupPathKind::WarmCache, 100, 160, 50)];
    let triggers = check_rollback_needed(&evidence, &c);
    assert!(triggers.contains(&RollbackTrigger::PerformanceRegression));
}

#[test]
fn test_no_rollback_small_regression() {
    let c = cfg();
    // 1% regression, within 5% threshold
    let evidence = vec![ev(StartupPathKind::WarmCache, 10000, 10100, 50)];
    assert!(check_rollback_needed(&evidence, &c).is_empty());
}

#[test]
fn test_rollback_observability_mismatch() {
    let mut c = cfg();
    c.require_observability_proof = true;
    let evidence = vec![ColdStartEvidence::new(
        StartupPathKind::AotRestored,
        100,
        80,
        0,
        ep(10),
    )];
    let triggers = check_rollback_needed(&evidence, &c);
    assert!(triggers.contains(&RollbackTrigger::ObservabilityMismatch));
}

#[test]
fn test_no_observability_rollback_cold_start() {
    let mut c = cfg();
    c.require_observability_proof = true;
    // ColdStart is not optimised, so zero samples don't trigger mismatch.
    let evidence = vec![ColdStartEvidence::new(
        StartupPathKind::ColdStart,
        100,
        80,
        0,
        ep(10),
    )];
    let triggers = check_rollback_needed(&evidence, &c);
    assert!(!triggers.contains(&RollbackTrigger::ObservabilityMismatch));
}

#[test]
fn test_rollback_empty_evidence() {
    let c = cfg();
    assert!(check_rollback_needed(&[], &c).is_empty());
}

// ============================================================================
// evaluate_cold_start
// ============================================================================

#[test]
fn test_evaluate_approved_happy_path() {
    let c = cfg();
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 800, 50)];
    let par = vec![parity(ParityCheckKind::SemanticParity, true, 0)];
    let verdict = evaluate_cold_start(&evidence, &par, &c).unwrap();
    assert_eq!(verdict, GovernanceVerdict::Approved);
}

#[test]
fn test_evaluate_blocked_no_speedup() {
    let c = cfg();
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 1000, 50)];
    let par = vec![parity(ParityCheckKind::SemanticParity, true, 0)];
    let verdict = evaluate_cold_start(&evidence, &par, &c).unwrap();
    match verdict {
        GovernanceVerdict::Blocked { reasons } => {
            assert!(reasons.iter().any(|r| r.contains("no evidence of speedup")));
        }
        other => panic!("expected Blocked, got {other}"),
    }
}

#[test]
fn test_evaluate_blocked_slower_sample() {
    let c = cfg();
    let ev_fast = ev(StartupPathKind::WarmCache, 1000, 800, 50);
    let ev_slow = ev(StartupPathKind::AotRestored, 1000, 1200, 50);
    let par = vec![parity(ParityCheckKind::SemanticParity, true, 0)];
    let verdict = evaluate_cold_start(&[ev_fast, ev_slow], &par, &c).unwrap();
    match verdict {
        GovernanceVerdict::Blocked { reasons } => {
            assert!(reasons.iter().any(|r| r.contains("slower")));
        }
        other => panic!("expected Blocked, got {other}"),
    }
}

#[test]
fn test_evaluate_blocked_semantic_parity_failed() {
    let c = cfg();
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 800, 50)];
    let par = vec![parity(ParityCheckKind::SemanticParity, false, 100_000)];
    let verdict = evaluate_cold_start(&evidence, &par, &c).unwrap();
    match verdict {
        GovernanceVerdict::Blocked { reasons } => {
            assert!(reasons.iter().any(|r| r.contains("semantic parity")));
        }
        other => panic!("expected Blocked, got {other}"),
    }
}

#[test]
fn test_evaluate_blocked_semantic_parity_missing() {
    let c = cfg();
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 800, 50)];
    // No semantic parity in the list.
    let par = vec![parity(ParityCheckKind::PerformanceParity, true, 0)];
    let verdict = evaluate_cold_start(&evidence, &par, &c).unwrap();
    match verdict {
        GovernanceVerdict::Blocked { reasons } => {
            assert!(
                reasons
                    .iter()
                    .any(|r| r.contains("semantic parity evidence missing"))
            );
        }
        other => panic!("expected Blocked, got {other}"),
    }
}

#[test]
fn test_evaluate_empty_evidence_error() {
    let c = cfg();
    let err = evaluate_cold_start(&[], &[], &c).unwrap_err();
    assert_eq!(err, GovernanceError::EmptyEvidence);
}

#[test]
fn test_evaluate_insufficient_samples_error() {
    let c = cfg();
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 800, 5)];
    let err = evaluate_cold_start(&evidence, &[], &c).unwrap_err();
    match err {
        GovernanceError::InsufficientSamples { have, need } => {
            assert_eq!(have, 5);
            assert_eq!(need, 30);
        }
        other => panic!("expected InsufficientSamples, got {other}"),
    }
}

#[test]
fn test_evaluate_invalid_config_error() {
    let mut c = cfg();
    c.min_benchmark_samples = 0;
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 800, 50)];
    let err = evaluate_cold_start(&evidence, &[], &c).unwrap_err();
    assert_eq!(err.as_str(), "invalid_config");
}

#[test]
fn test_evaluate_rollback_takes_priority_over_block() {
    let c = cfg();
    // 80% regression => triggers rollback
    let evidence = vec![ev(StartupPathKind::WarmCache, 100, 180, 50)];
    let par = vec![parity(ParityCheckKind::SemanticParity, true, 0)];
    let verdict = evaluate_cold_start(&evidence, &par, &c).unwrap();
    assert!(verdict.requires_rollback());
}

#[test]
fn test_evaluate_observability_proof_required_missing() {
    let mut c = cfg();
    c.require_observability_proof = true;
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 800, 50)];
    let par = vec![parity(ParityCheckKind::SemanticParity, true, 0)];
    let verdict = evaluate_cold_start(&evidence, &par, &c).unwrap();
    match verdict {
        GovernanceVerdict::Blocked { reasons } => {
            assert!(reasons.iter().any(|r| r.contains("observability")));
        }
        other => panic!("expected Blocked, got {other}"),
    }
}

#[test]
fn test_evaluate_observability_proof_satisfied() {
    let mut c = cfg();
    c.require_observability_proof = true;
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 800, 50)];
    let par = vec![
        parity(ParityCheckKind::SemanticParity, true, 0),
        parity(ParityCheckKind::BehavioralParity, true, 0),
    ];
    let verdict = evaluate_cold_start(&evidence, &par, &c).unwrap();
    assert_eq!(verdict, GovernanceVerdict::Approved);
}

#[test]
fn test_evaluate_semantic_parity_not_required() {
    let mut c = cfg();
    c.require_semantic_parity = false;
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 800, 50)];
    let verdict = evaluate_cold_start(&evidence, &[], &c).unwrap();
    assert_eq!(verdict, GovernanceVerdict::Approved);
}

#[test]
fn test_evaluate_divergence_exceeds_max() {
    let c = cfg();
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 800, 50)];
    let par = vec![parity(ParityCheckKind::SemanticParity, true, 100_000)];
    let verdict = evaluate_cold_start(&evidence, &par, &c).unwrap();
    match verdict {
        GovernanceVerdict::Blocked { reasons } => {
            assert!(reasons.iter().any(|r| r.contains("divergence")));
        }
        other => panic!("expected Blocked, got {other}"),
    }
}

#[test]
fn test_evaluate_multiple_parity_all_pass() {
    let c = cfg();
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 800, 50)];
    let par = vec![
        parity(ParityCheckKind::SemanticParity, true, 0),
        parity(ParityCheckKind::BehavioralParity, true, 0),
        parity(ParityCheckKind::PerformanceParity, true, 0),
    ];
    let verdict = evaluate_cold_start(&evidence, &par, &c).unwrap();
    assert_eq!(verdict, GovernanceVerdict::Approved);
}

#[test]
fn test_evaluate_aggregate_samples_sufficient() {
    let c = cfg();
    // Each evidence has 10 samples, but together 40 > 30 threshold.
    let evidence = vec![
        ev(StartupPathKind::WarmCache, 1000, 800, 10),
        ev(StartupPathKind::AotRestored, 1000, 700, 10),
        ev(StartupPathKind::ZygoteFork, 1000, 750, 10),
        ev(StartupPathKind::PrewarmedPool, 1000, 850, 10),
    ];
    let par = vec![parity(ParityCheckKind::SemanticParity, true, 0)];
    let verdict = evaluate_cold_start(&evidence, &par, &c).unwrap();
    assert_eq!(verdict, GovernanceVerdict::Approved);
}

// ============================================================================
// aggregate_speedup
// ============================================================================

#[test]
fn test_aggregate_speedup_single() {
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 800, 50)];
    assert_eq!(aggregate_speedup(&evidence), 200_000);
}

#[test]
fn test_aggregate_speedup_weighted() {
    let ev1 = ev(StartupPathKind::WarmCache, 1000, 800, 100); // 200_000
    let ev2 = ev(StartupPathKind::AotRestored, 1000, 900, 100); // 100_000
    // Weighted avg: (200_000 * 100 + 100_000 * 100) / 200 = 150_000
    assert_eq!(aggregate_speedup(&[ev1, ev2]), 150_000);
}

#[test]
fn test_aggregate_speedup_empty() {
    assert_eq!(aggregate_speedup(&[]), 0);
}

#[test]
fn test_aggregate_speedup_zero_total_samples() {
    let evidence = vec![ColdStartEvidence::new(
        StartupPathKind::WarmCache,
        100,
        80,
        0,
        ep(10),
    )];
    assert_eq!(aggregate_speedup(&evidence), 0);
}

// ============================================================================
// aggregate_verdict
// ============================================================================

#[test]
fn test_aggregate_verdict_faster() {
    let c = cfg();
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 800, 50)];
    assert_eq!(aggregate_verdict(&evidence, &c), BenchmarkVerdict::Faster);
}

#[test]
fn test_aggregate_verdict_slower() {
    let c = cfg();
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 1200, 50)];
    assert_eq!(aggregate_verdict(&evidence, &c), BenchmarkVerdict::Slower);
}

#[test]
fn test_aggregate_verdict_equivalent() {
    let c = cfg();
    let evidence = vec![ev(StartupPathKind::WarmCache, 10000, 9995, 50)];
    assert_eq!(
        aggregate_verdict(&evidence, &c),
        BenchmarkVerdict::Equivalent
    );
}

#[test]
fn test_aggregate_verdict_inconclusive() {
    let c = cfg();
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 800, 5)];
    assert_eq!(
        aggregate_verdict(&evidence, &c),
        BenchmarkVerdict::Inconclusive
    );
}

// ============================================================================
// DecisionReceipt
// ============================================================================

#[test]
fn test_receipt_component() {
    let r = DecisionReceipt::new(ep(10), GovernanceVerdict::Approved, vec![], vec![]);
    assert_eq!(r.component, COMPONENT);
}

#[test]
fn test_receipt_epoch() {
    let r = DecisionReceipt::new(ep(42), GovernanceVerdict::Approved, vec![], vec![]);
    assert_eq!(r.epoch, ep(42));
}

#[test]
fn test_receipt_hash_deterministic() {
    let eh = vec![ContentHash::compute(b"e1")];
    let ph = vec![ContentHash::compute(b"p1")];
    let r1 = DecisionReceipt::new(ep(10), GovernanceVerdict::Approved, eh.clone(), ph.clone());
    let r2 = DecisionReceipt::new(ep(10), GovernanceVerdict::Approved, eh, ph);
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_receipt_hash_varies_epoch() {
    let r1 = DecisionReceipt::new(ep(1), GovernanceVerdict::Approved, vec![], vec![]);
    let r2 = DecisionReceipt::new(ep(2), GovernanceVerdict::Approved, vec![], vec![]);
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_receipt_hash_varies_verdict() {
    let r1 = DecisionReceipt::new(ep(10), GovernanceVerdict::Approved, vec![], vec![]);
    let r2 = DecisionReceipt::new(
        ep(10),
        GovernanceVerdict::Blocked {
            reasons: vec!["x".into()],
        },
        vec![],
        vec![],
    );
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_receipt_display() {
    let r = DecisionReceipt::new(
        ep(10),
        GovernanceVerdict::Approved,
        vec![ContentHash::compute(b"e")],
        vec![ContentHash::compute(b"p")],
    );
    let s = r.to_string();
    assert!(s.contains("DecisionReceipt"));
    assert!(s.contains("approved"));
    assert!(s.contains("evidence=1"));
    assert!(s.contains("parity=1"));
}

#[test]
fn test_receipt_serde_roundtrip() {
    let r = DecisionReceipt::new(
        ep(10),
        GovernanceVerdict::Approved,
        vec![ContentHash::compute(b"e1")],
        vec![ContentHash::compute(b"p1")],
    );
    let j = serde_json::to_string(&r).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&j).unwrap();
    assert_eq!(r, back);
}

// ============================================================================
// produce_receipt
// ============================================================================

#[test]
fn test_produce_receipt_captures_evidence() {
    let evidence = vec![ev(StartupPathKind::WarmCache, 1000, 800, 50)];
    let par = vec![parity(ParityCheckKind::SemanticParity, true, 0)];
    let verdict = GovernanceVerdict::Approved;
    let receipt = produce_receipt(ep(10), &evidence, &par, &verdict);
    assert_eq!(receipt.evidence_hashes.len(), 1);
    assert_eq!(receipt.parity_hashes.len(), 1);
    assert_eq!(receipt.evidence_hashes[0], evidence[0].evidence_hash);
    assert_eq!(receipt.parity_hashes[0], par[0].evidence_hash);
}

#[test]
fn test_produce_receipt_empty_inputs() {
    let verdict = GovernanceVerdict::Blocked {
        reasons: vec!["none".into()],
    };
    let receipt = produce_receipt(ep(5), &[], &[], &verdict);
    assert!(receipt.evidence_hashes.is_empty());
    assert!(receipt.parity_hashes.is_empty());
    assert!(!receipt.verdict.allows_publication());
}

// ============================================================================
// End-to-end scenario tests
// ============================================================================

#[test]
fn test_e2e_aot_faster_with_full_parity() {
    let c = cfg();
    let evidence = vec![
        ev(StartupPathKind::AotRestored, 5000, 3000, 100),
        ev(StartupPathKind::AotRestored, 4000, 2500, 100),
    ];
    let par = vec![
        parity(ParityCheckKind::SemanticParity, true, 0),
        parity(ParityCheckKind::BehavioralParity, true, 0),
        parity(ParityCheckKind::PerformanceParity, true, 0),
    ];
    let verdict = evaluate_cold_start(&evidence, &par, &c).unwrap();
    assert_eq!(verdict, GovernanceVerdict::Approved);
    let receipt = produce_receipt(ep(10), &evidence, &par, &verdict);
    assert_eq!(receipt.evidence_hashes.len(), 2);
    assert_eq!(receipt.parity_hashes.len(), 3);
}

#[test]
fn test_e2e_warm_cache_regression_triggers_rollback() {
    let c = cfg();
    let evidence = vec![ev(StartupPathKind::WarmCache, 100, 200, 50)]; // 100% slower
    let par = vec![parity(ParityCheckKind::SemanticParity, true, 0)];
    let verdict = evaluate_cold_start(&evidence, &par, &c).unwrap();
    assert!(verdict.requires_rollback());
}

#[test]
fn test_e2e_zygote_fork_equivalent_blocked() {
    let c = cfg();
    let evidence = vec![ev(StartupPathKind::ZygoteFork, 1000, 999, 50)]; // ~0.1% speedup
    let par = vec![parity(ParityCheckKind::SemanticParity, true, 0)];
    let verdict = evaluate_cold_start(&evidence, &par, &c).unwrap();
    match verdict {
        GovernanceVerdict::Blocked { reasons } => {
            assert!(reasons.iter().any(|r| r.contains("no evidence of speedup")));
        }
        other => panic!("expected Blocked, got {other}"),
    }
}

#[test]
fn test_e2e_prewarmed_pool_fast_but_semantically_divergent() {
    let c = cfg();
    let evidence = vec![ev(StartupPathKind::PrewarmedPool, 1000, 500, 50)];
    let par = vec![parity(ParityCheckKind::SemanticParity, false, 200_000)];
    let verdict = evaluate_cold_start(&evidence, &par, &c).unwrap();
    assert!(!verdict.allows_publication());
}
