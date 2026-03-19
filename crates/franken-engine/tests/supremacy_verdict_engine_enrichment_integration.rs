//! Enrichment integration tests for `supremacy_verdict_engine` module.
//!
//! Tests advanced edge cases, multi-cell interactions, statistical boundaries,
//! side-constraint combinations, and report/receipt determinism.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::supremacy_verdict_engine::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn measurement(cell: &str, treatment: u64, baseline: u64) -> CellMeasurement {
    CellMeasurement {
        cell_id: cell.into(),
        treatment_ns: treatment,
        baseline_ns: baseline,
        observability_mode: ObservabilityMode::BudgetedCapture,
        epoch: 1,
        memory_delta_bytes: 0,
        tail_p99_ns: treatment + 100,
        baseline_tail_p99_ns: baseline + 100,
        crash_observed: false,
    }
}

fn measurement_with_mode(
    cell: &str,
    treatment: u64,
    baseline: u64,
    mode: ObservabilityMode,
) -> CellMeasurement {
    CellMeasurement {
        cell_id: cell.into(),
        treatment_ns: treatment,
        baseline_ns: baseline,
        observability_mode: mode,
        epoch: 1,
        memory_delta_bytes: 0,
        tail_p99_ns: treatment + 100,
        baseline_tail_p99_ns: baseline + 100,
        crash_observed: false,
    }
}

fn measurement_with_crash(cell: &str, treatment: u64, baseline: u64) -> CellMeasurement {
    CellMeasurement {
        cell_id: cell.into(),
        treatment_ns: treatment,
        baseline_ns: baseline,
        observability_mode: ObservabilityMode::BudgetedCapture,
        epoch: 1,
        memory_delta_bytes: 0,
        tail_p99_ns: treatment + 100,
        baseline_tail_p99_ns: baseline + 100,
        crash_observed: true,
    }
}

fn measurement_with_memory(
    cell: &str,
    treatment: u64,
    baseline: u64,
    memory_delta: i64,
) -> CellMeasurement {
    CellMeasurement {
        cell_id: cell.into(),
        treatment_ns: treatment,
        baseline_ns: baseline,
        observability_mode: ObservabilityMode::BudgetedCapture,
        epoch: 1,
        memory_delta_bytes: memory_delta,
        tail_p99_ns: treatment + 100,
        baseline_tail_p99_ns: baseline + 100,
        crash_observed: false,
    }
}

fn measurement_with_tail(
    cell: &str,
    treatment: u64,
    baseline: u64,
    tail_treatment: u64,
    tail_baseline: u64,
) -> CellMeasurement {
    CellMeasurement {
        cell_id: cell.into(),
        treatment_ns: treatment,
        baseline_ns: baseline,
        observability_mode: ObservabilityMode::BudgetedCapture,
        epoch: 1,
        memory_delta_bytes: 0,
        tail_p99_ns: tail_treatment,
        baseline_tail_p99_ns: tail_baseline,
        crash_observed: false,
    }
}

fn relaxed_config() -> VerdictConfig {
    VerdictConfig {
        min_observations: 5,
        min_effect_size: 10_000,
        max_cv: 1_000_000,
        ..VerdictConfig::default()
    }
}

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(100)
}

// ---------------------------------------------------------------------------
// 1. SPRT boundary conditions
// ---------------------------------------------------------------------------

#[test]
fn enrich_sprt_single_observation_no_decision() {
    let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
    state.update(500, 1000);
    assert_eq!(state.n_observations, 1);
    assert!(!state.is_decided());
}

#[test]
fn enrich_sprt_mean_zero_when_empty() {
    let state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
    assert_eq!(state.mean_treatment_millionths(), 0);
    assert_eq!(state.mean_baseline_millionths(), 0);
}

#[test]
fn enrich_sprt_effect_size_zero_when_empty() {
    let state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
    assert_eq!(state.effect_size_millionths(), 0);
}

#[test]
fn enrich_sprt_cv_zero_when_empty() {
    let state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
    assert_eq!(state.cv_treatment_millionths(), 0);
}

// ---------------------------------------------------------------------------
// 2. Multiple side-constraint violations
// ---------------------------------------------------------------------------

#[test]
fn enrich_multiple_violations_crash_and_tail() {
    let mut config = relaxed_config();
    config.max_crash_rate = 1;
    config.max_tail_regression = 1;
    let ms: Vec<_> = (0..20)
        .map(|_| {
            let mut m = measurement_with_crash("c1", 500, 1000);
            m.tail_p99_ns = 5000;
            m.baseline_tail_p99_ns = 1000;
            m
        })
        .collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let cv = &report.cell_verdicts[0];
    let kinds: Vec<_> = cv.violations.iter().map(|v| v.kind).collect();
    assert!(kinds.contains(&SideConstraintKind::CrashRate));
    assert!(kinds.contains(&SideConstraintKind::TailLatencyRegression));
}

// ---------------------------------------------------------------------------
// 3. Memory + crash combined
// ---------------------------------------------------------------------------

#[test]
fn enrich_memory_and_crash_combined_rejection() {
    let mut config = relaxed_config();
    config.max_crash_rate = 1;
    config.max_memory_regression = 1;
    let ms: Vec<_> = (0..20)
        .map(|_| {
            let mut m = measurement_with_memory("c1", 500, 1000, 999_999);
            m.crash_observed = true;
            m
        })
        .collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let cv = &report.cell_verdicts[0];
    assert_eq!(cv.verdict, SupremacyVerdict::Rejected);
}

// ---------------------------------------------------------------------------
// 4. VerdictConfig validation edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrich_validate_config_alpha_one_ok() {
    let mut config = VerdictConfig::default();
    config.alpha = 1;
    assert!(validate_config(&config).is_ok());
}

#[test]
fn enrich_validate_config_alpha_999999_ok() {
    let mut config = VerdictConfig::default();
    config.alpha = 999_999;
    assert!(validate_config(&config).is_ok());
}

#[test]
fn enrich_validate_config_min_obs_one_ok() {
    let mut config = VerdictConfig::default();
    config.min_observations = 1;
    assert!(validate_config(&config).is_ok());
}

#[test]
fn enrich_validate_config_board_threshold_one_ok() {
    let mut config = VerdictConfig::default();
    config.board_pass_threshold = 1;
    assert!(validate_config(&config).is_ok());
}

#[test]
fn enrich_validate_config_board_threshold_million_ok() {
    let mut config = VerdictConfig::default();
    config.board_pass_threshold = 1_000_000;
    assert!(validate_config(&config).is_ok());
}

// ---------------------------------------------------------------------------
// 5. Report determinism
// ---------------------------------------------------------------------------

#[test]
fn enrich_report_deterministic_verdict_and_receipt() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..50).map(|_| measurement("c1", 500, 1000)).collect();
    let r1 = evaluate_supremacy(&ms, &config, &epoch(), 9999).unwrap();
    let r2 = evaluate_supremacy(&ms, &config, &epoch(), 9999).unwrap();
    assert_eq!(r1.board_verdict, r2.board_verdict);
    assert_eq!(r1.confirmed_fraction, r2.confirmed_fraction);
    assert_eq!(r1.receipt, r2.receipt);
}

// ---------------------------------------------------------------------------
// 6. Report with many cells
// ---------------------------------------------------------------------------

#[test]
fn enrich_report_many_cells_all_have_verdicts() {
    let config = relaxed_config();
    let mut ms = Vec::new();
    for i in 0..20 {
        for _ in 0..50 {
            ms.push(measurement(&format!("c{i}"), 300, 1000));
        }
    }
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    assert_eq!(report.cell_verdicts.len(), 20);
    // With 50 observations of strong signal (300 vs 1000), all should be confirmed
    let confirmed = report.cell_verdicts.iter().filter(|v| v.verdict == SupremacyVerdict::Confirmed).count();
    assert_eq!(confirmed, 20);
}

// ---------------------------------------------------------------------------
// 7. VerdictError serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrich_verdict_error_all_variants_serde() {
    let errors = vec![
        VerdictError::NoMeasurements,
        VerdictError::TooManyCells { count: 300 },
        VerdictError::TooManySideConstraints { count: 50 },
        VerdictError::InvalidConfig { field: "alpha".into(), detail: "out of range".into() },
        VerdictError::UnknownCell { cell_id: "x".into() },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: VerdictError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ---------------------------------------------------------------------------
// 8. Observability mode filtering
// ---------------------------------------------------------------------------

#[test]
fn enrich_observability_mode_matching_passes() {
    let mut config = relaxed_config();
    config.required_observability_modes = vec![ObservabilityMode::BudgetedCapture];
    let ms: Vec<_> = (0..30)
        .map(|_| measurement_with_mode("c1", 500, 1000, ObservabilityMode::BudgetedCapture))
        .collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let cv = &report.cell_verdicts[0];
    assert!(!cv.violations.iter().any(|v| v.kind == SideConstraintKind::ObservabilityMismatch));
}

#[test]
fn enrich_observability_mode_multiple_required_all_present() {
    let mut config = relaxed_config();
    config.required_observability_modes = vec![
        ObservabilityMode::BudgetedCapture,
        ObservabilityMode::ExactShadow,
    ];
    let mut ms = Vec::new();
    for i in 0..30u64 {
        let mode = if i.is_multiple_of(2) {
            ObservabilityMode::BudgetedCapture
        } else {
            ObservabilityMode::ExactShadow
        };
        ms.push(measurement_with_mode("c1", 500, 1000, mode));
    }
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let cv = &report.cell_verdicts[0];
    assert!(!cv.violations.iter().any(|v| v.kind == SideConstraintKind::ObservabilityMismatch));
}

// ---------------------------------------------------------------------------
// 9. SPRT boundaries
// ---------------------------------------------------------------------------

#[test]
fn enrich_sprt_upper_positive_lower_negative() {
    let state = SequentialTestState::new(50_000, 200_000);
    assert!(state.upper_boundary > 0);
    assert!(state.lower_boundary < 0);
}

// ---------------------------------------------------------------------------
// 10. CellVerdict fields
// ---------------------------------------------------------------------------

#[test]
fn enrich_cell_verdict_fields_accessible() {
    let cv = CellVerdict {
        cell_id: "c1".into(),
        verdict: SupremacyVerdict::Inconclusive,
        rejection_reasons: vec![RejectionReason::StatisticallyInsignificant],
        n_observations: 10,
        effect_size: 50_000,
        cv_treatment: 200_000,
        violations: Vec::new(),
        final_llr: -100,
        mean_improvement_ratio: 0,
    };
    assert_eq!(cv.cell_id, "c1");
    assert_eq!(cv.n_observations, 10);
    assert_eq!(cv.final_llr, -100);
}

// ---------------------------------------------------------------------------
// 11. SideConstraintKind names non-empty
// ---------------------------------------------------------------------------

#[test]
fn enrich_side_constraint_kind_names_all_non_empty() {
    for kind in SideConstraintKind::ALL {
        assert!(!kind.as_str().is_empty());
        assert!(!kind.to_string().is_empty());
    }
}

// ---------------------------------------------------------------------------
// 12. RejectionReason all serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_rejection_reason_all_serde() {
    let reasons = vec![
        RejectionReason::StatisticallyInsignificant,
        RejectionReason::BelowEffectSizeFloor,
        RejectionReason::SideConstraintViolation,
        RejectionReason::ObservabilityInsufficient,
        RejectionReason::InsufficientDataNegativeTrend,
        RejectionReason::BoardLevelFailure,
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: RejectionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ---------------------------------------------------------------------------
// 13. Report no violations
// ---------------------------------------------------------------------------

#[test]
fn enrich_report_no_violations_confirmed() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..50).map(|_| measurement("c1", 300, 1000)).collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    assert_eq!(report.total_violations, 0);
}

// ---------------------------------------------------------------------------
// 14. summarize_report contains all cell ids
// ---------------------------------------------------------------------------

#[test]
fn enrich_summarize_report_contains_all_cell_ids() {
    let config = relaxed_config();
    let mut ms = Vec::new();
    for _ in 0..30 {
        ms.push(measurement("alpha", 500, 1000));
        ms.push(measurement("beta", 400, 900));
        ms.push(measurement("gamma", 600, 1100));
    }
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let summary = summarize_report(&report);
    assert!(summary.contains("alpha"));
    assert!(summary.contains("beta"));
    assert!(summary.contains("gamma"));
}

// ---------------------------------------------------------------------------
// 15. Timestamp in receipt
// ---------------------------------------------------------------------------

#[test]
fn enrich_receipt_timestamp_matches_input() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..10).map(|_| measurement("c1", 500, 1000)).collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 42_000).unwrap();
    assert_eq!(report.receipt.timestamp_micros, 42_000);
}

// ---------------------------------------------------------------------------
// 16. CellMeasurement fields
// ---------------------------------------------------------------------------

#[test]
fn enrich_cell_measurement_fields_accessible() {
    let m = CellMeasurement {
        cell_id: "c1".into(),
        treatment_ns: 100,
        baseline_ns: 200,
        observability_mode: ObservabilityMode::ExactShadow,
        epoch: 5,
        memory_delta_bytes: -1000,
        tail_p99_ns: 150,
        baseline_tail_p99_ns: 250,
        crash_observed: false,
    };
    assert_eq!(m.cell_id, "c1");
    assert_eq!(m.memory_delta_bytes, -1000);
}

// ---------------------------------------------------------------------------
// 17. Constants accessible
// ---------------------------------------------------------------------------

#[test]
fn enrich_default_constants_accessible() {
    assert!(DEFAULT_MIN_OBSERVATIONS > 0);
    assert!(DEFAULT_ALPHA > 0);
    assert!(DEFAULT_BETA > 0);
    assert!(DEFAULT_MIN_EFFECT_SIZE > 0);
    assert!(DEFAULT_MAX_CV > 0);
}

// ---------------------------------------------------------------------------
// 18. VerdictConfig custom serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_verdict_config_custom_values_serde() {
    let config = VerdictConfig {
        min_observations: 10,
        alpha: 25_000,
        beta: 100_000,
        min_effect_size: 50_000,
        max_cv: 300_000,
        max_memory_regression: 50_000,
        max_tail_regression: 50_000,
        max_crash_rate: 10_000,
        board_pass_threshold: 900_000,
        required_observability_modes: vec![ObservabilityMode::ExactShadow],
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: VerdictConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// 19. Zero treatment ns
// ---------------------------------------------------------------------------

#[test]
fn enrich_zero_treatment_ns_no_panic() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..10).map(|_| measurement("c1", 0, 1000)).collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    assert!(!report.cell_verdicts.is_empty());
}

// ---------------------------------------------------------------------------
// 20. Board rejection reasons
// ---------------------------------------------------------------------------

#[test]
fn enrich_board_rejection_reasons_for_rejected() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..30).map(|_| measurement("c1", 2000, 500)).collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    assert_eq!(report.board_verdict, SupremacyVerdict::Rejected);
    assert!(!report.board_rejection_reasons.is_empty());
}

// ---------------------------------------------------------------------------
// 21. confirmed_fraction zero when all rejected
// ---------------------------------------------------------------------------

#[test]
fn enrich_confirmed_fraction_zero_when_all_rejected() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..30).map(|_| measurement("c1", 2000, 500)).collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    assert_eq!(report.confirmed_fraction, 0);
}

// ---------------------------------------------------------------------------
// 22. Report serde with violations
// ---------------------------------------------------------------------------

#[test]
fn enrich_verdict_report_serde_with_violations() {
    let mut config = relaxed_config();
    config.max_crash_rate = 1;
    let ms: Vec<_> = (0..20).map(|_| measurement_with_crash("c1", 500, 1000)).collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    assert!(report.total_violations > 0);
    let json = serde_json::to_string(&report).unwrap();
    let back: VerdictReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// 23. Memory negative delta
// ---------------------------------------------------------------------------

#[test]
fn enrich_memory_negative_delta_no_violation() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..30)
        .map(|_| measurement_with_memory("c1", 500, 1000, -50_000))
        .collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let cv = &report.cell_verdicts[0];
    assert!(!cv.violations.iter().any(|v| v.kind == SideConstraintKind::MemoryRegression));
}

// ---------------------------------------------------------------------------
// 24. Tail equal no violation
// ---------------------------------------------------------------------------

#[test]
fn enrich_tail_equal_no_violation() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..30)
        .map(|_| measurement_with_tail("c1", 500, 1000, 1000, 1000))
        .collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let cv = &report.cell_verdicts[0];
    assert!(!cv.violations.iter().any(|v| v.kind == SideConstraintKind::TailLatencyRegression));
}

// ---------------------------------------------------------------------------
// 25. Schema and component format
// ---------------------------------------------------------------------------

#[test]
fn enrich_schema_version_and_component_format() {
    assert!(SCHEMA_VERSION.contains("supremacy-verdict-engine"));
    assert_eq!(COMPONENT, "supremacy_verdict_engine");
    assert!(BEAD_ID.starts_with("bd-"));
    assert!(POLICY_ID.starts_with("RGC-"));
}

// ---------------------------------------------------------------------------
// 26. SPRT serde after many updates
// ---------------------------------------------------------------------------

#[test]
fn enrich_sprt_serde_after_many_updates() {
    let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
    for i in 0..100 {
        state.update(500 + i, 1000 + i);
    }
    let json = serde_json::to_string(&state).unwrap();
    let back: SequentialTestState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, back);
    assert_eq!(state.n_observations, 100);
}

// ---------------------------------------------------------------------------
// 27. SideConstraintViolation serde
// ---------------------------------------------------------------------------

#[test]
fn enrich_side_constraint_violation_serde() {
    let v = SideConstraintViolation {
        kind: SideConstraintKind::MemoryRegression,
        cell_id: "c1".into(),
        observed: 500_000,
        threshold: 100_000,
        detail: "memory regression".into(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: SideConstraintViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// 28. SupremacyVerdict is_positive matrix
// ---------------------------------------------------------------------------

#[test]
fn enrich_supremacy_verdict_is_positive_matrix() {
    assert!(SupremacyVerdict::Confirmed.is_positive());
    assert!(!SupremacyVerdict::Rejected.is_positive());
    assert!(!SupremacyVerdict::Inconclusive.is_positive());
}

// ---------------------------------------------------------------------------
// 29. DecisionReceipt fields
// ---------------------------------------------------------------------------

#[test]
fn enrich_decision_receipt_fields_populated() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..10).map(|_| measurement("c1", 500, 1000)).collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 7777).unwrap();
    let r = &report.receipt;
    assert!(!r.schema_version.is_empty());
    assert!(!r.component.is_empty());
    assert!(!r.bead_id.is_empty());
    assert!(!r.policy_id.is_empty());
    assert_eq!(r.timestamp_micros, 7777);
}

// ---------------------------------------------------------------------------
// 30. Board verdict at boundary
// ---------------------------------------------------------------------------

#[test]
fn enrich_board_verdict_with_mixed_cells() {
    let mut config = relaxed_config();
    config.board_pass_threshold = 500_000;
    let mut ms = Vec::new();
    for _ in 0..50 {
        ms.push(measurement("confirmed", 300, 1000));
        ms.push(measurement("rejected", 2000, 500));
    }
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    assert!(!report.cell_verdicts.is_empty());
}
