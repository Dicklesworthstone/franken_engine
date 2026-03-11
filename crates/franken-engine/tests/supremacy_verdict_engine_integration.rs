//! Integration tests for the supremacy verdict engine.
//!
//! Bead: bd-1lsy.8.5.2 [RGC-705B]

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

fn default_config() -> VerdictConfig {
    VerdictConfig::default()
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
// ObservabilityMode tests
// ---------------------------------------------------------------------------

#[test]
fn test_observability_mode_all_variants() {
    assert_eq!(ObservabilityMode::ALL.len(), 4);
    for mode in ObservabilityMode::ALL {
        let s = mode.as_str();
        assert!(!s.is_empty());
    }
}

#[test]
fn test_observability_mode_rigorous() {
    assert!(ObservabilityMode::BudgetedCapture.is_rigorous());
    assert!(ObservabilityMode::ExactShadow.is_rigorous());
    assert!(!ObservabilityMode::DegradedCapture.is_rigorous());
    assert!(!ObservabilityMode::IncidentCapture.is_rigorous());
}

#[test]
fn test_observability_mode_serde_roundtrip() {
    for mode in ObservabilityMode::ALL {
        let json = serde_json::to_string(mode).unwrap();
        let parsed: ObservabilityMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*mode, parsed);
    }
}

#[test]
fn test_observability_mode_display() {
    assert_eq!(
        format!("{}", ObservabilityMode::BudgetedCapture),
        "budgeted_capture"
    );
    assert_eq!(
        format!("{}", ObservabilityMode::ExactShadow),
        "exact_shadow"
    );
    assert_eq!(
        format!("{}", ObservabilityMode::DegradedCapture),
        "degraded_capture"
    );
    assert_eq!(
        format!("{}", ObservabilityMode::IncidentCapture),
        "incident_capture"
    );
}

// ---------------------------------------------------------------------------
// SideConstraintKind tests
// ---------------------------------------------------------------------------

#[test]
fn test_side_constraint_kind_all_variants() {
    assert_eq!(SideConstraintKind::ALL.len(), 8);
    for kind in SideConstraintKind::ALL {
        assert!(!kind.as_str().is_empty());
    }
}

#[test]
fn test_side_constraint_kind_serde_roundtrip() {
    for kind in SideConstraintKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let parsed: SideConstraintKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, parsed);
    }
}

#[test]
fn test_side_constraint_kind_display_all() {
    for kind in SideConstraintKind::ALL {
        let display = format!("{kind}");
        assert_eq!(display, kind.as_str());
    }
}

// ---------------------------------------------------------------------------
// SupremacyVerdict tests
// ---------------------------------------------------------------------------

#[test]
fn test_supremacy_verdict_all_variants() {
    assert_eq!(SupremacyVerdict::ALL.len(), 3);
}

#[test]
fn test_supremacy_verdict_is_positive() {
    assert!(SupremacyVerdict::Confirmed.is_positive());
    assert!(!SupremacyVerdict::Rejected.is_positive());
    assert!(!SupremacyVerdict::Inconclusive.is_positive());
}

#[test]
fn test_supremacy_verdict_serde_roundtrip() {
    for v in SupremacyVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let parsed: SupremacyVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, parsed);
    }
}

#[test]
fn test_supremacy_verdict_display() {
    assert_eq!(format!("{}", SupremacyVerdict::Confirmed), "confirmed");
    assert_eq!(format!("{}", SupremacyVerdict::Rejected), "rejected");
    assert_eq!(
        format!("{}", SupremacyVerdict::Inconclusive),
        "inconclusive"
    );
}

// ---------------------------------------------------------------------------
// RejectionReason tests
// ---------------------------------------------------------------------------

#[test]
fn test_rejection_reason_display() {
    assert_eq!(
        format!("{}", RejectionReason::StatisticallyInsignificant),
        "statistically_insignificant"
    );
    assert_eq!(
        format!("{}", RejectionReason::BelowEffectSizeFloor),
        "below_effect_size_floor"
    );
    assert_eq!(
        format!("{}", RejectionReason::SideConstraintViolation),
        "side_constraint_violation"
    );
    assert_eq!(
        format!("{}", RejectionReason::ObservabilityInsufficient),
        "observability_insufficient"
    );
    assert_eq!(
        format!("{}", RejectionReason::InsufficientDataNegativeTrend),
        "insufficient_data_negative_trend"
    );
    assert_eq!(
        format!("{}", RejectionReason::BoardLevelFailure),
        "board_level_failure"
    );
}

#[test]
fn test_rejection_reason_serde() {
    let r = RejectionReason::StatisticallyInsignificant;
    let json = serde_json::to_string(&r).unwrap();
    let parsed: RejectionReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, parsed);
}

// ---------------------------------------------------------------------------
// SequentialTestState tests
// ---------------------------------------------------------------------------

#[test]
fn test_sprt_new_boundaries() {
    let state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
    assert!(state.upper_boundary > 0);
    assert!(state.lower_boundary < 0);
    assert_eq!(state.n_observations, 0);
    assert_eq!(state.cumulative_llr, 0);
}

#[test]
fn test_sprt_superiority_signal() {
    let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
    for _ in 0..100 {
        state.update(500, 1000);
    }
    assert_eq!(state.n_observations, 100);
    assert!(state.cumulative_llr > 0);
    assert!(state.accepts_superiority());
}

#[test]
fn test_sprt_null_signal() {
    let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
    for _ in 0..100 {
        state.update(1000, 500);
    }
    assert!(state.cumulative_llr < 0);
    assert!(state.accepts_null());
}

#[test]
fn test_sprt_equal_indeterminate() {
    let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
    for _ in 0..10 {
        state.update(1000, 1000);
    }
    assert_eq!(state.cumulative_llr, 0);
    assert!(!state.is_decided());
}

#[test]
fn test_sprt_effect_size_strong() {
    let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
    for _ in 0..50 {
        state.update(500, 1000);
    }
    let d = state.effect_size_millionths();
    assert!(
        d > 0,
        "strong superiority should yield positive effect size"
    );
}

#[test]
fn test_sprt_effect_size_zero_when_worse() {
    let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
    for _ in 0..50 {
        state.update(1000, 500);
    }
    assert_eq!(state.effect_size_millionths(), 0);
}

#[test]
fn test_sprt_cv_with_constant_values() {
    let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
    for _ in 0..30 {
        state.update(1000, 2000);
    }
    // Constant values should yield CV=0
    assert_eq!(state.cv_treatment_millionths(), 0);
}

#[test]
fn test_sprt_cv_with_variable_values() {
    let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
    state.update(100, 200);
    state.update(200, 300);
    state.update(300, 400);
    state.update(400, 500);
    let cv = state.cv_treatment_millionths();
    assert!(cv > 0, "varied values should have positive CV");
}

#[test]
fn test_sprt_serde_roundtrip() {
    let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
    state.update(100, 200);
    state.update(300, 400);
    let json = serde_json::to_string(&state).unwrap();
    let state2: SequentialTestState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, state2);
}

#[test]
fn test_sprt_mean_treatment() {
    let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
    state.update(100, 200);
    state.update(300, 400);
    let mean = state.mean_treatment_millionths();
    assert_eq!(mean, 200 * 1_000_000 / 2);
}

#[test]
fn test_sprt_mean_baseline() {
    let mut state = SequentialTestState::new(DEFAULT_ALPHA, DEFAULT_BETA);
    state.update(100, 200);
    state.update(300, 400);
    let mean = state.mean_baseline_millionths();
    assert_eq!(mean, 300 * 1_000_000 / 2);
}

// ---------------------------------------------------------------------------
// VerdictConfig tests
// ---------------------------------------------------------------------------

#[test]
fn test_verdict_config_default() {
    let config = VerdictConfig::default();
    assert_eq!(config.min_observations, DEFAULT_MIN_OBSERVATIONS);
    assert_eq!(config.alpha, DEFAULT_ALPHA);
    assert_eq!(config.beta, DEFAULT_BETA);
    assert_eq!(config.min_effect_size, DEFAULT_MIN_EFFECT_SIZE);
    assert_eq!(config.max_cv, DEFAULT_MAX_CV);
    assert_eq!(config.max_memory_regression, DEFAULT_MAX_MEMORY_REGRESSION);
    assert_eq!(config.max_tail_regression, DEFAULT_MAX_TAIL_REGRESSION);
    assert_eq!(config.max_crash_rate, DEFAULT_MAX_CRASH_RATE);
    assert_eq!(config.board_pass_threshold, 800_000);
}

#[test]
fn test_verdict_config_serde_roundtrip() {
    let config = VerdictConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let config2: VerdictConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, config2);
}

#[test]
fn test_validate_config_ok() {
    assert!(validate_config(&default_config()).is_ok());
}

#[test]
fn test_validate_config_alpha_zero() {
    let mut config = default_config();
    config.alpha = 0;
    assert!(validate_config(&config).is_err());
}

#[test]
fn test_validate_config_alpha_too_large() {
    let mut config = default_config();
    config.alpha = 1_000_000;
    assert!(validate_config(&config).is_err());
}

#[test]
fn test_validate_config_beta_zero() {
    let mut config = default_config();
    config.beta = 0;
    assert!(validate_config(&config).is_err());
}

#[test]
fn test_validate_config_beta_too_large() {
    let mut config = default_config();
    config.beta = 1_000_000;
    assert!(validate_config(&config).is_err());
}

#[test]
fn test_validate_config_min_obs_zero() {
    let mut config = default_config();
    config.min_observations = 0;
    assert!(validate_config(&config).is_err());
}

#[test]
fn test_validate_config_board_threshold_zero() {
    let mut config = default_config();
    config.board_pass_threshold = 0;
    assert!(validate_config(&config).is_err());
}

#[test]
fn test_validate_config_board_threshold_over_one() {
    let mut config = default_config();
    config.board_pass_threshold = 1_000_001;
    assert!(validate_config(&config).is_err());
}

// ---------------------------------------------------------------------------
// evaluate_supremacy — basic cases
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_empty_measurements() {
    let config = default_config();
    let result = evaluate_supremacy(&[], &config, &epoch(), 1000);
    assert!(matches!(result, Err(VerdictError::NoMeasurements)));
}

#[test]
fn test_evaluate_single_cell_insufficient_data() {
    let config = default_config();
    let ms: Vec<_> = (0..5).map(|_| measurement("c1", 500, 1000)).collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    assert_eq!(report.cell_verdicts.len(), 1);
    assert_eq!(
        report.cell_verdicts[0].verdict,
        SupremacyVerdict::Inconclusive
    );
    assert_eq!(report.board_verdict, SupremacyVerdict::Inconclusive);
}

#[test]
fn test_evaluate_single_cell_confirmed() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..50).map(|_| measurement("c1", 500, 1000)).collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    assert_eq!(report.cell_verdicts[0].verdict, SupremacyVerdict::Confirmed);
    assert_eq!(report.board_verdict, SupremacyVerdict::Confirmed);
    assert_eq!(report.confirmed_fraction, 1_000_000);
}

#[test]
fn test_evaluate_single_cell_rejected_worse() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..50).map(|_| measurement("c1", 1000, 500)).collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    assert_eq!(report.cell_verdicts[0].verdict, SupremacyVerdict::Rejected);
    assert_eq!(report.board_verdict, SupremacyVerdict::Rejected);
}

#[test]
fn test_evaluate_equal_performance_rejected() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..50).map(|_| measurement("c1", 1000, 1000)).collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let cv = &report.cell_verdicts[0];
    assert!(
        cv.verdict == SupremacyVerdict::Rejected || cv.verdict == SupremacyVerdict::Inconclusive
    );
}

// ---------------------------------------------------------------------------
// Multi-cell scenarios
// ---------------------------------------------------------------------------

#[test]
fn test_evaluate_two_cells_both_confirmed() {
    let config = relaxed_config();
    let mut ms = Vec::new();
    for _ in 0..50 {
        ms.push(measurement("c1", 500, 1000));
        ms.push(measurement("c2", 400, 900));
    }
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    assert_eq!(report.cell_verdicts.len(), 2);
    assert_eq!(report.board_verdict, SupremacyVerdict::Confirmed);
}

#[test]
fn test_evaluate_mixed_cells_board_failure() {
    let config = relaxed_config();
    let mut ms = Vec::new();
    for _ in 0..50 {
        ms.push(measurement("c1", 500, 1000)); // confirmed
        ms.push(measurement("c2", 2000, 1000)); // rejected
        ms.push(measurement("c3", 2000, 1000)); // rejected
    }
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    // Only 1/3 confirmed = ~333k, below 800k threshold
    assert_eq!(report.board_verdict, SupremacyVerdict::Rejected);
}

#[test]
fn test_evaluate_five_cells_four_confirmed() {
    let mut config = relaxed_config();
    config.board_pass_threshold = 800_000; // 80%
    let mut ms = Vec::new();
    for _ in 0..50 {
        ms.push(measurement("c1", 500, 1000));
        ms.push(measurement("c2", 400, 900));
        ms.push(measurement("c3", 300, 800));
        ms.push(measurement("c4", 450, 950));
        ms.push(measurement("c5", 2000, 500)); // rejected
    }
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    // 4/5 = 800k, exactly meeting threshold
    assert_eq!(report.board_verdict, SupremacyVerdict::Confirmed);
}

#[test]
fn test_evaluate_all_cells_inconclusive() {
    let config = default_config();
    let ms: Vec<_> = (0..5)
        .map(|i| measurement(&format!("c{i}"), 500, 1000))
        .collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    assert_eq!(report.board_verdict, SupremacyVerdict::Inconclusive);
}

// ---------------------------------------------------------------------------
// Side-constraint violations
// ---------------------------------------------------------------------------

#[test]
fn test_crash_rate_violation() {
    let mut config = relaxed_config();
    config.max_crash_rate = 50_000; // 5%
    let mut ms: Vec<_> = (0..10).map(|_| measurement("c1", 500, 1000)).collect();
    for m in ms.iter_mut().take(3) {
        m.crash_observed = true;
    }
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let cv = &report.cell_verdicts[0];
    assert!(
        cv.violations
            .iter()
            .any(|v| v.kind == SideConstraintKind::CrashRate)
    );
    assert_eq!(cv.verdict, SupremacyVerdict::Rejected);
}

#[test]
fn test_crash_rate_within_threshold() {
    let mut config = relaxed_config();
    config.max_crash_rate = 200_000; // 20%
    let mut ms: Vec<_> = (0..20).map(|_| measurement("c1", 500, 1000)).collect();
    ms[0].crash_observed = true;
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let cv = &report.cell_verdicts[0];
    assert!(
        !cv.violations
            .iter()
            .any(|v| v.kind == SideConstraintKind::CrashRate)
    );
}

#[test]
fn test_all_observations_crash() {
    let mut config = relaxed_config();
    config.max_crash_rate = 1_000;
    let ms: Vec<_> = (0..10)
        .map(|_| measurement_with_crash("c1", 500, 1000))
        .collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let cv = &report.cell_verdicts[0];
    assert!(
        cv.violations
            .iter()
            .any(|v| v.kind == SideConstraintKind::CrashRate)
    );
}

#[test]
fn test_tail_regression_violation() {
    let mut config = relaxed_config();
    config.max_tail_regression = 50_000; // 5%
    let ms: Vec<_> = (0..30)
        .map(|_| measurement_with_tail("c1", 500, 1000, 2000, 1000))
        .collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let cv = &report.cell_verdicts[0];
    assert!(
        cv.violations
            .iter()
            .any(|v| v.kind == SideConstraintKind::TailLatencyRegression)
    );
}

#[test]
fn test_tail_no_regression_when_treatment_better() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..30)
        .map(|_| measurement_with_tail("c1", 500, 1000, 600, 1100))
        .collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let cv = &report.cell_verdicts[0];
    assert!(
        !cv.violations
            .iter()
            .any(|v| v.kind == SideConstraintKind::TailLatencyRegression)
    );
}

#[test]
fn test_observability_mismatch_violation() {
    let mut config = relaxed_config();
    config.required_observability_modes = vec![ObservabilityMode::ExactShadow];
    let ms: Vec<_> = (0..30)
        .map(|_| measurement_with_mode("c1", 500, 1000, ObservabilityMode::DegradedCapture))
        .collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let cv = &report.cell_verdicts[0];
    assert!(
        cv.violations
            .iter()
            .any(|v| v.kind == SideConstraintKind::ObservabilityMismatch)
    );
}

#[test]
fn test_observability_empty_allowed_modes() {
    let mut config = relaxed_config();
    config.required_observability_modes = vec![];
    let ms: Vec<_> = (0..30)
        .map(|_| measurement_with_mode("c1", 500, 1000, ObservabilityMode::DegradedCapture))
        .collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let cv = &report.cell_verdicts[0];
    assert!(
        !cv.violations
            .iter()
            .any(|v| v.kind == SideConstraintKind::ObservabilityMismatch)
    );
}

#[test]
fn test_memory_regression_violation() {
    let mut config = relaxed_config();
    config.max_memory_regression = 10_000; // 1%
    let ms: Vec<_> = (0..30)
        .map(|_| measurement_with_memory("c1", 500, 1000, 500_000))
        .collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let cv = &report.cell_verdicts[0];
    assert!(
        cv.violations
            .iter()
            .any(|v| v.kind == SideConstraintKind::MemoryRegression)
    );
}

#[test]
fn test_memory_improvement_no_violation() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..30)
        .map(|_| measurement_with_memory("c1", 500, 1000, -100_000))
        .collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let cv = &report.cell_verdicts[0];
    assert!(
        !cv.violations
            .iter()
            .any(|v| v.kind == SideConstraintKind::MemoryRegression)
    );
}

// ---------------------------------------------------------------------------
// Effect-size floor
// ---------------------------------------------------------------------------

#[test]
fn test_effect_size_below_floor_rejected() {
    let mut config = relaxed_config();
    config.min_effect_size = 500_000; // 0.5 Cohen's d — very high bar
    // Marginal improvement
    let ms: Vec<_> = (0..50).map(|_| measurement("c1", 950, 1000)).collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let cv = &report.cell_verdicts[0];
    assert!(
        cv.rejection_reasons
            .contains(&RejectionReason::BelowEffectSizeFloor)
    );
}

#[test]
fn test_effect_size_above_floor_passes() {
    let config = relaxed_config();
    // Strong improvement
    let ms: Vec<_> = (0..50).map(|_| measurement("c1", 200, 1000)).collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let cv = &report.cell_verdicts[0];
    assert!(
        !cv.rejection_reasons
            .contains(&RejectionReason::BelowEffectSizeFloor)
    );
}

// ---------------------------------------------------------------------------
// Receipt tests
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_fields_populated() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..10).map(|_| measurement("c1", 500, 1000)).collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 99999).unwrap();
    assert_eq!(report.receipt.schema_version, SCHEMA_VERSION);
    assert_eq!(report.receipt.component, COMPONENT);
    assert_eq!(report.receipt.bead_id, BEAD_ID);
    assert_eq!(report.receipt.policy_id, POLICY_ID);
    assert_eq!(report.receipt.epoch, 100);
    assert_eq!(report.receipt.timestamp_micros, 99999);
}

#[test]
fn test_receipt_deterministic() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..20).map(|_| measurement("c1", 500, 1000)).collect();
    let r1 = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let r2 = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    assert_eq!(r1.receipt.input_hash, r2.receipt.input_hash);
    assert_eq!(r1.receipt.verdict_hash, r2.receipt.verdict_hash);
}

#[test]
fn test_receipt_changes_with_different_input() {
    let config = relaxed_config();
    let ms1: Vec<_> = (0..20).map(|_| measurement("c1", 500, 1000)).collect();
    let ms2: Vec<_> = (0..20).map(|_| measurement("c1", 600, 1000)).collect();
    let r1 = evaluate_supremacy(&ms1, &config, &epoch(), 1000).unwrap();
    let r2 = evaluate_supremacy(&ms2, &config, &epoch(), 1000).unwrap();
    assert_ne!(r1.receipt.input_hash, r2.receipt.input_hash);
}

#[test]
fn test_receipt_serde_roundtrip() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..10).map(|_| measurement("c1", 500, 1000)).collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let json = serde_json::to_string(&report.receipt).unwrap();
    let parsed: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(report.receipt, parsed);
}

// ---------------------------------------------------------------------------
// VerdictReport serde
// ---------------------------------------------------------------------------

#[test]
fn test_verdict_report_serde_roundtrip() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..30).map(|_| measurement("c1", 500, 1000)).collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let parsed: VerdictReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, parsed);
}

#[test]
fn test_cell_verdict_serde_roundtrip() {
    let cv = CellVerdict {
        cell_id: "c1".into(),
        verdict: SupremacyVerdict::Confirmed,
        rejection_reasons: Vec::new(),
        n_observations: 50,
        effect_size: 500_000,
        cv_treatment: 100_000,
        violations: Vec::new(),
        final_llr: 12345,
        mean_improvement_ratio: 400_000,
    };
    let json = serde_json::to_string(&cv).unwrap();
    let parsed: CellVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(cv, parsed);
}

#[test]
fn test_cell_measurement_serde_roundtrip() {
    let m = measurement("c1", 500, 1000);
    let json = serde_json::to_string(&m).unwrap();
    let parsed: CellMeasurement = serde_json::from_str(&json).unwrap();
    assert_eq!(m, parsed);
}

#[test]
fn test_side_constraint_violation_serde_roundtrip() {
    let v = SideConstraintViolation {
        kind: SideConstraintKind::CrashRate,
        cell_id: "c1".into(),
        observed: 300_000,
        threshold: 1_000,
        detail: "high crash rate".into(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let parsed: SideConstraintViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, parsed);
}

// ---------------------------------------------------------------------------
// summarize_report tests
// ---------------------------------------------------------------------------

#[test]
fn test_summarize_report_confirmed() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..50).map(|_| measurement("c1", 500, 1000)).collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let summary = summarize_report(&report);
    assert!(summary.contains("Board verdict:"));
    assert!(summary.contains("c1"));
}

#[test]
fn test_summarize_report_rejected_with_violations() {
    let mut config = relaxed_config();
    config.max_crash_rate = 1;
    let ms: Vec<_> = (0..10)
        .map(|_| measurement_with_crash("c1", 500, 1000))
        .collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let summary = summarize_report(&report);
    assert!(summary.contains("violations"));
}

#[test]
fn test_summarize_multi_cell() {
    let config = relaxed_config();
    let mut ms = Vec::new();
    for _ in 0..30 {
        ms.push(measurement("alpha", 500, 1000));
        ms.push(measurement("beta", 400, 900));
    }
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    let summary = summarize_report(&report);
    assert!(summary.contains("alpha"));
    assert!(summary.contains("beta"));
}

// ---------------------------------------------------------------------------
// Error display tests
// ---------------------------------------------------------------------------

#[test]
fn test_error_display_no_measurements() {
    assert_eq!(
        format!("{}", VerdictError::NoMeasurements),
        "no measurements provided"
    );
}

#[test]
fn test_error_display_too_many_cells() {
    let err = VerdictError::TooManyCells { count: 500 };
    let msg = format!("{err}");
    assert!(msg.contains("500"));
    assert!(msg.contains("256"));
}

#[test]
fn test_error_display_too_many_constraints() {
    let err = VerdictError::TooManySideConstraints { count: 99 };
    let msg = format!("{err}");
    assert!(msg.contains("99"));
}

#[test]
fn test_error_display_invalid_config() {
    let err = VerdictError::InvalidConfig {
        field: "alpha".into(),
        detail: "out of range".into(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("alpha"));
    assert!(msg.contains("out of range"));
}

#[test]
fn test_error_display_unknown_cell() {
    let err = VerdictError::UnknownCell {
        cell_id: "mystery".into(),
    };
    assert!(format!("{err}").contains("mystery"));
}

#[test]
fn test_error_serde_roundtrip() {
    let err = VerdictError::NoMeasurements;
    let json = serde_json::to_string(&err).unwrap();
    let parsed: VerdictError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, parsed);
}

// ---------------------------------------------------------------------------
// Constants tests
// ---------------------------------------------------------------------------

#[test]
fn test_constants() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.supremacy-verdict-engine.v1");
    assert_eq!(COMPONENT, "supremacy_verdict_engine");
    assert_eq!(BEAD_ID, "bd-1lsy.8.5.2");
    assert_eq!(POLICY_ID, "RGC-705B");
}

#[test]
fn test_default_constants() {
    assert_eq!(DEFAULT_MIN_OBSERVATIONS, 30);
    assert_eq!(DEFAULT_ALPHA, 50_000);
    assert_eq!(DEFAULT_BETA, 200_000);
    assert_eq!(DEFAULT_MIN_EFFECT_SIZE, 200_000);
    assert_eq!(DEFAULT_MAX_CV, 150_000);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_zero_baseline_ns() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..10).map(|_| measurement("c1", 100, 0)).collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    // Should not panic — just produce some verdict
    assert!(!report.cell_verdicts.is_empty());
}

#[test]
fn test_large_treatment_values() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..30)
        .map(|_| measurement("c1", u64::MAX / 2, u64::MAX / 2 + 1000))
        .collect();
    // Should not panic with large values
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    assert!(!report.cell_verdicts.is_empty());
}

#[test]
fn test_single_observation_per_cell() {
    let config = relaxed_config();
    let ms = vec![measurement("c1", 500, 1000)];
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    assert_eq!(report.cell_verdicts[0].n_observations, 1);
}

#[test]
fn test_many_cells() {
    let config = relaxed_config();
    let ms: Vec<_> = (0..200)
        .map(|i| measurement(&format!("cell_{i}"), 500, 1000))
        .collect();
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    assert_eq!(report.cell_verdicts.len(), 200);
}

#[test]
fn test_confirmed_fraction_calculation() {
    let config = relaxed_config();
    let mut ms = Vec::new();
    for _ in 0..50 {
        ms.push(measurement("c1", 500, 1000)); // confirmed
        ms.push(measurement("c2", 500, 1000)); // confirmed
    }
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    assert_eq!(report.confirmed_fraction, 1_000_000);
}

#[test]
fn test_total_violations_count() {
    let mut config = relaxed_config();
    config.max_crash_rate = 1;
    let mut ms = Vec::new();
    for _ in 0..10 {
        ms.push(measurement_with_crash("c1", 500, 1000));
        ms.push(measurement_with_crash("c2", 500, 1000));
    }
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    assert!(report.total_violations >= 2);
}

#[test]
fn test_board_rejection_reasons_populated() {
    let config = relaxed_config();
    let mut ms = Vec::new();
    for _ in 0..30 {
        ms.push(measurement("c1", 2000, 500)); // rejected
    }
    let report = evaluate_supremacy(&ms, &config, &epoch(), 1000).unwrap();
    assert!(!report.board_rejection_reasons.is_empty());
}

#[test]
fn test_mixed_observability_modes() {
    let config = relaxed_config();
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
    // Both modes are in the default required set — no violation
    let cv = &report.cell_verdicts[0];
    assert!(
        !cv.violations
            .iter()
            .any(|v| v.kind == SideConstraintKind::ObservabilityMismatch)
    );
}
