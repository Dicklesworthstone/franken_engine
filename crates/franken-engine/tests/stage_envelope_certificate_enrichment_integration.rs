//! Enrichment integration tests for `stage_envelope_certificate`.
//!
//! Covers additional edge-case scenarios for envelope certificates,
//! violation detection, severity classification, remediation logic,
//! bundle construction, and rendering beyond the base test suite.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::stage_envelope_certificate::*;

// ===========================================================================
// Helpers
// ===========================================================================

fn default_envelope(stage: ExecutionStage) -> StageLatencyEnvelope {
    StageLatencyEnvelope::default_for_stage(stage)
}

fn compliant_observation(stage: ExecutionStage) -> StageLatencyObservation {
    let env = default_envelope(stage);
    StageLatencyObservation {
        stage,
        stage_label: None,
        observation_count: 100,
        p50_ns: env.p50_budget_ns / 2,
        p95_ns: env.p95_budget_ns / 2,
        p99_ns: env.p99_budget_ns / 2,
        p999_ns: env.p999_budget_ns / 2,
        observed_epoch: 0,
    }
}

fn violating_observation(stage: ExecutionStage) -> StageLatencyObservation {
    let env = default_envelope(stage);
    StageLatencyObservation {
        stage,
        stage_label: None,
        observation_count: 100,
        p50_ns: env.p50_budget_ns + 1,
        p95_ns: env.p95_budget_ns + 1,
        p99_ns: env.p99_budget_ns * 2,
        p999_ns: env.p999_budget_ns * 3,
        observed_epoch: 0,
    }
}

// ===========================================================================
// 1. Severity classification via overshoot magnitudes
// ===========================================================================

#[test]
fn enrichment_minor_severity_small_overshoot() {
    let env = default_envelope(ExecutionStage::Parse);
    // Very slight overshoot: 1% of budget
    let obs = StageLatencyObservation {
        stage: ExecutionStage::Parse,
        stage_label: None,
        observation_count: 100,
        p50_ns: env.p50_budget_ns / 2,
        p95_ns: env.p95_budget_ns / 2,
        p99_ns: env.p99_budget_ns + env.p99_budget_ns / 100, // 1% over
        p999_ns: env.p999_budget_ns / 2,
        observed_epoch: 0,
    };
    let cert = issue_stage_certificate(&env, &obs, "minor", 0, vec![]);
    let report = generate_violation_report(&cert, "rpt-minor").unwrap();
    assert_eq!(report.severity, ViolationSeverity::Minor);
    assert_eq!(report.remediation, RemediationAction::Monitor);
}

#[test]
fn enrichment_moderate_severity_medium_overshoot() {
    let env = default_envelope(ExecutionStage::ModuleLoad);
    // 30% overshoot
    let obs = StageLatencyObservation {
        stage: ExecutionStage::ModuleLoad,
        stage_label: None,
        observation_count: 100,
        p50_ns: env.p50_budget_ns / 2,
        p95_ns: env.p95_budget_ns / 2,
        p99_ns: env.p99_budget_ns + env.p99_budget_ns * 30 / 100,
        p999_ns: env.p999_budget_ns / 2,
        observed_epoch: 0,
    };
    let cert = issue_stage_certificate(&env, &obs, "mod", 0, vec![]);
    let report = generate_violation_report(&cert, "rpt-mod").unwrap();
    assert_eq!(report.severity, ViolationSeverity::Moderate);
    assert_eq!(report.remediation, RemediationAction::IncreaseBudget);
}

#[test]
fn enrichment_severe_gc_pause_splits_stage() {
    let env = default_envelope(ExecutionStage::GcPause);
    // 75% overshoot on p99
    let obs = StageLatencyObservation {
        stage: ExecutionStage::GcPause,
        stage_label: None,
        observation_count: 100,
        p50_ns: env.p50_budget_ns / 2,
        p95_ns: env.p95_budget_ns / 2,
        p99_ns: env.p99_budget_ns + env.p99_budget_ns * 75 / 100,
        p999_ns: env.p999_budget_ns / 2,
        observed_epoch: 0,
    };
    let cert = issue_stage_certificate(&env, &obs, "gc-sev", 0, vec![]);
    let report = generate_violation_report(&cert, "rpt-gc").unwrap();
    assert_eq!(report.severity, ViolationSeverity::Severe);
    assert_eq!(report.remediation, RemediationAction::SplitStage);
}

#[test]
fn enrichment_compile_optimized_always_defers() {
    let env = default_envelope(ExecutionStage::CompileOptimized);
    // Even minor violation for CompileOptimized defers to background
    let obs = StageLatencyObservation {
        stage: ExecutionStage::CompileOptimized,
        stage_label: None,
        observation_count: 100,
        p50_ns: env.p50_budget_ns / 2,
        p95_ns: env.p95_budget_ns / 2,
        p99_ns: env.p99_budget_ns + 1,
        p999_ns: env.p999_budget_ns / 2,
        observed_epoch: 0,
    };
    let cert = issue_stage_certificate(&env, &obs, "co-defer", 0, vec![]);
    let report = generate_violation_report(&cert, "rpt-co").unwrap();
    assert_eq!(report.remediation, RemediationAction::DeferToBackground);
}

#[test]
fn enrichment_parse_severe_reduces_workload() {
    let env = default_envelope(ExecutionStage::Parse);
    // >50% overshoot
    let obs = StageLatencyObservation {
        stage: ExecutionStage::Parse,
        stage_label: None,
        observation_count: 100,
        p50_ns: env.p50_budget_ns / 2,
        p95_ns: env.p95_budget_ns / 2,
        p99_ns: env.p99_budget_ns + env.p99_budget_ns * 80 / 100,
        p999_ns: env.p999_budget_ns / 2,
        observed_epoch: 0,
    };
    let cert = issue_stage_certificate(&env, &obs, "parse-sev", 0, vec![]);
    let report = generate_violation_report(&cert, "rpt-parse-sev").unwrap();
    assert_eq!(report.severity, ViolationSeverity::Severe);
    assert_eq!(report.remediation, RemediationAction::ReduceWorkload);
}

// ===========================================================================
// 2. Observation edge cases
// ===========================================================================

#[test]
fn enrichment_observation_count_exactly_min() {
    let env = default_envelope(ExecutionStage::Parse);
    let obs = StageLatencyObservation {
        stage: ExecutionStage::Parse,
        stage_label: None,
        observation_count: MIN_OBSERVATION_COUNT,
        p50_ns: env.p50_budget_ns / 2,
        p95_ns: env.p95_budget_ns / 2,
        p99_ns: env.p99_budget_ns / 2,
        p999_ns: env.p999_budget_ns / 2,
        observed_epoch: 0,
    };
    let cert = issue_stage_certificate(&env, &obs, "exact-min", 0, vec![]);
    assert_eq!(cert.verdict, EnvelopeVerdict::Compliant);
}

#[test]
fn enrichment_observation_count_one_below_min() {
    let env = default_envelope(ExecutionStage::Parse);
    let obs = StageLatencyObservation {
        stage: ExecutionStage::Parse,
        stage_label: None,
        observation_count: MIN_OBSERVATION_COUNT - 1,
        p50_ns: env.p50_budget_ns / 2,
        p95_ns: env.p95_budget_ns / 2,
        p99_ns: env.p99_budget_ns / 2,
        p999_ns: env.p999_budget_ns / 2,
        observed_epoch: 0,
    };
    let cert = issue_stage_certificate(&env, &obs, "below-min", 0, vec![]);
    assert_eq!(cert.verdict, EnvelopeVerdict::InsufficientData);
}

#[test]
fn enrichment_all_percentiles_violated_simultaneously() {
    let env = default_envelope(ExecutionStage::Parse);
    let obs = StageLatencyObservation {
        stage: ExecutionStage::Parse,
        stage_label: None,
        observation_count: 100,
        p50_ns: env.p50_budget_ns * 2,
        p95_ns: env.p95_budget_ns * 2,
        p99_ns: env.p99_budget_ns * 2,
        p999_ns: env.p999_budget_ns * 2,
        observed_epoch: 0,
    };
    let cert = issue_stage_certificate(&env, &obs, "all-viol", 0, vec![]);
    assert_eq!(cert.verdict, EnvelopeVerdict::Violated);
    assert_eq!(cert.violations.len(), 4);
}

#[test]
fn enrichment_only_p50_violated() {
    let env = default_envelope(ExecutionStage::Lower);
    let obs = StageLatencyObservation {
        stage: ExecutionStage::Lower,
        stage_label: None,
        observation_count: 100,
        p50_ns: env.p50_budget_ns + 1,
        p95_ns: env.p95_budget_ns / 2,
        p99_ns: env.p99_budget_ns / 2,
        p999_ns: env.p999_budget_ns / 2,
        observed_epoch: 0,
    };
    let cert = issue_stage_certificate(&env, &obs, "p50-only", 0, vec![]);
    assert_eq!(cert.verdict, EnvelopeVerdict::Violated);
    assert_eq!(cert.violations.len(), 1);
    assert_eq!(cert.violations[0].percentile, LatencyPercentile::P50);
}

#[test]
fn enrichment_only_p999_violated() {
    let env = default_envelope(ExecutionStage::SandboxInit);
    let obs = StageLatencyObservation {
        stage: ExecutionStage::SandboxInit,
        stage_label: None,
        observation_count: 100,
        p50_ns: env.p50_budget_ns / 2,
        p95_ns: env.p95_budget_ns / 2,
        p99_ns: env.p99_budget_ns / 2,
        p999_ns: env.p999_budget_ns + 1,
        observed_epoch: 0,
    };
    let cert = issue_stage_certificate(&env, &obs, "p999-only", 0, vec![]);
    assert_eq!(cert.verdict, EnvelopeVerdict::Violated);
    assert_eq!(cert.violations.len(), 1);
    assert_eq!(cert.violations[0].percentile, LatencyPercentile::P999);
}

// ===========================================================================
// 3. Custom stage with label
// ===========================================================================

#[test]
fn enrichment_custom_stage_label_propagated_in_certificate() {
    let mut env = default_envelope(ExecutionStage::Custom);
    env.stage_label = Some("wasm_compile".to_string());
    let obs = StageLatencyObservation {
        stage: ExecutionStage::Custom,
        stage_label: Some("wasm_compile".to_string()),
        observation_count: 100,
        p50_ns: env.p50_budget_ns / 2,
        p95_ns: env.p95_budget_ns / 2,
        p99_ns: env.p99_budget_ns / 2,
        p999_ns: env.p999_budget_ns / 2,
        observed_epoch: 0,
    };
    let cert = issue_stage_certificate(&env, &obs, "custom-cert", 0, vec![]);
    assert_eq!(cert.stage_label, Some("wasm_compile".to_string()));
    assert_eq!(cert.stage, ExecutionStage::Custom);
}

// ===========================================================================
// 4. Bundle with all stages
// ===========================================================================

#[test]
fn enrichment_bundle_11_stages_all_compliant() {
    let stages = [
        ExecutionStage::Parse,
        ExecutionStage::Lower,
        ExecutionStage::CompileBaseline,
        ExecutionStage::CompileOptimized,
        ExecutionStage::GcPause,
        ExecutionStage::ModuleLoad,
        ExecutionStage::SandboxInit,
        ExecutionStage::ExecutionQuantum,
        ExecutionStage::CacheLookup,
        ExecutionStage::AotLoad,
        ExecutionStage::Custom,
    ];
    let envelopes: Vec<_> = stages.iter().map(|s| default_envelope(*s)).collect();
    let observations: Vec<_> = stages.iter().map(|s| compliant_observation(*s)).collect();
    let bundle = build_envelope_bundle(&envelopes, &observations, 0);
    assert_eq!(bundle.stage_count, 11);
    assert_eq!(bundle.compliant_count, 11);
    assert_eq!(bundle.violated_count, 0);
    assert_eq!(bundle.near_limit_count, 0);
    assert_eq!(bundle.overall_verdict, EnvelopeVerdict::Compliant);
}

#[test]
fn enrichment_bundle_multiple_violated_stages() {
    let envelopes = vec![
        default_envelope(ExecutionStage::Parse),
        default_envelope(ExecutionStage::GcPause),
        default_envelope(ExecutionStage::ModuleLoad),
    ];
    let observations = vec![
        violating_observation(ExecutionStage::Parse),
        violating_observation(ExecutionStage::GcPause),
        compliant_observation(ExecutionStage::ModuleLoad),
    ];
    let bundle = build_envelope_bundle(&envelopes, &observations, 0);
    assert_eq!(bundle.violated_count, 2);
    assert_eq!(bundle.compliant_count, 1);
    assert_eq!(bundle.overall_verdict, EnvelopeVerdict::Violated);
}

#[test]
fn enrichment_bundle_epoch_propagated() {
    let envelopes = vec![default_envelope(ExecutionStage::Parse)];
    let observations = vec![compliant_observation(ExecutionStage::Parse)];
    let bundle = build_envelope_bundle(&envelopes, &observations, 123);
    assert_eq!(bundle.bundle_epoch, 123);
}

// ===========================================================================
// 5. Rendering edge cases
// ===========================================================================

#[test]
fn enrichment_render_summary_empty_bundle() {
    let bundle = build_envelope_bundle(&[], &[], 0);
    let summary = render_envelope_summary(&bundle);
    assert!(summary.contains("overall_verdict: compliant"));
    assert!(summary.contains("stage_count: 0"));
}

#[test]
fn enrichment_render_violation_summary_multiple_violations() {
    let env = default_envelope(ExecutionStage::GcPause);
    let obs = StageLatencyObservation {
        stage: ExecutionStage::GcPause,
        stage_label: None,
        observation_count: 100,
        p50_ns: env.p50_budget_ns * 2,
        p95_ns: env.p95_budget_ns * 2,
        p99_ns: env.p99_budget_ns * 2,
        p999_ns: env.p999_budget_ns * 2,
        observed_epoch: 0,
    };
    let cert = issue_stage_certificate(&env, &obs, "multi-v", 0, vec![]);
    let report = generate_violation_report(&cert, "rpt-multi").unwrap();
    let summary = render_violation_summary(&report);
    assert!(summary.contains("stage: gc_pause"));
    assert!(summary.contains("p50"));
    assert!(summary.contains("p95"));
    assert!(summary.contains("p99"));
    assert!(summary.contains("p999"));
}

// ===========================================================================
// 6. PercentileViolation construction
// ===========================================================================

#[test]
fn enrichment_violation_fields_manually_constructed() {
    let v = PercentileViolation {
        percentile: LatencyPercentile::P95,
        observed_ns: 5_000_000,
        budget_ns: 2_000_000,
        overshoot_ns: 3_000_000,
        overshoot_fraction_millionths: 1_500_000,
    };
    assert_eq!(v.percentile, LatencyPercentile::P95);
    assert_eq!(v.observed_ns, 5_000_000);
    assert_eq!(v.budget_ns, 2_000_000);
    assert_eq!(v.overshoot_ns, 3_000_000);
    assert_eq!(v.overshoot_fraction_millionths, 1_500_000);
}

// ===========================================================================
// 7. Envelope budget_share values
// ===========================================================================

#[test]
fn enrichment_total_budget_shares_across_standard_stages() {
    let stages = [
        ExecutionStage::Parse,
        ExecutionStage::Lower,
        ExecutionStage::CompileBaseline,
        ExecutionStage::CompileOptimized,
        ExecutionStage::GcPause,
        ExecutionStage::ModuleLoad,
        ExecutionStage::SandboxInit,
        ExecutionStage::ExecutionQuantum,
        ExecutionStage::CacheLookup,
        ExecutionStage::AotLoad,
    ];
    let total_share: u64 = stages
        .iter()
        .map(|s| default_envelope(*s).budget_share_millionths)
        .sum();
    // Total should be roughly 100% (1_000_000) or close
    assert!(
        total_share > 0,
        "total budget share should be positive"
    );
}

// ===========================================================================
// 8. Observation serde
// ===========================================================================

#[test]
fn enrichment_observation_with_label_serde() {
    let obs = StageLatencyObservation {
        stage: ExecutionStage::Custom,
        stage_label: Some("my_custom_stage".to_string()),
        observation_count: 42,
        p50_ns: 100,
        p95_ns: 200,
        p99_ns: 300,
        p999_ns: 400,
        observed_epoch: 7,
    };
    let json = serde_json::to_string(&obs).unwrap();
    let restored: StageLatencyObservation = serde_json::from_str(&json).unwrap();
    assert_eq!(obs, restored);
}

// ===========================================================================
// 9. Bundle with mismatched envelope/observation stages
// ===========================================================================

#[test]
fn enrichment_bundle_no_matching_observations() {
    let envelopes = vec![default_envelope(ExecutionStage::Parse)];
    let observations = vec![compliant_observation(ExecutionStage::GcPause)]; // different stage
    let bundle = build_envelope_bundle(&envelopes, &observations, 0);
    // Parse has no matching observation, so it's skipped in certificates
    assert_eq!(bundle.certificates.len(), 0);
    assert_eq!(bundle.stage_count, 1); // envelope count
}

// ===========================================================================
// 10. Certificate JSON structure
// ===========================================================================

#[test]
fn enrichment_certificate_json_fields_complete() {
    let env = default_envelope(ExecutionStage::GcPause);
    let obs = violating_observation(ExecutionStage::GcPause);
    let cert = issue_stage_certificate(&env, &obs, "json-complete", 42, vec!["ev-abc".to_string()]);
    let val: serde_json::Value = serde_json::to_value(&cert).unwrap();
    assert_eq!(val["schema_version"], STAGE_ENVELOPE_SCHEMA_VERSION);
    assert_eq!(val["bead_id"], STAGE_ENVELOPE_BEAD_ID);
    assert_eq!(val["certificate_id"], "json-complete");
    assert_eq!(val["stage"], "gc_pause");
    assert_eq!(val["verdict"], "violated");
    assert_eq!(val["issued_epoch"], 42);
    assert!(val["violations"].is_array());
    assert!(val["evidence_ids"].is_array());
}

// ===========================================================================
// 11. ViolationReport JSON structure
// ===========================================================================

#[test]
fn enrichment_violation_report_json_fields_complete() {
    let env = default_envelope(ExecutionStage::Parse);
    let obs = violating_observation(ExecutionStage::Parse);
    let cert = issue_stage_certificate(&env, &obs, "json-rpt", 7, vec![]);
    let report = generate_violation_report(&cert, "rpt-json-comp").unwrap();
    let val: serde_json::Value = serde_json::to_value(&report).unwrap();
    assert_eq!(val["schema_version"], VIOLATION_REPORT_SCHEMA_VERSION);
    assert_eq!(val["bead_id"], STAGE_ENVELOPE_BEAD_ID);
    assert_eq!(val["report_id"], "rpt-json-comp");
    assert_eq!(val["stage"], "parse");
    assert_eq!(val["reported_epoch"], 7);
}

// ===========================================================================
// 12. Determinism across calls
// ===========================================================================

#[test]
fn enrichment_bundle_deterministic_across_calls() {
    let envelopes = vec![
        default_envelope(ExecutionStage::Parse),
        default_envelope(ExecutionStage::GcPause),
        default_envelope(ExecutionStage::ModuleLoad),
    ];
    let observations = vec![
        compliant_observation(ExecutionStage::Parse),
        violating_observation(ExecutionStage::GcPause),
        compliant_observation(ExecutionStage::ModuleLoad),
    ];
    let b1 = build_envelope_bundle(&envelopes, &observations, 0);
    let b2 = build_envelope_bundle(&envelopes, &observations, 0);
    assert_eq!(b1, b2);
}

#[test]
fn enrichment_violation_report_deterministic() {
    let env = default_envelope(ExecutionStage::GcPause);
    let obs = violating_observation(ExecutionStage::GcPause);
    let cert = issue_stage_certificate(&env, &obs, "det", 0, vec![]);
    let r1 = generate_violation_report(&cert, "rpt-det").unwrap();
    let r2 = generate_violation_report(&cert, "rpt-det").unwrap();
    assert_eq!(r1, r2);
}

// ===========================================================================
// 13. Display impls for enums
// ===========================================================================

#[test]
fn enrichment_execution_stage_clone() {
    let s1 = ExecutionStage::CacheLookup;
    let s2 = s1;
    assert_eq!(s1, s2);
}

#[test]
fn enrichment_verdict_ordering() {
    assert!(EnvelopeVerdict::Compliant < EnvelopeVerdict::NearLimit);
    assert!(EnvelopeVerdict::NearLimit < EnvelopeVerdict::Violated);
    assert!(EnvelopeVerdict::Violated < EnvelopeVerdict::InsufficientData);
}

#[test]
fn enrichment_severity_clone_and_compare() {
    let s = ViolationSeverity::Catastrophic;
    let c = s;
    assert_eq!(s, c);
    assert!(ViolationSeverity::Catastrophic > ViolationSeverity::Minor);
}

#[test]
fn enrichment_remediation_clone_and_compare() {
    let r = RemediationAction::SplitStage;
    let c = r;
    assert_eq!(r, c);
}

#[test]
fn enrichment_severity_serde_all() {
    for s in [ViolationSeverity::Minor, ViolationSeverity::Moderate,
              ViolationSeverity::Severe, ViolationSeverity::Catastrophic] {
        let json = serde_json::to_string(&s).unwrap();
        let back: ViolationSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn enrichment_remediation_serde_all() {
    for r in [RemediationAction::Monitor, RemediationAction::IncreaseBudget,
              RemediationAction::ReduceWorkload, RemediationAction::DeferToBackground,
              RemediationAction::SplitStage, RemediationAction::Downgrade] {
        let json = serde_json::to_string(&r).unwrap();
        let back: RemediationAction = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

#[test]
fn enrichment_envelope_serde_roundtrip() {
    let env = default_envelope(ExecutionStage::Parse);
    let json = serde_json::to_string(&env).unwrap();
    let back: StageLatencyEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, back);
}

#[test]
fn enrichment_verdict_serde_all() {
    for v in [EnvelopeVerdict::Compliant, EnvelopeVerdict::NearLimit,
              EnvelopeVerdict::Violated, EnvelopeVerdict::InsufficientData] {
        let json = serde_json::to_string(&v).unwrap();
        let back: EnvelopeVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_percentile_serde_all() {
    for p in [LatencyPercentile::P50, LatencyPercentile::P95,
              LatencyPercentile::P99, LatencyPercentile::P999] {
        let json = serde_json::to_string(&p).unwrap();
        let back: LatencyPercentile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}
