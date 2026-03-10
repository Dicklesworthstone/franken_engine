#![forbid(unsafe_code)]

//! Integration tests for stage-envelope certificates and violation detectors
//! (bd-1lsy.7.11.1 [RGC-611A]).

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

fn near_limit_observation(stage: ExecutionStage) -> StageLatencyObservation {
    let env = default_envelope(stage);
    StageLatencyObservation {
        stage,
        stage_label: None,
        observation_count: 100,
        p50_ns: env.p50_budget_ns * 85 / 100,
        p95_ns: env.p95_budget_ns * 85 / 100,
        p99_ns: env.p99_budget_ns * 85 / 100,
        p999_ns: env.p999_budget_ns * 85 / 100,
        observed_epoch: 0,
    }
}

fn insufficient_observation(stage: ExecutionStage) -> StageLatencyObservation {
    StageLatencyObservation {
        stage,
        stage_label: None,
        observation_count: 5, // below MIN_OBSERVATION_COUNT
        p50_ns: 100,
        p95_ns: 200,
        p99_ns: 300,
        p999_ns: 400,
        observed_epoch: 0,
    }
}

// ===========================================================================
// 1. Schema constants
// ===========================================================================

#[test]
fn schema_version_strings_are_non_empty() {
    assert!(!STAGE_ENVELOPE_SCHEMA_VERSION.is_empty());
    assert!(!VIOLATION_REPORT_SCHEMA_VERSION.is_empty());
    assert!(!ENVELOPE_BUNDLE_SCHEMA_VERSION.is_empty());
}

#[test]
fn schema_version_strings_follow_convention() {
    assert!(STAGE_ENVELOPE_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(VIOLATION_REPORT_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(ENVELOPE_BUNDLE_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn bead_id_is_correct() {
    assert_eq!(STAGE_ENVELOPE_BEAD_ID, "bd-1lsy.7.11.1");
}

#[test]
fn default_constants_are_sane() {
    const { assert!(DEFAULT_P999_BUDGET_NS > DEFAULT_P99_BUDGET_NS) };
    const { assert!(DEFAULT_P99_BUDGET_NS > 0) };
    const { assert!(MIN_OBSERVATION_COUNT > 0) };
}

// ===========================================================================
// 2. ExecutionStage enum
// ===========================================================================

#[test]
fn stage_display_all_variants() {
    let stages = [
        (ExecutionStage::Parse, "parse"),
        (ExecutionStage::Lower, "lower"),
        (ExecutionStage::CompileBaseline, "compile_baseline"),
        (ExecutionStage::CompileOptimized, "compile_optimized"),
        (ExecutionStage::GcPause, "gc_pause"),
        (ExecutionStage::ModuleLoad, "module_load"),
        (ExecutionStage::SandboxInit, "sandbox_init"),
        (ExecutionStage::ExecutionQuantum, "execution_quantum"),
        (ExecutionStage::CacheLookup, "cache_lookup"),
        (ExecutionStage::AotLoad, "aot_load"),
        (ExecutionStage::Custom, "custom"),
    ];
    for (stage, expected) in &stages {
        assert_eq!(stage.to_string(), *expected);
    }
}

#[test]
fn stage_serde_round_trip_all_variants() {
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
    for stage in &stages {
        let json = serde_json::to_string(stage).expect("serialize");
        let deser: ExecutionStage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*stage, deser);
    }
}

#[test]
fn stage_ordering() {
    assert!(ExecutionStage::Parse < ExecutionStage::Lower);
    assert!(ExecutionStage::Lower < ExecutionStage::CompileBaseline);
}

// ===========================================================================
// 3. LatencyPercentile
// ===========================================================================

#[test]
fn percentile_display_all() {
    assert_eq!(LatencyPercentile::P50.to_string(), "p50");
    assert_eq!(LatencyPercentile::P95.to_string(), "p95");
    assert_eq!(LatencyPercentile::P99.to_string(), "p99");
    assert_eq!(LatencyPercentile::P999.to_string(), "p999");
}

#[test]
fn percentile_rank_millionths_values() {
    assert_eq!(LatencyPercentile::P50.rank_millionths(), 500_000);
    assert_eq!(LatencyPercentile::P95.rank_millionths(), 950_000);
    assert_eq!(LatencyPercentile::P99.rank_millionths(), 990_000);
    assert_eq!(LatencyPercentile::P999.rank_millionths(), 999_000);
}

#[test]
fn percentile_serde_round_trip_all() {
    for p in &[
        LatencyPercentile::P50,
        LatencyPercentile::P95,
        LatencyPercentile::P99,
        LatencyPercentile::P999,
    ] {
        let json = serde_json::to_string(p).expect("serialize");
        let deser: LatencyPercentile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*p, deser);
    }
}

#[test]
fn percentile_ordering() {
    assert!(LatencyPercentile::P50 < LatencyPercentile::P95);
    assert!(LatencyPercentile::P95 < LatencyPercentile::P99);
    assert!(LatencyPercentile::P99 < LatencyPercentile::P999);
}

// ===========================================================================
// 4. EnvelopeVerdict
// ===========================================================================

#[test]
fn verdict_display_all() {
    assert_eq!(EnvelopeVerdict::Compliant.to_string(), "compliant");
    assert_eq!(EnvelopeVerdict::NearLimit.to_string(), "near_limit");
    assert_eq!(EnvelopeVerdict::Violated.to_string(), "violated");
    assert_eq!(
        EnvelopeVerdict::InsufficientData.to_string(),
        "insufficient_data"
    );
}

#[test]
fn verdict_serde_round_trip_all() {
    for v in &[
        EnvelopeVerdict::Compliant,
        EnvelopeVerdict::NearLimit,
        EnvelopeVerdict::Violated,
        EnvelopeVerdict::InsufficientData,
    ] {
        let json = serde_json::to_string(v).expect("serialize");
        let deser: EnvelopeVerdict = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*v, deser);
    }
}

// ===========================================================================
// 5. ViolationSeverity
// ===========================================================================

#[test]
fn severity_display_all() {
    assert_eq!(ViolationSeverity::Minor.to_string(), "minor");
    assert_eq!(ViolationSeverity::Moderate.to_string(), "moderate");
    assert_eq!(ViolationSeverity::Severe.to_string(), "severe");
    assert_eq!(ViolationSeverity::Catastrophic.to_string(), "catastrophic");
}

#[test]
fn severity_ordering() {
    assert!(ViolationSeverity::Minor < ViolationSeverity::Moderate);
    assert!(ViolationSeverity::Moderate < ViolationSeverity::Severe);
    assert!(ViolationSeverity::Severe < ViolationSeverity::Catastrophic);
}

#[test]
fn severity_serde_round_trip_all() {
    for s in &[
        ViolationSeverity::Minor,
        ViolationSeverity::Moderate,
        ViolationSeverity::Severe,
        ViolationSeverity::Catastrophic,
    ] {
        let json = serde_json::to_string(s).expect("serialize");
        let deser: ViolationSeverity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*s, deser);
    }
}

// ===========================================================================
// 6. RemediationAction
// ===========================================================================

#[test]
fn remediation_display_all() {
    let actions = [
        (RemediationAction::Monitor, "monitor"),
        (RemediationAction::IncreaseBudget, "increase_budget"),
        (RemediationAction::ReduceWorkload, "reduce_workload"),
        (RemediationAction::DeferToBackground, "defer_to_background"),
        (RemediationAction::SplitStage, "split_stage"),
        (RemediationAction::Downgrade, "downgrade"),
    ];
    for (action, expected) in &actions {
        assert_eq!(action.to_string(), *expected);
    }
}

#[test]
fn remediation_serde_round_trip_all() {
    for a in &[
        RemediationAction::Monitor,
        RemediationAction::IncreaseBudget,
        RemediationAction::ReduceWorkload,
        RemediationAction::DeferToBackground,
        RemediationAction::SplitStage,
        RemediationAction::Downgrade,
    ] {
        let json = serde_json::to_string(a).expect("serialize");
        let deser: RemediationAction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*a, deser);
    }
}

// ===========================================================================
// 7. StageLatencyEnvelope defaults
// ===========================================================================

#[test]
fn default_envelope_budget_monotonic_all_stages() {
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
    for stage in &stages {
        let env = default_envelope(*stage);
        assert!(
            env.p50_budget_ns <= env.p95_budget_ns,
            "p50 > p95 for {stage}"
        );
        assert!(
            env.p95_budget_ns <= env.p99_budget_ns,
            "p95 > p99 for {stage}"
        );
        assert!(
            env.p99_budget_ns <= env.p999_budget_ns,
            "p99 > p999 for {stage}"
        );
        assert!(
            env.budget_share_millionths > 0,
            "zero budget share for {stage}"
        );
    }
}

#[test]
fn default_envelope_nonzero_budgets() {
    let env = default_envelope(ExecutionStage::Parse);
    assert!(env.p50_budget_ns > 0);
    assert!(env.p95_budget_ns > 0);
    assert!(env.p99_budget_ns > 0);
    assert!(env.p999_budget_ns > 0);
}

#[test]
fn default_envelope_stage_field_correct() {
    let env = default_envelope(ExecutionStage::GcPause);
    assert_eq!(env.stage, ExecutionStage::GcPause);
    assert!(env.stage_label.is_none());
}

#[test]
fn envelope_serde_round_trip() {
    let env = default_envelope(ExecutionStage::Parse);
    let json = serde_json::to_string(&env).expect("serialize");
    let deser: StageLatencyEnvelope = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(env, deser);
}

#[test]
fn envelope_with_custom_label() {
    let mut env = default_envelope(ExecutionStage::Custom);
    env.stage_label = Some("wasm_instantiate".to_string());
    let json = serde_json::to_string(&env).expect("serialize");
    let deser: StageLatencyEnvelope = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deser.stage_label, Some("wasm_instantiate".to_string()));
}

// ===========================================================================
// 8. issue_stage_certificate
// ===========================================================================

#[test]
fn certificate_compliant_when_within_budget() {
    let env = default_envelope(ExecutionStage::Parse);
    let obs = compliant_observation(ExecutionStage::Parse);
    let cert = issue_stage_certificate(&env, &obs, "cert-1", 0, vec![]);
    assert_eq!(cert.verdict, EnvelopeVerdict::Compliant);
    assert!(cert.violations.is_empty());
    assert_eq!(cert.stage, ExecutionStage::Parse);
    assert_eq!(cert.schema_version, STAGE_ENVELOPE_SCHEMA_VERSION);
    assert_eq!(cert.bead_id, STAGE_ENVELOPE_BEAD_ID);
}

#[test]
fn certificate_violated_when_over_budget() {
    let env = default_envelope(ExecutionStage::GcPause);
    let obs = violating_observation(ExecutionStage::GcPause);
    let cert = issue_stage_certificate(&env, &obs, "cert-v", 0, vec![]);
    assert_eq!(cert.verdict, EnvelopeVerdict::Violated);
    assert!(!cert.violations.is_empty());
}

#[test]
fn certificate_near_limit_when_close_to_budget() {
    let env = default_envelope(ExecutionStage::Parse);
    let obs = near_limit_observation(ExecutionStage::Parse);
    let cert = issue_stage_certificate(&env, &obs, "cert-n", 0, vec![]);
    assert_eq!(cert.verdict, EnvelopeVerdict::NearLimit);
    assert!(cert.violations.is_empty()); // near_limit is not a violation
}

#[test]
fn certificate_insufficient_data_below_min_count() {
    let env = default_envelope(ExecutionStage::Parse);
    let obs = insufficient_observation(ExecutionStage::Parse);
    let cert = issue_stage_certificate(&env, &obs, "cert-i", 0, vec![]);
    assert_eq!(cert.verdict, EnvelopeVerdict::InsufficientData);
    assert!(cert.violations.is_empty());
}

#[test]
fn certificate_preserves_evidence_ids() {
    let env = default_envelope(ExecutionStage::Parse);
    let obs = compliant_observation(ExecutionStage::Parse);
    let evidence = vec!["ev-1".to_string(), "ev-2".to_string()];
    let cert = issue_stage_certificate(&env, &obs, "cert-ev", 42, evidence.clone());
    assert_eq!(cert.evidence_ids, evidence);
    assert_eq!(cert.issued_epoch, 42);
}

#[test]
fn certificate_preserves_certificate_id() {
    let env = default_envelope(ExecutionStage::Lower);
    let obs = compliant_observation(ExecutionStage::Lower);
    let cert = issue_stage_certificate(&env, &obs, "my-custom-id", 0, vec![]);
    assert_eq!(cert.certificate_id, "my-custom-id");
}

#[test]
fn certificate_serde_round_trip() {
    let env = default_envelope(ExecutionStage::GcPause);
    let obs = compliant_observation(ExecutionStage::GcPause);
    let cert = issue_stage_certificate(&env, &obs, "serde-cert", 42, vec!["ev-1".to_string()]);
    let json = serde_json::to_string(&cert).expect("serialize");
    let deser: StageEnvelopeCertificate = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(cert, deser);
}

#[test]
fn certificate_violated_serde_round_trip() {
    let env = default_envelope(ExecutionStage::GcPause);
    let obs = violating_observation(ExecutionStage::GcPause);
    let cert = issue_stage_certificate(&env, &obs, "v-serde", 0, vec![]);
    let json = serde_json::to_string(&cert).expect("serialize");
    let deser: StageEnvelopeCertificate = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(cert, deser);
}

#[test]
fn certificate_for_every_stage_type() {
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
    for stage in &stages {
        let env = default_envelope(*stage);
        let obs = compliant_observation(*stage);
        let cert = issue_stage_certificate(&env, &obs, "cert-all", 0, vec![]);
        assert_eq!(
            cert.verdict,
            EnvelopeVerdict::Compliant,
            "stage {stage} not compliant"
        );
    }
}

// ===========================================================================
// 9. PercentileViolation details
// ===========================================================================

#[test]
fn violation_overshoot_calculation() {
    let env = default_envelope(ExecutionStage::GcPause);
    // Double the p99 budget
    let obs = StageLatencyObservation {
        stage: ExecutionStage::GcPause,
        stage_label: None,
        observation_count: 100,
        p50_ns: env.p50_budget_ns / 2,
        p95_ns: env.p95_budget_ns / 2,
        p99_ns: env.p99_budget_ns * 2,
        p999_ns: env.p999_budget_ns / 2,
        observed_epoch: 0,
    };
    let cert = issue_stage_certificate(&env, &obs, "overshoot", 0, vec![]);
    assert_eq!(cert.verdict, EnvelopeVerdict::Violated);
    let p99_violations: Vec<_> = cert
        .violations
        .iter()
        .filter(|v| v.percentile == LatencyPercentile::P99)
        .collect();
    assert_eq!(p99_violations.len(), 1);
    assert_eq!(p99_violations[0].overshoot_ns, env.p99_budget_ns);
    assert_eq!(p99_violations[0].overshoot_fraction_millionths, 1_000_000); // 100%
}

#[test]
fn violation_no_overshoot_at_exact_budget() {
    let env = default_envelope(ExecutionStage::Parse);
    let obs = StageLatencyObservation {
        stage: ExecutionStage::Parse,
        stage_label: None,
        observation_count: 100,
        p50_ns: env.p50_budget_ns,
        p95_ns: env.p95_budget_ns,
        p99_ns: env.p99_budget_ns,
        p999_ns: env.p999_budget_ns,
        observed_epoch: 0,
    };
    let cert = issue_stage_certificate(&env, &obs, "exact", 0, vec![]);
    // At exact budget, not violated
    assert!(cert.violations.is_empty());
}

#[test]
fn violation_one_ns_over_budget() {
    let env = default_envelope(ExecutionStage::Parse);
    let obs = StageLatencyObservation {
        stage: ExecutionStage::Parse,
        stage_label: None,
        observation_count: 100,
        p50_ns: env.p50_budget_ns,
        p95_ns: env.p95_budget_ns,
        p99_ns: env.p99_budget_ns + 1,
        p999_ns: env.p999_budget_ns,
        observed_epoch: 0,
    };
    let cert = issue_stage_certificate(&env, &obs, "one-over", 0, vec![]);
    assert_eq!(cert.verdict, EnvelopeVerdict::Violated);
    assert_eq!(cert.violations.len(), 1);
    assert_eq!(cert.violations[0].percentile, LatencyPercentile::P99);
    assert_eq!(cert.violations[0].overshoot_ns, 1);
}

#[test]
fn violation_serde_round_trip() {
    let v = PercentileViolation {
        percentile: LatencyPercentile::P99,
        observed_ns: 20_000_000,
        budget_ns: 10_000_000,
        overshoot_ns: 10_000_000,
        overshoot_fraction_millionths: 1_000_000,
    };
    let json = serde_json::to_string(&v).expect("serialize");
    let deser: PercentileViolation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(v, deser);
}

// ===========================================================================
// 10. build_envelope_bundle
// ===========================================================================

#[test]
fn bundle_empty_pipeline() {
    let bundle = build_envelope_bundle(&[], &[], 0);
    assert_eq!(bundle.overall_verdict, EnvelopeVerdict::Compliant);
    assert_eq!(bundle.stage_count, 0);
    assert!(bundle.certificates.is_empty());
}

#[test]
fn bundle_all_compliant() {
    let stages = [
        ExecutionStage::Parse,
        ExecutionStage::Lower,
        ExecutionStage::GcPause,
    ];
    let envelopes: Vec<_> = stages.iter().map(|s| default_envelope(*s)).collect();
    let observations: Vec<_> = stages.iter().map(|s| compliant_observation(*s)).collect();
    let bundle = build_envelope_bundle(&envelopes, &observations, 0);
    assert_eq!(bundle.overall_verdict, EnvelopeVerdict::Compliant);
    assert_eq!(bundle.stage_count, 3);
    assert_eq!(bundle.compliant_count, 3);
    assert_eq!(bundle.violated_count, 0);
    assert_eq!(bundle.near_limit_count, 0);
}

#[test]
fn bundle_one_violated_dominates() {
    let envelopes = vec![
        default_envelope(ExecutionStage::Parse),
        default_envelope(ExecutionStage::GcPause),
    ];
    let observations = vec![
        compliant_observation(ExecutionStage::Parse),
        violating_observation(ExecutionStage::GcPause),
    ];
    let bundle = build_envelope_bundle(&envelopes, &observations, 0);
    assert_eq!(bundle.overall_verdict, EnvelopeVerdict::Violated);
    assert_eq!(bundle.violated_count, 1);
    assert_eq!(bundle.compliant_count, 1);
}

#[test]
fn bundle_near_limit_when_no_violations() {
    let envelopes = vec![
        default_envelope(ExecutionStage::Parse),
        default_envelope(ExecutionStage::Lower),
    ];
    let observations = vec![
        compliant_observation(ExecutionStage::Parse),
        near_limit_observation(ExecutionStage::Lower),
    ];
    let bundle = build_envelope_bundle(&envelopes, &observations, 0);
    assert_eq!(bundle.overall_verdict, EnvelopeVerdict::NearLimit);
    assert_eq!(bundle.near_limit_count, 1);
}

#[test]
fn bundle_insufficient_data_only_when_all_insufficient() {
    let envelopes = vec![default_envelope(ExecutionStage::Parse)];
    let observations = vec![insufficient_observation(ExecutionStage::Parse)];
    let bundle = build_envelope_bundle(&envelopes, &observations, 0);
    assert_eq!(bundle.overall_verdict, EnvelopeVerdict::InsufficientData);
}

#[test]
fn bundle_compliant_overrides_insufficient_data() {
    let envelopes = vec![
        default_envelope(ExecutionStage::Parse),
        default_envelope(ExecutionStage::Lower),
    ];
    let observations = vec![
        compliant_observation(ExecutionStage::Parse),
        insufficient_observation(ExecutionStage::Lower),
    ];
    let bundle = build_envelope_bundle(&envelopes, &observations, 0);
    // Compliant + insufficient = compliant overall (some data is good)
    assert_eq!(bundle.overall_verdict, EnvelopeVerdict::Compliant);
}

#[test]
fn bundle_total_budget_share() {
    let envelopes = vec![
        default_envelope(ExecutionStage::Parse),
        default_envelope(ExecutionStage::Lower),
        default_envelope(ExecutionStage::GcPause),
    ];
    let observations: Vec<_> = envelopes
        .iter()
        .map(|e| compliant_observation(e.stage))
        .collect();
    let bundle = build_envelope_bundle(&envelopes, &observations, 0);
    let expected_share: u64 = envelopes.iter().map(|e| e.budget_share_millionths).sum();
    assert_eq!(bundle.total_budget_share_millionths, expected_share);
}

#[test]
fn bundle_schema_and_epoch_fields() {
    let envelopes = vec![default_envelope(ExecutionStage::Parse)];
    let observations = vec![compliant_observation(ExecutionStage::Parse)];
    let bundle = build_envelope_bundle(&envelopes, &observations, 42);
    assert_eq!(bundle.schema_version, ENVELOPE_BUNDLE_SCHEMA_VERSION);
    assert_eq!(bundle.bead_id, STAGE_ENVELOPE_BEAD_ID);
    assert_eq!(bundle.bundle_epoch, 42);
}

#[test]
fn bundle_serde_round_trip() {
    let envelopes = vec![
        default_envelope(ExecutionStage::Parse),
        default_envelope(ExecutionStage::GcPause),
    ];
    let observations = vec![
        compliant_observation(ExecutionStage::Parse),
        violating_observation(ExecutionStage::GcPause),
    ];
    let bundle = build_envelope_bundle(&envelopes, &observations, 5);
    let json = serde_json::to_string(&bundle).expect("serialize");
    let deser: EnvelopeBundle = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(bundle, deser);
}

#[test]
fn bundle_missing_observation_skips_stage() {
    let envelopes = vec![
        default_envelope(ExecutionStage::Parse),
        default_envelope(ExecutionStage::GcPause),
    ];
    // Only provide observation for Parse, not GcPause
    let observations = vec![compliant_observation(ExecutionStage::Parse)];
    let bundle = build_envelope_bundle(&envelopes, &observations, 0);
    // GcPause should be skipped
    assert_eq!(bundle.certificates.len(), 1);
    assert_eq!(bundle.stage_count, 2); // envelopes count
}

// ===========================================================================
// 11. generate_violation_report
// ===========================================================================

#[test]
fn report_generated_for_violated_cert() {
    let env = default_envelope(ExecutionStage::GcPause);
    let obs = violating_observation(ExecutionStage::GcPause);
    let cert = issue_stage_certificate(&env, &obs, "v-cert", 5, vec![]);
    let report = generate_violation_report(&cert, "rpt-1");
    assert!(report.is_some());
    let rpt = report.unwrap();
    assert_eq!(rpt.stage, ExecutionStage::GcPause);
    assert!(!rpt.violations.is_empty());
    assert_eq!(rpt.reported_epoch, 5);
    assert_eq!(rpt.report_id, "rpt-1");
    assert_eq!(rpt.schema_version, VIOLATION_REPORT_SCHEMA_VERSION);
    assert_eq!(rpt.bead_id, STAGE_ENVELOPE_BEAD_ID);
}

#[test]
fn report_none_for_compliant_cert() {
    let env = default_envelope(ExecutionStage::Parse);
    let obs = compliant_observation(ExecutionStage::Parse);
    let cert = issue_stage_certificate(&env, &obs, "c-cert", 0, vec![]);
    assert!(generate_violation_report(&cert, "rpt-none").is_none());
}

#[test]
fn report_none_for_near_limit_cert() {
    let env = default_envelope(ExecutionStage::Parse);
    let obs = near_limit_observation(ExecutionStage::Parse);
    let cert = issue_stage_certificate(&env, &obs, "nl-cert", 0, vec![]);
    assert!(generate_violation_report(&cert, "rpt-nl").is_none());
}

#[test]
fn report_none_for_insufficient_data() {
    let env = default_envelope(ExecutionStage::Parse);
    let obs = insufficient_observation(ExecutionStage::Parse);
    let cert = issue_stage_certificate(&env, &obs, "id-cert", 0, vec![]);
    assert!(generate_violation_report(&cert, "rpt-id").is_none());
}

#[test]
fn report_severity_escalation() {
    let env = default_envelope(ExecutionStage::GcPause);
    // 3x p999 budget = 200% overshoot = catastrophic
    let obs = StageLatencyObservation {
        stage: ExecutionStage::GcPause,
        stage_label: None,
        observation_count: 100,
        p50_ns: env.p50_budget_ns / 2,
        p95_ns: env.p95_budget_ns / 2,
        p99_ns: env.p99_budget_ns / 2,
        p999_ns: env.p999_budget_ns * 4, // 300% overshoot
        observed_epoch: 0,
    };
    let cert = issue_stage_certificate(&env, &obs, "cat", 0, vec![]);
    let report = generate_violation_report(&cert, "rpt-cat").unwrap();
    assert_eq!(report.severity, ViolationSeverity::Catastrophic);
    assert_eq!(report.remediation, RemediationAction::Downgrade);
}

#[test]
fn report_serde_round_trip() {
    let env = default_envelope(ExecutionStage::GcPause);
    let obs = violating_observation(ExecutionStage::GcPause);
    let cert = issue_stage_certificate(&env, &obs, "v-cert", 0, vec![]);
    let report = generate_violation_report(&cert, "rpt-serde").unwrap();
    let json = serde_json::to_string(&report).expect("serialize");
    let deser: ViolationReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report, deser);
}

// ===========================================================================
// 12. Summary rendering
// ===========================================================================

#[test]
fn envelope_summary_compliant_pipeline() {
    let envelopes = vec![default_envelope(ExecutionStage::Parse)];
    let observations = vec![compliant_observation(ExecutionStage::Parse)];
    let bundle = build_envelope_bundle(&envelopes, &observations, 0);
    let summary = render_envelope_summary(&bundle);
    assert!(summary.contains("overall_verdict: compliant"));
    assert!(summary.contains("stage_count: 1"));
    assert!(summary.contains("compliant: 1"));
}

#[test]
fn envelope_summary_violated_pipeline() {
    let envelopes = vec![
        default_envelope(ExecutionStage::Parse),
        default_envelope(ExecutionStage::GcPause),
    ];
    let observations = vec![
        compliant_observation(ExecutionStage::Parse),
        violating_observation(ExecutionStage::GcPause),
    ];
    let bundle = build_envelope_bundle(&envelopes, &observations, 0);
    let summary = render_envelope_summary(&bundle);
    assert!(summary.contains("overall_verdict: violated"));
    assert!(summary.contains("violated_stages:"));
    assert!(summary.contains("gc_pause"));
}

#[test]
fn envelope_summary_contains_budget_share() {
    let envelopes = vec![default_envelope(ExecutionStage::Parse)];
    let observations = vec![compliant_observation(ExecutionStage::Parse)];
    let bundle = build_envelope_bundle(&envelopes, &observations, 0);
    let summary = render_envelope_summary(&bundle);
    assert!(summary.contains("total_budget_share:"));
}

#[test]
fn violation_summary_shows_stage_and_severity() {
    let env = default_envelope(ExecutionStage::GcPause);
    let obs = violating_observation(ExecutionStage::GcPause);
    let cert = issue_stage_certificate(&env, &obs, "v", 0, vec![]);
    let report = generate_violation_report(&cert, "rpt").unwrap();
    let summary = render_violation_summary(&report);
    assert!(summary.contains("stage: gc_pause"));
    assert!(summary.contains("severity:"));
    assert!(summary.contains("remediation:"));
}

#[test]
fn violation_summary_shows_percentile_details() {
    let env = default_envelope(ExecutionStage::GcPause);
    let obs = violating_observation(ExecutionStage::GcPause);
    let cert = issue_stage_certificate(&env, &obs, "v", 0, vec![]);
    let report = generate_violation_report(&cert, "rpt").unwrap();
    let summary = render_violation_summary(&report);
    assert!(summary.contains("observed="));
    assert!(summary.contains("budget="));
}

// ===========================================================================
// 13. Determinism
// ===========================================================================

#[test]
fn certificate_issuance_deterministic() {
    let env = default_envelope(ExecutionStage::Parse);
    let obs = compliant_observation(ExecutionStage::Parse);
    let c1 = issue_stage_certificate(&env, &obs, "det-1", 0, vec![]);
    let c2 = issue_stage_certificate(&env, &obs, "det-1", 0, vec![]);
    assert_eq!(c1, c2);
}

#[test]
fn bundle_deterministic() {
    let envelopes = vec![
        default_envelope(ExecutionStage::Parse),
        default_envelope(ExecutionStage::GcPause),
    ];
    let observations = vec![
        compliant_observation(ExecutionStage::Parse),
        violating_observation(ExecutionStage::GcPause),
    ];
    let b1 = build_envelope_bundle(&envelopes, &observations, 0);
    let b2 = build_envelope_bundle(&envelopes, &observations, 0);
    assert_eq!(b1, b2);
}

// ===========================================================================
// 14. JSON structure validation
// ===========================================================================

#[test]
fn certificate_json_has_expected_fields() {
    let env = default_envelope(ExecutionStage::Parse);
    let obs = compliant_observation(ExecutionStage::Parse);
    let cert = issue_stage_certificate(&env, &obs, "json", 0, vec![]);
    let val: serde_json::Value = serde_json::to_value(&cert).expect("to_value");
    assert!(val.get("schema_version").is_some());
    assert!(val.get("bead_id").is_some());
    assert!(val.get("certificate_id").is_some());
    assert!(val.get("stage").is_some());
    assert!(val.get("envelope").is_some());
    assert!(val.get("observation").is_some());
    assert!(val.get("verdict").is_some());
    assert!(val.get("violations").is_some());
    assert!(val.get("evidence_ids").is_some());
}

#[test]
fn bundle_json_has_expected_fields() {
    let envelopes = vec![default_envelope(ExecutionStage::Parse)];
    let observations = vec![compliant_observation(ExecutionStage::Parse)];
    let bundle = build_envelope_bundle(&envelopes, &observations, 0);
    let val: serde_json::Value = serde_json::to_value(&bundle).expect("to_value");
    assert!(val.get("schema_version").is_some());
    assert!(val.get("certificates").is_some());
    assert!(val.get("overall_verdict").is_some());
    assert!(val.get("stage_count").is_some());
    assert!(val.get("total_budget_share_millionths").is_some());
}

#[test]
fn report_json_has_expected_fields() {
    let env = default_envelope(ExecutionStage::GcPause);
    let obs = violating_observation(ExecutionStage::GcPause);
    let cert = issue_stage_certificate(&env, &obs, "json-v", 0, vec![]);
    let report = generate_violation_report(&cert, "rpt-json").unwrap();
    let val: serde_json::Value = serde_json::to_value(&report).expect("to_value");
    assert!(val.get("schema_version").is_some());
    assert!(val.get("stage").is_some());
    assert!(val.get("violations").is_some());
    assert!(val.get("severity").is_some());
    assert!(val.get("remediation").is_some());
}

// ===========================================================================
// 15. Edge cases and stress tests
// ===========================================================================

#[test]
fn full_pipeline_bundle_all_stages() {
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
    let envelopes: Vec<_> = stages.iter().map(|s| default_envelope(*s)).collect();
    let observations: Vec<_> = stages.iter().map(|s| compliant_observation(*s)).collect();
    let bundle = build_envelope_bundle(&envelopes, &observations, 0);
    assert_eq!(bundle.stage_count, 10);
    assert_eq!(bundle.compliant_count, 10);
    assert_eq!(bundle.overall_verdict, EnvelopeVerdict::Compliant);
}

#[test]
fn mixed_verdicts_in_pipeline() {
    let stages = [
        ExecutionStage::Parse,
        ExecutionStage::Lower,
        ExecutionStage::GcPause,
        ExecutionStage::CompileOptimized,
    ];
    let envelopes: Vec<_> = stages.iter().map(|s| default_envelope(*s)).collect();
    let observations = vec![
        compliant_observation(ExecutionStage::Parse),
        near_limit_observation(ExecutionStage::Lower),
        violating_observation(ExecutionStage::GcPause),
        insufficient_observation(ExecutionStage::CompileOptimized),
    ];
    let bundle = build_envelope_bundle(&envelopes, &observations, 0);
    assert_eq!(bundle.overall_verdict, EnvelopeVerdict::Violated);
    assert_eq!(bundle.compliant_count, 1);
    assert_eq!(bundle.near_limit_count, 1);
    assert_eq!(bundle.violated_count, 1);
    assert_eq!(bundle.insufficient_data_count, 1);
}

#[test]
fn zero_budget_handled_gracefully() {
    let env = StageLatencyEnvelope {
        stage: ExecutionStage::Custom,
        stage_label: Some("zero-budget".to_string()),
        p50_budget_ns: 0,
        p95_budget_ns: 0,
        p99_budget_ns: 0,
        p999_budget_ns: 0,
        budget_share_millionths: 0,
    };
    let obs = StageLatencyObservation {
        stage: ExecutionStage::Custom,
        stage_label: Some("zero-budget".to_string()),
        observation_count: 100,
        p50_ns: 1,
        p95_ns: 1,
        p99_ns: 1,
        p999_ns: 1,
        observed_epoch: 0,
    };
    let cert = issue_stage_certificate(&env, &obs, "zero", 0, vec![]);
    assert_eq!(cert.verdict, EnvelopeVerdict::Violated);
}

#[test]
fn observation_serde_round_trip() {
    let obs = compliant_observation(ExecutionStage::Parse);
    let json = serde_json::to_string(&obs).expect("serialize");
    let deser: StageLatencyObservation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(obs, deser);
}
