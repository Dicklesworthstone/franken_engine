//! Enrichment integration tests for `tail_latency_control_plane`.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::tail_latency_control_plane::{
    EndToEndLatencyBounds, GuardrailState, RuntimeGuardrailStatus, StressProfile,
    TAIL_LATENCY_CONTROL_PLANE_BEAD_ID, TAIL_LATENCY_CONTROL_PLANE_COMPONENT,
    TAIL_LATENCY_CONTROL_PLANE_POLICY_ID, TAIL_LATENCY_CONTROL_PLANE_REPORT_FILE,
    TAIL_LATENCY_CONTROL_PLANE_SCHEMA_VERSION, TailLatencyControlPlaneReport,
    TailLatencyControlPlaneRunManifest, TailLatencyControlPlaneTraceIds, TailLatencyDecomposition,
    build_tail_latency_control_plane_report, default_stage_envelopes,
    write_tail_latency_control_plane_bundle,
};

fn unique_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "enrichment_tail_latency_cp_{label}_{}_{}",
        std::process::id(),
        nanos
    ))
}

// ---------------------------------------------------------------------------
// StressProfile
// ---------------------------------------------------------------------------

#[test]
fn enrichment_stress_profile_balanced_as_str() {
    assert_eq!(StressProfile::Balanced.as_str(), "balanced");
}

#[test]
fn enrichment_stress_profile_synthetic_as_str() {
    assert_eq!(
        StressProfile::SyntheticContention.as_str(),
        "synthetic-contention"
    );
}

#[test]
fn enrichment_stress_profile_display_balanced() {
    assert_eq!(format!("{}", StressProfile::Balanced), "balanced");
}

#[test]
fn enrichment_stress_profile_display_synthetic() {
    assert_eq!(
        format!("{}", StressProfile::SyntheticContention),
        "synthetic-contention"
    );
}

#[test]
fn enrichment_stress_profile_from_str_balanced() {
    let parsed: StressProfile = "balanced".parse().unwrap();
    assert_eq!(parsed, StressProfile::Balanced);
}

#[test]
fn enrichment_stress_profile_from_str_synthetic_kebab() {
    let parsed: StressProfile = "synthetic-contention".parse().unwrap();
    assert_eq!(parsed, StressProfile::SyntheticContention);
}

#[test]
fn enrichment_stress_profile_from_str_synthetic_snake() {
    let parsed: StressProfile = "synthetic_contention".parse().unwrap();
    assert_eq!(parsed, StressProfile::SyntheticContention);
}

#[test]
fn enrichment_stress_profile_from_str_invalid() {
    let result: Result<StressProfile, _> = "unknown".parse();
    assert!(result.is_err());
}

#[test]
fn enrichment_stress_profile_serde_roundtrip() {
    for profile in [StressProfile::Balanced, StressProfile::SyntheticContention] {
        let json = serde_json::to_string(&profile).unwrap();
        let back: StressProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile, back);
    }
}

// ---------------------------------------------------------------------------
// GuardrailState
// ---------------------------------------------------------------------------

#[test]
fn enrichment_guardrail_state_display_all() {
    assert_eq!(format!("{}", GuardrailState::Nominal), "nominal");
    assert_eq!(format!("{}", GuardrailState::NearLimit), "near_limit");
    assert_eq!(
        format!("{}", GuardrailState::FallbackEngaged),
        "fallback_engaged"
    );
}

#[test]
fn enrichment_guardrail_state_serde_roundtrip() {
    for state in [
        GuardrailState::Nominal,
        GuardrailState::NearLimit,
        GuardrailState::FallbackEngaged,
    ] {
        let json = serde_json::to_string(&state).unwrap();
        let back: GuardrailState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_non_empty() {
    assert!(!TAIL_LATENCY_CONTROL_PLANE_SCHEMA_VERSION.is_empty());
}

#[test]
fn enrichment_bead_id_format() {
    assert!(TAIL_LATENCY_CONTROL_PLANE_BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrichment_policy_id_non_empty() {
    assert!(!TAIL_LATENCY_CONTROL_PLANE_POLICY_ID.is_empty());
}

#[test]
fn enrichment_component_non_empty() {
    assert!(!TAIL_LATENCY_CONTROL_PLANE_COMPONENT.is_empty());
}

#[test]
fn enrichment_report_file_ends_json() {
    assert!(TAIL_LATENCY_CONTROL_PLANE_REPORT_FILE.ends_with(".json"));
}

// ---------------------------------------------------------------------------
// default_stage_envelopes
// ---------------------------------------------------------------------------

#[test]
fn enrichment_default_stage_envelopes_count() {
    let envelopes = default_stage_envelopes();
    assert_eq!(envelopes.len(), 7);
}

#[test]
fn enrichment_default_stage_envelopes_all_positive_budgets() {
    for envelope in default_stage_envelopes() {
        assert!(envelope.p99_budget_ns > 0);
        assert!(envelope.p999_budget_ns > 0);
    }
}

// ---------------------------------------------------------------------------
// build_tail_latency_control_plane_report
// ---------------------------------------------------------------------------

#[test]
fn enrichment_balanced_report_schema_version() {
    let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 1).unwrap();
    assert_eq!(
        report.schema_version,
        TAIL_LATENCY_CONTROL_PLANE_SCHEMA_VERSION
    );
}

#[test]
fn enrichment_balanced_report_has_7_stages() {
    let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 1).unwrap();
    assert_eq!(report.envelope_bundle.stage_count, 7);
}

#[test]
fn enrichment_balanced_report_has_calibrations() {
    let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 1).unwrap();
    assert_eq!(report.stage_calibrations.len(), 7);
}

#[test]
fn enrichment_synthetic_report_has_violations() {
    let report =
        build_tail_latency_control_plane_report(StressProfile::SyntheticContention, 42).unwrap();
    assert!(!report.violation_reports.is_empty());
}

#[test]
fn enrichment_synthetic_report_shed_count_nonzero() {
    let report =
        build_tail_latency_control_plane_report(StressProfile::SyntheticContention, 42).unwrap();
    assert!(report.guardrails.shed_count > 0);
}

#[test]
fn enrichment_report_decomposition_nonzero() {
    let report =
        build_tail_latency_control_plane_report(StressProfile::SyntheticContention, 1).unwrap();
    assert!(report.decomposition.queue_p99_ns > 0);
    assert!(report.decomposition.service_p99_ns > 0);
}

#[test]
fn enrichment_report_serde_roundtrip() {
    let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 5).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: TailLatencyControlPlaneReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report.bead_id, back.bead_id);
    assert_eq!(report.profile, back.profile);
}

#[test]
fn enrichment_report_deterministic() {
    let r1 = build_tail_latency_control_plane_report(StressProfile::Balanced, 99).unwrap();
    let r2 = build_tail_latency_control_plane_report(StressProfile::Balanced, 99).unwrap();
    assert_eq!(r1.end_to_end_bounds, r2.end_to_end_bounds);
    assert_eq!(r1.decomposition, r2.decomposition);
}

// ---------------------------------------------------------------------------
// write bundle
// ---------------------------------------------------------------------------

#[test]
fn enrichment_write_bundle_creates_all_files() {
    let out_dir = unique_dir("write_all");
    let artifacts = write_tail_latency_control_plane_bundle(
        &out_dir,
        StressProfile::Balanced,
        1,
        &[String::from("test-cmd")],
    )
    .unwrap();
    assert!(artifacts.report_path.exists());
    assert!(artifacts.trace_ids_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
    assert!(artifacts.summary_path.exists());
    assert!(artifacts.env_path.exists());
    assert!(artifacts.repro_lock_path.exists());
}

#[test]
fn enrichment_write_bundle_manifest_deserializable() {
    let out_dir = unique_dir("manifest_deser");
    let artifacts = write_tail_latency_control_plane_bundle(
        &out_dir,
        StressProfile::Balanced,
        10,
        &[String::from("test")],
    )
    .unwrap();
    let bytes = std::fs::read(&artifacts.run_manifest_path).unwrap();
    let manifest: TailLatencyControlPlaneRunManifest = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(manifest.component, TAIL_LATENCY_CONTROL_PLANE_COMPONENT);
}

#[test]
fn enrichment_write_bundle_trace_ids_deserializable() {
    let out_dir = unique_dir("trace_deser");
    let artifacts = write_tail_latency_control_plane_bundle(
        &out_dir,
        StressProfile::SyntheticContention,
        42,
        &[String::from("test")],
    )
    .unwrap();
    let bytes = std::fs::read(&artifacts.trace_ids_path).unwrap();
    let trace_ids: TailLatencyControlPlaneTraceIds = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(trace_ids.profile, StressProfile::SyntheticContention);
}

#[test]
fn enrichment_write_bundle_summary_contains_profile() {
    let out_dir = unique_dir("summary");
    let artifacts = write_tail_latency_control_plane_bundle(
        &out_dir,
        StressProfile::Balanced,
        1,
        &[String::from("cmd")],
    )
    .unwrap();
    let summary = std::fs::read_to_string(&artifacts.summary_path).unwrap();
    assert!(summary.contains("balanced"));
}

// ---------------------------------------------------------------------------
// Serde roundtrips for sub-types
// ---------------------------------------------------------------------------

#[test]
fn enrichment_end_to_end_bounds_serde() {
    let bounds = EndToEndLatencyBounds {
        composition_model: "serial_min_plus_sum".to_string(),
        stage_count: 7,
        budget_p50_ns: 100,
        budget_p95_ns: 200,
        budget_p99_ns: 300,
        budget_p999_ns: 400,
        observed_p50_ns: 50,
        observed_p95_ns: 150,
        observed_p99_ns: 250,
        observed_p999_ns: 350,
        queue_adjusted_p99_ns: 280,
        queue_adjusted_p999_ns: 380,
    };
    let json = serde_json::to_string(&bounds).unwrap();
    let back: EndToEndLatencyBounds = serde_json::from_str(&json).unwrap();
    assert_eq!(bounds, back);
}

#[test]
fn enrichment_decomposition_serde() {
    let decomp = TailLatencyDecomposition {
        queue_p99_ns: 10,
        queue_p999_ns: 20,
        service_p99_ns: 30,
        service_p999_ns: 40,
        synchronization_p99_ns: 50,
        synchronization_p999_ns: 60,
        gc_p99_ns: 70,
        gc_p999_ns: 80,
    };
    let json = serde_json::to_string(&decomp).unwrap();
    let back: TailLatencyDecomposition = serde_json::from_str(&json).unwrap();
    assert_eq!(decomp, back);
}

#[test]
fn enrichment_runtime_guardrail_status_serde() {
    let status = RuntimeGuardrailStatus {
        state: GuardrailState::Nominal,
        fallback_activated: false,
        reason_codes: vec!["test".to_string()],
        controller_modes_after_guardrail: BTreeMap::new(),
        shed_count: 0,
        violated_stage_count: 0,
    };
    let json = serde_json::to_string(&status).unwrap();
    let back: RuntimeGuardrailStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(status, back);
}
