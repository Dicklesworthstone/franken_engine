#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::tail_latency_control_plane::{
    GuardrailState, StressProfile, TAIL_LATENCY_CONTROL_PLANE_BEAD_ID,
    TAIL_LATENCY_CONTROL_PLANE_COMPONENT, TailLatencyControlPlaneReport,
    TailLatencyControlPlaneRunManifest, TailLatencyControlPlaneTraceIds,
    build_tail_latency_control_plane_report, write_tail_latency_control_plane_bundle,
};

use frankenengine_engine::tail_latency_control_plane::{
    TAIL_LATENCY_CONTROL_PLANE_EVENT_SCHEMA_VERSION, TAIL_LATENCY_CONTROL_PLANE_POLICY_ID,
    TAIL_LATENCY_CONTROL_PLANE_RUN_MANIFEST_SCHEMA_VERSION,
    TAIL_LATENCY_CONTROL_PLANE_SCHEMA_VERSION, TAIL_LATENCY_CONTROL_PLANE_TRACE_IDS_SCHEMA_VERSION,
    TailLatencyControlPlaneEvent, default_stage_envelopes,
};

fn unique_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "franken_engine_tail_latency_control_plane_{label}_{}_{}",
        std::process::id(),
        nanos
    ))
}

fn extract_streamed_artifact(stdout: &str, artifact_name: &str) -> String {
    let begin = format!("__RGC_TAIL_LATENCY_CONTROL_PLANE_ARTIFACT__:BEGIN:{artifact_name}\n");
    let end = format!("\n__RGC_TAIL_LATENCY_CONTROL_PLANE_ARTIFACT__:END:{artifact_name}");
    let start = stdout
        .find(&begin)
        .unwrap_or_else(|| panic!("missing begin marker for {artifact_name}"))
        + begin.len();
    let end_offset = stdout[start..]
        .find(&end)
        .unwrap_or_else(|| panic!("missing end marker for {artifact_name}"));
    stdout[start..start + end_offset].to_string()
}

#[test]
fn synthetic_contention_report_engages_fallback() {
    let report =
        build_tail_latency_control_plane_report(StressProfile::SyntheticContention, 42).unwrap();
    assert_eq!(report.bead_id, TAIL_LATENCY_CONTROL_PLANE_BEAD_ID);
    assert_eq!(report.component, TAIL_LATENCY_CONTROL_PLANE_COMPONENT);
    assert!(report.guardrails.fallback_activated);
    assert_eq!(report.guardrails.state, GuardrailState::FallbackEngaged);
    assert!(!report.violation_reports.is_empty());
}

#[test]
fn balanced_report_stays_dependency_safe() {
    let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 11).unwrap();
    assert!(!report.guardrails.fallback_activated);
    assert_eq!(report.admission_manifest.summary.total_shed, 0);
    assert!(report.end_to_end_bounds.budget_p99_ns >= report.end_to_end_bounds.observed_p99_ns);
}

#[test]
fn write_bundle_emits_expected_artifacts() {
    let out_dir = unique_dir("bundle");
    let artifacts = write_tail_latency_control_plane_bundle(
        &out_dir,
        StressProfile::SyntheticContention,
        42,
        &[String::from(
            "cargo run -p frankenengine-engine --bin franken_tail_latency_control_plane -- --out-dir <dir>",
        )],
    )
    .unwrap();

    assert!(artifacts.report_path.exists());
    assert!(artifacts.trace_ids_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
    assert!(artifacts.step_logs_dir.join("step_000.log").exists());
    assert!(artifacts.summary_path.exists());
    assert!(artifacts.env_path.exists());
    assert!(artifacts.repro_lock_path.exists());
}

#[test]
fn manifest_and_trace_ids_reference_latency_control_plane_bundle() {
    let out_dir = unique_dir("manifest");
    let artifacts = write_tail_latency_control_plane_bundle(
        &out_dir,
        StressProfile::SyntheticContention,
        42,
        &[String::from(
            "cargo run -p frankenengine-engine --bin franken_tail_latency_control_plane -- --out-dir <dir> --profile synthetic-contention --epoch 42",
        )],
    )
    .unwrap();

    let manifest: TailLatencyControlPlaneRunManifest =
        serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).expect("read run manifest"))
            .unwrap();
    let trace_ids: TailLatencyControlPlaneTraceIds =
        serde_json::from_slice(&fs::read(&artifacts.trace_ids_path).expect("read trace ids"))
            .unwrap();
    let commands = fs::read_to_string(&artifacts.commands_path).unwrap();

    assert_eq!(
        manifest.artifact_paths.latency_control_plane_report,
        "latency_control_plane_report.json"
    );
    assert_eq!(manifest.component, TAIL_LATENCY_CONTROL_PLANE_COMPONENT);
    assert_eq!(trace_ids.component, TAIL_LATENCY_CONTROL_PLANE_COMPONENT);
    assert!(commands.contains("franken_tail_latency_control_plane"));
    assert_eq!(manifest.trace_id, trace_ids.trace_id);
}

#[test]
fn balanced_binary_emits_streamed_artifacts_without_fallback() {
    let out_dir = unique_dir("balanced-stream");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_tail_latency_control_plane"))
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--profile")
        .arg("balanced")
        .arg("--epoch")
        .arg("77")
        .arg("--emit-artifact-stream")
        .output()
        .expect("run tail latency control plane binary");

    assert!(
        output.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let manifest: TailLatencyControlPlaneRunManifest =
        serde_json::from_str(&extract_streamed_artifact(&stdout, "run_manifest.json"))
            .expect("streamed manifest json");
    let report: TailLatencyControlPlaneReport = serde_json::from_str(&extract_streamed_artifact(
        &stdout,
        "latency_control_plane_report.json",
    ))
    .expect("streamed report json");
    let commands = extract_streamed_artifact(&stdout, "commands.txt");
    let repro_lock: serde_json::Value =
        serde_json::from_str(&extract_streamed_artifact(&stdout, "repro.lock"))
            .expect("streamed repro lock json");
    let step_log = extract_streamed_artifact(&stdout, "step_logs/step_000.log");

    assert_eq!(manifest.profile, StressProfile::Balanced);
    assert!(!manifest.fallback_activated);
    assert_eq!(manifest.guardrail_state, report.guardrails.state);
    assert_ne!(report.guardrails.state, GuardrailState::FallbackEngaged);
    assert!(!report.guardrails.fallback_activated);
    assert!(commands.contains("--emit-artifact-stream"));
    assert_eq!(repro_lock["profile"], "balanced");
    assert_eq!(repro_lock["epoch"], 77);
    assert_eq!(
        repro_lock["replay_command"],
        "cargo run -p frankenengine-engine --bin franken_tail_latency_control_plane -- --out-dir <DIR> --profile balanced --epoch 77"
    );
    assert!(step_log.contains(&format!("guardrail_state={}", report.guardrails.state)));
    assert!(out_dir.join("run_manifest.json").exists());
    assert!(out_dir.join("latency_control_plane_report.json").exists());
}

// =========================================================================
// Enrichment: serde roundtrips
// =========================================================================

#[test]
fn report_serde_roundtrip_balanced() {
    let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 1).unwrap();
    let json = serde_json::to_string_pretty(&report).unwrap();
    let restored: TailLatencyControlPlaneReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

#[test]
fn report_serde_roundtrip_synthetic_contention() {
    let report =
        build_tail_latency_control_plane_report(StressProfile::SyntheticContention, 99).unwrap();
    let json = serde_json::to_string_pretty(&report).unwrap();
    let restored: TailLatencyControlPlaneReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

#[test]
fn run_manifest_serde_roundtrip() {
    let out_dir = unique_dir("manifest-serde");
    let artifacts = write_tail_latency_control_plane_bundle(
        &out_dir,
        StressProfile::Balanced,
        5,
        &["echo test".into()],
    )
    .unwrap();
    let manifest: TailLatencyControlPlaneRunManifest =
        serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).unwrap()).unwrap();
    let json = serde_json::to_string_pretty(&manifest).unwrap();
    let restored: TailLatencyControlPlaneRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, restored);
}

#[test]
fn trace_ids_serde_roundtrip() {
    let out_dir = unique_dir("trace-serde");
    let artifacts = write_tail_latency_control_plane_bundle(
        &out_dir,
        StressProfile::SyntheticContention,
        7,
        &["echo test".into()],
    )
    .unwrap();
    let trace_ids: TailLatencyControlPlaneTraceIds =
        serde_json::from_slice(&fs::read(&artifacts.trace_ids_path).unwrap()).unwrap();
    let json = serde_json::to_string_pretty(&trace_ids).unwrap();
    let restored: TailLatencyControlPlaneTraceIds = serde_json::from_str(&json).unwrap();
    assert_eq!(trace_ids, restored);
}

// =========================================================================
// Enrichment: schema version and component contracts
// =========================================================================

#[test]
fn balanced_report_schema_version_and_policy_id() {
    let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 1).unwrap();
    assert_eq!(
        report.schema_version,
        TAIL_LATENCY_CONTROL_PLANE_SCHEMA_VERSION
    );
    assert_eq!(report.policy_id, TAIL_LATENCY_CONTROL_PLANE_POLICY_ID);
    assert_eq!(report.component, TAIL_LATENCY_CONTROL_PLANE_COMPONENT);
}

#[test]
fn contention_report_schema_version_and_policy_id() {
    let report =
        build_tail_latency_control_plane_report(StressProfile::SyntheticContention, 1).unwrap();
    assert_eq!(
        report.schema_version,
        TAIL_LATENCY_CONTROL_PLANE_SCHEMA_VERSION
    );
    assert_eq!(report.policy_id, TAIL_LATENCY_CONTROL_PLANE_POLICY_ID);
    assert_eq!(report.component, TAIL_LATENCY_CONTROL_PLANE_COMPONENT);
}

#[test]
fn manifest_schema_version_matches_contract() {
    let out_dir = unique_dir("manifest-schema");
    let artifacts = write_tail_latency_control_plane_bundle(
        &out_dir,
        StressProfile::Balanced,
        1,
        &["echo ci".into()],
    )
    .unwrap();
    let manifest: TailLatencyControlPlaneRunManifest =
        serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).unwrap()).unwrap();
    assert_eq!(
        manifest.schema_version,
        TAIL_LATENCY_CONTROL_PLANE_RUN_MANIFEST_SCHEMA_VERSION
    );
    assert_eq!(manifest.component, TAIL_LATENCY_CONTROL_PLANE_COMPONENT);
    assert_eq!(manifest.policy_id, TAIL_LATENCY_CONTROL_PLANE_POLICY_ID);
}

#[test]
fn trace_ids_schema_version_matches_contract() {
    let out_dir = unique_dir("trace-schema");
    let artifacts = write_tail_latency_control_plane_bundle(
        &out_dir,
        StressProfile::SyntheticContention,
        3,
        &["echo ci".into()],
    )
    .unwrap();
    let trace_ids: TailLatencyControlPlaneTraceIds =
        serde_json::from_slice(&fs::read(&artifacts.trace_ids_path).unwrap()).unwrap();
    assert_eq!(
        trace_ids.schema_version,
        TAIL_LATENCY_CONTROL_PLANE_TRACE_IDS_SCHEMA_VERSION
    );
    assert_eq!(trace_ids.component, TAIL_LATENCY_CONTROL_PLANE_COMPONENT);
    assert_eq!(trace_ids.policy_id, TAIL_LATENCY_CONTROL_PLANE_POLICY_ID);
}

// =========================================================================
// Enrichment: stress profile parsing and display
// =========================================================================

#[test]
fn stress_profile_parse_balanced() {
    let profile: StressProfile = "balanced".parse().unwrap();
    assert_eq!(profile, StressProfile::Balanced);
    assert_eq!(profile.as_str(), "balanced");
    assert_eq!(profile.to_string(), "balanced");
}

#[test]
fn stress_profile_parse_synthetic_contention_kebab() {
    let profile: StressProfile = "synthetic-contention".parse().unwrap();
    assert_eq!(profile, StressProfile::SyntheticContention);
    assert_eq!(profile.as_str(), "synthetic-contention");
}

#[test]
fn stress_profile_parse_synthetic_contention_snake() {
    let profile: StressProfile = "synthetic_contention".parse().unwrap();
    assert_eq!(profile, StressProfile::SyntheticContention);
}

#[test]
fn stress_profile_parse_invalid_returns_error() {
    let err = "bogus".parse::<StressProfile>().unwrap_err();
    assert!(err.contains("unsupported stress profile"));
    assert!(err.contains("bogus"));
}

// =========================================================================
// Enrichment: guardrail state display
// =========================================================================

#[test]
fn guardrail_state_display_nominal() {
    assert_eq!(GuardrailState::Nominal.to_string(), "nominal");
}

#[test]
fn guardrail_state_display_near_limit() {
    assert_eq!(GuardrailState::NearLimit.to_string(), "near_limit");
}

#[test]
fn guardrail_state_display_fallback_engaged() {
    assert_eq!(
        GuardrailState::FallbackEngaged.to_string(),
        "fallback_engaged"
    );
}

// =========================================================================
// Enrichment: determinism — same inputs yield same hash
// =========================================================================

#[test]
fn deterministic_report_hash_for_same_epoch_and_profile() {
    let out1 = unique_dir("determinism-1");
    let out2 = unique_dir("determinism-2");
    let a1 = write_tail_latency_control_plane_bundle(
        &out1,
        StressProfile::Balanced,
        42,
        &["echo 1".into()],
    )
    .unwrap();
    let a2 = write_tail_latency_control_plane_bundle(
        &out2,
        StressProfile::Balanced,
        42,
        &["echo 2".into()],
    )
    .unwrap();
    let m1: TailLatencyControlPlaneRunManifest =
        serde_json::from_slice(&fs::read(&a1.run_manifest_path).unwrap()).unwrap();
    let m2: TailLatencyControlPlaneRunManifest =
        serde_json::from_slice(&fs::read(&a2.run_manifest_path).unwrap()).unwrap();
    assert_eq!(m1.report_hash, m2.report_hash);
    assert_eq!(m1.trace_id, m2.trace_id);
}

#[test]
fn different_epochs_produce_different_report_hashes() {
    let out1 = unique_dir("epoch-diff-1");
    let out2 = unique_dir("epoch-diff-2");
    let a1 = write_tail_latency_control_plane_bundle(
        &out1,
        StressProfile::Balanced,
        1,
        &["echo a".into()],
    )
    .unwrap();
    let a2 = write_tail_latency_control_plane_bundle(
        &out2,
        StressProfile::Balanced,
        2,
        &["echo b".into()],
    )
    .unwrap();
    let m1: TailLatencyControlPlaneRunManifest =
        serde_json::from_slice(&fs::read(&a1.run_manifest_path).unwrap()).unwrap();
    let m2: TailLatencyControlPlaneRunManifest =
        serde_json::from_slice(&fs::read(&a2.run_manifest_path).unwrap()).unwrap();
    assert_ne!(m1.report_hash, m2.report_hash);
}

// =========================================================================
// Enrichment: report content validation
// =========================================================================

#[test]
fn contention_report_has_nonempty_calibrations() {
    let report =
        build_tail_latency_control_plane_report(StressProfile::SyntheticContention, 10).unwrap();
    assert!(!report.stage_calibrations.is_empty());
    for calibration in &report.stage_calibrations {
        assert!(calibration.target_latency_ns > 0);
        assert!(calibration.arrival_rate_millionths > 0);
        assert!(calibration.mean_service_ns > 0);
    }
}

#[test]
fn balanced_report_has_nonempty_admission_receipts() {
    let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 7).unwrap();
    assert!(!report.admission_receipts.is_empty());
}

#[test]
fn contention_report_has_nonempty_controller_decisions() {
    let report =
        build_tail_latency_control_plane_report(StressProfile::SyntheticContention, 20).unwrap();
    assert!(!report.controller_decisions.is_empty());
}

#[test]
fn report_decomposition_fields_are_populated() {
    let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 1).unwrap();
    // At least the service p99 should be nonzero for a balanced scenario
    assert!(report.decomposition.service_p99_ns > 0);
    assert!(report.decomposition.service_p999_ns > 0);
}

#[test]
fn end_to_end_bounds_budget_exceeds_observed_for_balanced() {
    let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 1).unwrap();
    assert!(report.end_to_end_bounds.budget_p99_ns >= report.end_to_end_bounds.observed_p99_ns);
    assert!(report.end_to_end_bounds.budget_p999_ns >= report.end_to_end_bounds.observed_p999_ns);
    assert!(report.end_to_end_bounds.stage_count > 0);
}

#[test]
fn contention_report_guardrail_has_reason_codes() {
    let report =
        build_tail_latency_control_plane_report(StressProfile::SyntheticContention, 10).unwrap();
    assert!(report.guardrails.fallback_activated);
    assert!(!report.guardrails.reason_codes.is_empty());
}

// =========================================================================
// Enrichment: events JSONL validation
// =========================================================================

#[test]
fn events_jsonl_lines_are_valid_json() {
    let out_dir = unique_dir("events-jsonl");
    let artifacts = write_tail_latency_control_plane_bundle(
        &out_dir,
        StressProfile::SyntheticContention,
        10,
        &["echo ci".into()],
    )
    .unwrap();
    let events_text = fs::read_to_string(&artifacts.events_path).unwrap();
    let mut count = 0;
    for line in events_text.lines() {
        let event: TailLatencyControlPlaneEvent =
            serde_json::from_str(line).expect("each events.jsonl line must be valid JSON");
        assert_eq!(
            event.schema_version,
            TAIL_LATENCY_CONTROL_PLANE_EVENT_SCHEMA_VERSION
        );
        assert_eq!(event.component, TAIL_LATENCY_CONTROL_PLANE_COMPONENT);
        assert!(!event.trace_id.is_empty());
        assert!(!event.decision_id.is_empty());
        count += 1;
    }
    assert!(count > 0, "events.jsonl must not be empty");
}

// =========================================================================
// Enrichment: default stage envelopes
// =========================================================================

#[test]
fn default_stage_envelopes_cover_expected_stages() {
    let envelopes = default_stage_envelopes();
    assert!(
        envelopes.len() >= 7,
        "expected at least 7 default stage envelopes"
    );
    let stages: Vec<_> = envelopes.iter().map(|e| e.stage).collect();
    use frankenengine_engine::stage_envelope_certificate::ExecutionStage;
    assert!(stages.contains(&ExecutionStage::Parse));
    assert!(stages.contains(&ExecutionStage::Lower));
    assert!(stages.contains(&ExecutionStage::CompileOptimized));
    assert!(stages.contains(&ExecutionStage::ModuleLoad));
    assert!(stages.contains(&ExecutionStage::GcPause));
    assert!(stages.contains(&ExecutionStage::SandboxInit));
    assert!(stages.contains(&ExecutionStage::ExecutionQuantum));
}

// =========================================================================
// Enrichment: bundle summary.md content
// =========================================================================

#[test]
fn summary_md_contains_profile_and_guardrail_state() {
    let out_dir = unique_dir("summary-md");
    let artifacts = write_tail_latency_control_plane_bundle(
        &out_dir,
        StressProfile::SyntheticContention,
        5,
        &["echo ci".into()],
    )
    .unwrap();
    let summary = fs::read_to_string(&artifacts.summary_path).unwrap();
    assert!(summary.contains("synthetic-contention"));
    assert!(
        summary.contains("fallback") || summary.contains("guardrail"),
        "summary should mention fallback or guardrail status"
    );
}

// =========================================================================
// Enrichment: repro.lock content
// =========================================================================

#[test]
fn repro_lock_contains_replay_command_and_epoch() {
    let out_dir = unique_dir("repro-lock");
    let artifacts = write_tail_latency_control_plane_bundle(
        &out_dir,
        StressProfile::Balanced,
        77,
        &["echo ci".into()],
    )
    .unwrap();
    let repro: serde_json::Value =
        serde_json::from_slice(&fs::read(&artifacts.repro_lock_path).unwrap()).unwrap();
    assert_eq!(repro["profile"], "balanced");
    assert_eq!(repro["epoch"], 77);
    let replay_cmd = repro["replay_command"].as_str().unwrap();
    assert!(replay_cmd.contains("franken_tail_latency_control_plane"));
    assert!(replay_cmd.contains("--profile balanced"));
    assert!(replay_cmd.contains("--epoch 77"));
}

// =========================================================================
// Enrichment: env.json content
// =========================================================================

#[test]
fn env_json_contains_component_and_profile() {
    let out_dir = unique_dir("env-json");
    let artifacts = write_tail_latency_control_plane_bundle(
        &out_dir,
        StressProfile::Balanced,
        10,
        &["echo ci".into()],
    )
    .unwrap();
    let env: serde_json::Value =
        serde_json::from_slice(&fs::read(&artifacts.env_path).unwrap()).unwrap();
    assert_eq!(env["component"], TAIL_LATENCY_CONTROL_PLANE_COMPONENT);
    assert_eq!(env["policy_id"], TAIL_LATENCY_CONTROL_PLANE_POLICY_ID);
    assert_eq!(env["profile"], "balanced");
    assert_eq!(env["epoch"], 10);
    assert!(env["os"].is_string());
    assert!(env["arch"].is_string());
}

// =========================================================================
// Enrichment: report epoch propagation
// =========================================================================

#[test]
fn report_bundle_epoch_matches_input() {
    let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 999).unwrap();
    assert_eq!(report.bundle_epoch, 999);
}

#[test]
fn report_profile_matches_input() {
    let report =
        build_tail_latency_control_plane_report(StressProfile::SyntheticContention, 1).unwrap();
    assert_eq!(report.profile, StressProfile::SyntheticContention);
}

// =========================================================================
// Enrichment: guardrail state serde roundtrip
// =========================================================================

#[test]
fn guardrail_state_serde_roundtrip() {
    for state in [
        GuardrailState::Nominal,
        GuardrailState::NearLimit,
        GuardrailState::FallbackEngaged,
    ] {
        let json = serde_json::to_string(&state).unwrap();
        let restored: GuardrailState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, restored);
    }
}

#[test]
fn stress_profile_serde_roundtrip() {
    for profile in [StressProfile::Balanced, StressProfile::SyntheticContention] {
        let json = serde_json::to_string(&profile).unwrap();
        let restored: StressProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile, restored);
    }
}
