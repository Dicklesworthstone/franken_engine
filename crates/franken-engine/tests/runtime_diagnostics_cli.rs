use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::containment_executor::{ContainmentReceipt, ContainmentState};
use frankenengine_engine::evidence_ledger::{
    CandidateAction, ChosenAction, DecisionType, EvidenceEntry, EvidenceEntryBuilder, Witness,
};
use frankenengine_engine::expected_loss_selector::ContainmentAction;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::hostcall_telemetry::{
    FlowLabel, HostcallResult, HostcallTelemetryRecord, HostcallType, RecordInput, RecorderConfig,
    ResourceDelta, TelemetryRecorder,
};
use frankenengine_engine::runtime_diagnostics_cli::{
    ContainmentReceiptEnvelope, EvidenceExportFilter, EvidenceSeverity, GaEvidenceArtifactCategory,
    GaEvidenceArtifactLink, GaEvidencePackageInput, GcPressureSample, HostcallTelemetryEnvelope,
    OnboardingReadinessClass, OnboardingRemediationEffort, OnboardingScorecardInput,
    OnboardingScorecardSignal, PreflightVerdict, ReplayArtifactRecord,
    RolloutDecisionArtifactInput, RolloutRecommendation, RuntimeDiagnosticsCliInput,
    RuntimeExtensionState, RuntimeStateInput, SchedulerLaneSample, SupportBundleRedactionPolicy,
    build_ga_evidence_package, build_onboarding_scorecard, build_rollout_decision_artifact,
    collect_runtime_diagnostics, export_evidence_bundle, export_support_bundle,
    parse_decision_type, parse_evidence_severity, render_diagnostics_summary,
    render_evidence_summary, render_ga_evidence_package_summary,
    render_onboarding_scorecard_summary, render_preflight_summary,
    render_rollout_decision_artifact_summary, render_support_bundle_summary, run_preflight_doctor,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn build_sample_input() -> RuntimeDiagnosticsCliInput {
    RuntimeDiagnosticsCliInput {
        trace_id: "trace-runtime-cli".to_string(),
        decision_id: "decision-runtime-cli".to_string(),
        policy_id: "policy-runtime-cli".to_string(),
        runtime_state: RuntimeStateInput {
            snapshot_timestamp_ns: 20_000,
            loaded_extensions: vec![
                RuntimeExtensionState {
                    extension_id: "ext-a".to_string(),
                    containment_state: ContainmentState::Running,
                },
                RuntimeExtensionState {
                    extension_id: "ext-b".to_string(),
                    containment_state: ContainmentState::Sandboxed,
                },
            ],
            active_policies: vec!["policy-main".to_string(), "policy-main".to_string()],
            security_epoch: SecurityEpoch::from_raw(11),
            gc_pressure: vec![
                GcPressureSample {
                    extension_id: "ext-b".to_string(),
                    used_bytes: 900,
                    budget_bytes: 1_000,
                },
                GcPressureSample {
                    extension_id: "ext-a".to_string(),
                    used_bytes: 120,
                    budget_bytes: 1_000,
                },
            ],
            scheduler_lanes: vec![
                SchedulerLaneSample {
                    lane: "ready".to_string(),
                    queue_depth: 40,
                    max_depth: 100,
                    tasks_submitted: 80,
                    tasks_scheduled: 60,
                    tasks_completed: 58,
                    tasks_timed_out: 2,
                },
                SchedulerLaneSample {
                    lane: "cancel".to_string(),
                    queue_depth: 1,
                    max_depth: 8,
                    tasks_submitted: 5,
                    tasks_scheduled: 5,
                    tasks_completed: 5,
                    tasks_timed_out: 0,
                },
            ],
        },
        evidence_entries: sample_evidence_entries(),
        hostcall_records: vec![sample_hostcall_envelope()],
        containment_receipts: vec![sample_containment_envelope()],
        replay_artifacts: vec![ReplayArtifactRecord {
            trace_id: "trace-incident".to_string(),
            extension_id: "ext-a".to_string(),
            timestamp_ns: 1_104,
            artifact_id: "replay-1".to_string(),
            replay_pointer: "artifacts/replay/trace-incident.json".to_string(),
        }],
    }
}

fn sample_evidence_entries() -> Vec<EvidenceEntry> {
    vec![
        EvidenceEntryBuilder::new(
            "trace-incident",
            "dec-101",
            "policy-main",
            SecurityEpoch::from_raw(11),
            DecisionType::SecurityAction,
        )
        .timestamp_ns(1_101)
        .candidate(CandidateAction::new("sandbox", 120_000))
        .chosen(ChosenAction {
            action_name: "sandbox".to_string(),
            expected_loss_millionths: 120_000,
            rationale: "min-loss".to_string(),
        })
        .witness(Witness {
            witness_id: "w-1".to_string(),
            witness_type: "posterior".to_string(),
            value: "0.91".to_string(),
        })
        .meta("extension_id", "ext-a")
        .build()
        .expect("security entry should build"),
        EvidenceEntryBuilder::new(
            "trace-incident",
            "dec-102",
            "policy-main",
            SecurityEpoch::from_raw(11),
            DecisionType::PolicyUpdate,
        )
        .timestamp_ns(1_102)
        .candidate(CandidateAction::new("rotate", 1))
        .chosen(ChosenAction {
            action_name: "rotate".to_string(),
            expected_loss_millionths: 1,
            rationale: "rotation".to_string(),
        })
        .build()
        .expect("policy entry should build"),
    ]
}

fn sample_hostcall_envelope() -> HostcallTelemetryEnvelope {
    let mut recorder = TelemetryRecorder::new(RecorderConfig::default());
    recorder
        .record(
            1_103,
            RecordInput {
                extension_id: "ext-a".to_string(),
                hostcall_type: HostcallType::FsRead,
                capability_used: frankenengine_engine::capability::RuntimeCapability::FsRead,
                arguments_hash: ContentHash::compute(b"args"),
                result_status: HostcallResult::Denied {
                    reason: "policy".to_string(),
                },
                duration_ns: 5_000,
                resource_delta: ResourceDelta::default(),
                flow_label: FlowLabel::new("public", "public"),
                decision_id: Some("dec-101".to_string()),
            },
        )
        .expect("record should succeed");
    let record: HostcallTelemetryRecord = recorder.records()[0].clone();

    HostcallTelemetryEnvelope {
        trace_id: "trace-incident".to_string(),
        policy_id: "policy-main".to_string(),
        record,
    }
}

fn sample_containment_envelope() -> ContainmentReceiptEnvelope {
    let mut metadata = BTreeMap::new();
    metadata.insert("decision_id".to_string(), "dec-101".to_string());

    let receipt = ContainmentReceipt {
        receipt_id: "cr-1".to_string(),
        action: ContainmentAction::Sandbox,
        target_extension_id: "ext-a".to_string(),
        previous_state: ContainmentState::Running,
        new_state: ContainmentState::Sandboxed,
        timestamp_ns: 1_104,
        duration_ns: 0,
        success: true,
        cooperative: false,
        evidence_refs: vec!["ev-1".to_string()],
        epoch: SecurityEpoch::from_raw(11),
        content_hash: ContentHash::compute(b"cr-1"),
        metadata,
    };

    ContainmentReceiptEnvelope {
        trace_id: "trace-incident".to_string(),
        policy_id: "policy-main".to_string(),
        receipt,
    }
}

fn write_input_file(input: &RuntimeDiagnosticsCliInput) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    path.push(format!(
        "runtime_diagnostics_cli_test_{}_{}.json",
        std::process::id(),
        nonce
    ));

    fs::write(
        &path,
        serde_json::to_vec_pretty(input).expect("sample input should serialize"),
    )
    .expect("input file should be written");

    path
}

#[test]
fn diagnostics_command_outputs_runtime_state_json() {
    let input = build_sample_input();
    let input_path = write_input_file(&input);

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args(["diagnostics", "--input"])
        .arg(&input_path)
        .output()
        .expect("diagnostics command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid json output");

    let security_epoch = json["security_epoch"]
        .as_u64()
        .or_else(|| json["security_epoch"]["epoch"].as_u64());
    assert_eq!(security_epoch, Some(11));
    assert_eq!(json["loaded_extensions"].as_array().map(Vec::len), Some(2));
    assert_eq!(json["active_policies"].as_array().map(Vec::len), Some(1));

    let _ = fs::remove_file(input_path);
}

#[test]
fn evidence_export_filters_by_extension_trace_and_time() {
    let input = build_sample_input();
    let input_path = write_input_file(&input);

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "export-evidence",
            "--input",
            input_path.to_str().expect("path should be utf8"),
            "--extension-id",
            "ext-a",
            "--trace-id",
            "trace-incident",
            "--start-ns",
            "1103",
            "--end-ns",
            "1104",
            "--severity",
            "warning",
        ])
        .output()
        .expect("export command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid json output");
    let records = json["records"]
        .as_array()
        .expect("records should be an array");

    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|record| {
        record["trace_id"] == "trace-incident"
            && record["extension_id"] == "ext-a"
            && (record["timestamp_ns"] == 1103 || record["timestamp_ns"] == 1104)
            && record["severity"] == "warning"
    }));

    let _ = fs::remove_file(input_path);
}

#[test]
fn evidence_export_is_deterministic_for_same_query() {
    let input = build_sample_input();
    let input_path = write_input_file(&input);

    let run = |path: &PathBuf| {
        Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
            .args(["export-evidence", "--input"])
            .arg(path)
            .output()
            .expect("export command should execute")
    };

    let first = run(&input_path);
    let second = run(&input_path);

    assert!(first.status.success());
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);

    let _ = fs::remove_file(input_path);
}

#[test]
fn export_summary_reports_empty_result_as_valid() {
    let input = build_sample_input();
    let input_path = write_input_file(&input);

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "export-evidence",
            "--input",
            input_path.to_str().expect("path should be utf8"),
            "--extension-id",
            "missing-ext",
            "--summary",
        ])
        .output()
        .expect("export command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert_eq!(
        stdout.trim(),
        "No evidence entries found for the specified filters."
    );

    let _ = fs::remove_file(input_path);
}

#[test]
fn export_output_contains_all_required_evidence_categories() {
    let input = build_sample_input();
    let input_path = write_input_file(&input);

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args(["export-evidence", "--input"])
        .arg(&input_path)
        .output()
        .expect("export command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid json output");
    let records = json["records"]
        .as_array()
        .expect("records should be an array");

    let mut kinds = BTreeMap::<String, u64>::new();
    for record in records {
        let kind = record["kind"]
            .as_str()
            .expect("kind should be a string")
            .to_string();
        *kinds.entry(kind).or_insert(0) += 1;
    }

    for required in [
        "decision_receipt",
        "policy_change",
        "hostcall_telemetry",
        "containment_action",
        "replay_artifact",
    ] {
        assert!(
            kinds.contains_key(required),
            "missing required kind {required}"
        );
    }

    let _ = fs::remove_file(input_path);
}

#[test]
fn support_bundle_command_redacts_sensitive_values_and_writes_files() {
    let mut input = build_sample_input();
    input.evidence_entries[0]
        .metadata
        .insert("api_token".to_string(), "secret-token-value".to_string());
    let input_path = write_input_file(&input);

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args(["support-bundle", "--input"])
        .arg(&input_path)
        .output()
        .expect("support-bundle command should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid json output");
    assert_eq!(
        json["index"]["schema_version"],
        "franken-engine.runtime-diagnostics.support-bundle.v1"
    );
    assert!(
        json["index"]["total_redacted_fields"]
            .as_u64()
            .expect("total_redacted_fields should be u64")
            >= 1
    );

    let files = json["files"].as_array().expect("files should be an array");
    let evidence_file = files
        .iter()
        .find(|file| file["path"] == "support_bundle/evidence_records.jsonl")
        .expect("evidence file should be present");
    let evidence_content = evidence_file["content"]
        .as_str()
        .expect("evidence file content should be a string");
    assert!(!evidence_content.contains("secret-token-value"));
    assert!(evidence_content.contains("sha256:REDACTED"));

    let mut out_dir = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    out_dir.push(format!(
        "runtime_diagnostics_support_bundle_out_{}_{}",
        std::process::id(),
        nonce
    ));

    let write_output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "support-bundle",
            "--input",
            input_path.to_str().expect("path should be utf8"),
            "--summary",
            "--out-dir",
            out_dir.to_str().expect("dir should be utf8"),
        ])
        .output()
        .expect("support-bundle write command should execute");
    assert!(write_output.status.success());

    let written_index = out_dir.join("support_bundle/index.json");
    let written_summary = out_dir.join("support_bundle/summary.md");
    assert!(written_index.exists(), "index file should be written");
    assert!(written_summary.exists(), "summary file should be written");

    let _ = fs::remove_file(input_path);
    let _ = fs::remove_dir_all(out_dir);
}

#[test]
fn doctor_command_outputs_preflight_json_and_summary() {
    let input = build_sample_input();
    let input_path = write_input_file(&input);

    let json_output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args(["doctor", "--input"])
        .arg(&input_path)
        .output()
        .expect("doctor command should execute");

    assert!(json_output.status.success());
    let json_stdout = String::from_utf8(json_output.stdout).expect("stdout should be utf8");
    let value: serde_json::Value = serde_json::from_str(&json_stdout).expect("valid json output");
    assert_eq!(value["verdict"], "yellow");
    assert_eq!(
        value["support_bundle"]["index"]["schema_version"],
        "franken-engine.runtime-diagnostics.support-bundle.v1"
    );
    assert!(
        value["blockers"]
            .as_array()
            .is_some_and(|blockers| !blockers.is_empty()),
        "expected preflight blockers for sample input"
    );

    let summary_output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "doctor",
            "--input",
            input_path.to_str().expect("path should be utf8"),
            "--summary",
        ])
        .output()
        .expect("doctor summary command should execute");
    assert!(summary_output.status.success());
    let summary_stdout =
        String::from_utf8(summary_output.stdout).expect("summary stdout should be utf8");
    assert!(summary_stdout.contains("verdict: yellow"));
    assert!(summary_stdout.contains("support_bundle_id: bundle-"));
    assert!(summary_stdout.contains("runtime_diagnostics doctor --input <path> --summary"));

    let _ = fs::remove_file(input_path);
}

#[test]
fn doctor_command_writes_support_bundle_and_preflight_report() {
    let input = build_sample_input();
    let input_path = write_input_file(&input);

    let mut out_dir = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    out_dir.push(format!(
        "runtime_diagnostics_doctor_out_{}_{}",
        std::process::id(),
        nonce
    ));

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "doctor",
            "--input",
            input_path.to_str().expect("path should be utf8"),
            "--summary",
            "--out-dir",
            out_dir.to_str().expect("dir should be utf8"),
        ])
        .output()
        .expect("doctor command should execute");
    assert!(output.status.success());

    let written_index = out_dir.join("support_bundle/index.json");
    let written_report = out_dir.join("support_bundle/preflight_report.json");
    assert!(written_index.exists(), "index file should be written");
    assert!(
        written_report.exists(),
        "preflight report should be written"
    );

    let report_content = fs::read_to_string(&written_report).expect("report should be readable");
    let report_json: serde_json::Value =
        serde_json::from_str(&report_content).expect("report should be valid json");
    assert_eq!(report_json["verdict"], "yellow");
    assert_eq!(
        report_json["support_bundle"]["index"]["schema_version"],
        "franken-engine.runtime-diagnostics.support-bundle.v1"
    );

    let _ = fs::remove_file(input_path);
    let _ = fs::remove_dir_all(out_dir);
}

#[test]
fn ga_evidence_package_command_requires_release_candidate() {
    let input = clean_input();
    let input_path = write_input_file(&input);

    let output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "ga-evidence-package",
            "--input",
            input_path.to_str().expect("path should be utf8"),
        ])
        .output()
        .expect("ga evidence package command should execute");
    assert!(!output.status.success());

    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("missing required --release-candidate <id>"));

    let _ = fs::remove_file(input_path);
}

#[test]
fn ga_evidence_package_command_outputs_json_and_writes_files() {
    let input = clean_input();
    let input_path = write_input_file(&input);

    let json_output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "ga-evidence-package",
            "--input",
            input_path.to_str().expect("path should be utf8"),
            "--release-candidate",
            "rc-2026-03-05",
            "--workload-id",
            "pkg/ga-cli",
            "--package-name",
            "ga-cli",
            "--target-platform",
            "linux-x64",
            "--conformance-artifact",
            "artifacts/conformance.json::spec parity",
            "--performance-artifact",
            "artifacts/perf.json::latency envelope",
            "--security-artifact",
            "artifacts/security.json::security review",
            "--third-party-replay-command",
            "nix run .#replay -- --release-candidate rc-2026-03-05",
        ])
        .output()
        .expect("ga evidence package command should execute");
    assert!(json_output.status.success());

    let json_stdout = String::from_utf8(json_output.stdout).expect("stdout should be utf8");
    let value: serde_json::Value = serde_json::from_str(&json_stdout).expect("valid json output");
    assert_eq!(
        value["schema_version"],
        "franken-engine.runtime-diagnostics.ga-evidence-package.v1"
    );
    assert_eq!(value["release_candidate_id"], "rc-2026-03-05");
    assert_eq!(value["ga_gate_consumable"], true);
    assert_eq!(value["index"]["total_external_artifacts"], 3);
    assert!(
        value["files"].as_array().is_some_and(|files| {
            files
                .iter()
                .any(|file| file["path"] == "ga_evidence_package/index.json")
        }),
        "ga evidence package files should include index.json"
    );

    let mut out_dir = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    out_dir.push(format!(
        "runtime_diagnostics_ga_evidence_out_{}_{}",
        std::process::id(),
        nonce
    ));

    let summary_output = Command::new(env!("CARGO_BIN_EXE_runtime_diagnostics"))
        .args([
            "ga-evidence-package",
            "--input",
            input_path.to_str().expect("path should be utf8"),
            "--summary",
            "--out-dir",
            out_dir.to_str().expect("dir should be utf8"),
            "--release-candidate",
            "rc-2026-03-05",
            "--workload-id",
            "pkg/ga-cli",
            "--package-name",
            "ga-cli",
            "--target-platform",
            "linux-x64",
            "--conformance-artifact",
            "artifacts/conformance.json::spec parity",
            "--performance-artifact",
            "artifacts/perf.json::latency envelope",
            "--security-artifact",
            "artifacts/security.json::security review",
            "--third-party-replay-command",
            "nix run .#replay -- --release-candidate rc-2026-03-05",
        ])
        .output()
        .expect("ga evidence package summary command should execute");
    assert!(summary_output.status.success());

    let summary_stdout =
        String::from_utf8(summary_output.stdout).expect("summary stdout should be utf8");
    assert!(summary_stdout.contains("release_candidate_id: rc-2026-03-05"));
    assert!(summary_stdout.contains("ga_gate_consumable: true"));

    assert!(
        out_dir
            .join("support_bundle/preflight_report.json")
            .exists(),
        "preflight report should be written"
    );
    assert!(
        out_dir.join("ga_evidence_package/index.json").exists(),
        "ga evidence package index should be written"
    );
    assert!(
        out_dir.join("ga_evidence_package/summary.md").exists(),
        "ga evidence package summary should be written"
    );

    let _ = fs::remove_file(input_path);
    let _ = fs::remove_dir_all(out_dir);
}

// ── Library API tests (not CLI binary) ──────────────────────────────────

fn clean_input() -> RuntimeDiagnosticsCliInput {
    let mut input = build_sample_input();
    input.evidence_entries.clear();
    input.containment_receipts.clear();
    input
        .hostcall_records
        .retain(|rec| matches!(rec.record.result_status, HostcallResult::Success));
    for sample in &mut input.runtime_state.gc_pressure {
        sample.used_bytes = sample.used_bytes.min(sample.budget_bytes);
    }
    for lane in &mut input.runtime_state.scheduler_lanes {
        lane.tasks_timed_out = 0;
        lane.queue_depth = 0;
    }
    input
}

fn build_clean_ga_package_input() -> GaEvidencePackageInput {
    let input = clean_input();
    let preflight = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let onboarding = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id: "pkg/ga".to_string(),
        package_name: "ga".to_string(),
        target_platforms: vec!["linux-x64".to_string()],
        preflight: preflight.clone(),
        external_signals: Vec::new(),
    });
    let artifact = build_rollout_decision_artifact(&RolloutDecisionArtifactInput {
        onboarding_scorecard: onboarding.clone(),
        compatibility_advisories: Vec::new(),
        platform_matrix_signals: Vec::new(),
    });

    GaEvidencePackageInput {
        release_candidate_id: "rc-2026-03-05".to_string(),
        support_bundle: preflight.support_bundle,
        onboarding_scorecard: onboarding,
        rollout_decision_artifact: artifact,
        external_evidence_links: vec![
            GaEvidenceArtifactLink {
                category: GaEvidenceArtifactCategory::Security,
                path: "artifacts/security.json".to_string(),
                description: "security review".to_string(),
            },
            GaEvidenceArtifactLink {
                category: GaEvidenceArtifactCategory::Conformance,
                path: "artifacts/conformance.json".to_string(),
                description: "spec parity".to_string(),
            },
            GaEvidenceArtifactLink {
                category: GaEvidenceArtifactCategory::Performance,
                path: "artifacts/perf.json".to_string(),
                description: "latency envelope".to_string(),
            },
        ],
        third_party_replay_commands: vec![
            "nix run .#replay -- --release-candidate rc-2026-03-05".to_string(),
        ],
    }
}

// ── collect_runtime_diagnostics ─────────────────────────────────────────

#[test]
fn lib_diagnostics_sorts_extensions_alphabetically() {
    let input = build_sample_input();
    let out = collect_runtime_diagnostics(
        &input.runtime_state,
        &input.trace_id,
        &input.decision_id,
        &input.policy_id,
    );
    assert_eq!(out.loaded_extensions[0].extension_id, "ext-a");
    assert_eq!(out.loaded_extensions[1].extension_id, "ext-b");
}

#[test]
fn lib_diagnostics_deduplicates_active_policies() {
    let input = build_sample_input();
    let out = collect_runtime_diagnostics(
        &input.runtime_state,
        &input.trace_id,
        &input.decision_id,
        &input.policy_id,
    );
    assert_eq!(out.active_policies, vec!["policy-main"]);
}

#[test]
fn lib_diagnostics_is_deterministic() {
    let input = build_sample_input();
    let left = collect_runtime_diagnostics(
        &input.runtime_state,
        &input.trace_id,
        &input.decision_id,
        &input.policy_id,
    );
    let right = collect_runtime_diagnostics(
        &input.runtime_state,
        &input.trace_id,
        &input.decision_id,
        &input.policy_id,
    );
    assert_eq!(left, right);
}

#[test]
fn lib_diagnostics_computes_gc_over_budget_flag() {
    let mut input = build_sample_input();
    input.runtime_state.gc_pressure = vec![
        GcPressureSample {
            extension_id: "over".to_string(),
            used_bytes: 2000,
            budget_bytes: 500,
        },
        GcPressureSample {
            extension_id: "under".to_string(),
            used_bytes: 100,
            budget_bytes: 500,
        },
    ];
    let out = collect_runtime_diagnostics(
        &input.runtime_state,
        &input.trace_id,
        &input.decision_id,
        &input.policy_id,
    );
    let over = out
        .gc_pressure
        .iter()
        .find(|g| g.extension_id == "over")
        .unwrap();
    let under = out
        .gc_pressure
        .iter()
        .find(|g| g.extension_id == "under")
        .unwrap();
    assert!(over.over_budget);
    assert!(!under.over_budget);
}

// ── render_diagnostics_summary ──────────────────────────────────────────

#[test]
fn lib_render_diagnostics_summary_contains_key_fields() {
    let input = build_sample_input();
    let out = collect_runtime_diagnostics(
        &input.runtime_state,
        &input.trace_id,
        &input.decision_id,
        &input.policy_id,
    );
    let rendered = render_diagnostics_summary(&out);
    assert!(rendered.contains("security_epoch: 11"));
    assert!(rendered.contains("loaded_extensions: 2"));
    assert!(rendered.contains("active_policies: 1"));
    assert!(rendered.contains("gc_pressure_rows:"));
    assert!(rendered.contains("scheduler_lanes:"));
}

// ── export_evidence_bundle ──────────────────────────────────────────────

#[test]
fn lib_export_evidence_bundle_default_filter_returns_all() {
    let input = build_sample_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    assert!(output.summary.total_records >= 5);
    assert!(!output.records.is_empty());
}

#[test]
fn lib_export_evidence_bundle_filter_by_extension() {
    let input = build_sample_input();
    let filter = EvidenceExportFilter {
        extension_id: Some("ext-a".to_string()),
        ..EvidenceExportFilter::default()
    };
    let output = export_evidence_bundle(&input, filter);
    assert!(
        output
            .records
            .iter()
            .all(|r| r.extension_id.as_deref() == Some("ext-a"))
    );
}

#[test]
fn lib_export_evidence_bundle_filter_by_severity() {
    let input = build_sample_input();
    let filter = EvidenceExportFilter {
        severity: Some(EvidenceSeverity::Critical),
        ..EvidenceExportFilter::default()
    };
    let output = export_evidence_bundle(&input, filter);
    assert!(
        output
            .records
            .iter()
            .all(|r| r.severity >= EvidenceSeverity::Critical)
    );
}

#[test]
fn lib_export_evidence_bundle_is_sorted_by_timestamp() {
    let input = build_sample_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    for window in output.records.windows(2) {
        assert!(window[0].timestamp_ns <= window[1].timestamp_ns);
    }
}

// ── render_evidence_summary ─────────────────────────────────────────────

#[test]
fn lib_render_evidence_summary_nonempty() {
    let input = build_sample_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    let rendered = render_evidence_summary(&output);
    assert!(rendered.contains("total_records:"));
    assert!(rendered.contains("counts_by_kind:"));
}

#[test]
fn lib_render_evidence_summary_empty_filter() {
    let input = build_sample_input();
    let filter = EvidenceExportFilter {
        extension_id: Some("nonexistent-ext".to_string()),
        ..EvidenceExportFilter::default()
    };
    let output = export_evidence_bundle(&input, filter);
    let rendered = render_evidence_summary(&output);
    assert!(rendered.contains("No evidence entries found"));
}

// ── export_support_bundle ───────────────────────────────────────────────

#[test]
fn lib_export_support_bundle_produces_required_files() {
    let input = build_sample_input();
    let output = export_support_bundle(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let paths: std::collections::BTreeSet<String> =
        output.files.iter().map(|f| f.path.clone()).collect();
    for required in [
        "support_bundle/run_manifest.json",
        "support_bundle/events.jsonl",
        "support_bundle/commands.txt",
        "support_bundle/runtime_diagnostics.json",
        "support_bundle/evidence_records.jsonl",
        "support_bundle/summary.md",
        "support_bundle/index.json",
    ] {
        assert!(paths.contains(required), "missing file: {required}");
    }
}

#[test]
fn lib_export_support_bundle_is_deterministic() {
    let input = build_sample_input();
    let left = export_support_bundle(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let right = export_support_bundle(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    assert_eq!(left, right);
    assert_eq!(left.index.bundle_id, right.index.bundle_id);
}

#[test]
fn lib_export_support_bundle_redacts_custom_fragments() {
    let mut input = build_sample_input();
    input.evidence_entries[0]
        .metadata
        .insert("api_token".to_string(), "secret-val".to_string());
    let policy =
        SupportBundleRedactionPolicy::with_additional_fragments(vec!["custom_key".to_string()]);
    let output = export_support_bundle(&input, EvidenceExportFilter::default(), policy);
    assert!(output.index.total_redacted_fields >= 1);
}

// ── render_support_bundle_summary ───────────────────────────────────────

#[test]
fn lib_render_support_bundle_summary_has_bundle_id() {
    let input = build_sample_input();
    let output = export_support_bundle(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let rendered = render_support_bundle_summary(&output);
    assert!(rendered.contains("bundle_id: bundle-"));
    assert!(rendered.contains("reproducible_commands:"));
}

// ── run_preflight_doctor ────────────────────────────────────────────────

#[test]
fn lib_preflight_doctor_green_for_clean_input() {
    let input = clean_input();
    let output = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    assert_eq!(output.verdict, PreflightVerdict::Green);
    assert!(output.mandatory_field_status.valid);
}

#[test]
fn lib_preflight_doctor_yellow_for_timed_out_tasks() {
    let mut input = clean_input();
    input.runtime_state.scheduler_lanes[0].tasks_timed_out = 1;
    let output = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    assert_eq!(output.verdict, PreflightVerdict::Yellow);
    assert!(
        output
            .blockers
            .iter()
            .any(|b| b.blocker_id.contains("scheduler_timeouts"))
    );
}

#[test]
fn lib_preflight_doctor_red_for_gc_over_budget() {
    let mut input = build_sample_input();
    input.runtime_state.gc_pressure = vec![GcPressureSample {
        extension_id: "ext-oom".to_string(),
        used_bytes: 5000,
        budget_bytes: 1000,
    }];
    let output = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    assert_eq!(output.verdict, PreflightVerdict::Red);
    assert!(
        output
            .blockers
            .iter()
            .any(|b| b.blocker_id.contains("gc_over_budget"))
    );
}

// ── render_preflight_summary ────────────────────────────────────────────

#[test]
fn lib_render_preflight_summary_contains_verdict() {
    let input = build_sample_input();
    let output = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let rendered = render_preflight_summary(&output);
    assert!(rendered.contains("verdict:"));
    assert!(rendered.contains("mandatory_fields_valid: true"));
    assert!(rendered.contains("support_bundle_id: bundle-"));
}

// ── build_onboarding_scorecard ──────────────────────────────────────────

#[test]
fn lib_onboarding_scorecard_ready_for_clean_workload() {
    let input = clean_input();
    let preflight = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let scorecard = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id: "pkg/clean".to_string(),
        package_name: "clean".to_string(),
        target_platforms: vec!["linux-x64".to_string()],
        preflight,
        external_signals: Vec::new(),
    });
    assert_eq!(scorecard.readiness, OnboardingReadinessClass::Ready);
    assert_eq!(
        scorecard.remediation_effort,
        OnboardingRemediationEffort::Low
    );
    assert_eq!(scorecard.score.critical_signals, 0);
}

#[test]
fn lib_onboarding_scorecard_blocked_with_critical_external_signal() {
    let input = clean_input();
    let preflight = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let scorecard = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id: "pkg/blocked".to_string(),
        package_name: "blocked".to_string(),
        target_platforms: vec!["linux-x64".to_string()],
        preflight,
        external_signals: vec![OnboardingScorecardSignal {
            signal_id: "critical-signal".to_string(),
            source: "external".to_string(),
            severity: EvidenceSeverity::Critical,
            summary: "critical issue found".to_string(),
            remediation: "fix it".to_string(),
            reproducible_command: "run-check".to_string(),
            evidence_links: vec!["link.json".to_string()],
            owner_hint: None,
        }],
    });
    assert_eq!(scorecard.readiness, OnboardingReadinessClass::Blocked);
    assert!(scorecard.score.critical_signals >= 1);
}

#[test]
fn lib_onboarding_scorecard_deduplicates_platforms() {
    let input = clean_input();
    let preflight = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let scorecard = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id: "pkg/dedup".to_string(),
        package_name: "dedup".to_string(),
        target_platforms: vec![
            "linux-x64".to_string(),
            "linux-x64".to_string(),
            "macos-arm64".to_string(),
        ],
        preflight,
        external_signals: Vec::new(),
    });
    assert_eq!(
        scorecard.target_platforms,
        vec!["linux-x64".to_string(), "macos-arm64".to_string()]
    );
}

#[test]
fn lib_onboarding_scorecard_is_deterministic() {
    let input = clean_input();
    let preflight = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let sc_input = OnboardingScorecardInput {
        workload_id: "pkg/det".to_string(),
        package_name: "det".to_string(),
        target_platforms: vec!["linux-x64".to_string()],
        preflight,
        external_signals: Vec::new(),
    };
    let left = build_onboarding_scorecard(&sc_input);
    let right = build_onboarding_scorecard(&sc_input);
    assert_eq!(left, right);
}

// ── render_onboarding_scorecard_summary ─────────────────────────────────

#[test]
fn lib_render_onboarding_scorecard_summary_contains_key_fields() {
    let input = clean_input();
    let preflight = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let scorecard = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id: "pkg/render".to_string(),
        package_name: "render".to_string(),
        target_platforms: vec!["linux-x64".to_string()],
        preflight,
        external_signals: Vec::new(),
    });
    let rendered = render_onboarding_scorecard_summary(&scorecard);
    assert!(rendered.contains("schema_version:"));
    assert!(rendered.contains("readiness:"));
    assert!(rendered.contains("reproducible_commands:"));
}

// ── build_rollout_decision_artifact ─────────────────────────────────────

#[test]
fn lib_rollout_artifact_promotes_clean_workload() {
    let input = clean_input();
    let preflight = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let onboarding = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id: "pkg/promote".to_string(),
        package_name: "promote".to_string(),
        target_platforms: vec!["linux-x64".to_string()],
        preflight,
        external_signals: Vec::new(),
    });
    let artifact = build_rollout_decision_artifact(&RolloutDecisionArtifactInput {
        onboarding_scorecard: onboarding,
        compatibility_advisories: Vec::new(),
        platform_matrix_signals: Vec::new(),
    });
    assert_eq!(artifact.recommendation, RolloutRecommendation::Promote);
    assert!(artifact.mandatory_field_status.valid);
    assert!(artifact.ga_gate_consumable);
}

#[test]
fn lib_rollout_artifact_rollback_for_platform_critical() {
    let input = clean_input();
    let preflight = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let onboarding = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id: "pkg/rollback".to_string(),
        package_name: "rollback".to_string(),
        target_platforms: vec!["linux-x64".to_string()],
        preflight,
        external_signals: Vec::new(),
    });
    let artifact = build_rollout_decision_artifact(&RolloutDecisionArtifactInput {
        onboarding_scorecard: onboarding,
        compatibility_advisories: Vec::new(),
        platform_matrix_signals: vec![OnboardingScorecardSignal {
            signal_id: "plat:crit".to_string(),
            source: "platform_matrix".to_string(),
            severity: EvidenceSeverity::Critical,
            summary: "critical platform gap".to_string(),
            remediation: "fix platform".to_string(),
            reproducible_command: "run-check".to_string(),
            evidence_links: vec!["plat.json".to_string()],
            owner_hint: None,
        }],
    });
    assert_eq!(artifact.recommendation, RolloutRecommendation::Rollback);
}

#[test]
fn lib_rollout_artifact_defers_on_missing_mandatory_fields() {
    let input = clean_input();
    let preflight = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let mut onboarding = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id: "pkg/defer".to_string(),
        package_name: "defer".to_string(),
        target_platforms: vec!["linux-x64".to_string()],
        preflight,
        external_signals: Vec::new(),
    });
    onboarding.workload_id.clear();
    onboarding.logs.clear();
    let artifact = build_rollout_decision_artifact(&RolloutDecisionArtifactInput {
        onboarding_scorecard: onboarding,
        compatibility_advisories: Vec::new(),
        platform_matrix_signals: Vec::new(),
    });
    assert_eq!(artifact.recommendation, RolloutRecommendation::Defer);
    assert!(!artifact.mandatory_field_status.valid);
    assert!(!artifact.ga_gate_consumable);
}

// ── render_rollout_decision_artifact_summary ────────────────────────────

#[test]
fn lib_render_rollout_decision_artifact_summary_contains_key_fields() {
    let input = clean_input();
    let preflight = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let onboarding = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id: "pkg/render-art".to_string(),
        package_name: "render-art".to_string(),
        target_platforms: vec!["linux-x64".to_string()],
        preflight,
        external_signals: Vec::new(),
    });
    let artifact = build_rollout_decision_artifact(&RolloutDecisionArtifactInput {
        onboarding_scorecard: onboarding,
        compatibility_advisories: Vec::new(),
        platform_matrix_signals: Vec::new(),
    });
    let rendered = render_rollout_decision_artifact_summary(&artifact);
    assert!(rendered.contains("schema_version:"));
    assert!(rendered.contains("recommendation: promote"));
    assert!(rendered.contains("ga_gate_consumable: true"));
    assert!(rendered.contains("reproducible_commands:"));
}

// ── build_ga_evidence_package ───────────────────────────────────────────

#[test]
fn lib_ga_evidence_package_is_deterministic_and_consumable_for_complete_inputs() {
    let mut input = build_clean_ga_package_input();
    input
        .external_evidence_links
        .push(input.external_evidence_links[0].clone());
    input
        .third_party_replay_commands
        .push("  nix run .#replay -- --release-candidate rc-2026-03-05  ".to_string());

    let left = build_ga_evidence_package(&input);
    let right = build_ga_evidence_package(&input);

    assert_eq!(left, right);
    assert!(left.ga_gate_consumable);
    assert!(left.mandatory_field_status.valid);
    assert_eq!(left.external_evidence_links.len(), 3);
    assert_eq!(left.index.total_external_artifacts, 3);
    assert!(
        left.reproducible_commands
            .iter()
            .any(|command| { command == "nix run .#replay -- --release-candidate rc-2026-03-05" }),
        "expected normalized third-party replay command"
    );
}

#[test]
fn lib_ga_evidence_package_fails_closed_when_required_artifact_category_missing() {
    let mut input = build_clean_ga_package_input();
    input
        .external_evidence_links
        .retain(|link| link.category != GaEvidenceArtifactCategory::Security);

    let output = build_ga_evidence_package(&input);

    assert!(!output.mandatory_field_status.valid);
    assert!(!output.ga_gate_consumable);
    assert!(
        output
            .mandatory_field_status
            .missing_fields
            .contains(&"external_evidence_links:security".to_string())
    );
}

#[test]
fn lib_render_ga_evidence_package_summary_contains_key_fields() {
    let output = build_ga_evidence_package(&build_clean_ga_package_input());
    let rendered = render_ga_evidence_package_summary(&output);

    assert!(rendered.contains("schema_version:"));
    assert!(rendered.contains("release_candidate_id: rc-2026-03-05"));
    assert!(rendered.contains("ga_gate_consumable: true"));
    assert!(rendered.contains("external_evidence_links:"));
    assert!(rendered.contains("reproducible_commands:"));
}

// ── parse_evidence_severity / parse_decision_type ───────────────────────

#[test]
fn lib_parse_evidence_severity_all_variants() {
    assert_eq!(
        parse_evidence_severity("info"),
        Some(EvidenceSeverity::Info)
    );
    assert_eq!(
        parse_evidence_severity("warning"),
        Some(EvidenceSeverity::Warning)
    );
    assert_eq!(
        parse_evidence_severity("critical"),
        Some(EvidenceSeverity::Critical)
    );
    assert_eq!(
        parse_evidence_severity("INFO"),
        Some(EvidenceSeverity::Info)
    );
    assert_eq!(
        parse_evidence_severity("  Warning  "),
        Some(EvidenceSeverity::Warning)
    );
    assert_eq!(parse_evidence_severity("unknown"), None);
    assert_eq!(parse_evidence_severity(""), None);
}

#[test]
fn lib_parse_decision_type_all_variants() {
    assert_eq!(
        parse_decision_type("security_action"),
        Some(DecisionType::SecurityAction)
    );
    assert_eq!(
        parse_decision_type("policy_update"),
        Some(DecisionType::PolicyUpdate)
    );
    assert_eq!(
        parse_decision_type("epoch_transition"),
        Some(DecisionType::EpochTransition)
    );
    assert_eq!(
        parse_decision_type("revocation"),
        Some(DecisionType::Revocation)
    );
    assert_eq!(
        parse_decision_type("EXTENSION_LIFECYCLE"),
        Some(DecisionType::ExtensionLifecycle)
    );
    assert_eq!(parse_decision_type("unknown"), None);
}

// ── SupportBundleRedactionPolicy ────────────────────────────────────────

#[test]
fn lib_redaction_policy_default_contains_standard_fragments() {
    let policy = SupportBundleRedactionPolicy::default();
    assert!(policy.key_fragments.contains(&"secret".to_string()));
    assert!(policy.key_fragments.contains(&"token".to_string()));
    assert!(policy.key_fragments.contains(&"password".to_string()));
}

#[test]
fn lib_redaction_policy_with_additional_fragments() {
    let policy =
        SupportBundleRedactionPolicy::with_additional_fragments(vec!["custom_field".to_string()]);
    assert!(policy.key_fragments.contains(&"custom_field".to_string()));
    assert!(policy.key_fragments.contains(&"secret".to_string()));
}

#[test]
fn lib_redaction_policy_extend_deduplicates_and_sorts() {
    let mut policy = SupportBundleRedactionPolicy::default();
    policy.extend_fragments(vec![
        "secret".to_string(),
        "SECRET".to_string(),
        "new_frag".to_string(),
    ]);
    let count = policy
        .key_fragments
        .iter()
        .filter(|f| *f == "secret")
        .count();
    assert_eq!(count, 1);
    assert!(policy.key_fragments.contains(&"new_frag".to_string()));
    for window in policy.key_fragments.windows(2) {
        assert!(window[0] <= window[1], "fragments should be sorted");
    }
}

// ── Enum Display and serde roundtrips ───────────────────────────────────

#[test]
fn lib_preflight_verdict_display() {
    assert_eq!(PreflightVerdict::Green.to_string(), "green");
    assert_eq!(PreflightVerdict::Yellow.to_string(), "yellow");
    assert_eq!(PreflightVerdict::Red.to_string(), "red");
}

#[test]
fn lib_preflight_verdict_serde_roundtrip() {
    for v in [
        PreflightVerdict::Green,
        PreflightVerdict::Yellow,
        PreflightVerdict::Red,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: PreflightVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn lib_onboarding_readiness_class_display() {
    assert_eq!(OnboardingReadinessClass::Ready.to_string(), "ready");
    assert_eq!(
        OnboardingReadinessClass::Conditional.to_string(),
        "conditional"
    );
    assert_eq!(OnboardingReadinessClass::Blocked.to_string(), "blocked");
}

#[test]
fn lib_onboarding_readiness_class_serde_roundtrip() {
    for v in [
        OnboardingReadinessClass::Ready,
        OnboardingReadinessClass::Conditional,
        OnboardingReadinessClass::Blocked,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: OnboardingReadinessClass = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn lib_onboarding_remediation_effort_display() {
    assert_eq!(OnboardingRemediationEffort::Low.to_string(), "low");
    assert_eq!(OnboardingRemediationEffort::Medium.to_string(), "medium");
    assert_eq!(OnboardingRemediationEffort::High.to_string(), "high");
}

#[test]
fn lib_onboarding_remediation_effort_serde_roundtrip() {
    for v in [
        OnboardingRemediationEffort::Low,
        OnboardingRemediationEffort::Medium,
        OnboardingRemediationEffort::High,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: OnboardingRemediationEffort = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn lib_rollout_recommendation_display() {
    assert_eq!(RolloutRecommendation::Promote.to_string(), "promote");
    assert_eq!(RolloutRecommendation::CanaryHold.to_string(), "canary_hold");
    assert_eq!(RolloutRecommendation::Rollback.to_string(), "rollback");
    assert_eq!(RolloutRecommendation::Defer.to_string(), "defer");
}

#[test]
fn lib_rollout_recommendation_serde_roundtrip() {
    for v in [
        RolloutRecommendation::Promote,
        RolloutRecommendation::CanaryHold,
        RolloutRecommendation::Rollback,
        RolloutRecommendation::Defer,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: RolloutRecommendation = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn lib_ga_evidence_artifact_category_serde_roundtrip() {
    for value in [
        GaEvidenceArtifactCategory::Conformance,
        GaEvidenceArtifactCategory::Performance,
        GaEvidenceArtifactCategory::Security,
    ] {
        let json = serde_json::to_string(&value).unwrap();
        let back: GaEvidenceArtifactCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(value, back);
    }
}

// ── Serde roundtrips for complex output types ───────────────────────────

#[test]
fn lib_runtime_diagnostics_output_serde_roundtrip() {
    let input = build_sample_input();
    let out = collect_runtime_diagnostics(
        &input.runtime_state,
        &input.trace_id,
        &input.decision_id,
        &input.policy_id,
    );
    let json = serde_json::to_string(&out).unwrap();
    let back: frankenengine_engine::runtime_diagnostics_cli::RuntimeDiagnosticsOutput =
        serde_json::from_str(&json).unwrap();
    assert_eq!(out, back);
}

#[test]
fn lib_evidence_export_output_serde_roundtrip() {
    let input = build_sample_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    let json = serde_json::to_string(&output).unwrap();
    let back: frankenengine_engine::runtime_diagnostics_cli::EvidenceExportOutput =
        serde_json::from_str(&json).unwrap();
    assert_eq!(output, back);
}

#[test]
fn lib_support_bundle_output_serde_roundtrip() {
    let input = build_sample_input();
    let output = export_support_bundle(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let json = serde_json::to_string(&output).unwrap();
    let back: frankenengine_engine::runtime_diagnostics_cli::SupportBundleOutput =
        serde_json::from_str(&json).unwrap();
    assert_eq!(output, back);
}

#[test]
fn lib_preflight_doctor_output_serde_roundtrip() {
    let input = build_sample_input();
    let output = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let json = serde_json::to_string(&output).unwrap();
    let back: frankenengine_engine::runtime_diagnostics_cli::PreflightDoctorOutput =
        serde_json::from_str(&json).unwrap();
    assert_eq!(output, back);
}

#[test]
fn lib_onboarding_scorecard_output_serde_roundtrip() {
    let input = clean_input();
    let preflight = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let scorecard = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id: "pkg/serde".to_string(),
        package_name: "serde".to_string(),
        target_platforms: vec!["linux-x64".to_string()],
        preflight,
        external_signals: Vec::new(),
    });
    let json = serde_json::to_string(&scorecard).unwrap();
    let back: frankenengine_engine::runtime_diagnostics_cli::OnboardingScorecardOutput =
        serde_json::from_str(&json).unwrap();
    assert_eq!(scorecard, back);
}

#[test]
fn lib_rollout_decision_artifact_output_serde_roundtrip() {
    let input = clean_input();
    let preflight = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let onboarding = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id: "pkg/serde-art".to_string(),
        package_name: "serde-art".to_string(),
        target_platforms: vec!["linux-x64".to_string()],
        preflight,
        external_signals: Vec::new(),
    });
    let artifact = build_rollout_decision_artifact(&RolloutDecisionArtifactInput {
        onboarding_scorecard: onboarding,
        compatibility_advisories: Vec::new(),
        platform_matrix_signals: Vec::new(),
    });
    let json = serde_json::to_string(&artifact).unwrap();
    let back: frankenengine_engine::runtime_diagnostics_cli::RolloutDecisionArtifactOutput =
        serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, back);
}

#[test]
fn lib_ga_evidence_package_output_serde_roundtrip() {
    let output = build_ga_evidence_package(&build_clean_ga_package_input());
    let json = serde_json::to_string(&output).unwrap();
    let back: frankenengine_engine::runtime_diagnostics_cli::GaEvidencePackageOutput =
        serde_json::from_str(&json).unwrap();
    assert_eq!(output, back);
}

// ── Clone independence ──────────────────────────────────────────────────

#[test]
fn lib_diagnostics_output_clone_independence() {
    let input = build_sample_input();
    let out = collect_runtime_diagnostics(
        &input.runtime_state,
        &input.trace_id,
        &input.decision_id,
        &input.policy_id,
    );
    let mut cloned = out.clone();
    cloned.active_policies.push("extra".to_string());
    assert_ne!(out.active_policies.len(), cloned.active_policies.len());
}

#[test]
fn lib_evidence_export_output_clone_independence() {
    let input = build_sample_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    let mut cloned = output.clone();
    cloned.records.clear();
    assert!(!output.records.is_empty());
}

// ── JSON field name contracts ───────────────────────────────────────────

#[test]
fn lib_preflight_doctor_output_json_field_contract() {
    let input = build_sample_input();
    let output = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let json = serde_json::to_string(&output).unwrap();
    for field in [
        "\"trace_id\"",
        "\"decision_id\"",
        "\"policy_id\"",
        "\"verdict\"",
        "\"rationale\"",
        "\"blockers\"",
        "\"mandatory_field_status\"",
        "\"diagnostics\"",
        "\"evidence_summary\"",
        "\"support_bundle\"",
        "\"logs\"",
    ] {
        assert!(json.contains(field), "missing JSON field: {field}");
    }
}

#[test]
fn lib_onboarding_scorecard_output_json_field_contract() {
    let input = clean_input();
    let preflight = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let scorecard = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id: "pkg/json".to_string(),
        package_name: "json".to_string(),
        target_platforms: vec!["linux-x64".to_string()],
        preflight,
        external_signals: Vec::new(),
    });
    let json = serde_json::to_string(&scorecard).unwrap();
    for field in [
        "\"schema_version\"",
        "\"workload_id\"",
        "\"package_name\"",
        "\"readiness\"",
        "\"remediation_effort\"",
        "\"score\"",
        "\"unresolved_signals\"",
        "\"next_steps\"",
        "\"reproducible_commands\"",
        "\"logs\"",
    ] {
        assert!(json.contains(field), "missing JSON field: {field}");
    }
}

#[test]
fn lib_rollout_decision_artifact_json_field_contract() {
    let input = clean_input();
    let preflight = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let onboarding = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id: "pkg/json-art".to_string(),
        package_name: "json-art".to_string(),
        target_platforms: vec!["linux-x64".to_string()],
        preflight,
        external_signals: Vec::new(),
    });
    let artifact = build_rollout_decision_artifact(&RolloutDecisionArtifactInput {
        onboarding_scorecard: onboarding,
        compatibility_advisories: Vec::new(),
        platform_matrix_signals: Vec::new(),
    });
    let json = serde_json::to_string(&artifact).unwrap();
    for field in [
        "\"schema_version\"",
        "\"recommendation\"",
        "\"mandatory_field_status\"",
        "\"ga_gate_consumable\"",
        "\"pilot_gate_consumable\"",
        "\"rationale\"",
        "\"merged_signals\"",
        "\"evidence_links\"",
    ] {
        assert!(json.contains(field), "missing JSON field: {field}");
    }
}

#[test]
fn lib_ga_evidence_package_json_field_contract() {
    let output = build_ga_evidence_package(&build_clean_ga_package_input());
    let json = serde_json::to_string(&output).unwrap();
    for field in [
        "\"schema_version\"",
        "\"release_candidate_id\"",
        "\"mandatory_field_status\"",
        "\"ga_gate_consumable\"",
        "\"risk_disposition\"",
        "\"external_evidence_links\"",
        "\"reproducible_commands\"",
        "\"index\"",
        "\"files\"",
        "\"logs\"",
    ] {
        assert!(json.contains(field), "missing JSON field: {field}");
    }
}
