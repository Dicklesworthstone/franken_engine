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

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::benchmark_denominator::{
    BenchmarkCase, NativeCoveragePoint, PublicationContext, PublicationGateInput,
    evaluate_publication_gate,
};
use frankenengine_engine::causal_replay::{
    CounterfactualConfig, DecisionSnapshot, NondeterminismSource, RecorderConfig, RecordingMode,
    TraceRecord, TraceRecorder,
};
use frankenengine_engine::containment_executor::ContainmentState;
use frankenengine_engine::incident_replay_bundle::{BundleBuilder, IncidentReplayBundle};
use frankenengine_engine::quarantine_mesh_gate::{
    CriterionResult, FaultScenarioResult, FaultType, GateValidationResult,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::third_party_verifier::{
    BenchmarkClaimBundle, ClaimedBenchmarkOutcome, ContainmentClaimBundle, ReplayClaimBundle,
    ThirdPartyVerificationReport, VerificationAttestation, VerificationAttestationInput,
    VerificationVerdict, generate_attestation, verify_attestation, verify_benchmark_claim,
    verify_containment_claim, verify_replay_claim,
};

fn temp_json_path(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    path.push(format!("{prefix}_{}_{}.json", std::process::id(), nonce));
    path
}

fn write_json<T: serde::Serialize>(prefix: &str, value: &T) -> PathBuf {
    let path = temp_json_path(prefix);
    fs::write(
        &path,
        serde_json::to_vec_pretty(value).expect("json serialization should succeed"),
    )
    .expect("json write should succeed");
    path
}

fn write_text(prefix: &str, value: &str) -> PathBuf {
    let path = temp_json_path(prefix);
    fs::write(&path, value).expect("text write should succeed");
    path
}

fn temp_bundle_dir(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    path.push(format!("{prefix}_{}_bundle_{}", std::process::id(), nonce));
    path
}

fn write_benchmark_verifier_bundle(prefix: &str, claim: &BenchmarkClaimBundle) -> PathBuf {
    let dir = temp_bundle_dir(prefix);
    fs::create_dir_all(&dir).expect("bundle directory should be creatable");

    let manifest = serde_json::json!({
        "schema_version": "franken-engine.benchmark.bundle.v1",
        "trace_id": claim.trace_id,
        "decision_id": claim.decision_id,
        "policy_id": claim.policy_id,
        "submission_id": "submission-test-001",
        "benchmark_version": "extension-heavy.v1",
    });
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("manifest should serialize"),
    )
    .expect("manifest write should succeed");

    let env = serde_json::json!({
        "toolchain": "nightly-x86_64-unknown-linux-gnu",
        "os": "linux",
        "arch": "x86_64",
    });
    fs::write(
        dir.join("env.json"),
        serde_json::to_vec_pretty(&env).expect("env should serialize"),
    )
    .expect("env write should succeed");

    let repro_lock = serde_json::json!({
        "schema_version": "franken-engine.benchmark.repro-lock.v1",
        "seed": 42,
        "run_id": "run-test-001",
    });
    fs::write(
        dir.join("repro.lock"),
        serde_json::to_vec_pretty(&repro_lock).expect("repro lock should serialize"),
    )
    .expect("repro lock write should succeed");

    fs::write(
        dir.join("commands.txt"),
        "rch exec -- cargo test -p frankenengine-engine --test benchmark_denominator\n",
    )
    .expect("commands log write should succeed");

    fs::write(
        dir.join("results.json"),
        serde_json::to_vec_pretty(claim).expect("results should serialize"),
    )
    .expect("results write should succeed");

    dir
}

fn make_signing_key(seed: u8) -> SigningKey {
    let mut key = [0u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = seed.wrapping_add(index as u8).wrapping_mul(7);
    }
    SigningKey::from_bytes(key)
}

fn make_trace(trace_id: &str) -> TraceRecord {
    let signing_key = make_signing_key(9);
    let mut recorder = TraceRecorder::new(RecorderConfig {
        trace_id: trace_id.to_string(),
        recording_mode: RecordingMode::Full,
        epoch: SecurityEpoch::from_raw(3),
        start_tick: 1000,
        signing_key: signing_key.as_bytes().to_vec(),
    });

    recorder.record_nondeterminism(
        NondeterminismSource::Timestamp,
        vec![0, 0, 0, 0, 0, 0, 3, 232],
        1000,
        None,
    );

    recorder.record_decision(DecisionSnapshot {
        decision_index: 0,
        trace_id: trace_id.to_string(),
        decision_id: "decision-001".to_string(),
        policy_id: "policy-001".to_string(),
        policy_version: 1,
        epoch: SecurityEpoch::from_raw(3),
        tick: 1001,
        threshold_millionths: 500_000,
        loss_matrix: BTreeMap::new(),
        evidence_hashes: Vec::new(),
        chosen_action: "allow".to_string(),
        outcome_millionths: 100_000,
        extension_id: "ext-001".to_string(),
        nondeterminism_range: (0, 0),
    });

    recorder.finalize()
}

fn make_incident_bundle() -> (IncidentReplayBundle, String) {
    let signing_key = make_signing_key(11);
    let verification_key_hex = signing_key.verification_key().to_hex();
    let trace = make_trace("trace-verify-001");
    let bundle = BundleBuilder::new(
        "incident-verify-001".to_string(),
        SecurityEpoch::from_raw(3),
        5000,
        "producer-key-001".to_string(),
        signing_key,
    )
    .window(1000, 2000)
    .trace("trace-verify-001".to_string(), trace)
    .build()
    .expect("bundle should build");

    (bundle, verification_key_hex)
}

fn make_replay_claim_bundle() -> ReplayClaimBundle {
    let (bundle, verification_key_hex) = make_incident_bundle();
    ReplayClaimBundle {
        trace_id: "trace-verify-001".to_string(),
        decision_id: "decision-verify-001".to_string(),
        policy_id: "policy-verify-001".to_string(),
        verification_timestamp_ns: 6000,
        current_epoch: 3,
        bundle,
        signature_verification_key_hex: Some(verification_key_hex),
        receipt_verification_keys_hex: BTreeMap::new(),
        counterfactual_configs: Vec::new(),
    }
}

fn make_counterfactual_config(branch_id: &str) -> CounterfactualConfig {
    CounterfactualConfig {
        branch_id: branch_id.to_string(),
        threshold_override_millionths: None,
        loss_matrix_overrides: BTreeMap::new(),
        policy_version_override: None,
        containment_overrides: BTreeMap::new(),
        evidence_weight_overrides: BTreeMap::new(),
        branch_from_index: 0,
    }
}

fn benchmark_case(workload_id: &str, franken_tps: f64, baseline_tps: f64) -> BenchmarkCase {
    BenchmarkCase {
        workload_id: workload_id.to_string(),
        throughput_franken_tps: franken_tps,
        throughput_baseline_tps: baseline_tps,
        weight: None,
        behavior_equivalent: true,
        latency_envelope_ok: true,
        error_envelope_ok: true,
    }
}

fn make_benchmark_claim_bundle() -> BenchmarkClaimBundle {
    let input = PublicationGateInput {
        node_cases: vec![
            benchmark_case("boot-storm/s", 3000.0, 900.0),
            benchmark_case("mixed-cpu-io/s", 2800.0, 800.0),
        ],
        bun_cases: vec![
            benchmark_case("boot-storm/s", 3000.0, 950.0),
            benchmark_case("mixed-cpu-io/s", 2800.0, 850.0),
        ],
        native_coverage_progression: vec![NativeCoveragePoint {
            recorded_at_utc: "2026-02-23T00:00:00Z".to_string(),
            native_slots: 42,
            total_slots: 48,
        }],
        replacement_lineage_ids: vec!["lineage-a".to_string()],
    };

    let ctx = PublicationContext::new(
        "trace-bench-001".to_string(),
        "decision-bench-001".to_string(),
        "policy-bench-001".to_string(),
    );
    let recomputed = evaluate_publication_gate(&input, &ctx).expect("benchmark gate should pass");

    BenchmarkClaimBundle {
        trace_id: "trace-bench-001".to_string(),
        decision_id: "decision-bench-001".to_string(),
        policy_id: "policy-bench-001".to_string(),
        input,
        claimed: ClaimedBenchmarkOutcome {
            score_vs_node: recomputed.score_vs_node,
            score_vs_bun: recomputed.score_vs_bun,
            publish_allowed: recomputed.publish_allowed,
            blockers: recomputed.blockers.clone(),
        },
    }
}

fn make_containment_claim_bundle() -> ContainmentClaimBundle {
    let scenarios = vec![FaultScenarioResult {
        scenario_id: "scenario-1".to_string(),
        fault_type: FaultType::NetworkPartition,
        passed: true,
        criteria: vec![CriterionResult {
            name: "autonomous-isolation".to_string(),
            passed: true,
            detail: "isolated in budget".to_string(),
        }],
        receipts_emitted: 1,
        final_state: Some(ContainmentState::Quarantined),
        detection_latency_ns: 100_000_000,
        isolation_verified: true,
        recovery_verified: true,
    }];

    ContainmentClaimBundle {
        trace_id: "trace-cont-001".to_string(),
        decision_id: "decision-cont-001".to_string(),
        policy_id: "policy-cont-001".to_string(),
        detection_latency_sla_ns: 500_000_000,
        result: GateValidationResult {
            seed: 7,
            scenarios,
            passed: true,
            total_scenarios: 1,
            passed_scenarios: 1,
            events: Vec::new(),
            result_digest: "digest-001".to_string(),
        },
    }
}

fn make_attestation_input(sign: bool) -> VerificationAttestationInput {
    let report = verify_benchmark_claim(&make_benchmark_claim_bundle());
    let signing_key = make_signing_key(27);
    VerificationAttestationInput {
        report,
        issued_at_utc: "2026-02-24T00:00:00Z".to_string(),
        verifier_name: "Verifier".to_string(),
        verifier_version: "v1.2.0".to_string(),
        verifier_environment: "linux-x86_64".to_string(),
        methodology: "benchmark_recompute_v1".to_string(),
        scope_limitations: vec!["requires equivalent workload environment".to_string()],
        signing_key_hex: sign.then(|| hex::encode(signing_key.as_bytes())),
    }
}

#[test]
fn benchmark_claim_verifies_when_claim_matches_computation() {
    let bundle = make_benchmark_claim_bundle();
    let report = verify_benchmark_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Verified);
    assert_eq!(report.exit_code(), 0);
    assert!(report.scope_limitations.is_empty());
    assert!(report.confidence_statement.contains("checks passed"));
}

#[test]
fn benchmark_claim_detects_tampered_score() {
    let mut bundle = make_benchmark_claim_bundle();
    bundle.claimed.score_vs_node += 0.25;
    let report = verify_benchmark_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name == "score_vs_node_matches" && !check.passed)
    );
}

#[test]
fn replay_claim_verifies_integrity_and_fidelity() {
    let bundle = make_replay_claim_bundle();
    let report = verify_replay_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Verified);
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn containment_claim_verifies_when_counts_and_sla_match() {
    let bundle = make_containment_claim_bundle();
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Verified);
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn containment_claim_fails_when_latency_exceeds_sla() {
    let mut bundle = make_containment_claim_bundle();
    bundle.result.scenarios[0].detection_latency_ns = 600_000_000;
    let report = verify_containment_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.name.contains("latency_sla:scenario-1") && !check.passed)
    );
}

#[test]
fn attestation_generation_signs_and_verifies_report() {
    let input = make_attestation_input(true);
    let attestation = generate_attestation(&input).expect("attestation generation should succeed");
    assert!(attestation.signer_verification_key_hex.is_some());
    assert!(attestation.signature_hex.is_some());

    let verification = verify_attestation(&attestation);
    assert_eq!(verification.claim_type, "attestation");
    assert_eq!(verification.verdict, VerificationVerdict::Verified);
    assert_eq!(verification.exit_code(), 0);
}

#[test]
fn attestation_verification_is_partial_when_unsigned() {
    let input = make_attestation_input(false);
    let attestation = generate_attestation(&input).expect("attestation generation should succeed");
    assert!(attestation.signer_verification_key_hex.is_none());
    assert!(attestation.signature_hex.is_none());

    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::PartiallyVerified);
    assert_eq!(verification.exit_code(), 24);
}

#[test]
fn attestation_verification_detects_digest_tampering() {
    let input = make_attestation_input(true);
    let mut attestation = generate_attestation(&input).expect("attestation generation should work");
    attestation.report_digest_hex = "00".repeat(32);

    let verification = verify_attestation(&attestation);
    assert_eq!(verification.verdict, VerificationVerdict::Failed);
    assert!(
        verification
            .checks
            .iter()
            .any(|check| check.name == "report_digest_matches" && !check.passed)
    );
}

#[test]
fn franken_verify_benchmark_command_exits_successfully() {
    let input = make_benchmark_claim_bundle();
    let input_path = write_json("tpv_benchmark", &input);

    let output = Command::new(env!("CARGO_BIN_EXE_franken-verify"))
        .args([
            "benchmark",
            "--input",
            input_path.to_str().expect("utf8 path"),
            "--summary",
        ])
        .output()
        .expect("benchmark command should execute");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("claim_type=benchmark"));
    assert!(stdout.contains("verdict=Verified"));

    let _ = fs::remove_file(input_path);
}

#[test]
fn franken_verify_benchmark_audit_command_exits_successfully() {
    let input = make_benchmark_claim_bundle();
    let input_path = write_json("tpv_benchmark_audit", &input);

    let output = Command::new(env!("CARGO_BIN_EXE_franken-verify"))
        .args([
            "benchmark",
            "audit",
            "--input",
            input_path.to_str().expect("utf8 path"),
            "--summary",
        ])
        .output()
        .expect("benchmark audit command should execute");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("claim_type=benchmark"));
    assert!(stdout.contains("verdict=Verified"));

    let _ = fs::remove_file(input_path);
}

#[test]
fn franken_verify_benchmark_verify_bundle_command_exits_successfully() {
    let input = make_benchmark_claim_bundle();
    let bundle_dir = write_benchmark_verifier_bundle("tpv_benchmark_bundle_ok", &input);

    let output = Command::new(env!("CARGO_BIN_EXE_franken-verify"))
        .args([
            "benchmark",
            "verify",
            "--bundle",
            bundle_dir.to_str().expect("utf8 bundle path"),
            "--summary",
        ])
        .output()
        .expect("benchmark verify bundle command should execute");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("claim_type=benchmark"));
    assert!(stdout.contains("verdict=Verified"));

    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn franken_verify_benchmark_reproduce_bundle_command_exits_successfully() {
    let input = make_benchmark_claim_bundle();
    let bundle_dir = write_benchmark_verifier_bundle("tpv_benchmark_bundle_reproduce", &input);

    let output = Command::new(env!("CARGO_BIN_EXE_franken-verify"))
        .args([
            "benchmark",
            "reproduce",
            "--bundle",
            bundle_dir.to_str().expect("utf8 bundle path"),
            "--summary",
        ])
        .output()
        .expect("benchmark reproduce bundle command should execute");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("claim_type=benchmark"));
    assert!(stdout.contains("verdict=Verified"));

    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn franken_verify_benchmark_verify_bundle_fails_when_commands_missing() {
    let input = make_benchmark_claim_bundle();
    let bundle_dir = write_benchmark_verifier_bundle("tpv_benchmark_bundle_missing_cmds", &input);
    fs::remove_file(bundle_dir.join("commands.txt")).expect("remove commands.txt");

    let output = Command::new(env!("CARGO_BIN_EXE_franken-verify"))
        .args([
            "benchmark",
            "verify",
            "--bundle",
            bundle_dir.to_str().expect("utf8 bundle path"),
        ])
        .output()
        .expect("benchmark verify bundle command should execute");

    assert_eq!(output.status.code(), Some(25));
    let report: ThirdPartyVerificationReport =
        serde_json::from_slice(&output.stdout).expect("report json");
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    assert!(report.checks.iter().any(|check| {
        check.name == "bundle_file_commands.txt_present"
            && !check.passed
            && check.error_code.as_deref() == Some("FE-TPV-BUNDLE-0001")
    }));

    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn franken_verify_benchmark_fairness_command_surfaces_mismatch_failure() {
    let mut input = make_benchmark_claim_bundle();
    input.input.bun_cases[0].workload_id = "different-workload".to_string();
    let input_path = write_json("tpv_benchmark_fairness_mismatch", &input);

    let output = Command::new(env!("CARGO_BIN_EXE_franken-verify"))
        .args([
            "benchmark",
            "fairness",
            "--input",
            input_path.to_str().expect("utf8 path"),
            "--summary",
        ])
        .output()
        .expect("benchmark fairness command should execute");

    assert_eq!(output.status.code(), Some(25));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("claim_type=benchmark_fairness"));
    assert!(stdout.contains("verdict=Failed"));

    let _ = fs::remove_file(input_path);
}

#[test]
fn franken_verify_benchmark_verify_bundle_fails_when_manifest_context_mismatches_results() {
    let input = make_benchmark_claim_bundle();
    let bundle_dir = write_benchmark_verifier_bundle("tpv_benchmark_bundle_ctx_mismatch", &input);
    let mut manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("manifest.json")).expect("manifest should be readable"),
    )
    .expect("manifest should parse");
    manifest["policy_id"] = serde_json::Value::String("policy-mismatch".to_string());
    fs::write(
        bundle_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("manifest serialize"),
    )
    .expect("manifest rewrite should succeed");

    let output = Command::new(env!("CARGO_BIN_EXE_franken-verify"))
        .args([
            "benchmark",
            "verify",
            "--bundle",
            bundle_dir.to_str().expect("utf8 bundle path"),
        ])
        .output()
        .expect("benchmark verify bundle command should execute");

    assert_eq!(output.status.code(), Some(25));
    let report: ThirdPartyVerificationReport =
        serde_json::from_slice(&output.stdout).expect("report json");
    assert_eq!(report.verdict, VerificationVerdict::Failed);
    assert!(report.checks.iter().any(|check| {
        check.name == "bundle_manifest_context_matches_claim"
            && !check.passed
            && check.error_code.as_deref() == Some("FE-TPV-BUNDLE-0003")
    }));

    let _ = fs::remove_dir_all(bundle_dir);
}

#[test]
fn franken_verify_containment_command_surfaces_failure_exit_code() {
    let mut input = make_containment_claim_bundle();
    input.result.scenarios[0].detection_latency_ns = 800_000_000;
    let input_path = write_json("tpv_containment", &input);

    let output = Command::new(env!("CARGO_BIN_EXE_franken-verify"))
        .args([
            "containment",
            "--input",
            input_path.to_str().expect("utf8 path"),
            "--summary",
        ])
        .output()
        .expect("containment command should execute");

    assert_eq!(output.status.code(), Some(25));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("claim_type=containment"));
    assert!(stdout.contains("verdict=Failed"));

    let _ = fs::remove_file(input_path);
}

#[test]
fn franken_verify_replay_command_supports_signature_and_counterfactual_files() {
    let mut input = make_replay_claim_bundle();
    let verification_key_hex = input
        .signature_verification_key_hex
        .clone()
        .expect("replay bundle includes signature key");
    input.signature_verification_key_hex = None;

    let input_path = write_json("tpv_replay_input", &input);
    let signature_key_path = write_text("tpv_replay_sig_key", &verification_key_hex);
    let counterfactual_path = write_json(
        "tpv_replay_counterfactual",
        &make_counterfactual_config("auditor-branch-1"),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_franken-verify"))
        .args([
            "replay",
            "--input",
            input_path.to_str().expect("utf8 path"),
            "--signature-key-file",
            signature_key_path.to_str().expect("utf8 path"),
            "--counterfactual-config-file",
            counterfactual_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("replay command should execute");

    assert_eq!(output.status.code(), Some(0));
    let report: ThirdPartyVerificationReport =
        serde_json::from_slice(&output.stdout).expect("replay report json");
    assert_eq!(report.verdict, VerificationVerdict::Verified);
    assert!(
        report
            .checks
            .iter()
            .any(|check| { check.name.starts_with("signature:") && check.passed })
    );
    assert!(
        report
            .checks
            .iter()
            .any(|check| { check.name.starts_with("counterfactual:") && check.passed })
    );

    let _ = fs::remove_file(input_path);
    let _ = fs::remove_file(signature_key_path);
    let _ = fs::remove_file(counterfactual_path);
}

#[test]
fn franken_verify_replay_command_supports_receipt_key_file_json_map() {
    let input = make_replay_claim_bundle();
    let verification_key_hex = input
        .signature_verification_key_hex
        .clone()
        .expect("replay bundle includes signature key");
    let input_path = write_json("tpv_replay_receipt_input", &input);

    let receipt_keys: BTreeMap<String, String> =
        BTreeMap::from([(hex::encode([1u8; 32]), verification_key_hex)]);
    let receipt_key_path = write_json("tpv_replay_receipt_keys", &receipt_keys);

    let output = Command::new(env!("CARGO_BIN_EXE_franken-verify"))
        .args([
            "replay",
            "--input",
            input_path.to_str().expect("utf8 path"),
            "--receipt-key-file",
            receipt_key_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("replay command should execute");

    assert_eq!(output.status.code(), Some(24));
    let report: ThirdPartyVerificationReport =
        serde_json::from_slice(&output.stdout).expect("replay report json");
    assert_eq!(report.verdict, VerificationVerdict::PartiallyVerified);
    assert!(report.scope_limitations.iter().any(|entry| {
        entry.contains("no receipts in bundle")
            || entry.contains("required receipt verification keys missing")
    }));
    assert!(report.confidence_statement.contains("scope limitation"));
    assert!(report.checks.iter().any(|check| {
        check.name == "receipts:receipts-present" && check.detail.contains("skipped:")
    }));

    let _ = fs::remove_file(input_path);
    let _ = fs::remove_file(receipt_key_path);
}

#[test]
fn franken_verify_replay_command_rejects_invalid_receipt_key_pair_flag() {
    let input = make_replay_claim_bundle();
    let input_path = write_json("tpv_replay_invalid_receipt_flag", &input);

    let output = Command::new(env!("CARGO_BIN_EXE_franken-verify"))
        .args([
            "replay",
            "--input",
            input_path.to_str().expect("utf8 path"),
            "--receipt-key",
            "missing-separator",
        ])
        .output()
        .expect("replay command should execute");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("--receipt-key expects"));

    let _ = fs::remove_file(input_path);
}

#[test]
fn franken_verify_attestation_create_and_verify_commands() {
    let input = make_attestation_input(true);
    let input_path = write_json("tpv_attestation_input", &input);

    let create_output = Command::new(env!("CARGO_BIN_EXE_franken-verify"))
        .args([
            "attestation",
            "create",
            "--input",
            input_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("attestation create command should execute");

    assert_eq!(create_output.status.code(), Some(0));
    let attestation: VerificationAttestation =
        serde_json::from_slice(&create_output.stdout).expect("attestation json");
    assert!(attestation.signature_hex.is_some());

    let attestation_path = write_json("tpv_attestation", &attestation);
    let verify_output = Command::new(env!("CARGO_BIN_EXE_franken-verify"))
        .args([
            "attestation",
            "verify",
            "--input",
            attestation_path.to_str().expect("utf8 path"),
            "--summary",
        ])
        .output()
        .expect("attestation verify command should execute");

    assert_eq!(verify_output.status.code(), Some(0));
    let stdout = String::from_utf8(verify_output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("claim_type=attestation"));
    assert!(stdout.contains("verdict=Verified"));

    let _ = fs::remove_file(input_path);
    let _ = fs::remove_file(attestation_path);
}

#[test]
fn franken_verify_attestation_create_supports_signing_key_file_override() {
    let mut input = make_attestation_input(false);
    input.signing_key_hex = None;
    let input_path = write_json("tpv_attestation_input_override", &input);

    let signing_key = make_signing_key(41);
    let signing_key_hex = hex::encode(signing_key.as_bytes());
    let signing_key_path = write_text("tpv_attestation_signing_key", &signing_key_hex);

    let create_output = Command::new(env!("CARGO_BIN_EXE_franken-verify"))
        .args([
            "attestation",
            "create",
            "--input",
            input_path.to_str().expect("utf8 path"),
            "--signing-key-file",
            signing_key_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("attestation create command should execute");

    assert_eq!(create_output.status.code(), Some(0));
    let attestation: VerificationAttestation =
        serde_json::from_slice(&create_output.stdout).expect("attestation json");
    assert!(attestation.signature_hex.is_some());
    assert!(attestation.signer_verification_key_hex.is_some());

    let _ = fs::remove_file(input_path);
    let _ = fs::remove_file(signing_key_path);
}

#[test]
fn franken_verify_attestation_create_rejects_ambiguous_signing_key_flags() {
    let mut input = make_attestation_input(false);
    input.signing_key_hex = None;
    let input_path = write_json("tpv_attestation_input_ambiguous", &input);

    let signing_key_hex = hex::encode(make_signing_key(51).as_bytes());
    let signing_key_path = write_text(
        "tpv_attestation_signing_key_ambiguous",
        &hex::encode(make_signing_key(52).as_bytes()),
    );

    let create_output = Command::new(env!("CARGO_BIN_EXE_franken-verify"))
        .args([
            "attestation",
            "create",
            "--input",
            input_path.to_str().expect("utf8 path"),
            "--signing-key-hex",
            &signing_key_hex,
            "--signing-key-file",
            signing_key_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("attestation create command should execute");

    assert_eq!(create_output.status.code(), Some(2));
    let stderr = String::from_utf8(create_output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("mutually exclusive"));

    let _ = fs::remove_file(input_path);
    let _ = fs::remove_file(signing_key_path);
}

// ────────────────────────────────────────────────────────────
// Enrichment batch 8: verdict serde, report serde, constants,
// render functions, exit codes, edge cases
// ────────────────────────────────────────────────────────────

use frankenengine_engine::third_party_verifier::{
    DEFAULT_CONTAINMENT_LATENCY_SLA_NS, EXIT_CODE_FAILED, EXIT_CODE_INCONCLUSIVE,
    EXIT_CODE_PARTIALLY_VERIFIED, EXIT_CODE_VERIFIED, THIRD_PARTY_VERIFIER_COMPONENT,
    VerificationCheckResult, VerifierEvent, render_attestation_summary, render_report_summary,
};

#[test]
fn verification_verdict_serde_round_trip() {
    for verdict in [
        VerificationVerdict::Verified,
        VerificationVerdict::PartiallyVerified,
        VerificationVerdict::Failed,
        VerificationVerdict::Inconclusive,
    ] {
        let json = serde_json::to_string(&verdict).expect("serialize");
        let recovered: VerificationVerdict = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(verdict, recovered);
    }
}

#[test]
fn verification_verdict_exit_codes_match_constants() {
    assert_eq!(
        VerificationVerdict::Verified.exit_code(),
        EXIT_CODE_VERIFIED
    );
    assert_eq!(
        VerificationVerdict::PartiallyVerified.exit_code(),
        EXIT_CODE_PARTIALLY_VERIFIED
    );
    assert_eq!(VerificationVerdict::Failed.exit_code(), EXIT_CODE_FAILED);
    assert_eq!(
        VerificationVerdict::Inconclusive.exit_code(),
        EXIT_CODE_INCONCLUSIVE
    );
}

#[test]
fn constants_are_stable() {
    assert_eq!(THIRD_PARTY_VERIFIER_COMPONENT, "third_party_verifier");
    assert_eq!(DEFAULT_CONTAINMENT_LATENCY_SLA_NS, 500_000_000);
    assert_eq!(EXIT_CODE_VERIFIED, 0);
    assert_eq!(EXIT_CODE_PARTIALLY_VERIFIED, 24);
    assert_eq!(EXIT_CODE_FAILED, 25);
    assert_eq!(EXIT_CODE_INCONCLUSIVE, 26);
}

#[test]
fn report_serde_round_trip() {
    let bundle = make_benchmark_claim_bundle();
    let report = verify_benchmark_claim(&bundle);
    let json = serde_json::to_string(&report).expect("serialize");
    let recovered: ThirdPartyVerificationReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report.verdict, recovered.verdict);
    assert_eq!(report.checks.len(), recovered.checks.len());
    assert_eq!(report.claim_type, recovered.claim_type);
}

#[test]
fn check_result_serde_round_trip() {
    let check = VerificationCheckResult {
        name: "test_check".to_string(),
        passed: true,
        detail: "all good".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&check).expect("serialize");
    let recovered: VerificationCheckResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(check, recovered);
}

#[test]
fn verifier_event_serde_round_trip() {
    let event = VerifierEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
        event: "verify_benchmark".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: VerifierEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, recovered);
}

#[test]
fn render_report_summary_contains_verdict() {
    let bundle = make_benchmark_claim_bundle();
    let report = verify_benchmark_claim(&bundle);
    let summary = render_report_summary(&report);
    assert!(summary.contains("verdict=Verified"));
    assert!(summary.contains("claim_type=benchmark"));
}

#[test]
fn render_attestation_summary_contains_verifier_info() {
    let input = make_attestation_input(true);
    let attestation = generate_attestation(&input).expect("create attestation");
    let summary = render_attestation_summary(&attestation);
    assert!(!summary.is_empty());
    assert!(summary.contains("v1.2.0")); // verifier_version
    assert!(summary.contains("signed=true"));
}

#[test]
fn replay_claim_with_counterfactual_config_still_verifies() {
    let mut bundle = make_replay_claim_bundle();
    bundle
        .counterfactual_configs
        .push(make_counterfactual_config("cf-branch-1"));
    let report = verify_replay_claim(&bundle);
    assert_eq!(report.verdict, VerificationVerdict::Verified);
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name.starts_with("counterfactual:"))
    );
}

#[test]
fn containment_claim_with_no_scenarios_passes_vacuously() {
    let mut bundle = make_containment_claim_bundle();
    bundle.result.scenarios.clear();
    bundle.result.total_scenarios = 0;
    bundle.result.passed_scenarios = 0;
    let report = verify_containment_claim(&bundle);
    // With no scenarios the checks pass vacuously
    assert_eq!(report.verdict, VerificationVerdict::Verified);
}
