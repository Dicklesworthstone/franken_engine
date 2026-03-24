#![forbid(unsafe_code)]
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

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::attested_execution_cell::{
    SoftwareTrustRoot, TrustLevel, TrustRootBackend,
};
use frankenengine_engine::containment_executor::ContainmentState;
use frankenengine_engine::deterministic_replay::{NondeterminismSource, NondeterminismTrace};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::mmr_proof::MerkleMountainRange;
use frankenengine_engine::proof_schema::{
    AttestationValidityWindow, OptReceipt, OptimizationClass, ReceiptAttestationBindings,
    proof_schema_version_current,
};
use frankenengine_engine::receipt_verifier_pipeline::{
    AttestationLayerInput, ConsistencyProofInput, LogOperatorKey, ReceiptVerifierCliInput,
    SignatureLayerInput, SignedLogCheckpoint, SignerRevocationCache, TransparencyLayerInput,
    UnifiedReceiptVerificationRequest,
};
use frankenengine_engine::runtime_diagnostics_cli::{
    GcPressureSample, RuntimeDiagnosticsCliInput, RuntimeExtensionState, RuntimeStateInput,
    SchedulerLaneSample,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{Signature, SigningKey, sign_preimage};
use frankenengine_engine::tee_attestation_policy::{
    AttestationFreshnessWindow, AttestationQuote as PolicyAttestationQuote, DecisionImpact,
    MeasurementAlgorithm, MeasurementDigest, PlatformTrustRoot, RevocationFallback,
    RevocationProbeStatus, RevocationSource, RevocationSourceType, TeeAttestationPolicy,
    TeePlatform, TrustRootPinning, TrustRootSource,
};
use std::collections::BTreeMap;

fn temp_path(name: &str, ext: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    path.push(format!("{name}_{}_{}.{}", std::process::id(), nonce, ext));
    path
}

fn temp_dir(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    path.push(format!("{name}_{}_{}", std::process::id(), nonce));
    fs::create_dir_all(&path).expect("temp dir should be creatable");
    path
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn write_source(path: &Path, source: &str) {
    fs::write(path, source).expect("source fixture should write");
}

fn parse_stdout_json(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("stdout should contain valid json")
}

fn digest_hex(byte: u8, byte_len: usize) -> String {
    let mut out = String::with_capacity(byte_len * 2);
    for _ in 0..byte_len {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn sample_receipt_policy(
    policy_epoch: SecurityEpoch,
    intel_digest_hex: String,
    trust_root_id: &str,
) -> TeeAttestationPolicy {
    let mut approved_measurements = BTreeMap::new();
    approved_measurements.insert(
        TeePlatform::IntelSgx,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: intel_digest_hex,
        }],
    );
    approved_measurements.insert(
        TeePlatform::ArmTrustZone,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: digest_hex(0x22, 32),
        }],
    );
    approved_measurements.insert(
        TeePlatform::ArmCca,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: digest_hex(0x44, 32),
        }],
    );
    approved_measurements.insert(
        TeePlatform::AmdSev,
        vec![MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: digest_hex(0x33, 48),
        }],
    );

    TeeAttestationPolicy {
        schema_version: 1,
        policy_epoch,
        approved_measurements,
        freshness_window: AttestationFreshnessWindow {
            standard_max_age_secs: 120,
            high_impact_max_age_secs: 30,
        },
        revocation_sources: vec![
            RevocationSource {
                source_id: "intel_pcs".to_string(),
                source_type: RevocationSourceType::IntelPcs,
                endpoint: "https://intel.example/pcs".to_string(),
                on_unavailable: RevocationFallback::TryNextSource,
            },
            RevocationSource {
                source_id: "internal_ledger".to_string(),
                source_type: RevocationSourceType::InternalLedger,
                endpoint: "sqlite://revocations".to_string(),
                on_unavailable: RevocationFallback::FailClosed,
            },
        ],
        platform_trust_roots: vec![
            PlatformTrustRoot {
                root_id: trust_root_id.to_string(),
                platform: TeePlatform::IntelSgx,
                trust_anchor_pem: "-----BEGIN KEY-----intel-----END KEY-----".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(1),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
            PlatformTrustRoot {
                root_id: "arm-root".to_string(),
                platform: TeePlatform::ArmTrustZone,
                trust_anchor_pem: "-----BEGIN KEY-----arm-----END KEY-----".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(1),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
            PlatformTrustRoot {
                root_id: "cca-root".to_string(),
                platform: TeePlatform::ArmCca,
                trust_anchor_pem: "-----BEGIN KEY-----cca-----END KEY-----".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(1),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
            PlatformTrustRoot {
                root_id: "amd-root".to_string(),
                platform: TeePlatform::AmdSev,
                trust_anchor_pem: "-----BEGIN KEY-----amd-----END KEY-----".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(1),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
        ],
    }
}

fn build_valid_receipt_verifier_input() -> (String, ReceiptVerifierCliInput) {
    let receipt_id = "rcpt-001".to_string();
    let signer_key_id = EngineObjectId([0x44; 32]);
    let signer_key_bytes = vec![0x55; 32];

    let software_root = SoftwareTrustRoot::new("root-1", 7);
    let measurement = software_root.measure(
        b"code-v1",
        b"cfg-v1",
        b"policy-v1",
        b"schema-v1",
        "runtime-v1",
    );
    let nonce = [7u8; 32];
    let mut attestation_quote =
        software_root.attest(&measurement, nonce, 30_000_000_000, 10_000_000_000);
    attestation_quote.trust_level = TrustLevel::SoftwareOnly;

    let measurement_zone = "measurement-zone-test".to_string();
    let measurement_id = measurement
        .derive_id(&measurement_zone)
        .expect("measurement ID");
    let quote_digest =
        ContentHash::compute(&serde_json::to_vec(&attestation_quote).expect("quote json"));

    let mut replay_compatibility = BTreeMap::new();
    replay_compatibility.insert("arch".to_string(), "x86_64".to_string());
    replay_compatibility.insert("engine".to_string(), "franken-v1".to_string());

    let bindings = ReceiptAttestationBindings {
        quote_digest,
        measurement_id,
        attested_signer_key_id: signer_key_id.clone(),
        nonce,
        validity_window: AttestationValidityWindow {
            start_timestamp_ticks: 100,
            end_timestamp_ticks: 2_000,
        },
    };

    let unsigned_receipt = OptReceipt {
        schema_version: proof_schema_version_current(),
        optimization_id: "opt-01".to_string(),
        optimization_class: OptimizationClass::Superinstruction,
        baseline_ir_hash: ContentHash::compute(b"baseline"),
        candidate_ir_hash: ContentHash::compute(b"candidate"),
        translation_witness_hash: ContentHash::compute(b"translation"),
        invariance_digest: ContentHash::compute(b"invariance"),
        rollback_token_id: "rollback-01".to_string(),
        replay_compatibility,
        policy_epoch: SecurityEpoch::from_raw(5),
        timestamp_ticks: 1_000,
        signer_key_id: signer_key_id.clone(),
        correlation_id: "corr-01".to_string(),
        decision_impact: DecisionImpact::HighImpact,
        attestation_bindings: Some(bindings),
        signature: AuthenticityHash::compute_keyed(b"placeholder", b"placeholder"),
    };
    let receipt = unsigned_receipt.sign(&signer_key_bytes);
    let expected_preimage_hash = ContentHash::compute(&receipt.signing_preimage());

    let receipt_leaf_hash = ContentHash::compute(&receipt.signing_preimage());
    let leaf0 = ContentHash::compute(b"leaf0");
    let leaf1 = ContentHash::compute(b"leaf1");

    let mut old_mmr = MerkleMountainRange::new(5);
    old_mmr.append(leaf0);
    old_mmr.append(leaf1);
    let old_root = old_mmr.root_hash().expect("old root");

    let mut mmr = MerkleMountainRange::new(5);
    mmr.append(leaf0);
    mmr.append(leaf1);
    mmr.append(receipt_leaf_hash);
    let inclusion_proof = mmr.inclusion_proof(2).expect("inclusion");
    let consistency_proof = mmr.consistency_proof(2).expect("consistency");

    let operator_signing_key = SigningKey::from_bytes([9u8; 32]);
    let operator_verification_key = operator_signing_key.verification_key();
    let checkpoint_stub = SignedLogCheckpoint {
        checkpoint_seq: 1,
        log_length: inclusion_proof.stream_length,
        root_hash: mmr.root_hash().expect("root"),
        timestamp_ns: 20_000_000_000,
        operator_key_id: "operator-1".to_string(),
        signature: Signature::from_bytes([0u8; 64]),
    };
    let mut checkpoint = checkpoint_stub.clone();
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"FrankenEngine.ReceiptTransparencyCheckpoint.v1");
    preimage.extend_from_slice(&checkpoint_stub.checkpoint_seq.to_be_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(&checkpoint_stub.log_length.to_be_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(checkpoint_stub.root_hash.as_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(&checkpoint_stub.timestamp_ns.to_be_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(checkpoint_stub.operator_key_id.as_bytes());
    checkpoint.signature = sign_preimage(&operator_signing_key, &preimage).expect("checkpoint sig");

    let measurement_digest_hex = measurement.composite_hash().to_hex();
    let policy =
        sample_receipt_policy(SecurityEpoch::from_raw(5), measurement_digest_hex, "root-1");
    let mut revocation_observations = BTreeMap::new();
    revocation_observations.insert("intel_pcs".to_string(), RevocationProbeStatus::Good);
    revocation_observations.insert("internal_ledger".to_string(), RevocationProbeStatus::Good);

    let policy_quote = PolicyAttestationQuote {
        platform: TeePlatform::IntelSgx,
        measurement: MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: measurement.composite_hash().to_hex(),
        },
        quote_age_secs: 10,
        trust_root_id: "root-1".to_string(),
        revocation_observations,
    };

    let request = UnifiedReceiptVerificationRequest {
        trace_id: "trace-verify-01".to_string(),
        decision_id: "decision-verify-01".to_string(),
        policy_id: "policy-verify-01".to_string(),
        verification_timestamp_ns: 20_000_000_000,
        receipt,
        signature: SignatureLayerInput {
            expected_preimage_hash,
            signing_key_bytes: signer_key_bytes,
            signer_revocation: SignerRevocationCache {
                signer_key_id,
                source: "offline-signer-revocations".to_string(),
                is_revoked: false,
                cache_stale: false,
            },
        },
        transparency: TransparencyLayerInput {
            leaf_hash: receipt_leaf_hash,
            leaf_index: 2,
            inclusion_proof,
            consistency_proofs: vec![ConsistencyProofInput {
                from_root: old_root,
                proof: consistency_proof,
            }],
            checkpoint,
            operator_keys: vec![LogOperatorKey {
                key_id: "operator-1".to_string(),
                verification_key: operator_verification_key,
                revoked: false,
            }],
            cache_stale: false,
        },
        attestation: AttestationLayerInput {
            attestation_quote,
            policy_quote,
            policy,
            decision_impact: DecisionImpact::HighImpact,
            runtime_epoch: SecurityEpoch::from_raw(5),
            verification_time_ns: 20_000_000_000,
            measurement_zone,
            trust_roots: vec![software_root],
            policy_cache_stale: false,
            revocation_cache_stale: false,
        },
    };

    let mut receipts = BTreeMap::new();
    receipts.insert(receipt_id.clone(), request);
    (receipt_id, ReceiptVerifierCliInput { receipts })
}

fn write_receipt_verifier_input(path: &Path, input: &ReceiptVerifierCliInput) {
    fs::write(
        path,
        serde_json::to_vec_pretty(input).expect("receipt verifier input should serialize"),
    )
    .expect("receipt verifier input should write");
}

fn build_doctor_input() -> RuntimeDiagnosticsCliInput {
    RuntimeDiagnosticsCliInput {
        trace_id: "trace-frankenctl-doctor".to_string(),
        decision_id: "decision-frankenctl-doctor".to_string(),
        policy_id: "policy-frankenctl-doctor".to_string(),
        runtime_state: RuntimeStateInput {
            snapshot_timestamp_ns: 42_000,
            loaded_extensions: vec![RuntimeExtensionState {
                extension_id: "ext-doctor".to_string(),
                containment_state: ContainmentState::Running,
            }],
            active_policies: vec!["policy-main".to_string()],
            security_epoch: SecurityEpoch::from_raw(7),
            gc_pressure: vec![GcPressureSample {
                extension_id: "ext-doctor".to_string(),
                used_bytes: 128,
                budget_bytes: 1_024,
            }],
            scheduler_lanes: vec![SchedulerLaneSample {
                lane: "ready".to_string(),
                queue_depth: 1,
                max_depth: 8,
                tasks_submitted: 3,
                tasks_scheduled: 3,
                tasks_completed: 3,
                tasks_timed_out: 0,
            }],
        },
        evidence_entries: Vec::new(),
        hostcall_records: Vec::new(),
        containment_receipts: Vec::new(),
        replay_artifacts: Vec::new(),
    }
}

fn write_runtime_diagnostics_input(path: &Path, input: &RuntimeDiagnosticsCliInput) {
    fs::write(
        path,
        serde_json::to_vec_pretty(input).expect("runtime diagnostics input should serialize"),
    )
    .expect("runtime diagnostics input should write");
}

fn write_benchmark_score_input(path: &Path) {
    let score_input = serde_json::json!({
        "node_cases": [
            {
                "workload_id": "boot-storm/s",
                "throughput_franken_tps": 3000.0,
                "throughput_baseline_tps": 900.0,
                "weight": null,
                "behavior_equivalent": true,
                "latency_envelope_ok": true,
                "error_envelope_ok": true
            }
        ],
        "bun_cases": [
            {
                "workload_id": "boot-storm/s",
                "throughput_franken_tps": 3000.0,
                "throughput_baseline_tps": 950.0,
                "weight": null,
                "behavior_equivalent": true,
                "latency_envelope_ok": true,
                "error_envelope_ok": true
            }
        ],
        "native_coverage_progression": [
            {
                "recorded_at_utc": "2026-03-01T00:00:00Z",
                "native_slots": 42,
                "total_slots": 48
            }
        ],
        "replacement_lineage_ids": ["lineage-a"]
    });
    fs::write(
        path,
        serde_json::to_vec_pretty(&score_input).expect("score input should serialize"),
    )
    .expect("score input should write");
}

#[test]
fn frankenctl_help_lists_supported_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .arg("--help")
        .output()
        .expect("help command should execute");

    assert!(
        output.status.success(),
        "help failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(stdout.contains("frankenctl usage"));
    assert!(stdout.contains("frankenctl compile"));
    assert!(stdout.contains("frankenctl run"));
    assert!(stdout.contains("frankenctl doctor"));
    assert!(stdout.contains("frankenctl verify"));
    assert!(stdout.contains("frankenctl benchmark run"));
    assert!(stdout.contains("frankenctl benchmark score"));
    assert!(stdout.contains("frankenctl benchmark verify"));
    assert!(stdout.contains("frankenctl replay run"));
}

#[test]
fn frankenctl_react_help_is_available_without_changing_top_level_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(["react", "--help"])
        .output()
        .expect("react help should execute");

    assert!(
        output.status.success(),
        "react help failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(stdout.contains("react usage:"));
    assert!(stdout.contains("frankenctl react compile"));
    assert!(stdout.contains("frankenctl react build"));
    assert!(stdout.contains("frankenctl react contract"));
}

#[test]
fn frankenctl_react_contract_emits_machine_readable_contract() {
    let output_path = temp_path("frankenctl_react_contract", "json");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "react",
            "contract",
            "--trace-id",
            "trace-react-contract",
            "--decision-id",
            "decision-react-contract",
            "--policy-id",
            "policy-react-contract",
            "--out",
            output_path.to_str().expect("path should be utf8"),
        ])
        .output()
        .expect("react contract should execute");

    assert!(
        output.status.success(),
        "react contract failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout_json = parse_stdout_json(&output);
    assert_eq!(
        stdout_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.react-cli-contract.v1")
    );
    assert_eq!(
        stdout_json["trace_id"].as_str(),
        Some("trace-react-contract")
    );
    assert_eq!(
        stdout_json["decision_id"].as_str(),
        Some("decision-react-contract")
    );
    assert_eq!(
        stdout_json["policy_id"].as_str(),
        Some("policy-react-contract")
    );
    assert_eq!(
        stdout_json["capability_contract_schema_version"].as_str(),
        Some("rgc.react-capability-contract.v1")
    );
    assert_eq!(
        stdout_json["capability_contract_bead"].as_str(),
        Some("bd-1lsy.1.6.1")
    );
    assert_eq!(
        stdout_json["capability_contract_policy_id"].as_str(),
        Some("policy-rgc-react-capability-contract-v1")
    );
    assert!(
        stdout_json["commands"]
            .as_array()
            .is_some_and(|commands| commands.len() >= 3)
    );
    assert!(
        stdout_json["compile_capabilities"]
            .as_array()
            .is_some_and(|caps| !caps.is_empty())
    );
    let output_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&output_path).expect("contract output should exist"))
            .expect("contract output should parse");
    assert_eq!(stdout_json, output_json);

    let _ = fs::remove_file(output_path);
}

#[test]
fn frankenctl_react_compile_fails_closed_with_contract_guidance() {
    let source_path = temp_path("frankenctl_react_compile_source", "tsx");
    let report_path = temp_path("frankenctl_react_compile_report", "json");
    write_source(&source_path, "export const App = () => <div>Hello</div>;\n");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "react",
            "compile",
            "--input",
            source_path.to_str().expect("path should be utf8"),
            "--source-form",
            "tsx",
            "--runtime",
            "automatic",
            "--trace-id",
            "trace-react-compile",
            "--decision-id",
            "decision-react-compile",
            "--policy-id",
            "policy-react-compile",
            "--out",
            report_path.to_str().expect("path should be utf8"),
        ])
        .output()
        .expect("react compile should execute");

    assert_eq!(output.status.code(), Some(25));
    let stdout_json = parse_stdout_json(&output);
    assert_eq!(
        stdout_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.react-cli-report.v1")
    );
    assert_eq!(
        stdout_json["capability_id"].as_str(),
        Some("tsx-automatic-runtime-compile")
    );
    assert_eq!(stdout_json["support_status"].as_str(), Some("deferred"));
    assert_eq!(
        stdout_json["diagnostic"]["error_code"].as_str(),
        Some("FE-RGC-016A-CAP-0005")
    );
    assert_eq!(
        stdout_json["request"]["runtime_mode"].as_str(),
        Some("automatic")
    );
    let output_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).expect("react report should exist"))
            .expect("react report should parse");
    assert_eq!(stdout_json, output_json);

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(report_path);
}

fn assert_react_build_fails_closed(target: &str, capability_id: &str, error_code: &str) {
    let entry_name = format!("frankenctl_react_build_entry_{target}");
    let report_name = format!("frankenctl_react_build_report_{target}");
    let trace_id = format!("trace-react-build-{target}");
    let decision_id = format!("decision-react-build-{target}");
    let policy_id = format!("policy-react-build-{target}");
    let entry_path = temp_path(&entry_name, "jsx");
    let report_path = temp_path(&report_name, "json");
    write_source(
        &entry_path,
        "export default function App() { return <main />; }\n",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "react",
            "build",
            "--entry",
            entry_path.to_str().expect("path should be utf8"),
            "--target",
            target,
            "--trace-id",
            &trace_id,
            "--decision-id",
            &decision_id,
            "--policy-id",
            &policy_id,
            "--out",
            report_path.to_str().expect("path should be utf8"),
        ])
        .output()
        .expect("react build should execute");

    assert_eq!(output.status.code(), Some(25));
    let stdout_json = parse_stdout_json(&output);
    assert_eq!(stdout_json["capability_id"].as_str(), Some(capability_id));
    assert_eq!(stdout_json["support_status"].as_str(), Some("unsupported"));
    assert_eq!(
        stdout_json["diagnostic"]["error_code"].as_str(),
        Some(error_code)
    );
    assert_eq!(
        stdout_json["request"]["build_target"].as_str(),
        Some(target)
    );
    let output_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).expect("react build report should exist"))
            .expect("react build report should parse");
    assert_eq!(stdout_json, output_json);

    let _ = fs::remove_file(entry_path);
    let _ = fs::remove_file(report_path);
}

#[test]
fn frankenctl_react_build_fails_closed_with_contract_guidance() {
    assert_react_build_fails_closed("ssr", "react-ssr-entrypoint", "FE-RGC-016A-CAP-0007");
}

#[test]
fn frankenctl_react_example_app_client_build_fails_closed_with_contract_guidance() {
    assert_react_build_fails_closed(
        "client",
        "react-client-entry-preparation",
        "FE-RGC-016A-CAP-0008",
    );
}

#[test]
fn frankenctl_react_example_app_hydration_build_fails_closed_with_contract_guidance() {
    assert_react_build_fails_closed(
        "hydration",
        "react-hydration-handoff-artifacts",
        "FE-RGC-016A-CAP-0009",
    );
}

#[test]
fn frankenctl_react_cli_workflow_script_emits_expected_artifacts_and_routes() {
    let script =
        fs::read_to_string(repo_root().join("scripts/e2e/frankenctl_react_cli_workflow.sh"))
            .expect("react cli workflow script should exist");

    assert!(script.contains("source \"${root_dir}/scripts/e2e/parser_deterministic_env.sh\""));
    assert!(script.contains("parser_frontier_bootstrap_env"));
    assert!(script.contains(
        "artifact_root=\"${FRANKENCTL_REACT_CLI_ARTIFACT_ROOT:-artifacts/frankenctl_react_cli_workflow}\""
    ));
    assert!(script.contains("run_manifest.json"));
    assert!(script.contains("events.jsonl"));
    assert!(script.contains("commands.txt"));
    assert!(script.contains("trace_ids.json"));
    assert!(script.contains("react_cli_contract.json"));
    assert!(script.contains("react_compile_report.json"));
    assert!(script.contains("react_build_report.json"));
    assert!(script.contains("doctor_input.json"));
    assert!(script.contains("support_bundle/preflight_report.json"));
    assert!(script.contains("support_bundle/onboarding_scorecard.json"));
    assert!(script.contains("support_bundle/rollout_decision_artifact.json"));
    assert!(script.contains("support_bundle/frankenctl_doctor_report.json"));
    assert!(
        script.contains("cargo run -q -p frankenengine-engine --bin frankenctl -- react contract")
    );
    assert!(
        script.contains("cargo run -q -p frankenengine-engine --bin frankenctl -- react compile")
    );
    assert!(
        script.contains("cargo run -q -p frankenengine-engine --bin frankenctl -- react build")
    );
    assert!(script.contains("cargo run -q -p frankenengine-engine --bin frankenctl -- doctor"));
    assert!(
        script.contains("cargo run -q -p frankenengine-engine --bin frankenctl -- react --help")
    );
    assert!(script.contains("rch exec"));
    assert!(script.contains("falling back to local"));
    assert!(script.contains("usage: $0 [artifacts|check|test|clippy|ci]"));
}

#[test]
fn frankenctl_react_example_app_workflow_script_emits_expected_artifacts_and_routes() {
    let script = fs::read_to_string(
        repo_root().join("scripts/e2e/frankenctl_react_example_app_workflow.sh"),
    )
    .expect("react example-app workflow script should exist");

    assert!(script.contains("source \"${root_dir}/scripts/e2e/parser_deterministic_env.sh\""));
    assert!(script.contains("parser_frontier_bootstrap_env"));
    assert!(script.contains(
        "artifact_root=\"${FRANKENCTL_REACT_EXAMPLE_APP_ARTIFACT_ROOT:-artifacts/frankenctl_react_example_app_workflow}\""
    ));
    assert!(script.contains("scenario_id=\"bd-1lsy.10.12.3\""));
    assert!(script.contains("react_example_app_e2e_report.json"));
    assert!(script.contains("react_build_ssr_report.json"));
    assert!(script.contains("react_build_client_report.json"));
    assert!(script.contains("react_build_hydration_report.json"));
    assert!(script.contains("support_bundle/preflight_report.json"));
    assert!(script.contains("support_bundle/onboarding_scorecard.json"));
    assert!(script.contains("support_bundle/rollout_decision_artifact.json"));
    assert!(script.contains("support_bundle/frankenctl_doctor_report.json"));
    assert!(
        script.contains("cargo run -q -p frankenengine-engine --bin frankenctl -- react contract")
    );
    assert!(
        script.contains("cargo run -q -p frankenengine-engine --bin frankenctl -- react compile")
    );
    assert!(script.contains(
        "cargo run -q -p frankenengine-engine --bin frankenctl -- react build --entry ${build_entry_path} --target ssr"
    ));
    assert!(script.contains(
        "cargo run -q -p frankenengine-engine --bin frankenctl -- react build --entry ${build_entry_path} --target client"
    ));
    assert!(script.contains(
        "cargo run -q -p frankenengine-engine --bin frankenctl -- react build --entry ${build_entry_path} --target hydration"
    ));
    assert!(script.contains("cargo run -q -p frankenengine-engine --bin frankenctl -- doctor"));
    assert!(
        script.contains("cargo run -q -p frankenengine-engine --bin frankenctl -- react --help")
    );
    assert!(script.contains("rch exec"));
    assert!(script.contains("falling back to local"));
    assert!(script.contains("usage: $0 [artifacts|check|test|clippy|ci]"));
}

#[test]
fn frankenctl_cli_workflow_script_emits_trace_ids_artifact_contract() {
    let script = fs::read_to_string(repo_root().join("scripts/e2e/frankenctl_cli_workflow.sh"))
        .expect("frankenctl cli workflow script should exist");

    assert!(script.contains("trace_ids_path=\"${run_dir}/trace_ids.json\""));
    assert!(script.contains("franken-engine.frankenctl.cli.workflow.trace-ids.v1"));
    assert!(script.contains("\"trace_ids\": \"${trace_ids_path}\""));
    assert!(script.contains("cat ${trace_ids_path}"));
    assert!(script.contains("write_trace_ids"));
}

#[test]
fn frankenctl_cli_workflow_script_fails_closed_on_rch_drift() {
    let script = fs::read_to_string(repo_root().join("scripts/e2e/frankenctl_cli_workflow.sh"))
        .expect("frankenctl cli workflow script should exist");

    assert!(script.contains("${root_dir}/target_rch_frankenctl_cli_workflow"));
    assert!(
        script.contains("rch reported local fallback; refusing local execution for heavy command")
    );
    assert!(script.contains("rch output missing remote exit marker; failing closed"));
    assert!(script.contains("(missing-remote-exit-marker)"));
    assert!(!script.contains("warning: missing remote exit marker"));
}

#[test]
fn frankenctl_compile_then_verify_compile_artifact_round_trip() {
    let source_path = temp_path("frankenctl_compile_source", "js");
    let artifact_path = temp_path("frankenctl_compile_artifact", "json");
    write_source(&source_path, "const answer = 40 + 2;\n");

    let compile_output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "compile",
            "--input",
            source_path
                .to_str()
                .expect("source path should be valid utf8"),
            "--out",
            artifact_path
                .to_str()
                .expect("artifact path should be valid utf8"),
            "--goal",
            "script",
            "--trace-id",
            "trace-cli-compile",
            "--decision-id",
            "decision-cli-compile",
            "--policy-id",
            "policy-cli-compile",
        ])
        .output()
        .expect("compile command should execute");

    assert!(
        compile_output.status.success(),
        "compile failed with stderr={}",
        String::from_utf8_lossy(&compile_output.stderr)
    );
    let compile_json = parse_stdout_json(&compile_output);
    assert_eq!(
        compile_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );
    assert_eq!(compile_json["parse_goal"].as_str(), Some("script"));
    assert_eq!(
        compile_json["artifact_path"].as_str(),
        artifact_path.to_str()
    );
    assert_eq!(
        compile_json["source_ingestion"]["source_language"].as_str(),
        Some("javascript")
    );
    assert_eq!(
        compile_json["source_ingestion"]["normalization_applied"].as_bool(),
        Some(false)
    );

    let artifact_bytes = fs::read(&artifact_path).expect("compile artifact should exist");
    let artifact_json: serde_json::Value =
        serde_json::from_slice(&artifact_bytes).expect("artifact should be valid json");
    assert_eq!(
        artifact_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.compile-artifact.v1")
    );
    assert_eq!(
        artifact_json["source_ingestion"]["source_language"].as_str(),
        Some("javascript")
    );
    assert_eq!(
        artifact_json["source_ingestion"]["normalization_applied"].as_bool(),
        Some(false)
    );

    let verify_output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "verify",
            "compile-artifact",
            "--input",
            artifact_path
                .to_str()
                .expect("artifact path should be valid utf8"),
        ])
        .output()
        .expect("verify command should execute");

    assert!(
        verify_output.status.success(),
        "verify failed with stderr={}",
        String::from_utf8_lossy(&verify_output.stderr)
    );
    let verify_json = parse_stdout_json(&verify_output);
    assert_eq!(
        verify_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );
    assert_eq!(verify_json["passed"].as_bool(), Some(true));
    assert_eq!(verify_json["errors"].as_array().map(Vec::len), Some(0));

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(artifact_path);
}

#[test]
fn frankenctl_compile_normalizes_typescript_input() {
    let source_path = temp_path("frankenctl_compile_source_ts", "ts");
    let artifact_path = temp_path("frankenctl_compile_artifact_ts", "json");
    write_source(&source_path, "const answer: number = 40 + 2;\n");

    let compile_output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "compile",
            "--input",
            source_path
                .to_str()
                .expect("source path should be valid utf8"),
            "--out",
            artifact_path
                .to_str()
                .expect("artifact path should be valid utf8"),
            "--goal",
            "script",
            "--trace-id",
            "trace-cli-compile-ts",
            "--decision-id",
            "decision-cli-compile-ts",
            "--policy-id",
            "policy-cli-compile-ts",
        ])
        .output()
        .expect("compile command should execute");

    assert!(
        compile_output.status.success(),
        "compile failed with stderr={}",
        String::from_utf8_lossy(&compile_output.stderr)
    );
    let compile_json = parse_stdout_json(&compile_output);
    assert_eq!(
        compile_json["source_ingestion"]["source_language"].as_str(),
        Some("typescript")
    );
    assert_eq!(
        compile_json["source_ingestion"]["normalization_applied"].as_bool(),
        Some(true)
    );
    assert!(
        compile_json["source_ingestion"]["ts_decision_count"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );

    let artifact_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&artifact_path).expect("artifact should exist"))
            .expect("artifact should be valid json");
    assert_eq!(
        artifact_json["source_ingestion"]["source_language"].as_str(),
        Some("typescript")
    );
    assert_eq!(
        artifact_json["source_ingestion"]["normalization_applied"].as_bool(),
        Some(true)
    );
    assert_ne!(
        artifact_json["source_ingestion"]["original_source_hash"],
        artifact_json["source_ingestion"]["normalized_source_hash"]
    );

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(artifact_path);
}

#[test]
fn frankenctl_run_writes_execution_report() {
    let source_path = temp_path("frankenctl_run_source", "js");
    let report_path = temp_path("frankenctl_run_report", "json");
    write_source(&source_path, "let value = 2 + 3;\n");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            source_path
                .to_str()
                .expect("source path should be valid utf8"),
            "--extension-id",
            "ext-cli-run",
            "--out",
            report_path
                .to_str()
                .expect("report path should be valid utf8"),
        ])
        .output()
        .expect("run command should execute");

    assert!(
        output.status.success(),
        "run failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_json = parse_stdout_json(&output);
    assert_eq!(
        stdout_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );
    assert_eq!(stdout_json["extension_id"].as_str(), Some("ext-cli-run"));
    assert!(stdout_json["trace_id"].as_str().is_some());
    assert!(stdout_json["decision_id"].as_str().is_some());
    assert_eq!(
        stdout_json["source_ingestion"]["source_language"].as_str(),
        Some("javascript")
    );
    assert_eq!(
        stdout_json["source_ingestion"]["normalization_applied"].as_bool(),
        Some(false)
    );
    assert_eq!(
        stdout_json["lane"].as_str(),
        Some("baseline_deterministic_profile")
    );
    assert_eq!(
        stdout_json["lane_reason"].as_str(),
        Some("default_deterministic_profile")
    );
    assert!(stdout_json["containment_action"].as_str().is_some());

    let report_bytes = fs::read(&report_path).expect("run report should be written");
    let report_json: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("report should parse as json");
    assert_eq!(report_json["extension_id"].as_str(), Some("ext-cli-run"));
    assert_eq!(
        report_json["lane"].as_str(),
        Some("baseline_deterministic_profile")
    );
    assert_eq!(
        report_json["lane_reason"].as_str(),
        Some("default_deterministic_profile")
    );
    assert_eq!(
        report_json["source_ingestion"]["source_language"].as_str(),
        Some("javascript")
    );
    assert_eq!(
        report_json["source_ingestion"]["normalization_applied"].as_bool(),
        Some(false)
    );

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(report_path);
}

#[test]
fn frankenctl_run_normalizes_inline_typescript_input() {
    let source_path = temp_path("frankenctl_run_source_ts", "js");
    let report_path = temp_path("frankenctl_run_report_ts", "json");
    write_source(&source_path, "const value: number = 2 + 3;\n");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            source_path
                .to_str()
                .expect("source path should be valid utf8"),
            "--extension-id",
            "ext-cli-run-ts",
            "--out",
            report_path
                .to_str()
                .expect("report path should be valid utf8"),
        ])
        .output()
        .expect("run command should execute");

    assert!(
        output.status.success(),
        "run failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_json = parse_stdout_json(&output);
    assert_eq!(
        stdout_json["source_ingestion"]["source_language"].as_str(),
        Some("typescript")
    );
    assert_eq!(
        stdout_json["source_ingestion"]["normalization_applied"].as_bool(),
        Some(true)
    );
    assert!(
        stdout_json["source_ingestion"]["ts_decision_count"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );

    let report_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).expect("run report should be written"))
            .expect("report should parse as json");
    assert_eq!(
        report_json["source_ingestion"]["source_language"].as_str(),
        Some("typescript")
    );
    assert_eq!(
        report_json["source_ingestion"]["normalization_applied"].as_bool(),
        Some(true)
    );

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(report_path);
}

#[test]
fn frankenctl_replay_run_replays_trace_without_divergence() {
    let trace_path = temp_path("frankenctl_replay_trace", "json");
    let replay_report_path = temp_path("frankenctl_replay_report", "json");

    let mut trace = NondeterminismTrace::new("session-cli-replay");
    trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![7],
        1,
        "integration-test",
    );
    trace.capture(
        NondeterminismSource::TimerRead,
        vec![1, 2, 3],
        2,
        "integration-test",
    );
    trace.finalise(3);

    fs::write(
        &trace_path,
        serde_json::to_vec_pretty(&trace).expect("trace should serialize"),
    )
    .expect("trace file should write");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            trace_path
                .to_str()
                .expect("trace path should be valid utf8"),
            "--mode",
            "strict",
            "--out",
            replay_report_path
                .to_str()
                .expect("replay report path should be valid utf8"),
        ])
        .output()
        .expect("replay command should execute");

    assert!(
        output.status.success(),
        "replay failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_json = parse_stdout_json(&output);
    assert_eq!(
        stdout_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );
    assert_eq!(stdout_json["mode"].as_str(), Some("strict"));
    assert_eq!(stdout_json["event_count"].as_u64(), Some(2));
    assert_eq!(stdout_json["divergence_count"].as_u64(), Some(0));
    assert_eq!(stdout_json["critical_divergences"].as_u64(), Some(0));
    assert_eq!(stdout_json["complete"].as_bool(), Some(true));

    let report_bytes = fs::read(&replay_report_path).expect("replay report should be written");
    let report_json: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("replay report should parse as json");
    assert_eq!(
        report_json["session_id"].as_str(),
        Some("session-cli-replay")
    );

    let _ = fs::remove_file(trace_path);
    let _ = fs::remove_file(replay_report_path);
}

#[test]
fn frankenctl_verify_compile_artifact_failure_includes_trace_and_remediation() {
    let artifact_path = temp_path("frankenctl_invalid_compile_artifact", "json");
    fs::write(&artifact_path, "{}\n").expect("invalid artifact fixture should write");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "verify",
            "compile-artifact",
            "--input",
            artifact_path
                .to_str()
                .expect("artifact path should be valid utf8"),
        ])
        .output()
        .expect("verify command should execute");

    assert!(
        !output.status.success(),
        "verify compile-artifact should fail for invalid payload"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl trace_id=frankenctl-"),
        "stderr should include trace id, got: {stderr}"
    );
    assert!(
        stderr.contains("command=verify"),
        "stderr should include command label, got: {stderr}"
    );
    assert!(
        stderr.contains(
            "remediation: Inspect input artifact/receipt payload and rerun `frankenctl verify ...`."
        ),
        "stderr should include remediation guidance, got: {stderr}"
    );

    let _ = fs::remove_file(artifact_path);
}

// ── Version and help tests ────────────────────────────────────────────

#[test]
fn frankenctl_version_exits_successfully() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .arg("version")
        .output()
        .expect("version command should execute");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(!stdout.trim().is_empty(), "version should output something");
}

#[test]
fn frankenctl_dash_h_shows_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .arg("-h")
        .output()
        .expect("-h should execute");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(stdout.contains("frankenctl"));
}

#[test]
fn frankenctl_subcommand_help_paths_show_usage() {
    let cases: [(&[&str], &str); 12] = [
        (&["compile", "--help"], "compile usage:"),
        (&["run", "--help"], "run usage:"),
        (&["doctor", "--help"], "doctor usage:"),
        (&["verify", "--help"], "verify usage:"),
        (
            &["verify", "compile-artifact", "--help"],
            "verify compile-artifact usage:",
        ),
        (&["verify", "receipt", "--help"], "verify receipt usage:"),
        (&["benchmark", "--help"], "benchmark usage:"),
        (&["benchmark", "run", "--help"], "benchmark run usage:"),
        (&["benchmark", "score", "--help"], "benchmark score usage:"),
        (
            &["benchmark", "verify", "--help"],
            "benchmark verify usage:",
        ),
        (&["replay", "--help"], "replay usage:"),
        (&["replay", "run", "--help"], "replay run usage:"),
    ];

    for (args, expected) in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
            .args(args)
            .output()
            .expect("subcommand help should execute");
        assert!(
            output.status.success(),
            "help invocation {:?} failed with stderr={}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
        assert!(
            stdout.contains(expected),
            "help invocation {:?} should contain `{expected}`, got stdout={stdout}",
            args
        );
    }
}

#[test]
fn frankenctl_unknown_command_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .arg("nonexistent-command")
        .output()
        .expect("unknown command should execute");
    assert!(!output.status.success());
}

#[test]
fn frankenctl_no_args_shows_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .output()
        .expect("no-arg invocation should execute");
    // Should either show help or fail gracefully
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stdout.contains("frankenctl") || stderr.contains("frankenctl"),
        "should mention frankenctl in output"
    );
}

// ── Compile tests ─────────────────────────────────────────────────────

#[test]
fn frankenctl_compile_module_goal() {
    let source_path = temp_path("frankenctl_compile_module", "js");
    let artifact_path = temp_path("frankenctl_compile_module_artifact", "json");
    write_source(&source_path, "const x = 42;\n");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "compile",
            "--input",
            source_path.to_str().unwrap(),
            "--out",
            artifact_path.to_str().unwrap(),
            "--goal",
            "module",
            "--trace-id",
            "trace-module-compile",
            "--decision-id",
            "decision-module-compile",
            "--policy-id",
            "policy-module-compile",
        ])
        .output()
        .expect("compile module should execute");

    assert!(
        output.status.success(),
        "compile module failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output);
    assert_eq!(json["parse_goal"].as_str(), Some("module"));
    assert_eq!(
        json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(artifact_path);
}

#[test]
fn frankenctl_compile_missing_input_fails() {
    let artifact_path = temp_path("frankenctl_compile_no_input", "json");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(["compile", "--out", artifact_path.to_str().unwrap()])
        .output()
        .expect("compile with missing input should execute");

    assert!(!output.status.success());

    let _ = fs::remove_file(artifact_path);
}

#[test]
fn frankenctl_compile_nonexistent_source_fails() {
    let artifact_path = temp_path("frankenctl_compile_nosource", "json");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "compile",
            "--input",
            "/tmp/nonexistent_source_file_12345.js",
            "--out",
            artifact_path.to_str().unwrap(),
        ])
        .output()
        .expect("compile with nonexistent source should execute");

    assert!(!output.status.success());

    let _ = fs::remove_file(artifact_path);
}

#[test]
fn frankenctl_compile_default_trace_ids() {
    let source_path = temp_path("frankenctl_compile_defaults", "js");
    let artifact_path = temp_path("frankenctl_compile_defaults_art", "json");
    write_source(&source_path, "var x = 1;\n");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "compile",
            "--input",
            source_path.to_str().unwrap(),
            "--out",
            artifact_path.to_str().unwrap(),
        ])
        .output()
        .expect("compile with defaults should execute");

    assert!(
        output.status.success(),
        "compile defaults failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output);
    assert_eq!(json["parse_goal"].as_str(), Some("script"));
    assert!(json["hashes"]["parse_event_ir"].as_str().is_some());
    assert!(json["hashes"]["ir0"].as_str().is_some());

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(artifact_path);
}

// ── Run tests ─────────────────────────────────────────────────────────

#[test]
fn frankenctl_run_without_out_still_prints_json() {
    let source_path = temp_path("frankenctl_run_noout", "js");
    write_source(&source_path, "let z = 7;\n");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            source_path.to_str().unwrap(),
            "--extension-id",
            "ext-noout",
        ])
        .output()
        .expect("run without --out should execute");

    assert!(
        output.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output);
    assert_eq!(
        json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );
    assert_eq!(json["extension_id"].as_str(), Some("ext-noout"));
    assert!(json["trace_id"].as_str().is_some());

    let _ = fs::remove_file(source_path);
}

#[test]
fn frankenctl_run_missing_extension_id_fails() {
    let source_path = temp_path("frankenctl_run_no_extid", "js");
    write_source(&source_path, "let a = 1;\n");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(["run", "--input", source_path.to_str().unwrap()])
        .output()
        .expect("run without extension-id should execute");

    assert!(!output.status.success());

    let _ = fs::remove_file(source_path);
}

#[test]
fn frankenctl_doctor_outputs_json_and_writes_support_bundle() {
    let input_path = temp_path("frankenctl_doctor_input", "json");
    let out_dir = temp_dir("frankenctl_doctor_bundle");
    write_runtime_diagnostics_input(&input_path, &build_doctor_input());

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "doctor",
            "--input",
            input_path.to_str().unwrap(),
            "--workload-id",
            "demo-workload",
            "--package-name",
            "demo-package",
            "--target-platform",
            "linux-x86_64",
            "--out-dir",
            out_dir.to_str().unwrap(),
        ])
        .output()
        .expect("doctor command should execute");

    assert!(
        output.status.success(),
        "doctor failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output);
    assert_eq!(json["preflight_verdict"].as_str(), Some("green"));
    assert_eq!(json["readiness"].as_str(), Some("ready"));
    assert_eq!(json["rollout_recommendation"].as_str(), Some("promote"));
    assert_eq!(json["blocked"].as_bool(), Some(false));
    assert_eq!(json["signal_counts"]["external_signals"].as_u64(), Some(0));
    assert_eq!(
        json["signal_counts"]["compatibility_signals"].as_u64(),
        Some(0)
    );
    assert_eq!(json["signal_counts"]["platform_signals"].as_u64(), Some(0));
    assert!(
        out_dir
            .join("support_bundle/preflight_report.json")
            .is_file(),
        "expected preflight report to be written"
    );
    assert!(
        out_dir
            .join("support_bundle/onboarding_scorecard.json")
            .is_file(),
        "expected onboarding scorecard to be written"
    );
    assert!(
        out_dir
            .join("support_bundle/rollout_decision_artifact.json")
            .is_file(),
        "expected rollout decision artifact to be written"
    );
    assert!(
        out_dir
            .join("support_bundle/frankenctl_doctor_report.json")
            .is_file(),
        "expected doctor report to be written"
    );

    let _ = fs::remove_file(input_path);
    let _ = fs::remove_dir_all(out_dir);
}

#[test]
fn frankenctl_doctor_can_inline_compatibility_scenario_report() {
    let input_path = temp_path("frankenctl_doctor_input_with_advisories", "json");
    write_runtime_diagnostics_input(&input_path, &build_doctor_input());
    let scenario_report = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/runtime_compatibility_scenario_report_v1.json");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "doctor",
            "--input",
            input_path.to_str().unwrap(),
            "--scenario-report",
            scenario_report.to_str().unwrap(),
        ])
        .output()
        .expect("doctor command should execute");

    assert_eq!(
        output.status.code(),
        Some(25),
        "critical compatibility advisories should produce blocked exit code"
    );
    let json = parse_stdout_json(&output);
    assert_eq!(json["preflight_verdict"].as_str(), Some("green"));
    assert_eq!(
        json["signal_counts"]["compatibility_signals"].as_u64(),
        Some(1)
    );
    assert_eq!(json["blocked"].as_bool(), Some(true));
    assert!(
        json["rollout_decision"]["merged_signals"]
            .as_array()
            .is_some_and(|entries| !entries.is_empty()),
        "expected rollout decision to include compatibility advisory signal"
    );

    let _ = fs::remove_file(input_path);
}

#[test]
fn frankenctl_doctor_summary_mentions_verdict_and_recommendation() {
    let input_path = temp_path("frankenctl_doctor_summary_input", "json");
    write_runtime_diagnostics_input(&input_path, &build_doctor_input());

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "doctor",
            "--input",
            input_path.to_str().unwrap(),
            "--summary",
        ])
        .output()
        .expect("doctor --summary command should execute");

    assert!(
        output.status.success(),
        "doctor --summary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(stdout.contains("preflight_verdict: green"));
    assert!(stdout.contains("recommendation: promote"));
    assert!(stdout.contains("blocked: false"));

    let _ = fs::remove_file(input_path);
}

// ── Verify tests ──────────────────────────────────────────────────────

#[test]
fn frankenctl_verify_missing_subcommand_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .arg("verify")
        .output()
        .expect("verify without subcommand should execute");

    assert!(!output.status.success());
}

#[test]
fn frankenctl_verify_compile_artifact_nonexistent_file_fails() {
    let artifact_path = temp_path("frankenctl_verify_compile_artifact_missing_input", "json");
    let _ = fs::remove_file(&artifact_path);

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "verify",
            "compile-artifact",
            "--input",
            artifact_path
                .to_str()
                .expect("artifact path should be valid utf8"),
        ])
        .output()
        .expect("verify nonexistent file should execute");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("[frankenctl"));

    let _ = fs::remove_file(artifact_path);
}

#[test]
fn frankenctl_verify_receipt_missing_receipt_id_fails_with_parse_remediation() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(["verify", "receipt", "--input", "receipts.json"])
        .output()
        .expect("verify receipt parse failure should execute");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl trace_id=frankenctl-"),
        "stderr should include trace id, got: {stderr}"
    );
    assert!(
        stderr.contains("command=parse"),
        "stderr should include parse command label, got: {stderr}"
    );
    assert!(
        stderr.contains("verify receipt requires --receipt-id <id>"),
        "stderr should preserve parse failure, got: {stderr}"
    );
    assert!(
        stderr.contains(
            "remediation: Run `frankenctl --help` for full command usage and required arguments."
        ),
        "stderr should include parse remediation, got: {stderr}"
    );
}

#[test]
fn frankenctl_verify_receipt_nonexistent_file_fails_with_runtime_remediation() {
    let input_path = temp_path("frankenctl_verify_receipt_missing_input", "json");
    let _ = fs::remove_file(&input_path);

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "verify",
            "receipt",
            "--input",
            input_path.to_str().expect("path should be utf8"),
            "--receipt-id",
            "rcpt-1",
        ])
        .output()
        .expect("verify receipt nonexistent file should execute");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl trace_id=frankenctl-"),
        "stderr should include trace id, got: {stderr}"
    );
    assert!(
        stderr.contains("command=verify"),
        "stderr should include verify command label, got: {stderr}"
    );
    assert!(
        stderr.contains(
            "remediation: Inspect input artifact/receipt payload and rerun `frankenctl verify ...`."
        ),
        "stderr should include runtime remediation, got: {stderr}"
    );

    let _ = fs::remove_file(input_path);
}

#[test]
fn frankenctl_verify_receipt_unknown_receipt_id_fails_with_runtime_remediation() {
    let input_path = temp_path("frankenctl_verify_receipt_missing_id_input", "json");
    let (_receipt_id, input) = build_valid_receipt_verifier_input();
    write_receipt_verifier_input(&input_path, &input);

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "verify",
            "receipt",
            "--input",
            input_path.to_str().expect("path should be utf8"),
            "--receipt-id",
            "rcpt-missing",
        ])
        .output()
        .expect("verify receipt missing id command should execute");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl trace_id=frankenctl-"),
        "stderr should include trace id, got: {stderr}"
    );
    assert!(
        stderr.contains("command=verify"),
        "stderr should include verify command label, got: {stderr}"
    );
    assert!(
        stderr.contains(
            "receipt verification failed: receipt 'rcpt-missing' not found in verifier input"
        ),
        "stderr should preserve receipt-not-found failure, got: {stderr}"
    );
    assert!(
        stderr.contains(
            "remediation: Inspect input artifact/receipt payload and rerun `frankenctl verify ...`."
        ),
        "stderr should include runtime remediation, got: {stderr}"
    );

    let _ = fs::remove_file(input_path);
}

#[test]
fn frankenctl_verify_receipt_emits_json_verdict_for_valid_input() {
    let input_path = temp_path("frankenctl_verify_receipt_input", "json");
    let (receipt_id, input) = build_valid_receipt_verifier_input();
    write_receipt_verifier_input(&input_path, &input);

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "verify",
            "receipt",
            "--input",
            input_path.to_str().expect("path should be utf8"),
            "--receipt-id",
            receipt_id.as_str(),
        ])
        .output()
        .expect("verify receipt command should execute");

    assert!(
        output.status.success(),
        "verify receipt failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let verdict = parse_stdout_json(&output);
    assert_eq!(verdict["receipt_id"].as_str(), Some(receipt_id.as_str()));
    assert_eq!(verdict["trace_id"].as_str(), Some("trace-verify-01"));
    assert_eq!(verdict["decision_id"].as_str(), Some("decision-verify-01"));
    assert_eq!(verdict["policy_id"].as_str(), Some("policy-verify-01"));
    assert_eq!(verdict["passed"].as_bool(), Some(true));
    assert_eq!(verdict["exit_code"].as_i64(), Some(0));
    assert!(verdict["failure_class"].is_null());
    assert_eq!(verdict["signature"]["passed"].as_bool(), Some(true));
    assert_eq!(verdict["transparency"]["passed"].as_bool(), Some(true));
    assert_eq!(verdict["attestation"]["passed"].as_bool(), Some(true));
    assert_eq!(verdict["warnings"].as_array().map(Vec::len), Some(0));
    assert!(
        verdict["logs"]
            .as_array()
            .is_some_and(|logs| !logs.is_empty())
    );

    let _ = fs::remove_file(input_path);
}

#[test]
fn frankenctl_verify_receipt_summary_renders_human_verdict() {
    let input_path = temp_path("frankenctl_verify_receipt_summary_input", "json");
    let (receipt_id, input) = build_valid_receipt_verifier_input();
    write_receipt_verifier_input(&input_path, &input);

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "verify",
            "receipt",
            "--input",
            input_path.to_str().expect("path should be utf8"),
            "--receipt-id",
            receipt_id.as_str(),
            "--summary",
        ])
        .output()
        .expect("verify receipt summary command should execute");

    assert!(
        output.status.success(),
        "verify receipt --summary failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(stdout.contains("receipt=rcpt-001"));
    assert!(stdout.contains("passed=true"));
    assert!(stdout.contains("exit_code=0"));
    assert!(stdout.contains("failure_class=none"));
    assert!(stdout.contains("warnings=0"));

    let _ = fs::remove_file(input_path);
}

// ── Replay tests ──────────────────────────────────────────────────────

#[test]
fn frankenctl_replay_best_effort_mode() {
    let trace_path = temp_path("frankenctl_replay_besteffort", "json");
    let report_path = temp_path("frankenctl_replay_besteffort_report", "json");

    let mut trace = NondeterminismTrace::new("session-best-effort");
    trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![42],
        1,
        "integration-test",
    );
    trace.finalise(2);
    fs::write(&trace_path, serde_json::to_vec_pretty(&trace).unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            trace_path.to_str().unwrap(),
            "--mode",
            "best-effort",
            "--out",
            report_path.to_str().unwrap(),
        ])
        .output()
        .expect("replay best-effort should execute");

    assert!(
        output.status.success(),
        "replay best-effort failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output);
    assert_eq!(json["mode"].as_str(), Some("best-effort"));
    assert_eq!(json["event_count"].as_u64(), Some(1));

    let _ = fs::remove_file(trace_path);
    let _ = fs::remove_file(report_path);
}

#[test]
fn frankenctl_replay_validate_mode() {
    let trace_path = temp_path("frankenctl_replay_validate", "json");

    let mut trace = NondeterminismTrace::new("session-validate");
    trace.capture(
        NondeterminismSource::TimerRead,
        vec![10, 20],
        1,
        "integration-test",
    );
    trace.finalise(2);
    fs::write(&trace_path, serde_json::to_vec_pretty(&trace).unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            trace_path.to_str().unwrap(),
            "--mode",
            "validate",
        ])
        .output()
        .expect("replay validate should execute");

    assert!(
        output.status.success(),
        "replay validate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output);
    assert_eq!(json["mode"].as_str(), Some("validate"));

    let _ = fs::remove_file(trace_path);
}

#[test]
fn frankenctl_replay_nonexistent_trace_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            "/tmp/nonexistent_trace_99999.json",
        ])
        .output()
        .expect("replay nonexistent trace should execute");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("[frankenctl"));
}

#[test]
fn frankenctl_replay_missing_trace_arg_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(["replay", "run"])
        .output()
        .expect("replay without trace should execute");

    assert!(!output.status.success());
}

// ── Error output contract tests ───────────────────────────────────────

#[test]
fn frankenctl_error_output_includes_trace_id_and_remediation() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "compile",
            "--input",
            "/tmp/nonexistent_source_for_error_test.js",
            "--out",
            "/tmp/out.json",
        ])
        .output()
        .expect("compile error should execute");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl trace_id="),
        "error should include trace_id prefix: {stderr}"
    );
    assert!(
        stderr.contains("command=compile"),
        "error should include command label: {stderr}"
    );
    assert!(
        stderr.contains("remediation:"),
        "error should include remediation guidance: {stderr}"
    );
}

// ── Schema version contract tests ─────────────────────────────────────

#[test]
fn frankenctl_compile_output_schema_version_is_v1() {
    let source_path = temp_path("frankenctl_schema_check", "js");
    let artifact_path = temp_path("frankenctl_schema_check_art", "json");
    write_source(&source_path, "var q = true;\n");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "compile",
            "--input",
            source_path.to_str().unwrap(),
            "--out",
            artifact_path.to_str().unwrap(),
        ])
        .output()
        .expect("compile should execute");

    if output.status.success() {
        let json = parse_stdout_json(&output);
        assert_eq!(
            json["schema_version"].as_str(),
            Some("franken-engine.frankenctl.v1")
        );

        let art: serde_json::Value =
            serde_json::from_slice(&fs::read(&artifact_path).expect("artifact should exist"))
                .expect("artifact should parse");
        assert_eq!(
            art["schema_version"].as_str(),
            Some("franken-engine.frankenctl.compile-artifact.v1")
        );
    }

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(artifact_path);
}

#[test]
fn frankenctl_run_output_has_execution_fields() {
    let source_path = temp_path("frankenctl_run_fields", "js");
    write_source(&source_path, "let b = 2 * 3;\n");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            source_path.to_str().unwrap(),
            "--extension-id",
            "ext-fields",
        ])
        .output()
        .expect("run should execute");

    assert!(output.status.success());
    let json = parse_stdout_json(&output);
    assert!(json["lane"].as_str().is_some());
    assert!(json["containment_action"].as_str().is_some());
    assert!(json["instructions_executed"].as_u64().is_some());
    assert!(json["evidence_entries"].as_u64().is_some());

    let _ = fs::remove_file(source_path);
}

#[test]
fn frankenctl_benchmark_run_emits_minimal_artifact_bundle() {
    let output_dir = temp_dir("frankenctl_benchmark_run_bundle");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "benchmark",
            "run",
            "--seed",
            "7",
            "--run-id",
            "bench-run-cli",
            "--run-date",
            "2026-03-23",
            "--profile",
            "small",
            "--family",
            "boot-storm",
            "--out-dir",
            output_dir
                .to_str()
                .expect("benchmark output dir should be valid utf8"),
        ])
        .output()
        .expect("benchmark run command should execute");

    assert!(
        output.status.success(),
        "benchmark run failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output);
    assert_eq!(
        json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );
    assert_eq!(json["run_id"].as_str(), Some("bench-run-cli"));
    assert_eq!(json["run_date"].as_str(), Some("2026-03-23"));
    assert_eq!(json["seed"].as_u64(), Some(7));
    assert_eq!(json["blocked"].as_bool(), Some(false));
    assert_eq!(json["invariant_violations"].as_u64(), Some(0));
    assert!(
        json["total_operations"]
            .as_u64()
            .is_some_and(|value| value > 0),
        "benchmark run should report positive total_operations: {json}"
    );
    assert!(
        json["total_duration_us"]
            .as_u64()
            .is_some_and(|value| value > 0),
        "benchmark run should report positive total_duration_us: {json}"
    );
    assert_eq!(
        json["profiles"]
            .as_array()
            .expect("profiles should be an array")
            .iter()
            .filter_map(|value| value.as_str())
            .collect::<Vec<_>>(),
        vec!["S"]
    );
    assert_eq!(
        json["families"]
            .as_array()
            .expect("families should be an array")
            .iter()
            .filter_map(|value| value.as_str())
            .collect::<Vec<_>>(),
        vec!["boot-storm"]
    );

    let run_manifest_path = output_dir.join("run_manifest.json");
    let evidence_path = output_dir.join("benchmark_evidence.jsonl");
    let events_path = output_dir.join("events.jsonl");
    let commands_path = output_dir.join("commands.txt");
    let env_manifest_path = output_dir.join("benchmark_env_manifest.json");
    let raw_results_path = output_dir.join("raw_results_archive.json");
    let summary_path = output_dir.join("benchmark_summary.json");

    assert_eq!(
        json["artifacts"]["run_manifest"].as_str(),
        Some(
            run_manifest_path
                .to_str()
                .expect("run manifest path should be valid utf8")
        )
    );
    assert_eq!(
        json["artifacts"]["evidence_jsonl"].as_str(),
        Some(
            evidence_path
                .to_str()
                .expect("evidence path should be valid utf8")
        )
    );
    assert_eq!(
        json["artifacts"]["events_jsonl"].as_str(),
        Some(
            events_path
                .to_str()
                .expect("events path should be valid utf8")
        )
    );
    assert_eq!(
        json["artifacts"]["commands_txt"].as_str(),
        Some(
            commands_path
                .to_str()
                .expect("commands path should be valid utf8")
        )
    );
    assert_eq!(
        json["artifacts"]["benchmark_env_manifest"].as_str(),
        Some(
            env_manifest_path
                .to_str()
                .expect("env manifest path should be valid utf8")
        )
    );
    assert_eq!(
        json["artifacts"]["raw_results_archive"].as_str(),
        Some(
            raw_results_path
                .to_str()
                .expect("raw results path should be valid utf8")
        )
    );
    assert_eq!(
        json["artifacts"]["summary"].as_str(),
        Some(
            summary_path
                .to_str()
                .expect("summary path should be valid utf8")
        )
    );

    assert!(run_manifest_path.is_file());
    assert!(evidence_path.is_file());
    assert!(events_path.is_file());
    assert!(commands_path.is_file());
    assert!(env_manifest_path.is_file());
    assert!(raw_results_path.is_file());
    assert!(summary_path.is_file());

    let run_manifest_json: serde_json::Value = serde_json::from_slice(
        &fs::read(&run_manifest_path).expect("run manifest should be written"),
    )
    .expect("run manifest should parse");
    assert_eq!(run_manifest_json["run_id"].as_str(), Some("bench-run-cli"));
    assert_eq!(run_manifest_json["run_date"].as_str(), Some("2026-03-23"));
    assert_eq!(run_manifest_json["seed"].as_u64(), Some(7));
    assert_eq!(run_manifest_json["blocked"].as_bool(), Some(false));

    let summary_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&summary_path).expect("summary should be written"))
            .expect("summary should parse");
    assert_eq!(summary_json["run_id"].as_str(), Some("bench-run-cli"));
    assert_eq!(summary_json["blocked"].as_bool(), Some(false));
    assert!(
        summary_json["measurement_count"]
            .as_u64()
            .is_some_and(|value| value > 0),
        "benchmark summary should report at least one measurement: {summary_json}"
    );

    let commands = fs::read_to_string(&commands_path).expect("commands should be readable");
    assert!(commands.contains("cargo test -p frankenengine-engine"));
    assert!(commands.contains("scripts/run_benchmark_e2e_suite.sh report"));

    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn frankenctl_benchmark_run_missing_out_dir_value_fails_with_parse_remediation() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "benchmark",
            "run",
            "--profile",
            "small",
            "--family",
            "boot-storm",
            "--out-dir",
        ])
        .output()
        .expect("benchmark run parse failure should execute");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl trace_id=frankenctl-"),
        "stderr should include trace id, got: {stderr}"
    );
    assert!(
        stderr.contains("command=parse"),
        "stderr should include parse command label, got: {stderr}"
    );
    assert!(
        stderr.contains("--out-dir requires a value"),
        "stderr should preserve parse failure, got: {stderr}"
    );
    assert!(
        stderr.contains(
            "remediation: Run `frankenctl --help` for full command usage and required arguments."
        ),
        "stderr should include parse remediation, got: {stderr}"
    );
}

#[test]
fn frankenctl_benchmark_run_unknown_flag_fails_with_parse_remediation() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "benchmark",
            "run",
            "--profile",
            "small",
            "--family",
            "boot-storm",
            "--out-dir",
            "artifacts/bench-run-cli",
            "--bogus",
        ])
        .output()
        .expect("benchmark run unknown-flag failure should execute");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl trace_id=frankenctl-"),
        "stderr should include trace id, got: {stderr}"
    );
    assert!(
        stderr.contains("command=parse"),
        "stderr should include parse command label, got: {stderr}"
    );
    assert!(
        stderr.contains("unknown benchmark run flag `--bogus`"),
        "stderr should preserve parse failure, got: {stderr}"
    );
    assert!(
        stderr.contains(
            "remediation: Run `frankenctl --help` for full command usage and required arguments."
        ),
        "stderr should include parse remediation, got: {stderr}"
    );
}

#[test]
fn frankenctl_benchmark_score_missing_input_flag_fails_with_parse_remediation() {
    let output_path = temp_path("frankenctl_benchmark_score_missing_input", "json");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "benchmark",
            "score",
            "--output",
            output_path
                .to_str()
                .expect("score output path should be valid utf8"),
        ])
        .output()
        .expect("benchmark score missing-input failure should execute");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl trace_id=frankenctl-"),
        "stderr should include trace id, got: {stderr}"
    );
    assert!(
        stderr.contains("command=parse"),
        "stderr should include parse command label, got: {stderr}"
    );
    assert!(
        stderr.contains("benchmark score requires --input <path>"),
        "stderr should preserve parse failure, got: {stderr}"
    );
    assert!(
        stderr.contains(
            "remediation: Run `frankenctl --help` for full command usage and required arguments."
        ),
        "stderr should include parse remediation, got: {stderr}"
    );
}

#[test]
fn frankenctl_benchmark_score_unknown_flag_fails_with_parse_remediation() {
    let score_input_path = temp_path("frankenctl_benchmark_score_unknown_flag_input", "json");

    write_benchmark_score_input(&score_input_path);

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "benchmark",
            "score",
            "--input",
            score_input_path
                .to_str()
                .expect("score input path should be valid utf8"),
            "--bogus",
        ])
        .output()
        .expect("benchmark score unknown-flag failure should execute");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl trace_id=frankenctl-"),
        "stderr should include trace id, got: {stderr}"
    );
    assert!(
        stderr.contains("command=parse"),
        "stderr should include parse command label, got: {stderr}"
    );
    assert!(
        stderr.contains("unknown benchmark score flag `--bogus`"),
        "stderr should preserve parse failure, got: {stderr}"
    );
    assert!(
        stderr.contains(
            "remediation: Run `frankenctl --help` for full command usage and required arguments."
        ),
        "stderr should include parse remediation, got: {stderr}"
    );

    let _ = fs::remove_file(score_input_path);
}

#[test]
fn frankenctl_benchmark_score_nonexistent_input_fails_with_runtime_remediation() {
    let score_input_path = temp_path("frankenctl_benchmark_score_missing_input_file", "json");
    let score_output_path = temp_path("frankenctl_benchmark_score_missing_input_output", "json");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "benchmark",
            "score",
            "--input",
            score_input_path
                .to_str()
                .expect("score input path should be valid utf8"),
            "--output",
            score_output_path
                .to_str()
                .expect("score output path should be valid utf8"),
        ])
        .output()
        .expect("benchmark score missing-file failure should execute");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl trace_id=frankenctl-"),
        "stderr should include trace id, got: {stderr}"
    );
    assert!(
        stderr.contains("command=benchmark"),
        "stderr should include benchmark command label, got: {stderr}"
    );
    assert!(
        stderr.contains("failed to read"),
        "stderr should preserve read failure, got: {stderr}"
    );
    assert!(
        stderr.contains(
            score_input_path
                .to_str()
                .expect("score input path should be valid utf8")
        ),
        "stderr should include the missing input path, got: {stderr}"
    );
    assert!(
        stderr.contains(
            "remediation: Validate benchmark subcommand args (run|score|verify), then rerun `frankenctl benchmark ...`."
        ),
        "stderr should include runtime remediation, got: {stderr}"
    );
}

#[test]
fn frankenctl_benchmark_score_and_verify_bundle_round_trip() {
    let score_input_path = temp_path("frankenctl_benchmark_score_input", "json");
    let verify_report_path = temp_path("frankenctl_benchmark_verify_report", "json");
    let output_root = temp_dir("frankenctl_benchmark_bundle");
    let score_output_path = output_root.join("benchmark_score.json");
    let bundle_dir = output_root.join("benchmark_score.bundle");
    let bundle_results_path = bundle_dir.join("results.json");

    write_benchmark_score_input(&score_input_path);

    let score_output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "benchmark",
            "score",
            "--input",
            score_input_path
                .to_str()
                .expect("score input path should be valid utf8"),
            "--trace-id",
            "trace-bench-score-cli",
            "--decision-id",
            "decision-bench-score-cli",
            "--policy-id",
            "policy-bench-score-cli",
            "--output",
            score_output_path
                .to_str()
                .expect("score result path should be valid utf8"),
        ])
        .output()
        .expect("benchmark score command should execute");

    assert!(
        score_output.status.success(),
        "benchmark score failed with stderr={}",
        String::from_utf8_lossy(&score_output.stderr)
    );
    let score_json = parse_stdout_json(&score_output);
    assert_eq!(
        score_json["schema_version"].as_str(),
        Some("franken-engine.frankenctl.v1")
    );
    assert_eq!(
        score_json["trace_id"].as_str(),
        Some("trace-bench-score-cli")
    );
    assert_eq!(
        score_json["decision_id"].as_str(),
        Some("decision-bench-score-cli")
    );
    assert_eq!(
        score_json["policy_id"].as_str(),
        Some("policy-bench-score-cli")
    );
    assert_eq!(score_json["publish_allowed"].as_bool(), Some(true));
    assert_eq!(
        score_json["output"].as_str(),
        Some(
            score_output_path
                .to_str()
                .expect("score output path should be valid utf8")
        )
    );
    assert_eq!(
        score_json["bundle_env_path"].as_str(),
        Some(
            bundle_dir
                .join("env.json")
                .to_str()
                .expect("env path should be valid utf8")
        )
    );
    assert_eq!(
        score_json["benchmark_invocation_manifest_path"].as_str(),
        Some(
            bundle_dir
                .join("benchmark_invocation_manifest.json")
                .to_str()
                .expect("benchmark invocation manifest path should be valid utf8")
        )
    );
    assert_eq!(
        score_json["command_mode_receipt_path"].as_str(),
        Some(
            bundle_dir
                .join("command_mode_receipt.json")
                .to_str()
                .expect("command mode receipt path should be valid utf8")
        )
    );
    assert_eq!(
        score_json["runtime"]["mode"].as_str(),
        Some("deterministic-score")
    );
    assert_eq!(
        score_json["runtime"]["lane"].as_str(),
        Some("publication_gate")
    );
    assert_eq!(
        score_json["runtime"]["safe_mode_enabled"].as_bool(),
        Some(true)
    );
    assert!(
        score_json["runtime"]["feature_flags"]
            .as_array()
            .is_some_and(|flags| flags
                .iter()
                .any(|flag| flag.as_str() == Some("benchmark-score-cli")))
    );
    assert_eq!(
        score_json["bundle"].as_str(),
        Some(
            bundle_dir
                .to_str()
                .expect("bundle dir should be valid utf8")
        )
    );

    let results_json: serde_json::Value = serde_json::from_slice(
        &fs::read(&bundle_results_path).expect("score results should be written"),
    )
    .expect("score results should parse");
    assert_eq!(
        results_json["trace_id"].as_str(),
        Some("trace-bench-score-cli")
    );
    assert_eq!(
        results_json["claimed"]["publish_allowed"].as_bool(),
        Some(true)
    );
    let score_output_json: serde_json::Value = serde_json::from_slice(
        &fs::read(&score_output_path).expect("requested score output should be written"),
    )
    .expect("requested score output should parse");
    assert_eq!(score_output_json, results_json);
    assert!(bundle_dir.join("env.json").is_file());
    assert!(bundle_dir.join("manifest.json").is_file());
    assert!(bundle_dir.join("repro.lock").is_file());
    assert!(bundle_dir.join("commands.txt").is_file());
    assert!(
        bundle_dir
            .join("benchmark_invocation_manifest.json")
            .is_file()
    );
    assert!(bundle_dir.join("command_mode_receipt.json").is_file());
    let env_json: serde_json::Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("env.json")).expect("env.json should be written"),
    )
    .expect("env.json should parse");
    assert_eq!(
        env_json["runtime"]["mode"].as_str(),
        Some("deterministic-score")
    );
    assert_eq!(
        env_json["runtime"]["lane"].as_str(),
        Some("publication_gate")
    );
    assert_eq!(
        env_json["runtime"]["safe_mode_enabled"].as_bool(),
        Some(true)
    );
    assert!(
        env_json["runtime"]["feature_flags"]
            .as_array()
            .is_some_and(|flags| flags
                .iter()
                .any(|flag| flag.as_str() == Some("benchmark-score-cli")))
    );
    let manifest_json: serde_json::Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("manifest.json")).expect("manifest should be written"),
    )
    .expect("manifest should parse");
    assert_eq!(
        manifest_json["provenance"]["trace_id"].as_str(),
        Some("trace-bench-score-cli")
    );
    assert_eq!(
        manifest_json["artifacts"]["results"]["path"].as_str(),
        Some("results.json")
    );
    assert_eq!(
        manifest_json["artifacts"]["benchmark_invocation_manifest"]["path"].as_str(),
        Some("benchmark_invocation_manifest.json")
    );
    assert_eq!(
        manifest_json["artifacts"]["command_mode_receipt"]["path"].as_str(),
        Some("command_mode_receipt.json")
    );
    let benchmark_invocation_manifest_json: serde_json::Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("benchmark_invocation_manifest.json"))
            .expect("benchmark invocation manifest should be written"),
    )
    .expect("benchmark invocation manifest should parse");
    assert_eq!(
        benchmark_invocation_manifest_json["command"].as_str(),
        Some("frankenctl benchmark score")
    );
    assert_eq!(
        benchmark_invocation_manifest_json["requested_output_path"].as_str(),
        Some(
            score_output_path
                .to_str()
                .expect("requested output path should be valid utf8")
        )
    );
    assert_eq!(
        benchmark_invocation_manifest_json["artifacts"]["canonical_results"].as_str(),
        Some("results.json")
    );
    assert_eq!(
        benchmark_invocation_manifest_json["artifacts"]["command_mode_receipt"].as_str(),
        Some("command_mode_receipt.json")
    );
    assert_eq!(
        benchmark_invocation_manifest_json["runtime"]["mode"].as_str(),
        Some("deterministic-score")
    );
    let command_mode_receipt_json: serde_json::Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("command_mode_receipt.json"))
            .expect("command mode receipt should be written"),
    )
    .expect("command mode receipt should parse");
    assert_eq!(
        command_mode_receipt_json["command"].as_str(),
        Some("frankenctl benchmark score")
    );
    assert_eq!(
        command_mode_receipt_json["command_family"].as_str(),
        Some("benchmark")
    );
    assert_eq!(
        command_mode_receipt_json["runtime"]["mode"].as_str(),
        Some("deterministic-score")
    );
    assert_eq!(
        command_mode_receipt_json["runtime"]["lane"].as_str(),
        Some("publication_gate")
    );
    assert_eq!(
        command_mode_receipt_json["runtime"]["safe_mode_enabled"].as_bool(),
        Some(true)
    );
    let commands_txt =
        fs::read_to_string(bundle_dir.join("commands.txt")).expect("commands.txt should read");
    assert!(commands_txt.contains("rch exec --"));
    assert!(
        commands_txt.contains(
            score_output_path
                .to_str()
                .expect("score output path should be valid utf8")
        )
    );
    assert!(commands_txt.contains("frankenctl -- benchmark verify"));
    let repro_lock_json: serde_json::Value = serde_json::from_slice(
        &fs::read(bundle_dir.join("repro.lock")).expect("repro.lock should be written"),
    )
    .expect("repro.lock should parse");
    let expected_score_command = format!(
        "rch exec -- cargo run -p frankenengine-engine --bin frankenctl -- benchmark score --input {} --trace-id trace-bench-score-cli --decision-id decision-bench-score-cli --policy-id policy-bench-score-cli --output {}",
        score_input_path.display(),
        score_output_path.display()
    );
    assert_eq!(
        repro_lock_json["commands"][0].as_str(),
        Some(expected_score_command.as_str())
    );

    let verify_output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "benchmark",
            "verify",
            "--bundle",
            bundle_dir
                .to_str()
                .expect("bundle path should be valid utf8"),
            "--summary",
            "--output",
            verify_report_path
                .to_str()
                .expect("verify report path should be valid utf8"),
        ])
        .output()
        .expect("benchmark verify command should execute");

    assert!(
        verify_output.status.success(),
        "benchmark verify failed with stderr={}",
        String::from_utf8_lossy(&verify_output.stderr)
    );
    let verify_stdout = String::from_utf8(verify_output.stdout).expect("stdout should be utf8");
    assert!(verify_stdout.contains("claim_type=benchmark"));

    let verify_report: serde_json::Value = serde_json::from_slice(
        &fs::read(&verify_report_path).expect("verify report should be written"),
    )
    .expect("verify report should parse");
    assert_eq!(verify_report["claim_type"].as_str(), Some("benchmark"));
    assert_eq!(verify_report["verdict"].as_str(), Some("verified"));
    assert!(
        verify_report["checks"]
            .as_array()
            .is_some_and(|checks| !checks.is_empty())
    );
    assert!(
        verify_report["events"]
            .as_array()
            .is_some_and(|events| !events.is_empty())
    );
    let check_names = verify_report["checks"]
        .as_array()
        .expect("checks should be an array")
        .iter()
        .filter_map(|check| check["name"].as_str())
        .collect::<Vec<_>>();
    assert!(check_names.contains(&"bundle_env_runtime_contract_matches"));
    assert!(check_names.contains(&"bundle_env_runtime_feature_flag_present"));
    assert!(check_names.contains(&"bundle_command_mode_receipt_runtime_contract_matches"));
    assert!(
        check_names.contains(&"bundle_benchmark_invocation_manifest_artifact_contract_present")
    );

    let _ = fs::remove_file(score_input_path);
    let _ = fs::remove_file(verify_report_path);
    let _ = fs::remove_dir_all(output_root);
}

#[test]
fn frankenctl_benchmark_score_extensionless_output_path_materializes_bundle() {
    let score_input_path = temp_path("frankenctl_benchmark_score_input_extensionless", "json");
    let output_root = temp_dir("frankenctl_benchmark_bundle_extensionless");
    let score_output_path = output_root.join("benchmark_score");
    let bundle_dir = output_root.join("benchmark_score.bundle");
    let bundle_results_path = bundle_dir.join("results.json");

    write_benchmark_score_input(&score_input_path);

    let score_output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "benchmark",
            "score",
            "--input",
            score_input_path
                .to_str()
                .expect("score input path should be valid utf8"),
            "--trace-id",
            "trace-bench-score-extensionless",
            "--decision-id",
            "decision-bench-score-extensionless",
            "--policy-id",
            "policy-bench-score-extensionless",
            "--output",
            score_output_path
                .to_str()
                .expect("score output path should be valid utf8"),
        ])
        .output()
        .expect("benchmark score command should execute");

    assert!(
        score_output.status.success(),
        "benchmark score failed with stderr={}",
        String::from_utf8_lossy(&score_output.stderr)
    );
    let score_json = parse_stdout_json(&score_output);
    assert_eq!(
        score_json["output"].as_str(),
        Some(
            score_output_path
                .to_str()
                .expect("score output path should be valid utf8")
        )
    );
    assert_eq!(
        score_json["bundle"].as_str(),
        Some(
            bundle_dir
                .to_str()
                .expect("bundle dir should be valid utf8")
        )
    );
    assert!(score_output_path.is_file());
    assert!(bundle_results_path.is_file());
    assert!(bundle_dir.join("env.json").is_file());

    let score_output_json: serde_json::Value = serde_json::from_slice(
        &fs::read(&score_output_path).expect("requested score output should be written"),
    )
    .expect("requested score output should parse");
    let bundle_results_json: serde_json::Value = serde_json::from_slice(
        &fs::read(&bundle_results_path).expect("bundle results should be written"),
    )
    .expect("bundle results should parse");
    assert_eq!(score_output_json, bundle_results_json);

    let _ = fs::remove_file(score_input_path);
    let _ = fs::remove_dir_all(output_root);
}

#[test]
fn frankenctl_benchmark_verify_detects_results_digest_tampering() {
    let score_input_path = temp_path("frankenctl_benchmark_score_input_tamper", "json");
    let bundle_dir = temp_dir("frankenctl_benchmark_bundle_tamper");
    let bundle_results_path = bundle_dir.join("results.json");

    write_benchmark_score_input(&score_input_path);

    let score_output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "benchmark",
            "score",
            "--input",
            score_input_path
                .to_str()
                .expect("score input path should be valid utf8"),
            "--trace-id",
            "trace-bench-score-tamper",
            "--decision-id",
            "decision-bench-score-tamper",
            "--policy-id",
            "policy-bench-score-tamper",
            "--output",
            bundle_results_path
                .to_str()
                .expect("bundle results path should be valid utf8"),
        ])
        .output()
        .expect("benchmark score command should execute");

    assert!(
        score_output.status.success(),
        "benchmark score failed with stderr={}",
        String::from_utf8_lossy(&score_output.stderr)
    );

    let mut tampered_results =
        fs::read_to_string(&bundle_results_path).expect("results.json should be readable");
    tampered_results.push('\n');
    fs::write(&bundle_results_path, tampered_results).expect("results.json should rewrite");

    let verify_output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "benchmark",
            "verify",
            "--bundle",
            bundle_dir
                .to_str()
                .expect("bundle path should be valid utf8"),
        ])
        .output()
        .expect("benchmark verify command should execute");

    assert_eq!(verify_output.status.code(), Some(25));
    let verify_report = parse_stdout_json(&verify_output);
    assert_eq!(verify_report["verdict"].as_str(), Some("failed"));
    assert!(
        verify_report["checks"]
            .as_array()
            .is_some_and(|checks| checks.iter().any(|check| {
                check["name"].as_str() == Some("bundle_manifest_results_digest_matches")
                    && check["passed"].as_bool() == Some(false)
            }))
    );

    let _ = fs::remove_file(score_input_path);
    let _ = fs::remove_dir_all(bundle_dir);
}

// ── Replay trace serde roundtrip tests ────────────────────────────────

#[test]
fn frankenctl_replay_trace_serde_roundtrip_preserves_all_source_kinds() {
    let trace_path = temp_path("frankenctl_replay_serde_all", "json");

    let mut trace = NondeterminismTrace::new("session-serde-all-sources");
    for (vts, source) in NondeterminismSource::ALL.iter().enumerate() {
        trace.capture(
            source.clone(),
            vec![(vts as u8)],
            (vts as u64) + 1,
            "serde-test",
        );
    }
    trace.finalise((NondeterminismSource::ALL.len() as u64) + 1);

    let serialized = serde_json::to_vec_pretty(&trace).expect("trace should serialize");
    fs::write(&trace_path, &serialized).expect("trace file should write");

    let read_back = fs::read(&trace_path).expect("trace file should be readable");
    let deserialized: NondeterminismTrace =
        serde_json::from_slice(&read_back).expect("trace should deserialize");

    assert_eq!(
        deserialized.event_count(),
        NondeterminismSource::ALL.len(),
        "deserialized trace should preserve all source kind events"
    );
    assert!(deserialized.is_finalised());

    // Verify the roundtripped trace replays successfully
    let report_path = temp_path("frankenctl_replay_serde_all_report", "json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            trace_path.to_str().unwrap(),
            "--mode",
            "best-effort",
            "--out",
            report_path.to_str().unwrap(),
        ])
        .output()
        .expect("replay should execute");

    assert!(
        output.status.success(),
        "replay of roundtripped trace failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output);
    assert_eq!(
        json["event_count"].as_u64(),
        Some(NondeterminismSource::ALL.len() as u64)
    );

    let _ = fs::remove_file(trace_path);
    let _ = fs::remove_file(report_path);
}

#[test]
fn frankenctl_compile_empty_source_file_fails_with_structured_error() {
    let source_path = temp_path("frankenctl_compile_empty", "js");
    let artifact_path = temp_path("frankenctl_compile_empty_art", "json");
    write_source(&source_path, "");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "compile",
            "--input",
            source_path.to_str().unwrap(),
            "--out",
            artifact_path.to_str().unwrap(),
        ])
        .output()
        .expect("compile empty source should execute");

    assert!(
        !output.status.success(),
        "compile of empty source should fail"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl"),
        "error should include frankenctl prefix: {stderr}"
    );
    assert!(
        stderr.contains("remediation:"),
        "error should include remediation guidance: {stderr}"
    );

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(artifact_path);
}

#[test]
fn frankenctl_compile_deterministic_hashes_across_runs() {
    let source_path = temp_path("frankenctl_compile_determ", "js");
    let artifact_1 = temp_path("frankenctl_compile_determ_1", "json");
    let artifact_2 = temp_path("frankenctl_compile_determ_2", "json");
    write_source(&source_path, "const pi = 3;\n");

    let run_compile = |art: &std::path::Path| -> serde_json::Value {
        let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
            .args([
                "compile",
                "--input",
                source_path.to_str().unwrap(),
                "--out",
                art.to_str().unwrap(),
                "--trace-id",
                "trace-determ",
                "--decision-id",
                "decision-determ",
                "--policy-id",
                "policy-determ",
            ])
            .output()
            .expect("compile should execute");
        assert!(output.status.success());
        parse_stdout_json(&output)
    };

    let json1 = run_compile(&artifact_1);
    let json2 = run_compile(&artifact_2);

    assert_eq!(
        json1["hashes"]["parse_event_ir"], json2["hashes"]["parse_event_ir"],
        "parse_event_ir hash must be deterministic across runs"
    );
    assert_eq!(
        json1["hashes"]["ir0"], json2["hashes"]["ir0"],
        "ir0 hash must be deterministic across runs"
    );

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(artifact_1);
    let _ = fs::remove_file(artifact_2);
}

#[test]
fn frankenctl_replay_empty_trace_completes_immediately() {
    let trace_path = temp_path("frankenctl_replay_empty", "json");

    let mut trace = NondeterminismTrace::new("session-empty");
    trace.finalise(1);

    fs::write(
        &trace_path,
        serde_json::to_vec_pretty(&trace).expect("trace should serialize"),
    )
    .expect("trace file should write");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            trace_path.to_str().unwrap(),
            "--mode",
            "strict",
        ])
        .output()
        .expect("replay empty trace should execute");

    assert!(
        output.status.success(),
        "replay empty trace failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json = parse_stdout_json(&output);
    assert_eq!(json["event_count"].as_u64(), Some(0));
    assert_eq!(json["divergence_count"].as_u64(), Some(0));
    assert_eq!(json["complete"].as_bool(), Some(true));

    let _ = fs::remove_file(trace_path);
}

#[test]
fn frankenctl_replay_unfinished_trace_fails_closed() {
    let trace_path = temp_path("frankenctl_replay_unfinished", "json");

    let mut trace = NondeterminismTrace::new("session-unfinished");
    trace.capture(
        NondeterminismSource::TimerRead,
        vec![1, 2, 3],
        1,
        "integration-test",
    );

    fs::write(
        &trace_path,
        serde_json::to_vec_pretty(&trace).expect("trace should serialize"),
    )
    .expect("trace file should write");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "replay",
            "run",
            "--trace",
            trace_path.to_str().unwrap(),
            "--mode",
            "strict",
        ])
        .output()
        .expect("replay unfinished trace should execute");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("trace is not finalised"), "{stderr}");

    let _ = fs::remove_file(trace_path);
}

#[test]
fn frankenctl_benchmark_verify_missing_bundle_dir_fails() {
    let bundle_dir = temp_path("frankenctl_benchmark_verify_missing_bundle_dir", "bundle");
    let missing_results_path = bundle_dir.join("results.json");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "benchmark",
            "verify",
            "--bundle",
            bundle_dir
                .to_str()
                .expect("bundle dir path should be valid utf8"),
        ])
        .output()
        .expect("benchmark verify with missing bundle should execute");

    assert_eq!(
        output.status.code(),
        Some(2),
        "benchmark verify should fail for missing bundle dir"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl trace_id=frankenctl-"),
        "stderr should include trace id, got: {stderr}"
    );
    assert!(
        stderr.contains("command=benchmark"),
        "stderr should include benchmark command label, got: {stderr}"
    );
    assert!(
        stderr.contains("benchmark verify requires --bundle <dir> containing"),
        "stderr should preserve missing-bundle failure, got: {stderr}"
    );
    assert!(
        stderr.contains(
            missing_results_path
                .to_str()
                .expect("missing results path should be valid utf8")
        ),
        "stderr should name the missing results path, got: {stderr}"
    );
    assert!(
        stderr.contains(
            "remediation: Validate benchmark subcommand args (run|score|verify), then rerun `frankenctl benchmark ...`."
        ),
        "stderr should include runtime remediation, got: {stderr}"
    );
}

#[test]
fn frankenctl_benchmark_verify_missing_bundle_flag_fails_with_parse_remediation() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(["benchmark", "verify", "--summary"])
        .output()
        .expect("benchmark verify parse failure should execute");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl trace_id=frankenctl-"),
        "stderr should include trace id, got: {stderr}"
    );
    assert!(
        stderr.contains("command=parse"),
        "stderr should include parse command label, got: {stderr}"
    );
    assert!(
        stderr.contains("benchmark verify requires --bundle <dir>"),
        "stderr should preserve parse failure, got: {stderr}"
    );
    assert!(
        stderr.contains(
            "remediation: Run `frankenctl --help` for full command usage and required arguments."
        ),
        "stderr should include parse remediation, got: {stderr}"
    );
}

#[test]
fn frankenctl_benchmark_verify_unknown_flag_fails_with_parse_remediation() {
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "benchmark",
            "verify",
            "--bundle",
            "/tmp/frankenctl-benchmark-verify",
            "--bogus",
        ])
        .output()
        .expect("benchmark verify unknown flag should execute");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl trace_id=frankenctl-"),
        "stderr should include trace id, got: {stderr}"
    );
    assert!(
        stderr.contains("command=parse"),
        "stderr should include parse command label, got: {stderr}"
    );
    assert!(
        stderr.contains("unknown benchmark verify flag `--bogus`"),
        "stderr should preserve parse failure, got: {stderr}"
    );
    assert!(
        stderr.contains(
            "remediation: Run `frankenctl --help` for full command usage and required arguments."
        ),
        "stderr should include parse remediation, got: {stderr}"
    );
}

#[test]
fn frankenctl_benchmark_verify_incomplete_bundle_fails_with_runtime_remediation() {
    let bundle_dir = temp_dir("frankenctl_benchmark_verify_incomplete_bundle");
    fs::write(bundle_dir.join("env.json"), "{}\n").expect("env.json should write");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "benchmark",
            "verify",
            "--bundle",
            bundle_dir
                .to_str()
                .expect("bundle dir path should be valid utf8"),
        ])
        .output()
        .expect("benchmark verify incomplete bundle should execute");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("[frankenctl trace_id=frankenctl-"),
        "stderr should include trace id, got: {stderr}"
    );
    assert!(
        stderr.contains("command=benchmark"),
        "stderr should include benchmark command label, got: {stderr}"
    );
    assert!(
        stderr.contains("benchmark verify requires --bundle <dir> containing"),
        "stderr should preserve incomplete-bundle failure, got: {stderr}"
    );
    assert!(
        stderr.contains("results.json"),
        "stderr should identify the missing required bundle artifact, got: {stderr}"
    );
    assert!(
        stderr.contains(
            "remediation: Validate benchmark subcommand args (run|score|verify), then rerun `frankenctl benchmark ...`."
        ),
        "stderr should include runtime remediation, got: {stderr}"
    );

    let _ = fs::remove_dir_all(bundle_dir);
}
