#![forbid(unsafe_code)]

//! `[RC-B3][TEST]` (`bd-rc-2026-11-11-epic-g2vrp.22`):
//! Exhaustive 42-command `frankenctl` truth suite, real-Node parity export
//! negative/positive verification, `storage_adapter` fail-closed content-hash
//! error handling, `zero_placeholder_scan` synthetic-stub mutation test, and
//! `governance-surfaces` ceremony-feature isolation verification.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use frankenengine_engine::agent_sandbox::{
    AGENT_SANDBOX_MANIFEST_SCHEMA_VERSION, AgentSandboxManifest,
};
use frankenengine_engine::attested_execution_cell::{
    SoftwareTrustRoot, TrustLevel, TrustRootBackend,
};
use frankenengine_engine::benchmark_evidence_bundle::{
    BenchmarkRun, EnvironmentSnapshot, EvidenceBundle, ParityTarget, WorkloadCategory,
    WorkloadProvenance,
};
use frankenengine_engine::containment_executor::ContainmentState;
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::mmr_proof::MerkleMountainRange;
use frankenengine_engine::parser_oracle::DEFAULT_FIXTURE_CATALOG_PATH;
use frankenengine_engine::proof_schema::{
    AttestationValidityWindow, OptReceipt, OptimizationClass, ReceiptAttestationBindings,
    proof_schema_version_current,
};
use frankenengine_engine::react_mismatch_catalog::{
    ComparisonTarget, MismatchCatalog, MismatchDomain, MismatchEntry, MismatchSeverity,
    RemediationStatus,
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
use frankenengine_engine::signature_drift_gate::DriftGateConfig;
use frankenengine_engine::signature_preimage::{Signature, SigningKey, sign_preimage};
use frankenengine_engine::storage_adapter::{
    EventContext, InMemoryStorageAdapter, StorageAdapter, StorageError, StoreKind,
    encode_migration_state_hash,
};
use frankenengine_engine::tee_attestation_policy::{
    AttestationFreshnessWindow, AttestationQuote as PolicyAttestationQuote, DecisionImpact,
    MeasurementAlgorithm, MeasurementDigest, PlatformTrustRoot, RevocationFallback,
    RevocationProbeStatus, RevocationSource, RevocationSourceType, TeeAttestationPolicy,
    TeePlatform, TrustRootPinning, TrustRootSource,
};
use frankenengine_engine::zero_placeholder_scan::scan_production_source_placeholders;
use serde::Serialize;

const FRANKENCTL_BIN: &str = env!("CARGO_BIN_EXE_frankenctl");
const BENCHMARK_EXPORT_BIN: &str = env!("CARGO_BIN_EXE_franken-benchmark-evidence-export");
const ZERO_PLACEHOLDER_GATE_BIN: &str = env!("CARGO_BIN_EXE_franken_zero_placeholder_gate");
const SIGNATURE_DRIFT_GATE_BIN: &str = env!("CARGO_BIN_EXE_franken_signature_drift_gate");
const TEST262_RUNNER_BIN: &str = env!("CARGO_BIN_EXE_franken_test262_runner");
const LOCKSTEP_RUNNER_BIN: &str = env!("CARGO_BIN_EXE_franken_lockstep_runner");

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn scratch_dir(label: &str) -> PathBuf {
    let run_stamp_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "frankenctl_truth_g2vrp_22_{label}_{}_{}",
        std::process::id(),
        run_stamp_ns
    ));
    fs::create_dir_all(&dir).expect("scratch directory should be created");
    dir
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

fn attest_policy_quote(
    policy: &mut TeeAttestationPolicy,
    quote: &PolicyAttestationQuote,
) -> Signature {
    let signing_key = SigningKey::from_bytes([0x5a; 32]).expect("policy anchor signing key");
    let anchor = format!(
        "-----BEGIN FRANKENENGINE TRUST ANCHOR-----\n{}\n-----END FRANKENENGINE TRUST ANCHOR-----",
        hex::encode(signing_key.verification_key().as_bytes())
    );
    for root in &mut policy.platform_trust_roots {
        if root.platform == quote.platform && root.root_id == quote.trust_root_id {
            root.trust_anchor_pem = anchor.clone();
        }
    }
    sign_preimage(&signing_key, &quote.signing_preimage()).expect("sign policy quote preimage")
}

fn build_valid_receipt_verifier_input() -> (String, ReceiptVerifierCliInput) {
    let receipt_id = "rcpt-g2vrp-22".to_string();
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

    let measurement_zone = "measurement-zone-g2vrp-22".to_string();
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

    let rollback_id = String::from("rb-01");
    let unsigned_receipt = OptReceipt {
        schema_version: proof_schema_version_current(),
        optimization_id: "opt-g2vrp-22".to_string(),
        optimization_class: OptimizationClass::Superinstruction,
        baseline_ir_hash: ContentHash::compute(b"baseline"),
        candidate_ir_hash: ContentHash::compute(b"candidate"),
        translation_witness_hash: ContentHash::compute(b"translation"),
        invariance_digest: ContentHash::compute(b"invariance"),
        rollback_token_id: rollback_id,
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
    let receipt_leaf_hash = expected_preimage_hash;

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

    let operator_signing_key = SigningKey::from_bytes([9u8; 32]).expect("operator key");
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
    preimage.extend_from_slice(&(checkpoint_stub.operator_key_id.len() as u32).to_be_bytes());
    preimage.extend_from_slice(checkpoint_stub.operator_key_id.as_bytes());
    checkpoint.signature = sign_preimage(&operator_signing_key, &preimage).expect("checkpoint sig");

    let measurement_digest_hex = measurement.composite_hash().to_hex();
    let mut policy =
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
    let policy_quote_signature = attest_policy_quote(&mut policy, &policy_quote);

    let request = UnifiedReceiptVerificationRequest {
        trace_id: "trace-verify-g2vrp-22".to_string(),
        decision_id: "decision-verify-g2vrp-22".to_string(),
        policy_id: "policy-verify-g2vrp-22".to_string(),
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
            policy_quote_signature,
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

fn build_doctor_input() -> RuntimeDiagnosticsCliInput {
    RuntimeDiagnosticsCliInput {
        trace_id: "trace-frankenctl-doctor-g2vrp-22".to_string(),
        decision_id: "decision-frankenctl-doctor-g2vrp-22".to_string(),
        policy_id: "policy-frankenctl-doctor-g2vrp-22".to_string(),
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
        telemetry_drop_counts: Default::default(),
        containment_receipts: Vec::new(),
        replay_artifacts: Vec::new(),
    }
}

fn write_react_mismatch_catalog(path: &Path) {
    let mut catalog = MismatchCatalog::new(SecurityEpoch::from_raw(7));
    catalog
        .add_entry(MismatchEntry {
            entry_id: "react-ssr-open".to_string(),
            domain: MismatchDomain::ServerSideRender,
            severity: MismatchSeverity::Error,
            target: ComparisonTarget::NodeJs,
            summary: "SSR entry mismatch".to_string(),
            expected_behavior: "render should match".to_string(),
            actual_behavior: "render diverged".to_string(),
            reproduction: "cargo test -- react_ssr_case".to_string(),
            remediation: RemediationStatus::InProgress,
            advisory: "Switch to the documented SSR compatibility path.".to_string(),
            react_version_range: ">=18".to_string(),
            evidence_hash: ContentHash::compute(b"react-ssr-open"),
            detected_epoch: SecurityEpoch::from_raw(4),
            verified_epoch: SecurityEpoch::from_raw(7),
            tags: BTreeSet::from(["react".to_string(), "ssr".to_string(), "doctor".to_string()]),
        })
        .expect("catalog entry should be added");
    fs::write(path, serde_json::to_vec_pretty(&catalog).unwrap())
        .expect("catalog fixture should write");
}

#[derive(Debug, Serialize)]
struct CommandTelemetryRow {
    subcommand: String,
    args: Vec<String>,
    exit_code: i32,
    stdout_schema_valid: bool,
    duration_ms: u64,
    fabricated_literal_detected: bool,
}

fn has_fabricated_stub_literal(stdout: &str) -> bool {
    let lower = stdout.to_ascii_lowercase();
    [
        "\"fabricated\":true",
        "\"mock_metric\"",
        "\"placeholder_metric\"",
        "synthetic stub",
        "not yet wired",
        "hardcoded_stub",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn detect_bun_runtime() -> (String, Option<PathBuf>, bool) {
    if Command::new("bun")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
    {
        return ("bun".to_string(), None, true);
    }
    if let Ok(home) = std::env::var("HOME") {
        let bun_dir = PathBuf::from(home).join(".bun/bin");
        let bun_exe = bun_dir.join("bun");
        if bun_exe.is_file()
            && Command::new("bun")
                .env("PATH", &bun_dir)
                .arg("--version")
                .output()
                .is_ok_and(|out| out.status.success())
        {
            return (bun_exe.display().to_string(), Some(bun_dir), true);
        }
    }
    ("node".to_string(), None, false)
}

fn run_frankenctl_recorded_expect_code(
    root: &Path,
    subcommand: &str,
    args: &[&str],
    expected_exit_code: i32,
    extra_path_dir: Option<&Path>,
    expect_json_stdout: bool,
    telemetry: &mut Vec<CommandTelemetryRow>,
) -> Output {
    let arg_strings: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let started = Instant::now();
    let mut cmd = Command::new(FRANKENCTL_BIN);
    cmd.args(args).current_dir(root);
    if let Some(extra_dir) = extra_path_dir {
        let existing = std::env::var_os("PATH").unwrap_or_default();
        let mut paths = vec![extra_dir.to_path_buf()];
        paths.extend(std::env::split_paths(&existing));
        if let Ok(joined) = std::env::join_paths(paths) {
            cmd.env("PATH", joined);
        }
    }
    let output = cmd.output().expect("frankenctl subcommand should execute");
    let duration_ms = started.elapsed().as_millis() as u64;
    let exit_code = output.status.code().unwrap_or(-1);
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        exit_code, expected_exit_code,
        "frankenctl `{subcommand}` exited {exit_code} (expected {expected_exit_code}): stdout={stdout_str} stderr={stderr_str}"
    );
    let stdout_schema_valid = if expect_json_stdout {
        serde_json::from_slice::<serde_json::Value>(&output.stdout).is_ok()
    } else {
        !stdout_str.trim().is_empty()
    };
    assert!(
        stdout_schema_valid,
        "frankenctl `{subcommand}` produced invalid output: stdout={stdout_str}"
    );
    let fabricated_literal_detected = has_fabricated_stub_literal(&stdout_str);
    assert!(
        !fabricated_literal_detected,
        "frankenctl `{subcommand}` emitted a fabricated stub literal: {stdout_str}"
    );
    telemetry.push(CommandTelemetryRow {
        subcommand: subcommand.to_string(),
        args: arg_strings,
        exit_code,
        stdout_schema_valid,
        duration_ms,
        fabricated_literal_detected,
    });
    output
}

fn run_frankenctl_recorded(
    root: &Path,
    subcommand: &str,
    args: &[&str],
    expect_json_stdout: bool,
    telemetry: &mut Vec<CommandTelemetryRow>,
) -> Output {
    run_frankenctl_recorded_expect_code(
        root,
        subcommand,
        args,
        0,
        None,
        expect_json_stdout,
        telemetry,
    )
}

#[test]
fn frankenctl_help_and_readme_full_surface_have_exact_42_command_parity() {
    let root = repo_root();
    let readme = fs::read_to_string(root.join("README.md")).expect("README.md must read");

    // Extract the `### Full Surface` Markdown table from README.md.
    let full_surface_section = readme
        .split("### Full Surface")
        .nth(1)
        .and_then(|rest| rest.split("\n### ").next())
        .expect("README.md must contain `### Full Surface` section");

    let mut readme_commands = Vec::new();
    for line in full_surface_section.lines() {
        let trimmed = line.trim();
        if let Some(after_bar) = trimmed.strip_prefix("| `frankenctl ")
            && let Some(cmd_cell) = after_bar.split('`').next()
        {
            let tokens: Vec<&str> = cmd_cell.split_whitespace().collect();
            let key = match tokens.as_slice() {
                ["version", ..] => "version".to_string(),
                ["help", ..] => "help".to_string(),
                [
                    single @ ("compile" | "run" | "check" | "onboard" | "diff-behavior"
                    | "agent-sandbox" | "explain" | "doctor"),
                    ..,
                ] => (*single).to_string(),
                [group, sub, ..] => format!("{group} {sub}"),
                other => panic!("unexpected README Full Surface row: {other:?}"),
            };
            readme_commands.push(key);
        }
    }

    let expected_41_documented_rows: Vec<&str> = vec![
        "version",
        "help",
        "compile",
        "run",
        "check",
        "onboard",
        "diff-behavior",
        "evidence init",
        "agent-sandbox",
        "explain",
        "claims explain",
        "doctor",
        "verify compile-artifact",
        "verify receipt",
        "benchmark run",
        "benchmark compare",
        "benchmark score",
        "benchmark verify",
        "replay run",
        "replay debug",
        "differential-oracle run",
        "differential-oracle perf",
        "oracle run",
        "oracle report",
        "react compile",
        "react build",
        "react doctor",
        "react contract",
        "gates zero-placeholder",
        "gates signature-drift",
        "gates compounding-red-team",
        "gates erasure-bandwidth",
        "reports parser-oracle",
        "reports lowering-gap",
        "test test262",
        "test lockstep",
        "synth kernel-contract",
        "synth law-mining",
        "orchestrate context-refactor",
        "orchestrate tail-latency",
        "runtime diagnostics",
    ];
    assert_eq!(
        readme_commands, expected_41_documented_rows,
        "README.md `### Full Surface` must match all 41 documented leaf commands (+ nested `help <topic>` = 42)"
    );

    // Top-level `--help` and nested `help <topic>` must cover every top-level group without dead variants.
    let help_out = Command::new(FRANKENCTL_BIN)
        .arg("--help")
        .current_dir(&root)
        .output()
        .expect("frankenctl --help");
    assert!(help_out.status.success());
    let help_text = String::from_utf8_lossy(&help_out.stdout);
    for top_group in [
        "version",
        "help",
        "compile",
        "check",
        "onboard",
        "diff-behavior",
        "run",
        "evidence init",
        "agent-sandbox",
        "explain",
        "claims explain",
        "doctor",
        "verify compile-artifact",
        "verify receipt",
        "benchmark run",
        "benchmark compare",
        "benchmark score",
        "benchmark verify",
        "replay run",
        "replay debug",
        "differential-oracle run",
        "differential-oracle perf",
        "oracle run",
        "oracle report",
        "react compile|build|doctor|contract",
        "gates <gate-type>",
        "reports <report-type>",
        "test <test-type>",
        "synth <synth-type>",
        "orchestrate <orchestrate-type>",
        "runtime <runtime-type>",
    ] {
        assert!(
            help_text.contains(top_group),
            "frankenctl --help missing documented surface `{top_group}`"
        );
    }

    // Verify nested `frankenctl help <topic>` renders subcommands for every operator group.
    for (topic, required_leafs) in [
        (
            "gates",
            &[
                "zero-placeholder",
                "signature-drift",
                "compounding-red-team",
                "erasure-bandwidth",
            ][..],
        ),
        ("reports", &["parser-oracle", "lowering-gap"][..]),
        ("test", &["test262", "lockstep"][..]),
        ("synth", &["kernel-contract", "law-mining"][..]),
        ("orchestrate", &["context-refactor", "tail-latency"][..]),
        ("runtime", &["diagnostics"][..]),
    ] {
        let topic_help = Command::new(FRANKENCTL_BIN)
            .args(["help", topic])
            .current_dir(&root)
            .output()
            .expect("frankenctl help <topic>");
        assert!(
            topic_help.status.success(),
            "frankenctl help {topic} failed"
        );
        let topic_stdout = String::from_utf8_lossy(&topic_help.stdout);
        for leaf in required_leafs {
            assert!(
                topic_stdout.contains(leaf),
                "frankenctl help {topic} missing leaf `{leaf}`: {topic_stdout}"
            );
        }
    }
}

#[test]
fn frankenctl_executes_all_42_leaf_commands_with_zero_fabricated_stubs() {
    // Ensure sibling operator binaries are built into the Cargo target directory.
    for sibling in [
        ZERO_PLACEHOLDER_GATE_BIN,
        SIGNATURE_DRIFT_GATE_BIN,
        TEST262_RUNNER_BIN,
        LOCKSTEP_RUNNER_BIN,
    ] {
        assert!(
            Path::new(sibling).is_file(),
            "expected sibling operator binary to exist: {sibling}"
        );
    }

    let root = repo_root();
    let work = scratch_dir("all42");
    let mut telemetry = Vec::with_capacity(42);

    // Prepare real JS/TSX/package/config fixtures in scratch directory.
    let js_v1 = work.join("demo_v1.js");
    let js_v2 = work.join("demo_v2.js");
    fs::write(&js_v1, "const answer = 40 + 2;\nconsole.log(answer);\n").expect("write js_v1");
    fs::write(&js_v2, "const answer = 21 * 2;\nconsole.log(answer);\n").expect("write js_v2");

    let pkg_dir = work.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create pkg_dir");
    fs::write(
        pkg_dir.join("package.json"),
        r#"{"name":"demo-pkg","version":"1.0.0","main":"index.js"}"#,
    )
    .expect("write package.json");
    fs::write(
        pkg_dir.join("index.js"),
        "export const value = 7;\nexport function bump(x) { return x + value; }\n",
    )
    .expect("write pkg index.js");

    // 1. version
    let ver_out = run_frankenctl_recorded(&root, "version", &["version"], false, &mut telemetry);
    assert!(
        String::from_utf8_lossy(&ver_out.stdout).starts_with("frankenctl "),
        "frankenctl version must print binary name and version"
    );
    // 2. help
    run_frankenctl_recorded(&root, "help", &["help"], false, &mut telemetry);
    // 3. help <topic>
    run_frankenctl_recorded(
        &root,
        "help gates",
        &["help", "gates"],
        false,
        &mut telemetry,
    );

    // 4. compile
    let compile_artifact = work.join("demo.compile.json");
    run_frankenctl_recorded(
        &root,
        "compile",
        &[
            "compile",
            "--input",
            js_v1.to_str().unwrap(),
            "--out",
            compile_artifact.to_str().unwrap(),
            "--goal",
            "script",
        ],
        true,
        &mut telemetry,
    );
    assert!(compile_artifact.is_file());

    // 5. check
    let check_out_dir = work.join("check_bundle");
    run_frankenctl_recorded(
        &root,
        "check",
        &[
            "check",
            js_v1.to_str().unwrap(),
            "--goal",
            "script",
            "--format",
            "json",
            "--out",
            check_out_dir.to_str().unwrap(),
        ],
        true,
        &mut telemetry,
    );

    // 6. onboard
    let onboard_out_dir = work.join("onboard_bundle");
    run_frankenctl_recorded(
        &root,
        "onboard",
        &[
            "onboard",
            pkg_dir.to_str().unwrap(),
            "--goal",
            "module",
            "--format",
            "json",
            "--out",
            onboard_out_dir.to_str().unwrap(),
        ],
        true,
        &mut telemetry,
    );

    // 7. diff-behavior
    let diff_out_dir = work.join("diff_bundle");
    run_frankenctl_recorded(
        &root,
        "diff-behavior",
        &[
            "diff-behavior",
            js_v1.to_str().unwrap(),
            js_v2.to_str().unwrap(),
            "--format",
            "json",
            "--out",
            diff_out_dir.to_str().unwrap(),
        ],
        true,
        &mut telemetry,
    );

    // 8. evidence init
    let key_seed_path = work.join("authority.seed");
    let trust_snapshot_path = work.join("trust_snapshot.json");
    run_frankenctl_recorded(
        &root,
        "evidence init",
        &[
            "evidence",
            "init",
            "--producer-id",
            "g2vrp-22-producer",
            "--key-out",
            key_seed_path.to_str().unwrap(),
            "--trust-out",
            trust_snapshot_path.to_str().unwrap(),
            "--epoch",
            "7",
        ],
        true,
        &mut telemetry,
    );
    assert!(key_seed_path.is_file() && trust_snapshot_path.is_file());

    // 9. run (also emits report, explain bundle, and trace for downstream commands)
    let run_report_path = work.join("demo.run.json");
    let explain_bundle_path = work.join("demo.explain.json");
    let trace_path = work.join("demo.trace.json");
    run_frankenctl_recorded(
        &root,
        "run",
        &[
            "run",
            "--input",
            js_v1.to_str().unwrap(),
            "--extension-id",
            "ext-g2vrp-22",
            "--out",
            run_report_path.to_str().unwrap(),
            "--explain-out",
            explain_bundle_path.to_str().unwrap(),
            "--emit-trace",
            trace_path.to_str().unwrap(),
        ],
        true,
        &mut telemetry,
    );
    assert!(
        run_report_path.is_file() && explain_bundle_path.is_file() && trace_path.is_file(),
        "run must emit report, explain bundle, and trace"
    );

    // 10. agent-sandbox
    let sandbox_manifest_path = work.join("sandbox_manifest.json");
    let sandbox_manifest = AgentSandboxManifest {
        schema_version: AGENT_SANDBOX_MANIFEST_SCHEMA_VERSION.to_string(),
        agent_id: "agent-g2vrp-22".to_string(),
        tool_grants: Vec::new(),
        denied_capability_tags: Vec::new(),
        trust_level: Some("provisional".to_string()),
        host_io_root: None,
        host_io_max_bytes: None,
        acknowledge_unfiltered_network: false,
        purpose: None,
        metadata: BTreeMap::new(),
    };
    fs::write(
        &sandbox_manifest_path,
        serde_json::to_vec_pretty(&sandbox_manifest).unwrap(),
    )
    .expect("write sandbox manifest");
    let sandbox_report_path = work.join("sandbox.run.json");
    run_frankenctl_recorded(
        &root,
        "agent-sandbox",
        &[
            "agent-sandbox",
            "--manifest",
            sandbox_manifest_path.to_str().unwrap(),
            "--input",
            js_v1.to_str().unwrap(),
            "--out",
            sandbox_report_path.to_str().unwrap(),
        ],
        true,
        &mut telemetry,
    );

    // 11. explain
    run_frankenctl_recorded(
        &root,
        "explain",
        &[
            "explain",
            explain_bundle_path.to_str().unwrap(),
            "--format",
            "json",
        ],
        true,
        &mut telemetry,
    );
    let explain_derived_dir = work.join("explain_derived");
    let explain_emit_out = Command::new(FRANKENCTL_BIN)
        .args([
            "explain",
            explain_bundle_path.to_str().unwrap(),
            "--format",
            "json",
            "--emit-bundle",
            explain_derived_dir.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("explain --emit-bundle");
    assert!(explain_emit_out.status.success());
    assert!(explain_derived_dir.join("explain.md").is_file());

    // 12. claims explain
    run_frankenctl_recorded(
        &root,
        "claims explain",
        &["claims", "explain", "FE-CLAIM-006", "--format", "json"],
        true,
        &mut telemetry,
    );

    // 13. doctor
    let doctor_input_path = work.join("runtime_diagnostics_input.json");
    fs::write(
        &doctor_input_path,
        serde_json::to_vec_pretty(&build_doctor_input()).unwrap(),
    )
    .expect("write doctor input");
    let doctor_out_dir = work.join("doctor_out");
    run_frankenctl_recorded(
        &root,
        "doctor",
        &[
            "doctor",
            "--input",
            doctor_input_path.to_str().unwrap(),
            "--out-dir",
            doctor_out_dir.to_str().unwrap(),
        ],
        true,
        &mut telemetry,
    );

    // 14. verify compile-artifact
    run_frankenctl_recorded(
        &root,
        "verify compile-artifact",
        &[
            "verify",
            "compile-artifact",
            "--input",
            compile_artifact.to_str().unwrap(),
        ],
        true,
        &mut telemetry,
    );

    // 15. verify receipt
    let (receipt_id, verifier_input) = build_valid_receipt_verifier_input();
    let verifier_input_path = work.join("receipt_verifier_input.json");
    fs::write(
        &verifier_input_path,
        serde_json::to_vec_pretty(&verifier_input).unwrap(),
    )
    .expect("write receipt verifier input");
    run_frankenctl_recorded(
        &root,
        "verify receipt",
        &[
            "verify",
            "receipt",
            "--input",
            verifier_input_path.to_str().unwrap(),
            "--receipt-id",
            &receipt_id,
        ],
        true,
        &mut telemetry,
    );

    // 16. benchmark run (explicitly asserts js_runtime_execution_included == false)
    let bench_run_dir = work.join("bench_run");
    let bench_run_out = run_frankenctl_recorded(
        &root,
        "benchmark run",
        &[
            "benchmark",
            "run",
            "--profile",
            "small",
            "--family",
            "boot-storm",
            "--seed",
            "7",
            "--run-id",
            "bench-g2vrp-22",
            "--run-date",
            "2026-11-12",
            "--out-dir",
            bench_run_dir.to_str().unwrap(),
        ],
        true,
        &mut telemetry,
    );
    let bench_run_json: serde_json::Value =
        serde_json::from_slice(&bench_run_out.stdout).expect("benchmark run json");
    assert_eq!(
        bench_run_json["js_runtime_execution_included"].as_bool(),
        Some(false)
    );

    // 17. benchmark compare (1 real micro case across frankenctl, node, and bun when present)
    let (bun_program, bun_extra_path, bun_installed) = detect_bun_runtime();
    let compare_dir = work.join("compare_suite");
    fs::create_dir_all(&compare_dir).expect("create compare_dir");
    fs::write(compare_dir.join("case.js"), "console.log(6 * 7);\n").expect("write compare case");
    let compare_manifest_path = compare_dir.join("manifest.json");
    let compare_manifest = serde_json::json!({
        "schema_version": "franken-engine.benchmark-comparison-manifest.v1",
        "runtime_pins": {
            "franken_engine": "franken-engine-local",
            "node_lts": "node-local",
            "bun_stable": "bun-local"
        },
        "runtime_commands": {
            "frankenctl": FRANKENCTL_BIN,
            "node": "node",
            "bun": bun_program
        },
        "fairness_policy": {
            "warmup_runs": 1,
            "sample_count": 3,
            "case_timeout_ms": 15000
        },
        "cases": [
            {
                "benchmark_id": "tiny-six-times-seven",
                "category": "micro",
                "program_path": "case.js",
                "args": []
            }
        ]
    });
    fs::write(
        &compare_manifest_path,
        serde_json::to_vec_pretty(&compare_manifest).unwrap(),
    )
    .expect("write compare manifest");
    let compare_out_dir = work.join("bench_compare_out");
    run_frankenctl_recorded(
        &root,
        "benchmark compare",
        &[
            "benchmark",
            "compare",
            "--manifest",
            compare_manifest_path.to_str().unwrap(),
            "--run-id",
            "cmp-g2vrp-22",
            "--run-date",
            "2026-11-12",
            "--out-dir",
            compare_out_dir.to_str().unwrap(),
        ],
        true,
        &mut telemetry,
    );

    // 18. benchmark score
    let score_input_path = work.join("publication_gate_input.json");
    let score_input = serde_json::json!({
        "node_cases": [{
            "workload_id": "boot-storm/s",
            "throughput_franken_tps": 3000.0,
            "throughput_baseline_tps": 900.0,
            "weight": null,
            "behavior_equivalent": true,
            "latency_envelope_ok": true,
            "error_envelope_ok": true
        }],
        "bun_cases": [{
            "workload_id": "boot-storm/s",
            "throughput_franken_tps": 3000.0,
            "throughput_baseline_tps": 950.0,
            "weight": null,
            "behavior_equivalent": true,
            "latency_envelope_ok": true,
            "error_envelope_ok": true
        }],
        "native_coverage_progression": [{
            "recorded_at_utc": "2026-11-12T00:00:00Z",
            "native_slots": 42,
            "total_slots": 48
        }],
        "replacement_lineage_ids": ["lineage-g2vrp-22"]
    });
    fs::write(
        &score_input_path,
        serde_json::to_vec_pretty(&score_input).unwrap(),
    )
    .expect("write score input");
    let score_out_path = work.join("benchmark_score.json");
    let score_bundle_dir = work.join("benchmark_score.bundle");
    run_frankenctl_recorded(
        &root,
        "benchmark score",
        &[
            "benchmark",
            "score",
            "--input",
            score_input_path.to_str().unwrap(),
            "--output",
            score_out_path.to_str().unwrap(),
        ],
        true,
        &mut telemetry,
    );

    // 19. benchmark verify
    run_frankenctl_recorded(
        &root,
        "benchmark verify",
        &[
            "benchmark",
            "verify",
            "--bundle",
            score_bundle_dir.to_str().unwrap(),
        ],
        true,
        &mut telemetry,
    );

    // 20. replay run
    run_frankenctl_recorded(
        &root,
        "replay run",
        &[
            "replay",
            "run",
            "--trace",
            run_report_path.to_str().unwrap(),
            "--mode",
            "strict",
        ],
        true,
        &mut telemetry,
    );

    // 21. replay debug
    let debug_script_path = work.join("replay_debug_cmds.jsonl");
    fs::write(&debug_script_path, "{\"cmd\":\"state\"}\n").expect("write replay debug script");
    let debug_transcript_path = work.join("replay_debug.jsonl");
    run_frankenctl_recorded(
        &root,
        "replay debug",
        &[
            "replay",
            "debug",
            "--trace",
            trace_path.to_str().unwrap(),
            "--script",
            debug_script_path.to_str().unwrap(),
            "--out",
            debug_transcript_path.to_str().unwrap(),
        ],
        true,
        &mut telemetry,
    );

    // 22. differential-oracle run (exits 0 when both Node and Bun are installed;
    // exits 4 = ORACLE_EXIT_INSUFFICIENT when Bun is absent on a minimal runner,
    // proving it never fabricates cross-runtime consensus on missing runtimes).
    let diff_oracle_report = work.join("diff_oracle_run.json");
    let expected_diff_oracle_exit = if bun_installed { 0 } else { 4 };
    run_frankenctl_recorded_expect_code(
        &root,
        "differential-oracle run",
        &[
            "differential-oracle",
            "run",
            "--input",
            js_v1.to_str().unwrap(),
            "--out",
            diff_oracle_report.to_str().unwrap(),
        ],
        expected_diff_oracle_exit,
        bun_extra_path.as_deref(),
        true,
        &mut telemetry,
    );

    // 23. differential-oracle perf
    let diff_perf_report = work.join("diff_oracle_perf.json");
    run_frankenctl_recorded_expect_code(
        &root,
        "differential-oracle perf",
        &[
            "differential-oracle",
            "perf",
            "--manifest",
            compare_manifest_path.to_str().unwrap(),
            "--bun-bin",
            &bun_program,
            "--warmup",
            "1",
            "--samples",
            "1",
            "--out",
            diff_perf_report.to_str().unwrap(),
        ],
        0,
        bun_extra_path.as_deref(),
        true,
        &mut telemetry,
    );

    // 24. oracle run
    let oracle_bundle_dir = work.join("oracle_bundle");
    run_frankenctl_recorded(
        &root,
        "oracle run",
        &[
            "oracle",
            "run",
            js_v1.to_str().unwrap(),
            "--engines",
            "franken,core",
            "--bundle",
            oracle_bundle_dir.to_str().unwrap(),
            "--json",
        ],
        true,
        &mut telemetry,
    );

    // 25. oracle report
    run_frankenctl_recorded(
        &root,
        "oracle report",
        &[
            "oracle",
            "report",
            oracle_bundle_dir.to_str().unwrap(),
            "--json",
        ],
        true,
        &mut telemetry,
    );

    // 26. react compile
    let react_entry = work.join("App.jsx");
    fs::write(
        &react_entry,
        "export function App() { return <section>hello</section>; }\n",
    )
    .expect("write App.jsx");
    let react_compile_out = work.join("react_compile.json");
    run_frankenctl_recorded(
        &root,
        "react compile",
        &[
            "react",
            "compile",
            "--input",
            react_entry.to_str().unwrap(),
            "--source-form",
            "jsx",
            "--runtime",
            "classic",
            "--out",
            react_compile_out.to_str().unwrap(),
        ],
        true,
        &mut telemetry,
    );

    // 27. react build
    let react_build_dir = work.join("react_client_dist");
    let react_build_report = work.join("react_build.json");
    run_frankenctl_recorded(
        &root,
        "react build",
        &[
            "react",
            "build",
            "--entry",
            react_entry.to_str().unwrap(),
            "--target",
            "client",
            "--runtime",
            "classic",
            "--out-dir",
            react_build_dir.to_str().unwrap(),
            "--out",
            react_build_report.to_str().unwrap(),
        ],
        true,
        &mut telemetry,
    );

    // 28. react doctor
    let react_catalog_path = work.join("react_catalog.json");
    write_react_mismatch_catalog(&react_catalog_path);
    run_frankenctl_recorded(
        &root,
        "react doctor",
        &[
            "react",
            "doctor",
            "--catalog",
            react_catalog_path.to_str().unwrap(),
        ],
        true,
        &mut telemetry,
    );

    // 29. react contract
    run_frankenctl_recorded(
        &root,
        "react contract",
        &["react", "contract"],
        true,
        &mut telemetry,
    );

    // 30. gates zero-placeholder
    let zp_gate_dir = work.join("gate_zero_placeholder");
    run_frankenctl_recorded(
        &root,
        "gates zero-placeholder",
        &[
            "gates",
            "zero-placeholder",
            "--out-dir",
            zp_gate_dir.to_str().unwrap(),
        ],
        false,
        &mut telemetry,
    );
    assert!(zp_gate_dir.join("placeholder_gate_report.json").is_file());

    // 31. gates signature-drift
    let sig_drift_dir = work.join("gate_signature_drift");
    let sig_drift_cfg_path = work.join("signature_drift_cfg.json");
    fs::write(
        &sig_drift_cfg_path,
        serde_json::to_vec_pretty(&DriftGateConfig::default()).unwrap(),
    )
    .expect("write signature drift config");
    run_frankenctl_recorded(
        &root,
        "gates signature-drift",
        &[
            "gates",
            "signature-drift",
            "--out-dir",
            sig_drift_dir.to_str().unwrap(),
            "--config",
            sig_drift_cfg_path.to_str().unwrap(),
        ],
        false,
        &mut telemetry,
    );
    assert!(sig_drift_dir.join("run_manifest.json").is_file());

    // 32. gates compounding-red-team
    let red_team_dir = work.join("gate_compounding_red_team");
    run_frankenctl_recorded(
        &root,
        "gates compounding-red-team",
        &[
            "gates",
            "compounding-red-team",
            "--out-dir",
            red_team_dir.to_str().unwrap(),
        ],
        false,
        &mut telemetry,
    );

    // 33. gates erasure-bandwidth
    let bandwidth_dir = work.join("gate_erasure_bandwidth");
    run_frankenctl_recorded(
        &root,
        "gates erasure-bandwidth",
        &[
            "gates",
            "erasure-bandwidth",
            "--out-dir",
            bandwidth_dir.to_str().unwrap(),
        ],
        false,
        &mut telemetry,
    );
    assert!(
        bandwidth_dir
            .join("bandwidth_efficiency_report.json")
            .is_file()
    );

    // 34. reports parser-oracle
    let fixture_catalog = root.join(DEFAULT_FIXTURE_CATALOG_PATH);
    run_frankenctl_recorded(
        &root,
        "reports parser-oracle",
        &[
            "reports",
            "parser-oracle",
            "--partition",
            "smoke",
            "--gate-mode",
            "report_only",
            "--fixture-catalog",
            fixture_catalog.to_str().unwrap(),
        ],
        true,
        &mut telemetry,
    );

    // 35. reports lowering-gap
    let lowering_gap_dir = work.join("reports_lowering_gap");
    run_frankenctl_recorded(
        &root,
        "reports lowering-gap",
        &[
            "reports",
            "lowering-gap",
            "--out",
            lowering_gap_dir.to_str().unwrap(),
        ],
        false,
        &mut telemetry,
    );
    assert!(lowering_gap_dir.join("run_manifest.json").is_file());

    // 36. test test262
    let test262_out_dir = work.join("test262_out");
    run_frankenctl_recorded(
        &root,
        "test test262",
        &[
            "test",
            "test262",
            "--out-dir",
            test262_out_dir.to_str().unwrap(),
        ],
        false,
        &mut telemetry,
    );

    // 37. test lockstep
    let lockstep_out = work.join("lockstep_report.json");
    run_frankenctl_recorded(
        &root,
        "test lockstep",
        &["test", "lockstep", "--out", lockstep_out.to_str().unwrap()],
        false,
        &mut telemetry,
    );
    assert!(lockstep_out.is_file());

    // 38. synth kernel-contract
    let synth_kernel_dir = work.join("synth_kernel");
    run_frankenctl_recorded(
        &root,
        "synth kernel-contract",
        &[
            "synth",
            "kernel-contract",
            "--out-dir",
            synth_kernel_dir.to_str().unwrap(),
        ],
        false,
        &mut telemetry,
    );
    assert!(synth_kernel_dir.join("kernel_contract.json").is_file());

    // 39. synth law-mining
    let law_mining_out = work.join("law_mining.json");
    run_frankenctl_recorded(
        &root,
        "synth law-mining",
        &[
            "synth",
            "law-mining",
            "--out",
            law_mining_out.to_str().unwrap(),
        ],
        false,
        &mut telemetry,
    );
    assert!(law_mining_out.is_file());

    // 40. orchestrate context-refactor
    let ctx_refactor_out = work.join("context_refactor.json");
    run_frankenctl_recorded(
        &root,
        "orchestrate context-refactor",
        &[
            "orchestrate",
            "context-refactor",
            "--out",
            ctx_refactor_out.to_str().unwrap(),
        ],
        false,
        &mut telemetry,
    );
    assert!(ctx_refactor_out.is_file());

    // 41. orchestrate tail-latency
    let tail_latency_dir = work.join("tail_latency");
    run_frankenctl_recorded(
        &root,
        "orchestrate tail-latency",
        &[
            "orchestrate",
            "tail-latency",
            "--out-dir",
            tail_latency_dir.to_str().unwrap(),
        ],
        false,
        &mut telemetry,
    );

    // 42. runtime diagnostics
    let runtime_diag_dir = work.join("runtime_diagnostics");
    run_frankenctl_recorded(
        &root,
        "runtime diagnostics",
        &[
            "runtime",
            "diagnostics",
            "--input",
            doctor_input_path.to_str().unwrap(),
            "--out-dir",
            runtime_diag_dir.to_str().unwrap(),
        ],
        false,
        &mut telemetry,
    );
    assert!(runtime_diag_dir.join("preflight_report.json").is_file());

    assert_eq!(
        telemetry.len(),
        42,
        "must execute and verify all 42 frankenctl leaf commands"
    );

    // Write structured JSONL telemetry log and re-verify every line.
    let telemetry_jsonl_path = work.join("telemetry_42_commands.jsonl");
    let mut jsonl_buf = String::new();
    for row in &telemetry {
        jsonl_buf.push_str(&serde_json::to_string(row).expect("serialize telemetry row"));
        jsonl_buf.push('\n');
    }
    fs::write(&telemetry_jsonl_path, &jsonl_buf).expect("write telemetry jsonl");
    assert_eq!(jsonl_buf.lines().count(), 42);
}

#[test]
fn gates_signature_drift_forwards_config_and_resolves_sibling_binary_without_path() {
    let root = repo_root();
    let work = scratch_dir("sig_drift_pathless");
    let valid_cfg_path = work.join("valid_drift_config.json");
    let invalid_cfg_path = work.join("invalid_drift_config.json");
    let out_dir = work.join("out_ok");

    let mut cfg = DriftGateConfig::default();
    cfg.min_observations = 4;
    fs::write(&valid_cfg_path, serde_json::to_vec_pretty(&cfg).unwrap()).expect("write valid cfg");
    fs::write(&invalid_cfg_path, b"{\"max_l1_drift_millionths\": \"bad\"}")
        .expect("write invalid cfg");

    // 1. Sibling binary resolution works even when PATH is completely empty!
    let ok_out = Command::new(FRANKENCTL_BIN)
        .env("PATH", "")
        .args([
            "gates",
            "signature-drift",
            "--out-dir",
            out_dir.to_str().unwrap(),
            "--config",
            valid_cfg_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("run signature-drift with empty PATH");
    assert!(
        ok_out.status.success(),
        "sibling binary resolution must succeed with PATH='': stderr={}",
        String::from_utf8_lossy(&ok_out.stderr)
    );
    assert!(out_dir.join("run_manifest.json").is_file());

    // 2. Malformed `--config` fails closed with actionable DriftGateConfig diagnostic.
    let bad_cfg_out = Command::new(FRANKENCTL_BIN)
        .env("PATH", "")
        .args([
            "gates",
            "signature-drift",
            "--out-dir",
            work.join("out_bad_cfg").to_str().unwrap(),
            "--config",
            invalid_cfg_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("run signature-drift with invalid config");
    assert!(!bad_cfg_out.status.success());
    let bad_stderr = String::from_utf8_lossy(&bad_cfg_out.stderr);
    assert!(
        bad_stderr.contains("invalid signature-drift --config"),
        "expected invalid config error, got: {bad_stderr}"
    );

    // 3. Isolated copy of frankenctl without siblings and with PATH="" emits actionable build guidance.
    let isolated_dir = work.join("isolated_bin");
    fs::create_dir_all(&isolated_dir).expect("create isolated_dir");
    let isolated_frankenctl = isolated_dir.join("frankenctl");
    fs::copy(FRANKENCTL_BIN, &isolated_frankenctl).expect("copy frankenctl to isolated dir");
    let missing_sibling_out = Command::new(&isolated_frankenctl)
        .env("PATH", "")
        .args([
            "gates",
            "signature-drift",
            "--out-dir",
            work.join("out_missing_sibling").to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("run isolated frankenctl");
    assert!(!missing_sibling_out.status.success());
    let missing_stderr = String::from_utf8_lossy(&missing_sibling_out.stderr);
    assert!(
        missing_stderr.contains("franken_signature_drift_gate")
            && missing_stderr.contains("cargo build --release -p frankenengine-engine --bin"),
        "expected actionable sibling build instruction, got: {missing_stderr}"
    );
}

#[test]
fn benchmark_evidence_export_rejects_missing_or_fake_transcripts_and_verifies_live_node_parity() {
    let root = repo_root();
    let work = scratch_dir("bench_evidence_export");

    // Build a valid base EvidenceBundle with 1 workload provenance and 5 runs.
    let workload_id = "fib-parity-g2vrp-22";
    let js_path = work.join("fib_parity.js");
    let js_source = "function fib(n){let a=0,b=1;for(let i=0;i<n;i++){const t=a+b;a=b;b=t;}return a;}\nconsole.log(fib(12));\n";
    fs::write(&js_path, js_source).expect("write fib_parity.js");

    let mut bundle =
        EvidenceBundle::new("bundle-g2vrp-22".to_string(), SecurityEpoch::from_raw(11));
    bundle
        .add_provenance(WorkloadProvenance {
            workload_id: workload_id.to_string(),
            name: "Fibonacci(12) parity probe".to_string(),
            category: WorkloadCategory::Micro,
            source: js_path.display().to_string(),
            pinned_version: "head".to_string(),
            content_hash: ContentHash::compute(js_source.as_bytes()),
            provenance_epoch: SecurityEpoch::from_raw(11),
            tags: BTreeSet::from(["micro".to_string(), "parity".to_string()]),
        })
        .expect("add provenance");
    let env_snap = EnvironmentSnapshot::new(
        "linux".to_string(),
        "x86_64".to_string(),
        8,
        16 * 1024 * 1024 * 1024,
        "node".to_string(),
        "franken-0.3.0".to_string(),
        BTreeMap::new(),
    );
    for iter in 0..5u32 {
        bundle
            .add_run(BenchmarkRun {
                run_id: format!("run-{iter}"),
                workload_id: workload_id.to_string(),
                duration_us: 1_000 + u64::from(iter) * 10,
                peak_memory_bytes: 24 * 1024 * 1024,
                gc_pause_us: 0,
                is_warmup: false,
                iteration: iter,
                environment: env_snap.clone(),
                run_epoch: SecurityEpoch::from_raw(11),
            })
            .expect("add benchmark run");
    }
    let bundle_input_path = work.join("input_bundle.json");
    fs::write(
        &bundle_input_path,
        serde_json::to_vec_pretty(&bundle).unwrap(),
    )
    .expect("write input bundle");

    // Execute workload live on BOTH frankenctl and real Node.js!
    let franken_out = Command::new(FRANKENCTL_BIN)
        .args([
            "run",
            "--input",
            js_path.to_str().unwrap(),
            "--extension-id",
            "ext-fib-parity",
        ])
        .current_dir(&root)
        .output()
        .expect("frankenctl run fib");
    assert!(franken_out.status.success());
    let franken_json: serde_json::Value =
        serde_json::from_slice(&franken_out.stdout).expect("frankenctl run json");
    let franken_transcript = franken_json["console_output"]
        .as_array()
        .expect("console_output array")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .collect::<Vec<_>>()
        .join("\n");

    let node_out = Command::new("node")
        .env_remove("FORCE_COLOR")
        .env_remove("CLICOLOR_FORCE")
        .env("NO_COLOR", "1")
        .arg(&js_path)
        .current_dir(&root)
        .output()
        .expect("node fib");
    assert!(node_out.status.success());
    let node_transcript = String::from_utf8_lossy(&node_out.stdout)
        .trim_end_matches('\n')
        .to_string();
    assert_eq!(franken_transcript, "144");
    assert_eq!(node_transcript, "144");

    // Case A (NEGATIVE): Timing-only gate manifest missing Node.js transcript MUST exit != 0.
    let missing_transcript_gate = work.join("gate_missing_transcript.json");
    fs::write(
        &missing_transcript_gate,
        serde_json::to_vec_pretty(&serde_json::json!({
            "engine": "nodejs",
            "results": [{
                "test_name": workload_id,
                "value": 1.15
            }]
        }))
        .unwrap(),
    )
    .expect("write missing transcript gate");
    let missing_res = Command::new(BENCHMARK_EXPORT_BIN)
        .args([
            "--input",
            bundle_input_path.to_str().unwrap(),
            "--output",
            work.join("out_missing.json").to_str().unwrap(),
            "--gate-integration",
            missing_transcript_gate.to_str().unwrap(),
        ])
        .output()
        .expect("run export with missing transcript");
    assert!(
        !missing_res.status.success(),
        "timing-only gate manifest without Node transcript must fail closed"
    );
    assert!(
        String::from_utf8_lossy(&missing_res.stderr).contains("refusing to fabricate parity"),
        "stderr={}",
        String::from_utf8_lossy(&missing_res.stderr)
    );

    // Case B (NEGATIVE): Contradictory fabricated verdict (output_equivalent=true + behavioral_differences=2) MUST exit != 0.
    let contradictory_gate = work.join("gate_contradictory.json");
    fs::write(
        &contradictory_gate,
        serde_json::to_vec_pretty(&serde_json::json!({
            "engine": "nodejs",
            "results": [{
                "test_name": workload_id,
                "value": 1.15,
                "output_equivalent": true,
                "behavioral_differences": 2,
                "evidence_hash": "11".repeat(32)
            }]
        }))
        .unwrap(),
    )
    .expect("write contradictory gate");
    let contradictory_res = Command::new(BENCHMARK_EXPORT_BIN)
        .args([
            "--input",
            bundle_input_path.to_str().unwrap(),
            "--output",
            work.join("out_contradictory.json").to_str().unwrap(),
            "--gate-integration",
            contradictory_gate.to_str().unwrap(),
        ])
        .output()
        .expect("run export with contradictory gate");
    assert!(!contradictory_res.status.success());

    // Case C (NEGATIVE): Mismatched Node.js transcript produces output_equivalent=false and fails bundle publication verdict.
    let mismatch_js_path = work.join("node_mismatch.js");
    fs::write(&mismatch_js_path, "console.log(999);\n").expect("write mismatch js");
    let mismatch_node_out = Command::new("node")
        .env_remove("FORCE_COLOR")
        .env_remove("CLICOLOR_FORCE")
        .env("NO_COLOR", "1")
        .arg(&mismatch_js_path)
        .output()
        .expect("node mismatch");
    let mismatch_node_transcript = String::from_utf8_lossy(&mismatch_node_out.stdout)
        .trim_end_matches('\n')
        .to_string();
    let mismatch_gate = work.join("gate_mismatch.json");
    fs::write(
        &mismatch_gate,
        serde_json::to_vec_pretty(&serde_json::json!({
            "engine": "nodejs",
            "results": [{
                "test_name": workload_id,
                "value": 1.15,
                "franken_output": franken_transcript,
                "reference_output": mismatch_node_transcript
            }]
        }))
        .unwrap(),
    )
    .expect("write mismatch gate");
    let mismatch_report_path = work.join("out_mismatch_report.json");
    let mismatch_res = Command::new(BENCHMARK_EXPORT_BIN)
        .args([
            "--input",
            bundle_input_path.to_str().unwrap(),
            "--output",
            mismatch_report_path.to_str().unwrap(),
            "--type",
            "report",
            "--gate-integration",
            mismatch_gate.to_str().unwrap(),
        ])
        .output()
        .expect("run export with mismatched transcript");
    assert!(mismatch_res.status.success());
    let mismatch_report: serde_json::Value =
        serde_json::from_slice(&fs::read(&mismatch_report_path).unwrap()).unwrap();
    assert_ne!(
        mismatch_report["verdict"], "pass",
        "mismatched differential transcript must never receive a passing publication verdict: {mismatch_report}"
    );

    // Case D (POSITIVE): Matching real executed frankenctl + Node.js differential transcripts verify!
    let verified_gate = work.join("gate_verified_live.json");
    fs::write(
        &verified_gate,
        serde_json::to_vec_pretty(&serde_json::json!({
            "engine": "nodejs",
            "results": [{
                "test_name": workload_id,
                "value": 1.25,
                "franken_output": franken_transcript,
                "reference_output": node_transcript
            }]
        }))
        .unwrap(),
    )
    .expect("write verified gate");
    let verified_bundle_out = work.join("out_verified_bundle.json");
    let verified_res = Command::new(BENCHMARK_EXPORT_BIN)
        .args([
            "--input",
            bundle_input_path.to_str().unwrap(),
            "--output",
            verified_bundle_out.to_str().unwrap(),
            "--gate-integration",
            verified_gate.to_str().unwrap(),
        ])
        .output()
        .expect("run export with verified live transcripts");
    assert!(
        verified_res.status.success(),
        "verified live Node differential transcript must export cleanly: stderr={}",
        String::from_utf8_lossy(&verified_res.stderr)
    );
    let exported_bundle: EvidenceBundle =
        serde_json::from_slice(&fs::read(&verified_bundle_out).unwrap())
            .expect("parse exported EvidenceBundle");
    assert_eq!(exported_bundle.parity_verdicts.len(), 1);
    let pv = &exported_bundle.parity_verdicts[0];
    assert_eq!(pv.target, ParityTarget::NodeJs);
    assert!(pv.output_equivalent);
    assert_eq!(pv.behavioral_differences, 0);
    assert_ne!(pv.evidence_hash, ContentHash::from_bytes([0u8; 32]));
}

#[test]
fn ceremony_feature_isolation_storage_fail_closed_and_zero_placeholder_mutation_guard() {
    let root = repo_root();

    // 1. Verify >= 440 governance-surfaces modules + binaries are isolated from default builds.
    let lib_rs =
        fs::read_to_string(root.join("crates/franken-engine/src/lib.rs")).expect("read lib.rs");
    let mut gov_gated_modules = Vec::new();
    let mut prev_cfg = String::new();
    for line in lib_rs.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("#[cfg(") {
            prev_cfg = trimmed.to_string();
            continue;
        }
        if let Some(rest) = trimmed
            .strip_prefix("pub mod ")
            .or_else(|| trimmed.strip_prefix("mod "))
            && let Some(mod_name) = rest.strip_suffix(';')
        {
            if prev_cfg.contains("governance-surfaces") {
                gov_gated_modules.push(mod_name.trim().to_string());
            }
            prev_cfg.clear();
        } else if !trimmed.is_empty() && !trimmed.starts_with("//") && !trimmed.starts_with("#[") {
            prev_cfg.clear();
        }
    }
    let cargo_toml =
        fs::read_to_string(root.join("crates/franken-engine/Cargo.toml")).expect("read Cargo.toml");
    let gov_bin_count = cargo_toml
        .split("[[bin]]")
        .skip(1)
        .filter(|section| {
            section
                .split("\n[[")
                .next()
                .unwrap_or("")
                .contains("required-features = [\"governance-surfaces\"]")
        })
        .count();
    assert!(
        gov_gated_modules.len() >= 380,
        "expected >= 380 governance-surfaces gated library modules, found {}",
        gov_gated_modules.len()
    );
    assert!(
        gov_gated_modules.len() + gov_bin_count >= 440,
        "expected >= 440 isolated governance modules + bins, found {}",
        gov_gated_modules.len() + gov_bin_count
    );

    // Negative symbol check on default-built frankenctl binary (`#[cfg(not(feature = "governance-surfaces"))]`).
    #[cfg(not(feature = "governance-surfaces"))]
    {
        if let Ok(nm_out) = Command::new("nm").args(["-C", FRANKENCTL_BIN]).output()
            && nm_out.status.success()
        {
            let syms = String::from_utf8_lossy(&nm_out.stdout);
            for gated_mod in &gov_gated_modules {
                let needle = format!("frankenengine_engine::{gated_mod}::");
                assert!(
                    !syms.contains(&needle),
                    "default frankenctl binary leaked symbol from governance-surfaces module `{gated_mod}`"
                );
            }
            assert!(
                !syms.contains("frankenengine_test_support::") && !syms.contains("::Simulated"),
                "default frankenctl binary must not link frankenengine_test_support or Simulated* types"
            );
        }
    }

    // 2. Verify storage_adapter content-hash encoding fails closed without synthetic fallback.
    struct FailingState;
    impl Serialize for FailingState {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom("injected content-hash failure"))
        }
    }
    let err = encode_migration_state_hash(&FailingState, 1, 2)
        .expect_err("content-hash failure must fail closed");
    assert_eq!(err.code(), "FE-STOR-0006");
    assert!(matches!(
        err,
        StorageError::MigrationFailed { from: 1, to: 2, .. }
    ));

    let ctx = EventContext {
        trace_id: "trace-stor-g2vrp-22".to_string(),
        decision_id: "decision-stor-g2vrp-22".to_string(),
        policy_id: "policy-stor-g2vrp-22".to_string(),
    };
    let mut store_a = InMemoryStorageAdapter::new();
    let mut store_b = InMemoryStorageAdapter::new();
    store_a
        .put(
            StoreKind::ReplayIndex,
            "k".to_string(),
            b"value-a".to_vec(),
            BTreeMap::new(),
            &ctx,
        )
        .expect("put store_a");
    store_b
        .put(
            StoreKind::ReplayIndex,
            "k".to_string(),
            b"value-b".to_vec(),
            BTreeMap::new(),
            &ctx,
        )
        .expect("put store_b");
    let receipt_a = store_a.migrate_to(2).expect("migrate a");
    let receipt_b = store_b.migrate_to(2).expect("migrate b");
    assert_ne!(receipt_a.state_hash_before, receipt_b.state_hash_before);

    // 3. Mutation test proving zero_placeholder_scan catches injected stub macros while ignoring comments/strings/tests.
    let clean_src = scratch_dir("zp_clean_src");
    fs::write(
        clean_src.join("clean_mod.rs"),
        "// comment mentioning todo!() and unimplemented!()\n\
         pub fn real_answer() -> &'static str {\n\
             \"literal todo!(not_a_macro) and unimplemented!(also_literal)\"\n\
         }\n\
         #[cfg(test)]\n\
         mod tests {\n\
             #[test]\n\
             fn test_only_stub() {\n\
                 todo!(\"allowed after #[cfg(test)] mod\");\n\
             }\n\
         }\n",
    )
    .expect("write clean_mod.rs");
    let clean_hits = scan_production_source_placeholders(&clean_src).expect("scan clean_src");
    assert!(
        clean_hits.is_empty(),
        "clean synthetic crate must produce 0 hits, got: {clean_hits:?}"
    );

    let mutated_src = scratch_dir("zp_mutated_src");
    fs::write(
        mutated_src.join("mutated_mod.rs"),
        "pub fn half_baked_a() -> u32 {\n\
             todo!(\"injected synthetic stub\")\n\
         }\n\
         pub fn half_baked_b() -> u32 {\n\
             unimplemented!()\n\
         }\n",
    )
    .expect("write mutated_mod.rs");
    let mutated_hits = scan_production_source_placeholders(&mutated_src).expect("scan mutated_src");
    assert_eq!(mutated_hits.len(), 2, "must catch both injected stubs");
    assert_eq!(mutated_hits[0].relative_path, "mutated_mod.rs");
    assert_eq!(mutated_hits[0].line, 2);
    assert_eq!(mutated_hits[0].pattern, "todo!");
    assert_eq!(mutated_hits[1].line, 5);
    assert_eq!(mutated_hits[1].pattern, "unimplemented!");
}
