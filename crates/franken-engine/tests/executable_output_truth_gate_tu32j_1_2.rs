//! BRIDGE-00.2 (`bd-performance-conformance-bridge-tu32j.1.2`) executable-output,
//! conformance-claim, and authoritative claim-language truth gate tests.
//!
//! Covers normal, boundary, malformed, stale, missing, duplicate, reordered,
//! tampered, backend-label-only, simulated-compile-time, input-only-hash, and
//! synthetic-percentage inputs, plus end-to-end execution of the real
//! `franken_execution_truth_ledger audit-output-claims` binary.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Duration, Utc};
use frankenengine_engine::execution_truth_ledger::{
    CONFORMANCE_CLAIM_BUNDLE_SCHEMA_VERSION, ConformanceClaimBundle, DeoptMapEntryRecord,
    ERROR_OUTGATE_BACKEND_LABEL_ONLY, ERROR_OUTGATE_CLAIM_LANGUAGE, ERROR_OUTGATE_DISASSEMBLY,
    ERROR_OUTGATE_DISPATCH_ZERO, ERROR_OUTGATE_HARNESS_ORACLE, ERROR_OUTGATE_INPUT_ONLY_HASH,
    ERROR_OUTGATE_IO, ERROR_OUTGATE_JSON, ERROR_OUTGATE_MACHINE_CODE, ERROR_OUTGATE_MAPS,
    ERROR_OUTGATE_SELECTED_MANIFEST, ERROR_OUTGATE_SIMULATED_COMPILE, ERROR_OUTGATE_STALE_OR_ORDER,
    ERROR_OUTGATE_SYNTHETIC_PERCENTAGE, ERROR_OUTGATE_TIER_R_EQUIV,
    EXECUTABLE_TIER_BUNDLE_SCHEMA_VERSION, ExecutableTierClaimBundle, HarnessOracleRecord,
    OutputTruthAuditRequest, StackMapEntryRecord, TierREquivalenceRecord, ValidationContext,
    audit_output_claims, validate_conformance_claim_bundle, validate_executable_tier_bundle,
};
use sha2::{Digest, Sha256};

fn repo_root() -> PathBuf {
    for mut path in [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        PathBuf::from(file!()),
    ] {
        if path.is_file() {
            path.pop();
        }
        loop {
            if path.join("docs/execution_truth_ledger_v1.json").is_file() {
                return path;
            }
            if !path.pop() {
                break;
            }
        }
    }
    panic!("could not locate workspace root");
}

fn persistent_test_dir(tag: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = repo_root()
        .join("target")
        .join("executable_output_truth_gate_tu32j_1_2")
        .join(format!("{tag}_{}_{nonce}", std::process::id()));
    fs::create_dir_all(&dir).expect("create persistent test dir");
    dir
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn fixed_as_of() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-11-17T09:00:00Z")
        .expect("parse RFC3339")
        .with_timezone(&Utc)
}

fn fixed_context() -> ValidationContext {
    ValidationContext::deterministic_for_tests(fixed_as_of())
}

fn valid_executable_bundle() -> ExecutableTierClaimBundle {
    let machine_bytes: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0x5d, 0xc3,
    ];
    let machine_hex: String = machine_bytes.iter().map(|b| format!("{b:02x}")).collect();
    ExecutableTierClaimBundle {
        schema_version: EXECUTABLE_TIER_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_id: "exec-tier-valid-001".to_string(),
        owning_bead: "bd-performance-conformance-bridge-tu32j.1.2".to_string(),
        claim_id: "FE-CLAIM-010".to_string(),
        backend_kind: "x86_64_sysv_linked_jit".to_string(),
        generated_at_utc: "2026-11-17T08:00:00Z".to_string(),
        max_age_days: 14,
        simulated: false,
        compile_duration_origin: "measured_wall_ns".to_string(),
        compile_duration_ns: 184_200,
        input_ir_sha256: sha256_hex(b"ir3-module-canonical-bytes-v1"),
        machine_code_hex: machine_hex,
        machine_code_byte_len: machine_bytes.len(),
        final_byte_sha256: sha256_hex(machine_bytes),
        actual_dispatch_count: 16,
        disassembly_lines: vec![
            "0000: push rbp".to_string(),
            "0001: mov rbp, rsp".to_string(),
            "0004: mov eax, 42".to_string(),
            "0009: pop rbp".to_string(),
            "000a: ret".to_string(),
        ],
        stack_map_entries: vec![
            StackMapEntryRecord {
                code_offset: 0,
                live_root_slots: vec![],
            },
            StackMapEntryRecord {
                code_offset: 4,
                live_root_slots: vec![0, 2],
            },
        ],
        deopt_map_entries: vec![
            DeoptMapEntryRecord {
                code_offset: 4,
                ir3_pc: 1,
                reason: "smi_overflow_guard".to_string(),
            },
            DeoptMapEntryRecord {
                code_offset: 9,
                ir3_pc: 2,
                reason: "shape_check_guard".to_string(),
            },
        ],
        tier_r_equivalence: TierREquivalenceRecord {
            verified: true,
            witness_cases_passed: 32,
            witness_cases_total: 32,
            tier_r_trace_sha256: sha256_hex(b"tier-r-differential-witness-trace-v1"),
        },
    }
}

fn valid_conformance_bundle(root: &Path) -> ConformanceClaimBundle {
    let manifest_rel = "docs/test262_real_corpus_pass_rate_v1.json";
    let manifest_bytes = fs::read(root.join(manifest_rel)).expect("read manifest anchor");
    ConformanceClaimBundle {
        schema_version: CONFORMANCE_CLAIM_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_id: "conformance-valid-001".to_string(),
        owning_bead: "bd-performance-conformance-bridge-tu32j.1.2".to_string(),
        claim_id: "FE-CLAIM-TEST262".to_string(),
        generated_at_utc: "2026-11-17T08:00:00Z".to_string(),
        max_age_days: 14,
        selected_manifest_path: manifest_rel.to_string(),
        selected_manifest_sha256: sha256_hex(&manifest_bytes),
        selected_case_ids: vec![
            "built-ins/Array/isArray/15.4.3.2-0-1.js".to_string(),
            "language/expressions/addition/S11.6.1_A2.1_T1.js".to_string(),
            "language/statements/let/block-local-closure-get-before-initialization.js".to_string(),
            "language/types/number/S8.5_A1.js".to_string(),
        ],
        selected_case_count: 4,
        executed_count: 4,
        passed_count: 3,
        failed_count: 1,
        skipped_count: 0,
        pass_rate_millionths: 750_000,
        synthetic_percentage: false,
        estimation_method: "exact_executed_corpus".to_string(),
        full_suite_claim_allowed: false,
        harness_oracle: HarnessOracleRecord {
            oracle_kind: "test262_harness_v1".to_string(),
            includes_preloaded: true,
            async_done_tracked: true,
            negative_phase_verified: true,
        },
    }
}

#[test]
fn live_repository_passes_claim_language_truth_audit() {
    let root = repo_root();
    let output = audit_output_claims(&root, &OutputTruthAuditRequest::default(), &fixed_context());
    assert!(
        output.passed(),
        "live repository must pass claim-language truth audit: {:?}",
        output.report.findings
    );
    assert_eq!(output.report.governed_documents_checked, 8);
}

#[test]
fn valid_executable_and_conformance_bundles_pass_normal_and_boundary_checks() {
    let root = repo_root();
    let ctx = fixed_context();
    let mut exec_bundle = valid_executable_bundle();
    assert!(validate_executable_tier_bundle(&exec_bundle, &ctx).is_ok());

    // Boundary: 1-byte machine code (`0xc3` = `ret`), 1 dispatch, exact max_age_days boundary.
    exec_bundle.machine_code_hex = "c3".to_string();
    exec_bundle.machine_code_byte_len = 1;
    exec_bundle.final_byte_sha256 = sha256_hex(&[0xc3]);
    exec_bundle.actual_dispatch_count = 1;
    exec_bundle.stack_map_entries = vec![StackMapEntryRecord {
        code_offset: 0,
        live_root_slots: vec![],
    }];
    exec_bundle.deopt_map_entries = vec![DeoptMapEntryRecord {
        code_offset: 0,
        ir3_pc: 0,
        reason: "entry_guard".to_string(),
    }];
    exec_bundle.generated_at_utc = (fixed_as_of() - Duration::days(14)).to_rfc3339();
    assert!(validate_executable_tier_bundle(&exec_bundle, &ctx).is_ok());

    let conf_bundle = valid_conformance_bundle(&root);
    assert!(validate_conformance_claim_bundle(&root, &conf_bundle, &ctx).is_ok());
}

#[test]
fn executable_bundle_rejects_backend_labels_simulated_compile_and_input_hashes() {
    let ctx = fixed_context();

    let mut label_only = valid_executable_bundle();
    label_only.backend_kind = "unlinked_cranelift_backend_label".to_string();
    assert_eq!(
        validate_executable_tier_bundle(&label_only, &ctx)
            .unwrap_err()
            .0,
        ERROR_OUTGATE_BACKEND_LABEL_ONLY
    );

    let mut simulated = valid_executable_bundle();
    simulated.simulated = true;
    assert_eq!(
        validate_executable_tier_bundle(&simulated, &ctx)
            .unwrap_err()
            .0,
        ERROR_OUTGATE_SIMULATED_COMPILE
    );

    let mut synthetic_origin = valid_executable_bundle();
    synthetic_origin.compile_duration_origin = "estimated_from_ir_node_count".to_string();
    assert_eq!(
        validate_executable_tier_bundle(&synthetic_origin, &ctx)
            .unwrap_err()
            .0,
        ERROR_OUTGATE_SIMULATED_COMPILE
    );

    let mut input_hash = valid_executable_bundle();
    input_hash.input_ir_sha256 = input_hash.final_byte_sha256.clone();
    assert_eq!(
        validate_executable_tier_bundle(&input_hash, &ctx)
            .unwrap_err()
            .0,
        ERROR_OUTGATE_INPUT_ONLY_HASH
    );

    let mut zero_dispatch = valid_executable_bundle();
    zero_dispatch.actual_dispatch_count = 0;
    assert_eq!(
        validate_executable_tier_bundle(&zero_dispatch, &ctx)
            .unwrap_err()
            .0,
        ERROR_OUTGATE_DISPATCH_ZERO
    );

    let mut missing_disasm = valid_executable_bundle();
    missing_disasm.disassembly_lines.clear();
    assert_eq!(
        validate_executable_tier_bundle(&missing_disasm, &ctx)
            .unwrap_err()
            .0,
        ERROR_OUTGATE_DISASSEMBLY
    );

    let mut missing_maps = valid_executable_bundle();
    missing_maps.deopt_map_entries.clear();
    assert_eq!(
        validate_executable_tier_bundle(&missing_maps, &ctx)
            .unwrap_err()
            .0,
        ERROR_OUTGATE_MAPS
    );

    let mut tampered_bytes = valid_executable_bundle();
    tampered_bytes.machine_code_hex = "90c3".to_string();
    tampered_bytes.machine_code_byte_len = 2;
    assert_eq!(
        validate_executable_tier_bundle(&tampered_bytes, &ctx)
            .unwrap_err()
            .0,
        ERROR_OUTGATE_MACHINE_CODE
    );

    let mut unverified_tier_r = valid_executable_bundle();
    unverified_tier_r.tier_r_equivalence.verified = false;
    assert_eq!(
        validate_executable_tier_bundle(&unverified_tier_r, &ctx)
            .unwrap_err()
            .0,
        ERROR_OUTGATE_TIER_R_EQUIV
    );
}

#[test]
fn executable_and_conformance_bundles_reject_stale_duplicate_and_reordered_entries() {
    let root = repo_root();
    let ctx = fixed_context();

    let mut stale = valid_executable_bundle();
    stale.generated_at_utc = (fixed_as_of() - Duration::days(30)).to_rfc3339();
    assert_eq!(
        validate_executable_tier_bundle(&stale, &ctx).unwrap_err().0,
        ERROR_OUTGATE_STALE_OR_ORDER
    );

    let mut dup_stack_map = valid_executable_bundle();
    dup_stack_map.stack_map_entries = vec![
        StackMapEntryRecord {
            code_offset: 4,
            live_root_slots: vec![0],
        },
        StackMapEntryRecord {
            code_offset: 4,
            live_root_slots: vec![1],
        },
    ];
    assert_eq!(
        validate_executable_tier_bundle(&dup_stack_map, &ctx)
            .unwrap_err()
            .0,
        ERROR_OUTGATE_STALE_OR_ORDER
    );

    let mut reordered_deopt = valid_executable_bundle();
    reordered_deopt.deopt_map_entries.swap(0, 1);
    assert_eq!(
        validate_executable_tier_bundle(&reordered_deopt, &ctx)
            .unwrap_err()
            .0,
        ERROR_OUTGATE_STALE_OR_ORDER
    );

    let mut reordered_cases = valid_conformance_bundle(&root);
    reordered_cases.selected_case_ids.swap(0, 2);
    assert_eq!(
        validate_conformance_claim_bundle(&root, &reordered_cases, &ctx)
            .unwrap_err()
            .0,
        ERROR_OUTGATE_STALE_OR_ORDER
    );
}

#[test]
fn conformance_bundle_rejects_synthetic_percentages_missing_oracle_and_tampered_manifest() {
    let root = repo_root();
    let ctx = fixed_context();

    let mut synthetic = valid_conformance_bundle(&root);
    synthetic.synthetic_percentage = true;
    assert_eq!(
        validate_conformance_claim_bundle(&root, &synthetic, &ctx)
            .unwrap_err()
            .0,
        ERROR_OUTGATE_SYNTHETIC_PERCENTAGE
    );

    let mut proxy_rate = valid_conformance_bundle(&root);
    proxy_rate.estimation_method = "execution_coverage_proxy".to_string();
    assert_eq!(
        validate_conformance_claim_bundle(&root, &proxy_rate, &ctx)
            .unwrap_err()
            .0,
        ERROR_OUTGATE_SYNTHETIC_PERCENTAGE
    );

    let mut inflated_rate = valid_conformance_bundle(&root);
    inflated_rate.pass_rate_millionths = 999_999;
    assert_eq!(
        validate_conformance_claim_bundle(&root, &inflated_rate, &ctx)
            .unwrap_err()
            .0,
        ERROR_OUTGATE_SYNTHETIC_PERCENTAGE
    );

    let mut no_includes = valid_conformance_bundle(&root);
    no_includes.harness_oracle.includes_preloaded = false;
    assert_eq!(
        validate_conformance_claim_bundle(&root, &no_includes, &ctx)
            .unwrap_err()
            .0,
        ERROR_OUTGATE_HARNESS_ORACLE
    );

    let mut tampered_manifest = valid_conformance_bundle(&root);
    tampered_manifest.selected_manifest_sha256 = "f".repeat(64);
    assert_eq!(
        validate_conformance_claim_bundle(&root, &tampered_manifest, &ctx)
            .unwrap_err()
            .0,
        ERROR_OUTGATE_SELECTED_MANIFEST
    );

    let mut premature_full_claim = valid_conformance_bundle(&root);
    premature_full_claim.full_suite_claim_allowed = true;
    assert_eq!(
        validate_conformance_claim_bundle(&root, &premature_full_claim, &ctx)
            .unwrap_err()
            .0,
        ERROR_OUTGATE_CLAIM_LANGUAGE
    );
}

#[test]
fn cli_audit_output_claims_validates_files_and_rejects_malformed_missing_and_overclaim_overrides() {
    let root = repo_root();
    let dir = persistent_test_dir("cli_audit");
    let bin = env!("CARGO_BIN_EXE_franken_execution_truth_ledger");

    let valid_exec_path = dir.join("valid_exec.json");
    let valid_conf_path = dir.join("valid_conf.json");
    let events_path = dir.join("audit_events.jsonl");
    fs::write(
        &valid_exec_path,
        serde_json::to_vec_pretty(&valid_executable_bundle()).unwrap(),
    )
    .unwrap();
    fs::write(
        &valid_conf_path,
        serde_json::to_vec_pretty(&valid_conformance_bundle(&root)).unwrap(),
    )
    .unwrap();

    let pass_run = Command::new(bin)
        .args([
            "audit-output-claims",
            "--repo-root",
            root.to_str().unwrap(),
            "--executable-bundle",
            valid_exec_path.to_str().unwrap(),
            "--conformance-bundle",
            valid_conf_path.to_str().unwrap(),
            "--events",
            events_path.to_str().unwrap(),
            "--as-of",
            "2026-11-17T09:00:00Z",
        ])
        .output()
        .expect("run franken_execution_truth_ledger audit-output-claims");
    assert!(
        pass_run.status.success(),
        "valid audit-output-claims should pass: {}",
        String::from_utf8_lossy(&pass_run.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&pass_run.stdout).unwrap();
    assert_eq!(report["status"], "pass");
    assert_eq!(report["error_count"], 0);
    assert!(fs::read_to_string(&events_path).unwrap().lines().count() >= 10);

    // Seeded malformed JSON, missing file, unowned doc override, and false IR4 claim override.
    let malformed_path = dir.join("malformed_exec.json");
    let false_synthesis_path = dir.join("false_synthesis.md");
    fs::write(&malformed_path, b"{not valid json").unwrap();
    fs::write(
        &false_synthesis_path,
        "# Synthesis\n- `IR3` (Specialization-Intent IR)\n- `IR4` (Execution-Ready Low-Level IR)\n",
    )
    .unwrap();

    let request = OutputTruthAuditRequest {
        executable_bundles: vec![malformed_path, dir.join("missing_bundle.json")],
        conformance_bundles: vec![],
        doc_overrides: BTreeMap::from([
            (
                "docs/architecture/frankenengine_native_synthesis.md".to_string(),
                false_synthesis_path,
            ),
            (
                "docs/UNOWNED_SPECULATIVE_CLAIM.md".to_string(),
                valid_exec_path,
            ),
        ]),
        skip_repository_language_scan: false,
    };
    let negative = audit_output_claims(&root, &request, &fixed_context());
    assert!(!negative.passed());
    let codes: Vec<&str> = negative
        .report
        .findings
        .iter()
        .map(|f| f.error_code.as_str())
        .collect();
    assert!(codes.contains(&ERROR_OUTGATE_JSON), "{codes:?}");
    assert!(codes.contains(&ERROR_OUTGATE_IO), "{codes:?}");
    assert!(codes.contains(&ERROR_OUTGATE_CLAIM_LANGUAGE), "{codes:?}");
}
