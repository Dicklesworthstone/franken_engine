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
use std::path::PathBuf;

use frankenengine_engine::conformance_harness::{
    ConformanceAssetManifest, ConformanceAssetRecord, ConformanceCiGateError,
    ConformanceDeltaClassification, ConformanceDeltaKind, ConformanceFailureClass,
    ConformanceFailureSeverity, ConformanceIssueLink, ConformanceLogEvent,
    ConformanceManifestError, ConformanceMinimizationSummary, ConformanceMinimizedFailingVector,
    ConformanceMinimizedReproArtifact, ConformanceReplayContract,
    ConformanceReplayVerificationError, ConformanceReproEnvironment, ConformanceReproMetadata,
    ConformanceRunError, ConformanceRunLinkage, ConformanceRunResult, ConformanceRunSummary,
    ConformanceRunnerConfig, ConformanceWaiver, ConformanceWaiverSet, DeterministicRng,
    DonorFixture, DonorHarnessAdapter, DonorHarnessApi, WaiverReasonCode,
    canonicalize_conformance_output, classify_conformance_delta, classify_failure_class,
    severity_for_failure_class,
};

// ===================================================================
// ConformanceManifestError Display — exhaustive
// ===================================================================

#[test]
fn manifest_error_display_manifest_has_no_parent() {
    let err = ConformanceManifestError::ManifestHasNoParent;
    assert!(err.to_string().contains("no parent"));
}

#[test]
fn manifest_error_display_invalid_field_value() {
    let err = ConformanceManifestError::InvalidFieldValue {
        field: "category",
        value: "bad_value".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("category"));
    assert!(s.contains("bad_value"));
}

#[test]
fn manifest_error_display_invalid_ifc_expectation() {
    let err = ConformanceManifestError::InvalidIfcExpectation {
        asset_id: "asset-1".to_string(),
        category: "benign".to_string(),
        expected_outcome: "block".to_string(),
        expected_evidence_type: "flow_violation".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("asset-1"));
    assert!(s.contains("benign"));
    assert!(s.contains("block"));
}

#[test]
fn manifest_error_display_asset_io() {
    let err = ConformanceManifestError::AssetIo {
        asset_id: "asset-2".to_string(),
        path: PathBuf::from("/fake/path.json"),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
    };
    let s = err.to_string();
    assert!(s.contains("asset-2"));
    assert!(s.contains("/fake/path.json"));
}

#[test]
fn manifest_error_display_fixture_hash_mismatch() {
    let err = ConformanceManifestError::FixtureHashMismatch {
        asset_id: "asset-3".to_string(),
        expected: "aaa".to_string(),
        actual: "bbb".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("fixture hash mismatch"));
    assert!(s.contains("aaa"));
    assert!(s.contains("bbb"));
}

#[test]
fn manifest_error_display_expected_output_hash_mismatch() {
    let err = ConformanceManifestError::ExpectedOutputHashMismatch {
        asset_id: "asset-4".to_string(),
        expected: "ccc".to_string(),
        actual: "ddd".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("expected output hash mismatch"));
    assert!(s.contains("ccc"));
    assert!(s.contains("ddd"));
}

// ===================================================================
// ConformanceManifestError Error::source()
// ===================================================================

#[test]
fn manifest_error_source_asset_io_returns_some() {
    let err = ConformanceManifestError::AssetIo {
        asset_id: "a".to_string(),
        path: PathBuf::from("/p"),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "nf"),
    };
    let err_ref: &dyn std::error::Error = &err;
    assert!(err_ref.source().is_some());
}

#[test]
fn manifest_error_source_non_io_returns_none() {
    let err = ConformanceManifestError::EmptyAssetSet;
    let err_ref: &dyn std::error::Error = &err;
    assert!(err_ref.source().is_none());
}

#[test]
fn manifest_error_source_missing_field_returns_none() {
    let err = ConformanceManifestError::MissingField("field");
    let err_ref: &dyn std::error::Error = &err;
    assert!(err_ref.source().is_none());
}

// ===================================================================
// ConformanceRunError Display — remaining variants
// ===================================================================

#[test]
fn run_error_display_manifest() {
    let inner = ConformanceManifestError::EmptyAssetSet;
    let err = ConformanceRunError::Manifest(inner);
    assert!(err.to_string().contains("no assets"));
}

#[test]
fn run_error_display_fixture_io() {
    let err = ConformanceRunError::FixtureIo {
        asset_id: "asset-x".to_string(),
        path: PathBuf::from("/fixture"),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "nf"),
    };
    let s = err.to_string();
    assert!(s.contains("asset-x"));
    assert!(s.contains("/fixture"));
}

#[test]
fn run_error_display_invalid_fixture() {
    let err = ConformanceRunError::InvalidFixture {
        asset_id: "asset-y".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, "bad json"),
    };
    let s = err.to_string();
    assert!(s.contains("asset-y"));
    assert!(s.contains("bad json"));
}

#[test]
fn run_error_display_expected_output_io() {
    let err = ConformanceRunError::ExpectedOutputIo {
        asset_id: "asset-z".to_string(),
        path: PathBuf::from("/expected"),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
    };
    let s = err.to_string();
    assert!(s.contains("asset-z"));
    assert!(s.contains("/expected"));
}

#[test]
fn run_error_display_io() {
    let err = ConformanceRunError::Io(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "denied",
    ));
    assert!(err.to_string().contains("denied"));
}

// ===================================================================
// ConformanceRunError Error::source()
// ===================================================================

#[test]
fn run_error_source_manifest_returns_some() {
    let err = ConformanceRunError::Manifest(ConformanceManifestError::EmptyAssetSet);
    let err_ref: &dyn std::error::Error = &err;
    assert!(err_ref.source().is_some());
}

#[test]
fn run_error_source_fixture_io_returns_some() {
    let err = ConformanceRunError::FixtureIo {
        asset_id: "a".to_string(),
        path: PathBuf::from("/p"),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "nf"),
    };
    let err_ref: &dyn std::error::Error = &err;
    assert!(err_ref.source().is_some());
}

#[test]
fn run_error_source_invalid_config_returns_none() {
    let err = ConformanceRunError::InvalidConfig("reason".to_string());
    let err_ref: &dyn std::error::Error = &err;
    assert!(err_ref.source().is_none());
}

#[test]
fn run_error_source_repro_invariant_returns_none() {
    let err = ConformanceRunError::ReproInvariant {
        asset_id: "a".to_string(),
        detail: "d".to_string(),
    };
    let err_ref: &dyn std::error::Error = &err;
    assert!(err_ref.source().is_none());
}

// ===================================================================
// ConformanceReplayVerificationError Error impl
// ===================================================================

#[test]
fn replay_verification_error_implements_std_error() {
    let err: Box<dyn std::error::Error> =
        Box::new(ConformanceReplayVerificationError::FailureNotReproduced);
    assert!(err.source().is_none());
    assert!(!err.to_string().is_empty());
}

#[test]
fn replay_verification_error_all_variants_display() {
    let variants: Vec<ConformanceReplayVerificationError> = vec![
        ConformanceReplayVerificationError::FailureNotReproduced,
        ConformanceReplayVerificationError::FailureClassMismatch {
            expected: ConformanceFailureClass::Breaking,
            actual: ConformanceFailureClass::Performance,
        },
        ConformanceReplayVerificationError::DeltaClassificationDrift,
        ConformanceReplayVerificationError::DigestMismatch {
            expected: "a".to_string(),
            actual: "b".to_string(),
        },
    ];
    for v in &variants {
        assert!(!v.to_string().is_empty());
    }
}

// ===================================================================
// ConformanceCiGateError Error impl
// ===================================================================

#[test]
fn ci_gate_error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(ConformanceCiGateError {
        failed: 1,
        errored: 2,
    });
    assert!(err.source().is_none());
    assert!(err.to_string().contains("failed=1"));
    assert!(err.to_string().contains("errored=2"));
}

// ===================================================================
// DeterministicRng edge cases
// ===================================================================

#[test]
fn deterministic_rng_produces_nonzero_values() {
    let mut rng = DeterministicRng::seeded(1);
    let values: Vec<u64> = (0..10).map(|_| rng.next_u64()).collect();
    assert!(values.iter().all(|v| *v != 0));
}

#[test]
fn deterministic_rng_long_sequence_no_immediate_cycle() {
    let mut rng = DeterministicRng::seeded(42);
    let mut seen = std::collections::HashSet::new();
    for _ in 0..1000 {
        let v = rng.next_u64();
        seen.insert(v);
    }
    // After 1000 draws, expect at least 990 unique values (no short cycle).
    assert!(seen.len() > 990);
}

#[test]
fn deterministic_rng_zero_seed_fallback_consistent() {
    let mut a = DeterministicRng::seeded(0);
    let mut b = DeterministicRng::seeded(0);
    let seq_a: Vec<u64> = (0..10).map(|_| a.next_u64()).collect();
    let seq_b: Vec<u64> = (0..10).map(|_| b.next_u64()).collect();
    assert_eq!(seq_a, seq_b);
}

// ===================================================================
// canonicalize_conformance_output — additional cases
// ===================================================================

#[test]
fn canonicalize_multiple_props_lines_takes_first() {
    let raw = "props: z, a\nother line\nprops: b, c";
    let result = canonicalize_conformance_output(raw);
    // First props line gets sorted.
    assert!(result.starts_with("props:a,z"));
}

#[test]
fn canonicalize_props_empty_values_skipped() {
    let raw = "props: a, , b, ,";
    let result = canonicalize_conformance_output(raw);
    assert_eq!(result, "props:a,b");
}

#[test]
fn canonicalize_integer_and_float_normalized() {
    let raw = "val 3 done";
    let result = canonicalize_conformance_output(raw);
    assert_eq!(result, "val 3.000000 done");
}

#[test]
fn canonicalize_reference_error_normalized() {
    let raw = "ReferenceError: x is not defined";
    let result = canonicalize_conformance_output(raw);
    assert!(result.contains("ReferenceError|"));
    assert!(!result.contains("ReferenceError: "));
}

#[test]
fn canonicalize_syntax_error_normalized() {
    let raw = "SyntaxError: unexpected token";
    let result = canonicalize_conformance_output(raw);
    assert!(result.contains("SyntaxError|"));
}

// ===================================================================
// classify_conformance_delta — additional edge cases
// ===================================================================

#[test]
fn classify_delta_both_empty_returns_empty() {
    let deltas = classify_conformance_delta("", "");
    assert!(deltas.is_empty());
}

#[test]
fn classify_delta_props_modified_no_add_remove() {
    // Same field set, different values: SchemaFieldModified.
    let expected = "props: a, b\nvalue: 1";
    let actual = "props: a, b\nvalue: 2";
    let deltas = classify_conformance_delta(expected, actual);
    // The props line is identical after canonicalization, so this is a behavioral shift.
    assert!(!deltas.is_empty());
}

#[test]
fn classify_delta_error_format_different_error_types() {
    let expected = "TypeError|foo";
    let actual = "SyntaxError|bar";
    let deltas = classify_conformance_delta(expected, actual);
    assert!(!deltas.is_empty());
    // Both contain Error| so should detect error format change.
    assert!(
        deltas
            .iter()
            .any(|d| d.kind == ConformanceDeltaKind::ErrorFormatChange)
    );
}

#[test]
fn classify_delta_numeric_timing_multiple_numbers() {
    let expected = "latency 100 200 ms";
    let actual = "latency 150 250 ms";
    let deltas = classify_conformance_delta(expected, actual);
    assert!(
        deltas
            .iter()
            .any(|d| d.kind == ConformanceDeltaKind::TimingChange)
    );
}

// ===================================================================
// classify_failure_class — additional cases
// ===================================================================

#[test]
fn classify_failure_class_single_observability() {
    let deltas = vec![ConformanceDeltaClassification {
        kind: ConformanceDeltaKind::ErrorFormatChange,
        field: None,
        expected: None,
        actual: None,
        detail: String::new(),
    }];
    assert_eq!(
        classify_failure_class(&deltas),
        ConformanceFailureClass::Observability
    );
}

#[test]
fn classify_failure_class_highest_priority_wins() {
    let deltas = vec![
        ConformanceDeltaClassification {
            kind: ConformanceDeltaKind::TimingChange,
            field: None,
            expected: None,
            actual: None,
            detail: String::new(),
        },
        ConformanceDeltaClassification {
            kind: ConformanceDeltaKind::BehavioralSemanticShift,
            field: None,
            expected: None,
            actual: None,
            detail: String::new(),
        },
        ConformanceDeltaClassification {
            kind: ConformanceDeltaKind::ErrorFormatChange,
            field: None,
            expected: None,
            actual: None,
            detail: String::new(),
        },
    ];
    // Behavioral > Observability > Performance → Behavioral wins.
    assert_eq!(
        classify_failure_class(&deltas),
        ConformanceFailureClass::Behavioral
    );
}

// ===================================================================
// severity_for_failure_class — completeness
// ===================================================================

#[test]
fn severity_all_classes_mapped() {
    // Ensure all failure classes map to a severity.
    let classes = [
        ConformanceFailureClass::Breaking,
        ConformanceFailureClass::Behavioral,
        ConformanceFailureClass::Observability,
        ConformanceFailureClass::Performance,
    ];
    for class in classes {
        let sev = severity_for_failure_class(class);
        // Just verify it returns something (no panic).
        let _ = format!("{sev:?}");
    }
}

// ===================================================================
// ConformanceRunResult::enforce_ci_gate — waived only passes
// ===================================================================

#[test]
fn enforce_ci_gate_passes_when_all_waived() {
    let result = ConformanceRunResult {
        run_id: "run-1".to_string(),
        asset_manifest_hash: "hash".to_string(),
        logs: vec![],
        summary: ConformanceRunSummary {
            run_id: "run-1".to_string(),
            asset_manifest_hash: "hash".to_string(),
            total_assets: 5,
            passed: 0,
            failed: 0,
            waived: 5,
            errored: 0,
            env_fingerprint: "fp".to_string(),
        },
        minimized_repros: vec![],
    };
    assert!(result.enforce_ci_gate().is_ok());
}

#[test]
fn enforce_ci_gate_fails_on_both_failed_and_errored() {
    let result = ConformanceRunResult {
        run_id: "run-1".to_string(),
        asset_manifest_hash: "hash".to_string(),
        logs: vec![],
        summary: ConformanceRunSummary {
            run_id: "run-1".to_string(),
            asset_manifest_hash: "hash".to_string(),
            total_assets: 10,
            passed: 5,
            failed: 3,
            waived: 0,
            errored: 2,
            env_fingerprint: "fp".to_string(),
        },
        minimized_repros: vec![],
    };
    let err = result.enforce_ci_gate().unwrap_err();
    assert_eq!(err.failed, 3);
    assert_eq!(err.errored, 2);
}

// ===================================================================
// DonorHarnessAdapter via trait
// ===================================================================

#[test]
fn donor_harness_adapter_no_replacements_passthrough() {
    let adapter = DonorHarnessAdapter;
    let result = adapter.adapt_source("var x = 42;");
    assert_eq!(result, "var x = 42;");
}

#[test]
fn donor_harness_adapter_multiple_occurrences() {
    let adapter = DonorHarnessAdapter;
    let result = adapter.adapt_source("print(1); print(2);");
    assert_eq!(result, "franken_print(1); franken_print(2);");
}

// ===================================================================
// Serde roundtrips for pub types
// ===================================================================

#[test]
fn deterministic_rng_serde_preserves_state() {
    let mut rng = DeterministicRng::seeded(42);
    rng.next_u64(); // Advance state.
    let json = serde_json::to_string(&rng).expect("serialize");
    let restored: DeterministicRng = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(rng, restored);
}

#[test]
fn conformance_asset_record_serde_roundtrip() {
    let rec = ConformanceAssetRecord {
        asset_id: "test-001".to_string(),
        source_donor: "test262".to_string(),
        semantic_domain: "evaluation".to_string(),
        normative_reference: "ECMA-262 §15.1".to_string(),
        fixture_path: "fixtures/test-001.json".to_string(),
        fixture_hash: "abc123".to_string(),
        expected_output_path: "expected/test-001.txt".to_string(),
        expected_output_hash: "def456".to_string(),
        import_date: "2025-01-01".to_string(),
        category: Some("benign".to_string()),
        source_labels: vec!["credential".to_string()],
        sink_clearances: vec!["network_egress".to_string()],
        flow_path_type: Some("direct".to_string()),
        expected_outcome: Some("allow".to_string()),
        expected_evidence_type: Some("none".to_string()),
    };
    let json = serde_json::to_string(&rec).expect("serialize");
    let restored: ConformanceAssetRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(rec, restored);
}

#[test]
fn conformance_asset_manifest_serde_roundtrip() {
    let manifest = ConformanceAssetManifest {
        schema_version: ConformanceAssetManifest::CURRENT_SCHEMA.to_string(),
        generated_at_utc: "2025-01-01T00:00:00Z".to_string(),
        assets: vec![ConformanceAssetRecord {
            asset_id: "a1".to_string(),
            source_donor: "donor".to_string(),
            semantic_domain: "sem".to_string(),
            normative_reference: "ref".to_string(),
            fixture_path: "f.json".to_string(),
            fixture_hash: "h1".to_string(),
            expected_output_path: "e.txt".to_string(),
            expected_output_hash: "h2".to_string(),
            import_date: "2025-01-01".to_string(),
            category: None,
            source_labels: vec![],
            sink_clearances: vec![],
            flow_path_type: None,
            expected_outcome: None,
            expected_evidence_type: None,
        }],
    };
    let json = serde_json::to_string(&manifest).expect("serialize");
    let restored: ConformanceAssetManifest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(manifest, restored);
}

#[test]
fn conformance_waiver_serde_roundtrip() {
    let waiver = ConformanceWaiver {
        asset_id: "test-001".to_string(),
        reason_code: WaiverReasonCode::IntentionalDivergence,
        tracking_bead: "bd-99".to_string(),
        expiry_date: "2030-12-31".to_string(),
    };
    let json = serde_json::to_string(&waiver).expect("serialize");
    let restored: ConformanceWaiver = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(waiver, restored);
}

#[test]
fn conformance_waiver_set_serde_roundtrip() {
    let set = ConformanceWaiverSet {
        waivers: vec![ConformanceWaiver {
            asset_id: "a".to_string(),
            reason_code: WaiverReasonCode::HarnessGap,
            tracking_bead: "bd-1".to_string(),
            expiry_date: "2030-01-01".to_string(),
        }],
    };
    let json = serde_json::to_string(&set).expect("serialize");
    let restored: ConformanceWaiverSet = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(set, restored);
}

#[test]
fn conformance_repro_metadata_serde_roundtrip() {
    let meta = ConformanceReproMetadata::default();
    let json = serde_json::to_string(&meta).expect("serialize");
    let restored: ConformanceReproMetadata = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(meta, restored);
}

#[test]
fn conformance_runner_config_serde_roundtrip() {
    let config = ConformanceRunnerConfig::default();
    let json = serde_json::to_string(&config).expect("serialize");
    let restored: ConformanceRunnerConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, restored);
}

#[test]
fn conformance_log_event_serde_roundtrip() {
    let event = ConformanceLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "conformance_runner".to_string(),
        event: "asset_execution".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        asset_id: "a1".to_string(),
        workload_id: "w1".to_string(),
        semantic_domain: "sem".to_string(),
        category: Some("benign".to_string()),
        source_labels: vec!["credential".to_string()],
        sink_clearances: vec!["network_egress".to_string()],
        flow_path_type: Some("direct".to_string()),
        expected_outcome: Some("allow".to_string()),
        actual_outcome: Some("allow".to_string()),
        evidence_type: Some("none".to_string()),
        evidence_id: None,
        duration_us: 100,
        error_detail: None,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: ConformanceLogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

#[test]
fn conformance_run_summary_serde_roundtrip() {
    let summary = ConformanceRunSummary {
        run_id: "run-1".to_string(),
        asset_manifest_hash: "hash".to_string(),
        total_assets: 10,
        passed: 8,
        failed: 1,
        waived: 1,
        errored: 0,
        env_fingerprint: "fp".to_string(),
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let restored: ConformanceRunSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(summary, restored);
}

#[test]
fn conformance_run_result_serde_roundtrip() {
    let result = ConformanceRunResult {
        run_id: "run-1".to_string(),
        asset_manifest_hash: "hash".to_string(),
        logs: vec![],
        summary: ConformanceRunSummary {
            run_id: "run-1".to_string(),
            asset_manifest_hash: "hash".to_string(),
            total_assets: 0,
            passed: 0,
            failed: 0,
            waived: 0,
            errored: 0,
            env_fingerprint: "fp".to_string(),
        },
        minimized_repros: vec![],
    };
    let json = serde_json::to_string(&result).expect("serialize");
    let restored: ConformanceRunResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result, restored);
}

#[test]
fn conformance_delta_classification_serde_roundtrip() {
    let delta = ConformanceDeltaClassification {
        kind: ConformanceDeltaKind::BehavioralSemanticShift,
        field: None,
        expected: Some("true".to_string()),
        actual: Some("false".to_string()),
        detail: "semantic shift".to_string(),
    };
    let json = serde_json::to_string(&delta).expect("serialize");
    let restored: ConformanceDeltaClassification =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(delta, restored);
}

#[test]
fn conformance_repro_environment_serde_roundtrip() {
    let env = ConformanceReproEnvironment {
        locale: "C".to_string(),
        timezone: "UTC".to_string(),
        gc_schedule: "deterministic".to_string(),
        rust_toolchain: "stable".to_string(),
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
    };
    let json = serde_json::to_string(&env).expect("serialize");
    let restored: ConformanceReproEnvironment = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(env, restored);
}

#[test]
fn conformance_replay_contract_serde_roundtrip() {
    let replay = ConformanceReplayContract {
        deterministic_seed: 42,
        replay_command: "cmd".to_string(),
        verification_command: "verify".to_string(),
        verification_digest: "digest".to_string(),
    };
    let json = serde_json::to_string(&replay).expect("serialize");
    let restored: ConformanceReplayContract = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(replay, restored);
}

#[test]
fn conformance_issue_link_serde_roundtrip() {
    let link = ConformanceIssueLink {
        tracker: "beads".to_string(),
        issue_id: "bd-42".to_string(),
    };
    let json = serde_json::to_string(&link).expect("serialize");
    let restored: ConformanceIssueLink = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(link, restored);
}

#[test]
fn conformance_run_linkage_serde_roundtrip() {
    let linkage = ConformanceRunLinkage {
        run_id: "run-1".to_string(),
        trace_id: "trace-1".to_string(),
        decision_id: "dec-1".to_string(),
        ci_run_id: Some("ci-1".to_string()),
    };
    let json = serde_json::to_string(&linkage).expect("serialize");
    let restored: ConformanceRunLinkage = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(linkage, restored);
}

#[test]
fn conformance_minimized_failing_vector_serde_roundtrip() {
    let vector = ConformanceMinimizedFailingVector {
        asset_id: "a1".to_string(),
        source_donor: "test262".to_string(),
        semantic_domain: "sem".to_string(),
        normative_reference: "ref".to_string(),
        fixture: DonorFixture {
            donor_harness: "test262".to_string(),
            source: "var x = 1;".to_string(),
            observed_output: "1".to_string(),
        },
        expected_output: "expected".to_string(),
    };
    let json = serde_json::to_string(&vector).expect("serialize");
    let restored: ConformanceMinimizedFailingVector =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(vector, restored);
}

#[test]
fn conformance_minimization_summary_serde_roundtrip() {
    let summary = ConformanceMinimizationSummary {
        strategy: "greedy-delta-debugging".to_string(),
        original_source_lines: 10,
        minimized_source_lines: 3,
        original_expected_lines: 5,
        minimized_expected_lines: 2,
        original_actual_lines: 5,
        minimized_actual_lines: 2,
        preserved_failure_class: true,
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let restored: ConformanceMinimizationSummary =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(summary, restored);
}

#[test]
fn donor_fixture_serde_roundtrip() {
    let fixture = DonorFixture {
        donor_harness: "test262".to_string(),
        source: "var x = 1;".to_string(),
        observed_output: "1\n".to_string(),
    };
    let json = serde_json::to_string(&fixture).expect("serialize");
    let restored: DonorFixture = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(fixture, restored);
}

// ===================================================================
// WaiverReasonCode serde — all variants
// ===================================================================

#[test]
fn waiver_reason_code_serde_all_variants() {
    for code in [
        WaiverReasonCode::HarnessGap,
        WaiverReasonCode::HostHookMissing,
        WaiverReasonCode::IntentionalDivergence,
        WaiverReasonCode::NotYetImplemented,
    ] {
        let json = serde_json::to_string(&code).expect("serialize");
        let restored: WaiverReasonCode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(code, restored);
    }
}

// ===================================================================
// ConformanceFailureClass serde
// ===================================================================

#[test]
fn failure_class_serde_all_variants() {
    for class in [
        ConformanceFailureClass::Breaking,
        ConformanceFailureClass::Behavioral,
        ConformanceFailureClass::Observability,
        ConformanceFailureClass::Performance,
    ] {
        let json = serde_json::to_string(&class).expect("serialize");
        let restored: ConformanceFailureClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(class, restored);
    }
}

// ===================================================================
// ConformanceFailureSeverity serde
// ===================================================================

#[test]
fn failure_severity_serde_all_variants() {
    for sev in [
        ConformanceFailureSeverity::Info,
        ConformanceFailureSeverity::Warning,
        ConformanceFailureSeverity::Error,
        ConformanceFailureSeverity::Critical,
    ] {
        let json = serde_json::to_string(&sev).expect("serialize");
        let restored: ConformanceFailureSeverity =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(sev, restored);
    }
}

// ===================================================================
// ConformanceDeltaKind serde
// ===================================================================

#[test]
fn delta_kind_serde_all_variants() {
    for kind in [
        ConformanceDeltaKind::SchemaFieldAdded,
        ConformanceDeltaKind::SchemaFieldRemoved,
        ConformanceDeltaKind::SchemaFieldModified,
        ConformanceDeltaKind::BehavioralSemanticShift,
        ConformanceDeltaKind::TimingChange,
        ConformanceDeltaKind::ErrorFormatChange,
    ] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let restored: ConformanceDeltaKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(kind, restored);
    }
}

// ===================================================================
// ConformanceMinimizedReproArtifact verify_replay
// ===================================================================

fn build_test_repro_artifact(
    expected_output: &str,
    observed_output: &str,
) -> ConformanceMinimizedReproArtifact {
    let canonical_expected = canonicalize_conformance_output(expected_output);
    let canonical_actual = canonicalize_conformance_output(observed_output);
    let delta_classification = classify_conformance_delta(&canonical_expected, &canonical_actual);
    let failure_class = classify_failure_class(&delta_classification);
    let severity = severity_for_failure_class(failure_class);

    // We need to match the internal digest_hex logic (fnv1a64 → 16-char hex).
    // Since we can't call digest_hex from outside, compute it via the public API
    // by constructing a repro with a known seed and checking the verification_digest.
    // For simplicity, use an empty digest and expect verify_replay to fail.
    ConformanceMinimizedReproArtifact {
        schema_version: ConformanceMinimizedReproArtifact::CURRENT_SCHEMA.to_string(),
        artifact_id: "repro-test".to_string(),
        failure_id: "cf-test".to_string(),
        boundary_surface: "test/test".to_string(),
        failure_class,
        severity,
        version_combination: BTreeMap::new(),
        first_seen_commit: "abc123".to_string(),
        regression_commit: None,
        environment: ConformanceReproEnvironment {
            locale: "C".to_string(),
            timezone: "UTC".to_string(),
            gc_schedule: "deterministic".to_string(),
            rust_toolchain: "stable".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
        },
        replay: ConformanceReplayContract {
            deterministic_seed: 7,
            replay_command: "test".to_string(),
            verification_command: "test --verify".to_string(),
            verification_digest: "wrong_digest".to_string(),
        },
        expected_output: canonical_expected.clone(),
        actual_output: canonical_actual.clone(),
        delta_classification,
        minimization: ConformanceMinimizationSummary {
            strategy: "greedy-delta-debugging".to_string(),
            original_source_lines: 1,
            minimized_source_lines: 1,
            original_expected_lines: 1,
            minimized_expected_lines: 1,
            original_actual_lines: 1,
            minimized_actual_lines: 1,
            preserved_failure_class: true,
        },
        failing_vector: ConformanceMinimizedFailingVector {
            asset_id: "test-asset".to_string(),
            source_donor: "test262".to_string(),
            semantic_domain: "evaluation".to_string(),
            normative_reference: "§1".to_string(),
            fixture: DonorFixture {
                donor_harness: "test262".to_string(),
                source: "var x = 1;".to_string(),
                observed_output: observed_output.to_string(),
            },
            expected_output: expected_output.to_string(),
        },
        evidence_ledger_id: "ledger/test".to_string(),
        linked_run: ConformanceRunLinkage {
            run_id: "run-1".to_string(),
            trace_id: "trace-1".to_string(),
            decision_id: "dec-1".to_string(),
            ci_run_id: None,
        },
        issue_tracker: ConformanceIssueLink {
            tracker: "beads".to_string(),
            issue_id: "bd-1".to_string(),
        },
    }
}

#[test]
fn verify_replay_fails_when_outputs_match() {
    // If expected == actual after canonicalization, verify_replay should fail.
    let artifact = build_test_repro_artifact("hello", "hello");
    let result = artifact.verify_replay();
    assert!(matches!(
        result,
        Err(ConformanceReplayVerificationError::FailureNotReproduced)
    ));
}

#[test]
fn verify_replay_fails_on_wrong_digest() {
    // Expected and actual differ, but digest is wrong.
    let artifact = build_test_repro_artifact("result: true", "result: false");
    let result = artifact.verify_replay();
    assert!(matches!(
        result,
        Err(ConformanceReplayVerificationError::DigestMismatch { .. })
    ));
}

#[test]
fn repro_artifact_serde_roundtrip() {
    let artifact = build_test_repro_artifact("result: true", "result: false");
    let json = serde_json::to_string(&artifact).expect("serialize");
    let restored: ConformanceMinimizedReproArtifact =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, restored);
}

// ===================================================================
// ConformanceWaiverSet::default
// ===================================================================

#[test]
fn conformance_waiver_set_default_is_empty() {
    let set = ConformanceWaiverSet::default();
    assert!(set.waivers.is_empty());
}

// ===================================================================
// ConformanceReproMetadata default values
// ===================================================================

#[test]
fn repro_metadata_default_values() {
    let meta = ConformanceReproMetadata::default();
    assert!(meta.version_combination.contains_key("franken_engine"));
    assert_eq!(meta.first_seen_commit, "unknown");
    assert!(meta.regression_commit.is_none());
    assert!(meta.ci_run_id.is_none());
    assert_eq!(meta.issue_tracker_project, "beads");
    assert!(meta.issue_tracking_bead.is_none());
}

// ===================================================================
// ConformanceRunnerConfig default values
// ===================================================================

#[test]
fn runner_config_default_comprehensive() {
    let cfg = ConformanceRunnerConfig::default();
    assert_eq!(cfg.trace_prefix, "trace-conformance");
    assert_eq!(cfg.policy_id, "policy-conformance-v1");
    assert_eq!(cfg.seed, 7);
    assert_eq!(cfg.locale, "C");
    assert_eq!(cfg.timezone, "UTC");
    assert_eq!(cfg.gc_schedule, "deterministic");
    assert_eq!(cfg.run_date, "1970-01-01");
}

// ===================================================================
// ConformanceAssetManifest::CURRENT_SCHEMA
// ===================================================================

#[test]
fn manifest_current_schema_v1() {
    assert_eq!(
        ConformanceAssetManifest::CURRENT_SCHEMA,
        "franken-engine.conformance-assets.v1"
    );
}

#[test]
fn repro_artifact_current_schema_v1() {
    assert_eq!(
        ConformanceMinimizedReproArtifact::CURRENT_SCHEMA,
        "franken-engine.conformance-min-repro.v1"
    );
}
