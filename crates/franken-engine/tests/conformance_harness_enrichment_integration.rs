#![forbid(unsafe_code)]
//! Enrichment integration tests for `conformance_harness`.
//!
//! Adds JSON field-name stability, exact serde enum values, Display exactness,
//! Debug distinctness, error coverage, config defaults, and classification
//! logic beyond the existing 79 integration tests.

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

use std::collections::BTreeSet;

use frankenengine_engine::conformance_harness::{
    ConformanceCiGateError, ConformanceDeltaKind, ConformanceFailureClass,
    ConformanceFailureSeverity, ConformanceReproMetadata, ConformanceRunSummary,
    ConformanceRunnerConfig, DeterministicRng, WaiverReasonCode, canonicalize_conformance_output,
    classify_conformance_delta, classify_failure_class, severity_for_failure_class,
};

// ===========================================================================
// 1) WaiverReasonCode — serde exact tags
// ===========================================================================

#[test]
fn serde_exact_waiver_reason_code_tags() {
    let codes = [
        WaiverReasonCode::HarnessGap,
        WaiverReasonCode::HostHookMissing,
        WaiverReasonCode::IntentionalDivergence,
        WaiverReasonCode::NotYetImplemented,
    ];
    let expected = [
        "\"harness_gap\"",
        "\"host_hook_missing\"",
        "\"intentional_divergence\"",
        "\"not_yet_implemented\"",
    ];
    for (c, exp) in codes.iter().zip(expected.iter()) {
        let json = serde_json::to_string(c).unwrap();
        assert_eq!(json, *exp, "WaiverReasonCode serde tag mismatch for {c:?}");
    }
}

// ===========================================================================
// 2) ConformanceFailureClass — serde exact tags
// ===========================================================================

#[test]
fn serde_exact_failure_class_tags() {
    let classes = [
        ConformanceFailureClass::Breaking,
        ConformanceFailureClass::Behavioral,
        ConformanceFailureClass::Observability,
        ConformanceFailureClass::Performance,
    ];
    let expected = [
        "\"breaking\"",
        "\"behavioral\"",
        "\"observability\"",
        "\"performance\"",
    ];
    for (c, exp) in classes.iter().zip(expected.iter()) {
        let json = serde_json::to_string(c).unwrap();
        assert_eq!(
            json, *exp,
            "ConformanceFailureClass serde tag mismatch for {c:?}"
        );
    }
}

// ===========================================================================
// 3) ConformanceFailureSeverity — serde exact tags
// ===========================================================================

#[test]
fn serde_exact_failure_severity_tags() {
    let severities = [
        ConformanceFailureSeverity::Info,
        ConformanceFailureSeverity::Warning,
        ConformanceFailureSeverity::Error,
        ConformanceFailureSeverity::Critical,
    ];
    let expected = ["\"info\"", "\"warning\"", "\"error\"", "\"critical\""];
    for (s, exp) in severities.iter().zip(expected.iter()) {
        let json = serde_json::to_string(s).unwrap();
        assert_eq!(
            json, *exp,
            "ConformanceFailureSeverity serde tag mismatch for {s:?}"
        );
    }
}

// ===========================================================================
// 4) ConformanceDeltaKind — serde exact tags
// ===========================================================================

#[test]
fn serde_exact_delta_kind_tags() {
    let kinds = [
        ConformanceDeltaKind::SchemaFieldAdded,
        ConformanceDeltaKind::SchemaFieldRemoved,
        ConformanceDeltaKind::SchemaFieldModified,
        ConformanceDeltaKind::BehavioralSemanticShift,
        ConformanceDeltaKind::TimingChange,
        ConformanceDeltaKind::ErrorFormatChange,
    ];
    let expected = [
        "\"schema_field_added\"",
        "\"schema_field_removed\"",
        "\"schema_field_modified\"",
        "\"behavioral_semantic_shift\"",
        "\"timing_change\"",
        "\"error_format_change\"",
    ];
    for (k, exp) in kinds.iter().zip(expected.iter()) {
        let json = serde_json::to_string(k).unwrap();
        assert_eq!(
            json, *exp,
            "ConformanceDeltaKind serde tag mismatch for {k:?}"
        );
    }
}

// ===========================================================================
// 5) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_waiver_reason_code() {
    let variants = [
        format!("{:?}", WaiverReasonCode::HarnessGap),
        format!("{:?}", WaiverReasonCode::HostHookMissing),
        format!("{:?}", WaiverReasonCode::IntentionalDivergence),
        format!("{:?}", WaiverReasonCode::NotYetImplemented),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

#[test]
fn debug_distinct_failure_class() {
    let variants = [
        format!("{:?}", ConformanceFailureClass::Breaking),
        format!("{:?}", ConformanceFailureClass::Behavioral),
        format!("{:?}", ConformanceFailureClass::Observability),
        format!("{:?}", ConformanceFailureClass::Performance),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

#[test]
fn debug_distinct_failure_severity() {
    let variants = [
        format!("{:?}", ConformanceFailureSeverity::Info),
        format!("{:?}", ConformanceFailureSeverity::Warning),
        format!("{:?}", ConformanceFailureSeverity::Error),
        format!("{:?}", ConformanceFailureSeverity::Critical),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

#[test]
fn debug_distinct_delta_kind() {
    let variants = [
        format!("{:?}", ConformanceDeltaKind::SchemaFieldAdded),
        format!("{:?}", ConformanceDeltaKind::SchemaFieldRemoved),
        format!("{:?}", ConformanceDeltaKind::SchemaFieldModified),
        format!("{:?}", ConformanceDeltaKind::BehavioralSemanticShift),
        format!("{:?}", ConformanceDeltaKind::TimingChange),
        format!("{:?}", ConformanceDeltaKind::ErrorFormatChange),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 6);
}

// ===========================================================================
// 6) ConformanceCiGateError — Display + std::error::Error
// ===========================================================================

#[test]
fn ci_gate_error_display() {
    let e = ConformanceCiGateError {
        failed: 3,
        errored: 1,
    };
    let s = e.to_string();
    assert!(s.contains("3"), "should contain failed count: {s}");
    assert!(s.contains("1"), "should contain errored count: {s}");
}

#[test]
fn ci_gate_error_is_std_error() {
    let e = ConformanceCiGateError {
        failed: 0,
        errored: 0,
    };
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 7) ConformanceRunnerConfig — default
// ===========================================================================

#[test]
fn runner_config_default() {
    let config = ConformanceRunnerConfig::default();
    assert_eq!(config.locale, "C");
    assert_eq!(config.timezone, "UTC");
    assert_eq!(config.gc_schedule, "deterministic");
    assert_eq!(config.seed, 7);
}

// ===========================================================================
// 9) ConformanceReproMetadata — default
// ===========================================================================

#[test]
fn repro_metadata_default() {
    let meta = ConformanceReproMetadata::default();
    assert!(meta.version_combination.contains_key("franken_engine"));
    assert_eq!(meta.first_seen_commit, "unknown");
    assert_eq!(meta.issue_tracker_project, "beads");
}

// ===========================================================================
// 10) DeterministicRng
// ===========================================================================

#[test]
fn deterministic_rng_seeded_produces_values() {
    let mut rng = DeterministicRng::seeded(42);
    let v1 = rng.next_u64();
    let v2 = rng.next_u64();
    assert_ne!(v1, v2);
}

#[test]
fn deterministic_rng_same_seed_same_sequence() {
    let mut rng1 = DeterministicRng::seeded(123);
    let mut rng2 = DeterministicRng::seeded(123);
    for _ in 0..10 {
        assert_eq!(rng1.next_u64(), rng2.next_u64());
    }
}

#[test]
fn deterministic_rng_zero_seed_still_works() {
    let mut rng = DeterministicRng::seeded(0);
    let v = rng.next_u64();
    assert_ne!(v, 0);
}

// ===========================================================================
// 11) classify_conformance_delta
// ===========================================================================

#[test]
fn classify_delta_equal_inputs() {
    let deltas = classify_conformance_delta("hello", "hello");
    assert!(deltas.is_empty());
}

#[test]
fn classify_delta_different_inputs_nonempty() {
    let deltas = classify_conformance_delta("a\nb\nc", "a\nx\nc");
    assert!(!deltas.is_empty());
}

// ===========================================================================
// 12) classify_failure_class
// ===========================================================================

#[test]
fn classify_failure_class_empty_is_behavioral() {
    let class = classify_failure_class(&[]);
    assert_eq!(class, ConformanceFailureClass::Behavioral);
}

// ===========================================================================
// 13) severity_for_failure_class
// ===========================================================================

#[test]
fn severity_mapping() {
    assert_eq!(
        severity_for_failure_class(ConformanceFailureClass::Breaking),
        ConformanceFailureSeverity::Critical
    );
    assert_eq!(
        severity_for_failure_class(ConformanceFailureClass::Behavioral),
        ConformanceFailureSeverity::Error
    );
    assert_eq!(
        severity_for_failure_class(ConformanceFailureClass::Observability),
        ConformanceFailureSeverity::Warning
    );
    assert_eq!(
        severity_for_failure_class(ConformanceFailureClass::Performance),
        ConformanceFailureSeverity::Warning
    );
}

// ===========================================================================
// 14) canonicalize_conformance_output
// ===========================================================================

#[test]
fn canonicalize_normalizes_crlf() {
    let raw = "line1\r\nline2\r\n";
    let canonical = canonicalize_conformance_output(raw);
    assert!(!canonical.contains('\r'));
    assert!(canonical.contains("line1"));
    assert!(canonical.contains("line2"));
}

#[test]
fn canonicalize_skips_empty_lines() {
    let raw = "a\n\n\nb\n";
    let canonical = canonicalize_conformance_output(raw);
    assert!(!canonical.contains("\n\n"));
}

// ===========================================================================
// 15) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_waiver_reason_code() {
    for c in [
        WaiverReasonCode::HarnessGap,
        WaiverReasonCode::HostHookMissing,
        WaiverReasonCode::IntentionalDivergence,
        WaiverReasonCode::NotYetImplemented,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let rt: WaiverReasonCode = serde_json::from_str(&json).unwrap();
        assert_eq!(c, rt);
    }
}

#[test]
fn serde_roundtrip_failure_class() {
    for c in [
        ConformanceFailureClass::Breaking,
        ConformanceFailureClass::Behavioral,
        ConformanceFailureClass::Observability,
        ConformanceFailureClass::Performance,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let rt: ConformanceFailureClass = serde_json::from_str(&json).unwrap();
        assert_eq!(c, rt);
    }
}

#[test]
fn serde_roundtrip_failure_severity() {
    for s in [
        ConformanceFailureSeverity::Info,
        ConformanceFailureSeverity::Warning,
        ConformanceFailureSeverity::Error,
        ConformanceFailureSeverity::Critical,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let rt: ConformanceFailureSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, rt);
    }
}

#[test]
fn serde_roundtrip_delta_kind() {
    for k in [
        ConformanceDeltaKind::SchemaFieldAdded,
        ConformanceDeltaKind::SchemaFieldRemoved,
        ConformanceDeltaKind::SchemaFieldModified,
        ConformanceDeltaKind::BehavioralSemanticShift,
        ConformanceDeltaKind::TimingChange,
        ConformanceDeltaKind::ErrorFormatChange,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let rt: ConformanceDeltaKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, rt);
    }
}

#[test]
fn serde_roundtrip_runner_config() {
    let config = ConformanceRunnerConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let rt: ConformanceRunnerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, rt);
}

#[test]
fn serde_roundtrip_run_summary() {
    let summary = ConformanceRunSummary {
        run_id: "run-1".into(),
        asset_manifest_hash: "hash-1".into(),
        total_assets: 100,
        passed: 90,
        failed: 5,
        waived: 3,
        errored: 2,
        env_fingerprint: "fp".into(),
    };
    let json = serde_json::to_string(&summary).unwrap();
    let rt: ConformanceRunSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, rt);
}

// ===========================================================================
// 16) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_runner_config() {
    let config = ConformanceRunnerConfig::default();
    let v: serde_json::Value = serde_json::to_value(&config).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_prefix",
        "policy_id",
        "seed",
        "locale",
        "timezone",
        "gc_schedule",
        "run_date",
        "repro_metadata",
    ] {
        assert!(
            obj.contains_key(key),
            "ConformanceRunnerConfig missing field: {key}"
        );
    }
}

#[test]
fn json_fields_run_summary() {
    let summary = ConformanceRunSummary {
        run_id: "r".into(),
        asset_manifest_hash: "h".into(),
        total_assets: 0,
        passed: 0,
        failed: 0,
        waived: 0,
        errored: 0,
        env_fingerprint: "f".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&summary).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "run_id",
        "asset_manifest_hash",
        "total_assets",
        "passed",
        "failed",
        "waived",
        "errored",
        "env_fingerprint",
    ] {
        assert!(
            obj.contains_key(key),
            "ConformanceRunSummary missing field: {key}"
        );
    }
}

#[test]
fn json_fields_repro_metadata() {
    let meta = ConformanceReproMetadata::default();
    let v: serde_json::Value = serde_json::to_value(&meta).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "version_combination",
        "first_seen_commit",
        "regression_commit",
        "ci_run_id",
        "issue_tracker_project",
        "issue_tracking_bead",
    ] {
        assert!(
            obj.contains_key(key),
            "ConformanceReproMetadata missing field: {key}"
        );
    }
}

// ===========================================================================
// 10) JSON field-name stability — ConformanceDeltaClassification
// ===========================================================================

use frankenengine_engine::conformance_harness::{
    ConformanceAssetManifest, ConformanceAssetRecord, ConformanceDeltaClassification,
    ConformanceIssueLink, ConformanceLogEvent, ConformanceManifestError,
    ConformanceMinimizationSummary, ConformanceMinimizedFailingVector, ConformanceReplayContract,
    ConformanceReplayVerificationError, ConformanceReproEnvironment, ConformanceRunError,
    ConformanceRunLinkage, ConformanceRunResult, ConformanceWaiver, ConformanceWaiverSet,
    DonorFixture, DonorHarnessAdapter, DonorHarnessApi,
};

#[test]
fn json_fields_delta_classification() {
    let dc = ConformanceDeltaClassification {
        kind: ConformanceDeltaKind::SchemaFieldAdded,
        field: Some("prototype".to_string()),
        expected: Some("undefined".to_string()),
        actual: Some("[object Object]".to_string()),
        detail: "schema field added".to_string(),
    };
    let v: serde_json::Value = serde_json::to_value(&dc).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["kind", "field", "expected", "actual", "detail"] {
        assert!(
            obj.contains_key(key),
            "ConformanceDeltaClassification missing field: {key}"
        );
    }
}

// ===========================================================================
// 11) JSON field-name stability — ConformanceMinimizationSummary
// ===========================================================================

#[test]
fn json_fields_minimization_summary() {
    let ms = ConformanceMinimizationSummary {
        strategy: "ddmin".to_string(),
        original_source_lines: 100,
        minimized_source_lines: 10,
        original_expected_lines: 50,
        minimized_expected_lines: 5,
        original_actual_lines: 50,
        minimized_actual_lines: 5,
        preserved_failure_class: true,
    };
    let v: serde_json::Value = serde_json::to_value(&ms).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "strategy",
        "original_source_lines",
        "minimized_source_lines",
        "original_expected_lines",
        "minimized_expected_lines",
        "original_actual_lines",
        "minimized_actual_lines",
        "preserved_failure_class",
    ] {
        assert!(
            obj.contains_key(key),
            "ConformanceMinimizationSummary missing field: {key}"
        );
    }
}

// ===========================================================================
// 12) Serde roundtrip — ConformanceDeltaClassification
// ===========================================================================

#[test]
fn serde_roundtrip_delta_classification() {
    let dc = ConformanceDeltaClassification {
        kind: ConformanceDeltaKind::SchemaFieldRemoved,
        field: None,
        expected: None,
        actual: None,
        detail: "some detail".to_string(),
    };
    let json = serde_json::to_string(&dc).unwrap();
    let rt: ConformanceDeltaClassification = serde_json::from_str(&json).unwrap();
    assert_eq!(dc, rt);
}

// ===========================================================================
// 13) Serde roundtrip — ConformanceMinimizationSummary
// ===========================================================================

#[test]
fn serde_roundtrip_minimization_summary() {
    let ms = ConformanceMinimizationSummary {
        strategy: "bisect".to_string(),
        original_source_lines: 200,
        minimized_source_lines: 20,
        original_expected_lines: 80,
        minimized_expected_lines: 8,
        original_actual_lines: 80,
        minimized_actual_lines: 8,
        preserved_failure_class: false,
    };
    let json = serde_json::to_string(&ms).unwrap();
    let rt: ConformanceMinimizationSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(ms, rt);
}

// ===========================================================================
// 14) Serde roundtrip — ConformanceWaiver
// ===========================================================================

#[test]
fn serde_roundtrip_conformance_waiver() {
    let w = ConformanceWaiver {
        asset_id: "test262/built-ins/Array.json".to_string(),
        reason_code: WaiverReasonCode::HarnessGap,
        tracking_bead: "bd-123".to_string(),
        expiry_date: "2026-12-31".to_string(),
    };
    let json = serde_json::to_string(&w).unwrap();
    let rt: ConformanceWaiver = serde_json::from_str(&json).unwrap();
    assert_eq!(w, rt);
}

// ===========================================================================
// 15) ConformanceWaiverSet default
// ===========================================================================

#[test]
fn conformance_waiver_set_default_empty() {
    let ws = ConformanceWaiverSet::default();
    assert!(ws.waivers.is_empty());
}

// ===========================================================================
// 16) Serde roundtrip — ConformanceWaiverSet
// ===========================================================================

#[test]
fn serde_roundtrip_conformance_waiver_set() {
    let ws = ConformanceWaiverSet {
        waivers: vec![ConformanceWaiver {
            asset_id: "test.json".to_string(),
            reason_code: WaiverReasonCode::NotYetImplemented,
            tracking_bead: "bd-456".to_string(),
            expiry_date: "2027-01-01".to_string(),
        }],
    };
    let json = serde_json::to_string(&ws).unwrap();
    let rt: ConformanceWaiverSet = serde_json::from_str(&json).unwrap();
    assert_eq!(ws, rt);
}

// ===========================================================================
// 17) ConformanceReplayVerificationError — Display exactness
// ===========================================================================

#[test]
fn replay_verification_error_display_failure_not_reproduced() {
    let e = ConformanceReplayVerificationError::FailureNotReproduced;
    let s = e.to_string();
    assert!(
        s.contains("replay verification failed"),
        "should describe error: {s}"
    );
}

#[test]
fn replay_verification_error_display_class_mismatch() {
    let e = ConformanceReplayVerificationError::FailureClassMismatch {
        expected: ConformanceFailureClass::Breaking,
        actual: ConformanceFailureClass::Behavioral,
    };
    let s = e.to_string();
    assert!(
        s.contains("Breaking") || s.contains("breaking"),
        "should contain expected class: {s}"
    );
}

#[test]
fn replay_verification_error_display_delta_drift() {
    let e = ConformanceReplayVerificationError::DeltaClassificationDrift;
    let s = e.to_string();
    assert!(!s.is_empty());
}

#[test]
fn replay_verification_error_display_digest_mismatch() {
    let e = ConformanceReplayVerificationError::DigestMismatch {
        expected: "abc".to_string(),
        actual: "def".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("abc"), "should contain expected: {s}");
    assert!(s.contains("def"), "should contain actual: {s}");
}

#[test]
fn replay_verification_error_display_all_unique() {
    let variants: Vec<String> = vec![
        ConformanceReplayVerificationError::FailureNotReproduced.to_string(),
        ConformanceReplayVerificationError::FailureClassMismatch {
            expected: ConformanceFailureClass::Breaking,
            actual: ConformanceFailureClass::Behavioral,
        }
        .to_string(),
        ConformanceReplayVerificationError::DeltaClassificationDrift.to_string(),
        ConformanceReplayVerificationError::DigestMismatch {
            expected: "a".into(),
            actual: "b".into(),
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), variants.len());
}

// ===========================================================================
// 18) ConformanceReplayVerificationError — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_replay_verification_error() {
    let variants = [
        format!(
            "{:?}",
            ConformanceReplayVerificationError::FailureNotReproduced
        ),
        format!(
            "{:?}",
            ConformanceReplayVerificationError::FailureClassMismatch {
                expected: ConformanceFailureClass::Performance,
                actual: ConformanceFailureClass::Observability,
            }
        ),
        format!(
            "{:?}",
            ConformanceReplayVerificationError::DeltaClassificationDrift
        ),
        format!(
            "{:?}",
            ConformanceReplayVerificationError::DigestMismatch {
                expected: "exp".into(),
                actual: "act".into(),
            }
        ),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 19) DonorFixture serde roundtrip
// ===========================================================================

#[test]
fn serde_roundtrip_donor_fixture() {
    let df = DonorFixture {
        donor_harness: "test262".to_string(),
        source: "var x = 1;".to_string(),
        observed_output: "1".to_string(),
    };
    let json = serde_json::to_string(&df).unwrap();
    let rt: DonorFixture = serde_json::from_str(&json).unwrap();
    assert_eq!(df, rt);
}

// ===========================================================================
// 20) DonorHarnessAdapter — source adaptation
// ===========================================================================

#[test]
fn donor_harness_adapter_replaces_create_realm() {
    let adapter = DonorHarnessAdapter;
    let adapted = adapter.adapt_source("var r = $262.createRealm();");
    assert!(adapted.contains("__franken_create_realm()"));
    assert!(!adapted.contains("$262.createRealm()"));
}

#[test]
fn donor_harness_adapter_replaces_done() {
    let adapter = DonorHarnessAdapter;
    let adapted = adapter.adapt_source("$DONE();");
    assert!(adapted.contains("__franken_done"));
    assert!(!adapted.contains("$DONE"));
}

#[test]
fn donor_harness_adapter_replaces_print() {
    let adapter = DonorHarnessAdapter;
    let adapted = adapter.adapt_source("print('hello');");
    assert_eq!(adapted, "franken_print('hello');");
}

// ===========================================================================
// 21) JSON field-name stability — ConformanceAssetRecord
// ===========================================================================

#[test]
fn json_fields_conformance_asset_record() {
    let ar = ConformanceAssetRecord {
        asset_id: "test262/Array.json".to_string(),
        source_donor: "test262".to_string(),
        semantic_domain: "built-ins".to_string(),
        normative_reference: "ECMA-262 22.1".to_string(),
        fixture_path: "fixtures/array.js".to_string(),
        fixture_hash: "aabbccdd".to_string(),
        expected_output_path: "expected/array.txt".to_string(),
        expected_output_hash: "11223344".to_string(),
        import_date: "2026-01-01".to_string(),
        category: None,
        source_labels: vec![],
        sink_clearances: vec![],
        flow_path_type: None,
        expected_outcome: None,
        expected_evidence_type: None,
    };
    let v: serde_json::Value = serde_json::to_value(&ar).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "asset_id",
        "source_donor",
        "semantic_domain",
        "normative_reference",
        "fixture_path",
        "fixture_hash",
        "expected_output_path",
        "expected_output_hash",
        "import_date",
    ] {
        assert!(
            obj.contains_key(key),
            "ConformanceAssetRecord missing field: {key}"
        );
    }
}

// ===========================================================================
// 22) Serde roundtrip — ConformanceAssetRecord
// ===========================================================================

#[test]
fn serde_roundtrip_conformance_asset_record() {
    let ar = ConformanceAssetRecord {
        asset_id: "test.json".to_string(),
        source_donor: "donor".to_string(),
        semantic_domain: "dom".to_string(),
        normative_reference: "ref".to_string(),
        fixture_path: "p".to_string(),
        fixture_hash: "h".to_string(),
        expected_output_path: "ep".to_string(),
        expected_output_hash: "eh".to_string(),
        import_date: "2026-02-27".to_string(),
        category: Some("benign".to_string()),
        source_labels: vec!["public".to_string()],
        sink_clearances: vec!["low".to_string()],
        flow_path_type: Some("direct".to_string()),
        expected_outcome: Some("allow".to_string()),
        expected_evidence_type: Some("none".to_string()),
    };
    let json = serde_json::to_string(&ar).unwrap();
    let rt: ConformanceAssetRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(ar, rt);
}

// ===========================================================================
// 23) JSON field-name stability — ConformanceReproEnvironment
// ===========================================================================

#[test]
fn json_fields_repro_environment() {
    let env = ConformanceReproEnvironment {
        locale: "C".to_string(),
        timezone: "UTC".to_string(),
        gc_schedule: "deterministic".to_string(),
        rust_toolchain: "nightly-2026-02-15".to_string(),
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
    };
    let v: serde_json::Value = serde_json::to_value(&env).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "locale",
        "timezone",
        "gc_schedule",
        "rust_toolchain",
        "os",
        "arch",
    ] {
        assert!(
            obj.contains_key(key),
            "ConformanceReproEnvironment missing field: {key}"
        );
    }
}

// ===========================================================================
// 24) Serde roundtrip — ConformanceReproEnvironment
// ===========================================================================

#[test]
fn serde_roundtrip_repro_environment() {
    let env = ConformanceReproEnvironment {
        locale: "C".to_string(),
        timezone: "UTC".to_string(),
        gc_schedule: "deterministic".to_string(),
        rust_toolchain: "nightly".to_string(),
        os: "linux".to_string(),
        arch: "aarch64".to_string(),
    };
    let json = serde_json::to_string(&env).unwrap();
    let rt: ConformanceReproEnvironment = serde_json::from_str(&json).unwrap();
    assert_eq!(env, rt);
}

// ===========================================================================
// 25) JSON field-name stability — ConformanceReplayContract
// ===========================================================================

#[test]
fn json_fields_replay_contract() {
    let rc = ConformanceReplayContract {
        deterministic_seed: 42,
        replay_command: "cargo test".to_string(),
        verification_command: "cargo verify".to_string(),
        verification_digest: "digest123".to_string(),
    };
    let v: serde_json::Value = serde_json::to_value(&rc).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "deterministic_seed",
        "replay_command",
        "verification_command",
        "verification_digest",
    ] {
        assert!(
            obj.contains_key(key),
            "ConformanceReplayContract missing field: {key}"
        );
    }
}

// ===========================================================================
// 26) Serde roundtrip — ConformanceReplayContract
// ===========================================================================

#[test]
fn serde_roundtrip_replay_contract() {
    let rc = ConformanceReplayContract {
        deterministic_seed: 99,
        replay_command: "run".to_string(),
        verification_command: "verify".to_string(),
        verification_digest: "sha256:abc".to_string(),
    };
    let json = serde_json::to_string(&rc).unwrap();
    let rt: ConformanceReplayContract = serde_json::from_str(&json).unwrap();
    assert_eq!(rc, rt);
}

// ===========================================================================
// 27) JSON field-name stability — ConformanceIssueLink
// ===========================================================================

#[test]
fn json_fields_issue_link() {
    let il = ConformanceIssueLink {
        tracker: "github".to_string(),
        issue_id: "FRX-123".to_string(),
    };
    let v: serde_json::Value = serde_json::to_value(&il).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["tracker", "issue_id"] {
        assert!(
            obj.contains_key(key),
            "ConformanceIssueLink missing field: {key}"
        );
    }
}

// ===========================================================================
// 28) ConformanceRunResult — JSON fields and serde
// ===========================================================================

#[test]
fn json_fields_conformance_run_result() {
    let rr = ConformanceRunResult {
        run_id: "r1".into(),
        asset_manifest_hash: "h".into(),
        logs: vec![],
        summary: ConformanceRunSummary {
            run_id: "r1".into(),
            asset_manifest_hash: "h".into(),
            total_assets: 10,
            passed: 8,
            failed: 1,
            waived: 1,
            errored: 0,
            env_fingerprint: "f".into(),
        },
        minimized_repros: vec![],
    };
    let v: serde_json::Value = serde_json::to_value(&rr).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "run_id",
        "asset_manifest_hash",
        "logs",
        "summary",
        "minimized_repros",
    ] {
        assert!(
            obj.contains_key(key),
            "ConformanceRunResult missing field: {key}"
        );
    }
}

#[test]
fn serde_roundtrip_conformance_run_result() {
    let rr = ConformanceRunResult {
        run_id: "r-rt".into(),
        asset_manifest_hash: "h-rt".into(),
        logs: vec![],
        summary: ConformanceRunSummary {
            run_id: "r-rt".into(),
            asset_manifest_hash: "h-rt".into(),
            total_assets: 5,
            passed: 4,
            failed: 1,
            waived: 0,
            errored: 0,
            env_fingerprint: "f-rt".into(),
        },
        minimized_repros: vec![],
    };
    let json = serde_json::to_string(&rr).unwrap();
    let rt: ConformanceRunResult = serde_json::from_str(&json).unwrap();
    assert_eq!(rr, rt);
}

// ===========================================================================
// 29) ConformanceManifestError — Display all variants
// ===========================================================================

#[test]
fn manifest_error_display_unsupported_schema() {
    let e = ConformanceManifestError::UnsupportedSchema {
        expected: "v1".to_string(),
        actual: "v2".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("v1"));
    assert!(s.contains("v2"));
    assert!(s.contains("unsupported"));
}

#[test]
fn manifest_error_display_empty_asset_set() {
    let e = ConformanceManifestError::EmptyAssetSet;
    let s = e.to_string();
    assert!(s.contains("no assets"));
}

#[test]
fn manifest_error_display_manifest_has_no_parent() {
    let e = ConformanceManifestError::ManifestHasNoParent;
    let s = e.to_string();
    assert!(s.contains("parent"));
}

#[test]
fn manifest_error_display_missing_field() {
    let e = ConformanceManifestError::MissingField("asset_id");
    let s = e.to_string();
    assert!(s.contains("asset_id"));
    assert!(s.contains("missing"));
}

#[test]
fn manifest_error_display_invalid_field_value() {
    let e = ConformanceManifestError::InvalidFieldValue {
        field: "category",
        value: "unknown_cat".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("category"));
    assert!(s.contains("unknown_cat"));
}

#[test]
fn manifest_error_display_invalid_ifc_expectation() {
    let e = ConformanceManifestError::InvalidIfcExpectation {
        asset_id: "test-asset".to_string(),
        category: "benign".to_string(),
        expected_outcome: "block".to_string(),
        expected_evidence_type: "flow_violation".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("test-asset"));
    assert!(s.contains("benign"));
}

#[test]
fn manifest_error_display_fixture_hash_mismatch() {
    let e = ConformanceManifestError::FixtureHashMismatch {
        asset_id: "asset-1".to_string(),
        expected: "aabb".to_string(),
        actual: "ccdd".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("asset-1"));
    assert!(s.contains("aabb"));
    assert!(s.contains("ccdd"));
}

#[test]
fn manifest_error_display_expected_output_hash_mismatch() {
    let e = ConformanceManifestError::ExpectedOutputHashMismatch {
        asset_id: "asset-2".to_string(),
        expected: "1122".to_string(),
        actual: "3344".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("asset-2"));
    assert!(s.contains("1122"));
}

#[test]
fn manifest_error_display_all_unique() {
    let errors: Vec<String> = vec![
        ConformanceManifestError::UnsupportedSchema {
            expected: "a".into(),
            actual: "b".into(),
        }
        .to_string(),
        ConformanceManifestError::EmptyAssetSet.to_string(),
        ConformanceManifestError::ManifestHasNoParent.to_string(),
        ConformanceManifestError::MissingField("f").to_string(),
        ConformanceManifestError::InvalidFieldValue {
            field: "x",
            value: "y".into(),
        }
        .to_string(),
        ConformanceManifestError::InvalidIfcExpectation {
            asset_id: "a".into(),
            category: "b".into(),
            expected_outcome: "c".into(),
            expected_evidence_type: "d".into(),
        }
        .to_string(),
        ConformanceManifestError::FixtureHashMismatch {
            asset_id: "a".into(),
            expected: "e".into(),
            actual: "f".into(),
        }
        .to_string(),
        ConformanceManifestError::ExpectedOutputHashMismatch {
            asset_id: "a".into(),
            expected: "g".into(),
            actual: "h".into(),
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = errors.iter().collect();
    assert_eq!(unique.len(), 8);
}

#[test]
fn manifest_error_is_std_error() {
    let e = ConformanceManifestError::EmptyAssetSet;
    let err: &dyn std::error::Error = &e;
    assert!(!err.to_string().is_empty());
    assert!(err.source().is_none());
}

// ===========================================================================
// 30) ConformanceRunError — Display all variants
// ===========================================================================

#[test]
fn run_error_display_invalid_config() {
    let e = ConformanceRunError::InvalidConfig("bad seed".to_string());
    let s = e.to_string();
    assert!(s.contains("bad seed"));
    assert!(s.contains("invalid"));
}

#[test]
fn run_error_display_repro_invariant() {
    let e = ConformanceRunError::ReproInvariant {
        asset_id: "asset-r".to_string(),
        detail: "digest changed".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("asset-r"));
    assert!(s.contains("digest changed"));
}

#[test]
fn run_error_is_std_error() {
    let e = ConformanceRunError::InvalidConfig("test".to_string());
    let err: &dyn std::error::Error = &e;
    assert!(!err.to_string().is_empty());
    assert!(err.source().is_none());
}

// ===========================================================================
// 31) ConformanceRunLinkage — serde
// ===========================================================================

#[test]
fn serde_roundtrip_run_linkage() {
    let rl = ConformanceRunLinkage {
        run_id: "run-1".into(),
        trace_id: "trace-1".into(),
        decision_id: "dec-1".into(),
        ci_run_id: Some("ci-42".into()),
    };
    let json = serde_json::to_string(&rl).unwrap();
    let rt: ConformanceRunLinkage = serde_json::from_str(&json).unwrap();
    assert_eq!(rl, rt);
}

#[test]
fn serde_roundtrip_run_linkage_no_ci() {
    let rl = ConformanceRunLinkage {
        run_id: "run-2".into(),
        trace_id: "trace-2".into(),
        decision_id: "dec-2".into(),
        ci_run_id: None,
    };
    let json = serde_json::to_string(&rl).unwrap();
    let rt: ConformanceRunLinkage = serde_json::from_str(&json).unwrap();
    assert_eq!(rl, rt);
}

// ===========================================================================
// 32) ConformanceMinimizedFailingVector — serde
// ===========================================================================

#[test]
fn serde_roundtrip_minimized_failing_vector() {
    let v = ConformanceMinimizedFailingVector {
        asset_id: "test262/Array.json".into(),
        source_donor: "test262".into(),
        semantic_domain: "built-ins".into(),
        normative_reference: "ECMA-262 22.1".into(),
        fixture: DonorFixture {
            donor_harness: "test262".into(),
            source: "var x = [1,2,3];".into(),
            observed_output: "[1,2,3]".into(),
        },
        expected_output: "1,2,3".into(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let rt: ConformanceMinimizedFailingVector = serde_json::from_str(&json).unwrap();
    assert_eq!(v, rt);
}

// ===========================================================================
// 33) ConformanceLogEvent — serde
// ===========================================================================

#[test]
fn serde_roundtrip_log_event() {
    let event = ConformanceLogEvent {
        trace_id: "t-1".into(),
        decision_id: "d-1".into(),
        policy_id: "p-1".into(),
        component: "conformance_harness".into(),
        event: "asset_run".into(),
        outcome: "pass".into(),
        error_code: None,
        asset_id: "asset-1".into(),
        workload_id: "wl-1".into(),
        semantic_domain: "built-ins".into(),
        category: None,
        source_labels: vec![],
        sink_clearances: vec![],
        flow_path_type: None,
        expected_outcome: None,
        actual_outcome: None,
        evidence_type: None,
        evidence_id: None,
        duration_us: 1234,
        error_detail: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let rt: ConformanceLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, rt);
}

#[test]
fn serde_roundtrip_log_event_with_ifc_fields() {
    let event = ConformanceLogEvent {
        trace_id: "t-2".into(),
        decision_id: "d-2".into(),
        policy_id: "p-2".into(),
        component: "conformance_harness".into(),
        event: "ifc_check".into(),
        outcome: "block".into(),
        error_code: Some("IFC-VIOLATION".into()),
        asset_id: "ifc-asset-1".into(),
        workload_id: "wl-2".into(),
        semantic_domain: "ifc_corpus/exfil".into(),
        category: Some("exfil".into()),
        source_labels: vec!["credential".into()],
        sink_clearances: vec!["network_egress".into()],
        flow_path_type: Some("direct".into()),
        expected_outcome: Some("block".into()),
        actual_outcome: Some("block".into()),
        evidence_type: Some("flow_violation".into()),
        evidence_id: Some("ev-123".into()),
        duration_us: 5678,
        error_detail: Some("data flow blocked".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let rt: ConformanceLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, rt);
}

// ===========================================================================
// 34) ConformanceAssetManifest::CURRENT_SCHEMA
// ===========================================================================

#[test]
fn asset_manifest_current_schema_non_empty() {
    assert!(!ConformanceAssetManifest::CURRENT_SCHEMA.is_empty());
    assert!(ConformanceAssetManifest::CURRENT_SCHEMA.starts_with("franken-engine."));
}

// ===========================================================================
// 35) DeterministicRng — serde roundtrip
// ===========================================================================

#[test]
fn serde_roundtrip_deterministic_rng() {
    let rng = DeterministicRng::seeded(42);
    let json = serde_json::to_string(&rng).unwrap();
    let rt: DeterministicRng = serde_json::from_str(&json).unwrap();
    assert_eq!(rng, rt);
}

// ===========================================================================
// 36) Copy semantics for small enums
// ===========================================================================

#[test]
fn copy_semantics_waiver_reason_code() {
    let a = WaiverReasonCode::HarnessGap;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn copy_semantics_failure_class() {
    let a = ConformanceFailureClass::Breaking;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn copy_semantics_failure_severity() {
    let a = ConformanceFailureSeverity::Critical;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn copy_semantics_delta_kind() {
    let a = ConformanceDeltaKind::TimingChange;
    let b = a;
    assert_eq!(a, b);
}

// ===========================================================================
// 37) Clone independence for struct types
// ===========================================================================

#[test]
fn clone_independence_conformance_waiver() {
    let original = ConformanceWaiver {
        asset_id: "test.json".into(),
        reason_code: WaiverReasonCode::HarnessGap,
        tracking_bead: "bd-1".into(),
        expiry_date: "2027-01-01".into(),
    };
    let mut cloned = original.clone();
    cloned.asset_id = "modified.json".into();
    assert_eq!(original.asset_id, "test.json");
    assert_eq!(cloned.asset_id, "modified.json");
}

#[test]
fn clone_independence_conformance_run_summary() {
    let original = ConformanceRunSummary {
        run_id: "r1".into(),
        asset_manifest_hash: "h".into(),
        total_assets: 10,
        passed: 8,
        failed: 1,
        waived: 1,
        errored: 0,
        env_fingerprint: "fp".into(),
    };
    let mut cloned = original.clone();
    cloned.passed = 99;
    assert_eq!(original.passed, 8);
    assert_eq!(cloned.passed, 99);
}

#[test]
fn clone_independence_donor_fixture() {
    let original = DonorFixture {
        donor_harness: "test262".into(),
        source: "var x = 1;".into(),
        observed_output: "1".into(),
    };
    let mut cloned = original.clone();
    cloned.source = "modified".into();
    assert_eq!(original.source, "var x = 1;");
    assert_eq!(cloned.source, "modified");
}

// ===========================================================================
// 38) ConformanceRunResult enforce_ci_gate
// ===========================================================================

#[test]
fn enforce_ci_gate_passes_on_zero_failures() {
    let rr = ConformanceRunResult {
        run_id: "r".into(),
        asset_manifest_hash: "h".into(),
        logs: vec![],
        summary: ConformanceRunSummary {
            run_id: "r".into(),
            asset_manifest_hash: "h".into(),
            total_assets: 10,
            passed: 10,
            failed: 0,
            waived: 0,
            errored: 0,
            env_fingerprint: "f".into(),
        },
        minimized_repros: vec![],
    };
    assert!(rr.enforce_ci_gate().is_ok());
}

#[test]
fn enforce_ci_gate_fails_on_failures() {
    let rr = ConformanceRunResult {
        run_id: "r".into(),
        asset_manifest_hash: "h".into(),
        logs: vec![],
        summary: ConformanceRunSummary {
            run_id: "r".into(),
            asset_manifest_hash: "h".into(),
            total_assets: 10,
            passed: 8,
            failed: 2,
            waived: 0,
            errored: 0,
            env_fingerprint: "f".into(),
        },
        minimized_repros: vec![],
    };
    let err = rr.enforce_ci_gate().unwrap_err();
    assert_eq!(err.failed, 2);
    assert_eq!(err.errored, 0);
}

#[test]
fn enforce_ci_gate_fails_on_errors() {
    let rr = ConformanceRunResult {
        run_id: "r".into(),
        asset_manifest_hash: "h".into(),
        logs: vec![],
        summary: ConformanceRunSummary {
            run_id: "r".into(),
            asset_manifest_hash: "h".into(),
            total_assets: 10,
            passed: 9,
            failed: 0,
            waived: 0,
            errored: 1,
            env_fingerprint: "f".into(),
        },
        minimized_repros: vec![],
    };
    let err = rr.enforce_ci_gate().unwrap_err();
    assert_eq!(err.errored, 1);
}
