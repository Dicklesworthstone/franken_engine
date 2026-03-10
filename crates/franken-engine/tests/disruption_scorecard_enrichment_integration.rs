#![forbid(unsafe_code)]
//! Enrichment integration tests for `disruption_scorecard`.
//!
//! Adds Display exactness, Debug distinctness, serde exact tags,
//! JSON field-name stability, serde roundtrips, config defaults,
//! factory functions, and edge-case validation beyond the existing
//! 31 integration tests.

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

use frankenengine_engine::disruption_scorecard::{
    DimensionThreshold, DisruptionDimension, EvidenceInput, SCORECARD_COMPONENT,
    SCORECARD_SCHEMA_VERSION, ScorecardError, ScorecardHistory, ScorecardOutcome, ScorecardResult,
    ScorecardSchema, compute_scorecard, generate_log_entries, passes_release_gate,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// helpers
// ===========================================================================

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(5)
}

fn all_passing_evidence() -> Vec<EvidenceInput> {
    vec![
        EvidenceInput {
            dimension: DisruptionDimension::PerformanceDelta,
            raw_score_millionths: 200_000,
            source_beads: vec!["bd-1".into()],
            evidence_hash: ContentHash::compute(b"perf"),
        },
        EvidenceInput {
            dimension: DisruptionDimension::SecurityDelta,
            raw_score_millionths: 800_000,
            source_beads: vec!["bd-2".into()],
            evidence_hash: ContentHash::compute(b"sec"),
        },
        EvidenceInput {
            dimension: DisruptionDimension::AutonomyDelta,
            raw_score_millionths: 900_000,
            source_beads: vec!["bd-3".into()],
            evidence_hash: ContentHash::compute(b"auto"),
        },
    ]
}

// ===========================================================================
// 1) Constants — exact values
// ===========================================================================

#[test]
fn scorecard_component_exact() {
    assert_eq!(SCORECARD_COMPONENT, "disruption_scorecard");
}

#[test]
fn scorecard_schema_version_exact() {
    assert_eq!(
        SCORECARD_SCHEMA_VERSION,
        "franken-engine.disruption-scorecard.v1"
    );
}

// ===========================================================================
// 2) DisruptionDimension — Display exact values
// ===========================================================================

#[test]
fn dimension_display_performance_delta() {
    assert_eq!(
        DisruptionDimension::PerformanceDelta.to_string(),
        "performance_delta"
    );
}

#[test]
fn dimension_display_security_delta() {
    assert_eq!(
        DisruptionDimension::SecurityDelta.to_string(),
        "security_delta"
    );
}

#[test]
fn dimension_display_autonomy_delta() {
    assert_eq!(
        DisruptionDimension::AutonomyDelta.to_string(),
        "autonomy_delta"
    );
}

// ===========================================================================
// 3) DisruptionDimension::all — returns 3
// ===========================================================================

#[test]
fn dimension_all_has_three() {
    assert_eq!(DisruptionDimension::all().len(), 3);
}

#[test]
fn dimension_all_contains_all_variants() {
    let all = DisruptionDimension::all();
    assert!(all.contains(&DisruptionDimension::PerformanceDelta));
    assert!(all.contains(&DisruptionDimension::SecurityDelta));
    assert!(all.contains(&DisruptionDimension::AutonomyDelta));
}

// ===========================================================================
// 4) DisruptionDimension — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_disruption_dimension() {
    let variants = [
        format!("{:?}", DisruptionDimension::PerformanceDelta),
        format!("{:?}", DisruptionDimension::SecurityDelta),
        format!("{:?}", DisruptionDimension::AutonomyDelta),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 5) DisruptionDimension — serde roundtrip
// ===========================================================================

#[test]
fn serde_roundtrip_disruption_dimension_all() {
    for d in DisruptionDimension::all() {
        let json = serde_json::to_string(d).unwrap();
        let rt: DisruptionDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, rt);
    }
}

// ===========================================================================
// 6) ScorecardOutcome — Display exact values
// ===========================================================================

#[test]
fn scorecard_outcome_display_pass() {
    assert_eq!(ScorecardOutcome::Pass.to_string(), "pass");
}

#[test]
fn scorecard_outcome_display_fail() {
    assert_eq!(ScorecardOutcome::Fail.to_string(), "fail");
}

// ===========================================================================
// 7) ScorecardOutcome — is_pass
// ===========================================================================

#[test]
fn scorecard_outcome_is_pass_true() {
    assert!(ScorecardOutcome::Pass.is_pass());
}

#[test]
fn scorecard_outcome_is_pass_false() {
    assert!(!ScorecardOutcome::Fail.is_pass());
}

// ===========================================================================
// 8) ScorecardOutcome — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_scorecard_outcome() {
    let variants = [
        format!("{:?}", ScorecardOutcome::Pass),
        format!("{:?}", ScorecardOutcome::Fail),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 2);
}

// ===========================================================================
// 9) ScorecardError — Display exact values
// ===========================================================================

#[test]
fn scorecard_error_display_missing_dimension() {
    let e = ScorecardError::MissingDimension {
        dimension: "perf".into(),
    };
    assert_eq!(e.to_string(), "missing dimension in schema: perf");
}

#[test]
fn scorecard_error_display_invalid_threshold() {
    let e = ScorecardError::InvalidThreshold {
        dimension: "sec".into(),
        detail: "floor > target".into(),
    };
    let s = e.to_string();
    assert!(s.contains("sec"), "{s}");
    assert!(s.contains("floor > target"), "{s}");
}

#[test]
fn scorecard_error_display_missing_evidence() {
    let e = ScorecardError::MissingEvidence {
        dimension: "auto".into(),
    };
    let s = e.to_string();
    assert!(s.contains("auto"), "{s}");
}

#[test]
fn scorecard_error_display_empty_evidence_bundle() {
    let e = ScorecardError::EmptyEvidenceBundle;
    assert_eq!(e.to_string(), "evidence bundle is empty");
}

#[test]
fn scorecard_error_display_schema_validation_failed() {
    let e = ScorecardError::SchemaValidationFailed {
        detail: "bad".into(),
    };
    let s = e.to_string();
    assert!(s.contains("bad"), "{s}");
}

// ===========================================================================
// 10) ScorecardError — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_scorecard_error() {
    let variants = [
        format!(
            "{:?}",
            ScorecardError::MissingDimension {
                dimension: "a".into()
            }
        ),
        format!(
            "{:?}",
            ScorecardError::InvalidThreshold {
                dimension: "b".into(),
                detail: "c".into()
            }
        ),
        format!(
            "{:?}",
            ScorecardError::MissingEvidence {
                dimension: "d".into()
            }
        ),
        format!("{:?}", ScorecardError::EmptyEvidenceBundle),
        format!(
            "{:?}",
            ScorecardError::SchemaValidationFailed { detail: "e".into() }
        ),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 5);
}

// ===========================================================================
// 11) ScorecardError — serde roundtrip
// ===========================================================================

#[test]
fn serde_roundtrip_scorecard_error_all() {
    let errors = [
        ScorecardError::MissingDimension {
            dimension: "x".into(),
        },
        ScorecardError::InvalidThreshold {
            dimension: "y".into(),
            detail: "z".into(),
        },
        ScorecardError::MissingEvidence {
            dimension: "w".into(),
        },
        ScorecardError::EmptyEvidenceBundle,
        ScorecardError::SchemaValidationFailed { detail: "v".into() },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let rt: ScorecardError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, rt);
    }
}

// ===========================================================================
// 12) ScorecardSchema::default_schema — exact values
// ===========================================================================

#[test]
fn default_schema_version() {
    let s = ScorecardSchema::default_schema();
    assert_eq!(s.version, SCORECARD_SCHEMA_VERSION);
}

#[test]
fn default_schema_has_three_thresholds() {
    let s = ScorecardSchema::default_schema();
    assert_eq!(s.thresholds.len(), 3);
}

#[test]
fn default_schema_performance_delta_floor_zero() {
    let s = ScorecardSchema::default_schema();
    let t = &s.thresholds["performance_delta"];
    assert_eq!(t.floor_millionths, 0);
}

#[test]
fn default_schema_performance_delta_target() {
    let s = ScorecardSchema::default_schema();
    let t = &s.thresholds["performance_delta"];
    assert_eq!(t.target_millionths, 100_000);
}

#[test]
fn default_schema_security_delta_floor() {
    let s = ScorecardSchema::default_schema();
    let t = &s.thresholds["security_delta"];
    assert_eq!(t.floor_millionths, 500_000);
}

#[test]
fn default_schema_security_delta_target() {
    let s = ScorecardSchema::default_schema();
    let t = &s.thresholds["security_delta"];
    assert_eq!(t.target_millionths, 800_000);
}

#[test]
fn default_schema_autonomy_delta_floor() {
    let s = ScorecardSchema::default_schema();
    let t = &s.thresholds["autonomy_delta"];
    assert_eq!(t.floor_millionths, 600_000);
}

#[test]
fn default_schema_autonomy_delta_target() {
    let s = ScorecardSchema::default_schema();
    let t = &s.thresholds["autonomy_delta"];
    assert_eq!(t.target_millionths, 900_000);
}

#[test]
fn default_schema_has_evidence_sources() {
    let s = ScorecardSchema::default_schema();
    assert!(!s.evidence_sources.is_empty());
}

#[test]
fn default_schema_validates() {
    let s = ScorecardSchema::default_schema();
    assert!(s.validate().is_ok());
}

// ===========================================================================
// 13) DimensionThreshold — meets_floor / meets_target / is_valid
// ===========================================================================

#[test]
fn threshold_meets_floor_exact_boundary() {
    let t = DimensionThreshold {
        dimension: DisruptionDimension::SecurityDelta,
        floor_millionths: 500_000,
        target_millionths: 800_000,
        description: "d".into(),
    };
    assert!(t.meets_floor(500_000));
    assert!(!t.meets_floor(499_999));
}

#[test]
fn threshold_meets_target_exact_boundary() {
    let t = DimensionThreshold {
        dimension: DisruptionDimension::SecurityDelta,
        floor_millionths: 500_000,
        target_millionths: 800_000,
        description: "d".into(),
    };
    assert!(t.meets_target(800_000));
    assert!(!t.meets_target(799_999));
}

#[test]
fn threshold_is_valid_when_floor_le_target() {
    let t = DimensionThreshold {
        dimension: DisruptionDimension::PerformanceDelta,
        floor_millionths: 100,
        target_millionths: 200,
        description: "d".into(),
    };
    assert!(t.is_valid());
}

#[test]
fn threshold_is_valid_when_equal() {
    let t = DimensionThreshold {
        dimension: DisruptionDimension::PerformanceDelta,
        floor_millionths: 100,
        target_millionths: 100,
        description: "d".into(),
    };
    assert!(t.is_valid());
}

// ===========================================================================
// 14) JSON field-name stability — DimensionThreshold
// ===========================================================================

#[test]
fn json_fields_dimension_threshold() {
    let t = DimensionThreshold {
        dimension: DisruptionDimension::SecurityDelta,
        floor_millionths: 500_000,
        target_millionths: 800_000,
        description: "d".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&t).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "dimension",
        "floor_millionths",
        "target_millionths",
        "description",
    ] {
        assert!(
            obj.contains_key(key),
            "DimensionThreshold missing field: {key}"
        );
    }
}

// ===========================================================================
// 15) JSON field-name stability — EvidenceInput
// ===========================================================================

#[test]
fn json_fields_evidence_input() {
    let ei = EvidenceInput {
        dimension: DisruptionDimension::PerformanceDelta,
        raw_score_millionths: 100_000,
        source_beads: vec!["bd-1".into()],
        evidence_hash: ContentHash::compute(b"test"),
    };
    let v: serde_json::Value = serde_json::to_value(&ei).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "dimension",
        "raw_score_millionths",
        "source_beads",
        "evidence_hash",
    ] {
        assert!(obj.contains_key(key), "EvidenceInput missing field: {key}");
    }
}

// ===========================================================================
// 16) JSON field-name stability — ScorecardResult
// ===========================================================================

#[test]
fn json_fields_scorecard_result() {
    let schema = ScorecardSchema::default_schema();
    let evidence = all_passing_evidence();
    let result = compute_scorecard(&schema, &evidence, test_epoch(), "test".into()).unwrap();
    let v: serde_json::Value = serde_json::to_value(&result).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "schema_version",
        "dimension_scores",
        "outcome",
        "targets_met",
        "dimensions_evaluated",
        "epoch",
        "evidence_bundle_hash",
        "result_hash",
        "environment_fingerprint",
    ] {
        assert!(
            obj.contains_key(key),
            "ScorecardResult missing field: {key}"
        );
    }
}

// ===========================================================================
// 17) JSON field-name stability — ScorecardLogEntry
// ===========================================================================

#[test]
fn json_fields_scorecard_log_entry() {
    let schema = ScorecardSchema::default_schema();
    let evidence = all_passing_evidence();
    let result = compute_scorecard(&schema, &evidence, test_epoch(), "test".into()).unwrap();
    let logs = generate_log_entries("trace-1", &result);
    assert!(!logs.is_empty());
    let v: serde_json::Value = serde_json::to_value(&logs[0]).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "scorecard_version",
        "dimension",
        "raw_score_millionths",
        "threshold_floor_millionths",
        "threshold_target_millionths",
        "pass",
        "evidence_refs",
    ] {
        assert!(
            obj.contains_key(key),
            "ScorecardLogEntry missing field: {key}"
        );
    }
}

// ===========================================================================
// 18) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_dimension_threshold() {
    let t = DimensionThreshold {
        dimension: DisruptionDimension::AutonomyDelta,
        floor_millionths: 600_000,
        target_millionths: 900_000,
        description: "autonomy floor".into(),
    };
    let json = serde_json::to_string(&t).unwrap();
    let rt: DimensionThreshold = serde_json::from_str(&json).unwrap();
    assert_eq!(t, rt);
}

#[test]
fn serde_roundtrip_evidence_input() {
    let ei = EvidenceInput {
        dimension: DisruptionDimension::SecurityDelta,
        raw_score_millionths: 750_000,
        source_beads: vec!["bd-x".into()],
        evidence_hash: ContentHash::compute(b"evidence"),
    };
    let json = serde_json::to_string(&ei).unwrap();
    let rt: EvidenceInput = serde_json::from_str(&json).unwrap();
    assert_eq!(ei, rt);
}

#[test]
fn serde_roundtrip_scorecard_schema() {
    let s = ScorecardSchema::default_schema();
    let json = serde_json::to_string(&s).unwrap();
    let rt: ScorecardSchema = serde_json::from_str(&json).unwrap();
    assert_eq!(s, rt);
}

#[test]
fn serde_roundtrip_scorecard_result() {
    let schema = ScorecardSchema::default_schema();
    let evidence = all_passing_evidence();
    let result = compute_scorecard(&schema, &evidence, test_epoch(), "test".into()).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let rt: ScorecardResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, rt);
}

// ===========================================================================
// 19) compute_scorecard — empty evidence fails
// ===========================================================================

#[test]
fn compute_scorecard_empty_evidence_fails() {
    let schema = ScorecardSchema::default_schema();
    let err = compute_scorecard(&schema, &[], test_epoch(), "test".into()).unwrap_err();
    assert!(matches!(err, ScorecardError::EmptyEvidenceBundle));
}

// ===========================================================================
// 20) compute_scorecard — all passing
// ===========================================================================

#[test]
fn compute_scorecard_all_passing() {
    let schema = ScorecardSchema::default_schema();
    let evidence = all_passing_evidence();
    let result = compute_scorecard(&schema, &evidence, test_epoch(), "test".into()).unwrap();
    assert!(result.outcome.is_pass());
    assert_eq!(result.dimensions_evaluated, 3);
}

// ===========================================================================
// 21) passes_release_gate
// ===========================================================================

#[test]
fn passes_release_gate_on_pass() {
    let schema = ScorecardSchema::default_schema();
    let evidence = all_passing_evidence();
    let result = compute_scorecard(&schema, &evidence, test_epoch(), "test".into()).unwrap();
    assert!(passes_release_gate(&result));
}

// ===========================================================================
// 22) generate_log_entries — one per dimension
// ===========================================================================

#[test]
fn generate_log_entries_three_for_three_dimensions() {
    let schema = ScorecardSchema::default_schema();
    let evidence = all_passing_evidence();
    let result = compute_scorecard(&schema, &evidence, test_epoch(), "test".into()).unwrap();
    let logs = generate_log_entries("trace-1", &result);
    assert_eq!(logs.len(), 3);
}

// ===========================================================================
// 23) ScorecardHistory — initial state
// ===========================================================================

#[test]
fn scorecard_history_initial_empty() {
    let h = ScorecardHistory::new();
    assert!(h.is_empty());
    assert_eq!(h.len(), 0);
    assert!(h.latest().is_none());
    assert!(!h.has_regression());
}

// ===========================================================================
// 24) ScorecardHistory — default is empty
// ===========================================================================

#[test]
fn scorecard_history_default_is_empty() {
    let h = ScorecardHistory::default();
    assert!(h.is_empty());
}

// ===========================================================================
// 25) compute_scorecard — deterministic hash
// ===========================================================================

#[test]
fn compute_scorecard_deterministic_result_hash() {
    let schema = ScorecardSchema::default_schema();
    let evidence = all_passing_evidence();
    let r1 = compute_scorecard(&schema, &evidence, test_epoch(), "test".into()).unwrap();
    let r2 = compute_scorecard(&schema, &evidence, test_epoch(), "test".into()).unwrap();
    assert_eq!(r1.result_hash, r2.result_hash);
}
