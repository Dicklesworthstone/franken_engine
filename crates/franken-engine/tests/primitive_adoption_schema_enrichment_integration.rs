#![forbid(unsafe_code)]

//! Enrichment integration tests for the primitive_adoption_schema module.

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

use frankenengine_engine::primitive_adoption_schema::{
    EvRelevanceRiskScore, FallbackBudget, PrimitiveAdoptionRecord,
    PrimitiveAdoptionValidationError, PrimitiveTier, ReuseDecision, ReuseScan,
    VerificationChecklist,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_verification() -> VerificationChecklist {
    VerificationChecklist {
        checklist_version: "v1.0".to_string(),
        primary_paper_verified: true,
        independent_replication_completed: true,
        verification_notes: "Verified against reference impl".to_string(),
    }
}

fn make_score() -> EvRelevanceRiskScore {
    EvRelevanceRiskScore {
        ev_millionths: 750_000,
        relevance_millionths: 800_000,
        risk_millionths: 200_000,
    }
}

fn make_fallback() -> FallbackBudget {
    FallbackBudget {
        trigger: "latency_exceeded".to_string(),
        deterministic_mode: "replay_safe".to_string(),
        max_retry_count: 3,
        time_budget_ms: 5000,
        memory_budget_mb: 128,
    }
}

fn make_reuse_scan(decision: ReuseDecision) -> ReuseScan {
    ReuseScan {
        catalog_version: "2026-03-01".to_string(),
        decision,
        candidate_crates: if decision == ReuseDecision::AdoptExistingCrate {
            vec!["existing-crate".to_string()]
        } else {
            vec![]
        },
        rationale: "Evaluated available crates".to_string(),
    }
}

fn make_valid_record(tier: PrimitiveTier) -> PrimitiveAdoptionRecord {
    PrimitiveAdoptionRecord {
        primitive_id: "prim-001".to_string(),
        tier,
        verification: Some(make_verification()),
        score: make_score(),
        fallback: Some(make_fallback()),
        reuse_scan: if tier.requires_reuse_scan() {
            Some(make_reuse_scan(ReuseDecision::BuildNew))
        } else {
            None
        },
        adopt_vs_build_rationale: "Build new: no suitable existing crate".to_string(),
    }
}

// ---------------------------------------------------------------------------
// PrimitiveTier — Copy / Clone / Debug / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_primitive_tier_copy_semantics() {
    let a = PrimitiveTier::S;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_primitive_tier_clone_independence() {
    let a = PrimitiveTier::A;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_primitive_tier_debug_all_unique() {
    let all = [
        PrimitiveTier::S,
        PrimitiveTier::A,
        PrimitiveTier::B,
        PrimitiveTier::C,
    ];
    let dbgs: std::collections::BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 4);
}

#[test]
fn enrichment_primitive_tier_serde_json_field_values() {
    let json_s = serde_json::to_string(&PrimitiveTier::S).unwrap();
    let json_a = serde_json::to_string(&PrimitiveTier::A).unwrap();
    let json_b = serde_json::to_string(&PrimitiveTier::B).unwrap();
    let json_c = serde_json::to_string(&PrimitiveTier::C).unwrap();
    // serde rename_all = "snake_case" means lowercase
    assert_eq!(json_s, "\"s\"");
    assert_eq!(json_a, "\"a\"");
    assert_eq!(json_b, "\"b\"");
    assert_eq!(json_c, "\"c\"");
}

#[test]
fn enrichment_primitive_tier_requires_reuse_scan_count() {
    let all = [
        PrimitiveTier::S,
        PrimitiveTier::A,
        PrimitiveTier::B,
        PrimitiveTier::C,
    ];
    let count = all.iter().filter(|t| t.requires_reuse_scan()).count();
    assert_eq!(count, 2, "only S and A should require reuse scan");
}

// ---------------------------------------------------------------------------
// ReuseDecision — Copy / Clone / Debug / serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_reuse_decision_copy_semantics() {
    let a = ReuseDecision::BuildNew;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_reuse_decision_clone_independence() {
    let a = ReuseDecision::AdoptExistingCrate;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_reuse_decision_debug_all_unique() {
    let all = [
        ReuseDecision::AdoptExistingCrate,
        ReuseDecision::BuildNew,
        ReuseDecision::NotApplicable,
    ];
    let dbgs: std::collections::BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 3);
}

#[test]
fn enrichment_reuse_decision_serde_values() {
    let json_adopt = serde_json::to_string(&ReuseDecision::AdoptExistingCrate).unwrap();
    let json_build = serde_json::to_string(&ReuseDecision::BuildNew).unwrap();
    let json_na = serde_json::to_string(&ReuseDecision::NotApplicable).unwrap();
    // All should be distinct strings
    let vals: std::collections::BTreeSet<String> =
        [json_adopt, json_build, json_na].into_iter().collect();
    assert_eq!(vals.len(), 3);
}

// ---------------------------------------------------------------------------
// PrimitiveAdoptionValidationError — Clone / Debug / error_code
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validation_error_clone_independence() {
    let a = PrimitiveAdoptionValidationError::MissingVerificationMetadata;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_validation_error_debug_all_unique() {
    let all = [
        PrimitiveAdoptionValidationError::MissingVerificationMetadata,
        PrimitiveAdoptionValidationError::MissingFallbackMetadata,
        PrimitiveAdoptionValidationError::MissingReuseScanOutcome,
        PrimitiveAdoptionValidationError::InvalidScoreRange {
            field: "relevance".to_string(),
        },
        PrimitiveAdoptionValidationError::InvalidMetadataField {
            field: "id".to_string(),
        },
    ];
    let dbgs: std::collections::BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 5);
}

#[test]
fn enrichment_validation_error_codes_all_have_prefix() {
    let all = [
        PrimitiveAdoptionValidationError::MissingVerificationMetadata,
        PrimitiveAdoptionValidationError::MissingFallbackMetadata,
        PrimitiveAdoptionValidationError::MissingReuseScanOutcome,
        PrimitiveAdoptionValidationError::InvalidScoreRange {
            field: "x".to_string(),
        },
        PrimitiveAdoptionValidationError::InvalidMetadataField {
            field: "x".to_string(),
        },
    ];
    for err in &all {
        let code = err.error_code();
        assert!(
            code.starts_with("FE-FRX-16-"),
            "code missing prefix: {}",
            code
        );
    }
}

#[test]
fn enrichment_validation_error_serde_roundtrip_with_fields() {
    let a = PrimitiveAdoptionValidationError::InvalidScoreRange {
        field: "relevance_millionths".to_string(),
    };
    let json = serde_json::to_string(&a).unwrap();
    let b: PrimitiveAdoptionValidationError = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

#[test]
fn enrichment_validation_error_json_tagged() {
    let a = PrimitiveAdoptionValidationError::MissingVerificationMetadata;
    let json = serde_json::to_string(&a).unwrap();
    assert!(json.contains("\"kind\""), "should have tagged serde format");
}

// ---------------------------------------------------------------------------
// VerificationChecklist — Clone / Debug / JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verification_clone_independence() {
    let a = make_verification();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_verification_debug_nonempty() {
    assert!(!format!("{:?}", make_verification()).is_empty());
}

#[test]
fn enrichment_verification_json_field_names() {
    let json = serde_json::to_string(&make_verification()).unwrap();
    for field in &[
        "checklist_version",
        "primary_paper_verified",
        "independent_replication_completed",
        "verification_notes",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

// ---------------------------------------------------------------------------
// EvRelevanceRiskScore — Clone / Debug / JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_score_clone_independence() {
    let a = make_score();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_score_debug_nonempty() {
    assert!(!format!("{:?}", make_score()).is_empty());
}

#[test]
fn enrichment_score_json_field_names() {
    let json = serde_json::to_string(&make_score()).unwrap();
    for field in &["ev_millionths", "relevance_millionths", "risk_millionths"] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_score_negative_ev_valid() {
    let s = EvRelevanceRiskScore {
        ev_millionths: -500_000,
        relevance_millionths: 100_000,
        risk_millionths: 100_000,
    };
    let json = serde_json::to_string(&s).unwrap();
    let rt: EvRelevanceRiskScore = serde_json::from_str(&json).unwrap();
    assert_eq!(s, rt);
}

// ---------------------------------------------------------------------------
// FallbackBudget — Clone / Debug / JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_fallback_clone_independence() {
    let a = make_fallback();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_fallback_debug_nonempty() {
    assert!(!format!("{:?}", make_fallback()).is_empty());
}

#[test]
fn enrichment_fallback_json_field_names() {
    let json = serde_json::to_string(&make_fallback()).unwrap();
    for field in &[
        "trigger",
        "deterministic_mode",
        "max_retry_count",
        "time_budget_ms",
        "memory_budget_mb",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

// ---------------------------------------------------------------------------
// ReuseScan — Clone / Debug / JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_reuse_scan_clone_independence() {
    let a = make_reuse_scan(ReuseDecision::BuildNew);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_reuse_scan_debug_nonempty() {
    assert!(!format!("{:?}", make_reuse_scan(ReuseDecision::NotApplicable)).is_empty());
}

#[test]
fn enrichment_reuse_scan_json_field_names() {
    let json = serde_json::to_string(&make_reuse_scan(ReuseDecision::BuildNew)).unwrap();
    for field in &[
        "catalog_version",
        "decision",
        "candidate_crates",
        "rationale",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

// ---------------------------------------------------------------------------
// PrimitiveAdoptionRecord — Clone / Debug / JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_record_clone_independence() {
    let a = make_valid_record(PrimitiveTier::S);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_record_debug_nonempty() {
    assert!(!format!("{:?}", make_valid_record(PrimitiveTier::B)).is_empty());
}

#[test]
fn enrichment_record_json_field_names() {
    let json = serde_json::to_string(&make_valid_record(PrimitiveTier::A)).unwrap();
    for field in &[
        "primitive_id",
        "tier",
        "verification",
        "score",
        "fallback",
        "reuse_scan",
        "adopt_vs_build_rationale",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_record_serde_roundtrip_all_tiers() {
    for tier in &[
        PrimitiveTier::S,
        PrimitiveTier::A,
        PrimitiveTier::B,
        PrimitiveTier::C,
    ] {
        let rec = make_valid_record(*tier);
        let json = serde_json::to_string(&rec).unwrap();
        let rt: PrimitiveAdoptionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, rt, "roundtrip failed for tier {:?}", tier);
    }
}

// ---------------------------------------------------------------------------
// validate_for_activation — additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_validate_all_tiers_valid() {
    for tier in &[
        PrimitiveTier::S,
        PrimitiveTier::A,
        PrimitiveTier::B,
        PrimitiveTier::C,
    ] {
        let rec = make_valid_record(*tier);
        assert!(
            rec.validate_for_activation().is_ok(),
            "valid record should pass for {:?}",
            tier
        );
    }
}

#[test]
fn enrichment_validate_max_scores_ok() {
    let mut rec = make_valid_record(PrimitiveTier::C);
    rec.score.relevance_millionths = 1_000_000;
    rec.score.risk_millionths = 1_000_000;
    assert!(rec.validate_for_activation().is_ok());
}

#[test]
fn enrichment_validate_zero_scores_ok() {
    let mut rec = make_valid_record(PrimitiveTier::C);
    rec.score.relevance_millionths = 0;
    rec.score.risk_millionths = 0;
    rec.score.ev_millionths = 0;
    assert!(rec.validate_for_activation().is_ok());
}

#[test]
fn enrichment_validate_relevance_over_million() {
    let mut rec = make_valid_record(PrimitiveTier::C);
    rec.score.relevance_millionths = 1_000_001;
    let err = rec.validate_for_activation().unwrap_err();
    assert!(matches!(
        err,
        PrimitiveAdoptionValidationError::InvalidScoreRange { .. }
    ));
}

#[test]
fn enrichment_validate_risk_over_million() {
    let mut rec = make_valid_record(PrimitiveTier::C);
    rec.score.risk_millionths = 1_000_001;
    let err = rec.validate_for_activation().unwrap_err();
    assert!(matches!(
        err,
        PrimitiveAdoptionValidationError::InvalidScoreRange { .. }
    ));
}

#[test]
fn enrichment_validate_empty_id_returns_metadata_error() {
    let mut rec = make_valid_record(PrimitiveTier::C);
    rec.primitive_id = "".to_string();
    let err = rec.validate_for_activation().unwrap_err();
    assert!(matches!(
        err,
        PrimitiveAdoptionValidationError::InvalidMetadataField { .. }
    ));
}

#[test]
fn enrichment_validate_whitespace_id_returns_metadata_error() {
    let mut rec = make_valid_record(PrimitiveTier::C);
    rec.primitive_id = "   ".to_string();
    let err = rec.validate_for_activation().unwrap_err();
    assert!(matches!(
        err,
        PrimitiveAdoptionValidationError::InvalidMetadataField { .. }
    ));
}

#[test]
fn enrichment_validate_missing_verification() {
    let mut rec = make_valid_record(PrimitiveTier::C);
    rec.verification = None;
    let err = rec.validate_for_activation().unwrap_err();
    assert!(matches!(
        err,
        PrimitiveAdoptionValidationError::MissingVerificationMetadata
    ));
}

#[test]
fn enrichment_validate_missing_fallback() {
    let mut rec = make_valid_record(PrimitiveTier::C);
    rec.fallback = None;
    let err = rec.validate_for_activation().unwrap_err();
    assert!(matches!(
        err,
        PrimitiveAdoptionValidationError::MissingFallbackMetadata
    ));
}

#[test]
fn enrichment_validate_tier_s_missing_reuse_scan() {
    let mut rec = make_valid_record(PrimitiveTier::S);
    rec.reuse_scan = None;
    let err = rec.validate_for_activation().unwrap_err();
    assert!(matches!(
        err,
        PrimitiveAdoptionValidationError::MissingReuseScanOutcome
    ));
}

#[test]
fn enrichment_validate_adopt_with_empty_candidates() {
    let mut rec = make_valid_record(PrimitiveTier::S);
    rec.reuse_scan = Some(ReuseScan {
        catalog_version: "v1".to_string(),
        decision: ReuseDecision::AdoptExistingCrate,
        candidate_crates: vec![],
        rationale: "Adopting".to_string(),
    });
    let err = rec.validate_for_activation().unwrap_err();
    // Should fail because AdoptExistingCrate needs non-empty candidates
    assert!(matches!(
        err,
        PrimitiveAdoptionValidationError::MissingReuseScanOutcome
            | PrimitiveAdoptionValidationError::InvalidMetadataField { .. }
    ));
}

#[test]
fn enrichment_validate_adopt_with_candidates_ok() {
    let mut rec = make_valid_record(PrimitiveTier::S);
    rec.reuse_scan = Some(make_reuse_scan(ReuseDecision::AdoptExistingCrate));
    assert!(rec.validate_for_activation().is_ok());
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_five_run_determinism_serde() {
    let rec = make_valid_record(PrimitiveTier::S);
    let jsons: std::collections::BTreeSet<String> = (0..5)
        .map(|_| serde_json::to_string(&rec).unwrap())
        .collect();
    assert_eq!(jsons.len(), 1, "serde should be deterministic");
}

// ---------------------------------------------------------------------------
// Cross-cutting invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cross_cutting_error_code_unique_across_all() {
    let all = [
        PrimitiveAdoptionValidationError::MissingVerificationMetadata,
        PrimitiveAdoptionValidationError::MissingFallbackMetadata,
        PrimitiveAdoptionValidationError::MissingReuseScanOutcome,
        PrimitiveAdoptionValidationError::InvalidScoreRange {
            field: "x".to_string(),
        },
        PrimitiveAdoptionValidationError::InvalidMetadataField {
            field: "y".to_string(),
        },
    ];
    let codes: std::collections::BTreeSet<&str> = all.iter().map(|e| e.error_code()).collect();
    assert_eq!(codes.len(), 5);
}

#[test]
fn enrichment_cross_cutting_valid_record_roundtrips_cleanly() {
    for tier in &[
        PrimitiveTier::S,
        PrimitiveTier::A,
        PrimitiveTier::B,
        PrimitiveTier::C,
    ] {
        let rec = make_valid_record(*tier);
        assert!(rec.validate_for_activation().is_ok());
        let json = serde_json::to_string(&rec).unwrap();
        let rt: PrimitiveAdoptionRecord = serde_json::from_str(&json).unwrap();
        assert!(
            rt.validate_for_activation().is_ok(),
            "deserialized record should still validate for {:?}",
            tier
        );
    }
}

#[test]
fn enrichment_cross_cutting_tier_b_c_no_reuse_scan_needed() {
    for tier in &[PrimitiveTier::B, PrimitiveTier::C] {
        let mut rec = make_valid_record(*tier);
        rec.reuse_scan = None;
        assert!(
            rec.validate_for_activation().is_ok(),
            "tier {:?} should not require reuse scan",
            tier
        );
    }
}

#[test]
fn enrichment_cross_cutting_unverified_paper_fails() {
    let mut rec = make_valid_record(PrimitiveTier::C);
    rec.verification = Some(VerificationChecklist {
        checklist_version: "v1.0".to_string(),
        primary_paper_verified: false,
        independent_replication_completed: true,
        verification_notes: "notes".to_string(),
    });
    assert!(rec.validate_for_activation().is_err());
}

#[test]
fn enrichment_cross_cutting_zero_time_budget_fails() {
    let mut rec = make_valid_record(PrimitiveTier::C);
    rec.fallback = Some(FallbackBudget {
        trigger: "t".to_string(),
        deterministic_mode: "d".to_string(),
        max_retry_count: 1,
        time_budget_ms: 0,
        memory_budget_mb: 64,
    });
    assert!(rec.validate_for_activation().is_err());
}
