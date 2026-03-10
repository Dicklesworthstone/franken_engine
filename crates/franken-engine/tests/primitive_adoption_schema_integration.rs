//! Integration tests for the primitive adoption schema module.
//!
//! Exercises the public API of `primitive_adoption_schema` from outside
//! the crate boundary: tier classification, reuse decisions, validation
//! gate checks, error codes, and serde roundtrips.

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

fn valid_verification() -> VerificationChecklist {
    VerificationChecklist {
        checklist_version: "v1.0".into(),
        primary_paper_verified: true,
        independent_replication_completed: true,
        verification_notes: "Verified against reference impl".into(),
    }
}

fn valid_score() -> EvRelevanceRiskScore {
    EvRelevanceRiskScore {
        ev_millionths: 500_000,
        relevance_millionths: 800_000,
        risk_millionths: 200_000,
    }
}

fn valid_fallback() -> FallbackBudget {
    FallbackBudget {
        trigger: "timeout_or_divergence".into(),
        deterministic_mode: "scalar_fallback".into(),
        max_retry_count: 3,
        time_budget_ms: 100,
        memory_budget_mb: 16,
    }
}

fn valid_reuse_scan() -> ReuseScan {
    ReuseScan {
        catalog_version: "2026-Q1".into(),
        decision: ReuseDecision::BuildNew,
        candidate_crates: vec![],
        rationale: "No existing crate meets determinism requirements".into(),
    }
}

fn valid_record_tier_s() -> PrimitiveAdoptionRecord {
    PrimitiveAdoptionRecord {
        primitive_id: "prim-001".into(),
        tier: PrimitiveTier::S,
        verification: Some(valid_verification()),
        score: valid_score(),
        fallback: Some(valid_fallback()),
        reuse_scan: Some(valid_reuse_scan()),
        adopt_vs_build_rationale: "Build new for determinism guarantees".into(),
    }
}

fn valid_record_tier_c() -> PrimitiveAdoptionRecord {
    PrimitiveAdoptionRecord {
        primitive_id: "prim-low".into(),
        tier: PrimitiveTier::C,
        verification: Some(valid_verification()),
        score: valid_score(),
        fallback: Some(valid_fallback()),
        reuse_scan: None,
        adopt_vs_build_rationale: "Standard utility, no reuse scan needed".into(),
    }
}

// ---------------------------------------------------------------------------
// PrimitiveTier
// ---------------------------------------------------------------------------

#[test]
fn tier_s_requires_reuse_scan() {
    assert!(PrimitiveTier::S.requires_reuse_scan());
}

#[test]
fn tier_a_requires_reuse_scan() {
    assert!(PrimitiveTier::A.requires_reuse_scan());
}

#[test]
fn tier_b_no_reuse_scan() {
    assert!(!PrimitiveTier::B.requires_reuse_scan());
}

#[test]
fn tier_c_no_reuse_scan() {
    assert!(!PrimitiveTier::C.requires_reuse_scan());
}

#[test]
fn tier_serde_roundtrip_all_variants() {
    for tier in [
        PrimitiveTier::S,
        PrimitiveTier::A,
        PrimitiveTier::B,
        PrimitiveTier::C,
    ] {
        let json = serde_json::to_string(&tier).unwrap();
        let back: PrimitiveTier = serde_json::from_str(&json).unwrap();
        assert_eq!(tier, back);
    }
}

// ---------------------------------------------------------------------------
// ReuseDecision
// ---------------------------------------------------------------------------

#[test]
fn reuse_decision_serde_roundtrip() {
    for d in [
        ReuseDecision::AdoptExistingCrate,
        ReuseDecision::BuildNew,
        ReuseDecision::NotApplicable,
    ] {
        let json = serde_json::to_string(&d).unwrap();
        let back: ReuseDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}

// ---------------------------------------------------------------------------
// VerificationChecklist
// ---------------------------------------------------------------------------

#[test]
fn verification_checklist_serde_roundtrip() {
    let v = valid_verification();
    let json = serde_json::to_string(&v).unwrap();
    let back: VerificationChecklist = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// EvRelevanceRiskScore
// ---------------------------------------------------------------------------

#[test]
fn score_serde_roundtrip() {
    let s = valid_score();
    let json = serde_json::to_string(&s).unwrap();
    let back: EvRelevanceRiskScore = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn score_boundary_values() {
    let s = EvRelevanceRiskScore {
        ev_millionths: i64::MAX,
        relevance_millionths: 1_000_000,
        risk_millionths: 0,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: EvRelevanceRiskScore = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// FallbackBudget
// ---------------------------------------------------------------------------

#[test]
fn fallback_budget_serde_roundtrip() {
    let fb = valid_fallback();
    let json = serde_json::to_string(&fb).unwrap();
    let back: FallbackBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(fb, back);
}

// ---------------------------------------------------------------------------
// ReuseScan
// ---------------------------------------------------------------------------

#[test]
fn reuse_scan_serde_roundtrip() {
    let rs = valid_reuse_scan();
    let json = serde_json::to_string(&rs).unwrap();
    let back: ReuseScan = serde_json::from_str(&json).unwrap();
    assert_eq!(rs, back);
}

#[test]
fn reuse_scan_with_candidates() {
    let rs = ReuseScan {
        catalog_version: "2026-Q1".into(),
        decision: ReuseDecision::AdoptExistingCrate,
        candidate_crates: vec!["sha2".into(), "sha3".into()],
        rationale: "sha2 meets determinism bar".into(),
    };
    let json = serde_json::to_string(&rs).unwrap();
    let back: ReuseScan = serde_json::from_str(&json).unwrap();
    assert_eq!(rs, back);
}

// ---------------------------------------------------------------------------
// PrimitiveAdoptionValidationError — error codes
// ---------------------------------------------------------------------------

#[test]
fn error_codes_unique() {
    let errors = [
        PrimitiveAdoptionValidationError::MissingVerificationMetadata,
        PrimitiveAdoptionValidationError::MissingFallbackMetadata,
        PrimitiveAdoptionValidationError::MissingReuseScanOutcome,
        PrimitiveAdoptionValidationError::InvalidScoreRange {
            field: "relevance_millionths".into(),
        },
        PrimitiveAdoptionValidationError::InvalidMetadataField {
            field: "primitive_id".into(),
        },
    ];
    let codes: Vec<_> = errors.iter().map(|e| e.error_code()).collect();
    let mut deduped = codes.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(codes.len(), deduped.len());
}

#[test]
fn error_codes_start_with_prefix() {
    let errors = [
        PrimitiveAdoptionValidationError::MissingVerificationMetadata,
        PrimitiveAdoptionValidationError::MissingFallbackMetadata,
        PrimitiveAdoptionValidationError::MissingReuseScanOutcome,
        PrimitiveAdoptionValidationError::InvalidScoreRange { field: "x".into() },
        PrimitiveAdoptionValidationError::InvalidMetadataField { field: "x".into() },
    ];
    for err in &errors {
        assert!(
            err.error_code().starts_with("FE-FRX-16"),
            "bad prefix: {}",
            err.error_code()
        );
    }
}

#[test]
fn error_serde_roundtrip_all_variants() {
    let errors: Vec<PrimitiveAdoptionValidationError> = vec![
        PrimitiveAdoptionValidationError::MissingVerificationMetadata,
        PrimitiveAdoptionValidationError::MissingFallbackMetadata,
        PrimitiveAdoptionValidationError::MissingReuseScanOutcome,
        PrimitiveAdoptionValidationError::InvalidScoreRange {
            field: "risk_millionths".into(),
        },
        PrimitiveAdoptionValidationError::InvalidMetadataField {
            field: "primitive_id".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: PrimitiveAdoptionValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn error_tagged_serde_format() {
    let err = PrimitiveAdoptionValidationError::MissingVerificationMetadata;
    let json = serde_json::to_string(&err).unwrap();
    assert!(json.contains("\"kind\""), "no kind tag: {json}");
    assert!(
        json.contains("missing_verification_metadata"),
        "wrong variant name: {json}"
    );
}

// ---------------------------------------------------------------------------
// PrimitiveAdoptionRecord — serde
// ---------------------------------------------------------------------------

#[test]
fn record_serde_roundtrip_tier_s() {
    let r = valid_record_tier_s();
    let json = serde_json::to_string(&r).unwrap();
    let back: PrimitiveAdoptionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn record_serde_roundtrip_tier_c() {
    let r = valid_record_tier_c();
    let json = serde_json::to_string(&r).unwrap();
    let back: PrimitiveAdoptionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// validate_for_activation — happy paths
// ---------------------------------------------------------------------------

#[test]
fn validate_tier_s_valid() {
    assert!(valid_record_tier_s().validate_for_activation().is_ok());
}

#[test]
fn validate_tier_a_valid() {
    let mut r = valid_record_tier_s();
    r.tier = PrimitiveTier::A;
    assert!(r.validate_for_activation().is_ok());
}

#[test]
fn validate_tier_b_no_reuse_scan_ok() {
    let mut r = valid_record_tier_c();
    r.tier = PrimitiveTier::B;
    assert!(r.validate_for_activation().is_ok());
}

#[test]
fn validate_tier_c_no_reuse_scan_ok() {
    assert!(valid_record_tier_c().validate_for_activation().is_ok());
}

// ---------------------------------------------------------------------------
// validate_for_activation — empty primitive_id
// ---------------------------------------------------------------------------

#[test]
fn validate_empty_primitive_id() {
    let mut r = valid_record_tier_c();
    r.primitive_id = "".into();
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::InvalidMetadataField {
            field: "primitive_id".into()
        }
    );
}

#[test]
fn validate_whitespace_primitive_id() {
    let mut r = valid_record_tier_c();
    r.primitive_id = "   ".into();
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::InvalidMetadataField {
            field: "primitive_id".into()
        }
    );
}

// ---------------------------------------------------------------------------
// validate_for_activation — empty rationale
// ---------------------------------------------------------------------------

#[test]
fn validate_empty_rationale() {
    let mut r = valid_record_tier_c();
    r.adopt_vs_build_rationale = "".into();
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::InvalidMetadataField {
            field: "adopt_vs_build_rationale".into()
        }
    );
}

// ---------------------------------------------------------------------------
// validate_for_activation — score range
// ---------------------------------------------------------------------------

#[test]
fn validate_relevance_over_million() {
    let mut r = valid_record_tier_c();
    r.score.relevance_millionths = 1_000_001;
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::InvalidScoreRange {
            field: "relevance_millionths".into()
        }
    );
}

#[test]
fn validate_risk_over_million() {
    let mut r = valid_record_tier_c();
    r.score.risk_millionths = 1_000_001;
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::InvalidScoreRange {
            field: "risk_millionths".into()
        }
    );
}

#[test]
fn validate_relevance_exactly_million_ok() {
    let mut r = valid_record_tier_c();
    r.score.relevance_millionths = 1_000_000;
    assert!(r.validate_for_activation().is_ok());
}

#[test]
fn validate_risk_exactly_million_ok() {
    let mut r = valid_record_tier_c();
    r.score.risk_millionths = 1_000_000;
    assert!(r.validate_for_activation().is_ok());
}

#[test]
fn validate_zero_scores_ok() {
    let mut r = valid_record_tier_c();
    r.score.ev_millionths = 0;
    r.score.relevance_millionths = 0;
    r.score.risk_millionths = 0;
    assert!(r.validate_for_activation().is_ok());
}

#[test]
fn validate_negative_ev_millionths_ok() {
    let mut r = valid_record_tier_c();
    r.score.ev_millionths = -500_000;
    assert!(r.validate_for_activation().is_ok());
}

// ---------------------------------------------------------------------------
// validate_for_activation — missing verification
// ---------------------------------------------------------------------------

#[test]
fn validate_missing_verification() {
    let mut r = valid_record_tier_c();
    r.verification = None;
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingVerificationMetadata
    );
}

#[test]
fn validate_unverified_paper() {
    let mut r = valid_record_tier_c();
    let mut v = valid_verification();
    v.primary_paper_verified = false;
    r.verification = Some(v);
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingVerificationMetadata
    );
}

#[test]
fn validate_empty_checklist_version() {
    let mut r = valid_record_tier_c();
    let mut v = valid_verification();
    v.checklist_version = "".into();
    r.verification = Some(v);
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingVerificationMetadata
    );
}

#[test]
fn validate_empty_verification_notes() {
    let mut r = valid_record_tier_c();
    let mut v = valid_verification();
    v.verification_notes = "  ".into();
    r.verification = Some(v);
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingVerificationMetadata
    );
}

// ---------------------------------------------------------------------------
// validate_for_activation — missing fallback
// ---------------------------------------------------------------------------

#[test]
fn validate_missing_fallback() {
    let mut r = valid_record_tier_c();
    r.fallback = None;
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingFallbackMetadata
    );
}

#[test]
fn validate_empty_trigger() {
    let mut r = valid_record_tier_c();
    let mut fb = valid_fallback();
    fb.trigger = "".into();
    r.fallback = Some(fb);
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingFallbackMetadata
    );
}

#[test]
fn validate_empty_deterministic_mode() {
    let mut r = valid_record_tier_c();
    let mut fb = valid_fallback();
    fb.deterministic_mode = "".into();
    r.fallback = Some(fb);
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingFallbackMetadata
    );
}

#[test]
fn validate_zero_time_budget() {
    let mut r = valid_record_tier_c();
    let mut fb = valid_fallback();
    fb.time_budget_ms = 0;
    r.fallback = Some(fb);
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingFallbackMetadata
    );
}

#[test]
fn validate_zero_memory_budget() {
    let mut r = valid_record_tier_c();
    let mut fb = valid_fallback();
    fb.memory_budget_mb = 0;
    r.fallback = Some(fb);
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingFallbackMetadata
    );
}

#[test]
fn validate_zero_retry_count_ok() {
    let mut r = valid_record_tier_c();
    let mut fb = valid_fallback();
    fb.max_retry_count = 0;
    r.fallback = Some(fb);
    assert!(r.validate_for_activation().is_ok());
}

// ---------------------------------------------------------------------------
// validate_for_activation — reuse scan for S/A tiers
// ---------------------------------------------------------------------------

#[test]
fn validate_tier_s_missing_reuse_scan() {
    let mut r = valid_record_tier_s();
    r.reuse_scan = None;
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingReuseScanOutcome
    );
}

#[test]
fn validate_tier_a_missing_reuse_scan() {
    let mut r = valid_record_tier_s();
    r.tier = PrimitiveTier::A;
    r.reuse_scan = None;
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingReuseScanOutcome
    );
}

#[test]
fn validate_reuse_scan_empty_catalog_version() {
    let mut r = valid_record_tier_s();
    let mut rs = valid_reuse_scan();
    rs.catalog_version = "".into();
    r.reuse_scan = Some(rs);
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingReuseScanOutcome
    );
}

#[test]
fn validate_reuse_scan_empty_rationale() {
    let mut r = valid_record_tier_s();
    let mut rs = valid_reuse_scan();
    rs.rationale = "".into();
    r.reuse_scan = Some(rs);
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingReuseScanOutcome
    );
}

#[test]
fn validate_adopt_decision_empty_candidates() {
    let mut r = valid_record_tier_s();
    let mut rs = valid_reuse_scan();
    rs.decision = ReuseDecision::AdoptExistingCrate;
    rs.candidate_crates = vec![];
    r.reuse_scan = Some(rs);
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::InvalidMetadataField {
            field: "candidate_crates".into()
        }
    );
}

#[test]
fn validate_adopt_decision_with_candidates_ok() {
    let mut r = valid_record_tier_s();
    let mut rs = valid_reuse_scan();
    rs.decision = ReuseDecision::AdoptExistingCrate;
    rs.candidate_crates = vec!["sha2".into()];
    r.reuse_scan = Some(rs);
    assert!(r.validate_for_activation().is_ok());
}

#[test]
fn validate_build_new_empty_candidates_ok() {
    let r = valid_record_tier_s();
    assert_eq!(
        r.reuse_scan.as_ref().unwrap().decision,
        ReuseDecision::BuildNew
    );
    assert!(r.reuse_scan.as_ref().unwrap().candidate_crates.is_empty());
    assert!(r.validate_for_activation().is_ok());
}

#[test]
fn validate_not_applicable_reuse_ok() {
    let mut r = valid_record_tier_s();
    let mut rs = valid_reuse_scan();
    rs.decision = ReuseDecision::NotApplicable;
    r.reuse_scan = Some(rs);
    assert!(r.validate_for_activation().is_ok());
}

// ---------------------------------------------------------------------------
// Validation order (first error wins)
// ---------------------------------------------------------------------------

#[test]
fn validation_first_error_is_primitive_id() {
    let mut r = valid_record_tier_c();
    r.primitive_id = "".into();
    r.adopt_vs_build_rationale = "".into();
    r.verification = None;
    let err = r.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::InvalidMetadataField {
            field: "primitive_id".into()
        }
    );
}

// ---------------------------------------------------------------------------
// Full lifecycle
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_tier_s_validate_serde() {
    // 1. Build a valid tier-S record
    let record = valid_record_tier_s();

    // 2. Validate
    assert!(record.validate_for_activation().is_ok());

    // 3. Serde roundtrip
    let json = serde_json::to_string(&record).unwrap();
    let back: PrimitiveAdoptionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);

    // 4. Verify fields preserved
    assert_eq!(back.tier, PrimitiveTier::S);
    assert!(back.tier.requires_reuse_scan());
    assert!(back.reuse_scan.is_some());
    assert!(back.verification.is_some());
    assert!(back.fallback.is_some());
}

#[test]
fn full_lifecycle_tier_c_validate_serde() {
    let record = valid_record_tier_c();
    assert!(record.validate_for_activation().is_ok());

    let json = serde_json::to_string(&record).unwrap();
    let back: PrimitiveAdoptionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);

    assert_eq!(back.tier, PrimitiveTier::C);
    assert!(!back.tier.requires_reuse_scan());
    assert!(back.reuse_scan.is_none());
}

#[test]
fn full_lifecycle_all_tiers() {
    for tier in [
        PrimitiveTier::S,
        PrimitiveTier::A,
        PrimitiveTier::B,
        PrimitiveTier::C,
    ] {
        let mut record = if tier.requires_reuse_scan() {
            valid_record_tier_s()
        } else {
            valid_record_tier_c()
        };
        record.tier = tier;
        assert!(
            record.validate_for_activation().is_ok(),
            "tier {tier:?} failed validation"
        );

        let json = serde_json::to_string(&record).unwrap();
        let back: PrimitiveAdoptionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back, "serde mismatch for tier {tier:?}");
    }
}
