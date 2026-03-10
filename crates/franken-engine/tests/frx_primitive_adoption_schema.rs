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

use std::{fs, path::PathBuf};

#[path = "../src/primitive_adoption_schema.rs"]
mod primitive_adoption_schema;

use primitive_adoption_schema::{
    EvRelevanceRiskScore, FallbackBudget, PrimitiveAdoptionRecord,
    PrimitiveAdoptionValidationError, PrimitiveTier, ReuseDecision, ReuseScan,
    VerificationChecklist,
};
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn valid_record(tier: PrimitiveTier) -> PrimitiveAdoptionRecord {
    PrimitiveAdoptionRecord {
        primitive_id: "frx.primitive.lockfree_scheduler.v1".to_string(),
        tier,
        verification: Some(VerificationChecklist {
            checklist_version: "v1".to_string(),
            primary_paper_verified: true,
            independent_replication_completed: true,
            verification_notes: "replicated against reference corpus".to_string(),
        }),
        score: EvRelevanceRiskScore {
            ev_millionths: 250_000,
            relevance_millionths: 900_000,
            risk_millionths: 180_000,
        },
        fallback: Some(FallbackBudget {
            trigger: "calibration_drift".to_string(),
            deterministic_mode: "safe_mode_serial".to_string(),
            max_retry_count: 1,
            time_budget_ms: 50,
            memory_budget_mb: 128,
        }),
        reuse_scan: Some(ReuseScan {
            catalog_version: "crate-catalog-2026-02-25".to_string(),
            decision: ReuseDecision::AdoptExistingCrate,
            candidate_crates: vec!["crossbeam".to_string()],
            rationale: "adopted for proven lock-free queue semantics".to_string(),
        }),
        adopt_vs_build_rationale: "adopt existing implementation unless verification fails"
            .to_string(),
    }
}

#[test]
fn primitive_adoption_schema_doc_has_required_sections() {
    let path = repo_root().join("docs/FRX_PRIMITIVE_ADOPTION_SCHEMA_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Primitive Adoption Schema v1",
        "## Scope",
        "## Required Metadata",
        "## Activation Gate Rules",
        "## Crate Reuse Scan Contract",
        "## Structured Logging Contract",
        "## Operator Verification",
    ];
    for section in required_sections {
        assert!(
            doc.contains(section),
            "primitive adoption doc missing section: {section}"
        );
    }
}

#[test]
fn primitive_adoption_schema_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_primitive_adoption_schema_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.primitive.adoption.schema.v1")
    );
    assert_eq!(value["primary_bead"].as_str(), Some("bd-mjh3.16.1"));
    assert_eq!(
        value["activation_gate"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_verification_metadata"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_fallback_metadata"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_reuse_scan_outcome"].as_bool(),
        Some(true)
    );
}

#[test]
fn activation_allows_valid_s_tier_record() {
    let record = valid_record(PrimitiveTier::S);
    assert_eq!(record.validate_for_activation(), Ok(()));
}

#[test]
fn missing_verification_blocks_activation() {
    let mut record = valid_record(PrimitiveTier::S);
    record.verification = None;

    let error = record.validate_for_activation().unwrap_err();
    assert_eq!(
        error,
        PrimitiveAdoptionValidationError::MissingVerificationMetadata
    );
    assert_eq!(error.error_code(), "FE-FRX-16-VERIFY-0001");
}

#[test]
fn missing_fallback_blocks_activation() {
    let mut record = valid_record(PrimitiveTier::A);
    record.fallback = None;

    let error = record.validate_for_activation().unwrap_err();
    assert_eq!(
        error,
        PrimitiveAdoptionValidationError::MissingFallbackMetadata
    );
    assert_eq!(error.error_code(), "FE-FRX-16-FALLBACK-0001");
}

#[test]
fn missing_reuse_scan_blocks_s_tier_activation() {
    let mut record = valid_record(PrimitiveTier::S);
    record.reuse_scan = None;

    let error = record.validate_for_activation().unwrap_err();
    assert_eq!(
        error,
        PrimitiveAdoptionValidationError::MissingReuseScanOutcome
    );
    assert_eq!(error.error_code(), "FE-FRX-16-REUSE-0001");
}

#[test]
fn b_tier_can_activate_without_reuse_scan() {
    let mut record = valid_record(PrimitiveTier::B);
    record.reuse_scan = None;

    assert_eq!(record.validate_for_activation(), Ok(()));
}

// ---------- valid_record helper ----------

#[test]
fn valid_record_produces_valid_s_tier() {
    let record = valid_record(PrimitiveTier::S);
    assert_eq!(record.tier, PrimitiveTier::S);
    assert!(record.verification.is_some());
    assert!(record.fallback.is_some());
    assert!(record.reuse_scan.is_some());
    assert_eq!(record.validate_for_activation(), Ok(()));
}

// ---------- PrimitiveTier ----------

#[test]
fn primitive_tier_requires_reuse_scan_for_s_and_a() {
    assert!(PrimitiveTier::S.requires_reuse_scan());
    assert!(PrimitiveTier::A.requires_reuse_scan());
    assert!(!PrimitiveTier::B.requires_reuse_scan());
    assert!(!PrimitiveTier::C.requires_reuse_scan());
}

#[test]
fn primitive_tier_serde_roundtrip() {
    for tier in [
        PrimitiveTier::S,
        PrimitiveTier::A,
        PrimitiveTier::B,
        PrimitiveTier::C,
    ] {
        let json = serde_json::to_string(&tier).expect("serialize");
        let recovered: PrimitiveTier = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, tier);
    }
}

// ---------- ReuseDecision ----------

#[test]
fn reuse_decision_serde_roundtrip() {
    for decision in [
        ReuseDecision::AdoptExistingCrate,
        ReuseDecision::BuildNew,
        ReuseDecision::NotApplicable,
    ] {
        let json = serde_json::to_string(&decision).expect("serialize");
        let recovered: ReuseDecision = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, decision);
    }
}

// ---------- PrimitiveAdoptionRecord ----------

#[test]
fn primitive_adoption_record_serde_roundtrip() {
    let record = valid_record(PrimitiveTier::S);
    let json = serde_json::to_string(&record).expect("serialize");
    let recovered: PrimitiveAdoptionRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, record);
}

#[test]
fn a_tier_requires_reuse_scan_for_activation() {
    let mut record = valid_record(PrimitiveTier::A);
    record.reuse_scan = None;

    let err = record.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingReuseScanOutcome
    );
}

#[test]
fn c_tier_can_activate_without_reuse_scan() {
    let mut record = valid_record(PrimitiveTier::C);
    record.reuse_scan = None;

    assert_eq!(record.validate_for_activation(), Ok(()));
}

#[test]
fn empty_primitive_id_blocks_activation() {
    let mut record = valid_record(PrimitiveTier::B);
    record.primitive_id = String::new();

    let err = record.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::InvalidMetadataField {
            field: "primitive_id".to_string()
        }
    );
}

#[test]
fn empty_rationale_blocks_activation() {
    let mut record = valid_record(PrimitiveTier::B);
    record.adopt_vs_build_rationale = String::new();

    let err = record.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::InvalidMetadataField {
            field: "adopt_vs_build_rationale".to_string()
        }
    );
}

#[test]
fn score_relevance_out_of_range_blocks_activation() {
    let mut record = valid_record(PrimitiveTier::B);
    record.score.relevance_millionths = 1_000_001;

    let err = record.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::InvalidScoreRange {
            field: "relevance_millionths".to_string()
        }
    );
}

#[test]
fn score_risk_out_of_range_blocks_activation() {
    let mut record = valid_record(PrimitiveTier::B);
    record.score.risk_millionths = 1_000_001;

    let err = record.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::InvalidScoreRange {
            field: "risk_millionths".to_string()
        }
    );
}

// ---------- EvRelevanceRiskScore ----------

#[test]
fn ev_relevance_risk_score_serde_roundtrip() {
    let score = EvRelevanceRiskScore {
        ev_millionths: -500_000,
        relevance_millionths: 750_000,
        risk_millionths: 300_000,
    };
    let json = serde_json::to_string(&score).expect("serialize");
    let recovered: EvRelevanceRiskScore = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, score);
}

// ---------- VerificationChecklist ----------

#[test]
fn verification_checklist_serde_roundtrip() {
    let checklist = VerificationChecklist {
        checklist_version: "v2".to_string(),
        primary_paper_verified: true,
        independent_replication_completed: false,
        verification_notes: "notes".to_string(),
    };
    let json = serde_json::to_string(&checklist).expect("serialize");
    let recovered: VerificationChecklist = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, checklist);
}

// ---------- FallbackBudget ----------

#[test]
fn fallback_budget_serde_roundtrip() {
    let budget = FallbackBudget {
        trigger: "oom".to_string(),
        deterministic_mode: "crash_recovery".to_string(),
        max_retry_count: 3,
        time_budget_ms: 100,
        memory_budget_mb: 256,
    };
    let json = serde_json::to_string(&budget).expect("serialize");
    let recovered: FallbackBudget = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, budget);
}

// ---------- ReuseScan ----------

#[test]
fn reuse_scan_serde_roundtrip() {
    let scan = ReuseScan {
        catalog_version: "v3".to_string(),
        decision: ReuseDecision::BuildNew,
        candidate_crates: vec!["tokio".to_string()],
        rationale: "custom requirements".to_string(),
    };
    let json = serde_json::to_string(&scan).expect("serialize");
    let recovered: ReuseScan = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, scan);
}

// ---------- PrimitiveAdoptionValidationError ----------

#[test]
fn validation_error_codes_are_unique() {
    let errors = [
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
    let codes: std::collections::BTreeSet<&str> = errors.iter().map(|e| e.error_code()).collect();
    assert_eq!(codes.len(), errors.len());
}

#[test]
fn validation_error_codes_have_fe_prefix() {
    let errors = [
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
    for err in &errors {
        assert!(
            err.error_code().starts_with("FE-"),
            "error code {} must start with FE-",
            err.error_code()
        );
    }
}

#[test]
fn validation_error_serde_roundtrip() {
    for err in [
        PrimitiveAdoptionValidationError::MissingVerificationMetadata,
        PrimitiveAdoptionValidationError::MissingFallbackMetadata,
        PrimitiveAdoptionValidationError::MissingReuseScanOutcome,
        PrimitiveAdoptionValidationError::InvalidScoreRange {
            field: "relevance_millionths".to_string(),
        },
        PrimitiveAdoptionValidationError::InvalidMetadataField {
            field: "primitive_id".to_string(),
        },
    ] {
        let json = serde_json::to_string(&err).expect("serialize");
        let recovered: PrimitiveAdoptionValidationError =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, err);
    }
}

// ---------- validation determinism ----------

#[test]
fn validation_is_deterministic() {
    let record = valid_record(PrimitiveTier::S);
    let a = record.validate_for_activation();
    let b = record.validate_for_activation();
    assert_eq!(a, b);
}

// ---------- additional edge-case coverage ----------

#[test]
fn verification_with_empty_checklist_version_blocks_activation() {
    let mut record = valid_record(PrimitiveTier::B);
    record.verification = Some(VerificationChecklist {
        checklist_version: "   ".to_string(),
        primary_paper_verified: true,
        independent_replication_completed: true,
        verification_notes: "notes".to_string(),
    });

    let err = record.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingVerificationMetadata
    );
}

#[test]
fn fallback_with_zero_time_budget_blocks_activation() {
    let mut record = valid_record(PrimitiveTier::B);
    record.fallback = Some(FallbackBudget {
        trigger: "oom".to_string(),
        deterministic_mode: "safe".to_string(),
        max_retry_count: 1,
        time_budget_ms: 0,
        memory_budget_mb: 128,
    });

    let err = record.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingFallbackMetadata
    );
}

#[test]
fn adopt_existing_crate_with_empty_candidates_blocks_s_tier() {
    let mut record = valid_record(PrimitiveTier::S);
    record.reuse_scan = Some(ReuseScan {
        catalog_version: "v1".to_string(),
        decision: ReuseDecision::AdoptExistingCrate,
        candidate_crates: vec![],
        rationale: "we chose to adopt".to_string(),
    });

    let err = record.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::InvalidMetadataField {
            field: "candidate_crates".to_string()
        }
    );
}

#[test]
fn score_at_boundary_one_million_passes_validation() {
    let mut record = valid_record(PrimitiveTier::B);
    record.score.relevance_millionths = 1_000_000;
    record.score.risk_millionths = 1_000_000;

    assert_eq!(record.validate_for_activation(), Ok(()));
}

// ---------- enrichment: additional edge-case and validation coverage ----------

#[test]
fn fallback_with_zero_memory_budget_blocks_activation() {
    let mut record = valid_record(PrimitiveTier::B);
    record.fallback = Some(FallbackBudget {
        trigger: "oom".to_string(),
        deterministic_mode: "safe".to_string(),
        max_retry_count: 1,
        time_budget_ms: 50,
        memory_budget_mb: 0,
    });

    let err = record.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingFallbackMetadata
    );
}

#[test]
fn verification_with_primary_paper_not_verified_blocks_activation() {
    let mut record = valid_record(PrimitiveTier::B);
    record.verification = Some(VerificationChecklist {
        checklist_version: "v1".to_string(),
        primary_paper_verified: false,
        independent_replication_completed: true,
        verification_notes: "notes here".to_string(),
    });

    let err = record.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingVerificationMetadata
    );
}

#[test]
fn verification_with_empty_notes_blocks_activation() {
    let mut record = valid_record(PrimitiveTier::B);
    record.verification = Some(VerificationChecklist {
        checklist_version: "v1".to_string(),
        primary_paper_verified: true,
        independent_replication_completed: true,
        verification_notes: "   ".to_string(),
    });

    let err = record.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingVerificationMetadata
    );
}

#[test]
fn reuse_scan_with_empty_catalog_version_blocks_s_tier() {
    let mut record = valid_record(PrimitiveTier::S);
    record.reuse_scan = Some(ReuseScan {
        catalog_version: "   ".to_string(),
        decision: ReuseDecision::BuildNew,
        candidate_crates: vec![],
        rationale: "build new".to_string(),
    });

    let err = record.validate_for_activation().unwrap_err();
    assert_eq!(
        err,
        PrimitiveAdoptionValidationError::MissingReuseScanOutcome
    );
}

#[test]
fn score_ev_millionths_negative_value_passes_validation() {
    let mut record = valid_record(PrimitiveTier::B);
    record.score.ev_millionths = -1_000_000;
    record.score.relevance_millionths = 500_000;
    record.score.risk_millionths = 500_000;

    assert_eq!(
        record.validate_for_activation(),
        Ok(()),
        "negative ev_millionths is allowed (signed field)"
    );
}
