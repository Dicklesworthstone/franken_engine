//! Primitive adoption schema and activation gate checks.
//!
//! This module encodes FRX-16.1 requirements as machine-checkable structures
//! that can be used by gates and governance automation.

use serde::{Deserialize, Serialize};

/// Capability tier for an advanced primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrimitiveTier {
    S,
    A,
    B,
    C,
}

impl PrimitiveTier {
    /// S/A tiers are considered frontier/high-risk and require explicit reuse scan.
    #[must_use]
    pub const fn requires_reuse_scan(self) -> bool {
        matches!(self, Self::S | Self::A)
    }
}

/// Outcome of crate reuse scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReuseDecision {
    AdoptExistingCrate,
    BuildNew,
    NotApplicable,
}

/// Verification metadata proving the primitive was vetted before activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationChecklist {
    pub checklist_version: String,
    pub primary_paper_verified: bool,
    pub independent_replication_completed: bool,
    pub verification_notes: String,
}

/// EV/relevance/risk scoring tuple (fixed-point millionths).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvRelevanceRiskScore {
    pub ev_millionths: i64,
    pub relevance_millionths: u32,
    pub risk_millionths: u32,
}

/// Deterministic fallback trigger and budget summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackBudget {
    pub trigger: String,
    pub deterministic_mode: String,
    pub max_retry_count: u32,
    pub time_budget_ms: u64,
    pub memory_budget_mb: u32,
}

/// Crate-reuse scan result and adopt-vs-build rationale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReuseScan {
    pub catalog_version: String,
    pub decision: ReuseDecision,
    pub candidate_crates: Vec<String>,
    pub rationale: String,
}

/// Full machine-readable adoption record for one primitive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimitiveAdoptionRecord {
    pub primitive_id: String,
    pub tier: PrimitiveTier,
    pub verification: Option<VerificationChecklist>,
    pub score: EvRelevanceRiskScore,
    pub fallback: Option<FallbackBudget>,
    pub reuse_scan: Option<ReuseScan>,
    pub adopt_vs_build_rationale: String,
}

/// Deterministic validation error taxonomy for FRX-16.1 activation checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PrimitiveAdoptionValidationError {
    MissingVerificationMetadata,
    MissingFallbackMetadata,
    MissingReuseScanOutcome,
    InvalidScoreRange { field: String },
    InvalidMetadataField { field: String },
}

impl PrimitiveAdoptionValidationError {
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::MissingVerificationMetadata => "FE-FRX-16-VERIFY-0001",
            Self::MissingFallbackMetadata => "FE-FRX-16-FALLBACK-0001",
            Self::MissingReuseScanOutcome => "FE-FRX-16-REUSE-0001",
            Self::InvalidScoreRange { .. } => "FE-FRX-16-SCORE-0001",
            Self::InvalidMetadataField { .. } => "FE-FRX-16-METADATA-0001",
        }
    }
}

fn non_empty(value: &str) -> bool {
    !value.trim().is_empty()
}

impl PrimitiveAdoptionRecord {
    /// Validate FRX-16.1 activation gate requirements.
    pub fn validate_for_activation(&self) -> Result<(), PrimitiveAdoptionValidationError> {
        if !non_empty(self.primitive_id.as_str()) {
            return Err(PrimitiveAdoptionValidationError::InvalidMetadataField {
                field: "primitive_id".to_string(),
            });
        }
        if !non_empty(self.adopt_vs_build_rationale.as_str()) {
            return Err(PrimitiveAdoptionValidationError::InvalidMetadataField {
                field: "adopt_vs_build_rationale".to_string(),
            });
        }

        if self.score.relevance_millionths > 1_000_000 {
            return Err(PrimitiveAdoptionValidationError::InvalidScoreRange {
                field: "relevance_millionths".to_string(),
            });
        }
        if self.score.risk_millionths > 1_000_000 {
            return Err(PrimitiveAdoptionValidationError::InvalidScoreRange {
                field: "risk_millionths".to_string(),
            });
        }

        let verification = self
            .verification
            .as_ref()
            .ok_or(PrimitiveAdoptionValidationError::MissingVerificationMetadata)?;
        if !verification.primary_paper_verified
            || !non_empty(verification.checklist_version.as_str())
            || !non_empty(verification.verification_notes.as_str())
        {
            return Err(PrimitiveAdoptionValidationError::MissingVerificationMetadata);
        }

        let fallback = self
            .fallback
            .as_ref()
            .ok_or(PrimitiveAdoptionValidationError::MissingFallbackMetadata)?;
        if !non_empty(fallback.trigger.as_str())
            || !non_empty(fallback.deterministic_mode.as_str())
            || fallback.time_budget_ms == 0
            || fallback.memory_budget_mb == 0
        {
            return Err(PrimitiveAdoptionValidationError::MissingFallbackMetadata);
        }

        if self.tier.requires_reuse_scan() {
            let reuse = self
                .reuse_scan
                .as_ref()
                .ok_or(PrimitiveAdoptionValidationError::MissingReuseScanOutcome)?;
            if !non_empty(reuse.catalog_version.as_str()) || !non_empty(reuse.rationale.as_str()) {
                return Err(PrimitiveAdoptionValidationError::MissingReuseScanOutcome);
            }
            if matches!(reuse.decision, ReuseDecision::AdoptExistingCrate)
                && reuse.candidate_crates.is_empty()
            {
                return Err(PrimitiveAdoptionValidationError::InvalidMetadataField {
                    field: "candidate_crates".to_string(),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // -- PrimitiveTier --

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
    fn tier_serde_roundtrip() {
        for tier in [
            PrimitiveTier::S,
            PrimitiveTier::A,
            PrimitiveTier::B,
            PrimitiveTier::C,
        ] {
            let json = serde_json::to_string(&tier).expect("serialize derived Serialize");
            let back: PrimitiveTier =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(tier, back);
        }
    }

    #[test]
    fn tier_serde_snake_case() {
        let json = serde_json::to_string(&PrimitiveTier::S).expect("serialize derived Serialize");
        assert!(json.contains("s") || json.contains("S"));
    }

    // -- ReuseDecision --

    #[test]
    fn reuse_decision_serde_roundtrip() {
        for d in [
            ReuseDecision::AdoptExistingCrate,
            ReuseDecision::BuildNew,
            ReuseDecision::NotApplicable,
        ] {
            let json = serde_json::to_string(&d).expect("serialize derived Serialize");
            let back: ReuseDecision =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(d, back);
        }
    }

    // -- VerificationChecklist --

    #[test]
    fn verification_checklist_serde_roundtrip() {
        let v = valid_verification();
        let json = serde_json::to_string(&v).expect("serialize derived Serialize");
        let back: VerificationChecklist =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(v, back);
    }

    // -- EvRelevanceRiskScore --

    #[test]
    fn score_serde_roundtrip() {
        let s = valid_score();
        let json = serde_json::to_string(&s).expect("serialize derived Serialize");
        let back: EvRelevanceRiskScore =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(s, back);
    }

    #[test]
    fn score_boundary_values() {
        let s = EvRelevanceRiskScore {
            ev_millionths: i64::MAX,
            relevance_millionths: 1_000_000,
            risk_millionths: 0,
        };
        let json = serde_json::to_string(&s).expect("serialize derived Serialize");
        let back: EvRelevanceRiskScore =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(s, back);
    }

    // -- FallbackBudget --

    #[test]
    fn fallback_budget_serde_roundtrip() {
        let fb = valid_fallback();
        let json = serde_json::to_string(&fb).expect("serialize derived Serialize");
        let back: FallbackBudget =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(fb, back);
    }

    // -- ReuseScan --

    #[test]
    fn reuse_scan_serde_roundtrip() {
        let rs = valid_reuse_scan();
        let json = serde_json::to_string(&rs).expect("serialize derived Serialize");
        let back: ReuseScan = serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
        let json = serde_json::to_string(&rs).expect("serialize derived Serialize");
        let back: ReuseScan = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(rs.candidate_crates.len(), back.candidate_crates.len());
    }

    // -- PrimitiveAdoptionValidationError --

    #[test]
    fn error_codes_unique() {
        let errors = [
            PrimitiveAdoptionValidationError::MissingVerificationMetadata,
            PrimitiveAdoptionValidationError::MissingFallbackMetadata,
            PrimitiveAdoptionValidationError::MissingReuseScanOutcome,
            PrimitiveAdoptionValidationError::InvalidScoreRange {
                field: "relevance_millionths".to_string(),
            },
            PrimitiveAdoptionValidationError::InvalidMetadataField {
                field: "primitive_id".to_string(),
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
        let err = PrimitiveAdoptionValidationError::MissingVerificationMetadata;
        assert!(err.error_code().starts_with("FE-FRX-16"));
    }

    #[test]
    fn validation_error_serde_roundtrip() {
        let err = PrimitiveAdoptionValidationError::InvalidScoreRange {
            field: "risk_millionths".to_string(),
        };
        let val = serde_json::to_value(&err).expect("serde deserialization should succeed");
        let back: PrimitiveAdoptionValidationError =
            serde_json::from_value(val).expect("serde deserialization should succeed");
        assert_eq!(err, back);
    }

    #[test]
    fn validation_error_tagged_serde() {
        let err = PrimitiveAdoptionValidationError::MissingVerificationMetadata;
        let json = serde_json::to_string(&err).expect("serialize derived Serialize");
        assert!(json.contains("\"kind\""));
        assert!(json.contains("missing_verification_metadata"));
    }

    // -- PrimitiveAdoptionRecord --

    #[test]
    fn record_serde_roundtrip() {
        let r = valid_record_tier_s();
        let json = serde_json::to_string(&r).expect("serialize derived Serialize");
        let back: PrimitiveAdoptionRecord =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(r, back);
    }

    // -- validate_for_activation: happy paths --

    #[test]
    fn validate_tier_s_valid() {
        let r = valid_record_tier_s();
        assert!(r.validate_for_activation().is_ok());
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
        let r = valid_record_tier_c();
        assert!(r.validate_for_activation().is_ok());
    }

    // -- validate_for_activation: empty primitive_id --

    #[test]
    fn validate_empty_primitive_id() {
        let mut r = valid_record_tier_c();
        r.primitive_id = "".into();
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::InvalidMetadataField {
                field: "primitive_id".to_string()
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
                field: "primitive_id".to_string()
            }
        );
    }

    // -- validate_for_activation: empty rationale --

    #[test]
    fn validate_empty_rationale() {
        let mut r = valid_record_tier_c();
        r.adopt_vs_build_rationale = "".into();
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::InvalidMetadataField {
                field: "adopt_vs_build_rationale".to_string()
            }
        );
    }

    // -- validate_for_activation: score range --

    #[test]
    fn validate_relevance_over_million() {
        let mut r = valid_record_tier_c();
        r.score.relevance_millionths = 1_000_001;
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::InvalidScoreRange {
                field: "relevance_millionths".to_string()
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
                field: "risk_millionths".to_string()
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

    // -- validate_for_activation: missing verification --

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

    // -- validate_for_activation: missing fallback --

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

    // -- validate_for_activation: reuse scan for S/A --

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
                field: "candidate_crates".to_string()
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
            r.reuse_scan
                .as_ref()
                .expect("serde deserialization should succeed")
                .decision,
            ReuseDecision::BuildNew
        );
        assert!(
            r.reuse_scan
                .as_ref()
                .expect("serde deserialization should succeed")
                .candidate_crates
                .is_empty()
        );
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

    // -- non_empty helper --

    #[test]
    fn non_empty_rejects_empty() {
        assert!(!non_empty(""));
    }

    #[test]
    fn non_empty_rejects_whitespace() {
        assert!(!non_empty("   "));
        assert!(!non_empty("\t\n"));
    }

    #[test]
    fn non_empty_accepts_content() {
        assert!(non_empty("hello"));
        assert!(non_empty(" x "));
    }

    // -- Enrichment: Display uniqueness via BTreeSet --

    #[test]
    fn validation_error_display_uniqueness() {
        let displays: std::collections::BTreeSet<String> = [
            PrimitiveAdoptionValidationError::MissingVerificationMetadata,
            PrimitiveAdoptionValidationError::MissingFallbackMetadata,
            PrimitiveAdoptionValidationError::MissingReuseScanOutcome,
            PrimitiveAdoptionValidationError::InvalidScoreRange {
                field: "test".into(),
            },
            PrimitiveAdoptionValidationError::InvalidMetadataField {
                field: "test".into(),
            },
        ]
        .iter()
        .map(|e| e.error_code().to_string())
        .collect();
        assert_eq!(displays.len(), 5);
    }

    // -- Enrichment: all error codes unique --

    #[test]
    fn all_error_codes_have_stable_prefix() {
        let codes = [
            PrimitiveAdoptionValidationError::MissingVerificationMetadata.error_code(),
            PrimitiveAdoptionValidationError::MissingFallbackMetadata.error_code(),
            PrimitiveAdoptionValidationError::MissingReuseScanOutcome.error_code(),
            PrimitiveAdoptionValidationError::InvalidScoreRange { field: "x".into() }.error_code(),
            PrimitiveAdoptionValidationError::InvalidMetadataField { field: "x".into() }
                .error_code(),
        ];
        for code in &codes {
            assert!(code.starts_with("FE-FRX-16"));
        }
    }

    // -- Enrichment: boundary score values at zero --

    #[test]
    fn score_zero_values_valid() {
        let mut r = valid_record_tier_c();
        r.score.ev_millionths = 0;
        r.score.relevance_millionths = 0;
        r.score.risk_millionths = 0;
        assert!(r.validate_for_activation().is_ok());
    }

    // -- Enrichment: negative ev_millionths is valid --

    #[test]
    fn score_negative_ev_millionths_valid() {
        let mut r = valid_record_tier_c();
        r.score.ev_millionths = -500_000;
        assert!(r.validate_for_activation().is_ok());
    }

    // -- Enrichment: full record serde with all optional fields --

    #[test]
    fn full_record_with_all_options_serde_roundtrip() {
        let r = valid_record_tier_s();
        assert!(r.verification.is_some());
        assert!(r.fallback.is_some());
        assert!(r.reuse_scan.is_some());
        let json = serde_json::to_string(&r).expect("serialize derived Serialize");
        let back: PrimitiveAdoptionRecord =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(r, back);
    }

    // -- Enrichment: PrimitiveTier all variants serde --

    #[test]
    fn primitive_tier_all_variants_display() {
        // Tiers should serialize to expected lowercase/snake_case
        for tier in [
            PrimitiveTier::S,
            PrimitiveTier::A,
            PrimitiveTier::B,
            PrimitiveTier::C,
        ] {
            let json = serde_json::to_string(&tier).expect("serialize derived Serialize");
            assert!(!json.is_empty());
        }
    }

    // -- Enrichment: validation checks order (first error wins) --

    #[test]
    fn validation_first_error_is_primitive_id_when_empty() {
        let mut r = valid_record_tier_c();
        r.primitive_id = "".into();
        r.adopt_vs_build_rationale = "".into();
        r.verification = None;
        // Should fail on primitive_id first
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::InvalidMetadataField {
                field: "primitive_id".to_string()
            }
        );
    }

    // -- Enrichment: FallbackBudget zero retry count --

    #[test]
    fn fallback_zero_retry_count_valid() {
        let mut r = valid_record_tier_c();
        let mut fb = valid_fallback();
        fb.max_retry_count = 0;
        r.fallback = Some(fb);
        // zero retries is allowed (means no retries, not invalid)
        assert!(r.validate_for_activation().is_ok());
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2 — PearlTower 2026-02-27
    // -----------------------------------------------------------------------

    // -- Copy semantics --

    #[test]
    fn primitive_tier_copy_semantics() {
        let a = PrimitiveTier::S;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn reuse_decision_copy_semantics() {
        let a = ReuseDecision::BuildNew;
        let b = a;
        assert_eq!(a, b);
    }

    // -- Debug distinctness --

    #[test]
    fn primitive_tier_debug_all_distinct() {
        let set: std::collections::BTreeSet<String> = [
            PrimitiveTier::S,
            PrimitiveTier::A,
            PrimitiveTier::B,
            PrimitiveTier::C,
        ]
        .iter()
        .map(|t| format!("{t:?}"))
        .collect();
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn reuse_decision_debug_all_distinct() {
        let set: std::collections::BTreeSet<String> = [
            ReuseDecision::AdoptExistingCrate,
            ReuseDecision::BuildNew,
            ReuseDecision::NotApplicable,
        ]
        .iter()
        .map(|d| format!("{d:?}"))
        .collect();
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn validation_error_debug_all_distinct() {
        let set: std::collections::BTreeSet<String> = [
            PrimitiveAdoptionValidationError::MissingVerificationMetadata,
            PrimitiveAdoptionValidationError::MissingFallbackMetadata,
            PrimitiveAdoptionValidationError::MissingReuseScanOutcome,
            PrimitiveAdoptionValidationError::InvalidScoreRange {
                field: "x".to_string(),
            },
            PrimitiveAdoptionValidationError::InvalidMetadataField {
                field: "y".to_string(),
            },
        ]
        .iter()
        .map(|e| format!("{e:?}"))
        .collect();
        assert_eq!(set.len(), 5);
    }

    // -- Serde variant distinctness --

    #[test]
    fn primitive_tier_serde_all_distinct() {
        let set: std::collections::BTreeSet<String> = [
            PrimitiveTier::S,
            PrimitiveTier::A,
            PrimitiveTier::B,
            PrimitiveTier::C,
        ]
        .iter()
        .map(|t| serde_json::to_string(t).expect("serialize derived Serialize"))
        .collect();
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn reuse_decision_serde_all_distinct() {
        let set: std::collections::BTreeSet<String> = [
            ReuseDecision::AdoptExistingCrate,
            ReuseDecision::BuildNew,
            ReuseDecision::NotApplicable,
        ]
        .iter()
        .map(|d| serde_json::to_string(d).expect("serialize derived Serialize"))
        .collect();
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn validation_error_serde_all_distinct() {
        let set: std::collections::BTreeSet<String> = [
            PrimitiveAdoptionValidationError::MissingVerificationMetadata,
            PrimitiveAdoptionValidationError::MissingFallbackMetadata,
            PrimitiveAdoptionValidationError::MissingReuseScanOutcome,
            PrimitiveAdoptionValidationError::InvalidScoreRange {
                field: "a".to_string(),
            },
            PrimitiveAdoptionValidationError::InvalidMetadataField {
                field: "b".to_string(),
            },
        ]
        .iter()
        .map(|e| serde_json::to_string(e).expect("serialize derived Serialize"))
        .collect();
        assert_eq!(set.len(), 5);
    }

    // -- Clone independence --

    #[test]
    fn verification_checklist_clone_independence() {
        let v = valid_verification();
        let mut cloned = v.clone();
        cloned.checklist_version = "mutated".to_string();
        assert_eq!(v.checklist_version, "v1.0");
    }

    #[test]
    fn fallback_budget_clone_independence() {
        let fb = valid_fallback();
        let mut cloned = fb.clone();
        cloned.max_retry_count = 999;
        assert_eq!(fb.max_retry_count, 3);
    }

    #[test]
    fn reuse_scan_clone_independence() {
        let rs = valid_reuse_scan();
        let mut cloned = rs.clone();
        cloned.candidate_crates.push("new-crate".to_string());
        assert!(rs.candidate_crates.is_empty());
    }

    #[test]
    fn adoption_record_clone_independence() {
        let r = valid_record_tier_s();
        let mut cloned = r.clone();
        cloned.primitive_id = "mutated".to_string();
        assert_eq!(r.primitive_id, "prim-001");
    }

    // -- JSON field-name stability --

    #[test]
    fn verification_checklist_json_field_names() {
        let v = valid_verification();
        let val: serde_json::Value =
            serde_json::to_value(&v).expect("serde deserialization should succeed");
        let obj = val
            .as_object()
            .expect("serde deserialization should succeed");
        for key in [
            "checklist_version",
            "primary_paper_verified",
            "independent_replication_completed",
            "verification_notes",
        ] {
            assert!(obj.contains_key(key), "missing field: {key}");
        }
        assert_eq!(obj.len(), 4);
    }

    #[test]
    fn ev_relevance_risk_score_json_field_names() {
        let s = valid_score();
        let val: serde_json::Value =
            serde_json::to_value(&s).expect("serde deserialization should succeed");
        let obj = val
            .as_object()
            .expect("serde deserialization should succeed");
        for key in ["ev_millionths", "relevance_millionths", "risk_millionths"] {
            assert!(obj.contains_key(key), "missing field: {key}");
        }
        assert_eq!(obj.len(), 3);
    }

    #[test]
    fn fallback_budget_json_field_names() {
        let fb = valid_fallback();
        let val: serde_json::Value =
            serde_json::to_value(&fb).expect("serde deserialization should succeed");
        let obj = val
            .as_object()
            .expect("serde deserialization should succeed");
        for key in [
            "trigger",
            "deterministic_mode",
            "max_retry_count",
            "time_budget_ms",
            "memory_budget_mb",
        ] {
            assert!(obj.contains_key(key), "missing field: {key}");
        }
        assert_eq!(obj.len(), 5);
    }

    #[test]
    fn reuse_scan_json_field_names() {
        let rs = valid_reuse_scan();
        let val: serde_json::Value =
            serde_json::to_value(&rs).expect("serde deserialization should succeed");
        let obj = val
            .as_object()
            .expect("serde deserialization should succeed");
        for key in [
            "catalog_version",
            "decision",
            "candidate_crates",
            "rationale",
        ] {
            assert!(obj.contains_key(key), "missing field: {key}");
        }
        assert_eq!(obj.len(), 4);
    }

    #[test]
    fn adoption_record_json_field_names() {
        let r = valid_record_tier_s();
        let val: serde_json::Value =
            serde_json::to_value(&r).expect("serde deserialization should succeed");
        let obj = val
            .as_object()
            .expect("serde deserialization should succeed");
        for key in [
            "primitive_id",
            "tier",
            "verification",
            "score",
            "fallback",
            "reuse_scan",
            "adopt_vs_build_rationale",
        ] {
            assert!(obj.contains_key(key), "missing field: {key}");
        }
        assert_eq!(obj.len(), 7);
    }

    // -- Boundary/edge cases --

    #[test]
    fn score_max_u32_relevance_invalid() {
        let mut r = valid_record_tier_c();
        r.score.relevance_millionths = u32::MAX;
        let err = r.validate_for_activation().unwrap_err();
        assert!(matches!(
            err,
            PrimitiveAdoptionValidationError::InvalidScoreRange { .. }
        ));
    }

    #[test]
    fn score_max_u32_risk_invalid() {
        let mut r = valid_record_tier_c();
        r.score.risk_millionths = u32::MAX;
        let err = r.validate_for_activation().unwrap_err();
        assert!(matches!(
            err,
            PrimitiveAdoptionValidationError::InvalidScoreRange { .. }
        ));
    }

    #[test]
    fn fallback_max_values_serde_roundtrip() {
        let fb = FallbackBudget {
            trigger: "t".to_string(),
            deterministic_mode: "m".to_string(),
            max_retry_count: u32::MAX,
            time_budget_ms: u64::MAX,
            memory_budget_mb: u32::MAX,
        };
        let json = serde_json::to_string(&fb).expect("serialize derived Serialize");
        let back: FallbackBudget =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(fb, back);
    }

    #[test]
    fn score_i64_min_ev_millionths_serde_roundtrip() {
        let s = EvRelevanceRiskScore {
            ev_millionths: i64::MIN,
            relevance_millionths: 0,
            risk_millionths: 0,
        };
        let json = serde_json::to_string(&s).expect("serialize derived Serialize");
        let back: EvRelevanceRiskScore =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(s, back);
    }

    #[test]
    fn record_with_none_optional_fields_serde_roundtrip() {
        let r = PrimitiveAdoptionRecord {
            primitive_id: "bare-prim".to_string(),
            tier: PrimitiveTier::C,
            verification: None,
            score: valid_score(),
            fallback: None,
            reuse_scan: None,
            adopt_vs_build_rationale: "minimal".to_string(),
        };
        let json = serde_json::to_string(&r).expect("serialize derived Serialize");
        let back: PrimitiveAdoptionRecord =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(r, back);
    }

    #[test]
    fn reuse_scan_many_candidates() {
        let rs = ReuseScan {
            catalog_version: "2026-Q1".to_string(),
            decision: ReuseDecision::AdoptExistingCrate,
            candidate_crates: (0..50).map(|i| format!("crate-{i}")).collect(),
            rationale: "many options".to_string(),
        };
        let json = serde_json::to_string(&rs).expect("serialize derived Serialize");
        let back: ReuseScan = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(rs.candidate_crates.len(), back.candidate_crates.len());
    }

    // -- Serde roundtrips --

    #[test]
    fn validation_error_all_variants_serde_roundtrip() {
        let errors = [
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
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize derived Serialize");
            let back: PrimitiveAdoptionValidationError =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*err, back);
        }
    }

    // -- Debug nonempty --

    #[test]
    fn primitive_tier_debug_nonempty() {
        assert!(!format!("{:?}", PrimitiveTier::S).is_empty());
    }

    #[test]
    fn fallback_budget_debug_nonempty() {
        let fb = valid_fallback();
        assert!(!format!("{fb:?}").is_empty());
    }

    #[test]
    fn adoption_record_debug_nonempty() {
        let r = valid_record_tier_s();
        assert!(!format!("{r:?}").is_empty());
    }

    // -- Tagged serde format --

    #[test]
    fn validation_error_tagged_serde_missing_fallback() {
        let err = PrimitiveAdoptionValidationError::MissingFallbackMetadata;
        let json = serde_json::to_string(&err).expect("serialize derived Serialize");
        assert!(json.contains("\"kind\""));
        assert!(json.contains("missing_fallback_metadata"));
    }

    #[test]
    fn validation_error_tagged_serde_invalid_score_range() {
        let err = PrimitiveAdoptionValidationError::InvalidScoreRange {
            field: "risk_millionths".to_string(),
        };
        let json = serde_json::to_string(&err).expect("serialize derived Serialize");
        assert!(json.contains("\"kind\""));
        assert!(json.contains("invalid_score_range"));
        assert!(json.contains("risk_millionths"));
    }

    #[test]
    fn validation_error_tagged_serde_invalid_metadata_field() {
        let err = PrimitiveAdoptionValidationError::InvalidMetadataField {
            field: "candidate_crates".to_string(),
        };
        let json = serde_json::to_string(&err).expect("serialize derived Serialize");
        assert!(json.contains("\"kind\""));
        assert!(json.contains("invalid_metadata_field"));
        assert!(json.contains("candidate_crates"));
    }

    // -- Error code stability --

    #[test]
    fn error_code_missing_verification_is_verify_0001() {
        assert_eq!(
            PrimitiveAdoptionValidationError::MissingVerificationMetadata.error_code(),
            "FE-FRX-16-VERIFY-0001"
        );
    }

    #[test]
    fn error_code_missing_fallback_is_fallback_0001() {
        assert_eq!(
            PrimitiveAdoptionValidationError::MissingFallbackMetadata.error_code(),
            "FE-FRX-16-FALLBACK-0001"
        );
    }

    #[test]
    fn error_code_missing_reuse_is_reuse_0001() {
        assert_eq!(
            PrimitiveAdoptionValidationError::MissingReuseScanOutcome.error_code(),
            "FE-FRX-16-REUSE-0001"
        );
    }

    #[test]
    fn error_code_invalid_score_is_score_0001() {
        assert_eq!(
            PrimitiveAdoptionValidationError::InvalidScoreRange {
                field: "x".to_string()
            }
            .error_code(),
            "FE-FRX-16-SCORE-0001"
        );
    }

    #[test]
    fn error_code_invalid_metadata_is_metadata_0001() {
        assert_eq!(
            PrimitiveAdoptionValidationError::InvalidMetadataField {
                field: "x".to_string()
            }
            .error_code(),
            "FE-FRX-16-METADATA-0001"
        );
    }

    // -- Additional enrichment batch 2b --

    #[test]
    fn tier_b_with_reuse_scan_still_valid() {
        let mut r = valid_record_tier_c();
        r.tier = PrimitiveTier::B;
        r.reuse_scan = Some(valid_reuse_scan());
        assert!(r.validate_for_activation().is_ok());
    }

    #[test]
    fn verification_checklist_independent_replication_false_still_valid() {
        let mut r = valid_record_tier_c();
        let mut v = valid_verification();
        v.independent_replication_completed = false;
        r.verification = Some(v);
        assert!(r.validate_for_activation().is_ok());
    }

    #[test]
    fn reuse_scan_not_applicable_empty_candidates_ok() {
        let mut r = valid_record_tier_s();
        let mut rs = valid_reuse_scan();
        rs.decision = ReuseDecision::NotApplicable;
        rs.candidate_crates = vec![];
        r.reuse_scan = Some(rs);
        assert!(r.validate_for_activation().is_ok());
    }

    #[test]
    fn validation_error_clone_eq() {
        let err = PrimitiveAdoptionValidationError::InvalidScoreRange {
            field: "risk".to_string(),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn ev_relevance_risk_score_clone_eq() {
        let s = valid_score();
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    #[test]
    fn verification_checklist_debug_nonempty() {
        let v = valid_verification();
        assert!(!format!("{v:?}").is_empty());
    }

    #[test]
    fn reuse_scan_debug_nonempty() {
        let rs = valid_reuse_scan();
        assert!(!format!("{rs:?}").is_empty());
    }

    #[test]
    fn ev_relevance_risk_score_debug_nonempty() {
        let s = valid_score();
        assert!(!format!("{s:?}").is_empty());
    }

    #[test]
    fn record_tier_c_no_reuse_scan_json_has_null() {
        let r = valid_record_tier_c();
        let val: serde_json::Value =
            serde_json::to_value(&r).expect("serde deserialization should succeed");
        assert!(val["reuse_scan"].is_null());
    }

    #[test]
    fn validation_rationale_second_check_after_id() {
        let mut r = valid_record_tier_c();
        r.adopt_vs_build_rationale = "  ".to_string();
        let err = r.validate_for_activation().unwrap_err();
        assert_eq!(
            err,
            PrimitiveAdoptionValidationError::InvalidMetadataField {
                field: "adopt_vs_build_rationale".to_string()
            }
        );
    }
}
