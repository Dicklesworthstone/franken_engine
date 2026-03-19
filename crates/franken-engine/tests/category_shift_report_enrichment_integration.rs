//! Enrichment integration tests for `category_shift_report` module.
//!
//! Deep coverage of serde roundtrips, Display distinctness, deterministic hashing,
//! validation edge cases, markdown rendering, and log entry generation.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeSet;

use frankenengine_engine::category_shift_report::{
    CategoryShiftCapability, CategoryShiftClaim, CategoryShiftReportError,
    CategoryShiftReportInput, CategoryShiftReportLogEntry, BEAD_ID, COMPONENT,
    MINIMUM_PEER_REVIEWERS, MethodologySection, POLICY_ID, PeerReviewSignoff, SCHEMA_VERSION,
    build_category_shift_report, generate_log_entries, DimensionPublicationSummary,
    CategoryShiftReport,
};
use frankenengine_engine::disruption_scorecard::{
    DisruptionDimension, EvidenceInput, ScorecardResult, ScorecardSchema, compute_scorecard,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn evidence(dimension: DisruptionDimension, score: u64, beads: &[&str]) -> EvidenceInput {
    EvidenceInput {
        dimension,
        raw_score_millionths: score,
        source_beads: beads.iter().map(|bead| bead.to_string()).collect(),
        evidence_hash: ContentHash::compute(format!("{dimension}:{score}").as_bytes()),
    }
}

fn passing_scorecard() -> ScorecardResult {
    compute_scorecard(
        &ScorecardSchema::default_schema(),
        &[
            evidence(DisruptionDimension::PerformanceDelta, 150_000, &["bd-1"]),
            evidence(DisruptionDimension::SecurityDelta, 850_000, &["bd-2"]),
            evidence(DisruptionDimension::AutonomyDelta, 950_000, &["bd-3"]),
        ],
        SecurityEpoch::from_raw(7),
        "enrichment-test".to_string(),
    )
    .expect("passing scorecard")
}

fn claim(capability: CategoryShiftCapability) -> CategoryShiftClaim {
    CategoryShiftClaim {
        claim_id: capability.as_str().to_string(),
        capability,
        claim_statement: format!("{} demonstrated", capability.display_name()),
        evidence_summary: format!("{} evidence summary", capability.display_name()),
        evidence_bundle_ref: format!("archive/{}.json", capability.as_str()),
        evidence_hash: ContentHash::compute(capability.as_str().as_bytes()),
        reproduction_instructions: vec![format!("run {}", capability.as_str())],
        source_beads: vec!["bd-src".to_string()],
        caveats: vec!["corpus-limited".to_string()],
    }
}

fn methodology() -> MethodologySection {
    MethodologySection {
        summary: "Independent scorecard synthesis".to_string(),
        statistical_frameworks: vec!["paired benchmark deltas".to_string()],
        validation_methodology: vec!["spot-check reproduction".to_string()],
        limitations: vec!["benchmarks corpus-bound".to_string()],
    }
}

fn peer_reviews() -> Vec<PeerReviewSignoff> {
    vec![
        PeerReviewSignoff {
            reviewer_id: "rev-a".to_string(),
            reviewed_at_utc: "2026-03-15T00:00:00Z".to_string(),
            approved: true,
            notes: "looks good".to_string(),
        },
        PeerReviewSignoff {
            reviewer_id: "rev-b".to_string(),
            reviewed_at_utc: "2026-03-15T00:10:00Z".to_string(),
            approved: true,
            notes: "agreed".to_string(),
        },
    ]
}

fn valid_input() -> CategoryShiftReportInput {
    CategoryShiftReportInput {
        report_version: "v1".to_string(),
        candidate_id: "rc-1".to_string(),
        generated_at_utc: "2026-03-15T00:00:00Z".to_string(),
        archive_root: "archive/root".to_string(),
        scorecard_schema: ScorecardSchema::default_schema(),
        scorecard_result: passing_scorecard(),
        claims: CategoryShiftCapability::ALL.iter().copied().map(claim).collect(),
        methodology: methodology(),
        peer_reviews: peer_reviews(),
    }
}

// ---------------------------------------------------------------------------
// CategoryShiftCapability — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_capability_display_distinct() {
    let displays: BTreeSet<String> =
        CategoryShiftCapability::ALL.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrich_capability_display_names_distinct() {
    let names: BTreeSet<&str> =
        CategoryShiftCapability::ALL.iter().map(|c| c.display_name()).collect();
    assert_eq!(names.len(), 5);
}

#[test]
fn enrich_capability_as_str_matches_serde() {
    for cap in CategoryShiftCapability::ALL {
        let json = serde_json::to_string(&cap).unwrap();
        assert_eq!(json, format!("\"{}\"", cap.as_str()));
    }
}

#[test]
fn enrich_capability_ord_deterministic() {
    let mut sorted = CategoryShiftCapability::ALL;
    sorted.sort();
    assert_eq!(sorted, CategoryShiftCapability::ALL);
}

#[test]
fn enrich_capability_clone_eq() {
    for cap in CategoryShiftCapability::ALL {
        let cloned = cap;
        assert_eq!(cap, cloned);
    }
}

// ---------------------------------------------------------------------------
// CategoryShiftClaim — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_claim_validate_accepts_multiple_source_beads() {
    let mut c = claim(CategoryShiftCapability::DeterministicIfc);
    c.source_beads = vec!["bd-a".to_string(), "bd-b".to_string(), "bd-c".to_string()];
    assert!(c.validate().is_ok());
}

#[test]
fn enrich_claim_validate_accepts_empty_caveats() {
    let mut c = claim(CategoryShiftCapability::DeterministicIfc);
    c.caveats = Vec::new();
    assert!(c.validate().is_ok());
}

#[test]
fn enrich_claim_validate_rejects_bead_empty_string() {
    let mut c = claim(CategoryShiftCapability::DeterministicIfc);
    c.source_beads = vec!["bd-ok".to_string(), "".to_string()];
    assert!(c.validate().is_err());
}

#[test]
fn enrich_claim_hash_differs_by_statement() {
    let mut c1 = claim(CategoryShiftCapability::DeterministicIfc);
    let mut c2 = claim(CategoryShiftCapability::DeterministicIfc);
    c1.claim_statement = "version-a".to_string();
    c2.claim_statement = "version-b".to_string();
    assert_ne!(c1.compute_hash(), c2.compute_hash());
}

#[test]
fn enrich_claim_hash_stable_across_source_bead_order() {
    let mut c1 = claim(CategoryShiftCapability::DeterministicIfc);
    c1.source_beads = vec!["bd-z".to_string(), "bd-a".to_string()];
    let mut c2 = claim(CategoryShiftCapability::DeterministicIfc);
    c2.source_beads = vec!["bd-a".to_string(), "bd-z".to_string()];
    assert_eq!(c1.compute_hash(), c2.compute_hash());
}

#[test]
fn enrich_claim_serde_preserves_all_fields() {
    let c = claim(CategoryShiftCapability::PlasSignedWitnesses);
    let json = serde_json::to_string(&c).unwrap();
    let back: CategoryShiftClaim = serde_json::from_str(&json).unwrap();
    assert_eq!(back.claim_id, c.claim_id);
    assert_eq!(back.capability, c.capability);
    assert_eq!(back.claim_statement, c.claim_statement);
    assert_eq!(back.evidence_summary, c.evidence_summary);
    assert_eq!(back.evidence_bundle_ref, c.evidence_bundle_ref);
    assert_eq!(back.reproduction_instructions, c.reproduction_instructions);
    assert_eq!(back.source_beads, c.source_beads);
    assert_eq!(back.caveats, c.caveats);
}

// ---------------------------------------------------------------------------
// MethodologySection — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_methodology_validate_rejects_empty_validation_methodology() {
    let mut m = methodology();
    m.validation_methodology = Vec::new();
    let err = m.validate().unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InvalidMethodologyField { field } if field == "validation_methodology"
    ));
}

#[test]
fn enrich_methodology_validate_rejects_blank_limitation_item() {
    let mut m = methodology();
    m.limitations = vec!["ok".to_string(), "  ".to_string()];
    let err = m.validate().unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InvalidMethodologyField { field } if field == "limitations"
    ));
}

#[test]
fn enrich_methodology_serde_roundtrip() {
    let m = methodology();
    let json = serde_json::to_string(&m).unwrap();
    let back: MethodologySection = serde_json::from_str(&json).unwrap();
    assert_eq!(back.summary, m.summary);
    assert_eq!(back.statistical_frameworks, m.statistical_frameworks);
    assert_eq!(back.validation_methodology, m.validation_methodology);
    assert_eq!(back.limitations, m.limitations);
}

// ---------------------------------------------------------------------------
// PeerReviewSignoff — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_peer_review_serde_roundtrip() {
    let r = PeerReviewSignoff {
        reviewer_id: "rev-x".to_string(),
        reviewed_at_utc: "2026-03-18T12:00:00Z".to_string(),
        approved: false,
        notes: "needs revision".to_string(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: PeerReviewSignoff = serde_json::from_str(&json).unwrap();
    assert!(!back.approved);
    assert_eq!(back.reviewer_id, "rev-x");
    assert_eq!(back.notes, "needs revision");
}

#[test]
fn enrich_peer_review_debug_format() {
    let r = PeerReviewSignoff {
        reviewer_id: "test".to_string(),
        reviewed_at_utc: "2026-01-01T00:00:00Z".to_string(),
        approved: true,
        notes: "".to_string(),
    };
    let dbg = format!("{r:?}");
    assert!(dbg.contains("test"));
}

// ---------------------------------------------------------------------------
// DimensionPublicationSummary — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_dimension_summary_serde_roundtrip() {
    let s = DimensionPublicationSummary {
        raw_score_millionths: 600_000,
        floor_millionths: 200_000,
        target_millionths: 500_000,
        meets_floor: true,
        meets_target: true,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: DimensionPublicationSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back.raw_score_millionths, 600_000);
    assert!(back.meets_target);
    assert!(back.meets_floor);
}

#[test]
fn enrich_dimension_summary_below_target() {
    let s = DimensionPublicationSummary {
        raw_score_millionths: 100_000,
        floor_millionths: 50_000,
        target_millionths: 200_000,
        meets_floor: true,
        meets_target: false,
    };
    assert!(!s.meets_target);
    assert!(s.meets_floor);
}

// ---------------------------------------------------------------------------
// build_category_shift_report — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_build_report_has_correct_metadata() {
    let report = build_category_shift_report(valid_input()).unwrap();
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.component, COMPONENT);
    assert_eq!(report.bead_id, BEAD_ID);
    assert_eq!(report.policy_id, POLICY_ID);
    assert_eq!(report.report_version, "v1");
    assert_eq!(report.candidate_id, "rc-1");
}

#[test]
fn enrich_build_report_claims_sorted_by_capability() {
    let report = build_category_shift_report(valid_input()).unwrap();
    for i in 1..report.claims.len() {
        assert!(report.claims[i - 1].capability <= report.claims[i].capability);
    }
}

#[test]
fn enrich_build_report_publication_hash_changes_with_candidate() {
    let mut input1 = valid_input();
    input1.candidate_id = "alpha".to_string();
    let mut input2 = valid_input();
    input2.candidate_id = "beta".to_string();
    let r1 = build_category_shift_report(input1).unwrap();
    let r2 = build_category_shift_report(input2).unwrap();
    assert_ne!(r1.publication_hash, r2.publication_hash);
}

#[test]
fn enrich_build_report_dimension_summaries_complete() {
    let report = build_category_shift_report(valid_input()).unwrap();
    // Should have summaries for all dimensions
    assert!(!report.dimension_summaries.is_empty());
    for (_dim, summary) in &report.dimension_summaries {
        assert!(summary.meets_floor || summary.raw_score_millionths < summary.floor_millionths);
    }
}

#[test]
fn enrich_build_report_rejects_only_one_reviewer() {
    let mut input = valid_input();
    input.peer_reviews = vec![PeerReviewSignoff {
        reviewer_id: "solo".to_string(),
        reviewed_at_utc: "2026-03-15T00:00:00Z".to_string(),
        approved: true,
        notes: "".to_string(),
    }];
    let err = build_category_shift_report(input).unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InsufficientPeerReview { .. }
    ));
}

#[test]
fn enrich_build_report_rejects_zero_approved() {
    let mut input = valid_input();
    input.peer_reviews = vec![
        PeerReviewSignoff {
            reviewer_id: "a".to_string(),
            reviewed_at_utc: "2026-03-15T00:00:00Z".to_string(),
            approved: false,
            notes: "".to_string(),
        },
        PeerReviewSignoff {
            reviewer_id: "b".to_string(),
            reviewed_at_utc: "2026-03-15T00:00:00Z".to_string(),
            approved: false,
            notes: "".to_string(),
        },
    ];
    let err = build_category_shift_report(input).unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InsufficientPeerReview { .. }
    ));
}

// ---------------------------------------------------------------------------
// CategoryShiftReport methods — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_report_compute_hash_idempotent() {
    let report = build_category_shift_report(valid_input()).unwrap();
    let h1 = report.compute_hash();
    let h2 = report.compute_hash();
    assert_eq!(h1, h2);
}

#[test]
fn enrich_report_to_json_pretty_valid_json() {
    let report = build_category_shift_report(valid_input()).unwrap();
    let json_str = report.to_json_pretty().unwrap();
    let _: serde_json::Value = serde_json::from_str(&json_str).unwrap();
}

#[test]
fn enrich_report_to_markdown_contains_all_sections() {
    let report = build_category_shift_report(valid_input()).unwrap();
    let md = report.to_markdown();
    assert!(md.contains("# First Category-Shift Report"));
    assert!(md.contains("## Disruption Scorecard"));
    assert!(md.contains("## Beyond-Parity Claims"));
    assert!(md.contains("## Methodology"));
    assert!(md.contains("## Peer Review"));
}

#[test]
fn enrich_report_to_markdown_contains_reviewer_ids() {
    let report = build_category_shift_report(valid_input()).unwrap();
    let md = report.to_markdown();
    assert!(md.contains("rev-a"));
    assert!(md.contains("rev-b"));
}

#[test]
fn enrich_report_serde_full_roundtrip() {
    let report = build_category_shift_report(valid_input()).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: CategoryShiftReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report.publication_hash, back.publication_hash);
    assert_eq!(report.claims.len(), back.claims.len());
}

// ---------------------------------------------------------------------------
// generate_log_entries — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_log_entries_total_count() {
    let report = build_category_shift_report(valid_input()).unwrap();
    let entries = generate_log_entries("trace-enrich", &report);
    // 5 claims + 2 reviews = 7
    assert_eq!(entries.len(), 5 + MINIMUM_PEER_REVIEWERS);
}

#[test]
fn enrich_log_entries_all_have_publication_hash() {
    let report = build_category_shift_report(valid_input()).unwrap();
    let entries = generate_log_entries("trace-2", &report);
    for entry in &entries {
        assert_eq!(entry.publication_hash, report.publication_hash);
    }
}

#[test]
fn enrich_log_entries_serde_roundtrip() {
    let report = build_category_shift_report(valid_input()).unwrap();
    let entries = generate_log_entries("trace-3", &report);
    for entry in &entries {
        let json = serde_json::to_string(entry).unwrap();
        let back: CategoryShiftReportLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.trace_id, "trace-3");
        assert_eq!(back.component, COMPONENT);
    }
}

#[test]
fn enrich_log_entries_claim_events_have_evidence_hash() {
    let report = build_category_shift_report(valid_input()).unwrap();
    let entries = generate_log_entries("trace-4", &report);
    let claim_entries: Vec<_> = entries
        .iter()
        .filter(|e| e.event == "claim_published")
        .collect();
    for entry in &claim_entries {
        assert!(entry.evidence_hash.is_some());
        assert!(entry.claim_id.is_some());
        assert!(entry.evidence_bundle_ref.is_some());
    }
}

// ---------------------------------------------------------------------------
// Error Display — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_error_display_duplicate_claim_id() {
    let err = CategoryShiftReportError::DuplicateClaimId {
        claim_id: "dup-1".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("dup-1"));
}

#[test]
fn enrich_error_display_scorecard_schema_invalid() {
    let err = CategoryShiftReportError::ScorecardSchemaInvalid {
        detail: "bad data".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("bad data"));
}

#[test]
fn enrich_error_display_scorecard_outcome_not_publishable() {
    let err = CategoryShiftReportError::ScorecardOutcomeNotPublishable {
        outcome: "fail".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("fail"));
}

#[test]
fn enrich_error_display_duplicate_peer_reviewer() {
    let err = CategoryShiftReportError::DuplicatePeerReviewer {
        reviewer_id: "rev-dup".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("rev-dup"));
}

// ---------------------------------------------------------------------------
// Constants — enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrich_constants_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(BEAD_ID.starts_with("bd-"));
    assert_eq!(MINIMUM_PEER_REVIEWERS, 2);
}
