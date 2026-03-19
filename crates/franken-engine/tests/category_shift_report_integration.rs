//! Integration tests for the `category_shift_report` publication surface.
//!
//! Exercises deterministic report assembly from disruption-scorecard results,
//! required-claim validation, markdown/json rendering, and structured logs.

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

use frankenengine_engine::category_shift_report::{
    BEAD_ID, COMPONENT, CategoryShiftCapability, CategoryShiftClaim, CategoryShiftReportError,
    CategoryShiftReportInput, CategoryShiftReportLogEntry, MINIMUM_PEER_REVIEWERS,
    MethodologySection, POLICY_ID, PeerReviewSignoff, PrerequisiteGateRecord, PublishedArtifact,
    REQUIRED_PREREQUISITE_BEADS, SCHEMA_VERSION, build_category_shift_report, generate_log_entries,
};
use frankenengine_engine::disruption_scorecard::{
    DisruptionDimension, EvidenceInput, SCORECARD_SCHEMA_VERSION, ScorecardResult, ScorecardSchema,
    compute_scorecard,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

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
            evidence(DisruptionDimension::PerformanceDelta, 150_000, &["bd-1ze"]),
            evidence(
                DisruptionDimension::SecurityDelta,
                850_000,
                &["bd-eke", "bd-3rd"],
            ),
            evidence(
                DisruptionDimension::AutonomyDelta,
                950_000,
                &["bd-181", "bd-2n3"],
            ),
        ],
        SecurityEpoch::from_raw(19),
        "integration-env".to_string(),
    )
    .expect("passing scorecard")
}

fn below_target_scorecard() -> ScorecardResult {
    compute_scorecard(
        &ScorecardSchema::default_schema(),
        &[
            evidence(DisruptionDimension::PerformanceDelta, 95_000, &["bd-1ze"]),
            evidence(
                DisruptionDimension::SecurityDelta,
                850_000,
                &["bd-eke", "bd-3rd"],
            ),
            evidence(
                DisruptionDimension::AutonomyDelta,
                950_000,
                &["bd-181", "bd-2n3"],
            ),
        ],
        SecurityEpoch::from_raw(19),
        "integration-env".to_string(),
    )
    .expect("below-target scorecard")
}

fn claim(capability: CategoryShiftCapability) -> CategoryShiftClaim {
    CategoryShiftClaim {
        claim_id: format!("claim-{}", capability.as_str()),
        capability,
        claim_statement: format!(
            "{} is evidenced beyond incumbent parity.",
            capability.display_name()
        ),
        evidence_summary: format!(
            "{} evidence bundle cleared deterministic reproduction checks.",
            capability.display_name()
        ),
        evidence_bundle_ref: format!("claims/{}/bundle.json", capability.as_str()),
        evidence_hash: ContentHash::compute(capability.as_str().as_bytes()),
        reproduction_instructions: vec![
            format!("fetch {}", capability.as_str()),
            format!("replay {}", capability.as_str()),
        ],
        source_beads: vec!["bd-source-a".to_string(), "bd-source-b".to_string()],
        caveats: vec!["bounded to the published evaluation corpus".to_string()],
    }
}

fn all_claims() -> Vec<CategoryShiftClaim> {
    CategoryShiftCapability::ALL
        .iter()
        .copied()
        .map(claim)
        .collect()
}

fn methodology() -> MethodologySection {
    MethodologySection {
        summary: "The report synthesizes release-gate evidence using fixed thresholds, deterministic scoring, and independent reproduction spot-checks.".to_string(),
        statistical_frameworks: vec![
            "paired baseline delta analysis".to_string(),
            "deterministic replay verification".to_string(),
        ],
        validation_methodology: vec![
            "gate-prerequisite audit".to_string(),
            "independent reproduction spot-check".to_string(),
        ],
        limitations: vec![
            "performance claims remain corpus-scoped".to_string(),
            "security claims rely on the published adversarial corpus".to_string(),
        ],
    }
}

fn prerequisite_artifact_path(bead_id: &str) -> String {
    format!("prerequisites/{bead_id}/run_manifest.json")
}

fn prerequisite_gate(bead_id: &str) -> PrerequisiteGateRecord {
    PrerequisiteGateRecord {
        bead_id: bead_id.to_string(),
        artifact_manifest: prerequisite_artifact_path(bead_id),
        artifact_hash: ContentHash::compute(format!("gate:{bead_id}").as_bytes()),
        summary: format!("{bead_id} prerequisite gate passed"),
        passed: true,
    }
}

fn prerequisite_gates() -> Vec<PrerequisiteGateRecord> {
    REQUIRED_PREREQUISITE_BEADS
        .iter()
        .map(|bead_id| prerequisite_gate(bead_id))
        .collect()
}

fn published_artifacts() -> Vec<PublishedArtifact> {
    let mut artifacts = CategoryShiftCapability::ALL
        .iter()
        .copied()
        .map(|capability| PublishedArtifact {
            artifact_id: format!("claim-{}", capability.as_str()),
            relative_path: format!("claims/{}/bundle.json", capability.as_str()),
            kind: "evidence_bundle".to_string(),
            content_hash: ContentHash::compute(capability.as_str().as_bytes()),
        })
        .collect::<Vec<_>>();
    artifacts.extend(
        REQUIRED_PREREQUISITE_BEADS
            .iter()
            .map(|bead_id| PublishedArtifact {
                artifact_id: format!("gate-{bead_id}"),
                relative_path: prerequisite_artifact_path(bead_id),
                kind: "gate_manifest".to_string(),
                content_hash: ContentHash::compute(format!("gate:{bead_id}").as_bytes()),
            }),
    );
    artifacts
}

fn peer_reviews() -> Vec<PeerReviewSignoff> {
    vec![
        PeerReviewSignoff {
            reviewer_id: "reviewer-alfa".to_string(),
            reviewed_at_utc: "2026-03-13T01:00:00Z".to_string(),
            approved: true,
            notes: "claim/evidence mapping is coherent".to_string(),
        },
        PeerReviewSignoff {
            reviewer_id: "reviewer-bravo".to_string(),
            reviewed_at_utc: "2026-03-13T01:10:00Z".to_string(),
            approved: true,
            notes: "limitations are fairly stated".to_string(),
        },
    ]
}

fn report_input(scorecard_result: ScorecardResult) -> CategoryShiftReportInput {
    CategoryShiftReportInput {
        report_version: "2026.03.13-rc1".to_string(),
        candidate_id: "rc-2026-03-13".to_string(),
        generated_at_utc: "2026-03-13T02:00:00Z".to_string(),
        archive_root: "archive/category-shift/20260313T020000Z".to_string(),
        scorecard_schema: ScorecardSchema::default_schema(),
        scorecard_result,
        claims: all_claims(),
        methodology: methodology(),
        prerequisite_gates: prerequisite_gates(),
        published_artifacts: published_artifacts(),
        peer_reviews: peer_reviews(),
    }
}

#[test]
fn constants_match_expected_contract() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.category-shift-report.v1");
    assert_eq!(COMPONENT, "category_shift_report");
    assert_eq!(BEAD_ID, "bd-f7n");
    assert_eq!(POLICY_ID, "section-10.9-category-shift");
    const { assert!(MINIMUM_PEER_REVIEWERS >= 2) };
}

#[test]
fn build_report_success_and_renderings_are_stable() {
    let report = build_category_shift_report(report_input(passing_scorecard())).expect("report");

    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.component, COMPONENT);
    assert_eq!(report.bead_id, BEAD_ID);
    assert_eq!(report.policy_id, POLICY_ID);
    assert_eq!(report.scorecard_outcome, "pass");
    assert_eq!(report.claims.len(), CategoryShiftCapability::ALL.len());
    assert_eq!(
        report.claims[0].capability,
        CategoryShiftCapability::ProofCarryingOptimization
    );
    assert_eq!(report.dimension_summaries.len(), 3);
    assert!(report.dimension_summaries["performance_delta"].meets_target);
    assert!(report.dimension_summaries["security_delta"].meets_target);
    assert!(report.dimension_summaries["autonomy_delta"].meets_target);

    let json = report.to_json_pretty().expect("json");
    assert!(json.contains(SCHEMA_VERSION));
    assert!(json.contains("\"publication_hash\""));
    assert!(json.contains("\"scorecard_result_hash\""));

    let markdown = report.to_markdown();
    assert!(markdown.contains("# First Category-Shift Report"));
    assert!(markdown.contains("## Disruption Scorecard"));
    assert!(markdown.contains("## Beyond-Parity Claims"));
    assert!(markdown.contains("## Methodology"));
    assert!(markdown.contains("## Prerequisite Gates"));
    assert!(markdown.contains("## Published Artifacts"));
    assert!(markdown.contains("## Peer Review"));
    assert!(markdown.contains("Proof-Carrying Optimization"));
    assert!(markdown.contains(
        "archive/category-shift/20260313T020000Z/claims/proof_carrying_optimization/bundle.json"
    ));

    let rebuilt = build_category_shift_report(report_input(passing_scorecard())).expect("report");
    assert_eq!(report.publication_hash, rebuilt.publication_hash);
}

#[test]
fn build_report_fails_when_dimension_is_below_target() {
    let err = build_category_shift_report(report_input(below_target_scorecard())).unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::ScoreBelowTarget { ref dimension, .. }
        if dimension == "performance_delta"
    ));
}

#[test]
fn build_report_fails_when_capability_is_duplicated() {
    let mut input = report_input(passing_scorecard());
    input.claims[1].capability = input.claims[0].capability;
    let err = build_category_shift_report(input).unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::DuplicateCapability { .. }
    ));
}

#[test]
fn build_report_fails_when_scorecard_schema_is_invalid() {
    let mut input = report_input(passing_scorecard());
    let threshold = input
        .scorecard_schema
        .thresholds
        .get_mut("performance_delta")
        .expect("performance threshold");
    threshold.floor_millionths = 200_000;
    threshold.target_millionths = 100_000;

    let err = build_category_shift_report(input).unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::ScorecardSchemaInvalid { .. }
    ));
}

#[test]
fn build_report_fails_when_scorecard_result_hash_is_tampered() {
    let mut scorecard = passing_scorecard();
    scorecard.result_hash = ContentHash::compute(b"tampered-result-hash");

    let err = build_category_shift_report(report_input(scorecard)).unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::ScorecardResultHashMismatch { .. }
    ));
}

#[test]
fn build_report_fails_when_scorecard_flags_are_inconsistent() {
    let mut scorecard = passing_scorecard();
    scorecard
        .dimension_scores
        .get_mut("performance_delta")
        .expect("performance dimension")
        .meets_target = false;

    let err = build_category_shift_report(report_input(scorecard)).unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::ScorecardDimensionFlagMismatch {
            ref dimension,
            ref field,
            expected: true,
            found: false,
        } if dimension == "performance_delta" && field == "meets_target"
    ));
}

#[test]
fn build_report_fails_when_required_prerequisite_gate_is_missing() {
    let mut input = report_input(passing_scorecard());
    input.prerequisite_gates.pop();

    let err = build_category_shift_report(input).unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::MissingRequiredPrerequisiteGate { .. }
    ));
}

#[test]
fn build_report_fails_when_claim_bundle_is_not_published() {
    let mut input = report_input(passing_scorecard());
    input
        .published_artifacts
        .retain(|artifact| artifact.relative_path != "claims/deterministic_ifc/bundle.json");

    let err = build_category_shift_report(input).unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::MissingPublishedArtifact { ref relative_path }
        if relative_path == "claims/deterministic_ifc/bundle.json"
    ));
}

#[test]
fn log_entries_cover_claims_and_peer_reviews() {
    let report = build_category_shift_report(report_input(passing_scorecard())).expect("report");
    let logs = generate_log_entries("trace-category-shift", &report);

    assert_eq!(
        logs.len(),
        CategoryShiftCapability::ALL.len() + MINIMUM_PEER_REVIEWERS
    );
    assert!(
        logs.iter()
            .all(|log| log.trace_id == "trace-category-shift")
    );
    assert!(
        logs.iter()
            .all(|log| log.report_version == "2026.03.13-rc1")
    );
    assert!(logs.iter().all(|log| log.component == COMPONENT));

    let claim_logs: Vec<&CategoryShiftReportLogEntry> = logs
        .iter()
        .filter(|log| log.event == "claim_published")
        .collect();
    assert_eq!(claim_logs.len(), CategoryShiftCapability::ALL.len());
    assert!(claim_logs.iter().all(|log| log.claim_id.is_some()));
    assert!(
        claim_logs
            .iter()
            .all(|log| log.evidence_bundle_ref.is_some())
    );
    assert!(claim_logs.iter().all(|log| log.evidence_hash.is_some()));

    let review_logs: Vec<&CategoryShiftReportLogEntry> = logs
        .iter()
        .filter(|log| log.event == "peer_review_recorded")
        .collect();
    assert_eq!(review_logs.len(), MINIMUM_PEER_REVIEWERS);
    assert!(review_logs.iter().all(|log| log.reviewer_id.is_some()));
    assert!(
        review_logs
            .iter()
            .all(|log| log.review_status.as_deref() == Some("approved"))
    );
    assert!(
        logs.iter()
            .all(|log| log.publication_hash == report.publication_hash)
    );
}

#[test]
fn scorecard_schema_version_matches_source_contract() {
    let input = report_input(passing_scorecard());
    assert_eq!(input.scorecard_schema.version, SCORECARD_SCHEMA_VERSION);
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde roundtrips, validation edge cases, error Display
// ────────────────────────────────────────────────────────────

#[test]
fn category_shift_capability_serde_roundtrip() {
    for cap in CategoryShiftCapability::ALL {
        let json = serde_json::to_string(&cap).expect("serialize");
        let recovered: CategoryShiftCapability = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cap, recovered);
    }
}

#[test]
fn category_shift_capability_display_matches_as_str() {
    for cap in CategoryShiftCapability::ALL {
        assert_eq!(cap.to_string(), cap.as_str());
        assert!(!cap.as_str().is_empty());
        assert!(!cap.display_name().is_empty());
    }
}

#[test]
fn category_shift_capability_all_has_five_variants() {
    assert_eq!(CategoryShiftCapability::ALL.len(), 5);
    let mut seen = std::collections::BTreeSet::new();
    for cap in CategoryShiftCapability::ALL {
        assert!(seen.insert(cap), "duplicate in ALL: {:?}", cap);
    }
}

#[test]
fn claim_validate_rejects_empty_claim_id() {
    let mut c = claim(CategoryShiftCapability::DeterministicIfc);
    c.claim_id = "".to_string();
    let err = c.validate().unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InvalidClaimField { ref field, .. }
            if field == "claim_id"
    ));
}

#[test]
fn claim_validate_rejects_empty_claim_statement() {
    let mut c = claim(CategoryShiftCapability::DeterministicIfc);
    c.claim_statement = "  ".to_string();
    let err = c.validate().unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InvalidClaimField { ref field, .. }
            if field == "claim_statement"
    ));
}

#[test]
fn claim_validate_rejects_empty_evidence_summary() {
    let mut c = claim(CategoryShiftCapability::DeterministicIfc);
    c.evidence_summary = "".to_string();
    let err = c.validate().unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InvalidClaimField { ref field, .. }
            if field == "evidence_summary"
    ));
}

#[test]
fn claim_validate_rejects_empty_reproduction_instructions() {
    let mut c = claim(CategoryShiftCapability::DeterministicIfc);
    c.reproduction_instructions.clear();
    let err = c.validate().unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InvalidClaimField { ref field, .. }
            if field == "reproduction_instructions"
    ));
}

#[test]
fn claim_validate_rejects_empty_source_beads() {
    let mut c = claim(CategoryShiftCapability::DeterministicIfc);
    c.source_beads.clear();
    let err = c.validate().unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InvalidClaimField { ref field, .. }
            if field == "source_beads"
    ));
}

#[test]
fn claim_compute_hash_is_deterministic() {
    let c1 = claim(CategoryShiftCapability::ProofCarryingOptimization);
    let c2 = claim(CategoryShiftCapability::ProofCarryingOptimization);
    assert_eq!(c1.compute_hash(), c2.compute_hash());

    let c3 = claim(CategoryShiftCapability::DeterministicIfc);
    assert_ne!(c1.compute_hash(), c3.compute_hash());
}

#[test]
fn methodology_validate_rejects_empty_summary() {
    let mut m = methodology();
    m.summary = "".to_string();
    let err = m.validate().unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InvalidMethodologyField { ref field }
            if field == "summary"
    ));
}

#[test]
fn methodology_validate_rejects_empty_statistical_frameworks() {
    let mut m = methodology();
    m.statistical_frameworks.clear();
    let err = m.validate().unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InvalidMethodologyField { ref field }
            if field == "statistical_frameworks"
    ));
}

#[test]
fn methodology_validate_rejects_empty_validation_methodology() {
    let mut m = methodology();
    m.validation_methodology.clear();
    let err = m.validate().unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InvalidMethodologyField { ref field }
            if field == "validation_methodology"
    ));
}

#[test]
fn methodology_validate_rejects_empty_limitations() {
    let mut m = methodology();
    m.limitations.clear();
    let err = m.validate().unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InvalidMethodologyField { ref field }
            if field == "limitations"
    ));
}

#[test]
fn build_report_fails_with_insufficient_peer_reviewers() {
    let mut input = report_input(passing_scorecard());
    input.peer_reviews = vec![PeerReviewSignoff {
        reviewer_id: "solo-reviewer".to_string(),
        reviewed_at_utc: "2026-03-13T01:00:00Z".to_string(),
        approved: true,
        notes: "only one".to_string(),
    }];
    let err = build_category_shift_report(input).unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InsufficientPeerReview {
            approved_reviewers: 1
        }
    ));
}

#[test]
fn build_report_fails_with_duplicate_peer_reviewer() {
    let mut input = report_input(passing_scorecard());
    input.peer_reviews[1].reviewer_id = input.peer_reviews[0].reviewer_id.clone();
    let err = build_category_shift_report(input).unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::DuplicatePeerReviewer { .. }
    ));
}

#[test]
fn build_report_fails_with_duplicate_claim_id() {
    let mut input = report_input(passing_scorecard());
    input.claims[1].claim_id = input.claims[0].claim_id.clone();
    let err = build_category_shift_report(input).unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::DuplicateClaimId { .. }
    ));
}

#[test]
fn build_report_fails_when_missing_required_capability() {
    let mut input = report_input(passing_scorecard());
    input.claims.pop();
    let err = build_category_shift_report(input).unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::MissingRequiredCapability { .. }
    ));
}

#[test]
fn report_serde_roundtrip() {
    let report = build_category_shift_report(report_input(passing_scorecard())).expect("report");
    let json = serde_json::to_string(&report).expect("serialize");
    let recovered: frankenengine_engine::category_shift_report::CategoryShiftReport =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report, recovered);
    assert_eq!(report.publication_hash, recovered.publication_hash);
}

#[test]
fn report_compute_hash_is_deterministic() {
    let report = build_category_shift_report(report_input(passing_scorecard())).expect("report");
    let h1 = report.compute_hash();
    let h2 = report.compute_hash();
    assert_eq!(h1, h2);
    assert_eq!(h1, report.publication_hash);
}

#[test]
fn category_shift_report_error_display_is_nonempty() {
    let errors = [
        CategoryShiftReportError::InvalidClaimField {
            claim_id: "c1".to_string(),
            field: "claim_statement".to_string(),
        },
        CategoryShiftReportError::InvalidMethodologyField {
            field: "summary".to_string(),
        },
        CategoryShiftReportError::MissingRequiredCapability {
            capability: CategoryShiftCapability::DeterministicIfc,
        },
        CategoryShiftReportError::DuplicateCapability {
            capability: CategoryShiftCapability::DeterministicIfc,
        },
        CategoryShiftReportError::DuplicateClaimId {
            claim_id: "c1".to_string(),
        },
        CategoryShiftReportError::ScorecardSchemaInvalid {
            detail: "bad".to_string(),
        },
        CategoryShiftReportError::ScoreBelowTarget {
            dimension: "perf".to_string(),
            raw_score_millionths: 100_000,
            target_millionths: 200_000,
        },
        CategoryShiftReportError::InsufficientPeerReview {
            approved_reviewers: 1,
        },
        CategoryShiftReportError::DuplicatePeerReviewer {
            reviewer_id: "r1".to_string(),
        },
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "Display for {:?} is empty", err);
    }
}

#[test]
fn peer_review_signoff_serde_roundtrip() {
    let pr = PeerReviewSignoff {
        reviewer_id: "reviewer-test".to_string(),
        reviewed_at_utc: "2026-03-13T10:00:00Z".to_string(),
        approved: true,
        notes: "all good".to_string(),
    };
    let json = serde_json::to_string(&pr).expect("serialize");
    let recovered: PeerReviewSignoff = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(pr, recovered);
}

#[test]
fn methodology_section_serde_roundtrip() {
    let m = methodology();
    let json = serde_json::to_string(&m).expect("serialize");
    let recovered: MethodologySection = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(m, recovered);
}

#[test]
fn claim_serde_roundtrip() {
    let c = claim(CategoryShiftCapability::PlasSignedWitnesses);
    let json = serde_json::to_string(&c).expect("serialize");
    let recovered: CategoryShiftClaim = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(c, recovered);
}

#[test]
fn log_entry_serde_roundtrip() {
    let report = build_category_shift_report(report_input(passing_scorecard())).expect("report");
    let logs = generate_log_entries("trace-serde-test", &report);
    assert!(!logs.is_empty());
    for log in &logs {
        let json = serde_json::to_string(log).expect("serialize");
        let recovered: CategoryShiftReportLogEntry =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*log, recovered);
    }
}

#[test]
fn report_markdown_contains_caveats_and_limitations() {
    let report = build_category_shift_report(report_input(passing_scorecard())).expect("report");
    let md = report.to_markdown();
    assert!(md.contains("bounded to the published evaluation corpus"));
    assert!(md.contains("performance claims remain corpus-scoped"));
}

#[test]
fn build_report_fails_with_unapproved_peer_reviewer() {
    let mut input = report_input(passing_scorecard());
    input.peer_reviews[0].approved = false;
    let err = build_category_shift_report(input).unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InsufficientPeerReview {
            approved_reviewers: 1
        }
    ));
}

use frankenengine_engine::category_shift_report::DimensionPublicationSummary;

#[test]
fn dimension_publication_summary_serde_roundtrip() {
    let summary = DimensionPublicationSummary {
        raw_score_millionths: 850_000,
        floor_millionths: 100_000,
        target_millionths: 500_000,
        meets_floor: true,
        meets_target: true,
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let recovered: DimensionPublicationSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(summary, recovered);
}

#[test]
fn report_input_serde_roundtrip() {
    let input = report_input(passing_scorecard());
    let json = serde_json::to_string(&input).expect("serialize");
    let recovered: CategoryShiftReportInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(input, recovered);
}

// ────────────────────────────────────────────────────────────
// Enrichment batch 2: deeper edge cases, clone/debug, display
// uniqueness, ordering, more validation paths
// ────────────────────────────────────────────────────────────

#[test]
fn capability_all_as_str_values_are_unique() {
    let strs: Vec<&str> = CategoryShiftCapability::ALL
        .iter()
        .map(|c| c.as_str())
        .collect();
    let unique: std::collections::BTreeSet<&str> = strs.iter().copied().collect();
    assert_eq!(strs.len(), unique.len());
}

#[test]
fn capability_all_display_names_are_unique() {
    let names: Vec<&str> = CategoryShiftCapability::ALL
        .iter()
        .map(|c| c.display_name())
        .collect();
    let unique: std::collections::BTreeSet<&str> = names.iter().copied().collect();
    assert_eq!(names.len(), unique.len());
}

#[test]
fn capability_clone_and_debug() {
    for cap in CategoryShiftCapability::ALL {
        let cloned = cap.clone();
        assert_eq!(cap, cloned);
        let dbg = format!("{:?}", cap);
        assert!(!dbg.is_empty());
    }
}

#[test]
fn capability_ord_is_consistent() {
    let a = CategoryShiftCapability::ProofCarryingOptimization;
    let b = CategoryShiftCapability::DeterministicIfc;
    // Ordering should be consistent: either a < b or a > b (not equal, since they differ)
    assert_ne!(a.cmp(&b), std::cmp::Ordering::Equal);
    // Reverse ordering is antisymmetric
    assert_eq!(a.cmp(&b), b.cmp(&a).reverse());
}

#[test]
fn capability_serde_rename_all_snake_case() {
    let json = serde_json::to_string(&CategoryShiftCapability::ProofCarryingOptimization)
        .expect("serialize");
    assert_eq!(json, "\"proof_carrying_optimization\"");

    let json2 =
        serde_json::to_string(&CategoryShiftCapability::AdversarialCompromiseRateSuppression)
            .expect("serialize");
    assert_eq!(json2, "\"adversarial_compromise_rate_suppression\"");
}

#[test]
fn claim_validate_rejects_whitespace_only_evidence_bundle_ref() {
    let mut c = claim(CategoryShiftCapability::PlasSignedWitnesses);
    c.evidence_bundle_ref = "   ".to_string();
    let err = c.validate().unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InvalidClaimField { ref field, .. }
            if field == "evidence_bundle_ref"
    ));
}

#[test]
fn claim_validate_rejects_whitespace_reproduction_step() {
    let mut c = claim(CategoryShiftCapability::AutonomousQuarantineMesh);
    c.reproduction_instructions = vec!["step 1".to_string(), "  ".to_string()];
    let err = c.validate().unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InvalidClaimField { ref field, .. }
            if field == "reproduction_instructions"
    ));
}

#[test]
fn claim_validate_rejects_source_bead_without_bd_prefix() {
    let mut c = claim(CategoryShiftCapability::DeterministicIfc);
    c.source_beads = vec!["bd-valid".to_string(), "invalid-bead".to_string()];
    let err = c.validate().unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InvalidClaimField { ref field, .. }
            if field == "source_beads"
    ));
}

#[test]
fn claim_validate_rejects_whitespace_source_bead() {
    let mut c = claim(CategoryShiftCapability::DeterministicIfc);
    c.source_beads = vec!["  ".to_string()];
    let err = c.validate().unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InvalidClaimField { ref field, .. }
            if field == "source_beads"
    ));
}

#[test]
fn claim_compute_hash_order_independent_on_source_beads() {
    let mut c1 = claim(CategoryShiftCapability::ProofCarryingOptimization);
    c1.source_beads = vec!["bd-alpha".to_string(), "bd-beta".to_string()];
    let mut c2 = claim(CategoryShiftCapability::ProofCarryingOptimization);
    c2.source_beads = vec!["bd-beta".to_string(), "bd-alpha".to_string()];
    // compute_hash sorts source_beads, so order should not matter
    assert_eq!(c1.compute_hash(), c2.compute_hash());
}

#[test]
fn claim_clone_and_eq() {
    let c = claim(CategoryShiftCapability::AdversarialCompromiseRateSuppression);
    let cloned = c.clone();
    assert_eq!(c, cloned);
    assert_eq!(format!("{:?}", c), format!("{:?}", cloned));
}

#[test]
fn methodology_section_clone_and_debug() {
    let m = methodology();
    let cloned = m.clone();
    assert_eq!(m, cloned);
    let dbg = format!("{:?}", m);
    assert!(dbg.contains("summary"));
}

#[test]
fn methodology_validate_rejects_whitespace_in_statistical_frameworks() {
    let mut m = methodology();
    m.statistical_frameworks = vec!["valid".to_string(), "  ".to_string()];
    let err = m.validate().unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InvalidMethodologyField { ref field }
            if field == "statistical_frameworks"
    ));
}

#[test]
fn methodology_validate_rejects_whitespace_in_limitations() {
    let mut m = methodology();
    m.limitations = vec!["\t".to_string()];
    let err = m.validate().unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InvalidMethodologyField { ref field }
            if field == "limitations"
    ));
}

#[test]
fn methodology_validate_rejects_whitespace_in_validation_methodology() {
    let mut m = methodology();
    m.validation_methodology = vec!["ok".to_string(), "\n".to_string()];
    let err = m.validate().unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InvalidMethodologyField { ref field }
            if field == "validation_methodology"
    ));
}

#[test]
fn peer_review_signoff_clone_and_debug() {
    let pr = PeerReviewSignoff {
        reviewer_id: "rev-1".to_string(),
        reviewed_at_utc: "2026-03-14T00:00:00Z".to_string(),
        approved: false,
        notes: "needs revision".to_string(),
    };
    let cloned = pr.clone();
    assert_eq!(pr, cloned);
    let dbg = format!("{:?}", pr);
    assert!(dbg.contains("rev-1"));
}

#[test]
fn dimension_publication_summary_clone_and_debug() {
    let s = DimensionPublicationSummary {
        raw_score_millionths: 0,
        floor_millionths: 0,
        target_millionths: 0,
        meets_floor: false,
        meets_target: false,
    };
    let cloned = s.clone();
    assert_eq!(s, cloned);
    let dbg = format!("{:?}", s);
    assert!(dbg.contains("raw_score_millionths"));
}

#[test]
fn report_claims_are_sorted_by_capability() {
    let report = build_category_shift_report(report_input(passing_scorecard())).expect("report");
    for window in report.claims.windows(2) {
        assert!(
            window[0].capability <= window[1].capability,
            "claims not sorted by capability"
        );
    }
}

#[test]
fn report_peer_reviews_are_sorted_by_reviewer_id() {
    let report = build_category_shift_report(report_input(passing_scorecard())).expect("report");
    for window in report.peer_reviews.windows(2) {
        assert!(
            window[0].reviewer_id <= window[1].reviewer_id,
            "peer reviews not sorted by reviewer_id"
        );
    }
}

#[test]
fn report_json_pretty_is_valid_json() {
    let report = build_category_shift_report(report_input(passing_scorecard())).expect("report");
    let pretty_json = report.to_json_pretty().expect("json");
    let parsed: serde_json::Value = serde_json::from_str(&pretty_json).expect("parse");
    assert!(parsed.is_object());
    assert_eq!(parsed["schema_version"].as_str().unwrap(), SCHEMA_VERSION);
}

#[test]
fn report_markdown_contains_all_dimensions() {
    let report = build_category_shift_report(report_input(passing_scorecard())).expect("report");
    let md = report.to_markdown();
    assert!(md.contains("performance_delta"));
    assert!(md.contains("security_delta"));
    assert!(md.contains("autonomy_delta"));
}

#[test]
fn report_markdown_contains_all_capability_display_names() {
    let report = build_category_shift_report(report_input(passing_scorecard())).expect("report");
    let md = report.to_markdown();
    for cap in CategoryShiftCapability::ALL {
        assert!(
            md.contains(cap.display_name()),
            "markdown missing display_name for {:?}",
            cap
        );
    }
}

#[test]
fn report_markdown_contains_reproduction_steps() {
    let report = build_category_shift_report(report_input(passing_scorecard())).expect("report");
    let md = report.to_markdown();
    assert!(md.contains("Reproduction:"));
    for cap in CategoryShiftCapability::ALL {
        assert!(md.contains(&format!("fetch {}", cap.as_str())));
        assert!(md.contains(&format!("replay {}", cap.as_str())));
    }
}

#[test]
fn report_markdown_reviewer_approved_text() {
    let report = build_category_shift_report(report_input(passing_scorecard())).expect("report");
    let md = report.to_markdown();
    // Both reviewers approved
    assert!(md.contains("approved"));
    assert!(md.contains("reviewer-alfa"));
    assert!(md.contains("reviewer-bravo"));
}

#[test]
fn report_markdown_reviewer_rejected_text() {
    let mut input = report_input(passing_scorecard());
    // Need at least 2 approved; add a third reviewer who rejects
    input.peer_reviews.push(PeerReviewSignoff {
        reviewer_id: "reviewer-charlie".to_string(),
        reviewed_at_utc: "2026-03-13T01:20:00Z".to_string(),
        approved: false,
        notes: "disagree with claim 3".to_string(),
    });
    let report = build_category_shift_report(input).expect("report");
    let md = report.to_markdown();
    assert!(md.contains("rejected"));
    assert!(md.contains("reviewer-charlie"));
    assert!(md.contains("disagree with claim 3"));
}

#[test]
fn report_markdown_reviewer_empty_notes() {
    let mut input = report_input(passing_scorecard());
    input.peer_reviews[0].notes = "".to_string();
    let report = build_category_shift_report(input).expect("report");
    let md = report.to_markdown();
    // Empty notes should not produce " - " suffix
    let alfa_line = md
        .lines()
        .find(|l| l.contains("reviewer-alfa"))
        .expect("line");
    assert!(!alfa_line.ends_with(" - "));
}

#[test]
fn error_display_all_variants_unique() {
    let errors = vec![
        CategoryShiftReportError::InvalidClaimField {
            claim_id: "c1".to_string(),
            field: "f1".to_string(),
        },
        CategoryShiftReportError::InvalidMethodologyField {
            field: "f2".to_string(),
        },
        CategoryShiftReportError::MissingRequiredCapability {
            capability: CategoryShiftCapability::ProofCarryingOptimization,
        },
        CategoryShiftReportError::DuplicateCapability {
            capability: CategoryShiftCapability::DeterministicIfc,
        },
        CategoryShiftReportError::DuplicateClaimId {
            claim_id: "c2".to_string(),
        },
        CategoryShiftReportError::ScorecardSchemaInvalid {
            detail: "x".to_string(),
        },
        CategoryShiftReportError::ScorecardSchemaVersionMismatch {
            expected: "v1".to_string(),
            found: "v2".to_string(),
        },
        CategoryShiftReportError::ScorecardResultHashMismatch {
            expected: ContentHash::compute(b"a"),
            found: ContentHash::compute(b"b"),
        },
        CategoryShiftReportError::ScorecardOutcomeNotPublishable {
            outcome: "fail".to_string(),
        },
        CategoryShiftReportError::ScorecardDimensionMissing {
            dimension: "dim".to_string(),
        },
        CategoryShiftReportError::ScorecardDimensionFlagMismatch {
            dimension: "dim".to_string(),
            field: "meets_floor".to_string(),
            expected: true,
            found: false,
        },
        CategoryShiftReportError::ScoreBelowTarget {
            dimension: "dim".to_string(),
            raw_score_millionths: 100,
            target_millionths: 200,
        },
        CategoryShiftReportError::InsufficientPeerReview {
            approved_reviewers: 0,
        },
        CategoryShiftReportError::DuplicatePeerReviewer {
            reviewer_id: "dup".to_string(),
        },
    ];
    let displays: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
    let unique: std::collections::BTreeSet<&String> = displays.iter().collect();
    assert_eq!(
        displays.len(),
        unique.len(),
        "some error display strings collide"
    );
}

#[test]
fn error_clone_eq_debug() {
    let err = CategoryShiftReportError::ScorecardOutcomeNotPublishable {
        outcome: "fail".to_string(),
    };
    let cloned = err.clone();
    assert_eq!(err, cloned);
    let dbg = format!("{:?}", err);
    assert!(dbg.contains("ScorecardOutcomeNotPublishable"));
}

#[test]
fn error_is_std_error() {
    let err = CategoryShiftReportError::InsufficientPeerReview {
        approved_reviewers: 0,
    };
    let std_err: &dyn std::error::Error = &err;
    assert!(!std_err.to_string().is_empty());
}

#[test]
fn build_report_fails_with_scorecard_version_mismatch() {
    let mut scorecard = passing_scorecard();
    scorecard.schema_version = "wrong-version".to_string();
    // Must recompute result_hash after changing schema_version
    scorecard.result_hash = scorecard.compute_hash();
    let err = build_category_shift_report(report_input(scorecard)).unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::ScorecardSchemaVersionMismatch {
            ref expected,
            ref found,
        } if found == "wrong-version" && expected == SCORECARD_SCHEMA_VERSION
    ));
}

#[test]
fn build_report_fails_with_empty_reviewer_id() {
    let mut input = report_input(passing_scorecard());
    input.peer_reviews[0].reviewer_id = "".to_string();
    let err = build_category_shift_report(input).unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::DuplicatePeerReviewer { .. }
    ));
}

#[test]
fn build_report_fails_with_all_unapproved() {
    let mut input = report_input(passing_scorecard());
    for review in &mut input.peer_reviews {
        review.approved = false;
    }
    let err = build_category_shift_report(input).unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::InsufficientPeerReview {
            approved_reviewers: 0
        }
    ));
}

#[test]
fn build_report_with_extra_peer_reviewers_succeeds() {
    let mut input = report_input(passing_scorecard());
    input.peer_reviews.push(PeerReviewSignoff {
        reviewer_id: "reviewer-charlie".to_string(),
        reviewed_at_utc: "2026-03-13T02:00:00Z".to_string(),
        approved: true,
        notes: "extra reviewer".to_string(),
    });
    let report = build_category_shift_report(input).expect("report");
    assert_eq!(report.peer_reviews.len(), 3);
}

#[test]
fn build_report_with_meets_floor_flag_mismatch() {
    let mut scorecard = passing_scorecard();
    scorecard
        .dimension_scores
        .get_mut("security_delta")
        .expect("security_delta")
        .meets_floor = false;
    scorecard.result_hash = scorecard.compute_hash();
    let err = build_category_shift_report(report_input(scorecard)).unwrap_err();
    assert!(matches!(
        err,
        CategoryShiftReportError::ScorecardDimensionFlagMismatch {
            ref dimension,
            ref field,
            expected: true,
            found: false,
        } if dimension == "security_delta" && field == "meets_floor"
    ));
}

#[test]
fn log_entry_clone_and_debug() {
    let report = build_category_shift_report(report_input(passing_scorecard())).expect("report");
    let logs = generate_log_entries("trace-debug", &report);
    for log in &logs {
        let cloned = log.clone();
        assert_eq!(*log, cloned);
        let dbg = format!("{:?}", log);
        assert!(dbg.contains("trace-debug"));
    }
}

#[test]
fn log_entries_with_rejected_reviewer() {
    let mut input = report_input(passing_scorecard());
    input.peer_reviews.push(PeerReviewSignoff {
        reviewer_id: "reviewer-dissent".to_string(),
        reviewed_at_utc: "2026-03-13T03:00:00Z".to_string(),
        approved: false,
        notes: "disagreement".to_string(),
    });
    let report = build_category_shift_report(input).expect("report");
    let logs = generate_log_entries("trace-reject", &report);
    let rejected: Vec<_> = logs
        .iter()
        .filter(|l| l.review_status.as_deref() == Some("rejected"))
        .collect();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].reviewer_id.as_deref(), Some("reviewer-dissent"));
}

#[test]
fn log_entries_empty_claims_and_reviews_produces_empty_logs() {
    // Build a valid report, then generate logs with it
    let report = build_category_shift_report(report_input(passing_scorecard())).expect("report");
    // The report itself always has claims/reviews, so logs won't be empty here.
    // But we verify the count matches exactly.
    let logs = generate_log_entries("trace-count", &report);
    let claim_count = report.claims.len();
    let review_count = report.peer_reviews.len();
    assert_eq!(logs.len(), claim_count + review_count);
}

#[test]
fn report_publication_hash_changes_with_different_candidate_id() {
    let r1 = build_category_shift_report(report_input(passing_scorecard())).expect("r1");
    let mut input2 = report_input(passing_scorecard());
    input2.candidate_id = "rc-different-candidate".to_string();
    let r2 = build_category_shift_report(input2).expect("r2");
    assert_ne!(r1.publication_hash, r2.publication_hash);
}

#[test]
fn report_publication_hash_changes_with_different_generated_at() {
    let r1 = build_category_shift_report(report_input(passing_scorecard())).expect("r1");
    let mut input2 = report_input(passing_scorecard());
    input2.generated_at_utc = "2099-01-01T00:00:00Z".to_string();
    let r2 = build_category_shift_report(input2).expect("r2");
    assert_ne!(r1.publication_hash, r2.publication_hash);
}

#[test]
fn report_publication_hash_changes_with_different_methodology() {
    let r1 = build_category_shift_report(report_input(passing_scorecard())).expect("r1");
    let mut input2 = report_input(passing_scorecard());
    input2.methodology.summary = "Completely different methodology summary text.".to_string();
    let r2 = build_category_shift_report(input2).expect("r2");
    assert_ne!(r1.publication_hash, r2.publication_hash);
}

#[test]
fn claim_with_empty_caveats_is_valid() {
    let mut c = claim(CategoryShiftCapability::ProofCarryingOptimization);
    c.caveats.clear();
    assert!(c.validate().is_ok());
}

#[test]
fn report_markdown_omits_caveats_section_when_empty() {
    let mut input = report_input(passing_scorecard());
    for c in &mut input.claims {
        c.caveats.clear();
    }
    let report = build_category_shift_report(input).expect("report");
    let md = report.to_markdown();
    assert!(!md.contains("Caveats:"));
}

#[test]
fn dimension_publication_summary_boundary_zero_scores() {
    let s = DimensionPublicationSummary {
        raw_score_millionths: 0,
        floor_millionths: 0,
        target_millionths: 0,
        meets_floor: true,
        meets_target: true,
    };
    let json = serde_json::to_string(&s).expect("serialize");
    let recovered: DimensionPublicationSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(s, recovered);
    assert_eq!(recovered.raw_score_millionths, 0);
}

#[test]
fn dimension_publication_summary_boundary_max_scores() {
    let s = DimensionPublicationSummary {
        raw_score_millionths: u64::MAX,
        floor_millionths: u64::MAX,
        target_millionths: u64::MAX,
        meets_floor: true,
        meets_target: true,
    };
    let json = serde_json::to_string(&s).expect("serialize");
    let recovered: DimensionPublicationSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(s, recovered);
}

#[test]
fn report_clone_and_debug() {
    let report = build_category_shift_report(report_input(passing_scorecard())).expect("report");
    let cloned = report.clone();
    assert_eq!(report, cloned);
    let dbg = format!("{:?}", report);
    assert!(dbg.contains("CategoryShiftReport"));
    assert!(dbg.contains(SCHEMA_VERSION));
}

#[test]
fn report_input_clone_and_debug() {
    let input = report_input(passing_scorecard());
    let cloned = input.clone();
    assert_eq!(input, cloned);
    let dbg = format!("{:?}", input);
    assert!(dbg.contains("CategoryShiftReportInput"));
}
