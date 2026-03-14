//! Deterministic publication contract for beyond-parity category-shift reports.
//!
//! Bead: bd-f7n [10.9]
//!
//! This surface packages the capstone moonshot report that synthesizes
//! disruption-scorecard results, evidence-backed beyond-parity claims, peer
//! review, and publication metadata into a deterministic JSON + Markdown
//! artifact pair.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::disruption_scorecard::{DisruptionDimension, ScorecardResult, ScorecardSchema};
use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const SCHEMA_VERSION: &str = "franken-engine.category-shift-report.v1";
pub const COMPONENT: &str = "category_shift_report";
pub const BEAD_ID: &str = "bd-f7n";
pub const POLICY_ID: &str = "section-10.9-category-shift";
pub const MINIMUM_PEER_REVIEWERS: usize = 2;

// ---------------------------------------------------------------------------
// CategoryShiftCapability
// ---------------------------------------------------------------------------

/// Minimum beyond-parity capabilities that the first published report must cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CategoryShiftCapability {
    ProofCarryingOptimization,
    DeterministicIfc,
    PlasSignedWitnesses,
    AutonomousQuarantineMesh,
    AdversarialCompromiseRateSuppression,
}

impl CategoryShiftCapability {
    pub const ALL: [Self; 5] = [
        Self::ProofCarryingOptimization,
        Self::DeterministicIfc,
        Self::PlasSignedWitnesses,
        Self::AutonomousQuarantineMesh,
        Self::AdversarialCompromiseRateSuppression,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProofCarryingOptimization => "proof_carrying_optimization",
            Self::DeterministicIfc => "deterministic_ifc",
            Self::PlasSignedWitnesses => "plas_signed_witnesses",
            Self::AutonomousQuarantineMesh => "autonomous_quarantine_mesh",
            Self::AdversarialCompromiseRateSuppression => "adversarial_compromise_rate_suppression",
        }
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::ProofCarryingOptimization => "Proof-Carrying Optimization",
            Self::DeterministicIfc => "Deterministic IFC",
            Self::PlasSignedWitnesses => "PLAS with Signed Witnesses",
            Self::AutonomousQuarantineMesh => "Autonomous Quarantine Mesh",
            Self::AdversarialCompromiseRateSuppression => "Adversarial Compromise-Rate Suppression",
        }
    }
}

impl fmt::Display for CategoryShiftCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Claim / methodology / review data
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryShiftClaim {
    pub claim_id: String,
    pub capability: CategoryShiftCapability,
    pub claim_statement: String,
    pub evidence_summary: String,
    pub evidence_bundle_ref: String,
    pub evidence_hash: ContentHash,
    pub reproduction_instructions: Vec<String>,
    pub source_beads: Vec<String>,
    pub caveats: Vec<String>,
}

impl CategoryShiftClaim {
    pub fn validate(&self) -> Result<(), CategoryShiftReportError> {
        if self.claim_id.trim().is_empty() {
            return Err(CategoryShiftReportError::InvalidClaimField {
                claim_id: self.claim_id.clone(),
                field: "claim_id".to_string(),
            });
        }
        if self.claim_statement.trim().is_empty() {
            return Err(CategoryShiftReportError::InvalidClaimField {
                claim_id: self.claim_id.clone(),
                field: "claim_statement".to_string(),
            });
        }
        if self.evidence_summary.trim().is_empty() {
            return Err(CategoryShiftReportError::InvalidClaimField {
                claim_id: self.claim_id.clone(),
                field: "evidence_summary".to_string(),
            });
        }
        if self.evidence_bundle_ref.trim().is_empty() {
            return Err(CategoryShiftReportError::InvalidClaimField {
                claim_id: self.claim_id.clone(),
                field: "evidence_bundle_ref".to_string(),
            });
        }
        if self.reproduction_instructions.is_empty()
            || self
                .reproduction_instructions
                .iter()
                .any(|step| step.trim().is_empty())
        {
            return Err(CategoryShiftReportError::InvalidClaimField {
                claim_id: self.claim_id.clone(),
                field: "reproduction_instructions".to_string(),
            });
        }
        if self.source_beads.is_empty()
            || self
                .source_beads
                .iter()
                .any(|bead| bead.trim().is_empty() || !bead.starts_with("bd-"))
        {
            return Err(CategoryShiftReportError::InvalidClaimField {
                claim_id: self.claim_id.clone(),
                field: "source_beads".to_string(),
            });
        }
        Ok(())
    }

    pub fn compute_hash(&self) -> ContentHash {
        let mut source_beads = self.source_beads.clone();
        source_beads.sort();
        let canonical = [
            self.claim_id.clone(),
            self.capability.as_str().to_string(),
            self.claim_statement.clone(),
            self.evidence_summary.clone(),
            self.evidence_bundle_ref.clone(),
            self.evidence_hash.to_string(),
            self.reproduction_instructions.join("||"),
            source_beads.join("|"),
            self.caveats.join("||"),
        ]
        .join("|");
        ContentHash::compute(canonical.as_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodologySection {
    pub summary: String,
    pub statistical_frameworks: Vec<String>,
    pub validation_methodology: Vec<String>,
    pub limitations: Vec<String>,
}

impl MethodologySection {
    pub fn validate(&self) -> Result<(), CategoryShiftReportError> {
        if self.summary.trim().is_empty() {
            return Err(CategoryShiftReportError::InvalidMethodologyField {
                field: "summary".to_string(),
            });
        }
        if self.statistical_frameworks.is_empty()
            || self
                .statistical_frameworks
                .iter()
                .any(|item| item.trim().is_empty())
        {
            return Err(CategoryShiftReportError::InvalidMethodologyField {
                field: "statistical_frameworks".to_string(),
            });
        }
        if self.validation_methodology.is_empty()
            || self
                .validation_methodology
                .iter()
                .any(|item| item.trim().is_empty())
        {
            return Err(CategoryShiftReportError::InvalidMethodologyField {
                field: "validation_methodology".to_string(),
            });
        }
        if self.limitations.is_empty() || self.limitations.iter().any(|item| item.trim().is_empty())
        {
            return Err(CategoryShiftReportError::InvalidMethodologyField {
                field: "limitations".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerReviewSignoff {
    pub reviewer_id: String,
    pub reviewed_at_utc: String,
    pub approved: bool,
    pub notes: String,
}

// ---------------------------------------------------------------------------
// Report summaries / output
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DimensionPublicationSummary {
    pub raw_score_millionths: u64,
    pub floor_millionths: u64,
    pub target_millionths: u64,
    pub meets_floor: bool,
    pub meets_target: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryShiftReportInput {
    pub report_version: String,
    pub candidate_id: String,
    pub generated_at_utc: String,
    pub archive_root: String,
    pub scorecard_schema: ScorecardSchema,
    pub scorecard_result: ScorecardResult,
    pub claims: Vec<CategoryShiftClaim>,
    pub methodology: MethodologySection,
    pub peer_reviews: Vec<PeerReviewSignoff>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryShiftReport {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub policy_id: String,
    pub report_version: String,
    pub candidate_id: String,
    pub generated_at_utc: String,
    pub archive_root: String,
    pub scorecard_result_hash: ContentHash,
    pub scorecard_outcome: String,
    pub dimension_summaries: BTreeMap<String, DimensionPublicationSummary>,
    pub claims: Vec<CategoryShiftClaim>,
    pub methodology: MethodologySection,
    pub peer_reviews: Vec<PeerReviewSignoff>,
    pub publication_hash: ContentHash,
}

impl CategoryShiftReport {
    pub fn compute_hash(&self) -> ContentHash {
        let mut parts = vec![
            self.schema_version.clone(),
            self.component.clone(),
            self.bead_id.clone(),
            self.policy_id.clone(),
            self.report_version.clone(),
            self.candidate_id.clone(),
            self.generated_at_utc.clone(),
            self.archive_root.clone(),
            self.scorecard_result_hash.to_string(),
            self.scorecard_outcome.clone(),
        ];

        for (dimension, summary) in &self.dimension_summaries {
            parts.push(format!(
                "{dimension}:{}:{}:{}:{}:{}",
                summary.raw_score_millionths,
                summary.floor_millionths,
                summary.target_millionths,
                summary.meets_floor,
                summary.meets_target
            ));
        }

        for claim in &self.claims {
            parts.push(claim.compute_hash().to_string());
        }

        parts.push(self.methodology.summary.clone());
        parts.push(self.methodology.statistical_frameworks.join("|"));
        parts.push(self.methodology.validation_methodology.join("|"));
        parts.push(self.methodology.limitations.join("|"));

        for review in &self.peer_reviews {
            parts.push(format!(
                "{}:{}:{}:{}",
                review.reviewer_id, review.reviewed_at_utc, review.approved, review.notes
            ));
        }

        ContentHash::compute(parts.join("|").as_bytes())
    }

    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# First Category-Shift Report\n\n");
        out.push_str(&format!(
            "- Report version: `{}`\n- Candidate: `{}`\n- Generated at: `{}`\n- Publication hash: `{}`\n- Archive root: `{}`\n\n",
            self.report_version,
            self.candidate_id,
            self.generated_at_utc,
            self.publication_hash,
            self.archive_root
        ));

        out.push_str("## Disruption Scorecard\n\n");
        out.push_str("| Dimension | Raw | Floor | Target | Meets target |\n");
        out.push_str("| --- | ---: | ---: | ---: | --- |\n");
        for (dimension, summary) in &self.dimension_summaries {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                dimension,
                summary.raw_score_millionths,
                summary.floor_millionths,
                summary.target_millionths,
                if summary.meets_target { "yes" } else { "no" }
            ));
        }
        out.push('\n');

        out.push_str("## Beyond-Parity Claims\n\n");
        for claim in &self.claims {
            out.push_str(&format!(
                "### {} (`{}`)\n\n{}\n\nEvidence summary: {}\n\nEvidence bundle: `{}` (`{}`)\n\nSource beads: {}\n\n",
                claim.capability.display_name(),
                claim.claim_id,
                claim.claim_statement,
                claim.evidence_summary,
                claim.evidence_bundle_ref,
                claim.evidence_hash,
                claim.source_beads.join(", ")
            ));
            out.push_str("Reproduction:\n");
            for step in &claim.reproduction_instructions {
                out.push_str(&format!("- {}\n", step));
            }
            if !claim.caveats.is_empty() {
                out.push_str("\nCaveats:\n");
                for caveat in &claim.caveats {
                    out.push_str(&format!("- {}\n", caveat));
                }
            }
            out.push('\n');
        }

        out.push_str("## Methodology\n\n");
        out.push_str(&self.methodology.summary);
        out.push_str("\n\nStatistical frameworks:\n");
        for item in &self.methodology.statistical_frameworks {
            out.push_str(&format!("- {}\n", item));
        }
        out.push_str("\nValidation methodology:\n");
        for item in &self.methodology.validation_methodology {
            out.push_str(&format!("- {}\n", item));
        }
        out.push_str("\nKnown limitations:\n");
        for item in &self.methodology.limitations {
            out.push_str(&format!("- {}\n", item));
        }

        out.push_str("\n## Peer Review\n\n");
        for review in &self.peer_reviews {
            out.push_str(&format!(
                "- `{}` at `{}`: {}{}\n",
                review.reviewer_id,
                review.reviewed_at_utc,
                if review.approved {
                    "approved"
                } else {
                    "rejected"
                },
                if review.notes.trim().is_empty() {
                    String::new()
                } else {
                    format!(" - {}", review.notes)
                }
            ));
        }

        out
    }
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryShiftReportLogEntry {
    pub trace_id: String,
    pub report_version: String,
    pub component: String,
    pub event: String,
    pub claim_id: Option<String>,
    pub evidence_bundle_ref: Option<String>,
    pub evidence_hash: Option<ContentHash>,
    pub reviewer_id: Option<String>,
    pub review_status: Option<String>,
    pub publication_hash: ContentHash,
}

pub fn generate_log_entries(
    trace_id: &str,
    report: &CategoryShiftReport,
) -> Vec<CategoryShiftReportLogEntry> {
    let mut entries = Vec::new();

    for claim in &report.claims {
        entries.push(CategoryShiftReportLogEntry {
            trace_id: trace_id.to_string(),
            report_version: report.report_version.clone(),
            component: COMPONENT.to_string(),
            event: "claim_published".to_string(),
            claim_id: Some(claim.claim_id.clone()),
            evidence_bundle_ref: Some(claim.evidence_bundle_ref.clone()),
            evidence_hash: Some(claim.evidence_hash),
            reviewer_id: None,
            review_status: None,
            publication_hash: report.publication_hash,
        });
    }

    for review in &report.peer_reviews {
        entries.push(CategoryShiftReportLogEntry {
            trace_id: trace_id.to_string(),
            report_version: report.report_version.clone(),
            component: COMPONENT.to_string(),
            event: "peer_review_recorded".to_string(),
            claim_id: None,
            evidence_bundle_ref: None,
            evidence_hash: None,
            reviewer_id: Some(review.reviewer_id.clone()),
            review_status: Some(if review.approved {
                "approved".to_string()
            } else {
                "rejected".to_string()
            }),
            publication_hash: report.publication_hash,
        });
    }

    entries
}

// ---------------------------------------------------------------------------
// Errors / builders
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CategoryShiftReportError {
    InvalidClaimField {
        claim_id: String,
        field: String,
    },
    InvalidMethodologyField {
        field: String,
    },
    MissingRequiredCapability {
        capability: CategoryShiftCapability,
    },
    DuplicateCapability {
        capability: CategoryShiftCapability,
    },
    DuplicateClaimId {
        claim_id: String,
    },
    ScorecardSchemaInvalid {
        detail: String,
    },
    ScorecardSchemaVersionMismatch {
        expected: String,
        found: String,
    },
    ScorecardResultHashMismatch {
        expected: ContentHash,
        found: ContentHash,
    },
    ScorecardOutcomeNotPublishable {
        outcome: String,
    },
    ScorecardDimensionMissing {
        dimension: String,
    },
    ScorecardDimensionFlagMismatch {
        dimension: String,
        field: String,
        expected: bool,
        found: bool,
    },
    ScoreBelowTarget {
        dimension: String,
        raw_score_millionths: u64,
        target_millionths: u64,
    },
    InsufficientPeerReview {
        approved_reviewers: usize,
    },
    DuplicatePeerReviewer {
        reviewer_id: String,
    },
}

impl fmt::Display for CategoryShiftReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidClaimField { claim_id, field } => {
                write!(f, "invalid claim field `{field}` for claim `{claim_id}`")
            }
            Self::InvalidMethodologyField { field } => {
                write!(f, "invalid methodology field `{field}`")
            }
            Self::MissingRequiredCapability { capability } => {
                write!(f, "missing required capability `{capability}`")
            }
            Self::DuplicateCapability { capability } => {
                write!(f, "duplicate capability `{capability}`")
            }
            Self::DuplicateClaimId { claim_id } => write!(f, "duplicate claim id `{claim_id}`"),
            Self::ScorecardSchemaInvalid { detail } => {
                write!(f, "invalid scorecard schema: {detail}")
            }
            Self::ScorecardSchemaVersionMismatch { expected, found } => write!(
                f,
                "scorecard schema version mismatch: expected `{expected}`, found `{found}`"
            ),
            Self::ScorecardResultHashMismatch { expected, found } => write!(
                f,
                "scorecard result hash mismatch: expected `{expected}`, found `{found}`"
            ),
            Self::ScorecardOutcomeNotPublishable { outcome } => {
                write!(f, "scorecard outcome `{outcome}` is not publishable")
            }
            Self::ScorecardDimensionMissing { dimension } => {
                write!(f, "scorecard missing dimension `{dimension}`")
            }
            Self::ScorecardDimensionFlagMismatch {
                dimension,
                field,
                expected,
                found,
            } => write!(
                f,
                "scorecard dimension `{dimension}` has inconsistent `{field}` flag: expected `{expected}`, found `{found}`"
            ),
            Self::ScoreBelowTarget {
                dimension,
                raw_score_millionths,
                target_millionths,
            } => write!(
                f,
                "scorecard dimension `{dimension}` below target: {raw_score_millionths} < {target_millionths}"
            ),
            Self::InsufficientPeerReview { approved_reviewers } => write!(
                f,
                "insufficient approved peer reviews: {approved_reviewers} < {MINIMUM_PEER_REVIEWERS}"
            ),
            Self::DuplicatePeerReviewer { reviewer_id } => {
                write!(f, "duplicate peer reviewer `{reviewer_id}`")
            }
        }
    }
}

impl std::error::Error for CategoryShiftReportError {}

pub fn build_category_shift_report(
    input: CategoryShiftReportInput,
) -> Result<CategoryShiftReport, CategoryShiftReportError> {
    input.methodology.validate()?;
    input.scorecard_schema.validate().map_err(|err| {
        CategoryShiftReportError::ScorecardSchemaInvalid {
            detail: err.to_string(),
        }
    })?;

    let computed_result_hash = input.scorecard_result.compute_hash();
    if input.scorecard_result.result_hash != computed_result_hash {
        return Err(CategoryShiftReportError::ScorecardResultHashMismatch {
            expected: computed_result_hash,
            found: input.scorecard_result.result_hash,
        });
    }

    let expected_scorecard_version = input.scorecard_schema.version.clone();
    let found_scorecard_version = input.scorecard_result.schema_version.clone();
    if found_scorecard_version != expected_scorecard_version {
        return Err(CategoryShiftReportError::ScorecardSchemaVersionMismatch {
            expected: expected_scorecard_version,
            found: found_scorecard_version,
        });
    }

    if !input.scorecard_result.outcome.is_pass() {
        return Err(CategoryShiftReportError::ScorecardOutcomeNotPublishable {
            outcome: input.scorecard_result.outcome.to_string(),
        });
    }

    let mut seen_claim_ids = BTreeSet::new();
    let mut seen_capabilities = BTreeSet::new();
    let mut claims = input.claims;
    claims.sort_by_key(|claim| claim.capability);
    for claim in &claims {
        claim.validate()?;
        if !seen_claim_ids.insert(claim.claim_id.clone()) {
            return Err(CategoryShiftReportError::DuplicateClaimId {
                claim_id: claim.claim_id.clone(),
            });
        }
        if !seen_capabilities.insert(claim.capability) {
            return Err(CategoryShiftReportError::DuplicateCapability {
                capability: claim.capability,
            });
        }
    }

    for capability in CategoryShiftCapability::ALL {
        if !seen_capabilities.contains(&capability) {
            return Err(CategoryShiftReportError::MissingRequiredCapability { capability });
        }
    }

    let mut dimension_summaries = BTreeMap::new();
    for dimension in DisruptionDimension::all() {
        let key = dimension.as_str();
        let threshold = input.scorecard_schema.thresholds.get(key).ok_or_else(|| {
            CategoryShiftReportError::ScorecardDimensionMissing {
                dimension: key.to_string(),
            }
        })?;
        let score = input
            .scorecard_result
            .dimension_scores
            .get(key)
            .ok_or_else(|| CategoryShiftReportError::ScorecardDimensionMissing {
                dimension: key.to_string(),
            })?;
        let expected_meets_floor = threshold.meets_floor(score.raw_score_millionths);
        if score.meets_floor != expected_meets_floor {
            return Err(CategoryShiftReportError::ScorecardDimensionFlagMismatch {
                dimension: key.to_string(),
                field: "meets_floor".to_string(),
                expected: expected_meets_floor,
                found: score.meets_floor,
            });
        }
        let expected_meets_target = threshold.meets_target(score.raw_score_millionths);
        if score.meets_target != expected_meets_target {
            return Err(CategoryShiftReportError::ScorecardDimensionFlagMismatch {
                dimension: key.to_string(),
                field: "meets_target".to_string(),
                expected: expected_meets_target,
                found: score.meets_target,
            });
        }
        if score.raw_score_millionths < threshold.target_millionths {
            return Err(CategoryShiftReportError::ScoreBelowTarget {
                dimension: key.to_string(),
                raw_score_millionths: score.raw_score_millionths,
                target_millionths: threshold.target_millionths,
            });
        }
        dimension_summaries.insert(
            key.to_string(),
            DimensionPublicationSummary {
                raw_score_millionths: score.raw_score_millionths,
                floor_millionths: threshold.floor_millionths,
                target_millionths: threshold.target_millionths,
                meets_floor: expected_meets_floor,
                meets_target: expected_meets_target,
            },
        );
    }

    let mut peer_reviews = input.peer_reviews;
    peer_reviews.sort_by(|left, right| left.reviewer_id.cmp(&right.reviewer_id));
    let mut reviewer_ids = BTreeSet::new();
    let approved_reviewers = peer_reviews.iter().filter(|review| review.approved).count();
    for review in &peer_reviews {
        if review.reviewer_id.trim().is_empty() {
            return Err(CategoryShiftReportError::DuplicatePeerReviewer {
                reviewer_id: review.reviewer_id.clone(),
            });
        }
        if !reviewer_ids.insert(review.reviewer_id.clone()) {
            return Err(CategoryShiftReportError::DuplicatePeerReviewer {
                reviewer_id: review.reviewer_id.clone(),
            });
        }
    }
    if approved_reviewers < MINIMUM_PEER_REVIEWERS {
        return Err(CategoryShiftReportError::InsufficientPeerReview { approved_reviewers });
    }

    let mut report = CategoryShiftReport {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        report_version: input.report_version,
        candidate_id: input.candidate_id,
        generated_at_utc: input.generated_at_utc,
        archive_root: input.archive_root,
        scorecard_result_hash: computed_result_hash,
        scorecard_outcome: input.scorecard_result.outcome.to_string(),
        dimension_summaries,
        claims,
        methodology: input.methodology,
        peer_reviews,
        publication_hash: ContentHash::compute(b"placeholder"),
    };
    report.publication_hash = report.compute_hash();
    Ok(report)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disruption_scorecard::{EvidenceInput, compute_scorecard};
    use crate::security_epoch::SecurityEpoch;

    fn evidence(dimension: DisruptionDimension, score: u64, bead: &str) -> EvidenceInput {
        EvidenceInput {
            dimension,
            raw_score_millionths: score,
            source_beads: vec![bead.to_string()],
            evidence_hash: ContentHash::compute(format!("{dimension}:{score}").as_bytes()),
        }
    }

    fn scorecard_result() -> ScorecardResult {
        compute_scorecard(
            &ScorecardSchema::default_schema(),
            &[
                evidence(DisruptionDimension::PerformanceDelta, 150_000, "bd-1ze"),
                evidence(DisruptionDimension::SecurityDelta, 850_000, "bd-eke"),
                evidence(DisruptionDimension::AutonomyDelta, 950_000, "bd-2n3"),
            ],
            SecurityEpoch::from_raw(7),
            "unit-test".to_string(),
        )
        .expect("scorecard")
    }

    fn claim(capability: CategoryShiftCapability) -> CategoryShiftClaim {
        CategoryShiftClaim {
            claim_id: capability.as_str().to_string(),
            capability,
            claim_statement: format!("{} is demonstrated", capability.display_name()),
            evidence_summary: format!("{} summary", capability.display_name()),
            evidence_bundle_ref: format!("archive/{}.json", capability.as_str()),
            evidence_hash: ContentHash::compute(capability.as_str().as_bytes()),
            reproduction_instructions: vec![format!("rerun {}", capability.as_str())],
            source_beads: vec!["bd-source".to_string()],
            caveats: vec!["bounded to shipped corpus".to_string()],
        }
    }

    fn methodology() -> MethodologySection {
        MethodologySection {
            summary: "Independent scorecard-backed synthesis".to_string(),
            statistical_frameworks: vec!["paired benchmark deltas".to_string()],
            validation_methodology: vec!["independent reproduction spot-checks".to_string()],
            limitations: vec!["benchmarks remain corpus-bound".to_string()],
        }
    }

    fn peer_reviews() -> Vec<PeerReviewSignoff> {
        vec![
            PeerReviewSignoff {
                reviewer_id: "reviewer-a".to_string(),
                reviewed_at_utc: "2026-03-13T00:00:00Z".to_string(),
                approved: true,
                notes: "accurate".to_string(),
            },
            PeerReviewSignoff {
                reviewer_id: "reviewer-b".to_string(),
                reviewed_at_utc: "2026-03-13T00:10:00Z".to_string(),
                approved: true,
                notes: "fair caveats".to_string(),
            },
        ]
    }

    #[test]
    fn build_report_rejects_missing_capability() {
        let claims = CategoryShiftCapability::ALL[..4]
            .iter()
            .copied()
            .map(claim)
            .collect::<Vec<_>>();
        let err = build_category_shift_report(CategoryShiftReportInput {
            report_version: "v1".to_string(),
            candidate_id: "rc-1".to_string(),
            generated_at_utc: "2026-03-13T00:00:00Z".to_string(),
            archive_root: "archive/root".to_string(),
            scorecard_schema: ScorecardSchema::default_schema(),
            scorecard_result: scorecard_result(),
            claims,
            methodology: methodology(),
            peer_reviews: peer_reviews(),
        })
        .unwrap_err();
        assert!(matches!(
            err,
            CategoryShiftReportError::MissingRequiredCapability { .. }
        ));
    }

    #[test]
    fn build_report_rejects_insufficient_peer_review() {
        let claims = CategoryShiftCapability::ALL
            .iter()
            .copied()
            .map(claim)
            .collect::<Vec<_>>();
        let err = build_category_shift_report(CategoryShiftReportInput {
            report_version: "v1".to_string(),
            candidate_id: "rc-1".to_string(),
            generated_at_utc: "2026-03-13T00:00:00Z".to_string(),
            archive_root: "archive/root".to_string(),
            scorecard_schema: ScorecardSchema::default_schema(),
            scorecard_result: scorecard_result(),
            claims,
            methodology: methodology(),
            peer_reviews: vec![PeerReviewSignoff {
                reviewer_id: "solo".to_string(),
                reviewed_at_utc: "2026-03-13T00:00:00Z".to_string(),
                approved: true,
                notes: "not enough".to_string(),
            }],
        })
        .unwrap_err();
        assert!(matches!(
            err,
            CategoryShiftReportError::InsufficientPeerReview { .. }
        ));
    }

    #[test]
    fn generated_log_entries_cover_claims_and_reviews() {
        let claims = CategoryShiftCapability::ALL
            .iter()
            .copied()
            .map(claim)
            .collect::<Vec<_>>();
        let report = build_category_shift_report(CategoryShiftReportInput {
            report_version: "v1".to_string(),
            candidate_id: "rc-1".to_string(),
            generated_at_utc: "2026-03-13T00:00:00Z".to_string(),
            archive_root: "archive/root".to_string(),
            scorecard_schema: ScorecardSchema::default_schema(),
            scorecard_result: scorecard_result(),
            claims,
            methodology: methodology(),
            peer_reviews: peer_reviews(),
        })
        .expect("report");

        let entries = generate_log_entries("trace-1", &report);
        assert_eq!(
            entries.len(),
            CategoryShiftCapability::ALL.len() + MINIMUM_PEER_REVIEWERS
        );
        assert!(entries.iter().any(|entry| entry.claim_id.is_some()));
        assert!(entries.iter().any(|entry| entry.reviewer_id.is_some()));
    }
}
