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
pub const REQUIRED_PREREQUISITE_BEADS: [&str; 9] = [
    "bd-1ze", "bd-181", "bd-2n3", "bd-2rx", "bd-3rd", "bd-6pk", "bd-dkh", "bd-eke", "bd-uwc",
];

fn is_canonical_repo_relative_path(path: &str) -> bool {
    let trimmed = path.trim();
    if trimmed != path || trimmed.is_empty() || trimmed.starts_with('/') || trimmed.ends_with('/') {
        return false;
    }
    trimmed.split('/').all(|segment| {
        !segment.is_empty() && segment != "." && segment != ".." && !segment.contains('\\')
    })
}

fn archive_path(archive_root: &str, relative_path: &str) -> String {
    format!(
        "{}/{}",
        archive_root.trim_end_matches('/'),
        relative_path.trim_start_matches('/')
    )
}

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
        if !is_canonical_repo_relative_path(&self.evidence_bundle_ref) {
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
            {
                let mut sorted_caveats = self.caveats.clone();
                sorted_caveats.sort();
                sorted_caveats.join("||")
            },
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrerequisiteGateRecord {
    pub bead_id: String,
    pub artifact_manifest: String,
    pub artifact_hash: ContentHash,
    pub summary: String,
    pub passed: bool,
}

impl PrerequisiteGateRecord {
    pub fn validate(&self) -> Result<(), CategoryShiftReportError> {
        if self.bead_id.trim().is_empty() || !self.bead_id.starts_with("bd-") {
            return Err(CategoryShiftReportError::InvalidPrerequisiteGateField {
                bead_id: self.bead_id.clone(),
                field: "bead_id".to_string(),
            });
        }
        if !is_canonical_repo_relative_path(&self.artifact_manifest) {
            return Err(CategoryShiftReportError::InvalidPrerequisiteGateField {
                bead_id: self.bead_id.clone(),
                field: "artifact_manifest".to_string(),
            });
        }
        if self.summary.trim().is_empty() {
            return Err(CategoryShiftReportError::InvalidPrerequisiteGateField {
                bead_id: self.bead_id.clone(),
                field: "summary".to_string(),
            });
        }
        Ok(())
    }

    pub fn compute_hash(&self) -> ContentHash {
        ContentHash::compute(
            format!(
                "{}|{}|{}|{}|{}",
                self.bead_id, self.artifact_manifest, self.artifact_hash, self.summary, self.passed
            )
            .as_bytes(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedArtifact {
    pub artifact_id: String,
    pub relative_path: String,
    pub kind: String,
    pub content_hash: ContentHash,
}

impl PublishedArtifact {
    pub fn validate(&self) -> Result<(), CategoryShiftReportError> {
        if self.artifact_id.trim().is_empty() {
            return Err(CategoryShiftReportError::InvalidPublishedArtifactField {
                artifact_id: self.artifact_id.clone(),
                field: "artifact_id".to_string(),
            });
        }
        if !is_canonical_repo_relative_path(&self.relative_path) {
            return Err(CategoryShiftReportError::InvalidPublishedArtifactField {
                artifact_id: self.artifact_id.clone(),
                field: "relative_path".to_string(),
            });
        }
        if self.kind.trim().is_empty() {
            return Err(CategoryShiftReportError::InvalidPublishedArtifactField {
                artifact_id: self.artifact_id.clone(),
                field: "kind".to_string(),
            });
        }
        Ok(())
    }

    pub fn compute_hash(&self) -> ContentHash {
        ContentHash::compute(
            format!(
                "{}|{}|{}|{}",
                self.artifact_id, self.relative_path, self.kind, self.content_hash
            )
            .as_bytes(),
        )
    }
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
    pub prerequisite_gates: Vec<PrerequisiteGateRecord>,
    pub published_artifacts: Vec<PublishedArtifact>,
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
    pub prerequisite_gates: Vec<PrerequisiteGateRecord>,
    pub published_artifacts: Vec<PublishedArtifact>,
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
        {
            let mut sf = self.methodology.statistical_frameworks.clone();
            sf.sort();
            parts.push(sf.join("|"));
        }
        {
            let mut vm = self.methodology.validation_methodology.clone();
            vm.sort();
            parts.push(vm.join("|"));
        }
        {
            let mut lm = self.methodology.limitations.clone();
            lm.sort();
            parts.push(lm.join("|"));
        }

        for gate in &self.prerequisite_gates {
            parts.push(gate.compute_hash().to_string());
        }

        for artifact in &self.published_artifacts {
            parts.push(artifact.compute_hash().to_string());
        }

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
                archive_path(&self.archive_root, &claim.evidence_bundle_ref),
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

        out.push_str("\n## Prerequisite Gates\n\n");
        for gate in &self.prerequisite_gates {
            out.push_str(&format!(
                "- `{}`: {} - `{}` (`{}`)\n",
                gate.bead_id,
                if gate.passed {
                    gate.summary.as_str()
                } else {
                    "failed"
                },
                archive_path(&self.archive_root, &gate.artifact_manifest),
                gate.artifact_hash
            ));
        }

        out.push_str("\n## Published Artifacts\n\n");
        for artifact in &self.published_artifacts {
            out.push_str(&format!(
                "- `{}` [{}]: `{}` (`{}`)\n",
                artifact.artifact_id,
                artifact.kind,
                archive_path(&self.archive_root, &artifact.relative_path),
                artifact.content_hash
            ));
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
    InvalidArchiveRoot {
        archive_root: String,
    },
    InvalidClaimField {
        claim_id: String,
        field: String,
    },
    InvalidMethodologyField {
        field: String,
    },
    InvalidPrerequisiteGateField {
        bead_id: String,
        field: String,
    },
    InvalidPublishedArtifactField {
        artifact_id: String,
        field: String,
    },
    MissingRequiredCapability {
        capability: CategoryShiftCapability,
    },
    MissingRequiredPrerequisiteGate {
        bead_id: String,
    },
    DuplicateCapability {
        capability: CategoryShiftCapability,
    },
    DuplicateClaimId {
        claim_id: String,
    },
    DuplicatePrerequisiteGate {
        bead_id: String,
    },
    DuplicatePublishedArtifactPath {
        relative_path: String,
    },
    PrerequisiteGateFailed {
        bead_id: String,
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
    MissingPublishedArtifact {
        relative_path: String,
    },
    PublishedArtifactHashMismatch {
        relative_path: String,
        expected: ContentHash,
        found: ContentHash,
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
            Self::InvalidArchiveRoot { archive_root } => {
                write!(f, "invalid archive root `{archive_root}`")
            }
            Self::InvalidClaimField { claim_id, field } => {
                write!(f, "invalid claim field `{field}` for claim `{claim_id}`")
            }
            Self::InvalidMethodologyField { field } => {
                write!(f, "invalid methodology field `{field}`")
            }
            Self::InvalidPrerequisiteGateField { bead_id, field } => {
                write!(
                    f,
                    "invalid prerequisite gate field `{field}` for `{bead_id}`"
                )
            }
            Self::InvalidPublishedArtifactField { artifact_id, field } => {
                write!(
                    f,
                    "invalid published artifact field `{field}` for `{artifact_id}`"
                )
            }
            Self::MissingRequiredCapability { capability } => {
                write!(f, "missing required capability `{capability}`")
            }
            Self::MissingRequiredPrerequisiteGate { bead_id } => {
                write!(f, "missing required prerequisite gate `{bead_id}`")
            }
            Self::DuplicateCapability { capability } => {
                write!(f, "duplicate capability `{capability}`")
            }
            Self::DuplicateClaimId { claim_id } => write!(f, "duplicate claim id `{claim_id}`"),
            Self::DuplicatePrerequisiteGate { bead_id } => {
                write!(f, "duplicate prerequisite gate `{bead_id}`")
            }
            Self::DuplicatePublishedArtifactPath { relative_path } => {
                write!(f, "duplicate published artifact path `{relative_path}`")
            }
            Self::PrerequisiteGateFailed { bead_id } => {
                write!(f, "prerequisite gate `{bead_id}` did not pass")
            }
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
            Self::MissingPublishedArtifact { relative_path } => {
                write!(f, "missing published artifact `{relative_path}`")
            }
            Self::PublishedArtifactHashMismatch {
                relative_path,
                expected,
                found,
            } => write!(
                f,
                "published artifact `{relative_path}` hash mismatch: expected `{expected}`, found `{found}`"
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
    if !is_canonical_repo_relative_path(&input.archive_root) {
        return Err(CategoryShiftReportError::InvalidArchiveRoot {
            archive_root: input.archive_root,
        });
    }
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

    let mut published_artifacts = input.published_artifacts;
    published_artifacts.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let mut published_artifact_paths = BTreeSet::new();
    let mut published_artifact_hashes = BTreeMap::new();
    for artifact in &published_artifacts {
        artifact.validate()?;
        if !published_artifact_paths.insert(artifact.relative_path.clone()) {
            return Err(CategoryShiftReportError::DuplicatePublishedArtifactPath {
                relative_path: artifact.relative_path.clone(),
            });
        }
        published_artifact_hashes.insert(artifact.relative_path.clone(), artifact.content_hash);
    }

    let mut prerequisite_gates = input.prerequisite_gates;
    prerequisite_gates.sort_by(|left, right| left.bead_id.cmp(&right.bead_id));
    let mut seen_prerequisite_beads = BTreeSet::new();
    for gate in &prerequisite_gates {
        gate.validate()?;
        if !seen_prerequisite_beads.insert(gate.bead_id.clone()) {
            return Err(CategoryShiftReportError::DuplicatePrerequisiteGate {
                bead_id: gate.bead_id.clone(),
            });
        }
        if !gate.passed {
            return Err(CategoryShiftReportError::PrerequisiteGateFailed {
                bead_id: gate.bead_id.clone(),
            });
        }
        let published_hash = published_artifact_hashes
            .get(&gate.artifact_manifest)
            .copied()
            .ok_or_else(|| CategoryShiftReportError::MissingPublishedArtifact {
                relative_path: gate.artifact_manifest.clone(),
            })?;
        if published_hash != gate.artifact_hash {
            return Err(CategoryShiftReportError::PublishedArtifactHashMismatch {
                relative_path: gate.artifact_manifest.clone(),
                expected: published_hash,
                found: gate.artifact_hash,
            });
        }
    }

    for bead_id in REQUIRED_PREREQUISITE_BEADS {
        if !seen_prerequisite_beads.contains(bead_id) {
            return Err(CategoryShiftReportError::MissingRequiredPrerequisiteGate {
                bead_id: bead_id.to_string(),
            });
        }
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
        let published_hash = published_artifact_hashes
            .get(&claim.evidence_bundle_ref)
            .copied()
            .ok_or_else(|| CategoryShiftReportError::MissingPublishedArtifact {
                relative_path: claim.evidence_bundle_ref.clone(),
            })?;
        if published_hash != claim.evidence_hash {
            return Err(CategoryShiftReportError::PublishedArtifactHashMismatch {
                relative_path: claim.evidence_bundle_ref.clone(),
                expected: published_hash,
                found: claim.evidence_hash,
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
        prerequisite_gates,
        published_artifacts,
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
            evidence_bundle_ref: format!("claims/{}/bundle.json", capability.as_str()),
            evidence_hash: ContentHash::compute(capability.as_str().as_bytes()),
            reproduction_instructions: vec![format!("rerun {}", capability.as_str())],
            source_beads: vec!["bd-source".to_string()],
            caveats: vec!["bounded to shipped corpus".to_string()],
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
            summary: format!("{bead_id} publication gate passed"),
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

    // -----------------------------------------------------------------------
    // CategoryShiftCapability tests
    // -----------------------------------------------------------------------

    #[test]
    fn capability_all_has_five_elements() {
        assert_eq!(CategoryShiftCapability::ALL.len(), 5);
    }

    #[test]
    fn capability_all_order_is_deterministic() {
        assert_eq!(
            CategoryShiftCapability::ALL[0],
            CategoryShiftCapability::ProofCarryingOptimization
        );
        assert_eq!(
            CategoryShiftCapability::ALL[4],
            CategoryShiftCapability::AdversarialCompromiseRateSuppression
        );
    }

    #[test]
    fn capability_as_str_is_snake_case() {
        for cap in CategoryShiftCapability::ALL {
            assert!(!cap.as_str().is_empty());
            assert!(!cap.as_str().contains(' '));
        }
    }

    #[test]
    fn capability_display_name_is_human_readable() {
        for cap in CategoryShiftCapability::ALL {
            assert!(!cap.display_name().is_empty());
            assert!(cap.display_name().contains(' ') || cap.display_name() == "Deterministic IFC");
        }
    }

    #[test]
    fn capability_display_matches_as_str() {
        for cap in CategoryShiftCapability::ALL {
            assert_eq!(format!("{cap}"), cap.as_str());
        }
    }

    #[test]
    fn capability_serde_roundtrip() {
        for cap in CategoryShiftCapability::ALL {
            let json = serde_json::to_string(&cap).unwrap();
            let back: CategoryShiftCapability = serde_json::from_str(&json).unwrap();
            assert_eq!(back, cap);
        }
    }

    #[test]
    fn capability_serde_is_snake_case() {
        let json = serde_json::to_string(&CategoryShiftCapability::DeterministicIfc).unwrap();
        assert_eq!(json, "\"deterministic_ifc\"");
    }

    // -----------------------------------------------------------------------
    // Claim validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn claim_validate_ok_for_well_formed_claim() {
        let c = claim(CategoryShiftCapability::DeterministicIfc);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn claim_validate_rejects_empty_claim_id() {
        let mut c = claim(CategoryShiftCapability::DeterministicIfc);
        c.claim_id = "  ".to_string();
        let err = c.validate().unwrap_err();
        assert!(matches!(
            err,
            CategoryShiftReportError::InvalidClaimField { field, .. } if field == "claim_id"
        ));
    }

    #[test]
    fn claim_validate_rejects_empty_claim_statement() {
        let mut c = claim(CategoryShiftCapability::DeterministicIfc);
        c.claim_statement = String::new();
        let err = c.validate().unwrap_err();
        assert!(matches!(
            err,
            CategoryShiftReportError::InvalidClaimField { field, .. } if field == "claim_statement"
        ));
    }

    #[test]
    fn claim_validate_rejects_empty_evidence_summary() {
        let mut c = claim(CategoryShiftCapability::DeterministicIfc);
        c.evidence_summary = "   ".to_string();
        let err = c.validate().unwrap_err();
        assert!(matches!(
            err,
            CategoryShiftReportError::InvalidClaimField { field, .. } if field == "evidence_summary"
        ));
    }

    #[test]
    fn claim_validate_rejects_empty_evidence_bundle_ref() {
        let mut c = claim(CategoryShiftCapability::DeterministicIfc);
        c.evidence_bundle_ref = String::new();
        let err = c.validate().unwrap_err();
        assert!(matches!(
            err,
            CategoryShiftReportError::InvalidClaimField { field, .. } if field == "evidence_bundle_ref"
        ));
    }

    #[test]
    fn claim_validate_rejects_empty_reproduction_instructions() {
        let mut c = claim(CategoryShiftCapability::DeterministicIfc);
        c.reproduction_instructions = Vec::new();
        let err = c.validate().unwrap_err();
        assert!(matches!(
            err,
            CategoryShiftReportError::InvalidClaimField { field, .. } if field == "reproduction_instructions"
        ));
    }

    #[test]
    fn claim_validate_rejects_blank_reproduction_step() {
        let mut c = claim(CategoryShiftCapability::DeterministicIfc);
        c.reproduction_instructions = vec!["step 1".to_string(), "  ".to_string()];
        let err = c.validate().unwrap_err();
        assert!(matches!(
            err,
            CategoryShiftReportError::InvalidClaimField { field, .. } if field == "reproduction_instructions"
        ));
    }

    #[test]
    fn claim_validate_rejects_empty_source_beads() {
        let mut c = claim(CategoryShiftCapability::DeterministicIfc);
        c.source_beads = Vec::new();
        let err = c.validate().unwrap_err();
        assert!(matches!(
            err,
            CategoryShiftReportError::InvalidClaimField { field, .. } if field == "source_beads"
        ));
    }

    #[test]
    fn claim_validate_rejects_bead_without_prefix() {
        let mut c = claim(CategoryShiftCapability::DeterministicIfc);
        c.source_beads = vec!["no-prefix".to_string()];
        let err = c.validate().unwrap_err();
        assert!(matches!(
            err,
            CategoryShiftReportError::InvalidClaimField { field, .. } if field == "source_beads"
        ));
    }

    // -----------------------------------------------------------------------
    // Claim hash tests
    // -----------------------------------------------------------------------

    #[test]
    fn claim_compute_hash_is_deterministic() {
        let c = claim(CategoryShiftCapability::ProofCarryingOptimization);
        let h1 = c.compute_hash();
        let h2 = c.compute_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn claim_compute_hash_differs_for_different_capabilities() {
        let c1 = claim(CategoryShiftCapability::ProofCarryingOptimization);
        let c2 = claim(CategoryShiftCapability::DeterministicIfc);
        assert_ne!(c1.compute_hash(), c2.compute_hash());
    }

    #[test]
    fn claim_compute_hash_sorts_source_beads() {
        let mut c1 = claim(CategoryShiftCapability::DeterministicIfc);
        c1.source_beads = vec!["bd-a".to_string(), "bd-b".to_string()];
        let mut c2 = claim(CategoryShiftCapability::DeterministicIfc);
        c2.source_beads = vec!["bd-b".to_string(), "bd-a".to_string()];
        assert_eq!(c1.compute_hash(), c2.compute_hash());
    }

    // -----------------------------------------------------------------------
    // MethodologySection validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn methodology_validate_ok_for_well_formed() {
        assert!(methodology().validate().is_ok());
    }

    #[test]
    fn methodology_validate_rejects_empty_summary() {
        let mut m = methodology();
        m.summary = "  ".to_string();
        let err = m.validate().unwrap_err();
        assert!(matches!(
            err,
            CategoryShiftReportError::InvalidMethodologyField { field } if field == "summary"
        ));
    }

    #[test]
    fn methodology_validate_rejects_empty_frameworks() {
        let mut m = methodology();
        m.statistical_frameworks = Vec::new();
        let err = m.validate().unwrap_err();
        assert!(matches!(
            err,
            CategoryShiftReportError::InvalidMethodologyField { field } if field == "statistical_frameworks"
        ));
    }

    #[test]
    fn methodology_validate_rejects_blank_framework_item() {
        let mut m = methodology();
        m.statistical_frameworks = vec!["ok".to_string(), "".to_string()];
        let err = m.validate().unwrap_err();
        assert!(matches!(
            err,
            CategoryShiftReportError::InvalidMethodologyField { field } if field == "statistical_frameworks"
        ));
    }

    #[test]
    fn methodology_validate_rejects_empty_limitations() {
        let mut m = methodology();
        m.limitations = Vec::new();
        let err = m.validate().unwrap_err();
        assert!(matches!(
            err,
            CategoryShiftReportError::InvalidMethodologyField { field } if field == "limitations"
        ));
    }

    // -----------------------------------------------------------------------
    // build_category_shift_report additional paths
    // -----------------------------------------------------------------------

    fn valid_input() -> CategoryShiftReportInput {
        CategoryShiftReportInput {
            report_version: "v1".to_string(),
            candidate_id: "rc-1".to_string(),
            generated_at_utc: "2026-03-13T00:00:00Z".to_string(),
            archive_root: "archive/root".to_string(),
            scorecard_schema: ScorecardSchema::default_schema(),
            scorecard_result: scorecard_result(),
            claims: CategoryShiftCapability::ALL
                .iter()
                .copied()
                .map(claim)
                .collect(),
            methodology: methodology(),
            prerequisite_gates: prerequisite_gates(),
            published_artifacts: published_artifacts(),
            peer_reviews: peer_reviews(),
        }
    }

    #[test]
    fn build_report_succeeds_for_valid_input() {
        let report = build_category_shift_report(valid_input()).unwrap();
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.component, COMPONENT);
        assert_eq!(report.bead_id, BEAD_ID);
        assert_eq!(report.policy_id, POLICY_ID);
        assert_eq!(report.claims.len(), 5);
    }

    #[test]
    fn build_report_publication_hash_is_nonzero() {
        let report = build_category_shift_report(valid_input()).unwrap();
        assert_ne!(
            report.publication_hash,
            ContentHash::compute(b"placeholder")
        );
    }

    #[test]
    fn build_report_publication_hash_is_deterministic() {
        let r1 = build_category_shift_report(valid_input()).unwrap();
        let r2 = build_category_shift_report(valid_input()).unwrap();
        assert_eq!(r1.publication_hash, r2.publication_hash);
    }

    #[test]
    fn build_report_rejects_duplicate_claim_id() {
        let mut input = valid_input();
        input.claims[1].claim_id = input.claims[0].claim_id.clone();
        input.claims[1].capability = input.claims[0].capability;
        let err = build_category_shift_report(input).unwrap_err();
        assert!(matches!(
            err,
            CategoryShiftReportError::DuplicateClaimId { .. }
        ));
    }

    #[test]
    fn build_report_rejects_duplicate_capability() {
        let mut input = valid_input();
        input.claims[1].capability = input.claims[0].capability;
        let err = build_category_shift_report(input).unwrap_err();
        assert!(
            matches!(err, CategoryShiftReportError::DuplicateCapability { .. })
                || matches!(err, CategoryShiftReportError::DuplicateClaimId { .. })
                || matches!(
                    err,
                    CategoryShiftReportError::MissingRequiredCapability { .. }
                )
        );
    }

    #[test]
    fn build_report_rejects_duplicate_peer_reviewer() {
        let mut input = valid_input();
        input.peer_reviews[1].reviewer_id = input.peer_reviews[0].reviewer_id.clone();
        let err = build_category_shift_report(input).unwrap_err();
        assert!(matches!(
            err,
            CategoryShiftReportError::DuplicatePeerReviewer { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // CategoryShiftReport methods
    // -----------------------------------------------------------------------

    #[test]
    fn report_to_json_pretty_is_valid_json() {
        let report = build_category_shift_report(valid_input()).unwrap();
        let json_str = report.to_json_pretty().unwrap();
        let _parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    }

    #[test]
    fn report_to_markdown_contains_headings() {
        let report = build_category_shift_report(valid_input()).unwrap();
        let md = report.to_markdown();
        assert!(md.contains("# First Category-Shift Report"));
        assert!(md.contains("## Disruption Scorecard"));
        assert!(md.contains("## Beyond-Parity Claims"));
        assert!(md.contains("## Methodology"));
        assert!(md.contains("## Prerequisite Gates"));
        assert!(md.contains("## Published Artifacts"));
        assert!(md.contains("## Peer Review"));
    }

    #[test]
    fn report_to_markdown_contains_all_capabilities() {
        let report = build_category_shift_report(valid_input()).unwrap();
        let md = report.to_markdown();
        for cap in CategoryShiftCapability::ALL {
            assert!(
                md.contains(cap.display_name()),
                "markdown missing capability: {}",
                cap.display_name()
            );
        }
    }

    #[test]
    fn report_to_markdown_contains_publication_hash() {
        let report = build_category_shift_report(valid_input()).unwrap();
        let md = report.to_markdown();
        assert!(md.contains(&report.publication_hash.to_string()));
    }

    #[test]
    fn report_compute_hash_is_idempotent() {
        let report = build_category_shift_report(valid_input()).unwrap();
        let h1 = report.compute_hash();
        let h2 = report.compute_hash();
        assert_eq!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // generate_log_entries tests
    // -----------------------------------------------------------------------

    #[test]
    fn log_entries_claim_published_events_have_claim_id() {
        let report = build_category_shift_report(valid_input()).unwrap();
        let entries = generate_log_entries("trace-1", &report);
        let claim_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.event == "claim_published")
            .collect();
        assert_eq!(claim_entries.len(), 5);
        for entry in &claim_entries {
            assert!(entry.claim_id.is_some());
            assert!(entry.evidence_bundle_ref.is_some());
            assert!(entry.evidence_hash.is_some());
        }
    }

    #[test]
    fn log_entries_peer_review_events_have_reviewer_id() {
        let report = build_category_shift_report(valid_input()).unwrap();
        let entries = generate_log_entries("trace-1", &report);
        let review_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.event == "peer_review_recorded")
            .collect();
        assert_eq!(review_entries.len(), MINIMUM_PEER_REVIEWERS);
        for entry in &review_entries {
            assert!(entry.reviewer_id.is_some());
            assert!(entry.review_status.is_some());
        }
    }

    #[test]
    fn log_entries_all_have_trace_id() {
        let report = build_category_shift_report(valid_input()).unwrap();
        let entries = generate_log_entries("my-trace", &report);
        for entry in &entries {
            assert_eq!(entry.trace_id, "my-trace");
        }
    }

    // -----------------------------------------------------------------------
    // Error Display tests
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_invalid_claim_field() {
        let err = CategoryShiftReportError::InvalidClaimField {
            claim_id: "c1".to_string(),
            field: "claim_statement".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("c1"));
        assert!(msg.contains("claim_statement"));
    }

    #[test]
    fn error_display_missing_required_capability() {
        let err = CategoryShiftReportError::MissingRequiredCapability {
            capability: CategoryShiftCapability::DeterministicIfc,
        };
        let msg = format!("{err}");
        assert!(msg.contains("deterministic_ifc"));
    }

    #[test]
    fn error_display_insufficient_peer_review() {
        let err = CategoryShiftReportError::InsufficientPeerReview {
            approved_reviewers: 1,
        };
        let msg = format!("{err}");
        assert!(msg.contains("1"));
        assert!(msg.contains(&MINIMUM_PEER_REVIEWERS.to_string()));
    }

    // -----------------------------------------------------------------------
    // Constants tests
    // -----------------------------------------------------------------------

    #[test]
    fn constants_are_nonempty() {
        assert!(!SCHEMA_VERSION.is_empty());
        assert!(!COMPONENT.is_empty());
        assert!(!BEAD_ID.is_empty());
        assert!(!POLICY_ID.is_empty());
    }

    #[test]
    fn minimum_peer_reviewers_is_two() {
        assert_eq!(MINIMUM_PEER_REVIEWERS, 2);
    }

    // -----------------------------------------------------------------------
    // Serde round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn category_shift_claim_serde_roundtrip() {
        let c = claim(CategoryShiftCapability::PlasSignedWitnesses);
        let json = serde_json::to_string(&c).unwrap();
        let back: CategoryShiftClaim = serde_json::from_str(&json).unwrap();
        assert_eq!(back.claim_id, c.claim_id);
        assert_eq!(back.capability, c.capability);
    }

    #[test]
    fn methodology_section_serde_roundtrip() {
        let m = methodology();
        let json = serde_json::to_string(&m).unwrap();
        let back: MethodologySection = serde_json::from_str(&json).unwrap();
        assert_eq!(back.summary, m.summary);
    }

    #[test]
    fn peer_review_signoff_serde_roundtrip() {
        let review = PeerReviewSignoff {
            reviewer_id: "test-reviewer".to_string(),
            reviewed_at_utc: "2026-03-14T00:00:00Z".to_string(),
            approved: true,
            notes: "all good".to_string(),
        };
        let json = serde_json::to_string(&review).unwrap();
        let back: PeerReviewSignoff = serde_json::from_str(&json).unwrap();
        assert!(back.approved);
    }

    #[test]
    fn dimension_publication_summary_serde_roundtrip() {
        let summary = DimensionPublicationSummary {
            raw_score_millionths: 500_000,
            floor_millionths: 100_000,
            target_millionths: 400_000,
            meets_floor: true,
            meets_target: true,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: DimensionPublicationSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back.raw_score_millionths, 500_000);
        assert!(back.meets_target);
    }

    #[test]
    fn log_entry_serde_roundtrip() {
        let report = build_category_shift_report(valid_input()).unwrap();
        let entries = generate_log_entries("trace-1", &report);
        for entry in &entries {
            let json = serde_json::to_string(entry).unwrap();
            let back: CategoryShiftReportLogEntry = serde_json::from_str(&json).unwrap();
            assert_eq!(back.trace_id, "trace-1");
        }
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
            prerequisite_gates: prerequisite_gates(),
            published_artifacts: published_artifacts(),
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
            prerequisite_gates: prerequisite_gates(),
            published_artifacts: published_artifacts(),
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
            prerequisite_gates: prerequisite_gates(),
            published_artifacts: published_artifacts(),
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
