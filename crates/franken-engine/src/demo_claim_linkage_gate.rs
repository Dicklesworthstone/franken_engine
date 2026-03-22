//! Demo-to-claim linkage gate for production-facing milestones.
//!
//! Requires every milestone claim to map to a runnable demo specification,
//! evidence IDs, expected outputs, and verification commands. Claims without
//! complete linkage are rejected by the gate.
//!
//! Plan reference: FRX-16.3

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ── Constants ────────────────────────────────────────────────────────────

const MILLION: i64 = 1_000_000;

/// Schema version for demo-claim linkage gate artifacts.
pub const LINKAGE_GATE_SCHEMA_VERSION: &str = "franken-engine.demo-claim-linkage-gate.v1";

/// Maximum number of claims per evaluation.
const MAX_CLAIMS: usize = 256;

/// Maximum number of evidence links per claim.
const MAX_EVIDENCE_PER_CLAIM: usize = 64;

/// Maximum number of verification commands per demo.
const MAX_COMMANDS_PER_DEMO: usize = 32;

// ── Demo Specification ──────────────────────────────────────────────────

/// A runnable demo specification that demonstrates a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemoSpecification {
    /// Unique demo identifier.
    pub demo_id: String,
    /// Human-readable title.
    pub title: String,
    /// Description of what the demo shows.
    pub description: String,
    /// Milestone ID this demo belongs to.
    pub milestone_id: String,
    /// Whether the demo is runnable (has verification commands).
    pub runnable: bool,
    /// Verification commands to run the demo.
    pub verification_commands: Vec<VerificationCommand>,
    /// Expected outputs (keyed by output name).
    pub expected_outputs: BTreeMap<String, ExpectedOutput>,
    /// Tags for classification.
    pub tags: BTreeSet<String>,
}

impl DemoSpecification {
    /// Whether the demo is complete (has verification commands and expected outputs).
    pub fn is_complete(&self) -> bool {
        self.runnable && !self.verification_commands.is_empty() && !self.expected_outputs.is_empty()
    }

    /// Number of verification commands.
    pub fn command_count(&self) -> usize {
        self.verification_commands.len()
    }
}

impl fmt::Display for DemoSpecification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.is_complete() {
            "complete"
        } else {
            "incomplete"
        };
        write!(f, "demo({}, {}, {})", self.demo_id, self.title, status)
    }
}

/// A verification command for a demo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationCommand {
    /// Command identifier.
    pub command_id: String,
    /// The command to execute.
    pub command: String,
    /// Expected exit code (0 = success).
    pub expected_exit_code: i32,
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
    /// Whether this command is deterministic.
    pub deterministic: bool,
}

impl fmt::Display for VerificationCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cmd({}, exit={})",
            self.command_id, self.expected_exit_code
        )
    }
}

/// Expected output from a demo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedOutput {
    /// Output name.
    pub name: String,
    /// Expected content hash (deterministic outputs).
    pub expected_hash: Option<ContentHash>,
    /// Whether the output must exactly match.
    pub exact_match: bool,
    /// Acceptable tolerance for numeric outputs (millionths).
    pub tolerance_millionths: i64,
}

// ── Claim ───────────────────────────────────────────────────────────────

/// A production-facing milestone claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MilestoneClaim {
    /// Unique claim identifier.
    pub claim_id: String,
    /// Human-readable claim statement.
    pub statement: String,
    /// Milestone ID this claim belongs to.
    pub milestone_id: String,
    /// Category of the claim.
    pub category: ClaimCategory,
    /// Evidence links supporting this claim.
    pub evidence_links: Vec<EvidenceLink>,
    /// Demo specifications demonstrating this claim.
    pub demos: Vec<String>,
}

impl fmt::Display for MilestoneClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "claim({}, {}, evidence={}, demos={})",
            self.claim_id,
            self.category,
            self.evidence_links.len(),
            self.demos.len()
        )
    }
}

/// Category of a milestone claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimCategory {
    /// Performance claim (throughput, latency, etc.).
    Performance,
    /// Correctness claim (behavior, semantics).
    Correctness,
    /// Security claim (isolation, containment).
    Security,
    /// Compatibility claim (API, protocol).
    Compatibility,
    /// Reliability claim (availability, recovery).
    Reliability,
    /// Developer experience claim.
    DeveloperExperience,
}

impl fmt::Display for ClaimCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Performance => write!(f, "performance"),
            Self::Correctness => write!(f, "correctness"),
            Self::Security => write!(f, "security"),
            Self::Compatibility => write!(f, "compatibility"),
            Self::Reliability => write!(f, "reliability"),
            Self::DeveloperExperience => write!(f, "developer-experience"),
        }
    }
}

/// A link from a claim to supporting evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceLink {
    /// Evidence identifier.
    pub evidence_id: String,
    /// Kind of evidence.
    pub kind: EvidenceKind,
    /// Artifact hash for the evidence.
    pub artifact_hash: ContentHash,
    /// Brief description of what this evidence shows.
    pub description: String,
}

impl fmt::Display for EvidenceLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "evidence({}, {})", self.evidence_id, self.kind)
    }
}

/// Kind of evidence supporting a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceKind {
    /// Test suite result.
    TestResult,
    /// Benchmark result.
    BenchmarkResult,
    /// Security audit.
    SecurityAudit,
    /// Formal verification proof.
    FormalProof,
    /// Code review.
    CodeReview,
    /// Demo replay artifact.
    DemoReplay,
    /// Third-party verification.
    ThirdPartyVerification,
}

impl fmt::Display for EvidenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TestResult => write!(f, "test-result"),
            Self::BenchmarkResult => write!(f, "benchmark-result"),
            Self::SecurityAudit => write!(f, "security-audit"),
            Self::FormalProof => write!(f, "formal-proof"),
            Self::CodeReview => write!(f, "code-review"),
            Self::DemoReplay => write!(f, "demo-replay"),
            Self::ThirdPartyVerification => write!(f, "third-party-verification"),
        }
    }
}

// ── Linkage Check Result ────────────────────────────────────────────────

/// Result of checking a single claim's linkage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimLinkageResult {
    /// Claim ID that was checked.
    pub claim_id: String,
    /// Whether all linkage requirements are met.
    pub linked: bool,
    /// Whether the claim has at least one runnable demo.
    pub has_runnable_demo: bool,
    /// Whether the claim has evidence links.
    pub has_evidence: bool,
    /// Whether all referenced demos have expected outputs.
    pub demos_have_outputs: bool,
    /// Whether all referenced demos have verification commands.
    pub demos_have_commands: bool,
    /// Missing linkage details.
    pub missing: Vec<String>,
    /// Completeness score (millionths, 0 = nothing, MILLION = fully linked).
    pub completeness_millionths: i64,
}

// ── Gate Decision ───────────────────────────────────────────────────────

/// Gate decision for a milestone's demo-claim linkage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkageGateDecision {
    /// Decision ID.
    pub decision_id: String,
    /// Milestone ID that was evaluated.
    pub milestone_id: String,
    /// Epoch of evaluation.
    pub epoch: SecurityEpoch,
    /// Verdict.
    pub verdict: LinkageVerdict,
    /// Per-claim linkage results.
    pub claim_results: Vec<ClaimLinkageResult>,
    /// Total claims evaluated.
    pub total_claims: u64,
    /// Claims with complete linkage.
    pub linked_claims: u64,
    /// Claims missing linkage.
    pub unlinked_claims: u64,
    /// Aggregate completeness (millionths).
    pub aggregate_completeness_millionths: i64,
    /// Rationale.
    pub rationale: String,
    /// Artifact hash.
    pub artifact_hash: ContentHash,
}

impl LinkageGateDecision {
    /// Whether the gate passes.
    pub fn is_pass(&self) -> bool {
        self.verdict == LinkageVerdict::Pass
    }

    /// Fraction of claims that are linked (millionths).
    pub fn linkage_rate_millionths(&self) -> i64 {
        if self.total_claims == 0 {
            return 0;
        }
        (self.linked_claims as i128 * MILLION as i128 / self.total_claims as i128) as i64
    }
}

impl fmt::Display for LinkageGateDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "linkage-gate({}, {}, linked={}/{}, completeness={})",
            self.milestone_id,
            self.verdict,
            self.linked_claims,
            self.total_claims,
            self.aggregate_completeness_millionths
        )
    }
}

/// Verdict of a linkage gate evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkageVerdict {
    /// All claims are fully linked.
    Pass,
    /// Some claims are missing linkage.
    Fail,
    /// No claims to evaluate.
    Empty,
}

impl fmt::Display for LinkageVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Fail => write!(f, "fail"),
            Self::Empty => write!(f, "empty"),
        }
    }
}

// ── Configuration ───────────────────────────────────────────────────────

/// Configuration for the linkage gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkageGateConfig {
    /// Epoch for evaluation.
    pub epoch: SecurityEpoch,
    /// Minimum completeness to pass (millionths). Default = MILLION (100%).
    pub min_completeness_millionths: i64,
    /// Whether every claim must have at least one runnable demo.
    pub require_runnable_demo: bool,
    /// Whether every claim must have at least one evidence link.
    pub require_evidence: bool,
    /// Whether every demo must have expected outputs.
    pub require_expected_outputs: bool,
    /// Whether every demo must have verification commands.
    pub require_verification_commands: bool,
}

impl Default for LinkageGateConfig {
    fn default() -> Self {
        Self {
            epoch: SecurityEpoch::from_raw(1),
            min_completeness_millionths: MILLION,
            require_runnable_demo: true,
            require_evidence: true,
            require_expected_outputs: true,
            require_verification_commands: true,
        }
    }
}

// ── Error ───────────────────────────────────────────────────────────────

/// Errors from the linkage gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkageGateError {
    /// No claims provided.
    NoClaims,
    /// Too many claims.
    TooManyClaims { count: usize, max: usize },
    /// Duplicate claim ID.
    DuplicateClaim { claim_id: String },
    /// Duplicate demo ID.
    DuplicateDemo { demo_id: String },
    /// Too many evidence links on a claim.
    TooManyEvidenceLinks {
        claim_id: String,
        count: usize,
        max: usize,
    },
    /// Too many verification commands on a demo.
    TooManyCommands {
        demo_id: String,
        count: usize,
        max: usize,
    },
    /// Claim references unknown demo.
    UnknownDemo { claim_id: String, demo_id: String },
    /// Invalid configuration.
    InvalidConfig { detail: String },
}

impl fmt::Display for LinkageGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoClaims => write!(f, "no claims provided"),
            Self::TooManyClaims { count, max } => {
                write!(f, "too many claims: {} exceeds max {}", count, max)
            }
            Self::DuplicateClaim { claim_id } => {
                write!(f, "duplicate claim ID: {}", claim_id)
            }
            Self::DuplicateDemo { demo_id } => {
                write!(f, "duplicate demo ID: {}", demo_id)
            }
            Self::TooManyEvidenceLinks {
                claim_id,
                count,
                max,
            } => {
                write!(
                    f,
                    "claim {} has {} evidence links, max {}",
                    claim_id, count, max
                )
            }
            Self::TooManyCommands {
                demo_id,
                count,
                max,
            } => {
                write!(f, "demo {} has {} commands, max {}", demo_id, count, max)
            }
            Self::UnknownDemo { claim_id, demo_id } => {
                write!(f, "claim {} references unknown demo {}", claim_id, demo_id)
            }
            Self::InvalidConfig { detail } => {
                write!(f, "invalid config: {}", detail)
            }
        }
    }
}

impl std::error::Error for LinkageGateError {}

// ── Main Gate ───────────────────────────────────────────────────────────

/// Demo-to-claim linkage gate.
///
/// Evaluates whether all milestone claims have proper linkage to demos,
/// evidence, and verification commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoClaimLinkageGate {
    config: LinkageGateConfig,
    evaluation_count: u64,
}

impl DemoClaimLinkageGate {
    /// Create a new linkage gate.
    pub fn new(config: LinkageGateConfig) -> Result<Self, LinkageGateError> {
        if config.min_completeness_millionths < 0 || config.min_completeness_millionths > MILLION {
            return Err(LinkageGateError::InvalidConfig {
                detail: format!(
                    "min_completeness_millionths {} out of range [0, {}]",
                    config.min_completeness_millionths, MILLION
                ),
            });
        }
        Ok(Self {
            config,
            evaluation_count: 0,
        })
    }

    /// Access the configuration.
    pub fn config(&self) -> &LinkageGateConfig {
        &self.config
    }

    /// Number of evaluations performed.
    pub fn evaluation_count(&self) -> u64 {
        self.evaluation_count
    }

    /// Evaluate milestone claims against demo specifications.
    pub fn evaluate(
        &mut self,
        milestone_id: &str,
        claims: &[MilestoneClaim],
        demos: &[DemoSpecification],
    ) -> Result<LinkageGateDecision, LinkageGateError> {
        if claims.is_empty() {
            return Err(LinkageGateError::NoClaims);
        }
        if claims.len() > MAX_CLAIMS {
            return Err(LinkageGateError::TooManyClaims {
                count: claims.len(),
                max: MAX_CLAIMS,
            });
        }

        // Check duplicate claim IDs.
        let mut seen_claims = BTreeSet::new();
        for claim in claims {
            if !seen_claims.insert(&claim.claim_id) {
                return Err(LinkageGateError::DuplicateClaim {
                    claim_id: claim.claim_id.clone(),
                });
            }
            if claim.evidence_links.len() > MAX_EVIDENCE_PER_CLAIM {
                return Err(LinkageGateError::TooManyEvidenceLinks {
                    claim_id: claim.claim_id.clone(),
                    count: claim.evidence_links.len(),
                    max: MAX_EVIDENCE_PER_CLAIM,
                });
            }
        }

        // Build demo index and check duplicates.
        let mut demo_index: BTreeMap<&str, &DemoSpecification> = BTreeMap::new();
        for demo in demos {
            if demo_index.contains_key(demo.demo_id.as_str()) {
                return Err(LinkageGateError::DuplicateDemo {
                    demo_id: demo.demo_id.clone(),
                });
            }
            if demo.verification_commands.len() > MAX_COMMANDS_PER_DEMO {
                return Err(LinkageGateError::TooManyCommands {
                    demo_id: demo.demo_id.clone(),
                    count: demo.verification_commands.len(),
                    max: MAX_COMMANDS_PER_DEMO,
                });
            }
            demo_index.insert(&demo.demo_id, demo);
        }

        // Validate claim → demo references.
        for claim in claims {
            for demo_id in &claim.demos {
                if !demo_index.contains_key(demo_id.as_str()) {
                    return Err(LinkageGateError::UnknownDemo {
                        claim_id: claim.claim_id.clone(),
                        demo_id: demo_id.clone(),
                    });
                }
            }
        }

        self.evaluation_count += 1;

        // Evaluate each claim.
        let mut claim_results = Vec::new();
        let mut linked_count: u64 = 0;
        let mut total_completeness: i64 = 0;

        for claim in claims {
            let result = self.check_claim(claim, &demo_index);
            total_completeness += result.completeness_millionths;
            if result.linked {
                linked_count += 1;
            }
            claim_results.push(result);
        }

        let total_claims = claims.len() as u64;
        let aggregate_completeness = total_completeness / total_claims as i64;

        let verdict = if linked_count == total_claims {
            LinkageVerdict::Pass
        } else {
            LinkageVerdict::Fail
        };

        let rationale = match verdict {
            LinkageVerdict::Pass => format!(
                "All {} claims fully linked, completeness {}",
                total_claims, aggregate_completeness
            ),
            LinkageVerdict::Fail => {
                let unlinked: Vec<_> = claim_results
                    .iter()
                    .filter(|r| !r.linked)
                    .map(|r| r.claim_id.clone())
                    .collect();
                format!(
                    "{}/{} claims unlinked: {}",
                    unlinked.len(),
                    total_claims,
                    unlinked.join(", ")
                )
            }
            LinkageVerdict::Empty => "no claims to evaluate".to_string(),
        };

        // Compute artifact hash.
        let mut hash_buf = Vec::new();
        hash_buf.extend_from_slice(LINKAGE_GATE_SCHEMA_VERSION.as_bytes());
        hash_buf.extend_from_slice(milestone_id.as_bytes());
        hash_buf.extend_from_slice(&self.config.epoch.as_u64().to_le_bytes());
        hash_buf.extend_from_slice(&total_claims.to_le_bytes());
        hash_buf.extend_from_slice(&linked_count.to_le_bytes());
        for r in &claim_results {
            hash_buf.extend_from_slice(r.claim_id.as_bytes());
            hash_buf.extend_from_slice(&r.completeness_millionths.to_le_bytes());
        }

        let decision_id = format!(
            "linkage-{}-{}-{}",
            milestone_id,
            self.config.epoch.as_u64(),
            self.evaluation_count
        );

        Ok(LinkageGateDecision {
            decision_id,
            milestone_id: milestone_id.to_string(),
            epoch: self.config.epoch,
            verdict,
            claim_results,
            total_claims,
            linked_claims: linked_count,
            unlinked_claims: total_claims - linked_count,
            aggregate_completeness_millionths: aggregate_completeness,
            rationale,
            artifact_hash: ContentHash::compute(&hash_buf),
        })
    }

    // ── Claim Checking ──────────────────────────────────────────────

    fn check_claim(
        &self,
        claim: &MilestoneClaim,
        demo_index: &BTreeMap<&str, &DemoSpecification>,
    ) -> ClaimLinkageResult {
        let mut missing = Vec::new();
        let mut score: i64 = 0;
        let mut max_score: i64 = 0;

        // Check evidence links.
        let has_evidence = !claim.evidence_links.is_empty();
        if self.config.require_evidence {
            max_score += MILLION / 4;
            if has_evidence {
                score += MILLION / 4;
            } else {
                missing.push("no evidence links".to_string());
            }
        }

        // Check demo references.
        let has_runnable_demo = claim
            .demos
            .iter()
            .any(|d| demo_index.get(d.as_str()).is_some_and(|demo| demo.runnable));
        if self.config.require_runnable_demo {
            max_score += MILLION / 4;
            if has_runnable_demo {
                score += MILLION / 4;
            } else {
                missing.push("no runnable demo".to_string());
            }
        }

        // Check expected outputs.
        let demos_have_outputs = claim.demos.iter().all(|d| {
            demo_index
                .get(d.as_str())
                .is_some_and(|demo| !demo.expected_outputs.is_empty())
        }) && !claim.demos.is_empty();
        if self.config.require_expected_outputs {
            max_score += MILLION / 4;
            if demos_have_outputs {
                score += MILLION / 4;
            } else {
                missing.push("demos missing expected outputs".to_string());
            }
        }

        // Check verification commands.
        let demos_have_commands = claim.demos.iter().all(|d| {
            demo_index
                .get(d.as_str())
                .is_some_and(|demo| !demo.verification_commands.is_empty())
        }) && !claim.demos.is_empty();
        if self.config.require_verification_commands {
            max_score += MILLION / 4;
            if demos_have_commands {
                score += MILLION / 4;
            } else {
                missing.push("demos missing verification commands".to_string());
            }
        }

        let completeness = if max_score > 0 {
            (score * MILLION) / max_score
        } else {
            MILLION
        };

        let linked = missing.is_empty();

        ClaimLinkageResult {
            claim_id: claim.claim_id.clone(),
            linked,
            has_runnable_demo,
            has_evidence,
            demos_have_outputs,
            demos_have_commands,
            missing,
            completeness_millionths: completeness,
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────

    fn make_evidence(id: &str) -> EvidenceLink {
        EvidenceLink {
            evidence_id: id.to_string(),
            kind: EvidenceKind::TestResult,
            artifact_hash: ContentHash::compute(id.as_bytes()),
            description: format!("Evidence {}", id),
        }
    }

    fn make_command(id: &str) -> VerificationCommand {
        VerificationCommand {
            command_id: id.to_string(),
            command: format!("cargo test {}", id),
            expected_exit_code: 0,
            timeout_ms: 60_000,
            deterministic: true,
        }
    }

    fn make_output(name: &str) -> ExpectedOutput {
        ExpectedOutput {
            name: name.to_string(),
            expected_hash: Some(ContentHash::compute(name.as_bytes())),
            exact_match: true,
            tolerance_millionths: 0,
        }
    }

    fn make_demo(id: &str, runnable: bool) -> DemoSpecification {
        let commands = if runnable {
            vec![make_command(&format!("cmd-{}", id))]
        } else {
            Vec::new()
        };
        let mut outputs = BTreeMap::new();
        if runnable {
            outputs.insert("out1".to_string(), make_output("out1"));
        }
        DemoSpecification {
            demo_id: id.to_string(),
            title: format!("Demo {}", id),
            description: format!("Demo {} description", id),
            milestone_id: "m1".to_string(),
            runnable,
            verification_commands: commands,
            expected_outputs: outputs,
            tags: BTreeSet::new(),
        }
    }

    fn make_claim(
        id: &str,
        category: ClaimCategory,
        demos: Vec<&str>,
        evidence: Vec<&str>,
    ) -> MilestoneClaim {
        MilestoneClaim {
            claim_id: id.to_string(),
            statement: format!("Claim {}", id),
            milestone_id: "m1".to_string(),
            category,
            evidence_links: evidence.into_iter().map(make_evidence).collect(),
            demos: demos.into_iter().map(String::from).collect(),
        }
    }

    fn default_gate() -> DemoClaimLinkageGate {
        DemoClaimLinkageGate::new(LinkageGateConfig::default()).unwrap()
    }

    // ── Constructor Tests ───────────────────────────────────────────

    #[test]
    fn new_creates_gate() {
        let gate = default_gate();
        assert_eq!(gate.evaluation_count(), 0);
    }

    #[test]
    fn new_rejects_invalid_completeness_high() {
        let config = LinkageGateConfig {
            min_completeness_millionths: MILLION + 1,
            ..Default::default()
        };
        let result = DemoClaimLinkageGate::new(config);
        assert!(matches!(
            result,
            Err(LinkageGateError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn new_rejects_invalid_completeness_negative() {
        let config = LinkageGateConfig {
            min_completeness_millionths: -1,
            ..Default::default()
        };
        let result = DemoClaimLinkageGate::new(config);
        assert!(matches!(
            result,
            Err(LinkageGateError::InvalidConfig { .. })
        ));
    }

    // ── Evaluation Tests ────────────────────────────────────────────

    #[test]
    fn evaluate_rejects_no_claims() {
        let mut gate = default_gate();
        let result = gate.evaluate("m1", &[], &[]);
        assert!(matches!(result, Err(LinkageGateError::NoClaims)));
    }

    #[test]
    fn evaluate_rejects_too_many_claims() {
        let mut gate = default_gate();
        let demo = make_demo("d1", true);
        let claims: Vec<_> = (0..257)
            .map(|i| {
                make_claim(
                    &format!("c{}", i),
                    ClaimCategory::Performance,
                    vec!["d1"],
                    vec!["e1"],
                )
            })
            .collect();
        let result = gate.evaluate("m1", &claims, &[demo]);
        assert!(matches!(
            result,
            Err(LinkageGateError::TooManyClaims {
                count: 257,
                max: 256
            })
        ));
    }

    #[test]
    fn evaluate_rejects_duplicate_claims() {
        let mut gate = default_gate();
        let demo = make_demo("d1", true);
        let claims = vec![
            make_claim("dup", ClaimCategory::Performance, vec!["d1"], vec!["e1"]),
            make_claim("dup", ClaimCategory::Security, vec!["d1"], vec!["e2"]),
        ];
        let result = gate.evaluate("m1", &claims, &[demo]);
        assert!(matches!(
            result,
            Err(LinkageGateError::DuplicateClaim { .. })
        ));
    }

    #[test]
    fn evaluate_rejects_duplicate_demos() {
        let mut gate = default_gate();
        let demos = vec![make_demo("dup", true), make_demo("dup", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["dup"],
            vec!["e1"],
        )];
        let result = gate.evaluate("m1", &claims, &demos);
        assert!(matches!(
            result,
            Err(LinkageGateError::DuplicateDemo { .. })
        ));
    }

    #[test]
    fn evaluate_rejects_unknown_demo() {
        let mut gate = default_gate();
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["nonexistent"],
            vec!["e1"],
        )];
        let result = gate.evaluate("m1", &claims, &[]);
        assert!(matches!(result, Err(LinkageGateError::UnknownDemo { .. })));
    }

    #[test]
    fn evaluate_passes_fully_linked() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Pass);
        assert!(decision.is_pass());
        assert_eq!(decision.linked_claims, 1);
        assert_eq!(decision.unlinked_claims, 0);
    }

    #[test]
    fn evaluate_fails_missing_evidence() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec![], // No evidence
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Fail);
        assert!(!decision.is_pass());
    }

    #[test]
    fn evaluate_fails_missing_demo() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec![], // No demos
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Fail);
    }

    #[test]
    fn evaluate_fails_non_runnable_demo() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", false)]; // Not runnable
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Fail);
    }

    #[test]
    fn evaluate_increments_count() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let _ = gate.evaluate("m1", &claims, &demos);
        assert_eq!(gate.evaluation_count(), 1);
        let _ = gate.evaluate("m1", &claims, &demos);
        assert_eq!(gate.evaluation_count(), 2);
    }

    // ── Completeness Scoring ────────────────────────────────────────

    #[test]
    fn fully_linked_has_million_completeness() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.aggregate_completeness_millionths, MILLION);
    }

    #[test]
    fn partial_linkage_has_partial_completeness() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec![], // Missing evidence → 75% complete
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert!(decision.aggregate_completeness_millionths > 0);
        assert!(decision.aggregate_completeness_millionths < MILLION);
    }

    #[test]
    fn linkage_rate_computed() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![
            make_claim("c1", ClaimCategory::Performance, vec!["d1"], vec!["e1"]),
            make_claim("c2", ClaimCategory::Security, vec![], vec![]),
        ];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.linkage_rate_millionths(), 500_000); // 1/2
    }

    // ── Multiple Claims ─────────────────────────────────────────────

    #[test]
    fn multiple_claims_all_linked() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true), make_demo("d2", true)];
        let claims = vec![
            make_claim("c1", ClaimCategory::Performance, vec!["d1"], vec!["e1"]),
            make_claim("c2", ClaimCategory::Security, vec!["d2"], vec!["e2"]),
        ];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Pass);
        assert_eq!(decision.linked_claims, 2);
    }

    #[test]
    fn some_claims_linked_fails() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![
            make_claim("c1", ClaimCategory::Performance, vec!["d1"], vec!["e1"]),
            make_claim("c2", ClaimCategory::Security, vec![], vec![]), // Incomplete
        ];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Fail);
        assert_eq!(decision.linked_claims, 1);
        assert_eq!(decision.unlinked_claims, 1);
    }

    // ── Relaxed Configuration ───────────────────────────────────────

    #[test]
    fn passes_without_evidence_when_not_required() {
        let config = LinkageGateConfig {
            require_evidence: false,
            ..Default::default()
        };
        let mut gate = DemoClaimLinkageGate::new(config).unwrap();

        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec![],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Pass);
    }

    #[test]
    fn passes_without_runnable_when_not_required() {
        let mut config = LinkageGateConfig {
            require_runnable_demo: false,
            ..Default::default()
        };
        config.require_expected_outputs = false;
        config.require_verification_commands = false;
        let mut gate = DemoClaimLinkageGate::new(config).unwrap();

        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec![],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &[]).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Pass);
    }

    // ── Display / Serde ─────────────────────────────────────────────

    #[test]
    fn claim_category_display() {
        assert_eq!(format!("{}", ClaimCategory::Performance), "performance");
        assert_eq!(format!("{}", ClaimCategory::Correctness), "correctness");
        assert_eq!(format!("{}", ClaimCategory::Security), "security");
        assert_eq!(format!("{}", ClaimCategory::Compatibility), "compatibility");
        assert_eq!(format!("{}", ClaimCategory::Reliability), "reliability");
        assert_eq!(
            format!("{}", ClaimCategory::DeveloperExperience),
            "developer-experience"
        );
    }

    #[test]
    fn evidence_kind_display() {
        assert_eq!(format!("{}", EvidenceKind::TestResult), "test-result");
        assert_eq!(
            format!("{}", EvidenceKind::BenchmarkResult),
            "benchmark-result"
        );
        assert_eq!(format!("{}", EvidenceKind::SecurityAudit), "security-audit");
        assert_eq!(format!("{}", EvidenceKind::FormalProof), "formal-proof");
        assert_eq!(format!("{}", EvidenceKind::CodeReview), "code-review");
        assert_eq!(format!("{}", EvidenceKind::DemoReplay), "demo-replay");
        assert_eq!(
            format!("{}", EvidenceKind::ThirdPartyVerification),
            "third-party-verification"
        );
    }

    #[test]
    fn linkage_verdict_display() {
        assert_eq!(format!("{}", LinkageVerdict::Pass), "pass");
        assert_eq!(format!("{}", LinkageVerdict::Fail), "fail");
        assert_eq!(format!("{}", LinkageVerdict::Empty), "empty");
    }

    #[test]
    fn demo_display() {
        let demo = make_demo("d1", true);
        let display = format!("{}", demo);
        assert!(display.contains("d1"));
        assert!(display.contains("complete"));
    }

    #[test]
    fn demo_incomplete_display() {
        let demo = make_demo("d1", false);
        let display = format!("{}", demo);
        assert!(display.contains("incomplete"));
    }

    #[test]
    fn claim_display() {
        let claim = make_claim("c1", ClaimCategory::Performance, vec!["d1"], vec!["e1"]);
        let display = format!("{}", claim);
        assert!(display.contains("c1"));
        assert!(display.contains("performance"));
    }

    #[test]
    fn decision_display() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        let display = format!("{}", decision);
        assert!(display.contains("m1"));
        assert!(display.contains("pass"));
    }

    #[test]
    fn verification_command_display() {
        let cmd = make_command("cmd1");
        let display = format!("{}", cmd);
        assert!(display.contains("cmd1"));
    }

    #[test]
    fn evidence_link_display() {
        let ev = make_evidence("e1");
        let display = format!("{}", ev);
        assert!(display.contains("e1"));
    }

    #[test]
    fn error_display() {
        assert_eq!(
            format!("{}", LinkageGateError::NoClaims),
            "no claims provided"
        );
        assert!(
            format!(
                "{}",
                LinkageGateError::TooManyClaims {
                    count: 300,
                    max: 256
                }
            )
            .contains("300")
        );
        assert!(
            format!(
                "{}",
                LinkageGateError::UnknownDemo {
                    claim_id: "c1".to_string(),
                    demo_id: "x".to_string()
                }
            )
            .contains("x")
        );
    }

    #[test]
    fn error_implements_std_error() {
        let err = LinkageGateError::NoClaims;
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn serde_roundtrip_claim() {
        let claim = make_claim("c1", ClaimCategory::Performance, vec!["d1"], vec!["e1"]);
        let json = serde_json::to_string(&claim).unwrap();
        let back: MilestoneClaim = serde_json::from_str(&json).unwrap();
        assert_eq!(claim, back);
    }

    #[test]
    fn serde_roundtrip_demo() {
        let demo = make_demo("d1", true);
        let json = serde_json::to_string(&demo).unwrap();
        let back: DemoSpecification = serde_json::from_str(&json).unwrap();
        assert_eq!(demo, back);
    }

    #[test]
    fn serde_roundtrip_decision() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        let json = serde_json::to_string(&decision).unwrap();
        let back: LinkageGateDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back);
    }

    #[test]
    fn serde_roundtrip_config() {
        let config = LinkageGateConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: LinkageGateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // ── Artifact Hash ───────────────────────────────────────────────

    #[test]
    fn artifact_hash_deterministic() {
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];

        let mut g1 = default_gate();
        let d1 = g1.evaluate("m1", &claims, &demos).unwrap();

        let mut g2 = default_gate();
        let d2 = g2.evaluate("m1", &claims, &demos).unwrap();

        assert_eq!(d1.artifact_hash, d2.artifact_hash);
    }

    // ── Edge Cases ──────────────────────────────────────────────────

    #[test]
    fn config_accessor() {
        let gate = default_gate();
        assert_eq!(gate.config().min_completeness_millionths, MILLION);
    }

    #[test]
    fn config_default_values() {
        let config = LinkageGateConfig::default();
        assert_eq!(config.min_completeness_millionths, MILLION);
        assert!(config.require_runnable_demo);
        assert!(config.require_evidence);
        assert!(config.require_expected_outputs);
        assert!(config.require_verification_commands);
    }

    #[test]
    fn demo_is_complete() {
        let demo = make_demo("d1", true);
        assert!(demo.is_complete());

        let demo2 = make_demo("d2", false);
        assert!(!demo2.is_complete());
    }

    #[test]
    fn demo_command_count() {
        let demo = make_demo("d1", true);
        assert_eq!(demo.command_count(), 1);
    }

    #[test]
    fn linkage_rate_zero_claims() {
        let decision = LinkageGateDecision {
            decision_id: "test".to_string(),
            milestone_id: "m1".to_string(),
            epoch: SecurityEpoch::from_raw(1),
            verdict: LinkageVerdict::Empty,
            claim_results: Vec::new(),
            total_claims: 0,
            linked_claims: 0,
            unlinked_claims: 0,
            aggregate_completeness_millionths: 0,
            rationale: "empty".to_string(),
            artifact_hash: ContentHash::compute(b"test"),
        };
        assert_eq!(decision.linkage_rate_millionths(), 0);
    }

    #[test]
    fn claim_with_multiple_demos() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true), make_demo("d2", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1", "d2"],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Pass);
    }

    #[test]
    fn rationale_mentions_unlinked() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![
            make_claim("c1", ClaimCategory::Performance, vec!["d1"], vec!["e1"]),
            make_claim("c2", ClaimCategory::Security, vec![], vec![]),
        ];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert!(decision.rationale.contains("c2"));
    }

    #[test]
    fn pass_rationale_mentions_all_linked() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert!(decision.rationale.contains("All"));
    }

    // ── Enrichment: Clone Equality ─────────────────────────────────

    #[test]
    fn clone_eq_demo_specification() {
        let demo = make_demo("d1", true);
        let cloned = demo.clone();
        assert_eq!(demo, cloned);
    }

    #[test]
    fn clone_eq_verification_command() {
        let cmd = make_command("cmd1");
        let cloned = cmd.clone();
        assert_eq!(cmd, cloned);
    }

    #[test]
    fn clone_eq_expected_output() {
        let out = make_output("out1");
        let cloned = out.clone();
        assert_eq!(out, cloned);
    }

    #[test]
    fn clone_eq_milestone_claim() {
        let claim = make_claim("c1", ClaimCategory::Correctness, vec!["d1"], vec!["e1"]);
        let cloned = claim.clone();
        assert_eq!(claim, cloned);
    }

    #[test]
    fn clone_eq_claim_linkage_result() {
        let result = ClaimLinkageResult {
            claim_id: "c1".to_string(),
            linked: true,
            has_runnable_demo: true,
            has_evidence: true,
            demos_have_outputs: true,
            demos_have_commands: true,
            missing: Vec::new(),
            completeness_millionths: MILLION,
        };
        let cloned = result.clone();
        assert_eq!(result, cloned);
    }

    // ── Enrichment: JSON Field Presence ────────────────────────────

    #[test]
    fn json_fields_demo_specification() {
        let demo = make_demo("d1", true);
        let json = serde_json::to_string(&demo).unwrap();
        assert!(json.contains("\"demo_id\""));
        assert!(json.contains("\"title\""));
        assert!(json.contains("\"description\""));
        assert!(json.contains("\"milestone_id\""));
        assert!(json.contains("\"runnable\""));
        assert!(json.contains("\"verification_commands\""));
        assert!(json.contains("\"expected_outputs\""));
        assert!(json.contains("\"tags\""));
    }

    #[test]
    fn json_fields_linkage_gate_decision() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        let json = serde_json::to_string(&decision).unwrap();
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"milestone_id\""));
        assert!(json.contains("\"epoch\""));
        assert!(json.contains("\"verdict\""));
        assert!(json.contains("\"claim_results\""));
        assert!(json.contains("\"total_claims\""));
        assert!(json.contains("\"linked_claims\""));
        assert!(json.contains("\"unlinked_claims\""));
        assert!(json.contains("\"aggregate_completeness_millionths\""));
        assert!(json.contains("\"rationale\""));
        assert!(json.contains("\"artifact_hash\""));
    }

    #[test]
    fn json_fields_linkage_gate_config() {
        let config = LinkageGateConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"epoch\""));
        assert!(json.contains("\"min_completeness_millionths\""));
        assert!(json.contains("\"require_runnable_demo\""));
        assert!(json.contains("\"require_evidence\""));
        assert!(json.contains("\"require_expected_outputs\""));
        assert!(json.contains("\"require_verification_commands\""));
    }

    // ── Enrichment: Serde, Display, Boundary, Error ────────────────

    #[test]
    fn serde_roundtrip_error() {
        let err = LinkageGateError::TooManyEvidenceLinks {
            claim_id: "c1".to_string(),
            count: 100,
            max: 64,
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: LinkageGateError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn display_uniqueness_all_claim_categories() {
        let categories = [
            ClaimCategory::Performance,
            ClaimCategory::Correctness,
            ClaimCategory::Security,
            ClaimCategory::Compatibility,
            ClaimCategory::Reliability,
            ClaimCategory::DeveloperExperience,
        ];
        let displays: BTreeSet<String> = categories.iter().map(|c| format!("{}", c)).collect();
        assert_eq!(displays.len(), categories.len());
    }

    #[test]
    fn zero_completeness_config_passes_any_claim() {
        let mut config = LinkageGateConfig {
            min_completeness_millionths: 0,
            ..Default::default()
        };
        config.require_runnable_demo = false;
        config.require_evidence = false;
        config.require_expected_outputs = false;
        config.require_verification_commands = false;
        let mut gate = DemoClaimLinkageGate::new(config).unwrap();
        let claims = vec![make_claim("c1", ClaimCategory::Reliability, vec![], vec![])];
        let decision = gate.evaluate("m1", &claims, &[]).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Pass);
        assert_eq!(decision.aggregate_completeness_millionths, MILLION);
    }

    #[test]
    fn error_source_is_none() {
        let err = LinkageGateError::NoClaims;
        let source = std::error::Error::source(&err);
        assert!(source.is_none());
    }

    // ── Enrichment: Copy Semantics ──────────────────────────────────

    #[test]
    fn copy_semantics_claim_category() {
        let a = ClaimCategory::Performance;
        let b = a; // Copy
        let c = a; // still valid after copy
        assert_eq!(b, c);
        assert_eq!(a, ClaimCategory::Performance);
    }

    #[test]
    fn copy_semantics_evidence_kind() {
        let a = EvidenceKind::FormalProof;
        let b = a;
        let c = a;
        assert_eq!(b, c);
        assert_eq!(a, EvidenceKind::FormalProof);
    }

    #[test]
    fn copy_semantics_linkage_verdict() {
        let a = LinkageVerdict::Fail;
        let b = a;
        let c = a;
        assert_eq!(b, c);
        assert_eq!(a, LinkageVerdict::Fail);
    }

    #[test]
    fn copy_all_claim_categories() {
        let variants = [
            ClaimCategory::Performance,
            ClaimCategory::Correctness,
            ClaimCategory::Security,
            ClaimCategory::Compatibility,
            ClaimCategory::Reliability,
            ClaimCategory::DeveloperExperience,
        ];
        for v in variants {
            let copied = v;
            assert_eq!(v, copied);
        }
    }

    #[test]
    fn copy_all_evidence_kinds() {
        let variants = [
            EvidenceKind::TestResult,
            EvidenceKind::BenchmarkResult,
            EvidenceKind::SecurityAudit,
            EvidenceKind::FormalProof,
            EvidenceKind::CodeReview,
            EvidenceKind::DemoReplay,
            EvidenceKind::ThirdPartyVerification,
        ];
        for v in variants {
            let copied = v;
            assert_eq!(v, copied);
        }
    }

    #[test]
    fn copy_all_linkage_verdicts() {
        let variants = [
            LinkageVerdict::Pass,
            LinkageVerdict::Fail,
            LinkageVerdict::Empty,
        ];
        for v in variants {
            let copied = v;
            assert_eq!(v, copied);
        }
    }

    // ── Enrichment: Debug Distinctness ──────────────────────────────

    #[test]
    fn debug_distinct_claim_category() {
        let variants: Vec<String> = [
            ClaimCategory::Performance,
            ClaimCategory::Correctness,
            ClaimCategory::Security,
            ClaimCategory::Compatibility,
            ClaimCategory::Reliability,
            ClaimCategory::DeveloperExperience,
        ]
        .iter()
        .map(|v| format!("{:?}", v))
        .collect();
        let unique: BTreeSet<&String> = variants.iter().collect();
        assert_eq!(unique.len(), 6);
    }

    #[test]
    fn debug_distinct_evidence_kind() {
        let variants: Vec<String> = [
            EvidenceKind::TestResult,
            EvidenceKind::BenchmarkResult,
            EvidenceKind::SecurityAudit,
            EvidenceKind::FormalProof,
            EvidenceKind::CodeReview,
            EvidenceKind::DemoReplay,
            EvidenceKind::ThirdPartyVerification,
        ]
        .iter()
        .map(|v| format!("{:?}", v))
        .collect();
        let unique: BTreeSet<&String> = variants.iter().collect();
        assert_eq!(unique.len(), 7);
    }

    #[test]
    fn debug_distinct_linkage_verdict() {
        let variants: Vec<String> = [
            LinkageVerdict::Pass,
            LinkageVerdict::Fail,
            LinkageVerdict::Empty,
        ]
        .iter()
        .map(|v| format!("{:?}", v))
        .collect();
        let unique: BTreeSet<&String> = variants.iter().collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn debug_distinct_linkage_gate_error() {
        let variants: Vec<String> = [
            LinkageGateError::NoClaims,
            LinkageGateError::TooManyClaims {
                count: 300,
                max: 256,
            },
            LinkageGateError::DuplicateClaim {
                claim_id: "c1".into(),
            },
            LinkageGateError::DuplicateDemo {
                demo_id: "d1".into(),
            },
            LinkageGateError::TooManyEvidenceLinks {
                claim_id: "c1".into(),
                count: 100,
                max: 64,
            },
            LinkageGateError::TooManyCommands {
                demo_id: "d1".into(),
                count: 50,
                max: 32,
            },
            LinkageGateError::UnknownDemo {
                claim_id: "c1".into(),
                demo_id: "d1".into(),
            },
            LinkageGateError::InvalidConfig {
                detail: "bad".into(),
            },
        ]
        .iter()
        .map(|v| format!("{:?}", v))
        .collect();
        let unique: BTreeSet<&String> = variants.iter().collect();
        assert_eq!(unique.len(), 8);
    }

    // ── Enrichment: Serde Variant Distinctness ──────────────────────

    #[test]
    fn serde_distinct_claim_category() {
        let variants = [
            ClaimCategory::Performance,
            ClaimCategory::Correctness,
            ClaimCategory::Security,
            ClaimCategory::Compatibility,
            ClaimCategory::Reliability,
            ClaimCategory::DeveloperExperience,
        ];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(jsons.len(), 6);
    }

    #[test]
    fn serde_distinct_evidence_kind() {
        let variants = [
            EvidenceKind::TestResult,
            EvidenceKind::BenchmarkResult,
            EvidenceKind::SecurityAudit,
            EvidenceKind::FormalProof,
            EvidenceKind::CodeReview,
            EvidenceKind::DemoReplay,
            EvidenceKind::ThirdPartyVerification,
        ];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(jsons.len(), 7);
    }

    #[test]
    fn serde_distinct_linkage_verdict() {
        let variants = [
            LinkageVerdict::Pass,
            LinkageVerdict::Fail,
            LinkageVerdict::Empty,
        ];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(jsons.len(), 3);
    }

    #[test]
    fn serde_distinct_all_error_variants() {
        let variants = [
            LinkageGateError::NoClaims,
            LinkageGateError::TooManyClaims { count: 1, max: 1 },
            LinkageGateError::DuplicateClaim {
                claim_id: "x".into(),
            },
            LinkageGateError::DuplicateDemo {
                demo_id: "x".into(),
            },
            LinkageGateError::TooManyEvidenceLinks {
                claim_id: "x".into(),
                count: 1,
                max: 1,
            },
            LinkageGateError::TooManyCommands {
                demo_id: "x".into(),
                count: 1,
                max: 1,
            },
            LinkageGateError::UnknownDemo {
                claim_id: "x".into(),
                demo_id: "x".into(),
            },
            LinkageGateError::InvalidConfig { detail: "x".into() },
        ];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(jsons.len(), 8);
    }

    // ── Enrichment: Clone Independence ──────────────────────────────

    #[test]
    fn clone_independence_demo_specification() {
        let demo = make_demo("d1", true);
        let mut cloned = demo.clone();
        cloned.demo_id = "d2".to_string();
        cloned.title = "Changed".to_string();
        assert_eq!(demo.demo_id, "d1");
        assert_eq!(demo.title, "Demo d1");
    }

    #[test]
    fn clone_independence_verification_command() {
        let cmd = make_command("cmd1");
        let mut cloned = cmd.clone();
        cloned.command_id = "cmd2".to_string();
        cloned.expected_exit_code = 1;
        assert_eq!(cmd.command_id, "cmd1");
        assert_eq!(cmd.expected_exit_code, 0);
    }

    #[test]
    fn clone_independence_expected_output() {
        let out = make_output("out1");
        let mut cloned = out.clone();
        cloned.name = "out2".to_string();
        cloned.exact_match = false;
        assert_eq!(out.name, "out1");
        assert!(out.exact_match);
    }

    #[test]
    fn clone_independence_milestone_claim() {
        let claim = make_claim("c1", ClaimCategory::Security, vec!["d1"], vec!["e1"]);
        let mut cloned = claim.clone();
        cloned.claim_id = "c2".to_string();
        cloned.evidence_links.clear();
        assert_eq!(claim.claim_id, "c1");
        assert_eq!(claim.evidence_links.len(), 1);
    }

    #[test]
    fn clone_independence_evidence_link() {
        let ev = make_evidence("e1");
        let mut cloned = ev.clone();
        cloned.evidence_id = "e2".to_string();
        cloned.description = "Changed".to_string();
        assert_eq!(ev.evidence_id, "e1");
        assert_eq!(ev.description, "Evidence e1");
    }

    #[test]
    fn clone_independence_linkage_gate_config() {
        let cfg = LinkageGateConfig::default();
        let mut cloned = cfg.clone();
        cloned.min_completeness_millionths = 0;
        cloned.require_evidence = false;
        assert_eq!(cloned.min_completeness_millionths, 0);
        assert!(!cloned.require_evidence);
        assert_eq!(cfg.min_completeness_millionths, MILLION);
        assert!(cfg.require_evidence);
    }

    #[test]
    fn clone_independence_claim_linkage_result() {
        let result = ClaimLinkageResult {
            claim_id: "c1".to_string(),
            linked: true,
            has_runnable_demo: true,
            has_evidence: true,
            demos_have_outputs: true,
            demos_have_commands: true,
            missing: Vec::new(),
            completeness_millionths: MILLION,
        };
        let mut cloned = result.clone();
        cloned.claim_id = "c2".to_string();
        cloned.linked = false;
        cloned.missing.push("something".to_string());
        assert_eq!(result.claim_id, "c1");
        assert!(result.linked);
        assert!(result.missing.is_empty());
    }

    #[test]
    fn clone_independence_linkage_gate_decision() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        let mut cloned = decision.clone();
        cloned.milestone_id = "m2".to_string();
        cloned.verdict = LinkageVerdict::Fail;
        assert_eq!(decision.milestone_id, "m1");
        assert_eq!(decision.verdict, LinkageVerdict::Pass);
    }

    #[test]
    fn clone_independence_linkage_gate_error() {
        let err = LinkageGateError::DuplicateClaim {
            claim_id: "c1".to_string(),
        };
        let mut cloned = err.clone();
        if let LinkageGateError::DuplicateClaim { ref mut claim_id } = cloned {
            *claim_id = "c2".to_string();
        }
        assert_eq!(
            err,
            LinkageGateError::DuplicateClaim {
                claim_id: "c1".to_string()
            }
        );
    }

    #[test]
    fn clone_independence_gate_itself() {
        let gate = default_gate();
        let mut cloned = gate.clone();
        // Evaluate on cloned to increment its count
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let _ = cloned.evaluate("m1", &claims, &demos);
        assert_eq!(gate.evaluation_count(), 0);
        assert_eq!(cloned.evaluation_count(), 1);
    }

    // ── Enrichment: JSON Field-Name Stability ───────────────────────

    #[test]
    fn json_field_names_verification_command() {
        let cmd = make_command("cmd1");
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"command_id\""));
        assert!(json.contains("\"command\""));
        assert!(json.contains("\"expected_exit_code\""));
        assert!(json.contains("\"timeout_ms\""));
        assert!(json.contains("\"deterministic\""));
    }

    #[test]
    fn json_field_names_expected_output() {
        let out = make_output("out1");
        let json = serde_json::to_string(&out).unwrap();
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"expected_hash\""));
        assert!(json.contains("\"exact_match\""));
        assert!(json.contains("\"tolerance_millionths\""));
    }

    #[test]
    fn json_field_names_milestone_claim() {
        let claim = make_claim("c1", ClaimCategory::Performance, vec!["d1"], vec!["e1"]);
        let json = serde_json::to_string(&claim).unwrap();
        assert!(json.contains("\"claim_id\""));
        assert!(json.contains("\"statement\""));
        assert!(json.contains("\"milestone_id\""));
        assert!(json.contains("\"category\""));
        assert!(json.contains("\"evidence_links\""));
        assert!(json.contains("\"demos\""));
    }

    #[test]
    fn json_field_names_evidence_link() {
        let ev = make_evidence("e1");
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"evidence_id\""));
        assert!(json.contains("\"kind\""));
        assert!(json.contains("\"artifact_hash\""));
        assert!(json.contains("\"description\""));
    }

    #[test]
    fn json_field_names_claim_linkage_result() {
        let result = ClaimLinkageResult {
            claim_id: "c1".to_string(),
            linked: true,
            has_runnable_demo: true,
            has_evidence: true,
            demos_have_outputs: true,
            demos_have_commands: true,
            missing: Vec::new(),
            completeness_millionths: MILLION,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"claim_id\""));
        assert!(json.contains("\"linked\""));
        assert!(json.contains("\"has_runnable_demo\""));
        assert!(json.contains("\"has_evidence\""));
        assert!(json.contains("\"demos_have_outputs\""));
        assert!(json.contains("\"demos_have_commands\""));
        assert!(json.contains("\"missing\""));
        assert!(json.contains("\"completeness_millionths\""));
    }

    // ── Enrichment: Display Format Checks ───────────────────────────

    #[test]
    fn display_demo_specification_complete_format() {
        let demo = make_demo("alpha", true);
        let s = format!("{}", demo);
        assert_eq!(s, "demo(alpha, Demo alpha, complete)");
    }

    #[test]
    fn display_demo_specification_incomplete_format() {
        let demo = make_demo("beta", false);
        let s = format!("{}", demo);
        assert_eq!(s, "demo(beta, Demo beta, incomplete)");
    }

    #[test]
    fn display_verification_command_format() {
        let cmd = VerificationCommand {
            command_id: "vc-99".to_string(),
            command: "cargo test".to_string(),
            expected_exit_code: 42,
            timeout_ms: 1000,
            deterministic: false,
        };
        assert_eq!(format!("{}", cmd), "cmd(vc-99, exit=42)");
    }

    #[test]
    fn display_evidence_link_format() {
        let ev = EvidenceLink {
            evidence_id: "ev-77".to_string(),
            kind: EvidenceKind::SecurityAudit,
            artifact_hash: ContentHash::compute(b"x"),
            description: "desc".to_string(),
        };
        assert_eq!(format!("{}", ev), "evidence(ev-77, security-audit)");
    }

    #[test]
    fn display_milestone_claim_format() {
        let claim = MilestoneClaim {
            claim_id: "mc-1".to_string(),
            statement: "We do X".to_string(),
            milestone_id: "m5".to_string(),
            category: ClaimCategory::Reliability,
            evidence_links: vec![make_evidence("e1"), make_evidence("e2")],
            demos: vec!["d1".into(), "d2".into(), "d3".into()],
        };
        assert_eq!(
            format!("{}", claim),
            "claim(mc-1, reliability, evidence=2, demos=3)"
        );
    }

    #[test]
    fn display_linkage_gate_decision_format() {
        let decision = LinkageGateDecision {
            decision_id: "test".to_string(),
            milestone_id: "m7".to_string(),
            epoch: SecurityEpoch::from_raw(5),
            verdict: LinkageVerdict::Fail,
            claim_results: Vec::new(),
            total_claims: 10,
            linked_claims: 3,
            unlinked_claims: 7,
            aggregate_completeness_millionths: 300_000,
            rationale: "some reason".to_string(),
            artifact_hash: ContentHash::compute(b"x"),
        };
        assert_eq!(
            format!("{}", decision),
            "linkage-gate(m7, fail, linked=3/10, completeness=300000)"
        );
    }

    #[test]
    fn display_error_duplicate_claim() {
        let err = LinkageGateError::DuplicateClaim {
            claim_id: "abc".to_string(),
        };
        assert_eq!(format!("{}", err), "duplicate claim ID: abc");
    }

    #[test]
    fn display_error_duplicate_demo() {
        let err = LinkageGateError::DuplicateDemo {
            demo_id: "xyz".to_string(),
        };
        assert_eq!(format!("{}", err), "duplicate demo ID: xyz");
    }

    #[test]
    fn display_error_too_many_evidence_links() {
        let err = LinkageGateError::TooManyEvidenceLinks {
            claim_id: "c5".to_string(),
            count: 80,
            max: 64,
        };
        assert_eq!(format!("{}", err), "claim c5 has 80 evidence links, max 64");
    }

    #[test]
    fn display_error_too_many_commands() {
        let err = LinkageGateError::TooManyCommands {
            demo_id: "d9".to_string(),
            count: 40,
            max: 32,
        };
        assert_eq!(format!("{}", err), "demo d9 has 40 commands, max 32");
    }

    #[test]
    fn display_error_unknown_demo() {
        let err = LinkageGateError::UnknownDemo {
            claim_id: "c3".to_string(),
            demo_id: "d_missing".to_string(),
        };
        assert_eq!(
            format!("{}", err),
            "claim c3 references unknown demo d_missing"
        );
    }

    #[test]
    fn display_error_invalid_config() {
        let err = LinkageGateError::InvalidConfig {
            detail: "bad range".to_string(),
        };
        assert_eq!(format!("{}", err), "invalid config: bad range");
    }

    // ── Enrichment: Hash Consistency ────────────────────────────────

    #[test]
    fn hash_consistency_claim_category() {
        // ClaimCategory does not derive Hash, so we test serde stability instead
        let a = serde_json::to_string(&ClaimCategory::Security).unwrap();
        let b = serde_json::to_string(&ClaimCategory::Security).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn hash_consistency_evidence_kind() {
        let a = serde_json::to_string(&EvidenceKind::CodeReview).unwrap();
        let b = serde_json::to_string(&EvidenceKind::CodeReview).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn artifact_hash_differs_for_different_milestones() {
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let mut g1 = default_gate();
        let d1 = g1.evaluate("m1", &claims, &demos).unwrap();
        let mut g2 = default_gate();
        let d2 = g2.evaluate("m2", &claims, &demos).unwrap();
        assert_ne!(d1.artifact_hash, d2.artifact_hash);
    }

    #[test]
    fn artifact_hash_differs_for_different_claims() {
        let demos = vec![make_demo("d1", true), make_demo("d2", true)];
        let claims_a = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let claims_b = vec![make_claim(
            "c2",
            ClaimCategory::Security,
            vec!["d2"],
            vec!["e2"],
        )];
        let mut g1 = default_gate();
        let d1 = g1.evaluate("m1", &claims_a, &demos).unwrap();
        let mut g2 = default_gate();
        let d2 = g2.evaluate("m1", &claims_b, &demos).unwrap();
        assert_ne!(d1.artifact_hash, d2.artifact_hash);
    }

    // ── Enrichment: Boundary / Edge Cases ───────────────────────────

    #[test]
    fn boundary_max_timeout_u64() {
        let cmd = VerificationCommand {
            command_id: "cmd1".to_string(),
            command: "test".to_string(),
            expected_exit_code: 0,
            timeout_ms: u64::MAX,
            deterministic: true,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let back: VerificationCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(back.timeout_ms, u64::MAX);
    }

    #[test]
    fn boundary_tolerance_max_i64() {
        let out = ExpectedOutput {
            name: "out".to_string(),
            expected_hash: None,
            exact_match: false,
            tolerance_millionths: i64::MAX,
        };
        let json = serde_json::to_string(&out).unwrap();
        let back: ExpectedOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tolerance_millionths, i64::MAX);
    }

    #[test]
    fn boundary_tolerance_min_i64() {
        let out = ExpectedOutput {
            name: "out".to_string(),
            expected_hash: None,
            exact_match: false,
            tolerance_millionths: i64::MIN,
        };
        let json = serde_json::to_string(&out).unwrap();
        let back: ExpectedOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tolerance_millionths, i64::MIN);
    }

    #[test]
    fn boundary_empty_strings() {
        let demo = DemoSpecification {
            demo_id: String::new(),
            title: String::new(),
            description: String::new(),
            milestone_id: String::new(),
            runnable: false,
            verification_commands: Vec::new(),
            expected_outputs: BTreeMap::new(),
            tags: BTreeSet::new(),
        };
        let json = serde_json::to_string(&demo).unwrap();
        let back: DemoSpecification = serde_json::from_str(&json).unwrap();
        assert_eq!(demo, back);
    }

    #[test]
    fn boundary_empty_evidence_links() {
        let claim = MilestoneClaim {
            claim_id: "c1".to_string(),
            statement: "s".to_string(),
            milestone_id: "m1".to_string(),
            category: ClaimCategory::Correctness,
            evidence_links: Vec::new(),
            demos: Vec::new(),
        };
        let json = serde_json::to_string(&claim).unwrap();
        let back: MilestoneClaim = serde_json::from_str(&json).unwrap();
        assert_eq!(claim, back);
    }

    #[test]
    fn boundary_empty_missing_list() {
        let result = ClaimLinkageResult {
            claim_id: "c1".to_string(),
            linked: true,
            has_runnable_demo: true,
            has_evidence: true,
            demos_have_outputs: true,
            demos_have_commands: true,
            missing: Vec::new(),
            completeness_millionths: MILLION,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"missing\":[]"));
    }

    #[test]
    fn boundary_expected_output_no_hash() {
        let out = ExpectedOutput {
            name: "nullable".to_string(),
            expected_hash: None,
            exact_match: false,
            tolerance_millionths: 500_000,
        };
        let json = serde_json::to_string(&out).unwrap();
        assert!(json.contains("\"expected_hash\":null"));
        let back: ExpectedOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(out, back);
    }

    #[test]
    fn boundary_config_zero_completeness() {
        let config = LinkageGateConfig {
            min_completeness_millionths: 0,
            ..Default::default()
        };
        let gate = DemoClaimLinkageGate::new(config);
        assert!(gate.is_ok());
    }

    #[test]
    fn boundary_config_exact_million_completeness() {
        let config = LinkageGateConfig {
            min_completeness_millionths: MILLION,
            ..Default::default()
        };
        let gate = DemoClaimLinkageGate::new(config);
        assert!(gate.is_ok());
    }

    #[test]
    fn boundary_max_claims_exactly() {
        let mut gate = default_gate();
        let demo = make_demo("d1", true);
        let claims: Vec<_> = (0..256)
            .map(|i| {
                make_claim(
                    &format!("c{}", i),
                    ClaimCategory::Performance,
                    vec!["d1"],
                    vec!["e1"],
                )
            })
            .collect();
        let result = gate.evaluate("m1", &claims, &[demo]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().total_claims, 256);
    }

    #[test]
    fn boundary_epoch_u64_max() {
        let config = LinkageGateConfig {
            epoch: SecurityEpoch::from_raw(u64::MAX),
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: LinkageGateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.epoch, SecurityEpoch::from_raw(u64::MAX));
    }

    #[test]
    fn boundary_epoch_zero() {
        let config = LinkageGateConfig {
            epoch: SecurityEpoch::from_raw(0),
            ..Default::default()
        };
        let gate = DemoClaimLinkageGate::new(config);
        assert!(gate.is_ok());
    }

    #[test]
    fn boundary_negative_exit_code() {
        let cmd = VerificationCommand {
            command_id: "c1".to_string(),
            command: "fail".to_string(),
            expected_exit_code: -1,
            timeout_ms: 0,
            deterministic: false,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let back: VerificationCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expected_exit_code, -1);
    }

    #[test]
    fn boundary_demo_with_many_tags() {
        let mut tags = BTreeSet::new();
        for i in 0..100 {
            tags.insert(format!("tag-{}", i));
        }
        let demo = DemoSpecification {
            demo_id: "d1".to_string(),
            title: "t".to_string(),
            description: "d".to_string(),
            milestone_id: "m1".to_string(),
            runnable: true,
            verification_commands: vec![make_command("cmd1")],
            expected_outputs: {
                let mut m = BTreeMap::new();
                m.insert("o".to_string(), make_output("o"));
                m
            },
            tags,
        };
        let json = serde_json::to_string(&demo).unwrap();
        let back: DemoSpecification = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tags.len(), 100);
    }

    // ── Enrichment: Serde Roundtrips (complex structs) ──────────────

    #[test]
    fn serde_roundtrip_evidence_link() {
        let ev = EvidenceLink {
            evidence_id: "ev-complex".to_string(),
            kind: EvidenceKind::ThirdPartyVerification,
            artifact_hash: ContentHash::compute(b"complex-data"),
            description: "Complex evidence with special chars: <>&\"".to_string(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: EvidenceLink = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn serde_roundtrip_verification_command() {
        let cmd = VerificationCommand {
            command_id: "vc-round".to_string(),
            command: "echo 'hello world' | grep world".to_string(),
            expected_exit_code: 0,
            timeout_ms: 999_999,
            deterministic: false,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let back: VerificationCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(cmd, back);
    }

    #[test]
    fn serde_roundtrip_expected_output() {
        let out = ExpectedOutput {
            name: "out-trip".to_string(),
            expected_hash: Some(ContentHash::compute(b"trip")),
            exact_match: true,
            tolerance_millionths: 100,
        };
        let json = serde_json::to_string(&out).unwrap();
        let back: ExpectedOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(out, back);
    }

    #[test]
    fn serde_roundtrip_claim_linkage_result() {
        let result = ClaimLinkageResult {
            claim_id: "clr-1".to_string(),
            linked: false,
            has_runnable_demo: false,
            has_evidence: true,
            demos_have_outputs: false,
            demos_have_commands: false,
            missing: vec!["no demo".to_string(), "no outputs".to_string()],
            completeness_millionths: 250_000,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ClaimLinkageResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn serde_roundtrip_all_error_variants() {
        let variants = vec![
            LinkageGateError::NoClaims,
            LinkageGateError::TooManyClaims {
                count: 300,
                max: 256,
            },
            LinkageGateError::DuplicateClaim {
                claim_id: "dup".into(),
            },
            LinkageGateError::DuplicateDemo {
                demo_id: "dup".into(),
            },
            LinkageGateError::TooManyEvidenceLinks {
                claim_id: "c".into(),
                count: 100,
                max: 64,
            },
            LinkageGateError::TooManyCommands {
                demo_id: "d".into(),
                count: 50,
                max: 32,
            },
            LinkageGateError::UnknownDemo {
                claim_id: "c".into(),
                demo_id: "d".into(),
            },
            LinkageGateError::InvalidConfig {
                detail: "oops".into(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: LinkageGateError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn serde_roundtrip_gate_struct() {
        let gate = default_gate();
        let json = serde_json::to_string(&gate).unwrap();
        let back: DemoClaimLinkageGate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.evaluation_count(), 0);
    }

    #[test]
    fn serde_roundtrip_decision_fail_verdict() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim("c1", ClaimCategory::Security, vec![], vec![])];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Fail);
        let json = serde_json::to_string(&decision).unwrap();
        let back: LinkageGateDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back);
    }

    #[test]
    fn serde_roundtrip_claim_all_categories() {
        let categories = [
            ClaimCategory::Performance,
            ClaimCategory::Correctness,
            ClaimCategory::Security,
            ClaimCategory::Compatibility,
            ClaimCategory::Reliability,
            ClaimCategory::DeveloperExperience,
        ];
        for cat in &categories {
            let json = serde_json::to_string(cat).unwrap();
            let back: ClaimCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*cat, back);
        }
    }

    #[test]
    fn serde_roundtrip_evidence_all_kinds() {
        let kinds = [
            EvidenceKind::TestResult,
            EvidenceKind::BenchmarkResult,
            EvidenceKind::SecurityAudit,
            EvidenceKind::FormalProof,
            EvidenceKind::CodeReview,
            EvidenceKind::DemoReplay,
            EvidenceKind::ThirdPartyVerification,
        ];
        for k in &kinds {
            let json = serde_json::to_string(k).unwrap();
            let back: EvidenceKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    #[test]
    fn serde_roundtrip_verdicts_all() {
        let verdicts = [
            LinkageVerdict::Pass,
            LinkageVerdict::Fail,
            LinkageVerdict::Empty,
        ];
        for v in &verdicts {
            let json = serde_json::to_string(v).unwrap();
            let back: LinkageVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // ── Enrichment: Schema Version Constant ─────────────────────────

    #[test]
    fn schema_version_constant_is_stable() {
        assert_eq!(
            LINKAGE_GATE_SCHEMA_VERSION,
            "franken-engine.demo-claim-linkage-gate.v1"
        );
    }

    // ── Enrichment: Decision ID Format ──────────────────────────────

    #[test]
    fn decision_id_includes_milestone_and_epoch() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        assert!(decision.decision_id.starts_with("linkage-m1-1-"));
    }

    #[test]
    fn decision_id_increments_with_evaluations() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec!["e1"],
        )];
        let d1 = gate.evaluate("m1", &claims, &demos).unwrap();
        let d2 = gate.evaluate("m1", &claims, &demos).unwrap();
        assert_ne!(d1.decision_id, d2.decision_id);
        assert!(d1.decision_id.ends_with("-1"));
        assert!(d2.decision_id.ends_with("-2"));
    }

    // ── Enrichment: Relaxed Config Combinations ─────────────────────

    #[test]
    fn all_requirements_disabled_passes_empty_claim() {
        let config = LinkageGateConfig {
            require_runnable_demo: false,
            require_evidence: false,
            require_expected_outputs: false,
            require_verification_commands: false,
            ..Default::default()
        };
        let mut gate = DemoClaimLinkageGate::new(config).unwrap();
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::DeveloperExperience,
            vec![],
            vec![],
        )];
        let decision = gate.evaluate("m1", &claims, &[]).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Pass);
    }

    #[test]
    fn only_evidence_required_passes_with_evidence() {
        let config = LinkageGateConfig {
            require_runnable_demo: false,
            require_evidence: true,
            require_expected_outputs: false,
            require_verification_commands: false,
            ..Default::default()
        };
        let mut gate = DemoClaimLinkageGate::new(config).unwrap();
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Correctness,
            vec![],
            vec!["e1"],
        )];
        let decision = gate.evaluate("m1", &claims, &[]).unwrap();
        assert_eq!(decision.verdict, LinkageVerdict::Pass);
    }

    // ── Enrichment: Missing Reasons ─────────────────────────────────

    #[test]
    fn missing_reasons_fully_incomplete() {
        let mut gate = default_gate();
        let claims = vec![make_claim("c1", ClaimCategory::Performance, vec![], vec![])];
        let decision = gate.evaluate("m1", &claims, &[]).unwrap();
        let r = &decision.claim_results[0];
        assert!(!r.linked);
        assert!(!r.has_evidence);
        assert!(!r.has_runnable_demo);
        assert!(!r.demos_have_outputs);
        assert!(!r.demos_have_commands);
        assert!(r.missing.len() >= 4);
    }

    #[test]
    fn missing_reasons_only_missing_evidence() {
        let mut gate = default_gate();
        let demos = vec![make_demo("d1", true)];
        let claims = vec![make_claim(
            "c1",
            ClaimCategory::Performance,
            vec!["d1"],
            vec![], // no evidence
        )];
        let decision = gate.evaluate("m1", &claims, &demos).unwrap();
        let r = &decision.claim_results[0];
        assert!(!r.linked);
        assert!(r.has_runnable_demo);
        assert!(!r.has_evidence);
        assert_eq!(r.missing.len(), 1);
        assert!(r.missing[0].contains("evidence"));
    }

    // ── Enrichment: Demo is_complete Edge Cases ─────────────────────

    #[test]
    fn demo_runnable_but_no_commands_is_incomplete() {
        let demo = DemoSpecification {
            demo_id: "d1".to_string(),
            title: "t".to_string(),
            description: "d".to_string(),
            milestone_id: "m1".to_string(),
            runnable: true,
            verification_commands: Vec::new(),
            expected_outputs: {
                let mut m = BTreeMap::new();
                m.insert("o".into(), make_output("o"));
                m
            },
            tags: BTreeSet::new(),
        };
        assert!(!demo.is_complete());
    }

    #[test]
    fn demo_runnable_but_no_outputs_is_incomplete() {
        let demo = DemoSpecification {
            demo_id: "d1".to_string(),
            title: "t".to_string(),
            description: "d".to_string(),
            milestone_id: "m1".to_string(),
            runnable: true,
            verification_commands: vec![make_command("cmd1")],
            expected_outputs: BTreeMap::new(),
            tags: BTreeSet::new(),
        };
        assert!(!demo.is_complete());
    }

    #[test]
    fn demo_not_runnable_with_commands_and_outputs_is_incomplete() {
        let demo = DemoSpecification {
            demo_id: "d1".to_string(),
            title: "t".to_string(),
            description: "d".to_string(),
            milestone_id: "m1".to_string(),
            runnable: false,
            verification_commands: vec![make_command("cmd1")],
            expected_outputs: {
                let mut m = BTreeMap::new();
                m.insert("o".into(), make_output("o"));
                m
            },
            tags: BTreeSet::new(),
        };
        assert!(!demo.is_complete());
    }

    #[test]
    fn demo_command_count_zero() {
        let demo = make_demo("d1", false);
        assert_eq!(demo.command_count(), 0);
    }

    // ── Enrichment: Linkage Rate Fractions ──────────────────────────

    #[test]
    fn linkage_rate_one_of_three() {
        let decision = LinkageGateDecision {
            decision_id: "t".to_string(),
            milestone_id: "m".to_string(),
            epoch: SecurityEpoch::from_raw(1),
            verdict: LinkageVerdict::Fail,
            claim_results: Vec::new(),
            total_claims: 3,
            linked_claims: 1,
            unlinked_claims: 2,
            aggregate_completeness_millionths: 333_333,
            rationale: "".to_string(),
            artifact_hash: ContentHash::compute(b"x"),
        };
        assert_eq!(decision.linkage_rate_millionths(), 333_333); // 1/3
    }

    #[test]
    fn linkage_rate_all_linked() {
        let decision = LinkageGateDecision {
            decision_id: "t".to_string(),
            milestone_id: "m".to_string(),
            epoch: SecurityEpoch::from_raw(1),
            verdict: LinkageVerdict::Pass,
            claim_results: Vec::new(),
            total_claims: 5,
            linked_claims: 5,
            unlinked_claims: 0,
            aggregate_completeness_millionths: MILLION,
            rationale: "".to_string(),
            artifact_hash: ContentHash::compute(b"x"),
        };
        assert_eq!(decision.linkage_rate_millionths(), MILLION);
    }
}
