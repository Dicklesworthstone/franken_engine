//! Budgeted synthesis engine with equivalence proofs and cost models.
//!
//! Implements [RGC-613B]: bounded search over hot kernels, proof-backed
//! candidate admission, counterexample archives, and hardware-aware ranking.
//!
//! # Design
//!
//! - `SynthesisCandidate` represents a proposed alternative for a hot kernel.
//! - `EquivalenceProof` certifies that candidate and original have identical
//!   observable behavior for a given input class.
//! - `Counterexample` records a divergence between candidate and original.
//! - `CostModel` estimates hardware-specific execution cost.
//! - `SynthesisBudget` constrains search time and candidate count.
//! - `SynthesisSession` runs bounded search and produces a `SynthesisReport`.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-613B]

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.budgeted-synthesis-engine.v1";

/// Component name.
pub const COMPONENT: &str = "budgeted_synthesis_engine";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.7.13.2";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-613B";

/// Fixed-point unit.
const MILLION: u64 = 1_000_000;

/// Default maximum candidates per kernel.
pub const DEFAULT_MAX_CANDIDATES: u32 = 64;

/// Default search budget in time units (millionths of seconds).
pub const DEFAULT_SEARCH_BUDGET: u64 = 5_000_000; // 5 seconds

/// Maximum counterexamples to archive per candidate.
pub const MAX_COUNTEREXAMPLES: usize = 32;

/// Minimum speedup threshold for candidate admission (millionths).
/// A candidate must be at least 5% faster to be worth considering.
pub const MIN_SPEEDUP_THRESHOLD: u64 = 50_000;

// ---------------------------------------------------------------------------
// ProofStatus
// ---------------------------------------------------------------------------

/// Status of an equivalence proof attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    /// Proof succeeded: candidate is equivalent.
    Verified,
    /// Proof failed: divergence found.
    Refuted,
    /// Proof timed out: could not decide in budget.
    TimedOut,
    /// Proof not attempted (e.g., budget exhausted).
    Skipped,
}

impl ProofStatus {
    pub const ALL: &[Self] = &[Self::Verified, Self::Refuted, Self::TimedOut, Self::Skipped];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Refuted => "refuted",
            Self::TimedOut => "timed_out",
            Self::Skipped => "skipped",
        }
    }

    pub const fn is_verified(self) -> bool {
        matches!(self, Self::Verified)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Verified | Self::Refuted)
    }
}

impl fmt::Display for ProofStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CandidateOrigin
// ---------------------------------------------------------------------------

/// How a synthesis candidate was generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateOrigin {
    /// Enumerative search over instruction sequences.
    Enumerative,
    /// Stochastic superoptimization.
    Stochastic,
    /// Template-based pattern matching.
    TemplateBased,
    /// Rule-based algebraic simplification.
    AlgebraicSimplification,
    /// Manually provided candidate.
    Manual,
}

impl CandidateOrigin {
    pub const ALL: &[Self] = &[
        Self::Enumerative,
        Self::Stochastic,
        Self::TemplateBased,
        Self::AlgebraicSimplification,
        Self::Manual,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enumerative => "enumerative",
            Self::Stochastic => "stochastic",
            Self::TemplateBased => "template_based",
            Self::AlgebraicSimplification => "algebraic_simplification",
            Self::Manual => "manual",
        }
    }
}

impl fmt::Display for CandidateOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// EquivalenceProof
// ---------------------------------------------------------------------------

/// A proof (or refutation) of equivalence between original and candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivalenceProof {
    /// Proof status.
    pub status: ProofStatus,
    /// Number of input classes tested.
    pub input_classes_tested: u32,
    /// Number of input classes verified.
    pub input_classes_verified: u32,
    /// Time spent on proof (millionths of seconds).
    pub proof_time_millionths: u64,
    /// Content hash of the proof artifact.
    pub content_hash: ContentHash,
}

impl EquivalenceProof {
    /// Create a verified proof.
    pub fn verified(classes_tested: u32, proof_time: u64) -> Self {
        let mut h = Sha256::new();
        h.update(b"verified");
        h.update(classes_tested.to_le_bytes());
        h.update(proof_time.to_le_bytes());
        Self {
            status: ProofStatus::Verified,
            input_classes_tested: classes_tested,
            input_classes_verified: classes_tested,
            proof_time_millionths: proof_time,
            content_hash: ContentHash::compute(&h.finalize()),
        }
    }

    /// Create a refuted proof.
    pub fn refuted(classes_tested: u32, classes_verified: u32, proof_time: u64) -> Self {
        let mut h = Sha256::new();
        h.update(b"refuted");
        h.update(classes_tested.to_le_bytes());
        h.update(classes_verified.to_le_bytes());
        h.update(proof_time.to_le_bytes());
        Self {
            status: ProofStatus::Refuted,
            input_classes_tested: classes_tested,
            input_classes_verified: classes_verified,
            proof_time_millionths: proof_time,
            content_hash: ContentHash::compute(&h.finalize()),
        }
    }

    /// Create a timed-out proof.
    pub fn timed_out(classes_tested: u32, classes_verified: u32, proof_time: u64) -> Self {
        let mut h = Sha256::new();
        h.update(b"timed_out");
        h.update(classes_tested.to_le_bytes());
        h.update(proof_time.to_le_bytes());
        Self {
            status: ProofStatus::TimedOut,
            input_classes_tested: classes_tested,
            input_classes_verified: classes_verified,
            proof_time_millionths: proof_time,
            content_hash: ContentHash::compute(&h.finalize()),
        }
    }

    /// Coverage: verified/tested (millionths).
    pub fn coverage_millionths(&self) -> u64 {
        (self.input_classes_verified as u64)
            .saturating_mul(MILLION)
            .checked_div(self.input_classes_tested as u64)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Counterexample
// ---------------------------------------------------------------------------

/// A counterexample showing divergence between original and candidate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Counterexample {
    /// Input class that triggered the divergence.
    pub input_class: String,
    /// Expected output from original.
    pub expected_output_hash: ContentHash,
    /// Actual output from candidate.
    pub actual_output_hash: ContentHash,
    /// Brief description of the divergence.
    pub description: String,
}

// ---------------------------------------------------------------------------
// CostEstimate
// ---------------------------------------------------------------------------

/// Hardware-aware cost estimate for a kernel variant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CostEstimate {
    /// Hardware config identifier.
    pub hardware_id: String,
    /// Estimated cycles (millionths).
    pub cycles_millionths: u64,
    /// Estimated memory pressure (millionths of capacity).
    pub memory_pressure_millionths: u64,
    /// Estimated throughput (ops/sec, millionths).
    pub throughput_millionths: u64,
}

impl CostEstimate {
    /// Create a new cost estimate.
    pub fn new(
        hardware_id: impl Into<String>,
        cycles: u64,
        memory_pressure: u64,
        throughput: u64,
    ) -> Self {
        Self {
            hardware_id: hardware_id.into(),
            cycles_millionths: cycles,
            memory_pressure_millionths: memory_pressure,
            throughput_millionths: throughput,
        }
    }
}

// ---------------------------------------------------------------------------
// SynthesisCandidate
// ---------------------------------------------------------------------------

/// A proposed alternative implementation for a hot kernel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisCandidate {
    /// Unique candidate identifier.
    pub candidate_id: String,
    /// ID of the original kernel schema this replaces.
    pub original_schema_id: String,
    /// How this candidate was generated.
    pub origin: CandidateOrigin,
    /// Operation count of the candidate.
    pub op_count: u32,
    /// Equivalence proof.
    pub proof: EquivalenceProof,
    /// Counterexamples found during verification.
    pub counterexamples: Vec<Counterexample>,
    /// Hardware-specific cost estimates.
    pub cost_estimates: Vec<CostEstimate>,
    /// Estimated speedup over original (millionths). 1_050_000 = 1.05x.
    pub speedup_millionths: u64,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl SynthesisCandidate {
    /// Create a new candidate with computed hash.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        candidate_id: impl Into<String>,
        original_schema_id: impl Into<String>,
        origin: CandidateOrigin,
        op_count: u32,
        proof: EquivalenceProof,
        counterexamples: Vec<Counterexample>,
        cost_estimates: Vec<CostEstimate>,
        speedup_millionths: u64,
    ) -> Self {
        let candidate_id = candidate_id.into();
        let original_schema_id = original_schema_id.into();
        let mut h = Sha256::new();
        h.update(candidate_id.as_bytes());
        h.update(original_schema_id.as_bytes());
        h.update(origin.as_str().as_bytes());
        h.update(op_count.to_le_bytes());
        h.update(proof.status.as_str().as_bytes());
        h.update(speedup_millionths.to_le_bytes());
        let content_hash = ContentHash::compute(&h.finalize());

        Self {
            candidate_id,
            original_schema_id,
            origin,
            op_count,
            proof,
            counterexamples,
            cost_estimates,
            speedup_millionths,
            content_hash,
        }
    }

    /// Whether this candidate passed verification.
    pub fn is_verified(&self) -> bool {
        self.proof.status.is_verified()
    }

    /// Whether the speedup meets the minimum threshold.
    pub fn meets_speedup_threshold(&self) -> bool {
        self.speedup_millionths >= MILLION + MIN_SPEEDUP_THRESHOLD
    }

    /// Whether this candidate is admissible (verified + fast enough).
    pub fn is_admissible(&self) -> bool {
        self.is_verified() && self.meets_speedup_threshold()
    }
}

// ---------------------------------------------------------------------------
// SynthesisBudget
// ---------------------------------------------------------------------------

/// Budget constraints for a synthesis session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisBudget {
    /// Maximum candidates to evaluate per kernel.
    pub max_candidates: u32,
    /// Maximum search time (millionths of seconds).
    pub search_time_millionths: u64,
    /// Maximum proof time per candidate (millionths of seconds).
    pub proof_time_per_candidate_millionths: u64,
}

impl SynthesisBudget {
    /// Create a default budget.
    pub fn default_budget() -> Self {
        Self {
            max_candidates: DEFAULT_MAX_CANDIDATES,
            search_time_millionths: DEFAULT_SEARCH_BUDGET,
            proof_time_per_candidate_millionths: 1_000_000, // 1 second per candidate
        }
    }

    /// Create a custom budget.
    pub fn custom(max_candidates: u32, search_time: u64, proof_time: u64) -> Self {
        Self {
            max_candidates,
            search_time_millionths: search_time,
            proof_time_per_candidate_millionths: proof_time,
        }
    }
}

impl Default for SynthesisBudget {
    fn default() -> Self {
        Self::default_budget()
    }
}

// ---------------------------------------------------------------------------
// SynthesisReport
// ---------------------------------------------------------------------------

/// Report from a synthesis session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisReport {
    /// Schema version.
    pub schema_version: String,
    /// Epoch.
    pub epoch: SecurityEpoch,
    /// Target kernel schema ID.
    pub target_schema_id: String,
    /// Budget used.
    pub budget: SynthesisBudget,
    /// All evaluated candidates.
    pub candidates: Vec<SynthesisCandidate>,
    /// Best admissible candidate ID (if any).
    pub best_candidate_id: Option<String>,
    /// Admissible count.
    pub admissible_count: usize,
    /// Refuted count.
    pub refuted_count: usize,
    /// Timed-out count.
    pub timed_out_count: usize,
    /// Total search time consumed (millionths of seconds).
    pub total_search_time_millionths: u64,
    /// Total counterexamples found.
    pub total_counterexamples: usize,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl SynthesisReport {
    /// Create a synthesis report from candidates.
    pub fn new(
        epoch: SecurityEpoch,
        target_schema_id: impl Into<String>,
        budget: SynthesisBudget,
        candidates: Vec<SynthesisCandidate>,
    ) -> Self {
        let target_schema_id = target_schema_id.into();

        let admissible_count = candidates.iter().filter(|c| c.is_admissible()).count();
        let refuted_count = candidates
            .iter()
            .filter(|c| c.proof.status == ProofStatus::Refuted)
            .count();
        let timed_out_count = candidates
            .iter()
            .filter(|c| c.proof.status == ProofStatus::TimedOut)
            .count();
        let total_search_time_millionths: u64 = candidates
            .iter()
            .map(|c| c.proof.proof_time_millionths)
            .sum();
        let total_counterexamples: usize = candidates.iter().map(|c| c.counterexamples.len()).sum();

        // Best admissible: highest speedup among verified candidates
        let best_candidate_id = candidates
            .iter()
            .filter(|c| c.is_admissible())
            .max_by_key(|c| c.speedup_millionths)
            .map(|c| c.candidate_id.clone());

        let mut h = Sha256::new();
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        h.update(target_schema_id.as_bytes());
        h.update((candidates.len() as u64).to_le_bytes());
        h.update((admissible_count as u64).to_le_bytes());
        if let Some(ref best) = best_candidate_id {
            h.update(best.as_bytes());
        }
        let content_hash = ContentHash::compute(&h.finalize());

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            epoch,
            target_schema_id,
            budget,
            candidates,
            best_candidate_id,
            admissible_count,
            refuted_count,
            timed_out_count,
            total_search_time_millionths,
            total_counterexamples,
            content_hash,
        }
    }

    /// Total candidates evaluated.
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    /// Whether synthesis found a usable candidate.
    pub fn has_result(&self) -> bool {
        self.best_candidate_id.is_some()
    }

    /// Admission rate: admissible / total (millionths).
    pub fn admission_rate(&self) -> u64 {
        (self.admissible_count as u64)
            .saturating_mul(MILLION)
            .checked_div(self.candidates.len() as u64)
            .unwrap_or(0)
    }

    /// Get the best candidate (if any).
    pub fn best_candidate(&self) -> Option<&SynthesisCandidate> {
        self.best_candidate_id
            .as_ref()
            .and_then(|id| self.candidates.iter().find(|c| c.candidate_id == *id))
    }
}

// ---------------------------------------------------------------------------
// CounterexampleArchive
// ---------------------------------------------------------------------------

/// Archive of counterexamples across synthesis sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterexampleArchive {
    /// Schema ID → counterexamples found.
    pub entries: BTreeMap<String, Vec<Counterexample>>,
    /// Total counterexamples archived.
    pub total_count: usize,
}

impl CounterexampleArchive {
    /// Create an empty archive.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            total_count: 0,
        }
    }

    /// Add counterexamples from a synthesis report.
    pub fn ingest(&mut self, report: &SynthesisReport) {
        let entry = self
            .entries
            .entry(report.target_schema_id.clone())
            .or_default();
        for c in &report.candidates {
            for cx in &c.counterexamples {
                if entry.len() < MAX_COUNTEREXAMPLES {
                    entry.push(cx.clone());
                    self.total_count += 1;
                }
            }
        }
    }

    /// Number of schemas with counterexamples.
    pub fn schema_count(&self) -> usize {
        self.entries.len()
    }

    /// Get counterexamples for a schema.
    pub fn for_schema(&self, schema_id: &str) -> &[Counterexample] {
        self.entries
            .get(schema_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

impl Default for CounterexampleArchive {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(700)
    }

    fn verified_candidate(id: &str, speedup: u64) -> SynthesisCandidate {
        SynthesisCandidate::new(
            id,
            "kernel-1",
            CandidateOrigin::Enumerative,
            10,
            EquivalenceProof::verified(5, 500_000),
            Vec::new(),
            vec![CostEstimate::new("hw1", 100_000, 50_000, 800_000)],
            speedup,
        )
    }

    fn refuted_candidate(id: &str) -> SynthesisCandidate {
        let cx = Counterexample {
            input_class: "array-int32".into(),
            expected_output_hash: ContentHash::compute(b"expected"),
            actual_output_hash: ContentHash::compute(b"actual"),
            description: "off-by-one".into(),
        };
        SynthesisCandidate::new(
            id,
            "kernel-1",
            CandidateOrigin::Stochastic,
            12,
            EquivalenceProof::refuted(5, 3, 300_000),
            vec![cx],
            Vec::new(),
            1_100_000,
        )
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "budgeted_synthesis_engine");
    }

    #[test]
    fn bead_id_format() {
        assert!(BEAD_ID.starts_with("bd-"));
    }

    #[test]
    fn thresholds_valid() {
        let max_cand = DEFAULT_MAX_CANDIDATES;
        let search_b = DEFAULT_SEARCH_BUDGET;
        let max_cx = MAX_COUNTEREXAMPLES;
        let min_sp = MIN_SPEEDUP_THRESHOLD;
        assert!(max_cand > 0);
        assert!(search_b > 0);
        assert!(max_cx > 0);
        assert!(min_sp > 0);
        assert!(min_sp < MILLION);
    }

    // --- ProofStatus ---

    #[test]
    fn proof_status_all_length() {
        assert_eq!(ProofStatus::ALL.len(), 4);
    }

    #[test]
    fn proof_status_names_unique() {
        let names: BTreeSet<&str> = ProofStatus::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(names.len(), ProofStatus::ALL.len());
    }

    #[test]
    fn proof_status_semantics() {
        assert!(ProofStatus::Verified.is_verified());
        assert!(ProofStatus::Verified.is_terminal());
        assert!(!ProofStatus::Refuted.is_verified());
        assert!(ProofStatus::Refuted.is_terminal());
        assert!(!ProofStatus::TimedOut.is_terminal());
        assert!(!ProofStatus::Skipped.is_terminal());
    }

    #[test]
    fn proof_status_display() {
        for s in ProofStatus::ALL {
            assert_eq!(s.to_string(), s.as_str());
        }
    }

    #[test]
    fn proof_status_serde() {
        for s in ProofStatus::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: ProofStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    // --- CandidateOrigin ---

    #[test]
    fn origin_all_length() {
        assert_eq!(CandidateOrigin::ALL.len(), 5);
    }

    #[test]
    fn origin_names_unique() {
        let names: BTreeSet<&str> = CandidateOrigin::ALL.iter().map(|o| o.as_str()).collect();
        assert_eq!(names.len(), CandidateOrigin::ALL.len());
    }

    #[test]
    fn origin_display() {
        for o in CandidateOrigin::ALL {
            assert_eq!(o.to_string(), o.as_str());
        }
    }

    #[test]
    fn origin_serde() {
        for o in CandidateOrigin::ALL {
            let json = serde_json::to_string(o).unwrap();
            let back: CandidateOrigin = serde_json::from_str(&json).unwrap();
            assert_eq!(*o, back);
        }
    }

    // --- EquivalenceProof ---

    #[test]
    fn proof_verified() {
        let p = EquivalenceProof::verified(10, 500_000);
        assert_eq!(p.status, ProofStatus::Verified);
        assert_eq!(p.input_classes_tested, 10);
        assert_eq!(p.input_classes_verified, 10);
        assert_eq!(p.coverage_millionths(), MILLION);
    }

    #[test]
    fn proof_refuted_coverage() {
        let p = EquivalenceProof::refuted(10, 7, 300_000);
        assert_eq!(p.status, ProofStatus::Refuted);
        assert_eq!(p.coverage_millionths(), 700_000);
    }

    #[test]
    fn proof_timed_out() {
        let p = EquivalenceProof::timed_out(5, 3, 1_000_000);
        assert_eq!(p.status, ProofStatus::TimedOut);
    }

    #[test]
    fn proof_serde() {
        let p = EquivalenceProof::verified(8, 400_000);
        let json = serde_json::to_string(&p).unwrap();
        let back: EquivalenceProof = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    // --- SynthesisCandidate ---

    #[test]
    fn candidate_verified_admissible() {
        let c = verified_candidate("c1", 1_100_000); // 1.1x speedup
        assert!(c.is_verified());
        assert!(c.meets_speedup_threshold());
        assert!(c.is_admissible());
    }

    #[test]
    fn candidate_verified_too_slow() {
        let c = verified_candidate("c1", 1_020_000); // 1.02x < 1.05x threshold
        assert!(c.is_verified());
        assert!(!c.meets_speedup_threshold());
        assert!(!c.is_admissible());
    }

    #[test]
    fn candidate_refuted_not_admissible() {
        let c = refuted_candidate("c1");
        assert!(!c.is_verified());
        assert!(!c.is_admissible());
    }

    #[test]
    fn candidate_hash_deterministic() {
        let c1 = verified_candidate("c1", 1_100_000);
        let c2 = verified_candidate("c1", 1_100_000);
        assert_eq!(c1.content_hash, c2.content_hash);
    }

    #[test]
    fn candidate_serde() {
        let c = verified_candidate("c1", 1_200_000);
        let json = serde_json::to_string(&c).unwrap();
        let back: SynthesisCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- SynthesisBudget ---

    #[test]
    fn budget_default() {
        let b = SynthesisBudget::default_budget();
        assert_eq!(b.max_candidates, DEFAULT_MAX_CANDIDATES);
        assert_eq!(b.search_time_millionths, DEFAULT_SEARCH_BUDGET);
    }

    #[test]
    fn budget_custom() {
        let b = SynthesisBudget::custom(10, 2_000_000, 500_000);
        assert_eq!(b.max_candidates, 10);
    }

    #[test]
    fn budget_serde() {
        let b = SynthesisBudget::default();
        let json = serde_json::to_string(&b).unwrap();
        let back: SynthesisBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
    }

    // --- SynthesisReport ---

    #[test]
    fn report_empty() {
        let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), Vec::new());
        assert_eq!(r.candidate_count(), 0);
        assert!(!r.has_result());
        assert_eq!(r.admission_rate(), 0);
        assert_eq!(r.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn report_with_admissible() {
        let candidates = vec![
            verified_candidate("c1", 1_100_000),
            verified_candidate("c2", 1_200_000),
            refuted_candidate("c3"),
        ];
        let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
        assert!(r.has_result());
        assert_eq!(r.admissible_count, 2);
        assert_eq!(r.refuted_count, 1);
        assert_eq!(r.best_candidate_id.as_deref(), Some("c2")); // highest speedup
    }

    #[test]
    fn report_all_refuted() {
        let candidates = vec![refuted_candidate("c1"), refuted_candidate("c2")];
        let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
        assert!(!r.has_result());
        assert_eq!(r.refuted_count, 2);
    }

    #[test]
    fn report_best_candidate() {
        let candidates = vec![
            verified_candidate("c1", 1_100_000),
            verified_candidate("c2", 1_300_000),
        ];
        let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
        let best = r.best_candidate().unwrap();
        assert_eq!(best.candidate_id, "c2");
        assert_eq!(best.speedup_millionths, 1_300_000);
    }

    #[test]
    fn report_hash_deterministic() {
        let candidates = vec![verified_candidate("c1", 1_100_000)];
        let r1 = SynthesisReport::new(
            epoch(),
            "k1",
            SynthesisBudget::default(),
            candidates.clone(),
        );
        let r2 = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn report_serde() {
        let candidates = vec![verified_candidate("c1", 1_100_000), refuted_candidate("c2")];
        let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
        let json = serde_json::to_string(&r).unwrap();
        let back: SynthesisReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- CounterexampleArchive ---

    #[test]
    fn archive_empty() {
        let a = CounterexampleArchive::new();
        assert_eq!(a.schema_count(), 0);
        assert_eq!(a.total_count, 0);
    }

    #[test]
    fn archive_ingest() {
        let candidates = vec![refuted_candidate("c1")];
        let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
        let mut a = CounterexampleArchive::new();
        a.ingest(&r);
        assert_eq!(a.schema_count(), 1);
        assert_eq!(a.total_count, 1);
        assert_eq!(a.for_schema("k1").len(), 1);
    }

    #[test]
    fn archive_empty_schema_lookup() {
        let a = CounterexampleArchive::new();
        assert!(a.for_schema("nonexistent").is_empty());
    }

    #[test]
    fn archive_default() {
        let a = CounterexampleArchive::default();
        assert_eq!(a.schema_count(), 0);
    }

    #[test]
    fn archive_serde() {
        let mut a = CounterexampleArchive::new();
        let candidates = vec![refuted_candidate("c1")];
        let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
        a.ingest(&r);
        let json = serde_json::to_string(&a).unwrap();
        let back: CounterexampleArchive = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    // -----------------------------------------------------------------------
    // Additional tests — edge cases, boundaries, determinism, coverage
    // -----------------------------------------------------------------------

    // --- ProofStatus ordering ---

    #[test]
    fn proof_status_ord_verified_is_least() {
        // Verified < Refuted < TimedOut < Skipped by derive(Ord) on variant order
        assert!(ProofStatus::Verified < ProofStatus::Refuted);
        assert!(ProofStatus::Refuted < ProofStatus::TimedOut);
        assert!(ProofStatus::TimedOut < ProofStatus::Skipped);
    }

    #[test]
    fn proof_status_skipped_not_verified_not_terminal() {
        assert!(!ProofStatus::Skipped.is_verified());
        assert!(!ProofStatus::Skipped.is_terminal());
    }

    #[test]
    fn proof_status_timed_out_not_verified() {
        assert!(!ProofStatus::TimedOut.is_verified());
    }

    // --- CandidateOrigin ordering ---

    #[test]
    fn origin_ord_follows_definition_order() {
        assert!(CandidateOrigin::Enumerative < CandidateOrigin::Stochastic);
        assert!(CandidateOrigin::Stochastic < CandidateOrigin::TemplateBased);
        assert!(CandidateOrigin::TemplateBased < CandidateOrigin::AlgebraicSimplification);
        assert!(CandidateOrigin::AlgebraicSimplification < CandidateOrigin::Manual);
    }

    #[test]
    fn origin_serde_snake_case_format() {
        let json = serde_json::to_string(&CandidateOrigin::AlgebraicSimplification).unwrap();
        assert_eq!(json, "\"algebraic_simplification\"");
        let json2 = serde_json::to_string(&CandidateOrigin::TemplateBased).unwrap();
        assert_eq!(json2, "\"template_based\"");
    }

    // --- EquivalenceProof edge cases ---

    #[test]
    fn proof_coverage_zero_classes_returns_zero() {
        // When input_classes_tested is 0, checked_div returns None → 0
        let p = EquivalenceProof::verified(0, 100_000);
        assert_eq!(p.coverage_millionths(), 0);
    }

    #[test]
    fn proof_coverage_partial() {
        let p = EquivalenceProof::refuted(4, 1, 200_000);
        // 1/4 * 1_000_000 = 250_000
        assert_eq!(p.coverage_millionths(), 250_000);
    }

    #[test]
    fn proof_coverage_one_of_one() {
        let p = EquivalenceProof::verified(1, 50_000);
        assert_eq!(p.coverage_millionths(), MILLION);
    }

    #[test]
    fn proof_verified_hash_deterministic() {
        let p1 = EquivalenceProof::verified(10, 500_000);
        let p2 = EquivalenceProof::verified(10, 500_000);
        assert_eq!(p1.content_hash, p2.content_hash);
    }

    #[test]
    fn proof_verified_hash_differs_on_different_input() {
        let p1 = EquivalenceProof::verified(10, 500_000);
        let p2 = EquivalenceProof::verified(11, 500_000);
        assert_ne!(p1.content_hash, p2.content_hash);
    }

    #[test]
    fn proof_refuted_hash_differs_from_verified() {
        let p1 = EquivalenceProof::verified(10, 500_000);
        let p2 = EquivalenceProof::refuted(10, 10, 500_000);
        assert_ne!(p1.content_hash, p2.content_hash);
    }

    #[test]
    fn proof_timed_out_hash_deterministic() {
        let p1 = EquivalenceProof::timed_out(5, 3, 1_000_000);
        let p2 = EquivalenceProof::timed_out(5, 3, 1_000_000);
        assert_eq!(p1.content_hash, p2.content_hash);
    }

    #[test]
    fn proof_timed_out_coverage() {
        let p = EquivalenceProof::timed_out(10, 6, 1_000_000);
        assert_eq!(p.coverage_millionths(), 600_000);
    }

    #[test]
    fn proof_refuted_serde_roundtrip() {
        let p = EquivalenceProof::refuted(20, 15, 750_000);
        let json = serde_json::to_string(&p).unwrap();
        let back: EquivalenceProof = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
        assert_eq!(back.status, ProofStatus::Refuted);
        assert_eq!(back.input_classes_tested, 20);
        assert_eq!(back.input_classes_verified, 15);
    }

    #[test]
    fn proof_timed_out_serde_roundtrip() {
        let p = EquivalenceProof::timed_out(8, 4, 999_999);
        let json = serde_json::to_string(&p).unwrap();
        let back: EquivalenceProof = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    // --- CostEstimate ---

    #[test]
    fn cost_estimate_new_stores_fields() {
        let c = CostEstimate::new("gpu-a100", 2_000_000, 300_000, 5_000_000);
        assert_eq!(c.hardware_id, "gpu-a100");
        assert_eq!(c.cycles_millionths, 2_000_000);
        assert_eq!(c.memory_pressure_millionths, 300_000);
        assert_eq!(c.throughput_millionths, 5_000_000);
    }

    #[test]
    fn cost_estimate_serde_roundtrip() {
        let c = CostEstimate::new("arm-neon", 150_000, 25_000, 900_000);
        let json = serde_json::to_string(&c).unwrap();
        let back: CostEstimate = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn cost_estimate_ord_by_hardware_then_cycles() {
        let c1 = CostEstimate::new("aarch64", 100_000, 50_000, 800_000);
        let c2 = CostEstimate::new("x86_64", 100_000, 50_000, 800_000);
        // Ord derived: hardware_id is String, "aarch64" < "x86_64"
        assert!(c1 < c2);
    }

    // --- SynthesisCandidate edge cases ---

    #[test]
    fn candidate_at_exact_speedup_threshold() {
        // Exactly at the threshold: MILLION + MIN_SPEEDUP_THRESHOLD = 1_050_000
        let c = verified_candidate("c-edge", 1_050_000);
        assert!(c.is_verified());
        assert!(c.meets_speedup_threshold());
        assert!(c.is_admissible());
    }

    #[test]
    fn candidate_one_below_speedup_threshold() {
        // One below the threshold
        let c = verified_candidate("c-below", 1_049_999);
        assert!(c.is_verified());
        assert!(!c.meets_speedup_threshold());
        assert!(!c.is_admissible());
    }

    #[test]
    fn candidate_zero_speedup_not_admissible() {
        let c = verified_candidate("c-zero", 0);
        assert!(c.is_verified());
        assert!(!c.meets_speedup_threshold());
        assert!(!c.is_admissible());
    }

    #[test]
    fn candidate_hash_differs_on_id() {
        let c1 = verified_candidate("alpha", 1_200_000);
        let c2 = verified_candidate("beta", 1_200_000);
        assert_ne!(c1.content_hash, c2.content_hash);
    }

    #[test]
    fn candidate_hash_differs_on_speedup() {
        let c1 = verified_candidate("c1", 1_100_000);
        let c2 = verified_candidate("c1", 1_200_000);
        assert_ne!(c1.content_hash, c2.content_hash);
    }

    #[test]
    fn candidate_with_multiple_cost_estimates() {
        let costs = vec![
            CostEstimate::new("hw-a", 100_000, 50_000, 800_000),
            CostEstimate::new("hw-b", 200_000, 60_000, 600_000),
            CostEstimate::new("hw-c", 80_000, 40_000, 1_200_000),
        ];
        let c = SynthesisCandidate::new(
            "multi-hw",
            "kernel-2",
            CandidateOrigin::TemplateBased,
            15,
            EquivalenceProof::verified(20, 800_000),
            Vec::new(),
            costs,
            1_150_000,
        );
        assert_eq!(c.cost_estimates.len(), 3);
        assert!(c.is_admissible());
    }

    #[test]
    fn candidate_with_multiple_counterexamples() {
        let cxs: Vec<Counterexample> = (0..5)
            .map(|i| Counterexample {
                input_class: format!("class-{i}"),
                expected_output_hash: ContentHash::compute(format!("exp-{i}").as_bytes()),
                actual_output_hash: ContentHash::compute(format!("act-{i}").as_bytes()),
                description: format!("divergence-{i}"),
            })
            .collect();
        let c = SynthesisCandidate::new(
            "cx-heavy",
            "kernel-3",
            CandidateOrigin::Stochastic,
            20,
            EquivalenceProof::refuted(10, 5, 400_000),
            cxs,
            Vec::new(),
            1_300_000,
        );
        assert_eq!(c.counterexamples.len(), 5);
        assert!(!c.is_admissible()); // refuted
    }

    #[test]
    fn candidate_manual_origin() {
        let c = SynthesisCandidate::new(
            "manual-1",
            "kernel-1",
            CandidateOrigin::Manual,
            5,
            EquivalenceProof::verified(3, 100_000),
            Vec::new(),
            Vec::new(),
            1_500_000,
        );
        assert_eq!(c.origin, CandidateOrigin::Manual);
        assert!(c.is_admissible());
    }

    #[test]
    fn candidate_algebraic_origin() {
        let c = SynthesisCandidate::new(
            "alg-1",
            "kernel-1",
            CandidateOrigin::AlgebraicSimplification,
            3,
            EquivalenceProof::verified(8, 200_000),
            Vec::new(),
            Vec::new(),
            2_000_000, // 2x speedup
        );
        assert_eq!(c.origin, CandidateOrigin::AlgebraicSimplification);
        assert!(c.is_admissible());
    }

    // --- SynthesisBudget edge cases ---

    #[test]
    fn budget_default_trait_matches_method() {
        let b1 = SynthesisBudget::default();
        let b2 = SynthesisBudget::default_budget();
        assert_eq!(b1, b2);
    }

    #[test]
    fn budget_custom_zero_candidates() {
        let b = SynthesisBudget::custom(0, 0, 0);
        assert_eq!(b.max_candidates, 0);
        assert_eq!(b.search_time_millionths, 0);
        assert_eq!(b.proof_time_per_candidate_millionths, 0);
    }

    #[test]
    fn budget_custom_large_values() {
        let b = SynthesisBudget::custom(u32::MAX, u64::MAX, u64::MAX);
        assert_eq!(b.max_candidates, u32::MAX);
        assert_eq!(b.search_time_millionths, u64::MAX);
        assert_eq!(b.proof_time_per_candidate_millionths, u64::MAX);
    }

    // --- SynthesisReport edge cases ---

    #[test]
    fn report_admission_rate_all_admissible() {
        let candidates = vec![
            verified_candidate("c1", 1_100_000),
            verified_candidate("c2", 1_200_000),
        ];
        let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
        assert_eq!(r.admission_rate(), MILLION); // 100%
    }

    #[test]
    fn report_admission_rate_half() {
        let candidates = vec![verified_candidate("c1", 1_100_000), refuted_candidate("c2")];
        let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
        assert_eq!(r.admission_rate(), 500_000); // 50%
    }

    #[test]
    fn report_total_search_time_sums_correctly() {
        // Each verified_candidate has proof_time = 500_000, refuted has 300_000
        let candidates = vec![
            verified_candidate("c1", 1_100_000),
            verified_candidate("c2", 1_200_000),
            refuted_candidate("c3"),
        ];
        let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
        assert_eq!(r.total_search_time_millionths, 500_000 + 500_000 + 300_000);
    }

    #[test]
    fn report_total_counterexamples_counts_all() {
        let candidates = vec![refuted_candidate("c1"), refuted_candidate("c2")];
        let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
        // Each refuted candidate has 1 counterexample
        assert_eq!(r.total_counterexamples, 2);
    }

    #[test]
    fn report_timed_out_count() {
        let timed_out_c = SynthesisCandidate::new(
            "to-1",
            "kernel-1",
            CandidateOrigin::Enumerative,
            10,
            EquivalenceProof::timed_out(5, 2, 1_000_000),
            Vec::new(),
            Vec::new(),
            1_100_000,
        );
        let candidates = vec![
            verified_candidate("c1", 1_100_000),
            timed_out_c,
            refuted_candidate("c3"),
        ];
        let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
        assert_eq!(r.timed_out_count, 1);
        assert_eq!(r.refuted_count, 1);
        assert_eq!(r.admissible_count, 1);
    }

    #[test]
    fn report_best_candidate_is_none_when_no_admissible() {
        let timed_out_c = SynthesisCandidate::new(
            "to-1",
            "kernel-1",
            CandidateOrigin::Enumerative,
            10,
            EquivalenceProof::timed_out(5, 2, 1_000_000),
            Vec::new(),
            Vec::new(),
            1_500_000,
        );
        let r = SynthesisReport::new(
            epoch(),
            "k1",
            SynthesisBudget::default(),
            vec![timed_out_c, refuted_candidate("c2")],
        );
        assert!(r.best_candidate().is_none());
        assert!(!r.has_result());
    }

    #[test]
    fn report_hash_differs_on_epoch() {
        let candidates = vec![verified_candidate("c1", 1_100_000)];
        let r1 = SynthesisReport::new(
            SecurityEpoch::from_raw(1),
            "k1",
            SynthesisBudget::default(),
            candidates.clone(),
        );
        let r2 = SynthesisReport::new(
            SecurityEpoch::from_raw(2),
            "k1",
            SynthesisBudget::default(),
            candidates,
        );
        assert_ne!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn report_hash_differs_on_target_schema() {
        let candidates = vec![verified_candidate("c1", 1_100_000)];
        let r1 = SynthesisReport::new(
            epoch(),
            "kernel-a",
            SynthesisBudget::default(),
            candidates.clone(),
        );
        let r2 = SynthesisReport::new(epoch(), "kernel-b", SynthesisBudget::default(), candidates);
        assert_ne!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn report_verified_below_threshold_not_admissible() {
        // Candidate is verified but speedup below threshold — should NOT appear as best
        let candidates = vec![verified_candidate("c1", 1_020_000)];
        let r = SynthesisReport::new(epoch(), "k1", SynthesisBudget::default(), candidates);
        assert_eq!(r.admissible_count, 0);
        assert!(!r.has_result());
        assert!(r.best_candidate().is_none());
    }

    // --- CounterexampleArchive edge cases ---

    #[test]
    fn archive_ingest_multiple_schemas() {
        let mut archive = CounterexampleArchive::new();
        let r1 = SynthesisReport::new(
            epoch(),
            "kernel-a",
            SynthesisBudget::default(),
            vec![refuted_candidate("c1")],
        );
        let r2 = SynthesisReport::new(
            epoch(),
            "kernel-b",
            SynthesisBudget::default(),
            vec![refuted_candidate("c2")],
        );
        archive.ingest(&r1);
        archive.ingest(&r2);
        assert_eq!(archive.schema_count(), 2);
        assert_eq!(archive.total_count, 2);
        assert_eq!(archive.for_schema("kernel-a").len(), 1);
        assert_eq!(archive.for_schema("kernel-b").len(), 1);
    }

    #[test]
    fn archive_ingest_same_schema_accumulates() {
        let mut archive = CounterexampleArchive::new();
        let r1 = SynthesisReport::new(
            epoch(),
            "kernel-a",
            SynthesisBudget::default(),
            vec![refuted_candidate("c1")],
        );
        let r2 = SynthesisReport::new(
            epoch(),
            "kernel-a",
            SynthesisBudget::default(),
            vec![refuted_candidate("c2")],
        );
        archive.ingest(&r1);
        archive.ingest(&r2);
        assert_eq!(archive.schema_count(), 1);
        assert_eq!(archive.total_count, 2);
        assert_eq!(archive.for_schema("kernel-a").len(), 2);
    }

    #[test]
    fn archive_respects_max_counterexamples_cap() {
        let mut archive = CounterexampleArchive::new();
        // Create a report whose candidate has many counterexamples
        let cxs: Vec<Counterexample> = (0..MAX_COUNTEREXAMPLES + 10)
            .map(|i| Counterexample {
                input_class: format!("class-{i}"),
                expected_output_hash: ContentHash::compute(format!("exp-{i}").as_bytes()),
                actual_output_hash: ContentHash::compute(format!("act-{i}").as_bytes()),
                description: format!("div-{i}"),
            })
            .collect();
        let c = SynthesisCandidate::new(
            "cx-flood",
            "kernel-flood",
            CandidateOrigin::Stochastic,
            20,
            EquivalenceProof::refuted(50, 10, 500_000),
            cxs,
            Vec::new(),
            1_200_000,
        );
        let r = SynthesisReport::new(epoch(), "kernel-flood", SynthesisBudget::default(), vec![c]);
        archive.ingest(&r);
        // Should cap at MAX_COUNTEREXAMPLES
        assert_eq!(
            archive.for_schema("kernel-flood").len(),
            MAX_COUNTEREXAMPLES
        );
        assert_eq!(archive.total_count, MAX_COUNTEREXAMPLES);
    }

    #[test]
    fn archive_ingest_report_with_no_counterexamples() {
        let mut archive = CounterexampleArchive::new();
        let r = SynthesisReport::new(
            epoch(),
            "kernel-clean",
            SynthesisBudget::default(),
            vec![verified_candidate("c1", 1_200_000)],
        );
        archive.ingest(&r);
        // Verified candidates have no counterexamples, so nothing is added
        assert_eq!(archive.schema_count(), 0);
        assert_eq!(archive.total_count, 0);
    }

    // --- Counterexample ---

    #[test]
    fn counterexample_ord_by_input_class() {
        let cx1 = Counterexample {
            input_class: "alpha".into(),
            expected_output_hash: ContentHash::compute(b"e1"),
            actual_output_hash: ContentHash::compute(b"a1"),
            description: "d1".into(),
        };
        let cx2 = Counterexample {
            input_class: "beta".into(),
            expected_output_hash: ContentHash::compute(b"e2"),
            actual_output_hash: ContentHash::compute(b"a2"),
            description: "d2".into(),
        };
        assert!(cx1 < cx2);
    }

    #[test]
    fn counterexample_serde_roundtrip() {
        let cx = Counterexample {
            input_class: "float-array".into(),
            expected_output_hash: ContentHash::compute(b"expected-data"),
            actual_output_hash: ContentHash::compute(b"actual-data"),
            description: "precision loss in accumulator".into(),
        };
        let json = serde_json::to_string(&cx).unwrap();
        let back: Counterexample = serde_json::from_str(&json).unwrap();
        assert_eq!(cx, back);
    }

    #[test]
    fn counterexample_clone_eq() {
        let cx = Counterexample {
            input_class: "test".into(),
            expected_output_hash: ContentHash::compute(b"e"),
            actual_output_hash: ContentHash::compute(b"a"),
            description: "desc".into(),
        };
        let cx2 = cx.clone();
        assert_eq!(cx, cx2);
    }

    // --- Policy constant ---

    #[test]
    fn policy_id_format() {
        assert!(POLICY_ID.starts_with("RGC-"));
    }

    // --- Full pipeline scenario ---

    #[test]
    fn full_synthesis_pipeline_mixed_candidates() {
        // Simulate a realistic session with all candidate types
        let skipped_proof = EquivalenceProof {
            status: ProofStatus::Skipped,
            input_classes_tested: 0,
            input_classes_verified: 0,
            proof_time_millionths: 0,
            content_hash: ContentHash::compute(b"skipped"),
        };
        let skipped_c = SynthesisCandidate::new(
            "c-skipped",
            "kernel-mix",
            CandidateOrigin::Enumerative,
            8,
            skipped_proof,
            Vec::new(),
            Vec::new(),
            1_300_000,
        );
        let timed_out_c = SynthesisCandidate::new(
            "c-timeout",
            "kernel-mix",
            CandidateOrigin::Stochastic,
            14,
            EquivalenceProof::timed_out(10, 7, 1_000_000),
            Vec::new(),
            Vec::new(),
            1_150_000,
        );
        let candidates = vec![
            verified_candidate("c-fast", 1_400_000),
            verified_candidate("c-slow", 1_020_000), // below threshold
            refuted_candidate("c-bad"),
            timed_out_c,
            skipped_c,
        ];
        let budget = SynthesisBudget::custom(100, 10_000_000, 2_000_000);
        let r = SynthesisReport::new(epoch(), "kernel-mix", budget, candidates);

        assert_eq!(r.candidate_count(), 5);
        assert_eq!(r.admissible_count, 1); // only c-fast
        assert_eq!(r.refuted_count, 1);
        assert_eq!(r.timed_out_count, 1);
        assert_eq!(r.best_candidate_id.as_deref(), Some("c-fast"));
        assert!(r.has_result());

        let best = r.best_candidate().unwrap();
        assert_eq!(best.speedup_millionths, 1_400_000);
        assert!(best.is_admissible());
    }

    #[test]
    fn report_serde_roundtrip_with_all_statuses() {
        let skipped_proof = EquivalenceProof {
            status: ProofStatus::Skipped,
            input_classes_tested: 0,
            input_classes_verified: 0,
            proof_time_millionths: 0,
            content_hash: ContentHash::compute(b"skip"),
        };
        let candidates = vec![
            verified_candidate("c1", 1_200_000),
            refuted_candidate("c2"),
            SynthesisCandidate::new(
                "c3",
                "kernel-1",
                CandidateOrigin::TemplateBased,
                7,
                EquivalenceProof::timed_out(5, 2, 900_000),
                Vec::new(),
                Vec::new(),
                1_100_000,
            ),
            SynthesisCandidate::new(
                "c4",
                "kernel-1",
                CandidateOrigin::Manual,
                3,
                skipped_proof,
                Vec::new(),
                Vec::new(),
                1_050_000,
            ),
        ];
        let r = SynthesisReport::new(epoch(), "k-all", SynthesisBudget::default(), candidates);
        let json = serde_json::to_string_pretty(&r).unwrap();
        let back: SynthesisReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
        assert_eq!(back.candidate_count(), 4);
    }

    #[test]
    fn archive_cap_across_multiple_ingests() {
        let mut archive = CounterexampleArchive::new();
        // Ingest many small reports for the same schema until cap
        for i in 0..MAX_COUNTEREXAMPLES + 5 {
            let cx = Counterexample {
                input_class: format!("class-{i}"),
                expected_output_hash: ContentHash::compute(format!("e-{i}").as_bytes()),
                actual_output_hash: ContentHash::compute(format!("a-{i}").as_bytes()),
                description: format!("d-{i}"),
            };
            let c = SynthesisCandidate::new(
                format!("c-{i}"),
                "kernel-cap",
                CandidateOrigin::Stochastic,
                10,
                EquivalenceProof::refuted(5, 3, 200_000),
                vec![cx],
                Vec::new(),
                1_100_000,
            );
            let r =
                SynthesisReport::new(epoch(), "kernel-cap", SynthesisBudget::default(), vec![c]);
            archive.ingest(&r);
        }
        assert_eq!(archive.for_schema("kernel-cap").len(), MAX_COUNTEREXAMPLES);
        assert_eq!(archive.total_count, MAX_COUNTEREXAMPLES);
    }

    #[test]
    fn candidate_serde_with_counterexamples_and_costs() {
        let cx = Counterexample {
            input_class: "wide-vector".into(),
            expected_output_hash: ContentHash::compute(b"exp-wide"),
            actual_output_hash: ContentHash::compute(b"act-wide"),
            description: "SIMD lane mismatch".into(),
        };
        let costs = vec![
            CostEstimate::new("avx512", 50_000, 20_000, 2_000_000),
            CostEstimate::new("neon", 80_000, 30_000, 1_500_000),
        ];
        let c = SynthesisCandidate::new(
            "full-c",
            "kernel-full",
            CandidateOrigin::Stochastic,
            18,
            EquivalenceProof::refuted(12, 9, 600_000),
            vec![cx],
            costs,
            1_250_000,
        );
        let json = serde_json::to_string(&c).unwrap();
        let back: SynthesisCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
        assert_eq!(back.counterexamples.len(), 1);
        assert_eq!(back.cost_estimates.len(), 2);
    }
}
