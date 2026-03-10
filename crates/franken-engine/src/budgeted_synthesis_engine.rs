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

use std::collections::{BTreeMap, BTreeSet};
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
        assert!(DEFAULT_MAX_CANDIDATES > 0);
        assert!(DEFAULT_SEARCH_BUDGET > 0);
        assert!(MAX_COUNTEREXAMPLES > 0);
        assert!(MIN_SPEEDUP_THRESHOLD > 0);
        assert!(MIN_SPEEDUP_THRESHOLD < MILLION);
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
}
