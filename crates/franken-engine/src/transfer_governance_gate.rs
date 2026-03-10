#![forbid(unsafe_code)]

//! Transfer Governance Gate — RGC-612C
//!
//! Bead: bd-1lsy.7.12.3
//!
//! Wires workload-transfer evidence into benchmark-board coverage, rollout
//! gating, and published supremacy claims.  Transfer governance ensures that
//! priors from one workload neighborhood actually apply to other regions:
//! generalization quality is measured rather than assumed.
//!
//! All fractional arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for transfer governance artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.transfer-governance-gate.v1";
/// Component name used in evidence records and receipts.
pub const COMPONENT: &str = "transfer_governance_gate";
/// Bead identifier originating this module.
pub const BEAD_ID: &str = "bd-1lsy.7.12.3";
/// Policy reference.
pub const POLICY_ID: &str = "RGC-612C";

const MILLION: u64 = 1_000_000;
/// Default high-fidelity threshold (millionths). 900_000 = 90%.
pub const DEFAULT_HIGH_FIDELITY_THRESHOLD: u64 = 900_000;
/// Default moderate-fidelity threshold (millionths). 700_000 = 70%.
pub const DEFAULT_MODERATE_FIDELITY_THRESHOLD: u64 = 700_000;
/// Default drift alarm threshold (millionths). 200_000 = 20%.
pub const DEFAULT_DRIFT_ALARM_THRESHOLD: u64 = 200_000;
/// Default minimum sample count.
pub const DEFAULT_MIN_SAMPLE_COUNT: u64 = 30;
/// Default minimum coverage fraction (millionths). 800_000 = 80%.
pub const DEFAULT_MIN_COVERAGE_FRACTION: u64 = 800_000;
/// Default maximum batch size.
pub const DEFAULT_MAX_BATCH_SIZE: usize = 512;
const SPARSE_THRESHOLD: u64 = 300_000;
const PARTIAL_THRESHOLD: u64 = 700_000;

/// Domain of knowledge being transferred across workload neighborhoods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDomain {
    RewritePrior,
    TieringPolicy,
    CachePolicy,
    SchedulingHeuristic,
    InliningDecision,
    SpecializationStrategy,
}

impl TransferDomain {
    pub const ALL: &[Self] = &[
        Self::RewritePrior, Self::TieringPolicy, Self::CachePolicy,
        Self::SchedulingHeuristic, Self::InliningDecision, Self::SpecializationStrategy,
    ];
    #[must_use] pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RewritePrior => "rewrite_prior",
            Self::TieringPolicy => "tiering_policy",
            Self::CachePolicy => "cache_policy",
            Self::SchedulingHeuristic => "scheduling_heuristic",
            Self::InliningDecision => "inlining_decision",
            Self::SpecializationStrategy => "specialization_strategy",
        }
    }
}

impl fmt::Display for TransferDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.as_str()) }
}

/// Verdict from evaluating a single piece of transfer evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferVerdict {
    Validated,
    ConditionallyValid,
    DriftDetected,
    Rejected,
    InsufficientEvidence,
}

impl TransferVerdict {
    #[must_use] pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Validated => "validated",
            Self::ConditionallyValid => "conditionally_valid",
            Self::DriftDetected => "drift_detected",
            Self::Rejected => "rejected",
            Self::InsufficientEvidence => "insufficient_evidence",
        }
    }
    #[must_use] pub const fn allows_unconditional_rollout(&self) -> bool {
        matches!(self, Self::Validated)
    }
}

impl fmt::Display for TransferVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.as_str()) }
}

/// How thoroughly transfer evidence covers target workload regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageLevel {
    Full, Partial, Sparse, Uncovered,
}

impl CoverageLevel {
    #[must_use] pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full", Self::Partial => "partial",
            Self::Sparse => "sparse", Self::Uncovered => "uncovered",
        }
    }
    #[must_use] pub const fn sufficient_for_rollout(&self) -> bool {
        matches!(self, Self::Full | Self::Partial)
    }
}

impl fmt::Display for CoverageLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.as_str()) }
}

/// Action prescribed by the governance gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceAction {
    AllowRollout, ConditionalRollout, BlockRollout, RequireFreshEvidence, DowngradeSupremacy,
}

impl GovernanceAction {
    #[must_use] pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AllowRollout => "allow_rollout",
            Self::ConditionalRollout => "conditional_rollout",
            Self::BlockRollout => "block_rollout",
            Self::RequireFreshEvidence => "require_fresh_evidence",
            Self::DowngradeSupremacy => "downgrade_supremacy",
        }
    }
}

impl fmt::Display for GovernanceAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.as_str()) }
}

/// Evidence of how well a prior transfers from source to target workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferEvidence {
    pub domain: TransferDomain,
    pub source_workload_id: String,
    pub target_workload_id: String,
    pub transfer_fidelity: u64,
    pub drift_magnitude: u64,
    pub sample_count: u64,
    pub epoch: SecurityEpoch,
    pub evidence_hash: ContentHash,
}

impl TransferEvidence {
    #[must_use]
    pub fn new(
        domain: TransferDomain, source: &str, target: &str,
        fidelity: u64, drift: u64, samples: u64, epoch: SecurityEpoch,
    ) -> Self {
        let mut h = Sha256::new();
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(domain.as_str().as_bytes());
        h.update(source.as_bytes());
        h.update(target.as_bytes());
        h.update(fidelity.to_le_bytes());
        h.update(drift.to_le_bytes());
        h.update(samples.to_le_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        let evidence_hash = ContentHash::compute(&h.finalize());
        Self {
            domain, source_workload_id: source.into(), target_workload_id: target.into(),
            transfer_fidelity: fidelity, drift_magnitude: drift,
            sample_count: samples, epoch, evidence_hash,
        }
    }
}

impl fmt::Display for TransferEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TransferEvidence({} {}->{} fidelity={} drift={} n={})",
            self.domain, self.source_workload_id, self.target_workload_id,
            self.transfer_fidelity, self.drift_magnitude, self.sample_count)
    }
}

/// Record of transfer coverage for a particular workload region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageRecord {
    pub domain: TransferDomain,
    pub region_id: String,
    pub coverage_level: CoverageLevel,
    pub transfer_evidence_hash: ContentHash,
    pub last_validated_epoch: SecurityEpoch,
}

impl CoverageRecord {
    #[must_use]
    pub fn new(
        domain: TransferDomain, region_id: &str, coverage_level: CoverageLevel,
        transfer_evidence_hash: ContentHash, last_validated_epoch: SecurityEpoch,
    ) -> Self {
        Self { domain, region_id: region_id.into(), coverage_level,
               transfer_evidence_hash, last_validated_epoch }
    }

    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(self.domain.as_str().as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(self.region_id.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(self.coverage_level.as_str().as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(self.transfer_evidence_hash.as_bytes());
        buf.extend_from_slice(&self.last_validated_epoch.as_u64().to_le_bytes());
        ContentHash::compute(&buf)
    }
}

impl fmt::Display for CoverageRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Coverage({} region={} level={})", self.domain, self.region_id, self.coverage_level)
    }
}

/// Configuration for the transfer governance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    pub min_transfer_fidelity_high: u64,
    pub min_transfer_fidelity_moderate: u64,
    pub drift_alarm_threshold: u64,
    pub min_sample_count: u64,
    pub min_coverage_fraction: u64,
    pub max_batch_size: usize,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            min_transfer_fidelity_high: DEFAULT_HIGH_FIDELITY_THRESHOLD,
            min_transfer_fidelity_moderate: DEFAULT_MODERATE_FIDELITY_THRESHOLD,
            drift_alarm_threshold: DEFAULT_DRIFT_ALARM_THRESHOLD,
            min_sample_count: DEFAULT_MIN_SAMPLE_COUNT,
            min_coverage_fraction: DEFAULT_MIN_COVERAGE_FRACTION,
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
        }
    }
}

impl fmt::Display for GateConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GateConfig(high={} mod={} drift={} min_n={} cov={})",
            self.min_transfer_fidelity_high, self.min_transfer_fidelity_moderate,
            self.drift_alarm_threshold, self.min_sample_count, self.min_coverage_fraction)
    }
}

/// A governance decision for a single piece of transfer evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceDecision {
    pub action: GovernanceAction,
    pub evidence_hashes: Vec<ContentHash>,
    pub explanation: String,
    pub epoch: SecurityEpoch,
    pub receipt_hash: ContentHash,
}

impl GovernanceDecision {
    #[must_use]
    pub fn new(action: GovernanceAction, evidence_hashes: Vec<ContentHash>,
               explanation: &str, epoch: SecurityEpoch) -> Self {
        let mut h = Sha256::new();
        h.update(COMPONENT.as_bytes());
        h.update(action.as_str().as_bytes());
        for eh in &evidence_hashes { h.update(eh.as_bytes()); }
        h.update(explanation.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        let receipt_hash = ContentHash::compute(&h.finalize());
        Self { action, evidence_hashes, explanation: explanation.into(), epoch, receipt_hash }
    }
}

impl fmt::Display for GovernanceDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GovernanceDecision({} evidence_count={} epoch={})",
            self.action, self.evidence_hashes.len(), self.epoch.as_u64())
    }
}

/// Result of evaluating rollout readiness from transfer evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutGateResult {
    pub allowed: bool,
    pub conditions: Vec<String>,
    pub blocking_reasons: Vec<String>,
    pub coverage_summary: CoverageLevel,
}

impl RolloutGateResult {
    #[must_use] pub fn allowed(cov: CoverageLevel) -> Self {
        Self { allowed: true, conditions: Vec::new(), blocking_reasons: Vec::new(), coverage_summary: cov }
    }
    #[must_use] pub fn blocked(reasons: Vec<String>, cov: CoverageLevel) -> Self {
        Self { allowed: false, conditions: Vec::new(), blocking_reasons: reasons, coverage_summary: cov }
    }
    #[must_use] pub fn conditional(conds: Vec<String>, cov: CoverageLevel) -> Self {
        Self { allowed: true, conditions: conds, blocking_reasons: Vec::new(), coverage_summary: cov }
    }
}

impl fmt::Display for RolloutGateResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.allowed {
            write!(f, "RolloutGate(BLOCKED reasons={} coverage={})", self.blocking_reasons.len(), self.coverage_summary)
        } else if !self.conditions.is_empty() {
            write!(f, "RolloutGate(CONDITIONAL conditions={} coverage={})", self.conditions.len(), self.coverage_summary)
        } else {
            write!(f, "RolloutGate(ALLOWED coverage={})", self.coverage_summary)
        }
    }
}

/// A constraint on a published supremacy claim imposed by transfer governance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupremacyConstraint {
    pub claim_id: String,
    pub constraint_kind: String,
    pub severity: u64,
    pub explanation: String,
}

impl SupremacyConstraint {
    #[must_use]
    pub fn new(claim_id: &str, kind: &str, severity: u64, explanation: &str) -> Self {
        Self { claim_id: claim_id.into(), constraint_kind: kind.into(),
               severity, explanation: explanation.into() }
    }
    #[must_use] pub fn is_critical(&self) -> bool { self.severity >= 800_000 }
    #[must_use] pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(96);
        buf.extend_from_slice(self.claim_id.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(self.constraint_kind.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(&self.severity.to_le_bytes());
        buf.push(b'|');
        buf.extend_from_slice(self.explanation.as_bytes());
        ContentHash::compute(&buf)
    }
}

impl fmt::Display for SupremacyConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SupremacyConstraint(claim={} kind={} severity={})",
            self.claim_id, self.constraint_kind, self.severity)
    }
}

/// Content-hashed receipt for a governance decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    pub receipt_hash: ContentHash,
    pub component: String,
    pub epoch: SecurityEpoch,
    pub action: GovernanceAction,
    pub evidence_hash: ContentHash,
}

impl DecisionReceipt {
    #[must_use]
    pub fn new(epoch: SecurityEpoch, action: GovernanceAction, evidence_hash: ContentHash) -> Self {
        let mut h = Sha256::new();
        h.update(COMPONENT.as_bytes());
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        h.update(action.as_str().as_bytes());
        h.update(evidence_hash.as_bytes());
        let receipt_hash = ContentHash::compute(&h.finalize());
        Self { receipt_hash, component: COMPONENT.into(), epoch, action, evidence_hash }
    }
}

impl fmt::Display for DecisionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecisionReceipt({} action={} epoch={})", self.component, self.action, self.epoch.as_u64())
    }
}

/// Summary statistics from a batch governance evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceSummary {
    pub total_transfers: u64,
    pub validated: u64,
    pub conditionally_valid: u64,
    pub drift_detected: u64,
    pub rejected: u64,
    pub insufficient: u64,
    pub coverage_fraction: u64,
}

impl GovernanceSummary {
    #[must_use]
    pub fn from_counts(v: u64, cv: u64, dd: u64, r: u64, ins: u64) -> Self {
        let total = v.saturating_add(cv).saturating_add(dd).saturating_add(r).saturating_add(ins);
        let passing = v.saturating_add(cv);
        let frac = if total == 0 { 0 } else { passing.saturating_mul(MILLION).checked_div(total).unwrap_or(0) };
        Self { total_transfers: total, validated: v, conditionally_valid: cv,
               drift_detected: dd, rejected: r, insufficient: ins, coverage_fraction: frac }
    }
    #[must_use] pub fn pass_rate(&self) -> u64 {
        if self.total_transfers == 0 { return 0; }
        self.validated.saturating_mul(MILLION).checked_div(self.total_transfers).unwrap_or(0)
    }
}

impl fmt::Display for GovernanceSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GovernanceSummary(total={} v={} cv={} dd={} r={} ins={} cov={})",
            self.total_transfers, self.validated, self.conditionally_valid,
            self.drift_detected, self.rejected, self.insufficient, self.coverage_fraction)
    }
}

// ---------------------------------------------------------------------------
// Core evaluation functions
// ---------------------------------------------------------------------------

/// Evaluate a single piece of transfer evidence.
///
/// Priority: insufficient samples > drift > high fidelity > moderate > rejected.
#[must_use]
pub fn evaluate_transfer(ev: &TransferEvidence, cfg: &GateConfig) -> TransferVerdict {
    if ev.sample_count < cfg.min_sample_count { return TransferVerdict::InsufficientEvidence; }
    if ev.drift_magnitude > cfg.drift_alarm_threshold { return TransferVerdict::DriftDetected; }
    if ev.transfer_fidelity >= cfg.min_transfer_fidelity_high { return TransferVerdict::Validated; }
    if ev.transfer_fidelity >= cfg.min_transfer_fidelity_moderate { return TransferVerdict::ConditionallyValid; }
    TransferVerdict::Rejected
}

fn fraction_to_coverage(frac: u64, min_cov: u64) -> CoverageLevel {
    if frac >= min_cov { CoverageLevel::Full }
    else if frac >= PARTIAL_THRESHOLD { CoverageLevel::Partial }
    else if frac >= SPARSE_THRESHOLD { CoverageLevel::Sparse }
    else { CoverageLevel::Uncovered }
}

/// Evaluate coverage level from a set of coverage records.
#[must_use]
pub fn evaluate_coverage(records: &[CoverageRecord], cfg: &GateConfig) -> CoverageLevel {
    if records.is_empty() { return CoverageLevel::Uncovered; }
    let covered = records.iter().filter(|r| r.coverage_level.sufficient_for_rollout()).count() as u64;
    let total = records.len() as u64;
    let frac = covered.saturating_mul(MILLION).checked_div(total).unwrap_or(0);
    fraction_to_coverage(frac, cfg.min_coverage_fraction)
}

/// Evaluate rollout readiness from a batch of transfer evidence.
#[must_use]
pub fn evaluate_rollout(evidences: &[TransferEvidence], cfg: &GateConfig) -> RolloutGateResult {
    if evidences.is_empty() {
        return RolloutGateResult::blocked(vec!["no transfer evidence provided".into()], CoverageLevel::Uncovered);
    }
    let mut passing: u64 = 0;
    let mut blocking = Vec::new();
    let mut conditions = Vec::new();
    for ev in evidences {
        match evaluate_transfer(ev, cfg) {
            TransferVerdict::Validated => { passing += 1; }
            TransferVerdict::ConditionallyValid => {
                passing += 1;
                conditions.push(format!("conditional: {} {}->{}", ev.domain, ev.source_workload_id, ev.target_workload_id));
            }
            TransferVerdict::DriftDetected => {
                blocking.push(format!("drift: {} {}->{} ({})", ev.domain, ev.source_workload_id, ev.target_workload_id, ev.drift_magnitude));
            }
            TransferVerdict::Rejected => {
                blocking.push(format!("rejected: {} {}->{}", ev.domain, ev.source_workload_id, ev.target_workload_id));
            }
            TransferVerdict::InsufficientEvidence => {
                blocking.push(format!("insufficient: {} {}->{}", ev.domain, ev.source_workload_id, ev.target_workload_id));
            }
        }
    }
    let total = evidences.len() as u64;
    let cov_frac = passing.saturating_mul(MILLION).checked_div(total).unwrap_or(0);
    let cov = fraction_to_coverage(cov_frac, cfg.min_coverage_fraction);
    if !blocking.is_empty() {
        RolloutGateResult { allowed: false, conditions, blocking_reasons: blocking, coverage_summary: cov }
    } else if !conditions.is_empty() {
        RolloutGateResult::conditional(conditions, cov)
    } else {
        RolloutGateResult::allowed(cov)
    }
}

/// Evaluate a batch of transfer evidence producing decisions and a summary.
#[must_use]
pub fn evaluate_batch(evidences: &[TransferEvidence], cfg: &GateConfig) -> (Vec<GovernanceDecision>, GovernanceSummary) {
    let batch = if evidences.len() > cfg.max_batch_size { &evidences[..cfg.max_batch_size] } else { evidences };
    let (mut v, mut cv, mut dd, mut r, mut ins) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut decisions = Vec::with_capacity(batch.len());
    for ev in batch {
        let verdict = evaluate_transfer(ev, cfg);
        let (action, explanation) = match verdict {
            TransferVerdict::Validated => { v += 1; (GovernanceAction::AllowRollout,
                format!("validated: {} {}->{}", ev.domain, ev.source_workload_id, ev.target_workload_id)) }
            TransferVerdict::ConditionallyValid => { cv += 1; (GovernanceAction::ConditionalRollout,
                format!("conditional: {} {}->{}", ev.domain, ev.source_workload_id, ev.target_workload_id)) }
            TransferVerdict::DriftDetected => { dd += 1; (GovernanceAction::DowngradeSupremacy,
                format!("drift: {} {}->{}", ev.domain, ev.source_workload_id, ev.target_workload_id)) }
            TransferVerdict::Rejected => { r += 1; (GovernanceAction::BlockRollout,
                format!("rejected: {} {}->{}", ev.domain, ev.source_workload_id, ev.target_workload_id)) }
            TransferVerdict::InsufficientEvidence => { ins += 1; (GovernanceAction::RequireFreshEvidence,
                format!("insufficient: {} {}->{}", ev.domain, ev.source_workload_id, ev.target_workload_id)) }
        };
        decisions.push(GovernanceDecision::new(action, vec![ev.evidence_hash], &explanation, ev.epoch));
    }
    (decisions, GovernanceSummary::from_counts(v, cv, dd, r, ins))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(n: u64) -> SecurityEpoch { SecurityEpoch::from_raw(n) }
    fn ev(dom: TransferDomain, fid: u64, drift: u64, n: u64) -> TransferEvidence {
        TransferEvidence::new(dom, "src", "tgt", fid, drift, n, ep(10))
    }
    fn cov(dom: TransferDomain, reg: &str, lvl: CoverageLevel) -> CoverageRecord {
        CoverageRecord::new(dom, reg, lvl, ContentHash::compute(b"h"), ep(5))
    }

    #[test] fn test_constants() {
        assert!(SCHEMA_VERSION.contains("transfer-governance-gate"));
        assert_eq!(COMPONENT, "transfer_governance_gate");
        assert_eq!(BEAD_ID, "bd-1lsy.7.12.3");
        assert_eq!(POLICY_ID, "RGC-612C");
        assert!(DEFAULT_HIGH_FIDELITY_THRESHOLD > DEFAULT_MODERATE_FIDELITY_THRESHOLD);
    }

    #[test] fn test_domain_all_count() { assert_eq!(TransferDomain::ALL.len(), 6); }
    #[test] fn test_domain_display() {
        assert_eq!(TransferDomain::RewritePrior.to_string(), "rewrite_prior");
        assert_eq!(TransferDomain::SpecializationStrategy.to_string(), "specialization_strategy");
    }
    #[test] fn test_domain_serde() {
        for d in TransferDomain::ALL {
            let j = serde_json::to_string(d).unwrap();
            assert_eq!(*d, serde_json::from_str::<TransferDomain>(&j).unwrap());
        }
    }

    #[test] fn test_verdict_display() {
        assert_eq!(TransferVerdict::Validated.to_string(), "validated");
        assert_eq!(TransferVerdict::DriftDetected.to_string(), "drift_detected");
        assert_eq!(TransferVerdict::InsufficientEvidence.to_string(), "insufficient_evidence");
    }
    #[test] fn test_verdict_serde() {
        for v in [TransferVerdict::Validated, TransferVerdict::ConditionallyValid,
                   TransferVerdict::DriftDetected, TransferVerdict::Rejected, TransferVerdict::InsufficientEvidence] {
            let j = serde_json::to_string(&v).unwrap();
            assert_eq!(v, serde_json::from_str::<TransferVerdict>(&j).unwrap());
        }
    }
    #[test] fn test_verdict_unconditional() {
        assert!(TransferVerdict::Validated.allows_unconditional_rollout());
        assert!(!TransferVerdict::ConditionallyValid.allows_unconditional_rollout());
        assert!(!TransferVerdict::Rejected.allows_unconditional_rollout());
    }

    #[test] fn test_coverage_level_display() {
        assert_eq!(CoverageLevel::Full.to_string(), "full");
        assert_eq!(CoverageLevel::Uncovered.to_string(), "uncovered");
    }
    #[test] fn test_coverage_level_serde() {
        for l in [CoverageLevel::Full, CoverageLevel::Partial, CoverageLevel::Sparse, CoverageLevel::Uncovered] {
            let j = serde_json::to_string(&l).unwrap();
            assert_eq!(l, serde_json::from_str::<CoverageLevel>(&j).unwrap());
        }
    }
    #[test] fn test_coverage_sufficient() {
        assert!(CoverageLevel::Full.sufficient_for_rollout());
        assert!(CoverageLevel::Partial.sufficient_for_rollout());
        assert!(!CoverageLevel::Sparse.sufficient_for_rollout());
        assert!(!CoverageLevel::Uncovered.sufficient_for_rollout());
    }

    #[test] fn test_action_display() {
        assert_eq!(GovernanceAction::AllowRollout.to_string(), "allow_rollout");
        assert_eq!(GovernanceAction::DowngradeSupremacy.to_string(), "downgrade_supremacy");
    }
    #[test] fn test_action_serde() {
        for a in [GovernanceAction::AllowRollout, GovernanceAction::ConditionalRollout,
                   GovernanceAction::BlockRollout, GovernanceAction::RequireFreshEvidence,
                   GovernanceAction::DowngradeSupremacy] {
            let j = serde_json::to_string(&a).unwrap();
            assert_eq!(a, serde_json::from_str::<GovernanceAction>(&j).unwrap());
        }
    }

    #[test] fn test_evidence_creation() {
        let e = ev(TransferDomain::CachePolicy, 950_000, 10_000, 100);
        assert_eq!(e.domain, TransferDomain::CachePolicy);
        assert_eq!(e.transfer_fidelity, 950_000);
        assert_eq!(e.sample_count, 100);
    }
    #[test] fn test_evidence_hash_deterministic() {
        let a = ev(TransferDomain::RewritePrior, 900_000, 50_000, 50);
        let b = ev(TransferDomain::RewritePrior, 900_000, 50_000, 50);
        assert_eq!(a.evidence_hash, b.evidence_hash);
    }
    #[test] fn test_evidence_hash_differs() {
        let a = ev(TransferDomain::RewritePrior, 900_000, 50_000, 50);
        let b = ev(TransferDomain::CachePolicy, 900_000, 50_000, 50);
        assert_ne!(a.evidence_hash, b.evidence_hash);
    }
    #[test] fn test_evidence_display() {
        let e = ev(TransferDomain::TieringPolicy, 800_000, 20_000, 40);
        assert!(e.to_string().contains("tiering_policy"));
    }
    #[test] fn test_evidence_serde() {
        let e = ev(TransferDomain::InliningDecision, 750_000, 100_000, 60);
        let j = serde_json::to_string(&e).unwrap();
        assert_eq!(e, serde_json::from_str::<TransferEvidence>(&j).unwrap());
    }

    #[test] fn test_eval_validated() {
        let c = GateConfig::default();
        assert_eq!(evaluate_transfer(&ev(TransferDomain::RewritePrior, 950_000, 100_000, 50), &c), TransferVerdict::Validated);
    }
    #[test] fn test_eval_conditionally_valid() {
        let c = GateConfig::default();
        assert_eq!(evaluate_transfer(&ev(TransferDomain::CachePolicy, 750_000, 100_000, 50), &c), TransferVerdict::ConditionallyValid);
    }
    #[test] fn test_eval_drift() {
        let c = GateConfig::default();
        assert_eq!(evaluate_transfer(&ev(TransferDomain::TieringPolicy, 950_000, 300_000, 50), &c), TransferVerdict::DriftDetected);
    }
    #[test] fn test_eval_rejected() {
        let c = GateConfig::default();
        assert_eq!(evaluate_transfer(&ev(TransferDomain::SchedulingHeuristic, 500_000, 100_000, 50), &c), TransferVerdict::Rejected);
    }
    #[test] fn test_eval_insufficient() {
        let c = GateConfig::default();
        assert_eq!(evaluate_transfer(&ev(TransferDomain::InliningDecision, 950_000, 0, 5), &c), TransferVerdict::InsufficientEvidence);
    }
    #[test] fn test_eval_priority_drift_over_fidelity() {
        let c = GateConfig::default();
        // Drift takes priority even with perfect fidelity; insufficient takes priority over everything
        assert_eq!(evaluate_transfer(&ev(TransferDomain::RewritePrior, 990_000, 500_000, 100), &c), TransferVerdict::DriftDetected);
        assert_eq!(evaluate_transfer(&ev(TransferDomain::CachePolicy, 1_000_000, 500_000, 1), &c), TransferVerdict::InsufficientEvidence);
    }

    #[test] fn test_coverage_record_hashing() {
        let a = cov(TransferDomain::RewritePrior, "r1", CoverageLevel::Full);
        let b = cov(TransferDomain::RewritePrior, "r1", CoverageLevel::Full);
        let c = cov(TransferDomain::RewritePrior, "r1", CoverageLevel::Sparse);
        assert_eq!(a.content_hash(), b.content_hash());
        assert_ne!(a.content_hash(), c.content_hash());
        assert!(a.to_string().contains("Coverage"));
    }

    #[test] fn test_coverage_empty() {
        assert_eq!(evaluate_coverage(&[], &GateConfig::default()), CoverageLevel::Uncovered);
    }
    #[test] fn test_coverage_all_full() {
        let recs = (0..5).map(|i| cov(TransferDomain::RewritePrior, &format!("r{i}"), CoverageLevel::Full)).collect::<Vec<_>>();
        assert_eq!(evaluate_coverage(&recs, &GateConfig::default()), CoverageLevel::Full);
    }
    #[test] fn test_coverage_mixed_partial() {
        let recs = vec![
            cov(TransferDomain::RewritePrior, "a", CoverageLevel::Full),
            cov(TransferDomain::CachePolicy, "b", CoverageLevel::Sparse),
            cov(TransferDomain::TieringPolicy, "c", CoverageLevel::Full),
            cov(TransferDomain::InliningDecision, "d", CoverageLevel::Full),
        ]; // 3/4=750k -> Partial
        assert_eq!(evaluate_coverage(&recs, &GateConfig::default()), CoverageLevel::Partial);
    }

    #[test] fn test_config_default_and_serde() {
        let c = GateConfig::default();
        assert_eq!(c.min_transfer_fidelity_high, 900_000);
        assert_eq!(c.min_sample_count, 30);
        assert_eq!(c.max_batch_size, 512);
        let j = serde_json::to_string(&c).unwrap();
        assert_eq!(c, serde_json::from_str::<GateConfig>(&j).unwrap());
    }
    #[test] fn test_config_custom() {
        let c = GateConfig { min_transfer_fidelity_high: 800_000, min_transfer_fidelity_moderate: 600_000,
            drift_alarm_threshold: 300_000, min_sample_count: 10, min_coverage_fraction: 500_000, max_batch_size: 100 };
        assert_eq!(evaluate_transfer(&ev(TransferDomain::CachePolicy, 750_000, 100_000, 20), &c), TransferVerdict::ConditionallyValid);
    }

    #[test] fn test_decision_lifecycle() {
        let h = ContentHash::compute(b"ev");
        let d = GovernanceDecision::new(GovernanceAction::AllowRollout, vec![h], "ok", ep(10));
        assert_eq!(d.action, GovernanceAction::AllowRollout);
        assert_eq!(d.evidence_hashes.len(), 1);
        // Determinism
        let d2 = GovernanceDecision::new(GovernanceAction::AllowRollout, vec![h], "ok", ep(10));
        assert_eq!(d.receipt_hash, d2.receipt_hash);
        assert!(d.to_string().contains("allow_rollout"));
    }

    #[test] fn test_rollout_gate_result_constructors() {
        let a = RolloutGateResult::allowed(CoverageLevel::Full);
        assert!(a.allowed && a.conditions.is_empty() && a.blocking_reasons.is_empty());
        assert!(a.to_string().contains("ALLOWED"));
        let b = RolloutGateResult::blocked(vec!["x".into()], CoverageLevel::Sparse);
        assert!(!b.allowed && b.blocking_reasons.len() == 1);
        assert!(b.to_string().contains("BLOCKED"));
        let c = RolloutGateResult::conditional(vec!["c".into()], CoverageLevel::Partial);
        assert!(c.allowed && c.conditions.len() == 1);
    }

    #[test] fn test_supremacy_constraint() {
        let c = SupremacyConstraint::new("c1", "drift", 600_000, "drift");
        assert!(!c.is_critical());
        assert!(SupremacyConstraint::new("c2", "gap", 900_000, "gap").is_critical());
        let a = SupremacyConstraint::new("c", "k", 500_000, "e");
        let b = SupremacyConstraint::new("c", "k", 500_000, "e");
        assert_eq!(a.content_hash(), b.content_hash());
        assert!(c.to_string().contains("c1"));
    }

    #[test] fn test_receipt_lifecycle() {
        let h = ContentHash::compute(b"ev");
        let r = DecisionReceipt::new(ep(15), GovernanceAction::AllowRollout, h);
        assert_eq!(r.component, COMPONENT);
        assert_eq!(r.epoch.as_u64(), 15);
        // Determinism
        let r2 = DecisionReceipt::new(ep(15), GovernanceAction::AllowRollout, h);
        assert_eq!(r.receipt_hash, r2.receipt_hash);
        // Different action -> different hash
        let r3 = DecisionReceipt::new(ep(15), GovernanceAction::BlockRollout, h);
        assert_ne!(r.receipt_hash, r3.receipt_hash);
        assert!(r3.to_string().contains("block_rollout"));
    }

    #[test] fn test_rollout_empty_blocked() {
        let r = evaluate_rollout(&[], &GateConfig::default());
        assert!(!r.allowed);
    }
    #[test] fn test_rollout_all_validated() {
        let evs = vec![ev(TransferDomain::RewritePrior, 950_000, 50_000, 100),
                       ev(TransferDomain::CachePolicy, 920_000, 30_000, 80)];
        let r = evaluate_rollout(&evs, &GateConfig::default());
        assert!(r.allowed && r.conditions.is_empty());
        assert_eq!(r.coverage_summary, CoverageLevel::Full);
    }
    #[test] fn test_rollout_with_drift() {
        let evs = vec![ev(TransferDomain::RewritePrior, 950_000, 50_000, 100),
                       ev(TransferDomain::CachePolicy, 920_000, 400_000, 80)];
        assert!(!evaluate_rollout(&evs, &GateConfig::default()).allowed);
    }
    #[test] fn test_rollout_conditional() {
        let evs = vec![ev(TransferDomain::RewritePrior, 750_000, 50_000, 100),
                       ev(TransferDomain::CachePolicy, 800_000, 100_000, 80)];
        let r = evaluate_rollout(&evs, &GateConfig::default());
        assert!(r.allowed && !r.conditions.is_empty());
    }

    #[test] fn test_batch_mixed() {
        let c = GateConfig::default();
        let evs = vec![
            ev(TransferDomain::RewritePrior, 950_000, 50_000, 100),
            ev(TransferDomain::CachePolicy, 750_000, 100_000, 50),
            ev(TransferDomain::TieringPolicy, 950_000, 400_000, 60),
            ev(TransferDomain::SchedulingHeuristic, 300_000, 50_000, 40),
            ev(TransferDomain::InliningDecision, 950_000, 0, 5),
        ];
        let (decs, sum) = evaluate_batch(&evs, &c);
        assert_eq!(decs.len(), 5);
        assert_eq!(sum.validated, 1);
        assert_eq!(sum.conditionally_valid, 1);
        assert_eq!(sum.drift_detected, 1);
        assert_eq!(sum.rejected, 1);
        assert_eq!(sum.insufficient, 1);
    }
    #[test] fn test_batch_all_validated() {
        let evs = vec![ev(TransferDomain::RewritePrior, 950_000, 50_000, 100),
                       ev(TransferDomain::CachePolicy, 920_000, 30_000, 80)];
        let (_, sum) = evaluate_batch(&evs, &GateConfig::default());
        assert_eq!(sum.validated, 2);
        assert_eq!(sum.coverage_fraction, MILLION);
    }
    #[test] fn test_batch_max_size() {
        let c = GateConfig { max_batch_size: 2, ..GateConfig::default() };
        let evs = vec![ev(TransferDomain::RewritePrior, 950_000, 50_000, 100),
                       ev(TransferDomain::CachePolicy, 920_000, 30_000, 80),
                       ev(TransferDomain::TieringPolicy, 910_000, 40_000, 90)];
        let (decs, sum) = evaluate_batch(&evs, &c);
        assert_eq!(decs.len(), 2);
        assert_eq!(sum.total_transfers, 2);
    }

    #[test] fn test_summary_metrics() {
        let s = GovernanceSummary::from_counts(3, 1, 1, 0, 0);
        assert_eq!(s.pass_rate(), 600_000);
        assert_eq!(GovernanceSummary::from_counts(2, 2, 1, 0, 0).coverage_fraction, 800_000);
        let empty = GovernanceSummary::from_counts(0, 0, 0, 0, 0);
        assert_eq!(empty.total_transfers, 0);
        assert_eq!(empty.pass_rate(), 0);
        assert!(GovernanceSummary::from_counts(5, 2, 1, 1, 1).to_string().contains("total=10"));
    }

    #[test] fn test_boundary_conditions() {
        let c = GateConfig::default();
        // Fidelity exactly at high threshold -> Validated
        assert_eq!(evaluate_transfer(&ev(TransferDomain::RewritePrior, 900_000, 100_000, 50), &c), TransferVerdict::Validated);
        // Fidelity exactly at moderate threshold -> ConditionallyValid
        assert_eq!(evaluate_transfer(&ev(TransferDomain::RewritePrior, 700_000, 100_000, 50), &c), TransferVerdict::ConditionallyValid);
        // Drift exactly at threshold -> NOT drift (must exceed)
        assert_eq!(evaluate_transfer(&ev(TransferDomain::RewritePrior, 950_000, 200_000, 50), &c), TransferVerdict::Validated);
        // Drift one over -> DriftDetected
        assert_eq!(evaluate_transfer(&ev(TransferDomain::RewritePrior, 950_000, 200_001, 50), &c), TransferVerdict::DriftDetected);
        // Samples exactly at min -> sufficient
        assert_eq!(evaluate_transfer(&ev(TransferDomain::RewritePrior, 950_000, 50_000, 30), &c), TransferVerdict::Validated);
        // Samples one below min -> insufficient
        assert_eq!(evaluate_transfer(&ev(TransferDomain::RewritePrior, 950_000, 50_000, 29), &c), TransferVerdict::InsufficientEvidence);
    }
}
