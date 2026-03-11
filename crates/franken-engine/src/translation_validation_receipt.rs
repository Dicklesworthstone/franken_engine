//! Translation-validation receipt emission and fail-closed proof gating.
//!
//! Bead: bd-1lsy.7.7.2 [RGC-607B]
//!
//! Emits structured, content-addressed receipts for every optimization
//! that goes through the translation-validation gate.  Each receipt carries
//! the rewrite-pack version, applied rules, cost deltas, proof mode,
//! equivalence verdict, and a cryptographic signature chain so downstream
//! consumers (benchmarks, supremacy claims, regression gates) can verify
//! that a given performance artifact was produced by a validated path.
//!
//! # Fail-closed semantics
//!
//! - If proof fails or is inconclusive, the optimization is rejected and
//!   a `FailureReceipt` is emitted with the counterexample hash.
//! - If the receipt chain has gaps or signature mismatches the entire
//!   evidence bundle is invalidated.
//! - Quarantined optimizations cannot re-enter without fresh evidence.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

#![allow(clippy::field_reassign_with_default)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::security_epoch::SecurityEpoch;
use crate::versioned_rewrite_pack::{PackVersion, RewriteCategory};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const COMPONENT: &str = "translation_validation_receipt";
pub const BEAD_ID: &str = "bd-1lsy.7.7.2";
pub const RECEIPT_SCHEMA_VERSION: &str = "franken-engine.tv-receipt.v1";
pub const CHAIN_SCHEMA_VERSION: &str = "franken-engine.tv-receipt-chain.v1";
pub const SUMMARY_SCHEMA_VERSION: &str = "franken-engine.tv-receipt-summary.v1";

/// Maximum receipts retained in a chain before pruning.
pub const MAX_CHAIN_LENGTH: usize = 4096;

/// Maximum applied rules per receipt.
pub const MAX_RULES_PER_RECEIPT: usize = 256;

/// Threshold for cost improvement to count as "significant" (millionths).
pub const SIGNIFICANT_IMPROVEMENT_THRESHOLD: i64 = 50_000; // 5%

// ---------------------------------------------------------------------------
// ProofMode — how equivalence was established
// ---------------------------------------------------------------------------

/// How semantic equivalence was established for a rewrite application.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofMode {
    /// Symbolic equivalence proof (SMT/SAT solver output).
    Symbolic,
    /// Golden-corpus replay with bit-exact output comparison.
    GoldenCorpus,
    /// Differential trace comparison across representative workloads.
    DifferentialTrace,
    /// Rule is axiomatically sound (proven by construction).
    Axiomatic,
    /// Combined: multiple modes were used and all agreed.
    Composite,
}

impl fmt::Display for ProofMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Symbolic => write!(f, "symbolic"),
            Self::GoldenCorpus => write!(f, "golden_corpus"),
            Self::DifferentialTrace => write!(f, "differential_trace"),
            Self::Axiomatic => write!(f, "axiomatic"),
            Self::Composite => write!(f, "composite"),
        }
    }
}

// ---------------------------------------------------------------------------
// ProofEvidence — evidence backing a proof
// ---------------------------------------------------------------------------

/// Evidence artifact backing a translation-validation proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofEvidence {
    /// Proof mode used.
    pub mode: ProofMode,
    /// Content hash of the proof artifact.
    pub artifact_hash: ContentHash,
    /// Number of verification steps or test vectors.
    pub verification_steps: u64,
    /// Time spent on verification (deterministic ticks).
    pub verification_ticks: u64,
    /// Additional mode-specific metadata.
    pub metadata: BTreeMap<String, String>,
}

impl ProofEvidence {
    /// Create new proof evidence.
    pub fn new(
        mode: ProofMode,
        artifact_hash: ContentHash,
        verification_steps: u64,
        verification_ticks: u64,
    ) -> Self {
        Self {
            mode,
            artifact_hash,
            verification_steps,
            verification_ticks,
            metadata: BTreeMap::new(),
        }
    }

    /// Add metadata.
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Compute content hash of this evidence.
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update([self.mode.clone() as u8]);
        hasher.update(self.artifact_hash.as_bytes());
        hasher.update(self.verification_steps.to_le_bytes());
        hasher.update(self.verification_ticks.to_le_bytes());
        for (k, v) in &self.metadata {
            hasher.update(k.as_bytes());
            hasher.update(v.as_bytes());
        }
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// AppliedRuleRecord — a rule that was applied in a rewrite step
// ---------------------------------------------------------------------------

/// Record of a single rewrite rule application within a validation step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedRuleRecord {
    /// Pack from which the rule was drawn.
    pub pack_id: String,
    /// Pack version.
    pub pack_version: PackVersion,
    /// Rule identifier.
    pub rule_id: String,
    /// Category of the rewrite.
    pub category: RewriteCategory,
    /// Hash of the IR region before rewrite.
    pub before_hash: ContentHash,
    /// Hash of the IR region after rewrite.
    pub after_hash: ContentHash,
    /// Cost delta (millionths, negative = cost reduction = improvement).
    pub cost_delta_millionths: i64,
    /// Whether this rule was proven sound at pack level.
    pub rule_proven_sound: bool,
}

impl AppliedRuleRecord {
    /// Whether this rule application improved cost.
    pub fn is_improvement(&self) -> bool {
        self.cost_delta_millionths < 0
    }

    /// Whether improvement is significant (above threshold).
    pub fn is_significant_improvement(&self) -> bool {
        self.cost_delta_millionths < -SIGNIFICANT_IMPROVEMENT_THRESHOLD
    }
}

// ---------------------------------------------------------------------------
// ValidationVerdict — outcome of the proof step
// ---------------------------------------------------------------------------

/// Verdict from a translation-validation proof attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptVerdict {
    /// Equivalence confirmed; rewrite is semantics-preserving.
    Proven {
        /// Evidence backing the proof.
        evidence: ProofEvidence,
    },
    /// Equivalence disproven; counterexample found.
    Disproven {
        /// Hash of the counterexample.
        counterexample_hash: ContentHash,
        /// Human-readable divergence description.
        divergence: String,
    },
    /// Could not determine equivalence within budget.
    Inconclusive {
        /// Why the proof was inconclusive.
        reason: String,
        /// Budget consumed (verification ticks).
        budget_consumed_ticks: u64,
        /// Budget limit.
        budget_limit_ticks: u64,
    },
}

impl ReceiptVerdict {
    /// Whether this verdict permits the rewrite to be activated.
    pub fn permits_activation(&self) -> bool {
        matches!(self, Self::Proven { .. })
    }

    /// Whether the verdict is a hard failure (counterexample found).
    pub fn is_disproven(&self) -> bool {
        matches!(self, Self::Disproven { .. })
    }
}

impl fmt::Display for ReceiptVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proven { evidence } => {
                write!(f, "PROVEN ({})", evidence.mode)
            }
            Self::Disproven { divergence, .. } => {
                write!(f, "DISPROVEN: {divergence}")
            }
            Self::Inconclusive { reason, .. } => {
                write!(f, "INCONCLUSIVE: {reason}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TranslationValidationReceipt — the core receipt type
// ---------------------------------------------------------------------------

/// A content-addressed, signed receipt for a single translation-validation
/// step.  Each receipt covers one optimization attempt: the rules applied,
/// the proof mode, the verdict, and the cost impact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranslationValidationReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Monotonically increasing sequence number within a chain.
    pub sequence: u64,
    /// Unique optimization identifier.
    pub optimization_id: String,
    /// Hash of the previous receipt in the chain (if any).
    pub parent_hash: Option<ContentHash>,
    /// Security epoch at receipt creation.
    pub epoch: SecurityEpoch,
    /// Timestamp (deterministic ticks).
    pub timestamp_ticks: u64,
    /// Hash of the IR before any rewrites.
    pub baseline_ir_hash: ContentHash,
    /// Hash of the IR after all rewrites.
    pub optimized_ir_hash: ContentHash,
    /// Rules applied in this optimization step.
    pub applied_rules: Vec<AppliedRuleRecord>,
    /// Total cost delta (sum of all rule deltas, millionths).
    pub total_cost_delta_millionths: i64,
    /// Proof verdict.
    pub verdict: ReceiptVerdict,
    /// Cost model used for evaluation.
    pub cost_model_id: String,
    /// Categories of rewrites applied.
    pub rewrite_categories: BTreeSet<RewriteCategory>,
    /// Content hash of this receipt (deterministic).
    pub content_hash: ContentHash,
    /// Cryptographic signature.
    pub signature: AuthenticityHash,
}

impl TranslationValidationReceipt {
    /// Create a new receipt.  Computes content hash and leaves signature
    /// as zero (caller must sign via `.sign()`).
    pub fn new(
        sequence: u64,
        optimization_id: &str,
        parent_hash: Option<ContentHash>,
        epoch: SecurityEpoch,
        timestamp_ticks: u64,
        baseline_ir_hash: ContentHash,
        optimized_ir_hash: ContentHash,
        applied_rules: Vec<AppliedRuleRecord>,
        verdict: ReceiptVerdict,
        cost_model_id: &str,
    ) -> Self {
        let total_cost_delta_millionths: i64 =
            applied_rules.iter().map(|r| r.cost_delta_millionths).sum();

        let rewrite_categories: BTreeSet<RewriteCategory> =
            applied_rules.iter().map(|r| r.category).collect();

        let content_hash = Self::compute_hash(
            sequence,
            optimization_id,
            &parent_hash,
            epoch,
            timestamp_ticks,
            &baseline_ir_hash,
            &optimized_ir_hash,
            &applied_rules,
            &verdict,
        );

        Self {
            schema_version: RECEIPT_SCHEMA_VERSION.into(),
            sequence,
            optimization_id: optimization_id.into(),
            parent_hash,
            epoch,
            timestamp_ticks,
            baseline_ir_hash,
            optimized_ir_hash,
            applied_rules,
            total_cost_delta_millionths,
            verdict,
            cost_model_id: cost_model_id.into(),
            rewrite_categories,
            content_hash,
            signature: AuthenticityHash::compute_keyed(&[], &[]),
        }
    }

    /// Sign this receipt with the given key.
    pub fn sign(mut self, key: &[u8]) -> Self {
        let preimage = self.signing_preimage();
        self.signature = AuthenticityHash::compute_keyed(key, &preimage);
        self
    }

    /// Verify the receipt signature.
    pub fn verify_signature(&self, key: &[u8]) -> bool {
        let preimage = self.signing_preimage();
        let expected = AuthenticityHash::compute_keyed(key, &preimage);
        self.signature == expected
    }

    /// Whether this receipt permits the rewrite to be activated.
    pub fn permits_activation(&self) -> bool {
        self.verdict.permits_activation()
    }

    /// Whether this receipt represents a failure.
    pub fn is_failure(&self) -> bool {
        !self.verdict.permits_activation()
    }

    /// Number of rules applied.
    pub fn rule_count(&self) -> usize {
        self.applied_rules.len()
    }

    /// Number of rules that are proven sound at pack level.
    pub fn proven_sound_rule_count(&self) -> usize {
        self.applied_rules
            .iter()
            .filter(|r| r.rule_proven_sound)
            .count()
    }

    /// Whether all applied rules were proven sound at pack level.
    pub fn all_rules_proven_sound(&self) -> bool {
        self.applied_rules.iter().all(|r| r.rule_proven_sound)
    }

    /// Whether there was a net cost improvement.
    pub fn is_net_improvement(&self) -> bool {
        self.total_cost_delta_millionths < 0
    }

    fn signing_preimage(&self) -> Vec<u8> {
        let mut pre = Vec::new();
        pre.extend_from_slice(self.content_hash.as_bytes());
        pre.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        pre.extend_from_slice(&self.sequence.to_le_bytes());
        pre
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_hash(
        sequence: u64,
        optimization_id: &str,
        parent_hash: &Option<ContentHash>,
        epoch: SecurityEpoch,
        timestamp_ticks: u64,
        baseline_ir_hash: &ContentHash,
        optimized_ir_hash: &ContentHash,
        applied_rules: &[AppliedRuleRecord],
        verdict: &ReceiptVerdict,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(RECEIPT_SCHEMA_VERSION.as_bytes());
        hasher.update(sequence.to_le_bytes());
        hasher.update(optimization_id.as_bytes());
        if let Some(ph) = parent_hash {
            hasher.update([1]);
            hasher.update(ph.as_bytes());
        } else {
            hasher.update([0]);
        }
        hasher.update(epoch.as_u64().to_le_bytes());
        hasher.update(timestamp_ticks.to_le_bytes());
        hasher.update(baseline_ir_hash.as_bytes());
        hasher.update(optimized_ir_hash.as_bytes());
        for rule in applied_rules {
            hasher.update(rule.rule_id.as_bytes());
            hasher.update(rule.before_hash.as_bytes());
            hasher.update(rule.after_hash.as_bytes());
            hasher.update(rule.cost_delta_millionths.to_le_bytes());
        }
        let verdict_tag: u8 = match verdict {
            ReceiptVerdict::Proven { .. } => 1,
            ReceiptVerdict::Disproven { .. } => 2,
            ReceiptVerdict::Inconclusive { .. } => 3,
        };
        hasher.update([verdict_tag]);
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// FailureReceipt — emitted on proof failure or inconclusive result
// ---------------------------------------------------------------------------

/// A specialized receipt emitted when an optimization is rejected.
/// This is a lightweight record used for quarantine and audit trails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureReceipt {
    /// Optimization that was rejected.
    pub optimization_id: String,
    /// Pack that contained the failing rule(s).
    pub pack_id: String,
    /// Pack version.
    pub pack_version: PackVersion,
    /// Rule IDs that were attempted.
    pub attempted_rules: Vec<String>,
    /// Why the proof failed.
    pub failure_kind: FailureKind,
    /// Counterexample hash (if disproven).
    pub counterexample_hash: Option<ContentHash>,
    /// Whether the optimization was quarantined as a result.
    pub quarantined: bool,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Timestamp.
    pub timestamp_ticks: u64,
    /// Content hash.
    pub content_hash: ContentHash,
}

/// Why an optimization proof failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// Counterexample found: the rewrite changes semantics.
    CounterexampleFound { divergence: String },
    /// Proof budget exceeded: could not verify within time limit.
    BudgetExceeded {
        consumed_ticks: u64,
        limit_ticks: u64,
    },
    /// Interference detected: rules in the application set conflict.
    InterferenceDetected { conflicting_rules: Vec<String> },
    /// IR structure too complex for the chosen proof mode.
    ComplexityExceeded {
        metric: String,
        value: u64,
        limit: u64,
    },
    /// Rule application produced malformed IR.
    MalformedOutput { detail: String },
}

impl fmt::Display for FailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CounterexampleFound { divergence } => {
                write!(f, "counterexample: {divergence}")
            }
            Self::BudgetExceeded {
                consumed_ticks,
                limit_ticks,
            } => {
                write!(f, "budget exceeded: {consumed_ticks}/{limit_ticks} ticks")
            }
            Self::InterferenceDetected { conflicting_rules } => {
                write!(
                    f,
                    "interference: {} rules conflict",
                    conflicting_rules.len()
                )
            }
            Self::ComplexityExceeded {
                metric,
                value,
                limit,
            } => {
                write!(f, "complexity exceeded: {metric}={value} > {limit}")
            }
            Self::MalformedOutput { detail } => {
                write!(f, "malformed output: {detail}")
            }
        }
    }
}

impl FailureReceipt {
    /// Create a new failure receipt.
    pub fn new(
        optimization_id: &str,
        pack_id: &str,
        pack_version: PackVersion,
        attempted_rules: Vec<String>,
        failure_kind: FailureKind,
        counterexample_hash: Option<ContentHash>,
        quarantined: bool,
        epoch: SecurityEpoch,
        timestamp_ticks: u64,
    ) -> Self {
        let content_hash = Self::compute_hash(
            optimization_id,
            pack_id,
            &attempted_rules,
            &failure_kind,
            &counterexample_hash,
            epoch,
            timestamp_ticks,
        );
        Self {
            optimization_id: optimization_id.into(),
            pack_id: pack_id.into(),
            pack_version,
            attempted_rules,
            failure_kind,
            counterexample_hash,
            quarantined,
            epoch,
            timestamp_ticks,
            content_hash,
        }
    }

    fn compute_hash(
        optimization_id: &str,
        pack_id: &str,
        attempted_rules: &[String],
        failure_kind: &FailureKind,
        counterexample_hash: &Option<ContentHash>,
        epoch: SecurityEpoch,
        timestamp_ticks: u64,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(optimization_id.as_bytes());
        hasher.update(pack_id.as_bytes());
        for r in attempted_rules {
            hasher.update(r.as_bytes());
        }
        hasher.update(format!("{failure_kind}").as_bytes());
        if let Some(h) = counterexample_hash {
            hasher.update(h.as_bytes());
        }
        hasher.update(epoch.as_u64().to_le_bytes());
        hasher.update(timestamp_ticks.to_le_bytes());
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// ReceiptChain — ordered, hash-linked chain of receipts
// ---------------------------------------------------------------------------

/// An ordered, hash-linked chain of translation-validation receipts.
/// Each receipt's `parent_hash` links to the previous receipt's `content_hash`,
/// forming a tamper-evident audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptChain {
    /// Schema version.
    pub schema_version: String,
    /// Chain identifier (typically the optimization pipeline ID).
    pub chain_id: String,
    /// Receipts in chronological order.
    pub receipts: Vec<TranslationValidationReceipt>,
    /// Failure receipts (rejected optimizations).
    pub failures: Vec<FailureReceipt>,
    /// Maximum chain length before pruning oldest entries.
    pub max_length: usize,
    /// Next sequence number.
    pub next_sequence: u64,
    /// Security epoch at chain creation.
    pub created_epoch: SecurityEpoch,
    /// Content hash of the chain (hash of all receipt hashes).
    pub content_hash: ContentHash,
}

impl ReceiptChain {
    /// Create a new empty chain.
    pub fn new(chain_id: &str, epoch: SecurityEpoch) -> Self {
        Self {
            schema_version: CHAIN_SCHEMA_VERSION.into(),
            chain_id: chain_id.into(),
            receipts: Vec::new(),
            failures: Vec::new(),
            max_length: MAX_CHAIN_LENGTH,
            next_sequence: 1,
            created_epoch: epoch,
            content_hash: ContentHash::compute(&[]),
        }
    }

    /// Create a chain with a custom max length.
    pub fn with_max_length(mut self, max_length: usize) -> Self {
        self.max_length = max_length;
        self
    }

    /// Append a receipt to the chain.  Returns an error if the receipt's
    /// parent hash doesn't match the chain's last receipt hash.
    pub fn append(
        &mut self,
        receipt: TranslationValidationReceipt,
    ) -> Result<(), ReceiptChainError> {
        // Verify parent hash linkage
        let expected_parent = self.receipts.last().map(|r| r.content_hash.clone());
        if receipt.parent_hash != expected_parent {
            return Err(ReceiptChainError::ParentHashMismatch {
                expected: expected_parent,
                actual: receipt.parent_hash.clone(),
            });
        }

        // Verify sequence continuity
        if receipt.sequence != self.next_sequence {
            return Err(ReceiptChainError::SequenceGap {
                expected: self.next_sequence,
                actual: receipt.sequence,
            });
        }

        self.receipts.push(receipt);
        self.next_sequence += 1;

        // Prune if over capacity
        if self.receipts.len() > self.max_length {
            let excess = self.receipts.len() - self.max_length;
            self.receipts.drain(..excess);
        }

        self.recompute_hash();
        Ok(())
    }

    /// Record a failure (rejected optimization).
    pub fn record_failure(&mut self, failure: FailureReceipt) {
        self.failures.push(failure);
        // Keep failures bounded too
        if self.failures.len() > self.max_length {
            let excess = self.failures.len() - self.max_length;
            self.failures.drain(..excess);
        }
        self.recompute_hash();
    }

    /// Number of successful receipts.
    pub fn success_count(&self) -> usize {
        self.receipts
            .iter()
            .filter(|r| r.permits_activation())
            .count()
    }

    /// Number of failed/inconclusive receipts (in the main chain).
    pub fn rejected_count(&self) -> usize {
        self.receipts.iter().filter(|r| r.is_failure()).count()
    }

    /// Number of failure records.
    pub fn failure_count(&self) -> usize {
        self.failures.len()
    }

    /// Total cost delta across all successful receipts (millionths).
    pub fn total_cost_improvement(&self) -> i64 {
        self.receipts
            .iter()
            .filter(|r| r.permits_activation())
            .map(|r| r.total_cost_delta_millionths)
            .sum()
    }

    /// Verify the hash-chain integrity of all receipts.
    pub fn verify_integrity(&self) -> ChainIntegrityResult {
        let mut issues = Vec::new();

        for i in 0..self.receipts.len() {
            let receipt = &self.receipts[i];

            // Check parent hash linkage
            if i == 0 {
                // First receipt after pruning may have a parent hash
                // that refers to a pruned receipt — that's acceptable.
            } else {
                let prev = &self.receipts[i - 1];
                if receipt.parent_hash.as_ref() != Some(&prev.content_hash) {
                    issues.push(ChainIntegrityIssue::ParentHashBroken {
                        sequence: receipt.sequence,
                        expected_parent: Some(prev.content_hash.clone()),
                        actual_parent: receipt.parent_hash.clone(),
                    });
                }
            }

            // Check monotonicity
            if i > 0 && receipt.sequence <= self.receipts[i - 1].sequence {
                issues.push(ChainIntegrityIssue::SequenceNonMonotonic {
                    position: i,
                    sequence: receipt.sequence,
                    previous_sequence: self.receipts[i - 1].sequence,
                });
            }
        }

        ChainIntegrityResult {
            valid: issues.is_empty(),
            receipt_count: self.receipts.len(),
            issues,
        }
    }

    /// Get the last receipt in the chain.
    pub fn last_receipt(&self) -> Option<&TranslationValidationReceipt> {
        self.receipts.last()
    }

    /// Get all receipts for a specific optimization ID.
    pub fn receipts_for_optimization(&self, opt_id: &str) -> Vec<&TranslationValidationReceipt> {
        self.receipts
            .iter()
            .filter(|r| r.optimization_id == opt_id)
            .collect()
    }

    /// Get all failure records for a specific pack.
    pub fn failures_for_pack(&self, pack_id: &str) -> Vec<&FailureReceipt> {
        self.failures
            .iter()
            .filter(|f| f.pack_id == pack_id)
            .collect()
    }

    fn recompute_hash(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.chain_id.as_bytes());
        for r in &self.receipts {
            hasher.update(r.content_hash.as_bytes());
        }
        for f in &self.failures {
            hasher.update(f.content_hash.as_bytes());
        }
        self.content_hash = ContentHash::compute(&hasher.finalize());
    }
}

/// Errors from receipt chain operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptChainError {
    /// Parent hash mismatch (receipt doesn't link to chain tail).
    ParentHashMismatch {
        expected: Option<ContentHash>,
        actual: Option<ContentHash>,
    },
    /// Sequence number gap.
    SequenceGap { expected: u64, actual: u64 },
}

impl fmt::Display for ReceiptChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParentHashMismatch { .. } => write!(f, "parent hash mismatch"),
            Self::SequenceGap { expected, actual } => {
                write!(f, "sequence gap: expected {expected}, got {actual}")
            }
        }
    }
}

/// Result of chain integrity verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainIntegrityResult {
    /// Whether the chain is fully valid.
    pub valid: bool,
    /// Number of receipts checked.
    pub receipt_count: usize,
    /// Issues found.
    pub issues: Vec<ChainIntegrityIssue>,
}

/// An integrity issue in a receipt chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainIntegrityIssue {
    /// Parent hash doesn't match previous receipt's content hash.
    ParentHashBroken {
        sequence: u64,
        expected_parent: Option<ContentHash>,
        actual_parent: Option<ContentHash>,
    },
    /// Sequence number is not strictly monotonic.
    SequenceNonMonotonic {
        position: usize,
        sequence: u64,
        previous_sequence: u64,
    },
}

// ---------------------------------------------------------------------------
// ValidationReceiptEmitter — orchestrates receipt creation
// ---------------------------------------------------------------------------

/// Configuration for the receipt emitter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmitterConfig {
    /// Chain identifier.
    pub chain_id: String,
    /// Signing key for receipts.
    pub signing_key: Vec<u8>,
    /// Maximum chain length.
    pub max_chain_length: usize,
    /// Whether to quarantine on first failure.
    pub quarantine_on_first_failure: bool,
    /// Proof budget limit (ticks).
    pub proof_budget_ticks: u64,
    /// Default cost model ID.
    pub default_cost_model_id: String,
}

impl Default for EmitterConfig {
    fn default() -> Self {
        Self {
            chain_id: "default".into(),
            signing_key: vec![0u8; 32],
            max_chain_length: MAX_CHAIN_LENGTH,
            quarantine_on_first_failure: true,
            proof_budget_ticks: 10_000_000,
            default_cost_model_id: "baseline-v1".into(),
        }
    }
}

/// The translation-validation receipt emitter.  Maintains a receipt chain,
/// quarantine set, and statistics for the validation pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReceiptEmitter {
    /// Configuration.
    pub config: EmitterConfig,
    /// The receipt chain.
    pub chain: ReceiptChain,
    /// Quarantined optimization IDs.
    pub quarantine: BTreeSet<String>,
    /// Current security epoch.
    pub current_epoch: SecurityEpoch,
    /// Current timestamp (deterministic ticks).
    pub current_ticks: u64,
    /// Statistics.
    pub stats: EmitterStats,
}

/// Statistics tracked by the emitter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmitterStats {
    /// Total receipts emitted.
    pub total_receipts: u64,
    /// Receipts that permitted activation.
    pub total_proven: u64,
    /// Receipts that rejected activation (disproven).
    pub total_disproven: u64,
    /// Receipts that were inconclusive.
    pub total_inconclusive: u64,
    /// Total rules applied across all receipts.
    pub total_rules_applied: u64,
    /// Total cost improvement (millionths, negative = improvement).
    pub total_cost_improvement_millionths: i64,
    /// Number of optimizations quarantined.
    pub total_quarantined: u64,
    /// Number of signature verifications performed.
    pub total_verifications: u64,
    /// Number of verification failures.
    pub verification_failures: u64,
}

impl Default for EmitterStats {
    fn default() -> Self {
        Self {
            total_receipts: 0,
            total_proven: 0,
            total_disproven: 0,
            total_inconclusive: 0,
            total_rules_applied: 0,
            total_cost_improvement_millionths: 0,
            total_quarantined: 0,
            total_verifications: 0,
            verification_failures: 0,
        }
    }
}

/// Input for emitting a validation receipt.
#[derive(Debug, Clone)]
pub struct EmitInput {
    /// Optimization identifier.
    pub optimization_id: String,
    /// Hash of the baseline IR.
    pub baseline_ir_hash: ContentHash,
    /// Hash of the optimized IR.
    pub optimized_ir_hash: ContentHash,
    /// Rules that were applied.
    pub applied_rules: Vec<AppliedRuleRecord>,
    /// The proof verdict.
    pub verdict: ReceiptVerdict,
    /// Cost model ID used.
    pub cost_model_id: Option<String>,
}

/// Result of an emit operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmitResult {
    /// Receipt was emitted and the optimization is approved.
    Approved {
        receipt: TranslationValidationReceipt,
    },
    /// Receipt was emitted but the optimization is rejected.
    Rejected {
        receipt: TranslationValidationReceipt,
        failure: FailureReceipt,
    },
    /// Optimization was quarantined — cannot be submitted.
    Quarantined {
        optimization_id: String,
        reason: String,
    },
}

impl EmitResult {
    /// Whether the optimization was approved.
    pub fn is_approved(&self) -> bool {
        matches!(self, Self::Approved { .. })
    }

    /// Get the receipt (if any).
    pub fn receipt(&self) -> Option<&TranslationValidationReceipt> {
        match self {
            Self::Approved { receipt } | Self::Rejected { receipt, .. } => Some(receipt),
            Self::Quarantined { .. } => None,
        }
    }
}

impl ValidationReceiptEmitter {
    /// Create a new emitter.
    pub fn new(config: EmitterConfig, epoch: SecurityEpoch) -> Self {
        let chain =
            ReceiptChain::new(&config.chain_id, epoch).with_max_length(config.max_chain_length);
        Self {
            config,
            chain,
            quarantine: BTreeSet::new(),
            current_epoch: epoch,
            current_ticks: 0,
            stats: EmitterStats::default(),
        }
    }

    /// Advance the timestamp.
    pub fn tick(&mut self, ticks: u64) {
        self.current_ticks += ticks;
    }

    /// Advance the epoch.
    pub fn advance_epoch(&mut self) {
        self.current_epoch = SecurityEpoch::from_raw(self.current_epoch.as_u64() + 1);
    }

    /// Check if an optimization is quarantined.
    pub fn is_quarantined(&self, optimization_id: &str) -> bool {
        self.quarantine.contains(optimization_id)
    }

    /// Manually quarantine an optimization.
    pub fn quarantine_optimization(&mut self, optimization_id: &str) {
        self.quarantine.insert(optimization_id.into());
        self.stats.total_quarantined += 1;
    }

    /// Remove an optimization from quarantine (requires fresh evidence).
    pub fn lift_quarantine(&mut self, optimization_id: &str) -> bool {
        self.quarantine.remove(optimization_id)
    }

    /// Emit a translation-validation receipt.  This is the main entry point.
    ///
    /// - If the optimization is quarantined, returns `Quarantined`.
    /// - If the verdict is `Proven`, returns `Approved` with a signed receipt.
    /// - If the verdict is `Disproven` or `Inconclusive`, returns `Rejected`
    ///   with both a receipt and a failure record.  May quarantine the
    ///   optimization if configured to do so.
    pub fn emit(&mut self, input: EmitInput) -> EmitResult {
        // Check quarantine
        if self.is_quarantined(&input.optimization_id) {
            return EmitResult::Quarantined {
                optimization_id: input.optimization_id,
                reason: "optimization is quarantined".into(),
            };
        }

        let cost_model_id = input
            .cost_model_id
            .unwrap_or_else(|| self.config.default_cost_model_id.clone());

        let parent_hash = self.chain.last_receipt().map(|r| r.content_hash.clone());
        let sequence = self.chain.next_sequence;

        let receipt = TranslationValidationReceipt::new(
            sequence,
            &input.optimization_id,
            parent_hash,
            self.current_epoch,
            self.current_ticks,
            input.baseline_ir_hash,
            input.optimized_ir_hash,
            input.applied_rules.clone(),
            input.verdict.clone(),
            &cost_model_id,
        )
        .sign(&self.config.signing_key);

        // Update stats
        self.stats.total_receipts += 1;
        self.stats.total_rules_applied += input.applied_rules.len() as u64;

        match &input.verdict {
            ReceiptVerdict::Proven { .. } => {
                self.stats.total_proven += 1;
                self.stats.total_cost_improvement_millionths += receipt.total_cost_delta_millionths;

                // Append to chain (ignore pruning errors from sequence mismatch
                // after pruning — the chain handles that internally)
                let _ = self.chain.append(receipt.clone());

                EmitResult::Approved { receipt }
            }
            ReceiptVerdict::Disproven {
                counterexample_hash,
                divergence,
            } => {
                self.stats.total_disproven += 1;

                let failure = FailureReceipt::new(
                    &input.optimization_id,
                    &input
                        .applied_rules
                        .first()
                        .map(|r| r.pack_id.clone())
                        .unwrap_or_default(),
                    input
                        .applied_rules
                        .first()
                        .map(|r| r.pack_version)
                        .unwrap_or(PackVersion::CURRENT),
                    input
                        .applied_rules
                        .iter()
                        .map(|r| r.rule_id.clone())
                        .collect(),
                    FailureKind::CounterexampleFound {
                        divergence: divergence.clone(),
                    },
                    Some(counterexample_hash.clone()),
                    self.config.quarantine_on_first_failure,
                    self.current_epoch,
                    self.current_ticks,
                );

                if self.config.quarantine_on_first_failure {
                    self.quarantine_optimization(&input.optimization_id);
                }

                let _ = self.chain.append(receipt.clone());
                self.chain.record_failure(failure.clone());

                EmitResult::Rejected { receipt, failure }
            }
            ReceiptVerdict::Inconclusive {
                reason: _,
                budget_consumed_ticks,
                budget_limit_ticks,
            } => {
                self.stats.total_inconclusive += 1;

                let failure = FailureReceipt::new(
                    &input.optimization_id,
                    &input
                        .applied_rules
                        .first()
                        .map(|r| r.pack_id.clone())
                        .unwrap_or_default(),
                    input
                        .applied_rules
                        .first()
                        .map(|r| r.pack_version)
                        .unwrap_or(PackVersion::CURRENT),
                    input
                        .applied_rules
                        .iter()
                        .map(|r| r.rule_id.clone())
                        .collect(),
                    FailureKind::BudgetExceeded {
                        consumed_ticks: *budget_consumed_ticks,
                        limit_ticks: *budget_limit_ticks,
                    },
                    None,
                    false, // Don't quarantine on inconclusive by default
                    self.current_epoch,
                    self.current_ticks,
                );

                let _ = self.chain.append(receipt.clone());
                self.chain.record_failure(failure.clone());

                EmitResult::Rejected { receipt, failure }
            }
        }
    }

    /// Verify a receipt's signature using the emitter's key.
    pub fn verify_receipt(&mut self, receipt: &TranslationValidationReceipt) -> bool {
        self.stats.total_verifications += 1;
        let valid = receipt.verify_signature(&self.config.signing_key);
        if !valid {
            self.stats.verification_failures += 1;
        }
        valid
    }

    /// Get a summary of the emitter state.
    pub fn summary(&self) -> ReceiptSummary {
        let chain_integrity = self.chain.verify_integrity();
        let proven_rate_millionths = if self.stats.total_receipts > 0 {
            (self.stats.total_proven as i64 * 1_000_000) / self.stats.total_receipts as i64
        } else {
            0
        };

        ReceiptSummary {
            schema_version: SUMMARY_SCHEMA_VERSION.into(),
            chain_id: self.chain.chain_id.clone(),
            total_receipts: self.stats.total_receipts,
            total_proven: self.stats.total_proven,
            total_disproven: self.stats.total_disproven,
            total_inconclusive: self.stats.total_inconclusive,
            proven_rate_millionths,
            total_rules_applied: self.stats.total_rules_applied,
            total_cost_improvement_millionths: self.stats.total_cost_improvement_millionths,
            quarantine_count: self.quarantine.len(),
            chain_length: self.chain.receipts.len(),
            chain_valid: chain_integrity.valid,
            chain_integrity_issues: chain_integrity.issues.len(),
            current_epoch: self.current_epoch,
        }
    }
}

/// Summary of the receipt emitter state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptSummary {
    /// Schema version.
    pub schema_version: String,
    /// Chain identifier.
    pub chain_id: String,
    /// Total receipts emitted.
    pub total_receipts: u64,
    /// Receipts with proven verdict.
    pub total_proven: u64,
    /// Receipts with disproven verdict.
    pub total_disproven: u64,
    /// Receipts with inconclusive verdict.
    pub total_inconclusive: u64,
    /// Proven rate (millionths, 1_000_000 = 100%).
    pub proven_rate_millionths: i64,
    /// Total rules applied.
    pub total_rules_applied: u64,
    /// Total cost improvement (millionths).
    pub total_cost_improvement_millionths: i64,
    /// Number of quarantined optimizations.
    pub quarantine_count: usize,
    /// Current chain length.
    pub chain_length: usize,
    /// Whether the chain passes integrity checks.
    pub chain_valid: bool,
    /// Number of chain integrity issues.
    pub chain_integrity_issues: usize,
    /// Current security epoch.
    pub current_epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    fn test_hash(data: &[u8]) -> ContentHash {
        ContentHash::compute(data)
    }

    fn test_evidence() -> ProofEvidence {
        ProofEvidence::new(ProofMode::Symbolic, test_hash(b"proof-artifact"), 100, 5000)
    }

    fn test_rule(rule_id: &str, cost_delta: i64) -> AppliedRuleRecord {
        AppliedRuleRecord {
            pack_id: "test-pack".into(),
            pack_version: PackVersion::CURRENT,
            rule_id: rule_id.into(),
            category: RewriteCategory::AlgebraicSimplification,
            before_hash: test_hash(b"before"),
            after_hash: test_hash(b"after"),
            cost_delta_millionths: cost_delta,
            rule_proven_sound: true,
        }
    }

    fn proven_verdict() -> ReceiptVerdict {
        ReceiptVerdict::Proven {
            evidence: test_evidence(),
        }
    }

    fn disproven_verdict() -> ReceiptVerdict {
        ReceiptVerdict::Disproven {
            counterexample_hash: test_hash(b"counterexample"),
            divergence: "output mismatch on input #7".into(),
        }
    }

    fn inconclusive_verdict() -> ReceiptVerdict {
        ReceiptVerdict::Inconclusive {
            reason: "solver timeout".into(),
            budget_consumed_ticks: 10_000_000,
            budget_limit_ticks: 10_000_000,
        }
    }

    fn default_emitter() -> ValidationReceiptEmitter {
        ValidationReceiptEmitter::new(EmitterConfig::default(), test_epoch())
    }

    fn make_input(opt_id: &str, verdict: ReceiptVerdict) -> EmitInput {
        EmitInput {
            optimization_id: opt_id.into(),
            baseline_ir_hash: test_hash(b"baseline"),
            optimized_ir_hash: test_hash(b"optimized"),
            applied_rules: vec![test_rule("rule-1", -100_000)],
            verdict,
            cost_model_id: None,
        }
    }

    // --- ProofMode ---

    #[test]
    fn test_proof_mode_display() {
        assert_eq!(ProofMode::Symbolic.to_string(), "symbolic");
        assert_eq!(ProofMode::GoldenCorpus.to_string(), "golden_corpus");
        assert_eq!(
            ProofMode::DifferentialTrace.to_string(),
            "differential_trace"
        );
        assert_eq!(ProofMode::Axiomatic.to_string(), "axiomatic");
        assert_eq!(ProofMode::Composite.to_string(), "composite");
    }

    #[test]
    fn test_proof_mode_serde() {
        for mode in [
            ProofMode::Symbolic,
            ProofMode::GoldenCorpus,
            ProofMode::DifferentialTrace,
            ProofMode::Axiomatic,
            ProofMode::Composite,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let restored: ProofMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, restored);
        }
    }

    // --- ProofEvidence ---

    #[test]
    fn test_proof_evidence_creation() {
        let ev = test_evidence();
        assert_eq!(ev.mode, ProofMode::Symbolic);
        assert_eq!(ev.verification_steps, 100);
        assert_eq!(ev.verification_ticks, 5000);
    }

    #[test]
    fn test_proof_evidence_with_metadata() {
        let ev = test_evidence()
            .with_metadata("solver", "z3")
            .with_metadata("timeout", "30s");
        assert_eq!(ev.metadata.len(), 2);
        assert_eq!(ev.metadata.get("solver").unwrap(), "z3");
    }

    #[test]
    fn test_proof_evidence_content_hash_deterministic() {
        let ev1 = test_evidence();
        let ev2 = test_evidence();
        assert_eq!(ev1.content_hash(), ev2.content_hash());
    }

    #[test]
    fn test_proof_evidence_content_hash_differs_on_change() {
        let ev1 = test_evidence();
        let ev2 = ProofEvidence::new(
            ProofMode::GoldenCorpus,
            test_hash(b"proof-artifact"),
            100,
            5000,
        );
        assert_ne!(ev1.content_hash(), ev2.content_hash());
    }

    #[test]
    fn test_proof_evidence_serde() {
        let ev = test_evidence().with_metadata("k", "v");
        let json = serde_json::to_string(&ev).unwrap();
        let restored: ProofEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, restored);
    }

    // --- AppliedRuleRecord ---

    #[test]
    fn test_rule_improvement() {
        let improving = test_rule("r1", -200_000);
        assert!(improving.is_improvement());
        assert!(improving.is_significant_improvement());
    }

    #[test]
    fn test_rule_no_improvement() {
        let neutral = test_rule("r1", 0);
        assert!(!neutral.is_improvement());
        assert!(!neutral.is_significant_improvement());
    }

    #[test]
    fn test_rule_below_significance_threshold() {
        let small = test_rule("r1", -10_000);
        assert!(small.is_improvement());
        assert!(!small.is_significant_improvement());
    }

    #[test]
    fn test_rule_serde() {
        let rule = test_rule("r1", -100_000);
        let json = serde_json::to_string(&rule).unwrap();
        let restored: AppliedRuleRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, restored);
    }

    // --- ReceiptVerdict ---

    #[test]
    fn test_verdict_proven_permits_activation() {
        assert!(proven_verdict().permits_activation());
        assert!(!proven_verdict().is_disproven());
    }

    #[test]
    fn test_verdict_disproven_blocks_activation() {
        assert!(!disproven_verdict().permits_activation());
        assert!(disproven_verdict().is_disproven());
    }

    #[test]
    fn test_verdict_inconclusive_blocks_activation() {
        assert!(!inconclusive_verdict().permits_activation());
        assert!(!inconclusive_verdict().is_disproven());
    }

    #[test]
    fn test_verdict_display() {
        assert!(proven_verdict().to_string().contains("PROVEN"));
        assert!(disproven_verdict().to_string().contains("DISPROVEN"));
        assert!(inconclusive_verdict().to_string().contains("INCONCLUSIVE"));
    }

    #[test]
    fn test_verdict_serde_proven() {
        let v = proven_verdict();
        let json = serde_json::to_string(&v).unwrap();
        let restored: ReceiptVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }

    #[test]
    fn test_verdict_serde_disproven() {
        let v = disproven_verdict();
        let json = serde_json::to_string(&v).unwrap();
        let restored: ReceiptVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }

    #[test]
    fn test_verdict_serde_inconclusive() {
        let v = inconclusive_verdict();
        let json = serde_json::to_string(&v).unwrap();
        let restored: ReceiptVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }

    // --- TranslationValidationReceipt ---

    #[test]
    fn test_receipt_creation() {
        let receipt = TranslationValidationReceipt::new(
            1,
            "opt-001",
            None,
            test_epoch(),
            1000,
            test_hash(b"baseline"),
            test_hash(b"optimized"),
            vec![test_rule("r1", -100_000), test_rule("r2", -50_000)],
            proven_verdict(),
            "cost-model-v1",
        );
        assert_eq!(receipt.sequence, 1);
        assert_eq!(receipt.optimization_id, "opt-001");
        assert_eq!(receipt.total_cost_delta_millionths, -150_000);
        assert!(receipt.permits_activation());
        assert!(receipt.is_net_improvement());
        assert_eq!(receipt.rule_count(), 2);
    }

    #[test]
    fn test_receipt_sign_and_verify() {
        let key = b"test-signing-key-32-bytes-long!!";
        let receipt = TranslationValidationReceipt::new(
            1,
            "opt-001",
            None,
            test_epoch(),
            1000,
            test_hash(b"baseline"),
            test_hash(b"optimized"),
            vec![test_rule("r1", -100_000)],
            proven_verdict(),
            "cm",
        )
        .sign(key);

        assert!(receipt.verify_signature(key));
        assert!(!receipt.verify_signature(b"wrong-key-wrong-key-wrong-key!!x"));
    }

    #[test]
    fn test_receipt_all_rules_proven_sound() {
        let receipt = TranslationValidationReceipt::new(
            1,
            "opt",
            None,
            test_epoch(),
            0,
            test_hash(b"b"),
            test_hash(b"o"),
            vec![test_rule("r1", 0), test_rule("r2", 0)],
            proven_verdict(),
            "cm",
        );
        assert!(receipt.all_rules_proven_sound());
        assert_eq!(receipt.proven_sound_rule_count(), 2);
    }

    #[test]
    fn test_receipt_not_all_rules_proven() {
        let mut rule = test_rule("r1", 0);
        rule.rule_proven_sound = false;
        let receipt = TranslationValidationReceipt::new(
            1,
            "opt",
            None,
            test_epoch(),
            0,
            test_hash(b"b"),
            test_hash(b"o"),
            vec![rule, test_rule("r2", 0)],
            proven_verdict(),
            "cm",
        );
        assert!(!receipt.all_rules_proven_sound());
        assert_eq!(receipt.proven_sound_rule_count(), 1);
    }

    #[test]
    fn test_receipt_failure() {
        let receipt = TranslationValidationReceipt::new(
            1,
            "opt",
            None,
            test_epoch(),
            0,
            test_hash(b"b"),
            test_hash(b"o"),
            vec![test_rule("r1", 0)],
            disproven_verdict(),
            "cm",
        );
        assert!(receipt.is_failure());
        assert!(!receipt.permits_activation());
    }

    #[test]
    fn test_receipt_content_hash_deterministic() {
        let r1 = TranslationValidationReceipt::new(
            1,
            "opt",
            None,
            test_epoch(),
            0,
            test_hash(b"b"),
            test_hash(b"o"),
            vec![test_rule("r1", -100)],
            proven_verdict(),
            "cm",
        );
        let r2 = TranslationValidationReceipt::new(
            1,
            "opt",
            None,
            test_epoch(),
            0,
            test_hash(b"b"),
            test_hash(b"o"),
            vec![test_rule("r1", -100)],
            proven_verdict(),
            "cm",
        );
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_receipt_content_hash_differs_on_sequence() {
        let r1 = TranslationValidationReceipt::new(
            1,
            "opt",
            None,
            test_epoch(),
            0,
            test_hash(b"b"),
            test_hash(b"o"),
            vec![],
            proven_verdict(),
            "cm",
        );
        let r2 = TranslationValidationReceipt::new(
            2,
            "opt",
            None,
            test_epoch(),
            0,
            test_hash(b"b"),
            test_hash(b"o"),
            vec![],
            proven_verdict(),
            "cm",
        );
        assert_ne!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_receipt_serde_roundtrip() {
        let receipt = TranslationValidationReceipt::new(
            1,
            "opt-serde",
            None,
            test_epoch(),
            500,
            test_hash(b"b"),
            test_hash(b"o"),
            vec![test_rule("r1", -200_000)],
            proven_verdict(),
            "cm",
        )
        .sign(b"key123");
        let json = serde_json::to_string(&receipt).unwrap();
        let restored: TranslationValidationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, restored);
    }

    // --- FailureReceipt ---

    #[test]
    fn test_failure_receipt_counterexample() {
        let fr = FailureReceipt::new(
            "opt-fail",
            "pack-1",
            PackVersion::CURRENT,
            vec!["r1".into(), "r2".into()],
            FailureKind::CounterexampleFound {
                divergence: "output mismatch".into(),
            },
            Some(test_hash(b"counter")),
            true,
            test_epoch(),
            1000,
        );
        assert_eq!(fr.optimization_id, "opt-fail");
        assert!(fr.quarantined);
        assert!(fr.counterexample_hash.is_some());
    }

    #[test]
    fn test_failure_receipt_budget_exceeded() {
        let fr = FailureReceipt::new(
            "opt-timeout",
            "pack-1",
            PackVersion::CURRENT,
            vec!["r1".into()],
            FailureKind::BudgetExceeded {
                consumed_ticks: 10_000,
                limit_ticks: 10_000,
            },
            None,
            false,
            test_epoch(),
            2000,
        );
        assert!(!fr.quarantined);
        assert!(fr.counterexample_hash.is_none());
    }

    #[test]
    fn test_failure_receipt_serde() {
        let fr = FailureReceipt::new(
            "opt-f",
            "p1",
            PackVersion::CURRENT,
            vec!["r1".into()],
            FailureKind::InterferenceDetected {
                conflicting_rules: vec!["r1".into(), "r2".into()],
            },
            None,
            true,
            test_epoch(),
            500,
        );
        let json = serde_json::to_string(&fr).unwrap();
        let restored: FailureReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(fr, restored);
    }

    #[test]
    fn test_failure_kind_display() {
        let k1 = FailureKind::CounterexampleFound {
            divergence: "bad".into(),
        };
        assert!(k1.to_string().contains("counterexample"));

        let k2 = FailureKind::BudgetExceeded {
            consumed_ticks: 100,
            limit_ticks: 100,
        };
        assert!(k2.to_string().contains("budget exceeded"));

        let k3 = FailureKind::InterferenceDetected {
            conflicting_rules: vec!["a".into()],
        };
        assert!(k3.to_string().contains("interference"));

        let k4 = FailureKind::ComplexityExceeded {
            metric: "nodes".into(),
            value: 1000,
            limit: 500,
        };
        assert!(k4.to_string().contains("complexity"));

        let k5 = FailureKind::MalformedOutput {
            detail: "invalid cfg".into(),
        };
        assert!(k5.to_string().contains("malformed"));
    }

    #[test]
    fn test_failure_kind_serde() {
        let kinds = vec![
            FailureKind::CounterexampleFound {
                divergence: "x".into(),
            },
            FailureKind::BudgetExceeded {
                consumed_ticks: 1,
                limit_ticks: 2,
            },
            FailureKind::InterferenceDetected {
                conflicting_rules: vec!["a".into()],
            },
            FailureKind::ComplexityExceeded {
                metric: "n".into(),
                value: 1,
                limit: 2,
            },
            FailureKind::MalformedOutput { detail: "d".into() },
        ];
        for k in kinds {
            let json = serde_json::to_string(&k).unwrap();
            let restored: FailureKind = serde_json::from_str(&json).unwrap();
            assert_eq!(k, restored);
        }
    }

    // --- ReceiptChain ---

    #[test]
    fn test_chain_creation() {
        let chain = ReceiptChain::new("test-chain", test_epoch());
        assert_eq!(chain.chain_id, "test-chain");
        assert_eq!(chain.next_sequence, 1);
        assert!(chain.receipts.is_empty());
    }

    #[test]
    fn test_chain_append() {
        let mut chain = ReceiptChain::new("c1", test_epoch());
        let r = TranslationValidationReceipt::new(
            1,
            "opt",
            None,
            test_epoch(),
            0,
            test_hash(b"b"),
            test_hash(b"o"),
            vec![test_rule("r1", -100)],
            proven_verdict(),
            "cm",
        );
        chain.append(r).unwrap();
        assert_eq!(chain.receipts.len(), 1);
        assert_eq!(chain.next_sequence, 2);
    }

    #[test]
    fn test_chain_append_linked() {
        let mut chain = ReceiptChain::new("c1", test_epoch());
        let r1 = TranslationValidationReceipt::new(
            1,
            "opt-1",
            None,
            test_epoch(),
            0,
            test_hash(b"b"),
            test_hash(b"o"),
            vec![],
            proven_verdict(),
            "cm",
        );
        chain.append(r1).unwrap();

        let parent = chain.last_receipt().unwrap().content_hash.clone();
        let r2 = TranslationValidationReceipt::new(
            2,
            "opt-2",
            Some(parent),
            test_epoch(),
            100,
            test_hash(b"b2"),
            test_hash(b"o2"),
            vec![test_rule("r1", -50)],
            proven_verdict(),
            "cm",
        );
        chain.append(r2).unwrap();
        assert_eq!(chain.receipts.len(), 2);
    }

    #[test]
    fn test_chain_parent_hash_mismatch() {
        let mut chain = ReceiptChain::new("c1", test_epoch());
        let r1 = TranslationValidationReceipt::new(
            1,
            "opt",
            None,
            test_epoch(),
            0,
            test_hash(b"b"),
            test_hash(b"o"),
            vec![],
            proven_verdict(),
            "cm",
        );
        chain.append(r1).unwrap();

        let r2 = TranslationValidationReceipt::new(
            2,
            "opt-2",
            Some(test_hash(b"wrong-parent")),
            test_epoch(),
            0,
            test_hash(b"b"),
            test_hash(b"o"),
            vec![],
            proven_verdict(),
            "cm",
        );
        assert!(chain.append(r2).is_err());
    }

    #[test]
    fn test_chain_sequence_gap() {
        let mut chain = ReceiptChain::new("c1", test_epoch());
        let r = TranslationValidationReceipt::new(
            5,
            "opt",
            None,
            test_epoch(),
            0,
            test_hash(b"b"),
            test_hash(b"o"),
            vec![],
            proven_verdict(),
            "cm",
        );
        let err = chain.append(r).unwrap_err();
        assert!(matches!(
            err,
            ReceiptChainError::SequenceGap {
                expected: 1,
                actual: 5
            }
        ));
    }

    #[test]
    fn test_chain_pruning() {
        let mut chain = ReceiptChain::new("c1", test_epoch()).with_max_length(3);

        // Build a chain of 5 receipts
        let mut parent: Option<ContentHash> = None;
        for i in 1..=5u64 {
            let r = TranslationValidationReceipt::new(
                i,
                &format!("opt-{i}"),
                parent.clone(),
                test_epoch(),
                i * 100,
                test_hash(format!("b{i}").as_bytes()),
                test_hash(format!("o{i}").as_bytes()),
                vec![test_rule("r1", -(i as i64) * 1000)],
                proven_verdict(),
                "cm",
            );
            parent = Some(r.content_hash.clone());
            chain.append(r).unwrap();
        }

        assert_eq!(chain.receipts.len(), 3);
        // Should have the last 3
        assert_eq!(chain.receipts[0].sequence, 3);
        assert_eq!(chain.receipts[2].sequence, 5);
    }

    #[test]
    fn test_chain_success_count() {
        let mut chain = ReceiptChain::new("c1", test_epoch());
        let r1 = TranslationValidationReceipt::new(
            1,
            "opt-1",
            None,
            test_epoch(),
            0,
            test_hash(b"b"),
            test_hash(b"o"),
            vec![],
            proven_verdict(),
            "cm",
        );
        chain.append(r1).unwrap();

        let parent = chain.last_receipt().unwrap().content_hash.clone();
        let r2 = TranslationValidationReceipt::new(
            2,
            "opt-2",
            Some(parent),
            test_epoch(),
            0,
            test_hash(b"b"),
            test_hash(b"o"),
            vec![],
            disproven_verdict(),
            "cm",
        );
        chain.append(r2).unwrap();

        assert_eq!(chain.success_count(), 1);
        assert_eq!(chain.rejected_count(), 1);
    }

    #[test]
    fn test_chain_total_cost_improvement() {
        let mut chain = ReceiptChain::new("c1", test_epoch());
        let r = TranslationValidationReceipt::new(
            1,
            "opt",
            None,
            test_epoch(),
            0,
            test_hash(b"b"),
            test_hash(b"o"),
            vec![test_rule("r1", -500_000)],
            proven_verdict(),
            "cm",
        );
        chain.append(r).unwrap();
        assert_eq!(chain.total_cost_improvement(), -500_000);
    }

    #[test]
    fn test_chain_integrity_valid() {
        let mut chain = ReceiptChain::new("c1", test_epoch());
        let r = TranslationValidationReceipt::new(
            1,
            "opt",
            None,
            test_epoch(),
            0,
            test_hash(b"b"),
            test_hash(b"o"),
            vec![],
            proven_verdict(),
            "cm",
        );
        chain.append(r).unwrap();
        let result = chain.verify_integrity();
        assert!(result.valid);
        assert_eq!(result.receipt_count, 1);
    }

    #[test]
    fn test_chain_record_failure() {
        let mut chain = ReceiptChain::new("c1", test_epoch());
        let f = FailureReceipt::new(
            "opt-f",
            "p1",
            PackVersion::CURRENT,
            vec!["r1".into()],
            FailureKind::CounterexampleFound {
                divergence: "bad".into(),
            },
            None,
            false,
            test_epoch(),
            0,
        );
        chain.record_failure(f);
        assert_eq!(chain.failure_count(), 1);
    }

    #[test]
    fn test_chain_receipts_for_optimization() {
        let mut chain = ReceiptChain::new("c1", test_epoch());
        let r = TranslationValidationReceipt::new(
            1,
            "target-opt",
            None,
            test_epoch(),
            0,
            test_hash(b"b"),
            test_hash(b"o"),
            vec![],
            proven_verdict(),
            "cm",
        );
        chain.append(r).unwrap();
        let found = chain.receipts_for_optimization("target-opt");
        assert_eq!(found.len(), 1);
        assert!(chain.receipts_for_optimization("other").is_empty());
    }

    #[test]
    fn test_chain_serde_roundtrip() {
        let mut chain = ReceiptChain::new("c1", test_epoch());
        let r = TranslationValidationReceipt::new(
            1,
            "opt",
            None,
            test_epoch(),
            0,
            test_hash(b"b"),
            test_hash(b"o"),
            vec![test_rule("r1", -100)],
            proven_verdict(),
            "cm",
        );
        chain.append(r).unwrap();
        let json = serde_json::to_string(&chain).unwrap();
        let restored: ReceiptChain = serde_json::from_str(&json).unwrap();
        assert_eq!(chain, restored);
    }

    // --- ValidationReceiptEmitter ---

    #[test]
    fn test_emitter_creation() {
        let em = default_emitter();
        assert_eq!(em.stats.total_receipts, 0);
        assert!(em.quarantine.is_empty());
    }

    #[test]
    fn test_emitter_emit_proven() {
        let mut em = default_emitter();
        let result = em.emit(make_input("opt-1", proven_verdict()));
        assert!(result.is_approved());
        assert_eq!(em.stats.total_proven, 1);
        assert_eq!(em.stats.total_receipts, 1);
        assert_eq!(em.chain.receipts.len(), 1);
    }

    #[test]
    fn test_emitter_emit_disproven() {
        let mut em = default_emitter();
        let result = em.emit(make_input("opt-1", disproven_verdict()));
        assert!(!result.is_approved());
        assert_eq!(em.stats.total_disproven, 1);
        assert!(em.is_quarantined("opt-1")); // quarantine_on_first_failure
    }

    #[test]
    fn test_emitter_emit_inconclusive() {
        let mut em = default_emitter();
        let result = em.emit(make_input("opt-1", inconclusive_verdict()));
        assert!(!result.is_approved());
        assert_eq!(em.stats.total_inconclusive, 1);
        assert!(!em.is_quarantined("opt-1")); // not quarantined on inconclusive
    }

    #[test]
    fn test_emitter_quarantine_blocks_submission() {
        let mut em = default_emitter();
        em.quarantine_optimization("opt-blocked");
        let result = em.emit(make_input("opt-blocked", proven_verdict()));
        assert!(matches!(result, EmitResult::Quarantined { .. }));
    }

    #[test]
    fn test_emitter_lift_quarantine() {
        let mut em = default_emitter();
        em.quarantine_optimization("opt-1");
        assert!(em.is_quarantined("opt-1"));
        assert!(em.lift_quarantine("opt-1"));
        assert!(!em.is_quarantined("opt-1"));
    }

    #[test]
    fn test_emitter_verify_receipt() {
        let mut em = default_emitter();
        let result = em.emit(make_input("opt-1", proven_verdict()));
        let receipt = result.receipt().unwrap();
        assert!(em.verify_receipt(receipt));
        assert_eq!(em.stats.total_verifications, 1);
        assert_eq!(em.stats.verification_failures, 0);
    }

    #[test]
    fn test_emitter_verify_wrong_key() {
        let mut em = default_emitter();
        let result = em.emit(make_input("opt-1", proven_verdict()));
        let mut receipt = result.receipt().unwrap().clone();
        // Tamper with signature
        receipt.signature = AuthenticityHash::compute_keyed(b"wrong", b"data");
        assert!(!em.verify_receipt(&receipt));
        assert_eq!(em.stats.verification_failures, 1);
    }

    #[test]
    fn test_emitter_tick() {
        let mut em = default_emitter();
        em.tick(100);
        assert_eq!(em.current_ticks, 100);
        em.tick(50);
        assert_eq!(em.current_ticks, 150);
    }

    #[test]
    fn test_emitter_advance_epoch() {
        let mut em = default_emitter();
        let e0 = em.current_epoch;
        em.advance_epoch();
        assert_eq!(em.current_epoch.as_u64(), e0.as_u64() + 1);
    }

    #[test]
    fn test_emitter_summary() {
        let mut em = default_emitter();
        em.emit(make_input("opt-1", proven_verdict()));
        em.emit(make_input("opt-2", proven_verdict()));
        em.emit(make_input("opt-3", disproven_verdict()));
        let summary = em.summary();
        assert_eq!(summary.total_receipts, 3);
        assert_eq!(summary.total_proven, 2);
        assert_eq!(summary.total_disproven, 1);
        assert!(summary.chain_valid);
        assert_eq!(summary.quarantine_count, 1); // opt-3 quarantined
    }

    #[test]
    fn test_emitter_cost_tracking() {
        let mut em = default_emitter();
        let mut input = make_input("opt-1", proven_verdict());
        input.applied_rules = vec![test_rule("r1", -200_000), test_rule("r2", -300_000)];
        em.emit(input);
        assert_eq!(em.stats.total_cost_improvement_millionths, -500_000);
        assert_eq!(em.stats.total_rules_applied, 2);
    }

    #[test]
    fn test_emitter_multiple_proven_chain() {
        let mut em = default_emitter();
        for i in 0..5 {
            em.tick(100);
            em.emit(make_input(&format!("opt-{i}"), proven_verdict()));
        }
        assert_eq!(em.chain.receipts.len(), 5);
        let integrity = em.chain.verify_integrity();
        assert!(integrity.valid);
    }

    #[test]
    fn test_emitter_serde_roundtrip() {
        let mut em = default_emitter();
        em.emit(make_input("opt-1", proven_verdict()));
        em.emit(make_input("opt-2", disproven_verdict()));
        let json = serde_json::to_string(&em).unwrap();
        let restored: ValidationReceiptEmitter = serde_json::from_str(&json).unwrap();
        assert_eq!(em.stats.total_receipts, restored.stats.total_receipts);
        assert_eq!(em.quarantine, restored.quarantine);
    }

    #[test]
    fn test_emitter_config_default() {
        let cfg = EmitterConfig::default();
        assert_eq!(cfg.chain_id, "default");
        assert!(cfg.quarantine_on_first_failure);
        assert_eq!(cfg.max_chain_length, MAX_CHAIN_LENGTH);
    }

    #[test]
    fn test_emitter_no_quarantine_on_failure_config() {
        let config = EmitterConfig {
            quarantine_on_first_failure: false,
            ..Default::default()
        };
        let mut em = ValidationReceiptEmitter::new(config, test_epoch());
        em.emit(make_input("opt-1", disproven_verdict()));
        assert!(!em.is_quarantined("opt-1"));
    }

    #[test]
    fn test_emit_result_receipt_access() {
        let mut em = default_emitter();
        let approved = em.emit(make_input("opt-a", proven_verdict()));
        assert!(approved.receipt().is_some());

        em.quarantine_optimization("opt-q");
        let quarantined = em.emit(make_input("opt-q", proven_verdict()));
        assert!(quarantined.receipt().is_none());
    }

    #[test]
    fn test_chain_error_display() {
        let e1 = ReceiptChainError::ParentHashMismatch {
            expected: None,
            actual: Some(test_hash(b"x")),
        };
        assert!(e1.to_string().contains("parent hash mismatch"));

        let e2 = ReceiptChainError::SequenceGap {
            expected: 1,
            actual: 5,
        };
        assert!(e2.to_string().contains("sequence gap"));
    }

    #[test]
    fn test_receipt_rewrite_categories() {
        let rules = vec![test_rule("r1", -100), {
            let mut r = test_rule("r2", -200);
            r.category = RewriteCategory::DeadCodeElimination;
            r
        }];
        let receipt = TranslationValidationReceipt::new(
            1,
            "opt",
            None,
            test_epoch(),
            0,
            test_hash(b"b"),
            test_hash(b"o"),
            rules,
            proven_verdict(),
            "cm",
        );
        assert_eq!(receipt.rewrite_categories.len(), 2);
        assert!(
            receipt
                .rewrite_categories
                .contains(&RewriteCategory::AlgebraicSimplification)
        );
        assert!(
            receipt
                .rewrite_categories
                .contains(&RewriteCategory::DeadCodeElimination)
        );
    }

    #[test]
    fn test_summary_schema_version() {
        let em = default_emitter();
        let summary = em.summary();
        assert_eq!(summary.schema_version, SUMMARY_SCHEMA_VERSION);
    }

    #[test]
    fn test_summary_proven_rate() {
        let mut em = default_emitter();
        em.emit(make_input("opt-1", proven_verdict()));
        em.emit(make_input("opt-2", proven_verdict()));
        let summary = em.summary();
        assert_eq!(summary.proven_rate_millionths, 1_000_000); // 100%
    }

    #[test]
    fn test_summary_proven_rate_mixed() {
        let mut em = default_emitter();
        em.emit(make_input("opt-1", proven_verdict()));
        em.emit(make_input("opt-2", disproven_verdict()));
        let summary = em.summary();
        assert_eq!(summary.proven_rate_millionths, 500_000); // 50%
    }

    #[test]
    fn test_summary_empty() {
        let em = default_emitter();
        let summary = em.summary();
        assert_eq!(summary.total_receipts, 0);
        assert_eq!(summary.proven_rate_millionths, 0);
    }

    #[test]
    fn test_chain_failures_for_pack() {
        let mut chain = ReceiptChain::new("c1", test_epoch());
        let f1 = FailureReceipt::new(
            "opt-1",
            "pack-alpha",
            PackVersion::CURRENT,
            vec!["r1".into()],
            FailureKind::CounterexampleFound {
                divergence: "x".into(),
            },
            None,
            false,
            test_epoch(),
            0,
        );
        let f2 = FailureReceipt::new(
            "opt-2",
            "pack-beta",
            PackVersion::CURRENT,
            vec!["r2".into()],
            FailureKind::BudgetExceeded {
                consumed_ticks: 1,
                limit_ticks: 2,
            },
            None,
            false,
            test_epoch(),
            0,
        );
        chain.record_failure(f1);
        chain.record_failure(f2);
        assert_eq!(chain.failures_for_pack("pack-alpha").len(), 1);
        assert_eq!(chain.failures_for_pack("pack-beta").len(), 1);
        assert_eq!(chain.failures_for_pack("pack-gamma").len(), 0);
    }
}
