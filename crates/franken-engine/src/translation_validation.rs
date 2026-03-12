//! Translation-validation gate for adaptive optimization paths.
//!
//! Sits between the optimizer's candidate transform proposal and activation.
//! Every adaptive optimization path passes through this gate, which verifies
//! semantic equivalence between baseline and optimized IR.  On failure the
//! gate triggers fail-closed rollback to baseline execution.
//!
//! Plan references: Section 10.12 item 2, 9H.1 (Proof-Carrying Adaptive
//! Optimizer), 9F.1 (Verified Adaptive Compiler).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::proof_schema::{ActivationStage, OptReceipt, RollbackToken};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// ValidationMode — strategy for equivalence checking
// ---------------------------------------------------------------------------

/// Strategy used for translation-validation checking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationMode {
    /// Re-execute baseline and candidate over golden test vectors;
    /// compare observable outputs bit-for-bit.
    GoldenCorpusReplay {
        /// Hash of the golden test corpus.
        corpus_hash: ContentHash,
        /// Number of test vectors in the corpus.
        vector_count: u64,
    },
    /// Prove equivalence via symbolic analysis of IR transformation.
    SymbolicEquivalence {
        /// Hash of the proof artifact.
        proof_hash: ContentHash,
    },
    /// Compare execution traces (hostcall sequences, side-effect ordering)
    /// across representative workloads.
    DifferentialTrace {
        /// Hash of the workload used for comparison.
        workload_hash: ContentHash,
        /// Number of trace pairs compared.
        trace_pair_count: u64,
    },
}

impl fmt::Display for ValidationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GoldenCorpusReplay { vector_count, .. } => {
                write!(f, "golden_corpus_replay({vector_count} vectors)")
            }
            Self::SymbolicEquivalence { .. } => write!(f, "symbolic_equivalence"),
            Self::DifferentialTrace {
                trace_pair_count, ..
            } => write!(f, "differential_trace({trace_pair_count} pairs)"),
        }
    }
}

// ---------------------------------------------------------------------------
// ValidationVerdict — outcome of validation
// ---------------------------------------------------------------------------

/// Structured verdict from the translation-validation gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationVerdict {
    /// Semantic equivalence confirmed; activation may proceed.
    Pass {
        /// Mode used for validation.
        mode: ValidationMode,
        /// Hash of evidence supporting the pass verdict.
        evidence_hash: ContentHash,
    },
    /// Semantic divergence detected; fail-closed rollback required.
    Fail {
        /// Mode used for validation.
        mode: ValidationMode,
        /// Description of the divergence.
        divergence_reason: String,
        /// Hash of the counterexample fixture demonstrating divergence.
        counterexample_hash: ContentHash,
    },
    /// Equivalence could not be determined; fail-closed rollback required.
    Inconclusive {
        /// Mode attempted.
        mode: ValidationMode,
        /// Why the check was inconclusive.
        reason: String,
    },
}

impl ValidationVerdict {
    /// Whether this verdict permits activation.
    pub fn permits_activation(&self) -> bool {
        matches!(self, Self::Pass { .. })
    }
}

impl fmt::Display for ValidationVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass { mode, .. } => write!(f, "PASS ({mode})"),
            Self::Fail {
                mode,
                divergence_reason,
                ..
            } => write!(f, "FAIL ({mode}): {divergence_reason}"),
            Self::Inconclusive { mode, reason } => {
                write!(f, "INCONCLUSIVE ({mode}): {reason}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RollbackReceipt — audit artifact for fail-closed rollback
// ---------------------------------------------------------------------------

/// Signed receipt emitted when rollback is triggered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackReceipt {
    /// Rollback token ID consumed.
    pub rollback_token_id: String,
    /// Optimization ID being rolled back.
    pub optimization_id: String,
    /// Reason for the rollback.
    pub failure_reason: String,
    /// Hash of the counterexample that triggered rollback (if any).
    pub counterexample_hash: Option<ContentHash>,
    /// Hash of the restored baseline state.
    pub restoration_baseline_hash: ContentHash,
    /// Stage at which rollback occurred.
    pub rollback_from_stage: ActivationStage,
    /// Timestamp (deterministic ticks).
    pub timestamp_ticks: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Signature over the receipt.
    pub signature: AuthenticityHash,
}

impl RollbackReceipt {
    /// Compute the unsigned preimage for signing.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut pre = Vec::new();
        append_length_prefixed(&mut pre, self.rollback_token_id.as_bytes());
        append_length_prefixed(&mut pre, self.optimization_id.as_bytes());
        append_length_prefixed(&mut pre, self.failure_reason.as_bytes());
        if let Some(ref h) = self.counterexample_hash {
            pre.push(1);
            pre.extend_from_slice(h.as_bytes());
        } else {
            pre.push(0);
        }
        pre.extend_from_slice(self.restoration_baseline_hash.as_bytes());
        append_length_prefixed(&mut pre, self.rollback_from_stage.to_string().as_bytes());
        pre.extend_from_slice(&self.timestamp_ticks.to_be_bytes());
        pre.extend_from_slice(&self.epoch.as_u64().to_be_bytes());
        pre
    }

    /// Sign this receipt.
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
}

// ---------------------------------------------------------------------------
// StagePromotion — signed artifact for stage transitions
// ---------------------------------------------------------------------------

/// Signed record of an activation stage promotion or demotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagePromotion {
    /// Optimization ID.
    pub optimization_id: String,
    /// Stage being promoted from.
    pub from_stage: ActivationStage,
    /// Stage being promoted to.
    pub to_stage: ActivationStage,
    /// Evidence hash supporting the promotion decision.
    pub evidence_hash: ContentHash,
    /// Timestamp (deterministic ticks).
    pub timestamp_ticks: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Signature.
    pub signature: AuthenticityHash,
}

impl StagePromotion {
    /// Compute signing preimage.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut pre = Vec::new();
        append_length_prefixed(&mut pre, self.optimization_id.as_bytes());
        append_length_prefixed(&mut pre, self.from_stage.to_string().as_bytes());
        append_length_prefixed(&mut pre, self.to_stage.to_string().as_bytes());
        pre.extend_from_slice(self.evidence_hash.as_bytes());
        pre.extend_from_slice(&self.timestamp_ticks.to_be_bytes());
        pre.extend_from_slice(&self.epoch.as_u64().to_be_bytes());
        pre
    }

    /// Sign this record.
    pub fn sign(mut self, key: &[u8]) -> Self {
        let preimage = self.signing_preimage();
        self.signature = AuthenticityHash::compute_keyed(key, &preimage);
        self
    }

    /// Verify signature.
    pub fn verify_signature(&self, key: &[u8]) -> bool {
        let preimage = self.signing_preimage();
        let expected = AuthenticityHash::compute_keyed(key, &preimage);
        self.signature == expected
    }
}

// ---------------------------------------------------------------------------
// QuarantineEntry — record of a quarantined optimization
// ---------------------------------------------------------------------------

/// A quarantined optimization that cannot re-enter validation without
/// new evidence or explicit policy override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// Optimization ID.
    pub optimization_id: String,
    /// Reason for quarantine.
    pub reason: String,
    /// Counterexample hash (if divergence was detected).
    pub counterexample_hash: Option<ContentHash>,
    /// Epoch when quarantined.
    pub quarantined_epoch: SecurityEpoch,
    /// Timestamp when quarantined.
    pub quarantined_at_ticks: u64,
}

// ---------------------------------------------------------------------------
// ValidationGateError
// ---------------------------------------------------------------------------

/// Errors from the translation-validation gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationGateError {
    /// Receipt signature verification failed.
    InvalidReceiptSignature { optimization_id: String },
    /// Rollback token signature verification failed.
    InvalidTokenSignature { token_id: String },
    /// Rollback token has expired.
    TokenExpired {
        token_id: String,
        expiry_epoch: u64,
        current_epoch: u64,
    },
    /// Token and receipt optimization IDs do not match.
    TokenReceiptMismatch {
        token_optimization_id: String,
        receipt_optimization_id: String,
    },
    /// Optimization is quarantined.
    Quarantined {
        optimization_id: String,
        reason: String,
    },
    /// Invalid stage transition attempted.
    InvalidStageTransition {
        from: ActivationStage,
        to: ActivationStage,
    },
    /// Optimization not found in the gate's tracking.
    OptimizationNotFound { optimization_id: String },
    /// Duplicate optimization submission.
    DuplicateSubmission { optimization_id: String },
    /// Validation verdict does not permit activation.
    ActivationDenied { verdict: String },
}

impl fmt::Display for ValidationGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidReceiptSignature { optimization_id } => {
                write!(f, "invalid receipt signature: {optimization_id}")
            }
            Self::InvalidTokenSignature { token_id } => {
                write!(f, "invalid token signature: {token_id}")
            }
            Self::TokenExpired {
                token_id,
                expiry_epoch,
                current_epoch,
            } => write!(
                f,
                "token {token_id} expired: expiry={expiry_epoch} current={current_epoch}"
            ),
            Self::TokenReceiptMismatch {
                token_optimization_id,
                receipt_optimization_id,
            } => write!(
                f,
                "token/receipt mismatch: token={token_optimization_id} receipt={receipt_optimization_id}"
            ),
            Self::Quarantined {
                optimization_id,
                reason,
            } => write!(f, "quarantined {optimization_id}: {reason}"),
            Self::InvalidStageTransition { from, to } => {
                write!(f, "invalid stage transition: {from} -> {to}")
            }
            Self::OptimizationNotFound { optimization_id } => {
                write!(f, "optimization not found: {optimization_id}")
            }
            Self::DuplicateSubmission { optimization_id } => {
                write!(f, "duplicate submission: {optimization_id}")
            }
            Self::ActivationDenied { verdict } => {
                write!(f, "activation denied: {verdict}")
            }
        }
    }
}

impl std::error::Error for ValidationGateError {}

// ---------------------------------------------------------------------------
// ValidationEvent — audit trail
// ---------------------------------------------------------------------------

/// Audit event from the translation-validation gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationEvent {
    /// Optimization ID.
    pub optimization_id: String,
    /// Event type.
    pub event_type: ValidationEventType,
    /// Timestamp (deterministic ticks).
    pub timestamp_ticks: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
}

/// Types of validation events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationEventType {
    /// Optimization submitted to gate.
    Submitted,
    /// Validation verdict rendered.
    Validated { verdict: String },
    /// Stage promoted.
    StagePromoted {
        from: ActivationStage,
        to: ActivationStage,
    },
    /// Stage demoted (rollback).
    StageDemoted {
        from: ActivationStage,
        to: ActivationStage,
    },
    /// Rollback executed.
    RolledBack { reason: String },
    /// Optimization quarantined.
    Quarantined { reason: String },
    /// Quarantine lifted by policy override.
    QuarantineLifted { override_reason: String },
}

// ---------------------------------------------------------------------------
// TrackedOptimization — internal state per optimization
// ---------------------------------------------------------------------------

/// Internal tracking state for an optimization in the gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TrackedOptimization {
    /// Optimization ID.
    optimization_id: String,
    /// Current activation stage.
    current_stage: ActivationStage,
    /// The receipt that initiated this optimization.
    receipt_optimization_class: String,
    /// Rollback token ID associated with this optimization.
    rollback_token_id: String,
    /// Hash of baseline for verification.
    baseline_hash: ContentHash,
    /// Validation verdicts for each stage.
    stage_verdicts: BTreeMap<String, ValidationVerdict>,
    /// Stage promotion history.
    promotions: Vec<StagePromotion>,
}

// ---------------------------------------------------------------------------
// TranslationValidationGate — the main gate
// ---------------------------------------------------------------------------

/// The translation-validation gate that controls optimizer activation.
///
/// Every adaptive optimization path must pass through this gate.
/// The gate verifies semantic equivalence, manages activation staging,
/// and triggers fail-closed rollback on validation failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationValidationGate {
    /// Tracked optimizations indexed by optimization_id.
    tracked: BTreeMap<String, TrackedOptimization>,
    /// Quarantined optimizations.
    quarantine: BTreeMap<String, QuarantineEntry>,
    /// Audit event log.
    events: Vec<ValidationEvent>,
    /// Rollback receipts emitted.
    rollback_receipts: Vec<RollbackReceipt>,
}

impl TranslationValidationGate {
    /// Create a new, empty gate.
    pub fn new() -> Self {
        Self {
            tracked: BTreeMap::new(),
            quarantine: BTreeMap::new(),
            events: Vec::new(),
            rollback_receipts: Vec::new(),
        }
    }

    /// Submit an optimization for validation.
    ///
    /// Verifies the receipt signature, checks quarantine status, and
    /// validates the rollback token.  On success, registers the
    /// optimization in shadow stage.
    pub fn submit(
        &mut self,
        receipt: &OptReceipt,
        token: &RollbackToken,
        signing_key: &[u8],
        current_epoch: SecurityEpoch,
        now_ticks: u64,
    ) -> Result<(), ValidationGateError> {
        let opt_id = &receipt.optimization_id;

        // Check quarantine.
        if let Some(entry) = self.quarantine.get(opt_id) {
            return Err(ValidationGateError::Quarantined {
                optimization_id: opt_id.clone(),
                reason: entry.reason.clone(),
            });
        }

        // Check duplicate.
        if self.tracked.contains_key(opt_id) {
            return Err(ValidationGateError::DuplicateSubmission {
                optimization_id: opt_id.clone(),
            });
        }

        // Verify receipt signature.
        if !receipt.verify_signature(signing_key) {
            return Err(ValidationGateError::InvalidReceiptSignature {
                optimization_id: opt_id.clone(),
            });
        }

        // Verify token signature.
        if !token.verify_signature(signing_key) {
            return Err(ValidationGateError::InvalidTokenSignature {
                token_id: token.token_id.clone(),
            });
        }

        // Check token expiry.
        if token.is_expired(current_epoch) {
            return Err(ValidationGateError::TokenExpired {
                token_id: token.token_id.clone(),
                expiry_epoch: token.expiry_epoch.as_u64(),
                current_epoch: current_epoch.as_u64(),
            });
        }

        // Check token-receipt match.
        if token.optimization_id != receipt.optimization_id {
            return Err(ValidationGateError::TokenReceiptMismatch {
                token_optimization_id: token.optimization_id.clone(),
                receipt_optimization_id: receipt.optimization_id.clone(),
            });
        }

        // Register in shadow stage.
        self.tracked.insert(
            opt_id.clone(),
            TrackedOptimization {
                optimization_id: opt_id.clone(),
                current_stage: ActivationStage::Shadow,
                receipt_optimization_class: receipt.optimization_class.to_string(),
                rollback_token_id: token.token_id.clone(),
                baseline_hash: receipt.baseline_ir_hash,
                stage_verdicts: BTreeMap::new(),
                promotions: Vec::new(),
            },
        );

        self.events.push(ValidationEvent {
            optimization_id: opt_id.clone(),
            event_type: ValidationEventType::Submitted,
            timestamp_ticks: now_ticks,
            epoch: current_epoch,
        });

        Ok(())
    }

    /// Record a validation verdict for an optimization at its current stage.
    ///
    /// If the verdict is not `Pass`, triggers fail-closed rollback.
    pub fn record_verdict(
        &mut self,
        optimization_id: &str,
        verdict: ValidationVerdict,
        signing_key: &[u8],
        current_epoch: SecurityEpoch,
        now_ticks: u64,
    ) -> Result<Option<RollbackReceipt>, ValidationGateError> {
        let tracked = self.tracked.get_mut(optimization_id).ok_or_else(|| {
            ValidationGateError::OptimizationNotFound {
                optimization_id: optimization_id.to_string(),
            }
        })?;

        let stage_key = tracked.current_stage.to_string();

        self.events.push(ValidationEvent {
            optimization_id: optimization_id.to_string(),
            event_type: ValidationEventType::Validated {
                verdict: verdict.to_string(),
            },
            timestamp_ticks: now_ticks,
            epoch: current_epoch,
        });

        tracked.stage_verdicts.insert(stage_key, verdict.clone());

        if verdict.permits_activation() {
            return Ok(None);
        }

        // Fail-closed: trigger rollback.
        let (failure_reason, counterexample_hash) = match &verdict {
            ValidationVerdict::Fail {
                divergence_reason,
                counterexample_hash,
                ..
            } => (divergence_reason.clone(), Some(*counterexample_hash)),
            ValidationVerdict::Inconclusive { reason, .. } => {
                (format!("inconclusive: {reason}"), None)
            }
            ValidationVerdict::Pass { .. } => unreachable!(),
        };

        let receipt = self.execute_rollback(
            optimization_id,
            &failure_reason,
            counterexample_hash,
            signing_key,
            current_epoch,
            now_ticks,
        )?;

        Ok(Some(receipt))
    }

    /// Promote an optimization to the next activation stage.
    ///
    /// Requires a passing verdict at the current stage.
    pub fn promote(
        &mut self,
        optimization_id: &str,
        evidence_hash: ContentHash,
        signing_key: &[u8],
        current_epoch: SecurityEpoch,
        now_ticks: u64,
    ) -> Result<StagePromotion, ValidationGateError> {
        let tracked = self.tracked.get_mut(optimization_id).ok_or_else(|| {
            ValidationGateError::OptimizationNotFound {
                optimization_id: optimization_id.to_string(),
            }
        })?;

        let current = tracked.current_stage;
        let next = next_stage(current).ok_or(ValidationGateError::InvalidStageTransition {
            from: current,
            to: current, // no valid next
        })?;

        // Verify current stage has a passing verdict.
        let stage_key = current.to_string();
        let has_pass = tracked
            .stage_verdicts
            .get(&stage_key)
            .is_some_and(|v| v.permits_activation());

        if !has_pass {
            return Err(ValidationGateError::ActivationDenied {
                verdict: format!("no passing verdict at stage {current}"),
            });
        }

        let promotion = StagePromotion {
            optimization_id: optimization_id.to_string(),
            from_stage: current,
            to_stage: next,
            evidence_hash,
            timestamp_ticks: now_ticks,
            epoch: current_epoch,
            signature: AuthenticityHash::compute_keyed(&[], &[]),
        }
        .sign(signing_key);

        tracked.current_stage = next;
        tracked.promotions.push(promotion.clone());

        self.events.push(ValidationEvent {
            optimization_id: optimization_id.to_string(),
            event_type: ValidationEventType::StagePromoted {
                from: current,
                to: next,
            },
            timestamp_ticks: now_ticks,
            epoch: current_epoch,
        });

        Ok(promotion)
    }

    /// Demote an optimization to a previous stage (deterministic rollback).
    pub fn demote(
        &mut self,
        optimization_id: &str,
        target_stage: ActivationStage,
        reason: &str,
        signing_key: &[u8],
        current_epoch: SecurityEpoch,
        now_ticks: u64,
    ) -> Result<StagePromotion, ValidationGateError> {
        let tracked = self.tracked.get_mut(optimization_id).ok_or_else(|| {
            ValidationGateError::OptimizationNotFound {
                optimization_id: optimization_id.to_string(),
            }
        })?;

        let current = tracked.current_stage;
        if target_stage >= current {
            return Err(ValidationGateError::InvalidStageTransition {
                from: current,
                to: target_stage,
            });
        }

        let demotion = StagePromotion {
            optimization_id: optimization_id.to_string(),
            from_stage: current,
            to_stage: target_stage,
            evidence_hash: ContentHash::compute(reason.as_bytes()),
            timestamp_ticks: now_ticks,
            epoch: current_epoch,
            signature: AuthenticityHash::compute_keyed(&[], &[]),
        }
        .sign(signing_key);

        tracked.current_stage = target_stage;
        tracked.promotions.push(demotion.clone());

        self.events.push(ValidationEvent {
            optimization_id: optimization_id.to_string(),
            event_type: ValidationEventType::StageDemoted {
                from: current,
                to: target_stage,
            },
            timestamp_ticks: now_ticks,
            epoch: current_epoch,
        });

        Ok(demotion)
    }

    /// Execute fail-closed rollback for an optimization.
    fn execute_rollback(
        &mut self,
        optimization_id: &str,
        failure_reason: &str,
        counterexample_hash: Option<ContentHash>,
        signing_key: &[u8],
        current_epoch: SecurityEpoch,
        now_ticks: u64,
    ) -> Result<RollbackReceipt, ValidationGateError> {
        let tracked = self.tracked.remove(optimization_id).ok_or_else(|| {
            ValidationGateError::OptimizationNotFound {
                optimization_id: optimization_id.to_string(),
            }
        })?;

        let receipt = RollbackReceipt {
            rollback_token_id: tracked.rollback_token_id.clone(),
            optimization_id: optimization_id.to_string(),
            failure_reason: failure_reason.to_string(),
            counterexample_hash,
            restoration_baseline_hash: tracked.baseline_hash,
            rollback_from_stage: tracked.current_stage,
            timestamp_ticks: now_ticks,
            epoch: current_epoch,
            signature: AuthenticityHash::compute_keyed(&[], &[]),
        }
        .sign(signing_key);

        // Quarantine the failed optimization.
        self.quarantine.insert(
            optimization_id.to_string(),
            QuarantineEntry {
                optimization_id: optimization_id.to_string(),
                reason: failure_reason.to_string(),
                counterexample_hash,
                quarantined_epoch: current_epoch,
                quarantined_at_ticks: now_ticks,
            },
        );

        self.events.push(ValidationEvent {
            optimization_id: optimization_id.to_string(),
            event_type: ValidationEventType::RolledBack {
                reason: failure_reason.to_string(),
            },
            timestamp_ticks: now_ticks,
            epoch: current_epoch,
        });

        self.rollback_receipts.push(receipt.clone());

        Ok(receipt)
    }

    /// Lift quarantine for an optimization (policy override).
    pub fn lift_quarantine(
        &mut self,
        optimization_id: &str,
        override_reason: &str,
        current_epoch: SecurityEpoch,
        now_ticks: u64,
    ) -> Result<(), ValidationGateError> {
        if self.quarantine.remove(optimization_id).is_none() {
            return Err(ValidationGateError::OptimizationNotFound {
                optimization_id: optimization_id.to_string(),
            });
        }

        self.events.push(ValidationEvent {
            optimization_id: optimization_id.to_string(),
            event_type: ValidationEventType::QuarantineLifted {
                override_reason: override_reason.to_string(),
            },
            timestamp_ticks: now_ticks,
            epoch: current_epoch,
        });

        Ok(())
    }

    // -- Queries --

    /// Get the current stage of a tracked optimization.
    pub fn current_stage(&self, optimization_id: &str) -> Option<ActivationStage> {
        self.tracked.get(optimization_id).map(|t| t.current_stage)
    }

    /// Check if an optimization is quarantined.
    pub fn is_quarantined(&self, optimization_id: &str) -> bool {
        self.quarantine.contains_key(optimization_id)
    }

    /// Get a quarantine entry.
    pub fn get_quarantine_entry(&self, optimization_id: &str) -> Option<&QuarantineEntry> {
        self.quarantine.get(optimization_id)
    }

    /// Number of actively tracked optimizations.
    pub fn tracked_count(&self) -> usize {
        self.tracked.len()
    }

    /// Number of quarantined optimizations.
    pub fn quarantine_count(&self) -> usize {
        self.quarantine.len()
    }

    /// All quarantined optimization IDs.
    pub fn quarantined_ids(&self) -> BTreeSet<String> {
        self.quarantine.keys().cloned().collect()
    }

    /// Get all audit events.
    pub fn events(&self) -> &[ValidationEvent] {
        &self.events
    }

    /// Get all rollback receipts.
    pub fn rollback_receipts(&self) -> &[RollbackReceipt] {
        &self.rollback_receipts
    }

    /// Total number of audit events.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Get promotion history for a tracked optimization.
    pub fn promotion_history(&self, optimization_id: &str) -> Vec<&StagePromotion> {
        self.tracked
            .get(optimization_id)
            .map(|t| t.promotions.iter().collect())
            .unwrap_or_default()
    }
}

impl Default for TranslationValidationGate {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Stage transition helpers
// ---------------------------------------------------------------------------

/// Get the next activation stage in the promotion chain.
fn next_stage(current: ActivationStage) -> Option<ActivationStage> {
    match current {
        ActivationStage::Shadow => Some(ActivationStage::Canary),
        ActivationStage::Canary => Some(ActivationStage::Ramp),
        ActivationStage::Ramp => Some(ActivationStage::Default),
        ActivationStage::Default => None,
    }
}

/// Length-prefixed append for deterministic serialization.
fn append_length_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_object_id::{self, ObjectDomain, SchemaId};
    use crate::proof_schema::{OptimizationClass, proof_schema_version_current};
    use std::collections::BTreeMap;

    const TEST_KEY: &[u8] = b"test-signing-key-32-bytes-long!!";

    fn test_receipt(opt_id: &str) -> OptReceipt {
        let mut compat = BTreeMap::new();
        compat.insert("engine_version".into(), "0.1.0".into());

        let signer_key_id = engine_object_id::derive_id(
            ObjectDomain::KeyBundle,
            "test-zone",
            &SchemaId::from_definition(b"test-signer"),
            b"key-material",
        )
        .unwrap();

        OptReceipt {
            schema_version: proof_schema_version_current(),
            optimization_id: opt_id.to_string(),
            optimization_class: OptimizationClass::Superinstruction,
            baseline_ir_hash: ContentHash::compute(b"baseline-ir"),
            candidate_ir_hash: ContentHash::compute(b"candidate-ir"),
            translation_witness_hash: ContentHash::compute(b"witness"),
            invariance_digest: ContentHash::compute(b"invariance"),
            rollback_token_id: format!("token-{opt_id}"),
            replay_compatibility: compat,
            policy_epoch: SecurityEpoch::from_raw(1),
            timestamp_ticks: 1000,
            signer_key_id,
            correlation_id: format!("corr-{opt_id}"),
            decision_impact: crate::tee_attestation_policy::DecisionImpact::Standard,
            attestation_bindings: None,
            signature: AuthenticityHash::compute_keyed(&[], &[]),
        }
        .sign(TEST_KEY)
    }

    fn test_token(opt_id: &str) -> RollbackToken {
        let issuer_key_id = engine_object_id::derive_id(
            ObjectDomain::KeyBundle,
            "test-zone",
            &SchemaId::from_definition(b"test-issuer"),
            b"issuer-material",
        )
        .unwrap();

        RollbackToken {
            schema_version: proof_schema_version_current(),
            token_id: format!("token-{opt_id}"),
            optimization_id: opt_id.to_string(),
            baseline_snapshot_hash: ContentHash::compute(b"baseline-snapshot"),
            activation_stage: ActivationStage::Shadow,
            expiry_epoch: SecurityEpoch::from_raw(100),
            issuer_key_id,
            issuer_signature: AuthenticityHash::compute_keyed(&[], &[]),
        }
        .sign(TEST_KEY)
    }

    fn pass_verdict() -> ValidationVerdict {
        ValidationVerdict::Pass {
            mode: ValidationMode::GoldenCorpusReplay {
                corpus_hash: ContentHash::compute(b"golden-corpus"),
                vector_count: 100,
            },
            evidence_hash: ContentHash::compute(b"evidence"),
        }
    }

    fn fail_verdict() -> ValidationVerdict {
        ValidationVerdict::Fail {
            mode: ValidationMode::DifferentialTrace {
                workload_hash: ContentHash::compute(b"workload"),
                trace_pair_count: 50,
            },
            divergence_reason: "hostcall sequence divergence at step 42".into(),
            counterexample_hash: ContentHash::compute(b"counterexample"),
        }
    }

    fn inconclusive_verdict() -> ValidationVerdict {
        ValidationVerdict::Inconclusive {
            mode: ValidationMode::SymbolicEquivalence {
                proof_hash: ContentHash::compute(b"proof"),
            },
            reason: "solver timeout after 30s".into(),
        }
    }

    // -- ValidationVerdict --

    #[test]
    fn verdict_pass_permits_activation() {
        assert!(pass_verdict().permits_activation());
    }

    #[test]
    fn verdict_fail_denies_activation() {
        assert!(!fail_verdict().permits_activation());
    }

    #[test]
    fn verdict_inconclusive_denies_activation() {
        assert!(!inconclusive_verdict().permits_activation());
    }

    #[test]
    fn verdict_display() {
        assert!(pass_verdict().to_string().contains("PASS"));
        assert!(fail_verdict().to_string().contains("FAIL"));
        assert!(inconclusive_verdict().to_string().contains("INCONCLUSIVE"));
    }

    #[test]
    fn verdict_serde_roundtrip() {
        for v in [pass_verdict(), fail_verdict(), inconclusive_verdict()] {
            let json = serde_json::to_string(&v).unwrap();
            let restored: ValidationVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(v, restored);
        }
    }

    // -- ValidationMode --

    #[test]
    fn validation_mode_display() {
        let golden = ValidationMode::GoldenCorpusReplay {
            corpus_hash: ContentHash::compute(b"c"),
            vector_count: 42,
        };
        assert!(golden.to_string().contains("42 vectors"));

        let sym = ValidationMode::SymbolicEquivalence {
            proof_hash: ContentHash::compute(b"p"),
        };
        assert!(sym.to_string().contains("symbolic"));

        let diff = ValidationMode::DifferentialTrace {
            workload_hash: ContentHash::compute(b"w"),
            trace_pair_count: 7,
        };
        assert!(diff.to_string().contains("7 pairs"));
    }

    #[test]
    fn validation_mode_serde_roundtrip() {
        let modes = vec![
            ValidationMode::GoldenCorpusReplay {
                corpus_hash: ContentHash::compute(b"c"),
                vector_count: 100,
            },
            ValidationMode::SymbolicEquivalence {
                proof_hash: ContentHash::compute(b"p"),
            },
            ValidationMode::DifferentialTrace {
                workload_hash: ContentHash::compute(b"w"),
                trace_pair_count: 50,
            },
        ];
        for m in &modes {
            let json = serde_json::to_string(m).unwrap();
            let restored: ValidationMode = serde_json::from_str(&json).unwrap();
            assert_eq!(*m, restored);
        }
    }

    // -- Submit --

    #[test]
    fn submit_registers_in_shadow() {
        let mut gate = TranslationValidationGate::new();
        let receipt = test_receipt("opt-1");
        let token = test_token("opt-1");
        let epoch = SecurityEpoch::from_raw(1);

        gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
            .unwrap();

        assert_eq!(gate.tracked_count(), 1);
        assert_eq!(gate.current_stage("opt-1"), Some(ActivationStage::Shadow));
        assert_eq!(gate.event_count(), 1);
    }

    #[test]
    fn submit_duplicate_rejected() {
        let mut gate = TranslationValidationGate::new();
        let receipt = test_receipt("opt-1");
        let token = test_token("opt-1");
        let epoch = SecurityEpoch::from_raw(1);

        gate.submit(&receipt, &token, TEST_KEY, epoch, 1000)
            .unwrap();
        assert!(matches!(
            gate.submit(&receipt, &token, TEST_KEY, epoch, 2000),
            Err(ValidationGateError::DuplicateSubmission { .. })
        ));
    }

    #[test]
    fn submit_quarantined_rejected() {
        let mut gate = TranslationValidationGate::new();
        let receipt = test_receipt("opt-1");
        let token = test_token("opt-1");
        let epoch = SecurityEpoch::from_raw(1);

        // Manually quarantine.
        gate.quarantine.insert(
            "opt-1".into(),
            QuarantineEntry {
                optimization_id: "opt-1".into(),
                reason: "previously failed".into(),
                counterexample_hash: None,
                quarantined_epoch: epoch,
                quarantined_at_ticks: 500,
            },
        );

        assert!(matches!(
            gate.submit(&receipt, &token, TEST_KEY, epoch, 1000),
            Err(ValidationGateError::Quarantined { .. })
        ));
    }

    #[test]
    fn submit_invalid_receipt_signature_rejected() {
        let mut gate = TranslationValidationGate::new();
        let receipt = test_receipt("opt-1");
        let token = test_token("opt-1");
        let epoch = SecurityEpoch::from_raw(1);

        assert!(matches!(
            gate.submit(
                &receipt,
                &token,
                b"wrong-key-material!!!!!!!!!!!!!!",
                epoch,
                1000
            ),
            Err(ValidationGateError::InvalidReceiptSignature { .. })
        ));
    }

    #[test]
    fn submit_expired_token_rejected() {
        let mut gate = TranslationValidationGate::new();
        let receipt = test_receipt("opt-1");
        let token = test_token("opt-1");
        let epoch = SecurityEpoch::from_raw(200); // past expiry of 100

        assert!(matches!(
            gate.submit(&receipt, &token, TEST_KEY, epoch, 1000),
            Err(ValidationGateError::TokenExpired { .. })
        ));
    }

    #[test]
    fn submit_mismatched_token_receipt_rejected() {
        let mut gate = TranslationValidationGate::new();
        let receipt = test_receipt("opt-1");
        let token = test_token("opt-2"); // different optimization_id
        let epoch = SecurityEpoch::from_raw(1);

        assert!(matches!(
            gate.submit(&receipt, &token, TEST_KEY, epoch, 1000),
            Err(ValidationGateError::TokenReceiptMismatch { .. })
        ));
    }

    // -- Record verdict --

    #[test]
    fn verdict_pass_does_not_trigger_rollback() {
        let mut gate = TranslationValidationGate::new();
        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            SecurityEpoch::from_raw(1),
            1000,
        )
        .unwrap();

        let result = gate
            .record_verdict(
                "opt-1",
                pass_verdict(),
                TEST_KEY,
                SecurityEpoch::from_raw(1),
                2000,
            )
            .unwrap();

        assert!(result.is_none());
        assert_eq!(gate.tracked_count(), 1);
        assert_eq!(gate.quarantine_count(), 0);
    }

    #[test]
    fn verdict_fail_triggers_rollback() {
        let mut gate = TranslationValidationGate::new();
        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            SecurityEpoch::from_raw(1),
            1000,
        )
        .unwrap();

        let result = gate
            .record_verdict(
                "opt-1",
                fail_verdict(),
                TEST_KEY,
                SecurityEpoch::from_raw(1),
                2000,
            )
            .unwrap();

        assert!(result.is_some());
        let receipt = result.unwrap();
        assert_eq!(receipt.optimization_id, "opt-1");
        assert!(receipt.counterexample_hash.is_some());
        assert!(receipt.verify_signature(TEST_KEY));

        // Optimization removed from tracking and quarantined.
        assert_eq!(gate.tracked_count(), 0);
        assert_eq!(gate.quarantine_count(), 1);
        assert!(gate.is_quarantined("opt-1"));
    }

    #[test]
    fn verdict_inconclusive_triggers_rollback() {
        let mut gate = TranslationValidationGate::new();
        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            SecurityEpoch::from_raw(1),
            1000,
        )
        .unwrap();

        let result = gate
            .record_verdict(
                "opt-1",
                inconclusive_verdict(),
                TEST_KEY,
                SecurityEpoch::from_raw(1),
                2000,
            )
            .unwrap();

        assert!(result.is_some());
        let receipt = result.unwrap();
        assert!(receipt.failure_reason.contains("inconclusive"));
        assert!(receipt.counterexample_hash.is_none());
    }

    #[test]
    fn verdict_for_unknown_optimization_fails() {
        let mut gate = TranslationValidationGate::new();
        assert!(matches!(
            gate.record_verdict(
                "nonexistent",
                pass_verdict(),
                TEST_KEY,
                SecurityEpoch::from_raw(1),
                1000
            ),
            Err(ValidationGateError::OptimizationNotFound { .. })
        ));
    }

    // -- Promote --

    #[test]
    fn promote_shadow_to_canary() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);
        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();
        gate.record_verdict("opt-1", pass_verdict(), TEST_KEY, epoch, 2000)
            .unwrap();

        let promotion = gate
            .promote(
                "opt-1",
                ContentHash::compute(b"canary-evidence"),
                TEST_KEY,
                epoch,
                3000,
            )
            .unwrap();

        assert_eq!(promotion.from_stage, ActivationStage::Shadow);
        assert_eq!(promotion.to_stage, ActivationStage::Canary);
        assert!(promotion.verify_signature(TEST_KEY));
        assert_eq!(gate.current_stage("opt-1"), Some(ActivationStage::Canary));
    }

    #[test]
    fn promote_full_chain_shadow_to_default() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);
        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();

        let stages = [
            (ActivationStage::Shadow, ActivationStage::Canary),
            (ActivationStage::Canary, ActivationStage::Ramp),
            (ActivationStage::Ramp, ActivationStage::Default),
        ];

        for (tick, (from, to)) in stages.iter().enumerate() {
            let t = (tick as u64 + 1) * 1000 + 1000;
            gate.record_verdict("opt-1", pass_verdict(), TEST_KEY, epoch, t)
                .unwrap();
            let p = gate
                .promote(
                    "opt-1",
                    ContentHash::compute(b"evidence"),
                    TEST_KEY,
                    epoch,
                    t + 500,
                )
                .unwrap();
            assert_eq!(p.from_stage, *from);
            assert_eq!(p.to_stage, *to);
        }

        assert_eq!(gate.current_stage("opt-1"), Some(ActivationStage::Default));
    }

    #[test]
    fn promote_without_pass_verdict_denied() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);
        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();

        // No verdict recorded, promotion should fail.
        assert!(matches!(
            gate.promote("opt-1", ContentHash::compute(b"ev"), TEST_KEY, epoch, 2000),
            Err(ValidationGateError::ActivationDenied { .. })
        ));
    }

    #[test]
    fn promote_from_default_fails() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);
        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();

        // Fast-forward to Default.
        for t in [2000u64, 3000, 4000] {
            gate.record_verdict("opt-1", pass_verdict(), TEST_KEY, epoch, t)
                .unwrap();
            gate.promote(
                "opt-1",
                ContentHash::compute(b"ev"),
                TEST_KEY,
                epoch,
                t + 100,
            )
            .unwrap();
        }

        // Now at Default, should fail.
        gate.record_verdict("opt-1", pass_verdict(), TEST_KEY, epoch, 5000)
            .unwrap();
        assert!(matches!(
            gate.promote("opt-1", ContentHash::compute(b"ev"), TEST_KEY, epoch, 5100),
            Err(ValidationGateError::InvalidStageTransition { .. })
        ));
    }

    // -- Demote --

    #[test]
    fn demote_canary_to_shadow() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);
        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();
        gate.record_verdict("opt-1", pass_verdict(), TEST_KEY, epoch, 2000)
            .unwrap();
        gate.promote("opt-1", ContentHash::compute(b"ev"), TEST_KEY, epoch, 3000)
            .unwrap();

        let demotion = gate
            .demote(
                "opt-1",
                ActivationStage::Shadow,
                "p99 regression",
                TEST_KEY,
                epoch,
                4000,
            )
            .unwrap();

        assert_eq!(demotion.from_stage, ActivationStage::Canary);
        assert_eq!(demotion.to_stage, ActivationStage::Shadow);
        assert!(demotion.verify_signature(TEST_KEY));
        assert_eq!(gate.current_stage("opt-1"), Some(ActivationStage::Shadow));
    }

    #[test]
    fn demote_to_same_or_higher_stage_fails() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);
        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();

        // At Shadow, cannot demote to Shadow or higher.
        assert!(matches!(
            gate.demote(
                "opt-1",
                ActivationStage::Shadow,
                "reason",
                TEST_KEY,
                epoch,
                2000
            ),
            Err(ValidationGateError::InvalidStageTransition { .. })
        ));
    }

    // -- Quarantine --

    #[test]
    fn quarantine_blocks_resubmission() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);

        // Submit and fail.
        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();
        gate.record_verdict("opt-1", fail_verdict(), TEST_KEY, epoch, 2000)
            .unwrap();

        // Try to resubmit.
        assert!(matches!(
            gate.submit(
                &test_receipt("opt-1"),
                &test_token("opt-1"),
                TEST_KEY,
                epoch,
                3000
            ),
            Err(ValidationGateError::Quarantined { .. })
        ));
    }

    #[test]
    fn lift_quarantine_allows_resubmission() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);

        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();
        gate.record_verdict("opt-1", fail_verdict(), TEST_KEY, epoch, 2000)
            .unwrap();

        assert!(gate.is_quarantined("opt-1"));

        gate.lift_quarantine("opt-1", "new evidence available", epoch, 3000)
            .unwrap();

        assert!(!gate.is_quarantined("opt-1"));

        // Now can resubmit.
        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            4000,
        )
        .unwrap();
        assert_eq!(gate.tracked_count(), 1);
    }

    #[test]
    fn lift_quarantine_for_unknown_fails() {
        let mut gate = TranslationValidationGate::new();
        assert!(matches!(
            gate.lift_quarantine("nonexistent", "reason", SecurityEpoch::from_raw(1), 1000),
            Err(ValidationGateError::OptimizationNotFound { .. })
        ));
    }

    // -- RollbackReceipt --

    #[test]
    fn rollback_receipt_signature_roundtrip() {
        let receipt = RollbackReceipt {
            rollback_token_id: "token-1".into(),
            optimization_id: "opt-1".into(),
            failure_reason: "divergence".into(),
            counterexample_hash: Some(ContentHash::compute(b"cx")),
            restoration_baseline_hash: ContentHash::compute(b"baseline"),
            rollback_from_stage: ActivationStage::Canary,
            timestamp_ticks: 5000,
            epoch: SecurityEpoch::from_raw(1),
            signature: AuthenticityHash::compute_keyed(&[], &[]),
        }
        .sign(TEST_KEY);

        assert!(receipt.verify_signature(TEST_KEY));
        assert!(!receipt.verify_signature(b"wrong-key-material!!!!!!!!!!!!!!")); // wrong key
    }

    #[test]
    fn rollback_receipt_serde_roundtrip() {
        let receipt = RollbackReceipt {
            rollback_token_id: "token-1".into(),
            optimization_id: "opt-1".into(),
            failure_reason: "test failure".into(),
            counterexample_hash: None,
            restoration_baseline_hash: ContentHash::compute(b"baseline"),
            rollback_from_stage: ActivationStage::Shadow,
            timestamp_ticks: 1000,
            epoch: SecurityEpoch::from_raw(1),
            signature: AuthenticityHash::compute_keyed(&[], &[]),
        }
        .sign(TEST_KEY);

        let json = serde_json::to_string(&receipt).unwrap();
        let restored: RollbackReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, restored);
    }

    // -- StagePromotion --

    #[test]
    fn stage_promotion_signature_roundtrip() {
        let promo = StagePromotion {
            optimization_id: "opt-1".into(),
            from_stage: ActivationStage::Shadow,
            to_stage: ActivationStage::Canary,
            evidence_hash: ContentHash::compute(b"evidence"),
            timestamp_ticks: 3000,
            epoch: SecurityEpoch::from_raw(1),
            signature: AuthenticityHash::compute_keyed(&[], &[]),
        }
        .sign(TEST_KEY);

        assert!(promo.verify_signature(TEST_KEY));
    }

    #[test]
    fn stage_promotion_serde_roundtrip() {
        let promo = StagePromotion {
            optimization_id: "opt-1".into(),
            from_stage: ActivationStage::Canary,
            to_stage: ActivationStage::Ramp,
            evidence_hash: ContentHash::compute(b"ev"),
            timestamp_ticks: 4000,
            epoch: SecurityEpoch::from_raw(2),
            signature: AuthenticityHash::compute_keyed(&[], &[]),
        }
        .sign(TEST_KEY);

        let json = serde_json::to_string(&promo).unwrap();
        let restored: StagePromotion = serde_json::from_str(&json).unwrap();
        assert_eq!(promo, restored);
    }

    // -- Audit events --

    #[test]
    fn events_track_full_lifecycle() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);

        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();
        gate.record_verdict("opt-1", pass_verdict(), TEST_KEY, epoch, 2000)
            .unwrap();
        gate.promote("opt-1", ContentHash::compute(b"ev"), TEST_KEY, epoch, 3000)
            .unwrap();

        let events = gate.events();
        assert_eq!(events.len(), 3);
        assert!(matches!(
            events[0].event_type,
            ValidationEventType::Submitted
        ));
        assert!(matches!(
            events[1].event_type,
            ValidationEventType::Validated { .. }
        ));
        assert!(matches!(
            events[2].event_type,
            ValidationEventType::StagePromoted { .. }
        ));
    }

    #[test]
    fn events_track_rollback() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);

        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();
        gate.record_verdict("opt-1", fail_verdict(), TEST_KEY, epoch, 2000)
            .unwrap();

        let events = gate.events();
        assert_eq!(events.len(), 3); // submitted, validated, rolled_back
        assert!(matches!(
            events[2].event_type,
            ValidationEventType::RolledBack { .. }
        ));
    }

    #[test]
    fn events_track_quarantine_lift() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);

        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();
        gate.record_verdict("opt-1", fail_verdict(), TEST_KEY, epoch, 2000)
            .unwrap();
        gate.lift_quarantine("opt-1", "policy override", epoch, 3000)
            .unwrap();

        let events = gate.events();
        let last = events.last().unwrap();
        assert!(matches!(
            last.event_type,
            ValidationEventType::QuarantineLifted { .. }
        ));
    }

    // -- Error display --

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<ValidationGateError> = vec![
            ValidationGateError::InvalidReceiptSignature {
                optimization_id: "opt-1".into(),
            },
            ValidationGateError::InvalidTokenSignature {
                token_id: "tok-1".into(),
            },
            ValidationGateError::TokenExpired {
                token_id: "tok-1".into(),
                expiry_epoch: 10,
                current_epoch: 20,
            },
            ValidationGateError::TokenReceiptMismatch {
                token_optimization_id: "opt-a".into(),
                receipt_optimization_id: "opt-b".into(),
            },
            ValidationGateError::Quarantined {
                optimization_id: "opt-1".into(),
                reason: "failed".into(),
            },
            ValidationGateError::InvalidStageTransition {
                from: ActivationStage::Shadow,
                to: ActivationStage::Default,
            },
            ValidationGateError::OptimizationNotFound {
                optimization_id: "opt-x".into(),
            },
            ValidationGateError::DuplicateSubmission {
                optimization_id: "opt-1".into(),
            },
            ValidationGateError::ActivationDenied {
                verdict: "no pass".into(),
            },
        ];

        for err in &errors {
            let s = err.to_string();
            assert!(!s.is_empty(), "error display should not be empty");
        }
    }

    #[test]
    fn error_serde_roundtrip() {
        let err = ValidationGateError::TokenExpired {
            token_id: "tok-1".into(),
            expiry_epoch: 10,
            current_epoch: 20,
        };
        let json = serde_json::to_string(&err).unwrap();
        let restored: ValidationGateError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
    }

    // -- Gate serde --

    #[test]
    fn gate_serde_roundtrip() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);
        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();

        let json = serde_json::to_string(&gate).unwrap();
        let restored: TranslationValidationGate = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.tracked_count(), 1);
        assert_eq!(restored.event_count(), 1);
    }

    // -- Determinism --

    #[test]
    fn gate_deterministic() {
        let build = || {
            let mut g = TranslationValidationGate::new();
            let epoch = SecurityEpoch::from_raw(1);
            g.submit(
                &test_receipt("opt-1"),
                &test_token("opt-1"),
                TEST_KEY,
                epoch,
                1000,
            )
            .unwrap();
            g.record_verdict("opt-1", pass_verdict(), TEST_KEY, epoch, 2000)
                .unwrap();
            g.promote("opt-1", ContentHash::compute(b"ev"), TEST_KEY, epoch, 3000)
                .unwrap();
            g
        };

        let json1 = serde_json::to_string(&build()).unwrap();
        let json2 = serde_json::to_string(&build()).unwrap();
        assert_eq!(
            json1, json2,
            "identical operations must produce identical state"
        );
    }

    // -- next_stage helper --

    #[test]
    fn next_stage_chain() {
        assert_eq!(
            next_stage(ActivationStage::Shadow),
            Some(ActivationStage::Canary)
        );
        assert_eq!(
            next_stage(ActivationStage::Canary),
            Some(ActivationStage::Ramp)
        );
        assert_eq!(
            next_stage(ActivationStage::Ramp),
            Some(ActivationStage::Default)
        );
        assert_eq!(next_stage(ActivationStage::Default), None);
    }

    // -- Promotion history --

    #[test]
    fn promotion_history_tracks_chain() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);
        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();
        gate.record_verdict("opt-1", pass_verdict(), TEST_KEY, epoch, 2000)
            .unwrap();
        gate.promote("opt-1", ContentHash::compute(b"ev"), TEST_KEY, epoch, 3000)
            .unwrap();
        gate.record_verdict("opt-1", pass_verdict(), TEST_KEY, epoch, 4000)
            .unwrap();
        gate.promote("opt-1", ContentHash::compute(b"ev"), TEST_KEY, epoch, 5000)
            .unwrap();

        let history = gate.promotion_history("opt-1");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].from_stage, ActivationStage::Shadow);
        assert_eq!(history[1].from_stage, ActivationStage::Canary);
    }

    // -- Rollback receipts list --

    #[test]
    fn rollback_receipts_accumulated() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);

        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();
        gate.record_verdict("opt-1", fail_verdict(), TEST_KEY, epoch, 2000)
            .unwrap();

        gate.lift_quarantine("opt-1", "new evidence", epoch, 3000)
            .unwrap();
        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            4000,
        )
        .unwrap();
        gate.record_verdict("opt-1", inconclusive_verdict(), TEST_KEY, epoch, 5000)
            .unwrap();

        assert_eq!(gate.rollback_receipts().len(), 2);
    }

    // -- QuarantineEntry --

    #[test]
    fn quarantine_entry_serde_roundtrip() {
        let entry = QuarantineEntry {
            optimization_id: "opt-1".into(),
            reason: "divergence".into(),
            counterexample_hash: Some(ContentHash::compute(b"cx")),
            quarantined_epoch: SecurityEpoch::from_raw(1),
            quarantined_at_ticks: 5000,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let restored: QuarantineEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, restored);
    }

    // -- ValidationEvent --

    #[test]
    fn validation_event_serde_roundtrip() {
        let event = ValidationEvent {
            optimization_id: "opt-1".into(),
            event_type: ValidationEventType::StagePromoted {
                from: ActivationStage::Shadow,
                to: ActivationStage::Canary,
            },
            timestamp_ticks: 3000,
            epoch: SecurityEpoch::from_raw(1),
        };
        let json = serde_json::to_string(&event).unwrap();
        let restored: ValidationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, restored);
    }

    // -- Demotion events --

    #[test]
    fn demote_emits_stage_demoted_event() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);
        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();
        gate.record_verdict("opt-1", pass_verdict(), TEST_KEY, epoch, 2000)
            .unwrap();
        gate.promote("opt-1", ContentHash::compute(b"ev"), TEST_KEY, epoch, 3000)
            .unwrap();
        gate.demote(
            "opt-1",
            ActivationStage::Shadow,
            "p99 regression",
            TEST_KEY,
            epoch,
            4000,
        )
        .unwrap();

        let events = gate.events();
        let last = events.last().unwrap();
        assert!(matches!(
            last.event_type,
            ValidationEventType::StageDemoted {
                from: ActivationStage::Canary,
                to: ActivationStage::Shadow,
            }
        ));
    }

    // -- Multiple optimizations --

    #[test]
    fn multiple_optimizations_tracked_independently() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);

        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();
        gate.submit(
            &test_receipt("opt-2"),
            &test_token("opt-2"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();

        assert_eq!(gate.tracked_count(), 2);

        gate.record_verdict("opt-1", pass_verdict(), TEST_KEY, epoch, 2000)
            .unwrap();
        gate.record_verdict("opt-2", fail_verdict(), TEST_KEY, epoch, 2000)
            .unwrap();

        assert_eq!(gate.tracked_count(), 1); // opt-2 removed
        assert_eq!(gate.quarantine_count(), 1); // opt-2 quarantined
        assert_eq!(gate.current_stage("opt-1"), Some(ActivationStage::Shadow));
        assert!(gate.is_quarantined("opt-2"));
    }

    // -- Quarantined IDs --

    #[test]
    fn quarantined_ids_list() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);

        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();
        gate.record_verdict("opt-1", fail_verdict(), TEST_KEY, epoch, 2000)
            .unwrap();

        gate.lift_quarantine("opt-1", "retry", epoch, 3000).unwrap();
        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            4000,
        )
        .unwrap();
        gate.record_verdict("opt-1", fail_verdict(), TEST_KEY, epoch, 5000)
            .unwrap();

        gate.submit(
            &test_receipt("opt-2"),
            &test_token("opt-2"),
            TEST_KEY,
            epoch,
            6000,
        )
        .unwrap();
        gate.record_verdict("opt-2", fail_verdict(), TEST_KEY, epoch, 7000)
            .unwrap();

        let ids = gate.quarantined_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains("opt-1"));
        assert!(ids.contains("opt-2"));
    }

    // -- Enrichment: ValidationMode serde roundtrip --

    #[test]
    fn validation_mode_serde_roundtrip_golden() {
        let mode = ValidationMode::GoldenCorpusReplay {
            corpus_hash: ContentHash::compute(b"corpus"),
            vector_count: 100,
        };
        let json = serde_json::to_string(&mode).unwrap();
        let back: ValidationMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, back);
    }

    #[test]
    fn validation_mode_serde_roundtrip_symbolic() {
        let mode = ValidationMode::SymbolicEquivalence {
            proof_hash: ContentHash::compute(b"proof"),
        };
        let json = serde_json::to_string(&mode).unwrap();
        let back: ValidationMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, back);
    }

    #[test]
    fn validation_mode_serde_roundtrip_differential() {
        let mode = ValidationMode::DifferentialTrace {
            workload_hash: ContentHash::compute(b"workload"),
            trace_pair_count: 50,
        };
        let json = serde_json::to_string(&mode).unwrap();
        let back: ValidationMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, back);
    }

    // -- Enrichment: ValidationMode Display --

    #[test]
    fn validation_mode_display_all_variants() {
        let golden = ValidationMode::GoldenCorpusReplay {
            corpus_hash: ContentHash::compute(b"c"),
            vector_count: 42,
        };
        assert!(golden.to_string().contains("42"));
        assert!(golden.to_string().contains("golden"));

        let symbolic = ValidationMode::SymbolicEquivalence {
            proof_hash: ContentHash::compute(b"p"),
        };
        assert!(symbolic.to_string().contains("symbolic"));

        let diff = ValidationMode::DifferentialTrace {
            workload_hash: ContentHash::compute(b"w"),
            trace_pair_count: 7,
        };
        assert!(diff.to_string().contains("7"));
        assert!(diff.to_string().contains("differential"));
    }

    // -- Enrichment: ValidationVerdict permits_activation --

    #[test]
    fn verdict_pass_permits_activation_enrichment() {
        assert!(pass_verdict().permits_activation());
    }

    #[test]
    fn verdict_fail_does_not_permit_activation() {
        assert!(!fail_verdict().permits_activation());
    }

    #[test]
    fn verdict_inconclusive_does_not_permit_activation() {
        assert!(!inconclusive_verdict().permits_activation());
    }

    // -- Enrichment: ValidationVerdict Display --

    #[test]
    fn verdict_display_all_variants() {
        let pass = pass_verdict().to_string();
        assert!(pass.starts_with("PASS"), "pass display: {pass}");

        let fail = fail_verdict().to_string();
        assert!(fail.starts_with("FAIL"), "fail display: {fail}");

        let inc = inconclusive_verdict().to_string();
        assert!(
            inc.starts_with("INCONCLUSIVE"),
            "inconclusive display: {inc}"
        );
    }

    // -- Enrichment: ValidationVerdict serde roundtrip --

    #[test]
    fn verdict_serde_roundtrip_pass() {
        let v = pass_verdict();
        let json = serde_json::to_string(&v).unwrap();
        let back: ValidationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn verdict_serde_roundtrip_fail() {
        let v = fail_verdict();
        let json = serde_json::to_string(&v).unwrap();
        let back: ValidationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn verdict_serde_roundtrip_inconclusive() {
        let v = inconclusive_verdict();
        let json = serde_json::to_string(&v).unwrap();
        let back: ValidationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // -- Enrichment: RollbackReceipt serde roundtrip --

    #[test]
    fn rollback_receipt_serde_roundtrip_enrichment() {
        let receipt = RollbackReceipt {
            rollback_token_id: "tok-1".to_string(),
            optimization_id: "opt-1".to_string(),
            failure_reason: "divergence".to_string(),
            counterexample_hash: Some(ContentHash::compute(b"cx")),
            restoration_baseline_hash: ContentHash::compute(b"base"),
            rollback_from_stage: ActivationStage::Shadow,
            timestamp_ticks: 5000,
            epoch: SecurityEpoch::from_raw(1),
            signature: AuthenticityHash::compute_keyed(b"key", b"data"),
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let back: RollbackReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    // -- Enrichment: RollbackReceipt sign and verify --

    #[test]
    fn rollback_receipt_sign_verify() {
        let receipt = RollbackReceipt {
            rollback_token_id: "tok-1".to_string(),
            optimization_id: "opt-1".to_string(),
            failure_reason: "divergence".to_string(),
            counterexample_hash: None,
            restoration_baseline_hash: ContentHash::compute(b"base"),
            rollback_from_stage: ActivationStage::Canary,
            timestamp_ticks: 1000,
            epoch: SecurityEpoch::from_raw(1),
            signature: AuthenticityHash::compute_keyed(b"", b""),
        };
        let signed = receipt.sign(TEST_KEY);
        assert!(signed.verify_signature(TEST_KEY));
        assert!(!signed.verify_signature(b"wrong-key"));
    }

    // -- Enrichment: StagePromotion serde roundtrip --

    #[test]
    fn stage_promotion_serde_roundtrip_enrichment() {
        let promo = StagePromotion {
            optimization_id: "opt-1".to_string(),
            from_stage: ActivationStage::Shadow,
            to_stage: ActivationStage::Canary,
            evidence_hash: ContentHash::compute(b"ev"),
            timestamp_ticks: 3000,
            epoch: SecurityEpoch::from_raw(1),
            signature: AuthenticityHash::compute_keyed(b"k", b"d"),
        };
        let json = serde_json::to_string(&promo).unwrap();
        let back: StagePromotion = serde_json::from_str(&json).unwrap();
        assert_eq!(promo, back);
    }

    // -- Enrichment: StagePromotion sign and verify --

    #[test]
    fn stage_promotion_sign_verify() {
        let promo = StagePromotion {
            optimization_id: "opt-1".to_string(),
            from_stage: ActivationStage::Shadow,
            to_stage: ActivationStage::Canary,
            evidence_hash: ContentHash::compute(b"ev"),
            timestamp_ticks: 3000,
            epoch: SecurityEpoch::from_raw(1),
            signature: AuthenticityHash::compute_keyed(b"", b""),
        };
        let signed = promo.sign(TEST_KEY);
        assert!(signed.verify_signature(TEST_KEY));
        assert!(!signed.verify_signature(b"wrong-key"));
    }

    // -- Enrichment: ValidationGateError serde roundtrip --

    #[test]
    fn validation_gate_error_serde_roundtrip() {
        let err = ValidationGateError::Quarantined {
            optimization_id: "opt-1".to_string(),
            reason: "divergence".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: ValidationGateError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    // -- Enrichment: ValidationGateError Display uniqueness --

    #[test]
    fn validation_gate_error_display_all_distinct() {
        let variants: Vec<ValidationGateError> = vec![
            ValidationGateError::InvalidReceiptSignature {
                optimization_id: "o1".to_string(),
            },
            ValidationGateError::InvalidTokenSignature {
                token_id: "t1".to_string(),
            },
            ValidationGateError::TokenExpired {
                token_id: "t2".to_string(),
                expiry_epoch: 1,
                current_epoch: 2,
            },
            ValidationGateError::TokenReceiptMismatch {
                token_optimization_id: "a".to_string(),
                receipt_optimization_id: "b".to_string(),
            },
            ValidationGateError::Quarantined {
                optimization_id: "o2".to_string(),
                reason: "bad".to_string(),
            },
            ValidationGateError::InvalidStageTransition {
                from: ActivationStage::Shadow,
                to: ActivationStage::Shadow,
            },
            ValidationGateError::OptimizationNotFound {
                optimization_id: "o3".to_string(),
            },
            ValidationGateError::DuplicateSubmission {
                optimization_id: "o4".to_string(),
            },
            ValidationGateError::ActivationDenied {
                verdict: "FAIL".to_string(),
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = v.to_string();
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            variants.len(),
            "all error variants produce distinct messages"
        );
    }

    // -- Enrichment: fresh gate state --

    #[test]
    fn fresh_gate_has_no_tracked() {
        let gate = TranslationValidationGate::new();
        assert_eq!(gate.tracked_count(), 0);
    }

    #[test]
    fn fresh_gate_has_no_quarantined() {
        let gate = TranslationValidationGate::new();
        assert_eq!(gate.quarantine_count(), 0);
    }

    #[test]
    fn fresh_gate_has_no_events() {
        let gate = TranslationValidationGate::new();
        assert!(gate.events().is_empty());
    }

    #[test]
    fn fresh_gate_has_no_rollback_receipts() {
        let gate = TranslationValidationGate::new();
        assert!(gate.rollback_receipts().is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: ValidationGateError implements std::error::Error
    // -----------------------------------------------------------------------

    #[test]
    fn validation_gate_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ValidationGateError::InvalidReceiptSignature {
                optimization_id: "opt-1".into(),
            }),
            Box::new(ValidationGateError::OptimizationNotFound {
                optimization_id: "opt-x".into(),
            }),
            Box::new(ValidationGateError::DuplicateSubmission {
                optimization_id: "opt-d".into(),
            }),
            Box::new(ValidationGateError::ActivationDenied {
                verdict: "no pass".into(),
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            4,
            "all 4 variants produce distinct messages"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: QuarantineEntry with counterexample serde
    // -----------------------------------------------------------------------

    #[test]
    fn quarantine_entry_with_counterexample_serde_roundtrip() {
        let entry = QuarantineEntry {
            optimization_id: "opt-cx".into(),
            reason: "hostcall divergence".into(),
            counterexample_hash: Some(ContentHash::compute(b"counterexample-data")),
            quarantined_epoch: SecurityEpoch::from_raw(5),
            quarantined_at_ticks: 99999,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let restored: QuarantineEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, restored);
        assert!(restored.counterexample_hash.is_some());
    }

    // -----------------------------------------------------------------------
    // Enrichment: ActivationStage ordering via next_stage
    // -----------------------------------------------------------------------

    #[test]
    fn activation_stage_ordering_follows_chain() {
        // Verify the stage progression chain: Shadow < Canary < Ramp < Default
        assert!(ActivationStage::Shadow < ActivationStage::Canary);
        assert!(ActivationStage::Canary < ActivationStage::Ramp);
        assert!(ActivationStage::Ramp < ActivationStage::Default);
    }

    // -----------------------------------------------------------------------
    // Enrichment: gate event_count tracks all operations
    // -----------------------------------------------------------------------

    #[test]
    fn gate_event_count_tracks_submit_verdict_promote() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);
        assert_eq!(gate.event_count(), 0);

        gate.submit(
            &test_receipt("opt-1"),
            &test_token("opt-1"),
            TEST_KEY,
            epoch,
            1000,
        )
        .unwrap();
        assert_eq!(gate.event_count(), 1);

        gate.record_verdict("opt-1", pass_verdict(), TEST_KEY, epoch, 2000)
            .unwrap();
        assert_eq!(gate.event_count(), 2);

        gate.promote("opt-1", ContentHash::compute(b"ev"), TEST_KEY, epoch, 3000)
            .unwrap();
        assert_eq!(gate.event_count(), 3);
    }

    // -----------------------------------------------------------------------
    // Enrichment: ValidationEventType serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn validation_event_type_serde_roundtrip() {
        let types = vec![
            ValidationEventType::Submitted,
            ValidationEventType::Validated {
                verdict: "pass".into(),
            },
            ValidationEventType::RolledBack {
                reason: "divergence".into(),
            },
            ValidationEventType::StagePromoted {
                from: ActivationStage::Shadow,
                to: ActivationStage::Canary,
            },
            ValidationEventType::StageDemoted {
                from: ActivationStage::Canary,
                to: ActivationStage::Shadow,
            },
            ValidationEventType::QuarantineLifted {
                override_reason: "new evidence".into(),
            },
        ];
        for evt_type in &types {
            let event = ValidationEvent {
                optimization_id: "opt-test".into(),
                event_type: evt_type.clone(),
                timestamp_ticks: 42,
                epoch: SecurityEpoch::from_raw(1),
            };
            let json = serde_json::to_string(&event).unwrap();
            let back: ValidationEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(event, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: demote unknown optimization fails
    // -----------------------------------------------------------------------

    #[test]
    fn demote_unknown_optimization_fails() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);
        assert!(matches!(
            gate.demote(
                "nonexistent",
                ActivationStage::Shadow,
                "reason",
                TEST_KEY,
                epoch,
                1000
            ),
            Err(ValidationGateError::OptimizationNotFound { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Enrichment: promote unknown optimization fails
    // -----------------------------------------------------------------------

    #[test]
    fn promote_unknown_optimization_fails() {
        let mut gate = TranslationValidationGate::new();
        let epoch = SecurityEpoch::from_raw(1);
        assert!(matches!(
            gate.promote(
                "nonexistent",
                ContentHash::compute(b"ev"),
                TEST_KEY,
                epoch,
                1000
            ),
            Err(ValidationGateError::OptimizationNotFound { .. })
        ));
    }
}
