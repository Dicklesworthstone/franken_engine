//! Risk-priced capability leases (E10.T4, `bd-fqlfw.10.4`).
//!
//! Capabilities are not just allowed/denied — they are risk-priced leases
//! with budgets, evidence, and revocation. A [`CapabilityLease`] grants a
//! capability inside a scope while expected loss stays below budget: each
//! use is priced at the guardplane's expected loss of `Allow` under the
//! current posterior ([`ExpectedLossSelector::expected_losses`]), decrements
//! the lease's windowed risk budget, and emits a content-hashed
//! [`LeaseUsageReceipt`] showing the risk price paid. Crossing the
//! challenge threshold demands step-up verification; crossing the revoke
//! threshold kills the lease.
//!
//! Authority boundary: [`LeaseManager::request_use`] enforces the lease holder's
//! extension identity and capability before mutating budget state. The caller
//! must derive that identity from host-owned execution context rather than an
//! extension-controlled argument. v1 treats [`CapabilityLease::scope`] as an
//! opaque contract identifier, so the capability-specific hostcall gate must
//! still verify the concrete host/path/resource against that scope before
//! calling the manager. A lease receipt proves which declared scope was
//! charged; it does not by itself prove the concrete resource matched that
//! scope.
//!
//! Operational boundary (the original bead's v1 scope): an INTERNAL report
//! under fixed loss matrices. The "price" is expected loss in millionths, not
//! money; nothing here is an insurance or liability construct. All flow is deterministic:
//! the caller supplies trusted monotonic logical ticks and posteriors; no wall
//! clocks, no randomness; storage is `BTreeMap`; arithmetic is saturating
//! fixed-point millionths (1_000_000 = 1.0).
//!
//! Fail-closed defaults: unknown leases are errors, capability mismatches
//! and exhausted budgets are denials with receipts, a missing price for
//! `Allow` prices as `i64::MAX` (undeliverable), and every decision —
//! including denials and revocations — emits a receipt.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bayesian_posterior::Posterior;
use crate::capability::RuntimeCapability;
use crate::expected_loss_selector::{
    ContainmentAction, EXPECTED_LOSS_ALGORITHM_VERSION, ExpectedLossSelector, LossMatrix,
};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

/// Fixed-point scale: 1_000_000 = 1.0.
pub const MILLION: i64 = 1_000_000;

/// Schema version for serialized lease artifacts.
pub const CAPABILITY_LEASE_SCHEMA_VERSION: &str = "franken-engine.capability-lease.v4";

/// Version of the expected-loss arithmetic used to price capability uses.
pub const CAPABILITY_LEASE_PRICING_ALGORITHM: &str = EXPECTED_LOSS_ALGORITHM_VERSION;

/// Component label for telemetry and evidence entries.
pub const CAPABILITY_LEASE_COMPONENT: &str = "capability_lease";

/// A risk-priced capability lease: the contract under which an extension
/// may exercise one capability inside one scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityLease {
    pub lease_id: String,
    pub extension_id: String,
    pub capability: RuntimeCapability,
    /// Opaque, operator-meaningful scope identifier. Resource-specific matching
    /// (host patterns, path prefixes, and so on) is enforced by the caller.
    pub scope: String,
    /// Per-use ceiling: a single use priced above this is denied outright.
    pub max_expected_loss_millionths: i64,
    /// Step-up verification required when `p_malicious` reaches this level.
    pub challenge_threshold_millionths: i64,
    /// Lease is revoked when `p_malicious` reaches this level.
    pub revoke_threshold_millionths: i64,
    /// Width of the budget window in logical ticks (>= 1).
    pub budget_window_ticks: u64,
    /// Risk budget available inside each window, in loss millionths.
    pub window_budget_millionths: i64,
    /// Policy epoch the lease terms were issued under.
    pub policy_epoch: SecurityEpoch,
}

impl CapabilityLease {
    /// Validate structural invariants. Fail-closed: a malformed lease never
    /// enters the manager.
    pub fn validate(&self) -> Result<(), CapabilityLeaseError> {
        let detail = |message: &str| CapabilityLeaseError::InvalidLease {
            lease_id: self.lease_id.clone(),
            detail: message.to_string(),
        };
        if self.lease_id.trim().is_empty() {
            return Err(detail("lease_id must be non-empty"));
        }
        if self.extension_id.trim().is_empty() {
            return Err(detail("extension_id must be non-empty"));
        }
        if self.scope.trim().is_empty() {
            return Err(detail("scope must be non-empty"));
        }
        if self.budget_window_ticks == 0 {
            return Err(detail("budget_window_ticks must be >= 1"));
        }
        if self.window_budget_millionths < 0 {
            return Err(detail("window_budget_millionths must be >= 0"));
        }
        if self.max_expected_loss_millionths < 0 {
            return Err(detail("max_expected_loss_millionths must be >= 0"));
        }
        for (name, value) in [
            (
                "challenge_threshold_millionths",
                self.challenge_threshold_millionths,
            ),
            (
                "revoke_threshold_millionths",
                self.revoke_threshold_millionths,
            ),
        ] {
            if !(0..=MILLION).contains(&value) {
                return Err(detail(&format!("{name} must be within [0, {MILLION}]")));
            }
        }
        if self.challenge_threshold_millionths > self.revoke_threshold_millionths {
            return Err(detail(
                "challenge_threshold_millionths must not exceed revoke_threshold_millionths",
            ));
        }
        Ok(())
    }
}

/// Lifecycle status of a registered lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityLeaseStatus {
    Active,
    Revoked,
}

/// Why the manager could not produce a safe risk-price quote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PricingUnavailableReason {
    /// The supplied posterior violates its probability-distribution invariant.
    InvalidPosterior,
    /// The fixed matrix lacks a usable audit identity.
    InvalidLossMatrixId,
    /// The configured matrix does not contain every action/state pair exactly once.
    IncompleteLossMatrix,
    /// The Allow quote is negative, missing, or the reserved fail-closed maximum.
    UndeliverableAllowLoss,
}

/// Why a use request was denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum DenialReason {
    /// The lease's windowed risk budget cannot cover this use.
    BudgetExhausted {
        risk_price_millionths: i64,
        remaining_budget_millionths: i64,
    },
    /// A single use priced above the lease's per-use ceiling.
    PerUseCeilingExceeded {
        risk_price_millionths: i64,
        max_expected_loss_millionths: i64,
    },
    /// No safe Allow quote can be produced from the pricing inputs.
    PricingUnavailable {
        loss_matrix_id: String,
        pricing_reason: PricingUnavailableReason,
    },
    /// The lease was previously revoked.
    LeaseRevoked,
    /// The request named a capability the lease does not grant.
    CapabilityMismatch { requested: String, leased: String },
    /// The request came from an extension other than the lease holder.
    ExtensionMismatch { requested: String, leased: String },
    /// The caller's logical clock moved backwards for this lease.
    NonMonotonicTick {
        previous_tick: u64,
        requested_tick: u64,
    },
}

/// Outcome of one use request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum LeaseDecision {
    /// Use granted; the risk price was deducted from the window budget.
    Granted {
        risk_price_millionths: i64,
        remaining_budget_millionths: i64,
    },
    /// Risk crossed the challenge threshold: step-up verification required
    /// before this use can proceed. No budget is spent.
    ChallengeRequired { p_malicious_millionths: i64 },
    /// Risk crossed the revoke threshold: the lease is now revoked.
    Revoked { p_malicious_millionths: i64 },
    /// Use denied (fail-closed); see the reason.
    Denied { reason: DenialReason },
}

impl LeaseDecision {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Granted { .. } => "granted",
            Self::ChallengeRequired { .. } => "challenge_required",
            Self::Revoked { .. } => "revoked",
            Self::Denied { .. } => "denied",
        }
    }
}

/// Content-hashed receipt for one use request. Every decision — grant,
/// challenge, revocation, denial — emits one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseUsageReceipt {
    /// Schema that defines this receipt's fields and hash preimage.
    pub schema_version: String,
    /// Deterministic id: `<lease_id>#<sequence>`.
    pub receipt_id: String,
    pub lease_id: String,
    /// Extension holding the lease.
    pub extension_id: String,
    /// Extension identity presented by this use request.
    pub requester_extension_id: String,
    /// Capability granted by the lease.
    pub capability: String,
    /// Capability named by this use request.
    pub requested_capability: String,
    pub scope: String,
    /// Identifier and content identity of the matrix that produced the quote.
    pub loss_matrix_id: String,
    pub loss_matrix_hash: ContentHash,
    /// Arithmetic contract used with the matrix and posterior.
    pub pricing_algorithm: String,
    pub tick: u64,
    pub p_malicious_millionths: i64,
    /// Risk price quoted for this use (expected loss of Allow).
    pub risk_price_millionths: i64,
    pub decision_kind: String,
    /// Exact denial evidence; absent for grants, challenges, and revocations.
    pub denial_reason: Option<DenialReason>,
    pub remaining_budget_millionths: i64,
    pub policy_epoch: u64,
    pub content_hash: ContentHash,
}

/// Append a field's `Display` form to a content-hash preimage with a fixed-width
/// `u64` length prefix.
///
/// This receipt hash commits to the identity of a lease use, so its preimage
/// must be injective. The previous `format!("{}|{}|…")` join over the free-form
/// `receipt_id`/`lease_id`/`extension_id`/`capability`/`scope` strings was not
/// injective — a field containing `|` lets two distinct receipts collide (e.g.
/// `lease_id="a|b", extension_id="c"` and `lease_id="a", extension_id="b|c"`
/// both serialize to `…a|b|c…`). Length-prefixing each field removes the
/// ambiguity. Cf. the same fix crate-wide in commits 7f500570 / 1d3e0542.
fn hash_display(preimage: &mut Vec<u8>, value: &dyn std::fmt::Display) {
    let rendered = value.to_string();
    preimage.extend_from_slice(&(rendered.len() as u64).to_le_bytes());
    preimage.extend_from_slice(rendered.as_bytes());
}

fn hash_pricing_unavailable_reason(preimage: &mut Vec<u8>, reason: PricingUnavailableReason) {
    let tag = match reason {
        PricingUnavailableReason::InvalidPosterior => "invalid_posterior",
        PricingUnavailableReason::InvalidLossMatrixId => "invalid_loss_matrix_id",
        PricingUnavailableReason::IncompleteLossMatrix => "incomplete_loss_matrix",
        PricingUnavailableReason::UndeliverableAllowLoss => "undeliverable_allow_loss",
    };
    hash_display(preimage, &tag);
}

fn hash_denial_reason(preimage: &mut Vec<u8>, reason: Option<&DenialReason>) {
    match reason {
        None => hash_display(preimage, &"none"),
        Some(DenialReason::BudgetExhausted {
            risk_price_millionths,
            remaining_budget_millionths,
        }) => {
            hash_display(preimage, &"budget_exhausted");
            hash_display(preimage, risk_price_millionths);
            hash_display(preimage, remaining_budget_millionths);
        }
        Some(DenialReason::PerUseCeilingExceeded {
            risk_price_millionths,
            max_expected_loss_millionths,
        }) => {
            hash_display(preimage, &"per_use_ceiling_exceeded");
            hash_display(preimage, risk_price_millionths);
            hash_display(preimage, max_expected_loss_millionths);
        }
        Some(DenialReason::PricingUnavailable {
            loss_matrix_id,
            pricing_reason,
        }) => {
            hash_display(preimage, &"pricing_unavailable");
            hash_display(preimage, loss_matrix_id);
            hash_pricing_unavailable_reason(preimage, *pricing_reason);
        }
        Some(DenialReason::LeaseRevoked) => hash_display(preimage, &"lease_revoked"),
        Some(DenialReason::CapabilityMismatch { requested, leased }) => {
            hash_display(preimage, &"capability_mismatch");
            hash_display(preimage, requested);
            hash_display(preimage, leased);
        }
        Some(DenialReason::ExtensionMismatch { requested, leased }) => {
            hash_display(preimage, &"extension_mismatch");
            hash_display(preimage, requested);
            hash_display(preimage, leased);
        }
        Some(DenialReason::NonMonotonicTick {
            previous_tick,
            requested_tick,
        }) => {
            hash_display(preimage, &"non_monotonic_tick");
            hash_display(preimage, previous_tick);
            hash_display(preimage, requested_tick);
        }
    }
}

impl LeaseUsageReceipt {
    fn compute_hash(&self) -> ContentHash {
        // Length-prefixed fixed-order preimage.
        let mut preimage: Vec<u8> = Vec::new();
        hash_display(&mut preimage, &self.schema_version);
        hash_display(&mut preimage, &self.receipt_id);
        hash_display(&mut preimage, &self.lease_id);
        hash_display(&mut preimage, &self.extension_id);
        hash_display(&mut preimage, &self.requester_extension_id);
        hash_display(&mut preimage, &self.capability);
        hash_display(&mut preimage, &self.requested_capability);
        hash_display(&mut preimage, &self.scope);
        hash_display(&mut preimage, &self.loss_matrix_id);
        hash_display(&mut preimage, &self.loss_matrix_hash);
        hash_display(&mut preimage, &self.pricing_algorithm);
        hash_display(&mut preimage, &self.tick);
        hash_display(&mut preimage, &self.p_malicious_millionths);
        hash_display(&mut preimage, &self.risk_price_millionths);
        hash_display(&mut preimage, &self.decision_kind);
        hash_denial_reason(&mut preimage, self.denial_reason.as_ref());
        hash_display(&mut preimage, &self.remaining_budget_millionths);
        hash_display(&mut preimage, &self.policy_epoch);
        ContentHash::compute(&preimage)
    }

    /// Verify that all durable receipt fields still match the stored hash.
    pub fn verify_content_hash(&self) -> bool {
        self.content_hash == self.compute_hash()
    }
}

/// Recommended operator action for a lease, derived from fixed
/// deterministic rules over its observed usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseRecommendation {
    /// Lease was revoked: renewal requires explicit review.
    ReviewBeforeRenewal,
    /// Pricing inputs were invalid or incomplete and must be repaired.
    RepairPricingInputs,
    /// A request named authority this lease did not grant.
    ReviewCapabilityMismatch,
    /// A different extension attempted to exercise this lease.
    ReviewExtensionMismatch,
    /// The trusted logical clock supplied to the manager moved backwards.
    RepairLogicalClock,
    /// Challenges fired but no use was ever granted: the scope is riskier
    /// than the lease terms assume; narrow it.
    NarrowScope,
    /// Budget denials occurred: either reduce spend (tighter scope) or
    /// raise the window budget deliberately.
    RevisitBudget,
    /// Lease saw no use at all: consider revoking idle authority.
    ConsiderRevokingIdle,
    /// Observed usage fits the lease terms.
    KeepAsIs,
}

/// Per-lease usage summary inside a [`LeaseReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseSpendSummary {
    pub lease_id: String,
    pub extension_id: String,
    pub capability: String,
    pub scope: String,
    pub status: CapabilityLeaseStatus,
    pub spend_total_millionths: i64,
    pub remaining_budget_millionths: i64,
    pub uses_granted: u64,
    pub challenges: u64,
    pub denials: u64,
    pub budget_denials: u64,
    pub capability_mismatches: u64,
    pub extension_mismatches: u64,
    pub tick_regressions: u64,
    pub pricing_failures: u64,
    pub receipts: u64,
    pub recommendation: LeaseRecommendation,
}

/// Deterministic internal report: capability spend per extension, events,
/// and recommended lease changes (the bead's v1 deliverable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseReport {
    pub schema_version: String,
    pub loss_matrix_id: String,
    pub loss_matrix_hash: ContentHash,
    pub pricing_algorithm: String,
    /// Sorted by lease id (BTreeMap iteration order).
    pub summaries: Vec<LeaseSpendSummary>,
    pub total_spend_millionths: i64,
    pub total_receipts: u64,
    /// SHA-256 hex of the report serialized with this field empty.
    pub artifact_hash_hex: String,
}

impl LeaseReport {
    /// Recompute the report hash over the complete artifact with the hash
    /// field cleared, matching the construction preimage.
    pub fn recompute_artifact_hash_hex(&self) -> Result<String, CapabilityLeaseError> {
        let mut artifact = self.clone();
        artifact.artifact_hash_hex.clear();
        let payload =
            serde_json::to_vec(&artifact).map_err(|err| CapabilityLeaseError::Serialization {
                detail: err.to_string(),
            })?;
        Ok(sha256_hex(&payload))
    }

    /// Verify that every serialized report field still matches its stored
    /// artifact hash.
    pub fn verify_artifact_hash(&self) -> Result<bool, CapabilityLeaseError> {
        Ok(self.artifact_hash_hex == self.recompute_artifact_hash_hex()?)
    }
}

/// Errors from lease management (caller bugs / malformed contracts).
/// Runtime risk outcomes are [`LeaseDecision`]s, not errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityLeaseError {
    DuplicateLeaseId { lease_id: String },
    UnknownLeaseId { lease_id: String },
    InvalidLease { lease_id: String, detail: String },
    ReceiptSequenceExhausted { lease_id: String },
    Serialization { detail: String },
}

impl std::fmt::Display for CapabilityLeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateLeaseId { lease_id } => {
                write!(f, "duplicate lease id: {lease_id}")
            }
            Self::UnknownLeaseId { lease_id } => write!(f, "unknown lease id: {lease_id}"),
            Self::InvalidLease { lease_id, detail } => {
                write!(f, "invalid lease {lease_id}: {detail}")
            }
            Self::ReceiptSequenceExhausted { lease_id } => {
                write!(f, "receipt sequence exhausted for lease: {lease_id}")
            }
            Self::Serialization { detail } => write!(f, "serialization failure: {detail}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LeaseState {
    lease: CapabilityLease,
    status: CapabilityLeaseStatus,
    window_start_tick: u64,
    last_request_tick: Option<u64>,
    remaining_budget_millionths: i64,
    spend_total_millionths: i64,
    uses_granted: u64,
    challenges: u64,
    denials: u64,
    budget_denials: u64,
    capability_mismatches: u64,
    extension_mismatches: u64,
    tick_regressions: u64,
    pricing_failures: u64,
    receipt_count: u64,
}

/// The lease manager: prices uses, enforces budgets/thresholds, emits
/// receipts, and renders the deterministic internal report.
#[derive(Debug, Clone)]
pub struct LeaseManager {
    selector: ExpectedLossSelector,
    loss_matrix_id: String,
    loss_matrix_hash: ContentHash,
    loss_matrix_id_valid: bool,
    loss_matrix_complete: bool,
    leases: BTreeMap<String, LeaseState>,
    receipts: Vec<LeaseUsageReceipt>,
}

impl LeaseManager {
    /// Build a manager over a fixed loss matrix (operational v1: matrices are fixed,
    /// chosen at construction).
    pub fn new(loss_matrix: LossMatrix) -> Self {
        let loss_matrix_id = loss_matrix.matrix_id.clone();
        let loss_matrix_hash = loss_matrix.content_hash();
        let loss_matrix_id_valid = loss_matrix.has_valid_id();
        let loss_matrix_complete = loss_matrix.is_complete();
        Self {
            selector: ExpectedLossSelector::new(loss_matrix),
            loss_matrix_id,
            loss_matrix_hash,
            loss_matrix_id_valid,
            loss_matrix_complete,
            leases: BTreeMap::new(),
            receipts: Vec::new(),
        }
    }

    /// Manager over the balanced default loss matrix.
    pub fn balanced() -> Self {
        Self::new(LossMatrix::balanced())
    }

    /// Register a lease. Fail-closed on validation failure or duplicate id.
    pub fn register_lease(&mut self, lease: CapabilityLease) -> Result<(), CapabilityLeaseError> {
        lease.validate()?;
        if self.leases.contains_key(&lease.lease_id) {
            return Err(CapabilityLeaseError::DuplicateLeaseId {
                lease_id: lease.lease_id.clone(),
            });
        }
        let state = LeaseState {
            window_start_tick: 0,
            last_request_tick: None,
            remaining_budget_millionths: lease.window_budget_millionths,
            spend_total_millionths: 0,
            uses_granted: 0,
            challenges: 0,
            denials: 0,
            budget_denials: 0,
            capability_mismatches: 0,
            extension_mismatches: 0,
            tick_regressions: 0,
            pricing_failures: 0,
            receipt_count: 0,
            status: CapabilityLeaseStatus::Active,
            lease,
        };
        self.leases.insert(state.lease.lease_id.clone(), state);
        Ok(())
    }

    /// Current status of a lease.
    pub fn lease_status(
        &self,
        lease_id: &str,
    ) -> Result<CapabilityLeaseStatus, CapabilityLeaseError> {
        self.leases
            .get(lease_id)
            .map(|state| state.status)
            .ok_or_else(|| CapabilityLeaseError::UnknownLeaseId {
                lease_id: lease_id.to_string(),
            })
    }

    /// All receipts emitted so far, in emission order.
    pub fn receipts(&self) -> &[LeaseUsageReceipt] {
        &self.receipts
    }

    fn try_risk_price_millionths(
        &self,
        posterior: &Posterior,
    ) -> Result<i64, PricingUnavailableReason> {
        if !posterior.is_valid() {
            return Err(PricingUnavailableReason::InvalidPosterior);
        }
        if !self.loss_matrix_id_valid {
            return Err(PricingUnavailableReason::InvalidLossMatrixId);
        }
        if !self.loss_matrix_complete {
            return Err(PricingUnavailableReason::IncompleteLossMatrix);
        }
        let price = self
            .selector
            .expected_losses(posterior)
            .get(&ContainmentAction::Allow)
            .copied()
            .ok_or(PricingUnavailableReason::UndeliverableAllowLoss)?;
        if price < 0 || price == i64::MAX {
            return Err(PricingUnavailableReason::UndeliverableAllowLoss);
        }
        Ok(price)
    }

    /// Price a use as the expected loss of `Allow` under the posterior.
    /// Fail-closed: invalid inputs and undeliverable quotes return `i64::MAX`.
    pub fn risk_price_millionths(&self, posterior: &Posterior) -> i64 {
        self.try_risk_price_millionths(posterior)
            .unwrap_or(i64::MAX)
    }

    fn pricing_unavailable_decision(
        state: &mut LeaseState,
        loss_matrix_id: String,
        pricing_reason: PricingUnavailableReason,
    ) -> LeaseDecision {
        state.denials = state.denials.saturating_add(1);
        state.pricing_failures = state.pricing_failures.saturating_add(1);
        LeaseDecision::Denied {
            reason: DenialReason::PricingUnavailable {
                loss_matrix_id,
                pricing_reason,
            },
        }
    }

    /// Request one use of `capability` under `lease_id` at logical `tick`
    /// given the guardplane's current `posterior`. `requester_extension_id`
    /// must come from host-owned execution context, and `tick` must come from
    /// a trusted clock that never decreases for this lease. Every outcome
    /// emits a content-hashed receipt.
    pub fn request_use(
        &mut self,
        lease_id: &str,
        requester_extension_id: &str,
        capability: RuntimeCapability,
        posterior: &Posterior,
        tick: u64,
    ) -> Result<LeaseDecision, CapabilityLeaseError> {
        let risk_quote = self.try_risk_price_millionths(posterior);
        let risk_price = risk_quote.unwrap_or(i64::MAX);
        let pricing_unavailable = risk_quote.err();
        let loss_matrix_id = self.loss_matrix_id.clone();
        let loss_matrix_hash = self.loss_matrix_hash;
        let p_malicious = posterior.p_malicious;

        let state =
            self.leases
                .get_mut(lease_id)
                .ok_or_else(|| CapabilityLeaseError::UnknownLeaseId {
                    lease_id: lease_id.to_string(),
                })?;
        // Reserve the durable receipt sequence before any budget, status, or
        // accounting mutation. Saturating the counter would reuse the final
        // identifier forever and make distinct authority decisions
        // indistinguishable in the audit trail.
        let next_receipt_count = state.receipt_count.checked_add(1).ok_or_else(|| {
            CapabilityLeaseError::ReceiptSequenceExhausted {
                lease_id: state.lease.lease_id.clone(),
            }
        })?;

        // Authority and clock checks precede window mutation. A rejected caller
        // must not be able to reset another extension's budget by supplying a
        // future tick, and a clock rollback must not be silently accepted.
        let decision = if requester_extension_id != state.lease.extension_id {
            state.denials = state.denials.saturating_add(1);
            state.extension_mismatches = state.extension_mismatches.saturating_add(1);
            LeaseDecision::Denied {
                reason: DenialReason::ExtensionMismatch {
                    requested: requester_extension_id.to_string(),
                    leased: state.lease.extension_id.clone(),
                },
            }
        } else if capability != state.lease.capability {
            state.denials = state.denials.saturating_add(1);
            state.capability_mismatches = state.capability_mismatches.saturating_add(1);
            LeaseDecision::Denied {
                reason: DenialReason::CapabilityMismatch {
                    requested: capability.to_string(),
                    leased: state.lease.capability.to_string(),
                },
            }
        } else if let Some(previous_tick) = state
            .last_request_tick
            .filter(|previous_tick| tick < *previous_tick)
        {
            state.denials = state.denials.saturating_add(1);
            state.tick_regressions = state.tick_regressions.saturating_add(1);
            LeaseDecision::Denied {
                reason: DenialReason::NonMonotonicTick {
                    previous_tick,
                    requested_tick: tick,
                },
            }
        } else {
            state.last_request_tick = Some(tick);

            // Roll the budget window forward only for an authorized request
            // carrying a nondecreasing logical tick.
            if state.status == CapabilityLeaseStatus::Active
                && tick.saturating_sub(state.window_start_tick) >= state.lease.budget_window_ticks
            {
                let windows_elapsed =
                    tick.saturating_sub(state.window_start_tick) / state.lease.budget_window_ticks;
                state.window_start_tick = state.window_start_tick.saturating_add(
                    windows_elapsed.saturating_mul(state.lease.budget_window_ticks),
                );
                state.remaining_budget_millionths = state.lease.window_budget_millionths;
            }

            if state.status == CapabilityLeaseStatus::Revoked {
                state.denials = state.denials.saturating_add(1);
                LeaseDecision::Denied {
                    reason: DenialReason::LeaseRevoked,
                }
            } else if let Some(reason @ PricingUnavailableReason::InvalidPosterior) =
                pricing_unavailable
            {
                // A malformed posterior is not trustworthy threshold evidence. In
                // particular, an out-of-range p_malicious must not revoke a lease.
                Self::pricing_unavailable_decision(state, loss_matrix_id.clone(), reason)
            } else if p_malicious >= state.lease.revoke_threshold_millionths {
                state.status = CapabilityLeaseStatus::Revoked;
                LeaseDecision::Revoked {
                    p_malicious_millionths: p_malicious,
                }
            } else if p_malicious >= state.lease.challenge_threshold_millionths {
                state.challenges = state.challenges.saturating_add(1);
                LeaseDecision::ChallengeRequired {
                    p_malicious_millionths: p_malicious,
                }
            } else if let Some(reason) = pricing_unavailable {
                Self::pricing_unavailable_decision(state, loss_matrix_id.clone(), reason)
            } else if risk_price > state.lease.max_expected_loss_millionths {
                state.denials = state.denials.saturating_add(1);
                state.budget_denials = state.budget_denials.saturating_add(1);
                LeaseDecision::Denied {
                    reason: DenialReason::PerUseCeilingExceeded {
                        risk_price_millionths: risk_price,
                        max_expected_loss_millionths: state.lease.max_expected_loss_millionths,
                    },
                }
            } else if risk_price > state.remaining_budget_millionths {
                state.denials = state.denials.saturating_add(1);
                state.budget_denials = state.budget_denials.saturating_add(1);
                LeaseDecision::Denied {
                    reason: DenialReason::BudgetExhausted {
                        risk_price_millionths: risk_price,
                        remaining_budget_millionths: state.remaining_budget_millionths,
                    },
                }
            } else {
                state.remaining_budget_millionths =
                    state.remaining_budget_millionths.saturating_sub(risk_price);
                state.spend_total_millionths =
                    state.spend_total_millionths.saturating_add(risk_price);
                state.uses_granted = state.uses_granted.saturating_add(1);
                LeaseDecision::Granted {
                    risk_price_millionths: risk_price,
                    remaining_budget_millionths: state.remaining_budget_millionths,
                }
            }
        };

        state.receipt_count = next_receipt_count;
        let denial_reason = match &decision {
            LeaseDecision::Denied { reason } => Some(reason.clone()),
            _ => None,
        };
        let mut receipt = LeaseUsageReceipt {
            schema_version: CAPABILITY_LEASE_SCHEMA_VERSION.to_string(),
            receipt_id: format!("{}#{}", state.lease.lease_id, state.receipt_count),
            lease_id: state.lease.lease_id.clone(),
            extension_id: state.lease.extension_id.clone(),
            requester_extension_id: requester_extension_id.to_string(),
            capability: state.lease.capability.to_string(),
            requested_capability: capability.to_string(),
            scope: state.lease.scope.clone(),
            loss_matrix_id,
            loss_matrix_hash,
            pricing_algorithm: CAPABILITY_LEASE_PRICING_ALGORITHM.to_string(),
            tick,
            p_malicious_millionths: p_malicious,
            risk_price_millionths: risk_price,
            decision_kind: decision.kind().to_string(),
            denial_reason,
            remaining_budget_millionths: state.remaining_budget_millionths,
            policy_epoch: state.lease.policy_epoch.as_u64(),
            content_hash: ContentHash::compute(b"placeholder"),
        };
        receipt.content_hash = receipt.compute_hash();
        self.receipts.push(receipt);

        Ok(decision)
    }

    fn recommendation_for(&self, state: &LeaseState) -> LeaseRecommendation {
        if state.status == CapabilityLeaseStatus::Revoked {
            LeaseRecommendation::ReviewBeforeRenewal
        } else if !self.loss_matrix_id_valid
            || !self.loss_matrix_complete
            || state.pricing_failures > 0
        {
            LeaseRecommendation::RepairPricingInputs
        } else if state.extension_mismatches > 0 {
            LeaseRecommendation::ReviewExtensionMismatch
        } else if state.capability_mismatches > 0 {
            LeaseRecommendation::ReviewCapabilityMismatch
        } else if state.tick_regressions > 0 {
            LeaseRecommendation::RepairLogicalClock
        } else if state.challenges > 0 && state.uses_granted == 0 {
            LeaseRecommendation::NarrowScope
        } else if state.budget_denials > 0 {
            LeaseRecommendation::RevisitBudget
        } else if state.uses_granted == 0 && state.challenges == 0 {
            LeaseRecommendation::ConsiderRevokingIdle
        } else {
            LeaseRecommendation::KeepAsIs
        }
    }

    /// Render the deterministic internal report (v1 deliverable).
    pub fn report(&self) -> Result<LeaseReport, CapabilityLeaseError> {
        let summaries: Vec<LeaseSpendSummary> = self
            .leases
            .values()
            .map(|state| LeaseSpendSummary {
                lease_id: state.lease.lease_id.clone(),
                extension_id: state.lease.extension_id.clone(),
                capability: state.lease.capability.to_string(),
                scope: state.lease.scope.clone(),
                status: state.status,
                spend_total_millionths: state.spend_total_millionths,
                remaining_budget_millionths: state.remaining_budget_millionths,
                uses_granted: state.uses_granted,
                challenges: state.challenges,
                denials: state.denials,
                budget_denials: state.budget_denials,
                capability_mismatches: state.capability_mismatches,
                extension_mismatches: state.extension_mismatches,
                tick_regressions: state.tick_regressions,
                pricing_failures: state.pricing_failures,
                receipts: state.receipt_count,
                recommendation: self.recommendation_for(state),
            })
            .collect();
        let total_spend_millionths = summaries.iter().fold(0i64, |acc, summary| {
            acc.saturating_add(summary.spend_total_millionths)
        });
        let mut report = LeaseReport {
            schema_version: CAPABILITY_LEASE_SCHEMA_VERSION.to_string(),
            loss_matrix_id: self.loss_matrix_id.clone(),
            loss_matrix_hash: self.loss_matrix_hash,
            pricing_algorithm: CAPABILITY_LEASE_PRICING_ALGORITHM.to_string(),
            summaries,
            total_spend_millionths,
            total_receipts: self.receipts.len() as u64,
            artifact_hash_hex: String::new(),
        };
        report.artifact_hash_hex = report.recompute_artifact_hash_hex()?;
        Ok(report)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_receipt_hash_is_injective_across_id_field_boundary() {
        // bd-g52tf: receipt_id/lease_id/extension_id/capability/scope were
        // '|'-joined free-form strings, so (lease_id="a|b", extension_id="c") and
        // (lease_id="a", extension_id="b|c") produced the same preimage.
        // Length-prefixing each field pins them to distinct hashes.
        let mk = |lease_id: &str, extension_id: &str| {
            let receipt = LeaseUsageReceipt {
                schema_version: CAPABILITY_LEASE_SCHEMA_VERSION.to_string(),
                receipt_id: "r#0".to_string(),
                lease_id: lease_id.to_string(),
                extension_id: extension_id.to_string(),
                requester_extension_id: extension_id.to_string(),
                capability: "cap".to_string(),
                requested_capability: "cap".to_string(),
                scope: "scope".to_string(),
                loss_matrix_id: "balanced-v1".to_string(),
                loss_matrix_hash: LossMatrix::balanced().content_hash(),
                pricing_algorithm: CAPABILITY_LEASE_PRICING_ALGORITHM.to_string(),
                tick: 0,
                p_malicious_millionths: 0,
                risk_price_millionths: 0,
                decision_kind: "allow".to_string(),
                denial_reason: None,
                remaining_budget_millionths: 0,
                policy_epoch: 0,
                content_hash: ContentHash::compute(b"placeholder"),
            };
            receipt.compute_hash()
        };
        assert_ne!(
            mk("a|b", "c"),
            mk("a", "b|c"),
            "lease_id/extension_id field boundary must not collide"
        );
    }

    #[test]
    fn lease_receipt_hash_binds_epoch_requested_capability_and_denial_reason() {
        let base = LeaseUsageReceipt {
            schema_version: CAPABILITY_LEASE_SCHEMA_VERSION.to_string(),
            receipt_id: "l1#1".to_string(),
            lease_id: "l1".to_string(),
            extension_id: "ext-alpha".to_string(),
            requester_extension_id: "ext-alpha".to_string(),
            capability: "network_egress".to_string(),
            requested_capability: "network_egress".to_string(),
            scope: "egress:api.example".to_string(),
            loss_matrix_id: "balanced-v1".to_string(),
            loss_matrix_hash: LossMatrix::balanced().content_hash(),
            pricing_algorithm: CAPABILITY_LEASE_PRICING_ALGORITHM.to_string(),
            tick: 7,
            p_malicious_millionths: 10_000,
            risk_price_millionths: 1_700_000,
            decision_kind: "denied".to_string(),
            denial_reason: Some(DenialReason::BudgetExhausted {
                risk_price_millionths: 1_700_000,
                remaining_budget_millionths: 0,
            }),
            remaining_budget_millionths: 0,
            policy_epoch: 3,
            content_hash: ContentHash::compute(b"placeholder"),
        };
        let base_hash = base.compute_hash();

        let mut changed = base.clone();
        changed.schema_version = "franken-engine.capability-lease.v5".to_string();
        assert_ne!(base_hash, changed.compute_hash(), "schema must be bound");

        changed = base.clone();
        changed.loss_matrix_id = "balanced-v2".to_string();
        assert_ne!(
            base_hash,
            changed.compute_hash(),
            "loss matrix id must be bound"
        );

        changed = base.clone();
        changed.loss_matrix_hash = ContentHash::compute(b"different matrix");
        assert_ne!(
            base_hash,
            changed.compute_hash(),
            "loss matrix content hash must be bound"
        );

        changed = base.clone();
        changed.pricing_algorithm = "expected-loss.aggregate-truncation-v2".to_string();
        assert_ne!(
            base_hash,
            changed.compute_hash(),
            "pricing algorithm must be bound"
        );

        changed = base.clone();
        changed.policy_epoch = 4;
        assert_ne!(base_hash, changed.compute_hash(), "epoch must be bound");

        changed = base.clone();
        changed.requested_capability = "fs_write".to_string();
        assert_ne!(
            base_hash,
            changed.compute_hash(),
            "requested capability must be bound"
        );

        changed = base.clone();
        changed.requester_extension_id = "ext-other".to_string();
        assert_ne!(
            base_hash,
            changed.compute_hash(),
            "requester extension identity must be bound"
        );

        changed = base.clone();
        changed.denial_reason = Some(DenialReason::LeaseRevoked);
        assert_ne!(
            base_hash,
            changed.compute_hash(),
            "exact denial reason must be bound"
        );

        let mut sealed = base;
        sealed.content_hash = base_hash;
        assert!(sealed.verify_content_hash());
        sealed.policy_epoch = 4;
        assert!(!sealed.verify_content_hash());
    }

    fn lease(lease_id: &str) -> CapabilityLease {
        CapabilityLease {
            lease_id: lease_id.to_string(),
            extension_id: "ext-alpha".to_string(),
            capability: RuntimeCapability::NetworkEgress,
            scope: "egress:api.example".to_string(),
            // Balanced-matrix benign Allow price is 1_700_000 millionths
            // (1.7 loss units); budgets are scaled to grant a couple of
            // uses per window.
            max_expected_loss_millionths: 10_000_000,
            challenge_threshold_millionths: 200_000,
            revoke_threshold_millionths: 600_000,
            budget_window_ticks: 100,
            window_budget_millionths: 4_000_000,
            policy_epoch: SecurityEpoch::from_raw(3),
        }
    }

    fn benign_posterior() -> Posterior {
        Posterior::from_millionths(950_000, 30_000, 10_000, 10_000)
    }

    fn elevated_posterior() -> Posterior {
        // p_malicious 0.25: above challenge (0.2), below revoke (0.6).
        Posterior::from_millionths(600_000, 100_000, 250_000, 50_000)
    }

    fn hostile_posterior() -> Posterior {
        // p_malicious 0.7: above revoke threshold.
        Posterior::from_millionths(100_000, 100_000, 700_000, 100_000)
    }

    fn manager_with(lease_value: CapabilityLease) -> LeaseManager {
        let mut manager = LeaseManager::balanced();
        manager
            .register_lease(lease_value)
            .expect("registration should succeed");
        manager
    }

    // ── validation & registration ────────────────────────────────────

    #[test]
    fn valid_lease_registers() {
        let mut manager = LeaseManager::balanced();
        assert!(manager.register_lease(lease("l1")).is_ok());
        assert_eq!(
            manager.lease_status("l1").expect("status should resolve"),
            CapabilityLeaseStatus::Active
        );
    }

    #[test]
    fn duplicate_lease_id_rejected() {
        let mut manager = manager_with(lease("l1"));
        assert!(matches!(
            manager.register_lease(lease("l1")),
            Err(CapabilityLeaseError::DuplicateLeaseId { .. })
        ));
    }

    #[test]
    fn blank_identity_and_scope_fields_are_rejected() {
        let mut bad = lease("l1");
        bad.lease_id = "   ".to_string();
        assert!(matches!(
            bad.validate(),
            Err(CapabilityLeaseError::InvalidLease { .. })
        ));

        let mut bad = lease("l1");
        bad.extension_id = "\t".to_string();
        assert!(matches!(
            bad.validate(),
            Err(CapabilityLeaseError::InvalidLease { .. })
        ));

        let mut bad = lease("l1");
        bad.scope = "\n".to_string();
        assert!(matches!(
            bad.validate(),
            Err(CapabilityLeaseError::InvalidLease { .. })
        ));
    }

    #[test]
    fn zero_window_rejected() {
        let mut bad = lease("l1");
        bad.budget_window_ticks = 0;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn negative_budget_rejected() {
        let mut bad = lease("l1");
        bad.window_budget_millionths = -1;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn threshold_out_of_range_rejected() {
        let mut bad = lease("l1");
        bad.revoke_threshold_millionths = MILLION + 1;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn challenge_above_revoke_rejected() {
        let mut bad = lease("l1");
        bad.challenge_threshold_millionths = 700_000;
        bad.revoke_threshold_millionths = 600_000;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn unknown_lease_is_an_error_not_a_decision() {
        let mut manager = LeaseManager::balanced();
        let result = manager.request_use(
            "ghost",
            "ext-alpha",
            RuntimeCapability::NetworkEgress,
            &benign_posterior(),
            0,
        );
        assert!(matches!(
            result,
            Err(CapabilityLeaseError::UnknownLeaseId { .. })
        ));
    }

    #[test]
    fn receipt_sequence_exhaustion_fails_before_lease_state_mutation() {
        let mut manager = manager_with(lease("full-sequence"));
        manager
            .leases
            .get_mut("full-sequence")
            .expect("registered lease state must exist")
            .receipt_count = u64::MAX;
        let before = manager
            .leases
            .get("full-sequence")
            .expect("registered lease state must exist")
            .clone();

        let error = manager
            .request_use(
                "full-sequence",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &benign_posterior(),
                1,
            )
            .expect_err("an exhausted receipt sequence must fail closed");

        assert_eq!(
            error,
            CapabilityLeaseError::ReceiptSequenceExhausted {
                lease_id: "full-sequence".to_string(),
            }
        );
        assert_eq!(
            manager
                .leases
                .get("full-sequence")
                .expect("registered lease state must remain present"),
            &before
        );
        assert!(manager.receipts().is_empty());
    }

    // ── pricing & granting ───────────────────────────────────────────

    #[test]
    fn grant_decrements_budget_by_allow_expected_loss() {
        let mut manager = manager_with(lease("l1"));
        let posterior = benign_posterior();
        let price = manager.risk_price_millionths(&posterior);
        assert!(price > 0, "balanced matrix must price benign Allow > 0");
        let decision = manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &posterior,
                1,
            )
            .expect("request should succeed");
        match decision {
            LeaseDecision::Granted {
                risk_price_millionths,
                remaining_budget_millionths,
            } => {
                assert_eq!(risk_price_millionths, price);
                assert_eq!(remaining_budget_millionths, 4_000_000 - price);
            }
            other => panic!("expected grant, got {other:?}"),
        }
    }

    #[test]
    fn incomplete_loss_matrix_is_undeliverable_even_with_maximum_budget() {
        let matrix: LossMatrix = serde_json::from_value(serde_json::json!({
            "matrix_id": "incomplete",
            "entries": []
        }))
        .expect("loss matrix JSON should deserialize");
        let mut permissive_lease = lease("l1");
        permissive_lease.max_expected_loss_millionths = i64::MAX;
        permissive_lease.window_budget_millionths = i64::MAX;
        let mut manager = LeaseManager::new(matrix);
        manager
            .register_lease(permissive_lease)
            .expect("lease should register");

        let pre_use_report = manager.report().expect("report should build");
        assert_eq!(pre_use_report.summaries[0].pricing_failures, 0);
        assert_eq!(
            pre_use_report.summaries[0].recommendation,
            LeaseRecommendation::RepairPricingInputs,
            "a fixed incomplete matrix is already an operator-visible failure"
        );

        assert_eq!(manager.risk_price_millionths(&benign_posterior()), i64::MAX);
        let decision = manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &benign_posterior(),
                1,
            )
            .expect("invalid pricing is a denial, not a manager error");
        assert_eq!(
            decision,
            LeaseDecision::Denied {
                reason: DenialReason::PricingUnavailable {
                    loss_matrix_id: "incomplete".to_string(),
                    pricing_reason: PricingUnavailableReason::IncompleteLossMatrix,
                }
            }
        );
        let receipt = &manager.receipts()[0];
        assert_eq!(receipt.risk_price_millionths, i64::MAX);
        assert_eq!(
            receipt.denial_reason,
            match decision {
                LeaseDecision::Denied { reason } => Some(reason),
                _ => None,
            }
        );
        assert!(receipt.verify_content_hash());
        let report = manager.report().expect("report should build");
        assert_eq!(report.summaries[0].budget_denials, 0);
        assert_eq!(report.summaries[0].capability_mismatches, 0);
        assert_eq!(report.summaries[0].pricing_failures, 1);
        assert_eq!(
            report.summaries[0].recommendation,
            LeaseRecommendation::RepairPricingInputs
        );
    }

    #[test]
    fn blank_loss_matrix_id_is_undeliverable_and_operator_visible() {
        let mut matrix = LossMatrix::balanced();
        matrix.matrix_id = " \t ".to_string();
        let mut manager = LeaseManager::new(matrix);
        manager
            .register_lease(lease("blank-matrix-id"))
            .expect("lease should register");

        let pre_use_report = manager.report().expect("report should build");
        assert_eq!(
            pre_use_report.summaries[0].recommendation,
            LeaseRecommendation::RepairPricingInputs
        );

        let decision = manager
            .request_use(
                "blank-matrix-id",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &benign_posterior(),
                1,
            )
            .expect("invalid pricing identity should deny");
        assert!(matches!(
            decision,
            LeaseDecision::Denied {
                reason: DenialReason::PricingUnavailable {
                    pricing_reason: PricingUnavailableReason::InvalidLossMatrixId,
                    ..
                }
            }
        ));
        assert!(manager.receipts()[0].verify_content_hash());
    }

    #[test]
    fn invalid_posterior_and_negative_allow_quote_fail_closed() {
        let malformed = Posterior {
            p_benign: 1_000_001,
            p_anomalous: 0,
            p_malicious: 0,
            p_unknown: -1,
        };
        let mut manager = manager_with(lease("invalid-posterior"));
        let decision = manager
            .request_use(
                "invalid-posterior",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &malformed,
                1,
            )
            .expect("invalid posterior should produce a denial");
        assert!(matches!(
            decision,
            LeaseDecision::Denied {
                reason: DenialReason::PricingUnavailable {
                    pricing_reason: PricingUnavailableReason::InvalidPosterior,
                    ..
                }
            }
        ));

        let malformed_high_risk = Posterior {
            p_benign: -1,
            p_anomalous: 0,
            p_malicious: MILLION + 1,
            p_unknown: 0,
        };
        let mut manager = manager_with(lease("invalid-high-risk"));
        let decision = manager
            .request_use(
                "invalid-high-risk",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &malformed_high_risk,
                1,
            )
            .expect("invalid posterior should deny without changing lease status");
        assert!(matches!(
            decision,
            LeaseDecision::Denied {
                reason: DenialReason::PricingUnavailable {
                    pricing_reason: PricingUnavailableReason::InvalidPosterior,
                    ..
                }
            }
        ));
        assert_eq!(
            manager
                .lease_status("invalid-high-risk")
                .expect("lease should remain registered"),
            CapabilityLeaseStatus::Active,
            "an invalid p_malicious value must not revoke the lease"
        );

        let denial_json = serde_json::to_value(&decision).expect("denial should serialize");
        assert_eq!(denial_json["decision"], "denied");
        assert_eq!(denial_json["reason"]["reason"], "pricing_unavailable");
        assert_eq!(denial_json["reason"]["pricing_reason"], "invalid_posterior");
        let denial_round_trip: LeaseDecision =
            serde_json::from_value(denial_json).expect("pricing denial should deserialize");
        assert_eq!(denial_round_trip, decision);

        use crate::bayesian_posterior::RiskState;
        use crate::expected_loss_selector::LossEntry;
        let entries = ContainmentAction::ALL
            .iter()
            .flat_map(|action| {
                RiskState::ALL.iter().map(move |state| LossEntry {
                    action: *action,
                    state: *state,
                    loss_millionths: -MILLION,
                })
            })
            .collect();
        let mut manager = LeaseManager::new(LossMatrix::new("negative-allow", entries));
        manager
            .register_lease(lease("negative-allow"))
            .expect("lease should register");
        let decision = manager
            .request_use(
                "negative-allow",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &benign_posterior(),
                1,
            )
            .expect("negative pricing should produce a denial");
        assert!(matches!(
            decision,
            LeaseDecision::Denied {
                reason: DenialReason::PricingUnavailable {
                    pricing_reason: PricingUnavailableReason::UndeliverableAllowLoss,
                    ..
                }
            }
        ));
    }

    #[test]
    fn hostile_posterior_prices_higher_than_benign() {
        let manager = manager_with(lease("l1"));
        let benign_price = manager.risk_price_millionths(&benign_posterior());
        let hostile_price = manager.risk_price_millionths(&hostile_posterior());
        assert!(
            hostile_price > benign_price,
            "allowing under hostility must cost more ({hostile_price} <= {benign_price})"
        );
    }

    #[test]
    fn aggregate_micro_loss_cannot_bypass_zero_budget() {
        use crate::bayesian_posterior::RiskState;
        use crate::expected_loss_selector::LossEntry;

        let entries = ContainmentAction::ALL
            .iter()
            .flat_map(|action| {
                RiskState::ALL.iter().map(move |state| LossEntry {
                    action: *action,
                    state: *state,
                    loss_millionths: 1,
                })
            })
            .collect();
        let mut zero_budget = lease("micro-loss");
        zero_budget.window_budget_millionths = 0;
        zero_budget.challenge_threshold_millionths = MILLION;
        zero_budget.revoke_threshold_millionths = MILLION;
        let mut manager = LeaseManager::new(LossMatrix::new("micro-loss", entries));
        manager
            .register_lease(zero_budget)
            .expect("lease should register");

        let posterior = Posterior::uniform();
        assert_eq!(manager.risk_price_millionths(&posterior), 1);
        let decision = manager
            .request_use(
                "micro-loss",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &posterior,
                1,
            )
            .expect("priced request should produce a decision");
        assert_eq!(
            decision,
            LeaseDecision::Denied {
                reason: DenialReason::BudgetExhausted {
                    risk_price_millionths: 1,
                    remaining_budget_millionths: 0,
                }
            }
        );
    }

    #[test]
    fn budget_exhaustion_denies_with_receipt() {
        let mut manager = manager_with(lease("l1"));
        let posterior = benign_posterior();
        let price = manager.risk_price_millionths(&posterior);
        assert!(price > 0, "benign Allow must carry a nonzero price");
        let affordable_uses = 4_000_000 / price;
        assert!(affordable_uses >= 1, "fixture must afford at least one use");
        for index in 0..affordable_uses {
            let decision = manager
                .request_use(
                    "l1",
                    "ext-alpha",
                    RuntimeCapability::NetworkEgress,
                    &posterior,
                    1,
                )
                .expect("request should succeed");
            assert!(
                matches!(decision, LeaseDecision::Granted { .. }),
                "use {index} should grant"
            );
        }
        let denied = manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &posterior,
                1,
            )
            .expect("request should succeed");
        assert!(matches!(
            denied,
            LeaseDecision::Denied {
                reason: DenialReason::BudgetExhausted { .. }
            }
        ));
        assert_eq!(
            manager.receipts().len(),
            (affordable_uses + 1) as usize,
            "every decision must emit a receipt"
        );
        let report = manager.report().expect("report should build");
        assert_eq!(report.summaries[0].budget_denials, 1);
        assert_eq!(report.summaries[0].capability_mismatches, 0);
        assert_eq!(report.summaries[0].extension_mismatches, 0);
        assert_eq!(report.summaries[0].tick_regressions, 0);
    }

    #[test]
    fn per_use_ceiling_denies_expensive_single_use() {
        let mut capped = lease("l1");
        capped.max_expected_loss_millionths = 1; // essentially nothing fits
        let mut manager = manager_with(capped);
        let decision = manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &benign_posterior(),
                1,
            )
            .expect("request should succeed");
        assert!(matches!(
            decision,
            LeaseDecision::Denied {
                reason: DenialReason::PerUseCeilingExceeded { .. }
            }
        ));
    }

    #[test]
    fn capability_mismatch_denies_fail_closed() {
        let mut manager = manager_with(lease("l1"));
        let decision = manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::FsWrite,
                &benign_posterior(),
                1,
            )
            .expect("request should succeed");
        assert!(matches!(
            decision,
            LeaseDecision::Denied {
                reason: DenialReason::CapabilityMismatch { .. }
            }
        ));
        let receipt = &manager.receipts()[0];
        assert_eq!(receipt.capability, "network_egress");
        assert_eq!(receipt.requested_capability, "fs_write");
        assert_eq!(
            receipt.denial_reason,
            Some(DenialReason::CapabilityMismatch {
                requested: "fs_write".to_string(),
                leased: "network_egress".to_string(),
            })
        );
        assert!(receipt.verify_content_hash());
        let report = manager.report().expect("report should build");
        assert_eq!(report.summaries[0].budget_denials, 0);
        assert_eq!(report.summaries[0].capability_mismatches, 1);
        assert_eq!(report.summaries[0].extension_mismatches, 0);
        assert_eq!(
            report.summaries[0].recommendation,
            LeaseRecommendation::ReviewCapabilityMismatch
        );
    }

    #[test]
    fn extension_mismatch_cannot_advance_or_reset_the_lease_window() {
        let mut narrow = lease("l1");
        narrow.window_budget_millionths = 2_000_000;
        narrow.budget_window_ticks = 10;
        let mut manager = manager_with(narrow);
        let posterior = benign_posterior();

        let remaining_after_grant = match manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &posterior,
                1,
            )
            .expect("authorized request should succeed")
        {
            LeaseDecision::Granted {
                remaining_budget_millionths,
                ..
            } => remaining_budget_millionths,
            other => panic!("expected grant, got {other:?}"),
        };

        let mismatch = manager
            .request_use(
                "l1",
                "ext-other",
                RuntimeCapability::NetworkEgress,
                &posterior,
                10,
            )
            .expect("identity mismatch should produce a denial");
        assert_eq!(
            mismatch,
            LeaseDecision::Denied {
                reason: DenialReason::ExtensionMismatch {
                    requested: "ext-other".to_string(),
                    leased: "ext-alpha".to_string(),
                },
            }
        );
        let mismatch_receipt = &manager.receipts()[1];
        assert_eq!(mismatch_receipt.requester_extension_id, "ext-other");
        assert_eq!(
            mismatch_receipt.remaining_budget_millionths, remaining_after_grant,
            "an unauthorized future tick must not reset the victim's budget"
        );
        assert!(mismatch_receipt.verify_content_hash());

        let still_exhausted = manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &posterior,
                5,
            )
            .expect("authorized request should still produce a decision");
        assert!(matches!(
            still_exhausted,
            LeaseDecision::Denied {
                reason: DenialReason::BudgetExhausted { .. }
            }
        ));

        let report = manager.report().expect("report should build");
        let summary = &report.summaries[0];
        assert_eq!(summary.extension_mismatches, 1);
        assert_eq!(summary.capability_mismatches, 0);
        assert_eq!(summary.tick_regressions, 0);
        assert_eq!(
            summary.recommendation,
            LeaseRecommendation::ReviewExtensionMismatch
        );
    }

    // ── thresholds ───────────────────────────────────────────────────

    #[test]
    fn challenge_fires_at_threshold_without_spending() {
        let mut manager = manager_with(lease("l1"));
        let decision = manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &elevated_posterior(),
                1,
            )
            .expect("request should succeed");
        assert!(matches!(decision, LeaseDecision::ChallengeRequired { .. }));
        let report = manager.report().expect("report should build");
        assert_eq!(report.summaries[0].spend_total_millionths, 0);
        assert_eq!(report.summaries[0].challenges, 1);
    }

    #[test]
    fn revoke_fires_at_threshold_and_sticks() {
        let mut manager = manager_with(lease("l1"));
        let revoked = manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &hostile_posterior(),
                1,
            )
            .expect("request should succeed");
        assert!(matches!(revoked, LeaseDecision::Revoked { .. }));
        assert_eq!(
            manager.lease_status("l1").expect("status should resolve"),
            CapabilityLeaseStatus::Revoked
        );
        // Subsequent uses are denied even under a benign posterior.
        let after = manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &benign_posterior(),
                2,
            )
            .expect("request should succeed");
        assert!(matches!(
            after,
            LeaseDecision::Denied {
                reason: DenialReason::LeaseRevoked
            }
        ));
    }

    #[test]
    fn exact_challenge_threshold_triggers_challenge() {
        let mut manager = manager_with(lease("l1"));
        // p_malicious exactly 0.2 (the lease threshold).
        let posterior = Posterior::from_millionths(700_000, 50_000, 200_000, 50_000);
        let decision = manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &posterior,
                1,
            )
            .expect("request should succeed");
        assert!(matches!(decision, LeaseDecision::ChallengeRequired { .. }));
    }

    // ── budget window ────────────────────────────────────────────────

    #[test]
    fn window_rollover_restores_budget() {
        let mut narrow = lease("l1");
        narrow.window_budget_millionths = 2_000_000; // exactly one benign use
        narrow.budget_window_ticks = 10;
        let mut manager = manager_with(narrow);
        let posterior = benign_posterior();
        let price = manager.risk_price_millionths(&posterior);
        assert!(price > 0, "benign Allow must carry a nonzero price");
        let affordable_uses = 2_000_000 / price;
        assert!(affordable_uses >= 1, "fixture must afford at least one use");
        for _ in 0..affordable_uses {
            manager
                .request_use(
                    "l1",
                    "ext-alpha",
                    RuntimeCapability::NetworkEgress,
                    &posterior,
                    1,
                )
                .expect("request should succeed");
        }
        let denied = manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &posterior,
                5,
            )
            .expect("request should succeed");
        assert!(matches!(denied, LeaseDecision::Denied { .. }));
        // Tick 10 starts a new window: budget restored.
        let granted = manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &posterior,
                10,
            )
            .expect("request should succeed");
        assert!(matches!(granted, LeaseDecision::Granted { .. }));
    }

    #[test]
    fn window_rollover_spans_multiple_elapsed_windows() {
        let mut narrow = lease("l1");
        narrow.budget_window_ticks = 10;
        let mut manager = manager_with(narrow);
        let posterior = benign_posterior();
        manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &posterior,
                95,
            )
            .expect("request should succeed");
        // Window start must land on the 90..100 window, not drift.
        let granted = manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &posterior,
                99,
            )
            .expect("request should succeed");
        assert!(matches!(granted, LeaseDecision::Granted { .. }));
    }

    #[test]
    fn decreasing_ticks_are_receipted_denials_without_budget_mutation() {
        let mut narrow = lease("l1");
        narrow.window_budget_millionths = 2_000_000;
        narrow.budget_window_ticks = 10;
        let mut manager = manager_with(narrow);
        let posterior = benign_posterior();

        let remaining_after_grant = match manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &posterior,
                10,
            )
            .expect("first request should succeed")
        {
            LeaseDecision::Granted {
                remaining_budget_millionths,
                ..
            } => remaining_budget_millionths,
            other => panic!("expected grant, got {other:?}"),
        };

        for _ in 0..2 {
            let regressed = manager
                .request_use(
                    "l1",
                    "ext-alpha",
                    RuntimeCapability::NetworkEgress,
                    &posterior,
                    9,
                )
                .expect("clock regression should produce a denial");
            assert_eq!(
                regressed,
                LeaseDecision::Denied {
                    reason: DenialReason::NonMonotonicTick {
                        previous_tick: 10,
                        requested_tick: 9,
                    },
                }
            );
            let receipt = manager.receipts().last().expect("receipt must exist");
            assert_eq!(receipt.remaining_budget_millionths, remaining_after_grant);
            assert!(receipt.verify_content_hash());
        }

        let report = manager.report().expect("report should build");
        let summary = &report.summaries[0];
        assert_eq!(summary.tick_regressions, 2);
        assert_eq!(summary.uses_granted, 1);
        assert_eq!(summary.remaining_budget_millionths, remaining_after_grant);
        assert_eq!(
            summary.recommendation,
            LeaseRecommendation::RepairLogicalClock
        );
    }

    // ── receipts ─────────────────────────────────────────────────────

    #[test]
    fn receipts_are_sequential_and_hash_stable() {
        let mut manager = manager_with(lease("l1"));
        let posterior = benign_posterior();
        manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &posterior,
                1,
            )
            .expect("request should succeed");
        manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &posterior,
                2,
            )
            .expect("request should succeed");
        let receipts = manager.receipts();
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].receipt_id, "l1#1");
        assert_eq!(receipts[1].receipt_id, "l1#2");
        for receipt in receipts {
            assert_eq!(receipt.schema_version, CAPABILITY_LEASE_SCHEMA_VERSION);
            assert_eq!(receipt.loss_matrix_id, "balanced-v1");
            assert_eq!(
                receipt.loss_matrix_hash,
                LossMatrix::balanced().content_hash()
            );
            assert_eq!(
                receipt.pricing_algorithm,
                CAPABILITY_LEASE_PRICING_ALGORITHM
            );
            assert_eq!(receipt.content_hash, receipt.compute_hash());
        }
    }

    #[test]
    fn every_decision_kind_emits_a_receipt() {
        let mut manager = manager_with(lease("l1"));
        manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &benign_posterior(),
                1,
            )
            .expect("grant");
        manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &elevated_posterior(),
                2,
            )
            .expect("challenge");
        manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::FsWrite,
                &benign_posterior(),
                3,
            )
            .expect("mismatch denial");
        manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &hostile_posterior(),
                4,
            )
            .expect("revocation");
        let kinds: Vec<&str> = manager
            .receipts()
            .iter()
            .map(|receipt| receipt.decision_kind.as_str())
            .collect();
        assert_eq!(
            kinds,
            vec!["granted", "challenge_required", "denied", "revoked"]
        );
    }

    #[test]
    fn identical_runs_produce_identical_receipts() {
        let run = || {
            let mut manager = manager_with(lease("l1"));
            let posterior = benign_posterior();
            manager
                .request_use(
                    "l1",
                    "ext-alpha",
                    RuntimeCapability::NetworkEgress,
                    &posterior,
                    1,
                )
                .expect("request should succeed");
            manager
                .request_use(
                    "l1",
                    "ext-alpha",
                    RuntimeCapability::NetworkEgress,
                    &posterior,
                    2,
                )
                .expect("request should succeed");
            manager.receipts().to_vec()
        };
        assert_eq!(run(), run());
    }

    // ── report ───────────────────────────────────────────────────────

    #[test]
    fn report_summarizes_spend_and_events() {
        let mut manager = manager_with(lease("l1"));
        manager
            .register_lease({
                let mut second = lease("l2");
                second.extension_id = "ext-beta".to_string();
                second
            })
            .expect("registration should succeed");
        let posterior = benign_posterior();
        manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &posterior,
                1,
            )
            .expect("request should succeed");
        let report = manager.report().expect("report should build");
        assert_eq!(report.schema_version, CAPABILITY_LEASE_SCHEMA_VERSION);
        assert_eq!(report.summaries.len(), 2);
        assert_eq!(report.summaries[0].lease_id, "l1");
        assert_eq!(report.summaries[1].lease_id, "l2");
        assert!(report.total_spend_millionths > 0);
        assert_eq!(report.total_receipts, 1);
        assert_eq!(report.loss_matrix_id, "balanced-v1".to_string());
        assert_eq!(
            report.loss_matrix_hash,
            LossMatrix::balanced().content_hash()
        );
        assert_eq!(report.pricing_algorithm, CAPABILITY_LEASE_PRICING_ALGORITHM);
    }

    #[test]
    fn report_recommendations_follow_fixed_rules() {
        let mut manager = manager_with(lease("revoked"));
        manager
            .register_lease(lease("challenged-only"))
            .expect("ok");
        manager
            .register_lease({
                let mut tight = lease("budget-denied");
                tight.max_expected_loss_millionths = 1; // nothing fits
                tight
            })
            .expect("ok");
        manager.register_lease(lease("idle")).expect("ok");
        manager.register_lease(lease("healthy")).expect("ok");
        manager.register_lease(lease("mismatch")).expect("ok");
        manager
            .register_lease(lease("pricing-invalid"))
            .expect("ok");

        manager
            .request_use(
                "revoked",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &hostile_posterior(),
                1,
            )
            .expect("revocation");
        manager
            .request_use(
                "challenged-only",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &elevated_posterior(),
                1,
            )
            .expect("challenge");
        manager
            .request_use(
                "budget-denied",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &benign_posterior(),
                1,
            )
            .expect("denial");
        manager
            .request_use(
                "healthy",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &benign_posterior(),
                1,
            )
            .expect("grant");
        manager
            .request_use(
                "mismatch",
                "ext-alpha",
                RuntimeCapability::FsWrite,
                &benign_posterior(),
                1,
            )
            .expect("mismatch denial");
        manager
            .request_use(
                "pricing-invalid",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &Posterior {
                    p_benign: 1_000_001,
                    p_anomalous: 0,
                    p_malicious: 0,
                    p_unknown: -1,
                },
                1,
            )
            .expect("invalid pricing should deny");

        let report = manager.report().expect("report should build");
        let recommendation_of = |id: &str| {
            report
                .summaries
                .iter()
                .find(|summary| summary.lease_id == id)
                .map(|summary| summary.recommendation)
                .expect("summary should exist")
        };
        assert_eq!(
            recommendation_of("revoked"),
            LeaseRecommendation::ReviewBeforeRenewal
        );
        assert_eq!(
            recommendation_of("challenged-only"),
            LeaseRecommendation::NarrowScope
        );
        assert_eq!(
            recommendation_of("budget-denied"),
            LeaseRecommendation::RevisitBudget
        );
        assert_eq!(
            recommendation_of("idle"),
            LeaseRecommendation::ConsiderRevokingIdle
        );
        assert_eq!(recommendation_of("healthy"), LeaseRecommendation::KeepAsIs);
        assert_eq!(
            recommendation_of("mismatch"),
            LeaseRecommendation::ReviewCapabilityMismatch
        );
        assert_eq!(
            recommendation_of("pricing-invalid"),
            LeaseRecommendation::RepairPricingInputs
        );
    }

    #[test]
    fn report_hash_is_deterministic_and_self_consistent() {
        let build = || {
            let mut manager = manager_with(lease("l1"));
            manager
                .request_use(
                    "l1",
                    "ext-alpha",
                    RuntimeCapability::NetworkEgress,
                    &benign_posterior(),
                    1,
                )
                .expect("request should succeed");
            manager.report().expect("report should build")
        };
        let first = build();
        let second = build();
        assert_eq!(first, second);
        assert_eq!(first.artifact_hash_hex.len(), 64);
        assert!(
            first
                .verify_artifact_hash()
                .expect("report verification should serialize")
        );

        let mut tampered = first;
        tampered.summaries[0].remaining_budget_millionths = tampered.summaries[0]
            .remaining_budget_millionths
            .saturating_add(1);
        assert!(
            !tampered
                .verify_artifact_hash()
                .expect("tampered report verification should serialize")
        );
    }

    // ── serde ────────────────────────────────────────────────────────

    #[test]
    fn lease_receipt_and_report_serde_round_trip() {
        let mut manager = manager_with(lease("l1"));
        manager
            .request_use(
                "l1",
                "ext-alpha",
                RuntimeCapability::NetworkEgress,
                &benign_posterior(),
                1,
            )
            .expect("request should succeed");
        let report = manager.report().expect("report should build");

        let lease_json = serde_json::to_string(&lease("l1")).expect("serialize lease");
        let lease_decoded: CapabilityLease =
            serde_json::from_str(&lease_json).expect("deserialize lease");
        assert_eq!(lease_decoded, lease("l1"));

        let receipt = manager.receipts()[0].clone();
        let receipt_json = serde_json::to_string(&receipt).expect("serialize receipt");
        let receipt_decoded: LeaseUsageReceipt =
            serde_json::from_str(&receipt_json).expect("deserialize receipt");
        assert_eq!(receipt_decoded, receipt);

        let report_json = serde_json::to_string(&report).expect("serialize report");
        let report_decoded: LeaseReport =
            serde_json::from_str(&report_json).expect("deserialize report");
        assert_eq!(report_decoded, report);
    }

    #[test]
    fn error_display_is_specific() {
        let cases = [
            CapabilityLeaseError::DuplicateLeaseId {
                lease_id: "x".to_string(),
            },
            CapabilityLeaseError::UnknownLeaseId {
                lease_id: "y".to_string(),
            },
            CapabilityLeaseError::InvalidLease {
                lease_id: "z".to_string(),
                detail: "broken".to_string(),
            },
            CapabilityLeaseError::ReceiptSequenceExhausted {
                lease_id: "full".to_string(),
            },
            CapabilityLeaseError::Serialization {
                detail: "io".to_string(),
            },
        ];
        for case in cases {
            assert!(!case.to_string().is_empty());
        }
    }
}
