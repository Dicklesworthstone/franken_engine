#![allow(clippy::doc_markdown)]

//! Consume resource certificates in scheduler, GC, module, and specialization budgets.
//!
//! This module wires AARA resource certificates into runtime budget enforcement
//! points: scheduler admission, GC pacing, module-load gating, specialization
//! admission, and hostcall exhaustion monitoring. Every enforcement decision
//! produces an auditable receipt with explicit reason codes.
//!
//! ## Key Concepts
//!
//! - **BudgetEnforcer**: Stateful enforcer that consumes certificates and
//!   gates runtime operations against resource bounds.
//! - **EnforcementDecision**: The routing for each budget check: allow,
//!   throttle, or reject, with user-visible reason codes.
//! - **EnforcementReceipt**: Content-addressed, epoch-scoped audit record.
//! - **DimensionBudget**: Per-dimension runtime budget derived from certificates.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Module component name for diagnostics.
pub const COMPONENT: &str = "resource_certificate_consumer";

/// Schema version for enforcement artifacts.
pub const ENFORCEMENT_SCHEMA_VERSION: &str = "1.0.0";

/// Default headroom fraction (millionths) — enforcement triggers at 90% of bound.
pub const DEFAULT_THROTTLE_THRESHOLD_MILLIONTHS: u64 = 900_000;

/// Default hard-reject fraction (millionths) — enforcement rejects at 100% of bound.
pub const DEFAULT_REJECT_THRESHOLD_MILLIONTHS: u64 = 1_000_000;

/// Default minimum certificate confidence for enforcement (millionths).
pub const DEFAULT_MIN_CONFIDENCE_MILLIONTHS: i64 = 900_000;

/// Maximum tracked extensions per enforcer.
pub const DEFAULT_MAX_EXTENSIONS: usize = 1024;

/// Maximum receipts retained before oldest are discarded.
pub const DEFAULT_MAX_RECEIPTS: usize = 4096;

/// Millionths denominator.
pub const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// ResourceDimension (local mirror for pattern matching)
// ---------------------------------------------------------------------------

/// Resource dimensions that can be budget-enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EnforcedDimension {
    /// Wall-clock time budget (nanoseconds).
    Time,
    /// Heap memory allocation budget (bytes).
    HeapMemory,
    /// Stack depth budget (frames).
    StackDepth,
    /// Hostcall invocation count.
    HostcallCount,
    /// GC pressure budget (allocation rate bytes/s).
    GcPressure,
    /// Module load count.
    ModuleLoadCount,
    /// I/O operation count.
    IoOperationCount,
}

impl fmt::Display for EnforcedDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Time => write!(f, "time"),
            Self::HeapMemory => write!(f, "heap_memory"),
            Self::StackDepth => write!(f, "stack_depth"),
            Self::HostcallCount => write!(f, "hostcall_count"),
            Self::GcPressure => write!(f, "gc_pressure"),
            Self::ModuleLoadCount => write!(f, "module_load_count"),
            Self::IoOperationCount => write!(f, "io_operation_count"),
        }
    }
}

// ---------------------------------------------------------------------------
// BudgetEnforcementPolicy — configuration
// ---------------------------------------------------------------------------

/// Configuration for budget enforcement behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetEnforcementPolicy {
    /// Threshold (millionths of bound) at which throttling begins.
    pub throttle_threshold_millionths: u64,
    /// Threshold (millionths of bound) at which hard reject triggers.
    pub reject_threshold_millionths: u64,
    /// Minimum certificate confidence to accept (millionths).
    pub min_confidence_millionths: i64,
    /// Maximum tracked extensions.
    pub max_extensions: usize,
    /// Maximum retained receipts.
    pub max_receipts: usize,
    /// Dimensions to enforce (empty = enforce all present).
    pub enforced_dimensions: BTreeSet<EnforcedDimension>,
    /// Whether to fail-closed on missing certificates.
    pub fail_closed_on_missing: bool,
    /// Whether to fail-closed on abstained certificates.
    pub fail_closed_on_abstention: bool,
    /// Whether to emit detailed violation reasons.
    pub emit_violation_details: bool,
}

impl Default for BudgetEnforcementPolicy {
    fn default() -> Self {
        Self {
            throttle_threshold_millionths: DEFAULT_THROTTLE_THRESHOLD_MILLIONTHS,
            reject_threshold_millionths: DEFAULT_REJECT_THRESHOLD_MILLIONTHS,
            min_confidence_millionths: DEFAULT_MIN_CONFIDENCE_MILLIONTHS,
            max_extensions: DEFAULT_MAX_EXTENSIONS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            enforced_dimensions: BTreeSet::new(),
            fail_closed_on_missing: true,
            fail_closed_on_abstention: true,
            emit_violation_details: true,
        }
    }
}

impl BudgetEnforcementPolicy {
    /// Compute a deterministic hash of this policy.
    pub fn policy_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"BudgetEnforcementPolicy.v1");
        hasher.update(self.throttle_threshold_millionths.to_le_bytes());
        hasher.update(self.reject_threshold_millionths.to_le_bytes());
        hasher.update(self.min_confidence_millionths.to_le_bytes());
        hasher.update(self.max_extensions.to_le_bytes());
        hasher.update(self.max_receipts.to_le_bytes());
        hasher.update([u8::from(self.fail_closed_on_missing)]);
        hasher.update([u8::from(self.fail_closed_on_abstention)]);
        for dim in &self.enforced_dimensions {
            hasher.update(dim.to_string().as_bytes());
        }
        let digest = hasher.finalize();
        hex::encode(digest)
    }

    /// Whether a dimension should be enforced.
    pub fn should_enforce(&self, dim: EnforcedDimension) -> bool {
        self.enforced_dimensions.is_empty() || self.enforced_dimensions.contains(&dim)
    }
}

// ---------------------------------------------------------------------------
// DimensionBudget — per-dimension runtime budget derived from certificates
// ---------------------------------------------------------------------------

/// A runtime budget derived from a resource certificate bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DimensionBudget {
    /// The resource dimension.
    pub dimension: EnforcedDimension,
    /// Upper bound in millionths (from certificate).
    pub upper_bound_millionths: i64,
    /// Whether the bound is tight (exact analysis).
    pub is_tight: bool,
    /// Confidence in the bound (millionths).
    pub confidence_millionths: i64,
    /// Current usage in millionths.
    pub current_usage_millionths: i64,
    /// Certificate ID that produced this budget.
    pub source_certificate_id: String,
    /// Extension ID this budget applies to.
    pub extension_id: String,
}

impl DimensionBudget {
    /// Usage as a fraction of the upper bound (millionths).
    pub fn usage_ratio_millionths(&self) -> u64 {
        if self.upper_bound_millionths <= 0 {
            return MILLIONTHS;
        }
        let usage = self.current_usage_millionths.max(0) as u64;
        let bound = self.upper_bound_millionths as u64;
        usage
            .saturating_mul(MILLIONTHS)
            .checked_div(bound)
            .unwrap_or(MILLIONTHS)
    }

    /// Record additional usage.
    pub fn record_usage(&mut self, amount_millionths: i64) {
        self.current_usage_millionths = self
            .current_usage_millionths
            .saturating_add(amount_millionths);
    }

    /// Remaining budget in millionths.
    pub fn remaining_millionths(&self) -> i64 {
        self.upper_bound_millionths
            .saturating_sub(self.current_usage_millionths)
    }

    /// Whether budget is exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.current_usage_millionths >= self.upper_bound_millionths
    }
}

// ---------------------------------------------------------------------------
// EnforcementDecision — the routing for each budget check
// ---------------------------------------------------------------------------

/// The enforcement routing decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnforcementDecision {
    /// Operation allowed — within budget.
    Allow,
    /// Operation throttled — approaching budget limit.
    Throttle {
        /// Usage ratio that triggered throttling (millionths).
        usage_ratio_millionths: u64,
        /// The dimension being throttled.
        dimension: EnforcedDimension,
    },
    /// Operation rejected — budget exceeded or policy violation.
    Reject {
        /// Rejection reason.
        reason: BudgetViolationReason,
    },
}

impl fmt::Display for EnforcementDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Throttle {
                usage_ratio_millionths,
                dimension,
            } => write!(
                f,
                "throttle({}, {}%)",
                dimension,
                usage_ratio_millionths / 10_000
            ),
            Self::Reject { reason } => write!(f, "reject({})", reason),
        }
    }
}

// ---------------------------------------------------------------------------
// BudgetViolationReason — why enforcement acted
// ---------------------------------------------------------------------------

/// Reasons for budget enforcement action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetViolationReason {
    /// Budget exceeded for a dimension.
    BudgetExceeded {
        dimension: EnforcedDimension,
        usage_millionths: i64,
        bound_millionths: i64,
    },
    /// No certificate found for the extension.
    NoCertificate { extension_id: String },
    /// Usage targeted an enforced dimension that has no installed budget.
    MissingBudgetDimensions {
        extension_id: String,
        dimensions: Vec<EnforcedDimension>,
    },
    /// Certificate verdict is Abstained.
    CertificateAbstained {
        certificate_id: String,
        abstention_count: usize,
    },
    /// Certificate verdict is Violated.
    CertificateViolated { certificate_id: String },
    /// Certificate confidence below threshold.
    InsufficientConfidence {
        certificate_id: String,
        actual_millionths: i64,
        required_millionths: i64,
    },
    /// Certificate epoch does not match current epoch.
    EpochMismatch {
        certificate_epoch: u64,
        current_epoch: u64,
    },
    /// Extension limit exceeded.
    ExtensionLimitExceeded { current: usize, max: usize },
    /// Multiple dimensions exceeded simultaneously.
    MultipleDimensionsExceeded { dimensions: Vec<EnforcedDimension> },
}

impl fmt::Display for BudgetViolationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExceeded {
                dimension,
                usage_millionths,
                bound_millionths,
            } => write!(
                f,
                "budget_exceeded({}, {}/{})",
                dimension, usage_millionths, bound_millionths
            ),
            Self::NoCertificate { extension_id } => {
                write!(f, "no_certificate({})", extension_id)
            }
            Self::MissingBudgetDimensions {
                extension_id,
                dimensions,
            } => {
                let names: Vec<String> = dimensions.iter().map(|d| d.to_string()).collect();
                write!(f, "missing_budget({}: {})", extension_id, names.join(","))
            }
            Self::CertificateAbstained {
                certificate_id,
                abstention_count,
            } => write!(
                f,
                "abstained({}, {} points)",
                certificate_id, abstention_count
            ),
            Self::CertificateViolated { certificate_id } => {
                write!(f, "violated({})", certificate_id)
            }
            Self::InsufficientConfidence {
                actual_millionths,
                required_millionths,
                ..
            } => write!(
                f,
                "low_confidence({}/{})",
                actual_millionths, required_millionths
            ),
            Self::EpochMismatch {
                certificate_epoch,
                current_epoch,
            } => write!(
                f,
                "epoch_mismatch({}!={})",
                certificate_epoch, current_epoch
            ),
            Self::ExtensionLimitExceeded { current, max } => {
                write!(f, "extension_limit({}/{})", current, max)
            }
            Self::MultipleDimensionsExceeded { dimensions } => {
                let names: Vec<String> = dimensions.iter().map(|d| d.to_string()).collect();
                write!(f, "multi_exceeded({})", names.join(","))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EnforcementScope — what operation was checked
// ---------------------------------------------------------------------------

/// The scope of a budget enforcement check.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EnforcementScope {
    /// Scheduler task admission.
    SchedulerAdmission { task_type: String },
    /// GC cycle pacing.
    GcPacing { extension_id: String },
    /// Module load gating.
    ModuleLoad { specifier: String },
    /// Specialization admission.
    SpecializationAdmission { receipt_id: String },
    /// Hostcall invocation.
    HostcallInvocation { hostcall_id: String },
    /// I/O operation.
    IoOperation { operation_type: String },
    /// General budget check.
    General { description: String },
}

impl fmt::Display for EnforcementScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchedulerAdmission { task_type } => {
                write!(f, "scheduler({})", task_type)
            }
            Self::GcPacing { extension_id } => write!(f, "gc({})", extension_id),
            Self::ModuleLoad { specifier } => write!(f, "module({})", specifier),
            Self::SpecializationAdmission { receipt_id } => {
                write!(f, "specialization({})", receipt_id)
            }
            Self::HostcallInvocation { hostcall_id } => {
                write!(f, "hostcall({})", hostcall_id)
            }
            Self::IoOperation { operation_type } => write!(f, "io({})", operation_type),
            Self::General { description } => write!(f, "general({})", description),
        }
    }
}

// ---------------------------------------------------------------------------
// EnforcementReceipt — auditable decision record
// ---------------------------------------------------------------------------

/// Auditable receipt for a budget enforcement decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementReceipt {
    /// Content-addressed receipt identifier.
    pub receipt_id: String,
    /// Extension being checked.
    pub extension_id: String,
    /// Scope of the check.
    pub scope: EnforcementScope,
    /// Decision made.
    pub decision: EnforcementDecision,
    /// Certificate consulted (if any).
    pub certificate_id: Option<String>,
    /// Dimension budgets at time of decision.
    pub budget_snapshot: Vec<DimensionBudgetSnapshot>,
    /// Security epoch of this decision.
    pub decision_epoch: SecurityEpoch,
    /// Monotonic decision sequence.
    pub decision_sequence: u64,
    /// Content hash of this receipt.
    pub content_hash: ContentHash,
    /// Policy hash used.
    pub policy_hash: String,
}

/// Input for constructing an enforcement receipt.
#[derive(Debug, Clone)]
pub struct EnforcementReceiptInput {
    /// Extension being checked.
    pub extension_id: String,
    /// Scope of the check.
    pub scope: EnforcementScope,
    /// Decision made.
    pub decision: EnforcementDecision,
    /// Certificate consulted (if any).
    pub certificate_id: Option<String>,
    /// Budget snapshots at decision time.
    pub budget_snapshot: Vec<DimensionBudgetSnapshot>,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Decision sequence.
    pub seq: u64,
    /// Policy hash.
    pub policy_hash: String,
}

impl EnforcementReceipt {
    /// Create a new receipt from input.
    fn from_input(input: EnforcementReceiptInput) -> Self {
        let content_hash = Self::compute_hash(
            &input.extension_id,
            &input.scope,
            &input.decision,
            &input.epoch,
            input.seq,
        );
        let receipt_id = format!("erc-{}", &content_hash.to_hex()[..16]);
        Self {
            receipt_id,
            extension_id: input.extension_id,
            scope: input.scope,
            decision: input.decision,
            certificate_id: input.certificate_id,
            budget_snapshot: input.budget_snapshot,
            decision_epoch: input.epoch,
            decision_sequence: input.seq,
            content_hash,
            policy_hash: input.policy_hash,
        }
    }

    fn compute_hash(
        extension_id: &str,
        scope: &EnforcementScope,
        decision: &EnforcementDecision,
        epoch: &SecurityEpoch,
        seq: u64,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(b"EnforcementReceipt.v1");
        hasher.update(extension_id.as_bytes());
        hasher.update(scope.to_string().as_bytes());
        hasher.update(decision.to_string().as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        hasher.update(seq.to_le_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        ContentHash::compute(&bytes)
    }
}

impl fmt::Display for EnforcementReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] ext={} scope={} decision={} epoch={}",
            self.receipt_id,
            self.extension_id,
            self.scope,
            self.decision,
            self.decision_epoch.as_u64()
        )
    }
}

// ---------------------------------------------------------------------------
// DimensionBudgetSnapshot — point-in-time budget state
// ---------------------------------------------------------------------------

/// Snapshot of a dimension budget at decision time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DimensionBudgetSnapshot {
    /// The dimension.
    pub dimension: EnforcedDimension,
    /// Upper bound (millionths).
    pub upper_bound_millionths: i64,
    /// Current usage (millionths).
    pub current_usage_millionths: i64,
    /// Usage ratio (millionths).
    pub usage_ratio_millionths: u64,
}

impl DimensionBudgetSnapshot {
    /// Create from a budget.
    pub fn from_budget(budget: &DimensionBudget) -> Self {
        Self {
            dimension: budget.dimension,
            upper_bound_millionths: budget.upper_bound_millionths,
            current_usage_millionths: budget.current_usage_millionths,
            usage_ratio_millionths: budget.usage_ratio_millionths(),
        }
    }
}

// ---------------------------------------------------------------------------
// CertificateVerdict (local mirror)
// ---------------------------------------------------------------------------

/// Verdict from a resource certificate (mirrors aara_resource_certificate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CertificateVerdict {
    /// All bounds certified.
    Certified,
    /// Bounds computed but below confidence threshold.
    Provisional,
    /// Analysis abstained on critical path.
    Abstained,
    /// Bound violation proved.
    Violated,
}

impl fmt::Display for CertificateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certified => write!(f, "certified"),
            Self::Provisional => write!(f, "provisional"),
            Self::Abstained => write!(f, "abstained"),
            Self::Violated => write!(f, "violated"),
        }
    }
}

// ---------------------------------------------------------------------------
// CertificateDigest — lightweight certificate reference for the consumer
// ---------------------------------------------------------------------------

/// Lightweight digest of a resource certificate for consumer use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateDigest {
    /// Certificate ID.
    pub certificate_id: String,
    /// Region ID.
    pub region_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Verdict.
    pub verdict: CertificateVerdict,
    /// Resource bounds extracted.
    pub bounds: Vec<ExtractedBound>,
    /// Number of abstention points.
    pub abstention_count: usize,
    /// Minimum confidence across all bounds (millionths).
    pub min_confidence_millionths: i64,
}

/// A resource bound extracted from a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedBound {
    /// Dimension.
    pub dimension: EnforcedDimension,
    /// Upper bound (millionths).
    pub upper_bound_millionths: i64,
    /// Whether the bound is tight.
    pub is_tight: bool,
    /// Confidence (millionths).
    pub confidence_millionths: i64,
}

// ---------------------------------------------------------------------------
// ExtensionBudgetState — per-extension budget tracking
// ---------------------------------------------------------------------------

/// Per-extension budget state across all dimensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionBudgetState {
    /// Extension identifier.
    pub extension_id: String,
    /// Certificate digest currently in effect.
    pub active_certificate: Option<CertificateDigest>,
    /// Per-dimension budgets.
    pub budgets: BTreeMap<EnforcedDimension, DimensionBudget>,
    /// Enforcement decision counts.
    pub allow_count: u64,
    /// Throttle count.
    pub throttle_count: u64,
    /// Reject count.
    pub reject_count: u64,
}

impl ExtensionBudgetState {
    /// Create a new state for an extension.
    pub fn new(extension_id: String) -> Self {
        Self {
            extension_id,
            active_certificate: None,
            budgets: BTreeMap::new(),
            allow_count: 0,
            throttle_count: 0,
            reject_count: 0,
        }
    }

    /// Install a certificate digest and derive budgets.
    pub fn install_certificate(&mut self, digest: CertificateDigest) {
        self.budgets.clear();
        for bound in &digest.bounds {
            let budget = DimensionBudget {
                dimension: bound.dimension,
                upper_bound_millionths: bound.upper_bound_millionths,
                is_tight: bound.is_tight,
                confidence_millionths: bound.confidence_millionths,
                current_usage_millionths: 0,
                source_certificate_id: digest.certificate_id.clone(),
                extension_id: self.extension_id.clone(),
            };
            self.budgets.insert(bound.dimension, budget);
        }
        self.active_certificate = Some(digest);
    }

    /// Record usage for a dimension.
    pub fn record_usage(&mut self, dim: EnforcedDimension, amount_millionths: i64) {
        if let Some(budget) = self.budgets.get_mut(&dim) {
            budget.record_usage(amount_millionths);
        }
    }

    /// Get budget snapshot for all dimensions.
    pub fn budget_snapshots(&self) -> Vec<DimensionBudgetSnapshot> {
        self.budgets
            .values()
            .map(DimensionBudgetSnapshot::from_budget)
            .collect()
    }

    /// Total enforcement decisions.
    pub fn total_decisions(&self) -> u64 {
        self.allow_count + self.throttle_count + self.reject_count
    }
}

// ---------------------------------------------------------------------------
// BudgetEnforcer — the core enforcement engine
// ---------------------------------------------------------------------------

/// Core engine for consuming resource certificates and enforcing budgets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetEnforcer {
    /// Policy governing enforcement.
    pub policy: BudgetEnforcementPolicy,
    /// Current security epoch.
    pub current_epoch: SecurityEpoch,
    /// Per-extension budget states.
    pub extensions: BTreeMap<String, ExtensionBudgetState>,
    /// Enforcement receipts.
    pub receipts: Vec<EnforcementReceipt>,
    /// Monotonic decision sequence.
    decision_sequence: u64,
    /// Cached policy hash.
    policy_hash: String,
}

impl BudgetEnforcer {
    /// Create a new budget enforcer.
    pub fn new(policy: BudgetEnforcementPolicy, epoch: SecurityEpoch) -> Self {
        let policy_hash = policy.policy_hash();
        Self {
            policy,
            current_epoch: epoch,
            extensions: BTreeMap::new(),
            receipts: Vec::new(),
            decision_sequence: 0,
            policy_hash,
        }
    }

    /// Install a certificate for an extension.
    pub fn install_certificate(
        &mut self,
        extension_id: &str,
        digest: CertificateDigest,
    ) -> Result<(), BudgetViolationReason> {
        // Validate epoch.
        if digest.epoch.as_u64() > self.current_epoch.as_u64() {
            return Err(BudgetViolationReason::EpochMismatch {
                certificate_epoch: digest.epoch.as_u64(),
                current_epoch: self.current_epoch.as_u64(),
            });
        }

        // Validate verdict.
        if digest.verdict == CertificateVerdict::Violated {
            return Err(BudgetViolationReason::CertificateViolated {
                certificate_id: digest.certificate_id.clone(),
            });
        }

        // Validate confidence.
        if digest.min_confidence_millionths < self.policy.min_confidence_millionths {
            return Err(BudgetViolationReason::InsufficientConfidence {
                certificate_id: digest.certificate_id.clone(),
                actual_millionths: digest.min_confidence_millionths,
                required_millionths: self.policy.min_confidence_millionths,
            });
        }

        // Check extension limit.
        if !self.extensions.contains_key(extension_id)
            && self.extensions.len() >= self.policy.max_extensions
        {
            return Err(BudgetViolationReason::ExtensionLimitExceeded {
                current: self.extensions.len(),
                max: self.policy.max_extensions,
            });
        }

        // Check abstention if fail-closed.
        if self.policy.fail_closed_on_abstention && digest.verdict == CertificateVerdict::Abstained
        {
            return Err(BudgetViolationReason::CertificateAbstained {
                certificate_id: digest.certificate_id.clone(),
                abstention_count: digest.abstention_count,
            });
        }

        let state = self
            .extensions
            .entry(extension_id.to_string())
            .or_insert_with(|| ExtensionBudgetState::new(extension_id.to_string()));
        state.install_certificate(digest);
        Ok(())
    }

    /// Enforce budget for an operation.
    pub fn enforce(
        &mut self,
        extension_id: &str,
        scope: EnforcementScope,
        usage_deltas: &[(EnforcedDimension, i64)],
    ) -> EnforcementReceipt {
        let decision = self.compute_decision(extension_id, usage_deltas);

        // Update counts.
        if let Some(state) = self.extensions.get_mut(extension_id) {
            match &decision {
                EnforcementDecision::Allow => state.allow_count += 1,
                EnforcementDecision::Throttle { .. } => state.throttle_count += 1,
                EnforcementDecision::Reject { .. } => state.reject_count += 1,
            }
            // Record usage if allowed or throttled.
            if !matches!(decision, EnforcementDecision::Reject { .. }) {
                for (dim, amount) in usage_deltas {
                    state.record_usage(*dim, *amount);
                }
            }
        }

        let certificate_id = self
            .extensions
            .get(extension_id)
            .and_then(|s| s.active_certificate.as_ref())
            .map(|c| c.certificate_id.clone());

        let snapshots = self
            .extensions
            .get(extension_id)
            .map(|s| s.budget_snapshots())
            .unwrap_or_default();

        self.decision_sequence += 1;
        let receipt = EnforcementReceipt::from_input(EnforcementReceiptInput {
            extension_id: extension_id.to_string(),
            scope,
            decision,
            certificate_id,
            budget_snapshot: snapshots,
            epoch: self.current_epoch,
            seq: self.decision_sequence,
            policy_hash: self.policy_hash.clone(),
        });

        // Retain bounded receipts.
        if self.receipts.len() >= self.policy.max_receipts {
            self.receipts.remove(0);
        }
        self.receipts.push(receipt.clone());
        receipt
    }

    /// Compute the enforcement decision.
    fn compute_decision(
        &self,
        extension_id: &str,
        usage_deltas: &[(EnforcedDimension, i64)],
    ) -> EnforcementDecision {
        // Check if extension has a certificate.
        let Some(state) = self.extensions.get(extension_id) else {
            if self.policy.fail_closed_on_missing {
                return EnforcementDecision::Reject {
                    reason: BudgetViolationReason::NoCertificate {
                        extension_id: extension_id.to_string(),
                    },
                };
            }
            return EnforcementDecision::Allow;
        };

        if state.active_certificate.is_none() && self.policy.fail_closed_on_missing {
            return EnforcementDecision::Reject {
                reason: BudgetViolationReason::NoCertificate {
                    extension_id: extension_id.to_string(),
                },
            };
        }

        // Check each dimension.
        let mut worst_ratio: u64 = 0;
        let mut worst_dim = None;
        let mut missing_budget_dims = BTreeSet::new();
        let mut exceeded_dims = Vec::new();

        for (dim, delta) in usage_deltas {
            if !self.policy.should_enforce(*dim) {
                continue;
            }
            let Some(budget) = state.budgets.get(dim) else {
                missing_budget_dims.insert(*dim);
                continue;
            };

            let projected = budget.current_usage_millionths.saturating_add(*delta);
            let bound = budget.upper_bound_millionths;

            if bound <= 0 {
                // Zero or negative bound — always reject.
                exceeded_dims.push((*dim, projected, bound));
                continue;
            }

            let ratio = (projected.max(0) as u64)
                .saturating_mul(MILLIONTHS)
                .checked_div(bound as u64)
                .unwrap_or(MILLIONTHS);

            if ratio >= self.policy.reject_threshold_millionths {
                exceeded_dims.push((*dim, projected, bound));
            }

            if ratio > worst_ratio {
                worst_ratio = ratio;
                worst_dim = Some(*dim);
            }
        }

        if self.policy.fail_closed_on_missing && !missing_budget_dims.is_empty() {
            return EnforcementDecision::Reject {
                reason: BudgetViolationReason::MissingBudgetDimensions {
                    extension_id: extension_id.to_string(),
                    dimensions: missing_budget_dims.into_iter().collect(),
                },
            };
        }

        // Check for exceeded dimensions.
        if exceeded_dims.len() > 1 {
            return EnforcementDecision::Reject {
                reason: BudgetViolationReason::MultipleDimensionsExceeded {
                    dimensions: exceeded_dims.into_iter().map(|(dim, _, _)| dim).collect(),
                },
            };
        }
        if let Some((dim, projected_usage, bound_millionths)) = exceeded_dims.first().copied() {
            return EnforcementDecision::Reject {
                reason: BudgetViolationReason::BudgetExceeded {
                    dimension: dim,
                    usage_millionths: projected_usage,
                    bound_millionths,
                },
            };
        }

        // Check for throttle threshold.
        if worst_ratio >= self.policy.throttle_threshold_millionths
            && let Some(dim) = worst_dim
        {
            return EnforcementDecision::Throttle {
                usage_ratio_millionths: worst_ratio,
                dimension: dim,
            };
        }

        EnforcementDecision::Allow
    }

    /// Get the current decision sequence.
    pub fn decision_sequence(&self) -> u64 {
        self.decision_sequence
    }

    /// Get all receipts.
    pub fn all_receipts(&self) -> &[EnforcementReceipt] {
        &self.receipts
    }

    /// Get extension state.
    pub fn extension_state(&self, extension_id: &str) -> Option<&ExtensionBudgetState> {
        self.extensions.get(extension_id)
    }

    /// Number of tracked extensions.
    pub fn extension_count(&self) -> usize {
        self.extensions.len()
    }

    /// Check if any dimension is in throttle zone for an extension.
    pub fn is_throttled(&self, extension_id: &str) -> bool {
        self.extensions.get(extension_id).is_some_and(|state| {
            state
                .budgets
                .values()
                .any(|b| b.usage_ratio_millionths() >= self.policy.throttle_threshold_millionths)
        })
    }

    /// Check if any dimension is exhausted for an extension.
    pub fn is_exhausted(&self, extension_id: &str) -> bool {
        self.extensions
            .get(extension_id)
            .is_some_and(|state| state.budgets.values().any(|b| b.is_exhausted()))
    }

    /// Get aggregate enforcement summary.
    pub fn enforcement_summary(&self) -> EnforcementSummary {
        let mut total_allow = 0u64;
        let mut total_throttle = 0u64;
        let mut total_reject = 0u64;
        for state in self.extensions.values() {
            total_allow += state.allow_count;
            total_throttle += state.throttle_count;
            total_reject += state.reject_count;
        }
        EnforcementSummary {
            extension_count: self.extensions.len(),
            total_decisions: self.decision_sequence,
            total_allow,
            total_throttle,
            total_reject,
            receipts_retained: self.receipts.len(),
        }
    }
}

// ---------------------------------------------------------------------------
// EnforcementSummary — aggregate statistics
// ---------------------------------------------------------------------------

/// Aggregate enforcement statistics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementSummary {
    /// Number of tracked extensions.
    pub extension_count: usize,
    /// Total enforcement decisions made.
    pub total_decisions: u64,
    /// Total allow decisions.
    pub total_allow: u64,
    /// Total throttle decisions.
    pub total_throttle: u64,
    /// Total reject decisions.
    pub total_reject: u64,
    /// Receipts currently retained.
    pub receipts_retained: usize,
}

// ---------------------------------------------------------------------------
// ResourceConsumerManifest — top-level container
// ---------------------------------------------------------------------------

/// Top-level manifest for a resource certificate consumer session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceConsumerManifest {
    /// Schema version.
    pub schema_version: String,
    /// Component name.
    pub component: String,
    /// Policy hash.
    pub policy_hash: String,
    /// Security epoch.
    pub manifest_epoch: SecurityEpoch,
    /// Extension budget states.
    pub extension_states: Vec<ExtensionBudgetState>,
    /// Enforcement receipts.
    pub receipts: Vec<EnforcementReceipt>,
    /// Enforcement summary.
    pub summary: EnforcementSummary,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl ResourceConsumerManifest {
    /// Create a manifest from an enforcer.
    pub fn from_enforcer(enforcer: &BudgetEnforcer) -> Self {
        let extension_states: Vec<ExtensionBudgetState> =
            enforcer.extensions.values().cloned().collect();
        let summary = enforcer.enforcement_summary();
        let content_hash = Self::compute_hash(
            &enforcer.policy_hash,
            &enforcer.current_epoch,
            &extension_states,
        );
        Self {
            schema_version: ENFORCEMENT_SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            policy_hash: enforcer.policy_hash.clone(),
            manifest_epoch: enforcer.current_epoch,
            extension_states,
            receipts: enforcer.receipts.clone(),
            summary,
            content_hash,
        }
    }

    fn compute_hash(
        policy_hash: &str,
        epoch: &SecurityEpoch,
        states: &[ExtensionBudgetState],
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(b"ResourceConsumerManifest.v1");
        hasher.update(policy_hash.as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        hasher.update(states.len().to_le_bytes());
        for s in states {
            hasher.update(s.extension_id.as_bytes());
        }
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        ContentHash::compute(&bytes)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(10)
    }

    fn make_digest(cert_id: &str, verdict: CertificateVerdict) -> CertificateDigest {
        CertificateDigest {
            certificate_id: cert_id.to_string(),
            region_id: "region-1".to_string(),
            epoch: test_epoch(),
            verdict,
            bounds: vec![
                ExtractedBound {
                    dimension: EnforcedDimension::Time,
                    upper_bound_millionths: 10_000_000,
                    is_tight: true,
                    confidence_millionths: 950_000,
                },
                ExtractedBound {
                    dimension: EnforcedDimension::HeapMemory,
                    upper_bound_millionths: 50_000_000,
                    is_tight: false,
                    confidence_millionths: 920_000,
                },
                ExtractedBound {
                    dimension: EnforcedDimension::HostcallCount,
                    upper_bound_millionths: 100_000_000,
                    is_tight: true,
                    confidence_millionths: 980_000,
                },
            ],
            abstention_count: 0,
            min_confidence_millionths: 920_000,
        }
    }

    fn make_enforcer() -> BudgetEnforcer {
        BudgetEnforcer::new(BudgetEnforcementPolicy::default(), test_epoch())
    }

    // --- Policy tests ---

    #[test]
    fn test_default_policy() {
        let p = BudgetEnforcementPolicy::default();
        assert_eq!(p.throttle_threshold_millionths, 900_000);
        assert_eq!(p.reject_threshold_millionths, 1_000_000);
        assert!(p.fail_closed_on_missing);
        assert!(p.fail_closed_on_abstention);
        assert!(p.enforced_dimensions.is_empty());
    }

    #[test]
    fn test_policy_hash_deterministic() {
        let p1 = BudgetEnforcementPolicy::default();
        let p2 = BudgetEnforcementPolicy::default();
        assert_eq!(p1.policy_hash(), p2.policy_hash());
    }

    #[test]
    fn test_policy_hash_varies() {
        let p1 = BudgetEnforcementPolicy::default();
        let p2 = BudgetEnforcementPolicy {
            throttle_threshold_millionths: 800_000,
            ..BudgetEnforcementPolicy::default()
        };
        assert_ne!(p1.policy_hash(), p2.policy_hash());
    }

    #[test]
    fn test_should_enforce_all_when_empty() {
        let p = BudgetEnforcementPolicy::default();
        assert!(p.should_enforce(EnforcedDimension::Time));
        assert!(p.should_enforce(EnforcedDimension::HeapMemory));
    }

    #[test]
    fn test_should_enforce_specific() {
        let mut p = BudgetEnforcementPolicy::default();
        p.enforced_dimensions.insert(EnforcedDimension::Time);
        assert!(p.should_enforce(EnforcedDimension::Time));
        assert!(!p.should_enforce(EnforcedDimension::HeapMemory));
    }

    // --- DimensionBudget tests ---

    #[test]
    fn test_budget_usage_ratio() {
        let budget = DimensionBudget {
            dimension: EnforcedDimension::Time,
            upper_bound_millionths: 10_000_000,
            is_tight: true,
            confidence_millionths: 950_000,
            current_usage_millionths: 5_000_000,
            source_certificate_id: "cert-1".to_string(),
            extension_id: "ext-1".to_string(),
        };
        assert_eq!(budget.usage_ratio_millionths(), 500_000);
    }

    #[test]
    fn test_budget_usage_ratio_zero_bound() {
        let budget = DimensionBudget {
            dimension: EnforcedDimension::Time,
            upper_bound_millionths: 0,
            is_tight: true,
            confidence_millionths: 950_000,
            current_usage_millionths: 0,
            source_certificate_id: "cert-1".to_string(),
            extension_id: "ext-1".to_string(),
        };
        assert_eq!(budget.usage_ratio_millionths(), MILLIONTHS);
    }

    #[test]
    fn test_budget_record_usage() {
        let mut budget = DimensionBudget {
            dimension: EnforcedDimension::HostcallCount,
            upper_bound_millionths: 100_000_000,
            is_tight: true,
            confidence_millionths: 980_000,
            current_usage_millionths: 0,
            source_certificate_id: "cert-1".to_string(),
            extension_id: "ext-1".to_string(),
        };
        budget.record_usage(50_000_000);
        assert_eq!(budget.current_usage_millionths, 50_000_000);
        assert_eq!(budget.remaining_millionths(), 50_000_000);
        assert!(!budget.is_exhausted());
    }

    #[test]
    fn test_budget_exhausted() {
        let mut budget = DimensionBudget {
            dimension: EnforcedDimension::HostcallCount,
            upper_bound_millionths: 100_000_000,
            is_tight: true,
            confidence_millionths: 980_000,
            current_usage_millionths: 0,
            source_certificate_id: "cert-1".to_string(),
            extension_id: "ext-1".to_string(),
        };
        budget.record_usage(100_000_000);
        assert!(budget.is_exhausted());
        assert_eq!(budget.remaining_millionths(), 0);
    }

    // --- Certificate installation tests ---

    #[test]
    fn test_install_certified() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        assert!(enforcer.install_certificate("ext-1", digest).is_ok());
        assert_eq!(enforcer.extension_count(), 1);
    }

    #[test]
    fn test_install_provisional() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Provisional);
        assert!(enforcer.install_certificate("ext-1", digest).is_ok());
    }

    #[test]
    fn test_install_violated_rejected() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Violated);
        let result = enforcer.install_certificate("ext-1", digest);
        assert!(matches!(
            result,
            Err(BudgetViolationReason::CertificateViolated { .. })
        ));
    }

    #[test]
    fn test_install_abstained_rejected() {
        let mut enforcer = make_enforcer();
        let mut digest = make_digest("cert-1", CertificateVerdict::Abstained);
        digest.abstention_count = 3;
        let result = enforcer.install_certificate("ext-1", digest);
        assert!(matches!(
            result,
            Err(BudgetViolationReason::CertificateAbstained { .. })
        ));
    }

    #[test]
    fn test_install_abstained_allowed_when_not_fail_closed() {
        let policy = BudgetEnforcementPolicy {
            fail_closed_on_abstention: false,
            ..BudgetEnforcementPolicy::default()
        };
        let mut enforcer = BudgetEnforcer::new(policy, test_epoch());
        let mut digest = make_digest("cert-1", CertificateVerdict::Abstained);
        digest.abstention_count = 3;
        assert!(enforcer.install_certificate("ext-1", digest).is_ok());
    }

    #[test]
    fn test_install_future_epoch_rejected() {
        let mut enforcer = make_enforcer();
        let mut digest = make_digest("cert-1", CertificateVerdict::Certified);
        digest.epoch = SecurityEpoch::from_raw(100);
        let result = enforcer.install_certificate("ext-1", digest);
        assert!(matches!(
            result,
            Err(BudgetViolationReason::EpochMismatch { .. })
        ));
    }

    #[test]
    fn test_install_low_confidence_rejected() {
        let mut enforcer = make_enforcer();
        let mut digest = make_digest("cert-1", CertificateVerdict::Certified);
        digest.min_confidence_millionths = 500_000;
        let result = enforcer.install_certificate("ext-1", digest);
        assert!(matches!(
            result,
            Err(BudgetViolationReason::InsufficientConfidence { .. })
        ));
    }

    #[test]
    fn test_install_extension_limit() {
        let policy = BudgetEnforcementPolicy {
            max_extensions: 1,
            ..BudgetEnforcementPolicy::default()
        };
        let mut enforcer = BudgetEnforcer::new(policy, test_epoch());
        let d1 = make_digest("cert-1", CertificateVerdict::Certified);
        assert!(enforcer.install_certificate("ext-1", d1).is_ok());
        let d2 = make_digest("cert-2", CertificateVerdict::Certified);
        let result = enforcer.install_certificate("ext-2", d2);
        assert!(matches!(
            result,
            Err(BudgetViolationReason::ExtensionLimitExceeded { .. })
        ));
    }

    // --- Enforcement tests ---

    #[test]
    fn test_enforce_allow() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        enforcer.install_certificate("ext-1", digest).unwrap();
        let receipt = enforcer.enforce(
            "ext-1",
            EnforcementScope::General {
                description: "test".to_string(),
            },
            &[(EnforcedDimension::Time, 1_000_000)],
        );
        assert!(matches!(receipt.decision, EnforcementDecision::Allow));
    }

    #[test]
    fn test_enforce_throttle() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        enforcer.install_certificate("ext-1", digest).unwrap();

        // Use 91% of time budget (above 90% throttle threshold).
        let receipt = enforcer.enforce(
            "ext-1",
            EnforcementScope::SchedulerAdmission {
                task_type: "dispatch".to_string(),
            },
            &[(EnforcedDimension::Time, 9_100_001)],
        );
        assert!(matches!(
            receipt.decision,
            EnforcementDecision::Throttle { .. }
        ));
    }

    #[test]
    fn test_enforce_reject_exceeded() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        enforcer.install_certificate("ext-1", digest).unwrap();

        // Exceed time budget.
        let receipt = enforcer.enforce(
            "ext-1",
            EnforcementScope::General {
                description: "test".to_string(),
            },
            &[(EnforcedDimension::Time, 10_000_001)],
        );
        assert!(matches!(
            receipt.decision,
            EnforcementDecision::Reject {
                reason: BudgetViolationReason::BudgetExceeded { .. }
            }
        ));
        if let EnforcementDecision::Reject {
            reason:
                BudgetViolationReason::BudgetExceeded {
                    dimension,
                    usage_millionths,
                    bound_millionths,
                },
        } = receipt.decision
        {
            assert_eq!(dimension, EnforcedDimension::Time);
            assert_eq!(usage_millionths, 10_000_001);
            assert_eq!(bound_millionths, 10_000_000);
        } else {
            panic!("expected budget exceeded rejection");
        }
    }

    #[test]
    fn test_enforce_no_certificate_fail_closed() {
        let mut enforcer = make_enforcer();
        let receipt = enforcer.enforce(
            "ext-unknown",
            EnforcementScope::General {
                description: "test".to_string(),
            },
            &[(EnforcedDimension::Time, 1_000)],
        );
        assert!(matches!(
            receipt.decision,
            EnforcementDecision::Reject {
                reason: BudgetViolationReason::NoCertificate { .. }
            }
        ));
    }

    #[test]
    fn test_enforce_no_certificate_allow_when_not_fail_closed() {
        let policy = BudgetEnforcementPolicy {
            fail_closed_on_missing: false,
            ..BudgetEnforcementPolicy::default()
        };
        let mut enforcer = BudgetEnforcer::new(policy, test_epoch());
        let receipt = enforcer.enforce(
            "ext-unknown",
            EnforcementScope::General {
                description: "test".to_string(),
            },
            &[(EnforcedDimension::Time, 1_000)],
        );
        assert!(matches!(receipt.decision, EnforcementDecision::Allow));
    }

    #[test]
    fn test_enforce_missing_budget_dimension_rejects_when_fail_closed() {
        let mut enforcer = make_enforcer();
        let mut digest = make_digest("cert-1", CertificateVerdict::Certified);
        digest
            .bounds
            .retain(|bound| bound.dimension == EnforcedDimension::Time);
        enforcer.install_certificate("ext-1", digest).unwrap();

        let receipt = enforcer.enforce(
            "ext-1",
            EnforcementScope::General {
                description: "missing-budget".to_string(),
            },
            &[(EnforcedDimension::HeapMemory, 1_000)],
        );
        assert!(matches!(
            receipt.decision,
            EnforcementDecision::Reject {
                reason: BudgetViolationReason::MissingBudgetDimensions { .. }
            }
        ));
    }

    #[test]
    fn test_enforce_missing_budget_dimension_allows_when_not_fail_closed() {
        let policy = BudgetEnforcementPolicy {
            fail_closed_on_missing: false,
            ..BudgetEnforcementPolicy::default()
        };
        let mut enforcer = BudgetEnforcer::new(policy, test_epoch());
        let mut digest = make_digest("cert-1", CertificateVerdict::Certified);
        digest
            .bounds
            .retain(|bound| bound.dimension == EnforcedDimension::Time);
        enforcer.install_certificate("ext-1", digest).unwrap();

        let receipt = enforcer.enforce(
            "ext-1",
            EnforcementScope::General {
                description: "missing-budget".to_string(),
            },
            &[(EnforcedDimension::HeapMemory, 1_000)],
        );
        assert!(matches!(receipt.decision, EnforcementDecision::Allow));
    }

    #[test]
    fn test_enforce_multiple_dimensions_exceeded() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        enforcer.install_certificate("ext-1", digest).unwrap();

        let receipt = enforcer.enforce(
            "ext-1",
            EnforcementScope::General {
                description: "test".to_string(),
            },
            &[
                (EnforcedDimension::Time, 10_000_001),
                (EnforcedDimension::HeapMemory, 50_000_001),
            ],
        );
        assert!(matches!(
            receipt.decision,
            EnforcementDecision::Reject {
                reason: BudgetViolationReason::MultipleDimensionsExceeded { .. }
            }
        ));
    }

    #[test]
    fn test_enforce_usage_accumulates() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        enforcer.install_certificate("ext-1", digest).unwrap();

        // First call: 50%.
        enforcer.enforce(
            "ext-1",
            EnforcementScope::General {
                description: "op1".to_string(),
            },
            &[(EnforcedDimension::Time, 5_000_000)],
        );

        // Second call: 40% more (now 90% total).
        let receipt = enforcer.enforce(
            "ext-1",
            EnforcementScope::General {
                description: "op2".to_string(),
            },
            &[(EnforcedDimension::Time, 4_000_001)],
        );
        assert!(matches!(
            receipt.decision,
            EnforcementDecision::Throttle { .. }
        ));
    }

    #[test]
    fn test_enforce_reject_does_not_accumulate() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        enforcer.install_certificate("ext-1", digest).unwrap();

        // Reject: over budget.
        enforcer.enforce(
            "ext-1",
            EnforcementScope::General {
                description: "bad".to_string(),
            },
            &[(EnforcedDimension::Time, 10_000_001)],
        );

        // Usage should NOT have been recorded.
        let state = enforcer.extension_state("ext-1").unwrap();
        let time_budget = state.budgets.get(&EnforcedDimension::Time).unwrap();
        assert_eq!(time_budget.current_usage_millionths, 0);
    }

    // --- Scope tests ---

    #[test]
    fn test_scheduler_scope() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        enforcer.install_certificate("ext-1", digest).unwrap();

        let receipt = enforcer.enforce(
            "ext-1",
            EnforcementScope::SchedulerAdmission {
                task_type: "ExtensionDispatch".to_string(),
            },
            &[(EnforcedDimension::Time, 1_000_000)],
        );
        assert!(matches!(receipt.decision, EnforcementDecision::Allow));
        assert!(receipt.scope.to_string().contains("scheduler"));
    }

    #[test]
    fn test_gc_scope() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        enforcer.install_certificate("ext-1", digest).unwrap();

        // GcPressure has no budget in the certificate and fail_closed_on_missing
        // is true, so the enforcer rejects with MissingBudgetDimensions.
        let receipt = enforcer.enforce(
            "ext-1",
            EnforcementScope::GcPacing {
                extension_id: "ext-1".to_string(),
            },
            &[(EnforcedDimension::GcPressure, 1_000)],
        );
        assert!(matches!(receipt.decision, EnforcementDecision::Reject { .. }));
    }

    #[test]
    fn test_module_load_scope() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        enforcer.install_certificate("ext-1", digest).unwrap();

        // ModuleLoadCount has no budget in the certificate and fail_closed_on_missing
        // is true, so the enforcer rejects with MissingBudgetDimensions.
        let receipt = enforcer.enforce(
            "ext-1",
            EnforcementScope::ModuleLoad {
                specifier: "lodash".to_string(),
            },
            &[(EnforcedDimension::ModuleLoadCount, 1_000_000)],
        );
        assert!(matches!(receipt.decision, EnforcementDecision::Reject { .. }));
    }

    #[test]
    fn test_hostcall_scope() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        enforcer.install_certificate("ext-1", digest).unwrap();

        let receipt = enforcer.enforce(
            "ext-1",
            EnforcementScope::HostcallInvocation {
                hostcall_id: "fs_read".to_string(),
            },
            &[(EnforcedDimension::HostcallCount, 1_000_000)],
        );
        assert!(matches!(receipt.decision, EnforcementDecision::Allow));
    }

    #[test]
    fn test_specialization_scope() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        enforcer.install_certificate("ext-1", digest).unwrap();

        let receipt = enforcer.enforce(
            "ext-1",
            EnforcementScope::SpecializationAdmission {
                receipt_id: "spec-1".to_string(),
            },
            &[(EnforcedDimension::Time, 500_000)],
        );
        assert!(matches!(receipt.decision, EnforcementDecision::Allow));
    }

    // --- Receipt tests ---

    #[test]
    fn test_receipt_has_id() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        enforcer.install_certificate("ext-1", digest).unwrap();

        let receipt = enforcer.enforce(
            "ext-1",
            EnforcementScope::General {
                description: "test".to_string(),
            },
            &[(EnforcedDimension::Time, 1_000)],
        );
        assert!(receipt.receipt_id.starts_with("erc-"));
        assert_eq!(receipt.decision_sequence, 1);
    }

    #[test]
    fn test_receipt_display() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        enforcer.install_certificate("ext-1", digest).unwrap();

        let receipt = enforcer.enforce(
            "ext-1",
            EnforcementScope::General {
                description: "test".to_string(),
            },
            &[(EnforcedDimension::Time, 1_000)],
        );
        let display = receipt.to_string();
        assert!(display.contains("ext-1"));
        assert!(display.contains("allow"));
    }

    #[test]
    fn test_receipts_bounded() {
        let policy = BudgetEnforcementPolicy {
            max_receipts: 2,
            ..BudgetEnforcementPolicy::default()
        };
        let mut enforcer = BudgetEnforcer::new(policy, test_epoch());
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        enforcer.install_certificate("ext-1", digest).unwrap();

        for i in 0..5 {
            enforcer.enforce(
                "ext-1",
                EnforcementScope::General {
                    description: format!("op-{}", i),
                },
                &[(EnforcedDimension::Time, 1_000)],
            );
        }
        assert_eq!(enforcer.all_receipts().len(), 2);
    }

    // --- State tracking tests ---

    #[test]
    fn test_is_throttled() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        enforcer.install_certificate("ext-1", digest).unwrap();

        assert!(!enforcer.is_throttled("ext-1"));
        enforcer.enforce(
            "ext-1",
            EnforcementScope::General {
                description: "test".to_string(),
            },
            &[(EnforcedDimension::Time, 9_100_000)],
        );
        assert!(enforcer.is_throttled("ext-1"));
    }

    #[test]
    fn test_is_exhausted() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        enforcer.install_certificate("ext-1", digest).unwrap();

        assert!(!enforcer.is_exhausted("ext-1"));
        // Enforcement rejects when projected ratio >= reject_threshold, so usage
        // can never reach the bound through enforce() alone. Record usage directly
        // on the extension state to test the is_exhausted boundary.
        if let Some(state) = enforcer.extensions.get_mut("ext-1") {
            state.record_usage(EnforcedDimension::Time, 10_000_000);
        }
        assert!(enforcer.is_exhausted("ext-1"));
    }

    #[test]
    fn test_enforcement_summary() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        enforcer.install_certificate("ext-1", digest).unwrap();

        enforcer.enforce(
            "ext-1",
            EnforcementScope::General {
                description: "op1".to_string(),
            },
            &[(EnforcedDimension::Time, 1_000)],
        );
        enforcer.enforce(
            "ext-1",
            EnforcementScope::General {
                description: "op2".to_string(),
            },
            &[(EnforcedDimension::Time, 1_000)],
        );

        let summary = enforcer.enforcement_summary();
        assert_eq!(summary.extension_count, 1);
        assert_eq!(summary.total_decisions, 2);
        assert_eq!(summary.total_allow, 2);
        assert_eq!(summary.total_throttle, 0);
        assert_eq!(summary.total_reject, 0);
    }

    #[test]
    fn test_extension_decision_counts() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        enforcer.install_certificate("ext-1", digest).unwrap();

        // One allow.
        enforcer.enforce(
            "ext-1",
            EnforcementScope::General {
                description: "ok".to_string(),
            },
            &[(EnforcedDimension::Time, 1_000)],
        );

        let state = enforcer.extension_state("ext-1").unwrap();
        assert_eq!(state.allow_count, 1);
        assert_eq!(state.throttle_count, 0);
        assert_eq!(state.reject_count, 0);
        assert_eq!(state.total_decisions(), 1);
    }

    // --- Manifest tests ---

    #[test]
    fn test_manifest_creation() {
        let mut enforcer = make_enforcer();
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        enforcer.install_certificate("ext-1", digest).unwrap();
        enforcer.enforce(
            "ext-1",
            EnforcementScope::General {
                description: "test".to_string(),
            },
            &[(EnforcedDimension::Time, 1_000)],
        );

        let manifest = ResourceConsumerManifest::from_enforcer(&enforcer);
        assert_eq!(manifest.schema_version, ENFORCEMENT_SCHEMA_VERSION);
        assert_eq!(manifest.component, COMPONENT);
        assert_eq!(manifest.extension_states.len(), 1);
        assert_eq!(manifest.receipts.len(), 1);
    }

    // --- Display tests ---

    #[test]
    fn test_enforced_dimension_display() {
        assert_eq!(EnforcedDimension::Time.to_string(), "time");
        assert_eq!(EnforcedDimension::HeapMemory.to_string(), "heap_memory");
        assert_eq!(
            EnforcedDimension::HostcallCount.to_string(),
            "hostcall_count"
        );
        assert_eq!(EnforcedDimension::GcPressure.to_string(), "gc_pressure");
        assert_eq!(
            EnforcedDimension::ModuleLoadCount.to_string(),
            "module_load_count"
        );
        assert_eq!(
            EnforcedDimension::IoOperationCount.to_string(),
            "io_operation_count"
        );
        assert_eq!(EnforcedDimension::StackDepth.to_string(), "stack_depth");
    }

    #[test]
    fn test_decision_display() {
        let d1 = EnforcementDecision::Allow;
        assert_eq!(d1.to_string(), "allow");

        let d2 = EnforcementDecision::Throttle {
            usage_ratio_millionths: 910_000,
            dimension: EnforcedDimension::Time,
        };
        assert!(d2.to_string().contains("throttle"));

        let d3 = EnforcementDecision::Reject {
            reason: BudgetViolationReason::NoCertificate {
                extension_id: "ext-1".to_string(),
            },
        };
        assert!(d3.to_string().contains("reject"));
    }

    #[test]
    fn test_violation_reason_display() {
        let reasons: Vec<BudgetViolationReason> = vec![
            BudgetViolationReason::BudgetExceeded {
                dimension: EnforcedDimension::Time,
                usage_millionths: 100,
                bound_millionths: 50,
            },
            BudgetViolationReason::NoCertificate {
                extension_id: "x".to_string(),
            },
            BudgetViolationReason::CertificateAbstained {
                certificate_id: "c".to_string(),
                abstention_count: 3,
            },
            BudgetViolationReason::CertificateViolated {
                certificate_id: "c".to_string(),
            },
            BudgetViolationReason::EpochMismatch {
                certificate_epoch: 5,
                current_epoch: 10,
            },
            BudgetViolationReason::ExtensionLimitExceeded {
                current: 10,
                max: 10,
            },
            BudgetViolationReason::MultipleDimensionsExceeded {
                dimensions: vec![EnforcedDimension::Time, EnforcedDimension::HeapMemory],
            },
        ];
        for r in &reasons {
            assert!(!r.to_string().is_empty());
        }
    }

    #[test]
    fn test_scope_display() {
        let scopes: Vec<EnforcementScope> = vec![
            EnforcementScope::SchedulerAdmission {
                task_type: "dispatch".to_string(),
            },
            EnforcementScope::GcPacing {
                extension_id: "ext-1".to_string(),
            },
            EnforcementScope::ModuleLoad {
                specifier: "fs".to_string(),
            },
            EnforcementScope::SpecializationAdmission {
                receipt_id: "r-1".to_string(),
            },
            EnforcementScope::HostcallInvocation {
                hostcall_id: "read".to_string(),
            },
            EnforcementScope::IoOperation {
                operation_type: "write".to_string(),
            },
            EnforcementScope::General {
                description: "test".to_string(),
            },
        ];
        for s in &scopes {
            assert!(!s.to_string().is_empty());
        }
    }

    #[test]
    fn test_certificate_verdict_display() {
        assert_eq!(CertificateVerdict::Certified.to_string(), "certified");
        assert_eq!(CertificateVerdict::Provisional.to_string(), "provisional");
        assert_eq!(CertificateVerdict::Abstained.to_string(), "abstained");
        assert_eq!(CertificateVerdict::Violated.to_string(), "violated");
    }

    // --- Budget snapshot tests ---

    #[test]
    fn test_budget_snapshot() {
        let budget = DimensionBudget {
            dimension: EnforcedDimension::Time,
            upper_bound_millionths: 10_000_000,
            is_tight: true,
            confidence_millionths: 950_000,
            current_usage_millionths: 5_000_000,
            source_certificate_id: "cert-1".to_string(),
            extension_id: "ext-1".to_string(),
        };
        let snap = DimensionBudgetSnapshot::from_budget(&budget);
        assert_eq!(snap.dimension, EnforcedDimension::Time);
        assert_eq!(snap.upper_bound_millionths, 10_000_000);
        assert_eq!(snap.current_usage_millionths, 5_000_000);
        assert_eq!(snap.usage_ratio_millionths, 500_000);
    }

    // --- Extension state tests ---

    #[test]
    fn test_extension_state_install() {
        let mut state = ExtensionBudgetState::new("ext-1".to_string());
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        state.install_certificate(digest);
        assert_eq!(state.budgets.len(), 3);
        assert!(state.active_certificate.is_some());
    }

    #[test]
    fn test_extension_state_record_usage() {
        let mut state = ExtensionBudgetState::new("ext-1".to_string());
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        state.install_certificate(digest);
        state.record_usage(EnforcedDimension::Time, 1_000_000);
        let budget = state.budgets.get(&EnforcedDimension::Time).unwrap();
        assert_eq!(budget.current_usage_millionths, 1_000_000);
    }

    #[test]
    fn test_extension_state_budget_snapshots() {
        let mut state = ExtensionBudgetState::new("ext-1".to_string());
        let digest = make_digest("cert-1", CertificateVerdict::Certified);
        state.install_certificate(digest);
        let snaps = state.budget_snapshots();
        assert_eq!(snaps.len(), 3);
    }
}
