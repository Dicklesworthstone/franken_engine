//! Typed execution-slot registry for the Verified Self-Replacement Architecture.
//!
//! Each slot is a replaceable runtime component that can run either a native
//! Rust cell or an explicitly untrusted delegate cell.  The registry tracks
//! current implementations, promotion lineage, and rollback targets so that
//! delegate-to-native replacement is incremental, evidence-backed, and
//! deterministic.
//!
//! Plan references: Section 10.2 item 7, Section 9I.6 (Verified Self-Replacement
//! Architecture), Section 8.8 (cell model and constitutional rules).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// SlotId — unique, deterministic identifier for a replaceable runtime slot
// ---------------------------------------------------------------------------

/// Unique identifier for a replaceable runtime component.
///
/// Slot IDs are short kebab-case strings chosen from a fixed vocabulary
/// (see [`SlotKind`]).  They must be stable across releases so that
/// promotion lineage and rollback references remain valid.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SlotId(String);

impl SlotId {
    /// Create a new `SlotId`.  Returns `Err` if the id is empty or
    /// contains characters outside `[a-z0-9-]`.
    pub fn new(id: impl Into<String>) -> Result<Self, SlotRegistryError> {
        let id = id.into();
        if id.is_empty() {
            return Err(SlotRegistryError::InvalidSlotId {
                id: id.clone(),
                reason: "slot id must not be empty".into(),
            });
        }
        if !id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(SlotRegistryError::InvalidSlotId {
                id: id.clone(),
                reason: "slot id must contain only [a-z0-9-]".into(),
            });
        }
        Ok(Self(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SlotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// SlotKind — semantic boundary describing what a slot does
// ---------------------------------------------------------------------------

/// Describes the semantic boundary of a runtime slot — what the slot is
/// responsible for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SlotKind {
    /// Source text → `IR0 SyntaxIR` (lossless parse representation).
    Parser,
    /// `IR0` → `IR1 SpecIR` (ECMAScript-semantics IR).
    IrLowering,
    /// `IR1` → `IR2 CapabilityIR` (capability/effect graph overlay).
    CapabilityLowering,
    /// `IR2` → `IR3 ExecIR` (execution-ready deterministic IR).
    ExecLowering,
    /// Core bytecode/IR interpreter execution loop.
    Interpreter,
    /// Object model, prototype chain, property semantics.
    ObjectModel,
    /// Closure and lexical scope management.
    ScopeModel,
    /// Promise/microtask queue and async execution.
    AsyncRuntime,
    /// Garbage collector.
    GarbageCollector,
    /// Module resolver and cache.
    ModuleLoader,
    /// Extension hostcall dispatch table.
    HostcallDispatch,
    /// Built-in function implementations (Math, JSON, etc.).
    Builtins,
}

impl fmt::Display for SlotKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Parser => "parser",
            Self::IrLowering => "ir-lowering",
            Self::CapabilityLowering => "capability-lowering",
            Self::ExecLowering => "exec-lowering",
            Self::Interpreter => "interpreter",
            Self::ObjectModel => "object-model",
            Self::ScopeModel => "scope-model",
            Self::AsyncRuntime => "async-runtime",
            Self::GarbageCollector => "garbage-collector",
            Self::ModuleLoader => "module-loader",
            Self::HostcallDispatch => "hostcall-dispatch",
            Self::Builtins => "builtins",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// AuthorityEnvelope — capabilities a slot requires and is permitted
// ---------------------------------------------------------------------------

/// Capabilities that a slot is authorized to exercise.
///
/// The authority envelope constrains what effects a slot implementation may
/// trigger.  Native cells must have an authority envelope `<=` the
/// corresponding delegate cell envelope (Section 8.8 promotion rule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityEnvelope {
    /// Capabilities the slot requires to function.
    pub required: Vec<SlotCapability>,
    /// Maximum capabilities the slot is permitted to exercise.
    pub permitted: Vec<SlotCapability>,
}

impl AuthorityEnvelope {
    /// Verify that all required capabilities are within the permitted set.
    pub fn is_consistent(&self) -> bool {
        self.required.iter().all(|req| self.permitted.contains(req))
    }

    /// Check whether `candidate` envelope is `<=` this envelope (the
    /// candidate does not exceed our permitted set).
    pub fn subsumes(&self, candidate: &Self) -> bool {
        candidate
            .permitted
            .iter()
            .all(|cap| self.permitted.contains(cap))
    }
}

/// Individual capability a slot may exercise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SlotCapability {
    /// Read from the source/IR pipeline.
    ReadSource,
    /// Write/emit IR artifacts.
    EmitIr,
    /// Allocate managed heap objects.
    HeapAlloc,
    /// Schedule microtasks or async continuations.
    ScheduleAsync,
    /// Invoke hostcall dispatch table.
    InvokeHostcall,
    /// Access module cache/resolver.
    ModuleAccess,
    /// Trigger GC cycles.
    TriggerGc,
    /// Emit evidence/telemetry artifacts.
    EmitEvidence,
}

// ---------------------------------------------------------------------------
// PromotionStatus — lifecycle state of a slot's implementation
// ---------------------------------------------------------------------------

/// Tracks where a slot implementation stands in the delegate → native
/// promotion lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromotionStatus {
    /// Running an explicitly untrusted delegate cell.
    Delegate,
    /// A native candidate is under evaluation (shadow/canary).
    PromotionCandidate {
        /// Digest of the candidate native implementation.
        candidate_digest: String,
    },
    /// Promoted to native after passing all gates.
    Promoted {
        /// Digest of the active native implementation.
        native_digest: String,
        /// ID of the signed replacement receipt.
        receipt_id: String,
    },
    /// Demoted back to delegate after a post-promotion failure.
    Demoted {
        /// Reason for demotion.
        reason: String,
        /// Digest of the rollback target that is now active.
        rollback_digest: String,
    },
}

impl PromotionStatus {
    pub fn is_native(&self) -> bool {
        matches!(self, Self::Promoted { .. })
    }

    pub fn is_delegate(&self) -> bool {
        matches!(self, Self::Delegate | Self::Demoted { .. })
    }
}

impl fmt::Display for PromotionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delegate => write!(f, "delegate"),
            Self::PromotionCandidate { candidate_digest } => {
                write!(f, "promotion-candidate({})", candidate_digest)
            }
            Self::Promoted {
                native_digest,
                receipt_id,
            } => write!(f, "promoted({}, receipt={})", native_digest, receipt_id),
            Self::Demoted {
                reason,
                rollback_digest,
            } => write!(
                f,
                "demoted(reason={}, rollback={})",
                reason, rollback_digest
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// SlotEntry — full registration record for a single slot
// ---------------------------------------------------------------------------

/// Complete registration record for one execution slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotEntry {
    pub id: SlotId,
    pub kind: SlotKind,
    pub authority: AuthorityEnvelope,
    pub status: PromotionStatus,
    /// Content-addressed digest of the current active implementation.
    pub implementation_digest: String,
    /// Ordered lineage of previous promotion/demotion events.
    pub promotion_lineage: Vec<LineageEvent>,
    /// Digest of the last-known-good implementation for rollback.
    pub rollback_target: Option<String>,
}

/// A single promotion or demotion event in a slot's lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageEvent {
    /// What happened.
    pub transition: PromotionTransition,
    /// Digest of the implementation after this event.
    pub digest: String,
    /// ISO-8601 timestamp of the event.
    pub timestamp: String,
    /// Optional signed receipt ID (present for promotions).
    pub receipt_id: Option<String>,
}

/// The kind of transition recorded in lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromotionTransition {
    /// Initial registration as delegate.
    RegisteredDelegate,
    /// Entered promotion candidacy.
    EnteredCandidacy,
    /// Promoted to native.
    PromotedToNative,
    /// Demoted back to delegate.
    DemotedToDelegate,
    /// Rollback to a prior known-good state.
    RolledBack,
}

// ---------------------------------------------------------------------------
// SlotRegistryError — typed error contract
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlotRegistryError {
    InvalidSlotId {
        id: String,
        reason: String,
    },
    DuplicateSlotId {
        id: String,
    },
    SlotNotFound {
        id: String,
    },
    InconsistentAuthority {
        id: String,
        detail: String,
    },
    InvalidTransition {
        id: String,
        from: String,
        to: String,
    },
    AuthorityBroadening {
        id: String,
        detail: String,
    },
}

impl fmt::Display for SlotRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSlotId { id, reason } => {
                write!(f, "invalid slot id '{}': {}", id, reason)
            }
            Self::DuplicateSlotId { id } => {
                write!(f, "duplicate slot id '{}'", id)
            }
            Self::SlotNotFound { id } => {
                write!(f, "slot '{}' not found", id)
            }
            Self::InconsistentAuthority { id, detail } => {
                write!(f, "inconsistent authority for '{}': {}", id, detail)
            }
            Self::InvalidTransition { id, from, to } => {
                write!(f, "invalid transition for '{}': {} -> {}", id, from, to)
            }
            Self::AuthorityBroadening { id, detail } => {
                write!(f, "authority broadening rejected for '{}': {}", id, detail)
            }
        }
    }
}

impl std::error::Error for SlotRegistryError {}

// ---------------------------------------------------------------------------
// GA release guard (bd-2y5d)
// ---------------------------------------------------------------------------

/// Per-slot classification used by the GA delegate-cell release guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReleaseSlotClass {
    Core,
    NonCore,
}

impl fmt::Display for ReleaseSlotClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core => f.write_str("core"),
            Self::NonCore => f.write_str("non-core"),
        }
    }
}

/// Governance exemption allowing a temporary core-slot GA bypass.
///
/// Exemptions are only valid when:
/// - signed risk acknowledgement is present
/// - remediation plan is present
/// - approval is present
/// - expiry epoch is strictly greater than the current epoch
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreSlotExemption {
    pub exemption_id: String,
    pub slot_id: SlotId,
    pub approved_by: String,
    pub signed_risk_acknowledgement: String,
    pub remediation_plan: String,
    pub remediation_deadline_epoch: u64,
    pub expires_at_epoch: u64,
}

impl CoreSlotExemption {
    fn validate(
        &self,
        current_epoch: SecurityEpoch,
        core_slots: &BTreeSet<SlotId>,
    ) -> Result<(), GaReleaseGuardError> {
        if self.exemption_id.trim().is_empty() {
            return Err(GaReleaseGuardError::InvalidExemption {
                exemption_id: self.exemption_id.clone(),
                detail: "exemption_id must not be empty".to_string(),
            });
        }
        if self.approved_by.trim().is_empty() {
            return Err(GaReleaseGuardError::InvalidExemption {
                exemption_id: self.exemption_id.clone(),
                detail: "approved_by must not be empty".to_string(),
            });
        }
        if self.signed_risk_acknowledgement.trim().is_empty() {
            return Err(GaReleaseGuardError::InvalidExemption {
                exemption_id: self.exemption_id.clone(),
                detail: "signed_risk_acknowledgement must not be empty".to_string(),
            });
        }
        if self.remediation_plan.trim().is_empty() {
            return Err(GaReleaseGuardError::InvalidExemption {
                exemption_id: self.exemption_id.clone(),
                detail: "remediation_plan must not be empty".to_string(),
            });
        }
        if self.remediation_deadline_epoch <= current_epoch.as_u64() {
            return Err(GaReleaseGuardError::InvalidExemption {
                exemption_id: self.exemption_id.clone(),
                detail: "remediation_deadline_epoch must be in the future".to_string(),
            });
        }
        if self.expires_at_epoch <= current_epoch.as_u64() {
            return Err(GaReleaseGuardError::InvalidExemption {
                exemption_id: self.exemption_id.clone(),
                detail: "expires_at_epoch must be in the future".to_string(),
            });
        }
        if !core_slots.contains(&self.slot_id) {
            return Err(GaReleaseGuardError::InvalidExemption {
                exemption_id: self.exemption_id.clone(),
                detail: format!(
                    "slot `{}` is not configured as a core slot",
                    self.slot_id.as_str()
                ),
            });
        }
        Ok(())
    }
}

/// Guard configuration for evaluating GA readiness under delegate constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GaReleaseGuardConfig {
    /// Explicit core-slot list that must not depend on delegates at GA.
    pub core_slots: BTreeSet<SlotId>,
    /// Optional threshold for non-core delegate-backed slots.
    pub non_core_delegate_limit: Option<usize>,
    /// Dashboard reference for replacement lineage and slot progression.
    pub lineage_dashboard_ref: String,
}

impl Default for GaReleaseGuardConfig {
    fn default() -> Self {
        Self {
            core_slots: BTreeSet::new(),
            non_core_delegate_limit: None,
            lineage_dashboard_ref: "frankentui://replacement-lineage".to_string(),
        }
    }
}

/// Signed lineage artifact for a core-slot replacement.
///
/// This is produced by replacement-lineage tooling and consumed by the GA
/// release guard to verify that a native core slot has auditable provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GaSignedLineageArtifact {
    pub slot_id: SlotId,
    pub former_delegate_digest: String,
    pub replacement_component_digest: String,
    pub replacement_author: String,
    pub replacement_timestamp: String,
    pub lineage_signature: String,
    pub trust_anchor_ref: String,
    pub signature_verified: bool,
    pub equivalence_suite_ref: String,
    pub equivalence_passed: bool,
    pub delegate_fallback_reachable: bool,
}

impl GaSignedLineageArtifact {
    fn validate(&self, core_slots: &BTreeSet<SlotId>) -> Result<(), GaReleaseGuardError> {
        if !core_slots.contains(&self.slot_id) {
            return Err(GaReleaseGuardError::InvalidLineageArtifact {
                slot_id: self.slot_id.as_str().to_string(),
                detail: "lineage artifact references a non-core slot".to_string(),
            });
        }
        if self.former_delegate_digest.trim().is_empty() {
            return Err(GaReleaseGuardError::InvalidLineageArtifact {
                slot_id: self.slot_id.as_str().to_string(),
                detail: "former_delegate_digest must not be empty".to_string(),
            });
        }
        if self.replacement_component_digest.trim().is_empty() {
            return Err(GaReleaseGuardError::InvalidLineageArtifact {
                slot_id: self.slot_id.as_str().to_string(),
                detail: "replacement_component_digest must not be empty".to_string(),
            });
        }
        if self.replacement_author.trim().is_empty() {
            return Err(GaReleaseGuardError::InvalidLineageArtifact {
                slot_id: self.slot_id.as_str().to_string(),
                detail: "replacement_author must not be empty".to_string(),
            });
        }
        if self.replacement_timestamp.trim().is_empty() {
            return Err(GaReleaseGuardError::InvalidLineageArtifact {
                slot_id: self.slot_id.as_str().to_string(),
                detail: "replacement_timestamp must not be empty".to_string(),
            });
        }
        if self.lineage_signature.trim().is_empty() {
            return Err(GaReleaseGuardError::InvalidLineageArtifact {
                slot_id: self.slot_id.as_str().to_string(),
                detail: "lineage_signature must not be empty".to_string(),
            });
        }
        if self.trust_anchor_ref.trim().is_empty() {
            return Err(GaReleaseGuardError::InvalidLineageArtifact {
                slot_id: self.slot_id.as_str().to_string(),
                detail: "trust_anchor_ref must not be empty".to_string(),
            });
        }
        if self.equivalence_suite_ref.trim().is_empty() {
            return Err(GaReleaseGuardError::InvalidLineageArtifact {
                slot_id: self.slot_id.as_str().to_string(),
                detail: "equivalence_suite_ref must not be empty".to_string(),
            });
        }
        Ok(())
    }
}

/// Input contract for GA delegate-cell release guard evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GaReleaseGuardInput {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub current_epoch: SecurityEpoch,
    pub config: GaReleaseGuardConfig,
    pub exemptions: Vec<CoreSlotExemption>,
    pub lineage_artifacts: Vec<GaSignedLineageArtifact>,
    /// Optional estimated remediation timeline per slot id.
    pub remediation_estimates: BTreeMap<SlotId, String>,
}

/// Gate verdict for GA delegate-cell guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GaReleaseGuardVerdict {
    Pass,
    Blocked,
}

impl fmt::Display for GaReleaseGuardVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => f.write_str("pass"),
            Self::Blocked => f.write_str("blocked"),
        }
    }
}

/// Per-slot status snapshot emitted in GA guard artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GaReleaseSlotStatus {
    pub slot_id: SlotId,
    pub slot_kind: SlotKind,
    pub slot_class: ReleaseSlotClass,
    pub promotion_status: String,
    pub delegate_backed: bool,
    pub blocking: bool,
    pub exemption_id: Option<String>,
    pub lineage_signature_verified: Option<bool>,
    pub equivalence_passed: Option<bool>,
    pub delegate_fallback_reachable: Option<bool>,
    pub estimated_remediation: String,
}

/// Structured guard event for audit and reproducibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GaReleaseGuardEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub slot_id: Option<String>,
    pub detail: String,
}

/// Deterministic guard artifact produced by GA delegate-cell policy check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GaReleaseGuardArtifact {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub verdict: GaReleaseGuardVerdict,
    pub total_slots: usize,
    pub core_slot_count: usize,
    pub core_delegate_count: usize,
    pub non_core_delegate_count: usize,
    pub native_coverage_millionths: u64,
    pub lineage_dashboard_ref: String,
    pub exemptions_applied: Vec<String>,
    pub core_slots_missing_lineage: Vec<SlotId>,
    pub core_slots_lineage_mismatch: Vec<SlotId>,
    pub core_slots_invalid_signature: Vec<SlotId>,
    pub core_slots_equivalence_failed: Vec<SlotId>,
    pub core_slots_delegate_fallback_reachable: Vec<SlotId>,
    pub slot_statuses: Vec<GaReleaseSlotStatus>,
    pub blocking_slots: Vec<GaReleaseSlotStatus>,
    pub events: Vec<GaReleaseGuardEvent>,
}

/// Errors emitted by GA delegate-cell guard evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GaReleaseGuardError {
    InvalidInput {
        field: String,
        detail: String,
    },
    UnknownCoreSlot {
        slot_id: String,
    },
    InvalidExemption {
        exemption_id: String,
        detail: String,
    },
    DuplicateExemption {
        slot_id: String,
    },
    InvalidLineageArtifact {
        slot_id: String,
        detail: String,
    },
    DuplicateLineageArtifact {
        slot_id: String,
    },
}

impl fmt::Display for GaReleaseGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { field, detail } => {
                write!(f, "invalid input for `{field}`: {detail}")
            }
            Self::UnknownCoreSlot { slot_id } => {
                write!(f, "core slot `{slot_id}` is not registered")
            }
            Self::InvalidExemption {
                exemption_id,
                detail,
            } => {
                write!(f, "invalid exemption `{exemption_id}`: {detail}")
            }
            Self::DuplicateExemption { slot_id } => {
                write!(f, "duplicate exemption for slot `{slot_id}`")
            }
            Self::InvalidLineageArtifact { slot_id, detail } => {
                write!(f, "invalid lineage artifact for slot `{slot_id}`: {detail}")
            }
            Self::DuplicateLineageArtifact { slot_id } => {
                write!(f, "duplicate lineage artifact for slot `{slot_id}`")
            }
        }
    }
}

impl std::error::Error for GaReleaseGuardError {}

// ---------------------------------------------------------------------------
// Replacement progress telemetry (bd-1a5z)
// ---------------------------------------------------------------------------

/// Per-slot signal used to compute weighted replacement progress metrics.
///
/// Values are expressed in millionths to keep artifacts deterministic and
/// floating-point free.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotReplacementSignal {
    /// Relative invocation weight for this slot (must be > 0).
    pub invocation_weight_millionths: u64,
    /// Estimated throughput uplift if a delegate slot is replaced by native.
    pub throughput_uplift_millionths: i64,
    /// Estimated security-risk reduction if a delegate slot is replaced.
    pub security_risk_reduction_millionths: i64,
}

impl Default for SlotReplacementSignal {
    fn default() -> Self {
        Self {
            invocation_weight_millionths: 1_000_000,
            throughput_uplift_millionths: 0,
            security_risk_reduction_millionths: 0,
        }
    }
}

impl SlotReplacementSignal {
    fn validate(&self, slot_id: &SlotId) -> Result<(), ReplacementProgressError> {
        if self.invocation_weight_millionths == 0 {
            return Err(ReplacementProgressError::InvalidSignal {
                slot_id: slot_id.as_str().to_string(),
                detail: "invocation_weight_millionths must be greater than zero".to_string(),
            });
        }
        Ok(())
    }

    fn expected_value_score_millionths(&self) -> i64 {
        self.throughput_uplift_millionths
            .saturating_add(self.security_risk_reduction_millionths)
    }
}

/// Ranked replacement candidate for delegate-backed slots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplacementPriorityCandidate {
    pub slot_id: SlotId,
    pub slot_kind: SlotKind,
    pub promotion_status: String,
    pub delegate_backed: bool,
    pub invocation_weight_millionths: u64,
    pub throughput_uplift_millionths: i64,
    pub security_risk_reduction_millionths: i64,
    pub expected_value_score_millionths: i64,
    pub weighted_expected_value_score_millionths: i64,
}

/// Structured event for replacement-progress snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplacementProgressEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub slot_id: Option<String>,
    pub detail: String,
}

/// Deterministic replacement-progress artifact for native-coverage and
/// delegate replacement prioritization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplacementProgressSnapshot {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub total_slots: usize,
    pub native_slots: usize,
    pub delegate_slots: usize,
    pub native_coverage_millionths: u64,
    pub weighted_native_coverage_millionths: u64,
    pub weighted_delegate_throughput_uplift_millionths: i64,
    pub weighted_delegate_security_risk_reduction_millionths: i64,
    pub recommended_replacement_order: Vec<ReplacementPriorityCandidate>,
    pub events: Vec<ReplacementProgressEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplacementProgressError {
    InvalidInput { field: String, detail: String },
    UnknownSignalSlot { slot_id: String },
    InvalidSignal { slot_id: String, detail: String },
}

impl fmt::Display for ReplacementProgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { field, detail } => {
                write!(f, "invalid replacement progress input `{field}`: {detail}")
            }
            Self::UnknownSignalSlot { slot_id } => {
                write!(
                    f,
                    "replacement progress signal references unknown slot `{slot_id}`"
                )
            }
            Self::InvalidSignal { slot_id, detail } => {
                write!(
                    f,
                    "invalid replacement progress signal for `{slot_id}`: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for ReplacementProgressError {}

fn saturating_i128_to_i64(value: i128) -> i64 {
    if value > i64::MAX as i128 {
        i64::MAX
    } else if value < i64::MIN as i128 {
        i64::MIN
    } else {
        value as i64
    }
}

fn saturating_u128_to_i128(value: u128) -> i128 {
    if value > i128::MAX as u128 {
        i128::MAX
    } else {
        value as i128
    }
}

fn expected_former_delegate_digest(entry: &SlotEntry) -> Option<&str> {
    entry.rollback_target.as_deref().or_else(|| {
        entry
            .promotion_lineage
            .iter()
            .rev()
            .find_map(|event| match event.transition {
                PromotionTransition::RegisteredDelegate
                | PromotionTransition::DemotedToDelegate => Some(event.digest.as_str()),
                PromotionTransition::EnteredCandidacy
                | PromotionTransition::PromotedToNative
                | PromotionTransition::RolledBack => None,
            })
    })
}

// ---------------------------------------------------------------------------
// SlotRegistry — the registry itself
// ---------------------------------------------------------------------------

/// Registry of all typed execution slots in the runtime.
///
/// Slots are stored in a `BTreeMap` for deterministic iteration order
/// (important for replay and evidence generation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotRegistry {
    slots: BTreeMap<SlotId, SlotEntry>,
}

impl SlotRegistry {
    pub fn new() -> Self {
        Self {
            slots: BTreeMap::new(),
        }
    }

    /// Register a new slot as a delegate.  Fails if the slot ID already
    /// exists or the authority envelope is inconsistent.
    pub fn register_delegate(
        &mut self,
        id: SlotId,
        kind: SlotKind,
        authority: AuthorityEnvelope,
        implementation_digest: String,
        timestamp: String,
    ) -> Result<&SlotEntry, SlotRegistryError> {
        if self.slots.contains_key(&id) {
            return Err(SlotRegistryError::DuplicateSlotId { id: id.to_string() });
        }
        if !authority.is_consistent() {
            return Err(SlotRegistryError::InconsistentAuthority {
                id: id.to_string(),
                detail: "required capabilities not within permitted set".into(),
            });
        }

        let entry = SlotEntry {
            id: id.clone(),
            kind,
            authority,
            status: PromotionStatus::Delegate,
            implementation_digest: implementation_digest.clone(),
            promotion_lineage: vec![LineageEvent {
                transition: PromotionTransition::RegisteredDelegate,
                digest: implementation_digest,
                timestamp,
                receipt_id: None,
            }],
            rollback_target: None,
        };

        self.slots.insert(id.clone(), entry);
        Ok(self.slots.get(&id).expect("just inserted"))
    }

    /// Look up a slot by ID.
    pub fn get(&self, id: &SlotId) -> Option<&SlotEntry> {
        self.slots.get(id)
    }

    /// Iterate all slots in deterministic (sorted) order.
    pub fn iter(&self) -> impl Iterator<Item = (&SlotId, &SlotEntry)> {
        self.slots.iter()
    }

    /// Count of registered slots.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Number of slots currently running native implementations.
    pub fn native_count(&self) -> usize {
        self.slots.values().filter(|e| e.status.is_native()).count()
    }

    /// Number of slots currently running delegate implementations.
    pub fn delegate_count(&self) -> usize {
        self.slots
            .values()
            .filter(|e| e.status.is_delegate())
            .count()
    }

    /// Native coverage ratio (0.0–1.0).
    pub fn native_coverage(&self) -> f64 {
        if self.slots.is_empty() {
            return 0.0;
        }
        self.native_count() as f64 / self.slots.len() as f64
    }

    /// Build a deterministic replacement-progress snapshot containing native
    /// coverage, weighted delegate uplift estimates, and EV-ranked replacement
    /// order for delegate-backed slots.
    pub fn snapshot_replacement_progress(
        &self,
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
        signals: &BTreeMap<SlotId, SlotReplacementSignal>,
    ) -> Result<ReplacementProgressSnapshot, ReplacementProgressError> {
        let trace_id = trace_id.into();
        let decision_id = decision_id.into();
        let policy_id = policy_id.into();
        let component = "self_replacement_progress".to_string();

        if trace_id.trim().is_empty() {
            return Err(ReplacementProgressError::InvalidInput {
                field: "trace_id".to_string(),
                detail: "must not be empty".to_string(),
            });
        }
        if decision_id.trim().is_empty() {
            return Err(ReplacementProgressError::InvalidInput {
                field: "decision_id".to_string(),
                detail: "must not be empty".to_string(),
            });
        }
        if policy_id.trim().is_empty() {
            return Err(ReplacementProgressError::InvalidInput {
                field: "policy_id".to_string(),
                detail: "must not be empty".to_string(),
            });
        }

        for slot_id in signals.keys() {
            if !self.slots.contains_key(slot_id) {
                return Err(ReplacementProgressError::UnknownSignalSlot {
                    slot_id: slot_id.as_str().to_string(),
                });
            }
        }

        let total_slots = self.slots.len();
        let native_slots = self.native_count();
        let delegate_slots = self.delegate_count();

        let native_coverage_millionths = if total_slots == 0 {
            0
        } else {
            (native_slots as u64).saturating_mul(1_000_000) / total_slots as u64
        };

        let mut total_weight = 0u128;
        let mut native_weight = 0u128;
        let mut delegate_weight = 0u128;
        let mut delegate_throughput_weighted_sum = 0i128;
        let mut delegate_security_weighted_sum = 0i128;
        let mut recommended_replacement_order = Vec::new();

        for (slot_id, entry) in &self.slots {
            let signal = signals.get(slot_id).cloned().unwrap_or_default();
            signal.validate(slot_id)?;

            let weight = u128::from(signal.invocation_weight_millionths);
            total_weight = total_weight.saturating_add(weight);

            if entry.status.is_native() {
                native_weight = native_weight.saturating_add(weight);
                continue;
            }

            delegate_weight = delegate_weight.saturating_add(weight);

            let throughput_contribution = i128::from(signal.throughput_uplift_millionths)
                .saturating_mul(i128::from(signal.invocation_weight_millionths));
            let security_contribution = i128::from(signal.security_risk_reduction_millionths)
                .saturating_mul(i128::from(signal.invocation_weight_millionths));
            delegate_throughput_weighted_sum =
                delegate_throughput_weighted_sum.saturating_add(throughput_contribution);
            delegate_security_weighted_sum =
                delegate_security_weighted_sum.saturating_add(security_contribution);

            let weighted_ev = i128::from(signal.expected_value_score_millionths())
                .saturating_mul(i128::from(signal.invocation_weight_millionths))
                / 1_000_000;

            recommended_replacement_order.push(ReplacementPriorityCandidate {
                slot_id: slot_id.clone(),
                slot_kind: entry.kind,
                promotion_status: entry.status.to_string(),
                delegate_backed: true,
                invocation_weight_millionths: signal.invocation_weight_millionths,
                throughput_uplift_millionths: signal.throughput_uplift_millionths,
                security_risk_reduction_millionths: signal.security_risk_reduction_millionths,
                expected_value_score_millionths: signal.expected_value_score_millionths(),
                weighted_expected_value_score_millionths: saturating_i128_to_i64(weighted_ev),
            });
        }

        recommended_replacement_order.sort_by(|left, right| {
            right
                .weighted_expected_value_score_millionths
                .cmp(&left.weighted_expected_value_score_millionths)
                .then_with(|| left.slot_id.cmp(&right.slot_id))
        });

        let weighted_native_coverage_millionths = native_weight
            .saturating_mul(1_000_000)
            .checked_div(total_weight)
            .unwrap_or(0) as u64;
        let weighted_delegate_throughput_uplift_millionths = if delegate_weight == 0 {
            0
        } else {
            let divisor = saturating_u128_to_i128(delegate_weight).max(1);
            saturating_i128_to_i64(delegate_throughput_weighted_sum / divisor)
        };
        let weighted_delegate_security_risk_reduction_millionths = if delegate_weight == 0 {
            0
        } else {
            let divisor = saturating_u128_to_i128(delegate_weight).max(1);
            saturating_i128_to_i64(delegate_security_weighted_sum / divisor)
        };

        let mut events = Vec::with_capacity(recommended_replacement_order.len().saturating_add(1));
        for candidate in &recommended_replacement_order {
            events.push(ReplacementProgressEvent {
                trace_id: trace_id.clone(),
                decision_id: decision_id.clone(),
                policy_id: policy_id.clone(),
                component: component.clone(),
                event: "replacement_candidate_ranked".to_string(),
                outcome: "ranked".to_string(),
                error_code: None,
                slot_id: Some(candidate.slot_id.as_str().to_string()),
                detail: format!(
                    "weighted_expected_value_score_millionths={}, expected_value_score_millionths={}, invocation_weight_millionths={}",
                    candidate.weighted_expected_value_score_millionths,
                    candidate.expected_value_score_millionths,
                    candidate.invocation_weight_millionths
                ),
            });
        }

        events.push(ReplacementProgressEvent {
            trace_id: trace_id.clone(),
            decision_id: decision_id.clone(),
            policy_id: policy_id.clone(),
            component: component.clone(),
            event: "replacement_progress_snapshot_generated".to_string(),
            outcome: "success".to_string(),
            error_code: None,
            slot_id: None,
            detail: format!(
                "total_slots={}, native_slots={}, delegate_slots={}, native_coverage_millionths={}, weighted_native_coverage_millionths={}",
                total_slots,
                native_slots,
                delegate_slots,
                native_coverage_millionths,
                weighted_native_coverage_millionths
            ),
        });

        Ok(ReplacementProgressSnapshot {
            trace_id,
            decision_id,
            policy_id,
            component,
            total_slots,
            native_slots,
            delegate_slots,
            native_coverage_millionths,
            weighted_native_coverage_millionths,
            weighted_delegate_throughput_uplift_millionths,
            weighted_delegate_security_risk_reduction_millionths,
            recommended_replacement_order,
            events,
        })
    }

    /// Begin promotion candidacy for a slot.  The slot must currently be
    /// in `Delegate` or `Demoted` status.
    pub fn begin_candidacy(
        &mut self,
        id: &SlotId,
        candidate_digest: String,
        timestamp: String,
    ) -> Result<&SlotEntry, SlotRegistryError> {
        let entry = self
            .slots
            .get_mut(id)
            .ok_or_else(|| SlotRegistryError::SlotNotFound { id: id.to_string() })?;

        if !entry.status.is_delegate() {
            return Err(SlotRegistryError::InvalidTransition {
                id: id.to_string(),
                from: entry.status.to_string(),
                to: "promotion-candidate".into(),
            });
        }

        entry.status = PromotionStatus::PromotionCandidate {
            candidate_digest: candidate_digest.clone(),
        };
        entry.promotion_lineage.push(LineageEvent {
            transition: PromotionTransition::EnteredCandidacy,
            digest: candidate_digest,
            timestamp,
            receipt_id: None,
        });

        Ok(self.slots.get(id).expect("slot exists"))
    }

    /// Promote a candidate to native.  The slot must be in
    /// `PromotionCandidate` status.  The `native_authority` must not
    /// exceed the delegate's authority envelope.
    pub fn promote(
        &mut self,
        id: &SlotId,
        native_digest: String,
        native_authority: &AuthorityEnvelope,
        receipt_id: String,
        timestamp: String,
    ) -> Result<&SlotEntry, SlotRegistryError> {
        let entry = self
            .slots
            .get_mut(id)
            .ok_or_else(|| SlotRegistryError::SlotNotFound { id: id.to_string() })?;

        if !matches!(entry.status, PromotionStatus::PromotionCandidate { .. }) {
            return Err(SlotRegistryError::InvalidTransition {
                id: id.to_string(),
                from: entry.status.to_string(),
                to: "promoted".into(),
            });
        }

        if !native_authority.is_consistent() {
            return Err(SlotRegistryError::InconsistentAuthority {
                id: id.to_string(),
                detail: "native required capabilities not within permitted set".into(),
            });
        }

        // Authority preservation check (Section 8.8 rule 4):
        // native cell authority envelope must be <= delegate declared envelope.
        if !entry.authority.subsumes(native_authority) {
            return Err(SlotRegistryError::AuthorityBroadening {
                id: id.to_string(),
                detail: "native cell authority exceeds delegate envelope".into(),
            });
        }

        // Store current digest as rollback target.
        entry.rollback_target = Some(entry.implementation_digest.clone());
        entry.implementation_digest = native_digest.clone();
        entry.status = PromotionStatus::Promoted {
            native_digest: native_digest.clone(),
            receipt_id: receipt_id.clone(),
        };
        entry.promotion_lineage.push(LineageEvent {
            transition: PromotionTransition::PromotedToNative,
            digest: native_digest,
            timestamp,
            receipt_id: Some(receipt_id),
        });

        Ok(self.slots.get(id).expect("slot exists"))
    }

    /// Demote a promoted slot back to delegate status.
    pub fn demote(
        &mut self,
        id: &SlotId,
        reason: String,
        timestamp: String,
    ) -> Result<&SlotEntry, SlotRegistryError> {
        let entry = self
            .slots
            .get_mut(id)
            .ok_or_else(|| SlotRegistryError::SlotNotFound { id: id.to_string() })?;

        if !entry.status.is_native() {
            return Err(SlotRegistryError::InvalidTransition {
                id: id.to_string(),
                from: entry.status.to_string(),
                to: "demoted".into(),
            });
        }

        let rollback_digest = entry
            .rollback_target
            .clone()
            .unwrap_or_else(|| entry.implementation_digest.clone());

        entry.implementation_digest = rollback_digest.clone();
        entry.status = PromotionStatus::Demoted {
            reason,
            rollback_digest: rollback_digest.clone(),
        };
        entry.promotion_lineage.push(LineageEvent {
            transition: PromotionTransition::DemotedToDelegate,
            digest: rollback_digest,
            timestamp,
            receipt_id: None,
        });

        Ok(self.slots.get(id).expect("slot exists"))
    }

    /// Evaluate the hard GA delegate-cell guard for core slots.
    ///
    /// Core slots must be native unless a valid governance exemption is present.
    /// Exemptions are time-bounded and require signed risk acknowledgement plus
    /// a remediation plan. Non-core slots may be constrained by an optional
    /// delegate threshold.
    pub fn evaluate_ga_release_guard(
        &self,
        input: &GaReleaseGuardInput,
    ) -> Result<GaReleaseGuardArtifact, GaReleaseGuardError> {
        if input.trace_id.trim().is_empty() {
            return Err(GaReleaseGuardError::InvalidInput {
                field: "trace_id".to_string(),
                detail: "must not be empty".to_string(),
            });
        }
        if input.decision_id.trim().is_empty() {
            return Err(GaReleaseGuardError::InvalidInput {
                field: "decision_id".to_string(),
                detail: "must not be empty".to_string(),
            });
        }
        if input.policy_id.trim().is_empty() {
            return Err(GaReleaseGuardError::InvalidInput {
                field: "policy_id".to_string(),
                detail: "must not be empty".to_string(),
            });
        }
        if input.config.lineage_dashboard_ref.trim().is_empty() {
            return Err(GaReleaseGuardError::InvalidInput {
                field: "lineage_dashboard_ref".to_string(),
                detail: "must not be empty".to_string(),
            });
        }

        for core_slot in &input.config.core_slots {
            if !self.slots.contains_key(core_slot) {
                return Err(GaReleaseGuardError::UnknownCoreSlot {
                    slot_id: core_slot.as_str().to_string(),
                });
            }
        }

        let mut exemptions_by_slot: BTreeMap<SlotId, CoreSlotExemption> = BTreeMap::new();
        for exemption in &input.exemptions {
            exemption.validate(input.current_epoch, &input.config.core_slots)?;
            if exemptions_by_slot
                .insert(exemption.slot_id.clone(), exemption.clone())
                .is_some()
            {
                return Err(GaReleaseGuardError::DuplicateExemption {
                    slot_id: exemption.slot_id.as_str().to_string(),
                });
            }
        }

        let mut lineage_by_slot: BTreeMap<SlotId, GaSignedLineageArtifact> = BTreeMap::new();
        for lineage in &input.lineage_artifacts {
            lineage.validate(&input.config.core_slots)?;
            if lineage_by_slot
                .insert(lineage.slot_id.clone(), lineage.clone())
                .is_some()
            {
                return Err(GaReleaseGuardError::DuplicateLineageArtifact {
                    slot_id: lineage.slot_id.as_str().to_string(),
                });
            }
        }

        let mut slot_statuses = Vec::with_capacity(self.slots.len());
        let mut events = Vec::with_capacity(self.slots.len().saturating_add(2));
        let mut slot_event_metadata: BTreeMap<SlotId, (String, Option<String>)> = BTreeMap::new();
        let mut core_delegate_count = 0usize;
        let mut non_core_delegate_count = 0usize;
        let mut core_slots_missing_lineage = BTreeSet::new();
        let mut core_slots_lineage_mismatch = BTreeSet::new();
        let mut core_slots_invalid_signature = BTreeSet::new();
        let mut core_slots_equivalence_failed = BTreeSet::new();
        let mut core_slots_delegate_fallback_reachable = BTreeSet::new();

        for (slot_id, entry) in &self.slots {
            let slot_class = if input.config.core_slots.contains(slot_id) {
                ReleaseSlotClass::Core
            } else {
                ReleaseSlotClass::NonCore
            };
            let delegate_backed = !entry.status.is_native();

            if delegate_backed {
                match slot_class {
                    ReleaseSlotClass::Core => core_delegate_count += 1,
                    ReleaseSlotClass::NonCore => non_core_delegate_count += 1,
                }
            }

            let exemption = exemptions_by_slot.get(slot_id);
            let mut blocking = false;
            let mut error_code = None;
            let mut lineage_signature_verified = None;
            let mut equivalence_passed = None;
            let mut delegate_fallback_reachable = None;
            let detail = match slot_class {
                ReleaseSlotClass::Core => {
                    if delegate_backed {
                        if let Some(exemption) = exemption {
                            format!(
                                "core slot delegate-backed, temporary exemption `{}` active until epoch {}",
                                exemption.exemption_id, exemption.expires_at_epoch
                            )
                        } else {
                            blocking = true;
                            error_code = Some("FE-GA-CORE-DELEGATE-BLOCK".to_string());
                            "core slot delegate-backed without governance exemption".to_string()
                        }
                    } else {
                        match lineage_by_slot.get(slot_id) {
                            None => {
                                blocking = true;
                                core_slots_missing_lineage.insert(slot_id.clone());
                                error_code = Some("FE-GA-LINEAGE-MISSING".to_string());
                                "core slot is native but missing signed lineage artifact"
                                    .to_string()
                            }
                            Some(lineage) => {
                                lineage_signature_verified = Some(lineage.signature_verified);
                                equivalence_passed = Some(lineage.equivalence_passed);
                                delegate_fallback_reachable =
                                    Some(lineage.delegate_fallback_reachable);

                                if lineage.replacement_component_digest
                                    != entry.implementation_digest
                                {
                                    blocking = true;
                                    core_slots_lineage_mismatch.insert(slot_id.clone());
                                    error_code = Some("FE-GA-LINEAGE-DIGEST-MISMATCH".to_string());
                                    format!(
                                        "lineage digest `{}` does not match active digest `{}`",
                                        lineage.replacement_component_digest,
                                        entry.implementation_digest
                                    )
                                } else if let Some(expected_digest) =
                                    expected_former_delegate_digest(entry)
                                {
                                    if lineage.former_delegate_digest != expected_digest {
                                        blocking = true;
                                        core_slots_lineage_mismatch.insert(slot_id.clone());
                                        error_code =
                                            Some("FE-GA-LINEAGE-DIGEST-MISMATCH".to_string());
                                        format!(
                                            "lineage former delegate digest `{}` does not match expected delegate digest `{}`",
                                            lineage.former_delegate_digest, expected_digest
                                        )
                                    } else if !lineage.signature_verified {
                                        blocking = true;
                                        core_slots_invalid_signature.insert(slot_id.clone());
                                        error_code =
                                            Some("FE-GA-LINEAGE-SIGNATURE-INVALID".to_string());
                                        "signed lineage artifact failed trust-anchor verification"
                                            .to_string()
                                    } else if !lineage.equivalence_passed {
                                        blocking = true;
                                        core_slots_equivalence_failed.insert(slot_id.clone());
                                        error_code = Some("FE-GA-EQUIVALENCE-FAILED".to_string());
                                        format!(
                                            "behavioral equivalence suite `{}` did not pass",
                                            lineage.equivalence_suite_ref
                                        )
                                    } else if lineage.delegate_fallback_reachable {
                                        blocking = true;
                                        core_slots_delegate_fallback_reachable
                                            .insert(slot_id.clone());
                                        error_code =
                                            Some("FE-GA-DELEGATE-FALLBACK-REACHABLE".to_string());
                                        "delegate fallback path remains reachable in GA lane"
                                            .to_string()
                                    } else {
                                        "core slot is native with verified signed lineage and unreachable delegate fallback".to_string()
                                    }
                                } else if !lineage.signature_verified {
                                    blocking = true;
                                    core_slots_invalid_signature.insert(slot_id.clone());
                                    error_code =
                                        Some("FE-GA-LINEAGE-SIGNATURE-INVALID".to_string());
                                    "signed lineage artifact failed trust-anchor verification"
                                        .to_string()
                                } else if !lineage.equivalence_passed {
                                    blocking = true;
                                    core_slots_equivalence_failed.insert(slot_id.clone());
                                    error_code = Some("FE-GA-EQUIVALENCE-FAILED".to_string());
                                    format!(
                                        "behavioral equivalence suite `{}` did not pass",
                                        lineage.equivalence_suite_ref
                                    )
                                } else if lineage.delegate_fallback_reachable {
                                    blocking = true;
                                    core_slots_delegate_fallback_reachable.insert(slot_id.clone());
                                    error_code =
                                        Some("FE-GA-DELEGATE-FALLBACK-REACHABLE".to_string());
                                    "delegate fallback path remains reachable in GA lane"
                                        .to_string()
                                } else {
                                    "core slot is native with verified signed lineage and unreachable delegate fallback".to_string()
                                }
                            }
                        }
                    }
                }
                ReleaseSlotClass::NonCore => {
                    if delegate_backed {
                        "non-core slot delegate-backed".to_string()
                    } else {
                        "non-core slot is native".to_string()
                    }
                }
            };

            let estimated_remediation = input
                .remediation_estimates
                .get(slot_id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            slot_statuses.push(GaReleaseSlotStatus {
                slot_id: slot_id.clone(),
                slot_kind: entry.kind,
                slot_class,
                promotion_status: entry.status.to_string(),
                delegate_backed,
                blocking,
                exemption_id: exemption.map(|ex| ex.exemption_id.clone()),
                lineage_signature_verified,
                equivalence_passed,
                delegate_fallback_reachable,
                estimated_remediation,
            });
            slot_event_metadata.insert(slot_id.clone(), (detail, error_code));
        }

        let non_core_limit_breached = input
            .config
            .non_core_delegate_limit
            .map(|limit| non_core_delegate_count > limit)
            .unwrap_or(false);

        if non_core_limit_breached {
            let limit = input.config.non_core_delegate_limit.unwrap_or(0);
            for status in &mut slot_statuses {
                if status.slot_class == ReleaseSlotClass::NonCore && status.delegate_backed {
                    status.blocking = true;
                    slot_event_metadata.insert(
                        status.slot_id.clone(),
                        (
                            format!(
                                "non-core slot delegate-backed and aggregate delegate count {} exceeds configured limit {}",
                                non_core_delegate_count, limit
                            ),
                            Some("FE-GA-NONCORE-DELEGATE-LIMIT".to_string()),
                        ),
                    );
                }
            }
            events.push(GaReleaseGuardEvent {
                trace_id: input.trace_id.clone(),
                decision_id: input.decision_id.clone(),
                policy_id: input.policy_id.clone(),
                component: "ga_release_delegate_guard".to_string(),
                event: "non_core_delegate_limit_breached".to_string(),
                outcome: "fail".to_string(),
                error_code: Some("FE-GA-NONCORE-DELEGATE-LIMIT".to_string()),
                slot_id: None,
                detail: format!(
                    "non-core delegate slots {} exceeds configured limit {}",
                    non_core_delegate_count,
                    input.config.non_core_delegate_limit.unwrap_or(0)
                ),
            });
        }

        for status in &slot_statuses {
            let (detail, error_code) = slot_event_metadata
                .get(&status.slot_id)
                .cloned()
                .unwrap_or_else(|| ("slot status evaluated".to_string(), None));
            events.push(GaReleaseGuardEvent {
                trace_id: input.trace_id.clone(),
                decision_id: input.decision_id.clone(),
                policy_id: input.policy_id.clone(),
                component: "ga_release_delegate_guard".to_string(),
                event: "slot_status_evaluated".to_string(),
                outcome: if status.blocking { "fail" } else { "pass" }.to_string(),
                error_code,
                slot_id: Some(status.slot_id.as_str().to_string()),
                detail,
            });
        }

        let mut blocking_slots: Vec<GaReleaseSlotStatus> = slot_statuses
            .iter()
            .filter(|status| status.blocking)
            .cloned()
            .collect();
        blocking_slots.sort_by(|a, b| a.slot_id.cmp(&b.slot_id));

        let verdict = if blocking_slots.is_empty() {
            GaReleaseGuardVerdict::Pass
        } else {
            GaReleaseGuardVerdict::Blocked
        };

        let mut exemptions_applied = slot_statuses
            .iter()
            .filter_map(|status| status.exemption_id.clone())
            .collect::<Vec<_>>();
        exemptions_applied.sort();

        let core_slots_missing_lineage = core_slots_missing_lineage.into_iter().collect::<Vec<_>>();
        let core_slots_lineage_mismatch =
            core_slots_lineage_mismatch.into_iter().collect::<Vec<_>>();
        let core_slots_invalid_signature =
            core_slots_invalid_signature.into_iter().collect::<Vec<_>>();
        let core_slots_equivalence_failed = core_slots_equivalence_failed
            .into_iter()
            .collect::<Vec<_>>();
        let core_slots_delegate_fallback_reachable = core_slots_delegate_fallback_reachable
            .into_iter()
            .collect::<Vec<_>>();

        let core_slot_count = input.config.core_slots.len();
        let total_slots = self.slots.len();
        let native_coverage_millionths = if total_slots == 0 {
            0
        } else {
            (self.native_count() as u64).saturating_mul(1_000_000) / total_slots as u64
        };

        events.push(GaReleaseGuardEvent {
            trace_id: input.trace_id.clone(),
            decision_id: input.decision_id.clone(),
            policy_id: input.policy_id.clone(),
            component: "ga_release_delegate_guard".to_string(),
            event: "ga_release_guard_verdict".to_string(),
            outcome: verdict.to_string(),
            error_code: if verdict == GaReleaseGuardVerdict::Pass {
                None
            } else {
                Some("FE-GA-GATE-BLOCKED".to_string())
            },
            slot_id: None,
            detail: format!(
                "core_delegate_count={}, non_core_delegate_count={}, blocking_slots={}, missing_lineage={}, lineage_mismatch={}, invalid_signature={}, equivalence_failed={}, delegate_fallback_reachable={}",
                core_delegate_count,
                non_core_delegate_count,
                blocking_slots.len(),
                core_slots_missing_lineage.len(),
                core_slots_lineage_mismatch.len(),
                core_slots_invalid_signature.len(),
                core_slots_equivalence_failed.len(),
                core_slots_delegate_fallback_reachable.len()
            ),
        });

        Ok(GaReleaseGuardArtifact {
            trace_id: input.trace_id.clone(),
            decision_id: input.decision_id.clone(),
            policy_id: input.policy_id.clone(),
            component: "ga_release_delegate_guard".to_string(),
            verdict,
            total_slots,
            core_slot_count,
            core_delegate_count,
            non_core_delegate_count,
            native_coverage_millionths,
            lineage_dashboard_ref: input.config.lineage_dashboard_ref.clone(),
            exemptions_applied,
            core_slots_missing_lineage,
            core_slots_lineage_mismatch,
            core_slots_invalid_signature,
            core_slots_equivalence_failed,
            core_slots_delegate_fallback_reachable,
            slot_statuses,
            blocking_slots,
            events,
        })
    }

    /// Check whether all slots are native (GA readiness gate per
    /// Section 8.8 rule 5).
    pub fn is_ga_ready(&self) -> bool {
        !self.slots.is_empty() && self.native_count() == self.slots.len()
    }
}

impl Default for SlotRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_authority() -> AuthorityEnvelope {
        AuthorityEnvelope {
            required: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
            permitted: vec![
                SlotCapability::ReadSource,
                SlotCapability::EmitIr,
                SlotCapability::EmitEvidence,
            ],
        }
    }

    fn narrower_authority() -> AuthorityEnvelope {
        AuthorityEnvelope {
            required: vec![SlotCapability::ReadSource],
            permitted: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
        }
    }

    fn broader_authority() -> AuthorityEnvelope {
        AuthorityEnvelope {
            required: vec![SlotCapability::ReadSource],
            permitted: vec![
                SlotCapability::ReadSource,
                SlotCapability::EmitIr,
                SlotCapability::HeapAlloc,
                SlotCapability::InvokeHostcall,
            ],
        }
    }

    fn register_slot(
        registry: &mut SlotRegistry,
        id: &str,
        kind: SlotKind,
        digest: &str,
    ) -> SlotId {
        let slot_id = SlotId::new(id).expect("valid slot id");
        registry
            .register_delegate(
                slot_id.clone(),
                kind,
                test_authority(),
                digest.to_string(),
                "2026-02-21T00:00:00Z".to_string(),
            )
            .expect("register delegate");
        slot_id
    }

    fn promote_slot(registry: &mut SlotRegistry, id: &SlotId, digest: &str) {
        registry
            .begin_candidacy(
                id,
                format!("{digest}-candidate"),
                "2026-02-21T00:00:01Z".to_string(),
            )
            .expect("begin candidacy");
        registry
            .promote(
                id,
                digest.to_string(),
                &narrower_authority(),
                format!("receipt-{digest}"),
                "2026-02-21T00:00:02Z".to_string(),
            )
            .expect("promote");
    }

    fn guard_input(
        core_slots: BTreeSet<SlotId>,
        non_core_delegate_limit: Option<usize>,
    ) -> GaReleaseGuardInput {
        GaReleaseGuardInput {
            trace_id: "trace-ga-guard-001".to_string(),
            decision_id: "decision-ga-guard-001".to_string(),
            policy_id: "policy-ga-zero-delegate-core-v1".to_string(),
            current_epoch: SecurityEpoch::from_raw(42),
            config: GaReleaseGuardConfig {
                core_slots,
                non_core_delegate_limit,
                lineage_dashboard_ref: "frankentui://replacement-lineage/ga-readiness".to_string(),
            },
            exemptions: Vec::new(),
            lineage_artifacts: Vec::new(),
            remediation_estimates: BTreeMap::new(),
        }
    }

    fn lineage_artifact(
        slot_id: &SlotId,
        former_delegate_digest: &str,
        replacement_component_digest: &str,
    ) -> GaSignedLineageArtifact {
        GaSignedLineageArtifact {
            slot_id: slot_id.clone(),
            former_delegate_digest: former_delegate_digest.to_string(),
            replacement_component_digest: replacement_component_digest.to_string(),
            replacement_author: "native-team".to_string(),
            replacement_timestamp: "2026-02-21T00:00:03Z".to_string(),
            lineage_signature: "sig:lineage-proof".to_string(),
            trust_anchor_ref: "trust-anchor://ga-lineage-v1".to_string(),
            signature_verified: true,
            equivalence_suite_ref: "suite://ga-core-equivalence-v1".to_string(),
            equivalence_passed: true,
            delegate_fallback_reachable: false,
        }
    }

    fn exemption_for(slot_id: SlotId) -> CoreSlotExemption {
        CoreSlotExemption {
            exemption_id: format!("exemption-{}", slot_id.as_str()),
            slot_id,
            approved_by: "gov-council".to_string(),
            signed_risk_acknowledgement: "sig:risk-ack-001".to_string(),
            remediation_plan: "finish native replacement within one sprint".to_string(),
            remediation_deadline_epoch: 48,
            expires_at_epoch: 50,
        }
    }

    // -- SlotId validation --

    #[test]
    fn slot_id_rejects_empty() {
        assert!(matches!(
            SlotId::new(""),
            Err(SlotRegistryError::InvalidSlotId { .. })
        ));
    }

    #[test]
    fn slot_id_rejects_uppercase() {
        assert!(matches!(
            SlotId::new("Parser"),
            Err(SlotRegistryError::InvalidSlotId { .. })
        ));
    }

    #[test]
    fn slot_id_accepts_kebab_case() {
        let id = SlotId::new("ir-lowering").unwrap();
        assert_eq!(id.as_str(), "ir-lowering");
    }

    // -- Authority envelope --

    #[test]
    fn consistent_authority_validates() {
        assert!(test_authority().is_consistent());
    }

    #[test]
    fn inconsistent_authority_detected() {
        let bad = AuthorityEnvelope {
            required: vec![SlotCapability::HeapAlloc],
            permitted: vec![SlotCapability::ReadSource],
        };
        assert!(!bad.is_consistent());
    }

    #[test]
    fn authority_subsumes_narrower() {
        assert!(test_authority().subsumes(&narrower_authority()));
    }

    #[test]
    fn authority_does_not_subsume_broader() {
        assert!(!test_authority().subsumes(&broader_authority()));
    }

    // -- Registration --

    #[test]
    fn register_delegate_succeeds() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        let entry = reg
            .register_delegate(
                id.clone(),
                SlotKind::Parser,
                test_authority(),
                "sha256:abc123".into(),
                "2026-02-20T00:00:00Z".into(),
            )
            .unwrap();
        assert_eq!(entry.kind, SlotKind::Parser);
        assert!(entry.status.is_delegate());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn duplicate_registration_rejected() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        reg.register_delegate(
            id.clone(),
            SlotKind::Parser,
            test_authority(),
            "sha256:abc123".into(),
            "2026-02-20T00:00:00Z".into(),
        )
        .unwrap();
        assert!(matches!(
            reg.register_delegate(
                id,
                SlotKind::Parser,
                test_authority(),
                "sha256:def456".into(),
                "2026-02-20T00:00:01Z".into(),
            ),
            Err(SlotRegistryError::DuplicateSlotId { .. })
        ));
    }

    #[test]
    fn inconsistent_authority_rejected_on_register() {
        let mut reg = SlotRegistry::new();
        let bad = AuthorityEnvelope {
            required: vec![SlotCapability::HeapAlloc],
            permitted: vec![SlotCapability::ReadSource],
        };
        assert!(matches!(
            reg.register_delegate(
                SlotId::new("parser").unwrap(),
                SlotKind::Parser,
                bad,
                "sha256:abc".into(),
                "2026-02-20T00:00:00Z".into(),
            ),
            Err(SlotRegistryError::InconsistentAuthority { .. })
        ));
    }

    // -- Promotion lifecycle --

    #[test]
    fn full_promotion_lifecycle() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        reg.register_delegate(
            id.clone(),
            SlotKind::Parser,
            test_authority(),
            "sha256:delegate-v1".into(),
            "2026-02-20T00:00:00Z".into(),
        )
        .unwrap();

        // Begin candidacy
        reg.begin_candidacy(
            &id,
            "sha256:native-candidate".into(),
            "2026-02-20T01:00:00Z".into(),
        )
        .unwrap();
        let entry = reg.get(&id).unwrap();
        assert!(matches!(
            entry.status,
            PromotionStatus::PromotionCandidate { .. }
        ));

        // Promote with narrower authority (allowed)
        reg.promote(
            &id,
            "sha256:native-v1".into(),
            &narrower_authority(),
            "receipt-001".into(),
            "2026-02-20T02:00:00Z".into(),
        )
        .unwrap();
        let entry = reg.get(&id).unwrap();
        assert!(entry.status.is_native());
        assert_eq!(entry.implementation_digest, "sha256:native-v1");
        assert_eq!(reg.native_count(), 1);
        assert_eq!(reg.delegate_count(), 0);

        // Demote
        reg.demote(
            &id,
            "regression detected".into(),
            "2026-02-20T03:00:00Z".into(),
        )
        .unwrap();
        let entry = reg.get(&id).unwrap();
        assert!(entry.status.is_delegate());
        assert_eq!(reg.native_count(), 0);
        assert_eq!(reg.delegate_count(), 1);

        // Lineage should have 4 events
        assert_eq!(entry.promotion_lineage.len(), 4);
    }

    #[test]
    fn promotion_rejects_authority_broadening() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        reg.register_delegate(
            id.clone(),
            SlotKind::Parser,
            test_authority(),
            "sha256:delegate-v1".into(),
            "2026-02-20T00:00:00Z".into(),
        )
        .unwrap();
        reg.begin_candidacy(
            &id,
            "sha256:candidate".into(),
            "2026-02-20T01:00:00Z".into(),
        )
        .unwrap();

        // Try to promote with broader authority — must fail
        assert!(matches!(
            reg.promote(
                &id,
                "sha256:native".into(),
                &broader_authority(),
                "receipt-bad".into(),
                "2026-02-20T02:00:00Z".into(),
            ),
            Err(SlotRegistryError::AuthorityBroadening { .. })
        ));
    }

    #[test]
    fn invalid_transition_from_delegate_to_promoted() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        reg.register_delegate(
            id.clone(),
            SlotKind::Parser,
            test_authority(),
            "sha256:delegate-v1".into(),
            "2026-02-20T00:00:00Z".into(),
        )
        .unwrap();

        // Skip candidacy — go straight to promote
        assert!(matches!(
            reg.promote(
                &id,
                "sha256:native".into(),
                &narrower_authority(),
                "receipt".into(),
                "2026-02-20T01:00:00Z".into(),
            ),
            Err(SlotRegistryError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn demote_from_delegate_is_invalid() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        reg.register_delegate(
            id.clone(),
            SlotKind::Parser,
            test_authority(),
            "sha256:delegate-v1".into(),
            "2026-02-20T00:00:00Z".into(),
        )
        .unwrap();

        assert!(matches!(
            reg.demote(&id, "no reason".into(), "2026-02-20T01:00:00Z".into()),
            Err(SlotRegistryError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn slot_not_found_errors() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("nonexistent").unwrap();
        assert!(matches!(
            reg.begin_candidacy(&id, "d".into(), "t".into()),
            Err(SlotRegistryError::SlotNotFound { .. })
        ));
    }

    // -- GA readiness --

    #[test]
    fn empty_registry_not_ga_ready() {
        let reg = SlotRegistry::new();
        assert!(!reg.is_ga_ready());
    }

    #[test]
    fn all_native_is_ga_ready() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        reg.register_delegate(
            id.clone(),
            SlotKind::Parser,
            test_authority(),
            "sha256:d".into(),
            "t0".into(),
        )
        .unwrap();
        reg.begin_candidacy(&id, "sha256:c".into(), "t1".into())
            .unwrap();
        reg.promote(
            &id,
            "sha256:n".into(),
            &narrower_authority(),
            "r1".into(),
            "t2".into(),
        )
        .unwrap();
        assert!(reg.is_ga_ready());
    }

    #[test]
    fn native_coverage_calculation() {
        let mut reg = SlotRegistry::new();
        let id1 = SlotId::new("parser").unwrap();
        let id2 = SlotId::new("interpreter").unwrap();
        reg.register_delegate(
            id1.clone(),
            SlotKind::Parser,
            test_authority(),
            "sha256:d1".into(),
            "t0".into(),
        )
        .unwrap();
        reg.register_delegate(
            id2,
            SlotKind::Interpreter,
            test_authority(),
            "sha256:d2".into(),
            "t0".into(),
        )
        .unwrap();
        assert!((reg.native_coverage() - 0.0).abs() < f64::EPSILON);

        reg.begin_candidacy(&id1, "sha256:c1".into(), "t1".into())
            .unwrap();
        reg.promote(
            &id1,
            "sha256:n1".into(),
            &narrower_authority(),
            "r1".into(),
            "t2".into(),
        )
        .unwrap();
        assert!((reg.native_coverage() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn replacement_progress_snapshot_reports_weighted_metrics_and_ev_order() {
        let mut reg = SlotRegistry::new();
        let parser = register_slot(
            &mut reg,
            "parser",
            SlotKind::Parser,
            "sha256:delegate-parser-v1",
        );
        let interpreter = register_slot(
            &mut reg,
            "interpreter",
            SlotKind::Interpreter,
            "sha256:delegate-interpreter-v1",
        );
        let object_model = register_slot(
            &mut reg,
            "object-model",
            SlotKind::ObjectModel,
            "sha256:delegate-object-model-v1",
        );
        promote_slot(&mut reg, &parser, "sha256:native-parser-v2");

        let mut signals = BTreeMap::new();
        signals.insert(
            parser.clone(),
            SlotReplacementSignal {
                invocation_weight_millionths: 900_000,
                throughput_uplift_millionths: 200_000,
                security_risk_reduction_millionths: 100_000,
            },
        );
        signals.insert(
            interpreter.clone(),
            SlotReplacementSignal {
                invocation_weight_millionths: 800_000,
                throughput_uplift_millionths: 50_000,
                security_risk_reduction_millionths: 400_000,
            },
        );
        signals.insert(
            object_model.clone(),
            SlotReplacementSignal {
                invocation_weight_millionths: 100_000,
                throughput_uplift_millionths: 700_000,
                security_risk_reduction_millionths: 100_000,
            },
        );

        let snapshot = reg
            .snapshot_replacement_progress(
                "trace-self-replacement-001",
                "decision-self-replacement-001",
                "policy-self-replacement-001",
                &signals,
            )
            .expect("snapshot should succeed");

        assert_eq!(snapshot.total_slots, 3);
        assert_eq!(snapshot.native_slots, 1);
        assert_eq!(snapshot.delegate_slots, 2);
        assert_eq!(snapshot.native_coverage_millionths, 333_333);
        assert_eq!(snapshot.weighted_native_coverage_millionths, 500_000);
        assert_eq!(
            snapshot.weighted_delegate_throughput_uplift_millionths,
            122_222
        );
        assert_eq!(
            snapshot.weighted_delegate_security_risk_reduction_millionths,
            366_666
        );

        assert_eq!(snapshot.recommended_replacement_order.len(), 2);
        assert_eq!(
            snapshot.recommended_replacement_order[0].slot_id,
            interpreter
        );
        assert_eq!(
            snapshot.recommended_replacement_order[0].weighted_expected_value_score_millionths,
            360_000
        );
        assert_eq!(
            snapshot.recommended_replacement_order[1].slot_id,
            object_model
        );
        assert_eq!(
            snapshot.recommended_replacement_order[1].weighted_expected_value_score_millionths,
            80_000
        );

        assert!(
            snapshot
                .events
                .iter()
                .all(|event| event.trace_id == "trace-self-replacement-001"
                    && event.decision_id == "decision-self-replacement-001"
                    && event.policy_id == "policy-self-replacement-001"
                    && event.component == "self_replacement_progress")
        );
        assert!(snapshot.events.iter().any(|event| {
            event.event == "replacement_progress_snapshot_generated" && event.outcome == "success"
        }));
    }

    #[test]
    fn replacement_progress_snapshot_uses_default_signals_when_missing() {
        let mut reg = SlotRegistry::new();
        let parser = register_slot(
            &mut reg,
            "parser",
            SlotKind::Parser,
            "sha256:delegate-parser-v1",
        );
        let interpreter = register_slot(
            &mut reg,
            "interpreter",
            SlotKind::Interpreter,
            "sha256:delegate-interpreter-v1",
        );
        promote_slot(&mut reg, &parser, "sha256:native-parser-v2");

        let snapshot = reg
            .snapshot_replacement_progress(
                "trace-self-replacement-002",
                "decision-self-replacement-002",
                "policy-self-replacement-002",
                &BTreeMap::new(),
            )
            .expect("snapshot should succeed with defaults");

        assert_eq!(snapshot.native_coverage_millionths, 500_000);
        assert_eq!(snapshot.weighted_native_coverage_millionths, 500_000);
        assert_eq!(snapshot.weighted_delegate_throughput_uplift_millionths, 0);
        assert_eq!(
            snapshot.weighted_delegate_security_risk_reduction_millionths,
            0
        );
        assert_eq!(snapshot.recommended_replacement_order.len(), 1);
        assert_eq!(
            snapshot.recommended_replacement_order[0].slot_id,
            interpreter
        );
        assert_eq!(
            snapshot.recommended_replacement_order[0].invocation_weight_millionths,
            1_000_000
        );
    }

    #[test]
    fn replacement_progress_snapshot_rejects_unknown_signal_slot() {
        let mut reg = SlotRegistry::new();
        register_slot(
            &mut reg,
            "parser",
            SlotKind::Parser,
            "sha256:delegate-parser-v1",
        );

        let ghost = SlotId::new("ghost-slot").expect("valid slot id");
        let signals = BTreeMap::from([(
            ghost,
            SlotReplacementSignal {
                invocation_weight_millionths: 200_000,
                throughput_uplift_millionths: 100_000,
                security_risk_reduction_millionths: 100_000,
            },
        )]);

        assert!(matches!(
            reg.snapshot_replacement_progress("trace", "decision", "policy", &signals),
            Err(ReplacementProgressError::UnknownSignalSlot { .. })
        ));
    }

    #[test]
    fn replacement_progress_snapshot_rejects_zero_weight_signal() {
        let mut reg = SlotRegistry::new();
        let parser = register_slot(
            &mut reg,
            "parser",
            SlotKind::Parser,
            "sha256:delegate-parser-v1",
        );
        let signals = BTreeMap::from([(
            parser,
            SlotReplacementSignal {
                invocation_weight_millionths: 0,
                throughput_uplift_millionths: 500_000,
                security_risk_reduction_millionths: 500_000,
            },
        )]);

        assert!(matches!(
            reg.snapshot_replacement_progress("trace", "decision", "policy", &signals),
            Err(ReplacementProgressError::InvalidSignal { .. })
        ));
    }

    #[test]
    fn ga_guard_passes_when_core_slots_native_and_non_core_within_limit() {
        let mut reg = SlotRegistry::new();
        let parser = register_slot(
            &mut reg,
            "parser",
            SlotKind::Parser,
            "sha256:delegate-parser",
        );
        let interp = register_slot(
            &mut reg,
            "interpreter",
            SlotKind::Interpreter,
            "sha256:delegate-interpreter",
        );
        register_slot(
            &mut reg,
            "builtins",
            SlotKind::Builtins,
            "sha256:delegate-builtins",
        );

        promote_slot(&mut reg, &parser, "sha256:native-parser");
        promote_slot(&mut reg, &interp, "sha256:native-interpreter");

        let core_slots = BTreeSet::from([parser.clone(), interp.clone()]);
        let mut input = guard_input(core_slots, Some(1));
        input.remediation_estimates.insert(
            SlotId::new("builtins").expect("valid"),
            "2 weeks".to_string(),
        );
        input.lineage_artifacts = vec![
            lineage_artifact(&parser, "sha256:delegate-parser", "sha256:native-parser"),
            lineage_artifact(
                &interp,
                "sha256:delegate-interpreter",
                "sha256:native-interpreter",
            ),
        ];

        let artifact = reg
            .evaluate_ga_release_guard(&input)
            .expect("guard should pass");

        assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Pass);
        assert_eq!(artifact.core_delegate_count, 0);
        assert_eq!(artifact.non_core_delegate_count, 1);
        assert!(artifact.blocking_slots.is_empty());
        assert!(
            artifact
                .events
                .iter()
                .any(|event| event.event == "ga_release_guard_verdict" && event.outcome == "pass")
        );
    }

    #[test]
    fn ga_guard_blocks_delegate_backed_core_slot_without_exemption() {
        let mut reg = SlotRegistry::new();
        let parser = register_slot(
            &mut reg,
            "parser",
            SlotKind::Parser,
            "sha256:delegate-parser",
        );
        let interpreter = register_slot(
            &mut reg,
            "interpreter",
            SlotKind::Interpreter,
            "sha256:delegate-interpreter",
        );
        promote_slot(&mut reg, &interpreter, "sha256:native-interpreter");

        let core_slots = BTreeSet::from([parser.clone(), interpreter.clone()]);
        let mut input = guard_input(core_slots, Some(2));
        input
            .remediation_estimates
            .insert(parser.clone(), "5 days".to_string());
        input.lineage_artifacts = vec![lineage_artifact(
            &interpreter,
            "sha256:delegate-interpreter",
            "sha256:native-interpreter",
        )];

        let artifact = reg
            .evaluate_ga_release_guard(&input)
            .expect("guard evaluation should complete");

        assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
        assert_eq!(artifact.core_delegate_count, 1);
        assert_eq!(artifact.blocking_slots.len(), 1);
        assert_eq!(artifact.blocking_slots[0].slot_id, parser);
        assert!(artifact.events.iter().any(|event| {
            event.event == "slot_status_evaluated"
                && event.slot_id.as_deref() == Some("parser")
                && event.error_code.as_deref() == Some("FE-GA-CORE-DELEGATE-BLOCK")
        }));
    }

    #[test]
    fn ga_guard_accepts_valid_core_exemption() {
        let mut reg = SlotRegistry::new();
        let parser = register_slot(
            &mut reg,
            "parser",
            SlotKind::Parser,
            "sha256:delegate-parser",
        );
        let core_slots = BTreeSet::from([parser.clone()]);
        let mut input = guard_input(core_slots, None);
        input.exemptions = vec![exemption_for(parser.clone())];

        let artifact = reg
            .evaluate_ga_release_guard(&input)
            .expect("exemption should allow pass");

        assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Pass);
        assert_eq!(
            artifact.exemptions_applied,
            vec!["exemption-parser".to_string()]
        );
        let parser_status = artifact
            .slot_statuses
            .iter()
            .find(|status| status.slot_id == parser)
            .expect("parser status present");
        assert!(!parser_status.blocking);
        assert_eq!(
            parser_status.exemption_id.as_deref(),
            Some("exemption-parser")
        );
    }

    #[test]
    fn ga_guard_rejects_expired_exemption() {
        let mut reg = SlotRegistry::new();
        let parser = register_slot(
            &mut reg,
            "parser",
            SlotKind::Parser,
            "sha256:delegate-parser",
        );
        let core_slots = BTreeSet::from([parser.clone()]);
        let mut input = guard_input(core_slots, None);
        let mut exemption = exemption_for(parser);
        exemption.expires_at_epoch = 42;
        input.exemptions = vec![exemption];

        let error = reg
            .evaluate_ga_release_guard(&input)
            .expect_err("expired exemption must fail");
        assert!(matches!(
            error,
            GaReleaseGuardError::InvalidExemption { detail, .. }
            if detail == "expires_at_epoch must be in the future"
        ));
    }

    #[test]
    fn ga_guard_blocks_when_non_core_delegate_limit_is_exceeded() {
        let mut reg = SlotRegistry::new();
        let parser = register_slot(
            &mut reg,
            "parser",
            SlotKind::Parser,
            "sha256:delegate-parser",
        );
        promote_slot(&mut reg, &parser, "sha256:native-parser");

        let builtins = register_slot(
            &mut reg,
            "builtins",
            SlotKind::Builtins,
            "sha256:delegate-builtins",
        );
        let module_loader = register_slot(
            &mut reg,
            "module-loader",
            SlotKind::ModuleLoader,
            "sha256:delegate-module-loader",
        );

        let core_slots = BTreeSet::from([parser]);
        let mut input = guard_input(core_slots.clone(), Some(1));
        input.lineage_artifacts = vec![lineage_artifact(
            core_slots.iter().next().expect("core slot"),
            "sha256:delegate-parser",
            "sha256:native-parser",
        )];

        let artifact = reg
            .evaluate_ga_release_guard(&input)
            .expect("guard evaluation should complete");

        assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
        assert_eq!(artifact.non_core_delegate_count, 2);
        assert_eq!(artifact.blocking_slots.len(), 2);
        assert_eq!(artifact.blocking_slots[0].slot_id, builtins);
        assert_eq!(artifact.blocking_slots[1].slot_id, module_loader);
        assert!(artifact.events.iter().any(|event| {
            event.event == "non_core_delegate_limit_breached"
                && event.error_code.as_deref() == Some("FE-GA-NONCORE-DELEGATE-LIMIT")
        }));
    }

    #[test]
    fn ga_guard_blocks_native_core_slot_without_lineage_artifact() {
        let mut reg = SlotRegistry::new();
        let parser = register_slot(
            &mut reg,
            "parser",
            SlotKind::Parser,
            "sha256:delegate-parser",
        );
        promote_slot(&mut reg, &parser, "sha256:native-parser");

        let core_slots = BTreeSet::from([parser.clone()]);
        let input = guard_input(core_slots, None);

        let artifact = reg
            .evaluate_ga_release_guard(&input)
            .expect("guard evaluation should complete");

        assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
        assert_eq!(artifact.core_slots_missing_lineage, vec![parser]);
        assert!(artifact.events.iter().any(|event| {
            event.slot_id.as_deref() == Some("parser")
                && event.error_code.as_deref() == Some("FE-GA-LINEAGE-MISSING")
        }));
    }

    #[test]
    fn ga_guard_blocks_on_invalid_signature_and_reachable_delegate_fallback() {
        let mut reg = SlotRegistry::new();
        let parser = register_slot(
            &mut reg,
            "parser",
            SlotKind::Parser,
            "sha256:delegate-parser",
        );
        promote_slot(&mut reg, &parser, "sha256:native-parser");

        let core_slots = BTreeSet::from([parser.clone()]);
        let mut input = guard_input(core_slots, None);
        let mut bad_lineage =
            lineage_artifact(&parser, "sha256:delegate-parser", "sha256:native-parser");
        bad_lineage.signature_verified = false;
        bad_lineage.delegate_fallback_reachable = true;
        input.lineage_artifacts = vec![bad_lineage];

        let artifact = reg
            .evaluate_ga_release_guard(&input)
            .expect("guard evaluation should complete");

        assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
        assert_eq!(artifact.core_slots_invalid_signature, vec![parser.clone()]);
        assert!(
            artifact
                .core_slots_delegate_fallback_reachable
                .iter()
                .all(|slot| slot != &parser),
            "signature failure should fail before fallback check for deterministic ordering"
        );
        assert!(artifact.events.iter().any(|event| {
            event.slot_id.as_deref() == Some("parser")
                && event.error_code.as_deref() == Some("FE-GA-LINEAGE-SIGNATURE-INVALID")
        }));
    }

    #[test]
    fn ga_guard_blocks_when_delegate_fallback_path_is_reachable() {
        let mut reg = SlotRegistry::new();
        let parser = register_slot(
            &mut reg,
            "parser",
            SlotKind::Parser,
            "sha256:delegate-parser",
        );
        promote_slot(&mut reg, &parser, "sha256:native-parser");

        let core_slots = BTreeSet::from([parser.clone()]);
        let mut input = guard_input(core_slots, None);
        let mut lineage =
            lineage_artifact(&parser, "sha256:delegate-parser", "sha256:native-parser");
        lineage.delegate_fallback_reachable = true;
        input.lineage_artifacts = vec![lineage];

        let artifact = reg
            .evaluate_ga_release_guard(&input)
            .expect("guard evaluation should complete");

        assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
        assert_eq!(
            artifact.core_slots_delegate_fallback_reachable,
            vec![parser.clone()]
        );
        assert!(artifact.events.iter().any(|event| {
            event.slot_id.as_deref() == Some("parser")
                && event.error_code.as_deref() == Some("FE-GA-DELEGATE-FALLBACK-REACHABLE")
        }));
    }

    // -- Deterministic iteration order --

    #[test]
    fn slots_iterate_in_sorted_order() {
        let mut reg = SlotRegistry::new();
        for name in ["zz-last", "aa-first", "mm-middle"] {
            reg.register_delegate(
                SlotId::new(name).unwrap(),
                SlotKind::Builtins,
                test_authority(),
                format!("sha256:{name}"),
                "t0".into(),
            )
            .unwrap();
        }
        let ids: Vec<&str> = reg.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, vec!["aa-first", "mm-middle", "zz-last"]);
    }

    // -- Serialization round-trip --

    #[test]
    fn slot_entry_serialization_round_trip() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        reg.register_delegate(
            id,
            SlotKind::Parser,
            test_authority(),
            "sha256:abc".into(),
            "2026-02-20T00:00:00Z".into(),
        )
        .unwrap();

        let json = serde_json::to_string(&reg).expect("serialize");
        let roundtrip: SlotRegistry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(reg.len(), roundtrip.len());

        let orig_id = SlotId::new("parser").unwrap();
        assert_eq!(
            reg.get(&orig_id).unwrap().kind,
            roundtrip.get(&orig_id).unwrap().kind
        );
    }

    // -- SlotId Display and as_str --

    #[test]
    fn slot_id_display_and_as_str() {
        let id = SlotId::new("ir-lowering").unwrap();
        assert_eq!(id.to_string(), "ir-lowering");
        assert_eq!(id.as_str(), "ir-lowering");
    }

    #[test]
    fn slot_id_rejects_underscore() {
        assert!(matches!(
            SlotId::new("ir_lowering"),
            Err(SlotRegistryError::InvalidSlotId { .. })
        ));
    }

    #[test]
    fn slot_id_accepts_digits() {
        assert!(SlotId::new("parser-v2").is_ok());
    }

    // -- SlotKind Display all 12 variants --

    #[test]
    fn slot_kind_display_all_variants() {
        let expected = [
            (SlotKind::Parser, "parser"),
            (SlotKind::IrLowering, "ir-lowering"),
            (SlotKind::CapabilityLowering, "capability-lowering"),
            (SlotKind::ExecLowering, "exec-lowering"),
            (SlotKind::Interpreter, "interpreter"),
            (SlotKind::ObjectModel, "object-model"),
            (SlotKind::ScopeModel, "scope-model"),
            (SlotKind::AsyncRuntime, "async-runtime"),
            (SlotKind::GarbageCollector, "garbage-collector"),
            (SlotKind::ModuleLoader, "module-loader"),
            (SlotKind::HostcallDispatch, "hostcall-dispatch"),
            (SlotKind::Builtins, "builtins"),
        ];
        for (kind, label) in expected {
            assert_eq!(kind.to_string(), label);
        }
    }

    // -- PromotionStatus Display all 4 variants --

    #[test]
    fn promotion_status_display_all_variants() {
        assert_eq!(PromotionStatus::Delegate.to_string(), "delegate");
        let pc = PromotionStatus::PromotionCandidate {
            candidate_digest: "sha256:abc".to_string(),
        };
        assert!(pc.to_string().contains("sha256:abc"));
        let promoted = PromotionStatus::Promoted {
            native_digest: "sha256:xyz".to_string(),
            receipt_id: "r-1".to_string(),
        };
        let s = promoted.to_string();
        assert!(s.contains("sha256:xyz"));
        assert!(s.contains("r-1"));
        let demoted = PromotionStatus::Demoted {
            reason: "regression".to_string(),
            rollback_digest: "sha256:old".to_string(),
        };
        let s = demoted.to_string();
        assert!(s.contains("regression"));
        assert!(s.contains("sha256:old"));
    }

    // -- PromotionStatus is_native / is_delegate --

    #[test]
    fn promotion_status_is_native_and_is_delegate() {
        assert!(!PromotionStatus::Delegate.is_native());
        assert!(PromotionStatus::Delegate.is_delegate());

        let pc = PromotionStatus::PromotionCandidate {
            candidate_digest: "d".to_string(),
        };
        assert!(!pc.is_native());
        assert!(!pc.is_delegate());

        let promoted = PromotionStatus::Promoted {
            native_digest: "d".to_string(),
            receipt_id: "r".to_string(),
        };
        assert!(promoted.is_native());
        assert!(!promoted.is_delegate());

        let demoted = PromotionStatus::Demoted {
            reason: "r".to_string(),
            rollback_digest: "d".to_string(),
        };
        assert!(!demoted.is_native());
        assert!(demoted.is_delegate());
    }

    // -- ReleaseSlotClass Display --

    #[test]
    fn release_slot_class_display() {
        assert_eq!(ReleaseSlotClass::Core.to_string(), "core");
        assert_eq!(ReleaseSlotClass::NonCore.to_string(), "non-core");
    }

    // -- GaReleaseGuardVerdict Display --

    #[test]
    fn ga_release_guard_verdict_display() {
        assert_eq!(GaReleaseGuardVerdict::Pass.to_string(), "pass");
        assert_eq!(GaReleaseGuardVerdict::Blocked.to_string(), "blocked");
    }

    // -- SlotRegistryError Display all 6 variants --

    #[test]
    fn slot_registry_error_display_all_variants() {
        let errors = [
            (
                SlotRegistryError::InvalidSlotId {
                    id: "BAD".to_string(),
                    reason: "uppercase".to_string(),
                },
                "BAD",
            ),
            (
                SlotRegistryError::DuplicateSlotId {
                    id: "parser".to_string(),
                },
                "duplicate",
            ),
            (
                SlotRegistryError::SlotNotFound {
                    id: "ghost".to_string(),
                },
                "not found",
            ),
            (
                SlotRegistryError::InconsistentAuthority {
                    id: "parser".to_string(),
                    detail: "mismatch".to_string(),
                },
                "inconsistent",
            ),
            (
                SlotRegistryError::InvalidTransition {
                    id: "parser".to_string(),
                    from: "delegate".to_string(),
                    to: "promoted".to_string(),
                },
                "invalid transition",
            ),
            (
                SlotRegistryError::AuthorityBroadening {
                    id: "parser".to_string(),
                    detail: "extra caps".to_string(),
                },
                "broadening",
            ),
        ];
        for (err, expected_substr) in errors {
            let s = err.to_string();
            assert!(
                s.contains(expected_substr),
                "'{s}' should contain '{expected_substr}'"
            );
        }
    }

    // -- GaReleaseGuardError Display all 6 variants --

    #[test]
    fn ga_release_guard_error_display_all_variants() {
        let errors: Vec<GaReleaseGuardError> = vec![
            GaReleaseGuardError::InvalidInput {
                field: "trace_id".to_string(),
                detail: "empty".to_string(),
            },
            GaReleaseGuardError::UnknownCoreSlot {
                slot_id: "ghost".to_string(),
            },
            GaReleaseGuardError::InvalidExemption {
                exemption_id: "ex-1".to_string(),
                detail: "expired".to_string(),
            },
            GaReleaseGuardError::DuplicateExemption {
                slot_id: "parser".to_string(),
            },
            GaReleaseGuardError::InvalidLineageArtifact {
                slot_id: "parser".to_string(),
                detail: "empty digest".to_string(),
            },
            GaReleaseGuardError::DuplicateLineageArtifact {
                slot_id: "parser".to_string(),
            },
        ];
        for err in errors {
            let s = err.to_string();
            assert!(!s.is_empty());
        }
    }

    // -- ReplacementProgressError Display all 3 variants --

    #[test]
    fn replacement_progress_error_display_all_variants() {
        let errors: Vec<ReplacementProgressError> = vec![
            ReplacementProgressError::InvalidInput {
                field: "trace_id".to_string(),
                detail: "empty".to_string(),
            },
            ReplacementProgressError::UnknownSignalSlot {
                slot_id: "ghost".to_string(),
            },
            ReplacementProgressError::InvalidSignal {
                slot_id: "parser".to_string(),
                detail: "zero weight".to_string(),
            },
        ];
        for err in errors {
            let s = err.to_string();
            assert!(!s.is_empty());
        }
    }

    // -- SlotReplacementSignal default --

    #[test]
    fn slot_replacement_signal_default() {
        let s = SlotReplacementSignal::default();
        assert_eq!(s.invocation_weight_millionths, 1_000_000);
        assert_eq!(s.throughput_uplift_millionths, 0);
        assert_eq!(s.security_risk_reduction_millionths, 0);
    }

    // -- GaReleaseGuardConfig default --

    #[test]
    fn ga_release_guard_config_default() {
        let config = GaReleaseGuardConfig::default();
        assert!(config.core_slots.is_empty());
        assert!(config.non_core_delegate_limit.is_none());
        assert!(config.lineage_dashboard_ref.contains("frankentui"));
    }

    // -- Serde roundtrips --

    #[test]
    fn slot_id_serde_roundtrip() {
        let id = SlotId::new("parser").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let back: SlotId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn slot_kind_serde_roundtrip() {
        for kind in [
            SlotKind::Parser,
            SlotKind::IrLowering,
            SlotKind::CapabilityLowering,
            SlotKind::ExecLowering,
            SlotKind::Interpreter,
            SlotKind::ObjectModel,
            SlotKind::ScopeModel,
            SlotKind::AsyncRuntime,
            SlotKind::GarbageCollector,
            SlotKind::ModuleLoader,
            SlotKind::HostcallDispatch,
            SlotKind::Builtins,
        ] {
            let json = serde_json::to_value(kind).unwrap();
            let back: SlotKind = serde_json::from_value(json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn slot_capability_serde_roundtrip() {
        for cap in [
            SlotCapability::ReadSource,
            SlotCapability::EmitIr,
            SlotCapability::HeapAlloc,
            SlotCapability::ScheduleAsync,
            SlotCapability::InvokeHostcall,
            SlotCapability::ModuleAccess,
            SlotCapability::TriggerGc,
            SlotCapability::EmitEvidence,
        ] {
            let json = serde_json::to_value(cap).unwrap();
            let back: SlotCapability = serde_json::from_value(json).unwrap();
            assert_eq!(cap, back);
        }
    }

    #[test]
    fn promotion_status_serde_roundtrip() {
        let statuses = vec![
            PromotionStatus::Delegate,
            PromotionStatus::PromotionCandidate {
                candidate_digest: "sha256:c".to_string(),
            },
            PromotionStatus::Promoted {
                native_digest: "sha256:n".to_string(),
                receipt_id: "r-1".to_string(),
            },
            PromotionStatus::Demoted {
                reason: "bug".to_string(),
                rollback_digest: "sha256:old".to_string(),
            },
        ];
        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let back: PromotionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, back);
        }
    }

    #[test]
    fn promotion_transition_serde_roundtrip() {
        for t in [
            PromotionTransition::RegisteredDelegate,
            PromotionTransition::EnteredCandidacy,
            PromotionTransition::PromotedToNative,
            PromotionTransition::DemotedToDelegate,
            PromotionTransition::RolledBack,
        ] {
            let json = serde_json::to_value(t).unwrap();
            let back: PromotionTransition = serde_json::from_value(json).unwrap();
            assert_eq!(t, back);
        }
    }

    #[test]
    fn slot_registry_error_serde_roundtrip() {
        let errors = vec![
            SlotRegistryError::InvalidSlotId {
                id: "BAD".to_string(),
                reason: "uppercase".to_string(),
            },
            SlotRegistryError::DuplicateSlotId {
                id: "parser".to_string(),
            },
            SlotRegistryError::SlotNotFound {
                id: "ghost".to_string(),
            },
            SlotRegistryError::InconsistentAuthority {
                id: "parser".to_string(),
                detail: "mismatch".to_string(),
            },
            SlotRegistryError::InvalidTransition {
                id: "parser".to_string(),
                from: "delegate".to_string(),
                to: "promoted".to_string(),
            },
            SlotRegistryError::AuthorityBroadening {
                id: "parser".to_string(),
                detail: "extra caps".to_string(),
            },
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let back: SlotRegistryError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, back);
        }
    }

    #[test]
    fn ga_release_guard_error_serde_roundtrip() {
        let errors: Vec<GaReleaseGuardError> = vec![
            GaReleaseGuardError::InvalidInput {
                field: "f".to_string(),
                detail: "d".to_string(),
            },
            GaReleaseGuardError::UnknownCoreSlot {
                slot_id: "s".to_string(),
            },
            GaReleaseGuardError::InvalidExemption {
                exemption_id: "e".to_string(),
                detail: "d".to_string(),
            },
            GaReleaseGuardError::DuplicateExemption {
                slot_id: "s".to_string(),
            },
            GaReleaseGuardError::InvalidLineageArtifact {
                slot_id: "s".to_string(),
                detail: "d".to_string(),
            },
            GaReleaseGuardError::DuplicateLineageArtifact {
                slot_id: "s".to_string(),
            },
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let back: GaReleaseGuardError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, back);
        }
    }

    #[test]
    fn release_slot_class_serde_roundtrip() {
        for class in [ReleaseSlotClass::Core, ReleaseSlotClass::NonCore] {
            let json = serde_json::to_value(class).unwrap();
            let back: ReleaseSlotClass = serde_json::from_value(json).unwrap();
            assert_eq!(class, back);
        }
    }

    #[test]
    fn ga_release_guard_verdict_serde_roundtrip() {
        for v in [GaReleaseGuardVerdict::Pass, GaReleaseGuardVerdict::Blocked] {
            let json = serde_json::to_value(v).unwrap();
            let back: GaReleaseGuardVerdict = serde_json::from_value(json).unwrap();
            assert_eq!(v, back);
        }
    }

    // -- Empty registry --

    #[test]
    fn empty_registry_is_empty() {
        let reg = SlotRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert_eq!(reg.native_count(), 0);
        assert_eq!(reg.delegate_count(), 0);
        assert!((reg.native_coverage() - 0.0).abs() < f64::EPSILON);
    }

    // -- Replacement progress validation --

    #[test]
    fn replacement_progress_rejects_empty_trace_id() {
        let reg = SlotRegistry::new();
        let err = reg
            .snapshot_replacement_progress("", "d", "p", &BTreeMap::new())
            .unwrap_err();
        assert!(matches!(
            err,
            ReplacementProgressError::InvalidInput { field, .. } if field == "trace_id"
        ));
    }

    #[test]
    fn replacement_progress_rejects_empty_decision_id() {
        let reg = SlotRegistry::new();
        let err = reg
            .snapshot_replacement_progress("t", "", "p", &BTreeMap::new())
            .unwrap_err();
        assert!(matches!(
            err,
            ReplacementProgressError::InvalidInput { field, .. } if field == "decision_id"
        ));
    }

    #[test]
    fn replacement_progress_rejects_empty_policy_id() {
        let reg = SlotRegistry::new();
        let err = reg
            .snapshot_replacement_progress("t", "d", "", &BTreeMap::new())
            .unwrap_err();
        assert!(matches!(
            err,
            ReplacementProgressError::InvalidInput { field, .. } if field == "policy_id"
        ));
    }

    // -- Lineage event recording --

    #[test]
    fn lineage_records_each_transition() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        reg.register_delegate(
            id.clone(),
            SlotKind::Parser,
            test_authority(),
            "sha256:d1".into(),
            "t0".into(),
        )
        .unwrap();
        let entry = reg.get(&id).unwrap();
        assert_eq!(entry.promotion_lineage.len(), 1);
        assert_eq!(
            entry.promotion_lineage[0].transition,
            PromotionTransition::RegisteredDelegate
        );
        assert!(entry.promotion_lineage[0].receipt_id.is_none());

        reg.begin_candidacy(&id, "sha256:c1".into(), "t1".into())
            .unwrap();
        let entry = reg.get(&id).unwrap();
        assert_eq!(entry.promotion_lineage.len(), 2);
        assert_eq!(
            entry.promotion_lineage[1].transition,
            PromotionTransition::EnteredCandidacy
        );
    }

    // -- Authority envelope edge cases --

    #[test]
    fn empty_authority_envelope_is_consistent() {
        let env = AuthorityEnvelope {
            required: vec![],
            permitted: vec![],
        };
        assert!(env.is_consistent());
    }

    #[test]
    fn empty_authority_subsumes_empty() {
        let a = AuthorityEnvelope {
            required: vec![],
            permitted: vec![],
        };
        let b = AuthorityEnvelope {
            required: vec![],
            permitted: vec![],
        };
        assert!(a.subsumes(&b));
    }

    // -- SlotEntry get for nonexistent --

    #[test]
    fn get_returns_none_for_missing_slot() {
        let reg = SlotRegistry::new();
        let id = SlotId::new("nope").unwrap();
        assert!(reg.get(&id).is_none());
    }

    // -- Rollback target after demotion --

    #[test]
    fn rollback_target_set_after_demotion() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        reg.register_delegate(
            id.clone(),
            SlotKind::Parser,
            test_authority(),
            "sha256:d1".into(),
            "t0".into(),
        )
        .unwrap();
        reg.begin_candidacy(&id, "sha256:c1".into(), "t1".into())
            .unwrap();
        reg.promote(
            &id,
            "sha256:n1".into(),
            &narrower_authority(),
            "r1".into(),
            "t2".into(),
        )
        .unwrap();
        reg.demote(&id, "regression".into(), "t3".into()).unwrap();

        let entry = reg.get(&id).unwrap();
        assert_eq!(entry.rollback_target.as_deref(), Some("sha256:d1"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: struct serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn authority_envelope_serde_roundtrip() {
        let ae = AuthorityEnvelope {
            required: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
            permitted: vec![
                SlotCapability::ReadSource,
                SlotCapability::EmitIr,
                SlotCapability::EmitEvidence,
            ],
        };
        let json = serde_json::to_string(&ae).unwrap();
        let restored: AuthorityEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(ae, restored);
    }

    #[test]
    fn lineage_event_serde_roundtrip() {
        let ev = LineageEvent {
            transition: PromotionTransition::PromotedToNative,
            digest: "sha256:abc".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            receipt_id: Some("r-1".to_string()),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let restored: LineageEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, restored);
    }

    #[test]
    fn core_slot_exemption_serde_roundtrip() {
        let ex = CoreSlotExemption {
            exemption_id: "ex-1".to_string(),
            slot_id: SlotId::new("parser").unwrap(),
            approved_by: "admin".to_string(),
            signed_risk_acknowledgement: "ack".to_string(),
            remediation_plan: "plan".to_string(),
            remediation_deadline_epoch: 100,
            expires_at_epoch: 200,
        };
        let json = serde_json::to_string(&ex).unwrap();
        let restored: CoreSlotExemption = serde_json::from_str(&json).unwrap();
        assert_eq!(ex, restored);
    }

    #[test]
    fn ga_release_guard_event_serde_roundtrip() {
        let ev = GaReleaseGuardEvent {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            component: "ga_guard".to_string(),
            event: "evaluated".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            slot_id: Some("parser".to_string()),
            detail: "ok".to_string(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let restored: GaReleaseGuardEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, restored);
    }

    #[test]
    fn replacement_priority_candidate_serde_roundtrip() {
        let c = ReplacementPriorityCandidate {
            slot_id: SlotId::new("parser").unwrap(),
            slot_kind: SlotKind::Parser,
            promotion_status: "delegate".to_string(),
            delegate_backed: true,
            invocation_weight_millionths: 500_000,
            throughput_uplift_millionths: 200_000,
            security_risk_reduction_millionths: 100_000,
            expected_value_score_millionths: 300_000,
            weighted_expected_value_score_millionths: 150_000,
        };
        let json = serde_json::to_string(&c).unwrap();
        let restored: ReplacementPriorityCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(c, restored);
    }

    #[test]
    fn replacement_progress_event_serde_roundtrip() {
        let ev = ReplacementProgressEvent {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            component: "replacement".to_string(),
            event: "snapshot".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            slot_id: None,
            detail: "complete".to_string(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let restored: ReplacementProgressEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, restored);
    }

    #[test]
    fn slot_replacement_signal_serde_roundtrip() {
        let sig = SlotReplacementSignal {
            invocation_weight_millionths: 300_000,
            throughput_uplift_millionths: 50_000,
            security_risk_reduction_millionths: 100_000,
        };
        let json = serde_json::to_string(&sig).unwrap();
        let restored: SlotReplacementSignal = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, restored);
    }

    #[test]
    fn replacement_progress_error_serde_roundtrip() {
        let errors: Vec<ReplacementProgressError> = vec![
            ReplacementProgressError::InvalidInput {
                field: "trace_id".to_string(),
                detail: "empty".to_string(),
            },
            ReplacementProgressError::UnknownSignalSlot {
                slot_id: "unknown".to_string(),
            },
            ReplacementProgressError::InvalidSignal {
                slot_id: "parser".to_string(),
                detail: "zero weight".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let restored: ReplacementProgressError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: ordering
    // -----------------------------------------------------------------------

    #[test]
    fn slot_id_ordering() {
        let a = SlotId::new("alpha").unwrap();
        let b = SlotId::new("beta").unwrap();
        assert!(a < b);
    }

    // -----------------------------------------------------------------------
    // Enrichment: error is std::error::Error
    // -----------------------------------------------------------------------

    #[test]
    fn slot_registry_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(SlotRegistryError::SlotNotFound {
            id: "x".to_string(),
        });
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn ga_release_guard_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(GaReleaseGuardError::InvalidInput {
            field: "f".to_string(),
            detail: "d".to_string(),
        });
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn replacement_progress_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ReplacementProgressError::InvalidInput {
            field: "f".to_string(),
            detail: "d".to_string(),
        });
        assert!(!err.to_string().is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: missing serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn ga_release_guard_config_serde_roundtrip() {
        let mut core = BTreeSet::new();
        core.insert(SlotId::new("parser").unwrap());
        let config = GaReleaseGuardConfig {
            core_slots: core,
            non_core_delegate_limit: Some(3),
            lineage_dashboard_ref: "dash://test".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: GaReleaseGuardConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn ga_signed_lineage_artifact_serde_roundtrip() {
        let art = GaSignedLineageArtifact {
            slot_id: SlotId::new("parser").unwrap(),
            former_delegate_digest: "fd-001".into(),
            replacement_component_digest: "rc-001".into(),
            replacement_author: "agent-a".into(),
            replacement_timestamp: "2026-02-25T00:00:00Z".into(),
            lineage_signature: "sig-001".into(),
            trust_anchor_ref: "anchor-001".into(),
            signature_verified: true,
            equivalence_suite_ref: "suite-001".into(),
            equivalence_passed: true,
            delegate_fallback_reachable: false,
        };
        let json = serde_json::to_string(&art).unwrap();
        let back: GaSignedLineageArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(art, back);
    }

    #[test]
    fn ga_release_slot_status_serde_roundtrip() {
        let status = GaReleaseSlotStatus {
            slot_id: SlotId::new("parser").unwrap(),
            slot_kind: SlotKind::Parser,
            slot_class: ReleaseSlotClass::Core,
            promotion_status: "promoted".into(),
            delegate_backed: false,
            blocking: false,
            exemption_id: None,
            lineage_signature_verified: Some(true),
            equivalence_passed: Some(true),
            delegate_fallback_reachable: Some(false),
            estimated_remediation: "n/a".into(),
        };
        let json = serde_json::to_string(&status).unwrap();
        let back: GaReleaseSlotStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }

    #[test]
    fn ga_release_guard_artifact_serde_roundtrip() {
        let artifact = GaReleaseGuardArtifact {
            trace_id: "t-001".into(),
            decision_id: "d-001".into(),
            policy_id: "p-001".into(),
            component: "ga-guard".into(),
            verdict: GaReleaseGuardVerdict::Pass,
            total_slots: 5,
            core_slot_count: 2,
            core_delegate_count: 0,
            non_core_delegate_count: 1,
            native_coverage_millionths: 800_000,
            lineage_dashboard_ref: "dash://test".into(),
            exemptions_applied: vec![],
            core_slots_missing_lineage: vec![],
            core_slots_lineage_mismatch: vec![],
            core_slots_invalid_signature: vec![],
            core_slots_equivalence_failed: vec![],
            core_slots_delegate_fallback_reachable: vec![],
            slot_statuses: vec![],
            blocking_slots: vec![],
            events: vec![],
        };
        let json = serde_json::to_string(&artifact).unwrap();
        let back: GaReleaseGuardArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, back);
    }

    #[test]
    fn replacement_progress_snapshot_serde_roundtrip() {
        let snap = ReplacementProgressSnapshot {
            trace_id: "t-001".into(),
            decision_id: "d-001".into(),
            policy_id: "p-001".into(),
            component: "replacement-progress".into(),
            total_slots: 4,
            native_slots: 3,
            delegate_slots: 1,
            native_coverage_millionths: 750_000,
            weighted_native_coverage_millionths: 800_000,
            weighted_delegate_throughput_uplift_millionths: 100_000,
            weighted_delegate_security_risk_reduction_millionths: 50_000,
            recommended_replacement_order: vec![],
            events: vec![],
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: ReplacementProgressSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: utility function tests
    // -----------------------------------------------------------------------

    #[test]
    fn saturating_i128_to_i64_within_range() {
        assert_eq!(saturating_i128_to_i64(42), 42i64);
        assert_eq!(saturating_i128_to_i64(-42), -42i64);
        assert_eq!(saturating_i128_to_i64(0), 0i64);
    }

    #[test]
    fn saturating_i128_to_i64_overflows() {
        assert_eq!(saturating_i128_to_i64(i128::MAX), i64::MAX);
        assert_eq!(saturating_i128_to_i64(i128::MIN), i64::MIN);
        assert_eq!(saturating_i128_to_i64(i64::MAX as i128 + 1), i64::MAX);
        assert_eq!(saturating_i128_to_i64(i64::MIN as i128 - 1), i64::MIN);
    }

    #[test]
    fn saturating_u128_to_i128_within_range() {
        assert_eq!(saturating_u128_to_i128(0), 0i128);
        assert_eq!(saturating_u128_to_i128(42), 42i128);
    }

    #[test]
    fn saturating_u128_to_i128_overflows() {
        assert_eq!(saturating_u128_to_i128(u128::MAX), i128::MAX);
        assert_eq!(saturating_u128_to_i128(i128::MAX as u128 + 1), i128::MAX);
    }

    // -----------------------------------------------------------------------
    // Enrichment: method tests
    // -----------------------------------------------------------------------

    #[test]
    fn expected_value_score_millionths_sums_components() {
        let signal = SlotReplacementSignal {
            invocation_weight_millionths: 1_000_000,
            throughput_uplift_millionths: 300_000,
            security_risk_reduction_millionths: 200_000,
        };
        assert_eq!(signal.expected_value_score_millionths(), 500_000);
    }

    #[test]
    fn expected_value_score_millionths_negative() {
        let signal = SlotReplacementSignal {
            invocation_weight_millionths: 1_000_000,
            throughput_uplift_millionths: -100_000,
            security_risk_reduction_millionths: 50_000,
        };
        assert_eq!(signal.expected_value_score_millionths(), -50_000);
    }

    #[test]
    fn slot_registry_serde_roundtrip() {
        let mut reg = SlotRegistry::new();
        register_slot(&mut reg, "parser", SlotKind::Parser, "digest-parser");
        let json = serde_json::to_string(&reg).unwrap();
        let back: SlotRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(reg.len(), back.len());
        assert_eq!(
            reg.get(&SlotId::new("parser").unwrap()).unwrap().kind,
            back.get(&SlotId::new("parser").unwrap()).unwrap().kind,
        );
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn slot_id_rejects_underscore_chars() {
        assert!(matches!(
            SlotId::new("my_parser"),
            Err(SlotRegistryError::InvalidSlotId { .. })
        ));
    }

    #[test]
    fn slot_id_rejects_space_chars() {
        assert!(matches!(
            SlotId::new("my parser"),
            Err(SlotRegistryError::InvalidSlotId { .. })
        ));
    }

    #[test]
    fn native_coverage_empty_registry_returns_zero() {
        let reg = SlotRegistry::new();
        assert_eq!(reg.native_coverage(), 0.0);
    }

    #[test]
    fn native_coverage_all_delegates_returns_zero() {
        let mut reg = SlotRegistry::new();
        register_slot(&mut reg, "parser", SlotKind::Parser, "d1");
        register_slot(&mut reg, "interpreter", SlotKind::Interpreter, "d2");
        assert_eq!(reg.native_coverage(), 0.0);
        assert_eq!(reg.native_count(), 0);
        assert_eq!(reg.delegate_count(), 2);
    }

    #[test]
    fn native_coverage_all_native_returns_one() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        reg.register_delegate(
            id.clone(),
            SlotKind::Parser,
            test_authority(),
            "sha256:d1".into(),
            "t0".into(),
        )
        .unwrap();
        reg.begin_candidacy(&id, "sha256:candidate-1".into(), "t1".into())
            .unwrap();
        reg.promote(
            &id,
            "sha256:native-1".into(),
            &test_authority(),
            "receipt-1".into(),
            "t2".into(),
        )
        .unwrap();
        assert_eq!(reg.native_coverage(), 1.0);
    }

    #[test]
    fn authority_subsumes_partial_overlap_fails() {
        let broad = AuthorityEnvelope {
            required: vec![SlotCapability::ReadSource],
            permitted: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
        };
        let mixed = AuthorityEnvelope {
            required: vec![SlotCapability::ReadSource],
            permitted: vec![
                SlotCapability::ReadSource,
                SlotCapability::EmitIr,
                SlotCapability::HeapAlloc,
            ],
        };
        // broad does not subsume mixed because HeapAlloc not in broad.permitted
        assert!(!broad.subsumes(&mixed));
    }

    #[test]
    fn ga_release_guard_input_serde_roundtrip() {
        let input = GaReleaseGuardInput {
            trace_id: "trace-ga-1".to_string(),
            decision_id: "decision-ga-1".to_string(),
            policy_id: "policy-ga-1".to_string(),
            current_epoch: SecurityEpoch::from_raw(5),
            config: GaReleaseGuardConfig::default(),
            exemptions: Vec::new(),
            lineage_artifacts: Vec::new(),
            remediation_estimates: BTreeMap::new(),
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: GaReleaseGuardInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input.trace_id, back.trace_id);
        assert_eq!(input.decision_id, back.decision_id);
        assert_eq!(input.current_epoch, back.current_epoch);
    }

    #[test]
    fn slot_kind_variants_are_distinct() {
        assert_ne!(SlotKind::Parser, SlotKind::Interpreter);
        assert_ne!(SlotKind::Interpreter, SlotKind::Builtins);
        assert_ne!(SlotKind::Parser, SlotKind::GarbageCollector);
    }

    #[test]
    fn slot_capability_variants_are_distinct() {
        assert_ne!(SlotCapability::ReadSource, SlotCapability::EmitIr);
        assert_ne!(SlotCapability::EmitIr, SlotCapability::HeapAlloc);
        assert_ne!(SlotCapability::TriggerGc, SlotCapability::EmitEvidence);
    }

    #[test]
    fn slot_entry_serde_preserves_lineage() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        reg.register_delegate(
            id.clone(),
            SlotKind::Parser,
            test_authority(),
            "sha256:d1".into(),
            "t0".into(),
        )
        .unwrap();
        reg.begin_candidacy(&id, "sha256:c1".into(), "t1".into())
            .unwrap();
        let entry = reg.get(&id).unwrap();
        assert_eq!(entry.promotion_lineage.len(), 2);
        let json = serde_json::to_string(entry).unwrap();
        let back: SlotEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.promotion_lineage.len(), 2);
        assert_eq!(
            back.promotion_lineage[0].transition,
            PromotionTransition::RegisteredDelegate
        );
        assert_eq!(
            back.promotion_lineage[1].transition,
            PromotionTransition::EnteredCandidacy
        );
    }

    #[test]
    fn registry_len_and_is_empty() {
        let mut reg = SlotRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        register_slot(&mut reg, "parser", SlotKind::Parser, "d1");
        assert!(!reg.is_empty());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn replacement_signal_validate_rejects_zero_weight() {
        let signal = SlotReplacementSignal {
            invocation_weight_millionths: 0,
            throughput_uplift_millionths: 100_000,
            security_risk_reduction_millionths: 50_000,
        };
        let slot_id = SlotId::new("parser").unwrap();
        let err = signal.validate(&slot_id).unwrap_err();
        assert!(matches!(
            err,
            ReplacementProgressError::InvalidSignal { .. }
        ));
    }

    #[test]
    fn slot_registry_default_is_empty() {
        let reg = SlotRegistry::default();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn slot_id_serde_preserves_value() {
        let id = SlotId::new("ir-lowering").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"ir-lowering\"");
        let back: SlotId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn promotion_status_display_promoted_includes_receipt() {
        let status = PromotionStatus::Promoted {
            native_digest: "sha256:abc".to_string(),
            receipt_id: "receipt-42".to_string(),
        };
        let display = status.to_string();
        assert!(display.contains("sha256:abc"));
        assert!(display.contains("receipt-42"));
    }

    #[test]
    fn promotion_status_display_demoted_includes_reason() {
        let status = PromotionStatus::Demoted {
            reason: "regression detected".to_string(),
            rollback_digest: "sha256:rollback".to_string(),
        };
        let display = status.to_string();
        assert!(display.contains("regression detected"));
    }

    // -- Enrichment: PearlTower 2026-02-26 session 5 --

    #[test]
    fn is_ga_ready_mixed_slots_not_ready() {
        let mut reg = SlotRegistry::new();
        let parser = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-parser");
        register_slot(
            &mut reg,
            "interpreter",
            SlotKind::Interpreter,
            "sha256:d-interp",
        );
        promote_slot(&mut reg, &parser, "sha256:n-parser");
        assert!(
            !reg.is_ga_ready(),
            "mixed native/delegate should not be GA ready"
        );
        assert_eq!(reg.native_count(), 1);
        assert_eq!(reg.delegate_count(), 1);
    }

    #[test]
    fn ga_guard_blocks_on_lineage_digest_mismatch() {
        let mut reg = SlotRegistry::new();
        let parser = register_slot(
            &mut reg,
            "parser",
            SlotKind::Parser,
            "sha256:delegate-parser",
        );
        promote_slot(&mut reg, &parser, "sha256:native-parser");

        let core_slots = BTreeSet::from([parser.clone()]);
        let mut input = guard_input(core_slots, None);
        let wrong_lineage =
            lineage_artifact(&parser, "sha256:delegate-parser", "sha256:wrong-digest");
        input.lineage_artifacts = vec![wrong_lineage];

        let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
        assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
        assert_eq!(artifact.core_slots_lineage_mismatch, vec![parser]);
    }

    #[test]
    fn ga_guard_blocks_on_equivalence_failure() {
        let mut reg = SlotRegistry::new();
        let parser = register_slot(
            &mut reg,
            "parser",
            SlotKind::Parser,
            "sha256:delegate-parser",
        );
        promote_slot(&mut reg, &parser, "sha256:native-parser");

        let core_slots = BTreeSet::from([parser.clone()]);
        let mut input = guard_input(core_slots, None);
        let mut lineage =
            lineage_artifact(&parser, "sha256:delegate-parser", "sha256:native-parser");
        lineage.equivalence_passed = false;
        input.lineage_artifacts = vec![lineage];

        let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
        assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
        assert_eq!(artifact.core_slots_equivalence_failed, vec![parser]);
    }

    #[test]
    fn ga_guard_rejects_duplicate_exemptions() {
        let mut reg = SlotRegistry::new();
        let parser = register_slot(
            &mut reg,
            "parser",
            SlotKind::Parser,
            "sha256:delegate-parser",
        );
        let core_slots = BTreeSet::from([parser.clone()]);
        let mut input = guard_input(core_slots, None);
        input.exemptions = vec![exemption_for(parser.clone()), exemption_for(parser)];
        let err = reg.evaluate_ga_release_guard(&input).unwrap_err();
        assert!(matches!(
            err,
            GaReleaseGuardError::DuplicateExemption { .. }
        ));
    }

    #[test]
    fn ga_guard_rejects_duplicate_lineage_artifacts() {
        let mut reg = SlotRegistry::new();
        let parser = register_slot(
            &mut reg,
            "parser",
            SlotKind::Parser,
            "sha256:delegate-parser",
        );
        promote_slot(&mut reg, &parser, "sha256:native-parser");

        let core_slots = BTreeSet::from([parser.clone()]);
        let mut input = guard_input(core_slots, None);
        input.lineage_artifacts = vec![
            lineage_artifact(&parser, "sha256:delegate-parser", "sha256:native-parser"),
            lineage_artifact(&parser, "sha256:delegate-parser", "sha256:native-parser"),
        ];
        let err = reg.evaluate_ga_release_guard(&input).unwrap_err();
        assert!(matches!(
            err,
            GaReleaseGuardError::DuplicateLineageArtifact { .. }
        ));
    }

    #[test]
    fn re_promotion_from_demoted_state() {
        let mut reg = SlotRegistry::new();
        let id = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d1");
        promote_slot(&mut reg, &id, "sha256:n1");
        reg.demote(&id, "regression".into(), "t3".into()).unwrap();
        assert!(reg.get(&id).unwrap().status.is_delegate());

        reg.begin_candidacy(&id, "sha256:c2".into(), "t4".into())
            .unwrap();
        assert!(matches!(
            reg.get(&id).unwrap().status,
            PromotionStatus::PromotionCandidate { .. }
        ));
        reg.promote(
            &id,
            "sha256:n2".into(),
            &narrower_authority(),
            "receipt-n2".into(),
            "t5".into(),
        )
        .unwrap();
        assert!(reg.get(&id).unwrap().status.is_native());
        assert_eq!(reg.get(&id).unwrap().promotion_lineage.len(), 6);
    }

    #[test]
    fn demote_restores_implementation_digest() {
        let mut reg = SlotRegistry::new();
        let id = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:delegate-v1");
        promote_slot(&mut reg, &id, "sha256:native-v1");
        assert_eq!(
            reg.get(&id).unwrap().implementation_digest,
            "sha256:native-v1"
        );
        reg.demote(&id, "perf regression".into(), "t3".into())
            .unwrap();
        assert_eq!(
            reg.get(&id).unwrap().implementation_digest,
            "sha256:delegate-v1",
            "implementation_digest should be restored to rollback_target"
        );
    }

    #[test]
    fn ga_guard_rejects_empty_lineage_dashboard_ref() {
        let mut reg = SlotRegistry::new();
        register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d");
        let mut input = guard_input(BTreeSet::new(), None);
        input.config.lineage_dashboard_ref = "  ".to_string();
        let err = reg.evaluate_ga_release_guard(&input).unwrap_err();
        assert!(matches!(
            err,
            GaReleaseGuardError::InvalidInput { field, .. } if field == "lineage_dashboard_ref"
        ));
    }

    // -- Enrichment: PearlTower 2026-02-26 session 8 --

    #[test]
    fn register_delegate_rejects_inconsistent_authority() {
        let mut reg = SlotRegistry::new();
        let id = SlotId::new("parser").unwrap();
        // HeapAlloc is required but not in permitted → inconsistent
        let bad_authority = AuthorityEnvelope {
            required: vec![SlotCapability::ReadSource, SlotCapability::HeapAlloc],
            permitted: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
        };
        let err = reg
            .register_delegate(
                id,
                SlotKind::Parser,
                bad_authority,
                "sha256:d".into(),
                "t0".into(),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            SlotRegistryError::InconsistentAuthority { .. }
        ));
    }

    #[test]
    fn register_delegate_rejects_duplicate_slot_id() {
        let mut reg = SlotRegistry::new();
        register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d1");
        let id = SlotId::new("parser").unwrap();
        let err = reg
            .register_delegate(
                id,
                SlotKind::Parser,
                test_authority(),
                "sha256:d2".into(),
                "t1".into(),
            )
            .unwrap_err();
        assert!(matches!(err, SlotRegistryError::DuplicateSlotId { .. }));
    }

    #[test]
    fn promote_rejects_authority_broadening() {
        let mut reg = SlotRegistry::new();
        let id = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d1");
        reg.begin_candidacy(&id, "sha256:c1".into(), "t1".into())
            .unwrap();
        // broader_authority() includes HeapAlloc and InvokeHostcall which
        // are not in test_authority().permitted → AuthorityBroadening
        let err = reg
            .promote(
                &id,
                "sha256:n1".into(),
                &broader_authority(),
                "receipt-1".into(),
                "t2".into(),
            )
            .unwrap_err();
        assert!(matches!(err, SlotRegistryError::AuthorityBroadening { .. }));
    }

    #[test]
    fn promote_rejects_inconsistent_native_authority() {
        let mut reg = SlotRegistry::new();
        let id = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d1");
        reg.begin_candidacy(&id, "sha256:c1".into(), "t1".into())
            .unwrap();
        let bad_native_authority = AuthorityEnvelope {
            required: vec![SlotCapability::ReadSource, SlotCapability::EmitIr],
            permitted: vec![SlotCapability::ReadSource],
        };
        let err = reg
            .promote(
                &id,
                "sha256:n1".into(),
                &bad_native_authority,
                "receipt-1".into(),
                "t2".into(),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            SlotRegistryError::InconsistentAuthority { .. }
        ));
        let entry = reg.get(&id).expect("slot remains registered");
        assert!(matches!(
            entry.status,
            PromotionStatus::PromotionCandidate { .. }
        ));
        assert_eq!(entry.implementation_digest, "sha256:d1");
        assert_eq!(entry.rollback_target, None);
    }

    #[test]
    fn begin_candidacy_from_native_is_invalid_transition() {
        let mut reg = SlotRegistry::new();
        let id = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d1");
        promote_slot(&mut reg, &id, "sha256:n1");
        assert!(reg.get(&id).unwrap().status.is_native());
        let err = reg
            .begin_candidacy(&id, "sha256:c2".into(), "t3".into())
            .unwrap_err();
        assert!(matches!(err, SlotRegistryError::InvalidTransition { .. }));
    }

    #[test]
    fn demote_from_delegate_is_invalid_transition() {
        let mut reg = SlotRegistry::new();
        let id = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d1");
        assert!(reg.get(&id).unwrap().status.is_delegate());
        let err = reg.demote(&id, "reason".into(), "t1".into()).unwrap_err();
        assert!(matches!(err, SlotRegistryError::InvalidTransition { .. }));
    }

    #[test]
    fn ga_guard_blocks_core_delegate_without_exemption() {
        let mut reg = SlotRegistry::new();
        let parser = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-parser");
        // parser remains delegate, declared as core slot
        let core_slots = BTreeSet::from([parser.clone()]);
        let input = guard_input(core_slots, None);
        let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
        assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
        assert_eq!(artifact.core_delegate_count, 1);
        assert!(!artifact.blocking_slots.is_empty());
        assert!(artifact.blocking_slots[0].blocking);
    }

    #[test]
    fn ga_guard_blocks_invalid_lineage_signature() {
        let mut reg = SlotRegistry::new();
        let parser = register_slot(
            &mut reg,
            "parser",
            SlotKind::Parser,
            "sha256:delegate-parser",
        );
        promote_slot(&mut reg, &parser, "sha256:native-parser");

        let core_slots = BTreeSet::from([parser.clone()]);
        let mut input = guard_input(core_slots, None);
        let mut lineage =
            lineage_artifact(&parser, "sha256:delegate-parser", "sha256:native-parser");
        lineage.signature_verified = false;
        input.lineage_artifacts = vec![lineage];

        let artifact = reg.evaluate_ga_release_guard(&input).unwrap();
        assert_eq!(artifact.verdict, GaReleaseGuardVerdict::Blocked);
        assert_eq!(artifact.core_slots_invalid_signature, vec![parser]);
    }

    #[test]
    fn snapshot_replacement_progress_weighted_coverage() {
        let mut reg = SlotRegistry::new();
        let parser = register_slot(&mut reg, "parser", SlotKind::Parser, "sha256:d-parser");
        let interp = register_slot(
            &mut reg,
            "interpreter",
            SlotKind::Interpreter,
            "sha256:d-interp",
        );
        promote_slot(&mut reg, &parser, "sha256:n-parser");
        // parser is native with weight 3M, interpreter is delegate with weight 1M
        let mut signals = BTreeMap::new();
        signals.insert(
            parser.clone(),
            SlotReplacementSignal {
                invocation_weight_millionths: 3_000_000,
                throughput_uplift_millionths: 0,
                security_risk_reduction_millionths: 0,
            },
        );
        signals.insert(
            interp.clone(),
            SlotReplacementSignal {
                invocation_weight_millionths: 1_000_000,
                throughput_uplift_millionths: 200_000,
                security_risk_reduction_millionths: 100_000,
            },
        );
        let snap = reg
            .snapshot_replacement_progress("t1", "d1", "p1", &signals)
            .unwrap();
        assert_eq!(snap.total_slots, 2);
        assert_eq!(snap.native_slots, 1);
        assert_eq!(snap.delegate_slots, 1);
        // weighted native coverage = 3M / (3M + 1M) * 1M = 750_000
        assert_eq!(snap.weighted_native_coverage_millionths, 750_000);
        // one delegate candidate in replacement order
        assert_eq!(snap.recommended_replacement_order.len(), 1);
        assert_eq!(snap.recommended_replacement_order[0].slot_id, interp);
        assert!(snap.recommended_replacement_order[0].delegate_backed);
    }
}
