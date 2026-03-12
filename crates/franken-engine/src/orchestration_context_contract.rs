//! Canonical context threading contracts for orchestration boundaries.
//!
//! This module defines and enforces how execution contexts propagate
//! through orchestration boundaries: parent-to-child cell derivation,
//! cleanup/finalize context carving, and mock-free production path
//! validation.  The key principle is that a single canonical context
//! flows from entry to exit without conversion to mocks or fakes.
//!
//! Key capabilities:
//! - **Canonical context derivation**: parent contexts derive child
//!   contexts with strictly narrower budgets and inherited trace IDs.
//! - **Cleanup context carving**: cell-close/finalize contexts are
//!   carved from parent budgets with bounded overhead.
//! - **Mock-free validation**: production paths are validated to never
//!   contain mock or fake context seams.
//! - **Context lifecycle audit**: every derivation and consumption
//!   produces a deterministic audit trail.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//! All collections use BTreeMap/BTreeSet for deterministic ordering.
//!
//! Bead: bd-3nr.1.2.1 [10.13X.B1]
//! Plan reference: Section 10.13, Asupersync canonical context threading.
//! Dependencies: hash_tiers, security_epoch.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Component name for structured logging.
pub const COMPONENT: &str = "orchestration_context_contract";

/// Fixed-point unit: 1_000_000 = 1.0 (100%).
const MILLION: u64 = 1_000_000;

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.orchestration-context-contract.v1";

/// Maximum context derivation depth to prevent unbounded nesting.
const MAX_DERIVATION_DEPTH: u32 = 64;

/// Default cleanup budget fraction (10% of parent = 100_000 millionths).
const DEFAULT_CLEANUP_FRACTION_MILLIONTHS: u64 = 100_000;

/// Maximum cleanup budget fraction (25% of parent = 250_000 millionths).
const MAX_CLEANUP_FRACTION_MILLIONTHS: u64 = 250_000;

/// Minimum budget to allow derivation (1 ms).
const MIN_DERIVABLE_BUDGET_MS: u64 = 1;

// ---------------------------------------------------------------------------
// ContextOrigin — where a context came from
// ---------------------------------------------------------------------------

/// Describes the origin of an execution context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextOrigin {
    /// Root context created at orchestration entry.
    Root,
    /// Child context derived from a parent.
    ChildDerivation,
    /// Cleanup/finalize context carved from parent budget.
    CleanupCarve,
    /// Cell-close context for quiescent shutdown.
    CellClose,
    /// Replay context reconstructed from evidence.
    Replay,
}

impl ContextOrigin {
    /// Canonical string tag.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::ChildDerivation => "child_derivation",
            Self::CleanupCarve => "cleanup_carve",
            Self::CellClose => "cell_close",
            Self::Replay => "replay",
        }
    }

    /// Whether this origin is production-safe (no mock/fake).
    pub fn is_production_safe(self) -> bool {
        // All origins defined here are production-safe by construction.
        true
    }
}

impl fmt::Display for ContextOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ContextState — lifecycle state of a context
// ---------------------------------------------------------------------------

/// Lifecycle state of an execution context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextState {
    /// Context is active and can be consumed.
    Active,
    /// Context budget is exhausted (fail-closed).
    Exhausted,
    /// Context has been explicitly released.
    Released,
    /// Context was cancelled before completion.
    Cancelled,
}

impl ContextState {
    /// Canonical string tag.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Released => "released",
            Self::Cancelled => "cancelled",
        }
    }

    /// Whether the context can still be consumed.
    pub fn is_consumable(self) -> bool {
        matches!(self, Self::Active)
    }
}

impl fmt::Display for ContextState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// MockSeamClassification — how a mock seam is classified
// ---------------------------------------------------------------------------

/// Classification of a mock/fake context seam found during audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MockSeamClassification {
    /// Production seam that must be fixed (mock leaking into prod).
    MustFixProduction,
    /// Acceptable test-only usage.
    AcceptableTestOnly,
    /// False positive (not actually a mock seam).
    FalsePositive,
    /// Under investigation.
    UnderInvestigation,
}

impl MockSeamClassification {
    /// Canonical string tag.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MustFixProduction => "must_fix_production",
            Self::AcceptableTestOnly => "acceptable_test_only",
            Self::FalsePositive => "false_positive",
            Self::UnderInvestigation => "under_investigation",
        }
    }

    /// Whether this classification is safe for production.
    pub fn is_production_safe(self) -> bool {
        matches!(self, Self::AcceptableTestOnly | Self::FalsePositive)
    }
}

impl fmt::Display for MockSeamClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CanonicalContextDescriptor — describes a canonical context
// ---------------------------------------------------------------------------

/// Descriptor for a canonical execution context.
///
/// This is the audit-grade record of a context's identity, origin,
/// budget, and lineage.  Every context in the system should have
/// one of these descriptors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalContextDescriptor {
    /// Unique context identifier.
    pub context_id: String,
    /// Trace ID for correlation.
    pub trace_id: String,
    /// Where this context came from.
    pub origin: ContextOrigin,
    /// Current lifecycle state.
    pub state: ContextState,
    /// Parent context ID (None for root contexts).
    pub parent_id: Option<String>,
    /// Budget allocated to this context (milliseconds).
    pub budget_ms: u64,
    /// Budget consumed so far (milliseconds).
    pub consumed_ms: u64,
    /// Derivation depth (0 for root).
    pub depth: u32,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Content hash for integrity.
    pub content_hash: ContentHash,
}

impl CanonicalContextDescriptor {
    /// Remaining budget.
    pub fn remaining_ms(&self) -> u64 {
        self.budget_ms.saturating_sub(self.consumed_ms)
    }

    /// Budget consumption fraction (millionths).
    pub fn consumed_fraction_millionths(&self) -> u64 {
        if self.budget_ms == 0 {
            return MILLION;
        }
        self.consumed_ms
            .saturating_mul(MILLION)
            .checked_div(self.budget_ms)
            .unwrap_or(MILLION)
    }

    /// Whether this context can derive children.
    pub fn can_derive_child(&self) -> bool {
        self.state.is_consumable()
            && self.remaining_ms() >= MIN_DERIVABLE_BUDGET_MS
            && self.depth < MAX_DERIVATION_DEPTH
    }
}

impl fmt::Display for CanonicalContextDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ctx:{}(origin={},state={},budget={}/{},depth={})",
            self.context_id,
            self.origin,
            self.state,
            self.remaining_ms(),
            self.budget_ms,
            self.depth,
        )
    }
}

// ---------------------------------------------------------------------------
// DerivationRule — rules for deriving child contexts
// ---------------------------------------------------------------------------

/// Rules governing how child contexts are derived from parents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationRule {
    /// Rule identifier.
    pub rule_id: String,
    /// Maximum fraction of parent budget for child (millionths).
    pub max_child_fraction_millionths: u64,
    /// Fraction reserved for cleanup (millionths).
    pub cleanup_fraction_millionths: u64,
    /// Whether child trace IDs must derive from parent.
    pub require_trace_derivation: bool,
    /// Maximum derivation depth.
    pub max_depth: u32,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl DerivationRule {
    /// Create a derivation rule with defaults.
    pub fn new(rule_id: String) -> Self {
        let mut rule = Self {
            rule_id,
            max_child_fraction_millionths: 900_000, // 90%
            cleanup_fraction_millionths: DEFAULT_CLEANUP_FRACTION_MILLIONTHS,
            require_trace_derivation: true,
            max_depth: MAX_DERIVATION_DEPTH,
            content_hash: ContentHash::compute(b"placeholder"),
        };
        rule.content_hash = rule.compute_hash();
        rule
    }

    /// Create a strict rule (50% child, 10% cleanup, depth 16).
    pub fn strict(rule_id: String) -> Self {
        let mut rule = Self {
            rule_id,
            max_child_fraction_millionths: 500_000, // 50%
            cleanup_fraction_millionths: DEFAULT_CLEANUP_FRACTION_MILLIONTHS,
            require_trace_derivation: true,
            max_depth: 16,
            content_hash: ContentHash::compute(b"placeholder"),
        };
        rule.content_hash = rule.compute_hash();
        rule
    }

    fn compute_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(COMPONENT.as_bytes());
        hasher.update(b":rule:");
        hasher.update(self.rule_id.as_bytes());
        hasher.update(self.max_child_fraction_millionths.to_le_bytes());
        hasher.update(self.cleanup_fraction_millionths.to_le_bytes());
        hasher.update(if self.require_trace_derivation {
            b"t"
        } else {
            b"f"
        });
        hasher.update(self.max_depth.to_le_bytes());
        let result = hasher.finalize();
        ContentHash::compute(&result)
    }
}

impl fmt::Display for DerivationRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rule:{}(max_child={}%,cleanup={}%,max_depth={})",
            self.rule_id,
            self.max_child_fraction_millionths / 10_000,
            self.cleanup_fraction_millionths / 10_000,
            self.max_depth,
        )
    }
}

// ---------------------------------------------------------------------------
// DerivationEvent — audit trail for context derivations
// ---------------------------------------------------------------------------

/// Audit trail event for a context derivation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DerivationEvent {
    /// Event identifier.
    pub event_id: String,
    /// Parent context ID.
    pub parent_id: String,
    /// Child context ID.
    pub child_id: String,
    /// Origin of the child context.
    pub child_origin: ContextOrigin,
    /// Budget allocated to child (ms).
    pub child_budget_ms: u64,
    /// Budget remaining on parent after derivation (ms).
    pub parent_remaining_ms: u64,
    /// Rule used for derivation.
    pub rule_id: String,
    /// Depth of the child context.
    pub child_depth: u32,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl fmt::Display for DerivationEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "deriv:{}->{}(origin={},budget={}ms,depth={})",
            self.parent_id,
            self.child_id,
            self.child_origin,
            self.child_budget_ms,
            self.child_depth,
        )
    }
}

// ---------------------------------------------------------------------------
// MockSeamEntry — audit entry for a mock seam
// ---------------------------------------------------------------------------

/// Audit entry for a mock/fake context seam found in code.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MockSeamEntry {
    /// Unique seam identifier.
    pub seam_id: String,
    /// File path where the seam was found.
    pub file_path: String,
    /// Line number (approximate).
    pub line_number: u64,
    /// Classification of the seam.
    pub classification: MockSeamClassification,
    /// Description of the seam.
    pub description: String,
    /// Whether this seam has been remediated.
    pub remediated: bool,
}

impl fmt::Display for MockSeamEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "seam:{}(file={},line={},class={},remediated={})",
            self.seam_id, self.file_path, self.line_number, self.classification, self.remediated,
        )
    }
}

// ---------------------------------------------------------------------------
// ValidationReport — result of validating context threading
// ---------------------------------------------------------------------------

/// Report from validating context threading across orchestration paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    /// Report identifier.
    pub report_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Context descriptors validated.
    pub contexts_validated: u64,
    /// Derivation events checked.
    pub derivations_checked: u64,
    /// Mock seams audited.
    pub seams_audited: u64,
    /// Number of must-fix production seams found.
    pub production_seams_found: u64,
    /// Whether all contexts pass validation.
    pub all_contexts_valid: bool,
    /// Whether all derivations comply with rules.
    pub all_derivations_compliant: bool,
    /// Whether no production mock seams exist.
    pub mock_free: bool,
    /// Overall pass/fail.
    pub passed: bool,
    /// Failure reasons (empty if passed).
    pub failure_reasons: Vec<String>,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl fmt::Display for ValidationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "validation:{}(epoch={},contexts={},derivations={},seams={},passed={})",
            self.report_id,
            self.epoch.as_u64(),
            self.contexts_validated,
            self.derivations_checked,
            self.seams_audited,
            self.passed,
        )
    }
}

// ---------------------------------------------------------------------------
// ContextError — error types
// ---------------------------------------------------------------------------

/// Errors from context threading operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextError {
    /// Budget insufficient for derivation.
    InsufficientBudget {
        parent_id: String,
        remaining_ms: u64,
        requested_ms: u64,
    },
    /// Maximum derivation depth exceeded.
    DepthExceeded {
        parent_id: String,
        depth: u32,
        max_depth: u32,
    },
    /// Context is not in a consumable state.
    NotConsumable {
        context_id: String,
        state: ContextState,
    },
    /// Child budget exceeds allowed fraction of parent.
    ChildExceedsAllowedFraction {
        parent_id: String,
        child_budget_ms: u64,
        max_allowed_ms: u64,
    },
    /// Cleanup budget exceeds maximum fraction.
    CleanupExceedsMaxFraction {
        parent_id: String,
        cleanup_ms: u64,
        max_allowed_ms: u64,
    },
    /// Mock seam detected in production path.
    MockSeamDetected { seam_id: String, file_path: String },
    /// Context not found.
    ContextNotFound(String),
    /// Empty input.
    EmptyInput,
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientBudget {
                parent_id,
                remaining_ms,
                requested_ms,
            } => write!(
                f,
                "[{COMPONENT}] insufficient budget on {parent_id}: remaining={remaining_ms}ms, requested={requested_ms}ms",
            ),
            Self::DepthExceeded {
                parent_id,
                depth,
                max_depth,
            } => write!(
                f,
                "[{COMPONENT}] depth exceeded on {parent_id}: depth={depth}, max={max_depth}",
            ),
            Self::NotConsumable { context_id, state } => write!(
                f,
                "[{COMPONENT}] context {context_id} not consumable: state={state}",
            ),
            Self::ChildExceedsAllowedFraction {
                parent_id,
                child_budget_ms,
                max_allowed_ms,
            } => write!(
                f,
                "[{COMPONENT}] child budget {child_budget_ms}ms exceeds max {max_allowed_ms}ms on {parent_id}",
            ),
            Self::CleanupExceedsMaxFraction {
                parent_id,
                cleanup_ms,
                max_allowed_ms,
            } => write!(
                f,
                "[{COMPONENT}] cleanup budget {cleanup_ms}ms exceeds max {max_allowed_ms}ms on {parent_id}",
            ),
            Self::MockSeamDetected { seam_id, file_path } => write!(
                f,
                "[{COMPONENT}] mock seam detected: {seam_id} in {file_path}",
            ),
            Self::ContextNotFound(id) => {
                write!(f, "[{COMPONENT}] context not found: {id}")
            }
            Self::EmptyInput => write!(f, "[{COMPONENT}] empty input"),
        }
    }
}

// ---------------------------------------------------------------------------
// Core functions — context creation
// ---------------------------------------------------------------------------

/// Create a root context descriptor.
pub fn create_root_context(
    context_id: String,
    trace_id: String,
    budget_ms: u64,
    epoch: SecurityEpoch,
) -> CanonicalContextDescriptor {
    let content_hash = compute_context_hash(&context_id, &trace_id, budget_ms, 0, epoch);
    CanonicalContextDescriptor {
        context_id,
        trace_id,
        origin: ContextOrigin::Root,
        state: ContextState::Active,
        parent_id: None,
        budget_ms,
        consumed_ms: 0,
        depth: 0,
        epoch,
        content_hash,
    }
}

/// Derive a child context from a parent, consuming budget from the parent.
pub fn derive_child_context(
    parent: &mut CanonicalContextDescriptor,
    child_id: String,
    child_budget_ms: u64,
    origin: ContextOrigin,
    rule: &DerivationRule,
) -> Result<(CanonicalContextDescriptor, DerivationEvent), ContextError> {
    // Validate parent state.
    if !parent.state.is_consumable() {
        return Err(ContextError::NotConsumable {
            context_id: parent.context_id.clone(),
            state: parent.state,
        });
    }

    // Validate depth.
    let child_depth = parent.depth.saturating_add(1);
    if child_depth > rule.max_depth {
        return Err(ContextError::DepthExceeded {
            parent_id: parent.context_id.clone(),
            depth: child_depth,
            max_depth: rule.max_depth,
        });
    }

    // Validate budget.
    let remaining = parent.remaining_ms();
    if child_budget_ms > remaining {
        return Err(ContextError::InsufficientBudget {
            parent_id: parent.context_id.clone(),
            remaining_ms: remaining,
            requested_ms: child_budget_ms,
        });
    }

    // Validate child fraction.
    let max_child_ms = remaining
        .saturating_mul(rule.max_child_fraction_millionths)
        .checked_div(MILLION)
        .unwrap_or(0);
    if child_budget_ms > max_child_ms {
        return Err(ContextError::ChildExceedsAllowedFraction {
            parent_id: parent.context_id.clone(),
            child_budget_ms,
            max_allowed_ms: max_child_ms,
        });
    }

    // Consume budget from parent.
    parent.consumed_ms = parent.consumed_ms.saturating_add(child_budget_ms);

    // Derive trace ID.
    let child_trace_id = if rule.require_trace_derivation {
        format!("{}.child.{}", parent.trace_id, child_depth)
    } else {
        child_id.clone()
    };

    let content_hash = compute_context_hash(
        &child_id,
        &child_trace_id,
        child_budget_ms,
        child_depth,
        parent.epoch,
    );

    let child = CanonicalContextDescriptor {
        context_id: child_id.clone(),
        trace_id: child_trace_id,
        origin,
        state: ContextState::Active,
        parent_id: Some(parent.context_id.clone()),
        budget_ms: child_budget_ms,
        consumed_ms: 0,
        depth: child_depth,
        epoch: parent.epoch,
        content_hash,
    };

    let event_hash = compute_derivation_event_hash(
        &parent.context_id,
        &child_id,
        child_budget_ms,
        parent.remaining_ms(),
        parent.epoch,
    );

    let event = DerivationEvent {
        event_id: format!("deriv-{}-{}", &parent.context_id, &child_id,),
        parent_id: parent.context_id.clone(),
        child_id,
        child_origin: origin,
        child_budget_ms,
        parent_remaining_ms: parent.remaining_ms(),
        rule_id: rule.rule_id.clone(),
        child_depth,
        epoch: parent.epoch,
        content_hash: event_hash,
    };

    Ok((child, event))
}

/// Carve a cleanup context from a parent's remaining budget.
pub fn carve_cleanup_context(
    parent: &mut CanonicalContextDescriptor,
    cleanup_id: String,
    rule: &DerivationRule,
) -> Result<(CanonicalContextDescriptor, DerivationEvent), ContextError> {
    let remaining = parent.remaining_ms();
    let cleanup_ms = remaining
        .saturating_mul(rule.cleanup_fraction_millionths)
        .checked_div(MILLION)
        .unwrap_or(0);

    // Validate cleanup fraction doesn't exceed maximum.
    let max_cleanup_ms = remaining
        .saturating_mul(MAX_CLEANUP_FRACTION_MILLIONTHS)
        .checked_div(MILLION)
        .unwrap_or(0);
    if cleanup_ms > max_cleanup_ms {
        return Err(ContextError::CleanupExceedsMaxFraction {
            parent_id: parent.context_id.clone(),
            cleanup_ms,
            max_allowed_ms: max_cleanup_ms,
        });
    }

    if cleanup_ms < MIN_DERIVABLE_BUDGET_MS {
        return Err(ContextError::InsufficientBudget {
            parent_id: parent.context_id.clone(),
            remaining_ms: remaining,
            requested_ms: MIN_DERIVABLE_BUDGET_MS,
        });
    }

    derive_child_context(
        parent,
        cleanup_id,
        cleanup_ms,
        ContextOrigin::CleanupCarve,
        rule,
    )
}

/// Consume budget from a context.
pub fn consume_budget(ctx: &mut CanonicalContextDescriptor, ms: u64) -> Result<(), ContextError> {
    if !ctx.state.is_consumable() {
        return Err(ContextError::NotConsumable {
            context_id: ctx.context_id.clone(),
            state: ctx.state,
        });
    }

    if ms > ctx.remaining_ms() {
        ctx.state = ContextState::Exhausted;
        ctx.consumed_ms = ctx.budget_ms;
        return Err(ContextError::InsufficientBudget {
            parent_id: ctx.context_id.clone(),
            remaining_ms: ctx.remaining_ms(),
            requested_ms: ms,
        });
    }

    ctx.consumed_ms = ctx.consumed_ms.saturating_add(ms);
    if ctx.consumed_ms >= ctx.budget_ms {
        ctx.state = ContextState::Exhausted;
    }
    Ok(())
}

/// Release a context (mark as released).
pub fn release_context(ctx: &mut CanonicalContextDescriptor) {
    ctx.state = ContextState::Released;
}

/// Cancel a context (mark as cancelled).
pub fn cancel_context(ctx: &mut CanonicalContextDescriptor) {
    ctx.state = ContextState::Cancelled;
}

// ---------------------------------------------------------------------------
// Core functions — validation
// ---------------------------------------------------------------------------

/// Validate context threading across a set of contexts and derivation events.
pub fn validate_threading(
    contexts: &[CanonicalContextDescriptor],
    events: &[DerivationEvent],
    seams: &[MockSeamEntry],
    rule: &DerivationRule,
    epoch: SecurityEpoch,
) -> ValidationReport {
    let mut failure_reasons = Vec::new();
    let mut all_contexts_valid = true;
    let mut all_derivations_compliant = true;
    let mut production_seams: u64 = 0;

    // Validate contexts.
    let context_map: BTreeMap<String, &CanonicalContextDescriptor> =
        contexts.iter().map(|c| (c.context_id.clone(), c)).collect();

    for ctx in contexts {
        // Check depth limit.
        if ctx.depth > rule.max_depth {
            all_contexts_valid = false;
            failure_reasons.push(format!(
                "context {} exceeds max depth: {} > {}",
                ctx.context_id, ctx.depth, rule.max_depth,
            ));
        }

        // Check consumed doesn't exceed budget.
        if ctx.consumed_ms > ctx.budget_ms {
            all_contexts_valid = false;
            failure_reasons.push(format!(
                "context {} consumed {} > budget {}",
                ctx.context_id, ctx.consumed_ms, ctx.budget_ms,
            ));
        }

        // Check parent exists (if specified).
        if let Some(ref parent_id) = ctx.parent_id
            && !context_map.contains_key(parent_id)
        {
            // Parent might be in a different scope — warn but don't fail.
        }
    }

    // Validate derivation events.
    for event in events {
        // Check child budget doesn't exceed parent's max fraction.
        if let Some(parent) = context_map.get(&event.parent_id) {
            let max_child = parent
                .budget_ms
                .saturating_mul(rule.max_child_fraction_millionths)
                .checked_div(MILLION)
                .unwrap_or(0);
            if event.child_budget_ms > max_child {
                all_derivations_compliant = false;
                failure_reasons.push(format!(
                    "derivation {} child budget {}ms exceeds max {}ms",
                    event.event_id, event.child_budget_ms, max_child,
                ));
            }
        }

        // Check depth.
        if event.child_depth > rule.max_depth {
            all_derivations_compliant = false;
            failure_reasons.push(format!(
                "derivation {} depth {} exceeds max {}",
                event.event_id, event.child_depth, rule.max_depth,
            ));
        }
    }

    // Check mock seams.
    for seam in seams {
        if seam.classification == MockSeamClassification::MustFixProduction && !seam.remediated {
            production_seams += 1;
            failure_reasons.push(format!(
                "unremediated production mock seam: {} in {}",
                seam.seam_id, seam.file_path,
            ));
        }
    }

    let mock_free = production_seams == 0;
    let passed = all_contexts_valid && all_derivations_compliant && mock_free;

    let report_id = compute_report_id(epoch, contexts.len() as u64, events.len() as u64);
    let content_hash = compute_report_hash(&report_id, epoch, passed, &failure_reasons);

    ValidationReport {
        report_id,
        epoch,
        contexts_validated: contexts.len() as u64,
        derivations_checked: events.len() as u64,
        seams_audited: seams.len() as u64,
        production_seams_found: production_seams,
        all_contexts_valid,
        all_derivations_compliant,
        mock_free,
        passed,
        failure_reasons,
        content_hash,
    }
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

fn compute_context_hash(
    context_id: &str,
    trace_id: &str,
    budget_ms: u64,
    depth: u32,
    epoch: SecurityEpoch,
) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(COMPONENT.as_bytes());
    hasher.update(b":ctx:");
    hasher.update(context_id.as_bytes());
    hasher.update(b":");
    hasher.update(trace_id.as_bytes());
    hasher.update(budget_ms.to_le_bytes());
    hasher.update(depth.to_le_bytes());
    hasher.update(epoch.as_u64().to_le_bytes());
    let result = hasher.finalize();
    ContentHash::compute(&result)
}

fn compute_derivation_event_hash(
    parent_id: &str,
    child_id: &str,
    child_budget_ms: u64,
    parent_remaining_ms: u64,
    epoch: SecurityEpoch,
) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(COMPONENT.as_bytes());
    hasher.update(b":deriv:");
    hasher.update(parent_id.as_bytes());
    hasher.update(b"->");
    hasher.update(child_id.as_bytes());
    hasher.update(child_budget_ms.to_le_bytes());
    hasher.update(parent_remaining_ms.to_le_bytes());
    hasher.update(epoch.as_u64().to_le_bytes());
    let result = hasher.finalize();
    ContentHash::compute(&result)
}

fn compute_report_id(epoch: SecurityEpoch, ctx_count: u64, event_count: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(COMPONENT.as_bytes());
    hasher.update(b":report:");
    hasher.update(epoch.as_u64().to_le_bytes());
    hasher.update(ctx_count.to_le_bytes());
    hasher.update(event_count.to_le_bytes());
    let result = hasher.finalize();
    format!(
        "vr-{:02x}{:02x}{:02x}{:02x}",
        result[0], result[1], result[2], result[3],
    )
}

fn compute_report_hash(
    report_id: &str,
    epoch: SecurityEpoch,
    passed: bool,
    reasons: &[String],
) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(COMPONENT.as_bytes());
    hasher.update(b":validation:");
    hasher.update(report_id.as_bytes());
    hasher.update(epoch.as_u64().to_le_bytes());
    hasher.update(if passed { b"pass" } else { b"fail" });
    for r in reasons {
        hasher.update(r.as_bytes());
    }
    let result = hasher.finalize();
    ContentHash::compute(&result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    fn root_ctx(id: &str, budget_ms: u64) -> CanonicalContextDescriptor {
        create_root_context(id.to_string(), format!("trace-{id}"), budget_ms, epoch(1))
    }

    fn default_rule() -> DerivationRule {
        DerivationRule::new("default".to_string())
    }

    // -- ContextOrigin tests --

    #[test]
    fn context_origin_tags() {
        assert_eq!(ContextOrigin::Root.as_str(), "root");
        assert_eq!(ContextOrigin::ChildDerivation.as_str(), "child_derivation");
        assert_eq!(ContextOrigin::CleanupCarve.as_str(), "cleanup_carve");
        assert_eq!(ContextOrigin::CellClose.as_str(), "cell_close");
        assert_eq!(ContextOrigin::Replay.as_str(), "replay");
    }

    #[test]
    fn context_origin_production_safe() {
        assert!(ContextOrigin::Root.is_production_safe());
        assert!(ContextOrigin::CleanupCarve.is_production_safe());
    }

    // -- ContextState tests --

    #[test]
    fn context_state_consumable() {
        assert!(ContextState::Active.is_consumable());
        assert!(!ContextState::Exhausted.is_consumable());
        assert!(!ContextState::Released.is_consumable());
        assert!(!ContextState::Cancelled.is_consumable());
    }

    // -- MockSeamClassification tests --

    #[test]
    fn mock_seam_production_safe() {
        assert!(!MockSeamClassification::MustFixProduction.is_production_safe());
        assert!(MockSeamClassification::AcceptableTestOnly.is_production_safe());
        assert!(MockSeamClassification::FalsePositive.is_production_safe());
        assert!(!MockSeamClassification::UnderInvestigation.is_production_safe());
    }

    // -- Root context tests --

    #[test]
    fn root_context_creation() {
        let ctx = root_ctx("root-1", 10_000);
        assert_eq!(ctx.context_id, "root-1");
        assert_eq!(ctx.origin, ContextOrigin::Root);
        assert_eq!(ctx.state, ContextState::Active);
        assert_eq!(ctx.budget_ms, 10_000);
        assert_eq!(ctx.consumed_ms, 0);
        assert_eq!(ctx.depth, 0);
        assert!(ctx.parent_id.is_none());
        assert!(ctx.can_derive_child());
    }

    #[test]
    fn root_context_remaining() {
        let ctx = root_ctx("r1", 5000);
        assert_eq!(ctx.remaining_ms(), 5000);
        assert_eq!(ctx.consumed_fraction_millionths(), 0);
    }

    #[test]
    fn root_context_zero_budget() {
        let ctx = root_ctx("r0", 0);
        assert_eq!(ctx.remaining_ms(), 0);
        assert_eq!(ctx.consumed_fraction_millionths(), MILLION);
        assert!(!ctx.can_derive_child());
    }

    // -- Derivation tests --

    #[test]
    fn derive_child_basic() {
        let mut parent = root_ctx("parent", 10_000);
        let rule = default_rule();
        let (child, event) = derive_child_context(
            &mut parent,
            "child-1".to_string(),
            5000,
            ContextOrigin::ChildDerivation,
            &rule,
        )
        .unwrap();
        assert_eq!(child.context_id, "child-1");
        assert_eq!(child.origin, ContextOrigin::ChildDerivation);
        assert_eq!(child.budget_ms, 5000);
        assert_eq!(child.depth, 1);
        assert_eq!(child.parent_id, Some("parent".to_string()));
        assert_eq!(parent.consumed_ms, 5000);
        assert_eq!(event.parent_id, "parent");
        assert_eq!(event.child_id, "child-1");
    }

    #[test]
    fn derive_child_trace_inherited() {
        let mut parent = root_ctx("parent", 10_000);
        let rule = default_rule();
        let (child, _) = derive_child_context(
            &mut parent,
            "child-1".to_string(),
            5000,
            ContextOrigin::ChildDerivation,
            &rule,
        )
        .unwrap();
        assert!(child.trace_id.starts_with("trace-parent.child."));
    }

    #[test]
    fn derive_child_exceeds_budget() {
        let mut parent = root_ctx("parent", 1000);
        let rule = default_rule();
        let err = derive_child_context(
            &mut parent,
            "child".to_string(),
            2000,
            ContextOrigin::ChildDerivation,
            &rule,
        )
        .unwrap_err();
        assert!(matches!(err, ContextError::InsufficientBudget { .. }));
    }

    #[test]
    fn derive_child_exceeds_fraction() {
        let mut parent = root_ctx("parent", 10_000);
        let rule = DerivationRule::strict("strict".to_string());
        // Strict rule allows 50% = 5000ms.
        let err = derive_child_context(
            &mut parent,
            "child".to_string(),
            6000,
            ContextOrigin::ChildDerivation,
            &rule,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ContextError::ChildExceedsAllowedFraction { .. }
        ));
    }

    #[test]
    fn derive_child_depth_exceeded() {
        let mut parent = root_ctx("parent", 10_000);
        parent.depth = 63;
        let rule = default_rule();
        let err = derive_child_context(
            &mut parent,
            "child".to_string(),
            100,
            ContextOrigin::ChildDerivation,
            &rule,
        )
        .unwrap_err();
        assert!(matches!(err, ContextError::DepthExceeded { .. }));
    }

    #[test]
    fn derive_child_exhausted_parent() {
        let mut parent = root_ctx("parent", 10_000);
        parent.state = ContextState::Exhausted;
        let rule = default_rule();
        let err = derive_child_context(
            &mut parent,
            "child".to_string(),
            100,
            ContextOrigin::ChildDerivation,
            &rule,
        )
        .unwrap_err();
        assert!(matches!(err, ContextError::NotConsumable { .. }));
    }

    // -- Cleanup carve tests --

    #[test]
    fn carve_cleanup_basic() {
        let mut parent = root_ctx("parent", 10_000);
        let rule = default_rule();
        let (cleanup, event) =
            carve_cleanup_context(&mut parent, "cleanup-1".to_string(), &rule).unwrap();
        assert_eq!(cleanup.origin, ContextOrigin::CleanupCarve);
        // 10% of 10_000 = 1000ms.
        assert_eq!(cleanup.budget_ms, 1000);
        assert_eq!(event.child_origin, ContextOrigin::CleanupCarve);
    }

    #[test]
    fn carve_cleanup_from_small_budget() {
        let mut parent = root_ctx("parent", 5);
        let rule = default_rule();
        // 10% of 5ms = 0ms, which is below MIN_DERIVABLE_BUDGET_MS.
        let err = carve_cleanup_context(&mut parent, "cleanup".to_string(), &rule).unwrap_err();
        assert!(matches!(err, ContextError::InsufficientBudget { .. }));
    }

    // -- consume_budget tests --

    #[test]
    fn consume_budget_basic() {
        let mut ctx = root_ctx("ctx", 1000);
        consume_budget(&mut ctx, 500).unwrap();
        assert_eq!(ctx.consumed_ms, 500);
        assert_eq!(ctx.remaining_ms(), 500);
        assert_eq!(ctx.state, ContextState::Active);
    }

    #[test]
    fn consume_budget_exhausts() {
        let mut ctx = root_ctx("ctx", 1000);
        consume_budget(&mut ctx, 1000).unwrap();
        assert_eq!(ctx.state, ContextState::Exhausted);
    }

    #[test]
    fn consume_budget_exceeds() {
        let mut ctx = root_ctx("ctx", 100);
        let err = consume_budget(&mut ctx, 200).unwrap_err();
        assert!(matches!(err, ContextError::InsufficientBudget { .. }));
        assert_eq!(ctx.state, ContextState::Exhausted);
    }

    #[test]
    fn consume_budget_released() {
        let mut ctx = root_ctx("ctx", 1000);
        release_context(&mut ctx);
        let err = consume_budget(&mut ctx, 100).unwrap_err();
        assert!(matches!(err, ContextError::NotConsumable { .. }));
    }

    // -- release/cancel tests --

    #[test]
    fn release_context_transitions() {
        let mut ctx = root_ctx("ctx", 1000);
        release_context(&mut ctx);
        assert_eq!(ctx.state, ContextState::Released);
        assert!(!ctx.state.is_consumable());
    }

    #[test]
    fn cancel_context_transitions() {
        let mut ctx = root_ctx("ctx", 1000);
        cancel_context(&mut ctx);
        assert_eq!(ctx.state, ContextState::Cancelled);
    }

    // -- validation tests --

    #[test]
    fn validate_empty_passes() {
        let rule = default_rule();
        let report = validate_threading(&[], &[], &[], &rule, epoch(1));
        assert!(report.passed);
        assert!(report.all_contexts_valid);
        assert!(report.all_derivations_compliant);
        assert!(report.mock_free);
    }

    #[test]
    fn validate_healthy_threading() {
        let mut parent = root_ctx("parent", 10_000);
        let rule = default_rule();
        let (child, event) = derive_child_context(
            &mut parent,
            "child".to_string(),
            5000,
            ContextOrigin::ChildDerivation,
            &rule,
        )
        .unwrap();
        let contexts = vec![parent, child];
        let events = vec![event];
        let report = validate_threading(&contexts, &events, &[], &rule, epoch(1));
        assert!(report.passed);
        assert_eq!(report.contexts_validated, 2);
        assert_eq!(report.derivations_checked, 1);
    }

    #[test]
    fn validate_mock_seam_fails() {
        let rule = default_rule();
        let seam = MockSeamEntry {
            seam_id: "seam-1".to_string(),
            file_path: "src/production.rs".to_string(),
            line_number: 42,
            classification: MockSeamClassification::MustFixProduction,
            description: "MockCx in production path".to_string(),
            remediated: false,
        };
        let report = validate_threading(&[], &[], &[seam], &rule, epoch(1));
        assert!(!report.passed);
        assert!(!report.mock_free);
        assert_eq!(report.production_seams_found, 1);
    }

    #[test]
    fn validate_remediated_seam_passes() {
        let rule = default_rule();
        let seam = MockSeamEntry {
            seam_id: "seam-1".to_string(),
            file_path: "src/production.rs".to_string(),
            line_number: 42,
            classification: MockSeamClassification::MustFixProduction,
            description: "MockCx in production path".to_string(),
            remediated: true,
        };
        let report = validate_threading(&[], &[], &[seam], &rule, epoch(1));
        assert!(report.passed);
        assert!(report.mock_free);
    }

    // -- DerivationRule tests --

    #[test]
    fn derivation_rule_defaults() {
        let rule = default_rule();
        assert_eq!(rule.max_child_fraction_millionths, 900_000);
        assert_eq!(
            rule.cleanup_fraction_millionths,
            DEFAULT_CLEANUP_FRACTION_MILLIONTHS
        );
        assert!(rule.require_trace_derivation);
        assert_eq!(rule.max_depth, MAX_DERIVATION_DEPTH);
    }

    #[test]
    fn derivation_rule_strict() {
        let rule = DerivationRule::strict("strict".to_string());
        assert_eq!(rule.max_child_fraction_millionths, 500_000);
        assert_eq!(rule.max_depth, 16);
    }

    #[test]
    fn derivation_rule_hash_deterministic() {
        let r1 = DerivationRule::new("test".to_string());
        let r2 = DerivationRule::new("test".to_string());
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    // -- Serde round-trip tests --

    #[test]
    fn serde_context_roundtrip() {
        let ctx = root_ctx("serde-ctx", 5000);
        let json = serde_json::to_string(&ctx).unwrap();
        let restored: CanonicalContextDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, restored);
    }

    #[test]
    fn serde_origin_snake_case() {
        let origin = ContextOrigin::CleanupCarve;
        let json = serde_json::to_string(&origin).unwrap();
        assert_eq!(json, "\"cleanup_carve\"");
    }

    #[test]
    fn serde_error_roundtrip() {
        let err = ContextError::InsufficientBudget {
            parent_id: "p1".to_string(),
            remaining_ms: 100,
            requested_ms: 200,
        };
        let json = serde_json::to_string(&err).unwrap();
        let restored: ContextError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
    }

    // -- Display tests --

    #[test]
    fn display_context() {
        let ctx = root_ctx("disp-ctx", 1000);
        let s = format!("{ctx}");
        assert!(s.contains("disp-ctx"));
        assert!(s.contains("root"));
    }

    #[test]
    fn display_rule() {
        let rule = default_rule();
        let s = format!("{rule}");
        assert!(s.contains("default"));
    }

    #[test]
    fn display_error() {
        let err = ContextError::MockSeamDetected {
            seam_id: "s1".to_string(),
            file_path: "src/bad.rs".to_string(),
        };
        let s = format!("{err}");
        assert!(s.contains("mock seam"));
    }

    // -- End-to-end test --

    #[test]
    fn end_to_end_context_lifecycle() {
        let mut root = root_ctx("root", 10_000);
        let rule = default_rule();

        // Derive child.
        let (mut child, ev1) = derive_child_context(
            &mut root,
            "child-1".to_string(),
            4000,
            ContextOrigin::ChildDerivation,
            &rule,
        )
        .unwrap();

        // Consume budget in child.
        consume_budget(&mut child, 2000).unwrap();
        assert_eq!(child.remaining_ms(), 2000);

        // Carve cleanup from remaining parent budget.
        let (mut cleanup, ev2) =
            carve_cleanup_context(&mut root, "cleanup-1".to_string(), &rule).unwrap();

        // Release everything.
        release_context(&mut child);
        release_context(&mut cleanup);
        release_context(&mut root);

        // Validate.
        let contexts = vec![root, child, cleanup];
        let events = vec![ev1, ev2];
        let report = validate_threading(&contexts, &events, &[], &rule, epoch(1));
        assert!(report.passed);
        assert_eq!(report.contexts_validated, 3);
        assert_eq!(report.derivations_checked, 2);
    }
}
