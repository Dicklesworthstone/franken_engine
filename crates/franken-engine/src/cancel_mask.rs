//! Bounded cancellation masking for tiny atomic publication steps.
//!
//! A `CancelMask` guard temporarily suppresses cancellation observation
//! within a scoped block. Hard bounds on operation count prevent abuse.
//! Nesting is forbidden. Only allowlisted operations may mask.
//!
//! Plan references: Section 10.11 item 5, 9G.2 (cancellation as protocol),
//! Top-10 #3 (deterministic evidence graph + replay).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// MaskJustification — required context for mask creation
// ---------------------------------------------------------------------------

/// Justification required when creating a cancel mask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskJustification {
    /// Name of the operation being masked.
    pub operation_name: String,
    /// Expected operation count hint (for audit).
    pub expected_ops_hint: u64,
    /// Why this operation must be atomic.
    pub atomicity_reason: String,
}

// ---------------------------------------------------------------------------
// MaskOutcome — how the mask was released
// ---------------------------------------------------------------------------

/// How a cancel mask was released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaskOutcome {
    /// Mask released cleanly before bounds.
    CleanRelease,
    /// Operation count bound exceeded.
    BoundExceeded,
    /// Cancellation was pending when mask released.
    CancelDeferred,
}

impl fmt::Display for MaskOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CleanRelease => write!(f, "clean_release"),
            Self::BoundExceeded => write!(f, "bound_exceeded"),
            Self::CancelDeferred => write!(f, "cancel_deferred"),
        }
    }
}

// ---------------------------------------------------------------------------
// MaskError — errors when creating or using a mask
// ---------------------------------------------------------------------------

/// Error returned when mask creation or usage is denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaskError {
    /// Attempted to create a nested mask.
    NestingDenied,
    /// Operation not in the policy allowlist.
    OperationNotAllowed { operation_name: String },
    /// Mask already released.
    AlreadyReleased,
}

impl fmt::Display for MaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NestingDenied => write!(f, "mask nesting denied"),
            Self::OperationNotAllowed { operation_name } => {
                write!(f, "operation not allowed to mask: {operation_name}")
            }
            Self::AlreadyReleased => write!(f, "mask already released"),
        }
    }
}

impl std::error::Error for MaskError {}

// ---------------------------------------------------------------------------
// MaskBounds — per-operation bounds
// ---------------------------------------------------------------------------

/// Bounds for a specific maskable operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskBounds {
    /// Maximum operations (ticks) allowed under mask.
    pub max_ops: u64,
}

impl Default for MaskBounds {
    fn default() -> Self {
        Self { max_ops: 64 }
    }
}

// ---------------------------------------------------------------------------
// MaskPolicy — allowlist of maskable operations
// ---------------------------------------------------------------------------

/// Policy controlling which operations may create cancel masks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskPolicy {
    /// Default bounds for operations in the allowlist.
    pub default_bounds: MaskBounds,
    /// Per-operation bounds overrides. Key = operation_name.
    pub operation_bounds: BTreeMap<String, MaskBounds>,
    /// If true, bound violations are fatal (lab mode). Otherwise warning.
    pub lab_mode: bool,
}

impl MaskPolicy {
    /// Create a standard policy with common atomic operations.
    pub fn standard() -> Self {
        let mut operation_bounds = BTreeMap::new();
        operation_bounds.insert("checkpoint_write".to_string(), MaskBounds { max_ops: 32 });
        operation_bounds.insert("evidence_append".to_string(), MaskBounds { max_ops: 16 });
        operation_bounds.insert("two_phase_commit".to_string(), MaskBounds { max_ops: 64 });
        operation_bounds.insert("hash_link_finalize".to_string(), MaskBounds { max_ops: 8 });
        Self {
            default_bounds: MaskBounds::default(),
            operation_bounds,
            lab_mode: false,
        }
    }

    /// Check if an operation is allowed to mask.
    pub fn is_allowed(&self, operation_name: &str) -> bool {
        self.operation_bounds.contains_key(operation_name)
    }

    /// Get bounds for an operation (returns default if allowed but not overridden).
    pub fn bounds_for(&self, operation_name: &str) -> Option<MaskBounds> {
        if self.operation_bounds.contains_key(operation_name) {
            Some(
                self.operation_bounds
                    .get(operation_name)
                    .copied()
                    .unwrap_or(self.default_bounds),
            )
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// MaskEvent — structured evidence
// ---------------------------------------------------------------------------

/// Structured event emitted for mask lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskEvent {
    pub trace_id: String,
    pub region_id: String,
    pub mask_id: u64,
    pub operation_name: String,
    pub ops_executed: u64,
    pub outcome: MaskOutcome,
}

// ---------------------------------------------------------------------------
// CancelMaskContext — manages mask state for a region
// ---------------------------------------------------------------------------

/// Tracks cancel mask state within a region/context.
#[derive(Debug)]
pub struct CancelMaskContext {
    policy: MaskPolicy,
    trace_id: String,
    region_id: String,
    active_mask: Option<ActiveMask>,
    next_mask_id: u64,
    events: Vec<MaskEvent>,
}

#[derive(Debug)]
struct ActiveMask {
    mask_id: u64,
    operation_name: String,
    bounds: MaskBounds,
    ops_executed: u64,
    bound_exceeded: bool,
}

impl CancelMaskContext {
    /// Create a new mask context with the given policy.
    pub fn new(
        policy: MaskPolicy,
        trace_id: impl Into<String>,
        region_id: impl Into<String>,
    ) -> Self {
        Self {
            policy,
            trace_id: trace_id.into(),
            region_id: region_id.into(),
            active_mask: None,
            next_mask_id: 1,
            events: Vec::new(),
        }
    }

    /// Whether a mask is currently active (cancellation suppressed).
    pub fn is_masked(&self) -> bool {
        self.active_mask.as_ref().is_some_and(|m| !m.bound_exceeded)
    }

    /// Create a new cancel mask. Returns mask_id on success.
    pub fn create_mask(&mut self, justification: &MaskJustification) -> Result<u64, MaskError> {
        // Check nesting
        if self.active_mask.is_some() {
            return Err(MaskError::NestingDenied);
        }

        // Check policy
        if !self.policy.is_allowed(&justification.operation_name) {
            return Err(MaskError::OperationNotAllowed {
                operation_name: justification.operation_name.clone(),
            });
        }

        let bounds = self
            .policy
            .bounds_for(&justification.operation_name)
            .unwrap_or(self.policy.default_bounds);

        let mask_id = self.next_mask_id;
        self.next_mask_id += 1;

        self.active_mask = Some(ActiveMask {
            mask_id,
            operation_name: justification.operation_name.clone(),
            bounds,
            ops_executed: 0,
            bound_exceeded: false,
        });

        Ok(mask_id)
    }

    /// Tick the active mask (count one operation). Returns false if bound exceeded.
    pub fn tick(&mut self) -> bool {
        if let Some(mask) = &mut self.active_mask {
            if mask.bound_exceeded {
                return false;
            }
            mask.ops_executed += 1;
            if mask.ops_executed >= mask.bounds.max_ops {
                mask.bound_exceeded = true;
                self.events.push(MaskEvent {
                    trace_id: self.trace_id.clone(),
                    region_id: self.region_id.clone(),
                    mask_id: mask.mask_id,
                    operation_name: mask.operation_name.clone(),
                    ops_executed: mask.ops_executed,
                    outcome: MaskOutcome::BoundExceeded,
                });
                return false;
            }
            true
        } else {
            false
        }
    }

    /// Release the active mask. Returns the outcome.
    pub fn release_mask(&mut self, cancel_pending: bool) -> Result<MaskOutcome, MaskError> {
        let mask = self.active_mask.take().ok_or(MaskError::AlreadyReleased)?;

        let outcome = if mask.bound_exceeded {
            MaskOutcome::BoundExceeded
        } else if cancel_pending {
            MaskOutcome::CancelDeferred
        } else {
            MaskOutcome::CleanRelease
        };

        // Only emit event if we haven't already (bound_exceeded already emitted)
        if !mask.bound_exceeded {
            self.events.push(MaskEvent {
                trace_id: self.trace_id.clone(),
                region_id: self.region_id.clone(),
                mask_id: mask.mask_id,
                operation_name: mask.operation_name,
                ops_executed: mask.ops_executed,
                outcome,
            });
        }

        Ok(outcome)
    }

    /// Whether the policy treats bound violations as fatal.
    pub fn is_lab_mode(&self) -> bool {
        self.policy.lab_mode
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<MaskEvent> {
        std::mem::take(&mut self.events)
    }

    /// Number of events emitted.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context() -> CancelMaskContext {
        CancelMaskContext::new(MaskPolicy::standard(), "trace-1", "region-1")
    }

    fn checkpoint_justification() -> MaskJustification {
        MaskJustification {
            operation_name: "checkpoint_write".to_string(),
            expected_ops_hint: 10,
            atomicity_reason: "atomic checkpoint finalization".to_string(),
        }
    }

    // -- MaskOutcome --

    #[test]
    fn mask_outcome_display() {
        assert_eq!(MaskOutcome::CleanRelease.to_string(), "clean_release");
        assert_eq!(MaskOutcome::BoundExceeded.to_string(), "bound_exceeded");
        assert_eq!(MaskOutcome::CancelDeferred.to_string(), "cancel_deferred");
    }

    // -- Policy --

    #[test]
    fn standard_policy_allows_known_operations() {
        let policy = MaskPolicy::standard();
        assert!(policy.is_allowed("checkpoint_write"));
        assert!(policy.is_allowed("evidence_append"));
        assert!(policy.is_allowed("two_phase_commit"));
        assert!(policy.is_allowed("hash_link_finalize"));
        assert!(!policy.is_allowed("arbitrary_computation"));
    }

    #[test]
    fn policy_returns_per_operation_bounds() {
        let policy = MaskPolicy::standard();
        assert_eq!(
            policy.bounds_for("checkpoint_write"),
            Some(MaskBounds { max_ops: 32 })
        );
        assert_eq!(
            policy.bounds_for("hash_link_finalize"),
            Some(MaskBounds { max_ops: 8 })
        );
        assert_eq!(policy.bounds_for("unknown"), None);
    }

    // -- Mask creation --

    #[test]
    fn create_mask_succeeds_for_allowed_operation() {
        let mut ctx = test_context();
        // SAFETY: Test uses valid justification; create_mask succeeds in controlled test environment.
        let mask_id = ctx
            .create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        assert_eq!(mask_id, 1);
        assert!(ctx.is_masked());
    }

    #[test]
    fn create_mask_denied_for_disallowed_operation() {
        let mut ctx = test_context();
        let just = MaskJustification {
            operation_name: "long_computation".to_string(),
            expected_ops_hint: 10000,
            atomicity_reason: "none".to_string(),
        };
        let err = ctx.create_mask(&just).unwrap_err();
        assert_eq!(
            err,
            MaskError::OperationNotAllowed {
                operation_name: "long_computation".to_string()
            }
        );
    }

    #[test]
    fn nesting_denied() {
        let mut ctx = test_context();
        // SAFETY: Test uses valid justification; create_mask succeeds in controlled test environment.
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        let err = ctx.create_mask(&checkpoint_justification()).unwrap_err();
        assert_eq!(err, MaskError::NestingDenied);
    }

    // -- Mask lifecycle --

    #[test]
    fn clean_release_within_bounds() {
        let mut ctx = test_context();
        // SAFETY: Test uses valid justification; create_mask succeeds in controlled test environment.
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");

        for _ in 0..10 {
            assert!(ctx.tick());
        }

        // SAFETY: Test has valid mask; release_mask succeeds in controlled test environment.
        let outcome = ctx
            .release_mask(false)
            .expect("serde deserialization should succeed");
        assert_eq!(outcome, MaskOutcome::CleanRelease);
        assert!(!ctx.is_masked());
    }

    #[test]
    fn bound_exceeded_auto_unmasks() {
        let mut ctx = test_context();
        // SAFETY: Test uses valid justification; create_mask succeeds in controlled test environment.
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");

        // checkpoint_write has max_ops = 32
        for _ in 0..31 {
            assert!(ctx.tick());
        }
        // 32nd tick exceeds bound
        assert!(!ctx.tick());
        assert!(!ctx.is_masked());
    }

    #[test]
    fn release_after_bound_exceeded_reports_exceeded() {
        let mut ctx = test_context();
        // SAFETY: Test uses valid justification; create_mask succeeds in controlled test environment.
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");

        for _ in 0..32 {
            ctx.tick();
        }

        // SAFETY: Test has valid mask; release_mask succeeds in controlled test environment.
        let outcome = ctx
            .release_mask(false)
            .expect("serde deserialization should succeed");
        assert_eq!(outcome, MaskOutcome::BoundExceeded);
    }

    #[test]
    fn cancel_deferred_on_release() {
        let mut ctx = test_context();
        // SAFETY: Test uses valid justification; create_mask succeeds in controlled test environment.
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        ctx.tick();

        let outcome = ctx
            .release_mask(true)
            .expect("serde deserialization should succeed");
        assert_eq!(outcome, MaskOutcome::CancelDeferred);
    }

    #[test]
    fn release_without_active_mask_fails() {
        let mut ctx = test_context();
        let err = ctx.release_mask(false).unwrap_err();
        assert_eq!(err, MaskError::AlreadyReleased);
    }

    // -- Events --

    #[test]
    fn clean_release_emits_event() {
        let mut ctx = test_context();
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        ctx.tick();
        ctx.release_mask(false)
            .expect("serde deserialization should succeed");

        let events = ctx.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, MaskOutcome::CleanRelease);
        assert_eq!(events[0].operation_name, "checkpoint_write");
        assert_eq!(events[0].ops_executed, 1);
    }

    #[test]
    fn bound_exceeded_emits_event() {
        let mut ctx = test_context();
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        for _ in 0..32 {
            ctx.tick();
        }

        let events = ctx.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, MaskOutcome::BoundExceeded);
        assert_eq!(events[0].ops_executed, 32);
    }

    #[test]
    fn event_carries_correct_fields() {
        let mut ctx = test_context();
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        ctx.tick();
        ctx.release_mask(false)
            .expect("serde deserialization should succeed");

        let events = ctx.drain_events();
        let event = &events[0];
        assert_eq!(event.trace_id, "trace-1");
        assert_eq!(event.region_id, "region-1");
        assert_eq!(event.mask_id, 1);
    }

    // -- Sequential masks --

    #[test]
    fn sequential_masks_get_unique_ids() {
        let mut ctx = test_context();

        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        ctx.release_mask(false)
            .expect("serde deserialization should succeed");

        let mask_id = ctx
            .create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        assert_eq!(mask_id, 2);
        ctx.release_mask(false)
            .expect("serde deserialization should succeed");
    }

    // -- Deterministic replay --

    #[test]
    fn deterministic_event_sequence() {
        let run = || -> Vec<MaskEvent> {
            let mut ctx = test_context();
            ctx.create_mask(&checkpoint_justification())
                .expect("serde deserialization should succeed");
            for _ in 0..5 {
                ctx.tick();
            }
            ctx.release_mask(false)
                .expect("serde deserialization should succeed");

            ctx.create_mask(&MaskJustification {
                operation_name: "evidence_append".to_string(),
                expected_ops_hint: 3,
                atomicity_reason: "atomic append".to_string(),
            })
            .expect("serde deserialization should succeed");
            for _ in 0..16 {
                ctx.tick();
            }
            ctx.release_mask(true)
                .expect("serde deserialization should succeed");
            ctx.drain_events()
        };

        let events1 = run();
        let events2 = run();
        assert_eq!(events1, events2);
    }

    // -- MaskError --

    #[test]
    fn mask_error_display() {
        assert_eq!(MaskError::NestingDenied.to_string(), "mask nesting denied");
        assert!(
            MaskError::OperationNotAllowed {
                operation_name: "x".to_string()
            }
            .to_string()
            .contains("x")
        );
        assert_eq!(
            MaskError::AlreadyReleased.to_string(),
            "mask already released"
        );
    }

    // -- Lab mode --

    #[test]
    fn lab_mode_flag() {
        let mut policy = MaskPolicy::standard();
        policy.lab_mode = true;
        let ctx = CancelMaskContext::new(policy, "t", "r");
        assert!(ctx.is_lab_mode());
    }

    // -- Serialization --

    #[test]
    fn mask_justification_serialization_round_trip() {
        let just = checkpoint_justification();
        let json = serde_json::to_string(&just).expect("serialize derived Serialize");
        let restored: MaskJustification =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(just, restored);
    }

    #[test]
    fn mask_policy_serialization_round_trip() {
        let policy = MaskPolicy::standard();
        let json = serde_json::to_string(&policy).expect("serialize derived Serialize");
        let restored: MaskPolicy =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(policy, restored);
    }

    #[test]
    fn mask_event_serialization_round_trip() {
        let event = MaskEvent {
            trace_id: "t".to_string(),
            region_id: "r".to_string(),
            mask_id: 1,
            operation_name: "checkpoint_write".to_string(),
            ops_executed: 10,
            outcome: MaskOutcome::CleanRelease,
        };
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        let restored: MaskEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(event, restored);
    }

    // -- Tick without mask --

    #[test]
    fn tick_without_active_mask_returns_false() {
        let mut ctx = test_context();
        assert!(!ctx.tick());
    }

    // -- Hash link finalize bounds --

    #[test]
    fn hash_link_finalize_has_tight_bounds() {
        let mut ctx = test_context();
        ctx.create_mask(&MaskJustification {
            operation_name: "hash_link_finalize".to_string(),
            expected_ops_hint: 4,
            atomicity_reason: "hash chain append".to_string(),
        })
        .expect("serde deserialization should succeed");

        // max_ops = 8
        for _ in 0..7 {
            assert!(ctx.tick());
        }
        assert!(!ctx.tick()); // 8th exceeds
    }

    // -----------------------------------------------------------------------
    // Enrichment: serde roundtrips for leaf types
    // -----------------------------------------------------------------------

    #[test]
    fn mask_outcome_serde_all_variants() {
        let variants = [
            MaskOutcome::CleanRelease,
            MaskOutcome::BoundExceeded,
            MaskOutcome::CancelDeferred,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize derived Serialize");
            let restored: MaskOutcome =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn mask_error_serde_all_variants() {
        let variants: Vec<MaskError> = vec![
            MaskError::NestingDenied,
            MaskError::OperationNotAllowed {
                operation_name: "bad_op".to_string(),
            },
            MaskError::AlreadyReleased,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize derived Serialize");
            let restored: MaskError =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn mask_bounds_serde_roundtrip() {
        let bounds = MaskBounds { max_ops: 42 };
        let json = serde_json::to_string(&bounds).expect("serialize derived Serialize");
        let restored: MaskBounds =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(bounds, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: default values
    // -----------------------------------------------------------------------

    #[test]
    fn mask_bounds_default_value() {
        let b = MaskBounds::default();
        assert_eq!(b.max_ops, 64);
    }

    #[test]
    fn standard_policy_defaults() {
        let p = MaskPolicy::standard();
        assert!(!p.lab_mode);
        assert_eq!(p.default_bounds, MaskBounds::default());
        assert_eq!(p.operation_bounds.len(), 4);
    }

    // -----------------------------------------------------------------------
    // Enrichment: fresh context state
    // -----------------------------------------------------------------------

    #[test]
    fn fresh_context_initial_state() {
        let ctx = test_context();
        assert!(!ctx.is_masked());
        assert_eq!(ctx.event_count(), 0);
        assert!(!ctx.is_lab_mode());
    }

    // -----------------------------------------------------------------------
    // Enrichment: event_count and drain
    // -----------------------------------------------------------------------

    #[test]
    fn event_count_tracks_events() {
        let mut ctx = test_context();
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        ctx.tick();
        ctx.release_mask(false)
            .expect("serde deserialization should succeed");
        assert_eq!(ctx.event_count(), 1);

        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        ctx.tick();
        ctx.release_mask(true)
            .expect("serde deserialization should succeed");
        assert_eq!(ctx.event_count(), 2);
    }

    #[test]
    fn drain_events_clears_list() {
        let mut ctx = test_context();
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        ctx.tick();
        ctx.release_mask(false)
            .expect("serde deserialization should succeed");
        assert_eq!(ctx.event_count(), 1);

        let drained = ctx.drain_events();
        assert_eq!(drained.len(), 1);
        assert_eq!(ctx.event_count(), 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: tick after bound exceeded
    // -----------------------------------------------------------------------

    #[test]
    fn tick_after_bound_exceeded_stays_false() {
        let mut ctx = test_context();
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        // Exhaust bound (32 ops).
        for _ in 0..32 {
            ctx.tick();
        }
        // Further ticks still return false.
        assert!(!ctx.tick());
        assert!(!ctx.tick());
    }

    // -----------------------------------------------------------------------
    // Enrichment: release with cancel_pending after bound exceeded
    // -----------------------------------------------------------------------

    #[test]
    fn release_after_bound_exceeded_ignores_cancel_pending() {
        let mut ctx = test_context();
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        for _ in 0..32 {
            ctx.tick();
        }
        // Even with cancel_pending=true, outcome is BoundExceeded.
        let outcome = ctx
            .release_mask(true)
            .expect("serde deserialization should succeed");
        assert_eq!(outcome, MaskOutcome::BoundExceeded);
    }

    // -----------------------------------------------------------------------
    // Enrichment: new mask after bound exceeded release
    // -----------------------------------------------------------------------

    #[test]
    fn new_mask_after_bound_exceeded_release() {
        let mut ctx = test_context();
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        for _ in 0..32 {
            ctx.tick();
        }
        ctx.release_mask(false)
            .expect("serde deserialization should succeed");

        // Should be able to create a new mask.
        let id = ctx
            .create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        assert_eq!(id, 2);
        assert!(ctx.is_masked());
    }

    // -----------------------------------------------------------------------
    // Enrichment: evidence_append and two_phase_commit bounds
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_append_bounds() {
        let mut ctx = test_context();
        ctx.create_mask(&MaskJustification {
            operation_name: "evidence_append".to_string(),
            expected_ops_hint: 5,
            atomicity_reason: "atomic".to_string(),
        })
        .expect("serde deserialization should succeed");
        // max_ops = 16
        for _ in 0..15 {
            assert!(ctx.tick());
        }
        assert!(!ctx.tick()); // 16th exceeds
    }

    #[test]
    fn two_phase_commit_bounds() {
        let policy = MaskPolicy::standard();
        let bounds = policy
            .bounds_for("two_phase_commit")
            .expect("serde deserialization should succeed");
        assert_eq!(bounds.max_ops, 64);
    }

    // -----------------------------------------------------------------------
    // Enrichment: MaskError Display substring verification
    // -----------------------------------------------------------------------

    #[test]
    fn mask_error_display_substrings() {
        let e = MaskError::OperationNotAllowed {
            operation_name: "dangerous_op".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("not allowed"));
        assert!(s.contains("dangerous_op"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: not masked after clean release
    // -----------------------------------------------------------------------

    #[test]
    fn not_masked_after_release() {
        let mut ctx = test_context();
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        assert!(ctx.is_masked());
        ctx.release_mask(false)
            .expect("serde deserialization should succeed");
        assert!(!ctx.is_masked());
    }

    // -----------------------------------------------------------------------
    // Enrichment: release with bound_exceeded does not emit duplicate event
    // -----------------------------------------------------------------------

    // -- Enrichment: std::error --

    #[test]
    fn mask_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(MaskError::NestingDenied),
            Box::new(MaskError::OperationNotAllowed {
                operation_name: "cancel".into(),
            }),
            Box::new(MaskError::AlreadyReleased),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            3,
            "all 3 variants produce distinct messages"
        );
    }

    #[test]
    fn bound_exceeded_release_no_duplicate_event() {
        let mut ctx = test_context();
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        for _ in 0..32 {
            ctx.tick();
        }
        // 1 event from tick's bound exceeded
        assert_eq!(ctx.event_count(), 1);
        ctx.release_mask(false)
            .expect("serde deserialization should succeed");
        // Still just 1 event — no duplicate
        assert_eq!(ctx.event_count(), 1);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2: Display uniqueness, edge cases, serde
    // -----------------------------------------------------------------------

    #[test]
    fn mask_outcome_display_uniqueness() {
        let displays: std::collections::BTreeSet<String> = [
            MaskOutcome::CleanRelease,
            MaskOutcome::BoundExceeded,
            MaskOutcome::CancelDeferred,
        ]
        .iter()
        .map(|o| o.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            3,
            "all MaskOutcome variants must have unique Display"
        );
    }

    #[test]
    fn mask_error_display_uniqueness() {
        let displays: std::collections::BTreeSet<String> = [
            MaskError::NestingDenied,
            MaskError::OperationNotAllowed {
                operation_name: "test".to_string(),
            },
            MaskError::AlreadyReleased,
        ]
        .iter()
        .map(|e| e.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            3,
            "all MaskError variants must have unique Display"
        );
    }

    #[test]
    fn three_sequential_masks_increment_ids() {
        let mut ctx = test_context();
        for expected_id in 1..=3 {
            let id = ctx
                .create_mask(&checkpoint_justification())
                .expect("serde deserialization should succeed");
            assert_eq!(id, expected_id);
            ctx.release_mask(false)
                .expect("serde deserialization should succeed");
        }
        assert_eq!(ctx.event_count(), 3);
    }

    #[test]
    fn mask_justification_fields() {
        let just = MaskJustification {
            operation_name: "test_op".to_string(),
            expected_ops_hint: 42,
            atomicity_reason: "must be atomic".to_string(),
        };
        assert_eq!(just.operation_name, "test_op");
        assert_eq!(just.expected_ops_hint, 42);
        assert_eq!(just.atomicity_reason, "must be atomic");
    }

    #[test]
    fn mask_event_fields_for_cancel_deferred() {
        let mut ctx = test_context();
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        for _ in 0..5 {
            ctx.tick();
        }
        ctx.release_mask(true)
            .expect("serde deserialization should succeed");

        let events = ctx.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, MaskOutcome::CancelDeferred);
        assert_eq!(events[0].ops_executed, 5);
        assert_eq!(events[0].mask_id, 1);
    }

    #[test]
    fn policy_with_custom_bounds() {
        let mut policy = MaskPolicy::standard();
        policy
            .operation_bounds
            .insert("custom_op".to_string(), MaskBounds { max_ops: 4 });
        assert!(policy.is_allowed("custom_op"));
        assert_eq!(
            policy.bounds_for("custom_op"),
            Some(MaskBounds { max_ops: 4 })
        );
    }

    #[test]
    fn zero_tick_clean_release() {
        let mut ctx = test_context();
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        // Release immediately without any ticks
        let outcome = ctx
            .release_mask(false)
            .expect("serde deserialization should succeed");
        assert_eq!(outcome, MaskOutcome::CleanRelease);
        let events = ctx.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].ops_executed, 0);
    }

    #[test]
    fn lab_mode_policy_serde_roundtrip() {
        let mut policy = MaskPolicy::standard();
        policy.lab_mode = true;
        let json = serde_json::to_string(&policy).expect("serialize derived Serialize");
        let restored: MaskPolicy =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(policy, restored);
        assert!(restored.lab_mode);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 3: clone equality, JSON field presence, boundaries
    // -----------------------------------------------------------------------

    #[test]
    fn clone_eq_mask_justification() {
        let orig = MaskJustification {
            operation_name: "checkpoint_write".to_string(),
            expected_ops_hint: 99,
            atomicity_reason: "must finalize atomically".to_string(),
        };
        let cloned = orig.clone();
        assert_eq!(orig, cloned);
    }

    #[test]
    fn clone_eq_mask_outcome() {
        let variants = [
            MaskOutcome::CleanRelease,
            MaskOutcome::BoundExceeded,
            MaskOutcome::CancelDeferred,
        ];
        for v in &variants {
            let cloned = *v;
            assert_eq!(*v, cloned);
        }
    }

    #[test]
    fn clone_eq_mask_error_all_variants() {
        let variants = vec![
            MaskError::NestingDenied,
            MaskError::OperationNotAllowed {
                operation_name: "some_op".to_string(),
            },
            MaskError::AlreadyReleased,
        ];
        for v in &variants {
            let cloned = v.clone();
            assert_eq!(*v, cloned);
        }
    }

    #[test]
    fn clone_eq_mask_bounds() {
        let orig = MaskBounds { max_ops: 128 };
        let cloned = orig;
        assert_eq!(orig, cloned);
    }

    #[test]
    fn clone_eq_mask_policy() {
        let orig = MaskPolicy::standard();
        let cloned = orig.clone();
        assert_eq!(orig, cloned);
        assert_eq!(orig.operation_bounds.len(), cloned.operation_bounds.len());
    }

    #[test]
    fn json_field_presence_mask_justification() {
        let just = checkpoint_justification();
        let json = serde_json::to_string(&just).expect("serialize derived Serialize");
        assert!(json.contains("\"operation_name\""));
        assert!(json.contains("\"expected_ops_hint\""));
        assert!(json.contains("\"atomicity_reason\""));
    }

    #[test]
    fn json_field_presence_mask_event() {
        let event = MaskEvent {
            trace_id: "t1".to_string(),
            region_id: "r1".to_string(),
            mask_id: 7,
            operation_name: "evidence_append".to_string(),
            ops_executed: 3,
            outcome: MaskOutcome::CleanRelease,
        };
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"region_id\""));
        assert!(json.contains("\"mask_id\""));
        assert!(json.contains("\"operation_name\""));
        assert!(json.contains("\"ops_executed\""));
        assert!(json.contains("\"outcome\""));
    }

    #[test]
    fn json_field_presence_mask_policy() {
        let policy = MaskPolicy::standard();
        let json = serde_json::to_string(&policy).expect("serialize derived Serialize");
        assert!(json.contains("\"default_bounds\""));
        assert!(json.contains("\"operation_bounds\""));
        assert!(json.contains("\"lab_mode\""));
    }

    #[test]
    fn mask_error_source_returns_none() {
        use std::error::Error;
        let variants: Vec<MaskError> = vec![
            MaskError::NestingDenied,
            MaskError::OperationNotAllowed {
                operation_name: "op".to_string(),
            },
            MaskError::AlreadyReleased,
        ];
        for v in &variants {
            assert!(v.source().is_none(), "MaskError::source() should be None");
        }
    }

    #[test]
    fn mask_bounds_max_ops_one_exceeds_on_first_tick() {
        let mut policy = MaskPolicy::standard();
        policy
            .operation_bounds
            .insert("tiny_op".to_string(), MaskBounds { max_ops: 1 });
        let mut ctx = CancelMaskContext::new(policy, "t", "r");
        ctx.create_mask(&MaskJustification {
            operation_name: "tiny_op".to_string(),
            expected_ops_hint: 1,
            atomicity_reason: "single-tick atomic".to_string(),
        })
        .expect("serde deserialization should succeed");
        // First tick should exceed bound (ops_executed becomes 1 == max_ops)
        assert!(!ctx.tick());
        assert!(!ctx.is_masked());
    }

    #[test]
    fn mask_outcome_serde_preserves_display() {
        let variants = [
            MaskOutcome::CleanRelease,
            MaskOutcome::BoundExceeded,
            MaskOutcome::CancelDeferred,
        ];
        for v in &variants {
            let display_before = v.to_string();
            let json = serde_json::to_string(v).expect("serialize derived Serialize");
            let restored: MaskOutcome =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(display_before, restored.to_string());
        }
    }

    #[test]
    fn mask_error_debug_determinism() {
        let mk = || MaskError::OperationNotAllowed {
            operation_name: "replay_op".to_string(),
        };
        let debug1 = format!("{:?}", mk());
        let debug2 = format!("{:?}", mk());
        assert_eq!(
            debug1, debug2,
            "Debug output must be deterministic across runs"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: deep coverage
    // -----------------------------------------------------------------------

    #[test]
    fn clone_independence_mask_justification() {
        let orig = MaskJustification {
            operation_name: "checkpoint_write".to_string(),
            expected_ops_hint: 10,
            atomicity_reason: "atomic".to_string(),
        };
        let mut cloned = orig.clone();
        cloned.operation_name = "evidence_append".to_string();
        cloned.expected_ops_hint = 999;
        cloned.atomicity_reason = "changed".to_string();
        // Original must be unaffected.
        assert_eq!(orig.operation_name, "checkpoint_write");
        assert_eq!(orig.expected_ops_hint, 10);
        assert_eq!(orig.atomicity_reason, "atomic");
        assert_ne!(orig, cloned);
    }

    #[test]
    fn clone_independence_mask_policy() {
        let orig = MaskPolicy::standard();
        let mut cloned = orig.clone();
        cloned
            .operation_bounds
            .insert("extra_op".to_string(), MaskBounds { max_ops: 1 });
        cloned.lab_mode = true;
        cloned.default_bounds = MaskBounds { max_ops: 1 };
        // Original must be unaffected.
        assert!(!orig.is_allowed("extra_op"));
        assert!(!orig.lab_mode);
        assert_eq!(orig.default_bounds.max_ops, 64);
        assert_ne!(orig, cloned);
    }

    #[test]
    fn clone_independence_mask_event() {
        let orig = MaskEvent {
            trace_id: "t".to_string(),
            region_id: "r".to_string(),
            mask_id: 1,
            operation_name: "checkpoint_write".to_string(),
            ops_executed: 5,
            outcome: MaskOutcome::CleanRelease,
        };
        let mut cloned = orig.clone();
        cloned.trace_id = "modified".to_string();
        cloned.mask_id = 99;
        cloned.outcome = MaskOutcome::BoundExceeded;
        assert_eq!(orig.trace_id, "t");
        assert_eq!(orig.mask_id, 1);
        assert_eq!(orig.outcome, MaskOutcome::CleanRelease);
        assert_ne!(orig, cloned);
    }

    #[test]
    fn clone_independence_mask_error() {
        let orig = MaskError::OperationNotAllowed {
            operation_name: "op_a".to_string(),
        };
        let mut cloned = orig.clone();
        if let MaskError::OperationNotAllowed {
            ref mut operation_name,
        } = cloned
        {
            *operation_name = "op_b".to_string();
        }
        assert_ne!(orig, cloned);
        assert!(orig.to_string().contains("op_a"));
        assert!(cloned.to_string().contains("op_b"));
    }

    #[test]
    fn mask_outcome_debug_uniqueness() {
        let debugs: std::collections::BTreeSet<String> = [
            MaskOutcome::CleanRelease,
            MaskOutcome::BoundExceeded,
            MaskOutcome::CancelDeferred,
        ]
        .iter()
        .map(|o| format!("{o:?}"))
        .collect();
        assert_eq!(
            debugs.len(),
            3,
            "all MaskOutcome Debug representations must be unique"
        );
    }

    #[test]
    fn mask_error_debug_uniqueness() {
        let debugs: std::collections::BTreeSet<String> = [
            MaskError::NestingDenied,
            MaskError::OperationNotAllowed {
                operation_name: "x".to_string(),
            },
            MaskError::AlreadyReleased,
        ]
        .iter()
        .map(|e| format!("{e:?}"))
        .collect();
        assert_eq!(
            debugs.len(),
            3,
            "all MaskError Debug representations must be unique"
        );
    }

    #[test]
    fn mask_justification_debug_contains_fields() {
        let just = MaskJustification {
            operation_name: "my_op".to_string(),
            expected_ops_hint: 42,
            atomicity_reason: "reason_here".to_string(),
        };
        let dbg = format!("{just:?}");
        assert!(dbg.contains("my_op"));
        assert!(dbg.contains("42"));
        assert!(dbg.contains("reason_here"));
    }

    #[test]
    fn mask_bounds_debug_contains_max_ops() {
        let b = MaskBounds { max_ops: 256 };
        let dbg = format!("{b:?}");
        assert!(dbg.contains("256"));
    }

    #[test]
    fn mask_event_debug_contains_all_fields() {
        let event = MaskEvent {
            trace_id: "trace-abc".to_string(),
            region_id: "region-def".to_string(),
            mask_id: 77,
            operation_name: "hash_link_finalize".to_string(),
            ops_executed: 3,
            outcome: MaskOutcome::CancelDeferred,
        };
        let dbg = format!("{event:?}");
        assert!(dbg.contains("trace-abc"));
        assert!(dbg.contains("region-def"));
        assert!(dbg.contains("77"));
        assert!(dbg.contains("hash_link_finalize"));
        assert!(dbg.contains("3"));
        assert!(dbg.contains("CancelDeferred"));
    }

    #[test]
    fn empty_policy_denies_all_operations() {
        let policy = MaskPolicy {
            default_bounds: MaskBounds::default(),
            operation_bounds: BTreeMap::new(),
            lab_mode: false,
        };
        assert!(!policy.is_allowed("checkpoint_write"));
        assert!(!policy.is_allowed("evidence_append"));
        assert!(policy.bounds_for("checkpoint_write").is_none());
    }

    #[test]
    fn empty_policy_context_create_mask_fails() {
        let policy = MaskPolicy {
            default_bounds: MaskBounds::default(),
            operation_bounds: BTreeMap::new(),
            lab_mode: false,
        };
        let mut ctx = CancelMaskContext::new(policy, "t", "r");
        let err = ctx.create_mask(&checkpoint_justification()).unwrap_err();
        assert_eq!(
            err,
            MaskError::OperationNotAllowed {
                operation_name: "checkpoint_write".to_string()
            }
        );
    }

    #[test]
    fn empty_policy_serde_roundtrip() {
        let policy = MaskPolicy {
            default_bounds: MaskBounds { max_ops: 0 },
            operation_bounds: BTreeMap::new(),
            lab_mode: false,
        };
        let json = serde_json::to_string(&policy).expect("serialize derived Serialize");
        let restored: MaskPolicy =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(policy, restored);
        assert!(restored.operation_bounds.is_empty());
    }

    #[test]
    fn mask_bounds_zero_ops_exceeds_on_first_tick() {
        let mut policy = MaskPolicy::standard();
        policy
            .operation_bounds
            .insert("zero_op".to_string(), MaskBounds { max_ops: 0 });
        let mut ctx = CancelMaskContext::new(policy, "t", "r");
        ctx.create_mask(&MaskJustification {
            operation_name: "zero_op".to_string(),
            expected_ops_hint: 0,
            atomicity_reason: "zero".to_string(),
        })
        .expect("serde deserialization should succeed");
        // With max_ops=0, immediately masked; first tick sets ops_executed=1 >= 0
        // Actually ops_executed starts at 0 and bound is 0, so first tick: 0+1=1 >= 0 => exceeded
        assert!(!ctx.tick());
        assert!(!ctx.is_masked());
    }

    #[test]
    fn stress_many_sequential_masks() {
        let mut ctx = test_context();
        for i in 1..=100u64 {
            let id = ctx
                .create_mask(&checkpoint_justification())
                .expect("serde deserialization should succeed");
            assert_eq!(id, i);
            ctx.tick();
            ctx.release_mask(false)
                .expect("serde deserialization should succeed");
        }
        assert_eq!(ctx.event_count(), 100);
        let events = ctx.drain_events();
        assert_eq!(events.len(), 100);
        for (i, event) in events.iter().enumerate() {
            assert_eq!(event.mask_id, (i + 1) as u64);
            assert_eq!(event.outcome, MaskOutcome::CleanRelease);
        }
    }

    #[test]
    fn stress_tick_to_exact_bound() {
        let mut ctx = test_context();
        // two_phase_commit has max_ops=64
        ctx.create_mask(&MaskJustification {
            operation_name: "two_phase_commit".to_string(),
            expected_ops_hint: 64,
            atomicity_reason: "two-phase".to_string(),
        })
        .expect("serde deserialization should succeed");
        // Tick exactly 63 times — should all succeed.
        for _ in 0..63 {
            assert!(ctx.tick());
        }
        assert!(ctx.is_masked());
        // 64th tick exceeds the bound.
        assert!(!ctx.tick());
        assert!(!ctx.is_masked());
    }

    #[test]
    fn stress_alternating_operations() {
        let mut ctx = test_context();
        let ops = [
            "checkpoint_write",
            "evidence_append",
            "two_phase_commit",
            "hash_link_finalize",
        ];
        for (i, op) in ops.iter().enumerate() {
            let id = ctx
                .create_mask(&MaskJustification {
                    operation_name: op.to_string(),
                    expected_ops_hint: 1,
                    atomicity_reason: "stress test".to_string(),
                })
                .expect("serde deserialization should succeed");
            assert_eq!(id, (i + 1) as u64);
            ctx.tick();
            ctx.release_mask(false)
                .expect("serde deserialization should succeed");
        }
        assert_eq!(ctx.event_count(), 4);
    }

    #[test]
    fn deterministic_replay_with_mixed_outcomes() {
        let run = || -> Vec<MaskEvent> {
            let mut ctx = test_context();
            // Mask 1: clean release
            ctx.create_mask(&checkpoint_justification())
                .expect("serde deserialization should succeed");
            for _ in 0..5 {
                ctx.tick();
            }
            ctx.release_mask(false)
                .expect("serde deserialization should succeed");

            // Mask 2: bound exceeded
            ctx.create_mask(&MaskJustification {
                operation_name: "hash_link_finalize".to_string(),
                expected_ops_hint: 4,
                atomicity_reason: "hash".to_string(),
            })
            .expect("serde deserialization should succeed");
            for _ in 0..8 {
                ctx.tick();
            }
            ctx.release_mask(false)
                .expect("serde deserialization should succeed");

            // Mask 3: cancel deferred
            ctx.create_mask(&MaskJustification {
                operation_name: "evidence_append".to_string(),
                expected_ops_hint: 2,
                atomicity_reason: "evidence".to_string(),
            })
            .expect("serde deserialization should succeed");
            ctx.tick();
            ctx.tick();
            ctx.release_mask(true)
                .expect("serde deserialization should succeed");

            ctx.drain_events()
        };

        let events1 = run();
        let events2 = run();
        assert_eq!(events1.len(), 3);
        assert_eq!(events1, events2);
        assert_eq!(events1[0].outcome, MaskOutcome::CleanRelease);
        assert_eq!(events1[1].outcome, MaskOutcome::BoundExceeded);
        assert_eq!(events1[2].outcome, MaskOutcome::CancelDeferred);
    }

    #[test]
    fn double_release_returns_already_released() {
        let mut ctx = test_context();
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        ctx.release_mask(false)
            .expect("serde deserialization should succeed");
        let err = ctx.release_mask(false).unwrap_err();
        assert_eq!(err, MaskError::AlreadyReleased);
    }

    #[test]
    fn nesting_denied_with_different_operations() {
        let mut ctx = test_context();
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        let err = ctx
            .create_mask(&MaskJustification {
                operation_name: "evidence_append".to_string(),
                expected_ops_hint: 1,
                atomicity_reason: "nested".to_string(),
            })
            .unwrap_err();
        assert_eq!(err, MaskError::NestingDenied);
    }

    #[test]
    fn mask_event_serde_all_outcomes() {
        let outcomes = [
            MaskOutcome::CleanRelease,
            MaskOutcome::BoundExceeded,
            MaskOutcome::CancelDeferred,
        ];
        for outcome in &outcomes {
            let event = MaskEvent {
                trace_id: "t-serde".to_string(),
                region_id: "r-serde".to_string(),
                mask_id: 42,
                operation_name: "checkpoint_write".to_string(),
                ops_executed: 10,
                outcome: *outcome,
            };
            let json = serde_json::to_string(&event).expect("serialize derived Serialize");
            let restored: MaskEvent =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(event, restored);
        }
    }

    #[test]
    fn mask_justification_empty_strings_serde() {
        let just = MaskJustification {
            operation_name: String::new(),
            expected_ops_hint: 0,
            atomicity_reason: String::new(),
        };
        let json = serde_json::to_string(&just).expect("serialize derived Serialize");
        let restored: MaskJustification =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(just, restored);
        assert!(restored.operation_name.is_empty());
        assert!(restored.atomicity_reason.is_empty());
    }

    #[test]
    fn mask_justification_unicode_serde() {
        let just = MaskJustification {
            operation_name: "op_\u{1F600}_emoji".to_string(),
            expected_ops_hint: 1,
            atomicity_reason: "\u{00E9}\u{00E8}\u{00EA}".to_string(),
        };
        let json = serde_json::to_string(&just).expect("serialize derived Serialize");
        let restored: MaskJustification =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(just, restored);
    }

    #[test]
    fn mask_bounds_large_max_ops_serde() {
        let bounds = MaskBounds { max_ops: u64::MAX };
        let json = serde_json::to_string(&bounds).expect("serialize derived Serialize");
        let restored: MaskBounds =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(bounds, restored);
    }

    #[test]
    fn mask_policy_many_operations_serde() {
        let mut policy = MaskPolicy::standard();
        for i in 0..50 {
            policy
                .operation_bounds
                .insert(format!("op_{i}"), MaskBounds { max_ops: i + 1 });
        }
        let json = serde_json::to_string(&policy).expect("serialize derived Serialize");
        let restored: MaskPolicy =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(policy, restored);
        assert_eq!(restored.operation_bounds.len(), 54); // 4 standard + 50
    }

    #[test]
    fn drain_events_is_idempotent_on_empty() {
        let mut ctx = test_context();
        let drained1 = ctx.drain_events();
        let drained2 = ctx.drain_events();
        assert!(drained1.is_empty());
        assert!(drained2.is_empty());
        assert_eq!(ctx.event_count(), 0);
    }

    #[test]
    fn is_masked_false_after_bound_exceeded() {
        let mut ctx = test_context();
        ctx.create_mask(&MaskJustification {
            operation_name: "hash_link_finalize".to_string(),
            expected_ops_hint: 4,
            atomicity_reason: "hash".to_string(),
        })
        .expect("serde deserialization should succeed");
        assert!(ctx.is_masked());
        // Exhaust (max_ops = 8).
        for _ in 0..8 {
            ctx.tick();
        }
        assert!(!ctx.is_masked());
        // Still not masked after extra ticks.
        ctx.tick();
        assert!(!ctx.is_masked());
    }

    #[test]
    fn event_trace_and_region_propagation() {
        let mut ctx = CancelMaskContext::new(
            MaskPolicy::standard(),
            "trace-custom-42",
            "region-custom-99",
        );
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        ctx.tick();
        ctx.release_mask(false)
            .expect("serde deserialization should succeed");
        let events = ctx.drain_events();
        assert_eq!(events[0].trace_id, "trace-custom-42");
        assert_eq!(events[0].region_id, "region-custom-99");
    }

    #[test]
    fn context_with_empty_trace_and_region() {
        let mut ctx = CancelMaskContext::new(MaskPolicy::standard(), "", "");
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        ctx.tick();
        ctx.release_mask(false)
            .expect("serde deserialization should succeed");
        let events = ctx.drain_events();
        assert_eq!(events[0].trace_id, "");
        assert_eq!(events[0].region_id, "");
    }

    #[test]
    fn mask_after_nesting_denied_still_works() {
        let mut ctx = test_context();
        ctx.create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        // Attempt nested mask — fails.
        let _ = ctx.create_mask(&checkpoint_justification());
        // Original mask still active.
        assert!(ctx.is_masked());
        assert!(ctx.tick());
        ctx.release_mask(false)
            .expect("serde deserialization should succeed");
        assert!(!ctx.is_masked());
        // Can create a new mask now.
        let id = ctx
            .create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        assert_eq!(id, 2);
    }

    #[test]
    fn mask_after_disallowed_operation_error_still_works() {
        let mut ctx = test_context();
        let err = ctx
            .create_mask(&MaskJustification {
                operation_name: "unknown_op".to_string(),
                expected_ops_hint: 1,
                atomicity_reason: "test".to_string(),
            })
            .unwrap_err();
        assert!(matches!(err, MaskError::OperationNotAllowed { .. }));
        // Context should still be usable — no mask active.
        assert!(!ctx.is_masked());
        let id = ctx
            .create_mask(&checkpoint_justification())
            .expect("serde deserialization should succeed");
        assert_eq!(id, 1);
    }

    #[test]
    fn mask_event_equality() {
        let e1 = MaskEvent {
            trace_id: "t".to_string(),
            region_id: "r".to_string(),
            mask_id: 1,
            operation_name: "op".to_string(),
            ops_executed: 5,
            outcome: MaskOutcome::CleanRelease,
        };
        let e2 = e1.clone();
        assert_eq!(e1, e2);

        let e3 = MaskEvent {
            ops_executed: 6,
            ..e1.clone()
        };
        assert_ne!(e1, e3);
    }

    #[test]
    fn mask_outcome_copy_semantics() {
        let a = MaskOutcome::CancelDeferred;
        let b = a; // Copy
        let c = a; // Still valid after copy
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn mask_bounds_copy_semantics() {
        let a = MaskBounds { max_ops: 42 };
        let b = a; // Copy
        let c = a; // Still valid
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn policy_operation_bounds_are_sorted() {
        let policy = MaskPolicy::standard();
        let keys: Vec<&String> = policy.operation_bounds.keys().collect();
        // BTreeMap guarantees sorted order.
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn stress_drain_after_each_mask() {
        let mut ctx = test_context();
        for i in 1..=20u64 {
            ctx.create_mask(&checkpoint_justification())
                .expect("serde deserialization should succeed");
            for _ in 0..3 {
                ctx.tick();
            }
            ctx.release_mask(false)
                .expect("serde deserialization should succeed");
            let events = ctx.drain_events();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].mask_id, i);
            assert_eq!(events[0].ops_executed, 3);
            assert_eq!(ctx.event_count(), 0);
        }
    }

    #[test]
    fn mask_justification_inequality() {
        let a = MaskJustification {
            operation_name: "op_a".to_string(),
            expected_ops_hint: 10,
            atomicity_reason: "reason_a".to_string(),
        };
        let b = MaskJustification {
            operation_name: "op_b".to_string(),
            expected_ops_hint: 10,
            atomicity_reason: "reason_a".to_string(),
        };
        let c = MaskJustification {
            operation_name: "op_a".to_string(),
            expected_ops_hint: 20,
            atomicity_reason: "reason_a".to_string(),
        };
        let d = MaskJustification {
            operation_name: "op_a".to_string(),
            expected_ops_hint: 10,
            atomicity_reason: "reason_b".to_string(),
        };
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn mask_bounds_inequality() {
        let a = MaskBounds { max_ops: 10 };
        let b = MaskBounds { max_ops: 20 };
        assert_ne!(a, b);
    }

    #[test]
    fn mask_policy_inequality_on_lab_mode() {
        let mut a = MaskPolicy::standard();
        let mut b = MaskPolicy::standard();
        assert_eq!(a, b);
        b.lab_mode = true;
        assert_ne!(a, b);
        a.lab_mode = true;
        assert_eq!(a, b);
    }

    #[test]
    fn mask_policy_inequality_on_bounds() {
        let mut a = MaskPolicy::standard();
        let b = MaskPolicy::standard();
        a.default_bounds = MaskBounds { max_ops: 1 };
        assert_ne!(a, b);
    }

    #[test]
    fn context_debug_format_contains_policy() {
        let ctx = test_context();
        let dbg = format!("{ctx:?}");
        assert!(dbg.contains("CancelMaskContext"));
        assert!(dbg.contains("MaskPolicy"));
        assert!(dbg.contains("trace-1"));
        assert!(dbg.contains("region-1"));
    }
}
