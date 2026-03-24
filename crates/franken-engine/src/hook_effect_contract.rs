//! Formal Hook and Effect Semantics Contract (FRX-02.2)
//!
//! Machine-readable contract for React-compatible hook and effect semantics.
//! Defines hook slot indexing invariants, effect dependency semantics,
//! scheduling/timing boundaries observable to user code, and legal
//! transformations preserving semantics.
//!
//! Uses typestate-style phase constraints to prevent illegal lowering states.

#![forbid(unsafe_code)]

use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};

fn contract_schema() -> SchemaId {
    SchemaId::from_definition(b"hook_effect_contract-v1")
}
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

fn append_u8(buf: &mut Vec<u8>, value: u8) {
    buf.push(value);
}

fn append_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn append_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn append_bool(buf: &mut Vec<u8>, value: bool) {
    append_u8(buf, u8::from(value));
}

fn append_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    append_u64(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

fn append_string(buf: &mut Vec<u8>, value: &str) {
    append_len_prefixed(buf, value.as_bytes());
}

fn append_hook_kind(buf: &mut Vec<u8>, kind: HookKind) {
    let tag = match kind {
        HookKind::State => 0,
        HookKind::Reducer => 1,
        HookKind::Effect => 2,
        HookKind::LayoutEffect => 3,
        HookKind::Memo => 4,
        HookKind::Callback => 5,
        HookKind::Ref => 6,
        HookKind::Context => 7,
        HookKind::ImperativeHandle => 8,
        HookKind::DebugValue => 9,
        HookKind::DeferredValue => 10,
        HookKind::Transition => 11,
        HookKind::Id => 12,
        HookKind::SyncExternalStore => 13,
        HookKind::InsertionEffect => 14,
    };
    append_u8(buf, tag);
}

fn append_render_phase(buf: &mut Vec<u8>, phase: RenderPhase) {
    let tag = match phase {
        RenderPhase::Rendering => 0,
        RenderPhase::InsertionEffectsPending => 1,
        RenderPhase::LayoutEffectsPending => 2,
        RenderPhase::PaintPending => 3,
        RenderPhase::PassiveEffectsPending => 4,
        RenderPhase::Idle => 5,
        RenderPhase::Unmounting => 6,
    };
    append_u8(buf, tag);
}

fn append_effect_timing(buf: &mut Vec<u8>, timing: EffectTiming) {
    let tag = match timing {
        EffectTiming::Insertion => 0,
        EffectTiming::Layout => 1,
        EffectTiming::Passive => 2,
    };
    append_u8(buf, tag);
}

fn append_legal_transformation(buf: &mut Vec<u8>, transformation: LegalTransformation) {
    let tag = match transformation {
        LegalTransformation::MemoConstantFold => 0,
        LegalTransformation::CallbackInline => 1,
        LegalTransformation::StateToReducer => 2,
        LegalTransformation::RefHoist => 3,
        LegalTransformation::ContextDedup => 4,
        LegalTransformation::EffectElision => 5,
        LegalTransformation::MemoReorder => 6,
        LegalTransformation::StateBatch => 7,
    };
    append_u8(buf, tag);
}

fn append_unsupported_semantics_trigger(buf: &mut Vec<u8>, trigger: UnsupportedSemanticsTrigger) {
    let tag = match trigger {
        UnsupportedSemanticsTrigger::HookTopologyDrift => 0,
        UnsupportedSemanticsTrigger::DependencyShapeDrift => 1,
        UnsupportedSemanticsTrigger::OutOfRenderHookExecution => 2,
        UnsupportedSemanticsTrigger::SchedulerOrderingAmbiguity => 3,
        UnsupportedSemanticsTrigger::UnsupportedHookPrimitive => 4,
        UnsupportedSemanticsTrigger::TransformationProofMissing => 5,
    };
    append_u8(buf, tag);
}

fn append_fallback_execution_route(buf: &mut Vec<u8>, route: FallbackExecutionRoute) {
    let tag = match route {
        FallbackExecutionRoute::CompatibilityRuntimeLane => 0,
        FallbackExecutionRoute::BaselineInterpreterLane => 1,
        FallbackExecutionRoute::DeterministicSafeModeLane => 2,
    };
    append_u8(buf, tag);
}

fn append_hook_manifest_bytes(buf: &mut Vec<u8>, manifest: &HookManifest) {
    append_string(buf, &manifest.component_name);
    append_u32(buf, manifest.version);
    append_u64(buf, manifest.slots.len() as u64);
    for slot in &manifest.slots {
        append_u32(buf, slot.index.0);
        append_hook_kind(buf, slot.kind);
        match slot.deps.as_ref() {
            Some(deps) => {
                append_u8(buf, 1);
                append_u64(buf, deps.len() as u64);
                for dep in deps {
                    append_u64(buf, dep.0);
                }
            }
            None => append_u8(buf, 0),
        }
    }
}

fn append_scheduling_boundary(buf: &mut Vec<u8>, boundary: &SchedulingBoundary) {
    append_effect_timing(buf, boundary.timing);
    append_bool(buf, boundary.synchronous);
    append_bool(buf, boundary.dom_mutations_visible);
    append_bool(buf, boundary.state_updates_batched);
}

// ---------------------------------------------------------------------------
// Hook slot types
// ---------------------------------------------------------------------------

/// Identifies a hook call site within a component by its zero-based invocation
/// index. React requires hooks to be called in identical order on every render;
/// this index captures that invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HookSlotIndex(pub u32);

/// The kind of hook occupying a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HookKind {
    /// useState — produces (state, setter) pair.
    State,
    /// useReducer — produces (state, dispatch) pair.
    Reducer,
    /// useEffect — passive effect that runs after paint.
    Effect,
    /// useLayoutEffect — synchronous effect that runs before paint.
    LayoutEffect,
    /// useMemo — memoised computation.
    Memo,
    /// useCallback — memoised callback reference.
    Callback,
    /// useRef — stable mutable container.
    Ref,
    /// useContext — context subscription.
    Context,
    /// useImperativeHandle — exposed imperative methods.
    ImperativeHandle,
    /// useDebugValue — devtools label.
    DebugValue,
    /// useDeferredValue — deferred rendering.
    DeferredValue,
    /// useTransition — transition scheduling.
    Transition,
    /// useId — deterministic id generation.
    Id,
    /// useSyncExternalStore — external store subscription.
    SyncExternalStore,
    /// useInsertionEffect — CSS-in-JS insertion before layout effects.
    InsertionEffect,
}

impl HookKind {
    pub const ALL: &[HookKind] = &[
        Self::State,
        Self::Reducer,
        Self::Effect,
        Self::LayoutEffect,
        Self::Memo,
        Self::Callback,
        Self::Ref,
        Self::Context,
        Self::ImperativeHandle,
        Self::DebugValue,
        Self::DeferredValue,
        Self::Transition,
        Self::Id,
        Self::SyncExternalStore,
        Self::InsertionEffect,
    ];

    /// Whether this hook kind produces an effect that must be scheduled.
    pub fn has_effect_phase(&self) -> bool {
        matches!(
            self,
            Self::Effect | Self::LayoutEffect | Self::InsertionEffect
        )
    }

    /// Whether this hook kind can trigger a re-render via state update.
    pub fn can_trigger_rerender(&self) -> bool {
        matches!(
            self,
            Self::State
                | Self::Reducer
                | Self::Context
                | Self::SyncExternalStore
                | Self::Transition
                | Self::DeferredValue
        )
    }

    /// Whether this hook kind participates in dependency-array memoisation.
    pub fn has_dependency_array(&self) -> bool {
        matches!(
            self,
            Self::Effect
                | Self::LayoutEffect
                | Self::InsertionEffect
                | Self::Memo
                | Self::Callback
                | Self::ImperativeHandle
        )
    }
}

// ---------------------------------------------------------------------------
// Hook slot record
// ---------------------------------------------------------------------------

/// A single hook slot in a component's hook list. Captures the kind, position,
/// and dependency array (if applicable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookSlot {
    pub index: HookSlotIndex,
    pub kind: HookKind,
    /// Dependency array indices referencing external values.
    /// Empty means "run every render"; `None` means "run once on mount".
    pub deps: Option<Vec<DepToken>>,
}

/// Opaque token identifying a dependency value for equality tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DepToken(pub u64);

// ---------------------------------------------------------------------------
// Component hook manifest
// ---------------------------------------------------------------------------

/// The complete, ordered hook manifest for a single component. This is the
/// canonical source of truth for the component's hook call order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookManifest {
    pub component_name: String,
    pub slots: Vec<HookSlot>,
    pub version: u32,
}

/// Errors when validating a hook manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookManifestError {
    /// Slot indices are not consecutive starting from 0.
    NonConsecutiveIndices { expected: u32, found: u32 },
    /// Dependency array supplied for a hook kind that does not support deps.
    DepsOnNonDepHook {
        index: HookSlotIndex,
        kind: HookKind,
    },
    /// Manifest is empty (component must have at least one hook to be tracked).
    EmptyManifest,
    /// Duplicate slot index.
    DuplicateIndex(HookSlotIndex),
}

impl HookManifest {
    pub fn new(component_name: impl Into<String>, slots: Vec<HookSlot>) -> Self {
        Self {
            component_name: component_name.into(),
            slots,
            version: 1,
        }
    }

    /// Validate that the manifest satisfies React hook ordering invariants.
    pub fn validate(&self) -> Vec<HookManifestError> {
        let mut errors = Vec::new();
        if self.slots.is_empty() {
            errors.push(HookManifestError::EmptyManifest);
            return errors;
        }

        let mut seen = BTreeSet::new();
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.index.0 != i as u32 {
                errors.push(HookManifestError::NonConsecutiveIndices {
                    expected: i as u32,
                    found: slot.index.0,
                });
            }
            if !seen.insert(slot.index) {
                errors.push(HookManifestError::DuplicateIndex(slot.index));
            }
            if slot.deps.is_some() && !slot.kind.has_dependency_array() {
                errors.push(HookManifestError::DepsOnNonDepHook {
                    index: slot.index,
                    kind: slot.kind,
                });
            }
        }
        errors
    }

    /// Derive a content-addressed ID for this manifest.
    /// Includes all slot kinds and dependency tokens for collision resistance.
    pub fn derive_id(&self) -> EngineObjectId {
        let mut canonical = Vec::new();
        append_hook_manifest_bytes(&mut canonical, self);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "hook-effect",
            &contract_schema(),
            &canonical,
        )
        .expect("hook manifest id derivation")
    }
}

// ---------------------------------------------------------------------------
// Component render phase (typestate)
// ---------------------------------------------------------------------------

/// The phases of a component render lifecycle. Typestate-style: transitions are
/// validated at the contract level; illegal phase transitions are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RenderPhase {
    /// Component function body executing, hooks being called.
    Rendering,
    /// Render completed; insertion effects pending.
    InsertionEffectsPending,
    /// Insertion effects executed; layout effects pending.
    LayoutEffectsPending,
    /// Layout effects executed; browser paint can proceed.
    PaintPending,
    /// Paint completed; passive effects pending.
    PassiveEffectsPending,
    /// All effects drained; component is idle until next update.
    Idle,
    /// Component is being unmounted; cleanup effects executing.
    Unmounting,
}

impl RenderPhase {
    /// Legal successor phases from this phase.
    pub fn legal_successors(&self) -> &[RenderPhase] {
        match self {
            Self::Rendering => &[Self::InsertionEffectsPending],
            Self::InsertionEffectsPending => &[Self::LayoutEffectsPending],
            Self::LayoutEffectsPending => &[Self::PaintPending],
            Self::PaintPending => &[Self::PassiveEffectsPending],
            Self::PassiveEffectsPending => &[Self::Idle],
            Self::Idle => &[Self::Rendering, Self::Unmounting],
            Self::Unmounting => &[],
        }
    }

    /// Whether transition to `target` is legal from this phase.
    pub fn can_transition_to(&self, target: RenderPhase) -> bool {
        self.legal_successors().contains(&target)
    }
}

// ---------------------------------------------------------------------------
// Phase-constrained effect scheduling
// ---------------------------------------------------------------------------

/// The timing class of an effect, determining when it fires relative to paint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EffectTiming {
    /// useInsertionEffect — fires synchronously before DOM mutations are read.
    Insertion,
    /// useLayoutEffect — fires synchronously after DOM mutations, before paint.
    Layout,
    /// useEffect — fires asynchronously after paint.
    Passive,
}

impl EffectTiming {
    /// The render phase during which this effect class executes.
    pub fn execution_phase(&self) -> RenderPhase {
        match self {
            Self::Insertion => RenderPhase::InsertionEffectsPending,
            Self::Layout => RenderPhase::LayoutEffectsPending,
            Self::Passive => RenderPhase::PassiveEffectsPending,
        }
    }

    /// Scheduling ordering: insertion < layout < passive.
    pub fn scheduling_order(&self) -> u8 {
        match self {
            Self::Insertion => 0,
            Self::Layout => 1,
            Self::Passive => 2,
        }
    }
}

/// A pending effect instance to be scheduled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingEffect {
    pub component_name: String,
    pub hook_index: HookSlotIndex,
    pub timing: EffectTiming,
    /// Sequence number for deterministic ordering within the same timing class.
    pub tree_order: u64,
    /// Whether this is a cleanup (destroy) from a previous render.
    pub is_cleanup: bool,
}

impl PendingEffect {
    pub fn derive_id(&self) -> EngineObjectId {
        let mut canonical = Vec::new();
        append_string(&mut canonical, &self.component_name);
        append_u32(&mut canonical, self.hook_index.0);
        append_effect_timing(&mut canonical, self.timing);
        append_u64(&mut canonical, self.tree_order);
        append_bool(&mut canonical, self.is_cleanup);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "hook-effect",
            &contract_schema(),
            &canonical,
        )
        .expect("effect id derivation")
    }
}

// ---------------------------------------------------------------------------
// Effect scheduler
// ---------------------------------------------------------------------------

/// Deterministic effect scheduler that enforces React's effect ordering:
/// 1. All cleanups for a timing class fire before creates (tree order).
/// 2. Within cleanups/creates, fire in component tree order.
/// 3. Timing classes fire in order: insertion → layout → passive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectScheduler {
    pending: Vec<PendingEffect>,
}

impl EffectScheduler {
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    pub fn enqueue(&mut self, effect: PendingEffect) {
        self.pending.push(effect);
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Drain effects in React-correct order for the given timing class.
    /// Returns (cleanups, creates) both in tree order.
    pub fn drain_for_timing(
        &mut self,
        timing: EffectTiming,
    ) -> (Vec<PendingEffect>, Vec<PendingEffect>) {
        let (matching, rest): (Vec<_>, Vec<_>) =
            self.pending.drain(..).partition(|e| e.timing == timing);
        self.pending = rest;

        let mut cleanups: Vec<_> = matching.iter().filter(|e| e.is_cleanup).cloned().collect();
        let mut creates: Vec<_> = matching.iter().filter(|e| !e.is_cleanup).cloned().collect();
        cleanups.sort_by_key(|e| e.tree_order);
        creates.sort_by_key(|e| e.tree_order);

        (cleanups, creates)
    }

    /// Drain all effects in correct global order: insertion → layout → passive,
    /// each split into cleanups-then-creates in tree order.
    pub fn drain_all_ordered(&mut self) -> Vec<PendingEffect> {
        let mut result = Vec::new();
        for timing in &[
            EffectTiming::Insertion,
            EffectTiming::Layout,
            EffectTiming::Passive,
        ] {
            let (cleanups, creates) = self.drain_for_timing(*timing);
            result.extend(cleanups);
            result.extend(creates);
        }
        result
    }
}

impl Default for EffectScheduler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Dependency change detection
// ---------------------------------------------------------------------------

/// Outcome of comparing two dependency arrays for an effect/memo hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DepsChange {
    /// No deps array (run every render).
    AlwaysRun,
    /// Empty deps array (run only on mount/unmount).
    MountOnly,
    /// Deps unchanged — skip effect execution.
    Unchanged,
    /// At least one dep changed — re-run effect.
    Changed,
}

/// Compare previous and current dependency arrays to determine whether
/// an effect should re-run.
pub fn compare_deps(prev: Option<&[DepToken]>, curr: Option<&[DepToken]>) -> DepsChange {
    match (prev, curr) {
        (None, None) => DepsChange::AlwaysRun,
        (_, None) => DepsChange::AlwaysRun,
        (None, Some([])) => DepsChange::MountOnly,
        (None, Some(_)) => DepsChange::Changed,
        (Some(p), Some(c)) => {
            if c.is_empty() {
                return DepsChange::MountOnly;
            }
            if p.len() != c.len() {
                return DepsChange::Changed;
            }
            if p == c {
                DepsChange::Unchanged
            } else {
                DepsChange::Changed
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Hook rules of hooks enforcement
// ---------------------------------------------------------------------------

/// Violations of the Rules of Hooks detected at the contract level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookRuleViolation {
    /// Hook count changed between renders.
    HookCountMismatch {
        component: String,
        previous_count: u32,
        current_count: u32,
    },
    /// Hook kind at a given slot changed between renders.
    HookKindMismatch {
        component: String,
        slot: HookSlotIndex,
        previous_kind: HookKind,
        current_kind: HookKind,
    },
    /// Hook called outside a render phase.
    HookOutsideRender {
        component: String,
        slot: HookSlotIndex,
        actual_phase: RenderPhase,
    },
    /// Hook called conditionally (detected via slot order change).
    ConditionalHookCall {
        component: String,
        slot: HookSlotIndex,
    },
    /// Dependency array length changed between renders.
    DepsLengthMismatch {
        component: String,
        slot: HookSlotIndex,
        previous_len: usize,
        current_len: usize,
    },
}

/// Validate that two consecutive renders of the same component have compatible
/// hook call sequences.
pub fn validate_hook_consistency(
    prev: &HookManifest,
    curr: &HookManifest,
) -> Vec<HookRuleViolation> {
    let mut violations = Vec::new();

    if prev.slots.len() != curr.slots.len() {
        violations.push(HookRuleViolation::HookCountMismatch {
            component: curr.component_name.clone(),
            previous_count: prev.slots.len() as u32,
            current_count: curr.slots.len() as u32,
        });
        return violations;
    }

    for (p, c) in prev.slots.iter().zip(curr.slots.iter()) {
        if p.kind != c.kind {
            violations.push(HookRuleViolation::HookKindMismatch {
                component: curr.component_name.clone(),
                slot: c.index,
                previous_kind: p.kind,
                current_kind: c.kind,
            });
        }
        if let (Some(pd), Some(cd)) = (&p.deps, &c.deps)
            && pd.len() != cd.len()
        {
            violations.push(HookRuleViolation::DepsLengthMismatch {
                component: curr.component_name.clone(),
                slot: c.index,
                previous_len: pd.len(),
                current_len: cd.len(),
            });
        }
    }

    violations
}

// ---------------------------------------------------------------------------
// Legal transformations
// ---------------------------------------------------------------------------

/// Transformations that a compiler/optimizer may legally apply while preserving
/// hook/effect semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LegalTransformation {
    /// Constant-fold a useMemo whose deps are all constants.
    MemoConstantFold,
    /// Inline a useCallback whose body has no free variables beyond deps.
    CallbackInline,
    /// Merge adjacent useState calls into a single useReducer.
    StateToReducer,
    /// Hoist a useRef to module scope when the component is a singleton.
    RefHoist,
    /// Deduplicate identical useContext subscriptions.
    ContextDedup,
    /// Elide a useEffect whose body and cleanup are both no-ops.
    EffectElision,
    /// Reorder useMemo computations when there are no data dependencies between them.
    MemoReorder,
    /// Batch multiple setState calls into a single state update.
    StateBatch,
}

impl LegalTransformation {
    pub const ALL: &[LegalTransformation] = &[
        Self::MemoConstantFold,
        Self::CallbackInline,
        Self::StateToReducer,
        Self::RefHoist,
        Self::ContextDedup,
        Self::EffectElision,
        Self::MemoReorder,
        Self::StateBatch,
    ];

    /// The hook kinds this transformation is applicable to.
    pub fn applicable_hooks(&self) -> &[HookKind] {
        match self {
            Self::MemoConstantFold => &[HookKind::Memo],
            Self::CallbackInline => &[HookKind::Callback],
            Self::StateToReducer => &[HookKind::State],
            Self::RefHoist => &[HookKind::Ref],
            Self::ContextDedup => &[HookKind::Context],
            Self::EffectElision => &[
                HookKind::Effect,
                HookKind::LayoutEffect,
                HookKind::InsertionEffect,
            ],
            Self::MemoReorder => &[HookKind::Memo],
            Self::StateBatch => &[HookKind::State, HookKind::Reducer],
        }
    }

    /// Whether this transformation preserves the observable effect schedule.
    pub fn preserves_effect_order(&self) -> bool {
        match self {
            Self::MemoConstantFold
            | Self::CallbackInline
            | Self::RefHoist
            | Self::ContextDedup
            | Self::StateBatch => true,
            Self::StateToReducer | Self::EffectElision => true,
            Self::MemoReorder => false, // reorders computation, not effects
        }
    }

    /// Whether the transformation is always safe (no preconditions beyond type match).
    pub fn is_unconditional(&self) -> bool {
        matches!(self, Self::ContextDedup | Self::StateBatch)
    }
}

// ---------------------------------------------------------------------------
// Transformation precondition record
// ---------------------------------------------------------------------------

/// Evidence that a transformation's preconditions have been checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformationReceipt {
    pub transformation: LegalTransformation,
    pub component_name: String,
    pub target_slots: Vec<HookSlotIndex>,
    pub precondition_met: bool,
    pub reason: String,
}

impl TransformationReceipt {
    pub fn derive_id(&self) -> EngineObjectId {
        let mut canonical = Vec::new();
        append_legal_transformation(&mut canonical, self.transformation);
        append_string(&mut canonical, &self.component_name);
        append_u64(&mut canonical, self.target_slots.len() as u64);
        for slot in &self.target_slots {
            append_u32(&mut canonical, slot.0);
        }
        append_bool(&mut canonical, self.precondition_met);
        append_string(&mut canonical, &self.reason);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "hook-effect",
            &contract_schema(),
            &canonical,
        )
        .expect("transformation receipt id derivation")
    }
}

// ---------------------------------------------------------------------------
// Phase transition contract
// ---------------------------------------------------------------------------

/// A validated phase transition with evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseTransition {
    pub component_name: String,
    pub from: RenderPhase,
    pub to: RenderPhase,
    pub sequence_number: u64,
}

/// Errors from phase transition validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhaseTransitionError {
    IllegalTransition {
        component: String,
        from: RenderPhase,
        to: RenderPhase,
    },
}

impl PhaseTransition {
    pub fn validate(&self) -> Result<(), PhaseTransitionError> {
        if self.from.can_transition_to(self.to) {
            Ok(())
        } else {
            Err(PhaseTransitionError::IllegalTransition {
                component: self.component_name.clone(),
                from: self.from,
                to: self.to,
            })
        }
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let mut canonical = Vec::new();
        append_string(&mut canonical, &self.component_name);
        append_render_phase(&mut canonical, self.from);
        append_render_phase(&mut canonical, self.to);
        append_u64(&mut canonical, self.sequence_number);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "hook-effect",
            &contract_schema(),
            &canonical,
        )
        .expect("phase transition id derivation")
    }
}

// ---------------------------------------------------------------------------
// Component state machine
// ---------------------------------------------------------------------------

/// Tracks the render phase lifecycle of a single component instance,
/// enforcing typestate-style phase constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentPhaseTracker {
    pub component_name: String,
    pub current_phase: RenderPhase,
    pub render_count: u64,
    pub transition_log: Vec<PhaseTransition>,
    next_seq: u64,
}

impl ComponentPhaseTracker {
    pub fn new(component_name: impl Into<String>) -> Self {
        Self {
            component_name: component_name.into(),
            current_phase: RenderPhase::Idle,
            render_count: 0,
            transition_log: Vec::new(),
            next_seq: 0,
        }
    }

    /// Attempt a phase transition. Returns error if the transition is illegal.
    pub fn transition_to(
        &mut self,
        target: RenderPhase,
    ) -> Result<&PhaseTransition, PhaseTransitionError> {
        let transition = PhaseTransition {
            component_name: self.component_name.clone(),
            from: self.current_phase,
            to: target,
            sequence_number: self.next_seq,
        };
        transition.validate()?;

        if target == RenderPhase::Rendering {
            self.render_count += 1;
        }

        self.current_phase = target;
        self.next_seq += 1;
        self.transition_log.push(transition);
        Ok(self.transition_log.last().expect("just pushed"))
    }

    /// Run a complete render cycle: Rendering → ... → Idle.
    pub fn run_full_cycle(&mut self) -> Result<(), PhaseTransitionError> {
        let phases = [
            RenderPhase::Rendering,
            RenderPhase::InsertionEffectsPending,
            RenderPhase::LayoutEffectsPending,
            RenderPhase::PaintPending,
            RenderPhase::PassiveEffectsPending,
            RenderPhase::Idle,
        ];
        for phase in phases {
            self.transition_to(phase)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Scheduling boundary contract
// ---------------------------------------------------------------------------

/// Defines observable timing guarantees that user code may rely on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulingBoundary {
    /// Effect timing class.
    pub timing: EffectTiming,
    /// Whether this effect class is synchronous (blocks the rendering pipeline).
    pub synchronous: bool,
    /// Whether DOM reads in this phase see committed mutations.
    pub dom_mutations_visible: bool,
    /// Whether state updates in this phase trigger a synchronous re-render.
    pub state_updates_batched: bool,
}

impl SchedulingBoundary {
    /// Returns the canonical scheduling boundaries for all three effect classes.
    pub fn canonical_boundaries() -> Vec<SchedulingBoundary> {
        vec![
            SchedulingBoundary {
                timing: EffectTiming::Insertion,
                synchronous: true,
                dom_mutations_visible: false,
                state_updates_batched: true,
            },
            SchedulingBoundary {
                timing: EffectTiming::Layout,
                synchronous: true,
                dom_mutations_visible: true,
                state_updates_batched: true,
            },
            SchedulingBoundary {
                timing: EffectTiming::Passive,
                synchronous: false,
                dom_mutations_visible: true,
                state_updates_batched: true,
            },
        ]
    }
}

// ---------------------------------------------------------------------------
// Contract summary / evidence bundle
// ---------------------------------------------------------------------------

/// Top-level contract that bundles all hook/effect semantics for a component tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookEffectContract {
    pub manifests: BTreeMap<String, HookManifest>,
    pub scheduling_boundaries: Vec<SchedulingBoundary>,
    pub approved_transformations: BTreeSet<LegalTransformation>,
    pub version: u32,
}

impl HookEffectContract {
    pub fn new() -> Self {
        Self {
            manifests: BTreeMap::new(),
            scheduling_boundaries: SchedulingBoundary::canonical_boundaries(),
            approved_transformations: BTreeSet::new(),
            version: 1,
        }
    }

    pub fn register_manifest(&mut self, manifest: HookManifest) {
        self.manifests
            .insert(manifest.component_name.clone(), manifest);
    }

    pub fn approve_transformation(&mut self, t: LegalTransformation) {
        self.approved_transformations.insert(t);
    }

    /// Validate all registered manifests.
    pub fn validate_all(&self) -> BTreeMap<String, Vec<HookManifestError>> {
        let mut results = BTreeMap::new();
        for (name, manifest) in &self.manifests {
            let errors = manifest.validate();
            if !errors.is_empty() {
                results.insert(name.clone(), errors);
            }
        }
        results
    }

    /// Total hook count across all registered components.
    pub fn total_hook_count(&self) -> usize {
        self.manifests.values().map(|m| m.slots.len()).sum()
    }

    /// Count of effect-bearing hooks.
    pub fn effect_hook_count(&self) -> usize {
        self.manifests
            .values()
            .flat_map(|m| m.slots.iter())
            .filter(|s| s.kind.has_effect_phase())
            .count()
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let mut canonical = Vec::new();
        append_u32(&mut canonical, self.version);
        append_u64(&mut canonical, self.manifests.len() as u64);
        for (component_name, manifest) in &self.manifests {
            append_string(&mut canonical, component_name);
            append_hook_manifest_bytes(&mut canonical, manifest);
        }
        append_u64(&mut canonical, self.scheduling_boundaries.len() as u64);
        for boundary in &self.scheduling_boundaries {
            append_scheduling_boundary(&mut canonical, boundary);
        }
        append_u64(&mut canonical, self.approved_transformations.len() as u64);
        for transformation in &self.approved_transformations {
            append_legal_transformation(&mut canonical, *transformation);
        }
        derive_id(
            ObjectDomain::EvidenceRecord,
            "hook-effect",
            &contract_schema(),
            &canonical,
        )
        .expect("contract id derivation")
    }
}

impl Default for HookEffectContract {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unsupported semantics + deterministic fallback contract (FRX-02.3)
// ---------------------------------------------------------------------------

/// Deterministic reasons the compile path may be rejected while preserving
/// compatibility through a fallback execution route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum UnsupportedSemanticsTrigger {
    /// Hook topology changed between renders (count/order/kind drift).
    HookTopologyDrift,
    /// Dependency array shape changed in an unsupported way.
    DependencyShapeDrift,
    /// A hook escaped render phase boundaries.
    OutOfRenderHookExecution,
    /// Scheduler ordering cannot be proven equivalent.
    SchedulerOrderingAmbiguity,
    /// A hook primitive is not currently supported by lowering path.
    UnsupportedHookPrimitive,
    /// Required transformation witness/proof is absent.
    TransformationProofMissing,
}

impl UnsupportedSemanticsTrigger {
    /// Stable operator-facing error code.
    pub fn stable_error_code(&self) -> &'static str {
        match self {
            Self::HookTopologyDrift => "FE-HOOK-UNSUPPORTED-0001",
            Self::DependencyShapeDrift => "FE-HOOK-UNSUPPORTED-0002",
            Self::OutOfRenderHookExecution => "FE-HOOK-UNSUPPORTED-0003",
            Self::SchedulerOrderingAmbiguity => "FE-HOOK-UNSUPPORTED-0004",
            Self::UnsupportedHookPrimitive => "FE-HOOK-UNSUPPORTED-0005",
            Self::TransformationProofMissing => "FE-HOOK-UNSUPPORTED-0006",
        }
    }

    /// Deterministic human-readable compile-path rejection reason.
    pub fn rejection_reason(&self) -> &'static str {
        match self {
            Self::HookTopologyDrift => {
                "hook slot topology drifted from prior render; compile path rejected"
            }
            Self::DependencyShapeDrift => {
                "dependency array shape drift detected; compile path rejected"
            }
            Self::OutOfRenderHookExecution => {
                "hook executed outside render phase constraints; compile path rejected"
            }
            Self::SchedulerOrderingAmbiguity => {
                "effect schedule ordering could not be proven equivalent; compile path rejected"
            }
            Self::UnsupportedHookPrimitive => {
                "hook primitive unsupported by current lowering path; compile path rejected"
            }
            Self::TransformationProofMissing => {
                "required transformation proof receipt missing; compile path rejected"
            }
        }
    }

    /// Guidance to incrementally harden the unsupported case.
    pub fn hardening_guidance(&self) -> &'static str {
        match self {
            Self::HookTopologyDrift => {
                "stabilize hook call order/count, then rerun FRX hook consistency gate"
            }
            Self::DependencyShapeDrift => {
                "normalize dependency arrays to fixed cardinality and rerun dependency proofs"
            }
            Self::OutOfRenderHookExecution => {
                "move hook invocation into render boundary and enforce phase-typed transitions"
            }
            Self::SchedulerOrderingAmbiguity => {
                "emit explicit scheduling witness proving insertion/layout/passive equivalence"
            }
            Self::UnsupportedHookPrimitive => {
                "route primitive through compatibility lane and add lowering support behind proofs"
            }
            Self::TransformationProofMissing => {
                "generate transformation receipt and attach proof-obligation witness"
            }
        }
    }
}

/// Compatibility-preserving route selected when compile path is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FallbackExecutionRoute {
    /// Deterministic compatibility runtime lane preserving semantics.
    CompatibilityRuntimeLane,
    /// Baseline interpreter lane with no speculative transforms.
    BaselineInterpreterLane,
    /// Strict safe mode lane for phase/scheduler safety.
    DeterministicSafeModeLane,
}

/// Structured diagnostic emitted when unsupported semantics trigger fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsupportedSemanticsDiagnostic {
    pub schema_version: String,
    pub component_name: String,
    pub trigger: UnsupportedSemanticsTrigger,
    pub fallback_route: FallbackExecutionRoute,
    pub compile_path_rejected: bool,
    pub reason: String,
    pub hardening_guidance: String,
    pub error_code: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

impl UnsupportedSemanticsDiagnostic {
    pub fn derive_id(&self) -> EngineObjectId {
        let mut canonical = Vec::new();
        append_string(&mut canonical, &self.schema_version);
        append_string(&mut canonical, &self.component_name);
        append_unsupported_semantics_trigger(&mut canonical, self.trigger);
        append_fallback_execution_route(&mut canonical, self.fallback_route);
        append_bool(&mut canonical, self.compile_path_rejected);
        append_string(&mut canonical, &self.reason);
        append_string(&mut canonical, &self.hardening_guidance);
        append_string(&mut canonical, &self.error_code);
        append_string(&mut canonical, &self.trace_id);
        append_string(&mut canonical, &self.decision_id);
        append_string(&mut canonical, &self.policy_id);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "hook-effect",
            &contract_schema(),
            &canonical,
        )
        .expect("unsupported semantics diagnostic id derivation")
    }
}

/// Deterministically map unsupported trigger to compatibility-preserving route.
pub fn fallback_route_for_trigger(trigger: UnsupportedSemanticsTrigger) -> FallbackExecutionRoute {
    match trigger {
        UnsupportedSemanticsTrigger::HookTopologyDrift
        | UnsupportedSemanticsTrigger::DependencyShapeDrift
        | UnsupportedSemanticsTrigger::UnsupportedHookPrimitive => {
            FallbackExecutionRoute::CompatibilityRuntimeLane
        }
        UnsupportedSemanticsTrigger::TransformationProofMissing => {
            FallbackExecutionRoute::BaselineInterpreterLane
        }
        UnsupportedSemanticsTrigger::OutOfRenderHookExecution
        | UnsupportedSemanticsTrigger::SchedulerOrderingAmbiguity => {
            FallbackExecutionRoute::DeterministicSafeModeLane
        }
    }
}

/// Classify a hook rule violation into FRX-02.3 unsupported semantics triggers.
pub fn classify_unsupported_semantics(
    violation: &HookRuleViolation,
) -> UnsupportedSemanticsTrigger {
    match violation {
        HookRuleViolation::HookCountMismatch { .. }
        | HookRuleViolation::HookKindMismatch { .. }
        | HookRuleViolation::ConditionalHookCall { .. } => {
            UnsupportedSemanticsTrigger::HookTopologyDrift
        }
        HookRuleViolation::DepsLengthMismatch { .. } => {
            UnsupportedSemanticsTrigger::DependencyShapeDrift
        }
        HookRuleViolation::HookOutsideRender { .. } => {
            UnsupportedSemanticsTrigger::OutOfRenderHookExecution
        }
    }
}

/// Build deterministic, actionable fallback diagnostics for unsupported cases.
pub fn build_unsupported_semantics_diagnostic(
    component_name: impl Into<String>,
    trigger: UnsupportedSemanticsTrigger,
    trace_id: impl Into<String>,
    decision_id: impl Into<String>,
) -> UnsupportedSemanticsDiagnostic {
    let route = fallback_route_for_trigger(trigger);
    UnsupportedSemanticsDiagnostic {
        schema_version: "franken-engine.hook-effect-unsupported-semantics.v1".to_string(),
        component_name: component_name.into(),
        trigger,
        fallback_route: route,
        compile_path_rejected: true,
        reason: trigger.rejection_reason().to_string(),
        hardening_guidance: trigger.hardening_guidance().to_string(),
        error_code: trigger.stable_error_code().to_string(),
        trace_id: trace_id.into(),
        decision_id: decision_id.into(),
        policy_id: "policy-frx-unsupported-semantics-v1".to_string(),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- HookKind tests ----

    #[test]
    fn hook_kind_all_count() {
        assert_eq!(HookKind::ALL.len(), 15);
    }

    #[test]
    fn hook_kind_all_unique() {
        let set: BTreeSet<_> = HookKind::ALL.iter().collect();
        assert_eq!(set.len(), HookKind::ALL.len());
    }

    #[test]
    fn hook_kind_effect_phase() {
        for kind in HookKind::ALL {
            let expected = matches!(
                kind,
                HookKind::Effect | HookKind::LayoutEffect | HookKind::InsertionEffect
            );
            assert_eq!(kind.has_effect_phase(), expected, "{kind:?}");
        }
    }

    #[test]
    fn hook_kind_can_trigger_rerender() {
        assert!(HookKind::State.can_trigger_rerender());
        assert!(HookKind::Reducer.can_trigger_rerender());
        assert!(HookKind::Context.can_trigger_rerender());
        assert!(HookKind::SyncExternalStore.can_trigger_rerender());
        assert!(!HookKind::Memo.can_trigger_rerender());
        assert!(!HookKind::Ref.can_trigger_rerender());
        assert!(!HookKind::Effect.can_trigger_rerender());
    }

    #[test]
    fn hook_kind_has_dependency_array() {
        assert!(HookKind::Effect.has_dependency_array());
        assert!(HookKind::LayoutEffect.has_dependency_array());
        assert!(HookKind::InsertionEffect.has_dependency_array());
        assert!(HookKind::Memo.has_dependency_array());
        assert!(HookKind::Callback.has_dependency_array());
        assert!(HookKind::ImperativeHandle.has_dependency_array());
        assert!(!HookKind::State.has_dependency_array());
        assert!(!HookKind::Ref.has_dependency_array());
        assert!(!HookKind::Context.has_dependency_array());
    }

    // ---- HookSlot / HookManifest tests ----

    fn make_slot(index: u32, kind: HookKind, deps: Option<Vec<DepToken>>) -> HookSlot {
        HookSlot {
            index: HookSlotIndex(index),
            kind,
            deps,
        }
    }

    #[test]
    fn manifest_valid_simple() {
        let m = HookManifest::new(
            "Counter",
            vec![
                make_slot(0, HookKind::State, None),
                make_slot(1, HookKind::Effect, Some(vec![DepToken(1)])),
            ],
        );
        assert!(m.validate().is_empty());
    }

    #[test]
    fn manifest_empty_is_error() {
        let m = HookManifest::new("Empty", vec![]);
        let errors = m.validate();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0], HookManifestError::EmptyManifest);
    }

    #[test]
    fn manifest_non_consecutive_indices() {
        let m = HookManifest::new(
            "Bad",
            vec![
                make_slot(0, HookKind::State, None),
                make_slot(5, HookKind::Ref, None),
            ],
        );
        let errors = m.validate();
        assert!(errors.iter().any(|e| matches!(
            e,
            HookManifestError::NonConsecutiveIndices {
                expected: 1,
                found: 5,
            }
        )));
    }

    #[test]
    fn manifest_duplicate_index() {
        let m = HookManifest::new(
            "Dup",
            vec![
                make_slot(0, HookKind::State, None),
                make_slot(0, HookKind::Ref, None),
            ],
        );
        let errors = m.validate();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, HookManifestError::DuplicateIndex(HookSlotIndex(0))))
        );
    }

    #[test]
    fn manifest_deps_on_non_dep_hook() {
        let m = HookManifest::new(
            "BadDeps",
            vec![make_slot(0, HookKind::State, Some(vec![DepToken(1)]))],
        );
        let errors = m.validate();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, HookManifestError::DepsOnNonDepHook { .. }))
        );
    }

    #[test]
    fn manifest_derive_id_stable() {
        let m = HookManifest::new("Stable", vec![make_slot(0, HookKind::State, None)]);
        let id1 = m.derive_id();
        let id2 = m.derive_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn manifest_derive_id_differs_by_component() {
        let m1 = HookManifest::new("A", vec![make_slot(0, HookKind::State, None)]);
        let m2 = HookManifest::new("B", vec![make_slot(0, HookKind::State, None)]);
        assert_ne!(m1.derive_id(), m2.derive_id());
    }

    #[test]
    fn manifest_derive_id_distinguishes_none_and_empty_deps() {
        let m1 = HookManifest::new("Deps", vec![make_slot(0, HookKind::Effect, None)]);
        let m2 = HookManifest::new("Deps", vec![make_slot(0, HookKind::Effect, Some(vec![]))]);
        assert_ne!(m1.derive_id(), m2.derive_id());
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let m = HookManifest::new(
            "Counter",
            vec![
                make_slot(0, HookKind::State, None),
                make_slot(1, HookKind::Effect, Some(vec![DepToken(42), DepToken(99)])),
                make_slot(2, HookKind::Memo, Some(vec![])),
            ],
        );
        let json = serde_json::to_string(&m).unwrap();
        let m2: HookManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, m2);
    }

    // ---- RenderPhase tests ----

    #[test]
    fn render_phase_full_cycle() {
        let phases = [
            RenderPhase::Idle,
            RenderPhase::Rendering,
            RenderPhase::InsertionEffectsPending,
            RenderPhase::LayoutEffectsPending,
            RenderPhase::PaintPending,
            RenderPhase::PassiveEffectsPending,
            RenderPhase::Idle,
        ];
        for window in phases.windows(2) {
            assert!(
                window[0].can_transition_to(window[1]),
                "{:?} -> {:?} should be legal",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn render_phase_illegal_transitions() {
        // Cannot skip phases
        assert!(!RenderPhase::Rendering.can_transition_to(RenderPhase::PaintPending));
        assert!(!RenderPhase::Idle.can_transition_to(RenderPhase::PassiveEffectsPending));
        // Cannot go backwards
        assert!(!RenderPhase::PaintPending.can_transition_to(RenderPhase::Rendering));
        // Unmounting is terminal
        assert!(RenderPhase::Unmounting.legal_successors().is_empty());
    }

    #[test]
    fn render_phase_idle_can_unmount() {
        assert!(RenderPhase::Idle.can_transition_to(RenderPhase::Unmounting));
    }

    #[test]
    fn render_phase_serde_roundtrip() {
        for phase in &[
            RenderPhase::Rendering,
            RenderPhase::InsertionEffectsPending,
            RenderPhase::LayoutEffectsPending,
            RenderPhase::PaintPending,
            RenderPhase::PassiveEffectsPending,
            RenderPhase::Idle,
            RenderPhase::Unmounting,
        ] {
            let json = serde_json::to_string(phase).unwrap();
            let p2: RenderPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(*phase, p2);
        }
    }

    // ---- EffectTiming tests ----

    #[test]
    fn effect_timing_execution_phases() {
        assert_eq!(
            EffectTiming::Insertion.execution_phase(),
            RenderPhase::InsertionEffectsPending
        );
        assert_eq!(
            EffectTiming::Layout.execution_phase(),
            RenderPhase::LayoutEffectsPending
        );
        assert_eq!(
            EffectTiming::Passive.execution_phase(),
            RenderPhase::PassiveEffectsPending
        );
    }

    #[test]
    fn effect_timing_scheduling_order() {
        assert!(
            EffectTiming::Insertion.scheduling_order() < EffectTiming::Layout.scheduling_order()
        );
        assert!(EffectTiming::Layout.scheduling_order() < EffectTiming::Passive.scheduling_order());
    }

    // ---- EffectScheduler tests ----

    #[test]
    fn scheduler_empty() {
        let s = EffectScheduler::new();
        assert_eq!(s.pending_count(), 0);
    }

    fn make_effect(
        component: &str,
        slot: u32,
        timing: EffectTiming,
        tree_order: u64,
        is_cleanup: bool,
    ) -> PendingEffect {
        PendingEffect {
            component_name: component.to_string(),
            hook_index: HookSlotIndex(slot),
            timing,
            tree_order,
            is_cleanup,
        }
    }

    #[test]
    fn scheduler_drain_for_timing_separates_cleanup_and_create() {
        let mut s = EffectScheduler::new();
        s.enqueue(make_effect("A", 0, EffectTiming::Passive, 2, false));
        s.enqueue(make_effect("A", 0, EffectTiming::Passive, 1, true));
        s.enqueue(make_effect("B", 1, EffectTiming::Passive, 3, false));

        let (cleanups, creates) = s.drain_for_timing(EffectTiming::Passive);
        assert_eq!(cleanups.len(), 1);
        assert!(cleanups[0].is_cleanup);
        assert_eq!(creates.len(), 2);
        assert!(!creates[0].is_cleanup);
        assert!(!creates[1].is_cleanup);
    }

    #[test]
    fn scheduler_drain_for_timing_tree_order() {
        let mut s = EffectScheduler::new();
        s.enqueue(make_effect("C", 0, EffectTiming::Layout, 3, false));
        s.enqueue(make_effect("A", 0, EffectTiming::Layout, 1, false));
        s.enqueue(make_effect("B", 0, EffectTiming::Layout, 2, false));

        let (_, creates) = s.drain_for_timing(EffectTiming::Layout);
        assert_eq!(creates[0].tree_order, 1);
        assert_eq!(creates[1].tree_order, 2);
        assert_eq!(creates[2].tree_order, 3);
    }

    #[test]
    fn scheduler_drain_for_timing_does_not_drain_other_timings() {
        let mut s = EffectScheduler::new();
        s.enqueue(make_effect("A", 0, EffectTiming::Layout, 1, false));
        s.enqueue(make_effect("B", 0, EffectTiming::Passive, 2, false));

        let (c, r) = s.drain_for_timing(EffectTiming::Layout);
        assert_eq!(c.len() + r.len(), 1);
        assert_eq!(s.pending_count(), 1);
    }

    #[test]
    fn scheduler_drain_all_ordered() {
        let mut s = EffectScheduler::new();
        // Add effects in reverse timing order
        s.enqueue(make_effect("A", 0, EffectTiming::Passive, 1, false));
        s.enqueue(make_effect("B", 0, EffectTiming::Layout, 2, true));
        s.enqueue(make_effect("C", 0, EffectTiming::Insertion, 3, false));
        s.enqueue(make_effect("D", 0, EffectTiming::Insertion, 1, true));

        let all = s.drain_all_ordered();
        assert_eq!(all.len(), 4);
        // Insertion first (cleanup before create)
        assert_eq!(all[0].timing, EffectTiming::Insertion);
        assert!(all[0].is_cleanup); // D cleanup, tree_order=1
        assert_eq!(all[1].timing, EffectTiming::Insertion);
        assert!(!all[1].is_cleanup); // C create, tree_order=3
        // Layout
        assert_eq!(all[2].timing, EffectTiming::Layout);
        // Passive
        assert_eq!(all[3].timing, EffectTiming::Passive);
    }

    #[test]
    fn scheduler_default_is_empty() {
        let s = EffectScheduler::default();
        assert_eq!(s.pending_count(), 0);
    }

    // ---- DepsChange tests ----

    #[test]
    fn compare_deps_none_none() {
        assert_eq!(compare_deps(None, None), DepsChange::AlwaysRun);
    }

    #[test]
    fn compare_deps_none_current() {
        assert_eq!(
            compare_deps(None, Some(&[DepToken(1)])),
            DepsChange::Changed
        );
    }

    #[test]
    fn compare_deps_none_empty_current() {
        assert_eq!(compare_deps(None, Some(&[])), DepsChange::MountOnly);
    }

    #[test]
    fn compare_deps_some_none() {
        assert_eq!(
            compare_deps(Some(&[DepToken(1)]), None),
            DepsChange::AlwaysRun
        );
    }

    #[test]
    fn compare_deps_unchanged() {
        let deps = [DepToken(1), DepToken(2)];
        assert_eq!(
            compare_deps(Some(&deps), Some(&deps)),
            DepsChange::Unchanged
        );
    }

    #[test]
    fn compare_deps_changed_values() {
        assert_eq!(
            compare_deps(Some(&[DepToken(1)]), Some(&[DepToken(2)])),
            DepsChange::Changed
        );
    }

    #[test]
    fn compare_deps_changed_length() {
        assert_eq!(
            compare_deps(Some(&[DepToken(1)]), Some(&[DepToken(1), DepToken(2)])),
            DepsChange::Changed
        );
    }

    #[test]
    fn compare_deps_empty_is_mount_only() {
        assert_eq!(
            compare_deps(Some(&[DepToken(1)]), Some(&[])),
            DepsChange::MountOnly
        );
    }

    // ---- HookRuleViolation tests ----

    #[test]
    fn validate_consistency_matching_manifests() {
        let m = HookManifest::new(
            "App",
            vec![
                make_slot(0, HookKind::State, None),
                make_slot(1, HookKind::Effect, Some(vec![DepToken(1)])),
            ],
        );
        let violations = validate_hook_consistency(&m, &m);
        assert!(violations.is_empty());
    }

    #[test]
    fn validate_consistency_count_mismatch() {
        let prev = HookManifest::new("App", vec![make_slot(0, HookKind::State, None)]);
        let curr = HookManifest::new(
            "App",
            vec![
                make_slot(0, HookKind::State, None),
                make_slot(1, HookKind::Ref, None),
            ],
        );
        let violations = validate_hook_consistency(&prev, &curr);
        assert!(violations.iter().any(|v| matches!(
            v,
            HookRuleViolation::HookCountMismatch {
                previous_count: 1,
                current_count: 2,
                ..
            }
        )));
    }

    #[test]
    fn validate_consistency_kind_mismatch() {
        let prev = HookManifest::new("App", vec![make_slot(0, HookKind::State, None)]);
        let curr = HookManifest::new("App", vec![make_slot(0, HookKind::Ref, None)]);
        let violations = validate_hook_consistency(&prev, &curr);
        assert!(violations.iter().any(|v| matches!(
            v,
            HookRuleViolation::HookKindMismatch {
                previous_kind: HookKind::State,
                current_kind: HookKind::Ref,
                ..
            }
        )));
    }

    #[test]
    fn validate_consistency_deps_length_mismatch() {
        let prev = HookManifest::new(
            "App",
            vec![make_slot(0, HookKind::Effect, Some(vec![DepToken(1)]))],
        );
        let curr = HookManifest::new(
            "App",
            vec![make_slot(
                0,
                HookKind::Effect,
                Some(vec![DepToken(1), DepToken(2)]),
            )],
        );
        let violations = validate_hook_consistency(&prev, &curr);
        assert!(violations.iter().any(|v| matches!(
            v,
            HookRuleViolation::DepsLengthMismatch {
                previous_len: 1,
                current_len: 2,
                ..
            }
        )));
    }

    // ---- LegalTransformation tests ----

    #[test]
    fn legal_transformation_all_count() {
        assert_eq!(LegalTransformation::ALL.len(), 8);
    }

    #[test]
    fn legal_transformation_all_unique() {
        let set: BTreeSet<_> = LegalTransformation::ALL.iter().collect();
        assert_eq!(set.len(), LegalTransformation::ALL.len());
    }

    #[test]
    fn legal_transformation_applicable_hooks_non_empty() {
        for t in LegalTransformation::ALL {
            assert!(!t.applicable_hooks().is_empty(), "{t:?}");
        }
    }

    #[test]
    fn effect_elision_applies_to_all_effect_kinds() {
        let hooks = LegalTransformation::EffectElision.applicable_hooks();
        assert!(hooks.contains(&HookKind::Effect));
        assert!(hooks.contains(&HookKind::LayoutEffect));
        assert!(hooks.contains(&HookKind::InsertionEffect));
    }

    #[test]
    fn unconditional_transforms() {
        assert!(LegalTransformation::ContextDedup.is_unconditional());
        assert!(LegalTransformation::StateBatch.is_unconditional());
        assert!(!LegalTransformation::MemoConstantFold.is_unconditional());
    }

    #[test]
    fn memo_reorder_does_not_preserve_effect_order() {
        assert!(!LegalTransformation::MemoReorder.preserves_effect_order());
    }

    #[test]
    fn transformation_receipt_derive_id_stable() {
        let r = TransformationReceipt {
            transformation: LegalTransformation::MemoConstantFold,
            component_name: "App".into(),
            target_slots: vec![HookSlotIndex(0)],
            precondition_met: true,
            reason: "all deps constant".into(),
        };
        assert_eq!(r.derive_id(), r.derive_id());
    }

    #[test]
    fn transformation_receipt_serde_roundtrip() {
        let r = TransformationReceipt {
            transformation: LegalTransformation::StateBatch,
            component_name: "Counter".into(),
            target_slots: vec![HookSlotIndex(0), HookSlotIndex(1)],
            precondition_met: true,
            reason: "adjacent setState".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let r2: TransformationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(r, r2);
    }

    // ---- PhaseTransition tests ----

    #[test]
    fn phase_transition_valid() {
        let t = PhaseTransition {
            component_name: "App".into(),
            from: RenderPhase::Idle,
            to: RenderPhase::Rendering,
            sequence_number: 0,
        };
        assert!(t.validate().is_ok());
    }

    #[test]
    fn phase_transition_invalid() {
        let t = PhaseTransition {
            component_name: "App".into(),
            from: RenderPhase::Idle,
            to: RenderPhase::PaintPending,
            sequence_number: 0,
        };
        assert!(matches!(
            t.validate(),
            Err(PhaseTransitionError::IllegalTransition { .. })
        ));
    }

    #[test]
    fn phase_transition_derive_id_stable() {
        let t = PhaseTransition {
            component_name: "App".into(),
            from: RenderPhase::Idle,
            to: RenderPhase::Rendering,
            sequence_number: 0,
        };
        assert_eq!(t.derive_id(), t.derive_id());
    }

    // ---- ComponentPhaseTracker tests ----

    #[test]
    fn tracker_starts_idle() {
        let t = ComponentPhaseTracker::new("App");
        assert_eq!(t.current_phase, RenderPhase::Idle);
        assert_eq!(t.render_count, 0);
    }

    #[test]
    fn tracker_full_cycle() {
        let mut t = ComponentPhaseTracker::new("App");
        assert!(t.run_full_cycle().is_ok());
        assert_eq!(t.current_phase, RenderPhase::Idle);
        assert_eq!(t.render_count, 1);
        assert_eq!(t.transition_log.len(), 6);
    }

    #[test]
    fn tracker_double_cycle() {
        let mut t = ComponentPhaseTracker::new("App");
        assert!(t.run_full_cycle().is_ok());
        assert!(t.run_full_cycle().is_ok());
        assert_eq!(t.render_count, 2);
        assert_eq!(t.transition_log.len(), 12);
    }

    #[test]
    fn tracker_illegal_transition_rejected() {
        let mut t = ComponentPhaseTracker::new("App");
        let result = t.transition_to(RenderPhase::PaintPending);
        assert!(result.is_err());
        assert_eq!(t.current_phase, RenderPhase::Idle);
    }

    #[test]
    fn tracker_unmount_from_idle() {
        let mut t = ComponentPhaseTracker::new("App");
        assert!(t.transition_to(RenderPhase::Unmounting).is_ok());
        assert_eq!(t.current_phase, RenderPhase::Unmounting);
    }

    #[test]
    fn tracker_unmount_is_terminal() {
        let mut t = ComponentPhaseTracker::new("App");
        t.transition_to(RenderPhase::Unmounting).unwrap();
        assert!(t.transition_to(RenderPhase::Idle).is_err());
        assert!(t.transition_to(RenderPhase::Rendering).is_err());
    }

    #[test]
    fn tracker_serde_roundtrip() {
        let mut t = ComponentPhaseTracker::new("Counter");
        t.run_full_cycle().unwrap();
        let json = serde_json::to_string(&t).unwrap();
        let t2: ComponentPhaseTracker = serde_json::from_str(&json).unwrap();
        assert_eq!(t, t2);
    }

    // ---- SchedulingBoundary tests ----

    #[test]
    fn canonical_boundaries_count() {
        assert_eq!(SchedulingBoundary::canonical_boundaries().len(), 3);
    }

    #[test]
    fn insertion_is_synchronous_no_dom() {
        let bounds = SchedulingBoundary::canonical_boundaries();
        let insertion = bounds
            .iter()
            .find(|b| b.timing == EffectTiming::Insertion)
            .unwrap();
        assert!(insertion.synchronous);
        assert!(!insertion.dom_mutations_visible);
    }

    #[test]
    fn layout_is_synchronous_with_dom() {
        let bounds = SchedulingBoundary::canonical_boundaries();
        let layout = bounds
            .iter()
            .find(|b| b.timing == EffectTiming::Layout)
            .unwrap();
        assert!(layout.synchronous);
        assert!(layout.dom_mutations_visible);
    }

    #[test]
    fn passive_is_async_with_dom() {
        let bounds = SchedulingBoundary::canonical_boundaries();
        let passive = bounds
            .iter()
            .find(|b| b.timing == EffectTiming::Passive)
            .unwrap();
        assert!(!passive.synchronous);
        assert!(passive.dom_mutations_visible);
    }

    #[test]
    fn all_boundaries_batch_state_updates() {
        for b in SchedulingBoundary::canonical_boundaries() {
            assert!(b.state_updates_batched, "{:?}", b.timing);
        }
    }

    #[test]
    fn scheduling_boundary_serde_roundtrip() {
        let bounds = SchedulingBoundary::canonical_boundaries();
        let json = serde_json::to_string(&bounds).unwrap();
        let b2: Vec<SchedulingBoundary> = serde_json::from_str(&json).unwrap();
        assert_eq!(bounds, b2);
    }

    // ---- HookEffectContract tests ----

    #[test]
    fn contract_new_defaults() {
        let c = HookEffectContract::new();
        assert_eq!(c.manifests.len(), 0);
        assert_eq!(c.scheduling_boundaries.len(), 3);
        assert!(c.approved_transformations.is_empty());
        assert_eq!(c.version, 1);
    }

    #[test]
    fn contract_register_manifest() {
        let mut c = HookEffectContract::new();
        let m = HookManifest::new(
            "App",
            vec![
                make_slot(0, HookKind::State, None),
                make_slot(1, HookKind::Effect, Some(vec![DepToken(1)])),
            ],
        );
        c.register_manifest(m);
        assert_eq!(c.manifests.len(), 1);
        assert_eq!(c.total_hook_count(), 2);
        assert_eq!(c.effect_hook_count(), 1);
    }

    #[test]
    fn contract_approve_transformation() {
        let mut c = HookEffectContract::new();
        c.approve_transformation(LegalTransformation::StateBatch);
        c.approve_transformation(LegalTransformation::MemoConstantFold);
        assert_eq!(c.approved_transformations.len(), 2);
    }

    #[test]
    fn contract_validate_all_clean() {
        let mut c = HookEffectContract::new();
        c.register_manifest(HookManifest::new(
            "App",
            vec![make_slot(0, HookKind::State, None)],
        ));
        assert!(c.validate_all().is_empty());
    }

    #[test]
    fn contract_validate_all_catches_errors() {
        let mut c = HookEffectContract::new();
        c.register_manifest(HookManifest::new("Bad", vec![]));
        let results = c.validate_all();
        assert!(results.contains_key("Bad"));
    }

    #[test]
    fn contract_derive_id_stable() {
        let mut c = HookEffectContract::new();
        c.register_manifest(HookManifest::new(
            "App",
            vec![make_slot(0, HookKind::State, None)],
        ));
        assert_eq!(c.derive_id(), c.derive_id());
    }

    #[test]
    fn contract_derive_id_differs_by_manifest_details() {
        let mut c1 = HookEffectContract::new();
        c1.register_manifest(HookManifest::new(
            "App",
            vec![make_slot(0, HookKind::State, None)],
        ));

        let mut c2 = HookEffectContract::new();
        c2.register_manifest(HookManifest::new(
            "App",
            vec![make_slot(0, HookKind::Effect, Some(vec![DepToken(1)]))],
        ));

        assert_ne!(c1.derive_id(), c2.derive_id());
    }

    #[test]
    fn contract_serde_roundtrip() {
        let mut c = HookEffectContract::new();
        c.register_manifest(HookManifest::new(
            "Counter",
            vec![
                make_slot(0, HookKind::State, None),
                make_slot(1, HookKind::Effect, Some(vec![DepToken(1)])),
                make_slot(2, HookKind::Memo, Some(vec![DepToken(1), DepToken(2)])),
            ],
        ));
        c.approve_transformation(LegalTransformation::MemoConstantFold);
        let json = serde_json::to_string(&c).unwrap();
        let c2: HookEffectContract = serde_json::from_str(&json).unwrap();
        assert_eq!(c, c2);
    }

    #[test]
    fn contract_default_is_new() {
        let c1 = HookEffectContract::new();
        let c2 = HookEffectContract::default();
        assert_eq!(c1, c2);
    }

    // ---- Multi-component contract tests ----

    #[test]
    fn contract_multi_component_counts() {
        let mut c = HookEffectContract::new();
        c.register_manifest(HookManifest::new(
            "App",
            vec![
                make_slot(0, HookKind::State, None),
                make_slot(1, HookKind::Effect, Some(vec![])),
            ],
        ));
        c.register_manifest(HookManifest::new(
            "Header",
            vec![
                make_slot(0, HookKind::Context, None),
                make_slot(1, HookKind::LayoutEffect, Some(vec![DepToken(1)])),
                make_slot(2, HookKind::Ref, None),
            ],
        ));
        assert_eq!(c.manifests.len(), 2);
        assert_eq!(c.total_hook_count(), 5);
        assert_eq!(c.effect_hook_count(), 2); // Effect + LayoutEffect
    }

    // ---- Effect derive_id tests ----

    #[test]
    fn pending_effect_derive_id_stable() {
        let e = make_effect("App", 0, EffectTiming::Passive, 1, false);
        assert_eq!(e.derive_id(), e.derive_id());
    }

    #[test]
    fn pending_effect_derive_id_differs_by_cleanup() {
        let e1 = make_effect("App", 0, EffectTiming::Passive, 1, false);
        let e2 = make_effect("App", 0, EffectTiming::Passive, 1, true);
        assert_ne!(e1.derive_id(), e2.derive_id());
    }

    #[test]
    fn pending_effect_serde_roundtrip() {
        let e = make_effect("Counter", 2, EffectTiming::Layout, 42, true);
        let json = serde_json::to_string(&e).unwrap();
        let e2: PendingEffect = serde_json::from_str(&json).unwrap();
        assert_eq!(e, e2);
    }

    // ---- End-to-end pipeline test ----

    #[test]
    fn end_to_end_render_cycle_with_effects() {
        // 1. Define manifests
        let app_manifest = HookManifest::new(
            "App",
            vec![
                make_slot(0, HookKind::State, None),
                make_slot(1, HookKind::Effect, Some(vec![DepToken(1)])),
                make_slot(2, HookKind::LayoutEffect, Some(vec![DepToken(1)])),
                make_slot(3, HookKind::InsertionEffect, Some(vec![])),
            ],
        );
        assert!(app_manifest.validate().is_empty());

        // 2. Register in contract
        let mut contract = HookEffectContract::new();
        contract.register_manifest(app_manifest.clone());
        assert_eq!(contract.effect_hook_count(), 3);

        // 3. Schedule effects
        let mut scheduler = EffectScheduler::new();
        scheduler.enqueue(make_effect("App", 3, EffectTiming::Insertion, 1, false));
        scheduler.enqueue(make_effect("App", 2, EffectTiming::Layout, 1, false));
        scheduler.enqueue(make_effect("App", 1, EffectTiming::Passive, 1, false));

        // 4. Run phase tracker
        let mut tracker = ComponentPhaseTracker::new("App");
        tracker.transition_to(RenderPhase::Rendering).unwrap();
        tracker
            .transition_to(RenderPhase::InsertionEffectsPending)
            .unwrap();

        // Drain insertion effects
        let (c, r) = scheduler.drain_for_timing(EffectTiming::Insertion);
        assert_eq!(c.len() + r.len(), 1);

        tracker
            .transition_to(RenderPhase::LayoutEffectsPending)
            .unwrap();
        let (c, r) = scheduler.drain_for_timing(EffectTiming::Layout);
        assert_eq!(c.len() + r.len(), 1);

        tracker.transition_to(RenderPhase::PaintPending).unwrap();
        tracker
            .transition_to(RenderPhase::PassiveEffectsPending)
            .unwrap();
        let (c, r) = scheduler.drain_for_timing(EffectTiming::Passive);
        assert_eq!(c.len() + r.len(), 1);

        tracker.transition_to(RenderPhase::Idle).unwrap();
        assert_eq!(tracker.render_count, 1);
        assert_eq!(scheduler.pending_count(), 0);
    }

    #[test]
    fn end_to_end_re_render_with_dep_check() {
        let prev = HookManifest::new(
            "Counter",
            vec![
                make_slot(0, HookKind::State, None),
                make_slot(1, HookKind::Effect, Some(vec![DepToken(1)])),
            ],
        );
        let curr = HookManifest::new(
            "Counter",
            vec![
                make_slot(0, HookKind::State, None),
                make_slot(1, HookKind::Effect, Some(vec![DepToken(2)])),
            ],
        );

        // Validate consistency
        let violations = validate_hook_consistency(&prev, &curr);
        assert!(violations.is_empty());

        // Check deps changed
        let prev_deps = prev.slots[1].deps.as_deref();
        let curr_deps = curr.slots[1].deps.as_deref();
        assert_eq!(compare_deps(prev_deps, curr_deps), DepsChange::Changed);
    }

    #[test]
    fn end_to_end_transformation_audit_trail() {
        let mut contract = HookEffectContract::new();
        contract.register_manifest(HookManifest::new(
            "App",
            vec![
                make_slot(0, HookKind::State, None),
                make_slot(1, HookKind::State, None),
                make_slot(2, HookKind::Memo, Some(vec![DepToken(1)])),
            ],
        ));
        contract.approve_transformation(LegalTransformation::StateBatch);

        let receipt = TransformationReceipt {
            transformation: LegalTransformation::StateBatch,
            component_name: "App".into(),
            target_slots: vec![HookSlotIndex(0), HookSlotIndex(1)],
            precondition_met: true,
            reason: "adjacent useState calls".into(),
        };
        assert!(
            contract
                .approved_transformations
                .contains(&receipt.transformation)
        );

        // Verify receipt has stable ID
        let id = receipt.derive_id();
        assert_eq!(id, receipt.derive_id());
    }

    #[test]
    fn transformation_receipt_derive_id_differs_by_reason() {
        let receipt = TransformationReceipt {
            transformation: LegalTransformation::StateBatch,
            component_name: "App".into(),
            target_slots: vec![HookSlotIndex(0), HookSlotIndex(1)],
            precondition_met: true,
            reason: "adjacent useState calls".into(),
        };
        let mut changed_reason = receipt.clone();
        changed_reason.reason = "proof omitted".into();
        assert_ne!(receipt.derive_id(), changed_reason.derive_id());
    }

    // ---- Unsupported semantics + fallback tests ----

    #[test]
    fn classify_unsupported_semantics_from_hook_violations() {
        let mismatch = HookRuleViolation::HookCountMismatch {
            component: "App".into(),
            previous_count: 3,
            current_count: 2,
        };
        let deps = HookRuleViolation::DepsLengthMismatch {
            component: "App".into(),
            slot: HookSlotIndex(1),
            previous_len: 2,
            current_len: 1,
        };
        let outside = HookRuleViolation::HookOutsideRender {
            component: "App".into(),
            slot: HookSlotIndex(1),
            actual_phase: RenderPhase::Idle,
        };

        assert_eq!(
            classify_unsupported_semantics(&mismatch),
            UnsupportedSemanticsTrigger::HookTopologyDrift
        );
        assert_eq!(
            classify_unsupported_semantics(&deps),
            UnsupportedSemanticsTrigger::DependencyShapeDrift
        );
        assert_eq!(
            classify_unsupported_semantics(&outside),
            UnsupportedSemanticsTrigger::OutOfRenderHookExecution
        );
    }

    #[test]
    fn fallback_routes_are_deterministic_for_each_trigger() {
        for trigger in [
            UnsupportedSemanticsTrigger::HookTopologyDrift,
            UnsupportedSemanticsTrigger::DependencyShapeDrift,
            UnsupportedSemanticsTrigger::OutOfRenderHookExecution,
            UnsupportedSemanticsTrigger::SchedulerOrderingAmbiguity,
            UnsupportedSemanticsTrigger::UnsupportedHookPrimitive,
            UnsupportedSemanticsTrigger::TransformationProofMissing,
        ] {
            assert_eq!(
                fallback_route_for_trigger(trigger),
                fallback_route_for_trigger(trigger)
            );
            assert!(!trigger.stable_error_code().is_empty());
            assert!(!trigger.rejection_reason().is_empty());
            assert!(!trigger.hardening_guidance().is_empty());
        }
    }

    #[test]
    fn build_unsupported_semantics_diagnostic_is_actionable_and_stable() {
        let diagnostic = build_unsupported_semantics_diagnostic(
            "Counter",
            UnsupportedSemanticsTrigger::TransformationProofMissing,
            "trace-1",
            "decision-1",
        );

        assert_eq!(
            diagnostic.schema_version,
            "franken-engine.hook-effect-unsupported-semantics.v1"
        );
        assert!(diagnostic.compile_path_rejected);
        assert_eq!(
            diagnostic.fallback_route,
            FallbackExecutionRoute::BaselineInterpreterLane
        );
        assert_eq!(diagnostic.error_code, "FE-HOOK-UNSUPPORTED-0006");
        assert!(!diagnostic.reason.is_empty());
        assert!(!diagnostic.hardening_guidance.is_empty());
        assert_eq!(diagnostic.derive_id(), diagnostic.derive_id());
    }

    #[test]
    fn unsupported_semantics_diagnostic_derive_id_differs_by_trace_context() {
        let diagnostic = build_unsupported_semantics_diagnostic(
            "Counter",
            UnsupportedSemanticsTrigger::TransformationProofMissing,
            "trace-1",
            "decision-1",
        );
        let mut changed_context = diagnostic.clone();
        changed_context.trace_id = "trace-2".into();
        assert_ne!(diagnostic.derive_id(), changed_context.derive_id());
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn hook_kind_serde_all_variants() {
        for kind in HookKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: HookKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn hook_kind_all_has_fifteen_entries() {
        assert_eq!(HookKind::ALL.len(), 15);
    }

    #[test]
    fn render_phase_serde_all_variants() {
        let variants = [
            RenderPhase::Rendering,
            RenderPhase::InsertionEffectsPending,
            RenderPhase::LayoutEffectsPending,
            RenderPhase::PaintPending,
            RenderPhase::PassiveEffectsPending,
            RenderPhase::Idle,
            RenderPhase::Unmounting,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: RenderPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn effect_timing_serde_all_variants() {
        let variants = [
            EffectTiming::Insertion,
            EffectTiming::Layout,
            EffectTiming::Passive,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: EffectTiming = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn unsupported_semantics_trigger_serde_all_variants() {
        let variants = [
            UnsupportedSemanticsTrigger::HookTopologyDrift,
            UnsupportedSemanticsTrigger::DependencyShapeDrift,
            UnsupportedSemanticsTrigger::OutOfRenderHookExecution,
            UnsupportedSemanticsTrigger::SchedulerOrderingAmbiguity,
            UnsupportedSemanticsTrigger::UnsupportedHookPrimitive,
            UnsupportedSemanticsTrigger::TransformationProofMissing,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: UnsupportedSemanticsTrigger = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn unsupported_semantics_trigger_error_code_distinct() {
        let variants = [
            UnsupportedSemanticsTrigger::HookTopologyDrift,
            UnsupportedSemanticsTrigger::DependencyShapeDrift,
            UnsupportedSemanticsTrigger::OutOfRenderHookExecution,
            UnsupportedSemanticsTrigger::SchedulerOrderingAmbiguity,
            UnsupportedSemanticsTrigger::UnsupportedHookPrimitive,
            UnsupportedSemanticsTrigger::TransformationProofMissing,
        ];
        let set: std::collections::BTreeSet<&str> =
            variants.iter().map(|t| t.stable_error_code()).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn effect_timing_scheduling_order_monotonic() {
        assert!(
            EffectTiming::Insertion.scheduling_order() < EffectTiming::Layout.scheduling_order()
        );
        assert!(EffectTiming::Layout.scheduling_order() < EffectTiming::Passive.scheduling_order());
    }

    #[test]
    fn render_phase_unmounting_has_no_successors() {
        assert!(RenderPhase::Unmounting.legal_successors().is_empty());
    }
}
