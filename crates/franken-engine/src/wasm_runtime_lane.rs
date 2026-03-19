//! WASM Runtime Lane (FRX-04.2)
//!
//! High-performance signal graph and deterministic scheduler designed for
//! compilation to WASM. Targets large/high-churn workloads with:
//! - Bounded queues and deterministic topological propagation.
//! - Efficient JS↔WASM ABI for state updates and DOM op emission.
//! - Deterministic safe mode when resource budgets are exceeded.

use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

fn wasm_schema() -> SchemaId {
    SchemaId::from_definition(b"wasm_runtime_lane-v1")
}

// ---------------------------------------------------------------------------
// WASM-targeted signal node (compact representation)
// ---------------------------------------------------------------------------

/// Compact signal identifier for WASM linear memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WasmSignalId(pub u32);

/// Signal kind in the WASM lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum WasmSignalKind {
    Source,
    Derived,
    Effect,
}

/// Evaluation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum WasmSignalStatus {
    Clean,
    Dirty,
    Evaluating,
    Disposed,
}

/// Compact signal node for WASM linear memory layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmSignalNode {
    pub id: WasmSignalId,
    pub kind: WasmSignalKind,
    pub status: WasmSignalStatus,
    pub depth: u16,
    pub generation: u32,
    pub dependencies: BTreeSet<WasmSignalId>,
    pub dependents: BTreeSet<WasmSignalId>,
}

// ---------------------------------------------------------------------------
// Bounded queue
// ---------------------------------------------------------------------------

/// Bounded FIFO queue that enforces a capacity limit.
/// When full, new pushes are rejected (not dropped).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedQueue<T> {
    items: VecDeque<T>,
    capacity: u32,
}

/// Errors from bounded queue operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueError {
    Full { capacity: u32 },
    Empty,
}

impl<T> BoundedQueue<T> {
    pub fn new(capacity: u32) -> Self {
        Self {
            items: VecDeque::with_capacity(capacity as usize),
            capacity,
        }
    }

    pub fn push(&mut self, item: T) -> Result<(), QueueError> {
        if self.items.len() >= self.capacity as usize {
            return Err(QueueError::Full {
                capacity: self.capacity,
            });
        }
        self.items.push_back(item);
        Ok(())
    }

    pub fn pop(&mut self) -> Result<T, QueueError> {
        self.items.pop_front().ok_or(QueueError::Empty)
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.items.len() >= self.capacity as usize
    }

    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    pub fn drain_all(&mut self) -> Vec<T> {
        self.items.drain(..).collect()
    }

    pub fn clear(&mut self) {
        self.items.clear();
    }
}

// ---------------------------------------------------------------------------
// WASM signal graph
// ---------------------------------------------------------------------------

/// Errors from WASM signal graph operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmGraphError {
    NotFound(WasmSignalId),
    Disposed(WasmSignalId),
    DuplicateSignal(WasmSignalId),
    DepNotFound(WasmSignalId),
    DepthExceeded {
        signal: WasmSignalId,
        depth: u16,
        max: u16,
    },
    BudgetExceeded {
        metric: String,
        current: u64,
        limit: u64,
    },
}

/// WASM-optimised reactive signal graph with bounded resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmSignalGraph {
    nodes: BTreeMap<WasmSignalId, WasmSignalNode>,
    next_id: u32,
    generation: u32,
    pub max_depth: u16,
    pub max_nodes: u32,
}

impl WasmSignalGraph {
    pub fn new(max_depth: u16, max_nodes: u32) -> Self {
        Self {
            nodes: BTreeMap::new(),
            next_id: 0,
            generation: 0,
            max_depth,
            max_nodes,
        }
    }

    pub fn next_id(&mut self) -> WasmSignalId {
        let id = WasmSignalId(self.next_id);
        self.next_id += 1;
        id
    }

    pub fn active_count(&self) -> usize {
        self.nodes
            .values()
            .filter(|n| n.status != WasmSignalStatus::Disposed)
            .count()
    }

    /// Register a new signal node with bounded checks.
    pub fn register(
        &mut self,
        id: WasmSignalId,
        kind: WasmSignalKind,
        deps: BTreeSet<WasmSignalId>,
    ) -> Result<(), WasmGraphError> {
        if self.nodes.contains_key(&id) {
            return Err(WasmGraphError::DuplicateSignal(id));
        }
        if self.active_count() as u32 >= self.max_nodes {
            return Err(WasmGraphError::BudgetExceeded {
                metric: "nodes".into(),
                current: self.active_count() as u64,
                limit: self.max_nodes as u64,
            });
        }

        for dep in &deps {
            if !self.nodes.contains_key(dep) {
                return Err(WasmGraphError::DepNotFound(*dep));
            }
        }

        let depth = if deps.is_empty() {
            0
        } else {
            let max_dep_depth = deps
                .iter()
                .filter_map(|d| self.nodes.get(d))
                .map(|n| n.depth)
                .max()
                .unwrap_or(0);
            max_dep_depth + 1
        };

        if depth > self.max_depth {
            return Err(WasmGraphError::DepthExceeded {
                signal: id,
                depth,
                max: self.max_depth,
            });
        }

        for dep in &deps {
            if let Some(dep_node) = self.nodes.get_mut(dep) {
                dep_node.dependents.insert(id);
            }
        }

        self.nodes.insert(
            id,
            WasmSignalNode {
                id,
                kind,
                status: WasmSignalStatus::Dirty,
                depth,
                generation: self.generation,
                dependencies: deps,
                dependents: BTreeSet::new(),
            },
        );
        Ok(())
    }

    /// Mark dirty and propagate. Returns dirty list in topological order.
    pub fn propagate_dirty(
        &mut self,
        source: WasmSignalId,
    ) -> Result<Vec<WasmSignalId>, WasmGraphError> {
        if !self.nodes.contains_key(&source) {
            return Err(WasmGraphError::NotFound(source));
        }
        if self.nodes[&source].status == WasmSignalStatus::Disposed {
            return Err(WasmGraphError::Disposed(source));
        }

        self.generation = self.generation.wrapping_add(1);
        let target_gen = self.generation;

        let mut dirty = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(source);

        while let Some(current) = queue.pop_front() {
            if let Some(node) = self.nodes.get_mut(&current) {
                if node.generation == target_gen {
                    continue;
                }
                node.status = WasmSignalStatus::Dirty;
                node.generation = target_gen;
                dirty.push(current);
                let dependents: Vec<_> = node.dependents.iter().copied().collect();
                for d in dependents {
                    queue.push_back(d);
                }
            }
        }

        dirty.sort_by_key(|id| self.nodes.get(id).map_or(0, |n| n.depth));
        Ok(dirty)
    }

    pub fn mark_clean(&mut self, id: WasmSignalId) -> Result<(), WasmGraphError> {
        let node = self
            .nodes
            .get_mut(&id)
            .ok_or(WasmGraphError::NotFound(id))?;
        if node.status == WasmSignalStatus::Disposed {
            return Err(WasmGraphError::Disposed(id));
        }
        node.status = WasmSignalStatus::Clean;
        Ok(())
    }

    pub fn dispose(&mut self, id: WasmSignalId) -> Result<(), WasmGraphError> {
        let node = self
            .nodes
            .get(&id)
            .ok_or(WasmGraphError::NotFound(id))?
            .clone();

        for dep in &node.dependencies {
            if let Some(dep_node) = self.nodes.get_mut(dep) {
                dep_node.dependents.remove(&id);
            }
        }
        for dependent in &node.dependents {
            if let Some(dep_node) = self.nodes.get_mut(dependent) {
                dep_node.dependencies.remove(&id);
            }
        }

        if let Some(n) = self.nodes.get_mut(&id) {
            n.status = WasmSignalStatus::Disposed;
            n.dependencies.clear();
            n.dependents.clear();
        }
        Ok(())
    }

    pub fn get(&self, id: WasmSignalId) -> Option<&WasmSignalNode> {
        self.nodes.get(&id)
    }
}

// ---------------------------------------------------------------------------
// JS↔WASM ABI types
// ---------------------------------------------------------------------------

/// Represents a state update crossing the JS→WASM boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiStateUpdate {
    pub signal_id: WasmSignalId,
    /// Opaque payload (serialised value in ABI-compatible format).
    pub payload: Vec<u8>,
    pub sequence: u64,
}

/// A DOM operation emitted from WASM→JS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbiDomOp {
    Create {
        element_id: u32,
        tag_index: u16,
    },
    Remove {
        element_id: u32,
    },
    SetProp {
        element_id: u32,
        prop_index: u16,
        value: Vec<u8>,
    },
    RemoveProp {
        element_id: u32,
        prop_index: u16,
    },
    SetText {
        element_id: u32,
        text: Vec<u8>,
    },
    Move {
        element_id: u32,
        new_parent: u32,
        before: u32,
    },
}

impl AbiDomOp {
    pub fn target_element(&self) -> u32 {
        match self {
            Self::Create { element_id, .. } => *element_id,
            Self::Remove { element_id } => *element_id,
            Self::SetProp { element_id, .. } => *element_id,
            Self::RemoveProp { element_id, .. } => *element_id,
            Self::SetText { element_id, .. } => *element_id,
            Self::Move { element_id, .. } => *element_id,
        }
    }
}

/// A batch of DOM operations from WASM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiDomBatch {
    pub ops: Vec<AbiDomOp>,
    pub cycle: u64,
}

impl AbiDomBatch {
    pub fn new(cycle: u64) -> Self {
        Self {
            ops: Vec::new(),
            cycle,
        }
    }

    pub fn push(&mut self, op: AbiDomOp) {
        self.ops.push(op);
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("wasm_dom_batch:cycle{}:ops={}", self.cycle, self.ops.len());
        derive_id(
            ObjectDomain::EvidenceRecord,
            "wasm-lane",
            &wasm_schema(),
            canonical.as_bytes(),
        )
        .expect("wasm dom batch id")
    }
}

// ---------------------------------------------------------------------------
// Resource budget and safe mode
// ---------------------------------------------------------------------------

/// Resource budget for the WASM lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmBudget {
    /// Maximum signal nodes.
    pub max_signals: u32,
    /// Maximum signal graph depth.
    pub max_depth: u16,
    /// Maximum pending state updates in bounded queue.
    pub max_pending_updates: u32,
    /// Maximum DOM ops per flush cycle.
    pub max_dom_ops_per_cycle: u32,
    /// Maximum total evaluations per flush.
    pub max_evaluations_per_flush: u32,
}

impl WasmBudget {
    pub fn default_budget() -> Self {
        Self {
            max_signals: 50_000,
            max_depth: 128,
            max_pending_updates: 10_000,
            max_dom_ops_per_cycle: 50_000,
            max_evaluations_per_flush: 100_000,
        }
    }

    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.max_signals == 0 {
            errors.push("max_signals must be > 0".into());
        }
        if self.max_depth == 0 {
            errors.push("max_depth must be > 0".into());
        }
        if self.max_pending_updates == 0 {
            errors.push("max_pending_updates must be > 0".into());
        }
        if self.max_dom_ops_per_cycle == 0 {
            errors.push("max_dom_ops_per_cycle must be > 0".into());
        }
        if self.max_evaluations_per_flush == 0 {
            errors.push("max_evaluations_per_flush must be > 0".into());
        }
        errors
    }
}

/// Lane operational mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum WasmLaneMode {
    /// Normal execution.
    Normal,
    /// Safe mode: reduced throughput, extra validation, conservative scheduling.
    Safe,
    /// Degraded: budget exceeded, drop low-priority updates.
    Degraded,
    /// Halted: unrecoverable, requires restart.
    Halted,
}

/// Reason for entering safe/degraded mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafeModeReason {
    QueueOverflow { queue_len: u32, limit: u32 },
    DepthExceeded { depth: u16, limit: u16 },
    EvalBudgetExhausted { evals: u32, limit: u32 },
    DomOpBudgetExhausted { ops: u32, limit: u32 },
    SignalBudgetExhausted { signals: u32, limit: u32 },
}

// ---------------------------------------------------------------------------
// Flush result
// ---------------------------------------------------------------------------

/// Summary of a WASM lane flush cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmFlushResult {
    pub cycle: u64,
    pub updates_consumed: u32,
    pub signals_evaluated: u32,
    pub dom_ops_emitted: u32,
    pub mode_after: WasmLaneMode,
    pub safe_mode_triggers: Vec<SafeModeReason>,
}

impl WasmFlushResult {
    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!(
            "wasm_flush:cycle{}:updates={}:evals={}:ops={}:mode={:?}",
            self.cycle,
            self.updates_consumed,
            self.signals_evaluated,
            self.dom_ops_emitted,
            self.mode_after,
        );
        derive_id(
            ObjectDomain::EvidenceRecord,
            "wasm-lane",
            &wasm_schema(),
            canonical.as_bytes(),
        )
        .expect("wasm flush id")
    }
}

// ---------------------------------------------------------------------------
// WASM runtime lane
// ---------------------------------------------------------------------------

/// The complete WASM runtime lane instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmRuntimeLane {
    pub budget: WasmBudget,
    pub graph: WasmSignalGraph,
    pub update_queue: BoundedQueue<AbiStateUpdate>,
    pub mode: WasmLaneMode,
    pub flush_count: u64,
    pub total_evaluations: u64,
    pub total_dom_ops: u64,
    pub safe_mode_triggers: Vec<SafeModeReason>,
}

impl WasmRuntimeLane {
    pub fn new(budget: WasmBudget) -> Self {
        let graph = WasmSignalGraph::new(budget.max_depth, budget.max_signals);
        let update_queue = BoundedQueue::new(budget.max_pending_updates);
        Self {
            budget,
            graph,
            update_queue,
            mode: WasmLaneMode::Normal,
            flush_count: 0,
            total_evaluations: 0,
            total_dom_ops: 0,
            safe_mode_triggers: Vec::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(WasmBudget::default_budget())
    }

    /// Register a signal via lane-level API so budget/depth failures deterministically
    /// trigger safe mode reasons.
    pub fn register_signal(
        &mut self,
        kind: WasmSignalKind,
        deps: BTreeSet<WasmSignalId>,
    ) -> Result<WasmSignalId, WasmGraphError> {
        let id = self.graph.next_id();
        match self.graph.register(id, kind, deps) {
            Ok(()) => Ok(id),
            Err(err) => {
                match &err {
                    WasmGraphError::DepthExceeded { depth, max, .. } => {
                        self.enter_safe_mode(SafeModeReason::DepthExceeded {
                            depth: *depth,
                            limit: *max,
                        });
                    }
                    WasmGraphError::BudgetExceeded {
                        metric,
                        current,
                        limit,
                    } if metric == "nodes" => {
                        self.enter_safe_mode(SafeModeReason::SignalBudgetExhausted {
                            signals: (*current).min(u32::MAX as u64) as u32,
                            limit: (*limit).min(u32::MAX as u64) as u32,
                        });
                    }
                    _ => {}
                }
                Err(err)
            }
        }
    }

    /// Enqueue a state update from JS side.
    pub fn enqueue_update(&mut self, update: AbiStateUpdate) -> Result<(), SafeModeReason> {
        if self.update_queue.is_full() {
            let reason = SafeModeReason::QueueOverflow {
                queue_len: self.update_queue.len() as u32,
                limit: self.update_queue.capacity(),
            };
            self.enter_safe_mode(reason.clone());
            return Err(reason);
        }
        self.update_queue
            .push(update)
            .map_err(|_| SafeModeReason::QueueOverflow {
                queue_len: self.update_queue.len() as u32,
                limit: self.update_queue.capacity(),
            })
    }

    /// Execute a flush cycle: consume updates, propagate, evaluate, emit DOM ops.
    pub fn flush(&mut self) -> WasmFlushResult {
        let cycle = self.flush_count;
        self.flush_count += 1;

        let mut signals_evaluated = 0u32;
        let mut dom_ops_emitted = 0u32;
        let mut triggers = Vec::new();

        // Consume updates up to budget
        let updates = self.update_queue.drain_all();
        let updates_consumed = updates.len() as u32;

        // Propagate dirty for each update
        let mut all_dirty = BTreeSet::new();
        for update in &updates {
            if let Ok(dirty) = self.graph.propagate_dirty(update.signal_id) {
                for d in dirty {
                    all_dirty.insert(d);
                }
            }
        }

        // Evaluate dirty signals in topological order
        let mut eval_order: Vec<_> = all_dirty.into_iter().collect();
        eval_order.sort_by_key(|id| self.graph.get(*id).map_or(0, |n| n.depth));

        for sig in &eval_order {
            if signals_evaluated >= self.budget.max_evaluations_per_flush {
                triggers.push(SafeModeReason::EvalBudgetExhausted {
                    evals: signals_evaluated,
                    limit: self.budget.max_evaluations_per_flush,
                });
                break;
            }
            let _ = self.graph.mark_clean(*sig);
            signals_evaluated += 1;

            // Count effect signals as DOM op emitters
            if let Some(node) = self.graph.get(*sig)
                && node.kind == WasmSignalKind::Effect
            {
                let attempted = dom_ops_emitted.saturating_add(1);
                if attempted > self.budget.max_dom_ops_per_cycle {
                    triggers.push(SafeModeReason::DomOpBudgetExhausted {
                        ops: attempted,
                        limit: self.budget.max_dom_ops_per_cycle,
                    });
                    break;
                }
                dom_ops_emitted = attempted;
            }
        }

        self.total_evaluations += signals_evaluated as u64;
        self.total_dom_ops += dom_ops_emitted as u64;

        // Determine mode
        let mode_after = if triggers.is_empty() {
            self.mode
        } else {
            WasmLaneMode::Degraded
        };

        if !triggers.is_empty() {
            self.safe_mode_triggers.extend(triggers.clone());
            self.mode = mode_after;
        }

        WasmFlushResult {
            cycle,
            updates_consumed,
            signals_evaluated,
            dom_ops_emitted,
            mode_after,
            safe_mode_triggers: triggers,
        }
    }

    fn enter_safe_mode(&mut self, reason: SafeModeReason) {
        if self.mode == WasmLaneMode::Normal {
            self.mode = WasmLaneMode::Safe;
        }
        self.safe_mode_triggers.push(reason);
    }

    /// Reset to normal mode (e.g. after clearing queue pressure).
    pub fn reset_mode(&mut self) {
        self.mode = WasmLaneMode::Normal;
        self.safe_mode_triggers.clear();
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!(
            "wasm_lane:signals={}:mode={:?}:flushes={}",
            self.graph.active_count(),
            self.mode,
            self.flush_count,
        );
        derive_id(
            ObjectDomain::EvidenceRecord,
            "wasm-lane",
            &wasm_schema(),
            canonical.as_bytes(),
        )
        .expect("wasm lane id")
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js_runtime_lane::{
        SignalGraph as JsSignalGraph, SignalId as JsSignalId, SignalKind as JsSignalKind,
    };

    // ---- BoundedQueue tests ----

    #[test]
    fn bounded_queue_new() {
        let q: BoundedQueue<u32> = BoundedQueue::new(5);
        assert!(q.is_empty());
        assert!(!q.is_full());
        assert_eq!(q.capacity(), 5);
    }

    #[test]
    fn bounded_queue_push_pop() {
        let mut q = BoundedQueue::new(3);
        q.push(1).unwrap();
        q.push(2).unwrap();
        assert_eq!(q.len(), 2);
        assert_eq!(q.pop().unwrap(), 1);
        assert_eq!(q.pop().unwrap(), 2);
        assert!(q.is_empty());
    }

    #[test]
    fn bounded_queue_full() {
        let mut q = BoundedQueue::new(2);
        q.push(1).unwrap();
        q.push(2).unwrap();
        assert!(q.is_full());
        assert!(matches!(q.push(3), Err(QueueError::Full { capacity: 2 })));
    }

    #[test]
    fn bounded_queue_empty_pop() {
        let mut q: BoundedQueue<u32> = BoundedQueue::new(5);
        assert!(matches!(q.pop(), Err(QueueError::Empty)));
    }

    #[test]
    fn bounded_queue_drain_all() {
        let mut q = BoundedQueue::new(5);
        q.push(10).unwrap();
        q.push(20).unwrap();
        q.push(30).unwrap();
        let all = q.drain_all();
        assert_eq!(all, vec![10, 20, 30]);
        assert!(q.is_empty());
    }

    #[test]
    fn bounded_queue_clear_batch2() {
        let mut q = BoundedQueue::new(5);
        q.push(1).unwrap();
        q.push(2).unwrap();
        q.clear();
        assert!(q.is_empty());
    }

    // ---- WasmSignalGraph tests ----

    #[test]
    fn graph_new() {
        let g = WasmSignalGraph::new(64, 1000);
        assert_eq!(g.active_count(), 0);
    }

    #[test]
    fn graph_register_source() {
        let mut g = WasmSignalGraph::new(64, 1000);
        let id = g.next_id();
        g.register(id, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        assert_eq!(g.active_count(), 1);
        assert_eq!(g.get(id).unwrap().depth, 0);
    }

    #[test]
    fn graph_register_derived() {
        let mut g = WasmSignalGraph::new(64, 1000);
        let s = g.next_id();
        g.register(s, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        let d = g.next_id();
        let mut deps = BTreeSet::new();
        deps.insert(s);
        g.register(d, WasmSignalKind::Derived, deps).unwrap();
        assert_eq!(g.get(d).unwrap().depth, 1);
    }

    #[test]
    fn graph_depth_exceeded() {
        let mut g = WasmSignalGraph::new(2, 100);
        let s = g.next_id();
        g.register(s, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        let d1 = g.next_id();
        let mut deps = BTreeSet::new();
        deps.insert(s);
        g.register(d1, WasmSignalKind::Derived, deps).unwrap();
        let d2 = g.next_id();
        let mut deps2 = BTreeSet::new();
        deps2.insert(d1);
        g.register(d2, WasmSignalKind::Derived, deps2).unwrap();
        // depth 3 exceeds max_depth=2
        let d3 = g.next_id();
        let mut deps3 = BTreeSet::new();
        deps3.insert(d2);
        assert!(matches!(
            g.register(d3, WasmSignalKind::Derived, deps3),
            Err(WasmGraphError::DepthExceeded { .. })
        ));
    }

    #[test]
    fn graph_node_limit() {
        let mut g = WasmSignalGraph::new(64, 2);
        let s1 = g.next_id();
        let s2 = g.next_id();
        g.register(s1, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        g.register(s2, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        let s3 = g.next_id();
        assert!(matches!(
            g.register(s3, WasmSignalKind::Source, BTreeSet::new()),
            Err(WasmGraphError::BudgetExceeded { .. })
        ));
    }

    #[test]
    fn graph_duplicate_rejected() {
        let mut g = WasmSignalGraph::new(64, 100);
        let id = g.next_id();
        g.register(id, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        assert!(matches!(
            g.register(id, WasmSignalKind::Source, BTreeSet::new()),
            Err(WasmGraphError::DuplicateSignal(_))
        ));
    }

    #[test]
    fn graph_propagate_dirty() {
        let mut g = WasmSignalGraph::new(64, 100);
        let s = g.next_id();
        g.register(s, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        g.mark_clean(s).unwrap();
        let d = g.next_id();
        let mut deps = BTreeSet::new();
        deps.insert(s);
        g.register(d, WasmSignalKind::Derived, deps).unwrap();
        g.mark_clean(d).unwrap();
        let e = g.next_id();
        let mut deps2 = BTreeSet::new();
        deps2.insert(d);
        g.register(e, WasmSignalKind::Effect, deps2).unwrap();
        g.mark_clean(e).unwrap();

        let dirty = g.propagate_dirty(s).unwrap();
        assert_eq!(dirty.len(), 3);
        assert_eq!(dirty[0], s);
        assert_eq!(dirty[1], d);
        assert_eq!(dirty[2], e);
    }

    #[test]
    fn graph_dispose() {
        let mut g = WasmSignalGraph::new(64, 100);
        let s = g.next_id();
        g.register(s, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        let d = g.next_id();
        let mut deps = BTreeSet::new();
        deps.insert(s);
        g.register(d, WasmSignalKind::Derived, deps).unwrap();
        g.dispose(d).unwrap();
        assert_eq!(g.active_count(), 1);
    }

    #[test]
    fn graph_serde_roundtrip() {
        let mut g = WasmSignalGraph::new(64, 100);
        let s = g.next_id();
        g.register(s, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        let json = serde_json::to_string(&g).unwrap();
        let g2: WasmSignalGraph = serde_json::from_str(&json).unwrap();
        assert_eq!(g, g2);
    }

    // ---- ABI types tests ----

    #[test]
    fn abi_dom_op_target() {
        let op = AbiDomOp::SetProp {
            element_id: 42,
            prop_index: 0,
            value: vec![1, 2, 3],
        };
        assert_eq!(op.target_element(), 42);
    }

    #[test]
    fn abi_dom_batch_derive_id_stable() {
        let b = AbiDomBatch::new(1);
        assert_eq!(b.derive_id(), b.derive_id());
    }

    #[test]
    fn abi_dom_batch_serde_roundtrip() {
        let mut b = AbiDomBatch::new(5);
        b.push(AbiDomOp::Create {
            element_id: 0,
            tag_index: 1,
        });
        b.push(AbiDomOp::SetText {
            element_id: 0,
            text: b"hello".to_vec(),
        });
        let json = serde_json::to_string(&b).unwrap();
        let b2: AbiDomBatch = serde_json::from_str(&json).unwrap();
        assert_eq!(b, b2);
    }

    #[test]
    fn abi_state_update_serde_roundtrip() {
        let u = AbiStateUpdate {
            signal_id: WasmSignalId(7),
            payload: vec![0xDE, 0xAD],
            sequence: 42,
        };
        let json = serde_json::to_string(&u).unwrap();
        let u2: AbiStateUpdate = serde_json::from_str(&json).unwrap();
        assert_eq!(u, u2);
    }

    // ---- WasmBudget tests ----

    #[test]
    fn budget_defaults_valid() {
        let b = WasmBudget::default_budget();
        assert!(b.validate().is_empty());
    }

    #[test]
    fn budget_zero_signals_invalid() {
        let mut b = WasmBudget::default_budget();
        b.max_signals = 0;
        assert!(!b.validate().is_empty());
    }

    // ---- WasmRuntimeLane tests ----

    #[test]
    fn lane_with_defaults() {
        let lane = WasmRuntimeLane::with_defaults();
        assert_eq!(lane.mode, WasmLaneMode::Normal);
        assert_eq!(lane.flush_count, 0);
    }

    #[test]
    fn lane_enqueue_update() {
        let mut lane = WasmRuntimeLane::with_defaults();
        let s = lane.graph.next_id();
        lane.graph
            .register(s, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();

        lane.enqueue_update(AbiStateUpdate {
            signal_id: s,
            payload: vec![1],
            sequence: 0,
        })
        .unwrap();
        assert_eq!(lane.update_queue.len(), 1);
    }

    #[test]
    fn lane_flush_basic() {
        let mut lane = WasmRuntimeLane::with_defaults();
        let s = lane.graph.next_id();
        lane.graph
            .register(s, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        lane.graph.mark_clean(s).unwrap();

        let d = lane.graph.next_id();
        let mut deps = BTreeSet::new();
        deps.insert(s);
        lane.graph
            .register(d, WasmSignalKind::Derived, deps)
            .unwrap();
        lane.graph.mark_clean(d).unwrap();

        lane.enqueue_update(AbiStateUpdate {
            signal_id: s,
            payload: vec![42],
            sequence: 0,
        })
        .unwrap();

        let result = lane.flush();
        assert_eq!(result.cycle, 0);
        assert_eq!(result.updates_consumed, 1);
        assert_eq!(result.signals_evaluated, 2);
        assert_eq!(result.mode_after, WasmLaneMode::Normal);
        assert!(result.safe_mode_triggers.is_empty());
    }

    #[test]
    fn lane_flush_with_effect() {
        let mut lane = WasmRuntimeLane::with_defaults();
        let s = lane.graph.next_id();
        lane.graph
            .register(s, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        lane.graph.mark_clean(s).unwrap();

        let e = lane.graph.next_id();
        let mut deps = BTreeSet::new();
        deps.insert(s);
        lane.graph
            .register(e, WasmSignalKind::Effect, deps)
            .unwrap();
        lane.graph.mark_clean(e).unwrap();

        lane.enqueue_update(AbiStateUpdate {
            signal_id: s,
            payload: vec![],
            sequence: 0,
        })
        .unwrap();

        let result = lane.flush();
        assert_eq!(result.dom_ops_emitted, 1); // effect counts as dom op
    }

    #[test]
    fn lane_eval_budget_triggers_degraded() {
        let mut budget = WasmBudget::default_budget();
        budget.max_evaluations_per_flush = 1;
        let mut lane = WasmRuntimeLane::new(budget);

        let s = lane.graph.next_id();
        lane.graph
            .register(s, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        lane.graph.mark_clean(s).unwrap();

        let d = lane.graph.next_id();
        let mut deps = BTreeSet::new();
        deps.insert(s);
        lane.graph
            .register(d, WasmSignalKind::Derived, deps)
            .unwrap();
        lane.graph.mark_clean(d).unwrap();

        lane.enqueue_update(AbiStateUpdate {
            signal_id: s,
            payload: vec![],
            sequence: 0,
        })
        .unwrap();

        let result = lane.flush();
        assert_eq!(result.mode_after, WasmLaneMode::Degraded);
        assert!(!result.safe_mode_triggers.is_empty());
    }

    #[test]
    fn lane_dom_op_budget_triggers_degraded() {
        let mut budget = WasmBudget::default_budget();
        budget.max_dom_ops_per_cycle = 1;
        let mut lane = WasmRuntimeLane::new(budget);

        let s = lane.graph.next_id();
        lane.graph
            .register(s, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        lane.graph.mark_clean(s).unwrap();

        let e1 = lane.graph.next_id();
        let mut deps1 = BTreeSet::new();
        deps1.insert(s);
        lane.graph
            .register(e1, WasmSignalKind::Effect, deps1)
            .unwrap();
        lane.graph.mark_clean(e1).unwrap();

        let e2 = lane.graph.next_id();
        let mut deps2 = BTreeSet::new();
        deps2.insert(s);
        lane.graph
            .register(e2, WasmSignalKind::Effect, deps2)
            .unwrap();
        lane.graph.mark_clean(e2).unwrap();

        lane.enqueue_update(AbiStateUpdate {
            signal_id: s,
            payload: vec![1],
            sequence: 0,
        })
        .unwrap();

        let result = lane.flush();
        assert_eq!(result.mode_after, WasmLaneMode::Degraded);
        assert_eq!(result.dom_ops_emitted, 1);
        assert!(result.safe_mode_triggers.iter().any(|reason| matches!(
            reason,
            SafeModeReason::DomOpBudgetExhausted { limit: 1, .. }
        )));
    }

    #[test]
    fn lane_register_signal_depth_exceeded_enters_safe_mode() {
        let mut budget = WasmBudget::default_budget();
        budget.max_depth = 1;
        let mut lane = WasmRuntimeLane::new(budget);

        let s = lane
            .register_signal(WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        let mut deps = BTreeSet::new();
        deps.insert(s);
        let d = lane.register_signal(WasmSignalKind::Derived, deps).unwrap();
        let mut deps2 = BTreeSet::new();
        deps2.insert(d);

        let err = lane
            .register_signal(WasmSignalKind::Derived, deps2)
            .unwrap_err();
        assert!(matches!(err, WasmGraphError::DepthExceeded { .. }));
        assert_eq!(lane.mode, WasmLaneMode::Safe);
        assert!(
            lane.safe_mode_triggers
                .iter()
                .any(|reason| matches!(reason, SafeModeReason::DepthExceeded { .. }))
        );
    }

    #[test]
    fn lane_register_signal_budget_exceeded_enters_safe_mode() {
        let mut budget = WasmBudget::default_budget();
        budget.max_signals = 1;
        let mut lane = WasmRuntimeLane::new(budget);

        lane.register_signal(WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        let err = lane
            .register_signal(WasmSignalKind::Source, BTreeSet::new())
            .unwrap_err();
        assert!(matches!(err, WasmGraphError::BudgetExceeded { .. }));
        assert_eq!(lane.mode, WasmLaneMode::Safe);
        assert!(lane.safe_mode_triggers.iter().any(|reason| matches!(
            reason,
            SafeModeReason::SignalBudgetExhausted { limit: 1, .. }
        )));
    }

    #[test]
    fn lane_queue_overflow_safe_mode() {
        let mut budget = WasmBudget::default_budget();
        budget.max_pending_updates = 1;
        let mut lane = WasmRuntimeLane::new(budget);

        let s = lane.graph.next_id();
        lane.graph
            .register(s, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();

        lane.enqueue_update(AbiStateUpdate {
            signal_id: s,
            payload: vec![],
            sequence: 0,
        })
        .unwrap();

        // Second update should trigger safe mode
        let result = lane.enqueue_update(AbiStateUpdate {
            signal_id: s,
            payload: vec![],
            sequence: 1,
        });
        assert!(result.is_err());
        assert_eq!(lane.mode, WasmLaneMode::Safe);
    }

    #[test]
    fn lane_reset_mode() {
        let mut lane = WasmRuntimeLane::with_defaults();
        lane.mode = WasmLaneMode::Safe;
        lane.safe_mode_triggers.push(SafeModeReason::QueueOverflow {
            queue_len: 100,
            limit: 100,
        });
        lane.reset_mode();
        assert_eq!(lane.mode, WasmLaneMode::Normal);
        assert!(lane.safe_mode_triggers.is_empty());
    }

    #[test]
    fn lane_derive_id_stable() {
        let lane = WasmRuntimeLane::with_defaults();
        assert_eq!(lane.derive_id(), lane.derive_id());
    }

    #[test]
    fn lane_serde_roundtrip() {
        let lane = WasmRuntimeLane::with_defaults();
        let json = serde_json::to_string(&lane).unwrap();
        let l2: WasmRuntimeLane = serde_json::from_str(&json).unwrap();
        assert_eq!(lane, l2);
    }

    #[test]
    fn flush_result_derive_id_stable() {
        let r = WasmFlushResult {
            cycle: 0,
            updates_consumed: 5,
            signals_evaluated: 10,
            dom_ops_emitted: 3,
            mode_after: WasmLaneMode::Normal,
            safe_mode_triggers: vec![],
        };
        assert_eq!(r.derive_id(), r.derive_id());
    }

    // ---- End-to-end tests ----

    #[test]
    fn e2e_multi_update_flush() {
        let mut lane = WasmRuntimeLane::with_defaults();

        // Create 3 source signals
        let s1 = lane.graph.next_id();
        let s2 = lane.graph.next_id();
        let s3 = lane.graph.next_id();
        for s in [s1, s2, s3] {
            lane.graph
                .register(s, WasmSignalKind::Source, BTreeSet::new())
                .unwrap();
            lane.graph.mark_clean(s).unwrap();
        }

        // Derived that depends on s1+s2
        let d = lane.graph.next_id();
        let mut deps = BTreeSet::new();
        deps.insert(s1);
        deps.insert(s2);
        lane.graph
            .register(d, WasmSignalKind::Derived, deps)
            .unwrap();
        lane.graph.mark_clean(d).unwrap();

        // Effect on derived
        let e = lane.graph.next_id();
        let mut edeps = BTreeSet::new();
        edeps.insert(d);
        lane.graph
            .register(e, WasmSignalKind::Effect, edeps)
            .unwrap();
        lane.graph.mark_clean(e).unwrap();

        // Enqueue updates for s1 and s3
        lane.enqueue_update(AbiStateUpdate {
            signal_id: s1,
            payload: vec![1],
            sequence: 0,
        })
        .unwrap();
        lane.enqueue_update(AbiStateUpdate {
            signal_id: s3,
            payload: vec![3],
            sequence: 1,
        })
        .unwrap();

        let result = lane.flush();
        assert_eq!(result.updates_consumed, 2);
        // s1, s3 dirty + d (via s1) + e (via d) = 4 signals
        assert!(result.signals_evaluated >= 4);
        assert_eq!(result.mode_after, WasmLaneMode::Normal);
    }

    #[test]
    fn e2e_dispose_during_operation() {
        let mut lane = WasmRuntimeLane::with_defaults();
        let s = lane.graph.next_id();
        lane.graph
            .register(s, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        let d = lane.graph.next_id();
        let mut deps = BTreeSet::new();
        deps.insert(s);
        lane.graph
            .register(d, WasmSignalKind::Derived, deps)
            .unwrap();

        // Dispose derived
        lane.graph.dispose(d).unwrap();
        assert_eq!(lane.graph.active_count(), 1);

        // Source dirty propagation should not reach disposed
        let dirty = lane.graph.propagate_dirty(s).unwrap();
        assert_eq!(dirty.len(), 1);
    }

    #[test]
    fn e2e_sequential_flushes() {
        let mut lane = WasmRuntimeLane::with_defaults();
        let s = lane.graph.next_id();
        lane.graph
            .register(s, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();

        for i in 0..3 {
            lane.enqueue_update(AbiStateUpdate {
                signal_id: s,
                payload: vec![i as u8],
                sequence: i,
            })
            .unwrap();
            let result = lane.flush();
            assert_eq!(result.cycle, i);
        }
        assert_eq!(lane.flush_count, 3);
    }

    #[test]
    fn wasm_graph_matches_js_graph_dirty_propagation() {
        let mut js = JsSignalGraph::new();
        let js_s = js.next_signal_id();
        js.register(js_s, JsSignalKind::Source, BTreeSet::new())
            .unwrap();
        js.mark_clean(js_s).unwrap();
        let js_d = js.next_signal_id();
        let mut js_deps = BTreeSet::new();
        js_deps.insert(js_s);
        js.register(js_d, JsSignalKind::Derived, js_deps).unwrap();
        js.mark_clean(js_d).unwrap();
        let js_e = js.next_signal_id();
        let mut js_deps2 = BTreeSet::new();
        js_deps2.insert(js_d);
        js.register(js_e, JsSignalKind::Effect, js_deps2).unwrap();
        js.mark_clean(js_e).unwrap();

        let mut wasm = WasmSignalGraph::new(64, 100);
        let ws = wasm.next_id();
        wasm.register(ws, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        wasm.mark_clean(ws).unwrap();
        let wd = wasm.next_id();
        let mut wdeps = BTreeSet::new();
        wdeps.insert(ws);
        wasm.register(wd, WasmSignalKind::Derived, wdeps).unwrap();
        wasm.mark_clean(wd).unwrap();
        let we = wasm.next_id();
        let mut wdeps2 = BTreeSet::new();
        wdeps2.insert(wd);
        wasm.register(we, WasmSignalKind::Effect, wdeps2).unwrap();
        wasm.mark_clean(we).unwrap();

        let js_dirty = js.mark_dirty(js_s).unwrap();
        let wasm_dirty = wasm.propagate_dirty(ws).unwrap();
        let js_ids: Vec<u32> = js_dirty.into_iter().map(|id| id.0 as u32).collect();
        let wasm_ids: Vec<u32> = wasm_dirty.into_iter().map(|id| id.0).collect();
        assert_eq!(js_ids, wasm_ids);
    }

    #[test]
    fn wasm_graph_matches_js_graph_dispose_behavior() {
        let mut js = JsSignalGraph::new();
        let js_s = js.next_signal_id();
        js.register(js_s, JsSignalKind::Source, BTreeSet::new())
            .unwrap();
        let js_d = js.next_signal_id();
        let mut js_deps = BTreeSet::new();
        js_deps.insert(js_s);
        js.register(js_d, JsSignalKind::Derived, js_deps).unwrap();
        js.dispose(js_d).unwrap();
        let js_dirty = js.mark_dirty(js_s).unwrap();
        let js_ids: Vec<JsSignalId> = js_dirty;

        let mut wasm = WasmSignalGraph::new(64, 100);
        let ws = wasm.next_id();
        wasm.register(ws, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        let wd = wasm.next_id();
        let mut wdeps = BTreeSet::new();
        wdeps.insert(ws);
        wasm.register(wd, WasmSignalKind::Derived, wdeps).unwrap();
        wasm.dispose(wd).unwrap();
        let wasm_dirty = wasm.propagate_dirty(ws).unwrap();
        let wasm_ids: Vec<WasmSignalId> = wasm_dirty;

        assert_eq!(js_ids.len(), wasm_ids.len());
        assert_eq!(js_ids[0].0 as u32, wasm_ids[0].0);
    }

    // -- Enrichment: WasmSignalKind serde roundtrip --

    #[test]
    fn wasm_signal_kind_serde_roundtrip_batch2() {
        for kind in [
            WasmSignalKind::Source,
            WasmSignalKind::Derived,
            WasmSignalKind::Effect,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let restored: WasmSignalKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, restored);
        }
    }

    // -- Enrichment: WasmSignalStatus serde roundtrip --

    #[test]
    fn wasm_signal_status_serde_roundtrip() {
        for status in [
            WasmSignalStatus::Clean,
            WasmSignalStatus::Dirty,
            WasmSignalStatus::Evaluating,
            WasmSignalStatus::Disposed,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let restored: WasmSignalStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, restored);
        }
    }

    // -- Enrichment: WasmLaneMode serde roundtrip and ordering --

    #[test]
    fn wasm_lane_mode_serde_roundtrip() {
        for mode in [
            WasmLaneMode::Normal,
            WasmLaneMode::Safe,
            WasmLaneMode::Degraded,
            WasmLaneMode::Halted,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let restored: WasmLaneMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, restored);
        }
    }

    #[test]
    fn wasm_lane_mode_ordering() {
        assert!(WasmLaneMode::Normal < WasmLaneMode::Safe);
        assert!(WasmLaneMode::Safe < WasmLaneMode::Degraded);
        assert!(WasmLaneMode::Degraded < WasmLaneMode::Halted);
    }

    // -- Enrichment: SafeModeReason serde roundtrip --

    #[test]
    fn safe_mode_reason_serde_roundtrip() {
        let reasons = [
            SafeModeReason::QueueOverflow {
                queue_len: 100,
                limit: 100,
            },
            SafeModeReason::DepthExceeded {
                depth: 200,
                limit: 128,
            },
            SafeModeReason::EvalBudgetExhausted {
                evals: 50000,
                limit: 50000,
            },
            SafeModeReason::DomOpBudgetExhausted {
                ops: 10000,
                limit: 10000,
            },
            SafeModeReason::SignalBudgetExhausted {
                signals: 5000,
                limit: 5000,
            },
        ];
        for reason in &reasons {
            let json = serde_json::to_string(reason).unwrap();
            let restored: SafeModeReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*reason, restored);
        }
    }

    // -- Enrichment: WasmBudget serde roundtrip --

    #[test]
    fn wasm_budget_serde_roundtrip() {
        let budget = WasmBudget::default_budget();
        let json = serde_json::to_string(&budget).unwrap();
        let restored: WasmBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(budget, restored);
    }

    // -- Enrichment: WasmBudget validate all-zero fields --

    #[test]
    fn budget_all_zero_reports_multiple_errors() {
        let budget = WasmBudget {
            max_signals: 0,
            max_depth: 0,
            max_pending_updates: 0,
            max_dom_ops_per_cycle: 0,
            max_evaluations_per_flush: 100,
        };
        let errors = budget.validate();
        assert!(errors.len() >= 3);
    }

    // -- Enrichment: WasmFlushResult serde roundtrip --

    #[test]
    fn flush_result_serde_roundtrip() {
        let result = WasmFlushResult {
            cycle: 5,
            updates_consumed: 10,
            signals_evaluated: 20,
            dom_ops_emitted: 3,
            mode_after: WasmLaneMode::Normal,
            safe_mode_triggers: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: WasmFlushResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, restored);
    }

    // -- Enrichment: AbiDomOp target_element for all variants --

    #[test]
    fn abi_dom_op_target_all_variants() {
        let ops = [
            AbiDomOp::Create {
                element_id: 1,
                tag_index: 0,
            },
            AbiDomOp::Remove { element_id: 2 },
            AbiDomOp::SetProp {
                element_id: 3,
                prop_index: 0,
                value: vec![],
            },
            AbiDomOp::RemoveProp {
                element_id: 4,
                prop_index: 0,
            },
            AbiDomOp::SetText {
                element_id: 5,
                text: vec![],
            },
            AbiDomOp::Move {
                element_id: 6,
                new_parent: 0,
                before: 0,
            },
        ];
        for (i, op) in ops.iter().enumerate() {
            assert_eq!(op.target_element(), (i + 1) as u32);
        }
    }

    // -- Enrichment: graph propagate_dirty on disposed signal --

    #[test]
    fn graph_propagate_dirty_disposed_rejected() {
        let mut g = WasmSignalGraph::new(64, 100);
        let s = g.next_id();
        g.register(s, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        g.dispose(s).unwrap();
        assert!(matches!(
            g.propagate_dirty(s),
            Err(WasmGraphError::Disposed(_))
        ));
    }

    // -- Enrichment: graph propagate_dirty on nonexistent signal --

    #[test]
    fn graph_propagate_dirty_not_found() {
        let g = WasmSignalGraph::new(64, 100);
        assert!(matches!(
            g.clone().propagate_dirty(WasmSignalId(999)),
            Err(WasmGraphError::NotFound(_))
        ));
    }

    // -- Enrichment: lane total counters accumulate across flushes --

    #[test]
    fn lane_total_counters_accumulate() {
        let mut lane = WasmRuntimeLane::with_defaults();
        let s = lane.graph.next_id();
        lane.graph
            .register(s, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        lane.graph.mark_clean(s).unwrap();

        for i in 0..3u64 {
            lane.enqueue_update(AbiStateUpdate {
                signal_id: s,
                payload: vec![i as u8],
                sequence: i,
            })
            .unwrap();
            lane.flush();
        }

        assert_eq!(lane.flush_count, 3);
        assert!(lane.total_evaluations >= 3);
    }

    // -- Enrichment: WasmSignalId ordering --

    #[test]
    fn wasm_signal_id_ordering() {
        assert!(WasmSignalId(0) < WasmSignalId(1));
        assert!(WasmSignalId(1) < WasmSignalId(100));
        assert_eq!(WasmSignalId(42), WasmSignalId(42));
    }

    // -- Enrichment batch 2: PearlTower 2026-02-27 --

    #[test]
    fn bounded_queue_push_to_full_then_reject() {
        let mut q = BoundedQueue::<u32>::new(2);
        assert!(!q.is_full());
        q.push(10).unwrap();
        q.push(20).unwrap();
        assert!(q.is_full());
        let err = q.push(30).unwrap_err();
        assert_eq!(err, QueueError::Full { capacity: 2 });
    }

    #[test]
    fn bounded_queue_pop_fifo_order() {
        let mut q = BoundedQueue::new(3);
        q.push(1u32).unwrap();
        q.push(2).unwrap();
        q.push(3).unwrap();
        assert_eq!(q.pop().unwrap(), 1);
        assert_eq!(q.pop().unwrap(), 2);
        assert_eq!(q.pop().unwrap(), 3);
        assert_eq!(q.pop().unwrap_err(), QueueError::Empty);
    }

    #[test]
    fn bounded_queue_drain_all_empties() {
        let mut q = BoundedQueue::new(3);
        q.push(1u32).unwrap();
        q.push(2).unwrap();
        let drained = q.drain_all();
        assert_eq!(drained.len(), 2);
        assert!(q.is_empty());
    }

    #[test]
    fn bounded_queue_clear() {
        let mut q = BoundedQueue::new(3);
        q.push(1u32).unwrap();
        q.push(2).unwrap();
        q.clear();
        assert!(q.is_empty());
        assert!(!q.is_full());
    }

    #[test]
    fn graph_register_duplicate_fails() {
        let mut graph = WasmSignalGraph::new(16, 32);
        let id = graph.next_id();
        graph
            .register(id, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        let err = graph
            .register(id, WasmSignalKind::Source, BTreeSet::new())
            .unwrap_err();
        assert!(matches!(err, WasmGraphError::DuplicateSignal(_)));
    }

    #[test]
    fn graph_register_with_missing_dep_fails() {
        let mut graph = WasmSignalGraph::new(16, 32);
        let mut deps = BTreeSet::new();
        deps.insert(WasmSignalId(999));
        let id = graph.next_id();
        let err = graph
            .register(id, WasmSignalKind::Derived, deps)
            .unwrap_err();
        assert!(matches!(err, WasmGraphError::DepNotFound(_)));
    }

    #[test]
    fn graph_dispose_marks_disposed() {
        let mut graph = WasmSignalGraph::new(16, 32);
        let id = graph.next_id();
        graph
            .register(id, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        graph.dispose(id).unwrap();
        let node = graph.get(id).unwrap();
        assert_eq!(node.status, WasmSignalStatus::Disposed);
    }

    #[test]
    fn graph_propagate_dirty_on_disposed_fails() {
        let mut graph = WasmSignalGraph::new(16, 32);
        let id = graph.next_id();
        graph
            .register(id, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        graph.dispose(id).unwrap();
        let err = graph.propagate_dirty(id).unwrap_err();
        assert!(matches!(err, WasmGraphError::Disposed(_)));
    }

    #[test]
    fn graph_propagate_dirty_topological_order() {
        let mut graph = WasmSignalGraph::new(16, 32);
        let a = graph.next_id();
        let b = graph.next_id();
        let c = graph.next_id();
        graph
            .register(a, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        let mut deps_b = BTreeSet::new();
        deps_b.insert(a);
        graph.register(b, WasmSignalKind::Derived, deps_b).unwrap();
        let mut deps_c = BTreeSet::new();
        deps_c.insert(b);
        graph.register(c, WasmSignalKind::Effect, deps_c).unwrap();

        graph.mark_clean(a).unwrap();
        graph.mark_clean(b).unwrap();
        graph.mark_clean(c).unwrap();

        let dirty = graph.propagate_dirty(a).unwrap();
        // a(depth=0), b(depth=1), c(depth=2)
        assert_eq!(dirty.len(), 3);
        assert_eq!(dirty[0], a);
        assert_eq!(dirty[1], b);
        assert_eq!(dirty[2], c);
    }

    #[test]
    fn wasm_signal_kind_serde_roundtrip() {
        let kinds = [
            WasmSignalKind::Source,
            WasmSignalKind::Derived,
            WasmSignalKind::Effect,
        ];
        for kind in &kinds {
            let json = serde_json::to_string(kind).unwrap();
            let back: WasmSignalKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn wasm_signal_status_serde_roundtrip_all_variants() {
        let statuses = [
            WasmSignalStatus::Clean,
            WasmSignalStatus::Dirty,
            WasmSignalStatus::Evaluating,
            WasmSignalStatus::Disposed,
        ];
        for s in &statuses {
            let json = serde_json::to_string(s).unwrap();
            let back: WasmSignalStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn abi_dom_op_target_element_for_all_variants() {
        let ops = [
            AbiDomOp::Create {
                element_id: 1,
                tag_index: 0,
            },
            AbiDomOp::Remove { element_id: 2 },
            AbiDomOp::SetProp {
                element_id: 3,
                prop_index: 0,
                value: vec![],
            },
            AbiDomOp::RemoveProp {
                element_id: 4,
                prop_index: 0,
            },
            AbiDomOp::SetText {
                element_id: 5,
                text: vec![],
            },
            AbiDomOp::Move {
                element_id: 6,
                new_parent: 0,
                before: 0,
            },
        ];
        let ids: Vec<u32> = ops.iter().map(|op| op.target_element()).collect();
        assert_eq!(ids, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn queue_error_serde_roundtrip() {
        let full = QueueError::Full { capacity: 42 };
        let json = serde_json::to_string(&full).unwrap();
        let back: QueueError = serde_json::from_str(&json).unwrap();
        assert_eq!(full, back);

        let empty = QueueError::Empty;
        let json2 = serde_json::to_string(&empty).unwrap();
        let back2: QueueError = serde_json::from_str(&json2).unwrap();
        assert_eq!(empty, back2);
    }

    #[test]
    fn wasm_graph_error_serde_roundtrip() {
        let err = WasmGraphError::DepthExceeded {
            signal: WasmSignalId(1),
            depth: 20,
            max: 16,
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: WasmGraphError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    // -- Enrichment batch 3: PearlTower 2026-02-27 --

    #[test]
    fn clone_eq_wasm_signal_node() {
        let node = WasmSignalNode {
            id: WasmSignalId(7),
            kind: WasmSignalKind::Derived,
            status: WasmSignalStatus::Dirty,
            depth: 3,
            generation: 10,
            dependencies: {
                let mut s = BTreeSet::new();
                s.insert(WasmSignalId(1));
                s
            },
            dependents: BTreeSet::new(),
        };
        let cloned = node.clone();
        assert_eq!(node, cloned);
    }

    #[test]
    fn clone_eq_wasm_budget() {
        let budget = WasmBudget {
            max_signals: 100,
            max_depth: 16,
            max_pending_updates: 50,
            max_dom_ops_per_cycle: 200,
            max_evaluations_per_flush: 500,
        };
        let cloned = budget.clone();
        assert_eq!(budget, cloned);
    }

    #[test]
    fn clone_eq_abi_state_update() {
        let update = AbiStateUpdate {
            signal_id: WasmSignalId(42),
            payload: vec![0xCA, 0xFE],
            sequence: 999,
        };
        let cloned = update.clone();
        assert_eq!(update, cloned);
    }

    #[test]
    fn clone_eq_flush_result() {
        let result = WasmFlushResult {
            cycle: 5,
            updates_consumed: 3,
            signals_evaluated: 8,
            dom_ops_emitted: 2,
            mode_after: WasmLaneMode::Degraded,
            safe_mode_triggers: vec![SafeModeReason::EvalBudgetExhausted {
                evals: 100,
                limit: 100,
            }],
        };
        let cloned = result.clone();
        assert_eq!(result, cloned);
    }

    #[test]
    fn json_field_presence_wasm_signal_node() {
        let node = WasmSignalNode {
            id: WasmSignalId(0),
            kind: WasmSignalKind::Source,
            status: WasmSignalStatus::Clean,
            depth: 0,
            generation: 1,
            dependencies: BTreeSet::new(),
            dependents: BTreeSet::new(),
        };
        let json = serde_json::to_string(&node).unwrap();
        assert!(json.contains("\"id\""));
        assert!(json.contains("\"kind\""));
        assert!(json.contains("\"status\""));
        assert!(json.contains("\"depth\""));
        assert!(json.contains("\"generation\""));
        assert!(json.contains("\"dependencies\""));
        assert!(json.contains("\"dependents\""));
    }

    #[test]
    fn json_field_presence_wasm_budget() {
        let budget = WasmBudget::default_budget();
        let json = serde_json::to_string(&budget).unwrap();
        assert!(json.contains("\"max_signals\""));
        assert!(json.contains("\"max_depth\""));
        assert!(json.contains("\"max_pending_updates\""));
        assert!(json.contains("\"max_dom_ops_per_cycle\""));
        assert!(json.contains("\"max_evaluations_per_flush\""));
    }

    #[test]
    fn json_field_presence_abi_dom_batch() {
        let batch = AbiDomBatch::new(42);
        let json = serde_json::to_string(&batch).unwrap();
        assert!(json.contains("\"ops\""));
        assert!(json.contains("\"cycle\""));
    }

    #[test]
    fn serde_roundtrip_lane_with_signals() {
        let mut lane = WasmRuntimeLane::with_defaults();
        let s = lane.graph.next_id();
        lane.graph
            .register(s, WasmSignalKind::Source, BTreeSet::new())
            .unwrap();
        let d = lane.graph.next_id();
        let mut deps = BTreeSet::new();
        deps.insert(s);
        lane.graph
            .register(d, WasmSignalKind::Derived, deps)
            .unwrap();
        lane.enqueue_update(AbiStateUpdate {
            signal_id: s,
            payload: vec![1, 2, 3],
            sequence: 0,
        })
        .unwrap();
        let json = serde_json::to_string(&lane).unwrap();
        let restored: WasmRuntimeLane = serde_json::from_str(&json).unwrap();
        assert_eq!(lane, restored);
    }

    #[test]
    fn bounded_queue_capacity_zero_always_full() {
        let mut q = BoundedQueue::<u32>::new(0);
        assert!(q.is_full());
        assert!(q.is_empty());
        let err = q.push(1).unwrap_err();
        assert_eq!(err, QueueError::Full { capacity: 0 });
    }

    #[test]
    fn graph_zero_max_nodes_rejects_all() {
        let mut g = WasmSignalGraph::new(64, 0);
        let id = g.next_id();
        let err = g
            .register(id, WasmSignalKind::Source, BTreeSet::new())
            .unwrap_err();
        assert!(matches!(err, WasmGraphError::BudgetExceeded { .. }));
    }

    #[test]
    fn graph_mark_clean_nonexistent_returns_not_found() {
        let mut g = WasmSignalGraph::new(64, 100);
        let err = g.mark_clean(WasmSignalId(999)).unwrap_err();
        assert!(matches!(err, WasmGraphError::NotFound(_)));
    }

    #[test]
    fn graph_dispose_nonexistent_returns_not_found() {
        let g = WasmSignalGraph::new(64, 100);
        let err = g.clone().dispose(WasmSignalId(999)).unwrap_err();
        assert!(matches!(err, WasmGraphError::NotFound(_)));
    }
}
