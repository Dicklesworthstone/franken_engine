//! Enrichment integration tests for `wasm_runtime_lane`.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::wasm_runtime_lane::*;

// ---------------------------------------------------------------------------
// WasmSignalKind serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_signal_kind_serde_roundtrip() {
    for kind in [
        WasmSignalKind::Source,
        WasmSignalKind::Derived,
        WasmSignalKind::Effect,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: WasmSignalKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

// ---------------------------------------------------------------------------
// WasmSignalStatus serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_signal_status_serde_roundtrip() {
    for status in [
        WasmSignalStatus::Clean,
        WasmSignalStatus::Dirty,
        WasmSignalStatus::Evaluating,
        WasmSignalStatus::Disposed,
    ] {
        let json = serde_json::to_string(&status).unwrap();
        let back: WasmSignalStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }
}

// ---------------------------------------------------------------------------
// BoundedQueue
// ---------------------------------------------------------------------------

#[test]
fn enrichment_bounded_queue_push_pop() {
    let mut q: BoundedQueue<u32> = BoundedQueue::new(4);
    q.push(1).unwrap();
    q.push(2).unwrap();
    assert_eq!(q.len(), 2);
    assert_eq!(q.pop().unwrap(), 1);
    assert_eq!(q.pop().unwrap(), 2);
}

#[test]
fn enrichment_bounded_queue_overflow() {
    let mut q: BoundedQueue<u32> = BoundedQueue::new(2);
    q.push(1).unwrap();
    q.push(2).unwrap();
    let result = q.push(3);
    assert!(result.is_err());
}

#[test]
fn enrichment_bounded_queue_underflow() {
    let mut q: BoundedQueue<u32> = BoundedQueue::new(4);
    let result = q.pop();
    assert!(result.is_err());
}

#[test]
fn enrichment_bounded_queue_is_full() {
    let mut q: BoundedQueue<u32> = BoundedQueue::new(1);
    assert!(!q.is_full());
    q.push(1).unwrap();
    assert!(q.is_full());
}

#[test]
fn enrichment_bounded_queue_drain_all() {
    let mut q: BoundedQueue<u32> = BoundedQueue::new(4);
    q.push(10).unwrap();
    q.push(20).unwrap();
    let drained = q.drain_all();
    assert_eq!(drained, vec![10, 20]);
    assert!(q.is_empty());
}

#[test]
fn enrichment_bounded_queue_clear() {
    let mut q: BoundedQueue<u32> = BoundedQueue::new(4);
    q.push(1).unwrap();
    q.clear();
    assert!(q.is_empty());
    assert_eq!(q.capacity(), 4);
}

// ---------------------------------------------------------------------------
// WasmSignalGraph
// ---------------------------------------------------------------------------

#[test]
fn enrichment_signal_graph_register_and_get() {
    let mut graph = WasmSignalGraph::new(8, 100);
    let id = WasmSignalId(0);
    graph.register(id, WasmSignalKind::Source, BTreeSet::new()).unwrap();
    let node = graph.get(id).unwrap();
    assert_eq!(node.kind, WasmSignalKind::Source);
}

#[test]
fn enrichment_signal_graph_active_count() {
    let mut graph = WasmSignalGraph::new(8, 100);
    assert_eq!(graph.active_count(), 0);
    let id = graph.next_id();
    graph.register(id, WasmSignalKind::Effect, BTreeSet::new()).unwrap();
    assert_eq!(graph.active_count(), 1);
}

#[test]
fn enrichment_signal_graph_propagate_dirty() {
    let mut graph = WasmSignalGraph::new(8, 100);
    let id1 = graph.next_id();
    graph.register(id1, WasmSignalKind::Source, BTreeSet::new()).unwrap();
    graph.mark_clean(id1).unwrap();
    let id2 = graph.next_id();
    graph.register(id2, WasmSignalKind::Derived, BTreeSet::from([id1])).unwrap();
    graph.mark_clean(id2).unwrap();

    let dirty = graph.propagate_dirty(id1).unwrap();
    assert!(dirty.contains(&id2));
}

#[test]
fn enrichment_signal_graph_dispose() {
    let mut graph = WasmSignalGraph::new(8, 100);
    let id = graph.next_id();
    graph.register(id, WasmSignalKind::Source, BTreeSet::new()).unwrap();
    assert_eq!(graph.active_count(), 1);
    graph.dispose(id).unwrap();
    assert_eq!(graph.active_count(), 0);
}

#[test]
fn enrichment_signal_graph_max_nodes() {
    let mut graph = WasmSignalGraph::new(8, 2);
    let id1 = graph.next_id();
    graph.register(id1, WasmSignalKind::Source, BTreeSet::new()).unwrap();
    let id2 = graph.next_id();
    graph.register(id2, WasmSignalKind::Source, BTreeSet::new()).unwrap();
    let id3 = graph.next_id();
    let result = graph.register(id3, WasmSignalKind::Source, BTreeSet::new());
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// WasmBudget
// ---------------------------------------------------------------------------

#[test]
fn enrichment_wasm_budget_default_valid() {
    let budget = WasmBudget::default_budget();
    assert!(budget.validate().is_empty());
}

#[test]
fn enrichment_wasm_budget_zero_signals_invalid() {
    let mut budget = WasmBudget::default_budget();
    budget.max_signals = 0;
    assert!(!budget.validate().is_empty());
}

#[test]
fn enrichment_wasm_budget_serde_roundtrip() {
    let budget = WasmBudget::default_budget();
    let json = serde_json::to_string(&budget).unwrap();
    let back: WasmBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(budget, back);
}

// ---------------------------------------------------------------------------
// WasmLaneMode
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lane_mode_serde_roundtrip() {
    for mode in [
        WasmLaneMode::Normal,
        WasmLaneMode::Safe,
        WasmLaneMode::Degraded,
        WasmLaneMode::Halted,
    ] {
        let json = serde_json::to_string(&mode).unwrap();
        let back: WasmLaneMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, back);
    }
}

// ---------------------------------------------------------------------------
// SafeModeReason serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_safe_mode_reason_serde_roundtrip() {
    let reasons = vec![
        SafeModeReason::QueueOverflow { queue_len: 100, limit: 50 },
        SafeModeReason::DepthExceeded { depth: 16, limit: 8 },
        SafeModeReason::EvalBudgetExhausted { evals: 1000, limit: 500 },
        SafeModeReason::DomOpBudgetExhausted { ops: 200, limit: 100 },
        SafeModeReason::SignalBudgetExhausted { signals: 64, limit: 32 },
    ];
    for reason in &reasons {
        let json = serde_json::to_string(reason).unwrap();
        let back: SafeModeReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

// ---------------------------------------------------------------------------
// WasmRuntimeLane
// ---------------------------------------------------------------------------

#[test]
fn enrichment_runtime_lane_with_defaults() {
    let lane = WasmRuntimeLane::with_defaults();
    assert_eq!(lane.mode, WasmLaneMode::Normal);
    assert_eq!(lane.flush_count, 0);
}

#[test]
fn enrichment_runtime_lane_register_signal() {
    let mut lane = WasmRuntimeLane::with_defaults();
    let id = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    assert!(lane.graph.get(id).is_some());
}

#[test]
fn enrichment_runtime_lane_enqueue_update() {
    let mut lane = WasmRuntimeLane::with_defaults();
    let id = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let update = AbiStateUpdate {
        signal_id: id,
        payload: vec![1, 2, 3],
        sequence: 1,
    };
    lane.enqueue_update(update).unwrap();
    assert!(!lane.update_queue.is_empty());
}

#[test]
fn enrichment_runtime_lane_flush_empty() {
    let mut lane = WasmRuntimeLane::with_defaults();
    let result = lane.flush();
    assert_eq!(result.updates_consumed, 0);
    assert_eq!(result.signals_evaluated, 0);
    assert_eq!(result.mode_after, WasmLaneMode::Normal);
}

#[test]
fn enrichment_runtime_lane_flush_with_update() {
    let mut lane = WasmRuntimeLane::with_defaults();
    let id = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    lane.enqueue_update(AbiStateUpdate {
        signal_id: id,
        payload: vec![42],
        sequence: 1,
    })
    .unwrap();
    let result = lane.flush();
    assert!(result.updates_consumed >= 1);
}

#[test]
fn enrichment_runtime_lane_reset_mode() {
    let mut lane = WasmRuntimeLane::with_defaults();
    lane.mode = WasmLaneMode::Safe;
    lane.reset_mode();
    assert_eq!(lane.mode, WasmLaneMode::Normal);
}

// ---------------------------------------------------------------------------
// AbiDomOp
// ---------------------------------------------------------------------------

#[test]
fn enrichment_abi_dom_op_target_element() {
    let op = AbiDomOp::Create { element_id: 42, tag_index: 1 };
    assert_eq!(op.target_element(), 42);
}

#[test]
fn enrichment_abi_dom_op_remove_target() {
    let op = AbiDomOp::Remove { element_id: 7 };
    assert_eq!(op.target_element(), 7);
}

#[test]
fn enrichment_abi_dom_op_serde_roundtrip() {
    let ops = vec![
        AbiDomOp::Create { element_id: 1, tag_index: 0 },
        AbiDomOp::Remove { element_id: 2 },
        AbiDomOp::SetProp { element_id: 3, prop_index: 0, value: vec![1, 2] },
        AbiDomOp::SetText { element_id: 4, text: vec![65, 66] },
    ];
    for op in &ops {
        let json = serde_json::to_string(op).unwrap();
        let back: AbiDomOp = serde_json::from_str(&json).unwrap();
        assert_eq!(*op, back);
    }
}

// ---------------------------------------------------------------------------
// AbiDomBatch
// ---------------------------------------------------------------------------

#[test]
fn enrichment_abi_dom_batch_empty() {
    let batch = AbiDomBatch::new(1);
    assert!(batch.is_empty());
    assert_eq!(batch.cycle, 1);
}

#[test]
fn enrichment_abi_dom_batch_push_and_derive_id() {
    let mut batch = AbiDomBatch::new(1);
    batch.push(AbiDomOp::Create { element_id: 1, tag_index: 0 });
    assert!(!batch.is_empty());
    let _id = batch.derive_id();
}

// ---------------------------------------------------------------------------
// WasmFlushResult
// ---------------------------------------------------------------------------

#[test]
fn enrichment_flush_result_derive_id_deterministic() {
    let result = WasmFlushResult {
        cycle: 1,
        updates_consumed: 5,
        signals_evaluated: 3,
        dom_ops_emitted: 2,
        mode_after: WasmLaneMode::Normal,
        safe_mode_triggers: vec![],
    };
    let id1 = result.derive_id();
    let id2 = result.derive_id();
    assert_eq!(id1, id2);
}

#[test]
fn enrichment_flush_result_serde_roundtrip() {
    let result = WasmFlushResult {
        cycle: 10,
        updates_consumed: 1,
        signals_evaluated: 1,
        dom_ops_emitted: 0,
        mode_after: WasmLaneMode::Normal,
        safe_mode_triggers: vec![],
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: WasmFlushResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}
