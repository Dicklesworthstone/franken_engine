#![forbid(unsafe_code)]

//! Integration tests for `wasm_runtime_lane` module.
//! Exercises the public API from outside the crate boundary.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::wasm_runtime_lane::{
    AbiDomBatch, AbiDomOp, AbiStateUpdate, BoundedQueue, QueueError, SafeModeReason, WasmBudget,
    WasmFlushResult, WasmGraphError, WasmLaneMode, WasmRuntimeLane, WasmSignalGraph, WasmSignalId,
    WasmSignalKind, WasmSignalNode, WasmSignalStatus,
};
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Helper constructors
// ---------------------------------------------------------------------------

fn small_budget() -> WasmBudget {
    WasmBudget {
        max_signals: 10,
        max_depth: 4,
        max_pending_updates: 5,
        max_dom_ops_per_cycle: 3,
        max_evaluations_per_flush: 20,
    }
}

fn tiny_budget() -> WasmBudget {
    WasmBudget {
        max_signals: 3,
        max_depth: 2,
        max_pending_updates: 2,
        max_dom_ops_per_cycle: 1,
        max_evaluations_per_flush: 5,
    }
}

fn make_update(signal_id: u32, seq: u64) -> AbiStateUpdate {
    AbiStateUpdate {
        signal_id: WasmSignalId(signal_id),
        payload: vec![0xAB, 0xCD],
        sequence: seq,
    }
}

fn deps(ids: &[u32]) -> BTreeSet<WasmSignalId> {
    ids.iter().map(|i| WasmSignalId(*i)).collect()
}

// ===========================================================================
// Section 1 — WasmSignalId
// ===========================================================================

#[test]
fn signal_id_new_value() {
    let id = WasmSignalId(42);
    assert_eq!(id.0, 42);
}

#[test]
fn signal_id_ord() {
    let a = WasmSignalId(1);
    let b = WasmSignalId(2);
    assert!(a < b);
}

#[test]
fn signal_id_serde_roundtrip() {
    let id = WasmSignalId(999);
    let json = serde_json::to_string(&id).unwrap();
    let back: WasmSignalId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

#[test]
fn signal_id_debug() {
    let id = WasmSignalId(7);
    let s = format!("{:?}", id);
    assert!(s.contains("7"));
}

// ===========================================================================
// Section 2 — WasmSignalKind
// ===========================================================================

#[test]
fn signal_kind_variants_exist() {
    let _ = WasmSignalKind::Source;
    let _ = WasmSignalKind::Derived;
    let _ = WasmSignalKind::Effect;
}

#[test]
fn signal_kind_serde_roundtrip() {
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

#[test]
fn signal_kind_ord() {
    // Derived order: Source < Derived < Effect
    assert!(WasmSignalKind::Source < WasmSignalKind::Derived);
    assert!(WasmSignalKind::Derived < WasmSignalKind::Effect);
}

// ===========================================================================
// Section 3 — WasmSignalStatus
// ===========================================================================

#[test]
fn signal_status_variants_exist() {
    let _ = WasmSignalStatus::Clean;
    let _ = WasmSignalStatus::Dirty;
    let _ = WasmSignalStatus::Evaluating;
    let _ = WasmSignalStatus::Disposed;
}

#[test]
fn signal_status_serde_roundtrip() {
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

#[test]
fn signal_status_ord() {
    assert!(WasmSignalStatus::Clean < WasmSignalStatus::Dirty);
    assert!(WasmSignalStatus::Dirty < WasmSignalStatus::Evaluating);
    assert!(WasmSignalStatus::Evaluating < WasmSignalStatus::Disposed);
}

// ===========================================================================
// Section 4 — WasmSignalNode
// ===========================================================================

#[test]
fn signal_node_construction_and_fields() {
    let node = WasmSignalNode {
        id: WasmSignalId(0),
        kind: WasmSignalKind::Source,
        status: WasmSignalStatus::Dirty,
        depth: 0,
        generation: 1,
        dependencies: BTreeSet::new(),
        dependents: BTreeSet::new(),
    };
    assert_eq!(node.id, WasmSignalId(0));
    assert_eq!(node.kind, WasmSignalKind::Source);
    assert_eq!(node.status, WasmSignalStatus::Dirty);
    assert_eq!(node.depth, 0);
    assert_eq!(node.generation, 1);
    assert!(node.dependencies.is_empty());
    assert!(node.dependents.is_empty());
}

#[test]
fn signal_node_serde_roundtrip() {
    let mut dep_set = BTreeSet::new();
    dep_set.insert(WasmSignalId(1));
    let node = WasmSignalNode {
        id: WasmSignalId(2),
        kind: WasmSignalKind::Derived,
        status: WasmSignalStatus::Clean,
        depth: 1,
        generation: 5,
        dependencies: dep_set,
        dependents: BTreeSet::new(),
    };
    let json = serde_json::to_string(&node).unwrap();
    let back: WasmSignalNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

// ===========================================================================
// Section 5 — BoundedQueue
// ===========================================================================

#[test]
fn queue_new_empty() {
    let q: BoundedQueue<u32> = BoundedQueue::new(10);
    assert!(q.is_empty());
    assert!(!q.is_full());
    assert_eq!(q.len(), 0);
    assert_eq!(q.capacity(), 10);
}

#[test]
fn queue_push_pop_fifo() {
    let mut q = BoundedQueue::new(4);
    q.push(1u32).unwrap();
    q.push(2).unwrap();
    q.push(3).unwrap();
    assert_eq!(q.len(), 3);
    assert_eq!(q.pop().unwrap(), 1);
    assert_eq!(q.pop().unwrap(), 2);
    assert_eq!(q.pop().unwrap(), 3);
    assert!(q.is_empty());
}

#[test]
fn queue_full_rejects() {
    let mut q = BoundedQueue::new(2);
    q.push(10u32).unwrap();
    q.push(20).unwrap();
    assert!(q.is_full());
    let err = q.push(30).unwrap_err();
    assert_eq!(err, QueueError::Full { capacity: 2 });
}

#[test]
fn queue_pop_empty_errors() {
    let mut q: BoundedQueue<u32> = BoundedQueue::new(5);
    assert_eq!(q.pop().unwrap_err(), QueueError::Empty);
}

#[test]
fn queue_drain_all() {
    let mut q = BoundedQueue::new(5);
    q.push(1u32).unwrap();
    q.push(2).unwrap();
    q.push(3).unwrap();
    let items = q.drain_all();
    assert_eq!(items, vec![1, 2, 3]);
    assert!(q.is_empty());
    assert!(!q.is_full());
}

#[test]
fn queue_clear() {
    let mut q = BoundedQueue::new(5);
    q.push(1u32).unwrap();
    q.push(2).unwrap();
    q.clear();
    assert!(q.is_empty());
    assert_eq!(q.len(), 0);
    // Can push again after clear
    q.push(99).unwrap();
    assert_eq!(q.len(), 1);
}

#[test]
fn queue_serde_roundtrip() {
    let mut q = BoundedQueue::new(5);
    q.push(42u32).unwrap();
    q.push(43).unwrap();
    let json = serde_json::to_string(&q).unwrap();
    let back: BoundedQueue<u32> = serde_json::from_str(&json).unwrap();
    assert_eq!(q, back);
}

#[test]
fn queue_error_serde_roundtrip() {
    let err_full = QueueError::Full { capacity: 100 };
    let json = serde_json::to_string(&err_full).unwrap();
    let back: QueueError = serde_json::from_str(&json).unwrap();
    assert_eq!(err_full, back);

    let err_empty = QueueError::Empty;
    let json2 = serde_json::to_string(&err_empty).unwrap();
    let back2: QueueError = serde_json::from_str(&json2).unwrap();
    assert_eq!(err_empty, back2);
}

// ===========================================================================
// Section 6 — WasmSignalGraph
// ===========================================================================

#[test]
fn graph_new_empty() {
    let g = WasmSignalGraph::new(64, 1000);
    assert_eq!(g.active_count(), 0);
    assert_eq!(g.max_depth, 64);
    assert_eq!(g.max_nodes, 1000);
}

#[test]
fn graph_next_id_increments() {
    let mut g = WasmSignalGraph::new(64, 1000);
    let a = g.next_id();
    let b = g.next_id();
    let c = g.next_id();
    assert_eq!(a, WasmSignalId(0));
    assert_eq!(b, WasmSignalId(1));
    assert_eq!(c, WasmSignalId(2));
}

#[test]
fn graph_register_source_signal() {
    let mut g = WasmSignalGraph::new(64, 1000);
    let id = g.next_id();
    g.register(id, WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    assert_eq!(g.active_count(), 1);
    let node = g.get(id).unwrap();
    assert_eq!(node.kind, WasmSignalKind::Source);
    assert_eq!(node.depth, 0);
    assert_eq!(node.status, WasmSignalStatus::Dirty);
}

#[test]
fn graph_register_derived_depth() {
    let mut g = WasmSignalGraph::new(64, 1000);
    let s = g.next_id();
    g.register(s, WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let d = g.next_id();
    g.register(d, WasmSignalKind::Derived, deps(&[0])).unwrap();
    assert_eq!(g.get(d).unwrap().depth, 1);
    // Verify dependency linkage
    assert!(g.get(s).unwrap().dependents.contains(&d));
    assert!(g.get(d).unwrap().dependencies.contains(&s));
}

#[test]
fn graph_register_duplicate_error() {
    let mut g = WasmSignalGraph::new(64, 1000);
    let id = g.next_id();
    g.register(id, WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let err = g
        .register(id, WasmSignalKind::Source, BTreeSet::new())
        .unwrap_err();
    assert!(matches!(err, WasmGraphError::DuplicateSignal(_)));
}

#[test]
fn graph_register_dep_not_found() {
    let mut g = WasmSignalGraph::new(64, 1000);
    let id = g.next_id();
    let err = g
        .register(id, WasmSignalKind::Derived, deps(&[999]))
        .unwrap_err();
    assert!(matches!(
        err,
        WasmGraphError::DepNotFound(WasmSignalId(999))
    ));
}

#[test]
fn graph_register_depth_exceeded() {
    let mut g = WasmSignalGraph::new(1, 100);
    // Depth 0
    let s = g.next_id();
    g.register(s, WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    // Depth 1 — ok
    let d1 = g.next_id();
    g.register(d1, WasmSignalKind::Derived, deps(&[s.0]))
        .unwrap();
    // Depth 2 — exceeds max_depth=1
    let d2 = g.next_id();
    let err = g
        .register(d2, WasmSignalKind::Derived, deps(&[d1.0]))
        .unwrap_err();
    assert!(matches!(err, WasmGraphError::DepthExceeded { .. }));
}

#[test]
fn graph_register_node_limit() {
    let mut g = WasmSignalGraph::new(64, 2);
    let a = g.next_id();
    g.register(a, WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let b = g.next_id();
    g.register(b, WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    assert_eq!(g.active_count(), 2);
    let c = g.next_id();
    let err = g
        .register(c, WasmSignalKind::Source, BTreeSet::new())
        .unwrap_err();
    assert!(matches!(err, WasmGraphError::BudgetExceeded { .. }));
}

#[test]
fn graph_propagate_dirty_linear_chain() {
    let mut g = WasmSignalGraph::new(64, 100);
    let s = g.next_id();
    g.register(s, WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let d1 = g.next_id();
    g.register(d1, WasmSignalKind::Derived, deps(&[s.0]))
        .unwrap();
    let d2 = g.next_id();
    g.register(d2, WasmSignalKind::Derived, deps(&[d1.0]))
        .unwrap();
    // Mark s clean first, then propagate dirty
    g.mark_clean(s).unwrap();
    g.mark_clean(d1).unwrap();
    g.mark_clean(d2).unwrap();

    let dirty = g.propagate_dirty(s).unwrap();
    // Should return s, d1, d2 in topological (depth) order
    assert_eq!(dirty.len(), 3);
    assert_eq!(dirty[0], s);
    assert_eq!(dirty[1], d1);
    assert_eq!(dirty[2], d2);
}

#[test]
fn graph_propagate_dirty_not_found() {
    let mut g = WasmSignalGraph::new(64, 100);
    let err = g.propagate_dirty(WasmSignalId(999)).unwrap_err();
    assert!(matches!(err, WasmGraphError::NotFound(WasmSignalId(999))));
}

#[test]
fn graph_propagate_dirty_disposed_error() {
    let mut g = WasmSignalGraph::new(64, 100);
    let s = g.next_id();
    g.register(s, WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    g.dispose(s).unwrap();
    let err = g.propagate_dirty(s).unwrap_err();
    assert!(matches!(err, WasmGraphError::Disposed(_)));
}

#[test]
fn graph_mark_clean() {
    let mut g = WasmSignalGraph::new(64, 100);
    let s = g.next_id();
    g.register(s, WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    assert_eq!(g.get(s).unwrap().status, WasmSignalStatus::Dirty);
    g.mark_clean(s).unwrap();
    assert_eq!(g.get(s).unwrap().status, WasmSignalStatus::Clean);
}

#[test]
fn graph_mark_clean_not_found() {
    let mut g = WasmSignalGraph::new(64, 100);
    let err = g.mark_clean(WasmSignalId(42)).unwrap_err();
    assert!(matches!(err, WasmGraphError::NotFound(_)));
}

#[test]
fn graph_mark_clean_disposed_error() {
    let mut g = WasmSignalGraph::new(64, 100);
    let s = g.next_id();
    g.register(s, WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    g.dispose(s).unwrap();
    let err = g.mark_clean(s).unwrap_err();
    assert!(matches!(err, WasmGraphError::Disposed(_)));
}

#[test]
fn graph_dispose_removes_links() {
    let mut g = WasmSignalGraph::new(64, 100);
    let s = g.next_id();
    g.register(s, WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let d = g.next_id();
    g.register(d, WasmSignalKind::Derived, deps(&[s.0]))
        .unwrap();
    g.dispose(d).unwrap();
    // d is disposed
    assert_eq!(g.get(d).unwrap().status, WasmSignalStatus::Disposed);
    assert!(g.get(d).unwrap().dependencies.is_empty());
    assert!(g.get(d).unwrap().dependents.is_empty());
    // s no longer lists d as dependent
    assert!(!g.get(s).unwrap().dependents.contains(&d));
}

#[test]
fn graph_dispose_not_found() {
    let mut g = WasmSignalGraph::new(64, 100);
    let err = g.dispose(WasmSignalId(123)).unwrap_err();
    assert!(matches!(err, WasmGraphError::NotFound(_)));
}

#[test]
fn graph_get_nonexistent_returns_none() {
    let g = WasmSignalGraph::new(64, 100);
    assert!(g.get(WasmSignalId(0)).is_none());
}

#[test]
fn graph_serde_roundtrip() {
    let mut g = WasmSignalGraph::new(16, 100);
    let s = g.next_id();
    g.register(s, WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let json = serde_json::to_string(&g).unwrap();
    let back: WasmSignalGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(g, back);
}

// ===========================================================================
// Section 7 — WasmGraphError
// ===========================================================================

#[test]
fn graph_error_serde_roundtrip() {
    let errors = vec![
        WasmGraphError::NotFound(WasmSignalId(1)),
        WasmGraphError::Disposed(WasmSignalId(2)),
        WasmGraphError::DuplicateSignal(WasmSignalId(3)),
        WasmGraphError::DepNotFound(WasmSignalId(4)),
        WasmGraphError::DepthExceeded {
            signal: WasmSignalId(5),
            depth: 10,
            max: 8,
        },
        WasmGraphError::BudgetExceeded {
            metric: "nodes".into(),
            current: 100,
            limit: 50,
        },
    ];
    for err in errors {
        let json = serde_json::to_string(&err).unwrap();
        let back: WasmGraphError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }
}

// ===========================================================================
// Section 8 — ABI types
// ===========================================================================

#[test]
fn abi_state_update_construction() {
    let u = AbiStateUpdate {
        signal_id: WasmSignalId(3),
        payload: vec![1, 2, 3],
        sequence: 42,
    };
    assert_eq!(u.signal_id, WasmSignalId(3));
    assert_eq!(u.payload, vec![1, 2, 3]);
    assert_eq!(u.sequence, 42);
}

#[test]
fn abi_state_update_serde_roundtrip() {
    let u = AbiStateUpdate {
        signal_id: WasmSignalId(7),
        payload: vec![0xFF, 0x00],
        sequence: 100,
    };
    let json = serde_json::to_string(&u).unwrap();
    let back: AbiStateUpdate = serde_json::from_str(&json).unwrap();
    assert_eq!(u, back);
}

#[test]
fn abi_dom_op_target_element() {
    let ops = vec![
        (
            AbiDomOp::Create {
                element_id: 1,
                tag_index: 0,
            },
            1,
        ),
        (AbiDomOp::Remove { element_id: 2 }, 2),
        (
            AbiDomOp::SetProp {
                element_id: 3,
                prop_index: 1,
                value: vec![],
            },
            3,
        ),
        (
            AbiDomOp::RemoveProp {
                element_id: 4,
                prop_index: 2,
            },
            4,
        ),
        (
            AbiDomOp::SetText {
                element_id: 5,
                text: vec![0x41],
            },
            5,
        ),
        (
            AbiDomOp::Move {
                element_id: 6,
                new_parent: 0,
                before: 0,
            },
            6,
        ),
    ];
    for (op, expected) in ops {
        assert_eq!(op.target_element(), expected);
    }
}

#[test]
fn abi_dom_op_serde_roundtrip() {
    let op = AbiDomOp::SetProp {
        element_id: 10,
        prop_index: 5,
        value: vec![1, 2],
    };
    let json = serde_json::to_string(&op).unwrap();
    let back: AbiDomOp = serde_json::from_str(&json).unwrap();
    assert_eq!(op, back);
}

#[test]
fn abi_dom_batch_new_and_push() {
    let mut batch = AbiDomBatch::new(42);
    assert!(batch.is_empty());
    assert_eq!(batch.cycle, 42);
    batch.push(AbiDomOp::Create {
        element_id: 1,
        tag_index: 0,
    });
    assert!(!batch.is_empty());
    assert_eq!(batch.ops.len(), 1);
}

#[test]
fn abi_dom_batch_derive_id_deterministic() {
    let mut b1 = AbiDomBatch::new(1);
    b1.push(AbiDomOp::Remove { element_id: 10 });
    let mut b2 = AbiDomBatch::new(1);
    b2.push(AbiDomOp::Remove { element_id: 10 });
    // Same cycle + same ops count => same id
    assert_eq!(b1.derive_id(), b2.derive_id());
}

#[test]
fn abi_dom_batch_derive_id_changes_with_cycle() {
    let b1 = AbiDomBatch::new(1);
    let b2 = AbiDomBatch::new(2);
    assert_ne!(b1.derive_id(), b2.derive_id());
}

#[test]
fn abi_dom_batch_serde_roundtrip() {
    let mut batch = AbiDomBatch::new(10);
    batch.push(AbiDomOp::Create {
        element_id: 1,
        tag_index: 5,
    });
    batch.push(AbiDomOp::SetText {
        element_id: 1,
        text: b"hello".to_vec(),
    });
    let json = serde_json::to_string(&batch).unwrap();
    let back: AbiDomBatch = serde_json::from_str(&json).unwrap();
    assert_eq!(batch, back);
}

// ===========================================================================
// Section 9 — WasmBudget
// ===========================================================================

#[test]
fn budget_default_values() {
    let b = WasmBudget::default_budget();
    assert_eq!(b.max_signals, 50_000);
    assert_eq!(b.max_depth, 128);
    assert_eq!(b.max_pending_updates, 10_000);
    assert_eq!(b.max_dom_ops_per_cycle, 50_000);
    assert_eq!(b.max_evaluations_per_flush, 100_000);
}

#[test]
fn budget_validate_ok() {
    let b = WasmBudget::default_budget();
    assert!(b.validate().is_empty());
}

#[test]
fn budget_validate_zero_signals() {
    let mut b = WasmBudget::default_budget();
    b.max_signals = 0;
    let errors = b.validate();
    assert!(errors.iter().any(|e| e.contains("max_signals")));
}

#[test]
fn budget_validate_zero_depth() {
    let mut b = WasmBudget::default_budget();
    b.max_depth = 0;
    let errors = b.validate();
    assert!(errors.iter().any(|e| e.contains("max_depth")));
}

#[test]
fn budget_validate_zero_pending() {
    let mut b = WasmBudget::default_budget();
    b.max_pending_updates = 0;
    let errors = b.validate();
    assert!(errors.iter().any(|e| e.contains("max_pending_updates")));
}

#[test]
fn budget_validate_zero_dom_ops() {
    let mut b = WasmBudget::default_budget();
    b.max_dom_ops_per_cycle = 0;
    let errors = b.validate();
    assert!(errors.iter().any(|e| e.contains("max_dom_ops_per_cycle")));
}

#[test]
fn budget_validate_multiple_errors() {
    let b = WasmBudget {
        max_signals: 0,
        max_depth: 0,
        max_pending_updates: 0,
        max_dom_ops_per_cycle: 0,
        max_evaluations_per_flush: 100,
    };
    let errors = b.validate();
    assert_eq!(errors.len(), 4);
}

#[test]
fn budget_serde_roundtrip() {
    let b = small_budget();
    let json = serde_json::to_string(&b).unwrap();
    let back: WasmBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

// ===========================================================================
// Section 10 — WasmLaneMode
// ===========================================================================

#[test]
fn lane_mode_variants() {
    let modes = [
        WasmLaneMode::Normal,
        WasmLaneMode::Safe,
        WasmLaneMode::Degraded,
        WasmLaneMode::Halted,
    ];
    // All distinct
    for (i, a) in modes.iter().enumerate() {
        for (j, b) in modes.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn lane_mode_ord() {
    assert!(WasmLaneMode::Normal < WasmLaneMode::Safe);
    assert!(WasmLaneMode::Safe < WasmLaneMode::Degraded);
    assert!(WasmLaneMode::Degraded < WasmLaneMode::Halted);
}

#[test]
fn lane_mode_serde_roundtrip() {
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

// ===========================================================================
// Section 11 — SafeModeReason
// ===========================================================================

#[test]
fn safe_mode_reason_serde_roundtrip() {
    let reasons = vec![
        SafeModeReason::QueueOverflow {
            queue_len: 100,
            limit: 50,
        },
        SafeModeReason::DepthExceeded {
            depth: 20,
            limit: 10,
        },
        SafeModeReason::EvalBudgetExhausted {
            evals: 500,
            limit: 200,
        },
        SafeModeReason::DomOpBudgetExhausted {
            ops: 1000,
            limit: 500,
        },
        SafeModeReason::SignalBudgetExhausted {
            signals: 100,
            limit: 50,
        },
    ];
    for reason in reasons {
        let json = serde_json::to_string(&reason).unwrap();
        let back: SafeModeReason = serde_json::from_str(&json).unwrap();
        assert_eq!(reason, back);
    }
}

// ===========================================================================
// Section 12 — WasmFlushResult
// ===========================================================================

#[test]
fn flush_result_derive_id_deterministic() {
    let r1 = WasmFlushResult {
        cycle: 0,
        updates_consumed: 5,
        signals_evaluated: 10,
        dom_ops_emitted: 3,
        mode_after: WasmLaneMode::Normal,
        safe_mode_triggers: Vec::new(),
    };
    let r2 = r1.clone();
    assert_eq!(r1.derive_id(), r2.derive_id());
}

#[test]
fn flush_result_derive_id_varies_with_cycle() {
    let r1 = WasmFlushResult {
        cycle: 0,
        updates_consumed: 0,
        signals_evaluated: 0,
        dom_ops_emitted: 0,
        mode_after: WasmLaneMode::Normal,
        safe_mode_triggers: Vec::new(),
    };
    let r2 = WasmFlushResult {
        cycle: 1,
        ..r1.clone()
    };
    assert_ne!(r1.derive_id(), r2.derive_id());
}

#[test]
fn flush_result_serde_roundtrip() {
    let r = WasmFlushResult {
        cycle: 5,
        updates_consumed: 3,
        signals_evaluated: 10,
        dom_ops_emitted: 2,
        mode_after: WasmLaneMode::Degraded,
        safe_mode_triggers: vec![SafeModeReason::EvalBudgetExhausted {
            evals: 10,
            limit: 10,
        }],
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: WasmFlushResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ===========================================================================
// Section 13 — WasmRuntimeLane construction
// ===========================================================================

#[test]
fn lane_new_from_budget() {
    let lane = WasmRuntimeLane::new(small_budget());
    assert_eq!(lane.mode, WasmLaneMode::Normal);
    assert_eq!(lane.flush_count, 0);
    assert_eq!(lane.total_evaluations, 0);
    assert_eq!(lane.total_dom_ops, 0);
    assert!(lane.safe_mode_triggers.is_empty());
    assert!(lane.update_queue.is_empty());
    assert_eq!(lane.graph.active_count(), 0);
}

#[test]
fn lane_with_defaults() {
    let lane = WasmRuntimeLane::with_defaults();
    assert_eq!(lane.budget, WasmBudget::default_budget());
    assert_eq!(lane.mode, WasmLaneMode::Normal);
}

#[test]
fn lane_derive_id_deterministic() {
    let a = WasmRuntimeLane::new(small_budget());
    let b = WasmRuntimeLane::new(small_budget());
    assert_eq!(a.derive_id(), b.derive_id());
}

// ===========================================================================
// Section 14 — WasmRuntimeLane::register_signal
// ===========================================================================

#[test]
fn lane_register_signal_source() {
    let mut lane = WasmRuntimeLane::new(small_budget());
    let id = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    assert_eq!(id, WasmSignalId(0));
    assert_eq!(lane.graph.active_count(), 1);
}

#[test]
fn lane_register_signal_derived_with_deps() {
    let mut lane = WasmRuntimeLane::new(small_budget());
    let s = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let d = lane
        .register_signal(WasmSignalKind::Derived, deps(&[s.0]))
        .unwrap();
    assert_eq!(lane.graph.get(d).unwrap().depth, 1);
}

#[test]
fn lane_register_signal_depth_exceeded_enters_safe_mode() {
    // Need enough signal slots but shallow max_depth
    let budget = WasmBudget {
        max_signals: 10,
        max_depth: 2,
        max_pending_updates: 5,
        max_dom_ops_per_cycle: 10,
        max_evaluations_per_flush: 20,
    };
    let mut lane = WasmRuntimeLane::new(budget);
    let s = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let d1 = lane
        .register_signal(WasmSignalKind::Derived, deps(&[s.0]))
        .unwrap();
    let d2 = lane
        .register_signal(WasmSignalKind::Derived, deps(&[d1.0]))
        .unwrap();
    // depth 3 exceeds max_depth=2
    let err = lane
        .register_signal(WasmSignalKind::Derived, deps(&[d2.0]))
        .unwrap_err();
    assert!(matches!(err, WasmGraphError::DepthExceeded { .. }));
    assert_eq!(lane.mode, WasmLaneMode::Safe);
    assert!(
        lane.safe_mode_triggers
            .iter()
            .any(|r| matches!(r, SafeModeReason::DepthExceeded { .. }))
    );
}

#[test]
fn lane_register_signal_budget_exceeded_enters_safe_mode() {
    let mut lane = WasmRuntimeLane::new(tiny_budget()); // max_signals = 3
    lane.register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    lane.register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    lane.register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    // 4th exceeds max_signals=3
    let err = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap_err();
    assert!(matches!(err, WasmGraphError::BudgetExceeded { .. }));
    assert_eq!(lane.mode, WasmLaneMode::Safe);
    assert!(
        lane.safe_mode_triggers
            .iter()
            .any(|r| matches!(r, SafeModeReason::SignalBudgetExhausted { .. }))
    );
}

// ===========================================================================
// Section 15 — WasmRuntimeLane::enqueue_update
// ===========================================================================

#[test]
fn lane_enqueue_update_success() {
    let mut lane = WasmRuntimeLane::new(small_budget());
    let s = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    lane.enqueue_update(make_update(s.0, 1)).unwrap();
    assert_eq!(lane.update_queue.len(), 1);
}

#[test]
fn lane_enqueue_update_queue_overflow() {
    let mut lane = WasmRuntimeLane::new(tiny_budget()); // max_pending_updates = 2
    let _s = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    lane.enqueue_update(make_update(0, 1)).unwrap();
    lane.enqueue_update(make_update(0, 2)).unwrap();
    // 3rd overflows
    let err = lane.enqueue_update(make_update(0, 3)).unwrap_err();
    assert!(matches!(err, SafeModeReason::QueueOverflow { .. }));
    assert_eq!(lane.mode, WasmLaneMode::Safe);
}

// ===========================================================================
// Section 16 — WasmRuntimeLane::flush
// ===========================================================================

#[test]
fn lane_flush_empty() {
    let mut lane = WasmRuntimeLane::new(small_budget());
    let result = lane.flush();
    assert_eq!(result.cycle, 0);
    assert_eq!(result.updates_consumed, 0);
    assert_eq!(result.signals_evaluated, 0);
    assert_eq!(result.dom_ops_emitted, 0);
    assert_eq!(result.mode_after, WasmLaneMode::Normal);
    assert!(result.safe_mode_triggers.is_empty());
    assert_eq!(lane.flush_count, 1);
}

#[test]
fn lane_flush_with_source_update() {
    let mut lane = WasmRuntimeLane::new(small_budget());
    let s = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    // Mark clean first so propagate_dirty actually does something visible
    lane.graph.mark_clean(s).unwrap();
    lane.enqueue_update(make_update(s.0, 1)).unwrap();
    let result = lane.flush();
    assert_eq!(result.updates_consumed, 1);
    assert!(result.signals_evaluated >= 1);
    assert_eq!(result.cycle, 0);
    assert_eq!(lane.flush_count, 1);
}

#[test]
fn lane_flush_propagates_to_derived() {
    let mut lane = WasmRuntimeLane::new(small_budget());
    let s = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let d = lane
        .register_signal(WasmSignalKind::Derived, deps(&[s.0]))
        .unwrap();
    lane.graph.mark_clean(s).unwrap();
    lane.graph.mark_clean(d).unwrap();
    lane.enqueue_update(make_update(s.0, 1)).unwrap();
    let result = lane.flush();
    assert!(result.signals_evaluated >= 2);
    // Both should be clean after evaluation
    assert_eq!(lane.graph.get(s).unwrap().status, WasmSignalStatus::Clean);
    assert_eq!(lane.graph.get(d).unwrap().status, WasmSignalStatus::Clean);
}

#[test]
fn lane_flush_counts_effect_as_dom_op() {
    let mut lane = WasmRuntimeLane::new(small_budget());
    let s = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let e = lane
        .register_signal(WasmSignalKind::Effect, deps(&[s.0]))
        .unwrap();
    lane.graph.mark_clean(s).unwrap();
    lane.graph.mark_clean(e).unwrap();
    lane.enqueue_update(make_update(s.0, 1)).unwrap();
    let result = lane.flush();
    assert!(result.dom_ops_emitted >= 1);
    assert!(lane.total_dom_ops >= 1);
}

#[test]
fn lane_flush_eval_budget_exhaustion() {
    let budget = WasmBudget {
        max_signals: 10,
        max_depth: 4,
        max_pending_updates: 10,
        max_dom_ops_per_cycle: 100,
        max_evaluations_per_flush: 2, // Very small
    };
    let mut lane = WasmRuntimeLane::new(budget);
    let s1 = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let s2 = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let s3 = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    lane.graph.mark_clean(s1).unwrap();
    lane.graph.mark_clean(s2).unwrap();
    lane.graph.mark_clean(s3).unwrap();
    lane.enqueue_update(make_update(s1.0, 1)).unwrap();
    lane.enqueue_update(make_update(s2.0, 2)).unwrap();
    lane.enqueue_update(make_update(s3.0, 3)).unwrap();
    let result = lane.flush();
    assert_eq!(result.signals_evaluated, 2);
    assert!(
        result
            .safe_mode_triggers
            .iter()
            .any(|r| matches!(r, SafeModeReason::EvalBudgetExhausted { .. }))
    );
    assert_eq!(result.mode_after, WasmLaneMode::Degraded);
}

#[test]
fn lane_flush_dom_op_budget_exhaustion() {
    let budget = WasmBudget {
        max_signals: 10,
        max_depth: 4,
        max_pending_updates: 10,
        max_dom_ops_per_cycle: 1,
        max_evaluations_per_flush: 100,
    };
    let mut lane = WasmRuntimeLane::new(budget);
    let s = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let e1 = lane
        .register_signal(WasmSignalKind::Effect, deps(&[s.0]))
        .unwrap();
    let e2 = lane
        .register_signal(WasmSignalKind::Effect, deps(&[s.0]))
        .unwrap();
    lane.graph.mark_clean(s).unwrap();
    lane.graph.mark_clean(e1).unwrap();
    lane.graph.mark_clean(e2).unwrap();
    lane.enqueue_update(make_update(s.0, 1)).unwrap();
    let result = lane.flush();
    // At most 1 dom op allowed, but 2 effects need evaluation
    assert!(
        result
            .safe_mode_triggers
            .iter()
            .any(|r| matches!(r, SafeModeReason::DomOpBudgetExhausted { .. }))
    );
    assert_eq!(result.mode_after, WasmLaneMode::Degraded);
}

#[test]
fn lane_flush_increments_cycle() {
    let mut lane = WasmRuntimeLane::new(small_budget());
    let r1 = lane.flush();
    let r2 = lane.flush();
    let r3 = lane.flush();
    assert_eq!(r1.cycle, 0);
    assert_eq!(r2.cycle, 1);
    assert_eq!(r3.cycle, 2);
    assert_eq!(lane.flush_count, 3);
}

#[test]
fn lane_flush_accumulates_totals() {
    let mut lane = WasmRuntimeLane::new(small_budget());
    let s = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    lane.graph.mark_clean(s).unwrap();
    lane.enqueue_update(make_update(s.0, 1)).unwrap();
    lane.flush();
    lane.graph.mark_clean(s).unwrap();
    lane.enqueue_update(make_update(s.0, 2)).unwrap();
    lane.flush();
    assert!(lane.total_evaluations >= 2);
}

// ===========================================================================
// Section 17 — WasmRuntimeLane::reset_mode
// ===========================================================================

#[test]
fn lane_reset_mode() {
    let mut lane = WasmRuntimeLane::new(tiny_budget());
    // Fill queue to trigger safe mode
    let _s = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    lane.enqueue_update(make_update(0, 1)).unwrap();
    lane.enqueue_update(make_update(0, 2)).unwrap();
    let _ = lane.enqueue_update(make_update(0, 3)); // overflow => Safe
    assert_eq!(lane.mode, WasmLaneMode::Safe);
    lane.reset_mode();
    assert_eq!(lane.mode, WasmLaneMode::Normal);
    assert!(lane.safe_mode_triggers.is_empty());
}

// ===========================================================================
// Section 18 — Full lifecycle tests
// ===========================================================================

#[test]
fn lifecycle_register_enqueue_flush_dispose() {
    let mut lane = WasmRuntimeLane::new(small_budget());
    // Register source -> derived -> effect chain
    let s = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let d = lane
        .register_signal(WasmSignalKind::Derived, deps(&[s.0]))
        .unwrap();
    let e = lane
        .register_signal(WasmSignalKind::Effect, deps(&[d.0]))
        .unwrap();
    assert_eq!(lane.graph.active_count(), 3);

    // Mark all clean
    lane.graph.mark_clean(s).unwrap();
    lane.graph.mark_clean(d).unwrap();
    lane.graph.mark_clean(e).unwrap();

    // Enqueue update and flush
    lane.enqueue_update(make_update(s.0, 1)).unwrap();
    let result = lane.flush();
    assert_eq!(result.updates_consumed, 1);
    assert!(result.signals_evaluated >= 3);
    assert!(result.dom_ops_emitted >= 1);
    assert_eq!(result.mode_after, WasmLaneMode::Normal);

    // Dispose effect
    lane.graph.dispose(e).unwrap();
    assert_eq!(lane.graph.active_count(), 2);
    assert_eq!(
        lane.graph.get(e).unwrap().status,
        WasmSignalStatus::Disposed
    );
}

#[test]
fn lifecycle_multiple_flush_cycles() {
    let mut lane = WasmRuntimeLane::new(small_budget());
    let s1 = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let s2 = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let d = lane
        .register_signal(WasmSignalKind::Derived, deps(&[s1.0, s2.0]))
        .unwrap();

    // Cycle 0: update s1
    lane.graph.mark_clean(s1).unwrap();
    lane.graph.mark_clean(s2).unwrap();
    lane.graph.mark_clean(d).unwrap();
    lane.enqueue_update(make_update(s1.0, 1)).unwrap();
    let r0 = lane.flush();
    assert_eq!(r0.cycle, 0);
    assert!(r0.signals_evaluated >= 2); // s1 + d

    // Cycle 1: update s2
    lane.enqueue_update(make_update(s2.0, 2)).unwrap();
    let r1 = lane.flush();
    assert_eq!(r1.cycle, 1);
    assert!(r1.signals_evaluated >= 2); // s2 + d
}

#[test]
fn lifecycle_safe_mode_recovery() {
    let mut lane = WasmRuntimeLane::new(tiny_budget());
    let _s = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    lane.enqueue_update(make_update(0, 1)).unwrap();
    lane.enqueue_update(make_update(0, 2)).unwrap();
    // Overflow triggers safe mode
    let _ = lane.enqueue_update(make_update(0, 3));
    assert_eq!(lane.mode, WasmLaneMode::Safe);
    // Drain the queue via flush and reset
    lane.flush();
    lane.reset_mode();
    assert_eq!(lane.mode, WasmLaneMode::Normal);
    assert!(lane.safe_mode_triggers.is_empty());
    // Can continue working
    lane.enqueue_update(make_update(0, 4)).unwrap();
    assert_eq!(lane.update_queue.len(), 1);
}

#[test]
fn lifecycle_serde_full_lane_roundtrip() {
    let mut lane = WasmRuntimeLane::new(small_budget());
    let s = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let _d = lane
        .register_signal(WasmSignalKind::Derived, deps(&[s.0]))
        .unwrap();
    lane.enqueue_update(make_update(s.0, 1)).unwrap();
    lane.flush();

    let json = serde_json::to_string(&lane).unwrap();
    let back: WasmRuntimeLane = serde_json::from_str(&json).unwrap();
    assert_eq!(lane, back);
}

#[test]
fn lifecycle_derive_id_changes_after_flush() {
    let mut lane = WasmRuntimeLane::new(small_budget());
    let id_before = lane.derive_id();
    let _s = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    lane.flush();
    let id_after = lane.derive_id();
    // Different because active_count and flush_count changed
    assert_ne!(id_before, id_after);
}

#[test]
fn lifecycle_diamond_dependency_graph() {
    let mut lane = WasmRuntimeLane::new(small_budget());
    //   s
    //  / \
    // d1  d2
    //  \ /
    //   e
    let s = lane
        .register_signal(WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let d1 = lane
        .register_signal(WasmSignalKind::Derived, deps(&[s.0]))
        .unwrap();
    let d2 = lane
        .register_signal(WasmSignalKind::Derived, deps(&[s.0]))
        .unwrap();
    let e = lane
        .register_signal(WasmSignalKind::Effect, deps(&[d1.0, d2.0]))
        .unwrap();

    lane.graph.mark_clean(s).unwrap();
    lane.graph.mark_clean(d1).unwrap();
    lane.graph.mark_clean(d2).unwrap();
    lane.graph.mark_clean(e).unwrap();

    lane.enqueue_update(make_update(s.0, 1)).unwrap();
    let result = lane.flush();
    // All 4 signals should be evaluated: s, d1, d2, e
    assert_eq!(result.signals_evaluated, 4);
    assert!(result.dom_ops_emitted >= 1); // e is Effect
    assert_eq!(result.mode_after, WasmLaneMode::Normal);
}

#[test]
fn graph_disposed_node_frees_slot_for_new_registration() {
    let mut g = WasmSignalGraph::new(64, 2);
    let a = g.next_id();
    g.register(a, WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    let b = g.next_id();
    g.register(b, WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    assert_eq!(g.active_count(), 2);
    // Dispose a => active_count = 1
    g.dispose(a).unwrap();
    assert_eq!(g.active_count(), 1);
    // Now can register another
    let c = g.next_id();
    g.register(c, WasmSignalKind::Source, BTreeSet::new())
        .unwrap();
    assert_eq!(g.active_count(), 2);
}
