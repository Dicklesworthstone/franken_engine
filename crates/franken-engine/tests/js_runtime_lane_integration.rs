#![forbid(unsafe_code)]
//! Integration tests for the `js_runtime_lane` module.
//!
//! Exercises SignalGraph, UpdateScheduler, DomTree, DomPatch, EventDelegation,
//! JsLaneConfig, JsRuntimeLane, PatchBatch, FlushSummary, and full lifecycle.

use std::collections::BTreeSet;

use frankenengine_engine::js_runtime_lane::{
    DomElementId, DomPatch, DomPatchError, DomTree, EventDelegation, EventType, FlushSummary,
    JsLaneConfig, JsRuntimeLane, LaneState, PatchBatch, SignalGraph, SignalGraphError, SignalId,
    SignalKind, SignalStatus, UpdatePriority, UpdateScheduler,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn deps(ids: &[u64]) -> BTreeSet<SignalId> {
    ids.iter().map(|&i| SignalId(i)).collect()
}

// ===========================================================================
// 1. SignalKind / SignalStatus / SignalId
// ===========================================================================

#[test]
fn signal_kind_serde() {
    for kind in [SignalKind::Source, SignalKind::Derived, SignalKind::Effect] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: SignalKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kind);
    }
}

#[test]
fn signal_status_serde() {
    for st in [
        SignalStatus::Clean,
        SignalStatus::Dirty,
        SignalStatus::Evaluating,
        SignalStatus::Disposed,
    ] {
        let json = serde_json::to_string(&st).unwrap();
        let back: SignalStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, st);
    }
}

#[test]
fn signal_id_ordering() {
    assert!(SignalId(0) < SignalId(1));
    assert!(SignalId(99) < SignalId(100));
}

// ===========================================================================
// 2. SignalGraph — construction & registration
// ===========================================================================

#[test]
fn signal_graph_empty() {
    let g = SignalGraph::new();
    assert_eq!(g.node_count(), 0);
    assert!(g.get(SignalId(0)).is_none());
}

#[test]
fn signal_graph_default() {
    let g = SignalGraph::default();
    assert_eq!(g.node_count(), 0);
}

#[test]
fn signal_graph_register_source() {
    let mut g = SignalGraph::new();
    let id = g.next_signal_id();
    g.register(id, SignalKind::Source, BTreeSet::new()).unwrap();
    assert_eq!(g.node_count(), 1);
    let node = g.get(id).unwrap();
    assert_eq!(node.kind, SignalKind::Source);
    assert_eq!(node.depth, 0);
    assert_eq!(node.status, SignalStatus::Dirty); // new nodes start dirty
}

#[test]
fn signal_graph_register_derived_depth() {
    let mut g = SignalGraph::new();
    let s0 = g.next_signal_id();
    let s1 = g.next_signal_id();
    g.register(s0, SignalKind::Source, BTreeSet::new()).unwrap();
    g.register(s1, SignalKind::Derived, deps(&[s0.0])).unwrap();
    assert_eq!(g.get(s1).unwrap().depth, 1);
    // s0 should have s1 as dependent
    assert!(g.get(s0).unwrap().dependents.contains(&s1));
}

#[test]
fn signal_graph_register_effect_two_deep() {
    let mut g = SignalGraph::new();
    let s0 = g.next_signal_id();
    let s1 = g.next_signal_id();
    let s2 = g.next_signal_id();
    g.register(s0, SignalKind::Source, BTreeSet::new()).unwrap();
    g.register(s1, SignalKind::Derived, deps(&[s0.0])).unwrap();
    g.register(s2, SignalKind::Effect, deps(&[s1.0])).unwrap();
    assert_eq!(g.get(s2).unwrap().depth, 2);
}

#[test]
fn signal_graph_duplicate_register() {
    let mut g = SignalGraph::new();
    let id = g.next_signal_id();
    g.register(id, SignalKind::Source, BTreeSet::new()).unwrap();
    let err = g
        .register(id, SignalKind::Source, BTreeSet::new())
        .unwrap_err();
    assert!(matches!(err, SignalGraphError::DuplicateSignal(_)));
}

#[test]
fn signal_graph_register_missing_dep() {
    let mut g = SignalGraph::new();
    let id = g.next_signal_id();
    let err = g
        .register(id, SignalKind::Derived, deps(&[999]))
        .unwrap_err();
    assert!(matches!(err, SignalGraphError::NotFound(_)));
}

// ===========================================================================
// 3. SignalGraph — dirty propagation
// ===========================================================================

#[test]
fn signal_graph_mark_dirty_propagates() {
    let mut g = SignalGraph::new();
    let s0 = g.next_signal_id();
    let s1 = g.next_signal_id();
    let s2 = g.next_signal_id();
    g.register(s0, SignalKind::Source, BTreeSet::new()).unwrap();
    g.register(s1, SignalKind::Derived, deps(&[s0.0])).unwrap();
    g.register(s2, SignalKind::Effect, deps(&[s1.0])).unwrap();

    // Mark all clean first
    g.mark_clean(s0).unwrap();
    g.mark_clean(s1).unwrap();
    g.mark_clean(s2).unwrap();

    // Dirty s0 → should propagate to s1, s2
    let dirty = g.mark_dirty(s0).unwrap();
    assert_eq!(dirty.len(), 3); // s0, s1, s2
    // Sorted by depth
    assert_eq!(dirty[0], s0);
    assert_eq!(dirty[1], s1);
    assert_eq!(dirty[2], s2);
}

#[test]
fn signal_graph_mark_dirty_not_found() {
    let mut g = SignalGraph::new();
    let err = g.mark_dirty(SignalId(42)).unwrap_err();
    assert!(matches!(err, SignalGraphError::NotFound(_)));
}

#[test]
fn signal_graph_mark_dirty_disposed() {
    let mut g = SignalGraph::new();
    let id = g.next_signal_id();
    g.register(id, SignalKind::Source, BTreeSet::new()).unwrap();
    g.dispose(id).unwrap();
    let err = g.mark_dirty(id).unwrap_err();
    assert!(matches!(err, SignalGraphError::Disposed(_)));
}

// ===========================================================================
// 4. SignalGraph — evaluation order, clean, dispose
// ===========================================================================

#[test]
fn signal_graph_dirty_evaluation_order() {
    let mut g = SignalGraph::new();
    let s0 = g.next_signal_id();
    let s1 = g.next_signal_id();
    g.register(s0, SignalKind::Source, BTreeSet::new()).unwrap();
    g.register(s1, SignalKind::Derived, deps(&[s0.0])).unwrap();

    let order = g.dirty_evaluation_order();
    // Both start dirty; s0 should come before s1
    assert_eq!(order[0], s0);
    assert_eq!(order[1], s1);
}

#[test]
fn signal_graph_mark_clean() {
    let mut g = SignalGraph::new();
    let id = g.next_signal_id();
    g.register(id, SignalKind::Source, BTreeSet::new()).unwrap();
    assert_eq!(g.get(id).unwrap().status, SignalStatus::Dirty);
    g.mark_clean(id).unwrap();
    assert_eq!(g.get(id).unwrap().status, SignalStatus::Clean);
}

#[test]
fn signal_graph_mark_clean_not_found() {
    let mut g = SignalGraph::new();
    let err = g.mark_clean(SignalId(99)).unwrap_err();
    assert!(matches!(err, SignalGraphError::NotFound(_)));
}

#[test]
fn signal_graph_mark_clean_disposed() {
    let mut g = SignalGraph::new();
    let id = g.next_signal_id();
    g.register(id, SignalKind::Source, BTreeSet::new()).unwrap();
    g.dispose(id).unwrap();
    let err = g.mark_clean(id).unwrap_err();
    assert!(matches!(err, SignalGraphError::Disposed(_)));
}

#[test]
fn signal_graph_dispose_removes_links() {
    let mut g = SignalGraph::new();
    let s0 = g.next_signal_id();
    let s1 = g.next_signal_id();
    g.register(s0, SignalKind::Source, BTreeSet::new()).unwrap();
    g.register(s1, SignalKind::Derived, deps(&[s0.0])).unwrap();

    g.dispose(s1).unwrap();
    // s0 should no longer list s1 as dependent
    assert!(!g.get(s0).unwrap().dependents.contains(&s1));
    // s1 is disposed
    assert_eq!(g.get(s1).unwrap().status, SignalStatus::Disposed);
    // node_count excludes disposed
    assert_eq!(g.node_count(), 1);
}

#[test]
fn signal_graph_dispose_not_found() {
    let mut g = SignalGraph::new();
    let err = g.dispose(SignalId(77)).unwrap_err();
    assert!(matches!(err, SignalGraphError::NotFound(_)));
}

#[test]
fn signal_graph_serde() {
    let mut g = SignalGraph::new();
    let s0 = g.next_signal_id();
    let s1 = g.next_signal_id();
    g.register(s0, SignalKind::Source, BTreeSet::new()).unwrap();
    g.register(s1, SignalKind::Derived, deps(&[s0.0])).unwrap();
    let json = serde_json::to_string(&g).unwrap();
    let back: SignalGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(back, g);
}

// ===========================================================================
// 5. UpdatePriority
// ===========================================================================

#[test]
fn update_priority_urgency_ordering() {
    assert!(UpdatePriority::Sync.urgency() < UpdatePriority::UserBlocking.urgency());
    assert!(UpdatePriority::UserBlocking.urgency() < UpdatePriority::Normal.urgency());
    assert!(UpdatePriority::Normal.urgency() < UpdatePriority::Low.urgency());
    assert!(UpdatePriority::Low.urgency() < UpdatePriority::Idle.urgency());
}

#[test]
fn update_priority_serde() {
    for p in [
        UpdatePriority::Sync,
        UpdatePriority::UserBlocking,
        UpdatePriority::Normal,
        UpdatePriority::Low,
        UpdatePriority::Idle,
    ] {
        let json = serde_json::to_string(&p).unwrap();
        let back: UpdatePriority = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }
}

// ===========================================================================
// 6. UpdateScheduler
// ===========================================================================

#[test]
fn scheduler_empty() {
    let s = UpdateScheduler::new();
    assert!(s.is_empty());
    assert_eq!(s.pending_count(), 0);
}

#[test]
fn scheduler_default() {
    let s = UpdateScheduler::default();
    assert!(s.is_empty());
}

#[test]
fn scheduler_schedule_and_drain() {
    let mut s = UpdateScheduler::new();
    s.schedule(SignalId(1), UpdatePriority::Normal, "comp-a".into());
    s.schedule(SignalId(2), UpdatePriority::Sync, "comp-b".into());
    s.schedule(SignalId(3), UpdatePriority::Low, "comp-c".into());
    assert_eq!(s.pending_count(), 3);

    let batch = s.drain_batch();
    assert_eq!(batch.len(), 3);
    // Sync first, then Normal, then Low
    assert_eq!(batch[0].priority, UpdatePriority::Sync);
    assert_eq!(batch[1].priority, UpdatePriority::Normal);
    assert_eq!(batch[2].priority, UpdatePriority::Low);
    assert!(s.is_empty());
}

#[test]
fn scheduler_fifo_within_priority() {
    let mut s = UpdateScheduler::new();
    s.schedule(SignalId(1), UpdatePriority::Normal, "first".into());
    s.schedule(SignalId(2), UpdatePriority::Normal, "second".into());
    let batch = s.drain_batch();
    assert!(batch[0].sequence < batch[1].sequence);
    assert_eq!(batch[0].component, "first");
    assert_eq!(batch[1].component, "second");
}

#[test]
fn scheduler_max_updates_per_flush() {
    let mut s = UpdateScheduler::new();
    s.max_updates_per_flush = 2;
    s.schedule(SignalId(1), UpdatePriority::Normal, "a".into());
    s.schedule(SignalId(2), UpdatePriority::Normal, "b".into());
    s.schedule(SignalId(3), UpdatePriority::Normal, "c".into());

    let batch = s.drain_batch();
    assert_eq!(batch.len(), 2); // limited to 2
    assert_eq!(s.pending_count(), 1); // one remains
}

#[test]
fn scheduler_serde() {
    let mut s = UpdateScheduler::new();
    s.schedule(SignalId(5), UpdatePriority::Idle, "x".into());
    let json = serde_json::to_string(&s).unwrap();
    let back: UpdateScheduler = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

// ===========================================================================
// 7. DomPatch — target_element
// ===========================================================================

#[test]
fn dom_patch_target_element() {
    let create = DomPatch::CreateElement {
        id: DomElementId(1),
        tag: "div".into(),
        parent: None,
    };
    assert_eq!(create.target_element(), DomElementId(1));

    let remove = DomPatch::RemoveElement {
        id: DomElementId(2),
    };
    assert_eq!(remove.target_element(), DomElementId(2));

    let set = DomPatch::SetProperty {
        id: DomElementId(3),
        key: "class".into(),
        value: "active".into(),
    };
    assert_eq!(set.target_element(), DomElementId(3));

    let rm_prop = DomPatch::RemoveProperty {
        id: DomElementId(4),
        key: "class".into(),
    };
    assert_eq!(rm_prop.target_element(), DomElementId(4));

    let text = DomPatch::SetTextContent {
        id: DomElementId(5),
        text: "hello".into(),
    };
    assert_eq!(text.target_element(), DomElementId(5));

    let mv = DomPatch::MoveElement {
        id: DomElementId(6),
        new_parent: DomElementId(0),
        before_sibling: None,
    };
    assert_eq!(mv.target_element(), DomElementId(6));

    let repl = DomPatch::ReplaceElement {
        old: DomElementId(7),
        new_id: DomElementId(8),
        tag: "span".into(),
    };
    assert_eq!(repl.target_element(), DomElementId(7));
}

#[test]
fn dom_patch_serde() {
    let patch = DomPatch::SetProperty {
        id: DomElementId(1),
        key: "id".into(),
        value: "app".into(),
    };
    let json = serde_json::to_string(&patch).unwrap();
    let back: DomPatch = serde_json::from_str(&json).unwrap();
    assert_eq!(back, patch);
}

// ===========================================================================
// 8. PatchBatch
// ===========================================================================

#[test]
fn patch_batch_empty() {
    let batch = PatchBatch::new("comp", 0);
    assert!(batch.is_empty());
    assert_eq!(batch.component, "comp");
    assert_eq!(batch.cycle_sequence, 0);
}

#[test]
fn patch_batch_push() {
    let mut batch = PatchBatch::new("comp", 1);
    batch.push(DomPatch::CreateElement {
        id: DomElementId(1),
        tag: "div".into(),
        parent: None,
    });
    assert!(!batch.is_empty());
    assert_eq!(batch.patches.len(), 1);
}

#[test]
fn patch_batch_derive_id_deterministic() {
    let mut b1 = PatchBatch::new("comp", 1);
    b1.push(DomPatch::RemoveElement {
        id: DomElementId(1),
    });
    let mut b2 = PatchBatch::new("comp", 1);
    b2.push(DomPatch::RemoveElement {
        id: DomElementId(1),
    });
    assert_eq!(b1.derive_id(), b2.derive_id());
}

#[test]
fn patch_batch_derive_id_varies_with_input() {
    let b1 = PatchBatch::new("comp-a", 1);
    let b2 = PatchBatch::new("comp-b", 1);
    assert_ne!(b1.derive_id(), b2.derive_id());
}

#[test]
fn patch_batch_serde() {
    let mut batch = PatchBatch::new("test", 42);
    batch.push(DomPatch::SetTextContent {
        id: DomElementId(1),
        text: "hello".into(),
    });
    let json = serde_json::to_string(&batch).unwrap();
    let back: PatchBatch = serde_json::from_str(&json).unwrap();
    assert_eq!(back, batch);
}

// ===========================================================================
// 9. DomTree — create, property, text
// ===========================================================================

#[test]
fn dom_tree_empty() {
    let t = DomTree::new();
    assert_eq!(t.element_count(), 0);
    assert!(!t.contains(DomElementId(0)));
}

#[test]
fn dom_tree_default() {
    let t = DomTree::default();
    assert_eq!(t.element_count(), 0);
}

#[test]
fn dom_tree_create_root() {
    let mut t = DomTree::new();
    let id = t.next_element_id();
    t.apply_patch(&DomPatch::CreateElement {
        id,
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    assert_eq!(t.element_count(), 1);
    assert!(t.contains(id));
    let rec = t.get(id).unwrap();
    assert_eq!(rec.tag, "div");
    assert!(rec.parent.is_none());
}

#[test]
fn dom_tree_create_child() {
    let mut t = DomTree::new();
    let root = t.next_element_id();
    let child = t.next_element_id();
    t.apply_patch(&DomPatch::CreateElement {
        id: root,
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    t.apply_patch(&DomPatch::CreateElement {
        id: child,
        tag: "span".into(),
        parent: Some(root),
    })
    .unwrap();
    assert_eq!(t.element_count(), 2);
    assert_eq!(t.get(root).unwrap().children, vec![child]);
    assert_eq!(t.get(child).unwrap().parent, Some(root));
}

#[test]
fn dom_tree_create_duplicate() {
    let mut t = DomTree::new();
    let id = DomElementId(0);
    t.apply_patch(&DomPatch::CreateElement {
        id,
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    let err = t
        .apply_patch(&DomPatch::CreateElement {
            id,
            tag: "span".into(),
            parent: None,
        })
        .unwrap_err();
    assert!(matches!(err, DomPatchError::ElementAlreadyExists(_)));
}

#[test]
fn dom_tree_create_missing_parent() {
    let mut t = DomTree::new();
    let err = t
        .apply_patch(&DomPatch::CreateElement {
            id: DomElementId(0),
            tag: "div".into(),
            parent: Some(DomElementId(99)),
        })
        .unwrap_err();
    assert!(matches!(err, DomPatchError::ParentNotFound(_)));
}

#[test]
fn dom_tree_set_property() {
    let mut t = DomTree::new();
    let id = DomElementId(0);
    t.apply_patch(&DomPatch::CreateElement {
        id,
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    t.apply_patch(&DomPatch::SetProperty {
        id,
        key: "class".into(),
        value: "active".into(),
    })
    .unwrap();
    assert_eq!(
        t.get(id).unwrap().properties.get("class").unwrap(),
        "active"
    );
}

#[test]
fn dom_tree_remove_property() {
    let mut t = DomTree::new();
    let id = DomElementId(0);
    t.apply_patch(&DomPatch::CreateElement {
        id,
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    t.apply_patch(&DomPatch::SetProperty {
        id,
        key: "class".into(),
        value: "x".into(),
    })
    .unwrap();
    t.apply_patch(&DomPatch::RemoveProperty {
        id,
        key: "class".into(),
    })
    .unwrap();
    assert!(!t.get(id).unwrap().properties.contains_key("class"));
}

#[test]
fn dom_tree_set_text_content() {
    let mut t = DomTree::new();
    let id = DomElementId(0);
    t.apply_patch(&DomPatch::CreateElement {
        id,
        tag: "p".into(),
        parent: None,
    })
    .unwrap();
    t.apply_patch(&DomPatch::SetTextContent {
        id,
        text: "hello world".into(),
    })
    .unwrap();
    assert_eq!(
        t.get(id).unwrap().text_content.as_deref(),
        Some("hello world")
    );
}

// ===========================================================================
// 10. DomTree — remove, move, replace
// ===========================================================================

#[test]
fn dom_tree_remove_element() {
    let mut t = DomTree::new();
    let root = DomElementId(0);
    let child = DomElementId(1);
    t.apply_patch(&DomPatch::CreateElement {
        id: root,
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    t.apply_patch(&DomPatch::CreateElement {
        id: child,
        tag: "span".into(),
        parent: Some(root),
    })
    .unwrap();
    t.apply_patch(&DomPatch::RemoveElement { id: child })
        .unwrap();
    assert_eq!(t.element_count(), 1);
    assert!(!t.contains(child));
    assert!(t.get(root).unwrap().children.is_empty());
}

#[test]
fn dom_tree_remove_element_recursive() {
    let mut t = DomTree::new();
    let root = DomElementId(0);
    let child = DomElementId(1);
    let grandchild = DomElementId(2);
    t.apply_patch(&DomPatch::CreateElement {
        id: root,
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    t.apply_patch(&DomPatch::CreateElement {
        id: child,
        tag: "ul".into(),
        parent: Some(root),
    })
    .unwrap();
    t.apply_patch(&DomPatch::CreateElement {
        id: grandchild,
        tag: "li".into(),
        parent: Some(child),
    })
    .unwrap();
    // Removing child should also remove grandchild
    t.apply_patch(&DomPatch::RemoveElement { id: child })
        .unwrap();
    assert_eq!(t.element_count(), 1);
    assert!(!t.contains(child));
    assert!(!t.contains(grandchild));
}

#[test]
fn dom_tree_remove_not_found() {
    let mut t = DomTree::new();
    let err = t
        .apply_patch(&DomPatch::RemoveElement {
            id: DomElementId(99),
        })
        .unwrap_err();
    assert!(matches!(err, DomPatchError::ElementNotFound(_)));
}

#[test]
fn dom_tree_move_element() {
    let mut t = DomTree::new();
    let a = DomElementId(0);
    let b = DomElementId(1);
    let child = DomElementId(2);
    t.apply_patch(&DomPatch::CreateElement {
        id: a,
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    t.apply_patch(&DomPatch::CreateElement {
        id: b,
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    t.apply_patch(&DomPatch::CreateElement {
        id: child,
        tag: "span".into(),
        parent: Some(a),
    })
    .unwrap();

    // Move child from a to b
    t.apply_patch(&DomPatch::MoveElement {
        id: child,
        new_parent: b,
        before_sibling: None,
    })
    .unwrap();
    assert!(t.get(a).unwrap().children.is_empty());
    assert_eq!(t.get(b).unwrap().children, vec![child]);
    assert_eq!(t.get(child).unwrap().parent, Some(b));
}

#[test]
fn dom_tree_move_not_found() {
    let mut t = DomTree::new();
    let root = DomElementId(0);
    t.apply_patch(&DomPatch::CreateElement {
        id: root,
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    let err = t
        .apply_patch(&DomPatch::MoveElement {
            id: DomElementId(99),
            new_parent: root,
            before_sibling: None,
        })
        .unwrap_err();
    assert!(matches!(err, DomPatchError::ElementNotFound(_)));
}

#[test]
fn dom_tree_move_parent_not_found() {
    let mut t = DomTree::new();
    let id = DomElementId(0);
    t.apply_patch(&DomPatch::CreateElement {
        id,
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    let err = t
        .apply_patch(&DomPatch::MoveElement {
            id,
            new_parent: DomElementId(99),
            before_sibling: None,
        })
        .unwrap_err();
    assert!(matches!(err, DomPatchError::ParentNotFound(_)));
}

#[test]
fn dom_tree_replace_element() {
    let mut t = DomTree::new();
    let root = DomElementId(0);
    let old = DomElementId(1);
    let new_id = DomElementId(2);
    t.apply_patch(&DomPatch::CreateElement {
        id: root,
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    t.apply_patch(&DomPatch::CreateElement {
        id: old,
        tag: "span".into(),
        parent: Some(root),
    })
    .unwrap();
    t.apply_patch(&DomPatch::ReplaceElement {
        old,
        new_id,
        tag: "strong".into(),
    })
    .unwrap();
    assert!(!t.contains(old));
    assert!(t.contains(new_id));
    assert_eq!(t.get(new_id).unwrap().tag, "strong");
    assert_eq!(t.get(new_id).unwrap().parent, Some(root));
    assert_eq!(t.get(root).unwrap().children, vec![new_id]);
}

#[test]
fn dom_tree_replace_not_found() {
    let mut t = DomTree::new();
    let err = t
        .apply_patch(&DomPatch::ReplaceElement {
            old: DomElementId(99),
            new_id: DomElementId(100),
            tag: "div".into(),
        })
        .unwrap_err();
    assert!(matches!(err, DomPatchError::ElementNotFound(_)));
}

#[test]
fn dom_tree_apply_batch() {
    let mut t = DomTree::new();
    let mut batch = PatchBatch::new("test", 0);
    batch.push(DomPatch::CreateElement {
        id: DomElementId(0),
        tag: "div".into(),
        parent: None,
    });
    batch.push(DomPatch::CreateElement {
        id: DomElementId(1),
        tag: "p".into(),
        parent: Some(DomElementId(0)),
    });
    batch.push(DomPatch::SetTextContent {
        id: DomElementId(1),
        text: "content".into(),
    });
    t.apply_batch(&batch).unwrap();
    assert_eq!(t.element_count(), 2);
    assert_eq!(
        t.get(DomElementId(1)).unwrap().text_content.as_deref(),
        Some("content")
    );
}

#[test]
fn dom_tree_serde() {
    let mut t = DomTree::new();
    t.apply_patch(&DomPatch::CreateElement {
        id: DomElementId(0),
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    let json = serde_json::to_string(&t).unwrap();
    let back: DomTree = serde_json::from_str(&json).unwrap();
    assert_eq!(back, t);
}

// ===========================================================================
// 11. EventType
// ===========================================================================

#[test]
fn event_type_all_count() {
    assert_eq!(EventType::ALL.len(), 12);
}

#[test]
fn event_type_bubbles() {
    assert!(EventType::Click.bubbles());
    assert!(EventType::Input.bubbles());
    assert!(EventType::Submit.bubbles());
    assert!(EventType::KeyDown.bubbles());
    assert!(!EventType::Focus.bubbles());
    assert!(!EventType::Blur.bubbles());
    assert!(!EventType::MouseEnter.bubbles());
    assert!(!EventType::Resize.bubbles());
}

#[test]
fn event_type_serde() {
    for et in EventType::ALL {
        let json = serde_json::to_string(et).unwrap();
        let back: EventType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *et);
    }
}

// ===========================================================================
// 12. EventDelegation
// ===========================================================================

#[test]
fn event_delegation_empty() {
    let ed = EventDelegation::new();
    assert_eq!(ed.handler_count(), 0);
}

#[test]
fn event_delegation_default() {
    let ed = EventDelegation::default();
    assert_eq!(ed.handler_count(), 0);
}

#[test]
fn event_delegation_register() {
    let mut ed = EventDelegation::new();
    let h1 = ed.register(EventType::Click, DomElementId(1), "button-comp", false);
    let h2 = ed.register(EventType::Input, DomElementId(2), "input-comp", false);
    assert_ne!(h1, h2);
    assert_eq!(ed.handler_count(), 2);
}

#[test]
fn event_delegation_unregister() {
    let mut ed = EventDelegation::new();
    let h = ed.register(EventType::Click, DomElementId(1), "comp", false);
    assert!(ed.unregister(h));
    assert_eq!(ed.handler_count(), 0);
    // Unregistering non-existent returns false
    assert!(!ed.unregister(999));
}

#[test]
fn event_delegation_find_handlers() {
    let mut ed = EventDelegation::new();
    let elem = DomElementId(5);
    ed.register(EventType::Click, elem, "comp-a", false);
    ed.register(EventType::Click, elem, "comp-b", true);
    ed.register(EventType::Input, elem, "comp-c", false);

    let click_handlers = ed.find_handlers(EventType::Click, elem);
    assert_eq!(click_handlers.len(), 2);

    let input_handlers = ed.find_handlers(EventType::Input, elem);
    assert_eq!(input_handlers.len(), 1);

    let no_handlers = ed.find_handlers(EventType::Submit, elem);
    assert!(no_handlers.is_empty());
}

#[test]
fn event_delegation_cleanup_element() {
    let mut ed = EventDelegation::new();
    let elem = DomElementId(3);
    ed.register(EventType::Click, elem, "a", false);
    ed.register(EventType::Input, elem, "b", false);
    ed.register(EventType::Click, DomElementId(99), "c", false);

    let removed = ed.cleanup_element(elem);
    assert_eq!(removed, 2);
    assert_eq!(ed.handler_count(), 1);
}

#[test]
fn event_delegation_cleanup_component() {
    let mut ed = EventDelegation::new();
    ed.register(EventType::Click, DomElementId(1), "form-comp", false);
    ed.register(EventType::Input, DomElementId(2), "form-comp", false);
    ed.register(EventType::Click, DomElementId(3), "other-comp", false);

    let removed = ed.cleanup_component("form-comp");
    assert_eq!(removed, 2);
    assert_eq!(ed.handler_count(), 1);
}

#[test]
fn event_delegation_serde() {
    let mut ed = EventDelegation::new();
    ed.register(EventType::KeyDown, DomElementId(1), "comp", true);
    let json = serde_json::to_string(&ed).unwrap();
    let back: EventDelegation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ed);
}

// ===========================================================================
// 13. JsLaneConfig
// ===========================================================================

#[test]
fn js_lane_config_default() {
    let cfg = JsLaneConfig::default_config();
    assert_eq!(cfg.max_signal_depth, 64);
    assert_eq!(cfg.max_updates_per_flush, 1000);
    assert_eq!(cfg.max_dom_elements, 100_000);
    assert_eq!(cfg.max_event_handlers, 50_000);
    assert!(cfg.enable_effect_batching);
}

#[test]
fn js_lane_config_validate_ok() {
    let cfg = JsLaneConfig::default_config();
    assert!(cfg.validate().is_empty());
}

#[test]
fn js_lane_config_validate_zero_depth() {
    let mut cfg = JsLaneConfig::default_config();
    cfg.max_signal_depth = 0;
    let errors = cfg.validate();
    assert!(!errors.is_empty());
    assert!(errors[0].contains("max_signal_depth"));
}

#[test]
fn js_lane_config_validate_zero_flush() {
    let mut cfg = JsLaneConfig::default_config();
    cfg.max_updates_per_flush = 0;
    let errors = cfg.validate();
    assert!(errors.iter().any(|e| e.contains("max_updates_per_flush")));
}

#[test]
fn js_lane_config_validate_zero_dom() {
    let mut cfg = JsLaneConfig::default_config();
    cfg.max_dom_elements = 0;
    let errors = cfg.validate();
    assert!(errors.iter().any(|e| e.contains("max_dom_elements")));
}

#[test]
fn js_lane_config_validate_multiple_errors() {
    let cfg = JsLaneConfig {
        max_signal_depth: 0,
        max_updates_per_flush: 0,
        max_dom_elements: 0,
        max_event_handlers: 0,
        enable_effect_batching: false,
    };
    assert_eq!(cfg.validate().len(), 3);
}

#[test]
fn js_lane_config_serde() {
    let cfg = JsLaneConfig::default_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: JsLaneConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cfg);
}

// ===========================================================================
// 14. LaneState / FlushSummary
// ===========================================================================

#[test]
fn lane_state_serde() {
    for s in [
        LaneState::Ready,
        LaneState::Processing,
        LaneState::Suspended,
        LaneState::Shutdown,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: LaneState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn flush_summary_derive_id_deterministic() {
    let fs = FlushSummary {
        updates_processed: 10,
        signals_evaluated: 5,
        patches_emitted: 3,
        handlers_cleaned: 1,
        cycle_sequence: 42,
    };
    assert_eq!(fs.derive_id(), fs.derive_id());
}

#[test]
fn flush_summary_derive_id_varies() {
    let a = FlushSummary {
        updates_processed: 10,
        signals_evaluated: 5,
        patches_emitted: 3,
        handlers_cleaned: 1,
        cycle_sequence: 1,
    };
    let b = FlushSummary {
        updates_processed: 10,
        signals_evaluated: 5,
        patches_emitted: 3,
        handlers_cleaned: 1,
        cycle_sequence: 2,
    };
    assert_ne!(a.derive_id(), b.derive_id());
}

#[test]
fn flush_summary_serde() {
    let fs = FlushSummary {
        updates_processed: 7,
        signals_evaluated: 3,
        patches_emitted: 2,
        handlers_cleaned: 0,
        cycle_sequence: 1,
    };
    let json = serde_json::to_string(&fs).unwrap();
    let back: FlushSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, fs);
}

// ===========================================================================
// 15. JsRuntimeLane
// ===========================================================================

#[test]
fn js_runtime_lane_with_defaults() {
    let lane = JsRuntimeLane::with_defaults();
    assert_eq!(lane.state, LaneState::Ready);
    assert_eq!(lane.flush_count, 0);
    assert_eq!(lane.signal_graph.node_count(), 0);
    assert_eq!(lane.dom_tree.element_count(), 0);
    assert_eq!(lane.event_delegation.handler_count(), 0);
}

#[test]
fn js_runtime_lane_custom_config() {
    let mut cfg = JsLaneConfig::default_config();
    cfg.max_signal_depth = 128;
    let lane = JsRuntimeLane::new(cfg.clone());
    assert_eq!(lane.config, cfg);
}

#[test]
fn js_runtime_lane_derive_id_deterministic() {
    let a = JsRuntimeLane::with_defaults();
    let b = JsRuntimeLane::with_defaults();
    assert_eq!(a.derive_id(), b.derive_id());
}

#[test]
fn js_runtime_lane_derive_id_changes_with_state() {
    let mut a = JsRuntimeLane::with_defaults();
    let b = JsRuntimeLane::with_defaults();
    // Add a signal to a
    let sid = a.signal_graph.next_signal_id();
    a.signal_graph
        .register(sid, SignalKind::Source, BTreeSet::new())
        .unwrap();
    assert_ne!(a.derive_id(), b.derive_id());
}

#[test]
fn js_runtime_lane_serde() {
    let lane = JsRuntimeLane::with_defaults();
    let json = serde_json::to_string(&lane).unwrap();
    let back: JsRuntimeLane = serde_json::from_str(&json).unwrap();
    assert_eq!(back, lane);
}

// ===========================================================================
// 16. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_signal_schedule_patch_event() {
    let mut lane = JsRuntimeLane::with_defaults();

    // 1. Create signal graph: source → derived → effect
    let count = lane.signal_graph.next_signal_id();
    let doubled = lane.signal_graph.next_signal_id();
    let render = lane.signal_graph.next_signal_id();
    lane.signal_graph
        .register(count, SignalKind::Source, BTreeSet::new())
        .unwrap();
    lane.signal_graph
        .register(doubled, SignalKind::Derived, deps(&[count.0]))
        .unwrap();
    lane.signal_graph
        .register(render, SignalKind::Effect, deps(&[doubled.0]))
        .unwrap();

    // 2. Build DOM: root > button + display
    let root = DomElementId(0);
    let button = DomElementId(1);
    let display = DomElementId(2);
    lane.dom_tree
        .apply_patch(&DomPatch::CreateElement {
            id: root,
            tag: "div".into(),
            parent: None,
        })
        .unwrap();
    lane.dom_tree
        .apply_patch(&DomPatch::CreateElement {
            id: button,
            tag: "button".into(),
            parent: Some(root),
        })
        .unwrap();
    lane.dom_tree
        .apply_patch(&DomPatch::CreateElement {
            id: display,
            tag: "span".into(),
            parent: Some(root),
        })
        .unwrap();
    assert_eq!(lane.dom_tree.element_count(), 3);

    // 3. Register click handler
    let handler = lane
        .event_delegation
        .register(EventType::Click, button, "counter-comp", false);
    assert_eq!(lane.event_delegation.handler_count(), 1);

    // 4. Simulate click → schedule update
    lane.scheduler
        .schedule(count, UpdatePriority::Sync, "counter-comp".into());
    assert_eq!(lane.scheduler.pending_count(), 1);

    // 5. Flush: drain updates, mark dirty, evaluate, patch
    let updates = lane.scheduler.drain_batch();
    assert_eq!(updates.len(), 1);

    // Mark all clean first, then dirty the source
    lane.signal_graph.mark_clean(count).unwrap();
    lane.signal_graph.mark_clean(doubled).unwrap();
    lane.signal_graph.mark_clean(render).unwrap();
    let dirty = lane.signal_graph.mark_dirty(count).unwrap();
    assert_eq!(dirty.len(), 3);

    // Evaluate in order
    for sig in &dirty {
        lane.signal_graph.mark_clean(*sig).unwrap();
    }

    // Emit patch
    let mut batch = PatchBatch::new("counter-comp", lane.flush_count);
    batch.push(DomPatch::SetTextContent {
        id: display,
        text: "1".into(),
    });
    lane.dom_tree.apply_batch(&batch).unwrap();
    lane.flush_count += 1;

    // 6. Verify final state
    assert_eq!(
        lane.dom_tree.get(display).unwrap().text_content.as_deref(),
        Some("1")
    );
    assert_eq!(lane.flush_count, 1);
    assert!(lane.scheduler.is_empty());

    // 7. Cleanup handler
    assert!(lane.event_delegation.unregister(handler));
    assert_eq!(lane.event_delegation.handler_count(), 0);

    // 8. Serde round-trip of entire lane
    let json = serde_json::to_string(&lane).unwrap();
    let back: JsRuntimeLane = serde_json::from_str(&json).unwrap();
    assert_eq!(back, lane);
}

#[test]
fn full_lifecycle_complex_signal_diamond() {
    // Diamond: A → B, A → C, B → D, C → D
    let mut g = SignalGraph::new();
    let a = g.next_signal_id();
    let b = g.next_signal_id();
    let c = g.next_signal_id();
    let d = g.next_signal_id();
    g.register(a, SignalKind::Source, BTreeSet::new()).unwrap();
    g.register(b, SignalKind::Derived, deps(&[a.0])).unwrap();
    g.register(c, SignalKind::Derived, deps(&[a.0])).unwrap();
    g.register(d, SignalKind::Effect, deps(&[b.0, c.0]))
        .unwrap();

    // d has depth 2 (max(b.depth=1, c.depth=1) + 1)
    assert_eq!(g.get(d).unwrap().depth, 2);

    // Mark all clean, then dirty A
    for id in [a, b, c, d] {
        g.mark_clean(id).unwrap();
    }
    let dirty = g.mark_dirty(a).unwrap();
    assert_eq!(dirty.len(), 4);
    // D should be last (depth 2)
    assert_eq!(*dirty.last().unwrap(), d);
}
