//! Enrichment integration tests for `js_runtime_lane`.
//!
//! Covers: SignalId/SignalKind/SignalStatus serde, SignalGraph new/register/
//! mark_dirty/mark_clean/dispose/dirty_evaluation_order/serde, SignalGraphError
//! variants, UpdatePriority urgency/serde, UpdateScheduler schedule/drain_batch/
//! pending_count/serde, DomElementId serde, DomPatch target_element/serde,
//! PatchBatch new/push/is_empty/derive_id, DomTree apply_patch/apply_batch/
//! element_count/serde, DomPatchError variants, EventType ALL/bubbles/serde,
//! EventHandler/EventDelegation register/unregister/cleanup/find_handlers/serde,
//! JsLaneConfig default_config/validate, LaneState serde, FlushSummary derive_id,
//! JsRuntimeLane new/with_defaults/derive_id/serde.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeSet;

use frankenengine_engine::js_runtime_lane::*;

// ===========================================================================
// Helpers
// ===========================================================================

fn deps(ids: &[u64]) -> BTreeSet<SignalId> {
    ids.iter().map(|&i| SignalId(i)).collect()
}

// ===========================================================================
// 1. SignalKind serde roundtrip
// ===========================================================================

#[test]
fn signal_kind_serde_roundtrip_enrichment() {
    for kind in [SignalKind::Source, SignalKind::Derived, SignalKind::Effect] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: SignalKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kind);
    }
}

// ===========================================================================
// 2. SignalStatus serde roundtrip
// ===========================================================================

#[test]
fn signal_status_serde_roundtrip_enrichment() {
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

// ===========================================================================
// 3. SignalId ordering
// ===========================================================================

#[test]
fn signal_id_ordering_enrichment() {
    assert!(SignalId(0) < SignalId(1));
    assert_eq!(SignalId(42), SignalId(42));
}

// ===========================================================================
// 4. SignalGraph empty state
// ===========================================================================

#[test]
fn signal_graph_empty_enrichment() {
    let g = SignalGraph::new();
    assert_eq!(g.node_count(), 0);
    assert!(g.get(SignalId(0)).is_none());
    assert!(g.dirty_evaluation_order().is_empty());
}

// ===========================================================================
// 5. SignalGraph default
// ===========================================================================

#[test]
fn signal_graph_default_enrichment() {
    let g = SignalGraph::default();
    assert_eq!(g.node_count(), 0);
}

// ===========================================================================
// 6. SignalGraph register and get
// ===========================================================================

#[test]
fn signal_graph_register_get_enrichment() {
    let mut g = SignalGraph::new();
    let id = g.next_signal_id();
    g.register(id, SignalKind::Source, BTreeSet::new()).unwrap();
    let node = g.get(id).unwrap();
    assert_eq!(node.kind, SignalKind::Source);
    assert_eq!(node.status, SignalStatus::Dirty);
    assert_eq!(node.depth, 0);
}

// ===========================================================================
// 7. SignalGraph derived depth
// ===========================================================================

#[test]
fn signal_graph_derived_depth_enrichment() {
    let mut g = SignalGraph::new();
    let s1 = g.next_signal_id();
    g.register(s1, SignalKind::Source, BTreeSet::new()).unwrap();
    let d1 = g.next_signal_id();
    g.register(d1, SignalKind::Derived, deps(&[s1.0])).unwrap();
    assert_eq!(g.get(d1).unwrap().depth, 1);
}

// ===========================================================================
// 8. SignalGraph duplicate rejected
// ===========================================================================

#[test]
fn signal_graph_duplicate_rejected_enrichment() {
    let mut g = SignalGraph::new();
    let id = g.next_signal_id();
    g.register(id, SignalKind::Source, BTreeSet::new()).unwrap();
    assert!(matches!(
        g.register(id, SignalKind::Source, BTreeSet::new()),
        Err(SignalGraphError::DuplicateSignal(_))
    ));
}

// ===========================================================================
// 9. SignalGraph missing dep rejected
// ===========================================================================

#[test]
fn signal_graph_missing_dep_enrichment() {
    let mut g = SignalGraph::new();
    let id = g.next_signal_id();
    assert!(matches!(
        g.register(id, SignalKind::Derived, deps(&[999])),
        Err(SignalGraphError::NotFound(_))
    ));
}

// ===========================================================================
// 10. SignalGraph mark_dirty propagation
// ===========================================================================

#[test]
fn signal_graph_mark_dirty_propagates_enrichment() {
    let mut g = SignalGraph::new();
    let s = g.next_signal_id();
    g.register(s, SignalKind::Source, BTreeSet::new()).unwrap();
    g.mark_clean(s).unwrap();

    let d1 = g.next_signal_id();
    g.register(d1, SignalKind::Derived, deps(&[s.0])).unwrap();
    g.mark_clean(d1).unwrap();

    let dirty = g.mark_dirty(s).unwrap();
    assert_eq!(dirty.len(), 2);
    assert_eq!(dirty[0], s);
    assert_eq!(dirty[1], d1);
}

// ===========================================================================
// 11. SignalGraph mark_dirty not found
// ===========================================================================

#[test]
fn signal_graph_mark_dirty_not_found_enrichment() {
    let mut g = SignalGraph::new();
    assert!(matches!(
        g.mark_dirty(SignalId(99)),
        Err(SignalGraphError::NotFound(_))
    ));
}

// ===========================================================================
// 12. SignalGraph dispose
// ===========================================================================

#[test]
fn signal_graph_dispose_enrichment() {
    let mut g = SignalGraph::new();
    let s = g.next_signal_id();
    g.register(s, SignalKind::Source, BTreeSet::new()).unwrap();
    let d = g.next_signal_id();
    g.register(d, SignalKind::Derived, deps(&[s.0])).unwrap();

    g.dispose(d).unwrap();
    assert_eq!(g.node_count(), 1);
    assert!(g.get(s).unwrap().dependents.is_empty());
}

// ===========================================================================
// 13. SignalGraph serde roundtrip
// ===========================================================================

#[test]
fn signal_graph_serde_roundtrip_enrichment() {
    let mut g = SignalGraph::new();
    let s = g.next_signal_id();
    g.register(s, SignalKind::Source, BTreeSet::new()).unwrap();
    let json = serde_json::to_string(&g).unwrap();
    let back: SignalGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(back, g);
}

// ===========================================================================
// 14. UpdatePriority urgency ordering
// ===========================================================================

#[test]
fn update_priority_urgency_ordering_enrichment() {
    let priorities = [
        UpdatePriority::Sync,
        UpdatePriority::UserBlocking,
        UpdatePriority::Normal,
        UpdatePriority::Low,
        UpdatePriority::Idle,
    ];
    for pair in priorities.windows(2) {
        assert!(pair[0].urgency() < pair[1].urgency());
    }
}

// ===========================================================================
// 15. UpdatePriority serde roundtrip
// ===========================================================================

#[test]
fn update_priority_serde_roundtrip_enrichment() {
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
// 16. UpdateScheduler new empty
// ===========================================================================

#[test]
fn scheduler_new_empty_enrichment() {
    let s = UpdateScheduler::new();
    assert!(s.is_empty());
    assert_eq!(s.pending_count(), 0);
}

// ===========================================================================
// 17. UpdateScheduler schedule and drain
// ===========================================================================

#[test]
fn scheduler_schedule_drain_enrichment() {
    let mut s = UpdateScheduler::new();
    s.schedule(SignalId(0), UpdatePriority::Normal, "App".into());
    s.schedule(SignalId(1), UpdatePriority::Sync, "Header".into());
    assert_eq!(s.pending_count(), 2);

    let batch = s.drain_batch();
    // Sync has higher urgency (lower number) so should come first
    assert_eq!(batch[0].priority, UpdatePriority::Sync);
    assert_eq!(batch[1].priority, UpdatePriority::Normal);
    assert!(s.is_empty());
}

// ===========================================================================
// 18. UpdateScheduler default
// ===========================================================================

#[test]
fn scheduler_default_enrichment() {
    let s = UpdateScheduler::default();
    assert!(s.is_empty());
}

// ===========================================================================
// 19. UpdateScheduler serde roundtrip
// ===========================================================================

#[test]
fn scheduler_serde_roundtrip_enrichment() {
    let mut s = UpdateScheduler::new();
    s.schedule(SignalId(5), UpdatePriority::Low, "Footer".into());
    let json = serde_json::to_string(&s).unwrap();
    let back: UpdateScheduler = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

// ===========================================================================
// 20. DomPatch target_element
// ===========================================================================

#[test]
fn dom_patch_target_element_enrichment() {
    let p1 = DomPatch::CreateElement {
        id: DomElementId(1),
        tag: "div".into(),
        parent: None,
    };
    assert_eq!(p1.target_element(), DomElementId(1));

    let p2 = DomPatch::RemoveElement {
        id: DomElementId(2),
    };
    assert_eq!(p2.target_element(), DomElementId(2));

    let p3 = DomPatch::SetProperty {
        id: DomElementId(3),
        key: "class".into(),
        value: "foo".into(),
    };
    assert_eq!(p3.target_element(), DomElementId(3));

    let p4 = DomPatch::ReplaceElement {
        old: DomElementId(4),
        new_id: DomElementId(5),
        tag: "span".into(),
    };
    assert_eq!(p4.target_element(), DomElementId(4));
}

// ===========================================================================
// 21. DomPatch serde roundtrip
// ===========================================================================

#[test]
fn dom_patch_serde_roundtrip_enrichment() {
    let patches = vec![
        DomPatch::CreateElement {
            id: DomElementId(1),
            tag: "div".into(),
            parent: None,
        },
        DomPatch::RemoveElement {
            id: DomElementId(2),
        },
        DomPatch::SetProperty {
            id: DomElementId(3),
            key: "class".into(),
            value: "foo".into(),
        },
        DomPatch::RemoveProperty {
            id: DomElementId(4),
            key: "style".into(),
        },
        DomPatch::SetTextContent {
            id: DomElementId(5),
            text: "hello".into(),
        },
    ];
    for patch in &patches {
        let json = serde_json::to_string(patch).unwrap();
        let back: DomPatch = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *patch);
    }
}

// ===========================================================================
// 22. PatchBatch new and push
// ===========================================================================

#[test]
fn patch_batch_new_push_enrichment() {
    let mut batch = PatchBatch::new("App", 1);
    assert!(batch.is_empty());
    batch.push(DomPatch::CreateElement {
        id: DomElementId(1),
        tag: "div".into(),
        parent: None,
    });
    assert!(!batch.is_empty());
    assert_eq!(batch.patches.len(), 1);
}

// ===========================================================================
// 23. PatchBatch derive_id deterministic
// ===========================================================================

#[test]
fn patch_batch_derive_id_deterministic_enrichment() {
    let batch = PatchBatch::new("App", 1);
    let id1 = batch.derive_id();
    let id2 = batch.derive_id();
    assert_eq!(id1, id2);
}

// ===========================================================================
// 24. PatchBatch serde roundtrip
// ===========================================================================

#[test]
fn patch_batch_serde_roundtrip_enrichment() {
    let mut batch = PatchBatch::new("App", 5);
    batch.push(DomPatch::CreateElement {
        id: DomElementId(1),
        tag: "div".into(),
        parent: None,
    });
    let json = serde_json::to_string(&batch).unwrap();
    let back: PatchBatch = serde_json::from_str(&json).unwrap();
    assert_eq!(back, batch);
}

// ===========================================================================
// 25. DomTree new and element_count
// ===========================================================================

#[test]
fn dom_tree_new_enrichment() {
    let tree = DomTree::new();
    assert_eq!(tree.element_count(), 0);
}

// ===========================================================================
// 26. DomTree default
// ===========================================================================

#[test]
fn dom_tree_default_enrichment() {
    let tree = DomTree::default();
    assert_eq!(tree.element_count(), 0);
}

// ===========================================================================
// 27. DomTree apply_patch CreateElement
// ===========================================================================

#[test]
fn dom_tree_create_element_enrichment() {
    let mut tree = DomTree::new();
    tree.apply_patch(&DomPatch::CreateElement {
        id: DomElementId(0),
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    assert_eq!(tree.element_count(), 1);
    assert!(tree.contains(DomElementId(0)));
}

// ===========================================================================
// 28. DomTree apply_patch RemoveElement
// ===========================================================================

#[test]
fn dom_tree_remove_element_enrichment() {
    let mut tree = DomTree::new();
    tree.apply_patch(&DomPatch::CreateElement {
        id: DomElementId(0),
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    tree.apply_patch(&DomPatch::RemoveElement {
        id: DomElementId(0),
    })
    .unwrap();
    assert_eq!(tree.element_count(), 0);
}

// ===========================================================================
// 29. DomTree apply_patch SetProperty
// ===========================================================================

#[test]
fn dom_tree_set_property_enrichment() {
    let mut tree = DomTree::new();
    tree.apply_patch(&DomPatch::CreateElement {
        id: DomElementId(0),
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    tree.apply_patch(&DomPatch::SetProperty {
        id: DomElementId(0),
        key: "class".into(),
        value: "container".into(),
    })
    .unwrap();
    let rec = tree.get(DomElementId(0)).unwrap();
    assert_eq!(rec.properties.get("class"), Some(&"container".to_string()));
}

// ===========================================================================
// 30. DomTree apply_patch SetTextContent
// ===========================================================================

#[test]
fn dom_tree_set_text_enrichment() {
    let mut tree = DomTree::new();
    tree.apply_patch(&DomPatch::CreateElement {
        id: DomElementId(0),
        tag: "span".into(),
        parent: None,
    })
    .unwrap();
    tree.apply_patch(&DomPatch::SetTextContent {
        id: DomElementId(0),
        text: "hello".into(),
    })
    .unwrap();
    assert_eq!(
        tree.get(DomElementId(0)).unwrap().text_content.as_deref(),
        Some("hello")
    );
}

// ===========================================================================
// 31. DomTree error on duplicate create
// ===========================================================================

#[test]
fn dom_tree_duplicate_create_error_enrichment() {
    let mut tree = DomTree::new();
    tree.apply_patch(&DomPatch::CreateElement {
        id: DomElementId(0),
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    assert!(matches!(
        tree.apply_patch(&DomPatch::CreateElement {
            id: DomElementId(0),
            tag: "span".into(),
            parent: None,
        }),
        Err(DomPatchError::ElementAlreadyExists(_))
    ));
}

// ===========================================================================
// 32. DomTree error on remove missing
// ===========================================================================

#[test]
fn dom_tree_remove_missing_error_enrichment() {
    let mut tree = DomTree::new();
    assert!(matches!(
        tree.apply_patch(&DomPatch::RemoveElement {
            id: DomElementId(99),
        }),
        Err(DomPatchError::ElementNotFound(_))
    ));
}

// ===========================================================================
// 33. DomTree apply_batch
// ===========================================================================

#[test]
fn dom_tree_apply_batch_enrichment() {
    let mut tree = DomTree::new();
    let mut batch = PatchBatch::new("App", 1);
    batch.push(DomPatch::CreateElement {
        id: DomElementId(0),
        tag: "div".into(),
        parent: None,
    });
    batch.push(DomPatch::CreateElement {
        id: DomElementId(1),
        tag: "span".into(),
        parent: Some(DomElementId(0)),
    });
    tree.apply_batch(&batch).unwrap();
    assert_eq!(tree.element_count(), 2);
}

// ===========================================================================
// 34. DomTree serde roundtrip
// ===========================================================================

#[test]
fn dom_tree_serde_roundtrip_enrichment() {
    let mut tree = DomTree::new();
    tree.apply_patch(&DomPatch::CreateElement {
        id: DomElementId(0),
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    let json = serde_json::to_string(&tree).unwrap();
    let back: DomTree = serde_json::from_str(&json).unwrap();
    assert_eq!(back, tree);
}

// ===========================================================================
// 35. EventType ALL count
// ===========================================================================

#[test]
fn event_type_all_count_enrichment() {
    assert_eq!(EventType::ALL.len(), 12);
}

// ===========================================================================
// 36. EventType serde roundtrip
// ===========================================================================

#[test]
fn event_type_serde_roundtrip_enrichment() {
    for et in EventType::ALL {
        let json = serde_json::to_string(et).unwrap();
        let back: EventType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *et);
    }
}

// ===========================================================================
// 37. EventType bubbles
// ===========================================================================

#[test]
fn event_type_bubbles_enrichment() {
    assert!(EventType::Click.bubbles());
    assert!(EventType::Input.bubbles());
    assert!(!EventType::Focus.bubbles());
    assert!(!EventType::Blur.bubbles());
    assert!(!EventType::Resize.bubbles());
    assert!(!EventType::MouseEnter.bubbles());
}

// ===========================================================================
// 38. EventDelegation register and find
// ===========================================================================

#[test]
fn event_delegation_register_find_enrichment() {
    let mut ed = EventDelegation::new();
    let hid = ed.register(EventType::Click, DomElementId(1), "Button", false);
    assert_eq!(ed.handler_count(), 1);
    let handlers = ed.find_handlers(EventType::Click, DomElementId(1));
    assert_eq!(handlers.len(), 1);
    assert_eq!(handlers[0].id, hid);
}

// ===========================================================================
// 39. EventDelegation unregister
// ===========================================================================

#[test]
fn event_delegation_unregister_enrichment() {
    let mut ed = EventDelegation::new();
    let hid = ed.register(EventType::Click, DomElementId(1), "Button", false);
    assert!(ed.unregister(hid));
    assert_eq!(ed.handler_count(), 0);
    assert!(!ed.unregister(hid)); // already removed
}

// ===========================================================================
// 40. EventDelegation cleanup_element
// ===========================================================================

#[test]
fn event_delegation_cleanup_element_enrichment() {
    let mut ed = EventDelegation::new();
    ed.register(EventType::Click, DomElementId(1), "A", false);
    ed.register(EventType::Input, DomElementId(1), "A", false);
    ed.register(EventType::Click, DomElementId(2), "B", false);
    let removed = ed.cleanup_element(DomElementId(1));
    assert_eq!(removed, 2);
    assert_eq!(ed.handler_count(), 1);
}

// ===========================================================================
// 41. EventDelegation cleanup_component
// ===========================================================================

#[test]
fn event_delegation_cleanup_component_enrichment() {
    let mut ed = EventDelegation::new();
    ed.register(EventType::Click, DomElementId(1), "A", false);
    ed.register(EventType::Input, DomElementId(2), "A", false);
    ed.register(EventType::Click, DomElementId(3), "B", false);
    let removed = ed.cleanup_component("A");
    assert_eq!(removed, 2);
    assert_eq!(ed.handler_count(), 1);
}

// ===========================================================================
// 42. EventDelegation serde roundtrip
// ===========================================================================

#[test]
fn event_delegation_serde_roundtrip_enrichment() {
    let mut ed = EventDelegation::new();
    ed.register(EventType::Submit, DomElementId(1), "Form", true);
    let json = serde_json::to_string(&ed).unwrap();
    let back: EventDelegation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ed);
}

// ===========================================================================
// 43. EventDelegation default
// ===========================================================================

#[test]
fn event_delegation_default_enrichment() {
    let ed = EventDelegation::default();
    assert_eq!(ed.handler_count(), 0);
}

// ===========================================================================
// 44. JsLaneConfig default_config
// ===========================================================================

#[test]
fn js_lane_config_default_enrichment() {
    let c = JsLaneConfig::default_config();
    assert_eq!(c.max_signal_depth, 64);
    assert_eq!(c.max_updates_per_flush, 1000);
    assert!(c.max_dom_elements > 0);
    assert!(c.max_event_handlers > 0);
    assert!(c.enable_effect_batching);
}

// ===========================================================================
// 45. JsLaneConfig validate
// ===========================================================================

#[test]
fn js_lane_config_validate_default_ok_enrichment() {
    let c = JsLaneConfig::default_config();
    assert!(c.validate().is_empty());
}

#[test]
fn js_lane_config_validate_zero_depth_enrichment() {
    let mut c = JsLaneConfig::default_config();
    c.max_signal_depth = 0;
    let errors = c.validate();
    assert!(!errors.is_empty());
}

// ===========================================================================
// 46. JsLaneConfig serde roundtrip
// ===========================================================================

#[test]
fn js_lane_config_serde_roundtrip_enrichment() {
    let c = JsLaneConfig::default_config();
    let json = serde_json::to_string(&c).unwrap();
    let back: JsLaneConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

// ===========================================================================
// 47. LaneState serde roundtrip
// ===========================================================================

#[test]
fn lane_state_serde_roundtrip_enrichment() {
    for state in [
        LaneState::Ready,
        LaneState::Processing,
        LaneState::Suspended,
        LaneState::Shutdown,
    ] {
        let json = serde_json::to_string(&state).unwrap();
        let back: LaneState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }
}

// ===========================================================================
// 48. FlushSummary derive_id deterministic
// ===========================================================================

#[test]
fn flush_summary_derive_id_enrichment() {
    let fs = FlushSummary {
        updates_processed: 10,
        signals_evaluated: 5,
        patches_emitted: 3,
        handlers_cleaned: 1,
        cycle_sequence: 42,
    };
    let id1 = fs.derive_id();
    let id2 = fs.derive_id();
    assert_eq!(id1, id2);
}

// ===========================================================================
// 49. FlushSummary serde roundtrip
// ===========================================================================

#[test]
fn flush_summary_serde_roundtrip_enrichment() {
    let fs = FlushSummary {
        updates_processed: 10,
        signals_evaluated: 5,
        patches_emitted: 3,
        handlers_cleaned: 1,
        cycle_sequence: 42,
    };
    let json = serde_json::to_string(&fs).unwrap();
    let back: FlushSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, fs);
}

// ===========================================================================
// 50. JsRuntimeLane new
// ===========================================================================

#[test]
fn js_runtime_lane_new_enrichment() {
    let lane = JsRuntimeLane::new(JsLaneConfig::default_config());
    assert_eq!(lane.state, LaneState::Ready);
    assert_eq!(lane.flush_count, 0);
    assert_eq!(lane.signal_graph.node_count(), 0);
    assert_eq!(lane.dom_tree.element_count(), 0);
    assert_eq!(lane.event_delegation.handler_count(), 0);
}

// ===========================================================================
// 51. JsRuntimeLane with_defaults
// ===========================================================================

#[test]
fn js_runtime_lane_with_defaults_enrichment() {
    let lane = JsRuntimeLane::with_defaults();
    assert_eq!(lane.state, LaneState::Ready);
    assert_eq!(lane.config.max_signal_depth, 64);
}

// ===========================================================================
// 52. JsRuntimeLane derive_id deterministic
// ===========================================================================

#[test]
fn js_runtime_lane_derive_id_enrichment() {
    let lane = JsRuntimeLane::with_defaults();
    let id1 = lane.derive_id();
    let id2 = lane.derive_id();
    assert_eq!(id1, id2);
}

// ===========================================================================
// 53. JsRuntimeLane serde roundtrip
// ===========================================================================

#[test]
fn js_runtime_lane_serde_roundtrip_enrichment() {
    let lane = JsRuntimeLane::with_defaults();
    let json = serde_json::to_string(&lane).unwrap();
    let back: JsRuntimeLane = serde_json::from_str(&json).unwrap();
    assert_eq!(back, lane);
}

// ===========================================================================
// 54. DomTree MoveElement
// ===========================================================================

#[test]
fn dom_tree_move_element_enrichment() {
    let mut tree = DomTree::new();
    tree.apply_patch(&DomPatch::CreateElement {
        id: DomElementId(0),
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    tree.apply_patch(&DomPatch::CreateElement {
        id: DomElementId(1),
        tag: "span".into(),
        parent: Some(DomElementId(0)),
    })
    .unwrap();
    tree.apply_patch(&DomPatch::CreateElement {
        id: DomElementId(2),
        tag: "section".into(),
        parent: None,
    })
    .unwrap();

    // Move span from div to section
    tree.apply_patch(&DomPatch::MoveElement {
        id: DomElementId(1),
        new_parent: DomElementId(2),
        before_sibling: None,
    })
    .unwrap();

    assert_eq!(
        tree.get(DomElementId(1)).unwrap().parent,
        Some(DomElementId(2))
    );
    assert!(tree.get(DomElementId(0)).unwrap().children.is_empty());
}

// ===========================================================================
// 55. DomTree ReplaceElement
// ===========================================================================

#[test]
fn dom_tree_replace_element_enrichment() {
    let mut tree = DomTree::new();
    tree.apply_patch(&DomPatch::CreateElement {
        id: DomElementId(0),
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    tree.apply_patch(&DomPatch::ReplaceElement {
        old: DomElementId(0),
        new_id: DomElementId(1),
        tag: "section".into(),
    })
    .unwrap();
    assert!(!tree.contains(DomElementId(0)));
    assert!(tree.contains(DomElementId(1)));
    assert_eq!(tree.get(DomElementId(1)).unwrap().tag, "section");
}

// ===========================================================================
// 56. DomPatchError serde roundtrip
// ===========================================================================

#[test]
fn dom_patch_error_serde_roundtrip_enrichment() {
    let errors = vec![
        DomPatchError::ElementNotFound(DomElementId(1)),
        DomPatchError::ElementAlreadyExists(DomElementId(2)),
        DomPatchError::ParentNotFound(DomElementId(3)),
        DomPatchError::InvalidReparent {
            id: DomElementId(4),
            new_parent: DomElementId(5),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: DomPatchError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *err);
    }
}

// ===========================================================================
// 57. SignalGraphError serde roundtrip
// ===========================================================================

#[test]
fn signal_graph_error_serde_roundtrip_enrichment() {
    let errors = vec![
        SignalGraphError::NotFound(SignalId(1)),
        SignalGraphError::CycleDetected {
            signal: SignalId(2),
            path: vec![SignalId(2), SignalId(3)],
        },
        SignalGraphError::Disposed(SignalId(4)),
        SignalGraphError::DuplicateSignal(SignalId(5)),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: SignalGraphError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *err);
    }
}

// ===========================================================================
// 58. DomTree RemoveProperty
// ===========================================================================

#[test]
fn dom_tree_remove_property_enrichment() {
    let mut tree = DomTree::new();
    tree.apply_patch(&DomPatch::CreateElement {
        id: DomElementId(0),
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    tree.apply_patch(&DomPatch::SetProperty {
        id: DomElementId(0),
        key: "style".into(),
        value: "color:red".into(),
    })
    .unwrap();
    tree.apply_patch(&DomPatch::RemoveProperty {
        id: DomElementId(0),
        key: "style".into(),
    })
    .unwrap();
    assert!(tree.get(DomElementId(0)).unwrap().properties.is_empty());
}

// ===========================================================================
// 59. DomTree parent-child relationship
// ===========================================================================

#[test]
fn dom_tree_parent_child_enrichment() {
    let mut tree = DomTree::new();
    tree.apply_patch(&DomPatch::CreateElement {
        id: DomElementId(0),
        tag: "div".into(),
        parent: None,
    })
    .unwrap();
    tree.apply_patch(&DomPatch::CreateElement {
        id: DomElementId(1),
        tag: "span".into(),
        parent: Some(DomElementId(0)),
    })
    .unwrap();

    let parent_rec = tree.get(DomElementId(0)).unwrap();
    assert!(parent_rec.children.contains(&DomElementId(1)));
    let child_rec = tree.get(DomElementId(1)).unwrap();
    assert_eq!(child_rec.parent, Some(DomElementId(0)));
}

// ===========================================================================
// 60. Scheduler max_updates_per_flush
// ===========================================================================

#[test]
fn scheduler_max_updates_per_flush_enrichment() {
    let mut s = UpdateScheduler::new();
    s.max_updates_per_flush = 2;
    s.schedule(SignalId(0), UpdatePriority::Normal, "A".into());
    s.schedule(SignalId(1), UpdatePriority::Normal, "B".into());
    s.schedule(SignalId(2), UpdatePriority::Normal, "C".into());
    let batch = s.drain_batch();
    assert_eq!(batch.len(), 2);
    assert_eq!(s.pending_count(), 1);
}
