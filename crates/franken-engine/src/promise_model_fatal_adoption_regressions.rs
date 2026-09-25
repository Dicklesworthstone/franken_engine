//! Fatal Promise adoption graph regressions.

use super::*;

fn adopt(store: &mut PromiseStore, source: PromiseHandle, target: PromiseHandle) {
    store
        .register_native_adoption(source, target, Label::Public)
        .expect("pending source accepts native adoption");
}

fn assert_terminal(store: &PromiseStore, handle: PromiseHandle, epoch: u64, label: &Label) {
    let record = store.get(handle).expect("live Promise slot");
    assert_eq!(record.state, PromiseState::Rejected(JsValue::Undefined));
    assert_eq!(&record.label, label);
    assert_eq!(
        record.terminal_epoch, epoch,
        "no temporary worklist link remains"
    );
    assert!(!record.rejection_handled);
    assert!(record.reactions.is_empty());
    assert_eq!(record.reactions.capacity(), 0);
    assert!(store.was_terminally_rejected_in_epoch(handle, epoch));
}

#[test]
fn fatal_adoption_reaches_older_adopter_and_its_then_descendants() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let adopter = store.create();
    let descendant = store
        .then(adopter, None, None, Label::Secret, &mut queue)
        .expect("adopter's dependent");
    let unrelated = store.create();
    let source = store.create();
    assert!(adopter.0 < descendant.0 && descendant.0 < source.0);
    adopt(&mut store, source, adopter);
    let witness = store.witness_log().to_vec();
    let before_bytes = store.estimated_memory_bytes();

    let epoch = store
        .terminally_reject_without_jobs(source, &Label::Secret)
        .expect("terminal rejection");

    for handle in [source, adopter, descendant] {
        assert_terminal(&store, handle, epoch, &Label::Secret);
    }
    assert_eq!(store.get(unrelated).unwrap().state, PromiseState::Pending);
    assert_eq!(store.witness_log(), witness);
    assert_eq!(queue.total_enqueued(), 0);
    assert!(store.estimated_memory_bytes() <= before_bytes);
}

#[test]
fn fatal_adoption_visits_cycles_self_edges_and_shared_dependents_once() {
    let mut store = PromiseStore::new();
    let handles: Vec<_> = (0..5).map(|_| store.create()).collect();
    for (source, target) in [(4, 2), (4, 3), (2, 0), (3, 0), (0, 4), (2, 2)] {
        adopt(&mut store, handles[source], handles[target]);
    }
    let count = store
        .extend_terminal_rejection_without_jobs(handles[4], &Label::Internal, 17)
        .expect("cycle-safe fatal graph walk");
    assert_eq!(count, 4, "duplicate fulfill/reject edges count only once");
    for index in [0, 2, 3, 4] {
        assert_terminal(&store, handles[index], 17, &Label::Internal);
    }
    assert_eq!(store.get(handles[1]).unwrap().state, PromiseState::Pending);
}

#[test]
fn fatal_adoption_preserves_unrelated_reactions_and_incoming_sources() {
    let mut store = PromiseStore::new();
    let handles: Vec<_> = (0..8).map(|_| store.create()).collect();
    // Only outgoing dependency edges propagate failure. A source feeding
    // the failed component is not itself invalidated by that component.
    for (source, target) in [(5, 1), (1, 6), (6, 2), (7, 5), (0, 3), (3, 4)] {
        adopt(&mut store, handles[source], handles[target]);
    }
    let untouched: Vec<_> = [0, 3, 4, 7]
        .into_iter()
        .map(|index| (handles[index], store.get(handles[index]).unwrap().clone()))
        .collect();
    assert_eq!(
        store
            .extend_terminal_rejection_without_jobs(handles[5], &Label::Confidential, 9)
            .unwrap(),
        4
    );
    for index in [1, 2, 5, 6] {
        assert_terminal(&store, handles[index], 9, &Label::Confidential);
    }
    for (handle, before) in untouched {
        assert_eq!(store.get(handle).unwrap(), &before);
    }
}

#[test]
fn fatal_adoption_does_not_overwrite_settled_targets() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let fulfilled = store.resolve(JsValue::Int(41), Label::Secret, &mut queue);
    let rejected = store.reject_with(JsValue::Int(42), Label::Confidential, &mut queue);
    let source = store.create();
    adopt(&mut store, source, fulfilled);
    adopt(&mut store, source, rejected);
    let before_fulfilled = store.get(fulfilled).unwrap().clone();
    let before_rejected = store.get(rejected).unwrap().clone();
    let witness = store.witness_log().to_vec();
    assert_eq!(
        store
            .extend_terminal_rejection_without_jobs(source, &Label::TopSecret, 3)
            .unwrap(),
        1
    );
    assert_eq!(store.get(fulfilled).unwrap(), &before_fulfilled);
    assert_eq!(store.get(rejected).unwrap(), &before_rejected);
    assert_eq!(store.witness_log(), witness);
}

#[test]
fn fatal_adoption_skips_vacant_and_invalid_slots_without_losing_live_edges() {
    let mut store = PromiseStore::new();
    let removed = store.create();
    let live = store.create();
    let source = store.create();
    adopt(&mut store, source, removed);
    adopt(&mut store, source, PromiseHandle(u32::MAX));
    adopt(&mut store, source, live);
    store
        .remove_pending_at_execution_boundary(removed)
        .expect("unpublished pending slot can be removed");
    let witness = store.witness_log().to_vec();
    assert_eq!(
        store
            .extend_terminal_rejection_without_jobs(source, &Label::Public, 3)
            .unwrap(),
        2
    );
    assert!(matches!(
        store.get(removed),
        Err(PromiseError::InvalidHandle { .. })
    ));
    assert_terminal(&store, live, 3, &Label::Public);
    assert_terminal(&store, source, 3, &Label::Public);
    assert_eq!(store.witness_log(), witness);
}

#[test]
fn fatal_adoption_root_errors_leave_store_unchanged() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let settled = store.resolve(JsValue::Int(5), Label::Internal, &mut queue);
    let pending = store.create();
    let before = serde_json::to_vec(&store).unwrap();
    assert_eq!(
        store.extend_terminal_rejection_without_jobs(PromiseHandle(99), &Label::Secret, 7),
        Err(PromiseError::InvalidHandle {
            handle: PromiseHandle(99)
        })
    );
    assert_eq!(
        store.extend_terminal_rejection_without_jobs(settled, &Label::Secret, 7),
        Err(PromiseError::AlreadySettled { handle: settled })
    );
    assert_eq!(serde_json::to_vec(&store).unwrap(), before);
    assert_eq!(store.get(pending).unwrap().state, PromiseState::Pending);
}

#[test]
fn fatal_adoption_repeat_and_epoch_extension_preserve_completed_closures() {
    let mut store = PromiseStore::new();
    let handles: Vec<_> = (0..7).map(|_| store.create()).collect();
    for (source, target) in [(4, 0), (0, 2), (6, 2), (6, 1), (1, 5)] {
        adopt(&mut store, handles[source], handles[target]);
    }
    let epoch = store
        .terminally_reject_without_jobs(handles[4], &Label::Secret)
        .unwrap();
    let after_first = serde_json::to_vec(&store).unwrap();
    assert_eq!(
        store.extend_terminal_rejection_without_jobs(handles[0], &Label::Public, epoch),
        Ok(0)
    );
    assert_eq!(serde_json::to_vec(&store).unwrap(), after_first);
    assert_eq!(
        store.extend_terminal_rejection_without_jobs(handles[6], &Label::Secret, epoch),
        Ok(3)
    );
    for index in [0, 1, 2, 4, 5, 6] {
        assert_terminal(&store, handles[index], epoch, &Label::Secret);
    }
    assert_eq!(store.get(handles[3]).unwrap().state, PromiseState::Pending);
}

#[test]
fn fatal_adoption_deep_reverse_chain_requires_no_recursive_stack() {
    const COUNT: usize = 16_384;
    let mut store = PromiseStore::new();
    let handles: Vec<_> = (0..COUNT).map(|_| store.create()).collect();
    for pair in handles.windows(2) {
        adopt(&mut store, pair[1], pair[0]);
    }
    let witness_count = store.witness_log().len();
    assert_eq!(
        store.extend_terminal_rejection_without_jobs(handles[COUNT - 1], &Label::Secret, 1),
        Ok(COUNT)
    );
    for handle in handles {
        assert_terminal(&store, handle, 1, &Label::Secret);
    }
    assert_eq!(store.witness_log().len(), witness_count);
}

#[test]
fn fatal_adoption_uses_reaction_slot_identity_not_record_backreference() {
    let mut store = PromiseStore::new();
    let child = store.create();
    let source = store.create();
    adopt(&mut store, source, child);
    // The public serialized backreference is not permission to address a
    // different slot: traversal must follow the actual reaction handle.
    store
        .update(child, |record| record.handle = PromiseHandle(u32::MAX))
        .unwrap();
    assert_eq!(
        store.extend_terminal_rejection_without_jobs(source, &Label::Internal, 2),
        Ok(2)
    );
    assert_terminal(&store, child, 2, &Label::Internal);
    assert_terminal(&store, source, 2, &Label::Internal);
}

#[test]
fn fatal_adoption_compacts_labels_without_extra_jobs_or_witnesses() {
    let labels = [
        Label::Public,
        Label::Internal,
        Label::Confidential,
        Label::Secret,
        Label::TopSecret,
        Label::Custom {
            name: "terminal-label".repeat(4096),
            level: u32::MAX,
        },
    ];
    for label in labels {
        let mut store = PromiseStore::new();
        let target = store.create();
        let source = store.create();
        adopt(&mut store, source, target);
        let witness = store.witness_log().to_vec();
        let before_bytes = store.estimated_memory_bytes();
        let epoch = store
            .terminally_reject_without_jobs(source, &label)
            .unwrap();
        for handle in [source, target] {
            let record = store.get(handle).unwrap();
            assert_eq!(record.label.level(), label.level());
            assert_eq!(record.terminal_epoch, epoch);
            if let Label::Custom { name, .. } = &record.label {
                assert!(name.is_empty());
                assert_eq!(name.capacity(), 0);
            } else {
                assert_eq!(record.label, label);
            }
        }
        assert_eq!(store.witness_log(), witness);
        assert!(store.estimated_memory_bytes() <= before_bytes);
    }
}

#[test]
fn fatal_adoption_snapshot_retains_final_state_without_temporary_links() {
    let mut store = PromiseStore::new();
    let handles: Vec<_> = (0..4).map(|_| store.create()).collect();
    for (source, target) in [(3, 1), (3, 0), (0, 2), (2, 1)] {
        adopt(&mut store, handles[source], handles[target]);
    }
    let epoch = store
        .terminally_reject_without_jobs(handles[3], &Label::Secret)
        .unwrap();
    let snapshot = serde_json::to_value(&store).unwrap();
    let records = snapshot["promises"].as_array().unwrap();
    for record in records {
        assert!(record.get("terminal_epoch").is_none());
        assert!(record.get("terminal_next").is_none());
    }
    let restored: PromiseStore = serde_json::from_value(snapshot).unwrap();
    assert_eq!(restored.next_seq, store.next_seq);
    assert_eq!(restored.witness_log(), store.witness_log());
    for handle in handles {
        assert_terminal(&store, handle, epoch, &Label::Secret);
        let record = restored.get(handle).unwrap();
        assert_eq!(record.handle, handle);
        assert_eq!(record.creation_seq, u64::from(handle.0));
        assert_eq!(record.state, PromiseState::Rejected(JsValue::Undefined));
        assert_eq!(record.label, Label::Secret);
        assert!(record.reactions.is_empty());
        assert_eq!(
            record.terminal_epoch, 0,
            "transient marker is not persisted"
        );
    }
}

#[test]
fn fatal_adoption_generated_graphs_match_independent_reachability() {
    const COUNT: usize = 24;
    let mut random = 0x6d2b_79f5_u32;
    for case in 0..256 {
        let mut store = PromiseStore::new();
        let handles: Vec<_> = (0..COUNT).map(|_| store.create()).collect();
        let mut edges = vec![Vec::new(); COUNT];
        for (source, row) in edges.iter_mut().enumerate() {
            for (target, target_handle) in handles.iter().copied().enumerate() {
                random ^= random << 13;
                random ^= random >> 17;
                random ^= random << 5;
                if random.is_multiple_of(11) {
                    row.push(target);
                    adopt(&mut store, handles[source], target_handle);
                }
            }
        }
        let root = case % COUNT;
        let mut expected = vec![false; COUNT];
        let mut work = vec![root];
        while let Some(node) = work.pop() {
            if expected[node] {
                continue;
            }
            expected[node] = true;
            work.extend(edges[node].iter().copied());
        }
        let expected_count = expected.iter().filter(|&&visited| visited).count();
        // Deliberately collide epoch values with encoded worklist links.
        let epoch = (case % COUNT) as u64 + 1;
        assert_eq!(
            store.extend_terminal_rejection_without_jobs(handles[root], &Label::Secret, epoch),
            Ok(expected_count),
            "graph case {case}"
        );
        for (index, handle) in handles.into_iter().enumerate() {
            if expected[index] {
                assert_terminal(&store, handle, epoch, &Label::Secret);
            } else {
                assert_eq!(store.get(handle).unwrap().state, PromiseState::Pending);
                assert_eq!(store.get(handle).unwrap().terminal_epoch, 0);
                assert_eq!(
                    store.get(handle).unwrap().reactions.len(),
                    2 * edges[index].len()
                );
            }
        }
    }
}
