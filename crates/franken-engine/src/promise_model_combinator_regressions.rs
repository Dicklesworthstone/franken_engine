//! One-shot resolve/reject element guards for Promise combinator state.

use super::*;

fn all(total: u32) -> PromiseAllTracker {
    PromiseAllTracker {
        result_promise: PromiseHandle(0),
        values: BTreeMap::new(),
        total,
        resolved_count: 0,
        settled: false,
    }
}

fn all_settled(total: u32) -> PromiseAllSettledTracker {
    PromiseAllSettledTracker {
        result_promise: PromiseHandle(0),
        outcomes: BTreeMap::new(),
        total,
        settled_count: 0,
    }
}

fn any(total: u32) -> PromiseAnyTracker {
    PromiseAnyTracker {
        result_promise: PromiseHandle(0),
        errors: BTreeMap::new(),
        total,
        rejected_count: 0,
        settled: false,
    }
}

#[test]
fn all_preserves_first_values_and_announces_completion_once() {
    let mut tracker = all(2);
    assert!(!tracker.record_fulfillment(1, JsValue::Int(20)));
    assert!(!tracker.record_fulfillment(1, JsValue::Int(99)));
    assert_eq!(tracker.resolved_count, 1);
    assert!(tracker.record_fulfillment(0, JsValue::Int(10)));
    assert!(!tracker.record_fulfillment(0, JsValue::Int(88)));
    assert!(!tracker.record_fulfillment(1, JsValue::Int(77)));
    assert_eq!(
        tracker.collect_values(),
        vec![JsValue::Int(10), JsValue::Int(20)]
    );
    assert_eq!(tracker.resolved_count, 2);
}

#[test]
fn all_settled_shares_one_guard_between_fulfillment_and_rejection() {
    let mut tracker = all_settled(2);
    assert!(!tracker.record_fulfillment(0, JsValue::Int(10)));
    assert!(!tracker.record_rejection(0, JsValue::Int(99)));
    assert!(!tracker.record_fulfillment(0, JsValue::Int(88)));
    assert!(tracker.record_rejection(1, JsValue::Int(20)));
    assert!(!tracker.record_fulfillment(1, JsValue::Int(77)));
    assert!(!tracker.record_rejection(1, JsValue::Int(66)));
    assert_eq!(tracker.settled_count, 2);
    assert_eq!(tracker.outcomes[&0].status, "fulfilled");
    assert_eq!(tracker.outcomes[&0].value, JsValue::Int(10));
    assert_eq!(tracker.outcomes[&1].status, "rejected");
    assert_eq!(tracker.outcomes[&1].value, JsValue::Int(20));
}

#[test]
fn any_preserves_first_reasons_in_input_order() {
    let mut tracker = any(2);
    assert!(!tracker.record_rejection(1, JsValue::Int(20)));
    assert!(!tracker.record_rejection(1, JsValue::Int(99)));
    assert!(tracker.record_rejection(0, JsValue::Int(10)));
    assert!(!tracker.record_rejection(0, JsValue::Int(88)));
    assert!(!tracker.record_rejection(1, JsValue::Int(77)));
    assert_eq!(tracker.rejected_count, 2);
    assert_eq!(
        tracker.collect_errors(),
        vec![JsValue::Int(10), JsValue::Int(20)]
    );
}

#[test]
fn out_of_range_callbacks_never_fabricate_progress() {
    for index in [2, 3, u32::MAX] {
        let mut a = all(2);
        let mut s = all_settled(2);
        let mut n = any(2);
        assert!(!a.record_fulfillment(index, JsValue::Int(99)));
        assert!(!s.record_fulfillment(index, JsValue::Int(99)));
        assert!(!s.record_rejection(index, JsValue::Int(99)));
        assert!(!n.record_rejection(index, JsValue::Int(99)));
        assert_eq!(a.resolved_count, 0);
        assert_eq!(s.settled_count, 0);
        assert_eq!(n.rejected_count, 0);
        assert!(a.values.is_empty());
        assert!(s.outcomes.is_empty());
        assert!(n.errors.is_empty());
        assert!(!a.record_fulfillment(0, JsValue::Int(10)));
        assert!(a.record_fulfillment(1, JsValue::Int(20)));
        assert!(!s.record_fulfillment(0, JsValue::Int(10)));
        assert!(s.record_rejection(1, JsValue::Int(20)));
        assert!(!n.record_rejection(0, JsValue::Int(10)));
        assert!(n.record_rejection(1, JsValue::Int(20)));
    }
}

#[test]
fn empty_input_and_explicitly_settled_trackers_ignore_callbacks() {
    let mut a = all(0);
    let mut s = all_settled(0);
    let mut n = any(0);
    assert!(!a.record_fulfillment(0, JsValue::Undefined));
    assert!(!s.record_fulfillment(0, JsValue::Undefined));
    assert!(!s.record_rejection(0, JsValue::Undefined));
    assert!(!n.record_rejection(0, JsValue::Undefined));
    assert!(a.values.is_empty() && s.outcomes.is_empty() && n.errors.is_empty());
    let mut a = all(2);
    let mut n = any(2);
    a.mark_settled();
    n.mark_settled();
    assert!(!a.record_fulfillment(0, JsValue::Int(1)));
    assert!(!n.record_rejection(0, JsValue::Int(1)));
    assert_eq!(a.resolved_count, 0);
    assert_eq!(n.rejected_count, 0);
}

#[test]
fn one_shot_guards_survive_checkpoint_restore() {
    let mut tracker = all_settled(2);
    tracker.record_rejection(0, JsValue::Int(42));
    let wire = serde_json::to_vec(&tracker).unwrap();
    let mut restored: PromiseAllSettledTracker = serde_json::from_slice(&wire).unwrap();
    assert!(!restored.record_fulfillment(0, JsValue::Int(99)));
    assert_eq!(restored.outcomes[&0].value, JsValue::Int(42));
    assert_eq!(restored.outcomes[&0].status, "rejected");
    assert!(restored.record_fulfillment(1, JsValue::Int(7)));
    assert!(!restored.record_rejection(1, JsValue::Int(88)));
    assert_eq!(restored.settled_count, 2);
}

#[test]
fn native_element_jobs_share_registration_order_and_survive_restore_bd_9vouw_295() {
    for rejected in [false, true] {
        for settled_first in [false, true] {
            let mut store = PromiseStore::new();
            let mut queue = MicrotaskQueue::new();
            let source = store.create();
            let aggregate = store.create();
            let payload = JsValue::Object(crate::object_model::ObjectHandle(37));
            let settle = |store: &mut PromiseStore, queue: &mut MicrotaskQueue| {
                if rejected {
                    store.reject(source, payload.clone(), Label::Secret, queue)
                } else {
                    store.fulfill(source, payload.clone(), Label::Secret, queue)
                }
                .unwrap();
            };
            if settled_first {
                settle(&mut store, &mut queue);
            }
            let before = store
                .then(source, None, None, Label::Public, &mut queue)
                .unwrap();
            for index in 0..2 {
                store
                    .then_for_combinator(
                        source,
                        aggregate,
                        Label::Confidential,
                        PromiseCombinatorReaction {
                            combinator_id: 19,
                            index,
                        },
                        &mut queue,
                    )
                    .unwrap();
            }
            let after = store
                .then(source, None, None, Label::Public, &mut queue)
                .unwrap();

            // A checkpoint may contain pending native registrations or
            // already-enqueued native jobs; both preserve the same sequence.
            let store_wire = serde_json::to_vec(&store).unwrap();
            let queue_wire = serde_json::to_vec(&queue).unwrap();
            store = serde_json::from_slice(&store_wire).unwrap();
            queue = serde_json::from_slice(&queue_wire).unwrap();
            if !settled_first {
                assert!(queue.is_empty());
                let mut promises = Vec::new();
                store.for_each_edge(source, |edge| {
                    if let PromiseEdge::Promise(handle) = edge {
                        promises.push(handle);
                    }
                });
                assert_eq!(promises.iter().filter(|&&p| p == aggregate).count(), 4);
                settle(&mut store, &mut queue);
            }
            assert!(store.get(source).unwrap().rejection_handled);
            assert_eq!(store.get(aggregate).unwrap().state, PromiseState::Pending);
            let mut roots = Vec::new();
            queue.for_each_promise(|handle| roots.push(handle));
            assert_eq!(roots, [before, aggregate, aggregate, after]);
            let mut values = Vec::new();
            queue.for_each_value(|value| values.push(value.clone()));
            assert_eq!(values, vec![payload.clone(); 4]);
            queue.for_each_handler(|_| panic!("native jobs must not fabricate a handler"));

            for (position, expected_result) in roots.into_iter().enumerate() {
                let task = queue.dequeue().unwrap();
                if position == 1 || position == 2 {
                    assert_eq!(
                        task,
                        Microtask::PromiseCombinator {
                            combinator: PromiseCombinatorReaction {
                                combinator_id: 19,
                                index: (position - 1) as u32,
                            },
                            kind: if rejected {
                                ReactionKind::Reject
                            } else {
                                ReactionKind::Fulfill
                            },
                            argument: payload.clone(),
                            result_promise: expected_result,
                            label: Label::Secret,
                        }
                    );
                } else {
                    let expected = if rejected {
                        Microtask::PromiseRejection {
                            reason: payload.clone(),
                            result_promise: expected_result,
                            label: Label::Secret,
                        }
                    } else {
                        Microtask::PromiseReaction {
                            handler: None,
                            argument: payload.clone(),
                            result_promise: expected_result,
                            label: Label::Secret,
                        }
                    };
                    assert_eq!(task, expected);
                }
            }
            assert!(queue.is_empty());
            queue.compact();
            assert_eq!(
                queue.estimated_memory_bytes(),
                queue.estimated_memory_bytes_by_walk()
            );
            assert_eq!(
                store.estimated_memory_bytes(),
                store.estimated_memory_bytes_by_walk()
            );
        }
    }
}

#[test]
fn native_element_dependency_closes_on_terminal_failure_bd_9vouw_295() {
    let mut store = PromiseStore::new();
    let mut queue = MicrotaskQueue::new();
    let source = store.create();
    let aggregate = store.create();
    store
        .then_for_combinator(
            source,
            aggregate,
            Label::Secret,
            PromiseCombinatorReaction {
                combinator_id: 8,
                index: 0,
            },
            &mut queue,
        )
        .unwrap();
    let descendant = store
        .then(aggregate, None, None, Label::Public, &mut queue)
        .unwrap();
    let unrelated = store.create();
    let epoch = store
        .terminally_reject_without_jobs(source, &Label::Secret)
        .unwrap();
    for handle in [source, aggregate, descendant] {
        assert!(store.was_terminally_rejected_in_epoch(handle, epoch));
        let record = store.get(handle).unwrap();
        assert_eq!(record.state, PromiseState::Rejected(JsValue::Undefined));
        assert_eq!(record.label, Label::Secret);
        assert!(record.reactions.is_empty());
    }
    assert_eq!(store.get(unrelated).unwrap().state, PromiseState::Pending);
    assert!(queue.is_empty());
}
