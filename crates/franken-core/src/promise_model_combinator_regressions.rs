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
