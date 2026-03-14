#![forbid(unsafe_code)]

//! Enrichment integration tests for iterator_protocol.

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

use std::collections::BTreeSet;

use frankenengine_engine::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::iterator_protocol::*;

// ── Helpers ──────────────────────────────────────────────────────────────

fn test_schema() -> SchemaId {
    SchemaId::from_definition(ITERATOR_PROTOCOL_SCHEMA_VERSION.as_bytes())
}

fn make_id(label: &str) -> EngineObjectId {
    derive_id(
        ObjectDomain::EvidenceRecord,
        "iter-proto-enrich-test",
        &test_schema(),
        label.as_bytes(),
    )
    .expect("derive_id should succeed")
}

// ===========================================================================
// 1. IteratorValue — Clone independence, Display uniqueness, serde
// ===========================================================================

#[test]
fn enrichment_iterator_value_clone_independence_string() {
    let original = IteratorValue::String("hello".to_string());
    let mut cloned = original.clone();
    if let IteratorValue::String(ref mut s) = cloned {
        s.push_str("_mutated");
    }
    assert_eq!(original, IteratorValue::String("hello".to_string()));
    assert_eq!(cloned, IteratorValue::String("hello_mutated".to_string()));
}

#[test]
fn enrichment_iterator_value_clone_independence_array() {
    let original = IteratorValue::Array(vec![IteratorValue::Integer(1), IteratorValue::Integer(2)]);
    let mut cloned = original.clone();
    if let IteratorValue::Array(ref mut arr) = cloned {
        arr.push(IteratorValue::Integer(3));
    }
    if let IteratorValue::Array(ref arr) = original {
        assert_eq!(arr.len(), 2);
    }
    if let IteratorValue::Array(ref arr) = cloned {
        assert_eq!(arr.len(), 3);
    }
}

#[test]
fn enrichment_iterator_value_display_all_unique() {
    let variants: Vec<IteratorValue> = vec![
        IteratorValue::Undefined,
        IteratorValue::Null,
        IteratorValue::Boolean(true),
        IteratorValue::Boolean(false),
        IteratorValue::Integer(42),
        IteratorValue::String("x".to_string()),
        IteratorValue::FixedPoint(1_000_000),
        IteratorValue::ObjectRef(make_id("obj")),
        IteratorValue::Array(vec![]),
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(
        displays.len(),
        variants.len(),
        "some Display outputs collide"
    );
}

#[test]
fn enrichment_iterator_value_serde_all_variants() {
    let variants: Vec<IteratorValue> = vec![
        IteratorValue::Undefined,
        IteratorValue::Null,
        IteratorValue::Boolean(true),
        IteratorValue::Boolean(false),
        IteratorValue::Integer(i64::MAX),
        IteratorValue::Integer(i64::MIN),
        IteratorValue::String("".to_string()),
        IteratorValue::FixedPoint(-999_999),
        IteratorValue::ObjectRef(make_id("serde_obj")),
        IteratorValue::Array(vec![IteratorValue::Integer(1), IteratorValue::Null]),
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let restored: IteratorValue = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, restored);
    }
}

#[test]
fn enrichment_iterator_value_debug_all_nonempty() {
    let variants: Vec<IteratorValue> = vec![
        IteratorValue::Undefined,
        IteratorValue::Null,
        IteratorValue::Boolean(true),
        IteratorValue::Integer(0),
        IteratorValue::String("s".to_string()),
        IteratorValue::FixedPoint(0),
        IteratorValue::ObjectRef(make_id("dbg")),
        IteratorValue::Array(vec![]),
    ];
    for v in &variants {
        let dbg = format!("{v:?}");
        assert!(!dbg.is_empty());
    }
}

// ===========================================================================
// 2. IteratorResult — Clone independence
// ===========================================================================

#[test]
fn enrichment_iterator_result_clone_independence() {
    let original = IteratorResult::value(IteratorValue::String("original".to_string()));
    let mut cloned = original.clone();
    cloned.done = true;
    assert!(!original.done);
    assert!(cloned.done);
}

#[test]
fn enrichment_iterator_result_debug_nonempty() {
    let r = IteratorResult::done();
    let dbg = format!("{r:?}");
    assert!(dbg.contains("IteratorResult"));
}

// ===========================================================================
// 3. IterationKind — Copy, Ord, BTreeSet, Display uniqueness
// ===========================================================================

#[test]
fn enrichment_iteration_kind_copy_semantics() {
    let a = IterationKind::ForOf;
    let b = a;
    let c = a;
    assert_eq!(b, c);
    assert_eq!(a.to_string(), "for_of");
}

#[test]
fn enrichment_iteration_kind_ord_btreeset_dedup() {
    let all = [
        IterationKind::ForOf,
        IterationKind::ForIn,
        IterationKind::Destructuring,
        IterationKind::ArraySpread,
        IterationKind::CallSpread,
        IterationKind::YieldDelegate,
        IterationKind::CollectionConstruction,
        IterationKind::PromiseCombinator,
    ];
    let set: BTreeSet<IterationKind> = all.iter().copied().collect();
    assert_eq!(set.len(), 8);
    // Insert duplicates
    let mut set2 = set.clone();
    for k in &all {
        set2.insert(*k);
    }
    assert_eq!(set2.len(), 8);
}

#[test]
fn enrichment_iteration_kind_display_all_unique() {
    let all = [
        IterationKind::ForOf,
        IterationKind::ForIn,
        IterationKind::Destructuring,
        IterationKind::ArraySpread,
        IterationKind::CallSpread,
        IterationKind::YieldDelegate,
        IterationKind::CollectionConstruction,
        IterationKind::PromiseCombinator,
    ];
    let displays: BTreeSet<String> = all.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), 8);
}

#[test]
fn enrichment_iteration_kind_debug_all_unique() {
    let all = [
        IterationKind::ForOf,
        IterationKind::ForIn,
        IterationKind::Destructuring,
        IterationKind::ArraySpread,
        IterationKind::CallSpread,
        IterationKind::YieldDelegate,
        IterationKind::CollectionConstruction,
        IterationKind::PromiseCombinator,
    ];
    let debugs: BTreeSet<String> = all.iter().map(|k| format!("{k:?}")).collect();
    assert_eq!(debugs.len(), 8);
}

// ===========================================================================
// 4. IteratorSymbolKind — Copy, Ord, serde
// ===========================================================================

#[test]
fn enrichment_iterator_symbol_kind_copy_semantics() {
    let a = IteratorSymbolKind::Iterator;
    let b = a;
    let c = a;
    assert_eq!(b, c);
}

#[test]
fn enrichment_iterator_symbol_kind_ord_btreeset() {
    let set: BTreeSet<IteratorSymbolKind> = [
        IteratorSymbolKind::Iterator,
        IteratorSymbolKind::AsyncIterator,
    ]
    .iter()
    .copied()
    .collect();
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_iterator_symbol_kind_serde_roundtrip() {
    for kind in [
        IteratorSymbolKind::Iterator,
        IteratorSymbolKind::AsyncIterator,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let restored: IteratorSymbolKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, restored);
    }
}

#[test]
fn enrichment_iterator_symbol_kind_symbol_ids_distinct() {
    let sync_id = IteratorSymbolKind::Iterator.symbol_id();
    let async_id = IteratorSymbolKind::AsyncIterator.symbol_id();
    assert_ne!(sync_id, async_id);
}

// ===========================================================================
// 5. CloseReason — Clone, Display uniqueness, serde
// ===========================================================================

#[test]
fn enrichment_close_reason_display_all_unique() {
    let all = [
        CloseReason::Break,
        CloseReason::Return,
        CloseReason::Throw,
        CloseReason::DestructuringExhausted,
    ];
    let displays: BTreeSet<String> = all.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_close_reason_clone_independence() {
    let original = CloseReason::Break;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_close_reason_serde_all_variants() {
    let all = [
        CloseReason::Break,
        CloseReason::Return,
        CloseReason::Throw,
        CloseReason::DestructuringExhausted,
    ];
    for reason in &all {
        let json = serde_json::to_string(reason).unwrap();
        let restored: CloseReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, restored);
    }
}

// ===========================================================================
// 6. IterationErrorKind — Display uniqueness, serde
// ===========================================================================

#[test]
fn enrichment_iteration_error_kind_display_all_unique() {
    let all = [
        IterationErrorKind::NotIterable,
        IterationErrorKind::IteratorMethodNotObject,
        IterationErrorKind::NextNotCallable,
        IterationErrorKind::NextResultNotObject,
        IterationErrorKind::DoneNotBoolean,
        IterationErrorKind::UserException,
    ];
    let displays: BTreeSet<String> = all.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_iteration_error_kind_debug_all_unique() {
    let all = [
        IterationErrorKind::NotIterable,
        IterationErrorKind::IteratorMethodNotObject,
        IterationErrorKind::NextNotCallable,
        IterationErrorKind::NextResultNotObject,
        IterationErrorKind::DoneNotBoolean,
        IterationErrorKind::UserException,
    ];
    let debugs: BTreeSet<String> = all.iter().map(|k| format!("{k:?}")).collect();
    assert_eq!(debugs.len(), 6);
}

#[test]
fn enrichment_iteration_error_kind_serde_all_variants() {
    let all = [
        IterationErrorKind::NotIterable,
        IterationErrorKind::IteratorMethodNotObject,
        IterationErrorKind::NextNotCallable,
        IterationErrorKind::NextResultNotObject,
        IterationErrorKind::DoneNotBoolean,
        IterationErrorKind::UserException,
    ];
    for kind in &all {
        let json = serde_json::to_string(kind).unwrap();
        let restored: IterationErrorKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, restored);
    }
}

// ===========================================================================
// 7. IterationCompletion — serde, Debug uniqueness
// ===========================================================================

#[test]
fn enrichment_iteration_completion_debug_all_unique() {
    let all = [
        IterationCompletion::Normal,
        IterationCompletion::NotIterable,
        IterationCompletion::InvalidResult,
        IterationCompletion::CloseThrew,
        IterationCompletion::Abrupt {
            error_kind: IterationErrorKind::UserException,
        },
    ];
    let debugs: BTreeSet<String> = all.iter().map(|c| format!("{c:?}")).collect();
    assert_eq!(debugs.len(), 5);
}

#[test]
fn enrichment_iteration_completion_serde_all() {
    let all = [
        IterationCompletion::Normal,
        IterationCompletion::NotIterable,
        IterationCompletion::InvalidResult,
        IterationCompletion::CloseThrew,
        IterationCompletion::Abrupt {
            error_kind: IterationErrorKind::NotIterable,
        },
        IterationCompletion::Abrupt {
            error_kind: IterationErrorKind::UserException,
        },
    ];
    for c in &all {
        let json = serde_json::to_string(c).unwrap();
        let restored: IterationCompletion = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, restored);
    }
}

// ===========================================================================
// 8. IteratorProtocolError — Clone, Display, serde
// ===========================================================================

#[test]
fn enrichment_iterator_protocol_error_clone_independence() {
    let original = IteratorProtocolError::not_iterable("Array");
    let mut cloned = original.clone();
    cloned.message = "mutated".to_string();
    assert!(original.message.contains("Array"));
    assert_eq!(cloned.message, "mutated");
}

#[test]
fn enrichment_iterator_protocol_error_display_contains_kind_and_message() {
    let err = IteratorProtocolError::not_iterable("42");
    let display = err.to_string();
    assert!(display.contains("not_iterable"));
    assert!(display.contains("42 is not iterable"));
    assert!(display.contains("IteratorProtocolError"));
}

#[test]
fn enrichment_iterator_protocol_error_serde_all_constructors() {
    let id = make_id("err_serde");
    let errors = vec![
        IteratorProtocolError::not_iterable("number"),
        IteratorProtocolError::next_not_callable(id.clone()),
        IteratorProtocolError::next_result_not_object(id.clone(), 7),
        IteratorProtocolError::iterator_method_not_object("Map"),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: IteratorProtocolError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

#[test]
fn enrichment_iterator_protocol_error_json_field_names() {
    let err = IteratorProtocolError::not_iterable("test");
    let json = serde_json::to_string(&err).unwrap();
    assert!(json.contains("\"kind\""));
    assert!(json.contains("\"message\""));
    assert!(json.contains("\"record_id\""));
    assert!(json.contains("\"step_index\""));
}

// ===========================================================================
// 9. IteratorRecord — Clone independence, serde, Debug
// ===========================================================================

#[test]
fn enrichment_iterator_record_clone_independence() {
    let original = IteratorRecord {
        record_id: make_id("rec_clone"),
        iterator_ref: make_id("iter_clone"),
        next_method_ref: make_id("next_clone"),
        done: false,
        kind: IterationKind::ForOf,
        step_count: 5,
    };
    let mut cloned = original.clone();
    cloned.done = true;
    cloned.step_count = 99;
    assert!(!original.done);
    assert_eq!(original.step_count, 5);
    assert!(cloned.done);
    assert_eq!(cloned.step_count, 99);
}

#[test]
fn enrichment_iterator_record_debug_nonempty() {
    let record = IteratorRecord {
        record_id: make_id("rec_dbg"),
        iterator_ref: make_id("iter_dbg"),
        next_method_ref: make_id("next_dbg"),
        done: false,
        kind: IterationKind::Destructuring,
        step_count: 0,
    };
    let dbg = format!("{record:?}");
    assert!(dbg.contains("IteratorRecord"));
}

#[test]
fn enrichment_iterator_record_json_field_names() {
    let record = IteratorRecord {
        record_id: make_id("rec_json"),
        iterator_ref: make_id("iter_json"),
        next_method_ref: make_id("next_json"),
        done: true,
        kind: IterationKind::ForIn,
        step_count: 42,
    };
    let json = serde_json::to_string(&record).unwrap();
    assert!(json.contains("\"record_id\""));
    assert!(json.contains("\"iterator_ref\""));
    assert!(json.contains("\"next_method_ref\""));
    assert!(json.contains("\"done\""));
    assert!(json.contains("\"kind\""));
    assert!(json.contains("\"step_count\""));
}

// ===========================================================================
// 10. IterationEvent — Clone independence, serde
// ===========================================================================

#[test]
fn enrichment_iteration_event_clone_independence() {
    let event = make_next_event(
        make_id("ev_clone"),
        0,
        IteratorResult::value(IteratorValue::Integer(42)),
    );
    let mut cloned = event.clone();
    cloned.step_index = 99;
    assert_eq!(event.step_index, 0);
    assert_eq!(cloned.step_index, 99);
}

#[test]
fn enrichment_iteration_event_json_field_names() {
    let event = make_next_event(
        make_id("ev_json"),
        5,
        IteratorResult::value(IteratorValue::Null),
    );
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("\"record_id\""));
    assert!(json.contains("\"step_index\""));
    assert!(json.contains("\"operation\""));
    assert!(json.contains("\"completion\""));
}

// ===========================================================================
// 11. IterationTrace — Clone, determinism, cross-cutting invariants
// ===========================================================================

#[test]
fn enrichment_iteration_trace_clone_independence() {
    let record_id = make_id("trace_clone_rec");
    let mut trace = IterationTrace::new(
        make_id("trace_clone"),
        record_id.clone(),
        IterationKind::ForOf,
    );
    trace.record_event(make_next_event(
        record_id,
        0,
        IteratorResult::value(IteratorValue::Integer(1)),
    ));
    let mut cloned = trace.clone();
    cloned.completed = true;
    cloned.events.clear();
    assert!(!trace.completed);
    assert_eq!(trace.events.len(), 1);
    assert!(cloned.completed);
    assert!(cloned.events.is_empty());
}

#[test]
fn enrichment_iteration_trace_values_produced_equals_non_done_next_count() {
    let record_id = make_id("trace_count_rec");
    let mut trace = IterationTrace::new(
        make_id("trace_count"),
        record_id.clone(),
        IterationKind::ArraySpread,
    );
    for i in 0..10 {
        trace.record_event(make_next_event(
            record_id.clone(),
            i,
            IteratorResult::value(IteratorValue::Integer(i as i64)),
        ));
    }
    trace.record_event(make_next_event(record_id, 10, IteratorResult::done()));
    assert_eq!(trace.values_produced, 10);
    assert!(trace.completed);
    assert_eq!(trace.events.len(), 11);
}

#[test]
fn enrichment_iteration_trace_serde_roundtrip_with_mixed_events() {
    let record_id = make_id("trace_mixed_rec");
    let iterable_ref = make_id("iterable_mixed");
    let mut trace = IterationTrace::new(
        make_id("trace_mixed"),
        record_id.clone(),
        IterationKind::ForOf,
    );
    trace.record_event(make_get_iterator_event(
        record_id.clone(),
        0,
        IteratorSymbolKind::Iterator,
        iterable_ref,
    ));
    trace.record_event(make_next_event(
        record_id.clone(),
        1,
        IteratorResult::value(IteratorValue::String("hello".to_string())),
    ));
    trace.record_event(make_close_event(record_id, 2, CloseReason::Break, true));

    let json = serde_json::to_string(&trace).unwrap();
    let restored: IterationTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(trace, restored);
}

#[test]
fn enrichment_iteration_trace_json_field_names() {
    let trace = IterationTrace::new(
        make_id("trace_fields"),
        make_id("rec_fields"),
        IterationKind::ForOf,
    );
    let json = serde_json::to_string(&trace).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"bead_id\""));
    assert!(json.contains("\"trace_id\""));
    assert!(json.contains("\"record_id\""));
    assert!(json.contains("\"kind\""));
    assert!(json.contains("\"events\""));
    assert!(json.contains("\"completed\""));
    assert!(json.contains("\"values_produced\""));
}

// ===========================================================================
// 12. ForInEnumerationState — Clone, serde, edge cases
// ===========================================================================

#[test]
fn enrichment_for_in_state_clone_independence() {
    let mut original =
        ForInEnumerationState::new(make_id("forin_clone"), vec!["a".into(), "b".into()]);
    original.next_key();
    let mut cloned = original.clone();
    cloned.mark_deleted("b");
    // Original should still yield "b"
    assert_eq!(original.next_key(), Some("b".into()));
    // Cloned should skip "b"
    assert_eq!(cloned.next_key(), None);
}

#[test]
fn enrichment_for_in_state_debug_nonempty() {
    let state = ForInEnumerationState::new(make_id("forin_dbg"), vec!["x".into()]);
    let dbg = format!("{state:?}");
    assert!(dbg.contains("ForInEnumerationState"));
}

#[test]
fn enrichment_for_in_state_json_field_names() {
    let state = ForInEnumerationState::new(make_id("forin_json"), vec!["k".into()]);
    let json = serde_json::to_string(&state).unwrap();
    assert!(json.contains("\"object_ref\""));
    assert!(json.contains("\"keys\""));
    assert!(json.contains("\"current_index\""));
    assert!(json.contains("\"deleted_keys\""));
    assert!(json.contains("\"done\""));
}

#[test]
fn enrichment_for_in_large_key_set() {
    let keys: Vec<String> = (0..100).map(|i| format!("key_{i}")).collect();
    let mut state = ForInEnumerationState::new(make_id("forin_large"), keys.clone());
    let mut collected = Vec::new();
    while let Some(key) = state.next_key() {
        collected.push(key);
    }
    assert_eq!(collected.len(), 100);
    assert_eq!(collected, keys);
    assert!(state.is_done());
}

// ===========================================================================
// 13. collect_spread_values — edge cases
// ===========================================================================

#[test]
fn enrichment_collect_spread_values_ignores_close_events() {
    let record_id = make_id("spread_close");
    let mut trace = IterationTrace::new(
        make_id("t_spread_close"),
        record_id.clone(),
        IterationKind::ArraySpread,
    );
    trace.record_event(make_next_event(
        record_id.clone(),
        0,
        IteratorResult::value(IteratorValue::Integer(1)),
    ));
    trace.record_event(make_close_event(record_id, 1, CloseReason::Break, true));
    let values = collect_spread_values(&trace);
    assert_eq!(values.len(), 1);
    assert_eq!(values[0], IteratorValue::Integer(1));
}

#[test]
fn enrichment_collect_spread_values_with_done_with() {
    let record_id = make_id("spread_done_with");
    let mut trace = IterationTrace::new(
        make_id("t_spread_dw"),
        record_id.clone(),
        IterationKind::ArraySpread,
    );
    trace.record_event(make_next_event(
        record_id.clone(),
        0,
        IteratorResult::value(IteratorValue::Integer(1)),
    ));
    // done_with has a value but done=true, so collect should NOT include it
    trace.record_event(make_next_event(
        record_id,
        1,
        IteratorResult::done_with(IteratorValue::Integer(99)),
    ));
    let values = collect_spread_values(&trace);
    assert_eq!(values.len(), 1);
    assert_eq!(values[0], IteratorValue::Integer(1));
}

// ===========================================================================
// 14. render_iteration_summary — content checks
// ===========================================================================

#[test]
fn enrichment_render_summary_no_abrupt_omits_abrupt_line() {
    let trace = IterationTrace::new(
        make_id("summ_no_abrupt"),
        make_id("rec_no_abrupt"),
        IterationKind::ForOf,
    );
    let summary = render_iteration_summary(&trace);
    assert!(!summary.contains("abrupt_completions"));
}

#[test]
fn enrichment_render_summary_includes_kind() {
    for kind in [
        IterationKind::ForOf,
        IterationKind::ForIn,
        IterationKind::Destructuring,
        IterationKind::ArraySpread,
    ] {
        let trace = IterationTrace::new(make_id("summ_kind"), make_id("rec_kind"), kind);
        let summary = render_iteration_summary(&trace);
        assert!(
            summary.contains(&format!("kind: {kind}")),
            "summary should contain kind for {kind:?}"
        );
    }
}

// ===========================================================================
// 15. Determinism — 5-run proof
// ===========================================================================

#[test]
fn enrichment_full_trace_determinism_five_runs() {
    for _run in 0..5 {
        let record_id = make_id("det_rec");
        let iterable_ref = make_id("det_iterable");
        let mut trace = IterationTrace::new(
            make_id("det_trace"),
            record_id.clone(),
            IterationKind::ForOf,
        );
        trace.record_event(make_get_iterator_event(
            record_id.clone(),
            0,
            IteratorSymbolKind::Iterator,
            iterable_ref,
        ));
        for i in 1..=3 {
            trace.record_event(make_next_event(
                record_id.clone(),
                i,
                IteratorResult::value(IteratorValue::Integer(i as i64)),
            ));
        }
        trace.record_event(make_next_event(record_id, 4, IteratorResult::done()));
        assert_eq!(trace.values_produced, 3);
        assert!(trace.completed);
        assert_eq!(trace.events.len(), 5);
    }
}

#[test]
fn enrichment_trace_serde_determinism_five_runs() {
    let record_id = make_id("det_serde_rec");
    let mut trace = IterationTrace::new(
        make_id("det_serde_t"),
        record_id.clone(),
        IterationKind::ForOf,
    );
    trace.record_event(make_next_event(
        record_id.clone(),
        0,
        IteratorResult::value(IteratorValue::Integer(1)),
    ));
    trace.record_event(make_next_event(record_id, 1, IteratorResult::done()));
    let baseline_json = serde_json::to_string(&trace).unwrap();
    for run in 1..=5 {
        let json = serde_json::to_string(&trace).unwrap();
        assert_eq!(baseline_json, json, "serde run {run} diverged");
    }
}

// ===========================================================================
// 16. Cross-cutting: step_index monotonicity in events
// ===========================================================================

#[test]
fn enrichment_step_indices_in_trace_are_sequential() {
    let record_id = make_id("step_seq_rec");
    let iterable_ref = make_id("step_seq_iter");
    let mut trace = IterationTrace::new(
        make_id("step_seq_t"),
        record_id.clone(),
        IterationKind::ForOf,
    );
    trace.record_event(make_get_iterator_event(
        record_id.clone(),
        0,
        IteratorSymbolKind::Iterator,
        iterable_ref,
    ));
    trace.record_event(make_next_event(
        record_id.clone(),
        1,
        IteratorResult::value(IteratorValue::Integer(1)),
    ));
    trace.record_event(make_next_event(
        record_id.clone(),
        2,
        IteratorResult::value(IteratorValue::Integer(2)),
    ));
    trace.record_event(make_close_event(record_id, 3, CloseReason::Break, true));

    for (i, event) in trace.events.iter().enumerate() {
        assert_eq!(
            event.step_index, i as u64,
            "step_index mismatch at position {i}"
        );
    }
}

// ===========================================================================
// 17. Constants stability
// ===========================================================================

#[test]
fn enrichment_schema_version_format() {
    assert!(ITERATOR_PROTOCOL_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(ITERATOR_PROTOCOL_SCHEMA_VERSION.contains("iterator-protocol"));
    assert!(ITERATOR_PROTOCOL_SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn enrichment_bead_id_format() {
    assert!(ITERATOR_PROTOCOL_BEAD_ID.starts_with("bd-"));
}

// ===========================================================================
// 18. FixedPoint Display edge cases
// ===========================================================================

#[test]
fn enrichment_fixed_point_large_value() {
    let val = IteratorValue::FixedPoint(999_999_999_999);
    let display = val.to_string();
    assert!(display.contains("."));
    // 999_999_999_999 / 1_000_000 = 999999, frac = 999999
    assert_eq!(display, "999999.999999");
}

#[test]
fn enrichment_fixed_point_negative_fraction() {
    // -500_000 → whole = 0, frac = unsigned_abs(500_000) = 500000
    let val = IteratorValue::FixedPoint(-500_000);
    let display = val.to_string();
    assert_eq!(display, "0.500000");
}

// ===========================================================================
// 19. validate_iterator_result always succeeds
// ===========================================================================

#[test]
fn enrichment_validate_iterator_result_all_value_types_ok() {
    let results = vec![
        IteratorResult::value(IteratorValue::Undefined),
        IteratorResult::value(IteratorValue::Null),
        IteratorResult::value(IteratorValue::Boolean(false)),
        IteratorResult::value(IteratorValue::Integer(0)),
        IteratorResult::value(IteratorValue::String("".to_string())),
        IteratorResult::value(IteratorValue::FixedPoint(0)),
        IteratorResult::value(IteratorValue::Array(vec![])),
        IteratorResult::done(),
        IteratorResult::done_with(IteratorValue::Integer(42)),
    ];
    for r in &results {
        assert!(validate_iterator_result(r).is_ok());
    }
}
