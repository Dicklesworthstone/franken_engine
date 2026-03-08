#![forbid(unsafe_code)]

//! Integration tests for the iterator protocol substrate.
//!
//! Validates the iterator protocol types, trace recording, spread collection,
//! enumeration state, error handling, and serde round-trips across the public
//! API surface.
//!
//! Plan reference: bd-1lsy.4.8.1 [RGC-308A].

use frankenengine_engine::engine_object_id::{ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::iterator_protocol::*;
use frankenengine_engine::object_model::WellKnownSymbol;

fn test_schema() -> SchemaId {
    SchemaId::from_definition(ITERATOR_PROTOCOL_SCHEMA_VERSION.as_bytes())
}

fn make_id(label: &str) -> frankenengine_engine::engine_object_id::EngineObjectId {
    derive_id(
        ObjectDomain::EvidenceRecord,
        "iterator-protocol-integration",
        &test_schema(),
        label.as_bytes(),
    )
    .expect("derive_id should succeed")
}

// ---------------------------------------------------------------------------
// Full iteration session lifecycle
// ---------------------------------------------------------------------------

#[test]
fn full_for_of_lifecycle_records_correct_trace() {
    let trace_id = make_id("lifecycle_trace");
    let record_id = make_id("lifecycle_record");
    let iterable_ref = make_id("iterable_obj");

    let mut trace = IterationTrace::new(trace_id, record_id.clone(), IterationKind::ForOf);

    // GetIterator
    trace.record_event(make_get_iterator_event(
        record_id.clone(),
        0,
        IteratorSymbolKind::Iterator,
        iterable_ref,
    ));

    // Three values
    for i in 0..3 {
        trace.record_event(make_next_event(
            record_id.clone(),
            (i + 1) as u64,
            IteratorResult::value(IteratorValue::Integer(i * 10)),
        ));
    }

    // Done
    trace.record_event(make_next_event(record_id, 4, IteratorResult::done()));

    assert!(trace.completed);
    assert_eq!(trace.values_produced, 3);
    assert_eq!(trace.events.len(), 5);
    assert_eq!(trace.kind, IterationKind::ForOf);
}

#[test]
fn for_of_with_break_closes_iterator() {
    let record_id = make_id("break_record");
    let iterable_ref = make_id("break_iterable");
    let mut trace = IterationTrace::new(
        make_id("break_trace"),
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
    // break -> IteratorClose
    trace.record_event(make_close_event(
        record_id,
        2,
        CloseReason::Break,
        true, // return() was called
    ));

    assert!(trace.completed);
    assert_eq!(trace.values_produced, 1);
}

#[test]
fn for_of_with_throw_closes_iterator() {
    let record_id = make_id("throw_record");
    let mut trace = IterationTrace::new(
        make_id("throw_trace"),
        record_id.clone(),
        IterationKind::ForOf,
    );

    trace.record_event(make_close_event(
        record_id,
        0,
        CloseReason::Throw,
        false, // return() was not called (or didn't exist)
    ));

    assert!(trace.completed);
    assert_eq!(trace.values_produced, 0);
}

// ---------------------------------------------------------------------------
// Spread operations
// ---------------------------------------------------------------------------

#[test]
fn array_spread_collects_all_values() {
    let record_id = make_id("spread_record");
    let mut trace = IterationTrace::new(
        make_id("spread_trace"),
        record_id.clone(),
        IterationKind::ArraySpread,
    );

    let values_to_spread = vec![
        IteratorValue::Integer(1),
        IteratorValue::String("two".into()),
        IteratorValue::Boolean(true),
        IteratorValue::Null,
    ];

    for (i, val) in values_to_spread.iter().enumerate() {
        trace.record_event(make_next_event(
            record_id.clone(),
            i as u64,
            IteratorResult::value(val.clone()),
        ));
    }
    trace.record_event(make_next_event(record_id, 4, IteratorResult::done()));

    let collected = collect_spread_values(&trace);
    assert_eq!(collected, values_to_spread);
}

#[test]
fn call_spread_empty_iterable() {
    let record_id = make_id("empty_spread");
    let mut trace = IterationTrace::new(
        make_id("empty_trace"),
        record_id.clone(),
        IterationKind::CallSpread,
    );
    trace.record_event(make_next_event(record_id, 0, IteratorResult::done()));

    let collected = collect_spread_values(&trace);
    assert!(collected.is_empty());
}

// ---------------------------------------------------------------------------
// Destructuring
// ---------------------------------------------------------------------------

#[test]
fn destructuring_closes_after_consuming_needed_elements() {
    let record_id = make_id("destr_record");
    let mut trace = IterationTrace::new(
        make_id("destr_trace"),
        record_id.clone(),
        IterationKind::Destructuring,
    );

    // Consume 2 elements from an iterable with more
    trace.record_event(make_next_event(
        record_id.clone(),
        0,
        IteratorResult::value(IteratorValue::Integer(10)),
    ));
    trace.record_event(make_next_event(
        record_id.clone(),
        1,
        IteratorResult::value(IteratorValue::Integer(20)),
    ));
    // Close early
    trace.record_event(make_close_event(
        record_id,
        2,
        CloseReason::DestructuringExhausted,
        true,
    ));

    assert!(trace.completed);
    assert_eq!(trace.values_produced, 2);
}

// ---------------------------------------------------------------------------
// ForIn enumeration
// ---------------------------------------------------------------------------

#[test]
fn for_in_enumeration_basic_flow() {
    let obj = make_id("enum_obj");
    let keys = vec!["a".into(), "b".into(), "c".into(), "d".into()];
    let mut state = ForInEnumerationState::new(obj, keys);

    let mut collected = Vec::new();
    while let Some(key) = state.next_key() {
        collected.push(key);
    }

    assert_eq!(collected, vec!["a", "b", "c", "d"]);
    assert!(state.is_done());
}

#[test]
fn for_in_enumeration_with_runtime_deletion() {
    let obj = make_id("deletion_obj");
    let keys = vec![
        "alpha".into(),
        "beta".into(),
        "gamma".into(),
        "delta".into(),
    ];
    let mut state = ForInEnumerationState::new(obj, keys);

    // Yield first key
    assert_eq!(state.next_key(), Some("alpha".into()));

    // During iteration body, delete "gamma"
    state.mark_deleted("gamma");

    // Continue - should skip gamma
    assert_eq!(state.next_key(), Some("beta".into()));
    assert_eq!(state.next_key(), Some("delta".into()));
    assert_eq!(state.next_key(), None);
}

#[test]
fn for_in_enumeration_delete_already_yielded_key() {
    let obj = make_id("delete_yielded_obj");
    let keys = vec!["x".into(), "y".into(), "z".into()];
    let mut state = ForInEnumerationState::new(obj, keys);

    assert_eq!(state.next_key(), Some("x".into()));
    // Delete already-yielded key - should have no effect
    state.mark_deleted("x");
    assert_eq!(state.next_key(), Some("y".into()));
    assert_eq!(state.next_key(), Some("z".into()));
}

#[test]
fn for_in_enumeration_event_recording() {
    let record_id = make_id("forin_rec");
    let obj = make_id("forin_obj");
    let keys = vec!["name".into(), "age".into()];

    let event = make_enumerate_event(record_id.clone(), 0, obj.clone(), keys.clone());

    if let IterationOperation::EnumerateProperties {
        object_ref,
        keys: event_keys,
    } = &event.operation
    {
        assert_eq!(*object_ref, obj);
        assert_eq!(*event_keys, keys);
    } else {
        panic!("expected EnumerateProperties operation");
    }
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

#[test]
fn not_iterable_error_has_correct_kind() {
    let err = IteratorProtocolError::not_iterable("undefined");
    assert_eq!(err.kind, IterationErrorKind::NotIterable);
    assert!(err.to_string().contains("undefined is not iterable"));
}

#[test]
fn abrupt_completion_events_are_distinguishable() {
    let record_id = make_id("abrupt_rec");

    let normal_event = make_next_event(
        record_id.clone(),
        0,
        IteratorResult::value(IteratorValue::Integer(1)),
    );
    let abrupt_event = make_abrupt_event(
        record_id,
        1,
        IterationOperation::IteratorNext {
            result: IteratorResult::done(),
        },
        IterationErrorKind::NextResultNotObject,
    );

    assert!(matches!(
        normal_event.completion,
        IterationCompletion::Normal
    ));
    assert!(matches!(
        abrupt_event.completion,
        IterationCompletion::Abrupt { .. }
    ));
}

// ---------------------------------------------------------------------------
// Symbol integration
// ---------------------------------------------------------------------------

#[test]
fn iterator_symbol_maps_to_well_known_symbol() {
    let sync_key = IteratorSymbolKind::Iterator.property_key();
    let async_key = IteratorSymbolKind::AsyncIterator.property_key();

    assert_eq!(sync_key, WellKnownSymbol::Iterator.key());
    assert_eq!(async_key, WellKnownSymbol::AsyncIterator.key());

    // Symbols should be different
    assert_ne!(sync_key, async_key);
}

#[test]
fn symbol_ids_are_distinct() {
    let sync_id = IteratorSymbolKind::Iterator.symbol_id();
    let async_id = IteratorSymbolKind::AsyncIterator.symbol_id();
    assert_ne!(sync_id, async_id);
}

// ---------------------------------------------------------------------------
// Serde round-trip for all major types
// ---------------------------------------------------------------------------

#[test]
fn iteration_trace_json_round_trip_full_session() {
    let record_id = make_id("serde_rec");
    let iterable = make_id("serde_iter");
    let mut trace = IterationTrace::new(
        make_id("serde_trace"),
        record_id.clone(),
        IterationKind::ForOf,
    );

    trace.record_event(make_get_iterator_event(
        record_id.clone(),
        0,
        IteratorSymbolKind::Iterator,
        iterable,
    ));
    trace.record_event(make_next_event(
        record_id.clone(),
        1,
        IteratorResult::value(IteratorValue::String("hello".into())),
    ));
    trace.record_event(make_next_event(
        record_id.clone(),
        2,
        IteratorResult::value(IteratorValue::FixedPoint(1_500_000)),
    ));
    trace.record_event(make_next_event(
        record_id.clone(),
        3,
        IteratorResult::done(),
    ));

    let json = serde_json::to_string_pretty(&trace).expect("serialize");
    let parsed: IterationTrace = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(trace, parsed);
}

#[test]
fn for_in_state_json_round_trip() {
    let mut state = ForInEnumerationState::new(
        make_id("roundtrip_obj"),
        vec!["foo".into(), "bar".into(), "baz".into()],
    );
    state.next_key();
    state.mark_deleted("baz");

    let json = serde_json::to_string(&state).expect("serialize");
    let parsed: ForInEnumerationState = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(state, parsed);
}

#[test]
fn iterator_error_json_round_trip() {
    let errors = vec![
        IteratorProtocolError::not_iterable("number"),
        IteratorProtocolError::next_not_callable(make_id("err_rec")),
        IteratorProtocolError::next_result_not_object(make_id("err_rec2"), 7),
        IteratorProtocolError::iterator_method_not_object("Map"),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let parsed: IteratorProtocolError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, parsed);
    }
}

// ---------------------------------------------------------------------------
// Iterator value edge cases
// ---------------------------------------------------------------------------

#[test]
fn iterator_value_all_variants_display_and_serde() {
    let values = vec![
        IteratorValue::Undefined,
        IteratorValue::Null,
        IteratorValue::Boolean(true),
        IteratorValue::Boolean(false),
        IteratorValue::Integer(0),
        IteratorValue::Integer(i64::MAX),
        IteratorValue::Integer(i64::MIN),
        IteratorValue::String(String::new()),
        IteratorValue::String("with spaces".into()),
        IteratorValue::FixedPoint(0),
        IteratorValue::FixedPoint(1_000_000),
        IteratorValue::FixedPoint(-2_500_000),
        IteratorValue::ObjectRef(make_id("val_obj")),
        IteratorValue::Array(vec![]),
        IteratorValue::Array(vec![IteratorValue::Integer(1), IteratorValue::Null]),
    ];

    for val in &values {
        // Display doesn't panic
        let _display = val.to_string();

        // Serde round-trip
        let json = serde_json::to_string(val).expect("serialize");
        let parsed: IteratorValue = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*val, parsed);
    }
}

// ---------------------------------------------------------------------------
// Summary rendering
// ---------------------------------------------------------------------------

#[test]
fn summary_includes_all_key_fields() {
    let record_id = make_id("summary_rec");
    let mut trace = IterationTrace::new(
        make_id("summary_trace"),
        record_id.clone(),
        IterationKind::YieldDelegate,
    );
    trace.record_event(make_next_event(
        record_id.clone(),
        0,
        IteratorResult::value(IteratorValue::Integer(1)),
    ));
    trace.record_event(make_next_event(
        record_id.clone(),
        1,
        IteratorResult::value(IteratorValue::Integer(2)),
    ));
    trace.record_event(make_next_event(record_id, 2, IteratorResult::done()));

    let summary = render_iteration_summary(&trace);
    assert!(summary.contains("schema_version:"));
    assert!(summary.contains("kind: yield_delegate"));
    assert!(summary.contains("values_produced: 2"));
    assert!(summary.contains("completed: true"));
    assert!(summary.contains("events: 3"));
    // No abrupt_completions line since all are normal
    assert!(!summary.contains("abrupt_completions"));
}

#[test]
fn summary_shows_abrupt_count() {
    let record_id = make_id("abrupt_sum_rec");
    let mut trace = IterationTrace::new(
        make_id("abrupt_sum_trace"),
        record_id.clone(),
        IterationKind::ForOf,
    );
    trace.record_event(make_abrupt_event(
        record_id.clone(),
        0,
        IterationOperation::GetIterator {
            symbol: IteratorSymbolKind::Iterator,
            iterable_ref: make_id("bad_iter"),
        },
        IterationErrorKind::NotIterable,
    ));

    let summary = render_iteration_summary(&trace);
    assert!(summary.contains("abrupt_completions: 1"));
}

// ---------------------------------------------------------------------------
// IteratorRecord construction and serde
// ---------------------------------------------------------------------------

#[test]
fn iterator_record_all_kinds() {
    let kinds = vec![
        IterationKind::ForOf,
        IterationKind::ForIn,
        IterationKind::Destructuring,
        IterationKind::ArraySpread,
        IterationKind::CallSpread,
        IterationKind::YieldDelegate,
        IterationKind::CollectionConstruction,
        IterationKind::PromiseCombinator,
    ];

    for kind in kinds {
        let record = IteratorRecord {
            record_id: make_id(&format!("rec_{kind}")),
            iterator_ref: make_id("iter_ref"),
            next_method_ref: make_id("next_ref"),
            done: false,
            kind,
            step_count: 0,
        };
        let json = serde_json::to_string(&record).expect("serialize");
        let parsed: IteratorRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, parsed);
    }
}

// ---------------------------------------------------------------------------
// Validate function
// ---------------------------------------------------------------------------

#[test]
fn validate_various_iterator_results() {
    let results = vec![
        IteratorResult::value(IteratorValue::Undefined),
        IteratorResult::value(IteratorValue::Null),
        IteratorResult::value(IteratorValue::Integer(42)),
        IteratorResult::value(IteratorValue::String("x".into())),
        IteratorResult::done(),
        IteratorResult::done_with(IteratorValue::Boolean(true)),
    ];
    for result in &results {
        assert!(validate_iterator_result(result).is_ok());
    }
}

// ---------------------------------------------------------------------------
// Multi-step for-in simulation with trace
// ---------------------------------------------------------------------------

#[test]
fn for_in_full_lifecycle_with_trace() {
    let record_id = make_id("forin_lifecycle_rec");
    let obj = make_id("forin_lifecycle_obj");
    let keys = vec!["name".into(), "age".into(), "city".into()];
    let mut state = ForInEnumerationState::new(obj.clone(), keys.clone());

    let mut trace = IterationTrace::new(
        make_id("forin_lifecycle_trace"),
        record_id.clone(),
        IterationKind::ForIn,
    );

    // Record enumeration event
    trace.record_event(make_enumerate_event(
        record_id.clone(),
        0,
        obj,
        keys,
    ));

    // Iterate and record next events
    let mut step = 1u64;
    while let Some(key) = state.next_key() {
        trace.record_event(make_next_event(
            record_id.clone(),
            step,
            IteratorResult::value(IteratorValue::String(key)),
        ));
        step += 1;
    }

    trace.record_event(make_next_event(record_id, step, IteratorResult::done()));

    assert!(trace.completed);
    assert_eq!(trace.values_produced, 3);
    assert_eq!(trace.events.len(), 5); // 1 enumerate + 3 next + 1 done
    assert!(state.is_done());
}

// ---------------------------------------------------------------------------
// Generator yield delegate pattern
// ---------------------------------------------------------------------------

#[test]
fn yield_delegate_pattern_traces_correctly() {
    let record_id = make_id("yield_deleg_rec");
    let inner_iterable = make_id("yield_inner");
    let mut trace = IterationTrace::new(
        make_id("yield_deleg_trace"),
        record_id.clone(),
        IterationKind::YieldDelegate,
    );

    trace.record_event(make_get_iterator_event(
        record_id.clone(),
        0,
        IteratorSymbolKind::Iterator,
        inner_iterable,
    ));

    // Yield 5 values from inner generator
    for i in 0..5 {
        trace.record_event(make_next_event(
            record_id.clone(),
            (i + 1) as u64,
            IteratorResult::value(IteratorValue::Integer(i * 100)),
        ));
    }

    // Done with final return value
    trace.record_event(make_next_event(
        record_id,
        6,
        IteratorResult::done_with(IteratorValue::String("generator_return".into())),
    ));

    assert!(trace.completed);
    assert_eq!(trace.values_produced, 5);
    let spread = collect_spread_values(&trace);
    assert_eq!(spread.len(), 5);
}

// ---------------------------------------------------------------------------
// Collection construction pattern
// ---------------------------------------------------------------------------

#[test]
fn collection_construction_pattern() {
    let record_id = make_id("collection_rec");
    let source = make_id("collection_source");
    let mut trace = IterationTrace::new(
        make_id("collection_trace"),
        record_id.clone(),
        IterationKind::CollectionConstruction,
    );

    trace.record_event(make_get_iterator_event(
        record_id.clone(),
        0,
        IteratorSymbolKind::Iterator,
        source,
    ));

    // Array.from with mixed types
    let items = vec![
        IteratorValue::Integer(1),
        IteratorValue::String("two".into()),
        IteratorValue::Boolean(false),
        IteratorValue::FixedPoint(3_140_000),
    ];
    for (i, item) in items.iter().enumerate() {
        trace.record_event(make_next_event(
            record_id.clone(),
            (i + 1) as u64,
            IteratorResult::value(item.clone()),
        ));
    }
    trace.record_event(make_next_event(record_id, 5, IteratorResult::done()));

    let collected = collect_spread_values(&trace);
    assert_eq!(collected, items);
    assert_eq!(trace.kind, IterationKind::CollectionConstruction);
}

// ---------------------------------------------------------------------------
// Promise combinator pattern
// ---------------------------------------------------------------------------

#[test]
fn promise_combinator_traces_iterable_of_promises() {
    let record_id = make_id("promise_rec");
    let mut trace = IterationTrace::new(
        make_id("promise_trace"),
        record_id.clone(),
        IterationKind::PromiseCombinator,
    );

    // Promise.all receives object refs (promises)
    let promise_refs: Vec<_> = (0..3)
        .map(|i| IteratorValue::ObjectRef(make_id(&format!("promise_{i}"))))
        .collect();

    for (i, pref) in promise_refs.iter().enumerate() {
        trace.record_event(make_next_event(
            record_id.clone(),
            i as u64,
            IteratorResult::value(pref.clone()),
        ));
    }
    trace.record_event(make_next_event(record_id, 3, IteratorResult::done()));

    let spread = collect_spread_values(&trace);
    assert_eq!(spread.len(), 3);
    for val in &spread {
        assert!(matches!(val, IteratorValue::ObjectRef(_)));
    }
}

// ---------------------------------------------------------------------------
// Error recovery patterns
// ---------------------------------------------------------------------------

#[test]
fn error_in_next_followed_by_close() {
    let record_id = make_id("err_next_rec");
    let mut trace = IterationTrace::new(
        make_id("err_next_trace"),
        record_id.clone(),
        IterationKind::ForOf,
    );

    // First value OK
    trace.record_event(make_next_event(
        record_id.clone(),
        0,
        IteratorResult::value(IteratorValue::Integer(1)),
    ));

    // Second next() returns non-object — abrupt
    trace.record_event(make_abrupt_event(
        record_id.clone(),
        1,
        IterationOperation::IteratorNext {
            result: IteratorResult::done(),
        },
        IterationErrorKind::NextResultNotObject,
    ));

    // Close with throw
    trace.record_event(make_close_event(record_id, 2, CloseReason::Throw, true));

    assert!(trace.completed);
    assert_eq!(trace.values_produced, 1);
    assert_eq!(trace.events.len(), 3);

    let summary = render_iteration_summary(&trace);
    assert!(summary.contains("abrupt_completions: 1"));
}

#[test]
fn iterator_method_not_object_error() {
    let err = IteratorProtocolError::iterator_method_not_object("Set");
    assert_eq!(err.kind, IterationErrorKind::IteratorMethodNotObject);
    assert!(err.message.contains("Set"));
    assert!(err.message.contains("Symbol.iterator"));
    assert!(err.record_id.is_none());
    assert!(err.step_index.is_none());
}

// ---------------------------------------------------------------------------
// Large iteration traces
// ---------------------------------------------------------------------------

#[test]
fn large_iteration_trace_handles_many_events() {
    let record_id = make_id("large_rec");
    let iterable = make_id("large_iterable");
    let mut trace = IterationTrace::new(
        make_id("large_trace"),
        record_id.clone(),
        IterationKind::ForOf,
    );

    trace.record_event(make_get_iterator_event(
        record_id.clone(),
        0,
        IteratorSymbolKind::Iterator,
        iterable,
    ));

    let n = 100;
    for i in 0..n {
        trace.record_event(make_next_event(
            record_id.clone(),
            (i + 1) as u64,
            IteratorResult::value(IteratorValue::Integer(i)),
        ));
    }
    trace.record_event(make_next_event(
        record_id,
        (n + 1) as u64,
        IteratorResult::done(),
    ));

    assert!(trace.completed);
    assert_eq!(trace.values_produced, n as u64);
    assert_eq!(trace.events.len(), (n + 2) as usize);

    let spread = collect_spread_values(&trace);
    assert_eq!(spread.len(), n as usize);

    // Verify serde round-trip for large trace
    let json = serde_json::to_string(&trace).expect("serialize large");
    let parsed: IterationTrace = serde_json::from_str(&json).expect("deserialize large");
    assert_eq!(trace, parsed);
}

// ---------------------------------------------------------------------------
// Nested array values in spread
// ---------------------------------------------------------------------------

#[test]
fn nested_array_spread_values() {
    let record_id = make_id("nested_rec");
    let mut trace = IterationTrace::new(
        make_id("nested_trace"),
        record_id.clone(),
        IterationKind::ArraySpread,
    );

    let nested = IteratorValue::Array(vec![
        IteratorValue::Array(vec![IteratorValue::Integer(1), IteratorValue::Integer(2)]),
        IteratorValue::Array(vec![IteratorValue::String("inner".into())]),
    ]);

    trace.record_event(make_next_event(
        record_id.clone(),
        0,
        IteratorResult::value(nested.clone()),
    ));
    trace.record_event(make_next_event(record_id, 1, IteratorResult::done()));

    let spread = collect_spread_values(&trace);
    assert_eq!(spread.len(), 1);
    assert_eq!(spread[0], nested);
}

// ---------------------------------------------------------------------------
// Deterministic serialization
// ---------------------------------------------------------------------------

#[test]
fn trace_serialization_is_deterministic_across_calls() {
    let record_id = make_id("det_rec");
    let mut trace = IterationTrace::new(
        make_id("det_trace"),
        record_id.clone(),
        IterationKind::ForOf,
    );
    trace.record_event(make_next_event(
        record_id.clone(),
        0,
        IteratorResult::value(IteratorValue::Integer(42)),
    ));
    trace.record_event(make_next_event(record_id, 1, IteratorResult::done()));

    let json1 = serde_json::to_string(&trace).expect("ser1");
    let json2 = serde_json::to_string(&trace).expect("ser2");
    assert_eq!(json1, json2, "serialization must be deterministic");
}

// ---------------------------------------------------------------------------
// IterationKind display coverage
// ---------------------------------------------------------------------------

#[test]
fn all_iteration_kinds_have_distinct_display() {
    let kinds = vec![
        IterationKind::ForOf,
        IterationKind::ForIn,
        IterationKind::Destructuring,
        IterationKind::ArraySpread,
        IterationKind::CallSpread,
        IterationKind::YieldDelegate,
        IterationKind::CollectionConstruction,
        IterationKind::PromiseCombinator,
    ];
    let displays: Vec<String> = kinds.iter().map(|k| k.to_string()).collect();
    // All displays should be unique
    for (i, d1) in displays.iter().enumerate() {
        for (j, d2) in displays.iter().enumerate() {
            if i != j {
                assert_ne!(d1, d2, "kinds {i} and {j} have same display");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Close reason coverage
// ---------------------------------------------------------------------------

#[test]
fn all_close_reasons_serde_round_trip() {
    let reasons = vec![
        CloseReason::Break,
        CloseReason::Return,
        CloseReason::Throw,
        CloseReason::DestructuringExhausted,
    ];
    for reason in &reasons {
        let json = serde_json::to_string(reason).expect("serialize");
        let parsed: CloseReason = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*reason, parsed);
        // Display works
        let _d = reason.to_string();
    }
}
