#![forbid(unsafe_code)]

//! PERF-H6.3 capacity-hint regression tests (bd-o4cbn.4.3).
//!
//! H6.2 (bd-o4cbn.4.2) replaced `Vec::new()` with `Vec::with_capacity(n)` at
//! several hot-path constructors. A capacity hint must NOT change the final
//! length, contents, or order of the produced collection — it only pre-sizes
//! the backing allocation. These tests exercise each modified call site
//! through its public API and assert the final `Vec`/`String` content equals
//! the expected ordered sequence, guarding against an accidental semantic
//! change (e.g. a stray `truncate`, reordering, or off-by-one) sneaking in
//! alongside a future capacity-hint tweak.
//!
//! Modified sites covered (per H6.1 audit / H6.2 sweep):
//!   * `iterator_protocol::IterationTrace::new` — `events` Vec (cap 16)
//!   * `deterministic_sim_scheduler::SimReplayLog::new` — `entries` Vec (cap 128)
//!   * `evidence_ledger::EvidenceEntryBuilder::new` — candidates/constraints/witnesses
//!   * `lowering_pipeline::lower_ir0_to_ir3` — destructure_params/body_bindings Vecs

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::deterministic_sim_scheduler::{
    SimEventKind, SimPriority, SimReplayEntry, SimReplayLog,
};
use frankenengine_engine::engine_object_id::{EngineObjectId, ObjectDomain, derive_id};
use frankenengine_engine::evidence_ledger::{
    CandidateAction, ChosenAction, Constraint, DecisionType, EvidenceEntryBuilder, Witness,
};
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::iterator_protocol::{
    CloseReason, IterationKind, IterationOperation, IterationTrace, IteratorResult,
    IteratorSymbolKind, IteratorValue, make_close_event, make_get_iterator_event, make_next_event,
};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn test_schema_id() -> frankenengine_engine::engine_object_id::SchemaId {
    frankenengine_engine::engine_object_id::SchemaId::from_definition(b"perf-h6.3-regression")
}

fn test_id(label: &str) -> EngineObjectId {
    // Canonical bytes must be non-empty (derive_id rejects EmptyCanonicalBytes).
    derive_id(
        ObjectDomain::EvidenceRecord,
        label,
        &test_schema_id(),
        label.as_bytes(),
    )
    .expect("id derivation must succeed")
}

/// `IterationTrace::new` pre-sizes `events` to 16. Recording a known sequence
/// of events must yield exactly that sequence, in order, with no extra/dropped
/// entries regardless of the capacity hint.
#[test]
fn iteration_trace_events_preserve_order_and_content() {
    let trace_id = test_id("trace-it");
    let record_id = test_id("record-it");
    let iterable_ref = test_id("iterable-it");
    let mut trace = IterationTrace::new(trace_id, record_id.clone(), IterationKind::ForOf);

    // Empty trace starts with a zero-length events Vec (cap 16, len 0).
    assert!(trace.events.is_empty());

    trace.record_event(make_get_iterator_event(
        record_id.clone(),
        0,
        IteratorSymbolKind::Iterator,
        iterable_ref,
    ));
    trace.record_event(make_next_event(
        record_id.clone(),
        1,
        IteratorResult::value(IteratorValue::Integer(10)),
    ));
    trace.record_event(make_next_event(
        record_id.clone(),
        2,
        IteratorResult::value(IteratorValue::Integer(20)),
    ));
    trace.record_event(make_close_event(record_id, 3, CloseReason::Break, true));

    // Exact length and ordered content of the capacity-hinted Vec.
    assert_eq!(trace.events.len(), 4, "all four recorded events retained");
    assert_eq!(trace.values_produced, 2, "two non-done Next results");

    // Assert the ordered operation sequence is exactly what was recorded.
    assert!(matches!(
        trace.events[0].operation,
        IterationOperation::GetIterator { .. }
    ));
    assert!(matches!(
        &trace.events[1].operation,
        IterationOperation::IteratorNext { result } if result.value == IteratorValue::Integer(10)
    ));
    assert!(matches!(
        &trace.events[2].operation,
        IterationOperation::IteratorNext { result } if result.value == IteratorValue::Integer(20)
    ));
    assert!(matches!(
        trace.events[3].operation,
        IterationOperation::IteratorClose { .. }
    ));
    // Step indices preserved in dispatch order.
    let steps: Vec<u64> = trace.events.iter().map(|e| e.step_index).collect();
    assert_eq!(steps, vec![0, 1, 2, 3]);
}

/// `SimReplayLog::new` pre-sizes `entries` to 128. Pushing a known ordered
/// sequence of entries must reproduce exactly that sequence — the capacity
/// hint must not reorder, drop, or duplicate any entry.
#[test]
fn sim_replay_log_entries_preserve_order_and_content() {
    let mut log = SimReplayLog::new();
    assert!(log.is_empty());

    let expected = vec![
        SimReplayEntry {
            tick: 0,
            event_id: 0,
            kind: SimEventKind::EventLoopTick,
            priority: SimPriority::Normal,
        },
        SimReplayEntry {
            tick: 1,
            event_id: 1,
            kind: SimEventKind::ModuleLoad,
            priority: SimPriority::HighPriority,
        },
        SimReplayEntry {
            tick: 2,
            event_id: 2,
            kind: SimEventKind::MicrotaskDrain,
            priority: SimPriority::Microtask,
        },
    ];
    for entry in &expected {
        log.push(entry.clone());
    }

    assert_eq!(log.len(), expected.len());
    // Full ordered structural equality of the capacity-hinted Vec.
    assert_eq!(log.entries, expected);
}

/// `EvidenceEntryBuilder::new` pre-sizes candidates(4)/constraints(8)/
/// witnesses(4). Each builder Vec must contain exactly the appended items in
/// the documented order (candidates & constraints in insertion order;
/// witnesses sorted by `witness_id` for determinism).
#[test]
fn evidence_builder_vecs_preserve_order_and_content() {
    let entry = EvidenceEntryBuilder::new(
        "trace-ev",
        "decision-ev",
        "policy-ev",
        SecurityEpoch::from_raw(7),
        DecisionType::ContractEvaluation,
    )
    .candidate(CandidateAction::new("alpha", 100))
    .candidate(CandidateAction::new("beta", 200))
    .candidate(CandidateAction::new("gamma", 300))
    .constraint(Constraint {
        constraint_id: "c-1".to_string(),
        description: "first".to_string(),
        active: true,
    })
    .constraint(Constraint {
        constraint_id: "c-2".to_string(),
        description: "second".to_string(),
        active: false,
    })
    // Inserted out of id order to exercise the builder's deterministic sort.
    .witness(Witness {
        witness_id: "w-2".to_string(),
        witness_type: "t".to_string(),
        value: "v2".to_string(),
    })
    .witness(Witness {
        witness_id: "w-1".to_string(),
        witness_type: "t".to_string(),
        value: "v1".to_string(),
    })
    // A chosen action is required for the entry to build (MissingChosenAction).
    .chosen(ChosenAction {
        action_name: "alpha".to_string(),
        expected_loss_millionths: 100,
        rationale: "regression fixture".to_string(),
    })
    .build()
    .expect("evidence entry must build");

    // Candidates: insertion order preserved.
    let candidate_names: Vec<&str> = entry
        .candidates
        .iter()
        .map(|c| c.action_name.as_str())
        .collect();
    assert_eq!(candidate_names, vec!["alpha", "beta", "gamma"]);

    // Constraints: insertion order preserved.
    let constraint_ids: Vec<&str> = entry
        .constraints
        .iter()
        .map(|c| c.constraint_id.as_str())
        .collect();
    assert_eq!(constraint_ids, vec!["c-1", "c-2"]);

    // Witnesses: deterministically sorted by witness_id.
    let witness_ids: Vec<&str> = entry
        .witnesses
        .iter()
        .map(|w| w.witness_id.as_str())
        .collect();
    assert_eq!(witness_ids, vec!["w-1", "w-2"]);
}

const LOWERING_SOURCE: &str = r#"
function process({ alpha, beta }, [first, second], gamma) {
    const a = alpha + beta;
    let b = first - second;
    var c = gamma * 2;
    const d = a + b + c;
    return d;
}
process({ alpha: 1, beta: 2 }, [3, 4], 5);
"#;

fn parse_lowering_source() -> Ir0Module {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse_with_options(
            LOWERING_SOURCE,
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("lowering regression source must parse");
    Ir0Module::from_syntax_tree(tree, "perf_h6_lowering_regression.js")
}

/// `lower_ir0_to_ir3` builds `destructure_params` and `body_bindings` Vecs
/// with capacity hints during the IR0→IR1 stage. Lowering a function with
/// destructuring params plus several body variable declarations must be
/// deterministic: two independent lowerings of the same source must yield the
/// identical outcome. The capacity hint pre-sizes those Vecs but must not
/// perturb binding allocation order or content.
///
/// The pipeline is fail-closed on ambient-authority (a function body may
/// require an effect the empty caller profile lacks), so this test asserts
/// determinism of the *Result* regardless of Ok/Err — the capacity-hinted
/// allocation paths run before that gate either way, so a nondeterminism
/// regression there would surface as divergent IR1/IR3 or divergent errors.
#[test]
fn lowering_destructure_and_body_bindings_are_deterministic() {
    let ir0_a = parse_lowering_source();
    let ir0_b = parse_lowering_source();
    let ctx = LoweringContext::new("trace-lower", "decision-lower", "policy-lower");

    let out_a = lower_ir0_to_ir3(&ir0_a, &ctx);
    let out_b = lower_ir0_to_ir3(&ir0_b, &ctx);

    match (&out_a, &out_b) {
        (Ok(a), Ok(b)) => {
            // The full IR3/IR1 modules (which embed the body_bindings /
            // destructure_params results) must be identical across runs.
            assert_eq!(
                a.ir3, b.ir3,
                "IR3 lowering of destructuring + body-binding function must be deterministic"
            );
            assert_eq!(a.ir1, b.ir1, "IR1 stage must also be deterministic");
        }
        _ => {
            // Identical input must yield an identical fail-closed outcome.
            assert_eq!(
                format!("{out_a:?}"),
                format!("{out_b:?}"),
                "lowering must be deterministic for identical input (incl. fail-closed errors)"
            );
        }
    }
}
