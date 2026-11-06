//! Language operations lowered to HostCalls leave no per-call audit records
//! (bd-9vouw.76).
//!
//! Array and object destructuring, object rest, computed keys and the
//! arguments object lower to `builtin:*` HostCalls that need no authority.
//! Each call used to append a CapabilityChecked event, a HostcallDispatched
//! event and a constant `allowed` decision record, so the IR4 witness grew by
//! about 1.2 KB per array destructuring for the life of the run, and built a
//! hostcall telemetry record. Host effects are still recorded once per call.
//!
//! Effect-free builtins that do need authority (`JSON.stringify`,
//! `Object.keys`, `parseInt`, `String.fromCharCode`) record their first
//! grant per tag and count the repeats (bd-9vouw.83).
//! Deterministic queueMicrotask enqueues retain Timer authority and commit
//! exact callable order to a bounded SHA-256 witness (bd-9vouw.76).

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::{
    RuntimeCapability, hostcall_registry_row, is_language_operation_tag,
};
use frankenengine_engine::ir_contract::{Ir0Module, WitnessEvent, WitnessEventKind};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

struct Run {
    console: Vec<String>,
    decisions: Vec<String>,
    decision_count: u64,
    capability_checked_events: usize,
    dispatched_events: usize,
    telemetry_records: usize,
    witness_events: Vec<WitnessEvent>,
}

fn run(source: &str) -> Run {
    run_with_capabilities(source, &[])
}

fn run_with_capabilities(source: &str, extra_capabilities: &[RuntimeCapability]) -> Run {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "ops.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("parse");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "ops.js"),
        &LoweringContext::new("ops-trace", "ops-decision", "ops-policy"),
    )
    .expect("lower")
    .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.instruction_budget = 1_000_000_000;
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    config
        .granted_capabilities
        .extend(extra_capabilities.iter().cloned());
    let mut core = InterpreterCore::new(config, "ops");
    let result = core
        .execute(&module)
        .unwrap_or_else(|error| panic!("`{source}` failed: {error:?}"));
    let telemetry_records = core.hostcall_telemetry().records().len();
    Run {
        console: result
            .console_output
            .iter()
            .map(|entry| entry.message.clone())
            .collect(),
        decisions: result
            .hostcall_decisions
            .iter()
            .map(|decision| decision.capability.0.clone())
            .collect(),
        decision_count: result.hostcall_decision_count(),
        capability_checked_events: result
            .witness_events
            .iter()
            .filter(|event| event.kind == WitnessEventKind::CapabilityChecked)
            .count(),
        dispatched_events: result
            .witness_events
            .iter()
            .filter(|event| event.kind == WitnessEventKind::HostcallDispatched)
            .count(),
        telemetry_records,
        witness_events: result.witness_events,
    }
}

/// Each loop body runs every language operation 2,000 times; the only
/// recorded hostcall is the final `console.log`, so every record count equals
/// that of a program that only logs. Output matches Node v22.2.0.
#[test]
fn language_operations_leave_no_per_call_records() {
    let only_log = run("console.log(0);");
    assert_eq!(only_log.decisions, vec!["console:log".to_string()]);
    let cases = [
        (
            "let s = 0; for (let i = 0; i < 2000; i++) { const [a, b] = [i, 1]; s += a + b; } \
             console.log(s);",
            "2001000",
        ),
        (
            "let s = 0; for (let i = 0; i < 2000; i++) { const { a, b } = { a: i, b: 1 }; s += a + b; } \
             console.log(s);",
            "2001000",
        ),
        (
            "let s = 0; for (let i = 0; i < 2000; i++) { const { a, ...rest } = { a: 1, b: i }; s += rest.b; } \
             console.log(s);",
            "1999000",
        ),
        (
            "let s = 0; for (let i = 0; i < 2000; i++) { const [, x, ...ys] = [0, i, 1, 2]; s += x + ys.length; } \
             console.log(s);",
            "2003000",
        ),
        (
            "function f() { return arguments.length; } let s = 0; \
             for (let i = 0; i < 2000; i++) { const o = { ['k' + (i % 3)]: i }; s += f(o, i); } \
             console.log(s);",
            "4000",
        ),
    ];
    for (source, node) in cases {
        let run = run(source);
        assert_eq!(run.console, vec![node.to_string()], "{source}");
        assert_eq!(run.decisions, only_log.decisions, "{source}");
        assert_eq!(
            run.capability_checked_events, only_log.capability_checked_events,
            "{source}"
        );
        assert_eq!(
            run.dispatched_events, only_log.dispatched_events,
            "{source}"
        );
        assert_eq!(
            run.telemetry_records, only_log.telemetry_records,
            "{source}"
        );
    }
}

/// Host effects are still recorded on every call: three logs in a
/// destructuring loop leave three times one log's records.
#[test]
fn host_effects_are_still_recorded_per_call() {
    let only_log = run("console.log(0);");
    assert!(only_log.capability_checked_events > 0 && only_log.dispatched_events > 0);
    let run = run("for (let i = 0; i < 3; i++) { const [a] = [i]; console.log(a); }");
    assert_eq!(run.console, vec!["0", "1", "2"]);
    assert_eq!(run.decisions, vec!["console:log"; 3]);
    assert_eq!(
        run.capability_checked_events,
        3 * only_log.capability_checked_events
    );
    assert_eq!(run.dispatched_events, 3 * only_log.dispatched_events);
    assert_eq!(run.telemetry_records, 3 * only_log.telemetry_records);
}

/// bd-9vouw.83: four effect-free builtins per iteration record one grant per
/// tag for the whole run. 2,000 iterations leave the records of a single
/// iteration, while the decision total still counts every call. Output
/// matches Node v22.2.0.
#[test]
fn effect_free_builtin_grants_are_recorded_once_per_tag() {
    let program = |iterations: u32| {
        format!(
            "let s = ''; let t = 0; for (let i = 0; i < {iterations}; i++) {{ \
             t += JSON.stringify({{ i }}).length + Object.keys({{ a: i, b: 1 }}).length \
             + parseInt('7' + (i % 10)); s = String.fromCharCode(65 + (i % 26)); }} \
             console.log(t, s);"
        )
    };
    let once = run(&program(1));
    let many = run(&program(2000));
    assert_eq!(once.console, vec!["79 A"]);
    assert_eq!(many.console, vec!["171890 X"]);
    assert_eq!(once.decisions.len(), 5, "{:?}", once.decisions);
    assert_eq!(
        once.decisions.last().map(String::as_str),
        Some("console:log")
    );
    assert_eq!(many.decisions, once.decisions);
    assert_eq!(
        many.capability_checked_events,
        once.capability_checked_events
    );
    assert_eq!(many.dispatched_events, once.dispatched_events);
    assert_eq!(many.decision_count, once.decision_count + 4 * 1999);
}

/// The gate skips language operations only because they need no authority:
/// every such tag resolves to a registry row without one. Tags that do need
/// authority, or that are IFC checks, are not language operations.
#[test]
fn language_operation_tags_need_no_authority() {
    let language_operations = [
        "builtin:RequireObjectCoercible",
        "builtin:ObjectRest",
        "builtin:ToPropertyKey",
        "builtin:DestructureIteratorInit",
        "builtin:DestructureIteratorNext",
        "builtin:DestructureIteratorElide",
        "builtin:DestructureIteratorDone",
        "builtin:ClassMembersNonEnumerable",
        "builtin:ArgumentsObject",
        "builtin:proto:Array",
        "builtin:proto:Symbol",
        "builtin:instanceof:Map",
    ];
    for tag in language_operations {
        assert!(is_language_operation_tag(tag), "{tag}");
        let row = hostcall_registry_row(tag).expect("registered language operation");
        assert_eq!(row.authority, None, "{tag}");
    }
    for tag in [
        "ifc.check_flow",
        "promise:then",
        "console:log",
        "fs:read",
        "builtin:CryptoRandomBytes",
        "builtin:ObjectKeys",
        "builtin:instanceof:Symbol",
    ] {
        assert!(!is_language_operation_tag(tag), "{tag}");
    }
}

/// A long-lived interval has constant timer state and must also have a
/// bounded IR4 transcript. Scheduling, clearing and the final log remain
/// individual host effects; every callback still contributes to the seal.
#[test]
fn interval_callback_witness_is_bounded_and_commits_to_every_tick() {
    let program = |ticks| {
        format!(
            "let count = 0; const timer = setInterval(() => {{ \
             count += 1; if (count === {ticks}) {{ clearInterval(timer); console.log(count); }} \
             }}, 1);"
        )
    };
    let once = run_with_capabilities(&program(1), &[RuntimeCapability::Timer]);
    let many = run_with_capabilities(&program(20_000), &[RuntimeCapability::Timer]);
    assert_eq!(once.console, vec!["1"]);
    assert_eq!(many.console, vec!["20000"]);
    assert_eq!(many.decisions, once.decisions);
    assert_eq!(
        many.capability_checked_events,
        once.capability_checked_events
    );
    assert_eq!(many.dispatched_events, once.dispatched_events);
    assert_eq!(many.witness_events.len(), once.witness_events.len());
    assert!(
        serde_json::to_vec(&many.witness_events).unwrap().len() < 16_384,
        "twenty thousand interval ticks must not retain twenty thousand witness rows"
    );
    let once_commitment = once.witness_events.last().unwrap();
    let many_commitment = many.witness_events.last().unwrap();
    assert_eq!(many_commitment.kind, WitnessEventKind::ExecutionCompleted);
    assert_ne!(many_commitment.payload_hash, once_commitment.payload_hash);
}

/// Folding invocation markers must not fold the console effects in the
/// callback body, or suppress delivery after the first tick.
#[test]
fn interval_callback_host_effects_remain_individually_recorded() {
    let result = run_with_capabilities(
        "let count = 0; const timer = setInterval(() => { \
         count += 1; console.log(count); if (count === 3) clearInterval(timer); \
         }, 1);",
        &[RuntimeCapability::Timer],
    );
    assert_eq!(result.console, vec!["1", "2", "3"]);
    assert_eq!(
        result
            .decisions
            .iter()
            .filter(|tag| tag.as_str() == "console:log")
            .count(),
        3,
        "each real console effect must retain its own authority decision"
    );
}

/// Repeated queueMicrotask enqueues retain constant IR4 storage, while their
/// callbacks all run and their decision total still accounts for every check.
#[test]
fn microtask_enqueue_witness_is_bounded_and_counts_every_grant() {
    let program = |tasks| {
        format!(
            "let count = 0; for (let i = 0; i < {tasks}; i++) {{ \
             queueMicrotask(() => {{ count += 1; }}); }} \
             queueMicrotask(() => console.log(count));"
        )
    };
    let once = run_with_capabilities(&program(1), &[RuntimeCapability::Timer]);
    let many = run_with_capabilities(&program(20_000), &[RuntimeCapability::Timer]);
    assert_eq!(once.console, vec!["1"]);
    assert_eq!(many.console, vec!["20000"]);
    assert_eq!(many.decisions, once.decisions);
    assert_eq!(
        many.capability_checked_events,
        once.capability_checked_events
    );
    assert_eq!(many.dispatched_events, once.dispatched_events);
    assert_eq!(many.witness_events.len(), once.witness_events.len());
    assert_eq!(many.decision_count, once.decision_count + 19_999);
    assert!(
        serde_json::to_vec(&many.witness_events).unwrap().len() < 16_384,
        "twenty thousand enqueues must not retain twenty thousand witness rows"
    );
    assert_ne!(
        many.witness_events.last().unwrap().payload_hash,
        once.witness_events.last().unwrap().payload_hash,
        "the bounded commitment must still distinguish the number of enqueues"
    );
}

#[test]
fn microtask_commitment_binds_callable_order_even_when_outputs_match() {
    let declarations = "function first() {} function second() {} ";
    let ordered = format!("{declarations} queueMicrotask(first); queueMicrotask(second);");
    let reversed = format!("{declarations} queueMicrotask(second); queueMicrotask(first);");
    let repeated = format!("{declarations} queueMicrotask(first); queueMicrotask(first);");
    let a = run_with_capabilities(&ordered, &[RuntimeCapability::Timer]);
    let b = run_with_capabilities(&reversed, &[RuntimeCapability::Timer]);
    let c = run_with_capabilities(&repeated, &[RuntimeCapability::Timer]);
    assert!(a.console.is_empty() && b.console.is_empty() && c.console.is_empty());
    assert_eq!(a.decision_count, b.decision_count);
    assert_eq!(a.decision_count, c.decision_count);
    let commitment = |run: &Run| run.witness_events.last().unwrap().payload_hash;
    assert_ne!(commitment(&a), commitment(&b));
    assert_ne!(commitment(&a), commitment(&c));
    let again = run_with_capabilities(&ordered, &[RuntimeCapability::Timer]);
    assert_eq!(a.witness_events, again.witness_events);
}

/// First-class references use the same enqueue core. Folding their scheduling
/// evidence cannot suppress the real effects of any callback.
#[test]
fn first_class_microtask_callbacks_retain_individual_host_effects() {
    let result = run_with_capabilities(
        "const enqueue = queueMicrotask; \
         for (let i = 0; i < 3; i++) enqueue(() => console.log(i));",
        &[RuntimeCapability::Timer],
    );
    assert_eq!(result.console, vec!["0", "1", "2"]);
    assert_eq!(
        result
            .decisions
            .iter()
            .filter(|tag| tag.as_str() == "console:log")
            .count(),
        3
    );
    assert_eq!(
        result
            .decisions
            .iter()
            .filter(|tag| tag.as_str() == "builtin:QueueMicrotask")
            .count(),
        1
    );
    assert_eq!(result.decision_count, 6);
}

#[test]
fn nested_microtask_enqueues_survive_callback_snapshot_restore() {
    let program = |tasks| {
        format!(
            "let count = 0; function step() {{ count += 1; \
             if (count < {tasks}) queueMicrotask(step); else console.log(count); }} \
             queueMicrotask(step);"
        )
    };
    let once = run_with_capabilities(&program(1), &[RuntimeCapability::Timer]);
    let many = run_with_capabilities(&program(2_000), &[RuntimeCapability::Timer]);
    assert_eq!(many.console, vec!["2000"]);
    assert_eq!(many.decision_count, once.decision_count + 1_999);
    assert_eq!(many.witness_events.len(), once.witness_events.len());
    assert_ne!(
        many.witness_events.last().unwrap().payload_hash,
        once.witness_events.last().unwrap().payload_hash,
        "nested callback frames must not roll back the enqueue commitment"
    );
}

/// The original promise-heavy report-growth repro must keep all settlements
/// and results while retaining only the distinct builtin grants.
#[test]
fn promise_microtask_workload_keeps_bounded_witness_records() {
    let program = |tasks| {
        format!(
            "const pending = []; for (let i = 0; i < {tasks}; i++) {{ \
             pending.push(new Promise(resolve => queueMicrotask(() => resolve(i))) \
             .then(value => value + 1)); }} \
             Promise.all(pending).then(values => console.log(values.length, \
             values.reduce((sum, value) => sum + value, 0)));"
        )
    };
    let once = run_with_capabilities(&program(1), &[RuntimeCapability::Timer]);
    let many = run_with_capabilities(&program(2_000), &[RuntimeCapability::Timer]);
    assert_eq!(once.console, vec!["1 1"]);
    assert_eq!(many.console, vec!["2000 2001000"]);
    assert_eq!(many.decisions, once.decisions);
    assert_eq!(many.witness_events.len(), once.witness_events.len());
    assert!(serde_json::to_vec(&many.witness_events).unwrap().len() < 16_384);
}
