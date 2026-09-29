//! Language operations lowered to HostCalls leave no per-call audit records
//! (bd-9vouw.76).
//!
//! Array and object destructuring, object rest, computed keys and the
//! arguments object lower to `builtin:*` HostCalls that need no authority.
//! Each call used to append a CapabilityChecked event, a HostcallDispatched
//! event and a constant `allowed` decision record, so the IR4 witness grew by
//! about 1.2 KB per array destructuring for the life of the run, and built a
//! hostcall telemetry record. Host effects are still recorded once per call.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::{
    RuntimeCapability, hostcall_registry_row, is_language_operation_tag,
};
use frankenengine_engine::ir_contract::{Ir0Module, WitnessEventKind};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

struct Run {
    console: Vec<String>,
    decisions: Vec<String>,
    capability_checked_events: usize,
    dispatched_events: usize,
    telemetry_records: usize,
}

fn run(source: &str) -> Run {
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
