//! Native console and timer values retain the live host-effect boundary through
//! aliases, call/apply, binding and callback dispatch in both execution lanes.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    FailedConsoleSink, HookAction, InterpreterConfig, InterpreterError, LaneChoice, LaneRouter,
    RoutedResult,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::expected_loss_selector::LossMatrix;
use frankenengine_engine::guardplane_adapter::{
    GuardplaneAdapter, GuardplaneDecisionRecord, GuardplaneExtensionContext, GuardplaneOperation,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir0Module, Ir3Instruction, Ir3Module, RegRange,
};
use frankenengine_engine::lowering_pipeline::{
    AmbientAuthorityGrant, LoweringContext, lower_ir0_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
use frankenengine_engine::runtime_config::RuntimeConfig;
use frankenengine_engine::security_epoch::SecurityEpoch;

struct Run {
    result: Result<RoutedResult, InterpreterError>,
    adapter: Arc<GuardplaneAdapter>,
    failed_console: FailedConsoleSink,
}

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "native-value-host-effects.js".to_string(),
                text: source.to_string(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("source parses");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "native-value-host-effects.js"),
        &LoweringContext::new(
            "native-value-trace",
            "native-value-decision",
            "native-value-policy",
        )
        .with_ambient_authority_grant(AmbientAuthorityGrant::DenyAll),
    )
    .expect("source lowers")
    .ir3
}

fn execute(
    module: &Ir3Module,
    lane: LaneChoice,
    missing_authority: Option<RuntimeCapability>,
    witness_denied: Option<&str>,
) -> Run {
    let mut grants = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
        RuntimeCapability::Timer,
    ]);
    if let Some(missing) = missing_authority {
        grants.remove(&missing);
    }
    let mut context = GuardplaneExtensionContext::new(
        "native-value-host-effects",
        grants.iter().map(ToString::to_string).collect(),
        BTreeMap::new(),
    );
    if let Some(capability) = witness_denied {
        context.denied_capabilities.insert(capability.to_string());
    }
    let adapter = Arc::new(GuardplaneAdapter::host_effects_from_runtime_config(
        context,
        LossMatrix::balanced(),
        &RuntimeConfig::default(),
        SecurityEpoch::from_raw(1),
    ));
    let mut quickjs = InterpreterConfig::quickjs_defaults();
    quickjs.granted_capabilities = grants.clone();
    let mut v8 = InterpreterConfig::v8_defaults();
    v8.granted_capabilities = grants;
    let mut router = LaneRouter::with_configs(quickjs, v8);
    let failed_console = Arc::new(Mutex::new(Vec::new()));
    router.set_failed_console_output_sink(failed_console.clone());
    let result = router.execute_with_hook(
        module,
        "native-value-host-effects",
        Some(lane),
        Some(adapter.clone()),
    );
    Run {
        result,
        adapter,
        failed_console,
    }
}

fn only_decision(adapter: &GuardplaneAdapter, tag: &str) -> GuardplaneDecisionRecord {
    let mut decisions: Vec<_> = adapter
        .decision_records()
        .into_iter()
        .filter(|record| {
            matches!(
                &record.operation,
                GuardplaneOperation::Hostcall { capability, .. } if capability == tag
            )
        })
        .collect();
    assert_eq!(decisions.len(), 1, "one live decision for {tag}");
    decisions.pop().expect("one decision")
}

fn assert_value_path(module: &Ir3Module, tag: &str) {
    assert!(
        !module.instructions.iter().any(|instruction| {
            matches!(
                instruction,
                Ir3Instruction::HostCall { capability, .. } if capability.0 == tag
            )
        }),
        "the regression must invoke a function value, not a direct {tag} HostCall"
    );
}

const CONSOLE_CALLS: &[&str] = &[
    "const write = console.log; write('value');",
    "const key = 'lo' + 'g'; console[key]('value');",
    "console.log.call(null, 'value');",
    "console.log.apply(null, ['value']);",
    "const write = console.log.bind(null, 'value'); write();",
    "['value'].forEach(console.log);",
    "Promise.resolve('value').then(console.log);",
    "queueMicrotask(console.log.bind(null, 'value'));",
];

#[test]
fn console_value_calls_reach_live_guard_once_in_both_lanes_bd_9vouw_7() {
    for source in CONSOLE_CALLS {
        let module = lower(source);
        assert_value_path(&module, "console:log");
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let run = execute(&module, lane, None, None);
            let result = run.result.expect("authorized native console invocation");
            assert_eq!(result.result.console_output.len(), 1, "{lane:?}: {source}");
            assert_eq!(result.result.requested_hook_action, None);
            let decision = only_decision(&run.adapter, "console:log");
            assert_eq!(decision.action, HookAction::Allow);
            assert!(matches!(
                decision.operation,
                GuardplaneOperation::Hostcall { allowed: true, .. }
            ));
            assert_eq!(
                result
                    .result
                    .hostcall_decisions
                    .iter()
                    .filter(|decision| decision.capability.0 == "console:log")
                    .count(),
                1,
                "native dispatch records the actual authority decision once"
            );
        }
    }
}

#[test]
fn console_value_calls_cannot_bypass_witness_containment_in_both_lanes_bd_9vouw_7() {
    for source in CONSOLE_CALLS {
        let module = lower(source);
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let run = execute(&module, lane, None, Some("console:log"));
            let result = run.result.expect("containment is a structured outcome");
            let decision = only_decision(&run.adapter, "console:log");
            assert!(matches!(
                decision.operation,
                GuardplaneOperation::Hostcall { allowed: true, .. }
            ));
            assert_ne!(decision.action, HookAction::Allow);
            assert_eq!(result.result.requested_hook_action, Some(decision.action));
            assert!(result.result.console_output.is_empty(), "{lane:?}: {source}");
        }
    }
}

#[test]
fn console_value_calls_require_live_console_authority_in_both_lanes_bd_9vouw_7() {
    for source in CONSOLE_CALLS {
        let module = lower(source);
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let run = execute(
                &module,
                lane,
                Some(RuntimeCapability::Console),
                Some("console:log"),
            );
            assert!(
                matches!(
                    run.result,
                    Err(InterpreterError::CapabilityDenied { ref capability })
                        if capability == "console:log"
                ),
                "live denial remains primary: {lane:?}: {source}"
            );
            let decision = only_decision(&run.adapter, "console:log");
            assert!(matches!(
                decision.operation,
                GuardplaneOperation::Hostcall { allowed: false, .. }
            ));
            assert!(
                run.failed_console.lock().expect("console sink").is_empty(),
                "no output may precede denial"
            );
        }
    }
}

#[test]
fn console_value_methods_keep_exact_operation_names_in_both_lanes_bd_9vouw_7() {
    for method in ["log", "error", "warn", "info", "debug", "count"] {
        let tag = format!("console:{method}");
        let module = lower(&format!("const output = console.{method}; output('value');"));
        assert_value_path(&module, &tag);
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let allowed = execute(&module, lane, None, None);
            let result = allowed.result.expect("authorized native console method");
            assert_eq!(result.result.console_output.len(), 1);
            assert_eq!(
                only_decision(&allowed.adapter, &tag).action,
                HookAction::Allow
            );
            let stopped = execute(&module, lane, None, Some(&tag));
            let result = stopped.result.expect("exact witness operation contains");
            let decision = only_decision(&stopped.adapter, &tag);
            assert_ne!(decision.action, HookAction::Allow);
            assert_eq!(result.result.requested_hook_action, Some(decision.action));
            assert!(result.result.console_output.is_empty());
        }
    }
}

#[test]
fn timer_values_require_authority_before_callback_validation_or_effects_bd_9vouw_7() {
    for (name, argument) in [
        ("setTimeout", "null"),
        ("clearTimeout", "undefined"),
        ("setInterval", "null"),
        ("clearInterval", "undefined"),
        ("setImmediate", "null"),
        ("clearImmediate", "undefined"),
        ("queueMicrotask", "null"),
    ] {
        let mut chars = name.chars();
        let tag = format!(
            "builtin:{}{}",
            chars.next().expect("timer name").to_ascii_uppercase(),
            chars.as_str()
        );
        let module = lower(&format!("const timer = {name}; timer({argument});"));
        assert_value_path(&module, &tag);
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let run = execute(&module, lane, Some(RuntimeCapability::Timer), Some(&tag));
            assert!(
                matches!(
                    run.result,
                    Err(InterpreterError::CapabilityDenied { ref capability })
                        if capability == &tag
                ),
                "authority denial precedes callback validation: {lane:?}: {name}"
            );
            assert!(matches!(
                only_decision(&run.adapter, &tag).operation,
                GuardplaneOperation::Hostcall { allowed: false, .. }
            ));
        }
    }
}

#[test]
fn timer_value_effects_are_guarded_through_forwarding_in_both_lanes_bd_9vouw_7() {
    let cases = [
        (
            "builtin:SetTimeout",
            "const f = setTimeout; f(() => console.log('fired'), 0);",
            1,
        ),
        (
            "builtin:SetInterval",
            "let h; const f = setInterval; h = f(() => { clearInterval(h); console.log('fired'); }, 1);",
            1,
        ),
        (
            "builtin:SetImmediate",
            "const f = setImmediate.bind(null, () => console.log('fired')); f();",
            1,
        ),
        (
            "builtin:QueueMicrotask",
            "queueMicrotask.call(null, () => console.log('fired'));",
            1,
        ),
        (
            "builtin:ClearTimeout",
            "const h = setTimeout(() => console.log('fired'), 0); clearTimeout.apply(null, [h]);",
            0,
        ),
        (
            "builtin:ClearInterval",
            "const h = setInterval(() => console.log('fired'), 1); const f = clearInterval; f(h);",
            0,
        ),
        (
            "builtin:ClearImmediate",
            "const h = setImmediate(() => console.log('fired')); const f = clearImmediate.bind(null, h); f();",
            0,
        ),
    ];
    for (tag, source, output_count) in cases {
        let module = lower(source);
        assert_value_path(&module, tag);
        for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
            let allowed = execute(&module, lane, None, None);
            let result = allowed.result.expect("authorized timer effect completes");
            assert_eq!(result.result.requested_hook_action, None);
            assert_eq!(result.result.console_output.len(), output_count);
            assert_eq!(
                only_decision(&allowed.adapter, tag).action,
                HookAction::Allow
            );
            let stopped = execute(&module, lane, None, Some(tag));
            let result = stopped.result.expect("timer containment is structured");
            let decision = only_decision(&stopped.adapter, tag);
            assert_ne!(decision.action, HookAction::Allow);
            assert_eq!(result.result.requested_hook_action, Some(decision.action));
            assert!(result.result.console_output.is_empty(), "{lane:?}: {source}");
        }
    }
}

#[test]
fn direct_console_hostcall_still_has_one_live_decision_bd_9vouw_7() {
    let mut module = Ir3Module::new(ContentHash::compute(b"direct-console"), "direct-console");
    module.constant_pool = vec!["direct".into()];
    module.instructions = vec![
        Ir3Instruction::LoadStr {
            dst: 0,
            pool_index: 0,
        },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("console:log".into()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::Halt,
    ];
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let run = execute(&module, lane, None, None);
        let result = run.result.expect("direct hostcall completes");
        assert_eq!(result.result.console_output.len(), 1);
        assert_eq!(result.result.hostcall_decisions.len(), 1);
        assert_eq!(
            only_decision(&run.adapter, "console:log").action,
            HookAction::Allow
        );
    }
}
