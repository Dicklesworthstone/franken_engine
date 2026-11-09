//! Comprehensive tests for error stack trace formatting (bd-2fx18).
//!
//! Verifies proper V8-style stack trace formatting with:
//! - Simple call chain formatting
//! - Nested function calls with proper frame order
//! - Async/await frame chain preservation
//! - Stack truncation with "... N more frames" message
//! - Missing information fallback handling
//! - Source-authored names and exact module identities (bd-9vouw.502)
//!
//! Instruction-to-source positions are not available in IR3 yet. Frames must
//! omit those positions instead of presenting instruction indices as lines.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterCore, InterpreterError, LaneChoice, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir0Module, Ir3FunctionDesc, Ir3Instruction, Ir3Module, RegRange,
};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn config_with_caps(caps: &[RuntimeCapability]) -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::VmDispatch]);
    config.granted_capabilities.extend(caps.iter().copied());
    config
}

fn execute(
    module: &Ir3Module,
    caps: &[RuntimeCapability],
) -> Result<ExecutionResult, InterpreterError> {
    InterpreterCore::new(config_with_caps(caps), "error-stack-trace-public-api").execute(module)
}

fn error_property_module(source_label: &str, message: &str, property: &str) -> Ir3Module {
    let error_tag = CapabilityTag("builtin:Error".to_string());
    let mut module = Ir3Module::new(ContentHash::compute(source_label.as_bytes()), source_label);
    module.constant_pool = vec![message.into(), property.into()];
    module.instructions = vec![
        Ir3Instruction::LoadStr {
            dst: 0,
            pool_index: 0,
        },
        Ir3Instruction::HostCall {
            capability: error_tag.clone(),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::LoadStr {
            dst: 2,
            pool_index: 1,
        },
        Ir3Instruction::GetProperty {
            obj: 1,
            key: 2,
            dst: 3,
        },
        Ir3Instruction::Return { value: 3 },
    ];
    module.required_capabilities = vec![error_tag];
    module
}

fn integer_error_message_module(source_label: &str) -> Ir3Module {
    let error_tag = CapabilityTag("builtin:Error".to_string());
    let mut module = Ir3Module::new(ContentHash::compute(source_label.as_bytes()), source_label);
    module.constant_pool = vec!["message".into()];
    module.instructions = vec![
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::HostCall {
            capability: error_tag.clone(),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::LoadStr {
            dst: 2,
            pool_index: 0,
        },
        Ir3Instruction::GetProperty {
            obj: 1,
            key: 2,
            dst: 3,
        },
        Ir3Instruction::Return { value: 3 },
    ];
    module.required_capabilities = vec![error_tag];
    module
}

fn nested_error_stack_module(source_label: &str) -> Ir3Module {
    let error_tag = CapabilityTag("builtin:Error".to_string());
    let mut module = Ir3Module::new(ContentHash::compute(source_label.as_bytes()), source_label);
    module.constant_pool = vec!["nested failure".into(), "stack".into()];
    module.instructions = vec![
        Ir3Instruction::CreateClosure {
            dst: 0,
            function_index: 0,
            capture_count: 0,
        },
        Ir3Instruction::Call {
            callee: 0,
            args: RegRange { start: 1, count: 0 },
            dst: 1,
        },
        Ir3Instruction::Return { value: 1 },
        Ir3Instruction::LoadStr {
            dst: 0,
            pool_index: 0,
        },
        Ir3Instruction::HostCall {
            capability: error_tag.clone(),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
        Ir3Instruction::LoadStr {
            dst: 2,
            pool_index: 1,
        },
        Ir3Instruction::GetProperty {
            obj: 1,
            key: 2,
            dst: 3,
        },
        Ir3Instruction::Return { value: 3 },
    ];
    module.function_table.push(Ir3FunctionDesc {
        entry: 3,
        arity: 0,
        frame_size: 8,
        name: Some("nestedErrorFactory".to_string()),
        is_generator: false,
        rest_param_index: None,
    });
    module.required_capabilities = vec![error_tag];
    module
}

fn expect_string(result: ExecutionResult, context: &str) -> String {
    match result.value {
        Value::Str(value) => value.to_string(),
        other => panic!("{context}: expected string result, got {other:?}"),
    }
}

fn source_stack(source: &str, label: &str) -> String {
    let syntax = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: label.to_string(),
                text: source.to_string(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("stack regression source parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(syntax, label),
        &LoweringContext::new("stack-trace", "stack-trace", "stack-trace"),
    )
    .expect("stack regression source lowers")
    .ir3;
    expect_string(
        execute(
            &module,
            &[RuntimeCapability::Builtin, RuntimeCapability::HeapAllocate],
        )
        .expect("stack regression source executes"),
        "source-authored stack",
    )
}

#[test]
fn error_constructor_sets_message_property_via_public_ir() {
    let module = error_property_module("error-message-public", "Test error message", "message");
    let value = expect_string(
        execute(
            &module,
            &[RuntimeCapability::Builtin, RuntimeCapability::HeapAllocate],
        )
        .expect("Error hostcall should execute"),
        "message property",
    );

    assert_eq!(value, "Test error message");
}

#[test]
fn error_constructor_sets_name_property_via_public_ir() {
    let module = error_property_module("error-name-public", "ignored", "name");
    let value = expect_string(
        execute(
            &module,
            &[RuntimeCapability::Builtin, RuntimeCapability::HeapAllocate],
        )
        .expect("Error hostcall should execute"),
        "name property",
    );

    assert_eq!(value, "Error");
}

#[test]
fn error_constructor_stack_contains_v8_style_frame_and_source() {
    let module = error_property_module("stack-source-public.js", "boom", "stack");
    let stack = expect_string(
        execute(
            &module,
            &[RuntimeCapability::Builtin, RuntimeCapability::HeapAllocate],
        )
        .expect("Error hostcall should execute"),
        "stack property",
    );

    assert!(
        stack.contains("    at "),
        "stack should use V8-style frame prefix, got:\n{stack}"
    );
    assert!(
        stack.contains("stack-source-public.js"),
        "stack should include the current module source label, got:\n{stack}"
    );
    assert_eq!(
        stack,
        "Error: boom\n    at <anonymous> (stack-source-public.js)"
    );
}

#[test]
fn error_constructor_stack_is_deterministic_for_same_module() {
    let module = error_property_module("stack-determinism-public", "boom", "stack");
    let caps = [RuntimeCapability::Builtin, RuntimeCapability::HeapAllocate];
    let first = expect_string(
        execute(&module, &caps).expect("first Error hostcall should execute"),
        "first stack",
    );
    let second = expect_string(
        execute(&module, &caps).expect("second Error hostcall should execute"),
        "second stack",
    );

    assert_eq!(
        first, second,
        "same module should produce identical stack text"
    );
}

#[test]
fn error_constructor_stringifies_non_string_messages() {
    let module = integer_error_message_module("error-message-stringify-public");
    let message = expect_string(
        execute(
            &module,
            &[RuntimeCapability::Builtin, RuntimeCapability::HeapAllocate],
        )
        .expect("Error hostcall should execute"),
        "integer message",
    );

    assert_eq!(message, "42");
}

#[test]
fn error_stack_from_nested_call_preserves_public_frame_chain() {
    let module = nested_error_stack_module("nested-stack-public.cjs");
    let stack = expect_string(
        execute(
            &module,
            &[RuntimeCapability::Builtin, RuntimeCapability::HeapAllocate],
        )
        .expect("nested Error hostcall should execute"),
        "nested stack",
    );

    assert_eq!(
        stack,
        "Error: nested failure\n    at nestedErrorFactory (nested-stack-public.cjs)\n    at <anonymous> (nested-stack-public.cjs)",
        "the callee and its top-level caller must be distinct frames"
    );
}

#[test]
fn real_source_names_and_callers_are_in_execution_order_bd_9vouw_502() {
    let stack = source_stack(
        "function outer() { return middle(); } \
         const middle = () => box.explode(); \
         const box = { explode() { return new Error('boom').stack; } }; outer();",
        "app.mjs",
    );
    assert_eq!(
        stack,
        "Error: boom\n    at explode (app.mjs)\n    at middle (app.mjs)\n    at outer (app.mjs)\n    at <anonymous> (app.mjs)"
    );
}

#[test]
fn recursive_frames_are_preserved_and_truncation_counts_them_bd_9vouw_502() {
    let source = |depth| {
        format!(
            "function recur(n) {{ if (n === 0) return new Error('end').stack; \
             return recur(n - 1); }} recur({depth});"
        )
    };
    let short = source_stack(&source(3), "recursive.js");
    assert_eq!(short.matches("    at recur (recursive.js)").count(), 4);
    assert_eq!(
        short.lines().count(),
        6,
        "header, four calls, and top level"
    );

    let long = source_stack(&source(55), "recursive.js");
    assert_eq!(long.matches("    at recur (recursive.js)").count(), 50);
    assert_eq!(
        long.lines().count(),
        52,
        "header, frame limit, omitted count"
    );
    assert!(long.ends_with("    ... 7 more frames"), "{long}");
}

#[test]
fn opaque_source_labels_are_preserved_without_invented_positions_bd_9vouw_502() {
    for label in [
        "example.js",
        "example.cjs",
        "example.tsx",
        "memory:entry",
        "entry",
    ] {
        let stack = source_stack("new Error('boom').stack;", label);
        assert_eq!(stack, format!("Error: boom\n    at <anonymous> ({label})"));
    }
}

#[test]
fn capture_stack_trace_uses_source_names_and_keeps_non_enumerable_stack_bd_9vouw_502() {
    let stack = source_stack(
        "function capture() { const target = {name: 'Custom', message: 'boom'}; \
         Error.captureStackTrace(target); \
         if (Object.getOwnPropertyDescriptor(target, 'stack').enumerable) throw 'enumerable'; \
         return target.stack; } capture();",
        "capture.js",
    );
    assert_eq!(
        stack,
        "Custom: boom\n    at capture (capture.js)\n    at <anonymous> (capture.js)"
    );
}

#[test]
fn imported_function_stack_uses_its_own_program_and_path_bd_9vouw_502() {
    let root = tempfile::tempdir().expect("module fixture");
    let entry = root.path().join("entry.cjs");
    let worker = root.path().join("worker.cjs");
    let source = "const worker = require('./worker.cjs'); console.log(worker.make());";
    std::fs::write(&entry, source).expect("write entry");
    std::fs::write(
        &worker,
        "function nested() { return new Error('foreign').stack; } \
         module.exports.make = function importedFactory() { return nested(); };",
    )
    .expect("write worker");
    let package = ExtensionPackage {
        extension_id: "stack-module-regression".to_string(),
        source: source.to_string(),
        source_file: Some(entry.display().to_string()),
        module_root: Some(root.path().display().to_string()),
        capabilities: vec!["module_load".to_string(), "builtin".to_string()],
        version: "1.0.0".to_string(),
        metadata: Default::default(),
    };
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let result = ExecutionOrchestrator::new(OrchestratorConfig {
            force_lane: Some(lane),
            commonjs_entry: true,
            ..OrchestratorConfig::default()
        })
        .execute(&package)
        .expect("execute imported stack producer");
        let stack = &result.console_output[0].message;
        assert_eq!(
            stack,
            &format!(
                "Error: foreign\n    at nested ({})\n    at importedFactory ({})",
                worker.display(),
                worker.display()
            ),
            "{lane:?}: imported indices must resolve against the imported function table; \
             an isolated callback's synthetic trampoline is not a source caller"
        );
    }
}

#[test]
fn error_constructor_requires_builtin_capability_fail_closed() {
    let module = error_property_module("error-capability-public", "boom", "stack");
    let err = execute(&module, &[RuntimeCapability::HeapAllocate])
        .expect_err("missing Builtin capability must fail closed");

    assert!(
        matches!(err, InterpreterError::CapabilityDenied { ref capability } if capability == "builtin:Error"),
        "expected builtin capability denial, got {err:?}"
    );
}

#[test]
fn error_constructor_requires_heap_allocation_capability() {
    let module = error_property_module("error-heap-capability-public", "boom", "stack");
    let err = execute(&module, &[RuntimeCapability::Builtin])
        .expect_err("missing HeapAllocate capability must fail closed");

    assert!(
        matches!(err, InterpreterError::CapabilityDenied { ref capability } if capability == "HeapAllocate"),
        "expected heap allocation capability denial, got {err:?}"
    );
}

// The former `#[cfg(any())] mod legacy_private_api_tests` block was removed here
// (bd-bg9l1.24). It never compiled — it referenced the removed `InterpreterCore` /
// hand-built `Ir3Module` IR private APIs. V8-style frame formatting, deterministic
// stack output, nested-call frame-chain preservation, non-string message
// stringification and capability-gated construction are covered by the active
// current-API tests above in this file.
