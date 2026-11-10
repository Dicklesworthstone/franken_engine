//! Execute imported functions through the public core API. Entry programs use
//! unrelated function tables or no local functions, exercising both retained
//! and borrowed caller programs across module boundaries.

use std::collections::BTreeSet;
use std::path::PathBuf;

use frankenengine_core::ast::{ExportKind, ParseGoal, Statement};
use frankenengine_core::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::{Ir0Module, Ir3Instruction, Ir3Module};
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/modules")
        .canonicalize()
        .unwrap()
}

fn lower_source(source: &str) -> Ir3Module {
    let root = fixture_root();
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Module)
        .unwrap();
    let ir0 = Ir0Module::from_syntax_tree(tree, root.join("entry.mjs").display().to_string());
    lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new("module-ownership", "module-ownership", "module-ownership"),
    )
    .unwrap()
    .ir3
}

fn execute_module(
    module: &Ir3Module,
    throughput: bool,
) -> Result<ExecutionResult, InterpreterError> {
    let mut config = if throughput {
        InterpreterConfig::v8_defaults()
    } else {
        InterpreterConfig::quickjs_defaults()
    };
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::ModuleLoad,
    ]);
    config.module_root = Some(fixture_root().display().to_string());
    InterpreterCore::new(config, "module-ownership").execute(module)
}

fn execute(source: &str, throughput: bool) -> Result<Value, InterpreterError> {
    execute_module(&lower_source(source), throughput).map(|result| result.value)
}

fn assert_both(source: &str, expected: Value) {
    for throughput in [false, true] {
        assert_eq!(execute(source, throughput).unwrap(), expected, "{source}");
    }
}

#[test]
fn exported_declarations_keep_bindings_hoisting_and_initializer_order() {
    assert_both(
        "const answer = add(2); export function add(value) { return value + 40; } answer;",
        Value::Int(42),
    );
    assert_both(
        "answer = () => 42; export function answer() { return 0; } answer();",
        Value::Int(42),
    );
    assert_both(
        "let observed = ''; try { read(); } catch (error) { observed = error.name; } \
         export function read() { return value; } export const value = 42; \
         observed + ':' + read();",
        Value::str("ReferenceError:42"),
    );
    assert_both(
        "let calls = 0; function initialize() { calls += 1; return { x: 2, y: 3 }; } \
         export const { x: first, y: second } = initialize(); calls * 100 + first * 10 + second;",
        Value::Int(123),
    );
    assert_both(
        "export/* declaration */class Counter { constructor(value) { this.value = value; } \
             next() { this.value += 1; return this.value; } } \
         const counter = new Counter(41); counter.next();",
        Value::Int(42),
    );
}

#[test]
fn exported_async_generator_declarations_preserve_source_flags_and_names() {
    let tree = CanonicalEs2020Parser.parse(
        "export const { x: first, y: second } = { x: 2, y: 3 }; \
         export async function* sequence() { yield first; return second; }",
        ParseGoal::Module,
    ).unwrap();
    assert_eq!(tree.body.len(), 4);
    let Statement::VariableDeclaration(declaration) = &tree.body[0] else {
        panic!("expected the unchanged variable declaration");
    };
    assert_eq!(declaration.declarations[0].pattern.binding_names(), ["first", "second"]);
    let Statement::Export(export) = &tree.body[1] else {
        panic!("expected the variable export clause");
    };
    assert!(matches!(
        &export.kind,
        ExportKind::NamedClause(clause) if clause.canonical_head() == "{ first, second }",
    ));
    let Statement::FunctionDeclaration(function) = &tree.body[2] else {
        panic!("expected the unchanged function declaration");
    };
    assert_eq!(function.name.as_deref(), Some("sequence"));
    assert!(function.is_async && function.is_generator);
    let Statement::Export(export) = &tree.body[3] else {
        panic!("expected the function export clause");
    };
    assert!(matches!(
        &export.kind,
        ExportKind::NamedClause(clause) if clause.canonical_head() == "{ sequence }",
    ));
    let ir0 = Ir0Module::from_syntax_tree(tree, "export-async-generator");
    let lowered = lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new("exports", "exports", "exports"),
    ).unwrap();
    assert!(lowered.ir3.instructions.iter().any(|instruction| matches!(
        instruction,
        Ir3Instruction::CreateAsyncGenerator { .. },
    )));
    assert!(CanonicalEs2020Parser.parse("export const value = 1;", ParseGoal::Script).is_err());
    assert!(CanonicalEs2020Parser.parse("export function () {}", ParseGoal::Module).is_err());
}

#[test]
fn named_and_namespace_imports_use_the_exporters_code_and_constants() {
    assert_both(
        "import { add } from './operations.mjs'; function unrelated(x) { return -900; } add(2);",
        Value::Int(42),
    );
    assert_both(
        "import * as ops from './operations.mjs'; function unrelated() { return -900; } ops.add(3);",
        Value::Int(43),
    );
}

#[test]
fn foreign_calls_can_reenter_the_callers_module_and_restore_it() {
    assert_both(
        "import { apply, add } from './operations.mjs'; function double(x) { return x * 2; } apply(double, 7) + add(1);",
        Value::Int(56),
    );
}

#[test]
fn escaped_closures_keep_their_program_and_live_lexical_cells() {
    assert_both(
        "import { makeCounter } from './operations.mjs'; function unrelated() { return -900; } const a = makeCounter(); const b = makeCounter(); a() * 100 + a() * 10 + b();",
        Value::Int(121),
    );
}

#[test]
fn foreign_exceptions_restore_catch_finally_and_caller_code() {
    assert_both(
        "import { fail, add } from './operations.mjs'; let result = 0; try { try { fail(); } finally { result = 5; } } catch (error) { result += error; } result + add(1);",
        Value::Int(63),
    );
}

#[test]
fn imported_constructors_methods_and_derived_super_use_their_owners() {
    assert_both(
        "import { Counter } from './operations.mjs'; function unrelated() { return -900; } const counter = new Counter(40); counter.next() + counter.next();",
        Value::Int(83),
    );
    assert_both(
        "import { Counter } from './operations.mjs'; class Derived extends Counter { constructor(value) { super(value); } next() { return super.next() + 1; } } new Derived(40).next();",
        Value::Int(42),
    );
}

#[test]
fn generators_keep_code_identity_across_multiple_suspensions() {
    assert_both(
        "import { values } from './operations.mjs'; function unrelated() { return -900; } const iterator = values(2); iterator.next().value + iterator.next().value + iterator.next().value;",
        Value::Int(143),
    );
}

#[test]
fn relative_requires_inside_an_imported_function_use_its_origin() {
    assert_both(
        "import { loadSibling } from './nested/loader.mjs'; function unrelated() { return -900; } loadSibling();",
        Value::Int(73),
    );
}

#[test]
fn imported_timer_callbacks_return_without_reentering_the_importer() {
    // Exercise source timer registration and the importer's real completion.
    // Keep its code longer than the callback module so an owner mix-up cannot
    // accidentally resume at a compatible instruction in the foreign program.
    let source = format!(
        "import {{ tick }} from './timer.mjs'; function unrelated() {{ return -900; }} {} console.log('sync'); setTimeout(tick, 0); 1;",
        "0;".repeat(96),
    );
    let module = lower_source(&source);
    let callback_module = lower_source(include_str!("fixtures/modules/timer.mjs"));
    let main_halt = module
        .instructions
        .iter()
        .position(|instruction| matches!(instruction, Ir3Instruction::Halt))
        .unwrap();
    assert!(main_halt > callback_module.instructions.len());

    for throughput in [false, true] {
        let result = execute_module(&module, throughput).unwrap();
        assert_eq!(result.value, Value::Int(1));
        let output: Vec<_> = result
            .console_output
            .into_iter()
            .map(|line| line.message)
            .collect();
        assert_eq!(output, ["sync", "timer"]);
    }
}

#[test]
fn lazy_cjs_requires_preserve_the_exporting_modules_parent_identity() {
    let expected = Value::str(
        fixture_root()
            .join("nested/lazy_factory.cjs")
            .display()
            .to_string(),
    );
    for source in [
        "const factory = require('./nested/lazy_factory.cjs'); function unrelated() { return -900; } factory();",
        "require('./nested/lazy_caller.cjs');",
    ] {
        assert_both(source, expected.clone());
    }
}

#[test]
fn foreign_accessor_throws_preserve_object_identity_and_restore_caller_code() {
    assert_both(
        "import { explosive, token } from './accessors.mjs'; import { add } from './operations.mjs'; function unrelated() { return -900; } let caught = false; try { explosive.value; } catch (error) { caught = error === token; } caught && add(2) === 42;",
        Value::Bool(true),
    );
}

#[test]
fn reentrant_callback_throws_unwind_both_module_frames() {
    assert_both(
        "import { apply, add } from './operations.mjs'; const token = { marker: 23 }; function callback() { throw token; } let caught = false; try { apply(callback, 1); } catch (error) { caught = error === token; } caught && add(2) === 42;",
        Value::Bool(true),
    );
}
