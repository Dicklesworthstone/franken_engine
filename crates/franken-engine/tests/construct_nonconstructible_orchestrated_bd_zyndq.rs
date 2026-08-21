//! bd-zyndq — non-constructible `BuiltinFunction` values must reject `new`,
//! pinned on the ORCHESTRATED product path (`ExecutionOrchestrator::execute`),
//! not the HybridRouter-only eval harness.
//!
//! The engine models an explicit computed [[Construct]] allowlist per builtin
//! kind: callable-only natives such as `Array.isArray` throw TypeError under
//! `new`, while genuinely constructible builtins keep working. The TypeError
//! identity is pinned on the Rust `Err` surface (its exact
//! `type error: expected constructible function, got callable-only builtin
//! function …` diagnostic); the catchable-path test observes control flow
//! through Public literals only, so the fail-high Construct exception label
//! never has to cross an egress sink.

use std::collections::BTreeMap;

use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt,
};

fn package(id: &str, source: &str) -> ExtensionPackage {
    ExtensionPackage {
        extension_id: id.to_string(),
        source: source.to_string(),
        source_file: None,
        module_root: None,
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

fn console_lines(id: &str, source: &str) -> Vec<String> {
    let mut orchestrator = ExecutionOrchestrator::with_defaults();
    let result = orchestrator
        .execute(&package(id, source))
        .unwrap_or_else(|error| panic!("orchestrated execute failed for {id}: {error}"));
    result
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect()
}

fn execute_error(id: &str, source: &str) -> String {
    let mut orchestrator = ExecutionOrchestrator::with_defaults();
    match orchestrator.execute(&package(id, source)) {
        Ok(result) => panic!(
            "expected orchestrated execute to fail for {id}, got value {:?}",
            result.execution_value
        ),
        Err(error) => error.to_string(),
    }
}

/// Uncaught `new (Array.isArray)([])` surfaces the exact callable-only
/// TypeError diagnostic through the orchestrated error path.
#[test]
fn orchestrated_new_on_parenthesized_callable_only_builtin_rejects() {
    let message = execute_error(
        "ext-zyndq-paren",
        "const probe = (Array.isArray); new probe([]);",
    );
    assert!(
        message.contains("constructible function"),
        "must reject with the constructibility TypeError, got: {message}"
    );
    assert!(
        message.contains("callable-only builtin function"),
        "must name the callable-only builtin, got: {message}"
    );
}

/// The bare member form `new Array.isArray([])` takes the same rejection.
#[test]
fn orchestrated_new_on_member_callable_only_builtin_rejects() {
    let message = execute_error("ext-zyndq-member", "new Array.isArray([]);");
    assert!(
        message.contains("constructible function"),
        "must reject with the constructibility TypeError, got: {message}"
    );
}

/// The rejection is a catchable guest-level TypeError: an enclosing
/// `try`/`catch` observes it and execution continues. Only Public literals
/// are logged, so the fail-high Construct exception label never reaches an
/// egress sink.
#[test]
fn orchestrated_new_rejection_is_catchable() {
    let lines = console_lines(
        "ext-zyndq-catch",
        r#"
        const probe = (Array.isArray);
        let outcome = 'unset';
        try {
            new probe([]);
            outcome = 'constructed';
        } catch (error) {
            outcome = 'caught';
        }
        console.log(outcome);
        console.log('alive:' + probe([]));
        "#,
    );
    assert_eq!(lines, vec!["caught".to_string(), "alive:true".to_string()]);
}

/// A second callable-only builtin family: a captured `console.log` reference
/// rejects `new` with the same constructibility TypeError.
#[test]
fn orchestrated_new_on_console_log_reference_rejects() {
    let message = execute_error(
        "ext-zyndq-console",
        "const log = console.log; new log('x');",
    );
    assert!(
        message.contains("constructible function"),
        "must reject with the constructibility TypeError, got: {message}"
    );
}

/// Genuinely constructible builtins are preserved: `new EventEmitter()` (an
/// allowlisted constructible builtin reference) keeps working end to end.
#[test]
fn orchestrated_constructible_event_emitter_still_constructs() {
    let lines = console_lines(
        "ext-zyndq-emitter",
        r#"
        const { EventEmitter } = require('events');
        const e = new EventEmitter();
        e.on('ping', function () { console.log('pong'); });
        e.emit('ping');
        "#,
    );
    assert_eq!(lines, vec!["pong".to_string()]);
}

/// `new Function` is on the computed [[Construct]] allowlist: the generated
/// function is produced and stays invocable as a plain call.
#[test]
fn orchestrated_constructible_new_function_still_constructs() {
    let lines = console_lines(
        "ext-zyndq-function",
        r#"
        const generated = new Function('return 7');
        console.log('fn:' + generated());
        "#,
    );
    assert_eq!(lines, vec!["fn:7".to_string()]);
}
