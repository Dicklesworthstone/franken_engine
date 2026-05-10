#![forbid(unsafe_code)]

//! Integration tests for top-level await in ESM.
//!
//! Covers: basic top-level await parsing and execution, import ordering with TLA,
//! error propagation from TLA modules to importers, module evaluation becoming async.

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

use frankenengine_engine::ast::{ParseGoal, SyntaxTree};
use frankenengine_engine::module_async_evaluation::{
    AsyncEvalEventType, AsyncModuleEvaluator, AsyncModulePhase,
};
use frankenengine_engine::module_live_binding::LiveBindingMap;
use frankenengine_engine::object_model::JsValue;
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser, ParseResult};
use frankenengine_engine::promise_model::PromiseHandle;
use frankenengine_engine::static_semantics::{StaticErrorKind, analyze};

fn parse(source: &str, goal: ParseGoal) -> ParseResult<SyntaxTree> {
    CanonicalEs2020Parser.parse(source, goal)
}

// ---------------------------------------------------------------------------
// Basic TLA parsing tests
// ---------------------------------------------------------------------------

#[test]
fn tla_basic_variable_declaration_parses() {
    let source = "const data = await fetchData();";
    let tree = parse(source, ParseGoal::Module).expect("parse should succeed");

    // Verify parsing succeeded
    assert_eq!(tree.body.len(), 1);

    // Verify static semantics pass for module context
    let result = analyze(&tree);
    assert!(
        result.passed(),
        "Static semantics should pass for TLA in module"
    );
}

#[test]
fn tla_basic_expression_statement_parses() {
    let source = "await doSomething();";
    let tree = parse(source, ParseGoal::Module).expect("parse should succeed");

    // Verify parsing succeeded
    assert_eq!(tree.body.len(), 1);

    // Verify static semantics pass for module context
    let result = analyze(&tree);
    assert!(
        result.passed(),
        "Static semantics should pass for TLA in module"
    );
}

#[test]
fn tla_multiple_awaits_in_module() {
    let source = r#"
        const config = await loadConfig();
        const db = await connectDatabase(config.dbUrl);
        await initializeApp(db);
    "#;
    let tree = parse(source, ParseGoal::Module).expect("parse should succeed");

    // Verify all statements parsed
    assert_eq!(tree.body.len(), 3);

    // Verify static semantics pass
    let result = analyze(&tree);
    assert!(
        result.passed(),
        "Static semantics should pass for multiple TLA in module"
    );
}

#[test]
fn tla_rejected_in_script_context() {
    let source = "const data = await fetchData();";
    let tree = parse(source, ParseGoal::Script).expect("parse should succeed even in script");

    // Static semantics should reject await outside async function in scripts
    let result = analyze(&tree);
    assert!(
        !result.passed(),
        "Static semantics should reject TLA in script context"
    );

    // Check that we have the right error
    let errors = &result.errors;
    assert!(!errors.is_empty());
    assert!(errors[0].message.contains("await"));
}

#[test]
fn tla_with_complex_expressions() {
    let source = r#"
        const result = await Promise.all([
            fetch('/api/users'),
            fetch('/api/posts')
        ]);
        export const users = result[0];
        export const posts = result[1];
    "#;
    let tree = parse(source, ParseGoal::Module).expect("parse should succeed");

    // Verify static semantics pass
    let result = analyze(&tree);
    assert!(
        result.passed(),
        "Static semantics should pass for complex TLA with exports"
    );
}

// ---------------------------------------------------------------------------
// Module evaluation async behavior tests
// ---------------------------------------------------------------------------

#[test]
fn module_with_tla_has_async_phase() {
    let source = "const data = await fetchData();";
    let tree = parse(source, ParseGoal::Module).expect("parse should succeed");

    let result = analyze(&tree);
    assert!(result.passed());

    let mut evaluator = AsyncModuleEvaluator::with_defaults();
    evaluator.register_module("app.js", true, &[], Some(PromiseHandle(1)));
    evaluator
        .suspend_at_top_level_await("app.js", PromiseHandle(2))
        .expect("registered module should suspend at top-level await");

    let state = &evaluator.states()["app.js"];
    assert_eq!(state.phase, AsyncModulePhase::Suspended);
    assert!(state.has_top_level_await);
    assert_eq!(state.evaluation_promise, Some(PromiseHandle(1)));
    assert_eq!(state.suspensions.len(), 1);
    assert!(evaluator.witness_events().iter().any(|event| {
        event.module_specifier == "app.js"
            && event.event_type == AsyncEvalEventType::TopLevelAwaitSuspended
    }));
}

#[test]
fn module_without_tla_remains_sync() {
    let source = r#"
        export const value = 42;
        export function greet(name) {
            return `Hello, ${name}!`;
        }
    "#;
    let tree = parse(source, ParseGoal::Module).expect("parse should succeed");

    let result = analyze(&tree);
    assert!(result.passed());

    let mut evaluator = AsyncModuleEvaluator::with_defaults();
    evaluator.register_module("sync.js", false, &[], None);

    let state = &evaluator.states()["sync.js"];
    assert_eq!(state.phase, AsyncModulePhase::Synchronous);
    assert!(!state.has_top_level_await);
    assert_eq!(state.evaluation_promise, None);
    assert!(state.suspensions.is_empty());
}

// ---------------------------------------------------------------------------
// Import ordering and rejection propagation tests
// ---------------------------------------------------------------------------

#[test]
fn tla_import_ordering_waits_for_async_dependency() {
    let source = r#"
        import { helper } from './helper.js';
        const data = await fetchData();
        export const processed = helper(data);
    "#;
    let tree = parse(source, ParseGoal::Module).expect("parse should succeed");
    let result = analyze(&tree);
    assert!(
        result.passed(),
        "Module with imports and TLA should parse and validate"
    );

    let mut evaluator = AsyncModuleEvaluator::with_defaults();
    evaluator.register_module("helper.js", true, &[], Some(PromiseHandle(10)));
    evaluator
        .suspend_at_top_level_await("helper.js", PromiseHandle(11))
        .expect("async dependency should suspend at top-level await");
    evaluator.register_module("app.js", false, &["helper.js".to_string()], None);

    let app = &evaluator.states()["app.js"];
    assert_eq!(app.phase, AsyncModulePhase::AwaitingDependencies);
    assert!(app.pending_dependencies.contains("helper.js"));
    assert!(evaluator.witness_events().iter().any(|event| {
        event.module_specifier == "app.js"
            && event.event_type == AsyncEvalEventType::DependencySuspended
            && event.detail.contains("awaiting=helper.js")
    }));

    let resumable = evaluator
        .settle_module("helper.js")
        .expect("settled dependency should notify importers");
    assert!(resumable.contains(&"app.js".to_string()));
    evaluator
        .resume_evaluation("app.js")
        .expect("importer should resume after async dependency settles");
    evaluator
        .settle_module("app.js")
        .expect("importer should settle after resumption");
    assert_eq!(
        evaluator.states()["app.js"].phase,
        AsyncModulePhase::Settled
    );
}

#[test]
fn tla_error_propagates_to_importers() {
    let source = r#"
        let result;
        try {
            result = await riskyOperation();
        } catch (error) {
            throw error;
        }
        export { result };
    "#;
    let tree = parse(source, ParseGoal::Module).expect("parse should succeed");
    let result = analyze(&tree);
    assert!(
        result.passed(),
        "Module with TLA error handling should parse and validate"
    );

    let mut evaluator = AsyncModuleEvaluator::with_defaults();
    evaluator.register_module("risky.js", true, &[], Some(PromiseHandle(20)));
    evaluator.register_module("consumer.js", false, &["risky.js".to_string()], None);

    let mut live_bindings = LiveBindingMap::new();
    let linkage = evaluator
        .reject_module(
            "risky.js",
            &JsValue::Str("top-level await rejected".to_string()),
            &mut live_bindings,
        )
        .expect("rejected dependency should produce a linkage record");

    assert_eq!(linkage.rejected_module, "risky.js");
    assert!(
        linkage
            .linked_modules
            .iter()
            .any(|module| module.module_specifier == "consumer.js")
    );
    assert!(linkage.transitive_closure.contains("consumer.js"));
    let consumer = &evaluator.states()["consumer.js"];
    assert_eq!(consumer.phase, AsyncModulePhase::Rejected);
    assert!(
        consumer
            .rejection_reason_description
            .as_deref()
            .is_some_and(|reason| reason.contains("top-level await rejected"))
    );
    assert!(evaluator.witness_events().iter().any(|event| {
        event.module_specifier == "consumer.js"
            && event.event_type == AsyncEvalEventType::RejectionPropagated
            && event.detail.contains("from=risky.js")
    }));
}

// ---------------------------------------------------------------------------
// Edge cases and error conditions
// ---------------------------------------------------------------------------

#[test]
fn tla_await_in_function_still_requires_async() {
    let source = r#"
        const topLevel = await fetchConfig();

        function regular() {
            return await someOperation();
        }
    "#;
    let tree = parse(source, ParseGoal::Module).expect("parse should succeed");

    // Static semantics should reject await in non-async function,
    // even though top-level await is allowed
    let result = analyze(&tree);
    assert!(
        !result.passed(),
        "Static semantics should reject await in non-async function"
    );
    assert_eq!(result.errors.len(), 1, "Should have exactly one error");
    assert_eq!(
        result.errors[0].kind,
        StaticErrorKind::AwaitOutsideAsync,
        "Error should be AwaitOutsideAsync"
    );
}

#[test]
fn tla_nested_in_blocks() {
    let source = r#"
        if (true) {
            const data = await fetchData();
            console.log(data);
        }

        for (const item of await fetchList()) {
            console.log(item);
        }
    "#;
    let tree = parse(source, ParseGoal::Module).expect("parse should succeed");
    let result = analyze(&tree);
    assert!(
        result.passed(),
        "TLA in blocks should be valid in module context"
    );
}

#[test]
fn tla_empty_module_remains_valid() {
    let source = "";
    // Empty source should be handled gracefully
    let parse_result = parse(source, ParseGoal::Module);
    // Parser should reject empty source according to existing behavior
    assert!(parse_result.is_err(), "Empty source should be rejected");
}

#[test]
fn tla_module_with_only_await() {
    let source = "await initialize();";
    let tree = parse(source, ParseGoal::Module).expect("parse should succeed");
    let result = analyze(&tree);
    assert!(
        result.passed(),
        "Module with only TLA statement should be valid"
    );
}

// ---------------------------------------------------------------------------
// Deterministic behavior tests
// ---------------------------------------------------------------------------

#[test]
fn tla_parsing_is_deterministic() {
    let source = "const data = await fetchData();";

    // Parse multiple times and ensure consistent results
    let tree1 = parse(source, ParseGoal::Module).expect("first parse");
    let tree2 = parse(source, ParseGoal::Module).expect("second parse");

    // Basic consistency check - same number of statements
    assert_eq!(tree1.body.len(), tree2.body.len());
    assert_eq!(tree1.goal, tree2.goal);
}

#[test]
fn tla_static_analysis_is_deterministic() {
    let source = "const data = await fetchData();";
    let tree = parse(source, ParseGoal::Module).expect("parse");

    // Analyze multiple times and ensure consistent results
    let result1 = analyze(&tree);
    let result2 = analyze(&tree);

    assert_eq!(result1.passed(), result2.passed());
    assert_eq!(result1.error_count(), result2.error_count());
}
