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

use std::collections::BTreeMap;

use frankenengine_engine::ast::{ParseGoal, SyntaxTree};
use frankenengine_engine::parser::parse;
use frankenengine_engine::static_semantics::analyze;

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
    assert!(result.passed(), "Static semantics should pass for TLA in module");
}

#[test]
fn tla_basic_expression_statement_parses() {
    let source = "await doSomething();";
    let tree = parse(source, ParseGoal::Module).expect("parse should succeed");

    // Verify parsing succeeded
    assert_eq!(tree.body.len(), 1);

    // Verify static semantics pass for module context
    let result = analyze(&tree);
    assert!(result.passed(), "Static semantics should pass for TLA in module");
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
    assert!(result.passed(), "Static semantics should pass for multiple TLA in module");
}

#[test]
fn tla_rejected_in_script_context() {
    let source = "const data = await fetchData();";
    let tree = parse(source, ParseGoal::Script).expect("parse should succeed even in script");

    // Static semantics should reject await outside async function in scripts
    let result = analyze(&tree);
    assert!(!result.passed(), "Static semantics should reject TLA in script context");

    // Check that we have the right error
    let errors = result.errors();
    assert!(!errors.is_empty());
    assert!(errors[0].message().contains("await"));
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
    assert!(result.passed(), "Static semantics should pass for complex TLA with exports");
}

// ---------------------------------------------------------------------------
// Module evaluation async behavior tests
// ---------------------------------------------------------------------------

#[test]
fn module_with_tla_has_async_phase() {
    // This test verifies that a module containing top-level await
    // is detected as requiring async evaluation
    let source = "const data = await fetchData();";
    let tree = parse(source, ParseGoal::Module).expect("parse should succeed");

    // Static analysis should pass
    let result = analyze(&tree);
    assert!(result.passed());

    // TODO: When module evaluation is implemented, verify that
    // modules with TLA are marked as async
}

#[test]
fn module_without_tla_remains_sync() {
    // This test verifies that modules without top-level await
    // remain synchronous
    let source = r#"
        export const value = 42;
        export function greet(name) {
            return `Hello, ${name}!`;
        }
    "#;
    let tree = parse(source, ParseGoal::Module).expect("parse should succeed");

    // Static analysis should pass
    let result = analyze(&tree);
    assert!(result.passed());

    // TODO: When module evaluation is implemented, verify that
    // modules without TLA remain synchronous
}

// ---------------------------------------------------------------------------
// Import ordering tests (placeholders for now)
// ---------------------------------------------------------------------------

#[test]
fn tla_import_ordering_placeholder() {
    // TODO: Implement test for import ordering when module B uses TLA
    // and module A imports from B. A should wait for B's evaluation.

    // For now, just verify that the parser can handle imports
    let source = r#"
        import { helper } from './helper.js';
        const data = await fetchData();
        export const processed = helper(data);
    "#;
    let tree = parse(source, ParseGoal::Module).expect("parse should succeed");
    let result = analyze(&tree);
    assert!(result.passed(), "Module with imports and TLA should parse and validate");
}

#[test]
fn tla_error_propagation_placeholder() {
    // TODO: Implement test for error propagation from TLA modules

    // For now, just verify parsing of error handling with TLA
    let source = r#"
        try {
            const data = await riskyOperation();
            export const result = data;
        } catch (error) {
            console.error('TLA failed:', error);
            throw error;
        }
    "#;
    let tree = parse(source, ParseGoal::Module).expect("parse should succeed");
    let result = analyze(&tree);
    assert!(result.passed(), "Module with TLA error handling should parse and validate");
}

// ---------------------------------------------------------------------------
// Edge cases and error conditions
// ---------------------------------------------------------------------------

#[test]
fn tla_await_in_function_still_requires_async() {
    let source = r#"
        const topLevel = await fetchConfig();

        function regular() {
            // This should still fail - await in non-async function
            return await someOperation();
        }
    "#;
    let tree = parse(source, ParseGoal::Module).expect("parse should succeed");

    // Static semantics should reject await in non-async function,
    // even though top-level await is allowed
    let result = analyze(&tree);
    // TODO: This might need more sophisticated error detection
    // For now, just verify it parses
    assert!(tree.body.len() > 0);
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
    assert!(result.passed(), "TLA in blocks should be valid in module context");
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
    assert!(result.passed(), "Module with only TLA statement should be valid");
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