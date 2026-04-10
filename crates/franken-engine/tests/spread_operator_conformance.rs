//! Spread operator conformance tests.
//!
//! Bead: bd-6a61n.1.12 [RC-1.12]
//!
//! Validates:
//! - Parser recognizes ...expr in array literals, object literals, and calls
//! - IR lowering handles SpreadElement expressions
//! - AST canonical values include spread metadata

#![allow(clippy::needless_borrows_for_generic_args)]

use frankenengine_engine::ast::Expression;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_ok(source: &str) -> frankenengine_engine::ast::SyntaxTree {
    parse_script(source).unwrap_or_else(|e| panic!("should parse: {source}\nerror: {e:?}"))
}

fn lower_source(source: &str) {
    let tree = parse_script(source).expect("should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "spread_conformance.js");
    lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new("trace-spread", "decision-spread", "policy-spread"),
    )
    .expect("should lower");
}

// ---------------------------------------------------------------------------
// 1. Parser: spread in array literals
// ---------------------------------------------------------------------------

#[test]
fn parser_spread_in_array_literal() {
    let tree = parse_ok("[1, ...arr, 3]");
    assert!(!tree.body.is_empty());
}

#[test]
fn parser_spread_only_in_array() {
    let tree = parse_ok("[...items]");
    assert!(!tree.body.is_empty());
}

#[test]
fn parser_multiple_spreads_in_array() {
    let tree = parse_ok("[...a, ...b, ...c]");
    assert!(!tree.body.is_empty());
}

// ---------------------------------------------------------------------------
// 2. Parser: spread in object literals
// ---------------------------------------------------------------------------

#[test]
fn parser_spread_in_object_literal() {
    let tree = parse_ok("({a: 1, ...obj})");
    assert!(!tree.body.is_empty());
}

#[test]
fn parser_spread_only_in_object() {
    let tree = parse_ok("({...defaults})");
    assert!(!tree.body.is_empty());
}

// ---------------------------------------------------------------------------
// 3. Parser: spread in function call arguments
// ---------------------------------------------------------------------------

#[test]
fn parser_spread_in_call_args() {
    let tree = parse_ok("foo(...args)");
    assert!(!tree.body.is_empty());
}

#[test]
fn parser_spread_mixed_in_call_args() {
    let tree = parse_ok("foo(1, ...args, 3)");
    assert!(!tree.body.is_empty());
}

// ---------------------------------------------------------------------------
// 4. Lowering: spread expressions lower without error
// ---------------------------------------------------------------------------

#[test]
fn lowering_spread_in_array_does_not_error() {
    lower_source("var arr = [1, 2]; var result = [...arr];");
}

#[test]
fn lowering_spread_in_call_does_not_error() {
    lower_source("function foo(a, b) { return a; } foo(...[1, 2]);");
}

#[test]
fn lowering_spread_in_object_does_not_error() {
    lower_source("var obj = {a: 1}; var copy = {...obj};");
}

// ---------------------------------------------------------------------------
// 5. AST canonical value
// ---------------------------------------------------------------------------

#[test]
fn ast_spread_element_canonical_value() {
    let expr = Expression::SpreadElement(Box::new(Expression::Identifier("arr".to_string())));
    let cv = expr.canonical_value();
    // Verify the canonical value contains spread metadata via Debug format.
    let debug = format!("{cv:?}");
    assert!(
        debug.contains("spread"),
        "canonical value should contain 'spread': {debug}"
    );
}

// ---------------------------------------------------------------------------
// 6. Nested spread
// ---------------------------------------------------------------------------

#[test]
fn parser_nested_spread_in_array() {
    let tree = parse_ok("[...[...[1, 2]]]");
    assert!(!tree.body.is_empty());
}

// ---------------------------------------------------------------------------
// 7. Rest vs Spread distinction
// ---------------------------------------------------------------------------

#[test]
fn rest_in_destructuring_still_works() {
    // Rest in binding patterns should still work after spread additions
    let tree = parse_ok("var [a, ...rest] = [1, 2, 3];");
    assert!(!tree.body.is_empty());
}

#[test]
fn rest_in_function_params_still_works() {
    let tree = parse_ok("function foo(a, ...rest) { return rest; }");
    assert!(!tree.body.is_empty());
}
