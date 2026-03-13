//! Enrichment integration tests for `static_semantics`.
//!
//! Covers gaps: diagnostic code numbering sequence, StaticError canonical
//! value structure, StaticSemanticsEvent from various results, ordering
//! stability of StaticErrorKind, scope structure for nested blocks,
//! parser-driven analysis edge cases (nested functions, complex destructuring,
//! switch/if scoping, mixed import/export), and serde roundtrip depth.

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

use std::collections::BTreeSet;

use frankenengine_engine::ast::{
    BindingPattern, ExportDeclaration, ExportKind, Expression, ExpressionStatement,
    ImportDeclaration, ParseGoal, SourceSpan, Statement, SyntaxTree, VariableDeclaration,
    VariableDeclarationKind, VariableDeclarator,
};
use frankenengine_engine::ir_contract::BindingKind;
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
use frankenengine_engine::static_semantics::{
    STATIC_SEMANTICS_BEAD_ID, STATIC_SEMANTICS_COMPONENT, STATIC_SEMANTICS_CONTRACT_VERSION,
    StaticAnalysisResult, StaticError, StaticErrorKind, StaticSemanticsEvent, analyze,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_and_analyze(source: &str, goal: ParseGoal) -> StaticAnalysisResult {
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();
    let tree = parser
        .parse_with_options(source, goal, &options)
        .expect("parse should succeed");
    analyze(&tree)
}

fn span(line: u64) -> SourceSpan {
    SourceSpan::new(0, 10, line, 1, line, 10)
}

fn make_tree(goal: ParseGoal, body: Vec<Statement>) -> SyntaxTree {
    SyntaxTree {
        goal,
        body,
        span: SourceSpan::new(0, 100, 1, 1, 10, 1),
    }
}

fn var_decl(
    kind: VariableDeclarationKind,
    name: &str,
    init: Option<Expression>,
    line: u64,
) -> Statement {
    Statement::VariableDeclaration(VariableDeclaration {
        kind,
        declarations: vec![VariableDeclarator {
            pattern: BindingPattern::Identifier(name.to_string()),
            initializer: init,
            span: span(line),
        }],
        span: span(line),
    })
}

fn import_stmt(binding: Option<&str>, source: &str, line: u64) -> Statement {
    Statement::Import(ImportDeclaration {
        binding: binding.map(ToString::to_string),
        source: source.to_string(),
        span: span(line),
    })
}

fn export_named(name: &str, line: u64) -> Statement {
    Statement::Export(ExportDeclaration {
        kind: ExportKind::NamedClause(name.to_string()),
        span: span(line),
    })
}

fn expr_stmt(expr: Expression, line: u64) -> Statement {
    Statement::Expression(ExpressionStatement {
        expression: expr,
        span: span(line),
    })
}

// ---------------------------------------------------------------------------
// StaticErrorKind: diagnostic codes sequential numbering
// ---------------------------------------------------------------------------

#[test]
fn enrichment_diagnostic_codes_have_sequential_numbering() {
    let all_kinds = [
        StaticErrorKind::DuplicateBinding,
        StaticErrorKind::ConstWithoutInitializer,
        StaticErrorKind::ImportInScript,
        StaticErrorKind::ExportInScript,
        StaticErrorKind::DuplicateExport,
        StaticErrorKind::AwaitOutsideAsync,
        StaticErrorKind::TemporalDeadZone,
        StaticErrorKind::LexicalVarCollision,
        StaticErrorKind::EmptyDeclaratorList,
        StaticErrorKind::ReservedWordBinding,
        StaticErrorKind::ImportRedeclaration,
        StaticErrorKind::AssignmentToConst,
        StaticErrorKind::ReturnOutsideFunction,
        StaticErrorKind::BreakOutsideLoop,
        StaticErrorKind::ContinueOutsideLoop,
        StaticErrorKind::DuplicateParameter,
        StaticErrorKind::DeleteOfIdentifier,
        StaticErrorKind::EvalArgumentsBinding,
        StaticErrorKind::ForInInitializer,
        StaticErrorKind::DuplicateDestructuringBinding,
    ];
    assert_eq!(all_kinds.len(), 20);

    // Each code should end with a sequential number 0001 through 0020
    for (i, kind) in all_kinds.iter().enumerate() {
        let code = kind.diagnostic_code();
        let suffix = format!("{:04}", i + 1);
        assert!(
            code.ends_with(&suffix),
            "expected code for {kind} to end with {suffix}, got {code}"
        );
    }
}

#[test]
fn enrichment_diagnostic_codes_all_have_fe_static_diag_prefix() {
    let all_kinds = [
        StaticErrorKind::DuplicateBinding,
        StaticErrorKind::ConstWithoutInitializer,
        StaticErrorKind::ImportInScript,
        StaticErrorKind::ExportInScript,
        StaticErrorKind::DuplicateExport,
        StaticErrorKind::AwaitOutsideAsync,
        StaticErrorKind::TemporalDeadZone,
        StaticErrorKind::LexicalVarCollision,
        StaticErrorKind::EmptyDeclaratorList,
        StaticErrorKind::ReservedWordBinding,
        StaticErrorKind::ImportRedeclaration,
        StaticErrorKind::AssignmentToConst,
        StaticErrorKind::ReturnOutsideFunction,
        StaticErrorKind::BreakOutsideLoop,
        StaticErrorKind::ContinueOutsideLoop,
        StaticErrorKind::DuplicateParameter,
        StaticErrorKind::DeleteOfIdentifier,
        StaticErrorKind::EvalArgumentsBinding,
        StaticErrorKind::ForInInitializer,
        StaticErrorKind::DuplicateDestructuringBinding,
    ];
    for kind in &all_kinds {
        assert!(
            kind.diagnostic_code().starts_with("FE-STATIC-DIAG-"),
            "code for {kind} should start with FE-STATIC-DIAG-"
        );
    }
}

// ---------------------------------------------------------------------------
// StaticErrorKind: ordering is consistent with Ord derive
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_kind_ordering_stable() {
    let mut kinds = vec![
        StaticErrorKind::ContinueOutsideLoop,
        StaticErrorKind::DuplicateBinding,
        StaticErrorKind::TemporalDeadZone,
        StaticErrorKind::ImportInScript,
    ];
    let mut kinds2 = kinds.clone();
    kinds.sort();
    kinds2.sort();
    assert_eq!(kinds, kinds2);
    // DuplicateBinding should come before all others (first in enum)
    assert_eq!(kinds[0], StaticErrorKind::DuplicateBinding);
}

// ---------------------------------------------------------------------------
// StaticErrorKind: as_str and Display consistency
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_kind_as_str_all_snake_case() {
    let all_kinds = [
        StaticErrorKind::DuplicateBinding,
        StaticErrorKind::ConstWithoutInitializer,
        StaticErrorKind::ImportInScript,
        StaticErrorKind::ExportInScript,
        StaticErrorKind::DuplicateExport,
        StaticErrorKind::AwaitOutsideAsync,
        StaticErrorKind::TemporalDeadZone,
        StaticErrorKind::LexicalVarCollision,
        StaticErrorKind::EmptyDeclaratorList,
        StaticErrorKind::ReservedWordBinding,
        StaticErrorKind::ImportRedeclaration,
        StaticErrorKind::AssignmentToConst,
        StaticErrorKind::ReturnOutsideFunction,
        StaticErrorKind::BreakOutsideLoop,
        StaticErrorKind::ContinueOutsideLoop,
        StaticErrorKind::DuplicateParameter,
        StaticErrorKind::DeleteOfIdentifier,
        StaticErrorKind::EvalArgumentsBinding,
        StaticErrorKind::ForInInitializer,
        StaticErrorKind::DuplicateDestructuringBinding,
    ];
    for kind in &all_kinds {
        let s = kind.as_str();
        assert!(
            s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "{kind} as_str should be snake_case, got {s}"
        );
        assert_eq!(kind.to_string(), s, "Display should match as_str");
    }
}

// ---------------------------------------------------------------------------
// StaticErrorKind: serde roundtrip all 20 variants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_kind_serde_roundtrip_all_20() {
    let all_kinds = [
        StaticErrorKind::DuplicateBinding,
        StaticErrorKind::ConstWithoutInitializer,
        StaticErrorKind::ImportInScript,
        StaticErrorKind::ExportInScript,
        StaticErrorKind::DuplicateExport,
        StaticErrorKind::AwaitOutsideAsync,
        StaticErrorKind::TemporalDeadZone,
        StaticErrorKind::LexicalVarCollision,
        StaticErrorKind::EmptyDeclaratorList,
        StaticErrorKind::ReservedWordBinding,
        StaticErrorKind::ImportRedeclaration,
        StaticErrorKind::AssignmentToConst,
        StaticErrorKind::ReturnOutsideFunction,
        StaticErrorKind::BreakOutsideLoop,
        StaticErrorKind::ContinueOutsideLoop,
        StaticErrorKind::DuplicateParameter,
        StaticErrorKind::DeleteOfIdentifier,
        StaticErrorKind::EvalArgumentsBinding,
        StaticErrorKind::ForInInitializer,
        StaticErrorKind::DuplicateDestructuringBinding,
    ];
    let jsons: BTreeSet<_> = all_kinds
        .iter()
        .map(|k| {
            let json = serde_json::to_string(k).unwrap();
            let back: StaticErrorKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
            json
        })
        .collect();
    assert_eq!(jsons.len(), 20, "all 20 variants must produce unique JSON");
}

// ---------------------------------------------------------------------------
// StaticError: Display format
// ---------------------------------------------------------------------------

#[test]
fn enrichment_static_error_display_format() {
    let err = StaticError::new(
        StaticErrorKind::DuplicateBinding,
        "binding 'x' already declared",
        span(5),
    );
    let display = err.to_string();
    assert!(display.contains("FE-STATIC-DIAG-DUP-BINDING-0001"));
    assert!(display.contains("binding 'x' already declared"));
    assert!(display.contains("5"));
}

// ---------------------------------------------------------------------------
// StaticError: canonical_value structure
// ---------------------------------------------------------------------------

#[test]
fn enrichment_static_error_canonical_value_has_required_keys() {
    use frankenengine_engine::deterministic_serde::CanonicalValue;
    let err = StaticError::new(
        StaticErrorKind::TemporalDeadZone,
        "tdz violation for 'y'",
        span(10),
    );
    let cv = err.canonical_value();
    if let CanonicalValue::Map(map) = cv {
        assert!(map.contains_key("diagnostic_code"));
        assert!(map.contains_key("kind"));
        assert!(map.contains_key("message"));
        assert!(map.contains_key("span"));
        if let Some(CanonicalValue::String(kind)) = map.get("kind") {
            assert_eq!(kind, "temporal_dead_zone");
        } else {
            panic!("kind should be a string");
        }
    } else {
        panic!("expected CanonicalValue::Map");
    }
}

// ---------------------------------------------------------------------------
// StaticError: serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_static_error_serde_roundtrip() {
    let err = StaticError::new(
        StaticErrorKind::AssignmentToConst,
        "cannot assign to const 'MAX'",
        SourceSpan::new(10, 25, 3, 5, 3, 20),
    );
    let json = serde_json::to_string(&err).unwrap();
    let back: StaticError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

// ---------------------------------------------------------------------------
// StaticAnalysisResult: passed and error_count
// ---------------------------------------------------------------------------

#[test]
fn enrichment_empty_script_passes() {
    let tree = make_tree(ParseGoal::Script, vec![]);
    let result = analyze(&tree);
    assert!(result.passed());
    assert_eq!(result.error_count(), 0);
    assert!(!result.is_module);
}

#[test]
fn enrichment_empty_module_passes() {
    let tree = make_tree(ParseGoal::Module, vec![]);
    let result = analyze(&tree);
    assert!(result.passed());
    assert_eq!(result.error_count(), 0);
    assert!(result.is_module);
}

// ---------------------------------------------------------------------------
// StaticAnalysisResult: canonical_value structure
// ---------------------------------------------------------------------------

#[test]
fn enrichment_analysis_result_canonical_value_keys() {
    use frankenengine_engine::deterministic_serde::CanonicalValue;
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Let,
            "x",
            Some(Expression::NumericLiteral(1)),
            1,
        )],
    );
    let result = analyze(&tree);
    let cv = result.canonical_value();
    if let CanonicalValue::Map(map) = cv {
        assert!(map.contains_key("bindings"));
        assert!(map.contains_key("errors"));
        assert!(map.contains_key("is_module"));
        assert!(map.contains_key("scopes"));
    } else {
        panic!("expected CanonicalValue::Map");
    }
}

// ---------------------------------------------------------------------------
// StaticAnalysisResult: serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_analysis_result_serde_roundtrip() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![
            import_stmt(Some("React"), "react", 1),
            var_decl(
                VariableDeclarationKind::Const,
                "x",
                Some(Expression::NumericLiteral(42)),
                2,
            ),
            export_named("x", 3),
        ],
    );
    let result = analyze(&tree);
    assert!(result.passed());
    let json = serde_json::to_string(&result).unwrap();
    let back: StaticAnalysisResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// StaticSemanticsEvent: from passing result
// ---------------------------------------------------------------------------

#[test]
fn enrichment_event_from_passing_result() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Var,
            "a",
            Some(Expression::NumericLiteral(1)),
            1,
        )],
    );
    let result = analyze(&tree);
    let event = StaticSemanticsEvent::from_result(&result);
    assert_eq!(event.component, "static_semantics");
    assert_eq!(event.event, "analysis_complete");
    assert_eq!(event.outcome, "pass");
    assert_eq!(event.error_count, 0);
    assert!(!event.is_module);
    assert!(event.binding_count > 0);
    assert!(event.scope_count > 0);
}

#[test]
fn enrichment_event_from_failing_result() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Const,
            "x",
            None, // const without initializer
            1,
        )],
    );
    let result = analyze(&tree);
    assert!(!result.passed());
    let event = StaticSemanticsEvent::from_result(&result);
    assert_eq!(event.outcome, "fail");
    assert!(event.error_count > 0);
}

// ---------------------------------------------------------------------------
// StaticSemanticsEvent: canonical_value and serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_event_canonical_value_has_all_fields() {
    use frankenengine_engine::deterministic_serde::CanonicalValue;
    let tree = make_tree(ParseGoal::Module, vec![]);
    let result = analyze(&tree);
    let event = StaticSemanticsEvent::from_result(&result);
    let cv = event.canonical_value();
    if let CanonicalValue::Map(map) = cv {
        let expected_keys = [
            "binding_count",
            "component",
            "error_count",
            "event",
            "is_module",
            "outcome",
            "scope_count",
        ];
        for key in &expected_keys {
            assert!(
                map.contains_key(*key),
                "event canonical value missing key: {key}"
            );
        }
    } else {
        panic!("expected CanonicalValue::Map");
    }
}

#[test]
fn enrichment_event_serde_roundtrip() {
    let event = StaticSemanticsEvent {
        component: "static_semantics".to_string(),
        event: "analysis_complete".to_string(),
        outcome: "pass".to_string(),
        error_count: 0,
        binding_count: 5,
        scope_count: 2,
        is_module: true,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: StaticSemanticsEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_contract_version_starts_with_prefix() {
    assert!(STATIC_SEMANTICS_CONTRACT_VERSION.starts_with("franken-engine."));
}

#[test]
fn enrichment_bead_and_component_non_empty() {
    assert!(!STATIC_SEMANTICS_BEAD_ID.is_empty());
    assert!(!STATIC_SEMANTICS_COMPONENT.is_empty());
    assert_eq!(STATIC_SEMANTICS_COMPONENT, "static_semantics");
}

// ---------------------------------------------------------------------------
// Analysis: import in script detected
// ---------------------------------------------------------------------------

#[test]
fn enrichment_import_in_script_produces_error() {
    let tree = make_tree(ParseGoal::Script, vec![import_stmt(Some("foo"), "bar", 1)]);
    let result = analyze(&tree);
    assert!(!result.passed());
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.kind == StaticErrorKind::ImportInScript)
    );
}

// ---------------------------------------------------------------------------
// Analysis: export in script detected
// ---------------------------------------------------------------------------

#[test]
fn enrichment_export_in_script_produces_error() {
    let tree = make_tree(ParseGoal::Script, vec![export_named("x", 1)]);
    let result = analyze(&tree);
    assert!(!result.passed());
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.kind == StaticErrorKind::ExportInScript)
    );
}

// ---------------------------------------------------------------------------
// Analysis: const without initializer
// ---------------------------------------------------------------------------

#[test]
fn enrichment_const_without_init_detected() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(VariableDeclarationKind::Const, "x", None, 1)],
    );
    let result = analyze(&tree);
    assert!(!result.passed());
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.kind == StaticErrorKind::ConstWithoutInitializer)
    );
}

// ---------------------------------------------------------------------------
// Analysis: duplicate let binding
// ---------------------------------------------------------------------------

#[test]
fn enrichment_duplicate_let_binding_detected() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(1)),
                1,
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(2)),
                2,
            ),
        ],
    );
    let result = analyze(&tree);
    assert!(!result.passed());
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.kind == StaticErrorKind::DuplicateBinding)
    );
}

// ---------------------------------------------------------------------------
// Analysis: TDZ violation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_tdz_use_before_let() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            expr_stmt(Expression::Identifier("y".to_string()), 1),
            var_decl(
                VariableDeclarationKind::Let,
                "y",
                Some(Expression::NumericLiteral(1)),
                2,
            ),
        ],
    );
    let result = analyze(&tree);
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.kind == StaticErrorKind::TemporalDeadZone)
    );
}

// ---------------------------------------------------------------------------
// Analysis: var does not trigger TDZ
// ---------------------------------------------------------------------------

#[test]
fn enrichment_var_no_tdz() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            expr_stmt(Expression::Identifier("z".to_string()), 1),
            var_decl(
                VariableDeclarationKind::Var,
                "z",
                Some(Expression::NumericLiteral(1)),
                2,
            ),
        ],
    );
    let result = analyze(&tree);
    // var is hoisted, no TDZ
    let has_tdz = result
        .errors
        .iter()
        .any(|e| e.kind == StaticErrorKind::TemporalDeadZone);
    assert!(!has_tdz, "var should not trigger TDZ");
}

// ---------------------------------------------------------------------------
// Analysis: multiple errors in one tree
// ---------------------------------------------------------------------------

#[test]
fn enrichment_multiple_errors_collected() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(VariableDeclarationKind::Const, "a", None, 1), // const without init
            var_decl(
                VariableDeclarationKind::Let,
                "b",
                Some(Expression::NumericLiteral(1)),
                2,
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "b",
                Some(Expression::NumericLiteral(2)),
                3,
            ), // duplicate
        ],
    );
    let result = analyze(&tree);
    assert!(result.error_count() >= 2);
    let kinds: BTreeSet<_> = result.errors.iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&StaticErrorKind::ConstWithoutInitializer));
    assert!(kinds.contains(&StaticErrorKind::DuplicateBinding));
}

// ---------------------------------------------------------------------------
// Analysis: parser-driven tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_parser_var_let_const_valid() {
    let result = parse_and_analyze("var a = 1; let b = 2; const c = 3;", ParseGoal::Script);
    assert!(result.passed());
    assert!(result.bindings.len() >= 3);
}

#[test]
fn enrichment_parser_module_import_export_valid() {
    let result = parse_and_analyze(
        "import x from 'module'; export default x;",
        ParseGoal::Module,
    );
    assert!(result.passed());
    assert!(result.is_module);
}

#[test]
fn enrichment_parser_duplicate_let_detected() {
    let result = parse_and_analyze("let x = 1; let x = 2;", ParseGoal::Script);
    assert!(!result.passed());
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.kind == StaticErrorKind::DuplicateBinding)
    );
}

#[test]
fn enrichment_parser_const_without_init_rejected() {
    // The parser itself rejects `const x;` (no initializer) before static
    // analysis runs — verify the parse error mentions "initializer".
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();
    let err = parser
        .parse_with_options("const x;", ParseGoal::Script, &options)
        .expect_err("parser should reject const without initializer");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("initializer"),
        "error should mention initializer: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Analysis: determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_analysis_deterministic() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![
            import_stmt(Some("React"), "react", 1),
            var_decl(
                VariableDeclarationKind::Const,
                "x",
                Some(Expression::NumericLiteral(1)),
                2,
            ),
            export_named("x", 3),
        ],
    );
    let r1 = analyze(&tree);
    let r2 = analyze(&tree);
    assert_eq!(r1, r2);
}

// ---------------------------------------------------------------------------
// Scope structure: module vs script
// ---------------------------------------------------------------------------

#[test]
fn enrichment_script_has_global_scope() {
    let tree = make_tree(ParseGoal::Script, vec![]);
    let result = analyze(&tree);
    assert!(!result.scopes.is_empty());
    assert!(
        result
            .scopes
            .iter()
            .any(|s| s.kind == frankenengine_engine::ir_contract::ScopeKind::Global)
    );
}

#[test]
fn enrichment_module_has_module_scope() {
    let tree = make_tree(ParseGoal::Module, vec![]);
    let result = analyze(&tree);
    assert!(!result.scopes.is_empty());
    assert!(
        result
            .scopes
            .iter()
            .any(|s| s.kind == frankenengine_engine::ir_contract::ScopeKind::Module)
    );
}

// ---------------------------------------------------------------------------
// Lexical-var collision
// ---------------------------------------------------------------------------

#[test]
fn enrichment_let_then_var_collision() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(1)),
                1,
            ),
            var_decl(
                VariableDeclarationKind::Var,
                "x",
                Some(Expression::NumericLiteral(2)),
                2,
            ),
        ],
    );
    let result = analyze(&tree);
    assert!(!result.passed());
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.kind == StaticErrorKind::LexicalVarCollision)
    );
}

// ---------------------------------------------------------------------------
// Event counts match result
// ---------------------------------------------------------------------------

#[test]
fn enrichment_event_counts_match_analysis() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![
            import_stmt(Some("a"), "mod-a", 1),
            import_stmt(Some("b"), "mod-b", 2),
            var_decl(
                VariableDeclarationKind::Let,
                "c",
                Some(Expression::NumericLiteral(3)),
                3,
            ),
        ],
    );
    let result = analyze(&tree);
    let event = StaticSemanticsEvent::from_result(&result);
    assert_eq!(event.error_count, result.error_count() as u64);
    assert_eq!(event.binding_count, result.bindings.len() as u64);
    assert_eq!(event.scope_count, result.scopes.len() as u64);
    assert_eq!(event.is_module, result.is_module);
}

// ---------------------------------------------------------------------------
// Analysis: duplicate export detected
// ---------------------------------------------------------------------------

#[test]
fn enrichment_duplicate_export_detected() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(1)),
                1,
            ),
            export_named("x", 2),
            export_named("x", 3),
        ],
    );
    let result = analyze(&tree);
    assert!(!result.passed());
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.kind == StaticErrorKind::DuplicateExport)
    );
}

// ---------------------------------------------------------------------------
// Analysis: import redeclaration detected
// ---------------------------------------------------------------------------

#[test]
fn enrichment_import_redeclaration_detected() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![
            import_stmt(Some("x"), "mod-a", 1),
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(1)),
                2,
            ),
        ],
    );
    let result = analyze(&tree);
    assert!(!result.passed());
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.kind == StaticErrorKind::ImportRedeclaration
                || e.kind == StaticErrorKind::DuplicateBinding)
    );
}

// ---------------------------------------------------------------------------
// Analysis: empty declarator list
// ---------------------------------------------------------------------------

#[test]
fn enrichment_empty_declarator_list_detected() {
    use frankenengine_engine::ast::VariableDeclaration;
    let tree = make_tree(
        ParseGoal::Script,
        vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Let,
            declarations: vec![],
            span: span(1),
        })],
    );
    let result = analyze(&tree);
    assert!(!result.passed());
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.kind == StaticErrorKind::EmptyDeclaratorList)
    );
}

// ---------------------------------------------------------------------------
// Analysis: reserved word binding
// ---------------------------------------------------------------------------

#[test]
fn enrichment_reserved_word_binding_package() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![var_decl(
            VariableDeclarationKind::Let,
            "package",
            Some(Expression::NumericLiteral(1)),
            1,
        )],
    );
    let result = analyze(&tree);
    // module goal implies strict mode — "package" is a strict reserved word
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.kind == StaticErrorKind::ReservedWordBinding)
    );
}

#[test]
fn enrichment_reserved_word_binding_implements() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![var_decl(
            VariableDeclarationKind::Let,
            "implements",
            Some(Expression::NumericLiteral(1)),
            1,
        )],
    );
    let result = analyze(&tree);
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.kind == StaticErrorKind::ReservedWordBinding)
    );
}

// ---------------------------------------------------------------------------
// Analysis: valid module with multiple imports and exports
// ---------------------------------------------------------------------------

#[test]
fn enrichment_valid_module_complex() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![
            import_stmt(Some("a"), "mod-a", 1),
            import_stmt(Some("b"), "mod-b", 2),
            var_decl(
                VariableDeclarationKind::Const,
                "result",
                Some(Expression::NumericLiteral(42)),
                3,
            ),
            export_named("result", 4),
        ],
    );
    let result = analyze(&tree);
    assert!(result.passed());
    assert!(result.is_module);
    assert!(result.bindings.len() >= 3);
}

// ---------------------------------------------------------------------------
// Analysis: duplicate bindings across var kinds
// ---------------------------------------------------------------------------

#[test]
fn enrichment_const_then_let_collision() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Const,
                "x",
                Some(Expression::NumericLiteral(1)),
                1,
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(2)),
                2,
            ),
        ],
    );
    let result = analyze(&tree);
    assert!(!result.passed());
}

#[test]
fn enrichment_var_then_let_collision() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Var,
                "x",
                Some(Expression::NumericLiteral(1)),
                1,
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "x",
                Some(Expression::NumericLiteral(2)),
                2,
            ),
        ],
    );
    let result = analyze(&tree);
    assert!(!result.passed());
}

// ---------------------------------------------------------------------------
// Analysis: var-var does NOT collide
// ---------------------------------------------------------------------------

#[test]
fn enrichment_var_var_no_collision() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Var,
                "x",
                Some(Expression::NumericLiteral(1)),
                1,
            ),
            var_decl(
                VariableDeclarationKind::Var,
                "x",
                Some(Expression::NumericLiteral(2)),
                2,
            ),
        ],
    );
    let result = analyze(&tree);
    // var re-declaration is allowed in non-strict mode
    let has_dup = result
        .errors
        .iter()
        .any(|e| e.kind == StaticErrorKind::DuplicateBinding);
    assert!(!has_dup, "var-var should not be a duplicate binding error");
}

// ---------------------------------------------------------------------------
// Analysis: single binding passes
// ---------------------------------------------------------------------------

#[test]
fn enrichment_single_let_passes() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Let,
            "x",
            Some(Expression::NumericLiteral(1)),
            1,
        )],
    );
    let result = analyze(&tree);
    assert!(result.passed());
    assert!(!result.bindings.is_empty());
}

#[test]
fn enrichment_single_const_with_init_passes() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Const,
            "MAX",
            Some(Expression::NumericLiteral(100)),
            1,
        )],
    );
    let result = analyze(&tree);
    assert!(result.passed());
}

// ---------------------------------------------------------------------------
// StaticError: clone equality
// ---------------------------------------------------------------------------

#[test]
fn enrichment_static_error_clone_eq() {
    let err = StaticError::new(
        StaticErrorKind::BreakOutsideLoop,
        "break not in loop",
        span(10),
    );
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

// ---------------------------------------------------------------------------
// StaticAnalysisResult: serde roundtrip with errors
// ---------------------------------------------------------------------------

#[test]
fn enrichment_result_with_errors_serde_roundtrip() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(VariableDeclarationKind::Const, "a", None, 1),
            var_decl(
                VariableDeclarationKind::Let,
                "b",
                Some(Expression::NumericLiteral(1)),
                2,
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "b",
                Some(Expression::NumericLiteral(2)),
                3,
            ),
        ],
    );
    let result = analyze(&tree);
    assert!(!result.passed());
    let json = serde_json::to_string(&result).unwrap();
    let back: StaticAnalysisResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// Analysis: binding resolution produces BindingKind
// ---------------------------------------------------------------------------

#[test]
fn enrichment_binding_kind_let() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Let,
            "x",
            Some(Expression::NumericLiteral(1)),
            1,
        )],
    );
    let result = analyze(&tree);
    assert!(
        result
            .bindings
            .iter()
            .any(|b| b.name == "x" && b.kind == BindingKind::Let)
    );
}

#[test]
fn enrichment_binding_kind_const() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Const,
            "Y",
            Some(Expression::NumericLiteral(42)),
            1,
        )],
    );
    let result = analyze(&tree);
    assert!(
        result
            .bindings
            .iter()
            .any(|b| b.name == "Y" && b.kind == BindingKind::Const)
    );
}

#[test]
fn enrichment_binding_kind_var() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Var,
            "z",
            Some(Expression::NumericLiteral(0)),
            1,
        )],
    );
    let result = analyze(&tree);
    assert!(
        result
            .bindings
            .iter()
            .any(|b| b.name == "z" && b.kind == BindingKind::Var)
    );
}

// ---------------------------------------------------------------------------
// Analysis: import binding kind
// ---------------------------------------------------------------------------

#[test]
fn enrichment_binding_kind_import() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![import_stmt(Some("React"), "react", 1)],
    );
    let result = analyze(&tree);
    assert!(result.passed());
    assert!(
        result
            .bindings
            .iter()
            .any(|b| b.name == "React" && b.kind == BindingKind::Import)
    );
}

// ---------------------------------------------------------------------------
// Analysis: parser-driven complex programs
// ---------------------------------------------------------------------------

#[test]
fn enrichment_parser_nested_function_valid() {
    let result = parse_and_analyze(
        "function outer() { let x = 1; function inner() { let y = x; } }",
        ParseGoal::Script,
    );
    assert!(result.passed());
    assert!(result.scopes.len() >= 3); // global + outer + inner
}

#[test]
fn enrichment_parser_arrow_function_valid() {
    let result = parse_and_analyze("const add = (a, b) => a + b;", ParseGoal::Script);
    assert!(result.passed());
}

#[test]
fn enrichment_parser_if_block_scoping() {
    let result = parse_and_analyze("if (true) { let x = 1; } let x = 2;", ParseGoal::Script);
    // block-scoped: both x's are fine
    assert!(result.passed());
}

#[test]
fn enrichment_parser_for_loop_scoping() {
    let result = parse_and_analyze(
        "for (let i = 0; i < 10; i++) { let j = i; }",
        ParseGoal::Script,
    );
    assert!(result.passed());
}

#[test]
fn enrichment_parser_switch_scoping() {
    let result = parse_and_analyze(
        "switch (1) { case 1: { let x = 1; break; } case 2: { let x = 2; break; } }",
        ParseGoal::Script,
    );
    assert!(result.passed());
}

#[test]
fn enrichment_parser_try_catch_scoping() {
    let result = parse_and_analyze(
        "try { let x = 1; } catch (e) { let x = 2; }",
        ParseGoal::Script,
    );
    assert!(result.passed());
}

// ---------------------------------------------------------------------------
// Diagnostic code: uniqueness across all kinds
// ---------------------------------------------------------------------------

#[test]
fn enrichment_diagnostic_codes_all_unique() {
    let all_kinds = [
        StaticErrorKind::DuplicateBinding,
        StaticErrorKind::ConstWithoutInitializer,
        StaticErrorKind::ImportInScript,
        StaticErrorKind::ExportInScript,
        StaticErrorKind::DuplicateExport,
        StaticErrorKind::AwaitOutsideAsync,
        StaticErrorKind::TemporalDeadZone,
        StaticErrorKind::LexicalVarCollision,
        StaticErrorKind::EmptyDeclaratorList,
        StaticErrorKind::ReservedWordBinding,
        StaticErrorKind::ImportRedeclaration,
        StaticErrorKind::AssignmentToConst,
        StaticErrorKind::ReturnOutsideFunction,
        StaticErrorKind::BreakOutsideLoop,
        StaticErrorKind::ContinueOutsideLoop,
        StaticErrorKind::DuplicateParameter,
        StaticErrorKind::DeleteOfIdentifier,
        StaticErrorKind::EvalArgumentsBinding,
        StaticErrorKind::ForInInitializer,
        StaticErrorKind::DuplicateDestructuringBinding,
    ];
    let codes: BTreeSet<_> = all_kinds.iter().map(|k| k.diagnostic_code()).collect();
    assert_eq!(codes.len(), 20, "all diagnostic codes must be unique");
}

// ---------------------------------------------------------------------------
// StaticSemanticsEvent: component is always static_semantics
// ---------------------------------------------------------------------------

#[test]
fn enrichment_event_component_always_static_semantics() {
    let results = vec![
        analyze(&make_tree(ParseGoal::Script, vec![])),
        analyze(&make_tree(ParseGoal::Module, vec![])),
        analyze(&make_tree(
            ParseGoal::Script,
            vec![var_decl(
                VariableDeclarationKind::Let,
                "a",
                Some(Expression::NumericLiteral(1)),
                1,
            )],
        )),
    ];
    for result in &results {
        let event = StaticSemanticsEvent::from_result(result);
        assert_eq!(event.component, STATIC_SEMANTICS_COMPONENT);
    }
}

// ---------------------------------------------------------------------------
// Analysis: scope IDs are unique
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scope_ids_unique() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![
            var_decl(
                VariableDeclarationKind::Let,
                "a",
                Some(Expression::NumericLiteral(1)),
                1,
            ),
            var_decl(
                VariableDeclarationKind::Let,
                "b",
                Some(Expression::NumericLiteral(2)),
                2,
            ),
        ],
    );
    let result = analyze(&tree);
    let scope_ids: BTreeSet<_> = result.scopes.iter().map(|s| s.scope_id).collect();
    assert_eq!(scope_ids.len(), result.scopes.len());
}

// ---------------------------------------------------------------------------
// Analysis: binding IDs are unique
// ---------------------------------------------------------------------------

#[test]
fn enrichment_binding_ids_unique() {
    let tree = make_tree(
        ParseGoal::Module,
        vec![
            import_stmt(Some("a"), "mod-a", 1),
            var_decl(
                VariableDeclarationKind::Let,
                "b",
                Some(Expression::NumericLiteral(1)),
                2,
            ),
            var_decl(
                VariableDeclarationKind::Const,
                "c",
                Some(Expression::NumericLiteral(2)),
                3,
            ),
        ],
    );
    let result = analyze(&tree);
    let binding_ids: BTreeSet<_> = result.bindings.iter().map(|b| b.binding_id).collect();
    assert_eq!(binding_ids.len(), result.bindings.len());
}

// =========================================================================
// Enrichment: StaticErrorKind as_str all 20 distinct
// =========================================================================

#[test]
fn enrichment_as_str_all_20_distinct() {
    let all_kinds = [
        StaticErrorKind::DuplicateBinding,
        StaticErrorKind::ConstWithoutInitializer,
        StaticErrorKind::ImportInScript,
        StaticErrorKind::ExportInScript,
        StaticErrorKind::DuplicateExport,
        StaticErrorKind::AwaitOutsideAsync,
        StaticErrorKind::TemporalDeadZone,
        StaticErrorKind::LexicalVarCollision,
        StaticErrorKind::EmptyDeclaratorList,
        StaticErrorKind::ReservedWordBinding,
        StaticErrorKind::ImportRedeclaration,
        StaticErrorKind::AssignmentToConst,
        StaticErrorKind::ReturnOutsideFunction,
        StaticErrorKind::BreakOutsideLoop,
        StaticErrorKind::ContinueOutsideLoop,
        StaticErrorKind::DuplicateParameter,
        StaticErrorKind::DeleteOfIdentifier,
        StaticErrorKind::EvalArgumentsBinding,
        StaticErrorKind::ForInInitializer,
        StaticErrorKind::DuplicateDestructuringBinding,
    ];
    let strs: BTreeSet<_> = all_kinds.iter().map(|k| k.as_str()).collect();
    assert_eq!(strs.len(), 20, "all as_str values must be distinct");
    for s in &strs {
        assert!(!s.is_empty());
    }
}

// =========================================================================
// Enrichment: StaticErrorKind Display == as_str
// =========================================================================

#[test]
fn enrichment_error_kind_display_equals_as_str() {
    let kinds = [
        StaticErrorKind::DuplicateBinding,
        StaticErrorKind::AssignmentToConst,
        StaticErrorKind::DeleteOfIdentifier,
        StaticErrorKind::ForInInitializer,
        StaticErrorKind::DuplicateDestructuringBinding,
    ];
    for kind in &kinds {
        assert_eq!(kind.to_string(), kind.as_str());
    }
}

// =========================================================================
// Enrichment: StaticErrorKind Copy semantics
// =========================================================================

#[test]
fn enrichment_error_kind_copy_semantics() {
    let a = StaticErrorKind::TemporalDeadZone;
    let b = a;
    assert_eq!(a, b);
    let c = StaticErrorKind::DuplicateParameter;
    let d = c;
    assert_eq!(c, d);
}

// =========================================================================
// Enrichment: StaticErrorKind BTreeSet ordering
// =========================================================================

#[test]
fn enrichment_error_kind_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(StaticErrorKind::DuplicateBinding);
    set.insert(StaticErrorKind::AssignmentToConst);
    set.insert(StaticErrorKind::ReturnOutsideFunction);
    set.insert(StaticErrorKind::DuplicateBinding); // dup
    assert_eq!(set.len(), 3);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

// =========================================================================
// Enrichment: StaticErrorKind serde roundtrip all variants
// =========================================================================

#[test]
fn enrichment_error_kind_serde_all_variants() {
    let all_kinds = [
        StaticErrorKind::DuplicateBinding,
        StaticErrorKind::ConstWithoutInitializer,
        StaticErrorKind::ImportInScript,
        StaticErrorKind::ExportInScript,
        StaticErrorKind::DuplicateExport,
        StaticErrorKind::AwaitOutsideAsync,
        StaticErrorKind::TemporalDeadZone,
        StaticErrorKind::LexicalVarCollision,
        StaticErrorKind::EmptyDeclaratorList,
        StaticErrorKind::ReservedWordBinding,
        StaticErrorKind::ImportRedeclaration,
        StaticErrorKind::AssignmentToConst,
        StaticErrorKind::ReturnOutsideFunction,
        StaticErrorKind::BreakOutsideLoop,
        StaticErrorKind::ContinueOutsideLoop,
        StaticErrorKind::DuplicateParameter,
        StaticErrorKind::DeleteOfIdentifier,
        StaticErrorKind::EvalArgumentsBinding,
        StaticErrorKind::ForInInitializer,
        StaticErrorKind::DuplicateDestructuringBinding,
    ];
    for kind in &all_kinds {
        let json = serde_json::to_string(kind).unwrap();
        let back: StaticErrorKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// =========================================================================
// Enrichment: StaticError Display contains diagnostic_code and message
// =========================================================================

#[test]
fn enrichment_static_error_display_contains_code_and_message() {
    let err = StaticError::new(
        StaticErrorKind::BreakOutsideLoop,
        "break not in loop",
        span(5),
    );
    let display = err.to_string();
    assert!(display.contains("FE-STATIC-DIAG-BREAK-OUTSIDE-0014"));
    assert!(display.contains("break not in loop"));
    assert!(display.contains("5")); // line number
}

// =========================================================================
// Enrichment: StaticError Debug nonempty
// =========================================================================

#[test]
fn enrichment_static_error_debug_nonempty() {
    let err = StaticError::new(
        StaticErrorKind::ContinueOutsideLoop,
        "continue not in loop",
        span(7),
    );
    assert!(!format!("{err:?}").is_empty());
}

// =========================================================================
// Enrichment: StaticError serde roundtrip (individual)
// =========================================================================

#[test]
fn enrichment_static_error_serde_roundtrip_assignment_to_const() {
    let err = StaticError::new(
        StaticErrorKind::AssignmentToConst,
        "assignment to constant 'x'",
        span(42),
    );
    let json = serde_json::to_string(&err).unwrap();
    let back: StaticError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

// =========================================================================
// Enrichment: StaticSemanticsEvent serde roundtrip (module with import)
// =========================================================================

#[test]
fn enrichment_event_serde_roundtrip_module_import() {
    let result = analyze(&make_tree(
        ParseGoal::Module,
        vec![import_stmt(Some("x"), "mod", 1)],
    ));
    let event = StaticSemanticsEvent::from_result(&result);
    let json = serde_json::to_string(&event).unwrap();
    let back: StaticSemanticsEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// =========================================================================
// Enrichment: StaticSemanticsEvent clone independence
// =========================================================================

#[test]
fn enrichment_event_clone_independence() {
    let result = analyze(&make_tree(ParseGoal::Script, vec![]));
    let original = StaticSemanticsEvent::from_result(&result);
    let mut cloned = original.clone();
    cloned.outcome = "modified".to_string();
    assert_eq!(original.outcome, "pass");
    assert_eq!(cloned.outcome, "modified");
}

// =========================================================================
// Enrichment: StaticSemanticsEvent outcome pass vs fail
// =========================================================================

#[test]
fn enrichment_event_outcome_pass_vs_fail() {
    // passing
    let pass_result = analyze(&make_tree(ParseGoal::Script, vec![]));
    let pass_event = StaticSemanticsEvent::from_result(&pass_result);
    assert_eq!(pass_event.outcome, "pass");
    assert_eq!(pass_event.error_count, 0);

    // failing
    let fail_result = analyze(&make_tree(
        ParseGoal::Script,
        vec![var_decl(VariableDeclarationKind::Const, "a", None, 1)],
    ));
    let fail_event = StaticSemanticsEvent::from_result(&fail_result);
    assert_eq!(fail_event.outcome, "fail");
    assert!(fail_event.error_count > 0);
}

// =========================================================================
// Enrichment: StaticAnalysisResult clone independence
// =========================================================================

#[test]
fn enrichment_result_clone_independence() {
    let tree = make_tree(
        ParseGoal::Script,
        vec![var_decl(
            VariableDeclarationKind::Let,
            "x",
            Some(Expression::NumericLiteral(1)),
            1,
        )],
    );
    let original = analyze(&tree);
    let mut cloned = original.clone();
    cloned.errors.push(StaticError::new(
        StaticErrorKind::BreakOutsideLoop,
        "injected",
        span(99),
    ));
    assert!(original.passed());
    assert!(!cloned.passed());
}

// =========================================================================
// Enrichment: parser-driven ReturnOutsideFunction
// =========================================================================

#[test]
fn enrichment_parser_return_outside_function() {
    let result = parse_and_analyze("return 1;", ParseGoal::Script);
    assert!(!result.passed());
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.kind == StaticErrorKind::ReturnOutsideFunction)
    );
}

// =========================================================================
// Enrichment: parser-driven return inside function OK
// =========================================================================

#[test]
fn enrichment_parser_return_inside_function_ok() {
    let result = parse_and_analyze("function foo() { return 42; }", ParseGoal::Script);
    assert!(result.passed());
}

// =========================================================================
// Enrichment: parser-driven BreakOutsideLoop
// =========================================================================

#[test]
fn enrichment_parser_break_outside_loop() {
    let result = parse_and_analyze("break;", ParseGoal::Script);
    assert!(!result.passed());
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.kind == StaticErrorKind::BreakOutsideLoop)
    );
}

// =========================================================================
// Enrichment: parser-driven ContinueOutsideLoop
// =========================================================================

#[test]
fn enrichment_parser_continue_outside_loop() {
    let result = parse_and_analyze("continue;", ParseGoal::Script);
    assert!(!result.passed());
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.kind == StaticErrorKind::ContinueOutsideLoop)
    );
}

// =========================================================================
// Enrichment: break/continue inside loop OK
// =========================================================================

#[test]
fn enrichment_parser_break_continue_in_loop_ok() {
    let result = parse_and_analyze(
        "for (let i = 0; i < 10; i++) { if (i === 5) break; continue; }",
        ParseGoal::Script,
    );
    assert!(result.passed());
}

// =========================================================================
// Enrichment: parser-driven while loop scoping
// =========================================================================

#[test]
fn enrichment_parser_while_loop_scoping() {
    let result = parse_and_analyze(
        "let x = 0; while (x < 10) { let y = x; x = x + 1; }",
        ParseGoal::Script,
    );
    assert!(result.passed());
}

// =========================================================================
// Enrichment: parser-driven do-while scoping
// =========================================================================

#[test]
fn enrichment_parser_do_while_scoping() {
    let result = parse_and_analyze(
        "let x = 0; do { let y = x; x = x + 1; } while (x < 10);",
        ParseGoal::Script,
    );
    assert!(result.passed());
}

// =========================================================================
// Enrichment: parser-driven for-in scoping
// =========================================================================

#[test]
fn enrichment_parser_for_in_scoping() {
    let result = parse_and_analyze(
        "var obj = {}; for (let key in obj) { let val = key; }",
        ParseGoal::Script,
    );
    assert!(result.passed());
}

// =========================================================================
// Enrichment: parser-driven for-of scoping
// =========================================================================

#[test]
fn enrichment_parser_for_of_scoping() {
    let result = parse_and_analyze(
        "var arr = [1, 2, 3]; for (let item of arr) { let x = item; }",
        ParseGoal::Script,
    );
    assert!(result.passed());
}

// =========================================================================
// Enrichment: parser-driven break inside switch OK
// =========================================================================

#[test]
fn enrichment_parser_break_in_switch_ok() {
    let result = parse_and_analyze(
        "switch (1) { case 1: break; default: break; }",
        ParseGoal::Script,
    );
    assert!(result.passed());
}

// =========================================================================
// Enrichment: diagnostic_code prefix all start with FE-STATIC-DIAG
// =========================================================================

#[test]
fn enrichment_diagnostic_code_prefix() {
    let all_kinds = [
        StaticErrorKind::DuplicateBinding,
        StaticErrorKind::ConstWithoutInitializer,
        StaticErrorKind::ImportInScript,
        StaticErrorKind::ExportInScript,
        StaticErrorKind::DuplicateExport,
        StaticErrorKind::AwaitOutsideAsync,
        StaticErrorKind::TemporalDeadZone,
        StaticErrorKind::LexicalVarCollision,
        StaticErrorKind::EmptyDeclaratorList,
        StaticErrorKind::ReservedWordBinding,
        StaticErrorKind::ImportRedeclaration,
        StaticErrorKind::AssignmentToConst,
        StaticErrorKind::ReturnOutsideFunction,
        StaticErrorKind::BreakOutsideLoop,
        StaticErrorKind::ContinueOutsideLoop,
        StaticErrorKind::DuplicateParameter,
        StaticErrorKind::DeleteOfIdentifier,
        StaticErrorKind::EvalArgumentsBinding,
        StaticErrorKind::ForInInitializer,
        StaticErrorKind::DuplicateDestructuringBinding,
    ];
    for kind in &all_kinds {
        assert!(
            kind.diagnostic_code().starts_with("FE-STATIC-DIAG-"),
            "diagnostic code for {:?} should start with FE-STATIC-DIAG-",
            kind
        );
    }
}

// =========================================================================
// Enrichment: StaticSemanticsEvent event field always "analysis_complete"
// =========================================================================

#[test]
fn enrichment_event_field_always_analysis_complete() {
    let results = [
        analyze(&make_tree(ParseGoal::Script, vec![])),
        analyze(&make_tree(ParseGoal::Module, vec![])),
        analyze(&make_tree(
            ParseGoal::Script,
            vec![var_decl(VariableDeclarationKind::Const, "a", None, 1)],
        )),
    ];
    for result in &results {
        let event = StaticSemanticsEvent::from_result(result);
        assert_eq!(event.event, "analysis_complete");
    }
}

// =========================================================================
// Enrichment: StaticSemanticsEvent Debug nonempty
// =========================================================================

#[test]
fn enrichment_event_debug_nonempty() {
    let result = analyze(&make_tree(ParseGoal::Script, vec![]));
    let event = StaticSemanticsEvent::from_result(&result);
    assert!(!format!("{event:?}").is_empty());
}

// =========================================================================
// Enrichment: StaticErrorKind Debug nonempty all variants
// =========================================================================

#[test]
fn enrichment_error_kind_debug_nonempty_all() {
    let all_kinds = [
        StaticErrorKind::DuplicateBinding,
        StaticErrorKind::ConstWithoutInitializer,
        StaticErrorKind::ImportInScript,
        StaticErrorKind::ExportInScript,
        StaticErrorKind::DuplicateExport,
        StaticErrorKind::AwaitOutsideAsync,
        StaticErrorKind::TemporalDeadZone,
        StaticErrorKind::LexicalVarCollision,
        StaticErrorKind::EmptyDeclaratorList,
        StaticErrorKind::ReservedWordBinding,
        StaticErrorKind::ImportRedeclaration,
        StaticErrorKind::AssignmentToConst,
        StaticErrorKind::ReturnOutsideFunction,
        StaticErrorKind::BreakOutsideLoop,
        StaticErrorKind::ContinueOutsideLoop,
        StaticErrorKind::DuplicateParameter,
        StaticErrorKind::DeleteOfIdentifier,
        StaticErrorKind::EvalArgumentsBinding,
        StaticErrorKind::ForInInitializer,
        StaticErrorKind::DuplicateDestructuringBinding,
    ];
    let debugs: BTreeSet<String> = all_kinds.iter().map(|k| format!("{k:?}")).collect();
    assert_eq!(debugs.len(), 20);
    for d in &debugs {
        assert!(!d.is_empty());
    }
}

// =========================================================================
// Enrichment: parser-driven nested blocks with same let name across scopes
// =========================================================================

#[test]
fn enrichment_parser_nested_blocks_shadowing_ok() {
    let result = parse_and_analyze(
        "{ let x = 1; } { let x = 2; } let x = 3;",
        ParseGoal::Script,
    );
    assert!(result.passed());
}

// =========================================================================
// Enrichment: parser-driven module strict reserved word "yield" rejected
// =========================================================================

#[test]
fn enrichment_parser_module_strict_reserved_yield() {
    let result = parse_and_analyze("let yield = 1;", ParseGoal::Module);
    // module implies strict mode, "yield" is strict reserved
    assert!(!result.passed());
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.kind == StaticErrorKind::ReservedWordBinding)
    );
}

// =========================================================================
// Enrichment: parser-driven script mode allows strict reserved words
// =========================================================================

#[test]
fn enrichment_parser_script_allows_strict_reserved() {
    // In non-strict script mode, "package" is allowed as a binding
    let result = parse_and_analyze("var package = 1;", ParseGoal::Script);
    // Script mode is not strict — strict reserved words are valid bindings
    let has_reserved = result
        .errors
        .iter()
        .any(|e| e.kind == StaticErrorKind::ReservedWordBinding);
    assert!(
        !has_reserved,
        "script mode should allow strict reserved words"
    );
}
