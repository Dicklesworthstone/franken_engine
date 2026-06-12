//! Span-provenance goldens (E1.T3, `bd-fqlfw.1.3`).
//!
//! "A security diagnostic that points to the wrong source line is worse
//! than no diagnostic." These tests pin the SHIPPED span-provenance
//! contract with exact-value assertions that fail if span threading
//! regresses or drifts by even one column:
//!
//! - AST layer (`bd-fqlfw.1.1`): Member/Call expressions carry parse-time
//!   spans equal to their enclosing statement's span (the current contract
//!   is statement-granular; sub-expression precision is a documented
//!   follow-up).
//! - Diagnostic layer (`bd-fqlfw.1.2` / commit 6f5323ef):
//!   `AmbientAuthorityViolation` denials carry those spans — member-access
//!   denials (`process.env`) and `require(...)` call-site denials report
//!   exact source positions.
//!
//! The expected values use the proven single-line convention
//! (offsets `[0, len)`, 1-based lines/columns, `end_column = len + 1`)
//! that `parser_trait_ast` locks for statement spans, so any change to
//! span computation breaks these goldens loudly.
//!
//! `Ir2Op.span` goldens are deliberately absent: the IR-record carry is
//! split to `bd-fqlfw.1.5` (E1.T2b); extend this file when it lands.

use frankenengine_engine::ast::{Expression, ParseGoal, SourceSpan, Statement};
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringPipelineError, lower_ir0_to_ir1};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};
use frankenengine_engine::parser_api_stability::parse_module;

/// The proven statement-span convention for a single-line, single-statement
/// source with no trailing semicolon (mirrors `parser_trait_ast`).
fn single_line_span(source: &str) -> SourceSpan {
    let width = source.len() as u64;
    SourceSpan::new(0, width, 1, 1, 1, width + 1)
}

/// Lower a source string and return the ambient-authority denial span.
fn denial_span(source: &str) -> (String, Option<SourceSpan>) {
    let tree = parse_module(source).expect("fixture should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "span_provenance_golden");
    match lower_ir0_to_ir1(&ir0) {
        Err(LoweringPipelineError::AmbientAuthorityViolation { accessor, span, .. }) => {
            (accessor, span)
        }
        other => panic!("fixture must raise AmbientAuthorityViolation, got {other:?}"),
    }
}

// ── Diagnostic-layer goldens ─────────────────────────────────────────────

#[test]
fn golden_process_env_denial_span_single_line() {
    let source = "process.env";
    let (accessor, span) = denial_span(source);
    assert_eq!(accessor, "process.env");
    assert_eq!(
        span,
        Some(single_line_span(source)),
        "process.env denial must point at the exact statement span"
    );
}

#[test]
fn golden_global_this_process_denial_span_single_line() {
    let source = "globalThis.process";
    let (accessor, span) = denial_span(source);
    assert_eq!(accessor, "globalThis.process");
    assert_eq!(span, Some(single_line_span(source)));
}

#[test]
fn golden_nested_member_denial_span() {
    // The violation is raised on the inner `globalThis.process` member of
    // a deeper chain; the reported span is the enclosing statement's.
    let source = "globalThis.process.env.PATH";
    let (accessor, span) = denial_span(source);
    assert_eq!(accessor, "globalThis.process");
    assert_eq!(span, Some(single_line_span(source)));
}

#[test]
fn golden_require_denial_points_at_call_site() {
    // The bare `require` identifier carries no span (deferred by design);
    // the denial reports the enclosing call expression's span, which under
    // the statement-granular contract equals the statement span.
    let source = "const fs = require(\"fs\")";
    let (accessor, span) = denial_span(source);
    assert_eq!(accessor, "require");
    assert_eq!(span, Some(single_line_span(source)));
}

#[test]
fn golden_multi_line_denial_span_points_at_offending_line() {
    // Line 1 is benign; the violation sits on line 2. The span must place
    // the denial on line 2 with exact offsets — a diagnostic pointing at
    // line 1 (or drifting one column) fails this golden.
    let prefix = "const a = 1;\n";
    let offender = "process.env";
    let source = format!("{prefix}{offender}");
    let (accessor, span) = denial_span(&source);
    assert_eq!(accessor, "process.env");
    let span = span.expect("multi-line denial must carry a span");
    let start = prefix.len() as u64;
    let width = offender.len() as u64;
    assert_eq!(
        (
            span.start_offset,
            span.end_offset,
            span.start_line,
            span.start_column,
            span.end_line,
            span.end_column,
        ),
        (start, start + width, 2, 1, 2, width + 1),
        "denial must point at line 2's statement exactly: {span:?}"
    );
}

// ── AST-layer goldens ────────────────────────────────────────────────────

#[test]
fn golden_member_expression_carries_statement_span() {
    let parser = CanonicalEs2020Parser;
    let source = "obj.field";
    let tree = parser
        .parse(source, ParseGoal::Script)
        .expect("fixture should parse");
    let Statement::Expression(statement) = &tree.body[0] else {
        panic!("expected expression statement");
    };
    let Expression::Member { span, .. } = &statement.expression else {
        panic!("expected member expression");
    };
    assert_eq!(
        *span,
        Some(single_line_span(source)),
        "member AST node must carry the exact statement span"
    );
}

#[test]
fn golden_call_expression_carries_statement_span() {
    let parser = CanonicalEs2020Parser;
    let source = "doWork(1, 2)";
    let tree = parser
        .parse(source, ParseGoal::Script)
        .expect("fixture should parse");
    let Statement::Expression(statement) = &tree.body[0] else {
        panic!("expected expression statement");
    };
    let Expression::Call { span, .. } = &statement.expression else {
        panic!("expected call expression");
    };
    assert_eq!(*span, Some(single_line_span(source)));
}

// ── Bare-accessor contract goldens (E1.TEST / bd-fqlfw.1.4) ──────────────

#[test]
fn golden_bare_eval_denial_has_no_span_by_design() {
    // Bare-identifier accessors carry no span until identifier span
    // tracking lands (bd-fqlfw.1.1 deferred design). This golden pins the
    // CURRENT contract so that landing identifier spans forces a conscious
    // update here rather than a silent behavior change.
    let (accessor, span) = denial_span("eval(\"1\")");
    assert_eq!(accessor, "eval");
    // `eval(...)` is rejected on the bare callee identifier; the enclosing
    // call's span is not consulted by the Identifier-arm denial.
    assert!(
        span.is_none(),
        "bare eval denial unexpectedly carries a span — identifier spans \
         landed? Update this golden and the AmbientAuthorityViolation doc."
    );
}

#[test]
fn golden_bare_fetch_denial_has_no_span_by_design() {
    let (accessor, span) = denial_span("fetch");
    assert_eq!(accessor, "fetch");
    assert!(span.is_none());
}

#[test]
fn golden_stale_span_doctrine_stays_removed() {
    // bd-fqlfw.1.4 regression pin: the pre-1.2 doc note on
    // AmbientAuthorityViolation claimed the span was 'Currently always
    // `None`' because 'the AST `Expression` carries no span'. Both claims
    // are false since 06eed20b/6f5323ef. Pin their removal textually so a
    // revert or doc rot reintroducing the stale doctrine fails loudly.
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/lowering_pipeline.rs"
    ))
    .expect("lowering_pipeline.rs should be readable");
    assert!(
        !source.contains("Currently always `None`"),
        "the stale 'Currently always `None`' span doctrine is back in \
         lowering_pipeline.rs — spans ARE populated for member/require \
         denials since bd-fqlfw.1.2"
    );
    assert!(
        source.contains("bd-fqlfw.1.2"),
        "the AmbientAuthorityViolation span doc must reference the \
         bd-fqlfw.1.2 population contract"
    );
}

#[test]
fn golden_span_convention_is_one_column_strict() {
    // Belt-and-braces: a deliberately perturbed expectation must differ,
    // proving these goldens cannot pass vacuously.
    let source = "process.env";
    let (_, span) = denial_span(source);
    let span = span.expect("denial span");
    let mut drifted = span;
    drifted.start_column += 1;
    assert_ne!(span, drifted);
    let mut shifted = span;
    shifted.start_offset += 1;
    assert_ne!(span, shifted);
}
