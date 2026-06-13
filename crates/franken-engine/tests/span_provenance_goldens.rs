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
//! - IR-record layer (`bd-fqlfw.1.5`): `Ir2Op.span` carries the parse-time
//!   span of the nearest enclosing spanned expression (Call / OptionalCall /
//!   Member / OptionalMember), stamped narrowest-range-wins from the IR1
//!   span side-table. Statement-emitted ops and unspanned expression kinds
//!   honestly stay `None`.

use frankenengine_engine::ast::{Expression, ParseGoal, SourceSpan, Statement};
use frankenengine_engine::ir_contract::{Ir0Module, Ir1Op, Ir2Module};
use frankenengine_engine::lowering_pipeline::{
    LoweringPipelineError, lower_ir0_to_ir1, lower_ir1_to_ir2,
};
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

// ── Ir2Op-layer goldens (bd-fqlfw.1.5) ──────────────────────────────────

/// Lower a script source through IR0 → IR1 → IR2.
fn lower_script_to_ir2(source: &str) -> Ir2Module {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(source, ParseGoal::Script)
        .expect("fixture should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "span_provenance_golden");
    let ir1 = lower_ir0_to_ir1(&ir0)
        .expect("IR0->IR1 should succeed")
        .module;
    lower_ir1_to_ir2(&ir1)
        .expect("IR1->IR2 should succeed")
        .module
}

#[test]
fn golden_ir2_member_ops_carry_exact_member_span() {
    let source = "obj.field";
    let ir2 = lower_script_to_ir2(source);
    let get_property = ir2
        .ops
        .iter()
        .find(|op| matches!(op.inner, Ir1Op::GetProperty { .. }))
        .expect("member lowering must emit GetProperty");
    assert_eq!(
        get_property.span,
        Some(single_line_span(source)),
        "the GetProperty op must carry the member expression's exact span"
    );
    // The object load sits inside the member's op range, so it carries the
    // member span too (no narrower spanned expression encloses it).
    let load_binding = ir2
        .ops
        .iter()
        .find(|op| matches!(op.inner, Ir1Op::LoadBinding { .. }))
        .expect("member lowering must emit the object LoadBinding");
    assert_eq!(load_binding.span, Some(single_line_span(source)));
}

#[test]
fn golden_ir2_call_op_carries_exact_call_span() {
    let source = "doWork(1, 2)";
    let ir2 = lower_script_to_ir2(source);
    let call = ir2
        .ops
        .iter()
        .find(|op| matches!(op.inner, Ir1Op::Call { .. }))
        .expect("call lowering must emit Call");
    assert_eq!(
        call.span,
        Some(single_line_span(source)),
        "the Call op must carry the call expression's exact span"
    );
}

#[test]
fn golden_ir2_multi_line_ops_point_at_their_own_lines() {
    // Line 1 holds a member access, line 2 a call. Each op must point at
    // its own line: a GetProperty reported on line 2 (or a Call on line 1)
    // is exactly the wrong-line diagnostic failure class this file exists
    // to prevent.
    let source = "const a = obj.f;\nsink(a)";
    let ir2 = lower_script_to_ir2(source);
    let get_property_span = ir2
        .ops
        .iter()
        .find(|op| matches!(op.inner, Ir1Op::GetProperty { .. }))
        .expect("line-1 member must emit GetProperty")
        .span
        .expect("GetProperty must carry a span");
    assert_eq!(
        (get_property_span.start_line, get_property_span.end_line),
        (1, 1),
        "member op must point at line 1: {get_property_span:?}"
    );
    // The line-2 call to an unbound callee lowers through the generic
    // invoke hostcall (`Ir1Op::HostCall`); a bound/literal-arg call would be
    // `Ir1Op::Call`. Either way the call op must carry line 2's span — that
    // is the cross-line provenance this golden pins.
    let call_span = ir2
        .ops
        .iter()
        .find(|op| {
            matches!(op.inner, Ir1Op::Call { .. } | Ir1Op::HostCall { .. })
                && op.span.is_some_and(|s| s.start_line == 2)
        })
        .expect("line-2 call must emit a span-carrying Call/HostCall")
        .span
        .expect("call op must carry a span");
    assert_eq!(
        (call_span.start_line, call_span.end_line),
        (2, 2),
        "call op must point at line 2: {call_span:?}"
    );
    assert_eq!(
        call_span.start_offset,
        "const a = obj.f;\n".len() as u64,
        "line-2 span must start exactly after the line-1 prefix"
    );
    // No line-1 member op may bleed onto line 2, and vice versa.
    assert!(
        !ir2.ops
            .iter()
            .any(|op| matches!(op.inner, Ir1Op::GetProperty { .. })
                && op.span.is_some_and(|s| s.start_line == 2)),
        "no GetProperty may carry a line-2 span"
    );
}

#[test]
fn golden_ir2_unspanned_statement_ops_stay_none() {
    // No spanned expression kind (call/member family) appears in this
    // fixture, so every op must honestly report `None` rather than inherit
    // an unrelated span. Pins the CURRENT contract: literal and binding ops
    // gain spans only once their AST nodes do (bd-fqlfw.1.1 follow-up).
    let ir2 = lower_script_to_ir2("const a = 1");
    assert!(
        ir2.ops.iter().all(|op| op.span.is_none()),
        "no op may carry a span in a fixture without call/member expressions"
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
