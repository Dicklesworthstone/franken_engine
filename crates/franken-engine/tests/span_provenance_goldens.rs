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

/// True for any IR2 op that derives from a call expression. Method calls
/// lower to `CallMethod`, plain/desugared calls to `Call`, and
/// builtin/ambient calls to `HostCall` — all three are call-derived.
fn is_call_op(op: &frankenengine_engine::ir_contract::Ir2Op) -> bool {
    matches!(
        op.inner,
        Ir1Op::Call { .. } | Ir1Op::CallMethod { .. } | Ir1Op::HostCall { .. }
    )
}

/// True for any IR2 op that derives from a member access.
fn is_member_op(op: &frankenengine_engine::ir_contract::Ir2Op) -> bool {
    matches!(
        op.inner,
        Ir1Op::GetProperty { .. } | Ir1Op::SetProperty { .. }
    )
}

#[test]
fn golden_ir2_deeply_nested_member_chain_every_get_carries_span() {
    // a.b.c.d lowers to LoadBinding + three GetProperty ops. Under the
    // statement-granular contract each carries the whole-statement span;
    // sub-expression precision is the documented follow-up. The load-bearing
    // property is that EVERY member access in the chain carries a span — a
    // security diagnostic on `d` must not be span-less.
    let source = "a.b.c.d";
    let ir2 = lower_script_to_ir2(source);
    let gets: Vec<_> = ir2
        .ops
        .iter()
        .filter(|op| matches!(op.inner, Ir1Op::GetProperty { .. }))
        .collect();
    assert_eq!(gets.len(), 3, "a.b.c.d must emit one GetProperty per `.`");
    for get in &gets {
        assert_eq!(
            get.span,
            Some(single_line_span(source)),
            "every member access in the chain must carry the exact span"
        );
    }
}

#[test]
fn golden_ir2_optional_chain_desugar_is_fully_spanned() {
    // a?.b?.c desugars into a JumpIfNullish guard block. The whole block is
    // emitted inside the OptionalMember span range, so every op except the
    // statement-completion tail (Pop/Return) must carry the span — an
    // optional access must not produce span-less ops that a diagnostic would
    // then fail to locate.
    let source = "a?.b?.c";
    let ir2 = lower_script_to_ir2(source);
    let expected = Some(single_line_span(source));
    let mut member_ops = 0;
    for op in &ir2.ops {
        if matches!(op.inner, Ir1Op::Pop | Ir1Op::Return) && op.span.is_none() {
            continue; // statement-completion tail: documented None
        }
        assert_eq!(
            op.span, expected,
            "optional-chain op {:?} must carry the chain span",
            op.inner
        );
        if matches!(op.inner, Ir1Op::GetProperty { .. }) {
            member_ops += 1;
        }
    }
    assert_eq!(
        member_ops, 2,
        "a?.b?.c must emit two guarded GetProperty ops"
    );
}

#[test]
fn golden_ir2_method_call_carries_span() {
    // obj.m(1) lowers the member receiver + a CallMethod; both must carry the
    // statement span so a per-call authority diagnostic can point at it.
    let source = "obj.m(1)";
    let ir2 = lower_script_to_ir2(source);
    let expected = Some(single_line_span(source));
    let call = ir2
        .ops
        .iter()
        .find(|op| matches!(op.inner, Ir1Op::CallMethod { .. }))
        .expect("obj.m(1) must emit CallMethod");
    assert_eq!(call.span, expected, "method call must carry the call span");
    assert!(
        ir2.ops
            .iter()
            .any(|op| matches!(op.inner, Ir1Op::GetProperty { .. }) && op.span == expected),
        "the `.m` member access must carry the span too"
    );
}

#[test]
fn golden_ir2_jsx_desugar_createElement_call_carries_span() {
    // Native JSX has no core AST node: `Expression::Jsx` does not exist and
    // the lowering pipeline has no JSX arm (JSX is an FRX-track concern that
    // desugars to `createElement(...)` calls). This golden pins the shape JSX
    // actually reaches the core pipeline as — a `createElement` Call — and
    // proves it carries a span, so JSX-origin authority diagnostics are
    // span-accurate once FRX desugaring sets the call span. Native-JSX-syntax
    // span provenance is a tracked gap (no core node), NOT a silent pass; see
    // jsx_native_syntax_is_a_tracked_gap_not_silent below.
    let source = "createElement(\"div\", null)";
    let ir2 = lower_script_to_ir2(source);
    let call = ir2
        .ops
        .iter()
        .find(|op| matches!(op.inner, Ir1Op::Call { .. }))
        .expect("createElement(...) must emit a Call");
    assert_eq!(
        call.span,
        Some(single_line_span(source)),
        "the JSX-desugar createElement call must carry its exact span"
    );
}

#[test]
fn jsx_native_syntax_is_a_tracked_gap_not_silent() {
    // DW.STD: a missing capability must be enumerable, never a silent pass.
    // Native JSX syntax (`<div/>`) is deliberately absent from the core
    // parser/lowering — it routes through the FRX/react track. Pin that
    // absence textually so reintroducing a core JSX node forces a conscious
    // extension of the span-provenance goldens above rather than silently
    // shipping span-less JSX diagnostics.
    let lowering = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/lowering_pipeline.rs"
    ))
    .expect("lowering_pipeline.rs should be readable");
    assert!(
        !lowering.contains("Expression::Jsx"),
        "a core Expression::Jsx lowering arm appeared — extend the Ir2Op \
         span goldens to cover native JSX (currently FRX-desugar-only)"
    );
    let ast = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/ast.rs"))
        .expect("ast.rs should be readable");
    assert!(
        !ast.contains("Jsx {") && !ast.contains("JsxElement"),
        "a core JSX AST node appeared — extend native-JSX span coverage"
    );
}

#[test]
fn property_every_call_and_member_op_carries_inbounds_span() {
    // Property: across a corpus of expression-statement fixtures (no imports,
    // so GetProperty/Call ops originate only from member/call expressions),
    // EVERY call- and member-derived IR2 op carries an in-bounds Some(span),
    // and at least one op per fixture is spanned (anti-vacuity). A wrong or
    // missing span here is exactly the silent-diagnostic-corruption failure
    // class E5/E3/E8/E10.2 depend on this capstone to prevent.
    let corpus = [
        "obj.field",
        "obj.a.b.c",
        "obj.m(1, 2)",
        "doWork(1, 2)",
        "a?.b",
        "a?.b?.c",
        "fn()()",
        "outer.inner.method(x)",
        "createElement(\"div\", null, child)",
        "config.server.port",
    ];
    for source in corpus {
        let ir2 = lower_script_to_ir2(source);
        let len = source.len() as u64;
        let mut spanned = 0usize;
        let mut call_member_ops = 0usize;
        for op in &ir2.ops {
            if let Some(s) = op.span {
                spanned += 1;
                assert!(
                    s.start_offset <= s.end_offset && s.end_offset <= len,
                    "span out of byte bounds for {source:?}: {s:?}"
                );
                assert!(
                    s.start_line >= 1 && s.end_line >= s.start_line,
                    "span has invalid line range for {source:?}: {s:?}"
                );
            }
            if is_call_op(op) || is_member_op(op) {
                call_member_ops += 1;
                assert!(
                    op.span.is_some(),
                    "call/member op {:?} in {source:?} must carry a span \
                     (silent None would corrupt an authority diagnostic)",
                    op.inner
                );
            }
        }
        assert!(
            call_member_ops >= 1,
            "fixture {source:?} should contain at least one call/member op"
        );
        assert!(
            spanned >= 1,
            "fixture {source:?} must produce at least one spanned op (anti-vacuity)"
        );
    }
}

#[test]
fn tracked_gap_bare_identifier_statement_op_is_none_not_silent() {
    // DW.STD enumerated gap: a bare identifier reference carries no span
    // (bd-fqlfw.1.1 deferred identifier spans), so its LoadBinding op is
    // None when no spanned expression encloses it. Pin this so landing
    // identifier spans flips this assertion and forces a conscious goldens
    // update rather than silently changing diagnostic behavior.
    let ir2 = lower_script_to_ir2("freeVariable");
    let load = ir2
        .ops
        .iter()
        .find(|op| matches!(op.inner, Ir1Op::LoadBinding { .. }))
        .expect("bare identifier must emit a LoadBinding");
    assert!(
        load.span.is_none(),
        "a bare-identifier LoadBinding unexpectedly carries a span — \
         identifier spans landed? Update this tracked-gap pin and the \
         Ir2Op span goldens."
    );
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
