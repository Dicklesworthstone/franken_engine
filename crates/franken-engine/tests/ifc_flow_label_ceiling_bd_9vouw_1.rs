//! bd-9vouw.1: the static IFC flow simulation must not refuse benign programs
//! that contain no sensitive source, and must keep refusing programs that do.
//!
//! Regression evidence (2026-09-22 reality check): at HEAD a3ff9a112
//! `console.log(Math.max(1, 2))`, `[3,1,2].sort()`, closure calls, and
//! recursion were refused at lowering with `TopSecret -> Internal`, while the
//! 2026-08-16 build ran them. The fix bounds fail-high labels by the program's
//! label ceiling (`ir2_flow_label_ceiling` in lowering_pipeline.rs).
//!
//! Expected outputs below are Node v22.2.0's for the same source.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{
    LoweringContext, LoweringPipelineError, lower_ir0_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};
use frankenengine_extension_host::host_io::HostIoExceptionProvenance;

fn lower(name: &str, source: &str) -> Result<(), LoweringPipelineError> {
    lower_with_goal(name, source, ParseGoal::Script)
}

fn lower_with_goal(name: &str, source: &str, goal: ParseGoal) -> Result<(), LoweringPipelineError> {
    let tree = CanonicalEs2020Parser
        .parse(source, goal)
        .unwrap_or_else(|error| panic!("{name}: parse failed: {error}"));
    let ir0 = Ir0Module::from_syntax_tree(tree, format!("{name}.js"));
    let context = LoweringContext::new(
        "trace-bd-9vouw-1",
        "decision-bd-9vouw-1",
        "policy-bd-9vouw-1",
    );
    lower_ir0_to_ir3(&ir0, &context).map(|_| ())
}

fn eval_console(name: &str, source: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(source)
        .unwrap_or_else(|error| panic!("{name}: eval failed for {source:?}: {error}"));
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_denied(name: &str, source: &str, expected_source: Label) {
    match lower(name, source) {
        Err(LoweringPipelineError::UnauthorizedFlow {
            source_label,
            sink_clearance,
            ..
        }) => {
            assert_eq!(source_label, expected_source, "{name}: source label");
            assert_eq!(sink_clearance, Label::Internal, "{name}: sink clearance");
        }
        other => panic!(
            "{name}: expected UnauthorizedFlow {expected_source:?} -> Internal, got {other:?}"
        ),
    }
}

/// Benign programs: no literal, hostcall, or module load introduces anything
/// above Internal, so an unsummarized call cannot produce TopSecret data.
const BENIGN: &[(&str, &str, &str)] = &[
    (
        "builtin_method_on_global",
        "console.log(Math.max(1, 2));",
        "2",
    ),
    (
        "array_sort_join",
        "console.log([3,1,2].sort().join(','));",
        "1,2,3",
    ),
    (
        "closure_capture",
        "function mk(){ let c = 0; return () => ++c } const h = mk(); h(); console.log(h());",
        "2",
    ),
    (
        "recursion",
        "function fib(n){ return n < 2 ? n : fib(n - 1) + fib(n - 2) } console.log(fib(15));",
        "610",
    ),
    (
        "method_on_object_literal",
        "const o = { f(){ return 40 } }; console.log(o.f() + 2);",
        "42",
    ),
    (
        "higher_order_callbacks",
        "const xs = [1, 2, 3].map((x) => x * 2).filter((x) => x > 2); console.log(xs.join('|'));",
        "4|6",
    ),
    (
        "caught_user_error_message",
        "try { throw new Error('boom') } catch (e) { console.log(e.message) }",
        "boom",
    ),
    // Nested bodies are checked in isolation; their parameters and captures
    // start at the program bound, which is Internal here.
    (
        "parameter_to_nested_console",
        "function show(x){ console.log('v:' + x) } show(5);",
        "v:5",
    ),
    (
        "captured_binding_in_nested_console",
        "let n = 1; [1, 2].forEach((x) => { n += x }); function report(){ console.log(n) } report();",
        "4",
    ),
];

#[test]
fn benign_programs_lower_and_match_node_output_bd_9vouw_1() {
    for (name, source, expected) in BENIGN {
        if let Err(error) = lower(name, source) {
            panic!("{name}: benign program refused at lowering: {error}");
        }
        assert_eq!(
            eval_console(name, source),
            *expected,
            "{name}: console output"
        );
    }
}

#[test]
fn secret_literal_still_cannot_reach_console_through_unsummarized_calls_bd_9vouw_1() {
    // The ceiling is Secret here (sensitive-keyword literal), so every
    // fail-high result is bounded at Secret, which still cannot flow to the
    // Internal console sink. A fix that simply dropped fail-high labels would
    // let these through.
    assert_denied(
        "secret_through_returned_closure",
        "function mk(){ return (x) => x } const f = mk(); console.log(f('secret-token'));",
        Label::Secret,
    );
    assert_denied(
        "secret_through_builtin_on_global",
        "const s = 'secret-token'; console.log(Math.max(s.length, 1));",
        Label::Secret,
    );
    assert_denied(
        "secret_through_recursion",
        "function echo(n, v){ return n === 0 ? v : echo(n - 1, v) } console.log(echo(3, 'api_key=1'));",
        Label::Secret,
    );
    // Direct flows are unaffected by the ceiling.
    assert_denied(
        "direct_secret_literal",
        "console.log('secret-token');",
        Label::Secret,
    );
}

#[test]
fn secret_entering_a_nested_body_cannot_reach_its_sinks_bd_9vouw_1() {
    // Function bodies are flow-checked in isolation. A value that enters a
    // body as an argument or captured binding starts at the whole-program
    // bound, so a secret-holding program cannot print it from inside a callee.
    // The first three shapes leaked before bd-9vouw.1 too (unknown bindings
    // defaulted to Internal); the method/builtin shapes leaked only after the
    // first ceiling fix (b32c1e573) clamped nested bodies to their own ops.
    for (name, source) in [
        (
            "captured_secret_in_declared_function",
            "const t = 'secret-token'; function g(){ console.log(t) } g();",
        ),
        (
            "captured_secret_through_local_copy",
            "const t = 'secret-token'; const g = () => { const u = t; console.log(u) }; g();",
        ),
        (
            "secret_parameter",
            "function g(t){ console.log(t) } g('secret-token');",
        ),
        (
            "method_on_captured_secret",
            "const t = 'secret-token'; function g(){ console.log(t.toUpperCase()) } g();",
        ),
        (
            "builtin_over_captured_secret",
            "const t = 'secret-token'; function g(){ console.log(String(t)) } g();",
        ),
        (
            "method_on_secret_parameter",
            "function g(x){ console.log(x.slice(0)) } g('secret-token');",
        ),
        (
            "secret_returned_by_inner_closure",
            "function g(x){ const h = () => x; console.log(h()) } g('secret-token');",
        ),
        (
            "captured_secret_read_before_local_reassignment",
            "let t = 'secret-token'; function g(){ console.log(t); t = 'x' } g();",
        ),
    ] {
        assert_denied(name, source, Label::Secret);
    }
}

#[test]
fn callbacks_handed_to_engine_methods_cannot_launder_secrets_bd_zk58q() {
    // A method on a primitive or engine-closed receiver used to be treated as
    // a finite operation over its operand labels even when an argument was a
    // guest callback, so a secret thrown (or returned) by the callback left
    // the call labeled Internal. Such calls now fail high, bounded by the
    // program ceiling.
    assert_denied(
        "secret_thrown_from_buffer_map_callback",
        "try { Buffer.from('x').map(v => { throw 'secret-token' }) } catch (e) { console.log(e) }",
        Label::Secret,
    );
    assert_denied(
        "secret_returned_through_replace_callback",
        "console.log('abc'.replace(/a/, () => 'secret-token'));",
        Label::Secret,
    );
}

#[test]
fn benign_callbacks_handed_to_engine_methods_still_lower_bd_zk58q() {
    // Without a sensitive source the program ceiling is Internal, so failing
    // these calls high costs nothing.
    for (name, source) in [
        (
            "buffer_map_callback",
            "console.log(Buffer.from('ab').map(x => x + 1).toString());",
        ),
        (
            "replace_callback",
            "console.log('abc'.replace(/a/, () => 'z'));",
        ),
        (
            "caught_error_from_buffer_map_callback",
            "try { Buffer.from('x').map(v => { throw new Error('boom') }) } catch (e) { console.log(e.message) }",
        ),
    ] {
        if let Err(error) = lower(name, source) {
            panic!("{name}: benign callback program refused at lowering: {error}");
        }
    }
}

#[test]
fn nested_bodies_use_the_authenticated_host_io_provenance_bd_9vouw_1() {
    // A network callback reading a captured server handle. With a
    // provider-internal exception contract nothing in the program exceeds
    // Internal; an unknown provider may put host state into exceptions, so
    // the same program keeps failing high. Nested bodies used to be annotated
    // as Unknown regardless of the installed provider.
    let source = "const http = require('http'); \
        const srv = http.createServer((req, res) => { res.end('ok') }); \
        srv.listen(0, '127.0.0.1', () => { \
          http.get({ host: '127.0.0.1', port: srv.address().port, path: '/' }, \
            (res) => { console.log(res.statusCode) }) });";
    let lower_under = |provenance| {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .expect("parse");
        let ir0 = Ir0Module::from_syntax_tree(tree, "nested_http_callback.js");
        let context = LoweringContext::new(
            "trace-bd-9vouw-1",
            "decision-bd-9vouw-1",
            "policy-bd-9vouw-1",
        )
        .with_host_io_exception_provenance(provenance);
        lower_ir0_to_ir3(&ir0, &context).map(|_| ())
    };

    if let Err(error) = lower_under(HostIoExceptionProvenance::ProviderInternal) {
        panic!("provider-internal provenance must admit the callback: {error}");
    }
    match lower_under(HostIoExceptionProvenance::Unknown) {
        Err(LoweringPipelineError::UnauthorizedFlow {
            source_label,
            sink_clearance,
            ..
        }) => {
            assert_eq!(source_label, Label::TopSecret);
            assert_eq!(sink_clearance, Label::Internal);
        }
        other => panic!("unknown provenance must keep failing high, got {other:?}"),
    }
}

#[test]
fn opaque_module_code_keeps_fail_high_top_secret_bd_9vouw_1() {
    // A loaded module runs code this IR does not contain, so the ceiling
    // stays TopSecret and unsummarized call results keep failing high.
    let name = "unknown_module_callee";
    match lower_with_goal(
        name,
        "import m from './helper.js'; console.log(m.compute());",
        ParseGoal::Module,
    ) {
        Err(LoweringPipelineError::UnauthorizedFlow {
            source_label,
            sink_clearance,
            ..
        }) => {
            assert_eq!(source_label, Label::TopSecret, "{name}: source label");
            assert_eq!(sink_clearance, Label::Internal, "{name}: sink clearance");
        }
        other => panic!("{name}: expected UnauthorizedFlow TopSecret -> Internal, got {other:?}"),
    }
}
