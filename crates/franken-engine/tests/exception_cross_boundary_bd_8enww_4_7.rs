//! bd-8enww.4.7 — explicit `throw` crossing the generated-function boundary.
//!
//! Track-D (YTBG-D) G-3 exception semantics. An *explicit* `throw` inside a
//! `Function`-constructor-generated function must be catchable by an enclosing
//! `try`/`catch` in the CALLER, carrying the ORIGINAL thrown value — symmetric
//! with a native runtime error (e.g. `null.x` → `TypeError`), which was already
//! catchable across the boundary (bd-8enww.4.3 / 3.5).
//!
//! Background (root cause): a generated function runs in a separate re-entrant
//! `run_loop` whose catch-frame stack is cleared, so the caller's `try`/`catch`
//! is invisible to the inner loop. On an uncaught explicit `throw` the inner run
//! returns `UncaughtException` while preserving the thrown value in
//! `pending_exception`; the dispatch arm that invoked the generated function now
//! re-raises that preserved value into the caller's catch frames
//! (`route_isolated_explicit_throw`), exactly like the `Throw` instruction and
//! the `for…of` iterator re-raise.
//!
//! These tests drive the public `HybridRouter::eval` surface (the parent-bead
//! acceptance path) and assert observable values, not interpreter internals.

use frankenengine_engine::{EvalOutcome, HybridRouter};

/// Evaluate and require the program to COMPLETE (the throw was caught somewhere),
/// returning the formatted completion value.
fn caught(src: &str) -> String {
    let outcome: EvalOutcome = HybridRouter::default()
        .eval(src)
        .unwrap_or_else(|err| panic!("expected `{src}` to complete, got error: {}", err.message));
    outcome.value
}

/// Evaluate and require the program to FAIL CLOSED (no handler), returning the
/// surfaced diagnostic message.
fn uncaught(src: &str) -> String {
    HybridRouter::default()
        .eval(src)
        .map(|ok| format!("UNEXPECTED OK: {}", ok.value))
        .unwrap_err()
        .message
}

// --- primitive thrown values travel verbatim --------------------------------

#[test]
fn explicit_throw_string_is_caught_by_caller() {
    assert_eq!(
        caught(
            r#"var c = "uncaught"; try { new Function("throw 'boom';")(); } catch (e) { c = e; } c;"#
        ),
        "boom",
    );
}

#[test]
fn explicit_throw_number_is_caught_by_caller() {
    assert_eq!(
        caught(r#"var c = -1; try { new Function("throw 42;")(); } catch (e) { c = e; } c;"#),
        "42",
    );
}

#[test]
fn explicit_throw_boolean_is_caught_by_caller() {
    assert_eq!(
        caught(r#"var c = "x"; try { new Function("throw false;")(); } catch (e) { c = e; } c;"#),
        "false",
    );
}

#[test]
fn caught_thrown_primitive_preserves_its_type() {
    // The catch binding holds the original value, so `typeof e` is `number`,
    // not `string` (it was never coerced through the diagnostic surface).
    assert_eq!(
        caught(
            r#"var t = "?"; try { new Function("throw 7;")(); } catch (e) { t = typeof e; } t;"#
        ),
        "number",
    );
}

// --- thrown Error objects survive the boundary (shared-heap survival) --------

#[test]
fn explicit_throw_error_object_preserves_message() {
    assert_eq!(
        caught(
            r#"var c = "no"; try { new Function("throw new Error('bad');")(); } catch (e) { c = e.message; } c;"#
        ),
        "bad",
    );
}

#[test]
fn explicit_throw_typeerror_object_preserves_name() {
    assert_eq!(
        caught(
            r#"var c = "no"; try { new Function("throw new TypeError('nope');")(); } catch (e) { c = e.name; } c;"#
        ),
        "TypeError",
    );
}

// --- finally interaction: the re-thrown exception still crosses the boundary -

#[test]
fn explicit_throw_through_generated_finally_is_caught_by_caller() {
    // The generated body re-raises the exception after its own `finally` runs;
    // the caller still catches it.
    assert_eq!(
        caught(
            r#"var c = "uncaught"; try { new Function("try { throw 'p'; } finally { 1; }")(); } catch (e) { c = e; } c;"#
        ),
        "p",
    );
}

// --- symmetry: native runtime errors remained catchable (regression guard) ---

#[test]
fn native_error_crossing_boundary_still_catchable() {
    assert_eq!(
        caught(
            r#"var c = "no"; try { new Function("var o = null; return o.x;")(); } catch (e) { c = e.name; } c;"#
        ),
        "TypeError",
    );
}

// --- in-body catch still handles the throw without crossing (regression) -----

#[test]
fn explicit_throw_caught_inside_generated_body_does_not_cross() {
    assert_eq!(
        caught(r#"new Function("try { throw 'x'; } catch (e) { return 'caught:' + e; }")();"#),
        "caught:x",
    );
}

// --- fail-closed: an uncaught explicit throw still surfaces deterministically -

#[test]
fn uncaught_explicit_throw_still_surfaces() {
    let m1 = uncaught(r#"new Function("throw 'boom';")();"#);
    assert!(
        m1.contains("uncaught exception") && m1.contains("boom"),
        "uncaught throw must surface carrying the value: {m1}",
    );
    // Deterministic: identical source ⇒ identical surfaced message.
    let m2 = uncaught(r#"new Function("throw 'boom';")();"#);
    assert_eq!(m1, m2);
}

#[test]
fn caller_catch_only_fires_on_throw_not_on_normal_return() {
    // A generated function that returns normally is unaffected by the routing:
    // the caller's catch binding is never touched.
    assert_eq!(
        caught(
            r#"var c = "untouched"; try { c = new Function("return 9;")(); } catch (e) { c = "caught"; } c;"#
        ),
        "9",
    );
}

// --- the CallMethod dispatch arm routes the same way as the plain Call arm ---

#[test]
fn generated_function_called_as_method_throw_is_caught_by_caller() {
    // A generated function invoked as a *method* (`obj.f()`) dispatches through
    // the `CallMethod` arm rather than the plain `Call` arm. The same routing
    // applies, so the explicit throw is caught by the caller and binds the
    // original value.
    assert_eq!(
        caught(
            r#"var o = {}; o.f = new Function("throw 'm';"); var c = "no"; try { o.f(); } catch (e) { c = e; } c;"#
        ),
        "m",
    );
}

// --- the caller can re-throw the crossed exception to a further-out handler ---

#[test]
fn crossed_exception_can_be_rethrown_to_outer_handler() {
    assert_eq!(
        caught(
            r#"var c = "no";
               try {
                 try { new Function("throw 'inner';")(); }
                 catch (e) { throw e + ':again'; }
               } catch (e2) { c = e2; }
               c;"#
        ),
        "inner:again",
    );
}

#[test]
fn property_getter_throw_reaches_enclosing_catch() {
    assert_eq!(
        caught(
            r#"let answer = 0; const source = { get x() { throw 17; } }; try { source.x; } catch (e) { answer = e; } answer;"#
        ),
        "17",
    );
}

#[test]
fn property_getter_throw_preserves_object_identity() {
    assert_eq!(
        caught(
            r#"const token = { tag: 1 }; const source = { get x() { throw token; } }; let same = false; try { source.x; } catch (e) { same = e === token; } same;"#
        ),
        "true",
    );
}

#[test]
fn property_setter_throw_reaches_enclosing_catch() {
    assert_eq!(
        caught(
            r#"let answer = 0; const target = { set x(v) { throw v; } }; try { target.x = 23; } catch (e) { answer = e; } answer;"#
        ),
        "23",
    );
}

#[test]
fn proxy_get_trap_throw_reaches_enclosing_catch() {
    assert_eq!(
        caught(
            r#"const p = new Proxy({}, { get(target, key) { throw key; } }); let answer = ''; try { p.missing; } catch (e) { answer = e; } answer;"#
        ),
        "missing",
    );
}

#[test]
fn proxy_set_trap_throw_reaches_enclosing_catch() {
    assert_eq!(
        caught(
            r#"const p = new Proxy({}, { set(target, key, value) { throw value; } }); let answer = 0; try { p.x = 29; } catch (e) { answer = e; } answer;"#
        ),
        "29",
    );
}

#[test]
fn getter_throw_runs_each_finally_once() {
    assert_eq!(
        caught(
            r#"let trace = ''; const source = { get x() { try { throw 3; } finally { trace += 'g'; } } }; try { try { source.x; } finally { trace += 'i'; } } catch (e) { trace += e; } finally { trace += 'o'; } trace;"#
        ),
        "gi3o",
    );
}

#[test]
fn getter_throw_from_finally_replaces_pending_return() {
    assert_eq!(
        caught(
            r#"const source = { get x() { throw 31; } }; function f() { try { return 1; } finally { source.x; } } let answer = 0; try { answer = f(); } catch (e) { answer = e; } answer;"#
        ),
        "31",
    );
}

#[test]
fn caught_getter_throw_does_not_resurrect_after_finally() {
    assert_eq!(
        caught(
            r#"let trace = ''; const source = { get x() { throw 5; } }; try { source.x; } catch (e) { trace += e; } finally { trace += 'f'; } trace += 'n'; trace;"#
        ),
        "5fn",
    );
}

#[test]
fn getter_throw_can_be_rethrown_through_an_outer_handler() {
    assert_eq!(
        caught(
            r#"const source = { get x() { throw 7; } }; let answer = 0; try { try { source.x; } catch (e) { throw e + 1; } } catch (e) { answer = e; } answer;"#
        ),
        "8",
    );
}

#[test]
fn object_assignment_commits_earlier_writes_before_getter_throw() {
    assert_eq!(
        caught(
            r#"let a = 0, b = 0, trace = ''; try { ({ a, b } = { a: 3, get b() { throw 9; } }); } catch (e) { trace += e; } a + ':' + b + ':' + trace;"#
        ),
        "3:0:9",
    );
}

#[test]
fn getter_internal_catch_does_not_trigger_caller_catch() {
    assert_eq!(
        caught(
            r#"const source = { get x() { try { throw 11; } catch (e) { return e + 1; } } }; let answer = 0; try { answer = source.x; } catch (e) { answer = 99; } answer;"#
        ),
        "12",
    );
}

#[test]
fn getter_without_handler_remains_an_uncaught_exception() {
    let message = uncaught(r#"const source = { get x() { throw 37; } }; source.x;"#);
    assert!(
        message.contains("uncaught exception") && message.contains("37"),
        "{message}"
    );
}

fn protected_throw_flow(
    sink: Option<&str>,
    rethrow: bool,
) -> frankenengine_engine::ir_contract::Ir2Module {
    use frankenengine_engine::hash_tiers::ContentHash;
    use frankenengine_engine::ir_contract::{Ir1Literal, Ir1Module, Ir1Op};
    use frankenengine_engine::lowering_pipeline::lower_ir1_to_ir2;
    let mut ir1 = Ir1Module::new(
        ContentHash::compute(b"protected-throw-flow"),
        "protected-throw.js",
    );
    ir1.ops.extend([
        Ir1Op::BeginTry {
            catch_label: 1,
            finally_label: None,
        },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String("secret-sensitive-value".into()),
        },
        Ir1Op::Throw,
        Ir1Op::EndTry,
        Ir1Op::Jump { label_id: 2 },
        Ir1Op::Label { id: 1 },
    ]);
    match sink {
        Some(capability) => {
            ir1.ops.push(Ir1Op::HostCall {
                capability: capability.into(),
                arg_count: 1,
            });
            ir1.ops.push(Ir1Op::Pop);
        }
        None => ir1
            .ops
            .push(if rethrow { Ir1Op::Throw } else { Ir1Op::Pop }),
    }
    ir1.ops.extend([
        Ir1Op::Label { id: 2 },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        },
        Ir1Op::Return,
    ]);
    lower_ir1_to_ir2(&ir1)
        .expect("valid protected throw lowers")
        .module
}

#[test]
fn locally_caught_throw_keeps_its_label_without_becoming_egress() {
    use frankenengine_engine::ifc_artifacts::Label;
    let ir2 = protected_throw_flow(None, false);
    let flow = ir2.ops[2].flow.as_ref().expect("throw provenance");
    assert_eq!(flow.data_label, Label::Secret);
    assert_eq!(flow.sink_clearance, Label::Secret);
    assert!(!flow.declassification_required);
    assert_eq!(
        caught("try { throw 'secret-sensitive-value'; } catch (e) {} 7;"),
        "7"
    );
}

#[test]
fn caught_sensitive_throw_still_cannot_flow_to_real_sinks() {
    use frankenengine_engine::ifc_artifacts::Label;
    for capability in ["console:log", "net.http.request"] {
        let ir2 = protected_throw_flow(Some(capability), false);
        let flow = ir2.ops[6].flow.as_ref().expect("real sink provenance");
        assert_eq!(flow.data_label, Label::Secret);
        assert!(flow.declassification_required);
    }
    let diagnostic =
        uncaught("try { throw 'secret-sensitive-value'; } catch (e) { console.log(e); }");
    assert!(diagnostic.contains("unauthorized flow"), "{diagnostic}");
}

#[test]
fn rethrow_leaving_local_handlers_retains_external_clearance() {
    use frankenengine_engine::ifc_artifacts::Label;
    let ir2 = protected_throw_flow(None, true);
    let flow = ir2.ops[6]
        .flow
        .as_ref()
        .expect("uncaught rethrow provenance");
    assert_eq!(flow.data_label, Label::Secret);
    assert_eq!(flow.sink_clearance, Label::Internal);
    assert!(flow.declassification_required);
    let diagnostic = uncaught("try { throw 'secret-sensitive-value'; } catch (e) { throw e; }");
    assert!(diagnostic.contains("unauthorized flow"), "{diagnostic}");
}

#[test]
fn finally_only_region_does_not_authorize_sensitive_throw_egress() {
    use frankenengine_engine::hash_tiers::ContentHash;
    use frankenengine_engine::ifc_artifacts::Label;
    use frankenengine_engine::ir_contract::{Ir1Literal, Ir1Module, Ir1Op};
    use frankenengine_engine::lowering_pipeline::lower_ir1_to_ir2;
    let mut ir1 = Ir1Module::new(
        ContentHash::compute(b"finally-only-flow"),
        "finally-only.js",
    );
    ir1.ops.extend([
        Ir1Op::BeginTry {
            catch_label: 1,
            finally_label: Some(1),
        },
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String("secret-sensitive-value".into()),
        },
        Ir1Op::Throw,
        Ir1Op::EndTry,
        Ir1Op::Label { id: 1 },
        Ir1Op::EnterFinally,
        Ir1Op::EndFinally,
        Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        },
        Ir1Op::Return,
    ]);
    let ir2 = lower_ir1_to_ir2(&ir1)
        .expect("finally-only flow lowers")
        .module;
    let flow = ir2.ops[2].flow.as_ref().expect("throw provenance");
    assert_eq!(flow.data_label, Label::Secret);
    assert_eq!(flow.sink_clearance, Label::Internal);
    assert!(flow.declassification_required);
    let diagnostic = uncaught("try { throw 'secret-sensitive-value'; } finally { 0; }");
    assert!(diagnostic.contains("unauthorized flow"), "{diagnostic}");
}
