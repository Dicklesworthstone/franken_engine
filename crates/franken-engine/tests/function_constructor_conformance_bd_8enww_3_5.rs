#![forbid(unsafe_code)]

//! bd-8enww.3.5 (YTBG-C5): Function-constructor conformance and adversarial suite.
//!
//! Tracks C1–C4 built the `Function` constructor end-to-end: parse/compile the
//! parameter/body strings (`3.2`), make the artifact callable in global scope
//! (`3.3`), and add provenance / budgets / security accounting (`3.4`). This is
//! the **quality gate** for closing G-2 (the bead note: *do not close on `x*2`
//! alone — BotGuard needs generated code to interact with other runtime
//! features*).
//!
//! It exercises generated code interacting with the rest of the runtime through
//! the **public** `HybridRouter::eval` path (the parent-bead AC surface) and the
//! shared Track-A JS conformance runner (`_support::js_conformance`), which
//! produces structured logs carrying the eval source hash, expected/actual, and
//! — for failures — the error class/code/message that distinguishes a
//! **parse-time** failure from a **runtime thrown** error. Direct unit tests on
//! the native engine inspect the generated-code audit trail (the `genfn:` source
//! identity and the instruction budget the body consumed).
//!
//! Coverage map (bead AC + listed items):
//!   * AC#1 — the exact G-2 vector is included and green.
//!   * AC#2 — unit tests cover parameter parsing, body parsing, invocation, source provenance, global scope, and budget failure.
//!   * AC#3 — conformance/e2e logs are detailed enough to localize a generated-code failure (parse-time vs runtime is observable).
//!   * AC#4 — at least one generated function uses typed arrays (Track B, now landed: ArrayBuffer / Uint8Array / Int32Array / DataView).
//!   * plus: syntax errors, multiple parameters, global-vs-local scope, nested generated functions, and adversarial budget exhaustion.
//!
//! Catchability (the design note "once try/catch lands, add catchability
//! expectations for generated-code errors"): try/catch/finally executes **inside**
//! generated bodies, and a **native** runtime error raised inside a generated
//! function is catchable by an enclosing `try`/`catch` in the caller. The one
//! known boundary — an *explicit* `throw` crossing the generated→caller frame
//! boundary surfaces at the eval boundary rather than being caught by the
//! caller's handler — is asserted as current fail-closed behavior and tracked by
//! bd-8enww.4.7 (see `explicit_throw_*` below); the thrown value is never
//! silently swallowed.

mod _support;

use _support::js_conformance::{
    JsConformanceReport, JsConformanceVector, assert_js_conformance_vectors,
};
use frankenengine_engine::baseline_interpreter::{GeneratedCodeAuditEntry, GeneratedCodeEventKind};
use frankenengine_engine::{EvalOutcome, HybridRouter, JsEngine, QuickJsInspiredNativeEngine};

const CATEGORY: &str = "function_constructor";
const CATEGORY_TYPED_ARRAY: &str = "function_constructor_typed_array";
const CATEGORY_ADVERSARIAL: &str = "function_constructor_adversarial";

// --- helpers -----------------------------------------------------------------

/// Evaluate through the direct native engine, returning the full outcome so the
/// generated-code audit trail is observable (the audit is only carried on the
/// native-engine outcome, matching `function_constructor_provenance_bd_8enww_3_4`).
fn eval_outcome(source: &str) -> EvalOutcome {
    let mut engine = QuickJsInspiredNativeEngine;
    engine
        .eval(source)
        .expect("source should evaluate successfully")
}

fn eval_value(source: &str) -> String {
    eval_outcome(source).value
}

fn eval_value_hybrid(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .expect("source should evaluate successfully")
        .value
}

fn audit(source: &str) -> Vec<GeneratedCodeAuditEntry> {
    eval_outcome(source).generated_code_audit
}

fn render_report(report: &JsConformanceReport) {
    // Detailed, machine-readable log so a CI failure localizes the exact vector,
    // its source hash, and (for a failure) whether it diverged at parse or run.
    match serde_json::to_string_pretty(report) {
        Ok(json) => eprintln!("[bd-8enww.3.5] js conformance report:\n{json}"),
        Err(err) => eprintln!("[bd-8enww.3.5] failed to render report: {err}"),
    }
}

// --- conformance vector set --------------------------------------------------

/// The success/behavior conformance vectors run through `HybridRouter::eval`.
/// Each `value`/`caught_value` vector pins observable output against a frozen
/// expectation; the typed-array vectors additionally log memory size.
fn behavior_vectors() -> Vec<JsConformanceVector> {
    vec![
        // -- AC#1: the exact BotGuard G-2 vector -----------------------------
        JsConformanceVector::value(
            "fc-g2-canonical",
            CATEGORY,
            r#"var f = new Function("x", "return x * 2;"); f(21);"#,
            "42",
        ),
        JsConformanceVector::value(
            "fc-g2-direct-call",
            CATEGORY,
            r#"new Function("x", "return x * 2;")(21);"#,
            "42",
        ),
        // -- multiple parameters (both spellings) ----------------------------
        JsConformanceVector::value(
            "fc-multi-param-separate-strings",
            CATEGORY,
            r#"new Function("a", "b", "c", "return a + b + c;")(1, 2, 3);"#,
            "6",
        ),
        JsConformanceVector::value(
            "fc-multi-param-single-string",
            CATEGORY,
            r#"new Function("a, b, c", "return a * b * c;")(2, 3, 4);"#,
            "24",
        ),
        JsConformanceVector::value(
            "fc-missing-args-are-undefined",
            CATEGORY,
            r#"new Function("a", "b", "return typeof b;")(2);"#,
            "undefined",
        ),
        JsConformanceVector::value(
            "fc-no-return-yields-undefined",
            CATEGORY,
            r#"new Function("var a = 1;")();"#,
            "undefined",
        ),
        JsConformanceVector::value(
            "fc-multi-statement-body",
            CATEGORY,
            r#"new Function("a", "var x = a + 1; var y = x * 2; return y;")(10);"#,
            "22",
        ),
        // -- global-vs-local scope -------------------------------------------
        // Realm builtins are reachable from the generated function's
        // global-only scope; user top-level declarations and call-site locals
        // are NOT (asserted fail-closed in the adversarial set below).
        JsConformanceVector::value(
            "fc-scope-realm-builtin-visible",
            CATEGORY,
            r#"new Function("return Math.max(10, 42);")();"#,
            "42",
        ),
        JsConformanceVector::value(
            "fc-scope-nested-builtin-visible",
            CATEGORY,
            r#"new Function("return Math.max(Math.min(100, 42), 7);")();"#,
            "42",
        ),
        JsConformanceVector::value(
            "fc-this-is-undefined",
            CATEGORY,
            r#"new Function("return typeof this;")();"#,
            "undefined",
        ),
        // -- nested generated functions --------------------------------------
        // (a) inner functions defined INSIDE a generated body:
        JsConformanceVector::value(
            "fc-nested-inner-fn-decl",
            CATEGORY,
            r#"new Function("function inner() { return 7; } return inner();")();"#,
            "7",
        ),
        JsConformanceVector::value(
            "fc-nested-inner-fn-expr",
            CATEGORY,
            r#"new Function("var inner = function () { return 8; }; return inner();")();"#,
            "8",
        ),
        JsConformanceVector::value(
            "fc-nested-iife",
            CATEGORY,
            r#"new Function("return (function () { return 41; })();")();"#,
            "41",
        ),
        JsConformanceVector::value(
            "fc-nested-closure-over-local",
            CATEGORY,
            r#"new Function("var n = 10; var add = function (x) { return x + n; }; return add(5);")();"#,
            "15",
        ),
        // (b) two generated functions composed (one passed to another):
        JsConformanceVector::value(
            "fc-nested-compose-two-genfns",
            CATEGORY,
            r#"var g = new Function("return 7;"); var f = new Function("cb", "return cb() + 1;"); f(g);"#,
            "8",
        ),
        // -- catchability INSIDE a generated body ----------------------------
        JsConformanceVector::value(
            "fc-inbody-try-catch-explicit-throw",
            CATEGORY,
            r#"new Function("try { throw 'x'; } catch (e) { return 'caught:' + e; }")();"#,
            "caught:x",
        ),
        JsConformanceVector::value(
            "fc-inbody-try-catch-native-error",
            CATEGORY,
            r#"new Function("try { var o = null; return o.x; } catch (e) { return 'caught:' + e.name; }")();"#,
            "caught:TypeError",
        ),
        JsConformanceVector::value(
            "fc-inbody-try-finally-order",
            CATEGORY,
            r#"new Function("var r = ''; try { r = 'try'; } finally { r = r + ':fin'; } return r;")();"#,
            "try:fin",
        ),
        // -- catchability ACROSS the generated->caller boundary (native) -----
        // A native runtime error raised inside a generated function is catchable
        // by an enclosing try/catch in the caller (BotGuard uses deliberate
        // error probes). `caught_value` labels this as a post-unwind result.
        JsConformanceVector::caught_value(
            "fc-cross-boundary-native-error-catchable",
            CATEGORY,
            r#"var c = "uncaught"; try { new Function("var o = null; return o.x;")(); } catch (e) { c = e.name; } c;"#,
            "TypeError",
        ),
        // -- catchability ACROSS the generated->caller boundary (explicit throw)
        // bd-8enww.4.7: an explicit `throw` inside a generated function is now
        // catchable by the caller and binds the ORIGINAL thrown value — the
        // primitive value travels verbatim, and a thrown Error object preserves
        // its name/message (which exercises the shared-heap survival of the
        // thrown object across the generated frame's snapshot restore).
        JsConformanceVector::caught_value(
            "fc-cross-boundary-explicit-throw-primitive",
            CATEGORY,
            r#"var c = "uncaught"; try { new Function("throw 'boom';")(); } catch (e) { c = e; } c;"#,
            "boom",
        ),
        JsConformanceVector::caught_value(
            "fc-cross-boundary-explicit-throw-error-message",
            CATEGORY,
            r#"var c = "uncaught"; try { new Function("throw new Error('bad');")(); } catch (e) { c = e.message; } c;"#,
            "bad",
        ),
        JsConformanceVector::caught_value(
            "fc-cross-boundary-explicit-throw-error-name",
            CATEGORY,
            r#"var c = "uncaught"; try { new Function("throw new TypeError('nope');")(); } catch (e) { c = e.name; } c;"#,
            "TypeError",
        ),
        // -- AC#4: typed-array interaction (Track B landed) ------------------
        JsConformanceVector::value(
            "fc-ta-uint8-set-get",
            CATEGORY_TYPED_ARRAY,
            r#"new Function("var a = new Uint8Array(4); a[0] = 42; return a[0];")();"#,
            "42",
        )
        .with_resource(Some(4), "within_budget"),
        JsConformanceVector::value(
            "fc-ta-uint8-from-array-length",
            CATEGORY_TYPED_ARRAY,
            r#"new Function("var a = new Uint8Array([1, 2, 3, 4]); return a.length;")();"#,
            "4",
        )
        .with_resource(Some(4), "within_budget"),
        JsConformanceVector::value(
            "fc-ta-arraybuffer-bytelength",
            CATEGORY_TYPED_ARRAY,
            r#"new Function("var b = new ArrayBuffer(8); return b.byteLength;")();"#,
            "8",
        )
        .with_resource(Some(8), "within_budget"),
        JsConformanceVector::value(
            "fc-ta-dataview-get-set-uint8",
            CATEGORY_TYPED_ARRAY,
            r#"new Function("var b = new ArrayBuffer(4); var d = new DataView(b); d.setUint8(0, 7); return d.getUint8(0);")();"#,
            "7",
        )
        .with_resource(Some(4), "within_budget"),
        JsConformanceVector::value(
            "fc-ta-int32-roundtrip",
            CATEGORY_TYPED_ARRAY,
            r#"new Function("var a = new Int32Array(2); a[0] = 1000000; return a[0];")();"#,
            "1000000",
        )
        .with_resource(Some(8), "within_budget"),
        // BotGuard-style in-place memory shuffle over a typed array.
        JsConformanceVector::value(
            "fc-ta-botguard-style-shuffle",
            CATEGORY_TYPED_ARRAY,
            r#"new Function("var a = new Uint8Array([5, 6, 7, 8]); var t = a[0]; a[0] = a[3]; a[3] = t; return a[0] * 1000 + a[3];")();"#,
            "8005",
        )
        .with_resource(Some(4), "within_budget"),
        JsConformanceVector::value(
            "fc-ta-loop-sum",
            CATEGORY_TYPED_ARRAY,
            r#"new Function("var a = new Uint8Array([1, 2, 3, 4, 5]); var s = 0; for (var i = 0; i < a.length; i = i + 1) { s = s + a[i]; } return s;")();"#,
            "15",
        )
        .with_resource(Some(5), "within_budget"),
    ]
}

/// Adversarial / fail-closed vectors. Each expects a deterministic
/// `eval.runtime.fault` with a message substring that localizes the failure
/// stage (parse-time / lower-time / runtime).
fn adversarial_vectors() -> Vec<JsConformanceVector> {
    vec![
        // -- syntax errors: parse-time, identifiable by source context -------
        JsConformanceVector::engine_error(
            "fc-adv-syntax-error-body",
            CATEGORY_ADVERSARIAL,
            r#"new Function("x", "return {");"#,
            "eval.runtime.fault",
            Some("failed to parse module '<function-constructor>'"),
        ),
        JsConformanceVector::engine_error(
            "fc-adv-syntax-error-parameter",
            CATEGORY_ADVERSARIAL,
            r#"new Function("x-", "return x;");"#,
            "eval.runtime.fault",
            Some("failed to parse module '<function-constructor>'"),
        ),
        // -- adversarial budget exhaustion: runtime, deterministic limit -----
        JsConformanceVector::engine_error(
            "fc-adv-budget-exhaustion-infinite-loop",
            CATEGORY_ADVERSARIAL,
            r#"var f = new Function("while (true) {}"); f();"#,
            "eval.runtime.fault",
            Some("budget exhausted"),
        ),
        // -- containment: no ambient authority from generated code -----------
        JsConformanceVector::engine_error(
            "fc-adv-ambient-process-refused",
            CATEGORY_ADVERSARIAL,
            r#"var f = new Function("return process"); f();"#,
            "eval.runtime.fault",
            Some("ambient authority violation"),
        ),
        // -- containment: user top-level declarations are NOT visible --------
        // In a binding-led runtime a `Function`-constructed body can read module
        // globals; FrankenEngine isolates generated code to realm builtins, so a
        // user top-level `var` fails closed rather than leaking ambient state.
        JsConformanceVector::engine_error(
            "fc-adv-user-global-var-not-leaked",
            CATEGORY_ADVERSARIAL,
            r#"var userTopLevelValue = 99; var f = new Function("return userTopLevelValue;"); f();"#,
            "eval.runtime.fault",
            Some("uncaught exception"),
        ),
        JsConformanceVector::engine_error(
            "fc-adv-unbound-reference-fails-closed",
            CATEGORY_ADVERSARIAL,
            r#"new Function("return someUndeclaredGlobalXyz123;")();"#,
            "eval.runtime.fault",
            Some("uncaught exception"),
        ),
        // -- containment: no recursive dynamic codegen from generated code ---
        JsConformanceVector::engine_error(
            "fc-adv-codegen-within-codegen-refused",
            CATEGORY_ADVERSARIAL,
            r#"new Function("return new Function('return 7;')();")();"#,
            "eval.runtime.fault",
            Some("uncaught exception"),
        ),
        // -- AC#4 of bd-8enww.3.3: `new f(...)` on a generated function refused
        JsConformanceVector::engine_error(
            "fc-adv-construct-generated-function-refused",
            CATEGORY_ADVERSARIAL,
            r#"var f = new Function("return 1;"); new f();"#,
            "eval.runtime.fault",
            Some("bd-8enww.3.3"),
        ),
    ]
}

// --- the conformance gate ----------------------------------------------------

#[test]
fn function_constructor_conformance_suite_is_green() {
    let mut vectors = behavior_vectors();
    vectors.extend(adversarial_vectors());

    let report = assert_js_conformance_vectors(&vectors);
    render_report(&report);

    // Structured-log integrity: every vector is attributable and hashed, so a
    // future failure can be localized to an exact source + stage.
    assert_eq!(report.failed, 0);
    assert_eq!(report.total_vectors as usize, vectors.len());
    assert_eq!(report.passed as usize, vectors.len());
    for log in &report.logs {
        assert!(
            log.source_hash.starts_with("sha256:"),
            "every vector must log a source hash: {log:?}"
        );
        assert!(!log.vector_id.is_empty());
    }

    // Typed-array vectors must carry a logged memory size (AC#4 observability).
    for log in report
        .logs
        .iter()
        .filter(|log| log.category == CATEGORY_TYPED_ARRAY)
    {
        assert!(
            log.memory_size_bytes.is_some(),
            "typed-array vector must log memory size: {log:?}"
        );
        assert_ne!(log.budget_outcome, "not_applicable");
    }
}

// --- AC#1: the exact G-2 vector, isolated --------------------------------------

#[test]
fn ac1_exact_g2_vector_returns_42_through_hybrid_router() {
    assert_eq!(
        eval_value_hybrid(r#"var f = new Function("x", "return x * 2;"); f(21);"#),
        "42"
    );
}

// --- AC#3: logs distinguish PARSE-TIME from RUNTIME-THROWN failures -----------

#[test]
fn ac3_logs_distinguish_parse_time_from_runtime_failures() {
    // Two failing generated-code vectors with different failure stages; the
    // structured log's error_message localizes which stage diverged.
    let parse_time = JsConformanceVector::engine_error(
        "fc-diag-parse-time",
        CATEGORY_ADVERSARIAL,
        r#"new Function("x", "return {");"#,
        "eval.runtime.fault",
        Some("failed to parse module"),
    );
    let runtime_thrown = JsConformanceVector::engine_error(
        "fc-diag-runtime-thrown",
        CATEGORY_ADVERSARIAL,
        r#"new Function("return someUndeclaredGlobalXyz123;")();"#,
        "eval.runtime.fault",
        Some("uncaught exception"),
    );

    let report = assert_js_conformance_vectors(&[parse_time, runtime_thrown]);
    render_report(&report);

    let parse_log = report
        .logs
        .iter()
        .find(|log| log.vector_id == "fc-diag-parse-time")
        .expect("parse-time vector log");
    let runtime_log = report
        .logs
        .iter()
        .find(|log| log.vector_id == "fc-diag-runtime-thrown")
        .expect("runtime-thrown vector log");

    let parse_msg = parse_log
        .error_message
        .as_deref()
        .expect("parse-time failure carries a message");
    let runtime_msg = runtime_log
        .error_message
        .as_deref()
        .expect("runtime failure carries a message");

    assert!(
        parse_msg.contains("failed to parse module"),
        "parse-time message must name the parse stage: {parse_msg}"
    );
    assert!(
        runtime_msg.contains("uncaught exception"),
        "runtime message must name the thrown stage: {runtime_msg}"
    );
    // The two stages are observably different — a CI failure can localize them.
    assert_ne!(parse_msg, runtime_msg);
    assert!(!parse_msg.contains("uncaught exception"));
    assert!(!runtime_msg.contains("failed to parse module"));
}

// --- AC#2 + provenance: the audit trail names the generated source -----------

#[test]
fn ac2_audit_trail_names_generated_source_and_records_budget() {
    let entries = audit(r#"var f = new Function("x", "return x * 2;"); f(21);"#);

    let constructed = entries
        .iter()
        .find(|e| e.kind == GeneratedCodeEventKind::Constructed)
        .expect("a construction event");
    let invoked = entries
        .iter()
        .find(|e| e.kind == GeneratedCodeEventKind::Invoked)
        .expect("an invocation event");

    // The generated source is identified by a content-addressed `genfn:` id and
    // hashed parameter/body — the "generated source hash" the design requires.
    assert!(
        constructed.source_id.starts_with("genfn:"),
        "{}",
        constructed.source_id
    );
    assert_eq!(constructed.source_hash.len(), 64);
    assert_eq!(constructed.parameter_hash.len(), 64);
    // The invocation is attributable to the constructed source and records the
    // exact instruction budget the body consumed.
    assert_eq!(invoked.source_id, constructed.source_id);
    assert_eq!(invoked.outcome, "completed");
    assert!(
        invoked.instructions_consumed > 0,
        "expected non-zero budget spend, got {}",
        invoked.instructions_consumed
    );
}

#[test]
fn ac2_provenance_is_stable_and_content_addressed() {
    let source_id = |src: &str| -> String {
        audit(src)
            .into_iter()
            .find(|e| e.kind == GeneratedCodeEventKind::Constructed)
            .map(|e| e.source_id)
            .expect("a construction event")
    };

    // Identical source in identical context ⇒ identical id (stable across runs).
    let a = source_id(r#"new Function("x", "return x * 2;");"#);
    let b = source_id(r#"new Function("x", "return x * 2;");"#);
    assert_eq!(a, b);

    // Distinct bodies ⇒ distinct ids (no collision under content addressing).
    let c = source_id(r#"new Function("return 1;");"#);
    let d = source_id(r#"new Function("return 2;");"#);
    assert_ne!(c, d);
}

#[test]
fn ac2_generated_code_never_granted_dangerous_authority() {
    let entries = audit(r#"new Function("return Math.max(10, 42);")();"#);
    let invoked = entries
        .iter()
        .find(|e| e.kind == GeneratedCodeEventKind::Invoked)
        .expect("an invocation event");
    // The safe `builtin` grant is recorded; dangerous authority never is.
    assert!(
        invoked.granted_capabilities.iter().any(|c| c == "builtin"),
        "expected the builtin grant, got {:?}",
        invoked.granted_capabilities
    );
    for forbidden in ["fs_read", "fs_write", "process_spawn", "network_egress"] {
        assert!(
            !invoked.granted_capabilities.iter().any(|c| c == forbidden),
            "generated code must never be granted {forbidden}"
        );
    }
}

// --- AC#4: typed-array interaction, isolated for emphasis --------------------

#[test]
fn ac4_generated_function_interacts_with_typed_arrays() {
    // The headline "feature interaction" the bead note demands (not `x*2`).
    assert_eq!(
        eval_value_hybrid(
            r#"new Function("var a = new Uint8Array([5, 6, 7, 8]); var t = a[0]; a[0] = a[3]; a[3] = t; return a[0] * 1000 + a[3];")();"#
        ),
        "8005"
    );
    // The typed-array work happens inside generated code, and the run is still
    // audited (additive observability, not a behavior change).
    let entries = audit(r#"new Function("var a = new Uint8Array(4); a[0] = 42; return a[0];")();"#);
    assert!(
        entries
            .iter()
            .any(|e| e.kind == GeneratedCodeEventKind::Invoked && e.outcome == "completed"),
        "typed-array generated body must be audited as a completed invocation"
    );
}

// --- Adversarial: budget exhaustion is deterministic -------------------------

#[test]
fn adversarial_infinite_generated_loop_halts_deterministically() {
    let src = r#"var f = new Function("while (true) {}"); f();"#;
    let err1 = HybridRouter::default()
        .eval(src)
        .expect_err("infinite generated loop must fail closed");
    let err2 = HybridRouter::default()
        .eval(src)
        .expect_err("infinite generated loop must fail closed");
    assert!(
        err1.message.contains("budget exhausted"),
        "expected a budget-exhaustion message, got: {}",
        err1.message
    );
    // Deterministic: identical source ⇒ identical fault message.
    assert_eq!(err1.message, err2.message);

    // The native engine fails closed on the same vector (no route bypasses the
    // shared instruction budget that generated code runs under).
    let mut native = QuickJsInspiredNativeEngine;
    assert!(
        native.eval(src).is_err(),
        "the native engine must also halt the infinite generated loop"
    );
}

// --- Catchability boundary: explicit throw crossing the generated frame ------

#[test]
fn explicit_throw_crossing_generated_boundary_is_catchable_by_caller() {
    // bd-8enww.4.7 (CLOSED): an *explicit* `throw` inside a generated function
    // now propagates into an enclosing try/catch in the CALLER, carrying the
    // ORIGINAL thrown value — symmetric with a native runtime error, which was
    // already catchable (see `fc-cross-boundary-native-error-catchable`). The
    // caller's handler binds the thrown value verbatim.
    let mut router = HybridRouter::default();
    let out = router
        .eval(r#"var c = "uncaught"; try { new Function("throw 'boom';")(); } catch (e) { c = e; } c;"#)
        .expect("explicit throw crossing the generated boundary is now catchable");
    assert_eq!(
        out.value, "boom",
        "the caller's catch must bind the original thrown value",
    );

    // With NO enclosing handler the throw still fails closed deterministically:
    // the value surfaces at the eval boundary, never silently swallowed.
    let err = HybridRouter::default()
        .eval(r#"new Function("throw 'boom';")();"#)
        .expect_err("an uncaught explicit throw still surfaces");
    assert!(
        err.message.contains("uncaught exception") && err.message.contains("boom"),
        "the thrown value must surface when uncaught: {}",
        err.message
    );
}

// --- Determinism: identical generated source ⇒ identical observable result ----

#[test]
fn generated_invocation_is_deterministic_across_runs() {
    let src = r#"var f = new Function("a", "b", "return a * 10 + b;"); f(3, 4);"#;
    assert_eq!(eval_value(src), "34");
    assert_eq!(eval_value(src), eval_value(src));
    assert_eq!(eval_value_hybrid(src), eval_value(src));
}
