#![forbid(unsafe_code)]

//! bd-8enww.4.6 (YTBG-D6): exception conformance + e2e logging suite.
//!
//! This is the public-`eval` end-to-end half of the G-3 exception quality gate.
//! Every vector runs through `HybridRouter::eval` (the same surface a BotGuard VM
//! would hit) via the reusable bd-8enww.1.4 conformance runner
//! (`_support::js_conformance`), which emits one structured `JsConformanceLog`
//! per vector carrying: vector id, category, expected vs actual kind+result,
//! pass/fail, a `sha256:` source hash, and — on an engine error — the stable
//! error namespace/class/message. Crucially the log's `actual_kind` distinguishes
//! a value that was *caught* inside the program (`"value"` / `"caught_value"`)
//! from one that *escaped to eval* (`"engine_error"`), so a failure log pinpoints
//! the exact control-flow stage that diverged (AC#3).
//!
//! Coverage (AC#1, AC#2, AC#4):
//! - the G-3 report vector (a native `TypeError` from null property access caught
//!   by JS `try`/`catch`),
//! - thrown primitives (string, number) and thrown object values,
//! - native `TypeError` (null/undefined property access, unwinding from a called
//!   function) and native `ReferenceError` (temporal dead zone),
//! - `finally` side effects + completion-override ordering (normal, return, throw,
//!   break, nested `continue` exiting an outer `finally`),
//! - nested `try`/`catch`, catch-binding block scope, and rethrow to an outer
//!   handler,
//! - an uncaught throw escaping to `eval` as a stable `eval.runtime.fault`,
//! - generated-code errors (`new Function(...)`): in-body try/catch/finally and a
//!   native/explicit throw crossing the generated→caller boundary (Track C +
//!   bd-8enww.4.7).
//!
//! The complementary interpreter/IR3 *completion-record unit tests* (BeginTry /
//! EnterCatch / EnterFinally / EndFinally emission and ordering) live in
//! `exception_semantics_conformance.rs`; this file is the e2e structured-log
//! companion. Run with logs:
//!   cargo test -p frankenengine-engine --test exception_conformance_suite_bd_8enww_4_6 -- --nocapture

mod _support;

use _support::js_conformance::{
    JS_CONFORMANCE_RUNNER_ID, JS_CONFORMANCE_RUNNER_SCHEMA, JsConformanceReport,
    JsConformanceVector, assert_js_conformance_vectors, run_js_conformance_vectors,
};

const CAT_G3: &str = "exceptions/g3-native-typeerror";
const CAT_THROWN_PRIMITIVE: &str = "exceptions/thrown-primitive";
const CAT_THROWN_OBJECT: &str = "exceptions/thrown-object";
const CAT_NATIVE_ERROR: &str = "exceptions/native-error";
const CAT_FINALLY: &str = "exceptions/finally-ordering";
const CAT_NESTED: &str = "exceptions/nested-try-catch";
const CAT_RETHROW: &str = "exceptions/rethrow";
const CAT_UNCAUGHT: &str = "exceptions/uncaught-escape";
const CAT_GENERATED: &str = "exceptions/generated-code";

/// The full e2e exception vector corpus. Expected values are frozen against the
/// behavior already verified by `exception_semantics_conformance.rs` and the
/// Function-constructor conformance suite (bd-8enww.3.5 / 4.7).
fn exception_vectors() -> Vec<JsConformanceVector> {
    vec![
        // -- AC#1: the canonical G-3 report vector ---------------------------
        JsConformanceVector::caught_value(
            "ex-g3-null-property-typeerror-catchable",
            CAT_G3,
            r#"let result = "uncaught"; try { let o = null; o.x; } catch (e) { result = "caught"; } result;"#,
            "caught",
        ),
        // -- thrown primitives -----------------------------------------------
        JsConformanceVector::caught_value(
            "ex-throw-string-caught",
            CAT_THROWN_PRIMITIVE,
            r#"try { throw "ytbg"; } catch (e) { e; }"#,
            "ytbg",
        ),
        JsConformanceVector::caught_value(
            "ex-throw-number-caught",
            CAT_THROWN_PRIMITIVE,
            r#"try { throw 7; } catch (e) { e; }"#,
            "7",
        ),
        JsConformanceVector::caught_value(
            "ex-catch-binding-block-scoped",
            CAT_THROWN_PRIMITIVE,
            r#"let e = "outer"; try { throw "inner"; } catch (e) { e; } e;"#,
            "outer",
        ),
        // -- thrown object values --------------------------------------------
        JsConformanceVector::caught_value(
            "ex-throw-object-message",
            CAT_THROWN_OBJECT,
            r#"try { throw { message: "botguard" }; } catch (e) { e.message; }"#,
            "botguard",
        ),
        JsConformanceVector::caught_value(
            "ex-throw-object-code",
            CAT_THROWN_OBJECT,
            r#"try { throw { code: 7 }; } catch (e) { e.code; }"#,
            "7",
        ),
        // -- native errors (TypeError / ReferenceError) ----------------------
        JsConformanceVector::caught_value(
            "ex-native-typeerror-name",
            CAT_NATIVE_ERROR,
            r#"let name = "none"; try { let o = null; o.x; } catch (e) { name = e.name; } name;"#,
            "TypeError",
        ),
        JsConformanceVector::caught_value(
            "ex-native-typeerror-has-message",
            CAT_NATIVE_ERROR,
            r#"let msg = ""; try { let o = undefined; o.y; } catch (e) { msg = (typeof e.message === "string") ? "has-message" : "no-message"; } msg;"#,
            "has-message",
        ),
        JsConformanceVector::caught_value(
            "ex-native-error-unwinds-from-called-function",
            CAT_NATIVE_ERROR,
            r#"function boom() { let o = null; return o.z; } let r = "no"; try { boom(); } catch (e) { r = "yes:" + e.name; } r;"#,
            "yes:TypeError",
        ),
        JsConformanceVector::caught_value(
            "ex-native-referenceerror-tdz-catchable",
            CAT_NATIVE_ERROR,
            r#"let r = "none"; try { x; let x = 1; } catch (e) { r = e.name; } r;"#,
            "ReferenceError",
        ),
        // -- finally side effects + completion-override ordering -------------
        JsConformanceVector::value(
            "ex-finally-runs-on-normal-path-in-order",
            CAT_FINALLY,
            r#"let log = ""; try { log = log + "try"; } finally { log = log + ":finally"; } log;"#,
            "try:finally",
        ),
        JsConformanceVector::value(
            "ex-finally-runs-after-catch",
            CAT_FINALLY,
            r#"let log = ""; try { throw "x"; } catch (e) { log = log + "catch:" + e; } finally { log = log + ":finally"; } log;"#,
            "catch:x:finally",
        ),
        JsConformanceVector::value(
            "ex-finally-return-overrides-try-return",
            CAT_FINALLY,
            r#"function f() { try { return "try"; } finally { return "finally"; } } f();"#,
            "finally",
        ),
        JsConformanceVector::value(
            "ex-finally-return-overrides-try-throw",
            CAT_FINALLY,
            r#"function f() { try { throw "try"; } finally { return "final"; } } f();"#,
            "final",
        ),
        JsConformanceVector::value(
            "ex-finally-break-overrides-throw",
            CAT_FINALLY,
            r#"let log = ""; outer: { try { log = log + "try"; throw "x"; } finally { log = log + ":finally"; break outer; } log = log + ":after"; } log = log + ":done"; log;"#,
            "try:finally:done",
        ),
        JsConformanceVector::value(
            "ex-finally-continue-overrides-throw-each-iteration",
            CAT_FINALLY,
            r#"let log = ""; for (let i = 0; i < 2; i = i + 1) { try { log = log + "try" + i; throw "x"; } finally { log = log + ":finally" + i + ";"; continue; } log = log + "bad"; } log;"#,
            "try0:finally0;try1:finally1;",
        ),
        JsConformanceVector::value(
            "ex-nested-finally-continue-exits-outer-finally-overrides-return",
            CAT_FINALLY,
            r#"let log = ""; function f() { outer: for (let i = 0; i < 1; i = i + 1) { try { return "outer"; } finally { for (let j = 0; j < 1; j = j + 1) { try { throw "inner"; } finally { log = log + "inner;"; continue outer; } } log = log + "bad"; } } return "done"; } let result = f(); log + result;"#,
            "inner;done",
        ),
        // -- nested try/catch + rethrow --------------------------------------
        JsConformanceVector::value(
            "ex-nested-rethrow-from-catch-runs-finally-then-outer-catch",
            CAT_NESTED,
            r#"let log = ""; try { try { log = log + "try"; throw "x"; } catch (e) { log = log + ":catch"; throw "y"; } finally { log = log + ":finally"; } } catch (e) { log = log + ":outer:" + e; } log;"#,
            "try:catch:finally:outer:y",
        ),
        JsConformanceVector::caught_value(
            "ex-rethrow-reaches-outer-catch",
            CAT_RETHROW,
            r#"try { try { throw "nested"; } catch (e) { throw e; } } catch (outer) { outer; }"#,
            "nested",
        ),
        // -- uncaught throw escapes to eval (AC#3: distinguishable escape) ----
        JsConformanceVector::engine_error(
            "ex-uncaught-throw-escapes-to-eval",
            CAT_UNCAUGHT,
            r#"throw "uncaught-ytbg";"#,
            "eval.runtime.fault",
            Some("uncaught exception"),
        ),
        // -- AC#4: generated-code (new Function) exception cases -------------
        JsConformanceVector::value(
            "ex-genfn-inbody-try-catch-explicit-throw",
            CAT_GENERATED,
            r#"new Function("try { throw 'x'; } catch (e) { return 'caught:' + e; }")();"#,
            "caught:x",
        ),
        JsConformanceVector::value(
            "ex-genfn-inbody-try-catch-native-error",
            CAT_GENERATED,
            r#"new Function("try { var o = null; return o.x; } catch (e) { return 'caught:' + e.name; }")();"#,
            "caught:TypeError",
        ),
        JsConformanceVector::value(
            "ex-genfn-inbody-try-finally-order",
            CAT_GENERATED,
            r#"new Function("var r = ''; try { r = 'try'; } finally { r = r + ':fin'; } return r;")();"#,
            "try:fin",
        ),
        JsConformanceVector::caught_value(
            "ex-genfn-cross-boundary-native-error-catchable",
            CAT_GENERATED,
            r#"var c = "uncaught"; try { new Function("var o = null; return o.x;")(); } catch (e) { c = e.name; } c;"#,
            "TypeError",
        ),
        JsConformanceVector::caught_value(
            "ex-genfn-cross-boundary-explicit-throw-primitive",
            CAT_GENERATED,
            r#"var c = "uncaught"; try { new Function("throw 'boom';")(); } catch (e) { c = e; } c;"#,
            "boom",
        ),
        JsConformanceVector::caught_value(
            "ex-genfn-cross-boundary-explicit-throw-error-message",
            CAT_GENERATED,
            r#"var c = "uncaught"; try { new Function("throw new Error('bad');")(); } catch (e) { c = e.message; } c;"#,
            "bad",
        ),
        JsConformanceVector::caught_value(
            "ex-genfn-cross-boundary-explicit-throw-error-name",
            CAT_GENERATED,
            r#"var c = "uncaught"; try { new Function("throw new TypeError('nope');")(); } catch (e) { c = e.name; } c;"#,
            "TypeError",
        ),
    ]
}

/// Render the structured report as pretty JSON so `--nocapture` runs produce the
/// e2e log artifact (vector id, source hash, expected/actual, path taken).
fn render_report(report: &JsConformanceReport) {
    match serde_json::to_string_pretty(report) {
        Ok(json) => eprintln!("[bd-8enww.4.6] js-conformance report:\n{json}"),
        Err(err) => eprintln!("[bd-8enww.4.6] failed to render report: {err}"),
    }
}

/// AC#1/#2/#4: the full exception corpus passes through the public eval path, and
/// every named category is represented.
#[test]
fn exception_conformance_all_vectors_pass() {
    let vectors = exception_vectors();
    assert!(
        vectors.len() >= 25,
        "the exception conformance corpus must be comprehensive (>=25 vectors), got {}",
        vectors.len()
    );

    let report = assert_js_conformance_vectors(&vectors);
    render_report(&report);

    assert_eq!(report.total_vectors as usize, vectors.len());
    assert_eq!(report.failed, 0);
    assert_eq!(report.passed, report.total_vectors);

    // Every AC category must appear at least once.
    for category in [
        CAT_G3,
        CAT_THROWN_PRIMITIVE,
        CAT_THROWN_OBJECT,
        CAT_NATIVE_ERROR,
        CAT_FINALLY,
        CAT_NESTED,
        CAT_RETHROW,
        CAT_UNCAUGHT,
        CAT_GENERATED,
    ] {
        assert!(
            report.logs.iter().any(|log| log.category == category),
            "exception corpus must cover category '{category}'"
        );
    }
}

/// AC#3: a failure log identifies the exact control-flow stage that diverged.
///
/// Drive a deliberately-wrong expectation through the runner and assert the
/// structured log pinpoints the divergence: expected vs actual result, the
/// `actual_kind` (caught value vs escaped engine error), and a content hash of
/// the source. This proves the failure-localization surface used to triage
/// obfuscated BotGuard exception failures.
#[test]
fn exception_conformance_failure_log_localizes_divergence() {
    let wrong = JsConformanceVector::value(
        "ex-divergence-probe",
        CAT_THROWN_PRIMITIVE,
        r#"try { throw "actual-a"; } catch (e) { e; }"#,
        "expected-b",
    );
    let report = run_js_conformance_vectors(std::slice::from_ref(&wrong));

    assert_eq!(report.schema_version, JS_CONFORMANCE_RUNNER_SCHEMA);
    assert_eq!(report.runner_id, JS_CONFORMANCE_RUNNER_ID);
    assert_eq!(report.failed, 1);
    assert_eq!(report.passed, 0);

    let log = report
        .logs
        .iter()
        .find(|log| log.vector_id == "ex-divergence-probe")
        .expect("divergence probe must be logged");
    assert!(!log.passed, "the wrong-expectation vector must fail");
    assert_eq!(log.expected_result, "expected-b");
    assert_eq!(log.actual_result, "actual-a");
    // The throw was caught inside the program, so it did NOT escape to eval.
    assert_eq!(log.actual_kind, "value");
    assert_eq!(log.category, CAT_THROWN_PRIMITIVE);
    assert!(
        log.source_hash.starts_with("sha256:"),
        "every log must carry a content hash of the source, got {}",
        log.source_hash
    );
}

/// AC#3: the structured log distinguishes an exception *caught inside the
/// program* from one that *escaped to eval* — the single most important triage
/// signal for "did the error bypass the handler?".
#[test]
fn exception_conformance_distinguishes_caught_from_escaped() {
    let caught = JsConformanceVector::caught_value(
        "ex-caught-stays-inside",
        CAT_THROWN_PRIMITIVE,
        r#"try { throw "x"; } catch (e) { e; }"#,
        "x",
    );
    let escaped = JsConformanceVector::engine_error(
        "ex-escaped-to-eval",
        CAT_UNCAUGHT,
        r#"throw "x";"#,
        "eval.runtime.fault",
        Some("uncaught exception"),
    );

    let report = assert_js_conformance_vectors(&[caught, escaped]);

    let caught_log = report
        .logs
        .iter()
        .find(|log| log.vector_id == "ex-caught-stays-inside")
        .expect("caught vector log");
    let escaped_log = report
        .logs
        .iter()
        .find(|log| log.vector_id == "ex-escaped-to-eval")
        .expect("escaped vector log");

    assert_eq!(caught_log.actual_kind, "value");
    assert!(caught_log.error_code.is_none());

    assert_eq!(escaped_log.actual_kind, "engine_error");
    assert_eq!(
        escaped_log.error_code.as_deref(),
        Some("eval.runtime.fault")
    );
    assert!(
        escaped_log
            .error_message
            .as_deref()
            .is_some_and(|m| m.contains("uncaught exception")),
        "escaped error must record the thrown-value diagnostic"
    );
}
