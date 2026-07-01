//! bd-8enww.4.10 — an explicit `throw` from a `builtin:`-hostcall-dispatched
//! Array callback must be catchable by an enclosing `try`/`catch`, carrying the
//! ORIGINAL thrown value.
//!
//! Follow-up to bd-8enww.4.7 (cross-boundary explicit throw) and bd-8enww.4.8
//! (legacy mini-lane value fidelity). 4.7 made an explicit throw from an
//! `Array.prototype` callback catchable at the `Call` / `CallMethod` builtin
//! dispatch arms, and 4.8 made the surfaced *value* faithful on the legacy
//! reduce / `Array.from` mini-lanes. But two callback-running Array surfaces are
//! dispatched as `builtin:` *hostcalls* (the `HostCall` IR3 instruction), not the
//! `Call`/`CallMethod` arms, so their explicit throw escaped an enclosing
//! `try`/`catch` even though the value was already preserved:
//!
//!   * `Array.from(xs, mapFn)` → `builtin:ArrayFrom` (legacy mapper mini-lane).
//!   * `[<literal>].some(cb)` → `builtin:ArrayPrototypeSome` (a lowering fast-path for a *literal* receiver only).
//!
//! The fix routes the `builtin:` hostcall dispatch through the same
//! `route_isolated_explicit_throw` unwinding + throw-path IFC label join the
//! `Call`/`CallMethod` arms already use. This is uniform: any other
//! callback-running `builtin:` hostcall is covered too (AC#3). Non-throw hostcall
//! errors are a no-op through the router and propagate unchanged.
//!
//! Empirically confirmed BEFORE this fix (HybridRouter::eval): `forEach`, `map`,
//! `filter`, `find`, `findIndex`, `every`, and `reduce` were already CAUGHT (they
//! dispatch through `CallMethod`, or a variable-receiver `.some`); only the two
//! `builtin:` hostcall shapes above ESCAPED. Those are pinned here as regression
//! guards so the corrected diagnosis cannot silently rot.
//!
//! These drive the public `HybridRouter::eval` surface and assert observable
//! values. IFC-label soundness of the throw-path join lives in an in-crate unit
//! test (`array_hostcall_explicit_throw_over_secret_array_taints_catch_binding`),
//! since the eval surface does not expose register labels.

use frankenengine_engine::{EvalOutcome, HybridRouter};

/// Evaluate and require the program to COMPLETE (the throw was caught), returning
/// the formatted completion value.
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

// --- Array.from: the legacy mini-lane hostcall (the headline fix) ------------

#[test]
fn array_from_mapper_throw_string_is_caught_with_original_value() {
    // Previously ESCAPED as `uncaught exception: af` despite the try/catch.
    assert_eq!(
        caught(
            r#"var c = "no"; try { Array.from([1,2,3], function(x){ throw "af"; }); } catch (e) { c = e; } c;"#
        ),
        "af",
    );
}

#[test]
fn array_from_mapper_throw_number_preserves_primitive_type() {
    // The catch binding holds the original value verbatim, so `typeof e` is
    // `number` — never coerced through the diagnostic/error surface.
    assert_eq!(
        caught(
            r#"var t = "?"; try { Array.from([1,2,3], function(x){ throw 7; }); } catch (e) { t = typeof e; } t;"#
        ),
        "number",
    );
}

#[test]
fn array_from_crossed_throw_can_be_rethrown_to_outer_handler() {
    assert_eq!(
        caught(
            r#"var c = "no";
               try {
                 try { Array.from([1,2,3], function(x){ throw "inner"; }); }
                 catch (e) { throw e + ":again"; }
               } catch (e2) { c = e2; }
               c;"#
        ),
        "inner:again",
    );
}

// --- [<literal>].some: the array-literal fast-path hostcall ------------------

#[test]
fn array_literal_some_predicate_throw_string_is_caught() {
    // `[…].some(cb)` on a *literal* receiver lowers to `builtin:ArrayPrototypeSome`
    // (a hostcall), which previously ESCAPED as `uncaught exception: sm`.
    assert_eq!(
        caught(
            r#"var c = "no"; try { [1,2,3].some(function(x){ throw "sm"; }); } catch (e) { c = e; } c;"#
        ),
        "sm",
    );
}

#[test]
fn array_literal_some_predicate_throw_number_preserves_type() {
    assert_eq!(
        caught(
            r#"var t = "?"; try { [1,2,3].some(function(x){ throw 99; }); } catch (e) { t = typeof e; } t;"#
        ),
        "number",
    );
}

// --- regression guards: shapes that were ALREADY caught stay caught ----------

#[test]
fn every_predicate_throw_still_caught() {
    // `every` has no literal fast-path → CallMethod → already caught (4.7).
    assert_eq!(
        caught(
            r#"var c = "no"; try { [1,2,3].every(function(x){ throw "ev"; }); } catch (e) { c = e; } c;"#
        ),
        "ev",
    );
}

#[test]
fn find_and_findindex_and_filter_predicate_throw_still_caught() {
    assert_eq!(
        caught(
            r#"var c = "no"; try { [1,2,3].find(function(x){ throw "fd"; }); } catch (e) { c = e; } c;"#
        ),
        "fd",
    );
    assert_eq!(
        caught(
            r#"var c = "no"; try { [1,2,3].findIndex(function(x){ throw "fi"; }); } catch (e) { c = e; } c;"#
        ),
        "fi",
    );
    assert_eq!(
        caught(
            r#"var c = "no"; try { [1,2,3].filter(function(x){ throw "fl"; }); } catch (e) { c = e; } c;"#
        ),
        "fl",
    );
}

#[test]
fn variable_receiver_some_still_caught() {
    // A NON-literal receiver `.some` dispatches through `CallMethod` (no
    // lowering fast-path), so it was already caught — guard that the fix does
    // not disturb it.
    assert_eq!(
        caught(
            r#"var a = [1,2,3]; var c = "no"; try { a.some(function(x){ throw "vs"; }); } catch (e) { c = e; } c;"#
        ),
        "vs",
    );
}

// --- catch fires ONLY on throw, not on a normal return (no false catch) ------

#[test]
fn array_from_without_throw_maps_normally() {
    // `Array.from([1,2,3], x => x*10)` → [10,20,30]; `.length` is 3.
    assert_eq!(
        caught(r#"Array.from([1,2,3], function(x){ return x * 10; }).length;"#),
        "3",
    );
}

#[test]
fn array_literal_some_without_throw_returns_boolean() {
    assert_eq!(
        caught(r#"[1,2,3].some(function(x){ return x === 2; });"#),
        "true",
    );
    assert_eq!(
        caught(
            r#"var c = "no"; try { c = [1,2,3].some(function(x){ return x > 9; }); } catch (e) { c = "caught"; } c;"#
        ),
        "false",
    );
}

// --- fail-closed: an uncaught throw still surfaces carrying the value --------

#[test]
fn uncaught_array_from_throw_surfaces_deterministically_with_value() {
    let m1 = uncaught(r#"Array.from([1,2,3], function(x){ throw "boom"; });"#);
    assert!(
        m1.contains("uncaught exception") && m1.contains("boom"),
        "an uncaught Array.from mapper throw must surface carrying the value: {m1}",
    );
    let m2 = uncaught(r#"Array.from([1,2,3], function(x){ throw "boom"; });"#);
    assert_eq!(m1, m2, "identical source ⇒ identical surfaced message");
}

#[test]
fn uncaught_array_literal_some_throw_surfaces_with_value() {
    let m = uncaught(r#"[1,2,3].some(function(x){ throw "boom"; });"#);
    assert!(
        m.contains("uncaught exception") && m.contains("boom"),
        "an uncaught [literal].some predicate throw must surface carrying the value: {m}",
    );
}
