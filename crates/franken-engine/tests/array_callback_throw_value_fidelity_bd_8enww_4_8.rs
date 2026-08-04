//! bd-8enww.4.8 — explicit `throw` from an Array-callback mini-interpreter must
//! reach the caller's `catch` carrying the ORIGINAL thrown value.
//!
//! Follow-up to bd-8enww.4.7 (explicit throw across the generated-function
//! boundary). While 4.7's routing helper (`route_isolated_explicit_throw`, at
//! the `Call` + `CallMethod` builtin dispatch arms) also made an explicit throw
//! from an `Array.prototype` callback *catchable*, the value was wrong on the
//! legacy path: `reduce`/`reduceRight` (and the `Array.from` mapper) run their
//! callback through a self-contained mini-interpreter
//! (`invoke_simple_reduce_callback` / `invoke_simple_array_from_callback`) whose
//! instruction `match` had no `Throw` arm — an explicit `throw` fell into the
//! `other =>` catch-all and surfaced as an "unsupported instruction" `TypeError`,
//! which the caller then re-boxed into a generic Error object (`[object …]`).
//!
//! The fix teaches both mini-lanes to handle `Throw` exactly like the modern
//! loop: arm `pending_exception` with the value and surface `UncaughtException`,
//! which the existing dispatch routing re-raises into the caller's catch frames.
//! `forEach`/`map` already run on the modern `invoke_inline_method_call` lane and
//! preserved the value AND are caught via the `CallMethod` route; they are
//! covered here as regression guards.
//!
//! Scope boundary (found while closing this bead, later CLOSED by bd-8enww.4.10):
//! `Array.from` and the array-literal fast-path `[…].some(cb)` are dispatched as
//! `builtin:` HOSTCALLS (the `HostCall` IR3 instruction), not the `Call`/
//! `CallMethod` builtin arms that apply `route_isolated_explicit_throw`, so their
//! explicit callback throw preserved the VALUE (this bead) but originally escaped
//! an enclosing `try`/`catch`. (The originally-suspected `every`/`find` were in
//! fact already caught — they have no literal fast-path and go through
//! `CallMethod`.) bd-8enww.4.10 routed the `builtin:` hostcall arm through the
//! same unwinding + IFC join, so those throws are now catchable; see
//! `array_callback_catchability_bd_8enww_4_10.rs`.
//!
//! These tests drive the public `HybridRouter::eval` surface (the parent-bead
//! acceptance path) and assert observable values, not interpreter internals. The
//! IFC-label soundness of the throw-path join lives in an in-crate unit test
//! (`reducer_explicit_throw_over_secret_array_taints_catch_binding`), since the
//! eval surface does not expose register labels.

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

// --- reduce: the headline repro from the bead --------------------------------

#[test]
fn reduce_callback_throw_string_binds_original_value() {
    // The exact repro: previously bound an error object (`[object …]`).
    assert_eq!(
        caught(
            r#"var c = "no"; try { [1,2,3].reduce(function(a,b){ throw "cb"; }, 0); } catch (e) { c = e; } c;"#
        ),
        "cb",
    );
}

#[test]
fn reduce_callback_throw_number_binds_original_value() {
    assert_eq!(
        caught(
            r#"var c = -1; try { [1,2,3].reduce(function(a,b){ throw 42; }, 0); } catch (e) { c = e; } c;"#
        ),
        "42",
    );
}

#[test]
fn reduce_caught_thrown_primitive_preserves_its_type() {
    // The catch binding holds the original value verbatim, so `typeof e` is
    // `number` — never coerced through the diagnostic/error surface.
    assert_eq!(
        caught(
            r#"var t = "?"; try { [1,2,3].reduce(function(a,b){ throw 7; }, 0); } catch (e) { t = typeof e; } t;"#
        ),
        "number",
    );
}

#[test]
fn reduce_callback_throw_boolean_binds_original_value() {
    assert_eq!(
        caught(
            r#"var c = "x"; try { [1,2].reduce(function(a,b){ throw false; }, 0); } catch (e) { c = e; } c;"#
        ),
        "false",
    );
}

#[test]
fn reduce_right_callback_throw_string_binds_original_value() {
    assert_eq!(
        caught(
            r#"var c = "no"; try { [1,2,3].reduceRight(function(a,b){ throw "rr"; }, 0); } catch (e) { c = e; } c;"#
        ),
        "rr",
    );
}

#[test]
fn reduce_crossed_throw_can_be_rethrown_to_outer_handler() {
    assert_eq!(
        caught(
            r#"var c = "no";
               try {
                 try { [1,2,3].reduce(function(a,b){ throw "inner"; }, 0); }
                 catch (e) { throw e + ":again"; }
               } catch (e2) { c = e2; }
               c;"#
        ),
        "inner:again",
    );
}

// --- Array.from mapper: the sibling legacy mini-lane (value preserved) --------

#[test]
fn array_from_mapper_throw_caught_with_original_value() {
    // `Array.from` runs its map fn through the same legacy mini-lane as the
    // reducer, so THIS (4.8) fix makes an explicit mapper `throw` carry the
    // ORIGINAL value ("map") rather than a re-boxed "unsupported instruction"
    // error.
    //
    // The follow-up bd-8enww.4.10 then closed the catchability routing gap noted
    // when this bead landed: `Array.from` is dispatched via the `builtin:ArrayFrom`
    // hostcall, which now routes an explicit callback throw through
    // `route_isolated_explicit_throw` just like the `Call`/`CallMethod` arms — so
    // the throw is CAUGHT by an enclosing `try`/`catch`, binding the original
    // value this 4.8 fix preserved. (Deeper catchability coverage lives in
    // `array_callback_catchability_bd_8enww_4_10.rs`.)
    assert_eq!(
        caught(
            r#"var c = "no"; try { Array.from([1,2,3], function(x){ throw "map"; }); } catch (e) { c = e; } c;"#
        ),
        "map",
    );
}

// --- modern lane (forEach/map) preserves the value already (regression guard) -

#[test]
fn foreach_callback_throw_string_binds_original_value() {
    assert_eq!(
        caught(
            r#"var c = "no"; try { [1,2,3].forEach(function(x){ throw "fe"; }); } catch (e) { c = e; } c;"#
        ),
        "fe",
    );
}

#[test]
fn map_callback_throw_error_object_preserves_message() {
    // The modern lane can construct and throw an Error object (the legacy
    // mini-lanes cannot build objects) — the message survives to the caller.
    assert_eq!(
        caught(
            r#"var c = "no"; try { [1,2,3].map(function(x){ throw new Error("boom"); }); } catch (e) { c = e.message; } c;"#
        ),
        "boom",
    );
}

// --- normal (non-throwing) folds are unaffected (regression guard) -----------

#[test]
fn reduce_without_throw_still_folds_normally() {
    assert_eq!(
        caught(r#"[1,2,3,4].reduce(function(a,b){ return a + b; }, 0);"#),
        "10",
    );
}

#[test]
fn reduce_catch_only_fires_on_throw_not_on_normal_return() {
    assert_eq!(
        caught(
            r#"var c = "no"; try { c = [10,20].reduce(function(a,b){ return a + b; }, 0); } catch (e) { c = "caught"; } c;"#
        ),
        "30",
    );
}

// --- fail-closed: an uncaught reducer throw still surfaces with the value ----

#[test]
fn uncaught_reduce_throw_surfaces_deterministically() {
    let m1 = uncaught(r#"[1,2,3].reduce(function(a,b){ throw "boom"; }, 0);"#);
    assert!(
        m1.contains("uncaught exception") && m1.contains("boom"),
        "uncaught reducer throw must surface carrying the value: {m1}",
    );
    // Deterministic: identical source ⇒ identical surfaced message.
    let m2 = uncaught(r#"[1,2,3].reduce(function(a,b){ throw "boom"; }, 0);"#);
    assert_eq!(m1, m2);
}
