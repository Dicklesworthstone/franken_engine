//! Regression: `new Map()` / `new Set()` must expose their prototype methods
//! (set/get/has/delete/size; add/has/delete/clear/size) via member access.
//!
//! Bead: bd-juodx. REPRO (`HybridRouter::eval`): `let m = new Map();
//! m.set('a', 1); m.get('a');` faults "expected function, got undefined" —
//! `m.set` resolves to undefined.
//!
//! ROOT CAUSE + FIX PLAN (JadeHarbor): the method bodies ALREADY exist as
//! builtins (MapPrototypeSet/Get/Has/Delete, SetPrototypeAdd/Has/Delete/Clear),
//! and `new Map()/new Set()` construct an object tagged with a `__type` data
//! property (Map/Set) holding an internal `__entries`. The GAP is purely
//! member-access resolution: `prototype_chain_get_property_descriptor` has an
//! `is_array` fallback returning `array_prototype_method(key)` but NO Map/Set
//! equivalent. FIX (interpreter, baseline-only, mirrors the array seam): add a
//! `map_set_prototype_method(key, kind)` seam, detect kind via `__type` right
//! after the is_array block, and special-case the `size` GETTER (return the
//! entry count, not a function). baseline_interpreter.rs is leased by another
//! agent at staging time; these cases are `#[ignore]`d until it lands.
//!
//! They assert VALUES (not just `eval == Ok`).

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn map_set_then_get() {
    assert_eq!(
        eval_value("let m = new Map(); m.set('a', 1); m.get('a')"),
        "1"
    );
}

#[test]
fn map_has_and_size() {
    assert_eq!(
        eval_value("let m = new Map(); m.set('a', 1); m.set('b', 2); m.has('a') ? m.size : -1"),
        "2"
    );
}

#[test]
fn set_add_dedups_and_has() {
    assert_eq!(
        eval_value("let s = new Set(); s.add(1); s.add(1); s.has(1) ? s.size : -1"),
        "1"
    );
}

#[test]
fn map_delete_removes_entry() {
    assert_eq!(
        eval_value("let m = new Map(); m.set('a', 1); m.delete('a'); m.has('a')"),
        "false"
    );
}
