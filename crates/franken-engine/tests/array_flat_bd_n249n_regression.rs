//! Regression: `Array.prototype.flat` (ES2019) was not wired into the
//! `array_prototype_method` seam, so `[[1],[2,3]].flat()` faulted with
//! "expected function, got undefined".
//!
//! Bead: bd-n249n (found via JadeOx eval-probe sweep). FIX: add it mirroring
//! `Array.prototype.concat`/`at` — BuiltinFunctionKind::ArrayFlat + array_flat()
//! ctor + "flat" name + a receiver-aware execution arm (recursive
//! `array_flatten_into` up to `depth`, default 1, `Infinity` => fully flatten) +
//! wire "flat" in array_prototype_method. Purely additive.

use frankenengine_engine::HybridRouter;

fn ev(src: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(src) {
        Ok(o) => o.value,
        Err(e) => format!("ERR:{e}"),
    }
}

#[test]
fn flat_default_depth_one_length() {
    assert_eq!(ev("[[1],[2,3]].flat().length"), "3");
}

#[test]
fn flat_default_depth_one_values() {
    assert_eq!(ev("[[1],[2,3]].flat().join(',')"), "1,2,3");
}

#[test]
fn flat_default_only_one_level() {
    // depth defaults to 1: the inner [3,[4]] stays nested -> 3 top-level elems.
    assert_eq!(ev("[1,[2,[3,[4]]]].flat().length"), "3");
}

#[test]
fn flat_explicit_depth_two() {
    assert_eq!(ev("[1,[2,[3]]].flat(2).join(',')"), "1,2,3");
}

#[test]
fn flat_infinity_fully_flattens() {
    assert_eq!(ev("[1,[2,[3,[4]]]].flat(Infinity).join(',')"), "1,2,3,4");
}

#[test]
fn flat_no_nesting_is_shallow_copy() {
    assert_eq!(ev("[1,2,3].flat().join(',')"), "1,2,3");
}

#[test]
fn flat_empty_array() {
    assert_eq!(ev("[].flat().length"), "0");
}

#[test]
fn flat_depth_zero_keeps_nesting() {
    // flat(0) flattens nothing: still 2 top-level elements, both arrays.
    assert_eq!(ev("[[1],[2,3]].flat(0).length"), "2");
}

#[test]
fn flat_mixed_scalar_and_array() {
    assert_eq!(ev("[1,[2,3],4].flat().join(',')"), "1,2,3,4");
}
