//! Regression: Array.prototype findLast/findLastIndex (ES2023), flatMap
//! (ES2019), and copyWithin (ES2015) were unwired in the array_prototype_method
//! seam, so each faulted "expected function, got undefined".
//!
//! Beads: bd-isqzc (findLast/findLastIndex/flatMap) + bd-xjkup (copyWithin),
//! found via JadeOx eval-probe sweep. FIX: add each via the 5-part array seam.
//! findLast/findLastIndex mirror find/findIndex but iterate in reverse; flatMap
//! maps then flattens one level (reusing array_flatten_into at depth 0);
//! copyWithin snapshots the source slice then writes in place.

use frankenengine_engine::HybridRouter;

fn ev(src: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(src) {
        Ok(o) => o.value,
        Err(e) => format!("ERR:{e}"),
    }
}

#[test]
fn find_last_returns_last_match() {
    assert_eq!(ev("[1,2,3,4].findLast(x=>x<3)"), "2");
}

#[test]
fn find_last_no_match_undefined() {
    assert_eq!(ev("[1,2].findLast(x=>x>5)"), "undefined");
}

#[test]
fn find_last_index_returns_last_match_index() {
    assert_eq!(ev("[1,2,3,4].findLastIndex(x=>x<3)"), "1");
}

#[test]
fn find_last_index_no_match_minus_one() {
    assert_eq!(ev("[1,2].findLastIndex(x=>x>5)"), "-1");
}

#[test]
fn flat_map_spreads_array_results() {
    assert_eq!(
        ev("[1,2,3].flatMap(x=>[x,x*10]).join(',')"),
        "1,10,2,20,3,30"
    );
}

#[test]
fn flat_map_appends_scalar_results() {
    assert_eq!(ev("[1,2].flatMap(x=>x*2).join(',')"), "2,4");
}

#[test]
fn flat_map_only_one_level() {
    // inner nesting beyond one level is preserved (flatMap flattens one level).
    assert_eq!(ev("[1].flatMap(x=>[[x]]).length"), "1");
}

#[test]
fn copy_within_basic() {
    assert_eq!(ev("[1,2,3,4,5].copyWithin(0,3).join(',')"), "4,5,3,4,5");
}

#[test]
fn copy_within_with_end() {
    assert_eq!(ev("[1,2,3,4,5].copyWithin(0,3,4).join(',')"), "4,2,3,4,5");
}

#[test]
fn copy_within_negative_start() {
    assert_eq!(ev("[1,2,3,4,5].copyWithin(0,-2).join(',')"), "4,5,3,4,5");
}

#[test]
fn copy_within_returns_array() {
    assert_eq!(ev("[1,2,3].copyWithin(0,1).length"), "3");
}

#[test]
fn existing_find_unaffected() {
    assert_eq!(ev("[1,2,3,4].find(x=>x>2)"), "3");
    assert_eq!(ev("[1,2,3].map(x=>x*2).join(',')"), "2,4,6");
}
