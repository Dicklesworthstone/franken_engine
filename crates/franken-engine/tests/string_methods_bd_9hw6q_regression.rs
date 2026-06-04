//! Regression: String.prototype trimStart/trimEnd (ES2019), replaceAll
//! (ES2021), and codePointAt (ES2015) were unwired in the string member-access
//! seam, so `'  x'.trimStart()` etc. faulted "expected function, got undefined".
//!
//! Bead: bd-9hw6q (found via JadeOx eval-probe sweep). FIX: add each via the
//! 5-part string seam (enum variant + ctor + name + execution arm +
//! string_property_value dispatch). replaceAll handles string search values
//! (the common case); codePointAt uses Unicode scalar offsets, consistent with
//! this engine's other string methods.

use frankenengine_engine::HybridRouter;

fn ev(src: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(src) {
        Ok(o) => o.value,
        Err(e) => format!("ERR:{e}"),
    }
}

#[test]
fn trim_start() {
    assert_eq!(ev("'   hi'.trimStart()"), "hi");
}

#[test]
fn trim_start_keeps_trailing() {
    assert_eq!(ev("'  hi  '.trimStart()"), "hi  ");
}

#[test]
fn trim_end() {
    assert_eq!(ev("'hi   '.trimEnd()"), "hi");
}

#[test]
fn trim_end_keeps_leading() {
    assert_eq!(ev("'  hi  '.trimEnd()"), "  hi");
}

#[test]
fn replace_all_replaces_every_occurrence() {
    assert_eq!(ev("'aaa'.replaceAll('a','b')"), "bbb");
}

#[test]
fn replace_all_multichar() {
    assert_eq!(ev("'a-b-c'.replaceAll('-','_')"), "a_b_c");
}

#[test]
fn replace_all_no_match_unchanged() {
    assert_eq!(ev("'abc'.replaceAll('x','y')"), "abc");
}

#[test]
fn code_point_at_basic() {
    assert_eq!(ev("'A'.codePointAt(0)"), "65");
}

#[test]
fn code_point_at_index() {
    assert_eq!(ev("'ABC'.codePointAt(2)"), "67");
}

#[test]
fn code_point_at_out_of_range() {
    assert_eq!(ev("'A'.codePointAt(5)"), "undefined");
}

#[test]
fn code_point_at_default_index() {
    assert_eq!(ev("'Z'.codePointAt()"), "90");
}

#[test]
fn existing_trim_unaffected() {
    assert_eq!(ev("'  hi  '.trim()"), "hi");
}
