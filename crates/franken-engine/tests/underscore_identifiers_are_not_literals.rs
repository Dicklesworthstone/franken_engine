//! Identifiers that start with `_` followed by digits or `n` (`_n`, `_1`,
//! `_0x1f`, `__n`) were read as numeric literals: the literal parsers
//! removed every `_` (numeric separators) before looking at the digits, so
//! `_n` became `0n`, `_1` became 1 and `_0x1f` became 31, and `_n++` failed
//! to parse ("invalid update target"). Babel's `_createForOfIteratorHelper`
//! (`value: r[_n++]`, in validator.js and most Babel-compiled packages) and
//! obfuscator output (`_0x…` names) stopped there. A literal starts with a
//! digit and a separator sits between two digits. Expected strings are Node
//! v22.2.0's completion values for the same programs.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn check(source: &str, node: &str) {
    let value = match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    };
    assert_eq!(value, node, "`{source}` must match Node v22.2.0");
}

#[test]
fn underscore_identifiers_are_bindings_and_separators_still_work() {
    check(
        "var _n = 5, _1 = 7, _0x1f = 3, __n = 2; \
         [_n, _1, _0x1f, __n, _n++, _n, 1_000, 0xFF_FF, 1_000n, 1_000.5].join()",
        "5,7,3,2,5,6,1000,65535,1000,1000.5",
    );
    check(
        "function _0x2a(_0x1) { return _0x1 * 2; } var _0xab = _0x2a(21); [_0xab, typeof _0x2a].join()",
        "42,function",
    );
}

/// Babel's iterator helper, as bundled into validator.js.
#[test]
fn babel_iterator_helper_increments_its_index() {
    check(
        "var r = [1, 2], _n = 0; var f = function() { return _n >= r.length ? { done: true } : \
         { done: false, value: r[_n++] }; }; JSON.stringify([f(), f(), f()])",
        "[{\"done\":false,\"value\":1},{\"done\":false,\"value\":2},{\"done\":true}]",
    );
}
