//! bd-9vouw.40 and siblings: `String.prototype.split` with a RegExp or
//! non-string separator and a `limit`, `new RegExp(pattern, flags)`,
//! functions answering `hasOwnProperty`/`propertyIsEnumerable` for their own
//! properties, and Number.prototype methods requiring a Number receiver
//! (thisNumberValue).
//!
//! Before this, a RegExp separator returned the whole string as one
//! element, `limit` was ignored, `RegExp` was not defined, `F.hasOwnProperty`
//! was undefined, and `toExponential` coerced any receiver. Expected strings
//! are what Node v22.2.0 prints for the same programs.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

#[test]
fn split_with_regexp_separators() {
    check(
        "'a,b'.split(/,/).length + ':' + 'a1b2c'.split(/(\\d)/).join('|') + ':' + \
         'a b  c'.split(/\\s+/).join('|');",
        "2:a|1|b|2|c:a|b|c",
    );
    // A comma inside a regex literal does not split declarations or
    // argument lists.
    check(
        "var r = /,/, n = 2; 'a,b'.split(r).length + n + ':' + ['x', /[,]/.source, 'y'].length;",
        "4:3",
    );
    // Empty matches split between characters, never at either end.
    check(
        "'abc'.split(/(?:)/).join('|') + ':' + 'aXXb'.split(/X*/).join('|') + ':' + \
         ''.split(/,/).length + ':' + ''.split(/(?:)/).length;",
        "a|b|c:a|b:1:0",
    );
}

#[test]
fn split_limit_and_non_string_separators() {
    check(
        "'a,b,c'.split(',', 2).join('|') + ':' + 'a,b,c'.split(/,/, 1).join('|') + ':' + \
         'a,b'.split(',', 0).length;",
        "a|b:a:0",
    );
    check("'a1b1c'.split(1).join('|');", "a|b|c");
}

#[test]
fn regexp_constructor() {
    check(
        "var r = new RegExp('a+', 'g'); r.test('baa') + ':' + r.source + ':' + r.flags;",
        "true:a+:g",
    );
    check(
        "var r = new RegExp(/x\\d/i); r.test('X5') + ':' + r.flags;",
        "true:i",
    );
}

#[test]
fn functions_answer_own_property_queries() {
    check(
        "function F() {} F.x = 1; F.hasOwnProperty('x') + ':' + F.hasOwnProperty('y') + ':' + \
         F.propertyIsEnumerable('x');",
        "true:false:true",
    );
}

#[test]
fn number_methods_require_a_number_receiver() {
    check(
        "var r; try { Number.prototype.toExponential.call({}); r = 'no'; } \
         catch (e) { r = e instanceof TypeError; } r;",
        "true",
    );
    check(
        "var r; try { Number.prototype.toPrecision.call('5', 1); r = 'no'; } \
         catch (e) { r = e instanceof TypeError; } r;",
        "true",
    );
}
