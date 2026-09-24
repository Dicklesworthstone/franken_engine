//! String.prototype.replace / replaceAll: callable replacers and ES2020
//! GetSubstitution templates (`$1`, `$&`, `` $` ``, `$'`, `$$`).
//!
//! Before this, a replacer function was converted to its source-less string
//! ("[Function: closure0]") and `$1`-style templates were inserted literally,
//! so everyday idioms like `s.replace(/-(\w)/g, (m, c) => c.toUpperCase())`
//! produced garbage. Expected strings are what Node v22.2.0 prints for the
//! same programs.
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
fn callable_replacers() {
    check(
        "'aXbX'.replace('X', function (m) { return m.toLowerCase(); }) + '|' + \
         'ab'.replace(/(a)(b)/, function (m, p1, p2) { return p2 + p1; }) + '|' + \
         'aa'.replace(/a/g, function () { return 'b'; });",
        "axbX|ba|bb",
    );
    check(
        "'hello world'.replace(/o/g, '0') + '|' + \
         'x-y_z'.replace(/[-_](\\w)/g, function (m, c) { return c.toUpperCase(); });",
        "hell0 w0rld|xYZ",
    );
    // The replacer receives the match offset and the whole input.
    check(
        "var offs = []; 'xaxa'.replace(/a/g, function (m, off, s) { offs.push(off + s.length); \
         return m; }); offs.join();",
        "5,7",
    );
    // The first-class method value takes the same path.
    check(
        "var f = 'abc'.replace; f.call('abc', /b/, function () { return 'B'; });",
        "aBc",
    );
}

#[test]
fn substitution_templates() {
    check(
        "'John Smith'.replace(/(\\w+)\\s(\\w+)/, '$2, $1') + '|' + 'abc'.replace('b', '[$&]') + \
         '|' + 'abc'.replace('b', '[$`|$\\']') + '|' + 'a'.replace('a', '$$');",
        "Smith, John|a[b]c|a[a|c]c|$",
    );
}

#[test]
fn replace_all() {
    check(
        "'aaa'.replaceAll('a', 'b') + '|' + \
         'a.b.c'.replaceAll('.', function (m, off) { return off; }) + '|' + \
         'ab'.replaceAll('', '-');",
        "bbb|a1b3c|-a-b-",
    );
    check(
        "var r; try { 'a'.replaceAll(/a/, 'b'); r = 'no'; } catch (e) { r = e instanceof TypeError; } r;",
        "true",
    );
}
