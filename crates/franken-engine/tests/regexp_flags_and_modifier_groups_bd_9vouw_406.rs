//! bd-9vouw.406: a regular expression literal's flags are every
//! IdentifierPart character after its closing slash (ES2020 11.8.5), so
//! `/./G`, `/./\u0067`, `/a/gg` and `/a/instanceof` are SyntaxErrors, and a
//! group that opens with `(?` must be a lookaround, a named or non-capturing
//! group, or a modifier group `(?ims-ims:...)` (ES2025 22.2.1). The engine
//! stopped the flags at the first other letter (leaving a stray name) and
//! took `(?ms-i)`, `(?-s)` and `(?u:a)` as the `regex` crate's own flag
//! groups. Valid flags, groups and divisions still compile and run. The
//! lines are Node v22.2.0's.

use frankenengine_engine::HybridRouter;

#[test]
fn regexp_flags_and_group_openers_are_checked_at_parse_time() {
    let source = r#"
var cases = ["x = /./G;", "x = /./\\u0067;", "x = /a/gg;", "x = /a/instanceof RegExp;", "x = /(?ms-i)/;", "x = /(?-s)/;", "x = /(?-u:a)/;", "x = /(?u:a)/;", "x = /(?ii:a)/;", "x = /(?-:a)/;", "x = /a/gimsy;", "x = /a/dgimsy;", "x = /a/v;", "x = /a/g.test('a');", "x = /a/ instanceof RegExp;", "x = /(?:a)(?=b)(?!c)/;", "x = /(?<n>a)(?<=a)(?<!b)/;", "x = /[(?ms)]/;", "x = 4 /2/ 1;", "x = /a/g\n.source;"];
console.log(cases.map(function (s, i) { try { Function(s); return i + ':ok'; } catch (e) { return i + ':' + e.name; } }).join(' '));
console.log(/a/g.flags, /b/.source, /(?:x)y/.exec('xy')[0], 'aB'.replace(/b/i, 'c'), 8 /2/ 2);
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "0:SyntaxError 1:SyntaxError 2:SyntaxError 3:SyntaxError 4:SyntaxError 5:SyntaxError 6:SyntaxError 7:SyntaxError 8:SyntaxError 9:SyntaxError 10:ok 11:ok 12:ok 13:ok 14:ok 15:ok 16:ok 17:ok 18:ok 19:ok",
            "g b xy ac 2",
        ]
    );
}
