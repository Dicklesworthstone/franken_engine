//! bd-9vouw.89: JavaScript RegExp syntax on the `regex` crate.
//!
//! Patterns valid in JavaScript were rejected ("unclosed character class",
//! "hexadecimal literal is not a Unicode scalar value") or matched with
//! `regex` semantics (Unicode `\w`). lodash 4.17.21 died at load on
//! `reRegExpChar`, and dayjs customParseFormat's format regex failed to
//! compile. Expected strings are what Node v22.2.0 prints.
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

/// lodash's `escapeRegExp` pattern: `[` inside a class is a literal.
#[test]
fn brackets_inside_a_class_are_literals() {
    check(
        r"'a.b*c(d)[e]{f}'.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&');",
        r"a\.b\*c\(d\)\[e\]\{f\}",
    );
}

/// dayjs customParseFormat tokenizes a format string with this pattern.
#[test]
fn dayjs_custom_parse_format_tokens() {
    check(
        r"'YYYY-MM-DD [at] HH:mm'.match(/(\[[^[]*\])|([-_:/.,()\s]+)|(A|a|Q|YYYY|YY?|ww?|MM?M?M?|Do|DD?|hh?|HH?|mm?|ss?|S{1,3}|z|ZZ?)/g).join('|');",
        "YYYY|-|MM|-|DD| |[at]| |HH|:|mm",
    );
}

#[test]
fn character_class_escapes_are_ascii() {
    check(
        r"[/^\w*$/.test('café'), /\W/.test('é'), /\d/.test('٣'), /^\s$/.test('\uFEFF'), /\bfoo\b/.test('éfooé')].join();",
        "false,true,false,true,true",
    );
}

#[test]
fn dot_braces_and_empty_matches() {
    check(
        r"[/^.$/.test('\r'), /^.$/s.test('\r'), /a{b/.test('a{b'), 'x{{y}}z'.replace(/{{([\s\S]+?)}}/, '$1')].join();",
        "false,true,true,xyz",
    );
}

/// lodash's astral-range idioms, as literals and through `RegExp(...)`.
#[test]
fn surrogate_escapes_match_supplementary_characters() {
    check(
        r"[/[\ud800-\udfff]/.test('a😀'), /[\ud800-\udfff]/.test('abc'), /^[\ud800-\udbff][\udc00-\udfff]$/.test('😀'), /\ud83c[\udffb-\udfff]/.test('👍🏽'), new RegExp('[\\u200d\\ud800-\\udfff]').test('x😀')].join();",
        "true,false,true,true,true",
    );
}

#[test]
fn unicode_flag_and_control_escapes() {
    check(
        r"[/\u{1F600}/u.test('😀'), /^\u{3}$/.test('uuu'), /^[+--]+$/.test('+,-'), /^\cJ$/.test('\n'), /^[\b]$/.test('\b')].join();",
        "true,true,true,true,true",
    );
}
