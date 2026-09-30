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

// Look-around and backreferences run on the backtracking matcher
// (BRIDGE-16.2 slice); the `regex` crate cannot express them.

/// lodash's `stringToPath` over `rePropName` (`_.get(obj, 'a[0].b["c.d"].e')`).
#[test]
fn lodash_property_paths() {
    check(
        r#"var rePropName = /[^.[\]]+|\[(?:(-?\d+(?:\.\d+)?)|(["'])((?:(?!\2)[^\\]|\\.)*?)\2)\]|(?=(?:\.|\[\])(?:\.|\[\]|$))/g; var keys = []; 'a[0].b["c.d"].e'.replace(rePropName, function (match, number, quote, subString) { keys.push(quote ? subString : (number || match)); return ''; }); keys.join('|');"#,
        "a|0|b|c.d|e",
    );
}

#[test]
fn look_behind_and_backreferences() {
    check(
        r"['price: $42, tax $3'.match(/(?<=\$)\d+/g).join(), 'aaa bbb'.replace(/(\w)\1+/g, '<$&>'), /(?<!\$)\b\d+/.exec('$42 17')[0]].join(' ');",
        "42,3 <aaa> <bbb> 17",
    );
    check(
        r"var s = 'key=value; other=thing'; var out = []; var re = /(\w+)=(?=(\w+))/g; var m; while ((m = re.exec(s))) out.push(m[1] + ':' + m[2]); out.join(',');",
        "key:value,other:thing",
    );
}

#[test]
fn named_groups() {
    check(
        r"var m = /(?<year>\d{4})-(?<month>\d{2})/.exec('on 2024-01-15'); [m.index, m.groups.month, '2024-01'.replace(/(?<y>\d+)-(?<m>\d+)/, '$<m>/$<y>')].join(' ');",
        "3 01 01/2024",
    );
}

/// A global search resumes where the last match ended, or one character
/// later after an empty match; an empty match right after a match counts.
#[test]
fn global_iteration_follows_advance_string_index() {
    check(
        r"['abc'.replace(/b*/g, 'X'), 'abc'.match(/b*/g).length, 'a1b22'.split(/\d*/).join('|'), 'x'.replace(/(?:)/g, '-')].join(' ');",
        "XaXXcX 4 a|b| -x-",
    );
}

/// `search`/`match` compile a non-RegExp argument as a pattern, and report
/// UTF-16 indices.
#[test]
fn string_arguments_are_patterns_and_indices_are_utf16() {
    check(
        r"['a.b'.search('.'), 'é1'.search('1'), 'a.b'.match('.')[0], 'é1'.search(/\d/)].join(',');",
        "0,1,a,1",
    );
}

/// Without look-around, `(a+)+b` runs on the `regex` automaton in linear
/// time (Node backtracks about 2^30 steps to the same `false`). With an
/// empty look-ahead it needs the backtracking matcher, which stops at its
/// step budget with a catchable RangeError where Node keeps backtracking.
#[test]
fn catastrophic_backtracking_is_a_range_error() {
    check(r"/(a+)+b/.test('a'.repeat(30));", "false");
    check(
        r"var r; try { r = /(a+)+b(?=)/.test('a'.repeat(30)); } catch (e) { r = e instanceof RangeError; } r;",
        "true",
    );
}
