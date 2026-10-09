//! Early errors of regular expression literals (ES2020 12.2.8.1).
//!
//! An invalid literal is a SyntaxError of the whole script, even in a
//! function that never runs. The engine compiled a literal only when it was
//! evaluated, so `function never() { return /(?<a>x)(?<a>y)/; }` ran and an
//! invalid literal elsewhere failed only when reached. Literals are now
//! checked at parse time: invalid or duplicate flags, and patterns that both
//! the backtracking parser and the `regex` crate reject. Verdicts are Node
//! v22.2.0's (`new Function(src)` throws SyntaxError / values below).
//!
//! No-claim: a literal either engine accepts is left to the runtime. The
//! backtracking parser is lenient in some `u`-mode corners (identity escapes
//! such as `\-` or `\a`), so those invalid literals still parse. Nested
//! quantifiers (`/a**/`, which the `regex` crate would compile) are refused
//! before either engine sees them (bd-9vouw.337).
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> Result<String, String> {
    HybridRouter::default()
        .eval(source)
        .map(|outcome| outcome.value)
        .map_err(|error| error.to_string())
}

#[test]
fn invalid_literals_are_early_syntax_errors() {
    for source in [
        "/a/gg",
        "/(?<a>x)(?<a>y)/",
        "/(?<1a>x)/",
        "/(?<a>x/",
        "/x{2,1}/",
        "/[z-a]/",
        "/\\p{Nope}/u",
        "/(/",
        "/a/uv",
        // Never evaluated, still refused.
        "function never() { return /(?<a>x)(?<a>y)/; } 1",
    ] {
        let error = eval(source).expect_err(source);
        assert!(
            error.contains("parse") && error.contains("Invalid"),
            "`{source}` must be an early SyntaxError, got {error}"
        );
    }
}

#[test]
fn valid_literals_still_run() {
    assert_eq!(
        eval(
            "[/a{/.test('a{'), /\\8/.test('8'), /]/.test(']'), /{/.test('{'), \
             /\\p{L}/u.test('é'), /(?<a>x)\\k<a>/.test('xx'), /[\\b]/.test('\\b'), \
             /x/v.test('x')].join()"
        ),
        Ok("true,true,true,true,true,true,true,true".to_string())
    );
}

/// `new RegExp(pattern, flags)` is a SyntaxError for invalid flags or a
/// pattern that does not parse (ES2020 21.2.3.2.2), with the literal's
/// rule; code validates user patterns this way. The constructor accepted
/// anything and failed only at the first match.
#[test]
fn the_constructor_throws_syntax_errors() {
    assert_eq!(
        eval(
            "function valid(p, f) { try { new RegExp(p, f); return true; } \
             catch (e) { return e instanceof SyntaxError ? false : 'other'; } } \
             [valid('['), valid('a', 'gg'), valid('(?<a>x)(?<a>y)'), valid('a('), valid('a+'), \
             valid('\\\\d{2,}', 'giu'), valid('x', 'uv'), valid('[a-z]', 'v')].join()"
        ),
        Ok("false,false,false,false,true,true,false,true".to_string())
    );
}

/// bd-9vouw.337: a quantifier right after another (after its optional lazy
/// `?`) has nothing to repeat (ES2020 21.2.1: a Term is an Atom with at most
/// one Quantifier). The `regex` crate compiled `a**` as `(a*)*`, so
/// `new RegExp('a**')` succeeded and the literal parsed (10 Node-passing
/// Test262 tests, built-ins/RegExp/S15.10.1_A1_T1..T6, T13..T16). One
/// quantifier with its lazy `?`, a `\u{10}` code point escape with `u`, and
/// a quantifier on a class or group stay valid. Verdicts and the message
/// are Node v22.2.0's.
#[test]
fn nested_quantifiers_are_syntax_errors() {
    for source in [
        "/a**/",
        "function never() { return /x{1}{1,}/; } 1",
        "/a+?+/",
    ] {
        let error = eval(source).expect_err(source);
        assert!(
            error.contains("parse") && error.contains("Nothing to repeat"),
            "`{source}` must be an early SyntaxError, got {error}"
        );
    }
    assert_eq!(
        eval(
            "function valid(p, f) { try { new RegExp(p, f); return true; } \
             catch (e) { return e instanceof SyntaxError ? e.message : 'other'; } } \
             [valid('a**'), valid('a***'), valid('a++'), valid('a+++'), valid('a???'), \
             valid('a????'), valid('x{1}{1,}'), valid('x{1,2}{1}'), valid('x{1,}{1}'), \
             valid('x{0,1}{1,}'), valid('a*?'), valid('a{1}?'), valid('\\\\u{10}*', 'u'), \
             valid('[*]+'), valid('(?:ab)+?')].join('|')"
        ),
        Ok("Invalid regular expression: /a**/: Nothing to repeat|\
            Invalid regular expression: /a***/: Nothing to repeat|\
            Invalid regular expression: /a++/: Nothing to repeat|\
            Invalid regular expression: /a+++/: Nothing to repeat|\
            Invalid regular expression: /a???/: Nothing to repeat|\
            Invalid regular expression: /a????/: Nothing to repeat|\
            Invalid regular expression: /x{1}{1,}/: Nothing to repeat|\
            Invalid regular expression: /x{1,2}{1}/: Nothing to repeat|\
            Invalid regular expression: /x{1,}{1}/: Nothing to repeat|\
            Invalid regular expression: /x{0,1}{1,}/: Nothing to repeat|\
            true|true|true|true|true"
            .to_string())
    );
}

/// Unicode property escapes take exactly the names ECMAScript defines
/// (ES2024 22.2.2.9): case-sensitive, no spaces, no `Is` prefix, no other
/// properties (`Block`), properties of strings only with `v` and never
/// negated, and always braced. The `regex` crate matches names loosely, so
/// `/\p{greek}/u` and `/\p{ Lu }/u` compiled. Without `u` or `v`, `\p` is an
/// identity escape. Verdicts and matches are Node v22.2.0's.
#[test]
fn unicode_property_names_are_exact() {
    for source in [
        "/\\p{greek}/u",
        "/\\p{ Lu }/u",
        "/\\p{Block=Basic_Latin}/u",
        "/\\P{Prepended_Concatenation_Mark}/u",
        "/\\p{IsScript=Adlam}/u",
        "/\\p{Script=greek}/u",
        "/\\pL/u",
        "/\\p{Lu/u",
        "/\\p{RGI_Emoji}/u",
        "/\\P{RGI_Emoji}/v",
    ] {
        let error = eval(source).expect_err(source);
        assert!(
            error.contains("parse") && error.contains("Invalid"),
            "`{source}` must be an early SyntaxError, got {error}"
        );
    }
    assert_eq!(
        eval(
            "[/\\p{Script=Greek}+/u.exec('αβγ')[0], /\\p{sc=Latn}/u.exec('x')[0], \
             /[\\p{Lu}\\p{Nd}]+/u.exec('A1b')[0], /\\P{ASCII}/u.exec('aé')[0], \
             /\\p{General_Category=Decimal_Number}/u.exec('٣')[0], /\\p{Alphabetic}/u.exec('ж')[0], \
             /\\p{gc=L}/u.exec('1b')[0], /\\p{greek}/.test('p{greek}')].join()"
        ),
        Ok("αβγ,x,A1,é,٣,ж,b,true".to_string())
    );
    assert_eq!(
        eval(
            "function valid(p, f) { try { new RegExp(p, f); return true; } \
             catch (e) { return e instanceof SyntaxError ? false : 'other'; } } \
             [valid('\\\\p{greek}', 'u'), valid('\\\\p{Script=Greek}', 'u'), valid('\\\\p{greek}')].join()"
        ),
        Ok("false,true,true".to_string())
    );
}

/// The surrogate category (`Cs`, `Surrogate`, `gc=Cs`) is a valid
/// General_Category value, but the `regex` crate does not know it, so the
/// literal failed to parse and `new RegExp('\\p{Cs}', 'u')` threw. ohm-js
/// builds that pattern for every category when it loads. Expected values are
/// Node v22.2.0's on the same source. No-claim: Node also matches `\p{Cs}`
/// against a lone surrogate string; that is not covered here.
#[test]
fn surrogate_category_escapes_compile() {
    assert_eq!(
        eval(
            "[/\\p{Cs}/u.test('a'), /^\\P{Cs}+$/u.test('ab😀'), /[\\p{Surrogate}b]/u.exec('ab')[0], \
             new RegExp('\\\\p{gc=Cs}', 'u').test('x'), /(?<=a)\\P{Cs}/u.exec('ab')[0], \
             ['Cs', 'Lu'].map(n => new RegExp('\\\\p{' + n + '}', 'u').test('A')).join('/')].join()"
        ),
        Ok("false,true,b,false,b,false/true".to_string())
    );
}
