//! JavaScript RegExp patterns were handed to the `regex` crate verbatim.
//! The two spell some meanings differently, so the usual escapeRegExp
//! (`/[.*+?^${}()|[\]\\]/g`, in lodash, path-to-regexp and countless
//! helpers) failed to compile (`[` inside a class opens a nested class in
//! `regex`), a literal `{` failed, `\d`/`\w` matched non-ASCII digits and
//! letters, and `.` matched `\r` and U+2028. Patterns are now translated
//! first. Expected strings are Node v22.2.0's completion values.
//!
//! No-claim: lone surrogate escapes (`[\uD800-\uDBFF]`), look-around and
//! backreferences still fail to compile (BRIDGE-16.1); `\b`, `\s` and `\D`
//! inside a class keep the `regex` crate's Unicode meaning.
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
fn escape_regexp_helpers_compile() {
    check(
        r#"'a.b*c(d)[e]{f}|g/h\\i'.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')"#,
        r#"a\.b\*c\(d\)\[e\]\{f\}\|g/h\\i"#,
    );
    check(
        r#"'^$.*+?()[]{}|'.replace(/[\\^$.*+?()[\]{}|]/g, '\\$&')"#,
        r#"\^\$\.\*\+\?\(\)\[\]\{\}\|"#,
    );
}

#[test]
fn literal_braces_and_quantifiers() {
    check(
        r#"[/a{/.test('a{'), /{}/.test('{}'), /x{2}/.test('xx'), /x{2,}/.test('x'), /\${(\w+)}/.exec('${name}')[1]].join()"#,
        "true,true,true,false,name",
    );
}

#[test]
fn digit_word_and_dot_classes_are_javascripts() {
    check(
        r#"[/^\d+$/.test('١٢'), /^\d+$/.test('42'), /^\w+$/.test('é'), /^\w+$/.test('a_1'), /\D/.test('١'), /[\d]/.test('7')].join()"#,
        "false,true,false,true,true,true",
    );
    check(
        r#"[/a.b/.test('a\rb'), /a.b/s.test('a\rb'), /a.b/.test('a b'), /a.b/.test('a-b'), /a.b/.test('a\nb')].join()"#,
        "false,true,false,true,false",
    );
    check(
        r#"[/a[^]b/.test('a\nb'), /a[]b/.test('ab'), /[&&]/.test('&'), /[~~]/.test('~'), /\0/.test('\0'), /a\/b/.test('a/b')].join()"#,
        "true,false,true,true,true,true",
    );
}
