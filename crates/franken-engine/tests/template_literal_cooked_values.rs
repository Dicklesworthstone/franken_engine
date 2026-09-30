//! Template literals evaluate to their cooked template value (ES2020
//! 11.8.6.1): escapes decode as in string literals, a backslash before a
//! line break is a line continuation, and a literal CR LF or CR is LF.
//!
//! The parser keeps quasis raw (a tagged template reads them as `.raw`) and
//! lowering loaded them as they were, so an untagged template kept every
//! escape as written: `a\nb` was the four characters `a`, `\`, `n`, `b`,
//! and a template that builds a RegExp source or a Windows path kept each
//! backslash doubled (luxon's ISO zone pattern failed to compile).
//! Expected strings are what Node v22.2.0 prints for the same programs.
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
fn escapes_cook_in_untagged_templates() {
    check(
        r"JSON.stringify(`a\nb\tc`) + ':' + `a\nb`.length;",
        r#""a\nb\tc":3"#,
    );
    check(r"`a\\[b`.length + ':' + `a\\[b`;", r"4:a\[b");
    check(r"JSON.stringify(`\x41\u0042\u{43}\0`);", r#""ABC\u0000""#);
    check(r#"`q\`r\$s\{t\'u\" v`;"#, r#"q`r$s{t'u" v"#);
    check(
        r"var dir = 'Users'; `C:\\${dir}\\x` + ':' + `${dir}\n`.length;",
        r"C:\Users\x:6",
    );
}

#[test]
fn a_template_built_regexp_source_keeps_single_backslashes() {
    // luxon builds its ISO zone pattern this way.
    check(
        r"var s = 'S'; var src = `(?:${s}?(?:\\[(${s})\\])?)?`; src + ' ' + new RegExp(src).test('S[S]') + ' ' + new RegExp(src).exec('S[S]')[1];",
        r"(?:S?(?:\[(S)\])?)? true S",
    );
}

#[test]
fn line_continuations_and_line_terminators() {
    // `\` then a line break contributes nothing; a CR LF or CR in the
    // template text is LF.
    check("JSON.stringify(`x\\\ny`);", r#""xy""#);
    check("JSON.stringify(`x\\\r\ny`);", r#""xy""#);
    check("JSON.stringify(`a\r\nb\rc`);", r#""a\nb\nc""#);
}

#[test]
fn surrogate_escapes() {
    // A lone surrogate escape is one code unit; a pair is one code point.
    check(
        r"(`\uD83D\uDE00` === '\u{1F600}') + ':' + `\uD83D`.length + ':' + `\uD83D`.charCodeAt(0);",
        r"true:1:55357",
    );
}

#[test]
fn tagged_templates_see_cooked_and_raw_strings() {
    check(
        r"function t(s) { return JSON.stringify([s[0], s.raw[0]]); } t`a\nb\\c`;",
        r#"["a\nb\\c","a\\nb\\\\c"]"#,
    );
    check(
        "function t(s) { return JSON.stringify([s[0], s.raw[0].length]); } t`x\\\ny`;",
        r#"["xy",4]"#,
    );
}
