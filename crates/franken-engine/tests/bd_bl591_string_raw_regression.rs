//! Regression coverage for bd-bl591: `String.raw` was unwired — the bare
//! `String` global has no eval-scope binding, so `String.raw` resolved to
//! `undefined` and faulted ("expected object, got undefined"). It is now routed
//! through the slot-0 static-builtin lowering interception to a `builtin:StringRaw`
//! handler that reads the template's `.raw` array and interleaves substitutions.

use frankenengine_engine::HybridRouter;

fn eval(src: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(src) {
        Ok(outcome) => format!("{}", outcome.value),
        Err(err) => format!("ERR={err}"),
    }
}

#[test]
fn string_raw_tag_preserves_escapes_without_substitution() {
    // Raw form keeps the backslash literal (does NOT cook \n into a newline).
    assert_eq!(eval("String.raw`Hi\\n`;"), "Hi\\n");
    assert_eq!(eval("String.raw`a\\tb`;"), "a\\tb");
}

#[test]
fn string_raw_tag_interleaves_substitutions() {
    assert_eq!(eval("String.raw`a${1 + 1}b`;"), "a2b");
    assert_eq!(eval("String.raw`\\t${1}x${2}`;"), "\\t1x2");
    assert_eq!(eval("let n = 7; String.raw`v=${n}`;"), "v=7");
}

#[test]
fn string_raw_direct_call_reads_raw_property() {
    assert_eq!(
        eval("String.raw({ raw: [\"a\", \"b\", \"c\"] }, \"-\", \"+\");"),
        "a-b+c"
    );
    assert_eq!(eval("String.raw({ raw: [\"x\", \"y\"] }, \"Z\");"), "xZy");
}

#[test]
fn string_raw_empty_or_missing_raw_yields_empty_string() {
    assert_eq!(eval("String.raw({});"), "");
    assert_eq!(eval("String.raw({ raw: [] });"), "");
}

#[test]
fn string_raw_is_shadowable() {
    // A user binding named `String` suppresses the static interception, so the
    // user's own `raw` is invoked instead of the builtin.
    assert_eq!(
        eval("let String = { raw: () => 9 }; String.raw`anything`;"),
        "9"
    );
}
