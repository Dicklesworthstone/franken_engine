//! bd-9vouw.395: a unary operator before the base of `**` (`-3 ** 2`,
//! `typeof 1 ** 2`, `3 * -b ** 2`, `2 ** -3 ** 2`) and `??` mixed with
//! `&&` / `||` without parentheses are SyntaxErrors (ES2016 12.6, ES2020
//! 12.13), while `2 ** -3`, `(-3) ** 2`, `++x ** 2`, `x++ ** 2`, a `??`
//! chain and parenthesized mixes evaluate. The engine evaluated the invalid
//! forms (`-3 ** 2` gave 9). Each case compiles with Function(). The line is
//! Node v22.2.0's.

use frankenengine_engine::HybridRouter;

#[test]
fn unary_exponent_bases_and_mixed_nullish_are_syntax_errors() {
    let source = r#"
var r = [];
function t(n, src) { try { var v = Function(src)(); r.push(n + "=" + v); } catch (e) { r.push(n + "!" + e.name); } }
t("neg-base", "return -3 ** 2");
t("typeof-base", "return typeof 1 ** 2");
t("not-base", "return !1 ** 2");
t("bitnot-base", "return ~3 ** 2");
t("plus-base", "return +1 ** 2");
t("delete-base", "var o = {p: 1}; return delete o.p ** 2");
t("void-base", "return void 0 ** 2");
t("neg-exponent", "return 2 ** -3");
t("neg-in-chain", "return 2 ** -3 ** 2");
t("paren-base", "return (-3) ** 2");
t("preinc-base", "var x = 2; return ++x ** 2");
t("postinc-base", "var x = 2; return x++ ** 2");
t("mul-neg-pow", "var b = 2; return 3 * -b ** 2");
t("and-nullish", "return 0 && 0 ?? true");
t("or-nullish", "return 0 || 0 ?? true");
t("nullish-and", "return 0 ?? 0 && true");
t("nullish-or", "return 0 ?? 0 || true");
t("paren-mix", "return (0 || 0) ?? true");
t("nullish-chain", "return null ?? undefined ?? 3");
t("nested-paren-mix", "return 0 ?? (0 || 7)");
console.log(r.join(" | "));
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
            "neg-base!SyntaxError | typeof-base!SyntaxError | not-base!SyntaxError | bitnot-base!SyntaxError | plus-base!SyntaxError | delete-base!SyntaxError | void-base!SyntaxError | neg-exponent=0.125 | neg-in-chain!SyntaxError | paren-base=9 | preinc-base=9 | postinc-base=4 | mul-neg-pow!SyntaxError | and-nullish!SyntaxError | or-nullish!SyntaxError | nullish-and!SyntaxError | nullish-or!SyntaxError | paren-mix=0 | nullish-chain=3 | nested-paren-mix=0",
        ]
    );
}
