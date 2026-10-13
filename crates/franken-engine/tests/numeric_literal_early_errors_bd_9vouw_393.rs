//! bd-9vouw.393: a token spelled like a number that is not a NumericLiteral
//! (`0x`, `0xG`, `0b2`, `0o9`, `00b0`, separators after a leading zero, a
//! prefix or another separator, an escaped separator, `1e`), a BigInt with a
//! leading zero (`08n`, `00n`) or a fraction (`1.5n`), and a legacy octal or
//! leading-zero literal in strict code are SyntaxErrors at parse time. Each
//! case compiles with Function(), so the error is caught. Valid forms (`1.`,
//! `.5`, prefixes, separators, sloppy `010` and `08.5`, BigInts, member
//! access on numbers) still evaluate. The engine deferred most of these to
//! a runtime error and accepted `08n` and strict `010`. The lines are Node
//! v22.2.0's.

use frankenengine_engine::HybridRouter;

#[test]
fn invalid_numeric_literals_are_syntax_errors() {
    let source = r#"
var r = [];
function t(n, src) { try { Function(src); r.push(n + ":ok"); } catch (e) { r.push(n + "!" + e.name); } }
t("hex-no-digits", "return 0x");
t("hex-bad-digit", "return 0xG");
t("binary-bad-digit", "return 0b2");
t("binary-no-digits", "return 0b");
t("octal-bad-digit", "return 0o9");
t("binary-after-zero", "return 00b0");
t("separator-after-zero", "return 0_1");
t("double-separator", "return 1__0");
t("trailing-separator", "return 1_");
t("separator-after-prefix", "return 0b_1");
t("separator-in-fraction-start", "return 1._5");
t("escaped-separator", "return 1\\u005F0");
t("bigint-leading-zero", "return 08n");
t("bigint-legacy-octal", "return 00n");
t("bigint-fraction", "return 1.5n");
t("strict-legacy-octal", "'use strict'; return 010");
t("strict-leading-zero", "'use strict'; return 08");
t("sloppy-legacy-octal", "return 010");
t("exponent-no-digits", "return 1e");
var f = 1..toString, g = 5 .toFixed, h = 1.5e3.valueOf;
var ok = [1., .5, 5.e2, 0x1F, 0o17, 0b101, 1_000, 0.0_1, 1e-3, 08.5, 010, 0n, 0x1fn, 1_0n];
console.log(r.join(" | "));
console.log(typeof f, typeof g, typeof h, ok.join(), 2..valueOf(), 0.5.toFixed(1));
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
            "hex-no-digits!SyntaxError | hex-bad-digit!SyntaxError | binary-bad-digit!SyntaxError | binary-no-digits!SyntaxError | octal-bad-digit!SyntaxError | binary-after-zero!SyntaxError | separator-after-zero!SyntaxError | double-separator!SyntaxError | trailing-separator!SyntaxError | separator-after-prefix!SyntaxError | separator-in-fraction-start!SyntaxError | escaped-separator!SyntaxError | bigint-leading-zero!SyntaxError | bigint-legacy-octal!SyntaxError | bigint-fraction!SyntaxError | strict-legacy-octal!SyntaxError | strict-leading-zero!SyntaxError | sloppy-legacy-octal:ok | exponent-no-digits!SyntaxError",
            "function function function 1,0.5,500,31,15,5,1000,0.01,0.001,8.5,8,0,31,10 2 0.5",
        ]
    );
}
