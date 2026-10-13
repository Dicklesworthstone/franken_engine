//! bd-9vouw.401: with the RegExp `u` flag a `{` that starts no quantifier,
//! a lone `}` or `]`, and a class range with a class escape end are
//! SyntaxErrors (from `new RegExp` and as a literal); without `u` Annex B
//! keeps them literal. Expected line is Node v22.2.0's output.

use frankenengine_engine::HybridRouter;

#[test]
fn unicode_mode_lone_brackets_and_escape_ranges_are_syntax_errors() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + "=" + f()); } catch (e) { out.push(name + "!" + e.name); } }
t("open-brace", function () { return new RegExp("a{", "u").test("a{"); });
t("partial-quantifier", function () { return new RegExp("a{1,", "u").test("a"); });
t("lone-close-brace", function () { return new RegExp("a}", "u").test("a}"); });
t("lone-bracket", function () { return new RegExp("]", "u").test("]"); });
t("escape-range-start", function () { return new RegExp("[\\d-z]", "u").test("q"); });
t("escape-range-end", function () { return new RegExp("[a-\\p{Hex}]", "u").test("b"); });
t("literal-brace", function () { return Function("return /x{/u;")(); });
t("annexb-brace", function () { return new RegExp("a{", "").test("a{"); });
t("annexb-range", function () { return new RegExp("[\\d-z]", "").test("-"); });
t("quantifier", function () { return new RegExp("^a{2,3}$", "u").test("aaa"); });
t("escaped-braces", function () { return new RegExp("\\{\\}\\]", "u").test("{}]"); });
t("escape-dash-end", function () { return new RegExp("[\\w-]", "u").test("-"); });
t("v-class-braces", function () { return new RegExp("[a]{2}", "v").test("aa"); });
console.log(out.join(" | "));
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
            "open-brace!SyntaxError | partial-quantifier!SyntaxError | lone-close-brace!SyntaxError | lone-bracket!SyntaxError | escape-range-start!SyntaxError | escape-range-end!SyntaxError | literal-brace!SyntaxError | annexb-brace=true | annexb-range=true | quantifier=true | escaped-braces=true | escape-dash-end=true | v-class-braces=true",
        ]
    );
}
