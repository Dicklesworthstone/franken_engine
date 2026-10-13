//! bd-9vouw.400: under the RegExp `v` flag a class with an unescaped
//! syntax character or a reserved double punctuator is a SyntaxError, from
//! `new RegExp` and as a literal; valid `v` classes (ranges, `--`, `&&`,
//! `\q{}`) still match. Expected line is Node v22.2.0's output.

use frankenengine_engine::HybridRouter;

#[test]
fn unicode_sets_class_syntax_errors_are_syntax_errors() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + "=" + f()); } catch (e) { out.push(name + "!" + e.name); } }
t("ctor-paren", function () { return new RegExp("[(]", "v").test("("); });
t("ctor-double", function () { return new RegExp("[!!]", "v").test("!"); });
t("ctor-dash", function () { return new RegExp("[-]", "v").test("-"); });
t("ctor-and", function () { return new RegExp("[a&&&b]", "v").test("a"); });
t("literal-paren", function () { return Function("return /[(]/v;")(); });
t("literal-hat", function () { return Function("return /[_^^]/v;")(); });
t("u-flag-paren", function () { return new RegExp("[(]", "u").test("("); });
t("ctor-range", function () { return new RegExp("[a-z]", "v").test("q"); });
t("ctor-subtract", function () { return new RegExp("[\\p{L}--\\p{Lu}]", "v").test("a") + "," + new RegExp("[\\p{L}--\\p{Lu}]", "v").test("A"); });
t("ctor-intersect", function () { return new RegExp("[[a-z]&&[aeiou]]", "v").test("e") + "," + new RegExp("[[a-z]&&[aeiou]]", "v").test("b"); });
t("ctor-escaped", function () { return new RegExp("[\\(\\!!]", "v").test("!"); });
t("literal-strings", function () { return Function("return /^[\\q{abc|d}]$/v.test('abc');")(); });
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
            "ctor-paren!SyntaxError | ctor-double!SyntaxError | ctor-dash!SyntaxError | ctor-and!SyntaxError | literal-paren!SyntaxError | literal-hat!SyntaxError | u-flag-paren=true | ctor-range=true | ctor-subtract=true,false | ctor-intersect=true,false | ctor-escaped=true | literal-strings=true",
        ]
    );
}
