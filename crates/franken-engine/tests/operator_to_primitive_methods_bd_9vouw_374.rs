//! bd-9vouw.374: an operator converts an object through OrdinaryToPrimitive
//! (ES2020 7.1.1.1) whenever the program defines a `toString` or `valueOf`
//! on its chain, callable or not, and when the chain has no
//! Object.prototype: a non-callable method is skipped, none callable is a
//! TypeError, and a getter-defined method runs its getter. The engine's
//! string form answered "[object Object]" for +, ==, relational operators
//! and template substitutions unless a guest function was found. The line is
//! Node v22.2.0's output for the same program.

use frankenengine_engine::HybridRouter;

#[test]
fn operators_convert_objects_through_ordinary_to_primitive() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + "=" + f()); } catch (e) { out.push(name + "!" + e.constructor.name); } }
var none = { valueOf: null, toString: null };
t("add", function () { return none + ""; });
t("tostring-null", function () { return ({ toString: null }) + ""; });
t("template", function () { return `${{ toString: null }}`; });
t("bigint", function () { return none + 0n; });
t("lt", function () { return none < 1; });
t("eq", function () { return none == 1; });
t("null-proto-add", function () { return Object.create(null) + ""; });
t("null-proto-eq", function () { return Object.create(null) == "x"; });
t("valueof-num", function () { return ({ toString: null, valueOf: function () { return 4; } }) + 1; });
t("getter", function () { var log = []; var o = { get valueOf() { log.push("get"); return function () { return 2; }; } }; return (o * 3) + ":" + log.join(); });
t("plain", function () { return ({}) + "|" + [1, 2] + "|" + new Error("e"); });
t("class-method", function () { class P { toString() { return "p"; } } return new P() + "!"; });
console.log(out.join(' '));
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
            "add!TypeError tostring-null!TypeError template!TypeError bigint!TypeError lt!TypeError eq!TypeError null-proto-add!TypeError null-proto-eq!TypeError valueof-num=5 getter=6:get plain=[object Object]|1,2|Error: e class-method=p!",
        ]
    );
}
