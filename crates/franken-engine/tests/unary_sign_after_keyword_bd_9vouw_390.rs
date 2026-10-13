//! bd-9vouw.390: a `+`/`-` right after `typeof`, `void`, `delete` or `in`
//! (and `await` / `yield` where they are operators) is a sign of the
//! operand: `typeof -1` is "number", `void -1` undefined, `delete -x` true.
//! The parser split them as binary expressions on an identifier named
//! `typeof` / `void` / `delete` ("typeof is not defined"). A property
//! named `typeof` still subtracts. The lines are Node v22.2.0's.

use frankenengine_engine::HybridRouter;

#[test]
fn sign_after_keyword_operator_is_unary() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + "=" + f()); } catch (e) { out.push(name + "!" + e.constructor.name); } }
var x = 1, y = { typeof: 5 };
t("typeof-neg", function () { return [typeof -Infinity, typeof -1, typeof - x, typeof +x, typeof +"3"].join(); });
t("void-sign", function () { return [void -1, void +x].join(); });
t("delete-sign", function () { return [delete -x, delete void typeof +-~!0].join(); });
t("in-sign", function () { return -1 in { "-1": 0 }; });
t("property-named-typeof", function () { return y.typeof - 1; });
t("generator-yield-sign", function () { function* g() { var r = yield -1; return r; } var it = g(); return it.next().value + "," + it.next(3).value; });
var asyncResult = [];
(async function () { asyncResult.push(await -2, await +x); })().then(function () { console.log("async=" + asyncResult.join()); });
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
            "typeof-neg=number,number,number,number,number | void-sign=, | delete-sign=true,true | in-sign=true | property-named-typeof=4 | generator-yield-sign=-1,3",
            "async=-2,1",
        ]
    );
}
