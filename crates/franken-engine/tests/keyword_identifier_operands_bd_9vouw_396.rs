//! bd-9vouw.396: outside a generator in non-strict code `yield`, and in
//! script code outside async functions `await`, is an identifier, also
//! before a binary operator: `yield + x`, `yield * 2`, `await + 1`,
//! `await instanceof Object`. The engine parsed `yield ` / `await ` followed
//! by anything as a yield / await expression and refused it. Inside a
//! generator or an async function they stay operators, and strict code and
//! `yield x` outside a generator stay SyntaxErrors. The line is Node
//! v22.2.0's.

use frankenengine_engine::HybridRouter;

#[test]
fn yield_and_await_identifiers_are_operands() {
    let source = r#"
var cases = [
  "var yield = 4, x = 1; return [yield + x, yield * 2, yield - 1, yield % 3, yield < 5, yield == 4, yield instanceof Object, yield in {4: 1}].join();",
  "var yield = [7]; return yield[0];",
  "var yield = function (a) { return a + 1; }; return yield(1);",
  "var yield = 2; yield += 3; return yield;",
  "var await = 3; return [await + 1, await * 2, await - 1, await instanceof Object].join();",
  "function await(a) { return a * 2; } return await(4);",
  "var await = {k: 9}; return await.k;",
  "function* g() { var r = yield + 1; return r; } var it = g(); it.next(); return it.next(5).value;",
  "async function f() { return await + 1; } return typeof f;",
  "'use strict'; var yield = 1;",
  "yield x;",
  "function* g() { yield * 2; }",
];
console.log(cases.map(function (s, i) {
  try { return i + ":" + String(Function(s)()); } catch (e) { return i + ":" + e.name; }
}).join(" | "));
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
            "0:5,8,3,1,true,true,false,true | 1:7 | 2:2 | 3:5 | 4:4,6,2,false | 5:8 | 6:9 | 7:5 | 8:function | 9:SyntaxError | 10:SyntaxError | 11:undefined",
        ]
    );
}
