//! bd-9vouw.336: for every binary operator but `+` and the relational ones,
//! ToNumeric of the left operand completes before the right operand
//! converts (ES2020 12.15.3 ApplyStringOrNumericBinaryOperator), so a left
//! operand whose valueOf returns a Symbol throws a TypeError before the
//! right operand's valueOf runs. The engine converted both operands first,
//! so the right operand's throw won (11 Node-passing Test262
//! order-of-evaluation tests). `<` still converts both operands to
//! primitives first (7.2.13), a Symbol from the right operand still throws
//! after both conversions, and a BigInt left operand does not throw. Node
//! v22.2.0 gives this line.

use frankenengine_engine::HybridRouter;

#[test]
fn a_symbol_left_operand_throws_before_the_right_operand_converts() {
    let source = r#"
var out = [];
function run(name, f) {
  var trace = [];
  try {
    f(trace);
    out.push(name + ':ok:' + trace.join(''));
  } catch (e) {
    out.push(name + ':' + (e instanceof TypeError ? 'TypeError' : e === 'R' ? 'R' : String(e)) + ':' + trace.join(''));
  }
}
function lhsSym(t) { return { valueOf: function () { t.push('3'); return Symbol('s'); } }; }
function rhsThrow(t) { return { valueOf: function () { t.push('4'); throw 'R'; } }; }
function rhsSym(t) { return { valueOf: function () { t.push('4'); return Symbol('s'); } }; }
function one(t) { return { valueOf: function () { t.push('3'); return 1; } }; }
run('and', function (t) { return lhsSym(t) & rhsThrow(t); });
run('sub', function (t) { return lhsSym(t) - rhsThrow(t); });
run('exp', function (t) { return lhsSym(t) ** rhsThrow(t); });
run('shl', function (t) { return lhsSym(t) << rhsThrow(t); });
run('ushr', function (t) { return lhsSym(t) >>> rhsThrow(t); });
run('lt', function (t) { return lhsSym(t) < rhsThrow(t); });
run('rsym', function (t) { return one(t) * rhsSym(t); });
run('big', function (t) { return { valueOf: function () { t.push('3'); return 1n; } } - rhsThrow(t); });
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
            "and:TypeError:3 sub:TypeError:3 exp:TypeError:3 shl:TypeError:3 ushr:TypeError:3 lt:R:34 rsym:TypeError:34 big:R:34"
        ]
    );
}

#[test]
fn compact_numeric_paths_preserve_special_values_and_observable_fallbacks() {
    let source = r#"
function add(a, b) { return a + b; }
function sub(a, b) { return a - b; }
function mul(a, b) { return a * b; }
function div(a, b) { return a / b; }
function mod(a, b) { return a % b; }
var value = 0.5;
for (var i = 0; i < 256; i++) {
  value = mod(sub(div(mul(add(value, 0.5), 1.5), 1.5), 0.25), 97.25);
}
var trace = [];
var left = { valueOf: function () { trace.push('L'); return 7.5; } };
var right = { valueOf: function () { trace.push('R'); return 2; } };
var converted = [add(left, right), sub(left, right), mul(left, right),
  div(left, right), mod(left, right)];
var checks = [
  Object.is(mul(0, -3), -0),
  Object.is(mul(-0, -3), 0),
  Object.is(mod(-6, 3), -0),
  Object.is(div(-0, -3), 0),
  Object.is(div(0, -3), -0),
  Number.isNaN(mod(1, 0)),
  Number.isNaN(mod(Infinity, 2)),
  div(1, 0) === Infinity,
  div(-1, 0) === -Infinity,
  Number.isNaN(sub(Infinity, Infinity)),
  Number.isNaN(mul(Infinity, 0)),
  add(9007199254740991, 2) === 9007199254740992,
  sub(-9007199254740991, 2) === -9007199254740992,
  mul(9007199254740991, 2) === 18014398509481982,
  mod(7n, 2n) === 1n,
  add('2', 3) === '23'
];
console.log(value + '|' + checks.join(',') + '|' + converted.join(',') + '|' + trace.join(''));
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
            "64.5|true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true|9.5,5.5,15,3.75,1.5|LRLRLRLRLR"
        ]
    );
}
