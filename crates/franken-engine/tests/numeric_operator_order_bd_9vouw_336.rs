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
