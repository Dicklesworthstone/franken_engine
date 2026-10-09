//! bd-9vouw.359: an optional call with spread arguments expands them, and
//! an optional member call keeps its receiver (`f?.(...xs)`,
//! `o.m?.(...xs)`, `o?.m(...xs)`, `callback?.(...args)`). The optional-chain
//! lowering opted out of any call link with spread arguments, and the
//! fallback pushed each spread element's array as one argument and called
//! without the receiver: `sum?.(...[10, 20, 40])` gave "010,20,40" and a
//! method saw `this` undefined. The call now goes through ReflectApply with
//! the argument array, as `super.m(...xs)` does; a nullish callee or object
//! still skips evaluating the arguments. The line is Node v22.2.0's (Bun
//! 1.4.2 agrees).

use frankenengine_engine::HybridRouter;

#[test]
fn optional_calls_spread_their_arguments_and_keep_the_receiver() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + '=' + JSON.stringify(f())); } catch (e) { out.push(name + '!' + e.constructor.name); } }
function sum() { var s = 0; for (var i = 0; i < arguments.length; i++) s += arguments[i]; return s; }
var args = [10, 20, 40];
var o = { m: sum, n: null, v: 3, self: function () { return this.v + arguments.length; } };
var calls = 0;
function side() { calls++; return [1, 2]; }
t('opt-call-spread', function () { return sum?.(...args); });
t('opt-member-call-spread', function () { return o.m?.(...args); });
t('opt-chain-call-spread', function () { return o?.m(...args); });
t('opt-null-spread', function () { return o.n?.(...args); });
t('opt-mixed', function () { return o?.m?.(1, ...args, 2); });
t('plain-spread', function () { return o.m(...args); });
t('this-opt-spread', function () { return o.self?.(...[1, 2]); });
t('this-chain-spread', function () { return o?.self(...[1, 2, 3]); });
t('computed-opt-spread', function () { return o['self']?.(...[1]); });
t('deep-chain-spread', function () { var root = { a: { b: o } }; return root.a?.b.self?.(...args); });
t('short-circuit-callee', function () { var r = o.n?.(...side()); return [r, calls]; });
t('short-circuit-object', function () { var none = null; var r = none?.m(...side()); return [r, calls]; });
t('evaluated-when-present', function () { var r = o.m?.(...side()); return [r, calls]; });
t('not-callable', function () { return o.v?.(...args); });
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
            "opt-call-spread=70 opt-member-call-spread=70 opt-chain-call-spread=70 opt-null-spread=undefined opt-mixed=73 plain-spread=70 this-opt-spread=5 this-chain-spread=6 computed-opt-spread=4 deep-chain-spread=6 short-circuit-callee=[null,0] short-circuit-object=[null,0] evaluated-when-present=[3,1] not-callable!TypeError"
        ]
    );
}
