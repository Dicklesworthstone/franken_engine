#![forbid(unsafe_code)]

//! bd-9vouw.272 phase 2: Function.prototype's `caller` and `arguments` are
//! accessors whose get and set are %ThrowTypeError% (ES2020 9.2.7
//! AddRestrictedFunctionProperties), so reading or writing them on a strict,
//! arrow, method, class, generator, async, bound or built-in function throws
//! a TypeError; Node's sloppy ordinary functions answer null. The engine read
//! undefined everywhere and Function.prototype had neither property (about
//! 45 Node-passing Test262 tests in the rc-next33 merged-tree census:
//! built-ins/ThrowTypeError, Function/15.3.5.4_2-*gs, the restricted-property
//! tests).

use frankenengine_engine::HybridRouter;

/// Reads on every function kind, the accessor pair's identity (one
/// %ThrowTypeError% for both properties, get and set, and a strict arguments
/// object's `callee`), %ThrowTypeError%'s own shape, a write through the
/// inherited setter, and deleting the accessor. Expected lines are Node
/// v22.2.0's output, captured programmatically.
///
/// No-claim: a sloppy function's own `caller` and `arguments` are answered
/// on read only; they are not reported by hasOwnProperty,
/// getOwnPropertyDescriptor or getOwnPropertyNames, and `arguments` is null
/// even during a call (Node: the live arguments object).
#[test]
fn function_prototype_caller_and_arguments_are_throw_type_error_accessors() {
    let source = r#"function k(f) { try { f(); return 'ok'; } catch (e) { return e.constructor.name; } }
function sloppy() { return 1; }
function strict() { 'use strict'; return 1; }
var arrow = () => 1;
var obj = { m() {}, *g() {} };
class C {}
async function af() {}
var bound = sloppy.bind(null);
console.log(sloppy.caller, sloppy.arguments, k(function () { return strict.caller; }), k(function () { return strict.arguments; }));
console.log(k(function () { return arrow.caller; }), k(function () { return obj.m.arguments; }), k(function () { return obj.g.caller; }), k(function () { return C.caller; }), k(function () { return af.arguments; }), k(function () { return bound.caller; }), k(function () { return [].push.caller; }));
var callerDesc = Object.getOwnPropertyDescriptor(Function.prototype, 'caller');
var argumentsDesc = Object.getOwnPropertyDescriptor(Function.prototype, 'arguments');
var thrower = callerDesc.get;
console.log(typeof thrower, callerDesc.set === thrower, argumentsDesc.get === thrower, argumentsDesc.set === thrower, callerDesc.enumerable, callerDesc.configurable, argumentsDesc.enumerable, argumentsDesc.configurable);
var strictCallee = (function () { 'use strict'; return Object.getOwnPropertyDescriptor(arguments, 'callee').get; })();
console.log(strictCallee === thrower, thrower.name === '', thrower.length, Object.isFrozen(thrower), Object.isExtensible(thrower), Object.getPrototypeOf(thrower) === Function.prototype, k(thrower), k(function () { strict.caller = 1; }));
console.log(Object.prototype.hasOwnProperty.call(strict, 'caller'), Object.prototype.hasOwnProperty.call(arrow, 'arguments'), 'caller' in strict, Function.prototype.hasOwnProperty('caller'));
console.log(delete Function.prototype.caller, strict.caller, k(function () { return strict.arguments; }));
"#;
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(
        lines,
        [
            "null null TypeError TypeError",
            "TypeError TypeError TypeError TypeError TypeError TypeError TypeError",
            "function true true true false true false true",
            "true true 0 true false true TypeError TypeError",
            "false false true true",
            "true undefined TypeError",
        ]
    );
}
