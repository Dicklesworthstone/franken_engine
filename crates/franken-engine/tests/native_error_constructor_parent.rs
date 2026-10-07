#![forbid(unsafe_code)]

//! ES2020 19.5.6.2 (ES2021 20.5.7.2): each NativeError constructor's
//! [[Prototype]] is %Error%. Object.getPrototypeOf(RangeError) answered
//! Function.prototype (6 Node-passing Test262 tests in the rc-next33
//! merged-tree census: Object/getPrototypeOf/15.2.3.2-2-12..17), and a read
//! of a static RangeError lacks stopped at Function.prototype, so
//! `TypeError.captureStackTrace(obj)` threw where Node code calls it.

use frankenengine_engine::HybridRouter;

/// [[GetPrototypeOf]] of every NativeError constructor, Error's statics
/// (captureStackTrace, a program-set stackTraceLimit and custom static) read
/// through them without becoming own properties, and their own name and
/// length. Expected lines are Node v22.2.0's output, captured
/// programmatically.
#[test]
fn native_error_constructors_inherit_from_error() {
    let source = r#"var names = ['EvalError', 'RangeError', 'ReferenceError', 'SyntaxError', 'TypeError', 'URIError', 'AggregateError'];
console.log(names.map(function (name) { return Object.getPrototypeOf(globalThis[name]) === Error; }).join(','), Object.getPrototypeOf(Error) === Function.prototype, Reflect.getPrototypeOf(TypeError) === Error);
console.log(RangeError.captureStackTrace === Error.captureStackTrace, typeof TypeError.captureStackTrace, RangeError.hasOwnProperty('captureStackTrace'), Error.hasOwnProperty('captureStackTrace'));
Error.stackTraceLimit = 3;
Error.customStatic = 'from Error';
console.log(RangeError.stackTraceLimit, TypeError.customStatic, RangeError.hasOwnProperty('customStatic'), RangeError.name, TypeError.length, AggregateError.length);
var target = {};
TypeError.captureStackTrace(target);
console.log(typeof target.stack, RangeError.prototype instanceof Error, Object.getPrototypeOf(RangeError.prototype) === Error.prototype);
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
            "true,true,true,true,true,true,true true true",
            "true function false true",
            "3 from Error false RangeError 1 2",
            "string true true",
        ]
    );
}
