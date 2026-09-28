//! ES2020 19.1.3.6 Object.prototype.toString: the builtinTag of Dates,
//! RegExps and Errors and the standard @@toStringTag of Map, Set, WeakMap,
//! WeakSet, ArrayBuffer, DataView and typed arrays. FrankenEngine answered
//! "[object Object]" for every object except arrays, which broke the classic
//! `Object.prototype.toString.call(x) === '[object Date]'` type checks and made
//! isPlainObject-style checks accept Dates and Maps. Expected string is Node
//! v22.2.0's output.
//!
//! No-claim: guest-defined @@toStringTag getters, Arguments, JSON and Math
//! still answer "[object Object]".

use frankenengine_engine::HybridRouter;

#[test]
fn builtin_objects_report_their_tags() {
    let source = "const t = x => Object.prototype.toString.call(x);\n\
                  class M extends Map {} class E extends Error {}\n\
                  [t(new Date(0)), t(/x/), t(new Map()), t(new Set()), t(new WeakMap()), t(new WeakSet()), \
                  t(new Error('e')), t(new TypeError('e')), t(new E('x')), t(new M()), t(new Uint8Array(1)), \
                  t(new Float64Array(1)), t(new ArrayBuffer(1)), t(new DataView(new ArrayBuffer(1))), t({}), \
                  t([]), t(Object.create(null)), t(Error.prototype)].join(' ');";
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "[object Date] [object RegExp] [object Map] [object Set] [object WeakMap] [object WeakSet] \
         [object Error] [object Error] [object Error] [object Map] [object Uint8Array] \
         [object Float64Array] [object ArrayBuffer] [object DataView] [object Object] \
         [object Array] [object Object] [object Object]"
    );
}
