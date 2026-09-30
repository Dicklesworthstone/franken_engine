//! `Object.create(null)` objects inherit nothing: reading `toString` or
//! `hasOwnProperty` on them is undefined. FrankenEngine's property-read
//! fallback served Object.prototype's builtin methods to every object, so a
//! null-prototype dictionary keyed by user input (a word counter seeing
//! "toString") read a builtin function instead of undefined. The `in` check
//! already followed the prototype chain. Expected string is Node v22.2.0's.

use frankenengine_engine::HybridRouter;

#[test]
fn null_prototype_objects_do_not_see_object_prototype_methods() {
    let source = "const d = Object.create(null); d.x = 1;\n\
                  const w = Object.create(null); for (const k of ['toString', 'a', 'toString']) w[k] = (w[k] || 0) + 1;\n\
                  [typeof d.toString, typeof d.hasOwnProperty, 'toString' in d, w.toString, \
                  Object.keys(w).join(), typeof ({}).toString].join(' ');";
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(value, "undefined undefined false 2 toString,a function");
}
