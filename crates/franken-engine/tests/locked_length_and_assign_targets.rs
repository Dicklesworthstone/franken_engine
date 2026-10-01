//! Writes that must fail, and the TypeErrors they raise (ES2020 7.3.4
//! Set(O, P, V, true)). Expected strings are Node v22.2.0's output.
//!
//! - push/pop/shift/unshift/splice on an Array whose `length` is not
//!   writable (defineProperty, Object.freeze) throw, after the element steps
//!   the specification performs first; the element-storage path changed the
//!   length anyway (Test262 Array/prototype/pop/
//!   set-length-zero-array-length-is-non-writable).
//! - Object.assign boxes a primitive target (ToObject) and copies onto the
//!   wrapper; a String wrapper's indices are not writable, so
//!   `Object.assign('a', [1])` throws (Test262 Object/assign/
//!   assignment-to-readonly-property-of-target-must-throw-a-typeerror-exception).

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value
}

#[test]
fn length_changing_methods_throw_on_a_locked_length() {
    let source = "var r = [];\n\
                  function t(f) { try { f(); return 'no throw'; } catch (e) { return e.constructor.name; } }\n\
                  var a = [1, 2]; Object.defineProperty(a, 'length', { writable: false });\n\
                  r.push(t(() => a.pop()), a.length, t(() => a.push(3)), a.length, t(() => a.shift()), \
                  t(() => a.unshift(0)), t(() => a.splice(0, 1)), a.join());\n\
                  var e = []; Object.defineProperty(e, 'length', { writable: false });\n\
                  r.push(t(() => e.pop()), t(() => e.push()));\n\
                  var f = Object.freeze([1]); r.push(t(() => f.push(2)), t(() => f.pop()), f.length);\n\
                  var ok = [1]; ok.push(2); ok.pop(); r.push(ok.join());\n\
                  r.join(' ');";
    assert_eq!(
        eval(source),
        "TypeError 2 TypeError 2 TypeError TypeError TypeError , TypeError TypeError TypeError \
         TypeError 1 1"
    );
}

#[test]
fn object_assign_boxes_a_primitive_target() {
    let source = "var r = [];\n\
                  try { Object.assign('a', [1]); r.push('no throw'); } catch (e) { r.push(e.constructor.name); }\n\
                  var n = Object.assign(1, { a: 2 }); r.push(typeof n, n instanceof Number, n.a, +n);\n\
                  var s = Object.assign('xy', { z: 3 }); r.push(typeof s, s.z, s.length, String(s));\n\
                  var b = Object.assign(true); r.push(typeof b);\n\
                  r.join(' ');";
    assert_eq!(
        eval(source),
        "TypeError object true 2 1 object 3 2 xy object"
    );
}
