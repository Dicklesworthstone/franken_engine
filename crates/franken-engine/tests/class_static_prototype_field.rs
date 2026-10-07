#![forbid(unsafe_code)]

//! A static class field whose computed key is "prototype" is a TypeError
//! (ES2022 DefineField is CreateDataPropertyOrThrow, and a class's own
//! `prototype` is non-configurable); Node raises it when the field is
//! defined, before any initializer runs. The engine defined the field on
//! the constructor's backing object (2 Node-passing Test262 tests in the
//! rc-next33 merged-tree census: {statements,expressions}/class/elements/
//! fields-computed-name-static-propname-prototype).

use frankenengine_engine::HybridRouter;

/// Static fields keyed "prototype" (with and without an initializer, and
/// built by concatenation, whose initializer must not run), next to a
/// static `constructor` field, an instance field named prototype and a
/// symbol-keyed static field. Expected lines are Node v22.2.0's output,
/// captured programmatically.
#[test]
fn static_field_named_prototype_is_a_type_error() {
    let source = r#"function k(f) { try { f(); return 'ok'; } catch (e) { return e.constructor.name; } }
var ran = [];
console.log(k(function () { class C { static ['prototype'] = 42; } }), k(function () { class C { static ['prototype']; } }), k(function () { class C { static ['proto' + 'type'] = (ran.push('init'), 1); } }), ran.join(','));
class D { static ['constructor'] = 'ok'; ['prototype'] = 'instance'; static name2 = 'n'; }
console.log(D.constructor, new D().prototype, D.name2, typeof D.prototype, k(function () { var E = class { static [Symbol.iterator] = 1; }; return E; }));
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
        ["TypeError TypeError TypeError ", "ok instance n object ok",]
    );
}
