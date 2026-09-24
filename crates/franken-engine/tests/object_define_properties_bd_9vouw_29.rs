//! bd-9vouw.29: `Object.defineProperties` and the `Object.defineProperty`
//! TypeErrors of ES2020 19.1.2.3-19.1.2.4.
//!
//! `Object.defineProperties` did not exist ("expected function, got
//! undefined"), a non-object `Object.defineProperty` target returned
//! `undefined`, and a non-object descriptor was stored as the property value.
//! Expected strings are what Node v22.2.0 prints for the same programs.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

#[test]
fn define_properties_installs_data_and_accessor_properties() {
    check(
        "const o = {}; Object.defineProperties(o, {a: {value: 1}, b: {get() { return 2; }}}); o.a + o.b;",
        "3",
    );
    check(
        "const o = {}; Object.defineProperties(o, {a: {value: 1}}) === o;",
        "true",
    );
}

#[test]
fn define_properties_validates_every_descriptor_before_defining() {
    check(
        "let r; try { Object.defineProperties({}, {a: 5}); } catch (e) { r = e.name; } r;",
        "TypeError",
    );
    // A later invalid descriptor leaves the earlier one undefined.
    check(
        "const o = {}; let r; try { Object.defineProperties(o, {a: {value: 1}, b: 5}); } \
         catch (e) { r = e.name + ':' + ('a' in o); } r;",
        "TypeError:false",
    );
}

#[test]
fn define_property_rejects_non_object_target_and_descriptor() {
    check(
        "let r; try { Object.defineProperty(1, 'x', {value: 1}); } catch (e) { r = e.name; } r;",
        "TypeError",
    );
    check(
        "let r; try { Object.defineProperty({}, 'x', 5); } catch (e) { r = e.name; } r;",
        "TypeError",
    );
    // Positive control: the ordinary form still defines the property.
    check(
        "const o = {}; Object.defineProperty(o, 'x', {value: 7}); o.x;",
        "7",
    );
}
