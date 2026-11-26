#![forbid(unsafe_code)]

//! ES2020 7.3.23 EnumerableOwnPropertyNames for Object.values and
//! Object.entries: the key list is taken first, then each key is checked
//! and read in turn. The engine read every property up front, so a getter
//! that deleted a later key or made it non-enumerable still had it listed,
//! and a later data property's value predated the getter (4 Node-passing
//! Test262 tests in the rc-next33 merged-tree census:
//! Object/{entries,values}/getter-{removing,making-future-key-nonenumerable}).

use frankenengine_engine::HybridRouter;

/// Getters that delete, hide, change and add properties, key order
/// (integer keys first), a non-enumerable property, a string and a typed
/// array, and the order getters run in. Expected lines are Node v22.2.0's
/// output, captured programmatically.
#[test]
fn values_and_entries_check_each_key_when_reached() {
    let source = r#"var removing = { get a() { delete this.b; return 'a'; }, b: 'b', c: 'c' };
var hiding = { get a() { Object.defineProperty(this, 'b', { enumerable: false }); return 'a'; }, b: 'b', c: 'c' };
var changing = { get a() { this.b = 'changed'; return 'a'; }, b: 'b' };
var adding = { get a() { this.z = 'late'; return 'a'; }, b: 'b' };
console.log(JSON.stringify(Object.entries(removing)), JSON.stringify(Object.values({ get a() { delete this.b; return 1; }, b: 2, c: 3 })));
console.log(JSON.stringify(Object.entries(hiding)), JSON.stringify(Object.values(changing)), JSON.stringify(Object.entries(adding)));
var ordered = { b: 1, 2: 'two', a: 2, 1: 'one' };
Object.defineProperty(ordered, 'hidden', { value: 3, enumerable: false });
console.log(JSON.stringify(Object.entries(ordered)), JSON.stringify(Object.values(ordered)), JSON.stringify(Object.entries('hi')), JSON.stringify(Object.values(new Uint8Array([7, 8]))));
var reads = [];
var traced = {};
['x', 'y'].forEach(function (key) { Object.defineProperty(traced, key, { get: function () { reads.push(key); return key.toUpperCase(); }, enumerable: true }); });
console.log(JSON.stringify(Object.values(traced)), reads.join(','));
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
            "[[\"a\",\"a\"],[\"c\",\"c\"]] [1,3]",
            "[[\"a\",\"a\"],[\"c\",\"c\"]] [\"a\",\"changed\"] [[\"a\",\"a\"],[\"b\",\"b\"]]",
            "[[\"1\",\"one\"],[\"2\",\"two\"],[\"b\",1],[\"a\",2]] [\"one\",\"two\",1,2] [[\"0\",\"h\"],[\"1\",\"i\"]] [7,8]",
            "[\"X\",\"Y\"] x,y",
        ]
    );
}

fn assert_for_property_carriers(body: &str, expected: &[&str]) {
    for receiver in [
        "({})",
        "(function () {})",
        "(function () {}).bind(null)",
        "Promise.resolve(1)",
        "(function* () { yield 1; })()",
        "(async function* () { yield 1; })()",
        "[1].values()",
        "'a'[Symbol.iterator]()",
        "new Proxy(function () {}, {})",
    ] {
        let source = format!("var value = {receiver};\n{body}");
        let lines: Vec<String> = HybridRouter::default()
            .eval(&source)
            .unwrap_or_else(|error| panic!("receiver {receiver}: {error}"))
            .console_output
            .into_iter()
            .map(|entry| entry.message)
            .collect();
        assert_eq!(lines, expected, "receiver {receiver}");
    }
}

#[test]
fn values_and_entries_observe_live_descriptors_on_every_property_carrier() {
    for (method, expected) in [
        ("values", "[\"first\",\"shown\",\"changed\"] true added"),
        (
            "entries",
            "[[\"a\",\"first\"],[\"c\",\"shown\"],[\"e\",\"changed\"]] true added",
        ),
    ] {
        let body = format!(
            r#"
var receivers = [];
Object.defineProperty(value, 'a', {{
    enumerable: true,
    get: function () {{
        receivers.push(this === value);
        delete this.b;
        Object.defineProperty(this, 'c', {{ enumerable: true }});
        Object.defineProperty(this, 'd', {{ enumerable: false }});
        this.e = 'changed';
        this.late = 'added';
        return 'first';
    }}
}});
value.b = 'deleted';
Object.defineProperty(value, 'c', {{ value: 'shown', configurable: true }});
value.d = 'hidden';
value.e = 'old';
Object.defineProperty(value, Symbol('ignored'), {{
    enumerable: true,
    get: function () {{ throw 'must not read symbol'; }}
}});
var result = Object.{method}(value);
console.log(JSON.stringify(result), receivers.join(','), value.late);
"#
        );
        assert_for_property_carriers(&body, &[expected]);
    }
}

#[test]
fn values_and_entries_preserve_abrupt_getters_and_receiver_identity() {
    for method in ["values", "entries"] {
        let body = format!(
            r#"
var token = {{}};
var reads = [];
Object.defineProperty(value, 'a', {{
    enumerable: true,
    get: function () {{ reads.push('a:' + (this === value)); throw token; }}
}});
Object.defineProperty(value, 'b', {{
    enumerable: true,
    get: function () {{ reads.push('b'); return 2; }}
}});
var caught;
try {{ Object.{method}(value); }} catch (error) {{ caught = error; }}
console.log(caught === token, reads.join(','));
"#
        );
        assert_for_property_carriers(&body, &["true a:true"]);
    }
}
