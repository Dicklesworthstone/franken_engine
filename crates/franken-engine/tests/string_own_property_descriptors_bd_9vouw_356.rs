//! bd-9vouw.356: a String's own code-unit indices and `length` have
//! descriptors (ES2020 9.4.3.1 StringGetOwnProperty): read-only and
//! non-configurable, the indices enumerable and `length` not.
//! Object.getOwnPropertyDescriptor answered undefined for them, on a string
//! primitive (ToObject gives a String exotic object) and on a String
//! object alike, while getOwnPropertyNames listed them. Another key, an
//! index past the length or a non-canonical index is not an own String
//! property; a String object's added properties keep their own
//! descriptors. The line is Node v22.2.0's (Bun 1.4.2 agrees).

use frankenengine_engine::HybridRouter;

#[test]
fn string_indices_and_length_have_descriptors() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + ':' + JSON.stringify(f())); } catch (e) { out.push(name + ':' + e.constructor.name); } }
t('str-0', function () { return Object.getOwnPropertyDescriptor('abc', '0'); });
t('str-len', function () { return Object.getOwnPropertyDescriptor('abc', 'length'); });
t('str-oob', function () { return Object.getOwnPropertyDescriptor('abc', '3'); });
t('str-noncanon', function () { return Object.getOwnPropertyDescriptor('abc', '01'); });
t('str-other', function () { return Object.getOwnPropertyDescriptor('abc', 'toString'); });
t('strobj-1', function () { return Object.getOwnPropertyDescriptor(new String('xy'), '1'); });
t('strobj-len', function () { return Reflect.getOwnPropertyDescriptor(new String('xy'), 'length'); });
var so = new String('q'); so.extra = 5;
t('strobj-extra', function () { return Object.getOwnPropertyDescriptor(so, 'extra'); });
t('astral', function () { return Object.getOwnPropertyDescriptor('😀', '1').value.charCodeAt(0); });
t('num', function () { return Object.getOwnPropertyDescriptor(5, 'toFixed'); });
t('descs', function () { return Object.getOwnPropertyDescriptors('ab'); });
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
            "str-0:{\"value\":\"a\",\"writable\":false,\"enumerable\":true,\"configurable\":false} str-len:{\"value\":3,\"writable\":false,\"enumerable\":false,\"configurable\":false} str-oob:undefined str-noncanon:undefined str-other:undefined strobj-1:{\"value\":\"y\",\"writable\":false,\"enumerable\":true,\"configurable\":false} strobj-len:{\"value\":2,\"writable\":false,\"enumerable\":false,\"configurable\":false} strobj-extra:{\"value\":5,\"writable\":true,\"enumerable\":true,\"configurable\":true} astral:56832 num:undefined descs:{\"0\":{\"value\":\"a\",\"writable\":false,\"enumerable\":true,\"configurable\":false},\"1\":{\"value\":\"b\",\"writable\":false,\"enumerable\":true,\"configurable\":false},\"length\":{\"value\":2,\"writable\":false,\"enumerable\":false,\"configurable\":false}}"
        ]
    );
}
