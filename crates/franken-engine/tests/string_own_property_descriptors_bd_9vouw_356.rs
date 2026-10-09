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

/// A String wrapper's own keys are its indices, then `length`
/// (ES2020 9.4.3.3), and Object.assign / object spread copy its indices
/// (enumerable; `length` is not). getOwnPropertyNames, Reflect.ownKeys and
/// getOwnPropertyDescriptors left `length` out, and copies of
/// `new String('ab')` had no indices. Node v22.2.0's line (Bun 1.4.2
/// agrees).
#[test]
fn string_wrapper_own_keys_and_copies() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + '=' + JSON.stringify(f())); } catch (e) { out.push(name + '!' + e.constructor.name); } }
t('assign-prim', function () { return Object.assign({}, 'ab'); });
t('assign-wrapper', function () { return Object.assign({}, Object('ab')); });
t('spread-prim', function () { return { ...'ab' }; });
t('spread-wrapper', function () { return { ...Object('ab') }; });
t('entries', function () { return Object.entries('ab'); });
t('values', function () { return Object.values(Object('ab')); });
t('names-prim', function () { return Object.getOwnPropertyNames('ab'); });
t('names-wrapper', function () { return Object.getOwnPropertyNames(Object('ab')); });
t('ownkeys', function () { return Reflect.ownKeys(Object('ab')); });
t('descs', function () { return Object.keys(Object.getOwnPropertyDescriptors('ab')); });
t('hasown', function () { return [Object.hasOwn('ab', 1), Object.hasOwn('ab', 'length'), Object('ab').hasOwnProperty('length')]; });
t('rest', function () { var { 0: a, ...r } = 'xyz'; return [a, r]; });
t('assign-extra', function () { var s = Object('ab'); s.x = 1; return Object.assign({}, s); });
console.log(out.join(' | '));
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
            "assign-prim={\"0\":\"a\",\"1\":\"b\"} | assign-wrapper={\"0\":\"a\",\"1\":\"b\"} | spread-prim={\"0\":\"a\",\"1\":\"b\"} | spread-wrapper={\"0\":\"a\",\"1\":\"b\"} | entries=[[\"0\",\"a\"],[\"1\",\"b\"]] | values=[\"a\",\"b\"] | names-prim=[\"0\",\"1\",\"length\"] | names-wrapper=[\"0\",\"1\",\"length\"] | ownkeys=[\"0\",\"1\",\"length\"] | descs=[\"0\",\"1\",\"length\"] | hasown=[true,true,true] | rest=[\"x\",{\"1\":\"y\",\"2\":\"z\"}] | assign-extra={\"0\":\"a\",\"1\":\"b\",\"x\":1}",
        ]
    );
}
