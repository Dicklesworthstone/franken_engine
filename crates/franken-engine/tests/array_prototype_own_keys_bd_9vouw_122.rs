//! bd-9vouw.122: %Array.prototype% lists its own keys.
//!
//! `Object.getOwnPropertyNames(Array.prototype)` was empty (Node v22: 40
//! names), `Array.prototype.hasOwnProperty(Symbol.iterator)` was false and
//! `Array.prototype.length` was undefined, although each method was already
//! an own property to hasOwnProperty and getOwnPropertyDescriptor. PROGRAM
//! checks the names in Node's order, `length` 0, the own @@iterator (key
//! and descriptor), Reflect.ownKeys order, that Object.keys stays empty, and
//! that a property a program adds comes last. NODE_OUTPUT is Node v22.2.0's
//! output.
//!
//! `toLocaleString` is compared separately: the engine lists it exactly when
//! Array.prototype has it as an own property, which it does not yet here
//! (the read falls through to Object.prototype.toLocaleString).
//! No-claim: @@unscopables is not listed, as Array.prototype has no
//! @@unscopables object in this engine.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const PROGRAM: &str = r#"const names = Object.getOwnPropertyNames(Array.prototype);
console.log(JSON.stringify(names.filter(function (name) { return name !== 'toLocaleString'; })));
console.log(names.includes('toLocaleString') === Array.prototype.hasOwnProperty('toLocaleString'));
console.log(Array.prototype.length, Array.prototype.hasOwnProperty('length'), Array.prototype.hasOwnProperty(Symbol.iterator), Object.getOwnPropertySymbols(Array.prototype).includes(Symbol.iterator));
const keys = Reflect.ownKeys(Array.prototype);
console.log(keys.indexOf('length'), keys.indexOf(Symbol.iterator) > keys.indexOf('toString'), typeof keys[keys.length - 1]);
const d = Object.getOwnPropertyDescriptor(Array.prototype, Symbol.iterator);
console.log(d.value === Array.prototype.values, d.writable, d.enumerable, d.configurable);
console.log(Object.keys(Array.prototype).length, Object.create(Array.prototype).length, [].length, [1, 2].length);
Array.prototype.myExtra = 1;
console.log(Object.getOwnPropertyNames(Array.prototype).slice(-1)[0]);
delete Array.prototype.myExtra;
console.log(Object.getOwnPropertyNames(Array.prototype).includes('myExtra'), Object.getOwnPropertyNames([]).join());"#;

const NODE_OUTPUT: &str = r#"["length","constructor","at","concat","copyWithin","fill","find","findIndex","findLast","findLastIndex","lastIndexOf","pop","push","reverse","shift","unshift","slice","sort","splice","includes","indexOf","join","keys","entries","values","forEach","filter","flat","flatMap","map","every","some","reduce","reduceRight","toReversed","toSorted","toSpliced","with","toString"]
true
0 true true true
0 true symbol
true true false true
0 0 0 2
myExtra
false length"#;

fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "array-prototype-own-keys.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "array-prototype-own-keys.js"),
        &LoweringContext::new("apk-trace", "apk-decision", "apk-policy"),
    )
    .map_err(|error| format!("lower: {error:?}"))?
    .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "array-prototype-own-keys");
    let result = core.execute(&module);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "memory accounting drift"
    );
    let result = result.map_err(|error| format!("execute: {error:?}"))?;
    Ok(result
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n"))
}

#[test]
fn array_prototype_own_keys_match_node() {
    let output = console_output(PROGRAM).expect("the program runs");
    for (index, (actual, expected)) in output.lines().zip(NODE_OUTPUT.lines()).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), NODE_OUTPUT.lines().count());
}

/// bd-9vouw.249: the other built-in prototypes whose methods are served
/// virtually list their own names too:
/// `Object.getOwnPropertyNames(Map.prototype)` was empty, and
/// `Map.prototype.hasOwnProperty('size')` was false although `'size' in
/// Map.prototype` was true. OWN_NAMES_PROGRAM compares sorted names (the
/// engine lists methods alphabetically, not in Node's creation order) for
/// Map, Set, WeakMap, WeakSet, Promise, RegExp and SharedArrayBuffer, and
/// checks that the accessors stay non-enumerable.
const OWN_NAMES_PROGRAM: &str = r#"const names = (proto) => Object.getOwnPropertyNames(proto).sort().join(',');
console.log(names(Map.prototype));
console.log(names(Set.prototype));
console.log(names(WeakMap.prototype), '|', names(WeakSet.prototype));
console.log(names(Promise.prototype), '|', names(RegExp.prototype));
console.log(Object.keys(Map.prototype).length, Map.prototype.hasOwnProperty('size'), Object.getOwnPropertyNames(Object.create(Map.prototype)).length);
console.log(Map.prototype.propertyIsEnumerable('size'), Object.keys(Set.prototype).length, 'size' in Map.prototype, Object.getOwnPropertyNames(SharedArrayBuffer.prototype).sort().join(','));"#;

/// Node v22.2.0's output for `OWN_NAMES_PROGRAM`.
const OWN_NAMES_NODE_OUTPUT: &str = r#"clear,constructor,delete,entries,forEach,get,has,keys,set,size,values
add,clear,constructor,delete,difference,entries,forEach,has,intersection,isDisjointFrom,isSubsetOf,isSupersetOf,keys,size,symmetricDifference,union,values
constructor,delete,get,has,set | add,constructor,delete,has
catch,constructor,finally,then | compile,constructor,dotAll,exec,flags,global,hasIndices,ignoreCase,multiline,source,sticky,test,toString,unicode,unicodeSets
0 true 0
false 0 true byteLength,constructor,grow,growable,maxByteLength,slice"#;

#[test]
fn other_builtin_prototypes_list_their_own_names_bd_9vouw_249() {
    let output = console_output(OWN_NAMES_PROGRAM).expect("the program runs");
    for (index, (actual, expected)) in output
        .lines()
        .zip(OWN_NAMES_NODE_OUTPUT.lines())
        .enumerate()
    {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(
        output.lines().count(),
        OWN_NAMES_NODE_OUTPUT.lines().count()
    );
}

/// bd-9vouw.249 (regression found by the rc-next28 Test262 census): `delete`
/// of a built-in prototype accessor (`Map.prototype.size`,
/// `DataView.prototype.buffer`, `Symbol.prototype.description`) returned
/// true and left it: still an own property to hasOwnProperty (which this
/// bead had just taught to see the accessors), with a descriptor, and still
/// read through instances. Test262's verifyConfigurable deletes the property
/// and checks hasOwnProperty, so 11 prop-desc tests went red. A redefined
/// accessor that is then deleted is gone too (it came back as the built-in
/// one). DELETE_NODE_OUTPUT is Node v22.2.0's output, captured
/// programmatically.
const DELETE_PROGRAM: &str = r#"var hop = Function.prototype.call.bind(Object.prototype.hasOwnProperty);
var m = new Map([[1, 2]]);
console.log(m.size, delete Map.prototype.size, hop(Map.prototype, 'size'), Map.prototype.hasOwnProperty('size'), 'size' in Map.prototype, m.size);
console.log(delete DataView.prototype.buffer, hop(DataView.prototype, 'buffer'), Object.getOwnPropertyNames(DataView.prototype).indexOf('buffer'), new DataView(new ArrayBuffer(2)).buffer);
console.log(delete Set.prototype.size, Object.getOwnPropertyDescriptor(Set.prototype, 'size'), Reflect.has(Set.prototype, 'size'));
console.log(delete Symbol.prototype.description, hop(Symbol.prototype, 'description'), Symbol('d').description);
Object.defineProperty(RegExp.prototype, 'sticky', { get() { return 'mine'; }, configurable: true });
console.log(/a/.sticky, delete RegExp.prototype.sticky, /a/.sticky, hop(RegExp.prototype, 'sticky'), /a/y.flags);
console.log(delete Map.prototype.size, Object.getOwnPropertyNames(Map.prototype).indexOf('size'));"#;

/// Node v22.2.0's output for `DELETE_PROGRAM`.
const DELETE_NODE_OUTPUT: &str = r#"1 true false false false undefined
true false -1 undefined
true undefined false
true false undefined
mine true undefined false 
true -1"#;

#[test]
fn deleted_prototype_accessors_are_gone_bd_9vouw_249() {
    let output = console_output(DELETE_PROGRAM).expect("the program runs");
    for (index, (actual, expected)) in output.lines().zip(DELETE_NODE_OUTPUT.lines()).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), DELETE_NODE_OUTPUT.lines().count());
}
