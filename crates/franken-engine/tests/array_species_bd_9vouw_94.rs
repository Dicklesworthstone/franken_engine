//! bd-9vouw.94: ArraySpeciesCreate and @@species for the Array methods.
//!
//! map, filter, slice, splice, concat, flat and flatMap built a plain array
//! whatever the receiver's `constructor` said, so `class A extends Array {}`
//! instances returned Arrays, a `constructor[Symbol.species]` was never
//! consulted, and a non-object `constructor` did not throw. The built-in
//! constructors had no `[Symbol.species]`, and `new A(3)` ignored its
//! argument (length 0). PROGRAM covers subclass results, a species
//! override, a species function that builds a non-array, a null species,
//! the @@species reads, the order in splice (species before the receiver
//! changes), the TypeErrors, and a non-array receiver (no species).
//! NODE_OUTPUT is Node v22.2.0's output.
//!
//! PROGRAM_TYPED covers TypedArraySpeciesCreate (map, filter, slice,
//! subarray) and ArrayBuffer.prototype.slice's SpeciesConstructor: subclass
//! results, a species of another kind, the order (map's species before its
//! callbacks, filter's after), and the TypeErrors for a bad constructor,
//! a non-typed-array or too-short result, a content-type mismatch, and a
//! species buffer that is the receiver or too small.
//!
//! PROGRAM_DEFINE covers CreateDataPropertyOrThrow on a species result:
//! each Array method redefines a configurable property the species
//! constructor made non-writable, and a non-configurable property or a
//! non-extensible result is a TypeError.
//!
//! PROGRAM_FROM covers Array.from / Array.of with a constructor `this`: a
//! subclass inherits them and gets an instance of itself (they returned a
//! plain Array), a subclass constructor runs, a plain function receiver
//! builds a non-array, and Array.from itself still builds an Array.
//!
//! No-claim: an array-like source constructs with no argument (the spec
//! passes its length); only a constructor that reads its argument can tell.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const PROGRAM: &str = r#"class A extends Array {}
const a = new A(); a.push(1, 2, 3);
console.log(a.map((x) => x) instanceof A, a.filter(Boolean) instanceof A, a.slice(1) instanceof A, a.splice(0, 1) instanceof A, a.concat([4]) instanceof A, a.flat() instanceof A, a.flatMap((x) => [x]) instanceof A);
console.log(a.map((x) => x * 2).join(), a.filter((x) => x > 2).join(), a.slice(0, 1).length, new A(3).length, Reflect.construct(A, [3]).length, new A(1, 2).join(), new A('x').length);
class B extends Array { static get [Symbol.species]() { return Array; } }
const b = new B(); b.push(1, 2);
console.log(b.map((x) => x) instanceof B, b.map((x) => x).constructor === Array, B[Symbol.species] === Array);
const custom = [1, 2];
custom.constructor = { [Symbol.species]: function (n) { this.made = n; } };
const mapped = custom.map((x) => x + 1);
console.log(mapped.made, mapped[0], mapped[1], Array.isArray(mapped), mapped.length);
const nullSpecies = [1]; nullSpecies.constructor = { [Symbol.species]: null };
console.log(Array.isArray(nullSpecies.map((x) => x)), Object.getPrototypeOf(nullSpecies.slice()) === Array.prototype);
console.log(Array[Symbol.species] === Array, Map[Symbol.species] === Map, Set[Symbol.species] === Set, Promise[Symbol.species] === Promise, RegExp[Symbol.species] === RegExp, ArrayBuffer[Symbol.species] === ArrayBuffer, Uint8Array[Symbol.species] === Uint8Array, A[Symbol.species] === A);
function F() {}
console.log(F[Symbol.species], typeof Object[Symbol.species]);
const order = [];
const spliced = [1, 2, 3];
spliced.constructor = { [Symbol.species]: function (n) { order.push('species:' + n + ':' + spliced.length); } };
spliced.splice(0, 2);
console.log(order.join(), spliced.join());
for (const [label, run] of [
  ['constructor not object', () => { const x = [1]; x.constructor = 5; x.map((v) => v); }],
  ['species not constructor', () => { const x = [1]; x.constructor = { [Symbol.species]: 7 }; x.filter(Boolean); }],
  ['non-array receiver ignores constructor', () => { const o = { length: 1, 0: 'a', constructor: 5 }; return Array.prototype.map.call(o, (v) => v); }],
]) {
  try { const r = run(); console.log(label, 'no throw', Array.isArray(r)); } catch (e) { console.log(label, e.constructor.name); }
}"#;

const NODE_OUTPUT: &str = r#"true true true true true true true
4,6 3 1 3 3 1,2 1
false true true
2 2 3 false undefined
true true
true true true true true true true true
undefined undefined
species:2:3 3
constructor not object TypeError
species not constructor TypeError
non-array receiver ignores constructor no throw true"#;

const PROGRAM_TYPED: &str = r#"class U extends Uint8Array {}
const u = new U([1, 2, 3, 4]);
console.log(u instanceof U, u.map((x) => x * 2) instanceof U, u.filter((x) => x > 1) instanceof U, u.slice(1) instanceof U, u.subarray(1) instanceof U);
console.log(Array.from(u.map((x) => x * 2)).join(), Array.from(u.filter((x) => x > 2)).join(), Array.from(u.slice(1, 3)).join(), Array.from(u.subarray(2)).join(), u.subarray(1).byteOffset);
const plain = new Uint8Array([1, 2]);
plain.constructor = { [Symbol.species]: Uint16Array };
const widened = plain.map((x) => x * 300);
console.log(widened.constructor.name, Array.from(widened).join(), plain.slice().constructor.name);
const order = [];
const ordered = new Uint8Array([5, 6]);
ordered.constructor = { [Symbol.species]: function (n) { order.push('species:' + n); return new Uint8Array(n); } };
ordered.map((x) => { order.push('cb:' + x); return x; });
ordered.filter((x) => { order.push('fcb:' + x); return true; });
console.log(order.join());
class AB extends ArrayBuffer {}
const ab = new AB(8);
console.log(ab instanceof AB, ab.slice(2) instanceof AB, ab.slice(2).byteLength, ArrayBuffer[Symbol.species] === ArrayBuffer, AB[Symbol.species] === AB);
for (const [label, run] of [
  ['constructor not object', () => { const x = new Uint8Array(1); x.constructor = 1; x.map((v) => v); }],
  ['species result not typed array', () => { const x = new Uint8Array(1); x.constructor = { [Symbol.species]: function () { return {}; } }; x.filter(() => true); }],
  ['species result too short', () => { const x = new Uint8Array(4); x.constructor = { [Symbol.species]: function () { return new Uint8Array(1); } }; x.slice(); }],
  ['content type mismatch', () => { const x = new Uint8Array(1); x.constructor = { [Symbol.species]: BigInt64Array }; x.map((v) => v); }],
  ['buffer species returns same', () => { const b = new ArrayBuffer(4); b.constructor = { [Symbol.species]: function () { return b; } }; b.slice(); }],
  ['buffer species too small', () => { const b = new ArrayBuffer(4); b.constructor = { [Symbol.species]: function () { return new ArrayBuffer(1); } }; b.slice(); }],
]) {
  try { run(); console.log(label, 'no throw'); } catch (e) { console.log(label, e.constructor.name); }
}"#;

const NODE_OUTPUT_TYPED: &str = r#"true true true true true
2,4,6,8 3,4 2,3 3,4 1
Uint16Array 300,600 Uint16Array
species:2,cb:5,cb:6,fcb:5,fcb:6,species:2
true true 6 true true
constructor not object TypeError
species result not typed array TypeError
species result too short TypeError
content type mismatch TypeError
buffer species returns same TypeError
buffer species too small TypeError"#;

const PROGRAM_DEFINE: &str = r#"function speciesOf(C) { return { [Symbol.species]: C }; }
var Readonly0 = function () { Object.defineProperty(this, '0', { value: 1, writable: false, enumerable: false, configurable: true }); };
for (const [label, run] of [
  ['concat', (a) => a.concat(2)],
  ['map', (a) => a.map((x) => x * 2)],
  ['filter', (a) => a.filter(() => true)],
  ['slice', (a) => a.slice(0)],
  ['splice', (a) => a.splice(0, 1)],
  ['flat', (a) => a.flat()],
  ['flatMap', (a) => a.flatMap((x) => [x])],
]) {
  const source = [7]; source.constructor = speciesOf(Readonly0);
  const d = Object.getOwnPropertyDescriptor(run(source), '0');
  console.log(label, d.value, d.writable, d.enumerable, d.configurable);
}
var Locked0 = function () { Object.defineProperty(this, '0', { value: 1, writable: false, configurable: false }); };
var Sealed = function () { Object.preventExtensions(this); };
for (const [label, C] of [['non-configurable', Locked0], ['non-extensible', Sealed]]) {
  const source = [7]; source.constructor = speciesOf(C);
  try { source.map((x) => x); console.log(label, 'no throw'); } catch (e) { console.log(label, e.constructor.name); }
}"#;

const NODE_OUTPUT_DEFINE: &str = r#"concat 7 true true true
map 14 true true true
filter 7 true true true
slice 7 true true true
splice 7 true true true
flat 7 true true true
flatMap 7 true true true
non-configurable TypeError
non-extensible TypeError"#;

const PROGRAM_FROM: &str = r#"class A extends Array {}
class B extends Array { constructor(...a) { super(...a); this.tag = 'b'; } }
function F() { this.made = true; }
var a = A.from([1, 2, 3]); var o = A.of(7, 8); var b = B.from(new Set(['x', 'y'])); var f = Array.from.call(F, [5, 6]);
console.log(a instanceof A, a.length, a.join(), o instanceof A, o.join(), b instanceof B, b.tag, b.join(), f instanceof F, f.made, f.length, f[1], Array.isArray(f), Array.from([1]).constructor === Array, A.from([4], x => x * 2).join());
"#;

const NODE_OUTPUT_FROM: &str = r#"true 3 1,2,3 true 7,8 true b x,y true true 2 6 false true 8
"#;

/// bd-9vouw.278: each of Array, ArrayBuffer, Map, Promise, RegExp, Set,
/// SharedArrayBuffer and %TypedArray% has its own `get [Symbol.species]`
/// accessor (ES2020 22.1.2.5 and the like): not enumerable, configurable,
/// no setter, `return this`. The concrete typed array constructors inherit
/// it. A delete or redefinition is what later reads (and species lookups)
/// see. Promise's statics are in Node's order. Expected: Node v22.2.0's
/// output, captured programmatically.
const PROGRAM_SPECIES_GETTERS: &str = r#"function d(C) { var x = Object.getOwnPropertyDescriptor(C, Symbol.species); return x ? [typeof x.get, x.get.name, x.get.length, x.set, x.enumerable, x.configurable, x.get.call(7) === 7].join() : 'none'; }
var TA = Object.getPrototypeOf(Int8Array);
console.log(['Array', 'ArrayBuffer', 'Map', 'Promise', 'RegExp', 'Set', 'SharedArrayBuffer'].map(function (n) { return n + ':' + d(globalThis[n]); }).join(' '));
console.log(d(TA), d(Int8Array), Int8Array[Symbol.species] === Int8Array, Reflect.ownKeys(Map).indexOf(Symbol.species) >= 0, Object.getOwnPropertySymbols(Set).length);
class A extends Array {}
console.log(A[Symbol.species] === A, Object.getOwnPropertyDescriptor(Array, Symbol.species).get.call(A) === A);
console.log(delete Array[Symbol.species], Array[Symbol.species], A[Symbol.species], new A(1, 2).map(function (x) { return x; }).constructor === Array);
Object.defineProperty(Map, Symbol.species, { value: 'v' });
console.log(Map[Symbol.species], delete Promise[Symbol.species], Promise[Symbol.species], Object.getOwnPropertyNames(Promise).join());"#;

const NODE_OUTPUT_SPECIES_GETTERS: &str = r#"Array:function,get [Symbol.species],0,,false,true,true ArrayBuffer:function,get [Symbol.species],0,,false,true,true Map:function,get [Symbol.species],0,,false,true,true Promise:function,get [Symbol.species],0,,false,true,true RegExp:function,get [Symbol.species],0,,false,true,true Set:function,get [Symbol.species],0,,false,true,true SharedArrayBuffer:function,get [Symbol.species],0,,false,true,true
function,get [Symbol.species],0,,false,true,true none true true 1
true true
true undefined undefined true
v true undefined length,name,prototype,all,allSettled,any,race,resolve,reject,withResolvers"#;

fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "array-species.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "array-species.js"),
        &LoweringContext::new("species-trace", "species-decision", "species-policy"),
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
    let mut core = InterpreterCore::new(config, "array-species");
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
fn array_methods_use_species_like_node() {
    let output = console_output(PROGRAM).expect("the program runs");
    for (index, (actual, expected)) in output.lines().zip(NODE_OUTPUT.lines()).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), NODE_OUTPUT.lines().count());
}

#[test]
fn typed_array_and_array_buffer_methods_use_species_like_node() {
    let output = console_output(PROGRAM_TYPED).expect("the program runs");
    for (index, (actual, expected)) in output.lines().zip(NODE_OUTPUT_TYPED.lines()).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), NODE_OUTPUT_TYPED.lines().count());
}

#[test]
fn species_results_get_create_data_property_semantics() {
    let output = console_output(PROGRAM_DEFINE).expect("the program runs");
    for (index, (actual, expected)) in output.lines().zip(NODE_OUTPUT_DEFINE.lines()).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), NODE_OUTPUT_DEFINE.lines().count());
}

#[test]
fn array_from_and_of_construct_their_this_bd_9vouw_94() {
    let output = console_output(PROGRAM_FROM).expect("the program runs");
    assert_eq!(output, NODE_OUTPUT_FROM.trim_end());
}

#[test]
fn builtin_constructors_own_species_getters_bd_9vouw_278() {
    let output = console_output(PROGRAM_SPECIES_GETTERS).expect("the program runs");
    assert_eq!(output, NODE_OUTPUT_SPECIES_GETTERS);
}

/// ArrayCreate rejects an impossible array length before visiting any
/// element. The throwing first element makes the pre-fix failure bounded:
/// it reports Error instead of walking billions of indices.
#[test]
fn array_species_rejects_oversized_default_results_before_elements() {
    let source = r#"
function attempt(f) { try { f(); return 'ok'; } catch (e) { return e.constructor.name; } }
var reads = 0;
var callbacks = 0;
function plain() {
    return { length: 4294967296,
        get 0() { reads++; throw new Error('element'); },
        get constructor() { throw new Error('non-array constructor'); }
    };
}
function proxied(constructor) {
    var target = [];
    target.constructor = constructor;
    return new Proxy(target, {
        get(t, key) { return key === 'length' ? 4294967296 : Reflect.get(t, key); },
        has() { reads++; throw new Error('element'); }
    });
}
function callback(value) { callbacks++; return value; }
var slice = Array.prototype.slice;
var splice = Array.prototype.splice;
var map = Array.prototype.map;
console.log(attempt(() => slice.call(plain())), attempt(() => splice.call(plain(), 0)), attempt(() => map.call(plain(), callback)));
for (var constructor of [undefined, Array, {}, { [Symbol.species]: null }, { [Symbol.species]: Array }]) {
    console.log(attempt(() => slice.call(proxied(constructor))), attempt(() => splice.call(proxied(constructor), 0)), attempt(() => map.call(proxied(constructor), callback)));
}
console.log(reads, callbacks, attempt(() => map.call(plain(), null)));
"#;
    let output = console_output(source).expect("oversized results throw catchable RangeErrors");
    assert_eq!(
        output,
        "RangeError RangeError RangeError\nRangeError RangeError RangeError\nRangeError RangeError RangeError\nRangeError RangeError RangeError\nRangeError RangeError RangeError\nRangeError RangeError RangeError\n0 0 TypeError"
    );
}

/// The length limit belongs to ArrayCreate, after constructor/species
/// lookup. It must not preempt a custom species or reject 2^32 - 1.
#[test]
fn array_species_length_validation_preserves_constructor_and_element_order() {
    let source = r#"
function attempt(f) { try { f(); return 'ok'; } catch (e) { return e.message; } }
function input(length, constructor) {
    var target = [];
    target.constructor = constructor;
    return new Proxy(target, {
        get(t, key) { return key === 'length' ? length : Reflect.get(t, key); },
        has() { throw new Error('first element'); }
    });
}
function Species(length) { throw new Error('species:' + length); }
var custom = { [Symbol.species]: Species };
var slice = Array.prototype.slice;
var splice = Array.prototype.splice;
var map = Array.prototype.map;
console.log(attempt(() => slice.call(input(4294967296, custom))), attempt(() => splice.call(input(4294967296, custom), 0)), attempt(() => map.call(input(4294967296, custom), x => x)));
console.log(attempt(() => slice.call(input(4294967295, undefined))), attempt(() => splice.call(input(4294967295, undefined), 0)), attempt(() => map.call(input(4294967295, undefined), x => x)));
var order = [];
var source = new Proxy([], {
    get(t, key) {
        order.push(String(key));
        if (key === 'length') return 4294967296;
        if (key === 'constructor') return { get [Symbol.species]() { order.push('species'); return undefined; } };
        return Reflect.get(t, key);
    }
});
try { slice.call(source, { valueOf() { order.push('start'); return 0; } }); } catch (e) { order.push(e.constructor.name); }
console.log(order.join(','));
"#;
    let output = console_output(source).expect("species and element exceptions remain observable");
    assert_eq!(
        output,
        "species:4294967296 species:4294967296 species:4294967296\nfirst element first element first element\nlength,start,constructor,species,RangeError"
    );
}

/// Generic array methods must share ArraySpeciesCreate with ordinary
/// arrays. Arbitrary species objects get CreateDataPropertyOrThrow; map
/// and filter do not set their length, while slice/splice/concat do.
#[test]
fn generic_array_methods_use_species_and_create_data_properties() {
    let source = r#"
function Species(length) {
    this.requested = length;
    Object.defineProperty(this, '0', { value: 'old', writable: false, configurable: true });
}
function input() {
    var target = [4, 5];
    target.constructor = { [Symbol.species]: Species };
    return new Proxy(target, {});
}
for (var method of ['map', 'filter', 'slice', 'splice', 'concat']) {
    var source = input();
    var result;
    if (method === 'map') result = source.map(x => x * 2);
    else if (method === 'filter') result = source.filter(x => x > 4);
    else if (method === 'slice') result = source.slice(0, 1);
    else if (method === 'splice') result = source.splice(0, 1);
    else result = source.concat([6]);
    var descriptor = Object.getOwnPropertyDescriptor(result, '0');
    console.log(method, result instanceof Species, result.requested, result.length, result[0], descriptor.writable, descriptor.enumerable, descriptor.configurable);
}
Object.defineProperty(Array, Symbol.species, { value: Species, configurable: true });
var ordinary = [1, 2].map(x => x + 1);
console.log(ordinary instanceof Species, ordinary.requested, ordinary.length, ordinary[0]);
"#;
    let output = console_output(source).expect("generic and ordinary species results run");
    assert_eq!(
        output,
        "map true 2 undefined 8 true true true\nfilter true 0 undefined 5 true true true\nslice true 1 1 4 true true true\nsplice true 1 1 4 true true true\nconcat true 0 3 4 true true true\ntrue 2 undefined 2"
    );
}

#[test]
fn generic_array_species_proxy_observes_definitions_and_length_sets() {
    let source = r#"
var events = [];
function Species(length) {
    events.push('species:' + length);
    return new Proxy({}, {
        defineProperty(target, key, descriptor) {
            events.push('define:' + key + ':' + descriptor.writable + ':' + descriptor.enumerable + ':' + descriptor.configurable);
            return Reflect.defineProperty(target, key, descriptor);
        },
        set(target, key, value) { events.push('set:' + key + ':' + value); return Reflect.set(target, key, value); }
    });
}
for (var method of ['map', 'filter', 'slice', 'splice', 'concat']) {
    events = [];
    var target = [7];
    target.constructor = { [Symbol.species]: Species };
    var source = new Proxy(target, {});
    if (method === 'map') source.map(x => x);
    else if (method === 'filter') source.filter(x => true);
    else if (method === 'slice') source.slice();
    else if (method === 'splice') source.splice(0);
    else source.concat();
    console.log(method, events.join(','));
}
"#;
    let output = console_output(source).expect("species proxy traps run in specification order");
    assert_eq!(
        output,
        "map species:1,define:0:true:true:true\nfilter species:0,define:0:true:true:true\nslice species:1,define:0:true:true:true,set:length:1\nsplice species:1,define:0:true:true:true,set:length:1\nconcat species:0,define:0:true:true:true,set:length:1"
    );
}

#[test]
fn generic_array_species_refusals_stop_before_splice_mutates_the_source() {
    let source = r#"
function Locked() {
    Object.defineProperty(this, '0', { value: 'locked', configurable: false });
}
function Sealed() { return Object.preventExtensions({}); }
function Refusing() { return new Proxy({}, { defineProperty() { return false; } }); }
for (var Species of [Locked, Sealed, Refusing]) {
    var target = [7, 8];
    target.constructor = { [Symbol.species]: Species };
    var source = new Proxy(target, {});
    try { source.splice(0, 1); console.log('unexpected success'); }
    catch (e) { console.log(e.constructor.name, target.join(',')); }
}
"#;
    let output = console_output(source).expect("species refusals are catchable TypeErrors");
    assert_eq!(output, "TypeError 7,8\nTypeError 7,8\nTypeError 7,8");
}

/// Species can return an object already reachable through a public alias.
/// Read that untouched alias into a fresh register after the source completes.
/// A public control register proves that catch or callback context cannot
/// conceal missing provenance on the stored elements.
#[test]
fn generic_species_copies_preserve_public_alias_labels_after_success_and_partial_failure() {
    use frankenengine_engine::baseline_interpreter::Value;
    use frankenengine_engine::ifc_artifacts::Label;
    use frankenengine_engine::ir_contract::{Ir3Instruction, Ir3Module};

    fn lower(source: &str) -> Ir3Module {
        let tree = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "species-alias-labels.js".into(),
                    text: source.into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .unwrap();
        lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "species-alias-labels.js"),
            &LoweringContext::new("species-trace", "species-decision", "species-policy"),
        )
        .unwrap()
        .ir3
    }

    let source = r#"
        const output = 424241;
        if (PARTIAL) Object.defineProperty(output, BLOCKED_KEY, { value: 'locked' });
        const destination = PROXIED ? new Proxy(output, {
            defineProperty(target, key, descriptor) {
                JSON.parse('0');
                return Reflect.defineProperty(target, key, descriptor);
            },
            set(target, key, value) {
                JSON.parse('0');
                return Reflect.set(target, key, value);
            }
        }) : output;
        function Species() { return destination; }
        const source = INITIAL_SOURCE;
        source.constructor = { [Symbol.species]: Species };
        source[SECRET_KEY] = 424242;
        let state = 'success';
        try { source.slice({ valueOf() { return 0; } }); }
        catch (error) { state = error.name; }
        state;
    "#;
    for length_only in [false, true] {
        for proxied in [false, true] {
            for partial in [false, true] {
                let source = source
                    .replace("PROXIED", if proxied { "true" } else { "false" })
                    .replace("PARTIAL", if partial { "true" } else { "false" })
                    .replace("BLOCKED_KEY", if length_only { "'length'" } else { "'1'" })
                    .replace("INITIAL_SOURCE", if length_only { "[]" } else { "[0, 8]" })
                    .replace("SECRET_KEY", if length_only { "'length'" } else { "'0'" });
                let mut module = lower(&source);
                let mut markers = [0, 0];
                for instruction in &mut module.instructions {
                    if let Ir3Instruction::LoadInt { dst, value } = instruction {
                        let marker = match *value {
                            424241 => Some((0, 200)),
                            424242 => Some((1, 201)),
                            _ => None,
                        };
                        if let Some((index, seed)) = marker {
                            markers[index] += 1;
                            *instruction = Ir3Instruction::Move {
                                dst: *dst,
                                src: seed,
                            };
                        }
                    }
                }
                assert_eq!(markers, [1, 1], "each seeded source marker is unique");
                // Branchless observation after the script's completion; append
                // it so function entries and all existing jump targets stay valid.
                let observation = module.instructions.len() as u32;
                let script_end = module
                    .instructions
                    .iter()
                    .position(|instruction| matches!(instruction, Ir3Instruction::Halt))
                    .expect("main code precedes its Halt and appended function bodies");
                let mut returns = 0;
                for instruction in &mut module.instructions[..script_end] {
                    if let Ir3Instruction::Return { value } = instruction {
                        assert_eq!(*value, 0, "script completion is carried by r0");
                        returns += 1;
                        *instruction = Ir3Instruction::Jump {
                            target: observation,
                        };
                    }
                }
                assert_eq!(
                    returns, 1,
                    "one script completion precedes alias observation"
                );
                let separator = module.constant_pool.len() as u32;
                module.constant_pool.push("|".into());
                module.instructions.extend([
                    Ir3Instruction::LoadInt { dst: 204, value: 0 },
                    Ir3Instruction::GetProperty {
                        obj: 200,
                        key: 202,
                        dst: 203,
                    },
                    Ir3Instruction::LoadStr {
                        dst: 205,
                        pool_index: separator,
                    },
                    Ir3Instruction::Add {
                        dst: 206,
                        lhs: 0,
                        rhs: 205,
                    },
                    Ir3Instruction::Add {
                        dst: 207,
                        lhs: 206,
                        rhs: 203,
                    },
                    Ir3Instruction::Return { value: 207 },
                ]);
                for source_label in [Label::Public, Label::Secret] {
                    for mut config in [
                        InterpreterConfig::quickjs_defaults(),
                        InterpreterConfig::v8_defaults(),
                    ] {
                        config.granted_capabilities = [
                            RuntimeCapability::VmDispatch,
                            RuntimeCapability::HeapAllocate,
                            RuntimeCapability::Builtin,
                        ]
                        .into_iter()
                        .collect();
                        let mut core = InterpreterCore::new(config, "species-alias-labels");
                        let output = core.alloc_object_with_prototype(None).unwrap();
                        core.seed_register(200, Value::Object(output)).unwrap();
                        core.seed_register(201, Value::Int(7)).unwrap();
                        core.seed_register(
                            202,
                            Value::str(if length_only { "length" } else { "0" }),
                        )
                        .unwrap();
                        core.set_register_label(201, source_label.clone()).unwrap();
                        let result = core.execute(&module).unwrap();
                        assert_eq!(
                            result.value,
                            Value::str(if length_only && partial {
                                "TypeError|locked"
                            } else if partial {
                                "TypeError|7"
                            } else {
                                "success|7"
                            }),
                            "length_only={length_only}, proxied={proxied}, partial={partial}"
                        );
                        assert_eq!(
                            core.get_register_label(203).unwrap(),
                            &source_label,
                            "length_only={length_only}, proxied={proxied}, partial={partial}"
                        );
                        assert_eq!(core.get_register_label(200).unwrap(), &Label::Public);
                        assert_eq!(core.get_register_label(204).unwrap(), &Label::Public);
                        assert_eq!(
                            core.estimated_memory_bytes(),
                            core.recompute_estimated_memory_bytes()
                        );
                    }
                }
            }
        }
    }
}
