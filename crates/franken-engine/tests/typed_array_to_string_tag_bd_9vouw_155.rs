//! bd-9vouw.155: %TypedArray%.prototype[@@toStringTag] is an accessor
//! (ES2020 22.2.3.32) whose getter returns the receiver's [[TypedArrayName]]
//! and undefined for anything else. It was missing, so
//! `Object.getOwnPropertyDescriptor(%TypedArray%.prototype,
//! Symbol.toStringTag).get` threw while safe-stable-stringify (used by pino
//! and winston) loaded, and `new Uint8Array(1)[Symbol.toStringTag]` was
//! undefined. Expected strings are Node v22.2.0's output for the same
//! programs.
//!
//! No-claim: the string-keyed methods of %TypedArray%.prototype are still
//! not listed by Object.getOwnPropertyNames (bd-9vouw.68), nor is its
//! @@iterator by Object.getOwnPropertySymbols.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

/// The descriptor is an accessor with the spec's attributes and getter name.
#[test]
fn typed_array_to_string_tag_accessor_descriptor() {
    let source = "var TA = Object.getPrototypeOf(Uint8Array.prototype);\n\
         var d = Object.getOwnPropertyDescriptor(TA, Symbol.toStringTag);\n\
         [typeof d.get, d.set, d.enumerable, d.configurable, 'value' in d, d.get.name, d.get.length,\n\
          Object.getOwnPropertySymbols(TA).includes(Symbol.toStringTag)].join(' ');";
    assert_eq!(
        eval(source),
        "function  false true false get [Symbol.toStringTag] 0 true"
    );
}

/// The getter names each typed array kind and is undefined for other receivers, without throwing.
#[test]
fn typed_array_to_string_tag_getter_on_receivers() {
    let source = "var get = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Int8Array.prototype), Symbol.toStringTag).get;\n\
         [get.call(new Int8Array(1)), get.call(new Float64Array(1)), get.call(new Uint8ClampedArray(1)),\n\
          String(get.call({})), String(get.call(new ArrayBuffer(1))), String(get.call(new DataView(new ArrayBuffer(1)))),\n\
          String(get.call(1)), String(get.call(undefined)), String(get.call([]))].join(' ');";
    assert_eq!(
        eval(source),
        "Int8Array Float64Array Uint8ClampedArray undefined undefined undefined undefined undefined undefined"
    );
}

/// [[Get]] on instances reaches the getter, and a subclass can shadow it.
#[test]
fn typed_array_to_string_tag_instances_inherit_the_tag() {
    let source = "class Mine extends Uint16Array { get [Symbol.toStringTag]() { return 'Mine'; } }\n\
         [new Uint8Array(2)[Symbol.toStringTag], new BigInt64Array(1)[Symbol.toStringTag],\n\
          Object.prototype.toString.call(new Int32Array(1)), new Mine(1)[Symbol.toStringTag],\n\
          Object.prototype.toString.call(new Mine(1)), Uint8Array.prototype[Symbol.toStringTag] === undefined].join(' ');";
    assert_eq!(
        eval(source),
        "Uint8Array BigInt64Array [object Int32Array] Mine [object Mine] true"
    );
}

/// safe-stable-stringify's load-time read and its use of the getter.
#[test]
fn typed_array_to_string_tag_safe_stable_stringify_load_shape() {
    let source = "var typedArrayPrototypeGetSymbolToStringTag = Object.getOwnPropertyDescriptor(\n\
           Object.getPrototypeOf(Object.getPrototypeOf(new Int8Array())), Symbol.toStringTag).get;\n\
         function isTypedArrayWithEntries(value) {\n\
           return typedArrayPrototypeGetSymbolToStringTag.call(value) !== undefined && value.length !== 0;\n\
         }\n\
         [isTypedArrayWithEntries(new Uint8Array(2)), isTypedArrayWithEntries(new Uint8Array(0)),\n\
          isTypedArrayWithEntries([1]), isTypedArrayWithEntries({ length: 3 })].join(' ');";
    assert_eq!(eval(source), "true false false false");
}
