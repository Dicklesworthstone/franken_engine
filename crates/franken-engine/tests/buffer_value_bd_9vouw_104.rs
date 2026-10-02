//! bd-9vouw.104: `Buffer` is a first-class constructor value.
//!
//! The global existed only as a lowering rewrite of `Buffer.from(...)` and the
//! other static member calls: `typeof Buffer` was 'undefined', `x instanceof
//! Buffer` threw ReferenceError, and Buffer instances had no prototype, so
//! `buf instanceof Uint8Array` was false and `buf.constructor` was Object.
//! Now `Buffer` is a global constructor whose statics route to the same
//! builtins, `Buffer.prototype` inherits from `Uint8Array.prototype` and
//! serves Buffer's methods ahead of the typed array ones, and every Buffer is
//! linked to it. Expected strings are Node v22.2.0's output for the same
//! programs.
//!
//! No-claim: `buf.map(...)` and the other species-creating methods return a
//! Uint8Array, not a Buffer (Node: Buffer); `Buffer.isEncoding`,
//! `Buffer.allocUnsafeSlow` and `class X extends Buffer` are not covered;
//! `Object.getPrototypeOf(Buffer)` is not `Uint8Array`.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

/// `Buffer` is a value: typeof, name, length, poolSize, an alias, and the global object's property.
#[test]
fn buffer_global_value() {
    let source = "const B = Buffer;\n\
         [typeof Buffer, Buffer.name, Buffer.length, Buffer.poolSize, B === Buffer, globalThis.Buffer === Buffer,\n\
          typeof B.from, B.from('hi').toString('hex')].join(' ');";
    assert_eq!(
        eval(source),
        "function Buffer 3 8192 true true function 6869"
    );
}

/// Statics read as values keep their behavior, names and lengths.
#[test]
fn buffer_statics_as_values() {
    let source = "const { from, alloc, concat, isBuffer, byteLength, compare } = Buffer;\n\
         [from('ab').toString(), alloc(2, 7).toString('hex'), concat([from('a'), from('b')]).toString(),\n\
          isBuffer(from('x')), isBuffer(new Uint8Array(1)), byteLength('h\\u00e9'), compare(from('a'), from('b')),\n\
          [Buffer.from, Buffer.alloc, Buffer.allocUnsafe, Buffer.byteLength, Buffer.concat, Buffer.compare, Buffer.isBuffer]\n\
            .map(f => f.name + '/' + f.length).join(',')].join(' ');";
    assert_eq!(
        eval(source),
        "ab 0707 ab true false 3 -1 from/3,alloc/3,allocUnsafe/1,byteLength/2,concat/2,compare/2,isBuffer/1"
    );
}

/// Instances inherit from Buffer.prototype, which inherits from Uint8Array.prototype.
#[test]
fn buffer_instances_link_to_buffer_prototype() {
    let source = "const b = Buffer.from('hi');\n\
         [b instanceof Buffer, b instanceof Uint8Array, Object.getPrototypeOf(b) === Buffer.prototype,\n\
          Object.getPrototypeOf(Buffer.prototype) === Uint8Array.prototype, b.constructor === Buffer, b.constructor.name,\n\
          b.buffer instanceof ArrayBuffer, new Uint8Array(2) instanceof Buffer, Buffer.alloc(1) instanceof Buffer,\n\
          b.subarray(1) instanceof Buffer, b.slice(0, 1) instanceof Uint8Array].join(' ');";
    assert_eq!(
        eval(source),
        "true true true true true Buffer true false true true true"
    );
}

/// Buffer's own methods shadow %TypedArray.prototype%'s, and the inherited ones still work.
#[test]
fn buffer_buffer_methods_win() {
    let source = "const b = Buffer.from('hi');\n\
         [b.toString(), String(b), b.subarray(1).toString(), b.slice(0, 1).toString(), JSON.stringify(b),\n\
          b.toString === Buffer.prototype.toString, typeof Buffer.prototype.readUInt8, typeof Buffer.prototype.map,\n\
          b.includes(105), b.indexOf('i'), Array.from(b.map(x => x + 1)).join(), b.reduce((a, x) => a + x, 0),\n\
          require('util').inspect(b), Object.prototype.toString.call(b)].join(' ');";
    assert_eq!(
        eval(source),
        "hi hi i h {\"type\":\"Buffer\",\"data\":[104,105]} true function function true 1 105,106 209 <Buffer 68 69> [object Uint8Array]"
    );
}

/// The is-buffer package's duck check and instanceof without a typeof guard.
#[test]
fn buffer_is_buffer_package_check() {
    let source = "function isBuffer(obj) {\n\
           return obj != null && obj.constructor != null && typeof obj.constructor.isBuffer === 'function' && obj.constructor.isBuffer(obj);\n\
         }\n\
         function bytes(x) { if (x instanceof Buffer) return 'buffer'; if (x instanceof Uint8Array) return 'u8'; return typeof x; }\n\
         [isBuffer(Buffer.from('a')), isBuffer(new Uint8Array(1)), isBuffer({}), isBuffer(null),\n\
          bytes(Buffer.from('a')), bytes(new Uint8Array(1)), bytes('s')].join(' ');";
    assert_eq!(eval(source), "true false false false buffer u8 string");
}

/// The deprecated Buffer(arg) and new Buffer(arg) forms.
#[test]
fn buffer_call_and_construct() {
    let source = "[new Buffer('ab').toString(), Buffer('cd').toString(), new Buffer(3).length, Buffer(2).toString('hex'),\n\
          new Buffer([1, 2]) instanceof Buffer].join(' ');";
    assert_eq!(eval(source), "ab cd 3 0000 true");
}
