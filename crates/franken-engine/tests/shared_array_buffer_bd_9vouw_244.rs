#![forbid(unsafe_code)]

//! bd-9vouw.244: SharedArrayBuffer (ES2020 24.2) was not defined. Test262
//! has about 300 Node-passing failures with "SharedArrayBuffer is not
//! defined" across ArrayBuffer, TypedArray, DataView and Atomics.
//! whatwg-url (under node-fetch v2) failed to load:
//! webidl-conversions reads
//! `Object.getOwnPropertyDescriptor(SharedArrayBuffer.prototype,
//! "byteLength").get` and the `resizable` and `growable` getters when it
//! loads.
//!
//! PROGRAM covers:
//! - construction, typed array and DataView views over a SharedArrayBuffer;
//! - slice, including a subclass;
//! - the fixed-length getters (growable, maxByteLength) and grow;
//! - calls without `new`;
//! - each kind's byteLength getter and slice refusing the other kind;
//! - the ArrayBuffer resizable/maxByteLength/detached getters;
//! - toStringTag, lengths and own keys.
//!
//! Expected lines are Node v22.2.0's output, captured programmatically.
//!
//! No-claim: no buffer is growable or resizable (a maxByteLength option is
//! ignored) and nothing detaches. One agent runs, so no bytes are shared
//! with another thread. Atomics is not part of this.

use frankenengine_engine::HybridRouter;

#[test]
fn shared_array_buffer_matches_node_bd_9vouw_244() {
    let source = r#"function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var sab = new SharedArrayBuffer(8);
var view = new Int32Array(sab);
view[1] = 42;
console.log(typeof SharedArrayBuffer, SharedArrayBuffer.length, SharedArrayBuffer.name, sab.byteLength, Object.prototype.toString.call(sab), sab instanceof SharedArrayBuffer, sab instanceof ArrayBuffer);
console.log(view.buffer === sab, view.length, view[1], new Uint8Array(sab)[4], new DataView(sab).getInt32(4, true));
var piece = sab.slice(4);
console.log(piece instanceof SharedArrayBuffer, piece.byteLength, new Int32Array(piece)[0], sab.slice(-4, -2).byteLength, sab.slice().byteLength);
console.log(sab.growable, sab.maxByteLength, attempt(() => sab.grow(16)), attempt(() => SharedArrayBuffer(4)), attempt(() => new SharedArrayBuffer(-1)));
var abByteLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
var sabByteLength = Object.getOwnPropertyDescriptor(SharedArrayBuffer.prototype, 'byteLength').get;
var ab = new ArrayBuffer(3);
console.log(attempt(() => abByteLength.call(sab)), attempt(() => sabByteLength.call(ab)), sabByteLength.call(sab), abByteLength.call(ab));
console.log(attempt(() => ArrayBuffer.prototype.slice.call(sab)), attempt(() => SharedArrayBuffer.prototype.slice.call(ab)), ArrayBuffer.isView(sab), ArrayBuffer.isView(view));
var d = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'resizable');
console.log(typeof d.get, ab.resizable, ab.maxByteLength, ab.detached, Object.getOwnPropertyDescriptor(SharedArrayBuffer.prototype, 'growable').get.call(sab));
console.log(SharedArrayBuffer.prototype[Symbol.toStringTag], SharedArrayBuffer.prototype.constructor === SharedArrayBuffer, SharedArrayBuffer.prototype.slice.length, SharedArrayBuffer.prototype.grow.length, SharedArrayBuffer.prototype.slice === ArrayBuffer.prototype.slice);
class MySab extends SharedArrayBuffer {}
var mine = new MySab(2);
console.log(mine instanceof MySab, mine.byteLength, mine.slice(1) instanceof SharedArrayBuffer);
console.log(Object.getOwnPropertyNames(SharedArrayBuffer.prototype).sort().join(','));
console.log(new SharedArrayBuffer(2));
console.log([new ArrayBuffer(1)]);"#;
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
            r#"function 1 SharedArrayBuffer 8 [object SharedArrayBuffer] true false"#,
            r#"true 2 42 42 42"#,
            r#"true 4 42 2 8"#,
            r#"false 8 TypeError TypeError RangeError"#,
            r#"TypeError TypeError 8 3"#,
            r#"TypeError TypeError false true"#,
            r#"function false 3 false false"#,
            r#"SharedArrayBuffer true 2 1 false"#,
            r#"true 2 true"#,
            r#"byteLength,constructor,grow,growable,maxByteLength,slice"#,
            r#"SharedArrayBuffer { [Uint8Contents]: <00 00>, byteLength: 2 }"#,
            r#"[ ArrayBuffer { [Uint8Contents]: <00>, byteLength: 1 } ]"#,
        ]
    );
}
