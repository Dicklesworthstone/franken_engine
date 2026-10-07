#![forbid(unsafe_code)]

//! bd-9vouw.256: resizable ArrayBuffers, growable SharedArrayBuffers and
//! ArrayBuffer transfer (ES2024 25.1, 25.2). The engine had none of them:
//! 452 Node-passing Test262 tests declaring resizable-arraybuffer or
//! arraybuffer-transfer failed (TypedArray/prototype 183, ArrayBuffer 91,
//! Array/prototype 78, SharedArrayBuffer 34, DataView 24).
//!
//! PROGRAM covers:
//! - the maxByteLength option, the resizable/maxByteLength getters and the
//!   RangeError/TypeError cases of construction and `resize`;
//! - a length-tracking typed array and DataView following resizes, and
//!   fixed-length ones going out of bounds (lengths and offset 0, element
//!   reads undefined, writes ignored, methods and the DataView accessors
//!   TypeError) and back in bounds when the buffer grows;
//! - `subarray` of a length-tracking array tracking too;
//! - a typed array iterator seeing growth, and TypeError once its array
//!   is out of bounds;
//! - growable SharedArrayBuffers and `grow`;
//! - `transfer` / `transferToFixedLength`, the detached getter, and
//!   TypeErrors on a detached buffer and its views;
//! - the new methods' lengths, names and the prototype's own names.
//!
//! Expected lines are Node v22.2.0's output, captured programmatically.
//!
//! No-claim: `maxByteLength` above 2^45 is refused, as Node does on this
//! host, and a resize past the 8 MiB per-buffer cap is a RangeError. A
//! DataView constructor whose NewTarget's `prototype` getter resizes the
//! buffer is not re-checked (ES2024 25.3.2.1 steps 11-14), and
//! structuredClone does not preserve resizability.

use frankenengine_engine::HybridRouter;

#[test]
fn resizable_array_buffers_match_node_bd_9vouw_256() {
    let source = r#"function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var rab = new ArrayBuffer(8, { maxByteLength: 16 });
console.log(rab.resizable, rab.maxByteLength, rab.byteLength, new ArrayBuffer(4).resizable, new ArrayBuffer(4).maxByteLength, new ArrayBuffer(0, null).resizable, new ArrayBuffer(0, { maxByteLength: undefined }).resizable);
console.log(attempt(() => new ArrayBuffer(9, { maxByteLength: 8 })), attempt(() => new ArrayBuffer(0, { maxByteLength: -1 })), attempt(() => new ArrayBuffer(0, { get maxByteLength() { throw new SyntaxError('x'); } })), attempt(() => new ArrayBuffer(4).resize(2)));
var tracking = new Uint16Array(rab);
var fixed = new Uint8Array(rab, 2, 4);
var view = new DataView(rab);
var fixedView = new DataView(rab, 4, 2);
tracking[0] = 0x0102; fixed[3] = 9;
console.log(tracking.length, fixed.length, view.byteLength, fixedView.byteLength, fixed.byteOffset, view.getUint8(5));
console.log(attempt(() => rab.resize(17)), attempt(() => rab.resize(-1)), rab.resize(12), rab.byteLength, tracking.length, tracking.byteLength, fixed.length, view.byteLength, fixedView.byteLength);
rab.resize(4);
console.log(tracking.length, fixed.length, fixed.byteLength, fixed.byteOffset, fixed[0], attempt(() => fixed.fill(1)), attempt(() => fixed.join()), attempt(() => [...fixed]), view.byteLength, attempt(() => fixedView.byteLength), attempt(() => fixedView.getUint8(0)));
fixed[0] = 5;
console.log(Object.keys(fixed).length, 0 in fixed, Array.prototype.join.call(fixed), tracking[0], tracking[1]);
rab.resize(10);
console.log(tracking.length, fixed.length, fixed.byteOffset, Array.from(fixed).join(), fixedView.byteLength, fixedView.byteOffset, Array.from(new Uint8Array(rab)).join());
var sub = tracking.subarray(1);
var subFixed = tracking.subarray(1, 3);
rab.resize(16);
console.log(sub.length, sub.byteOffset, subFixed.length, tracking.length);
var seen = [];
var grower = new ArrayBuffer(2, { maxByteLength: 6 });
var growing = new Uint8Array(grower);
for (var value of growing) { seen.push(value); if (grower.byteLength < 6) grower.resize(grower.byteLength + 2); }
console.log(seen.length, growing.length);
var shrinker = new ArrayBuffer(4, { maxByteLength: 8 });
var shrinkingFixed = new Uint8Array(shrinker, 0, 4);
var it = shrinkingFixed.values();
it.next();
shrinker.resize(2);
console.log(attempt(() => it.next().value));
var gsab = new SharedArrayBuffer(4, { maxByteLength: 8 });
var gview = new Int8Array(gsab);
console.log(gsab.growable, gsab.maxByteLength, new SharedArrayBuffer(4).growable, attempt(() => gsab.grow(2)), attempt(() => gsab.grow(9)), gsab.grow(6), gsab.byteLength, gview.length, attempt(() => new SharedArrayBuffer(4).grow(4)));
var source = new ArrayBuffer(4, { maxByteLength: 8 });
new Uint8Array(source).set([1, 2, 3, 4]);
var sourceView = new Uint8Array(source);
var moved = source.transfer(6);
console.log(source.detached, source.byteLength, source.maxByteLength, moved.byteLength, moved.resizable, moved.maxByteLength, Array.from(new Uint8Array(moved)).join(), sourceView.length, sourceView.byteOffset);
console.log(attempt(() => source.slice()), attempt(() => source.resize(2)), attempt(() => source.transfer()), attempt(() => new Uint8Array(source)), attempt(() => sourceView.at(0)), attempt(() => new DataView(source)));
var fixedSource = new ArrayBuffer(3);
var fixedSourceView = new Uint8Array(fixedSource);
var shrunk = fixedSource.transferToFixedLength(2);
console.log(fixedSource.detached, shrunk.resizable, shrunk.byteLength, fixedSourceView.length, moved.transferToFixedLength().resizable, new ArrayBuffer(2, { maxByteLength: 4 }).transfer().resizable);
console.log(ArrayBuffer.prototype.resize.length, ArrayBuffer.prototype.transfer.length, ArrayBuffer.prototype.transferToFixedLength.length, ArrayBuffer.prototype.resize.name, Object.getOwnPropertyNames(ArrayBuffer.prototype).sort().join());"#;
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
            r#"true 16 8 false 4 false false"#,
            r#"RangeError RangeError SyntaxError TypeError"#,
            r#"4 4 8 2 2 9"#,
            r#"RangeError RangeError undefined 12 6 12 4 12 2"#,
            r#"2 0 0 0 undefined TypeError TypeError TypeError 4 TypeError TypeError"#,
            r#"0 false  258 0"#,
            r#"5 4 2 0,0,0,0 2 4 2,1,0,0,0,0,0,0,0,0"#,
            r#"7 2 2 8"#,
            r#"6 6"#,
            r#"TypeError"#,
            r#"true 8 false RangeError RangeError undefined 6 6 TypeError"#,
            r#"true 0 0 6 true 8 1,2,3,4,0,0 0 0"#,
            r#"TypeError TypeError TypeError TypeError TypeError TypeError"#,
            r#"true false 2 0 false true"#,
            r#"1 0 0 resize byteLength,constructor,detached,maxByteLength,resizable,resize,slice,transfer,transferToFixedLength"#,
        ]
    );
}
