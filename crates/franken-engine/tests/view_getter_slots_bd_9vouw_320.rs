//! bd-9vouw.320: the %TypedArray%.prototype and DataView.prototype
//! buffer, byteOffset, byteLength and length getters read the view's
//! internal slots. Called on a view whose own properties of those names a
//! program redefined (directly, `.call` or Reflect.apply), they returned
//! the redefinitions. string_decoder relies on these getters so that own
//! properties cannot redirect a decode. Plain property reads still see the
//! own properties, and a length-tracking view over a resized buffer still
//! reads its current length (0 when out of bounds). Node v22.2.0 gives this
//! value; Bun 1.4.2 agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn view_getters_read_internal_slots_not_own_properties() {
    let source = r#"
var out = [];
var u = new Uint8Array(new ArrayBuffer(8), 2, 4);
var realBuffer = u.buffer;
Object.defineProperty(u, 'buffer', { value: 5 });
Object.defineProperty(u, 'byteOffset', { value: 7 });
Object.defineProperty(u, 'byteLength', { value: 9 });
Object.defineProperty(u, 'length', { value: 11 });
var proto = Object.getPrototypeOf(Uint8Array.prototype);
function getter(owner, key) { return Object.getOwnPropertyDescriptor(owner, key).get; }
out.push(getter(proto, 'buffer').call(u) === realBuffer, getter(proto, 'byteOffset').call(u), getter(proto, 'byteLength').call(u), getter(proto, 'length').call(u));
out.push(u.buffer, u.byteOffset, u.byteLength, u.length);
var d = new DataView(new ArrayBuffer(6), 1, 4);
var dBuffer = d.buffer;
Object.defineProperty(d, 'buffer', { value: 1 });
Object.defineProperty(d, 'byteOffset', { value: 2 });
Object.defineProperty(d, 'byteLength', { value: 3 });
out.push(getter(DataView.prototype, 'buffer').call(d) === dBuffer, Reflect.apply(getter(DataView.prototype, 'byteOffset'), d, []), getter(DataView.prototype, 'byteLength').call(d));
var rab = new ArrayBuffer(8, { maxByteLength: 16 });
var tracking = new Uint16Array(rab, 2);
rab.resize(4);
out.push(getter(proto, 'length').call(tracking), getter(proto, 'byteLength').call(tracking), getter(proto, 'byteOffset').call(tracking));
rab.resize(1);
out.push(getter(proto, 'length').call(tracking), getter(proto, 'byteOffset').call(tracking));
out.join(' ');
"#;
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(value, "true 2 4 4 5 7 9 11 true 1 4 1 2 2 0 0");
}
