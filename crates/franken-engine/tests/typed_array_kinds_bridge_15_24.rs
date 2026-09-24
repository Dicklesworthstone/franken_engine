//! BRIDGE-15.24 (slice): all nine non-BigInt ES2020 TypedArray kinds, with
//! their element conversions, and the binary-data constructors as values.
//!
//! Only Uint8/Int32/Uint32 existed; `Float64Array` & co. were "not defined",
//! which failed every Test262 test that includes harness/testTypedArray.js at
//! load (it lists all nine constructors). Expected strings are what Node
//! v22.2.0 prints for the same programs.
//!
//! Elements are read back by index (TypedArray.prototype.join is not
//! implemented yet; see BRIDGE-15.24).
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

#[test]
fn float_arrays_store_numbers() {
    check(
        "const a = new Float64Array(3); a[1] = 1.5; a.length + ':' + a[1] + ':' + a[0];",
        "3:1.5:0",
    );
    // Float32 rounds through single precision.
    check("new Float32Array([1.1])[0];", "1.100000023841858");
}

#[test]
fn integer_arrays_wrap_modulo_their_width() {
    check(
        "const a = new Int8Array([127, 128, -129, 1.9]); [a[0], a[1], a[2], a[3]].join();",
        "127,-128,127,1",
    );
    check(
        "const i = new Int16Array([70000, -32769]); const u = new Uint16Array([-1, 65536]); \
         [i[0], i[1]].join() + '|' + [u[0], u[1]].join();",
        "4464,32767|65535,0",
    );
}

#[test]
fn uint8_clamped_rounds_half_to_even_and_clamps() {
    check(
        "const c = new Uint8ClampedArray([-5, 300, 1.5, 2.5, 254.5]); [c[0], c[1], c[2], c[3], c[4]].join();",
        "0,255,2,2,254",
    );
}

#[test]
fn binary_constructors_are_values() {
    check(
        "[typeof Float64Array, typeof Uint8ClampedArray, typeof ArrayBuffer, typeof DataView].join();",
        "function,function,function,function",
    );
    check("const C = Uint8Array; new C([1, 2, 300])[2];", "44");
    // The shape of harness/testTypedArray.js: constructors held in an array.
    check(
        "const cs = [Float64Array, Float32Array, Int32Array, Int16Array, Int8Array, \
         Uint32Array, Uint16Array, Uint8Array, Uint8ClampedArray]; \
         cs.map(C => new C(2).length).join();",
        "2,2,2,2,2,2,2,2,2",
    );
    check(
        "Float64Array.name + ':' + Float64Array.length + ':' + Int8Array.BYTES_PER_ELEMENT;",
        "Float64Array:3:1",
    );
}
