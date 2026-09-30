//! bd-9vouw.97: ArrayBuffer.isView and ArrayBuffer.prototype.slice were
//! missing, so rfdc and dequal, which test for binary views before cloning
//! or comparing, and `buffer.slice(n)` failed with "expected function, got
//! undefined". Expected strings are Node v22.2.0's.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn check(source: &str, node: &str) {
    let value = match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    };
    assert_eq!(value, node, "`{source}` must match Node v22.2.0");
}

#[test]
fn is_view_recognizes_typed_arrays_and_data_views() {
    check(
        "[ArrayBuffer.isView(new Uint8Array(2)), ArrayBuffer.isView(new DataView(new ArrayBuffer(2))), \
         ArrayBuffer.isView(new ArrayBuffer(2)), ArrayBuffer.isView([]), ArrayBuffer.isView()].join(' ')",
        "true true false false false",
    );
    check(
        "const isView = ArrayBuffer.isView; [typeof isView, isView.length, isView(new Float64Array(1))].join(' ')",
        "function 1 true",
    );
}

#[test]
fn slice_copies_a_clamped_range_of_bytes() {
    check("var b = new ArrayBuffer(4); b.slice(1).byteLength", "3");
    check(
        "var b = new ArrayBuffer(8); [b.slice(2, 5).byteLength, b.slice(-3).byteLength, \
         b.slice(-3, -1).byteLength, b.slice(5, 2).byteLength, b.slice().byteLength, \
         b.slice(20).byteLength, b.slice(-20, 3).byteLength].join()",
        "3,3,2,0,8,0,3",
    );
    check(
        "var b = new ArrayBuffer(6); new Uint8Array(b).set([5, 6, 7, 8, 9, 10]); \
         Array.from(new Uint8Array(b.slice(1.7, '4'))).join()",
        "6,7,8",
    );
}

#[test]
fn slice_is_an_independent_copy() {
    check(
        "var b = new ArrayBuffer(4); var u = new Uint8Array(b); u.set([1, 2, 3, 4]); \
         var s = b.slice(1, 3); var v = new Uint8Array(s); v[0] = 9; \
         [Array.from(v).join('-'), Array.from(u).join('-'), s instanceof ArrayBuffer, s !== b].join()",
        "9-3,1-2-3-4,true,true",
    );
}

/// Every ArrayBuffer (constructed, a typed array's `.buffer`, a slice)
/// inherits from ArrayBuffer.prototype; none did, so `instanceof
/// ArrayBuffer` was false and `constructor` was Object.
#[test]
fn array_buffers_inherit_from_array_buffer_prototype() {
    check(
        "var b = new ArrayBuffer(4); var u = new Uint8Array(4); [b instanceof ArrayBuffer, \
         Object.getPrototypeOf(b) === ArrayBuffer.prototype, u.buffer instanceof ArrayBuffer, \
         b.slice(1) instanceof ArrayBuffer, b.constructor === ArrayBuffer, \
         b.slice(1).constructor === ArrayBuffer].join()",
        "true,true,true,true,true,true",
    );
}

#[test]
fn slice_is_the_prototype_method_and_checks_its_receiver() {
    check(
        "var b = new ArrayBuffer(4); [typeof b.slice, b.slice.length, b.slice.name, \
         ArrayBuffer.prototype.slice === b.slice].join()",
        "function,2,slice,true",
    );
    check(
        "var r; try { ArrayBuffer.prototype.slice.call(new Uint8Array(2)); r = 'no'; } \
         catch (e) { r = e.constructor.name; } r",
        "TypeError",
    );
}
