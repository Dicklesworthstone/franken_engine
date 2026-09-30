//! bd-9vouw.97 (part): ArrayBuffer.isView was missing, so rfdc and dequal,
//! which test for binary views before cloning or comparing, failed with
//! "expected function, got undefined". Expected strings are Node v22.2.0's.
//!
//! No-claim: ArrayBuffer.prototype.slice is still missing (bd-9vouw.97).
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
