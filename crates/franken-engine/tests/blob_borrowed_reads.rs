//! Exercise Blob's native methods through normal lowering, dispatch and the
//! promise job queue. Running the JS fixture in Node supplies reference
//! behavior, but does not replace this native-engine execution test.

use frankenengine_engine::HybridRouter;

#[test]
fn blob_borrowed_reads_preserve_byte_text_and_callback_semantics() {
    let outcome = HybridRouter::default()
        .eval(include_str!("fixtures/blob_borrowed_reads/reads.js"))
        .unwrap_or_else(|error| panic!("Blob evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(lines, ["blob borrowed reads: 40 checks"]);
}
