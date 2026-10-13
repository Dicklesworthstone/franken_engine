//! Exercise the shipped pure-module rewrite, not a stand-alone codec model.
//! The companion Node differential test runs the same JavaScript source and
//! fixture, but does not substitute for these native-engine execution tests.

use frankenengine_engine::HybridRouter;

#[test]
fn buffer_transcode_preserves_unicode_errors_and_view_boundaries() {
    let outcome = HybridRouter::default()
        .eval(include_str!("fixtures/buffer_transcode/conversions.js"))
        .unwrap_or_else(|error| panic!("buffer transcoding failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(lines, ["buffer transcode: 42 checks"]);
}
