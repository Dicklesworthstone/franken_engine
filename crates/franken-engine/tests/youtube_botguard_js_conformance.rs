#![forbid(unsafe_code)]

mod _support;

use _support::js_conformance::{
    JS_CONFORMANCE_RUNNER_ID, JS_CONFORMANCE_RUNNER_SCHEMA, JsConformanceReport,
    JsConformanceVector, assert_js_conformance_vectors, run_js_conformance_vectors,
};
use frankenengine_engine::HybridRouter;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Instant,
};

const YOUTUBE_SIGNATURE_CIPHER_FIXTURE: &str = r#"
var Mt = {
  rv: function(a){ a.reverse(); },
  sp: function(a,b){ a.splice(0,b); },
  sw: function(a,b){ var c=a[0]; a[0]=a[b%a.length]; a[b%a.length]=c; }
};
function decipherSig(a){
  a = a.split("");
  Mt.sw(a,3); Mt.rv(a,0); Mt.sp(a,2); Mt.sw(a,1); Mt.rv(a,0);
  return a.join("");
}
decipherSig("0123456789")
"#;

const REAL_YOUTUBE_FIXTURE_ENV: &str = "FRANKEN_ENGINE_YOUTUBE_FIXTURES";
const REAL_YOUTUBE_FIXTURE_SCHEMA: &str = "franken-engine.youtube-real-js-fixture.v1";
const REAL_YOUTUBE_FIXTURE_CONTRACT: &str = r#"
Offline real YouTube fixture contract for bd-8enww.1.3.

Purpose:
- franken_whisper owns extracting real YouTube base.js functions and expected
  outputs from its downloader/extractor context.
- franken_engine owns replaying those frozen functions through HybridRouter::eval
  without fetching YouTube, invoking Node, or depending on franken_whisper internals.

How to run:
- Set FRANKEN_ENGINE_YOUTUBE_FIXTURES to either one JSON file or a directory of
  .json files.
- Each file may contain one fixture object or an array of fixture objects.
- Run: cargo test -p frankenengine-engine --test youtube_botguard_js_conformance -- --nocapture

Required fixture fields:
{
  "schema_version": "franken-engine.youtube-real-js-fixture.v1",
  "fixture_id": "yt-2026-06-08-player-abc123-sig-001",
  "fixture_kind": "signature_cipher", // or "n_param"
  "source_url": "https://www.youtube.com/s/player/.../base.js",
  "source_observed_utc": "2026-06-08T00:00:00Z",
  "source_sha256": "sha256:<sha256 of the full fetched base.js body>",
  "extracted_js_sha256": "sha256:<sha256 of extracted_js below>",
  "entrypoint": "decipherSig",
  "extracted_js": "function decipherSig(a){ ... }",
  "encrypted_input": "the encrypted s or n input",
  "expected_output": "the extractor-verified output",
  "notes": "optional context for humans"
}

Rules:
- fixture_kind=signature_cipher covers the real base.js signature `s` transform.
- fixture_kind=n_param covers the real base.js `n` throttling transform.
- entrypoint is intentionally restricted to a plain JavaScript identifier in v1.
- extracted_js must define that entrypoint; the test evaluates
  `<extracted_js>; <entrypoint>(<encrypted_input as a JSON string>)`.
- source_url/source_observed_utc/source_sha256 preserve provenance, but tests do
  not fetch the URL or verify network state.
- extracted_js_sha256 is verified locally so accidental fixture drift fails fast.
- Missing fixtures are a structured skip, not a silent pass; supplied fixtures
  must pass or the test fails with a JSON report.
"#;

#[derive(Debug, Clone, Copy)]
struct BotGuardSpikeProbe {
    id: &'static str,
    category: &'static str,
    source: &'static str,
    expected_result: &'static str,
    expectation_basis: &'static str,
    severity_if_gap: &'static str,
    follow_up_bead: &'static str,
    rationale: &'static str,
}

#[derive(Debug, Serialize)]
struct BotGuardSpikeReport {
    schema_version: &'static str,
    source_gap_report: &'static str,
    total_probes: usize,
    confirmed_gap_count: usize,
    sufficient_count: usize,
    observations: Vec<BotGuardSpikeObservation>,
}

#[derive(Debug, Serialize)]
struct BotGuardSpikeObservation {
    probe_id: String,
    category: String,
    minimal_js: String,
    expectation_basis: String,
    expected_result: String,
    observed_kind: String,
    observed_result: String,
    status: String,
    blocking_severity: String,
    follow_up_bead: String,
    rationale: String,
    source_hash: String,
    duration_ns: u64,
    error_code: Option<String>,
    error_message: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealYoutubeFixture {
    schema_version: String,
    fixture_id: String,
    fixture_kind: RealYoutubeFixtureKind,
    source_url: String,
    source_observed_utc: String,
    source_sha256: String,
    extracted_js_sha256: String,
    entrypoint: String,
    extracted_js: String,
    encrypted_input: String,
    expected_output: String,
    notes: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RealYoutubeFixtureKind {
    SignatureCipher,
    NParam,
}

impl RealYoutubeFixtureKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::SignatureCipher => "signature_cipher",
            Self::NParam => "n_param",
        }
    }
}

#[derive(Debug, Serialize)]
struct RealYoutubeFixtureSkipReport {
    schema_version: &'static str,
    status: &'static str,
    env_var: &'static str,
    missing_fixture_kinds: [&'static str; 2],
    contract: &'static str,
}

#[derive(Debug, Serialize)]
struct RealYoutubeFixtureRunReport {
    schema_version: &'static str,
    status: &'static str,
    env_var: &'static str,
    fixture_root: String,
    total_fixtures: usize,
    passed: usize,
    failed: usize,
    signature_cipher_count: usize,
    n_param_count: usize,
    missing_fixture_kinds: Vec<&'static str>,
    logs: Vec<RealYoutubeFixtureRunLog>,
}

#[derive(Debug, Serialize)]
struct RealYoutubeFixtureRunLog {
    fixture_id: String,
    fixture_kind: &'static str,
    fixture_path: String,
    source_url: String,
    source_observed_utc: String,
    source_sha256: String,
    extracted_js_sha256: String,
    computed_extracted_js_sha256: String,
    entrypoint: String,
    encrypted_input_sha256: String,
    expected_output: String,
    observed_kind: String,
    observed_output: String,
    passed: bool,
    duration_ns: u64,
    engine: Option<String>,
    route_reason: Option<String>,
    error_code: Option<String>,
    error_message: Option<String>,
    notes: Option<String>,
}

fn ytbg_memory_value(
    id: &'static str,
    category: &'static str,
    source: &'static str,
    value: &'static str,
    memory_size_bytes: u64,
) -> JsConformanceVector {
    JsConformanceVector::value(id, category, source, value)
        .with_resource(Some(memory_size_bytes), "within_budget")
}

fn ytbg_memory_error(
    id: &'static str,
    category: &'static str,
    source: &'static str,
    namespace: &'static str,
    message_contains: Option<&'static str>,
    memory_size_bytes: u64,
    budget_outcome: &'static str,
) -> JsConformanceVector {
    JsConformanceVector::engine_error(id, category, source, namespace, message_contains)
        .with_resource(Some(memory_size_bytes), budget_outcome)
}

fn assert_resource_logging(report: &JsConformanceReport, category: &str) {
    assert!(
        report.logs.iter().all(|log| log.category == category),
        "all vectors should be categorized for YTBG reporting"
    );
    assert!(
        report
            .logs
            .iter()
            .all(|log| log.memory_size_bytes.is_some()),
        "typed-array vectors must log memory size"
    );
    assert!(
        report
            .logs
            .iter()
            .all(|log| log.budget_outcome != "not_applicable"),
        "typed-array vectors must log budget outcome"
    );
}

#[test]
fn youtube_signature_cipher_acceptance_gate() {
    let vectors = [JsConformanceVector::value(
        "youtube-signature-cipher-decipherSig",
        "youtube_signature_cipher",
        YOUTUBE_SIGNATURE_CIPHER_FIXTURE,
        "31204576",
    )];

    let report = assert_js_conformance_vectors(&vectors);
    let log = report
        .logs
        .first()
        .expect("cipher acceptance gate must emit one structured log");

    assert_eq!(report.total_vectors, 1);
    assert_eq!(report.passed, 1);
    assert_eq!(report.failed, 0);
    assert_eq!(log.vector_id, "youtube-signature-cipher-decipherSig");
    assert_eq!(log.category, "youtube_signature_cipher");
    assert_eq!(log.expected_result, "31204576");
    assert_eq!(log.actual_result, "31204576");
    assert!(log.source_hash.starts_with("sha256:"));
}

#[test]
fn confirmed_working_youtube_js_vector_table() {
    let vectors = [
        JsConformanceVector::value(
            "yt-report-array-reverse-join",
            "confirmed_working_youtube_js",
            r#"var a=["1","2","3"]; a.reverse(); a.join("")"#,
            "321",
        ),
        JsConformanceVector::value(
            "yt-report-array-splice-join",
            "confirmed_working_youtube_js",
            r#"var a=["1","2","3","4"]; a.splice(0,2); a.join("")"#,
            "34",
        ),
        JsConformanceVector::value(
            "yt-report-array-slice-join",
            "confirmed_working_youtube_js",
            r#"var a=["1","2","3"]; a.slice(1).join("")"#,
            "23",
        ),
        JsConformanceVector::value(
            "yt-report-string-split-join",
            "confirmed_working_youtube_js",
            r#"var s="abc"; s.split("").join("-")"#,
            "a-b-c",
        ),
        JsConformanceVector::value(
            "yt-report-string-from-char-code",
            "confirmed_working_youtube_js",
            "String.fromCharCode(66)",
            "B",
        ),
        JsConformanceVector::value(
            "yt-report-string-char-code-at",
            "confirmed_working_youtube_js",
            r#"var x="A"; x.charCodeAt(0)"#,
            "65",
        ),
        JsConformanceVector::value(
            "yt-report-for-loop-accumulation",
            "confirmed_working_youtube_js",
            "var s=0; for(var i=0;i<5;i++){s+=i;} s",
            "10",
        ),
        JsConformanceVector::value(
            "yt-report-regexp-test",
            "confirmed_working_youtube_js",
            r#"/ab+c/.test("xabbbcx")"#,
            "true",
        ),
        JsConformanceVector::value(
            "yt-report-regexp-replace-global",
            "confirmed_working_youtube_js",
            r#""a1b2c3".replace(/[0-9]/g,"_")"#,
            "a_b_c_",
        ),
        JsConformanceVector::value(
            "yt-report-array-map-function-join",
            "confirmed_working_youtube_js",
            r#"[1,2,3].map(function(x){return x*x;}).join(",")"#,
            "1,4,9",
        ),
        JsConformanceVector::value(
            "yt-report-json-parse-stringify",
            "confirmed_working_youtube_js",
            r#"JSON.stringify(JSON.parse('{"a":1,"b":[2,3]}'))"#,
            r#"{"a":1,"b":[2,3]}"#,
        ),
        JsConformanceVector::value(
            "yt-report-bitwise-unsigned-shift",
            "confirmed_working_youtube_js",
            "(0xFFFFFFFF & 0x0F) >>> 0",
            "15",
        ),
        JsConformanceVector::value(
            "yt-report-math-imul-floor",
            "confirmed_working_youtube_js",
            "Math.floor(Math.imul(7,7)/2)",
            "24",
        ),
    ];

    let report = assert_js_conformance_vectors(&vectors);

    assert_eq!(report.total_vectors, vectors.len() as u32);
    assert_eq!(report.passed, vectors.len() as u32);
    assert_eq!(report.failed, 0);
    assert!(
        report
            .logs
            .iter()
            .all(|log| log.category == "confirmed_working_youtube_js")
    );
    assert!(
        report
            .logs
            .iter()
            .any(|log| log.vector_id == "yt-report-json-parse-stringify")
    );
}

#[test]
fn arraybuffer_backing_store_conformance_vectors() {
    let vectors = [
        ytbg_memory_value(
            "ytbg-arraybuffer-byte-length-three",
            "arraybuffer",
            "var b = new ArrayBuffer(3); b.byteLength",
            "3",
            3,
        ),
        ytbg_memory_value(
            "ytbg-arraybuffer-byte-length-default-zero",
            "arraybuffer",
            "var b = new ArrayBuffer(); b.byteLength",
            "0",
            0,
        ),
        ytbg_memory_error(
            "ytbg-arraybuffer-negative-length-range-error",
            "arraybuffer",
            "new ArrayBuffer(-1)",
            "eval.runtime.fault",
            Some("invalid ArrayBuffer byteLength"),
            0,
            "range_rejected",
        ),
        ytbg_memory_error(
            "ytbg-arraybuffer-oversized-length-range-error",
            "arraybuffer",
            "new ArrayBuffer(8388609)",
            "eval.runtime.fault",
            Some("per-buffer cap"),
            8_388_609,
            "budget_rejected",
        ),
    ];

    let report = assert_js_conformance_vectors(&vectors);
    println!(
        "YTBG_ARRAYBUFFER_CONFORMANCE_REPORT_JSON={}",
        serde_json::to_string_pretty(&report).expect("ArrayBuffer report must serialize")
    );

    assert_eq!(report.total_vectors, vectors.len() as u32);
    assert_eq!(report.passed, vectors.len() as u32);
    assert_eq!(report.failed, 0);
    assert_resource_logging(&report, "arraybuffer");
    assert!(
        report
            .logs
            .iter()
            .filter(|log| log.actual_kind == "engine_error")
            .all(
                |log| log.error_code.as_deref() == Some("eval.runtime.fault")
                    && log.error_message.as_deref().is_some_and(|message| {
                        message.contains("ArrayBuffer") && message.contains("byteLength")
                    }),
            ),
        "ArrayBuffer rejection vectors must emit deterministic structured runtime errors"
    );
}

#[test]
fn typed_array_constructor_view_conformance_vectors() {
    let vectors = [
        ytbg_memory_value(
            "ytbg-typedarray-typeof-uint8array",
            "typedarray",
            "typeof Uint8Array",
            "function",
            0,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-uint8-length",
            "typedarray",
            "var u = new Uint8Array(3); u.length",
            "3",
            3,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-uint8-byte-length",
            "typedarray",
            "var u = new Uint8Array(3); u.byteLength",
            "3",
            3,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-uint8-buffer-byte-length",
            "typedarray",
            "var u = new Uint8Array(3); u.buffer.byteLength",
            "3",
            3,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-int32-arraybuffer-length",
            "typedarray",
            "var b = new ArrayBuffer(8); var i = new Int32Array(b); i.length",
            "2",
            8,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-uint32-window-byte-offset",
            "typedarray",
            "var b = new ArrayBuffer(12); var u = new Uint32Array(b, 4, 2); u.byteOffset",
            "4",
            12,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-uint32-window-length",
            "typedarray",
            "var b = new ArrayBuffer(12); var u = new Uint32Array(b, 4, 2); u.length",
            "2",
            12,
        ),
        ytbg_memory_error(
            "ytbg-typedarray-int32-misaligned-byte-offset",
            "typedarray",
            "new Int32Array(new ArrayBuffer(4), 1)",
            "eval.runtime.fault",
            Some("misaligned"),
            4,
            "range_rejected",
        ),
        ytbg_memory_error(
            "ytbg-typedarray-uint32-implicit-length-alignment",
            "typedarray",
            "new Uint32Array(new ArrayBuffer(5))",
            "eval.runtime.fault",
            Some("not a multiple"),
            5,
            "range_rejected",
        ),
    ];

    let report = assert_js_conformance_vectors(&vectors);
    println!(
        "YTBG_TYPED_ARRAY_CONFORMANCE_REPORT_JSON={}",
        serde_json::to_string_pretty(&report).expect("typed-array report must serialize")
    );

    assert_eq!(report.total_vectors, vectors.len() as u32);
    assert_eq!(report.passed, vectors.len() as u32);
    assert_eq!(report.failed, 0);
    assert_resource_logging(&report, "typedarray");
    assert!(
        report
            .logs
            .iter()
            .filter(|log| log.actual_kind == "engine_error")
            .all(
                |log| log.error_code.as_deref() == Some("eval.runtime.fault")
                    && log.error_message.as_deref().is_some_and(|message| {
                        message.contains("Uint32Array")
                            || message.contains("Int32Array")
                            || message.contains("typed-array")
                    }),
            ),
        "typed-array rejection vectors must emit deterministic structured runtime errors"
    );
}

#[test]
fn typed_array_indexed_storage_conformance_vectors() {
    let vectors = [
        ytbg_memory_value(
            "ytbg-typedarray-g1-indexed-sum",
            "typedarray_indexed_storage",
            "var a = new Uint8Array(3); a[0] = 255; a[1] = 1; a[0] + a[1]",
            "256",
            3,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-uint8-wraps-modulo-256",
            "typedarray_indexed_storage",
            "var a = new Uint8Array(2); a[0] = 256; a[1] = 0 - 1; a[0] + a[1]",
            "255",
            2,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-int32-signed-wrap",
            "typedarray_indexed_storage",
            "var i = new Int32Array(1); i[0] = 2147483648; i[0]",
            "-2147483648",
            4,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-uint32-unsigned-wrap",
            "typedarray_indexed_storage",
            "var u = new Uint32Array(1); u[0] = 0 - 1; u[0]",
            "4294967295",
            4,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-oob-read-after-write-is-undefined",
            "typedarray_indexed_storage",
            "var a = new Uint8Array(1); a[1] = 7; a[1]",
            "undefined",
            1,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-non-index-property-preserved",
            "typedarray_indexed_storage",
            "var a = new Uint8Array(1); a.foo = 9; a.foo",
            "9",
            1,
        ),
    ];

    let report = assert_js_conformance_vectors(&vectors);
    println!(
        "YTBG_TYPED_ARRAY_INDEXED_STORAGE_CONFORMANCE_REPORT_JSON={}",
        serde_json::to_string_pretty(&report)
            .expect("typed-array indexed-storage report must serialize")
    );

    assert_eq!(report.total_vectors, vectors.len() as u32);
    assert_eq!(report.passed, vectors.len() as u32);
    assert_eq!(report.failed, 0);
    assert_resource_logging(&report, "typedarray_indexed_storage");
}

#[test]
fn data_view_integer_accessors_conformance_vectors() {
    let vectors = [
        ytbg_memory_value(
            "ytbg-dataview-typeof",
            "dataview_integer_accessors",
            "typeof DataView",
            "function",
            0,
        ),
        ytbg_memory_value(
            "ytbg-dataview-byte-length",
            "dataview_integer_accessors",
            "var b = new ArrayBuffer(4); var d = new DataView(b); d.byteLength",
            "4",
            4,
        ),
        ytbg_memory_value(
            "ytbg-dataview-window-byte-offset",
            "dataview_integer_accessors",
            "var b = new ArrayBuffer(8); var d = new DataView(b, 2, 4); d.byteOffset",
            "2",
            8,
        ),
        ytbg_memory_value(
            "ytbg-dataview-uint8-round-trip",
            "dataview_integer_accessors",
            "var b = new ArrayBuffer(4); var d = new DataView(b); d.setUint8(0,255); d.getUint8(0)",
            "255",
            4,
        ),
        ytbg_memory_value(
            "ytbg-dataview-uint32-big-endian-first-byte",
            "dataview_integer_accessors",
            "var b = new ArrayBuffer(4); var d = new DataView(b); d.setUint32(0,16909060,false); d.getUint8(0)",
            "1",
            4,
        ),
        ytbg_memory_value(
            "ytbg-dataview-uint32-little-endian-round-trip",
            "dataview_integer_accessors",
            "var b = new ArrayBuffer(4); var d = new DataView(b); d.setUint32(0,16909060,true); d.getUint32(0,true)",
            "16909060",
            4,
        ),
        ytbg_memory_value(
            "ytbg-dataview-int32-signed-wrap",
            "dataview_integer_accessors",
            "var b = new ArrayBuffer(4); var d = new DataView(b); d.setInt32(0,2147483648,false); d.getInt32(0,false)",
            "-2147483648",
            4,
        ),
        ytbg_memory_value(
            "ytbg-dataview-write-visible-to-uint8array",
            "dataview_integer_accessors",
            "var b = new ArrayBuffer(2); var d = new DataView(b); var a = new Uint8Array(b); d.setUint8(0,42); a[0]",
            "42",
            2,
        ),
        ytbg_memory_value(
            "ytbg-dataview-reads-uint8array-write",
            "dataview_integer_accessors",
            "var b = new ArrayBuffer(2); var d = new DataView(b); var a = new Uint8Array(b); a[1] = 7; d.getUint8(1)",
            "7",
            2,
        ),
        ytbg_memory_error(
            "ytbg-dataview-constructor-byte-offset-range-error",
            "dataview_integer_accessors",
            "new DataView(new ArrayBuffer(4), 5)",
            "eval.runtime.fault",
            Some("DataView byteOffset"),
            4,
            "range_rejected",
        ),
        ytbg_memory_error(
            "ytbg-dataview-getuint32-out-of-bounds",
            "dataview_integer_accessors",
            "var b = new ArrayBuffer(4); var d = new DataView(b); d.getUint32(1)",
            "eval.runtime.fault",
            Some("out of bounds"),
            4,
            "range_rejected",
        ),
    ];

    let report = assert_js_conformance_vectors(&vectors);
    println!(
        "YTBG_DATAVIEW_INTEGER_ACCESSORS_CONFORMANCE_REPORT_JSON={}",
        serde_json::to_string_pretty(&report).expect("DataView report must serialize")
    );

    assert_eq!(report.total_vectors, vectors.len() as u32);
    assert_eq!(report.passed, vectors.len() as u32);
    assert_eq!(report.failed, 0);
    assert_resource_logging(&report, "dataview_integer_accessors");
    assert!(
        report
            .logs
            .iter()
            .filter(|log| log.actual_kind == "engine_error")
            .all(
                |log| log.error_code.as_deref() == Some("eval.runtime.fault")
                    && log
                        .error_message
                        .as_deref()
                        .is_some_and(|message| message.contains("DataView"))
            ),
        "DataView rejection vectors must emit deterministic structured runtime errors"
    );
}

#[test]
fn typed_array_method_conformance_vectors() {
    let vectors = [
        ytbg_memory_value(
            "ytbg-typedarray-set-array-source",
            "typedarray_methods",
            "var a = new Uint8Array(4); a.set([1,2],1); a[0] + a[1]*10 + a[2]*100 + a[3]*1000",
            "210",
            4,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-fill-window",
            "typedarray_methods",
            "var a = new Uint8Array(4); a.fill(7,1,3); a[0] + a[1] + a[2] + a[3]",
            "14",
            4,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-copy-within-overlap",
            "typedarray_methods",
            "var a = new Uint8Array(4); a.set([1,2,3,4]); a.copyWithin(2,0,2); a[0]*1000 + a[1]*100 + a[2]*10 + a[3]",
            "1212",
            4,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-subarray-shares-backing",
            "typedarray_methods",
            "var a = new Uint8Array(4); a.set([10,20,30,40]); var s = a.subarray(1,3); s[0] = 99; a[1]",
            "99",
            4,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-slice-copies-backing",
            "typedarray_methods",
            "var a = new Uint8Array(4); a.set([10,20,30,40]); var s = a.slice(1,3); s[0] = 99; a[1]",
            "20",
            4,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-int32-set-wrap",
            "typedarray_methods",
            "var i = new Int32Array(2); i.set([2147483648],1); i[1]",
            "-2147483648",
            8,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-array-from-conversion",
            "typedarray_methods",
            "var a = new Uint8Array(3); a.set([5,6,7]); Array.from(a).join(\",\")",
            "5,6,7",
            3,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-values-iterator",
            "typedarray_methods",
            "var a = new Uint8Array(3); a.set([5,6,7]); var it = a.values(); it.next().value + it.next().value",
            "11",
            3,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-keys-iterator",
            "typedarray_methods",
            "var a = new Uint8Array(3); var it = a.keys(); it.next().value + it.next().value",
            "1",
            3,
        ),
        ytbg_memory_value(
            "ytbg-typedarray-entries-iterator",
            "typedarray_methods",
            "var a = new Uint8Array(1); a[0] = 5; var e = a.entries().next().value; e[0]*10 + e[1]",
            "5",
            1,
        ),
        ytbg_memory_error(
            "ytbg-typedarray-unsupported-method-diagnostic",
            "typedarray_methods",
            "new Uint8Array(1).map(0)",
            "eval.runtime.fault",
            Some("unsupported TypedArray method"),
            1,
            "unsupported_method_rejected",
        ),
    ];

    let report = assert_js_conformance_vectors(&vectors);
    println!(
        "YTBG_TYPED_ARRAY_METHOD_CONFORMANCE_REPORT_JSON={}",
        serde_json::to_string_pretty(&report).expect("typed-array method report must serialize")
    );

    assert_eq!(report.total_vectors, vectors.len() as u32);
    assert_eq!(report.passed, vectors.len() as u32);
    assert_eq!(report.failed, 0);
    assert_resource_logging(&report, "typedarray_methods");
    assert!(
        report
            .logs
            .iter()
            .filter(|log| log.actual_kind == "engine_error")
            .all(
                |log| log.error_code.as_deref() == Some("eval.runtime.fault")
                    && log
                        .error_message
                        .as_deref()
                        .is_some_and(|message| message.contains("TypedArray"))
            ),
        "typed-array unsupported method vectors must emit deterministic structured runtime errors"
    );
}

#[test]
fn likely_botguard_gap_spike_vectors_are_logged_with_current_observations() {
    let probes = [
        BotGuardSpikeProbe {
            id: "ytbg-spike-instruction-budget-loop-50k",
            category: "budget",
            source: "var s=0; for(var i=0;i<50000;i++){s=(s+i)&65535;} s",
            expected_result: "6872",
            expectation_basis: "Node arithmetic ground truth for a 50k-iteration loop; this probes whether public eval can sustain BotGuard-scale loop pressure before a dedicated generated-code budget test exists.",
            severity_if_gap: "confirmed-blocker-for-botguard-scale-runs",
            follow_up_bead: "bd-8enww.5.5",
            rationale: "BotGuard runs are heavier than the signature cipher; a loop budget failure means the implementation needs configurable budgets and execution logs before PO-token replay can be trusted.",
        },
        BotGuardSpikeProbe {
            id: "ytbg-spike-date-now-deterministic-pair",
            category: "date",
            source: "var a=Date.now(); var b=Date.now(); (a == b) + ':' + (a >= 0)",
            expected_result: "true:true",
            expectation_basis: "FrankenEngine deterministic sandbox-time contract: Date.now must be numeric and replay-stable within the same deterministic eval slice.",
            severity_if_gap: "confirmed-blocker-for-deterministic-time-shim",
            follow_up_bead: "bd-8enww.5.3",
            rationale: "BotGuard probes clock surfaces, but FrankenEngine must not delegate wall-clock nondeterminism into replay or IFC-sensitive execution.",
        },
        BotGuardSpikeProbe {
            id: "ytbg-spike-date-epoch-get-time",
            category: "date",
            source: "new Date(0).getTime()",
            expected_result: "0",
            expectation_basis: "ECMAScript Date constructor/getTime ground truth for an explicit epoch timestamp.",
            severity_if_gap: "confirmed-blocker-for-date-constructor-surface",
            follow_up_bead: "bd-8enww.5.3",
            rationale: "Explicit Date construction is a small but load-bearing browser compatibility surface for obfuscated JS probes.",
        },
        BotGuardSpikeProbe {
            id: "ytbg-spike-performance-global-type",
            category: "performance",
            source: "typeof performance",
            expected_result: "object",
            expectation_basis: "Browser and modern Node global-surface ground truth: BotGuard expects a performance object to exist, with deterministic behavior supplied by FrankenEngine.",
            severity_if_gap: "confirmed-blocker-for-performance-shim",
            follow_up_bead: "bd-8enww.5.3",
            rationale: "A missing performance object will break timing probes before deeper BotGuard semantics are reached.",
        },
        BotGuardSpikeProbe {
            id: "ytbg-spike-performance-now-monotonic-type",
            category: "performance",
            source: "var a=performance.now(); var b=performance.now(); typeof a + ':' + (b >= a)",
            expected_result: "number:true",
            expectation_basis: "Browser performance.now contract narrowed for FrankenEngine: numeric monotonic reads, implemented with deterministic sandbox time rather than host wall time.",
            severity_if_gap: "confirmed-blocker-for-performance-now-shim",
            follow_up_bead: "bd-8enww.5.3",
            rationale: "BotGuard anti-tamper code often compares high-resolution timing surfaces; a deterministic shim needs both presence and monotonic numeric reads.",
        },
        BotGuardSpikeProbe {
            id: "ytbg-spike-object-keys-values-order",
            category: "object-statics",
            source: "Object.keys({b:2,a:1}).join(',') + '|' + Object.values({b:2,a:1}).join(',')",
            expected_result: "b,a|2,1",
            expectation_basis: "ECMAScript enumerable own string-key insertion-order behavior for Object.keys/Object.values.",
            severity_if_gap: "confirmed-blocker-for-object-static-enumeration",
            follow_up_bead: "bd-8enww.5.4",
            rationale: "BotGuard VM tables commonly enumerate object records; wrong ordering or missing statics can silently corrupt decoded operations.",
        },
        BotGuardSpikeProbe {
            id: "ytbg-spike-object-define-property-own-names",
            category: "object-statics",
            source: "var o={a:1}; Object.defineProperty(o,'x',{value:2, enumerable:false}); Object.getOwnPropertyNames(o).join(',') + ':' + o.x",
            expected_result: "a,x:2",
            expectation_basis: "ECMAScript descriptor and own-property-name ground truth for a non-enumerable data property.",
            severity_if_gap: "confirmed-blocker-for-object-descriptor-statics",
            follow_up_bead: "bd-8enww.5.4",
            rationale: "Obfuscated JS often hides VM metadata behind descriptors; BotGuard support needs descriptor writes and own-name discovery to agree.",
        },
        BotGuardSpikeProbe {
            id: "ytbg-spike-object-create-assign",
            category: "object-statics",
            source: "var p={inherited:1}; var o=Object.create(p); o.own=2; var t=Object.assign({a:1}, o); Object.keys(t).join(',') + ':' + (t.a + t.own)",
            expected_result: "a,own:3",
            expectation_basis: "ECMAScript Object.create prototype separation plus Object.assign enumerable-own-copy behavior.",
            severity_if_gap: "confirmed-blocker-for-object-create-assign",
            follow_up_bead: "bd-8enww.5.4",
            rationale: "BotGuard-like code relies on prototype separation and enumerable-only copying; failures here should become Object static implementation work.",
        },
    ];

    let vectors: Vec<JsConformanceVector> = probes
        .iter()
        .map(|probe| {
            JsConformanceVector::value(
                probe.id,
                probe.category,
                probe.source,
                probe.expected_result,
            )
        })
        .collect();

    let conformance_report = run_js_conformance_vectors(&vectors);
    let observations: Vec<BotGuardSpikeObservation> = probes
        .iter()
        .zip(conformance_report.logs.iter())
        .map(|(probe, log)| {
            let status = if log.passed {
                "sufficient-for-current-probe"
            } else {
                "confirmed-gap"
            };
            let blocking_severity = if log.passed {
                "not-blocking-current-probe"
            } else {
                probe.severity_if_gap
            };

            BotGuardSpikeObservation {
                probe_id: probe.id.to_owned(),
                category: probe.category.to_owned(),
                minimal_js: probe.source.to_owned(),
                expectation_basis: probe.expectation_basis.to_owned(),
                expected_result: probe.expected_result.to_owned(),
                observed_kind: log.actual_kind.clone(),
                observed_result: log.actual_result.clone(),
                status: status.to_owned(),
                blocking_severity: blocking_severity.to_owned(),
                follow_up_bead: probe.follow_up_bead.to_owned(),
                rationale: probe.rationale.to_owned(),
                source_hash: log.source_hash.clone(),
                duration_ns: log.duration_ns,
                error_code: log.error_code.clone(),
                error_message: log.error_message.clone(),
            }
        })
        .collect();
    let confirmed_gap_count = observations
        .iter()
        .filter(|observation| observation.status == "confirmed-gap")
        .count();
    let spike_report = BotGuardSpikeReport {
        schema_version: "franken-engine.ytbg-likely-gap-spike.v1",
        source_gap_report: "/dp/franken_whisper/docs/FRANKENENGINE_YOUTUBE_CIPHER_JS_GAP_REPORT.md#4",
        total_probes: observations.len(),
        confirmed_gap_count,
        sufficient_count: observations.len().saturating_sub(confirmed_gap_count),
        observations,
    };

    println!(
        "YTBG_BOTGUARD_LIKELY_GAP_SPIKE_REPORT_JSON={}",
        serde_json::to_string_pretty(&spike_report).expect("spike report must serialize")
    );

    assert_eq!(conformance_report.total_vectors, probes.len() as u32);
    assert_eq!(spike_report.total_probes, probes.len());
    assert_eq!(
        spike_report.confirmed_gap_count + spike_report.sufficient_count,
        probes.len()
    );
    assert!(
        spike_report
            .observations
            .iter()
            .all(|observation| observation.source_hash.starts_with("sha256:"))
    );
    assert!(
        spike_report
            .observations
            .iter()
            .any(|observation| observation.category == "budget")
    );
    assert!(
        spike_report
            .observations
            .iter()
            .any(|observation| observation.category == "date")
    );
    assert!(
        spike_report
            .observations
            .iter()
            .any(|observation| observation.category == "performance")
    );
    assert!(
        spike_report
            .observations
            .iter()
            .any(|observation| observation.category == "object-statics")
    );
}

/// bd-8enww.5.3 (YTBG-E3): the deterministic `performance` shim is live through
/// the public `HybridRouter` surface — the path BotGuard / PO-token fixtures use.
/// These are the two `performance` spike vectors that were confirmed gaps in the
/// bd-8enww.5.2 spike (`typeof performance` -> `undefined`, `performance.now()` ->
/// `eval.runtime.fault`); they are pinned here as HARD regressions so a broken or
/// missing `performance` global fails this test rather than silently downgrading
/// to a logged spike observation. The deterministic monotonic read also guards the
/// replay contract (a later read never precedes an earlier one).
#[test]
fn performance_shim_vectors_pass_through_hybrid_router() {
    let vectors = [
        JsConformanceVector::value(
            "ytbg-performance-global-type",
            "performance",
            "typeof performance",
            "object",
        ),
        JsConformanceVector::value(
            "ytbg-performance-now-monotonic-type",
            "performance",
            "var a=performance.now(); var b=performance.now(); typeof a + ':' + (b >= a)",
            "number:true",
        ),
    ];
    let report = assert_js_conformance_vectors(&vectors);
    assert_eq!(report.total_vectors, vectors.len() as u32);
    assert_eq!(report.passed, vectors.len() as u32);
    assert_eq!(report.failed, 0);
}

#[test]
fn real_youtube_fixture_contract_is_self_documenting() {
    assert!(REAL_YOUTUBE_FIXTURE_CONTRACT.contains(REAL_YOUTUBE_FIXTURE_ENV));
    assert!(REAL_YOUTUBE_FIXTURE_CONTRACT.contains(REAL_YOUTUBE_FIXTURE_SCHEMA));
    assert!(REAL_YOUTUBE_FIXTURE_CONTRACT.contains("signature_cipher"));
    assert!(REAL_YOUTUBE_FIXTURE_CONTRACT.contains("n_param"));
    assert!(REAL_YOUTUBE_FIXTURE_CONTRACT.contains("source_sha256"));
    assert!(REAL_YOUTUBE_FIXTURE_CONTRACT.contains("extracted_js_sha256"));
    assert!(REAL_YOUTUBE_FIXTURE_CONTRACT.contains("HybridRouter::eval"));
}

#[test]
fn real_youtube_base_js_and_n_param_fixtures_run_when_supplied() {
    let Some(fixture_root) = env::var_os(REAL_YOUTUBE_FIXTURE_ENV).map(PathBuf::from) else {
        let skip_report = RealYoutubeFixtureSkipReport {
            schema_version: REAL_YOUTUBE_FIXTURE_SCHEMA,
            status: "skipped-no-fixture-env",
            env_var: REAL_YOUTUBE_FIXTURE_ENV,
            missing_fixture_kinds: ["signature_cipher", "n_param"],
            contract: REAL_YOUTUBE_FIXTURE_CONTRACT,
        };
        println!(
            "YOUTUBE_REAL_FIXTURE_SKIP_REPORT_JSON={}",
            serde_json::to_string_pretty(&skip_report).expect("skip report must serialize")
        );
        return;
    };

    let fixtures = load_real_youtube_fixtures(&fixture_root)
        .unwrap_or_else(|err| panic!("failed to load real YouTube fixtures: {err}"));
    assert!(
        !fixtures.is_empty(),
        "{} was set to {} but no JSON fixtures were loaded",
        REAL_YOUTUBE_FIXTURE_ENV,
        fixture_root.display()
    );

    let report = run_real_youtube_fixture_set(&fixture_root, &fixtures);
    println!(
        "YOUTUBE_REAL_FIXTURE_RUN_REPORT_JSON={}",
        serde_json::to_string_pretty(&report).expect("fixture run report must serialize")
    );

    assert_eq!(
        report.failed,
        0,
        "real YouTube fixture failures:\n{}",
        serde_json::to_string_pretty(&report).expect("fixture report must serialize after failure")
    );
}

#[test]
fn runner_handles_values_caught_exceptions_and_engine_errors() {
    let vectors = [
        JsConformanceVector::value("ytbg-runner-expression", "expression", "1 + 2 * 3", "7"),
        JsConformanceVector::value(
            "ytbg-runner-multi-statement",
            "multi_statement",
            "var s = 0; for (var i = 0; i < 5; i++) { s += i; } s;",
            "10",
        ),
        JsConformanceVector::caught_value(
            "ytbg-runner-caught-throw",
            "caught_exception",
            "var r = 0; try { throw 42; } catch (e) { r = e; } r;",
            "42",
        ),
        JsConformanceVector::engine_error(
            "ytbg-runner-engine-error",
            "engine_error",
            " ",
            "eval.parse.empty_source",
            Some("source is empty"),
        ),
    ];

    let report = assert_js_conformance_vectors(&vectors);

    assert_eq!(report.schema_version, JS_CONFORMANCE_RUNNER_SCHEMA);
    assert_eq!(report.runner_id, JS_CONFORMANCE_RUNNER_ID);
    assert_eq!(report.total_vectors, 4);
    assert_eq!(report.passed, 4);
    assert_eq!(report.failed, 0);
    assert_eq!(report.logs.len(), 4);

    for log in &report.logs {
        assert!(!log.vector_id.is_empty());
        assert!(!log.category.is_empty());
        assert!(!log.expected_kind.is_empty());
        assert!(!log.expected_result.is_empty());
        assert!(!log.actual_kind.is_empty());
        assert!(!log.actual_result.is_empty());
        assert!(log.source_hash.starts_with("sha256:"));
        assert_eq!(log.source_hash.len(), "sha256:".len() + 64);
    }
}

#[test]
fn report_round_trips_as_structured_json() {
    let vectors = [JsConformanceVector::value(
        "ytbg-runner-json-roundtrip",
        "expression",
        "6 * 7",
        "42",
    )];

    let report = run_js_conformance_vectors(&vectors);
    report.assert_all_passed();

    let encoded = serde_json::to_string_pretty(&report).expect("report should serialize");
    let decoded: JsConformanceReport =
        serde_json::from_str(&encoded).expect("report should deserialize");

    assert_eq!(decoded, report);
    assert!(encoded.contains("ytbg-runner-json-roundtrip"));
    assert!(encoded.contains("sha256:"));
}

#[test]
fn runner_is_offline_by_default() {
    let report = run_js_conformance_vectors(&[]);

    assert_eq!(report.schema_version, JS_CONFORMANCE_RUNNER_SCHEMA);
    assert_eq!(report.runner_id, JS_CONFORMANCE_RUNNER_ID);
    assert_eq!(report.total_vectors, 0);
    assert_eq!(report.passed, 0);
    assert_eq!(report.failed, 0);
    assert!(report.logs.is_empty());
    assert!(report.runner_id.contains("offline"));
}

fn load_real_youtube_fixtures(
    fixture_root: &Path,
) -> Result<Vec<(PathBuf, RealYoutubeFixture)>, String> {
    if fixture_root.is_file() {
        return load_real_youtube_fixture_file(fixture_root);
    }
    if !fixture_root.is_dir() {
        return Err(format!(
            "{} must point to a JSON file or directory, got {}",
            REAL_YOUTUBE_FIXTURE_ENV,
            fixture_root.display()
        ));
    }

    let mut paths = Vec::new();
    for entry in fs::read_dir(fixture_root)
        .map_err(|err| format!("read_dir {} failed: {err}", fixture_root.display()))?
    {
        let entry = entry.map_err(|err| format!("read_dir entry failed: {err}"))?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            paths.push(path);
        }
    }
    paths.sort();

    let mut fixtures = Vec::new();
    for path in paths {
        fixtures.extend(load_real_youtube_fixture_file(&path)?);
    }
    Ok(fixtures)
}

fn load_real_youtube_fixture_file(
    path: &Path,
) -> Result<Vec<(PathBuf, RealYoutubeFixture)>, String> {
    let content =
        fs::read_to_string(path).map_err(|err| format!("read {} failed: {err}", path.display()))?;
    let trimmed = content.trim_start();
    let fixtures = if trimmed.starts_with('[') {
        serde_json::from_str::<Vec<RealYoutubeFixture>>(&content)
            .map_err(|err| format!("parse {} as fixture array failed: {err}", path.display()))?
    } else {
        vec![
            serde_json::from_str::<RealYoutubeFixture>(&content)
                .map_err(|err| format!("parse {} as fixture failed: {err}", path.display()))?,
        ]
    };

    fixtures
        .into_iter()
        .map(|fixture| {
            validate_real_youtube_fixture(&fixture, path)?;
            Ok((path.to_path_buf(), fixture))
        })
        .collect()
}

fn validate_real_youtube_fixture(fixture: &RealYoutubeFixture, path: &Path) -> Result<(), String> {
    if fixture.schema_version != REAL_YOUTUBE_FIXTURE_SCHEMA {
        return Err(format!(
            "{} has schema_version {:?}, expected {:?}",
            path.display(),
            fixture.schema_version,
            REAL_YOUTUBE_FIXTURE_SCHEMA
        ));
    }
    for (field, value) in [
        ("fixture_id", fixture.fixture_id.as_str()),
        ("source_url", fixture.source_url.as_str()),
        ("source_observed_utc", fixture.source_observed_utc.as_str()),
        ("entrypoint", fixture.entrypoint.as_str()),
        ("extracted_js", fixture.extracted_js.as_str()),
        ("encrypted_input", fixture.encrypted_input.as_str()),
        ("expected_output", fixture.expected_output.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(format!(
                "{} field {field} must not be empty",
                path.display()
            ));
        }
    }
    validate_sha256_field(path, "source_sha256", &fixture.source_sha256)?;
    validate_sha256_field(path, "extracted_js_sha256", &fixture.extracted_js_sha256)?;
    if !is_plain_js_identifier(&fixture.entrypoint) {
        return Err(format!(
            "{} entrypoint {:?} is not a plain JavaScript identifier",
            path.display(),
            fixture.entrypoint
        ));
    }

    let computed_hash = sha256_prefixed(fixture.extracted_js.as_bytes());
    if computed_hash != fixture.extracted_js_sha256 {
        return Err(format!(
            "{} extracted_js_sha256 mismatch for {}: expected field {}, computed {}",
            path.display(),
            fixture.fixture_id,
            fixture.extracted_js_sha256,
            computed_hash
        ));
    }
    Ok(())
}

fn validate_sha256_field(path: &Path, field: &str, value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(format!(
            "{} field {field} must start with sha256:",
            path.display()
        ));
    };
    if hex.len() != 64 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "{} field {field} must contain a 64-hex-character SHA-256 digest",
            path.display()
        ));
    }
    Ok(())
}

fn run_real_youtube_fixture_set(
    fixture_root: &Path,
    fixtures: &[(PathBuf, RealYoutubeFixture)],
) -> RealYoutubeFixtureRunReport {
    let logs: Vec<RealYoutubeFixtureRunLog> = fixtures
        .iter()
        .map(|(path, fixture)| run_real_youtube_fixture(path, fixture))
        .collect();
    let passed = logs.iter().filter(|log| log.passed).count();
    let signature_cipher_count = logs
        .iter()
        .filter(|log| log.fixture_kind == RealYoutubeFixtureKind::SignatureCipher.as_str())
        .count();
    let n_param_count = logs
        .iter()
        .filter(|log| log.fixture_kind == RealYoutubeFixtureKind::NParam.as_str())
        .count();
    let mut missing_fixture_kinds = Vec::new();
    if signature_cipher_count == 0 {
        missing_fixture_kinds.push(RealYoutubeFixtureKind::SignatureCipher.as_str());
    }
    if n_param_count == 0 {
        missing_fixture_kinds.push(RealYoutubeFixtureKind::NParam.as_str());
    }

    RealYoutubeFixtureRunReport {
        schema_version: REAL_YOUTUBE_FIXTURE_SCHEMA,
        status: "executed-supplied-fixtures",
        env_var: REAL_YOUTUBE_FIXTURE_ENV,
        fixture_root: fixture_root.display().to_string(),
        total_fixtures: logs.len(),
        passed,
        failed: logs.len().saturating_sub(passed),
        signature_cipher_count,
        n_param_count,
        missing_fixture_kinds,
        logs,
    }
}

fn run_real_youtube_fixture(path: &Path, fixture: &RealYoutubeFixture) -> RealYoutubeFixtureRunLog {
    let encrypted_input_literal =
        serde_json::to_string(&fixture.encrypted_input).expect("string literal must serialize");
    let eval_source = format!(
        "{}\n{}({})",
        fixture.extracted_js, fixture.entrypoint, encrypted_input_literal
    );
    let started = Instant::now();
    let result = HybridRouter::default().eval(&eval_source);
    let duration_ns = saturating_duration_ns(started.elapsed().as_nanos());
    let computed_extracted_js_sha256 = sha256_prefixed(fixture.extracted_js.as_bytes());
    let encrypted_input_sha256 = sha256_prefixed(fixture.encrypted_input.as_bytes());

    match result {
        Ok(outcome) => {
            let passed = outcome.value == fixture.expected_output;
            RealYoutubeFixtureRunLog {
                fixture_id: fixture.fixture_id.clone(),
                fixture_kind: fixture.fixture_kind.as_str(),
                fixture_path: path.display().to_string(),
                source_url: fixture.source_url.clone(),
                source_observed_utc: fixture.source_observed_utc.clone(),
                source_sha256: fixture.source_sha256.clone(),
                extracted_js_sha256: fixture.extracted_js_sha256.clone(),
                computed_extracted_js_sha256,
                entrypoint: fixture.entrypoint.clone(),
                encrypted_input_sha256,
                expected_output: fixture.expected_output.clone(),
                observed_kind: "value".to_owned(),
                observed_output: outcome.value,
                passed,
                duration_ns,
                engine: Some(outcome.engine.to_string()),
                route_reason: Some(outcome.route_reason.to_string()),
                error_code: None,
                error_message: None,
                notes: fixture.notes.clone(),
            }
        }
        Err(err) => RealYoutubeFixtureRunLog {
            fixture_id: fixture.fixture_id.clone(),
            fixture_kind: fixture.fixture_kind.as_str(),
            fixture_path: path.display().to_string(),
            source_url: fixture.source_url.clone(),
            source_observed_utc: fixture.source_observed_utc.clone(),
            source_sha256: fixture.source_sha256.clone(),
            extracted_js_sha256: fixture.extracted_js_sha256.clone(),
            computed_extracted_js_sha256,
            entrypoint: fixture.entrypoint.clone(),
            encrypted_input_sha256,
            expected_output: fixture.expected_output.clone(),
            observed_kind: "engine_error".to_owned(),
            observed_output: err.stable_namespace().to_owned(),
            passed: false,
            duration_ns,
            engine: None,
            route_reason: None,
            error_code: Some(err.stable_namespace().to_owned()),
            error_message: Some(err.message),
            notes: fixture.notes.clone(),
        },
    }
}

fn is_plain_js_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first == '$' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch == '$' || ch.is_ascii_alphanumeric())
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex::encode(digest))
}

fn saturating_duration_ns(value: u128) -> u64 {
    if value > u128::from(u64::MAX) {
        u64::MAX
    } else {
        value as u64
    }
}
