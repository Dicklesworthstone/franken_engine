//! bd-9vouw.5: standing differential probe corpus vs Node on the default
//! `frankenctl run` path.
//!
//! Why this exists: an IFC over-taint regression made `console.log(Math.max(1, 2))`
//! unrunnable for about four weeks while every engine test stayed green, and
//! the only end-to-end smoke ran `const answer = 40 + 2;`. This test runs 50
//! small ES2015-2020 programs through the real CLI and compares their console
//! output byte-for-byte with Node v22.2.0 (recorded in
//! `fixtures/js_probe_corpus_v1.json`).
//!
//! The ledger below is a two-way ratchet:
//! - `Pass` cases must match Node exactly;
//! - `KnownFailure` cases must still fail and name the bead that owns the fix.
//!   When a fix lands the case starts passing, and this test fails until the
//!   case is moved to `Pass` — so the ledger cannot silently go stale;
//! - `DeniedByDesign` cases must be refused by the ambient-authority membrane;
//! - `OutOfScope` cases exercise syntax beyond the ES2020 target and must still
//!   fail; if one starts passing it moves to `Pass`.
//!
//! Retire this test once the BRIDGE-12 Test262 harness runs on every push and
//! covers these constructs.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Pass,
    /// Names the bead that owns the fix.
    KnownFailure(&'static str),
    DeniedByDesign,
    /// Names the construct and why it is outside the ES2020 target.
    OutOfScope(&'static str),
}

// Owning beads for the known failures (BRIDGE semantic leaves, plus the two
// focused bugs filed from this corpus's first real run on 2026-09-23).
const SLOPPY_MODE: &str = "bd-performance-conformance-bridge-tu32j.15.6";
const DESCRIPTORS: &str = "bd-performance-conformance-bridge-tu32j.14.4";
const DATE_JSON: &str = "bd-performance-conformance-bridge-tu32j.16.5";
const COLLECTIONS: &str = "bd-performance-conformance-bridge-tu32j.16.6";
const TYPED_ARRAYS: &str = "bd-performance-conformance-bridge-tu32j.16.7";
const ERRORS_AND_URI: &str = "bd-performance-conformance-bridge-tu32j.16.11";
const SYMBOLS: &str = "bd-performance-conformance-bridge-tu32j.16.17";
const BIGINT: &str = "bd-performance-conformance-bridge-tu32j.16.19";
const REGEXP_GRAMMAR: &str = "bd-performance-conformance-bridge-tu32j.17.1";
const REGEXP_STRING_METHODS: &str = "bd-performance-conformance-bridge-tu32j.17.3";
/// `for await` lowers to synchronous for-of (no `@@asyncIterator` dispatch).
const ASYNC_ITERATION: &str = "bd-performance-conformance-bridge-tu32j.18.9";

/// Case id -> expectation. Every corpus case must appear exactly once.
/// Filled from the observed verdicts of the first run (2026-09-23): 20 match
/// Node, 4 are refused by design, 26 fail. 29_promise_all_race moved to Pass
/// with bd-auy04 (`new Promise`); on 2026-09-24 06, 15, 37, 40, 42 and 47
/// started matching Node (standard globals and Map/Set iteration, bd-9vouw.17;
/// number formatting, bd-9vouw.2; large integer literals, bd-6vl81), 02 with
/// `super` in classes (bd-9vouw.24), 05 once `await` stopped suspending its
/// caller (bd-9vouw.26), and 23 and 43 with Number.prototype.toPrecision and
/// the arguments object (f2870e990, bd-9vouw.25).
const LEDGER: &[(&str, Expect)] = &[
    ("01_closure", Expect::Pass),
    ("02_class_super", Expect::Pass),
    ("03_destructure_spread", Expect::Pass),
    ("04_generators", Expect::Pass),
    ("05_async_order", Expect::Pass),
    ("06_map_set", Expect::Pass),
    ("07_json", Expect::KnownFailure(DATE_JSON)),
    (
        "08_regexp_named_lookbehind",
        Expect::KnownFailure(REGEXP_GRAMMAR),
    ),
    (
        "09_regexp_replace",
        Expect::KnownFailure(REGEXP_STRING_METHODS),
    ),
    ("10_proxy_reflect", Expect::Pass),
    ("11_symbol_iter", Expect::Pass),
    ("12_typed_arrays", Expect::KnownFailure(TYPED_ARRAYS)),
    ("13_bigint", Expect::KnownFailure(BIGINT)),
    ("14_labels_switch", Expect::Pass),
    ("15_try_finally", Expect::Pass),
    ("16_defineProperty", Expect::KnownFailure(DESCRIPTORS)),
    ("17_array_methods", Expect::Pass),
    ("18_string_methods", Expect::Pass),
    ("19_optional_nullish", Expect::Pass),
    ("20_tagged_template", Expect::Pass),
    ("21_sloppy_with_args", Expect::KnownFailure(SLOPPY_MODE)),
    ("22_eval_function", Expect::DeniedByDesign),
    ("23_number_format", Expect::Pass),
    ("24_date", Expect::KnownFailure(DATE_JSON)),
    ("25_getter_setter_proto", Expect::Pass),
    ("26_error_types", Expect::DeniedByDesign),
    ("27_weakmap_holes", Expect::KnownFailure(COLLECTIONS)),
    ("28_sort_stability", Expect::Pass),
    ("29_promise_all_race", Expect::Pass),
    ("30_async_iter", Expect::KnownFailure(ASYNC_ITERATION)),
    ("31_object_entries_order", Expect::Pass),
    ("32_instanceof_hasinstance", Expect::KnownFailure(SYMBOLS)),
    (
        "33_class_private_post2020",
        Expect::OutOfScope("ES2022 class private fields; the target is ES2020"),
    ),
    ("34_string_unicode", Expect::KnownFailure(ERRORS_AND_URI)),
    ("35_math", Expect::Pass),
    ("36_closures_in_loops", Expect::Pass),
    ("37_function_props", Expect::Pass),
    ("38_json_reviver", Expect::Pass),
    ("39_destructure_default", Expect::Pass),
    ("40_exceptions_across_calls", Expect::Pass),
    ("41_int_overflow", Expect::Pass),
    ("42_int_overflow_loop", Expect::Pass),
    ("43_arguments_object", Expect::Pass),
    (
        "44_regexp_backref_lookahead",
        Expect::KnownFailure(REGEXP_GRAMMAR),
    ),
    ("45_date_methods", Expect::KnownFailure(DATE_JSON)),
    ("46_catch_message", Expect::Pass),
    ("47_number_to_string", Expect::Pass),
    ("48_ambient_process", Expect::DeniedByDesign),
    ("49_ambient_require_fs", Expect::DeniedByDesign),
    ("50_getter_label_join", Expect::Pass),
];

#[derive(Debug)]
enum Observed {
    Output(String),
    Failed(String),
}

fn corpus() -> Vec<(String, String, String)> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/js_probe_corpus_v1.json");
    let doc: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read corpus")).expect("corpus json");
    assert_eq!(doc["oracle"]["version"].as_str(), Some("v22.2.0"));
    doc["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| {
            (
                case["id"].as_str().expect("id").to_string(),
                case["source"].as_str().expect("source").to_string(),
                case["node_output"]
                    .as_str()
                    .expect("node_output")
                    .to_string(),
            )
        })
        .collect()
}

fn run_case(dir: &PathBuf, id: &str, source: &str) -> Observed {
    let input = dir.join(format!("{id}.js"));
    let report = dir.join(format!("{id}.run.json"));
    fs::write(&input, source).expect("write case");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("utf8"),
            "--extension-id",
            "probe-corpus",
            "--instruction-budget",
            "10000000",
            "--out",
            report.to_str().expect("utf8"),
        ])
        .output()
        .expect("frankenctl should execute");
    if !output.status.success() {
        return Observed::Failed(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report).expect("read report")).expect("report json");
    let text = report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .map(|entry| entry["message"].as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>()
        .join("\n");
    Observed::Output(text)
}

#[test]
fn js_probe_corpus_matches_node_ledger_bd_9vouw_5() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("fe_probe_corpus_{}_{nonce}", std::process::id()));
    fs::create_dir_all(&dir).expect("temp dir");

    let ledger: BTreeMap<&str, Expect> = LEDGER.iter().copied().collect();
    assert_eq!(ledger.len(), LEDGER.len(), "duplicate ledger entries");

    let mut problems = Vec::new();
    let mut table = Vec::new();
    let cases = corpus();
    for (id, source, node_output) in &cases {
        let observed = run_case(&dir, id, source);
        let matches = matches!(&observed, Observed::Output(text) if text == node_output);
        let denied = matches!(&observed, Observed::Failed(stderr) if stderr.contains("ambient authority violation"));
        let verdict = if matches {
            "PASS"
        } else if denied {
            "DENIED"
        } else {
            "FAIL"
        };
        let detail = match &observed {
            Observed::Output(text) => format!("output={text:?}"),
            Observed::Failed(stderr) => {
                let line = stderr
                    .lines()
                    .find(|line| line.contains("failed for"))
                    .unwrap_or(stderr);
                format!("error={}", line.chars().take(200).collect::<String>())
            }
        };
        table.push(format!("{verdict:6} {id:32} node={node_output:?} {detail}"));
        match ledger.get(id.as_str()) {
            None => problems.push(format!("{id}: missing from LEDGER (observed {verdict})")),
            Some(Expect::Pass) if !matches => {
                problems.push(format!(
                    "{id}: expected Node output {node_output:?}, {detail}"
                ));
            }
            Some(Expect::KnownFailure(bead)) if matches => problems.push(format!(
                "{id}: now matches Node — move it to Pass (fixed under {bead})"
            )),
            Some(Expect::KnownFailure(_)) if denied => problems.push(format!(
                "{id}: listed as KnownFailure but refused by the ambient-authority membrane"
            )),
            Some(Expect::OutOfScope(reason)) if matches => problems.push(format!(
                "{id}: now matches Node — move it to Pass ({reason})"
            )),
            Some(Expect::DeniedByDesign) if !denied => {
                problems.push(format!(
                    "{id}: expected an ambient-authority refusal, {detail}"
                ));
            }
            _ => {}
        }
    }
    for id in ledger.keys() {
        if !cases.iter().any(|(case_id, _, _)| case_id == id) {
            problems.push(format!("{id}: in LEDGER but not in the corpus"));
        }
    }
    let passing = table.iter().filter(|row| row.starts_with("PASS")).count();
    eprintln!(
        "probe corpus: {passing}/{} match Node\n{}",
        cases.len(),
        table.join("\n")
    );
    assert!(
        problems.is_empty(),
        "probe corpus ledger violations:\n{}",
        problems.join("\n")
    );
}
