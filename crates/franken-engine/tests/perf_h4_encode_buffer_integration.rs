#![forbid(unsafe_code)]
//! PERF-H4.7 — buffered-encoding round-trip integration test (bd-o4cbn.5.7).
//!
//! H4 introduced buffer-pool reuse on the canonical encoding path. The risk is
//! that pooled/reused buffers silently change the bytes that flow through
//! `frankenctl compile` (encode) and `frankenctl replay` (decode + re-encode).
//! These two tests guard the end-to-end frankenctl surface:
//!
//! 1. `frankenctl_compile_artifact_unchanged_after_buffer_pool` locks the
//!    deterministic IR content-hashes emitted by `frankenctl compile` against
//!    an insta snapshot. The hashes are content-derived and independent of
//!    timestamps/ids (we still pin those for byte stability), so the snapshot
//!    is an honest cross-build regression lock: any drift in the encode path
//!    moves a hash and fails.
//!
//!    NOTE: `frankenctl compile` embeds the verbatim `--input` path into the
//!    IR0 content hash (parse_event_ir stays path-independent), so the golden is
//!    only reproducible when the input path string is fixed. We therefore run
//!    compile with cwd set to a temp dir and a fixed relative `--input` name.
//!
//! 2. `frankenctl_run_replay_strict_passes_after_buffer_pool` captures a real
//!    nondeterminism trace from a live engine execution, serialises it, and
//!    drives `frankenctl replay --mode strict` over it. This exercises the
//!    decode + replay + re-encode round-trip through the actual binary and
//!    asserts strict replay completes with zero divergences. The replay source
//!    is property-heavy so the capture is non-empty; replay compares the trace
//!    against itself in-process.
//!
//! Re-bless the snapshot after an intentional encode change with:
//!   INSTA_UPDATE=always cargo test --test perf_h4_encode_buffer_integration \
//!       frankenctl_compile_artifact_unchanged_after_buffer_pool -- --nocapture

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use frankenengine_engine::baseline_interpreter::{ExecutionResult, QuickJsLane};
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;

/// Scalar source that drives the full parse→lower→encode pipeline through
/// `frankenctl compile`. The companion within-run test
/// `frankenctl_compile_and_run_artifacts_are_byte_identical_with_fixed_inputs`
/// in `deterministic_replay_integration.rs` proves byte-stability for one
/// invocation pair; here we add the cross-build snapshot lock H4.7 asks for.
const COMPILE_SOURCE: &str = "const a = 7;\n\
const b = 11;\n\
const c = a * b;\n\
const total = a + b + c;\n\
total;\n";

/// Stable, machine-independent source identifier. `frankenctl compile` embeds
/// the verbatim `--input` string into the IR0 content hash, so the golden is
/// only reproducible across machines/builds when that string is fixed. We pass
/// this relative name and run compile with cwd set to the temp dir.
const COMPILE_INPUT_NAME: &str = "h4_encode_fixture.js";
const COMPILE_OUTPUT_NAME: &str = "h4_encode_artifact.json";

/// Property-heavy source: drives real property-resolution nondeterminism events
/// so the captured trace is non-empty and finalised before replay.
const TRACE_SOURCE: &str = "const config = { mode: 1, level: 2, name: 3 };\n\
const nested = { inner: config };\n\
const mode = config.mode;\n\
const level = config.level;\n\
const total = mode + level + config.name;\n\
const deep = nested.inner;\n\
total;\n";

/// Ordered hash fields emitted under `compile_json["hashes"]`.
const HASH_FIELDS: [&str; 5] = ["parse_event_ir", "ir0", "ir1", "ir2", "ir3"];

fn assert_command_success(output: &Output, command: &str) {
    assert!(
        output.status.success(),
        "{command} failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Run `frankenctl compile` with cwd set to `dir` and relative input/output
/// names, so the embedded source path (and thus the IR0 content hash) is stable
/// across processes and machines.
fn run_frankenctl_compile(dir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .current_dir(dir)
        .arg("compile")
        .arg("--input")
        .arg(COMPILE_INPUT_NAME)
        .arg("--out")
        .arg(COMPILE_OUTPUT_NAME)
        .arg("--goal")
        .arg("script")
        .arg("--trace-id")
        .arg("h4-encode-buffer-trace")
        .arg("--decision-id")
        .arg("h4-encode-buffer-decision")
        .arg("--policy-id")
        .arg("h4-encode-buffer-policy")
        .arg("--generated-unix-ns")
        .arg("0")
        .output()
        .expect("frankenctl compile should execute")
}

fn run_frankenctl_replay_strict(trace_path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .arg("replay")
        .arg("run")
        .arg("--trace")
        .arg(trace_path)
        .arg("--mode")
        .arg("strict")
        .output()
        .expect("frankenctl replay should execute")
}

/// Extract the five content-hashes from a `frankenctl compile` of `COMPILE_SOURCE`.
fn capture_hashes() -> serde_json::Map<String, serde_json::Value> {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let source_path = temp.path().join(COMPILE_INPUT_NAME);
    fs::write(&source_path, COMPILE_SOURCE).expect("source fixture should write");

    let compiled = run_frankenctl_compile(temp.path());
    assert_command_success(&compiled, "frankenctl compile");

    let compile_json: serde_json::Value =
        serde_json::from_slice(&compiled.stdout).expect("compile stdout should parse as JSON");
    let hashes = compile_json["hashes"]
        .as_object()
        .expect("compile output should carry a hashes object")
        .clone();

    let mut selected = serde_json::Map::new();
    for field in HASH_FIELDS {
        let value = hashes
            .get(field)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("compile hashes must include non-null `{field}`"));
        assert!(
            !value.is_empty(),
            "compile hash `{field}` must be non-empty"
        );
        selected.insert(
            field.to_string(),
            serde_json::Value::String(value.to_string()),
        );
    }
    selected
}

fn execute_trace_fixture(trace_id: &str) -> ExecutionResult {
    let tree = parse_script(TRACE_SOURCE).expect("trace source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "perf_h4_encode_buffer.js");
    let context = LoweringContext::new(
        "perf-h4-encode-trace",
        "perf-h4-encode-decision",
        "perf-h4-encode-policy",
    );
    let module: Ir3Module = lower_ir0_to_ir3(&ir0, &context)
        .expect("trace source should lower")
        .ir3;
    QuickJsLane::new()
        .execute(&module, trace_id)
        .expect("trace source should execute")
}

#[test]
fn frankenctl_compile_artifact_unchanged_after_buffer_pool() {
    let captured = capture_hashes();

    // The encode path must be byte-stable within a build: a second compile of
    // the same source must produce the identical hash set.
    let captured_again = capture_hashes();
    assert_eq!(
        captured, captured_again,
        "frankenctl compile must be deterministic across repeated invocations"
    );

    let serialized =
        serde_json::to_string_pretty(&captured).expect("captured hashes should serialise");
    insta::assert_snapshot!(
        "frankenctl_compile_artifact_unchanged_after_buffer_pool",
        serialized
    );
}

#[test]
fn frankenctl_run_replay_strict_passes_after_buffer_pool() {
    let recorded = execute_trace_fixture("perf-h4-encode-replay");
    let trace = &recorded.nondeterminism_trace;
    assert!(
        trace.event_count() > 0,
        "live execution must capture nondeterminism events to replay"
    );
    assert!(
        trace.is_finalised(),
        "captured trace must be finalised before replay"
    );

    let temp = tempfile::tempdir().expect("tempdir should be created");
    let trace_path = temp.path().join("captured_trace.json");
    let serialized =
        serde_json::to_string_pretty(trace).expect("captured trace should serialise to JSON");
    fs::write(&trace_path, serialized).expect("trace file should write");

    let replay = run_frankenctl_replay_strict(&trace_path);
    assert_command_success(&replay, "frankenctl replay --mode strict");

    let replay_json: serde_json::Value =
        serde_json::from_slice(&replay.stdout).expect("replay stdout should parse as JSON");
    assert_eq!(
        replay_json["mode"].as_str(),
        Some("strict"),
        "replay should report strict mode"
    );
    assert_eq!(
        replay_json["divergence_count"].as_u64(),
        Some(0),
        "strict replay of a freshly-captured trace must not diverge"
    );
    assert_eq!(
        replay_json["critical_divergences"].as_u64(),
        Some(0),
        "strict replay must report zero critical divergences"
    );
    assert_eq!(
        replay_json["complete"].as_bool(),
        Some(true),
        "strict replay must consume every captured event"
    );
    assert_eq!(
        replay_json["event_count"].as_u64(),
        replay_json["replayed_events"].as_u64(),
        "every captured event must be replayed"
    );
}
