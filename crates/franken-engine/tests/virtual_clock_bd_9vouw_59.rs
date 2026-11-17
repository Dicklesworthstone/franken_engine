//! bd-9vouw.59: the deterministic wall clock must advance.
//!
//! Before the change `Date.now()` and `new Date()` returned the fixed epoch
//! (2026-01-01T00:00:00Z) for the whole run: a 100 ms timer observed 0 ms
//! elapsed, work never took time, and `while (Date.now() < t) {}` spun until
//! the instruction budget killed it. The engine already kept a virtual event
//! loop clock that advances to each timer's due time; the wall clock and
//! `performance.now()` now read it (plus one virtual millisecond per 1,000
//! guest instructions), `--clock-epoch <ms|now>` selects and records the
//! starting epoch for replay, and strict replay re-executes every reading
//! identically.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const EPOCH_MS: i64 = 1_767_225_600_000;

fn scratch_dir(tag: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("target")
        .join("virtual_clock_bd_9vouw_59");
    let dir = root.join(format!(
        "fe_virtual_clock_{tag}_{}_{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn frankenctl(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(args)
        .output()
        .expect("frankenctl should execute")
}

/// Run `source` with optional extra CLI flags and return `(console_lines, report_json)`.
fn run_with_extra(
    dir: &Path,
    name: &str,
    source: &str,
    extra_args: &[&str],
) -> (Vec<String>, serde_json::Value) {
    let input = dir.join(format!("{name}.js"));
    let report = dir.join(format!("{name}.run.json"));
    fs::write(&input, source).expect("program");
    let mut args = vec![
        "run",
        "--input",
        input.to_str().expect("utf8"),
        "--extension-id",
        "clock",
        "--instruction-budget",
        "50000000",
        "--out",
        report.to_str().expect("utf8"),
    ];
    args.extend_from_slice(extra_args);
    let output = frankenctl(&args);
    assert!(
        output.status.success(),
        "{name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&report).expect("report")).expect("json");
    let lines = parsed["console_output"]
        .as_array()
        .expect("console")
        .iter()
        .map(|entry| entry["message"].as_str().expect("message").to_string())
        .collect();
    (lines, parsed)
}

fn run_lines(dir: &Path, name: &str, source: &str) -> Vec<String> {
    run_with_extra(dir, name, source, &[]).0
}

#[test]
fn a_fresh_run_starts_at_the_fixed_epoch() {
    let dir = scratch_dir("epoch");
    let lines = run_lines(&dir, "epoch", "console.log(Date.now());");
    assert_eq!(lines, vec![EPOCH_MS.to_string()]);
}

#[test]
fn timer_callbacks_observe_their_delays_in_order_including_performance_now() {
    let dir = scratch_dir("timers");
    let source = "const start = Date.now();\n\
        const p0 = performance.now();\n\
        setTimeout(() => console.log('t100', Date.now() - start >= 100, new Date().getTime() - start >= 100, performance.now() - p0 >= 100), 100);\n\
        setTimeout(() => console.log('t5', Date.now() - start >= 5, performance.now() - p0 >= 5), 5);\n";
    assert_eq!(
        run_lines(&dir, "timers", source),
        vec!["t5 true true", "t100 true true true"]
    );
}

#[test]
fn guest_work_advances_the_clock_and_busy_waits_end() {
    let dir = scratch_dir("work");
    let source = "const a = Date.now(); let x = 0; for (let i = 0; i < 100000; i++) x += i;\n\
        const b = Date.now(); console.log(b >= a, b - a > 0);\n\
        const s = Date.now(); let spins = 0; while (Date.now() - s < 50) spins++;\n\
        console.log(spins > 0, Date.now() - s >= 50);\n";
    assert_eq!(
        run_lines(&dir, "work", source),
        vec!["true true", "true true"]
    );
}

#[test]
fn date_subtraction_idiom_computes_exact_elapsed_days() {
    let dir = scratch_dir("date_sub");
    let source = "console.log((new Date(2020, 0, 11) - new Date(2020, 0, 1)) / 864e5 === 10);\n";
    assert_eq!(run_lines(&dir, "date_sub", source), vec!["true"]);
}

#[test]
fn virtual_time_is_deterministic_modulo_signing_and_strictly_replayable() {
    let dir = scratch_dir("replay");
    let source = "const s = Date.now(); let x = 0; for (let i = 0; i < 20000; i++) x += i;\n\
        setTimeout(() => console.log(Date.now() - s), 30); console.log(Date.now() - s);\n";
    let (first_lines, first_report) = run_with_extra(&dir, "first", source, &[]);
    let (second_lines, second_report) = run_with_extra(&dir, "second", source, &[]);
    assert_eq!(
        first_lines, second_lines,
        "virtual time must not depend on wall time"
    );
    assert_eq!(
        first_report["ir4_witness_hash"],
        second_report["ir4_witness_hash"]
    );
    assert_eq!(
        first_report["replay_input"]["unsigned_execution_content"],
        second_report["replay_input"]["unsigned_execution_content"]
    );
    assert!(
        first_report["replay_input"]["clock_epoch_ms"].is_null(),
        "default runs must omit clock_epoch_ms so historical/golden replay inputs stay unchanged"
    );
    let replay = frankenctl(&[
        "replay",
        "run",
        "--trace",
        dir.join("first.run.json").to_str().expect("utf8"),
        "--mode",
        "strict",
        "--out",
        dir.join("first.replay.json").to_str().expect("utf8"),
    ]);
    assert!(
        replay.status.success(),
        "strict replay: {}",
        String::from_utf8_lossy(&replay.stderr)
    );
}

#[test]
fn clock_epoch_override_and_now_record_epoch_and_strict_replay_reproduces_it() {
    let dir = scratch_dir("custom_epoch");
    let custom_epoch = "1700000000000";
    let source = "const start = Date.now();\n\
        setTimeout(() => console.log(start, Date.now() - start >= 25), 25);\n";
    let (custom_lines, custom_report) =
        run_with_extra(&dir, "custom", source, &["--clock-epoch", custom_epoch]);
    assert_eq!(custom_lines, vec!["1700000000000 true"]);
    assert_eq!(
        custom_report["replay_input"]["clock_epoch_ms"].as_i64(),
        Some(1_700_000_000_000)
    );
    let custom_replay = frankenctl(&[
        "replay",
        "run",
        "--trace",
        dir.join("custom.run.json").to_str().expect("utf8"),
        "--mode",
        "strict",
        "--out",
        dir.join("custom.replay.json").to_str().expect("utf8"),
    ]);
    assert!(
        custom_replay.status.success(),
        "custom epoch strict replay failed: {}",
        String::from_utf8_lossy(&custom_replay.stderr)
    );

    let (now_lines, now_report) = run_with_extra(&dir, "now", source, &["--clock-epoch", "now"]);
    let recorded_now = now_report["replay_input"]["clock_epoch_ms"]
        .as_i64()
        .expect("now epoch recorded");
    assert!(
        recorded_now >= EPOCH_MS,
        "wall clock now ({recorded_now}) should be >= 2026-01-01 ({EPOCH_MS})"
    );
    assert_eq!(now_lines, vec![format!("{recorded_now} true")]);
    let now_replay = frankenctl(&[
        "replay",
        "run",
        "--trace",
        dir.join("now.run.json").to_str().expect("utf8"),
        "--mode",
        "strict",
        "--out",
        dir.join("now.replay.json").to_str().expect("utf8"),
    ]);
    assert!(
        now_replay.status.success(),
        "now-epoch strict replay failed: {}",
        String::from_utf8_lossy(&now_replay.stderr)
    );
}
