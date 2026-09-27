//! bd-9vouw.59: the deterministic wall clock must advance.
//!
//! Before the change `Date.now()` and `new Date()` returned the fixed epoch
//! (2026-01-01T00:00:00Z) for the whole run: a 100 ms timer observed 0 ms
//! elapsed, work never took time, and `while (Date.now() < t) {}` spun until
//! the instruction budget killed it. The engine already kept a virtual event
//! loop clock that advances to each timer's due time; the wall clock now reads
//! it (plus one virtual millisecond per 1,000 guest instructions), so timer
//! idioms see their delays, elapsed-time measurement sees work, and busy-waits
//! end, while two runs of the same program still print the same values and
//! strict replay re-executes them exactly.
//! No-claim: virtual time is deterministic, not wall time; absolute readings
//! differ from Node's, the relations tested here do not.

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
    let dir = std::env::temp_dir().join(format!(
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

/// Run `source` and return its console lines; panics with stderr on failure.
fn run_lines(dir: &Path, name: &str, source: &str) -> Vec<String> {
    let input = dir.join(format!("{name}.js"));
    let report = dir.join(format!("{name}.run.json"));
    fs::write(&input, source).expect("program");
    let output = frankenctl(&[
        "run",
        "--input",
        input.to_str().expect("utf8"),
        "--extension-id",
        "clock",
        "--instruction-budget",
        "50000000",
        "--out",
        report.to_str().expect("utf8"),
    ]);
    assert!(
        output.status.success(),
        "{name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&report).expect("report")).expect("json");
    parsed["console_output"]
        .as_array()
        .expect("console")
        .iter()
        .map(|entry| entry["message"].as_str().expect("message").to_string())
        .collect()
}

#[test]
fn a_fresh_run_starts_at_the_fixed_epoch() {
    let dir = scratch_dir("epoch");
    let lines = run_lines(&dir, "epoch", "console.log(Date.now());");
    assert_eq!(lines, vec![EPOCH_MS.to_string()]);
}

#[test]
fn timer_callbacks_observe_their_delays_in_order() {
    let dir = scratch_dir("timers");
    let source = "const start = Date.now();\n\
        setTimeout(() => console.log('t100', Date.now() - start >= 100, new Date().getTime() - start >= 100), 100);\n\
        setTimeout(() => console.log('t5', Date.now() - start >= 5), 5);\n";
    // node: t5 true / t100 true true
    assert_eq!(
        run_lines(&dir, "timers", source),
        vec!["t5 true", "t100 true true"]
    );
}

#[test]
fn guest_work_advances_the_clock_and_busy_waits_end() {
    let dir = scratch_dir("work");
    let source = "const a = Date.now(); let x = 0; for (let i = 0; i < 100000; i++) x += i;\n\
        const b = Date.now(); console.log(b >= a, b - a > 0);\n\
        const s = Date.now(); let spins = 0; while (Date.now() - s < 50) spins++;\n\
        console.log(spins > 0, Date.now() - s >= 50);\n";
    // node (this host, 3/3 runs): true true / true true. On a fast machine
    // Node's first `b - a > 0` can read 0 ms; the engine's virtual clock
    // charges the 100k-iteration loop deterministically.
    assert_eq!(
        run_lines(&dir, "work", source),
        vec!["true true", "true true"]
    );
}

#[test]
fn virtual_time_is_deterministic_and_strictly_replayable() {
    let dir = scratch_dir("replay");
    let source = "const s = Date.now(); let x = 0; for (let i = 0; i < 20000; i++) x += i;\n\
        setTimeout(() => console.log(Date.now() - s), 30); console.log(Date.now() - s);\n";
    let first = run_lines(&dir, "first", source);
    let second = run_lines(&dir, "second", source);
    assert_eq!(first, second, "virtual time must not depend on wall time");
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
