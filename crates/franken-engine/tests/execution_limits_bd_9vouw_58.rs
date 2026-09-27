//! bd-9vouw.58: hard-coded limits must not kill or silently truncate
//! ordinary programs on `frankenctl run`, and every operator override must be
//! recorded so strict replay re-executes under the same limits.
//!
//! Each case runs through the real `frankenctl` binary. Expected outputs were
//! produced by Node v22.2.0 on the identical source. Before the change:
//! 10,001 zero-delay timers died with "event loop turn limit exceeded"; the
//! heap-object cap had no flag; and a 3,000-line program reported only its
//! last 1,000 lines with exit 0 and no sign of the loss. The parser token
//! budget and the event-loop turn cap are main's (`run --parser-max-tokens`,
//! f00c4b425); the token case here checks that flag composes with these.
//! No-claim: this does not change the default instruction budget.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn scratch_dir(tag: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("fe_limits_{tag}_{}_{nonce}", std::process::id()));
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn frankenctl(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(args)
        .output()
        .expect("frankenctl should execute")
}

/// `frankenctl run` of `source`; returns the process output and, on success,
/// the parsed report.
fn run(
    dir: &Path,
    name: &str,
    source: &str,
    extra: &[&str],
) -> (Output, Option<serde_json::Value>) {
    let input = dir.join(format!("{name}.js"));
    let report = dir.join(format!("{name}.run.json"));
    fs::write(&input, source).expect("write program");
    let mut args = vec![
        "run",
        "--input",
        input.to_str().expect("utf8"),
        "--extension-id",
        "limits",
        "--out",
        report.to_str().expect("utf8"),
    ];
    args.extend_from_slice(extra);
    let output = frankenctl(&args);
    let parsed = output.status.success().then(|| {
        serde_json::from_str(&fs::read_to_string(&report).expect("report")).expect("report json")
    });
    (output, parsed)
}

fn console_lines(report: &serde_json::Value) -> Vec<String> {
    report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .map(|entry| entry["message"].as_str().expect("message").to_string())
        .collect()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn more_than_ten_thousand_timers_run_to_completion() {
    let dir = scratch_dir("timers");
    let source = "let n=0; for (let i=0;i<10001;i++) setTimeout(()=>{ n++; if (n===10001) console.log('all', n) }, 0);\n";
    let (output, report) = run(
        &dir,
        "timers",
        source,
        &["--instruction-budget", "50000000"],
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    // node: all 10001
    assert_eq!(console_lines(&report.expect("report")), vec!["all 10001"]);
}

#[test]
fn heap_object_cap_is_configurable_and_recorded_for_replay() {
    let dir = scratch_dir("heap");
    let source = "let s=0; for (let i=0;i<150000;i++){ const o={a:i}; s+=o.a&1 } console.log(s);\n";
    let budget = ["--instruction-budget", "100000000"];

    // Default containment cap (append-only heap) still fails closed.
    let (default_run, _) = run(&dir, "heap_default", source, &budget);
    assert!(
        !default_run.status.success(),
        "150k allocations must exceed the default cap"
    );
    assert!(
        stderr(&default_run).contains("memory budget exceeded"),
        "{}",
        stderr(&default_run)
    );

    let (raised_run, report) = run(
        &dir,
        "heap_raised",
        source,
        &[budget[0], budget[1], "--max-heap-objects", "1000000"],
    );
    assert!(
        raised_run.status.success(),
        "stderr: {}",
        stderr(&raised_run)
    );
    let report = report.expect("report");
    // node: 75000
    assert_eq!(console_lines(&report), vec!["75000"]);
    assert_eq!(report["replay_input"]["max_heap_objects"], 1_000_000);

    // Strict replay re-executes under the recorded cap (it would fail closed
    // under the default cap).
    let replay_out = dir.join("heap_raised.replay.json");
    let replay = frankenctl(&[
        "replay",
        "run",
        "--trace",
        dir.join("heap_raised.run.json").to_str().expect("utf8"),
        "--mode",
        "strict",
        "--out",
        replay_out.to_str().expect("utf8"),
    ]);
    assert!(
        replay.status.success(),
        "replay stderr: {}",
        stderr(&replay)
    );
}

#[test]
fn default_runs_keep_limit_fields_off_the_replay_input() {
    let dir = scratch_dir("wire");
    let (output, report) = run(&dir, "plain", "console.log(1 + 1);\n", &[]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let replay_input = report.expect("report")["replay_input"].clone();
    for key in [
        "max_heap_objects",
        "max_heap_bytes",
        "max_console_entries",
        "parser_max_token_count",
        "max_source_bytes",
    ] {
        assert!(
            replay_input.get(key).is_none(),
            "{key} must be absent by default"
        );
    }
}

#[test]
fn token_budget_binds_by_default_and_the_run_flag_raises_it() {
    let dir = scratch_dir("tokens");
    // ~80k tokens in ~230 KB: beyond the library's 65,536-token default,
    // far below the 1 MiB byte cap. The default binds; main's
    // `--parser-max-tokens` (bd-9vouw.58) raises it.
    let elements: Vec<String> = (0..40_000).map(|i| i.to_string()).collect();
    let source = format!(
        "const a=[{}]; console.log(a.length, a[39999]);\n",
        elements.join(",")
    );
    let (default_run, _) = run(&dir, "big_literal_default", &source, &[]);
    assert!(!default_run.status.success());
    assert!(
        stderr(&default_run).contains("token budget exceeded"),
        "{}",
        stderr(&default_run)
    );
    let (output, report) = run(
        &dir,
        "big_literal",
        &source,
        &["--parser-max-tokens", "100000"],
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    // node: 40000 39999
    assert_eq!(console_lines(&report.expect("report")), vec!["40000 39999"]);

    // A lower explicit token cap still binds and fails closed.
    let (capped, _) = run(
        &dir,
        "big_literal_capped",
        &source,
        &["--parser-max-tokens", "1000"],
    );
    assert!(!capped.status.success());
    assert!(
        stderr(&capped).contains("token budget exceeded"),
        "{}",
        stderr(&capped)
    );
}

#[test]
fn console_rotation_is_never_silent_and_the_cap_is_configurable() {
    let dir = scratch_dir("console");
    let source = "for (let i=0;i<3000;i++) console.log('line', i);\n";
    let budget = ["--instruction-budget", "10000000"];

    let (output, report) = run(&dir, "rotated", source, &budget);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let lines = console_lines(&report.expect("report"));
    let marker = &lines[0];
    assert!(
        marker.starts_with("[frankenengine] ")
            && marker.contains("earlier console entries were dropped"),
        "a rotated transcript must lead with the drop marker, got {marker:?}"
    );
    let retained = lines.len() - 1;
    assert!(retained < 3000);
    assert!(
        marker.starts_with(&format!("[frankenengine] {} earlier", 3000 - retained)),
        "marker must count exactly the dropped entries: {marker:?}"
    );
    assert_eq!(lines.last().map(String::as_str), Some("line 2999"));

    let (output, report) = run(
        &dir,
        "full",
        source,
        &[budget[0], budget[1], "--max-console-entries", "5000"],
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let lines = console_lines(&report.expect("report"));
    // node: 3000 lines, "line 0" .. "line 2999"
    assert_eq!(lines.len(), 3000);
    assert_eq!(lines[0], "line 0");
    assert_eq!(lines[2999], "line 2999");
}
