//! bd-9vouw.6: `frankenctl run --instruction-budget` lets ordinary programs run
//! through the primary CLI while keeping budget exhaustion fail-closed and
//! strict replay exact.
//!
//! Before this change `frankenctl run` always used the 100k-instruction
//! containment default with no override, so a 1M-iteration loop that Node
//! finishes in ~60 ms could not run at all.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const LOOP_SOURCE: &str =
    "var i = 0; var sum = 0; while (i < 1000000) { sum = sum + i; i = i + 1; } console.log(sum);";

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("{name}_{}_{nonce}", std::process::id()));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

fn frankenctl(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(args)
        .output()
        .expect("frankenctl should execute")
}

fn utf8(path: &Path) -> &str {
    path.to_str().expect("utf8 path")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn run_with_instruction_budget_executes_loop_and_replays_strictly_bd_9vouw_6() {
    let dir = temp_dir("fe_run_budget");
    let source = dir.join("loop.js");
    fs::write(&source, LOOP_SOURCE).expect("write source");
    let report = dir.join("loop.run.json");

    let output = frankenctl(&[
        "run",
        "--input",
        utf8(&source),
        "--extension-id",
        "budget-ext",
        "--instruction-budget",
        "50000000",
        "--out",
        utf8(&report),
    ]);
    assert!(output.status.success(), "run failed: {}", stderr_of(&output));

    let report_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&report).expect("read report")).expect("report json");
    let messages: Vec<&str> = report_json["console_output"]
        .as_array()
        .expect("console_output array")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .collect();
    assert_eq!(messages, vec!["499999500000"], "sum of 0..1e6 must match Node");
    assert_eq!(
        report_json["replay_input"]["instruction_budget"].as_u64(),
        Some(50_000_000),
        "the override must be recorded for replay"
    );

    let replay_report = dir.join("loop.replay.json");
    let replay = frankenctl(&[
        "replay",
        "run",
        "--trace",
        utf8(&report),
        "--mode",
        "strict",
        "--out",
        utf8(&replay_report),
    ]);
    assert!(
        replay.status.success(),
        "strict replay of a budgeted run failed: {}",
        stderr_of(&replay)
    );
}

#[test]
fn default_budget_still_fails_closed_and_omits_replay_field_bd_9vouw_6() {
    let dir = temp_dir("fe_run_default_budget");
    let source = dir.join("loop.js");
    fs::write(&source, LOOP_SOURCE).expect("write source");

    let output = frankenctl(&[
        "run",
        "--input",
        utf8(&source),
        "--extension-id",
        "budget-ext",
    ]);
    assert!(!output.status.success(), "default budget must not run a 1M-iteration loop");
    assert!(
        stderr_of(&output).contains("instruction budget exhausted"),
        "expected typed budget exhaustion, got: {}",
        stderr_of(&output)
    );

    // A small program under the default budget keeps the pre-existing report
    // shape: no instruction_budget key in the replay input.
    let small = dir.join("small.js");
    fs::write(&small, "console.log(40 + 2);").expect("write small source");
    let report = dir.join("small.run.json");
    let output = frankenctl(&[
        "run",
        "--input",
        utf8(&small),
        "--extension-id",
        "budget-ext",
        "--out",
        utf8(&report),
    ]);
    assert!(output.status.success(), "small run failed: {}", stderr_of(&output));
    let report_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&report).expect("read report")).expect("report json");
    assert!(
        report_json["replay_input"].get("instruction_budget").is_none(),
        "default runs must not grow a new report field"
    );
}

#[test]
fn instruction_budget_flag_is_validated_bd_9vouw_6() {
    let dir = temp_dir("fe_run_budget_validation");
    let source = dir.join("small.js");
    fs::write(&source, "console.log(1);").expect("write source");

    for (value, needle) in [
        ("0", "--instruction-budget must be at least 1"),
        ("10000000001", "--instruction-budget must be at most 10000000000"),
        ("not-a-number", "--instruction-budget"),
    ] {
        let output = frankenctl(&[
            "run",
            "--input",
            utf8(&source),
            "--extension-id",
            "budget-ext",
            "--instruction-budget",
            value,
        ]);
        assert!(!output.status.success(), "budget {value} must be rejected");
        assert!(
            stderr_of(&output).contains(needle),
            "budget {value}: expected `{needle}` in stderr, got: {}",
            stderr_of(&output)
        );
    }
}

#[test]
fn help_oracle_topic_is_routed_bd_9vouw_6() {
    let output = frankenctl(&["help", "oracle"]);
    assert!(output.status.success(), "help oracle failed: {}", stderr_of(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("oracle run"), "help oracle must describe oracle run: {stdout}");

    let run_help = frankenctl(&["help", "run"]);
    assert!(run_help.status.success());
    assert!(String::from_utf8_lossy(&run_help.stdout).contains("--instruction-budget"));
}
