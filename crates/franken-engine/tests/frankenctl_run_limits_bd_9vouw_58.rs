//! bd-9vouw.58: default limits that real programs outgrow, on `frankenctl run`.
//!
//! - The parser's default token budget (65,536) is below what real packages
//!   need: lodash 4.17.21 is 121,349 tokens and failed with "token budget
//!   exceeded" before any of it ran, and `run` had no way to raise it.
//!   `--parser-max-tokens` raises it; the budget stays fail-closed and strict
//!   replay reuses the recorded value.
//! - The event loop stopped after a fixed 10,000 turns, so 10,001 `setTimeout`
//!   callbacks failed as an internal invariant violation. Turns are now
//!   bounded by the instruction budget (at least 10,000), and exhausting them
//!   is a typed budget failure.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

/// About 120,000 tokens (six per statement) in about 200 KB, well under the
/// 1 MiB source-byte budget.
fn large_source() -> String {
    format!(
        "var s = 0;\n{}console.log(s);\n",
        "s = s + 1;\n".repeat(20_000)
    )
}

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
fn default_token_budget_fails_closed_with_the_flag_named_bd_9vouw_58() {
    let dir = temp_dir("fe_run_parser_default");
    let source = dir.join("large.js");
    fs::write(&source, large_source()).expect("write source");

    let output = frankenctl(&[
        "run",
        "--input",
        utf8(&source),
        "--extension-id",
        "parser-ext",
    ]);
    assert!(
        !output.status.success(),
        "a 120k-token source must not parse under the default budget"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("token budget exceeded"),
        "expected typed token-budget exhaustion, got: {stderr}"
    );
    assert!(
        stderr.contains("--parser-max-tokens"),
        "the failure must name the flag that raises the budget, got: {stderr}"
    );
}

#[test]
fn run_with_parser_max_tokens_parses_and_replays_strictly_bd_9vouw_58() {
    let dir = temp_dir("fe_run_parser_budget");
    let source = dir.join("large.js");
    fs::write(&source, large_source()).expect("write source");
    let report = dir.join("large.run.json");

    let output = frankenctl(&[
        "run",
        "--input",
        utf8(&source),
        "--extension-id",
        "parser-ext",
        "--parser-max-tokens",
        "200000",
        "--instruction-budget",
        "10000000",
        "--out",
        utf8(&report),
    ]);
    assert!(
        output.status.success(),
        "run failed: {}",
        stderr_of(&output)
    );
    let report_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&report).expect("read report")).expect("report json");
    let messages: Vec<&str> = report_json["console_output"]
        .as_array()
        .expect("console_output array")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .collect();
    assert_eq!(messages, vec!["20000"], "the program must run to the end");
    assert_eq!(
        report_json["replay_input"]["parser_max_token_count"].as_u64(),
        Some(200_000),
        "the override must be recorded for replay"
    );

    let replay = frankenctl(&[
        "replay",
        "run",
        "--trace",
        utf8(&report),
        "--mode",
        "strict",
        "--out",
        utf8(&dir.join("large.replay.json")),
    ]);
    assert!(
        replay.status.success(),
        "strict replay of a run with a raised parser budget failed: {}",
        stderr_of(&replay)
    );

    // NEGATIVE: a replay under a smaller recorded budget cannot parse the
    // source, so it must fail instead of reproducing the run.
    let mut tampered_json = report_json.clone();
    tampered_json["replay_input"]["parser_max_token_count"] = serde_json::json!(1000);
    let tampered = dir.join("large.tampered.json");
    fs::write(
        &tampered,
        serde_json::to_vec_pretty(&tampered_json).expect("serialize tampered report"),
    )
    .expect("write tampered report");
    let tampered_replay = frankenctl(&[
        "replay",
        "run",
        "--trace",
        utf8(&tampered),
        "--mode",
        "strict",
        "--out",
        utf8(&dir.join("large.tampered.replay.json")),
    ]);
    assert!(
        !tampered_replay.status.success(),
        "strict replay under a smaller parser budget must fail, stdout: {} stderr: {}",
        String::from_utf8_lossy(&tampered_replay.stdout),
        stderr_of(&tampered_replay)
    );
}

#[test]
fn default_runs_keep_their_report_shape_bd_9vouw_58() {
    let dir = temp_dir("fe_run_parser_shape");
    let small = dir.join("small.js");
    fs::write(&small, "console.log(40 + 2);").expect("write small source");
    let report = dir.join("small.run.json");
    let output = frankenctl(&[
        "run",
        "--input",
        utf8(&small),
        "--extension-id",
        "parser-ext",
        "--out",
        utf8(&report),
    ]);
    assert!(
        output.status.success(),
        "small run failed: {}",
        stderr_of(&output)
    );
    let report_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&report).expect("read report")).expect("report json");
    assert!(
        report_json["replay_input"]
            .get("parser_max_token_count")
            .is_none(),
        "default runs must not grow a new report field"
    );
}

#[test]
fn parser_max_tokens_flag_is_validated_and_documented_bd_9vouw_58() {
    let dir = temp_dir("fe_run_parser_validation");
    let source = dir.join("small.js");
    fs::write(&source, "console.log(1);").expect("write source");
    for (value, needle) in [
        ("0", "--parser-max-tokens must be at least 1"),
        ("16777217", "--parser-max-tokens must be at most 16777216"),
        ("many", "--parser-max-tokens"),
    ] {
        let output = frankenctl(&[
            "run",
            "--input",
            utf8(&source),
            "--extension-id",
            "parser-ext",
            "--parser-max-tokens",
            value,
        ]);
        assert!(
            !output.status.success(),
            "token budget {value} must be rejected"
        );
        assert!(
            stderr_of(&output).contains(needle),
            "token budget {value}: expected `{needle}` in stderr, got: {}",
            stderr_of(&output)
        );
    }

    let run_help = frankenctl(&["help", "run"]);
    assert!(run_help.status.success());
    assert!(String::from_utf8_lossy(&run_help.stdout).contains("--parser-max-tokens"));
}

#[test]
fn event_loop_turns_follow_the_instruction_budget_bd_9vouw_58() {
    let dir = temp_dir("fe_run_turns");
    let source = dir.join("timers.js");
    fs::write(
        &source,
        "let n = 0; for (let i = 0; i < 10001; i++) setTimeout(() => { n++; }, 0); \
         setTimeout(() => console.log(n), 1);",
    )
    .expect("write source");
    let report = dir.join("timers.run.json");
    let output = frankenctl(&[
        "run",
        "--input",
        utf8(&source),
        "--extension-id",
        "turns-ext",
        "--instruction-budget",
        "10000000",
        "--out",
        utf8(&report),
    ]);
    assert!(
        output.status.success(),
        "10,001 timers must run: {}",
        stderr_of(&output)
    );
    let report_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&report).expect("read report")).expect("report json");
    let messages: Vec<&str> = report_json["console_output"]
        .as_array()
        .expect("console_output array")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .collect();
    assert_eq!(messages, vec!["10001"], "Node v22.2.0 prints 10001");

    // NEGATIVE: an interval that never stops still ends, as a typed budget
    // failure rather than an internal invariant violation.
    let runaway = dir.join("runaway.js");
    fs::write(&runaway, "setInterval(() => {}, 0);").expect("write runaway source");
    let output = frankenctl(&[
        "run",
        "--input",
        utf8(&runaway),
        "--extension-id",
        "turns-ext",
    ]);
    assert!(
        !output.status.success(),
        "a runaway interval must not succeed"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("instruction budget exhausted"),
        "expected a typed budget failure, got: {stderr}"
    );
    assert!(
        !stderr.contains("invariant violated"),
        "budget exhaustion is not an internal invariant violation: {stderr}"
    );
}
