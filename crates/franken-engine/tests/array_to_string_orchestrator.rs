//! Regression tests for Array.prototype.toString / array string coercion on
//! the orchestrated `frankenctl run` path (bd-sxh8o.3).
//!
//! Live 2026-08-20: `console.log([1,2,3].toString())` printed
//! `[object Array]` and `console.log([1,2,3])` printed `[object Object]`.
//! These tests shell the real `frankenctl` binary so the fix is proven on the
//! shipped CLI path, not only in interpreter unit tests.

#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    path.push(format!("{name}_{}_{}", std::process::id(), nonce));
    fs::create_dir_all(&path).expect("temp dir should be creatable");
    path
}

fn run_console_messages(test_name: &str, extension_id: &str, source: &str) -> Vec<String> {
    let dir = temp_dir(test_name);
    let input = dir.join("input.js");
    let out = dir.join("run.json");
    fs::write(&input, source).expect("source should write");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("utf8 path"),
            "--extension-id",
            extension_id,
            "--out",
            out.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("frankenctl run should execute");
    assert!(
        output.status.success(),
        "frankenctl run should exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value = serde_json::from_slice(
        &fs::read(&out).expect("run report should be readable"),
    )
    .expect("run report should be JSON");
    report["console_output"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry["message"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn array_to_string_joins_elements_bd_sxh8o_3() {
    let messages = run_console_messages(
        "fe_sxh8o3_tostring",
        "bd-sxh8o3-tostring",
        "console.log([1,2,3].toString());\n",
    );
    assert_eq!(messages, vec!["1,2,3"], "Array.prototype.toString should join");
}

#[test]
fn console_log_of_array_prints_join_bd_sxh8o_3() {
    let messages = run_console_messages(
        "fe_sxh8o3_console",
        "bd-sxh8o3-console",
        "console.log([1,2,3]);\nconsole.log([1,2,3].map(x => x * 2));\n",
    );
    assert_eq!(
        messages,
        vec!["1,2,3", "2,4,6"],
        "console.log of an array must not print [object Array]/[object Object]"
    );
}

#[test]
fn empty_and_hole_arrays_bd_sxh8o_3() {
    let messages = run_console_messages(
        "fe_sxh8o3_empty_holes",
        "bd-sxh8o3-empty",
        "console.log('<' + [].toString() + '>');\nconsole.log([1,,3].toString());\nconsole.log([null, undefined, 4].toString());\n",
    );
    assert_eq!(
        messages,
        vec!["<>", "1,,3", ",,4"],
        "empty array joins to \"\"; holes/null/undefined render empty"
    );
}

#[test]
fn nested_arrays_recurse_through_default_join_bd_sxh8o_3() {
    let messages = run_console_messages(
        "fe_sxh8o3_nested",
        "bd-sxh8o3-nested",
        "console.log([[1,2],[3]].toString());\nconsole.log([[1,2],[3]].join('-'));\n",
    );
    assert_eq!(
        messages,
        vec!["1,2,3", "1,2-3"],
        "nested arrays stringify through their own default join"
    );
}

#[test]
fn cyclic_array_does_not_overflow_bd_sxh8o_3() {
    let messages = run_console_messages(
        "fe_sxh8o3_cyclic",
        "bd-sxh8o3-cyclic",
        "var a = [1, 2];\na.push(a);\nconsole.log(a.toString());\n",
    );
    assert_eq!(
        messages,
        vec!["1,2,"],
        "a cyclic array renders its cycle as \"\" instead of recursing forever"
    );
}

#[test]
fn own_join_override_wins_bd_sxh8o_3() {
    let messages = run_console_messages(
        "fe_sxh8o3_join_override",
        "bd-sxh8o3-override",
        "var a = [1, 2];\na.join = () => 'custom';\nconsole.log(a.toString());\n",
    );
    assert_eq!(
        messages,
        vec!["custom"],
        "Array.prototype.toString must invoke a callable own `join` override"
    );
}
