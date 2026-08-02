//! Process-level contract tests for `scripts/bv_actionable_filter.sh` (bd-5oef0).
//!
//! The filter sits between two independently versioned CLIs, so reimplementing
//! its jq expression in Rust cannot prove that the shipped shell surface still
//! accepts their real JSON shapes. These tests execute the script itself with
//! exported Bash functions standing in for `bv` and `br`; no fixture files or
//! temporary directories are created.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{Value, json};

const COMMAND_HARNESS: &str = r#"
set -euo pipefail

bv() {
  local status="${BV_FIXTURE_STATUS:-0}"
  if [[ "$status" != "0" ]]; then
    return "$status"
  fi
  printf '%s\n' "$BV_FIXTURE"
}

br() {
  case " $* " in
    *" ready --json "*)
      ;;
    *)
      printf 'unexpected br arguments: %s\n' "$*" >&2
      return 64
      ;;
  esac
  local status="${BR_READY_STATUS:-0}"
  if [[ "$status" != "0" ]]; then
    return "$status"
  fi
  printf '%s\n' "$BR_READY_FIXTURE"
}

export -f bv br
exec bash "$1" --json
"#;

fn script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("scripts/bv_actionable_filter.sh")
}

fn mock_bv_output() -> Value {
    json!({
        "plan": {
            "tracks": [
                {
                    "track_id": "track1",
                    "items": [
                        {"id": "bd-ready1", "status": "open", "title": "Ready item 1"},
                        {"id": "bd-blocked1", "status": "open", "title": "Blocked item 1"},
                        {"id": "bd-ready2", "status": "open", "title": "Ready item 2"}
                    ]
                },
                {
                    "track_id": "track2",
                    "items": [
                        {
                            "id": "bd-dependency-blocked1",
                            "status": "open",
                            "title": "Dependency-blocked item serialized as open"
                        },
                        {"id": "bd-ready3", "status": "open", "title": "Ready item 3"}
                    ]
                },
                {
                    "track_id": "track3",
                    "items": [
                        {"id": "bd-blocked2", "status": "open", "title": "Blocked item 2"}
                    ]
                }
            ]
        }
    })
}

fn ready_issues() -> Value {
    json!([
        {"id": "bd-ready1", "status": "open"},
        {"id": "bd-ready2", "status": "open"},
        {"id": "bd-ready3", "status": "open"}
    ])
}

fn run_filter_raw(ready: &str, ready_status: Option<u8>, bv_status: Option<u8>) -> Output {
    let mut command = Command::new("bash");
    command
        .arg("-c")
        .arg(COMMAND_HARNESS)
        .arg("bv-actionable-filter-contract")
        .arg(script_path())
        .env("BV_FIXTURE", mock_bv_output().to_string())
        .env("BR_READY_FIXTURE", ready);
    if let Some(status) = ready_status {
        command.env("BR_READY_STATUS", status.to_string());
    }
    if let Some(status) = bv_status {
        command.env("BV_FIXTURE_STATUS", status.to_string());
    }
    command
        .output()
        .expect("execute the real bv actionable filter script")
}

fn run_filter(ready: &Value) -> Output {
    run_filter_raw(&ready.to_string(), None, None)
}

fn successful_json(output: Output) -> Value {
    assert!(
        output.status.success(),
        "filter failed with {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("filter stdout is JSON")
}

fn filtered_ids(output: &Value) -> Vec<&str> {
    output["plan"]["tracks"]
        .as_array()
        .expect("plan.tracks is an array")
        .iter()
        .flat_map(|track| {
            track["items"]
                .as_array()
                .expect("track.items is an array")
                .iter()
        })
        .map(|item| item["id"].as_str().expect("item id is a string"))
        .collect()
}

fn assert_expected_filter_result(output: &Value) {
    assert_eq!(
        filtered_ids(output),
        ["bd-ready1", "bd-ready2", "bd-ready3"]
    );
    let track_ids: Vec<_> = output["plan"]["tracks"]
        .as_array()
        .expect("plan.tracks is an array")
        .iter()
        .map(|track| track["track_id"].as_str().expect("track id is a string"))
        .collect();
    assert_eq!(track_ids, ["track1", "track2"]);
}

#[test]
fn bv_filter_intersects_with_legacy_br_ready_arrays() {
    let output = successful_json(run_filter(&ready_issues()));
    assert_expected_filter_result(&output);
}

#[test]
fn bv_filter_intersects_with_current_br_ready_envelopes() {
    let ready = json!({
        "issues": ready_issues(),
        "total": 3,
        "limit": 50,
        "offset": 0,
        "has_more": false
    });

    let output = successful_json(run_filter(&ready));
    assert_expected_filter_result(&output);
}

#[test]
fn bv_filter_rejects_unknown_br_json_shapes() {
    let output = run_filter_raw(r#"{"unexpected":[]}"#, None, None);

    assert!(
        !output.status.success(),
        "unknown br JSON shape must fail closed\nstdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn bv_filter_rejects_ready_issues_without_string_ids() {
    let output = run_filter(&json!({"issues": [{"id": 42}]}));

    assert!(
        !output.status.success(),
        "non-string ready IDs must fail closed\nstdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn bv_filter_propagates_br_and_bv_command_failures() {
    let ready_failure = run_filter_raw(&ready_issues().to_string(), Some(17), None);
    assert_eq!(ready_failure.status.code(), Some(17));

    let bv_failure = run_filter_raw(&ready_issues().to_string(), None, Some(23));
    assert_eq!(bv_failure.status.code(), Some(23));
}
