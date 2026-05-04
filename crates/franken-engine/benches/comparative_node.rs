#![forbid(unsafe_code)]

//! Criterion-backed FrankenEngine vs Node.js subprocess benchmarks.
//!
//! Methodology:
//! - Each workload is a standalone JavaScript file materialized under
//!   `COMPARATIVE_NODE_BENCH_DIR` or the system temp directory.
//! - FrankenEngine is measured through `frankenctl run --input <workload>` so
//!   the number includes the CLI/orchestrator path operators invoke.
//! - Node.js is measured with the same workload path through the `node` binary.
//! - `frankenctl` is resolved from `FRANKENCTL`, Cargo's bin env var, the
//!   current benchmark target directory, or PATH.
//! - Before timing, the harness performs one semantic sanity check: Node's
//!   stdout must match either FrankenEngine's captured console output or final
//!   execution value in the frankenctl JSON result.
//! - Criterion reports timings per runtime and workload; ratios are meaningful
//!   only for this subprocess/CLI methodology, not as broad VM throughput.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use serde_json::Value;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[derive(Debug, Clone, Copy)]
struct Workload {
    id: &'static str,
    source: &'static str,
    expected_stdout: &'static str,
}

const WORKLOADS: &[Workload] = &[
    Workload {
        id: "numeric_loop",
        source: r#"
var i = 0;
var sum = 0;
while (i < 10000) {
  sum = sum + i;
  i = i + 1;
}
console.log(sum);
sum;
"#,
        expected_stdout: "49995000",
    },
    Workload {
        id: "basic_arithmetic",
        source: r#"
var i = 0;
var acc = 1;
while (i < 20000) {
  acc = (acc * 17 + i) % 1000003;
  i = i + 1;
}
console.log(acc);
acc;
"#,
        expected_stdout: "120504",
    },
    Workload {
        id: "json_roundtrip",
        source: r#"
var i = 0;
var payload = [{"idx":0,"value":0},{"idx":1,"value":2},{"idx":2,"value":4},{"idx":3,"value":6}];
var total = 0;
while (i < 1000) {
  var text = JSON.stringify(payload);
  var out = JSON.parse(text);
  total = total + out.length + out[3].value;
  i = i + 1;
}
console.log(total);
total;
"#,
        expected_stdout: "10000",
    },
];

fn bench_comparative_node(c: &mut Criterion) {
    let Some(frankenctl) = frankenctl_path() else {
        eprintln!("skipping comparative_node: frankenctl binary not found");
        return;
    };
    let Some(node) = node_path() else {
        eprintln!("skipping comparative_node: node binary not found");
        return;
    };

    let fixtures = materialize_workloads();

    for (workload, path) in WORKLOADS.iter().zip(fixtures.iter()) {
        verify_equivalent_output(&frankenctl, &node, workload, path);

        let mut group = c.benchmark_group(format!("comparative_node/{}", workload.id));
        group.bench_with_input(
            BenchmarkId::new("frankenengine_frankenctl_run", workload.id),
            path,
            |b, path| {
                b.iter(|| {
                    let output = run_frankenctl(&frankenctl, workload.id, path);
                    black_box(output.stdout.len())
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("node_lts", workload.id),
            path,
            |b, path| {
                b.iter(|| {
                    let output = run_node(&node, path);
                    black_box(output.stdout.len())
                });
            },
        );
        group.finish();
    }
}

fn frankenctl_path() -> Option<PathBuf> {
    env::var_os("FRANKENCTL")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(|| {
            option_env!("CARGO_BIN_EXE_frankenctl")
                .filter(|path| !path.is_empty())
                .map(PathBuf::from)
                .filter(|path| path.is_file())
        })
        .or_else(frankenctl_in_current_target_dir)
        .or_else(|| command_in_path("frankenctl"))
}

fn frankenctl_in_current_target_dir() -> Option<PathBuf> {
    let current_exe = env::current_exe().ok()?;
    let deps_dir = current_exe.parent()?;
    let profile_dir = deps_dir.parent()?;
    command_in_dir(profile_dir, "frankenctl")
}

fn command_in_dir(dir: &Path, command: &str) -> Option<PathBuf> {
    let candidate = dir.join(executable_name(command));
    candidate.is_file().then_some(candidate)
}

fn executable_name(command: &str) -> String {
    format!("{command}{}", env::consts::EXE_SUFFIX)
}

fn command_in_path(command: &str) -> Option<PathBuf> {
    let executable = executable_name(command);
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|entry| entry.join(&executable))
        .find(|candidate| candidate.is_file())
}

fn node_path() -> Option<PathBuf> {
    env::var_os("NODE")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(|| command_in_path("node"))
}

fn materialize_workloads() -> Vec<PathBuf> {
    let root = env::var_os("COMPARATIVE_NODE_BENCH_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::temp_dir().join("franken_engine_comparative_node_bench"));
    fs::create_dir_all(&root).expect("comparative benchmark fixture directory should be writable");

    WORKLOADS
        .iter()
        .map(|workload| {
            let path = root.join(format!("{}.js", workload.id));
            fs::write(&path, workload.source)
                .expect("comparative benchmark workload should be writable");
            path
        })
        .collect()
}

fn verify_equivalent_output(frankenctl: &Path, node: &Path, workload: &Workload, path: &Path) {
    let node_output = run_node(node, path);
    let node_stdout = stdout_trimmed(&node_output);
    assert_eq!(
        node_stdout, workload.expected_stdout,
        "Node output for {} drifted from the pinned workload expectation",
        workload.id
    );

    let franken_output = run_frankenctl(frankenctl, workload.id, path);
    let franken_json: Value =
        serde_json::from_slice(&franken_output.stdout).expect("frankenctl run should emit JSON");
    assert!(
        franken_json_contains_value(&franken_json, workload.expected_stdout),
        "FrankenEngine output for {} did not match Node stdout {}; frankenctl JSON was {}",
        workload.id,
        workload.expected_stdout,
        franken_json
    );
}

fn run_frankenctl(frankenctl: &Path, workload_id: &str, path: &Path) -> Output {
    let extension_id = format!("bench-node-{workload_id}");
    let args = vec![
        OsString::from("run"),
        OsString::from("--input"),
        path.as_os_str().to_os_string(),
        OsString::from("--extension-id"),
        OsString::from(extension_id),
    ];
    run_checked(frankenctl, &args)
}

fn run_node(node: &Path, path: &Path) -> Output {
    run_checked(node, &[path.as_os_str().to_os_string()])
}

fn run_checked(program: &Path, args: &[OsString]) -> Output {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to spawn {}: {error}", program.display()));
    assert!(
        output.status.success(),
        "{} failed with status {:?}; stderr={}",
        program.display(),
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn stdout_trimmed(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn franken_json_contains_value(value: &Value, expected: &str) -> bool {
    value
        .get("console_output")
        .and_then(Value::as_array)
        .map(|entries| {
            entries.iter().any(|entry| {
                entry
                    .get("message")
                    .and_then(Value::as_str)
                    .is_some_and(|message| message.trim() == expected)
            })
        })
        .unwrap_or(false)
        || value_matches_expected(value.get("execution_value"), expected)
}

fn value_matches_expected(value: Option<&Value>, expected: &str) -> bool {
    match value {
        Some(Value::String(actual)) => actual.trim() == expected,
        Some(Value::Number(actual)) => actual.to_string() == expected,
        Some(Value::Object(object)) => object
            .get("value")
            .is_some_and(|inner| value_matches_expected(Some(inner), expected)),
        _ => false,
    }
}

criterion_group! {
    name = comparative_node;
    config = Criterion::default().sample_size(10);
    targets = bench_comparative_node
}
criterion_main!(comparative_node);
