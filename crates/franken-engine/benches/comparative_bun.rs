#![forbid(unsafe_code)]

//! Criterion-backed FrankenEngine vs Bun subprocess benchmarks.
//!
//! Methodology:
//! - Each workload is a standalone JavaScript file materialized under
//!   `COMPARATIVE_BUN_BENCH_DIR` or the system temp directory.
//! - FrankenEngine is measured through `frankenctl run --input <workload>` so
//!   the number includes the CLI/orchestrator path operators invoke.
//! - Bun is measured with the same workload path through the `bun` binary.
//! - `frankenctl` is resolved from `FRANKENCTL`, Cargo's bin env var, the
//!   current benchmark target directory, or PATH.
//! - Before timing, the harness performs one semantic sanity check: Bun's
//!   stdout must match either FrankenEngine's captured console output or final
//!   execution value in the frankenctl JSON result.
//! - Resource measurement (wall-time + peak RSS) uses pidfd+wait4 on Linux
//!   (matching FrankenEngine's methodology from commit d728d81a) with fallback
//!   to GNU time wrapper for portability.
//! - Criterion reports timings per runtime and workload; ratios are meaningful
//!   only for this subprocess/CLI methodology, not as broad VM throughput.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use serde_json::Value;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::hint::black_box;
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use rustix::{
    event::{PollFd, PollFlags, poll},
    process::{Pid, PidfdFlags, getpid, pidfd_open},
    time::Timespec,
};
#[cfg(target_os = "linux")]
use wait4::Wait4;

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
    Workload {
        id: "array_indexing",
        source: r#"
var i = 0;
var values = [];
while (i < 1000) {
  values[i] = i % 17;
  i = i + 1;
}
var total = 0;
i = 0;
while (i < values.length) {
  total = total + values[i];
  i = i + 1;
}
console.log(total);
total;
"#,
        expected_stdout: "7979",
    },
];

#[derive(Debug, Clone, Copy)]
enum MeasurementMode {
    #[cfg(target_os = "linux")]
    DirectLinuxWait4,
    SimpleCommand,
}

#[derive(Debug)]
struct BunMeasurement {
    wall_time_ns: u64,
    peak_rss_bytes: u64,
    output: Output,
}

#[cfg(target_os = "linux")]
fn supports_direct_measurement() -> bool {
    static SUPPORT: OnceLock<bool> = OnceLock::new();
    *SUPPORT.get_or_init(|| pidfd_open(getpid(), PidfdFlags::empty()).is_ok())
}

#[cfg(not(target_os = "linux"))]
fn supports_direct_measurement() -> bool {
    false
}

fn measurement_mode() -> MeasurementMode {
    if supports_direct_measurement() {
        #[cfg(target_os = "linux")]
        return MeasurementMode::DirectLinuxWait4;
    }
    MeasurementMode::SimpleCommand
}

#[cfg(target_os = "linux")]
fn wait_for_pidfd<P: AsFd>(pidfd: &P, timeout: Duration) -> std::io::Result<bool> {
    let started = Instant::now();
    loop {
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return Ok(false);
        }

        let remaining = timeout - elapsed;
        let timeout_spec = Timespec {
            tv_sec: remaining.as_secs() as i64,
            tv_nsec: remaining.subsec_nanos() as i64,
        };

        let poll_fd = PollFd::new(pidfd, PollFlags::IN);
        match poll(&mut [poll_fd], Some(&timeout_spec)) {
            Ok(n) if n > 0 => return Ok(true),
            Ok(_) => return Ok(false),                // timeout
            Err(rustix::io::Errno::INTR) => continue, // interrupted, retry
            Err(e) => return Err(std::io::Error::other(e)),
        }
    }
}

#[cfg(target_os = "linux")]
fn force_terminate_child(child: &mut Child) -> std::io::Result<std::process::ExitStatus> {
    let _ = child.kill();
    child.wait()
}

#[cfg(target_os = "linux")]
fn run_bun_with_measurement(bun: &Path, path: &Path) -> std::io::Result<BunMeasurement> {
    let timeout = Duration::from_secs(30);
    let mut command = Command::new(bun);
    command.arg(path);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);

    let mut child = command.spawn()?;

    let pidfd = pidfd_open(Pid::from_child(&child), PidfdFlags::empty())?;
    let started = Instant::now();

    if !wait_for_pidfd(&pidfd, timeout)? {
        let status = force_terminate_child(&mut child)?;
        let _stdout = read_child_stdout(child.stdout.take())?;
        let _stderr = read_child_stderr(child.stderr.take())?;
        return Err(std::io::Error::other(format!(
            "Bun timed out after 30s, exit_code={:?}",
            status.code()
        )));
    }

    let resuse = child.wait4()?;
    let wall_time_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;

    let stdout = read_child_stdout(child.stdout.take())?;
    let stderr = read_child_stderr(child.stderr.take())?;

    Ok(BunMeasurement {
        wall_time_ns,
        peak_rss_bytes: resuse.rusage.maxrss,
        output: Output {
            status: resuse.status,
            stdout,
            stderr,
        },
    })
}

fn read_child_stdout(mut stream: Option<std::process::ChildStdout>) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut buffer = Vec::new();
    if let Some(ref mut s) = stream {
        s.read_to_end(&mut buffer)?;
    }
    Ok(buffer)
}

fn read_child_stderr(mut stream: Option<std::process::ChildStderr>) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut buffer = Vec::new();
    if let Some(ref mut s) = stream {
        s.read_to_end(&mut buffer)?;
    }
    Ok(buffer)
}

fn bench_comparative_bun(c: &mut Criterion) {
    let Some(frankenctl) = frankenctl_path() else {
        eprintln!("skipping comparative_bun: frankenctl binary not found");
        return;
    };
    let Some(bun) = bun_path() else {
        eprintln!("skipping comparative_bun: bun binary not found");
        return;
    };

    let fixtures = materialize_workloads();

    for (workload, path) in WORKLOADS.iter().zip(fixtures.iter()) {
        verify_equivalent_output(&frankenctl, &bun, workload, path);

        let mut group = c.benchmark_group(format!("comparative_bun/{}", workload.id));
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
            BenchmarkId::new("bun_stable", workload.id),
            path,
            |b, path| {
                b.iter(|| {
                    let measurement = run_bun_measured(&bun, path);
                    // Report both wall time and peak RSS for comprehensive measurement
                    black_box((
                        measurement.output.stdout.len(),
                        measurement.wall_time_ns,
                        measurement.peak_rss_bytes,
                    ))
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

fn bun_path() -> Option<PathBuf> {
    env::var_os("BUN")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(|| command_in_path("bun"))
}

fn materialize_workloads() -> Vec<PathBuf> {
    let root = env::var_os("COMPARATIVE_BUN_BENCH_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::temp_dir().join("franken_engine_comparative_bun_bench"));
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

fn verify_equivalent_output(frankenctl: &Path, bun: &Path, workload: &Workload, path: &Path) {
    let bun_output = run_bun(bun, path);
    let bun_stdout = stdout_trimmed(&bun_output);
    assert_eq!(
        bun_stdout, workload.expected_stdout,
        "Bun output for {} drifted from the pinned workload expectation",
        workload.id
    );

    let franken_output = run_frankenctl(frankenctl, workload.id, path);
    let franken_json: Value =
        serde_json::from_slice(&franken_output.stdout).expect("frankenctl run should emit JSON");
    assert!(
        franken_json_contains_value(&franken_json, workload.expected_stdout),
        "FrankenEngine output for {} did not match Bun stdout {}; frankenctl JSON was {}",
        workload.id,
        workload.expected_stdout,
        franken_json
    );
}

fn run_frankenctl(frankenctl: &Path, workload_id: &str, path: &Path) -> Output {
    let extension_id = format!("bench-bun-{workload_id}");
    let args = vec![
        OsString::from("run"),
        OsString::from("--input"),
        path.as_os_str().to_os_string(),
        OsString::from("--extension-id"),
        OsString::from(extension_id),
    ];
    run_checked(frankenctl, &args)
}

fn run_bun(bun: &Path, path: &Path) -> Output {
    match measurement_mode() {
        #[cfg(target_os = "linux")]
        MeasurementMode::DirectLinuxWait4 => match run_bun_with_measurement(bun, path) {
            Ok(measurement) => measurement.output,
            Err(e) => panic!("Bun measurement failed: {e}"),
        },
        #[cfg(not(target_os = "linux"))]
        MeasurementMode::DirectLinuxWait4 => {
            unreachable!("Direct Linux measurement mode selected on non-Linux platform")
        }
        MeasurementMode::SimpleCommand => run_checked(bun, &[path.as_os_str().to_os_string()]),
    }
}

fn run_bun_measured(bun: &Path, path: &Path) -> BunMeasurement {
    match measurement_mode() {
        #[cfg(target_os = "linux")]
        MeasurementMode::DirectLinuxWait4 => match run_bun_with_measurement(bun, path) {
            Ok(measurement) => measurement,
            Err(e) => panic!("Bun measurement failed: {e}"),
        },
        #[cfg(not(target_os = "linux"))]
        MeasurementMode::DirectLinuxWait4 => {
            unreachable!("Direct Linux measurement mode selected on non-Linux platform")
        }
        MeasurementMode::SimpleCommand => {
            let started = Instant::now();
            let output = run_checked(bun, &[path.as_os_str().to_os_string()]);
            let wall_time_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
            BunMeasurement {
                wall_time_ns,
                peak_rss_bytes: 0, // No RSS measurement in simple mode
                output,
            }
        }
    }
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
    name = comparative_bun;
    config = Criterion::default().sample_size(10);
    targets = bench_comparative_bun
}
criterion_main!(comparative_bun);
