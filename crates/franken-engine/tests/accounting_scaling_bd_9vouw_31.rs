//! bd-9vouw.31: memory accounting must not make each operation's cost grow
//! with the number of live closures or with Promise history.
//!
//! Before the fix every scope operation re-walked every live closure's
//! captured environment, and every Promise operation re-walked every Promise
//! record and replay-witness event, so these programs ran in O(N^2): 800 live
//! closures took ~20 s against ~0.19 s for the closure-free twin, and 2000
//! `f(i).then(...)` calls did not finish in 10 minutes.
//!
//! Each case runs the same program through `frankenctl run` at N and at 8N
//! and bounds the wall-time ratio. Linear work scales ~8x and the old
//! quadratic accounting ~64x; the bound (24x) sits far from both, so the test
//! tolerates a loaded machine without admitting the quadratic. Output is
//! checked against Node v22.2.0 so a fast wrong answer cannot pass.
//! No-claim: this bounds scaling on the default run path; it is not a
//! throughput benchmark and says nothing about absolute speed.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const SMALL: usize = 250;
const LARGE: usize = SMALL * 8;
const MAX_RATIO: f64 = 24.0;

fn scratch_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "fe_accounting_scaling_{}_{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// Best-of-3 wall time of one `frankenctl run`, plus its console output.
fn timed_run(dir: &Path, name: &str, source: &str) -> (f64, String) {
    let input = dir.join(format!("{name}.js"));
    let report = dir.join(format!("{name}.run.json"));
    fs::write(&input, source).expect("write program");
    let mut best = f64::INFINITY;
    let mut console = String::new();
    for _ in 0..3 {
        let start = Instant::now();
        let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
            .args([
                "run",
                "--input",
                input.to_str().expect("utf8"),
                "--extension-id",
                "accounting-scaling",
                "--instruction-budget",
                "500000000",
                "--out",
                report.to_str().expect("utf8"),
            ])
            .output()
            .expect("frankenctl should execute");
        let elapsed = start.elapsed().as_secs_f64();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{name} failed: {}",
            stderr
                .lines()
                .find(|line| line.contains("failed for"))
                .unwrap_or(&stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(&report).expect("read report")).expect("report json");
        console = report["console_output"]
            .as_array()
            .expect("console_output")
            .iter()
            .map(|entry| entry["message"].as_str().unwrap_or_default().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        best = best.min(elapsed);
    }
    (best, console)
}

fn assert_linear(
    case: &str,
    program: impl Fn(usize) -> String,
    expected: impl Fn(usize) -> String,
) {
    let dir = scratch_dir();
    let (small_secs, small_out) = timed_run(&dir, &format!("{case}_{SMALL}"), &program(SMALL));
    let (large_secs, large_out) = timed_run(&dir, &format!("{case}_{LARGE}"), &program(LARGE));
    assert_eq!(small_out, expected(SMALL), "{case} N={SMALL} output");
    assert_eq!(large_out, expected(LARGE), "{case} N={LARGE} output");
    let ratio = large_secs / small_secs.max(1e-3);
    eprintln!(
        "{case}: N={SMALL} {small_secs:.3}s, N={LARGE} {large_secs:.3}s, ratio {ratio:.1}x (linear ~8x, quadratic ~64x)"
    );
    assert!(
        ratio < MAX_RATIO,
        "{case}: 8x the work took {ratio:.1}x the time ({small_secs:.3}s -> {large_secs:.3}s); per-operation cost is growing with live state"
    );
}

#[test]
fn live_closures_do_not_make_scope_operations_quadratic_bd_9vouw_31() {
    // Node v22.2.0: `${n} ${n*(n-1)/2} ${n-1}`.
    assert_linear(
        "closures",
        |n| {
            format!(
                "const a=[]; for (let i=0;i<{n};i++) a.push(()=>i); let s=0; \
                 for (let i=0;i<{n};i++) s+=i; console.log(a.length, s, a[{n}-1]());"
            )
        },
        |n| format!("{n} {} {}", n * (n - 1) / 2, n - 1),
    );
}

#[test]
fn promise_history_does_not_make_promise_operations_quadratic_bd_9vouw_31() {
    // Node v22.2.0 prints n: every reaction runs before the 0 ms timer.
    assert_linear(
        "async_then",
        |n| {
            format!(
                "async function f(x){{ return x+1 }} let n=0; \
                 for (let i=0;i<{n};i++){{ f(i).then(()=>{{ n++ }}) }} \
                 setTimeout(()=>console.log(n),0);"
            )
        },
        |n| n.to_string(),
    );
}
