//! Shared golden/snapshot test support utilities.
//!
//! The old `GoldenDiag` fixture-comparison abstraction has been retired as
//! suites move to `insta`. This module now keeps only the cross-suite scrub
//! regexes and CLI binary resolution support that current tests still share.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex, OnceLock};

use regex::Regex;

// ---------------------------------------------------------------------------
// Shared scrub patterns (bd-ub6x8.12)
//
// These patterns recur across multiple golden suites (cli_golden,
// benchmark_diagnostic_golden, etc.). Centralising them here keeps the
// canonical-scrub vocabulary consistent and avoids per-suite recompiles.
// Suites with bespoke patterns (UUIDs, evidence hashes, etc.) still keep
// those local — only the cross-suite repeats live in this module.
// ---------------------------------------------------------------------------

/// ISO 8601 timestamps like `2026-04-30T12:34:56Z`.
#[allow(dead_code)]
pub static SCRUB_ISO_TIMESTAMP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[Z\d\.\-\+:]*").unwrap());

/// Absolute paths rooted at `/data/projects/franken_engine`.
#[allow(dead_code)]
pub static SCRUB_PROJECT_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/data/projects/franken_engine[/\w\-\.]*").unwrap());

/// Temporary paths under `/tmp/...`.
#[allow(dead_code)]
pub static SCRUB_TMP_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/tmp/[/\w\-\.]*").unwrap());

/// Cargo `target/...` build-artifact paths.
#[allow(dead_code)]
pub static SCRUB_TARGET_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\.rch-)?target(?:-[\w\-]+)?/[\w\-/\.]*").unwrap());

// ---------------------------------------------------------------------------
// Build-on-demand for CLI golden tests (bd-ub6x8.20)
//
// Without this helper, `cargo test --test cli_golden` (or
// `--test benchmark_diagnostic_golden`) would fail with "Binary not found"
// unless the caller had already run `cargo build --bins`. Worse, if the bin
// sources had changed since the last full build, the test would compare new
// goldens against a stale binary — a silent false-positive failure.
//
// `resolve_built_cli_binary` invokes `cargo build --bin <name>` exactly once
// per binary per process, then resolves the produced path. Setting
// `CLI_GOLDEN_BIN_DIR` skips the build (CI ships pre-built binaries that way).
// ---------------------------------------------------------------------------

/// Resolve the path to a freshly-built CLI binary, building it on demand.
///
/// Honors two environment hooks:
/// - `CLI_GOLDEN_BIN_DIR`: if set, return `<dir>/<binary_name>` without
///   invoking cargo (CI uses this with a prebuilt artifact directory).
/// - `CARGO_TARGET_DIR`: respected as the build output root, defaulting to
///   the crate's `target/`.
#[allow(dead_code)]
pub fn resolve_built_cli_binary(binary_name: &'static str) -> Result<PathBuf, String> {
    if let Ok(bin_dir) = std::env::var("CLI_GOLDEN_BIN_DIR") {
        let p = PathBuf::from(bin_dir).join(binary_name);
        if !p.exists() {
            return Err(format!(
                "CLI_GOLDEN_BIN_DIR set but binary not found: {}",
                p.display()
            ));
        }
        return Ok(p);
    }

    // Per-binary memo: serialise concurrent test threads asking for the same
    // bin so we issue at most one `cargo build` per binary per process.
    static CACHE: OnceLock<Mutex<HashMap<&'static str, Result<PathBuf, String>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().unwrap_or_else(|poison| poison.into_inner());
    if let Some(existing) = guard.get(binary_name) {
        return existing.clone();
    }

    let result = build_and_locate(binary_name);
    guard.insert(binary_name, result.clone());
    result
}

#[allow(dead_code)]
fn build_and_locate(binary_name: &'static str) -> Result<PathBuf, String> {
    use std::process::Command;

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(&cargo)
        .args(["build", "--bin", binary_name])
        .status()
        .map_err(|e| {
            format!(
                "spawning `{} build --bin {}` failed: {}",
                cargo, binary_name, e
            )
        })?;
    if !status.success() {
        return Err(format!(
            "`{} build --bin {}` exited with status {}",
            cargo, binary_name, status
        ));
    }

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let target_dir =
        std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| format!("{}/target", manifest_dir));
    let binary_path = PathBuf::from(target_dir).join("debug").join(binary_name);
    if !binary_path.exists() {
        return Err(format!(
            "binary not found after `cargo build --bin {}`: {}",
            binary_name,
            binary_path.display()
        ));
    }
    Ok(binary_path)
}
