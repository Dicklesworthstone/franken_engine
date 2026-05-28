//! Golden test diagnostics and error recovery utilities.
//!
//! Provides unified error handling, clear diagnostics, and helpful suggestions
//! for golden test frameworks across the codebase. Addresses common issues:
//! - Missing fixtures with clear instructions
//! - Overwhelming diff output with smart truncation
//! - Inconsistent environment variable handling
//! - Poor error context and recovery suggestions

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, OnceLock};

use regex::Regex;

/// Maximum lines to show from start/end of diff before truncating.
const DIFF_CONTEXT_LINES: usize = 10;

/// Maximum total diff lines before truncating.
const MAX_DIFF_LINES: usize = 50;

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
    LazyLock::new(|| Regex::new(r"target[/\w\-\.]*").unwrap());

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

/// Golden test error recovery and diagnostic utilities.
pub struct GoldenDiag {
    /// Test framework name for error messages.
    pub framework_name: &'static str,
    /// Environment variable name for regeneration.
    pub regen_env_var: &'static str,
}

impl GoldenDiag {
    /// Create diagnostics helper for CLI golden tests.
    #[allow(dead_code)]
    pub fn cli() -> Self {
        Self {
            framework_name: "CLI golden",
            regen_env_var: "UPDATE_GOLDENS",
        }
    }

    /// Create diagnostics helper for React compilation golden tests.
    #[allow(dead_code)]
    pub fn react() -> Self {
        Self {
            framework_name: "React golden",
            regen_env_var: "UPDATE_GOLDENS",
        }
    }

    /// Create diagnostics helper for policy theorem compiler golden tests.
    #[allow(dead_code)]
    pub fn policy() -> Self {
        Self {
            framework_name: "Policy golden",
            regen_env_var: "UPDATE_GOLDENS",
        }
    }

    /// Assert that actual content matches golden fixture with helpful diagnostics.
    ///
    /// # Arguments
    /// - `actual`: Current test output content
    /// - `fixture_path`: Path to golden fixture file
    /// - `test_name`: Test case name for error context
    /// - `hint`: Optional hint about what content represents
    pub fn assert_golden_match(
        &self,
        actual: &str,
        fixture_path: &Path,
        test_name: &str,
        hint: Option<&str>,
    ) {
        // Check if regeneration is requested
        if std::env::var(self.regen_env_var).is_ok() {
            self.save_fixture(actual, fixture_path, test_name);
            return;
        }

        // Load existing fixture
        let expected = match fs::read_to_string(fixture_path) {
            Ok(content) => content,
            Err(_) => {
                self.panic_missing_fixture(fixture_path, test_name, hint);
            }
        };

        // Compare content
        if actual == expected {
            // Sweep any stale .actual sibling left by a prior failing run so the
            // working tree stays tidy once the test goes green again (bd-ub6x8.7).
            let _ = fs::remove_file(fixture_path.with_extension("actual"));
            return; // Test passes
        }

        // Handle mismatch with helpful diagnostics
        self.handle_mismatch(actual, &expected, fixture_path, test_name, hint);
    }

    /// Save fixture content to file with proper error handling.
    fn save_fixture(&self, content: &str, fixture_path: &Path, test_name: &str) {
        if let Some(parent) = fixture_path.parent() {
            fs::create_dir_all(parent).unwrap_or_else(|e| {
                panic!(
                    "{} fixture directory creation failed for {}: {}\nPath: {}",
                    self.framework_name,
                    test_name,
                    e,
                    parent.display()
                );
            });
        }

        fs::write(fixture_path, content).unwrap_or_else(|e| {
            panic!(
                "{} fixture save failed for {}: {}\nPath: {}",
                self.framework_name,
                test_name,
                e,
                fixture_path.display()
            );
        });

        eprintln!(
            "✅ Generated {} fixture: {}",
            self.framework_name, test_name
        );
    }

    /// Panic with helpful message for missing fixture.
    fn panic_missing_fixture(&self, fixture_path: &Path, test_name: &str, hint: Option<&str>) -> ! {
        let hint_msg = hint
            .map(|h| format!("\nContent: {}", h))
            .unwrap_or_default();

        panic!(
            "\n🔍 {} FIXTURE MISSING: {}\n\
             \n📁 Expected path: {}\
             {}\n\
             \n💡 To generate fixture:\n\
             \n   {}=1 cargo test {} -- --nocapture\n\
             \n   Then review the generated fixture and commit it.\n",
            self.framework_name,
            test_name,
            fixture_path.display(),
            hint_msg,
            self.regen_env_var,
            test_name
        );
    }

    /// Handle content mismatch with smart diff presentation.
    fn handle_mismatch(
        &self,
        actual: &str,
        expected: &str,
        fixture_path: &Path,
        test_name: &str,
        hint: Option<&str>,
    ) -> ! {
        // Write actual output to file for easy comparison
        let actual_path = fixture_path.with_extension("actual");
        if let Err(e) = fs::write(&actual_path, actual) {
            eprintln!("⚠️  Warning: Could not write actual output file: {}", e);
        }

        let hint_msg = hint
            .map(|h| format!("\nContent: {}", h))
            .unwrap_or_default();

        // Prepare smart diff
        let diff_summary = self.format_smart_diff(actual, expected);

        panic!(
            "\n❌ {} MISMATCH: {}\
             {}\n\
             \n📁 Expected: {}\
             \n📄 Actual:   {}\n\
             \n📊 Diff summary:\n{}\n\
             \n💡 To update fixture:\n\
             \n   {}=1 cargo test {} -- --nocapture\n\
             \n🔧 To compare files:\n\
             \n   diff {} {}\n",
            self.framework_name,
            test_name,
            hint_msg,
            fixture_path.display(),
            actual_path.display(),
            diff_summary,
            self.regen_env_var,
            test_name,
            fixture_path.display(),
            actual_path.display()
        );
    }

    /// Format smart diff with truncation and line context.
    fn format_smart_diff(&self, actual: &str, expected: &str) -> String {
        let actual_lines: Vec<&str> = actual.lines().collect();
        let expected_lines: Vec<&str> = expected.lines().collect();

        // Quick summary stats
        let mut summary = format!(
            "   Lines: expected={}, actual={}\n",
            expected_lines.len(),
            actual_lines.len()
        );

        // Find first and last differing lines
        let mut first_diff: Option<usize> = None;
        let mut last_diff: Option<usize> = None;
        let max_lines = actual_lines.len().max(expected_lines.len());

        for i in 0..max_lines {
            let actual_line = actual_lines.get(i).unwrap_or(&"");
            let expected_line = expected_lines.get(i).unwrap_or(&"");

            if actual_line != expected_line {
                if first_diff.is_none() {
                    first_diff = Some(i);
                }
                last_diff = Some(i);
            }
        }

        match first_diff {
            None => {
                summary.push_str("   No line differences found (whitespace/encoding issue?)\n");
            }
            Some(first) => {
                let last = last_diff.unwrap_or(first);
                let diff_span = last - first + 1;

                summary.push_str(&format!(
                    "   First diff: line {}, Last diff: line {}, Span: {} lines\n",
                    first + 1,
                    last + 1,
                    diff_span
                ));

                // Show context around first difference
                if diff_span <= MAX_DIFF_LINES {
                    summary.push_str(&self.format_diff_context(
                        &actual_lines,
                        &expected_lines,
                        first,
                        last,
                    ));
                } else {
                    summary.push_str(&format!(
                        "   Diff too large ({} lines), showing first {} and last {} lines:\n",
                        diff_span, DIFF_CONTEXT_LINES, DIFF_CONTEXT_LINES
                    ));
                    summary.push_str(&self.format_diff_context(
                        &actual_lines,
                        &expected_lines,
                        first,
                        first + DIFF_CONTEXT_LINES - 1,
                    ));
                    summary.push_str("   ... (truncated) ...\n");
                    summary.push_str(&self.format_diff_context(
                        &actual_lines,
                        &expected_lines,
                        last - DIFF_CONTEXT_LINES + 1,
                        last,
                    ));
                }
            }
        }

        summary
    }

    /// Format diff context around specific line range.
    fn format_diff_context(
        &self,
        actual_lines: &[&str],
        expected_lines: &[&str],
        start: usize,
        end: usize,
    ) -> String {
        let mut context = String::new();

        for i in start..=end {
            let line_num = i + 1;
            let actual_line = actual_lines.get(i).unwrap_or(&"<missing>");
            let expected_line = expected_lines.get(i).unwrap_or(&"<missing>");

            if actual_line != expected_line {
                context.push_str(&format!("   {:3}: - {}\n", line_num, expected_line));
                context.push_str(&format!("   {:3}: + {}\n", line_num, actual_line));
            } else {
                context.push_str(&format!("   {:3}:   {}\n", line_num, actual_line));
            }
        }

        context
    }
}
