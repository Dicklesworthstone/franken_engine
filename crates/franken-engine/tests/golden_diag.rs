//! Golden test diagnostics and error recovery utilities.
//!
//! Provides unified error handling, clear diagnostics, and helpful suggestions
//! for golden test frameworks across the codebase. Addresses common issues:
//! - Missing fixtures with clear instructions
//! - Overwhelming diff output with smart truncation
//! - Inconsistent environment variable handling
//! - Poor error context and recovery suggestions

#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

/// Maximum lines to show from start/end of diff before truncating.
const DIFF_CONTEXT_LINES: usize = 10;

/// Maximum total diff lines before truncating.
const MAX_DIFF_LINES: usize = 50;

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
