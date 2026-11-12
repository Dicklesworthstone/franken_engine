#![forbid(unsafe_code)]

//! Test262 Real Conformance Harness
//!
//! Bead: bd-24pou - implements actual Test262 test suite integration.
//!
//! This module provides integration with the official tc39/test262 test suite,
//! replacing the fake fixture-only approach with real differential testing.
//!
//! Workflow:
//! 1. Download Test262 suite from tc39/test262 at pinned commit
//! 2. Parse .js test files and extract metadata
//! 3. Filter tests based on ES2020 profile (include/exclude patterns)
//! 4. Convert to case vectors for franken_test262_runner
//! 5. Execute via existing Test262 gate infrastructure

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::test262_release_gate::{ProfileDecision, Test262PinSet, Test262Profile};
use serde::{Deserialize, Serialize};

/// Test262 test metadata extracted from test file frontmatter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Test262TestCase {
    /// Test file path relative to Test262 repo root (e.g., "language/expressions/arrow.js")
    pub file_path: String,

    /// ES2020 specification clause reference
    pub es_clause: String,

    /// Test description from frontmatter
    pub description: String,

    /// JavaScript source code (without frontmatter)
    pub source: String,

    /// Expected test outcome
    pub expected_outcome: Test262ExpectedOutcome,

    /// Test features required (from frontmatter)
    pub features: Vec<String>,

    /// Test flags (from frontmatter)
    pub flags: Vec<String>,

    /// Test includes (harness files required)
    pub includes: Vec<String>,

    /// Negative test details if applicable
    pub negative: Option<Test262Negative>,
}

/// Expected outcome for a Test262 test case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Test262ExpectedOutcome {
    /// Test should execute successfully and produce some result
    Pass,
    /// Test should throw a specific error type
    ThrowError { error_type: String },
    /// Test contains early syntax error and should not parse
    ParseError,
}

/// Negative test configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Test262Negative {
    /// Expected error phase (parse, early, runtime, etc.)
    pub phase: String,
    /// Expected error type (SyntaxError, ReferenceError, etc.)
    pub error_type: String,
}

/// Test262 case vector for franken_test262_runner execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Test262CaseVector {
    pub test_id: String,
    pub es2020_clause: String,
    pub source: String,
    pub expected_value: String,
    #[serde(default)]
    pub runtime_lane: String,
    #[serde(default)]
    pub deterministic_seed: u64,
}

/// Test262 suite integration manager.
pub struct Test262Harness {
    /// Path to Test262 repository clone
    test262_path: PathBuf,
    /// Pinned commit configuration
    pins: Test262PinSet,
    /// Test selection profile
    profile: Test262Profile,
}

impl Test262Harness {
    /// Create new harness with Test262 repo path and configuration.
    pub fn new(test262_path: PathBuf, pins: Test262PinSet, profile: Test262Profile) -> Self {
        Self {
            test262_path,
            pins,
            profile,
        }
    }

    /// Download Test262 suite to specified path if not already present.
    pub fn ensure_test262_suite(&self) -> Result<(), Test262HarnessError> {
        if self.test262_path.exists() {
            // Verify it's at the right commit
            self.verify_commit()?;
            return Ok(());
        }

        // Clone Test262 repository
        self.clone_test262()?;
        self.checkout_pinned_commit()?;

        Ok(())
    }

    /// Extract all Test262 test cases matching the profile.
    pub fn extract_test_cases(&self) -> Result<Vec<Test262TestCase>, Test262HarnessError> {
        self.ensure_test262_suite()?;

        let mut test_cases = Vec::new();

        // Walk through test directory structure
        self.walk_test_directory(&self.test262_path.join("test"), &mut test_cases)?;

        // Filter by profile include/exclude patterns
        let mut filtered: Vec<Test262TestCase> = test_cases
            .into_iter()
            .filter(|test| {
                // `*_FIXTURE.js` files are helper modules imported by real tests, not
                // tests themselves (they carry no frontmatter); never run them.
                if test.file_path.ends_with("_FIXTURE.js") {
                    return false;
                }
                let decision = self.profile.classify(&test.file_path);
                matches!(decision, ProfileDecision::Included)
            })
            .collect();

        // `fs::read_dir` order is platform-dependent, so sort by the (test/-relative)
        // path to make extraction — and any `truncate`-based sampling on top of it —
        // deterministic and reproducible across hosts.
        filtered.sort_by(|a, b| a.file_path.cmp(&b.file_path));

        Ok(filtered)
    }

    /// Convert Test262 test cases to case vectors for franken_test262_runner.
    ///
    /// Per the official Test262 runner specification, non-`raw`, non-`module`
    /// tests without `onlyStrict` or `noStrict` execute in BOTH sloppy mode and
    /// `"use strict"` mode (`#strict` vector suffix).
    pub fn generate_case_vectors(&self, test_cases: &[Test262TestCase]) -> Vec<Test262CaseVector> {
        let mut vectors = Vec::with_capacity(test_cases.len() * 2);
        for test in test_cases {
            vectors.extend(self.test_case_to_vectors(test));
        }
        vectors
    }

    /// Write case vectors to JSONL file for franken_test262_runner.
    pub fn write_case_vectors(
        &self,
        case_vectors: &[Test262CaseVector],
        output_path: &Path,
    ) -> Result<(), Test262HarnessError> {
        let mut jsonl_lines = Vec::new();

        for vector in case_vectors {
            let json = serde_json::to_string(vector)
                .map_err(|e| Test262HarnessError::SerializationError(e.to_string()))?;
            jsonl_lines.push(json);
        }

        fs::write(output_path, jsonl_lines.join("\n"))
            .map_err(|e| Test262HarnessError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Clone Test262 repository from GitHub.
    fn clone_test262(&self) -> Result<(), Test262HarnessError> {
        let output = Command::new("git")
            .args([
                "clone",
                "--depth=1", // Shallow clone for speed
                "https://github.com/tc39/test262.git",
                &self.test262_path.to_string_lossy(),
            ])
            .output()
            .map_err(|e| Test262HarnessError::GitError(e.to_string()))?;

        if !output.status.success() {
            return Err(Test262HarnessError::GitError(format!(
                "git clone failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    /// Checkout pinned commit specified in pins configuration.
    fn checkout_pinned_commit(&self) -> Result<(), Test262HarnessError> {
        let output = Command::new("git")
            .args(["checkout", &self.pins.test262_commit])
            .current_dir(&self.test262_path)
            .output()
            .map_err(|e| Test262HarnessError::GitError(e.to_string()))?;

        if !output.status.success() {
            return Err(Test262HarnessError::GitError(format!(
                "git checkout {} failed: {}",
                self.pins.test262_commit,
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    /// Verify repository is at the correct pinned commit.
    fn verify_commit(&self) -> Result<(), Test262HarnessError> {
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&self.test262_path)
            .output()
            .map_err(|e| Test262HarnessError::GitError(e.to_string()))?;

        if !output.status.success() {
            return Err(Test262HarnessError::GitError(
                "Failed to get current commit".to_string(),
            ));
        }

        let current_commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if current_commit != self.pins.test262_commit {
            return Err(Test262HarnessError::CommitMismatch {
                expected: self.pins.test262_commit.clone(),
                actual: current_commit,
            });
        }

        Ok(())
    }

    /// Recursively walk Test262 test directory and parse .js files.
    fn walk_test_directory(
        &self,
        dir: &Path,
        test_cases: &mut Vec<Test262TestCase>,
    ) -> Result<(), Test262HarnessError> {
        let entries = fs::read_dir(dir).map_err(|e| Test262HarnessError::IoError(e.to_string()))?;

        for entry in entries {
            let entry = entry.map_err(|e| Test262HarnessError::IoError(e.to_string()))?;
            let path = entry.path();

            if path.is_dir() {
                // Recurse into subdirectories
                self.walk_test_directory(&path, test_cases)?;
            } else if path.extension().and_then(|s| s.to_str()) == Some("js") {
                // Parse JavaScript test file
                if let Ok(test_case) = self.parse_test_file(&path) {
                    test_cases.push(test_case);
                }
            }
        }

        Ok(())
    }

    /// Parse a single Test262 .js test file.
    fn parse_test_file(&self, file_path: &Path) -> Result<Test262TestCase, Test262HarnessError> {
        let content = fs::read_to_string(file_path)
            .map_err(|e| Test262HarnessError::IoError(e.to_string()))?;

        // Extract the path relative to the Test262 `test/` directory, so it matches
        // the profile include/exclude patterns (`language/*`, `built-ins/*`) and the
        // canonical case-vector `test_id` format (e.g. "language/expressions/arrow.js").
        // The profile and the `test_id`s are relative to `test/`, not the repo root,
        // so a bare `strip_prefix(repo_root)` would leave a `test/` segment that
        // matches no include pattern and silently classifies every real case as
        // NotSelected (the bug that made the real corpus yield zero vectors).
        let from_repo_root = file_path.strip_prefix(&self.test262_path).map_err(|_| {
            Test262HarnessError::PathError("Test file not under Test262 repo".to_string())
        })?;
        let relative_path = from_repo_root
            .strip_prefix("test")
            .unwrap_or(from_repo_root)
            .to_string_lossy()
            .to_string();

        // Parse frontmatter and source
        let (frontmatter, source) = self.split_frontmatter(&content)?;
        let metadata = self.parse_frontmatter(&frontmatter)?;

        Ok(Test262TestCase {
            file_path: relative_path,
            es_clause: metadata
                .get("esid")
                .or_else(|| metadata.get("es6id"))
                .or_else(|| metadata.get("es5id"))
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
            description: metadata.get("description").cloned().unwrap_or_default(),
            source,
            expected_outcome: self.determine_expected_outcome(&metadata),
            features: self.parse_list_field(&metadata, "features"),
            flags: self.parse_list_field(&metadata, "flags"),
            includes: self.parse_list_field(&metadata, "includes"),
            negative: self.parse_negative_field(&metadata),
        })
    }

    /// Split Test262 file into frontmatter and source code.
    fn split_frontmatter(&self, content: &str) -> Result<(String, String), Test262HarnessError> {
        // The Test262 frontmatter is a `/*--- … ---*/` block near the top of the
        // file. Real suite files prefix it with a copyright/license comment block
        // (e.g. `// Copyright … `), so the marker is NOT at byte 0 — a
        // `starts_with` check rejects essentially the entire real corpus (the bug
        // that, together with the `test/`-prefix path issue, made the live suite
        // yield zero vectors). Locate the opening marker wherever it sits.
        const OPEN: &str = "/*---";
        const CLOSE: &str = "---*/";

        let open_offset = content.find(OPEN).ok_or_else(|| {
            Test262HarnessError::ParseError("Missing Test262 frontmatter".to_string())
        })?;

        // Search for the closing marker AFTER the opening one. Otherwise inputs
        // like "/*-----*/" hit a `---*/` substring that overlaps with `/*---`
        // and produce a frontmatter slice with start > end (panic on indexing).
        let after_open = &content[open_offset + OPEN.len()..];
        let close_offset = after_open
            .find(CLOSE)
            .ok_or_else(|| Test262HarnessError::ParseError("Malformed frontmatter".to_string()))?;

        let frontmatter = after_open[..close_offset].to_string();
        // The executable test body is everything after the closing marker. The
        // pre-frontmatter license block is comments only, so dropping it does not
        // change execution semantics.
        let source = after_open[close_offset + CLOSE.len()..].to_string();

        Ok((frontmatter, source))
    }

    /// Parse YAML-like Test262 frontmatter (supporting inline scalars/lists/maps,
    /// indented block mappings like `negative:\n  phase: parse\n  type: SyntaxError`,
    /// and indented `- item` block sequences for `includes`/`flags`/`features`).
    fn parse_frontmatter(
        &self,
        frontmatter: &str,
    ) -> Result<BTreeMap<String, String>, Test262HarnessError> {
        let mut metadata: BTreeMap<String, String> = BTreeMap::new();
        let mut current_section: Option<String> = None;

        for raw_line in frontmatter.lines() {
            let trimmed = raw_line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let indent = raw_line.len() - raw_line.trim_start().len();

            if indent > 0
                && let Some(section) = current_section.as_deref()
            {
                if let Some(item) = trimmed.strip_prefix('-') {
                    let item = item.trim().trim_matches(|c| c == '"' || c == '\'');
                    if !item.is_empty() {
                        let entry = metadata.entry(section.to_string()).or_default();
                        if !entry.is_empty() {
                            entry.push_str(", ");
                        }
                        entry.push_str(item);
                    }
                    continue;
                }
                if let Some((sub_key, sub_val)) = trimmed.split_once(':') {
                    let sub_key = sub_key.trim();
                    let sub_val = sub_val.trim().trim_matches(|c| c == '"' || c == '\'');
                    if section == "negative" {
                        metadata.insert(format!("negative.{sub_key}"), sub_val.to_string());
                        metadata
                            .entry("negative".to_string())
                            .or_insert_with(|| "present".to_string());
                        continue;
                    }
                }
                if matches!(section, "description" | "info") {
                    let entry = metadata.entry(section.to_string()).or_default();
                    if !entry.is_empty() {
                        entry.push(' ');
                    }
                    entry.push_str(trimmed);
                    continue;
                }
            }

            if let Some((key, value)) = trimmed.split_once(':') {
                let key = key.trim().to_string();
                let value = value.trim();
                if value.is_empty()
                    || value == ">"
                    || value == "|"
                    || value == ">-"
                    || value == "|-"
                {
                    current_section = Some(key.clone());
                    metadata.entry(key).or_default();
                } else {
                    current_section = None;
                    if key == "negative" && value.starts_with('{') && value.ends_with('}') {
                        let inner = &value[1..value.len() - 1];
                        for pair in inner.split(',') {
                            if let Some((k, v)) = pair.split_once(':') {
                                metadata.insert(
                                    format!("negative.{}", k.trim()),
                                    v.trim().trim_matches(|c| c == '"' || c == '\'').to_string(),
                                );
                            }
                        }
                    }
                    metadata.insert(
                        key,
                        value.trim_matches(|c| c == '"' || c == '\'').to_string(),
                    );
                }
            }
        }

        Ok(metadata)
    }

    /// Parse list fields like features, flags, includes.
    fn parse_list_field(&self, metadata: &BTreeMap<String, String>, field: &str) -> Vec<String> {
        metadata
            .get(field)
            .map(|s| {
                s.trim_matches(|c| c == '[' || c == ']')
                    .split(',')
                    .map(|item| {
                        item.trim()
                            .trim_matches(|c| c == '"' || c == '\'')
                            .to_string()
                    })
                    .filter(|item| !item.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Parse negative test configuration.
    fn parse_negative_field(&self, metadata: &BTreeMap<String, String>) -> Option<Test262Negative> {
        if let (Some(phase), Some(error_type)) = (
            metadata.get("negative.phase"),
            metadata.get("negative.type"),
        ) && !phase.is_empty()
            && !error_type.is_empty()
        {
            return Some(Test262Negative {
                phase: phase.clone(),
                error_type: error_type.clone(),
            });
        }
        None
    }

    /// Determine expected test outcome from metadata.
    fn determine_expected_outcome(
        &self,
        metadata: &BTreeMap<String, String>,
    ) -> Test262ExpectedOutcome {
        if let Some(neg) = self.parse_negative_field(metadata) {
            if matches!(neg.phase.as_str(), "parse" | "early") {
                Test262ExpectedOutcome::ParseError
            } else {
                Test262ExpectedOutcome::ThrowError {
                    error_type: neg.error_type,
                }
            }
        } else if metadata
            .get("flags")
            .is_some_and(|flags| flags.split(',').any(|f| f.trim() == "early"))
        {
            Test262ExpectedOutcome::ParseError
        } else {
            Test262ExpectedOutcome::Pass
        }
    }

    fn build_harness_prelude(&self, test: &Test262TestCase) -> String {
        if test.flags.iter().any(|f| f == "raw") {
            return String::new();
        }
        const HOST_262_PRELUDE: &str = r#"var $262 = {
  global: globalThis,
  createRealm: function() { return $262; },
  detachArrayBuffer: function() {},
  gc: function() {},
  evalScript: function(code) { return eval(code); }
};
"#;
        const FALLBACK_ASSERT_STA: &str = r#"function Test262Error(message) {
  this.name = "Test262Error";
  this.message = message === undefined ? "" : String(message);
}
Test262Error.prototype.toString = function() {
  return "Test262Error: " + this.message;
};
Test262Error.thrower = function(message) {
  throw new Test262Error(message);
};
function $ERROR(message) {
  throw new Test262Error(message);
}
function $DONOTEVALUATE() {
  throw "Test262: This statement should not be evaluated.";
}
function assert(mustBeTrue, message) {
  if (mustBeTrue === true) {
    return;
  }
  throw new Test262Error(message === undefined ? "Expected true but got " + String(mustBeTrue) : message);
}
assert._isSameValue = function(a, b) {
  if (a === b) {
    return a !== 0 || 1 / a === 1 / b;
  }
  return a !== a && b !== b;
};
assert.sameValue = function(actual, expected, message) {
  if (assert._isSameValue(actual, expected)) {
    return;
  }
  throw new Test262Error((message ? message + " " : "") + "Expected SameValue(" + String(actual) + ", " + String(expected) + ") to be true");
};
assert.notSameValue = function(actual, unexpected, message) {
  if (!assert._isSameValue(actual, unexpected)) {
    return;
  }
  throw new Test262Error((message ? message + " " : "") + "Expected SameValue(" + String(actual) + ", " + String(unexpected) + ") to be false");
};
assert.throws = function(expectedErrorConstructor, func, message) {
  if (typeof func !== "function") {
    throw new Test262Error("assert.throws requires a function");
  }
  var thrown = false;
  try {
    func();
  } catch (err) {
    thrown = true;
    if (typeof err !== "object" || err === null) {
      throw new Test262Error((message ? message + " " : "") + "Thrown value was not an object");
    }
    if (err.constructor !== expectedErrorConstructor && !(err instanceof expectedErrorConstructor)) {
      throw new Test262Error((message ? message + " " : "") + "Unexpected error constructor");
    }
    return;
  }
  if (!thrown) {
    throw new Test262Error((message ? message + " " : "") + "Expected function to throw");
  }
};
"#;
        let mut prelude = String::from(HOST_262_PRELUDE);
        let harness_dir = self.test262_path.join("harness");
        let sta_path = harness_dir.join("sta.js");
        let assert_path = harness_dir.join("assert.js");
        if let (Ok(sta), Ok(assert_js)) = (
            fs::read_to_string(&sta_path),
            fs::read_to_string(&assert_path),
        ) {
            prelude.push_str(&sta);
            prelude.push('\n');
            prelude.push_str(&assert_js);
            prelude.push('\n');
        } else {
            prelude.push_str(FALLBACK_ASSERT_STA);
        }
        for include in &test.includes {
            if matches!(include.as_str(), "sta.js" | "assert.js") {
                continue;
            }
            let include_path = harness_dir.join(include);
            if let Ok(helper_src) = fs::read_to_string(&include_path) {
                prelude.push_str(&helper_src);
                prelude.push('\n');
            }
        }
        prelude
    }

    fn expected_value_for_case(&self, test: &Test262TestCase) -> String {
        if let Some(neg) = &test.negative {
            return format!("NEGATIVE:{}:{}", neg.phase, neg.error_type);
        }
        match &test.expected_outcome {
            Test262ExpectedOutcome::Pass => "TEST262_PASS".to_string(),
            Test262ExpectedOutcome::ThrowError { error_type } => format!("THROW:{error_type}"),
            Test262ExpectedOutcome::ParseError => "PARSE_ERROR".to_string(),
        }
    }

    fn deterministic_seed_for_id(test_id: &str) -> u64 {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in test_id.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        hash
    }

    /// Convert a `Test262TestCase` into its sloppy and/or strict `Test262CaseVector`s.
    fn test_case_to_vectors(&self, test: &Test262TestCase) -> Vec<Test262CaseVector> {
        if test.source.trim().is_empty() {
            return Vec::new();
        }
        let expected_value = self.expected_value_for_case(test);
        let prelude = self.build_harness_prelude(test);
        let has_flag = |flag: &str| test.flags.iter().any(|f| f == flag);
        let is_raw = has_flag("raw");
        let is_module = has_flag("module");
        let only_strict = has_flag("onlyStrict");
        let no_strict = has_flag("noStrict");

        let compose_source = |strict_prefix: bool| -> String {
            let mut out = String::with_capacity(prelude.len() + test.source.len() + 20);
            if strict_prefix {
                out.push_str("\"use strict\";\n");
            }
            out.push_str(&prelude);
            out.push_str(&test.source);
            out
        };

        if is_raw || is_module || no_strict {
            let id = test.file_path.clone();
            vec![Test262CaseVector {
                deterministic_seed: Self::deterministic_seed_for_id(&id),
                test_id: id,
                es2020_clause: test.es_clause.clone(),
                source: compose_source(false),
                expected_value,
                runtime_lane: "hybrid".to_string(),
            }]
        } else if only_strict {
            let id = test.file_path.clone();
            vec![Test262CaseVector {
                deterministic_seed: Self::deterministic_seed_for_id(&id),
                test_id: id,
                es2020_clause: test.es_clause.clone(),
                source: compose_source(true),
                expected_value,
                runtime_lane: "hybrid".to_string(),
            }]
        } else {
            let sloppy_id = test.file_path.clone();
            let strict_id = format!("{}#strict", test.file_path);
            vec![
                Test262CaseVector {
                    deterministic_seed: Self::deterministic_seed_for_id(&sloppy_id),
                    test_id: sloppy_id,
                    es2020_clause: test.es_clause.clone(),
                    source: compose_source(false),
                    expected_value: expected_value.clone(),
                    runtime_lane: "hybrid".to_string(),
                },
                Test262CaseVector {
                    deterministic_seed: Self::deterministic_seed_for_id(&strict_id),
                    test_id: strict_id,
                    es2020_clause: test.es_clause.clone(),
                    source: compose_source(true),
                    expected_value,
                    runtime_lane: "hybrid".to_string(),
                },
            ]
        }
    }
}

/// Error types for Test262 harness operations.
#[derive(Debug, thiserror::Error)]
pub enum Test262HarnessError {
    #[error("I/O error: {0}")]
    IoError(String),

    #[error("Git operation failed: {0}")]
    GitError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Path error: {0}")]
    PathError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Commit mismatch: expected {expected}, got {actual}")]
    CommitMismatch { expected: String, actual: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn harness() -> Test262Harness {
        // Path/pins/profile are unused by split_frontmatter; placeholder values
        // are sufficient for these focused tests.
        let pins = Test262PinSet {
            schema_version: "test262.pinset.v1".to_string(),
            source_repo: "https://github.com/tc39/test262.git".to_string(),
            es_profile: "ES2020".to_string(),
            test262_commit: "0".repeat(40),
        };
        let profile = Test262Profile {
            schema_version: "test262.profile.v1".to_string(),
            profile_name: "placeholder".to_string(),
            es_profile: "ES2020".to_string(),
            includes: Vec::new(),
            excludes: Vec::new(),
        };
        Test262Harness::new(PathBuf::from("/tmp/test262-placeholder"), pins, profile)
    }

    #[test]
    fn split_frontmatter_extracts_metadata_and_source() {
        let h = harness();
        let content = "/*---\nesid: sec-test\ndescription: example\n---*/\nconst answer = 42;\n";
        let (front, source) = h
            .split_frontmatter(content)
            .expect("well-formed frontmatter splits cleanly");
        assert!(front.contains("esid: sec-test"));
        assert!(front.contains("description: example"));
        assert_eq!(source, "\nconst answer = 42;\n");
    }

    #[test]
    fn split_frontmatter_finds_marker_after_leading_license_comment() {
        // Regression for CEI D.2 (bd-sde5e.4.2): real tc39/test262 files begin with
        // a `// Copyright …` license block *before* the `/*--- … ---*/` frontmatter,
        // so a `starts_with` check rejected essentially the entire real corpus
        // (zero extracted vectors). The marker must be located wherever it sits.
        let h = harness();
        let content = "// Copyright 2009 the Sputnik authors. All rights reserved.\n\
                       // This code is governed by the BSD license.\n\n\
                       /*---\nesid: 11.6.1\ndescription: real-style header\n---*/\n\
                       if (true + true !== 2) { throw new Error(); }\n";
        let (front, source) = h
            .split_frontmatter(content)
            .expect("marker after a leading comment block must still split");
        assert!(front.contains("esid: 11.6.1"));
        assert!(source.contains("if (true + true !== 2)"));
        // The pre-frontmatter license comments are dropped (comments only).
        assert!(!source.contains("Copyright"));
    }

    #[test]
    fn split_frontmatter_rejects_missing_open_marker() {
        let h = harness();
        assert!(matches!(
            h.split_frontmatter("// no frontmatter here\nconst x = 1;"),
            Err(Test262HarnessError::ParseError(_))
        ));
    }

    #[test]
    fn split_frontmatter_rejects_unterminated_frontmatter() {
        let h = harness();
        assert!(matches!(
            h.split_frontmatter("/*--- esid: sec-test"),
            Err(Test262HarnessError::ParseError(_))
        ));
    }

    #[test]
    fn split_frontmatter_does_not_panic_on_overlapping_markers() {
        // Regression: "/*-----*/" starts with "/*---" AND contains "---*/"
        // beginning at byte offset 4 (overlapping the opener). The previous
        // implementation produced `content[5..4]` and panicked. The fix must
        // either return Ok with a valid split or Err — but never panic.
        // For this input there is no valid closing marker after the opener
        // (the remainder is just "--*/"), so a ParseError is the correct
        // outcome.
        let h = harness();
        let result = h.split_frontmatter("/*-----*/");
        assert!(
            matches!(result, Err(Test262HarnessError::ParseError(_))),
            "expected ParseError for malformed overlapping marker, got {result:?}",
        );
    }

    #[test]
    fn split_frontmatter_handles_minimal_well_formed_block() {
        let h = harness();
        let (front, source) = h
            .split_frontmatter("/*------*/")
            .expect("minimal block should split");
        // Body between the two markers is empty.
        assert_eq!(front, "");
        assert_eq!(source, "");
    }

    #[test]
    fn parse_frontmatter_handles_multiline_negative_lists_and_dual_strict_vectors() {
        let h = harness();
        let front = "\
es6id: 13.3.1.1
description: >
  multiline
  description
includes:
  - propertyHelper.js
  - compareArray.js
flags:
  - noStrict
negative:
  phase: parse
  type: SyntaxError
";
        let meta = h.parse_frontmatter(front).expect("frontmatter parses");
        assert_eq!(meta.get("es6id").map(String::as_str), Some("13.3.1.1"));
        assert_eq!(
            h.parse_list_field(&meta, "includes"),
            vec![
                "propertyHelper.js".to_string(),
                "compareArray.js".to_string()
            ]
        );
        assert_eq!(
            h.parse_negative_field(&meta),
            Some(Test262Negative {
                phase: "parse".to_string(),
                error_type: "SyntaxError".to_string(),
            })
        );

        let pos_case = Test262TestCase {
            file_path: "language/expressions/addition/basic.js".to_string(),
            es_clause: "12.8.3".to_string(),
            description: "basic".to_string(),
            source: "assert.sameValue(1 + 2, 3);".to_string(),
            expected_outcome: Test262ExpectedOutcome::Pass,
            features: Vec::new(),
            flags: Vec::new(),
            includes: Vec::new(),
            negative: None,
        };
        let vectors = h.generate_case_vectors(&[pos_case]);
        assert_eq!(vectors.len(), 2);
        assert_eq!(vectors[0].test_id, "language/expressions/addition/basic.js");
        assert_eq!(vectors[0].expected_value, "TEST262_PASS");
        assert!(!vectors[0].source.starts_with("\"use strict\";"));
        assert!(vectors[0].source.contains("assert.sameValue"));
        assert_eq!(
            vectors[1].test_id,
            "language/expressions/addition/basic.js#strict"
        );
        assert!(vectors[1].source.starts_with("\"use strict\";\n"));
    }
}
