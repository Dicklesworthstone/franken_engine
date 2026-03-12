//! Fail-closed guardrails rejecting new production `control_plane::mocks` usage.
//!
//! Bead: bd-3nr.1.2.2 [10.13X.B2]
//!
//! This module enforces a fail-closed policy preventing any future
//! introduction of `control_plane::mocks` or equivalent fake-context
//! stand-ins in production (non-test) code paths.  It provides:
//!
//! - **Pattern registry**: known symbols and import patterns that
//!   indicate mock/fake usage.
//! - **Scope classifier**: determines whether a usage site is
//!   test-only or production.
//! - **Guard policy**: pass/fail decision with violation evidence.
//! - **Guard report**: deterministic, serde-able report with per-file
//!   verdicts and an aggregate gate decision.
//!
//! All collections use BTreeMap/BTreeSet for deterministic ordering.
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Dependencies: hash_tiers, security_epoch.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Component name for structured logging.
pub const COMPONENT: &str = "mock_seam_guardrail";

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.mock-seam-guardrail.v1";

/// Maximum patterns per category to avoid unbounded registration.
const MAX_PATTERNS_PER_CATEGORY: usize = 256;

/// Maximum files in a single guard sweep.
const MAX_FILES_PER_SWEEP: usize = 8192;

/// Maximum violations before early-abort.
const MAX_VIOLATIONS_BEFORE_ABORT: usize = 1024;

/// Fixed-point unit: 1_000_000 = 1.0 (100%).
#[allow(dead_code)]
const MILLION: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// PatternCategory
// ---------------------------------------------------------------------------

/// Category of forbidden pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternCategory {
    /// Direct import of `control_plane::mocks` module.
    MockModuleImport,
    /// Usage of `MockCx`, `MockBudget`, or similar mock context types.
    MockContextType,
    /// Seed-derived trace context (e.g., `trace_id_from_seed`).
    SeedDerivedTrace,
    /// Fake budget construction outside test harness.
    FakeBudget,
    /// Stub lifecycle or stub policy usage.
    StubLifecycle,
    /// Hardcoded sentinel values standing in for real contexts.
    HardcodedSentinel,
}

impl PatternCategory {
    /// All categories for exhaustive iteration.
    pub fn all() -> &'static [PatternCategory] {
        &[
            PatternCategory::MockModuleImport,
            PatternCategory::MockContextType,
            PatternCategory::SeedDerivedTrace,
            PatternCategory::FakeBudget,
            PatternCategory::StubLifecycle,
            PatternCategory::HardcodedSentinel,
        ]
    }

    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Self::MockModuleImport => "mock_module_import",
            Self::MockContextType => "mock_context_type",
            Self::SeedDerivedTrace => "seed_derived_trace",
            Self::FakeBudget => "fake_budget",
            Self::StubLifecycle => "stub_lifecycle",
            Self::HardcodedSentinel => "hardcoded_sentinel",
        }
    }
}

impl fmt::Display for PatternCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// ScopeClassification
// ---------------------------------------------------------------------------

/// Whether a code site is test-only or production.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeClassification {
    /// Inside `#[cfg(test)]`, a `tests/` directory, or behind a
    /// test-only feature gate — acceptable.
    TestOnly,
    /// Production code path — forbidden.
    Production,
    /// Could not classify (e.g., generated code).
    Unknown,
}

impl fmt::Display for ScopeClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TestOnly => write!(f, "test_only"),
            Self::Production => write!(f, "production"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// ForbiddenPattern
// ---------------------------------------------------------------------------

/// A registered forbidden pattern.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ForbiddenPattern {
    /// The literal string to match (substring match).
    pub needle: String,
    /// Category of the pattern.
    pub category: PatternCategory,
    /// Human-readable reason this pattern is forbidden.
    pub reason: String,
    /// Content hash of the pattern definition for audit trail.
    pub definition_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// PatternRegistry
// ---------------------------------------------------------------------------

/// Registry of forbidden patterns grouped by category.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PatternRegistry {
    /// Patterns indexed by category.
    pub patterns: BTreeMap<String, Vec<ForbiddenPattern>>,
    /// Total pattern count.
    pub total_count: usize,
    /// Registry content hash.
    pub registry_hash: ContentHash,
}

/// Build the default pattern registry with known mock-seam indicators.
pub fn build_default_registry() -> PatternRegistry {
    let mut patterns: BTreeMap<String, Vec<ForbiddenPattern>> = BTreeMap::new();

    let defaults = vec![
        (
            "control_plane::mocks",
            PatternCategory::MockModuleImport,
            "Direct import of mock module",
        ),
        (
            "use crate::control_plane::mocks",
            PatternCategory::MockModuleImport,
            "Crate-relative mock import",
        ),
        (
            "MockCx",
            PatternCategory::MockContextType,
            "Mock context type usage",
        ),
        (
            "MockBudget",
            PatternCategory::MockContextType,
            "Mock budget type usage",
        ),
        (
            "FakeCx",
            PatternCategory::MockContextType,
            "Fake context type usage",
        ),
        (
            "FakeBudget",
            PatternCategory::FakeBudget,
            "Fake budget construction",
        ),
        (
            "trace_id_from_seed",
            PatternCategory::SeedDerivedTrace,
            "Seed-derived trace context",
        ),
        (
            "StubLifecycle",
            PatternCategory::StubLifecycle,
            "Stub lifecycle stand-in",
        ),
        (
            "StubPolicy",
            PatternCategory::StubLifecycle,
            "Stub policy stand-in",
        ),
        (
            "MOCK_TRACE_ID",
            PatternCategory::HardcodedSentinel,
            "Hardcoded mock trace ID",
        ),
        (
            "FAKE_EPOCH",
            PatternCategory::HardcodedSentinel,
            "Hardcoded fake epoch sentinel",
        ),
        (
            "DUMMY_BUDGET",
            PatternCategory::HardcodedSentinel,
            "Hardcoded dummy budget sentinel",
        ),
    ];

    let mut total = 0usize;
    for (needle, category, reason) in defaults {
        let hash_input = format!("{category}:{needle}");
        let definition_hash = ContentHash::compute(hash_input.as_bytes());
        let pattern = ForbiddenPattern {
            needle: needle.to_string(),
            category,
            reason: reason.to_string(),
            definition_hash,
        };
        let key = category.label().to_string();
        patterns.entry(key).or_default().push(pattern);
        total += 1;
    }

    let registry_hash = compute_registry_hash(&patterns);

    PatternRegistry {
        patterns,
        total_count: total,
        registry_hash,
    }
}

/// Register a custom forbidden pattern.
pub fn register_pattern(
    registry: &mut PatternRegistry,
    needle: String,
    category: PatternCategory,
    reason: String,
) -> Result<(), GuardrailError> {
    if needle.is_empty() {
        return Err(GuardrailError::EmptyPattern);
    }
    let key = category.label().to_string();
    let existing = registry.patterns.entry(key).or_default();
    if existing.len() >= MAX_PATTERNS_PER_CATEGORY {
        return Err(GuardrailError::PatternLimitExceeded {
            category,
            limit: MAX_PATTERNS_PER_CATEGORY,
        });
    }
    // Check for duplicates.
    if existing.iter().any(|p| p.needle == needle) {
        return Err(GuardrailError::DuplicatePattern {
            needle: needle.clone(),
        });
    }
    let hash_input = format!("{category}:{needle}");
    let definition_hash = ContentHash::compute(hash_input.as_bytes());
    existing.push(ForbiddenPattern {
        needle,
        category,
        reason,
        definition_hash,
    });
    registry.total_count += 1;
    registry.registry_hash = compute_registry_hash(&registry.patterns);
    Ok(())
}

fn compute_registry_hash(patterns: &BTreeMap<String, Vec<ForbiddenPattern>>) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(b"mock-seam-guardrail-registry-v1");
    for (cat, pats) in patterns {
        hasher.update(cat.as_bytes());
        for p in pats {
            hasher.update(p.needle.as_bytes());
        }
    }
    let digest = hasher.finalize();
    ContentHash::compute(&digest)
}

// ---------------------------------------------------------------------------
// FileScanResult
// ---------------------------------------------------------------------------

/// A single match found during scanning.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PatternMatch {
    /// 1-based line number.
    pub line_number: u32,
    /// The matched needle.
    pub pattern_needle: String,
    /// Category of the matched pattern.
    pub category: PatternCategory,
    /// Scope classification of the match site.
    pub scope: ScopeClassification,
    /// Excerpt of the matching line (truncated to 200 chars).
    pub line_excerpt: String,
}

/// Scan result for a single file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FileScanResult {
    /// Relative file path.
    pub file_path: String,
    /// Content hash of the scanned file.
    pub file_hash: ContentHash,
    /// All matches found.
    pub matches: Vec<PatternMatch>,
    /// Number of production-scope violations.
    pub production_violation_count: usize,
    /// Number of test-only matches (informational).
    pub test_only_count: usize,
    /// Per-file verdict.
    pub verdict: FileVerdict,
}

/// Verdict for a single file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileVerdict {
    /// No forbidden patterns found.
    Clean,
    /// Forbidden patterns found only in test scope — allowed.
    TestOnlyUsage,
    /// Production violations found — fails the guard.
    ProductionViolation,
}

impl fmt::Display for FileVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => write!(f, "clean"),
            Self::TestOnlyUsage => write!(f, "test_only_usage"),
            Self::ProductionViolation => write!(f, "production_violation"),
        }
    }
}

// ---------------------------------------------------------------------------
// WaiverPolicy
// ---------------------------------------------------------------------------

/// A waiver that exempts specific files or patterns from the guard.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Waiver {
    /// Unique waiver identifier.
    pub waiver_id: String,
    /// File path glob or exact path being waived.
    pub file_pattern: String,
    /// Optional pattern needle being waived (None = all patterns).
    pub pattern_needle: Option<String>,
    /// Justification for the waiver.
    pub justification: String,
    /// Epoch when the waiver was granted.
    pub granted_epoch: SecurityEpoch,
    /// Optional expiry epoch after which the waiver is void.
    pub expiry_epoch: Option<SecurityEpoch>,
}

/// Waiver policy containing all active waivers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WaiverPolicy {
    /// Active waivers.
    pub waivers: Vec<Waiver>,
    /// Policy content hash.
    pub policy_hash: ContentHash,
}

/// Create an empty waiver policy.
pub fn empty_waiver_policy() -> WaiverPolicy {
    WaiverPolicy {
        waivers: Vec::new(),
        policy_hash: ContentHash::compute(b"empty-waiver-policy"),
    }
}

/// Add a waiver to the policy.
pub fn add_waiver(
    policy: &mut WaiverPolicy,
    waiver_id: String,
    file_pattern: String,
    pattern_needle: Option<String>,
    justification: String,
    granted_epoch: SecurityEpoch,
    expiry_epoch: Option<SecurityEpoch>,
) -> Result<(), GuardrailError> {
    if waiver_id.is_empty() {
        return Err(GuardrailError::EmptyWaiverId);
    }
    if policy.waivers.iter().any(|w| w.waiver_id == waiver_id) {
        return Err(GuardrailError::DuplicateWaiver {
            waiver_id: waiver_id.clone(),
        });
    }
    policy.waivers.push(Waiver {
        waiver_id,
        file_pattern,
        pattern_needle,
        justification,
        granted_epoch,
        expiry_epoch,
    });
    policy.policy_hash = compute_waiver_hash(&policy.waivers);
    Ok(())
}

/// Check whether a specific match is waived.
pub fn is_waived(
    policy: &WaiverPolicy,
    file_path: &str,
    pattern_needle: &str,
    current_epoch: SecurityEpoch,
) -> bool {
    policy.waivers.iter().any(|w| {
        // Check expiry.
        if let Some(exp) = w.expiry_epoch
            && current_epoch.as_u64() > exp.as_u64()
        {
            return false;
        }
        // Check file pattern (exact match or suffix match).
        let file_matches = file_path == w.file_pattern || file_path.ends_with(&w.file_pattern);
        if !file_matches {
            return false;
        }
        // Check pattern needle.
        match &w.pattern_needle {
            None => true,
            Some(pn) => pn == pattern_needle,
        }
    })
}

fn compute_waiver_hash(waivers: &[Waiver]) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(b"mock-seam-waiver-policy-v1");
    for w in waivers {
        hasher.update(w.waiver_id.as_bytes());
        hasher.update(w.file_pattern.as_bytes());
    }
    ContentHash::compute(&hasher.finalize())
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/// Classify a line's scope based on surrounding context indicators.
pub fn classify_scope(
    file_path: &str,
    line_content: &str,
    in_test_block: bool,
) -> ScopeClassification {
    // Files in tests/ directory are always test-only.
    if file_path.contains("/tests/") || file_path.starts_with("tests/") {
        return ScopeClassification::TestOnly;
    }
    // Lines inside #[cfg(test)] blocks.
    if in_test_block {
        return ScopeClassification::TestOnly;
    }
    // Lines that are comments or doc-comments are test-adjacent.
    let trimmed = line_content.trim();
    if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("//!") {
        return ScopeClassification::TestOnly;
    }
    ScopeClassification::Production
}

/// Scan a single file's content against the pattern registry.
pub fn scan_file_content(
    file_path: &str,
    content: &str,
    registry: &PatternRegistry,
    waiver_policy: &WaiverPolicy,
    current_epoch: SecurityEpoch,
) -> FileScanResult {
    let file_hash = ContentHash::compute(content.as_bytes());
    let mut matches = Vec::new();
    let mut production_count = 0usize;
    let mut test_only_count = 0usize;
    let mut in_test_block = false;

    let all_patterns: Vec<&ForbiddenPattern> =
        registry.patterns.values().flat_map(|v| v.iter()).collect();

    for (idx, line) in content.lines().enumerate() {
        let line_number = (idx + 1) as u32;

        // Track #[cfg(test)] blocks.
        let trimmed = line.trim();
        if trimmed == "#[cfg(test)]" {
            in_test_block = true;
        }
        // Rough heuristic: leaving test block when we hit a top-level
        // non-indented item after being in test mode.
        if in_test_block
            && !trimmed.is_empty()
            && !trimmed.starts_with(' ')
            && !trimmed.starts_with('\t')
            && (trimmed.starts_with("pub mod ")
                || trimmed.starts_with("pub fn ")
                || trimmed.starts_with("pub struct "))
            && !trimmed.contains("test")
        {
            in_test_block = false;
        }

        for pattern in &all_patterns {
            if line.contains(&pattern.needle) {
                let scope = classify_scope(file_path, line, in_test_block);

                // Check waiver.
                if is_waived(waiver_policy, file_path, &pattern.needle, current_epoch) {
                    continue;
                }

                let excerpt = if line.len() > 200 {
                    format!("{}...", &line[..197])
                } else {
                    line.to_string()
                };

                let m = PatternMatch {
                    line_number,
                    pattern_needle: pattern.needle.clone(),
                    category: pattern.category,
                    scope,
                    line_excerpt: excerpt,
                };

                match scope {
                    ScopeClassification::Production | ScopeClassification::Unknown => {
                        production_count += 1;
                    }
                    ScopeClassification::TestOnly => {
                        test_only_count += 1;
                    }
                }
                matches.push(m);
            }
        }
    }

    let verdict = if production_count > 0 {
        FileVerdict::ProductionViolation
    } else if test_only_count > 0 {
        FileVerdict::TestOnlyUsage
    } else {
        FileVerdict::Clean
    };

    FileScanResult {
        file_path: file_path.to_string(),
        file_hash,
        matches,
        production_violation_count: production_count,
        test_only_count,
        verdict,
    }
}

// ---------------------------------------------------------------------------
// GuardReport
// ---------------------------------------------------------------------------

/// Gate decision for the entire sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    /// All files clean or test-only — guard passes.
    Pass,
    /// Production violations found — guard fails (fail-closed).
    Fail,
    /// Sweep aborted due to too many violations.
    AbortedExcessViolations,
}

impl fmt::Display for GateDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Fail => write!(f, "fail"),
            Self::AbortedExcessViolations => write!(f, "aborted_excess_violations"),
        }
    }
}

/// Aggregate guard report for all scanned files.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GuardReport {
    /// Schema version.
    pub schema_version: String,
    /// Component name.
    pub component: String,
    /// Gate decision.
    pub decision: GateDecision,
    /// Total files scanned.
    pub files_scanned: usize,
    /// Files with production violations.
    pub files_with_violations: usize,
    /// Files with test-only usage.
    pub files_with_test_only: usize,
    /// Clean files.
    pub clean_files: usize,
    /// Total production violation count.
    pub total_production_violations: usize,
    /// Total test-only match count.
    pub total_test_only_matches: usize,
    /// Per-file results (only files with matches, for brevity).
    pub file_results: Vec<FileScanResult>,
    /// Registry used for the sweep.
    pub registry_hash: ContentHash,
    /// Waiver policy used.
    pub waiver_policy_hash: ContentHash,
    /// Epoch at sweep time.
    pub sweep_epoch: SecurityEpoch,
    /// Report content hash.
    pub report_hash: ContentHash,
    /// Violation categories found (deduped).
    pub violation_categories: BTreeSet<String>,
}

/// Build a guard report from a collection of file scan results.
pub fn build_guard_report(
    file_results: Vec<FileScanResult>,
    registry: &PatternRegistry,
    waiver_policy: &WaiverPolicy,
    sweep_epoch: SecurityEpoch,
) -> GuardReport {
    let files_scanned = file_results.len();
    let mut files_with_violations = 0usize;
    let mut files_with_test_only = 0usize;
    let mut clean_files = 0usize;
    let mut total_production = 0usize;
    let mut total_test_only = 0usize;
    let mut violation_categories = BTreeSet::new();

    for r in &file_results {
        match r.verdict {
            FileVerdict::ProductionViolation => {
                files_with_violations += 1;
                for m in &r.matches {
                    if m.scope == ScopeClassification::Production
                        || m.scope == ScopeClassification::Unknown
                    {
                        violation_categories.insert(m.category.label().to_string());
                    }
                }
            }
            FileVerdict::TestOnlyUsage => files_with_test_only += 1,
            FileVerdict::Clean => clean_files += 1,
        }
        total_production += r.production_violation_count;
        total_test_only += r.test_only_count;
    }

    let decision = if total_production > MAX_VIOLATIONS_BEFORE_ABORT {
        GateDecision::AbortedExcessViolations
    } else if total_production > 0 {
        GateDecision::Fail
    } else {
        GateDecision::Pass
    };

    // Only include files with matches in the report.
    let included_results: Vec<FileScanResult> = file_results
        .into_iter()
        .filter(|r| r.verdict != FileVerdict::Clean)
        .collect();

    let report_hash = compute_report_hash(&included_results, sweep_epoch);

    GuardReport {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        decision,
        files_scanned,
        files_with_violations,
        files_with_test_only,
        clean_files,
        total_production_violations: total_production,
        total_test_only_matches: total_test_only,
        file_results: included_results,
        registry_hash: registry.registry_hash,
        waiver_policy_hash: waiver_policy.policy_hash,
        sweep_epoch,
        report_hash,
        violation_categories,
    }
}

fn compute_report_hash(results: &[FileScanResult], epoch: SecurityEpoch) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(b"mock-seam-guard-report-v1");
    hasher.update(epoch.as_u64().to_le_bytes());
    for r in results {
        hasher.update(r.file_path.as_bytes());
        hasher.update(r.file_hash.as_bytes());
        hasher.update((r.production_violation_count as u64).to_le_bytes());
    }
    ContentHash::compute(&hasher.finalize())
}

// ---------------------------------------------------------------------------
// GuardrailError
// ---------------------------------------------------------------------------

/// Errors from guardrail operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailError {
    /// Pattern string is empty.
    EmptyPattern,
    /// Pattern limit exceeded for a category.
    PatternLimitExceeded {
        category: PatternCategory,
        limit: usize,
    },
    /// Duplicate pattern needle.
    DuplicatePattern { needle: String },
    /// File limit exceeded in sweep.
    FileLimitExceeded { limit: usize },
    /// Waiver ID is empty.
    EmptyWaiverId,
    /// Duplicate waiver ID.
    DuplicateWaiver { waiver_id: String },
    /// Waiver expired.
    WaiverExpired {
        waiver_id: String,
        expired_at: u64,
        current: u64,
    },
}

impl fmt::Display for GuardrailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPattern => write!(f, "pattern needle must not be empty"),
            Self::PatternLimitExceeded { category, limit } => {
                write!(f, "pattern limit {limit} exceeded for category {category}")
            }
            Self::DuplicatePattern { needle } => {
                write!(f, "duplicate pattern: {needle}")
            }
            Self::FileLimitExceeded { limit } => {
                write!(f, "file limit {limit} exceeded in sweep")
            }
            Self::EmptyWaiverId => write!(f, "waiver ID must not be empty"),
            Self::DuplicateWaiver { waiver_id } => {
                write!(f, "duplicate waiver ID: {waiver_id}")
            }
            Self::WaiverExpired {
                waiver_id,
                expired_at,
                current,
            } => {
                write!(
                    f,
                    "waiver {waiver_id} expired at epoch {expired_at} (current: {current})"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience: full sweep
// ---------------------------------------------------------------------------

/// Run a full guard sweep over a set of (path, content) pairs.
pub fn run_guard_sweep(
    files: &[(&str, &str)],
    registry: &PatternRegistry,
    waiver_policy: &WaiverPolicy,
    sweep_epoch: SecurityEpoch,
) -> Result<GuardReport, GuardrailError> {
    if files.len() > MAX_FILES_PER_SWEEP {
        return Err(GuardrailError::FileLimitExceeded {
            limit: MAX_FILES_PER_SWEEP,
        });
    }
    let mut results = Vec::with_capacity(files.len());
    for (path, content) in files {
        results.push(scan_file_content(
            path,
            content,
            registry,
            waiver_policy,
            sweep_epoch,
        ));
    }
    Ok(build_guard_report(
        results,
        registry,
        waiver_policy,
        sweep_epoch,
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    // --- PatternCategory ---

    #[test]
    fn pattern_category_all_covers_every_variant() {
        let all = PatternCategory::all();
        assert_eq!(all.len(), 6);
    }

    #[test]
    fn pattern_category_labels_unique() {
        let labels: BTreeSet<&str> = PatternCategory::all().iter().map(|c| c.label()).collect();
        assert_eq!(labels.len(), PatternCategory::all().len());
    }

    #[test]
    fn pattern_category_display_matches_label() {
        for c in PatternCategory::all() {
            assert_eq!(format!("{c}"), c.label());
        }
    }

    #[test]
    fn pattern_category_serde_round_trip() {
        for c in PatternCategory::all() {
            let json = serde_json::to_string(c).unwrap();
            let back: PatternCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*c, back);
        }
    }

    // --- ScopeClassification ---

    #[test]
    fn scope_classification_display() {
        assert_eq!(format!("{}", ScopeClassification::TestOnly), "test_only");
        assert_eq!(format!("{}", ScopeClassification::Production), "production");
        assert_eq!(format!("{}", ScopeClassification::Unknown), "unknown");
    }

    #[test]
    fn scope_classification_serde_round_trip() {
        for s in [
            ScopeClassification::TestOnly,
            ScopeClassification::Production,
            ScopeClassification::Unknown,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: ScopeClassification = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    // --- PatternRegistry ---

    #[test]
    fn default_registry_has_patterns() {
        let reg = build_default_registry();
        assert!(reg.total_count >= 10);
        assert!(!reg.patterns.is_empty());
    }

    #[test]
    fn default_registry_hash_deterministic() {
        let r1 = build_default_registry();
        let r2 = build_default_registry();
        assert_eq!(r1.registry_hash, r2.registry_hash);
    }

    #[test]
    fn register_custom_pattern() {
        let mut reg = build_default_registry();
        let before = reg.total_count;
        register_pattern(
            &mut reg,
            "CustomMock".to_string(),
            PatternCategory::MockContextType,
            "custom mock type".to_string(),
        )
        .unwrap();
        assert_eq!(reg.total_count, before + 1);
    }

    #[test]
    fn register_empty_pattern_error() {
        let mut reg = build_default_registry();
        let err = register_pattern(
            &mut reg,
            "".to_string(),
            PatternCategory::MockContextType,
            "reason".to_string(),
        );
        assert_eq!(err, Err(GuardrailError::EmptyPattern));
    }

    #[test]
    fn register_duplicate_pattern_error() {
        let mut reg = build_default_registry();
        let err = register_pattern(
            &mut reg,
            "MockCx".to_string(),
            PatternCategory::MockContextType,
            "already there".to_string(),
        );
        assert!(matches!(err, Err(GuardrailError::DuplicatePattern { .. })));
    }

    #[test]
    fn registry_serde_round_trip() {
        let reg = build_default_registry();
        let json = serde_json::to_string(&reg).unwrap();
        let back: PatternRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(reg.total_count, back.total_count);
        assert_eq!(reg.registry_hash, back.registry_hash);
    }

    // --- ScopeClassification ---

    #[test]
    fn classify_test_directory() {
        let scope = classify_scope("tests/foo.rs", "use MockCx;", false);
        assert_eq!(scope, ScopeClassification::TestOnly);
    }

    #[test]
    fn classify_production_code() {
        let scope = classify_scope("src/orchestrator.rs", "let cx = MockCx::new();", false);
        assert_eq!(scope, ScopeClassification::Production);
    }

    #[test]
    fn classify_cfg_test_block() {
        let scope = classify_scope("src/orchestrator.rs", "let cx = MockCx::new();", true);
        assert_eq!(scope, ScopeClassification::TestOnly);
    }

    #[test]
    fn classify_comment_line() {
        let scope = classify_scope("src/orchestrator.rs", "// MockCx is used here", false);
        assert_eq!(scope, ScopeClassification::TestOnly);
    }

    // --- FileScanResult ---

    #[test]
    fn scan_clean_file() {
        let reg = build_default_registry();
        let waiver = empty_waiver_policy();
        let result = scan_file_content(
            "src/clean.rs",
            "fn main() {\n    println!(\"hello\");\n}\n",
            &reg,
            &waiver,
            epoch(1),
        );
        assert_eq!(result.verdict, FileVerdict::Clean);
        assert_eq!(result.production_violation_count, 0);
        assert_eq!(result.test_only_count, 0);
        assert!(result.matches.is_empty());
    }

    #[test]
    fn scan_production_violation() {
        let reg = build_default_registry();
        let waiver = empty_waiver_policy();
        let content = "use crate::control_plane::mocks;\nfn run() { let cx = MockCx::new(); }\n";
        let result = scan_file_content("src/bad.rs", content, &reg, &waiver, epoch(1));
        assert_eq!(result.verdict, FileVerdict::ProductionViolation);
        assert!(result.production_violation_count >= 2);
    }

    #[test]
    fn scan_test_only_usage() {
        let reg = build_default_registry();
        let waiver = empty_waiver_policy();
        let content = "#[cfg(test)]\nmod tests {\n    use MockCx;\n}\n";
        let result = scan_file_content("src/ok.rs", content, &reg, &waiver, epoch(1));
        assert_eq!(result.verdict, FileVerdict::TestOnlyUsage);
        assert_eq!(result.production_violation_count, 0);
        assert!(result.test_only_count > 0);
    }

    #[test]
    fn scan_file_in_tests_dir() {
        let reg = build_default_registry();
        let waiver = empty_waiver_policy();
        let content = "use MockCx;\nlet cx = MockBudget::new(100);\n";
        let result = scan_file_content("tests/integration.rs", content, &reg, &waiver, epoch(1));
        assert_eq!(result.verdict, FileVerdict::TestOnlyUsage);
        assert_eq!(result.production_violation_count, 0);
    }

    #[test]
    fn scan_file_hash_deterministic() {
        let reg = build_default_registry();
        let waiver = empty_waiver_policy();
        let content = "fn foo() {}\n";
        let r1 = scan_file_content("src/a.rs", content, &reg, &waiver, epoch(1));
        let r2 = scan_file_content("src/a.rs", content, &reg, &waiver, epoch(1));
        assert_eq!(r1.file_hash, r2.file_hash);
    }

    #[test]
    fn scan_result_serde_round_trip() {
        let reg = build_default_registry();
        let waiver = empty_waiver_policy();
        let content = "use MockCx;\n";
        let result = scan_file_content("src/bad.rs", content, &reg, &waiver, epoch(1));
        let json = serde_json::to_string(&result).unwrap();
        let back: FileScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.verdict, back.verdict);
        assert_eq!(result.file_hash, back.file_hash);
    }

    // --- WaiverPolicy ---

    #[test]
    fn empty_waiver_policy_no_waivers() {
        let p = empty_waiver_policy();
        assert!(p.waivers.is_empty());
    }

    #[test]
    fn add_waiver_success() {
        let mut p = empty_waiver_policy();
        add_waiver(
            &mut p,
            "w-001".to_string(),
            "src/legacy.rs".to_string(),
            Some("MockCx".to_string()),
            "Legacy code".to_string(),
            epoch(1),
            Some(epoch(100)),
        )
        .unwrap();
        assert_eq!(p.waivers.len(), 1);
    }

    #[test]
    fn add_waiver_duplicate_error() {
        let mut p = empty_waiver_policy();
        add_waiver(
            &mut p,
            "w-001".to_string(),
            "src/a.rs".to_string(),
            None,
            "reason".to_string(),
            epoch(1),
            None,
        )
        .unwrap();
        let err = add_waiver(
            &mut p,
            "w-001".to_string(),
            "src/b.rs".to_string(),
            None,
            "reason2".to_string(),
            epoch(1),
            None,
        );
        assert!(matches!(err, Err(GuardrailError::DuplicateWaiver { .. })));
    }

    #[test]
    fn add_waiver_empty_id_error() {
        let mut p = empty_waiver_policy();
        let err = add_waiver(
            &mut p,
            "".to_string(),
            "src/a.rs".to_string(),
            None,
            "reason".to_string(),
            epoch(1),
            None,
        );
        assert_eq!(err, Err(GuardrailError::EmptyWaiverId));
    }

    #[test]
    fn is_waived_exact_match() {
        let mut p = empty_waiver_policy();
        add_waiver(
            &mut p,
            "w-001".to_string(),
            "src/legacy.rs".to_string(),
            Some("MockCx".to_string()),
            "legacy".to_string(),
            epoch(1),
            None,
        )
        .unwrap();
        assert!(is_waived(&p, "src/legacy.rs", "MockCx", epoch(5)));
        assert!(!is_waived(&p, "src/legacy.rs", "MockBudget", epoch(5)));
        assert!(!is_waived(&p, "src/other.rs", "MockCx", epoch(5)));
    }

    #[test]
    fn is_waived_expired() {
        let mut p = empty_waiver_policy();
        add_waiver(
            &mut p,
            "w-exp".to_string(),
            "src/legacy.rs".to_string(),
            None,
            "temporary".to_string(),
            epoch(1),
            Some(epoch(10)),
        )
        .unwrap();
        assert!(is_waived(&p, "src/legacy.rs", "MockCx", epoch(5)));
        assert!(!is_waived(&p, "src/legacy.rs", "MockCx", epoch(11)));
    }

    #[test]
    fn waived_match_not_reported() {
        let reg = build_default_registry();
        let mut waiver = empty_waiver_policy();
        add_waiver(
            &mut waiver,
            "w-001".to_string(),
            "src/waived.rs".to_string(),
            Some("MockCx".to_string()),
            "legacy exemption".to_string(),
            epoch(1),
            None,
        )
        .unwrap();
        let content = "let cx = MockCx::new();\n";
        let result = scan_file_content("src/waived.rs", content, &reg, &waiver, epoch(1));
        // MockCx should be waived, but MockBudget etc. should not appear.
        assert_eq!(result.production_violation_count, 0);
    }

    #[test]
    fn waiver_policy_serde_round_trip() {
        let mut p = empty_waiver_policy();
        add_waiver(
            &mut p,
            "w-001".to_string(),
            "src/a.rs".to_string(),
            None,
            "reason".to_string(),
            epoch(1),
            Some(epoch(100)),
        )
        .unwrap();
        let json = serde_json::to_string(&p).unwrap();
        let back: WaiverPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p.waivers.len(), back.waivers.len());
        assert_eq!(p.policy_hash, back.policy_hash);
    }

    // --- GuardReport ---

    #[test]
    fn guard_report_pass_on_clean() {
        let reg = build_default_registry();
        let waiver = empty_waiver_policy();
        let files: Vec<(&str, &str)> = vec![("src/a.rs", "fn a() {}"), ("src/b.rs", "fn b() {}")];
        let report = run_guard_sweep(&files, &reg, &waiver, epoch(1)).unwrap();
        assert_eq!(report.decision, GateDecision::Pass);
        assert_eq!(report.files_scanned, 2);
        assert_eq!(report.clean_files, 2);
    }

    #[test]
    fn guard_report_fail_on_violation() {
        let reg = build_default_registry();
        let waiver = empty_waiver_policy();
        let files: Vec<(&str, &str)> = vec![("src/bad.rs", "let cx = MockCx::new();")];
        let report = run_guard_sweep(&files, &reg, &waiver, epoch(1)).unwrap();
        assert_eq!(report.decision, GateDecision::Fail);
        assert_eq!(report.files_with_violations, 1);
        assert!(report.total_production_violations > 0);
    }

    #[test]
    fn guard_report_pass_with_test_only() {
        let reg = build_default_registry();
        let waiver = empty_waiver_policy();
        let files: Vec<(&str, &str)> = vec![("tests/test_a.rs", "use MockCx;\nuse MockBudget;")];
        let report = run_guard_sweep(&files, &reg, &waiver, epoch(1)).unwrap();
        assert_eq!(report.decision, GateDecision::Pass);
        assert_eq!(report.files_with_test_only, 1);
        assert_eq!(report.total_production_violations, 0);
    }

    #[test]
    fn guard_report_hash_deterministic() {
        let reg = build_default_registry();
        let waiver = empty_waiver_policy();
        let files: Vec<(&str, &str)> = vec![("src/a.rs", "fn a() {}")];
        let r1 = run_guard_sweep(&files, &reg, &waiver, epoch(1)).unwrap();
        let r2 = run_guard_sweep(&files, &reg, &waiver, epoch(1)).unwrap();
        assert_eq!(r1.report_hash, r2.report_hash);
    }

    #[test]
    fn guard_report_serde_round_trip() {
        let reg = build_default_registry();
        let waiver = empty_waiver_policy();
        let files: Vec<(&str, &str)> = vec![("src/bad.rs", "let cx = MockCx::new();")];
        let report = run_guard_sweep(&files, &reg, &waiver, epoch(1)).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let back: GuardReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.decision, back.decision);
        assert_eq!(report.report_hash, back.report_hash);
    }

    #[test]
    fn guard_report_includes_violation_categories() {
        let reg = build_default_registry();
        let waiver = empty_waiver_policy();
        let files: Vec<(&str, &str)> =
            vec![("src/bad.rs", "MockCx::new();\ntrace_id_from_seed(42);\n")];
        let report = run_guard_sweep(&files, &reg, &waiver, epoch(1)).unwrap();
        assert!(report.violation_categories.contains("mock_context_type"));
        assert!(report.violation_categories.contains("seed_derived_trace"));
    }

    // --- FileVerdict ---

    #[test]
    fn file_verdict_display() {
        assert_eq!(format!("{}", FileVerdict::Clean), "clean");
        assert_eq!(format!("{}", FileVerdict::TestOnlyUsage), "test_only_usage");
        assert_eq!(
            format!("{}", FileVerdict::ProductionViolation),
            "production_violation"
        );
    }

    #[test]
    fn file_verdict_serde_round_trip() {
        for v in [
            FileVerdict::Clean,
            FileVerdict::TestOnlyUsage,
            FileVerdict::ProductionViolation,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let back: FileVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    // --- GateDecision ---

    #[test]
    fn gate_decision_display() {
        assert_eq!(format!("{}", GateDecision::Pass), "pass");
        assert_eq!(format!("{}", GateDecision::Fail), "fail");
        assert_eq!(
            format!("{}", GateDecision::AbortedExcessViolations),
            "aborted_excess_violations"
        );
    }

    #[test]
    fn gate_decision_serde_round_trip() {
        for d in [
            GateDecision::Pass,
            GateDecision::Fail,
            GateDecision::AbortedExcessViolations,
        ] {
            let json = serde_json::to_string(&d).unwrap();
            let back: GateDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(d, back);
        }
    }

    // --- GuardrailError ---

    #[test]
    fn guardrail_error_display() {
        let e = GuardrailError::EmptyPattern;
        assert!(!format!("{e}").is_empty());

        let e2 = GuardrailError::PatternLimitExceeded {
            category: PatternCategory::MockModuleImport,
            limit: 256,
        };
        assert!(format!("{e2}").contains("256"));

        let e3 = GuardrailError::DuplicatePattern {
            needle: "MockCx".to_string(),
        };
        assert!(format!("{e3}").contains("MockCx"));
    }

    #[test]
    fn guardrail_error_serde_round_trip() {
        let errors = vec![
            GuardrailError::EmptyPattern,
            GuardrailError::PatternLimitExceeded {
                category: PatternCategory::FakeBudget,
                limit: 256,
            },
            GuardrailError::DuplicatePattern {
                needle: "foo".to_string(),
            },
            GuardrailError::FileLimitExceeded { limit: 8192 },
            GuardrailError::EmptyWaiverId,
            GuardrailError::DuplicateWaiver {
                waiver_id: "w-001".to_string(),
            },
            GuardrailError::WaiverExpired {
                waiver_id: "w-002".to_string(),
                expired_at: 10,
                current: 20,
            },
        ];
        for e in &errors {
            let json = serde_json::to_string(e).unwrap();
            let back: GuardrailError = serde_json::from_str(&json).unwrap();
            assert_eq!(*e, back);
        }
    }

    // --- Full sweep edge cases ---

    #[test]
    fn sweep_empty_files() {
        let reg = build_default_registry();
        let waiver = empty_waiver_policy();
        let files: Vec<(&str, &str)> = vec![];
        let report = run_guard_sweep(&files, &reg, &waiver, epoch(1)).unwrap();
        assert_eq!(report.decision, GateDecision::Pass);
        assert_eq!(report.files_scanned, 0);
    }

    #[test]
    fn sweep_mixed_clean_and_violations() {
        let reg = build_default_registry();
        let waiver = empty_waiver_policy();
        let files: Vec<(&str, &str)> = vec![
            ("src/clean.rs", "fn clean() {}"),
            ("src/bad.rs", "let b = MockBudget::new(100);"),
            ("tests/ok.rs", "use MockCx;"),
        ];
        let report = run_guard_sweep(&files, &reg, &waiver, epoch(1)).unwrap();
        assert_eq!(report.decision, GateDecision::Fail);
        assert_eq!(report.files_scanned, 3);
        assert_eq!(report.clean_files, 1);
        assert_eq!(report.files_with_violations, 1);
        assert_eq!(report.files_with_test_only, 1);
    }

    #[test]
    fn sweep_waiver_turns_violation_to_pass() {
        let reg = build_default_registry();
        let mut waiver = empty_waiver_policy();
        add_waiver(
            &mut waiver,
            "w-legacy".to_string(),
            "src/legacy.rs".to_string(),
            None,
            "legacy exemption".to_string(),
            epoch(1),
            None,
        )
        .unwrap();
        let files: Vec<(&str, &str)> = vec![(
            "src/legacy.rs",
            "let cx = MockCx::new();\nlet b = MockBudget::new(10);",
        )];
        let report = run_guard_sweep(&files, &reg, &waiver, epoch(1)).unwrap();
        assert_eq!(report.decision, GateDecision::Pass);
    }

    #[test]
    fn scan_long_line_truncated() {
        let reg = build_default_registry();
        let waiver = empty_waiver_policy();
        let long_line = format!("let cx = MockCx::new(); {}", "x".repeat(300));
        let result = scan_file_content("src/long.rs", &long_line, &reg, &waiver, epoch(1));
        assert!(result.matches.iter().all(|m| m.line_excerpt.len() <= 200));
    }

    #[test]
    fn multiple_patterns_same_line() {
        let reg = build_default_registry();
        let waiver = empty_waiver_policy();
        let content = "use MockCx; use MockBudget;\n";
        let result = scan_file_content("src/multi.rs", content, &reg, &waiver, epoch(1));
        assert!(result.matches.len() >= 2);
    }

    #[test]
    fn custom_pattern_detected() {
        let mut reg = build_default_registry();
        register_pattern(
            &mut reg,
            "BOGUS_CONTEXT".to_string(),
            PatternCategory::HardcodedSentinel,
            "test sentinel".to_string(),
        )
        .unwrap();
        let waiver = empty_waiver_policy();
        let content = "let ctx = BOGUS_CONTEXT;\n";
        let result = scan_file_content("src/custom.rs", content, &reg, &waiver, epoch(1));
        assert_eq!(result.verdict, FileVerdict::ProductionViolation);
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.pattern_needle == "BOGUS_CONTEXT")
        );
    }

    #[test]
    fn seed_derived_trace_detected() {
        let reg = build_default_registry();
        let waiver = empty_waiver_policy();
        let content = "let tid = trace_id_from_seed(42);\n";
        let result = scan_file_content("src/trace.rs", content, &reg, &waiver, epoch(1));
        assert_eq!(result.verdict, FileVerdict::ProductionViolation);
        assert!(
            result
                .matches
                .iter()
                .any(|m| m.category == PatternCategory::SeedDerivedTrace)
        );
    }
}
