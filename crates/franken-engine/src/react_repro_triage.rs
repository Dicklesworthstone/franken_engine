//! React ecosystem failure triage: minimized repro extraction, owner routing,
//! severity taxonomy, and user-facing classification.
//!
//! Bead: bd-1lsy.5.7.3 [RGC-405C]
//!
//! When React ecosystem incompatibilities surface, this module classifies them
//! into actionable engineering work: distinguishing transform bugs, resolver
//! bugs, runtime semantic gaps, unsupported environment boundaries, and plain
//! package misuse. Each failure is minimized, assigned an owner bead, and
//! given user-visible advisory language.
//!
//! The output (`react_repro_catalog.json`) is consumed by advisory generators,
//! docs pipelines, and workload triage gates.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const SCHEMA_VERSION: &str = "franken-engine.react-repro-triage.v1";
pub const BEAD_ID: &str = "bd-1lsy.5.7.3";
pub const POLICY_ID: &str = "RGC-405C";
pub const COMPONENT: &str = "react_repro_triage";
#[allow(dead_code)]
const MILLIONTHS: u64 = 1_000_000;
const MAX_REPRO_SOURCE_LEN: usize = 65_536;
const MAX_ADVISORY_LEN: usize = 4096;
const MAX_CATALOG_ENTRIES: usize = 10_000;

// ---------------------------------------------------------------------------
// FailureClass
// ---------------------------------------------------------------------------

/// Root classification of a React ecosystem failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    /// JSX/TSX transform produces incorrect output.
    TransformBug,
    /// Module resolver fails to locate or load a React dependency.
    ResolverBug,
    /// Runtime semantic gap: engine does not implement required semantics.
    RuntimeSemanticGap,
    /// Unsupported environment boundary (e.g., platform API not available).
    UnsupportedEnvironment,
    /// User-side package misuse or version incompatibility.
    PackageMisuse,
    /// React-specific hook ordering or lifecycle invariant violation.
    HookInvariantViolation,
    /// SSR/hydration mismatch between server and client output.
    HydrationMismatch,
    /// Suspense boundary behavior divergence.
    SuspenseDivergence,
    /// Error boundary propagation failure.
    ErrorBoundaryFailure,
    /// Unknown or unclassified failure.
    Unclassified,
}

impl FailureClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TransformBug => "transform_bug",
            Self::ResolverBug => "resolver_bug",
            Self::RuntimeSemanticGap => "runtime_semantic_gap",
            Self::UnsupportedEnvironment => "unsupported_environment",
            Self::PackageMisuse => "package_misuse",
            Self::HookInvariantViolation => "hook_invariant_violation",
            Self::HydrationMismatch => "hydration_mismatch",
            Self::SuspenseDivergence => "suspense_divergence",
            Self::ErrorBoundaryFailure => "error_boundary_failure",
            Self::Unclassified => "unclassified",
        }
    }

    /// Whether this class represents an engine bug (vs user/environment issue).
    #[must_use]
    pub const fn is_engine_bug(self) -> bool {
        matches!(
            self,
            Self::TransformBug
                | Self::ResolverBug
                | Self::RuntimeSemanticGap
                | Self::HookInvariantViolation
                | Self::HydrationMismatch
                | Self::SuspenseDivergence
                | Self::ErrorBoundaryFailure
        )
    }

    /// All known failure classes.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::TransformBug,
            Self::ResolverBug,
            Self::RuntimeSemanticGap,
            Self::UnsupportedEnvironment,
            Self::PackageMisuse,
            Self::HookInvariantViolation,
            Self::HydrationMismatch,
            Self::SuspenseDivergence,
            Self::ErrorBoundaryFailure,
            Self::Unclassified,
        ]
    }
}

impl fmt::Display for FailureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// FailureSeverity
// ---------------------------------------------------------------------------

/// Severity of a React ecosystem failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureSeverity {
    /// Blocks a core React workflow entirely.
    Critical,
    /// Degrades a common workflow but has workarounds.
    High,
    /// Affects an uncommon or edge-case workflow.
    Medium,
    /// Cosmetic or low-impact difference.
    Low,
    /// Informational only (no user impact).
    Info,
}

impl FailureSeverity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }

    /// Numeric weight for sorting (higher = more severe).
    #[must_use]
    pub const fn weight(self) -> u32 {
        match self {
            Self::Critical => 5,
            Self::High => 4,
            Self::Medium => 3,
            Self::Low => 2,
            Self::Info => 1,
        }
    }
}

impl fmt::Display for FailureSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// OwnerRoute
// ---------------------------------------------------------------------------

/// Owner routing for a failure — maps to a bead or team.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OwnerRoute {
    /// Owning bead identifier (e.g., "bd-1lsy.3.6.1").
    pub bead_id: String,
    /// Team or subsystem that owns the fix.
    pub team: String,
    /// Brief routing rationale.
    pub rationale: String,
}

// ---------------------------------------------------------------------------
// MinimizedRepro
// ---------------------------------------------------------------------------

/// A minimized reproduction case for a React ecosystem failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimizedRepro {
    /// Deterministic identifier for this repro.
    pub repro_id: String,
    /// Minimal source code that triggers the failure.
    pub source: String,
    /// Expected behavior description.
    pub expected: String,
    /// Actual behavior description.
    pub actual: String,
    /// Content hash of the source for dedup.
    pub source_hash: ContentHash,
    /// React version(s) affected.
    pub react_versions: BTreeSet<String>,
    /// Whether the repro is deterministic.
    pub deterministic: bool,
    /// Replay command to reproduce.
    pub replay_command: String,
}

impl MinimizedRepro {
    /// Build a repro from inputs, computing hashes deterministically.
    #[must_use]
    pub fn build(
        source: &str,
        expected: &str,
        actual: &str,
        react_versions: BTreeSet<String>,
        replay_command: &str,
    ) -> Self {
        let truncated_source = if source.len() > MAX_REPRO_SOURCE_LEN {
            &source[..MAX_REPRO_SOURCE_LEN]
        } else {
            source
        };
        let source_hash = ContentHash::compute(truncated_source.as_bytes());
        let repro_id = format!("repro-{}", &source_hash.to_string()[..16]);

        Self {
            repro_id,
            source: truncated_source.to_string(),
            expected: expected.to_string(),
            actual: actual.to_string(),
            source_hash,
            react_versions,
            deterministic: true,
            replay_command: replay_command.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// TriageEntry
// ---------------------------------------------------------------------------

/// A single triaged React ecosystem failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageEntry {
    /// Unique identifier for this entry.
    pub entry_id: String,
    /// Failure classification.
    pub failure_class: FailureClass,
    /// Severity.
    pub severity: FailureSeverity,
    /// Owner routing.
    pub owner: OwnerRoute,
    /// Minimized reproduction.
    pub repro: MinimizedRepro,
    /// User-facing advisory text.
    pub advisory: String,
    /// Whether this is currently unresolved.
    pub unresolved: bool,
    /// Content hash for tamper detection.
    pub content_hash: ContentHash,
}

impl TriageEntry {
    /// Build a triage entry from parts, computing hashes.
    #[must_use]
    pub fn build(
        failure_class: FailureClass,
        severity: FailureSeverity,
        owner: OwnerRoute,
        repro: MinimizedRepro,
        advisory: &str,
    ) -> Self {
        let truncated_advisory = if advisory.len() > MAX_ADVISORY_LEN {
            &advisory[..MAX_ADVISORY_LEN]
        } else {
            advisory
        };

        let mut hasher = Sha256::new();
        hasher.update(failure_class.as_str().as_bytes());
        hasher.update(severity.as_str().as_bytes());
        hasher.update(owner.bead_id.as_bytes());
        hasher.update(repro.source_hash.as_bytes());
        let digest = hasher.finalize();
        let content_hash = ContentHash::from_bytes(digest.into());

        let entry_id = format!(
            "triage-{}-{}",
            failure_class.as_str(),
            &repro.repro_id[..repro.repro_id.len().min(12)]
        );

        Self {
            entry_id,
            failure_class,
            severity,
            owner,
            repro,
            advisory: truncated_advisory.to_string(),
            unresolved: true,
            content_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// ReproCatalog
// ---------------------------------------------------------------------------

/// Complete catalog of triaged React ecosystem failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproCatalog {
    /// Schema version.
    pub schema_version: String,
    /// Bead identifier.
    pub bead_id: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Component name.
    pub component: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// All triage entries in deterministic order.
    pub entries: Vec<TriageEntry>,
    /// Summary statistics.
    pub summary: CatalogSummary,
    /// Content hash of the full catalog.
    pub content_hash: ContentHash,
}

/// Summary statistics for a repro catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogSummary {
    /// Total entries.
    pub total_entries: usize,
    /// Entries by failure class.
    pub by_class: BTreeMap<String, usize>,
    /// Entries by severity.
    pub by_severity: BTreeMap<String, usize>,
    /// Unresolved count.
    pub unresolved_count: usize,
    /// Engine-bug count (vs user/environment).
    pub engine_bug_count: usize,
    /// Distinct owner beads.
    pub distinct_owners: usize,
    /// Severity-weighted score (higher = more severe backlog).
    pub severity_weighted_score: u64,
}

impl ReproCatalog {
    /// Build a catalog from a list of triage entries.
    #[must_use]
    pub fn build(entries: Vec<TriageEntry>, epoch: SecurityEpoch) -> Self {
        let mut by_class: BTreeMap<String, usize> = BTreeMap::new();
        let mut by_severity: BTreeMap<String, usize> = BTreeMap::new();
        let mut owner_beads = BTreeSet::new();
        let mut unresolved_count = 0usize;
        let mut engine_bug_count = 0usize;
        let mut severity_score = 0u64;

        for entry in &entries {
            *by_class
                .entry(entry.failure_class.as_str().to_string())
                .or_insert(0) += 1;
            *by_severity
                .entry(entry.severity.as_str().to_string())
                .or_insert(0) += 1;
            owner_beads.insert(entry.owner.bead_id.clone());
            if entry.unresolved {
                unresolved_count += 1;
            }
            if entry.failure_class.is_engine_bug() {
                engine_bug_count += 1;
            }
            severity_score += u64::from(entry.severity.weight());
        }

        let summary = CatalogSummary {
            total_entries: entries.len(),
            by_class,
            by_severity,
            unresolved_count,
            engine_bug_count,
            distinct_owners: owner_beads.len(),
            severity_weighted_score: severity_score,
        };

        let content_hash = compute_catalog_hash(&entries, &summary);

        let mut sorted_entries = entries;
        sorted_entries.sort_by(|a, b| {
            b.severity
                .weight()
                .cmp(&a.severity.weight())
                .then_with(|| a.failure_class.cmp(&b.failure_class))
                .then_with(|| a.entry_id.cmp(&b.entry_id))
        });

        // Enforce max entries
        if sorted_entries.len() > MAX_CATALOG_ENTRIES {
            sorted_entries.truncate(MAX_CATALOG_ENTRIES);
        }

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            policy_id: POLICY_ID.to_string(),
            component: COMPONENT.to_string(),
            epoch,
            entries: sorted_entries,
            summary,
            content_hash,
        }
    }

    /// Verify the content hash matches the current entries.
    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        let expected = compute_catalog_hash(&self.entries, &self.summary);
        self.content_hash == expected
    }

    /// Filter entries by failure class.
    #[must_use]
    pub fn entries_by_class(&self, class: FailureClass) -> Vec<&TriageEntry> {
        self.entries
            .iter()
            .filter(|e| e.failure_class == class)
            .collect()
    }

    /// Filter entries by severity.
    #[must_use]
    pub fn entries_by_severity(&self, severity: FailureSeverity) -> Vec<&TriageEntry> {
        self.entries
            .iter()
            .filter(|e| e.severity == severity)
            .collect()
    }

    /// Get all unresolved entries.
    #[must_use]
    pub fn unresolved(&self) -> Vec<&TriageEntry> {
        self.entries.iter().filter(|e| e.unresolved).collect()
    }

    /// Get all engine-bug entries.
    #[must_use]
    pub fn engine_bugs(&self) -> Vec<&TriageEntry> {
        self.entries
            .iter()
            .filter(|e| e.failure_class.is_engine_bug())
            .collect()
    }

    /// Check if the catalog has any critical unresolved engine bugs.
    #[must_use]
    pub fn has_critical_engine_bugs(&self) -> bool {
        self.entries.iter().any(|e| {
            e.unresolved
                && e.failure_class.is_engine_bug()
                && e.severity == FailureSeverity::Critical
        })
    }
}

// ---------------------------------------------------------------------------
// TriageEvent
// ---------------------------------------------------------------------------

/// Structured event emitted during triage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageEvent {
    /// Schema version.
    pub schema_version: String,
    /// Trace identifier.
    pub trace_id: String,
    /// Decision identifier.
    pub decision_id: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Component name.
    pub component: String,
    /// Event kind.
    pub event: String,
    /// Outcome.
    pub outcome: String,
    /// Error code if applicable.
    pub error_code: Option<String>,
    /// Deterministic seed.
    pub seed: String,
    /// Scenario identifier.
    pub scenario_id: String,
    /// Failure class being triaged.
    pub failure_class: String,
    /// Severity assigned.
    pub severity: String,
    /// Owner bead routed to.
    pub owner_bead: String,
}

/// Build a triage event.
#[must_use]
pub fn build_triage_event(
    trace_id: &str,
    decision_id: &str,
    scenario_id: &str,
    entry: &TriageEntry,
) -> TriageEvent {
    TriageEvent {
        schema_version: SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event: "failure_triaged".to_string(),
        outcome: if entry.unresolved {
            "unresolved"
        } else {
            "resolved"
        }
        .to_string(),
        error_code: if entry.unresolved {
            Some(format!(
                "REACT-TRIAGE-{}",
                entry.failure_class.as_str().to_uppercase()
            ))
        } else {
            None
        },
        seed: "react-repro-triage-v1".to_string(),
        scenario_id: scenario_id.to_string(),
        failure_class: entry.failure_class.as_str().to_string(),
        severity: entry.severity.as_str().to_string(),
        owner_bead: entry.owner.bead_id.clone(),
    }
}

/// Symptom flags for failure classification.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FailureSymptoms {
    pub has_transform_diff: bool,
    pub has_resolver_error: bool,
    pub has_runtime_gap: bool,
    pub has_env_boundary: bool,
    pub has_version_mismatch: bool,
    pub has_hook_violation: bool,
    pub has_hydration_diff: bool,
    pub has_suspense_diff: bool,
    pub has_error_boundary_diff: bool,
}

/// Classify a failure from symptoms.
#[must_use]
pub fn classify_failure(symptoms: &FailureSymptoms) -> FailureClass {
    // Priority order: most specific first
    if symptoms.has_hook_violation {
        return FailureClass::HookInvariantViolation;
    }
    if symptoms.has_hydration_diff {
        return FailureClass::HydrationMismatch;
    }
    if symptoms.has_suspense_diff {
        return FailureClass::SuspenseDivergence;
    }
    if symptoms.has_error_boundary_diff {
        return FailureClass::ErrorBoundaryFailure;
    }
    if symptoms.has_transform_diff {
        return FailureClass::TransformBug;
    }
    if symptoms.has_resolver_error {
        return FailureClass::ResolverBug;
    }
    if symptoms.has_runtime_gap {
        return FailureClass::RuntimeSemanticGap;
    }
    if symptoms.has_env_boundary {
        return FailureClass::UnsupportedEnvironment;
    }
    if symptoms.has_version_mismatch {
        return FailureClass::PackageMisuse;
    }
    FailureClass::Unclassified
}

/// Assign severity based on failure class and impact indicators.
#[must_use]
pub fn assign_severity(
    class: FailureClass,
    blocks_core_workflow: bool,
    has_workaround: bool,
    is_edge_case: bool,
) -> FailureSeverity {
    if blocks_core_workflow && class.is_engine_bug() {
        return FailureSeverity::Critical;
    }
    if is_edge_case {
        return FailureSeverity::Info;
    }
    if class.is_engine_bug() && !has_workaround {
        return FailureSeverity::High;
    }
    if class.is_engine_bug() && has_workaround {
        return FailureSeverity::Medium;
    }
    if !class.is_engine_bug() {
        return FailureSeverity::Low;
    }
    FailureSeverity::Medium
}

/// Map a failure class to a default owner route.
#[must_use]
pub fn default_owner_route(class: FailureClass) -> OwnerRoute {
    match class {
        FailureClass::TransformBug => OwnerRoute {
            bead_id: "bd-1lsy.3.6.1".to_string(),
            team: "jsx-transform".to_string(),
            rationale: "JSX/TSX transform produces incorrect output".to_string(),
        },
        FailureClass::ResolverBug => OwnerRoute {
            bead_id: "bd-1lsy.5.8.2".to_string(),
            team: "module-resolution".to_string(),
            rationale: "Module resolver fails to locate React dependency".to_string(),
        },
        FailureClass::RuntimeSemanticGap => OwnerRoute {
            bead_id: "bd-1lsy.4.9.1".to_string(),
            team: "runtime-semantics".to_string(),
            rationale: "Engine missing required runtime semantics".to_string(),
        },
        FailureClass::UnsupportedEnvironment => OwnerRoute {
            bead_id: "bd-1lsy.5.9.2".to_string(),
            team: "environment-compat".to_string(),
            rationale: "Platform API not available in engine environment".to_string(),
        },
        FailureClass::PackageMisuse => OwnerRoute {
            bead_id: "bd-1lsy.5.7.3".to_string(),
            team: "docs-triage".to_string(),
            rationale: "User version/config issue — needs advisory update".to_string(),
        },
        FailureClass::HookInvariantViolation => OwnerRoute {
            bead_id: "bd-1lsy.3.6.2".to_string(),
            team: "react-lowering".to_string(),
            rationale: "React hook ordering or lifecycle invariant broken".to_string(),
        },
        FailureClass::HydrationMismatch => OwnerRoute {
            bead_id: "bd-1lsy.5.7.2".to_string(),
            team: "ssr-hydration".to_string(),
            rationale: "SSR/client hydration output diverges".to_string(),
        },
        FailureClass::SuspenseDivergence => OwnerRoute {
            bead_id: "bd-1lsy.3.6.2".to_string(),
            team: "react-lowering".to_string(),
            rationale: "Suspense boundary behavior differs from React".to_string(),
        },
        FailureClass::ErrorBoundaryFailure => OwnerRoute {
            bead_id: "bd-1lsy.3.6.2".to_string(),
            team: "react-lowering".to_string(),
            rationale: "Error boundary propagation diverges from React".to_string(),
        },
        FailureClass::Unclassified => OwnerRoute {
            bead_id: "bd-1lsy.5.7.3".to_string(),
            team: "triage".to_string(),
            rationale: "Failure not yet classified — needs manual investigation".to_string(),
        },
    }
}

/// Generate user-facing advisory text for a failure class.
#[must_use]
pub fn generate_advisory(class: FailureClass, severity: FailureSeverity) -> String {
    let action = match severity {
        FailureSeverity::Critical => "This blocks a core React workflow. Fix is in progress.",
        FailureSeverity::High => "This impacts common workflows. A fix or workaround is planned.",
        FailureSeverity::Medium => "This affects some workflows. A workaround may be available.",
        FailureSeverity::Low => "This is a minor or edge-case difference.",
        FailureSeverity::Info => "This is an informational difference with no user impact.",
    };

    let description = match class {
        FailureClass::TransformBug => {
            "The JSX/TSX transform produces different output than expected. This is an engine-side bug in the compilation pipeline."
        }
        FailureClass::ResolverBug => {
            "The module resolver cannot locate a React dependency. This is an engine-side bug in the resolution pipeline."
        }
        FailureClass::RuntimeSemanticGap => {
            "The engine does not yet implement a JavaScript/React semantic feature required by this code."
        }
        FailureClass::UnsupportedEnvironment => {
            "A platform API required by this code is not available in the FrankenEngine environment."
        }
        FailureClass::PackageMisuse => {
            "This failure appears to be caused by a package version mismatch or misconfiguration."
        }
        FailureClass::HookInvariantViolation => {
            "React hook ordering or lifecycle rules are not correctly enforced by the engine."
        }
        FailureClass::HydrationMismatch => {
            "Server-rendered HTML and client-side hydration output do not match."
        }
        FailureClass::SuspenseDivergence => {
            "Suspense boundary behavior differs from standard React."
        }
        FailureClass::ErrorBoundaryFailure => {
            "Error boundary propagation does not match standard React behavior."
        }
        FailureClass::Unclassified => {
            "This failure has not yet been classified. It is under investigation."
        }
    };

    format!("{description} {action}")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn compute_catalog_hash(entries: &[TriageEntry], summary: &CatalogSummary) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_VERSION.as_bytes());
    hasher.update(summary.total_entries.to_le_bytes().as_slice());
    hasher.update(summary.unresolved_count.to_le_bytes().as_slice());
    hasher.update(summary.engine_bug_count.to_le_bytes().as_slice());
    hasher.update(summary.severity_weighted_score.to_le_bytes().as_slice());
    for entry in entries {
        hasher.update(entry.content_hash.as_bytes());
    }
    let digest = hasher.finalize();
    ContentHash::from_bytes(digest.into())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_repro() -> MinimizedRepro {
        MinimizedRepro::build(
            "import React from 'react';\nfunction App() { return <div />; }",
            "Should compile to createElement call",
            "Produces invalid output",
            BTreeSet::from(["18.2.0".to_string()]),
            "frankenctl compile --input repro.tsx --goal module",
        )
    }

    fn sample_owner() -> OwnerRoute {
        OwnerRoute {
            bead_id: "bd-1lsy.3.6.1".to_string(),
            team: "jsx-transform".to_string(),
            rationale: "Transform bug in JSX pipeline".to_string(),
        }
    }

    fn sample_entry() -> TriageEntry {
        TriageEntry::build(
            FailureClass::TransformBug,
            FailureSeverity::High,
            sample_owner(),
            sample_repro(),
            "JSX transform produces incorrect output.",
        )
    }

    #[test]
    fn failure_class_all_variants_unique() {
        let all = FailureClass::all();
        let set: BTreeSet<_> = all.iter().collect();
        assert_eq!(all.len(), set.len());
    }

    #[test]
    fn failure_class_as_str_not_empty() {
        for class in FailureClass::all() {
            assert!(!class.as_str().is_empty());
        }
    }

    #[test]
    fn failure_class_display_matches_as_str() {
        for class in FailureClass::all() {
            assert_eq!(class.to_string(), class.as_str());
        }
    }

    #[test]
    fn engine_bug_classification() {
        assert!(FailureClass::TransformBug.is_engine_bug());
        assert!(FailureClass::ResolverBug.is_engine_bug());
        assert!(FailureClass::RuntimeSemanticGap.is_engine_bug());
        assert!(!FailureClass::UnsupportedEnvironment.is_engine_bug());
        assert!(!FailureClass::PackageMisuse.is_engine_bug());
        assert!(FailureClass::HookInvariantViolation.is_engine_bug());
        assert!(FailureClass::HydrationMismatch.is_engine_bug());
        assert!(!FailureClass::Unclassified.is_engine_bug());
    }

    #[test]
    fn severity_weight_ordering() {
        assert!(FailureSeverity::Critical.weight() > FailureSeverity::High.weight());
        assert!(FailureSeverity::High.weight() > FailureSeverity::Medium.weight());
        assert!(FailureSeverity::Medium.weight() > FailureSeverity::Low.weight());
        assert!(FailureSeverity::Low.weight() > FailureSeverity::Info.weight());
    }

    #[test]
    fn severity_display() {
        assert_eq!(FailureSeverity::Critical.to_string(), "critical");
        assert_eq!(FailureSeverity::Info.to_string(), "info");
    }

    #[test]
    fn minimized_repro_build_deterministic() {
        let r1 = sample_repro();
        let r2 = sample_repro();
        assert_eq!(r1.source_hash, r2.source_hash);
        assert_eq!(r1.repro_id, r2.repro_id);
        assert!(r1.deterministic);
    }

    #[test]
    fn minimized_repro_truncates_long_source() {
        let long_source = "x".repeat(MAX_REPRO_SOURCE_LEN + 1000);
        let repro =
            MinimizedRepro::build(&long_source, "expected", "actual", BTreeSet::new(), "cmd");
        assert_eq!(repro.source.len(), MAX_REPRO_SOURCE_LEN);
    }

    #[test]
    fn triage_entry_build_has_content_hash() {
        let entry = sample_entry();
        assert!(!entry.entry_id.is_empty());
        assert!(entry.unresolved);
        // Content hash should be non-zero
        assert_ne!(entry.content_hash.to_string(), "");
    }

    #[test]
    fn triage_entry_serde_roundtrip() {
        let entry = sample_entry();
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: TriageEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, parsed);
    }

    #[test]
    fn catalog_build_empty() {
        let catalog = ReproCatalog::build(Vec::new(), SecurityEpoch::from_raw(1));
        assert_eq!(catalog.entries.len(), 0);
        assert_eq!(catalog.summary.total_entries, 0);
        assert_eq!(catalog.summary.unresolved_count, 0);
        assert!(catalog.verify_integrity());
    }

    #[test]
    fn catalog_build_single_entry() {
        let entry = sample_entry();
        let catalog = ReproCatalog::build(vec![entry.clone()], SecurityEpoch::from_raw(1));
        assert_eq!(catalog.entries.len(), 1);
        assert_eq!(catalog.summary.total_entries, 1);
        assert_eq!(catalog.summary.engine_bug_count, 1);
        assert!(catalog.verify_integrity());
    }

    #[test]
    fn catalog_sorted_by_severity() {
        let critical = TriageEntry::build(
            FailureClass::TransformBug,
            FailureSeverity::Critical,
            sample_owner(),
            sample_repro(),
            "critical",
        );
        let low = TriageEntry::build(
            FailureClass::PackageMisuse,
            FailureSeverity::Low,
            default_owner_route(FailureClass::PackageMisuse),
            MinimizedRepro::build("low", "e", "a", BTreeSet::new(), "cmd"),
            "low",
        );
        let catalog = ReproCatalog::build(vec![low, critical], SecurityEpoch::from_raw(1));
        assert_eq!(catalog.entries[0].severity, FailureSeverity::Critical);
    }

    #[test]
    fn catalog_summary_counts() {
        let entries = vec![
            sample_entry(),
            TriageEntry::build(
                FailureClass::PackageMisuse,
                FailureSeverity::Low,
                default_owner_route(FailureClass::PackageMisuse),
                MinimizedRepro::build("misuse", "e", "a", BTreeSet::new(), "cmd"),
                "misuse advisory",
            ),
        ];
        let catalog = ReproCatalog::build(entries, SecurityEpoch::from_raw(1));
        assert_eq!(catalog.summary.total_entries, 2);
        assert_eq!(catalog.summary.engine_bug_count, 1); // TransformBug only
        assert_eq!(catalog.summary.unresolved_count, 2);
        assert_eq!(catalog.summary.distinct_owners, 2);
    }

    #[test]
    fn catalog_filters_by_class() {
        let entries = vec![
            sample_entry(),
            TriageEntry::build(
                FailureClass::ResolverBug,
                FailureSeverity::Medium,
                default_owner_route(FailureClass::ResolverBug),
                MinimizedRepro::build("resolver", "e", "a", BTreeSet::new(), "cmd"),
                "resolver advisory",
            ),
        ];
        let catalog = ReproCatalog::build(entries, SecurityEpoch::from_raw(1));
        assert_eq!(
            catalog.entries_by_class(FailureClass::TransformBug).len(),
            1
        );
        assert_eq!(catalog.entries_by_class(FailureClass::ResolverBug).len(), 1);
        assert_eq!(
            catalog.entries_by_class(FailureClass::PackageMisuse).len(),
            0
        );
    }

    #[test]
    fn catalog_filters_by_severity() {
        let catalog = ReproCatalog::build(vec![sample_entry()], SecurityEpoch::from_raw(1));
        assert_eq!(catalog.entries_by_severity(FailureSeverity::High).len(), 1);
        assert_eq!(catalog.entries_by_severity(FailureSeverity::Low).len(), 0);
    }

    #[test]
    fn catalog_has_critical_engine_bugs() {
        let critical = TriageEntry::build(
            FailureClass::TransformBug,
            FailureSeverity::Critical,
            sample_owner(),
            sample_repro(),
            "critical",
        );
        let catalog = ReproCatalog::build(vec![critical], SecurityEpoch::from_raw(1));
        assert!(catalog.has_critical_engine_bugs());
    }

    #[test]
    fn catalog_no_critical_when_all_resolved() {
        let mut entry = TriageEntry::build(
            FailureClass::TransformBug,
            FailureSeverity::Critical,
            sample_owner(),
            sample_repro(),
            "critical",
        );
        entry.unresolved = false;
        let catalog = ReproCatalog::build(vec![entry], SecurityEpoch::from_raw(1));
        assert!(!catalog.has_critical_engine_bugs());
    }

    #[test]
    fn classify_failure_priority_order() {
        // Hook violation takes priority
        assert_eq!(
            classify_failure(&FailureSymptoms {
                has_transform_diff: true,
                has_resolver_error: true,
                has_runtime_gap: true,
                has_env_boundary: true,
                has_version_mismatch: true,
                has_hook_violation: true,
                has_hydration_diff: true,
                has_suspense_diff: true,
                has_error_boundary_diff: true,
            }),
            FailureClass::HookInvariantViolation
        );
        // Hydration next
        assert_eq!(
            classify_failure(&FailureSymptoms {
                has_transform_diff: true,
                has_resolver_error: true,
                has_runtime_gap: true,
                has_env_boundary: true,
                has_version_mismatch: true,
                has_hook_violation: false,
                has_hydration_diff: true,
                has_suspense_diff: true,
                has_error_boundary_diff: true,
            }),
            FailureClass::HydrationMismatch
        );
        // Transform when no higher-priority
        assert_eq!(
            classify_failure(&FailureSymptoms {
                has_transform_diff: true,
                ..FailureSymptoms::default()
            }),
            FailureClass::TransformBug
        );
        // Unclassified when all false
        assert_eq!(
            classify_failure(&FailureSymptoms::default()),
            FailureClass::Unclassified
        );
    }

    #[test]
    fn assign_severity_critical_engine_bug() {
        assert_eq!(
            assign_severity(FailureClass::TransformBug, true, false, false),
            FailureSeverity::Critical
        );
    }

    #[test]
    fn assign_severity_high_no_workaround() {
        assert_eq!(
            assign_severity(FailureClass::ResolverBug, false, false, false),
            FailureSeverity::High
        );
    }

    #[test]
    fn assign_severity_medium_with_workaround() {
        assert_eq!(
            assign_severity(FailureClass::RuntimeSemanticGap, false, true, false),
            FailureSeverity::Medium
        );
    }

    #[test]
    fn assign_severity_low_non_engine() {
        assert_eq!(
            assign_severity(FailureClass::PackageMisuse, false, false, false),
            FailureSeverity::Low
        );
    }

    #[test]
    fn default_owner_route_all_classes() {
        for class in FailureClass::all() {
            let owner = default_owner_route(*class);
            assert!(!owner.bead_id.is_empty());
            assert!(!owner.team.is_empty());
            assert!(!owner.rationale.is_empty());
        }
    }

    #[test]
    fn generate_advisory_not_empty() {
        for class in FailureClass::all() {
            for sev in [
                FailureSeverity::Critical,
                FailureSeverity::High,
                FailureSeverity::Medium,
                FailureSeverity::Low,
                FailureSeverity::Info,
            ] {
                let advisory = generate_advisory(*class, sev);
                assert!(!advisory.is_empty());
            }
        }
    }

    #[test]
    fn build_triage_event_structure() {
        let entry = sample_entry();
        let event = build_triage_event("trace-001", "decision-001", "scenario-001", &entry);
        assert_eq!(event.component, COMPONENT);
        assert_eq!(event.policy_id, POLICY_ID);
        assert_eq!(event.failure_class, "transform_bug");
        assert_eq!(event.severity, "high");
        assert_eq!(event.outcome, "unresolved");
        assert!(event.error_code.is_some());
    }

    #[test]
    fn triage_event_resolved_no_error_code() {
        let mut entry = sample_entry();
        entry.unresolved = false;
        let event = build_triage_event("trace", "decision", "scenario", &entry);
        assert_eq!(event.outcome, "resolved");
        assert!(event.error_code.is_none());
    }

    #[test]
    fn catalog_serde_roundtrip() {
        let catalog = ReproCatalog::build(vec![sample_entry()], SecurityEpoch::from_raw(1));
        let json = serde_json::to_string_pretty(&catalog).unwrap();
        let parsed: ReproCatalog = serde_json::from_str(&json).unwrap();
        assert_eq!(catalog, parsed);
    }

    #[test]
    fn schema_constants_non_empty() {
        assert!(!SCHEMA_VERSION.is_empty());
        assert!(!BEAD_ID.is_empty());
        assert!(!POLICY_ID.is_empty());
        assert!(!COMPONENT.is_empty());
    }

    // ── enrichment: failure class exhaustiveness ──────────────────

    #[test]
    fn failure_class_all_has_ten_variants() {
        assert_eq!(FailureClass::all().len(), 10);
    }

    #[test]
    fn failure_class_as_str_all_snake_case() {
        for class in FailureClass::all() {
            let s = class.as_str();
            assert!(
                s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "failure class '{}' is not snake_case",
                s
            );
        }
    }

    #[test]
    fn failure_class_serde_roundtrip_all_variants() {
        for class in FailureClass::all() {
            let json = serde_json::to_string(class).unwrap();
            let decoded: FailureClass = serde_json::from_str(&json).unwrap();
            assert_eq!(*class, decoded);
        }
    }

    #[test]
    fn failure_class_suspense_and_error_boundary_are_engine_bugs() {
        assert!(FailureClass::SuspenseDivergence.is_engine_bug());
        assert!(FailureClass::ErrorBoundaryFailure.is_engine_bug());
    }

    // ── enrichment: severity properties ───────────────────────────

    #[test]
    fn severity_all_variants_have_distinct_as_str() {
        let strs: BTreeSet<&str> = [
            FailureSeverity::Critical,
            FailureSeverity::High,
            FailureSeverity::Medium,
            FailureSeverity::Low,
            FailureSeverity::Info,
        ]
        .iter()
        .map(|s| s.as_str())
        .collect();
        assert_eq!(strs.len(), 5);
    }

    #[test]
    fn severity_display_matches_as_str() {
        for sev in [
            FailureSeverity::Critical,
            FailureSeverity::High,
            FailureSeverity::Medium,
            FailureSeverity::Low,
            FailureSeverity::Info,
        ] {
            assert_eq!(sev.to_string(), sev.as_str());
        }
    }

    #[test]
    fn severity_serde_roundtrip_all_variants() {
        for sev in [
            FailureSeverity::Critical,
            FailureSeverity::High,
            FailureSeverity::Medium,
            FailureSeverity::Low,
            FailureSeverity::Info,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let decoded: FailureSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, decoded);
        }
    }

    #[test]
    fn severity_weights_are_all_distinct() {
        let weights: BTreeSet<u32> = [
            FailureSeverity::Critical,
            FailureSeverity::High,
            FailureSeverity::Medium,
            FailureSeverity::Low,
            FailureSeverity::Info,
        ]
        .iter()
        .map(|s| s.weight())
        .collect();
        assert_eq!(weights.len(), 5);
    }

    // ── enrichment: minimized repro ───────────────────────────────

    #[test]
    fn minimized_repro_repro_id_starts_with_prefix() {
        let repro = sample_repro();
        assert!(
            repro.repro_id.starts_with("repro-"),
            "repro_id should start with 'repro-'"
        );
    }

    #[test]
    fn minimized_repro_source_hash_is_deterministic() {
        let r1 = MinimizedRepro::build("source", "expected", "actual", BTreeSet::new(), "cmd");
        let r2 = MinimizedRepro::build("source", "expected", "actual", BTreeSet::new(), "cmd");
        assert_eq!(r1.source_hash, r2.source_hash);
    }

    #[test]
    fn minimized_repro_different_source_different_hash() {
        let r1 = MinimizedRepro::build("source-a", "expected", "actual", BTreeSet::new(), "cmd");
        let r2 = MinimizedRepro::build("source-b", "expected", "actual", BTreeSet::new(), "cmd");
        assert_ne!(r1.source_hash, r2.source_hash);
    }

    #[test]
    fn minimized_repro_preserves_react_versions() {
        let versions = BTreeSet::from(["18.2.0".to_string(), "18.3.0".to_string()]);
        let repro = MinimizedRepro::build("src", "e", "a", versions.clone(), "cmd");
        assert_eq!(repro.react_versions, versions);
    }

    #[test]
    fn minimized_repro_empty_source() {
        let repro = MinimizedRepro::build("", "e", "a", BTreeSet::new(), "cmd");
        assert!(repro.source.is_empty());
        assert!(repro.deterministic);
    }

    #[test]
    fn minimized_repro_serde_roundtrip() {
        let repro = sample_repro();
        let json = serde_json::to_string(&repro).unwrap();
        let decoded: MinimizedRepro = serde_json::from_str(&json).unwrap();
        assert_eq!(repro, decoded);
    }

    // ── enrichment: triage entry ──────────────────────────────────

    #[test]
    fn triage_entry_id_contains_failure_class() {
        let entry = sample_entry();
        assert!(
            entry.entry_id.contains("transform_bug"),
            "entry_id should contain the failure class"
        );
    }

    #[test]
    fn triage_entry_truncates_long_advisory() {
        let long_advisory = "x".repeat(MAX_ADVISORY_LEN + 500);
        let entry = TriageEntry::build(
            FailureClass::TransformBug,
            FailureSeverity::High,
            sample_owner(),
            sample_repro(),
            &long_advisory,
        );
        assert_eq!(entry.advisory.len(), MAX_ADVISORY_LEN);
    }

    #[test]
    fn triage_entry_content_hash_deterministic() {
        let e1 = sample_entry();
        let e2 = sample_entry();
        assert_eq!(e1.content_hash, e2.content_hash);
    }

    #[test]
    fn triage_entry_different_class_different_hash() {
        let e1 = TriageEntry::build(
            FailureClass::TransformBug,
            FailureSeverity::High,
            sample_owner(),
            sample_repro(),
            "advisory",
        );
        let e2 = TriageEntry::build(
            FailureClass::ResolverBug,
            FailureSeverity::High,
            sample_owner(),
            sample_repro(),
            "advisory",
        );
        assert_ne!(e1.content_hash, e2.content_hash);
    }

    // ── enrichment: catalog properties ────────────────────────────

    #[test]
    fn catalog_verify_integrity_single_entry() {
        let catalog = ReproCatalog::build(vec![sample_entry()], SecurityEpoch::from_raw(1));
        assert!(catalog.verify_integrity());
    }

    #[test]
    fn catalog_schema_version_matches_constant() {
        let catalog = ReproCatalog::build(vec![], SecurityEpoch::from_raw(1));
        assert_eq!(catalog.schema_version, SCHEMA_VERSION);
        assert_eq!(catalog.bead_id, BEAD_ID);
        assert_eq!(catalog.policy_id, POLICY_ID);
        assert_eq!(catalog.component, COMPONENT);
    }

    #[test]
    fn catalog_by_class_counts_sum_to_total() {
        let entries = vec![
            sample_entry(),
            TriageEntry::build(
                FailureClass::ResolverBug,
                FailureSeverity::Medium,
                default_owner_route(FailureClass::ResolverBug),
                MinimizedRepro::build("res", "e", "a", BTreeSet::new(), "cmd"),
                "resolver advisory",
            ),
        ];
        let catalog = ReproCatalog::build(entries, SecurityEpoch::from_raw(1));
        let sum: usize = catalog.summary.by_class.values().sum();
        assert_eq!(sum, catalog.summary.total_entries);
    }

    #[test]
    fn catalog_by_severity_counts_sum_to_total() {
        let entries = vec![
            sample_entry(),
            TriageEntry::build(
                FailureClass::PackageMisuse,
                FailureSeverity::Low,
                default_owner_route(FailureClass::PackageMisuse),
                MinimizedRepro::build("pkg", "e", "a", BTreeSet::new(), "cmd"),
                "misuse advisory",
            ),
        ];
        let catalog = ReproCatalog::build(entries, SecurityEpoch::from_raw(1));
        let sum: usize = catalog.summary.by_severity.values().sum();
        assert_eq!(sum, catalog.summary.total_entries);
    }

    #[test]
    fn catalog_severity_weighted_score_increases_with_severity() {
        let low_catalog = ReproCatalog::build(
            vec![TriageEntry::build(
                FailureClass::PackageMisuse,
                FailureSeverity::Low,
                default_owner_route(FailureClass::PackageMisuse),
                MinimizedRepro::build("low", "e", "a", BTreeSet::new(), "cmd"),
                "low",
            )],
            SecurityEpoch::from_raw(1),
        );
        let high_catalog = ReproCatalog::build(
            vec![TriageEntry::build(
                FailureClass::TransformBug,
                FailureSeverity::Critical,
                sample_owner(),
                sample_repro(),
                "critical",
            )],
            SecurityEpoch::from_raw(1),
        );
        assert!(
            high_catalog.summary.severity_weighted_score
                > low_catalog.summary.severity_weighted_score
        );
    }

    // ── enrichment: classify_failure individual symptoms ──────────

    #[test]
    fn classify_failure_resolver_only() {
        assert_eq!(
            classify_failure(&FailureSymptoms {
                has_resolver_error: true,
                ..FailureSymptoms::default()
            }),
            FailureClass::ResolverBug
        );
    }

    #[test]
    fn classify_failure_runtime_gap_only() {
        assert_eq!(
            classify_failure(&FailureSymptoms {
                has_runtime_gap: true,
                ..FailureSymptoms::default()
            }),
            FailureClass::RuntimeSemanticGap
        );
    }

    #[test]
    fn classify_failure_env_boundary_only() {
        assert_eq!(
            classify_failure(&FailureSymptoms {
                has_env_boundary: true,
                ..FailureSymptoms::default()
            }),
            FailureClass::UnsupportedEnvironment
        );
    }

    #[test]
    fn classify_failure_version_mismatch_only() {
        assert_eq!(
            classify_failure(&FailureSymptoms {
                has_version_mismatch: true,
                ..FailureSymptoms::default()
            }),
            FailureClass::PackageMisuse
        );
    }

    #[test]
    fn classify_failure_suspense_only() {
        assert_eq!(
            classify_failure(&FailureSymptoms {
                has_suspense_diff: true,
                ..FailureSymptoms::default()
            }),
            FailureClass::SuspenseDivergence
        );
    }

    #[test]
    fn classify_failure_error_boundary_only() {
        assert_eq!(
            classify_failure(&FailureSymptoms {
                has_error_boundary_diff: true,
                ..FailureSymptoms::default()
            }),
            FailureClass::ErrorBoundaryFailure
        );
    }

    // ── enrichment: assign_severity edge cases ────────────────────

    #[test]
    fn assign_severity_info_when_resolved() {
        assert_eq!(
            assign_severity(FailureClass::TransformBug, false, false, true),
            FailureSeverity::Info
        );
    }

    #[test]
    fn assign_severity_unclassified_is_low() {
        assert_eq!(
            assign_severity(FailureClass::Unclassified, false, false, false),
            FailureSeverity::Low
        );
    }

    // ── enrichment: owner route properties ────────────────────────

    #[test]
    fn owner_route_serde_roundtrip() {
        let owner = sample_owner();
        let json = serde_json::to_string(&owner).unwrap();
        let decoded: OwnerRoute = serde_json::from_str(&json).unwrap();
        assert_eq!(owner, decoded);
    }

    #[test]
    fn default_owner_routes_have_distinct_teams_for_different_classes() {
        let transform_owner = default_owner_route(FailureClass::TransformBug);
        let resolver_owner = default_owner_route(FailureClass::ResolverBug);
        // Different classes may have different teams (not guaranteed, but likely)
        assert!(!transform_owner.team.is_empty());
        assert!(!resolver_owner.team.is_empty());
    }

    // ── enrichment: triage event details ──────────────────────────

    #[test]
    fn build_triage_event_trace_ids_propagated() {
        let entry = sample_entry();
        let event = build_triage_event("trace-42", "decision-42", "scenario-42", &entry);
        assert_eq!(event.trace_id, "trace-42");
        assert_eq!(event.decision_id, "decision-42");
    }

    #[test]
    fn build_triage_event_owner_bead_included() {
        let entry = sample_entry();
        let event = build_triage_event("t", "d", "s", &entry);
        assert_eq!(event.owner_bead, entry.owner.bead_id);
    }

    // ── enrichment: advisory generation ───────────────────────────

    #[test]
    fn generate_advisory_contains_class_name() {
        let advisory = generate_advisory(FailureClass::TransformBug, FailureSeverity::Critical);
        assert!(
            advisory.contains("transform") || advisory.contains("Transform"),
            "advisory should reference the failure class"
        );
    }

    #[test]
    fn generate_advisory_bounded_length() {
        for class in FailureClass::all() {
            for sev in [
                FailureSeverity::Critical,
                FailureSeverity::High,
                FailureSeverity::Medium,
                FailureSeverity::Low,
                FailureSeverity::Info,
            ] {
                let advisory = generate_advisory(*class, sev);
                assert!(
                    advisory.len() <= MAX_ADVISORY_LEN,
                    "advisory for {:?}/{:?} exceeds max length",
                    class,
                    sev
                );
            }
        }
    }

    // ── enrichment: catalog summary ───────────────────────────────

    #[test]
    fn catalog_summary_serde_roundtrip() {
        let catalog = ReproCatalog::build(vec![sample_entry()], SecurityEpoch::from_raw(1));
        let json = serde_json::to_string(&catalog.summary).unwrap();
        let decoded: CatalogSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(catalog.summary, decoded);
    }

    #[test]
    fn schema_version_starts_with_franken_engine() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    }
}
