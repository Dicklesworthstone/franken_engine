#![forbid(unsafe_code)]
//! Lifecycle scenario and containment test migration to upstream-frankenlab-backed
//! harnesses and oracles.
//!
//! Bead: bd-3nr.1.4.2 \[10.13X.D2\]
//!
//! Migrates lifecycle and containment validation from local mock-centric harnesses
//! toward the upstream-frankenlab-backed harness/oracle model established by the
//! bridge contract (bd-3nr.1.4.1). This module operationalizes the biggest
//! correctness/reliability opportunity from the gap matrix audit: using
//! deterministic seed-based replay, oracle-backed invariant checking, and
//! upstream-compatible evidence linkage for all lifecycle paths.
//!
//! The migration covers:
//! 1. **Scenario migration status** — tracking which lifecycle scenarios have been
//!    migrated from local-only to upstream-backed execution.
//! 2. **Harness adapter** — translating between local `LabRuntime`/`Verdict` types
//!    and the bridge contract's `TraceCertificate`/`ReplayVerdict` types.
//! 3. **Oracle migration** — tracking which oracle invariants are checked locally
//!    vs. dispatched through the bridge.
//! 4. **Containment test registry** — cataloging containment tests with their
//!    migration status and upstream coverage.
//! 5. **Migration report** — structured assessment of migration progress.
//!
//! Plan references: Section 10.13X item D2.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the harness migration format.
pub const HARNESS_MIGRATION_SCHEMA_VERSION: &str = "franken-engine.frankenlab-harness-migration.v1";

/// Bead identifier for this module.
pub const HARNESS_MIGRATION_BEAD_ID: &str = "bd-3nr.1.4.2";

/// Fixed-point scale (1_000_000 = 100%).
const SCALE: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// MigrationStatus — per-scenario migration state
// ---------------------------------------------------------------------------

/// Migration status for a single lifecycle scenario or containment test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStatus {
    /// Not yet started — still using local-only harness.
    LocalOnly,
    /// In progress — bridge adapter wired but oracles not yet validated.
    InProgress,
    /// Migrated — using upstream-backed harness with oracle validation.
    Migrated,
    /// Verified — migrated and cross-validated against local results.
    Verified,
    /// Deferred — migration not feasible or not needed.
    Deferred,
}

impl MigrationStatus {
    /// Whether this status indicates the scenario is on the upstream path.
    pub fn is_upstream_backed(&self) -> bool {
        matches!(self, Self::Migrated | Self::Verified)
    }

    /// Whether migration work is still needed.
    pub fn needs_work(&self) -> bool {
        matches!(self, Self::LocalOnly | Self::InProgress)
    }
}

impl fmt::Display for MigrationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalOnly => write!(f, "local_only"),
            Self::InProgress => write!(f, "in_progress"),
            Self::Migrated => write!(f, "migrated"),
            Self::Verified => write!(f, "verified"),
            Self::Deferred => write!(f, "deferred"),
        }
    }
}

// ---------------------------------------------------------------------------
// LifecycleScenarioId — identifies lifecycle paths
// ---------------------------------------------------------------------------

/// Identifies a specific lifecycle scenario path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleScenarioId {
    /// Extension startup and region creation.
    Startup,
    /// Graceful shutdown with quiescent close.
    NormalShutdown,
    /// Forced cancellation mid-operation.
    ForcedCancel,
    /// Policy violation leading to quarantine isolation.
    Quarantine,
    /// Capability revocation during active session.
    Revocation,
    /// Control-plane failure with safe degradation.
    DegradedMode,
    /// Multiple extensions with cross-extension isolation.
    MultiExtension,
    /// Budget exhaustion during cell close.
    BudgetExhaustion,
    /// Nested child context propagation.
    ChildContextPropagation,
    /// Evidence chain integrity across lifecycle.
    EvidenceChainIntegrity,
}

impl LifecycleScenarioId {
    /// All scenarios in deterministic order.
    pub const ALL: [Self; 10] = [
        Self::Startup,
        Self::NormalShutdown,
        Self::ForcedCancel,
        Self::Quarantine,
        Self::Revocation,
        Self::DegradedMode,
        Self::MultiExtension,
        Self::BudgetExhaustion,
        Self::ChildContextPropagation,
        Self::EvidenceChainIntegrity,
    ];
}

impl fmt::Display for LifecycleScenarioId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Startup => write!(f, "startup"),
            Self::NormalShutdown => write!(f, "normal_shutdown"),
            Self::ForcedCancel => write!(f, "forced_cancel"),
            Self::Quarantine => write!(f, "quarantine"),
            Self::Revocation => write!(f, "revocation"),
            Self::DegradedMode => write!(f, "degraded_mode"),
            Self::MultiExtension => write!(f, "multi_extension"),
            Self::BudgetExhaustion => write!(f, "budget_exhaustion"),
            Self::ChildContextPropagation => write!(f, "child_context_propagation"),
            Self::EvidenceChainIntegrity => write!(f, "evidence_chain_integrity"),
        }
    }
}

// ---------------------------------------------------------------------------
// ScenarioMigrationEntry — one scenario's migration record
// ---------------------------------------------------------------------------

/// Migration record for a single lifecycle scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioMigrationEntry {
    /// Which scenario.
    pub scenario_id: LifecycleScenarioId,
    /// Current migration status.
    pub status: MigrationStatus,
    /// Local harness used (module path).
    pub local_harness: String,
    /// Upstream harness target (if applicable).
    pub upstream_harness: Option<String>,
    /// Oracle invariants checked locally.
    pub local_oracles: BTreeSet<String>,
    /// Oracle invariants dispatched through bridge.
    pub bridge_oracles: BTreeSet<String>,
    /// Whether replay determinism is verified.
    pub replay_verified: bool,
    /// Whether evidence linkage is established.
    pub evidence_linked: bool,
    /// Human-readable migration notes.
    pub notes: String,
}

impl ScenarioMigrationEntry {
    /// Create a new entry in LocalOnly status.
    pub fn local_only(scenario_id: LifecycleScenarioId, local_harness: &str) -> Self {
        Self {
            scenario_id,
            status: MigrationStatus::LocalOnly,
            local_harness: local_harness.to_owned(),
            upstream_harness: None,
            local_oracles: BTreeSet::new(),
            bridge_oracles: BTreeSet::new(),
            replay_verified: false,
            evidence_linked: false,
            notes: String::new(),
        }
    }

    /// Total oracle count (local + bridge).
    pub fn total_oracles(&self) -> usize {
        self.local_oracles.len() + self.bridge_oracles.len()
    }

    /// Fraction of oracles dispatched through bridge, in millionths.
    pub fn bridge_oracle_fraction_millionths(&self) -> u64 {
        let total = self.total_oracles();
        if total == 0 {
            return 0;
        }
        (self.bridge_oracles.len() as u64) * SCALE / (total as u64)
    }

    /// Whether all oracles are bridge-dispatched.
    pub fn all_oracles_bridged(&self) -> bool {
        !self.bridge_oracles.is_empty() && self.local_oracles.is_empty()
    }

    /// Mark as migrated.
    pub fn mark_migrated(&mut self, upstream_harness: &str) {
        self.status = MigrationStatus::Migrated;
        self.upstream_harness = Some(upstream_harness.to_owned());
    }

    /// Mark as verified (cross-validated).
    pub fn mark_verified(&mut self) {
        self.status = MigrationStatus::Verified;
        self.replay_verified = true;
        self.evidence_linked = true;
    }
}

// ---------------------------------------------------------------------------
// ContainmentTestKind — types of containment tests
// ---------------------------------------------------------------------------

/// Types of containment tests that need migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentTestKind {
    /// Region isolation under fault injection.
    RegionIsolation,
    /// Budget enforcement at cell boundaries.
    BudgetEnforcement,
    /// Capability narrowing across spawn boundaries.
    CapabilityNarrowing,
    /// Evidence chain completeness under cancellation.
    EvidenceCompleteness,
    /// Quarantine containment after policy violation.
    QuarantineContainment,
    /// Outcome propagation correctness.
    OutcomePropagation,
    /// Cancellation lifecycle compliance.
    CancellationCompliance,
    /// Mock seam absence in production paths.
    MockSeamAbsence,
}

impl ContainmentTestKind {
    /// All variants in deterministic order.
    pub const ALL: [Self; 8] = [
        Self::RegionIsolation,
        Self::BudgetEnforcement,
        Self::CapabilityNarrowing,
        Self::EvidenceCompleteness,
        Self::QuarantineContainment,
        Self::OutcomePropagation,
        Self::CancellationCompliance,
        Self::MockSeamAbsence,
    ];
}

impl fmt::Display for ContainmentTestKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegionIsolation => write!(f, "region_isolation"),
            Self::BudgetEnforcement => write!(f, "budget_enforcement"),
            Self::CapabilityNarrowing => write!(f, "capability_narrowing"),
            Self::EvidenceCompleteness => write!(f, "evidence_completeness"),
            Self::QuarantineContainment => write!(f, "quarantine_containment"),
            Self::OutcomePropagation => write!(f, "outcome_propagation"),
            Self::CancellationCompliance => write!(f, "cancellation_compliance"),
            Self::MockSeamAbsence => write!(f, "mock_seam_absence"),
        }
    }
}

// ---------------------------------------------------------------------------
// ContainmentTestEntry — one containment test's migration record
// ---------------------------------------------------------------------------

/// Migration record for a single containment test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentTestEntry {
    /// Test kind.
    pub kind: ContainmentTestKind,
    /// Current migration status.
    pub status: MigrationStatus,
    /// Source test file (relative path).
    pub source_file: String,
    /// Number of test cases in local suite.
    pub local_test_count: usize,
    /// Number of test cases migrated to upstream harness.
    pub upstream_test_count: usize,
    /// Whether the test uses mock context (MockCx/MockBudget).
    pub uses_mock_context: bool,
    /// Whether the test is covered by an upstream oracle.
    pub oracle_covered: bool,
    /// Migration notes.
    pub notes: String,
}

impl ContainmentTestEntry {
    /// Create a new entry.
    pub fn new(kind: ContainmentTestKind, source_file: &str, local_test_count: usize) -> Self {
        Self {
            kind,
            status: MigrationStatus::LocalOnly,
            source_file: source_file.to_owned(),
            local_test_count,
            upstream_test_count: 0,
            uses_mock_context: false,
            oracle_covered: false,
            notes: String::new(),
        }
    }

    /// Migration coverage fraction in millionths.
    pub fn migration_coverage_millionths(&self) -> u64 {
        if self.local_test_count == 0 {
            return 0;
        }
        (self.upstream_test_count as u64) * SCALE / (self.local_test_count as u64)
    }

    /// Whether fully migrated.
    pub fn fully_migrated(&self) -> bool {
        self.upstream_test_count >= self.local_test_count && self.status.is_upstream_backed()
    }
}

// ---------------------------------------------------------------------------
// HarnessMigrationRegistry — tracks all migrations
// ---------------------------------------------------------------------------

/// Registry tracking migration of all lifecycle scenarios and containment
/// tests from local to upstream-backed harnesses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessMigrationRegistry {
    /// Schema version.
    pub schema_version: String,
    /// Security epoch at which the registry was created.
    pub epoch: SecurityEpoch,
    /// Per-scenario migration entries.
    pub scenarios: Vec<ScenarioMigrationEntry>,
    /// Per-containment-test migration entries.
    pub containment_tests: Vec<ContainmentTestEntry>,
}

impl HarnessMigrationRegistry {
    /// Create an empty registry.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            schema_version: HARNESS_MIGRATION_SCHEMA_VERSION.to_owned(),
            epoch,
            scenarios: Vec::new(),
            containment_tests: Vec::new(),
        }
    }

    /// Create a registry pre-populated with default lifecycle scenarios.
    pub fn with_default_scenarios(epoch: SecurityEpoch) -> Self {
        let mut reg = Self::new(epoch);

        // Register all lifecycle scenarios with their local harness
        for scenario_id in LifecycleScenarioId::ALL {
            let local_harness = match scenario_id {
                LifecycleScenarioId::Startup
                | LifecycleScenarioId::NormalShutdown
                | LifecycleScenarioId::ForcedCancel
                | LifecycleScenarioId::Quarantine
                | LifecycleScenarioId::Revocation
                | LifecycleScenarioId::DegradedMode
                | LifecycleScenarioId::MultiExtension => "frankenlab_extension_lifecycle",
                LifecycleScenarioId::BudgetExhaustion => "budget_propagation_contract",
                LifecycleScenarioId::ChildContextPropagation => "budget_propagation_contract",
                LifecycleScenarioId::EvidenceChainIntegrity => "evidence_replay_checker",
            };
            reg.scenarios.push(ScenarioMigrationEntry::local_only(
                scenario_id,
                local_harness,
            ));
        }

        // Register default containment test kinds
        let containment_sources = [
            (
                ContainmentTestKind::RegionIsolation,
                "tests/frankenlab_extension_lifecycle_integration.rs",
                15,
            ),
            (
                ContainmentTestKind::BudgetEnforcement,
                "tests/budget_propagation_contract_integration.rs",
                30,
            ),
            (
                ContainmentTestKind::CapabilityNarrowing,
                "tests/outcome_capability_narrowing_integration.rs",
                35,
            ),
            (
                ContainmentTestKind::EvidenceCompleteness,
                "tests/evidence_replay_checker_integration.rs",
                20,
            ),
            (
                ContainmentTestKind::QuarantineContainment,
                "tests/frankenlab_extension_lifecycle_integration.rs",
                10,
            ),
            (
                ContainmentTestKind::OutcomePropagation,
                "tests/outcome_capability_narrowing_integration.rs",
                15,
            ),
            (
                ContainmentTestKind::CancellationCompliance,
                "tests/frankenlab_extension_lifecycle_integration.rs",
                12,
            ),
            (
                ContainmentTestKind::MockSeamAbsence,
                "tests/execution_orchestrator_integration.rs",
                8,
            ),
        ];

        for (kind, source, count) in containment_sources {
            reg.containment_tests
                .push(ContainmentTestEntry::new(kind, source, count));
        }

        reg
    }

    /// Get scenario entry by ID.
    pub fn scenario(&self, id: LifecycleScenarioId) -> Option<&ScenarioMigrationEntry> {
        self.scenarios.iter().find(|s| s.scenario_id == id)
    }

    /// Get mutable scenario entry by ID.
    pub fn scenario_mut(&mut self, id: LifecycleScenarioId) -> Option<&mut ScenarioMigrationEntry> {
        self.scenarios.iter_mut().find(|s| s.scenario_id == id)
    }

    /// Get containment test entry by kind.
    pub fn containment_test(&self, kind: ContainmentTestKind) -> Option<&ContainmentTestEntry> {
        self.containment_tests.iter().find(|t| t.kind == kind)
    }

    /// Get mutable containment test entry by kind.
    pub fn containment_test_mut(
        &mut self,
        kind: ContainmentTestKind,
    ) -> Option<&mut ContainmentTestEntry> {
        self.containment_tests.iter_mut().find(|t| t.kind == kind)
    }

    /// Count of scenarios by migration status.
    pub fn scenario_status_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for s in &self.scenarios {
            *counts.entry(s.status.to_string()).or_insert(0) += 1;
        }
        counts
    }

    /// Count of containment tests by migration status.
    pub fn containment_status_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for t in &self.containment_tests {
            *counts.entry(t.status.to_string()).or_insert(0) += 1;
        }
        counts
    }

    /// Overall scenario migration progress in millionths.
    pub fn scenario_migration_progress_millionths(&self) -> u64 {
        if self.scenarios.is_empty() {
            return 0;
        }
        let migrated = self
            .scenarios
            .iter()
            .filter(|s| s.status.is_upstream_backed())
            .count() as u64;
        migrated * SCALE / (self.scenarios.len() as u64)
    }

    /// Overall containment test migration progress in millionths.
    pub fn containment_migration_progress_millionths(&self) -> u64 {
        if self.containment_tests.is_empty() {
            return 0;
        }
        let total_local: u64 = self
            .containment_tests
            .iter()
            .map(|t| t.local_test_count as u64)
            .sum();
        if total_local == 0 {
            return 0;
        }
        let total_upstream: u64 = self
            .containment_tests
            .iter()
            .map(|t| t.upstream_test_count as u64)
            .sum();
        total_upstream * SCALE / total_local
    }

    /// Build a migration report.
    pub fn build_report(&self) -> HarnessMigrationReport {
        let scenario_counts = self.scenario_status_counts();
        let containment_counts = self.containment_status_counts();

        let scenarios_needing_work = self
            .scenarios
            .iter()
            .filter(|s| s.status.needs_work())
            .count();

        let containment_needing_work = self
            .containment_tests
            .iter()
            .filter(|t| t.status.needs_work())
            .count();

        let mock_context_tests = self
            .containment_tests
            .iter()
            .filter(|t| t.uses_mock_context)
            .count();

        let oracle_covered_tests = self
            .containment_tests
            .iter()
            .filter(|t| t.oracle_covered)
            .count();

        let replay_verified_scenarios = self.scenarios.iter().filter(|s| s.replay_verified).count();

        let evidence_linked_scenarios = self.scenarios.iter().filter(|s| s.evidence_linked).count();

        let content_bytes =
            serde_json::to_vec(&(&self.scenarios, &self.containment_tests)).unwrap_or_default();
        let content_hash = ContentHash::compute(&content_bytes);

        HarnessMigrationReport {
            schema_version: HARNESS_MIGRATION_SCHEMA_VERSION.to_owned(),
            epoch: self.epoch,
            total_scenarios: self.scenarios.len(),
            total_containment_tests: self.containment_tests.len(),
            scenario_status_counts: scenario_counts,
            containment_status_counts: containment_counts,
            scenario_migration_progress_millionths: self.scenario_migration_progress_millionths(),
            containment_migration_progress_millionths: self
                .containment_migration_progress_millionths(),
            scenarios_needing_work,
            containment_needing_work,
            mock_context_tests,
            oracle_covered_tests,
            replay_verified_scenarios,
            evidence_linked_scenarios,
            migration_complete: scenarios_needing_work == 0 && containment_needing_work == 0,
            content_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// HarnessMigrationReport — structured migration assessment
// ---------------------------------------------------------------------------

/// Report assessing the overall migration progress from local to upstream
/// harnesses and oracles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessMigrationReport {
    /// Schema version.
    pub schema_version: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Total lifecycle scenarios tracked.
    pub total_scenarios: usize,
    /// Total containment tests tracked.
    pub total_containment_tests: usize,
    /// Scenario counts by migration status.
    pub scenario_status_counts: BTreeMap<String, usize>,
    /// Containment test counts by migration status.
    pub containment_status_counts: BTreeMap<String, usize>,
    /// Overall scenario migration progress in millionths.
    pub scenario_migration_progress_millionths: u64,
    /// Overall containment test migration progress in millionths.
    pub containment_migration_progress_millionths: u64,
    /// Scenarios still needing work.
    pub scenarios_needing_work: usize,
    /// Containment tests still needing work.
    pub containment_needing_work: usize,
    /// Containment tests that use mock context.
    pub mock_context_tests: usize,
    /// Containment tests covered by upstream oracles.
    pub oracle_covered_tests: usize,
    /// Scenarios with replay determinism verified.
    pub replay_verified_scenarios: usize,
    /// Scenarios with evidence linkage established.
    pub evidence_linked_scenarios: usize,
    /// Whether all migrations are complete.
    pub migration_complete: bool,
    /// Content hash for deterministic comparison.
    pub content_hash: ContentHash,
}

impl HarnessMigrationReport {
    /// Whether migration is fully complete.
    pub fn is_complete(&self) -> bool {
        self.migration_complete
    }

    /// Whether any mock context usage remains.
    pub fn has_mock_context_usage(&self) -> bool {
        self.mock_context_tests > 0
    }
}

impl fmt::Display for HarnessMigrationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HarnessMigrationReport(scenarios={}/{} migrated, containment={}/{} migrated, \
             mocks={}, oracles={}, complete={})",
            self.total_scenarios - self.scenarios_needing_work,
            self.total_scenarios,
            self.total_containment_tests - self.containment_needing_work,
            self.total_containment_tests,
            self.mock_context_tests,
            self.oracle_covered_tests,
            self.migration_complete,
        )
    }
}

// ---------------------------------------------------------------------------
// OracleMigrationEntry — tracking oracle migration
// ---------------------------------------------------------------------------

/// Tracks migration of a specific oracle invariant from local to bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleMigrationEntry {
    /// Oracle invariant name.
    pub invariant_name: String,
    /// Scenarios that use this oracle.
    pub used_by_scenarios: BTreeSet<String>,
    /// Whether the oracle is available locally.
    pub available_locally: bool,
    /// Whether the oracle is available through the bridge.
    pub available_via_bridge: bool,
    /// Whether local and bridge implementations are cross-validated.
    pub cross_validated: bool,
}

impl OracleMigrationEntry {
    /// Create a local-only oracle entry.
    pub fn local_only(name: &str) -> Self {
        Self {
            invariant_name: name.to_owned(),
            used_by_scenarios: BTreeSet::new(),
            available_locally: true,
            available_via_bridge: false,
            cross_validated: false,
        }
    }

    /// Create a bridge-available oracle entry.
    pub fn bridged(name: &str) -> Self {
        Self {
            invariant_name: name.to_owned(),
            used_by_scenarios: BTreeSet::new(),
            available_locally: true,
            available_via_bridge: true,
            cross_validated: false,
        }
    }

    /// Add a scenario that uses this oracle.
    pub fn add_scenario(&mut self, scenario: &str) {
        self.used_by_scenarios.insert(scenario.to_owned());
    }

    /// Mark as cross-validated.
    pub fn mark_cross_validated(&mut self) {
        self.cross_validated = true;
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(300)
    }

    // -- MigrationStatus tests --

    #[test]
    fn migration_status_upstream_backed() {
        assert!(!MigrationStatus::LocalOnly.is_upstream_backed());
        assert!(!MigrationStatus::InProgress.is_upstream_backed());
        assert!(MigrationStatus::Migrated.is_upstream_backed());
        assert!(MigrationStatus::Verified.is_upstream_backed());
        assert!(!MigrationStatus::Deferred.is_upstream_backed());
    }

    #[test]
    fn migration_status_needs_work() {
        assert!(MigrationStatus::LocalOnly.needs_work());
        assert!(MigrationStatus::InProgress.needs_work());
        assert!(!MigrationStatus::Migrated.needs_work());
        assert!(!MigrationStatus::Verified.needs_work());
        assert!(!MigrationStatus::Deferred.needs_work());
    }

    #[test]
    fn migration_status_serde_roundtrip() {
        for status in [
            MigrationStatus::LocalOnly,
            MigrationStatus::InProgress,
            MigrationStatus::Migrated,
            MigrationStatus::Verified,
            MigrationStatus::Deferred,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let round: MigrationStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, round);
        }
    }

    // -- LifecycleScenarioId tests --

    #[test]
    fn lifecycle_scenario_id_all_has_ten() {
        assert_eq!(LifecycleScenarioId::ALL.len(), 10);
    }

    #[test]
    fn lifecycle_scenario_id_all_unique() {
        let set: BTreeSet<LifecycleScenarioId> = LifecycleScenarioId::ALL.iter().copied().collect();
        assert_eq!(set.len(), 10);
    }

    #[test]
    fn lifecycle_scenario_id_display() {
        assert_eq!(LifecycleScenarioId::Startup.to_string(), "startup");
        assert_eq!(
            LifecycleScenarioId::ForcedCancel.to_string(),
            "forced_cancel"
        );
        assert_eq!(
            LifecycleScenarioId::BudgetExhaustion.to_string(),
            "budget_exhaustion"
        );
    }

    // -- ScenarioMigrationEntry tests --

    #[test]
    fn scenario_entry_local_only_defaults() {
        let entry = ScenarioMigrationEntry::local_only(
            LifecycleScenarioId::Startup,
            "frankenlab_extension_lifecycle",
        );
        assert_eq!(entry.status, MigrationStatus::LocalOnly);
        assert!(entry.upstream_harness.is_none());
        assert!(!entry.replay_verified);
        assert!(!entry.evidence_linked);
        assert_eq!(entry.total_oracles(), 0);
    }

    #[test]
    fn scenario_entry_oracle_fractions() {
        let mut entry = ScenarioMigrationEntry::local_only(LifecycleScenarioId::Startup, "test");
        entry.local_oracles.insert("safety".to_owned());
        entry.local_oracles.insert("liveness".to_owned());
        entry.bridge_oracles.insert("determinism".to_owned());

        assert_eq!(entry.total_oracles(), 3);
        assert_eq!(entry.bridge_oracle_fraction_millionths(), 333_333);
        assert!(!entry.all_oracles_bridged());
    }

    #[test]
    fn scenario_entry_mark_migrated() {
        let mut entry =
            ScenarioMigrationEntry::local_only(LifecycleScenarioId::Quarantine, "local");
        entry.mark_migrated("upstream::lab::scenario_runner");
        assert_eq!(entry.status, MigrationStatus::Migrated);
        assert!(entry.upstream_harness.is_some());
    }

    #[test]
    fn scenario_entry_mark_verified() {
        let mut entry = ScenarioMigrationEntry::local_only(LifecycleScenarioId::Startup, "local");
        entry.mark_verified();
        assert_eq!(entry.status, MigrationStatus::Verified);
        assert!(entry.replay_verified);
        assert!(entry.evidence_linked);
    }

    #[test]
    fn scenario_entry_serde_roundtrip() {
        let mut entry =
            ScenarioMigrationEntry::local_only(LifecycleScenarioId::Revocation, "lifecycle");
        entry.local_oracles.insert("safety".to_owned());
        entry.bridge_oracles.insert("determinism".to_owned());
        entry.mark_migrated("upstream");
        let json = serde_json::to_string(&entry).unwrap();
        let round: ScenarioMigrationEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, round);
    }

    // -- ContainmentTestKind tests --

    #[test]
    fn containment_test_kind_all_has_eight() {
        assert_eq!(ContainmentTestKind::ALL.len(), 8);
    }

    #[test]
    fn containment_test_kind_all_unique() {
        let set: BTreeSet<ContainmentTestKind> = ContainmentTestKind::ALL.iter().copied().collect();
        assert_eq!(set.len(), 8);
    }

    // -- ContainmentTestEntry tests --

    #[test]
    fn containment_entry_defaults() {
        let entry =
            ContainmentTestEntry::new(ContainmentTestKind::RegionIsolation, "tests/foo.rs", 10);
        assert_eq!(entry.status, MigrationStatus::LocalOnly);
        assert_eq!(entry.local_test_count, 10);
        assert_eq!(entry.upstream_test_count, 0);
        assert!(!entry.uses_mock_context);
        assert!(!entry.oracle_covered);
    }

    #[test]
    fn containment_entry_migration_coverage() {
        let mut entry =
            ContainmentTestEntry::new(ContainmentTestKind::BudgetEnforcement, "tests/b.rs", 20);
        entry.upstream_test_count = 15;
        assert_eq!(entry.migration_coverage_millionths(), 750_000);
        assert!(!entry.fully_migrated());

        entry.upstream_test_count = 20;
        entry.status = MigrationStatus::Migrated;
        assert!(entry.fully_migrated());
    }

    #[test]
    fn containment_entry_serde_roundtrip() {
        let entry =
            ContainmentTestEntry::new(ContainmentTestKind::MockSeamAbsence, "tests/orch.rs", 8);
        let json = serde_json::to_string(&entry).unwrap();
        let round: ContainmentTestEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, round);
    }

    // -- HarnessMigrationRegistry tests --

    #[test]
    fn registry_new_empty() {
        let reg = HarnessMigrationRegistry::new(test_epoch());
        assert!(reg.scenarios.is_empty());
        assert!(reg.containment_tests.is_empty());
    }

    #[test]
    fn registry_with_defaults_populated() {
        let reg = HarnessMigrationRegistry::with_default_scenarios(test_epoch());
        assert_eq!(reg.scenarios.len(), 10);
        assert_eq!(reg.containment_tests.len(), 8);
    }

    #[test]
    fn registry_scenario_lookup() {
        let reg = HarnessMigrationRegistry::with_default_scenarios(test_epoch());
        let startup = reg.scenario(LifecycleScenarioId::Startup).unwrap();
        assert_eq!(startup.scenario_id, LifecycleScenarioId::Startup);
        assert_eq!(startup.local_harness, "frankenlab_extension_lifecycle");
    }

    #[test]
    fn registry_containment_lookup() {
        let reg = HarnessMigrationRegistry::with_default_scenarios(test_epoch());
        let test = reg
            .containment_test(ContainmentTestKind::BudgetEnforcement)
            .unwrap();
        assert_eq!(test.kind, ContainmentTestKind::BudgetEnforcement);
    }

    #[test]
    fn registry_status_counts_all_local() {
        let reg = HarnessMigrationRegistry::with_default_scenarios(test_epoch());
        let counts = reg.scenario_status_counts();
        assert_eq!(*counts.get("local_only").unwrap(), 10);
    }

    #[test]
    fn registry_migration_progress_zero_initially() {
        let reg = HarnessMigrationRegistry::with_default_scenarios(test_epoch());
        assert_eq!(reg.scenario_migration_progress_millionths(), 0);
        assert_eq!(reg.containment_migration_progress_millionths(), 0);
    }

    #[test]
    fn registry_migration_progress_partial() {
        let mut reg = HarnessMigrationRegistry::with_default_scenarios(test_epoch());
        // Migrate 3 of 10 scenarios
        reg.scenario_mut(LifecycleScenarioId::Startup)
            .unwrap()
            .mark_migrated("upstream");
        reg.scenario_mut(LifecycleScenarioId::NormalShutdown)
            .unwrap()
            .mark_migrated("upstream");
        reg.scenario_mut(LifecycleScenarioId::ForcedCancel)
            .unwrap()
            .mark_verified();

        assert_eq!(reg.scenario_migration_progress_millionths(), 300_000);
    }

    #[test]
    fn registry_serde_roundtrip() {
        let reg = HarnessMigrationRegistry::with_default_scenarios(test_epoch());
        let json = serde_json::to_string_pretty(&reg).unwrap();
        let round: HarnessMigrationRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(reg, round);
    }

    // -- Report tests --

    #[test]
    fn report_initial_state() {
        let reg = HarnessMigrationRegistry::with_default_scenarios(test_epoch());
        let report = reg.build_report();
        assert!(!report.is_complete());
        assert_eq!(report.total_scenarios, 10);
        assert_eq!(report.total_containment_tests, 8);
        assert_eq!(report.scenarios_needing_work, 10);
        assert_eq!(report.containment_needing_work, 8);
    }

    #[test]
    fn report_after_full_migration() {
        let mut reg = HarnessMigrationRegistry::with_default_scenarios(test_epoch());

        // Migrate all scenarios
        for scenario_id in LifecycleScenarioId::ALL {
            reg.scenario_mut(scenario_id).unwrap().mark_verified();
        }

        // Migrate all containment tests
        for kind in ContainmentTestKind::ALL {
            let test = reg.containment_test_mut(kind).unwrap();
            test.status = MigrationStatus::Verified;
            test.upstream_test_count = test.local_test_count;
        }

        let report = reg.build_report();
        assert!(report.is_complete());
        assert_eq!(report.scenarios_needing_work, 0);
        assert_eq!(report.containment_needing_work, 0);
        assert_eq!(report.scenario_migration_progress_millionths, SCALE);
    }

    #[test]
    fn report_serde_roundtrip() {
        let reg = HarnessMigrationRegistry::with_default_scenarios(test_epoch());
        let report = reg.build_report();
        let json = serde_json::to_string_pretty(&report).unwrap();
        let round: HarnessMigrationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, round);
    }

    #[test]
    fn report_content_hash_deterministic() {
        let make = || {
            let reg = HarnessMigrationRegistry::with_default_scenarios(test_epoch());
            reg.build_report()
        };
        let r1 = make();
        let r2 = make();
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn report_display() {
        let reg = HarnessMigrationRegistry::with_default_scenarios(test_epoch());
        let report = reg.build_report();
        let s = format!("{report}");
        assert!(s.contains("HarnessMigrationReport"));
    }

    // -- OracleMigrationEntry tests --

    #[test]
    fn oracle_entry_local_only() {
        let entry = OracleMigrationEntry::local_only("safety");
        assert!(entry.available_locally);
        assert!(!entry.available_via_bridge);
        assert!(!entry.cross_validated);
    }

    #[test]
    fn oracle_entry_bridged() {
        let entry = OracleMigrationEntry::bridged("determinism");
        assert!(entry.available_locally);
        assert!(entry.available_via_bridge);
    }

    #[test]
    fn oracle_entry_add_scenario() {
        let mut entry = OracleMigrationEntry::local_only("safety");
        entry.add_scenario("startup");
        entry.add_scenario("shutdown");
        entry.add_scenario("startup"); // duplicate
        assert_eq!(entry.used_by_scenarios.len(), 2);
    }

    #[test]
    fn oracle_entry_serde_roundtrip() {
        let mut entry = OracleMigrationEntry::bridged("safety");
        entry.add_scenario("startup");
        entry.mark_cross_validated();
        let json = serde_json::to_string(&entry).unwrap();
        let round: OracleMigrationEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, round);
    }

    // -----------------------------------------------------------------------
    // Deep enrichment tests (PearlTower 2026-03-18)
    // -----------------------------------------------------------------------

    #[test]
    fn migration_status_display_all() {
        for status in [
            MigrationStatus::LocalOnly,
            MigrationStatus::InProgress,
            MigrationStatus::Migrated,
            MigrationStatus::Verified,
            MigrationStatus::Deferred,
        ] {
            assert!(!format!("{status}").is_empty());
        }
    }

    #[test]
    fn lifecycle_scenario_id_serde_all() {
        for id in LifecycleScenarioId::ALL {
            let json = serde_json::to_string(&id).unwrap();
            let back: LifecycleScenarioId = serde_json::from_str(&json).unwrap();
            assert_eq!(id, back);
        }
    }

    #[test]
    fn lifecycle_scenario_id_display_all() {
        for id in LifecycleScenarioId::ALL {
            assert!(!id.to_string().is_empty());
        }
    }

    #[test]
    fn containment_test_kind_serde_all() {
        for kind in ContainmentTestKind::ALL {
            let json = serde_json::to_string(&kind).unwrap();
            let back: ContainmentTestKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn containment_test_kind_display_all() {
        for kind in ContainmentTestKind::ALL {
            assert!(!kind.to_string().is_empty());
        }
    }

    #[test]
    fn scenario_entry_all_oracles_bridged_when_empty() {
        let entry = ScenarioMigrationEntry::local_only(LifecycleScenarioId::Startup, "test");
        // No oracles → vacuously true
        assert!(entry.all_oracles_bridged());
    }

    #[test]
    fn scenario_entry_bridge_oracle_fraction_zero_with_no_bridge() {
        let mut entry = ScenarioMigrationEntry::local_only(LifecycleScenarioId::Startup, "test");
        entry.local_oracles.insert("safety".to_owned());
        assert_eq!(entry.bridge_oracle_fraction_millionths(), 0);
    }

    #[test]
    fn scenario_entry_bridge_oracle_fraction_full() {
        let mut entry = ScenarioMigrationEntry::local_only(LifecycleScenarioId::Startup, "test");
        entry.bridge_oracles.insert("safety".to_owned());
        assert_eq!(entry.bridge_oracle_fraction_millionths(), SCALE);
    }

    #[test]
    fn containment_entry_zero_local_tests() {
        let entry = ContainmentTestEntry::new(ContainmentTestKind::RegionIsolation, "test", 0);
        assert_eq!(entry.migration_coverage_millionths(), 0);
    }

    #[test]
    fn containment_entry_fully_migrated_requires_status() {
        let mut entry =
            ContainmentTestEntry::new(ContainmentTestKind::BudgetEnforcement, "test", 10);
        entry.upstream_test_count = 10;
        // Status is still LocalOnly, so not fully migrated
        assert!(!entry.fully_migrated());
    }

    #[test]
    fn registry_scenario_mut_exists() {
        let mut reg = HarnessMigrationRegistry::with_default_scenarios(test_epoch());
        assert!(reg.scenario_mut(LifecycleScenarioId::Quarantine).is_some());
    }

    #[test]
    fn registry_containment_test_mut_exists() {
        let mut reg = HarnessMigrationRegistry::with_default_scenarios(test_epoch());
        assert!(
            reg.containment_test_mut(ContainmentTestKind::RegionIsolation)
                .is_some()
        );
    }

    #[test]
    fn registry_scenario_not_found() {
        let reg = HarnessMigrationRegistry::new(test_epoch());
        assert!(reg.scenario(LifecycleScenarioId::Startup).is_none());
    }

    #[test]
    fn report_schema_version() {
        let reg = HarnessMigrationRegistry::with_default_scenarios(test_epoch());
        let report = reg.build_report();
        assert_eq!(report.schema_version, HARNESS_MIGRATION_SCHEMA_VERSION);
    }

    #[test]
    fn schema_constants_non_empty() {
        assert!(!HARNESS_MIGRATION_SCHEMA_VERSION.is_empty());
        assert!(!HARNESS_MIGRATION_BEAD_ID.is_empty());
        assert!(HARNESS_MIGRATION_SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn oracle_entry_mark_cross_validated() {
        let mut entry = OracleMigrationEntry::local_only("test");
        assert!(!entry.cross_validated);
        entry.mark_cross_validated();
        assert!(entry.cross_validated);
    }

    #[test]
    fn registry_content_hash_deterministic() {
        let r1 = HarnessMigrationRegistry::with_default_scenarios(test_epoch());
        let r2 = HarnessMigrationRegistry::with_default_scenarios(test_epoch());
        assert_eq!(
            r1.build_report().content_hash,
            r2.build_report().content_hash
        );
    }

    #[test]
    fn scenario_entry_deferred() {
        let mut entry = ScenarioMigrationEntry::local_only(LifecycleScenarioId::Startup, "test");
        entry.status = MigrationStatus::Deferred;
        assert!(!entry.status.needs_work());
        assert!(!entry.status.is_upstream_backed());
    }
}
