// FRX-20.1: Unified Unit-Test Taxonomy, Fixture Registry, and Determinism Contract
//
// Defines a canonical unit-test taxonomy across compiler/runtime/router/governance
// surfaces and binds each class to deterministic fixture requirements.
//
// Plan reference: bd-mjh3.20.1

use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

pub const TEST_TAXONOMY_SCHEMA_VERSION: &str = "0.1.0";
pub const FIXTURE_REGISTRY_SCHEMA_VERSION: &str = "0.1.0";

const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Test class taxonomy
// ---------------------------------------------------------------------------

/// Canonical test classes spanning all FrankenEngine surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TestClass {
    /// Deterministic positive-path coverage of core semantics.
    Core,
    /// Boundary conditions, off-by-one, type coercion edges, etc.
    Edge,
    /// Intentionally malicious or malformed inputs designed to break invariants.
    Adversarial,
    /// Regression pinning for previously-observed failures.
    Regression,
    /// Fault injection (corruption, timeout, partition, resource exhaustion).
    FaultInjection,
}

impl TestClass {
    pub const ALL: &'static [TestClass] = &[
        TestClass::Core,
        TestClass::Edge,
        TestClass::Adversarial,
        TestClass::Regression,
        TestClass::FaultInjection,
    ];

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Edge => "edge",
            Self::Adversarial => "adversarial",
            Self::Regression => "regression",
            Self::FaultInjection => "fault_injection",
        }
    }

    /// Whether this class requires a deterministic seed for reproducibility.
    #[must_use]
    pub const fn requires_seed(&self) -> bool {
        match self {
            Self::Core | Self::Edge | Self::Regression => false,
            Self::Adversarial | Self::FaultInjection => true,
        }
    }

    /// Minimum fixture provenance level required for this class.
    #[must_use]
    pub const fn min_provenance_level(&self) -> ProvenanceLevel {
        match self {
            Self::Core => ProvenanceLevel::Authored,
            Self::Edge => ProvenanceLevel::Authored,
            Self::Adversarial => ProvenanceLevel::Generated,
            Self::Regression => ProvenanceLevel::Captured,
            Self::FaultInjection => ProvenanceLevel::Generated,
        }
    }
}

impl fmt::Display for TestClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Surface taxonomy
// ---------------------------------------------------------------------------

/// Ownership surfaces that tests target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TestSurface {
    Compiler,
    Runtime,
    Router,
    Governance,
    Parser,
    Scheduler,
    Evidence,
    Security,
}

impl TestSurface {
    pub const ALL: &'static [TestSurface] = &[
        TestSurface::Compiler,
        TestSurface::Runtime,
        TestSurface::Router,
        TestSurface::Governance,
        TestSurface::Parser,
        TestSurface::Scheduler,
        TestSurface::Evidence,
        TestSurface::Security,
    ];

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Compiler => "compiler",
            Self::Runtime => "runtime",
            Self::Router => "router",
            Self::Governance => "governance",
            Self::Parser => "parser",
            Self::Scheduler => "scheduler",
            Self::Evidence => "evidence",
            Self::Security => "security",
        }
    }

    /// Lane charter bead that owns this surface.
    #[must_use]
    pub const fn lane_charter_ref(&self) -> &'static str {
        match self {
            Self::Compiler => "bd-mjh3.10.2",
            Self::Runtime => "bd-mjh3.10.3",
            Self::Router => "bd-mjh3.10.3",
            Self::Governance => "bd-mjh3.10.7",
            Self::Parser => "bd-mjh3.10.3",
            Self::Scheduler => "bd-mjh3.10.3",
            Self::Evidence => "bd-mjh3.10.7",
            Self::Security => "bd-mjh3.10.4",
        }
    }
}

impl fmt::Display for TestSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/// How a fixture was produced. Determines trust and reproducibility guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProvenanceLevel {
    /// Hand-written by an engineer with known intent.
    Authored,
    /// Generated by a deterministic procedure from a seed.
    Generated,
    /// Captured from a real production or regression trace.
    Captured,
    /// Synthesized by a counterexample/mutation engine.
    Synthesized,
}

impl ProvenanceLevel {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Authored => "authored",
            Self::Generated => "generated",
            Self::Captured => "captured",
            Self::Synthesized => "synthesized",
        }
    }

    /// Ordering for provenance-level comparisons: higher = more trust.
    #[must_use]
    pub const fn trust_rank(&self) -> u8 {
        match self {
            Self::Synthesized => 0,
            Self::Generated => 1,
            Self::Captured => 2,
            Self::Authored => 3,
        }
    }
}

impl fmt::Display for ProvenanceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Determinism contract
// ---------------------------------------------------------------------------

/// Determinism requirements for a test execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterminismContract {
    /// Schema version for this contract.
    pub schema: String,
    /// Whether the test must produce bit-identical output on repeated runs.
    pub bit_identical_required: bool,
    /// Whether a seed must be provided and logged.
    pub seed_required: bool,
    /// Whether a virtual clock must be used (no real wall-clock references).
    pub virtual_clock_required: bool,
    /// Whether all RNG sources must be replaced with deterministic variants.
    pub deterministic_rng_required: bool,
    /// Maximum allowed execution-order nondeterminism sources.
    pub max_nondeterminism_sources: u64,
    /// Tolerance for numeric results (0 = exact match, >0 = fixed-point delta).
    pub numeric_tolerance_millionths: i64,
}

impl DeterminismContract {
    /// Strict contract: bit-identical, seeded, virtual clock, deterministic RNG.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            schema: TEST_TAXONOMY_SCHEMA_VERSION.to_string(),
            bit_identical_required: true,
            seed_required: true,
            virtual_clock_required: true,
            deterministic_rng_required: true,
            max_nondeterminism_sources: 0,
            numeric_tolerance_millionths: 0,
        }
    }

    /// Relaxed contract: no bit-identical, optional seed, allows tolerance.
    #[must_use]
    pub fn relaxed(tolerance_millionths: i64) -> Self {
        Self {
            schema: TEST_TAXONOMY_SCHEMA_VERSION.to_string(),
            bit_identical_required: false,
            seed_required: false,
            virtual_clock_required: false,
            deterministic_rng_required: false,
            max_nondeterminism_sources: 3,
            numeric_tolerance_millionths: tolerance_millionths,
        }
    }

    /// Default contract for a given test class.
    #[must_use]
    pub fn for_class(class: TestClass) -> Self {
        match class {
            TestClass::Core | TestClass::Edge => Self {
                schema: TEST_TAXONOMY_SCHEMA_VERSION.to_string(),
                bit_identical_required: true,
                seed_required: false,
                virtual_clock_required: false,
                deterministic_rng_required: false,
                max_nondeterminism_sources: 0,
                numeric_tolerance_millionths: 0,
            },
            TestClass::Adversarial => Self::strict(),
            TestClass::FaultInjection => Self {
                schema: TEST_TAXONOMY_SCHEMA_VERSION.to_string(),
                bit_identical_required: true,
                seed_required: true,
                virtual_clock_required: true,
                deterministic_rng_required: true,
                max_nondeterminism_sources: 1, // fault-injection point
                numeric_tolerance_millionths: 0,
            },
            TestClass::Regression => Self {
                schema: TEST_TAXONOMY_SCHEMA_VERSION.to_string(),
                bit_identical_required: true,
                seed_required: false,
                virtual_clock_required: false,
                deterministic_rng_required: false,
                max_nondeterminism_sources: 0,
                numeric_tolerance_millionths: 0,
            },
        }
    }

    /// Validate that this contract is internally consistent.
    #[must_use]
    pub fn validate(&self) -> Vec<ContractViolation> {
        let mut violations = Vec::new();
        if self.bit_identical_required
            && self.max_nondeterminism_sources > 0
            && !self.deterministic_rng_required
        {
            violations.push(ContractViolation {
                field: "max_nondeterminism_sources".to_string(),
                message: "bit-identical required but nondeterminism sources allowed without deterministic RNG".to_string(),
            });
        }
        if self.numeric_tolerance_millionths < 0 {
            violations.push(ContractViolation {
                field: "numeric_tolerance_millionths".to_string(),
                message: "tolerance must be non-negative".to_string(),
            });
        }
        if self.bit_identical_required && self.numeric_tolerance_millionths > 0 {
            violations.push(ContractViolation {
                field: "numeric_tolerance_millionths".to_string(),
                message: "bit-identical required but nonzero tolerance set".to_string(),
            });
        }
        violations
    }
}

/// A specific violation found during contract validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractViolation {
    pub field: String,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Fixture registry
// ---------------------------------------------------------------------------

/// A single fixture entry in the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureEntry {
    /// Unique fixture identifier.
    pub fixture_id: String,
    /// Human-readable description.
    pub description: String,
    /// Which test class this fixture targets.
    pub test_class: TestClass,
    /// Which surface(s) this fixture covers.
    pub surfaces: BTreeSet<TestSurface>,
    /// How the fixture was produced.
    pub provenance: ProvenanceLevel,
    /// Deterministic seed (if applicable).
    pub seed: Option<u64>,
    /// Content hash for integrity verification.
    pub content_hash: String,
    /// Schema version of the fixture format.
    pub format_version: String,
    /// Bead or ticket reference that introduced this fixture.
    pub origin_ref: String,
    /// Tags for free-form categorization.
    pub tags: BTreeSet<String>,
}

impl FixtureEntry {
    /// Validate that this fixture meets the determinism contract for its class.
    pub fn validate_against_contract(
        &self,
        contract: &DeterminismContract,
    ) -> Vec<ContractViolation> {
        let mut violations = Vec::new();
        if contract.seed_required && self.seed.is_none() {
            violations.push(ContractViolation {
                field: "seed".to_string(),
                message: format!(
                    "fixture {} requires seed for class {}",
                    self.fixture_id, self.test_class
                ),
            });
        }
        let min_prov = self.test_class.min_provenance_level();
        if self.provenance.trust_rank() < min_prov.trust_rank() {
            violations.push(ContractViolation {
                field: "provenance".to_string(),
                message: format!(
                    "fixture {} has provenance {} but class {} requires at least {}",
                    self.fixture_id, self.provenance, self.test_class, min_prov
                ),
            });
        }
        if self.content_hash.is_empty() {
            violations.push(ContractViolation {
                field: "content_hash".to_string(),
                message: format!("fixture {} missing content hash", self.fixture_id),
            });
        }
        violations
    }

    /// Derive an EngineObjectId for this fixture.
    pub fn derive_id(&self) -> Result<EngineObjectId, crate::engine_object_id::IdError> {
        let schema = SchemaId::from_definition(b"franken-engine.test-taxonomy.fixture-entry.v1");
        let canonical = format!(
            "{}|{}|{}",
            self.fixture_id, self.format_version, self.content_hash
        );
        derive_id(
            ObjectDomain::EvidenceRecord,
            &format!("fixture:{}", self.fixture_id),
            &schema,
            canonical.as_bytes(),
        )
    }
}

/// The central fixture registry for the entire test suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureRegistry {
    pub schema: String,
    pub entries: Vec<FixtureEntry>,
}

impl FixtureRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema: FIXTURE_REGISTRY_SCHEMA_VERSION.to_string(),
            entries: Vec::new(),
        }
    }

    /// Register a new fixture. Returns error if duplicate ID.
    pub fn register(&mut self, entry: FixtureEntry) -> Result<(), RegistryError> {
        if self
            .entries
            .iter()
            .any(|e| e.fixture_id == entry.fixture_id)
        {
            return Err(RegistryError::DuplicateFixtureId(entry.fixture_id));
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Look up a fixture by ID.
    #[must_use]
    pub fn lookup(&self, fixture_id: &str) -> Option<&FixtureEntry> {
        self.entries.iter().find(|e| e.fixture_id == fixture_id)
    }

    /// All fixtures for a given test class.
    #[must_use]
    pub fn by_class(&self, class: TestClass) -> Vec<&FixtureEntry> {
        self.entries
            .iter()
            .filter(|e| e.test_class == class)
            .collect()
    }

    /// All fixtures covering a given surface.
    #[must_use]
    pub fn by_surface(&self, surface: TestSurface) -> Vec<&FixtureEntry> {
        self.entries
            .iter()
            .filter(|e| e.surfaces.contains(&surface))
            .collect()
    }

    /// Validate every fixture against its class contract.
    #[must_use]
    pub fn validate_all(&self) -> Vec<(String, Vec<ContractViolation>)> {
        let mut results = Vec::new();
        for entry in &self.entries {
            let contract = DeterminismContract::for_class(entry.test_class);
            let violations = entry.validate_against_contract(&contract);
            if !violations.is_empty() {
                results.push((entry.fixture_id.clone(), violations));
            }
        }
        results
    }

    /// Coverage matrix: for each (class, surface), how many fixtures exist.
    #[must_use]
    pub fn coverage_matrix(&self) -> BTreeMap<(TestClass, TestSurface), u64> {
        let mut matrix = BTreeMap::new();
        for entry in &self.entries {
            for surface in &entry.surfaces {
                *matrix.entry((entry.test_class, *surface)).or_insert(0) += 1;
            }
        }
        matrix
    }

    /// Identify gaps: (class, surface) pairs with zero fixtures.
    #[must_use]
    pub fn coverage_gaps(&self) -> Vec<(TestClass, TestSurface)> {
        let matrix = self.coverage_matrix();
        let mut gaps = Vec::new();
        for class in TestClass::ALL {
            for surface in TestSurface::ALL {
                if !matrix.contains_key(&(*class, *surface)) {
                    gaps.push((*class, *surface));
                }
            }
        }
        gaps
    }

    /// Total number of fixtures.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for FixtureRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Ownership map
// ---------------------------------------------------------------------------

/// Maps fixture sets to lane charter owners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipEntry {
    pub surface: TestSurface,
    pub test_class: TestClass,
    pub lane_charter_ref: String,
    pub owner_agent: String,
    pub fixture_ids: BTreeSet<String>,
}

/// Complete ownership map linking fixtures to lane charters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipMap {
    pub schema: String,
    pub entries: Vec<OwnershipEntry>,
}

impl OwnershipMap {
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema: TEST_TAXONOMY_SCHEMA_VERSION.to_string(),
            entries: Vec::new(),
        }
    }

    /// Add an ownership entry.
    pub fn add(&mut self, entry: OwnershipEntry) {
        self.entries.push(entry);
    }

    /// Look up all ownership entries for a surface.
    #[must_use]
    pub fn by_surface(&self, surface: TestSurface) -> Vec<&OwnershipEntry> {
        self.entries
            .iter()
            .filter(|e| e.surface == surface)
            .collect()
    }

    /// Unowned fixtures: fixture IDs present in registry but absent from ownership map.
    #[must_use]
    pub fn unowned_fixtures(&self, registry: &FixtureRegistry) -> Vec<String> {
        let owned: BTreeSet<&str> = self
            .entries
            .iter()
            .flat_map(|e| e.fixture_ids.iter().map(String::as_str))
            .collect();
        registry
            .entries
            .iter()
            .filter(|f| !owned.contains(f.fixture_id.as_str()))
            .map(|f| f.fixture_id.clone())
            .collect()
    }
}

impl Default for OwnershipMap {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Test execution result
// ---------------------------------------------------------------------------

/// Outcome of a single test execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TestOutcome {
    Pass,
    Fail,
    Skip,
    Timeout,
    Flake,
}

impl TestOutcome {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Skip => "skip",
            Self::Timeout => "timeout",
            Self::Flake => "flake",
        }
    }

    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Pass)
    }
}

impl fmt::Display for TestOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A recorded test execution with evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestExecutionRecord {
    /// Fixture that was executed.
    pub fixture_id: String,
    /// Test class.
    pub test_class: TestClass,
    /// Surface under test.
    pub surface: TestSurface,
    /// Outcome of the execution.
    pub outcome: TestOutcome,
    /// Seed used (if any).
    pub seed: Option<u64>,
    /// Duration in microseconds.
    pub duration_us: u64,
    /// Whether determinism contract was satisfied.
    pub determinism_satisfied: bool,
    /// Evidence hash for the execution artifact.
    pub evidence_hash: String,
    /// Human-readable notes.
    pub notes: String,
}

// ---------------------------------------------------------------------------
// Test suite summary
// ---------------------------------------------------------------------------

/// Aggregated summary across a test suite run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestSuiteSummary {
    pub schema: String,
    pub total: u64,
    pub passed: u64,
    pub failed: u64,
    pub skipped: u64,
    pub timed_out: u64,
    pub flaky: u64,
    /// Pass rate in millionths (1_000_000 = 100%).
    pub pass_rate_millionths: i64,
    /// Per-class breakdown.
    pub class_breakdown: BTreeMap<TestClass, ClassBreakdown>,
    /// Per-surface breakdown.
    pub surface_breakdown: BTreeMap<TestSurface, u64>,
    /// Determinism contract satisfaction rate in millionths.
    pub determinism_rate_millionths: i64,
}

/// Per-class test breakdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassBreakdown {
    pub total: u64,
    pub passed: u64,
    pub failed: u64,
}

impl TestSuiteSummary {
    /// Build a summary from a collection of execution records.
    #[must_use]
    pub fn from_records(records: &[TestExecutionRecord]) -> Self {
        let total = records.len() as u64;
        let passed = records
            .iter()
            .filter(|r| r.outcome == TestOutcome::Pass)
            .count() as u64;
        let failed = records
            .iter()
            .filter(|r| r.outcome == TestOutcome::Fail)
            .count() as u64;
        let skipped = records
            .iter()
            .filter(|r| r.outcome == TestOutcome::Skip)
            .count() as u64;
        let timed_out = records
            .iter()
            .filter(|r| r.outcome == TestOutcome::Timeout)
            .count() as u64;
        let flaky = records
            .iter()
            .filter(|r| r.outcome == TestOutcome::Flake)
            .count() as u64;

        let pass_rate_millionths = if total > 0 {
            (passed as i64).saturating_mul(MILLION) / total as i64
        } else {
            0
        };

        let determinism_count = records.iter().filter(|r| r.determinism_satisfied).count() as u64;
        let determinism_rate_millionths = if total > 0 {
            (determinism_count as i64).saturating_mul(MILLION) / total as i64
        } else {
            0
        };

        let mut class_breakdown = BTreeMap::new();
        for class in TestClass::ALL {
            let class_records: Vec<_> = records.iter().filter(|r| r.test_class == *class).collect();
            if !class_records.is_empty() {
                let ct = class_records.len() as u64;
                let cp = class_records
                    .iter()
                    .filter(|r| r.outcome == TestOutcome::Pass)
                    .count() as u64;
                let cf = class_records
                    .iter()
                    .filter(|r| r.outcome == TestOutcome::Fail)
                    .count() as u64;
                class_breakdown.insert(
                    *class,
                    ClassBreakdown {
                        total: ct,
                        passed: cp,
                        failed: cf,
                    },
                );
            }
        }

        let mut surface_breakdown = BTreeMap::new();
        for record in records {
            *surface_breakdown.entry(record.surface).or_insert(0u64) += 1;
        }

        Self {
            schema: TEST_TAXONOMY_SCHEMA_VERSION.to_string(),
            total,
            passed,
            failed,
            skipped,
            timed_out,
            flaky,
            pass_rate_millionths,
            class_breakdown,
            surface_breakdown,
            determinism_rate_millionths,
        }
    }

    /// Whether the suite meets a minimum pass-rate threshold.
    #[must_use]
    pub fn meets_threshold(&self, threshold_millionths: i64) -> bool {
        self.pass_rate_millionths >= threshold_millionths
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the test taxonomy subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryError {
    DuplicateFixtureId(String),
    FixtureNotFound(String),
    InvalidFixture(String),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateFixtureId(id) => write!(f, "duplicate fixture ID: {id}"),
            Self::FixtureNotFound(id) => write!(f, "fixture not found: {id}"),
            Self::InvalidFixture(msg) => write!(f, "invalid fixture: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- TestClass --

    #[test]
    fn test_class_all_count() {
        assert_eq!(TestClass::ALL.len(), 5);
    }

    #[test]
    fn test_class_as_str_roundtrip() {
        for class in TestClass::ALL {
            assert!(!class.as_str().is_empty());
            assert_eq!(class.to_string(), class.as_str());
        }
    }

    #[test]
    fn test_class_requires_seed() {
        assert!(!TestClass::Core.requires_seed());
        assert!(!TestClass::Edge.requires_seed());
        assert!(TestClass::Adversarial.requires_seed());
        assert!(!TestClass::Regression.requires_seed());
        assert!(TestClass::FaultInjection.requires_seed());
    }

    #[test]
    fn test_class_serde_roundtrip() {
        for class in TestClass::ALL {
            let json = serde_json::to_string(class).unwrap();
            let back: TestClass = serde_json::from_str(&json).unwrap();
            assert_eq!(*class, back);
        }
    }

    #[test]
    fn test_class_ordering() {
        assert!(TestClass::Core < TestClass::Edge);
        assert!(TestClass::Edge < TestClass::Adversarial);
    }

    // -- TestSurface --

    #[test]
    fn test_surface_all_count() {
        assert_eq!(TestSurface::ALL.len(), 8);
    }

    #[test]
    fn test_surface_as_str_roundtrip() {
        for surface in TestSurface::ALL {
            assert!(!surface.as_str().is_empty());
            assert_eq!(surface.to_string(), surface.as_str());
        }
    }

    #[test]
    fn test_surface_lane_charter_ref() {
        for surface in TestSurface::ALL {
            let lc = surface.lane_charter_ref();
            assert!(lc.starts_with("bd-mjh3.10."));
        }
    }

    #[test]
    fn test_surface_serde_roundtrip() {
        for surface in TestSurface::ALL {
            let json = serde_json::to_string(surface).unwrap();
            let back: TestSurface = serde_json::from_str(&json).unwrap();
            assert_eq!(*surface, back);
        }
    }

    // -- ProvenanceLevel --

    #[test]
    fn provenance_trust_rank_order() {
        assert!(
            ProvenanceLevel::Synthesized.trust_rank() < ProvenanceLevel::Generated.trust_rank()
        );
        assert!(ProvenanceLevel::Generated.trust_rank() < ProvenanceLevel::Captured.trust_rank());
        assert!(ProvenanceLevel::Captured.trust_rank() < ProvenanceLevel::Authored.trust_rank());
    }

    #[test]
    fn provenance_display() {
        assert_eq!(ProvenanceLevel::Authored.to_string(), "authored");
        assert_eq!(ProvenanceLevel::Generated.to_string(), "generated");
    }

    #[test]
    fn provenance_serde_roundtrip() {
        let p = ProvenanceLevel::Captured;
        let json = serde_json::to_string(&p).unwrap();
        let back: ProvenanceLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    // -- DeterminismContract --

    #[test]
    fn contract_strict_is_valid() {
        let c = DeterminismContract::strict();
        assert!(c.validate().is_empty());
        assert!(c.bit_identical_required);
        assert!(c.seed_required);
        assert!(c.virtual_clock_required);
        assert!(c.deterministic_rng_required);
    }

    #[test]
    fn contract_relaxed_is_valid() {
        let c = DeterminismContract::relaxed(1000);
        assert!(c.validate().is_empty());
        assert!(!c.bit_identical_required);
        assert_eq!(c.numeric_tolerance_millionths, 1000);
    }

    #[test]
    fn contract_for_class_core() {
        let c = DeterminismContract::for_class(TestClass::Core);
        assert!(c.bit_identical_required);
        assert!(!c.seed_required);
        assert_eq!(c.max_nondeterminism_sources, 0);
    }

    #[test]
    fn contract_for_class_adversarial() {
        let c = DeterminismContract::for_class(TestClass::Adversarial);
        assert!(c.seed_required);
        assert!(c.deterministic_rng_required);
        assert!(c.virtual_clock_required);
    }

    #[test]
    fn contract_for_class_fault_injection() {
        let c = DeterminismContract::for_class(TestClass::FaultInjection);
        assert!(c.seed_required);
        assert!(c.deterministic_rng_required);
        assert_eq!(c.max_nondeterminism_sources, 1);
    }

    #[test]
    fn contract_invalid_negative_tolerance() {
        let c = DeterminismContract {
            schema: TEST_TAXONOMY_SCHEMA_VERSION.to_string(),
            bit_identical_required: false,
            seed_required: false,
            virtual_clock_required: false,
            deterministic_rng_required: false,
            max_nondeterminism_sources: 0,
            numeric_tolerance_millionths: -1,
        };
        let violations = c.validate();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].field, "numeric_tolerance_millionths");
    }

    #[test]
    fn contract_invalid_bit_identical_with_tolerance() {
        let c = DeterminismContract {
            schema: TEST_TAXONOMY_SCHEMA_VERSION.to_string(),
            bit_identical_required: true,
            seed_required: false,
            virtual_clock_required: false,
            deterministic_rng_required: false,
            max_nondeterminism_sources: 0,
            numeric_tolerance_millionths: 100,
        };
        let violations = c.validate();
        assert!(!violations.is_empty());
    }

    #[test]
    fn contract_serde_roundtrip() {
        let c = DeterminismContract::strict();
        let json = serde_json::to_string(&c).unwrap();
        let back: DeterminismContract = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // -- FixtureEntry --

    fn make_fixture(id: &str, class: TestClass) -> FixtureEntry {
        FixtureEntry {
            fixture_id: id.to_string(),
            description: format!("Test fixture {id}"),
            test_class: class,
            surfaces: BTreeSet::from([TestSurface::Parser]),
            provenance: ProvenanceLevel::Authored,
            seed: if class.requires_seed() {
                Some(42)
            } else {
                None
            },
            content_hash: "sha256:abc123".to_string(),
            format_version: "1.0.0".to_string(),
            origin_ref: "bd-test".to_string(),
            tags: BTreeSet::new(),
        }
    }

    #[test]
    fn fixture_validate_passes_for_core() {
        let f = make_fixture("core-001", TestClass::Core);
        let c = DeterminismContract::for_class(TestClass::Core);
        assert!(f.validate_against_contract(&c).is_empty());
    }

    #[test]
    fn fixture_validate_fails_missing_seed() {
        let mut f = make_fixture("adv-001", TestClass::Adversarial);
        f.seed = None;
        let c = DeterminismContract::for_class(TestClass::Adversarial);
        let violations = f.validate_against_contract(&c);
        assert!(!violations.is_empty());
        assert!(violations.iter().any(|v| v.field == "seed"));
    }

    #[test]
    fn fixture_validate_fails_empty_hash() {
        let mut f = make_fixture("core-002", TestClass::Core);
        f.content_hash = String::new();
        let c = DeterminismContract::for_class(TestClass::Core);
        let violations = f.validate_against_contract(&c);
        assert!(violations.iter().any(|v| v.field == "content_hash"));
    }

    #[test]
    fn fixture_derive_id() {
        let f = make_fixture("core-003", TestClass::Core);
        let id = f.derive_id().unwrap();
        assert!(!id.to_hex().is_empty());
    }

    #[test]
    fn fixture_serde_roundtrip() {
        let f = make_fixture("serde-001", TestClass::Edge);
        let json = serde_json::to_string(&f).unwrap();
        let back: FixtureEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    // -- FixtureRegistry --

    #[test]
    fn registry_new_is_empty() {
        let r = FixtureRegistry::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert_eq!(r.schema, FIXTURE_REGISTRY_SCHEMA_VERSION);
    }

    #[test]
    fn registry_default_is_empty() {
        let r = FixtureRegistry::default();
        assert!(r.is_empty());
    }

    #[test]
    fn registry_register_and_lookup() {
        let mut r = FixtureRegistry::new();
        r.register(make_fixture("f1", TestClass::Core)).unwrap();
        assert_eq!(r.len(), 1);
        assert!(r.lookup("f1").is_some());
        assert!(r.lookup("f2").is_none());
    }

    #[test]
    fn registry_rejects_duplicate() {
        let mut r = FixtureRegistry::new();
        r.register(make_fixture("f1", TestClass::Core)).unwrap();
        let err = r.register(make_fixture("f1", TestClass::Edge)).unwrap_err();
        assert_eq!(err, RegistryError::DuplicateFixtureId("f1".to_string()));
    }

    #[test]
    fn registry_by_class() {
        let mut r = FixtureRegistry::new();
        r.register(make_fixture("c1", TestClass::Core)).unwrap();
        r.register(make_fixture("c2", TestClass::Core)).unwrap();
        r.register(make_fixture("e1", TestClass::Edge)).unwrap();
        assert_eq!(r.by_class(TestClass::Core).len(), 2);
        assert_eq!(r.by_class(TestClass::Edge).len(), 1);
        assert_eq!(r.by_class(TestClass::Adversarial).len(), 0);
    }

    #[test]
    fn registry_by_surface() {
        let mut r = FixtureRegistry::new();
        let mut f = make_fixture("s1", TestClass::Core);
        f.surfaces = BTreeSet::from([TestSurface::Compiler, TestSurface::Runtime]);
        r.register(f).unwrap();
        r.register(make_fixture("s2", TestClass::Core)).unwrap(); // Parser only
        assert_eq!(r.by_surface(TestSurface::Compiler).len(), 1);
        assert_eq!(r.by_surface(TestSurface::Parser).len(), 1);
        assert_eq!(r.by_surface(TestSurface::Runtime).len(), 1);
    }

    #[test]
    fn registry_validate_all_clean() {
        let mut r = FixtureRegistry::new();
        r.register(make_fixture("v1", TestClass::Core)).unwrap();
        r.register(make_fixture("v2", TestClass::Adversarial))
            .unwrap();
        assert!(r.validate_all().is_empty());
    }

    #[test]
    fn registry_validate_all_catches_missing_seed() {
        let mut r = FixtureRegistry::new();
        let mut bad = make_fixture("bad1", TestClass::Adversarial);
        bad.seed = None;
        r.register(bad).unwrap();
        let results = r.validate_all();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "bad1");
    }

    #[test]
    fn registry_coverage_matrix() {
        let mut r = FixtureRegistry::new();
        r.register(make_fixture("m1", TestClass::Core)).unwrap();
        r.register(make_fixture("m2", TestClass::Core)).unwrap();
        r.register(make_fixture("m3", TestClass::Edge)).unwrap();
        let matrix = r.coverage_matrix();
        assert_eq!(matrix[&(TestClass::Core, TestSurface::Parser)], 2);
        assert_eq!(matrix[&(TestClass::Edge, TestSurface::Parser)], 1);
    }

    #[test]
    fn registry_coverage_gaps() {
        let r = FixtureRegistry::new();
        let gaps = r.coverage_gaps();
        // 5 classes × 8 surfaces = 40 gaps
        assert_eq!(gaps.len(), 40);
    }

    #[test]
    fn registry_coverage_gaps_decrease_with_fixtures() {
        let mut r = FixtureRegistry::new();
        let initial_gaps = r.coverage_gaps().len();
        r.register(make_fixture("g1", TestClass::Core)).unwrap();
        let after_one = r.coverage_gaps().len();
        assert!(after_one < initial_gaps);
    }

    #[test]
    fn registry_serde_roundtrip() {
        let mut r = FixtureRegistry::new();
        r.register(make_fixture("sr1", TestClass::Core)).unwrap();
        r.register(make_fixture("sr2", TestClass::Adversarial))
            .unwrap();
        let json = serde_json::to_string(&r).unwrap();
        let back: FixtureRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // -- OwnershipMap --

    #[test]
    fn ownership_map_new_is_empty() {
        let m = OwnershipMap::new();
        assert!(m.entries.is_empty());
    }

    #[test]
    fn ownership_map_default() {
        let m = OwnershipMap::default();
        assert!(m.entries.is_empty());
    }

    #[test]
    fn ownership_map_add_and_query() {
        let mut m = OwnershipMap::new();
        m.add(OwnershipEntry {
            surface: TestSurface::Parser,
            test_class: TestClass::Core,
            lane_charter_ref: "bd-mjh3.10.3".to_string(),
            owner_agent: "PearlTower".to_string(),
            fixture_ids: BTreeSet::from(["f1".to_string()]),
        });
        assert_eq!(m.by_surface(TestSurface::Parser).len(), 1);
        assert_eq!(m.by_surface(TestSurface::Compiler).len(), 0);
    }

    #[test]
    fn ownership_map_unowned_fixtures() {
        let mut reg = FixtureRegistry::new();
        reg.register(make_fixture("f1", TestClass::Core)).unwrap();
        reg.register(make_fixture("f2", TestClass::Edge)).unwrap();

        let mut m = OwnershipMap::new();
        m.add(OwnershipEntry {
            surface: TestSurface::Parser,
            test_class: TestClass::Core,
            lane_charter_ref: "bd-mjh3.10.3".to_string(),
            owner_agent: "PearlTower".to_string(),
            fixture_ids: BTreeSet::from(["f1".to_string()]),
        });

        let unowned = m.unowned_fixtures(&reg);
        assert_eq!(unowned, vec!["f2".to_string()]);
    }

    #[test]
    fn ownership_map_serde_roundtrip() {
        let mut m = OwnershipMap::new();
        m.add(OwnershipEntry {
            surface: TestSurface::Compiler,
            test_class: TestClass::Regression,
            lane_charter_ref: "bd-mjh3.10.2".to_string(),
            owner_agent: "SilverLake".to_string(),
            fixture_ids: BTreeSet::from(["r1".to_string(), "r2".to_string()]),
        });
        let json = serde_json::to_string(&m).unwrap();
        let back: OwnershipMap = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    // -- TestOutcome --

    #[test]
    fn test_outcome_display() {
        assert_eq!(TestOutcome::Pass.to_string(), "pass");
        assert_eq!(TestOutcome::Fail.to_string(), "fail");
        assert_eq!(TestOutcome::Flake.to_string(), "flake");
    }

    #[test]
    fn test_outcome_is_success() {
        assert!(TestOutcome::Pass.is_success());
        assert!(!TestOutcome::Fail.is_success());
        assert!(!TestOutcome::Skip.is_success());
        assert!(!TestOutcome::Timeout.is_success());
        assert!(!TestOutcome::Flake.is_success());
    }

    #[test]
    fn test_outcome_serde_roundtrip() {
        for outcome in [
            TestOutcome::Pass,
            TestOutcome::Fail,
            TestOutcome::Skip,
            TestOutcome::Timeout,
            TestOutcome::Flake,
        ] {
            let json = serde_json::to_string(&outcome).unwrap();
            let back: TestOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(outcome, back);
        }
    }

    // -- TestExecutionRecord --

    fn make_record(fixture_id: &str, outcome: TestOutcome) -> TestExecutionRecord {
        TestExecutionRecord {
            fixture_id: fixture_id.to_string(),
            test_class: TestClass::Core,
            surface: TestSurface::Parser,
            outcome,
            seed: None,
            duration_us: 1000,
            determinism_satisfied: true,
            evidence_hash: "sha256:evidence".to_string(),
            notes: String::new(),
        }
    }

    #[test]
    fn execution_record_serde_roundtrip() {
        let r = make_record("f1", TestOutcome::Pass);
        let json = serde_json::to_string(&r).unwrap();
        let back: TestExecutionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // -- TestSuiteSummary --

    #[test]
    fn suite_summary_empty() {
        let s = TestSuiteSummary::from_records(&[]);
        assert_eq!(s.total, 0);
        assert_eq!(s.passed, 0);
        assert_eq!(s.pass_rate_millionths, 0);
    }

    #[test]
    fn suite_summary_all_pass() {
        let records = vec![
            make_record("a", TestOutcome::Pass),
            make_record("b", TestOutcome::Pass),
        ];
        let s = TestSuiteSummary::from_records(&records);
        assert_eq!(s.total, 2);
        assert_eq!(s.passed, 2);
        assert_eq!(s.pass_rate_millionths, MILLION);
    }

    #[test]
    fn suite_summary_mixed() {
        let records = vec![
            make_record("a", TestOutcome::Pass),
            make_record("b", TestOutcome::Fail),
            make_record("c", TestOutcome::Skip),
            make_record("d", TestOutcome::Timeout),
        ];
        let s = TestSuiteSummary::from_records(&records);
        assert_eq!(s.total, 4);
        assert_eq!(s.passed, 1);
        assert_eq!(s.failed, 1);
        assert_eq!(s.skipped, 1);
        assert_eq!(s.timed_out, 1);
        assert_eq!(s.pass_rate_millionths, 250_000); // 25%
    }

    #[test]
    fn suite_summary_class_breakdown() {
        let mut r1 = make_record("a", TestOutcome::Pass);
        r1.test_class = TestClass::Core;
        let mut r2 = make_record("b", TestOutcome::Fail);
        r2.test_class = TestClass::Edge;
        let mut r3 = make_record("c", TestOutcome::Pass);
        r3.test_class = TestClass::Core;

        let s = TestSuiteSummary::from_records(&[r1, r2, r3]);
        let core = &s.class_breakdown[&TestClass::Core];
        assert_eq!(core.total, 2);
        assert_eq!(core.passed, 2);
        let edge = &s.class_breakdown[&TestClass::Edge];
        assert_eq!(edge.total, 1);
        assert_eq!(edge.failed, 1);
    }

    #[test]
    fn suite_summary_surface_breakdown() {
        let mut r1 = make_record("a", TestOutcome::Pass);
        r1.surface = TestSurface::Compiler;
        let r2 = make_record("b", TestOutcome::Pass); // Parser
        let s = TestSuiteSummary::from_records(&[r1, r2]);
        assert_eq!(s.surface_breakdown[&TestSurface::Compiler], 1);
        assert_eq!(s.surface_breakdown[&TestSurface::Parser], 1);
    }

    #[test]
    fn suite_summary_determinism_rate() {
        let mut r1 = make_record("a", TestOutcome::Pass);
        r1.determinism_satisfied = true;
        let mut r2 = make_record("b", TestOutcome::Pass);
        r2.determinism_satisfied = false;
        let s = TestSuiteSummary::from_records(&[r1, r2]);
        assert_eq!(s.determinism_rate_millionths, 500_000);
    }

    #[test]
    fn suite_summary_meets_threshold() {
        let records = vec![
            make_record("a", TestOutcome::Pass),
            make_record("b", TestOutcome::Pass),
            make_record("c", TestOutcome::Fail),
        ];
        let s = TestSuiteSummary::from_records(&records);
        assert!(s.meets_threshold(600_000)); // 60% threshold, actual ~66%
        assert!(!s.meets_threshold(700_000)); // 70% threshold, actual ~66%
    }

    #[test]
    fn suite_summary_serde_roundtrip() {
        let records = vec![
            make_record("a", TestOutcome::Pass),
            make_record("b", TestOutcome::Fail),
        ];
        let s = TestSuiteSummary::from_records(&records);
        let json = serde_json::to_string(&s).unwrap();
        let back: TestSuiteSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // -- RegistryError --

    #[test]
    fn registry_error_display() {
        let e = RegistryError::DuplicateFixtureId("f1".to_string());
        assert!(e.to_string().contains("f1"));
        let e2 = RegistryError::FixtureNotFound("f2".to_string());
        assert!(e2.to_string().contains("f2"));
        let e3 = RegistryError::InvalidFixture("bad".to_string());
        assert!(e3.to_string().contains("bad"));
    }

    #[test]
    fn registry_error_serde_roundtrip() {
        let e = RegistryError::DuplicateFixtureId("test".to_string());
        let json = serde_json::to_string(&e).unwrap();
        let back: RegistryError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // -- Cross-cutting --

    #[test]
    fn min_provenance_for_each_class() {
        assert_eq!(
            TestClass::Core.min_provenance_level(),
            ProvenanceLevel::Authored
        );
        assert_eq!(
            TestClass::Edge.min_provenance_level(),
            ProvenanceLevel::Authored
        );
        assert_eq!(
            TestClass::Adversarial.min_provenance_level(),
            ProvenanceLevel::Generated
        );
        assert_eq!(
            TestClass::Regression.min_provenance_level(),
            ProvenanceLevel::Captured
        );
        assert_eq!(
            TestClass::FaultInjection.min_provenance_level(),
            ProvenanceLevel::Generated
        );
    }

    #[test]
    fn contract_for_all_classes_is_valid() {
        for class in TestClass::ALL {
            let c = DeterminismContract::for_class(*class);
            assert!(
                c.validate().is_empty(),
                "Contract for {class} has violations"
            );
        }
    }

    #[test]
    fn complete_workflow_register_validate_summarize() {
        // Build registry
        let mut reg = FixtureRegistry::new();
        for i in 0..5 {
            for class in TestClass::ALL {
                let id = format!("{}-{i}", class.as_str());
                let mut f = make_fixture(&id, *class);
                f.surfaces = BTreeSet::from([TestSurface::Parser, TestSurface::Runtime]);
                reg.register(f).unwrap();
            }
        }
        assert_eq!(reg.len(), 25);

        // Validate
        let violations = reg.validate_all();
        assert!(violations.is_empty());

        // Build execution records
        let records: Vec<_> = reg
            .entries
            .iter()
            .map(|f| TestExecutionRecord {
                fixture_id: f.fixture_id.clone(),
                test_class: f.test_class,
                surface: TestSurface::Parser,
                outcome: TestOutcome::Pass,
                seed: f.seed,
                duration_us: 500,
                determinism_satisfied: true,
                evidence_hash: "sha256:ok".to_string(),
                notes: String::new(),
            })
            .collect();
        let summary = TestSuiteSummary::from_records(&records);
        assert_eq!(summary.total, 25);
        assert_eq!(summary.passed, 25);
        assert_eq!(summary.pass_rate_millionths, MILLION);
        assert!(summary.meets_threshold(999_000));
    }

    #[test]
    fn ownership_map_complete_coverage() {
        let mut reg = FixtureRegistry::new();
        reg.register(make_fixture("f1", TestClass::Core)).unwrap();
        reg.register(make_fixture("f2", TestClass::Edge)).unwrap();

        let mut m = OwnershipMap::new();
        m.add(OwnershipEntry {
            surface: TestSurface::Parser,
            test_class: TestClass::Core,
            lane_charter_ref: TestSurface::Parser.lane_charter_ref().to_string(),
            owner_agent: "Agent1".to_string(),
            fixture_ids: BTreeSet::from(["f1".to_string(), "f2".to_string()]),
        });
        assert!(m.unowned_fixtures(&reg).is_empty());
    }

    #[test]
    fn test_class_display_unique() {
        let mut strs = BTreeSet::new();
        for class in TestClass::ALL {
            assert!(strs.insert(class.as_str()));
        }
    }

    #[test]
    fn test_surface_display_unique() {
        let mut strs = BTreeSet::new();
        for surface in TestSurface::ALL {
            assert!(strs.insert(surface.as_str()));
        }
    }

    #[test]
    fn flake_counted_in_summary() {
        let mut r = make_record("f1", TestOutcome::Flake);
        r.determinism_satisfied = false;
        let s = TestSuiteSummary::from_records(&[r]);
        assert_eq!(s.flaky, 1);
        assert_eq!(s.passed, 0);
        assert!(!s.meets_threshold(1));
    }

    #[test]
    fn fixture_multiple_surfaces() {
        let mut f = make_fixture("multi", TestClass::Core);
        f.surfaces = BTreeSet::from([
            TestSurface::Compiler,
            TestSurface::Runtime,
            TestSurface::Router,
        ]);
        let mut reg = FixtureRegistry::new();
        reg.register(f).unwrap();
        let matrix = reg.coverage_matrix();
        assert_eq!(matrix[&(TestClass::Core, TestSurface::Compiler)], 1);
        assert_eq!(matrix[&(TestClass::Core, TestSurface::Runtime)], 1);
        assert_eq!(matrix[&(TestClass::Core, TestSurface::Router)], 1);
    }

    #[test]
    fn contract_violation_serde_roundtrip() {
        let v = ContractViolation {
            field: "seed".to_string(),
            message: "missing".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: ContractViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn schema_versions_set() {
        assert!(!TEST_TAXONOMY_SCHEMA_VERSION.is_empty());
        assert!(!FIXTURE_REGISTRY_SCHEMA_VERSION.is_empty());
    }

    // ================================================================
    // Enrichment tests — deeper edge-case and cross-cutting coverage
    // ================================================================

    // -- TestClass enrichment --

    #[test]
    fn test_class_all_exhaustive() {
        let all_set: BTreeSet<TestClass> = TestClass::ALL.iter().copied().collect();
        assert_eq!(all_set.len(), TestClass::ALL.len(), "ALL has no duplicates");
    }

    #[test]
    fn test_class_ordering_is_total() {
        for (i, a) in TestClass::ALL.iter().enumerate() {
            for b in &TestClass::ALL[i + 1..] {
                assert!(a < b, "{a} should be < {b}");
            }
        }
    }

    #[test]
    fn test_class_requires_seed_implies_generated_provenance() {
        for class in TestClass::ALL {
            if class.requires_seed() {
                assert!(
                    class.min_provenance_level().trust_rank()
                        <= ProvenanceLevel::Generated.trust_rank(),
                    "{class} requires seed but min provenance is above Generated"
                );
            }
        }
    }

    // -- TestSurface enrichment --

    #[test]
    fn test_surface_all_exhaustive() {
        let all_set: BTreeSet<TestSurface> = TestSurface::ALL.iter().copied().collect();
        assert_eq!(
            all_set.len(),
            TestSurface::ALL.len(),
            "ALL has no duplicates"
        );
    }

    #[test]
    fn test_surface_lane_charter_refs_nonempty() {
        for surface in TestSurface::ALL {
            let lcr = surface.lane_charter_ref();
            assert!(!lcr.is_empty(), "{surface} has empty lane charter ref");
            assert!(
                lcr.starts_with("bd-"),
                "{surface} lane charter ref should start with bd-"
            );
        }
    }

    #[test]
    fn test_surface_ordering_is_total() {
        for (i, a) in TestSurface::ALL.iter().enumerate() {
            for b in &TestSurface::ALL[i + 1..] {
                assert!(a < b, "{a} should be < {b}");
            }
        }
    }

    // -- ProvenanceLevel enrichment --

    #[test]
    fn provenance_trust_rank_unique() {
        let ranks: Vec<u8> = [
            ProvenanceLevel::Synthesized,
            ProvenanceLevel::Generated,
            ProvenanceLevel::Captured,
            ProvenanceLevel::Authored,
        ]
        .iter()
        .map(|p| p.trust_rank())
        .collect();
        let set: BTreeSet<u8> = ranks.iter().copied().collect();
        assert_eq!(ranks.len(), set.len(), "trust ranks must be unique");
    }

    #[test]
    fn provenance_serde_all_variants() {
        for p in [
            ProvenanceLevel::Authored,
            ProvenanceLevel::Generated,
            ProvenanceLevel::Captured,
            ProvenanceLevel::Synthesized,
        ] {
            let json = serde_json::to_string(&p).unwrap();
            let back: ProvenanceLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(p, back);
        }
    }

    #[test]
    fn provenance_display_all_unique() {
        let mut strs = BTreeSet::new();
        for p in [
            ProvenanceLevel::Authored,
            ProvenanceLevel::Generated,
            ProvenanceLevel::Captured,
            ProvenanceLevel::Synthesized,
        ] {
            assert!(strs.insert(p.to_string()), "duplicate display for {p}");
        }
    }

    // -- DeterminismContract enrichment --

    #[test]
    fn contract_strict_zero_tolerance() {
        let c = DeterminismContract::strict();
        assert_eq!(c.numeric_tolerance_millionths, 0);
        assert_eq!(c.max_nondeterminism_sources, 0);
    }

    #[test]
    fn contract_relaxed_zero_tolerance_valid() {
        let c = DeterminismContract::relaxed(0);
        assert!(c.validate().is_empty());
    }

    #[test]
    fn contract_bit_identical_with_nondet_no_rng_invalid() {
        let c = DeterminismContract {
            schema: TEST_TAXONOMY_SCHEMA_VERSION.to_string(),
            bit_identical_required: true,
            seed_required: true,
            virtual_clock_required: true,
            deterministic_rng_required: false,
            max_nondeterminism_sources: 2,
            numeric_tolerance_millionths: 0,
        };
        let violations = c.validate();
        assert!(!violations.is_empty());
        assert!(
            violations
                .iter()
                .any(|v| v.field == "max_nondeterminism_sources")
        );
    }

    #[test]
    fn contract_bit_identical_with_nondet_and_rng_valid() {
        let c = DeterminismContract {
            schema: TEST_TAXONOMY_SCHEMA_VERSION.to_string(),
            bit_identical_required: true,
            seed_required: true,
            virtual_clock_required: true,
            deterministic_rng_required: true,
            max_nondeterminism_sources: 1,
            numeric_tolerance_millionths: 0,
        };
        assert!(c.validate().is_empty());
    }

    #[test]
    fn contract_multiple_violations() {
        let c = DeterminismContract {
            schema: TEST_TAXONOMY_SCHEMA_VERSION.to_string(),
            bit_identical_required: true,
            seed_required: false,
            virtual_clock_required: false,
            deterministic_rng_required: false,
            max_nondeterminism_sources: 5,
            numeric_tolerance_millionths: -100,
        };
        let violations = c.validate();
        assert!(violations.len() >= 2, "expected multiple violations");
    }

    #[test]
    fn contract_for_class_regression() {
        let c = DeterminismContract::for_class(TestClass::Regression);
        assert!(c.bit_identical_required);
        assert!(!c.seed_required);
        assert!(!c.virtual_clock_required);
        assert_eq!(c.max_nondeterminism_sources, 0);
    }

    #[test]
    fn contract_for_class_edge_same_as_core() {
        let core = DeterminismContract::for_class(TestClass::Core);
        let edge = DeterminismContract::for_class(TestClass::Edge);
        assert_eq!(core, edge);
    }

    #[test]
    fn contract_schema_matches_module_version() {
        let c = DeterminismContract::strict();
        assert_eq!(c.schema, TEST_TAXONOMY_SCHEMA_VERSION);
    }

    // -- FixtureEntry enrichment --

    #[test]
    fn fixture_validate_low_provenance_for_core() {
        let mut f = make_fixture("prov-core", TestClass::Core);
        f.provenance = ProvenanceLevel::Synthesized;
        let c = DeterminismContract::for_class(TestClass::Core);
        let violations = f.validate_against_contract(&c);
        assert!(
            violations.iter().any(|v| v.field == "provenance"),
            "Synthesized provenance should fail for Core class"
        );
    }

    #[test]
    fn fixture_validate_captured_ok_for_regression() {
        let mut f = make_fixture("reg-001", TestClass::Regression);
        f.provenance = ProvenanceLevel::Captured;
        let c = DeterminismContract::for_class(TestClass::Regression);
        assert!(f.validate_against_contract(&c).is_empty());
    }

    #[test]
    fn fixture_validate_authored_ok_for_any_class() {
        for class in TestClass::ALL {
            let f = make_fixture(&format!("auth-{}", class.as_str()), *class);
            let c = DeterminismContract::for_class(*class);
            let provenance_violations: Vec<_> = f
                .validate_against_contract(&c)
                .into_iter()
                .filter(|v| v.field == "provenance")
                .collect();
            assert!(
                provenance_violations.is_empty(),
                "Authored provenance should be accepted for {class}"
            );
        }
    }

    #[test]
    fn fixture_derive_id_deterministic() {
        let f = make_fixture("det-001", TestClass::Core);
        let id1 = f.derive_id().unwrap();
        let id2 = f.derive_id().unwrap();
        assert_eq!(id1, id2, "derive_id must be deterministic");
    }

    #[test]
    fn fixture_derive_id_distinct_for_different_ids() {
        let f1 = make_fixture("distinct-a", TestClass::Core);
        let f2 = make_fixture("distinct-b", TestClass::Core);
        let id1 = f1.derive_id().unwrap();
        let id2 = f2.derive_id().unwrap();
        assert_ne!(
            id1, id2,
            "different fixture_ids should produce different IDs"
        );
    }

    #[test]
    fn fixture_tags_deterministic_ordering() {
        let mut f = make_fixture("tags-001", TestClass::Core);
        f.tags = BTreeSet::from(["alpha".to_string(), "beta".to_string(), "gamma".to_string()]);
        let json = serde_json::to_string(&f).unwrap();
        let back: FixtureEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(f.tags, back.tags);
        let tags_vec: Vec<_> = back.tags.iter().collect();
        assert_eq!(tags_vec, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn fixture_empty_surfaces() {
        let mut f = make_fixture("no-surface", TestClass::Core);
        f.surfaces = BTreeSet::new();
        let json = serde_json::to_string(&f).unwrap();
        let back: FixtureEntry = serde_json::from_str(&json).unwrap();
        assert!(back.surfaces.is_empty());
    }

    #[test]
    fn fixture_all_surfaces() {
        let mut f = make_fixture("all-surfaces", TestClass::Core);
        f.surfaces = TestSurface::ALL.iter().copied().collect();
        assert_eq!(f.surfaces.len(), 8);
        let json = serde_json::to_string(&f).unwrap();
        let back: FixtureEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(f.surfaces, back.surfaces);
    }

    // -- FixtureRegistry enrichment --

    #[test]
    fn registry_multi_class_multi_surface_coverage() {
        let mut r = FixtureRegistry::new();
        for class in TestClass::ALL {
            for surface in TestSurface::ALL {
                let id = format!("{}-{}", class.as_str(), surface.as_str());
                let mut f = make_fixture(&id, *class);
                f.surfaces = BTreeSet::from([*surface]);
                r.register(f).unwrap();
            }
        }
        assert_eq!(r.len(), 40);
        assert!(
            r.coverage_gaps().is_empty(),
            "full matrix should have no gaps"
        );
    }

    #[test]
    fn registry_coverage_matrix_multi_surface_fixture() {
        let mut r = FixtureRegistry::new();
        let mut f = make_fixture("multi-surface", TestClass::Core);
        f.surfaces = BTreeSet::from([
            TestSurface::Compiler,
            TestSurface::Runtime,
            TestSurface::Parser,
        ]);
        r.register(f).unwrap();
        let matrix = r.coverage_matrix();
        assert_eq!(matrix[&(TestClass::Core, TestSurface::Compiler)], 1);
        assert_eq!(matrix[&(TestClass::Core, TestSurface::Runtime)], 1);
        assert_eq!(matrix[&(TestClass::Core, TestSurface::Parser)], 1);
        assert_eq!(r.coverage_gaps().len(), 37); // 40 - 3
    }

    #[test]
    fn registry_validate_all_with_mixed_valid_invalid() {
        let mut r = FixtureRegistry::new();
        r.register(make_fixture("good", TestClass::Core)).unwrap();
        let mut bad = make_fixture("bad-adv", TestClass::Adversarial);
        bad.seed = None;
        r.register(bad).unwrap();
        let results = r.validate_all();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "bad-adv");
    }

    #[test]
    fn registry_by_class_empty_for_missing() {
        let mut r = FixtureRegistry::new();
        r.register(make_fixture("c", TestClass::Core)).unwrap();
        assert!(r.by_class(TestClass::FaultInjection).is_empty());
    }

    #[test]
    fn registry_by_surface_empty_for_missing() {
        let mut r = FixtureRegistry::new();
        r.register(make_fixture("p", TestClass::Core)).unwrap(); // Parser only
        assert!(r.by_surface(TestSurface::Governance).is_empty());
    }

    #[test]
    fn registry_large_scale() {
        let mut r = FixtureRegistry::new();
        for i in 0..200 {
            r.register(make_fixture(&format!("large-{i}"), TestClass::ALL[i % 5]))
                .unwrap();
        }
        assert_eq!(r.len(), 200);
        assert_eq!(r.by_class(TestClass::Core).len(), 40);
        assert_eq!(r.by_class(TestClass::Edge).len(), 40);
    }

    #[test]
    fn registry_serde_roundtrip_large() {
        let mut r = FixtureRegistry::new();
        for i in 0..50 {
            let mut f = make_fixture(&format!("rt-{i}"), TestClass::ALL[i % 5]);
            f.tags = BTreeSet::from([format!("tag-{}", i % 3)]);
            r.register(f).unwrap();
        }
        let json = serde_json::to_string(&r).unwrap();
        let back: FixtureRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // -- OwnershipMap enrichment --

    #[test]
    fn ownership_map_multi_agent() {
        let mut m = OwnershipMap::new();
        m.add(OwnershipEntry {
            surface: TestSurface::Parser,
            test_class: TestClass::Core,
            lane_charter_ref: "bd-mjh3.10.3".to_string(),
            owner_agent: "Agent-A".to_string(),
            fixture_ids: BTreeSet::from(["f1".to_string()]),
        });
        m.add(OwnershipEntry {
            surface: TestSurface::Parser,
            test_class: TestClass::Edge,
            lane_charter_ref: "bd-mjh3.10.3".to_string(),
            owner_agent: "Agent-B".to_string(),
            fixture_ids: BTreeSet::from(["f2".to_string()]),
        });
        let parser_entries = m.by_surface(TestSurface::Parser);
        assert_eq!(parser_entries.len(), 2);
    }

    #[test]
    fn ownership_map_all_fixtures_owned() {
        let mut reg = FixtureRegistry::new();
        for i in 0..5 {
            reg.register(make_fixture(&format!("o-{i}"), TestClass::Core))
                .unwrap();
        }
        let mut m = OwnershipMap::new();
        m.add(OwnershipEntry {
            surface: TestSurface::Parser,
            test_class: TestClass::Core,
            lane_charter_ref: "bd-mjh3.10.3".to_string(),
            owner_agent: "OwnerAll".to_string(),
            fixture_ids: (0..5).map(|i| format!("o-{i}")).collect(),
        });
        assert!(m.unowned_fixtures(&reg).is_empty());
    }

    #[test]
    fn ownership_map_partial_ownership() {
        let mut reg = FixtureRegistry::new();
        for i in 0..4 {
            reg.register(make_fixture(&format!("p-{i}"), TestClass::Core))
                .unwrap();
        }
        let mut m = OwnershipMap::new();
        m.add(OwnershipEntry {
            surface: TestSurface::Parser,
            test_class: TestClass::Core,
            lane_charter_ref: "bd-mjh3.10.3".to_string(),
            owner_agent: "PartialOwner".to_string(),
            fixture_ids: BTreeSet::from(["p-0".to_string(), "p-1".to_string()]),
        });
        let unowned = m.unowned_fixtures(&reg);
        assert_eq!(unowned.len(), 2);
        assert!(unowned.contains(&"p-2".to_string()));
        assert!(unowned.contains(&"p-3".to_string()));
    }

    #[test]
    fn ownership_map_empty_registry_no_unowned() {
        let reg = FixtureRegistry::new();
        let m = OwnershipMap::new();
        assert!(m.unowned_fixtures(&reg).is_empty());
    }

    // -- TestOutcome enrichment --

    #[test]
    fn test_outcome_ordering() {
        assert!(TestOutcome::Pass < TestOutcome::Fail);
        assert!(TestOutcome::Skip < TestOutcome::Timeout);
    }

    #[test]
    fn test_outcome_as_str_all_unique() {
        let strs: BTreeSet<&str> = [
            TestOutcome::Pass,
            TestOutcome::Fail,
            TestOutcome::Skip,
            TestOutcome::Timeout,
            TestOutcome::Flake,
        ]
        .iter()
        .map(|o| o.as_str())
        .collect();
        assert_eq!(strs.len(), 5);
    }

    // -- TestExecutionRecord enrichment --

    #[test]
    fn execution_record_with_seed() {
        let mut r = make_record("seeded", TestOutcome::Pass);
        r.seed = Some(42);
        r.test_class = TestClass::Adversarial;
        let json = serde_json::to_string(&r).unwrap();
        let back: TestExecutionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.seed, Some(42));
        assert_eq!(back.test_class, TestClass::Adversarial);
    }

    #[test]
    fn execution_record_with_notes() {
        let mut r = make_record("noted", TestOutcome::Fail);
        r.notes = "Known flaky on CI".to_string();
        let json = serde_json::to_string(&r).unwrap();
        let back: TestExecutionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.notes, "Known flaky on CI");
    }

    #[test]
    fn execution_record_all_surfaces() {
        for surface in TestSurface::ALL {
            let mut r = make_record(&format!("surf-{}", surface.as_str()), TestOutcome::Pass);
            r.surface = *surface;
            let json = serde_json::to_string(&r).unwrap();
            let back: TestExecutionRecord = serde_json::from_str(&json).unwrap();
            assert_eq!(back.surface, *surface);
        }
    }

    // -- TestSuiteSummary enrichment --

    #[test]
    fn suite_summary_all_fail() {
        let records = vec![
            make_record("f1", TestOutcome::Fail),
            make_record("f2", TestOutcome::Fail),
            make_record("f3", TestOutcome::Fail),
        ];
        let s = TestSuiteSummary::from_records(&records);
        assert_eq!(s.total, 3);
        assert_eq!(s.failed, 3);
        assert_eq!(s.pass_rate_millionths, 0);
        assert!(!s.meets_threshold(1));
    }

    #[test]
    fn suite_summary_all_skip() {
        let records = vec![
            make_record("s1", TestOutcome::Skip),
            make_record("s2", TestOutcome::Skip),
        ];
        let s = TestSuiteSummary::from_records(&records);
        assert_eq!(s.skipped, 2);
        assert_eq!(s.pass_rate_millionths, 0);
    }

    #[test]
    fn suite_summary_single_record() {
        let s = TestSuiteSummary::from_records(&[make_record("one", TestOutcome::Pass)]);
        assert_eq!(s.total, 1);
        assert_eq!(s.passed, 1);
        assert_eq!(s.pass_rate_millionths, MILLION);
        assert!(s.meets_threshold(MILLION));
    }

    #[test]
    fn suite_summary_all_determinism_satisfied() {
        let records = vec![
            make_record("d1", TestOutcome::Pass),
            make_record("d2", TestOutcome::Pass),
        ];
        let s = TestSuiteSummary::from_records(&records);
        assert_eq!(s.determinism_rate_millionths, MILLION);
    }

    #[test]
    fn suite_summary_no_determinism_satisfied() {
        let mut r1 = make_record("nd1", TestOutcome::Pass);
        r1.determinism_satisfied = false;
        let mut r2 = make_record("nd2", TestOutcome::Fail);
        r2.determinism_satisfied = false;
        let s = TestSuiteSummary::from_records(&[r1, r2]);
        assert_eq!(s.determinism_rate_millionths, 0);
    }

    #[test]
    fn suite_summary_surface_breakdown_all_surfaces() {
        let records: Vec<_> = TestSurface::ALL
            .iter()
            .enumerate()
            .map(|(i, surface)| {
                let mut r = make_record(&format!("sb-{i}"), TestOutcome::Pass);
                r.surface = *surface;
                r
            })
            .collect();
        let s = TestSuiteSummary::from_records(&records);
        for surface in TestSurface::ALL {
            assert_eq!(s.surface_breakdown[surface], 1);
        }
    }

    #[test]
    fn suite_summary_class_breakdown_all_classes() {
        let records: Vec<_> = TestClass::ALL
            .iter()
            .enumerate()
            .map(|(i, class)| {
                let mut r = make_record(&format!("cb-{i}"), TestOutcome::Pass);
                r.test_class = *class;
                r
            })
            .collect();
        let s = TestSuiteSummary::from_records(&records);
        for class in TestClass::ALL {
            let cb = &s.class_breakdown[class];
            assert_eq!(cb.total, 1);
            assert_eq!(cb.passed, 1);
            assert_eq!(cb.failed, 0);
        }
    }

    #[test]
    fn suite_summary_meets_threshold_edge_exact() {
        let records = vec![
            make_record("t1", TestOutcome::Pass),
            make_record("t2", TestOutcome::Fail),
        ];
        let s = TestSuiteSummary::from_records(&records);
        assert!(s.meets_threshold(500_000)); // exactly 50%
        assert!(!s.meets_threshold(500_001)); // 50% + epsilon
    }

    #[test]
    fn suite_summary_serde_roundtrip_complex() {
        let mut records = Vec::new();
        for (i, class) in TestClass::ALL.iter().enumerate() {
            for (j, surface) in TestSurface::ALL.iter().enumerate() {
                let outcome = if (i + j) % 3 == 0 {
                    TestOutcome::Fail
                } else {
                    TestOutcome::Pass
                };
                let mut r = make_record(&format!("cx-{i}-{j}"), outcome);
                r.test_class = *class;
                r.surface = *surface;
                r.determinism_satisfied = (i % 2 == 0);
                records.push(r);
            }
        }
        let s = TestSuiteSummary::from_records(&records);
        let json = serde_json::to_string(&s).unwrap();
        let back: TestSuiteSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // -- RegistryError enrichment --

    #[test]
    fn registry_error_all_variants_display() {
        let errors = vec![
            RegistryError::DuplicateFixtureId("dup".to_string()),
            RegistryError::FixtureNotFound("missing".to_string()),
            RegistryError::InvalidFixture("broken".to_string()),
        ];
        for e in &errors {
            let display = e.to_string();
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn registry_error_serde_all_variants() {
        let errors = vec![
            RegistryError::DuplicateFixtureId("dup".to_string()),
            RegistryError::FixtureNotFound("missing".to_string()),
            RegistryError::InvalidFixture("broken".to_string()),
        ];
        for e in errors {
            let json = serde_json::to_string(&e).unwrap();
            let back: RegistryError = serde_json::from_str(&json).unwrap();
            assert_eq!(e, back);
        }
    }

    // -- Cross-cutting enrichment --

    #[test]
    fn end_to_end_taxonomy_pipeline() {
        // 1. Build registry with all class × surface combinations
        let mut reg = FixtureRegistry::new();
        let mut fixture_ids = BTreeSet::new();
        for class in TestClass::ALL {
            for surface in TestSurface::ALL {
                let id = format!("e2e-{}-{}", class.as_str(), surface.as_str());
                let mut f = make_fixture(&id, *class);
                f.surfaces = BTreeSet::from([*surface]);
                fixture_ids.insert(id.clone());
                reg.register(f).unwrap();
            }
        }
        assert_eq!(reg.len(), 40);
        assert!(reg.coverage_gaps().is_empty());
        assert!(reg.validate_all().is_empty());

        // 2. Build ownership map covering all fixtures
        let mut omap = OwnershipMap::new();
        for surface in TestSurface::ALL {
            let surface_fixtures: BTreeSet<String> = fixture_ids
                .iter()
                .filter(|id| id.ends_with(surface.as_str()))
                .cloned()
                .collect();
            omap.add(OwnershipEntry {
                surface: *surface,
                test_class: TestClass::Core, // representative
                lane_charter_ref: surface.lane_charter_ref().to_string(),
                owner_agent: "E2EAgent".to_string(),
                fixture_ids: surface_fixtures,
            });
        }
        assert!(omap.unowned_fixtures(&reg).is_empty());

        // 3. Execute and summarize
        let records: Vec<_> = reg
            .entries
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let outcome = if i % 10 == 0 {
                    TestOutcome::Fail
                } else {
                    TestOutcome::Pass
                };
                TestExecutionRecord {
                    fixture_id: f.fixture_id.clone(),
                    test_class: f.test_class,
                    surface: *f.surfaces.iter().next().unwrap(),
                    outcome,
                    seed: f.seed,
                    duration_us: 100 + (i as u64) * 10,
                    determinism_satisfied: true,
                    evidence_hash: format!("sha256:e2e-{i}"),
                    notes: String::new(),
                }
            })
            .collect();
        let summary = TestSuiteSummary::from_records(&records);
        assert_eq!(summary.total, 40);
        assert!(summary.passed >= 36);
        assert!(summary.meets_threshold(900_000)); // >= 90%
    }

    #[test]
    fn fixture_id_derivation_stability_across_serde() {
        let f = make_fixture("stability-check", TestClass::Adversarial);
        let id_before = f.derive_id().unwrap();
        let json = serde_json::to_string(&f).unwrap();
        let back: FixtureEntry = serde_json::from_str(&json).unwrap();
        let id_after = back.derive_id().unwrap();
        assert_eq!(
            id_before, id_after,
            "ID derivation must survive serde roundtrip"
        );
    }

    #[test]
    fn contract_for_every_class_has_correct_schema() {
        for class in TestClass::ALL {
            let c = DeterminismContract::for_class(*class);
            assert_eq!(c.schema, TEST_TAXONOMY_SCHEMA_VERSION);
        }
    }

    #[test]
    fn coverage_gap_count_monotone_decreasing() {
        let mut reg = FixtureRegistry::new();
        let mut prev_gaps = reg.coverage_gaps().len();
        for (i, class) in TestClass::ALL.iter().enumerate() {
            for (j, surface) in TestSurface::ALL.iter().enumerate() {
                let id = format!("mono-{i}-{j}");
                let mut f = make_fixture(&id, *class);
                f.surfaces = BTreeSet::from([*surface]);
                reg.register(f).unwrap();
                let new_gaps = reg.coverage_gaps().len();
                assert!(new_gaps <= prev_gaps, "gaps must be monotone decreasing");
                prev_gaps = new_gaps;
            }
        }
        assert_eq!(prev_gaps, 0);
    }

    #[test]
    fn ownership_map_by_surface_empty_for_unregistered_surface() {
        let m = OwnershipMap::new();
        assert!(m.by_surface(TestSurface::Security).is_empty());
    }

    #[test]
    fn suite_summary_flake_rate_separate_from_fail() {
        let records = vec![
            make_record("fr1", TestOutcome::Pass),
            make_record("fr2", TestOutcome::Flake),
            make_record("fr3", TestOutcome::Fail),
        ];
        let s = TestSuiteSummary::from_records(&records);
        assert_eq!(s.flaky, 1);
        assert_eq!(s.failed, 1);
        assert_eq!(s.passed, 1);
        assert!(!TestOutcome::Flake.is_success());
    }

    #[test]
    fn registry_default_schema_matches_constant() {
        let r = FixtureRegistry::default();
        assert_eq!(r.schema, FIXTURE_REGISTRY_SCHEMA_VERSION);
    }

    #[test]
    fn ownership_map_default_schema_matches_constant() {
        let m = OwnershipMap::default();
        assert_eq!(m.schema, TEST_TAXONOMY_SCHEMA_VERSION);
    }
}
