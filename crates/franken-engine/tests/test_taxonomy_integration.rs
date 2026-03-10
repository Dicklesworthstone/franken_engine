#![forbid(unsafe_code)]
//! Integration tests for the `test_taxonomy` module.
//!
//! Exercises the unified test taxonomy, fixture registry, determinism
//! contracts, ownership mapping, and test suite summaries from outside
//! the crate boundary.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeSet;

use frankenengine_engine::test_taxonomy::{
    ClassBreakdown, ContractViolation, DeterminismContract, FIXTURE_REGISTRY_SCHEMA_VERSION,
    FixtureEntry, FixtureRegistry, OwnershipEntry, OwnershipMap, ProvenanceLevel, RegistryError,
    TEST_TAXONOMY_SCHEMA_VERSION, TestClass, TestExecutionRecord, TestOutcome, TestSuiteSummary,
    TestSurface,
};

// ===========================================================================
// Helpers
// ===========================================================================

fn make_fixture(id: &str, class: TestClass) -> FixtureEntry {
    FixtureEntry {
        fixture_id: id.into(),
        description: format!("fixture {id}"),
        test_class: class,
        surfaces: [TestSurface::Parser].into_iter().collect(),
        provenance: ProvenanceLevel::Authored,
        seed: if class.requires_seed() {
            Some(42)
        } else {
            None
        },
        content_hash: "abcdef0123456789".into(),
        format_version: "1.0".into(),
        origin_ref: "bd-test".into(),
        tags: BTreeSet::new(),
    }
}

fn make_record(fixture_id: &str, outcome: TestOutcome) -> TestExecutionRecord {
    TestExecutionRecord {
        fixture_id: fixture_id.into(),
        test_class: TestClass::Core,
        surface: TestSurface::Parser,
        outcome,
        seed: None,
        duration_us: 100,
        determinism_satisfied: true,
        evidence_hash: "hash123".into(),
        notes: String::new(),
    }
}

// ===========================================================================
// 1. Schema version constants
// ===========================================================================

#[test]
fn schema_version_constants_nonempty() {
    assert!(!TEST_TAXONOMY_SCHEMA_VERSION.is_empty());
    assert!(!FIXTURE_REGISTRY_SCHEMA_VERSION.is_empty());
}

// ===========================================================================
// 2. TestClass enum
// ===========================================================================

#[test]
fn test_class_all_has_five_variants() {
    assert_eq!(TestClass::ALL.len(), 5);
}

#[test]
fn test_class_as_str() {
    for class in TestClass::ALL {
        let s = class.as_str();
        assert!(!s.is_empty());
    }
}

#[test]
fn test_class_display() {
    for class in TestClass::ALL {
        let display = format!("{class}");
        assert_eq!(display, class.as_str());
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
fn test_class_min_provenance_level() {
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
        TestClass::FaultInjection.min_provenance_level(),
        ProvenanceLevel::Generated
    );
    assert_eq!(
        TestClass::Regression.min_provenance_level(),
        ProvenanceLevel::Captured
    );
}

#[test]
fn test_class_serde_round_trip() {
    for class in TestClass::ALL {
        let json = serde_json::to_string(class).unwrap();
        let back: TestClass = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *class);
    }
}

// ===========================================================================
// 3. TestSurface enum
// ===========================================================================

#[test]
fn test_surface_all_has_eight_variants() {
    assert_eq!(TestSurface::ALL.len(), 8);
}

#[test]
fn test_surface_as_str() {
    for surface in TestSurface::ALL {
        assert!(!surface.as_str().is_empty());
    }
}

#[test]
fn test_surface_display() {
    for surface in TestSurface::ALL {
        let display = format!("{surface}");
        assert_eq!(display, surface.as_str());
    }
}

#[test]
fn test_surface_lane_charter_ref() {
    for surface in TestSurface::ALL {
        let ref_str = surface.lane_charter_ref();
        assert!(ref_str.starts_with("bd-"), "lane charter ref: {ref_str}");
    }
}

#[test]
fn test_surface_serde_round_trip() {
    for surface in TestSurface::ALL {
        let json = serde_json::to_string(surface).unwrap();
        let back: TestSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *surface);
    }
}

// ===========================================================================
// 4. ProvenanceLevel enum
// ===========================================================================

#[test]
fn provenance_level_as_str() {
    for level in [
        ProvenanceLevel::Authored,
        ProvenanceLevel::Generated,
        ProvenanceLevel::Captured,
        ProvenanceLevel::Synthesized,
    ] {
        assert!(!level.as_str().is_empty());
    }
}

#[test]
fn provenance_level_trust_rank_ordering() {
    assert!(ProvenanceLevel::Authored.trust_rank() > ProvenanceLevel::Captured.trust_rank());
    assert!(ProvenanceLevel::Captured.trust_rank() > ProvenanceLevel::Generated.trust_rank());
    assert!(ProvenanceLevel::Generated.trust_rank() > ProvenanceLevel::Synthesized.trust_rank());
}

#[test]
fn provenance_level_serde_round_trip() {
    for level in [
        ProvenanceLevel::Authored,
        ProvenanceLevel::Generated,
        ProvenanceLevel::Captured,
        ProvenanceLevel::Synthesized,
    ] {
        let json = serde_json::to_string(&level).unwrap();
        let back: ProvenanceLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, level);
    }
}

// ===========================================================================
// 5. DeterminismContract
// ===========================================================================

#[test]
fn strict_contract_is_fully_deterministic() {
    let c = DeterminismContract::strict();
    assert!(c.bit_identical_required);
    assert!(c.seed_required);
    assert!(c.virtual_clock_required);
    assert!(c.deterministic_rng_required);
    assert_eq!(c.max_nondeterminism_sources, 0);
    assert_eq!(c.numeric_tolerance_millionths, 0);
    assert!(c.validate().is_empty());
}

#[test]
fn relaxed_contract_allows_tolerance() {
    let c = DeterminismContract::relaxed(1000);
    assert!(!c.bit_identical_required);
    assert_eq!(c.numeric_tolerance_millionths, 1000);
    assert!(c.validate().is_empty());
}

#[test]
fn for_class_core_is_bit_identical() {
    let c = DeterminismContract::for_class(TestClass::Core);
    assert!(c.bit_identical_required);
    assert!(!c.seed_required);
    assert!(c.validate().is_empty());
}

#[test]
fn for_class_adversarial_is_strict() {
    let c = DeterminismContract::for_class(TestClass::Adversarial);
    assert!(c.bit_identical_required);
    assert!(c.seed_required);
    assert!(c.validate().is_empty());
}

#[test]
fn for_class_fault_injection() {
    let c = DeterminismContract::for_class(TestClass::FaultInjection);
    assert!(c.bit_identical_required);
    assert!(c.seed_required);
    assert!(c.virtual_clock_required);
    assert!(c.deterministic_rng_required);
    assert!(c.validate().is_empty());
}

#[test]
fn contract_validates_negative_tolerance() {
    let mut c = DeterminismContract::strict();
    c.numeric_tolerance_millionths = -1;
    let violations = c.validate();
    assert!(!violations.is_empty());
}

#[test]
fn contract_validates_bit_identical_with_tolerance() {
    let mut c = DeterminismContract::strict();
    c.numeric_tolerance_millionths = 100;
    let violations = c.validate();
    assert!(!violations.is_empty());
}

#[test]
fn contract_validates_nondeterminism_without_rng() {
    let mut c = DeterminismContract::strict();
    c.max_nondeterminism_sources = 1;
    c.deterministic_rng_required = false;
    let violations = c.validate();
    assert!(!violations.is_empty());
}

#[test]
fn contract_serde_round_trip() {
    let c = DeterminismContract::strict();
    let json = serde_json::to_string(&c).unwrap();
    let back: DeterminismContract = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

// ===========================================================================
// 6. ContractViolation
// ===========================================================================

#[test]
fn contract_violation_serde_round_trip() {
    let v = ContractViolation {
        field: "tolerance".into(),
        message: "negative tolerance".into(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: ContractViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(back.field, "tolerance");
}

// ===========================================================================
// 7. FixtureEntry
// ===========================================================================

#[test]
fn fixture_entry_valid_core() {
    let f = make_fixture("fx-1", TestClass::Core);
    let contract = DeterminismContract::for_class(TestClass::Core);
    let violations = f.validate_against_contract(&contract);
    assert!(violations.is_empty(), "violations: {violations:?}");
}

#[test]
fn fixture_entry_valid_adversarial_with_seed() {
    let f = make_fixture("fx-adv", TestClass::Adversarial);
    assert!(f.seed.is_some());
    let contract = DeterminismContract::for_class(TestClass::Adversarial);
    let violations = f.validate_against_contract(&contract);
    assert!(violations.is_empty(), "violations: {violations:?}");
}

#[test]
fn fixture_entry_missing_seed_when_required() {
    let mut f = make_fixture("fx-adv", TestClass::Adversarial);
    f.seed = None; // adversarial requires seed
    let contract = DeterminismContract::strict();
    let violations = f.validate_against_contract(&contract);
    assert!(!violations.is_empty());
}

#[test]
fn fixture_entry_insufficient_provenance() {
    let mut f = make_fixture("fx-core", TestClass::Core);
    f.provenance = ProvenanceLevel::Synthesized; // Core needs Authored (rank 3), Synthesized is rank 0
    let contract = DeterminismContract::for_class(TestClass::Core);
    let violations = f.validate_against_contract(&contract);
    assert!(!violations.is_empty());
}

#[test]
fn fixture_entry_empty_hash_is_violation() {
    let mut f = make_fixture("fx-1", TestClass::Core);
    f.content_hash = String::new();
    let contract = DeterminismContract::for_class(TestClass::Core);
    let violations = f.validate_against_contract(&contract);
    assert!(!violations.is_empty());
}

#[test]
fn fixture_entry_derive_id() {
    let f = make_fixture("fx-1", TestClass::Core);
    let id = f.derive_id().unwrap();
    let id_str = format!("{id:?}");
    assert!(!id_str.is_empty());
}

#[test]
fn fixture_entry_derive_id_deterministic() {
    let f = make_fixture("fx-1", TestClass::Core);
    let id1 = f.derive_id().unwrap();
    let id2 = f.derive_id().unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn fixture_entry_serde_round_trip() {
    let f = make_fixture("fx-1", TestClass::Core);
    let json = serde_json::to_string(&f).unwrap();
    let back: FixtureEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.fixture_id, "fx-1");
    assert_eq!(back.test_class, TestClass::Core);
}

// ===========================================================================
// 8. FixtureRegistry
// ===========================================================================

#[test]
fn registry_new_is_empty() {
    let reg = FixtureRegistry::new();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
}

#[test]
fn registry_register_and_lookup() {
    let mut reg = FixtureRegistry::new();
    let f = make_fixture("fx-1", TestClass::Core);
    reg.register(f).unwrap();
    assert_eq!(reg.len(), 1);
    let found = reg.lookup("fx-1").unwrap();
    assert_eq!(found.fixture_id, "fx-1");
}

#[test]
fn registry_duplicate_id_error() {
    let mut reg = FixtureRegistry::new();
    reg.register(make_fixture("fx-1", TestClass::Core)).unwrap();
    let result = reg.register(make_fixture("fx-1", TestClass::Edge));
    assert!(result.is_err());
    if let Err(RegistryError::DuplicateFixtureId(id)) = result {
        assert_eq!(id, "fx-1");
    }
}

#[test]
fn registry_lookup_missing() {
    let reg = FixtureRegistry::new();
    assert!(reg.lookup("nonexistent").is_none());
}

#[test]
fn registry_by_class() {
    let mut reg = FixtureRegistry::new();
    reg.register(make_fixture("fx-core-1", TestClass::Core))
        .unwrap();
    reg.register(make_fixture("fx-core-2", TestClass::Core))
        .unwrap();
    reg.register(make_fixture("fx-edge-1", TestClass::Edge))
        .unwrap();
    let cores = reg.by_class(TestClass::Core);
    assert_eq!(cores.len(), 2);
    let edges = reg.by_class(TestClass::Edge);
    assert_eq!(edges.len(), 1);
}

#[test]
fn registry_by_surface() {
    let mut reg = FixtureRegistry::new();
    reg.register(make_fixture("fx-1", TestClass::Core)).unwrap();
    let parsers = reg.by_surface(TestSurface::Parser);
    assert_eq!(parsers.len(), 1);
    let compilers = reg.by_surface(TestSurface::Compiler);
    assert!(compilers.is_empty());
}

#[test]
fn registry_by_surface_multi_surface_fixture() {
    let mut reg = FixtureRegistry::new();
    let mut f = make_fixture("fx-multi", TestClass::Core);
    f.surfaces = [TestSurface::Parser, TestSurface::Runtime]
        .into_iter()
        .collect();
    reg.register(f).unwrap();
    assert_eq!(reg.by_surface(TestSurface::Parser).len(), 1);
    assert_eq!(reg.by_surface(TestSurface::Runtime).len(), 1);
    assert_eq!(reg.by_surface(TestSurface::Compiler).len(), 0);
}

// ===========================================================================
// 9. Coverage matrix and gaps
// ===========================================================================

#[test]
fn coverage_matrix_empty_registry() {
    let reg = FixtureRegistry::new();
    let matrix = reg.coverage_matrix();
    assert!(matrix.is_empty());
}

#[test]
fn coverage_matrix_counts_correctly() {
    let mut reg = FixtureRegistry::new();
    reg.register(make_fixture("fx-1", TestClass::Core)).unwrap();
    reg.register(make_fixture("fx-2", TestClass::Core)).unwrap();
    let matrix = reg.coverage_matrix();
    assert_eq!(matrix[&(TestClass::Core, TestSurface::Parser)], 2);
}

#[test]
fn coverage_gaps_full_matrix() {
    let reg = FixtureRegistry::new();
    let gaps = reg.coverage_gaps();
    // 5 classes × 8 surfaces = 40 gaps when empty
    assert_eq!(gaps.len(), 40);
}

#[test]
fn coverage_gaps_decrease_with_fixtures() {
    let mut reg = FixtureRegistry::new();
    reg.register(make_fixture("fx-1", TestClass::Core)).unwrap();
    let gaps = reg.coverage_gaps();
    // Should be 39 since Core×Parser is now covered
    assert_eq!(gaps.len(), 39);
    assert!(!gaps.contains(&(TestClass::Core, TestSurface::Parser)));
}

// ===========================================================================
// 10. Validate all fixtures
// ===========================================================================

#[test]
fn validate_all_valid_fixtures() {
    let mut reg = FixtureRegistry::new();
    reg.register(make_fixture("fx-1", TestClass::Core)).unwrap();
    reg.register(make_fixture("fx-2", TestClass::Edge)).unwrap();
    let violations = reg.validate_all();
    assert!(violations.is_empty(), "violations: {violations:?}");
}

#[test]
fn validate_all_detects_violations() {
    let mut reg = FixtureRegistry::new();
    let mut f = make_fixture("fx-bad", TestClass::Core);
    f.content_hash = String::new(); // violation
    reg.register(f).unwrap();
    let violations = reg.validate_all();
    assert!(!violations.is_empty());
    assert_eq!(violations[0].0, "fx-bad");
}

// ===========================================================================
// 11. OwnershipMap
// ===========================================================================

#[test]
fn ownership_map_new_is_empty() {
    let om = OwnershipMap::new();
    assert!(om.entries.is_empty());
}

#[test]
fn ownership_map_add_and_query() {
    let mut om = OwnershipMap::new();
    om.add(OwnershipEntry {
        surface: TestSurface::Parser,
        test_class: TestClass::Core,
        lane_charter_ref: "bd-mjh3.10.3".into(),
        owner_agent: "PearlTower".into(),
        fixture_ids: ["fx-1".into()].into_iter().collect(),
    });
    let parser_entries = om.by_surface(TestSurface::Parser);
    assert_eq!(parser_entries.len(), 1);
    assert_eq!(parser_entries[0].owner_agent, "PearlTower");
}

#[test]
fn ownership_map_unowned_fixtures() {
    let mut reg = FixtureRegistry::new();
    reg.register(make_fixture("fx-1", TestClass::Core)).unwrap();
    reg.register(make_fixture("fx-2", TestClass::Edge)).unwrap();

    let mut om = OwnershipMap::new();
    om.add(OwnershipEntry {
        surface: TestSurface::Parser,
        test_class: TestClass::Core,
        lane_charter_ref: "bd-1".into(),
        owner_agent: "agent-1".into(),
        fixture_ids: ["fx-1".into()].into_iter().collect(),
    });

    let unowned = om.unowned_fixtures(&reg);
    assert_eq!(unowned.len(), 1);
    assert!(unowned.contains(&"fx-2".to_string()));
}

#[test]
fn ownership_map_all_owned() {
    let mut reg = FixtureRegistry::new();
    reg.register(make_fixture("fx-1", TestClass::Core)).unwrap();

    let mut om = OwnershipMap::new();
    om.add(OwnershipEntry {
        surface: TestSurface::Parser,
        test_class: TestClass::Core,
        lane_charter_ref: "bd-1".into(),
        owner_agent: "agent-1".into(),
        fixture_ids: ["fx-1".into()].into_iter().collect(),
    });

    let unowned = om.unowned_fixtures(&reg);
    assert!(unowned.is_empty());
}

#[test]
fn ownership_entry_serde_round_trip() {
    let entry = OwnershipEntry {
        surface: TestSurface::Compiler,
        test_class: TestClass::Adversarial,
        lane_charter_ref: "bd-mjh3.10.2".into(),
        owner_agent: "agent-x".into(),
        fixture_ids: ["fx-1".into(), "fx-2".into()].into_iter().collect(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: OwnershipEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.surface, TestSurface::Compiler);
    assert_eq!(back.fixture_ids.len(), 2);
}

// ===========================================================================
// 12. TestOutcome enum
// ===========================================================================

#[test]
fn test_outcome_as_str() {
    for outcome in [
        TestOutcome::Pass,
        TestOutcome::Fail,
        TestOutcome::Skip,
        TestOutcome::Timeout,
        TestOutcome::Flake,
    ] {
        assert!(!outcome.as_str().is_empty());
    }
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
fn test_outcome_display() {
    for outcome in [
        TestOutcome::Pass,
        TestOutcome::Fail,
        TestOutcome::Skip,
        TestOutcome::Timeout,
        TestOutcome::Flake,
    ] {
        let display = format!("{outcome}");
        assert_eq!(display, outcome.as_str());
    }
}

#[test]
fn test_outcome_serde_round_trip() {
    for outcome in [
        TestOutcome::Pass,
        TestOutcome::Fail,
        TestOutcome::Skip,
        TestOutcome::Timeout,
        TestOutcome::Flake,
    ] {
        let json = serde_json::to_string(&outcome).unwrap();
        let back: TestOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, outcome);
    }
}

// ===========================================================================
// 13. TestExecutionRecord
// ===========================================================================

#[test]
fn execution_record_serde_round_trip() {
    let record = make_record("fx-1", TestOutcome::Pass);
    let json = serde_json::to_string(&record).unwrap();
    let back: TestExecutionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back.fixture_id, "fx-1");
    assert_eq!(back.outcome, TestOutcome::Pass);
}

// ===========================================================================
// 14. TestSuiteSummary
// ===========================================================================

#[test]
fn suite_summary_from_empty_records() {
    let summary = TestSuiteSummary::from_records(&[]);
    assert_eq!(summary.total, 0);
    assert_eq!(summary.passed, 0);
    assert_eq!(summary.failed, 0);
}

#[test]
fn suite_summary_from_all_passing() {
    let records = vec![
        make_record("fx-1", TestOutcome::Pass),
        make_record("fx-2", TestOutcome::Pass),
    ];
    let summary = TestSuiteSummary::from_records(&records);
    assert_eq!(summary.total, 2);
    assert_eq!(summary.passed, 2);
    assert_eq!(summary.pass_rate_millionths, 1_000_000);
}

#[test]
fn suite_summary_from_mixed_outcomes() {
    let records = vec![
        make_record("fx-1", TestOutcome::Pass),
        make_record("fx-2", TestOutcome::Fail),
        make_record("fx-3", TestOutcome::Skip),
        make_record("fx-4", TestOutcome::Timeout),
        make_record("fx-5", TestOutcome::Flake),
    ];
    let summary = TestSuiteSummary::from_records(&records);
    assert_eq!(summary.total, 5);
    assert_eq!(summary.passed, 1);
    assert_eq!(summary.failed, 1);
    assert_eq!(summary.skipped, 1);
    assert_eq!(summary.timed_out, 1);
    assert_eq!(summary.flaky, 1);
    // pass rate = 1/5 = 200_000 millionths
    assert_eq!(summary.pass_rate_millionths, 200_000);
}

#[test]
fn suite_summary_meets_threshold() {
    let records = vec![
        make_record("fx-1", TestOutcome::Pass),
        make_record("fx-2", TestOutcome::Pass),
    ];
    let summary = TestSuiteSummary::from_records(&records);
    assert!(summary.meets_threshold(1_000_000));
    assert!(summary.meets_threshold(900_000));
}

#[test]
fn suite_summary_does_not_meet_threshold() {
    let records = vec![
        make_record("fx-1", TestOutcome::Pass),
        make_record("fx-2", TestOutcome::Fail),
    ];
    let summary = TestSuiteSummary::from_records(&records);
    assert!(!summary.meets_threshold(900_000));
}

#[test]
fn suite_summary_class_breakdown() {
    let records = vec![
        TestExecutionRecord {
            fixture_id: "fx-1".into(),
            test_class: TestClass::Core,
            surface: TestSurface::Parser,
            outcome: TestOutcome::Pass,
            seed: None,
            duration_us: 100,
            determinism_satisfied: true,
            evidence_hash: "h".into(),
            notes: String::new(),
        },
        TestExecutionRecord {
            fixture_id: "fx-2".into(),
            test_class: TestClass::Core,
            surface: TestSurface::Parser,
            outcome: TestOutcome::Fail,
            seed: None,
            duration_us: 200,
            determinism_satisfied: true,
            evidence_hash: "h".into(),
            notes: String::new(),
        },
        TestExecutionRecord {
            fixture_id: "fx-3".into(),
            test_class: TestClass::Edge,
            surface: TestSurface::Runtime,
            outcome: TestOutcome::Pass,
            seed: None,
            duration_us: 50,
            determinism_satisfied: true,
            evidence_hash: "h".into(),
            notes: String::new(),
        },
    ];
    let summary = TestSuiteSummary::from_records(&records);
    let core = &summary.class_breakdown[&TestClass::Core];
    assert_eq!(core.total, 2);
    assert_eq!(core.passed, 1);
    assert_eq!(core.failed, 1);
    let edge = &summary.class_breakdown[&TestClass::Edge];
    assert_eq!(edge.total, 1);
    assert_eq!(edge.passed, 1);
}

#[test]
fn suite_summary_surface_breakdown() {
    let records = vec![
        make_record("fx-1", TestOutcome::Pass),
        make_record("fx-2", TestOutcome::Fail),
    ];
    let summary = TestSuiteSummary::from_records(&records);
    assert_eq!(summary.surface_breakdown[&TestSurface::Parser], 2);
}

#[test]
fn suite_summary_determinism_rate() {
    let mut records = vec![
        make_record("fx-1", TestOutcome::Pass),
        make_record("fx-2", TestOutcome::Pass),
    ];
    records[1].determinism_satisfied = false;
    let summary = TestSuiteSummary::from_records(&records);
    assert_eq!(summary.determinism_rate_millionths, 500_000);
}

#[test]
fn suite_summary_serde_round_trip() {
    let records = vec![make_record("fx-1", TestOutcome::Pass)];
    let summary = TestSuiteSummary::from_records(&records);
    let json = serde_json::to_string(&summary).unwrap();
    let back: TestSuiteSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total, 1);
    assert_eq!(back.passed, 1);
}

// ===========================================================================
// 15. ClassBreakdown serde
// ===========================================================================

#[test]
fn class_breakdown_serde_round_trip() {
    let cb = ClassBreakdown {
        total: 10,
        passed: 7,
        failed: 3,
    };
    let json = serde_json::to_string(&cb).unwrap();
    let back: ClassBreakdown = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total, 10);
    assert_eq!(back.passed, 7);
}

// ===========================================================================
// 16. RegistryError
// ===========================================================================

#[test]
fn registry_error_display() {
    let err = RegistryError::DuplicateFixtureId("fx-1".into());
    let display = format!("{err}");
    assert!(display.contains("fx-1"));
}

#[test]
fn registry_error_fixture_not_found_display() {
    let err = RegistryError::FixtureNotFound("fx-missing".into());
    let display = format!("{err}");
    assert!(display.contains("fx-missing"));
}

#[test]
fn registry_error_serde_round_trip() {
    let err = RegistryError::DuplicateFixtureId("fx-1".into());
    let json = serde_json::to_string(&err).unwrap();
    let back: RegistryError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

// ===========================================================================
// 17. FixtureRegistry serde
// ===========================================================================

#[test]
fn fixture_registry_serde_round_trip() {
    let mut reg = FixtureRegistry::new();
    reg.register(make_fixture("fx-1", TestClass::Core)).unwrap();
    reg.register(make_fixture("fx-2", TestClass::Edge)).unwrap();
    let json = serde_json::to_string(&reg).unwrap();
    let back: FixtureRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 2);
    assert!(back.lookup("fx-1").is_some());
}

// ===========================================================================
// 18. OwnershipMap serde
// ===========================================================================

#[test]
fn ownership_map_serde_round_trip() {
    let mut om = OwnershipMap::new();
    om.add(OwnershipEntry {
        surface: TestSurface::Parser,
        test_class: TestClass::Core,
        lane_charter_ref: "bd-1".into(),
        owner_agent: "agent".into(),
        fixture_ids: BTreeSet::new(),
    });
    let json = serde_json::to_string(&om).unwrap();
    let back: OwnershipMap = serde_json::from_str(&json).unwrap();
    assert_eq!(back.entries.len(), 1);
}

// ===========================================================================
// 19. Full lifecycle: register → validate → execute → summarize
// ===========================================================================

#[test]
fn full_lifecycle_register_validate_execute_summarize() {
    // Register fixtures
    let mut reg = FixtureRegistry::new();
    reg.register(make_fixture("fx-core-1", TestClass::Core))
        .unwrap();
    reg.register(make_fixture("fx-core-2", TestClass::Core))
        .unwrap();
    reg.register(make_fixture("fx-edge-1", TestClass::Edge))
        .unwrap();
    reg.register(make_fixture("fx-adv-1", TestClass::Adversarial))
        .unwrap();

    // Validate all
    let violations = reg.validate_all();
    assert!(violations.is_empty());

    // Check coverage
    let matrix = reg.coverage_matrix();
    assert_eq!(matrix[&(TestClass::Core, TestSurface::Parser)], 2);
    assert_eq!(matrix[&(TestClass::Edge, TestSurface::Parser)], 1);
    assert_eq!(matrix[&(TestClass::Adversarial, TestSurface::Parser)], 1);

    // Execute tests
    let records = vec![
        TestExecutionRecord {
            fixture_id: "fx-core-1".into(),
            test_class: TestClass::Core,
            surface: TestSurface::Parser,
            outcome: TestOutcome::Pass,
            seed: None,
            duration_us: 100,
            determinism_satisfied: true,
            evidence_hash: "h1".into(),
            notes: String::new(),
        },
        TestExecutionRecord {
            fixture_id: "fx-core-2".into(),
            test_class: TestClass::Core,
            surface: TestSurface::Parser,
            outcome: TestOutcome::Pass,
            seed: None,
            duration_us: 150,
            determinism_satisfied: true,
            evidence_hash: "h2".into(),
            notes: String::new(),
        },
        TestExecutionRecord {
            fixture_id: "fx-edge-1".into(),
            test_class: TestClass::Edge,
            surface: TestSurface::Parser,
            outcome: TestOutcome::Fail,
            seed: None,
            duration_us: 200,
            determinism_satisfied: true,
            evidence_hash: "h3".into(),
            notes: "boundary check failed".into(),
        },
        TestExecutionRecord {
            fixture_id: "fx-adv-1".into(),
            test_class: TestClass::Adversarial,
            surface: TestSurface::Parser,
            outcome: TestOutcome::Pass,
            seed: Some(42),
            duration_us: 300,
            determinism_satisfied: true,
            evidence_hash: "h4".into(),
            notes: String::new(),
        },
    ];

    // Summarize
    let summary = TestSuiteSummary::from_records(&records);
    assert_eq!(summary.total, 4);
    assert_eq!(summary.passed, 3);
    assert_eq!(summary.failed, 1);
    assert_eq!(summary.pass_rate_millionths, 750_000);
    assert_eq!(summary.determinism_rate_millionths, 1_000_000);
    assert!(summary.meets_threshold(700_000));
    assert!(!summary.meets_threshold(800_000));
}

// ===========================================================================
// 20. Coverage with multiple surfaces per fixture
// ===========================================================================

#[test]
fn coverage_matrix_multi_surface_fixture() {
    let mut reg = FixtureRegistry::new();
    let mut f = make_fixture("fx-multi", TestClass::Core);
    f.surfaces = [
        TestSurface::Parser,
        TestSurface::Runtime,
        TestSurface::Compiler,
    ]
    .into_iter()
    .collect();
    reg.register(f).unwrap();
    let matrix = reg.coverage_matrix();
    assert_eq!(matrix[&(TestClass::Core, TestSurface::Parser)], 1);
    assert_eq!(matrix[&(TestClass::Core, TestSurface::Runtime)], 1);
    assert_eq!(matrix[&(TestClass::Core, TestSurface::Compiler)], 1);
    let gaps = reg.coverage_gaps();
    assert!(!gaps.contains(&(TestClass::Core, TestSurface::Parser)));
    assert!(!gaps.contains(&(TestClass::Core, TestSurface::Runtime)));
    assert!(!gaps.contains(&(TestClass::Core, TestSurface::Compiler)));
}

// ===========================================================================
// 21. Fixture with tags
// ===========================================================================

#[test]
fn fixture_with_tags_serde() {
    let mut f = make_fixture("fx-tagged", TestClass::Regression);
    f.tags = ["smoke".into(), "parser-v2".into()].into_iter().collect();
    let json = serde_json::to_string(&f).unwrap();
    let back: FixtureEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.tags.len(), 2);
    assert!(back.tags.contains("smoke"));
    assert!(back.tags.contains("parser-v2"));
}
