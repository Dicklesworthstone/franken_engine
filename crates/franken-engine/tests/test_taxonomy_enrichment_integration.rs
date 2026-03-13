#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::test_taxonomy::{
    ClassBreakdown, ContractViolation, DeterminismContract, FIXTURE_REGISTRY_SCHEMA_VERSION,
    FixtureEntry, FixtureRegistry, OwnershipEntry, OwnershipMap, ProvenanceLevel, RegistryError,
    TEST_TAXONOMY_SCHEMA_VERSION, TestClass, TestExecutionRecord, TestOutcome, TestSuiteSummary,
    TestSurface,
};

// =========================================================================
// Helpers
// =========================================================================

fn make_fixture(id: &str, class: TestClass) -> FixtureEntry {
    FixtureEntry {
        fixture_id: id.to_string(),
        description: format!("Enrichment fixture {id}"),
        test_class: class,
        surfaces: BTreeSet::from([TestSurface::Parser]),
        provenance: ProvenanceLevel::Authored,
        seed: if class.requires_seed() {
            Some(42)
        } else {
            None
        },
        content_hash: "sha256:enrichment".to_string(),
        format_version: "1.0.0".to_string(),
        origin_ref: "bd-enrichment".to_string(),
        tags: BTreeSet::new(),
    }
}

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

// =========================================================================
// A. BTreeSet ordering and dedup for all enums
// =========================================================================

#[test]
fn enrichment_test_class_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    for class in TestClass::ALL {
        set.insert(*class);
    }
    // Insert duplicates
    set.insert(TestClass::Core);
    set.insert(TestClass::Adversarial);
    assert_eq!(set.len(), 5);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

#[test]
fn enrichment_test_surface_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    for surface in TestSurface::ALL {
        set.insert(*surface);
    }
    set.insert(TestSurface::Compiler);
    set.insert(TestSurface::Security);
    assert_eq!(set.len(), 8);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

#[test]
fn enrichment_provenance_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    set.insert(ProvenanceLevel::Authored);
    set.insert(ProvenanceLevel::Generated);
    set.insert(ProvenanceLevel::Captured);
    set.insert(ProvenanceLevel::Synthesized);
    set.insert(ProvenanceLevel::Authored); // duplicate
    assert_eq!(set.len(), 4);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

#[test]
fn enrichment_test_outcome_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    set.insert(TestOutcome::Pass);
    set.insert(TestOutcome::Fail);
    set.insert(TestOutcome::Skip);
    set.insert(TestOutcome::Timeout);
    set.insert(TestOutcome::Flake);
    set.insert(TestOutcome::Pass); // duplicate
    assert_eq!(set.len(), 5);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

// =========================================================================
// B. Hash consistency
// =========================================================================

#[test]
fn enrichment_test_class_hash_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    for class in TestClass::ALL {
        let mut h1 = DefaultHasher::new();
        class.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        class.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}

#[test]
fn enrichment_test_surface_hash_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    for surface in TestSurface::ALL {
        let mut h1 = DefaultHasher::new();
        surface.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        surface.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}

#[test]
fn enrichment_provenance_hash_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let levels = [
        ProvenanceLevel::Authored,
        ProvenanceLevel::Generated,
        ProvenanceLevel::Captured,
        ProvenanceLevel::Synthesized,
    ];
    for level in &levels {
        let mut h1 = DefaultHasher::new();
        level.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        level.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}

#[test]
fn enrichment_test_outcome_hash_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let outcomes = [
        TestOutcome::Pass,
        TestOutcome::Fail,
        TestOutcome::Skip,
        TestOutcome::Timeout,
        TestOutcome::Flake,
    ];
    for outcome in &outcomes {
        let mut h1 = DefaultHasher::new();
        outcome.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        outcome.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}

// =========================================================================
// C. Display values distinct for all enums
// =========================================================================

#[test]
fn enrichment_test_class_display_distinct() {
    let displays: BTreeSet<String> = TestClass::ALL.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_test_surface_display_distinct() {
    let displays: BTreeSet<String> = TestSurface::ALL.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 8);
}

#[test]
fn enrichment_provenance_display_distinct() {
    let displays: BTreeSet<String> = [
        ProvenanceLevel::Authored,
        ProvenanceLevel::Generated,
        ProvenanceLevel::Captured,
        ProvenanceLevel::Synthesized,
    ]
    .iter()
    .map(|p| p.to_string())
    .collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_test_outcome_display_distinct() {
    let displays: BTreeSet<String> = [
        TestOutcome::Pass,
        TestOutcome::Fail,
        TestOutcome::Skip,
        TestOutcome::Timeout,
        TestOutcome::Flake,
    ]
    .iter()
    .map(|o| o.to_string())
    .collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_registry_error_display_distinct() {
    let displays: BTreeSet<String> = [
        RegistryError::DuplicateFixtureId("id1".to_string()),
        RegistryError::FixtureNotFound("id2".to_string()),
        RegistryError::InvalidFixture("bad".to_string()),
    ]
    .iter()
    .map(|e| e.to_string())
    .collect();
    assert_eq!(displays.len(), 3);
}

// =========================================================================
// D. Debug nonempty for all types
// =========================================================================

#[test]
fn enrichment_debug_nonempty_enums() {
    for class in TestClass::ALL {
        assert!(!format!("{class:?}").is_empty());
    }
    for surface in TestSurface::ALL {
        assert!(!format!("{surface:?}").is_empty());
    }
    for prov in &[
        ProvenanceLevel::Authored,
        ProvenanceLevel::Generated,
        ProvenanceLevel::Captured,
        ProvenanceLevel::Synthesized,
    ] {
        assert!(!format!("{prov:?}").is_empty());
    }
    for outcome in &[
        TestOutcome::Pass,
        TestOutcome::Fail,
        TestOutcome::Skip,
        TestOutcome::Timeout,
        TestOutcome::Flake,
    ] {
        assert!(!format!("{outcome:?}").is_empty());
    }
}

#[test]
fn enrichment_debug_nonempty_structs() {
    let contract = DeterminismContract::strict();
    assert!(!format!("{contract:?}").is_empty());

    let violation = ContractViolation {
        field: "f".to_string(),
        message: "m".to_string(),
    };
    assert!(!format!("{violation:?}").is_empty());

    let fixture = make_fixture("dbg", TestClass::Core);
    assert!(!format!("{fixture:?}").is_empty());

    let registry = FixtureRegistry::new();
    assert!(!format!("{registry:?}").is_empty());

    let ownership = OwnershipEntry {
        surface: TestSurface::Parser,
        test_class: TestClass::Core,
        lane_charter_ref: "bd-test".to_string(),
        owner_agent: "Agent".to_string(),
        fixture_ids: BTreeSet::new(),
    };
    assert!(!format!("{ownership:?}").is_empty());

    let map = OwnershipMap::new();
    assert!(!format!("{map:?}").is_empty());

    let record = make_record("dbg", TestOutcome::Pass);
    assert!(!format!("{record:?}").is_empty());

    let summary = TestSuiteSummary::from_records(&[]);
    assert!(!format!("{summary:?}").is_empty());

    let breakdown = ClassBreakdown {
        total: 10,
        passed: 8,
        failed: 2,
    };
    assert!(!format!("{breakdown:?}").is_empty());

    for err in &[
        RegistryError::DuplicateFixtureId("x".to_string()),
        RegistryError::FixtureNotFound("y".to_string()),
        RegistryError::InvalidFixture("z".to_string()),
    ] {
        assert!(!format!("{err:?}").is_empty());
    }
}

// =========================================================================
// E. Clone independence
// =========================================================================

#[test]
fn enrichment_clone_independence_contract() {
    let original = DeterminismContract::strict();
    let mut cloned = original.clone();
    cloned.bit_identical_required = false;
    cloned.numeric_tolerance_millionths = 999;
    assert!(original.bit_identical_required);
    assert_eq!(original.numeric_tolerance_millionths, 0);
}

#[test]
fn enrichment_clone_independence_fixture() {
    let original = make_fixture("orig", TestClass::Core);
    let mut cloned = original.clone();
    cloned.fixture_id = "modified".to_string();
    cloned.content_hash = "sha256:modified".to_string();
    assert_eq!(original.fixture_id, "orig");
    assert_eq!(original.content_hash, "sha256:enrichment");
}

#[test]
fn enrichment_clone_independence_registry() {
    let mut original = FixtureRegistry::new();
    original
        .register(make_fixture("r1", TestClass::Core))
        .unwrap();
    let cloned = original.clone();
    original
        .register(make_fixture("r2", TestClass::Edge))
        .unwrap();
    assert_eq!(cloned.len(), 1);
    assert_eq!(original.len(), 2);
}

#[test]
fn enrichment_clone_independence_ownership_map() {
    let mut original = OwnershipMap::new();
    original.add(OwnershipEntry {
        surface: TestSurface::Parser,
        test_class: TestClass::Core,
        lane_charter_ref: "bd-test".to_string(),
        owner_agent: "Agent".to_string(),
        fixture_ids: BTreeSet::from(["f1".to_string()]),
    });
    let cloned = original.clone();
    original.add(OwnershipEntry {
        surface: TestSurface::Compiler,
        test_class: TestClass::Edge,
        lane_charter_ref: "bd-test2".to_string(),
        owner_agent: "Agent2".to_string(),
        fixture_ids: BTreeSet::new(),
    });
    assert_eq!(cloned.entries.len(), 1);
    assert_eq!(original.entries.len(), 2);
}

#[test]
fn enrichment_clone_independence_execution_record() {
    let original = make_record("orig", TestOutcome::Pass);
    let mut cloned = original.clone();
    cloned.fixture_id = "modified".to_string();
    cloned.outcome = TestOutcome::Fail;
    assert_eq!(original.fixture_id, "orig");
    assert_eq!(original.outcome, TestOutcome::Pass);
}

// =========================================================================
// F. Copy semantics for enums
// =========================================================================

#[test]
fn enrichment_copy_semantics_test_class() {
    let a = TestClass::Adversarial;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_copy_semantics_test_surface() {
    let a = TestSurface::Security;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_copy_semantics_provenance() {
    let a = ProvenanceLevel::Captured;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_copy_semantics_test_outcome() {
    let a = TestOutcome::Flake;
    let b = a;
    assert_eq!(a, b);
}

// =========================================================================
// G. Serde roundtrips for intermediate structs
// =========================================================================

#[test]
fn enrichment_contract_violation_serde_roundtrip() {
    let v = ContractViolation {
        field: "test_field".to_string(),
        message: "something is wrong".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: ContractViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_class_breakdown_serde_roundtrip() {
    let b = ClassBreakdown {
        total: 100,
        passed: 95,
        failed: 5,
    };
    let json = serde_json::to_string(&b).unwrap();
    let back: ClassBreakdown = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

#[test]
fn enrichment_ownership_entry_serde_roundtrip() {
    let entry = OwnershipEntry {
        surface: TestSurface::Governance,
        test_class: TestClass::FaultInjection,
        lane_charter_ref: "bd-mjh3.10.7".to_string(),
        owner_agent: "ScarletHill".to_string(),
        fixture_ids: BTreeSet::from(["f1".to_string(), "f2".to_string(), "f3".to_string()]),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: OwnershipEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_registry_error_serde_all_variants() {
    let errors = [
        RegistryError::DuplicateFixtureId("dup".to_string()),
        RegistryError::FixtureNotFound("missing".to_string()),
        RegistryError::InvalidFixture("invalid".to_string()),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: RegistryError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// =========================================================================
// H. Contract validation edge cases
// =========================================================================

#[test]
fn enrichment_contract_bit_identical_with_nondeterminism_no_rng() {
    // bit_identical + nondet_sources > 0 + no deterministic_rng → violation
    let c = DeterminismContract {
        schema: TEST_TAXONOMY_SCHEMA_VERSION.to_string(),
        bit_identical_required: true,
        seed_required: false,
        virtual_clock_required: false,
        deterministic_rng_required: false,
        max_nondeterminism_sources: 2,
        numeric_tolerance_millionths: 0,
    };
    let violations = c.validate();
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].field, "max_nondeterminism_sources");
}

#[test]
fn enrichment_contract_multiple_violations_stacking() {
    // bit_identical + nondet > 0 + no rng + negative tolerance + bit_identical with tolerance
    let c = DeterminismContract {
        schema: TEST_TAXONOMY_SCHEMA_VERSION.to_string(),
        bit_identical_required: true,
        seed_required: false,
        virtual_clock_required: false,
        deterministic_rng_required: false,
        max_nondeterminism_sources: 1,
        numeric_tolerance_millionths: -5,
    };
    let violations = c.validate();
    // Should flag: nondeterminism without rng, negative tolerance
    // Note: tolerance is negative so bit_identical+tolerance check (tolerance > 0) won't fire
    assert!(violations.len() >= 2);
    let fields: BTreeSet<&str> = violations.iter().map(|v| v.field.as_str()).collect();
    assert!(fields.contains("max_nondeterminism_sources"));
    assert!(fields.contains("numeric_tolerance_millionths"));
}

#[test]
fn enrichment_contract_bit_identical_with_deterministic_rng_ok() {
    // bit_identical + nondet_sources > 0 BUT deterministic_rng = true → no violation from this rule
    let c = DeterminismContract {
        schema: TEST_TAXONOMY_SCHEMA_VERSION.to_string(),
        bit_identical_required: true,
        seed_required: true,
        virtual_clock_required: true,
        deterministic_rng_required: true,
        max_nondeterminism_sources: 1,
        numeric_tolerance_millionths: 0,
    };
    let violations = c.validate();
    assert!(violations.is_empty());
}

// =========================================================================
// I. Fixture validation edge cases
// =========================================================================

#[test]
fn enrichment_fixture_provenance_below_minimum() {
    // Core class min provenance is Authored (trust_rank 3)
    // Synthesized has trust_rank 0 → violation
    let mut f = make_fixture("prov-below", TestClass::Core);
    f.provenance = ProvenanceLevel::Synthesized;
    let contract = DeterminismContract::for_class(TestClass::Core);
    let violations = f.validate_against_contract(&contract);
    assert!(violations.iter().any(|v| v.field == "provenance"));
}

#[test]
fn enrichment_fixture_multiple_validation_failures() {
    // Adversarial: needs seed + min provenance Generated
    let mut f = make_fixture("multi-fail", TestClass::Adversarial);
    f.seed = None;
    f.content_hash = String::new();
    // Provenance is Authored (rank 3) > Generated (rank 1), so no provenance violation
    let contract = DeterminismContract::for_class(TestClass::Adversarial);
    let violations = f.validate_against_contract(&contract);
    assert!(violations.len() >= 2);
    let fields: BTreeSet<&str> = violations.iter().map(|v| v.field.as_str()).collect();
    assert!(fields.contains("seed"));
    assert!(fields.contains("content_hash"));
}

#[test]
fn enrichment_fixture_derive_id_deterministic() {
    let f = make_fixture("det-id", TestClass::Core);
    let id1 = f.derive_id().unwrap();
    let id2 = f.derive_id().unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn enrichment_fixture_derive_id_different_for_different_content() {
    let f1 = make_fixture("id-a", TestClass::Core);
    let mut f2 = make_fixture("id-b", TestClass::Core);
    f2.content_hash = "sha256:different".to_string();
    let id1 = f1.derive_id().unwrap();
    let id2 = f2.derive_id().unwrap();
    assert_ne!(id1, id2);
}

// =========================================================================
// J. Registry edge cases
// =========================================================================

#[test]
fn enrichment_registry_by_class_all_classes() {
    let mut r = FixtureRegistry::new();
    for (i, class) in TestClass::ALL.iter().enumerate() {
        let mut f = make_fixture(&format!("class-{i}"), *class);
        if class.requires_seed() {
            f.seed = Some(42);
        }
        r.register(f).unwrap();
    }
    for class in TestClass::ALL {
        assert_eq!(r.by_class(*class).len(), 1);
    }
}

#[test]
fn enrichment_registry_by_surface_all_surfaces() {
    let mut r = FixtureRegistry::new();
    for (i, surface) in TestSurface::ALL.iter().enumerate() {
        let mut f = make_fixture(&format!("surf-{i}"), TestClass::Core);
        f.surfaces = BTreeSet::from([*surface]);
        r.register(f).unwrap();
    }
    for surface in TestSurface::ALL {
        assert_eq!(r.by_surface(*surface).len(), 1);
    }
}

#[test]
fn enrichment_registry_multi_surface_fixture_appears_in_all() {
    let mut r = FixtureRegistry::new();
    let mut f = make_fixture("multi-surf", TestClass::Core);
    f.surfaces = BTreeSet::from([
        TestSurface::Compiler,
        TestSurface::Runtime,
        TestSurface::Router,
    ]);
    r.register(f).unwrap();
    assert_eq!(r.by_surface(TestSurface::Compiler).len(), 1);
    assert_eq!(r.by_surface(TestSurface::Runtime).len(), 1);
    assert_eq!(r.by_surface(TestSurface::Router).len(), 1);
    assert_eq!(r.by_surface(TestSurface::Parser).len(), 0);
}

#[test]
fn enrichment_registry_coverage_matrix_multi_surface() {
    let mut r = FixtureRegistry::new();
    let mut f = make_fixture("cov-multi", TestClass::Edge);
    f.surfaces = BTreeSet::from([TestSurface::Evidence, TestSurface::Security]);
    r.register(f).unwrap();
    let matrix = r.coverage_matrix();
    assert_eq!(matrix[&(TestClass::Edge, TestSurface::Evidence)], 1);
    assert_eq!(matrix[&(TestClass::Edge, TestSurface::Security)], 1);
    assert!(!matrix.contains_key(&(TestClass::Edge, TestSurface::Parser)));
}

#[test]
fn enrichment_registry_coverage_gaps_full_coverage() {
    let mut r = FixtureRegistry::new();
    let mut idx = 0;
    for class in TestClass::ALL {
        for surface in TestSurface::ALL {
            let mut f = make_fixture(&format!("full-{idx}"), *class);
            f.surfaces = BTreeSet::from([*surface]);
            if class.requires_seed() {
                f.seed = Some(42);
            }
            r.register(f).unwrap();
            idx += 1;
        }
    }
    assert!(r.coverage_gaps().is_empty());
}

// =========================================================================
// K. Ownership map edge cases
// =========================================================================

#[test]
fn enrichment_ownership_all_fixtures_owned() {
    let mut reg = FixtureRegistry::new();
    reg.register(make_fixture("o1", TestClass::Core)).unwrap();
    reg.register(make_fixture("o2", TestClass::Edge)).unwrap();

    let mut m = OwnershipMap::new();
    m.add(OwnershipEntry {
        surface: TestSurface::Parser,
        test_class: TestClass::Core,
        lane_charter_ref: "bd-test".to_string(),
        owner_agent: "Agent".to_string(),
        fixture_ids: BTreeSet::from(["o1".to_string(), "o2".to_string()]),
    });
    assert!(m.unowned_fixtures(&reg).is_empty());
}

#[test]
fn enrichment_ownership_multiple_surfaces() {
    let mut m = OwnershipMap::new();
    m.add(OwnershipEntry {
        surface: TestSurface::Parser,
        test_class: TestClass::Core,
        lane_charter_ref: "bd-1".to_string(),
        owner_agent: "A".to_string(),
        fixture_ids: BTreeSet::new(),
    });
    m.add(OwnershipEntry {
        surface: TestSurface::Compiler,
        test_class: TestClass::Edge,
        lane_charter_ref: "bd-2".to_string(),
        owner_agent: "B".to_string(),
        fixture_ids: BTreeSet::new(),
    });
    m.add(OwnershipEntry {
        surface: TestSurface::Parser,
        test_class: TestClass::Adversarial,
        lane_charter_ref: "bd-3".to_string(),
        owner_agent: "C".to_string(),
        fixture_ids: BTreeSet::new(),
    });
    assert_eq!(m.by_surface(TestSurface::Parser).len(), 2);
    assert_eq!(m.by_surface(TestSurface::Compiler).len(), 1);
    assert_eq!(m.by_surface(TestSurface::Governance).len(), 0);
}

// =========================================================================
// L. Suite summary edge cases
// =========================================================================

#[test]
fn enrichment_suite_summary_all_flaky() {
    let records = vec![
        make_record("a", TestOutcome::Flake),
        make_record("b", TestOutcome::Flake),
    ];
    let s = TestSuiteSummary::from_records(&records);
    assert_eq!(s.total, 2);
    assert_eq!(s.flaky, 2);
    assert_eq!(s.passed, 0);
    assert_eq!(s.pass_rate_millionths, 0);
}

#[test]
fn enrichment_suite_summary_all_five_outcomes() {
    let records = vec![
        make_record("a", TestOutcome::Pass),
        make_record("b", TestOutcome::Fail),
        make_record("c", TestOutcome::Skip),
        make_record("d", TestOutcome::Timeout),
        make_record("e", TestOutcome::Flake),
    ];
    let s = TestSuiteSummary::from_records(&records);
    assert_eq!(s.total, 5);
    assert_eq!(s.passed, 1);
    assert_eq!(s.failed, 1);
    assert_eq!(s.skipped, 1);
    assert_eq!(s.timed_out, 1);
    assert_eq!(s.flaky, 1);
    assert_eq!(s.pass_rate_millionths, 200_000); // 1/5 = 20%
}

#[test]
fn enrichment_suite_summary_determinism_rate_zero() {
    let mut r1 = make_record("a", TestOutcome::Pass);
    r1.determinism_satisfied = false;
    let mut r2 = make_record("b", TestOutcome::Pass);
    r2.determinism_satisfied = false;
    let s = TestSuiteSummary::from_records(&[r1, r2]);
    assert_eq!(s.determinism_rate_millionths, 0);
}

#[test]
fn enrichment_suite_summary_determinism_rate_full() {
    let r1 = make_record("a", TestOutcome::Pass);
    let r2 = make_record("b", TestOutcome::Fail);
    let s = TestSuiteSummary::from_records(&[r1, r2]);
    // Both have determinism_satisfied = true
    assert_eq!(s.determinism_rate_millionths, 1_000_000);
}

#[test]
fn enrichment_suite_summary_threshold_exact_boundary() {
    // 2 pass out of 3 = 666666 millionths
    let records = vec![
        make_record("a", TestOutcome::Pass),
        make_record("b", TestOutcome::Pass),
        make_record("c", TestOutcome::Fail),
    ];
    let s = TestSuiteSummary::from_records(&records);
    assert!(s.meets_threshold(s.pass_rate_millionths));
    assert!(!s.meets_threshold(s.pass_rate_millionths + 1));
}

#[test]
fn enrichment_suite_summary_surface_breakdown_all_surfaces() {
    let mut records = Vec::new();
    for (i, surface) in TestSurface::ALL.iter().enumerate() {
        let mut r = make_record(&format!("s-{i}"), TestOutcome::Pass);
        r.surface = *surface;
        records.push(r);
    }
    let s = TestSuiteSummary::from_records(&records);
    assert_eq!(s.surface_breakdown.len(), 8);
    for surface in TestSurface::ALL {
        assert_eq!(s.surface_breakdown[surface], 1);
    }
}

#[test]
fn enrichment_suite_summary_class_breakdown_all_classes() {
    let mut records = Vec::new();
    for (i, class) in TestClass::ALL.iter().enumerate() {
        let mut r = make_record(&format!("c-{i}"), TestOutcome::Pass);
        r.test_class = *class;
        records.push(r);
    }
    let s = TestSuiteSummary::from_records(&records);
    assert_eq!(s.class_breakdown.len(), 5);
    for class in TestClass::ALL {
        let b = &s.class_breakdown[class];
        assert_eq!(b.total, 1);
        assert_eq!(b.passed, 1);
        assert_eq!(b.failed, 0);
    }
}

// =========================================================================
// M. TestClass behavioral properties
// =========================================================================

#[test]
fn enrichment_test_class_as_str_matches_display() {
    for class in TestClass::ALL {
        assert_eq!(class.as_str(), class.to_string());
    }
}

#[test]
fn enrichment_test_surface_as_str_matches_display() {
    for surface in TestSurface::ALL {
        assert_eq!(surface.as_str(), surface.to_string());
    }
}

#[test]
fn enrichment_provenance_as_str_matches_display() {
    for level in &[
        ProvenanceLevel::Authored,
        ProvenanceLevel::Generated,
        ProvenanceLevel::Captured,
        ProvenanceLevel::Synthesized,
    ] {
        assert_eq!(level.as_str(), level.to_string());
    }
}

#[test]
fn enrichment_test_outcome_as_str_matches_display() {
    for outcome in &[
        TestOutcome::Pass,
        TestOutcome::Fail,
        TestOutcome::Skip,
        TestOutcome::Timeout,
        TestOutcome::Flake,
    ] {
        assert_eq!(outcome.as_str(), outcome.to_string());
    }
}

// =========================================================================
// N. Trust rank ordering and provenance boundary
// =========================================================================

#[test]
fn enrichment_trust_rank_monotonic() {
    let levels = [
        ProvenanceLevel::Synthesized,
        ProvenanceLevel::Generated,
        ProvenanceLevel::Captured,
        ProvenanceLevel::Authored,
    ];
    for i in 1..levels.len() {
        assert!(levels[i].trust_rank() > levels[i - 1].trust_rank());
    }
}

#[test]
fn enrichment_requires_seed_only_adversarial_and_fault_injection() {
    let seed_classes: Vec<&TestClass> = TestClass::ALL
        .iter()
        .filter(|c| c.requires_seed())
        .collect();
    assert_eq!(seed_classes.len(), 2);
    assert!(seed_classes.contains(&&TestClass::Adversarial));
    assert!(seed_classes.contains(&&TestClass::FaultInjection));
}

// =========================================================================
// O. Lane charter refs are all well-formed
// =========================================================================

#[test]
fn enrichment_lane_charter_refs_well_formed() {
    for surface in TestSurface::ALL {
        let lcr = surface.lane_charter_ref();
        assert!(
            lcr.starts_with("bd-mjh3.10."),
            "surface {:?} has ref {lcr}",
            surface
        );
        // Parse the final segment as a number
        let suffix = lcr.strip_prefix("bd-mjh3.10.").unwrap();
        assert!(
            suffix.parse::<u32>().is_ok(),
            "suffix {suffix} is not a number"
        );
    }
}

// =========================================================================
// P. Schema version constants
// =========================================================================

#[test]
fn enrichment_schema_versions_semver_format() {
    for version in &[
        TEST_TAXONOMY_SCHEMA_VERSION,
        FIXTURE_REGISTRY_SCHEMA_VERSION,
    ] {
        let parts: Vec<&str> = version.split('.').collect();
        assert_eq!(parts.len(), 3, "version {version} not semver");
        for part in &parts {
            assert!(part.parse::<u32>().is_ok(), "part {part} not numeric");
        }
    }
}

// =========================================================================
// Q. DeterminismContract::for_class covers all classes
// =========================================================================

#[test]
fn enrichment_for_class_all_valid() {
    for class in TestClass::ALL {
        let contract = DeterminismContract::for_class(*class);
        // For built-in classes, contracts should self-validate clean
        // (FaultInjection has nondet=1 but also deterministic_rng=true)
        let violations = contract.validate();
        assert!(
            violations.is_empty(),
            "class {:?} has violations: {:?}",
            class,
            violations
        );
    }
}

#[test]
fn enrichment_for_class_strict_consistency() {
    // Adversarial should produce the same as strict()
    let adv = DeterminismContract::for_class(TestClass::Adversarial);
    let strict = DeterminismContract::strict();
    assert_eq!(adv, strict);
}

// =========================================================================
// R. Validate_all catches per-fixture violations
// =========================================================================

#[test]
fn enrichment_validate_all_multiple_failing_fixtures() {
    let mut r = FixtureRegistry::new();
    let mut f1 = make_fixture("bad1", TestClass::Adversarial);
    f1.seed = None;
    r.register(f1).unwrap();
    let mut f2 = make_fixture("bad2", TestClass::Adversarial);
    f2.seed = None;
    f2.content_hash = String::new();
    r.register(f2).unwrap();
    r.register(make_fixture("good", TestClass::Core)).unwrap();

    let results = r.validate_all();
    assert_eq!(results.len(), 2);
    let ids: BTreeSet<&str> = results.iter().map(|r| r.0.as_str()).collect();
    assert!(ids.contains("bad1"));
    assert!(ids.contains("bad2"));
}

// =========================================================================
// S. Serde roundtrips for complex nested structures
// =========================================================================

#[test]
fn enrichment_suite_summary_with_breakdowns_serde() {
    let mut records = Vec::new();
    // Create a diverse set
    for (i, class) in TestClass::ALL.iter().enumerate() {
        for (j, surface) in TestSurface::ALL.iter().enumerate() {
            let outcome = if (i + j) % 3 == 0 {
                TestOutcome::Pass
            } else if (i + j) % 3 == 1 {
                TestOutcome::Fail
            } else {
                TestOutcome::Skip
            };
            let mut r = make_record(&format!("r-{i}-{j}"), outcome);
            r.test_class = *class;
            r.surface = *surface;
            r.determinism_satisfied = (i + j) % 2 == 0;
            records.push(r);
        }
    }
    let summary = TestSuiteSummary::from_records(&records);
    let json = serde_json::to_string(&summary).unwrap();
    let back: TestSuiteSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
    assert_eq!(back.total, 40); // 5 classes × 8 surfaces
}

#[test]
fn enrichment_fixture_with_all_optional_fields_serde() {
    let mut f = make_fixture("full-opts", TestClass::FaultInjection);
    f.seed = Some(123456789);
    f.tags = BTreeSet::from([
        "deterministic".to_string(),
        "regression".to_string(),
        "priority-high".to_string(),
    ]);
    f.surfaces = BTreeSet::from([
        TestSurface::Compiler,
        TestSurface::Runtime,
        TestSurface::Evidence,
    ]);
    let json = serde_json::to_string(&f).unwrap();
    let back: FixtureEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
    assert_eq!(back.tags.len(), 3);
    assert_eq!(back.surfaces.len(), 3);
}

#[test]
fn enrichment_execution_record_with_seed_serde() {
    let mut r = make_record("seeded", TestOutcome::Pass);
    r.seed = Some(999);
    r.test_class = TestClass::Adversarial;
    r.duration_us = 999_999;
    r.notes = "enrichment test with seed".to_string();
    let json = serde_json::to_string(&r).unwrap();
    let back: TestExecutionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
    assert_eq!(back.seed, Some(999));
}

// =========================================================================
// T. BTreeMap key usage for enums in coverage matrix
// =========================================================================

#[test]
fn enrichment_coverage_matrix_btreemap_key_ordering() {
    let mut r = FixtureRegistry::new();
    // Register one fixture per class with Parser surface
    for (i, class) in TestClass::ALL.iter().enumerate() {
        let mut f = make_fixture(&format!("matrix-{i}"), *class);
        if class.requires_seed() {
            f.seed = Some(42);
        }
        r.register(f).unwrap();
    }
    let matrix = r.coverage_matrix();
    let keys: Vec<_> = matrix.keys().collect();
    // BTreeMap keys should be sorted
    for i in 1..keys.len() {
        assert!(keys[i - 1] < keys[i]);
    }
}
