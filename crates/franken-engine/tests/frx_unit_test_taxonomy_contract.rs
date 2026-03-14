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
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::test_taxonomy::{
    ClassBreakdown, ContractViolation, DeterminismContract, FIXTURE_REGISTRY_SCHEMA_VERSION,
    FixtureEntry, FixtureRegistry, OwnershipEntry, OwnershipMap, ProvenanceLevel, RegistryError,
    TEST_TAXONOMY_SCHEMA_VERSION, TestClass, TestExecutionRecord, TestOutcome, TestSuiteSummary,
    TestSurface,
};
use serde::Deserialize;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn parse_test_class(raw: &str) -> TestClass {
    match raw {
        "core" => TestClass::Core,
        "edge" => TestClass::Edge,
        "adversarial" => TestClass::Adversarial,
        "regression" => TestClass::Regression,
        "fault_injection" => TestClass::FaultInjection,
        other => panic!("unknown test class: {other}"),
    }
}

fn parse_surface(raw: &str) -> TestSurface {
    match raw {
        "compiler" => TestSurface::Compiler,
        "runtime" => TestSurface::Runtime,
        "router" => TestSurface::Router,
        "governance" => TestSurface::Governance,
        "parser" => TestSurface::Parser,
        "scheduler" => TestSurface::Scheduler,
        "evidence" => TestSurface::Evidence,
        "security" => TestSurface::Security,
        other => panic!("unknown test surface: {other}"),
    }
}

#[derive(Debug, Deserialize)]
struct UnitTaxonomyContract {
    schema_version: String,
    primary_bead: String,
    generated_by: String,
    taxonomy: TaxonomySection,
    fixture_registry: FixtureRegistrySection,
    determinism_contract: DeterminismSection,
    lane_ownership_map: Vec<LaneOwnershipEntry>,
    unit_to_e2e_mappings: Vec<UnitToE2eMapping>,
    logging_contract: LoggingContract,
    failure_policy: FailurePolicy,
    operator_verification: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TaxonomySection {
    module_schema_version: String,
    fixture_registry_schema_version: String,
    classes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FixtureRegistrySection {
    required_fields: Vec<String>,
    provenance_levels: Vec<String>,
    seed_policy: SeedPolicy,
    artifact_retention_hooks: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SeedPolicy {
    required_for_classes: Vec<String>,
    optional_for_classes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DeterminismSection {
    strict_contract_schema: String,
    seed_control_required_classes: Vec<String>,
    virtual_clock_required_classes: Vec<String>,
    deterministic_rng_required_classes: Vec<String>,
    environment_controls: Vec<String>,
    replay_requirements: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LaneOwnershipEntry {
    surface: String,
    lane_charter_ref: String,
    required_classes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct UnitToE2eMapping {
    test_class: String,
    scenario_families: Vec<String>,
    coverage_rationale: String,
}

#[derive(Debug, Deserialize)]
struct LoggingContract {
    component: String,
    required_fields: Vec<String>,
    artifact_retention_hooks: Vec<String>,
    fail_closed_on_missing_fields: bool,
}

#[derive(Debug, Deserialize)]
struct FailurePolicy {
    mode: String,
    error_code: String,
    block_on_schema_drift: bool,
    block_on_missing_lane_ownership: bool,
    block_on_missing_unit_to_e2e_mapping: bool,
    block_on_logging_contract_gap: bool,
}

#[test]
fn frx_20_1_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_UNIT_TEST_TAXONOMY_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for section in [
        "# FRX Unit-Test Taxonomy and Fixture Registry V1",
        "## Scope",
        "## Unit-Test Taxonomy",
        "## Fixture Registry Schema",
        "## Determinism and Replay Contract",
        "## Lane Ownership Map",
        "## Unit-to-E2E Coverage Mapping",
        "## Logging and Artifact Retention Hooks",
        "## CI Gate and Failure Policy",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(section),
            "missing required section `{section}` in {}",
            path.display()
        );
    }
}

#[test]
fn frx_20_1_contract_schema_versions_are_pinned() {
    let path = repo_root().join("docs/frx_unit_test_taxonomy_v1.json");
    let contract: UnitTaxonomyContract = load_json(&path);

    assert_eq!(
        contract.schema_version, "frx.unit-test-taxonomy.contract.v1",
        "contract schema version drift"
    );
    assert_eq!(contract.primary_bead, "bd-mjh3.20.1");
    assert_eq!(contract.generated_by, "bd-mjh3.20.1");
    assert_eq!(
        contract.taxonomy.module_schema_version,
        TEST_TAXONOMY_SCHEMA_VERSION
    );
    assert_eq!(
        contract.taxonomy.fixture_registry_schema_version,
        FIXTURE_REGISTRY_SCHEMA_VERSION
    );
    assert_eq!(
        contract.determinism_contract.strict_contract_schema,
        TEST_TAXONOMY_SCHEMA_VERSION
    );
}

#[test]
fn frx_20_1_taxonomy_classes_cover_all_canonical_variants() {
    let path = repo_root().join("docs/frx_unit_test_taxonomy_v1.json");
    let contract: UnitTaxonomyContract = load_json(&path);

    let classes_from_contract: BTreeSet<TestClass> = contract
        .taxonomy
        .classes
        .iter()
        .map(|raw| parse_test_class(raw))
        .collect();
    let expected: BTreeSet<TestClass> = TestClass::ALL.iter().copied().collect();

    assert_eq!(classes_from_contract, expected);
}

#[test]
fn frx_20_1_lane_ownership_map_covers_every_surface_and_class() {
    let path = repo_root().join("docs/frx_unit_test_taxonomy_v1.json");
    let contract: UnitTaxonomyContract = load_json(&path);

    let expected_classes: BTreeSet<TestClass> = TestClass::ALL.iter().copied().collect();
    let expected_surfaces: BTreeSet<TestSurface> = TestSurface::ALL.iter().copied().collect();

    let mapped_surfaces: BTreeSet<TestSurface> = contract
        .lane_ownership_map
        .iter()
        .map(|entry| parse_surface(entry.surface.as_str()))
        .collect();

    assert_eq!(
        mapped_surfaces, expected_surfaces,
        "surface coverage mismatch"
    );

    for entry in &contract.lane_ownership_map {
        let surface = parse_surface(entry.surface.as_str());
        assert_eq!(entry.lane_charter_ref, surface.lane_charter_ref());

        let classes: BTreeSet<TestClass> = entry
            .required_classes
            .iter()
            .map(|raw| parse_test_class(raw))
            .collect();
        assert_eq!(
            classes, expected_classes,
            "ownership entry `{}` does not require full class set",
            entry.surface
        );
    }
}

#[test]
fn frx_20_1_determinism_class_requirements_match_runtime_contracts() {
    let path = repo_root().join("docs/frx_unit_test_taxonomy_v1.json");
    let contract: UnitTaxonomyContract = load_json(&path);

    let required_seed: BTreeSet<TestClass> = contract
        .determinism_contract
        .seed_control_required_classes
        .iter()
        .map(|raw| parse_test_class(raw))
        .collect();
    let required_clock: BTreeSet<TestClass> = contract
        .determinism_contract
        .virtual_clock_required_classes
        .iter()
        .map(|raw| parse_test_class(raw))
        .collect();
    let required_rng: BTreeSet<TestClass> = contract
        .determinism_contract
        .deterministic_rng_required_classes
        .iter()
        .map(|raw| parse_test_class(raw))
        .collect();

    for class in TestClass::ALL {
        let dc = DeterminismContract::for_class(*class);

        assert_eq!(
            required_seed.contains(class),
            dc.seed_required,
            "seed requirement mismatch for class {class}"
        );
        assert_eq!(
            required_clock.contains(class),
            dc.virtual_clock_required,
            "virtual clock requirement mismatch for class {class}"
        );
        assert_eq!(
            required_rng.contains(class),
            dc.deterministic_rng_required,
            "deterministic RNG requirement mismatch for class {class}"
        );
    }

    for control in [
        "timezone",
        "locale",
        "rust_toolchain",
        "seed_transcript_checksum",
        "env_fingerprint",
    ] {
        assert!(
            contract
                .determinism_contract
                .environment_controls
                .iter()
                .any(|item| item == control),
            "missing determinism environment control: {control}"
        );
    }

    for replay_req in [
        "record_replay_command",
        "record_target_dir",
        "record_rch_execution_mode",
        "retain_gate_artifacts",
    ] {
        assert!(
            contract
                .determinism_contract
                .replay_requirements
                .iter()
                .any(|item| item == replay_req),
            "missing replay requirement: {replay_req}"
        );
    }
}

#[test]
fn frx_20_1_unit_to_e2e_mapping_is_complete_and_rationalized() {
    let path = repo_root().join("docs/frx_unit_test_taxonomy_v1.json");
    let contract: UnitTaxonomyContract = load_json(&path);

    let mapped_classes: BTreeSet<TestClass> = contract
        .unit_to_e2e_mappings
        .iter()
        .map(|mapping| parse_test_class(mapping.test_class.as_str()))
        .collect();
    let expected: BTreeSet<TestClass> = TestClass::ALL.iter().copied().collect();

    assert_eq!(mapped_classes, expected, "unit->e2e mapping is incomplete");

    for mapping in &contract.unit_to_e2e_mappings {
        assert!(
            !mapping.scenario_families.is_empty(),
            "scenario families missing for class {}",
            mapping.test_class
        );
        assert!(
            !mapping.coverage_rationale.trim().is_empty(),
            "coverage rationale missing for class {}",
            mapping.test_class
        );
    }
}

#[test]
fn frx_20_1_logging_contract_and_failure_policy_are_fail_closed() {
    let path = repo_root().join("docs/frx_unit_test_taxonomy_v1.json");
    let contract: UnitTaxonomyContract = load_json(&path);

    assert_eq!(
        contract.logging_contract.component,
        "frx_unit_test_taxonomy_contract"
    );
    assert!(contract.logging_contract.fail_closed_on_missing_fields);

    for field in [
        "fixture_id",
        "description",
        "test_class",
        "surfaces",
        "provenance",
        "seed",
        "content_hash",
        "format_version",
        "origin_ref",
        "tags",
    ] {
        assert!(
            contract
                .fixture_registry
                .required_fields
                .iter()
                .any(|item| item == field),
            "missing fixture registry field: {field}"
        );
    }

    for level in ["authored", "generated", "captured", "synthesized"] {
        assert!(
            contract
                .fixture_registry
                .provenance_levels
                .iter()
                .any(|item| item == level),
            "missing provenance level: {level}"
        );
    }

    for field in [
        "scenario_id",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "seed",
        "timing",
        "decision_path",
        "outcome",
        "error_code",
        "replay_command",
    ] {
        assert!(
            contract
                .logging_contract
                .required_fields
                .iter()
                .any(|item| item == field),
            "missing logging field: {field}"
        );
    }

    for hook in ["run_manifest.json", "events.jsonl", "commands.txt"] {
        assert!(
            contract
                .logging_contract
                .artifact_retention_hooks
                .iter()
                .any(|item| item == hook),
            "missing logging artifact hook: {hook}"
        );
        assert!(
            contract
                .fixture_registry
                .artifact_retention_hooks
                .iter()
                .any(|item| item == hook),
            "missing fixture artifact hook: {hook}"
        );
    }

    assert_eq!(contract.failure_policy.mode, "fail_closed");
    assert_eq!(
        contract.failure_policy.error_code,
        "FE-FRX-20-1-TAXONOMY-0001"
    );
    assert!(contract.failure_policy.block_on_schema_drift);
    assert!(contract.failure_policy.block_on_missing_lane_ownership);
    assert!(contract.failure_policy.block_on_missing_unit_to_e2e_mapping);
    assert!(contract.failure_policy.block_on_logging_contract_gap);

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("run_frx_unit_test_taxonomy_contract_suite.sh ci"))
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("frx_unit_test_taxonomy_contract_replay.sh ci"))
    );
}

#[test]
fn frx_20_1_fixture_registry_contract_can_satisfy_seed_and_coverage_requirements() {
    let path = repo_root().join("docs/frx_unit_test_taxonomy_v1.json");
    let contract: UnitTaxonomyContract = load_json(&path);

    let required_seed_classes: BTreeSet<TestClass> = contract
        .fixture_registry
        .seed_policy
        .required_for_classes
        .iter()
        .map(|raw| parse_test_class(raw))
        .collect();
    let optional_seed_classes: BTreeSet<TestClass> = contract
        .fixture_registry
        .seed_policy
        .optional_for_classes
        .iter()
        .map(|raw| parse_test_class(raw))
        .collect();

    let all_classes: BTreeSet<TestClass> = TestClass::ALL.iter().copied().collect();
    assert_eq!(
        required_seed_classes
            .union(&optional_seed_classes)
            .copied()
            .collect::<BTreeSet<_>>(),
        all_classes,
        "seed policy must partition all classes"
    );

    let mut registry = FixtureRegistry::new();
    let mut counter = 0_u64;

    for class in TestClass::ALL {
        for surface in TestSurface::ALL {
            counter += 1;
            let seed = if required_seed_classes.contains(class) {
                Some(1_000 + counter)
            } else {
                None
            };
            let entry = FixtureEntry {
                fixture_id: format!("frx20-{}-{}", class.as_str(), surface.as_str()),
                description: format!(
                    "FRX-20.1 contract fixture for {} {}",
                    class.as_str(),
                    surface.as_str()
                ),
                test_class: *class,
                surfaces: BTreeSet::from([*surface]),
                provenance: class.min_provenance_level(),
                seed,
                content_hash: format!("sha256:frx20-{}-{}", class.as_str(), surface.as_str()),
                format_version: "frx.unit-fixture.v1".to_string(),
                origin_ref: "bd-mjh3.20.1".to_string(),
                tags: BTreeSet::from([class.as_str().to_string(), surface.as_str().to_string()]),
            };
            registry.register(entry).unwrap();
        }
    }

    assert!(registry.validate_all().is_empty());
    assert!(registry.coverage_gaps().is_empty());
}

// ---------- parse_test_class ----------

#[test]
fn parse_test_class_all_variants() {
    assert_eq!(parse_test_class("core"), TestClass::Core);
    assert_eq!(parse_test_class("edge"), TestClass::Edge);
    assert_eq!(parse_test_class("adversarial"), TestClass::Adversarial);
    assert_eq!(parse_test_class("regression"), TestClass::Regression);
    assert_eq!(
        parse_test_class("fault_injection"),
        TestClass::FaultInjection
    );
}

#[test]
#[should_panic(expected = "unknown test class")]
fn parse_test_class_panics_on_unknown() {
    parse_test_class("invalid");
}

// ---------- parse_surface ----------

#[test]
fn parse_surface_all_variants() {
    assert_eq!(parse_surface("compiler"), TestSurface::Compiler);
    assert_eq!(parse_surface("runtime"), TestSurface::Runtime);
    assert_eq!(parse_surface("router"), TestSurface::Router);
    assert_eq!(parse_surface("governance"), TestSurface::Governance);
    assert_eq!(parse_surface("parser"), TestSurface::Parser);
    assert_eq!(parse_surface("scheduler"), TestSurface::Scheduler);
    assert_eq!(parse_surface("evidence"), TestSurface::Evidence);
    assert_eq!(parse_surface("security"), TestSurface::Security);
}

#[test]
#[should_panic(expected = "unknown test surface")]
fn parse_surface_panics_on_unknown() {
    parse_surface("nonexistent");
}

// ---------- TestClass ----------

#[test]
fn test_class_all_has_correct_count() {
    assert_eq!(TestClass::ALL.len(), 5);
}

#[test]
fn test_class_serde_roundtrip() {
    for class in TestClass::ALL {
        let json = serde_json::to_string(class).expect("serialize");
        let recovered: TestClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, *class);
    }
}

#[test]
fn test_class_as_str_is_nonempty() {
    for class in TestClass::ALL {
        assert!(!class.as_str().is_empty());
    }
}

// ---------- TestSurface ----------

#[test]
fn test_surface_all_has_correct_count() {
    assert_eq!(TestSurface::ALL.len(), 8);
}

#[test]
fn test_surface_serde_roundtrip() {
    for surface in TestSurface::ALL {
        let json = serde_json::to_string(surface).expect("serialize");
        let recovered: TestSurface = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, *surface);
    }
}

#[test]
fn test_surface_as_str_is_nonempty() {
    for surface in TestSurface::ALL {
        assert!(!surface.as_str().is_empty());
    }
}

#[test]
fn test_surface_lane_charter_ref_is_nonempty() {
    for surface in TestSurface::ALL {
        assert!(!surface.lane_charter_ref().is_empty());
    }
}

// ---------- DeterminismContract ----------

#[test]
fn determinism_contract_for_all_classes() {
    for class in TestClass::ALL {
        let dc = DeterminismContract::for_class(*class);
        // At minimum, the contract should be well-defined (no panic)
        let _ = dc.seed_required;
        let _ = dc.virtual_clock_required;
        let _ = dc.deterministic_rng_required;
    }
}

// ---------- FixtureEntry ----------

#[test]
fn fixture_entry_serde_roundtrip() {
    let entry = FixtureEntry {
        fixture_id: "test-fixture".to_string(),
        description: "test description".to_string(),
        test_class: TestClass::Core,
        surfaces: BTreeSet::from([TestSurface::Parser]),
        provenance: TestClass::Core.min_provenance_level(),
        seed: Some(42),
        content_hash: "sha256:abc".to_string(),
        format_version: "v1".to_string(),
        origin_ref: "bd-test".to_string(),
        tags: BTreeSet::from(["core".to_string()]),
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let recovered: FixtureEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.fixture_id, "test-fixture");
    assert_eq!(recovered.test_class, TestClass::Core);
}

// ---------- FixtureRegistry ----------

#[test]
fn fixture_registry_new_is_empty() {
    let registry = FixtureRegistry::new();
    assert!(registry.validate_all().is_empty());
}

// ---------- schema version constants ----------

#[test]
fn schema_version_constants_are_nonempty() {
    assert!(!TEST_TAXONOMY_SCHEMA_VERSION.is_empty());
    assert!(!FIXTURE_REGISTRY_SCHEMA_VERSION.is_empty());
}

// ---------- FixtureRegistry lookup/by_class/by_surface ----------

#[test]
fn fixture_registry_lookup_returns_registered_entry() {
    let mut registry = FixtureRegistry::new();
    let entry = FixtureEntry {
        fixture_id: "lookup-test".to_string(),
        description: "test entry".to_string(),
        test_class: TestClass::Edge,
        surfaces: BTreeSet::from([TestSurface::Runtime]),
        provenance: TestClass::Edge.min_provenance_level(),
        seed: Some(99),
        content_hash: "sha256:lookup".to_string(),
        format_version: "v1".to_string(),
        origin_ref: "bd-test".to_string(),
        tags: BTreeSet::from(["edge".to_string()]),
    };
    registry.register(entry).unwrap();
    let found = registry.lookup("lookup-test");
    assert!(found.is_some());
    assert_eq!(found.unwrap().test_class, TestClass::Edge);
    assert!(registry.lookup("nonexistent").is_none());
}

#[test]
fn fixture_registry_rejects_duplicate_id() {
    let mut registry = FixtureRegistry::new();
    let entry = FixtureEntry {
        fixture_id: "dup-test".to_string(),
        description: "first".to_string(),
        test_class: TestClass::Core,
        surfaces: BTreeSet::from([TestSurface::Parser]),
        provenance: TestClass::Core.min_provenance_level(),
        seed: Some(1),
        content_hash: "sha256:dup1".to_string(),
        format_version: "v1".to_string(),
        origin_ref: "bd-test".to_string(),
        tags: BTreeSet::new(),
    };
    registry.register(entry.clone()).unwrap();
    let err = registry.register(entry);
    assert!(err.is_err());
}

#[test]
fn fixture_registry_by_class_filters_correctly() {
    let mut registry = FixtureRegistry::new();
    for (i, class) in [TestClass::Core, TestClass::Edge, TestClass::Core]
        .iter()
        .enumerate()
    {
        let entry = FixtureEntry {
            fixture_id: format!("class-filter-{i}"),
            description: "test".to_string(),
            test_class: *class,
            surfaces: BTreeSet::from([TestSurface::Compiler]),
            provenance: class.min_provenance_level(),
            seed: Some(i as u64),
            content_hash: format!("sha256:cf{i}"),
            format_version: "v1".to_string(),
            origin_ref: "bd-test".to_string(),
            tags: BTreeSet::new(),
        };
        registry.register(entry).unwrap();
    }
    assert_eq!(registry.by_class(TestClass::Core).len(), 2);
    assert_eq!(registry.by_class(TestClass::Edge).len(), 1);
    assert_eq!(registry.by_class(TestClass::Adversarial).len(), 0);
}

#[test]
fn fixture_registry_coverage_matrix_and_gaps() {
    let mut registry = FixtureRegistry::new();
    let entry = FixtureEntry {
        fixture_id: "cov-test".to_string(),
        description: "test".to_string(),
        test_class: TestClass::Core,
        surfaces: BTreeSet::from([TestSurface::Parser, TestSurface::Runtime]),
        provenance: TestClass::Core.min_provenance_level(),
        seed: Some(10),
        content_hash: "sha256:cov".to_string(),
        format_version: "v1".to_string(),
        origin_ref: "bd-test".to_string(),
        tags: BTreeSet::new(),
    };
    registry.register(entry).unwrap();

    let matrix = registry.coverage_matrix();
    assert_eq!(
        matrix.get(&(TestClass::Core, TestSurface::Parser)),
        Some(&1)
    );
    assert_eq!(
        matrix.get(&(TestClass::Core, TestSurface::Runtime)),
        Some(&1)
    );
    assert!(!matrix.contains_key(&(TestClass::Edge, TestSurface::Parser)));

    let gaps = registry.coverage_gaps();
    // Should have gaps for everything except Core+Parser and Core+Runtime
    assert!(!gaps.is_empty());
    assert!(gaps.contains(&(TestClass::Edge, TestSurface::Compiler)));
}

#[test]
fn fixture_registry_len_and_is_empty() {
    let mut registry = FixtureRegistry::new();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);

    let entry = FixtureEntry {
        fixture_id: "len-test".to_string(),
        description: "test".to_string(),
        test_class: TestClass::Regression,
        surfaces: BTreeSet::from([TestSurface::Governance]),
        provenance: TestClass::Regression.min_provenance_level(),
        seed: Some(7),
        content_hash: "sha256:len".to_string(),
        format_version: "v1".to_string(),
        origin_ref: "bd-test".to_string(),
        tags: BTreeSet::new(),
    };
    registry.register(entry).unwrap();
    assert!(!registry.is_empty());
    assert_eq!(registry.len(), 1);
}

#[test]
fn test_class_requires_seed_is_consistent_with_determinism_contract() {
    for class in TestClass::ALL {
        let dc = DeterminismContract::for_class(*class);
        assert_eq!(
            class.requires_seed(),
            dc.seed_required,
            "TestClass::requires_seed disagrees with DeterminismContract for {class}"
        );
    }
}

#[test]
fn fixture_entry_derive_id_is_deterministic() {
    let entry = FixtureEntry {
        fixture_id: "derive-id-test".to_string(),
        description: "test derive_id determinism".to_string(),
        test_class: TestClass::Core,
        surfaces: BTreeSet::from([TestSurface::Parser]),
        provenance: TestClass::Core.min_provenance_level(),
        seed: Some(42),
        content_hash: "sha256:derive-id".to_string(),
        format_version: "frx.unit-fixture.v1".to_string(),
        origin_ref: "bd-test".to_string(),
        tags: BTreeSet::from(["core".to_string()]),
    };
    let id_a = entry.derive_id().expect("derive_id a");
    let id_b = entry.derive_id().expect("derive_id b");
    assert_eq!(id_a, id_b);
}

// ---------- FixtureRegistry by_surface ----------

#[test]
fn fixture_registry_by_surface_filters_correctly() {
    let mut registry = FixtureRegistry::new();
    let entry1 = FixtureEntry {
        fixture_id: "surf-filter-1".to_string(),
        description: "first".to_string(),
        test_class: TestClass::Core,
        surfaces: BTreeSet::from([TestSurface::Parser, TestSurface::Runtime]),
        provenance: TestClass::Core.min_provenance_level(),
        seed: Some(1),
        content_hash: "sha256:sf1".to_string(),
        format_version: "v1".to_string(),
        origin_ref: "bd-test".to_string(),
        tags: BTreeSet::new(),
    };
    let entry2 = FixtureEntry {
        fixture_id: "surf-filter-2".to_string(),
        description: "second".to_string(),
        test_class: TestClass::Edge,
        surfaces: BTreeSet::from([TestSurface::Compiler]),
        provenance: TestClass::Edge.min_provenance_level(),
        seed: Some(2),
        content_hash: "sha256:sf2".to_string(),
        format_version: "v1".to_string(),
        origin_ref: "bd-test".to_string(),
        tags: BTreeSet::new(),
    };
    registry.register(entry1).unwrap();
    registry.register(entry2).unwrap();
    assert_eq!(registry.by_surface(TestSurface::Parser).len(), 1);
    assert_eq!(registry.by_surface(TestSurface::Runtime).len(), 1);
    assert_eq!(registry.by_surface(TestSurface::Compiler).len(), 1);
    assert_eq!(registry.by_surface(TestSurface::Scheduler).len(), 0);
}

// ---------- DeterminismContract validate ----------

#[test]
fn determinism_contract_strict_validates_clean() {
    let dc = DeterminismContract::strict();
    assert!(dc.seed_required);
    assert!(dc.virtual_clock_required);
    assert!(dc.deterministic_rng_required);
    let violations = dc.validate();
    assert!(
        violations.is_empty(),
        "strict contract should have no violations"
    );
}

#[test]
fn determinism_contract_relaxed_has_correct_tolerance() {
    let dc = DeterminismContract::relaxed(500_000);
    // Relaxed contracts do not require seed, virtual clock, or deterministic RNG
    assert!(!dc.seed_required);
    assert!(!dc.virtual_clock_required);
    assert!(!dc.deterministic_rng_required);
    assert_eq!(dc.numeric_tolerance_millionths, 500_000);
}

// ---------- TestClass min_provenance_level ----------

#[test]
fn test_class_min_provenance_level_is_defined_for_all() {
    for class in TestClass::ALL {
        let prov = class.min_provenance_level();
        // Provenance level must have non-empty as_str
        assert!(
            !prov.as_str().is_empty(),
            "provenance as_str empty for {class}"
        );
        // trust_rank must be in range 0..=3
        assert!(
            prov.trust_rank() <= 3,
            "trust_rank out of range for {class}"
        );
    }
}

// ---------- FixtureEntry validate_against_contract ----------

#[test]
fn fixture_entry_validation_detects_missing_seed_for_core_class() {
    let dc = DeterminismContract::for_class(TestClass::Core);
    let entry = FixtureEntry {
        fixture_id: "no-seed-core".to_string(),
        description: "missing seed for core class".to_string(),
        test_class: TestClass::Core,
        surfaces: BTreeSet::from([TestSurface::Parser]),
        provenance: TestClass::Core.min_provenance_level(),
        seed: None, // core class requires seed
        content_hash: "sha256:noseed".to_string(),
        format_version: "v1".to_string(),
        origin_ref: "bd-test".to_string(),
        tags: BTreeSet::new(),
    };
    if dc.seed_required {
        let violations = entry.validate_against_contract(&dc);
        assert!(
            !violations.is_empty(),
            "missing seed should produce violation for core class"
        );
    }
}

// ────────────────────────────────────────────────────────────
// Enrichment: ProvenanceLevel
// ────────────────────────────────────────────────────────────

#[test]
fn provenance_level_as_str_all_four_variants() {
    assert_eq!(ProvenanceLevel::Authored.as_str(), "authored");
    assert_eq!(ProvenanceLevel::Generated.as_str(), "generated");
    assert_eq!(ProvenanceLevel::Captured.as_str(), "captured");
    assert_eq!(ProvenanceLevel::Synthesized.as_str(), "synthesized");
}

#[test]
fn provenance_level_trust_rank_ordering() {
    assert!(ProvenanceLevel::Synthesized.trust_rank() < ProvenanceLevel::Generated.trust_rank());
    assert!(ProvenanceLevel::Generated.trust_rank() < ProvenanceLevel::Captured.trust_rank());
    assert!(ProvenanceLevel::Captured.trust_rank() < ProvenanceLevel::Authored.trust_rank());
    assert!(ProvenanceLevel::Authored.trust_rank() <= 3);
}

#[test]
fn provenance_level_display_matches_as_str() {
    for prov in [
        ProvenanceLevel::Authored,
        ProvenanceLevel::Generated,
        ProvenanceLevel::Captured,
        ProvenanceLevel::Synthesized,
    ] {
        assert_eq!(prov.to_string(), prov.as_str());
    }
}

#[test]
fn provenance_level_serde_roundtrip_all_variants() {
    for prov in [
        ProvenanceLevel::Authored,
        ProvenanceLevel::Generated,
        ProvenanceLevel::Captured,
        ProvenanceLevel::Synthesized,
    ] {
        let json = serde_json::to_string(&prov).expect("serialize");
        let recovered: ProvenanceLevel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, prov);
    }
}

// ────────────────────────────────────────────────────────────
// Enrichment: TestOutcome
// ────────────────────────────────────────────────────────────

#[test]
fn test_outcome_as_str_all_five_variants() {
    assert_eq!(TestOutcome::Pass.as_str(), "pass");
    assert_eq!(TestOutcome::Fail.as_str(), "fail");
    assert_eq!(TestOutcome::Skip.as_str(), "skip");
    assert_eq!(TestOutcome::Timeout.as_str(), "timeout");
    assert_eq!(TestOutcome::Flake.as_str(), "flake");
}

#[test]
fn test_outcome_is_success_only_for_pass() {
    assert!(TestOutcome::Pass.is_success());
    assert!(!TestOutcome::Fail.is_success());
    assert!(!TestOutcome::Skip.is_success());
    assert!(!TestOutcome::Timeout.is_success());
    assert!(!TestOutcome::Flake.is_success());
}

#[test]
fn test_outcome_display_matches_as_str() {
    for outcome in [
        TestOutcome::Pass,
        TestOutcome::Fail,
        TestOutcome::Skip,
        TestOutcome::Timeout,
        TestOutcome::Flake,
    ] {
        assert_eq!(outcome.to_string(), outcome.as_str());
    }
}

#[test]
fn test_outcome_serde_roundtrip_all_variants() {
    for outcome in [
        TestOutcome::Pass,
        TestOutcome::Fail,
        TestOutcome::Skip,
        TestOutcome::Timeout,
        TestOutcome::Flake,
    ] {
        let json = serde_json::to_string(&outcome).expect("serialize");
        let recovered: TestOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, outcome);
    }
}

// ────────────────────────────────────────────────────────────
// Enrichment: TestExecutionRecord
// ────────────────────────────────────────────────────────────

fn sample_execution_record(outcome: TestOutcome) -> TestExecutionRecord {
    TestExecutionRecord {
        fixture_id: "test-fixture-exec".to_string(),
        test_class: TestClass::Core,
        surface: TestSurface::Parser,
        outcome,
        seed: Some(42),
        duration_us: 1500,
        determinism_satisfied: true,
        evidence_hash: "sha256:exec-evidence".to_string(),
        notes: "integration test record".to_string(),
    }
}

#[test]
fn test_execution_record_serde_roundtrip() {
    let record = sample_execution_record(TestOutcome::Pass);
    let json = serde_json::to_string(&record).expect("serialize");
    let recovered: TestExecutionRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.fixture_id, record.fixture_id);
    assert_eq!(recovered.outcome, TestOutcome::Pass);
    assert_eq!(recovered.seed, Some(42));
    assert_eq!(recovered.duration_us, 1500);
    assert!(recovered.determinism_satisfied);
}

#[test]
fn test_execution_record_without_seed() {
    let mut record = sample_execution_record(TestOutcome::Fail);
    record.seed = None;
    let json = serde_json::to_string(&record).expect("serialize");
    let recovered: TestExecutionRecord = serde_json::from_str(&json).expect("deserialize");
    assert!(recovered.seed.is_none());
    assert_eq!(recovered.outcome, TestOutcome::Fail);
}

// ────────────────────────────────────────────────────────────
// Enrichment: TestSuiteSummary
// ────────────────────────────────────────────────────────────

#[test]
fn test_suite_summary_from_empty_records() {
    let summary = TestSuiteSummary::from_records(&[]);
    assert_eq!(summary.total, 0);
    assert_eq!(summary.passed, 0);
    assert_eq!(summary.pass_rate_millionths, 0);
    assert_eq!(summary.determinism_rate_millionths, 0);
    assert!(summary.class_breakdown.is_empty());
    assert!(summary.surface_breakdown.is_empty());
}

#[test]
fn test_suite_summary_from_mixed_records() {
    let records = vec![
        sample_execution_record(TestOutcome::Pass),
        {
            let mut r = sample_execution_record(TestOutcome::Fail);
            r.fixture_id = "fix-2".to_string();
            r.test_class = TestClass::Edge;
            r.surface = TestSurface::Runtime;
            r.determinism_satisfied = false;
            r
        },
        {
            let mut r = sample_execution_record(TestOutcome::Skip);
            r.fixture_id = "fix-3".to_string();
            r.test_class = TestClass::Adversarial;
            r.surface = TestSurface::Compiler;
            r
        },
    ];
    let summary = TestSuiteSummary::from_records(&records);
    assert_eq!(summary.total, 3);
    assert_eq!(summary.passed, 1);
    assert_eq!(summary.failed, 1);
    assert_eq!(summary.skipped, 1);
    assert_eq!(summary.timed_out, 0);
    assert_eq!(summary.flaky, 0);
    // 1/3 pass rate = 333_333 millionths
    assert_eq!(summary.pass_rate_millionths, 333_333);
    // 2/3 determinism satisfied
    assert_eq!(summary.determinism_rate_millionths, 666_666);
    assert!(summary.class_breakdown.contains_key(&TestClass::Core));
    assert!(summary.class_breakdown.contains_key(&TestClass::Edge));
    assert_eq!(summary.surface_breakdown[&TestSurface::Parser], 1);
    assert_eq!(summary.surface_breakdown[&TestSurface::Runtime], 1);
}

#[test]
fn test_suite_summary_meets_threshold() {
    let records = vec![sample_execution_record(TestOutcome::Pass), {
        let mut r = sample_execution_record(TestOutcome::Pass);
        r.fixture_id = "fix-2".to_string();
        r
    }];
    let summary = TestSuiteSummary::from_records(&records);
    assert_eq!(summary.pass_rate_millionths, 1_000_000);
    assert!(summary.meets_threshold(999_999));
    assert!(summary.meets_threshold(1_000_000));
    assert!(!summary.meets_threshold(1_000_001));
}

#[test]
fn test_suite_summary_serde_roundtrip() {
    let records = vec![sample_execution_record(TestOutcome::Pass)];
    let summary = TestSuiteSummary::from_records(&records);
    let json = serde_json::to_string(&summary).expect("serialize");
    let recovered: TestSuiteSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.total, summary.total);
    assert_eq!(recovered.pass_rate_millionths, summary.pass_rate_millionths);
}

// ────────────────────────────────────────────────────────────
// Enrichment: ClassBreakdown
// ────────────────────────────────────────────────────────────

#[test]
fn class_breakdown_serde_roundtrip() {
    let bd = ClassBreakdown {
        total: 10,
        passed: 8,
        failed: 2,
    };
    let json = serde_json::to_string(&bd).expect("serialize");
    let recovered: ClassBreakdown = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, bd);
}

// ────────────────────────────────────────────────────────────
// Enrichment: OwnershipMap
// ────────────────────────────────────────────────────────────

#[test]
fn ownership_map_new_is_empty() {
    let map = OwnershipMap::new();
    assert!(map.entries.is_empty());
    assert_eq!(map.schema, TEST_TAXONOMY_SCHEMA_VERSION);
}

#[test]
fn ownership_map_default_equals_new() {
    let a = OwnershipMap::new();
    let b = OwnershipMap::default();
    assert_eq!(a, b);
}

#[test]
fn ownership_map_add_and_by_surface() {
    let mut map = OwnershipMap::new();
    map.add(OwnershipEntry {
        surface: TestSurface::Parser,
        test_class: TestClass::Core,
        lane_charter_ref: "bd-mjh3.10.3".to_string(),
        owner_agent: "AgentA".to_string(),
        fixture_ids: BTreeSet::from(["fix-1".to_string()]),
    });
    map.add(OwnershipEntry {
        surface: TestSurface::Compiler,
        test_class: TestClass::Edge,
        lane_charter_ref: "bd-mjh3.10.2".to_string(),
        owner_agent: "AgentB".to_string(),
        fixture_ids: BTreeSet::from(["fix-2".to_string()]),
    });

    assert_eq!(map.by_surface(TestSurface::Parser).len(), 1);
    assert_eq!(map.by_surface(TestSurface::Compiler).len(), 1);
    assert_eq!(map.by_surface(TestSurface::Runtime).len(), 0);
}

#[test]
fn ownership_map_unowned_fixtures_detects_gaps() {
    let mut registry = FixtureRegistry::new();
    registry
        .register(FixtureEntry {
            fixture_id: "owned-fix".to_string(),
            description: "owned".to_string(),
            test_class: TestClass::Core,
            surfaces: BTreeSet::from([TestSurface::Parser]),
            provenance: ProvenanceLevel::Authored,
            seed: None,
            content_hash: "sha256:owned".to_string(),
            format_version: "v1".to_string(),
            origin_ref: "bd-test".to_string(),
            tags: BTreeSet::new(),
        })
        .unwrap();
    registry
        .register(FixtureEntry {
            fixture_id: "unowned-fix".to_string(),
            description: "unowned".to_string(),
            test_class: TestClass::Edge,
            surfaces: BTreeSet::from([TestSurface::Runtime]),
            provenance: ProvenanceLevel::Authored,
            seed: None,
            content_hash: "sha256:unowned".to_string(),
            format_version: "v1".to_string(),
            origin_ref: "bd-test".to_string(),
            tags: BTreeSet::new(),
        })
        .unwrap();

    let mut map = OwnershipMap::new();
    map.add(OwnershipEntry {
        surface: TestSurface::Parser,
        test_class: TestClass::Core,
        lane_charter_ref: "bd-mjh3.10.3".to_string(),
        owner_agent: "AgentA".to_string(),
        fixture_ids: BTreeSet::from(["owned-fix".to_string()]),
    });

    let unowned = map.unowned_fixtures(&registry);
    assert_eq!(unowned, vec!["unowned-fix".to_string()]);
}

#[test]
fn ownership_entry_serde_roundtrip() {
    let entry = OwnershipEntry {
        surface: TestSurface::Governance,
        test_class: TestClass::Regression,
        lane_charter_ref: "bd-mjh3.10.7".to_string(),
        owner_agent: "AgentX".to_string(),
        fixture_ids: BTreeSet::from(["f1".to_string(), "f2".to_string()]),
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let recovered: OwnershipEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, entry);
}

// ────────────────────────────────────────────────────────────
// Enrichment: ContractViolation, RegistryError, DeterminismContract
// ────────────────────────────────────────────────────────────

#[test]
fn contract_violation_serde_roundtrip() {
    let v = ContractViolation {
        field: "seed".to_string(),
        message: "missing seed".to_string(),
    };
    let json = serde_json::to_string(&v).expect("serialize");
    let recovered: ContractViolation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, v);
}

#[test]
fn registry_error_display_all_three_variants() {
    let errors = [
        RegistryError::DuplicateFixtureId("fix-dup".to_string()),
        RegistryError::FixtureNotFound("fix-missing".to_string()),
        RegistryError::InvalidFixture("bad structure".to_string()),
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "Display must produce non-empty output");
    }
    assert!(errors[0].to_string().contains("fix-dup"));
    assert!(errors[1].to_string().contains("fix-missing"));
    assert!(errors[2].to_string().contains("bad structure"));
}

#[test]
fn registry_error_serde_roundtrip() {
    let err = RegistryError::DuplicateFixtureId("fix-dup".to_string());
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: RegistryError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, err);
}

#[test]
fn determinism_contract_serde_roundtrip() {
    let dc = DeterminismContract::strict();
    let json = serde_json::to_string(&dc).expect("serialize");
    let recovered: DeterminismContract = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, dc);
}

#[test]
fn determinism_contract_validate_detects_negative_tolerance() {
    let mut dc = DeterminismContract::relaxed(0);
    dc.numeric_tolerance_millionths = -1;
    let violations = dc.validate();
    assert!(
        violations
            .iter()
            .any(|v| v.field == "numeric_tolerance_millionths"),
        "negative tolerance must be flagged"
    );
}

#[test]
fn determinism_contract_validate_detects_bit_identical_with_tolerance() {
    let mut dc = DeterminismContract::strict();
    dc.numeric_tolerance_millionths = 100;
    let violations = dc.validate();
    assert!(
        violations
            .iter()
            .any(|v| v.message.contains("nonzero tolerance")),
        "bit-identical with nonzero tolerance must be flagged"
    );
}

#[test]
fn test_class_display_matches_as_str() {
    for class in TestClass::ALL {
        assert_eq!(class.to_string(), class.as_str());
    }
}

#[test]
fn test_surface_display_matches_as_str() {
    for surface in TestSurface::ALL {
        assert_eq!(surface.to_string(), surface.as_str());
    }
}

#[test]
fn fixture_registry_default_equals_new() {
    let a = FixtureRegistry::new();
    let b = FixtureRegistry::default();
    assert_eq!(a, b);
}
