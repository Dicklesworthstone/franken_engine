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

use std::{collections::BTreeSet, fs, path::PathBuf};

#[path = "../src/unit_test_taxonomy.rs"]
mod unit_test_taxonomy;

use serde_json::Value;
use unit_test_taxonomy::{
    LaneId, REQUIRED_STRUCTURED_LOG_FIELDS, UnitTestClass, default_frx20_bundle,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn frx_20_1_doc_has_required_sections() {
    let path = repo_root().join("docs/FRX_UNIT_TEST_TAXONOMY_FIXTURE_REGISTRY_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Unit-Test Taxonomy and Fixture Registry v1",
        "## Scope",
        "## Unit-Test Taxonomy",
        "## Fixture Registry Contract",
        "## Determinism Contract",
        "## Lane Ownership and Coverage Mapping",
        "## Structured Logging and Artifact Retention",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn frx_20_1_contract_is_machine_readable_and_versioned() {
    let path = repo_root().join("docs/frx_unit_test_taxonomy_fixture_registry_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.unit-test-taxonomy.v1")
    );
    assert_eq!(value["bead_id"].as_str(), Some("bd-mjh3.20.1"));
    assert_eq!(
        value["fixture_registry_schema_version"].as_str(),
        Some("frx.fixture-registry.v1")
    );
    assert_eq!(
        value["determinism_contract"]["schema_version"].as_str(),
        Some("frx.test-determinism-contract.v1")
    );

    assert_eq!(
        value["determinism_contract"]["require_seed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["determinism_contract"]["require_seed_transcript_checksum"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["determinism_contract"]["require_toolchain_fingerprint"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["determinism_contract"]["require_replay_command"].as_bool(),
        Some(true)
    );
}

#[test]
fn frx_20_1_runtime_bundle_validates() {
    let bundle = default_frx20_bundle();
    assert_eq!(bundle.validate_for_gate(), Ok(()));
}

#[test]
fn frx_20_1_lane_coverage_is_complete() {
    let bundle = default_frx20_bundle();

    let seen_lanes: BTreeSet<_> = bundle
        .lane_coverage
        .iter()
        .map(|entry| entry.lane)
        .collect();
    for lane in LaneId::ALL {
        assert!(
            seen_lanes.contains(&lane),
            "missing lane coverage for {}",
            lane.as_str()
        );
    }

    for entry in &bundle.lane_coverage {
        assert!(
            !entry.required_unit_classes.is_empty(),
            "lane {} missing required unit classes",
            entry.lane.as_str()
        );
        assert!(
            !entry.mapped_e2e_families.is_empty(),
            "lane {} missing e2e family mapping",
            entry.lane.as_str()
        );
    }
}

#[test]
fn frx_20_1_fixture_registry_points_to_existing_assets() {
    let bundle = default_frx20_bundle();

    for fixture in &bundle.fixture_registry {
        let fixture_path = repo_root().join(&fixture.fixture_path);
        assert!(
            fixture_path.exists(),
            "fixture path does not exist for {}: {}",
            fixture.fixture_id,
            fixture_path.display()
        );

        if let Some(trace_path) = &fixture.trace_path {
            let trace = repo_root().join(trace_path);
            assert!(
                trace.exists(),
                "trace path does not exist for {}: {}",
                fixture.fixture_id,
                trace.display()
            );
        }

        let provenance = repo_root().join(&fixture.provenance);
        assert!(
            provenance.exists(),
            "provenance path does not exist for {}: {}",
            fixture.fixture_id,
            provenance.display()
        );
    }
}

#[test]
fn frx_20_1_registry_requires_all_structured_log_fields() {
    let bundle = default_frx20_bundle();

    for fixture in &bundle.fixture_registry {
        let present: BTreeSet<&str> = fixture
            .structured_log_fields
            .iter()
            .map(String::as_str)
            .collect();

        for field in REQUIRED_STRUCTURED_LOG_FIELDS {
            assert!(
                present.contains(field),
                "fixture {} missing required structured log field {}",
                fixture.fixture_id,
                field
            );
        }
    }
}

#[test]
fn frx_20_1_all_test_classes_appear_in_lane_requirements() {
    let bundle = default_frx20_bundle();

    let mut seen = BTreeSet::new();
    for coverage in &bundle.lane_coverage {
        for class in &coverage.required_unit_classes {
            seen.insert(*class);
        }
    }

    for class in UnitTestClass::ALL {
        assert!(
            seen.contains(&class),
            "unit test class {} not represented in any lane coverage",
            class.as_str()
        );
    }
}

#[test]
fn frx_20_1_operator_verification_commands_present() {
    let path = repo_root().join("docs/frx_unit_test_taxonomy_fixture_registry_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    let commands = value["operator_verification"]
        .as_array()
        .expect("operator_verification should be an array");

    assert!(
        commands.iter().any(|cmd| {
            cmd.as_str().is_some_and(|line| {
                line.contains("run_frx_unit_test_taxonomy_fixture_registry_gate.sh ci")
            })
        }),
        "operator verification must include CI gate command"
    );

    assert!(
        commands.iter().any(|cmd| {
            cmd.as_str().is_some_and(|line| {
                line.contains("frx_unit_test_taxonomy_fixture_registry_replay.sh")
            })
        }),
        "operator verification must include replay command"
    );
}

// ---------- UnitTestClass ----------

#[test]
fn unit_test_class_all_is_nonempty() {
    assert!(!UnitTestClass::ALL.is_empty());
}

#[test]
fn unit_test_class_as_str_is_nonempty() {
    for class in UnitTestClass::ALL {
        assert!(!class.as_str().is_empty());
    }
}

#[test]
fn unit_test_class_serde_roundtrip() {
    for class in UnitTestClass::ALL {
        let json = serde_json::to_string(&class).expect("serialize");
        let recovered: UnitTestClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, class);
    }
}

// ---------- LaneId ----------

#[test]
fn lane_id_all_is_nonempty() {
    assert!(!LaneId::ALL.is_empty());
}

#[test]
fn lane_id_as_str_is_nonempty() {
    for lane in LaneId::ALL {
        assert!(!lane.as_str().is_empty());
    }
}

#[test]
fn lane_id_serde_roundtrip() {
    for lane in LaneId::ALL {
        let json = serde_json::to_string(&lane).expect("serialize");
        let recovered: LaneId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, lane);
    }
}

// ---------- REQUIRED_STRUCTURED_LOG_FIELDS ----------

#[test]
fn required_structured_log_fields_is_nonempty() {
    assert!(!REQUIRED_STRUCTURED_LOG_FIELDS.is_empty());
    assert!(REQUIRED_STRUCTURED_LOG_FIELDS.contains(&"trace_id"));
    assert!(REQUIRED_STRUCTURED_LOG_FIELDS.contains(&"outcome"));
}

// ---------- default_frx20_bundle ----------

#[test]
fn default_bundle_lane_coverage_is_nonempty() {
    let bundle = default_frx20_bundle();
    assert!(!bundle.lane_coverage.is_empty());
}

#[test]
fn default_bundle_fixture_registry_is_nonempty() {
    let bundle = default_frx20_bundle();
    assert!(!bundle.fixture_registry.is_empty());
}

#[test]
fn default_bundle_validation_is_deterministic() {
    let a = default_frx20_bundle();
    let b = default_frx20_bundle();
    assert_eq!(a.validate_for_gate(), b.validate_for_gate());
}

#[test]
fn lane_id_all_variants_roundtrip() {
    for lane in [
        LaneId::Compiler,
        LaneId::JsRuntime,
        LaneId::WasmRuntime,
        LaneId::HybridRouter,
        LaneId::Verification,
    ] {
        let json = serde_json::to_string(&lane).expect("serialize");
        let recovered: LaneId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(lane, recovered);
    }
}

#[test]
fn unit_test_class_all_variants_roundtrip() {
    for class in [
        UnitTestClass::Core,
        UnitTestClass::Edge,
        UnitTestClass::Adversarial,
        UnitTestClass::Regression,
        UnitTestClass::FaultInjection,
    ] {
        let json = serde_json::to_string(&class).expect("serialize");
        let recovered: UnitTestClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(class, recovered);
    }
}

#[test]
fn default_bundle_has_nonempty_schema_version() {
    let bundle = default_frx20_bundle();
    assert!(!bundle.schema_version.is_empty());
}

#[test]
fn lane_id_debug_is_nonempty() {
    for lane in [
        LaneId::Compiler,
        LaneId::JsRuntime,
        LaneId::WasmRuntime,
        LaneId::HybridRouter,
        LaneId::Verification,
    ] {
        assert!(!format!("{lane:?}").is_empty());
    }
}

#[test]
fn unit_test_class_debug_is_nonempty() {
    for class in [
        UnitTestClass::Core,
        UnitTestClass::Edge,
        UnitTestClass::Adversarial,
        UnitTestClass::Regression,
        UnitTestClass::FaultInjection,
    ] {
        assert!(!format!("{class:?}").is_empty());
    }
}

#[test]
fn required_structured_log_fields_all_entries_are_nonempty() {
    assert!(!REQUIRED_STRUCTURED_LOG_FIELDS.is_empty());
    for field in REQUIRED_STRUCTURED_LOG_FIELDS {
        assert!(!field.trim().is_empty());
    }
}

#[test]
fn default_bundle_debug_is_nonempty() {
    let bundle = default_frx20_bundle();
    assert!(!format!("{bundle:?}").is_empty());
}

#[test]
fn default_bundle_serde_is_deterministic() {
    let bundle = default_frx20_bundle();
    let a = serde_json::to_string(&bundle).expect("first");
    let b = serde_json::to_string(&bundle).expect("second");
    assert_eq!(a, b);
}

#[test]
fn unit_test_class_serde_is_deterministic() {
    for class in UnitTestClass::ALL {
        let a = serde_json::to_string(&class).expect("first");
        let b = serde_json::to_string(&class).expect("second");
        assert_eq!(a, b);
    }
}

// ---------- LaneId uniqueness ----------

#[test]
fn lane_id_as_str_values_are_all_distinct() {
    let strs: BTreeSet<&str> = LaneId::ALL.iter().map(|l| l.as_str()).collect();
    assert_eq!(
        strs.len(),
        LaneId::ALL.len(),
        "every LaneId must have a distinct as_str() value"
    );
}

// ---------- UnitTestClass uniqueness ----------

#[test]
fn unit_test_class_as_str_values_are_all_distinct() {
    let strs: BTreeSet<&str> = UnitTestClass::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(
        strs.len(),
        UnitTestClass::ALL.len(),
        "every UnitTestClass must have a distinct as_str() value"
    );
}

// ---------- default_frx20_bundle fixture IDs are unique ----------

#[test]
fn default_bundle_fixture_ids_are_unique() {
    let bundle = default_frx20_bundle();
    let mut seen = BTreeSet::new();
    for fixture in &bundle.fixture_registry {
        assert!(
            seen.insert(fixture.fixture_id.clone()),
            "duplicate fixture_id in default bundle: {}",
            fixture.fixture_id
        );
    }
}

// ---------- enrichment: deeper validation and error-path coverage ----------

#[test]
fn default_bundle_determinism_contract_requires_seed_and_replay() {
    let bundle = default_frx20_bundle();
    assert!(
        bundle.determinism_contract.require_seed,
        "determinism contract must require seed"
    );
    assert!(
        bundle.determinism_contract.require_replay_command,
        "determinism contract must require replay command"
    );
    assert!(
        bundle.determinism_contract.require_toolchain_fingerprint,
        "determinism contract must require toolchain fingerprint"
    );
}

#[test]
fn default_bundle_determinism_contract_timezone_is_utc() {
    let bundle = default_frx20_bundle();
    assert_eq!(
        bundle.determinism_contract.timezone, "UTC",
        "determinism contract timezone must be UTC"
    );
    assert!(bundle.determinism_contract.require_fixed_timezone);
}

#[test]
fn default_bundle_lane_coverage_has_all_eight_lanes() {
    let bundle = default_frx20_bundle();
    assert_eq!(
        bundle.lane_coverage.len(),
        LaneId::ALL.len(),
        "lane_coverage must have exactly {} entries (one per LaneId)",
        LaneId::ALL.len()
    );
}

#[test]
fn default_bundle_fixture_registry_entries_have_nonempty_e2e_families() {
    let bundle = default_frx20_bundle();
    for fixture in &bundle.fixture_registry {
        assert!(
            !fixture.e2e_family.trim().is_empty(),
            "fixture {} must have a non-empty e2e_family",
            fixture.fixture_id
        );
        assert!(
            !fixture.seed_strategy.trim().is_empty(),
            "fixture {} must have a non-empty seed_strategy",
            fixture.fixture_id
        );
    }
}

#[test]
fn default_bundle_serde_roundtrip_preserves_bundle() {
    let bundle = default_frx20_bundle();
    let json = serde_json::to_string(&bundle).expect("serialize bundle");
    let recovered: unit_test_taxonomy::UnitTestTaxonomyBundle =
        serde_json::from_str(&json).expect("deserialize bundle");
    assert_eq!(bundle, recovered, "serde roundtrip must preserve bundle");
}
