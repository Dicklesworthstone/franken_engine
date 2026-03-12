#![forbid(unsafe_code)]
//! Integration tests for the `unit_test_taxonomy` module.
//!
//! Exercises UnitTestClass, LaneId, DeterminismContract, FixtureRegistryEntry,
//! LaneCoverageContract, UnitTestTaxonomyBundle, TaxonomyValidationError,
//! default_frx20_bundle, and validate_for_gate.

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

use frankenengine_engine::unit_test_taxonomy::{
    DETERMINISM_CONTRACT_SCHEMA_VERSION, DeterminismContract, FIXTURE_REGISTRY_SCHEMA_VERSION,
    FixtureRegistryEntry, LaneCoverageContract, LaneId, REQUIRED_STRUCTURED_LOG_FIELDS,
    TaxonomyValidationError, UNIT_TEST_TAXONOMY_SCHEMA_VERSION, UnitTestClass,
    UnitTestTaxonomyBundle, default_frx20_bundle,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn all_required_log_fields() -> Vec<String> {
    REQUIRED_STRUCTURED_LOG_FIELDS
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

fn make_fixture(id: &str, lane: LaneId) -> FixtureRegistryEntry {
    FixtureRegistryEntry {
        fixture_id: id.into(),
        fixture_path: format!("tests/{id}"),
        trace_path: Some(format!("traces/{id}")),
        provenance: "test-provenance".into(),
        owner_lane: lane,
        required_classes: vec![UnitTestClass::Core],
        e2e_family: "test-family".into(),
        seed_strategy: "fixed".into(),
        structured_log_fields: all_required_log_fields(),
        artifact_retention: "manifest+events".into(),
    }
}

fn make_lane_coverage(lane: LaneId) -> LaneCoverageContract {
    LaneCoverageContract {
        lane,
        owner: format!("frx-{}-lane", lane.as_str()),
        required_unit_classes: vec![UnitTestClass::Core, UnitTestClass::Regression],
        mapped_e2e_families: vec![format!("frx_{}", lane.as_str())],
        coverage_rationale: format!("{} lane coverage rationale", lane.as_str()),
    }
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn schema_versions_nonempty() {
    assert!(!UNIT_TEST_TAXONOMY_SCHEMA_VERSION.is_empty());
    assert!(!FIXTURE_REGISTRY_SCHEMA_VERSION.is_empty());
    assert!(!DETERMINISM_CONTRACT_SCHEMA_VERSION.is_empty());
}

#[test]
fn required_log_fields_nonempty() {
    assert!(!REQUIRED_STRUCTURED_LOG_FIELDS.is_empty());
    assert!(REQUIRED_STRUCTURED_LOG_FIELDS.contains(&"schema_version"));
    assert!(REQUIRED_STRUCTURED_LOG_FIELDS.contains(&"trace_id"));
    assert!(REQUIRED_STRUCTURED_LOG_FIELDS.contains(&"outcome"));
}

// ===========================================================================
// 2. UnitTestClass
// ===========================================================================

#[test]
fn unit_test_class_all_has_five() {
    assert_eq!(UnitTestClass::ALL.len(), 5);
}

#[test]
fn unit_test_class_as_str() {
    assert_eq!(UnitTestClass::Core.as_str(), "core");
    assert_eq!(UnitTestClass::Edge.as_str(), "edge");
    assert_eq!(UnitTestClass::Adversarial.as_str(), "adversarial");
    assert_eq!(UnitTestClass::Regression.as_str(), "regression");
    assert_eq!(UnitTestClass::FaultInjection.as_str(), "fault_injection");
}

#[test]
fn unit_test_class_serde() {
    for c in &UnitTestClass::ALL {
        let json = serde_json::to_string(c).unwrap();
        let back: UnitTestClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

// ===========================================================================
// 3. LaneId
// ===========================================================================

#[test]
fn lane_id_all_has_eight() {
    assert_eq!(LaneId::ALL.len(), 8);
}

#[test]
fn lane_id_as_str() {
    assert_eq!(LaneId::Compiler.as_str(), "compiler");
    assert_eq!(LaneId::JsRuntime.as_str(), "js_runtime");
    assert_eq!(LaneId::WasmRuntime.as_str(), "wasm_runtime");
    assert_eq!(LaneId::HybridRouter.as_str(), "hybrid_router");
    assert_eq!(LaneId::Verification.as_str(), "verification");
    assert_eq!(LaneId::Toolchain.as_str(), "toolchain");
    assert_eq!(LaneId::GovernanceEvidence.as_str(), "governance_evidence");
    assert_eq!(LaneId::AdoptionRelease.as_str(), "adoption_release");
}

#[test]
fn lane_id_serde() {
    for l in &LaneId::ALL {
        let json = serde_json::to_string(l).unwrap();
        let back: LaneId = serde_json::from_str(&json).unwrap();
        assert_eq!(*l, back);
    }
}

// ===========================================================================
// 4. DeterminismContract
// ===========================================================================

#[test]
fn determinism_contract_default_frx20() {
    let contract = DeterminismContract::default_frx20();
    assert_eq!(contract.schema_version, DETERMINISM_CONTRACT_SCHEMA_VERSION);
    assert!(contract.require_seed);
    assert!(contract.require_seed_transcript_checksum);
    assert!(contract.require_fixed_timezone);
    assert_eq!(contract.timezone, "UTC");
    assert!(contract.require_fixed_locale);
    assert_eq!(contract.lang, "C.UTF-8");
    assert_eq!(contract.lc_all, "C.UTF-8");
    assert!(contract.require_toolchain_fingerprint);
    assert!(contract.require_replay_command);
}

#[test]
fn determinism_contract_serde() {
    let contract = DeterminismContract::default_frx20();
    let json = serde_json::to_string(&contract).unwrap();
    let back: DeterminismContract = serde_json::from_str(&json).unwrap();
    assert_eq!(back, contract);
}

// ===========================================================================
// 5. FixtureRegistryEntry
// ===========================================================================

#[test]
fn fixture_entry_serde() {
    let entry = make_fixture("fix-1", LaneId::Compiler);
    let json = serde_json::to_string(&entry).unwrap();
    let back: FixtureRegistryEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

// ===========================================================================
// 6. LaneCoverageContract
// ===========================================================================

#[test]
fn lane_coverage_serde() {
    let coverage = make_lane_coverage(LaneId::Compiler);
    let json = serde_json::to_string(&coverage).unwrap();
    let back: LaneCoverageContract = serde_json::from_str(&json).unwrap();
    assert_eq!(back, coverage);
}

// ===========================================================================
// 7. TaxonomyValidationError
// ===========================================================================

#[test]
fn error_code_missing_required_field() {
    let err = TaxonomyValidationError::MissingRequiredField {
        field: "test".into(),
    };
    assert!(!err.error_code().is_empty());
    assert!(err.error_code().contains("REGISTRY"));
}

#[test]
fn error_code_invalid_schema_version() {
    let err = TaxonomyValidationError::InvalidSchemaVersion {
        field: "f".into(),
        expected: "e".into(),
        actual: "a".into(),
    };
    assert!(err.error_code().contains("SCHEMA"));
}

#[test]
fn error_code_missing_structured_log_field() {
    let err = TaxonomyValidationError::MissingStructuredLogField {
        fixture_id: "f".into(),
        field: "trace_id".into(),
    };
    assert!(err.error_code().contains("LOGGING"));
}

#[test]
fn error_code_duplicate_fixture_id() {
    let err = TaxonomyValidationError::DuplicateFixtureId {
        fixture_id: "f".into(),
    };
    assert!(err.error_code().contains("REGISTRY"));
}

#[test]
fn error_code_duplicate_lane_coverage() {
    let err = TaxonomyValidationError::DuplicateLaneCoverage { lane: "l".into() };
    assert!(err.error_code().contains("COVERAGE"));
}

#[test]
fn error_code_missing_lane_coverage() {
    let err = TaxonomyValidationError::MissingLaneCoverage { lane: "l".into() };
    assert!(err.error_code().contains("COVERAGE"));
}

#[test]
fn validation_error_serde() {
    let err = TaxonomyValidationError::DuplicateFixtureId {
        fixture_id: "f".into(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: TaxonomyValidationError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

// ===========================================================================
// 8. default_frx20_bundle
// ===========================================================================

#[test]
fn default_bundle_validates() {
    let bundle = default_frx20_bundle();
    assert!(
        bundle.validate_for_gate().is_ok(),
        "default bundle should validate: {:?}",
        bundle.validate_for_gate().err()
    );
}

#[test]
fn default_bundle_has_all_lanes() {
    let bundle = default_frx20_bundle();
    assert_eq!(bundle.lane_coverage.len(), 8);
}

#[test]
fn default_bundle_has_fixtures() {
    let bundle = default_frx20_bundle();
    assert!(!bundle.fixture_registry.is_empty());
}

#[test]
fn default_bundle_schema_versions() {
    let bundle = default_frx20_bundle();
    assert_eq!(bundle.schema_version, UNIT_TEST_TAXONOMY_SCHEMA_VERSION);
    assert_eq!(
        bundle.fixture_registry_schema_version,
        FIXTURE_REGISTRY_SCHEMA_VERSION
    );
}

#[test]
fn default_bundle_serde() {
    let bundle = default_frx20_bundle();
    let json = serde_json::to_string(&bundle).unwrap();
    let back: UnitTestTaxonomyBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(back, bundle);
}

// ===========================================================================
// 9. validate_for_gate — error paths
// ===========================================================================

#[test]
fn validate_wrong_schema_version() {
    let mut bundle = default_frx20_bundle();
    bundle.schema_version = "wrong".into();
    let err = bundle.validate_for_gate().unwrap_err();
    assert!(matches!(
        err,
        TaxonomyValidationError::InvalidSchemaVersion { .. }
    ));
}

#[test]
fn validate_wrong_fixture_registry_schema() {
    let mut bundle = default_frx20_bundle();
    bundle.fixture_registry_schema_version = "wrong".into();
    let err = bundle.validate_for_gate().unwrap_err();
    assert!(matches!(
        err,
        TaxonomyValidationError::InvalidSchemaVersion { .. }
    ));
}

#[test]
fn validate_empty_lane_coverage() {
    let mut bundle = default_frx20_bundle();
    bundle.lane_coverage = vec![];
    let err = bundle.validate_for_gate().unwrap_err();
    assert!(matches!(
        err,
        TaxonomyValidationError::MissingRequiredField { .. }
    ));
}

#[test]
fn validate_missing_lane() {
    let mut bundle = default_frx20_bundle();
    // Remove one lane coverage
    bundle.lane_coverage.retain(|c| c.lane != LaneId::Compiler);
    let err = bundle.validate_for_gate().unwrap_err();
    assert!(matches!(
        err,
        TaxonomyValidationError::MissingLaneCoverage { .. }
    ));
}

#[test]
fn validate_empty_fixture_registry() {
    let mut bundle = default_frx20_bundle();
    bundle.fixture_registry = vec![];
    let err = bundle.validate_for_gate().unwrap_err();
    assert!(matches!(
        err,
        TaxonomyValidationError::MissingRequiredField { .. }
    ));
}

#[test]
fn validate_duplicate_fixture_id() {
    let mut bundle = default_frx20_bundle();
    let dup = bundle.fixture_registry[0].clone();
    bundle.fixture_registry.push(dup);
    let err = bundle.validate_for_gate().unwrap_err();
    assert!(matches!(
        err,
        TaxonomyValidationError::DuplicateFixtureId { .. }
    ));
}

// ===========================================================================
// 10. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_build_validate_serialize() {
    // 1. Build custom bundle
    let bundle = UnitTestTaxonomyBundle {
        schema_version: UNIT_TEST_TAXONOMY_SCHEMA_VERSION.into(),
        fixture_registry_schema_version: FIXTURE_REGISTRY_SCHEMA_VERSION.into(),
        determinism_contract: DeterminismContract::default_frx20(),
        lane_coverage: LaneId::ALL.iter().map(|l| make_lane_coverage(*l)).collect(),
        fixture_registry: vec![
            make_fixture("fix-1", LaneId::Compiler),
            make_fixture("fix-2", LaneId::JsRuntime),
        ],
    };

    // 2. Validate
    assert!(bundle.validate_for_gate().is_ok());

    // 3. Serde round-trip
    let json = serde_json::to_string(&bundle).unwrap();
    let back: UnitTestTaxonomyBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(back, bundle);
}

// ===========================================================================
// 11. UnitTestClass ordering and Clone
// ===========================================================================

#[test]
fn unit_test_class_ordering_declaration() {
    assert!(UnitTestClass::Core < UnitTestClass::Edge);
    assert!(UnitTestClass::Edge < UnitTestClass::Adversarial);
    assert!(UnitTestClass::Adversarial < UnitTestClass::Regression);
    assert!(UnitTestClass::Regression < UnitTestClass::FaultInjection);
}

#[test]
fn unit_test_class_clone_eq() {
    for c in &UnitTestClass::ALL {
        let cloned = *c;
        assert_eq!(*c, cloned);
    }
}

#[test]
fn unit_test_class_serde_snake_case_format() {
    let json = serde_json::to_string(&UnitTestClass::FaultInjection).unwrap();
    assert_eq!(json, "\"fault_injection\"");
    let json2 = serde_json::to_string(&UnitTestClass::Core).unwrap();
    assert_eq!(json2, "\"core\"");
}

// ===========================================================================
// 12. LaneId ordering and Clone
// ===========================================================================

#[test]
fn lane_id_ordering_declaration() {
    assert!(LaneId::Compiler < LaneId::JsRuntime);
    assert!(LaneId::JsRuntime < LaneId::WasmRuntime);
    assert!(LaneId::WasmRuntime < LaneId::HybridRouter);
    assert!(LaneId::HybridRouter < LaneId::Verification);
    assert!(LaneId::Verification < LaneId::Toolchain);
    assert!(LaneId::Toolchain < LaneId::GovernanceEvidence);
    assert!(LaneId::GovernanceEvidence < LaneId::AdoptionRelease);
}

#[test]
fn lane_id_clone_eq() {
    for l in &LaneId::ALL {
        let cloned = *l;
        assert_eq!(*l, cloned);
    }
}

// ===========================================================================
// 13. DeterminismContract — custom fields
// ===========================================================================

#[test]
fn determinism_contract_custom_fields_serde() {
    let contract = DeterminismContract {
        schema_version: DETERMINISM_CONTRACT_SCHEMA_VERSION.into(),
        require_seed: false,
        require_seed_transcript_checksum: false,
        require_fixed_timezone: false,
        timezone: String::new(),
        require_fixed_locale: false,
        lang: String::new(),
        lc_all: String::new(),
        require_toolchain_fingerprint: false,
        require_replay_command: false,
    };
    let json = serde_json::to_string(&contract).unwrap();
    let back: DeterminismContract = serde_json::from_str(&json).unwrap();
    assert_eq!(back, contract);
    assert!(!back.require_seed);
}

// ===========================================================================
// 14. FixtureRegistryEntry — None trace_path
// ===========================================================================

#[test]
fn fixture_entry_none_trace_path_serde() {
    let mut entry = make_fixture("no-trace", LaneId::Toolchain);
    entry.trace_path = None;
    let json = serde_json::to_string(&entry).unwrap();
    let back: FixtureRegistryEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.trace_path, None);
    assert_eq!(back.fixture_id, "no-trace");
}

// ===========================================================================
// 15. Validation error — all variants serde roundtrip
// ===========================================================================

#[test]
fn all_error_variants_serde_roundtrip() {
    let variants = vec![
        TaxonomyValidationError::MissingRequiredField { field: "f".into() },
        TaxonomyValidationError::InvalidSchemaVersion {
            field: "sv".into(),
            expected: "v1".into(),
            actual: "v0".into(),
        },
        TaxonomyValidationError::MissingStructuredLogField {
            fixture_id: "fix1".into(),
            field: "trace_id".into(),
        },
        TaxonomyValidationError::DuplicateFixtureId {
            fixture_id: "dup".into(),
        },
        TaxonomyValidationError::DuplicateLaneCoverage {
            lane: "compiler".into(),
        },
        TaxonomyValidationError::MissingLaneCoverage {
            lane: "wasm".into(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: TaxonomyValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, v);
    }
}

// ===========================================================================
// 16. Validate — duplicate lane coverage
// ===========================================================================

#[test]
fn validate_duplicate_lane_coverage() {
    let mut bundle = default_frx20_bundle();
    let dup = bundle.lane_coverage[0].clone();
    bundle.lane_coverage.push(dup);
    let err = bundle.validate_for_gate().unwrap_err();
    assert!(matches!(
        err,
        TaxonomyValidationError::DuplicateLaneCoverage { .. }
    ));
}

// ===========================================================================
// 17. Validate — determinism contract schema propagated through bundle
// ===========================================================================

#[test]
fn validate_determinism_contract_schema_propagates() {
    let mut bundle = default_frx20_bundle();
    bundle.determinism_contract.schema_version = "wrong".into();
    let err = bundle.validate_for_gate().unwrap_err();
    assert!(matches!(
        err,
        TaxonomyValidationError::InvalidSchemaVersion { .. }
    ));
}

// ===========================================================================
// 18. default_frx20_bundle — structural assertions
// ===========================================================================

#[test]
fn default_bundle_fixtures_all_have_required_classes() {
    let bundle = default_frx20_bundle();
    for fixture in &bundle.fixture_registry {
        assert!(
            !fixture.required_classes.is_empty(),
            "fixture {} has no required_classes",
            fixture.fixture_id
        );
    }
}

#[test]
fn default_bundle_lane_coverages_have_e2e_families() {
    let bundle = default_frx20_bundle();
    for lc in &bundle.lane_coverage {
        assert!(
            !lc.mapped_e2e_families.is_empty(),
            "lane {:?} has no mapped_e2e_families",
            lc.lane
        );
    }
}

#[test]
fn default_bundle_fixture_ids_unique() {
    let bundle = default_frx20_bundle();
    let mut seen = std::collections::BTreeSet::new();
    for fixture in &bundle.fixture_registry {
        assert!(
            seen.insert(&fixture.fixture_id),
            "duplicate fixture_id: {}",
            fixture.fixture_id
        );
    }
}

#[test]
fn required_log_fields_count() {
    assert_eq!(REQUIRED_STRUCTURED_LOG_FIELDS.len(), 12);
}

#[test]
fn validate_fixture_missing_structured_log_field() {
    let mut bundle = default_frx20_bundle();
    bundle.fixture_registry[0]
        .structured_log_fields
        .retain(|f| f != "seed");
    let err = bundle.validate_for_gate().unwrap_err();
    assert!(matches!(
        err,
        TaxonomyValidationError::MissingStructuredLogField { .. }
    ));
}
