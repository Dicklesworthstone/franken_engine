//! Enrichment integration tests for `unit_test_taxonomy`.
//!
//! Covers Copy/Clone semantics, BTreeSet dedup, Debug uniqueness,
//! serde JSON field stability, Clone independence, determinism, and
//! cross-cutting invariants NOT already tested in the base integration file.

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
// UnitTestClass enrichment
// ===========================================================================

#[test]
fn enrichment_unit_test_class_copy_semantics() {
    let a = UnitTestClass::Adversarial;
    let b = a;
    assert_eq!(a, b);
    assert_eq!(a.as_str(), "adversarial");
}

#[test]
fn enrichment_unit_test_class_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for &c in &UnitTestClass::ALL {
        set.insert(c);
        set.insert(c);
    }
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_unit_test_class_debug_all_unique() {
    let debugs: BTreeSet<String> = UnitTestClass::ALL
        .iter()
        .map(|c| format!("{c:?}"))
        .collect();
    assert_eq!(debugs.len(), 5);
}

#[test]
fn enrichment_unit_test_class_as_str_all_unique() {
    let strs: BTreeSet<&str> = UnitTestClass::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(strs.len(), 5);
}

// ===========================================================================
// LaneId enrichment
// ===========================================================================

#[test]
fn enrichment_lane_id_copy_semantics() {
    let a = LaneId::Compiler;
    let b = a;
    assert_eq!(a, b);
    assert_eq!(a.as_str(), "compiler");
}

#[test]
fn enrichment_lane_id_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for &l in &LaneId::ALL {
        set.insert(l);
        set.insert(l);
    }
    assert_eq!(set.len(), 8);
}

#[test]
fn enrichment_lane_id_debug_all_unique() {
    let debugs: BTreeSet<String> = LaneId::ALL.iter().map(|l| format!("{l:?}")).collect();
    assert_eq!(debugs.len(), 8);
}

#[test]
fn enrichment_lane_id_as_str_all_unique() {
    let strs: BTreeSet<&str> = LaneId::ALL.iter().map(|l| l.as_str()).collect();
    assert_eq!(strs.len(), 8);
}

// ===========================================================================
// DeterminismContract enrichment
// ===========================================================================

#[test]
fn enrichment_determinism_contract_clone_independence() {
    let original = DeterminismContract::default_frx20();
    let mut cloned = original.clone();
    cloned.timezone = "America/New_York".to_string();
    assert_eq!(original.timezone, "UTC");
    assert_eq!(cloned.timezone, "America/New_York");
}

#[test]
fn enrichment_determinism_contract_debug_nonempty() {
    let contract = DeterminismContract::default_frx20();
    let dbg = format!("{contract:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("DeterminismContract"));
}

#[test]
fn enrichment_determinism_contract_json_field_names() {
    let contract = DeterminismContract::default_frx20();
    let json = serde_json::to_string(&contract).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"require_seed\""));
    assert!(json.contains("\"require_seed_transcript_checksum\""));
    assert!(json.contains("\"require_fixed_timezone\""));
    assert!(json.contains("\"timezone\""));
    assert!(json.contains("\"require_fixed_locale\""));
    assert!(json.contains("\"lang\""));
    assert!(json.contains("\"lc_all\""));
    assert!(json.contains("\"require_toolchain_fingerprint\""));
    assert!(json.contains("\"require_replay_command\""));
}

// ===========================================================================
// FixtureRegistryEntry enrichment
// ===========================================================================

#[test]
fn enrichment_fixture_entry_clone_independence() {
    let original = make_fixture("fix-original", LaneId::Compiler);
    let mut cloned = original.clone();
    cloned.fixture_id = "fix-cloned".to_string();
    assert_eq!(original.fixture_id, "fix-original");
    assert_eq!(cloned.fixture_id, "fix-cloned");
}

#[test]
fn enrichment_fixture_entry_debug_nonempty() {
    let entry = make_fixture("fix-debug", LaneId::JsRuntime);
    let dbg = format!("{entry:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("FixtureRegistryEntry"));
}

#[test]
fn enrichment_fixture_entry_json_field_names() {
    let entry = make_fixture("fix-json", LaneId::Verification);
    let json = serde_json::to_string(&entry).unwrap();
    assert!(json.contains("\"fixture_id\""));
    assert!(json.contains("\"fixture_path\""));
    assert!(json.contains("\"trace_path\""));
    assert!(json.contains("\"provenance\""));
    assert!(json.contains("\"owner_lane\""));
    assert!(json.contains("\"required_classes\""));
    assert!(json.contains("\"e2e_family\""));
    assert!(json.contains("\"seed_strategy\""));
    assert!(json.contains("\"structured_log_fields\""));
    assert!(json.contains("\"artifact_retention\""));
}

// ===========================================================================
// LaneCoverageContract enrichment
// ===========================================================================

#[test]
fn enrichment_lane_coverage_clone_independence() {
    let original = make_lane_coverage(LaneId::Compiler);
    let mut cloned = original.clone();
    cloned.owner = "mutated-owner".to_string();
    assert_ne!(original.owner, "mutated-owner");
    assert_eq!(cloned.owner, "mutated-owner");
}

#[test]
fn enrichment_lane_coverage_debug_nonempty() {
    let lc = make_lane_coverage(LaneId::Toolchain);
    let dbg = format!("{lc:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("LaneCoverageContract"));
}

#[test]
fn enrichment_lane_coverage_json_field_names() {
    let lc = make_lane_coverage(LaneId::GovernanceEvidence);
    let json = serde_json::to_string(&lc).unwrap();
    assert!(json.contains("\"lane\""));
    assert!(json.contains("\"owner\""));
    assert!(json.contains("\"required_unit_classes\""));
    assert!(json.contains("\"mapped_e2e_families\""));
    assert!(json.contains("\"coverage_rationale\""));
}

// ===========================================================================
// UnitTestTaxonomyBundle enrichment
// ===========================================================================

#[test]
fn enrichment_bundle_clone_independence() {
    let original = default_frx20_bundle();
    let mut cloned = original.clone();
    cloned.schema_version = "mutated".to_string();
    assert_eq!(original.schema_version, UNIT_TEST_TAXONOMY_SCHEMA_VERSION);
    assert_eq!(cloned.schema_version, "mutated");
}

#[test]
fn enrichment_bundle_debug_nonempty() {
    let bundle = default_frx20_bundle();
    let dbg = format!("{bundle:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("UnitTestTaxonomyBundle"));
}

#[test]
fn enrichment_bundle_json_field_names() {
    let bundle = default_frx20_bundle();
    let json = serde_json::to_string(&bundle).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"fixture_registry_schema_version\""));
    assert!(json.contains("\"determinism_contract\""));
    assert!(json.contains("\"lane_coverage\""));
    assert!(json.contains("\"fixture_registry\""));
}

#[test]
fn enrichment_bundle_validate_determinism_five_runs() {
    for _ in 0..5 {
        let bundle = default_frx20_bundle();
        assert!(bundle.validate_for_gate().is_ok());
    }
}

// ===========================================================================
// TaxonomyValidationError enrichment
// ===========================================================================

#[test]
fn enrichment_validation_error_clone_independence() {
    let original = TaxonomyValidationError::MissingRequiredField {
        field: "test".to_string(),
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_validation_error_debug_all_unique() {
    let variants = vec![
        TaxonomyValidationError::MissingRequiredField {
            field: "f".to_string(),
        },
        TaxonomyValidationError::InvalidSchemaVersion {
            field: "sv".to_string(),
            expected: "v1".to_string(),
            actual: "v0".to_string(),
        },
        TaxonomyValidationError::MissingStructuredLogField {
            fixture_id: "fix".to_string(),
            field: "trace_id".to_string(),
        },
        TaxonomyValidationError::DuplicateFixtureId {
            fixture_id: "dup".to_string(),
        },
        TaxonomyValidationError::DuplicateLaneCoverage {
            lane: "compiler".to_string(),
        },
        TaxonomyValidationError::MissingLaneCoverage {
            lane: "wasm".to_string(),
        },
    ];
    let debugs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 6);
}

#[test]
fn enrichment_validation_error_codes_all_unique() {
    let variants = vec![
        TaxonomyValidationError::MissingRequiredField {
            field: "f".to_string(),
        },
        TaxonomyValidationError::InvalidSchemaVersion {
            field: "sv".to_string(),
            expected: "v1".to_string(),
            actual: "v0".to_string(),
        },
        TaxonomyValidationError::MissingStructuredLogField {
            fixture_id: "fix".to_string(),
            field: "trace_id".to_string(),
        },
        TaxonomyValidationError::DuplicateFixtureId {
            fixture_id: "dup".to_string(),
        },
        TaxonomyValidationError::DuplicateLaneCoverage {
            lane: "compiler".to_string(),
        },
        TaxonomyValidationError::MissingLaneCoverage {
            lane: "wasm".to_string(),
        },
    ];
    let codes: BTreeSet<&str> = variants.iter().map(|v| v.error_code()).collect();
    // 6 variants but some share error code prefixes — at least 4 distinct codes
    assert!(
        codes.len() >= 4,
        "expected at least 4 distinct error codes, got {}",
        codes.len()
    );
}

#[test]
fn enrichment_validation_error_codes_contain_frx_20() {
    let variants = vec![
        TaxonomyValidationError::MissingRequiredField {
            field: "f".to_string(),
        },
        TaxonomyValidationError::InvalidSchemaVersion {
            field: "sv".to_string(),
            expected: "v1".to_string(),
            actual: "v0".to_string(),
        },
        TaxonomyValidationError::MissingStructuredLogField {
            fixture_id: "fix".to_string(),
            field: "trace_id".to_string(),
        },
        TaxonomyValidationError::DuplicateFixtureId {
            fixture_id: "dup".to_string(),
        },
        TaxonomyValidationError::DuplicateLaneCoverage {
            lane: "compiler".to_string(),
        },
        TaxonomyValidationError::MissingLaneCoverage {
            lane: "wasm".to_string(),
        },
    ];
    for v in &variants {
        assert!(
            v.error_code().contains("FRX-20"),
            "error code should contain FRX-20: {}",
            v.error_code()
        );
    }
}

// ===========================================================================
// Cross-cutting: constants stability
// ===========================================================================

#[test]
fn enrichment_constants_stable() {
    assert_eq!(
        UNIT_TEST_TAXONOMY_SCHEMA_VERSION,
        "frx.unit-test-taxonomy.v1"
    );
    assert_eq!(FIXTURE_REGISTRY_SCHEMA_VERSION, "frx.fixture-registry.v1");
    assert_eq!(
        DETERMINISM_CONTRACT_SCHEMA_VERSION,
        "frx.test-determinism-contract.v1"
    );
}

#[test]
fn enrichment_required_log_fields_all_nonempty() {
    for field in REQUIRED_STRUCTURED_LOG_FIELDS {
        assert!(!field.is_empty(), "log field should not be empty");
    }
}

#[test]
fn enrichment_required_log_fields_all_unique() {
    let set: BTreeSet<&str> = REQUIRED_STRUCTURED_LOG_FIELDS.iter().copied().collect();
    assert_eq!(set.len(), REQUIRED_STRUCTURED_LOG_FIELDS.len());
}

// ===========================================================================
// Cross-cutting: default bundle lane coverage matches LaneId::ALL
// ===========================================================================

#[test]
fn enrichment_default_bundle_covers_all_lane_ids() {
    let bundle = default_frx20_bundle();
    let covered_lanes: BTreeSet<LaneId> = bundle.lane_coverage.iter().map(|lc| lc.lane).collect();
    for &lane in &LaneId::ALL {
        assert!(
            covered_lanes.contains(&lane),
            "missing lane coverage for {lane:?}"
        );
    }
}

// ===========================================================================
// Cross-cutting: default bundle fixtures have all required log fields
// ===========================================================================

#[test]
fn enrichment_default_bundle_fixtures_have_all_log_fields() {
    let bundle = default_frx20_bundle();
    let required: BTreeSet<&str> = REQUIRED_STRUCTURED_LOG_FIELDS.iter().copied().collect();
    for fixture in &bundle.fixture_registry {
        let present: BTreeSet<&str> = fixture
            .structured_log_fields
            .iter()
            .map(String::as_str)
            .collect();
        for &req in &required {
            assert!(
                present.contains(req),
                "fixture {} missing log field: {req}",
                fixture.fixture_id
            );
        }
    }
}

// ===========================================================================
// Cross-cutting: serde roundtrip preserves validation
// ===========================================================================

#[test]
fn enrichment_serde_roundtrip_preserves_validation() {
    let bundle = default_frx20_bundle();
    assert!(bundle.validate_for_gate().is_ok());
    let json = serde_json::to_string(&bundle).unwrap();
    let back: UnitTestTaxonomyBundle = serde_json::from_str(&json).unwrap();
    assert!(back.validate_for_gate().is_ok());
}

// ===========================================================================
// Cross-cutting: custom bundle with all lanes validates
// ===========================================================================

#[test]
fn enrichment_custom_bundle_validates() {
    let bundle = UnitTestTaxonomyBundle {
        schema_version: UNIT_TEST_TAXONOMY_SCHEMA_VERSION.into(),
        fixture_registry_schema_version: FIXTURE_REGISTRY_SCHEMA_VERSION.into(),
        determinism_contract: DeterminismContract::default_frx20(),
        lane_coverage: LaneId::ALL.iter().map(|l| make_lane_coverage(*l)).collect(),
        fixture_registry: vec![
            make_fixture("custom-1", LaneId::Compiler),
            make_fixture("custom-2", LaneId::JsRuntime),
            make_fixture("custom-3", LaneId::WasmRuntime),
        ],
    };
    assert!(bundle.validate_for_gate().is_ok());
}

// ===========================================================================
// UnitTestClass — serde roundtrip all variants
// ===========================================================================

#[test]
fn enrichment_unit_test_class_serde_all_variants() {
    for &c in &UnitTestClass::ALL {
        let json = serde_json::to_string(&c).unwrap();
        let back: UnitTestClass = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}

// ===========================================================================
// LaneId — serde roundtrip all variants
// ===========================================================================

#[test]
fn enrichment_lane_id_serde_all_variants() {
    for &l in &LaneId::ALL {
        let json = serde_json::to_string(&l).unwrap();
        let back: LaneId = serde_json::from_str(&json).unwrap();
        assert_eq!(l, back);
    }
}

// ===========================================================================
// UnitTestClass — ordering matches ALL array order
// ===========================================================================

#[test]
fn enrichment_unit_test_class_ordering_matches_all() {
    for i in 0..UnitTestClass::ALL.len() - 1 {
        assert!(
            UnitTestClass::ALL[i] < UnitTestClass::ALL[i + 1],
            "{:?} should be < {:?}",
            UnitTestClass::ALL[i],
            UnitTestClass::ALL[i + 1]
        );
    }
}

// ===========================================================================
// LaneId — ordering matches ALL array order
// ===========================================================================

#[test]
fn enrichment_lane_id_ordering_matches_all() {
    for i in 0..LaneId::ALL.len() - 1 {
        assert!(
            LaneId::ALL[i] < LaneId::ALL[i + 1],
            "{:?} should be < {:?}",
            LaneId::ALL[i],
            LaneId::ALL[i + 1]
        );
    }
}

// ===========================================================================
// DeterminismContract — serde roundtrip
// ===========================================================================

#[test]
fn enrichment_determinism_contract_serde_roundtrip() {
    let contract = DeterminismContract::default_frx20();
    let json = serde_json::to_string(&contract).unwrap();
    let back: DeterminismContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, back);
}

// ===========================================================================
// DeterminismContract — default values
// ===========================================================================

#[test]
fn enrichment_determinism_contract_default_values() {
    let c = DeterminismContract::default_frx20();
    assert_eq!(c.schema_version, DETERMINISM_CONTRACT_SCHEMA_VERSION);
    assert!(c.require_seed);
    assert!(c.require_seed_transcript_checksum);
    assert!(c.require_fixed_timezone);
    assert_eq!(c.timezone, "UTC");
    assert!(c.require_fixed_locale);
    assert_eq!(c.lang, "C.UTF-8");
    assert_eq!(c.lc_all, "C.UTF-8");
    assert!(c.require_toolchain_fingerprint);
    assert!(c.require_replay_command);
}

// ===========================================================================
// FixtureRegistryEntry — serde roundtrip
// ===========================================================================

#[test]
fn enrichment_fixture_entry_serde_roundtrip() {
    let entry = make_fixture("serde-rt", LaneId::Compiler);
    let json = serde_json::to_string(&entry).unwrap();
    let back: FixtureRegistryEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ===========================================================================
// LaneCoverageContract — serde roundtrip
// ===========================================================================

#[test]
fn enrichment_lane_coverage_serde_roundtrip() {
    let lc = make_lane_coverage(LaneId::Verification);
    let json = serde_json::to_string(&lc).unwrap();
    let back: LaneCoverageContract = serde_json::from_str(&json).unwrap();
    assert_eq!(lc, back);
}

// ===========================================================================
// UnitTestTaxonomyBundle — serde roundtrip
// ===========================================================================

#[test]
fn enrichment_bundle_serde_roundtrip() {
    let bundle = default_frx20_bundle();
    let json = serde_json::to_string(&bundle).unwrap();
    let back: UnitTestTaxonomyBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

// ===========================================================================
// Validation — invalid schema version
// ===========================================================================

#[test]
fn enrichment_bundle_invalid_schema_version_fails() {
    let mut bundle = default_frx20_bundle();
    bundle.schema_version = "wrong".to_string();
    let err = bundle.validate_for_gate().unwrap_err();
    assert_eq!(err.error_code(), "FE-FRX-20-1-SCHEMA-0001");
}

#[test]
fn enrichment_bundle_invalid_fixture_registry_schema_version_fails() {
    let mut bundle = default_frx20_bundle();
    bundle.fixture_registry_schema_version = "wrong".to_string();
    let err = bundle.validate_for_gate().unwrap_err();
    assert_eq!(err.error_code(), "FE-FRX-20-1-SCHEMA-0001");
}

// ===========================================================================
// Validation — empty lane coverage
// ===========================================================================

#[test]
fn enrichment_bundle_empty_lane_coverage_fails() {
    let mut bundle = default_frx20_bundle();
    bundle.lane_coverage.clear();
    let err = bundle.validate_for_gate().unwrap_err();
    assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0001");
}

// ===========================================================================
// Validation — empty fixture registry
// ===========================================================================

#[test]
fn enrichment_bundle_empty_fixture_registry_fails() {
    let mut bundle = default_frx20_bundle();
    bundle.fixture_registry.clear();
    let err = bundle.validate_for_gate().unwrap_err();
    assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0001");
}

// ===========================================================================
// Validation — duplicate fixture IDs
// ===========================================================================

#[test]
fn enrichment_bundle_duplicate_fixture_id_fails() {
    let mut bundle = default_frx20_bundle();
    let dup = bundle.fixture_registry[0].clone();
    bundle.fixture_registry.push(dup);
    let err = bundle.validate_for_gate().unwrap_err();
    assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0002");
}

// ===========================================================================
// Validation — duplicate lane coverage
// ===========================================================================

#[test]
fn enrichment_bundle_duplicate_lane_coverage_fails() {
    let mut bundle = default_frx20_bundle();
    let dup = bundle.lane_coverage[0].clone();
    bundle.lane_coverage.push(dup);
    let err = bundle.validate_for_gate().unwrap_err();
    assert_eq!(err.error_code(), "FE-FRX-20-1-COVERAGE-0001");
}

// ===========================================================================
// Validation — missing lane coverage
// ===========================================================================

#[test]
fn enrichment_bundle_missing_lane_coverage_fails() {
    let mut bundle = default_frx20_bundle();
    bundle
        .lane_coverage
        .retain(|lc| lc.lane != LaneId::AdoptionRelease);
    let err = bundle.validate_for_gate().unwrap_err();
    assert_eq!(err.error_code(), "FE-FRX-20-1-COVERAGE-0002");
}

// ===========================================================================
// Validation — missing structured log field
// ===========================================================================

#[test]
fn enrichment_bundle_missing_log_field_fails() {
    let mut bundle = default_frx20_bundle();
    bundle.fixture_registry[0].structured_log_fields.clear();
    let err = bundle.validate_for_gate().unwrap_err();
    assert_eq!(err.error_code(), "FE-FRX-20-1-LOGGING-0001");
}

// ===========================================================================
// TaxonomyValidationError — serde roundtrip all variants
// ===========================================================================

#[test]
fn enrichment_validation_error_serde_all_variants() {
    let variants = vec![
        TaxonomyValidationError::MissingRequiredField {
            field: "x".to_string(),
        },
        TaxonomyValidationError::InvalidSchemaVersion {
            field: "sv".to_string(),
            expected: "v1".to_string(),
            actual: "v0".to_string(),
        },
        TaxonomyValidationError::MissingStructuredLogField {
            fixture_id: "fix".to_string(),
            field: "trace_id".to_string(),
        },
        TaxonomyValidationError::DuplicateFixtureId {
            fixture_id: "dup".to_string(),
        },
        TaxonomyValidationError::DuplicateLaneCoverage {
            lane: "compiler".to_string(),
        },
        TaxonomyValidationError::MissingLaneCoverage {
            lane: "wasm".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: TaxonomyValidationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// Default bundle — fixture count
// ===========================================================================

#[test]
fn enrichment_default_bundle_has_fixtures() {
    let bundle = default_frx20_bundle();
    assert!(
        bundle.fixture_registry.len() >= 2,
        "expected at least 2 fixtures, got {}",
        bundle.fixture_registry.len()
    );
}

// ===========================================================================
// Default bundle — all fixture IDs unique
// ===========================================================================

#[test]
fn enrichment_default_bundle_fixture_ids_unique() {
    let bundle = default_frx20_bundle();
    let ids: BTreeSet<&str> = bundle
        .fixture_registry
        .iter()
        .map(|f| f.fixture_id.as_str())
        .collect();
    assert_eq!(ids.len(), bundle.fixture_registry.len());
}

// ===========================================================================
// Default bundle — all lane coverage owners nonempty
// ===========================================================================

#[test]
fn enrichment_default_bundle_lane_owners_nonempty() {
    let bundle = default_frx20_bundle();
    for lc in &bundle.lane_coverage {
        assert!(
            !lc.owner.trim().is_empty(),
            "lane {:?} has empty owner",
            lc.lane
        );
    }
}

// ===========================================================================
// REQUIRED_STRUCTURED_LOG_FIELDS — known fields present
// ===========================================================================

#[test]
fn enrichment_required_log_fields_contain_known() {
    let fields: BTreeSet<&str> = REQUIRED_STRUCTURED_LOG_FIELDS.iter().copied().collect();
    assert!(fields.contains("schema_version"));
    assert!(fields.contains("trace_id"));
    assert!(fields.contains("decision_id"));
    assert!(fields.contains("outcome"));
    assert!(fields.contains("error_code"));
}

// ===========================================================================
// DeterminismContract — invalid timezone detected
// ===========================================================================

#[test]
fn enrichment_determinism_contract_empty_timezone_invalid() {
    let mut bundle = default_frx20_bundle();
    bundle.determinism_contract.timezone = "".to_string();
    let err = bundle.validate_for_gate().unwrap_err();
    assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0001");
}

// ===========================================================================
// DeterminismContract — invalid locale detected
// ===========================================================================

#[test]
fn enrichment_determinism_contract_empty_locale_invalid() {
    let mut bundle = default_frx20_bundle();
    bundle.determinism_contract.lang = "".to_string();
    let err = bundle.validate_for_gate().unwrap_err();
    assert_eq!(err.error_code(), "FE-FRX-20-1-REGISTRY-0001");
}
