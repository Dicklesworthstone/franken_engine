//! Edge-case integration tests for `cross_repo_contract`.
//!
//! Covers: RegressionClass, ContractViolation, SchemaContract, FieldType,
//! verify_structured_log, verify_error_code_format, verify_deterministic_serde,
//! verify_schema_compliance, VersionCompatibilityEntry, ContractSuiteResult,
//! boundary contract builders, integration_point_inventory,
//! version_compatibility_registry.

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

use frankenengine_engine::cross_repo_contract::{
    ContractSuiteResult, ContractViolation, FieldType, RegressionClass, SchemaContract,
    VersionCompatibilityEntry, fastapi_endpoint_response_contract,
    frankensqlite_migration_receipt_contract, frankensqlite_storage_event_contract,
    frankensqlite_store_record_contract, frankentui_envelope_contract, integration_point_inventory,
    verify_deterministic_serde, verify_error_code_format, verify_schema_compliance,
    verify_structured_log, version_compatibility_registry,
};
use std::collections::{BTreeMap, BTreeSet};

// ── RegressionClass ─────────────────────────────────────────────────────────

#[test]
fn regression_class_copy_semantics() {
    let a = RegressionClass::Breaking;
    let b = a; // Copy
    assert_eq!(a, b);
}

#[test]
fn regression_class_serde_all_four_stable_strings() {
    let pairs = [
        (RegressionClass::Breaking, "\"Breaking\""),
        (RegressionClass::Behavioral, "\"Behavioral\""),
        (RegressionClass::Observability, "\"Observability\""),
        (RegressionClass::Performance, "\"Performance\""),
    ];
    for (class, expected) in &pairs {
        let json = serde_json::to_string(class).unwrap();
        assert_eq!(&json, expected);
        let back: RegressionClass = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *class);
    }
}

#[test]
fn regression_class_ordering_exhaustive() {
    let sorted = [
        RegressionClass::Breaking,
        RegressionClass::Behavioral,
        RegressionClass::Observability,
        RegressionClass::Performance,
    ];
    for i in 0..sorted.len() {
        for j in (i + 1)..sorted.len() {
            assert!(
                sorted[i] < sorted[j],
                "{:?} should be < {:?}",
                sorted[i],
                sorted[j]
            );
        }
    }
}

#[test]
fn regression_class_display_all_uppercase() {
    let classes = [
        (RegressionClass::Breaking, "BREAKING"),
        (RegressionClass::Behavioral, "BEHAVIORAL"),
        (RegressionClass::Observability, "OBSERVABILITY"),
        (RegressionClass::Performance, "PERFORMANCE"),
    ];
    for (class, expected) in &classes {
        assert_eq!(class.to_string(), *expected);
    }
}

// ── FieldType ───────────────────────────────────────────────────────────────

#[test]
fn field_type_ordering_all_six() {
    let sorted = [
        FieldType::String,
        FieldType::Number,
        FieldType::Bool,
        FieldType::Array,
        FieldType::Object,
        FieldType::Null,
    ];
    for i in 0..sorted.len() {
        for j in (i + 1)..sorted.len() {
            assert!(
                sorted[i] < sorted[j],
                "{:?} should be < {:?}",
                sorted[i],
                sorted[j]
            );
        }
    }
}

#[test]
fn field_type_serde_all_six() {
    let types = [
        FieldType::String,
        FieldType::Number,
        FieldType::Bool,
        FieldType::Array,
        FieldType::Object,
        FieldType::Null,
    ];
    for ft in &types {
        let json = serde_json::to_string(ft).unwrap();
        let back: FieldType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, *ft);
    }
}

#[test]
fn field_type_display_all_six_lowercase() {
    let pairs = [
        (FieldType::String, "string"),
        (FieldType::Number, "number"),
        (FieldType::Bool, "bool"),
        (FieldType::Array, "array"),
        (FieldType::Object, "object"),
        (FieldType::Null, "null"),
    ];
    for (ft, expected) in &pairs {
        assert_eq!(ft.to_string(), *expected);
    }
}

#[test]
fn field_type_copy_semantics() {
    let a = FieldType::Object;
    let b = a;
    assert_eq!(a, b);
}

// ── ContractViolation ───────────────────────────────────────────────────────

#[test]
fn contract_violation_serde_round_trip() {
    let v = ContractViolation {
        boundary: "test-boundary".to_string(),
        contract_name: "TestType".to_string(),
        regression_class: RegressionClass::Observability,
        detail: "test detail".to_string(),
    };
    verify_deterministic_serde(&v).unwrap();
}

#[test]
fn contract_violation_display_format() {
    let v = ContractViolation {
        boundary: "b".to_string(),
        contract_name: "C".to_string(),
        regression_class: RegressionClass::Performance,
        detail: "slow".to_string(),
    };
    let s = v.to_string();
    assert!(s.contains("PERFORMANCE"));
    assert!(s.contains("b/C"));
    assert!(s.contains("slow"));
}

#[test]
fn contract_violation_display_with_all_regression_classes() {
    for class in [
        RegressionClass::Breaking,
        RegressionClass::Behavioral,
        RegressionClass::Observability,
        RegressionClass::Performance,
    ] {
        let v = ContractViolation {
            boundary: "x".to_string(),
            contract_name: "Y".to_string(),
            regression_class: class,
            detail: "d".to_string(),
        };
        let s = v.to_string();
        assert!(
            s.contains(&class.to_string()),
            "display must contain class name"
        );
    }
}

#[test]
fn contract_violation_empty_strings() {
    let v = ContractViolation {
        boundary: String::new(),
        contract_name: String::new(),
        regression_class: RegressionClass::Breaking,
        detail: String::new(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: ContractViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(back.boundary, "");
    assert_eq!(back.contract_name, "");
    assert_eq!(back.detail, "");
}

// ── SchemaContract ──────────────────────────────────────────────────────────

#[test]
fn schema_contract_verify_non_object_json() {
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "Test".to_string(),
        required_fields: BTreeSet::new(),
        field_types: BTreeMap::new(),
    };
    // Array
    let violations = contract.verify(&serde_json::json!([1, 2, 3]));
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].regression_class, RegressionClass::Breaking);
    assert!(violations[0].detail.contains("expected JSON object"));

    // String
    let violations = contract.verify(&serde_json::json!("hello"));
    assert_eq!(violations.len(), 1);

    // Number
    let violations = contract.verify(&serde_json::json!(42));
    assert_eq!(violations.len(), 1);

    // Boolean
    let violations = contract.verify(&serde_json::json!(true));
    assert_eq!(violations.len(), 1);

    // Null
    let violations = contract.verify(&serde_json::json!(null));
    assert_eq!(violations.len(), 1);
}

#[test]
fn schema_contract_empty_object_no_requirements() {
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "Test".to_string(),
        required_fields: BTreeSet::new(),
        field_types: BTreeMap::new(),
    };
    let violations = contract.verify(&serde_json::json!({}));
    assert!(violations.is_empty());
}

#[test]
fn schema_contract_all_fields_present_passes() {
    let mut required = BTreeSet::new();
    required.insert("a".to_string());
    required.insert("b".to_string());
    let mut types = BTreeMap::new();
    types.insert("a".to_string(), FieldType::String);
    types.insert("b".to_string(), FieldType::Number);

    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "Test".to_string(),
        required_fields: required,
        field_types: types,
    };
    let violations = contract.verify(&serde_json::json!({"a": "hello", "b": 42}));
    assert!(violations.is_empty());
}

#[test]
fn schema_contract_null_field_accepted_for_typed_field() {
    let mut types = BTreeMap::new();
    types.insert("x".to_string(), FieldType::String);

    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "Test".to_string(),
        required_fields: BTreeSet::new(),
        field_types: types,
    };
    // null is accepted (skipped) even when type says String
    let violations = contract.verify(&serde_json::json!({"x": null}));
    assert!(violations.is_empty());
}

#[test]
fn schema_contract_extra_fields_allowed() {
    let mut required = BTreeSet::new();
    required.insert("a".to_string());
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "Test".to_string(),
        required_fields: required,
        field_types: BTreeMap::new(),
    };
    let violations = contract.verify(&serde_json::json!({"a": 1, "extra1": "x", "extra2": true}));
    assert!(violations.is_empty());
}

#[test]
fn schema_contract_multiple_missing_fields() {
    let mut required = BTreeSet::new();
    required.insert("alpha".to_string());
    required.insert("beta".to_string());
    required.insert("gamma".to_string());
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "Test".to_string(),
        required_fields: required,
        field_types: BTreeMap::new(),
    };
    let violations = contract.verify(&serde_json::json!({}));
    assert_eq!(violations.len(), 3);
    let fields: BTreeSet<String> = violations.iter().map(|v| v.detail.clone()).collect();
    assert!(fields.iter().any(|d| d.contains("alpha")));
    assert!(fields.iter().any(|d| d.contains("beta")));
    assert!(fields.iter().any(|d| d.contains("gamma")));
}

#[test]
fn schema_contract_multiple_wrong_types() {
    let mut types = BTreeMap::new();
    types.insert("name".to_string(), FieldType::String);
    types.insert("count".to_string(), FieldType::Number);
    types.insert("active".to_string(), FieldType::Bool);
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "Test".to_string(),
        required_fields: BTreeSet::new(),
        field_types: types,
    };
    // All wrong types
    let violations = contract.verify(&serde_json::json!({
        "name": 123,
        "count": "not_a_number",
        "active": [1, 2]
    }));
    assert_eq!(violations.len(), 3);
    for v in &violations {
        assert_eq!(v.regression_class, RegressionClass::Breaking);
    }
}

#[test]
fn schema_contract_mixed_missing_and_wrong_type() {
    let mut required = BTreeSet::new();
    required.insert("id".to_string());
    required.insert("value".to_string());
    let mut types = BTreeMap::new();
    types.insert("id".to_string(), FieldType::String);
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "Test".to_string(),
        required_fields: required,
        field_types: types,
    };
    // "id" present but wrong type, "value" missing
    let violations = contract.verify(&serde_json::json!({"id": 42}));
    assert_eq!(violations.len(), 2);
}

#[test]
fn schema_contract_serde_round_trip() {
    let mut required = BTreeSet::new();
    required.insert("field_a".to_string());
    let mut types = BTreeMap::new();
    types.insert("field_a".to_string(), FieldType::Object);
    let contract = SchemaContract {
        boundary: "boundary".to_string(),
        type_name: "TypeName".to_string(),
        required_fields: required,
        field_types: types,
    };
    verify_deterministic_serde(&contract).unwrap();
}

#[test]
fn schema_contract_field_absent_from_types_not_checked() {
    // If a field is in required_fields but not in field_types,
    // its presence is checked but not its type.
    let mut required = BTreeSet::new();
    required.insert("data".to_string());
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "Test".to_string(),
        required_fields: required,
        field_types: BTreeMap::new(),
    };
    // data present with any type → no violations
    let violations = contract.verify(&serde_json::json!({"data": [1,2,3]}));
    assert!(violations.is_empty());
    let violations = contract.verify(&serde_json::json!({"data": "str"}));
    assert!(violations.is_empty());
}

// ── verify_structured_log ───────────────────────────────────────────────────

#[test]
fn verify_structured_log_non_object() {
    let violations = verify_structured_log(&serde_json::json!("not an object"), "test");
    assert_eq!(violations.len(), 1);
    assert_eq!(
        violations[0].regression_class,
        RegressionClass::Observability
    );
    assert!(violations[0].detail.contains("JSON object"));
}

#[test]
fn verify_structured_log_array_input() {
    let violations = verify_structured_log(&serde_json::json!([1, 2]), "test");
    assert_eq!(violations.len(), 1);
}

#[test]
fn verify_structured_log_all_required_present() {
    let json = serde_json::json!({
        "trace_id": "t",
        "component": "c",
        "event": "e",
        "outcome": "o"
    });
    let violations = verify_structured_log(&json, "test");
    assert!(violations.is_empty());
}

#[test]
fn verify_structured_log_all_required_plus_optional() {
    let json = serde_json::json!({
        "trace_id": "t",
        "component": "c",
        "event": "e",
        "outcome": "o",
        "decision_id": "d",
        "policy_id": "p",
        "error_code": "E-001"
    });
    let violations = verify_structured_log(&json, "test");
    assert!(violations.is_empty());
}

#[test]
fn verify_structured_log_partial_missing() {
    let json = serde_json::json!({
        "trace_id": "t",
        "event": "e"
    });
    let violations = verify_structured_log(&json, "boundary_x");
    assert_eq!(violations.len(), 2); // missing component and outcome
    assert!(violations.iter().all(|v| v.boundary == "boundary_x"));
    assert!(
        violations
            .iter()
            .all(|v| v.contract_name == "structured_log")
    );
}

#[test]
fn verify_structured_log_empty_object() {
    let violations = verify_structured_log(&serde_json::json!({}), "test");
    assert_eq!(violations.len(), 4); // all 4 required fields missing
}

// ── verify_error_code_format ────────────────────────────────────────────────

#[test]
fn verify_error_code_format_empty_prefix() {
    // Empty prefix matches everything
    assert!(verify_error_code_format("anything", ""));
    assert!(verify_error_code_format("", ""));
}

#[test]
fn verify_error_code_format_exact_match() {
    assert!(verify_error_code_format("FE-STOR-", "FE-STOR-"));
}

#[test]
fn verify_error_code_format_longer_code() {
    assert!(verify_error_code_format("FE-STOR-0001-extra", "FE-STOR-"));
}

#[test]
fn verify_error_code_format_wrong_prefix() {
    assert!(!verify_error_code_format("XX-0001", "FE-STOR-"));
}

#[test]
fn verify_error_code_format_code_shorter_than_prefix() {
    assert!(!verify_error_code_format("FE", "FE-STOR-"));
}

#[test]
fn verify_error_code_format_case_sensitive() {
    assert!(!verify_error_code_format("fe-stor-0001", "FE-STOR-"));
}

// ── verify_deterministic_serde ──────────────────────────────────────────────

#[test]
fn verify_deterministic_serde_simple_types() {
    verify_deterministic_serde(&42u32).unwrap();
    verify_deterministic_serde(&"hello".to_string()).unwrap();
    verify_deterministic_serde(&true).unwrap();
    verify_deterministic_serde(&vec![1, 2, 3]).unwrap();
}

#[test]
fn verify_deterministic_serde_btree_map() {
    let mut map = BTreeMap::new();
    map.insert("z".to_string(), 1);
    map.insert("a".to_string(), 2);
    map.insert("m".to_string(), 3);
    verify_deterministic_serde(&map).unwrap();
}

#[test]
fn verify_deterministic_serde_nested_struct() {
    let v = ContractViolation {
        boundary: "b".to_string(),
        contract_name: "c".to_string(),
        regression_class: RegressionClass::Breaking,
        detail: "d".to_string(),
    };
    verify_deterministic_serde(&v).unwrap();
}

#[test]
fn verify_deterministic_serde_contract_suite_result() {
    let mut boundaries = BTreeSet::new();
    boundaries.insert("a".to_string());
    boundaries.insert("b".to_string());
    let result = ContractSuiteResult {
        total_contracts: 10,
        passed: 8,
        failed: 2,
        violations: vec![ContractViolation {
            boundary: "a".to_string(),
            contract_name: "T".to_string(),
            regression_class: RegressionClass::Behavioral,
            detail: "d".to_string(),
        }],
        boundaries_covered: boundaries,
    };
    verify_deterministic_serde(&result).unwrap();
}

// ── verify_schema_compliance ────────────────────────────────────────────────

#[test]
fn verify_schema_compliance_with_compliant_json() {
    let mut required = BTreeSet::new();
    required.insert("id".to_string());
    let mut types = BTreeMap::new();
    types.insert("id".to_string(), FieldType::String);
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "Test".to_string(),
        required_fields: required,
        field_types: types,
    };

    #[derive(serde::Serialize)]
    struct TestType {
        id: String,
    }
    let value = TestType {
        id: "hello".to_string(),
    };
    let violations = verify_schema_compliance(&value, &contract);
    assert!(violations.is_empty());
}

#[test]
fn verify_schema_compliance_with_non_compliant_type() {
    let mut types = BTreeMap::new();
    types.insert("count".to_string(), FieldType::Number);
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "Test".to_string(),
        required_fields: BTreeSet::new(),
        field_types: types,
    };

    #[derive(serde::Serialize)]
    struct TestType {
        count: String, // should be number
    }
    let value = TestType {
        count: "not_number".to_string(),
    };
    let violations = verify_schema_compliance(&value, &contract);
    assert_eq!(violations.len(), 1);
    assert!(violations[0].detail.contains("count"));
}

// ── Boundary contract builders ──────────────────────────────────────────────

#[test]
fn frankentui_contract_has_required_fields() {
    let contract = frankentui_envelope_contract();
    assert_eq!(contract.boundary, "frankentui");
    assert_eq!(contract.type_name, "AdapterEnvelope");
    assert!(contract.required_fields.contains("schema_version"));
    assert!(contract.required_fields.contains("trace_id"));
    assert!(contract.required_fields.contains("generated_at_unix_ms"));
    assert!(contract.required_fields.contains("stream"));
    assert!(contract.required_fields.contains("update_kind"));
    assert!(contract.required_fields.contains("payload"));
    assert_eq!(contract.required_fields.len(), 6);
}

#[test]
fn frankentui_contract_field_types_match_required() {
    let contract = frankentui_envelope_contract();
    for field in &contract.required_fields {
        assert!(
            contract.field_types.contains_key(field),
            "required field `{field}` must have a type declared"
        );
    }
}

#[test]
fn frankentui_contract_serde() {
    let contract = frankentui_envelope_contract();
    verify_deterministic_serde(&contract).unwrap();
}

#[test]
fn frankensqlite_store_record_contract_fields() {
    let contract = frankensqlite_store_record_contract();
    assert_eq!(contract.boundary, "frankensqlite");
    assert_eq!(contract.type_name, "StoreRecord");
    assert_eq!(contract.required_fields.len(), 5);
    assert!(contract.required_fields.contains("store"));
    assert!(contract.required_fields.contains("key"));
    assert!(contract.required_fields.contains("value"));
    assert!(contract.required_fields.contains("metadata"));
    assert!(contract.required_fields.contains("revision"));
}

#[test]
fn frankensqlite_store_record_contract_types() {
    let contract = frankensqlite_store_record_contract();
    assert_eq!(contract.field_types["store"], FieldType::String);
    assert_eq!(contract.field_types["key"], FieldType::String);
    assert_eq!(contract.field_types["value"], FieldType::Array);
    assert_eq!(contract.field_types["metadata"], FieldType::Object);
    assert_eq!(contract.field_types["revision"], FieldType::Number);
}

#[test]
fn fastapi_contract_has_required_fields() {
    let contract = fastapi_endpoint_response_contract();
    assert_eq!(contract.boundary, "fastapi_rust");
    assert_eq!(contract.type_name, "EndpointResponse");
    assert_eq!(contract.required_fields.len(), 5);
    assert!(contract.required_fields.contains("status"));
    assert!(contract.required_fields.contains("endpoint"));
    assert!(contract.required_fields.contains("trace_id"));
    assert!(contract.required_fields.contains("request_id"));
    assert!(contract.required_fields.contains("log"));
}

#[test]
fn frankensqlite_storage_event_contract_fields() {
    let contract = frankensqlite_storage_event_contract();
    assert_eq!(contract.boundary, "frankensqlite");
    assert_eq!(contract.type_name, "StorageEvent");
    assert_eq!(contract.required_fields.len(), 6);
    assert!(contract.required_fields.contains("trace_id"));
    assert!(contract.required_fields.contains("decision_id"));
    assert!(contract.required_fields.contains("policy_id"));
    assert!(contract.required_fields.contains("component"));
    assert!(contract.required_fields.contains("event"));
    assert!(contract.required_fields.contains("outcome"));
}

#[test]
fn frankensqlite_migration_receipt_contract_fields() {
    let contract = frankensqlite_migration_receipt_contract();
    assert_eq!(contract.boundary, "frankensqlite");
    assert_eq!(contract.type_name, "MigrationReceipt");
    assert_eq!(contract.required_fields.len(), 7);
    assert!(contract.required_fields.contains("backend"));
    assert!(contract.required_fields.contains("from_version"));
    assert!(contract.required_fields.contains("to_version"));
    assert!(contract.required_fields.contains("stores_touched"));
    assert!(contract.required_fields.contains("records_touched"));
    assert!(contract.required_fields.contains("state_hash_before"));
    assert!(contract.required_fields.contains("state_hash_after"));
}

#[test]
fn all_contracts_have_non_empty_required_fields() {
    let contracts = [
        frankentui_envelope_contract(),
        frankensqlite_store_record_contract(),
        fastapi_endpoint_response_contract(),
        frankensqlite_storage_event_contract(),
        frankensqlite_migration_receipt_contract(),
    ];
    for contract in &contracts {
        assert!(
            !contract.required_fields.is_empty(),
            "contract {}/{} has no required fields",
            contract.boundary,
            contract.type_name
        );
    }
}

#[test]
fn all_contracts_have_non_empty_field_types() {
    let contracts = [
        frankentui_envelope_contract(),
        frankensqlite_store_record_contract(),
        fastapi_endpoint_response_contract(),
        frankensqlite_storage_event_contract(),
        frankensqlite_migration_receipt_contract(),
    ];
    for contract in &contracts {
        assert!(
            !contract.field_types.is_empty(),
            "contract {}/{} has no field types",
            contract.boundary,
            contract.type_name
        );
    }
}

#[test]
fn all_contracts_field_types_cover_required_fields() {
    let contracts = [
        frankentui_envelope_contract(),
        frankensqlite_store_record_contract(),
        fastapi_endpoint_response_contract(),
        frankensqlite_storage_event_contract(),
        frankensqlite_migration_receipt_contract(),
    ];
    for contract in &contracts {
        for field in &contract.required_fields {
            assert!(
                contract.field_types.contains_key(field),
                "contract {}/{}: required field `{field}` has no declared type",
                contract.boundary,
                contract.type_name
            );
        }
    }
}

#[test]
fn all_contracts_serde_round_trip() {
    let contracts = [
        frankentui_envelope_contract(),
        frankensqlite_store_record_contract(),
        fastapi_endpoint_response_contract(),
        frankensqlite_storage_event_contract(),
        frankensqlite_migration_receipt_contract(),
    ];
    for contract in &contracts {
        verify_deterministic_serde(contract).unwrap();
    }
}

// ── VersionCompatibilityEntry ───────────────────────────────────────────────

#[test]
fn version_compatibility_entry_serde() {
    let entry = VersionCompatibilityEntry {
        boundary: "test".to_string(),
        current_version: 5,
        minimum_compatible_version: 1,
    };
    verify_deterministic_serde(&entry).unwrap();
}

#[test]
fn version_compatibility_entry_fields() {
    let entry = VersionCompatibilityEntry {
        boundary: "b".to_string(),
        current_version: 0,
        minimum_compatible_version: 0,
    };
    assert_eq!(entry.boundary, "b");
    assert_eq!(entry.current_version, 0);
    assert_eq!(entry.minimum_compatible_version, 0);
}

// ── version_compatibility_registry ──────────────────────────────────────────

#[test]
fn version_compatibility_registry_has_three_entries() {
    let registry = version_compatibility_registry();
    assert_eq!(registry.len(), 3);
}

#[test]
fn version_compatibility_registry_all_current_gte_minimum() {
    let registry = version_compatibility_registry();
    for entry in &registry {
        assert!(
            entry.current_version >= entry.minimum_compatible_version,
            "boundary {}: current {} < minimum {}",
            entry.boundary,
            entry.current_version,
            entry.minimum_compatible_version
        );
    }
}

#[test]
fn version_compatibility_registry_unique_boundaries() {
    let registry = version_compatibility_registry();
    let boundaries: BTreeSet<String> = registry.iter().map(|e| e.boundary.clone()).collect();
    assert_eq!(boundaries.len(), registry.len());
}

#[test]
fn version_compatibility_registry_minimum_at_least_one() {
    let registry = version_compatibility_registry();
    for entry in &registry {
        assert!(
            entry.minimum_compatible_version >= 1,
            "boundary {}: minimum version should be >= 1",
            entry.boundary
        );
    }
}

#[test]
fn version_compatibility_registry_serde() {
    let registry = version_compatibility_registry();
    verify_deterministic_serde(&registry).unwrap();
}

// ── integration_point_inventory ─────────────────────────────────────────────

#[test]
fn integration_point_inventory_has_three_boundaries() {
    let inventory = integration_point_inventory();
    assert_eq!(inventory.len(), 3);
    assert!(inventory.contains_key("frankentui"));
    assert!(inventory.contains_key("frankensqlite"));
    assert!(inventory.contains_key("fastapi_rust"));
}

#[test]
fn integration_point_inventory_non_empty_per_boundary() {
    let inventory = integration_point_inventory();
    for (boundary, types) in &inventory {
        assert!(
            !types.is_empty(),
            "boundary `{boundary}` has no integration points"
        );
    }
}

#[test]
fn integration_point_inventory_unique_type_names_per_boundary() {
    let inventory = integration_point_inventory();
    for (boundary, types) in &inventory {
        let unique: BTreeSet<&String> = types.iter().collect();
        assert_eq!(
            unique.len(),
            types.len(),
            "boundary `{boundary}` has duplicate type names"
        );
    }
}

#[test]
fn integration_point_inventory_frankentui_includes_envelope() {
    let inventory = integration_point_inventory();
    let frankentui = &inventory["frankentui"];
    assert!(frankentui.contains(&"AdapterEnvelope".to_string()));
}

#[test]
fn integration_point_inventory_frankensqlite_includes_store_record() {
    let inventory = integration_point_inventory();
    let sqlite = &inventory["frankensqlite"];
    assert!(sqlite.contains(&"StoreRecord".to_string()));
    assert!(sqlite.contains(&"MigrationReceipt".to_string()));
    assert!(sqlite.contains(&"StorageEvent".to_string()));
}

#[test]
fn integration_point_inventory_fastapi_includes_endpoint_response() {
    let inventory = integration_point_inventory();
    let fastapi = &inventory["fastapi_rust"];
    assert!(fastapi.contains(&"EndpointResponse".to_string()));
    assert!(fastapi.contains(&"ErrorEnvelope".to_string()));
}

#[test]
fn integration_point_inventory_deterministic() {
    let a = integration_point_inventory();
    let b = integration_point_inventory();
    assert_eq!(a, b);
}

// ── ContractSuiteResult ─────────────────────────────────────────────────────

#[test]
fn contract_suite_result_is_passing_empty_violations() {
    let result = ContractSuiteResult {
        total_contracts: 5,
        passed: 5,
        failed: 0,
        violations: Vec::new(),
        boundaries_covered: BTreeSet::new(),
    };
    assert!(result.is_passing());
}

#[test]
fn contract_suite_result_is_passing_with_violations() {
    let result = ContractSuiteResult {
        total_contracts: 5,
        passed: 4,
        failed: 1,
        violations: vec![ContractViolation {
            boundary: "x".to_string(),
            contract_name: "Y".to_string(),
            regression_class: RegressionClass::Breaking,
            detail: "d".to_string(),
        }],
        boundaries_covered: BTreeSet::new(),
    };
    assert!(!result.is_passing());
}

#[test]
fn contract_suite_result_display_format() {
    let mut boundaries = BTreeSet::new();
    boundaries.insert("a".to_string());
    boundaries.insert("b".to_string());
    let result = ContractSuiteResult {
        total_contracts: 20,
        passed: 18,
        failed: 2,
        violations: Vec::new(),
        boundaries_covered: boundaries,
    };
    let s = result.to_string();
    assert!(s.contains("contracts=20"));
    assert!(s.contains("passed=18"));
    assert!(s.contains("failed=2"));
    assert!(s.contains("boundaries=2"));
}

#[test]
fn contract_suite_result_display_zero_boundaries() {
    let result = ContractSuiteResult {
        total_contracts: 0,
        passed: 0,
        failed: 0,
        violations: Vec::new(),
        boundaries_covered: BTreeSet::new(),
    };
    let s = result.to_string();
    assert!(s.contains("boundaries=0"));
}

#[test]
fn contract_suite_result_serde() {
    let result = ContractSuiteResult {
        total_contracts: 3,
        passed: 2,
        failed: 1,
        violations: vec![
            ContractViolation {
                boundary: "a".to_string(),
                contract_name: "T1".to_string(),
                regression_class: RegressionClass::Breaking,
                detail: "d1".to_string(),
            },
            ContractViolation {
                boundary: "b".to_string(),
                contract_name: "T2".to_string(),
                regression_class: RegressionClass::Performance,
                detail: "d2".to_string(),
            },
        ],
        boundaries_covered: {
            let mut s = BTreeSet::new();
            s.insert("a".to_string());
            s.insert("b".to_string());
            s
        },
    };
    verify_deterministic_serde(&result).unwrap();
}

// ── REQUIRED_LOG_FIELDS / OPTIONAL_LOG_FIELDS ───────────────────────────────

#[test]
fn required_log_fields_count() {
    use frankenengine_engine::cross_repo_contract::REQUIRED_LOG_FIELDS;
    assert_eq!(REQUIRED_LOG_FIELDS.len(), 4);
    assert!(REQUIRED_LOG_FIELDS.contains(&"trace_id"));
    assert!(REQUIRED_LOG_FIELDS.contains(&"component"));
    assert!(REQUIRED_LOG_FIELDS.contains(&"event"));
    assert!(REQUIRED_LOG_FIELDS.contains(&"outcome"));
}

#[test]
fn optional_log_fields_count() {
    use frankenengine_engine::cross_repo_contract::OPTIONAL_LOG_FIELDS;
    assert_eq!(OPTIONAL_LOG_FIELDS.len(), 3);
    assert!(OPTIONAL_LOG_FIELDS.contains(&"decision_id"));
    assert!(OPTIONAL_LOG_FIELDS.contains(&"policy_id"));
    assert!(OPTIONAL_LOG_FIELDS.contains(&"error_code"));
}

#[test]
fn required_and_optional_fields_no_overlap() {
    use frankenengine_engine::cross_repo_contract::{OPTIONAL_LOG_FIELDS, REQUIRED_LOG_FIELDS};
    let required: BTreeSet<&str> = REQUIRED_LOG_FIELDS.iter().copied().collect();
    let optional: BTreeSet<&str> = OPTIONAL_LOG_FIELDS.iter().copied().collect();
    let overlap: BTreeSet<&str> = required.intersection(&optional).copied().collect();
    assert!(overlap.is_empty(), "overlap: {overlap:?}");
}

// ── Deterministic contract builder outputs ──────────────────────────────────

#[test]
fn contract_builders_deterministic() {
    for _ in 0..10 {
        assert_eq!(
            frankentui_envelope_contract(),
            frankentui_envelope_contract()
        );
        assert_eq!(
            frankensqlite_store_record_contract(),
            frankensqlite_store_record_contract()
        );
        assert_eq!(
            fastapi_endpoint_response_contract(),
            fastapi_endpoint_response_contract()
        );
        assert_eq!(
            frankensqlite_storage_event_contract(),
            frankensqlite_storage_event_contract()
        );
        assert_eq!(
            frankensqlite_migration_receipt_contract(),
            frankensqlite_migration_receipt_contract()
        );
    }
}

// ── Integration: cross-verify contracts with inventory ──────────────────────

#[test]
fn all_contract_boundaries_in_inventory() {
    let inventory = integration_point_inventory();
    let contracts = [
        frankentui_envelope_contract(),
        frankensqlite_store_record_contract(),
        fastapi_endpoint_response_contract(),
        frankensqlite_storage_event_contract(),
        frankensqlite_migration_receipt_contract(),
    ];
    for contract in &contracts {
        assert!(
            inventory.contains_key(&contract.boundary),
            "contract boundary `{}` not in inventory",
            contract.boundary
        );
    }
}

#[test]
fn all_contract_type_names_in_inventory() {
    let inventory = integration_point_inventory();
    let contracts = [
        frankentui_envelope_contract(),
        frankensqlite_store_record_contract(),
        fastapi_endpoint_response_contract(),
        frankensqlite_storage_event_contract(),
        frankensqlite_migration_receipt_contract(),
    ];
    for contract in &contracts {
        let types = &inventory[&contract.boundary];
        assert!(
            types.contains(&contract.type_name),
            "contract type `{}` not in boundary `{}` inventory",
            contract.type_name,
            contract.boundary
        );
    }
}

#[test]
fn all_contract_boundaries_in_version_registry() {
    let registry = version_compatibility_registry();
    let reg_boundaries: BTreeSet<String> = registry.iter().map(|e| e.boundary.clone()).collect();
    let contracts = [
        frankentui_envelope_contract(),
        frankensqlite_store_record_contract(),
        fastapi_endpoint_response_contract(),
        frankensqlite_storage_event_contract(),
        frankensqlite_migration_receipt_contract(),
    ];
    for contract in &contracts {
        assert!(
            reg_boundaries.contains(&contract.boundary),
            "boundary `{}` not in version registry",
            contract.boundary
        );
    }
}

#[test]
fn inventory_boundaries_match_registry_boundaries() {
    let inventory = integration_point_inventory();
    let registry = version_compatibility_registry();
    let inv_boundaries: BTreeSet<String> = inventory.keys().cloned().collect();
    let reg_boundaries: BTreeSet<String> = registry.iter().map(|e| e.boundary.clone()).collect();
    assert_eq!(inv_boundaries, reg_boundaries);
}

// ── Edge case: verify against empty/minimal contracts ───────────────────────

#[test]
fn schema_contract_verify_empty_required_empty_types() {
    let contract = SchemaContract {
        boundary: "empty".to_string(),
        type_name: "Empty".to_string(),
        required_fields: BTreeSet::new(),
        field_types: BTreeMap::new(),
    };
    let violations = contract.verify(&serde_json::json!({"anything": "goes"}));
    assert!(violations.is_empty());
}

#[test]
fn schema_contract_verify_with_nested_objects() {
    let mut types = BTreeMap::new();
    types.insert("data".to_string(), FieldType::Object);
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "Nested".to_string(),
        required_fields: BTreeSet::new(),
        field_types: types,
    };
    let violations = contract.verify(&serde_json::json!({"data": {"inner": 42}}));
    assert!(violations.is_empty());
}

#[test]
fn schema_contract_verify_array_type_check() {
    let mut types = BTreeMap::new();
    types.insert("items".to_string(), FieldType::Array);
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "ArrayTest".to_string(),
        required_fields: BTreeSet::new(),
        field_types: types,
    };
    // Correct: array
    let violations = contract.verify(&serde_json::json!({"items": [1, 2, 3]}));
    assert!(violations.is_empty());
    // Wrong: string
    let violations = contract.verify(&serde_json::json!({"items": "not_array"}));
    assert_eq!(violations.len(), 1);
    assert!(violations[0].detail.contains("items"));
}

#[test]
fn schema_contract_verify_bool_type_check() {
    let mut types = BTreeMap::new();
    types.insert("flag".to_string(), FieldType::Bool);
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "BoolTest".to_string(),
        required_fields: BTreeSet::new(),
        field_types: types,
    };
    let violations = contract.verify(&serde_json::json!({"flag": true}));
    assert!(violations.is_empty());
    let violations = contract.verify(&serde_json::json!({"flag": "true"}));
    assert_eq!(violations.len(), 1);
}
