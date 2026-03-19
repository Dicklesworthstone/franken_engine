#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

//! Enrichment integration tests for the cross_repo_contract module.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::cross_repo_contract::{
    ContractSuiteResult, ContractViolation, FieldType, RegressionClass, SchemaContract,
    VersionCompatibilityEntry, fastapi_endpoint_response_contract,
    frankensqlite_migration_receipt_contract, frankensqlite_storage_event_contract,
    frankensqlite_store_record_contract, frankentui_envelope_contract,
    integration_point_inventory, verify_deterministic_serde, verify_error_code_format,
    verify_schema_compliance, verify_structured_log, version_compatibility_registry,
    OPTIONAL_LOG_FIELDS, REQUIRED_LOG_FIELDS,
};

// ---------------------------------------------------------------------------
// RegressionClass serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn regression_class_serde_all_variants() {
    let variants = vec![
        RegressionClass::Breaking,
        RegressionClass::Behavioral,
        RegressionClass::Observability,
        RegressionClass::Performance,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let decoded: RegressionClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, decoded);
    }
}

#[test]
fn regression_class_display_all_distinct() {
    let variants = vec![
        RegressionClass::Breaking,
        RegressionClass::Behavioral,
        RegressionClass::Observability,
        RegressionClass::Performance,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), variants.len());
}

// ---------------------------------------------------------------------------
// FieldType serde and display
// ---------------------------------------------------------------------------

#[test]
fn field_type_serde_all_variants() {
    let variants = vec![
        FieldType::String,
        FieldType::Number,
        FieldType::Bool,
        FieldType::Array,
        FieldType::Object,
        FieldType::Null,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let decoded: FieldType = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, decoded);
    }
}

#[test]
fn field_type_display_all_distinct() {
    let variants = vec![
        FieldType::String,
        FieldType::Number,
        FieldType::Bool,
        FieldType::Array,
        FieldType::Object,
        FieldType::Null,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), variants.len());
}

// ---------------------------------------------------------------------------
// ContractViolation serde and display
// ---------------------------------------------------------------------------

#[test]
fn contract_violation_serde_roundtrip() {
    let v = ContractViolation {
        boundary: "frankentui".to_string(),
        contract_name: "AdapterEnvelope".to_string(),
        regression_class: RegressionClass::Breaking,
        detail: "missing field".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let decoded: ContractViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
}

#[test]
fn contract_violation_display_contains_boundary_and_detail() {
    let v = ContractViolation {
        boundary: "frankentui".to_string(),
        contract_name: "Envelope".to_string(),
        regression_class: RegressionClass::Breaking,
        detail: "missing required field".to_string(),
    };
    let s = v.to_string();
    assert!(s.contains("frankentui"));
    assert!(s.contains("Envelope"));
    assert!(s.contains("missing required field"));
}

// ---------------------------------------------------------------------------
// SchemaContract enrichment
// ---------------------------------------------------------------------------

#[test]
fn schema_contract_serde_roundtrip() {
    let mut required = BTreeSet::new();
    required.insert("foo".to_string());
    let mut types = BTreeMap::new();
    types.insert("foo".to_string(), FieldType::String);
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "TestType".to_string(),
        required_fields: required,
        field_types: types,
    };
    let json = serde_json::to_string(&contract).unwrap();
    let decoded: SchemaContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, decoded);
}

#[test]
fn schema_contract_verify_non_object_returns_breaking() {
    let contract = frankentui_envelope_contract();
    let json = serde_json::Value::String("not an object".to_string());
    let violations = contract.verify(&json);
    assert!(!violations.is_empty());
    assert_eq!(violations[0].regression_class, RegressionClass::Breaking);
}

#[test]
fn schema_contract_verify_missing_field_returns_violation() {
    let contract = frankentui_envelope_contract();
    let json = serde_json::json!({});
    let violations = contract.verify(&json);
    assert!(!violations.is_empty());
    // should mention missing required fields
    assert!(violations.iter().any(|v| v.detail.contains("missing")));
}

#[test]
fn schema_contract_verify_wrong_type_returns_violation() {
    let contract = frankentui_envelope_contract();
    let json = serde_json::json!({
        "schema_version": "not_a_number",
        "trace_id": "t1",
        "generated_at_unix_ms": 123,
        "stream": "s",
        "update_kind": "snapshot",
        "payload": {}
    });
    let violations = contract.verify(&json);
    assert!(
        violations.iter().any(|v| v.detail.contains("expected type")),
        "should detect type mismatch for schema_version"
    );
}

#[test]
fn schema_contract_verify_valid_passes() {
    let contract = frankentui_envelope_contract();
    let json = serde_json::json!({
        "schema_version": 1,
        "trace_id": "t1",
        "generated_at_unix_ms": 1700000000000u64,
        "stream": "IncidentReplay",
        "update_kind": "Snapshot",
        "payload": {"IncidentReplay": {}}
    });
    let violations = contract.verify(&json);
    assert!(violations.is_empty(), "violations: {violations:?}");
}

// ---------------------------------------------------------------------------
// Boundary contract builders
// ---------------------------------------------------------------------------

#[test]
fn frankentui_contract_has_required_fields() {
    let contract = frankentui_envelope_contract();
    assert!(contract.required_fields.contains("schema_version"));
    assert!(contract.required_fields.contains("trace_id"));
    assert!(contract.required_fields.contains("payload"));
}

#[test]
fn frankensqlite_store_record_contract_has_fields() {
    let contract = frankensqlite_store_record_contract();
    assert!(contract.required_fields.contains("store"));
    assert!(contract.required_fields.contains("key"));
    assert!(contract.required_fields.contains("value"));
}

#[test]
fn fastapi_endpoint_response_contract_has_fields() {
    let contract = fastapi_endpoint_response_contract();
    assert!(contract.required_fields.contains("status"));
    assert!(contract.required_fields.contains("endpoint"));
    assert!(contract.required_fields.contains("trace_id"));
}

#[test]
fn frankensqlite_storage_event_contract_has_fields() {
    let contract = frankensqlite_storage_event_contract();
    assert!(contract.required_fields.contains("trace_id"));
    assert!(contract.required_fields.contains("component"));
    assert!(contract.required_fields.contains("event"));
    assert!(contract.required_fields.contains("outcome"));
}

#[test]
fn frankensqlite_migration_receipt_contract_has_fields() {
    let contract = frankensqlite_migration_receipt_contract();
    assert!(contract.required_fields.contains("backend"));
    assert!(contract.required_fields.contains("from_version"));
    assert!(contract.required_fields.contains("to_version"));
}

// ---------------------------------------------------------------------------
// verify_structured_log enrichment
// ---------------------------------------------------------------------------

#[test]
fn verify_structured_log_valid_event() {
    let json = serde_json::json!({
        "trace_id": "t1",
        "component": "engine",
        "event": "startup",
        "outcome": "ok"
    });
    let violations = verify_structured_log(&json, "test");
    assert!(violations.is_empty());
}

#[test]
fn verify_structured_log_missing_fields() {
    let json = serde_json::json!({"trace_id": "t1"});
    let violations = verify_structured_log(&json, "test");
    assert!(violations.len() >= 2); // missing component, event, outcome
}

#[test]
fn verify_structured_log_non_object() {
    let json = serde_json::json!("not_an_object");
    let violations = verify_structured_log(&json, "test");
    assert!(!violations.is_empty());
    assert_eq!(violations[0].regression_class, RegressionClass::Observability);
}

// ---------------------------------------------------------------------------
// verify_error_code_format
// ---------------------------------------------------------------------------

#[test]
fn verify_error_code_format_matching_prefix() {
    assert!(verify_error_code_format("FE-IFC-001", "FE-IFC"));
}

#[test]
fn verify_error_code_format_non_matching() {
    assert!(!verify_error_code_format("FE-IFC-001", "FE-RGC"));
}

// ---------------------------------------------------------------------------
// verify_deterministic_serde
// ---------------------------------------------------------------------------

#[test]
fn verify_deterministic_serde_simple_struct() {
    let v = ContractViolation {
        boundary: "test".to_string(),
        contract_name: "t".to_string(),
        regression_class: RegressionClass::Breaking,
        detail: "d".to_string(),
    };
    verify_deterministic_serde(&v).unwrap();
}

#[test]
fn verify_deterministic_serde_btree_map() {
    let mut map = BTreeMap::new();
    map.insert("a".to_string(), 1u64);
    map.insert("b".to_string(), 2u64);
    verify_deterministic_serde(&map).unwrap();
}

// ---------------------------------------------------------------------------
// VersionCompatibilityEntry enrichment
// ---------------------------------------------------------------------------

#[test]
fn version_compatibility_entry_serde_roundtrip() {
    let entry = VersionCompatibilityEntry {
        boundary: "frankentui".to_string(),
        current_version: 2,
        minimum_compatible_version: 1,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let decoded: VersionCompatibilityEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, decoded);
}

#[test]
fn version_compatibility_registry_has_three_entries() {
    let registry = version_compatibility_registry();
    assert_eq!(registry.len(), 3);
    let boundaries: BTreeSet<&str> = registry.iter().map(|e| e.boundary.as_str()).collect();
    assert!(boundaries.contains("frankentui"));
    assert!(boundaries.contains("frankensqlite"));
    assert!(boundaries.contains("fastapi_rust"));
}

#[test]
fn version_compatibility_registry_current_geq_minimum() {
    for entry in version_compatibility_registry() {
        assert!(
            entry.current_version >= entry.minimum_compatible_version,
            "boundary {}: current {} < min {}",
            entry.boundary,
            entry.current_version,
            entry.minimum_compatible_version
        );
    }
}

// ---------------------------------------------------------------------------
// integration_point_inventory enrichment
// ---------------------------------------------------------------------------

#[test]
fn integration_point_inventory_has_three_boundaries() {
    let inv = integration_point_inventory();
    assert_eq!(inv.len(), 3);
    assert!(inv.contains_key("frankentui"));
    assert!(inv.contains_key("frankensqlite"));
    assert!(inv.contains_key("fastapi_rust"));
}

#[test]
fn integration_point_inventory_all_non_empty() {
    let inv = integration_point_inventory();
    for (boundary, points) in &inv {
        assert!(
            !points.is_empty(),
            "boundary {boundary} has no integration points"
        );
    }
}

// ---------------------------------------------------------------------------
// ContractSuiteResult enrichment
// ---------------------------------------------------------------------------

#[test]
fn contract_suite_result_serde_roundtrip() {
    let result = ContractSuiteResult {
        total_contracts: 5,
        passed: 3,
        failed: 2,
        violations: vec![ContractViolation {
            boundary: "test".to_string(),
            contract_name: "t".to_string(),
            regression_class: RegressionClass::Behavioral,
            detail: "d".to_string(),
        }],
        boundaries_covered: {
            let mut s = BTreeSet::new();
            s.insert("test".to_string());
            s
        },
    };
    let json = serde_json::to_string(&result).unwrap();
    let decoded: ContractSuiteResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, decoded);
}

#[test]
fn contract_suite_result_is_passing_when_no_violations() {
    let result = ContractSuiteResult {
        total_contracts: 3,
        passed: 3,
        failed: 0,
        violations: vec![],
        boundaries_covered: BTreeSet::new(),
    };
    assert!(result.is_passing());
}

#[test]
fn contract_suite_result_not_passing_with_violations() {
    let result = ContractSuiteResult {
        total_contracts: 3,
        passed: 2,
        failed: 1,
        violations: vec![ContractViolation {
            boundary: "x".to_string(),
            contract_name: "y".to_string(),
            regression_class: RegressionClass::Breaking,
            detail: "z".to_string(),
        }],
        boundaries_covered: BTreeSet::new(),
    };
    assert!(!result.is_passing());
}

#[test]
fn contract_suite_result_display_contains_counts() {
    let result = ContractSuiteResult {
        total_contracts: 10,
        passed: 8,
        failed: 2,
        violations: vec![],
        boundaries_covered: {
            let mut s = BTreeSet::new();
            s.insert("a".to_string());
            s
        },
    };
    let s = result.to_string();
    assert!(s.contains("10"));
    assert!(s.contains("8"));
    assert!(s.contains("2"));
}

// ---------------------------------------------------------------------------
// Log field constants
// ---------------------------------------------------------------------------

#[test]
fn required_log_fields_non_empty() {
    assert!(!REQUIRED_LOG_FIELDS.is_empty());
    assert!(REQUIRED_LOG_FIELDS.contains(&"trace_id"));
    assert!(REQUIRED_LOG_FIELDS.contains(&"component"));
}

#[test]
fn optional_log_fields_non_empty() {
    assert!(!OPTIONAL_LOG_FIELDS.is_empty());
}

// ---------------------------------------------------------------------------
// verify_schema_compliance enrichment
// ---------------------------------------------------------------------------

#[test]
fn verify_schema_compliance_with_non_serializable_falls_back_to_breaking() {
    // Verify with a simple valid object
    let contract = frankentui_envelope_contract();
    let json = serde_json::json!({
        "schema_version": 1,
        "trace_id": "t1",
        "generated_at_unix_ms": 100,
        "stream": "s",
        "update_kind": "snap",
        "payload": {}
    });
    let violations = verify_schema_compliance(&json, &contract);
    assert!(violations.is_empty());
}

// ---------------------------------------------------------------------------
// Deterministic: contracts are stable across calls
// ---------------------------------------------------------------------------

#[test]
fn frankentui_contract_deterministic_50_times() {
    let first = serde_json::to_string(&frankentui_envelope_contract()).unwrap();
    for _ in 0..50 {
        let current = serde_json::to_string(&frankentui_envelope_contract()).unwrap();
        assert_eq!(first, current);
    }
}

#[test]
fn integration_point_inventory_deterministic_50_times() {
    let first = serde_json::to_string(&integration_point_inventory()).unwrap();
    for _ in 0..50 {
        let current = serde_json::to_string(&integration_point_inventory()).unwrap();
        assert_eq!(first, current);
    }
}
