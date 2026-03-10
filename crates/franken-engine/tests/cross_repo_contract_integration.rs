#![forbid(unsafe_code)]

//! Integration tests for the `cross_repo_contract` module.
//!
//! Covers: RegressionClass, ContractViolation, SchemaContract, FieldType,
//! verify_structured_log, verify_error_code_format, verify_deterministic_serde,
//! verify_schema_compliance, VersionCompatibilityEntry, ContractSuiteResult,
//! all five boundary contract builders, integration_point_inventory,
//! version_compatibility_registry, and cross-boundary interaction scenarios.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::cross_repo_contract::{
    ContractSuiteResult, ContractViolation, FieldType, OPTIONAL_LOG_FIELDS, REQUIRED_LOG_FIELDS,
    RegressionClass, SchemaContract, VersionCompatibilityEntry, fastapi_endpoint_response_contract,
    frankensqlite_migration_receipt_contract, frankensqlite_storage_event_contract,
    frankensqlite_store_record_contract, frankentui_envelope_contract, integration_point_inventory,
    verify_deterministic_serde, verify_error_code_format, verify_schema_compliance,
    verify_structured_log, version_compatibility_registry,
};
use frankenengine_engine::frankentui_adapter::{
    AdapterEnvelope, AdapterStream, ControlDashboardView, DashboardMetricView, ExtensionStatusRow,
    FRANKENTUI_ADAPTER_SCHEMA_VERSION, FrankentuiViewPayload, IncidentReplayView, ReplayEventView,
    ReplayStatus, UpdateKind,
};
use frankenengine_engine::policy_controller::service_endpoint_template::{
    AuthContext, ControlAction, EndpointResponse, ErrorEnvelope, HealthStatusResponse,
    ReplayCommand, RequestContext, SCOPE_CONTROL_WRITE, SCOPE_EVIDENCE_READ, SCOPE_HEALTH_READ,
    SCOPE_REPLAY_READ, SCOPE_REPLAY_WRITE, StructuredLogEvent,
};
use frankenengine_engine::storage_adapter::{
    EventContext, InMemoryStorageAdapter, MigrationReceipt, STORAGE_SCHEMA_VERSION, StorageAdapter,
    StorageError, StorageEvent, StoreKind, StoreQuery, StoreRecord,
};

// ============================================================================
// Section 1: RegressionClass
// ============================================================================

#[test]
fn regression_class_display_format_matches_uppercase() {
    assert_eq!(RegressionClass::Breaking.to_string(), "BREAKING");
    assert_eq!(RegressionClass::Behavioral.to_string(), "BEHAVIORAL");
    assert_eq!(RegressionClass::Observability.to_string(), "OBSERVABILITY");
    assert_eq!(RegressionClass::Performance.to_string(), "PERFORMANCE");
}

#[test]
fn regression_class_serde_round_trip_all_variants() {
    for class in [
        RegressionClass::Breaking,
        RegressionClass::Behavioral,
        RegressionClass::Observability,
        RegressionClass::Performance,
    ] {
        let json = serde_json::to_string(&class).unwrap();
        let back: RegressionClass = serde_json::from_str(&json).unwrap();
        assert_eq!(back, class);
        verify_deterministic_serde(&class).unwrap();
    }
}

#[test]
fn regression_class_ord_breaking_is_lowest() {
    assert!(RegressionClass::Breaking < RegressionClass::Behavioral);
    assert!(RegressionClass::Behavioral < RegressionClass::Observability);
    assert!(RegressionClass::Observability < RegressionClass::Performance);
}

#[test]
fn regression_class_sort_deterministic() {
    let mut a = vec![
        RegressionClass::Performance,
        RegressionClass::Breaking,
        RegressionClass::Observability,
        RegressionClass::Behavioral,
    ];
    let mut b = a.clone();
    b.reverse();
    a.sort();
    b.sort();
    assert_eq!(a, b);
    assert_eq!(a[0], RegressionClass::Breaking);
    assert_eq!(a[3], RegressionClass::Performance);
}

// ============================================================================
// Section 2: FieldType
// ============================================================================

#[test]
fn field_type_display_lowercase_strings() {
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
fn field_type_serde_round_trip_all_six() {
    for ft in [
        FieldType::String,
        FieldType::Number,
        FieldType::Bool,
        FieldType::Array,
        FieldType::Object,
        FieldType::Null,
    ] {
        let json = serde_json::to_string(&ft).unwrap();
        let back: FieldType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ft);
    }
}

#[test]
fn field_type_ord_deterministic_sort() {
    let mut items = vec![
        FieldType::Null,
        FieldType::Object,
        FieldType::String,
        FieldType::Bool,
        FieldType::Number,
        FieldType::Array,
    ];
    let mut copy = items.clone();
    copy.reverse();
    items.sort();
    copy.sort();
    assert_eq!(items, copy);
}

#[test]
fn field_type_display_values_all_unique() {
    let displays: BTreeSet<String> = [
        FieldType::String,
        FieldType::Number,
        FieldType::Bool,
        FieldType::Array,
        FieldType::Object,
        FieldType::Null,
    ]
    .iter()
    .map(|f| f.to_string())
    .collect();
    assert_eq!(displays.len(), 6);
}

// ============================================================================
// Section 3: ContractViolation
// ============================================================================

#[test]
fn contract_violation_display_contains_all_components() {
    let v = ContractViolation {
        boundary: "my_boundary".to_string(),
        contract_name: "MyContract".to_string(),
        regression_class: RegressionClass::Breaking,
        detail: "field was removed".to_string(),
    };
    let s = v.to_string();
    assert!(s.contains("BREAKING"));
    assert!(s.contains("my_boundary/MyContract"));
    assert!(s.contains("field was removed"));
}

#[test]
fn contract_violation_serde_round_trip() {
    let v = ContractViolation {
        boundary: "sqlite".to_string(),
        contract_name: "StoreRecord".to_string(),
        regression_class: RegressionClass::Behavioral,
        detail: "ordering changed".to_string(),
    };
    verify_deterministic_serde(&v).unwrap();
}

#[test]
fn contract_violation_with_empty_strings() {
    let v = ContractViolation {
        boundary: String::new(),
        contract_name: String::new(),
        regression_class: RegressionClass::Performance,
        detail: String::new(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: ContractViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
    // Display should not panic
    let _ = v.to_string();
}

#[test]
fn contract_violation_display_with_each_regression_class() {
    for class in [
        RegressionClass::Breaking,
        RegressionClass::Behavioral,
        RegressionClass::Observability,
        RegressionClass::Performance,
    ] {
        let v = ContractViolation {
            boundary: "b".to_string(),
            contract_name: "C".to_string(),
            regression_class: class,
            detail: "d".to_string(),
        };
        let s = v.to_string();
        assert!(s.contains(&class.to_string()));
    }
}

// ============================================================================
// Section 4: SchemaContract verification
// ============================================================================

#[test]
fn schema_contract_verify_non_object_returns_single_breaking() {
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "T".to_string(),
        required_fields: BTreeSet::new(),
        field_types: BTreeMap::new(),
    };
    for non_obj in [
        serde_json::json!("string"),
        serde_json::json!(42),
        serde_json::json!(true),
        serde_json::json!(null),
        serde_json::json!([1, 2]),
    ] {
        let violations = contract.verify(&non_obj);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].regression_class, RegressionClass::Breaking);
        assert!(violations[0].detail.contains("expected JSON object"));
    }
}

#[test]
fn schema_contract_verify_empty_object_no_requirements_passes() {
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "T".to_string(),
        required_fields: BTreeSet::new(),
        field_types: BTreeMap::new(),
    };
    let violations = contract.verify(&serde_json::json!({}));
    assert!(violations.is_empty());
}

#[test]
fn schema_contract_verify_detects_missing_required_fields() {
    let mut required = BTreeSet::new();
    required.insert("alpha".to_string());
    required.insert("beta".to_string());
    required.insert("gamma".to_string());
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "T".to_string(),
        required_fields: required,
        field_types: BTreeMap::new(),
    };
    let violations = contract.verify(&serde_json::json!({}));
    assert_eq!(violations.len(), 3);
    let details: BTreeSet<String> = violations.iter().map(|v| v.detail.clone()).collect();
    assert!(details.iter().any(|d| d.contains("alpha")));
    assert!(details.iter().any(|d| d.contains("beta")));
    assert!(details.iter().any(|d| d.contains("gamma")));
}

#[test]
fn schema_contract_verify_detects_type_mismatch() {
    let mut types = BTreeMap::new();
    types.insert("name".to_string(), FieldType::String);
    types.insert("count".to_string(), FieldType::Number);
    types.insert("active".to_string(), FieldType::Bool);
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "T".to_string(),
        required_fields: BTreeSet::new(),
        field_types: types,
    };
    let violations = contract.verify(&serde_json::json!({
        "name": 123,
        "count": "wrong",
        "active": [1]
    }));
    assert_eq!(violations.len(), 3);
    for v in &violations {
        assert_eq!(v.regression_class, RegressionClass::Breaking);
    }
}

#[test]
fn schema_contract_verify_null_is_accepted_for_any_field_type() {
    let mut types = BTreeMap::new();
    types.insert("s".to_string(), FieldType::String);
    types.insert("n".to_string(), FieldType::Number);
    types.insert("b".to_string(), FieldType::Bool);
    types.insert("a".to_string(), FieldType::Array);
    types.insert("o".to_string(), FieldType::Object);
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "T".to_string(),
        required_fields: BTreeSet::new(),
        field_types: types,
    };
    let violations = contract.verify(&serde_json::json!({
        "s": null, "n": null, "b": null, "a": null, "o": null
    }));
    assert!(violations.is_empty());
}

#[test]
fn schema_contract_verify_extra_fields_are_ignored() {
    let mut required = BTreeSet::new();
    required.insert("id".to_string());
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "T".to_string(),
        required_fields: required,
        field_types: BTreeMap::new(),
    };
    let violations = contract.verify(&serde_json::json!({"id": 1, "extra": "ok", "more": true}));
    assert!(violations.is_empty());
}

#[test]
fn schema_contract_verify_mixed_missing_and_wrong_type() {
    let mut required = BTreeSet::new();
    required.insert("id".to_string());
    required.insert("value".to_string());
    let mut types = BTreeMap::new();
    types.insert("id".to_string(), FieldType::String);
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "T".to_string(),
        required_fields: required,
        field_types: types,
    };
    // id: present but wrong type; value: missing
    let violations = contract.verify(&serde_json::json!({"id": 42}));
    assert_eq!(violations.len(), 2);
}

#[test]
fn schema_contract_serde_round_trip() {
    let contract = frankentui_envelope_contract();
    verify_deterministic_serde(&contract).unwrap();
}

// ============================================================================
// Section 5: verify_structured_log
// ============================================================================

#[test]
fn verify_structured_log_non_object_returns_observability_violation() {
    for non_obj in [
        serde_json::json!("hello"),
        serde_json::json!(42),
        serde_json::json!([1]),
        serde_json::json!(null),
    ] {
        let violations = verify_structured_log(&non_obj, "test");
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].regression_class,
            RegressionClass::Observability
        );
        assert!(violations[0].detail.contains("JSON object"));
    }
}

#[test]
fn verify_structured_log_all_fields_present_passes() {
    let json = serde_json::json!({
        "trace_id": "t", "component": "c", "event": "e", "outcome": "o"
    });
    assert!(verify_structured_log(&json, "test").is_empty());
}

#[test]
fn verify_structured_log_empty_object_reports_all_four_missing() {
    let violations = verify_structured_log(&serde_json::json!({}), "test");
    assert_eq!(violations.len(), 4);
    for v in &violations {
        assert_eq!(v.regression_class, RegressionClass::Observability);
        assert_eq!(v.contract_name, "structured_log");
    }
}

#[test]
fn verify_structured_log_partial_missing() {
    let json = serde_json::json!({"trace_id": "t", "event": "e"});
    let violations = verify_structured_log(&json, "boundary_x");
    assert_eq!(violations.len(), 2); // missing component, outcome
    assert!(violations.iter().all(|v| v.boundary == "boundary_x"));
}

#[test]
fn verify_structured_log_boundary_name_propagated() {
    let json = serde_json::json!({"trace_id": "t"});
    let violations = verify_structured_log(&json, "custom_boundary");
    for v in &violations {
        assert_eq!(v.boundary, "custom_boundary");
    }
}

// ============================================================================
// Section 6: verify_error_code_format
// ============================================================================

#[test]
fn error_code_format_matches_prefix() {
    assert!(verify_error_code_format("FE-STOR-0001", "FE-STOR-"));
    assert!(verify_error_code_format("FE-IFC-001", "FE-IFC"));
}

#[test]
fn error_code_format_rejects_wrong_prefix() {
    assert!(!verify_error_code_format("XX-0001", "FE-STOR-"));
    assert!(!verify_error_code_format("fe-stor-0001", "FE-STOR-"));
}

#[test]
fn error_code_format_empty_prefix_matches_anything() {
    assert!(verify_error_code_format("anything", ""));
    assert!(verify_error_code_format("", ""));
}

#[test]
fn error_code_format_code_shorter_than_prefix_rejects() {
    assert!(!verify_error_code_format("FE", "FE-STOR-"));
}

#[test]
fn error_code_format_exact_match() {
    assert!(verify_error_code_format("FE-STOR-", "FE-STOR-"));
}

// ============================================================================
// Section 7: verify_deterministic_serde
// ============================================================================

#[test]
fn deterministic_serde_simple_types() {
    verify_deterministic_serde(&42u32).unwrap();
    verify_deterministic_serde(&"hello".to_string()).unwrap();
    verify_deterministic_serde(&true).unwrap();
    verify_deterministic_serde(&vec![1, 2, 3]).unwrap();
}

#[test]
fn deterministic_serde_btree_map_ordering_stable() {
    let mut map = BTreeMap::new();
    map.insert("z".to_string(), 1);
    map.insert("a".to_string(), 2);
    map.insert("m".to_string(), 3);
    verify_deterministic_serde(&map).unwrap();
}

#[test]
fn deterministic_serde_nested_struct() {
    let v = ContractViolation {
        boundary: "b".to_string(),
        contract_name: "c".to_string(),
        regression_class: RegressionClass::Breaking,
        detail: "d".to_string(),
    };
    verify_deterministic_serde(&v).unwrap();
}

// ============================================================================
// Section 8: verify_schema_compliance
// ============================================================================

#[test]
fn schema_compliance_with_compliant_struct() {
    #[derive(serde::Serialize)]
    struct TestType {
        id: String,
        count: u32,
    }
    let mut required = BTreeSet::new();
    required.insert("id".to_string());
    required.insert("count".to_string());
    let mut types = BTreeMap::new();
    types.insert("id".to_string(), FieldType::String);
    types.insert("count".to_string(), FieldType::Number);
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "TestType".to_string(),
        required_fields: required,
        field_types: types,
    };
    let value = TestType {
        id: "hello".to_string(),
        count: 42,
    };
    let violations = verify_schema_compliance(&value, &contract);
    assert!(violations.is_empty());
}

#[test]
fn schema_compliance_with_wrong_type_struct() {
    #[derive(serde::Serialize)]
    struct TestType {
        count: String, // should be number
    }
    let mut types = BTreeMap::new();
    types.insert("count".to_string(), FieldType::Number);
    let contract = SchemaContract {
        boundary: "test".to_string(),
        type_name: "TestType".to_string(),
        required_fields: BTreeSet::new(),
        field_types: types,
    };
    let value = TestType {
        count: "not_a_number".to_string(),
    };
    let violations = verify_schema_compliance(&value, &contract);
    assert_eq!(violations.len(), 1);
    assert!(violations[0].detail.contains("count"));
}

// ============================================================================
// Section 9: Boundary contract builder content validation
// ============================================================================

#[test]
fn frankentui_contract_has_all_six_required_fields() {
    let c = frankentui_envelope_contract();
    assert_eq!(c.boundary, "frankentui");
    assert_eq!(c.type_name, "AdapterEnvelope");
    assert_eq!(c.required_fields.len(), 6);
    for field in [
        "schema_version",
        "trace_id",
        "generated_at_unix_ms",
        "stream",
        "update_kind",
        "payload",
    ] {
        assert!(c.required_fields.contains(field));
    }
}

#[test]
fn frankentui_contract_field_types_cover_all_required() {
    let c = frankentui_envelope_contract();
    for field in &c.required_fields {
        assert!(c.field_types.contains_key(field));
    }
    assert_eq!(
        *c.field_types.get("schema_version").unwrap(),
        FieldType::Number
    );
    assert_eq!(*c.field_types.get("trace_id").unwrap(), FieldType::String);
    assert_eq!(*c.field_types.get("payload").unwrap(), FieldType::Object);
}

#[test]
fn frankensqlite_store_record_contract_content() {
    let c = frankensqlite_store_record_contract();
    assert_eq!(c.boundary, "frankensqlite");
    assert_eq!(c.type_name, "StoreRecord");
    assert_eq!(c.required_fields.len(), 5);
    assert_eq!(*c.field_types.get("value").unwrap(), FieldType::Array);
    assert_eq!(*c.field_types.get("metadata").unwrap(), FieldType::Object);
    assert_eq!(*c.field_types.get("revision").unwrap(), FieldType::Number);
}

#[test]
fn fastapi_contract_content() {
    let c = fastapi_endpoint_response_contract();
    assert_eq!(c.boundary, "fastapi_rust");
    assert_eq!(c.type_name, "EndpointResponse");
    assert_eq!(c.required_fields.len(), 5);
    assert_eq!(*c.field_types.get("log").unwrap(), FieldType::Object);
    assert_eq!(*c.field_types.get("status").unwrap(), FieldType::String);
}

#[test]
fn frankensqlite_storage_event_contract_content() {
    let c = frankensqlite_storage_event_contract();
    assert_eq!(c.boundary, "frankensqlite");
    assert_eq!(c.type_name, "StorageEvent");
    assert_eq!(c.required_fields.len(), 6);
    for f in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
    ] {
        assert!(c.required_fields.contains(f));
    }
}

#[test]
fn frankensqlite_migration_receipt_contract_content() {
    let c = frankensqlite_migration_receipt_contract();
    assert_eq!(c.boundary, "frankensqlite");
    assert_eq!(c.type_name, "MigrationReceipt");
    assert_eq!(c.required_fields.len(), 7);
    assert_eq!(
        *c.field_types.get("stores_touched").unwrap(),
        FieldType::Array
    );
}

#[test]
fn all_five_contracts_serde_round_trip() {
    for contract in [
        frankentui_envelope_contract(),
        frankensqlite_store_record_contract(),
        fastapi_endpoint_response_contract(),
        frankensqlite_storage_event_contract(),
        frankensqlite_migration_receipt_contract(),
    ] {
        verify_deterministic_serde(&contract).unwrap();
    }
}

#[test]
fn all_contracts_types_cover_required() {
    for contract in [
        frankentui_envelope_contract(),
        frankensqlite_store_record_contract(),
        fastapi_endpoint_response_contract(),
        frankensqlite_storage_event_contract(),
        frankensqlite_migration_receipt_contract(),
    ] {
        for field in &contract.required_fields {
            assert!(
                contract.field_types.contains_key(field),
                "{}/{}: required field `{field}` has no type",
                contract.boundary,
                contract.type_name
            );
        }
    }
}

#[test]
fn contract_builders_deterministic_over_iterations() {
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
    }
}

// ============================================================================
// Section 10: VersionCompatibilityEntry and registry
// ============================================================================

#[test]
fn version_compatibility_entry_serde_round_trip() {
    let entry = VersionCompatibilityEntry {
        boundary: "test".to_string(),
        current_version: 5,
        minimum_compatible_version: 1,
    };
    verify_deterministic_serde(&entry).unwrap();
}

#[test]
fn version_compatibility_registry_has_three_entries() {
    let registry = version_compatibility_registry();
    assert_eq!(registry.len(), 3);
}

#[test]
fn version_compatibility_registry_current_gte_minimum() {
    for entry in &version_compatibility_registry() {
        assert!(
            entry.current_version >= entry.minimum_compatible_version,
            "{}: current {} < minimum {}",
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
    for entry in &version_compatibility_registry() {
        assert!(entry.minimum_compatible_version >= 1);
    }
}

#[test]
fn version_compatibility_registry_covers_all_three_boundaries() {
    let boundaries: BTreeSet<String> = version_compatibility_registry()
        .iter()
        .map(|e| e.boundary.clone())
        .collect();
    assert!(boundaries.contains("frankentui"));
    assert!(boundaries.contains("frankensqlite"));
    assert!(boundaries.contains("fastapi_rust"));
}

#[test]
fn version_compatibility_registry_frankentui_version_matches_const() {
    let registry = version_compatibility_registry();
    let tui = registry
        .iter()
        .find(|e| e.boundary == "frankentui")
        .unwrap();
    assert_eq!(tui.current_version, FRANKENTUI_ADAPTER_SCHEMA_VERSION);
}

#[test]
fn version_compatibility_registry_frankensqlite_version_matches_const() {
    let registry = version_compatibility_registry();
    let sql = registry
        .iter()
        .find(|e| e.boundary == "frankensqlite")
        .unwrap();
    assert_eq!(sql.current_version, STORAGE_SCHEMA_VERSION);
}

// ============================================================================
// Section 11: integration_point_inventory
// ============================================================================

#[test]
fn inventory_has_three_boundaries() {
    let inv = integration_point_inventory();
    assert_eq!(inv.len(), 3);
    assert!(inv.contains_key("frankentui"));
    assert!(inv.contains_key("frankensqlite"));
    assert!(inv.contains_key("fastapi_rust"));
}

#[test]
fn inventory_non_empty_per_boundary() {
    for (boundary, types) in &integration_point_inventory() {
        assert!(!types.is_empty(), "{boundary} has no types");
    }
}

#[test]
fn inventory_unique_type_names_per_boundary() {
    for (boundary, types) in &integration_point_inventory() {
        let unique: BTreeSet<&String> = types.iter().collect();
        assert_eq!(
            unique.len(),
            types.len(),
            "{boundary} has duplicate type names"
        );
    }
}

#[test]
fn inventory_deterministic_across_calls() {
    let a = integration_point_inventory();
    let b = integration_point_inventory();
    assert_eq!(a, b);
}

#[test]
fn inventory_contains_all_contract_type_names() {
    let inv = integration_point_inventory();
    let contracts = [
        frankentui_envelope_contract(),
        frankensqlite_store_record_contract(),
        fastapi_endpoint_response_contract(),
        frankensqlite_storage_event_contract(),
        frankensqlite_migration_receipt_contract(),
    ];
    for contract in &contracts {
        let types = inv.get(&contract.boundary).unwrap();
        assert!(
            types.contains(&contract.type_name),
            "{}/{} not in inventory",
            contract.boundary,
            contract.type_name
        );
    }
}

// ============================================================================
// Section 12: ContractSuiteResult
// ============================================================================

#[test]
fn contract_suite_result_is_passing_when_no_violations() {
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
fn contract_suite_result_not_passing_with_violations() {
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
fn contract_suite_result_display() {
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
fn contract_suite_result_serde_round_trip() {
    let result = ContractSuiteResult {
        total_contracts: 3,
        passed: 2,
        failed: 1,
        violations: vec![ContractViolation {
            boundary: "a".to_string(),
            contract_name: "T".to_string(),
            regression_class: RegressionClass::Behavioral,
            detail: "d".to_string(),
        }],
        boundaries_covered: {
            let mut s = BTreeSet::new();
            s.insert("a".to_string());
            s
        },
    };
    verify_deterministic_serde(&result).unwrap();
}

#[test]
fn contract_suite_result_zero_counters() {
    let result = ContractSuiteResult {
        total_contracts: 0,
        passed: 0,
        failed: 0,
        violations: Vec::new(),
        boundaries_covered: BTreeSet::new(),
    };
    assert!(result.is_passing());
    let s = result.to_string();
    assert!(s.contains("contracts=0"));
    assert!(s.contains("boundaries=0"));
}

// ============================================================================
// Section 13: REQUIRED_LOG_FIELDS / OPTIONAL_LOG_FIELDS constants
// ============================================================================

#[test]
fn required_log_fields_has_four_entries() {
    assert_eq!(REQUIRED_LOG_FIELDS.len(), 4);
    assert!(REQUIRED_LOG_FIELDS.contains(&"trace_id"));
    assert!(REQUIRED_LOG_FIELDS.contains(&"component"));
    assert!(REQUIRED_LOG_FIELDS.contains(&"event"));
    assert!(REQUIRED_LOG_FIELDS.contains(&"outcome"));
}

#[test]
fn optional_log_fields_has_three_entries() {
    assert_eq!(OPTIONAL_LOG_FIELDS.len(), 3);
    assert!(OPTIONAL_LOG_FIELDS.contains(&"decision_id"));
    assert!(OPTIONAL_LOG_FIELDS.contains(&"policy_id"));
    assert!(OPTIONAL_LOG_FIELDS.contains(&"error_code"));
}

#[test]
fn required_and_optional_fields_no_overlap() {
    let required: BTreeSet<&str> = REQUIRED_LOG_FIELDS.iter().copied().collect();
    let optional: BTreeSet<&str> = OPTIONAL_LOG_FIELDS.iter().copied().collect();
    let overlap: BTreeSet<&str> = required.intersection(&optional).copied().collect();
    assert!(overlap.is_empty());
}

// ============================================================================
// Section 14: Cross-boundary contract/inventory/registry consistency
// ============================================================================

#[test]
fn all_contract_boundaries_in_inventory() {
    let inv = integration_point_inventory();
    for contract in [
        frankentui_envelope_contract(),
        frankensqlite_store_record_contract(),
        fastapi_endpoint_response_contract(),
    ] {
        assert!(inv.contains_key(&contract.boundary));
    }
}

#[test]
fn inventory_boundaries_match_registry_boundaries() {
    let inv_boundaries: BTreeSet<String> = integration_point_inventory().keys().cloned().collect();
    let reg_boundaries: BTreeSet<String> = version_compatibility_registry()
        .iter()
        .map(|e| e.boundary.clone())
        .collect();
    assert_eq!(inv_boundaries, reg_boundaries);
}

// ============================================================================
// Section 15: Live cross-boundary integration: frankentui
// ============================================================================

fn sample_envelope() -> AdapterEnvelope {
    let replay = IncidentReplayView::snapshot(
        "trace-integ-1",
        "integ-scenario",
        vec![ReplayEventView::new(
            1,
            "engine",
            "startup",
            "ok",
            1_700_000_000_000,
        )],
    );
    AdapterEnvelope::new(
        "trace-integ-1",
        1_700_000_000_000,
        AdapterStream::IncidentReplay,
        UpdateKind::Snapshot,
        FrankentuiViewPayload::IncidentReplay(replay),
    )
}

#[test]
fn frankentui_envelope_schema_compliance() {
    let contract = frankentui_envelope_contract();
    let envelope = sample_envelope();
    let violations = verify_schema_compliance(&envelope, &contract);
    assert!(violations.is_empty(), "violations: {violations:?}");
}

#[test]
fn frankentui_envelope_deterministic_serde() {
    verify_deterministic_serde(&sample_envelope()).unwrap();
}

#[test]
fn frankentui_envelope_schema_version_matches_const() {
    assert_eq!(
        sample_envelope().schema_version,
        FRANKENTUI_ADAPTER_SCHEMA_VERSION
    );
}

#[test]
fn frankentui_control_dashboard_payload_serializes_as_object() {
    let dashboard = FrankentuiViewPayload::ControlDashboard(ControlDashboardView {
        cluster: "prod".to_string(),
        zone: "us-east".to_string(),
        security_epoch: 5,
        runtime_mode: "secure".to_string(),
        metrics: vec![DashboardMetricView {
            metric: "p95_ms".to_string(),
            value: 42,
            unit: "ms".to_string(),
        }],
        extension_rows: vec![ExtensionStatusRow {
            extension_id: "ext-a".to_string(),
            state: "running".to_string(),
            trust_level: "verified".to_string(),
        }],
        incident_counts: BTreeMap::new(),
    });
    let envelope = AdapterEnvelope::new(
        "trace-dash",
        1_700_000_000_000,
        AdapterStream::ControlDashboard,
        UpdateKind::Snapshot,
        dashboard,
    );
    let json = serde_json::to_value(&envelope).unwrap();
    assert!(json["payload"].is_object());
}

#[test]
fn frankentui_replay_status_enum_values_stable() {
    let pairs = [
        (ReplayStatus::Running, "running"),
        (ReplayStatus::Complete, "complete"),
        (ReplayStatus::Failed, "failed"),
        (ReplayStatus::NoEvents, "no_events"),
    ];
    for (status, expected) in &pairs {
        let json = serde_json::to_value(status).unwrap();
        assert_eq!(json.as_str().unwrap(), *expected);
    }
}

#[test]
fn frankentui_stream_enum_values_stable() {
    let pairs = [
        (AdapterStream::IncidentReplay, "incident_replay"),
        (AdapterStream::PolicyExplanation, "policy_explanation"),
        (AdapterStream::ControlDashboard, "control_dashboard"),
    ];
    for (stream, expected) in &pairs {
        let json = serde_json::to_value(stream).unwrap();
        assert_eq!(json.as_str().unwrap(), *expected);
    }
}

#[test]
fn frankentui_update_kind_enum_values_stable() {
    let pairs = [
        (UpdateKind::Snapshot, "snapshot"),
        (UpdateKind::Delta, "delta"),
        (UpdateKind::Heartbeat, "heartbeat"),
    ];
    for (kind, expected) in &pairs {
        let json = serde_json::to_value(kind).unwrap();
        assert_eq!(json.as_str().unwrap(), *expected);
    }
}

// ============================================================================
// Section 16: Live cross-boundary integration: frankensqlite
// ============================================================================

fn sample_store_record() -> StoreRecord {
    let mut metadata = BTreeMap::new();
    metadata.insert("kind".to_string(), "benchmark".to_string());
    StoreRecord {
        store: StoreKind::BenchmarkLedger,
        key: "bench/latency".to_string(),
        value: vec![42, 0, 0, 0],
        metadata,
        revision: 1,
    }
}

#[test]
fn frankensqlite_store_record_schema_compliance() {
    let contract = frankensqlite_store_record_contract();
    let violations = verify_schema_compliance(&sample_store_record(), &contract);
    assert!(violations.is_empty(), "violations: {violations:?}");
}

#[test]
fn frankensqlite_store_record_deterministic_serde() {
    verify_deterministic_serde(&sample_store_record()).unwrap();
}

#[test]
fn frankensqlite_migration_receipt_schema_compliance() {
    let contract = frankensqlite_migration_receipt_contract();
    let receipt = MigrationReceipt {
        backend: "in_memory".to_string(),
        from_version: 1,
        to_version: 2,
        stores_touched: vec![StoreKind::ReplayIndex],
        records_touched: 5,
        state_hash_before: "abc123".to_string(),
        state_hash_after: "def456".to_string(),
    };
    let violations = verify_schema_compliance(&receipt, &contract);
    assert!(violations.is_empty(), "violations: {violations:?}");
}

#[test]
fn frankensqlite_storage_event_schema_and_log_compliance() {
    let event = StorageEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        component: "storage_adapter".to_string(),
        event: "put".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    // Schema contract
    let contract = frankensqlite_storage_event_contract();
    let violations = verify_schema_compliance(&event, &contract);
    assert!(violations.is_empty());
    // Also satisfies structured log
    let json = serde_json::to_value(&event).unwrap();
    let log_violations = verify_structured_log(&json, "frankensqlite");
    assert!(log_violations.is_empty());
}

#[test]
fn frankensqlite_store_kind_serialization_stable() {
    let pairs = [
        (StoreKind::ReplayIndex, "ReplayIndex"),
        (StoreKind::EvidenceIndex, "EvidenceIndex"),
        (StoreKind::BenchmarkLedger, "BenchmarkLedger"),
        (StoreKind::PolicyCache, "PolicyCache"),
        (StoreKind::PlasWitness, "PlasWitness"),
        (StoreKind::ReplacementLineage, "ReplacementLineage"),
        (StoreKind::IfcProvenance, "IfcProvenance"),
        (StoreKind::SpecializationIndex, "SpecializationIndex"),
    ];
    for (kind, expected) in &pairs {
        let json = serde_json::to_value(kind).unwrap();
        assert_eq!(json.as_str().unwrap(), *expected);
    }
}

#[test]
fn frankensqlite_error_codes_all_start_with_fe_stor() {
    let errors = [
        StorageError::InvalidContext {
            field: "trace_id".to_string(),
        },
        StorageError::InvalidKey {
            key: "bad".to_string(),
        },
        StorageError::InvalidQuery {
            detail: "bad".to_string(),
        },
        StorageError::NotFound {
            store: StoreKind::ReplayIndex,
            key: "missing".to_string(),
        },
        StorageError::SchemaVersionMismatch {
            expected: 1,
            actual: 2,
        },
        StorageError::MigrationFailed {
            from: 1,
            to: 0,
            reason: "downgrade".to_string(),
        },
        StorageError::IntegrityViolation {
            store: StoreKind::PolicyCache,
            detail: "corrupt".to_string(),
        },
        StorageError::BackendUnavailable {
            backend: "sqlite".to_string(),
            detail: "down".to_string(),
        },
        StorageError::WriteRejected {
            detail: "readonly".to_string(),
        },
    ];
    for err in &errors {
        assert!(
            verify_error_code_format(err.code(), "FE-STOR-"),
            "error code `{}` does not start with FE-STOR-",
            err.code()
        );
    }
}

#[test]
fn frankensqlite_adapter_operations_emit_events() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = EventContext::new("trace-integ", "decision-integ", "policy-integ").expect("ctx");
    adapter
        .put(
            StoreKind::ReplayIndex,
            "key-1".to_string(),
            vec![1],
            BTreeMap::new(),
            &ctx,
        )
        .expect("put");
    adapter
        .get(StoreKind::ReplayIndex, "key-1", &ctx)
        .expect("get");
    let events = StorageAdapter::events(&adapter);
    assert!(events.len() >= 2);
    for event in events {
        assert_eq!(event.trace_id, "trace-integ");
        assert_eq!(event.component, "storage_adapter");
    }
}

#[test]
fn frankensqlite_query_ordering_is_deterministic() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = EventContext::new("trace-ord", "decision-ord", "policy-ord").expect("ctx");
    for key in ["z-key", "a-key", "m-key"] {
        adapter
            .put(
                StoreKind::EvidenceIndex,
                key.to_string(),
                vec![1],
                BTreeMap::new(),
                &ctx,
            )
            .expect("put");
    }
    let first = adapter
        .query(StoreKind::EvidenceIndex, &StoreQuery::default(), &ctx)
        .expect("q1");
    let second = adapter
        .query(StoreKind::EvidenceIndex, &StoreQuery::default(), &ctx)
        .expect("q2");
    let k1: Vec<&str> = first.iter().map(|r| r.key.as_str()).collect();
    let k2: Vec<&str> = second.iter().map(|r| r.key.as_str()).collect();
    assert_eq!(k1, k2);
    assert_eq!(k1, vec!["a-key", "m-key", "z-key"]);
}

// ============================================================================
// Section 17: Live cross-boundary integration: fastapi_rust
// ============================================================================

fn sample_health_response() -> EndpointResponse<HealthStatusResponse> {
    EndpointResponse {
        status: "ok".to_string(),
        endpoint: "health".to_string(),
        trace_id: "trace-integ".to_string(),
        request_id: "req-integ".to_string(),
        data: Some(HealthStatusResponse {
            runtime_status: "healthy".to_string(),
            loaded_extensions: vec!["ext-a".to_string()],
            security_epoch: 10,
            gc_pressure_basis_points: 50,
        }),
        error: None,
        log: StructuredLogEvent {
            trace_id: "trace-integ".to_string(),
            decision_id: Some("decision-integ".to_string()),
            policy_id: Some("policy-integ".to_string()),
            component: "service.api".to_string(),
            event: "health.read".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        },
    }
}

#[test]
fn fastapi_endpoint_response_schema_compliance() {
    let contract = fastapi_endpoint_response_contract();
    let violations = verify_schema_compliance(&sample_health_response(), &contract);
    assert!(violations.is_empty(), "violations: {violations:?}");
}

#[test]
fn fastapi_endpoint_response_deterministic_serde() {
    verify_deterministic_serde(&sample_health_response()).unwrap();
}

#[test]
fn fastapi_endpoint_response_log_structured_compliance() {
    let json = serde_json::to_value(sample_health_response()).unwrap();
    let log_json = &json["log"];
    let violations = verify_structured_log(log_json, "fastapi_rust");
    assert!(violations.is_empty());
}

#[test]
fn fastapi_error_envelope_has_required_fields() {
    let error = ErrorEnvelope {
        error_code: "unauthorized".to_string(),
        message: "missing scope".to_string(),
        trace_id: "trace-1".to_string(),
        component: "service.api".to_string(),
        details: BTreeMap::new(),
    };
    let json = serde_json::to_value(&error).unwrap();
    let obj = json.as_object().unwrap();
    for field in ["error_code", "message", "trace_id", "component", "details"] {
        assert!(obj.contains_key(field));
    }
}

#[test]
fn fastapi_control_action_enum_stable() {
    let pairs = [
        (ControlAction::Start, "Start"),
        (ControlAction::Stop, "Stop"),
        (ControlAction::Suspend, "Suspend"),
        (ControlAction::Quarantine, "Quarantine"),
    ];
    for (action, expected) in &pairs {
        let json = serde_json::to_value(action).unwrap();
        assert_eq!(json.as_str().unwrap(), *expected);
    }
}

#[test]
fn fastapi_replay_command_enum_stable() {
    let pairs = [
        (ReplayCommand::Start, "Start"),
        (ReplayCommand::Stop, "Stop"),
        (ReplayCommand::Status, "Status"),
    ];
    for (cmd, expected) in &pairs {
        let json = serde_json::to_value(cmd).unwrap();
        assert_eq!(json.as_str().unwrap(), *expected);
    }
}

#[test]
fn fastapi_scope_constants_non_empty_and_prefixed() {
    for scope in [
        SCOPE_HEALTH_READ,
        SCOPE_CONTROL_WRITE,
        SCOPE_EVIDENCE_READ,
        SCOPE_REPLAY_READ,
        SCOPE_REPLAY_WRITE,
    ] {
        assert!(!scope.is_empty());
        assert!(scope.starts_with("engine."));
    }
}

#[test]
fn fastapi_request_context_serde() {
    let ctx = RequestContext {
        trace_id: "trace-1".to_string(),
        request_id: "req-1".to_string(),
        component: "service.api".to_string(),
        decision_id: Some("d-1".to_string()),
        policy_id: None,
    };
    verify_deterministic_serde(&ctx).unwrap();
}

#[test]
fn fastapi_auth_context_serde() {
    let auth = AuthContext {
        subject: "operator@example".to_string(),
        scopes: vec!["engine.health.read".to_string()],
    };
    verify_deterministic_serde(&auth).unwrap();
}

// ============================================================================
// Section 18: Cross-boundary data flow scenarios
// ============================================================================

#[test]
fn cross_boundary_storage_then_tui_deterministic() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = EventContext::new("trace-xb", "decision-xb", "policy-xb").expect("ctx");
    adapter
        .put(
            StoreKind::EvidenceIndex,
            "decision/1".to_string(),
            b"evidence-payload".to_vec(),
            BTreeMap::new(),
            &ctx,
        )
        .expect("put");
    let loaded = adapter
        .get(StoreKind::EvidenceIndex, "decision/1", &ctx)
        .expect("get")
        .expect("record exists");

    let replay_event = ReplayEventView::new(1, "storage_adapter", "put", "ok", 1_700_000_000_000);
    let replay = IncidentReplayView::snapshot(&loaded.key, "evidence-replay", vec![replay_event]);
    let envelope = AdapterEnvelope::new(
        "trace-xb",
        1_700_000_000_000,
        AdapterStream::IncidentReplay,
        UpdateKind::Snapshot,
        FrankentuiViewPayload::IncidentReplay(replay),
    );

    verify_deterministic_serde(&loaded).unwrap();
    verify_deterministic_serde(&envelope).unwrap();
}

#[test]
fn cross_boundary_service_and_storage_both_pass_structured_log() {
    let storage_event = StorageEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "storage_adapter".to_string(),
        event: "put".to_string(),
        outcome: "error".to_string(),
        error_code: Some("FE-STOR-0002".to_string()),
    };
    let service_log = StructuredLogEvent {
        trace_id: "trace-1".to_string(),
        decision_id: Some("d-1".to_string()),
        policy_id: Some("p-1".to_string()),
        component: "service.api".to_string(),
        event: "control.execute".to_string(),
        outcome: "error".to_string(),
        error_code: Some("unauthorized".to_string()),
    };
    let v1 = verify_structured_log(
        &serde_json::to_value(&storage_event).unwrap(),
        "frankensqlite",
    );
    let v2 = verify_structured_log(&serde_json::to_value(&service_log).unwrap(), "fastapi_rust");
    assert!(v1.is_empty());
    assert!(v2.is_empty());
}

#[test]
fn schema_contract_detects_missing_field_in_hand_crafted_json() {
    let contract = frankensqlite_store_record_contract();
    // missing "revision"
    let json = serde_json::json!({
        "store": "ReplayIndex",
        "key": "k1",
        "value": [1],
        "metadata": {}
    });
    let violations = contract.verify(&json);
    assert_eq!(violations.len(), 1);
    assert!(violations[0].detail.contains("revision"));

    // add it back
    let mut json2 = json.clone();
    json2["revision"] = serde_json::json!(1);
    let violations2 = contract.verify(&json2);
    assert!(violations2.is_empty());
}

#[test]
fn schema_contract_detects_wrong_type_in_hand_crafted_json() {
    let contract = frankensqlite_store_record_contract();
    let json = serde_json::json!({
        "store": "ReplayIndex",
        "key": "k1",
        "value": [1],
        "metadata": {},
        "revision": "not_a_number"
    });
    let violations = contract.verify(&json);
    assert_eq!(violations.len(), 1);
    assert!(violations[0].detail.contains("revision"));
    assert!(violations[0].detail.contains("number"));
}
