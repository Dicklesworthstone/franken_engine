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

use serde_json::Value;

const SCHEMA_JSON: &str = include_str!("../../../docs/frx_evidence_ledger_event_v1.schema.json");

fn parse_schema() -> Value {
    serde_json::from_str(SCHEMA_JSON).expect("evidence ledger event schema must parse")
}

#[test]
fn schema_parses_as_valid_json() {
    let schema = parse_schema();
    assert!(schema.is_object());
}

#[test]
fn schema_declares_json_schema_draft() {
    let schema = parse_schema();
    let draft = schema["$schema"].as_str().expect("$schema must be present");
    assert!(
        draft.contains("json-schema.org"),
        "$schema must reference json-schema.org: {draft}"
    );
}

#[test]
fn schema_has_expected_id() {
    let schema = parse_schema();
    assert_eq!(schema["$id"].as_str(), Some("frx.evidence.ledger.event.v1"));
}

#[test]
fn schema_root_type_is_object() {
    let schema = parse_schema();
    assert_eq!(schema["type"].as_str(), Some("object"));
}

#[test]
fn schema_disallows_additional_properties() {
    let schema = parse_schema();
    assert_eq!(schema["additionalProperties"].as_bool(), Some(false));
}

#[test]
fn schema_declares_required_fields() {
    let schema = parse_schema();
    let required = schema["required"]
        .as_array()
        .expect("required must be an array");
    assert!(
        required.len() >= 10,
        "schema must require at least 10 fields, got {}",
        required.len()
    );

    let required_set: BTreeSet<&str> = required
        .iter()
        .map(|v| v.as_str().expect("required entries must be strings"))
        .collect();

    for field in [
        "schema_version",
        "claim_id",
        "evidence_id",
        "policy_id",
        "trace_id",
        "decision_id",
        "event_type",
        "action",
        "artifact_hash",
        "signer",
        "created_at",
    ] {
        assert!(
            required_set.contains(field),
            "missing required field: {field}"
        );
    }
}

#[test]
fn schema_version_property_is_const() {
    let schema = parse_schema();
    let version_prop = &schema["properties"]["schema_version"];
    assert_eq!(
        version_prop["const"].as_str(),
        Some("frx.evidence.ledger.event.v1"),
        "schema_version must be a const matching the $id"
    );
}

#[test]
fn event_type_enum_covers_expected_decisions() {
    let schema = parse_schema();
    let event_type = &schema["properties"]["event_type"];
    let enum_values = event_type["enum"]
        .as_array()
        .expect("event_type must have enum constraint");

    let types: BTreeSet<&str> = enum_values
        .iter()
        .map(|v| v.as_str().expect("enum values must be strings"))
        .collect();

    for expected in [
        "compile_decision",
        "runtime_route_decision",
        "fallback_decision",
        "demotion_decision",
        "promotion_decision",
        "incident_event",
    ] {
        assert!(
            types.contains(expected),
            "missing event_type enum value: {expected}"
        );
    }
    assert_eq!(types.len(), 6, "event_type enum must have exactly 6 values");
}

#[test]
fn string_properties_have_min_length() {
    let schema = parse_schema();
    let props = schema["properties"]
        .as_object()
        .expect("properties must be an object");

    for field in [
        "claim_id",
        "evidence_id",
        "policy_id",
        "trace_id",
        "decision_id",
        "action",
        "signer",
    ] {
        let prop = &props[field];
        assert_eq!(
            prop["type"].as_str(),
            Some("string"),
            "{field} must be a string type"
        );
        assert!(
            prop["minLength"].as_u64().unwrap_or(0) >= 1,
            "{field} must have minLength >= 1"
        );
    }
}

#[test]
fn artifact_hash_has_minimum_length() {
    let schema = parse_schema();
    let artifact_hash = &schema["properties"]["artifact_hash"];
    assert_eq!(artifact_hash["type"].as_str(), Some("string"));
    assert!(
        artifact_hash["minLength"].as_u64().unwrap_or(0) >= 8,
        "artifact_hash must have minLength >= 8"
    );
}

#[test]
fn created_at_has_datetime_format() {
    let schema = parse_schema();
    let created_at = &schema["properties"]["created_at"];
    assert_eq!(created_at["type"].as_str(), Some("string"));
    assert_eq!(
        created_at["format"].as_str(),
        Some("date-time"),
        "created_at must use date-time format"
    );
}

#[test]
fn calibration_property_has_expected_numeric_fields() {
    let schema = parse_schema();
    let calibration = &schema["properties"]["calibration"];
    assert_eq!(calibration["type"].as_str(), Some("object"));
    assert_eq!(calibration["additionalProperties"].as_bool(), Some(false));

    let cal_props = calibration["properties"]
        .as_object()
        .expect("calibration properties must be an object");
    for field in ["ece", "brier", "coverage"] {
        assert_eq!(
            cal_props[field]["type"].as_str(),
            Some("number"),
            "calibration.{field} must be a number"
        );
    }
}

#[test]
fn provenance_property_has_required_fields() {
    let schema = parse_schema();
    let provenance = &schema["properties"]["provenance"];
    assert_eq!(provenance["type"].as_str(), Some("object"));
    assert_eq!(provenance["additionalProperties"].as_bool(), Some(false));

    let required = provenance["required"]
        .as_array()
        .expect("provenance must have required fields");
    let req_set: BTreeSet<&str> = required.iter().map(|v| v.as_str().unwrap()).collect();
    assert!(req_set.contains("build_id"));
    assert!(req_set.contains("toolchain"));
}

#[test]
fn all_declared_properties_have_type_constraints() {
    let schema = parse_schema();
    let props = schema["properties"]
        .as_object()
        .expect("properties must be an object");

    for (name, prop) in props {
        assert!(
            prop.get("type").is_some() || prop.get("const").is_some(),
            "property '{name}' must have a type or const constraint"
        );
    }
}

#[test]
fn deterministic_double_parse() {
    let a = parse_schema();
    let b = parse_schema();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Enrichment: untested properties and structural invariants
// ---------------------------------------------------------------------------

#[test]
fn rejected_alternatives_is_array_of_strings() {
    let schema = parse_schema();
    let ra = &schema["properties"]["rejected_alternatives"];
    assert_eq!(ra["type"].as_str(), Some("array"));
    assert_eq!(ra["items"]["type"].as_str(), Some("string"));
}

#[test]
fn assumptions_is_array_of_strings() {
    let schema = parse_schema();
    let assumptions = &schema["properties"]["assumptions"];
    assert_eq!(assumptions["type"].as_str(), Some("array"));
    assert_eq!(assumptions["items"]["type"].as_str(), Some("string"));
}

#[test]
fn loss_terms_is_object_with_number_additional_properties() {
    let schema = parse_schema();
    let lt = &schema["properties"]["loss_terms"];
    assert_eq!(lt["type"].as_str(), Some("object"));
    assert_eq!(
        lt["additionalProperties"]["type"].as_str(),
        Some("number"),
        "loss_terms values must be numbers"
    );
}

#[test]
fn signature_is_optional_string() {
    let schema = parse_schema();
    let sig = &schema["properties"]["signature"];
    assert_eq!(sig["type"].as_str(), Some("string"));
    let required: BTreeSet<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        !required.contains("signature"),
        "signature must be optional"
    );
}

#[test]
fn provenance_has_policy_bundle_hash_field() {
    let schema = parse_schema();
    let prov_props = schema["properties"]["provenance"]["properties"]
        .as_object()
        .unwrap();
    assert!(
        prov_props.contains_key("policy_bundle_hash"),
        "provenance must have policy_bundle_hash"
    );
    assert_eq!(
        prov_props["policy_bundle_hash"]["type"].as_str(),
        Some("string")
    );
}

#[test]
fn schema_has_title() {
    let schema = parse_schema();
    let title = schema["title"].as_str().expect("schema must have title");
    assert!(
        title.contains("Evidence"),
        "title should reference Evidence: {title}"
    );
}

#[test]
fn schema_uses_2020_12_draft() {
    let schema = parse_schema();
    let draft = schema["$schema"].as_str().unwrap();
    assert!(draft.contains("2020-12"), "must use 2020-12 draft: {draft}");
}

#[test]
fn required_field_count_is_exactly_eleven() {
    let schema = parse_schema();
    let required = schema["required"].as_array().unwrap();
    assert_eq!(required.len(), 11, "must have exactly 11 required fields");
}

#[test]
fn optional_fields_are_not_in_required() {
    let schema = parse_schema();
    let required: BTreeSet<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for optional in [
        "rejected_alternatives",
        "assumptions",
        "calibration",
        "loss_terms",
        "signature",
        "provenance",
    ] {
        assert!(
            !required.contains(optional),
            "{optional} must be optional (not required)"
        );
    }
}

#[test]
fn total_property_count() {
    let schema = parse_schema();
    let props = schema["properties"].as_object().unwrap();
    // 11 required + 6 optional = 17 total
    assert_eq!(props.len(), 17, "schema must have exactly 17 properties");
}

#[test]
fn event_type_enum_values_are_unique() {
    let schema = parse_schema();
    let values = schema["properties"]["event_type"]["enum"]
        .as_array()
        .unwrap();
    let unique: BTreeSet<&str> = values.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(
        unique.len(),
        values.len(),
        "event_type enum values must be unique"
    );
}

#[test]
fn calibration_required_fields_if_present() {
    let schema = parse_schema();
    let cal = &schema["properties"]["calibration"];
    let cal_props = cal["properties"].as_object().unwrap();
    // All three calibration fields should exist
    assert_eq!(cal_props.len(), 3);
    for field in ["ece", "brier", "coverage"] {
        assert!(
            cal_props.contains_key(field),
            "calibration missing field: {field}"
        );
    }
}

#[test]
fn provenance_build_id_and_toolchain_are_strings() {
    let schema = parse_schema();
    let prov = &schema["properties"]["provenance"]["properties"];
    assert_eq!(prov["build_id"]["type"].as_str(), Some("string"));
    assert_eq!(prov["toolchain"]["type"].as_str(), Some("string"));
}
