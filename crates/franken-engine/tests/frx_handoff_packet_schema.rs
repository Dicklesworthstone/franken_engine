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

const SCHEMA_JSON: &str = include_str!("../../../docs/frx_handoff_packet_schema_v1.json");

fn parse_schema() -> Value {
    serde_json::from_str(SCHEMA_JSON).expect("handoff packet schema must parse")
}

#[test]
fn schema_parses_as_valid_json() {
    let schema = parse_schema();
    assert!(schema.is_object());
}

#[test]
fn schema_declares_json_schema_draft_2020() {
    let schema = parse_schema();
    let draft = schema["$schema"].as_str().expect("$schema must be present");
    assert!(
        draft.contains("json-schema.org/draft/2020-12"),
        "$schema must reference 2020-12 draft: {draft}"
    );
}

#[test]
fn schema_has_expected_id() {
    let schema = parse_schema();
    assert_eq!(schema["$id"].as_str(), Some("frx.handoff.packet.v1"));
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
fn schema_required_fields_count() {
    let schema = parse_schema();
    let required = schema["required"]
        .as_array()
        .expect("required must be an array");
    assert_eq!(required.len(), 16, "must have exactly 16 required fields");
}

#[test]
fn schema_required_fields_include_core_set() {
    let schema = parse_schema();
    let required: BTreeSet<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for field in [
        "packet_id",
        "producer_track",
        "consumer_track",
        "wave_id",
        "artifact_ids",
        "confidence",
        "readiness_class",
        "created_at",
        "entry_criteria",
        "exit_criteria",
        "handoff_package",
    ] {
        assert!(required.contains(field), "missing required: {field}");
    }
}

#[test]
fn wave_id_enum_has_4_values() {
    let schema = parse_schema();
    let wave_enum = schema["properties"]["wave_id"]["enum"]
        .as_array()
        .expect("wave_id must have enum");
    assert_eq!(wave_enum.len(), 4);
    let values: BTreeSet<&str> = wave_enum.iter().map(|v| v.as_str().unwrap()).collect();
    for expected in ["wave_0", "wave_1", "wave_2", "wave_3"] {
        assert!(values.contains(expected), "missing wave: {expected}");
    }
}

#[test]
fn readiness_class_enum_has_3_values() {
    let schema = parse_schema();
    let rc_enum = schema["properties"]["readiness_class"]["enum"]
        .as_array()
        .expect("readiness_class must have enum");
    assert_eq!(rc_enum.len(), 3);
    let values: BTreeSet<&str> = rc_enum.iter().map(|v| v.as_str().unwrap()).collect();
    for expected in ["ready_now", "ready_next", "gated"] {
        assert!(values.contains(expected), "missing readiness: {expected}");
    }
}

#[test]
fn confidence_has_zero_to_one_bounds() {
    let schema = parse_schema();
    let confidence = &schema["properties"]["confidence"];
    assert_eq!(confidence["type"].as_str(), Some("number"));
    assert_eq!(confidence["minimum"].as_f64(), Some(0.0));
    assert_eq!(confidence["maximum"].as_f64(), Some(1.0));
}

#[test]
fn created_at_has_datetime_format() {
    let schema = parse_schema();
    let created_at = &schema["properties"]["created_at"];
    assert_eq!(created_at["type"].as_str(), Some("string"));
    assert_eq!(created_at["format"].as_str(), Some("date-time"));
}

#[test]
fn producer_track_has_pattern() {
    let schema = parse_schema();
    let pt = &schema["properties"]["producer_track"];
    assert_eq!(pt["type"].as_str(), Some("string"));
    assert!(
        pt["pattern"].as_str().is_some(),
        "producer_track must have pattern constraint"
    );
}

#[test]
fn artifact_ids_is_array_with_min_items() {
    let schema = parse_schema();
    let ai = &schema["properties"]["artifact_ids"];
    assert_eq!(ai["type"].as_str(), Some("array"));
    assert_eq!(ai["minItems"].as_u64(), Some(1));
}

#[test]
fn max_wait_seconds_is_positive_integer() {
    let schema = parse_schema();
    let mws = &schema["properties"]["max_wait_seconds"];
    assert_eq!(mws["type"].as_str(), Some("integer"));
    assert!(mws["minimum"].as_u64().unwrap_or(0) >= 1);
}

#[test]
fn defs_has_criterion_and_attestation_and_package() {
    let schema = parse_schema();
    let defs = schema["$defs"]
        .as_object()
        .expect("$defs must be an object");
    let def_keys: BTreeSet<&str> = defs.keys().map(String::as_str).collect();
    for expected in ["criterion", "criterion_attestation", "handoff_package"] {
        assert!(def_keys.contains(expected), "missing $def: {expected}");
    }
}

#[test]
fn criterion_def_has_expected_required_fields() {
    let schema = parse_schema();
    let criterion = &schema["$defs"]["criterion"];
    assert_eq!(criterion["type"].as_str(), Some("object"));
    assert_eq!(criterion["additionalProperties"].as_bool(), Some(false));
    let required: BTreeSet<&str> = criterion["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for field in ["criterion_id", "bead_id", "required_status", "mandatory"] {
        assert!(required.contains(field), "criterion missing: {field}");
    }
}

#[test]
fn criterion_required_status_enum_has_3_values() {
    let schema = parse_schema();
    let status_enum = &schema["$defs"]["criterion"]["properties"]["required_status"]["enum"];
    let values: BTreeSet<&str> = status_enum
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(values, BTreeSet::from(["open", "in_progress", "closed"]));
}

#[test]
fn handoff_package_def_has_expected_required_fields() {
    let schema = parse_schema();
    let pkg = &schema["$defs"]["handoff_package"];
    assert_eq!(pkg["type"].as_str(), Some("object"));
    assert_eq!(pkg["additionalProperties"].as_bool(), Some(false));
    let required: BTreeSet<&str> = pkg["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for field in [
        "changed_beads",
        "artifact_links",
        "open_risks",
        "next_step_recommendations",
        "completeness_score_milli",
    ] {
        assert!(required.contains(field), "package missing: {field}");
    }
}

#[test]
fn completeness_score_milli_has_bounded_range() {
    let schema = parse_schema();
    let score = &schema["$defs"]["handoff_package"]["properties"]["completeness_score_milli"];
    assert_eq!(score["type"].as_str(), Some("integer"));
    assert_eq!(score["minimum"].as_u64(), Some(0));
    assert_eq!(score["maximum"].as_u64(), Some(1000));
}

#[test]
fn all_properties_have_type_constraints() {
    let schema = parse_schema();
    let props = schema["properties"]
        .as_object()
        .expect("properties must be object");
    for (name, prop) in props {
        assert!(
            prop.get("type").is_some() || prop.get("$ref").is_some(),
            "property '{name}' must have type or $ref"
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
// Enrichment: criterion_attestation def
// ---------------------------------------------------------------------------

#[test]
fn criterion_attestation_def_has_expected_required_fields() {
    let schema = parse_schema();
    let att = &schema["$defs"]["criterion_attestation"];
    assert_eq!(att["type"].as_str(), Some("object"));
    assert_eq!(att["additionalProperties"].as_bool(), Some(false));
    let required: BTreeSet<&str> = att["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for field in ["criterion_id", "bead_id", "bead_status", "artifact_ref"] {
        assert!(required.contains(field), "attestation missing: {field}");
    }
}

#[test]
fn criterion_attestation_bead_status_enum_matches_criterion_required_status() {
    let schema = parse_schema();
    let crit_status: BTreeSet<&str> = schema["$defs"]["criterion"]["properties"]["required_status"]
        ["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let att_status: BTreeSet<&str> =
        schema["$defs"]["criterion_attestation"]["properties"]["bead_status"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
    assert_eq!(
        crit_status, att_status,
        "criterion.required_status and attestation.bead_status enums must match"
    );
}

// ---------------------------------------------------------------------------
// Enrichment: consumer_track pattern, contract_version, notes, array items
// ---------------------------------------------------------------------------

#[test]
fn consumer_track_has_same_pattern_as_producer_track() {
    let schema = parse_schema();
    let producer_pattern = schema["properties"]["producer_track"]["pattern"]
        .as_str()
        .unwrap();
    let consumer_pattern = schema["properties"]["consumer_track"]["pattern"]
        .as_str()
        .unwrap();
    assert_eq!(
        producer_pattern, consumer_pattern,
        "producer and consumer track patterns must match"
    );
}

#[test]
fn contract_version_has_min_length() {
    let schema = parse_schema();
    let cv = &schema["properties"]["contract_version"];
    assert_eq!(cv["type"].as_str(), Some("string"));
    assert!(
        cv["minLength"].as_u64().unwrap_or(0) >= 1,
        "contract_version must have minLength >= 1"
    );
}

#[test]
fn notes_property_is_optional_string() {
    let schema = parse_schema();
    let notes = &schema["properties"]["notes"];
    assert_eq!(notes["type"].as_str(), Some("string"));
    let required: BTreeSet<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        !required.contains("notes"),
        "notes must be optional (not in required)"
    );
}

#[test]
fn artifact_ids_items_are_non_empty_strings() {
    let schema = parse_schema();
    let items = &schema["properties"]["artifact_ids"]["items"];
    assert_eq!(items["type"].as_str(), Some("string"));
    assert!(
        items["minLength"].as_u64().unwrap_or(0) >= 1,
        "artifact_ids items must have minLength >= 1"
    );
}

#[test]
fn entry_criteria_items_reference_criterion_def() {
    let schema = parse_schema();
    let entry = &schema["properties"]["entry_criteria"];
    assert_eq!(entry["type"].as_str(), Some("array"));
    assert_eq!(entry["minItems"].as_u64(), Some(1));
    let ref_path = entry["items"]["$ref"].as_str().unwrap();
    assert_eq!(ref_path, "#/$defs/criterion");
}

#[test]
fn exit_criteria_items_reference_criterion_def() {
    let schema = parse_schema();
    let exit = &schema["properties"]["exit_criteria"];
    assert_eq!(exit["type"].as_str(), Some("array"));
    assert_eq!(exit["minItems"].as_u64(), Some(1));
    let ref_path = exit["items"]["$ref"].as_str().unwrap();
    assert_eq!(ref_path, "#/$defs/criterion");
}

#[test]
fn criteria_attestations_items_reference_attestation_def() {
    let schema = parse_schema();
    let att = &schema["properties"]["criteria_attestations"];
    assert_eq!(att["type"].as_str(), Some("array"));
    assert_eq!(att["minItems"].as_u64(), Some(1));
    let ref_path = att["items"]["$ref"].as_str().unwrap();
    assert_eq!(ref_path, "#/$defs/criterion_attestation");
}

#[test]
fn handoff_package_ref_points_to_defs() {
    let schema = parse_schema();
    let pkg_ref = schema["properties"]["handoff_package"]["$ref"]
        .as_str()
        .unwrap();
    assert_eq!(pkg_ref, "#/$defs/handoff_package");
}

#[test]
fn handoff_package_arrays_require_min_one_item() {
    let schema = parse_schema();
    let pkg = &schema["$defs"]["handoff_package"]["properties"];
    for array_field in [
        "changed_beads",
        "artifact_links",
        "open_risks",
        "next_step_recommendations",
    ] {
        assert_eq!(
            pkg[array_field]["type"].as_str(),
            Some("array"),
            "{array_field} must be array"
        );
        assert_eq!(
            pkg[array_field]["minItems"].as_u64(),
            Some(1),
            "{array_field} must have minItems=1"
        );
        assert_eq!(
            pkg[array_field]["items"]["type"].as_str(),
            Some("string"),
            "{array_field} items must be strings"
        );
    }
}

#[test]
fn criterion_string_fields_have_min_length() {
    let schema = parse_schema();
    let crit_props = schema["$defs"]["criterion"]["properties"]
        .as_object()
        .unwrap();
    for field in ["criterion_id", "bead_id", "required_artifact"] {
        assert!(
            crit_props[field]["minLength"].as_u64().unwrap_or(0) >= 1,
            "criterion.{field} must have minLength >= 1"
        );
    }
}

#[test]
fn owner_fields_are_required_strings() {
    let schema = parse_schema();
    let required: BTreeSet<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for field in ["producer_owner", "consumer_owner"] {
        assert!(required.contains(field), "{field} must be required");
        let prop = &schema["properties"][field];
        assert_eq!(prop["type"].as_str(), Some("string"));
        assert!(
            prop["minLength"].as_u64().unwrap_or(0) >= 1,
            "{field} must have minLength >= 1"
        );
    }
}

#[test]
fn schema_has_title() {
    let schema = parse_schema();
    let title = schema["title"].as_str().expect("schema must have title");
    assert!(!title.is_empty(), "schema title must be non-empty");
}

#[test]
fn total_required_field_count_equals_property_count_minus_optional() {
    let schema = parse_schema();
    let required = schema["required"].as_array().unwrap().len();
    let props = schema["properties"].as_object().unwrap().len();
    // notes is the only optional field
    assert_eq!(
        required,
        props - 1,
        "all properties except notes must be required"
    );
}
