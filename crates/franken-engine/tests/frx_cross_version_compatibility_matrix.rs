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

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

const MATRIX_SCHEMA_VERSION: &str = "franken-engine.frx-cross-version-compat-matrix.v1";
const MATRIX_JSON: &str =
    include_str!("../../../docs/frx_cross_version_compatibility_matrix_v1.json");
const REPLAY_COMMAND: &str = "./scripts/e2e/frx_cross_version_compatibility_matrix_replay.sh ci";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CompatibilityMatrix {
    schema_version: String,
    generated_at_utc: String,
    policy_id: String,
    dimensions: MatrixDimensions,
    cases: Vec<CompatibilityCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MatrixDimensions {
    react_versions: Vec<String>,
    browsers: Vec<String>,
    api_families: Vec<String>,
    compatibility_routes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CompatibilityCase {
    case_id: String,
    api_family: String,
    surface: String,
    react18_status: String,
    react19_status: String,
    browser_constraints: Vec<String>,
    compatibility_route: String,
    deterministic_fallback_required: bool,
    risk_level: String,
    behavior_notes: String,
    test_selector_tags: Vec<String>,
    release_claim_tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MatrixLogEvent {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    scenario_id: String,
    outcome: String,
    error_code: Option<String>,
    replay_command: String,
}

fn parse_matrix() -> CompatibilityMatrix {
    serde_json::from_str(MATRIX_JSON).expect("compatibility matrix json must parse")
}

fn projection_from_tags<'a>(
    cases: &'a [CompatibilityCase],
    selector: impl Fn(&'a CompatibilityCase) -> &'a [String],
) -> BTreeMap<String, Vec<String>> {
    let mut projection = BTreeMap::<String, Vec<String>>::new();
    for case in cases {
        for tag in selector(case) {
            projection
                .entry(tag.clone())
                .or_default()
                .push(case.case_id.clone());
        }
    }

    for ids in projection.values_mut() {
        ids.sort();
        ids.dedup();
    }

    projection
}

#[test]
fn cross_version_matrix_covers_declared_api_families() {
    let matrix = parse_matrix();

    assert_eq!(matrix.schema_version, MATRIX_SCHEMA_VERSION);
    assert_eq!(matrix.policy_id, "policy-frx-cross-version-compat-v1");
    assert!(matrix.generated_at_utc.ends_with('Z'));

    let versions: BTreeSet<_> = matrix.dimensions.react_versions.iter().cloned().collect();
    assert!(versions.contains("18.3"));
    assert!(versions.contains("19.0"));

    let case_families: BTreeSet<_> = matrix
        .cases
        .iter()
        .map(|case| case.api_family.clone())
        .collect();
    let declared_families: BTreeSet<_> = matrix.dimensions.api_families.iter().cloned().collect();
    assert!(declared_families.is_subset(&case_families));

    let mut seen_case_ids = BTreeSet::new();
    for case in &matrix.cases {
        assert!(seen_case_ids.insert(case.case_id.clone()));
        assert!(!case.surface.is_empty());
        assert!(!case.react18_status.is_empty());
        assert!(!case.react19_status.is_empty());
        assert!(!case.browser_constraints.is_empty());
        assert!(!case.risk_level.is_empty());
        assert!(!case.behavior_notes.is_empty());
        assert!(!case.test_selector_tags.is_empty());
        assert!(!case.release_claim_tags.is_empty());
        assert!(
            matrix
                .dimensions
                .compatibility_routes
                .contains(&case.compatibility_route)
        );
        if case.deterministic_fallback_required {
            assert_ne!(case.compatibility_route, "compile_native");
        }
    }
}

#[test]
fn cross_version_matrix_drives_deterministic_test_selection_projection() {
    let matrix = parse_matrix();

    let projection_a = projection_from_tags(&matrix.cases, |case| &case.test_selector_tags);
    let projection_b = projection_from_tags(&matrix.cases, |case| &case.test_selector_tags);

    assert_eq!(projection_a, projection_b);
    assert!(projection_a.contains_key("frx02"));
    assert!(projection_a.contains_key("react18"));
    assert!(projection_a.contains_key("react19"));

    for case_ids in projection_a.values() {
        assert!(!case_ids.is_empty());
        let mut sorted = case_ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(*case_ids, sorted);
    }
}

#[test]
fn cross_version_matrix_drives_release_claim_projection_and_logs() {
    let matrix = parse_matrix();

    let release_projection = projection_from_tags(&matrix.cases, |case| &case.release_claim_tags);
    assert!(release_projection.contains_key("frx-semantic-parity"));
    assert!(release_projection.contains_key("frx-deterministic-fallback"));
    assert!(release_projection.contains_key("frx-browser-surface-coverage"));

    let events: Vec<MatrixLogEvent> = matrix
        .cases
        .iter()
        .take(3)
        .enumerate()
        .map(|(idx, case)| MatrixLogEvent {
            schema_version: "franken-engine.parser-log-event.v1".to_string(),
            trace_id: format!("trace-frx-cross-version-{}", case.case_id),
            decision_id: format!("decision-frx-cross-version-{idx}"),
            policy_id: matrix.policy_id.clone(),
            component: "frx_cross_version_compatibility_matrix".to_string(),
            event: "matrix_case_validated".to_string(),
            scenario_id: case.case_id.clone(),
            outcome: "pass".to_string(),
            error_code: None,
            replay_command: REPLAY_COMMAND.to_string(),
        })
        .collect();

    assert_eq!(events.len(), 3);
    for event in &events {
        assert_eq!(event.schema_version, "franken-engine.parser-log-event.v1");
        assert_eq!(event.policy_id, "policy-frx-cross-version-compat-v1");
        assert_eq!(event.component, "frx_cross_version_compatibility_matrix");
        assert_eq!(event.outcome, "pass");
        assert_eq!(event.error_code, None);
        assert_eq!(event.replay_command, REPLAY_COMMAND);
    }

    let jsonl = events
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .expect("events must serialize")
        .join("\n");
    assert!(jsonl.contains("matrix_case_validated"));
}

// ---------- parse_matrix ----------

#[test]
fn parse_matrix_schema_version_matches_constant() {
    let matrix = parse_matrix();
    assert_eq!(matrix.schema_version, MATRIX_SCHEMA_VERSION);
}

#[test]
fn parse_matrix_cases_have_unique_ids() {
    let matrix = parse_matrix();
    let ids: BTreeSet<_> = matrix.cases.iter().map(|c| c.case_id.clone()).collect();
    assert_eq!(ids.len(), matrix.cases.len());
}

#[test]
fn parse_matrix_dimensions_nonempty() {
    let matrix = parse_matrix();
    assert!(!matrix.dimensions.react_versions.is_empty());
    assert!(!matrix.dimensions.browsers.is_empty());
    assert!(!matrix.dimensions.api_families.is_empty());
    assert!(!matrix.dimensions.compatibility_routes.is_empty());
}

// ---------- projection_from_tags ----------

#[test]
fn projection_from_tags_empty_cases() {
    let cases: Vec<CompatibilityCase> = vec![];
    let projection = projection_from_tags(&cases, |c| &c.test_selector_tags);
    assert!(projection.is_empty());
}

#[test]
fn projection_from_tags_deduplicates_case_ids() {
    let matrix = parse_matrix();
    let projection = projection_from_tags(&matrix.cases, |c| &c.test_selector_tags);
    for case_ids in projection.values() {
        let set: BTreeSet<_> = case_ids.iter().collect();
        assert_eq!(
            set.len(),
            case_ids.len(),
            "case IDs should be unique per tag"
        );
    }
}

#[test]
fn projection_from_tags_is_deterministic() {
    let matrix = parse_matrix();
    let a = projection_from_tags(&matrix.cases, |c| &c.release_claim_tags);
    let b = projection_from_tags(&matrix.cases, |c| &c.release_claim_tags);
    assert_eq!(a, b);
}

#[test]
fn projection_from_tags_case_ids_are_sorted() {
    let matrix = parse_matrix();
    let projection = projection_from_tags(&matrix.cases, |c| &c.test_selector_tags);
    for case_ids in projection.values() {
        let mut sorted = case_ids.clone();
        sorted.sort();
        assert_eq!(*case_ids, sorted);
    }
}

// ---------- MatrixLogEvent serde ----------

#[test]
fn matrix_log_event_serde_roundtrip() {
    let event = MatrixLogEvent {
        schema_version: "franken-engine.parser-log-event.v1".to_string(),
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        component: "test".to_string(),
        event: "validated".to_string(),
        scenario_id: "s1".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        replay_command: "./replay.sh".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let deserialized: MatrixLogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, deserialized);
}

#[test]
fn matrix_log_event_with_error_code_serde() {
    let event = MatrixLogEvent {
        schema_version: "v1".to_string(),
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        scenario_id: "s".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("FE-TEST-001".to_string()),
        replay_command: "./replay.sh".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    assert!(json.contains("FE-TEST-001"));
    let deserialized: MatrixLogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deserialized.error_code, Some("FE-TEST-001".to_string()));
}

// ---------- matrix risk levels ----------

#[test]
fn all_cases_have_valid_risk_levels() {
    let matrix = parse_matrix();
    let valid_levels = ["low", "medium", "high", "critical"];
    for case in &matrix.cases {
        assert!(
            valid_levels.contains(&case.risk_level.as_str()),
            "unexpected risk level `{}` for case {}",
            case.risk_level,
            case.case_id
        );
    }
}

// ---------- compatibility routes ----------

#[test]
fn all_cases_use_declared_compatibility_routes() {
    let matrix = parse_matrix();
    for case in &matrix.cases {
        assert!(
            matrix
                .dimensions
                .compatibility_routes
                .contains(&case.compatibility_route),
            "case {} uses undeclared route: {}",
            case.case_id,
            case.compatibility_route
        );
    }
}

// ---------- deterministic double parse ----------

#[test]
fn cross_version_matrix_deterministic_double_parse() {
    let a = parse_matrix();
    let b = parse_matrix();
    assert_eq!(a, b);
}

// ---------- all cases have test_selector_tags ----------

#[test]
fn all_cases_have_at_least_one_test_selector_tag() {
    let matrix = parse_matrix();
    for case in &matrix.cases {
        assert!(
            !case.test_selector_tags.is_empty(),
            "case {} missing test_selector_tags",
            case.case_id
        );
    }
}

// ---------- all cases have release_claim_tags ----------

#[test]
fn all_cases_have_at_least_one_release_claim_tag() {
    let matrix = parse_matrix();
    for case in &matrix.cases {
        assert!(
            !case.release_claim_tags.is_empty(),
            "case {} missing release_claim_tags",
            case.case_id
        );
    }
}

// ---------- doc file exists and is nonempty ----------

#[test]
fn cross_version_compatibility_doc_is_nonempty() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRX_CROSS_VERSION_COMPATIBILITY_MATRIX_V1.md");
    let content = std::fs::read_to_string(&path).expect("read doc");
    assert!(!content.is_empty());
}

#[test]
fn matrix_schema_version_matches_constant() {
    let matrix = parse_matrix();
    assert_eq!(matrix.schema_version, MATRIX_SCHEMA_VERSION);
}

#[test]
fn matrix_generated_at_utc_ends_with_z() {
    let matrix = parse_matrix();
    assert!(
        matrix.generated_at_utc.ends_with('Z'),
        "generated_at_utc must end with Z"
    );
}

#[test]
fn matrix_cases_have_unique_case_ids() {
    let matrix = parse_matrix();
    let mut seen = BTreeSet::new();
    for case in &matrix.cases {
        assert!(
            seen.insert(&case.case_id),
            "duplicate case_id: {}",
            case.case_id
        );
    }
}

#[test]
fn matrix_has_nonempty_policy_id() {
    let matrix = parse_matrix();
    assert!(!matrix.policy_id.trim().is_empty());
}

#[test]
fn matrix_dimensions_have_nonempty_react_versions() {
    let matrix = parse_matrix();
    assert!(!matrix.dimensions.react_versions.is_empty());
    for version in &matrix.dimensions.react_versions {
        assert!(!version.trim().is_empty());
    }
}

#[test]
fn matrix_deterministic_double_parse() {
    let a = parse_matrix();
    let b = parse_matrix();
    assert_eq!(a.schema_version, b.schema_version);
    assert_eq!(a.cases.len(), b.cases.len());
}

// ────────────────────────────────────────────────────────────
// Batch enrichment: browser coverage, surface nonempty,
// deterministic_fallback_required consistency, case_id prefix,
// react status values, compatibility route set, dimension completeness
// ────────────────────────────────────────────────────────────

#[test]
fn all_cases_have_nonempty_behavior_notes() {
    let matrix = parse_matrix();
    for case in &matrix.cases {
        assert!(
            !case.behavior_notes.trim().is_empty(),
            "case {} has empty behavior_notes",
            case.case_id
        );
    }
}

#[test]
fn all_cases_have_nonempty_surface() {
    let matrix = parse_matrix();
    for case in &matrix.cases {
        assert!(
            !case.surface.trim().is_empty(),
            "case {} has empty surface",
            case.case_id
        );
    }
}

#[test]
fn browser_constraints_are_all_nonempty_strings() {
    let matrix = parse_matrix();
    for case in &matrix.cases {
        for constraint in &case.browser_constraints {
            assert!(
                !constraint.trim().is_empty(),
                "case {} has empty browser constraint",
                case.case_id
            );
        }
    }
}

#[test]
fn react18_and_react19_statuses_are_nonempty() {
    let matrix = parse_matrix();
    for case in &matrix.cases {
        assert!(
            !case.react18_status.trim().is_empty(),
            "case {} has empty react18_status",
            case.case_id
        );
        assert!(
            !case.react19_status.trim().is_empty(),
            "case {} has empty react19_status",
            case.case_id
        );
    }
}

#[test]
fn deterministic_fallback_cases_have_non_compile_native_route() {
    let matrix = parse_matrix();
    for case in &matrix.cases {
        if case.deterministic_fallback_required {
            assert_ne!(
                case.compatibility_route, "compile_native",
                "case {} requires fallback but has compile_native route",
                case.case_id
            );
        }
    }
}

#[test]
fn dimensions_browsers_are_nonempty() {
    let matrix = parse_matrix();
    assert!(!matrix.dimensions.browsers.is_empty());
    for browser in &matrix.dimensions.browsers {
        assert!(!browser.trim().is_empty());
    }
}

#[test]
fn projection_from_release_claim_tags_covers_all_cases() {
    let matrix = parse_matrix();
    let projection = projection_from_tags(&matrix.cases, |c| &c.release_claim_tags);
    let all_case_ids: BTreeSet<_> = matrix.cases.iter().map(|c| c.case_id.clone()).collect();
    let covered: BTreeSet<_> = projection.values().flatten().cloned().collect();
    for case_id in &all_case_ids {
        assert!(
            covered.contains(case_id),
            "case {case_id} not covered by any release_claim_tag"
        );
    }
}

// ────────────────────────────────────────────────────────────
// Enrichment batch: clone/debug, serde edge cases, invariant
// checks, field validation, projection properties
// ────────────────────────────────────────────────────────────

#[test]
fn compatibility_matrix_clone_preserves_equality() {
    let matrix = parse_matrix();
    let cloned = matrix.clone();
    assert_eq!(matrix, cloned);
    assert_eq!(matrix.cases.len(), cloned.cases.len());
    assert_eq!(matrix.dimensions, cloned.dimensions);
}

#[test]
fn compatibility_matrix_debug_contains_schema_version() {
    let matrix = parse_matrix();
    let debug_str = format!("{:?}", matrix);
    assert!(
        debug_str.contains("schema_version"),
        "Debug output should contain schema_version field"
    );
    assert!(
        debug_str.contains(&matrix.schema_version),
        "Debug output should contain schema version value"
    );
}

#[test]
fn compatibility_case_clone_preserves_all_fields() {
    let matrix = parse_matrix();
    for case in &matrix.cases {
        let cloned = case.clone();
        assert_eq!(case.case_id, cloned.case_id);
        assert_eq!(case.api_family, cloned.api_family);
        assert_eq!(case.surface, cloned.surface);
        assert_eq!(case.react18_status, cloned.react18_status);
        assert_eq!(case.react19_status, cloned.react19_status);
        assert_eq!(case.browser_constraints, cloned.browser_constraints);
        assert_eq!(case.compatibility_route, cloned.compatibility_route);
        assert_eq!(
            case.deterministic_fallback_required,
            cloned.deterministic_fallback_required
        );
        assert_eq!(case.risk_level, cloned.risk_level);
        assert_eq!(case.behavior_notes, cloned.behavior_notes);
        assert_eq!(case.test_selector_tags, cloned.test_selector_tags);
        assert_eq!(case.release_claim_tags, cloned.release_claim_tags);
    }
}

#[test]
fn matrix_log_event_serde_roundtrip_with_all_fields_populated() {
    let event = MatrixLogEvent {
        schema_version: "franken-engine.parser-log-event.v1".to_string(),
        trace_id: "trace-roundtrip-full".to_string(),
        decision_id: "decision-roundtrip-full".to_string(),
        policy_id: "policy-frx-cross-version-compat-v1".to_string(),
        component: "frx_cross_version_compatibility_matrix".to_string(),
        event: "matrix_case_validated".to_string(),
        scenario_id: "scenario-full".to_string(),
        outcome: "pass".to_string(),
        error_code: Some("FE-COMPAT-999".to_string()),
        replay_command: REPLAY_COMMAND.to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let rt: MatrixLogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, rt);
    assert!(json.contains("FE-COMPAT-999"));
    assert!(json.contains(REPLAY_COMMAND));
}

#[test]
fn matrix_log_event_deserialize_from_known_json() {
    let json = r#"{
        "schema_version": "v1",
        "trace_id": "t-known",
        "decision_id": "d-known",
        "policy_id": "p-known",
        "component": "test_component",
        "event": "test_event",
        "scenario_id": "s-known",
        "outcome": "fail",
        "error_code": "ERR-42",
        "replay_command": "./run.sh"
    }"#;
    let event: MatrixLogEvent = serde_json::from_str(json).expect("deserialize known json");
    assert_eq!(event.trace_id, "t-known");
    assert_eq!(event.outcome, "fail");
    assert_eq!(event.error_code, Some("ERR-42".to_string()));
}

#[test]
fn matrix_log_event_deserialize_null_error_code() {
    let json = r#"{
        "schema_version": "v1",
        "trace_id": "t-null",
        "decision_id": "d-null",
        "policy_id": "p-null",
        "component": "c",
        "event": "e",
        "scenario_id": "s-null",
        "outcome": "pass",
        "error_code": null,
        "replay_command": "./replay.sh"
    }"#;
    let event: MatrixLogEvent = serde_json::from_str(json).expect("deserialize null error_code");
    assert_eq!(event.error_code, None);
}

#[test]
fn matrix_log_event_clone_and_debug() {
    let event = MatrixLogEvent {
        schema_version: "v1".to_string(),
        trace_id: "t-debug".to_string(),
        decision_id: "d-debug".to_string(),
        policy_id: "p-debug".to_string(),
        component: "comp".to_string(),
        event: "evt".to_string(),
        scenario_id: "scen".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        replay_command: "./r.sh".to_string(),
    };
    let cloned = event.clone();
    assert_eq!(event, cloned);
    let debug = format!("{:?}", event);
    assert!(debug.contains("t-debug"));
    assert!(debug.contains("MatrixLogEvent"));
}

#[test]
fn matrix_log_event_jsonl_batch_serialization() {
    let events: Vec<MatrixLogEvent> = (0..5)
        .map(|i| MatrixLogEvent {
            schema_version: "v1".to_string(),
            trace_id: format!("trace-batch-{i}"),
            decision_id: format!("decision-batch-{i}"),
            policy_id: "policy-batch".to_string(),
            component: "batch_comp".to_string(),
            event: "batch_event".to_string(),
            scenario_id: format!("scenario-batch-{i}"),
            outcome: if i % 2 == 0 { "pass" } else { "fail" }.to_string(),
            error_code: if i % 2 == 1 {
                Some(format!("ERR-{i}"))
            } else {
                None
            },
            replay_command: REPLAY_COMMAND.to_string(),
        })
        .collect();

    let lines: Vec<String> = events
        .iter()
        .map(|e| serde_json::to_string(e).expect("serialize"))
        .collect();

    assert_eq!(lines.len(), 5);
    for (i, line) in lines.iter().enumerate() {
        let rt: MatrixLogEvent = serde_json::from_str(line).expect("deserialize line");
        assert_eq!(rt, events[i]);
    }
}

#[test]
fn projection_from_test_selector_tags_covers_all_cases() {
    let matrix = parse_matrix();
    let projection = projection_from_tags(&matrix.cases, |c| &c.test_selector_tags);
    let all_case_ids: BTreeSet<_> = matrix.cases.iter().map(|c| c.case_id.clone()).collect();
    let covered: BTreeSet<_> = projection.values().flatten().cloned().collect();
    for case_id in &all_case_ids {
        assert!(
            covered.contains(case_id),
            "case {case_id} not covered by any test_selector_tag"
        );
    }
}

#[test]
fn browser_constraints_reference_declared_browsers() {
    let matrix = parse_matrix();
    let declared: BTreeSet<_> = matrix.dimensions.browsers.iter().cloned().collect();
    for case in &matrix.cases {
        for constraint in &case.browser_constraints {
            assert!(
                declared.contains(constraint),
                "case {} references undeclared browser constraint: {}",
                case.case_id,
                constraint
            );
        }
    }
}

#[test]
fn api_families_in_cases_match_declared_dimensions() {
    let matrix = parse_matrix();
    let declared: BTreeSet<_> = matrix.dimensions.api_families.iter().cloned().collect();
    for case in &matrix.cases {
        assert!(
            declared.contains(&case.api_family),
            "case {} uses undeclared api_family: {}",
            case.case_id,
            case.api_family
        );
    }
}

#[test]
fn matrix_dimensions_have_no_duplicates() {
    let matrix = parse_matrix();

    let rv_set: BTreeSet<_> = matrix.dimensions.react_versions.iter().collect();
    assert_eq!(rv_set.len(), matrix.dimensions.react_versions.len());

    let br_set: BTreeSet<_> = matrix.dimensions.browsers.iter().collect();
    assert_eq!(br_set.len(), matrix.dimensions.browsers.len());

    let af_set: BTreeSet<_> = matrix.dimensions.api_families.iter().collect();
    assert_eq!(af_set.len(), matrix.dimensions.api_families.len());

    let cr_set: BTreeSet<_> = matrix.dimensions.compatibility_routes.iter().collect();
    assert_eq!(cr_set.len(), matrix.dimensions.compatibility_routes.len());
}

#[test]
fn matrix_dimensions_clone_preserves_equality() {
    let matrix = parse_matrix();
    let dims = matrix.dimensions.clone();
    assert_eq!(matrix.dimensions, dims);
    assert_eq!(
        matrix.dimensions.react_versions.len(),
        dims.react_versions.len()
    );
    assert_eq!(matrix.dimensions.browsers.len(), dims.browsers.len());
}

#[test]
fn high_risk_cases_require_deterministic_fallback() {
    let matrix = parse_matrix();
    for case in &matrix.cases {
        if case.risk_level == "critical" {
            assert!(
                case.deterministic_fallback_required,
                "critical-risk case {} should require deterministic fallback",
                case.case_id
            );
        }
    }
}

#[test]
fn matrix_log_event_equality_distinguishes_different_trace_ids() {
    let base = MatrixLogEvent {
        schema_version: "v1".to_string(),
        trace_id: "trace-a".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        scenario_id: "s".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        replay_command: "./r.sh".to_string(),
    };
    let mut different = base.clone();
    different.trace_id = "trace-b".to_string();
    assert_ne!(base, different);
}

#[test]
fn matrix_case_ids_have_consistent_prefix() {
    let matrix = parse_matrix();
    if matrix.cases.is_empty() {
        return;
    }
    // Extract the prefix pattern from the first case_id (everything before the last hyphen-number)
    let first_id = &matrix.cases[0].case_id;
    let prefix = first_id
        .rfind('-')
        .map(|pos| &first_id[..pos])
        .unwrap_or(first_id.as_str());
    for case in &matrix.cases {
        assert!(
            case.case_id.starts_with(prefix),
            "case_id {} does not share prefix {} with first case",
            case.case_id,
            prefix
        );
    }
}

#[test]
fn projection_tag_keys_are_nonempty_strings() {
    let matrix = parse_matrix();
    let test_proj = projection_from_tags(&matrix.cases, |c| &c.test_selector_tags);
    for key in test_proj.keys() {
        assert!(
            !key.trim().is_empty(),
            "empty tag key in test_selector projection"
        );
    }
    let release_proj = projection_from_tags(&matrix.cases, |c| &c.release_claim_tags);
    for key in release_proj.keys() {
        assert!(
            !key.trim().is_empty(),
            "empty tag key in release_claim projection"
        );
    }
}
