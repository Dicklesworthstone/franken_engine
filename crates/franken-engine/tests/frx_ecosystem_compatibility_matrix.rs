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

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};

const MATRIX_SCHEMA_VERSION: &str = "frx.ecosystem-compatibility-matrix.v1";
const MATRIX_JSON: &str = include_str!("../../../docs/frx_ecosystem_compatibility_matrix_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EcosystemMatrix {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: MatrixTrack,
    required_structured_log_fields: Vec<String>,
    entries: Vec<CompatibilityEntry>,
    known_gaps: Vec<KnownGap>,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MatrixTrack {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CompatibilityEntry {
    stack_id: String,
    category: String,
    surface: String,
    compatibility_status: String,
    integration_test_id: String,
    evidence_bundle_ref: String,
    fallback_route: String,
    roadmap_status: String,
    notes: String,
    structured_log_template: StructuredLogTemplate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StructuredLogTemplate {
    scenario_id: String,
    component: String,
    decision_path: String,
    outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct KnownGap {
    stack_id: String,
    surface: String,
    fallback_route: String,
    roadmap_status: String,
    owner_lane: String,
    target_milestone: String,
    blocking_issue: String,
    error_code: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_matrix() -> EcosystemMatrix {
    serde_json::from_str(MATRIX_JSON).expect("ecosystem compatibility matrix json must parse")
}

fn entry_index(matrix: &EcosystemMatrix) -> BTreeMap<&str, &CompatibilityEntry> {
    matrix
        .entries
        .iter()
        .map(|entry| (entry.stack_id.as_str(), entry))
        .collect()
}

#[test]
fn frx_07_3_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_ECOSYSTEM_COMPATIBILITY_MATRIX_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Ecosystem Compatibility Matrix V1",
        "## Scope",
        "## Coverage Dimensions",
        "## High-Impact Stack Coverage",
        "## Legacy API Surface Coverage",
        "## Known Gaps and Fallback/Roadmap Status",
        "## Deterministic Logging and Evidence Contract",
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
fn frx_07_3_matrix_is_versioned_and_track_bound() {
    let matrix = parse_matrix();

    assert_eq!(matrix.schema_version, MATRIX_SCHEMA_VERSION);
    assert_eq!(matrix.bead_id, "bd-mjh3.7.3");
    assert_eq!(matrix.generated_by, "bd-mjh3.7.3");
    assert_eq!(matrix.track.id, "FRX-07.3");
    assert_eq!(matrix.track.name, "Ecosystem Compatibility Matrix");
    assert!(matrix.generated_at_utc.ends_with('Z'));
    assert!(!matrix.entries.is_empty());
}

#[test]
fn frx_07_3_covers_required_high_impact_stacks_and_legacy_apis() {
    let matrix = parse_matrix();
    let entries = entry_index(&matrix);

    for stack in [
        "redux-toolkit",
        "zustand",
        "recoil",
        "react-router",
        "react-hook-form",
        "formik",
        "tanstack-query",
        "apollo-client",
        "legacy-class-components",
        "portals-refs",
        "context-error-boundaries",
    ] {
        assert!(
            entries.contains_key(stack),
            "missing required stack: {stack}"
        );
    }

    let categories: BTreeSet<_> = matrix
        .entries
        .iter()
        .map(|entry| entry.category.as_str())
        .collect();
    for required in ["state_lib", "routing", "forms", "data_lib", "legacy_api"] {
        assert!(
            categories.contains(required),
            "missing category: {required}"
        );
    }
}

#[test]
fn frx_07_3_entries_have_integration_test_refs_and_deterministic_templates() {
    let matrix = parse_matrix();

    let allowed_statuses: BTreeSet<&str> =
        ["native", "compatibility_fallback"].into_iter().collect();
    let allowed_roadmap: BTreeSet<&str> =
        ["released", "investigating", "targeted_patch", "planned"]
            .into_iter()
            .collect();

    for entry in &matrix.entries {
        assert!(
            allowed_statuses.contains(entry.compatibility_status.as_str()),
            "invalid compatibility_status for {}: {}",
            entry.stack_id,
            entry.compatibility_status
        );
        assert!(
            !entry.integration_test_id.trim().is_empty(),
            "missing integration_test_id for {}",
            entry.stack_id
        );
        assert!(
            entry.evidence_bundle_ref.starts_with("artifacts/"),
            "evidence bundle must point under artifacts/ for {}",
            entry.stack_id
        );
        assert!(
            allowed_roadmap.contains(entry.roadmap_status.as_str()),
            "invalid roadmap_status for {}: {}",
            entry.stack_id,
            entry.roadmap_status
        );
        assert!(!entry.surface.trim().is_empty());
        assert!(!entry.notes.trim().is_empty());

        let template = &entry.structured_log_template;
        assert!(template.scenario_id.starts_with("frx-07.3-"));
        assert_eq!(template.component, "frx_ecosystem_compatibility_matrix");
        assert!(!template.decision_path.trim().is_empty());
        assert!(["pass", "fallback"].contains(&template.outcome.as_str()));

        if entry.compatibility_status != "native" {
            assert_ne!(entry.fallback_route, "none");
        }
    }
}

#[test]
fn frx_07_3_known_gaps_are_fail_closed_and_traceable() {
    let matrix = parse_matrix();
    let entries = entry_index(&matrix);

    let allowed_fallbacks: BTreeSet<&str> = ["compatibility_fallback", "deterministic_safe_mode"]
        .into_iter()
        .collect();
    let allowed_roadmap: BTreeSet<&str> =
        ["investigating", "targeted_patch", "planned", "released"]
            .into_iter()
            .collect();

    assert!(
        !matrix.known_gaps.is_empty(),
        "expected at least one known gap"
    );

    for gap in &matrix.known_gaps {
        let entry = entries
            .get(gap.stack_id.as_str())
            .unwrap_or_else(|| panic!("known gap references unknown stack: {}", gap.stack_id));

        assert!(
            entry.compatibility_status != "native",
            "known gap stack must not be native-only: {}",
            gap.stack_id
        );
        assert!(
            allowed_fallbacks.contains(gap.fallback_route.as_str()),
            "invalid gap fallback route for {}: {}",
            gap.stack_id,
            gap.fallback_route
        );
        assert!(
            allowed_roadmap.contains(gap.roadmap_status.as_str()),
            "invalid roadmap status for {}: {}",
            gap.stack_id,
            gap.roadmap_status
        );
        assert!(gap.target_milestone.starts_with("FRX-07."));
        assert!(gap.blocking_issue.starts_with("bd-mjh3.7."));
        assert!(gap.error_code.starts_with("FE-FRX-07-3-GAP-"));
        assert!(!gap.owner_lane.trim().is_empty());
        assert_eq!(gap.surface, entry.surface);
    }
}

#[test]
fn frx_07_3_structured_log_fields_and_operator_commands_are_present() {
    let matrix = parse_matrix();

    let required_fields: BTreeSet<&str> = [
        "schema_version",
        "scenario_id",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "decision_path",
        "seed",
        "timing_us",
        "outcome",
        "error_code",
    ]
    .into_iter()
    .collect();
    let actual_fields: BTreeSet<&str> = matrix
        .required_structured_log_fields
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(actual_fields, required_fields);

    assert!(
        matrix
            .operator_verification
            .iter()
            .any(|line| { line.contains("run_frx_ecosystem_compatibility_matrix_suite.sh ci") }),
        "operator verification must include CI gate command"
    );
    assert!(
        matrix
            .operator_verification
            .iter()
            .any(|line| line.contains("frx_ecosystem_compatibility_matrix_replay.sh")),
        "operator verification must include replay command"
    );
    assert!(
        matrix
            .operator_verification
            .iter()
            .any(|line| line.contains("jq empty docs/frx_ecosystem_compatibility_matrix_v1.json")),
        "operator verification must include JSON validation command"
    );
}

#[test]
fn frx_07_3_entry_index_returns_correct_count_and_unique_keys() {
    let matrix = parse_matrix();
    let index = entry_index(&matrix);
    assert_eq!(
        index.len(),
        matrix.entries.len(),
        "entry_index size must match entries length (all stack_ids unique)"
    );
    for entry in &matrix.entries {
        assert!(
            index.contains_key(entry.stack_id.as_str()),
            "entry_index must contain stack_id: {}",
            entry.stack_id
        );
    }
}

#[test]
fn frx_07_3_structured_log_scenario_ids_are_unique_across_entries() {
    let matrix = parse_matrix();
    let mut seen = BTreeSet::new();
    for entry in &matrix.entries {
        assert!(
            seen.insert(&entry.structured_log_template.scenario_id),
            "duplicate scenario_id: {}",
            entry.structured_log_template.scenario_id
        );
    }
}

#[test]
fn frx_07_3_known_gap_stack_ids_are_subset_of_entry_stack_ids() {
    let matrix = parse_matrix();
    let entry_ids: BTreeSet<&str> = matrix.entries.iter().map(|e| e.stack_id.as_str()).collect();
    for gap in &matrix.known_gaps {
        assert!(
            entry_ids.contains(gap.stack_id.as_str()),
            "known gap references stack_id not in entries: {}",
            gap.stack_id
        );
    }
}

#[test]
fn frx_07_3_all_entries_have_nonempty_stack_id_and_surface() {
    let matrix = parse_matrix();
    for entry in &matrix.entries {
        assert!(
            !entry.stack_id.trim().is_empty(),
            "stack_id must not be empty"
        );
        assert!(
            !entry.surface.trim().is_empty(),
            "surface must not be empty for {}",
            entry.stack_id
        );
        assert!(
            !entry.category.trim().is_empty(),
            "category must not be empty for {}",
            entry.stack_id
        );
    }
}

#[test]
fn frx_07_3_serde_roundtrip_preserves_matrix() {
    let matrix = parse_matrix();
    let serialized = serde_json::to_string(&matrix).expect("serialize");
    let deserialized: EcosystemMatrix = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(matrix, deserialized);
}

#[test]
fn frx_07_3_deterministic_double_parse() {
    let a = parse_matrix();
    let b = parse_matrix();
    assert_eq!(a, b);
}

#[test]
fn frx_07_3_known_gaps_have_unique_stack_id_surface_pairs() {
    let matrix = parse_matrix();
    let mut seen = BTreeSet::new();
    for gap in &matrix.known_gaps {
        assert!(
            seen.insert((&gap.stack_id, &gap.surface)),
            "duplicate known gap: {} / {}",
            gap.stack_id,
            gap.surface
        );
    }
}

#[test]
fn frx_07_3_evidence_bundle_refs_are_all_under_artifacts() {
    let matrix = parse_matrix();
    for entry in &matrix.entries {
        assert!(
            entry.evidence_bundle_ref.starts_with("artifacts/"),
            "evidence_bundle_ref must be under artifacts/: {}",
            entry.evidence_bundle_ref
        );
        assert!(
            !entry.evidence_bundle_ref.trim().is_empty(),
            "evidence_bundle_ref must not be empty for {}",
            entry.stack_id
        );
    }
}

#[test]
fn frx_07_3_doc_file_exists_and_is_nonempty() {
    let path = repo_root().join("docs/FRX_ECOSYSTEM_COMPATIBILITY_MATRIX_V1.md");
    let content = fs::read_to_string(&path).expect("read doc");
    assert!(!content.is_empty());
}

// ---------- integration_test_ids are unique ----------

#[test]
fn frx_07_3_integration_test_ids_are_unique() {
    let matrix = parse_matrix();
    let mut seen = BTreeSet::new();
    for entry in &matrix.entries {
        assert!(
            seen.insert(&entry.integration_test_id),
            "duplicate integration_test_id: {}",
            entry.integration_test_id
        );
    }
}

// ---------- operator verification has JSON validation ----------

#[test]
fn frx_07_3_operator_verification_includes_json_validation() {
    let matrix = parse_matrix();
    assert!(
        matrix
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("jq empty")),
        "operator verification must include JSON validation"
    );
}

// ---------- known gap error codes are unique ----------

#[test]
fn frx_07_3_known_gap_error_codes_are_unique() {
    let matrix = parse_matrix();
    let mut seen = BTreeSet::new();
    for gap in &matrix.known_gaps {
        assert!(
            seen.insert(&gap.error_code),
            "duplicate error_code in known gaps: {}",
            gap.error_code
        );
    }
}

#[test]
fn ecosystem_matrix_schema_version_matches_constant() {
    let matrix = parse_matrix();
    assert_eq!(matrix.schema_version, MATRIX_SCHEMA_VERSION);
}

#[test]
fn ecosystem_matrix_serde_roundtrip() {
    let matrix = parse_matrix();
    let json = serde_json::to_string(&matrix).expect("serialize");
    let recovered: EcosystemMatrix = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.schema_version, matrix.schema_version);
    assert_eq!(recovered.entries.len(), matrix.entries.len());
}

#[test]
fn ecosystem_matrix_operator_verification_has_entries() {
    let matrix = parse_matrix();
    assert!(
        !matrix.operator_verification.is_empty(),
        "operator_verification must not be empty"
    );
}

#[test]
fn ecosystem_matrix_has_nonempty_bead_id() {
    let matrix = parse_matrix();
    assert!(!matrix.bead_id.trim().is_empty());
}

#[test]
fn ecosystem_matrix_has_nonempty_generated_by() {
    let matrix = parse_matrix();
    assert!(!matrix.generated_by.trim().is_empty());
}

#[test]
fn ecosystem_matrix_deterministic_double_parse() {
    let a = parse_matrix();
    let b = parse_matrix();
    assert_eq!(a.schema_version, b.schema_version);
    assert_eq!(a.entries.len(), b.entries.len());
    assert_eq!(a.known_gaps.len(), b.known_gaps.len());
}

// ────────────────────────────────────────────────────────────
// Batch enrichment: notes nonempty, fallback route consistency,
// known gap target milestones, track fields, structured log
// decision_path nonempty, entry category coverage, gap owner_lane
// ────────────────────────────────────────────────────────────

#[test]
fn frx_07_3_all_entries_have_nonempty_notes() {
    let matrix = parse_matrix();
    for entry in &matrix.entries {
        assert!(
            !entry.notes.trim().is_empty(),
            "entry {} has empty notes",
            entry.stack_id
        );
    }
}

#[test]
fn frx_07_3_native_entries_have_none_fallback_route() {
    let matrix = parse_matrix();
    for entry in &matrix.entries {
        if entry.compatibility_status == "native" {
            assert_eq!(
                entry.fallback_route, "none",
                "native entry {} should have fallback_route 'none'",
                entry.stack_id
            );
        }
    }
}

#[test]
fn frx_07_3_known_gap_owner_lanes_are_nonempty() {
    let matrix = parse_matrix();
    for gap in &matrix.known_gaps {
        assert!(
            !gap.owner_lane.trim().is_empty(),
            "known gap {} has empty owner_lane",
            gap.stack_id
        );
    }
}

#[test]
fn frx_07_3_track_id_and_name_are_nonempty() {
    let matrix = parse_matrix();
    assert!(!matrix.track.id.trim().is_empty());
    assert!(!matrix.track.name.trim().is_empty());
}

#[test]
fn frx_07_3_structured_log_decision_paths_are_nonempty() {
    let matrix = parse_matrix();
    for entry in &matrix.entries {
        assert!(
            !entry
                .structured_log_template
                .decision_path
                .trim()
                .is_empty(),
            "entry {} has empty decision_path in log template",
            entry.stack_id
        );
    }
}

#[test]
fn frx_07_3_known_gap_blocking_issues_are_nonempty() {
    let matrix = parse_matrix();
    for gap in &matrix.known_gaps {
        assert!(
            !gap.blocking_issue.trim().is_empty(),
            "known gap {} has empty blocking_issue",
            gap.stack_id
        );
    }
}

#[test]
fn frx_07_3_compatibility_entry_serde_round_trip() {
    let matrix = parse_matrix();
    let entry = &matrix.entries[0];
    let json = serde_json::to_string(entry).expect("serialize");
    let recovered: CompatibilityEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry.stack_id, recovered.stack_id);
    assert_eq!(entry.category, recovered.category);
    assert_eq!(entry.surface, recovered.surface);
    assert_eq!(
        entry.structured_log_template.scenario_id,
        recovered.structured_log_template.scenario_id
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment batch: 17 new tests
// ────────────────────────────────────────────────────────────

#[test]
fn frx_07_3_known_gap_serde_round_trip_all() {
    let matrix = parse_matrix();
    for gap in &matrix.known_gaps {
        let json = serde_json::to_string(gap).expect("serialize gap");
        let recovered: KnownGap = serde_json::from_str(&json).expect("deserialize gap");
        assert_eq!(
            gap, &recovered,
            "round-trip mismatch for gap {}",
            gap.stack_id
        );
    }
}

#[test]
fn frx_07_3_matrix_track_serde_round_trip() {
    let matrix = parse_matrix();
    let json = serde_json::to_string(&matrix.track).expect("serialize track");
    let recovered: MatrixTrack = serde_json::from_str(&json).expect("deserialize track");
    assert_eq!(matrix.track, recovered);
}

#[test]
fn frx_07_3_structured_log_template_serde_round_trip() {
    let matrix = parse_matrix();
    for entry in &matrix.entries {
        let json =
            serde_json::to_string(&entry.structured_log_template).expect("serialize template");
        let recovered: StructuredLogTemplate =
            serde_json::from_str(&json).expect("deserialize template");
        assert_eq!(entry.structured_log_template, recovered);
    }
}

#[test]
fn frx_07_3_clone_preserves_full_matrix_equality() {
    let matrix = parse_matrix();
    let cloned = matrix.clone();
    assert_eq!(matrix, cloned);
    assert_eq!(matrix.entries.len(), cloned.entries.len());
    assert_eq!(matrix.known_gaps.len(), cloned.known_gaps.len());
    assert_eq!(
        matrix.required_structured_log_fields,
        cloned.required_structured_log_fields
    );
}

#[test]
fn frx_07_3_debug_format_contains_schema_version() {
    let matrix = parse_matrix();
    let debug_str = format!("{:?}", matrix);
    assert!(
        debug_str.contains(MATRIX_SCHEMA_VERSION),
        "debug output must contain schema version"
    );
}

#[test]
fn frx_07_3_debug_format_contains_track_id() {
    let matrix = parse_matrix();
    let debug_str = format!("{:?}", matrix);
    assert!(
        debug_str.contains("FRX-07.3"),
        "debug output must contain track id"
    );
}

#[test]
fn frx_07_3_fallback_entries_have_fallback_outcome_in_template() {
    let matrix = parse_matrix();
    for entry in &matrix.entries {
        if entry.compatibility_status == "compatibility_fallback" {
            assert_eq!(
                entry.structured_log_template.outcome, "fallback",
                "compatibility_fallback entry {} must have outcome 'fallback'",
                entry.stack_id
            );
        }
    }
}

#[test]
fn frx_07_3_native_entries_have_pass_outcome_in_template() {
    let matrix = parse_matrix();
    for entry in &matrix.entries {
        if entry.compatibility_status == "native" {
            assert_eq!(
                entry.structured_log_template.outcome, "pass",
                "native entry {} must have outcome 'pass'",
                entry.stack_id
            );
        }
    }
}

#[test]
fn frx_07_3_generated_at_utc_is_valid_iso8601() {
    let matrix = parse_matrix();
    let ts = &matrix.generated_at_utc;
    assert!(ts.ends_with('Z'), "timestamp must end with Z");
    assert!(ts.contains('T'), "timestamp must contain T separator");
    let parts: Vec<&str> = ts.split('T').collect();
    assert_eq!(
        parts.len(),
        2,
        "timestamp must have exactly one T separator"
    );
    let date_parts: Vec<&str> = parts[0].split('-').collect();
    assert_eq!(date_parts.len(), 3, "date must have year-month-day");
    assert_eq!(date_parts[0].len(), 4, "year must be 4 digits");
    assert_eq!(date_parts[1].len(), 2, "month must be 2 digits");
    assert_eq!(date_parts[2].len(), 2, "day must be 2 digits");
}

#[test]
fn frx_07_3_required_structured_log_fields_count_is_12() {
    let matrix = parse_matrix();
    assert_eq!(
        matrix.required_structured_log_fields.len(),
        12,
        "expected exactly 12 required structured log fields"
    );
}

#[test]
fn frx_07_3_required_log_fields_are_unique() {
    let matrix = parse_matrix();
    let mut seen = BTreeSet::new();
    for field in &matrix.required_structured_log_fields {
        assert!(
            seen.insert(field.as_str()),
            "duplicate required_structured_log_field: {}",
            field
        );
    }
}

#[test]
fn frx_07_3_every_fallback_entry_has_matching_known_gap() {
    let matrix = parse_matrix();
    let gap_stack_ids: BTreeSet<&str> = matrix
        .known_gaps
        .iter()
        .map(|g| g.stack_id.as_str())
        .collect();
    for entry in &matrix.entries {
        if entry.compatibility_status == "compatibility_fallback" {
            assert!(
                gap_stack_ids.contains(entry.stack_id.as_str()),
                "compatibility_fallback entry {} must have a corresponding known gap",
                entry.stack_id
            );
        }
    }
}

#[test]
fn frx_07_3_all_entries_component_field_matches_matrix_name() {
    let matrix = parse_matrix();
    for entry in &matrix.entries {
        assert_eq!(
            entry.structured_log_template.component, "frx_ecosystem_compatibility_matrix",
            "entry {} component must be 'frx_ecosystem_compatibility_matrix'",
            entry.stack_id
        );
    }
}

#[test]
fn frx_07_3_categories_per_entry_match_expected_set() {
    let matrix = parse_matrix();
    let allowed: BTreeSet<&str> = ["state_lib", "routing", "forms", "data_lib", "legacy_api"]
        .into_iter()
        .collect();
    for entry in &matrix.entries {
        assert!(
            allowed.contains(entry.category.as_str()),
            "entry {} has unexpected category: {}",
            entry.stack_id,
            entry.category
        );
    }
}

#[test]
fn frx_07_3_pretty_json_roundtrip_preserves_matrix() {
    let matrix = parse_matrix();
    let pretty = serde_json::to_string_pretty(&matrix).expect("pretty serialize");
    let recovered: EcosystemMatrix = serde_json::from_str(&pretty).expect("deserialize pretty");
    assert_eq!(matrix, recovered);
}

#[test]
fn frx_07_3_known_gap_target_milestones_follow_pattern() {
    let matrix = parse_matrix();
    for gap in &matrix.known_gaps {
        assert!(
            gap.target_milestone.starts_with("FRX-"),
            "gap {} target_milestone must start with 'FRX-': {}",
            gap.stack_id,
            gap.target_milestone
        );
        let suffix = &gap.target_milestone["FRX-".len()..];
        assert!(
            suffix.contains('.'),
            "gap {} target_milestone must contain dot-separated version: {}",
            gap.stack_id,
            gap.target_milestone
        );
    }
}

#[test]
fn frx_07_3_operator_verification_commands_are_nonempty_strings() {
    let matrix = parse_matrix();
    for cmd in &matrix.operator_verification {
        assert!(
            !cmd.trim().is_empty(),
            "operator_verification must not contain empty commands"
        );
        assert!(
            cmd.len() > 3,
            "operator_verification command is suspiciously short: {}",
            cmd
        );
    }
}
