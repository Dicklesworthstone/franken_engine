#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};

const MATRIX_SCHEMA_VERSION: &str = "rgc.executable-compatibility-target-matrix.v1";
const MATRIX_JSON: &str =
    include_str!("../../../docs/rgc_executable_compatibility_target_matrix_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CompatibilityMatrix {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: MatrixTrack,
    scope: MatrixScope,
    required_structured_log_fields: Vec<String>,
    critical_behavior_bead_ids: Vec<String>,
    milestone_targets: Vec<MilestoneTarget>,
    react_capability_contract_ref: ReactCapabilityContractRef,
    coverage_rows: Vec<CoverageRow>,
    waiver_governance: WaiverGovernance,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MatrixTrack {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MatrixScope {
    project_epic: String,
    snapshot_source: String,
    snapshot_generated_at_utc: String,
    open_bead_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MilestoneTarget {
    milestone: String,
    description: String,
    required_beads: Vec<String>,
    stop_go_rule: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReactCapabilityContractRef {
    bead_id: String,
    contract_doc: String,
    contract_json: String,
    coverage_row_id: String,
    required_capability_ids: Vec<String>,
    product_surface_beads: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CoverageRow {
    row_id: String,
    bead_selectors: Vec<String>,
    requirement_id: String,
    test_kind: String,
    harness_entrypoint: String,
    deterministic_seed_policy: String,
    required_log_fields: Vec<String>,
    artifact_paths: Vec<String>,
    gate_owner: String,
    pass_fail_interpretation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WaiverGovernance {
    waiver_required_fields: Vec<String>,
    max_waiver_age_hours: u64,
    fail_closed_on_expired_waiver: bool,
    fail_closed_on_missing_signature: bool,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_matrix() -> CompatibilityMatrix {
    serde_json::from_str(MATRIX_JSON).expect("rgc compatibility target matrix json must parse")
}

fn selector_matches(selector: &str, bead_id: &str) -> bool {
    if let Some(prefix) = selector.strip_suffix(".*") {
        bead_id == prefix || bead_id.starts_with(&format!("{prefix}."))
    } else {
        bead_id == selector
    }
}

fn matched_row_ids<'a>(matrix: &'a CompatibilityMatrix, bead_id: &str) -> Vec<&'a str> {
    matrix
        .coverage_rows
        .iter()
        .filter(|row| {
            row.bead_selectors
                .iter()
                .any(|selector| selector_matches(selector, bead_id))
        })
        .map(|row| row.row_id.as_str())
        .collect()
}

#[test]
fn rgc_011_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_EXECUTABLE_COMPATIBILITY_TARGET_MATRIX_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# RGC Executable Compatibility Target Matrix V1",
        "## Purpose",
        "## Matrix Model",
        "## React/JSX/TSX Extension",
        "## Compatibility Targets By Milestone",
        "## Required Logging Fields",
        "## Waiver Governance",
        "## Diff-Reviewability Contract",
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
fn rgc_011_matrix_is_versioned_and_track_bound() {
    let matrix = parse_matrix();

    assert_eq!(matrix.schema_version, MATRIX_SCHEMA_VERSION);
    assert_eq!(matrix.bead_id, "bd-1lsy.1.1");
    assert_eq!(matrix.generated_by, "bd-1lsy.1.1");
    assert_eq!(matrix.track.id, "RGC-011");
    assert_eq!(matrix.track.name, "Executable Compatibility Target Matrix");
    assert!(matrix.generated_at_utc.ends_with('Z'));
    assert!(matrix.scope.snapshot_generated_at_utc.ends_with('Z'));
    assert_eq!(matrix.scope.project_epic, "bd-1lsy");
    assert!(
        matrix
            .scope
            .snapshot_source
            .contains("br list --json filtered")
    );
}

#[test]
fn rgc_011_scope_snapshot_has_unique_sorted_open_beads() {
    let matrix = parse_matrix();
    assert!(
        !matrix.scope.open_bead_ids.is_empty(),
        "expected non-empty RGC open bead scope"
    );

    let mut sorted = matrix.scope.open_bead_ids.clone();
    sorted.sort();
    assert_eq!(
        sorted, matrix.scope.open_bead_ids,
        "open_bead_ids snapshot must be lexicographically sorted"
    );

    let unique: BTreeSet<_> = matrix.scope.open_bead_ids.iter().collect();
    assert_eq!(
        unique.len(),
        matrix.scope.open_bead_ids.len(),
        "open_bead_ids snapshot must not contain duplicates"
    );
}

#[test]
fn rgc_011_all_open_beads_are_mapped_to_at_least_one_verification_row() {
    let matrix = parse_matrix();

    for bead_id in &matrix.scope.open_bead_ids {
        let matched = matched_row_ids(&matrix, bead_id);
        assert!(
            !matched.is_empty(),
            "open bead {bead_id} has no verification mapping row"
        );
    }
}

#[test]
fn rgc_011_critical_behavior_beads_have_unit_integration_and_e2e_rows() {
    let matrix = parse_matrix();

    let row_kind_by_id: BTreeMap<&str, &str> = matrix
        .coverage_rows
        .iter()
        .map(|row| (row.row_id.as_str(), row.test_kind.as_str()))
        .collect();

    for bead_id in &matrix.critical_behavior_bead_ids {
        let matched = matched_row_ids(&matrix, bead_id);
        assert!(
            !matched.is_empty(),
            "critical behavior bead {bead_id} must have at least one matched row"
        );

        let kinds: BTreeSet<&str> = matched
            .iter()
            .map(|row_id| {
                row_kind_by_id
                    .get(row_id)
                    .copied()
                    .unwrap_or_else(|| panic!("row_id {row_id} missing from row_kind index"))
            })
            .collect();

        for required in ["unit", "integration", "e2e"] {
            assert!(
                kinds.contains(required),
                "critical bead {bead_id} missing required {required} coverage kind"
            );
        }
    }
}

#[test]
fn rgc_011_rows_reference_executable_entrypoints_logs_and_artifact_triad() {
    let matrix = parse_matrix();

    let required_log_fields: BTreeSet<&str> = [
        "trace_id",
        "decision_id",
        "runtime_lane",
        "seed",
        "result",
        "error_code",
    ]
    .into_iter()
    .collect();

    for row in &matrix.coverage_rows {
        assert!(
            !row.requirement_id.trim().is_empty(),
            "row {} missing requirement_id",
            row.row_id
        );
        assert!(
            ["unit", "integration", "e2e"].contains(&row.test_kind.as_str()),
            "row {} has unsupported test kind {}",
            row.row_id,
            row.test_kind
        );
        assert!(
            !row.harness_entrypoint.trim().is_empty(),
            "row {} missing harness entrypoint",
            row.row_id
        );
        assert!(
            !row.deterministic_seed_policy.trim().is_empty(),
            "row {} missing deterministic seed policy",
            row.row_id
        );
        assert!(
            !row.gate_owner.trim().is_empty(),
            "row {} missing gate owner",
            row.row_id
        );
        assert!(
            !row.pass_fail_interpretation.trim().is_empty(),
            "row {} missing pass/fail interpretation",
            row.row_id
        );

        let field_set: BTreeSet<&str> =
            row.required_log_fields.iter().map(String::as_str).collect();
        for required in &required_log_fields {
            assert!(
                field_set.contains(required),
                "row {} missing required log field {}",
                row.row_id,
                required
            );
        }

        let triad_checks = ["run_manifest.json", "events.jsonl", "commands.txt"];
        for triad in triad_checks {
            assert!(
                row.artifact_paths.iter().any(|path| path.ends_with(triad)),
                "row {} missing artifact triad member {}",
                row.row_id,
                triad
            );
        }
    }
}

#[test]
fn rgc_011_matrix_required_log_fields_and_waiver_rules_are_fail_closed() {
    let matrix = parse_matrix();

    let required = [
        "trace_id",
        "decision_id",
        "runtime_lane",
        "seed",
        "result",
        "error_code",
    ];

    let root_fields: BTreeSet<&str> = matrix
        .required_structured_log_fields
        .iter()
        .map(String::as_str)
        .collect();

    for field in required {
        assert!(
            root_fields.contains(field),
            "matrix root missing required log field {field}"
        );
    }

    assert!(matrix.waiver_governance.max_waiver_age_hours > 0);
    assert!(matrix.waiver_governance.fail_closed_on_expired_waiver);
    assert!(matrix.waiver_governance.fail_closed_on_missing_signature);

    let waiver_required: BTreeSet<&str> = matrix
        .waiver_governance
        .waiver_required_fields
        .iter()
        .map(String::as_str)
        .collect();

    for field in [
        "waiver_id",
        "bead_id",
        "requirement_id",
        "owner",
        "expiry_utc",
        "rationale",
        "mitigation_plan",
        "approval_signature_ref",
    ] {
        assert!(
            waiver_required.contains(field),
            "waiver governance missing required field {field}"
        );
    }
}

#[test]
fn rgc_011_milestone_targets_reference_required_beads_and_rules() {
    let matrix = parse_matrix();

    let allowed = BTreeSet::from([
        "M1".to_string(),
        "M2".to_string(),
        "M3".to_string(),
        "M4".to_string(),
        "M5".to_string(),
    ]);

    assert_eq!(
        matrix.milestone_targets.len(),
        5,
        "expected exactly five milestone targets"
    );

    for target in &matrix.milestone_targets {
        assert!(allowed.contains(&target.milestone));
        assert!(!target.description.trim().is_empty());
        assert!(!target.stop_go_rule.trim().is_empty());
        assert!(
            !target.required_beads.is_empty(),
            "milestone {} missing required beads",
            target.milestone
        );
        for bead in &target.required_beads {
            assert!(
                matrix.scope.open_bead_ids.contains(bead),
                "milestone {} references bead not in open scope snapshot: {}",
                target.milestone,
                bead
            );
        }
    }
}

#[test]
fn rgc_011_operator_verification_commands_are_present() {
    let matrix = parse_matrix();
    assert!(
        matrix.operator_verification.len() >= 3,
        "expected operator verification command set"
    );

    assert!(
        matrix
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("jq empty")),
        "operator verification must include json validation"
    );
    assert!(
        matrix.operator_verification.iter().any(|cmd| cmd.contains(
            "cargo test -p frankenengine-engine --test rgc_executable_compatibility_target_matrix"
        )),
        "operator verification must include matrix contract test"
    );
    assert!(
        matrix
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("./scripts/run_rgc_react_capability_contract.sh ci")),
        "operator verification must include react capability contract gate"
    );
}

#[test]
fn rgc_011_react_capability_extension_is_bound_and_covered() {
    let matrix = parse_matrix();
    let react = &matrix.react_capability_contract_ref;

    assert_eq!(react.bead_id, "bd-1lsy.1.6.1");
    assert_eq!(
        react.contract_doc,
        "docs/RGC_REACT_CAPABILITY_CONTRACT_V1.md"
    );
    assert_eq!(
        react.contract_json,
        "docs/rgc_react_capability_contract_v1.json"
    );
    assert_eq!(react.coverage_row_id, "rgc-react-capability-contract");
    assert!(
        matrix
            .coverage_rows
            .iter()
            .any(|row| row.row_id == react.coverage_row_id),
        "matrix must include the react capability coverage row"
    );
    assert_eq!(
        react.required_capability_ids.len(),
        10,
        "expected explicit React capability row list"
    );
    assert!(
        !react.product_surface_beads.is_empty(),
        "react capability extension must name product surfaces"
    );
}

#[test]
fn selector_matches_exact_bead_id() {
    assert!(selector_matches("bd-1lsy.2.1", "bd-1lsy.2.1"));
    assert!(!selector_matches("bd-1lsy.2.1", "bd-1lsy.2.2"));
}

#[test]
fn selector_matches_wildcard_prefix() {
    assert!(selector_matches("bd-1lsy.*", "bd-1lsy.2.1"));
    assert!(selector_matches("bd-1lsy.*", "bd-1lsy"));
    assert!(!selector_matches("bd-1lsy.*", "bd-2abc"));
}

#[test]
fn selector_matches_no_false_positives() {
    assert!(!selector_matches("bd-1lsy", "bd-1lsy.2"));
    assert!(!selector_matches("bd-abc.*", "bd-xyz.1"));
}

#[test]
fn matched_row_ids_returns_empty_for_unknown_bead() {
    let matrix = parse_matrix();
    let rows = matched_row_ids(&matrix, "bd-nonexistent-bead");
    assert!(rows.is_empty());
}

#[test]
fn rgc_011_row_ids_are_unique() {
    let matrix = parse_matrix();
    let mut seen = BTreeSet::new();
    for row in &matrix.coverage_rows {
        assert!(seen.insert(&row.row_id), "duplicate row_id: {}", row.row_id);
    }
}

#[test]
fn rgc_011_serde_roundtrip_preserves_matrix() {
    let matrix = parse_matrix();
    let serialized = serde_json::to_string(&matrix).expect("serialize");
    let deserialized: CompatibilityMatrix = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(matrix, deserialized);
}

#[test]
fn rgc_011_deterministic_double_parse() {
    let a = parse_matrix();
    let b = parse_matrix();
    assert_eq!(a, b);
}

#[test]
fn rgc_011_doc_file_is_nonempty() {
    let path = repo_root().join("docs/RGC_EXECUTABLE_COMPATIBILITY_TARGET_MATRIX_V1.md");
    let content = fs::read_to_string(&path).expect("read doc");
    assert!(!content.is_empty());
}

#[test]
fn rgc_011_milestone_ids_are_unique() {
    let matrix = parse_matrix();
    let mut seen = BTreeSet::new();
    for target in &matrix.milestone_targets {
        assert!(
            seen.insert(&target.milestone),
            "duplicate milestone: {}",
            target.milestone
        );
    }
}

#[test]
fn matrix_schema_version_matches_constant() {
    let matrix = parse_matrix();
    assert_eq!(matrix.schema_version, MATRIX_SCHEMA_VERSION);
}

#[test]
fn matrix_serde_roundtrip_preserves_schema() {
    let matrix = parse_matrix();
    let json = serde_json::to_string(&matrix).expect("serialize");
    let recovered: CompatibilityMatrix = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.schema_version, matrix.schema_version);
}

#[test]
fn matrix_milestone_targets_are_nonempty() {
    let matrix = parse_matrix();
    assert!(!matrix.milestone_targets.is_empty());
}

#[test]
fn matrix_debug_is_nonempty() {
    let matrix = parse_matrix();
    assert!(!format!("{matrix:?}").is_empty());
}

#[test]
fn matrix_coverage_rows_all_have_at_least_one_bead_selector() {
    let matrix = parse_matrix();
    for row in &matrix.coverage_rows {
        assert!(
            !row.bead_selectors.is_empty(),
            "row {} must have at least one bead selector",
            row.row_id
        );
    }
}

#[test]
fn matrix_scope_open_bead_ids_are_nonempty() {
    let matrix = parse_matrix();
    assert!(!matrix.scope.open_bead_ids.is_empty());
}

#[test]
fn selector_matches_wildcard_does_not_match_longer_prefix() {
    // "bd-1lsy.*" should NOT match "bd-1lsyX" (different prefix, not child)
    assert!(!selector_matches("bd-1lsy.*", "bd-1lsyX"));
    assert!(!selector_matches("bd-1lsy.*", "bd-1lsy2"));
}

#[test]
fn selector_matches_exact_does_not_match_child() {
    // Exact selector "bd-abc" must NOT match "bd-abc.1"
    assert!(!selector_matches("bd-abc", "bd-abc.1"));
    assert!(!selector_matches("bd-abc", "bd-abc.1.2"));
}

#[test]
fn matched_row_ids_covers_all_open_beads_at_least_once() {
    let matrix = parse_matrix();
    for bead_id in &matrix.scope.open_bead_ids {
        let rows = matched_row_ids(&matrix, bead_id);
        assert!(
            !rows.is_empty(),
            "open bead {bead_id} should match at least one coverage row"
        );
    }
}

#[test]
fn matrix_serde_roundtrip_preserves_all_row_ids() {
    let matrix = parse_matrix();
    let json = serde_json::to_string(&matrix).expect("serialize");
    let recovered: CompatibilityMatrix = serde_json::from_str(&json).expect("deserialize");
    let original_ids: Vec<&str> = matrix
        .coverage_rows
        .iter()
        .map(|r| r.row_id.as_str())
        .collect();
    let recovered_ids: Vec<&str> = recovered
        .coverage_rows
        .iter()
        .map(|r| r.row_id.as_str())
        .collect();
    assert_eq!(original_ids, recovered_ids);
}

#[test]
fn matrix_critical_behavior_bead_ids_are_nonempty_and_unique() {
    let matrix = parse_matrix();
    assert!(
        !matrix.critical_behavior_bead_ids.is_empty(),
        "expected at least one critical behavior bead"
    );
    let unique: BTreeSet<_> = matrix.critical_behavior_bead_ids.iter().collect();
    assert_eq!(
        unique.len(),
        matrix.critical_behavior_bead_ids.len(),
        "critical behavior bead IDs must be unique"
    );
}

#[test]
fn matrix_waiver_governance_max_age_is_bounded() {
    let matrix = parse_matrix();
    // Waivers should expire in a reasonable timeframe (< 1 year = 8760 hours)
    assert!(
        matrix.waiver_governance.max_waiver_age_hours <= 8760,
        "max waiver age should be bounded to at most 1 year"
    );
}

#[test]
fn matrix_coverage_rows_have_nonempty_row_ids() {
    let matrix = parse_matrix();
    for row in &matrix.coverage_rows {
        assert!(
            !row.row_id.trim().is_empty(),
            "row_id must not be empty or whitespace"
        );
    }
}
