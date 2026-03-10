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
    process::Command,
};

use serde::{Deserialize, Serialize};

const MATRIX_SCHEMA_VERSION: &str = "rgc.verification-coverage-matrix.v1";
const MATRIX_JSON: &str = include_str!("../../../docs/rgc_verification_coverage_matrix_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VerificationCoverageMatrix {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: MatrixTrack,
    scope: MatrixScope,
    required_structured_log_fields: Vec<String>,
    critical_behavior_bead_ids: Vec<String>,
    milestone_targets: Vec<MilestoneTarget>,
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct LiveIssue {
    id: String,
    status: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_matrix() -> VerificationCoverageMatrix {
    serde_json::from_str(MATRIX_JSON).expect("RGC verification coverage matrix JSON must parse")
}

fn selector_matches(selector: &str, bead_id: &str) -> bool {
    if let Some(prefix) = selector.strip_suffix(".*") {
        bead_id == prefix || bead_id.starts_with(&format!("{prefix}."))
    } else {
        bead_id == selector
    }
}

fn matched_row_ids<'a>(matrix: &'a VerificationCoverageMatrix, bead_id: &str) -> Vec<&'a str> {
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

fn load_live_open_rgc_beads() -> Option<Vec<String>> {
    let output = match Command::new("br")
        .args(["list", "--json", "--limit", "0"])
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => panic!("failed to execute `br list --json`: {error}"),
    };

    assert!(
        output.status.success(),
        "`br list --json` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let issues: Vec<LiveIssue> = serde_json::from_slice(&output.stdout)
        .expect("`br list --json` output must deserialize as issue array");

    let mut beads: Vec<String> = issues
        .into_iter()
        .filter(|issue| issue.id.starts_with("bd-1lsy") && issue.status != "closed")
        .map(|issue| issue.id)
        .collect();
    beads.sort();
    beads.dedup();
    Some(beads)
}

#[test]
fn rgc_051_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_VERIFICATION_COVERAGE_MATRIX_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# RGC Verification Coverage Matrix V1",
        "## Purpose",
        "## Matrix Model",
        "## Coverage Guarantees",
        "## Gate Runner",
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
fn rgc_051_matrix_is_versioned_and_track_bound() {
    let matrix = parse_matrix();

    assert_eq!(matrix.schema_version, MATRIX_SCHEMA_VERSION);
    assert_eq!(matrix.bead_id, "bd-1lsy.11.1");
    assert_eq!(matrix.generated_by, "bd-1lsy.11.1");
    assert_eq!(matrix.track.id, "RGC-051");
    assert_eq!(matrix.track.name, "Verification Coverage Matrix");
    assert!(matrix.generated_at_utc.ends_with('Z'));
    assert!(matrix.scope.snapshot_generated_at_utc.ends_with('Z'));
    assert_eq!(matrix.scope.project_epic, "bd-1lsy");
    assert!(
        matrix
            .scope
            .snapshot_source
            .contains("br list --json --limit 0 filtered")
    );
}

#[test]
fn rgc_051_scope_snapshot_has_unique_sorted_open_beads() {
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
fn rgc_051_all_open_beads_are_mapped_to_at_least_one_verification_row() {
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
fn rgc_051_critical_behavior_beads_have_unit_integration_and_e2e_rows() {
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
fn rgc_051_critical_behavior_beads_are_within_open_scope_snapshot() {
    let matrix = parse_matrix();
    let open_scope: BTreeSet<&str> = matrix
        .scope
        .open_bead_ids
        .iter()
        .map(String::as_str)
        .collect();

    for bead_id in &matrix.critical_behavior_bead_ids {
        assert!(
            open_scope.contains(bead_id.as_str()),
            "critical behavior bead {} must be present in scope.open_bead_ids",
            bead_id
        );
    }
}

#[test]
fn rgc_051_rows_reference_executable_entrypoints_logs_and_artifact_triad() {
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

        for triad in ["run_manifest.json", "events.jsonl", "commands.txt"] {
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
fn rgc_051_milestone_targets_reference_open_scope_beads() {
    let matrix = parse_matrix();
    let allowed = BTreeSet::from([
        "M1".to_string(),
        "M2".to_string(),
        "M3".to_string(),
        "M4".to_string(),
        "M5".to_string(),
    ]);

    assert_eq!(matrix.milestone_targets.len(), 5);

    for target in &matrix.milestone_targets {
        assert!(allowed.contains(&target.milestone));
        assert!(!target.description.trim().is_empty());
        assert!(!target.stop_go_rule.trim().is_empty());
        assert!(!target.required_beads.is_empty());
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
fn rgc_051_waiver_rules_are_fail_closed_and_complete() {
    let matrix = parse_matrix();

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
fn rgc_051_operator_verification_commands_are_present() {
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
        matrix
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("run_rgc_verification_coverage_matrix.sh")),
        "operator verification must include matrix gate runner"
    );
}

#[test]
fn rgc_051_snapshot_matches_live_beads_state() {
    let matrix = parse_matrix();
    let Some(live) = load_live_open_rgc_beads() else {
        eprintln!("skipping live-bead snapshot assertion: `br` not available in this environment");
        return;
    };

    assert_eq!(
        matrix.scope.open_bead_ids, live,
        "matrix scope snapshot must match live non-closed bd-1lsy* beads from `br list --json`"
    );
}

#[test]
fn rgc_051_selector_matches_exact_bead_id() {
    assert!(selector_matches("bd-1lsy.2.1", "bd-1lsy.2.1"));
    assert!(!selector_matches("bd-1lsy.2.1", "bd-1lsy.2.2"));
}

#[test]
fn rgc_051_selector_matches_wildcard_prefix() {
    assert!(selector_matches("bd-1lsy.*", "bd-1lsy.2.1"));
    assert!(selector_matches("bd-1lsy.*", "bd-1lsy"));
    assert!(!selector_matches("bd-1lsy.*", "bd-2abc"));
}

#[test]
fn rgc_051_matched_row_ids_empty_for_unknown_bead() {
    let matrix = parse_matrix();
    let rows = matched_row_ids(&matrix, "bd-nonexistent-bead");
    assert!(rows.is_empty());
}

#[test]
fn rgc_051_row_ids_are_unique() {
    let matrix = parse_matrix();
    let mut seen = BTreeSet::new();
    for row in &matrix.coverage_rows {
        assert!(seen.insert(&row.row_id), "duplicate row_id: {}", row.row_id);
    }
}

#[test]
fn rgc_051_serde_roundtrip_preserves_matrix() {
    let matrix = parse_matrix();
    let serialized = serde_json::to_string(&matrix).expect("serialize");
    let deserialized: VerificationCoverageMatrix =
        serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(matrix, deserialized);
}

#[test]
fn rgc_051_deterministic_double_parse() {
    let a = parse_matrix();
    let b = parse_matrix();
    assert_eq!(a, b);
}

#[test]
fn rgc_051_doc_file_is_nonempty() {
    let path = repo_root().join("docs/RGC_VERIFICATION_COVERAGE_MATRIX_V1.md");
    let content = fs::read_to_string(&path).expect("read doc");
    assert!(!content.is_empty());
}

#[test]
fn rgc_051_milestone_ids_are_unique() {
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
fn rgc_051_matrix_has_nonempty_generated_by() {
    let matrix = parse_matrix();
    assert!(!matrix.generated_by.trim().is_empty());
}

#[test]
fn rgc_051_matrix_track_fields_are_nonempty() {
    let matrix = parse_matrix();
    assert!(!matrix.track.id.trim().is_empty());
    assert!(!matrix.track.name.trim().is_empty());
}

#[test]
fn rgc_051_matrix_generated_at_utc_ends_with_z() {
    let matrix = parse_matrix();
    assert!(matrix.generated_at_utc.ends_with('Z'));
}

#[test]
fn rgc_051_schema_version_matches_constant() {
    let matrix = parse_matrix();
    assert_eq!(matrix.schema_version, MATRIX_SCHEMA_VERSION);
}

#[test]
fn rgc_051_coverage_rows_are_nonempty() {
    let matrix = parse_matrix();
    assert!(
        !matrix.coverage_rows.is_empty(),
        "coverage_rows must not be empty"
    );
}

#[test]
fn rgc_051_coverage_rows_have_nonempty_fields() {
    let matrix = parse_matrix();
    for row in &matrix.coverage_rows {
        assert!(!row.row_id.trim().is_empty(), "row_id must not be empty");
    }
}

#[test]
fn rgc_051_required_structured_log_fields_present() {
    let matrix = parse_matrix();
    assert!(
        !matrix.required_structured_log_fields.is_empty(),
        "required_structured_log_fields must not be empty"
    );
    // trace_id and decision_id are always required
    let actual: BTreeSet<&str> = matrix
        .required_structured_log_fields
        .iter()
        .map(String::as_str)
        .collect();
    assert!(actual.contains("trace_id"), "must require trace_id");
    assert!(actual.contains("decision_id"), "must require decision_id");
}

#[test]
fn rgc_051_critical_behavior_bead_ids_are_nonempty() {
    let matrix = parse_matrix();
    assert!(
        !matrix.critical_behavior_bead_ids.is_empty(),
        "critical_behavior_bead_ids must not be empty"
    );
    for bead_id in &matrix.critical_behavior_bead_ids {
        assert!(!bead_id.trim().is_empty());
    }
}

#[test]
fn rgc_051_scope_project_epic_is_nonempty() {
    let matrix = parse_matrix();
    assert!(!matrix.scope.project_epic.trim().is_empty());
}

#[test]
fn rgc_051_scope_snapshot_source_is_nonempty() {
    let matrix = parse_matrix();
    assert!(!matrix.scope.snapshot_source.trim().is_empty());
}

#[test]
fn rgc_051_waiver_governance_has_positive_max_age() {
    let matrix = parse_matrix();
    assert!(matrix.waiver_governance.max_waiver_age_hours > 0);
}

#[test]
fn rgc_051_waiver_governance_required_fields_nonempty() {
    let matrix = parse_matrix();
    assert!(!matrix.waiver_governance.waiver_required_fields.is_empty());
}
