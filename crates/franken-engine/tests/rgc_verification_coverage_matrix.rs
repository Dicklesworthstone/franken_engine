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

use serde::de::DeserializeOwned;
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

fn parse_json_slice<T: DeserializeOwned>(bytes: &[u8], context: &str) -> T {
    serde_json::from_slice(bytes).unwrap_or_else(|error| panic!("{context}: {error}"))
}

fn parse_json_str<T: DeserializeOwned>(json: &str, context: &str) -> T {
    serde_json::from_str(json).unwrap_or_else(|error| panic!("{context}: {error}"))
}

fn to_json_string<T: Serialize>(value: &T, context: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|error| panic!("{context}: {error}"))
}

fn to_pretty_json_string<T: Serialize>(value: &T, context: &str) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|error| panic!("{context}: {error}"))
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

    let issues: Vec<LiveIssue> = parse_json_slice(&output.stdout, "parse `br list --json` output");

    let mut beads: Vec<String> = issues
        .into_iter()
        .filter(|issue| issue.id.starts_with("bd-1lsy") && issue.status != "closed")
        .map(|issue| issue.id)
        .collect();
    beads.sort();
    beads.dedup();
    Some(beads)
}

/// Explicit opt-out for environments that genuinely lack the `br` CLI (e.g.
/// hermetic CI sandboxes). When unset, a missing `br` is a HARD FAILURE: the
/// snapshot-vs-live assertion must never silently pass green on coverage it
/// could not actually verify.
const ALLOW_MISSING_BR_ENV: &str = "RGC_051_ALLOW_MISSING_BR";

/// Decision for the snapshot-vs-live reconciliation, factored out so the
/// fail-closed contract is itself unit-testable without depending on whether
/// `br` happens to be installed in the test environment.
#[derive(Debug, PartialEq, Eq)]
enum SnapshotCheck {
    /// `br` produced live state; the committed snapshot must equal it.
    Verify { live: Vec<String> },
    /// `br` is unavailable but the operator explicitly waived the check.
    WaivedMissingBr,
    /// `br` is unavailable and no waiver is set: fail closed.
    FailClosedMissingBr,
}

/// Classify what the snapshot test should do given the live bead state
/// (`None` ⇔ `br` not on PATH) and whether a waiver is in effect.
fn classify_snapshot_check(live: Option<Vec<String>>, allow_missing_br: bool) -> SnapshotCheck {
    match (live, allow_missing_br) {
        (Some(live), _) => SnapshotCheck::Verify { live },
        (None, true) => SnapshotCheck::WaivedMissingBr,
        (None, false) => SnapshotCheck::FailClosedMissingBr,
    }
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
    let allow_missing_br = std::env::var_os(ALLOW_MISSING_BR_ENV).is_some();
    match classify_snapshot_check(load_live_open_rgc_beads(), allow_missing_br) {
        SnapshotCheck::Verify { live } => assert_eq!(
            matrix.scope.open_bead_ids, live,
            "matrix scope snapshot must match live non-closed bd-1lsy* beads from `br list --json`"
        ),
        SnapshotCheck::WaivedMissingBr => eprintln!(
            "WAIVED: `br` unavailable and {ALLOW_MISSING_BR_ENV} is set; live-bead snapshot \
             assertion skipped. Coverage snapshot is UNVERIFIED."
        ),
        SnapshotCheck::FailClosedMissingBr => panic!(
            "`br` CLI is not on PATH, so the matrix scope snapshot cannot be verified against \
             live bead state. Failing closed instead of passing green on unverified coverage. \
             Install `br`, or set {ALLOW_MISSING_BR_ENV}=1 to explicitly waive the check in \
             environments that genuinely lack the CLI."
        ),
    }
}

#[test]
fn rgc_051_snapshot_check_fails_closed_when_br_missing_and_not_waived() {
    assert_eq!(
        classify_snapshot_check(None, false),
        SnapshotCheck::FailClosedMissingBr,
        "missing `br` without an explicit waiver must fail closed, not silently skip"
    );
}

#[test]
fn rgc_051_snapshot_check_waives_only_with_explicit_optout() {
    assert_eq!(
        classify_snapshot_check(None, true),
        SnapshotCheck::WaivedMissingBr,
        "missing `br` is skipped only when the explicit waiver env var is set"
    );
}

#[test]
fn rgc_051_snapshot_check_verifies_when_br_available() {
    let live = vec!["bd-1lsy.2.1".to_string(), "bd-1lsy.11.1".to_string()];
    assert_eq!(
        classify_snapshot_check(Some(live.clone()), false),
        SnapshotCheck::Verify { live },
        "available `br` output must always drive verification regardless of the waiver flag"
    );
    let live2 = vec!["bd-1lsy.2.1".to_string()];
    assert_eq!(
        classify_snapshot_check(Some(live2.clone()), true),
        SnapshotCheck::Verify { live: live2 },
        "a waiver must never suppress verification when `br` output is actually present"
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
    let serialized = to_json_string(&matrix, "serialize coverage matrix");
    let deserialized: VerificationCoverageMatrix =
        parse_json_str(&serialized, "deserialize coverage matrix");
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

// ---------- enrichment: struct clone/debug ----------

#[test]
fn rgc_051_matrix_clone_equals_original() {
    let matrix = parse_matrix();
    let cloned = matrix.clone();
    assert_eq!(matrix, cloned);
}

#[test]
fn rgc_051_matrix_debug_contains_schema_version() {
    let matrix = parse_matrix();
    let debug = format!("{matrix:?}");
    assert!(debug.contains("VerificationCoverageMatrix"));
    assert!(debug.contains(&matrix.schema_version));
}

// ---------- enrichment: individual struct serde ----------

#[test]
fn rgc_051_matrix_track_serde_roundtrip() {
    let track = MatrixTrack {
        id: "RGC-051".to_string(),
        name: "Test".to_string(),
    };
    let json = to_json_string(&track, "serialize matrix track");
    let recovered: MatrixTrack = parse_json_str(&json, "deserialize matrix track");
    assert_eq!(track, recovered);
}

#[test]
fn rgc_051_matrix_scope_serde_roundtrip() {
    let scope = MatrixScope {
        project_epic: "bd-1lsy".to_string(),
        snapshot_source: "test".to_string(),
        snapshot_generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        open_bead_ids: vec!["bd-1lsy.1".to_string()],
    };
    let json = to_json_string(&scope, "serialize matrix scope");
    let recovered: MatrixScope = parse_json_str(&json, "deserialize matrix scope");
    assert_eq!(scope, recovered);
}

#[test]
fn rgc_051_milestone_target_serde_roundtrip() {
    let target = MilestoneTarget {
        milestone: "M1".to_string(),
        description: "First milestone".to_string(),
        required_beads: vec!["bd-1lsy.1".to_string()],
        stop_go_rule: "all_pass".to_string(),
    };
    let json = to_json_string(&target, "serialize milestone target");
    let recovered: MilestoneTarget = parse_json_str(&json, "deserialize milestone target");
    assert_eq!(target, recovered);
}

#[test]
fn rgc_051_coverage_row_serde_roundtrip() {
    let row = CoverageRow {
        row_id: "row-1".to_string(),
        bead_selectors: vec!["bd-1lsy.*".to_string()],
        requirement_id: "req-1".to_string(),
        test_kind: "unit".to_string(),
        harness_entrypoint: "cargo test".to_string(),
        deterministic_seed_policy: "fixed_42".to_string(),
        required_log_fields: vec!["trace_id".to_string()],
        artifact_paths: vec!["run_manifest.json".to_string()],
        gate_owner: "team-a".to_string(),
        pass_fail_interpretation: "strict".to_string(),
    };
    let json = to_json_string(&row, "serialize coverage row");
    let recovered: CoverageRow = parse_json_str(&json, "deserialize coverage row");
    assert_eq!(row, recovered);
}

#[test]
fn rgc_051_waiver_governance_serde_roundtrip() {
    let waiver = WaiverGovernance {
        waiver_required_fields: vec!["waiver_id".to_string()],
        max_waiver_age_hours: 72,
        fail_closed_on_expired_waiver: true,
        fail_closed_on_missing_signature: true,
    };
    let json = to_json_string(&waiver, "serialize waiver governance");
    let recovered: WaiverGovernance = parse_json_str(&json, "deserialize waiver governance");
    assert_eq!(waiver, recovered);
}

// ---------- enrichment: selector_matches edge cases ----------

#[test]
fn rgc_051_selector_matches_wildcard_does_not_match_partial_prefix() {
    // "bd-1lsy.*" should NOT match "bd-1lsyX" (no dot separator)
    assert!(!selector_matches("bd-1lsy.*", "bd-1lsyX"));
}

#[test]
fn rgc_051_selector_matches_exact_does_not_wildcard() {
    assert!(selector_matches("bd-1lsy.2", "bd-1lsy.2"));
    assert!(!selector_matches("bd-1lsy.2", "bd-1lsy.2.1"));
}

#[test]
fn rgc_051_selector_matches_wildcard_matches_self() {
    // "bd-1lsy.*" should match "bd-1lsy" (the prefix itself)
    assert!(selector_matches("bd-1lsy.*", "bd-1lsy"));
}

// ---------- enrichment: JSON field names ----------

#[test]
fn rgc_051_matrix_json_has_expected_top_level_fields() {
    let val: serde_json::Value = serde_json::from_str(MATRIX_JSON).expect("matrix json must parse");
    let obj = val.as_object().expect("root must be object");
    for field in [
        "schema_version",
        "bead_id",
        "generated_by",
        "generated_at_utc",
        "track",
        "scope",
        "required_structured_log_fields",
        "critical_behavior_bead_ids",
        "milestone_targets",
        "coverage_rows",
        "waiver_governance",
        "operator_verification",
    ] {
        assert!(obj.contains_key(field), "missing field: {field}");
    }
}

// ---------- enrichment: coverage_rows bead_selectors are nonempty ----------

#[test]
fn rgc_051_coverage_rows_all_have_bead_selectors() {
    let matrix = parse_matrix();
    for row in &matrix.coverage_rows {
        assert!(
            !row.bead_selectors.is_empty(),
            "row {} must have at least one bead_selector",
            row.row_id
        );
    }
}

// ---------- enrichment: operator_verification entries nonempty ----------

#[test]
fn rgc_051_operator_verification_entries_are_nonempty() {
    let matrix = parse_matrix();
    for entry in &matrix.operator_verification {
        assert!(
            !entry.trim().is_empty(),
            "operator_verification entry must not be empty"
        );
    }
}

// ---------- enrichment: milestone required_beads are unique ----------

#[test]
fn rgc_051_milestone_required_beads_are_unique_per_milestone() {
    let matrix = parse_matrix();
    for target in &matrix.milestone_targets {
        let mut seen = BTreeSet::new();
        for bead in &target.required_beads {
            assert!(
                seen.insert(bead),
                "duplicate bead {} in milestone {}",
                bead,
                target.milestone
            );
        }
    }
}

// ---------- enrichment: pretty print roundtrip ----------

#[test]
fn rgc_051_pretty_json_roundtrip_preserves_equality() {
    let matrix = parse_matrix();
    let pretty = to_pretty_json_string(&matrix, "serialize pretty coverage matrix");
    let recovered: VerificationCoverageMatrix =
        parse_json_str(&pretty, "deserialize pretty coverage matrix");
    assert_eq!(matrix, recovered);
}

// ---------- enrichment: required_structured_log_fields unique ----------

#[test]
fn rgc_051_required_structured_log_fields_are_unique() {
    let matrix = parse_matrix();
    let mut seen = BTreeSet::new();
    for field in &matrix.required_structured_log_fields {
        assert!(
            seen.insert(field.as_str()),
            "duplicate required_structured_log_field: {field}"
        );
    }
}
