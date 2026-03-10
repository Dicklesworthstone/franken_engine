//! Integration tests for the `version_matrix_lane` module.
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

use frankenengine_engine::version_matrix_lane::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn simple_version_source(tags: &[&str]) -> VersionSource {
    VersionSource {
        tags: tags.iter().map(|s| s.to_string()).collect(),
        branch_names: vec![],
        current_override: None,
        previous_override: None,
        next_override: None,
    }
}

fn simple_spec(surface: &str, local_tags: &[&str], remote_tags: &[&str]) -> BoundaryMatrixSpec {
    BoundaryMatrixSpec {
        boundary_surface: surface.to_string(),
        local_repo: format!("{surface}-local"),
        remote_repo: format!("{surface}-remote"),
        local_versions: simple_version_source(local_tags),
        remote_versions: simple_version_source(remote_tags),
        pinned_combinations: vec![],
    }
}

fn make_result(cell: &VersionMatrixCell, outcome: MatrixOutcome) -> MatrixCellResult {
    MatrixCellResult {
        trace_id: format!("trace-{}", cell.cell_id),
        decision_id: format!("dec-{}", cell.cell_id),
        policy_id: "policy-default".to_string(),
        cell_id: cell.cell_id.clone(),
        boundary_surface: cell.boundary_surface.clone(),
        lane_kind: cell.lane_kind,
        outcome,
        error_code: None,
        failure_fingerprint: None,
        failure_class: None,
    }
}

fn make_fail_result(
    cell: &VersionMatrixCell,
    fingerprint: &str,
    error_code: &str,
) -> MatrixCellResult {
    MatrixCellResult {
        trace_id: format!("trace-{}", cell.cell_id),
        decision_id: format!("dec-{}", cell.cell_id),
        policy_id: "policy-default".to_string(),
        cell_id: cell.cell_id.clone(),
        boundary_surface: cell.boundary_surface.clone(),
        lane_kind: cell.lane_kind,
        outcome: MatrixOutcome::Fail,
        error_code: Some(error_code.to_string()),
        failure_fingerprint: Some(fingerprint.to_string()),
        failure_class: Some("test-class".to_string()),
    }
}

// ===========================================================================
// 1. Schema constant
// ===========================================================================

#[test]
fn schema_constant_is_stable() {
    assert_eq!(
        VERSION_MATRIX_SCHEMA,
        "franken-engine.version-matrix-lane.v1"
    );
}

// ===========================================================================
// 2. MatrixLaneKind
// ===========================================================================

#[test]
fn lane_kind_as_str_all_variants() {
    assert_eq!(MatrixLaneKind::Current.as_str(), "n_n");
    assert_eq!(MatrixLaneKind::Previous.as_str(), "n_n_minus_1");
    assert_eq!(MatrixLaneKind::Next.as_str(), "n_n_plus_1");
    assert_eq!(MatrixLaneKind::Pinned.as_str(), "pinned");
}

#[test]
fn lane_kind_as_str_uniqueness() {
    let strs: BTreeSet<&str> = [
        MatrixLaneKind::Current,
        MatrixLaneKind::Previous,
        MatrixLaneKind::Next,
        MatrixLaneKind::Pinned,
    ]
    .iter()
    .map(|k| k.as_str())
    .collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn lane_kind_ordering_current_lt_previous_lt_next_lt_pinned() {
    assert!(MatrixLaneKind::Current < MatrixLaneKind::Previous);
    assert!(MatrixLaneKind::Previous < MatrixLaneKind::Next);
    assert!(MatrixLaneKind::Next < MatrixLaneKind::Pinned);
}

#[test]
fn lane_kind_serde_roundtrip_all_variants() {
    for kind in [
        MatrixLaneKind::Current,
        MatrixLaneKind::Previous,
        MatrixLaneKind::Next,
        MatrixLaneKind::Pinned,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: MatrixLaneKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

#[test]
fn lane_kind_serde_snake_case_values() {
    assert_eq!(
        serde_json::to_string(&MatrixLaneKind::Current).unwrap(),
        "\"current\""
    );
    assert_eq!(
        serde_json::to_string(&MatrixLaneKind::Previous).unwrap(),
        "\"previous\""
    );
    assert_eq!(
        serde_json::to_string(&MatrixLaneKind::Next).unwrap(),
        "\"next\""
    );
    assert_eq!(
        serde_json::to_string(&MatrixLaneKind::Pinned).unwrap(),
        "\"pinned\""
    );
}

// ===========================================================================
// 3. MatrixOutcome / FailureScopeKind serde
// ===========================================================================

#[test]
fn matrix_outcome_serde_roundtrip() {
    for outcome in [MatrixOutcome::Pass, MatrixOutcome::Fail] {
        let json = serde_json::to_string(&outcome).unwrap();
        let back: MatrixOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, back);
    }
}

#[test]
fn matrix_outcome_snake_case_values() {
    assert_eq!(
        serde_json::to_string(&MatrixOutcome::Pass).unwrap(),
        "\"pass\""
    );
    assert_eq!(
        serde_json::to_string(&MatrixOutcome::Fail).unwrap(),
        "\"fail\""
    );
}

#[test]
fn failure_scope_kind_serde_roundtrip() {
    for scope in [
        FailureScopeKind::Universal,
        FailureScopeKind::VersionSpecific,
    ] {
        let json = serde_json::to_string(&scope).unwrap();
        let back: FailureScopeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(scope, back);
    }
}

// ===========================================================================
// 4. VersionMatrixError
// ===========================================================================

#[test]
fn error_display_missing_current_includes_repo() {
    let e = VersionMatrixError::MissingCurrentVersion {
        repo: "my-engine".to_string(),
    };
    let msg = e.to_string();
    assert!(msg.contains("my-engine"));
    assert!(msg.contains("current version"));
}

#[test]
fn error_display_invalid_pinned_includes_surface_and_reason() {
    let e = VersionMatrixError::InvalidPinnedCombination {
        boundary_surface: "ifc-surface".to_string(),
        reason: "empty local_version".to_string(),
    };
    let msg = e.to_string();
    assert!(msg.contains("ifc-surface"));
    assert!(msg.contains("empty local_version"));
}

#[test]
fn error_implements_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(VersionMatrixError::MissingCurrentVersion {
        repo: "x".to_string(),
    });
    assert!(e.source().is_none());
    assert!(!e.to_string().is_empty());
}

#[test]
fn error_clone_eq() {
    let e1 = VersionMatrixError::MissingCurrentVersion {
        repo: "r".to_string(),
    };
    let e2 = e1.clone();
    assert_eq!(e1, e2);

    let e3 = VersionMatrixError::InvalidPinnedCombination {
        boundary_surface: "s".to_string(),
        reason: "r".to_string(),
    };
    let e4 = e3.clone();
    assert_eq!(e3, e4);
    assert_ne!(e1, e3);
}

// ===========================================================================
// 5. VersionSource / BoundaryMatrixSpec serde
// ===========================================================================

#[test]
fn version_source_default_is_empty() {
    let vs = VersionSource::default();
    assert!(vs.tags.is_empty());
    assert!(vs.branch_names.is_empty());
    assert!(vs.current_override.is_none());
    assert!(vs.previous_override.is_none());
    assert!(vs.next_override.is_none());
}

#[test]
fn version_source_serde_roundtrip() {
    let vs = VersionSource {
        tags: vec!["v1.0.0".to_string(), "v2.0.0-beta".to_string()],
        branch_names: vec!["main".to_string(), "next".to_string()],
        current_override: Some("1.0.0".to_string()),
        previous_override: None,
        next_override: Some("3.0.0".to_string()),
    };
    let json = serde_json::to_string(&vs).unwrap();
    let back: VersionSource = serde_json::from_str(&json).unwrap();
    assert_eq!(vs, back);
}

#[test]
fn boundary_matrix_spec_serde_roundtrip() {
    let spec = simple_spec("ifc", &["v1.0.0", "v0.9.0"], &["v2.0.0", "v1.9.0"]);
    let json = serde_json::to_string(&spec).unwrap();
    let back: BoundaryMatrixSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, back);
}

#[test]
fn boundary_matrix_spec_pinned_combinations_default_empty() {
    // pinned_combinations has serde(default), so missing field should deserialize as empty vec.
    let json = r#"{
        "boundary_surface": "test",
        "local_repo": "lr",
        "remote_repo": "rr",
        "local_versions": {"tags":[],"branch_names":[],"current_override":null,"previous_override":null,"next_override":null},
        "remote_versions": {"tags":[],"branch_names":[],"current_override":null,"previous_override":null,"next_override":null}
    }"#;
    let spec: BoundaryMatrixSpec = serde_json::from_str(json).unwrap();
    assert!(spec.pinned_combinations.is_empty());
}

// ===========================================================================
// 6. derive_version_slots
// ===========================================================================

#[test]
fn derive_slots_picks_latest_stable_as_current() {
    let source = simple_version_source(&["v1.0.0", "v2.0.0", "v1.5.0"]);
    let slots = derive_version_slots(&source, "engine").unwrap();
    assert_eq!(slots.current, "2.0.0");
}

#[test]
fn derive_slots_previous_is_next_lower_stable() {
    let source = simple_version_source(&["v1.0.0", "v1.1.0", "v1.2.0"]);
    let slots = derive_version_slots(&source, "engine").unwrap();
    assert_eq!(slots.current, "1.2.0");
    assert_eq!(slots.previous, Some("1.1.0".to_string()));
}

#[test]
fn derive_slots_no_previous_when_single_stable() {
    let source = simple_version_source(&["v1.0.0"]);
    let slots = derive_version_slots(&source, "engine").unwrap();
    assert_eq!(slots.current, "1.0.0");
    assert!(slots.previous.is_none());
}

#[test]
fn derive_slots_current_override_takes_precedence() {
    let mut source = simple_version_source(&["v1.0.0", "v2.0.0"]);
    source.current_override = Some("9.9.9".to_string());
    let slots = derive_version_slots(&source, "engine").unwrap();
    assert_eq!(slots.current, "9.9.9");
}

#[test]
fn derive_slots_previous_override_takes_precedence() {
    let mut source = simple_version_source(&["v1.0.0", "v2.0.0"]);
    source.previous_override = Some("0.1.0".to_string());
    let slots = derive_version_slots(&source, "engine").unwrap();
    assert_eq!(slots.previous, Some("0.1.0".to_string()));
}

#[test]
fn derive_slots_next_override_takes_precedence() {
    let mut source = simple_version_source(&["v1.0.0"]);
    source.next_override = Some("99.0.0".to_string());
    let slots = derive_version_slots(&source, "engine").unwrap();
    assert_eq!(slots.next, Some("99.0.0".to_string()));
}

#[test]
fn derive_slots_prerelease_tag_becomes_next() {
    let source = simple_version_source(&["v1.0.0", "v1.1.0-rc.1"]);
    let slots = derive_version_slots(&source, "engine").unwrap();
    assert_eq!(slots.current, "1.0.0");
    assert_eq!(slots.next, Some("1.1.0-rc.1".to_string()));
    assert!(
        slots
            .derivation_notes
            .iter()
            .any(|n| n.contains("prerelease"))
    );
}

#[test]
fn derive_slots_branch_main_derives_next_when_no_prerelease() {
    let mut source = simple_version_source(&["v1.0.0"]);
    source.branch_names = vec!["main".to_string()];
    let slots = derive_version_slots(&source, "engine").unwrap();
    assert_eq!(slots.next, Some("1.0.1-next".to_string()));
    assert!(slots.derivation_notes.iter().any(|n| n.contains("branch")));
}

#[test]
fn derive_slots_branch_nightly_derives_next() {
    let mut source = simple_version_source(&["v3.2.1"]);
    source.branch_names = vec!["nightly-build".to_string()];
    let slots = derive_version_slots(&source, "engine").unwrap();
    assert_eq!(slots.next, Some("3.2.2-next".to_string()));
}

#[test]
fn derive_slots_branch_next_derives_next() {
    let mut source = simple_version_source(&["v5.0.0"]);
    source.branch_names = vec!["feature-next".to_string()];
    let slots = derive_version_slots(&source, "engine").unwrap();
    assert_eq!(slots.next, Some("5.0.1-next".to_string()));
}

#[test]
fn derive_slots_no_tags_no_override_returns_error() {
    let source = VersionSource::default();
    let result = derive_version_slots(&source, "my-repo");
    match result {
        Err(VersionMatrixError::MissingCurrentVersion { repo }) => {
            assert_eq!(repo, "my-repo");
        }
        _ => panic!("expected MissingCurrentVersion error"),
    }
}

#[test]
fn derive_slots_only_prereleases_picks_latest_prerelease() {
    let source = simple_version_source(&["v1.0.0-alpha", "v1.0.0-beta", "v0.9.0-rc.1"]);
    let slots = derive_version_slots(&source, "engine").unwrap();
    // No stable versions; should pick latest prerelease as current.
    assert_eq!(slots.current, "1.0.0-beta");
}

#[test]
fn derive_slots_v_prefix_stripped_in_current() {
    let source = simple_version_source(&["v4.5.6"]);
    let slots = derive_version_slots(&source, "engine").unwrap();
    // The formatted version should not have a 'v' prefix.
    assert_eq!(slots.current, "4.5.6");
}

#[test]
fn derive_slots_many_versions_picks_correct_previous() {
    let source = simple_version_source(&["v1.0.0", "v1.1.0", "v1.2.0", "v2.0.0", "v2.1.0"]);
    let slots = derive_version_slots(&source, "engine").unwrap();
    assert_eq!(slots.current, "2.1.0");
    assert_eq!(slots.previous, Some("2.0.0".to_string()));
}

// ===========================================================================
// 7. derive_version_matrix
// ===========================================================================

#[test]
fn derive_matrix_empty_specs_returns_empty_plan() {
    let plan = derive_version_matrix(&[]).unwrap();
    assert!(plan.cells.is_empty());
    assert_eq!(plan.schema_version, VERSION_MATRIX_SCHEMA);
    assert_eq!(plan.generated_at_utc, "1970-01-01T00:00:00Z");
}

#[test]
fn derive_matrix_single_spec_current_cell() {
    let spec = simple_spec("ifc", &["v1.0.0"], &["v2.0.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    let current_cells: Vec<_> = plan
        .cells
        .iter()
        .filter(|c| c.lane_kind == MatrixLaneKind::Current)
        .collect();
    assert_eq!(current_cells.len(), 1);
    assert_eq!(current_cells[0].local_version, "1.0.0");
    assert_eq!(current_cells[0].remote_version, "2.0.0");
    assert!(!current_cells[0].pinned);
}

#[test]
fn derive_matrix_includes_previous_lane_when_remote_has_multiple() {
    let spec = simple_spec("ifc", &["v1.0.0"], &["v2.0.0", "v1.9.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    let prev = plan
        .cells
        .iter()
        .find(|c| c.lane_kind == MatrixLaneKind::Previous);
    assert!(prev.is_some());
    let prev = prev.unwrap();
    assert_eq!(prev.local_version, "1.0.0");
    assert_eq!(prev.remote_version, "1.9.0");
}

#[test]
fn derive_matrix_includes_next_lane_with_prerelease_remote() {
    let spec = simple_spec("ifc", &["v1.0.0"], &["v2.0.0", "v2.1.0-rc.1"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    let next = plan
        .cells
        .iter()
        .find(|c| c.lane_kind == MatrixLaneKind::Next);
    assert!(next.is_some());
    assert_eq!(next.unwrap().remote_version, "2.1.0-rc.1");
}

#[test]
fn derive_matrix_pinned_combination_creates_pinned_cell() {
    let mut spec = simple_spec("ifc", &["v1.0.0"], &["v2.0.0"]);
    spec.pinned_combinations.push(PinnedVersionCombination {
        local_version: "0.8.0".to_string(),
        remote_version: "1.5.0".to_string(),
        reason: "legacy customer".to_string(),
    });
    let plan = derive_version_matrix(&[spec]).unwrap();
    let pinned: Vec<_> = plan
        .cells
        .iter()
        .filter(|c| c.lane_kind == MatrixLaneKind::Pinned)
        .collect();
    assert_eq!(pinned.len(), 1);
    assert!(pinned[0].pinned);
    assert_eq!(pinned[0].local_version, "0.8.0");
    assert_eq!(pinned[0].remote_version, "1.5.0");
}

#[test]
fn derive_matrix_rejects_empty_local_pinned_version() {
    let mut spec = simple_spec("ifc", &["v1.0.0"], &["v2.0.0"]);
    spec.pinned_combinations.push(PinnedVersionCombination {
        local_version: "".to_string(),
        remote_version: "1.0.0".to_string(),
        reason: "bad".to_string(),
    });
    let result = derive_version_matrix(&[spec]);
    assert!(matches!(
        result,
        Err(VersionMatrixError::InvalidPinnedCombination { .. })
    ));
}

#[test]
fn derive_matrix_rejects_empty_remote_pinned_version() {
    let mut spec = simple_spec("ifc", &["v1.0.0"], &["v2.0.0"]);
    spec.pinned_combinations.push(PinnedVersionCombination {
        local_version: "1.0.0".to_string(),
        remote_version: "  ".to_string(),
        reason: "whitespace-only".to_string(),
    });
    let result = derive_version_matrix(&[spec]);
    assert!(matches!(
        result,
        Err(VersionMatrixError::InvalidPinnedCombination { .. })
    ));
}

#[test]
fn derive_matrix_deduplicates_identical_specs() {
    let spec = simple_spec("ifc", &["v1.0.0", "v0.9.0"], &["v2.0.0", "v1.9.0"]);
    let plan = derive_version_matrix(&[spec.clone(), spec]).unwrap();
    // Duplicate cells from the same spec should be deduplicated by cell_id.
    let ids: BTreeSet<_> = plan.cells.iter().map(|c| c.cell_id.clone()).collect();
    assert_eq!(ids.len(), plan.cells.len());
}

#[test]
fn derive_matrix_cells_sorted_by_surface_then_lane_then_versions() {
    let spec_a = simple_spec("aaa", &["v1.0.0"], &["v2.0.0", "v1.9.0"]);
    let spec_b = simple_spec("bbb", &["v1.0.0"], &["v3.0.0"]);
    let plan = derive_version_matrix(&[spec_b, spec_a]).unwrap();
    // Cells should be sorted: aaa before bbb.
    let surfaces: Vec<_> = plan
        .cells
        .iter()
        .map(|c| c.boundary_surface.clone())
        .collect();
    for window in surfaces.windows(2) {
        assert!(window[0] <= window[1]);
    }
}

#[test]
fn derive_matrix_cell_id_format() {
    let spec = simple_spec("ifc", &["v1.0.0"], &["v2.0.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    let current = plan
        .cells
        .iter()
        .find(|c| c.lane_kind == MatrixLaneKind::Current)
        .unwrap();
    assert_eq!(current.cell_id, "ifc::n_n::1.0.0::2.0.0");
}

#[test]
fn derive_matrix_conformance_command_contains_cell_id() {
    let spec = simple_spec("ifc", &["v1.0.0"], &["v2.0.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    for cell in &plan.cells {
        assert!(cell.expected_conformance_command.contains(&cell.cell_id));
        assert!(cell.expected_conformance_command.contains("--matrix-cell"));
    }
}

#[test]
fn derive_matrix_multiple_specs_produces_cells_for_each() {
    let spec1 = simple_spec("ifc", &["v1.0.0"], &["v2.0.0"]);
    let spec2 = simple_spec("rpc", &["v3.0.0"], &["v4.0.0"]);
    let plan = derive_version_matrix(&[spec1, spec2]).unwrap();
    let surfaces: BTreeSet<_> = plan
        .cells
        .iter()
        .map(|c| c.boundary_surface.clone())
        .collect();
    assert!(surfaces.contains("ifc"));
    assert!(surfaces.contains("rpc"));
}

#[test]
fn derive_matrix_multiple_pinned_combinations() {
    let mut spec = simple_spec("ifc", &["v1.0.0"], &["v2.0.0"]);
    spec.pinned_combinations.push(PinnedVersionCombination {
        local_version: "0.8.0".to_string(),
        remote_version: "1.5.0".to_string(),
        reason: "legacy-a".to_string(),
    });
    spec.pinned_combinations.push(PinnedVersionCombination {
        local_version: "0.7.0".to_string(),
        remote_version: "1.4.0".to_string(),
        reason: "legacy-b".to_string(),
    });
    let plan = derive_version_matrix(&[spec]).unwrap();
    let pinned_count = plan
        .cells
        .iter()
        .filter(|c| c.lane_kind == MatrixLaneKind::Pinned)
        .count();
    assert_eq!(pinned_count, 2);
}

// ===========================================================================
// 8. VersionMatrixPlan serde
// ===========================================================================

#[test]
fn version_matrix_plan_serde_roundtrip() {
    let spec = simple_spec("ifc", &["v1.0.0", "v0.9.0"], &["v2.0.0", "v1.9.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    let json = serde_json::to_string_pretty(&plan).unwrap();
    let back: VersionMatrixPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(plan, back);
}

#[test]
fn version_matrix_plan_json_has_expected_fields() {
    let spec = simple_spec("ifc", &["v1.0.0"], &["v2.0.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    let json = serde_json::to_string(&plan).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"generated_at_utc\""));
    assert!(json.contains("\"cells\""));
    assert!(json.contains("\"cell_id\""));
    assert!(json.contains("\"lane_kind\""));
    assert!(json.contains("\"expected_conformance_command\""));
}

// ===========================================================================
// 9. MatrixCellResult serde
// ===========================================================================

#[test]
fn matrix_cell_result_serde_roundtrip_pass() {
    let r = MatrixCellResult {
        trace_id: "t-001".to_string(),
        decision_id: "d-001".to_string(),
        policy_id: "p-001".to_string(),
        cell_id: "cell-001".to_string(),
        boundary_surface: "ifc".to_string(),
        lane_kind: MatrixLaneKind::Current,
        outcome: MatrixOutcome::Pass,
        error_code: None,
        failure_fingerprint: None,
        failure_class: None,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: MatrixCellResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn matrix_cell_result_serde_roundtrip_fail_with_details() {
    let r = MatrixCellResult {
        trace_id: "t-002".to_string(),
        decision_id: "d-002".to_string(),
        policy_id: "p-002".to_string(),
        cell_id: "cell-002".to_string(),
        boundary_surface: "rpc".to_string(),
        lane_kind: MatrixLaneKind::Next,
        outcome: MatrixOutcome::Fail,
        error_code: Some("E-TIMEOUT".to_string()),
        failure_fingerprint: Some("fp-abc123".to_string()),
        failure_class: Some("network".to_string()),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: MatrixCellResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ===========================================================================
// 10. classify_failure_scopes
// ===========================================================================

#[test]
fn classify_no_failures_returns_empty() {
    let spec = simple_spec("ifc", &["v1.0.0", "v0.9.0"], &["v2.0.0", "v1.9.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    let results: Vec<_> = plan
        .cells
        .iter()
        .map(|c| make_result(c, MatrixOutcome::Pass))
        .collect();
    let scopes = classify_failure_scopes(&plan, &results);
    assert!(scopes.is_empty());
}

#[test]
fn classify_universal_when_all_cells_fail_same_fingerprint() {
    let spec = simple_spec("ifc", &["v1.0.0", "v0.9.0"], &["v2.0.0", "v1.9.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    assert!(
        plan.cells.len() >= 2,
        "need at least 2 cells for universal test"
    );
    let results: Vec<_> = plan
        .cells
        .iter()
        .map(|c| make_fail_result(c, "fp-universal", "E1"))
        .collect();
    let scopes = classify_failure_scopes(&plan, &results);
    assert!(!scopes.is_empty());
    assert!(
        scopes
            .iter()
            .all(|s| s.scope == FailureScopeKind::Universal)
    );
}

#[test]
fn classify_version_specific_when_only_one_cell_fails() {
    let spec = simple_spec("ifc", &["v1.0.0", "v0.9.0"], &["v2.0.0", "v1.9.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    assert!(plan.cells.len() >= 2);
    let mut results: Vec<_> = plan
        .cells
        .iter()
        .map(|c| make_result(c, MatrixOutcome::Pass))
        .collect();
    // Fail only the first cell.
    results[0] = make_fail_result(&plan.cells[0], "fp-specific", "E2");
    let scopes = classify_failure_scopes(&plan, &results);
    assert_eq!(scopes.len(), 1);
    assert_eq!(scopes[0].scope, FailureScopeKind::VersionSpecific);
    assert_eq!(scopes[0].failing_cells.len(), 1);
}

#[test]
fn classify_multiple_fingerprints_same_boundary() {
    let spec = simple_spec("ifc", &["v1.0.0", "v0.9.0"], &["v2.0.0", "v1.9.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    assert!(plan.cells.len() >= 2);
    let mut results: Vec<_> = plan
        .cells
        .iter()
        .map(|c| make_result(c, MatrixOutcome::Pass))
        .collect();
    results[0] = make_fail_result(&plan.cells[0], "fp-A", "E1");
    results[1] = make_fail_result(&plan.cells[1], "fp-B", "E2");
    let scopes = classify_failure_scopes(&plan, &results);
    // Two different fingerprints => two scope entries.
    let fingerprints: BTreeSet<_> = scopes
        .iter()
        .map(|s| s.failure_fingerprint.clone())
        .collect();
    assert!(fingerprints.contains("fp-A"));
    assert!(fingerprints.contains("fp-B"));
}

#[test]
fn classify_scopes_sorted_by_boundary_then_fingerprint() {
    let spec_a = simple_spec("aaa", &["v1.0.0"], &["v2.0.0"]);
    let spec_b = simple_spec("bbb", &["v1.0.0"], &["v2.0.0"]);
    let plan = derive_version_matrix(&[spec_a, spec_b]).unwrap();
    let results: Vec<_> = plan
        .cells
        .iter()
        .map(|c| make_fail_result(c, "fp-x", "E1"))
        .collect();
    let scopes = classify_failure_scopes(&plan, &results);
    for window in scopes.windows(2) {
        let ord = window[0]
            .boundary_surface
            .cmp(&window[1].boundary_surface)
            .then(
                window[0]
                    .failure_fingerprint
                    .cmp(&window[1].failure_fingerprint),
            );
        assert!(ord != std::cmp::Ordering::Greater);
    }
}

#[test]
fn classify_fails_without_fingerprint_are_ignored() {
    let spec = simple_spec("ifc", &["v1.0.0"], &["v2.0.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    // Fail with no fingerprint.
    let results: Vec<_> = plan
        .cells
        .iter()
        .map(|c| MatrixCellResult {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            cell_id: c.cell_id.clone(),
            boundary_surface: c.boundary_surface.clone(),
            lane_kind: c.lane_kind,
            outcome: MatrixOutcome::Fail,
            error_code: Some("E1".to_string()),
            failure_fingerprint: None,
            failure_class: None,
        })
        .collect();
    let scopes = classify_failure_scopes(&plan, &results);
    assert!(scopes.is_empty());
}

#[test]
fn classify_failing_cells_within_scope_are_sorted() {
    let spec = simple_spec("ifc", &["v1.0.0", "v0.9.0"], &["v2.0.0", "v1.9.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    let results: Vec<_> = plan
        .cells
        .iter()
        .map(|c| make_fail_result(c, "fp-same", "E1"))
        .collect();
    let scopes = classify_failure_scopes(&plan, &results);
    for scope in &scopes {
        let mut sorted = scope.failing_cells.clone();
        sorted.sort();
        assert_eq!(scope.failing_cells, sorted);
    }
}

// ===========================================================================
// 11. summarize_matrix_health
// ===========================================================================

#[test]
fn health_all_pass() {
    let spec = simple_spec("ifc", &["v1.0.0", "v0.9.0"], &["v2.0.0", "v1.9.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    let results: Vec<_> = plan
        .cells
        .iter()
        .map(|c| make_result(c, MatrixOutcome::Pass))
        .collect();
    let health = summarize_matrix_health(&plan, &results);
    assert_eq!(health.total_cells, plan.cells.len());
    assert_eq!(health.passed_cells, plan.cells.len());
    assert_eq!(health.failed_cells, 0);
    assert_eq!(health.universal_failures, 0);
    assert_eq!(health.version_specific_failures, 0);
}

#[test]
fn health_all_fail_universal() {
    let spec = simple_spec("ifc", &["v1.0.0", "v0.9.0"], &["v2.0.0", "v1.9.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    let results: Vec<_> = plan
        .cells
        .iter()
        .map(|c| make_fail_result(c, "fp-all", "E1"))
        .collect();
    let health = summarize_matrix_health(&plan, &results);
    assert_eq!(health.total_cells, plan.cells.len());
    assert_eq!(health.passed_cells, 0);
    assert_eq!(health.failed_cells, plan.cells.len());
    assert!(health.universal_failures > 0);
}

#[test]
fn health_mixed_outcomes() {
    let spec = simple_spec("ifc", &["v1.0.0", "v0.9.0"], &["v2.0.0", "v1.9.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    assert!(plan.cells.len() >= 2);
    let mut results: Vec<_> = plan
        .cells
        .iter()
        .map(|c| make_result(c, MatrixOutcome::Pass))
        .collect();
    // Fail one cell.
    results[0] = make_fail_result(&plan.cells[0], "fp-one", "E1");
    let health = summarize_matrix_health(&plan, &results);
    assert_eq!(health.passed_cells, plan.cells.len() - 1);
    assert_eq!(health.failed_cells, 1);
    assert_eq!(health.version_specific_failures, 1);
    assert_eq!(health.universal_failures, 0);
}

#[test]
fn health_empty_results_all_zeroes() {
    let spec = simple_spec("ifc", &["v1.0.0"], &["v2.0.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    let health = summarize_matrix_health(&plan, &[]);
    assert_eq!(health.total_cells, plan.cells.len());
    assert_eq!(health.passed_cells, 0);
    assert_eq!(health.failed_cells, 0);
}

#[test]
fn health_serde_roundtrip() {
    let summary = MatrixHealthSummary {
        total_cells: 10,
        passed_cells: 7,
        failed_cells: 3,
        universal_failures: 1,
        version_specific_failures: 2,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: MatrixHealthSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ===========================================================================
// 12. VersionSlots serde
// ===========================================================================

#[test]
fn version_slots_serde_roundtrip() {
    let slots = VersionSlots {
        current: "1.0.0".to_string(),
        previous: Some("0.9.0".to_string()),
        next: Some("1.1.0-next".to_string()),
        derivation_notes: vec!["derived from branch".to_string()],
    };
    let json = serde_json::to_string(&slots).unwrap();
    let back: VersionSlots = serde_json::from_str(&json).unwrap();
    assert_eq!(slots, back);
}

#[test]
fn version_slots_serde_roundtrip_none_fields() {
    let slots = VersionSlots {
        current: "2.0.0".to_string(),
        previous: None,
        next: None,
        derivation_notes: vec![],
    };
    let json = serde_json::to_string(&slots).unwrap();
    let back: VersionSlots = serde_json::from_str(&json).unwrap();
    assert_eq!(slots, back);
}

// ===========================================================================
// 13. MatrixFailureScope serde
// ===========================================================================

#[test]
fn matrix_failure_scope_serde_roundtrip() {
    let scope = MatrixFailureScope {
        boundary_surface: "ifc".to_string(),
        failure_fingerprint: "fp-round".to_string(),
        scope: FailureScopeKind::VersionSpecific,
        failing_cells: vec!["c1".to_string(), "c2".to_string()],
    };
    let json = serde_json::to_string(&scope).unwrap();
    let back: MatrixFailureScope = serde_json::from_str(&json).unwrap();
    assert_eq!(scope, back);
}

// ===========================================================================
// 14. PinnedVersionCombination serde
// ===========================================================================

#[test]
fn pinned_version_combination_serde_roundtrip() {
    let pvc = PinnedVersionCombination {
        local_version: "1.0.0".to_string(),
        remote_version: "2.0.0".to_string(),
        reason: "legacy support".to_string(),
    };
    let json = serde_json::to_string(&pvc).unwrap();
    let back: PinnedVersionCombination = serde_json::from_str(&json).unwrap();
    assert_eq!(pvc, back);
}

// ===========================================================================
// 15. End-to-end scenario: multi-boundary, mixed outcomes
// ===========================================================================

#[test]
fn e2e_multi_boundary_full_pipeline() {
    // Build two boundary surfaces with different version landscapes.
    let mut spec_ifc = simple_spec(
        "ifc",
        &["v1.0.0", "v0.9.0"],
        &["v2.0.0", "v1.9.0", "v2.1.0-rc.1"],
    );
    spec_ifc.pinned_combinations.push(PinnedVersionCombination {
        local_version: "0.8.0".to_string(),
        remote_version: "1.5.0".to_string(),
        reason: "legacy".to_string(),
    });
    let spec_rpc = simple_spec("rpc", &["v3.0.0"], &["v4.0.0"]);

    let plan = derive_version_matrix(&[spec_ifc, spec_rpc]).unwrap();
    assert_eq!(plan.schema_version, VERSION_MATRIX_SCHEMA);

    // Verify we have cells for both boundaries.
    let boundaries: BTreeSet<_> = plan
        .cells
        .iter()
        .map(|c| c.boundary_surface.clone())
        .collect();
    assert!(boundaries.contains("ifc"));
    assert!(boundaries.contains("rpc"));

    // ifc should have: current, previous, next, pinned = 4 cells.
    let ifc_cells: Vec<_> = plan
        .cells
        .iter()
        .filter(|c| c.boundary_surface == "ifc")
        .collect();
    assert_eq!(ifc_cells.len(), 4);

    // Verify lane kinds for ifc.
    let ifc_kinds: BTreeSet<_> = ifc_cells.iter().map(|c| c.lane_kind).collect();
    assert!(ifc_kinds.contains(&MatrixLaneKind::Current));
    assert!(ifc_kinds.contains(&MatrixLaneKind::Previous));
    assert!(ifc_kinds.contains(&MatrixLaneKind::Next));
    assert!(ifc_kinds.contains(&MatrixLaneKind::Pinned));

    // Build results: ifc all fail, rpc passes.
    let mut results = Vec::new();
    for cell in &plan.cells {
        if cell.boundary_surface == "ifc" {
            results.push(make_fail_result(cell, "fp-ifc-bug", "E42"));
        } else {
            results.push(make_result(cell, MatrixOutcome::Pass));
        }
    }

    let scopes = classify_failure_scopes(&plan, &results);
    // ifc should have a universal failure scope.
    let ifc_scopes: Vec<_> = scopes
        .iter()
        .filter(|s| s.boundary_surface == "ifc")
        .collect();
    assert_eq!(ifc_scopes.len(), 1);
    assert_eq!(ifc_scopes[0].scope, FailureScopeKind::Universal);
    assert_eq!(ifc_scopes[0].failing_cells.len(), 4);

    // rpc should have no failure scopes.
    let rpc_scopes: Vec<_> = scopes
        .iter()
        .filter(|s| s.boundary_surface == "rpc")
        .collect();
    assert!(rpc_scopes.is_empty());

    // Health summary.
    let health = summarize_matrix_health(&plan, &results);
    assert_eq!(health.total_cells, plan.cells.len());
    assert_eq!(health.passed_cells, 1);
    assert_eq!(health.failed_cells, 4);
    assert_eq!(health.universal_failures, 1);
    assert_eq!(health.version_specific_failures, 0);
}

// ===========================================================================
// 16. VersionMatrixCell fields populated correctly
// ===========================================================================

#[test]
fn cell_local_repo_and_remote_repo_propagated() {
    let spec = BoundaryMatrixSpec {
        boundary_surface: "ifc".to_string(),
        local_repo: "my-engine".to_string(),
        remote_repo: "my-host".to_string(),
        local_versions: simple_version_source(&["v1.0.0"]),
        remote_versions: simple_version_source(&["v2.0.0"]),
        pinned_combinations: vec![],
    };
    let plan = derive_version_matrix(&[spec]).unwrap();
    for cell in &plan.cells {
        assert_eq!(cell.local_repo, "my-engine");
        assert_eq!(cell.remote_repo, "my-host");
        assert_eq!(cell.boundary_surface, "ifc");
    }
}

// ===========================================================================
// 17. Clone/Eq for VersionMatrixCell
// ===========================================================================

#[test]
fn version_matrix_cell_clone_eq() {
    let spec = simple_spec("ifc", &["v1.0.0"], &["v2.0.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    for cell in &plan.cells {
        let cloned = cell.clone();
        assert_eq!(cell, &cloned);
    }
}

// ===========================================================================
// 18. VersionMatrixPlan clone eq
// ===========================================================================

#[test]
fn version_matrix_plan_clone_eq() {
    let spec = simple_spec("ifc", &["v1.0.0", "v0.9.0"], &["v2.0.0", "v1.9.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    let cloned = plan.clone();
    assert_eq!(plan, cloned);
}

// ===========================================================================
// 19. Derive with branch-derived next on the local side too
// ===========================================================================

#[test]
fn derive_matrix_next_lane_from_branch_convention() {
    let mut spec = simple_spec("ifc", &["v1.0.0"], &["v2.0.0"]);
    spec.remote_versions.branch_names = vec!["main".to_string()];
    let plan = derive_version_matrix(&[spec]).unwrap();
    let next = plan
        .cells
        .iter()
        .find(|c| c.lane_kind == MatrixLaneKind::Next);
    assert!(next.is_some());
    assert_eq!(next.unwrap().remote_version, "2.0.1-next");
}

// ===========================================================================
// 20. Large matrix with many specs
// ===========================================================================

#[test]
fn derive_matrix_ten_specs_no_panic() {
    let specs: Vec<_> = (0..10)
        .map(|i| {
            simple_spec(
                &format!("surface-{i:02}"),
                &["v1.0.0", "v0.9.0"],
                &["v2.0.0", "v1.9.0"],
            )
        })
        .collect();
    let plan = derive_version_matrix(&specs).unwrap();
    // Each spec produces current + previous = 2 cells minimum.
    assert!(plan.cells.len() >= 20);
    // Verify all cell_ids are unique.
    let ids: BTreeSet<_> = plan.cells.iter().map(|c| c.cell_id.clone()).collect();
    assert_eq!(ids.len(), plan.cells.len());
}

// ===========================================================================
// 21. Verify that classify returns empty when plan has cells but results is empty
// ===========================================================================

#[test]
fn classify_empty_results_returns_empty_scopes() {
    let spec = simple_spec("ifc", &["v1.0.0"], &["v2.0.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    let scopes = classify_failure_scopes(&plan, &[]);
    assert!(scopes.is_empty());
}

// ===========================================================================
// 22. Debug formatting
// ===========================================================================

#[test]
fn all_types_implement_debug() {
    let vs = VersionSource::default();
    let _ = format!("{vs:?}");

    let pvc = PinnedVersionCombination {
        local_version: "a".to_string(),
        remote_version: "b".to_string(),
        reason: "c".to_string(),
    };
    let _ = format!("{pvc:?}");

    let spec = simple_spec("ifc", &["v1.0.0"], &["v2.0.0"]);
    let _ = format!("{spec:?}");

    let plan = derive_version_matrix(&[spec]).unwrap();
    let _ = format!("{plan:?}");

    let err = VersionMatrixError::MissingCurrentVersion {
        repo: "r".to_string(),
    };
    let _ = format!("{err:?}");

    let health = MatrixHealthSummary {
        total_cells: 1,
        passed_cells: 1,
        failed_cells: 0,
        universal_failures: 0,
        version_specific_failures: 0,
    };
    let _ = format!("{health:?}");

    let scope = MatrixFailureScope {
        boundary_surface: "b".to_string(),
        failure_fingerprint: "f".to_string(),
        scope: FailureScopeKind::Universal,
        failing_cells: vec![],
    };
    let _ = format!("{scope:?}");
}

// ===========================================================================
// 23. Tags with complex formats (e.g., release/v1.0.0)
// ===========================================================================

#[test]
fn derive_slots_tags_with_path_separators() {
    // parse_versions_from_tags splits on non-(alnum, '.', '-') chars.
    let source = VersionSource {
        tags: vec!["release/v1.0.0".to_string(), "release/v2.0.0".to_string()],
        branch_names: vec![],
        current_override: None,
        previous_override: None,
        next_override: None,
    };
    let slots = derive_version_slots(&source, "engine").unwrap();
    assert_eq!(slots.current, "2.0.0");
    assert_eq!(slots.previous, Some("1.0.0".to_string()));
}

#[test]
fn derive_slots_tags_with_equals_separator() {
    let source = VersionSource {
        tags: vec!["package=v3.1.4".to_string()],
        branch_names: vec![],
        current_override: None,
        previous_override: None,
        next_override: None,
    };
    let slots = derive_version_slots(&source, "engine").unwrap();
    assert_eq!(slots.current, "3.1.4");
}

// ===========================================================================
// 24. Multiple prereleases, highest is chosen for next
// ===========================================================================

#[test]
fn derive_slots_multiple_prereleases_picks_highest() {
    let source =
        simple_version_source(&["v1.0.0", "v1.1.0-alpha.1", "v1.1.0-beta.1", "v1.1.0-rc.1"]);
    let slots = derive_version_slots(&source, "engine").unwrap();
    assert_eq!(slots.current, "1.0.0");
    // rc.1 > beta.1 > alpha.1 lexicographically.
    assert_eq!(slots.next, Some("1.1.0-rc.1".to_string()));
}

// ===========================================================================
// 25. Duplicate pinned combination is deduplicated
// ===========================================================================

#[test]
fn derive_matrix_duplicate_pinned_deduped() {
    let mut spec = simple_spec("ifc", &["v1.0.0"], &["v2.0.0"]);
    let pvc = PinnedVersionCombination {
        local_version: "0.8.0".to_string(),
        remote_version: "1.5.0".to_string(),
        reason: "legacy".to_string(),
    };
    spec.pinned_combinations.push(pvc.clone());
    spec.pinned_combinations.push(pvc);
    let plan = derive_version_matrix(&[spec]).unwrap();
    let pinned_count = plan
        .cells
        .iter()
        .filter(|c| c.lane_kind == MatrixLaneKind::Pinned)
        .count();
    // Deduplication by cell_id means identical pinned combos produce only one cell.
    assert_eq!(pinned_count, 1);
}

// ===========================================================================
// 26. VersionMatrixCell boundary_surface matches spec
// ===========================================================================

#[test]
fn cell_boundary_surface_always_matches_spec() {
    let spec = simple_spec("my-boundary", &["v1.0.0"], &["v2.0.0"]);
    let plan = derive_version_matrix(&[spec]).unwrap();
    for cell in &plan.cells {
        assert_eq!(cell.boundary_surface, "my-boundary");
    }
}

// ===========================================================================
// 27. BTreeMap usage in failure grouping
// ===========================================================================

#[test]
fn classify_deterministic_ordering_across_boundaries() {
    let specs: Vec<_> = ["alpha", "beta", "gamma"]
        .iter()
        .map(|name| simple_spec(name, &["v1.0.0"], &["v2.0.0"]))
        .collect();
    let plan = derive_version_matrix(&specs).unwrap();
    let results: Vec<_> = plan
        .cells
        .iter()
        .map(|c| make_fail_result(c, "fp-shared", "E1"))
        .collect();
    let scopes = classify_failure_scopes(&plan, &results);
    let boundary_order: Vec<_> = scopes.iter().map(|s| s.boundary_surface.clone()).collect();
    assert_eq!(boundary_order, vec!["alpha", "beta", "gamma"]);
}
