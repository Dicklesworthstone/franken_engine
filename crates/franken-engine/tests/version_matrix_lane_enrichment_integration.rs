//! Enrichment integration tests for `version_matrix_lane`.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use frankenengine_engine::version_matrix_lane::*;

fn make_version_source() -> VersionSource {
    VersionSource {
        tags: vec!["v1.0.0".to_string(), "v1.1.0".to_string(), "v2.0.0".to_string()],
        branch_names: vec!["main".to_string()],
        current_override: None,
        previous_override: None,
        next_override: None,
    }
}

fn make_spec() -> BoundaryMatrixSpec {
    BoundaryMatrixSpec {
        boundary_surface: "http-api".to_string(),
        local_repo: "franken-engine".to_string(),
        remote_repo: "external-service".to_string(),
        local_versions: make_version_source(),
        remote_versions: make_version_source(),
        pinned_combinations: vec![],
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_version_matrix_schema_non_empty() {
    assert!(!VERSION_MATRIX_SCHEMA.is_empty());
}

// ---------------------------------------------------------------------------
// MatrixLaneKind
// ---------------------------------------------------------------------------

#[test]
fn enrichment_matrix_lane_kind_as_str_current() {
    let s = MatrixLaneKind::Current.as_str();
    assert!(!s.is_empty());
}

#[test]
fn enrichment_matrix_lane_kind_as_str_previous() {
    let s = MatrixLaneKind::Previous.as_str();
    assert!(!s.is_empty());
}

#[test]
fn enrichment_matrix_lane_kind_as_str_next() {
    let s = MatrixLaneKind::Next.as_str();
    assert!(!s.is_empty());
}

#[test]
fn enrichment_matrix_lane_kind_as_str_unique() {
    let mut strs = std::collections::BTreeSet::new();
    for kind in [MatrixLaneKind::Current, MatrixLaneKind::Previous, MatrixLaneKind::Next] {
        assert!(strs.insert(kind.as_str()));
    }
}

#[test]
fn enrichment_matrix_lane_kind_serde_roundtrip() {
    for kind in [
        MatrixLaneKind::Current,
        MatrixLaneKind::Previous,
        MatrixLaneKind::Next,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: MatrixLaneKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

// ---------------------------------------------------------------------------
// VersionSource serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_version_source_serde_roundtrip() {
    let src = make_version_source();
    let json = serde_json::to_string(&src).unwrap();
    let back: VersionSource = serde_json::from_str(&json).unwrap();
    assert_eq!(src, back);
}

// ---------------------------------------------------------------------------
// BoundaryMatrixSpec serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_boundary_matrix_spec_serde_roundtrip() {
    let spec = make_spec();
    let json = serde_json::to_string(&spec).unwrap();
    let back: BoundaryMatrixSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, back);
}

// ---------------------------------------------------------------------------
// derive_version_slots
// ---------------------------------------------------------------------------

#[test]
fn enrichment_derive_version_slots_from_tags() {
    let src = make_version_source();
    let slots = derive_version_slots(&src, "franken-engine").unwrap();
    assert!(!slots.current.is_empty());
}

#[test]
fn enrichment_derive_version_slots_with_override() {
    let mut src = make_version_source();
    src.current_override = Some("v99.0.0".to_string());
    let slots = derive_version_slots(&src, "franken-engine").unwrap();
    assert_eq!(slots.current, "v99.0.0");
}

#[test]
fn enrichment_derive_version_slots_empty_tags_error() {
    let src = VersionSource {
        tags: vec![],
        branch_names: vec![],
        current_override: None,
        previous_override: None,
        next_override: None,
    };
    let result = derive_version_slots(&src, "franken-engine");
    assert!(result.is_err());
}

#[test]
fn enrichment_derive_version_slots_serde_roundtrip() {
    let src = make_version_source();
    let slots = derive_version_slots(&src, "franken-engine").unwrap();
    let json = serde_json::to_string(&slots).unwrap();
    let back: VersionSlots = serde_json::from_str(&json).unwrap();
    assert_eq!(slots.current, back.current);
}

// ---------------------------------------------------------------------------
// derive_version_matrix
// ---------------------------------------------------------------------------

#[test]
fn enrichment_derive_version_matrix_produces_plan() {
    let spec = make_spec();
    let plan = derive_version_matrix(&[spec.clone()]).unwrap();
    assert_eq!(plan.schema_version, VERSION_MATRIX_SCHEMA);
    assert!(!plan.cells.is_empty());
}

#[test]
fn enrichment_derive_version_matrix_cells_have_boundary() {
    let spec = make_spec();
    let plan = derive_version_matrix(&[spec.clone()]).unwrap();
    for cell in &plan.cells {
        assert_eq!(cell.boundary_surface, "http-api");
    }
}

#[test]
fn enrichment_derive_version_matrix_plan_serde_roundtrip() {
    let spec = make_spec();
    let plan = derive_version_matrix(&[spec.clone()]).unwrap();
    let json = serde_json::to_string(&plan).unwrap();
    let back: VersionMatrixPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(plan.cells.len(), back.cells.len());
}

// ---------------------------------------------------------------------------
// MatrixOutcome / MatrixCellResult
// ---------------------------------------------------------------------------

#[test]
fn enrichment_matrix_outcome_serde_roundtrip() {
    for o in [MatrixOutcome::Pass, MatrixOutcome::Fail] {
        let json = serde_json::to_string(&o).unwrap();
        let back: MatrixOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }
}

#[test]
fn enrichment_matrix_cell_result_serde_roundtrip() {
    let result = MatrixCellResult {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        cell_id: "c1".to_string(),
        boundary_surface: "api".to_string(),
        lane_kind: MatrixLaneKind::Current,
        outcome: MatrixOutcome::Pass,
        error_code: None,
        failure_fingerprint: None,
        failure_class: None,
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: MatrixCellResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// classify_failure_scopes
// ---------------------------------------------------------------------------

#[test]
fn enrichment_classify_failure_scopes_no_failures() {
    let spec = make_spec();
    let plan = derive_version_matrix(&[spec.clone()]).unwrap();
    let results: Vec<MatrixCellResult> = plan.cells.iter().map(|c| MatrixCellResult {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        cell_id: c.cell_id.clone(),
        boundary_surface: c.boundary_surface.clone(),
        lane_kind: c.lane_kind,
        outcome: MatrixOutcome::Pass,
        error_code: None,
        failure_fingerprint: None,
        failure_class: None,
    }).collect();
    let scopes = classify_failure_scopes(&plan, &results);
    assert!(scopes.is_empty());
}

#[test]
fn enrichment_classify_failure_scopes_with_failure() {
    let spec = make_spec();
    let plan = derive_version_matrix(&[spec.clone()]).unwrap();
    let results: Vec<MatrixCellResult> = plan.cells.iter().map(|c| MatrixCellResult {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        cell_id: c.cell_id.clone(),
        boundary_surface: c.boundary_surface.clone(),
        lane_kind: c.lane_kind,
        outcome: MatrixOutcome::Fail,
        error_code: Some("E001".to_string()),
        failure_fingerprint: Some("fp1".to_string()),
        failure_class: Some("timeout".to_string()),
    }).collect();
    let scopes = classify_failure_scopes(&plan, &results);
    assert!(!scopes.is_empty());
}

// ---------------------------------------------------------------------------
// summarize_matrix_health
// ---------------------------------------------------------------------------

#[test]
fn enrichment_summarize_health_all_pass() {
    let spec = make_spec();
    let plan = derive_version_matrix(&[spec.clone()]).unwrap();
    let results: Vec<MatrixCellResult> = plan.cells.iter().map(|c| MatrixCellResult {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        cell_id: c.cell_id.clone(),
        boundary_surface: c.boundary_surface.clone(),
        lane_kind: c.lane_kind,
        outcome: MatrixOutcome::Pass,
        error_code: None,
        failure_fingerprint: None,
        failure_class: None,
    }).collect();
    let summary = summarize_matrix_health(&plan, &results);
    assert_eq!(summary.total_cells, plan.cells.len());
    assert_eq!(summary.passed_cells, plan.cells.len());
    assert_eq!(summary.failed_cells, 0);
}

#[test]
fn enrichment_summarize_health_empty_plan() {
    let plan = VersionMatrixPlan {
        schema_version: VERSION_MATRIX_SCHEMA.to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        cells: vec![],
    };
    let summary = summarize_matrix_health(&plan, &[]);
    assert_eq!(summary.total_cells, 0);
}

// ---------------------------------------------------------------------------
// FailureScopeKind serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_failure_scope_kind_serde() {
    for k in [FailureScopeKind::Universal, FailureScopeKind::VersionSpecific] {
        let json = serde_json::to_string(&k).unwrap();
        let back: FailureScopeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, back);
    }
}

// ---------------------------------------------------------------------------
// PinnedVersionCombination serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pinned_version_combination_serde() {
    let combo = PinnedVersionCombination {
        local_version: "v1.0.0".to_string(),
        remote_version: "v2.0.0".to_string(),
        reason: "known compatibility".to_string(),
    };
    let json = serde_json::to_string(&combo).unwrap();
    let back: PinnedVersionCombination = serde_json::from_str(&json).unwrap();
    assert_eq!(combo, back);
}

// ---------------------------------------------------------------------------
// VersionMatrixCell serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_version_matrix_cell_serde() {
    let cell = VersionMatrixCell {
        cell_id: "c1".to_string(),
        boundary_surface: "api".to_string(),
        local_repo: "local".to_string(),
        remote_repo: "remote".to_string(),
        local_version: "v1".to_string(),
        remote_version: "v2".to_string(),
        lane_kind: MatrixLaneKind::Current,
        pinned: false,
        expected_conformance_command: "cargo test".to_string(),
    };
    let json = serde_json::to_string(&cell).unwrap();
    let back: VersionMatrixCell = serde_json::from_str(&json).unwrap();
    assert_eq!(cell, back);
}

// ---------------------------------------------------------------------------
// Additional coverage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_derive_version_slots_previous_override() {
    let mut src = make_version_source();
    src.previous_override = Some("v0.9.0".to_string());
    let slots = derive_version_slots(&src, "franken-engine").unwrap();
    assert_eq!(slots.previous, Some("v0.9.0".to_string()));
}

#[test]
fn enrichment_derive_version_slots_next_override() {
    let mut src = make_version_source();
    src.next_override = Some("v3.0.0".to_string());
    let slots = derive_version_slots(&src, "franken-engine").unwrap();
    assert_eq!(slots.next, Some("v3.0.0".to_string()));
}

#[test]
fn enrichment_matrix_plan_has_schema_version() {
    let spec = make_spec();
    let plan = derive_version_matrix(&[spec]).unwrap();
    assert_eq!(plan.schema_version, VERSION_MATRIX_SCHEMA);
}

#[test]
fn enrichment_matrix_plan_generated_at_non_empty() {
    let spec = make_spec();
    let plan = derive_version_matrix(&[spec]).unwrap();
    assert!(!plan.generated_at_utc.is_empty());
}

#[test]
fn enrichment_matrix_cell_has_repos() {
    let spec = make_spec();
    let plan = derive_version_matrix(&[spec]).unwrap();
    for cell in &plan.cells {
        assert!(!cell.local_repo.is_empty());
        assert!(!cell.remote_repo.is_empty());
    }
}

#[test]
fn enrichment_health_summary_serde_roundtrip() {
    let summary = MatrixHealthSummary {
        total_cells: 10,
        passed_cells: 8,
        failed_cells: 2,
        universal_failures: 0,
        version_specific_failures: 2,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: MatrixHealthSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn enrichment_matrix_failure_scope_serde_roundtrip() {
    let scope = MatrixFailureScope {
        boundary_surface: "api".to_string(),
        failure_fingerprint: "fp1".to_string(),
        scope: FailureScopeKind::VersionSpecific,
        failing_cells: vec!["c1".to_string()],
    };
    let json = serde_json::to_string(&scope).unwrap();
    let back: MatrixFailureScope = serde_json::from_str(&json).unwrap();
    assert_eq!(scope, back);
}

#[test]
fn enrichment_version_matrix_error_serde() {
    let err = VersionMatrixError::MissingCurrentVersion {
        repo: "test-repo".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: VersionMatrixError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}
