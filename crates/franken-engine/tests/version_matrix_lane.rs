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

#[path = "../src/version_matrix_lane.rs"]
mod version_matrix_lane;

use version_matrix_lane::{
    BoundaryMatrixSpec, FailureScopeKind, MatrixCellResult, MatrixFailureScope,
    MatrixHealthSummary, MatrixLaneKind, MatrixOutcome, PinnedVersionCombination,
    VersionMatrixCell, VersionMatrixError, VersionMatrixPlan, VersionSlots, VersionSource,
    classify_failure_scopes, derive_version_matrix, derive_version_slots, summarize_matrix_health,
};

fn sample_spec() -> BoundaryMatrixSpec {
    BoundaryMatrixSpec {
        boundary_surface: "frankensqlite/store_record".to_string(),
        local_repo: "franken_engine".to_string(),
        remote_repo: "frankensqlite".to_string(),
        local_versions: VersionSource {
            tags: vec!["v1.4.0".to_string(), "v1.3.9".to_string()],
            branch_names: vec!["main".to_string()],
            current_override: None,
            previous_override: None,
            next_override: None,
        },
        remote_versions: VersionSource {
            tags: vec![
                "v2.3.0".to_string(),
                "v2.2.0".to_string(),
                "v2.4.0-rc1".to_string(),
            ],
            branch_names: vec!["main".to_string()],
            current_override: None,
            previous_override: None,
            next_override: None,
        },
        pinned_combinations: vec![PinnedVersionCombination {
            local_version: "1.4.0".to_string(),
            remote_version: "2.1.5".to_string(),
            reason: "known regression tracking".to_string(),
        }],
    }
}

#[test]
fn matrix_derives_n_previous_next_and_pinned_cells() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");

    let lanes: Vec<MatrixLaneKind> = plan.cells.iter().map(|cell| cell.lane_kind).collect();
    assert!(lanes.contains(&MatrixLaneKind::Current));
    assert!(lanes.contains(&MatrixLaneKind::Previous));
    assert!(lanes.contains(&MatrixLaneKind::Next));
    assert!(lanes.contains(&MatrixLaneKind::Pinned));

    let current = plan
        .cells
        .iter()
        .find(|cell| cell.lane_kind == MatrixLaneKind::Current)
        .expect("current lane");
    assert_eq!(current.local_version, "1.4.0");
    assert_eq!(current.remote_version, "2.3.0");

    let previous = plan
        .cells
        .iter()
        .find(|cell| cell.lane_kind == MatrixLaneKind::Previous)
        .expect("previous lane");
    assert_eq!(previous.remote_version, "2.2.0");

    let next = plan
        .cells
        .iter()
        .find(|cell| cell.lane_kind == MatrixLaneKind::Next)
        .expect("next lane");
    assert_eq!(next.remote_version, "2.4.0-rc1");

    let pinned = plan
        .cells
        .iter()
        .find(|cell| cell.lane_kind == MatrixLaneKind::Pinned)
        .expect("pinned lane");
    assert_eq!(pinned.local_version, "1.4.0");
    assert_eq!(pinned.remote_version, "2.1.5");
    assert!(pinned.pinned);
}

#[test]
fn next_version_falls_back_to_branch_convention_when_no_prerelease_tag_exists() {
    let slots = derive_version_slots(
        &VersionSource {
            tags: vec!["v3.1.4".to_string(), "v3.1.3".to_string()],
            branch_names: vec!["main".to_string()],
            current_override: None,
            previous_override: None,
            next_override: None,
        },
        "franken_node",
    )
    .expect("derive slots");

    assert_eq!(slots.current, "3.1.4");
    assert_eq!(slots.previous.as_deref(), Some("3.1.3"));
    assert_eq!(slots.next.as_deref(), Some("3.1.5-next"));
}

#[test]
fn missing_current_version_is_fail_closed() {
    let err = derive_version_slots(
        &VersionSource {
            tags: vec!["not-a-version".to_string()],
            branch_names: vec![],
            current_override: None,
            previous_override: None,
            next_override: None,
        },
        "frankentui",
    )
    .expect_err("must fail when no current version can be derived");

    match err {
        VersionMatrixError::MissingCurrentVersion { repo } => {
            assert_eq!(repo, "frankentui");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn failure_scope_classification_marks_universal_vs_version_specific() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");

    let mut results = Vec::new();
    for cell in &plan.cells {
        results.push(MatrixCellResult {
            trace_id: format!("trace-{}", cell.cell_id),
            decision_id: format!("decision-{}", cell.cell_id),
            policy_id: "policy-version-matrix-v1".to_string(),
            cell_id: cell.cell_id.clone(),
            boundary_surface: cell.boundary_surface.clone(),
            lane_kind: cell.lane_kind,
            outcome: MatrixOutcome::Pass,
            error_code: None,
            failure_fingerprint: None,
            failure_class: None,
        });
    }

    // Universal failure appears in all cells.
    for result in &mut results {
        result.outcome = MatrixOutcome::Fail;
        result.failure_fingerprint = Some("fp-universal".to_string());
        result.failure_class = Some("breaking".to_string());
    }

    // Add one version-specific failure in a single cell.
    let specific = MatrixCellResult {
        trace_id: "trace-specific".to_string(),
        decision_id: "decision-specific".to_string(),
        policy_id: "policy-version-matrix-v1".to_string(),
        cell_id: plan.cells[0].cell_id.clone(),
        boundary_surface: plan.cells[0].boundary_surface.clone(),
        lane_kind: plan.cells[0].lane_kind,
        outcome: MatrixOutcome::Fail,
        error_code: Some("FE-MATRIX-VERSION-SPECIFIC".to_string()),
        failure_fingerprint: Some("fp-version-specific".to_string()),
        failure_class: Some("behavioral".to_string()),
    };
    results.push(specific);

    let scopes = classify_failure_scopes(&plan, &results);

    let universal = scopes
        .iter()
        .find(|scope| scope.failure_fingerprint == "fp-universal")
        .expect("universal scope");
    assert_eq!(universal.scope, FailureScopeKind::Universal);

    let version_specific = scopes
        .iter()
        .find(|scope| scope.failure_fingerprint == "fp-version-specific")
        .expect("version-specific scope");
    assert_eq!(version_specific.scope, FailureScopeKind::VersionSpecific);
    assert_eq!(version_specific.failing_cells.len(), 1);
}

#[test]
fn matrix_health_summary_counts_cells_and_scope_types() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");
    let mut results = Vec::new();

    for (idx, cell) in plan.cells.iter().enumerate() {
        results.push(MatrixCellResult {
            trace_id: format!("trace-{idx}"),
            decision_id: format!("decision-{idx}"),
            policy_id: "policy-version-matrix-v1".to_string(),
            cell_id: cell.cell_id.clone(),
            boundary_surface: cell.boundary_surface.clone(),
            lane_kind: cell.lane_kind,
            outcome: if idx % 2 == 0 {
                MatrixOutcome::Pass
            } else {
                MatrixOutcome::Fail
            },
            error_code: if idx % 2 == 0 {
                None
            } else {
                Some("FE-MATRIX-FAIL".to_string())
            },
            failure_fingerprint: if idx % 2 == 0 {
                None
            } else {
                Some(format!("fp-{idx}"))
            },
            failure_class: if idx % 2 == 0 {
                None
            } else {
                Some("behavioral".to_string())
            },
        });
    }

    let summary = summarize_matrix_health(&plan, &results);
    assert_eq!(summary.total_cells, plan.cells.len());
    assert_eq!(
        summary.passed_cells + summary.failed_cells,
        summary.total_cells
    );
    assert_eq!(summary.version_specific_failures, summary.failed_cells);
}

// ---------- sample_spec ----------

#[test]
fn sample_spec_has_valid_surface() {
    let spec = sample_spec();
    assert_eq!(spec.boundary_surface, "frankensqlite/store_record");
}

#[test]
fn sample_spec_has_local_and_remote_versions() {
    let spec = sample_spec();
    assert!(!spec.local_versions.tags.is_empty());
    assert!(!spec.remote_versions.tags.is_empty());
}

// ---------- derive_version_slots ----------

#[test]
fn derive_version_slots_with_overrides() {
    let slots = derive_version_slots(
        &VersionSource {
            tags: vec!["v1.0.0".to_string()],
            branch_names: vec!["main".to_string()],
            current_override: Some("9.9.9".to_string()),
            previous_override: Some("8.8.8".to_string()),
            next_override: Some("10.0.0-alpha".to_string()),
        },
        "test-repo",
    )
    .expect("derive slots");
    assert_eq!(slots.current, "9.9.9");
    assert_eq!(slots.previous.as_deref(), Some("8.8.8"));
    assert_eq!(slots.next.as_deref(), Some("10.0.0-alpha"));
}

// ---------- MatrixLaneKind ----------

#[test]
fn matrix_lane_kind_serde_roundtrip() {
    for kind in [
        MatrixLaneKind::Current,
        MatrixLaneKind::Previous,
        MatrixLaneKind::Next,
        MatrixLaneKind::Pinned,
    ] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: MatrixLaneKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, kind);
    }
}

// ---------- MatrixOutcome ----------

#[test]
fn matrix_outcome_serde_roundtrip() {
    for outcome in [MatrixOutcome::Pass, MatrixOutcome::Fail] {
        let json = serde_json::to_string(&outcome).expect("serialize");
        let recovered: MatrixOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, outcome);
    }
}

// ---------- FailureScopeKind ----------

#[test]
fn failure_scope_kind_serde_roundtrip() {
    for kind in [
        FailureScopeKind::Universal,
        FailureScopeKind::VersionSpecific,
    ] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: FailureScopeKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, kind);
    }
}

// ---------- VersionMatrixError ----------

#[test]
fn version_matrix_error_display_is_nonempty() {
    let err = VersionMatrixError::MissingCurrentVersion {
        repo: "test-repo".to_string(),
    };
    let msg = format!("{err}");
    assert!(!msg.is_empty());
    assert!(msg.contains("test-repo"));
}

// ---------- derive_version_matrix ----------

#[test]
fn derive_version_matrix_empty_specs_produces_empty_cells() {
    let plan = derive_version_matrix(&[]).expect("derive empty matrix");
    assert!(plan.cells.is_empty());
}

// ---------- PinnedVersionCombination ----------

#[test]
fn pinned_combination_appears_in_matrix() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");
    let pinned_cells: Vec<_> = plan.cells.iter().filter(|cell| cell.pinned).collect();
    assert_eq!(pinned_cells.len(), 1);
    assert_eq!(pinned_cells[0].local_version, "1.4.0");
    assert_eq!(pinned_cells[0].remote_version, "2.1.5");
}

// ---------- summarize_matrix_health ----------

#[test]
fn health_summary_all_pass() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");
    let results: Vec<_> = plan
        .cells
        .iter()
        .enumerate()
        .map(|(idx, cell)| MatrixCellResult {
            trace_id: format!("trace-{idx}"),
            decision_id: format!("decision-{idx}"),
            policy_id: "policy-v1".to_string(),
            cell_id: cell.cell_id.clone(),
            boundary_surface: cell.boundary_surface.clone(),
            lane_kind: cell.lane_kind,
            outcome: MatrixOutcome::Pass,
            error_code: None,
            failure_fingerprint: None,
            failure_class: None,
        })
        .collect();
    let summary = summarize_matrix_health(&plan, &results);
    assert_eq!(summary.passed_cells, summary.total_cells);
    assert_eq!(summary.failed_cells, 0);
}

// ---------- cell_ids are unique ----------

#[test]
fn derived_matrix_cell_ids_are_unique() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");
    let mut seen = std::collections::BTreeSet::new();
    for cell in &plan.cells {
        assert!(
            seen.insert(&cell.cell_id),
            "duplicate cell_id: {}",
            cell.cell_id
        );
    }
}

// ---------- multiple specs ----------

#[test]
fn derive_version_matrix_with_multiple_specs() {
    let mut spec2 = sample_spec();
    spec2.boundary_surface = "frankenhttp/request_handler".to_string();
    spec2.remote_repo = "frankenhttp".to_string();

    let plan = derive_version_matrix(&[sample_spec(), spec2]).expect("derive matrix");
    let surfaces: std::collections::BTreeSet<&str> = plan
        .cells
        .iter()
        .map(|cell| cell.boundary_surface.as_str())
        .collect();
    assert!(surfaces.len() >= 2);
}

// ---------- deterministic ----------

#[test]
fn derive_version_matrix_is_deterministic() {
    let a = derive_version_matrix(&[sample_spec()]).expect("derive a");
    let b = derive_version_matrix(&[sample_spec()]).expect("derive b");
    assert_eq!(a.cells.len(), b.cells.len());
    for (ca, cb) in a.cells.iter().zip(&b.cells) {
        assert_eq!(ca.cell_id, cb.cell_id);
        assert_eq!(ca.lane_kind, cb.lane_kind);
        assert_eq!(ca.local_version, cb.local_version);
        assert_eq!(ca.remote_version, cb.remote_version);
    }
}

// ---------- health all fail ----------

#[test]
fn health_summary_all_fail() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");
    let results: Vec<_> = plan
        .cells
        .iter()
        .enumerate()
        .map(|(idx, cell)| MatrixCellResult {
            trace_id: format!("trace-{idx}"),
            decision_id: format!("decision-{idx}"),
            policy_id: "policy-v1".to_string(),
            cell_id: cell.cell_id.clone(),
            boundary_surface: cell.boundary_surface.clone(),
            lane_kind: cell.lane_kind,
            outcome: MatrixOutcome::Fail,
            error_code: Some("FE-MATRIX-FAIL".to_string()),
            failure_fingerprint: Some(format!("fp-{idx}")),
            failure_class: Some("behavioral".to_string()),
        })
        .collect();
    let summary = summarize_matrix_health(&plan, &results);
    assert_eq!(summary.failed_cells, summary.total_cells);
    assert_eq!(summary.passed_cells, 0);
}

// ---------- version source single tag ----------

#[test]
fn derive_version_slots_single_tag_no_previous() {
    let slots = derive_version_slots(
        &VersionSource {
            tags: vec!["v1.0.0".to_string()],
            branch_names: vec!["main".to_string()],
            current_override: None,
            previous_override: None,
            next_override: None,
        },
        "single-repo",
    )
    .expect("derive slots");
    assert_eq!(slots.current, "1.0.0");
    assert!(slots.previous.is_none());
}

// ---------- enrichment: serde roundtrips, error paths, edge cases ----------

#[test]
fn version_source_serde_roundtrip() {
    let vs = VersionSource {
        tags: vec!["v1.0.0".to_string()],
        branch_names: vec!["main".to_string()],
        current_override: Some("2.0.0".to_string()),
        previous_override: None,
        next_override: None,
    };
    let json = serde_json::to_string(&vs).expect("serialize");
    let recovered: VersionSource = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.tags, vs.tags);
    assert_eq!(recovered.current_override.as_deref(), Some("2.0.0"));
}

#[test]
fn pinned_version_combination_serde_roundtrip() {
    let pvc = PinnedVersionCombination {
        local_version: "1.0.0".to_string(),
        remote_version: "2.0.0".to_string(),
        reason: "test".to_string(),
    };
    let json = serde_json::to_string(&pvc).expect("serialize");
    let recovered: PinnedVersionCombination = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.local_version, "1.0.0");
    assert_eq!(recovered.reason, "test");
}

#[test]
fn boundary_matrix_spec_serde_roundtrip() {
    let spec = sample_spec();
    let json = serde_json::to_string(&spec).expect("serialize");
    let recovered: BoundaryMatrixSpec = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.boundary_surface, spec.boundary_surface);
    assert_eq!(recovered.pinned_combinations.len(), 1);
}

#[test]
fn version_matrix_cell_serde_roundtrip() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");
    let cell = &plan.cells[0];
    let json = serde_json::to_string(cell).expect("serialize");
    let recovered: VersionMatrixCell = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.cell_id, cell.cell_id);
    assert_eq!(recovered.lane_kind, cell.lane_kind);
}

#[test]
fn version_matrix_plan_serde_roundtrip() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");
    let json = serde_json::to_string(&plan).expect("serialize");
    let recovered: VersionMatrixPlan = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.cells.len(), plan.cells.len());
    assert_eq!(recovered.schema_version, plan.schema_version);
}

#[test]
fn version_slots_serde_roundtrip() {
    let slots =
        derive_version_slots(&sample_spec().local_versions, "test-repo").expect("derive slots");
    let json = serde_json::to_string(&slots).expect("serialize");
    let recovered: VersionSlots = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.current, slots.current);
    assert_eq!(recovered.previous, slots.previous);
}

#[test]
fn matrix_cell_result_serde_roundtrip() {
    let result = MatrixCellResult {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        cell_id: "cell-1".to_string(),
        boundary_surface: "test/boundary".to_string(),
        lane_kind: MatrixLaneKind::Current,
        outcome: MatrixOutcome::Pass,
        error_code: None,
        failure_fingerprint: None,
        failure_class: None,
    };
    let json = serde_json::to_string(&result).expect("serialize");
    let recovered: MatrixCellResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.cell_id, "cell-1");
    assert_eq!(recovered.outcome, MatrixOutcome::Pass);
}

#[test]
fn matrix_failure_scope_serde_roundtrip() {
    let scope = MatrixFailureScope {
        boundary_surface: "test/surface".to_string(),
        failure_fingerprint: "fp-1".to_string(),
        scope: FailureScopeKind::Universal,
        failing_cells: vec!["cell-1".to_string(), "cell-2".to_string()],
    };
    let json = serde_json::to_string(&scope).expect("serialize");
    let recovered: MatrixFailureScope = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.scope, FailureScopeKind::Universal);
    assert_eq!(recovered.failing_cells.len(), 2);
}

#[test]
fn matrix_health_summary_serde_roundtrip() {
    let summary = MatrixHealthSummary {
        total_cells: 10,
        passed_cells: 7,
        failed_cells: 3,
        universal_failures: 1,
        version_specific_failures: 2,
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let recovered: MatrixHealthSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.total_cells, 10);
    assert_eq!(recovered.universal_failures, 1);
}

#[test]
fn version_matrix_error_invalid_pinned_display() {
    let err = VersionMatrixError::InvalidPinnedCombination {
        boundary_surface: "test/surface".to_string(),
        reason: "missing version".to_string(),
    };
    let msg = err.to_string();
    assert!(!msg.is_empty());
    assert!(msg.contains("test/surface"));
}

#[test]
fn version_matrix_error_is_std_error() {
    let err = VersionMatrixError::MissingCurrentVersion {
        repo: "test-repo".to_string(),
    };
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

#[test]
fn matrix_lane_kind_as_str_is_nonempty() {
    for kind in [
        MatrixLaneKind::Current,
        MatrixLaneKind::Previous,
        MatrixLaneKind::Next,
        MatrixLaneKind::Pinned,
    ] {
        assert!(!kind.as_str().is_empty());
    }
}

#[test]
fn classify_failure_scopes_empty_results_produces_empty() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");
    let scopes = classify_failure_scopes(&plan, &[]);
    assert!(scopes.is_empty());
}

// ---------- enrichment batch: edge cases, serde, debug, clone, invariants ----------

#[test]
fn version_matrix_error_serde_roundtrip_missing_current() {
    let err = VersionMatrixError::MissingCurrentVersion {
        repo: "franken_core".to_string(),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: VersionMatrixError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, err);
}

#[test]
fn version_matrix_error_serde_roundtrip_invalid_pinned() {
    let err = VersionMatrixError::InvalidPinnedCombination {
        boundary_surface: "api/v2".to_string(),
        reason: "remote_version is blank".to_string(),
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: VersionMatrixError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, err);
}

#[test]
fn version_source_debug_contains_field_names() {
    let vs = VersionSource {
        tags: vec!["v1.0.0".to_string()],
        branch_names: vec!["main".to_string()],
        current_override: None,
        previous_override: None,
        next_override: None,
    };
    let dbg = format!("{vs:?}");
    assert!(dbg.contains("tags"));
    assert!(dbg.contains("branch_names"));
    assert!(dbg.contains("current_override"));
}

#[test]
fn pinned_version_combination_debug_contains_reason() {
    let pvc = PinnedVersionCombination {
        local_version: "1.0.0".to_string(),
        remote_version: "2.0.0".to_string(),
        reason: "regression tracking".to_string(),
    };
    let dbg = format!("{pvc:?}");
    assert!(dbg.contains("regression tracking"));
}

#[test]
fn version_matrix_cell_debug_includes_cell_id() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");
    let cell = &plan.cells[0];
    let dbg = format!("{cell:?}");
    assert!(dbg.contains(&cell.cell_id));
    assert!(dbg.contains("boundary_surface"));
}

#[test]
fn matrix_health_summary_debug_includes_counts() {
    let summary = MatrixHealthSummary {
        total_cells: 5,
        passed_cells: 3,
        failed_cells: 2,
        universal_failures: 0,
        version_specific_failures: 2,
    };
    let dbg = format!("{summary:?}");
    assert!(dbg.contains("total_cells"));
    assert!(dbg.contains("5"));
    assert!(dbg.contains("failed_cells"));
}

#[test]
fn matrix_failure_scope_debug_includes_fingerprint() {
    let scope = MatrixFailureScope {
        boundary_surface: "test/surface".to_string(),
        failure_fingerprint: "fp-debug-test".to_string(),
        scope: FailureScopeKind::VersionSpecific,
        failing_cells: vec!["cell-x".to_string()],
    };
    let dbg = format!("{scope:?}");
    assert!(dbg.contains("fp-debug-test"));
    assert!(dbg.contains("VersionSpecific"));
}

#[test]
fn derive_version_matrix_rejects_empty_remote_pinned_version() {
    let mut spec = sample_spec();
    spec.pinned_combinations = vec![PinnedVersionCombination {
        local_version: "1.0.0".to_string(),
        remote_version: "   ".to_string(),
        reason: "whitespace only".to_string(),
    }];
    let err = derive_version_matrix(&[spec]).expect_err("should reject whitespace-only version");
    match err {
        VersionMatrixError::InvalidPinnedCombination {
            boundary_surface, ..
        } => {
            assert_eq!(boundary_surface, "frankensqlite/store_record");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn version_slots_derivation_notes_populated_for_branch_derived_next() {
    let slots = derive_version_slots(
        &VersionSource {
            tags: vec!["v2.5.0".to_string(), "v2.4.0".to_string()],
            branch_names: vec!["main".to_string()],
            current_override: None,
            previous_override: None,
            next_override: None,
        },
        "test-repo",
    )
    .expect("derive slots");
    assert_eq!(slots.current, "2.5.0");
    assert_eq!(slots.previous.as_deref(), Some("2.4.0"));
    assert!(slots.next.is_some());
    assert!(
        slots
            .derivation_notes
            .iter()
            .any(|note| note.contains("branch")),
        "derivation notes should mention branch convention"
    );
}

#[test]
fn version_slots_derivation_notes_populated_for_prerelease_next() {
    let slots = derive_version_slots(
        &VersionSource {
            tags: vec!["v1.0.0".to_string(), "v1.1.0-rc1".to_string()],
            branch_names: vec![],
            current_override: None,
            previous_override: None,
            next_override: None,
        },
        "test-repo",
    )
    .expect("derive slots");
    assert_eq!(slots.current, "1.0.0");
    assert_eq!(slots.next.as_deref(), Some("1.1.0-rc1"));
    assert!(
        slots
            .derivation_notes
            .iter()
            .any(|note| note.contains("prerelease")),
        "derivation notes should mention prerelease tag"
    );
}

#[test]
fn matrix_cell_conformance_command_contains_cell_id() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");
    for cell in &plan.cells {
        assert!(
            cell.expected_conformance_command.contains(&cell.cell_id),
            "conformance command must embed cell_id for traceability"
        );
        assert!(cell.expected_conformance_command.contains("cargo test"));
    }
}

#[test]
fn matrix_plan_schema_version_matches_constant() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");
    assert_eq!(
        plan.schema_version, "franken-engine.version-matrix-lane.v1",
        "schema version must match the module constant"
    );
}

#[test]
fn matrix_plan_generated_at_utc_is_epoch() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");
    assert_eq!(plan.generated_at_utc, "1970-01-01T00:00:00Z");
}

#[test]
fn classify_failure_scopes_pass_results_with_fingerprint_are_ignored() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");
    let results: Vec<MatrixCellResult> = plan
        .cells
        .iter()
        .enumerate()
        .map(|(idx, cell)| MatrixCellResult {
            trace_id: format!("trace-{idx}"),
            decision_id: format!("decision-{idx}"),
            policy_id: "policy-v1".to_string(),
            cell_id: cell.cell_id.clone(),
            boundary_surface: cell.boundary_surface.clone(),
            lane_kind: cell.lane_kind,
            outcome: MatrixOutcome::Pass,
            error_code: None,
            failure_fingerprint: Some("fp-should-be-ignored".to_string()),
            failure_class: None,
        })
        .collect();
    let scopes = classify_failure_scopes(&plan, &results);
    assert!(
        scopes.is_empty(),
        "passing results with fingerprints should not generate failure scopes"
    );
}

#[test]
fn classify_failure_scopes_fail_without_fingerprint_ignored() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");
    let results: Vec<MatrixCellResult> = plan
        .cells
        .iter()
        .enumerate()
        .map(|(idx, cell)| MatrixCellResult {
            trace_id: format!("trace-{idx}"),
            decision_id: format!("decision-{idx}"),
            policy_id: "policy-v1".to_string(),
            cell_id: cell.cell_id.clone(),
            boundary_surface: cell.boundary_surface.clone(),
            lane_kind: cell.lane_kind,
            outcome: MatrixOutcome::Fail,
            error_code: Some("FE-ERR".to_string()),
            failure_fingerprint: None,
            failure_class: Some("unknown".to_string()),
        })
        .collect();
    let scopes = classify_failure_scopes(&plan, &results);
    assert!(
        scopes.is_empty(),
        "failures without fingerprint should produce no scopes"
    );
}

#[test]
fn matrix_cell_boundary_surface_matches_spec() {
    let plan = derive_version_matrix(&[sample_spec()]).expect("derive matrix");
    for cell in &plan.cells {
        assert_eq!(
            cell.boundary_surface, "frankensqlite/store_record",
            "all cells should inherit the spec boundary_surface"
        );
    }
}

#[test]
fn version_source_clone_independence() {
    let original = VersionSource {
        tags: vec!["v1.0.0".to_string()],
        branch_names: vec!["main".to_string()],
        current_override: Some("1.0.0".to_string()),
        previous_override: Some("0.9.0".to_string()),
        next_override: Some("2.0.0".to_string()),
    };
    let mut cloned = original.clone();
    cloned.tags.push("v3.0.0".to_string());
    cloned.current_override = None;
    assert_eq!(original.tags.len(), 1, "original must be unmodified");
    assert_eq!(original.current_override.as_deref(), Some("1.0.0"));
    assert_eq!(cloned.tags.len(), 2);
}
