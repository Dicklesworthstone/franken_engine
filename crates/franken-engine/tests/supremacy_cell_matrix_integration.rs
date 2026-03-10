//! Integration tests for supremacy cell matrix contract (RGC-705A).

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

use frankenengine_engine::supremacy_cell_matrix::{
    ChangelogEntry, EntryMode, InterferenceProfile, InterferenceRule, MeasurementFamily,
    REQUIRED_BOARD_FAMILIES, REQUIRED_MATRIX_DIMENSIONS, SUPREMACY_CELL_MATRIX_COMPONENT,
    SUPREMACY_CELL_MATRIX_LOG_SCHEMA_VERSION, SUPREMACY_CELL_MATRIX_SCHEMA_VERSION, SharedResource,
    SupremacyCellFamilySpec, SupremacyCellMatrixArtifact, SupremacyCellMatrixError,
    SupremacyCellSpec, TailAxis, TailDecompositionAxisSpec, WarmState, WorkloadFamily,
    artifact_hash, build_interference_index, validate_artifact,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn all_dimensions() -> Vec<String> {
    REQUIRED_MATRIX_DIMENSIONS
        .iter()
        .map(|d| d.to_string())
        .collect()
}

fn make_family_spec(family: WorkloadFamily, mf: MeasurementFamily) -> SupremacyCellFamilySpec {
    SupremacyCellFamilySpec {
        family,
        measurement_family: mf,
        required_dimensions: all_dimensions(),
        required_for_board: true,
        shipped_surface_note: format!("{family:?} note"),
    }
}

fn all_family_specs() -> Vec<SupremacyCellFamilySpec> {
    vec![
        make_family_spec(WorkloadFamily::ParseCompile, MeasurementFamily::Latency),
        make_family_spec(WorkloadFamily::ColdStart, MeasurementFamily::Latency),
        make_family_spec(
            WorkloadFamily::WarmThroughput,
            MeasurementFamily::Throughput,
        ),
        make_family_spec(WorkloadFamily::Async, MeasurementFamily::Latency),
        make_family_spec(WorkloadFamily::ModuleGraphs, MeasurementFamily::Latency),
        make_family_spec(WorkloadFamily::NpmCohorts, MeasurementFamily::Latency),
        make_family_spec(WorkloadFamily::ReactCompile, MeasurementFamily::Latency),
        make_family_spec(WorkloadFamily::ReactSsr, MeasurementFamily::Latency),
        make_family_spec(WorkloadFamily::ReactClient, MeasurementFamily::Latency),
        make_family_spec(WorkloadFamily::MixedPackage, MeasurementFamily::Macro),
        make_family_spec(WorkloadFamily::TailLatency, MeasurementFamily::TailLatency),
        make_family_spec(WorkloadFamily::MemoryPressure, MeasurementFamily::Memory),
    ]
}

fn make_interference_rule(
    id: &str,
    primary: WorkloadFamily,
    concurrent: WorkloadFamily,
) -> InterferenceRule {
    InterferenceRule {
        rule_id: id.to_string(),
        primary_family: primary,
        concurrent_family: concurrent,
        shared_resources: vec![SharedResource::FrontendCpu],
        decomposition_label: "test decomp".to_string(),
        explanation: "test explanation".to_string(),
    }
}

fn make_tail_axis(axis: TailAxis) -> TailDecompositionAxisSpec {
    TailDecompositionAxisSpec {
        axis,
        stage: format!("{axis:?}"),
        description: format!("{axis:?} desc"),
    }
}

fn all_tail_axes() -> Vec<TailDecompositionAxisSpec> {
    vec![
        make_tail_axis(TailAxis::ParseNs),
        make_tail_axis(TailAxis::CompileNs),
        make_tail_axis(TailAxis::ModuleLoadNs),
        make_tail_axis(TailAxis::QueueDelayNs),
        make_tail_axis(TailAxis::RenderNs),
        make_tail_axis(TailAxis::HydrationNs),
        make_tail_axis(TailAxis::GcPauseNs),
    ]
}

fn make_cell(
    id: &str,
    family: WorkloadFamily,
    entry_mode: EntryMode,
    warm_state: WarmState,
    mf: MeasurementFamily,
    interference: InterferenceProfile,
    interference_rules: Vec<String>,
    tail_axes: Vec<TailAxis>,
) -> SupremacyCellSpec {
    SupremacyCellSpec {
        cell_id: id.to_string(),
        family,
        workload_kind: format!("{family:?}"),
        environment: "test_env".to_string(),
        entry_mode,
        warm_state,
        measurement_family: mf,
        interference_profile: interference,
        mixed_with: vec![],
        interference_rule_ids: interference_rules,
        tail_axis_ids: tail_axes,
        required_for_universal_verdict: true,
    }
}

fn valid_artifact() -> SupremacyCellMatrixArtifact {
    let interference_rules = vec![
        make_interference_rule(
            "r1",
            WorkloadFamily::ModuleGraphs,
            WorkloadFamily::NpmCohorts,
        ),
        make_interference_rule(
            "r2",
            WorkloadFamily::MixedPackage,
            WorkloadFamily::ModuleGraphs,
        ),
        make_interference_rule(
            "r3",
            WorkloadFamily::TailLatency,
            WorkloadFamily::MemoryPressure,
        ),
    ];

    let cells = vec![
        make_cell(
            "c01",
            WorkloadFamily::ParseCompile,
            EntryMode::Cli,
            WarmState::Warm,
            MeasurementFamily::Latency,
            InterferenceProfile::Isolated,
            vec![],
            vec![],
        ),
        make_cell(
            "c02",
            WorkloadFamily::ColdStart,
            EntryMode::Cli,
            WarmState::Cold,
            MeasurementFamily::Latency,
            InterferenceProfile::Isolated,
            vec![],
            vec![],
        ),
        make_cell(
            "c03",
            WorkloadFamily::WarmThroughput,
            EntryMode::Cli,
            WarmState::Warm,
            MeasurementFamily::Throughput,
            InterferenceProfile::Isolated,
            vec![],
            vec![],
        ),
        make_cell(
            "c04",
            WorkloadFamily::Async,
            EntryMode::Cli,
            WarmState::Mixed,
            MeasurementFamily::Latency,
            InterferenceProfile::Isolated,
            vec![],
            vec![],
        ),
        make_cell(
            "c05",
            WorkloadFamily::ModuleGraphs,
            EntryMode::Cli,
            WarmState::Cold,
            MeasurementFamily::Latency,
            InterferenceProfile::SharedCache,
            vec!["r1".to_string()],
            vec![],
        ),
        make_cell(
            "c06",
            WorkloadFamily::NpmCohorts,
            EntryMode::Cli,
            WarmState::Cold,
            MeasurementFamily::Latency,
            InterferenceProfile::SharedCache,
            vec!["r1".to_string()],
            vec![],
        ),
        make_cell(
            "c07",
            WorkloadFamily::ReactCompile,
            EntryMode::NativeReactCompile,
            WarmState::Warm,
            MeasurementFamily::Latency,
            InterferenceProfile::Isolated,
            vec![],
            vec![],
        ),
        make_cell(
            "c08",
            WorkloadFamily::ReactSsr,
            EntryMode::NativeReactSsr,
            WarmState::Warm,
            MeasurementFamily::Latency,
            InterferenceProfile::Isolated,
            vec![],
            vec![],
        ),
        make_cell(
            "c09",
            WorkloadFamily::ReactClient,
            EntryMode::NativeReactClient,
            WarmState::Warm,
            MeasurementFamily::Latency,
            InterferenceProfile::Isolated,
            vec![],
            vec![],
        ),
        make_cell(
            "c10",
            WorkloadFamily::MixedPackage,
            EntryMode::MixedPackage,
            WarmState::Mixed,
            MeasurementFamily::Macro,
            InterferenceProfile::MixedBoard,
            vec!["r2".to_string()],
            vec![],
        ),
        make_cell(
            "c11",
            WorkloadFamily::TailLatency,
            EntryMode::Cli,
            WarmState::Warm,
            MeasurementFamily::TailLatency,
            InterferenceProfile::TailStress,
            vec!["r3".to_string()],
            vec![TailAxis::ParseNs, TailAxis::CompileNs],
        ),
        make_cell(
            "c12",
            WorkloadFamily::MemoryPressure,
            EntryMode::Cli,
            WarmState::Mixed,
            MeasurementFamily::Memory,
            InterferenceProfile::MemoryContention,
            vec!["r3".to_string()],
            vec![],
        ),
    ];

    SupremacyCellMatrixArtifact {
        schema_version: SUPREMACY_CELL_MATRIX_SCHEMA_VERSION.to_string(),
        contract_version: "1.0.0".to_string(),
        log_schema_version: SUPREMACY_CELL_MATRIX_LOG_SCHEMA_VERSION.to_string(),
        required_artifacts: vec!["benchmark_results".to_string()],
        required_consumers: vec!["rollout_gate".to_string()],
        changelog: vec![ChangelogEntry {
            version: "1.0.0".to_string(),
            rationale: "initial".to_string(),
            impact_assessment: "none".to_string(),
            compatibility_notes: "n/a".to_string(),
            changed_at_utc: "2026-01-01T00:00:00Z".to_string(),
        }],
        matrix_dimensions: all_dimensions(),
        cell_families: all_family_specs(),
        cells,
        interference_rules,
        tail_decomposition_axes: all_tail_axes(),
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_component_name() {
    assert_eq!(SUPREMACY_CELL_MATRIX_COMPONENT, "supremacy_cell_matrix");
}

#[test]
fn test_schema_version_nonempty() {
    assert!(!SUPREMACY_CELL_MATRIX_SCHEMA_VERSION.is_empty());
    assert!(SUPREMACY_CELL_MATRIX_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn test_log_schema_version_nonempty() {
    assert!(!SUPREMACY_CELL_MATRIX_LOG_SCHEMA_VERSION.is_empty());
    assert!(SUPREMACY_CELL_MATRIX_LOG_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn test_required_dimensions_count() {
    assert_eq!(REQUIRED_MATRIX_DIMENSIONS.len(), 6);
}

#[test]
fn test_required_dimensions_unique() {
    let set: BTreeSet<&str> = REQUIRED_MATRIX_DIMENSIONS.iter().copied().collect();
    assert_eq!(set.len(), REQUIRED_MATRIX_DIMENSIONS.len());
}

#[test]
fn test_required_board_families_count() {
    assert_eq!(REQUIRED_BOARD_FAMILIES.len(), 12);
}

#[test]
fn test_required_board_families_unique() {
    let set: BTreeSet<WorkloadFamily> = REQUIRED_BOARD_FAMILIES.iter().copied().collect();
    assert_eq!(set.len(), REQUIRED_BOARD_FAMILIES.len());
}

// ---------------------------------------------------------------------------
// WorkloadFamily
// ---------------------------------------------------------------------------

#[test]
fn test_workload_family_as_str() {
    assert_eq!(WorkloadFamily::ParseCompile.as_str(), "parse_compile");
    assert_eq!(WorkloadFamily::ColdStart.as_str(), "cold_start");
    assert_eq!(WorkloadFamily::Async.as_str(), "async");
    assert_eq!(WorkloadFamily::ReactSsr.as_str(), "react_ssr");
}

#[test]
fn test_workload_family_display() {
    for wf in REQUIRED_BOARD_FAMILIES {
        assert_eq!(format!("{wf}"), wf.as_str());
    }
}

#[test]
fn test_workload_family_as_str_snake_case() {
    for wf in REQUIRED_BOARD_FAMILIES {
        let s = wf.as_str();
        assert!(s.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
    }
}

#[test]
fn test_workload_family_serde_roundtrip() {
    for wf in REQUIRED_BOARD_FAMILIES {
        let json = serde_json::to_string(wf).unwrap();
        let back: WorkloadFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*wf, back);
    }
}

#[test]
fn test_workload_family_ordering() {
    assert!(WorkloadFamily::ParseCompile < WorkloadFamily::ColdStart);
}

// ---------------------------------------------------------------------------
// Other enum serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn test_measurement_family_serde_roundtrip() {
    for mf in [
        MeasurementFamily::Latency,
        MeasurementFamily::Throughput,
        MeasurementFamily::Macro,
        MeasurementFamily::Memory,
        MeasurementFamily::TailLatency,
    ] {
        let json = serde_json::to_string(&mf).unwrap();
        let back: MeasurementFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(mf, back);
    }
}

#[test]
fn test_entry_mode_serde_roundtrip() {
    for em in [
        EntryMode::Cli,
        EntryMode::Library,
        EntryMode::NativeReactCompile,
        EntryMode::NativeReactSsr,
        EntryMode::NativeReactClient,
        EntryMode::MixedPackage,
    ] {
        let json = serde_json::to_string(&em).unwrap();
        let back: EntryMode = serde_json::from_str(&json).unwrap();
        assert_eq!(em, back);
    }
}

#[test]
fn test_warm_state_serde_roundtrip() {
    for ws in [WarmState::Cold, WarmState::Warm, WarmState::Mixed] {
        let json = serde_json::to_string(&ws).unwrap();
        let back: WarmState = serde_json::from_str(&json).unwrap();
        assert_eq!(ws, back);
    }
}

#[test]
fn test_interference_profile_serde_roundtrip() {
    for ip in [
        InterferenceProfile::Isolated,
        InterferenceProfile::SharedCache,
        InterferenceProfile::SchedulerContention,
        InterferenceProfile::MixedBoard,
        InterferenceProfile::TailStress,
        InterferenceProfile::MemoryContention,
    ] {
        let json = serde_json::to_string(&ip).unwrap();
        let back: InterferenceProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(ip, back);
    }
}

#[test]
fn test_shared_resource_serde_roundtrip() {
    for sr in [
        SharedResource::FrontendCpu,
        SharedResource::ArtifactCache,
        SharedResource::ModuleCache,
        SharedResource::SchedulerQueue,
        SharedResource::MemoryBandwidth,
        SharedResource::WorkerThreads,
    ] {
        let json = serde_json::to_string(&sr).unwrap();
        let back: SharedResource = serde_json::from_str(&json).unwrap();
        assert_eq!(sr, back);
    }
}

#[test]
fn test_tail_axis_serde_roundtrip() {
    for ta in [
        TailAxis::ParseNs,
        TailAxis::CompileNs,
        TailAxis::ModuleLoadNs,
        TailAxis::QueueDelayNs,
        TailAxis::RenderNs,
        TailAxis::HydrationNs,
        TailAxis::GcPauseNs,
    ] {
        let json = serde_json::to_string(&ta).unwrap();
        let back: TailAxis = serde_json::from_str(&json).unwrap();
        assert_eq!(ta, back);
    }
}

// ---------------------------------------------------------------------------
// validate_artifact — happy path
// ---------------------------------------------------------------------------

#[test]
fn test_valid_artifact_passes_validation() {
    validate_artifact(&valid_artifact()).unwrap();
}

// ---------------------------------------------------------------------------
// validate_artifact — error paths
// ---------------------------------------------------------------------------

#[test]
fn test_invalid_schema_version() {
    let mut art = valid_artifact();
    art.schema_version = "wrong".to_string();
    let err = validate_artifact(&art).unwrap_err();
    assert!(matches!(
        err,
        SupremacyCellMatrixError::InvalidSchemaVersion { .. }
    ));
}

#[test]
fn test_invalid_log_schema_version() {
    let mut art = valid_artifact();
    art.log_schema_version = "wrong".to_string();
    let err = validate_artifact(&art).unwrap_err();
    assert!(matches!(
        err,
        SupremacyCellMatrixError::InvalidLogSchemaVersion { .. }
    ));
}

#[test]
fn test_missing_matrix_dimension() {
    let mut art = valid_artifact();
    art.matrix_dimensions.retain(|d| d != "workload_family");
    let err = validate_artifact(&art).unwrap_err();
    assert!(matches!(
        err,
        SupremacyCellMatrixError::MissingMatrixDimension { .. }
    ));
}

#[test]
fn test_unknown_family_dimension() {
    let mut art = valid_artifact();
    art.cell_families[0]
        .required_dimensions
        .push("bogus".to_string());
    let err = validate_artifact(&art).unwrap_err();
    assert!(matches!(
        err,
        SupremacyCellMatrixError::UnknownFamilyDimension { .. }
    ));
}

#[test]
fn test_duplicate_family() {
    let mut art = valid_artifact();
    let first = art.cell_families[0].clone();
    art.cell_families.push(first);
    let err = validate_artifact(&art).unwrap_err();
    assert!(matches!(
        err,
        SupremacyCellMatrixError::DuplicateFamily { .. }
    ));
}

#[test]
fn test_missing_required_family() {
    let mut art = valid_artifact();
    art.cell_families
        .retain(|f| f.family != WorkloadFamily::Async);
    let err = validate_artifact(&art).unwrap_err();
    assert!(matches!(
        err,
        SupremacyCellMatrixError::MissingFamily { .. }
    ));
}

#[test]
fn test_duplicate_cell_id() {
    let mut art = valid_artifact();
    let first = art.cells[0].clone();
    art.cells.push(first);
    let err = validate_artifact(&art).unwrap_err();
    assert!(matches!(
        err,
        SupremacyCellMatrixError::DuplicateCellId { .. }
    ));
}

#[test]
fn test_duplicate_interference_rule() {
    let mut art = valid_artifact();
    let first = art.interference_rules[0].clone();
    art.interference_rules.push(first);
    let err = validate_artifact(&art).unwrap_err();
    assert!(matches!(
        err,
        SupremacyCellMatrixError::DuplicateInterferenceRule { .. }
    ));
}

#[test]
fn test_unknown_interference_rule() {
    let mut art = valid_artifact();
    art.cells[4]
        .interference_rule_ids
        .push("nonexistent".to_string());
    let err = validate_artifact(&art).unwrap_err();
    assert!(matches!(
        err,
        SupremacyCellMatrixError::UnknownInterferenceRule { .. }
    ));
}

#[test]
fn test_missing_interference_metadata() {
    let mut art = valid_artifact();
    // ModuleGraphs requires interference metadata but we clear it
    art.cells[4].interference_rule_ids.clear();
    let err = validate_artifact(&art).unwrap_err();
    assert!(matches!(
        err,
        SupremacyCellMatrixError::MissingInterferenceMetadata { .. }
    ));
}

#[test]
fn test_missing_tail_decomposition() {
    let mut art = valid_artifact();
    // TailLatency cell requires tail axes
    let tail_idx = art
        .cells
        .iter()
        .position(|c| c.family == WorkloadFamily::TailLatency)
        .unwrap();
    art.cells[tail_idx].tail_axis_ids.clear();
    let err = validate_artifact(&art).unwrap_err();
    assert!(matches!(
        err,
        SupremacyCellMatrixError::MissingTailDecomposition { .. }
    ));
}

#[test]
fn test_unknown_tail_axis() {
    let mut art = valid_artifact();
    // Remove HydrationNs from defined axes, then add it to a cell
    art.tail_decomposition_axes
        .retain(|a| a.axis != TailAxis::HydrationNs);
    let tail_idx = art
        .cells
        .iter()
        .position(|c| c.family == WorkloadFamily::TailLatency)
        .unwrap();
    art.cells[tail_idx]
        .tail_axis_ids
        .push(TailAxis::HydrationNs);
    let err = validate_artifact(&art).unwrap_err();
    assert!(matches!(
        err,
        SupremacyCellMatrixError::UnknownTailAxis { .. }
    ));
}

#[test]
fn test_cold_start_must_be_cold() {
    let mut art = valid_artifact();
    let cold_idx = art
        .cells
        .iter()
        .position(|c| c.family == WorkloadFamily::ColdStart)
        .unwrap();
    art.cells[cold_idx].warm_state = WarmState::Warm;
    let err = validate_artifact(&art).unwrap_err();
    assert!(matches!(
        err,
        SupremacyCellMatrixError::ColdStartMustBeCold { .. }
    ));
}

#[test]
fn test_react_compile_entry_mode_mismatch() {
    let mut art = valid_artifact();
    let idx = art
        .cells
        .iter()
        .position(|c| c.family == WorkloadFamily::ReactCompile)
        .unwrap();
    art.cells[idx].entry_mode = EntryMode::Cli;
    let err = validate_artifact(&art).unwrap_err();
    assert!(matches!(
        err,
        SupremacyCellMatrixError::ReactEntryModeMismatch {
            expected: EntryMode::NativeReactCompile,
            ..
        }
    ));
}

#[test]
fn test_react_ssr_entry_mode_mismatch() {
    let mut art = valid_artifact();
    let idx = art
        .cells
        .iter()
        .position(|c| c.family == WorkloadFamily::ReactSsr)
        .unwrap();
    art.cells[idx].entry_mode = EntryMode::Library;
    let err = validate_artifact(&art).unwrap_err();
    assert!(matches!(
        err,
        SupremacyCellMatrixError::ReactEntryModeMismatch {
            expected: EntryMode::NativeReactSsr,
            ..
        }
    ));
}

#[test]
fn test_react_client_entry_mode_mismatch() {
    let mut art = valid_artifact();
    let idx = art
        .cells
        .iter()
        .position(|c| c.family == WorkloadFamily::ReactClient)
        .unwrap();
    art.cells[idx].entry_mode = EntryMode::Cli;
    let err = validate_artifact(&art).unwrap_err();
    assert!(matches!(
        err,
        SupremacyCellMatrixError::ReactEntryModeMismatch {
            expected: EntryMode::NativeReactClient,
            ..
        }
    ));
}

#[test]
fn test_missing_family_coverage() {
    let mut art = valid_artifact();
    art.cells
        .retain(|c| c.family != WorkloadFamily::MemoryPressure);
    let err = validate_artifact(&art).unwrap_err();
    assert!(matches!(
        err,
        SupremacyCellMatrixError::MissingFamilyCoverage { .. }
    ));
}

// ---------------------------------------------------------------------------
// build_interference_index
// ---------------------------------------------------------------------------

#[test]
fn test_interference_index_non_empty() {
    let art = valid_artifact();
    let index = build_interference_index(&art).unwrap();
    assert!(!index.is_empty());
}

#[test]
fn test_interference_index_symmetric() {
    let art = valid_artifact();
    let index = build_interference_index(&art).unwrap();
    for (family, related) in &index {
        for other in related {
            let reverse = index.get(other).expect("symmetric entry");
            assert!(reverse.contains(family));
        }
    }
}

#[test]
fn test_interference_index_contains_rule_families() {
    let art = valid_artifact();
    let index = build_interference_index(&art).unwrap();
    assert!(index.contains_key(&WorkloadFamily::ModuleGraphs));
    assert!(index.contains_key(&WorkloadFamily::NpmCohorts));
}

#[test]
fn test_interference_index_rejects_invalid_artifact() {
    let mut art = valid_artifact();
    art.schema_version = "wrong".to_string();
    let err = build_interference_index(&art).unwrap_err();
    assert!(matches!(
        err,
        SupremacyCellMatrixError::InvalidSchemaVersion { .. }
    ));
}

// ---------------------------------------------------------------------------
// artifact_hash
// ---------------------------------------------------------------------------

#[test]
fn test_artifact_hash_deterministic() {
    let art = valid_artifact();
    let h1 = artifact_hash(&art).unwrap();
    let h2 = artifact_hash(&art).unwrap();
    assert_eq!(h1, h2);
}

#[test]
fn test_artifact_hash_is_sha256_hex() {
    let art = valid_artifact();
    let hash = artifact_hash(&art).unwrap();
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_artifact_hash_changes_with_content() {
    let mut art = valid_artifact();
    let h1 = artifact_hash(&art).unwrap();
    art.contract_version = "changed".to_string();
    let h2 = artifact_hash(&art).unwrap();
    assert_ne!(h1, h2);
}

// ---------------------------------------------------------------------------
// Error display
// ---------------------------------------------------------------------------

#[test]
fn test_error_display_invalid_schema() {
    let err = SupremacyCellMatrixError::InvalidSchemaVersion {
        found: "bad".to_string(),
    };
    assert!(err.to_string().contains("bad"));
}

#[test]
fn test_error_display_missing_dimension() {
    let err = SupremacyCellMatrixError::MissingMatrixDimension {
        dimension: "foo".to_string(),
    };
    assert!(err.to_string().contains("foo"));
}

#[test]
fn test_error_display_duplicate_cell() {
    let err = SupremacyCellMatrixError::DuplicateCellId {
        cell_id: "c99".to_string(),
    };
    assert!(err.to_string().contains("c99"));
}

#[test]
fn test_error_display_cold_start() {
    let err = SupremacyCellMatrixError::ColdStartMustBeCold {
        cell_id: "c1".to_string(),
    };
    assert!(err.to_string().contains("cold"));
}

#[test]
fn test_error_display_react_mismatch() {
    let err = SupremacyCellMatrixError::ReactEntryModeMismatch {
        cell_id: "c7".to_string(),
        expected: EntryMode::NativeReactCompile,
        found: EntryMode::Cli,
    };
    let s = err.to_string();
    assert!(s.contains("c7"));
}

// ---------------------------------------------------------------------------
// Struct serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn test_artifact_serde_roundtrip() {
    let art = valid_artifact();
    let json = serde_json::to_string(&art).unwrap();
    let back: SupremacyCellMatrixArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(art, back);
}

#[test]
fn test_changelog_entry_serde_roundtrip() {
    let entry = ChangelogEntry {
        version: "2.0".to_string(),
        rationale: "update".to_string(),
        impact_assessment: "low".to_string(),
        compatibility_notes: "compat".to_string(),
        changed_at_utc: "2026-03-10T00:00:00Z".to_string(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: ChangelogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn test_cell_spec_serde_roundtrip() {
    let cell = make_cell(
        "test",
        WorkloadFamily::Async,
        EntryMode::Cli,
        WarmState::Warm,
        MeasurementFamily::Latency,
        InterferenceProfile::Isolated,
        vec![],
        vec![],
    );
    let json = serde_json::to_string(&cell).unwrap();
    let back: SupremacyCellSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(cell, back);
}

#[test]
fn test_interference_rule_serde_roundtrip() {
    let rule = make_interference_rule("r-test", WorkloadFamily::Async, WorkloadFamily::ColdStart);
    let json = serde_json::to_string(&rule).unwrap();
    let back: InterferenceRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, back);
}

#[test]
fn test_tail_axis_spec_serde_roundtrip() {
    let spec = make_tail_axis(TailAxis::GcPauseNs);
    let json = serde_json::to_string(&spec).unwrap();
    let back: TailDecompositionAxisSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, back);
}

#[test]
fn test_family_spec_serde_roundtrip() {
    let spec = make_family_spec(WorkloadFamily::Async, MeasurementFamily::Latency);
    let json = serde_json::to_string(&spec).unwrap();
    let back: SupremacyCellFamilySpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, back);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_all_required_dimensions_present() {
    for d in REQUIRED_MATRIX_DIMENSIONS {
        assert!(!d.is_empty());
    }
}

#[test]
fn test_cell_with_multiple_interference_rules() {
    let mut art = valid_artifact();
    let idx = art
        .cells
        .iter()
        .position(|c| c.family == WorkloadFamily::ModuleGraphs)
        .unwrap();
    art.cells[idx].interference_rule_ids = vec!["r1".to_string(), "r2".to_string()];
    validate_artifact(&art).unwrap();
}

#[test]
fn test_cell_with_multiple_tail_axes() {
    let art = valid_artifact();
    let tail_cell = art
        .cells
        .iter()
        .find(|c| c.family == WorkloadFamily::TailLatency)
        .unwrap();
    assert!(tail_cell.tail_axis_ids.len() >= 2);
    validate_artifact(&art).unwrap();
}
