//! Enrichment integration tests for the supremacy cell matrix module.
//!
//! These tests exercise advanced edge cases, cross-cutting invariants,
//! determinism properties, Display uniqueness, error lifecycle, and
//! structural guarantees beyond the baseline integration coverage.

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

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::supremacy_cell_matrix::*;

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
// Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_display_workload_family_all_unique() {
    let all = [
        WorkloadFamily::ParseCompile,
        WorkloadFamily::ColdStart,
        WorkloadFamily::WarmThroughput,
        WorkloadFamily::Async,
        WorkloadFamily::ModuleGraphs,
        WorkloadFamily::NpmCohorts,
        WorkloadFamily::ReactCompile,
        WorkloadFamily::ReactSsr,
        WorkloadFamily::ReactClient,
        WorkloadFamily::MixedPackage,
        WorkloadFamily::TailLatency,
        WorkloadFamily::MemoryPressure,
    ];
    let display_set: BTreeSet<String> = all.iter().map(|v| v.to_string()).collect();
    assert_eq!(
        display_set.len(),
        all.len(),
        "all Display strings must be unique"
    );
}

#[test]
fn enrichment_display_workload_family_no_empty_strings() {
    for wf in REQUIRED_BOARD_FAMILIES {
        let s = wf.to_string();
        assert!(
            !s.is_empty(),
            "Display must not produce empty string for {wf:?}"
        );
        assert!(
            s.len() >= 4,
            "Display string for {wf:?} suspiciously short: {s}"
        );
    }
}

// ---------------------------------------------------------------------------
// Enum serde roundtrips with JSON value inspection
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_workload_family_json_value_is_string() {
    for wf in REQUIRED_BOARD_FAMILIES {
        let value: serde_json::Value = serde_json::to_value(wf).unwrap();
        assert!(
            value.is_string(),
            "WorkloadFamily JSON must be a string, got {value:?}"
        );
    }
}

#[test]
fn enrichment_serde_measurement_family_json_values_are_snake_case() {
    let all = [
        MeasurementFamily::Latency,
        MeasurementFamily::Throughput,
        MeasurementFamily::Macro,
        MeasurementFamily::Memory,
        MeasurementFamily::TailLatency,
    ];
    for mf in all {
        let json = serde_json::to_string(&mf).unwrap();
        let trimmed = json.trim_matches('"');
        assert!(
            trimmed.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "MeasurementFamily serde should be snake_case, got {trimmed}"
        );
    }
}

#[test]
fn enrichment_serde_warm_state_roundtrip_via_json_value() {
    for ws in [WarmState::Cold, WarmState::Warm, WarmState::Mixed] {
        let value = serde_json::to_value(&ws).unwrap();
        let back: WarmState = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(ws, back);
    }
}

#[test]
fn enrichment_serde_interference_profile_roundtrip_via_bytes() {
    for ip in [
        InterferenceProfile::Isolated,
        InterferenceProfile::SharedCache,
        InterferenceProfile::SchedulerContention,
        InterferenceProfile::MixedBoard,
        InterferenceProfile::TailStress,
        InterferenceProfile::MemoryContention,
    ] {
        let bytes = serde_json::to_vec(&ip).unwrap();
        let back: InterferenceProfile = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(ip, back);
    }
}

#[test]
fn enrichment_serde_shared_resource_json_values_are_unique() {
    let all = [
        SharedResource::FrontendCpu,
        SharedResource::ArtifactCache,
        SharedResource::ModuleCache,
        SharedResource::SchedulerQueue,
        SharedResource::MemoryBandwidth,
        SharedResource::WorkerThreads,
    ];
    let json_set: BTreeSet<String> = all
        .iter()
        .map(|sr| serde_json::to_string(sr).unwrap())
        .collect();
    assert_eq!(
        json_set.len(),
        all.len(),
        "all SharedResource JSON strings must be unique"
    );
}

#[test]
fn enrichment_serde_tail_axis_json_values_are_unique() {
    let all = [
        TailAxis::ParseNs,
        TailAxis::CompileNs,
        TailAxis::ModuleLoadNs,
        TailAxis::QueueDelayNs,
        TailAxis::RenderNs,
        TailAxis::HydrationNs,
        TailAxis::GcPauseNs,
    ];
    let json_set: BTreeSet<String> = all
        .iter()
        .map(|ta| serde_json::to_string(ta).unwrap())
        .collect();
    assert_eq!(
        json_set.len(),
        all.len(),
        "all TailAxis JSON strings must be unique"
    );
}

// ---------------------------------------------------------------------------
// Struct construction and field access
// ---------------------------------------------------------------------------

#[test]
fn enrichment_struct_changelog_entry_fields_accessible() {
    let entry = ChangelogEntry {
        version: "2.0.0".to_string(),
        rationale: "enrichment rationale".to_string(),
        impact_assessment: "medium".to_string(),
        compatibility_notes: "breaks nothing".to_string(),
        changed_at_utc: "2026-03-19T12:00:00Z".to_string(),
    };
    assert_eq!(entry.version, "2.0.0");
    assert_eq!(entry.rationale, "enrichment rationale");
    assert_eq!(entry.impact_assessment, "medium");
    assert_eq!(entry.compatibility_notes, "breaks nothing");
    assert_eq!(entry.changed_at_utc, "2026-03-19T12:00:00Z");
}

#[test]
fn enrichment_struct_cell_spec_with_mixed_with_populated() {
    let cell = SupremacyCellSpec {
        cell_id: "enrichment_cell".to_string(),
        family: WorkloadFamily::MixedPackage,
        workload_kind: "enrichment workload".to_string(),
        environment: "enrichment_env".to_string(),
        entry_mode: EntryMode::MixedPackage,
        warm_state: WarmState::Mixed,
        measurement_family: MeasurementFamily::Macro,
        interference_profile: InterferenceProfile::MixedBoard,
        mixed_with: vec![WorkloadFamily::Async, WorkloadFamily::ReactSsr],
        interference_rule_ids: vec!["rule_a".to_string()],
        tail_axis_ids: vec![],
        required_for_universal_verdict: false,
    };
    assert_eq!(cell.mixed_with.len(), 2);
    assert!(cell.mixed_with.contains(&WorkloadFamily::Async));
    assert!(cell.mixed_with.contains(&WorkloadFamily::ReactSsr));
    assert!(!cell.required_for_universal_verdict);
}

#[test]
fn enrichment_struct_interference_rule_multiple_shared_resources() {
    let rule = InterferenceRule {
        rule_id: "enrich_rule".to_string(),
        primary_family: WorkloadFamily::ReactSsr,
        concurrent_family: WorkloadFamily::ReactClient,
        shared_resources: vec![
            SharedResource::ArtifactCache,
            SharedResource::SchedulerQueue,
            SharedResource::MemoryBandwidth,
        ],
        decomposition_label: "ssr_vs_hydration".to_string(),
        explanation: "SSR and client compete for bandwidth".to_string(),
    };
    assert_eq!(rule.shared_resources.len(), 3);
    assert_eq!(rule.primary_family, WorkloadFamily::ReactSsr);
    assert_eq!(rule.concurrent_family, WorkloadFamily::ReactClient);
}

// ---------------------------------------------------------------------------
// Lifecycle: validate then hash, hash stability across clones
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_validate_then_hash() {
    let art = valid_artifact();
    validate_artifact(&art).expect("must validate");
    let hash = artifact_hash(&art).expect("must hash");
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn enrichment_lifecycle_clone_preserves_hash() {
    let art = valid_artifact();
    let cloned = art.clone();
    let h1 = artifact_hash(&art).unwrap();
    let h2 = artifact_hash(&cloned).unwrap();
    assert_eq!(h1, h2, "clone must produce identical hash");
}

#[test]
fn enrichment_lifecycle_validate_then_build_interference_index() {
    let art = valid_artifact();
    validate_artifact(&art).unwrap();
    let index = build_interference_index(&art).unwrap();
    assert!(!index.is_empty());
    // All index keys should be present in at least one rule
    let rule_families: BTreeSet<WorkloadFamily> = art
        .interference_rules
        .iter()
        .flat_map(|r| [r.primary_family, r.concurrent_family])
        .collect();
    for key in index.keys() {
        assert!(
            rule_families.contains(key),
            "index key {key:?} not in any rule"
        );
    }
}

// ---------------------------------------------------------------------------
// Content hash determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hash_determinism_repeated_calls() {
    let art = valid_artifact();
    let hashes: Vec<String> = (0..10).map(|_| artifact_hash(&art).unwrap()).collect();
    for h in &hashes {
        assert_eq!(h, &hashes[0], "hash must be deterministic across calls");
    }
}

#[test]
fn enrichment_hash_determinism_different_field_changes() {
    let base = valid_artifact();
    let base_hash = artifact_hash(&base).unwrap();

    // Changing changelog should produce a different hash
    let mut v1 = base.clone();
    v1.changelog.push(ChangelogEntry {
        version: "1.1.0".to_string(),
        rationale: "update".to_string(),
        impact_assessment: "low".to_string(),
        compatibility_notes: "compatible".to_string(),
        changed_at_utc: "2026-03-19T00:00:00Z".to_string(),
    });
    let h1 = artifact_hash(&v1).unwrap();
    assert_ne!(base_hash, h1, "adding changelog entry must change hash");

    // Changing required_consumers should produce a different hash
    let mut v2 = base.clone();
    v2.required_consumers.push("new_consumer".to_string());
    let h2 = artifact_hash(&v2).unwrap();
    assert_ne!(base_hash, h2, "adding consumer must change hash");

    // Both changes produce different hashes from each other
    assert_ne!(h1, h2, "different changes must produce different hashes");
}

#[test]
fn enrichment_hash_determinism_cell_order_sensitive() {
    let art = valid_artifact();
    let h1 = artifact_hash(&art).unwrap();

    let mut reversed = art.clone();
    reversed.cells.reverse();
    let h2 = artifact_hash(&reversed).unwrap();
    // Reversing cell order should change the hash since JSON serialization is order-dependent
    assert_ne!(
        h1, h2,
        "cell ordering must affect hash (JSON is order-sensitive)"
    );
}

// ---------------------------------------------------------------------------
// Edge cases: validation boundary conditions
// ---------------------------------------------------------------------------

#[test]
fn enrichment_edge_cold_start_with_mixed_warm_state_rejected() {
    let mut art = valid_artifact();
    let idx = art
        .cells
        .iter()
        .position(|c| c.family == WorkloadFamily::ColdStart)
        .unwrap();
    art.cells[idx].warm_state = WarmState::Mixed;
    let err = validate_artifact(&art).unwrap_err();
    assert!(
        matches!(err, SupremacyCellMatrixError::ColdStartMustBeCold { .. }),
        "ColdStart with Mixed warm state must be rejected"
    );
}

#[test]
fn enrichment_edge_non_react_family_any_entry_mode_accepted() {
    // ParseCompile should accept any entry mode since react entry mode checks
    // only apply to React* families
    let mut art = valid_artifact();
    let idx = art
        .cells
        .iter()
        .position(|c| c.family == WorkloadFamily::ParseCompile)
        .unwrap();
    art.cells[idx].entry_mode = EntryMode::Library;
    validate_artifact(&art).expect("non-react family should accept Library entry mode");

    art.cells[idx].entry_mode = EntryMode::MixedPackage;
    validate_artifact(&art).expect("non-react family should accept MixedPackage entry mode");
}

#[test]
fn enrichment_edge_isolated_parse_compile_no_interference_rules_ok() {
    // ParseCompile is not in the families that require interference metadata,
    // and Isolated profile also does not require it.
    let art = valid_artifact();
    let cell = art
        .cells
        .iter()
        .find(|c| c.family == WorkloadFamily::ParseCompile)
        .unwrap();
    assert_eq!(cell.interference_profile, InterferenceProfile::Isolated);
    assert!(cell.interference_rule_ids.is_empty());
    validate_artifact(&art).expect("isolated ParseCompile without rules is valid");
}

#[test]
fn enrichment_edge_non_isolated_non_required_family_needs_rules() {
    // If a non-required-interference family (e.g. ParseCompile) has a non-isolated
    // interference profile, it must have rules
    let mut art = valid_artifact();
    let idx = art
        .cells
        .iter()
        .position(|c| c.family == WorkloadFamily::ParseCompile)
        .unwrap();
    art.cells[idx].interference_profile = InterferenceProfile::SharedCache;
    art.cells[idx].interference_rule_ids.clear();
    let err = validate_artifact(&art).unwrap_err();
    assert!(
        matches!(
            err,
            SupremacyCellMatrixError::MissingInterferenceMetadata { .. }
        ),
        "non-isolated profile without rules must be rejected"
    );
}

#[test]
fn enrichment_edge_tail_measurement_on_non_tail_family_needs_axes() {
    // A non-TailLatency family cell with MeasurementFamily::TailLatency
    // should still require tail axes
    let mut art = valid_artifact();
    let idx = art
        .cells
        .iter()
        .position(|c| c.family == WorkloadFamily::ParseCompile)
        .unwrap();
    art.cells[idx].measurement_family = MeasurementFamily::TailLatency;
    art.cells[idx].tail_axis_ids.clear();
    let err = validate_artifact(&art).unwrap_err();
    assert!(
        matches!(
            err,
            SupremacyCellMatrixError::MissingTailDecomposition { .. }
        ),
        "tail_latency measurement family requires tail axes even on non-TailLatency families"
    );
}

#[test]
fn enrichment_edge_multiple_cells_same_family_accepted() {
    // Multiple cells for the same family should validate if cell IDs differ
    let mut art = valid_artifact();
    let extra_cell = make_cell(
        "c01_extra",
        WorkloadFamily::ParseCompile,
        EntryMode::Library,
        WarmState::Cold,
        MeasurementFamily::Latency,
        InterferenceProfile::Isolated,
        vec![],
        vec![],
    );
    art.cells.push(extra_cell);
    validate_artifact(&art).expect("multiple cells per family should be allowed");
}

#[test]
fn enrichment_edge_empty_changelog_accepted() {
    let mut art = valid_artifact();
    art.changelog.clear();
    validate_artifact(&art).expect("empty changelog should be accepted");
}

#[test]
fn enrichment_edge_empty_required_artifacts_accepted() {
    let mut art = valid_artifact();
    art.required_artifacts.clear();
    validate_artifact(&art).expect("empty required_artifacts should be accepted");
}

// ---------------------------------------------------------------------------
// Error message content validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_all_variants_have_nonempty_display() {
    let errors: Vec<SupremacyCellMatrixError> = vec![
        SupremacyCellMatrixError::InvalidSchemaVersion {
            found: "x".to_string(),
        },
        SupremacyCellMatrixError::InvalidLogSchemaVersion {
            found: "y".to_string(),
        },
        SupremacyCellMatrixError::MissingMatrixDimension {
            dimension: "d".to_string(),
        },
        SupremacyCellMatrixError::UnknownFamilyDimension {
            family: WorkloadFamily::Async,
            dimension: "q".to_string(),
        },
        SupremacyCellMatrixError::DuplicateFamily {
            family: WorkloadFamily::ColdStart,
        },
        SupremacyCellMatrixError::MissingFamily {
            family: WorkloadFamily::ReactSsr,
        },
        SupremacyCellMatrixError::MissingFamilyCoverage {
            family: WorkloadFamily::TailLatency,
        },
        SupremacyCellMatrixError::DuplicateCellId {
            cell_id: "z".to_string(),
        },
        SupremacyCellMatrixError::DuplicateInterferenceRule {
            rule_id: "rr".to_string(),
        },
        SupremacyCellMatrixError::UnknownInterferenceRule {
            cell_id: "c".to_string(),
            rule_id: "r".to_string(),
        },
        SupremacyCellMatrixError::MissingInterferenceMetadata {
            cell_id: "ci".to_string(),
        },
        SupremacyCellMatrixError::MissingTailDecomposition {
            cell_id: "ct".to_string(),
        },
        SupremacyCellMatrixError::UnknownTailAxis {
            cell_id: "ca".to_string(),
            axis: TailAxis::GcPauseNs,
        },
        SupremacyCellMatrixError::ColdStartMustBeCold {
            cell_id: "cc".to_string(),
        },
        SupremacyCellMatrixError::ReactEntryModeMismatch {
            cell_id: "cr".to_string(),
            expected: EntryMode::NativeReactCompile,
            found: EntryMode::Cli,
        },
        SupremacyCellMatrixError::Serialization("ser error".to_string()),
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(
            !msg.is_empty(),
            "error variant {err:?} should produce non-empty Display"
        );
        assert!(
            msg.len() >= 10,
            "error message too short for {err:?}: {msg}"
        );
    }
}

#[test]
fn enrichment_error_clone_preserves_equality() {
    let err = SupremacyCellMatrixError::UnknownInterferenceRule {
        cell_id: "cell_x".to_string(),
        rule_id: "rule_y".to_string(),
    };
    let cloned = err.clone();
    assert_eq!(err, cloned);
    assert_eq!(err.to_string(), cloned.to_string());
}

#[test]
fn enrichment_error_different_payloads_not_equal() {
    let e1 = SupremacyCellMatrixError::DuplicateCellId {
        cell_id: "a".to_string(),
    };
    let e2 = SupremacyCellMatrixError::DuplicateCellId {
        cell_id: "b".to_string(),
    };
    assert_ne!(e1, e2);
}

// ---------------------------------------------------------------------------
// Interference index advanced checks
// ---------------------------------------------------------------------------

#[test]
fn enrichment_interference_index_no_self_loops() {
    let art = valid_artifact();
    let index = build_interference_index(&art).unwrap();
    for (family, related) in &index {
        assert!(
            !related.contains(family),
            "interference index should not have self-loop for {family:?}"
        );
    }
}

#[test]
fn enrichment_interference_index_sorted_values() {
    let art = valid_artifact();
    let index = build_interference_index(&art).unwrap();
    for (family, related) in &index {
        let mut sorted = related.clone();
        sorted.sort();
        assert_eq!(
            *related, sorted,
            "interference index values for {family:?} should be sorted"
        );
    }
}

#[test]
fn enrichment_interference_index_matches_rule_count() {
    let art = valid_artifact();
    let index = build_interference_index(&art).unwrap();
    // Each rule contributes two directed edges, but the index deduplicates.
    // Count total distinct edges in the index
    let total_edges: usize = index.values().map(|v| v.len()).sum();
    // Each undirected rule edge appears twice (once for each direction)
    // So total directed edges should be 2 * number of rules (assuming no duplication)
    assert_eq!(
        total_edges,
        art.interference_rules.len() * 2,
        "each rule produces two directed index entries"
    );
}

// ---------------------------------------------------------------------------
// SecurityEpoch cross-module interop
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cross_module_security_epoch_usable_alongside_matrix() {
    // Verify SecurityEpoch can be used in the same context as matrix types
    let epoch = SecurityEpoch::from_raw(42);
    assert_eq!(epoch.as_u64(), 42);

    let art = valid_artifact();
    validate_artifact(&art).unwrap();
    // Both modules coexist without conflict
    let _ = artifact_hash(&art).unwrap();
}

// ---------------------------------------------------------------------------
// Serde roundtrip for full artifact via bytes
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_artifact_roundtrip_via_vec_bytes() {
    let art = valid_artifact();
    let bytes = serde_json::to_vec(&art).unwrap();
    let back: SupremacyCellMatrixArtifact = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(art, back);
}

#[test]
fn enrichment_serde_artifact_roundtrip_via_pretty_print() {
    let art = valid_artifact();
    let pretty = serde_json::to_string_pretty(&art).unwrap();
    let back: SupremacyCellMatrixArtifact = serde_json::from_str(&pretty).unwrap();
    assert_eq!(art, back);
    // Pretty print should produce more bytes than compact
    let compact = serde_json::to_string(&art).unwrap();
    assert!(
        pretty.len() > compact.len(),
        "pretty print should be longer than compact"
    );
}

// ---------------------------------------------------------------------------
// Constants structural guarantees
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_schema_versions_contain_v1() {
    assert!(
        SUPREMACY_CELL_MATRIX_SCHEMA_VERSION.contains("v1"),
        "schema version should contain v1"
    );
    assert!(
        SUPREMACY_CELL_MATRIX_LOG_SCHEMA_VERSION.contains("v1"),
        "log schema version should contain v1"
    );
}

#[test]
fn enrichment_constants_required_board_families_covers_all_enum_variants() {
    // REQUIRED_BOARD_FAMILIES has exactly 12 entries matching all WorkloadFamily variants
    let required_set: BTreeSet<WorkloadFamily> = REQUIRED_BOARD_FAMILIES.iter().copied().collect();
    let expected = [
        WorkloadFamily::ParseCompile,
        WorkloadFamily::ColdStart,
        WorkloadFamily::WarmThroughput,
        WorkloadFamily::Async,
        WorkloadFamily::ModuleGraphs,
        WorkloadFamily::NpmCohorts,
        WorkloadFamily::ReactCompile,
        WorkloadFamily::ReactSsr,
        WorkloadFamily::ReactClient,
        WorkloadFamily::MixedPackage,
        WorkloadFamily::TailLatency,
        WorkloadFamily::MemoryPressure,
    ];
    let expected_set: BTreeSet<WorkloadFamily> = expected.into_iter().collect();
    assert_eq!(required_set, expected_set);
}

#[test]
fn enrichment_constants_dimensions_all_lowercase_underscore() {
    for dim in REQUIRED_MATRIX_DIMENSIONS {
        assert!(
            dim.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "dimension {dim} must be lowercase with underscores only"
        );
    }
}

// ---------------------------------------------------------------------------
// Artifact with maximally populated fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_with_all_tail_axes_on_tail_cell() {
    let mut art = valid_artifact();
    let idx = art
        .cells
        .iter()
        .position(|c| c.family == WorkloadFamily::TailLatency)
        .unwrap();
    art.cells[idx].tail_axis_ids = vec![
        TailAxis::ParseNs,
        TailAxis::CompileNs,
        TailAxis::ModuleLoadNs,
        TailAxis::QueueDelayNs,
        TailAxis::RenderNs,
        TailAxis::HydrationNs,
        TailAxis::GcPauseNs,
    ];
    validate_artifact(&art).expect("cell with all 7 tail axes should validate");
    assert_eq!(art.cells[idx].tail_axis_ids.len(), 7);
}

#[test]
fn enrichment_artifact_multiple_changelog_entries_accepted() {
    let mut art = valid_artifact();
    for i in 0..5 {
        art.changelog.push(ChangelogEntry {
            version: format!("1.{i}.0"),
            rationale: format!("update {i}"),
            impact_assessment: "low".to_string(),
            compatibility_notes: "compatible".to_string(),
            changed_at_utc: format!("2026-03-{:02}T00:00:00Z", i + 1),
        });
    }
    validate_artifact(&art).expect("multiple changelog entries should be accepted");
    assert_eq!(art.changelog.len(), 6); // 1 original + 5 new
}

// ---------------------------------------------------------------------------
// BTreeMap ordering guarantees
// ---------------------------------------------------------------------------

#[test]
fn enrichment_btreemap_interference_index_keys_sorted() {
    let art = valid_artifact();
    let index = build_interference_index(&art).unwrap();
    let keys: Vec<WorkloadFamily> = index.keys().copied().collect();
    let mut sorted_keys = keys.clone();
    sorted_keys.sort();
    assert_eq!(keys, sorted_keys, "BTreeMap keys must be in sorted order");
}

// ---------------------------------------------------------------------------
// WorkloadFamily as_str consistency with serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_workload_family_as_str_equals_serde_json_content() {
    for wf in REQUIRED_BOARD_FAMILIES {
        let serde_str = serde_json::to_string(wf).unwrap();
        let serde_content = serde_str.trim_matches('"');
        assert_eq!(
            wf.as_str(),
            serde_content,
            "as_str and serde JSON content must match for {wf:?}"
        );
    }
}
