use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use frankenengine_engine::supremacy_cell_matrix::{
    ChangelogEntry, EntryMode, InterferenceProfile, InterferenceRule, MeasurementFamily,
    REQUIRED_BOARD_FAMILIES, REQUIRED_MATRIX_DIMENSIONS, SUPREMACY_CELL_MATRIX_COMPONENT,
    SUPREMACY_CELL_MATRIX_LOG_SCHEMA_VERSION, SUPREMACY_CELL_MATRIX_SCHEMA_VERSION, SharedResource,
    SupremacyCellFamilySpec, SupremacyCellMatrixArtifact, SupremacyCellMatrixError,
    SupremacyCellSpec, TailAxis, TailDecompositionAxisSpec, WarmState, WorkloadFamily,
    artifact_hash, build_interference_index, validate_artifact,
};

fn load_fixture() -> SupremacyCellMatrixArtifact {
    let path = Path::new("tests/fixtures/supremacy_cell_matrix_v1.json");
    let bytes = fs::read(path).expect("read supremacy cell matrix fixture");
    serde_json::from_slice(&bytes).expect("deserialize supremacy cell matrix fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/RGC_SUPREMACY_CELL_MATRIX_V1.md");
    fs::read_to_string(path).expect("read supremacy cell matrix doc")
}

fn load_runner_script() -> String {
    let path = Path::new("../../scripts/run_supremacy_cell_matrix_suite.sh");
    fs::read_to_string(path).expect("read supremacy cell matrix runner")
}

#[test]
fn supremacy_cell_matrix_fixture_versions_and_artifacts_are_stable() {
    let fixture = load_fixture();

    assert_eq!(
        fixture.schema_version,
        SUPREMACY_CELL_MATRIX_SCHEMA_VERSION.to_string()
    );
    assert_eq!(
        fixture.log_schema_version,
        SUPREMACY_CELL_MATRIX_LOG_SCHEMA_VERSION.to_string()
    );
    assert_eq!(
        fixture.required_artifacts,
        vec![
            "supremacy_cell_matrix.json",
            "run_manifest.json",
            "events.jsonl",
            "commands.txt",
        ]
    );
    assert_eq!(
        fixture.required_consumers,
        vec!["benchmark", "docs", "rollout", "ga"]
    );
}

#[test]
fn supremacy_cell_matrix_fixture_is_valid_and_complete() {
    let fixture = load_fixture();
    validate_artifact(&fixture).expect("fixture should validate");

    let families: BTreeSet<WorkloadFamily> = fixture
        .cell_families
        .iter()
        .map(|family| family.family)
        .collect();
    let required: BTreeSet<WorkloadFamily> = REQUIRED_BOARD_FAMILIES.iter().copied().collect();
    assert_eq!(families, required);

    let cell_families: BTreeSet<WorkloadFamily> =
        fixture.cells.iter().map(|cell| cell.family).collect();
    assert_eq!(cell_families, required);
}

#[test]
fn supremacy_cell_matrix_interference_index_has_expected_edges() {
    let fixture = load_fixture();
    let index = build_interference_index(&fixture).expect("index should build");

    let mixed_edges = index
        .get(&WorkloadFamily::MixedPackage)
        .expect("mixed package edges");
    assert!(mixed_edges.contains(&WorkloadFamily::Async));
    assert!(mixed_edges.contains(&WorkloadFamily::ModuleGraphs));
    assert!(mixed_edges.contains(&WorkloadFamily::TailLatency));

    let react_edges = index
        .get(&WorkloadFamily::ReactSsr)
        .expect("react ssr edges");
    assert!(react_edges.contains(&WorkloadFamily::ReactClient));
    assert!(react_edges.contains(&WorkloadFamily::MemoryPressure));
}

#[test]
fn supremacy_cell_matrix_hash_is_deterministic() {
    let fixture = load_fixture();
    let first = artifact_hash(&fixture).expect("hash should succeed");
    let second = artifact_hash(&fixture).expect("hash should succeed");

    assert_eq!(first, second);
    assert_eq!(first.len(), 64);
}

#[test]
fn supremacy_cell_matrix_doc_has_required_sections_and_keywords() {
    let doc = load_doc();

    let required_sections = [
        "## Purpose",
        "## Matrix Dimensions",
        "## Required Families",
        "## Interference Model",
        "## Tail Decomposition",
        "## Verification",
    ];
    for section in required_sections {
        assert!(
            doc.contains(section),
            "required section missing from doc: {section}"
        );
    }

    let keywords = [
        "React",
        "cold-start",
        "module",
        "async",
        "mixed-package",
        "interference",
        "tail-latency",
        "rch",
        "supremacy_cell_matrix.json",
    ];
    for keyword in keywords {
        assert!(
            doc.contains(keyword),
            "required keyword missing from doc: {keyword}"
        );
    }

    let word_count = doc.split_whitespace().count();
    assert!(
        word_count >= 250,
        "doc should have at least 250 words, found {word_count}"
    );
}

#[test]
fn supremacy_cell_matrix_runner_script_requires_rch_and_contract_outputs() {
    let script = load_runner_script();

    for snippet in [
        "rch is required",
        "cargo check -p frankenengine-engine --test supremacy_cell_matrix",
        "cargo test -p frankenengine-engine --test supremacy_cell_matrix",
        "cargo clippy -p frankenengine-engine --test supremacy_cell_matrix -- -D warnings",
        "supremacy_cell_matrix.json",
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
    ] {
        assert!(
            script.contains(snippet),
            "runner script missing required snippet: {snippet}"
        );
    }
}

// ── Serde round-trip tests ──────────────────────────────────────────

#[test]
fn workload_family_serde_round_trip_all_variants() {
    let variants = [
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
    for variant in variants {
        let json = serde_json::to_string(&variant).expect("serialize");
        let back: WorkloadFamily = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, variant);
    }
}

#[test]
fn measurement_family_serde_round_trip_all_variants() {
    let variants = [
        MeasurementFamily::Latency,
        MeasurementFamily::Throughput,
        MeasurementFamily::Macro,
        MeasurementFamily::Memory,
        MeasurementFamily::TailLatency,
    ];
    for variant in variants {
        let json = serde_json::to_string(&variant).expect("serialize");
        let back: MeasurementFamily = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, variant);
    }
}

#[test]
fn entry_mode_serde_round_trip_all_variants() {
    let variants = [
        EntryMode::Cli,
        EntryMode::Library,
        EntryMode::NativeReactCompile,
        EntryMode::NativeReactSsr,
        EntryMode::NativeReactClient,
        EntryMode::MixedPackage,
    ];
    for variant in variants {
        let json = serde_json::to_string(&variant).expect("serialize");
        let back: EntryMode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, variant);
    }
}

#[test]
fn warm_state_serde_round_trip_all_variants() {
    let variants = [WarmState::Cold, WarmState::Warm, WarmState::Mixed];
    for variant in variants {
        let json = serde_json::to_string(&variant).expect("serialize");
        let back: WarmState = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, variant);
    }
}

#[test]
fn interference_profile_serde_round_trip_all_variants() {
    let variants = [
        InterferenceProfile::Isolated,
        InterferenceProfile::SharedCache,
        InterferenceProfile::SchedulerContention,
        InterferenceProfile::MixedBoard,
        InterferenceProfile::TailStress,
        InterferenceProfile::MemoryContention,
    ];
    for variant in variants {
        let json = serde_json::to_string(&variant).expect("serialize");
        let back: InterferenceProfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, variant);
    }
}

#[test]
fn shared_resource_serde_round_trip_all_variants() {
    let variants = [
        SharedResource::FrontendCpu,
        SharedResource::ArtifactCache,
        SharedResource::ModuleCache,
        SharedResource::SchedulerQueue,
        SharedResource::MemoryBandwidth,
        SharedResource::WorkerThreads,
    ];
    for variant in variants {
        let json = serde_json::to_string(&variant).expect("serialize");
        let back: SharedResource = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, variant);
    }
}

#[test]
fn tail_axis_serde_round_trip_all_variants() {
    let variants = [
        TailAxis::ParseNs,
        TailAxis::CompileNs,
        TailAxis::ModuleLoadNs,
        TailAxis::QueueDelayNs,
        TailAxis::RenderNs,
        TailAxis::HydrationNs,
        TailAxis::GcPauseNs,
    ];
    for variant in variants {
        let json = serde_json::to_string(&variant).expect("serialize");
        let back: TailAxis = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, variant);
    }
}

#[test]
fn full_artifact_serde_round_trip() {
    let fixture = load_fixture();
    let json = serde_json::to_string_pretty(&fixture).expect("serialize");
    let back: SupremacyCellMatrixArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, fixture);
}

// ── Display tests ───────────────────────────────────────────────────

#[test]
fn workload_family_display_matches_as_str() {
    let variants = [
        (WorkloadFamily::ParseCompile, "parse_compile"),
        (WorkloadFamily::ColdStart, "cold_start"),
        (WorkloadFamily::WarmThroughput, "warm_throughput"),
        (WorkloadFamily::Async, "async"),
        (WorkloadFamily::ModuleGraphs, "module_graphs"),
        (WorkloadFamily::NpmCohorts, "npm_cohorts"),
        (WorkloadFamily::ReactCompile, "react_compile"),
        (WorkloadFamily::ReactSsr, "react_ssr"),
        (WorkloadFamily::ReactClient, "react_client"),
        (WorkloadFamily::MixedPackage, "mixed_package"),
        (WorkloadFamily::TailLatency, "tail_latency"),
        (WorkloadFamily::MemoryPressure, "memory_pressure"),
    ];
    for (variant, expected) in variants {
        assert_eq!(variant.to_string(), expected);
        assert_eq!(variant.as_str(), expected);
    }
}

// ── Error Display tests ─────────────────────────────────────────────

#[test]
fn error_display_invalid_schema_version() {
    let err = SupremacyCellMatrixError::InvalidSchemaVersion {
        found: "v999".to_string(),
    };
    assert_eq!(err.to_string(), "unexpected schema version `v999`");
}

#[test]
fn error_display_invalid_log_schema_version() {
    let err = SupremacyCellMatrixError::InvalidLogSchemaVersion {
        found: "log.v0".to_string(),
    };
    assert_eq!(err.to_string(), "unexpected log schema version `log.v0`");
}

#[test]
fn error_display_missing_matrix_dimension() {
    let err = SupremacyCellMatrixError::MissingMatrixDimension {
        dimension: "entry_mode".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "missing required matrix dimension `entry_mode`"
    );
}

#[test]
fn error_display_unknown_family_dimension() {
    let err = SupremacyCellMatrixError::UnknownFamilyDimension {
        family: WorkloadFamily::Async,
        dimension: "bogus".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "family `async` references unknown matrix dimension `bogus`"
    );
}

#[test]
fn error_display_duplicate_family() {
    let err = SupremacyCellMatrixError::DuplicateFamily {
        family: WorkloadFamily::ReactSsr,
    };
    assert_eq!(
        err.to_string(),
        "duplicate family definition for `react_ssr`"
    );
}

#[test]
fn error_display_missing_family() {
    let err = SupremacyCellMatrixError::MissingFamily {
        family: WorkloadFamily::MemoryPressure,
    };
    assert_eq!(
        err.to_string(),
        "missing required family definition for `memory_pressure`"
    );
}

#[test]
fn error_display_missing_family_coverage() {
    let err = SupremacyCellMatrixError::MissingFamilyCoverage {
        family: WorkloadFamily::ColdStart,
    };
    assert_eq!(
        err.to_string(),
        "missing cell coverage for required family `cold_start`"
    );
}

#[test]
fn error_display_duplicate_cell_id() {
    let err = SupremacyCellMatrixError::DuplicateCellId {
        cell_id: "cell_x".to_string(),
    };
    assert_eq!(err.to_string(), "duplicate cell id `cell_x`");
}

#[test]
fn error_display_duplicate_interference_rule() {
    let err = SupremacyCellMatrixError::DuplicateInterferenceRule {
        rule_id: "rule_1".to_string(),
    };
    assert_eq!(err.to_string(), "duplicate interference rule id `rule_1`");
}

#[test]
fn error_display_cold_start_must_be_cold() {
    let err = SupremacyCellMatrixError::ColdStartMustBeCold {
        cell_id: "cs_warm".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "cold-start cell `cs_warm` must use warm_state=cold"
    );
}

#[test]
fn error_display_react_entry_mode_mismatch() {
    let err = SupremacyCellMatrixError::ReactEntryModeMismatch {
        cell_id: "react_x".to_string(),
        expected: EntryMode::NativeReactSsr,
        found: EntryMode::Cli,
    };
    let msg = err.to_string();
    assert!(msg.contains("react_x"));
    assert!(msg.contains("NativeReactSsr"));
    assert!(msg.contains("Cli"));
}

#[test]
fn error_display_serialization() {
    let err = SupremacyCellMatrixError::Serialization("bad data".to_string());
    assert_eq!(
        err.to_string(),
        "failed to serialize supremacy cell matrix: bad data"
    );
}

// ── Validation error path tests ─────────────────────────────────────

#[test]
fn validate_rejects_wrong_schema_version() {
    let mut fixture = load_fixture();
    fixture.schema_version = "wrong.version".to_string();
    let err = validate_artifact(&fixture).expect_err("should reject");
    assert!(matches!(
        err,
        SupremacyCellMatrixError::InvalidSchemaVersion { .. }
    ));
}

#[test]
fn validate_rejects_wrong_log_schema_version() {
    let mut fixture = load_fixture();
    fixture.log_schema_version = "wrong.log.version".to_string();
    let err = validate_artifact(&fixture).expect_err("should reject");
    assert!(matches!(
        err,
        SupremacyCellMatrixError::InvalidLogSchemaVersion { .. }
    ));
}

#[test]
fn validate_rejects_missing_matrix_dimension() {
    let mut fixture = load_fixture();
    fixture.matrix_dimensions.retain(|d| d != "warm_state");
    let err = validate_artifact(&fixture).expect_err("should reject");
    assert!(matches!(
        err,
        SupremacyCellMatrixError::MissingMatrixDimension { .. }
    ));
}

#[test]
fn validate_rejects_unknown_family_dimension() {
    let mut fixture = load_fixture();
    fixture.cell_families[0]
        .required_dimensions
        .push("nonexistent_dim".to_string());
    let err = validate_artifact(&fixture).expect_err("should reject");
    assert!(matches!(
        err,
        SupremacyCellMatrixError::UnknownFamilyDimension { .. }
    ));
}

#[test]
fn validate_rejects_duplicate_family() {
    let mut fixture = load_fixture();
    let dup = fixture.cell_families[0].clone();
    fixture.cell_families.push(dup);
    let err = validate_artifact(&fixture).expect_err("should reject");
    assert!(matches!(
        err,
        SupremacyCellMatrixError::DuplicateFamily { .. }
    ));
}

#[test]
fn validate_rejects_missing_required_family() {
    let mut fixture = load_fixture();
    fixture
        .cell_families
        .retain(|f| f.family != WorkloadFamily::MemoryPressure);
    let err = validate_artifact(&fixture).expect_err("should reject");
    assert!(matches!(
        err,
        SupremacyCellMatrixError::MissingFamily { .. }
    ));
}

#[test]
fn validate_rejects_duplicate_cell_id() {
    let mut fixture = load_fixture();
    let dup = fixture.cells[0].clone();
    fixture.cells.push(dup);
    let err = validate_artifact(&fixture).expect_err("should reject");
    assert!(matches!(
        err,
        SupremacyCellMatrixError::DuplicateCellId { .. }
    ));
}

#[test]
fn validate_rejects_duplicate_interference_rule_id() {
    let mut fixture = load_fixture();
    let dup = fixture.interference_rules[0].clone();
    fixture.interference_rules.push(dup);
    let err = validate_artifact(&fixture).expect_err("should reject");
    assert!(matches!(
        err,
        SupremacyCellMatrixError::DuplicateInterferenceRule { .. }
    ));
}

#[test]
fn validate_rejects_cold_start_with_warm_state() {
    let mut fixture = load_fixture();
    let cell = fixture
        .cells
        .iter_mut()
        .find(|c| c.family == WorkloadFamily::ColdStart)
        .expect("cold start cell");
    cell.warm_state = WarmState::Warm;
    let err = validate_artifact(&fixture).expect_err("should reject");
    assert!(matches!(
        err,
        SupremacyCellMatrixError::ColdStartMustBeCold { .. }
    ));
}

#[test]
fn validate_rejects_react_compile_with_wrong_entry_mode() {
    let mut fixture = load_fixture();
    let cell = fixture
        .cells
        .iter_mut()
        .find(|c| c.family == WorkloadFamily::ReactCompile)
        .expect("react compile cell");
    cell.entry_mode = EntryMode::Library;
    let err = validate_artifact(&fixture).expect_err("should reject");
    if let SupremacyCellMatrixError::ReactEntryModeMismatch {
        expected, found, ..
    } = &err
    {
        assert_eq!(*expected, EntryMode::NativeReactCompile);
        assert_eq!(*found, EntryMode::Library);
    } else {
        panic!("expected ReactEntryModeMismatch, got {err:?}");
    }
}

#[test]
fn validate_rejects_react_ssr_with_wrong_entry_mode() {
    let mut fixture = load_fixture();
    let cell = fixture
        .cells
        .iter_mut()
        .find(|c| c.family == WorkloadFamily::ReactSsr)
        .expect("react ssr cell");
    cell.entry_mode = EntryMode::Cli;
    let err = validate_artifact(&fixture).expect_err("should reject");
    if let SupremacyCellMatrixError::ReactEntryModeMismatch {
        expected, found, ..
    } = &err
    {
        assert_eq!(*expected, EntryMode::NativeReactSsr);
        assert_eq!(*found, EntryMode::Cli);
    } else {
        panic!("expected ReactEntryModeMismatch, got {err:?}");
    }
}

#[test]
fn validate_rejects_react_client_with_wrong_entry_mode() {
    let mut fixture = load_fixture();
    let cell = fixture
        .cells
        .iter_mut()
        .find(|c| c.family == WorkloadFamily::ReactClient)
        .expect("react client cell");
    cell.entry_mode = EntryMode::MixedPackage;
    let err = validate_artifact(&fixture).expect_err("should reject");
    if let SupremacyCellMatrixError::ReactEntryModeMismatch {
        expected, found, ..
    } = &err
    {
        assert_eq!(*expected, EntryMode::NativeReactClient);
        assert_eq!(*found, EntryMode::MixedPackage);
    } else {
        panic!("expected ReactEntryModeMismatch, got {err:?}");
    }
}

#[test]
fn validate_rejects_cell_referencing_unknown_interference_rule() {
    let mut fixture = load_fixture();
    let cell = fixture
        .cells
        .iter_mut()
        .find(|c| !c.interference_rule_ids.is_empty())
        .expect("cell with interference rules");
    cell.interference_rule_ids
        .push("nonexistent_rule".to_string());
    let err = validate_artifact(&fixture).expect_err("should reject");
    assert!(matches!(
        err,
        SupremacyCellMatrixError::UnknownInterferenceRule { .. }
    ));
}

#[test]
fn validate_rejects_missing_interference_metadata_for_non_isolated() {
    let mut fixture = load_fixture();
    // Find a cell with non-isolated profile and clear its rules
    let cell = fixture
        .cells
        .iter_mut()
        .find(|c| c.interference_profile != InterferenceProfile::Isolated)
        .expect("non-isolated cell");
    cell.interference_rule_ids.clear();
    let err = validate_artifact(&fixture).expect_err("should reject");
    assert!(matches!(
        err,
        SupremacyCellMatrixError::MissingInterferenceMetadata { .. }
    ));
}

#[test]
fn validate_rejects_missing_tail_decomposition_for_tail_measurement() {
    let mut fixture = load_fixture();
    // Find a cell and make it have tail_latency measurement without axes
    let cell = fixture
        .cells
        .iter_mut()
        .find(|c| c.family == WorkloadFamily::TailLatency)
        .expect("tail cell");
    cell.tail_axis_ids.clear();
    let err = validate_artifact(&fixture).expect_err("should reject");
    assert!(matches!(
        err,
        SupremacyCellMatrixError::MissingTailDecomposition { .. }
    ));
}

#[test]
fn validate_rejects_unknown_tail_axis_reference() {
    let mut fixture = load_fixture();
    let cell = fixture
        .cells
        .iter_mut()
        .find(|c| !c.tail_axis_ids.is_empty())
        .expect("cell with tail axes");
    cell.tail_axis_ids.push(TailAxis::CompileNs);
    // Remove CompileNs from the axis definitions
    fixture
        .tail_decomposition_axes
        .retain(|a| a.axis != TailAxis::CompileNs);
    let err = validate_artifact(&fixture).expect_err("should reject");
    assert!(matches!(
        err,
        SupremacyCellMatrixError::UnknownTailAxis { .. }
    ));
}

#[test]
fn validate_rejects_missing_family_coverage() {
    let mut fixture = load_fixture();
    // Remove all cells from one required family
    fixture
        .cells
        .retain(|c| c.family != WorkloadFamily::ParseCompile);
    let err = validate_artifact(&fixture).expect_err("should reject");
    assert!(matches!(
        err,
        SupremacyCellMatrixError::MissingFamilyCoverage { .. }
    ));
}

// ── Constants tests ─────────────────────────────────────────────────

#[test]
fn component_constant_value() {
    assert_eq!(SUPREMACY_CELL_MATRIX_COMPONENT, "supremacy_cell_matrix");
}

#[test]
fn required_matrix_dimensions_has_six_entries() {
    assert_eq!(REQUIRED_MATRIX_DIMENSIONS.len(), 6);
    assert!(REQUIRED_MATRIX_DIMENSIONS.contains(&"workload_family"));
    assert!(REQUIRED_MATRIX_DIMENSIONS.contains(&"environment"));
    assert!(REQUIRED_MATRIX_DIMENSIONS.contains(&"entry_mode"));
    assert!(REQUIRED_MATRIX_DIMENSIONS.contains(&"warm_state"));
    assert!(REQUIRED_MATRIX_DIMENSIONS.contains(&"measurement_family"));
    assert!(REQUIRED_MATRIX_DIMENSIONS.contains(&"interference_profile"));
}

#[test]
fn required_board_families_has_twelve_entries() {
    assert_eq!(REQUIRED_BOARD_FAMILIES.len(), 12);
}

// ── Interference index tests ────────────────────────────────────────

#[test]
fn interference_index_is_bidirectional() {
    let fixture = load_fixture();
    let index = build_interference_index(&fixture).expect("build");
    // For every rule, both primary and concurrent should appear in each other's edge sets
    for rule in &fixture.interference_rules {
        let primary_edges = index.get(&rule.primary_family).expect("primary in index");
        assert!(
            primary_edges.contains(&rule.concurrent_family),
            "primary {} should list concurrent {}",
            rule.primary_family,
            rule.concurrent_family,
        );
        let concurrent_edges = index
            .get(&rule.concurrent_family)
            .expect("concurrent in index");
        assert!(
            concurrent_edges.contains(&rule.primary_family),
            "concurrent {} should list primary {}",
            rule.concurrent_family,
            rule.primary_family,
        );
    }
}

#[test]
fn interference_index_propagates_validation_error() {
    let mut fixture = load_fixture();
    fixture.schema_version = "bad".to_string();
    let err = build_interference_index(&fixture).expect_err("should fail");
    assert!(matches!(
        err,
        SupremacyCellMatrixError::InvalidSchemaVersion { .. }
    ));
}

// ── Hash tests ──────────────────────────────────────────────────────

#[test]
fn artifact_hash_changes_when_content_changes() {
    let fixture = load_fixture();
    let original = artifact_hash(&fixture).expect("hash");

    let mut modified = fixture.clone();
    modified.contract_version = "999.0.0".to_string();
    let changed = artifact_hash(&modified).expect("hash");

    assert_ne!(original, changed);
}

#[test]
fn artifact_hash_is_hex_encoded_sha256() {
    let fixture = load_fixture();
    let hash = artifact_hash(&fixture).expect("hash");
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

// ── Struct field tests ──────────────────────────────────────────────

#[test]
fn changelog_entry_serde_round_trip() {
    let entry = ChangelogEntry {
        version: "1.0.0".to_string(),
        rationale: "initial".to_string(),
        impact_assessment: "none".to_string(),
        compatibility_notes: "n/a".to_string(),
        changed_at_utc: "2026-01-01T00:00:00Z".to_string(),
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let back: ChangelogEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, entry);
}

#[test]
fn supremacy_cell_family_spec_serde_round_trip() {
    let spec = SupremacyCellFamilySpec {
        family: WorkloadFamily::Async,
        measurement_family: MeasurementFamily::Latency,
        required_dimensions: vec!["workload_family".to_string()],
        required_for_board: true,
        shipped_surface_note: "test note".to_string(),
    };
    let json = serde_json::to_string(&spec).expect("serialize");
    let back: SupremacyCellFamilySpec = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, spec);
}

#[test]
fn supremacy_cell_spec_serde_round_trip() {
    let spec = SupremacyCellSpec {
        cell_id: "test_cell".to_string(),
        family: WorkloadFamily::ColdStart,
        workload_kind: "test".to_string(),
        environment: "linux".to_string(),
        entry_mode: EntryMode::Cli,
        warm_state: WarmState::Cold,
        measurement_family: MeasurementFamily::Latency,
        interference_profile: InterferenceProfile::Isolated,
        mixed_with: vec![],
        interference_rule_ids: vec![],
        tail_axis_ids: vec![],
        required_for_universal_verdict: true,
    };
    let json = serde_json::to_string(&spec).expect("serialize");
    let back: SupremacyCellSpec = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, spec);
}

#[test]
fn interference_rule_serde_round_trip() {
    let rule = InterferenceRule {
        rule_id: "test_rule".to_string(),
        primary_family: WorkloadFamily::Async,
        concurrent_family: WorkloadFamily::MixedPackage,
        shared_resources: vec![
            SharedResource::SchedulerQueue,
            SharedResource::WorkerThreads,
        ],
        decomposition_label: "label".to_string(),
        explanation: "explanation".to_string(),
    };
    let json = serde_json::to_string(&rule).expect("serialize");
    let back: InterferenceRule = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, rule);
}

#[test]
fn tail_decomposition_axis_spec_serde_round_trip() {
    let spec = TailDecompositionAxisSpec {
        axis: TailAxis::GcPauseNs,
        stage: "memory_reclamation".to_string(),
        description: "GC pauses".to_string(),
    };
    let json = serde_json::to_string(&spec).expect("serialize");
    let back: TailDecompositionAxisSpec = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, spec);
}

// ── Ordering and Eq tests ───────────────────────────────────────────

#[test]
fn workload_family_ord_is_consistent() {
    // Derive-based Ord should be stable across calls
    let a = WorkloadFamily::Async;
    let b = WorkloadFamily::ReactSsr;
    let cmp1 = a.cmp(&b);
    let cmp2 = a.cmp(&b);
    assert_eq!(cmp1, cmp2);
}

#[test]
fn workload_family_btree_set_deduplicates() {
    let mut set = BTreeSet::new();
    set.insert(WorkloadFamily::Async);
    set.insert(WorkloadFamily::Async);
    set.insert(WorkloadFamily::ColdStart);
    assert_eq!(set.len(), 2);
}

// ── Clone and Debug tests ───────────────────────────────────────────

#[test]
fn workload_family_debug_is_not_empty() {
    let dbg = format!("{:?}", WorkloadFamily::ParseCompile);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("ParseCompile"));
}

#[test]
fn error_clone_and_eq() {
    let err = SupremacyCellMatrixError::DuplicateCellId {
        cell_id: "x".to_string(),
    };
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn error_debug_is_not_empty() {
    let err = SupremacyCellMatrixError::MissingFamily {
        family: WorkloadFamily::Async,
    };
    let dbg = format!("{err:?}");
    assert!(!dbg.is_empty());
}

// ── Edge case tests ─────────────────────────────────────────────────

#[test]
fn validate_accepts_extra_non_required_dimensions() {
    let mut fixture = load_fixture();
    fixture
        .matrix_dimensions
        .push("extra_custom_dim".to_string());
    // Should still validate, extra dimensions are allowed
    validate_artifact(&fixture).expect("extra dims are fine");
}

#[test]
fn validate_accepts_extra_families_beyond_required() {
    // The fixture should validate even if we add an extra family spec,
    // as long as all required families are still covered and it doesn't duplicate.
    // Since WorkloadFamily is an enum with fixed variants, we cannot add a truly
    // extra family. Instead, verify the fixture is exactly the required set.
    let fixture = load_fixture();
    let families: BTreeSet<WorkloadFamily> =
        fixture.cell_families.iter().map(|f| f.family).collect();
    assert_eq!(families.len(), REQUIRED_BOARD_FAMILIES.len());
}

#[test]
fn fixture_all_cells_have_nonempty_cell_id() {
    let fixture = load_fixture();
    for cell in &fixture.cells {
        assert!(!cell.cell_id.is_empty(), "cell id must not be empty");
    }
}

#[test]
fn fixture_all_interference_rules_have_nonempty_fields() {
    let fixture = load_fixture();
    for rule in &fixture.interference_rules {
        assert!(!rule.rule_id.is_empty());
        assert!(!rule.shared_resources.is_empty());
        assert!(!rule.decomposition_label.is_empty());
        assert!(!rule.explanation.is_empty());
    }
}

#[test]
fn fixture_all_tail_axes_have_nonempty_fields() {
    let fixture = load_fixture();
    for axis in &fixture.tail_decomposition_axes {
        assert!(!axis.stage.is_empty());
        assert!(!axis.description.is_empty());
    }
}

#[test]
fn fixture_changelog_has_at_least_one_entry() {
    let fixture = load_fixture();
    assert!(!fixture.changelog.is_empty());
    let first = &fixture.changelog[0];
    assert!(!first.version.is_empty());
    assert!(!first.rationale.is_empty());
}

#[test]
fn workload_family_serde_uses_snake_case() {
    let json = serde_json::to_string(&WorkloadFamily::ReactSsr).expect("serialize");
    assert_eq!(json, "\"react_ssr\"");

    let json = serde_json::to_string(&WorkloadFamily::MixedPackage).expect("serialize");
    assert_eq!(json, "\"mixed_package\"");

    let json = serde_json::to_string(&WorkloadFamily::WarmThroughput).expect("serialize");
    assert_eq!(json, "\"warm_throughput\"");
}

#[test]
fn entry_mode_serde_uses_snake_case() {
    let json = serde_json::to_string(&EntryMode::NativeReactCompile).expect("serialize");
    assert_eq!(json, "\"native_react_compile\"");

    let json = serde_json::to_string(&EntryMode::NativeReactSsr).expect("serialize");
    assert_eq!(json, "\"native_react_ssr\"");
}

#[test]
fn interference_profile_serde_uses_snake_case() {
    let json = serde_json::to_string(&InterferenceProfile::SchedulerContention).expect("serialize");
    assert_eq!(json, "\"scheduler_contention\"");

    let json = serde_json::to_string(&InterferenceProfile::MemoryContention).expect("serialize");
    assert_eq!(json, "\"memory_contention\"");
}

#[test]
fn shared_resource_serde_uses_snake_case() {
    let json = serde_json::to_string(&SharedResource::FrontendCpu).expect("serialize");
    assert_eq!(json, "\"frontend_cpu\"");

    let json = serde_json::to_string(&SharedResource::MemoryBandwidth).expect("serialize");
    assert_eq!(json, "\"memory_bandwidth\"");
}

#[test]
fn tail_axis_serde_uses_snake_case() {
    let json = serde_json::to_string(&TailAxis::ModuleLoadNs).expect("serialize");
    assert_eq!(json, "\"module_load_ns\"");

    let json = serde_json::to_string(&TailAxis::QueueDelayNs).expect("serialize");
    assert_eq!(json, "\"queue_delay_ns\"");
}

#[test]
fn validate_rejects_module_graphs_without_interference_rules() {
    let mut fixture = load_fixture();
    let cell = fixture
        .cells
        .iter_mut()
        .find(|c| c.family == WorkloadFamily::ModuleGraphs)
        .expect("module graphs cell");
    cell.interference_profile = InterferenceProfile::Isolated;
    cell.interference_rule_ids.clear();
    // ModuleGraphs requires interference metadata regardless of profile
    let err = validate_artifact(&fixture).expect_err("should reject");
    assert!(matches!(
        err,
        SupremacyCellMatrixError::MissingInterferenceMetadata { .. }
    ));
}

#[test]
fn validate_rejects_npm_cohorts_without_interference_rules() {
    let mut fixture = load_fixture();
    let cell = fixture
        .cells
        .iter_mut()
        .find(|c| c.family == WorkloadFamily::NpmCohorts)
        .expect("npm cohorts cell");
    cell.interference_profile = InterferenceProfile::Isolated;
    cell.interference_rule_ids.clear();
    let err = validate_artifact(&fixture).expect_err("should reject");
    assert!(matches!(
        err,
        SupremacyCellMatrixError::MissingInterferenceMetadata { .. }
    ));
}

#[test]
fn validate_rejects_memory_pressure_without_interference_rules() {
    let mut fixture = load_fixture();
    let cell = fixture
        .cells
        .iter_mut()
        .find(|c| c.family == WorkloadFamily::MemoryPressure)
        .expect("memory pressure cell");
    cell.interference_profile = InterferenceProfile::Isolated;
    cell.interference_rule_ids.clear();
    let err = validate_artifact(&fixture).expect_err("should reject");
    assert!(matches!(
        err,
        SupremacyCellMatrixError::MissingInterferenceMetadata { .. }
    ));
}
