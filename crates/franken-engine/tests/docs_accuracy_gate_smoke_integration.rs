//! Integration tests for the docs accuracy gate smoke suite.
//!
//! Validates that the comprehensive docs accuracy gate infrastructure works
//! end-to-end including inventory building, gate evaluation, and smoke testing.

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
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use frankenengine_engine::docs_accuracy_gate::{
    DocSource, DocsAccuracyGate, DocsAccuracyInventory, DocumentedSurface, DriftClass, GateConfig,
    GateReport, SurfaceType, build_seed_inventory,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn create_test_inventory() -> DocsAccuracyInventory {
    let mut inv = build_seed_inventory();

    // Add operator documentation surfaces
    let mut sources = BTreeSet::new();
    sources.insert(DocSource::OperatorDocs);

    let operator_surface = DocumentedSurface {
        id: "test_operator_guide".to_string(),
        name: "V8 supremacy evidence publication".to_string(),
        surface_type: SurfaceType::RuntimeBehavior,
        sources,
        documented_behavior: "Gate-based publication with cell status verification".to_string(),
        shipped_behavior: "Gate-based publication with cell status verification".to_string(),
        drift_class: DriftClass::Aligned,
        drift_notes: String::new(),
        explicitly_unsupported: false,
    };
    inv.add_surface(operator_surface).unwrap();

    // Add observability mode surface
    let mut obs_sources = BTreeSet::new();
    obs_sources.insert(DocSource::OperatorDocs);
    obs_sources.insert(DocSource::InlineComments);

    let obs_surface = DocumentedSurface {
        id: "test_observability_mode".to_string(),
        name: "BudgetedCapture mode".to_string(),
        surface_type: SurfaceType::RuntimeBehavior,
        sources: obs_sources,
        documented_behavior: "Production-safe telemetry with bounded overhead".to_string(),
        shipped_behavior: "Production-safe telemetry with bounded overhead".to_string(),
        drift_class: DriftClass::Aligned,
        drift_notes: String::new(),
        explicitly_unsupported: false,
    };
    inv.add_surface(obs_surface).unwrap();

    inv
}

// ---------------------------------------------------------------------------
// Basic inventory and gate functionality
// ---------------------------------------------------------------------------

#[test]
fn docs_accuracy_inventory_comprehensive_coverage() {
    let inv = create_test_inventory();

    // Verify we have surfaces from all expected source types
    let by_source = inv.surfaces_by_source();
    assert!(by_source.contains_key(&DocSource::Readme));
    assert!(by_source.contains_key(&DocSource::CliHelp));
    assert!(by_source.contains_key(&DocSource::OperatorDocs));

    // Verify we have different surface types
    let has_commands = inv
        .surfaces
        .iter()
        .any(|s| s.surface_type == SurfaceType::Command);
    let has_runtime_behaviors = inv
        .surfaces
        .iter()
        .any(|s| s.surface_type == SurfaceType::RuntimeBehavior);
    assert!(has_commands);
    assert!(has_runtime_behaviors);

    // Verify surface count is reasonable
    assert!(inv.surface_count() >= 10); // At least the seed inventory plus test additions
}

#[test]
fn docs_accuracy_gate_evaluates_comprehensive_inventory() {
    let gate = DocsAccuracyGate::with_defaults();
    let inv = create_test_inventory();

    let report = gate.evaluate(&inv);

    // With properly aligned inventory, gate should pass
    assert!(report.verdict.is_pass());
    assert_eq!(report.bead_id, "bd-1lsy.10.11");
    assert_eq!(report.component, "docs_accuracy_gate");
    assert!(report.total_surfaces > 0);
    assert_eq!(
        report.total_surfaces,
        report.aligned_count + report.drifted_count
    );
}

#[test]
fn docs_accuracy_gate_blocks_contradictory_behavior() {
    let gate = DocsAccuracyGate::with_defaults();
    let mut inv = create_test_inventory();

    // Add a surface with contradictory behavior
    let mut sources = BTreeSet::new();
    sources.insert(DocSource::Readme);

    let contradictory_surface = DocumentedSurface {
        id: "test_contradictory".to_string(),
        name: "frankenctl broken-command".to_string(),
        surface_type: SurfaceType::Command,
        sources,
        documented_behavior: "Documented as working correctly".to_string(),
        shipped_behavior: "Actually returns error 500".to_string(),
        drift_class: DriftClass::ContradictoryBehavior,
        drift_notes: "CLI behavior contradicts documentation".to_string(),
        explicitly_unsupported: false,
    };
    inv.add_surface(contradictory_surface).unwrap();

    let report = gate.evaluate(&inv);

    // Gate should fail due to contradictory behavior
    assert!(!report.verdict.is_pass());
}

#[test]
fn docs_accuracy_gate_allows_minor_syntax_drift() {
    let gate = DocsAccuracyGate::with_defaults();
    let mut inv = create_test_inventory();

    // Add a surface with minor syntax drift (acceptable)
    let mut sources = BTreeSet::new();
    sources.insert(DocSource::CliHelp);

    let minor_drift_surface = DocumentedSurface {
        id: "test_minor_drift".to_string(),
        name: "frankenctl compile".to_string(),
        surface_type: SurfaceType::Command,
        sources,
        documented_behavior: "frankenctl compile --input file.js".to_string(),
        shipped_behavior: "frankenctl compile -i file.js".to_string(),
        drift_class: DriftClass::MinorSyntaxDrift,
        drift_notes: "Short flag vs long flag difference".to_string(),
        explicitly_unsupported: false,
    };
    inv.add_surface(minor_drift_surface).unwrap();

    let report = gate.evaluate(&inv);

    // Gate should pass since minor syntax drift is acceptable
    assert!(report.verdict.is_pass());
}

#[test]
fn docs_accuracy_gate_report_serde_roundtrip() {
    let gate = DocsAccuracyGate::with_defaults();
    let inv = create_test_inventory();
    let report = gate.evaluate(&inv);

    let json = serde_json::to_string(&report).unwrap();
    let parsed: GateReport = serde_json::from_str(&json).unwrap();

    assert_eq!(report.total_surfaces, parsed.total_surfaces);
    assert_eq!(report.verdict.is_pass(), parsed.verdict.is_pass());
    assert_eq!(report.inventory_hash, parsed.inventory_hash);
    assert_eq!(report.drift_distribution, parsed.drift_distribution);
}

#[test]
fn docs_accuracy_inventory_content_hash_stability() {
    let inv1 = create_test_inventory();
    let inv2 = create_test_inventory();

    // Same inventory should produce same hash
    assert_eq!(inv1.content_hash(), inv2.content_hash());

    // Different inventory should produce different hash
    let mut inv3 = create_test_inventory();
    let mut sources = BTreeSet::new();
    sources.insert(DocSource::ExternalReference);

    let extra_surface = DocumentedSurface {
        id: "extra_surface".to_string(),
        name: "Extra documentation surface".to_string(),
        surface_type: SurfaceType::ApiSurface,
        sources,
        documented_behavior: "Extra behavior".to_string(),
        shipped_behavior: "Extra behavior".to_string(),
        drift_class: DriftClass::Aligned,
        drift_notes: String::new(),
        explicitly_unsupported: false,
    };
    inv3.add_surface(extra_surface).unwrap();

    assert_ne!(inv1.content_hash(), inv3.content_hash());
}

// ---------------------------------------------------------------------------
// Script and binary integration tests
// ---------------------------------------------------------------------------

#[test]
fn docs_accuracy_gate_suite_script_exists_and_executable() {
    let script_path = repo_root().join("scripts/run_docs_accuracy_gate_suite.sh");
    assert!(
        script_path.exists(),
        "docs accuracy gate suite script should exist"
    );

    let metadata = fs::metadata(&script_path).unwrap();
    let permissions = metadata.permissions();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert!(
            permissions.mode() & 0o111 != 0,
            "script should be executable"
        );
    }
}

#[test]
fn docs_accuracy_gate_smoke_script_exists_and_executable() {
    let smoke_script_path = repo_root().join("scripts/e2e/docs_accuracy_gate_smoke.sh");
    assert!(
        smoke_script_path.exists(),
        "docs accuracy gate smoke script should exist"
    );

    let metadata = fs::metadata(&smoke_script_path).unwrap();
    let permissions = metadata.permissions();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert!(
            permissions.mode() & 0o111 != 0,
            "smoke script should be executable"
        );
    }
}

#[test]
fn docs_accuracy_gate_script_has_expected_structure() {
    let script_path = repo_root().join("scripts/run_docs_accuracy_gate_suite.sh");
    let content = fs::read_to_string(&script_path).unwrap();

    // Verify script has expected components
    assert!(
        content.contains("docs_accuracy_gate"),
        "should reference docs accuracy gate"
    );
    assert!(
        content.contains("rch"),
        "should use rch for remote compilation"
    );
    assert!(
        content.contains("bd-1lsy.10.11.3"),
        "should reference correct bead ID"
    );
    assert!(
        content.contains("RGC-911C"),
        "should reference correct RGC scenario"
    );
    assert!(
        content.contains("observability"),
        "should handle observability mode guidance"
    );
    assert!(
        content.contains("operator"),
        "should handle operator documentation"
    );
    assert!(
        content.contains("check|test|clippy|ci"),
        "should support all execution modes"
    );
}

#[test]
fn docs_accuracy_smoke_script_has_expected_structure() {
    let smoke_script_path = repo_root().join("scripts/e2e/docs_accuracy_gate_smoke.sh");
    let content = fs::read_to_string(&smoke_script_path).unwrap();

    // Verify smoke script follows established patterns
    assert!(
        content.contains("parser_frontier_bootstrap_env"),
        "should bootstrap deterministic environment"
    );
    assert!(
        content.contains("SCENARIO=\"smoke\""),
        "should set smoke scenario"
    );
    assert!(
        content.contains("run_docs_accuracy_gate_suite.sh ci"),
        "should call main suite in ci mode"
    );
}

// ---------------------------------------------------------------------------
// Release gate configuration tests
// ---------------------------------------------------------------------------

#[test]
fn docs_accuracy_gate_default_config_is_strict() {
    let config = GateConfig::default();

    // Default config should be strict for release gating
    assert_eq!(
        config.max_aspirational_claims, 0,
        "should not allow aspirational claims by default"
    );
    assert_eq!(
        config.max_broken_examples, 0,
        "should not allow broken examples by default"
    );
    assert!(
        config.fail_on_contradictory,
        "should fail on contradictory behavior by default"
    );
    assert_eq!(
        config.max_avg_severity_millionths, 50_000,
        "should have low severity threshold"
    );
    assert_eq!(
        config.min_alignment_rate_millionths, 950_000,
        "should require high alignment rate (95%)"
    );
}

#[test]
fn docs_accuracy_gate_custom_config_allows_flexibility() {
    let lenient_config = GateConfig {
        max_aspirational_claims: 3,
        max_broken_examples: 1,
        fail_on_contradictory: false,
        max_avg_severity_millionths: 200_000,
        min_alignment_rate_millionths: 800_000,
    };

    let gate = DocsAccuracyGate::new(lenient_config);
    let mut inv = create_test_inventory();

    // Add some drift that would fail default config
    let mut sources = BTreeSet::new();
    sources.insert(DocSource::Readme);

    let aspirational_surface = DocumentedSurface {
        id: "aspirational_test".to_string(),
        name: "frankenctl future-command".to_string(),
        surface_type: SurfaceType::Command,
        sources,
        documented_behavior: "Will be implemented in future release".to_string(),
        shipped_behavior: "Not yet implemented".to_string(),
        drift_class: DriftClass::AspirationalClaim,
        drift_notes: "Planned feature documentation".to_string(),
        explicitly_unsupported: false,
    };
    inv.add_surface(aspirational_surface).unwrap();

    let report = gate.evaluate(&inv);

    // Lenient config should allow this drift
    assert!(report.verdict.is_pass());
}

// ---------------------------------------------------------------------------
// Error handling and edge cases
// ---------------------------------------------------------------------------

#[test]
fn docs_accuracy_gate_handles_empty_inventory_gracefully() {
    let gate = DocsAccuracyGate::with_defaults();
    let inv = DocsAccuracyInventory::new();

    let report = gate.evaluate(&inv);

    // Empty inventory should fail
    assert!(!report.verdict.is_pass());
    assert_eq!(report.total_surfaces, 0);
    assert_eq!(report.aligned_count, 0);
    assert_eq!(report.drifted_count, 0);
}

#[test]
fn docs_accuracy_gate_handles_large_inventory() {
    let gate = DocsAccuracyGate::with_defaults();
    let mut inv = DocsAccuracyInventory::new();

    // Add many aligned surfaces
    for i in 0..100 {
        let mut sources = BTreeSet::new();
        sources.insert(DocSource::InlineComments);

        let surface = DocumentedSurface {
            id: format!("large_test_surface_{i}"),
            name: format!("Test surface {i}"),
            surface_type: SurfaceType::ApiSurface,
            sources,
            documented_behavior: format!("Test behavior {i}"),
            shipped_behavior: format!("Test behavior {i}"),
            drift_class: DriftClass::Aligned,
            drift_notes: String::new(),
            explicitly_unsupported: false,
        };
        inv.add_surface(surface).unwrap();
    }

    let report = gate.evaluate(&inv);

    // Large aligned inventory should pass
    assert!(report.verdict.is_pass());
    assert_eq!(report.total_surfaces, 100);
    assert_eq!(report.aligned_count, 100);
    assert_eq!(report.drifted_count, 0);
    assert_eq!(report.alignment_rate_millionths, 1_000_000);
}

#[test]
fn docs_accuracy_inventory_rejects_duplicate_surface_ids() {
    let mut inv = DocsAccuracyInventory::new();

    let mut sources = BTreeSet::new();
    sources.insert(DocSource::Readme);

    let surface1 = DocumentedSurface {
        id: "duplicate_id".to_string(),
        name: "Surface 1".to_string(),
        surface_type: SurfaceType::Command,
        sources: sources.clone(),
        documented_behavior: "Behavior 1".to_string(),
        shipped_behavior: "Behavior 1".to_string(),
        drift_class: DriftClass::Aligned,
        drift_notes: String::new(),
        explicitly_unsupported: false,
    };

    let surface2 = DocumentedSurface {
        id: "duplicate_id".to_string(), // Same ID
        name: "Surface 2".to_string(),
        surface_type: SurfaceType::Flag,
        sources,
        documented_behavior: "Behavior 2".to_string(),
        shipped_behavior: "Behavior 2".to_string(),
        drift_class: DriftClass::Aligned,
        drift_notes: String::new(),
        explicitly_unsupported: false,
    };

    // First addition should succeed
    inv.add_surface(surface1).unwrap();

    // Second addition with same ID should fail
    let result = inv.add_surface(surface2);
    assert!(result.is_err());
}

#[test]
fn docs_accuracy_gate_bead_and_component_identifiers_correct() {
    let gate = DocsAccuracyGate::with_defaults();
    let inv = create_test_inventory();
    let report = gate.evaluate(&inv);

    assert_eq!(report.bead_id, "bd-1lsy.10.11");
    assert_eq!(report.component, "docs_accuracy_gate");
    assert!(report.schema_version.contains("docs-accuracy-gate"));
}

// ---------------------------------------------------------------------------
// Observability mode specific tests
// ---------------------------------------------------------------------------

#[test]
fn docs_accuracy_inventory_tracks_observability_modes() {
    let inv = create_test_inventory();

    // Find the observability mode surface we added
    let obs_surface = inv
        .surfaces
        .iter()
        .find(|s| s.id == "test_observability_mode")
        .expect("observability mode surface should exist");

    assert_eq!(obs_surface.name, "BudgetedCapture mode");
    assert!(obs_surface.sources.contains(&DocSource::OperatorDocs));
    assert!(obs_surface.sources.contains(&DocSource::InlineComments));
    assert_eq!(obs_surface.surface_type, SurfaceType::RuntimeBehavior);
}

#[test]
fn docs_accuracy_inventory_tracks_operator_documentation() {
    let inv = create_test_inventory();

    // Find the operator documentation surface we added
    let op_surface = inv
        .surfaces
        .iter()
        .find(|s| s.id == "test_operator_guide")
        .expect("operator guide surface should exist");

    assert_eq!(op_surface.name, "V8 supremacy evidence publication");
    assert!(op_surface.sources.contains(&DocSource::OperatorDocs));
    assert_eq!(op_surface.surface_type, SurfaceType::RuntimeBehavior);
}

#[test]
fn docs_accuracy_gate_comprehensive_coverage_validation() {
    let inv = create_test_inventory();

    // Verify comprehensive coverage of documentation sources
    let source_counts = inv.surfaces_by_source();

    // Should have surfaces from multiple documentation sources
    assert!(
        source_counts.len() >= 3,
        "should have surfaces from multiple documentation sources"
    );

    // Verify we have the key surface types for comprehensive docs accuracy
    let has_commands = inv
        .surfaces
        .iter()
        .any(|s| s.surface_type == SurfaceType::Command);
    let has_runtime_behaviors = inv
        .surfaces
        .iter()
        .any(|s| s.surface_type == SurfaceType::RuntimeBehavior);

    assert!(has_commands, "should include CLI command surfaces");
    assert!(
        has_runtime_behaviors,
        "should include runtime behavior surfaces"
    );

    // Verify drift classification is working
    let drift_dist = inv.surfaces_by_drift();
    assert!(
        drift_dist.contains_key(&DriftClass::Aligned),
        "should have aligned surfaces"
    );

    // All test surfaces should be aligned (no intentional drift in test)
    let aligned_count = *drift_dist.get(&DriftClass::Aligned).unwrap_or(&0);
    assert!(aligned_count > 0, "should have some aligned surfaces");
}
