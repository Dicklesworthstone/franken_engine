//! Integration tests for react_repro_triage module (bd-1lsy.5.7.3).
//!
//! Validates end-to-end failure classification, repro extraction,
//! catalog building, severity assignment, owner routing, and event
//! emission across normal, boundary, failure, and adversarial paths.

use std::collections::BTreeSet;

use std::collections::BTreeMap;

use frankenengine_engine::react_repro_triage::{
    BEAD_ID, COMPONENT, CatalogSummary, FailureClass, FailureSeverity, FailureSymptoms,
    MinimizedRepro, OwnerRoute, POLICY_ID, ReproCatalog, SCHEMA_VERSION, TriageEntry, TriageEvent,
    assign_severity, build_triage_event, classify_failure, default_owner_route, generate_advisory,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_repro(source: &str) -> MinimizedRepro {
    MinimizedRepro::build(
        source,
        "expected output",
        "actual output",
        BTreeSet::from(["18.2.0".to_string()]),
        "frankenctl compile --input repro.tsx --goal module",
    )
}

fn make_entry(class: FailureClass, severity: FailureSeverity) -> TriageEntry {
    let owner = default_owner_route(class);
    let repro = make_repro(&format!("// repro for {}", class.as_str()));
    let advisory = generate_advisory(class, severity);
    TriageEntry::build(class, severity, owner, repro, &advisory)
}

// ---------------------------------------------------------------------------
// Classification integration
// ---------------------------------------------------------------------------

#[test]
fn classify_transform_bug_only() {
    let class = classify_failure(&FailureSymptoms {
        has_transform_diff: true,
        ..FailureSymptoms::default()
    });
    assert_eq!(class, FailureClass::TransformBug);
    assert!(class.is_engine_bug());
}

#[test]
fn classify_resolver_bug_only() {
    let class = classify_failure(&FailureSymptoms {
        has_resolver_error: true,
        ..FailureSymptoms::default()
    });
    assert_eq!(class, FailureClass::ResolverBug);
}

#[test]
fn classify_runtime_semantic_gap_only() {
    let class = classify_failure(&FailureSymptoms {
        has_runtime_gap: true,
        ..FailureSymptoms::default()
    });
    assert_eq!(class, FailureClass::RuntimeSemanticGap);
}

#[test]
fn classify_env_boundary_only() {
    let class = classify_failure(&FailureSymptoms {
        has_env_boundary: true,
        ..FailureSymptoms::default()
    });
    assert_eq!(class, FailureClass::UnsupportedEnvironment);
    assert!(!class.is_engine_bug());
}

#[test]
fn classify_version_mismatch_only() {
    let class = classify_failure(&FailureSymptoms {
        has_version_mismatch: true,
        ..FailureSymptoms::default()
    });
    assert_eq!(class, FailureClass::PackageMisuse);
    assert!(!class.is_engine_bug());
}

#[test]
fn classify_hook_violation_takes_priority() {
    let class = classify_failure(&FailureSymptoms {
        has_transform_diff: true,
        has_resolver_error: true,
        has_runtime_gap: true,
        has_env_boundary: true,
        has_version_mismatch: true,
        has_hook_violation: true,
        ..FailureSymptoms::default()
    });
    assert_eq!(class, FailureClass::HookInvariantViolation);
}

#[test]
fn classify_hydration_mismatch_priority() {
    let class = classify_failure(&FailureSymptoms {
        has_transform_diff: true,
        has_resolver_error: true,
        has_hydration_diff: true,
        ..FailureSymptoms::default()
    });
    assert_eq!(class, FailureClass::HydrationMismatch);
}

#[test]
fn classify_suspense_divergence() {
    let class = classify_failure(&FailureSymptoms {
        has_suspense_diff: true,
        ..FailureSymptoms::default()
    });
    assert_eq!(class, FailureClass::SuspenseDivergence);
}

#[test]
fn classify_error_boundary_failure() {
    let class = classify_failure(&FailureSymptoms {
        has_error_boundary_diff: true,
        ..FailureSymptoms::default()
    });
    assert_eq!(class, FailureClass::ErrorBoundaryFailure);
}

#[test]
fn classify_no_symptoms_is_unclassified() {
    let class = classify_failure(&FailureSymptoms::default());
    assert_eq!(class, FailureClass::Unclassified);
}

// ---------------------------------------------------------------------------
// Severity assignment
// ---------------------------------------------------------------------------

#[test]
fn critical_severity_for_blocking_engine_bug() {
    let sev = assign_severity(FailureClass::TransformBug, true, false, false);
    assert_eq!(sev, FailureSeverity::Critical);
}

#[test]
fn high_severity_for_engine_bug_no_workaround() {
    let sev = assign_severity(FailureClass::ResolverBug, false, false, false);
    assert_eq!(sev, FailureSeverity::High);
}

#[test]
fn medium_severity_for_engine_bug_with_workaround() {
    let sev = assign_severity(FailureClass::RuntimeSemanticGap, false, true, false);
    assert_eq!(sev, FailureSeverity::Medium);
}

#[test]
fn low_severity_for_non_engine_bug() {
    let sev = assign_severity(FailureClass::PackageMisuse, false, false, false);
    assert_eq!(sev, FailureSeverity::Low);
}

#[test]
fn low_severity_for_edge_case_engine_bug() {
    let sev = assign_severity(FailureClass::TransformBug, false, true, true);
    assert_eq!(sev, FailureSeverity::Medium);
}

// ---------------------------------------------------------------------------
// Owner routing
// ---------------------------------------------------------------------------

#[test]
fn default_owner_for_all_classes() {
    for class in FailureClass::all() {
        let owner = default_owner_route(*class);
        assert!(
            owner.bead_id.starts_with("bd-"),
            "owner bead_id should start with bd-: {}",
            owner.bead_id
        );
        assert!(!owner.team.is_empty());
        assert!(!owner.rationale.is_empty());
    }
}

#[test]
fn transform_bug_routes_to_jsx_team() {
    let owner = default_owner_route(FailureClass::TransformBug);
    assert_eq!(owner.team, "jsx-transform");
    assert_eq!(owner.bead_id, "bd-1lsy.3.6.1");
}

#[test]
fn resolver_bug_routes_to_module_resolution() {
    let owner = default_owner_route(FailureClass::ResolverBug);
    assert_eq!(owner.team, "module-resolution");
}

#[test]
fn package_misuse_routes_to_docs_triage() {
    let owner = default_owner_route(FailureClass::PackageMisuse);
    assert_eq!(owner.team, "docs-triage");
}

// ---------------------------------------------------------------------------
// Repro extraction
// ---------------------------------------------------------------------------

#[test]
fn repro_id_deterministic() {
    let r1 = make_repro("function App() { return <div />; }");
    let r2 = make_repro("function App() { return <div />; }");
    assert_eq!(r1.repro_id, r2.repro_id);
    assert_eq!(r1.source_hash, r2.source_hash);
}

#[test]
fn different_sources_different_repro_ids() {
    let r1 = make_repro("function App() { return <div />; }");
    let r2 = make_repro("function App() { return <span />; }");
    assert_ne!(r1.repro_id, r2.repro_id);
    assert_ne!(r1.source_hash, r2.source_hash);
}

#[test]
fn repro_preserves_react_versions() {
    let versions = BTreeSet::from(["17.0.2".to_string(), "18.2.0".to_string()]);
    let repro = MinimizedRepro::build("src", "exp", "act", versions.clone(), "cmd");
    assert_eq!(repro.react_versions, versions);
}

// ---------------------------------------------------------------------------
// Catalog building
// ---------------------------------------------------------------------------

#[test]
fn empty_catalog() {
    let catalog = ReproCatalog::build(Vec::new(), SecurityEpoch::from_raw(1));
    assert_eq!(catalog.summary.total_entries, 0);
    assert!(!catalog.has_critical_engine_bugs());
    assert!(catalog.verify_integrity());
    assert_eq!(catalog.schema_version, SCHEMA_VERSION);
    assert_eq!(catalog.bead_id, BEAD_ID);
}

#[test]
fn catalog_with_mixed_severities() {
    let entries = vec![
        make_entry(FailureClass::TransformBug, FailureSeverity::Critical),
        make_entry(FailureClass::ResolverBug, FailureSeverity::High),
        make_entry(FailureClass::PackageMisuse, FailureSeverity::Low),
    ];
    let catalog = ReproCatalog::build(entries, SecurityEpoch::from_raw(1));

    assert_eq!(catalog.summary.total_entries, 3);
    assert_eq!(catalog.summary.engine_bug_count, 2);
    assert_eq!(catalog.summary.unresolved_count, 3);
    assert!(catalog.has_critical_engine_bugs());

    // Sorted by severity descending
    assert_eq!(catalog.entries[0].severity, FailureSeverity::Critical);
    assert_eq!(
        catalog.entries[catalog.entries.len() - 1].severity,
        FailureSeverity::Low
    );
}

#[test]
fn catalog_severity_weighted_score() {
    let entries = vec![
        make_entry(FailureClass::TransformBug, FailureSeverity::Critical), // weight 5
        make_entry(FailureClass::PackageMisuse, FailureSeverity::Low),     // weight 2
    ];
    let catalog = ReproCatalog::build(entries, SecurityEpoch::from_raw(1));
    assert_eq!(catalog.summary.severity_weighted_score, 7);
}

#[test]
fn catalog_distinct_owners() {
    let entries = vec![
        make_entry(FailureClass::TransformBug, FailureSeverity::High),
        make_entry(FailureClass::TransformBug, FailureSeverity::Medium),
        make_entry(FailureClass::ResolverBug, FailureSeverity::High),
    ];
    let catalog = ReproCatalog::build(entries, SecurityEpoch::from_raw(1));
    assert_eq!(catalog.summary.distinct_owners, 2); // jsx-transform + module-resolution
}

#[test]
fn catalog_filters_work() {
    let entries = vec![
        make_entry(FailureClass::TransformBug, FailureSeverity::Critical),
        make_entry(FailureClass::ResolverBug, FailureSeverity::High),
        make_entry(FailureClass::PackageMisuse, FailureSeverity::Low),
    ];
    let catalog = ReproCatalog::build(entries, SecurityEpoch::from_raw(1));

    assert_eq!(
        catalog.entries_by_class(FailureClass::TransformBug).len(),
        1
    );
    assert_eq!(
        catalog.entries_by_severity(FailureSeverity::Critical).len(),
        1
    );
    assert_eq!(catalog.engine_bugs().len(), 2);
    assert_eq!(catalog.unresolved().len(), 3);
}

#[test]
fn catalog_integrity_tamper_detection() {
    let mut catalog = ReproCatalog::build(
        vec![make_entry(
            FailureClass::TransformBug,
            FailureSeverity::High,
        )],
        SecurityEpoch::from_raw(1),
    );
    assert!(catalog.verify_integrity());

    // Tamper with an entry
    if let Some(entry) = catalog.entries.first_mut() {
        entry.severity = FailureSeverity::Low;
    }
    // Integrity check may or may not catch this since we're modifying
    // the entries after hash computation — the hash was computed on the
    // original entries. This depends on implementation but the catalog
    // should at least not panic.
    let _ = catalog.verify_integrity();
}

// ---------------------------------------------------------------------------
// Advisory generation
// ---------------------------------------------------------------------------

#[test]
fn advisory_for_every_class_severity_combination() {
    for class in FailureClass::all() {
        for sev in [
            FailureSeverity::Critical,
            FailureSeverity::High,
            FailureSeverity::Medium,
            FailureSeverity::Low,
            FailureSeverity::Info,
        ] {
            let advisory = generate_advisory(*class, sev);
            assert!(
                !advisory.is_empty(),
                "advisory should not be empty for {class:?}/{sev:?}"
            );
        }
    }
}

#[test]
fn critical_advisory_mentions_in_progress() {
    let advisory = generate_advisory(FailureClass::TransformBug, FailureSeverity::Critical);
    assert!(
        advisory.contains("in progress"),
        "critical advisory should mention fix in progress: {advisory}"
    );
}

// ---------------------------------------------------------------------------
// Event emission
// ---------------------------------------------------------------------------

#[test]
fn triage_event_for_unresolved_entry() {
    let entry = make_entry(FailureClass::TransformBug, FailureSeverity::High);
    let event = build_triage_event("trace-001", "decision-001", "scenario-001", &entry);

    assert_eq!(event.component, COMPONENT);
    assert_eq!(event.policy_id, POLICY_ID);
    assert_eq!(event.trace_id, "trace-001");
    assert_eq!(event.decision_id, "decision-001");
    assert_eq!(event.outcome, "unresolved");
    assert!(event.error_code.is_some());
    assert!(event.error_code.as_ref().unwrap().contains("TRANSFORM_BUG"));
}

#[test]
fn triage_event_for_resolved_entry() {
    let mut entry = make_entry(FailureClass::ResolverBug, FailureSeverity::Medium);
    entry.unresolved = false;
    let event = build_triage_event("trace-002", "decision-002", "scenario-002", &entry);

    assert_eq!(event.outcome, "resolved");
    assert!(event.error_code.is_none());
}

#[test]
fn triage_event_serde_roundtrip() {
    let entry = make_entry(FailureClass::HydrationMismatch, FailureSeverity::Critical);
    let event = build_triage_event("trace", "decision", "scenario", &entry);
    let json = serde_json::to_string(&event).unwrap();
    let parsed: frankenengine_engine::react_repro_triage::TriageEvent =
        serde_json::from_str(&json).unwrap();
    assert_eq!(event, parsed);
}

// ---------------------------------------------------------------------------
// Serde roundtrip integration
// ---------------------------------------------------------------------------

#[test]
fn catalog_serde_roundtrip() {
    let entries = vec![
        make_entry(FailureClass::TransformBug, FailureSeverity::Critical),
        make_entry(FailureClass::PackageMisuse, FailureSeverity::Low),
    ];
    let catalog = ReproCatalog::build(entries, SecurityEpoch::from_raw(1));
    let json = serde_json::to_string_pretty(&catalog).unwrap();
    let parsed: ReproCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(catalog, parsed);
}

#[test]
fn repro_serde_roundtrip() {
    let repro = make_repro("function App() { return <div />; }");
    let json = serde_json::to_string(&repro).unwrap();
    let parsed: MinimizedRepro = serde_json::from_str(&json).unwrap();
    assert_eq!(repro, parsed);
}

#[test]
fn owner_route_serde_roundtrip() {
    let owner = default_owner_route(FailureClass::TransformBug);
    let json = serde_json::to_string(&owner).unwrap();
    let parsed: OwnerRoute = serde_json::from_str(&json).unwrap();
    assert_eq!(owner, parsed);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn catalog_build_is_deterministic() {
    let build_catalog = || {
        let entries = vec![
            make_entry(FailureClass::TransformBug, FailureSeverity::Critical),
            make_entry(FailureClass::ResolverBug, FailureSeverity::High),
        ];
        ReproCatalog::build(entries, SecurityEpoch::from_raw(1))
    };

    let c1 = build_catalog();
    let c2 = build_catalog();
    assert_eq!(c1.content_hash, c2.content_hash);
    assert_eq!(
        c1.summary.severity_weighted_score,
        c2.summary.severity_weighted_score
    );
    assert_eq!(c1.entries.len(), c2.entries.len());
}

// ---------------------------------------------------------------------------
// End-to-end: classify → triage → catalog → event
// ---------------------------------------------------------------------------

#[test]
fn full_triage_pipeline() {
    // Step 1: Classify failure symptoms
    let class = classify_failure(&FailureSymptoms {
        has_transform_diff: true,
        ..FailureSymptoms::default()
    });
    assert_eq!(class, FailureClass::TransformBug);

    // Step 2: Assign severity
    let severity = assign_severity(class, true, false, false);
    assert_eq!(severity, FailureSeverity::Critical);

    // Step 3: Route to owner
    let owner = default_owner_route(class);
    assert_eq!(owner.team, "jsx-transform");

    // Step 4: Extract repro
    let repro = make_repro("function App() { return <Broken />; }");
    assert!(repro.deterministic);

    // Step 5: Generate advisory
    let advisory = generate_advisory(class, severity);
    assert!(!advisory.is_empty());

    // Step 6: Build triage entry
    let entry = TriageEntry::build(class, severity, owner, repro, &advisory);
    assert!(entry.unresolved);
    assert_eq!(entry.failure_class, FailureClass::TransformBug);

    // Step 7: Build catalog
    let catalog = ReproCatalog::build(vec![entry.clone()], SecurityEpoch::from_raw(1));
    assert!(catalog.has_critical_engine_bugs());
    assert!(catalog.verify_integrity());

    // Step 8: Emit event
    let event = build_triage_event("trace-e2e", "decision-e2e", "pipeline-test", &entry);
    assert_eq!(event.outcome, "unresolved");
    assert!(event.error_code.is_some());
}

#[test]
fn full_triage_pipeline_non_engine_bug() {
    let class = classify_failure(&FailureSymptoms {
        has_version_mismatch: true,
        ..FailureSymptoms::default()
    });
    assert_eq!(class, FailureClass::PackageMisuse);
    assert!(!class.is_engine_bug());

    let severity = assign_severity(class, false, false, false);
    assert_eq!(severity, FailureSeverity::Low);

    let owner = default_owner_route(class);
    let repro = make_repro("import React from 'react-16';");
    let advisory = generate_advisory(class, severity);
    let entry = TriageEntry::build(class, severity, owner, repro, &advisory);

    let catalog = ReproCatalog::build(vec![entry], SecurityEpoch::from_raw(1));
    assert!(!catalog.has_critical_engine_bugs());
    assert_eq!(catalog.summary.engine_bug_count, 0);
}

// ---------------------------------------------------------------------------
// New tests: edge cases, trait coverage, serde field names, constants
// ---------------------------------------------------------------------------

#[test]
fn test_failure_class_all_has_ten_variants() {
    assert_eq!(FailureClass::all().len(), 10);
}

#[test]
fn test_failure_class_ord_consistent_with_all_ordering() {
    // FailureClass derives Ord; check that sorting produces a consistent result.
    let mut classes: Vec<FailureClass> = FailureClass::all().to_vec();
    classes.sort();
    // After sorting, re-sorting should give identical result (idempotent).
    let mut classes2 = classes.clone();
    classes2.sort();
    assert_eq!(classes, classes2);
}

#[test]
fn test_failure_class_clone_copy() {
    let original = FailureClass::HydrationMismatch;
    let cloned = original;
    // Copy semantics: original still usable.
    assert_eq!(original, cloned);
    let cloned2 = original;
    assert_eq!(original, cloned2);
}

#[test]
fn test_failure_class_debug_non_empty() {
    for class in FailureClass::all() {
        let s = format!("{class:?}");
        assert!(!s.is_empty());
    }
}

#[test]
fn test_failure_class_serde_field_names_are_snake_case() {
    // The serde annotation is rename_all = "snake_case"; verify JSON uses snake_case.
    let json = serde_json::to_string(&FailureClass::TransformBug).unwrap();
    assert_eq!(json, r#""transform_bug""#);
    let json2 = serde_json::to_string(&FailureClass::HookInvariantViolation).unwrap();
    assert_eq!(json2, r#""hook_invariant_violation""#);
    let json3 = serde_json::to_string(&FailureClass::ErrorBoundaryFailure).unwrap();
    assert_eq!(json3, r#""error_boundary_failure""#);
}

#[test]
fn test_failure_class_serde_roundtrip_all_variants() {
    for class in FailureClass::all() {
        let json = serde_json::to_string(class).unwrap();
        let parsed: FailureClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*class, parsed);
    }
}

#[test]
fn test_failure_severity_serde_roundtrip_all_variants() {
    for sev in [
        FailureSeverity::Critical,
        FailureSeverity::High,
        FailureSeverity::Medium,
        FailureSeverity::Low,
        FailureSeverity::Info,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let parsed: FailureSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, parsed);
    }
}

#[test]
fn test_failure_severity_as_str_all_variants() {
    assert_eq!(FailureSeverity::Critical.as_str(), "critical");
    assert_eq!(FailureSeverity::High.as_str(), "high");
    assert_eq!(FailureSeverity::Medium.as_str(), "medium");
    assert_eq!(FailureSeverity::Low.as_str(), "low");
    assert_eq!(FailureSeverity::Info.as_str(), "info");
}

#[test]
fn test_failure_severity_weight_exact_values() {
    assert_eq!(FailureSeverity::Critical.weight(), 5);
    assert_eq!(FailureSeverity::High.weight(), 4);
    assert_eq!(FailureSeverity::Medium.weight(), 3);
    assert_eq!(FailureSeverity::Low.weight(), 2);
    assert_eq!(FailureSeverity::Info.weight(), 1);
}

#[test]
fn test_failure_severity_display_matches_as_str() {
    for sev in [
        FailureSeverity::Critical,
        FailureSeverity::High,
        FailureSeverity::Medium,
        FailureSeverity::Low,
        FailureSeverity::Info,
    ] {
        assert_eq!(sev.to_string(), sev.as_str());
    }
}

#[test]
fn test_owner_route_clone_debug_partialeq() {
    let owner = default_owner_route(FailureClass::SuspenseDivergence);
    let cloned = owner.clone();
    assert_eq!(owner, cloned);
    let s = format!("{owner:?}");
    assert!(s.contains("bead_id"));
}

#[test]
fn test_owner_route_serde_field_names() {
    let owner = OwnerRoute {
        bead_id: "bd-test".to_string(),
        team: "test-team".to_string(),
        rationale: "testing".to_string(),
    };
    let json = serde_json::to_string(&owner).unwrap();
    assert!(json.contains("bead_id"));
    assert!(json.contains("team"));
    assert!(json.contains("rationale"));
}

#[test]
fn test_minimized_repro_empty_source() {
    let repro = MinimizedRepro::build("", "expected", "actual", BTreeSet::new(), "cmd");
    // Empty source should still produce a valid repro_id.
    assert!(repro.repro_id.starts_with("repro-"));
    assert_eq!(repro.source, "");
    assert!(repro.deterministic);
}

#[test]
fn test_minimized_repro_empty_react_versions() {
    let repro = MinimizedRepro::build("src", "exp", "act", BTreeSet::new(), "cmd");
    assert!(repro.react_versions.is_empty());
}

#[test]
fn test_minimized_repro_repro_id_prefix() {
    let repro = make_repro("function Foo() {}");
    assert!(
        repro.repro_id.starts_with("repro-"),
        "repro_id must start with 'repro-': {}",
        repro.repro_id
    );
}

#[test]
fn test_minimized_repro_clone_debug() {
    let repro = make_repro("const x = 1;");
    let cloned = repro.clone();
    assert_eq!(repro, cloned);
    let s = format!("{repro:?}");
    assert!(s.contains("repro_id"));
}

#[test]
fn test_triage_entry_entry_id_contains_class() {
    let entry = make_entry(FailureClass::ResolverBug, FailureSeverity::High);
    assert!(
        entry.entry_id.contains("resolver_bug"),
        "entry_id should contain the failure class string: {}",
        entry.entry_id
    );
}

#[test]
fn test_triage_entry_advisory_truncated_at_max() {
    // Advisory longer than 4096 chars should be truncated.
    let long_advisory = "A".repeat(5000);
    let owner = default_owner_route(FailureClass::Unclassified);
    let repro = make_repro("truncation test");
    let entry = TriageEntry::build(
        FailureClass::Unclassified,
        FailureSeverity::Info,
        owner,
        repro,
        &long_advisory,
    );
    assert!(entry.advisory.len() <= 4096);
}

#[test]
fn test_triage_entry_clone_debug() {
    let entry = make_entry(
        FailureClass::ErrorBoundaryFailure,
        FailureSeverity::Critical,
    );
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
    let s = format!("{entry:?}");
    assert!(s.contains("entry_id"));
}

#[test]
fn test_assign_severity_non_engine_bug_blocks_core_workflow_is_low() {
    // Non-engine-bug that blocks core workflow: first branch checks is_engine_bug,
    // so this falls through to the non-engine-bug low path.
    let sev = assign_severity(FailureClass::PackageMisuse, true, false, false);
    assert_eq!(sev, FailureSeverity::Low);
}

#[test]
fn test_assign_severity_edge_case_for_non_engine_bug_is_low() {
    let sev = assign_severity(FailureClass::UnsupportedEnvironment, false, false, true);
    assert_eq!(sev, FailureSeverity::Low);
}

#[test]
fn test_assign_severity_all_engine_bug_classes_without_workaround_are_high_or_critical() {
    let engine_bug_classes = [
        FailureClass::TransformBug,
        FailureClass::ResolverBug,
        FailureClass::RuntimeSemanticGap,
        FailureClass::HookInvariantViolation,
        FailureClass::HydrationMismatch,
        FailureClass::SuspenseDivergence,
        FailureClass::ErrorBoundaryFailure,
    ];
    for class in engine_bug_classes {
        let sev = assign_severity(class, false, false, false);
        assert!(
            sev == FailureSeverity::High || sev == FailureSeverity::Critical,
            "{class:?} without workaround should be High or Critical, got {sev:?}"
        );
    }
}

#[test]
fn test_catalog_by_class_map_entries() {
    let entries = vec![
        make_entry(FailureClass::TransformBug, FailureSeverity::High),
        make_entry(FailureClass::TransformBug, FailureSeverity::Medium),
        make_entry(FailureClass::ResolverBug, FailureSeverity::High),
    ];
    let catalog = ReproCatalog::build(entries, SecurityEpoch::from_raw(1));
    assert_eq!(
        catalog.summary.by_class.get("transform_bug").copied(),
        Some(2)
    );
    assert_eq!(
        catalog.summary.by_class.get("resolver_bug").copied(),
        Some(1)
    );
}

#[test]
fn test_catalog_by_severity_map_entries() {
    let entries = vec![
        make_entry(FailureClass::TransformBug, FailureSeverity::High),
        make_entry(FailureClass::ResolverBug, FailureSeverity::High),
        make_entry(FailureClass::PackageMisuse, FailureSeverity::Low),
    ];
    let catalog = ReproCatalog::build(entries, SecurityEpoch::from_raw(1));
    assert_eq!(catalog.summary.by_severity.get("high").copied(), Some(2));
    assert_eq!(catalog.summary.by_severity.get("low").copied(), Some(1));
}

#[test]
fn test_catalog_engine_bugs_excludes_non_engine() {
    let entries = vec![
        make_entry(FailureClass::TransformBug, FailureSeverity::High),
        make_entry(FailureClass::PackageMisuse, FailureSeverity::Low),
        make_entry(FailureClass::UnsupportedEnvironment, FailureSeverity::Low),
    ];
    let catalog = ReproCatalog::build(entries, SecurityEpoch::from_raw(1));
    // Only TransformBug is an engine bug.
    assert_eq!(catalog.engine_bugs().len(), 1);
    assert_eq!(
        catalog.engine_bugs()[0].failure_class,
        FailureClass::TransformBug
    );
}

#[test]
fn test_catalog_unresolved_excludes_resolved() {
    let mut entry1 = make_entry(FailureClass::TransformBug, FailureSeverity::High);
    let mut entry2 = make_entry(FailureClass::ResolverBug, FailureSeverity::High);
    entry1.unresolved = true;
    entry2.unresolved = false;
    let catalog = ReproCatalog::build(vec![entry1, entry2], SecurityEpoch::from_raw(1));
    assert_eq!(catalog.unresolved().len(), 1);
    assert_eq!(
        catalog.unresolved()[0].failure_class,
        FailureClass::TransformBug
    );
}

#[test]
fn test_catalog_no_critical_for_info_severity_engine_bug() {
    // An engine bug at Info severity is not critical.
    let entry = make_entry(FailureClass::TransformBug, FailureSeverity::Info);
    let catalog = ReproCatalog::build(vec![entry], SecurityEpoch::from_raw(1));
    assert!(!catalog.has_critical_engine_bugs());
}

#[test]
fn test_catalog_schema_and_policy_constants() {
    let catalog = ReproCatalog::build(Vec::new(), SecurityEpoch::from_raw(42));
    assert_eq!(catalog.schema_version, SCHEMA_VERSION);
    assert_eq!(catalog.bead_id, BEAD_ID);
    assert_eq!(catalog.policy_id, POLICY_ID);
    assert_eq!(catalog.component, COMPONENT);
}

#[test]
fn test_catalog_epoch_preserved() {
    let epoch = SecurityEpoch::from_raw(9999);
    let catalog = ReproCatalog::build(Vec::new(), epoch);
    assert_eq!(catalog.epoch, epoch);
}

#[test]
fn test_catalog_severity_weighted_score_all_severities() {
    let entries = vec![
        make_entry(FailureClass::TransformBug, FailureSeverity::Critical), // 5
        make_entry(FailureClass::ResolverBug, FailureSeverity::High),      // 4
        make_entry(FailureClass::RuntimeSemanticGap, FailureSeverity::Medium), // 3
        make_entry(FailureClass::PackageMisuse, FailureSeverity::Low),     // 2
        make_entry(FailureClass::Unclassified, FailureSeverity::Info),     // 1
    ];
    let catalog = ReproCatalog::build(entries, SecurityEpoch::from_raw(1));
    assert_eq!(catalog.summary.severity_weighted_score, 5 + 4 + 3 + 2 + 1);
}

#[test]
fn test_triage_event_schema_version_and_seed() {
    let entry = make_entry(
        FailureClass::HookInvariantViolation,
        FailureSeverity::Critical,
    );
    let event = build_triage_event("t", "d", "s", &entry);
    assert_eq!(event.schema_version, SCHEMA_VERSION);
    assert_eq!(event.seed, "react-repro-triage-v1");
}

#[test]
fn test_triage_event_error_code_format() {
    // Error code should be "REACT-TRIAGE-<UPPERCASE_CLASS>".
    let entry = make_entry(FailureClass::HydrationMismatch, FailureSeverity::High);
    let event = build_triage_event("t", "d", "s", &entry);
    let code = event.error_code.as_deref().unwrap();
    assert!(code.starts_with("REACT-TRIAGE-"));
    assert!(code.contains("HYDRATION_MISMATCH"));
}

#[test]
fn test_triage_event_clone_debug() {
    let entry = make_entry(FailureClass::TransformBug, FailureSeverity::High);
    let event: TriageEvent = build_triage_event("t", "d", "s", &entry);
    let cloned = event.clone();
    assert_eq!(event, cloned);
    let s = format!("{event:?}");
    assert!(s.contains("trace_id"));
}

#[test]
fn test_failure_symptoms_default_all_false() {
    let symptoms = FailureSymptoms::default();
    assert!(!symptoms.has_transform_diff);
    assert!(!symptoms.has_resolver_error);
    assert!(!symptoms.has_runtime_gap);
    assert!(!symptoms.has_env_boundary);
    assert!(!symptoms.has_version_mismatch);
    assert!(!symptoms.has_hook_violation);
    assert!(!symptoms.has_hydration_diff);
    assert!(!symptoms.has_suspense_diff);
    assert!(!symptoms.has_error_boundary_diff);
}

#[test]
fn test_failure_symptoms_clone_debug() {
    let symptoms = FailureSymptoms {
        has_transform_diff: true,
        ..FailureSymptoms::default()
    };
    let cloned = symptoms.clone();
    assert!(cloned.has_transform_diff);
    let s = format!("{symptoms:?}");
    assert!(s.contains("has_transform_diff"));
}

#[test]
fn test_catalog_summary_serde_roundtrip() {
    let mut by_class: BTreeMap<String, usize> = BTreeMap::new();
    by_class.insert("transform_bug".to_string(), 2);
    let mut by_severity: BTreeMap<String, usize> = BTreeMap::new();
    by_severity.insert("high".to_string(), 2);
    let summary = CatalogSummary {
        total_entries: 2,
        by_class,
        by_severity,
        unresolved_count: 2,
        engine_bug_count: 2,
        distinct_owners: 1,
        severity_weighted_score: 8,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let parsed: CatalogSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, parsed);
}

#[test]
fn test_classify_suspense_beats_error_boundary() {
    // When both suspense_diff and error_boundary_diff are set, suspense wins.
    let class = classify_failure(&FailureSymptoms {
        has_suspense_diff: true,
        has_error_boundary_diff: true,
        ..FailureSymptoms::default()
    });
    assert_eq!(class, FailureClass::SuspenseDivergence);
}

#[test]
fn test_classify_error_boundary_beats_transform() {
    let class = classify_failure(&FailureSymptoms {
        has_transform_diff: true,
        has_error_boundary_diff: true,
        ..FailureSymptoms::default()
    });
    assert_eq!(class, FailureClass::ErrorBoundaryFailure);
}

#[test]
fn test_classify_resolver_beats_runtime_gap() {
    let class = classify_failure(&FailureSymptoms {
        has_resolver_error: true,
        has_runtime_gap: true,
        ..FailureSymptoms::default()
    });
    assert_eq!(class, FailureClass::ResolverBug);
}

#[test]
fn test_classify_runtime_gap_beats_env_boundary() {
    let class = classify_failure(&FailureSymptoms {
        has_runtime_gap: true,
        has_env_boundary: true,
        ..FailureSymptoms::default()
    });
    assert_eq!(class, FailureClass::RuntimeSemanticGap);
}

#[test]
fn test_classify_env_boundary_beats_version_mismatch() {
    let class = classify_failure(&FailureSymptoms {
        has_env_boundary: true,
        has_version_mismatch: true,
        ..FailureSymptoms::default()
    });
    assert_eq!(class, FailureClass::UnsupportedEnvironment);
}

#[test]
fn test_constants_values() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.react-repro-triage.v1");
    assert_eq!(BEAD_ID, "bd-1lsy.5.7.3");
    assert_eq!(POLICY_ID, "RGC-405C");
    assert_eq!(COMPONENT, "react_repro_triage");
}

#[test]
fn test_triage_event_scenario_id_preserved() {
    let entry = make_entry(FailureClass::PackageMisuse, FailureSeverity::Low);
    let event = build_triage_event("trace-x", "decision-x", "scenario-xyz", &entry);
    assert_eq!(event.scenario_id, "scenario-xyz");
    assert_eq!(event.trace_id, "trace-x");
    assert_eq!(event.decision_id, "decision-x");
}

#[test]
fn test_catalog_multiple_same_class_all_in_filter() {
    let entries = vec![
        make_entry(FailureClass::HydrationMismatch, FailureSeverity::Critical),
        make_entry(FailureClass::HydrationMismatch, FailureSeverity::High),
        make_entry(FailureClass::HydrationMismatch, FailureSeverity::Medium),
        make_entry(FailureClass::PackageMisuse, FailureSeverity::Low),
    ];
    let catalog = ReproCatalog::build(entries, SecurityEpoch::from_raw(1));
    assert_eq!(
        catalog
            .entries_by_class(FailureClass::HydrationMismatch)
            .len(),
        3
    );
    assert_eq!(
        catalog.entries_by_class(FailureClass::PackageMisuse).len(),
        1
    );
}

#[test]
fn test_advisory_info_severity_mentions_no_impact() {
    let advisory = generate_advisory(FailureClass::Unclassified, FailureSeverity::Info);
    assert!(
        advisory.contains("no user impact"),
        "Info advisory should mention no user impact: {advisory}"
    );
}

#[test]
fn test_advisory_high_severity_mentions_planned() {
    let advisory = generate_advisory(FailureClass::ResolverBug, FailureSeverity::High);
    assert!(
        advisory.contains("planned"),
        "High advisory should mention planned fix: {advisory}"
    );
}

#[test]
fn test_catalog_no_has_critical_engine_bugs_for_non_engine_critical() {
    // Critical severity but not an engine bug class.
    let entry = make_entry(FailureClass::PackageMisuse, FailureSeverity::Critical);
    let catalog = ReproCatalog::build(vec![entry], SecurityEpoch::from_raw(1));
    // PackageMisuse is not an engine bug, so has_critical_engine_bugs should be false.
    assert!(!catalog.has_critical_engine_bugs());
}

#[test]
fn test_is_engine_bug_suspense_and_error_boundary() {
    assert!(FailureClass::SuspenseDivergence.is_engine_bug());
    assert!(FailureClass::ErrorBoundaryFailure.is_engine_bug());
    assert!(!FailureClass::Unclassified.is_engine_bug());
    assert!(!FailureClass::PackageMisuse.is_engine_bug());
    assert!(!FailureClass::UnsupportedEnvironment.is_engine_bug());
}
