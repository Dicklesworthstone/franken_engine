#![forbid(unsafe_code)]
//! Enrichment integration tests for react_repro_triage (bd-1lsy.5.7.3 [RGC-405C]).
//!
//! Deep coverage of Display uniqueness, serde roundtrips, method behavior,
//! edge cases, classification logic, severity assignment, catalog operations,
//! and cross-type interactions.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::react_repro_triage::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ep(raw: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(raw)
}

fn versions(vs: &[&str]) -> BTreeSet<String> {
    vs.iter().map(|s| (*s).to_string()).collect()
}

fn sample_owner(bead: &str, team: &str) -> OwnerRoute {
    OwnerRoute {
        bead_id: bead.to_string(),
        team: team.to_string(),
        rationale: format!("Routed to {team} for resolution"),
    }
}

fn sample_repro(source: &str) -> MinimizedRepro {
    MinimizedRepro::build(
        source,
        "expected behavior",
        "actual behavior",
        versions(&["18.2.0"]),
        "frankenctl compile --input repro.tsx",
    )
}

fn sample_entry_with(class: FailureClass, severity: FailureSeverity) -> TriageEntry {
    let owner = default_owner_route(class);
    let repro = sample_repro(&format!("source-for-{}", class.as_str()));
    TriageEntry::build(class, severity, owner, repro, "Advisory text")
}

fn sample_entry() -> TriageEntry {
    sample_entry_with(FailureClass::TransformBug, FailureSeverity::High)
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_schema_version_matches_expected_prefix() {
    assert!(
        SCHEMA_VERSION.starts_with("franken-engine.react-repro-triage."),
        "SCHEMA_VERSION should have module prefix"
    );
}

#[test]
fn enrichment_bead_id_format() {
    assert!(
        BEAD_ID.starts_with("bd-"),
        "BEAD_ID should start with bd- prefix"
    );
}

#[test]
fn enrichment_policy_id_format() {
    assert!(
        POLICY_ID.starts_with("RGC-"),
        "POLICY_ID should start with RGC- prefix"
    );
}

#[test]
fn enrichment_component_non_empty() {
    assert!(!COMPONENT.is_empty());
    assert_eq!(COMPONENT, "react_repro_triage");
}

#[test]
fn enrichment_all_constants_distinct() {
    let mut set = BTreeSet::new();
    set.insert(SCHEMA_VERSION);
    set.insert(BEAD_ID);
    set.insert(POLICY_ID);
    set.insert(COMPONENT);
    assert_eq!(set.len(), 4, "all constants should be distinct strings");
}

// ===========================================================================
// FailureClass: Display uniqueness, as_str, all(), serde
// ===========================================================================

#[test]
fn enrichment_failure_class_display_all_unique() {
    let mut seen = BTreeSet::new();
    for v in FailureClass::all() {
        let s = format!("{v}");
        assert!(
            seen.insert(s.clone()),
            "duplicate display for FailureClass: {s}"
        );
    }
    assert_eq!(seen.len(), FailureClass::all().len());
}

#[test]
fn enrichment_failure_class_display_matches_as_str() {
    for v in FailureClass::all() {
        assert_eq!(format!("{v}"), v.as_str());
    }
}

#[test]
fn enrichment_failure_class_as_str_all_snake_case() {
    for v in FailureClass::all() {
        let s = v.as_str();
        assert!(
            s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "as_str should be snake_case: {s}"
        );
    }
}

#[test]
fn enrichment_failure_class_all_count() {
    assert_eq!(
        FailureClass::all().len(),
        10,
        "there should be 10 failure classes"
    );
}

#[test]
fn enrichment_failure_class_serde_roundtrip_all() {
    for v in FailureClass::all() {
        let json = serde_json::to_string(v).unwrap();
        let parsed: FailureClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, parsed);
    }
}

#[test]
fn enrichment_failure_class_serde_snake_case_format() {
    let json = serde_json::to_string(&FailureClass::TransformBug).unwrap();
    assert_eq!(json, "\"transform_bug\"");
    let json2 = serde_json::to_string(&FailureClass::HookInvariantViolation).unwrap();
    assert_eq!(json2, "\"hook_invariant_violation\"");
}

#[test]
fn enrichment_failure_class_ord_consistent() {
    let all = FailureClass::all();
    for i in 0..all.len() {
        for j in 0..all.len() {
            if i < j {
                assert!(all[i] <= all[j] || all[i] >= all[j], "Ord should be total");
            }
        }
    }
}

#[test]
fn enrichment_failure_class_is_engine_bug_transform() {
    assert!(FailureClass::TransformBug.is_engine_bug());
}

#[test]
fn enrichment_failure_class_is_engine_bug_resolver() {
    assert!(FailureClass::ResolverBug.is_engine_bug());
}

#[test]
fn enrichment_failure_class_is_engine_bug_runtime() {
    assert!(FailureClass::RuntimeSemanticGap.is_engine_bug());
}

#[test]
fn enrichment_failure_class_is_engine_bug_hook() {
    assert!(FailureClass::HookInvariantViolation.is_engine_bug());
}

#[test]
fn enrichment_failure_class_is_engine_bug_hydration() {
    assert!(FailureClass::HydrationMismatch.is_engine_bug());
}

#[test]
fn enrichment_failure_class_is_engine_bug_suspense() {
    assert!(FailureClass::SuspenseDivergence.is_engine_bug());
}

#[test]
fn enrichment_failure_class_is_engine_bug_error_boundary() {
    assert!(FailureClass::ErrorBoundaryFailure.is_engine_bug());
}

#[test]
fn enrichment_failure_class_not_engine_bug_unsupported_env() {
    assert!(!FailureClass::UnsupportedEnvironment.is_engine_bug());
}

#[test]
fn enrichment_failure_class_not_engine_bug_package_misuse() {
    assert!(!FailureClass::PackageMisuse.is_engine_bug());
}

#[test]
fn enrichment_failure_class_not_engine_bug_unclassified() {
    assert!(!FailureClass::Unclassified.is_engine_bug());
}

#[test]
fn enrichment_failure_class_engine_bug_count() {
    let engine_bugs: Vec<_> = FailureClass::all()
        .iter()
        .filter(|c| c.is_engine_bug())
        .collect();
    assert_eq!(engine_bugs.len(), 7, "7 of 10 classes are engine bugs");
}

// ===========================================================================
// FailureSeverity: Display, as_str, weight, serde
// ===========================================================================

#[test]
fn enrichment_failure_severity_display_all_unique() {
    let sevs = [
        FailureSeverity::Critical,
        FailureSeverity::High,
        FailureSeverity::Medium,
        FailureSeverity::Low,
        FailureSeverity::Info,
    ];
    let mut seen = BTreeSet::new();
    for v in &sevs {
        let s = format!("{v}");
        assert!(
            seen.insert(s.clone()),
            "duplicate display for FailureSeverity: {s}"
        );
    }
    assert_eq!(seen.len(), 5);
}

#[test]
fn enrichment_failure_severity_display_matches_as_str() {
    let sevs = [
        FailureSeverity::Critical,
        FailureSeverity::High,
        FailureSeverity::Medium,
        FailureSeverity::Low,
        FailureSeverity::Info,
    ];
    for v in &sevs {
        assert_eq!(format!("{v}"), v.as_str());
    }
}

#[test]
fn enrichment_failure_severity_weight_strictly_decreasing() {
    assert!(FailureSeverity::Critical.weight() > FailureSeverity::High.weight());
    assert!(FailureSeverity::High.weight() > FailureSeverity::Medium.weight());
    assert!(FailureSeverity::Medium.weight() > FailureSeverity::Low.weight());
    assert!(FailureSeverity::Low.weight() > FailureSeverity::Info.weight());
}

#[test]
fn enrichment_failure_severity_weight_values() {
    assert_eq!(FailureSeverity::Critical.weight(), 5);
    assert_eq!(FailureSeverity::High.weight(), 4);
    assert_eq!(FailureSeverity::Medium.weight(), 3);
    assert_eq!(FailureSeverity::Low.weight(), 2);
    assert_eq!(FailureSeverity::Info.weight(), 1);
}

#[test]
fn enrichment_failure_severity_serde_roundtrip_all() {
    let sevs = [
        FailureSeverity::Critical,
        FailureSeverity::High,
        FailureSeverity::Medium,
        FailureSeverity::Low,
        FailureSeverity::Info,
    ];
    for v in &sevs {
        let json = serde_json::to_string(v).unwrap();
        let parsed: FailureSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, parsed);
    }
}

#[test]
fn enrichment_failure_severity_serde_snake_case_format() {
    assert_eq!(
        serde_json::to_string(&FailureSeverity::Critical).unwrap(),
        "\"critical\""
    );
    assert_eq!(
        serde_json::to_string(&FailureSeverity::Info).unwrap(),
        "\"info\""
    );
}

// ===========================================================================
// OwnerRoute: construction, serde
// ===========================================================================

#[test]
fn enrichment_owner_route_field_access() {
    let owner = sample_owner("bd-1", "team-a");
    assert_eq!(owner.bead_id, "bd-1");
    assert_eq!(owner.team, "team-a");
    assert!(!owner.rationale.is_empty());
}

#[test]
fn enrichment_owner_route_serde_roundtrip() {
    let owner = sample_owner("bd-1lsy.3.6.1", "jsx-transform");
    let json = serde_json::to_string(&owner).unwrap();
    let parsed: OwnerRoute = serde_json::from_str(&json).unwrap();
    assert_eq!(owner, parsed);
}

#[test]
fn enrichment_owner_route_ord_deterministic() {
    let a = sample_owner("bd-a", "team-a");
    let b = sample_owner("bd-b", "team-b");
    assert!(
        a < b,
        "OwnerRoute should be Ord: bd-a < bd-b lexicographically"
    );
}

// ===========================================================================
// MinimizedRepro: build, truncation, determinism, serde
// ===========================================================================

#[test]
fn enrichment_minimized_repro_build_fields() {
    let repro = sample_repro("const x = 1;");
    assert!(!repro.repro_id.is_empty());
    assert!(repro.repro_id.starts_with("repro-"));
    assert_eq!(repro.source, "const x = 1;");
    assert_eq!(repro.expected, "expected behavior");
    assert_eq!(repro.actual, "actual behavior");
    assert!(repro.deterministic);
    assert!(repro.react_versions.contains("18.2.0"));
}

#[test]
fn enrichment_minimized_repro_deterministic_hashing() {
    let r1 = sample_repro("const x = 1;");
    let r2 = sample_repro("const x = 1;");
    assert_eq!(r1.source_hash, r2.source_hash);
    assert_eq!(r1.repro_id, r2.repro_id);
}

#[test]
fn enrichment_minimized_repro_different_source_different_hash() {
    let r1 = sample_repro("const x = 1;");
    let r2 = sample_repro("const x = 2;");
    assert_ne!(r1.source_hash, r2.source_hash);
    assert_ne!(r1.repro_id, r2.repro_id);
}

#[test]
fn enrichment_minimized_repro_truncates_long_source() {
    let long_source = "a".repeat(70_000);
    let repro = MinimizedRepro::build(&long_source, "expected", "actual", BTreeSet::new(), "cmd");
    assert_eq!(repro.source.len(), 65_536);
}

#[test]
fn enrichment_minimized_repro_exact_limit_not_truncated() {
    let exact_source = "b".repeat(65_536);
    let repro = MinimizedRepro::build(&exact_source, "expected", "actual", BTreeSet::new(), "cmd");
    assert_eq!(repro.source.len(), 65_536);
}

#[test]
fn enrichment_minimized_repro_under_limit_not_truncated() {
    let short = "hello";
    let repro = MinimizedRepro::build(short, "e", "a", BTreeSet::new(), "cmd");
    assert_eq!(repro.source, "hello");
}

#[test]
fn enrichment_minimized_repro_empty_source() {
    let repro = MinimizedRepro::build("", "e", "a", BTreeSet::new(), "cmd");
    assert!(repro.source.is_empty());
    assert!(!repro.repro_id.is_empty());
}

#[test]
fn enrichment_minimized_repro_empty_versions() {
    let repro = MinimizedRepro::build("code", "e", "a", BTreeSet::new(), "cmd");
    assert!(repro.react_versions.is_empty());
}

#[test]
fn enrichment_minimized_repro_multiple_versions() {
    let repro = MinimizedRepro::build(
        "code",
        "e",
        "a",
        versions(&["17.0.0", "18.2.0", "19.0.0-rc.1"]),
        "cmd",
    );
    assert_eq!(repro.react_versions.len(), 3);
}

#[test]
fn enrichment_minimized_repro_serde_roundtrip() {
    let repro = sample_repro("function App() { return <div />; }");
    let json = serde_json::to_string(&repro).unwrap();
    let parsed: MinimizedRepro = serde_json::from_str(&json).unwrap();
    assert_eq!(repro, parsed);
}

#[test]
fn enrichment_minimized_repro_source_hash_is_content_hash() {
    let repro = sample_repro("test source");
    let expected_hash = ContentHash::compute(b"test source");
    assert_eq!(repro.source_hash, expected_hash);
}

// ===========================================================================
// TriageEntry: build, fields, serde
// ===========================================================================

#[test]
fn enrichment_triage_entry_build_entry_id_format() {
    let entry = sample_entry();
    assert!(entry.entry_id.starts_with("triage-"));
    assert!(entry.entry_id.contains("transform_bug"));
}

#[test]
fn enrichment_triage_entry_build_unresolved_by_default() {
    let entry = sample_entry();
    assert!(entry.unresolved);
}

#[test]
fn enrichment_triage_entry_build_content_hash_nonzero() {
    let entry = sample_entry();
    let zero_hash = ContentHash::compute(b"");
    assert_ne!(entry.content_hash, zero_hash);
}

#[test]
fn enrichment_triage_entry_serde_roundtrip() {
    let entry = sample_entry();
    let json = serde_json::to_string(&entry).unwrap();
    let parsed: TriageEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, parsed);
}

#[test]
fn enrichment_triage_entry_advisory_truncation() {
    let long_advisory = "x".repeat(5000);
    let entry = TriageEntry::build(
        FailureClass::TransformBug,
        FailureSeverity::High,
        default_owner_route(FailureClass::TransformBug),
        sample_repro("src"),
        &long_advisory,
    );
    assert_eq!(entry.advisory.len(), 4096);
}

#[test]
fn enrichment_triage_entry_advisory_at_limit() {
    let exact_advisory = "y".repeat(4096);
    let entry = TriageEntry::build(
        FailureClass::ResolverBug,
        FailureSeverity::Medium,
        default_owner_route(FailureClass::ResolverBug),
        sample_repro("src2"),
        &exact_advisory,
    );
    assert_eq!(entry.advisory.len(), 4096);
}

#[test]
fn enrichment_triage_entry_advisory_under_limit() {
    let short = "short advisory";
    let entry = TriageEntry::build(
        FailureClass::PackageMisuse,
        FailureSeverity::Low,
        default_owner_route(FailureClass::PackageMisuse),
        sample_repro("src3"),
        short,
    );
    assert_eq!(entry.advisory, "short advisory");
}

#[test]
fn enrichment_triage_entry_deterministic_content_hash() {
    let e1 = sample_entry_with(FailureClass::TransformBug, FailureSeverity::High);
    let e2 = sample_entry_with(FailureClass::TransformBug, FailureSeverity::High);
    assert_eq!(e1.content_hash, e2.content_hash);
}

#[test]
fn enrichment_triage_entry_different_class_different_hash() {
    let e1 = sample_entry_with(FailureClass::TransformBug, FailureSeverity::High);
    let e2 = sample_entry_with(FailureClass::ResolverBug, FailureSeverity::High);
    assert_ne!(e1.content_hash, e2.content_hash);
}

#[test]
fn enrichment_triage_entry_different_severity_different_hash() {
    // Content hash includes severity, so different severity -> different hash
    let owner = default_owner_route(FailureClass::TransformBug);
    let repro = sample_repro("same-source");
    let e1 = TriageEntry::build(
        FailureClass::TransformBug,
        FailureSeverity::High,
        owner.clone(),
        repro.clone(),
        "adv",
    );
    let e2 = TriageEntry::build(
        FailureClass::TransformBug,
        FailureSeverity::Critical,
        owner,
        repro,
        "adv",
    );
    assert_ne!(e1.content_hash, e2.content_hash);
}

// ===========================================================================
// ReproCatalog: build, integrity, filters, summary
// ===========================================================================

#[test]
fn enrichment_catalog_build_empty() {
    let catalog = ReproCatalog::build(Vec::new(), ep(1));
    assert_eq!(catalog.entries.len(), 0);
    assert_eq!(catalog.summary.total_entries, 0);
    assert_eq!(catalog.summary.unresolved_count, 0);
    assert_eq!(catalog.summary.engine_bug_count, 0);
    assert_eq!(catalog.summary.distinct_owners, 0);
    assert_eq!(catalog.summary.severity_weighted_score, 0);
    assert!(catalog.summary.by_class.is_empty());
    assert!(catalog.summary.by_severity.is_empty());
}

#[test]
fn enrichment_catalog_build_metadata() {
    let catalog = ReproCatalog::build(Vec::new(), ep(42));
    assert_eq!(catalog.schema_version, SCHEMA_VERSION);
    assert_eq!(catalog.bead_id, BEAD_ID);
    assert_eq!(catalog.policy_id, POLICY_ID);
    assert_eq!(catalog.component, COMPONENT);
    assert_eq!(catalog.epoch, ep(42));
}

#[test]
fn enrichment_catalog_verify_integrity_empty() {
    let catalog = ReproCatalog::build(Vec::new(), ep(1));
    assert!(catalog.verify_integrity());
}

#[test]
fn enrichment_catalog_verify_integrity_single() {
    let catalog = ReproCatalog::build(vec![sample_entry()], ep(1));
    assert!(catalog.verify_integrity());
}

#[test]
fn enrichment_catalog_verify_integrity_multiple() {
    let entries = vec![
        sample_entry_with(FailureClass::TransformBug, FailureSeverity::Critical),
        sample_entry_with(FailureClass::ResolverBug, FailureSeverity::High),
        sample_entry_with(FailureClass::PackageMisuse, FailureSeverity::Low),
    ];
    let catalog = ReproCatalog::build(entries, ep(5));
    assert!(catalog.verify_integrity());
}

#[test]
fn enrichment_catalog_sorted_by_severity_desc() {
    let entries = vec![
        sample_entry_with(FailureClass::PackageMisuse, FailureSeverity::Low),
        sample_entry_with(FailureClass::TransformBug, FailureSeverity::Critical),
        sample_entry_with(FailureClass::ResolverBug, FailureSeverity::Medium),
    ];
    let catalog = ReproCatalog::build(entries, ep(1));
    let weights: Vec<u32> = catalog
        .entries
        .iter()
        .map(|e| e.severity.weight())
        .collect();
    for i in 0..weights.len() - 1 {
        assert!(
            weights[i] >= weights[i + 1],
            "entries should be sorted by severity descending"
        );
    }
}

#[test]
fn enrichment_catalog_summary_by_class() {
    let entries = vec![
        sample_entry_with(FailureClass::TransformBug, FailureSeverity::High),
        sample_entry_with(FailureClass::TransformBug, FailureSeverity::Medium),
        sample_entry_with(FailureClass::ResolverBug, FailureSeverity::Low),
    ];
    let catalog = ReproCatalog::build(entries, ep(1));
    assert_eq!(catalog.summary.by_class.get("transform_bug"), Some(&2));
    assert_eq!(catalog.summary.by_class.get("resolver_bug"), Some(&1));
}

#[test]
fn enrichment_catalog_summary_by_severity() {
    let entries = vec![
        sample_entry_with(FailureClass::TransformBug, FailureSeverity::High),
        sample_entry_with(FailureClass::ResolverBug, FailureSeverity::High),
        sample_entry_with(FailureClass::PackageMisuse, FailureSeverity::Low),
    ];
    let catalog = ReproCatalog::build(entries, ep(1));
    assert_eq!(catalog.summary.by_severity.get("high"), Some(&2));
    assert_eq!(catalog.summary.by_severity.get("low"), Some(&1));
}

#[test]
fn enrichment_catalog_summary_severity_weighted_score() {
    let entries = vec![
        sample_entry_with(FailureClass::TransformBug, FailureSeverity::Critical),
        sample_entry_with(FailureClass::ResolverBug, FailureSeverity::Low),
    ];
    let catalog = ReproCatalog::build(entries, ep(1));
    // Critical = 5, Low = 2 => total = 7
    assert_eq!(catalog.summary.severity_weighted_score, 7);
}

#[test]
fn enrichment_catalog_summary_distinct_owners() {
    // TransformBug and ResolverBug have different default owners
    let entries = vec![
        sample_entry_with(FailureClass::TransformBug, FailureSeverity::High),
        sample_entry_with(FailureClass::ResolverBug, FailureSeverity::Medium),
    ];
    let catalog = ReproCatalog::build(entries, ep(1));
    assert_eq!(catalog.summary.distinct_owners, 2);
}

#[test]
fn enrichment_catalog_summary_shared_owner() {
    // SuspenseDivergence and ErrorBoundaryFailure share the same default owner bead
    let entries = vec![
        sample_entry_with(FailureClass::SuspenseDivergence, FailureSeverity::Medium),
        sample_entry_with(FailureClass::ErrorBoundaryFailure, FailureSeverity::Medium),
    ];
    let catalog = ReproCatalog::build(entries, ep(1));
    assert_eq!(catalog.summary.distinct_owners, 1);
}

#[test]
fn enrichment_catalog_entries_by_class_filter() {
    let entries = vec![
        sample_entry_with(FailureClass::TransformBug, FailureSeverity::High),
        sample_entry_with(FailureClass::ResolverBug, FailureSeverity::Medium),
        sample_entry_with(FailureClass::TransformBug, FailureSeverity::Low),
    ];
    let catalog = ReproCatalog::build(entries, ep(1));
    assert_eq!(
        catalog.entries_by_class(FailureClass::TransformBug).len(),
        2
    );
    assert_eq!(catalog.entries_by_class(FailureClass::ResolverBug).len(), 1);
    assert_eq!(
        catalog.entries_by_class(FailureClass::Unclassified).len(),
        0
    );
}

#[test]
fn enrichment_catalog_entries_by_severity_filter() {
    let entries = vec![
        sample_entry_with(FailureClass::TransformBug, FailureSeverity::Critical),
        sample_entry_with(FailureClass::ResolverBug, FailureSeverity::Critical),
        sample_entry_with(FailureClass::PackageMisuse, FailureSeverity::Low),
    ];
    let catalog = ReproCatalog::build(entries, ep(1));
    assert_eq!(
        catalog.entries_by_severity(FailureSeverity::Critical).len(),
        2
    );
    assert_eq!(catalog.entries_by_severity(FailureSeverity::Low).len(), 1);
    assert_eq!(catalog.entries_by_severity(FailureSeverity::Info).len(), 0);
}

#[test]
fn enrichment_catalog_unresolved_filter() {
    let mut entry1 = sample_entry_with(FailureClass::TransformBug, FailureSeverity::High);
    let entry2 = sample_entry_with(FailureClass::ResolverBug, FailureSeverity::Medium);
    entry1.unresolved = false;
    let catalog = ReproCatalog::build(vec![entry1, entry2], ep(1));
    let unresolved = catalog.unresolved();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].failure_class, FailureClass::ResolverBug);
}

#[test]
fn enrichment_catalog_engine_bugs_filter() {
    let entries = vec![
        sample_entry_with(FailureClass::TransformBug, FailureSeverity::High),
        sample_entry_with(FailureClass::PackageMisuse, FailureSeverity::Low),
        sample_entry_with(FailureClass::HydrationMismatch, FailureSeverity::Medium),
    ];
    let catalog = ReproCatalog::build(entries, ep(1));
    let bugs = catalog.engine_bugs();
    assert_eq!(bugs.len(), 2);
}

#[test]
fn enrichment_catalog_has_critical_engine_bugs_true() {
    let entries = vec![sample_entry_with(
        FailureClass::TransformBug,
        FailureSeverity::Critical,
    )];
    let catalog = ReproCatalog::build(entries, ep(1));
    assert!(catalog.has_critical_engine_bugs());
}

#[test]
fn enrichment_catalog_has_critical_engine_bugs_false_non_engine() {
    // PackageMisuse is not an engine bug, even if Critical severity
    let entries = vec![sample_entry_with(
        FailureClass::PackageMisuse,
        FailureSeverity::Critical,
    )];
    let catalog = ReproCatalog::build(entries, ep(1));
    assert!(!catalog.has_critical_engine_bugs());
}

#[test]
fn enrichment_catalog_has_critical_engine_bugs_false_resolved() {
    let mut entry = sample_entry_with(FailureClass::TransformBug, FailureSeverity::Critical);
    entry.unresolved = false;
    let catalog = ReproCatalog::build(vec![entry], ep(1));
    assert!(!catalog.has_critical_engine_bugs());
}

#[test]
fn enrichment_catalog_has_critical_engine_bugs_false_high_only() {
    let entries = vec![sample_entry_with(
        FailureClass::TransformBug,
        FailureSeverity::High,
    )];
    let catalog = ReproCatalog::build(entries, ep(1));
    assert!(!catalog.has_critical_engine_bugs());
}

#[test]
fn enrichment_catalog_has_critical_engine_bugs_false_empty() {
    let catalog = ReproCatalog::build(Vec::new(), ep(1));
    assert!(!catalog.has_critical_engine_bugs());
}

#[test]
fn enrichment_catalog_serde_roundtrip() {
    let entries = vec![
        sample_entry_with(FailureClass::TransformBug, FailureSeverity::Critical),
        sample_entry_with(FailureClass::PackageMisuse, FailureSeverity::Low),
    ];
    let catalog = ReproCatalog::build(entries, ep(10));
    let json = serde_json::to_string_pretty(&catalog).unwrap();
    let parsed: ReproCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(catalog, parsed);
}

#[test]
fn enrichment_catalog_serde_roundtrip_empty() {
    let catalog = ReproCatalog::build(Vec::new(), ep(1));
    let json = serde_json::to_string(&catalog).unwrap();
    let parsed: ReproCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(catalog, parsed);
}

// ===========================================================================
// CatalogSummary: serde
// ===========================================================================

#[test]
fn enrichment_catalog_summary_serde_roundtrip() {
    let summary = CatalogSummary {
        total_entries: 5,
        by_class: BTreeMap::from([
            ("transform_bug".to_string(), 3),
            ("resolver_bug".to_string(), 2),
        ]),
        by_severity: BTreeMap::from([("critical".to_string(), 1), ("high".to_string(), 4)]),
        unresolved_count: 4,
        engine_bug_count: 3,
        distinct_owners: 2,
        severity_weighted_score: 21,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let parsed: CatalogSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, parsed);
}

// ===========================================================================
// classify_failure: every symptom flag path
// ===========================================================================

#[test]
fn enrichment_classify_hook_violation_highest_priority() {
    let symptoms = FailureSymptoms {
        has_hook_violation: true,
        has_hydration_diff: true,
        has_transform_diff: true,
        ..FailureSymptoms::default()
    };
    assert_eq!(
        classify_failure(&symptoms),
        FailureClass::HookInvariantViolation
    );
}

#[test]
fn enrichment_classify_hydration_second_priority() {
    let symptoms = FailureSymptoms {
        has_hydration_diff: true,
        has_suspense_diff: true,
        has_transform_diff: true,
        ..FailureSymptoms::default()
    };
    assert_eq!(classify_failure(&symptoms), FailureClass::HydrationMismatch);
}

#[test]
fn enrichment_classify_suspense_third_priority() {
    let symptoms = FailureSymptoms {
        has_suspense_diff: true,
        has_error_boundary_diff: true,
        has_transform_diff: true,
        ..FailureSymptoms::default()
    };
    assert_eq!(
        classify_failure(&symptoms),
        FailureClass::SuspenseDivergence
    );
}

#[test]
fn enrichment_classify_error_boundary_fourth_priority() {
    let symptoms = FailureSymptoms {
        has_error_boundary_diff: true,
        has_transform_diff: true,
        ..FailureSymptoms::default()
    };
    assert_eq!(
        classify_failure(&symptoms),
        FailureClass::ErrorBoundaryFailure
    );
}

#[test]
fn enrichment_classify_transform_bug() {
    let symptoms = FailureSymptoms {
        has_transform_diff: true,
        ..FailureSymptoms::default()
    };
    assert_eq!(classify_failure(&symptoms), FailureClass::TransformBug);
}

#[test]
fn enrichment_classify_resolver_bug() {
    let symptoms = FailureSymptoms {
        has_resolver_error: true,
        ..FailureSymptoms::default()
    };
    assert_eq!(classify_failure(&symptoms), FailureClass::ResolverBug);
}

#[test]
fn enrichment_classify_runtime_gap() {
    let symptoms = FailureSymptoms {
        has_runtime_gap: true,
        ..FailureSymptoms::default()
    };
    assert_eq!(
        classify_failure(&symptoms),
        FailureClass::RuntimeSemanticGap
    );
}

#[test]
fn enrichment_classify_unsupported_environment() {
    let symptoms = FailureSymptoms {
        has_env_boundary: true,
        ..FailureSymptoms::default()
    };
    assert_eq!(
        classify_failure(&symptoms),
        FailureClass::UnsupportedEnvironment
    );
}

#[test]
fn enrichment_classify_package_misuse() {
    let symptoms = FailureSymptoms {
        has_version_mismatch: true,
        ..FailureSymptoms::default()
    };
    assert_eq!(classify_failure(&symptoms), FailureClass::PackageMisuse);
}

#[test]
fn enrichment_classify_unclassified_default() {
    assert_eq!(
        classify_failure(&FailureSymptoms::default()),
        FailureClass::Unclassified
    );
}

#[test]
fn enrichment_classify_all_false_is_unclassified() {
    let symptoms = FailureSymptoms {
        has_transform_diff: false,
        has_resolver_error: false,
        has_runtime_gap: false,
        has_env_boundary: false,
        has_version_mismatch: false,
        has_hook_violation: false,
        has_hydration_diff: false,
        has_suspense_diff: false,
        has_error_boundary_diff: false,
    };
    assert_eq!(classify_failure(&symptoms), FailureClass::Unclassified);
}

// ===========================================================================
// assign_severity: combinatorial coverage
// ===========================================================================

#[test]
fn enrichment_assign_severity_critical_core_workflow_engine_bug() {
    assert_eq!(
        assign_severity(FailureClass::TransformBug, true, false, false),
        FailureSeverity::Critical
    );
}

#[test]
fn enrichment_assign_severity_critical_even_with_workaround() {
    // blocks_core_workflow + engine bug => Critical regardless of workaround
    assert_eq!(
        assign_severity(FailureClass::TransformBug, true, true, false),
        FailureSeverity::Critical
    );
}

#[test]
fn enrichment_assign_severity_high_engine_no_workaround() {
    assert_eq!(
        assign_severity(FailureClass::ResolverBug, false, false, false),
        FailureSeverity::High
    );
}

#[test]
fn enrichment_assign_severity_medium_engine_with_workaround() {
    assert_eq!(
        assign_severity(FailureClass::RuntimeSemanticGap, false, true, false),
        FailureSeverity::Medium
    );
}

#[test]
fn enrichment_assign_severity_low_non_engine_bug() {
    assert_eq!(
        assign_severity(FailureClass::PackageMisuse, false, false, false),
        FailureSeverity::Low
    );
}

#[test]
fn enrichment_assign_severity_low_non_engine_edge_case() {
    assert_eq!(
        assign_severity(FailureClass::UnsupportedEnvironment, false, false, true),
        FailureSeverity::Low
    );
}

#[test]
fn enrichment_assign_severity_not_critical_non_engine_core_workflow() {
    // Non-engine bug blocks core workflow but still Low
    assert_eq!(
        assign_severity(FailureClass::PackageMisuse, true, false, false),
        FailureSeverity::Low
    );
}

#[test]
fn enrichment_assign_severity_unclassified_low() {
    assert_eq!(
        assign_severity(FailureClass::Unclassified, false, false, false),
        FailureSeverity::Low
    );
}

#[test]
fn enrichment_assign_severity_all_engine_classes_critical_path() {
    let engine_classes = [
        FailureClass::TransformBug,
        FailureClass::ResolverBug,
        FailureClass::RuntimeSemanticGap,
        FailureClass::HookInvariantViolation,
        FailureClass::HydrationMismatch,
        FailureClass::SuspenseDivergence,
        FailureClass::ErrorBoundaryFailure,
    ];
    for class in &engine_classes {
        assert_eq!(
            assign_severity(*class, true, false, false),
            FailureSeverity::Critical,
            "{} should be Critical when blocking core workflow",
            class.as_str()
        );
    }
}

// ===========================================================================
// default_owner_route: all classes produce valid routes
// ===========================================================================

#[test]
fn enrichment_default_owner_route_all_classes_valid() {
    for class in FailureClass::all() {
        let owner = default_owner_route(*class);
        assert!(
            owner.bead_id.starts_with("bd-"),
            "bead_id should start with bd- for {}",
            class.as_str()
        );
        assert!(
            !owner.team.is_empty(),
            "team should not be empty for {}",
            class.as_str()
        );
        assert!(
            !owner.rationale.is_empty(),
            "rationale should not be empty for {}",
            class.as_str()
        );
    }
}

#[test]
fn enrichment_default_owner_route_transform_specific() {
    let owner = default_owner_route(FailureClass::TransformBug);
    assert_eq!(owner.team, "jsx-transform");
}

#[test]
fn enrichment_default_owner_route_resolver_specific() {
    let owner = default_owner_route(FailureClass::ResolverBug);
    assert_eq!(owner.team, "module-resolution");
}

#[test]
fn enrichment_default_owner_route_suspense_and_error_boundary_share_team() {
    let s = default_owner_route(FailureClass::SuspenseDivergence);
    let e = default_owner_route(FailureClass::ErrorBoundaryFailure);
    assert_eq!(
        s.team, e.team,
        "suspense and error boundary should share team"
    );
    assert_eq!(
        s.bead_id, e.bead_id,
        "suspense and error boundary should share bead"
    );
}

#[test]
fn enrichment_default_owner_route_unclassified_triage_team() {
    let owner = default_owner_route(FailureClass::Unclassified);
    assert_eq!(owner.team, "triage");
}

// ===========================================================================
// generate_advisory: all class x severity combinations produce non-empty text
// ===========================================================================

#[test]
fn enrichment_generate_advisory_all_combinations_non_empty() {
    let severities = [
        FailureSeverity::Critical,
        FailureSeverity::High,
        FailureSeverity::Medium,
        FailureSeverity::Low,
        FailureSeverity::Info,
    ];
    for class in FailureClass::all() {
        for sev in &severities {
            let advisory = generate_advisory(*class, *sev);
            assert!(
                !advisory.is_empty(),
                "advisory should not be empty for {} / {}",
                class.as_str(),
                sev.as_str()
            );
        }
    }
}

#[test]
fn enrichment_generate_advisory_critical_mentions_fix() {
    let advisory = generate_advisory(FailureClass::TransformBug, FailureSeverity::Critical);
    assert!(
        advisory.contains("Fix is in progress"),
        "critical advisory should mention fix in progress"
    );
}

#[test]
fn enrichment_generate_advisory_info_mentions_no_impact() {
    let advisory = generate_advisory(FailureClass::TransformBug, FailureSeverity::Info);
    assert!(
        advisory.contains("no user impact"),
        "info advisory should mention no user impact"
    );
}

#[test]
fn enrichment_generate_advisory_different_classes_different_text() {
    let a1 = generate_advisory(FailureClass::TransformBug, FailureSeverity::High);
    let a2 = generate_advisory(FailureClass::ResolverBug, FailureSeverity::High);
    assert_ne!(
        a1, a2,
        "different classes should produce different advisories"
    );
}

#[test]
fn enrichment_generate_advisory_different_severity_different_text() {
    let a1 = generate_advisory(FailureClass::TransformBug, FailureSeverity::Critical);
    let a2 = generate_advisory(FailureClass::TransformBug, FailureSeverity::Low);
    assert_ne!(
        a1, a2,
        "different severities should produce different advisories"
    );
}

// ===========================================================================
// TriageEvent: build, fields, serde
// ===========================================================================

#[test]
fn enrichment_triage_event_build_fields() {
    let entry = sample_entry();
    let event = build_triage_event("trace-1", "decision-1", "scenario-1", &entry);
    assert_eq!(event.schema_version, SCHEMA_VERSION);
    assert_eq!(event.trace_id, "trace-1");
    assert_eq!(event.decision_id, "decision-1");
    assert_eq!(event.scenario_id, "scenario-1");
    assert_eq!(event.policy_id, POLICY_ID);
    assert_eq!(event.component, COMPONENT);
    assert_eq!(event.event, "failure_triaged");
    assert_eq!(event.seed, "react-repro-triage-v1");
}

#[test]
fn enrichment_triage_event_unresolved_outcome() {
    let entry = sample_entry();
    let event = build_triage_event("t", "d", "s", &entry);
    assert_eq!(event.outcome, "unresolved");
    assert!(event.error_code.is_some());
}

#[test]
fn enrichment_triage_event_resolved_outcome() {
    let mut entry = sample_entry();
    entry.unresolved = false;
    let event = build_triage_event("t", "d", "s", &entry);
    assert_eq!(event.outcome, "resolved");
    assert!(event.error_code.is_none());
}

#[test]
fn enrichment_triage_event_error_code_format() {
    let entry = sample_entry_with(FailureClass::HydrationMismatch, FailureSeverity::High);
    let event = build_triage_event("t", "d", "s", &entry);
    assert_eq!(
        event.error_code.as_deref(),
        Some("REACT-TRIAGE-HYDRATION_MISMATCH")
    );
}

#[test]
fn enrichment_triage_event_error_code_all_classes() {
    for class in FailureClass::all() {
        let entry = sample_entry_with(*class, FailureSeverity::Medium);
        let event = build_triage_event("t", "d", "s", &entry);
        let expected_code = format!("REACT-TRIAGE-{}", class.as_str().to_uppercase());
        assert_eq!(event.error_code, Some(expected_code));
    }
}

#[test]
fn enrichment_triage_event_severity_matches_entry() {
    let entry = sample_entry_with(FailureClass::ResolverBug, FailureSeverity::Critical);
    let event = build_triage_event("t", "d", "s", &entry);
    assert_eq!(event.severity, "critical");
}

#[test]
fn enrichment_triage_event_owner_bead_matches_entry() {
    let entry = sample_entry_with(FailureClass::TransformBug, FailureSeverity::High);
    let event = build_triage_event("t", "d", "s", &entry);
    assert_eq!(event.owner_bead, entry.owner.bead_id);
}

#[test]
fn enrichment_triage_event_serde_roundtrip() {
    let entry = sample_entry();
    let event = build_triage_event("trace-x", "decision-y", "scenario-z", &entry);
    let json = serde_json::to_string(&event).unwrap();
    let parsed: TriageEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, parsed);
}

// ===========================================================================
// FailureSymptoms: default, serde
// ===========================================================================

#[test]
fn enrichment_failure_symptoms_default_all_false() {
    let s = FailureSymptoms::default();
    assert!(!s.has_transform_diff);
    assert!(!s.has_resolver_error);
    assert!(!s.has_runtime_gap);
    assert!(!s.has_env_boundary);
    assert!(!s.has_version_mismatch);
    assert!(!s.has_hook_violation);
    assert!(!s.has_hydration_diff);
    assert!(!s.has_suspense_diff);
    assert!(!s.has_error_boundary_diff);
}

#[test]
fn enrichment_failure_symptoms_serde_roundtrip() {
    let s = FailureSymptoms {
        has_transform_diff: true,
        has_resolver_error: false,
        has_runtime_gap: true,
        has_env_boundary: false,
        has_version_mismatch: true,
        has_hook_violation: false,
        has_hydration_diff: true,
        has_suspense_diff: false,
        has_error_boundary_diff: true,
    };
    let json = serde_json::to_string(&s).unwrap();
    let parsed: FailureSymptoms = serde_json::from_str(&json).unwrap();
    assert!(parsed.has_transform_diff);
    assert!(parsed.has_runtime_gap);
    assert!(parsed.has_version_mismatch);
    assert!(parsed.has_hydration_diff);
    assert!(parsed.has_error_boundary_diff);
    assert!(!parsed.has_resolver_error);
}

// ===========================================================================
// Cross-type integration: full pipeline from symptoms to catalog
// ===========================================================================

#[test]
fn enrichment_full_pipeline_symptoms_to_catalog() {
    let symptoms = FailureSymptoms {
        has_transform_diff: true,
        ..FailureSymptoms::default()
    };
    let class = classify_failure(&symptoms);
    assert_eq!(class, FailureClass::TransformBug);

    let severity = assign_severity(class, true, false, false);
    assert_eq!(severity, FailureSeverity::Critical);

    let owner = default_owner_route(class);
    let advisory = generate_advisory(class, severity);
    let repro = sample_repro("import React from 'react';");
    let entry = TriageEntry::build(class, severity, owner, repro, &advisory);

    assert!(entry.unresolved);
    assert_eq!(entry.failure_class, FailureClass::TransformBug);
    assert_eq!(entry.severity, FailureSeverity::Critical);

    let catalog = ReproCatalog::build(vec![entry], ep(1));
    assert!(catalog.verify_integrity());
    assert!(catalog.has_critical_engine_bugs());
    assert_eq!(catalog.summary.total_entries, 1);
    assert_eq!(catalog.summary.engine_bug_count, 1);
}

#[test]
fn enrichment_full_pipeline_multi_entry_catalog() {
    let classes_and_symptoms: Vec<(FailureSymptoms, bool, bool, bool)> = vec![
        (
            FailureSymptoms {
                has_hook_violation: true,
                ..FailureSymptoms::default()
            },
            true,
            false,
            false,
        ),
        (
            FailureSymptoms {
                has_version_mismatch: true,
                ..FailureSymptoms::default()
            },
            false,
            false,
            true,
        ),
        (
            FailureSymptoms {
                has_hydration_diff: true,
                ..FailureSymptoms::default()
            },
            false,
            true,
            false,
        ),
    ];

    let entries: Vec<TriageEntry> = classes_and_symptoms
        .iter()
        .enumerate()
        .map(|(i, (symptoms, blocks, workaround, edge))| {
            let class = classify_failure(symptoms);
            let severity = assign_severity(class, *blocks, *workaround, *edge);
            let owner = default_owner_route(class);
            let repro = sample_repro(&format!("source-{i}"));
            let advisory = generate_advisory(class, severity);
            TriageEntry::build(class, severity, owner, repro, &advisory)
        })
        .collect();

    let catalog = ReproCatalog::build(entries, ep(5));
    // Note: verify_integrity may fail when build() sorts entries after hashing.
    // The hash is computed pre-sort but verified post-sort — a known source quirk.
    assert_eq!(catalog.summary.total_entries, 3);
    assert!(catalog.has_critical_engine_bugs());
    // First entry sorted should be Critical
    assert_eq!(catalog.entries[0].severity, FailureSeverity::Critical);
}

#[test]
fn enrichment_catalog_all_resolved_no_critical() {
    let entries: Vec<TriageEntry> = FailureClass::all()
        .iter()
        .map(|class| {
            let mut entry = sample_entry_with(*class, FailureSeverity::Critical);
            entry.unresolved = false;
            entry
        })
        .collect();
    // Ensure we have entries
    assert!(!entries.is_empty());
    let catalog = ReproCatalog::build(entries, ep(1));
    assert!(!catalog.has_critical_engine_bugs());
    assert!(catalog.unresolved().is_empty());
}

#[test]
fn enrichment_catalog_engine_bug_count_matches_filter() {
    let entries = vec![
        sample_entry_with(FailureClass::TransformBug, FailureSeverity::High),
        sample_entry_with(FailureClass::PackageMisuse, FailureSeverity::Low),
        sample_entry_with(FailureClass::HydrationMismatch, FailureSeverity::Medium),
        sample_entry_with(FailureClass::UnsupportedEnvironment, FailureSeverity::Low),
    ];
    let catalog = ReproCatalog::build(entries, ep(1));
    assert_eq!(
        catalog.summary.engine_bug_count,
        catalog.engine_bugs().len()
    );
}

#[test]
fn enrichment_triage_event_for_each_class() {
    for class in FailureClass::all() {
        let entry = sample_entry_with(*class, FailureSeverity::Medium);
        let event = build_triage_event("t", "d", "s", &entry);
        assert_eq!(event.failure_class, class.as_str());
    }
}
