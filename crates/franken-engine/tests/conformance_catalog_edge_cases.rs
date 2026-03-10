//! Edge-case integration tests for `conformance_catalog`.
//!
//! The inline unit tests (~70) cover basic functionality. These tests target
//! boundary conditions, exhaustive variant coverage, ordering invariants,
//! serde round-trips for every struct/enum, and multi-step integration
//! scenarios not reachable from a single inline test.

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

use frankenengine_engine::conformance_catalog::*;
use frankenengine_engine::cross_repo_contract::RegressionClass;

// ── helpers ────────────────────────────────────────────────────────────────

fn make_surface(
    sibling: SiblingRepo,
    id: &str,
    kind: SurfaceKind,
    vc: VersionClass,
) -> BoundarySurface {
    BoundarySurface {
        sibling,
        surface_id: id.to_string(),
        surface_kind: kind,
        description: format!("test surface {id}"),
        covered_fields: ["f1"].iter().map(|s| s.to_string()).collect(),
        version_class: vc,
    }
}

fn make_entry(id: &str, sibling: SiblingRepo, class: RegressionClass) -> CatalogEntry {
    let surface = make_surface(sibling, id, SurfaceKind::ApiMessage, VersionClass::Minor);
    CatalogEntry {
        entry_id: id.to_string(),
        boundary: surface,
        positive_vectors: vec![ConformanceVector {
            vector_id: format!("{id}/pos"),
            description: "positive".to_string(),
            input_json: "{}".to_string(),
            expected_pass: true,
            expected_regression_class: None,
        }],
        negative_vectors: vec![ConformanceVector {
            vector_id: format!("{id}/neg"),
            description: "negative".to_string(),
            input_json: "{}".to_string(),
            expected_pass: false,
            expected_regression_class: Some(class),
        }],
        replay_obligation: ReplayObligation::standard(id, sibling),
        failure_class: class,
        approved: true,
        approval_epoch: Some(1),
    }
}

fn valid_artifact(test_id: &str, boundary: SiblingRepo) -> ReplayArtifact {
    let mut versions = BTreeMap::new();
    versions.insert("dep".to_string(), SemanticVersion::new(1, 0, 0));
    ReplayArtifact {
        test_id: test_id.to_string(),
        boundary,
        deterministic_seed: 42,
        pinned_versions: versions,
        input_snapshot: vec![1, 2, 3],
        expected_output_hash: "abc123".to_string(),
        reproduction_command: "cargo test".to_string(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SiblingRepo
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sibling_repo_all_count_matches_variants() {
    assert_eq!(SiblingRepo::all().len(), 6);
}

#[test]
fn sibling_repo_as_str_all_unique() {
    let strs: BTreeSet<&str> = SiblingRepo::all().iter().map(|r| r.as_str()).collect();
    assert_eq!(strs.len(), 6);
}

#[test]
fn sibling_repo_display_matches_as_str() {
    for repo in SiblingRepo::all() {
        assert_eq!(repo.to_string(), repo.as_str());
    }
}

#[test]
fn sibling_repo_ordering_is_declaration_order() {
    let all = SiblingRepo::all();
    for i in 1..all.len() {
        assert!(
            all[i - 1] < all[i],
            "{:?} should be < {:?}",
            all[i - 1],
            all[i]
        );
    }
}

#[test]
fn sibling_repo_hash_consistency() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    for repo in SiblingRepo::all() {
        assert!(set.insert(*repo));
    }
    // Re-insert should fail
    for repo in SiblingRepo::all() {
        assert!(!set.insert(*repo));
    }
}

#[test]
fn sibling_repo_copy_eq() {
    let a = SiblingRepo::Asupersync;
    let b = a; // Copy
    let c = a; // Copy again — original still usable
    assert_eq!(a, b);
    assert_eq!(b, c);
}

#[test]
fn sibling_repo_primary_count() {
    let primary_count = SiblingRepo::all().iter().filter(|r| r.is_primary()).count();
    assert_eq!(primary_count, 4);
    let non_primary = SiblingRepo::all()
        .iter()
        .filter(|r| !r.is_primary())
        .count();
    assert_eq!(non_primary, 2);
}

#[test]
fn sibling_repo_serde_all_variants() {
    for repo in SiblingRepo::all() {
        let json = serde_json::to_string(repo).unwrap();
        let decoded: SiblingRepo = serde_json::from_str(&json).unwrap();
        assert_eq!(*repo, decoded);
        // Ensure JSON is a quoted string
        assert!(json.starts_with('"'));
        assert!(json.ends_with('"'));
    }
}

#[test]
fn sibling_repo_debug_all_variants() {
    for repo in SiblingRepo::all() {
        let debug = format!("{:?}", repo);
        assert!(!debug.is_empty());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SurfaceKind
// ═══════════════════════════════════════════════════════════════════════════

fn all_surface_kinds() -> Vec<SurfaceKind> {
    vec![
        SurfaceKind::IdentifierSchema,
        SurfaceKind::DecisionPayload,
        SurfaceKind::EvidencePayload,
        SurfaceKind::ApiMessage,
        SurfaceKind::PersistenceSemantics,
        SurfaceKind::ReplayFormat,
        SurfaceKind::ExportFormat,
        SurfaceKind::TuiEventContract,
        SurfaceKind::TuiStateContract,
        SurfaceKind::TelemetrySchema,
    ]
}

#[test]
fn surface_kind_display_matches_as_str() {
    for kind in all_surface_kinds() {
        assert_eq!(kind.to_string(), kind.as_str());
    }
}

#[test]
fn surface_kind_ordering_is_declaration_order() {
    let kinds = all_surface_kinds();
    for i in 1..kinds.len() {
        assert!(
            kinds[i - 1] < kinds[i],
            "{:?} should be < {:?}",
            kinds[i - 1],
            kinds[i]
        );
    }
}

#[test]
fn surface_kind_serde_all_10() {
    for kind in all_surface_kinds() {
        let json = serde_json::to_string(&kind).unwrap();
        let decoded: SurfaceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, decoded);
    }
}

#[test]
fn surface_kind_as_str_no_uppercase() {
    for kind in all_surface_kinds() {
        let s = kind.as_str();
        assert_eq!(s, s.to_lowercase(), "as_str should be lowercase: {s}");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// VersionClass
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn version_class_serde_all() {
    for vc in [
        VersionClass::Patch,
        VersionClass::Minor,
        VersionClass::Major,
    ] {
        let json = serde_json::to_string(&vc).unwrap();
        let decoded: VersionClass = serde_json::from_str(&json).unwrap();
        assert_eq!(vc, decoded);
    }
}

#[test]
fn version_class_display_matches_as_str() {
    for vc in [
        VersionClass::Patch,
        VersionClass::Minor,
        VersionClass::Major,
    ] {
        assert_eq!(vc.to_string(), vc.as_str());
    }
}

#[test]
fn version_class_ordering_patch_minor_major() {
    assert!(VersionClass::Patch < VersionClass::Minor);
    assert!(VersionClass::Minor < VersionClass::Major);
}

#[test]
fn version_class_additive_fields_truth_table() {
    assert!(!VersionClass::Patch.allows_additive_fields());
    assert!(VersionClass::Minor.allows_additive_fields());
    assert!(VersionClass::Major.allows_additive_fields());
}

#[test]
fn version_class_breaking_changes_truth_table() {
    assert!(!VersionClass::Patch.allows_breaking_changes());
    assert!(!VersionClass::Minor.allows_breaking_changes());
    assert!(VersionClass::Major.allows_breaking_changes());
}

// ═══════════════════════════════════════════════════════════════════════════
// SemanticVersion
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn semantic_version_zero() {
    let v = SemanticVersion::new(0, 0, 0);
    assert_eq!(v.to_string(), "0.0.0");
}

#[test]
fn semantic_version_max_components() {
    let v = SemanticVersion::new(u32::MAX, u32::MAX, u32::MAX);
    assert_eq!(
        v.to_string(),
        format!("{}.{}.{}", u32::MAX, u32::MAX, u32::MAX)
    );
}

#[test]
fn semantic_version_ordering_major_first() {
    let v1 = SemanticVersion::new(1, 99, 99);
    let v2 = SemanticVersion::new(2, 0, 0);
    assert!(v1 < v2);
}

#[test]
fn semantic_version_ordering_minor_second() {
    let v1 = SemanticVersion::new(1, 1, 99);
    let v2 = SemanticVersion::new(1, 2, 0);
    assert!(v1 < v2);
}

#[test]
fn semantic_version_ordering_patch_third() {
    let v1 = SemanticVersion::new(1, 2, 3);
    let v2 = SemanticVersion::new(1, 2, 4);
    assert!(v1 < v2);
}

#[test]
fn semantic_version_eq() {
    let a = SemanticVersion::new(1, 2, 3);
    let b = SemanticVersion::new(1, 2, 3);
    assert_eq!(a, b);
}

#[test]
fn semantic_version_serde_roundtrip() {
    let v = SemanticVersion::new(10, 20, 30);
    let json = serde_json::to_string(&v).unwrap();
    let decoded: SemanticVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
}

#[test]
fn semantic_version_copy() {
    let a = SemanticVersion::new(1, 0, 0);
    let b = a; // Copy
    assert_eq!(a, b);
}

// ═══════════════════════════════════════════════════════════════════════════
// VersionCompatibility
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn version_compatibility_display_all() {
    assert_eq!(VersionCompatibility::Exact.to_string(), "exact");
    assert_eq!(
        VersionCompatibility::PatchCompatible.to_string(),
        "patch_compatible"
    );
    assert_eq!(
        VersionCompatibility::MinorCompatible.to_string(),
        "minor_compatible"
    );
    assert_eq!(
        VersionCompatibility::MajorIncompatible.to_string(),
        "major_incompatible"
    );
}

#[test]
fn version_compatibility_is_compatible_truth_table() {
    assert!(VersionCompatibility::Exact.is_compatible());
    assert!(VersionCompatibility::PatchCompatible.is_compatible());
    assert!(VersionCompatibility::MinorCompatible.is_compatible());
    assert!(!VersionCompatibility::MajorIncompatible.is_compatible());
}

#[test]
fn version_compatibility_ordering() {
    assert!(VersionCompatibility::Exact < VersionCompatibility::PatchCompatible);
    assert!(VersionCompatibility::PatchCompatible < VersionCompatibility::MinorCompatible);
    assert!(VersionCompatibility::MinorCompatible < VersionCompatibility::MajorIncompatible);
}

#[test]
fn version_compatibility_serde_all() {
    for vc in [
        VersionCompatibility::Exact,
        VersionCompatibility::PatchCompatible,
        VersionCompatibility::MinorCompatible,
        VersionCompatibility::MajorIncompatible,
    ] {
        let json = serde_json::to_string(&vc).unwrap();
        let decoded: VersionCompatibility = serde_json::from_str(&json).unwrap();
        assert_eq!(vc, decoded);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// negotiate_version
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn negotiate_version_zero_versions() {
    let v = SemanticVersion::new(0, 0, 0);
    assert_eq!(negotiate_version(v, v), VersionCompatibility::Exact);
}

#[test]
fn negotiate_version_same_major_different_minor_and_patch() {
    // Minor differs => MinorCompatible (patch difference is ignored)
    let a = SemanticVersion::new(1, 2, 3);
    let b = SemanticVersion::new(1, 5, 9);
    assert_eq!(
        negotiate_version(a, b),
        VersionCompatibility::MinorCompatible
    );
}

#[test]
fn negotiate_version_different_major_same_minor_patch() {
    let a = SemanticVersion::new(1, 5, 5);
    let b = SemanticVersion::new(2, 5, 5);
    assert_eq!(
        negotiate_version(a, b),
        VersionCompatibility::MajorIncompatible
    );
}

#[test]
fn negotiate_version_commutative_exact() {
    let a = SemanticVersion::new(3, 2, 1);
    assert_eq!(negotiate_version(a, a), negotiate_version(a, a));
}

#[test]
fn negotiate_version_commutative_patch() {
    let a = SemanticVersion::new(1, 0, 0);
    let b = SemanticVersion::new(1, 0, 1);
    assert_eq!(negotiate_version(a, b), negotiate_version(b, a));
}

#[test]
fn negotiate_version_commutative_minor() {
    let a = SemanticVersion::new(1, 0, 0);
    let b = SemanticVersion::new(1, 1, 0);
    assert_eq!(negotiate_version(a, b), negotiate_version(b, a));
}

#[test]
fn negotiate_version_commutative_major() {
    let a = SemanticVersion::new(1, 0, 0);
    let b = SemanticVersion::new(2, 0, 0);
    assert_eq!(negotiate_version(a, b), negotiate_version(b, a));
}

#[test]
fn negotiate_version_0x_series() {
    // 0.x versions: same major=0, different minor => MinorCompatible
    let a = SemanticVersion::new(0, 1, 0);
    let b = SemanticVersion::new(0, 2, 0);
    assert_eq!(
        negotiate_version(a, b),
        VersionCompatibility::MinorCompatible
    );
}

#[test]
fn negotiate_version_0x_patch_only() {
    let a = SemanticVersion::new(0, 1, 0);
    let b = SemanticVersion::new(0, 1, 1);
    assert_eq!(
        negotiate_version(a, b),
        VersionCompatibility::PatchCompatible
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// FailureSeverity
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn failure_severity_display_all() {
    assert_eq!(FailureSeverity::Info.to_string(), "info");
    assert_eq!(FailureSeverity::Warning.to_string(), "warning");
    assert_eq!(FailureSeverity::Error.to_string(), "error");
    assert_eq!(FailureSeverity::Critical.to_string(), "critical");
}

#[test]
fn failure_severity_as_str_matches_display() {
    for sev in [
        FailureSeverity::Info,
        FailureSeverity::Warning,
        FailureSeverity::Error,
        FailureSeverity::Critical,
    ] {
        assert_eq!(sev.as_str(), sev.to_string());
    }
}

#[test]
fn failure_severity_ordering_all() {
    assert!(FailureSeverity::Info < FailureSeverity::Warning);
    assert!(FailureSeverity::Warning < FailureSeverity::Error);
    assert!(FailureSeverity::Error < FailureSeverity::Critical);
}

#[test]
fn failure_severity_serde_all() {
    for sev in [
        FailureSeverity::Info,
        FailureSeverity::Warning,
        FailureSeverity::Error,
        FailureSeverity::Critical,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let decoded: FailureSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, decoded);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// RequiredResponse
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn required_response_display_all() {
    assert_eq!(RequiredResponse::Log.to_string(), "log");
    assert_eq!(RequiredResponse::Warn.to_string(), "warn");
    assert_eq!(RequiredResponse::Block.to_string(), "block");
}

#[test]
fn required_response_as_str_matches_display() {
    for rr in [
        RequiredResponse::Log,
        RequiredResponse::Warn,
        RequiredResponse::Block,
    ] {
        assert_eq!(rr.as_str(), rr.to_string());
    }
}

#[test]
fn required_response_ordering() {
    assert!(RequiredResponse::Log < RequiredResponse::Warn);
    assert!(RequiredResponse::Warn < RequiredResponse::Block);
}

#[test]
fn required_response_serde_all() {
    for rr in [
        RequiredResponse::Log,
        RequiredResponse::Warn,
        RequiredResponse::Block,
    ] {
        let json = serde_json::to_string(&rr).unwrap();
        let decoded: RequiredResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(rr, decoded);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FailureTaxonomyEntry + failure_taxonomy + classify_failure
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn failure_taxonomy_exactly_four_entries() {
    assert_eq!(failure_taxonomy().len(), 4);
}

#[test]
fn failure_taxonomy_unique_classes() {
    let taxonomy = failure_taxonomy();
    let classes: BTreeSet<_> = taxonomy.iter().map(|t| t.regression_class).collect();
    assert_eq!(classes.len(), 4);
}

#[test]
fn failure_taxonomy_serde_individual_entries() {
    for entry in &failure_taxonomy() {
        let json = serde_json::to_string(entry).unwrap();
        let decoded: FailureTaxonomyEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(*entry, decoded);
    }
}

#[test]
fn classify_failure_all_four_classes() {
    let taxonomy = failure_taxonomy();
    for class in [
        RegressionClass::Breaking,
        RegressionClass::Behavioral,
        RegressionClass::Observability,
        RegressionClass::Performance,
    ] {
        let entry = classify_failure(&taxonomy, class);
        assert!(entry.is_some(), "missing taxonomy for {:?}", class);
        assert_eq!(entry.unwrap().regression_class, class);
    }
}

#[test]
fn classify_failure_empty_taxonomy_returns_none() {
    let empty: Vec<FailureTaxonomyEntry> = vec![];
    assert!(classify_failure(&empty, RegressionClass::Breaking).is_none());
}

#[test]
fn classify_failure_breaking_is_critical_block() {
    let taxonomy = failure_taxonomy();
    let entry = classify_failure(&taxonomy, RegressionClass::Breaking).unwrap();
    assert_eq!(entry.severity, FailureSeverity::Critical);
    assert_eq!(entry.required_response, RequiredResponse::Block);
}

#[test]
fn classify_failure_performance_is_warning_log() {
    let taxonomy = failure_taxonomy();
    let entry = classify_failure(&taxonomy, RegressionClass::Performance).unwrap();
    assert_eq!(entry.severity, FailureSeverity::Warning);
    assert_eq!(entry.required_response, RequiredResponse::Log);
}

#[test]
fn failure_taxonomy_evidence_counts() {
    let taxonomy = failure_taxonomy();
    let breaking = classify_failure(&taxonomy, RegressionClass::Breaking).unwrap();
    assert_eq!(breaking.evidence_requirements.len(), 5);
    let behavioral = classify_failure(&taxonomy, RegressionClass::Behavioral).unwrap();
    assert_eq!(behavioral.evidence_requirements.len(), 4);
    let observability = classify_failure(&taxonomy, RegressionClass::Observability).unwrap();
    assert_eq!(observability.evidence_requirements.len(), 3);
    let performance = classify_failure(&taxonomy, RegressionClass::Performance).unwrap();
    assert_eq!(performance.evidence_requirements.len(), 5);
}

// ═══════════════════════════════════════════════════════════════════════════
// FieldVersionCoverage
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn field_version_coverage_serde() {
    let fvc = FieldVersionCoverage {
        field_name: "trace_id".to_string(),
        protected_at: VersionClass::Minor,
        required: true,
    };
    let json = serde_json::to_string(&fvc).unwrap();
    let decoded: FieldVersionCoverage = serde_json::from_str(&json).unwrap();
    assert_eq!(fvc, decoded);
}

#[test]
fn field_version_coverage_optional_field() {
    let fvc = FieldVersionCoverage {
        field_name: "metadata".to_string(),
        protected_at: VersionClass::Patch,
        required: false,
    };
    assert!(!fvc.required);
    assert_eq!(fvc.protected_at, VersionClass::Patch);
}

// ═══════════════════════════════════════════════════════════════════════════
// VersionNegotiationResult
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn version_negotiation_result_with_migration_path() {
    let result = VersionNegotiationResult {
        boundary: SiblingRepo::FrankenNode,
        local_version: SemanticVersion::new(1, 0, 0),
        remote_version: SemanticVersion::new(2, 0, 0),
        compatibility: VersionCompatibility::MajorIncompatible,
        migration_required: true,
        migration_path: Some("run v1_to_v2_migration.sh".to_string()),
    };
    let json = serde_json::to_string(&result).unwrap();
    let decoded: VersionNegotiationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, decoded);
    assert!(decoded.migration_required);
    assert!(decoded.migration_path.is_some());
}

#[test]
fn version_negotiation_result_no_migration() {
    let result = VersionNegotiationResult {
        boundary: SiblingRepo::Frankentui,
        local_version: SemanticVersion::new(1, 0, 0),
        remote_version: SemanticVersion::new(1, 0, 1),
        compatibility: VersionCompatibility::PatchCompatible,
        migration_required: false,
        migration_path: None,
    };
    assert!(!result.migration_required);
    assert!(result.migration_path.is_none());
}

// ═══════════════════════════════════════════════════════════════════════════
// BoundarySurface
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn boundary_surface_serde_roundtrip() {
    let surface = make_surface(
        SiblingRepo::Frankensqlite,
        "test/surface",
        SurfaceKind::PersistenceSemantics,
        VersionClass::Major,
    );
    let json = serde_json::to_string(&surface).unwrap();
    let decoded: BoundarySurface = serde_json::from_str(&json).unwrap();
    assert_eq!(surface, decoded);
}

#[test]
fn boundary_surface_many_covered_fields() {
    let mut fields = BTreeSet::new();
    for i in 0..100 {
        fields.insert(format!("field_{i}"));
    }
    let surface = BoundarySurface {
        sibling: SiblingRepo::Asupersync,
        surface_id: "many_fields".to_string(),
        surface_kind: SurfaceKind::IdentifierSchema,
        description: "stress test".to_string(),
        covered_fields: fields.clone(),
        version_class: VersionClass::Minor,
    };
    assert_eq!(surface.covered_fields.len(), 100);
    let json = serde_json::to_string(&surface).unwrap();
    let decoded: BoundarySurface = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.covered_fields.len(), 100);
}

// ═══════════════════════════════════════════════════════════════════════════
// ReplayObligation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn replay_obligation_standard_all_true() {
    let obl = ReplayObligation::standard("t1", SiblingRepo::Asupersync);
    assert!(obl.must_pin_versions);
    assert!(obl.must_provide_seed);
    assert!(obl.must_capture_input);
    assert!(obl.must_hash_output);
    assert_eq!(obl.test_id, "t1");
    assert_eq!(obl.boundary, SiblingRepo::Asupersync);
}

#[test]
fn replay_obligation_verify_all_violations_simultaneously() {
    let obl = ReplayObligation::standard("t1", SiblingRepo::Frankentui);
    let artifact = ReplayArtifact {
        test_id: "wrong_id".to_string(),
        boundary: SiblingRepo::Frankensqlite,
        deterministic_seed: 0,
        pinned_versions: BTreeMap::new(),
        input_snapshot: vec![],
        expected_output_hash: String::new(),
        reproduction_command: "cargo test".to_string(),
    };
    let errors = obl.verify(&artifact);
    // Should detect: empty pinned_versions, zero seed, empty input, empty hash,
    // test_id mismatch, boundary mismatch
    assert_eq!(errors.len(), 6, "expected 6 errors, got: {errors:?}");
}

#[test]
fn replay_obligation_verify_valid_artifact_zero_errors() {
    let obl = ReplayObligation::standard("t1", SiblingRepo::Frankentui);
    let artifact = valid_artifact("t1", SiblingRepo::Frankentui);
    let errors = obl.verify(&artifact);
    assert!(errors.is_empty());
}

#[test]
fn replay_obligation_relaxed_verify() {
    let obl = ReplayObligation {
        test_id: "t1".to_string(),
        boundary: SiblingRepo::Asupersync,
        must_pin_versions: false,
        must_provide_seed: false,
        must_capture_input: false,
        must_hash_output: false,
    };
    let artifact = ReplayArtifact {
        test_id: "t1".to_string(),
        boundary: SiblingRepo::Asupersync,
        deterministic_seed: 0,
        pinned_versions: BTreeMap::new(),
        input_snapshot: vec![],
        expected_output_hash: String::new(),
        reproduction_command: String::new(),
    };
    let errors = obl.verify(&artifact);
    assert!(
        errors.is_empty(),
        "relaxed obligation should pass: {errors:?}"
    );
}

#[test]
fn replay_obligation_serde_roundtrip() {
    let obl = ReplayObligation::standard("serde_test", SiblingRepo::FrankenNode);
    let json = serde_json::to_string(&obl).unwrap();
    let decoded: ReplayObligation = serde_json::from_str(&json).unwrap();
    assert_eq!(obl, decoded);
}

#[test]
fn replay_obligation_verify_test_id_mismatch_only() {
    let obl = ReplayObligation::standard("expected", SiblingRepo::Frankentui);
    let mut artifact = valid_artifact("expected", SiblingRepo::Frankentui);
    artifact.test_id = "actual".to_string();
    let errors = obl.verify(&artifact);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("test_id mismatch"));
}

#[test]
fn replay_obligation_verify_boundary_mismatch_only() {
    let obl = ReplayObligation::standard("t1", SiblingRepo::Frankentui);
    let mut artifact = valid_artifact("t1", SiblingRepo::Frankentui);
    artifact.boundary = SiblingRepo::Asupersync;
    let errors = obl.verify(&artifact);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("boundary mismatch"));
}

// ═══════════════════════════════════════════════════════════════════════════
// ReplayArtifact
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn replay_artifact_serde_roundtrip() {
    let artifact = valid_artifact("rt_test", SiblingRepo::SqlmodelRust);
    let json = serde_json::to_string(&artifact).unwrap();
    let decoded: ReplayArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, decoded);
}

#[test]
fn replay_artifact_multiple_pinned_versions() {
    let mut versions = BTreeMap::new();
    versions.insert("a".to_string(), SemanticVersion::new(1, 0, 0));
    versions.insert("b".to_string(), SemanticVersion::new(2, 3, 4));
    versions.insert("c".to_string(), SemanticVersion::new(0, 0, 1));
    let artifact = ReplayArtifact {
        test_id: "multi".to_string(),
        boundary: SiblingRepo::FastapiRust,
        deterministic_seed: 999,
        pinned_versions: versions,
        input_snapshot: vec![0xFF; 1024],
        expected_output_hash: "sha256:abc".to_string(),
        reproduction_command: "make test".to_string(),
    };
    assert_eq!(artifact.pinned_versions.len(), 3);
    let json = serde_json::to_string(&artifact).unwrap();
    let decoded: ReplayArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, decoded);
}

// ═══════════════════════════════════════════════════════════════════════════
// ConformanceVector
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn conformance_vector_serde_positive() {
    let v = ConformanceVector {
        vector_id: "v1".to_string(),
        description: "positive test".to_string(),
        input_json: "{\"key\": 42}".to_string(),
        expected_pass: true,
        expected_regression_class: None,
    };
    let json = serde_json::to_string(&v).unwrap();
    let decoded: ConformanceVector = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
}

#[test]
fn conformance_vector_serde_negative() {
    let v = ConformanceVector {
        vector_id: "v2".to_string(),
        description: "negative test".to_string(),
        input_json: "{}".to_string(),
        expected_pass: false,
        expected_regression_class: Some(RegressionClass::Breaking),
    };
    let json = serde_json::to_string(&v).unwrap();
    let decoded: ConformanceVector = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
    assert_eq!(
        decoded.expected_regression_class,
        Some(RegressionClass::Breaking)
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// CatalogEntry
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn catalog_entry_has_required_vectors_both_present() {
    let entry = make_entry(
        "test/both",
        SiblingRepo::Frankentui,
        RegressionClass::Behavioral,
    );
    assert!(entry.has_required_vectors());
}

#[test]
fn catalog_entry_has_required_vectors_no_positive() {
    let mut entry = make_entry(
        "test/no_pos",
        SiblingRepo::Frankentui,
        RegressionClass::Behavioral,
    );
    entry.positive_vectors.clear();
    assert!(!entry.has_required_vectors());
}

#[test]
fn catalog_entry_has_required_vectors_no_negative() {
    let mut entry = make_entry(
        "test/no_neg",
        SiblingRepo::Frankentui,
        RegressionClass::Behavioral,
    );
    entry.negative_vectors.clear();
    assert!(!entry.has_required_vectors());
}

#[test]
fn catalog_entry_has_required_vectors_both_empty() {
    let mut entry = make_entry(
        "test/both_empty",
        SiblingRepo::Frankentui,
        RegressionClass::Behavioral,
    );
    entry.positive_vectors.clear();
    entry.negative_vectors.clear();
    assert!(!entry.has_required_vectors());
}

#[test]
fn catalog_entry_serde_roundtrip() {
    let entry = make_entry(
        "serde/entry",
        SiblingRepo::Frankensqlite,
        RegressionClass::Breaking,
    );
    let json = serde_json::to_string(&entry).unwrap();
    let decoded: CatalogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, decoded);
}

#[test]
fn catalog_entry_unapproved() {
    let mut entry = make_entry(
        "unapproved",
        SiblingRepo::Frankentui,
        RegressionClass::Behavioral,
    );
    entry.approved = false;
    entry.approval_epoch = None;
    assert!(!entry.approved);
    assert!(entry.approval_epoch.is_none());
}

// ═══════════════════════════════════════════════════════════════════════════
// ChangeKind
// ═══════════════════════════════════════════════════════════════════════════

fn all_change_kinds() -> Vec<ChangeKind> {
    vec![
        ChangeKind::EntryAdded,
        ChangeKind::EntryModified,
        ChangeKind::EntryRemoved,
        ChangeKind::TaxonomyUpdated,
        ChangeKind::VectorAdded,
        ChangeKind::VectorRemoved,
    ]
}

#[test]
fn change_kind_display_all_six() {
    let expected = [
        "entry_added",
        "entry_modified",
        "entry_removed",
        "taxonomy_updated",
        "vector_added",
        "vector_removed",
    ];
    for (kind, exp) in all_change_kinds().iter().zip(expected.iter()) {
        assert_eq!(kind.to_string(), *exp);
    }
}

#[test]
fn change_kind_ordering_declaration_order() {
    let kinds = all_change_kinds();
    for i in 1..kinds.len() {
        assert!(kinds[i - 1] < kinds[i]);
    }
}

#[test]
fn change_kind_serde_all_six() {
    for kind in all_change_kinds() {
        let json = serde_json::to_string(&kind).unwrap();
        let decoded: ChangeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, decoded);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CatalogChangeRecord
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn catalog_change_record_serde() {
    let record = CatalogChangeRecord {
        version: SemanticVersion::new(1, 2, 0),
        description: "added new entry".to_string(),
        affected_entries: vec!["entry_a".to_string(), "entry_b".to_string()],
        change_kind: ChangeKind::EntryAdded,
    };
    let json = serde_json::to_string(&record).unwrap();
    let decoded: CatalogChangeRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, decoded);
}

#[test]
fn catalog_change_record_empty_affected() {
    let record = CatalogChangeRecord {
        version: SemanticVersion::new(0, 0, 1),
        description: "taxonomy update".to_string(),
        affected_entries: vec![],
        change_kind: ChangeKind::TaxonomyUpdated,
    };
    assert!(record.affected_entries.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// CatalogValidationError
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn catalog_validation_error_display_with_entry_id() {
    let err = CatalogValidationError {
        entry_id: Some("my/entry".to_string()),
        field: "vector_id".to_string(),
        detail: "duplicate vector".to_string(),
    };
    assert_eq!(err.to_string(), "[my/entry] vector_id: duplicate vector");
}

#[test]
fn catalog_validation_error_display_without_entry_id() {
    let err = CatalogValidationError {
        entry_id: None,
        field: "taxonomy".to_string(),
        detail: "incomplete".to_string(),
    };
    assert_eq!(err.to_string(), "[catalog] taxonomy: incomplete");
}

#[test]
fn catalog_validation_error_serde() {
    let err = CatalogValidationError {
        entry_id: Some("x".to_string()),
        field: "f".to_string(),
        detail: "d".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let decoded: CatalogValidationError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, decoded);
}

// ═══════════════════════════════════════════════════════════════════════════
// ConformanceCatalog
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn catalog_new_empty() {
    let catalog = ConformanceCatalog::new(SemanticVersion::new(0, 1, 0));
    assert!(catalog.entries.is_empty());
    assert_eq!(catalog.taxonomy.len(), 4); // auto-populated
    assert!(catalog.change_log.is_empty());
    assert_eq!(catalog.catalog_version, SemanticVersion::new(0, 1, 0));
}

#[test]
fn catalog_add_entry_creates_change_record() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    let entry = make_entry(
        "add/test",
        SiblingRepo::Frankentui,
        RegressionClass::Behavioral,
    );
    catalog.add_entry(entry);
    assert_eq!(catalog.entries.len(), 1);
    assert_eq!(catalog.change_log.len(), 1);
    assert_eq!(catalog.change_log[0].change_kind, ChangeKind::EntryAdded);
    assert_eq!(catalog.change_log[0].affected_entries, vec!["add/test"]);
    assert_eq!(catalog.change_log[0].version, SemanticVersion::new(1, 0, 0));
}

#[test]
fn catalog_add_multiple_entries() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    for i in 0..5 {
        let entry = make_entry(
            &format!("entry_{i}"),
            SiblingRepo::Asupersync,
            RegressionClass::Behavioral,
        );
        catalog.add_entry(entry);
    }
    assert_eq!(catalog.entries.len(), 5);
    assert_eq!(catalog.change_log.len(), 5);
}

#[test]
fn catalog_get_entry_found() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(make_entry(
        "find_me",
        SiblingRepo::Frankentui,
        RegressionClass::Behavioral,
    ));
    let found = catalog.get_entry("find_me");
    assert!(found.is_some());
    assert_eq!(found.unwrap().entry_id, "find_me");
}

#[test]
fn catalog_get_entry_not_found() {
    let catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    assert!(catalog.get_entry("nope").is_none());
}

#[test]
fn catalog_entries_for_boundary_filters() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(make_entry(
        "a1",
        SiblingRepo::Frankentui,
        RegressionClass::Behavioral,
    ));
    catalog.add_entry(make_entry(
        "a2",
        SiblingRepo::Frankentui,
        RegressionClass::Breaking,
    ));
    catalog.add_entry(make_entry(
        "b1",
        SiblingRepo::Asupersync,
        RegressionClass::Behavioral,
    ));

    let tui = catalog.entries_for_boundary(SiblingRepo::Frankentui);
    assert_eq!(tui.len(), 2);
    let asup = catalog.entries_for_boundary(SiblingRepo::Asupersync);
    assert_eq!(asup.len(), 1);
    let sqlite = catalog.entries_for_boundary(SiblingRepo::Frankensqlite);
    assert_eq!(sqlite.len(), 0);
}

#[test]
fn catalog_covered_boundaries_empty() {
    let catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    assert!(catalog.covered_boundaries().is_empty());
}

#[test]
fn catalog_covered_boundaries_deduplicates() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(make_entry(
        "x1",
        SiblingRepo::Frankentui,
        RegressionClass::Behavioral,
    ));
    catalog.add_entry(make_entry(
        "x2",
        SiblingRepo::Frankentui,
        RegressionClass::Breaking,
    ));
    let covered = catalog.covered_boundaries();
    assert_eq!(covered.len(), 1);
    assert!(covered.contains(&SiblingRepo::Frankentui));
}

#[test]
fn catalog_entries_by_class_empty() {
    let catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    assert!(catalog.entries_by_class().is_empty());
}

#[test]
fn catalog_entries_by_class_counts_correct() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(make_entry(
        "e1",
        SiblingRepo::Frankentui,
        RegressionClass::Breaking,
    ));
    catalog.add_entry(make_entry(
        "e2",
        SiblingRepo::Frankentui,
        RegressionClass::Breaking,
    ));
    catalog.add_entry(make_entry(
        "e3",
        SiblingRepo::Frankentui,
        RegressionClass::Behavioral,
    ));

    let counts = catalog.entries_by_class();
    assert_eq!(counts[&RegressionClass::Breaking], 2);
    assert_eq!(counts[&RegressionClass::Behavioral], 1);
    assert!(!counts.contains_key(&RegressionClass::Performance));
}

#[test]
fn catalog_validate_vector_coverage_all_valid() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(make_entry(
        "v1",
        SiblingRepo::Frankentui,
        RegressionClass::Behavioral,
    ));
    assert!(catalog.validate_vector_coverage().is_empty());
}

#[test]
fn catalog_validate_vector_coverage_missing_positive() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    let mut entry = make_entry("v1", SiblingRepo::Frankentui, RegressionClass::Behavioral);
    entry.positive_vectors.clear();
    catalog.add_entry(entry);
    let errors = catalog.validate_vector_coverage();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("v1"));
}

#[test]
fn catalog_serde_roundtrip() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(2, 0, 0));
    catalog.add_entry(make_entry(
        "s1",
        SiblingRepo::Frankentui,
        RegressionClass::Behavioral,
    ));
    catalog.add_entry(make_entry(
        "s2",
        SiblingRepo::Asupersync,
        RegressionClass::Breaking,
    ));
    let json = serde_json::to_string(&catalog).unwrap();
    let decoded: ConformanceCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(catalog, decoded);
}

// ═══════════════════════════════════════════════════════════════════════════
// validate_catalog
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn validate_catalog_clean_passes() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(make_entry(
        "clean",
        SiblingRepo::Frankentui,
        RegressionClass::Behavioral,
    ));
    let errors = validate_catalog(&catalog);
    assert!(errors.is_empty(), "errors: {errors:?}");
}

#[test]
fn validate_catalog_duplicate_entry_ids() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(make_entry(
        "dup",
        SiblingRepo::Frankentui,
        RegressionClass::Behavioral,
    ));
    // Manually push a duplicate (bypassing add_entry's change log)
    catalog.entries.push(make_entry(
        "dup",
        SiblingRepo::Asupersync,
        RegressionClass::Breaking,
    ));
    let errors = validate_catalog(&catalog);
    assert!(
        errors
            .iter()
            .any(|e| e.detail.contains("duplicate entry ID"))
    );
}

#[test]
fn validate_catalog_duplicate_vector_ids() {
    let mut entry = make_entry("dvec", SiblingRepo::Frankentui, RegressionClass::Behavioral);
    // Make positive and negative share the same vector_id
    entry.negative_vectors[0].vector_id = entry.positive_vectors[0].vector_id.clone();
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(entry);
    let errors = validate_catalog(&catalog);
    assert!(
        errors
            .iter()
            .any(|e| e.detail.contains("duplicate vector ID"))
    );
}

#[test]
fn validate_catalog_empty_covered_fields() {
    let mut entry = make_entry(
        "empty_fields",
        SiblingRepo::Frankentui,
        RegressionClass::Behavioral,
    );
    entry.boundary.covered_fields.clear();
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(entry);
    let errors = validate_catalog(&catalog);
    assert!(errors.iter().any(|e| e.field == "covered_fields"));
}

#[test]
fn validate_catalog_missing_taxonomy_class() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    // Remove all taxonomy entries
    catalog.taxonomy.clear();
    let errors = validate_catalog(&catalog);
    // Should report 4 missing classes
    let taxonomy_errors: Vec<_> = errors.iter().filter(|e| e.field == "taxonomy").collect();
    assert_eq!(taxonomy_errors.len(), 4);
}

#[test]
fn validate_catalog_partial_taxonomy() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    // Keep only Breaking
    catalog
        .taxonomy
        .retain(|t| t.regression_class == RegressionClass::Breaking);
    let errors = validate_catalog(&catalog);
    let taxonomy_errors: Vec<_> = errors.iter().filter(|e| e.field == "taxonomy").collect();
    assert_eq!(taxonomy_errors.len(), 3); // Missing Behavioral, Observability, Performance
}

#[test]
fn validate_catalog_multiple_error_types() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.taxonomy.clear(); // 4 taxonomy errors
    let mut entry = make_entry("bad", SiblingRepo::Frankentui, RegressionClass::Behavioral);
    entry.positive_vectors.clear(); // missing vectors
    entry.boundary.covered_fields.clear(); // empty fields
    catalog.add_entry(entry);
    let errors = validate_catalog(&catalog);
    assert!(
        errors.len() >= 6,
        "expected at least 6 errors, got {}: {errors:?}",
        errors.len()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// canonical_boundary_surfaces
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn canonical_surfaces_count() {
    let surfaces = canonical_boundary_surfaces();
    assert_eq!(surfaces.len(), 12);
}

#[test]
fn canonical_surfaces_all_repos_covered() {
    let surfaces = canonical_boundary_surfaces();
    let repos: BTreeSet<SiblingRepo> = surfaces.iter().map(|s| s.sibling).collect();
    for repo in SiblingRepo::all() {
        assert!(
            repos.contains(repo),
            "repo {} not in canonical surfaces",
            repo
        );
    }
}

#[test]
fn canonical_surfaces_unique_ids() {
    let surfaces = canonical_boundary_surfaces();
    let ids: BTreeSet<&str> = surfaces.iter().map(|s| s.surface_id.as_str()).collect();
    assert_eq!(ids.len(), surfaces.len());
}

#[test]
fn canonical_surfaces_all_have_nonempty_fields() {
    for surface in canonical_boundary_surfaces() {
        assert!(
            !surface.covered_fields.is_empty(),
            "surface {} has no fields",
            surface.surface_id
        );
    }
}

#[test]
fn canonical_surfaces_serde_roundtrip() {
    let surfaces = canonical_boundary_surfaces();
    let json = serde_json::to_string(&surfaces).unwrap();
    let decoded: Vec<BoundarySurface> = serde_json::from_str(&json).unwrap();
    assert_eq!(surfaces, decoded);
}

// ═══════════════════════════════════════════════════════════════════════════
// build_canonical_catalog
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn build_canonical_catalog_entry_count() {
    let catalog = build_canonical_catalog();
    assert_eq!(catalog.entries.len(), 12);
}

#[test]
fn build_canonical_catalog_version() {
    let catalog = build_canonical_catalog();
    assert_eq!(catalog.catalog_version, SemanticVersion::new(1, 0, 0));
}

#[test]
fn build_canonical_catalog_all_approved() {
    let catalog = build_canonical_catalog();
    for entry in &catalog.entries {
        assert!(
            entry.approved,
            "entry {} should be approved",
            entry.entry_id
        );
        assert_eq!(entry.approval_epoch, Some(1));
    }
}

#[test]
fn build_canonical_catalog_validates_clean() {
    let catalog = build_canonical_catalog();
    let errors = validate_catalog(&catalog);
    assert!(
        errors.is_empty(),
        "canonical catalog should validate: {errors:?}"
    );
}

#[test]
fn build_canonical_catalog_change_log_matches_entries() {
    let catalog = build_canonical_catalog();
    assert_eq!(catalog.change_log.len(), catalog.entries.len());
    for record in &catalog.change_log {
        assert_eq!(record.change_kind, ChangeKind::EntryAdded);
        assert_eq!(record.version, SemanticVersion::new(1, 0, 0));
    }
}

#[test]
fn build_canonical_catalog_failure_class_mapping() {
    let catalog = build_canonical_catalog();
    for entry in &catalog.entries {
        let expected_class = match entry.boundary.version_class {
            VersionClass::Major => RegressionClass::Breaking,
            VersionClass::Minor => RegressionClass::Behavioral,
            VersionClass::Patch => RegressionClass::Observability,
        };
        assert_eq!(
            entry.failure_class, expected_class,
            "entry {} has wrong class",
            entry.entry_id
        );
    }
}

#[test]
fn build_canonical_catalog_deterministic() {
    let a = build_canonical_catalog();
    let b = build_canonical_catalog();
    let json_a = serde_json::to_string(&a).unwrap();
    let json_b = serde_json::to_string(&b).unwrap();
    assert_eq!(json_a, json_b);
}

#[test]
fn build_canonical_catalog_serde_roundtrip() {
    let catalog = build_canonical_catalog();
    let json = serde_json::to_string(&catalog).unwrap();
    let decoded: ConformanceCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(catalog, decoded);
}

// ═══════════════════════════════════════════════════════════════════════════
// Integration: full lifecycle scenarios
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn integration_build_query_validate_serialize() {
    let catalog = build_canonical_catalog();

    // Query
    let tui_entries = catalog.entries_for_boundary(SiblingRepo::Frankentui);
    assert_eq!(tui_entries.len(), 2);

    // Validate
    let errors = validate_catalog(&catalog);
    assert!(errors.is_empty());

    // Class counts
    let counts = catalog.entries_by_class();
    let total: usize = counts.values().sum();
    assert_eq!(total, 12);

    // Serialize and verify round-trip
    let json = serde_json::to_string(&catalog).unwrap();
    let decoded: ConformanceCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(catalog, decoded);
}

#[test]
fn integration_custom_catalog_with_validation_errors() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(0, 1, 0));

    // Add a valid entry
    catalog.add_entry(make_entry(
        "valid",
        SiblingRepo::Frankentui,
        RegressionClass::Behavioral,
    ));

    // Add an entry missing negative vectors
    let mut bad_entry = make_entry("bad", SiblingRepo::Asupersync, RegressionClass::Breaking);
    bad_entry.negative_vectors.clear();
    catalog.add_entry(bad_entry);

    let errors = validate_catalog(&catalog);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].detail.contains("bad"));
}

#[test]
fn integration_version_negotiation_across_all_boundaries() {
    let local = SemanticVersion::new(1, 0, 0);
    let results: Vec<VersionNegotiationResult> = SiblingRepo::all()
        .iter()
        .map(|&repo| {
            let remote = if repo.is_primary() {
                SemanticVersion::new(1, 0, 1) // patch diff
            } else {
                SemanticVersion::new(2, 0, 0) // major diff
            };
            let compat = negotiate_version(local, remote);
            VersionNegotiationResult {
                boundary: repo,
                local_version: local,
                remote_version: remote,
                compatibility: compat,
                migration_required: !compat.is_compatible(),
                migration_path: if !compat.is_compatible() {
                    Some(format!("migrate_{}", repo.as_str()))
                } else {
                    None
                },
            }
        })
        .collect();

    assert_eq!(results.len(), 6);
    let compatible_count = results
        .iter()
        .filter(|r| r.compatibility.is_compatible())
        .count();
    assert_eq!(compatible_count, 4); // 4 primary repos got patch diff
    let incompatible_count = results
        .iter()
        .filter(|r| !r.compatibility.is_compatible())
        .count();
    assert_eq!(incompatible_count, 2); // 2 non-primary got major diff
}

#[test]
fn integration_replay_obligation_for_canonical_entries() {
    let catalog = build_canonical_catalog();
    for entry in &catalog.entries {
        let artifact = valid_artifact(&entry.entry_id, entry.boundary.sibling);
        let errors = entry.replay_obligation.verify(&artifact);
        assert!(
            errors.is_empty(),
            "entry {} obligation failed: {errors:?}",
            entry.entry_id
        );
    }
}

#[test]
fn integration_taxonomy_classify_all_canonical_entries() {
    let catalog = build_canonical_catalog();
    for entry in &catalog.entries {
        let classified = classify_failure(&catalog.taxonomy, entry.failure_class);
        assert!(
            classified.is_some(),
            "no taxonomy for {:?}",
            entry.failure_class
        );
    }
}
