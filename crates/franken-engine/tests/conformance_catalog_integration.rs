#![forbid(unsafe_code)]

//! Integration tests for the `conformance_catalog` module.
//!
//! Covers: SiblingRepo, SurfaceKind, VersionClass, SemanticVersion,
//! VersionCompatibility, negotiate_version, FailureSeverity, RequiredResponse,
//! FailureTaxonomyEntry, classify_failure, ReplayArtifact, ReplayObligation,
//! ConformanceVector, CatalogEntry, ConformanceCatalog, CatalogChangeRecord,
//! ChangeKind, CatalogValidationError, validate_catalog, canonical_boundary_surfaces,
//! build_canonical_catalog, FieldVersionCoverage, VersionNegotiationResult.

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

use frankenengine_engine::conformance_catalog::{
    BoundarySurface, CatalogChangeRecord, CatalogEntry, CatalogValidationError, ChangeKind,
    ConformanceCatalog, ConformanceVector, FailureSeverity, FailureTaxonomyEntry,
    FieldVersionCoverage, ReplayArtifact, ReplayObligation, RequiredResponse, SemanticVersion,
    SiblingRepo, SurfaceKind, VersionClass, VersionCompatibility, VersionNegotiationResult,
    build_canonical_catalog, canonical_boundary_surfaces, classify_failure, failure_taxonomy,
    negotiate_version, validate_catalog,
};
use frankenengine_engine::cross_repo_contract::RegressionClass;

// ---------------------------------------------------------------------------
// Helper builders
// ---------------------------------------------------------------------------

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
        covered_fields: ["field_a", "field_b"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        version_class: vc,
    }
}

fn make_vector(id: &str, pass: bool) -> ConformanceVector {
    ConformanceVector {
        vector_id: id.to_string(),
        description: format!("vector {id}"),
        input_json: "{}".to_string(),
        expected_pass: pass,
        expected_regression_class: if pass {
            None
        } else {
            Some(RegressionClass::Behavioral)
        },
    }
}

fn make_entry(id: &str, sibling: SiblingRepo) -> CatalogEntry {
    CatalogEntry {
        entry_id: id.to_string(),
        boundary: make_surface(sibling, id, SurfaceKind::ApiMessage, VersionClass::Minor),
        positive_vectors: vec![make_vector(&format!("{id}/pos"), true)],
        negative_vectors: vec![make_vector(&format!("{id}/neg"), false)],
        replay_obligation: ReplayObligation::standard(id, sibling),
        failure_class: RegressionClass::Behavioral,
        approved: true,
        approval_epoch: Some(1),
    }
}

fn make_valid_artifact(test_id: &str, boundary: SiblingRepo) -> ReplayArtifact {
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

// ===========================================================================
// Section 1: SiblingRepo enumeration
// ===========================================================================

#[test]
fn sibling_repo_all_returns_six_variants() {
    let all = SiblingRepo::all();
    assert_eq!(all.len(), 6);
}

#[test]
fn sibling_repo_as_str_matches_display() {
    for repo in SiblingRepo::all() {
        assert_eq!(repo.as_str(), repo.to_string());
    }
}

#[test]
fn sibling_repo_primary_vs_optional() {
    let primary: Vec<_> = SiblingRepo::all()
        .iter()
        .filter(|r| r.is_primary())
        .collect();
    let optional: Vec<_> = SiblingRepo::all()
        .iter()
        .filter(|r| !r.is_primary())
        .collect();
    assert_eq!(primary.len(), 4);
    assert_eq!(optional.len(), 2);
    assert!(!SiblingRepo::SqlmodelRust.is_primary());
    assert!(!SiblingRepo::FastapiRust.is_primary());
}

#[test]
fn sibling_repo_ord_is_deterministic() {
    let mut repos: Vec<SiblingRepo> = SiblingRepo::all().to_vec();
    repos.sort();
    let mut repos2 = repos.clone();
    repos2.sort();
    assert_eq!(repos, repos2);
}

#[test]
fn sibling_repo_serde_all_variants() {
    for repo in SiblingRepo::all() {
        let json = serde_json::to_string(repo).unwrap();
        let decoded: SiblingRepo = serde_json::from_str(&json).unwrap();
        assert_eq!(*repo, decoded);
    }
}

#[test]
fn sibling_repo_debug_contains_variant_name() {
    let dbg = format!("{:?}", SiblingRepo::Asupersync);
    assert!(dbg.contains("Asupersync"));
}

// ===========================================================================
// Section 2: SurfaceKind
// ===========================================================================

#[test]
fn surface_kind_as_str_all_unique() {
    let kinds = [
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
    ];
    let strs: BTreeSet<&str> = kinds.iter().map(|k| k.as_str()).collect();
    assert_eq!(strs.len(), 10);
}

#[test]
fn surface_kind_display_matches_as_str() {
    let kinds = [
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
    ];
    for kind in &kinds {
        assert_eq!(kind.as_str(), kind.to_string());
    }
}

#[test]
fn surface_kind_serde_round_trip() {
    let kind = SurfaceKind::TelemetrySchema;
    let json = serde_json::to_string(&kind).unwrap();
    let decoded: SurfaceKind = serde_json::from_str(&json).unwrap();
    assert_eq!(kind, decoded);
}

// ===========================================================================
// Section 3: VersionClass
// ===========================================================================

#[test]
fn version_class_ordering() {
    assert!(VersionClass::Patch < VersionClass::Minor);
    assert!(VersionClass::Minor < VersionClass::Major);
}

#[test]
fn version_class_permissions_patch() {
    assert!(!VersionClass::Patch.allows_additive_fields());
    assert!(!VersionClass::Patch.allows_breaking_changes());
}

#[test]
fn version_class_permissions_minor() {
    assert!(VersionClass::Minor.allows_additive_fields());
    assert!(!VersionClass::Minor.allows_breaking_changes());
}

#[test]
fn version_class_permissions_major() {
    assert!(VersionClass::Major.allows_additive_fields());
    assert!(VersionClass::Major.allows_breaking_changes());
}

#[test]
fn version_class_display_and_as_str() {
    for vc in [
        VersionClass::Patch,
        VersionClass::Minor,
        VersionClass::Major,
    ] {
        assert_eq!(vc.as_str(), vc.to_string());
    }
}

#[test]
fn version_class_serde_round_trip() {
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

// ===========================================================================
// Section 4: SemanticVersion
// ===========================================================================

#[test]
fn semantic_version_new_and_fields() {
    let v = SemanticVersion::new(3, 14, 159);
    assert_eq!(v.major, 3);
    assert_eq!(v.minor, 14);
    assert_eq!(v.patch, 159);
}

#[test]
fn semantic_version_display() {
    assert_eq!(SemanticVersion::new(0, 0, 0).to_string(), "0.0.0");
    assert_eq!(SemanticVersion::new(1, 2, 3).to_string(), "1.2.3");
    assert_eq!(
        SemanticVersion::new(100, 200, 300).to_string(),
        "100.200.300"
    );
}

#[test]
fn semantic_version_ordering() {
    let v100 = SemanticVersion::new(1, 0, 0);
    let v110 = SemanticVersion::new(1, 1, 0);
    let v111 = SemanticVersion::new(1, 1, 1);
    let v200 = SemanticVersion::new(2, 0, 0);
    assert!(v100 < v110);
    assert!(v110 < v111);
    assert!(v111 < v200);
}

#[test]
fn semantic_version_equality() {
    let a = SemanticVersion::new(1, 2, 3);
    let b = SemanticVersion::new(1, 2, 3);
    assert_eq!(a, b);
}

#[test]
fn semantic_version_serde_round_trip() {
    let v = SemanticVersion::new(7, 8, 9);
    let json = serde_json::to_string(&v).unwrap();
    let decoded: SemanticVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
}

// ===========================================================================
// Section 5: VersionCompatibility and negotiate_version
// ===========================================================================

#[test]
fn negotiate_exact() {
    let v = SemanticVersion::new(1, 2, 3);
    assert_eq!(negotiate_version(v, v), VersionCompatibility::Exact);
}

#[test]
fn negotiate_patch_level() {
    let a = SemanticVersion::new(1, 2, 3);
    let b = SemanticVersion::new(1, 2, 7);
    assert_eq!(
        negotiate_version(a, b),
        VersionCompatibility::PatchCompatible
    );
}

#[test]
fn negotiate_minor_level() {
    let a = SemanticVersion::new(1, 2, 3);
    let b = SemanticVersion::new(1, 5, 0);
    assert_eq!(
        negotiate_version(a, b),
        VersionCompatibility::MinorCompatible
    );
}

#[test]
fn negotiate_major_level() {
    let a = SemanticVersion::new(1, 2, 3);
    let b = SemanticVersion::new(3, 0, 0);
    assert_eq!(
        negotiate_version(a, b),
        VersionCompatibility::MajorIncompatible
    );
}

#[test]
fn negotiate_symmetric_for_patch_and_minor() {
    let a = SemanticVersion::new(1, 2, 3);
    let b = SemanticVersion::new(1, 2, 9);
    assert_eq!(negotiate_version(a, b), negotiate_version(b, a));

    let c = SemanticVersion::new(1, 5, 0);
    assert_eq!(negotiate_version(a, c), negotiate_version(c, a));
}

#[test]
fn version_compatibility_is_compatible() {
    assert!(VersionCompatibility::Exact.is_compatible());
    assert!(VersionCompatibility::PatchCompatible.is_compatible());
    assert!(VersionCompatibility::MinorCompatible.is_compatible());
    assert!(!VersionCompatibility::MajorIncompatible.is_compatible());
}

#[test]
fn version_compatibility_display_all_unique() {
    let variants = [
        VersionCompatibility::Exact,
        VersionCompatibility::PatchCompatible,
        VersionCompatibility::MinorCompatible,
        VersionCompatibility::MajorIncompatible,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn version_compatibility_serde_round_trip() {
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

// ===========================================================================
// Section 6: FieldVersionCoverage
// ===========================================================================

#[test]
fn field_version_coverage_serde_round_trip() {
    let fvc = FieldVersionCoverage {
        field_name: "trace_id".to_string(),
        protected_at: VersionClass::Major,
        required: true,
    };
    let json = serde_json::to_string(&fvc).unwrap();
    let decoded: FieldVersionCoverage = serde_json::from_str(&json).unwrap();
    assert_eq!(fvc, decoded);
}

#[test]
fn field_version_coverage_optional_field() {
    let fvc = FieldVersionCoverage {
        field_name: "optional_tag".to_string(),
        protected_at: VersionClass::Minor,
        required: false,
    };
    assert!(!fvc.required);
    assert_eq!(fvc.protected_at, VersionClass::Minor);
}

// ===========================================================================
// Section 7: VersionNegotiationResult
// ===========================================================================

#[test]
fn version_negotiation_result_serde_round_trip() {
    let result = VersionNegotiationResult {
        boundary: SiblingRepo::Frankentui,
        local_version: SemanticVersion::new(1, 0, 0),
        remote_version: SemanticVersion::new(1, 1, 0),
        compatibility: VersionCompatibility::MinorCompatible,
        migration_required: false,
        migration_path: None,
    };
    let json = serde_json::to_vec(&result).unwrap();
    let decoded: VersionNegotiationResult = serde_json::from_slice(&json).unwrap();
    assert_eq!(result, decoded);
}

#[test]
fn version_negotiation_result_with_migration() {
    let result = VersionNegotiationResult {
        boundary: SiblingRepo::Frankensqlite,
        local_version: SemanticVersion::new(1, 0, 0),
        remote_version: SemanticVersion::new(2, 0, 0),
        compatibility: VersionCompatibility::MajorIncompatible,
        migration_required: true,
        migration_path: Some("v1_to_v2_migration".to_string()),
    };
    assert!(result.migration_required);
    assert!(result.migration_path.is_some());
    // round-trip
    let json = serde_json::to_string(&result).unwrap();
    let decoded: VersionNegotiationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, decoded);
}

// ===========================================================================
// Section 8: FailureSeverity and RequiredResponse
// ===========================================================================

#[test]
fn failure_severity_ordering() {
    assert!(FailureSeverity::Info < FailureSeverity::Warning);
    assert!(FailureSeverity::Warning < FailureSeverity::Error);
    assert!(FailureSeverity::Error < FailureSeverity::Critical);
}

#[test]
fn failure_severity_display_and_as_str() {
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
fn required_response_display_and_as_str() {
    for rr in [
        RequiredResponse::Log,
        RequiredResponse::Warn,
        RequiredResponse::Block,
    ] {
        assert_eq!(rr.as_str(), rr.to_string());
    }
}

#[test]
fn required_response_serde_round_trip() {
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

// ===========================================================================
// Section 9: FailureTaxonomy and classify_failure
// ===========================================================================

#[test]
fn failure_taxonomy_has_four_entries() {
    let taxonomy = failure_taxonomy();
    assert_eq!(taxonomy.len(), 4);
}

#[test]
fn failure_taxonomy_covers_all_regression_classes() {
    let taxonomy = failure_taxonomy();
    let classes: BTreeSet<RegressionClass> = taxonomy.iter().map(|t| t.regression_class).collect();
    assert!(classes.contains(&RegressionClass::Breaking));
    assert!(classes.contains(&RegressionClass::Behavioral));
    assert!(classes.contains(&RegressionClass::Observability));
    assert!(classes.contains(&RegressionClass::Performance));
}

#[test]
fn failure_taxonomy_breaking_is_critical_block() {
    let taxonomy = failure_taxonomy();
    let breaking = taxonomy
        .iter()
        .find(|t| t.regression_class == RegressionClass::Breaking)
        .unwrap();
    assert_eq!(breaking.severity, FailureSeverity::Critical);
    assert_eq!(breaking.required_response, RequiredResponse::Block);
}

#[test]
fn failure_taxonomy_evidence_non_empty() {
    let taxonomy = failure_taxonomy();
    for entry in &taxonomy {
        assert!(!entry.evidence_requirements.is_empty());
    }
}

#[test]
fn failure_taxonomy_serde_round_trip() {
    let taxonomy = failure_taxonomy();
    let json = serde_json::to_vec(&taxonomy).unwrap();
    let decoded: Vec<FailureTaxonomyEntry> = serde_json::from_slice(&json).unwrap();
    assert_eq!(taxonomy, decoded);
}

#[test]
fn classify_failure_finds_breaking() {
    let taxonomy = failure_taxonomy();
    let entry = classify_failure(&taxonomy, RegressionClass::Breaking);
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().severity, FailureSeverity::Critical);
}

#[test]
fn classify_failure_finds_performance() {
    let taxonomy = failure_taxonomy();
    let entry = classify_failure(&taxonomy, RegressionClass::Performance);
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().required_response, RequiredResponse::Log);
}

#[test]
fn classify_failure_empty_taxonomy_returns_none() {
    let empty: Vec<FailureTaxonomyEntry> = Vec::new();
    assert!(classify_failure(&empty, RegressionClass::Breaking).is_none());
}

// ===========================================================================
// Section 10: ReplayObligation and ReplayArtifact
// ===========================================================================

#[test]
fn replay_obligation_standard_all_flags_set() {
    let obl = ReplayObligation::standard("t1", SiblingRepo::Asupersync);
    assert!(obl.must_pin_versions);
    assert!(obl.must_provide_seed);
    assert!(obl.must_capture_input);
    assert!(obl.must_hash_output);
    assert_eq!(obl.test_id, "t1");
    assert_eq!(obl.boundary, SiblingRepo::Asupersync);
}

#[test]
fn replay_obligation_verify_valid() {
    let obl = ReplayObligation::standard("t1", SiblingRepo::Asupersync);
    let artifact = make_valid_artifact("t1", SiblingRepo::Asupersync);
    let errors = obl.verify(&artifact);
    assert!(errors.is_empty(), "unexpected errors: {errors:?}");
}

#[test]
fn replay_obligation_verify_empty_pinned_versions() {
    let obl = ReplayObligation::standard("t1", SiblingRepo::Asupersync);
    let mut artifact = make_valid_artifact("t1", SiblingRepo::Asupersync);
    artifact.pinned_versions = BTreeMap::new();
    let errors = obl.verify(&artifact);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("pinned_versions"));
}

#[test]
fn replay_obligation_verify_zero_seed() {
    let obl = ReplayObligation::standard("t1", SiblingRepo::Asupersync);
    let mut artifact = make_valid_artifact("t1", SiblingRepo::Asupersync);
    artifact.deterministic_seed = 0;
    let errors = obl.verify(&artifact);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("deterministic_seed"));
}

#[test]
fn replay_obligation_verify_empty_input_snapshot() {
    let obl = ReplayObligation::standard("t1", SiblingRepo::Asupersync);
    let mut artifact = make_valid_artifact("t1", SiblingRepo::Asupersync);
    artifact.input_snapshot = vec![];
    let errors = obl.verify(&artifact);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("input_snapshot"));
}

#[test]
fn replay_obligation_verify_empty_output_hash() {
    let obl = ReplayObligation::standard("t1", SiblingRepo::Asupersync);
    let mut artifact = make_valid_artifact("t1", SiblingRepo::Asupersync);
    artifact.expected_output_hash = String::new();
    let errors = obl.verify(&artifact);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("expected_output_hash"));
}

#[test]
fn replay_obligation_verify_test_id_mismatch() {
    let obl = ReplayObligation::standard("t1", SiblingRepo::Asupersync);
    let artifact = make_valid_artifact("t2", SiblingRepo::Asupersync);
    let errors = obl.verify(&artifact);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("test_id mismatch"));
}

#[test]
fn replay_obligation_verify_boundary_mismatch() {
    let obl = ReplayObligation::standard("t1", SiblingRepo::Asupersync);
    let artifact = make_valid_artifact("t1", SiblingRepo::Frankentui);
    let errors = obl.verify(&artifact);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("boundary mismatch"));
}

#[test]
fn replay_obligation_verify_multiple_errors() {
    let obl = ReplayObligation::standard("t1", SiblingRepo::Asupersync);
    let artifact = ReplayArtifact {
        test_id: "wrong".to_string(),
        boundary: SiblingRepo::Frankentui,
        deterministic_seed: 0,
        pinned_versions: BTreeMap::new(),
        input_snapshot: vec![],
        expected_output_hash: String::new(),
        reproduction_command: "cargo test".to_string(),
    };
    let errors = obl.verify(&artifact);
    // pinned_versions, seed, input, hash, test_id, boundary = 6 errors
    assert_eq!(errors.len(), 6);
}

#[test]
fn replay_obligation_relaxed_flags() {
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
    assert!(errors.is_empty());
}

#[test]
fn replay_artifact_serde_round_trip() {
    let artifact = make_valid_artifact("t1", SiblingRepo::Frankensqlite);
    let json = serde_json::to_vec(&artifact).unwrap();
    let decoded: ReplayArtifact = serde_json::from_slice(&json).unwrap();
    assert_eq!(artifact, decoded);
}

#[test]
fn replay_obligation_serde_round_trip() {
    let obl = ReplayObligation::standard("t1", SiblingRepo::Frankentui);
    let json = serde_json::to_vec(&obl).unwrap();
    let decoded: ReplayObligation = serde_json::from_slice(&json).unwrap();
    assert_eq!(obl, decoded);
}

// ===========================================================================
// Section 11: CatalogEntry and ConformanceVector
// ===========================================================================

#[test]
fn catalog_entry_has_required_vectors_both() {
    let entry = make_entry("e1", SiblingRepo::Asupersync);
    assert!(entry.has_required_vectors());
}

#[test]
fn catalog_entry_no_positive_vectors() {
    let mut entry = make_entry("e1", SiblingRepo::Asupersync);
    entry.positive_vectors.clear();
    assert!(!entry.has_required_vectors());
}

#[test]
fn catalog_entry_no_negative_vectors() {
    let mut entry = make_entry("e1", SiblingRepo::Asupersync);
    entry.negative_vectors.clear();
    assert!(!entry.has_required_vectors());
}

#[test]
fn conformance_vector_serde_round_trip() {
    let v = make_vector("v1", true);
    let json = serde_json::to_string(&v).unwrap();
    let decoded: ConformanceVector = serde_json::from_str(&json).unwrap();
    assert_eq!(v, decoded);
}

// ===========================================================================
// Section 12: ConformanceCatalog core methods
// ===========================================================================

#[test]
fn catalog_new_starts_empty() {
    let catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    assert!(catalog.entries.is_empty());
    assert!(!catalog.taxonomy.is_empty()); // populated from failure_taxonomy()
    assert!(catalog.change_log.is_empty());
    assert_eq!(catalog.catalog_version, SemanticVersion::new(1, 0, 0));
}

#[test]
fn catalog_add_entry_records_change() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(make_entry("e1", SiblingRepo::Asupersync));
    assert_eq!(catalog.entries.len(), 1);
    assert_eq!(catalog.change_log.len(), 1);
    assert_eq!(catalog.change_log[0].change_kind, ChangeKind::EntryAdded);
    assert!(
        catalog.change_log[0]
            .affected_entries
            .contains(&"e1".to_string())
    );
}

#[test]
fn catalog_get_entry_found() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(make_entry("e1", SiblingRepo::Asupersync));
    assert!(catalog.get_entry("e1").is_some());
    assert_eq!(catalog.get_entry("e1").unwrap().entry_id, "e1");
}

#[test]
fn catalog_get_entry_missing() {
    let catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    assert!(catalog.get_entry("nonexistent").is_none());
}

#[test]
fn catalog_entries_for_boundary() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(make_entry("e1", SiblingRepo::Asupersync));
    catalog.add_entry(make_entry("e2", SiblingRepo::Asupersync));
    catalog.add_entry(make_entry("e3", SiblingRepo::Frankentui));

    let asupersync_entries = catalog.entries_for_boundary(SiblingRepo::Asupersync);
    assert_eq!(asupersync_entries.len(), 2);
    let frankentui_entries = catalog.entries_for_boundary(SiblingRepo::Frankentui);
    assert_eq!(frankentui_entries.len(), 1);
    let sqlite_entries = catalog.entries_for_boundary(SiblingRepo::Frankensqlite);
    assert_eq!(sqlite_entries.len(), 0);
}

#[test]
fn catalog_covered_boundaries() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(make_entry("e1", SiblingRepo::Asupersync));
    catalog.add_entry(make_entry("e2", SiblingRepo::Frankentui));
    let covered = catalog.covered_boundaries();
    assert_eq!(covered.len(), 2);
    assert!(covered.contains(&SiblingRepo::Asupersync));
    assert!(covered.contains(&SiblingRepo::Frankentui));
}

#[test]
fn catalog_entries_by_class() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(make_entry("e1", SiblingRepo::Asupersync));
    catalog.add_entry(make_entry("e2", SiblingRepo::Frankentui));
    let counts = catalog.entries_by_class();
    let total: usize = counts.values().sum();
    assert_eq!(total, 2);
}

#[test]
fn catalog_validate_vector_coverage_clean() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(make_entry("e1", SiblingRepo::Asupersync));
    let errors = catalog.validate_vector_coverage();
    assert!(errors.is_empty());
}

#[test]
fn catalog_validate_vector_coverage_detects_missing() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    let mut entry = make_entry("e1", SiblingRepo::Asupersync);
    entry.positive_vectors.clear();
    entry.negative_vectors.clear();
    catalog.entries.push(entry); // bypass add_entry to avoid change log noise
    let errors = catalog.validate_vector_coverage();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("e1"));
}

#[test]
fn catalog_serde_round_trip() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(2, 0, 0));
    catalog.add_entry(make_entry("e1", SiblingRepo::Asupersync));
    let json = serde_json::to_vec(&catalog).unwrap();
    let decoded: ConformanceCatalog = serde_json::from_slice(&json).unwrap();
    assert_eq!(catalog, decoded);
}

// ===========================================================================
// Section 13: ChangeKind and CatalogChangeRecord
// ===========================================================================

#[test]
fn change_kind_display_all_variants() {
    let expected = [
        (ChangeKind::EntryAdded, "entry_added"),
        (ChangeKind::EntryModified, "entry_modified"),
        (ChangeKind::EntryRemoved, "entry_removed"),
        (ChangeKind::TaxonomyUpdated, "taxonomy_updated"),
        (ChangeKind::VectorAdded, "vector_added"),
        (ChangeKind::VectorRemoved, "vector_removed"),
    ];
    for (kind, text) in &expected {
        assert_eq!(kind.to_string(), *text);
    }
}

#[test]
fn change_kind_serde_round_trip() {
    for kind in [
        ChangeKind::EntryAdded,
        ChangeKind::EntryModified,
        ChangeKind::EntryRemoved,
        ChangeKind::TaxonomyUpdated,
        ChangeKind::VectorAdded,
        ChangeKind::VectorRemoved,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let decoded: ChangeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, decoded);
    }
}

#[test]
fn catalog_change_record_serde_round_trip() {
    let record = CatalogChangeRecord {
        version: SemanticVersion::new(1, 0, 0),
        description: "added new entry".to_string(),
        affected_entries: vec!["e1".to_string(), "e2".to_string()],
        change_kind: ChangeKind::EntryAdded,
    };
    let json = serde_json::to_string(&record).unwrap();
    let decoded: CatalogChangeRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, decoded);
}

// ===========================================================================
// Section 14: CatalogValidationError and validate_catalog
// ===========================================================================

#[test]
fn catalog_validation_error_display_with_entry_id() {
    let err = CatalogValidationError {
        entry_id: Some("test/entry".to_string()),
        field: "vector_id".to_string(),
        detail: "duplicate".to_string(),
    };
    assert_eq!(err.to_string(), "[test/entry] vector_id: duplicate");
}

#[test]
fn catalog_validation_error_display_without_entry_id() {
    let err = CatalogValidationError {
        entry_id: None,
        field: "taxonomy".to_string(),
        detail: "missing class".to_string(),
    };
    assert_eq!(err.to_string(), "[catalog] taxonomy: missing class");
}

#[test]
fn catalog_validation_error_serde_round_trip() {
    let err = CatalogValidationError {
        entry_id: Some("e1".to_string()),
        field: "field".to_string(),
        detail: "detail".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let decoded: CatalogValidationError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, decoded);
}

#[test]
fn validate_catalog_clean_catalog() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(make_entry("e1", SiblingRepo::Asupersync));
    let errors = validate_catalog(&catalog);
    assert!(errors.is_empty(), "unexpected errors: {errors:?}");
}

#[test]
fn validate_catalog_detects_missing_vectors() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    let mut entry = make_entry("e1", SiblingRepo::Asupersync);
    entry.positive_vectors.clear();
    entry.negative_vectors.clear();
    catalog.add_entry(entry);
    let errors = validate_catalog(&catalog);
    assert!(errors.iter().any(|e| e.field == "vector_coverage"));
}

#[test]
fn validate_catalog_detects_duplicate_entry_ids() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(make_entry("e1", SiblingRepo::Asupersync));
    // Push a duplicate directly
    catalog
        .entries
        .push(make_entry("e1", SiblingRepo::Frankentui));
    let errors = validate_catalog(&catalog);
    assert!(
        errors
            .iter()
            .any(|e| e.detail.contains("duplicate entry ID"))
    );
}

#[test]
fn validate_catalog_detects_empty_covered_fields() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    let mut entry = make_entry("e1", SiblingRepo::Asupersync);
    entry.boundary.covered_fields = BTreeSet::new();
    catalog.add_entry(entry);
    let errors = validate_catalog(&catalog);
    assert!(errors.iter().any(|e| e.field == "covered_fields"));
}

#[test]
fn validate_catalog_detects_duplicate_vector_ids() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    let mut entry = make_entry("e1", SiblingRepo::Asupersync);
    // Add a positive vector with the same ID as the negative vector
    let dup = entry.negative_vectors[0].clone();
    entry.positive_vectors.push(dup);
    catalog.add_entry(entry);
    let errors = validate_catalog(&catalog);
    assert!(
        errors
            .iter()
            .any(|e| e.detail.contains("duplicate vector ID"))
    );
}

#[test]
fn validate_catalog_missing_taxonomy_class() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(make_entry("e1", SiblingRepo::Asupersync));
    // Remove one taxonomy entry
    catalog
        .taxonomy
        .retain(|t| t.regression_class != RegressionClass::Performance);
    let errors = validate_catalog(&catalog);
    assert!(
        errors
            .iter()
            .any(|e| e.field == "taxonomy" && e.detail.contains("PERFORMANCE"))
    );
}

// ===========================================================================
// Section 15: canonical_boundary_surfaces
// ===========================================================================

#[test]
fn canonical_surfaces_cover_all_siblings() {
    let surfaces = canonical_boundary_surfaces();
    let siblings: BTreeSet<SiblingRepo> = surfaces.iter().map(|s| s.sibling).collect();
    for repo in SiblingRepo::all() {
        assert!(siblings.contains(repo), "missing sibling: {repo}");
    }
}

#[test]
fn canonical_surfaces_unique_ids() {
    let surfaces = canonical_boundary_surfaces();
    let mut seen = BTreeSet::new();
    for surface in &surfaces {
        assert!(
            seen.insert(&surface.surface_id),
            "duplicate: {}",
            surface.surface_id
        );
    }
}

#[test]
fn canonical_surfaces_non_empty_covered_fields() {
    for surface in &canonical_boundary_surfaces() {
        assert!(
            !surface.covered_fields.is_empty(),
            "empty fields in {}",
            surface.surface_id
        );
    }
}

#[test]
fn canonical_surfaces_count() {
    let surfaces = canonical_boundary_surfaces();
    // 3 asupersync + 2 frankentui + 3 frankensqlite + 1 franken_node + 2 fastapi_rust + 1 sqlmodel_rust = 12
    assert_eq!(surfaces.len(), 12);
}

// ===========================================================================
// Section 16: build_canonical_catalog
// ===========================================================================

#[test]
fn canonical_catalog_validates_clean() {
    let catalog = build_canonical_catalog();
    let errors = validate_catalog(&catalog);
    assert!(errors.is_empty(), "validation errors: {errors:?}");
}

#[test]
fn canonical_catalog_entries_match_surfaces() {
    let catalog = build_canonical_catalog();
    let surfaces = canonical_boundary_surfaces();
    assert_eq!(catalog.entries.len(), surfaces.len());
}

#[test]
fn canonical_catalog_all_entries_approved() {
    let catalog = build_canonical_catalog();
    for entry in &catalog.entries {
        assert!(entry.approved, "entry {} not approved", entry.entry_id);
        assert_eq!(entry.approval_epoch, Some(1));
    }
}

#[test]
fn canonical_catalog_changelog_matches_entries() {
    let catalog = build_canonical_catalog();
    assert_eq!(catalog.change_log.len(), catalog.entries.len());
    for record in &catalog.change_log {
        assert_eq!(record.change_kind, ChangeKind::EntryAdded);
    }
}

#[test]
fn canonical_catalog_taxonomy_has_four_entries() {
    let catalog = build_canonical_catalog();
    assert_eq!(catalog.taxonomy.len(), 4);
}

#[test]
fn canonical_catalog_entries_by_class_totals() {
    let catalog = build_canonical_catalog();
    let counts = catalog.entries_by_class();
    let total: usize = counts.values().sum();
    assert_eq!(total, catalog.entries.len());
}

#[test]
fn canonical_catalog_major_surfaces_map_to_breaking() {
    let catalog = build_canonical_catalog();
    for entry in &catalog.entries {
        if entry.boundary.version_class == VersionClass::Major {
            assert_eq!(entry.failure_class, RegressionClass::Breaking);
        }
    }
}

#[test]
fn canonical_catalog_minor_surfaces_map_to_behavioral() {
    let catalog = build_canonical_catalog();
    for entry in &catalog.entries {
        if entry.boundary.version_class == VersionClass::Minor {
            assert_eq!(entry.failure_class, RegressionClass::Behavioral);
        }
    }
}

#[test]
fn canonical_catalog_patch_surfaces_map_to_observability() {
    let catalog = build_canonical_catalog();
    for entry in &catalog.entries {
        if entry.boundary.version_class == VersionClass::Patch {
            assert_eq!(entry.failure_class, RegressionClass::Observability);
        }
    }
}

#[test]
fn canonical_catalog_serde_round_trip() {
    let catalog = build_canonical_catalog();
    let json = serde_json::to_vec(&catalog).unwrap();
    let decoded: ConformanceCatalog = serde_json::from_slice(&json).unwrap();
    assert_eq!(catalog, decoded);
}

// ===========================================================================
// Section 17: BoundarySurface serde
// ===========================================================================

#[test]
fn boundary_surface_serde_round_trip() {
    let surface = make_surface(
        SiblingRepo::Frankensqlite,
        "sqlite/test",
        SurfaceKind::PersistenceSemantics,
        VersionClass::Major,
    );
    let json = serde_json::to_string(&surface).unwrap();
    let decoded: BoundarySurface = serde_json::from_str(&json).unwrap();
    assert_eq!(surface, decoded);
}

// ===========================================================================
// Section 18: Integration workflows
// ===========================================================================

#[test]
fn full_lifecycle_create_add_lookup_validate() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(0, 1, 0));

    // Add entries for two boundaries
    catalog.add_entry(make_entry("alpha/test", SiblingRepo::Asupersync));
    catalog.add_entry(make_entry("beta/test", SiblingRepo::Frankentui));

    // Look up
    assert!(catalog.get_entry("alpha/test").is_some());
    assert!(catalog.get_entry("beta/test").is_some());
    assert!(catalog.get_entry("gamma/test").is_none());

    // Boundary filter
    let asup = catalog.entries_for_boundary(SiblingRepo::Asupersync);
    assert_eq!(asup.len(), 1);

    // Covered boundaries
    let covered = catalog.covered_boundaries();
    assert_eq!(covered.len(), 2);

    // Validate
    let errors = validate_catalog(&catalog);
    assert!(errors.is_empty(), "errors: {errors:?}");
}

#[test]
fn version_negotiation_across_all_boundaries() {
    let local = SemanticVersion::new(1, 0, 0);
    for repo in SiblingRepo::all() {
        let remote_compat = SemanticVersion::new(1, 0, 1);
        let result = negotiate_version(local, remote_compat);
        assert!(
            result.is_compatible(),
            "patch for {repo} should be compatible"
        );

        let remote_break = SemanticVersion::new(2, 0, 0);
        let result = negotiate_version(local, remote_break);
        assert!(
            !result.is_compatible(),
            "major for {repo} should be incompatible"
        );
    }
}

#[test]
fn catalog_entry_serde_round_trip() {
    let entry = make_entry("serde/test", SiblingRepo::FrankenNode);
    let json = serde_json::to_vec(&entry).unwrap();
    let decoded: CatalogEntry = serde_json::from_slice(&json).unwrap();
    assert_eq!(entry, decoded);
}
