//! Enrichment integration tests for the `conformance_catalog` module.
//!
//! Covers Copy/Clone semantics, BTreeSet ordering, serde roundtrips, Display
//! coverage, Debug nonempty, as_str coverage, version negotiation, failure
//! taxonomy, replay obligations, catalog lifecycle, JSON field-name stability,
//! and determinism.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::conformance_catalog::{
    BoundarySurface, CatalogChangeRecord, CatalogEntry, ChangeKind, ConformanceCatalog,
    ConformanceVector, FailureSeverity, FailureTaxonomyEntry, FieldVersionCoverage, ReplayArtifact,
    ReplayObligation, RequiredResponse, SemanticVersion, SiblingRepo, SurfaceKind, VersionClass,
    VersionCompatibility, VersionNegotiationResult, canonical_boundary_surfaces, classify_failure,
    failure_taxonomy, negotiate_version,
};
use frankenengine_engine::cross_repo_contract::RegressionClass;

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn test_boundary_surface() -> BoundarySurface {
    BoundarySurface {
        sibling: SiblingRepo::Asupersync,
        surface_id: "test/surface".to_string(),
        surface_kind: SurfaceKind::ApiMessage,
        description: "test boundary".to_string(),
        covered_fields: {
            let mut s = BTreeSet::new();
            s.insert("field_a".to_string());
            s.insert("field_b".to_string());
            s
        },
        version_class: VersionClass::Minor,
    }
}

fn test_conformance_vector(id: &str, pass: bool) -> ConformanceVector {
    ConformanceVector {
        vector_id: id.to_string(),
        description: format!("Vector {id}"),
        input_json: r#"{"key": "value"}"#.to_string(),
        expected_pass: pass,
        expected_regression_class: if pass {
            None
        } else {
            Some(RegressionClass::Breaking)
        },
    }
}

fn test_replay_obligation(test_id: &str) -> ReplayObligation {
    ReplayObligation::standard(test_id, SiblingRepo::Asupersync)
}

fn test_replay_artifact(test_id: &str) -> ReplayArtifact {
    let mut pinned = BTreeMap::new();
    pinned.insert("dep".to_string(), SemanticVersion::new(1, 0, 0));
    ReplayArtifact {
        test_id: test_id.to_string(),
        boundary: SiblingRepo::Asupersync,
        deterministic_seed: 42,
        pinned_versions: pinned,
        input_snapshot: vec![1, 2, 3],
        expected_output_hash: "abc123".to_string(),
        reproduction_command: "cargo test".to_string(),
    }
}

fn test_catalog_entry(id: &str) -> CatalogEntry {
    CatalogEntry {
        entry_id: id.to_string(),
        boundary: test_boundary_surface(),
        positive_vectors: vec![test_conformance_vector("pos-1", true)],
        negative_vectors: vec![test_conformance_vector("neg-1", false)],
        replay_obligation: test_replay_obligation(id),
        failure_class: RegressionClass::Breaking,
        approved: true,
        approval_epoch: Some(1),
    }
}

// -----------------------------------------------------------------------
// Copy semantics
// -----------------------------------------------------------------------

#[test]
fn enrichment_sibling_repo_copy() {
    let original = SiblingRepo::Asupersync;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_surface_kind_copy() {
    let original = SurfaceKind::ApiMessage;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_version_class_copy() {
    let original = VersionClass::Minor;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_failure_severity_copy() {
    let original = FailureSeverity::Critical;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_required_response_copy() {
    let original = RequiredResponse::Block;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_version_compatibility_copy() {
    let original = VersionCompatibility::Exact;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_change_kind_copy() {
    let original = ChangeKind::EntryAdded;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_semantic_version_copy() {
    let original = SemanticVersion::new(1, 2, 3);
    let copied = original;
    assert_eq!(original, copied);
}

// -----------------------------------------------------------------------
// Clone independence
// -----------------------------------------------------------------------

#[test]
fn enrichment_boundary_surface_clone_independence() {
    let original = test_boundary_surface();
    let mut cloned = original.clone();
    cloned.surface_id = "mutated".to_string();
    cloned.sibling = SiblingRepo::Frankentui;
    assert_eq!(original.surface_id, "test/surface");
    assert_eq!(original.sibling, SiblingRepo::Asupersync);
}

#[test]
fn enrichment_catalog_entry_clone_independence() {
    let original = test_catalog_entry("orig");
    let mut cloned = original.clone();
    cloned.entry_id = "mutated".to_string();
    cloned.approved = false;
    assert_eq!(original.entry_id, "orig");
    assert!(original.approved);
}

#[test]
fn enrichment_conformance_catalog_clone_independence() {
    let mut original = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    original.add_entry(test_catalog_entry("e1"));
    let mut cloned = original.clone();
    cloned.add_entry(test_catalog_entry("e2"));
    assert_eq!(original.entries.len(), 1);
    assert_eq!(cloned.entries.len(), 2);
}

#[test]
fn enrichment_replay_obligation_clone_independence() {
    let original = test_replay_obligation("t1");
    let mut cloned = original.clone();
    cloned.must_pin_versions = false;
    assert!(original.must_pin_versions);
}

// -----------------------------------------------------------------------
// BTreeSet ordering and dedup
// -----------------------------------------------------------------------

#[test]
fn enrichment_sibling_repo_btreeset_ordering() {
    let mut set = BTreeSet::new();
    for repo in SiblingRepo::all() {
        set.insert(*repo);
    }
    assert_eq!(set.len(), SiblingRepo::all().len());
}

#[test]
fn enrichment_sibling_repo_btreeset_dedup() {
    let mut set = BTreeSet::new();
    set.insert(SiblingRepo::Asupersync);
    set.insert(SiblingRepo::Asupersync);
    set.insert(SiblingRepo::Frankentui);
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_surface_kind_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(SurfaceKind::TelemetrySchema);
    set.insert(SurfaceKind::IdentifierSchema);
    set.insert(SurfaceKind::ApiMessage);
    let items: Vec<_> = set.iter().collect();
    assert!(items[0] <= items[1]);
    assert!(items[1] <= items[2]);
}

#[test]
fn enrichment_failure_severity_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(FailureSeverity::Critical);
    set.insert(FailureSeverity::Info);
    set.insert(FailureSeverity::Warning);
    set.insert(FailureSeverity::Error);
    let items: Vec<_> = set.iter().collect();
    assert_eq!(*items[0], FailureSeverity::Info);
    assert_eq!(*items[3], FailureSeverity::Critical);
}

// -----------------------------------------------------------------------
// Serde roundtrips
// -----------------------------------------------------------------------

#[test]
fn enrichment_sibling_repo_serde_all() {
    for repo in SiblingRepo::all() {
        let json = serde_json::to_string(repo).unwrap();
        let restored: SiblingRepo = serde_json::from_str(&json).unwrap();
        assert_eq!(*repo, restored);
    }
}

#[test]
fn enrichment_surface_kind_serde_all() {
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
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let restored: SurfaceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, restored);
    }
}

#[test]
fn enrichment_version_class_serde_all() {
    for vc in [
        VersionClass::Patch,
        VersionClass::Minor,
        VersionClass::Major,
    ] {
        let json = serde_json::to_string(&vc).unwrap();
        let restored: VersionClass = serde_json::from_str(&json).unwrap();
        assert_eq!(vc, restored);
    }
}

#[test]
fn enrichment_failure_severity_serde_all() {
    for sev in [
        FailureSeverity::Info,
        FailureSeverity::Warning,
        FailureSeverity::Error,
        FailureSeverity::Critical,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let restored: FailureSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, restored);
    }
}

#[test]
fn enrichment_required_response_serde_all() {
    for rr in [
        RequiredResponse::Log,
        RequiredResponse::Warn,
        RequiredResponse::Block,
    ] {
        let json = serde_json::to_string(&rr).unwrap();
        let restored: RequiredResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(rr, restored);
    }
}

#[test]
fn enrichment_version_compatibility_serde_all() {
    for vc in [
        VersionCompatibility::Exact,
        VersionCompatibility::PatchCompatible,
        VersionCompatibility::MinorCompatible,
        VersionCompatibility::MajorIncompatible,
    ] {
        let json = serde_json::to_string(&vc).unwrap();
        let restored: VersionCompatibility = serde_json::from_str(&json).unwrap();
        assert_eq!(vc, restored);
    }
}

#[test]
fn enrichment_change_kind_serde_all() {
    for ck in [
        ChangeKind::EntryAdded,
        ChangeKind::EntryModified,
        ChangeKind::EntryRemoved,
        ChangeKind::TaxonomyUpdated,
        ChangeKind::VectorAdded,
        ChangeKind::VectorRemoved,
    ] {
        let json = serde_json::to_string(&ck).unwrap();
        let restored: ChangeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(ck, restored);
    }
}

#[test]
fn enrichment_semantic_version_serde_roundtrip() {
    let v = SemanticVersion::new(2, 3, 4);
    let json = serde_json::to_string(&v).unwrap();
    let restored: SemanticVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

#[test]
fn enrichment_boundary_surface_serde_roundtrip() {
    let bs = test_boundary_surface();
    let json = serde_json::to_string(&bs).unwrap();
    let restored: BoundarySurface = serde_json::from_str(&json).unwrap();
    assert_eq!(bs, restored);
}

#[test]
fn enrichment_conformance_vector_serde_roundtrip() {
    let v = test_conformance_vector("cv-serde", true);
    let json = serde_json::to_string(&v).unwrap();
    let restored: ConformanceVector = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

#[test]
fn enrichment_replay_artifact_serde_roundtrip() {
    let ra = test_replay_artifact("ra-serde");
    let json = serde_json::to_string(&ra).unwrap();
    let restored: ReplayArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(ra, restored);
}

#[test]
fn enrichment_replay_obligation_serde_roundtrip() {
    let ro = test_replay_obligation("ro-serde");
    let json = serde_json::to_string(&ro).unwrap();
    let restored: ReplayObligation = serde_json::from_str(&json).unwrap();
    assert_eq!(ro, restored);
}

#[test]
fn enrichment_catalog_entry_serde_roundtrip() {
    let entry = test_catalog_entry("ce-serde");
    let json = serde_json::to_string(&entry).unwrap();
    let restored: CatalogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, restored);
}

#[test]
fn enrichment_failure_taxonomy_entry_serde_roundtrip() {
    let taxonomy = failure_taxonomy();
    for t in &taxonomy {
        let json = serde_json::to_string(t).unwrap();
        let restored: FailureTaxonomyEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, restored);
    }
}

#[test]
fn enrichment_field_version_coverage_serde_roundtrip() {
    let fvc = FieldVersionCoverage {
        field_name: "test_field".to_string(),
        protected_at: VersionClass::Minor,
        required: true,
    };
    let json = serde_json::to_string(&fvc).unwrap();
    let restored: FieldVersionCoverage = serde_json::from_str(&json).unwrap();
    assert_eq!(fvc, restored);
}

#[test]
fn enrichment_version_negotiation_result_serde_roundtrip() {
    let vnr = VersionNegotiationResult {
        boundary: SiblingRepo::Frankentui,
        local_version: SemanticVersion::new(1, 2, 0),
        remote_version: SemanticVersion::new(1, 3, 0),
        compatibility: VersionCompatibility::MinorCompatible,
        migration_required: false,
        migration_path: None,
    };
    let json = serde_json::to_string(&vnr).unwrap();
    let restored: VersionNegotiationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(vnr, restored);
}

#[test]
fn enrichment_catalog_change_record_serde_roundtrip() {
    let cr = CatalogChangeRecord {
        version: SemanticVersion::new(1, 0, 0),
        description: "added entry".to_string(),
        affected_entries: vec!["e1".to_string()],
        change_kind: ChangeKind::EntryAdded,
    };
    let json = serde_json::to_string(&cr).unwrap();
    let restored: CatalogChangeRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(cr, restored);
}

#[test]
fn enrichment_conformance_catalog_serde_roundtrip() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(test_catalog_entry("e1"));
    let json = serde_json::to_string(&catalog).unwrap();
    let restored: ConformanceCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(catalog, restored);
}

// -----------------------------------------------------------------------
// Display coverage
// -----------------------------------------------------------------------

#[test]
fn enrichment_sibling_repo_display_all_unique() {
    let displays: BTreeSet<String> = SiblingRepo::all().iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), SiblingRepo::all().len());
}

#[test]
fn enrichment_sibling_repo_display_specific() {
    assert_eq!(SiblingRepo::Asupersync.to_string(), "asupersync");
    assert_eq!(SiblingRepo::Frankentui.to_string(), "frankentui");
    assert_eq!(SiblingRepo::Frankensqlite.to_string(), "frankensqlite");
    assert_eq!(SiblingRepo::FrankenNode.to_string(), "franken_node");
    assert_eq!(SiblingRepo::SqlmodelRust.to_string(), "sqlmodel_rust");
    assert_eq!(SiblingRepo::FastapiRust.to_string(), "fastapi_rust");
}

#[test]
fn enrichment_surface_kind_display_all_unique() {
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
    let displays: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), 10);
}

#[test]
fn enrichment_version_class_display() {
    assert_eq!(VersionClass::Patch.to_string(), "patch");
    assert_eq!(VersionClass::Minor.to_string(), "minor");
    assert_eq!(VersionClass::Major.to_string(), "major");
}

#[test]
fn enrichment_failure_severity_display_all() {
    assert_eq!(FailureSeverity::Info.to_string(), "info");
    assert_eq!(FailureSeverity::Warning.to_string(), "warning");
    assert_eq!(FailureSeverity::Error.to_string(), "error");
    assert_eq!(FailureSeverity::Critical.to_string(), "critical");
}

#[test]
fn enrichment_required_response_display_all() {
    assert_eq!(RequiredResponse::Log.to_string(), "log");
    assert_eq!(RequiredResponse::Warn.to_string(), "warn");
    assert_eq!(RequiredResponse::Block.to_string(), "block");
}

#[test]
fn enrichment_version_compatibility_display_all() {
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
fn enrichment_change_kind_display_all_unique() {
    let kinds = [
        ChangeKind::EntryAdded,
        ChangeKind::EntryModified,
        ChangeKind::EntryRemoved,
        ChangeKind::TaxonomyUpdated,
        ChangeKind::VectorAdded,
        ChangeKind::VectorRemoved,
    ];
    let displays: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_semantic_version_display() {
    assert_eq!(SemanticVersion::new(1, 2, 3).to_string(), "1.2.3");
    assert_eq!(SemanticVersion::new(0, 0, 0).to_string(), "0.0.0");
}

// -----------------------------------------------------------------------
// as_str coverage
// -----------------------------------------------------------------------

#[test]
fn enrichment_sibling_repo_as_str_all() {
    for repo in SiblingRepo::all() {
        let s = repo.as_str();
        assert!(!s.is_empty());
        assert_eq!(repo.to_string(), s);
    }
}

#[test]
fn enrichment_surface_kind_as_str_all() {
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
fn enrichment_version_class_as_str_all() {
    assert_eq!(VersionClass::Patch.as_str(), "patch");
    assert_eq!(VersionClass::Minor.as_str(), "minor");
    assert_eq!(VersionClass::Major.as_str(), "major");
}

#[test]
fn enrichment_failure_severity_as_str_all() {
    assert_eq!(FailureSeverity::Info.as_str(), "info");
    assert_eq!(FailureSeverity::Warning.as_str(), "warning");
    assert_eq!(FailureSeverity::Error.as_str(), "error");
    assert_eq!(FailureSeverity::Critical.as_str(), "critical");
}

#[test]
fn enrichment_required_response_as_str_all() {
    assert_eq!(RequiredResponse::Log.as_str(), "log");
    assert_eq!(RequiredResponse::Warn.as_str(), "warn");
    assert_eq!(RequiredResponse::Block.as_str(), "block");
}

// -----------------------------------------------------------------------
// Debug nonempty
// -----------------------------------------------------------------------

#[test]
fn enrichment_boundary_surface_debug() {
    let bs = test_boundary_surface();
    let dbg = format!("{bs:?}");
    assert!(dbg.contains("BoundarySurface"));
}

#[test]
fn enrichment_catalog_entry_debug() {
    let entry = test_catalog_entry("dbg");
    let dbg = format!("{entry:?}");
    assert!(dbg.contains("CatalogEntry"));
}

#[test]
fn enrichment_conformance_catalog_debug() {
    let catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    let dbg = format!("{catalog:?}");
    assert!(dbg.contains("ConformanceCatalog"));
}

#[test]
fn enrichment_replay_obligation_debug() {
    let ro = test_replay_obligation("dbg");
    let dbg = format!("{ro:?}");
    assert!(dbg.contains("ReplayObligation"));
}

#[test]
fn enrichment_replay_artifact_debug() {
    let ra = test_replay_artifact("dbg");
    let dbg = format!("{ra:?}");
    assert!(dbg.contains("ReplayArtifact"));
}

// -----------------------------------------------------------------------
// SiblingRepo
// -----------------------------------------------------------------------

#[test]
fn enrichment_sibling_repo_all_returns_six() {
    assert_eq!(SiblingRepo::all().len(), 6);
}

#[test]
fn enrichment_sibling_repo_is_primary() {
    assert!(SiblingRepo::Asupersync.is_primary());
    assert!(SiblingRepo::Frankentui.is_primary());
    assert!(SiblingRepo::Frankensqlite.is_primary());
    assert!(SiblingRepo::FrankenNode.is_primary());
    assert!(!SiblingRepo::SqlmodelRust.is_primary());
    assert!(!SiblingRepo::FastapiRust.is_primary());
}

// -----------------------------------------------------------------------
// VersionClass
// -----------------------------------------------------------------------

#[test]
fn enrichment_version_class_allows_additive() {
    assert!(!VersionClass::Patch.allows_additive_fields());
    assert!(VersionClass::Minor.allows_additive_fields());
    assert!(VersionClass::Major.allows_additive_fields());
}

#[test]
fn enrichment_version_class_allows_breaking() {
    assert!(!VersionClass::Patch.allows_breaking_changes());
    assert!(!VersionClass::Minor.allows_breaking_changes());
    assert!(VersionClass::Major.allows_breaking_changes());
}

// -----------------------------------------------------------------------
// VersionCompatibility
// -----------------------------------------------------------------------

#[test]
fn enrichment_version_compatibility_is_compatible() {
    assert!(VersionCompatibility::Exact.is_compatible());
    assert!(VersionCompatibility::PatchCompatible.is_compatible());
    assert!(VersionCompatibility::MinorCompatible.is_compatible());
    assert!(!VersionCompatibility::MajorIncompatible.is_compatible());
}

// -----------------------------------------------------------------------
// Version negotiation
// -----------------------------------------------------------------------

#[test]
fn enrichment_negotiate_exact() {
    let v = SemanticVersion::new(1, 2, 3);
    assert_eq!(negotiate_version(v, v), VersionCompatibility::Exact);
}

#[test]
fn enrichment_negotiate_patch_compatible() {
    let a = SemanticVersion::new(1, 2, 3);
    let b = SemanticVersion::new(1, 2, 4);
    assert_eq!(
        negotiate_version(a, b),
        VersionCompatibility::PatchCompatible
    );
}

#[test]
fn enrichment_negotiate_minor_compatible() {
    let a = SemanticVersion::new(1, 2, 0);
    let b = SemanticVersion::new(1, 3, 0);
    assert_eq!(
        negotiate_version(a, b),
        VersionCompatibility::MinorCompatible
    );
}

#[test]
fn enrichment_negotiate_major_incompatible() {
    let a = SemanticVersion::new(1, 0, 0);
    let b = SemanticVersion::new(2, 0, 0);
    assert_eq!(
        negotiate_version(a, b),
        VersionCompatibility::MajorIncompatible
    );
}

// -----------------------------------------------------------------------
// Failure taxonomy
// -----------------------------------------------------------------------

#[test]
fn enrichment_failure_taxonomy_has_four_entries() {
    let tax = failure_taxonomy();
    assert_eq!(tax.len(), 4);
}

#[test]
fn enrichment_failure_taxonomy_covers_all_regression_classes() {
    let tax = failure_taxonomy();
    let classes: BTreeSet<_> = tax.iter().map(|t| t.regression_class).collect();
    assert!(classes.contains(&RegressionClass::Breaking));
    assert!(classes.contains(&RegressionClass::Behavioral));
    assert!(classes.contains(&RegressionClass::Observability));
    assert!(classes.contains(&RegressionClass::Performance));
}

#[test]
fn enrichment_classify_failure_finds_breaking() {
    let tax = failure_taxonomy();
    let entry = classify_failure(&tax, RegressionClass::Breaking);
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().severity, FailureSeverity::Critical);
    assert_eq!(entry.unwrap().required_response, RequiredResponse::Block);
}

#[test]
fn enrichment_classify_failure_finds_behavioral() {
    let tax = failure_taxonomy();
    let entry = classify_failure(&tax, RegressionClass::Behavioral);
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().severity, FailureSeverity::Error);
}

#[test]
fn enrichment_taxonomy_entries_have_evidence() {
    let tax = failure_taxonomy();
    for t in &tax {
        assert!(!t.evidence_requirements.is_empty());
        assert!(!t.description.is_empty());
    }
}

// -----------------------------------------------------------------------
// Replay obligations
// -----------------------------------------------------------------------

#[test]
fn enrichment_replay_obligation_standard() {
    let ro = ReplayObligation::standard("test-1", SiblingRepo::Frankentui);
    assert_eq!(ro.test_id, "test-1");
    assert_eq!(ro.boundary, SiblingRepo::Frankentui);
    assert!(ro.must_pin_versions);
    assert!(ro.must_provide_seed);
    assert!(ro.must_capture_input);
    assert!(ro.must_hash_output);
}

#[test]
fn enrichment_replay_obligation_verify_valid() {
    let ro = test_replay_obligation("t1");
    let ra = test_replay_artifact("t1");
    let errors = ro.verify(&ra);
    assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
}

#[test]
fn enrichment_replay_obligation_verify_missing_versions() {
    let ro = test_replay_obligation("t1");
    let mut ra = test_replay_artifact("t1");
    ra.pinned_versions.clear();
    let errors = ro.verify(&ra);
    assert!(!errors.is_empty());
    assert!(errors[0].contains("pinned_versions"));
}

#[test]
fn enrichment_replay_obligation_verify_zero_seed() {
    let ro = test_replay_obligation("t1");
    let mut ra = test_replay_artifact("t1");
    ra.deterministic_seed = 0;
    let errors = ro.verify(&ra);
    assert!(!errors.is_empty());
    assert!(errors[0].contains("deterministic_seed"));
}

#[test]
fn enrichment_replay_obligation_verify_empty_input() {
    let ro = test_replay_obligation("t1");
    let mut ra = test_replay_artifact("t1");
    ra.input_snapshot.clear();
    let errors = ro.verify(&ra);
    assert!(!errors.is_empty());
    assert!(errors[0].contains("input_snapshot"));
}

#[test]
fn enrichment_replay_obligation_verify_empty_hash() {
    let ro = test_replay_obligation("t1");
    let mut ra = test_replay_artifact("t1");
    ra.expected_output_hash = String::new();
    let errors = ro.verify(&ra);
    assert!(!errors.is_empty());
    assert!(errors[0].contains("expected_output_hash"));
}

#[test]
fn enrichment_replay_obligation_verify_test_id_mismatch() {
    let ro = test_replay_obligation("t1");
    let ra = test_replay_artifact("t2");
    let errors = ro.verify(&ra);
    assert!(!errors.is_empty());
    assert!(errors.iter().any(|e| e.contains("test_id mismatch")));
}

#[test]
fn enrichment_replay_obligation_verify_boundary_mismatch() {
    let ro = ReplayObligation::standard("t1", SiblingRepo::Frankentui);
    let ra = test_replay_artifact("t1"); // Asupersync
    let errors = ro.verify(&ra);
    assert!(!errors.is_empty());
    assert!(errors.iter().any(|e| e.contains("boundary mismatch")));
}

// -----------------------------------------------------------------------
// Catalog lifecycle
// -----------------------------------------------------------------------

#[test]
fn enrichment_catalog_new_empty() {
    let catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    assert!(catalog.entries.is_empty());
    assert!(!catalog.taxonomy.is_empty()); // pre-loaded taxonomy
    assert!(catalog.change_log.is_empty());
}

#[test]
fn enrichment_catalog_add_entry() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(test_catalog_entry("e1"));
    assert_eq!(catalog.entries.len(), 1);
    assert_eq!(catalog.change_log.len(), 1);
    assert_eq!(catalog.change_log[0].change_kind, ChangeKind::EntryAdded);
}

#[test]
fn enrichment_catalog_get_entry() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(test_catalog_entry("e1"));
    catalog.add_entry(test_catalog_entry("e2"));
    assert!(catalog.get_entry("e1").is_some());
    assert!(catalog.get_entry("e2").is_some());
    assert!(catalog.get_entry("e3").is_none());
}

#[test]
fn enrichment_catalog_entries_for_boundary() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(test_catalog_entry("e1")); // Asupersync boundary
    let entries = catalog.entries_for_boundary(SiblingRepo::Asupersync);
    assert_eq!(entries.len(), 1);
    let entries = catalog.entries_for_boundary(SiblingRepo::Frankentui);
    assert!(entries.is_empty());
}

#[test]
fn enrichment_catalog_validate_vector_coverage_good() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(test_catalog_entry("e1"));
    let errors = catalog.validate_vector_coverage();
    assert!(errors.is_empty());
}

#[test]
fn enrichment_catalog_validate_vector_coverage_bad() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    let mut entry = test_catalog_entry("e-bad");
    entry.positive_vectors.clear();
    catalog.add_entry(entry);
    let errors = catalog.validate_vector_coverage();
    assert!(!errors.is_empty());
    assert!(errors[0].contains("e-bad"));
}

#[test]
fn enrichment_catalog_covered_boundaries() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(test_catalog_entry("e1"));
    let boundaries = catalog.covered_boundaries();
    assert!(boundaries.contains(&SiblingRepo::Asupersync));
}

#[test]
fn enrichment_catalog_entries_by_class() {
    let mut catalog = ConformanceCatalog::new(SemanticVersion::new(1, 0, 0));
    catalog.add_entry(test_catalog_entry("e1"));
    let by_class = catalog.entries_by_class();
    assert_eq!(*by_class.get(&RegressionClass::Breaking).unwrap(), 1);
}

#[test]
fn enrichment_catalog_entry_has_required_vectors() {
    let entry = test_catalog_entry("e1");
    assert!(entry.has_required_vectors());

    let mut entry_no_pos = test_catalog_entry("e2");
    entry_no_pos.positive_vectors.clear();
    assert!(!entry_no_pos.has_required_vectors());

    let mut entry_no_neg = test_catalog_entry("e3");
    entry_no_neg.negative_vectors.clear();
    assert!(!entry_no_neg.has_required_vectors());
}

// -----------------------------------------------------------------------
// Canonical boundary surfaces
// -----------------------------------------------------------------------

#[test]
fn enrichment_canonical_boundary_surfaces_nonempty() {
    let surfaces = canonical_boundary_surfaces();
    assert!(!surfaces.is_empty());
}

#[test]
fn enrichment_canonical_surfaces_have_unique_ids() {
    let surfaces = canonical_boundary_surfaces();
    let ids: BTreeSet<&str> = surfaces.iter().map(|s| s.surface_id.as_str()).collect();
    assert_eq!(ids.len(), surfaces.len());
}

#[test]
fn enrichment_canonical_surfaces_cover_primary_siblings() {
    let surfaces = canonical_boundary_surfaces();
    let siblings: BTreeSet<SiblingRepo> = surfaces.iter().map(|s| s.sibling).collect();
    assert!(siblings.contains(&SiblingRepo::Asupersync));
    assert!(siblings.contains(&SiblingRepo::Frankentui));
}

// -----------------------------------------------------------------------
// JSON field-name stability
// -----------------------------------------------------------------------

#[test]
fn enrichment_boundary_surface_json_field_names() {
    let bs = test_boundary_surface();
    let json = serde_json::to_string(&bs).unwrap();
    for field in [
        "sibling",
        "surface_id",
        "surface_kind",
        "description",
        "covered_fields",
        "version_class",
    ] {
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

#[test]
fn enrichment_catalog_entry_json_field_names() {
    let entry = test_catalog_entry("json-fields");
    let json = serde_json::to_string(&entry).unwrap();
    for field in [
        "entry_id",
        "boundary",
        "positive_vectors",
        "negative_vectors",
        "replay_obligation",
        "failure_class",
        "approved",
        "approval_epoch",
    ] {
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

#[test]
fn enrichment_replay_artifact_json_field_names() {
    let ra = test_replay_artifact("json-fields");
    let json = serde_json::to_string(&ra).unwrap();
    for field in [
        "test_id",
        "boundary",
        "deterministic_seed",
        "pinned_versions",
        "input_snapshot",
        "expected_output_hash",
        "reproduction_command",
    ] {
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

#[test]
fn enrichment_semantic_version_json_field_names() {
    let v = SemanticVersion::new(1, 2, 3);
    let json = serde_json::to_string(&v).unwrap();
    for field in ["major", "minor", "patch"] {
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

// -----------------------------------------------------------------------
// SemanticVersion ordering
// -----------------------------------------------------------------------

#[test]
fn enrichment_semantic_version_ordering() {
    assert!(SemanticVersion::new(1, 0, 0) < SemanticVersion::new(2, 0, 0));
    assert!(SemanticVersion::new(1, 0, 0) < SemanticVersion::new(1, 1, 0));
    assert!(SemanticVersion::new(1, 0, 0) < SemanticVersion::new(1, 0, 1));
    assert_eq!(SemanticVersion::new(1, 2, 3), SemanticVersion::new(1, 2, 3));
}

// -----------------------------------------------------------------------
// Determinism
// -----------------------------------------------------------------------

#[test]
fn enrichment_failure_taxonomy_deterministic() {
    let t1 = failure_taxonomy();
    let t2 = failure_taxonomy();
    assert_eq!(t1, t2);
}

#[test]
fn enrichment_canonical_surfaces_deterministic() {
    let s1 = canonical_boundary_surfaces();
    let s2 = canonical_boundary_surfaces();
    assert_eq!(s1, s2);
}

#[test]
fn enrichment_negotiate_version_deterministic() {
    let a = SemanticVersion::new(1, 2, 0);
    let b = SemanticVersion::new(1, 3, 0);
    let r1 = negotiate_version(a, b);
    let r2 = negotiate_version(a, b);
    assert_eq!(r1, r2);
}
