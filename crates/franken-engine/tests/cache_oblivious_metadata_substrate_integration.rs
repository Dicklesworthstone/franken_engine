//! Integration tests for cache_oblivious_metadata_substrate (RGC-626).

use frankenengine_engine::cache_oblivious_metadata_substrate::{
    CacheObliviousSpecimenFamily, CacheObliviousVerdict, SubstrateConfig, SubstrateError,
    SubstrateOrchestrator, cache_oblivious_corpus, run_cache_oblivious_corpus,
};
use frankenengine_engine::metadata_substrate_inventory::MetadataStructureKind;
use frankenengine_engine::metadata_substrate_optimized::SubstrateKind as OptSubstrateKind;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

// --- Construction ---

#[test]
fn test_orchestrator_defaults() {
    let orch = SubstrateOrchestrator::with_defaults(test_epoch());
    assert_eq!(orch.summary().total_decisions, 0);
    assert!(!orch.inventory().assignments.is_empty());
}

#[test]
fn test_custom_config() {
    let config = SubstrateConfig {
        enable_optimization: false,
        ..SubstrateConfig::default()
    };
    let orch = SubstrateOrchestrator::new(test_epoch(), config);
    assert_eq!(orch.summary().total_decisions, 0);
}

// --- Single selection ---

#[test]
fn test_select_shape_table() {
    let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
    let sel = orch
        .select_substrate(MetadataStructureKind::ShapeTable)
        .unwrap();
    assert_eq!(sel.seq, 1);
    assert_eq!(sel.structure_kind, MetadataStructureKind::ShapeTable);
}

#[test]
fn test_select_all_structures() {
    let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
    let results = orch.select_all();
    assert!(results.iter().all(|r| r.is_ok()));
    assert!(orch.summary().kinds_covered > 0);
}

#[test]
fn test_select_all_then_lookup() {
    let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
    let _ = orch.select_all();
    assert!(
        orch.get_selection(MetadataStructureKind::ShapeTable)
            .is_some()
    );
    assert!(
        orch.get_selection(MetadataStructureKind::StringTable)
            .is_some()
    );
}

// --- Optimization disabled ---

#[test]
fn test_opt_disabled_all_generic() {
    let config = SubstrateConfig {
        enable_optimization: false,
        ..SubstrateConfig::default()
    };
    let mut orch = SubstrateOrchestrator::new(test_epoch(), config);
    let results = orch.select_all();
    for r in &results {
        let sel = r.as_ref().unwrap();
        assert_eq!(sel.active_substrate, OptSubstrateKind::GenericFallback);
    }
    assert_eq!(orch.summary().generic_count, results.len() as u64);
}

// --- Summary ---

#[test]
fn test_summary_coverage() {
    let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
    let _ = orch.select_all();
    let summary = orch.summary();
    assert!(summary.coverage_millionths > 0);
    assert_eq!(
        summary.optimized_count + summary.generic_count,
        summary.total_decisions
    );
}

#[test]
fn test_summary_deterministic() {
    let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
    let _ = orch.select_all();
    let s1 = orch.summary();
    let s2 = orch.summary();
    assert_eq!(s1.content_hash, s2.content_hash);
}

// --- History ---

#[test]
fn test_history_matches_decisions() {
    let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
    let _ = orch.select_substrate(MetadataStructureKind::ShapeTable);
    let _ = orch.select_substrate(MetadataStructureKind::StringTable);
    let _ = orch.select_substrate(MetadataStructureKind::GcMetadata);
    assert_eq!(orch.history().len(), 3);
}

#[test]
fn test_history_bounded() {
    let config = SubstrateConfig {
        max_history: 2,
        ..SubstrateConfig::default()
    };
    let mut orch = SubstrateOrchestrator::new(test_epoch(), config);
    let _ = orch.select_all();
    assert!(orch.history().len() <= 2);
}

#[test]
fn test_history_disabled() {
    let config = SubstrateConfig {
        record_history: false,
        ..SubstrateConfig::default()
    };
    let mut orch = SubstrateOrchestrator::new(test_epoch(), config);
    let _ = orch.select_all();
    assert!(orch.history().is_empty());
}

// --- Reset ---

#[test]
fn test_reset_clears_all() {
    let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
    let _ = orch.select_all();
    assert!(orch.summary().total_decisions > 0);
    orch.reset(SecurityEpoch::from_raw(2));
    assert_eq!(orch.summary().total_decisions, 0);
    assert!(orch.history().is_empty());
    assert!(
        orch.get_selection(MetadataStructureKind::ShapeTable)
            .is_none()
    );
}

#[test]
fn test_reset_allows_reuse() {
    let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
    let _ = orch.select_all();
    orch.reset(SecurityEpoch::from_raw(2));
    let sel = orch
        .select_substrate(MetadataStructureKind::ShapeTable)
        .unwrap();
    assert_eq!(sel.seq, 1);
}

// --- Error display ---

#[test]
fn test_error_display() {
    assert!(format!("{}", SubstrateError::EmptyInventory).contains("empty"));
    assert!(
        format!(
            "{}",
            SubstrateError::MissingAssignment {
                kind: "X".to_string()
            }
        )
        .contains("X")
    );
}

// --- Evidence corpus ---

#[test]
fn test_corpus_all_pass() {
    let inv = run_cache_oblivious_corpus();
    for e in &inv.evidences {
        assert_eq!(
            e.verdict,
            CacheObliviousVerdict::Pass,
            "failed: {} - {}",
            e.specimen_id,
            e.details
        );
    }
}

#[test]
fn test_corpus_covers_families() {
    let corpus = cache_oblivious_corpus();
    for family in CacheObliviousSpecimenFamily::ALL {
        assert!(
            corpus.iter().any(|s| s.family == *family),
            "missing: {family:?}"
        );
    }
}

#[test]
fn test_corpus_deterministic() {
    let i1 = run_cache_oblivious_corpus();
    let i2 = run_cache_oblivious_corpus();
    assert_eq!(i1.inventory_hash, i2.inventory_hash);
}

// --- Seq increment ---

#[test]
fn test_seq_increments() {
    let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
    let s1 = orch
        .select_substrate(MetadataStructureKind::ShapeTable)
        .unwrap();
    let s2 = orch
        .select_substrate(MetadataStructureKind::StringTable)
        .unwrap();
    let s3 = orch
        .select_substrate(MetadataStructureKind::GcMetadata)
        .unwrap();
    assert_eq!(s1.seq, 1);
    assert_eq!(s2.seq, 2);
    assert_eq!(s3.seq, 3);
}

// --- Governance ---

#[test]
fn test_governance_disabled() {
    let config = SubstrateConfig {
        enable_governance: false,
        ..SubstrateConfig::default()
    };
    let mut orch = SubstrateOrchestrator::new(test_epoch(), config);
    let sel = orch
        .select_substrate(MetadataStructureKind::ShapeTable)
        .unwrap();
    assert!(!sel.governance_overridden);
}

// --- All structure kinds ---

#[test]
fn test_all_individual_kinds() {
    let mut orch = SubstrateOrchestrator::with_defaults(test_epoch());
    let kinds = [
        MetadataStructureKind::ShapeTable,
        MetadataStructureKind::InlineCacheTable,
        MetadataStructureKind::StringTable,
        MetadataStructureKind::ScopeChainTable,
        MetadataStructureKind::ModuleGraph,
        MetadataStructureKind::PrototypeChainTable,
        MetadataStructureKind::TypeFeedbackVector,
        MetadataStructureKind::CompilationCache,
        MetadataStructureKind::GcMetadata,
        MetadataStructureKind::AllocationSiteTable,
    ];
    for kind in &kinds {
        assert!(orch.select_substrate(*kind).is_ok(), "failed for {kind:?}");
    }
    assert_eq!(orch.summary().kinds_covered, kinds.len());
}
