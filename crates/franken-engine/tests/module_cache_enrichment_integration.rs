//! Enrichment integration tests for `module_cache`.
//!
//! Covers gaps: CachePolicyReportError Display all 12 variants,
//! CacheWorkloadClass/CacheLocalityClass/CachePolicyKind as_str and serde,
//! S3FifoConfig main_queue_entries calculation, S3FifoAdoptionWedgeContract
//! default validation, render_s3fifo_baseline_summary output format,
//! adaptive config defaults and validation, schema constant uniqueness,
//! default corpus/report structural invariants, cache lifecycle with
//! snapshot merge convergence, and serde roundtrips for policy metric types.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::module_cache::*;

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_constants_all_start_with_prefix() {
    let constants = [
        CACHE_TRACE_CORPUS_SCHEMA_VERSION,
        CACHE_POLICY_BASELINE_SCHEMA_VERSION,
        S3FIFO_ADOPTION_WEDGE_SCHEMA_VERSION,
        S3FIFO_BASELINE_CONTRACT_SCHEMA_VERSION,
        S3FIFO_BASELINE_EVENT_SCHEMA_VERSION,
        S3FIFO_BASELINE_ENV_SCHEMA_VERSION,
        S3FIFO_BASELINE_ARTIFACT_MANIFEST_SCHEMA_VERSION,
        S3FIFO_BASELINE_REPRO_LOCK_SCHEMA_VERSION,
        S3FIFO_BASELINE_RUN_MANIFEST_SCHEMA_VERSION,
        S3FIFO_BASELINE_TRACE_IDS_SCHEMA_VERSION,
        S3FIFO_ADAPTIVE_SCHEMA_VERSION,
    ];
    for c in &constants {
        assert!(
            c.starts_with("franken-engine."),
            "schema constant {c} must start with franken-engine."
        );
    }
    let set: BTreeSet<_> = constants.iter().collect();
    assert_eq!(
        set.len(),
        constants.len(),
        "all schema constants must be unique"
    );
}

#[test]
fn enrichment_component_and_bead_ids_non_empty() {
    assert!(!S3FIFO_BASELINE_COMPONENT.is_empty());
    assert!(!S3FIFO_BASELINE_BEAD_ID.is_empty());
    assert!(!S3FIFO_ADAPTIVE_BEAD_ID.is_empty());
}

// ---------------------------------------------------------------------------
// CacheWorkloadClass
// ---------------------------------------------------------------------------

#[test]
fn enrichment_workload_class_as_str_all_unique() {
    let variants = [
        CacheWorkloadClass::ColdCompile,
        CacheWorkloadClass::WarmRun,
        CacheWorkloadClass::PackageGraph,
        CacheWorkloadClass::ReactApp,
        CacheWorkloadClass::ScanHeavy,
    ];
    let strs: BTreeSet<_> = variants.iter().map(|v| v.as_str()).collect();
    assert_eq!(strs.len(), variants.len());
}

#[test]
fn enrichment_workload_class_serde_roundtrip_all() {
    let variants = [
        CacheWorkloadClass::ColdCompile,
        CacheWorkloadClass::WarmRun,
        CacheWorkloadClass::PackageGraph,
        CacheWorkloadClass::ReactApp,
        CacheWorkloadClass::ScanHeavy,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: CacheWorkloadClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// CacheLocalityClass
// ---------------------------------------------------------------------------

#[test]
fn enrichment_locality_class_default_is_warm() {
    assert_eq!(CacheLocalityClass::default(), CacheLocalityClass::Warm);
}

#[test]
fn enrichment_locality_class_as_str_all_unique() {
    let variants = [
        CacheLocalityClass::Hot,
        CacheLocalityClass::Warm,
        CacheLocalityClass::Scan,
    ];
    let strs: BTreeSet<_> = variants.iter().map(|v| v.as_str()).collect();
    assert_eq!(strs.len(), variants.len());
}

#[test]
fn enrichment_locality_class_serde_roundtrip_all() {
    let variants = [
        CacheLocalityClass::Hot,
        CacheLocalityClass::Warm,
        CacheLocalityClass::Scan,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: CacheLocalityClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// CachePolicyKind
// ---------------------------------------------------------------------------

#[test]
fn enrichment_policy_kind_as_str_distinct() {
    assert_ne!(
        CachePolicyKind::SingleQueueFifo.as_str(),
        CachePolicyKind::S3Fifo.as_str()
    );
}

#[test]
fn enrichment_policy_kind_serde_roundtrip() {
    for kind in [CachePolicyKind::SingleQueueFifo, CachePolicyKind::S3Fifo] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: CachePolicyKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

// ---------------------------------------------------------------------------
// S3FifoConfig
// ---------------------------------------------------------------------------

#[test]
fn enrichment_s3fifo_config_main_queue_entries() {
    let config = S3FifoConfig::default();
    // main = resident - small = 4 - 2 = 2
    assert_eq!(config.main_queue_entries(), 2);
}

#[test]
fn enrichment_s3fifo_config_main_queue_saturates() {
    let config = S3FifoConfig {
        resident_capacity_entries: 2,
        small_queue_entries: 5,
        ghost_queue_entries: 4,
    };
    // small > resident → saturating_sub yields 0
    assert_eq!(config.main_queue_entries(), 0);
}

#[test]
fn enrichment_s3fifo_config_serde_roundtrip() {
    let config = S3FifoConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: S3FifoConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// SingleQueueFifoConfig
// ---------------------------------------------------------------------------

#[test]
fn enrichment_single_queue_config_default_capacity() {
    let config = SingleQueueFifoConfig::default();
    assert_eq!(config.capacity_entries, 4);
}

// ---------------------------------------------------------------------------
// CacheErrorCode
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cache_error_code_stable_codes_have_prefix() {
    let codes = [
        CacheErrorCode::ModuleRevoked,
        CacheErrorCode::VersionRegression,
        CacheErrorCode::EmptyModuleId,
    ];
    for code in &codes {
        assert!(
            code.stable_code().starts_with("FE-MODCACHE-"),
            "stable code {} must start with FE-MODCACHE-",
            code.stable_code()
        );
    }
    let stable: BTreeSet<_> = codes.iter().map(|c| c.stable_code()).collect();
    assert_eq!(stable.len(), codes.len(), "all stable codes must be unique");
}

// ---------------------------------------------------------------------------
// CachePolicyReportError Display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cache_policy_report_error_display_all_variants() {
    let errors: Vec<CachePolicyReportError> = vec![
        CachePolicyReportError::EmptyCorpusId,
        CachePolicyReportError::EmptyCorpusCases,
        CachePolicyReportError::DuplicateTraceId {
            trace_id: "t1".to_string(),
        },
        CachePolicyReportError::EmptyTraceId,
        CachePolicyReportError::EmptyTrace {
            trace_id: "t2".to_string(),
        },
        CachePolicyReportError::NonMonotonicTraceSequence {
            trace_id: "t3".to_string(),
            previous: 5,
            actual: 3,
        },
        CachePolicyReportError::EmptyModuleIdInTrace {
            trace_id: "t4".to_string(),
            sequence: 7,
        },
        CachePolicyReportError::InvalidSchemaVersion {
            expected: "v1".to_string(),
            actual: "v2".to_string(),
        },
        CachePolicyReportError::CorpusHashMismatch {
            expected: ContentHash::compute(b"a"),
            actual: ContentHash::compute(b"b"),
        },
        CachePolicyReportError::InvalidConfig {
            field: "capacity",
            detail: "must be > 0".to_string(),
        },
        CachePolicyReportError::InvalidAdoptionWedge {
            field: "surfaces",
            detail: "empty".to_string(),
        },
        CachePolicyReportError::InvalidBaselineReport {
            field: "cases",
            detail: "missing".to_string(),
        },
    ];
    let displays: BTreeSet<_> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(
        displays.len(),
        errors.len(),
        "all error displays must be unique"
    );
    // Check a few contain expected substrings
    assert!(errors[0].to_string().contains("empty"));
    assert!(errors[2].to_string().contains("t1"));
    assert!(errors[5].to_string().contains("5"));
    assert!(errors[5].to_string().contains("3"));
}

#[test]
fn enrichment_cache_policy_report_error_is_std_error() {
    let err = CachePolicyReportError::EmptyCorpusId;
    let _: &dyn std::error::Error = &err;
}

// ---------------------------------------------------------------------------
// S3FifoAdoptionWedgeContract default
// ---------------------------------------------------------------------------

#[test]
fn enrichment_adoption_wedge_default_validates() {
    let wedge = S3FifoAdoptionWedgeContract::default();
    assert!(wedge.validate().is_ok());
    assert!(!wedge.replaced_surfaces.is_empty());
    assert!(!wedge.untouched_surfaces.is_empty());
    assert!(!wedge.win_metrics.is_empty());
    assert!(!wedge.rollback_criteria.is_empty());
    assert_eq!(
        wedge.incumbent_policy_name,
        CachePolicyKind::SingleQueueFifo.as_str()
    );
}

#[test]
fn enrichment_adoption_wedge_serde_roundtrip() {
    let wedge = S3FifoAdoptionWedgeContract::default();
    let json = serde_json::to_string(&wedge).unwrap();
    let back: S3FifoAdoptionWedgeContract = serde_json::from_str(&json).unwrap();
    assert_eq!(wedge, back);
}

// ---------------------------------------------------------------------------
// Default trace corpus manifest
// ---------------------------------------------------------------------------

#[test]
fn enrichment_default_corpus_manifest_has_five_workload_classes() {
    let manifest = default_s3fifo_trace_corpus_manifest();
    assert!(manifest.validate().is_ok());
    let workload_strs: BTreeSet<_> = manifest
        .cases
        .iter()
        .map(|c| c.workload_class.as_str())
        .collect();
    assert_eq!(
        workload_strs.len(),
        5,
        "should cover all 5 workload classes"
    );
}

#[test]
fn enrichment_default_corpus_manifest_trace_ids_unique() {
    let manifest = default_s3fifo_trace_corpus_manifest();
    let ids: BTreeSet<_> = manifest.cases.iter().map(|c| &c.trace_id).collect();
    assert_eq!(ids.len(), manifest.cases.len());
}

#[test]
fn enrichment_default_corpus_manifest_serde_roundtrip() {
    let manifest = default_s3fifo_trace_corpus_manifest();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: CacheTraceCorpusManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

// ---------------------------------------------------------------------------
// Default baseline report
// ---------------------------------------------------------------------------

#[test]
fn enrichment_default_baseline_report_succeeds() {
    let report = default_s3fifo_baseline_report().unwrap();
    assert!(!report.cases.is_empty());
    assert_eq!(report.aggregate.total_cases, report.cases.len() as u64);
}

#[test]
fn enrichment_default_baseline_report_validates() {
    let manifest = default_s3fifo_trace_corpus_manifest();
    let report = default_s3fifo_baseline_report().unwrap();
    assert!(report.validate(&manifest).is_ok());
}

#[test]
fn enrichment_default_baseline_report_serde_roundtrip() {
    let report = default_s3fifo_baseline_report().unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: CachePolicyBaselineReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// render_s3fifo_baseline_summary
// ---------------------------------------------------------------------------

#[test]
fn enrichment_render_baseline_summary_contains_sections() {
    let report = default_s3fifo_baseline_report().unwrap();
    let summary = render_s3fifo_baseline_summary(&report);
    assert!(summary.contains("S3-FIFO Baseline Comparator Summary"));
    assert!(summary.contains("bead_id"));
    assert!(summary.contains("corpus_id"));
    assert!(summary.contains("baseline_policy"));
    assert!(summary.contains("candidate_policy"));
    assert!(summary.contains("improved_hit_rate_cases"));
}

// ---------------------------------------------------------------------------
// CachePolicyMetrics serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_policy_metrics_serde_roundtrip() {
    let metrics = CachePolicyMetrics {
        policy_name: "test_policy".to_string(),
        total_accesses: 100,
        hit_count: 60,
        miss_count: 40,
        ghost_hit_count: 5,
        eviction_count: 10,
        promotion_count: 3,
        requeue_count: 2,
        hit_rate_millionths: 600_000,
        hot_retention_millionths: 800_000,
        scan_pollution_millionths: 50_000,
        final_resident_keys: vec!["mod-a".to_string(), "mod-b".to_string()],
    };
    let json = serde_json::to_string(&metrics).unwrap();
    let back: CachePolicyMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(metrics, back);
}

// ---------------------------------------------------------------------------
// CachePolicyAggregateSummary serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_aggregate_summary_serde_roundtrip() {
    let summary = CachePolicyAggregateSummary {
        total_cases: 5,
        improved_hit_rate_cases: 3,
        improved_hot_retention_cases: 2,
        reduced_scan_pollution_cases: 4,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: CachePolicyAggregateSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// AdaptiveSplitConfig defaults
// ---------------------------------------------------------------------------

#[test]
fn enrichment_adaptive_split_config_defaults() {
    let config = AdaptiveSplitConfig::default();
    assert_eq!(config.min_small_fraction_millionths, 100_000);
    assert_eq!(config.max_small_fraction_millionths, 500_000);
    assert_eq!(config.max_step_per_epoch, 1);
    assert_eq!(config.epoch_length, 16);
}

#[test]
fn enrichment_adaptive_split_config_serde_roundtrip() {
    let config = AdaptiveSplitConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: AdaptiveSplitConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// ValueAdmissionConfig defaults
// ---------------------------------------------------------------------------

#[test]
fn enrichment_value_admission_config_defaults() {
    let config = ValueAdmissionConfig::default();
    assert_eq!(config.initial_threshold_millionths, 100_000);
    assert_eq!(config.alpha_millionths, 250_000);
    assert_eq!(config.floor_value_millionths, 0);
}

#[test]
fn enrichment_value_admission_config_serde_roundtrip() {
    let config = ValueAdmissionConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: ValueAdmissionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// S3FifoAdaptiveConfig defaults and validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_adaptive_config_defaults() {
    let config = S3FifoAdaptiveConfig::default();
    assert_eq!(config.resident_capacity_entries, 8);
    assert_eq!(config.initial_small_queue_entries, 3);
    assert_eq!(config.ghost_queue_entries, 8);
    assert!(config.validate().is_ok());
}

#[test]
fn enrichment_adaptive_config_serde_roundtrip() {
    let config = S3FifoAdaptiveConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: S3FifoAdaptiveConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// AdmissionVerdict serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_admission_verdict_serde_roundtrip() {
    let verdict = AdmissionVerdict {
        sequence: 42,
        label: "mod-alpha".to_string(),
        value_millionths: 750_000,
        threshold_millionths: 100_000,
        admitted: true,
    };
    let json = serde_json::to_string(&verdict).unwrap();
    let back: AdmissionVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(verdict, back);
}

// ---------------------------------------------------------------------------
// S3FifoBaselineComparatorContractFixture
// ---------------------------------------------------------------------------

#[test]
fn enrichment_baseline_contract_fixture_structure() {
    let fixture = default_s3fifo_baseline_contract_fixture();
    assert!(!fixture.required_artifacts.is_empty());
    assert!(!fixture.workload_classes.is_empty());
    assert!(!fixture.win_metrics.is_empty());
    assert_eq!(fixture.bead_id, S3FIFO_BASELINE_BEAD_ID);
}

#[test]
fn enrichment_baseline_contract_fixture_serde_roundtrip() {
    let fixture = default_s3fifo_baseline_contract_fixture();
    let json = serde_json::to_string(&fixture).unwrap();
    let back: S3FifoBaselineComparatorContractFixture = serde_json::from_str(&json).unwrap();
    assert_eq!(fixture, back);
}

// ---------------------------------------------------------------------------
// Default S3FIFO configs match defaults
// ---------------------------------------------------------------------------

#[test]
fn enrichment_default_baseline_config_matches_single_queue_default() {
    let config = default_s3fifo_baseline_config();
    assert_eq!(config, SingleQueueFifoConfig::default());
}

#[test]
fn enrichment_default_candidate_config_matches_s3fifo_default() {
    let config = default_s3fifo_candidate_config();
    assert_eq!(config, S3FifoConfig::default());
}

#[test]
fn enrichment_default_adaptive_config_matches_s3fifo_adaptive_default() {
    let config = default_s3fifo_adaptive_config();
    assert_eq!(config, S3FifoAdaptiveConfig::default());
}

// ---------------------------------------------------------------------------
// Cache lifecycle: insert, get, invalidate, snapshot
// ---------------------------------------------------------------------------

fn test_context() -> CacheContext {
    CacheContext::new(
        "trace-enrichment",
        "decision-enrichment",
        "policy-enrichment",
    )
}

fn test_version(policy: u64) -> ModuleVersionFingerprint {
    ModuleVersionFingerprint::new(ContentHash::compute(b"source-1"), policy, 1)
}

fn test_insert_request(module_id: &str, policy_version: u64) -> CacheInsertRequest {
    let version = test_version(policy_version);
    CacheInsertRequest::new(
        module_id,
        version,
        ContentHash::compute(format!("artifact-{module_id}").as_bytes()),
        format!("./resolved/{module_id}.js"),
    )
}

#[test]
fn enrichment_cache_insert_get_invalidate_cycle() {
    let mut cache = ModuleCache::new();
    let ctx = test_context();
    let req = test_insert_request("mod-a", 1);
    cache.insert(req.clone(), &ctx).unwrap();

    let version = test_version(1);
    assert!(cache.get("mod-a", &version).is_some());

    cache.invalidate_source_update("mod-a", ContentHash::compute(b"source-2"), &ctx);
    assert!(cache.get("mod-a", &version).is_none());
}

#[test]
fn enrichment_cache_revocation_blocks_insert() {
    let mut cache = ModuleCache::new();
    let ctx = test_context();
    cache.invalidate_trust_revocation("mod-b", 1, &ctx);
    let req = test_insert_request("mod-b", 1);
    let result = cache.insert(req, &ctx);
    assert!(result.is_err());
}

#[test]
fn enrichment_cache_restore_trust_allows_insert() {
    let mut cache = ModuleCache::new();
    let ctx = test_context();
    cache.invalidate_trust_revocation("mod-c", 1, &ctx);
    cache.restore_trust("mod-c", 2, &ctx);
    let version = ModuleVersionFingerprint::new(ContentHash::compute(b"src"), 1, 2);
    let req = CacheInsertRequest::new("mod-c", version, ContentHash::compute(b"art"), "./mod-c.js");
    assert!(cache.insert(req, &ctx).is_ok());
}

#[test]
fn enrichment_cache_snapshot_reflects_state() {
    let mut cache = ModuleCache::new();
    let ctx = test_context();
    let req = test_insert_request("mod-d", 1);
    cache.insert(req, &ctx).unwrap();
    let snap = cache.snapshot();
    assert_eq!(snap.entries.len(), 1);
    assert!(snap.revoked_modules.is_empty());
}

#[test]
fn enrichment_cache_state_hash_deterministic() {
    let make = || {
        let mut cache = ModuleCache::new();
        let ctx = test_context();
        let req = test_insert_request("mod-e", 1);
        cache.insert(req, &ctx).unwrap();
        cache.state_hash()
    };
    assert_eq!(make(), make());
}

#[test]
fn enrichment_cache_events_accumulate() {
    let mut cache = ModuleCache::new();
    let ctx = test_context();
    assert!(cache.events().is_empty());
    let req = test_insert_request("mod-f", 1);
    cache.insert(req, &ctx).unwrap();
    assert!(!cache.events().is_empty());
    let count_after_insert = cache.events().len();
    cache.invalidate_source_update("mod-f", ContentHash::compute(b"new"), &ctx);
    assert!(cache.events().len() > count_after_insert);
}

// ---------------------------------------------------------------------------
// Snapshot merge convergence
// ---------------------------------------------------------------------------

#[test]
fn enrichment_snapshot_merge_converges() {
    let mut cache_a = ModuleCache::new();
    let mut cache_b = ModuleCache::new();
    let ctx = test_context();

    let req_a = test_insert_request("shared", 1);
    cache_a.insert(req_a, &ctx).unwrap();

    let version_b = ModuleVersionFingerprint::new(ContentHash::compute(b"source-2"), 2, 1);
    let req_b = CacheInsertRequest::new(
        "shared",
        version_b.clone(),
        ContentHash::compute(b"art-b"),
        "./shared-b.js",
    );
    cache_b.insert(req_b, &ctx).unwrap();

    let snap_b = cache_b.snapshot();
    cache_a.merge_snapshot(&snap_b, &ctx);

    // After merge, cache_a should have the newer version
    let latest = cache_a.snapshot().latest_versions.get("shared").cloned();
    assert_eq!(latest, Some(version_b));
}

// ---------------------------------------------------------------------------
// annotate_trace_with_default_values
// ---------------------------------------------------------------------------

#[test]
fn enrichment_annotate_trace_preserves_structure() {
    let manifest = default_s3fifo_trace_corpus_manifest();
    let case = &manifest.cases[0];
    let annotated = annotate_trace_with_default_values(case);
    assert_eq!(annotated.trace_id, case.trace_id);
    assert_eq!(annotated.workload_class, case.workload_class);
    assert_eq!(annotated.accesses.len(), case.accesses.len());
    for (orig, ann) in case.accesses.iter().zip(annotated.accesses.iter()) {
        assert_eq!(orig.sequence, ann.sequence);
        assert_eq!(orig.key, ann.key);
        assert_eq!(orig.locality, ann.locality);
    }
}

// ---------------------------------------------------------------------------
// simulate_s3fifo_adaptive with default config
// ---------------------------------------------------------------------------

#[test]
fn enrichment_simulate_adaptive_default_produces_metrics() {
    let manifest = default_s3fifo_trace_corpus_manifest();
    let case = &manifest.cases[0];
    let annotated = annotate_trace_with_default_values(case);
    let config = default_s3fifo_adaptive_config();
    let metrics = simulate_s3fifo_adaptive(&annotated, &config);
    assert_eq!(metrics.base.total_accesses, annotated.accesses.len() as u64);
    assert_eq!(
        metrics.base.hit_count + metrics.base.miss_count,
        metrics.base.total_accesses
    );
}

#[test]
fn enrichment_simulate_adaptive_deterministic() {
    let manifest = default_s3fifo_trace_corpus_manifest();
    let case = &manifest.cases[0];
    let annotated = annotate_trace_with_default_values(case);
    let config = default_s3fifo_adaptive_config();
    let m1 = simulate_s3fifo_adaptive(&annotated, &config);
    let m2 = simulate_s3fifo_adaptive(&annotated, &config);
    assert_eq!(m1, m2);
}
