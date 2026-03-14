#![forbid(unsafe_code)]

//! Enrichment integration tests for the `benchmark_evidence_bundle` module.

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

use frankenengine_engine::benchmark_evidence_bundle::{
    BEAD_ID, BenchmarkRun, BundleConfig, BundleError, BundleStatus, BundleVerdict, COMPONENT,
    DEFAULT_MIN_PARITY_RATIO, EnvironmentSnapshot, EvidenceBundle, MAX_CV_MILLIONTHS,
    MAX_ENVIRONMENT_DRIFT, MIN_RUNS_PER_WORKLOAD, POLICY_ID, ParityTarget, ParityVerdict,
    SCHEMA_VERSION, TimingStats, WorkloadCategory, WorkloadProvenance, WorkloadStatEntry,
    evaluate_bundle, generate_report,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn env() -> EnvironmentSnapshot {
    EnvironmentSnapshot::new(
        "linux".into(),
        "x86_64".into(),
        16,
        64_000_000_000,
        "node 22.1.0".into(),
        "franken 0.1.0".into(),
        BTreeMap::new(),
    )
}

fn prov(id: &str, cat: WorkloadCategory) -> WorkloadProvenance {
    WorkloadProvenance {
        workload_id: id.into(),
        name: format!("Workload {id}"),
        category: cat,
        source: "test-corpus".into(),
        pinned_version: "abc123".into(),
        content_hash: ContentHash::compute(id.as_bytes()),
        provenance_epoch: epoch(1),
        tags: BTreeSet::new(),
    }
}

fn run_with(id: &str, wid: &str, dur: u64, iter: u32) -> BenchmarkRun {
    BenchmarkRun {
        run_id: id.into(),
        workload_id: wid.into(),
        duration_us: dur,
        peak_memory_bytes: 1024,
        gc_pause_us: 0,
        is_warmup: false,
        iteration: iter,
        environment: env(),
        run_epoch: epoch(5),
    }
}

fn parity_verdict(wid: &str, target: ParityTarget, ratio: u64) -> ParityVerdict {
    ParityVerdict {
        workload_id: wid.into(),
        target,
        output_equivalent: true,
        performance_ratio_millionths: ratio,
        behavioral_differences: 0,
        difference_details: Vec::new(),
        evidence_hash: ContentHash::compute(wid.as_bytes()),
    }
}

fn full_bundle() -> EvidenceBundle {
    let mut b = EvidenceBundle::new("bundle-1".into(), epoch(5));
    b.add_provenance(prov("w1", WorkloadCategory::Micro))
        .unwrap();
    b.add_provenance(prov("w2", WorkloadCategory::Application))
        .unwrap();
    for i in 0..6 {
        b.add_run(run_with(&format!("r1-{i}"), "w1", 1000 + i * 5, i as u32))
            .unwrap();
        b.add_run(run_with(&format!("r2-{i}"), "w2", 2000 + i * 10, i as u32))
            .unwrap();
    }
    b.add_parity_verdict(parity_verdict("w1", ParityTarget::NodeJs, 1_050_000))
        .unwrap();
    b.add_parity_verdict(parity_verdict("w2", ParityTarget::NodeJs, 990_000))
        .unwrap();
    b
}

// ===========================================================================
// WorkloadCategory enrichment
// ===========================================================================

#[test]
fn enrichment_workload_category_copy_semantics() {
    let a = WorkloadCategory::Micro;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_workload_category_btreeset_dedup_6() {
    let set: BTreeSet<WorkloadCategory> = WorkloadCategory::ALL.iter().copied().collect();
    assert_eq!(set.len(), 6);
    // Re-insert duplicates.
    let mut set2 = set.clone();
    for &c in WorkloadCategory::ALL {
        set2.insert(c);
    }
    assert_eq!(set2.len(), 6);
}

#[test]
fn enrichment_workload_category_debug_all_unique() {
    let debugs: BTreeSet<String> = WorkloadCategory::ALL
        .iter()
        .map(|c| format!("{c:?}"))
        .collect();
    assert_eq!(debugs.len(), 6);
}

#[test]
fn enrichment_workload_category_display_all_unique() {
    let displays: BTreeSet<String> = WorkloadCategory::ALL
        .iter()
        .map(|c| c.to_string())
        .collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_workload_category_as_str_matches_display() {
    for &cat in WorkloadCategory::ALL {
        assert_eq!(cat.as_str(), &cat.to_string());
    }
}

// ===========================================================================
// ParityTarget enrichment
// ===========================================================================

#[test]
fn enrichment_parity_target_copy_semantics() {
    let a = ParityTarget::NodeJs;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_parity_target_btreeset_dedup_4() {
    let set: BTreeSet<ParityTarget> = ParityTarget::ALL.iter().copied().collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_parity_target_debug_all_unique() {
    let debugs: BTreeSet<String> = ParityTarget::ALL.iter().map(|t| format!("{t:?}")).collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn enrichment_parity_target_display_all_unique() {
    let displays: BTreeSet<String> = ParityTarget::ALL.iter().map(|t| t.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_parity_target_as_str_matches_display() {
    for &t in ParityTarget::ALL {
        assert_eq!(t.as_str(), &t.to_string());
    }
}

// ===========================================================================
// BundleStatus enrichment
// ===========================================================================

#[test]
fn enrichment_bundle_status_copy_semantics() {
    let a = BundleStatus::Assembling;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_bundle_status_btreeset_dedup_5() {
    let set: BTreeSet<BundleStatus> = [
        BundleStatus::Assembling,
        BundleStatus::Sealed,
        BundleStatus::Published,
        BundleStatus::Rejected,
        BundleStatus::Superseded,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_bundle_status_debug_all_unique() {
    let debugs: BTreeSet<String> = [
        BundleStatus::Assembling,
        BundleStatus::Sealed,
        BundleStatus::Published,
        BundleStatus::Rejected,
        BundleStatus::Superseded,
    ]
    .iter()
    .map(|s| format!("{s:?}"))
    .collect();
    assert_eq!(debugs.len(), 5);
}

#[test]
fn enrichment_bundle_status_display_all_unique() {
    let displays: BTreeSet<String> = [
        BundleStatus::Assembling,
        BundleStatus::Sealed,
        BundleStatus::Published,
        BundleStatus::Rejected,
        BundleStatus::Superseded,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_bundle_status_as_str_matches_display() {
    for s in [
        BundleStatus::Assembling,
        BundleStatus::Sealed,
        BundleStatus::Published,
        BundleStatus::Rejected,
        BundleStatus::Superseded,
    ] {
        assert_eq!(s.as_str(), &s.to_string());
    }
}

#[test]
fn enrichment_bundle_status_serde_roundtrip_all() {
    for s in [
        BundleStatus::Assembling,
        BundleStatus::Sealed,
        BundleStatus::Published,
        BundleStatus::Rejected,
        BundleStatus::Superseded,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: BundleStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ===========================================================================
// EnvironmentSnapshot enrichment
// ===========================================================================

#[test]
fn enrichment_environment_clone_independence() {
    let e1 = env();
    let mut e2 = e1.clone();
    e2.logical_cores = 99;
    assert_eq!(e1.logical_cores, 16);
    assert_eq!(e2.logical_cores, 99);
}

#[test]
fn enrichment_environment_json_field_names() {
    let e = env();
    let json = serde_json::to_string(&e).unwrap();
    for field in [
        "os",
        "cpu_model",
        "logical_cores",
        "memory_bytes",
        "runtime_version",
        "engine_version",
        "extra",
        "snapshot_hash",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_environment_debug_nonempty() {
    let e = env();
    let dbg = format!("{e:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("EnvironmentSnapshot"));
}

#[test]
fn enrichment_environment_hash_changes_with_extra() {
    let e1 = env();
    let mut extra = BTreeMap::new();
    extra.insert("key".to_string(), "value".to_string());
    let e2 = EnvironmentSnapshot::new(
        "linux".into(),
        "x86_64".into(),
        16,
        64_000_000_000,
        "node 22.1.0".into(),
        "franken 0.1.0".into(),
        extra,
    );
    assert_ne!(e1.snapshot_hash, e2.snapshot_hash);
}

#[test]
fn enrichment_environment_drift_partial() {
    let e1 = env();
    let e2 = EnvironmentSnapshot::new(
        "linux".into(),         // same
        "arm64".into(),         // different
        16,                     // same
        64_000_000_000,         // same
        "node 22.1.0".into(),   // same
        "franken 0.2.0".into(), // different
        BTreeMap::new(),
    );
    let drifts = e1.drift_from(&e2);
    assert_eq!(drifts.len(), 2);
}

// ===========================================================================
// WorkloadProvenance enrichment
// ===========================================================================

#[test]
fn enrichment_workload_provenance_clone_independence() {
    let p = prov("w1", WorkloadCategory::Micro);
    let mut p2 = p.clone();
    p2.name = "changed".to_string();
    assert_eq!(p.name, "Workload w1");
    assert_eq!(p2.name, "changed");
}

#[test]
fn enrichment_workload_provenance_debug_nonempty() {
    let p = prov("w1", WorkloadCategory::Micro);
    let dbg = format!("{p:?}");
    assert!(!dbg.is_empty());
}

#[test]
fn enrichment_workload_provenance_serde_roundtrip() {
    let p = prov("w1", WorkloadCategory::Micro);
    let json = serde_json::to_string(&p).unwrap();
    let back: WorkloadProvenance = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn enrichment_workload_provenance_json_field_names() {
    let p = prov("w1", WorkloadCategory::Micro);
    let json = serde_json::to_string(&p).unwrap();
    for field in [
        "workload_id",
        "name",
        "category",
        "source",
        "pinned_version",
        "content_hash",
        "provenance_epoch",
        "tags",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ===========================================================================
// BenchmarkRun enrichment
// ===========================================================================

#[test]
fn enrichment_benchmark_run_clone_independence() {
    let r = run_with("r1", "w1", 1000, 0);
    let mut r2 = r.clone();
    r2.duration_us = 9999;
    assert_eq!(r.duration_us, 1000);
    assert_eq!(r2.duration_us, 9999);
}

#[test]
fn enrichment_benchmark_run_debug_nonempty() {
    let r = run_with("r1", "w1", 1000, 0);
    let dbg = format!("{r:?}");
    assert!(!dbg.is_empty());
}

#[test]
fn enrichment_benchmark_run_serde_roundtrip() {
    let r = run_with("r1", "w1", 1000, 0);
    let json = serde_json::to_string(&r).unwrap();
    let back: BenchmarkRun = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_benchmark_run_json_field_names() {
    let r = run_with("r1", "w1", 1000, 0);
    let json = serde_json::to_string(&r).unwrap();
    for field in [
        "run_id",
        "workload_id",
        "duration_us",
        "peak_memory_bytes",
        "gc_pause_us",
        "is_warmup",
        "iteration",
        "environment",
        "run_epoch",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ===========================================================================
// ParityVerdict enrichment
// ===========================================================================

#[test]
fn enrichment_parity_verdict_clone_independence() {
    let v = parity_verdict("w1", ParityTarget::NodeJs, 1_000_000);
    let mut v2 = v.clone();
    v2.behavioral_differences = 42;
    assert_eq!(v.behavioral_differences, 0);
    assert_eq!(v2.behavioral_differences, 42);
}

#[test]
fn enrichment_parity_verdict_serde_roundtrip() {
    let v = parity_verdict("w1", ParityTarget::NodeJs, 1_000_000);
    let json = serde_json::to_string(&v).unwrap();
    let back: ParityVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_parity_verdict_json_field_names() {
    let v = parity_verdict("w1", ParityTarget::NodeJs, 1_000_000);
    let json = serde_json::to_string(&v).unwrap();
    for field in [
        "workload_id",
        "target",
        "output_equivalent",
        "performance_ratio_millionths",
        "behavioral_differences",
        "difference_details",
        "evidence_hash",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_parity_verdict_boundary_ratio() {
    // Exactly at threshold
    let v = parity_verdict("w1", ParityTarget::NodeJs, DEFAULT_MIN_PARITY_RATIO);
    assert!(v.is_acceptable(DEFAULT_MIN_PARITY_RATIO));
    // One below threshold
    let v2 = parity_verdict("w1", ParityTarget::NodeJs, DEFAULT_MIN_PARITY_RATIO - 1);
    assert!(!v2.is_acceptable(DEFAULT_MIN_PARITY_RATIO));
}

// ===========================================================================
// BundleConfig enrichment
// ===========================================================================

#[test]
fn enrichment_bundle_config_clone_independence() {
    let cfg = BundleConfig::default();
    let mut cfg2 = cfg.clone();
    cfg2.min_runs_per_workload = 99;
    assert_eq!(cfg.min_runs_per_workload, MIN_RUNS_PER_WORKLOAD);
    assert_eq!(cfg2.min_runs_per_workload, 99);
}

#[test]
fn enrichment_bundle_config_default_matches_constants() {
    let cfg = BundleConfig::default();
    assert_eq!(cfg.min_runs_per_workload, MIN_RUNS_PER_WORKLOAD);
    assert_eq!(cfg.max_cv_millionths, MAX_CV_MILLIONTHS);
    assert_eq!(cfg.min_parity_ratio, DEFAULT_MIN_PARITY_RATIO);
    assert_eq!(cfg.max_environment_drift, MAX_ENVIRONMENT_DRIFT);
}

#[test]
fn enrichment_bundle_config_debug_nonempty() {
    let cfg = BundleConfig::default();
    let dbg = format!("{cfg:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("BundleConfig"));
}

#[test]
fn enrichment_bundle_config_json_field_names() {
    let cfg = BundleConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    for field in [
        "min_runs_per_workload",
        "max_cv_millionths",
        "min_parity_ratio",
        "max_environment_drift",
        "required_categories",
        "required_parity_targets",
        "min_verification_epoch",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ===========================================================================
// BundleError enrichment
// ===========================================================================

#[test]
fn enrichment_bundle_error_display_all_unique() {
    let displays: BTreeSet<String> = [
        BundleError::BundleSealed {
            bundle_id: "b1".into(),
        }
        .to_string(),
        BundleError::DuplicateWorkload {
            workload_id: "w1".into(),
        }
        .to_string(),
        BundleError::MissingProvenance {
            workload_id: "w1".into(),
        }
        .to_string(),
        BundleError::InvalidTransition {
            from: BundleStatus::Assembling,
            to: BundleStatus::Published,
        }
        .to_string(),
        BundleError::InvalidConfig {
            reason: "bad".into(),
        }
        .to_string(),
        BundleError::StaleEvidence {
            bundle_epoch: 1,
            required_epoch: 5,
        }
        .to_string(),
    ]
    .into_iter()
    .collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_bundle_error_debug_all_unique() {
    let debugs: BTreeSet<String> = [
        format!(
            "{:?}",
            BundleError::BundleSealed {
                bundle_id: "b1".into()
            }
        ),
        format!(
            "{:?}",
            BundleError::DuplicateWorkload {
                workload_id: "w1".into()
            }
        ),
        format!(
            "{:?}",
            BundleError::MissingProvenance {
                workload_id: "w1".into()
            }
        ),
        format!(
            "{:?}",
            BundleError::InvalidTransition {
                from: BundleStatus::Assembling,
                to: BundleStatus::Published,
            }
        ),
        format!(
            "{:?}",
            BundleError::InvalidConfig {
                reason: "bad".into()
            }
        ),
        format!(
            "{:?}",
            BundleError::StaleEvidence {
                bundle_epoch: 1,
                required_epoch: 5,
            }
        ),
    ]
    .into_iter()
    .collect();
    assert_eq!(debugs.len(), 6);
}

#[test]
fn enrichment_bundle_error_clone_independence() {
    let err = BundleError::InvalidConfig {
        reason: "original".to_string(),
    };
    let cloned = err.clone();
    assert_eq!(err, cloned);
    if let BundleError::InvalidConfig { reason } = &err {
        assert_eq!(reason, "original");
    }
}

#[test]
fn enrichment_bundle_error_serde_roundtrip_all() {
    let errors = [
        BundleError::BundleSealed {
            bundle_id: "b1".into(),
        },
        BundleError::DuplicateWorkload {
            workload_id: "w1".into(),
        },
        BundleError::MissingProvenance {
            workload_id: "w2".into(),
        },
        BundleError::InvalidTransition {
            from: BundleStatus::Assembling,
            to: BundleStatus::Published,
        },
        BundleError::InvalidConfig {
            reason: "test".into(),
        },
        BundleError::StaleEvidence {
            bundle_epoch: 1,
            required_epoch: 10,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: BundleError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn enrichment_bundle_error_display_invalid_config_contains_reason() {
    let err = BundleError::InvalidConfig {
        reason: "custom-reason".into(),
    };
    assert!(err.to_string().contains("custom-reason"));
}

#[test]
fn enrichment_bundle_error_display_stale_contains_epochs() {
    let err = BundleError::StaleEvidence {
        bundle_epoch: 42,
        required_epoch: 100,
    };
    let s = err.to_string();
    assert!(s.contains("42"), "display: {s}");
    assert!(s.contains("100"), "display: {s}");
}

// ===========================================================================
// BundleVerdict enrichment
// ===========================================================================

#[test]
fn enrichment_bundle_verdict_clone_independence() {
    let v = BundleVerdict::Fail {
        reasons: vec!["original".to_string()],
    };
    let cloned = v.clone();
    assert_eq!(v, cloned);
}

#[test]
fn enrichment_bundle_verdict_debug_nonempty() {
    let v = BundleVerdict::Pass {
        workload_count: 2,
        total_runs: 10,
        categories: BTreeSet::new(),
    };
    let dbg = format!("{v:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("Pass"));
}

#[test]
fn enrichment_bundle_verdict_serde_roundtrip_all_variants() {
    let verdicts = [
        BundleVerdict::Pass {
            workload_count: 2,
            total_runs: 10,
            categories: [WorkloadCategory::Micro].into_iter().collect(),
        },
        BundleVerdict::Fail {
            reasons: vec!["too few".into()],
        },
        BundleVerdict::Incomplete {
            missing: vec!["no provenance".into()],
        },
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: BundleVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// TimingStats enrichment
// ===========================================================================

#[test]
fn enrichment_timing_stats_clone_independence() {
    let stats = TimingStats::from_durations(&[100, 200, 300]);
    let mut cloned = stats.clone();
    cloned.count = 99;
    assert_eq!(stats.count, 3);
    assert_eq!(cloned.count, 99);
}

#[test]
fn enrichment_timing_stats_debug_nonempty() {
    let stats = TimingStats::from_durations(&[100, 200, 300]);
    let dbg = format!("{stats:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("TimingStats"));
}

#[test]
fn enrichment_timing_stats_json_field_names() {
    let stats = TimingStats::from_durations(&[100, 200, 300]);
    let json = serde_json::to_string(&stats).unwrap();
    for field in [
        "count",
        "min_us",
        "max_us",
        "mean_us",
        "median_us",
        "stddev_us",
        "cv_millionths",
        "p95_us",
        "p99_us",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_timing_stats_min_max_ordering() {
    let stats = TimingStats::from_durations(&[500, 100, 300, 200, 400]);
    assert!(stats.min_us <= stats.mean_us);
    assert!(stats.mean_us <= stats.max_us);
    assert!(stats.min_us <= stats.median_us);
    assert!(stats.median_us <= stats.max_us);
}

#[test]
fn enrichment_timing_stats_percentile_ordering() {
    let durations: Vec<u64> = (1..=200).collect();
    let stats = TimingStats::from_durations(&durations);
    assert!(stats.p95_us <= stats.p99_us);
    assert!(stats.p99_us <= stats.max_us);
    assert!(stats.min_us <= stats.p95_us);
}

#[test]
fn enrichment_timing_stats_is_stable_boundary() {
    let stats = TimingStats::from_durations(&[100, 100, 100, 100, 100]);
    assert!(stats.is_stable(0)); // cv_millionths is 0, threshold is 0
    assert!(stats.is_stable(MAX_CV_MILLIONTHS));
}

#[test]
fn enrichment_timing_stats_two_values() {
    let stats = TimingStats::from_durations(&[100, 200]);
    assert_eq!(stats.count, 2);
    assert_eq!(stats.min_us, 100);
    assert_eq!(stats.max_us, 200);
    assert_eq!(stats.mean_us, 150);
    assert_eq!(stats.median_us, 150); // (100+200)/2
}

// ===========================================================================
// EvidenceBundle enrichment
// ===========================================================================

#[test]
fn enrichment_evidence_bundle_clone_independence() {
    let b = full_bundle();
    let mut b2 = b.clone();
    b2.bundle_id = "changed".to_string();
    assert_eq!(b.bundle_id, "bundle-1");
    assert_eq!(b2.bundle_id, "changed");
}

#[test]
fn enrichment_evidence_bundle_debug_nonempty() {
    let b = EvidenceBundle::new("b1".into(), epoch(1));
    let dbg = format!("{b:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("EvidenceBundle"));
}

#[test]
fn enrichment_evidence_bundle_new_schema_version() {
    let b = EvidenceBundle::new("b1".into(), epoch(1));
    assert_eq!(b.schema_version, SCHEMA_VERSION);
}

#[test]
fn enrichment_evidence_bundle_hash_changes_on_parity_add() {
    let mut b = EvidenceBundle::new("b1".into(), epoch(1));
    b.add_provenance(prov("w1", WorkloadCategory::Micro))
        .unwrap();
    let h_before = b.bundle_hash;
    b.add_parity_verdict(parity_verdict("w1", ParityTarget::NodeJs, 1_000_000))
        .unwrap();
    assert_ne!(h_before, b.bundle_hash);
}

#[test]
fn enrichment_evidence_bundle_reference_environment_set_on_first_run() {
    let mut b = EvidenceBundle::new("b1".into(), epoch(1));
    b.add_provenance(prov("w1", WorkloadCategory::Micro))
        .unwrap();
    assert!(b.reference_environment.is_none());
    b.add_run(run_with("r1", "w1", 100, 0)).unwrap();
    assert!(b.reference_environment.is_some());
}

// ===========================================================================
// WorkloadStatEntry enrichment
// ===========================================================================

#[test]
fn enrichment_workload_stat_entry_clone_independence() {
    let entry = WorkloadStatEntry {
        workload_id: "w1".to_string(),
        category: WorkloadCategory::Micro,
        stats: TimingStats::from_durations(&[100, 200]),
        parity_verdicts: 1,
        all_parity_passed: true,
    };
    let mut cloned = entry.clone();
    cloned.parity_verdicts = 99;
    assert_eq!(entry.parity_verdicts, 1);
    assert_eq!(cloned.parity_verdicts, 99);
}

#[test]
fn enrichment_workload_stat_entry_serde_roundtrip() {
    let entry = WorkloadStatEntry {
        workload_id: "w1".to_string(),
        category: WorkloadCategory::Application,
        stats: TimingStats::from_durations(&[100, 200, 300]),
        parity_verdicts: 2,
        all_parity_passed: false,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: WorkloadStatEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ===========================================================================
// Report enrichment
// ===========================================================================

#[test]
fn enrichment_report_categories_match_bundle() {
    let b = full_bundle();
    let r = generate_report(&b, &BundleConfig::default());
    assert_eq!(r.categories, b.categories());
}

#[test]
fn enrichment_report_parity_pass_count() {
    let b = full_bundle();
    let r = generate_report(&b, &BundleConfig::default());
    // Both parity verdicts have ratio >= DEFAULT_MIN_PARITY_RATIO and output_equivalent=true
    assert_eq!(r.parity_pass_count, 2);
}

#[test]
fn enrichment_report_environment_drift_count_zero() {
    let b = full_bundle();
    let r = generate_report(&b, &BundleConfig::default());
    // All runs use same environment
    assert_eq!(r.environment_drift_count, 0);
}

#[test]
fn enrichment_report_schema_version_matches_constant() {
    let b = full_bundle();
    let r = generate_report(&b, &BundleConfig::default());
    assert_eq!(r.schema_version, SCHEMA_VERSION);
}

#[test]
fn enrichment_report_json_field_names() {
    let b = full_bundle();
    let r = generate_report(&b, &BundleConfig::default());
    let json = serde_json::to_string(&r).unwrap();
    for field in [
        "schema_version",
        "bundle_id",
        "status",
        "epoch",
        "total_workloads",
        "total_effective_runs",
        "total_warmup_runs",
        "workload_stats",
        "parity_verdict_count",
        "parity_pass_count",
        "environment_drift_count",
        "categories",
        "verdict",
        "report_hash",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ===========================================================================
// Five-run determinism
// ===========================================================================

#[test]
fn enrichment_five_run_determinism_bundle_hash() {
    let hashes: Vec<_> = (0..5).map(|_| full_bundle().bundle_hash).collect();
    for h in &hashes[1..] {
        assert_eq!(hashes[0], *h);
    }
}

#[test]
fn enrichment_five_run_determinism_report_hash() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let b = full_bundle();
            generate_report(&b, &BundleConfig::default()).report_hash
        })
        .collect();
    for h in &hashes[1..] {
        assert_eq!(hashes[0], *h);
    }
}

#[test]
fn enrichment_five_run_determinism_timing_stats() {
    let stats: Vec<_> = (0..5)
        .map(|_| TimingStats::from_durations(&[100, 200, 300, 400, 500]))
        .collect();
    for s in &stats[1..] {
        assert_eq!(stats[0], *s);
    }
}

#[test]
fn enrichment_five_run_determinism_environment_hash() {
    let hashes: Vec<_> = (0..5).map(|_| env().snapshot_hash).collect();
    for h in &hashes[1..] {
        assert_eq!(hashes[0], *h);
    }
}

// ===========================================================================
// Constants stability
// ===========================================================================

#[test]
fn enrichment_constants_stability() {
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.benchmark-evidence-bundle.v1"
    );
    assert_eq!(COMPONENT, "benchmark_evidence_bundle");
    assert!(BEAD_ID.starts_with("bd-"));
    assert!(POLICY_ID.starts_with("RGC-"));
    assert!(MIN_RUNS_PER_WORKLOAD >= 3);
    assert!(MAX_CV_MILLIONTHS > 0);
    assert!(DEFAULT_MIN_PARITY_RATIO > 0);
    assert!(MAX_ENVIRONMENT_DRIFT > 0);
}

// ===========================================================================
// Cross-cutting
// ===========================================================================

#[test]
fn enrichment_reject_from_assembling_fails() {
    let mut b = full_bundle();
    let err = b.reject().unwrap_err();
    assert!(matches!(err, BundleError::InvalidTransition { .. }));
}

#[test]
fn enrichment_publish_from_assembling_fails() {
    let mut b = full_bundle();
    let err = b.publish().unwrap_err();
    assert!(matches!(err, BundleError::InvalidTransition { .. }));
}

#[test]
fn enrichment_publish_from_rejected_fails() {
    let mut b = full_bundle();
    b.seal().unwrap();
    b.reject().unwrap();
    let err = b.publish().unwrap_err();
    assert!(matches!(err, BundleError::InvalidTransition { .. }));
}

#[test]
fn enrichment_evaluate_after_seal_still_works() {
    let mut b = full_bundle();
    b.seal().unwrap();
    let v = evaluate_bundle(&b, &BundleConfig::default());
    assert!(matches!(v, BundleVerdict::Pass { .. }));
}
