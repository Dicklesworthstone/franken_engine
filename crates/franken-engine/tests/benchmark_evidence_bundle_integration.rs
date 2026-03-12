//! Integration tests for the benchmark_evidence_bundle module.
//!
//! Tests bundle assembly, evaluation, reporting, serde roundtrips,
//! and cross-concern interactions.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::benchmark_evidence_bundle::{
    BEAD_ID, BenchmarkRun, BundleConfig, BundleError, BundleStatus, BundleVerdict, COMPONENT,
    DEFAULT_MIN_PARITY_RATIO, EnvironmentSnapshot, EvidenceBundle, MAX_CV_MILLIONTHS,
    MAX_ENVIRONMENT_DRIFT, MIN_RUNS_PER_WORKLOAD, POLICY_ID, ParityTarget, ParityVerdict,
    SCHEMA_VERSION, TimingStats, WorkloadCategory, WorkloadProvenance, evaluate_bundle,
    generate_report,
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

fn env_different() -> EnvironmentSnapshot {
    EnvironmentSnapshot::new(
        "macos".into(),
        "arm64".into(),
        8,
        32_000_000_000,
        "node 20.0.0".into(),
        "franken 0.2.0".into(),
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

fn run(id: &str, wid: &str, dur: u64, iter: u32) -> BenchmarkRun {
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

fn warmup_run(id: &str, wid: &str) -> BenchmarkRun {
    let mut r = run(id, wid, 5000, 0);
    r.is_warmup = true;
    r
}

fn parity(wid: &str, target: ParityTarget, ratio: u64) -> ParityVerdict {
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
        b.add_run(run(&format!("r1-{i}"), "w1", 1000 + i * 5, i as u32))
            .unwrap();
        b.add_run(run(&format!("r2-{i}"), "w2", 2000 + i * 10, i as u32))
            .unwrap();
    }
    b.add_parity_verdict(parity("w1", ParityTarget::NodeJs, 1_050_000))
        .unwrap();
    b.add_parity_verdict(parity("w2", ParityTarget::NodeJs, 990_000))
        .unwrap();
    b
}

fn default_config() -> BundleConfig {
    BundleConfig::default()
}

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_contains_component() {
    assert!(SCHEMA_VERSION.contains("benchmark-evidence-bundle"));
}

#[test]
fn component_is_snake_case() {
    assert_eq!(COMPONENT, "benchmark_evidence_bundle");
}

#[test]
fn bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn policy_id_format() {
    assert!(POLICY_ID.starts_with("RGC-"));
}

#[test]
fn min_runs_per_workload_sensible() {
    const { assert!(MIN_RUNS_PER_WORKLOAD >= 3) };
}

#[test]
fn max_cv_sensible() {
    const { assert!(MAX_CV_MILLIONTHS > 0) };
    const { assert!(MAX_CV_MILLIONTHS <= 500_000) };
}

#[test]
fn default_parity_ratio_sensible() {
    const { assert!(DEFAULT_MIN_PARITY_RATIO >= 900_000) };
    const { assert!(DEFAULT_MIN_PARITY_RATIO <= 1_000_000) };
}

// ---------------------------------------------------------------------------
// WorkloadCategory
// ---------------------------------------------------------------------------

#[test]
fn workload_category_all_count() {
    assert_eq!(WorkloadCategory::ALL.len(), 6);
}

#[test]
fn workload_category_display_matches_as_str() {
    for &cat in WorkloadCategory::ALL {
        assert_eq!(cat.to_string(), cat.as_str());
    }
}

#[test]
fn workload_category_serde() {
    for &cat in WorkloadCategory::ALL {
        let json = serde_json::to_string(&cat).unwrap();
        let back: WorkloadCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, back);
    }
}

#[test]
fn workload_category_distinct_strings() {
    let strings: BTreeSet<_> = WorkloadCategory::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(strings.len(), WorkloadCategory::ALL.len());
}

// ---------------------------------------------------------------------------
// ParityTarget
// ---------------------------------------------------------------------------

#[test]
fn parity_target_all_count() {
    assert_eq!(ParityTarget::ALL.len(), 4);
}

#[test]
fn parity_target_serde() {
    for &t in ParityTarget::ALL {
        let json = serde_json::to_string(&t).unwrap();
        let back: ParityTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }
}

#[test]
fn parity_target_display() {
    for &t in ParityTarget::ALL {
        assert_eq!(t.to_string(), t.as_str());
    }
}

// ---------------------------------------------------------------------------
// BundleStatus
// ---------------------------------------------------------------------------

#[test]
fn bundle_status_display() {
    assert_eq!(BundleStatus::Assembling.to_string(), "assembling");
    assert_eq!(BundleStatus::Sealed.to_string(), "sealed");
    assert_eq!(BundleStatus::Published.to_string(), "published");
    assert_eq!(BundleStatus::Rejected.to_string(), "rejected");
    assert_eq!(BundleStatus::Superseded.to_string(), "superseded");
}

// ---------------------------------------------------------------------------
// EnvironmentSnapshot
// ---------------------------------------------------------------------------

#[test]
fn environment_hash_deterministic() {
    let e1 = env();
    let e2 = env();
    assert_eq!(e1.snapshot_hash, e2.snapshot_hash);
}

#[test]
fn environment_hash_varies_with_input() {
    let e1 = env();
    let e2 = env_different();
    assert_ne!(e1.snapshot_hash, e2.snapshot_hash);
}

#[test]
fn environment_drift_count() {
    let e1 = env();
    let e2 = env_different();
    let drifts = e1.drift_from(&e2);
    // os, cpu, cores, memory, runtime, engine = 6 drifts
    assert_eq!(drifts.len(), 6);
}

#[test]
fn environment_no_drift_identical() {
    let e1 = env();
    assert!(e1.drift_from(&env()).is_empty());
}

#[test]
fn environment_serde_roundtrip() {
    let e = env();
    let json = serde_json::to_string(&e).unwrap();
    let back: EnvironmentSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// EvidenceBundle CRUD
// ---------------------------------------------------------------------------

#[test]
fn new_bundle_assembling() {
    let b = EvidenceBundle::new("b1".into(), epoch(1));
    assert_eq!(b.status, BundleStatus::Assembling);
    assert!(b.provenances.is_empty());
    assert!(b.runs.is_empty());
    assert!(b.parity_verdicts.is_empty());
}

#[test]
fn add_provenance_success() {
    let mut b = EvidenceBundle::new("b1".into(), epoch(1));
    assert!(
        b.add_provenance(prov("w1", WorkloadCategory::Micro))
            .is_ok()
    );
    assert_eq!(b.provenances.len(), 1);
}

#[test]
fn add_duplicate_provenance_error() {
    let mut b = EvidenceBundle::new("b1".into(), epoch(1));
    b.add_provenance(prov("w1", WorkloadCategory::Micro))
        .unwrap();
    let err = b
        .add_provenance(prov("w1", WorkloadCategory::Application))
        .unwrap_err();
    assert!(matches!(err, BundleError::DuplicateWorkload { .. }));
}

#[test]
fn add_run_without_provenance_error() {
    let mut b = EvidenceBundle::new("b1".into(), epoch(1));
    let err = b.add_run(run("r1", "w1", 100, 0)).unwrap_err();
    assert!(matches!(err, BundleError::MissingProvenance { .. }));
}

#[test]
fn add_run_with_provenance_success() {
    let mut b = EvidenceBundle::new("b1".into(), epoch(1));
    b.add_provenance(prov("w1", WorkloadCategory::Micro))
        .unwrap();
    assert!(b.add_run(run("r1", "w1", 100, 0)).is_ok());
}

#[test]
fn add_parity_verdict_success() {
    let mut b = EvidenceBundle::new("b1".into(), epoch(1));
    assert!(
        b.add_parity_verdict(parity("w1", ParityTarget::NodeJs, 1_000_000))
            .is_ok()
    );
}

#[test]
fn seal_transitions_status() {
    let mut b = full_bundle();
    assert!(b.seal().is_ok());
    assert_eq!(b.status, BundleStatus::Sealed);
}

#[test]
fn sealed_bundle_rejects_adds() {
    let mut b = full_bundle();
    b.seal().unwrap();
    assert!(matches!(
        b.add_provenance(prov("w3", WorkloadCategory::Memory)),
        Err(BundleError::BundleSealed { .. })
    ));
    assert!(matches!(
        b.add_run(run("rx", "w1", 100, 99)),
        Err(BundleError::BundleSealed { .. })
    ));
    assert!(matches!(
        b.add_parity_verdict(parity("w1", ParityTarget::Bun, 1_000_000)),
        Err(BundleError::BundleSealed { .. })
    ));
}

#[test]
fn publish_requires_sealed() {
    let mut b = full_bundle();
    assert!(matches!(
        b.publish(),
        Err(BundleError::InvalidTransition { .. })
    ));
    b.seal().unwrap();
    assert!(b.publish().is_ok());
    assert_eq!(b.status, BundleStatus::Published);
}

#[test]
fn reject_requires_sealed() {
    let mut b = full_bundle();
    b.seal().unwrap();
    assert!(b.reject().is_ok());
    assert_eq!(b.status, BundleStatus::Rejected);
}

#[test]
fn double_seal_error() {
    let mut b = full_bundle();
    b.seal().unwrap();
    assert!(matches!(b.seal(), Err(BundleError::BundleSealed { .. })));
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

#[test]
fn effective_runs_excludes_warmup() {
    let mut b = EvidenceBundle::new("b1".into(), epoch(1));
    b.add_provenance(prov("w1", WorkloadCategory::Micro))
        .unwrap();
    b.add_run(warmup_run("w0", "w1")).unwrap();
    b.add_run(run("r1", "w1", 100, 1)).unwrap();
    assert_eq!(b.runs.len(), 2);
    assert_eq!(b.effective_runs().len(), 1);
}

#[test]
fn runs_for_workload() {
    let b = full_bundle();
    assert_eq!(b.runs_for_workload("w1").len(), 6);
    assert_eq!(b.runs_for_workload("w2").len(), 6);
    assert_eq!(b.runs_for_workload("w999").len(), 0);
}

#[test]
fn workload_ids() {
    let b = full_bundle();
    let ids = b.workload_ids();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&"w1"));
    assert!(ids.contains(&"w2"));
}

#[test]
fn categories_from_provenances() {
    let b = full_bundle();
    let cats = b.categories();
    assert!(cats.contains(&WorkloadCategory::Micro));
    assert!(cats.contains(&WorkloadCategory::Application));
}

#[test]
fn workload_stats_present() {
    let b = full_bundle();
    let stats = b.workload_stats("w1").unwrap();
    assert_eq!(stats.count, 6);
    assert!(stats.min_us > 0);
}

#[test]
fn workload_stats_absent() {
    let b = full_bundle();
    assert!(b.workload_stats("nonexist").is_none());
}

#[test]
fn parity_for_workload_filters() {
    let b = full_bundle();
    assert_eq!(b.parity_for_workload("w1").len(), 1);
    assert_eq!(b.parity_for_workload("w2").len(), 1);
    assert_eq!(b.parity_for_workload("w999").len(), 0);
}

// ---------------------------------------------------------------------------
// TimingStats
// ---------------------------------------------------------------------------

#[test]
fn timing_stats_empty_input() {
    let stats = TimingStats::from_durations(&[]);
    assert_eq!(stats.count, 0);
}

#[test]
fn timing_stats_single_value() {
    let stats = TimingStats::from_durations(&[42]);
    assert_eq!(stats.count, 1);
    assert_eq!(stats.min_us, 42);
    assert_eq!(stats.max_us, 42);
    assert_eq!(stats.mean_us, 42);
}

#[test]
fn timing_stats_constant_values() {
    let stats = TimingStats::from_durations(&[100, 100, 100, 100, 100]);
    assert_eq!(stats.cv_millionths, 0);
    assert!(stats.is_stable(MAX_CV_MILLIONTHS));
}

#[test]
fn timing_stats_percentiles_100_values() {
    let durations: Vec<u64> = (1..=100).collect();
    let stats = TimingStats::from_durations(&durations);
    assert_eq!(stats.min_us, 1);
    assert_eq!(stats.max_us, 100);
    assert_eq!(stats.p95_us, 95);
    assert_eq!(stats.p99_us, 99);
}

#[test]
fn timing_stats_serde() {
    let stats = TimingStats::from_durations(&[100, 200, 300]);
    let json = serde_json::to_string(&stats).unwrap();
    let back: TimingStats = serde_json::from_str(&json).unwrap();
    assert_eq!(stats, back);
}

// ---------------------------------------------------------------------------
// ParityVerdict
// ---------------------------------------------------------------------------

#[test]
fn parity_acceptable_above_threshold() {
    let v = parity("w1", ParityTarget::NodeJs, 1_050_000);
    assert!(v.is_acceptable(DEFAULT_MIN_PARITY_RATIO));
}

#[test]
fn parity_unacceptable_below_threshold() {
    let v = parity("w1", ParityTarget::NodeJs, 800_000);
    assert!(!v.is_acceptable(DEFAULT_MIN_PARITY_RATIO));
}

#[test]
fn parity_unacceptable_not_equivalent() {
    let mut v = parity("w1", ParityTarget::NodeJs, 1_200_000);
    v.output_equivalent = false;
    assert!(!v.is_acceptable(DEFAULT_MIN_PARITY_RATIO));
}

// ---------------------------------------------------------------------------
// Evaluation — Pass
// ---------------------------------------------------------------------------

#[test]
fn evaluate_pass_full_bundle() {
    let b = full_bundle();
    let v = evaluate_bundle(&b, &default_config());
    assert!(matches!(v, BundleVerdict::Pass { .. }));
    if let BundleVerdict::Pass {
        workload_count,
        total_runs,
        ..
    } = v
    {
        assert_eq!(workload_count, 2);
        assert_eq!(total_runs, 12);
    }
}

// ---------------------------------------------------------------------------
// Evaluation — Incomplete
// ---------------------------------------------------------------------------

#[test]
fn evaluate_incomplete_no_provenances() {
    let b = EvidenceBundle::new("empty".into(), epoch(5));
    let v = evaluate_bundle(&b, &default_config());
    assert!(matches!(v, BundleVerdict::Incomplete { .. }));
}

#[test]
fn evaluate_incomplete_missing_category() {
    let b = full_bundle();
    let mut cfg = default_config();
    cfg.required_categories.insert(WorkloadCategory::ColdStart);
    let v = evaluate_bundle(&b, &cfg);
    assert!(matches!(v, BundleVerdict::Incomplete { .. }));
}

#[test]
fn evaluate_incomplete_missing_parity_target() {
    let b = full_bundle();
    let mut cfg = default_config();
    cfg.required_parity_targets.insert(ParityTarget::Bun);
    let v = evaluate_bundle(&b, &cfg);
    assert!(matches!(v, BundleVerdict::Incomplete { .. }));
}

// ---------------------------------------------------------------------------
// Evaluation — Fail
// ---------------------------------------------------------------------------

#[test]
fn evaluate_fail_insufficient_runs() {
    let mut b = EvidenceBundle::new("b1".into(), epoch(5));
    b.add_provenance(prov("w1", WorkloadCategory::Micro))
        .unwrap();
    b.add_run(run("r1", "w1", 100, 0)).unwrap();
    let v = evaluate_bundle(&b, &default_config());
    assert!(matches!(v, BundleVerdict::Fail { .. }));
}

#[test]
fn evaluate_fail_stale_epoch() {
    let b = full_bundle();
    let mut cfg = default_config();
    cfg.min_verification_epoch = epoch(100);
    let v = evaluate_bundle(&b, &cfg);
    assert!(matches!(v, BundleVerdict::Fail { .. }));
}

#[test]
fn evaluate_fail_parity_failure() {
    let mut b = full_bundle();
    b.add_parity_verdict(ParityVerdict {
        workload_id: "w1".into(),
        target: ParityTarget::Bun,
        output_equivalent: false,
        performance_ratio_millionths: 500_000,
        behavioral_differences: 5,
        difference_details: vec!["output mismatch".into()],
        evidence_hash: ContentHash::compute(b"bad"),
    })
    .unwrap();
    let v = evaluate_bundle(&b, &default_config());
    assert!(matches!(v, BundleVerdict::Fail { .. }));
}

#[test]
fn evaluate_fail_environment_drift() {
    let mut b = EvidenceBundle::new("b1".into(), epoch(5));
    b.add_provenance(prov("w1", WorkloadCategory::Micro))
        .unwrap();
    for i in 0..6 {
        let mut r = run(&format!("r-{i}"), "w1", 1000, i as u32);
        if i > 0 {
            r.environment = EnvironmentSnapshot::new(
                format!("os-{i}"),
                format!("cpu-{i}"),
                (16 + i) as u32,
                64_000_000_000 + (i as u64) * 1000,
                "node 22.1.0".into(),
                "franken 0.1.0".into(),
                BTreeMap::new(),
            );
        }
        b.add_run(r).unwrap();
    }
    let v = evaluate_bundle(&b, &default_config());
    assert!(matches!(v, BundleVerdict::Fail { .. }));
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

#[test]
fn report_basic_fields() {
    let b = full_bundle();
    let r = generate_report(&b, &default_config());
    assert_eq!(r.bundle_id, "bundle-1");
    assert_eq!(r.total_workloads, 2);
    assert_eq!(r.total_effective_runs, 12);
    assert_eq!(r.parity_verdict_count, 2);
}

#[test]
fn report_workload_stats_populated() {
    let b = full_bundle();
    let r = generate_report(&b, &default_config());
    assert_eq!(r.workload_stats.len(), 2);
    for ws in &r.workload_stats {
        assert!(ws.stats.count >= 5);
    }
}

#[test]
fn report_hash_deterministic() {
    let b = full_bundle();
    let r1 = generate_report(&b, &default_config());
    let r2 = generate_report(&b, &default_config());
    assert_eq!(r1.report_hash, r2.report_hash);
}

#[test]
fn report_warmup_count() {
    let mut b = EvidenceBundle::new("b1".into(), epoch(5));
    b.add_provenance(prov("w1", WorkloadCategory::Micro))
        .unwrap();
    b.add_run(warmup_run("w0", "w1")).unwrap();
    for i in 0..6 {
        b.add_run(run(&format!("r-{i}"), "w1", 100, i as u32 + 1))
            .unwrap();
    }
    let r = generate_report(&b, &default_config());
    assert_eq!(r.total_warmup_runs, 1);
    assert_eq!(r.total_effective_runs, 6);
}

#[test]
fn report_verdict_pass() {
    let b = full_bundle();
    let r = generate_report(&b, &default_config());
    assert!(matches!(r.verdict, BundleVerdict::Pass { .. }));
}

// ---------------------------------------------------------------------------
// Hash integrity
// ---------------------------------------------------------------------------

#[test]
fn bundle_hash_changes_on_provenance_add() {
    let mut b = EvidenceBundle::new("b1".into(), epoch(1));
    let h1 = b.bundle_hash;
    b.add_provenance(prov("w1", WorkloadCategory::Micro))
        .unwrap();
    assert_ne!(h1, b.bundle_hash);
}

#[test]
fn bundle_hash_changes_on_run_add() {
    let mut b = EvidenceBundle::new("b1".into(), epoch(1));
    b.add_provenance(prov("w1", WorkloadCategory::Micro))
        .unwrap();
    let h1 = b.bundle_hash;
    b.add_run(run("r1", "w1", 100, 0)).unwrap();
    assert_ne!(h1, b.bundle_hash);
}

#[test]
fn bundle_hash_changes_on_seal() {
    let mut b = full_bundle();
    let h1 = b.bundle_hash;
    b.seal().unwrap();
    assert_ne!(h1, b.bundle_hash);
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn bundle_serde_roundtrip() {
    let b = full_bundle();
    let json = serde_json::to_string(&b).unwrap();
    let back: EvidenceBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(b.bundle_id, back.bundle_id);
    assert_eq!(b.runs.len(), back.runs.len());
    assert_eq!(b.provenances.len(), back.provenances.len());
}

#[test]
fn config_serde_roundtrip() {
    let cfg = default_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: BundleConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn report_serde_roundtrip() {
    let b = full_bundle();
    let r = generate_report(&b, &default_config());
    let json = serde_json::to_string(&r).unwrap();
    let back = serde_json::from_str::<serde_json::Value>(&json).unwrap();
    assert_eq!(back["bundle_id"], "bundle-1");
}

#[test]
fn verdict_serde_roundtrip() {
    let v = BundleVerdict::Fail {
        reasons: vec!["too few runs".into()],
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: BundleVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// Error display
// ---------------------------------------------------------------------------

#[test]
fn error_display_sealed() {
    let e = BundleError::BundleSealed {
        bundle_id: "b1".into(),
    };
    assert!(e.to_string().contains("sealed"));
}

#[test]
fn error_display_duplicate() {
    let e = BundleError::DuplicateWorkload {
        workload_id: "w1".into(),
    };
    assert!(e.to_string().contains("duplicate"));
}

#[test]
fn error_display_missing_provenance() {
    let e = BundleError::MissingProvenance {
        workload_id: "w1".into(),
    };
    assert!(e.to_string().contains("provenance"));
}

#[test]
fn error_display_invalid_transition() {
    let e = BundleError::InvalidTransition {
        from: BundleStatus::Assembling,
        to: BundleStatus::Published,
    };
    assert!(e.to_string().contains("invalid"));
}

#[test]
fn error_display_stale() {
    let e = BundleError::StaleEvidence {
        bundle_epoch: 1,
        required_epoch: 5,
    };
    assert!(e.to_string().contains("stale"));
}

// ---------------------------------------------------------------------------
// Cross-concern: full workflow
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_assemble_seal_publish() {
    let mut b = full_bundle();
    assert_eq!(b.status, BundleStatus::Assembling);

    // Evaluate before seal — should pass.
    let v = evaluate_bundle(&b, &default_config());
    assert!(matches!(v, BundleVerdict::Pass { .. }));

    // Seal.
    b.seal().unwrap();
    assert_eq!(b.status, BundleStatus::Sealed);

    // Publish.
    b.publish().unwrap();
    assert_eq!(b.status, BundleStatus::Published);
}

#[test]
fn multi_workload_multi_target_evaluation() {
    let mut b = EvidenceBundle::new("multi".into(), epoch(5));
    for (wid, cat) in [
        ("micro-1", WorkloadCategory::Micro),
        ("app-1", WorkloadCategory::Application),
        ("fw-1", WorkloadCategory::Framework),
    ] {
        b.add_provenance(prov(wid, cat)).unwrap();
        for i in 0..6 {
            b.add_run(run(&format!("{wid}-r{i}"), wid, 500 + i * 5, i as u32))
                .unwrap();
        }
        b.add_parity_verdict(parity(wid, ParityTarget::NodeJs, 1_000_000))
            .unwrap();
        b.add_parity_verdict(parity(wid, ParityTarget::Bun, 1_100_000))
            .unwrap();
    }
    let v = evaluate_bundle(&b, &default_config());
    assert!(matches!(
        v,
        BundleVerdict::Pass {
            workload_count: 3,
            total_runs: 18,
            ..
        }
    ));
}

#[test]
fn config_with_required_categories_and_targets() {
    let b = full_bundle();
    let mut cfg = default_config();
    cfg.required_categories.insert(WorkloadCategory::Micro);
    cfg.required_categories
        .insert(WorkloadCategory::Application);
    cfg.required_parity_targets.insert(ParityTarget::NodeJs);
    let v = evaluate_bundle(&b, &cfg);
    assert!(matches!(v, BundleVerdict::Pass { .. }));
}

#[test]
fn environment_drift_tracking_across_runs() {
    let mut b = EvidenceBundle::new("b1".into(), epoch(5));
    b.add_provenance(prov("w1", WorkloadCategory::Micro))
        .unwrap();
    // First run sets reference.
    b.add_run(run("r0", "w1", 100, 0)).unwrap();
    assert!(b.environment_drifts.is_empty());
    // Second run with different env.
    let mut r = run("r1", "w1", 100, 1);
    r.environment = env_different();
    b.add_run(r).unwrap();
    assert!(!b.environment_drifts.is_empty());
}

#[test]
fn max_environment_drift_respected() {
    let mut b = EvidenceBundle::new("b1".into(), epoch(5));
    b.add_provenance(prov("w1", WorkloadCategory::Micro))
        .unwrap();
    b.add_run(run("r0", "w1", 100, 0)).unwrap();
    // Add runs with enough drift to exceed MAX_ENVIRONMENT_DRIFT.
    for i in 1..=6u64 {
        let mut r = run(&format!("r{i}"), "w1", 100, i as u32);
        r.environment = EnvironmentSnapshot::new(
            format!("os-{i}"),
            format!("cpu-{i}"),
            i as u32,
            i * 1_000_000_000,
            format!("node {i}.0.0"),
            format!("franken 0.{i}.0"),
            BTreeMap::new(),
        );
        b.add_run(r).unwrap();
    }
    assert!(b.environment_drifts.len() > MAX_ENVIRONMENT_DRIFT);
    let v = evaluate_bundle(&b, &default_config());
    assert!(matches!(v, BundleVerdict::Fail { .. }));
}
