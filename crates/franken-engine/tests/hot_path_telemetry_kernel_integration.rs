//! Integration tests for hot_path_telemetry_kernel.
//!
//! Tests: kernel lifecycle, sketch writing, exact-shadow calibration,
//! evidence thinning, manifest building, determinism, serde round-trips,
//! budget exhaustion, capture mode transitions, and end-to-end workflows.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::hot_path_telemetry_kernel::{
    COMPONENT, CalibrationEvidence, CaptureMode, ExactShadowCounter, HotPathEvidenceEntry,
    KernelRegistry, KernelState, KernelSummary, SCHEMA_VERSION, SketchWriterKind, TelemetryError,
    TelemetryManifest, ThinnedBundle, ThinningPolicy, ThinningStrategy, apply_thinning,
    build_manifest, build_registry, calibrate_kernel, create_kernel, register_kernel,
    submit_observation,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

const MILLION: u64 = 1_000_000;

fn make_kernel(id: &str, rate: u64, budget: u64) -> KernelState {
    create_kernel(
        id.to_string(),
        SketchWriterKind::CountMin,
        rate,
        budget,
        epoch(1),
    )
}

fn make_policy(id: &str, strategy: ThinningStrategy, retention: u64) -> ThinningPolicy {
    ThinningPolicy::new(id.to_string(), strategy, retention, 0, 0)
}

fn make_entry(
    id: &str,
    kernel_id: &str,
    key: &str,
    seq: u64,
    mode: CaptureMode,
) -> HotPathEvidenceEntry {
    HotPathEvidenceEntry {
        entry_id: id.to_string(),
        kernel_id: kernel_id.to_string(),
        key: key.to_string(),
        weight_millionths: MILLION,
        priority: 0,
        capture_mode: mode,
        epoch: epoch(1),
        sequence: seq,
        content_hash: ContentHash::compute(format!("{id}:{kernel_id}:{key}:{seq}").as_bytes()),
    }
}

// ---------------------------------------------------------------------------
// Kernel lifecycle
// ---------------------------------------------------------------------------

#[test]
fn integration_kernel_create_and_register() {
    let mut registry = build_registry("int-reg".to_string(), epoch(1));
    let k1 = create_kernel(
        "k1".to_string(),
        SketchWriterKind::CountMin,
        MILLION,
        500,
        epoch(1),
    );
    let k2 = create_kernel(
        "k2".to_string(),
        SketchWriterKind::HeavyHitter,
        500_000,
        1000,
        epoch(1),
    );
    register_kernel(&mut registry, k1).unwrap();
    register_kernel(&mut registry, k2).unwrap();
    assert_eq!(registry.kernels.len(), 2);
    assert_eq!(registry.active_count(), 2);
    // Deterministic ordering by kernel_id.
    assert_eq!(registry.kernels[0].kernel_id, "k1");
    assert_eq!(registry.kernels[1].kernel_id, "k2");
}

#[test]
fn integration_kernel_all_writer_kinds() {
    let kinds = [
        SketchWriterKind::CountMin,
        SketchWriterKind::HeavyHitter,
        SketchWriterKind::Quantile,
        SketchWriterKind::Histogram,
    ];
    let mut registry = build_registry("kinds-reg".to_string(), epoch(1));
    for (i, kind) in kinds.iter().enumerate() {
        let k = create_kernel(format!("k{i}"), *kind, MILLION, 100, epoch(1));
        register_kernel(&mut registry, k).unwrap();
    }
    assert_eq!(registry.kernels.len(), 4);
    // Each kernel should have different writer_kind.
    let writer_kinds: BTreeSet<String> = registry
        .kernels
        .iter()
        .map(|k| k.writer_kind.as_str().to_string())
        .collect();
    assert_eq!(writer_kinds.len(), 4);
}

#[test]
fn integration_registry_hash_deterministic() {
    let mut r1 = build_registry("det-reg".to_string(), epoch(1));
    let mut r2 = build_registry("det-reg".to_string(), epoch(1));
    for id in ["k_a", "k_b", "k_c"] {
        register_kernel(&mut r1, make_kernel(id, MILLION, 100)).unwrap();
        register_kernel(&mut r2, make_kernel(id, MILLION, 100)).unwrap();
    }
    assert_eq!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// Sketch writing
// ---------------------------------------------------------------------------

#[test]
fn integration_submit_observations_accumulate() {
    let mut k = make_kernel("k1", MILLION, 100);
    // Submit same key multiple times.
    for _ in 0..10 {
        submit_observation(&mut k, "opcode_add", 500_000).unwrap();
    }
    assert_eq!(k.accepted_count, 10);
    assert_eq!(k.sketch_buckets.len(), 1);
    let bucket = &k.sketch_buckets[0];
    assert_eq!(bucket.key, "opcode_add");
    assert_eq!(bucket.weight_millionths, 5_000_000); // 10 * 500k
    assert_eq!(bucket.count, 10);
}

#[test]
fn integration_submit_multiple_keys() {
    let mut k = make_kernel("k1", MILLION, 100);
    for i in 0..20 {
        submit_observation(&mut k, &format!("key_{}", i % 5), MILLION).unwrap();
    }
    assert_eq!(k.sketch_buckets.len(), 5);
    assert_eq!(k.accepted_count, 20);
    // Each key should have count 4.
    for bucket in &k.sketch_buckets {
        assert_eq!(bucket.count, 4);
    }
}

#[test]
fn integration_submit_returns_entry_with_correct_fields() {
    let mut k = make_kernel("k1", MILLION, 100);
    let entry = submit_observation(&mut k, "test_key", 750_000)
        .unwrap()
        .unwrap();
    assert!(entry.entry_id.starts_with("hpte-k1-0-"));
    assert_eq!(entry.kernel_id, "k1");
    assert_eq!(entry.key, "test_key");
    assert_eq!(entry.weight_millionths, 750_000);
    assert_eq!(entry.capture_mode, CaptureMode::Budgeted);
    assert_eq!(entry.sequence, 0);
}

#[test]
fn integration_budget_exhaustion_transitions_to_degraded() {
    let mut k = make_kernel("k1", MILLION, 5);
    for i in 0..5 {
        let result = submit_observation(&mut k, &format!("key_{i}"), MILLION);
        assert!(result.is_ok());
    }
    assert!(k.exhausted);
    assert_eq!(k.capture_mode, CaptureMode::Degraded);
    assert!(!k.is_active());
    // Further submissions fail.
    let err = submit_observation(&mut k, "extra", MILLION).unwrap_err();
    assert!(matches!(err, TelemetryError::BudgetExhausted(_)));
}

#[test]
fn integration_sequence_monotonic() {
    let mut k = make_kernel("k1", MILLION, 100);
    let mut last_seq = 0u64;
    for i in 0..10 {
        let entry = submit_observation(&mut k, &format!("key_{i}"), MILLION)
            .unwrap()
            .unwrap();
        if i > 0 {
            assert!(entry.sequence > last_seq);
        }
        last_seq = entry.sequence;
    }
}

// ---------------------------------------------------------------------------
// Exact-shadow calibration
// ---------------------------------------------------------------------------

#[test]
fn integration_calibration_perfect_alignment() {
    let mut k = make_kernel("k1", MILLION, 100);
    let mut shadow = ExactShadowCounter::new("k1".to_string());
    let keys = ["add", "sub", "mul", "div", "mod"];
    for key in &keys {
        for _ in 0..10 {
            submit_observation(&mut k, key, MILLION).unwrap();
            shadow.observe(key, MILLION);
        }
    }
    let evidence = calibrate_kernel(&k, &shadow, epoch(1)).unwrap();
    assert!(evidence.passed);
    assert_eq!(evidence.keys_compared, 5);
    assert_eq!(evidence.mean_error_millionths, 0);
    assert_eq!(evidence.max_error_millionths, 0);
    for r in &evidence.per_key_results {
        assert!(r.passed);
        assert_eq!(r.exact_count, 10);
        assert_eq!(r.sketch_estimate, 10);
    }
}

#[test]
fn integration_calibration_detects_undercounting() {
    let mut k = make_kernel("k1", MILLION, 100);
    let mut shadow = ExactShadowCounter::new("k1".to_string());
    // Sketch sees 5, shadow sees 20.
    for _ in 0..5 {
        submit_observation(&mut k, "key_a", MILLION).unwrap();
    }
    for _ in 0..20 {
        shadow.observe("key_a", MILLION);
    }
    let evidence = calibrate_kernel(&k, &shadow, epoch(1)).unwrap();
    assert!(!evidence.passed);
    let r = &evidence.per_key_results[0];
    // Error = |5 - 20| / 20 = 75% = 750_000 millionths.
    assert_eq!(r.absolute_error, 15);
    assert_eq!(r.relative_error_millionths, 750_000);
}

#[test]
fn integration_calibration_detects_overcounting() {
    let mut k = make_kernel("k1", MILLION, 100);
    let mut shadow = ExactShadowCounter::new("k1".to_string());
    // Sketch sees 20, shadow sees 10.
    for _ in 0..20 {
        submit_observation(&mut k, "key_a", MILLION).unwrap();
    }
    for _ in 0..10 {
        shadow.observe("key_a", MILLION);
    }
    let evidence = calibrate_kernel(&k, &shadow, epoch(1)).unwrap();
    assert!(!evidence.passed);
    let r = &evidence.per_key_results[0];
    assert_eq!(r.exact_count, 10);
    assert_eq!(r.sketch_estimate, 20);
    assert_eq!(r.absolute_error, 10);
}

#[test]
fn integration_calibration_evidence_hash_stable() {
    let mut k1 = make_kernel("k1", MILLION, 100);
    let mut s1 = ExactShadowCounter::new("k1".to_string());
    let mut k2 = make_kernel("k1", MILLION, 100);
    let mut s2 = ExactShadowCounter::new("k1".to_string());
    for i in 0..5 {
        let key = format!("key_{i}");
        submit_observation(&mut k1, &key, MILLION).unwrap();
        s1.observe(&key, MILLION);
        submit_observation(&mut k2, &key, MILLION).unwrap();
        s2.observe(&key, MILLION);
    }
    let e1 = calibrate_kernel(&k1, &s1, epoch(1)).unwrap();
    let e2 = calibrate_kernel(&k2, &s2, epoch(1)).unwrap();
    assert_eq!(e1.content_hash, e2.content_hash);
}

#[test]
fn integration_calibration_error_mismatched_kernel() {
    let k = make_kernel("k1", MILLION, 100);
    let shadow = ExactShadowCounter::new("k_other".to_string());
    let err = calibrate_kernel(&k, &shadow, epoch(1)).unwrap_err();
    assert!(matches!(err, TelemetryError::KernelNotFound(_)));
}

#[test]
fn integration_shadow_counter_accumulates_weight() {
    let mut shadow = ExactShadowCounter::new("k1".to_string());
    shadow.observe("key_a", 300_000);
    shadow.observe("key_a", 700_000);
    shadow.observe("key_b", 500_000);
    assert_eq!(shadow.total_weight_millionths, 1_500_000);
    assert_eq!(shadow.total_observations, 3);
    assert_eq!(shadow.distinct_keys(), 2);
}

// ---------------------------------------------------------------------------
// Evidence thinning
// ---------------------------------------------------------------------------

#[test]
fn integration_thinning_retains_all_at_full_rate() {
    let entries: Vec<HotPathEvidenceEntry> = (0..50)
        .map(|i| {
            make_entry(
                &format!("e{i}"),
                "k1",
                &format!("key_{i}"),
                i,
                CaptureMode::Budgeted,
            )
        })
        .collect();
    let policy = make_policy("retain-all", ThinningStrategy::UniformRate, MILLION);
    let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();
    assert_eq!(bundle.original_count, 50);
    assert_eq!(bundle.retained_count, 50);
    assert_eq!(bundle.discarded_ids.len(), 0);
    assert_eq!(bundle.actual_retention_millionths, MILLION);
}

#[test]
fn integration_thinning_rejects_zero_retention() {
    let entries = vec![make_entry("e0", "k1", "key_0", 0, CaptureMode::Budgeted)];
    let policy = make_policy("zero", ThinningStrategy::UniformRate, 0);
    let err = apply_thinning(&entries, &policy, epoch(1)).unwrap_err();
    assert!(matches!(err, TelemetryError::InvalidPolicy(_)));
}

#[test]
fn integration_thinning_hash_deterministic_stable() {
    let entries: Vec<HotPathEvidenceEntry> = (0..200)
        .map(|i| {
            make_entry(
                &format!("e{i}"),
                "k1",
                &format!("key_{i}"),
                i,
                CaptureMode::Budgeted,
            )
        })
        .collect();
    let policy = make_policy("det", ThinningStrategy::HashDeterministic, 300_000);
    let b1 = apply_thinning(&entries, &policy, epoch(1)).unwrap();
    let b2 = apply_thinning(&entries, &policy, epoch(1)).unwrap();
    assert_eq!(b1.retained_ids, b2.retained_ids);
    assert_eq!(b1.discarded_ids, b2.discarded_ids);
    assert_eq!(b1.content_hash, b2.content_hash);
}

#[test]
fn integration_thinning_priority_entries_always_kept() {
    let mut entries: Vec<HotPathEvidenceEntry> = (0..20)
        .map(|i| {
            make_entry(
                &format!("e{i}"),
                "k1",
                &format!("key_{i}"),
                i,
                CaptureMode::Budgeted,
            )
        })
        .collect();
    // Mark first 5 as high priority.
    for entry in entries.iter_mut().take(5) {
        entry.priority = 100;
    }
    let mut policy = ThinningPolicy::new(
        "prio".to_string(),
        ThinningStrategy::UniformRate,
        1, // Almost zero retention.
        0,
        50, // Priority floor.
    );
    let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();
    // At least the 5 priority entries should be retained.
    assert!(bundle.priority_retained_count >= 5);
    for i in 0..5 {
        assert!(bundle.retained_ids.contains(&format!("e{i}")));
    }
}

#[test]
fn integration_thinning_exact_mode_always_retained() {
    let entries = vec![
        make_entry("exact1", "k1", "key_0", 0, CaptureMode::ExactShadow),
        make_entry("exact2", "k1", "key_1", 1, CaptureMode::FullCapture),
        make_entry("budget1", "k1", "key_2", 2, CaptureMode::Budgeted),
        make_entry("budget2", "k1", "key_3", 3, CaptureMode::Budgeted),
        make_entry("degraded1", "k1", "key_4", 4, CaptureMode::Degraded),
    ];
    let policy = make_policy("exact-keep", ThinningStrategy::UniformRate, 1);
    let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();
    assert!(bundle.retained_ids.contains("exact1"));
    assert!(bundle.retained_ids.contains("exact2"));
}

#[test]
fn integration_thinning_empty_input() {
    let entries: Vec<HotPathEvidenceEntry> = Vec::new();
    let policy = make_policy("empty", ThinningStrategy::UniformRate, MILLION);
    let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();
    assert_eq!(bundle.original_count, 0);
    assert_eq!(bundle.retained_count, 0);
    assert_eq!(bundle.actual_retention_millionths, 0);
}

#[test]
fn integration_thinning_all_strategies() {
    let entries: Vec<HotPathEvidenceEntry> = (0..50)
        .map(|i| {
            make_entry(
                &format!("e{i}"),
                "k1",
                &format!("key_{i}"),
                i,
                CaptureMode::Budgeted,
            )
        })
        .collect();
    let strategies = [
        ThinningStrategy::UniformRate,
        ThinningStrategy::HashDeterministic,
        ThinningStrategy::WeightProportional,
        ThinningStrategy::EpochAdaptive,
        ThinningStrategy::PriorityTiered,
    ];
    for strategy in &strategies {
        let policy = make_policy(&format!("strat-{}", strategy.as_str()), *strategy, 500_000);
        let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();
        assert!(
            bundle.retained_count > 0,
            "strategy {} retained nothing",
            strategy.as_str()
        );
        assert!(
            bundle.retained_count <= 50,
            "strategy {} retained too many",
            strategy.as_str()
        );
    }
}

#[test]
fn integration_thinning_bundle_ids_unique() {
    let entries: Vec<HotPathEvidenceEntry> = (0..10)
        .map(|i| {
            make_entry(
                &format!("e{i}"),
                "k1",
                &format!("key_{i}"),
                i,
                CaptureMode::Budgeted,
            )
        })
        .collect();
    let p1 = make_policy("pol-a", ThinningStrategy::UniformRate, 500_000);
    let p2 = make_policy("pol-b", ThinningStrategy::UniformRate, 500_000);
    let b1 = apply_thinning(&entries, &p1, epoch(1)).unwrap();
    let b2 = apply_thinning(&entries, &p2, epoch(1)).unwrap();
    assert_ne!(b1.bundle_id, b2.bundle_id);
}

// ---------------------------------------------------------------------------
// Manifest building
// ---------------------------------------------------------------------------

#[test]
fn integration_manifest_healthy_registry() {
    let mut registry = build_registry("man-reg".to_string(), epoch(5));
    register_kernel(&mut registry, make_kernel("k1", MILLION, 100)).unwrap();
    register_kernel(&mut registry, make_kernel("k2", 500_000, 200)).unwrap();
    let manifest = build_manifest(
        "man-1".to_string(),
        &registry,
        Vec::new(),
        Vec::new(),
        epoch(5),
    );
    assert!(manifest.publishable);
    assert_eq!(manifest.kernel_summaries.len(), 2);
    assert_eq!(manifest.overall_mode, CaptureMode::Budgeted);
    assert_eq!(manifest.schema_version, SCHEMA_VERSION);
}

#[test]
fn integration_manifest_degraded_kernel_blocks_publish() {
    let mut registry = build_registry("deg-reg".to_string(), epoch(1));
    let mut k = make_kernel("k1", MILLION, 1);
    submit_observation(&mut k, "key", MILLION).unwrap();
    register_kernel(&mut registry, k).unwrap();
    let manifest = build_manifest(
        "deg-man".to_string(),
        &registry,
        Vec::new(),
        Vec::new(),
        epoch(1),
    );
    assert!(!manifest.publishable);
    assert!(
        manifest
            .rejection_reasons
            .iter()
            .any(|r| r.contains("degraded"))
    );
}

#[test]
fn integration_manifest_failed_calibration_blocks_publish() {
    let mut registry = build_registry("cal-reg".to_string(), epoch(1));
    register_kernel(&mut registry, make_kernel("k1", MILLION, 100)).unwrap();
    let failed_cal = CalibrationEvidence {
        kernel_id: "k1".to_string(),
        epoch: epoch(1),
        per_key_results: Vec::new(),
        mean_error_millionths: 150_000,
        max_error_millionths: 300_000,
        passed: false,
        threshold_millionths: 50_000,
        keys_compared: 5,
        content_hash: ContentHash::compute(b"failed"),
    };
    let manifest = build_manifest(
        "cal-man".to_string(),
        &registry,
        vec![failed_cal],
        Vec::new(),
        epoch(1),
    );
    assert!(!manifest.publishable);
    assert!(
        manifest
            .rejection_reasons
            .iter()
            .any(|r| r.contains("calibration"))
    );
}

#[test]
fn integration_manifest_hash_deterministic() {
    let mut r1 = build_registry("det-reg".to_string(), epoch(1));
    register_kernel(&mut r1, make_kernel("k1", MILLION, 100)).unwrap();
    let mut r2 = build_registry("det-reg".to_string(), epoch(1));
    register_kernel(&mut r2, make_kernel("k1", MILLION, 100)).unwrap();
    let m1 = build_manifest("det-man".to_string(), &r1, Vec::new(), Vec::new(), epoch(1));
    let m2 = build_manifest("det-man".to_string(), &r2, Vec::new(), Vec::new(), epoch(1));
    assert_eq!(m1.content_hash, m2.content_hash);
}

#[test]
fn integration_manifest_with_thinning_reports() {
    let mut registry = build_registry("thin-reg".to_string(), epoch(1));
    register_kernel(&mut registry, make_kernel("k1", MILLION, 100)).unwrap();
    let entries: Vec<HotPathEvidenceEntry> = (0..20)
        .map(|i| {
            make_entry(
                &format!("e{i}"),
                "k1",
                &format!("key_{i}"),
                i,
                CaptureMode::Budgeted,
            )
        })
        .collect();
    let policy = make_policy("thin-pol", ThinningStrategy::UniformRate, 500_000);
    let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();
    let manifest = build_manifest(
        "thin-man".to_string(),
        &registry,
        Vec::new(),
        vec![bundle],
        epoch(1),
    );
    assert!(manifest.publishable);
    assert_eq!(manifest.thinning_reports.len(), 1);
}

// ---------------------------------------------------------------------------
// End-to-end workflow
// ---------------------------------------------------------------------------

#[test]
fn integration_end_to_end_complete_workflow() {
    // 1. Create registry and kernels.
    let mut registry = build_registry("e2e-reg".to_string(), epoch(10));
    let k_cm = create_kernel(
        "cm-kernel".to_string(),
        SketchWriterKind::CountMin,
        MILLION,
        50,
        epoch(10),
    );
    let k_hh = create_kernel(
        "hh-kernel".to_string(),
        SketchWriterKind::HeavyHitter,
        800_000,
        100,
        epoch(10),
    );
    register_kernel(&mut registry, k_cm).unwrap();
    register_kernel(&mut registry, k_hh).unwrap();

    // 2. Submit observations with exact-shadow.
    let mut shadow_cm = ExactShadowCounter::new("cm-kernel".to_string());
    let mut shadow_hh = ExactShadowCounter::new("hh-kernel".to_string());
    let mut all_entries = Vec::new();

    let k_cm = registry.find_kernel_mut("cm-kernel").unwrap();
    for i in 0..30 {
        let key = format!("op_{}", i % 6);
        if let Some(entry) = submit_observation(k_cm, &key, MILLION).unwrap() {
            all_entries.push(entry);
        }
        shadow_cm.observe(&key, MILLION);
    }

    let k_hh = registry.find_kernel_mut("hh-kernel").unwrap();
    for i in 0..40 {
        let key = format!("call_{}", i % 8);
        if let Some(entry) = submit_observation(k_hh, &key, MILLION).unwrap() {
            all_entries.push(entry);
        }
        shadow_hh.observe(&key, MILLION);
    }

    // 3. Calibrate both kernels.
    let cal_cm = calibrate_kernel(
        registry.find_kernel("cm-kernel").unwrap(),
        &shadow_cm,
        epoch(10),
    )
    .unwrap();
    let cal_hh = calibrate_kernel(
        registry.find_kernel("hh-kernel").unwrap(),
        &shadow_hh,
        epoch(10),
    )
    .unwrap();

    // 4. Thin evidence.
    let policy = make_policy("e2e-policy", ThinningStrategy::HashDeterministic, 500_000);
    let bundle = apply_thinning(&all_entries, &policy, epoch(10)).unwrap();
    assert!(bundle.retained_count > 0);

    // 5. Build manifest.
    registry.recompute_hash();
    let manifest = build_manifest(
        "e2e-manifest".to_string(),
        &registry,
        vec![cal_cm, cal_hh],
        vec![bundle],
        epoch(10),
    );

    // Verify manifest.
    assert_eq!(manifest.kernel_summaries.len(), 2);
    assert_eq!(manifest.calibration_evidence.len(), 2);
    assert_eq!(manifest.thinning_reports.len(), 1);
    // CM kernel should have accepted all (100% rate, budget 50).
    let cm_summary = manifest
        .kernel_summaries
        .iter()
        .find(|s| s.kernel_id == "cm-kernel")
        .unwrap();
    assert_eq!(cm_summary.writer_kind, SketchWriterKind::CountMin);
    assert!(cm_summary.accepted_events > 0);
}

#[test]
fn integration_e2e_determinism_across_runs() {
    // Run the same workflow twice and verify identical results.
    let run = || {
        let mut registry = build_registry("det-reg".to_string(), epoch(1));
        let k = create_kernel(
            "det-k".to_string(),
            SketchWriterKind::Quantile,
            MILLION,
            50,
            epoch(1),
        );
        register_kernel(&mut registry, k).unwrap();
        let mut shadow = ExactShadowCounter::new("det-k".to_string());
        let mut entries = Vec::new();
        let k = registry.find_kernel_mut("det-k").unwrap();
        for i in 0..20 {
            let key = format!("deterministic_key_{i}");
            if let Some(entry) = submit_observation(k, &key, MILLION).unwrap() {
                entries.push(entry);
            }
            shadow.observe(&key, MILLION);
        }
        let cal =
            calibrate_kernel(registry.find_kernel("det-k").unwrap(), &shadow, epoch(1)).unwrap();
        let policy = make_policy("det-pol", ThinningStrategy::HashDeterministic, 400_000);
        let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();
        registry.recompute_hash();
        let manifest = build_manifest(
            "det-man".to_string(),
            &registry,
            vec![cal],
            vec![bundle],
            epoch(1),
        );
        manifest
    };

    let m1 = run();
    let m2 = run();
    assert_eq!(m1.content_hash, m2.content_hash);
    assert_eq!(m1.publishable, m2.publishable);
    assert_eq!(m1.kernel_summaries.len(), m2.kernel_summaries.len());
    for (s1, s2) in m1.kernel_summaries.iter().zip(m2.kernel_summaries.iter()) {
        assert_eq!(s1.kernel_id, s2.kernel_id);
        assert_eq!(s1.accepted_events, s2.accepted_events);
    }
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn integration_serde_kernel_registry_roundtrip() {
    let mut registry = build_registry("serde-reg".to_string(), epoch(1));
    register_kernel(&mut registry, make_kernel("k1", MILLION, 100)).unwrap();
    register_kernel(&mut registry, make_kernel("k2", 500_000, 200)).unwrap();
    let json = serde_json::to_string(&registry).unwrap();
    let restored: KernelRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(registry, restored);
}

#[test]
fn integration_serde_calibration_evidence_roundtrip() {
    let mut k = make_kernel("k1", MILLION, 100);
    let mut shadow = ExactShadowCounter::new("k1".to_string());
    for i in 0..5 {
        let key = format!("key_{i}");
        submit_observation(&mut k, &key, MILLION).unwrap();
        shadow.observe(&key, MILLION);
    }
    let evidence = calibrate_kernel(&k, &shadow, epoch(1)).unwrap();
    let json = serde_json::to_string(&evidence).unwrap();
    let restored: CalibrationEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(evidence, restored);
}

#[test]
fn integration_serde_thinned_bundle_roundtrip() {
    let entries: Vec<HotPathEvidenceEntry> = (0..10)
        .map(|i| {
            make_entry(
                &format!("e{i}"),
                "k1",
                &format!("key_{i}"),
                i,
                CaptureMode::Budgeted,
            )
        })
        .collect();
    let policy = make_policy("serde-pol", ThinningStrategy::UniformRate, 500_000);
    let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();
    let json = serde_json::to_string(&bundle).unwrap();
    let restored: ThinnedBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, restored);
}

#[test]
fn integration_serde_manifest_roundtrip() {
    let mut registry = build_registry("serde-man-reg".to_string(), epoch(1));
    register_kernel(&mut registry, make_kernel("k1", MILLION, 100)).unwrap();
    let manifest = build_manifest(
        "serde-man".to_string(),
        &registry,
        Vec::new(),
        Vec::new(),
        epoch(1),
    );
    let json = serde_json::to_string(&manifest).unwrap();
    let restored: TelemetryManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, restored);
}

#[test]
fn integration_serde_capture_mode_snake_case() {
    let mode = CaptureMode::ExactShadow;
    let json = serde_json::to_string(&mode).unwrap();
    assert_eq!(json, "\"exact_shadow\"");
    let restored: CaptureMode = serde_json::from_str(&json).unwrap();
    assert_eq!(mode, restored);
}

#[test]
fn integration_serde_thinning_strategy_snake_case() {
    let strategy = ThinningStrategy::WeightProportional;
    let json = serde_json::to_string(&strategy).unwrap();
    assert_eq!(json, "\"weight_proportional\"");
    let restored: ThinningStrategy = serde_json::from_str(&json).unwrap();
    assert_eq!(strategy, restored);
}

// ---------------------------------------------------------------------------
// Edge cases and error paths
// ---------------------------------------------------------------------------

#[test]
fn integration_kernel_zero_budget() {
    let mut k = make_kernel("k-zero", MILLION, 0);
    let err = submit_observation(&mut k, "key", MILLION).unwrap_err();
    assert!(matches!(err, TelemetryError::BudgetExhausted(_)));
}

#[test]
fn integration_shadow_counter_inactive_no_observe() {
    let mut shadow = ExactShadowCounter::new("k1".to_string());
    shadow.active = false;
    shadow.observe("key_a", MILLION);
    assert_eq!(shadow.total_observations, 0);
    assert_eq!(shadow.distinct_keys(), 0);
}

#[test]
fn integration_calibration_empty_both_sides() {
    let k = make_kernel("k1", MILLION, 100);
    let shadow = ExactShadowCounter::new("k1".to_string());
    let err = calibrate_kernel(&k, &shadow, epoch(1)).unwrap_err();
    assert!(matches!(err, TelemetryError::EmptyInput));
}

#[test]
fn integration_manifest_all_kernels_exhausted() {
    let mut registry = build_registry("exh-reg".to_string(), epoch(1));
    let mut k1 = make_kernel("k1", MILLION, 1);
    let mut k2 = make_kernel("k2", MILLION, 1);
    submit_observation(&mut k1, "a", MILLION).unwrap();
    submit_observation(&mut k2, "b", MILLION).unwrap();
    register_kernel(&mut registry, k1).unwrap();
    register_kernel(&mut registry, k2).unwrap();
    let manifest = build_manifest(
        "exh-man".to_string(),
        &registry,
        Vec::new(),
        Vec::new(),
        epoch(1),
    );
    assert!(!manifest.publishable);
    assert!(
        manifest
            .rejection_reasons
            .iter()
            .any(|r| r.contains("exhausted"))
    );
}

#[test]
fn integration_error_display_coverage() {
    let errors = vec![
        TelemetryError::KernelNotFound("k99".to_string()),
        TelemetryError::BudgetExhausted("k1".to_string()),
        TelemetryError::RegistryFull,
        TelemetryError::SketchCapacityExceeded("k1".to_string()),
        TelemetryError::CalibrationFailed {
            kernel_id: "k1".to_string(),
            max_error_millionths: 200_000,
            threshold_millionths: 50_000,
        },
        TelemetryError::InvalidPolicy("bad".to_string()),
        TelemetryError::EpochMismatch {
            expected: epoch(1),
            actual: epoch(2),
        },
        TelemetryError::EmptyInput,
    ];
    for err in &errors {
        let s = format!("{err}");
        assert!(!s.is_empty());
        assert!(s.contains(COMPONENT));
    }
}

#[test]
fn integration_display_formats() {
    // Test all Display implementations.
    let k = make_kernel("disp-k", MILLION, 100);
    let s = format!("{k}");
    assert!(s.contains("disp-k"));

    let shadow = ExactShadowCounter::new("disp-k".to_string());
    let s = format!("{shadow}");
    assert!(s.contains("disp-k"));

    let registry = build_registry("disp-reg".to_string(), epoch(1));
    let s = format!("{registry}");
    assert!(s.contains("disp-reg"));

    let policy = make_policy("disp-pol", ThinningStrategy::UniformRate, 500_000);
    let s = format!("{policy}");
    assert!(s.contains("disp-pol"));
}

// ---------------------------------------------------------------------------
// Capture mode transitions
// ---------------------------------------------------------------------------

#[test]
fn integration_capture_mode_transition_on_budget_exhaustion() {
    let mut k = make_kernel("k-trans", MILLION, 3);
    assert_eq!(k.capture_mode, CaptureMode::Budgeted);
    for i in 0..3 {
        submit_observation(&mut k, &format!("key_{i}"), MILLION).unwrap();
    }
    assert_eq!(k.capture_mode, CaptureMode::Degraded);
    assert!(k.exhausted);
}

#[test]
fn integration_exact_shadow_mode_kernel() {
    let mut k = create_kernel(
        "exact-k".to_string(),
        SketchWriterKind::CountMin,
        MILLION,
        100,
        epoch(1),
    );
    k.capture_mode = CaptureMode::ExactShadow;
    let entry = submit_observation(&mut k, "key_a", MILLION)
        .unwrap()
        .unwrap();
    assert_eq!(entry.capture_mode, CaptureMode::ExactShadow);
}

#[test]
fn integration_full_capture_mode_kernel() {
    let mut k = create_kernel(
        "full-k".to_string(),
        SketchWriterKind::HeavyHitter,
        MILLION,
        100,
        epoch(1),
    );
    k.capture_mode = CaptureMode::FullCapture;
    let entry = submit_observation(&mut k, "key_a", MILLION)
        .unwrap()
        .unwrap();
    assert_eq!(entry.capture_mode, CaptureMode::FullCapture);
}
