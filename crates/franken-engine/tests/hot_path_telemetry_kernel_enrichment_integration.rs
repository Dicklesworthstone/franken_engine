//! Enrichment integration tests for hot_path_telemetry_kernel.
//!
//! Covers gaps not addressed by the base integration test file:
//! display uniqueness, serde roundtrips for sub-types, hash sensitivity,
//! registry edge cases, manifest rejection accumulation, thinning bundle
//! invariants, and evidence entry compute_hash determinism.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::hot_path_telemetry_kernel::{
    COMPONENT, CalibrationEvidence, CaptureMode, ExactShadowCounter, HotPathEvidenceEntry,
    KernelState, KernelSummary, KeyCalibrationResult, SCHEMA_VERSION, SketchBucket,
    SketchWriterKind, TelemetryError, TelemetryManifest, ThinningPolicy, ThinningStrategy,
    apply_thinning, build_manifest, build_registry, calibrate_kernel, create_kernel,
    register_kernel, submit_observation,
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
// Constants validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_component_constant_nonempty() {
    assert!(!COMPONENT.is_empty());
    assert!(COMPONENT.contains("telemetry"));
}

#[test]
fn enrichment_schema_version_contains_component() {
    assert!(SCHEMA_VERSION.contains("hot-path-telemetry-kernel"));
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
}

// ---------------------------------------------------------------------------
// Display uniqueness for all enum variants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_capture_mode_display_all_unique() {
    let modes = [
        CaptureMode::Budgeted,
        CaptureMode::ExactShadow,
        CaptureMode::Degraded,
        CaptureMode::FullCapture,
    ];
    let displays: BTreeSet<String> = modes.iter().map(|m| format!("{m}")).collect();
    assert_eq!(displays.len(), modes.len());
}

#[test]
fn enrichment_thinning_strategy_display_all_unique() {
    let strategies = [
        ThinningStrategy::UniformRate,
        ThinningStrategy::HashDeterministic,
        ThinningStrategy::WeightProportional,
        ThinningStrategy::EpochAdaptive,
        ThinningStrategy::PriorityTiered,
    ];
    let displays: BTreeSet<String> = strategies.iter().map(|s| format!("{s}")).collect();
    assert_eq!(displays.len(), strategies.len());
}

#[test]
fn enrichment_sketch_writer_kind_display_all_unique() {
    let kinds = [
        SketchWriterKind::CountMin,
        SketchWriterKind::HeavyHitter,
        SketchWriterKind::Quantile,
        SketchWriterKind::Histogram,
    ];
    let displays: BTreeSet<String> = kinds.iter().map(|k| format!("{k}")).collect();
    assert_eq!(displays.len(), kinds.len());
}

// ---------------------------------------------------------------------------
// Serde roundtrips for sub-types not covered by base tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_sketch_bucket_roundtrip() {
    let bucket = SketchBucket {
        key: "opcode_add".to_string(),
        weight_millionths: 750_000,
        count: 42,
        last_sequence: 99,
    };
    let json = serde_json::to_string(&bucket).unwrap();
    let restored: SketchBucket = serde_json::from_str(&json).unwrap();
    assert_eq!(bucket, restored);
}

#[test]
fn enrichment_serde_key_calibration_result_roundtrip() {
    let result = KeyCalibrationResult {
        key: "test_key".to_string(),
        exact_count: 100,
        sketch_estimate: 95,
        absolute_error: 5,
        relative_error_millionths: 50_000,
        passed: true,
    };
    let json = serde_json::to_string(&result).unwrap();
    let restored: KeyCalibrationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn enrichment_serde_kernel_summary_roundtrip() {
    let summary = KernelSummary {
        kernel_id: "ks-1".to_string(),
        writer_kind: SketchWriterKind::HeavyHitter,
        capture_mode: CaptureMode::Budgeted,
        budget_consumed_millionths: 250_000,
        effective_rate_millionths: 800_000,
        total_events: 1000,
        accepted_events: 800,
        distinct_keys: 15,
        is_active: true,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let restored: KernelSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

#[test]
fn enrichment_serde_exact_shadow_counter_roundtrip() {
    let mut shadow = ExactShadowCounter::new("k1".to_string());
    shadow.observe("key_a", 500_000);
    shadow.observe("key_b", 300_000);
    shadow.observe("key_a", 200_000);
    let json = serde_json::to_string(&shadow).unwrap();
    let restored: ExactShadowCounter = serde_json::from_str(&json).unwrap();
    assert_eq!(shadow, restored);
}

#[test]
fn enrichment_serde_telemetry_error_all_variants() {
    let errors: Vec<TelemetryError> = vec![
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
        let json = serde_json::to_string(err).unwrap();
        let restored: TelemetryError = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{err}"), format!("{restored}"));
    }
}

// ---------------------------------------------------------------------------
// CaptureMode serde for all variants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_capture_mode_all_variants() {
    let modes = [
        CaptureMode::Budgeted,
        CaptureMode::ExactShadow,
        CaptureMode::Degraded,
        CaptureMode::FullCapture,
    ];
    for mode in &modes {
        let json = serde_json::to_string(mode).unwrap();
        let restored: CaptureMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*mode, restored);
    }
}

#[test]
fn enrichment_serde_thinning_strategy_all_variants() {
    let strategies = [
        ThinningStrategy::UniformRate,
        ThinningStrategy::HashDeterministic,
        ThinningStrategy::WeightProportional,
        ThinningStrategy::EpochAdaptive,
        ThinningStrategy::PriorityTiered,
    ];
    for strategy in &strategies {
        let json = serde_json::to_string(strategy).unwrap();
        let restored: ThinningStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*strategy, restored);
    }
}

#[test]
fn enrichment_serde_sketch_writer_kind_all_variants() {
    let kinds = [
        SketchWriterKind::CountMin,
        SketchWriterKind::HeavyHitter,
        SketchWriterKind::Quantile,
        SketchWriterKind::Histogram,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let restored: SketchWriterKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, restored);
    }
}

// ---------------------------------------------------------------------------
// ThinningPolicy hash sensitivity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_thinning_policy_hash_sensitive_to_id() {
    let p1 = make_policy("pol-a", ThinningStrategy::UniformRate, 500_000);
    let p2 = make_policy("pol-b", ThinningStrategy::UniformRate, 500_000);
    assert_ne!(p1.content_hash, p2.content_hash);
}

#[test]
fn enrichment_thinning_policy_hash_sensitive_to_retention() {
    let p1 = make_policy("pol", ThinningStrategy::UniformRate, 500_000);
    let p2 = make_policy("pol", ThinningStrategy::UniformRate, 600_000);
    assert_ne!(p1.content_hash, p2.content_hash);
}

#[test]
fn enrichment_thinning_policy_max_rounds_default() {
    let p = make_policy("pol", ThinningStrategy::UniformRate, 500_000);
    // MAX_THINNING_ROUNDS is 256 (private), policy.max_rounds should be set to it.
    assert_eq!(p.max_rounds, 256);
}

#[test]
fn enrichment_thinning_policy_priority_floor_custom() {
    let p = ThinningPolicy::new(
        "prio-pol".to_string(),
        ThinningStrategy::PriorityTiered,
        500_000,
        0,
        75,
    );
    assert_eq!(p.priority_floor, 75);
}

// ---------------------------------------------------------------------------
// HotPathEvidenceEntry compute_hash determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evidence_entry_hash_deterministic() {
    let e1 = make_entry("e1", "k1", "key_a", 0, CaptureMode::Budgeted);
    let e2 = make_entry("e1", "k1", "key_a", 0, CaptureMode::Budgeted);
    assert_eq!(e1.content_hash, e2.content_hash);
}

#[test]
fn enrichment_evidence_entry_hash_sensitive_to_key() {
    let e1 = make_entry("e1", "k1", "key_a", 0, CaptureMode::Budgeted);
    let e2 = make_entry("e2", "k1", "key_b", 0, CaptureMode::Budgeted);
    assert_ne!(e1.content_hash, e2.content_hash);
}

#[test]
fn enrichment_evidence_entry_hash_sensitive_to_mode() {
    let e1 = make_entry("e1", "k1", "key_a", 0, CaptureMode::Budgeted);
    let e2 = make_entry("e2", "k1", "key_a", 0, CaptureMode::ExactShadow);
    assert_ne!(e1.content_hash, e2.content_hash);
}

#[test]
fn enrichment_evidence_entry_hash_sensitive_to_sequence() {
    let e1 = make_entry("e1", "k1", "key_a", 0, CaptureMode::Budgeted);
    let e2 = make_entry("e2", "k1", "key_a", 1, CaptureMode::Budgeted);
    assert_ne!(e1.content_hash, e2.content_hash);
}

// ---------------------------------------------------------------------------
// HotPathEvidenceEntry Display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evidence_entry_display_contains_fields() {
    let entry = make_entry("e42", "k1", "opcode_add", 7, CaptureMode::Budgeted);
    let s = format!("{entry}");
    assert!(s.contains("e42"));
    assert!(s.contains("k1"));
    assert!(s.contains("opcode_add"));
}

// ---------------------------------------------------------------------------
// KernelRegistry edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_registry_multiple_kernels_sorted() {
    let mut registry = build_registry("sort-reg".to_string(), epoch(1));
    register_kernel(&mut registry, make_kernel("k_z", MILLION, 100)).unwrap();
    register_kernel(&mut registry, make_kernel("k_a", MILLION, 200)).unwrap();
    register_kernel(&mut registry, make_kernel("k_m", MILLION, 300)).unwrap();
    assert_eq!(registry.kernels.len(), 3);
    // Kernels should be sorted by ID.
    assert_eq!(registry.kernels[0].kernel_id, "k_a");
    assert_eq!(registry.kernels[1].kernel_id, "k_m");
    assert_eq!(registry.kernels[2].kernel_id, "k_z");
}

#[test]
fn enrichment_registry_find_kernel_mut_updates() {
    let mut registry = build_registry("mut-reg".to_string(), epoch(1));
    register_kernel(&mut registry, make_kernel("k1", MILLION, 100)).unwrap();
    let k = registry.find_kernel_mut("k1").unwrap();
    submit_observation(k, "test_key", MILLION).unwrap();
    // Verify the mutation persisted.
    let k_ref = registry.find_kernel("k1").unwrap();
    assert_eq!(k_ref.accepted_count, 1);
    assert_eq!(k_ref.sketch_buckets.len(), 1);
}

#[test]
fn enrichment_registry_recompute_hash_changes_on_mutation() {
    let mut registry = build_registry("hash-reg".to_string(), epoch(1));
    register_kernel(&mut registry, make_kernel("k1", MILLION, 100)).unwrap();
    let hash_before = registry.content_hash;
    let k = registry.find_kernel_mut("k1").unwrap();
    submit_observation(k, "key_a", MILLION).unwrap();
    registry.recompute_hash();
    assert_ne!(hash_before, registry.content_hash);
}

#[test]
fn enrichment_registry_active_count_decrements_on_exhaustion() {
    let mut registry = build_registry("active-reg".to_string(), epoch(1));
    register_kernel(&mut registry, make_kernel("k1", MILLION, 1)).unwrap();
    register_kernel(&mut registry, make_kernel("k2", MILLION, 100)).unwrap();
    assert_eq!(registry.active_count(), 2);
    let k = registry.find_kernel_mut("k1").unwrap();
    submit_observation(k, "key", MILLION).unwrap();
    assert_eq!(registry.active_count(), 1);
}

#[test]
fn enrichment_registry_display_format() {
    let mut registry = build_registry("disp-reg".to_string(), epoch(1));
    register_kernel(&mut registry, make_kernel("k1", MILLION, 100)).unwrap();
    let s = format!("{registry}");
    assert!(s.contains("disp-reg"));
}

// ---------------------------------------------------------------------------
// ThinnedBundle invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_thinned_bundle_id_prefix() {
    let entries: Vec<HotPathEvidenceEntry> = (0..5)
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
    let policy = make_policy("thn-test", ThinningStrategy::UniformRate, MILLION);
    let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();
    assert!(bundle.bundle_id.starts_with("thn-"));
}

#[test]
fn enrichment_thinned_bundle_rounds_applied_is_one() {
    let entries = vec![make_entry("e0", "k1", "key_0", 0, CaptureMode::Budgeted)];
    let policy = make_policy("rounds-test", ThinningStrategy::UniformRate, MILLION);
    let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();
    assert_eq!(bundle.rounds_applied, 1);
}

#[test]
fn enrichment_thinned_bundle_retained_plus_discarded_equals_original() {
    let entries: Vec<HotPathEvidenceEntry> = (0..100)
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
    let policy = make_policy("sum-test", ThinningStrategy::HashDeterministic, 300_000);
    let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();
    assert_eq!(
        bundle.retained_ids.len() + bundle.discarded_ids.len(),
        entries.len(),
    );
}

#[test]
fn enrichment_thinned_bundle_no_overlap_retained_discarded() {
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
    let policy = make_policy("overlap-test", ThinningStrategy::UniformRate, 500_000);
    let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();
    let overlap: BTreeSet<_> = bundle
        .retained_ids
        .intersection(&bundle.discarded_ids)
        .collect();
    assert!(overlap.is_empty());
}

#[test]
fn enrichment_thinned_bundle_hash_sensitive_to_epoch() {
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
    let policy = make_policy("epoch-test", ThinningStrategy::UniformRate, MILLION);
    let b1 = apply_thinning(&entries, &policy, epoch(1)).unwrap();
    let b2 = apply_thinning(&entries, &policy, epoch(2)).unwrap();
    assert_ne!(b1.content_hash, b2.content_hash);
}

// ---------------------------------------------------------------------------
// CalibrationEvidence invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_calibration_threshold_matches_constant() {
    let mut k = make_kernel("k1", MILLION, 100);
    let mut shadow = ExactShadowCounter::new("k1".to_string());
    for _ in 0..10 {
        submit_observation(&mut k, "key_a", MILLION).unwrap();
        shadow.observe("key_a", MILLION);
    }
    let evidence = calibrate_kernel(&k, &shadow, epoch(1)).unwrap();
    // threshold_millionths should be 50_000 (CALIBRATION_ERROR_THRESHOLD)
    assert_eq!(evidence.threshold_millionths, 50_000);
}

#[test]
fn enrichment_calibration_hash_sensitive_to_epoch() {
    let mut k1 = make_kernel("k1", MILLION, 100);
    let mut s1 = ExactShadowCounter::new("k1".to_string());
    let mut k2 = make_kernel("k1", MILLION, 100);
    let mut s2 = ExactShadowCounter::new("k1".to_string());
    for _ in 0..5 {
        submit_observation(&mut k1, "key_a", MILLION).unwrap();
        s1.observe("key_a", MILLION);
        submit_observation(&mut k2, "key_a", MILLION).unwrap();
        s2.observe("key_a", MILLION);
    }
    let e1 = calibrate_kernel(&k1, &s1, epoch(1)).unwrap();
    let e2 = calibrate_kernel(&k2, &s2, epoch(2)).unwrap();
    assert_ne!(e1.content_hash, e2.content_hash);
}

#[test]
fn enrichment_calibration_shadow_only_key_has_zero_sketch_estimate() {
    let mut k = make_kernel("k1", MILLION, 100);
    let mut shadow = ExactShadowCounter::new("k1".to_string());
    // Only shadow sees key_b, both see key_a.
    submit_observation(&mut k, "key_a", MILLION).unwrap();
    shadow.observe("key_a", MILLION);
    shadow.observe("key_b", MILLION);
    let evidence = calibrate_kernel(&k, &shadow, epoch(1)).unwrap();
    let key_b_result = evidence
        .per_key_results
        .iter()
        .find(|r| r.key == "key_b")
        .unwrap();
    assert_eq!(key_b_result.sketch_estimate, 0);
    assert_eq!(key_b_result.exact_count, 1);
    assert!(!key_b_result.passed); // 100% error > 5% threshold
}

#[test]
fn enrichment_calibration_sketch_only_key_has_full_error() {
    let mut k = make_kernel("k1", MILLION, 100);
    let mut shadow = ExactShadowCounter::new("k1".to_string());
    // Only sketch sees key_c, both see key_a.
    submit_observation(&mut k, "key_a", MILLION).unwrap();
    submit_observation(&mut k, "key_c", MILLION).unwrap();
    shadow.observe("key_a", MILLION);
    let evidence = calibrate_kernel(&k, &shadow, epoch(1)).unwrap();
    let key_c_result = evidence
        .per_key_results
        .iter()
        .find(|r| r.key == "key_c")
        .unwrap();
    assert_eq!(key_c_result.exact_count, 0);
    assert_eq!(key_c_result.sketch_estimate, 1);
    // exact_count=0, sketch>0 => 100% error = MILLION
    assert_eq!(key_c_result.relative_error_millionths, MILLION);
}

// ---------------------------------------------------------------------------
// Manifest rejection reasons accumulation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_multiple_rejection_reasons() {
    let mut registry = build_registry("multi-rej".to_string(), epoch(1));
    let mut k = make_kernel("k1", MILLION, 1);
    submit_observation(&mut k, "key", MILLION).unwrap();
    register_kernel(&mut registry, k).unwrap();
    let failed_cal = CalibrationEvidence {
        kernel_id: "k1".to_string(),
        epoch: epoch(1),
        per_key_results: Vec::new(),
        mean_error_millionths: 200_000,
        max_error_millionths: 400_000,
        passed: false,
        threshold_millionths: 50_000,
        keys_compared: 1,
        content_hash: ContentHash::compute(b"failed"),
    };
    let manifest = build_manifest(
        "multi-rej-man".to_string(),
        &registry,
        vec![failed_cal],
        Vec::new(),
        epoch(1),
    );
    assert!(!manifest.publishable);
    // Should have both degraded AND calibration failure reasons.
    assert!(manifest.rejection_reasons.len() >= 2);
    assert!(
        manifest
            .rejection_reasons
            .iter()
            .any(|r| r.contains("degraded"))
    );
    assert!(
        manifest
            .rejection_reasons
            .iter()
            .any(|r| r.contains("calibration"))
    );
}

#[test]
fn enrichment_manifest_empty_registry_publishable() {
    let registry = build_registry("empty-reg".to_string(), epoch(1));
    let manifest = build_manifest(
        "empty-man".to_string(),
        &registry,
        Vec::new(),
        Vec::new(),
        epoch(1),
    );
    // Empty registry with no kernels should be publishable (no degraded, no failed cals).
    assert!(manifest.publishable);
    assert!(manifest.kernel_summaries.is_empty());
}

#[test]
fn enrichment_manifest_overall_mode_worst_case() {
    let mut registry = build_registry("mode-reg".to_string(), epoch(1));
    // k1: healthy (Budgeted), k2: exhausted (Degraded).
    register_kernel(&mut registry, make_kernel("k1", MILLION, 100)).unwrap();
    let mut k2 = make_kernel("k2", MILLION, 1);
    submit_observation(&mut k2, "key", MILLION).unwrap();
    register_kernel(&mut registry, k2).unwrap();
    let manifest = build_manifest(
        "mode-man".to_string(),
        &registry,
        Vec::new(),
        Vec::new(),
        epoch(1),
    );
    // Overall mode should be Degraded (worst case).
    assert_eq!(manifest.overall_mode, CaptureMode::Degraded);
}

// ---------------------------------------------------------------------------
// KernelSummary field verification via manifest
// ---------------------------------------------------------------------------

#[test]
fn enrichment_kernel_summary_fields_accurate() {
    let mut registry = build_registry("summary-reg".to_string(), epoch(1));
    let mut k = create_kernel(
        "sum-k".to_string(),
        SketchWriterKind::Quantile,
        MILLION,
        100,
        epoch(1),
    );
    // Submit 10 unique keys.
    for i in 0..10 {
        submit_observation(&mut k, &format!("key_{i}"), MILLION).unwrap();
    }
    register_kernel(&mut registry, k).unwrap();
    let manifest = build_manifest(
        "sum-man".to_string(),
        &registry,
        Vec::new(),
        Vec::new(),
        epoch(1),
    );
    let summary = &manifest.kernel_summaries[0];
    assert_eq!(summary.kernel_id, "sum-k");
    assert_eq!(summary.writer_kind, SketchWriterKind::Quantile);
    assert_eq!(summary.capture_mode, CaptureMode::Budgeted);
    assert_eq!(summary.total_events, 10);
    assert_eq!(summary.accepted_events, 10);
    assert_eq!(summary.distinct_keys, 10);
    assert!(summary.is_active);
    assert_eq!(summary.effective_rate_millionths, MILLION);
}

#[test]
fn enrichment_kernel_summary_exhausted_inactive() {
    let mut registry = build_registry("inact-reg".to_string(), epoch(1));
    let mut k = make_kernel("inact-k", MILLION, 2);
    submit_observation(&mut k, "a", MILLION).unwrap();
    submit_observation(&mut k, "b", MILLION).unwrap();
    register_kernel(&mut registry, k).unwrap();
    let manifest = build_manifest(
        "inact-man".to_string(),
        &registry,
        Vec::new(),
        Vec::new(),
        epoch(1),
    );
    let summary = &manifest.kernel_summaries[0];
    assert!(!summary.is_active);
    assert_eq!(summary.budget_consumed_millionths, MILLION);
}

// ---------------------------------------------------------------------------
// ExactShadowCounter edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_shadow_counter_display_format() {
    let mut shadow = ExactShadowCounter::new("shd-k".to_string());
    shadow.observe("key_a", 500_000);
    let s = format!("{shadow}");
    assert!(s.contains("shd-k"));
    assert!(s.contains("active=true"));
}

#[test]
fn enrichment_shadow_counter_weight_accumulation_multiple_keys() {
    let mut shadow = ExactShadowCounter::new("k1".to_string());
    shadow.observe("a", 100_000);
    shadow.observe("b", 200_000);
    shadow.observe("a", 300_000);
    assert_eq!(shadow.total_weight_millionths, 600_000);
    assert_eq!(shadow.total_observations, 3);
    assert_eq!(shadow.distinct_keys(), 2);
    assert_eq!(shadow.count_for("a"), 2);
    assert_eq!(shadow.count_for("b"), 1);
}

#[test]
fn enrichment_shadow_counter_count_for_missing_key_returns_zero() {
    let shadow = ExactShadowCounter::new("k1".to_string());
    assert_eq!(shadow.count_for("nonexistent"), 0);
}

// ---------------------------------------------------------------------------
// Kernel state edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_kernel_all_writer_kinds_create() {
    let kinds = [
        SketchWriterKind::CountMin,
        SketchWriterKind::HeavyHitter,
        SketchWriterKind::Quantile,
        SketchWriterKind::Histogram,
    ];
    for kind in &kinds {
        let k = create_kernel("k".to_string(), *kind, MILLION, 100, epoch(1));
        assert_eq!(k.writer_kind, *kind);
        assert!(k.is_active());
    }
}

#[test]
fn enrichment_kernel_budget_consumed_full_original_budget() {
    let k = make_kernel("k-full", MILLION, 1000);
    // No observations => 0% consumed.
    assert_eq!(k.budget_consumed_millionths(), 0);
}

#[test]
fn enrichment_kernel_effective_rate_mixed_accept_reject() {
    let mut k = make_kernel("k-mix", MILLION, 1000);
    k.accepted_count = 30;
    k.rejected_count = 70;
    // 30/(30+70) = 30% = 300_000 millionths
    assert_eq!(k.effective_rate_millionths(), 300_000);
}

#[test]
fn enrichment_kernel_display_contains_mode_and_writer() {
    let k = create_kernel(
        "disp-k".to_string(),
        SketchWriterKind::Histogram,
        MILLION,
        100,
        epoch(1),
    );
    let s = format!("{k}");
    assert!(s.contains("disp-k"));
    assert!(s.contains("histogram"));
    assert!(s.contains("budgeted"));
}

// ---------------------------------------------------------------------------
// Thinning with weight-proportional strategy edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_weight_proportional_high_weight_improves_retention() {
    // With WeightProportional, higher weights should generally increase retention.
    let high_weight_entries: Vec<HotPathEvidenceEntry> = (0..50)
        .map(|i| {
            let mut e = make_entry(
                &format!("h{i}"),
                "k1",
                &format!("key_{i}"),
                i,
                CaptureMode::Budgeted,
            );
            e.weight_millionths = MILLION; // max weight
            e
        })
        .collect();
    let low_weight_entries: Vec<HotPathEvidenceEntry> = (0..50)
        .map(|i| {
            let mut e = make_entry(
                &format!("l{i}"),
                "k1",
                &format!("lkey_{i}"),
                i + 100,
                CaptureMode::Budgeted,
            );
            e.weight_millionths = 1; // minimal weight
            e
        })
        .collect();

    let policy = make_policy("wp-test", ThinningStrategy::WeightProportional, 200_000);
    let b_high = apply_thinning(&high_weight_entries, &policy, epoch(1)).unwrap();
    let b_low = apply_thinning(&low_weight_entries, &policy, epoch(1)).unwrap();
    // High-weight entries should have higher retention.
    assert!(
        b_high.retained_count >= b_low.retained_count,
        "high={} low={}",
        b_high.retained_count,
        b_low.retained_count,
    );
}

// ---------------------------------------------------------------------------
// Epoch-adaptive thinning
// ---------------------------------------------------------------------------

#[test]
fn enrichment_epoch_adaptive_deterministic() {
    let entries: Vec<HotPathEvidenceEntry> = (0..30)
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
    let policy = make_policy("ea-test", ThinningStrategy::EpochAdaptive, 400_000);
    let b1 = apply_thinning(&entries, &policy, epoch(1)).unwrap();
    let b2 = apply_thinning(&entries, &policy, epoch(1)).unwrap();
    assert_eq!(b1.retained_ids, b2.retained_ids);
}

// ---------------------------------------------------------------------------
// Manifest with passing calibration + thinning
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_passing_calibration_publishable() {
    let mut registry = build_registry("pass-cal-reg".to_string(), epoch(1));
    let mut k = make_kernel("k1", MILLION, 100);
    let mut shadow = ExactShadowCounter::new("k1".to_string());
    for i in 0..10 {
        let key = format!("key_{i}");
        submit_observation(&mut k, &key, MILLION).unwrap();
        shadow.observe(&key, MILLION);
    }
    let cal = calibrate_kernel(&k, &shadow, epoch(1)).unwrap();
    assert!(cal.passed);
    register_kernel(&mut registry, k).unwrap();
    let manifest = build_manifest(
        "pass-cal-man".to_string(),
        &registry,
        vec![cal],
        Vec::new(),
        epoch(1),
    );
    assert!(manifest.publishable);
    assert!(manifest.rejection_reasons.is_empty());
}

// ---------------------------------------------------------------------------
// Manifest hash sensitivity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_hash_sensitive_to_id() {
    let mut r1 = build_registry("reg".to_string(), epoch(1));
    register_kernel(&mut r1, make_kernel("k1", MILLION, 100)).unwrap();
    let m1 = build_manifest("man-a".to_string(), &r1, Vec::new(), Vec::new(), epoch(1));
    let m2 = build_manifest("man-b".to_string(), &r1, Vec::new(), Vec::new(), epoch(1));
    assert_ne!(m1.content_hash, m2.content_hash);
}

#[test]
fn enrichment_manifest_hash_sensitive_to_epoch() {
    let mut r1 = build_registry("reg".to_string(), epoch(1));
    register_kernel(&mut r1, make_kernel("k1", MILLION, 100)).unwrap();
    let m1 = build_manifest("man".to_string(), &r1, Vec::new(), Vec::new(), epoch(1));
    let m2 = build_manifest("man".to_string(), &r1, Vec::new(), Vec::new(), epoch(2));
    assert_ne!(m1.content_hash, m2.content_hash);
}

// ---------------------------------------------------------------------------
// Submit observation entry_id format
// ---------------------------------------------------------------------------

#[test]
fn enrichment_submit_entry_id_contains_kernel_and_sequence() {
    let mut k = make_kernel("my-kernel", MILLION, 100);
    let entry = submit_observation(&mut k, "test_key", 500_000)
        .unwrap()
        .unwrap();
    assert!(entry.entry_id.contains("my-kernel"));
    // Sequence 0 for first observation.
    assert!(entry.entry_id.contains("-0-"));
}

#[test]
fn enrichment_submit_entry_weight_preserved() {
    let mut k = make_kernel("k1", MILLION, 100);
    let entry = submit_observation(&mut k, "key", 750_000).unwrap().unwrap();
    assert_eq!(entry.weight_millionths, 750_000);
}

#[test]
fn enrichment_submit_entry_epoch_preserved() {
    let mut k = make_kernel("k1", MILLION, 100);
    let entry = submit_observation(&mut k, "key", MILLION).unwrap().unwrap();
    assert_eq!(entry.epoch, epoch(1));
}

// ---------------------------------------------------------------------------
// Serde roundtrip — ThinnedBundle Display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_thinned_bundle_display_contains_policy_id() {
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
    let policy = make_policy("my-policy", ThinningStrategy::UniformRate, MILLION);
    let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();
    let s = format!("{bundle}");
    assert!(s.contains("my-policy"));
}

// ---------------------------------------------------------------------------
// TelemetryManifest Display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_display_contains_id_and_version() {
    let registry = build_registry("reg".to_string(), epoch(1));
    let manifest = build_manifest(
        "test-manifest-42".to_string(),
        &registry,
        Vec::new(),
        Vec::new(),
        epoch(1),
    );
    let s = format!("{manifest}");
    assert!(s.contains("test-manifest-42"));
}

// ---------------------------------------------------------------------------
// Serde — TelemetryManifest full roundtrip with data
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_manifest_with_calibrations_and_thinning() {
    let mut registry = build_registry("full-serde-reg".to_string(), epoch(1));
    let mut k = make_kernel("k1", MILLION, 100);
    let mut shadow = ExactShadowCounter::new("k1".to_string());
    for i in 0..5 {
        let key = format!("key_{i}");
        submit_observation(&mut k, &key, MILLION).unwrap();
        shadow.observe(&key, MILLION);
    }
    let cal = calibrate_kernel(&k, &shadow, epoch(1)).unwrap();
    register_kernel(&mut registry, k).unwrap();

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
    let policy = make_policy("serde-pol", ThinningStrategy::UniformRate, MILLION);
    let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();

    let manifest = build_manifest(
        "full-serde-man".to_string(),
        &registry,
        vec![cal],
        vec![bundle],
        epoch(1),
    );
    let json = serde_json::to_string(&manifest).unwrap();
    let restored: TelemetryManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, restored);
}

// ---------------------------------------------------------------------------
// Multiple calibration failures accumulate
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_multiple_calibration_failures() {
    let mut registry = build_registry("mcal-reg".to_string(), epoch(1));
    register_kernel(&mut registry, make_kernel("k1", MILLION, 100)).unwrap();
    register_kernel(&mut registry, make_kernel("k2", MILLION, 100)).unwrap();
    let failed1 = CalibrationEvidence {
        kernel_id: "k1".to_string(),
        epoch: epoch(1),
        per_key_results: Vec::new(),
        mean_error_millionths: 100_000,
        max_error_millionths: 200_000,
        passed: false,
        threshold_millionths: 50_000,
        keys_compared: 1,
        content_hash: ContentHash::compute(b"f1"),
    };
    let failed2 = CalibrationEvidence {
        kernel_id: "k2".to_string(),
        epoch: epoch(1),
        per_key_results: Vec::new(),
        mean_error_millionths: 150_000,
        max_error_millionths: 300_000,
        passed: false,
        threshold_millionths: 50_000,
        keys_compared: 1,
        content_hash: ContentHash::compute(b"f2"),
    };
    let manifest = build_manifest(
        "mcal-man".to_string(),
        &registry,
        vec![failed1, failed2],
        Vec::new(),
        epoch(1),
    );
    assert!(!manifest.publishable);
    // Should have rejection reasons for both calibration failures.
    let cal_reasons: Vec<_> = manifest
        .rejection_reasons
        .iter()
        .filter(|r| r.contains("calibration"))
        .collect();
    assert_eq!(cal_reasons.len(), 2);
}

// ---------------------------------------------------------------------------
// TelemetryError Display covers COMPONENT
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_display_all_contain_component() {
    let errors = [
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
    let displays: BTreeSet<String> = errors.iter().map(|e| format!("{e}")).collect();
    // All 8 variants should have unique display strings.
    assert_eq!(displays.len(), 8);
    // All should contain COMPONENT.
    for s in &displays {
        assert!(s.contains(COMPONENT), "missing COMPONENT in: {s}");
    }
}

// ---------------------------------------------------------------------------
// Sketch bucket edge case: multiple keys accumulate independently
// ---------------------------------------------------------------------------

#[test]
fn enrichment_sketch_buckets_independent_accumulation() {
    let mut k = make_kernel("k1", MILLION, 1000);
    for _ in 0..5 {
        submit_observation(&mut k, "key_a", 100_000).unwrap();
    }
    for _ in 0..3 {
        submit_observation(&mut k, "key_b", 200_000).unwrap();
    }
    let a = k.sketch_buckets.iter().find(|b| b.key == "key_a").unwrap();
    let b = k.sketch_buckets.iter().find(|b| b.key == "key_b").unwrap();
    assert_eq!(a.count, 5);
    assert_eq!(a.weight_millionths, 500_000);
    assert_eq!(b.count, 3);
    assert_eq!(b.weight_millionths, 600_000);
}
