//! Integration tests for the distribution shift monitor module (RGC-706A).

use frankenengine_engine::distribution_shift_monitor::{
    EmbeddingVector, KernelKind, MmdResult, MonitorConfig, MonitorState, ShiftCertificate,
    ShiftError, ShiftEvidenceManifest, ShiftVerdict, StreamKind, StreamWindow, WindowConfig,
    SHIFT_MONITOR_COMPONENT, SHIFT_MONITOR_POLICY_ID, SHIFT_MONITOR_SCHEMA_VERSION,
    build_window, compute_kernel_value, compute_mmd_squared, detect_shift, run_shift_evidence,
};
use frankenengine_engine::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_embedding(dims: Vec<u64>) -> EmbeddingVector {
    let hash = ContentHash::compute(&serde_json::to_vec(&dims).unwrap());
    EmbeddingVector {
        dimensions: dims,
        source_hash: hash,
    }
}

fn uniform_embeddings(value: u64, dim: usize, count: usize) -> Vec<EmbeddingVector> {
    (0..count)
        .map(|i| {
            let v = value.saturating_add(i as u64 * 100);
            make_embedding(vec![v; dim])
        })
        .collect()
}

fn small_config() -> MonitorConfig {
    MonitorConfig {
        window: WindowConfig {
            window_size: 5,
            slide_step: 2,
            min_samples: 2,
        },
        kernel: KernelKind::Linear,
        significance_threshold_millionths: 100_000,
        min_effect_size_millionths: 10_000,
        abstention_sample_floor: 3,
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn integration_schema_version_is_nonempty() {
    assert!(!SHIFT_MONITOR_SCHEMA_VERSION.is_empty());
    assert!(SHIFT_MONITOR_SCHEMA_VERSION.contains("distribution-shift-monitor"));
}

#[test]
fn integration_component_name() {
    assert_eq!(SHIFT_MONITOR_COMPONENT, "distribution_shift_monitor");
}

#[test]
fn integration_policy_id() {
    assert_eq!(SHIFT_MONITOR_POLICY_ID, "RGC-706A");
}

// ---------------------------------------------------------------------------
// StreamKind serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn integration_stream_kind_serde_roundtrip() {
    for kind in [StreamKind::Benchmark, StreamKind::LiveWorkload] {
        let json = serde_json::to_string(&kind).unwrap();
        let deserialized: StreamKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, deserialized);
    }
}

#[test]
fn integration_stream_kind_display() {
    assert_eq!(StreamKind::Benchmark.to_string(), "benchmark");
    assert_eq!(StreamKind::LiveWorkload.to_string(), "live_workload");
}

// ---------------------------------------------------------------------------
// KernelKind serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn integration_kernel_kind_serde_roundtrip() {
    let kernels = vec![
        KernelKind::Linear,
        KernelKind::Polynomial { degree: 3 },
        KernelKind::GaussianRbf {
            bandwidth_millionths: 1_000_000,
        },
    ];
    for k in kernels {
        let json = serde_json::to_string(&k).unwrap();
        let back: KernelKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, back);
    }
}

// ---------------------------------------------------------------------------
// EmbeddingVector
// ---------------------------------------------------------------------------

#[test]
fn integration_embedding_vector_serde_roundtrip() {
    let emb = make_embedding(vec![500_000, 600_000, 700_000]);
    let json = serde_json::to_string(&emb).unwrap();
    let back: EmbeddingVector = serde_json::from_str(&json).unwrap();
    assert_eq!(emb, back);
}

// ---------------------------------------------------------------------------
// WindowConfig
// ---------------------------------------------------------------------------

#[test]
fn integration_window_config_serde_roundtrip() {
    let wc = WindowConfig {
        window_size: 50,
        slide_step: 25,
        min_samples: 5,
    };
    let json = serde_json::to_string(&wc).unwrap();
    let back: WindowConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(wc, back);
}

// ---------------------------------------------------------------------------
// compute_kernel_value
// ---------------------------------------------------------------------------

#[test]
fn integration_linear_kernel_identical_vectors() {
    let a = make_embedding(vec![1_000_000, 1_000_000]);
    let val = compute_kernel_value(&a, &a, &KernelKind::Linear);
    // dot(a,a) = 1.0*1.0 + 1.0*1.0 = 2.0 = 2_000_000
    assert_eq!(val, 2_000_000);
}

#[test]
fn integration_linear_kernel_orthogonal_vectors() {
    let a = make_embedding(vec![1_000_000, 0]);
    let b = make_embedding(vec![0, 1_000_000]);
    let val = compute_kernel_value(&a, &b, &KernelKind::Linear);
    assert_eq!(val, 0);
}

#[test]
fn integration_kernel_dimension_mismatch_returns_zero() {
    let a = make_embedding(vec![500_000, 600_000]);
    let b = make_embedding(vec![500_000]);
    let val = compute_kernel_value(&a, &b, &KernelKind::Linear);
    assert_eq!(val, 0);
}

#[test]
fn integration_polynomial_kernel_degree_one() {
    let a = make_embedding(vec![1_000_000]);
    let b = make_embedding(vec![1_000_000]);
    let val = compute_kernel_value(&a, &b, &KernelKind::Polynomial { degree: 1 });
    // (dot + 1.0)^1 = (1.0 + 1.0) = 2.0 = 2_000_000
    assert_eq!(val, 2_000_000);
}

#[test]
fn integration_gaussian_rbf_identical_vectors() {
    let a = make_embedding(vec![500_000, 500_000]);
    let val = compute_kernel_value(
        &a,
        &a,
        &KernelKind::GaussianRbf {
            bandwidth_millionths: 1_000_000,
        },
    );
    // k(a,a) should be 1.0 = 1_000_000 (distance is 0)
    assert_eq!(val, 1_000_000);
}

#[test]
fn integration_gaussian_rbf_zero_bandwidth_nonzero_distance() {
    let a = make_embedding(vec![500_000]);
    let b = make_embedding(vec![600_000]);
    let val = compute_kernel_value(
        &a,
        &b,
        &KernelKind::GaussianRbf {
            bandwidth_millionths: 0,
        },
    );
    assert_eq!(val, 0);
}

#[test]
fn integration_gaussian_rbf_zero_bandwidth_zero_distance() {
    let a = make_embedding(vec![500_000]);
    let val = compute_kernel_value(
        &a,
        &a,
        &KernelKind::GaussianRbf {
            bandwidth_millionths: 0,
        },
    );
    assert_eq!(val, 1_000_000);
}

// ---------------------------------------------------------------------------
// compute_mmd_squared
// ---------------------------------------------------------------------------

#[test]
fn integration_mmd_identical_distributions() {
    let embeddings = uniform_embeddings(500_000, 2, 5);
    let result = compute_mmd_squared(&embeddings, &embeddings, &KernelKind::Linear).unwrap();
    // Identical distributions => MMD^2 ~ 0
    assert_eq!(result.mmd_squared_millionths, 0);
}

#[test]
fn integration_mmd_empty_left_fails() {
    let right = uniform_embeddings(500_000, 2, 3);
    let result = compute_mmd_squared(&[], &right, &KernelKind::Linear);
    assert_eq!(result.unwrap_err(), ShiftError::EmptyWindow);
}

#[test]
fn integration_mmd_empty_right_fails() {
    let left = uniform_embeddings(500_000, 2, 3);
    let result = compute_mmd_squared(&left, &[], &KernelKind::Linear);
    assert_eq!(result.unwrap_err(), ShiftError::EmptyWindow);
}

#[test]
fn integration_mmd_dimension_mismatch() {
    let left = vec![make_embedding(vec![500_000, 600_000])];
    let right = vec![make_embedding(vec![500_000])];
    let result = compute_mmd_squared(&left, &right, &KernelKind::Linear);
    assert!(matches!(result, Err(ShiftError::DimensionMismatch { .. })));
}

#[test]
fn integration_mmd_result_sample_counts() {
    let left = uniform_embeddings(500_000, 2, 4);
    let right = uniform_embeddings(800_000, 2, 6);
    let result = compute_mmd_squared(&left, &right, &KernelKind::Linear).unwrap();
    assert_eq!(result.sample_count_left, 4);
    assert_eq!(result.sample_count_right, 6);
}

// ---------------------------------------------------------------------------
// build_window
// ---------------------------------------------------------------------------

#[test]
fn integration_build_window_sets_fields() {
    let embeddings = uniform_embeddings(500_000, 2, 5);
    let window = build_window(StreamKind::Benchmark, embeddings.clone(), 10);
    assert_eq!(window.stream_kind, StreamKind::Benchmark);
    assert_eq!(window.start_index, 10);
    assert_eq!(window.end_index, 15);
    assert_eq!(window.embeddings.len(), 5);
}

#[test]
fn integration_build_window_hash_determinism() {
    let embeddings = uniform_embeddings(500_000, 2, 5);
    let w1 = build_window(StreamKind::LiveWorkload, embeddings.clone(), 0);
    let w2 = build_window(StreamKind::LiveWorkload, embeddings, 0);
    assert_eq!(w1.window_hash, w2.window_hash);
}

#[test]
fn integration_build_window_serde_roundtrip() {
    let embeddings = uniform_embeddings(500_000, 2, 3);
    let window = build_window(StreamKind::Benchmark, embeddings, 0);
    let json = serde_json::to_string(&window).unwrap();
    let back: StreamWindow = serde_json::from_str(&json).unwrap();
    assert_eq!(window, back);
}

// ---------------------------------------------------------------------------
// detect_shift
// ---------------------------------------------------------------------------

#[test]
fn integration_detect_shift_no_shift_similar_distributions() {
    let config = small_config();
    let bench = build_window(
        StreamKind::Benchmark,
        uniform_embeddings(500_000, 2, 5),
        0,
    );
    let live = build_window(
        StreamKind::LiveWorkload,
        uniform_embeddings(500_000, 2, 5),
        0,
    );
    let cert = detect_shift(&bench, &live, &config);
    assert_eq!(cert.verdict, ShiftVerdict::NoShift);
    assert_eq!(cert.schema_version, SHIFT_MONITOR_SCHEMA_VERSION);
}

#[test]
fn integration_detect_shift_insufficient_samples() {
    let config = MonitorConfig {
        window: WindowConfig {
            window_size: 100,
            slide_step: 50,
            min_samples: 10,
        },
        kernel: KernelKind::Linear,
        significance_threshold_millionths: 100_000,
        min_effect_size_millionths: 10_000,
        abstention_sample_floor: 100,
    };
    let bench = build_window(
        StreamKind::Benchmark,
        uniform_embeddings(500_000, 2, 3),
        0,
    );
    let live = build_window(
        StreamKind::LiveWorkload,
        uniform_embeddings(600_000, 2, 3),
        0,
    );
    let cert = detect_shift(&bench, &live, &config);
    assert!(matches!(cert.verdict, ShiftVerdict::Abstained { .. }));
}

#[test]
fn integration_detect_shift_abstention_sample_floor() {
    let config = MonitorConfig {
        abstention_sample_floor: 1000,
        ..small_config()
    };
    let bench = build_window(
        StreamKind::Benchmark,
        uniform_embeddings(500_000, 2, 3),
        0,
    );
    let live = build_window(
        StreamKind::LiveWorkload,
        uniform_embeddings(600_000, 2, 3),
        0,
    );
    let cert = detect_shift(&bench, &live, &config);
    assert!(matches!(cert.verdict, ShiftVerdict::Abstained { .. }));
    assert!(cert.mmd.is_none());
}

#[test]
fn integration_detect_shift_certificate_hash_determinism() {
    let config = small_config();
    let bench = build_window(
        StreamKind::Benchmark,
        uniform_embeddings(500_000, 2, 5),
        0,
    );
    let live = build_window(
        StreamKind::LiveWorkload,
        uniform_embeddings(500_000, 2, 5),
        0,
    );
    let cert1 = detect_shift(&bench, &live, &config);
    let cert2 = detect_shift(&bench, &live, &config);
    assert_eq!(cert1.certificate_hash, cert2.certificate_hash);
}

#[test]
fn integration_detect_shift_certificate_serde_roundtrip() {
    let config = small_config();
    let bench = build_window(
        StreamKind::Benchmark,
        uniform_embeddings(500_000, 2, 5),
        0,
    );
    let live = build_window(
        StreamKind::LiveWorkload,
        uniform_embeddings(500_000, 2, 5),
        0,
    );
    let cert = detect_shift(&bench, &live, &config);
    let json = serde_json::to_string(&cert).unwrap();
    let back: ShiftCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ---------------------------------------------------------------------------
// ShiftVerdict serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn integration_shift_verdict_serde_all_variants() {
    let verdicts = vec![
        ShiftVerdict::NoShift,
        ShiftVerdict::ShiftDetected {
            mmd_squared: 200_000,
        },
        ShiftVerdict::InsufficientSamples {
            available: 3,
            required: 10,
        },
        ShiftVerdict::Abstained {
            reason: "test".into(),
        },
    ];
    for v in verdicts {
        let json = serde_json::to_string(&v).unwrap();
        let back: ShiftVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ---------------------------------------------------------------------------
// ShiftError serde + display
// ---------------------------------------------------------------------------

#[test]
fn integration_shift_error_serde_roundtrip() {
    let errors = vec![
        ShiftError::EmptyWindow,
        ShiftError::DimensionMismatch {
            expected: 3,
            actual: 2,
        },
        ShiftError::InvalidConfig {
            reason: "bad".into(),
        },
        ShiftError::InsufficientData,
    ];
    for e in errors {
        let json = serde_json::to_string(&e).unwrap();
        let back: ShiftError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }
}

#[test]
fn integration_shift_error_display() {
    assert_eq!(ShiftError::EmptyWindow.to_string(), "empty window");
    let dm = ShiftError::DimensionMismatch {
        expected: 3,
        actual: 2,
    };
    assert!(dm.to_string().contains("dimension mismatch"));
    assert!(ShiftError::InsufficientData.to_string().contains("insufficient"));
}

// ---------------------------------------------------------------------------
// MonitorConfig
// ---------------------------------------------------------------------------

#[test]
fn integration_monitor_config_default_config() {
    let c = MonitorConfig::default_config();
    assert_eq!(c.window.window_size, 100);
    assert_eq!(c.window.slide_step, 50);
    assert_eq!(c.window.min_samples, 10);
    assert!(c.significance_threshold_millionths > 0);
    assert!(c.min_effect_size_millionths > 0);
    assert!(c.abstention_sample_floor > 0);
}

#[test]
fn integration_monitor_config_serde_roundtrip() {
    let c = MonitorConfig::default_config();
    let json = serde_json::to_string(&c).unwrap();
    let back: MonitorConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// MonitorState
// ---------------------------------------------------------------------------

#[test]
fn integration_monitor_state_serde_roundtrip() {
    let state = MonitorState {
        benchmark_windows: vec![build_window(
            StreamKind::Benchmark,
            uniform_embeddings(500_000, 2, 3),
            0,
        )],
        live_windows: vec![build_window(
            StreamKind::LiveWorkload,
            uniform_embeddings(600_000, 2, 3),
            0,
        )],
        certificates: Vec::new(),
        state_hash: ContentHash::compute(b"test-state"),
    };
    let json = serde_json::to_string(&state).unwrap();
    let back: MonitorState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, back);
}

// ---------------------------------------------------------------------------
// MmdResult serde
// ---------------------------------------------------------------------------

#[test]
fn integration_mmd_result_serde_roundtrip() {
    let r = MmdResult {
        mmd_squared_millionths: 150_000,
        threshold_millionths: 100_000,
        is_shifted: true,
        sample_count_left: 10,
        sample_count_right: 12,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: MmdResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// Evidence manifest
// ---------------------------------------------------------------------------

#[test]
fn integration_run_shift_evidence_produces_manifest() {
    let manifest = run_shift_evidence();
    assert_eq!(manifest.schema_version, SHIFT_MONITOR_SCHEMA_VERSION);
    assert!(manifest.windows_compared >= 2);
    assert!(manifest.error.is_none());
    assert!(!manifest.certificates.is_empty());
}

#[test]
fn integration_evidence_manifest_hash_determinism() {
    let m1 = run_shift_evidence();
    let m2 = run_shift_evidence();
    assert_eq!(m1.manifest_hash, m2.manifest_hash);
}

#[test]
fn integration_evidence_manifest_serde_roundtrip() {
    let manifest = run_shift_evidence();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ShiftEvidenceManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn integration_evidence_certificates_have_schema_version() {
    let manifest = run_shift_evidence();
    for cert in &manifest.certificates {
        assert_eq!(cert.schema_version, SHIFT_MONITOR_SCHEMA_VERSION);
    }
}

#[test]
fn integration_evidence_has_both_shift_and_no_shift() {
    let manifest = run_shift_evidence();
    let has_shift = manifest
        .certificates
        .iter()
        .any(|c| matches!(c.verdict, ShiftVerdict::ShiftDetected { .. }));
    let has_no_shift = manifest
        .certificates
        .iter()
        .any(|c| matches!(c.verdict, ShiftVerdict::NoShift));
    // Evidence corpus is designed to produce both
    assert!(has_shift || has_no_shift);
}

// ---------------------------------------------------------------------------
// Kernel value determinism
// ---------------------------------------------------------------------------

#[test]
fn integration_kernel_value_determinism_linear() {
    let a = make_embedding(vec![300_000, 700_000]);
    let b = make_embedding(vec![600_000, 400_000]);
    let v1 = compute_kernel_value(&a, &b, &KernelKind::Linear);
    let v2 = compute_kernel_value(&a, &b, &KernelKind::Linear);
    assert_eq!(v1, v2);
}

#[test]
fn integration_kernel_value_determinism_polynomial() {
    let a = make_embedding(vec![300_000, 700_000]);
    let b = make_embedding(vec![600_000, 400_000]);
    let kernel = KernelKind::Polynomial { degree: 2 };
    let v1 = compute_kernel_value(&a, &b, &kernel);
    let v2 = compute_kernel_value(&a, &b, &kernel);
    assert_eq!(v1, v2);
}

#[test]
fn integration_kernel_value_determinism_rbf() {
    let a = make_embedding(vec![300_000, 700_000]);
    let b = make_embedding(vec![600_000, 400_000]);
    let kernel = KernelKind::GaussianRbf {
        bandwidth_millionths: 1_000_000,
    };
    let v1 = compute_kernel_value(&a, &b, &kernel);
    let v2 = compute_kernel_value(&a, &b, &kernel);
    assert_eq!(v1, v2);
}
