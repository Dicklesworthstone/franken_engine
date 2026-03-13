#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use frankenengine_engine::distribution_shift_monitor::{
    EmbeddingVector, KernelKind, MmdResult, MonitorConfig, MonitorState,
    SHIFT_MONITOR_SCHEMA_VERSION, ShiftCertificate, ShiftError, ShiftEvidenceManifest,
    ShiftVerdict, StreamKind, WindowConfig, build_window, compute_kernel_value,
    compute_mmd_squared, detect_shift, run_shift_evidence,
};
use frankenengine_engine::hash_tiers::ContentHash;

fn emb(dims: &[u64]) -> EmbeddingVector {
    EmbeddingVector {
        dimensions: dims.to_vec(),
        source_hash: ContentHash::compute(
            &dims
                .iter()
                .flat_map(|d| d.to_le_bytes())
                .collect::<Vec<u8>>(),
        ),
    }
}

fn small_config() -> MonitorConfig {
    MonitorConfig {
        window: WindowConfig {
            window_size: 10,
            slide_step: 5,
            min_samples: 3,
        },
        kernel: KernelKind::Linear,
        significance_threshold_millionths: 100_000,
        min_effect_size_millionths: 10_000,
        abstention_sample_floor: 4,
    }
}

// =========================================================================
// A. StreamKind ordering and Copy/Hash
// =========================================================================

#[test]
fn enrichment_stream_kind_ordering() {
    assert!(StreamKind::Benchmark < StreamKind::LiveWorkload);
}

#[test]
fn enrichment_stream_kind_copy_hash() {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    set.insert(StreamKind::Benchmark);
    set.insert(StreamKind::LiveWorkload);
    set.insert(StreamKind::Benchmark); // duplicate
    assert_eq!(set.len(), 2);
}

// =========================================================================
// B. ShiftVerdict serde for all variants
// =========================================================================

#[test]
fn enrichment_shift_verdict_no_shift_serde() {
    let v = ShiftVerdict::NoShift;
    let json = serde_json::to_string(&v).unwrap();
    let back: ShiftVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_shift_verdict_shift_detected_serde() {
    let v = ShiftVerdict::ShiftDetected {
        mmd_squared: 200_000,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: ShiftVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_shift_verdict_insufficient_samples_serde() {
    let v = ShiftVerdict::InsufficientSamples {
        available: 5,
        required: 10,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: ShiftVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_shift_verdict_abstained_serde() {
    let v = ShiftVerdict::Abstained {
        reason: "test reason".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: ShiftVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// =========================================================================
// C. ShiftError Display all variants
// =========================================================================

#[test]
fn enrichment_shift_error_display_empty_window() {
    let e = ShiftError::EmptyWindow;
    assert_eq!(e.to_string(), "empty window");
}

#[test]
fn enrichment_shift_error_display_dimension_mismatch() {
    let e = ShiftError::DimensionMismatch {
        expected: 3,
        actual: 5,
    };
    let display = e.to_string();
    assert!(display.contains("3"));
    assert!(display.contains("5"));
}

#[test]
fn enrichment_shift_error_display_invalid_config() {
    let e = ShiftError::InvalidConfig {
        reason: "bad threshold".to_string(),
    };
    assert!(e.to_string().contains("bad threshold"));
}

#[test]
fn enrichment_shift_error_display_insufficient_data() {
    let e = ShiftError::InsufficientData;
    assert_eq!(e.to_string(), "insufficient data");
}

// =========================================================================
// D. detect_shift with actual shift detected
// =========================================================================

#[test]
fn enrichment_detect_shift_detects_large_shift() {
    let config = small_config();
    // Benchmark near (0.1, 0.1)
    let bench_embs: Vec<EmbeddingVector> = (0..5)
        .map(|i| emb(&[100_000 + i * 100, 100_000 + i * 100]))
        .collect();
    // Live near (0.9, 0.9) — large distance
    let live_embs: Vec<EmbeddingVector> = (0..5)
        .map(|i| emb(&[900_000 + i * 100, 900_000 + i * 100]))
        .collect();
    let bench_win = build_window(StreamKind::Benchmark, bench_embs, 0);
    let live_win = build_window(StreamKind::LiveWorkload, live_embs, 0);
    let cert = detect_shift(&bench_win, &live_win, &config);
    assert!(
        matches!(cert.verdict, ShiftVerdict::ShiftDetected { .. }),
        "expected shift detected, got {:?}",
        cert.verdict
    );
    assert!(cert.mmd.is_some());
    assert!(cert.mmd.as_ref().unwrap().is_shifted);
}

// =========================================================================
// E. compute_mmd_squared with different distributions
// =========================================================================

#[test]
fn enrichment_mmd_different_distributions() {
    let left = vec![emb(&[100_000, 100_000]), emb(&[150_000, 150_000])];
    let right = vec![emb(&[900_000, 900_000]), emb(&[950_000, 950_000])];
    let result = compute_mmd_squared(&left, &right, &KernelKind::Linear).unwrap();
    assert!(result.mmd_squared_millionths > 0);
    assert_eq!(result.sample_count_left, 2);
    assert_eq!(result.sample_count_right, 2);
}

// =========================================================================
// F. compute_kernel_value polynomial degree > 1
// =========================================================================

#[test]
fn enrichment_polynomial_kernel_degree_2() {
    let a = emb(&[500_000, 500_000]);
    let b = emb(&[500_000, 500_000]);
    let val = compute_kernel_value(&a, &b, &KernelKind::Polynomial { degree: 2 });
    // dot = 0.5, shifted = 1.5, 1.5^2 = 2.25 = 2_250_000
    assert!(val > 0);
}

#[test]
fn enrichment_polynomial_kernel_degree_3() {
    let a = emb(&[1_000_000]);
    let b = emb(&[1_000_000]);
    let val = compute_kernel_value(&a, &b, &KernelKind::Polynomial { degree: 3 });
    // dot = 1.0, shifted = 2.0, 2.0^3 = 8.0 = 8_000_000
    assert!(val > 0);
}

// =========================================================================
// G. GaussianRbf with large distance returns 0
// =========================================================================

#[test]
fn enrichment_gaussian_rbf_large_distance() {
    let a = emb(&[0, 0]);
    let b = emb(&[10_000_000, 10_000_000]); // very far
    let val = compute_kernel_value(
        &a,
        &b,
        &KernelKind::GaussianRbf {
            bandwidth_millionths: 1_000_000,
        },
    );
    assert_eq!(val, 0);
}

// =========================================================================
// H. MmdResult serde roundtrip
// =========================================================================

#[test]
fn enrichment_mmd_result_serde_roundtrip() {
    let mmd = MmdResult {
        mmd_squared_millionths: 50_000,
        threshold_millionths: 100_000,
        is_shifted: false,
        sample_count_left: 10,
        sample_count_right: 10,
    };
    let json = serde_json::to_string(&mmd).unwrap();
    let back: MmdResult = serde_json::from_str(&json).unwrap();
    assert_eq!(mmd, back);
}

// =========================================================================
// I. MonitorState with data
// =========================================================================

#[test]
fn enrichment_monitor_state_with_windows() {
    let bench = build_window(StreamKind::Benchmark, vec![emb(&[500_000])], 0);
    let live = build_window(StreamKind::LiveWorkload, vec![emb(&[600_000])], 0);
    let state = MonitorState {
        benchmark_windows: vec![bench.clone()],
        live_windows: vec![live.clone()],
        certificates: Vec::new(),
        state_hash: ContentHash::compute(b"test_state"),
    };
    let json = serde_json::to_string(&state).unwrap();
    let back: MonitorState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, back);
    assert_eq!(back.benchmark_windows.len(), 1);
    assert_eq!(back.live_windows.len(), 1);
}

// =========================================================================
// J. ShiftEvidenceManifest with error
// =========================================================================

#[test]
fn enrichment_evidence_manifest_with_error() {
    let manifest = ShiftEvidenceManifest {
        schema_version: SHIFT_MONITOR_SCHEMA_VERSION.to_string(),
        windows_compared: 0,
        shifts_detected: 0,
        abstentions: 0,
        certificates: Vec::new(),
        manifest_hash: ContentHash::compute(b"error"),
        error: Some("computation failed".to_string()),
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ShiftEvidenceManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back.error, Some("computation failed".to_string()));
}

// =========================================================================
// K. MonitorConfig default_config values
// =========================================================================

#[test]
fn enrichment_monitor_config_default_values() {
    let config = MonitorConfig::default_config();
    assert_eq!(config.window.window_size, 100);
    assert_eq!(config.window.slide_step, 50);
    assert_eq!(config.window.min_samples, 10);
    assert_eq!(config.significance_threshold_millionths, 100_000);
    assert_eq!(config.min_effect_size_millionths, 10_000);
    assert_eq!(config.abstention_sample_floor, 10);
    assert!(matches!(
        config.kernel,
        KernelKind::GaussianRbf {
            bandwidth_millionths: 1_000_000
        }
    ));
}

// =========================================================================
// L. build_window with empty embeddings
// =========================================================================

#[test]
fn enrichment_build_window_empty() {
    let win = build_window(StreamKind::Benchmark, Vec::new(), 0);
    assert!(win.embeddings.is_empty());
    assert_eq!(win.start_index, 0);
    assert_eq!(win.end_index, 0);
}

// =========================================================================
// M. Certificate fields populated correctly
// =========================================================================

#[test]
fn enrichment_certificate_has_schema_version() {
    let config = small_config();
    let bench = build_window(
        StreamKind::Benchmark,
        (0..5).map(|i| emb(&[500_000 + i * 100])).collect(),
        0,
    );
    let live = build_window(
        StreamKind::LiveWorkload,
        (0..5).map(|i| emb(&[500_000 + i * 100])).collect(),
        0,
    );
    let cert = detect_shift(&bench, &live, &config);
    assert_eq!(cert.schema_version, SHIFT_MONITOR_SCHEMA_VERSION);
}

// =========================================================================
// N. run_shift_evidence produces reasonable output
// =========================================================================

#[test]
fn enrichment_run_shift_evidence_no_error() {
    let manifest = run_shift_evidence();
    assert!(manifest.error.is_none());
    assert!(manifest.windows_compared > 0);
    assert_eq!(manifest.schema_version, SHIFT_MONITOR_SCHEMA_VERSION);
}

// =========================================================================
// O. Debug formatting nonempty
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", StreamKind::Benchmark).is_empty());
    assert!(!format!("{:?}", KernelKind::Linear).is_empty());
    assert!(!format!("{:?}", ShiftVerdict::NoShift).is_empty());
    assert!(!format!("{:?}", ShiftError::EmptyWindow).is_empty());
    assert!(
        !format!(
            "{:?}",
            WindowConfig {
                window_size: 10,
                slide_step: 5,
                min_samples: 3
            }
        )
        .is_empty()
    );
}

// =========================================================================
// P. ShiftCertificate serde roundtrip
// =========================================================================

#[test]
fn enrichment_shift_certificate_serde_roundtrip() {
    let config = small_config();
    let bench = build_window(
        StreamKind::Benchmark,
        (0..5).map(|i| emb(&[500_000 + i * 100])).collect(),
        0,
    );
    let live = build_window(
        StreamKind::LiveWorkload,
        (0..5).map(|i| emb(&[500_000 + i * 200])).collect(),
        0,
    );
    let cert = detect_shift(&bench, &live, &config);
    let json = serde_json::to_string(&cert).unwrap();
    let back: ShiftCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// =========================================================================
// Q. detect_shift when MMD computation error (dimension mismatch)
// =========================================================================

#[test]
fn enrichment_detect_shift_dimension_mismatch_abstains() {
    let config = small_config();
    // Benchmark has 2D vectors
    let bench = build_window(
        StreamKind::Benchmark,
        (0..5).map(|i| emb(&[500_000 + i, 500_000])).collect(),
        0,
    );
    // Live has 3D vectors — dimension mismatch
    let live = build_window(
        StreamKind::LiveWorkload,
        (0..5)
            .map(|i| emb(&[500_000 + i, 500_000, 500_000]))
            .collect(),
        0,
    );
    let cert = detect_shift(&bench, &live, &config);
    assert!(matches!(cert.verdict, ShiftVerdict::Abstained { .. }));
    assert!(cert.mmd.is_none());
}

// =========================================================================
// R. Stream window indices
// =========================================================================

#[test]
fn enrichment_stream_window_indices() {
    let embs: Vec<EmbeddingVector> = (0..10).map(|i| emb(&[i * 100_000])).collect();
    let win = build_window(StreamKind::LiveWorkload, embs, 42);
    assert_eq!(win.start_index, 42);
    assert_eq!(win.end_index, 52);
    assert_eq!(win.embeddings.len(), 10);
}
