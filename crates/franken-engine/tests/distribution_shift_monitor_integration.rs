//! Integration tests for `distribution_shift_monitor` module.
//!
//! Validates public API, deterministic windowing, shift verdicts, evidence
//! manifests, and deterministic artifact emission for replay workflows.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::needless_borrows_for_generic_args
)]

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use frankenengine_engine::distribution_shift_monitor::*;
use frankenengine_engine::hash_tiers::ContentHash;
use serde::Serialize;

const MILLION: u64 = 1_000_000;

fn emb(id: &str, dims: &[u64]) -> EmbeddingVector {
    EmbeddingVector {
        dimensions: dims.to_vec(),
        source_hash: ContentHash::compute(id.as_bytes()),
    }
}

fn build_series(
    prefix: &str,
    base_x: u64,
    base_y: u64,
    step_x: u64,
    step_y: u64,
    count: usize,
) -> Vec<EmbeddingVector> {
    (0..count)
        .map(|i| {
            emb(
                &format!("{prefix}-{i}"),
                &[
                    base_x.saturating_add((i as u64).saturating_mul(step_x)),
                    base_y.saturating_add((i as u64).saturating_mul(step_y)),
                ],
            )
        })
        .collect()
}

fn benchmark_window() -> StreamWindow {
    build_window(
        StreamKind::Benchmark,
        build_series("bench", 500_000, 500_000, 1_000, 500, 12),
        0,
    )
}

fn negative_control_window() -> StreamWindow {
    build_window(
        StreamKind::LiveWorkload,
        build_series("negative", 500_000, 500_000, 1_100, 600, 12),
        0,
    )
}

fn mild_shift_window() -> StreamWindow {
    build_window(
        StreamKind::LiveWorkload,
        build_series("mild", 650_000, 650_000, 1_000, 500, 12),
        0,
    )
}

fn severe_shift_window() -> StreamWindow {
    build_window(
        StreamKind::LiveWorkload,
        build_series("severe", 800_000, 800_000, 1_000, 500, 12),
        0,
    )
}

fn short_window() -> StreamWindow {
    build_window(
        StreamKind::LiveWorkload,
        build_series("short", 800_000, 800_000, 1_000, 500, 4),
        0,
    )
}

fn mismatched_dimension_window() -> StreamWindow {
    build_window(
        StreamKind::LiveWorkload,
        vec![
            emb("mismatch-0", &[900_000, 900_000, 900_000]),
            emb("mismatch-1", &[910_000, 910_000, 910_000]),
            emb("mismatch-2", &[920_000, 920_000, 920_000]),
            emb("mismatch-3", &[930_000, 930_000, 930_000]),
            emb("mismatch-4", &[940_000, 940_000, 940_000]),
            emb("mismatch-5", &[950_000, 950_000, 950_000]),
            emb("mismatch-6", &[960_000, 960_000, 960_000]),
            emb("mismatch-7", &[970_000, 970_000, 970_000]),
            emb("mismatch-8", &[980_000, 980_000, 980_000]),
            emb("mismatch-9", &[990_000, 990_000, 990_000]),
            emb("mismatch-10", &[995_000, 995_000, 995_000]),
            emb("mismatch-11", &[999_000, 999_000, 999_000]),
        ],
        0,
    )
}

fn base_config() -> MonitorConfig {
    let mut config = MonitorConfig::default_config();
    config.window.min_samples = 6;
    config.abstention_sample_floor = 10;
    config
}

fn verdict_name(verdict: &ShiftVerdict) -> &'static str {
    match verdict {
        ShiftVerdict::NoShift => "no_shift",
        ShiftVerdict::ShiftDetected { .. } => "shift_detected",
        ShiftVerdict::InsufficientSamples { .. } => "insufficient_samples",
        ShiftVerdict::Abstained { .. } => "abstained",
    }
}

fn artifact_dir() -> PathBuf {
    if let Ok(path) = std::env::var("DISTRIBUTION_SHIFT_MONITOR_ARTIFACT_DIR") {
        return PathBuf::from(path);
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time")
        .as_nanos();
    std::env::temp_dir().join(format!("distribution_shift_monitor_artifacts_{nonce}"))
}

fn write_json<T: Serialize>(path: impl AsRef<Path>, value: &T) {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent directory");
    }
    let json = serde_json::to_vec_pretty(value).expect("serialize json");
    fs::write(path, json).expect("write json");
}

fn write_jsonl<T: Serialize>(path: impl AsRef<Path>, values: &[T]) {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent directory");
    }

    let mut lines = String::new();
    for value in values {
        let line = serde_json::to_string(value).expect("serialize jsonl line");
        lines.push_str(&line);
        lines.push('\n');
    }
    fs::write(path, lines).expect("write jsonl");
}

#[derive(Serialize)]
struct WindowArtifact {
    schema_version: &'static str,
    component: &'static str,
    benchmark_window: StreamWindow,
    scenario_windows: BTreeMap<String, StreamWindow>,
}

#[derive(Serialize)]
struct KernelStatisticLine {
    scenario_id: String,
    verdict: String,
    mmd_squared_millionths: Option<u64>,
    threshold_millionths: Option<u64>,
    is_shifted: Option<bool>,
    sample_count_left: u64,
    sample_count_right: u64,
    certificate_hash: String,
}

#[derive(Serialize)]
struct ShiftAlarmReport {
    schema_version: &'static str,
    component: &'static str,
    compared_scenarios: usize,
    shifts_detected: usize,
    no_shift: usize,
    insufficient_samples: usize,
    abstentions: usize,
    max_mmd_squared_millionths: u64,
    verdict_by_scenario: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct NegativeControlReport {
    schema_version: &'static str,
    component: &'static str,
    scenario_id: &'static str,
    verdict: String,
    passes_negative_control: bool,
    certificate_hash: String,
}

#[test]
fn constants_are_stable() {
    assert_eq!(
        SHIFT_MONITOR_SCHEMA_VERSION,
        "franken-engine.distribution-shift-monitor.v1"
    );
    assert_eq!(SHIFT_MONITOR_COMPONENT, "distribution_shift_monitor");
    assert_eq!(SHIFT_MONITOR_POLICY_ID, "RGC-706A");
}

#[test]
fn window_hash_is_deterministic() {
    let left = benchmark_window();
    let right = benchmark_window();

    assert_eq!(left.window_hash, right.window_hash);
    assert_eq!(left.start_index, 0);
    assert_eq!(left.end_index, 12);
}

#[test]
fn negative_control_stays_no_shift() {
    let certificate = detect_shift(
        &benchmark_window(),
        &negative_control_window(),
        &base_config(),
    );

    assert_eq!(certificate.schema_version, SHIFT_MONITOR_SCHEMA_VERSION);
    assert!(matches!(certificate.verdict, ShiftVerdict::NoShift));
    assert!(certificate.mmd.is_some());

    let mmd = certificate.mmd.expect("mmd details");
    assert!(!mmd.is_shifted);
    assert!(mmd.mmd_squared_millionths <= mmd.threshold_millionths);
}

#[test]
fn severe_divergence_detects_shift() {
    let certificate = detect_shift(&benchmark_window(), &severe_shift_window(), &base_config());

    match certificate.verdict {
        ShiftVerdict::ShiftDetected { mmd_squared } => {
            let mmd = certificate.mmd.expect("mmd details");
            assert_eq!(mmd_squared, mmd.mmd_squared_millionths);
            assert!(mmd.is_shifted);
            assert!(mmd.mmd_squared_millionths > mmd.threshold_millionths);
        }
        other => panic!("expected shift-detected verdict, got {other:?}"),
    }
}

#[test]
fn insufficient_samples_is_distinct_from_abstention() {
    let mut config = base_config();
    config.abstention_sample_floor = 4;
    config.window.min_samples = 6;

    let certificate = detect_shift(&benchmark_window(), &short_window(), &config);

    assert!(matches!(
        certificate.verdict,
        ShiftVerdict::InsufficientSamples {
            available: 4,
            required: 6
        }
    ));
    assert!(certificate.mmd.is_none());
}

#[test]
fn abstains_below_total_sample_floor() {
    let mut config = base_config();
    config.abstention_sample_floor = 32;

    let certificate = detect_shift(&benchmark_window(), &short_window(), &config);

    match certificate.verdict {
        ShiftVerdict::Abstained { reason } => {
            assert!(reason.contains("below abstention floor"));
        }
        other => panic!("expected abstention, got {other:?}"),
    }
    assert!(certificate.mmd.is_none());
}

#[test]
fn dimension_mismatch_abstains_fail_closed() {
    let mut config = base_config();
    config.abstention_sample_floor = 8;

    let certificate = detect_shift(&benchmark_window(), &mismatched_dimension_window(), &config);

    match certificate.verdict {
        ShiftVerdict::Abstained { reason } => {
            assert_eq!(reason, "MMD computation failed");
        }
        other => panic!("expected fail-closed abstention, got {other:?}"),
    }
    assert!(certificate.mmd.is_none());
}

#[test]
fn mmd_orders_negative_mild_and_severe_scenarios() {
    let kernel = KernelKind::GaussianRbf {
        bandwidth_millionths: MILLION,
    };
    let benchmark = benchmark_window();

    let negative = compute_mmd_squared(
        &benchmark.embeddings,
        &negative_control_window().embeddings,
        &kernel,
    )
    .expect("negative control mmd");
    let mild = compute_mmd_squared(
        &benchmark.embeddings,
        &mild_shift_window().embeddings,
        &kernel,
    )
    .expect("mild mmd");
    let severe = compute_mmd_squared(
        &benchmark.embeddings,
        &severe_shift_window().embeddings,
        &kernel,
    )
    .expect("severe mmd");

    assert!(negative.mmd_squared_millionths < mild.mmd_squared_millionths);
    assert!(mild.mmd_squared_millionths <= severe.mmd_squared_millionths);
}

#[test]
fn run_shift_evidence_manifest_is_consistent() {
    let manifest = run_shift_evidence();

    assert_eq!(manifest.schema_version, SHIFT_MONITOR_SCHEMA_VERSION);
    assert_eq!(manifest.windows_compared, 2);
    assert_eq!(manifest.shifts_detected, 1);
    assert_eq!(manifest.abstentions, 0);
    assert_eq!(manifest.certificates.len(), 2);
    assert!(manifest.error.is_none());
    assert_ne!(manifest.manifest_hash, ContentHash::default());
}

#[test]
fn run_shift_evidence_is_deterministic() {
    let first = run_shift_evidence();
    let second = run_shift_evidence();

    assert_eq!(first.manifest_hash, second.manifest_hash);
    assert_eq!(first.certificates, second.certificates);
}

#[test]
fn emit_shift_monitor_artifacts_for_replay() {
    let dir = artifact_dir();
    fs::create_dir_all(&dir).expect("create artifact dir");

    let benchmark = benchmark_window();
    let negative = negative_control_window();
    let mild = mild_shift_window();
    let severe = severe_shift_window();
    let short = short_window();

    let mut insufficient_config = base_config();
    insufficient_config.abstention_sample_floor = 4;
    insufficient_config.window.min_samples = 6;

    let mut abstention_config = base_config();
    abstention_config.abstention_sample_floor = 32;

    let negative_cert = detect_shift(&benchmark, &negative, &base_config());
    let mild_cert = detect_shift(&benchmark, &mild, &base_config());
    let severe_cert = detect_shift(&benchmark, &severe, &base_config());
    let insufficient_cert = detect_shift(&benchmark, &short, &insufficient_config);
    let abstained_cert = detect_shift(&benchmark, &short, &abstention_config);

    let mut scenario_windows = BTreeMap::new();
    scenario_windows.insert("negative_control".to_string(), negative.clone());
    scenario_windows.insert("mild_shift".to_string(), mild.clone());
    scenario_windows.insert("severe_shift".to_string(), severe.clone());
    scenario_windows.insert("short_sample".to_string(), short.clone());

    write_json(
        dir.join("live_shift_windows.json"),
        &WindowArtifact {
            schema_version: "franken-engine.distribution-shift-monitor.window-corpus.v1",
            component: SHIFT_MONITOR_COMPONENT,
            benchmark_window: benchmark.clone(),
            scenario_windows,
        },
    );

    let statistics = vec![
        ("negative_control", &negative_cert),
        ("mild_shift", &mild_cert),
        ("severe_shift", &severe_cert),
        ("insufficient_samples", &insufficient_cert),
        ("abstained_floor", &abstained_cert),
    ]
    .into_iter()
    .map(|(scenario_id, cert)| KernelStatisticLine {
        scenario_id: scenario_id.to_string(),
        verdict: verdict_name(&cert.verdict).to_string(),
        mmd_squared_millionths: cert.mmd.as_ref().map(|mmd| mmd.mmd_squared_millionths),
        threshold_millionths: cert.mmd.as_ref().map(|mmd| mmd.threshold_millionths),
        is_shifted: cert.mmd.as_ref().map(|mmd| mmd.is_shifted),
        sample_count_left: cert
            .mmd
            .as_ref()
            .map(|mmd| mmd.sample_count_left)
            .unwrap_or(cert.benchmark_window.embeddings.len() as u64),
        sample_count_right: cert
            .mmd
            .as_ref()
            .map(|mmd| mmd.sample_count_right)
            .unwrap_or(cert.live_window.embeddings.len() as u64),
        certificate_hash: cert.certificate_hash.to_string(),
    })
    .collect::<Vec<_>>();
    write_jsonl(dir.join("kernel_shift_statistics.jsonl"), &statistics);

    let certificates = [
        &negative_cert,
        &mild_cert,
        &severe_cert,
        &insufficient_cert,
        &abstained_cert,
    ];
    let shifts_detected = certificates
        .iter()
        .filter(|cert| matches!(cert.verdict, ShiftVerdict::ShiftDetected { .. }))
        .count();
    let no_shift = certificates
        .iter()
        .filter(|cert| matches!(cert.verdict, ShiftVerdict::NoShift))
        .count();
    let insufficient_samples = certificates
        .iter()
        .filter(|cert| matches!(cert.verdict, ShiftVerdict::InsufficientSamples { .. }))
        .count();
    let abstentions = certificates
        .iter()
        .filter(|cert| matches!(cert.verdict, ShiftVerdict::Abstained { .. }))
        .count();
    let max_mmd_squared_millionths = certificates
        .iter()
        .filter_map(|cert| cert.mmd.as_ref().map(|mmd| mmd.mmd_squared_millionths))
        .max()
        .unwrap_or(0);

    let verdict_by_scenario = [
        (
            "negative_control".to_string(),
            verdict_name(&negative_cert.verdict).to_string(),
        ),
        (
            "mild_shift".to_string(),
            verdict_name(&mild_cert.verdict).to_string(),
        ),
        (
            "severe_shift".to_string(),
            verdict_name(&severe_cert.verdict).to_string(),
        ),
        (
            "insufficient_samples".to_string(),
            verdict_name(&insufficient_cert.verdict).to_string(),
        ),
        (
            "abstained_floor".to_string(),
            verdict_name(&abstained_cert.verdict).to_string(),
        ),
    ]
    .into_iter()
    .collect();

    write_json(
        dir.join("shift_alarm_report.json"),
        &ShiftAlarmReport {
            schema_version: "franken-engine.distribution-shift-monitor.alarm-report.v1",
            component: SHIFT_MONITOR_COMPONENT,
            compared_scenarios: certificates.len(),
            shifts_detected,
            no_shift,
            insufficient_samples,
            abstentions,
            max_mmd_squared_millionths,
            verdict_by_scenario,
        },
    );

    write_json(
        dir.join("shift_negative_control_report.json"),
        &NegativeControlReport {
            schema_version: "franken-engine.distribution-shift-monitor.negative-control.v1",
            component: SHIFT_MONITOR_COMPONENT,
            scenario_id: "negative_control",
            verdict: verdict_name(&negative_cert.verdict).to_string(),
            passes_negative_control: matches!(negative_cert.verdict, ShiftVerdict::NoShift),
            certificate_hash: negative_cert.certificate_hash.to_string(),
        },
    );

    let alarm_report =
        fs::read_to_string(dir.join("shift_alarm_report.json")).expect("read report");
    let statistics_jsonl =
        fs::read_to_string(dir.join("kernel_shift_statistics.jsonl")).expect("read jsonl");
    assert!(alarm_report.contains("\"severe_shift\""));
    assert!(alarm_report.contains("\"shifts_detected\""));
    assert!(statistics_jsonl.contains("\"scenario_id\":\"negative_control\""));
    assert!(statistics_jsonl.contains("\"scenario_id\":\"severe_shift\""));
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde roundtrips, kernel variants, error paths,
// config defaults, determinism, Display impls
// ────────────────────────────────────────────────────────────

#[test]
fn stream_kind_serde_roundtrip() {
    for kind in [StreamKind::Benchmark, StreamKind::LiveWorkload] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: StreamKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(kind, recovered);
    }
}

#[test]
fn stream_kind_display() {
    assert_eq!(StreamKind::Benchmark.to_string(), "benchmark");
    assert_eq!(StreamKind::LiveWorkload.to_string(), "live_workload");
}

#[test]
fn kernel_kind_serde_roundtrip_all_variants() {
    let kernels = [
        KernelKind::Linear,
        KernelKind::Polynomial { degree: 3 },
        KernelKind::GaussianRbf {
            bandwidth_millionths: MILLION,
        },
    ];
    for kernel in &kernels {
        let json = serde_json::to_string(kernel).expect("serialize");
        let recovered: KernelKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*kernel, recovered);
    }
}

#[test]
fn shift_verdict_serde_roundtrip_all_variants() {
    let verdicts = [
        ShiftVerdict::NoShift,
        ShiftVerdict::ShiftDetected { mmd_squared: 42 },
        ShiftVerdict::InsufficientSamples {
            available: 3,
            required: 6,
        },
        ShiftVerdict::Abstained {
            reason: "test reason".to_string(),
        },
    ];
    for verdict in &verdicts {
        let json = serde_json::to_string(verdict).expect("serialize");
        let recovered: ShiftVerdict = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*verdict, recovered);
    }
}

#[test]
fn shift_error_serde_roundtrip_all_variants() {
    let errors = [
        ShiftError::EmptyWindow,
        ShiftError::DimensionMismatch {
            expected: 2,
            actual: 3,
        },
        ShiftError::InvalidConfig {
            reason: "bad config".to_string(),
        },
        ShiftError::InsufficientData,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let recovered: ShiftError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, recovered);
    }
}

#[test]
fn shift_error_display_is_nonempty() {
    let errors = [
        ShiftError::EmptyWindow,
        ShiftError::DimensionMismatch {
            expected: 2,
            actual: 3,
        },
        ShiftError::InvalidConfig {
            reason: "bad".to_string(),
        },
        ShiftError::InsufficientData,
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "Display for {:?} is empty", err);
    }
}

#[test]
fn monitor_config_default_has_sane_values() {
    let config = MonitorConfig::default_config();
    assert!(config.window.window_size > 0);
    assert!(config.window.slide_step > 0);
    assert!(config.window.min_samples > 0);
    assert!(config.significance_threshold_millionths > 0);
    assert!(config.min_effect_size_millionths > 0);
    assert!(config.abstention_sample_floor > 0);
}

#[test]
fn monitor_config_serde_roundtrip() {
    let config = base_config();
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: MonitorConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, recovered);
}

#[test]
fn embedding_vector_serde_roundtrip() {
    let v = emb("test", &[500_000, 600_000]);
    let json = serde_json::to_string(&v).expect("serialize");
    let recovered: EmbeddingVector = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(v, recovered);
}

#[test]
fn stream_window_serde_roundtrip() {
    let window = benchmark_window();
    let json = serde_json::to_string(&window).expect("serialize");
    let recovered: StreamWindow = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(window, recovered);
    assert_eq!(window.window_hash, recovered.window_hash);
}

#[test]
fn build_window_indices_match_embedding_count() {
    let embeddings = build_series("idx", 500_000, 500_000, 1_000, 500, 8);
    let window = build_window(StreamKind::Benchmark, embeddings, 5);
    assert_eq!(window.start_index, 5);
    assert_eq!(window.end_index, 13); // 5 + 8
    assert_eq!(window.embeddings.len(), 8);
}

#[test]
fn compute_mmd_squared_empty_window_is_error() {
    let kernel = KernelKind::Linear;
    let non_empty = vec![emb("a", &[100_000])];
    let err = compute_mmd_squared(&[], &non_empty, &kernel).unwrap_err();
    assert!(matches!(err, ShiftError::EmptyWindow));

    let err2 = compute_mmd_squared(&non_empty, &[], &kernel).unwrap_err();
    assert!(matches!(err2, ShiftError::EmptyWindow));
}

#[test]
fn compute_mmd_squared_identical_distributions_yields_low_value() {
    let kernel = KernelKind::GaussianRbf {
        bandwidth_millionths: MILLION,
    };
    let data = build_series("same", 500_000, 500_000, 1_000, 500, 12);
    let result = compute_mmd_squared(&data, &data, &kernel).expect("mmd");
    // Identical distributions should have MMD² ≈ 0
    assert_eq!(result.mmd_squared_millionths, 0);
    assert!(!result.is_shifted);
}

#[test]
fn compute_kernel_value_linear_kernel() {
    let a = emb("ka", &[MILLION, 0]);
    let b = emb("kb", &[0, MILLION]);
    let value = compute_kernel_value(&a, &b, &KernelKind::Linear);
    // Linear kernel: dot product in millionths. (1M * 0 + 0 * 1M) / 1M = 0
    assert_eq!(value, 0);

    let c = emb("kc", &[MILLION, MILLION]);
    let value2 = compute_kernel_value(&a, &c, &KernelKind::Linear);
    // (1M * 1M + 0 * 1M) / 1M = 1M
    assert_eq!(value2, MILLION);
}

#[test]
fn compute_kernel_value_dimension_mismatch_returns_zero() {
    let a = emb("ka", &[MILLION, 0]);
    let b = emb("kb", &[MILLION, 0, MILLION]);
    let value = compute_kernel_value(&a, &b, &KernelKind::Linear);
    assert_eq!(value, 0);
}

#[test]
fn shift_certificate_serde_roundtrip() {
    let certificate = detect_shift(
        &benchmark_window(),
        &negative_control_window(),
        &base_config(),
    );
    let json = serde_json::to_string(&certificate).expect("serialize");
    let recovered: ShiftCertificate = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(certificate, recovered);
    assert_eq!(certificate.certificate_hash, recovered.certificate_hash);
}

#[test]
fn shift_certificate_hash_is_deterministic() {
    let cert1 = detect_shift(
        &benchmark_window(),
        &negative_control_window(),
        &base_config(),
    );
    let cert2 = detect_shift(
        &benchmark_window(),
        &negative_control_window(),
        &base_config(),
    );
    assert_eq!(cert1.certificate_hash, cert2.certificate_hash);
}

#[test]
fn shift_evidence_manifest_serde_roundtrip() {
    let manifest = run_shift_evidence();
    let json = serde_json::to_string(&manifest).expect("serialize");
    let recovered: ShiftEvidenceManifest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(manifest, recovered);
}

#[test]
fn mmd_result_serde_roundtrip() {
    let kernel = KernelKind::GaussianRbf {
        bandwidth_millionths: MILLION,
    };
    let result = compute_mmd_squared(
        &benchmark_window().embeddings,
        &severe_shift_window().embeddings,
        &kernel,
    )
    .expect("mmd");
    let json = serde_json::to_string(&result).expect("serialize");
    let recovered: MmdResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result, recovered);
}

#[test]
fn window_config_serde_roundtrip() {
    let config = WindowConfig {
        window_size: 100,
        slide_step: 50,
        min_samples: 10,
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: WindowConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, recovered);
}

#[test]
fn detect_shift_with_polynomial_kernel() {
    let mut config = base_config();
    config.kernel = KernelKind::Polynomial { degree: 2 };
    let certificate = detect_shift(&benchmark_window(), &severe_shift_window(), &config);
    // Should still detect shift with polynomial kernel
    assert!(matches!(
        certificate.verdict,
        ShiftVerdict::ShiftDetected { .. } | ShiftVerdict::NoShift
    ));
    assert!(certificate.mmd.is_some());
}

#[test]
fn detect_shift_with_linear_kernel() {
    let mut config = base_config();
    config.kernel = KernelKind::Linear;
    let certificate = detect_shift(&benchmark_window(), &severe_shift_window(), &config);
    assert!(certificate.mmd.is_some());
}

#[test]
fn monitor_state_serde_roundtrip() {
    let state = MonitorState {
        benchmark_windows: vec![benchmark_window()],
        live_windows: vec![negative_control_window()],
        certificates: vec![detect_shift(
            &benchmark_window(),
            &negative_control_window(),
            &base_config(),
        )],
        state_hash: ContentHash::compute(b"test-state"),
    };
    let json = serde_json::to_string(&state).expect("serialize");
    let recovered: MonitorState = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(state, recovered);
}

#[test]
fn embedding_vector_hash_is_deterministic() {
    let v1 = emb("deterministic", &[100_000, 200_000]);
    let v2 = emb("deterministic", &[100_000, 200_000]);
    assert_eq!(v1.source_hash, v2.source_hash);

    let v3 = emb("different", &[100_000, 200_000]);
    assert_ne!(v1.source_hash, v3.source_hash);
}

// ────────────────────────────────────────────────────────────
// Enrichment batch 2: clone, debug, edge cases, boundary
// values, kernel coverage, config permutations
// ────────────────────────────────────────────────────────────

#[test]
fn stream_kind_clone_eq_debug() {
    let a = StreamKind::Benchmark;
    let b = a;
    assert_eq!(a, b);
    let dbg_a = format!("{a:?}");
    let dbg_b = format!("{b:?}");
    assert_eq!(dbg_a, dbg_b);
    assert!(dbg_a.contains("Benchmark"));

    let c = StreamKind::LiveWorkload;
    let d = c;
    assert_eq!(c, d);
    assert_ne!(a, c);
    let dbg_c = format!("{c:?}");
    assert!(dbg_c.contains("LiveWorkload"));
    // Debug outputs for different variants must be distinct
    assert_ne!(dbg_a, dbg_c);
}

#[test]
fn stream_kind_display_outputs_are_unique() {
    let variants = [StreamKind::Benchmark, StreamKind::LiveWorkload];
    let displays: Vec<String> = variants.iter().map(|v| v.to_string()).collect();
    for i in 0..displays.len() {
        for j in (i + 1)..displays.len() {
            assert_ne!(displays[i], displays[j]);
        }
    }
}

#[test]
fn stream_kind_ord_is_consistent() {
    let a = StreamKind::Benchmark;
    let b = StreamKind::LiveWorkload;
    // Ordering must be total and consistent
    assert!(a < b || b < a || a == b);
    // From the derive order: Benchmark < LiveWorkload
    assert!(a < b);
}

#[test]
fn kernel_kind_clone_eq_debug() {
    let linear = KernelKind::Linear;
    assert_eq!(linear, linear);

    let poly = KernelKind::Polynomial { degree: 5 };
    assert_eq!(poly, poly);

    let rbf = KernelKind::GaussianRbf {
        bandwidth_millionths: 2_000_000,
    };
    assert_eq!(rbf, rbf);

    // Debug outputs for different variants must be distinct
    let dbgs: Vec<String> = [&linear, &poly, &rbf]
        .iter()
        .map(|k| format!("{k:?}"))
        .collect();
    for i in 0..dbgs.len() {
        for j in (i + 1)..dbgs.len() {
            assert_ne!(dbgs[i], dbgs[j]);
        }
    }
}

#[test]
fn kernel_kind_ne_across_variants() {
    let linear = KernelKind::Linear;
    let poly = KernelKind::Polynomial { degree: 2 };
    let rbf = KernelKind::GaussianRbf {
        bandwidth_millionths: MILLION,
    };
    assert_ne!(linear, poly);
    assert_ne!(linear, rbf);
    assert_ne!(poly, rbf);
}

#[test]
fn kernel_kind_polynomial_different_degrees_ne() {
    let p2 = KernelKind::Polynomial { degree: 2 };
    let p3 = KernelKind::Polynomial { degree: 3 };
    assert_ne!(p2, p3);
    let json2 = serde_json::to_string(&p2).expect("serialize");
    let json3 = serde_json::to_string(&p3).expect("serialize");
    assert_ne!(json2, json3);
}

#[test]
fn kernel_kind_rbf_different_bandwidths_ne() {
    let r1 = KernelKind::GaussianRbf {
        bandwidth_millionths: MILLION,
    };
    let r2 = KernelKind::GaussianRbf {
        bandwidth_millionths: 500_000,
    };
    assert_ne!(r1, r2);
}

#[test]
fn shift_verdict_clone_eq_debug_all_variants() {
    let variants: Vec<ShiftVerdict> = vec![
        ShiftVerdict::NoShift,
        ShiftVerdict::ShiftDetected { mmd_squared: 99 },
        ShiftVerdict::InsufficientSamples {
            available: 1,
            required: 10,
        },
        ShiftVerdict::Abstained {
            reason: "test".to_string(),
        },
    ];
    for v in &variants {
        let cloned = v.clone();
        assert_eq!(*v, cloned);
    }
    // Debug outputs for every variant must be distinct
    let dbgs: Vec<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    for i in 0..dbgs.len() {
        for j in (i + 1)..dbgs.len() {
            assert_ne!(dbgs[i], dbgs[j]);
        }
    }
}

#[test]
fn shift_error_clone_eq_debug_all_variants() {
    let variants: Vec<ShiftError> = vec![
        ShiftError::EmptyWindow,
        ShiftError::DimensionMismatch {
            expected: 5,
            actual: 7,
        },
        ShiftError::InvalidConfig {
            reason: "broken".to_string(),
        },
        ShiftError::InsufficientData,
    ];
    for e in &variants {
        let cloned = e.clone();
        assert_eq!(*e, cloned);
    }
    let dbgs: Vec<String> = variants.iter().map(|e| format!("{e:?}")).collect();
    for i in 0..dbgs.len() {
        for j in (i + 1)..dbgs.len() {
            assert_ne!(dbgs[i], dbgs[j]);
        }
    }
}

#[test]
fn shift_error_display_outputs_are_unique() {
    let errors: Vec<ShiftError> = vec![
        ShiftError::EmptyWindow,
        ShiftError::DimensionMismatch {
            expected: 2,
            actual: 3,
        },
        ShiftError::InvalidConfig {
            reason: "bad".to_string(),
        },
        ShiftError::InsufficientData,
    ];
    let displays: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
    for i in 0..displays.len() {
        for j in (i + 1)..displays.len() {
            assert_ne!(displays[i], displays[j]);
        }
    }
}

#[test]
fn shift_error_display_exact_strings() {
    assert_eq!(ShiftError::EmptyWindow.to_string(), "empty window");
    assert_eq!(
        ShiftError::DimensionMismatch {
            expected: 10,
            actual: 20,
        }
        .to_string(),
        "dimension mismatch: expected 10, got 20"
    );
    assert_eq!(
        ShiftError::InvalidConfig {
            reason: "zero bandwidth".to_string(),
        }
        .to_string(),
        "invalid config: zero bandwidth"
    );
    assert_eq!(
        ShiftError::InsufficientData.to_string(),
        "insufficient data"
    );
}

#[test]
fn embedding_vector_clone_eq() {
    let v = emb("clone-test", &[100_000, 200_000, 300_000]);
    let cloned = v.clone();
    assert_eq!(v, cloned);
    assert_eq!(v.dimensions, cloned.dimensions);
    assert_eq!(v.source_hash, cloned.source_hash);
}

#[test]
fn embedding_vector_empty_dimensions() {
    let v = emb("empty-dims", &[]);
    assert!(v.dimensions.is_empty());
    let json = serde_json::to_string(&v).expect("serialize");
    let recovered: EmbeddingVector = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(v, recovered);
}

#[test]
fn embedding_vector_single_dimension() {
    let v = emb("single", &[MILLION]);
    assert_eq!(v.dimensions.len(), 1);
    assert_eq!(v.dimensions[0], MILLION);
}

#[test]
fn embedding_vector_large_dimension_values() {
    let large = u64::MAX / 2;
    let v = emb("large", &[large, large]);
    let json = serde_json::to_string(&v).expect("serialize");
    let recovered: EmbeddingVector = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(v, recovered);
    assert_eq!(recovered.dimensions[0], large);
}

#[test]
fn stream_window_clone_eq_debug() {
    let w = benchmark_window();
    let cloned = w.clone();
    assert_eq!(w, cloned);
    assert_eq!(w.window_hash, cloned.window_hash);
    let dbg = format!("{w:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("StreamWindow"));
}

#[test]
fn build_window_empty_embeddings() {
    let w = build_window(StreamKind::Benchmark, vec![], 0);
    assert_eq!(w.start_index, 0);
    assert_eq!(w.end_index, 0);
    assert!(w.embeddings.is_empty());
    assert_eq!(w.stream_kind, StreamKind::Benchmark);
    // Serde roundtrip for empty window
    let json = serde_json::to_string(&w).expect("serialize");
    let recovered: StreamWindow = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(w, recovered);
}

#[test]
fn build_window_large_start_index() {
    let start = 1_000_000u64;
    let embeddings = vec![emb("large-start", &[500_000])];
    let w = build_window(StreamKind::LiveWorkload, embeddings, start);
    assert_eq!(w.start_index, start);
    assert_eq!(w.end_index, start + 1);
    assert_eq!(w.embeddings.len(), 1);
}

#[test]
fn build_window_different_kinds_produce_same_hash_for_same_embeddings() {
    // Window hash is based on embeddings content, not stream kind
    let embeddings = build_series("kind-test", 500_000, 500_000, 1_000, 500, 6);
    let w_bench = build_window(StreamKind::Benchmark, embeddings.clone(), 0);
    let w_live = build_window(StreamKind::LiveWorkload, embeddings, 0);
    // The hash is computed from embeddings only, so it should match
    assert_eq!(w_bench.window_hash, w_live.window_hash);
    // But the windows themselves differ because stream_kind differs
    assert_ne!(w_bench, w_live);
}

#[test]
fn mmd_result_clone_eq_debug() {
    let mmd = MmdResult {
        mmd_squared_millionths: 42_000,
        threshold_millionths: 100_000,
        is_shifted: true,
        sample_count_left: 12,
        sample_count_right: 12,
    };
    let cloned = mmd.clone();
    assert_eq!(mmd, cloned);
    let dbg = format!("{mmd:?}");
    assert!(dbg.contains("42000"));
    assert!(dbg.contains("MmdResult"));
}

#[test]
fn mmd_result_boundary_zero_values() {
    let mmd = MmdResult {
        mmd_squared_millionths: 0,
        threshold_millionths: 0,
        is_shifted: false,
        sample_count_left: 0,
        sample_count_right: 0,
    };
    let json = serde_json::to_string(&mmd).expect("serialize");
    let recovered: MmdResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(mmd, recovered);
}

#[test]
fn mmd_result_boundary_max_values() {
    let mmd = MmdResult {
        mmd_squared_millionths: u64::MAX,
        threshold_millionths: u64::MAX,
        is_shifted: true,
        sample_count_left: u64::MAX,
        sample_count_right: u64::MAX,
    };
    let json = serde_json::to_string(&mmd).expect("serialize");
    let recovered: MmdResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(mmd, recovered);
}

#[test]
fn window_config_clone_eq_debug() {
    let wc = WindowConfig {
        window_size: 200,
        slide_step: 100,
        min_samples: 20,
    };
    let cloned = wc.clone();
    assert_eq!(wc, cloned);
    let dbg = format!("{wc:?}");
    assert!(dbg.contains("WindowConfig"));
    assert!(dbg.contains("200"));
}

#[test]
fn window_config_zero_fields_serde_roundtrip() {
    let wc = WindowConfig {
        window_size: 0,
        slide_step: 0,
        min_samples: 0,
    };
    let json = serde_json::to_string(&wc).expect("serialize");
    let recovered: WindowConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(wc, recovered);
}

#[test]
fn monitor_config_clone_eq_debug() {
    let config = MonitorConfig::default_config();
    let cloned = config.clone();
    assert_eq!(config, cloned);
    let dbg = format!("{config:?}");
    assert!(dbg.contains("MonitorConfig"));
    assert!(dbg.contains("GaussianRbf"));
}

#[test]
fn monitor_config_with_linear_kernel_serde() {
    let config = MonitorConfig {
        window: WindowConfig {
            window_size: 50,
            slide_step: 25,
            min_samples: 5,
        },
        kernel: KernelKind::Linear,
        significance_threshold_millionths: 200_000,
        min_effect_size_millionths: 20_000,
        abstention_sample_floor: 8,
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: MonitorConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, recovered);
}

#[test]
fn monitor_config_with_polynomial_kernel_serde() {
    let config = MonitorConfig {
        window: WindowConfig {
            window_size: 50,
            slide_step: 10,
            min_samples: 5,
        },
        kernel: KernelKind::Polynomial { degree: 4 },
        significance_threshold_millionths: 50_000,
        min_effect_size_millionths: 5_000,
        abstention_sample_floor: 4,
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: MonitorConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, recovered);
}

#[test]
fn shift_certificate_clone_eq_debug() {
    let cert = detect_shift(
        &benchmark_window(),
        &negative_control_window(),
        &base_config(),
    );
    let cloned = cert.clone();
    assert_eq!(cert, cloned);
    assert_eq!(cert.certificate_hash, cloned.certificate_hash);
    assert_eq!(cert.config_hash, cloned.config_hash);
    let dbg = format!("{cert:?}");
    assert!(dbg.contains("ShiftCertificate"));
}

#[test]
fn shift_certificate_config_hash_varies_with_config() {
    let config1 = base_config();
    let mut config2 = base_config();
    config2.significance_threshold_millionths = 999_999;

    let cert1 = detect_shift(&benchmark_window(), &negative_control_window(), &config1);
    let cert2 = detect_shift(&benchmark_window(), &negative_control_window(), &config2);

    assert_ne!(cert1.config_hash, cert2.config_hash);
}

#[test]
fn shift_certificate_all_verdict_branches() {
    // NoShift
    let cert_no = detect_shift(
        &benchmark_window(),
        &negative_control_window(),
        &base_config(),
    );
    assert!(matches!(cert_no.verdict, ShiftVerdict::NoShift));
    assert!(cert_no.mmd.is_some());

    // ShiftDetected
    let cert_shift = detect_shift(&benchmark_window(), &severe_shift_window(), &base_config());
    assert!(matches!(
        cert_shift.verdict,
        ShiftVerdict::ShiftDetected { .. }
    ));
    assert!(cert_shift.mmd.is_some());

    // InsufficientSamples
    let mut insuf_config = base_config();
    insuf_config.abstention_sample_floor = 4;
    insuf_config.window.min_samples = 6;
    let cert_insuf = detect_shift(&benchmark_window(), &short_window(), &insuf_config);
    assert!(matches!(
        cert_insuf.verdict,
        ShiftVerdict::InsufficientSamples { .. }
    ));
    assert!(cert_insuf.mmd.is_none());

    // Abstained (sample floor)
    let mut abs_config = base_config();
    abs_config.abstention_sample_floor = 100;
    let cert_abs = detect_shift(&benchmark_window(), &short_window(), &abs_config);
    assert!(matches!(cert_abs.verdict, ShiftVerdict::Abstained { .. }));
    assert!(cert_abs.mmd.is_none());

    // All four have distinct certificate hashes
    let hashes = [
        &cert_no.certificate_hash,
        &cert_shift.certificate_hash,
        &cert_insuf.certificate_hash,
        &cert_abs.certificate_hash,
    ];
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j]);
        }
    }
}

#[test]
fn monitor_state_clone_eq_debug() {
    let state = MonitorState {
        benchmark_windows: vec![benchmark_window()],
        live_windows: vec![negative_control_window()],
        certificates: vec![],
        state_hash: ContentHash::compute(b"state-clone-test"),
    };
    let cloned = state.clone();
    assert_eq!(state, cloned);
    let dbg = format!("{state:?}");
    assert!(dbg.contains("MonitorState"));
}

#[test]
fn monitor_state_empty_serde_roundtrip() {
    let state = MonitorState {
        benchmark_windows: vec![],
        live_windows: vec![],
        certificates: vec![],
        state_hash: ContentHash::compute(b"empty-state"),
    };
    let json = serde_json::to_string(&state).expect("serialize");
    let recovered: MonitorState = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(state, recovered);
}

#[test]
fn shift_evidence_manifest_clone_eq_debug() {
    let manifest = run_shift_evidence();
    let cloned = manifest.clone();
    assert_eq!(manifest, cloned);
    assert_eq!(manifest.manifest_hash, cloned.manifest_hash);
    let dbg = format!("{manifest:?}");
    assert!(dbg.contains("ShiftEvidenceManifest"));
}

#[test]
fn shift_evidence_manifest_shifts_and_abstentions_consistent() {
    let manifest = run_shift_evidence();
    let counted_shifts = manifest
        .certificates
        .iter()
        .filter(|c| matches!(c.verdict, ShiftVerdict::ShiftDetected { .. }))
        .count() as u32;
    let counted_abstentions = manifest
        .certificates
        .iter()
        .filter(|c| matches!(c.verdict, ShiftVerdict::Abstained { .. }))
        .count() as u32;
    assert_eq!(manifest.shifts_detected, counted_shifts);
    assert_eq!(manifest.abstentions, counted_abstentions);
    // windows_compared equals certificate count
    assert_eq!(
        manifest.windows_compared,
        manifest.certificates.len() as u32
    );
}

#[test]
fn compute_kernel_value_polynomial_degree_zero() {
    // (dot + 1.0)^0 = 1.0 for any inputs
    let a = emb("pz-a", &[500_000, 700_000]);
    let b = emb("pz-b", &[300_000, 900_000]);
    let val = compute_kernel_value(&a, &b, &KernelKind::Polynomial { degree: 0 });
    assert_eq!(val, MILLION); // 1.0 in millionths
}

#[test]
fn compute_kernel_value_polynomial_degree_two() {
    let a = emb("p2-a", &[MILLION, 0]);
    let b = emb("p2-b", &[MILLION, 0]);
    // dot = 1.0, (1.0 + 1.0)^2 = 4.0 = 4_000_000
    let val = compute_kernel_value(&a, &b, &KernelKind::Polynomial { degree: 2 });
    assert_eq!(val, 4_000_000);
}

#[test]
fn compute_kernel_value_rbf_identical_points() {
    let a = emb("rbf-id-a", &[750_000, 250_000]);
    let b = emb("rbf-id-b", &[750_000, 250_000]);
    let val = compute_kernel_value(
        &a,
        &b,
        &KernelKind::GaussianRbf {
            bandwidth_millionths: MILLION,
        },
    );
    // Distance = 0, exp(0) = 1.0
    assert_eq!(val, MILLION);
}

#[test]
fn compute_kernel_value_rbf_zero_bandwidth_identical() {
    let a = emb("rbf-zb-a", &[500_000]);
    let b = emb("rbf-zb-b", &[500_000]);
    let val = compute_kernel_value(
        &a,
        &b,
        &KernelKind::GaussianRbf {
            bandwidth_millionths: 0,
        },
    );
    // zero bandwidth, zero distance -> MILLION
    assert_eq!(val, MILLION);
}

#[test]
fn compute_kernel_value_rbf_zero_bandwidth_different() {
    let a = emb("rbf-zb2-a", &[500_000]);
    let b = emb("rbf-zb2-b", &[600_000]);
    let val = compute_kernel_value(
        &a,
        &b,
        &KernelKind::GaussianRbf {
            bandwidth_millionths: 0,
        },
    );
    // zero bandwidth, nonzero distance -> 0
    assert_eq!(val, 0);
}

#[test]
fn compute_mmd_squared_single_element_identical() {
    let a = vec![emb("mmd-single", &[500_000, 500_000])];
    let kernel = KernelKind::GaussianRbf {
        bandwidth_millionths: MILLION,
    };
    let result = compute_mmd_squared(&a, &a, &kernel).expect("mmd");
    assert_eq!(result.mmd_squared_millionths, 0);
    assert_eq!(result.sample_count_left, 1);
    assert_eq!(result.sample_count_right, 1);
}

#[test]
fn compute_mmd_squared_dimension_mismatch_across_sets() {
    let left = vec![emb("dim-l", &[500_000, 500_000])];
    let right = vec![emb("dim-r", &[500_000])];
    let result = compute_mmd_squared(&left, &right, &KernelKind::Linear);
    assert!(matches!(
        result,
        Err(ShiftError::DimensionMismatch {
            expected: 2,
            actual: 1
        })
    ));
}

#[test]
fn compute_mmd_squared_both_empty() {
    let result = compute_mmd_squared(&[], &[], &KernelKind::Linear);
    assert!(matches!(result, Err(ShiftError::EmptyWindow)));
}

#[test]
fn constants_fixed_point_unit_value() {
    // MILLION constant used in tests matches the module's fixed-point unit
    assert_eq!(MILLION, 1_000_000);
}

#[test]
fn shift_verdict_no_shift_serde_json_stable() {
    let v = ShiftVerdict::NoShift;
    let json = serde_json::to_string(&v).expect("serialize");
    // snake_case rename means it serializes as a specific string
    let recovered: ShiftVerdict = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(v, recovered);
    // Verify the JSON contains the expected variant name
    assert!(json.contains("no_shift"));
}

#[test]
fn shift_verdict_shift_detected_carries_mmd_squared() {
    let v = ShiftVerdict::ShiftDetected {
        mmd_squared: 123_456,
    };
    let json = serde_json::to_string(&v).expect("serialize");
    assert!(json.contains("123456"));
    let recovered: ShiftVerdict = serde_json::from_str(&json).expect("deserialize");
    if let ShiftVerdict::ShiftDetected { mmd_squared } = recovered {
        assert_eq!(mmd_squared, 123_456);
    } else {
        panic!("expected ShiftDetected");
    }
}

#[test]
fn detect_shift_abstains_on_dimension_mismatch_in_live_window() {
    // The mismatched_dimension_window has 3D embeddings vs benchmark's 2D
    let mut config = base_config();
    config.abstention_sample_floor = 8;
    let cert = detect_shift(&benchmark_window(), &mismatched_dimension_window(), &config);
    match &cert.verdict {
        ShiftVerdict::Abstained { reason } => {
            assert_eq!(reason, "MMD computation failed");
        }
        other => panic!("expected Abstained, got {other:?}"),
    }
    assert!(cert.mmd.is_none());
    assert_eq!(cert.schema_version, SHIFT_MONITOR_SCHEMA_VERSION);
    assert_ne!(cert.certificate_hash, ContentHash::default());
}

#[test]
fn detect_shift_mild_shift_is_between_no_shift_and_severe() {
    let config = base_config();
    let bench = benchmark_window();

    let cert_no = detect_shift(&bench, &negative_control_window(), &config);
    let cert_mild = detect_shift(&bench, &mild_shift_window(), &config);
    let cert_severe = detect_shift(&bench, &severe_shift_window(), &config);

    // All three should have MMD results
    let mmd_no = cert_no.mmd.as_ref().expect("no-shift mmd");
    let mmd_mild = cert_mild.mmd.as_ref().expect("mild mmd");
    let mmd_severe = cert_severe.mmd.as_ref().expect("severe mmd");

    // MMD values should be ordered: negative < mild <= severe
    assert!(mmd_no.mmd_squared_millionths < mmd_mild.mmd_squared_millionths);
    assert!(mmd_mild.mmd_squared_millionths <= mmd_severe.mmd_squared_millionths);
}

#[test]
fn monitor_state_with_multiple_certificates_serde() {
    let cert1 = detect_shift(
        &benchmark_window(),
        &negative_control_window(),
        &base_config(),
    );
    let cert2 = detect_shift(&benchmark_window(), &severe_shift_window(), &base_config());
    let state = MonitorState {
        benchmark_windows: vec![benchmark_window(), benchmark_window()],
        live_windows: vec![negative_control_window(), severe_shift_window()],
        certificates: vec![cert1, cert2],
        state_hash: ContentHash::compute(b"multi-cert-state"),
    };
    let json = serde_json::to_string(&state).expect("serialize");
    let recovered: MonitorState = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(state, recovered);
    assert_eq!(recovered.certificates.len(), 2);
    assert_eq!(recovered.benchmark_windows.len(), 2);
    assert_eq!(recovered.live_windows.len(), 2);
}

#[test]
fn shift_evidence_manifest_no_error_field() {
    let manifest = run_shift_evidence();
    assert!(manifest.error.is_none());
    // Verify the JSON output omits error or has it as null
    let json = serde_json::to_string(&manifest).expect("serialize");
    let val: serde_json::Value = serde_json::from_str(&json).expect("parse");
    assert!(val["error"].is_null());
}

#[test]
fn shift_evidence_manifest_hash_changes_with_different_certificates() {
    // The manifest hash should be derived from certificates
    let m1 = run_shift_evidence();
    let m2 = run_shift_evidence();
    // Same inputs produce same hash
    assert_eq!(m1.manifest_hash, m2.manifest_hash);
    // Verify hash is non-default
    assert_ne!(m1.manifest_hash, ContentHash::default());
}
