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

use frankenengine_engine::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::entropy_evidence_compressor::{
    ArithmeticCoder, CompressionCertificate, EntropyEstimator,
};
use frankenengine_engine::observability_channel_model::{
    ChannelState, PayloadFamily, canonical_channel_specs,
    generate_report as generate_channel_report,
};
use frankenengine_engine::observability_probe_design::{
    CandidateProbe, MultiModeManifest, ProbeDomain, ProbeGranularity, ProbeUniverse,
};
use frankenengine_engine::observability_quality_sentinel::{
    DegradationRegime, DemotionTarget, ObservabilityQualitySentinel, QualityDimension,
    QualityObservation, canonical_demotion_policy, generate_report as generate_sentinel_report,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn probe_id(label: &str) -> EngineObjectId {
    let schema =
        SchemaId::from_definition(b"franken-engine.observability-channel-model.integration.v1");
    derive_id(
        ObjectDomain::EvidenceRecord,
        "tests.observability_channel_model",
        &schema,
        label.as_bytes(),
    )
    .expect("derive deterministic probe id")
}

fn add_probe(
    universe: &mut ProbeUniverse,
    name: &str,
    domain: ProbeDomain,
    utility_millionths: i64,
    latency_micros: u64,
    memory_bytes: u64,
    events: &[&str],
) {
    let probe = CandidateProbe {
        id: probe_id(name),
        name: name.to_string(),
        domain,
        granularity: ProbeGranularity::Medium,
        forensic_utility_millionths: utility_millionths,
        latency_overhead_micros: latency_micros,
        memory_overhead_bytes: memory_bytes,
        covers_events: events.iter().map(|event| (*event).to_string()).collect(),
        metadata: BTreeMap::new(),
    };
    universe.add_probe(probe).expect("add probe to universe");
}

fn probe_universe() -> ProbeUniverse {
    let mut universe = ProbeUniverse::new();
    add_probe(
        &mut universe,
        "compiler_frontier_probe",
        ProbeDomain::Compiler,
        900_000,
        120,
        2_048,
        &["compile_start", "compile_end", "ir_emit"],
    );
    add_probe(
        &mut universe,
        "runtime_guardplane_probe",
        ProbeDomain::Runtime,
        880_000,
        150,
        2_048,
        &["decision_start", "decision_end", "policy_violation"],
    );
    add_probe(
        &mut universe,
        "evidence_chain_probe",
        ProbeDomain::EvidencePipeline,
        860_000,
        90,
        1_536,
        &["artifact_write", "artifact_hash", "artifact_publish"],
    );
    add_probe(
        &mut universe,
        "governance_audit_probe",
        ProbeDomain::Governance,
        910_000,
        130,
        2_560,
        &["policy_gate", "demotion_receipt", "replay_request"],
    );
    universe
}

#[test]
fn canonical_specs_cover_required_families_and_fail_closed_on_lossy_replay() {
    let specs = canonical_channel_specs();
    let families: BTreeSet<PayloadFamily> = specs.iter().map(|spec| spec.family).collect();

    assert_eq!(families.len(), 5);
    assert!(families.contains(&PayloadFamily::Decision));
    assert!(families.contains(&PayloadFamily::Replay));
    assert!(families.contains(&PayloadFamily::Optimization));
    assert!(families.contains(&PayloadFamily::Security));
    assert!(families.contains(&PayloadFamily::LegalProvenance));

    let replay_spec = specs
        .iter()
        .find(|spec| spec.family == PayloadFamily::Replay)
        .expect("replay channel spec");
    assert!(!replay_spec.lossy_permitted);
    assert_eq!(replay_spec.envelope.max_distortion_millionths, 0);

    let epoch = SecurityEpoch::from_raw(17);
    let mut replay_state = ChannelState::new(replay_spec.channel_id.clone(), epoch);
    replay_state
        .emit(replay_spec, 1)
        .expect_err("replay channel must fail closed on any lossy emission");

    let mut states = BTreeMap::new();
    states.insert(replay_spec.channel_id.clone(), replay_state);
    let report = generate_channel_report(&specs, &states, epoch);

    assert!(!report.gate_pass);
    assert!(report.total_violations >= 1);
}

#[test]
fn multi_mode_manifest_is_deterministic_and_incident_mode_expands_coverage() {
    let universe = probe_universe();
    let manifest_a = MultiModeManifest::build(&universe);
    let manifest_b = MultiModeManifest::build(&universe);

    assert_eq!(manifest_a.manifest_hash, manifest_b.manifest_hash);
    assert!(manifest_a.normal_schedule.within_budget);
    assert!(manifest_a.degraded_schedule.within_budget);
    assert!(manifest_a.incident_schedule.within_budget);
    assert!(
        manifest_a.incident_schedule.event_coverage_millionths
            >= manifest_a.normal_schedule.event_coverage_millionths
    );
    assert!(manifest_a.incident_schedule.probe_count() >= manifest_a.normal_schedule.probe_count());
}

#[test]
fn entropy_certificate_and_quality_sentinel_fail_closed_in_fidelity_emergency() {
    let mut estimator = EntropyEstimator::new();
    let symbols: Vec<u32> = (0..420).map(|index| (index % 7) as u32).collect();
    for symbol in &symbols {
        estimator.observe(*symbol);
    }

    let coder = ArithmeticCoder::from_estimator(&estimator).expect("build arithmetic coder");
    let compressed = coder.encode(&symbols).expect("encode symbols");
    let kraft_sum = coder
        .verify_kraft_inequality()
        .expect("verify kraft inequality");
    let certificate = CompressionCertificate::build(&estimator, &compressed, kraft_sum);

    assert!(certificate.kraft_satisfied);
    assert!(certificate.shannon_lower_bound_bits > 0);
    assert!(certificate.achieved_bits > 0);
    assert!(
        certificate.is_within_factor(8_000_000),
        "compression should remain within an 8x bound of the Shannon lower bound",
    );

    let policy = canonical_demotion_policy(SecurityEpoch::from_raw(23));
    let mut sentinel = ObservabilityQualitySentinel::new(policy);
    let mut saw_replay_demotion = false;

    let baseline = QualityObservation {
        dimension: QualityDimension::SignalFidelity,
        value_millionths: 950_000,
        timestamp_ns: 1_000,
        channel_id: "ch-replay-verifier".to_string(),
    };
    sentinel.observe(&baseline);

    for step in 0..14u64 {
        let low_fidelity = QualityObservation {
            dimension: QualityDimension::SignalFidelity,
            value_millionths: 300_000,
            timestamp_ns: 2_000 + step,
            channel_id: "ch-replay-verifier".to_string(),
        };
        let (_artifacts, receipts) = sentinel.observe(&low_fidelity);
        if receipts
            .iter()
            .any(|receipt| receipt.new_mode == DemotionTarget::FullReplayCapture)
        {
            saw_replay_demotion = true;
        }
    }

    assert!(
        saw_replay_demotion,
        "fidelity emergency should trigger full replay capture demotion",
    );

    let report = generate_sentinel_report(&sentinel);
    assert_eq!(report.overall_regime, DegradationRegime::Emergency);
    assert!(!report.gate_pass);
}

// ────────────────────────────────────────────────────────────
// Enrichment: channel state emit/drain/drop, report generation,
// epoch resets, cross-channel interaction, canonical specs
// ────────────────────────────────────────────────────────────

use frankenengine_engine::observability_channel_model::{
    ChannelPath, ChannelReport, ChannelSpec, DistortionMetric, FailureBudget, PolicyViolation,
    RateDistortionEnvelope, RateDistortionPoint, ViolationKind, canonical_risk_ledgers,
};

fn lossy_spec(channel_id: &str) -> ChannelSpec {
    ChannelSpec {
        channel_id: channel_id.to_string(),
        family: PayloadFamily::Optimization,
        path: ChannelPath::RuntimeToLedger,
        envelope: RateDistortionEnvelope {
            family: PayloadFamily::Optimization,
            metric: DistortionMetric::SquaredError,
            frontier: vec![
                RateDistortionPoint {
                    distortion_millionths: 0,
                    rate_millibits: 1_000_000,
                },
                RateDistortionPoint {
                    distortion_millionths: 500_000,
                    rate_millibits: 500_000,
                },
            ],
            max_distortion_millionths: 500_000,
            min_rate_millibits: 100_000,
        },
        failure_budget: FailureBudget {
            max_drops_per_epoch: 3,
            max_degraded_per_epoch: 5,
            degradation_threshold_millionths: 200_000,
            fail_closed: true,
        },
        max_items_per_epoch: 10,
        buffer_capacity: 4,
        lossy_permitted: true,
        tags: vec![],
    }
}

fn lossless_spec(channel_id: &str) -> ChannelSpec {
    ChannelSpec {
        channel_id: channel_id.to_string(),
        family: PayloadFamily::Replay,
        path: ChannelPath::RuntimeToLedger,
        envelope: RateDistortionEnvelope {
            family: PayloadFamily::Replay,
            metric: DistortionMetric::Hamming,
            frontier: vec![RateDistortionPoint {
                distortion_millionths: 0,
                rate_millibits: 1_000_000,
            }],
            max_distortion_millionths: 0,
            min_rate_millibits: 1_000_000,
        },
        failure_budget: FailureBudget {
            max_drops_per_epoch: 0,
            max_degraded_per_epoch: 0,
            degradation_threshold_millionths: 0,
            fail_closed: true,
        },
        max_items_per_epoch: 100,
        buffer_capacity: 50,
        lossy_permitted: false,
        tags: vec![],
    }
}

#[test]
fn emit_drain_cycle_maintains_consistent_buffer_usage() {
    let spec = lossy_spec("ch-emit-drain");
    let epoch = SecurityEpoch::from_raw(1);
    let mut state = ChannelState::new("ch-emit-drain".to_string(), epoch);

    for _ in 0..4 {
        state.emit(&spec, 0).expect("emit within buffer");
    }
    assert_eq!(state.buffer_used, 4);
    assert_eq!(state.items_emitted, 4);

    state.drain_one();
    state.drain_one();
    assert_eq!(state.buffer_used, 2);

    state.emit(&spec, 0).expect("emit after drain");
    assert_eq!(state.buffer_used, 3);
    assert_eq!(state.items_emitted, 5);
}

#[test]
fn backpressure_blocks_emit_when_buffer_is_full() {
    let spec = lossy_spec("ch-backpressure");
    let epoch = SecurityEpoch::from_raw(1);
    let mut state = ChannelState::new("ch-backpressure".to_string(), epoch);

    for _ in 0..4 {
        state.emit(&spec, 0).expect("fill buffer");
    }

    let err = state.emit(&spec, 0).expect_err("buffer full should reject");
    assert_eq!(err.violation_kind, ViolationKind::BackpressureOverflow);
    assert_eq!(state.violations.len(), 1);

    state.drain_one();
    state
        .emit(&spec, 0)
        .expect("emit after drain relieves backpressure");
    assert_eq!(state.items_emitted, 5);
}

#[test]
fn rate_cap_blocks_emit_after_max_items_reached() {
    let spec = lossy_spec("ch-rate-cap");
    let epoch = SecurityEpoch::from_raw(1);
    let mut state = ChannelState::new("ch-rate-cap".to_string(), epoch);

    for _ in 0..10 {
        state.emit(&spec, 0).expect("emit within cap");
        state.drain_one();
    }

    let err = state
        .emit(&spec, 0)
        .expect_err("rate cap exceeded should reject");
    assert_eq!(err.violation_kind, ViolationKind::UncappedTelemetry);
}

#[test]
fn lossless_channel_rejects_any_distortion() {
    let spec = lossless_spec("ch-lossless");
    let epoch = SecurityEpoch::from_raw(1);
    let mut state = ChannelState::new("ch-lossless".to_string(), epoch);

    state.emit(&spec, 0).expect("zero distortion is ok");

    let err = state
        .emit(&spec, 1)
        .expect_err("any distortion on lossless channel should fail");
    assert_eq!(err.violation_kind, ViolationKind::UnverifiableLoss);
}

#[test]
fn drop_budget_exceeded_triggers_violation() {
    let spec = lossy_spec("ch-drops");
    let epoch = SecurityEpoch::from_raw(1);
    let mut state = ChannelState::new("ch-drops".to_string(), epoch);

    for _ in 0..3 {
        state.record_drop(&spec).expect("drop within budget");
    }
    assert!(state.violations.is_empty());

    let err = state
        .record_drop(&spec)
        .expect_err("drop budget exceeded (fail_closed)");
    assert_eq!(err.violation_kind, ViolationKind::DropBudgetExceeded);
}

#[test]
fn epoch_reset_clears_all_counters_and_violations() {
    let spec = lossy_spec("ch-epoch");
    let epoch = SecurityEpoch::from_raw(1);
    let mut state = ChannelState::new("ch-epoch".to_string(), epoch);

    state.emit(&spec, 0).expect("emit");
    state.record_drop(&spec).expect("drop");
    state.emit(&spec, 300_000).expect("degraded emit");
    assert!(state.items_emitted > 0);
    assert!(state.items_dropped > 0);
    assert!(state.items_degraded > 0);

    state.epoch_reset(SecurityEpoch::from_raw(2));
    assert_eq!(state.epoch, SecurityEpoch::from_raw(2));
    assert_eq!(state.items_emitted, 0);
    assert_eq!(state.items_dropped, 0);
    assert_eq!(state.items_degraded, 0);
    assert_eq!(state.buffer_used, 0);
    assert!(state.violations.is_empty());
    assert!(state.is_healthy(&spec));
}

#[test]
fn report_marks_gate_pass_when_all_channels_healthy() {
    let specs = vec![lossy_spec("ch-a"), lossy_spec("ch-b")];
    let epoch = SecurityEpoch::from_raw(5);
    let mut states = BTreeMap::new();

    let mut state_a = ChannelState::new("ch-a".to_string(), epoch);
    state_a.emit(&specs[0], 0).expect("emit a");
    states.insert("ch-a".to_string(), state_a);

    let mut state_b = ChannelState::new("ch-b".to_string(), epoch);
    state_b.emit(&specs[1], 0).expect("emit b");
    states.insert("ch-b".to_string(), state_b);

    let report = generate_channel_report(&specs, &states, epoch);
    assert!(report.gate_pass);
    assert_eq!(report.total_violations, 0);
    assert_eq!(report.channels.len(), 2);
    assert!(report.channels.iter().all(|ch| ch.healthy));
    assert!(report.summary.contains("PASS"));
}

#[test]
fn report_fails_gate_when_any_channel_has_violations() {
    let spec = lossy_spec("ch-unhealthy");
    let epoch = SecurityEpoch::from_raw(3);

    let mut state = ChannelState::new("ch-unhealthy".to_string(), epoch);
    for _ in 0..4 {
        state.emit(&spec, 0).expect("fill buffer");
    }
    let _err = state.emit(&spec, 0);

    let mut states = BTreeMap::new();
    states.insert("ch-unhealthy".to_string(), state);

    let report = generate_channel_report(&[spec], &states, epoch);
    assert!(!report.gate_pass);
    assert!(report.total_violations >= 1);
    assert!(report.summary.contains("FAIL"));
}

#[test]
fn report_with_no_state_for_a_spec_defaults_to_healthy() {
    let specs = vec![lossy_spec("ch-no-state")];
    let states = BTreeMap::new();
    let epoch = SecurityEpoch::from_raw(1);

    let report = generate_channel_report(&specs, &states, epoch);
    assert!(report.gate_pass);
    assert_eq!(report.channels.len(), 1);
    assert!(report.channels[0].healthy);
    assert_eq!(report.channels[0].items_emitted, 0);
}

#[test]
fn report_epoch_is_propagated_to_output() {
    let specs = canonical_channel_specs();
    let states = BTreeMap::new();
    let epoch = SecurityEpoch::from_raw(42);

    let report = generate_channel_report(&specs, &states, epoch);
    assert_eq!(report.epoch, SecurityEpoch::from_raw(42));
    assert!(!report.content_hash.is_empty());
}

#[test]
fn report_content_hash_is_deterministic() {
    let specs = canonical_channel_specs();
    let states = BTreeMap::new();
    let epoch = SecurityEpoch::from_raw(10);

    let report_a = generate_channel_report(&specs, &states, epoch);
    let report_b = generate_channel_report(&specs, &states, epoch);
    assert_eq!(report_a.content_hash, report_b.content_hash);
}

#[test]
fn canonical_specs_all_have_nonempty_channel_id_and_valid_envelope() {
    let specs = canonical_channel_specs();
    assert!(specs.len() >= 5, "at least one spec per family");

    for spec in &specs {
        assert!(!spec.channel_id.is_empty());
        assert!(spec.max_items_per_epoch > 0);
        assert!(spec.buffer_capacity > 0);
        assert!(!spec.envelope.frontier.is_empty());
        assert!(
            spec.envelope.frontier[0].distortion_millionths
                <= spec.envelope.max_distortion_millionths
        );
    }
}

#[test]
fn canonical_risk_ledgers_are_nonempty_with_valid_entries() {
    let ledgers = canonical_risk_ledgers();
    assert!(!ledgers.is_empty());

    for ledger in &ledgers {
        assert!(!ledger.entries.is_empty());
        for entry in &ledger.entries {
            assert!(entry.risk_millionths >= 0);
        }
    }
}

#[test]
fn channel_report_serde_roundtrip() {
    let specs = canonical_channel_specs();
    let states = BTreeMap::new();
    let epoch = SecurityEpoch::from_raw(7);

    let report = generate_channel_report(&specs, &states, epoch);
    let json = serde_json::to_string(&report).expect("serialize report");
    let recovered: ChannelReport = serde_json::from_str(&json).expect("deserialize report");
    assert_eq!(report, recovered);
}

#[test]
fn utilization_increases_with_emissions() {
    let spec = lossy_spec("ch-util");
    let epoch = SecurityEpoch::from_raw(1);
    let mut state = ChannelState::new("ch-util".to_string(), epoch);

    let mut states = BTreeMap::new();
    states.insert("ch-util".to_string(), state.clone());
    let report_before = generate_channel_report(std::slice::from_ref(&spec), &states, epoch);
    let util_before = report_before.channels[0].utilization_millionths;

    for _ in 0..5 {
        state.emit(&spec, 0).expect("emit");
        state.drain_one();
    }

    states.insert("ch-util".to_string(), state);
    let report_after = generate_channel_report(&[spec], &states, epoch);
    let util_after = report_after.channels[0].utilization_millionths;

    assert!(util_after > util_before);
}

// ────────────────────────────────────────────────────────────
// Enrichment batch 8: enum serde/Display, envelope methods,
// risk ledger, violation kind, constants, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn schema_version_constant_is_stable() {
    use frankenengine_engine::observability_channel_model::SCHEMA_VERSION;
    assert_eq!(SCHEMA_VERSION, "franken-engine.observability-channel.v1");
}

#[test]
fn payload_family_all_has_five_elements() {
    assert_eq!(PayloadFamily::ALL.len(), 5);
}

#[test]
fn payload_family_serde_round_trip() {
    for family in PayloadFamily::ALL {
        let json = serde_json::to_string(&family).expect("serialize");
        let recovered: PayloadFamily = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(family, recovered);
    }
}

#[test]
fn payload_family_display_all_unique() {
    let displays: BTreeSet<String> = PayloadFamily::ALL.iter().map(|f| f.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn distortion_metric_serde_round_trip() {
    let metrics = [
        DistortionMetric::Hamming,
        DistortionMetric::SquaredError,
        DistortionMetric::LogLoss,
        DistortionMetric::EditDistance,
        DistortionMetric::BinaryFidelity,
    ];
    for metric in metrics {
        let json = serde_json::to_string(&metric).expect("serialize");
        let recovered: DistortionMetric = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(metric, recovered);
    }
}

#[test]
fn distortion_metric_display_all_unique() {
    let metrics = [
        DistortionMetric::Hamming,
        DistortionMetric::SquaredError,
        DistortionMetric::LogLoss,
        DistortionMetric::EditDistance,
        DistortionMetric::BinaryFidelity,
    ];
    let displays: BTreeSet<String> = metrics.iter().map(|m| m.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn channel_path_all_has_five_elements() {
    assert_eq!(ChannelPath::ALL.len(), 5);
}

#[test]
fn channel_path_serde_round_trip() {
    for path in ChannelPath::ALL {
        let json = serde_json::to_string(&path).expect("serialize");
        let recovered: ChannelPath = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(path, recovered);
    }
}

#[test]
fn channel_path_display_all_unique() {
    let displays: BTreeSet<String> = ChannelPath::ALL.iter().map(|p| p.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn violation_kind_serde_round_trip() {
    let kinds = [
        ViolationKind::UncappedTelemetry,
        ViolationKind::UnverifiableLoss,
        ViolationKind::DropBudgetExceeded,
        ViolationKind::DegradationBudgetExceeded,
        ViolationKind::BackpressureOverflow,
    ];
    for kind in kinds {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: ViolationKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(kind, recovered);
    }
}

#[test]
fn violation_kind_display_all_unique() {
    let kinds = [
        ViolationKind::UncappedTelemetry,
        ViolationKind::UnverifiableLoss,
        ViolationKind::DropBudgetExceeded,
        ViolationKind::DegradationBudgetExceeded,
        ViolationKind::BackpressureOverflow,
    ];
    let displays: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn rate_distortion_envelope_rate_at_distortion_interpolates() {
    let envelope = RateDistortionEnvelope {
        family: PayloadFamily::Optimization,
        metric: DistortionMetric::SquaredError,
        frontier: vec![
            RateDistortionPoint {
                distortion_millionths: 0,
                rate_millibits: 1_000_000,
            },
            RateDistortionPoint {
                distortion_millionths: 500_000,
                rate_millibits: 500_000,
            },
        ],
        max_distortion_millionths: 500_000,
        min_rate_millibits: 100_000,
    };

    // At zero distortion, rate should be 1_000_000
    assert_eq!(envelope.rate_at_distortion(0), Some(1_000_000));
    // At max distortion, rate should be 500_000
    assert_eq!(envelope.rate_at_distortion(500_000), Some(500_000));
    // Midpoint should interpolate to ~750_000
    assert_eq!(envelope.rate_at_distortion(250_000), Some(750_000));
    // Beyond max distortion returns None
    assert_eq!(envelope.rate_at_distortion(500_001), None);
}

#[test]
fn rate_distortion_envelope_empty_frontier_returns_none() {
    let envelope = RateDistortionEnvelope {
        family: PayloadFamily::Decision,
        metric: DistortionMetric::Hamming,
        frontier: vec![],
        max_distortion_millionths: 100_000,
        min_rate_millibits: 0,
    };
    assert_eq!(envelope.rate_at_distortion(0), None);
}

#[test]
fn rate_distortion_envelope_is_achievable() {
    let envelope = RateDistortionEnvelope {
        family: PayloadFamily::Optimization,
        metric: DistortionMetric::SquaredError,
        frontier: vec![
            RateDistortionPoint {
                distortion_millionths: 0,
                rate_millibits: 1_000_000,
            },
            RateDistortionPoint {
                distortion_millionths: 500_000,
                rate_millibits: 500_000,
            },
        ],
        max_distortion_millionths: 500_000,
        min_rate_millibits: 100_000,
    };

    // At zero distortion, rate 1M is achievable
    assert!(envelope.is_achievable(1_000_000, 0));
    // At zero distortion, rate below min is not achievable
    assert!(!envelope.is_achievable(500_000, 0));
    // Beyond max distortion is never achievable
    assert!(!envelope.is_achievable(2_000_000, 600_000));
}

#[test]
fn risk_ledger_risk_at_distortion_returns_closest_entry() {
    let ledgers = canonical_risk_ledgers();
    // Just verify it returns a non-negative value for 0 distortion
    for ledger in &ledgers {
        let risk = ledger.risk_at_distortion(0);
        assert!(risk >= 0);
    }
}

#[test]
fn channel_state_is_healthy_when_no_violations() {
    let spec = lossy_spec("ch-healthy-check");
    let epoch = SecurityEpoch::from_raw(1);
    let state = ChannelState::new("ch-healthy-check".to_string(), epoch);
    assert!(state.is_healthy(&spec));
}

#[test]
fn channel_state_is_not_healthy_after_violation() {
    let spec = lossy_spec("ch-unhealthy-check");
    let epoch = SecurityEpoch::from_raw(1);
    let mut state = ChannelState::new("ch-unhealthy-check".to_string(), epoch);

    // Fill buffer to trigger backpressure overflow
    for _ in 0..4 {
        state.emit(&spec, 0).expect("fill buffer");
    }
    let _ = state.emit(&spec, 0); // triggers violation
    assert!(!state.is_healthy(&spec));
}

#[test]
fn channel_state_serde_round_trip() {
    let spec = lossy_spec("ch-state-serde");
    let epoch = SecurityEpoch::from_raw(5);
    let mut state = ChannelState::new("ch-state-serde".to_string(), epoch);
    state.emit(&spec, 0).expect("emit");

    let json = serde_json::to_string(&state).expect("serialize");
    let recovered: ChannelState = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(state, recovered);
}

#[test]
fn channel_spec_serde_round_trip() {
    let spec = lossy_spec("ch-spec-serde");
    let json = serde_json::to_string(&spec).expect("serialize");
    let recovered: ChannelSpec = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(spec, recovered);
}

#[test]
fn policy_violation_serde_round_trip() {
    let violation = PolicyViolation {
        channel_id: "ch-viol".to_string(),
        epoch: SecurityEpoch::from_raw(3),
        violation_kind: ViolationKind::DropBudgetExceeded,
        detail: "drop budget exceeded at item 4".to_string(),
    };
    let json = serde_json::to_string(&violation).expect("serialize");
    let recovered: PolicyViolation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(violation, recovered);
}
