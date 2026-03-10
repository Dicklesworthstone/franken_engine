#![forbid(unsafe_code)]
//! Integration tests for the `parallel_interference_gate` module.
//!
//! Covers: interference taxonomy enums, witness/transcript comparison,
//! flake-rate measurement, gate configuration, gate evaluation,
//! operator summary, replay bundles, rollback integration, serde
//! round-trips, determinism, and cross-concern integration scenarios.

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

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::parallel_interference_gate::{
    self, COMPONENT, DEFAULT_FLAKE_THRESHOLD_MILLIONTHS, DEFAULT_MAX_WORKER_VARIATIONS,
    DEFAULT_REPEATS_PER_SEED, DEFAULT_SEED_COUNT, FlakeRate, GateConfig, GateDecision, GateResult,
    InterferenceClass, InterferenceIncident, InterferenceSeverity, OperatorSummary, ReplayBundle,
    RootCauseHint, RunRecord, SCHEMA_VERSION, WitnessDiff, WitnessDiffEntry,
};
use frankenengine_engine::parallel_parser::{
    MergeWitness, ParallelConfig, ParserMode, RollbackControl, ScheduleDispatch, ScheduleTranscript,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_source() -> String {
    let mut source = String::new();
    for i in 0..50 {
        source.push_str(&format!("var x{} = {};\n", i, i));
    }
    source
}

fn small_gate_config() -> GateConfig {
    GateConfig {
        seed_count: 3,
        repeats_per_seed: 2,
        flake_threshold_millionths: 0,
        worker_variations: vec![2, 4],
        base_config: ParallelConfig {
            min_parallel_bytes: 10,
            always_check_parity: true,
            ..ParallelConfig::default()
        },
        require_serial_parity: true,
    }
}

fn make_transcript(
    seed: u64,
    worker_count: u32,
    plan_hash: ContentHash,
    execution_order: Vec<u32>,
) -> ScheduleTranscript {
    let dispatches: Vec<ScheduleDispatch> = execution_order
        .iter()
        .enumerate()
        .map(|(step_index, chunk_index)| ScheduleDispatch {
            step_index: step_index as u32,
            chunk_index: *chunk_index,
            worker_slot: if worker_count == 0 {
                0
            } else {
                (step_index as u32) % worker_count
            },
        })
        .collect();

    let mut payload = format!("{seed}:{worker_count}:{}:", plan_hash.to_hex());
    for chunk_index in &execution_order {
        payload.push_str(&format!("{chunk_index},"));
    }
    for dispatch in &dispatches {
        payload.push_str(&format!(
            "{}:{}:{},",
            dispatch.step_index, dispatch.chunk_index, dispatch.worker_slot
        ));
    }
    let transcript_hash = ContentHash::compute(payload.as_bytes());

    ScheduleTranscript {
        seed,
        worker_count,
        plan_hash,
        execution_order,
        dispatches,
        transcript_hash,
    }
}

fn make_incident(
    class: InterferenceClass,
    severity: InterferenceSeverity,
    seed: u64,
    worker_count: u32,
) -> InterferenceIncident {
    InterferenceIncident {
        class,
        severity,
        seed,
        worker_count,
        run_index: 0,
        expected_hash: ContentHash::compute(b"expected"),
        actual_hash: ContentHash::compute(b"actual"),
        mismatch_token_index: None,
        triage_hint: format!("test hint seed={}", seed),
        remediation_playbook_id: format!("playbook.interference.{}", class),
        replay_command: format!(
            "franken-engine parallel-parse --workers {} --seed {}",
            worker_count, seed
        ),
    }
}

fn make_gate_result_with_incidents(incidents: Vec<InterferenceIncident>) -> GateResult {
    let mismatched = incidents.len() as u64;
    let total_runs = 12;
    let flake_rate = FlakeRate::compute(total_runs, mismatched, 0);
    let decision = if incidents
        .iter()
        .any(|i| i.severity == InterferenceSeverity::Critical)
    {
        GateDecision::Reject
    } else if !incidents.is_empty() {
        GateDecision::Hold
    } else {
        GateDecision::Promote
    };
    GateResult {
        schema_version: SCHEMA_VERSION.to_string(),
        decision,
        rationale: "synthetic".to_string(),
        runs: Vec::new(),
        incidents,
        flake_rate,
        reference_hash: ContentHash::compute(b"ref"),
        seeds_tested: vec![0, 1, 2],
        workers_tested: vec![2, 4],
        total_runs,
        input_hash: ContentHash::compute(b"input"),
        input_bytes: 100,
    }
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn constants_have_expected_values() {
    assert_eq!(COMPONENT, "parallel_interference_gate");
    assert_eq!(
        SCHEMA_VERSION,
        "franken-engine.parallel-interference-gate.v1"
    );
    assert_eq!(DEFAULT_SEED_COUNT, 10);
    assert_eq!(DEFAULT_REPEATS_PER_SEED, 3);
    assert_eq!(DEFAULT_FLAKE_THRESHOLD_MILLIONTHS, 0);
    assert_eq!(DEFAULT_MAX_WORKER_VARIATIONS, 4);
}

// ===========================================================================
// 2. InterferenceClass enum
// ===========================================================================

#[test]
fn interference_class_all_variants_display() {
    let cases = [
        (InterferenceClass::MergeOrder, "merge-order"),
        (InterferenceClass::Scheduler, "scheduler"),
        (
            InterferenceClass::DataStructureIteration,
            "data-structure-iteration",
        ),
        (InterferenceClass::ArtifactPipeline, "artifact-pipeline"),
        (InterferenceClass::TimeoutRace, "timeout-race"),
        (InterferenceClass::BackpressureDrift, "backpressure-drift"),
    ];
    for (variant, expected) in cases {
        assert_eq!(variant.to_string(), expected);
    }
}

#[test]
fn interference_class_serde_roundtrip_all_variants() {
    let variants = [
        InterferenceClass::MergeOrder,
        InterferenceClass::Scheduler,
        InterferenceClass::DataStructureIteration,
        InterferenceClass::ArtifactPipeline,
        InterferenceClass::TimeoutRace,
        InterferenceClass::BackpressureDrift,
    ];
    for v in variants {
        let json = serde_json::to_string(&v).unwrap();
        let back: InterferenceClass = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back, "serde roundtrip failed for {:?}", v);
    }
}

#[test]
fn interference_class_ordering_total() {
    assert!(InterferenceClass::MergeOrder < InterferenceClass::Scheduler);
    assert!(InterferenceClass::Scheduler < InterferenceClass::DataStructureIteration);
    assert!(InterferenceClass::DataStructureIteration < InterferenceClass::ArtifactPipeline);
    assert!(InterferenceClass::ArtifactPipeline < InterferenceClass::TimeoutRace);
    assert!(InterferenceClass::TimeoutRace < InterferenceClass::BackpressureDrift);
}

#[test]
fn interference_class_clone_eq() {
    let a = InterferenceClass::MergeOrder;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn interference_class_debug_format() {
    let dbg = format!("{:?}", InterferenceClass::BackpressureDrift);
    assert!(dbg.contains("BackpressureDrift"));
}

// ===========================================================================
// 3. InterferenceSeverity enum
// ===========================================================================

#[test]
fn interference_severity_all_variants_display() {
    assert_eq!(InterferenceSeverity::Info.to_string(), "info");
    assert_eq!(InterferenceSeverity::Warning.to_string(), "warning");
    assert_eq!(InterferenceSeverity::Critical.to_string(), "critical");
}

#[test]
fn interference_severity_serde_roundtrip() {
    for v in [
        InterferenceSeverity::Info,
        InterferenceSeverity::Warning,
        InterferenceSeverity::Critical,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: InterferenceSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn interference_severity_ordering_total() {
    assert!(InterferenceSeverity::Info < InterferenceSeverity::Warning);
    assert!(InterferenceSeverity::Warning < InterferenceSeverity::Critical);
    // Transitive
    assert!(InterferenceSeverity::Info < InterferenceSeverity::Critical);
}

#[test]
fn interference_severity_clone_eq() {
    let a = InterferenceSeverity::Warning;
    let b = a;
    assert_eq!(a, b);
}

// ===========================================================================
// 4. InterferenceIncident struct
// ===========================================================================

#[test]
fn interference_incident_construction_and_fields() {
    let incident = make_incident(
        InterferenceClass::Scheduler,
        InterferenceSeverity::Warning,
        7,
        4,
    );
    assert_eq!(incident.class, InterferenceClass::Scheduler);
    assert_eq!(incident.severity, InterferenceSeverity::Warning);
    assert_eq!(incident.seed, 7);
    assert_eq!(incident.worker_count, 4);
    assert_eq!(incident.run_index, 0);
    assert!(incident.mismatch_token_index.is_none());
    assert!(incident.triage_hint.contains("seed=7"));
    assert!(incident.remediation_playbook_id.contains("scheduler"));
    assert!(incident.replay_command.contains("--workers 4"));
}

#[test]
fn interference_incident_with_mismatch_index() {
    let mut incident = make_incident(
        InterferenceClass::MergeOrder,
        InterferenceSeverity::Critical,
        1,
        8,
    );
    incident.mismatch_token_index = Some(42);
    assert_eq!(incident.mismatch_token_index, Some(42));
}

#[test]
fn interference_incident_serde_roundtrip() {
    let incident = InterferenceIncident {
        class: InterferenceClass::TimeoutRace,
        severity: InterferenceSeverity::Info,
        seed: 99,
        worker_count: 2,
        run_index: 3,
        expected_hash: ContentHash::compute(b"exp"),
        actual_hash: ContentHash::compute(b"act"),
        mismatch_token_index: Some(10),
        triage_hint: "timeout triggered".to_string(),
        remediation_playbook_id: "playbook.interference.timeout-race".to_string(),
        replay_command: "replay --seed 99".to_string(),
    };
    let json = serde_json::to_string(&incident).unwrap();
    let back: InterferenceIncident = serde_json::from_str(&json).unwrap();
    assert_eq!(incident, back);
}

#[test]
fn interference_incident_serde_no_mismatch_index() {
    let incident = make_incident(
        InterferenceClass::ArtifactPipeline,
        InterferenceSeverity::Warning,
        0,
        2,
    );
    let json = serde_json::to_string(&incident).unwrap();
    let back: InterferenceIncident = serde_json::from_str(&json).unwrap();
    assert_eq!(incident, back);
    assert!(back.mismatch_token_index.is_none());
}

// ===========================================================================
// 5. WitnessDiff / WitnessDiffEntry structs
// ===========================================================================

#[test]
fn witness_diff_entry_construction() {
    let entry = WitnessDiffEntry {
        field: "chunk_count".to_string(),
        expected: "3".to_string(),
        actual: "4".to_string(),
    };
    assert_eq!(entry.field, "chunk_count");
    assert_eq!(entry.expected, "3");
    assert_eq!(entry.actual, "4");
}

#[test]
fn witness_diff_entry_serde_roundtrip() {
    let entry = WitnessDiffEntry {
        field: "total_tokens".to_string(),
        expected: "50".to_string(),
        actual: "60".to_string(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: WitnessDiffEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn witness_diff_matching() {
    let diff = WitnessDiff {
        matches: true,
        diffs: Vec::new(),
    };
    assert!(diff.matches);
    assert!(diff.diffs.is_empty());
}

#[test]
fn witness_diff_not_matching() {
    let diff = WitnessDiff {
        matches: false,
        diffs: vec![WitnessDiffEntry {
            field: "merged_hash".to_string(),
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        }],
    };
    assert!(!diff.matches);
    assert_eq!(diff.diffs.len(), 1);
}

#[test]
fn witness_diff_serde_roundtrip() {
    let diff = WitnessDiff {
        matches: false,
        diffs: vec![
            WitnessDiffEntry {
                field: "f1".to_string(),
                expected: "a".to_string(),
                actual: "b".to_string(),
            },
            WitnessDiffEntry {
                field: "f2".to_string(),
                expected: "c".to_string(),
                actual: "d".to_string(),
            },
        ],
    };
    let json = serde_json::to_string(&diff).unwrap();
    let back: WitnessDiff = serde_json::from_str(&json).unwrap();
    assert_eq!(diff, back);
}

// ===========================================================================
// 6. compare_witnesses
// ===========================================================================

#[test]
fn compare_witnesses_identical() {
    let w = MergeWitness {
        merged_hash: ContentHash::compute(b"test"),
        witness_hash: ContentHash::compute(b"witness"),
        chunk_count: 4,
        boundary_repairs: 0,
        total_tokens: 100,
    };
    let diff = parallel_interference_gate::compare_witnesses(&w, &w);
    assert!(diff.matches);
    assert!(diff.diffs.is_empty());
}

#[test]
fn compare_witnesses_hash_only_mismatch() {
    let w1 = MergeWitness {
        merged_hash: ContentHash::compute(b"a"),
        witness_hash: ContentHash::compute(b"shared"),
        chunk_count: 3,
        boundary_repairs: 1,
        total_tokens: 50,
    };
    let w2 = MergeWitness {
        merged_hash: ContentHash::compute(b"b"),
        witness_hash: ContentHash::compute(b"shared"),
        chunk_count: 3,
        boundary_repairs: 1,
        total_tokens: 50,
    };
    let diff = parallel_interference_gate::compare_witnesses(&w1, &w2);
    assert!(!diff.matches);
    assert_eq!(diff.diffs.len(), 1);
    assert_eq!(diff.diffs[0].field, "merged_hash");
}

#[test]
fn compare_witnesses_chunk_count_mismatch() {
    let w1 = MergeWitness {
        merged_hash: ContentHash::compute(b"same"),
        witness_hash: ContentHash::compute(b"shared"),
        chunk_count: 3,
        boundary_repairs: 0,
        total_tokens: 50,
    };
    let w2 = MergeWitness {
        merged_hash: ContentHash::compute(b"same"),
        witness_hash: ContentHash::compute(b"shared"),
        chunk_count: 5,
        boundary_repairs: 0,
        total_tokens: 50,
    };
    let diff = parallel_interference_gate::compare_witnesses(&w1, &w2);
    assert!(!diff.matches);
    assert!(diff.diffs.iter().any(|d| d.field == "chunk_count"));
}

#[test]
fn compare_witnesses_boundary_repairs_mismatch() {
    let w1 = MergeWitness {
        merged_hash: ContentHash::compute(b"same"),
        witness_hash: ContentHash::compute(b"shared"),
        chunk_count: 3,
        boundary_repairs: 0,
        total_tokens: 50,
    };
    let w2 = MergeWitness {
        merged_hash: ContentHash::compute(b"same"),
        witness_hash: ContentHash::compute(b"shared"),
        chunk_count: 3,
        boundary_repairs: 2,
        total_tokens: 50,
    };
    let diff = parallel_interference_gate::compare_witnesses(&w1, &w2);
    assert!(!diff.matches);
    assert!(diff.diffs.iter().any(|d| d.field == "boundary_repairs"));
}

#[test]
fn compare_witnesses_total_tokens_mismatch() {
    let w1 = MergeWitness {
        merged_hash: ContentHash::compute(b"same"),
        witness_hash: ContentHash::compute(b"shared"),
        chunk_count: 3,
        boundary_repairs: 0,
        total_tokens: 50,
    };
    let w2 = MergeWitness {
        merged_hash: ContentHash::compute(b"same"),
        witness_hash: ContentHash::compute(b"shared"),
        chunk_count: 3,
        boundary_repairs: 0,
        total_tokens: 60,
    };
    let diff = parallel_interference_gate::compare_witnesses(&w1, &w2);
    assert!(!diff.matches);
    assert!(diff.diffs.iter().any(|d| d.field == "total_tokens"));
}

#[test]
fn compare_witnesses_all_fields_differ() {
    let w1 = MergeWitness {
        merged_hash: ContentHash::compute(b"a"),
        witness_hash: ContentHash::compute(b"wa"),
        chunk_count: 1,
        boundary_repairs: 0,
        total_tokens: 10,
    };
    let w2 = MergeWitness {
        merged_hash: ContentHash::compute(b"b"),
        witness_hash: ContentHash::compute(b"wb"),
        chunk_count: 2,
        boundary_repairs: 3,
        total_tokens: 40,
    };
    let diff = parallel_interference_gate::compare_witnesses(&w1, &w2);
    assert!(!diff.matches);
    assert_eq!(diff.diffs.len(), 5);
}

// ===========================================================================
// 7. compare_transcripts
// ===========================================================================

#[test]
fn compare_transcripts_identical() {
    let t = make_transcript(42, 4, ContentHash::compute(b"plan"), vec![0, 1, 2, 3]);
    let diff = parallel_interference_gate::compare_transcripts(&t, &t);
    assert!(diff.matches);
    assert!(diff.diffs.is_empty());
}

#[test]
fn compare_transcripts_seed_differs() {
    let t1 = make_transcript(1, 4, ContentHash::compute(b"plan"), vec![0, 1, 2]);
    let t2 = ScheduleTranscript {
        seed: 2,
        ..t1.clone()
    };
    let diff = parallel_interference_gate::compare_transcripts(&t1, &t2);
    assert!(!diff.matches);
    assert!(diff.diffs.iter().any(|d| d.field == "seed"));
}

#[test]
fn compare_transcripts_worker_count_differs() {
    let t1 = make_transcript(1, 4, ContentHash::compute(b"plan"), vec![0, 1]);
    let t2 = ScheduleTranscript {
        worker_count: 8,
        ..t1.clone()
    };
    let diff = parallel_interference_gate::compare_transcripts(&t1, &t2);
    assert!(!diff.matches);
    assert!(diff.diffs.iter().any(|d| d.field == "worker_count"));
}

#[test]
fn compare_transcripts_plan_hash_differs() {
    let t1 = make_transcript(1, 4, ContentHash::compute(b"plan_a"), vec![0, 1]);
    let t2 = ScheduleTranscript {
        plan_hash: ContentHash::compute(b"plan_b"),
        ..t1.clone()
    };
    let diff = parallel_interference_gate::compare_transcripts(&t1, &t2);
    assert!(!diff.matches);
    assert!(diff.diffs.iter().any(|d| d.field == "plan_hash"));
}

#[test]
fn compare_transcripts_execution_order_differs() {
    let t1 = make_transcript(1, 4, ContentHash::compute(b"plan"), vec![0, 1, 2]);
    let t2 = ScheduleTranscript {
        execution_order: vec![2, 1, 0],
        ..t1.clone()
    };
    let diff = parallel_interference_gate::compare_transcripts(&t1, &t2);
    assert!(!diff.matches);
    assert!(diff.diffs.iter().any(|d| d.field == "execution_order"));
}

#[test]
fn compare_transcripts_all_fields_differ() {
    let t1 = make_transcript(1, 2, ContentHash::compute(b"a"), vec![0]);
    let t2 = make_transcript(9, 8, ContentHash::compute(b"b"), vec![1, 0]);
    let diff = parallel_interference_gate::compare_transcripts(&t1, &t2);
    assert!(!diff.matches);
    assert_eq!(diff.diffs.len(), 6);
}

// ===========================================================================
// 8. FlakeRate
// ===========================================================================

#[test]
fn flake_rate_zero_runs() {
    let fr = FlakeRate::compute(0, 0, 0);
    assert_eq!(fr.total_runs, 0);
    assert_eq!(fr.mismatched_runs, 0);
    assert_eq!(fr.rate_millionths, 0);
    assert!(fr.within_threshold);
}

#[test]
fn flake_rate_no_mismatches() {
    let fr = FlakeRate::compute(100, 0, 0);
    assert_eq!(fr.rate_millionths, 0);
    assert!(fr.within_threshold);
}

#[test]
fn flake_rate_all_mismatched() {
    let fr = FlakeRate::compute(100, 100, 0);
    assert_eq!(fr.rate_millionths, 1_000_000);
    assert!(!fr.within_threshold);
}

#[test]
fn flake_rate_half_mismatched() {
    let fr = FlakeRate::compute(100, 50, 0);
    assert_eq!(fr.rate_millionths, 500_000);
    assert!(!fr.within_threshold);
}

#[test]
fn flake_rate_partial_within_threshold() {
    let fr = FlakeRate::compute(100, 10, 100_000);
    assert_eq!(fr.rate_millionths, 100_000); // exactly 10%
    assert!(fr.within_threshold); // equal to threshold counts as within
}

#[test]
fn flake_rate_partial_above_threshold() {
    let fr = FlakeRate::compute(100, 20, 100_000);
    assert_eq!(fr.rate_millionths, 200_000); // 20%
    assert!(!fr.within_threshold);
}

#[test]
fn flake_rate_threshold_boundary_exact() {
    // rate == threshold => within_threshold
    let fr = FlakeRate::compute(1_000_000, 500_000, 500_000);
    assert_eq!(fr.rate_millionths, 500_000);
    assert!(fr.within_threshold);
}

#[test]
fn flake_rate_threshold_boundary_one_over() {
    let fr = FlakeRate::compute(1_000_000, 500_001, 500_000);
    assert!(fr.rate_millionths > 500_000);
    assert!(!fr.within_threshold);
}

#[test]
fn flake_rate_single_run_no_mismatch() {
    let fr = FlakeRate::compute(1, 0, 0);
    assert_eq!(fr.rate_millionths, 0);
    assert!(fr.within_threshold);
}

#[test]
fn flake_rate_single_run_mismatched() {
    let fr = FlakeRate::compute(1, 1, 0);
    assert_eq!(fr.rate_millionths, 1_000_000);
    assert!(!fr.within_threshold);
}

#[test]
fn flake_rate_excess_mismatches_clamp_to_full_rate() {
    let fr = FlakeRate::compute(5, 10, 0);
    assert_eq!(fr.mismatched_runs, 5);
    assert_eq!(fr.rate_millionths, 1_000_000);
    assert!(!fr.within_threshold);
}

#[test]
fn flake_rate_serde_roundtrip() {
    let fr = FlakeRate::compute(50, 5, 200_000);
    let json = serde_json::to_string(&fr).unwrap();
    let back: FlakeRate = serde_json::from_str(&json).unwrap();
    assert_eq!(fr, back);
}

#[test]
fn flake_rate_deterministic() {
    let a = FlakeRate::compute(200, 10, 50_000);
    let b = FlakeRate::compute(200, 10, 50_000);
    assert_eq!(a, b);
}

// ===========================================================================
// 9. GateConfig
// ===========================================================================

#[test]
fn gate_config_default_values() {
    let config = GateConfig::default();
    assert_eq!(config.seed_count, DEFAULT_SEED_COUNT);
    assert_eq!(config.repeats_per_seed, DEFAULT_REPEATS_PER_SEED);
    assert_eq!(
        config.flake_threshold_millionths,
        DEFAULT_FLAKE_THRESHOLD_MILLIONTHS
    );
    assert_eq!(config.worker_variations, vec![2, 4, 8]);
    assert!(config.require_serial_parity);
    assert!(config.base_config.always_check_parity);
}

#[test]
fn gate_config_custom() {
    let config = GateConfig {
        seed_count: 5,
        repeats_per_seed: 10,
        flake_threshold_millionths: 50_000,
        worker_variations: vec![16],
        base_config: ParallelConfig::default(),
        require_serial_parity: false,
    };
    assert_eq!(config.seed_count, 5);
    assert!(!config.require_serial_parity);
}

#[test]
fn gate_config_serde_roundtrip() {
    let config = small_gate_config();
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn gate_config_default_serde_roundtrip() {
    let config = GateConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ===========================================================================
// 10. GateDecision enum
// ===========================================================================

#[test]
fn gate_decision_display_all_variants() {
    assert_eq!(GateDecision::Promote.to_string(), "promote");
    assert_eq!(GateDecision::Hold.to_string(), "hold");
    assert_eq!(GateDecision::Reject.to_string(), "reject");
}

#[test]
fn gate_decision_ordering() {
    assert!(GateDecision::Promote < GateDecision::Hold);
    assert!(GateDecision::Hold < GateDecision::Reject);
    assert!(GateDecision::Promote < GateDecision::Reject);
}

#[test]
fn gate_decision_serde_roundtrip() {
    for d in [
        GateDecision::Promote,
        GateDecision::Hold,
        GateDecision::Reject,
    ] {
        let json = serde_json::to_string(&d).unwrap();
        let back: GateDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}

#[test]
fn gate_decision_clone_copy() {
    let a = GateDecision::Hold;
    let b = a;
    assert_eq!(a, b);
}

// ===========================================================================
// 11. RunRecord struct
// ===========================================================================

#[test]
fn run_record_construction_parallel() {
    let rr = RunRecord {
        seed: 7,
        worker_count: 4,
        run_index: 2,
        output_hash: ContentHash::compute(b"out"),
        token_count: 100,
        mode: ParserMode::Parallel,
        parity_ok: Some(true),
        merge_witness_hash: Some(ContentHash::compute(b"witness")),
    };
    assert_eq!(rr.seed, 7);
    assert_eq!(rr.mode, ParserMode::Parallel);
    assert_eq!(rr.parity_ok, Some(true));
    assert!(rr.merge_witness_hash.is_some());
}

#[test]
fn run_record_construction_serial() {
    let rr = RunRecord {
        seed: 0,
        worker_count: 2,
        run_index: 0,
        output_hash: ContentHash::compute(b"serial"),
        token_count: 10,
        mode: ParserMode::Serial,
        parity_ok: None,
        merge_witness_hash: None,
    };
    assert_eq!(rr.mode, ParserMode::Serial);
    assert!(rr.parity_ok.is_none());
    assert!(rr.merge_witness_hash.is_none());
}

#[test]
fn run_record_serde_roundtrip() {
    let rr = RunRecord {
        seed: 42,
        worker_count: 8,
        run_index: 3,
        output_hash: ContentHash::compute(b"test"),
        token_count: 200,
        mode: ParserMode::Parallel,
        parity_ok: Some(false),
        merge_witness_hash: Some(ContentHash::compute(b"wh")),
    };
    let json = serde_json::to_string(&rr).unwrap();
    let back: RunRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rr, back);
}

// ===========================================================================
// 12. GateResult struct
// ===========================================================================

#[test]
fn gate_result_synthetic_construction() {
    let result = make_gate_result_with_incidents(Vec::new());
    assert_eq!(result.decision, GateDecision::Promote);
    assert!(result.incidents.is_empty());
    assert_eq!(result.schema_version, SCHEMA_VERSION);
}

#[test]
fn gate_result_serde_roundtrip_clean() {
    let source = test_source();
    let config = small_gate_config();
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    let json = serde_json::to_string(&result).unwrap();
    let back: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn gate_result_serde_roundtrip_with_incidents() {
    let incidents = vec![make_incident(
        InterferenceClass::Scheduler,
        InterferenceSeverity::Warning,
        1,
        4,
    )];
    let result = make_gate_result_with_incidents(incidents);
    let json = serde_json::to_string(&result).unwrap();
    let back: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ===========================================================================
// 13. evaluate_gate — happy path (deterministic input)
// ===========================================================================

#[test]
fn evaluate_gate_promotes_deterministic_input() {
    let source = test_source();
    let config = small_gate_config();
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    assert_eq!(result.decision, GateDecision::Promote);
    assert!(result.incidents.is_empty());
    assert_eq!(result.flake_rate.mismatched_runs, 0);
}

#[test]
fn evaluate_gate_correct_run_count() {
    let source = test_source();
    let config = small_gate_config();
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    let expected_runs = config.worker_variations.len() as u64
        * config.seed_count as u64
        * config.repeats_per_seed as u64;
    assert_eq!(result.total_runs, expected_runs);
    assert_eq!(result.runs.len() as u64, expected_runs);
}

#[test]
fn evaluate_gate_seeds_tracked() {
    let source = test_source();
    let config = small_gate_config();
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    assert_eq!(result.seeds_tested.len(), config.seed_count as usize);
    // Seeds should be 0..seed_count
    for i in 0..config.seed_count {
        assert!(result.seeds_tested.contains(&(i as u64)));
    }
}

#[test]
fn evaluate_gate_workers_tracked() {
    let source = test_source();
    let config = small_gate_config();
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    assert_eq!(result.workers_tested.len(), config.worker_variations.len());
    for w in &config.worker_variations {
        assert!(result.workers_tested.contains(w));
    }
}

#[test]
fn evaluate_gate_schema_version() {
    let source = test_source();
    let config = small_gate_config();
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    assert_eq!(result.schema_version, SCHEMA_VERSION);
}

#[test]
fn evaluate_gate_input_hash_matches() {
    let source = test_source();
    let expected_hash = ContentHash::compute(source.as_bytes());
    let config = small_gate_config();
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    assert_eq!(result.input_hash, expected_hash);
}

#[test]
fn evaluate_gate_input_bytes() {
    let source = test_source();
    let config = small_gate_config();
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    assert_eq!(result.input_bytes, source.len() as u64);
}

// ===========================================================================
// 14. evaluate_gate — edge cases
// ===========================================================================

#[test]
fn evaluate_gate_empty_input() {
    let config = small_gate_config();
    let result = parallel_interference_gate::evaluate_gate("", &config);
    assert_eq!(result.decision, GateDecision::Promote);
    assert_eq!(result.input_bytes, 0);
}

#[test]
fn evaluate_gate_only_whitespace() {
    let source = "   \n\t\n   ";
    let config = small_gate_config();
    let result = parallel_interference_gate::evaluate_gate(source, &config);
    assert_eq!(result.decision, GateDecision::Promote);
}

#[test]
fn evaluate_gate_only_newlines() {
    let source = "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";
    let config = small_gate_config();
    let result = parallel_interference_gate::evaluate_gate(source, &config);
    assert_eq!(result.decision, GateDecision::Promote);
}

#[test]
fn evaluate_gate_small_below_parallel_threshold() {
    let config = GateConfig {
        seed_count: 2,
        repeats_per_seed: 2,
        worker_variations: vec![2],
        ..GateConfig::default()
    };
    let result = parallel_interference_gate::evaluate_gate("x = 1;", &config);
    assert_eq!(result.decision, GateDecision::Promote);
}

#[test]
fn evaluate_gate_single_seed_single_repeat_single_worker() {
    let source = test_source();
    let config = GateConfig {
        seed_count: 1,
        repeats_per_seed: 1,
        worker_variations: vec![4],
        ..small_gate_config()
    };
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    assert_eq!(result.total_runs, 1);
    assert_eq!(result.decision, GateDecision::Promote);
}

#[test]
fn evaluate_gate_eight_workers() {
    let source = test_source();
    let config = GateConfig {
        seed_count: 2,
        repeats_per_seed: 2,
        worker_variations: vec![8],
        ..small_gate_config()
    };
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    assert_eq!(result.decision, GateDecision::Promote);
}

#[test]
fn evaluate_gate_operators_and_strings() {
    let mut source = String::new();
    for i in 0..50 {
        source.push_str(&format!(
            "var s{} = \"hello\"; x{} == {} && y{} != z{};\n",
            i, i, i, i, i
        ));
    }
    let config = small_gate_config();
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    assert_eq!(result.decision, GateDecision::Promote);
}

#[test]
fn evaluate_gate_many_worker_variations() {
    let source = test_source();
    let config = GateConfig {
        seed_count: 2,
        repeats_per_seed: 1,
        worker_variations: vec![2, 3, 4, 5, 6, 7, 8],
        ..small_gate_config()
    };
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    assert_eq!(result.total_runs, 2 * 7);
    assert_eq!(result.workers_tested.len(), 7);
}

// ===========================================================================
// 15. evaluate_gate — determinism
// ===========================================================================

#[test]
fn evaluate_gate_deterministic_repeated() {
    let source = test_source();
    let config = GateConfig {
        seed_count: 2,
        repeats_per_seed: 2,
        worker_variations: vec![2],
        ..small_gate_config()
    };
    let r1 = parallel_interference_gate::evaluate_gate(&source, &config);
    let r2 = parallel_interference_gate::evaluate_gate(&source, &config);
    assert_eq!(r1.decision, r2.decision);
    assert_eq!(r1.reference_hash, r2.reference_hash);
    assert_eq!(r1.total_runs, r2.total_runs);
    assert_eq!(r1.input_hash, r2.input_hash);
    assert_eq!(r1.flake_rate, r2.flake_rate);
}

#[test]
fn evaluate_gate_different_sources_different_hashes() {
    let config = GateConfig {
        seed_count: 1,
        repeats_per_seed: 1,
        worker_variations: vec![2],
        ..small_gate_config()
    };
    let r1 = parallel_interference_gate::evaluate_gate("var a = 1;", &config);
    let r2 = parallel_interference_gate::evaluate_gate("var b = 2;", &config);
    assert_ne!(r1.input_hash, r2.input_hash);
}

#[test]
fn evaluate_gate_same_source_same_reference_hash() {
    let source = test_source();
    let config = small_gate_config();
    let r1 = parallel_interference_gate::evaluate_gate(&source, &config);
    let r2 = parallel_interference_gate::evaluate_gate(&source, &config);
    assert_eq!(r1.reference_hash, r2.reference_hash);
}

// ===========================================================================
// 16. evaluate_gate — rationale text
// ===========================================================================

#[test]
fn evaluate_gate_promote_rationale_contains_run_count() {
    let source = test_source();
    let config = small_gate_config();
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    assert_eq!(result.decision, GateDecision::Promote);
    assert!(
        result.rationale.contains(&result.total_runs.to_string()),
        "Rationale should mention total runs: {}",
        result.rationale
    );
    assert!(result.rationale.contains("deterministic"));
}

// ===========================================================================
// 17. generate_operator_summary
// ===========================================================================

#[test]
fn operator_summary_promote_clean() {
    let source = test_source();
    let config = small_gate_config();
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    let summary = parallel_interference_gate::generate_operator_summary(&result);
    assert_eq!(summary.decision, GateDecision::Promote);
    assert_eq!(summary.incident_count, 0);
    assert!(summary.root_cause_hints.is_empty());
    assert!(summary.recommended_action.contains("safe to promote"));
}

#[test]
fn operator_summary_hold_with_incidents() {
    let incidents = vec![
        make_incident(
            InterferenceClass::Scheduler,
            InterferenceSeverity::Warning,
            0,
            2,
        ),
        make_incident(
            InterferenceClass::Scheduler,
            InterferenceSeverity::Warning,
            1,
            2,
        ),
        make_incident(
            InterferenceClass::MergeOrder,
            InterferenceSeverity::Warning,
            2,
            4,
        ),
    ];
    let result = make_gate_result_with_incidents(incidents);
    let summary = parallel_interference_gate::generate_operator_summary(&result);
    assert_eq!(summary.decision, GateDecision::Hold);
    assert_eq!(summary.incident_count, 3);
    assert!(!summary.root_cause_hints.is_empty());
    // Scheduler has 2 incidents, should be ranked first
    assert_eq!(
        summary.root_cause_hints[0].class,
        InterferenceClass::Scheduler
    );
    assert_eq!(summary.root_cause_hints[0].count, 2);
    assert_eq!(
        summary.root_cause_hints[1].class,
        InterferenceClass::MergeOrder
    );
    assert_eq!(summary.root_cause_hints[1].count, 1);
    assert!(summary.recommended_action.contains("Investigate"));
}

#[test]
fn operator_summary_reject_with_critical() {
    let incidents = vec![make_incident(
        InterferenceClass::MergeOrder,
        InterferenceSeverity::Critical,
        0,
        4,
    )];
    let result = make_gate_result_with_incidents(incidents);
    let summary = parallel_interference_gate::generate_operator_summary(&result);
    assert_eq!(summary.decision, GateDecision::Reject);
    assert!(summary.recommended_action.contains("serial fallback"));
}

#[test]
fn operator_summary_flake_rate_display() {
    let result = make_gate_result_with_incidents(Vec::new());
    let summary = parallel_interference_gate::generate_operator_summary(&result);
    assert!(summary.flake_rate_display.contains("/1M"));
}

#[test]
fn operator_summary_serde_roundtrip() {
    let source = test_source();
    let config = small_gate_config();
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    let summary = parallel_interference_gate::generate_operator_summary(&result);
    let json = serde_json::to_string(&summary).unwrap();
    let back: OperatorSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn operator_summary_root_cause_severity_escalation() {
    // Same class, different severities: should take max severity
    let incidents = vec![
        make_incident(
            InterferenceClass::Scheduler,
            InterferenceSeverity::Info,
            0,
            2,
        ),
        make_incident(
            InterferenceClass::Scheduler,
            InterferenceSeverity::Warning,
            1,
            2,
        ),
    ];
    let result = make_gate_result_with_incidents(incidents);
    let summary = parallel_interference_gate::generate_operator_summary(&result);
    assert_eq!(summary.root_cause_hints.len(), 1);
    assert_eq!(
        summary.root_cause_hints[0].class,
        InterferenceClass::Scheduler
    );
    assert_eq!(
        summary.root_cause_hints[0].severity,
        InterferenceSeverity::Warning
    );
    assert_eq!(summary.root_cause_hints[0].count, 2);
}

#[test]
fn operator_summary_root_cause_has_remediation() {
    let incidents = vec![
        make_incident(
            InterferenceClass::BackpressureDrift,
            InterferenceSeverity::Warning,
            0,
            2,
        ),
        make_incident(
            InterferenceClass::TimeoutRace,
            InterferenceSeverity::Warning,
            1,
            4,
        ),
    ];
    let result = make_gate_result_with_incidents(incidents);
    let summary = parallel_interference_gate::generate_operator_summary(&result);
    for hint in &summary.root_cause_hints {
        assert!(!hint.remediation.is_empty());
    }
}

// ===========================================================================
// 18. RootCauseHint struct
// ===========================================================================

#[test]
fn root_cause_hint_construction() {
    let hint = RootCauseHint {
        class: InterferenceClass::DataStructureIteration,
        count: 5,
        severity: InterferenceSeverity::Critical,
        remediation: "Replace HashMap with BTreeMap".to_string(),
    };
    assert_eq!(hint.class, InterferenceClass::DataStructureIteration);
    assert_eq!(hint.count, 5);
    assert_eq!(hint.severity, InterferenceSeverity::Critical);
}

#[test]
fn root_cause_hint_serde_roundtrip() {
    let hint = RootCauseHint {
        class: InterferenceClass::ArtifactPipeline,
        count: 2,
        severity: InterferenceSeverity::Info,
        remediation: "Check timestamps".to_string(),
    };
    let json = serde_json::to_string(&hint).unwrap();
    let back: RootCauseHint = serde_json::from_str(&json).unwrap();
    assert_eq!(hint, back);
}

// ===========================================================================
// 19. ReplayBundle
// ===========================================================================

#[test]
fn replay_bundle_construction() {
    let bundle = ReplayBundle {
        schema_version: SCHEMA_VERSION.to_string(),
        input_hash: ContentHash::compute(b"inp"),
        input_bytes: 200,
        incidents: vec![make_incident(
            InterferenceClass::Scheduler,
            InterferenceSeverity::Warning,
            3,
            4,
        )],
        failing_seeds: vec![3],
        failing_workers: vec![4],
        replay_commands: vec!["replay --seed 3".to_string()],
        reference_hash: ContentHash::compute(b"ref"),
    };
    assert_eq!(bundle.schema_version, SCHEMA_VERSION);
    assert_eq!(bundle.input_bytes, 200);
    assert_eq!(bundle.failing_seeds, vec![3]);
}

#[test]
fn replay_bundle_serde_roundtrip() {
    let bundle = ReplayBundle {
        schema_version: SCHEMA_VERSION.to_string(),
        input_hash: ContentHash::compute(b"test"),
        input_bytes: 100,
        incidents: vec![make_incident(
            InterferenceClass::MergeOrder,
            InterferenceSeverity::Warning,
            5,
            4,
        )],
        failing_seeds: vec![5],
        failing_workers: vec![4],
        replay_commands: vec!["replay".to_string()],
        reference_hash: ContentHash::compute(b"ref"),
    };
    let json = serde_json::to_string(&bundle).unwrap();
    let back: ReplayBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

// ===========================================================================
// 20. build_replay_bundle
// ===========================================================================

#[test]
fn build_replay_bundle_none_on_clean_run() {
    let source = test_source();
    let config = small_gate_config();
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    let bundle = parallel_interference_gate::build_replay_bundle(&result);
    assert!(bundle.is_none());
}

#[test]
fn build_replay_bundle_some_on_incidents() {
    let incidents = vec![
        make_incident(
            InterferenceClass::MergeOrder,
            InterferenceSeverity::Warning,
            1,
            2,
        ),
        make_incident(
            InterferenceClass::Scheduler,
            InterferenceSeverity::Warning,
            3,
            4,
        ),
    ];
    let result = make_gate_result_with_incidents(incidents);
    let bundle = parallel_interference_gate::build_replay_bundle(&result).unwrap();
    assert_eq!(bundle.schema_version, SCHEMA_VERSION);
    assert_eq!(bundle.incidents.len(), 2);
    assert_eq!(bundle.input_hash, result.input_hash);
    assert_eq!(bundle.input_bytes, result.input_bytes);
    assert_eq!(bundle.reference_hash, result.reference_hash);
}

#[test]
fn build_replay_bundle_deduplicates_seeds_and_workers() {
    let incidents = vec![
        make_incident(
            InterferenceClass::MergeOrder,
            InterferenceSeverity::Warning,
            1,
            2,
        ),
        make_incident(
            InterferenceClass::Scheduler,
            InterferenceSeverity::Warning,
            1,
            2,
        ),
        make_incident(
            InterferenceClass::TimeoutRace,
            InterferenceSeverity::Warning,
            3,
            4,
        ),
    ];
    let result = make_gate_result_with_incidents(incidents);
    let bundle = parallel_interference_gate::build_replay_bundle(&result).unwrap();
    // Seeds: {1, 3} deduped via BTreeSet
    assert_eq!(bundle.failing_seeds.len(), 2);
    assert!(bundle.failing_seeds.contains(&1));
    assert!(bundle.failing_seeds.contains(&3));
    // Workers: {2, 4} deduped via BTreeSet
    assert_eq!(bundle.failing_workers.len(), 2);
    assert!(bundle.failing_workers.contains(&2));
    assert!(bundle.failing_workers.contains(&4));
}

#[test]
fn build_replay_bundle_replay_commands_per_incident() {
    let incidents = vec![
        make_incident(
            InterferenceClass::MergeOrder,
            InterferenceSeverity::Warning,
            0,
            2,
        ),
        make_incident(
            InterferenceClass::Scheduler,
            InterferenceSeverity::Warning,
            1,
            4,
        ),
    ];
    let result = make_gate_result_with_incidents(incidents);
    let bundle = parallel_interference_gate::build_replay_bundle(&result).unwrap();
    assert_eq!(bundle.replay_commands.len(), 2);
}

#[test]
fn build_replay_bundle_serde_roundtrip() {
    let incidents = vec![make_incident(
        InterferenceClass::ArtifactPipeline,
        InterferenceSeverity::Critical,
        7,
        8,
    )];
    let result = make_gate_result_with_incidents(incidents);
    let bundle = parallel_interference_gate::build_replay_bundle(&result).unwrap();
    let json = serde_json::to_string(&bundle).unwrap();
    let back: ReplayBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

// ===========================================================================
// 21. apply_gate_to_rollback
// ===========================================================================

#[test]
fn apply_gate_to_rollback_promote_no_trigger() {
    let source = test_source();
    let config = small_gate_config();
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    let mut rollback = RollbackControl::default();
    let triggered = parallel_interference_gate::apply_gate_to_rollback(&result, &mut rollback);
    assert!(!triggered);
    assert!(!rollback.parallel_disabled);
    assert_eq!(rollback.consecutive_failures, 0);
}

#[test]
fn apply_gate_to_rollback_hold_increments_failure() {
    let incidents = vec![make_incident(
        InterferenceClass::Scheduler,
        InterferenceSeverity::Warning,
        0,
        2,
    )];
    let result = make_gate_result_with_incidents(incidents);
    assert_eq!(result.decision, GateDecision::Hold);

    let mut rollback = RollbackControl::default();
    let triggered = parallel_interference_gate::apply_gate_to_rollback(&result, &mut rollback);
    // Default threshold is 3, first failure shouldn't trigger
    assert!(!triggered);
    assert_eq!(rollback.consecutive_failures, 1);
}

#[test]
fn apply_gate_to_rollback_reject_increments_failure() {
    let incidents = vec![make_incident(
        InterferenceClass::MergeOrder,
        InterferenceSeverity::Critical,
        0,
        4,
    )];
    let result = make_gate_result_with_incidents(incidents);
    assert_eq!(result.decision, GateDecision::Reject);

    let mut rollback = RollbackControl::default();
    let triggered = parallel_interference_gate::apply_gate_to_rollback(&result, &mut rollback);
    assert!(!triggered); // first failure, threshold is 3
    assert_eq!(rollback.consecutive_failures, 1);
}

#[test]
fn apply_gate_to_rollback_three_failures_triggers_rollback() {
    let incidents = vec![make_incident(
        InterferenceClass::MergeOrder,
        InterferenceSeverity::Critical,
        0,
        4,
    )];
    let result = make_gate_result_with_incidents(incidents);
    let mut rollback = RollbackControl::default();

    // First two should not trigger
    assert!(!parallel_interference_gate::apply_gate_to_rollback(
        &result,
        &mut rollback
    ));
    assert!(!parallel_interference_gate::apply_gate_to_rollback(
        &result,
        &mut rollback
    ));
    // Third should trigger auto-rollback (threshold = 3)
    let triggered = parallel_interference_gate::apply_gate_to_rollback(&result, &mut rollback);
    assert!(triggered);
    assert!(rollback.parallel_disabled);
}

#[test]
fn apply_gate_to_rollback_promote_resets_failures() {
    let source = test_source();
    let config = small_gate_config();
    let good_result = parallel_interference_gate::evaluate_gate(&source, &config);

    let mut rollback = RollbackControl::default();
    rollback.record_failure("prev-fail-1");
    rollback.record_failure("prev-fail-2");
    assert_eq!(rollback.consecutive_failures, 2);

    parallel_interference_gate::apply_gate_to_rollback(&good_result, &mut rollback);
    assert_eq!(rollback.consecutive_failures, 0);
}

#[test]
fn apply_gate_to_rollback_custom_threshold() {
    let incidents = vec![make_incident(
        InterferenceClass::Scheduler,
        InterferenceSeverity::Warning,
        0,
        2,
    )];
    let result = make_gate_result_with_incidents(incidents);

    let mut rollback = RollbackControl {
        auto_rollback_threshold: 1,
        ..RollbackControl::default()
    };
    let triggered = parallel_interference_gate::apply_gate_to_rollback(&result, &mut rollback);
    assert!(triggered);
    assert!(rollback.parallel_disabled);
}

// ===========================================================================
// 22. Cross-concern integration scenarios
// ===========================================================================

#[test]
fn full_pipeline_evaluate_then_summary_then_replay() {
    let source = test_source();
    let config = small_gate_config();
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    let summary = parallel_interference_gate::generate_operator_summary(&result);
    let bundle = parallel_interference_gate::build_replay_bundle(&result);

    assert_eq!(result.decision, GateDecision::Promote);
    assert_eq!(summary.decision, GateDecision::Promote);
    assert!(bundle.is_none()); // no incidents => no replay bundle
}

#[test]
fn full_pipeline_with_synthetic_incidents() {
    let incidents = vec![
        make_incident(
            InterferenceClass::MergeOrder,
            InterferenceSeverity::Warning,
            0,
            2,
        ),
        make_incident(
            InterferenceClass::Scheduler,
            InterferenceSeverity::Warning,
            1,
            4,
        ),
        make_incident(
            InterferenceClass::MergeOrder,
            InterferenceSeverity::Warning,
            2,
            2,
        ),
    ];
    let result = make_gate_result_with_incidents(incidents);

    let summary = parallel_interference_gate::generate_operator_summary(&result);
    assert_eq!(summary.decision, GateDecision::Hold);
    assert_eq!(summary.incident_count, 3);
    // MergeOrder has 2 incidents, Scheduler has 1 => MergeOrder first
    assert_eq!(
        summary.root_cause_hints[0].class,
        InterferenceClass::MergeOrder
    );
    assert_eq!(summary.root_cause_hints[0].count, 2);

    let bundle = parallel_interference_gate::build_replay_bundle(&result).unwrap();
    assert_eq!(bundle.incidents.len(), 3);
    assert_eq!(bundle.failing_seeds.len(), 3); // 0, 1, 2

    let mut rollback = RollbackControl::default();
    let triggered = parallel_interference_gate::apply_gate_to_rollback(&result, &mut rollback);
    assert!(!triggered); // first failure
    assert_eq!(rollback.consecutive_failures, 1);
}

#[test]
fn evaluate_and_rollback_cycle() {
    let source = test_source();
    let config = small_gate_config();
    let mut rollback = RollbackControl::default();

    // Evaluate clean run
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    parallel_interference_gate::apply_gate_to_rollback(&result, &mut rollback);
    assert_eq!(rollback.consecutive_failures, 0);

    // Simulate a synthetic fail
    let bad = make_gate_result_with_incidents(vec![make_incident(
        InterferenceClass::Scheduler,
        InterferenceSeverity::Warning,
        0,
        2,
    )]);
    parallel_interference_gate::apply_gate_to_rollback(&bad, &mut rollback);
    assert_eq!(rollback.consecutive_failures, 1);

    // Another clean run resets
    let result2 = parallel_interference_gate::evaluate_gate(&source, &config);
    parallel_interference_gate::apply_gate_to_rollback(&result2, &mut rollback);
    assert_eq!(rollback.consecutive_failures, 0);
}

#[test]
fn evaluate_and_bundle_serde_end_to_end() {
    let incidents = vec![make_incident(
        InterferenceClass::BackpressureDrift,
        InterferenceSeverity::Warning,
        5,
        8,
    )];
    let result = make_gate_result_with_incidents(incidents);

    // Serialize the full result
    let result_json = serde_json::to_string(&result).unwrap();
    let result_back: GateResult = serde_json::from_str(&result_json).unwrap();
    assert_eq!(result, result_back);

    // Build bundle and serialize
    let bundle = parallel_interference_gate::build_replay_bundle(&result_back).unwrap();
    let bundle_json = serde_json::to_string(&bundle).unwrap();
    let bundle_back: ReplayBundle = serde_json::from_str(&bundle_json).unwrap();
    assert_eq!(bundle, bundle_back);

    // Summary serde
    let summary = parallel_interference_gate::generate_operator_summary(&result_back);
    let summary_json = serde_json::to_string(&summary).unwrap();
    let summary_back: OperatorSummary = serde_json::from_str(&summary_json).unwrap();
    assert_eq!(summary, summary_back);
}

// ===========================================================================
// 23. OperatorSummary struct
// ===========================================================================

#[test]
fn operator_summary_construction() {
    let summary = OperatorSummary {
        decision: GateDecision::Hold,
        total_runs: 50,
        incident_count: 3,
        root_cause_hints: Vec::new(),
        flake_rate_display: "100/1M (threshold 0/1M)".to_string(),
        recommended_action: "Investigate".to_string(),
    };
    assert_eq!(summary.decision, GateDecision::Hold);
    assert_eq!(summary.total_runs, 50);
    assert_eq!(summary.incident_count, 3);
}

#[test]
fn operator_summary_serde_roundtrip_with_hints() {
    let summary = OperatorSummary {
        decision: GateDecision::Reject,
        total_runs: 100,
        incident_count: 5,
        root_cause_hints: vec![
            RootCauseHint {
                class: InterferenceClass::MergeOrder,
                count: 3,
                severity: InterferenceSeverity::Critical,
                remediation: "Fix merge".to_string(),
            },
            RootCauseHint {
                class: InterferenceClass::Scheduler,
                count: 2,
                severity: InterferenceSeverity::Warning,
                remediation: "Fix scheduler".to_string(),
            },
        ],
        flake_rate_display: "50000/1M (threshold 0/1M)".to_string(),
        recommended_action: "Force serial".to_string(),
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: OperatorSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ===========================================================================
// 24. Gate decision logic coverage
// ===========================================================================

#[test]
fn gate_decision_reject_on_critical_severity() {
    let result = make_gate_result_with_incidents(vec![make_incident(
        InterferenceClass::MergeOrder,
        InterferenceSeverity::Critical,
        0,
        4,
    )]);
    assert_eq!(result.decision, GateDecision::Reject);
}

#[test]
fn gate_decision_hold_on_warning_only() {
    let result = make_gate_result_with_incidents(vec![make_incident(
        InterferenceClass::Scheduler,
        InterferenceSeverity::Warning,
        0,
        2,
    )]);
    assert_eq!(result.decision, GateDecision::Hold);
}

#[test]
fn gate_decision_promote_on_no_incidents() {
    let result = make_gate_result_with_incidents(Vec::new());
    assert_eq!(result.decision, GateDecision::Promote);
}

// ===========================================================================
// 25. FlakeRate edge cases
// ===========================================================================

#[test]
fn flake_rate_large_values_no_overflow() {
    let fr = FlakeRate::compute(u64::MAX, 1, 0);
    // Should not panic; rate should be 0 (1 * 1_000_000 / u64::MAX rounds to 0)
    assert_eq!(fr.rate_millionths, 0);
    assert!(fr.within_threshold);
}

#[test]
fn flake_rate_max_threshold() {
    let fr = FlakeRate::compute(100, 100, u64::MAX);
    assert_eq!(fr.rate_millionths, 1_000_000);
    assert!(fr.within_threshold); // threshold is u64::MAX
}

// ===========================================================================
// 26. BTreeSet deterministic ordering in evaluate_gate
// ===========================================================================

#[test]
fn evaluate_gate_seeds_sorted() {
    let source = test_source();
    let config = GateConfig {
        seed_count: 5,
        repeats_per_seed: 1,
        worker_variations: vec![2],
        ..small_gate_config()
    };
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    // Seeds should be sorted (BTreeSet guarantees ordering)
    let mut sorted = result.seeds_tested.clone();
    sorted.sort();
    assert_eq!(result.seeds_tested, sorted);
}

#[test]
fn evaluate_gate_workers_sorted() {
    let source = test_source();
    let config = GateConfig {
        seed_count: 1,
        repeats_per_seed: 1,
        worker_variations: vec![8, 2, 4],
        ..small_gate_config()
    };
    let result = parallel_interference_gate::evaluate_gate(&source, &config);
    let mut sorted = result.workers_tested.clone();
    sorted.sort();
    assert_eq!(result.workers_tested, sorted);
}

// ===========================================================================
// 27. Multiple interference classes in one gate result
// ===========================================================================

#[test]
fn operator_summary_multiple_classes_sorted_by_count() {
    let incidents = vec![
        make_incident(
            InterferenceClass::TimeoutRace,
            InterferenceSeverity::Warning,
            0,
            2,
        ),
        make_incident(
            InterferenceClass::BackpressureDrift,
            InterferenceSeverity::Warning,
            1,
            4,
        ),
        make_incident(
            InterferenceClass::BackpressureDrift,
            InterferenceSeverity::Warning,
            2,
            4,
        ),
        make_incident(
            InterferenceClass::BackpressureDrift,
            InterferenceSeverity::Info,
            3,
            4,
        ),
        make_incident(
            InterferenceClass::TimeoutRace,
            InterferenceSeverity::Warning,
            4,
            2,
        ),
    ];
    let result = make_gate_result_with_incidents(incidents);
    let summary = parallel_interference_gate::generate_operator_summary(&result);
    // BackpressureDrift has 3 incidents, TimeoutRace has 2
    assert_eq!(
        summary.root_cause_hints[0].class,
        InterferenceClass::BackpressureDrift
    );
    assert_eq!(summary.root_cause_hints[0].count, 3);
    assert_eq!(
        summary.root_cause_hints[0].severity,
        InterferenceSeverity::Warning
    );
    assert_eq!(
        summary.root_cause_hints[1].class,
        InterferenceClass::TimeoutRace
    );
    assert_eq!(summary.root_cause_hints[1].count, 2);
}

// ===========================================================================
// 28. Debug formatting
// ===========================================================================

#[test]
fn all_types_debug_format() {
    // Verify Debug impl doesn't panic for all types
    let _ = format!("{:?}", InterferenceClass::MergeOrder);
    let _ = format!("{:?}", InterferenceSeverity::Info);
    let _ = format!("{:?}", GateDecision::Promote);

    let incident = make_incident(
        InterferenceClass::Scheduler,
        InterferenceSeverity::Warning,
        0,
        2,
    );
    let _ = format!("{:?}", incident);

    let diff = WitnessDiff {
        matches: true,
        diffs: Vec::new(),
    };
    let _ = format!("{:?}", diff);

    let entry = WitnessDiffEntry {
        field: "f".to_string(),
        expected: "a".to_string(),
        actual: "b".to_string(),
    };
    let _ = format!("{:?}", entry);

    let fr = FlakeRate::compute(10, 1, 0);
    let _ = format!("{:?}", fr);

    let config = GateConfig::default();
    let _ = format!("{:?}", config);

    let rr = RunRecord {
        seed: 0,
        worker_count: 2,
        run_index: 0,
        output_hash: ContentHash::compute(b"x"),
        token_count: 1,
        mode: ParserMode::Serial,
        parity_ok: None,
        merge_witness_hash: None,
    };
    let _ = format!("{:?}", rr);

    let bundle = ReplayBundle {
        schema_version: SCHEMA_VERSION.to_string(),
        input_hash: ContentHash::compute(b"x"),
        input_bytes: 1,
        incidents: Vec::new(),
        failing_seeds: Vec::new(),
        failing_workers: Vec::new(),
        replay_commands: Vec::new(),
        reference_hash: ContentHash::compute(b"r"),
    };
    let _ = format!("{:?}", bundle);

    let summary = OperatorSummary {
        decision: GateDecision::Promote,
        total_runs: 0,
        incident_count: 0,
        root_cause_hints: Vec::new(),
        flake_rate_display: "0/1M".to_string(),
        recommended_action: "none".to_string(),
    };
    let _ = format!("{:?}", summary);

    let hint = RootCauseHint {
        class: InterferenceClass::MergeOrder,
        count: 1,
        severity: InterferenceSeverity::Info,
        remediation: "fix".to_string(),
    };
    let _ = format!("{:?}", hint);
}

// ===========================================================================
// 29. Collected BTreeSet invariant in replay bundle
// ===========================================================================

#[test]
fn replay_bundle_seeds_and_workers_are_sorted() {
    let incidents = vec![
        make_incident(
            InterferenceClass::Scheduler,
            InterferenceSeverity::Warning,
            9,
            8,
        ),
        make_incident(
            InterferenceClass::MergeOrder,
            InterferenceSeverity::Warning,
            1,
            2,
        ),
        make_incident(
            InterferenceClass::TimeoutRace,
            InterferenceSeverity::Warning,
            5,
            4,
        ),
    ];
    let result = make_gate_result_with_incidents(incidents);
    let bundle = parallel_interference_gate::build_replay_bundle(&result).unwrap();
    // BTreeSet iteration => sorted
    let mut seeds_sorted = bundle.failing_seeds.clone();
    seeds_sorted.sort();
    assert_eq!(bundle.failing_seeds, seeds_sorted);

    let mut workers_sorted = bundle.failing_workers.clone();
    workers_sorted.sort();
    assert_eq!(bundle.failing_workers, workers_sorted);
}

// ===========================================================================
// 30. Hash collections (BTreeSet in InterferenceClass)
// ===========================================================================

#[test]
fn interference_class_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(InterferenceClass::Scheduler);
    set.insert(InterferenceClass::MergeOrder);
    set.insert(InterferenceClass::Scheduler); // duplicate
    assert_eq!(set.len(), 2);
    // BTreeSet ordering: MergeOrder < Scheduler
    let items: Vec<_> = set.into_iter().collect();
    assert_eq!(items[0], InterferenceClass::MergeOrder);
    assert_eq!(items[1], InterferenceClass::Scheduler);
}

#[test]
fn interference_severity_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(InterferenceSeverity::Critical);
    set.insert(InterferenceSeverity::Info);
    set.insert(InterferenceSeverity::Warning);
    assert_eq!(set.len(), 3);
    let items: Vec<_> = set.into_iter().collect();
    assert_eq!(items[0], InterferenceSeverity::Info);
    assert_eq!(items[1], InterferenceSeverity::Warning);
    assert_eq!(items[2], InterferenceSeverity::Critical);
}

#[test]
fn gate_decision_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(GateDecision::Reject);
    set.insert(GateDecision::Promote);
    set.insert(GateDecision::Hold);
    let items: Vec<_> = set.into_iter().collect();
    assert_eq!(
        items,
        vec![
            GateDecision::Promote,
            GateDecision::Hold,
            GateDecision::Reject
        ]
    );
}
