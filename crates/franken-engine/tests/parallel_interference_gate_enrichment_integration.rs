#![forbid(unsafe_code)]
//! Enrichment integration tests for the `parallel_interference_gate` module.
//!
//! Covers additional scenarios: edge-case gate configs, multi-incident classification,
//! operator summary corner cases, replay bundle composition, witness/transcript comparison
//! boundary conditions, flake-rate arithmetic, rollback integration fidelity,
//! serde round-trip determinism, and cross-concern integration patterns.

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
    COMPONENT, DEFAULT_FLAKE_THRESHOLD_MILLIONTHS, DEFAULT_MAX_WORKER_VARIATIONS,
    DEFAULT_REPEATS_PER_SEED, DEFAULT_SEED_COUNT, FlakeRate, GateConfig, GateDecision, GateResult,
    InterferenceClass, InterferenceIncident, InterferenceSeverity, OperatorSummary, ReplayBundle,
    RootCauseHint, RunRecord, SCHEMA_VERSION, WitnessDiff, WitnessDiffEntry,
};
use frankenengine_engine::parallel_interference_gate::{
    apply_gate_to_rollback, build_replay_bundle, compare_transcripts, compare_witnesses,
    evaluate_gate, generate_operator_summary,
};
use frankenengine_engine::parallel_parser::{
    MergeWitness, ParallelConfig, ParserMode, RollbackControl, ScheduleDispatch, ScheduleTranscript,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_source_large() -> String {
    let mut s = String::new();
    for i in 0..200 {
        s.push_str(&format!("var a{} = {};\n", i, i * 3));
    }
    s
}

fn make_incident(
    class: InterferenceClass,
    severity: InterferenceSeverity,
    seed: u64,
) -> InterferenceIncident {
    InterferenceIncident {
        class,
        severity,
        seed,
        worker_count: 4,
        run_index: 0,
        expected_hash: ContentHash::compute(b"expected"),
        actual_hash: ContentHash::compute(b"actual"),
        mismatch_token_index: None,
        triage_hint: format!("seed-{}", seed),
        remediation_playbook_id: format!("playbook.interference.{}", class),
        replay_command: format!("replay --seed {}", seed),
    }
}

fn make_gate_result(decision: GateDecision, incidents: Vec<InterferenceIncident>) -> GateResult {
    let flake = FlakeRate::compute(100, incidents.len() as u64, 0);
    GateResult {
        schema_version: SCHEMA_VERSION.to_string(),
        decision,
        rationale: "test".to_string(),
        runs: Vec::new(),
        incidents,
        flake_rate: flake,
        reference_hash: ContentHash::compute(b"ref"),
        seeds_tested: vec![0, 1, 2],
        workers_tested: vec![2, 4],
        total_runs: 100,
        input_hash: ContentHash::compute(b"input"),
        input_bytes: 500,
    }
}

fn minimal_gate_config() -> GateConfig {
    GateConfig {
        seed_count: 2,
        repeats_per_seed: 1,
        flake_threshold_millionths: 0,
        worker_variations: vec![2],
        base_config: ParallelConfig {
            min_parallel_bytes: 10,
            always_check_parity: true,
            ..ParallelConfig::default()
        },
        require_serial_parity: true,
    }
}

// ===========================================================================
// 1. Constants and basic identity
// ===========================================================================

#[test]
fn enrichment_component_name_non_empty() {
    assert!(!COMPONENT.is_empty());
    assert!(COMPONENT.contains("interference"));
}

#[test]
fn enrichment_schema_version_format() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("parallel-interference-gate"));
}

#[test]
fn enrichment_defaults_are_consistent() {
    assert!(DEFAULT_SEED_COUNT > 0);
    assert!(DEFAULT_REPEATS_PER_SEED > 0);
    assert!(DEFAULT_MAX_WORKER_VARIATIONS > 0);
    assert_eq!(DEFAULT_FLAKE_THRESHOLD_MILLIONTHS, 0);
}

// ===========================================================================
// 2. InterferenceClass
// ===========================================================================

#[test]
fn enrichment_interference_class_all_variants_display() {
    let variants = [
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
    for (variant, expected) in &variants {
        assert_eq!(variant.to_string(), *expected);
    }
}

#[test]
fn enrichment_interference_class_serde_roundtrip_all() {
    let variants = [
        InterferenceClass::MergeOrder,
        InterferenceClass::Scheduler,
        InterferenceClass::DataStructureIteration,
        InterferenceClass::ArtifactPipeline,
        InterferenceClass::TimeoutRace,
        InterferenceClass::BackpressureDrift,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: InterferenceClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_interference_class_clone_eq() {
    let a = InterferenceClass::MergeOrder;
    let b = a;
    assert_eq!(a, b);
}

// ===========================================================================
// 3. InterferenceSeverity
// ===========================================================================

#[test]
fn enrichment_severity_all_variants_display() {
    assert_eq!(InterferenceSeverity::Info.to_string(), "info");
    assert_eq!(InterferenceSeverity::Warning.to_string(), "warning");
    assert_eq!(InterferenceSeverity::Critical.to_string(), "critical");
}

#[test]
fn enrichment_severity_ordering_complete() {
    assert!(InterferenceSeverity::Info < InterferenceSeverity::Warning);
    assert!(InterferenceSeverity::Warning < InterferenceSeverity::Critical);
    assert!(InterferenceSeverity::Info < InterferenceSeverity::Critical);
}

#[test]
fn enrichment_severity_serde_roundtrip() {
    for s in [
        InterferenceSeverity::Info,
        InterferenceSeverity::Warning,
        InterferenceSeverity::Critical,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: InterferenceSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ===========================================================================
// 4. InterferenceIncident
// ===========================================================================

#[test]
fn enrichment_incident_all_fields_populated() {
    let inc = make_incident(
        InterferenceClass::Scheduler,
        InterferenceSeverity::Warning,
        42,
    );
    assert_eq!(inc.class, InterferenceClass::Scheduler);
    assert_eq!(inc.severity, InterferenceSeverity::Warning);
    assert_eq!(inc.seed, 42);
    assert_eq!(inc.worker_count, 4);
    assert_eq!(inc.run_index, 0);
    assert!(inc.triage_hint.contains("42"));
    assert!(inc.replay_command.contains("42"));
}

#[test]
fn enrichment_incident_with_mismatch_token_index() {
    let mut inc = make_incident(
        InterferenceClass::MergeOrder,
        InterferenceSeverity::Critical,
        7,
    );
    inc.mismatch_token_index = Some(99);
    let json = serde_json::to_string(&inc).unwrap();
    let back: InterferenceIncident = serde_json::from_str(&json).unwrap();
    assert_eq!(back.mismatch_token_index, Some(99));
}

#[test]
fn enrichment_incident_clone_deep_equality() {
    let inc = make_incident(
        InterferenceClass::TimeoutRace,
        InterferenceSeverity::Info,
        1,
    );
    let cloned = inc.clone();
    assert_eq!(inc, cloned);
}

// ===========================================================================
// 5. WitnessDiff / WitnessDiffEntry
// ===========================================================================

#[test]
fn enrichment_witness_diff_all_fields_different() {
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
        boundary_repairs: 1,
        total_tokens: 20,
    };
    let diff = compare_witnesses(&w1, &w2);
    assert!(!diff.matches);
    assert_eq!(diff.diffs.len(), 5);
    let fields: BTreeSet<String> = diff.diffs.iter().map(|d| d.field.clone()).collect();
    assert!(fields.contains("merged_hash"));
    assert!(fields.contains("witness_hash"));
    assert!(fields.contains("chunk_count"));
    assert!(fields.contains("boundary_repairs"));
    assert!(fields.contains("total_tokens"));
}

#[test]
fn enrichment_witness_diff_entry_serde_roundtrip() {
    let entry = WitnessDiffEntry {
        field: "chunk_count".to_string(),
        expected: "3".to_string(),
        actual: "4".to_string(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: WitnessDiffEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_witness_diff_empty_diffs_means_matches() {
    let diff = WitnessDiff {
        matches: true,
        diffs: Vec::new(),
    };
    assert!(diff.matches);
    assert!(diff.diffs.is_empty());
}

// ===========================================================================
// 6. ScheduleTranscript comparison
// ===========================================================================

#[test]
fn enrichment_transcript_diff_multiple_fields() {
    let dispatches = vec![ScheduleDispatch {
        step_index: 0,
        chunk_index: 0,
        worker_slot: 0,
    }];
    let t1 = ScheduleTranscript {
        seed: 1,
        worker_count: 2,
        plan_hash: ContentHash::compute(b"p1"),
        execution_order: vec![0],
        dispatches: dispatches.clone(),
        transcript_hash: ContentHash::compute(b"t1"),
    };
    let t2 = ScheduleTranscript {
        seed: 2,
        worker_count: 4,
        plan_hash: ContentHash::compute(b"p2"),
        execution_order: vec![1, 0],
        dispatches: vec![ScheduleDispatch {
            step_index: 1,
            chunk_index: 1,
            worker_slot: 1,
        }],
        transcript_hash: ContentHash::compute(b"t2"),
    };
    let diff = compare_transcripts(&t1, &t2);
    assert!(!diff.matches);
    assert!(diff.diffs.len() >= 4);
}

#[test]
fn enrichment_transcript_diff_only_execution_order_differs() {
    let dispatches = vec![ScheduleDispatch {
        step_index: 0,
        chunk_index: 0,
        worker_slot: 0,
    }];
    let t1 = ScheduleTranscript {
        seed: 42,
        worker_count: 4,
        plan_hash: ContentHash::compute(b"plan"),
        execution_order: vec![0, 1],
        dispatches: dispatches.clone(),
        transcript_hash: ContentHash::compute(b"same"),
    };
    let t2 = ScheduleTranscript {
        execution_order: vec![1, 0],
        ..t1.clone()
    };
    let diff = compare_transcripts(&t1, &t2);
    assert!(!diff.matches);
    assert!(diff.diffs.iter().any(|d| d.field == "execution_order"));
}

// ===========================================================================
// 7. FlakeRate
// ===========================================================================

#[test]
fn enrichment_flake_rate_mismatch_exceeds_total_clamped() {
    let fr = FlakeRate::compute(10, 100, 0);
    // mismatched_runs is clamped to total_runs
    assert_eq!(fr.mismatched_runs, 10);
    assert_eq!(fr.rate_millionths, 1_000_000);
}

#[test]
fn enrichment_flake_rate_threshold_boundary() {
    let fr = FlakeRate::compute(100, 10, 100_000);
    assert_eq!(fr.rate_millionths, 100_000);
    assert!(fr.within_threshold); // exactly at threshold
}

#[test]
fn enrichment_flake_rate_just_above_threshold() {
    let fr = FlakeRate::compute(100, 11, 100_000);
    assert_eq!(fr.rate_millionths, 110_000);
    assert!(!fr.within_threshold);
}

#[test]
fn enrichment_flake_rate_serde_roundtrip_zero() {
    let fr = FlakeRate::compute(0, 0, 0);
    let json = serde_json::to_string(&fr).unwrap();
    let back: FlakeRate = serde_json::from_str(&json).unwrap();
    assert_eq!(fr, back);
}

// ===========================================================================
// 8. GateConfig
// ===========================================================================

#[test]
fn enrichment_gate_config_default_worker_variations() {
    let config = GateConfig::default();
    assert_eq!(config.worker_variations, vec![2, 4, 8]);
    assert!(config.require_serial_parity);
}

#[test]
fn enrichment_gate_config_serde_roundtrip() {
    let config = minimal_gate_config();
    let json = serde_json::to_string(&config).unwrap();
    let back: GateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn enrichment_gate_config_custom_threshold() {
    let mut config = GateConfig::default();
    config.flake_threshold_millionths = 500_000;
    assert_eq!(config.flake_threshold_millionths, 500_000);
}

// ===========================================================================
// 9. GateDecision
// ===========================================================================

#[test]
fn enrichment_gate_decision_display() {
    assert_eq!(GateDecision::Promote.to_string(), "promote");
    assert_eq!(GateDecision::Hold.to_string(), "hold");
    assert_eq!(GateDecision::Reject.to_string(), "reject");
}

#[test]
fn enrichment_gate_decision_ordering() {
    assert!(GateDecision::Promote < GateDecision::Hold);
    assert!(GateDecision::Hold < GateDecision::Reject);
}

#[test]
fn enrichment_gate_decision_serde_roundtrip() {
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

// ===========================================================================
// 10. RunRecord
// ===========================================================================

#[test]
fn enrichment_run_record_fields() {
    let rec = RunRecord {
        seed: 7,
        worker_count: 4,
        run_index: 2,
        output_hash: ContentHash::compute(b"out"),
        token_count: 100,
        mode: ParserMode::Serial,
        parity_ok: Some(true),
        merge_witness_hash: None,
    };
    assert_eq!(rec.seed, 7);
    assert_eq!(rec.worker_count, 4);
    assert_eq!(rec.token_count, 100);
    assert_eq!(rec.parity_ok, Some(true));
}

#[test]
fn enrichment_run_record_serde_roundtrip() {
    let rec = RunRecord {
        seed: 0,
        worker_count: 2,
        run_index: 0,
        output_hash: ContentHash::compute(b"x"),
        token_count: 50,
        mode: ParserMode::Serial,
        parity_ok: None,
        merge_witness_hash: Some(ContentHash::compute(b"w")),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: RunRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
}

// ===========================================================================
// 11. GateResult
// ===========================================================================

#[test]
fn enrichment_gate_result_serde_roundtrip() {
    let result = make_gate_result(GateDecision::Promote, Vec::new());
    let json = serde_json::to_string(&result).unwrap();
    let back: GateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn enrichment_gate_result_with_incidents() {
    let incidents = vec![
        make_incident(
            InterferenceClass::MergeOrder,
            InterferenceSeverity::Critical,
            1,
        ),
        make_incident(
            InterferenceClass::Scheduler,
            InterferenceSeverity::Warning,
            2,
        ),
    ];
    let result = make_gate_result(GateDecision::Reject, incidents);
    assert_eq!(result.incidents.len(), 2);
    assert_eq!(result.decision, GateDecision::Reject);
}

// ===========================================================================
// 12. evaluate_gate
// ===========================================================================

#[test]
fn enrichment_evaluate_gate_deterministic_small() {
    let source = "var x = 1;\nvar y = 2;\n";
    let config = minimal_gate_config();
    let r1 = evaluate_gate(source, &config);
    let r2 = evaluate_gate(source, &config);
    assert_eq!(r1.decision, r2.decision);
    assert_eq!(r1.total_runs, r2.total_runs);
    assert_eq!(r1.reference_hash, r2.reference_hash);
}

#[test]
fn enrichment_evaluate_gate_schema_version() {
    let config = minimal_gate_config();
    let result = evaluate_gate("42;", &config);
    assert_eq!(result.schema_version, SCHEMA_VERSION);
}

#[test]
fn enrichment_evaluate_gate_total_runs_matches_config() {
    let config = GateConfig {
        seed_count: 3,
        repeats_per_seed: 2,
        worker_variations: vec![2, 4],
        ..GateConfig::default()
    };
    let result = evaluate_gate("var z = 0;", &config);
    // 2 worker variants * 3 seeds * 2 repeats = 12
    assert_eq!(result.total_runs, 12);
}

#[test]
fn enrichment_evaluate_gate_input_hash_consistency() {
    let source = "1 + 2;";
    let config = minimal_gate_config();
    let result = evaluate_gate(source, &config);
    assert_eq!(result.input_hash, ContentHash::compute(source.as_bytes()));
    assert_eq!(result.input_bytes, source.len() as u64);
}

#[test]
fn enrichment_evaluate_gate_large_source() {
    let source = test_source_large();
    let config = minimal_gate_config();
    let result = evaluate_gate(&source, &config);
    assert!(result.total_runs > 0);
    assert!(result.input_bytes > 100);
}

// ===========================================================================
// 13. OperatorSummary / generate_operator_summary
// ===========================================================================

#[test]
fn enrichment_operator_summary_no_incidents() {
    let result = make_gate_result(GateDecision::Promote, Vec::new());
    let summary = generate_operator_summary(&result);
    assert_eq!(summary.decision, GateDecision::Promote);
    assert_eq!(summary.incident_count, 0);
    assert!(summary.root_cause_hints.is_empty());
    assert!(summary.recommended_action.contains("safe to promote"));
}

#[test]
fn enrichment_operator_summary_with_incidents() {
    let incidents = vec![
        make_incident(
            InterferenceClass::Scheduler,
            InterferenceSeverity::Warning,
            1,
        ),
        make_incident(
            InterferenceClass::Scheduler,
            InterferenceSeverity::Warning,
            2,
        ),
        make_incident(
            InterferenceClass::MergeOrder,
            InterferenceSeverity::Critical,
            3,
        ),
    ];
    let result = make_gate_result(GateDecision::Reject, incidents);
    let summary = generate_operator_summary(&result);
    assert_eq!(summary.incident_count, 3);
    assert!(!summary.root_cause_hints.is_empty());
    // Scheduler has 2 incidents, should be first
    assert_eq!(
        summary.root_cause_hints[0].class,
        InterferenceClass::Scheduler
    );
    assert_eq!(summary.root_cause_hints[0].count, 2);
}

#[test]
fn enrichment_operator_summary_hold_recommended_action() {
    let incidents = vec![make_incident(
        InterferenceClass::BackpressureDrift,
        InterferenceSeverity::Warning,
        0,
    )];
    let result = make_gate_result(GateDecision::Hold, incidents);
    let summary = generate_operator_summary(&result);
    assert!(summary.recommended_action.contains("Investigate"));
}

#[test]
fn enrichment_operator_summary_reject_recommended_action() {
    let incidents = vec![make_incident(
        InterferenceClass::MergeOrder,
        InterferenceSeverity::Critical,
        0,
    )];
    let result = make_gate_result(GateDecision::Reject, incidents);
    let summary = generate_operator_summary(&result);
    assert!(summary.recommended_action.contains("serial fallback"));
}

#[test]
fn enrichment_operator_summary_serde_roundtrip() {
    let result = make_gate_result(GateDecision::Promote, Vec::new());
    let summary = generate_operator_summary(&result);
    let json = serde_json::to_string(&summary).unwrap();
    let back: OperatorSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ===========================================================================
// 14. RootCauseHint
// ===========================================================================

#[test]
fn enrichment_root_cause_hint_serde_roundtrip() {
    let hint = RootCauseHint {
        class: InterferenceClass::DataStructureIteration,
        count: 5,
        severity: InterferenceSeverity::Warning,
        remediation: "Replace HashMap".to_string(),
    };
    let json = serde_json::to_string(&hint).unwrap();
    let back: RootCauseHint = serde_json::from_str(&json).unwrap();
    assert_eq!(hint, back);
}

// ===========================================================================
// 15. ReplayBundle / build_replay_bundle
// ===========================================================================

#[test]
fn enrichment_replay_bundle_none_when_no_incidents() {
    let result = make_gate_result(GateDecision::Promote, Vec::new());
    assert!(build_replay_bundle(&result).is_none());
}

#[test]
fn enrichment_replay_bundle_present_with_incidents() {
    let incidents = vec![
        make_incident(
            InterferenceClass::Scheduler,
            InterferenceSeverity::Warning,
            10,
        ),
        make_incident(
            InterferenceClass::MergeOrder,
            InterferenceSeverity::Critical,
            20,
        ),
    ];
    let result = make_gate_result(GateDecision::Reject, incidents);
    let bundle = build_replay_bundle(&result).unwrap();
    assert_eq!(bundle.schema_version, SCHEMA_VERSION);
    assert_eq!(bundle.incidents.len(), 2);
    // failing_seeds should be deduplicated and sorted
    assert_eq!(bundle.failing_seeds, vec![10, 20]);
    assert_eq!(bundle.replay_commands.len(), 2);
}

#[test]
fn enrichment_replay_bundle_serde_roundtrip() {
    let incidents = vec![make_incident(
        InterferenceClass::TimeoutRace,
        InterferenceSeverity::Info,
        5,
    )];
    let result = make_gate_result(GateDecision::Hold, incidents);
    let bundle = build_replay_bundle(&result).unwrap();
    let json = serde_json::to_string(&bundle).unwrap();
    let back: ReplayBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

#[test]
fn enrichment_replay_bundle_deduplicates_workers() {
    let incidents = vec![
        make_incident(
            InterferenceClass::Scheduler,
            InterferenceSeverity::Warning,
            1,
        ),
        make_incident(
            InterferenceClass::Scheduler,
            InterferenceSeverity::Warning,
            2,
        ),
    ];
    // Both incidents have worker_count=4
    let result = make_gate_result(GateDecision::Hold, incidents);
    let bundle = build_replay_bundle(&result).unwrap();
    assert_eq!(bundle.failing_workers, vec![4]);
}

// ===========================================================================
// 16. apply_gate_to_rollback
// ===========================================================================

#[test]
fn enrichment_rollback_promote_records_success() {
    let result = make_gate_result(GateDecision::Promote, Vec::new());
    let mut rollback = RollbackControl::default();
    let triggered = apply_gate_to_rollback(&result, &mut rollback);
    assert!(!triggered);
}

#[test]
fn enrichment_rollback_reject_records_failure() {
    let incidents = vec![make_incident(
        InterferenceClass::MergeOrder,
        InterferenceSeverity::Critical,
        0,
    )];
    let result = make_gate_result(GateDecision::Reject, incidents);
    let mut rollback = RollbackControl {
        auto_rollback_threshold: 1,
        ..RollbackControl::default()
    };
    let triggered = apply_gate_to_rollback(&result, &mut rollback);
    assert!(triggered);
}

#[test]
fn enrichment_rollback_hold_records_failure() {
    let incidents = vec![make_incident(
        InterferenceClass::Scheduler,
        InterferenceSeverity::Warning,
        0,
    )];
    let result = make_gate_result(GateDecision::Hold, incidents);
    let mut rollback = RollbackControl {
        auto_rollback_threshold: 1,
        ..RollbackControl::default()
    };
    let triggered = apply_gate_to_rollback(&result, &mut rollback);
    assert!(triggered);
}

// ===========================================================================
// 17. Cross-concern integration: evaluate_gate -> summary -> replay
// ===========================================================================

#[test]
fn enrichment_end_to_end_clean_gate() {
    let config = minimal_gate_config();
    let result = evaluate_gate("var x = 42;", &config);
    let summary = generate_operator_summary(&result);
    let bundle = build_replay_bundle(&result);
    assert_eq!(result.decision, GateDecision::Promote);
    assert_eq!(summary.decision, GateDecision::Promote);
    assert!(bundle.is_none());
}

#[test]
fn enrichment_evaluate_gate_seeds_tested_populated() {
    let config = GateConfig {
        seed_count: 5,
        repeats_per_seed: 1,
        worker_variations: vec![2],
        ..GateConfig::default()
    };
    let result = evaluate_gate("true;", &config);
    assert_eq!(result.seeds_tested.len(), 5);
    // Seeds should be 0..5
    for i in 0..5u64 {
        assert!(result.seeds_tested.contains(&i));
    }
}

#[test]
fn enrichment_evaluate_gate_workers_tested_populated() {
    let config = GateConfig {
        seed_count: 1,
        repeats_per_seed: 1,
        worker_variations: vec![2, 4, 8],
        ..GateConfig::default()
    };
    let result = evaluate_gate("null;", &config);
    assert_eq!(result.workers_tested.len(), 3);
}
