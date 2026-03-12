//! Integration tests for the `disruption_scorecard` module.
//!
//! Exercises the full scorecard lifecycle from the public API: schema setup,
//! evidence gathering, deterministic scoring, release-gate enforcement,
//! structured logging, history tracking, trend analysis, and serde round-trips.

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

use frankenengine_engine::disruption_scorecard::{
    DimensionScore, DimensionThreshold, DisruptionDimension, EvidenceInput, HistoryEntry,
    SCORECARD_COMPONENT, SCORECARD_SCHEMA_VERSION, ScorecardError, ScorecardHistory,
    ScorecardLogEntry, ScorecardOutcome, ScorecardResult, ScorecardSchema, compute_scorecard,
    generate_log_entries, passes_release_gate,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn evidence(dim: DisruptionDimension, score: u64, beads: &[&str]) -> EvidenceInput {
    EvidenceInput {
        dimension: dim,
        raw_score_millionths: score,
        source_beads: beads.iter().map(|s| s.to_string()).collect(),
        evidence_hash: ContentHash::compute(format!("{}:{}", dim, score).as_bytes()),
    }
}

fn all_passing_evidence() -> Vec<EvidenceInput> {
    vec![
        evidence(DisruptionDimension::PerformanceDelta, 150_000, &["bd-1ze"]),
        evidence(DisruptionDimension::SecurityDelta, 750_000, &["bd-3rd"]),
        evidence(DisruptionDimension::AutonomyDelta, 800_000, &["bd-181"]),
    ]
}

fn all_failing_evidence() -> Vec<EvidenceInput> {
    vec![
        evidence(DisruptionDimension::PerformanceDelta, 0, &["bd-1ze"]),
        evidence(DisruptionDimension::SecurityDelta, 100_000, &["bd-3rd"]),
        evidence(DisruptionDimension::AutonomyDelta, 200_000, &["bd-181"]),
    ]
}

fn all_exceeding_targets() -> Vec<EvidenceInput> {
    vec![
        evidence(DisruptionDimension::PerformanceDelta, 200_000, &["bd-1ze"]),
        evidence(DisruptionDimension::SecurityDelta, 900_000, &["bd-3rd"]),
        evidence(DisruptionDimension::AutonomyDelta, 950_000, &["bd-181"]),
    ]
}

fn schema() -> ScorecardSchema {
    ScorecardSchema::default_schema()
}

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

// ---------------------------------------------------------------------------
// Full lifecycle: schema → evidence → score → gate → log → history
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_passing() {
    let s = schema();
    let ev = all_passing_evidence();
    let result = compute_scorecard(&s, &ev, epoch(), "test-env".to_string()).unwrap();

    // Overall pass
    assert_eq!(result.outcome, ScorecardOutcome::Pass);
    assert!(passes_release_gate(&result));
    assert_eq!(result.dimensions_evaluated, 3);

    // Per-dimension checks
    let perf = &result.dimension_scores["performance_delta"];
    assert!(perf.meets_floor);
    assert_eq!(perf.raw_score_millionths, 150_000);

    let sec = &result.dimension_scores["security_delta"];
    assert!(sec.meets_floor);
    assert_eq!(sec.raw_score_millionths, 750_000);

    let auto = &result.dimension_scores["autonomy_delta"];
    assert!(auto.meets_floor);
    assert_eq!(auto.raw_score_millionths, 800_000);

    // Structured logging
    let logs = generate_log_entries("trace-1", &result);
    assert_eq!(logs.len(), 3);
    for log in &logs {
        assert_eq!(log.trace_id, "trace-1");
        assert_eq!(log.scorecard_version, SCORECARD_SCHEMA_VERSION);
        assert!(log.pass);
    }

    // History tracking
    let mut history = ScorecardHistory::new();
    assert!(history.is_empty());
    history.append(
        "rc-1".to_string(),
        "2026-02-24T00:00:00Z".to_string(),
        result.clone(),
    );
    assert_eq!(history.len(), 1);
    assert!(!history.is_empty());
    assert_eq!(history.latest().unwrap().candidate_id, "rc-1");
    assert!(!history.has_regression());

    // Result hash is deterministic
    assert_eq!(result.result_hash, result.compute_hash());
}

#[test]
fn full_lifecycle_failing() {
    let s = schema();
    let ev = all_failing_evidence();
    let result = compute_scorecard(&s, &ev, epoch(), "test-env".to_string()).unwrap();

    assert_eq!(result.outcome, ScorecardOutcome::Fail);
    assert!(!passes_release_gate(&result));

    // Performance at 0 meets floor of 0
    let perf = &result.dimension_scores["performance_delta"];
    assert!(perf.meets_floor); // floor is 0

    // Security below floor
    let sec = &result.dimension_scores["security_delta"];
    assert!(!sec.meets_floor);

    // Autonomy below floor
    let auto = &result.dimension_scores["autonomy_delta"];
    assert!(!auto.meets_floor);

    // Logs show failures
    let logs = generate_log_entries("trace-2", &result);
    let failing_logs: Vec<_> = logs.iter().filter(|l| !l.pass).collect();
    assert_eq!(failing_logs.len(), 2); // security + autonomy
}

// ---------------------------------------------------------------------------
// Determinism: same inputs → identical outputs
// ---------------------------------------------------------------------------

#[test]
fn deterministic_computation() {
    let s = schema();
    let ev = all_passing_evidence();

    let r1 = compute_scorecard(&s, &ev, epoch(), "env".to_string()).unwrap();
    let r2 = compute_scorecard(&s, &ev, epoch(), "env".to_string()).unwrap();

    assert_eq!(r1.result_hash, r2.result_hash);
    assert_eq!(r1.outcome, r2.outcome);
    assert_eq!(r1.evidence_bundle_hash, r2.evidence_bundle_hash);
    assert_eq!(r1.dimension_scores, r2.dimension_scores);
    assert_eq!(r1.targets_met, r2.targets_met);
}

#[test]
fn different_evidence_produces_different_hash() {
    let s = schema();
    let ev1 = all_passing_evidence();
    let ev2 = all_exceeding_targets();

    let r1 = compute_scorecard(&s, &ev1, epoch(), "env".to_string()).unwrap();
    let r2 = compute_scorecard(&s, &ev2, epoch(), "env".to_string()).unwrap();

    assert_ne!(r1.result_hash, r2.result_hash);
}

// ---------------------------------------------------------------------------
// Target tracking
// ---------------------------------------------------------------------------

#[test]
fn targets_met_count() {
    let s = schema();

    // Exceeding all targets
    let ev = all_exceeding_targets();
    let r = compute_scorecard(&s, &ev, epoch(), "env".to_string()).unwrap();
    assert_eq!(r.targets_met, 3);

    // Passing floors but not all targets
    let ev_mixed = vec![
        evidence(DisruptionDimension::PerformanceDelta, 50_000, &["bd-1ze"]), // floor 0, target 100k → below target
        evidence(DisruptionDimension::SecurityDelta, 750_000, &["bd-3rd"]), // floor 500k, target 800k → below target
        evidence(DisruptionDimension::AutonomyDelta, 950_000, &["bd-181"]), // floor 600k, target 900k → above target
    ];
    let r2 = compute_scorecard(&s, &ev_mixed, epoch(), "env".to_string()).unwrap();
    assert_eq!(r2.outcome, ScorecardOutcome::Pass);
    assert_eq!(r2.targets_met, 1); // only autonomy
}

// ---------------------------------------------------------------------------
// Schema validation
// ---------------------------------------------------------------------------

#[test]
fn default_schema_is_valid() {
    let s = schema();
    assert!(s.validate().is_ok());
    assert_eq!(s.version, SCORECARD_SCHEMA_VERSION);
    assert_eq!(s.thresholds.len(), 3);
}

#[test]
fn schema_missing_dimension_fails() {
    let mut s = schema();
    s.thresholds.remove("security_delta");

    let result = s.validate();
    assert!(matches!(
        result,
        Err(ScorecardError::MissingDimension { .. })
    ));
}

#[test]
fn schema_floor_above_target_fails() {
    let mut s = schema();
    if let Some(thresh) = s.thresholds.get_mut("performance_delta") {
        thresh.floor_millionths = 999_999;
        thresh.target_millionths = 100;
    }

    let result = s.validate();
    assert!(matches!(
        result,
        Err(ScorecardError::InvalidThreshold { .. })
    ));
}

// ---------------------------------------------------------------------------
// Evidence validation
// ---------------------------------------------------------------------------

#[test]
fn empty_evidence_bundle_fails() {
    let s = schema();
    let result = compute_scorecard(&s, &[], epoch(), "env".to_string());
    assert!(matches!(result, Err(ScorecardError::EmptyEvidenceBundle)));
}

#[test]
fn missing_dimension_evidence_fails() {
    let s = schema();
    // Only provide two of three dimensions
    let ev = vec![
        evidence(DisruptionDimension::PerformanceDelta, 150_000, &["bd-1ze"]),
        evidence(DisruptionDimension::SecurityDelta, 750_000, &["bd-3rd"]),
        // Missing AutonomyDelta
    ];
    let result = compute_scorecard(&s, &ev, epoch(), "env".to_string());
    assert!(matches!(
        result,
        Err(ScorecardError::MissingEvidence { .. })
    ));
}

// ---------------------------------------------------------------------------
// History and regression detection
// ---------------------------------------------------------------------------

#[test]
fn history_regression_detection() {
    let s = schema();
    let mut history = ScorecardHistory::new();

    // First result: good scores
    let ev1 = all_exceeding_targets();
    let r1 = compute_scorecard(&s, &ev1, epoch(), "env".to_string()).unwrap();
    history.append("rc-1".to_string(), "2026-02-24T00:00:00Z".to_string(), r1);
    assert!(!history.has_regression());

    // Second result: score regresses
    let ev2 = vec![
        evidence(DisruptionDimension::PerformanceDelta, 100_000, &["bd-1ze"]), // dropped from 200k
        evidence(DisruptionDimension::SecurityDelta, 800_000, &["bd-3rd"]),    // dropped from 900k
        evidence(DisruptionDimension::AutonomyDelta, 950_000, &["bd-181"]),    // same
    ];
    let r2 = compute_scorecard(&s, &ev2, epoch(), "env".to_string()).unwrap();
    history.append("rc-2".to_string(), "2026-02-24T01:00:00Z".to_string(), r2);
    assert!(history.has_regression());
}

#[test]
fn history_no_regression_when_scores_improve() {
    let s = schema();
    let mut history = ScorecardHistory::new();

    let ev1 = all_passing_evidence();
    let r1 = compute_scorecard(&s, &ev1, epoch(), "env".to_string()).unwrap();
    history.append("rc-1".to_string(), "2026-02-24T00:00:00Z".to_string(), r1);

    let ev2 = all_exceeding_targets();
    let r2 = compute_scorecard(&s, &ev2, epoch(), "env".to_string()).unwrap();
    history.append("rc-2".to_string(), "2026-02-24T01:00:00Z".to_string(), r2);

    assert!(!history.has_regression());
}

#[test]
fn history_single_entry_no_regression() {
    let s = schema();
    let mut history = ScorecardHistory::new();

    let ev = all_failing_evidence();
    let r = compute_scorecard(&s, &ev, epoch(), "env".to_string()).unwrap();
    history.append("rc-1".to_string(), "2026-02-24T00:00:00Z".to_string(), r);

    assert!(!history.has_regression()); // Can't regress with only one entry
}

#[test]
fn history_empty_no_regression() {
    let history = ScorecardHistory::new();
    assert!(!history.has_regression());
    assert!(history.latest().is_none());
}

// ---------------------------------------------------------------------------
// Structured logging
// ---------------------------------------------------------------------------

#[test]
fn log_entries_match_dimensions() {
    let s = schema();
    let ev = all_passing_evidence();
    let result = compute_scorecard(&s, &ev, epoch(), "env".to_string()).unwrap();
    let logs = generate_log_entries("trace-log", &result);

    assert_eq!(logs.len(), 3);

    // All entries have correct trace_id and schema version
    for log in &logs {
        assert_eq!(log.trace_id, "trace-log");
        assert_eq!(log.scorecard_version, SCORECARD_SCHEMA_VERSION);
        assert!(!log.evidence_refs.is_empty());
    }

    // Dimensions are all represented
    let dims: Vec<_> = logs.iter().map(|l| l.dimension).collect();
    assert!(dims.contains(&DisruptionDimension::PerformanceDelta));
    assert!(dims.contains(&DisruptionDimension::SecurityDelta));
    assert!(dims.contains(&DisruptionDimension::AutonomyDelta));
}

#[test]
fn log_entries_for_failing_result() {
    let s = schema();
    let ev = all_failing_evidence();
    let result = compute_scorecard(&s, &ev, epoch(), "env".to_string()).unwrap();
    let logs = generate_log_entries("trace-fail", &result);

    let failing: Vec<_> = logs.iter().filter(|l| !l.pass).collect();
    assert!(!failing.is_empty());

    // Thresholds match schema
    for log in &logs {
        let dim_key = log.dimension.as_str();
        let threshold = s.thresholds.get(dim_key).unwrap();
        assert_eq!(log.threshold_floor_millionths, threshold.floor_millionths);
        assert_eq!(log.threshold_target_millionths, threshold.target_millionths);
    }
}

// ---------------------------------------------------------------------------
// Threshold behavior
// ---------------------------------------------------------------------------

#[test]
fn score_exactly_at_floor_passes() {
    let s = schema();
    let ev = vec![
        evidence(DisruptionDimension::PerformanceDelta, 0, &["bd-1ze"]), // floor is 0
        evidence(DisruptionDimension::SecurityDelta, 500_000, &["bd-3rd"]), // floor is 500k
        evidence(DisruptionDimension::AutonomyDelta, 600_000, &["bd-181"]), // floor is 600k
    ];
    let r = compute_scorecard(&s, &ev, epoch(), "env".to_string()).unwrap();
    assert_eq!(r.outcome, ScorecardOutcome::Pass);
}

#[test]
fn score_one_below_floor_fails() {
    let s = schema();
    let ev = vec![
        evidence(DisruptionDimension::PerformanceDelta, 150_000, &["bd-1ze"]),
        evidence(DisruptionDimension::SecurityDelta, 499_999, &["bd-3rd"]), // one below floor
        evidence(DisruptionDimension::AutonomyDelta, 800_000, &["bd-181"]),
    ];
    let r = compute_scorecard(&s, &ev, epoch(), "env".to_string()).unwrap();
    assert_eq!(r.outcome, ScorecardOutcome::Fail);
    assert!(!passes_release_gate(&r));
}

#[test]
fn score_exactly_at_target_meets_target() {
    let s = schema();
    let ev = vec![
        evidence(DisruptionDimension::PerformanceDelta, 100_000, &["bd-1ze"]), // target is 100k
        evidence(DisruptionDimension::SecurityDelta, 800_000, &["bd-3rd"]),    // target is 800k
        evidence(DisruptionDimension::AutonomyDelta, 900_000, &["bd-181"]),    // target is 900k
    ];
    let r = compute_scorecard(&s, &ev, epoch(), "env".to_string()).unwrap();
    assert_eq!(r.targets_met, 3);
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn scorecard_result_serde_roundtrip() {
    let s = schema();
    let ev = all_passing_evidence();
    let result = compute_scorecard(&s, &ev, epoch(), "env".to_string()).unwrap();

    let json = serde_json::to_string(&result).unwrap();
    let restored: ScorecardResult = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.outcome, result.outcome);
    assert_eq!(restored.result_hash, result.result_hash);
    assert_eq!(restored.targets_met, result.targets_met);
    assert_eq!(restored.dimension_scores, result.dimension_scores);
}

#[test]
fn scorecard_schema_serde_roundtrip() {
    let s = schema();
    let json = serde_json::to_string(&s).unwrap();
    let restored: ScorecardSchema = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.version, s.version);
    assert_eq!(restored.thresholds.len(), 3);
    assert_eq!(restored.evidence_sources, s.evidence_sources);
}

#[test]
fn scorecard_history_serde_roundtrip() {
    let s = schema();
    let mut history = ScorecardHistory::new();

    for i in 0..3 {
        let ev = vec![
            evidence(
                DisruptionDimension::PerformanceDelta,
                100_000 + i * 10_000,
                &["bd-1ze"],
            ),
            evidence(
                DisruptionDimension::SecurityDelta,
                600_000 + i * 10_000,
                &["bd-3rd"],
            ),
            evidence(
                DisruptionDimension::AutonomyDelta,
                700_000 + i * 10_000,
                &["bd-181"],
            ),
        ];
        let r = compute_scorecard(&s, &ev, epoch(), "env".to_string()).unwrap();
        history.append(format!("rc-{i}"), format!("2026-02-24T0{i}:00:00Z"), r);
    }

    let json = serde_json::to_string(&history).unwrap();
    let restored: ScorecardHistory = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.len(), 3);
    assert_eq!(restored.latest().unwrap().candidate_id, "rc-2");
}

// ---------------------------------------------------------------------------
// DimensionThreshold edge cases
// ---------------------------------------------------------------------------

#[test]
fn threshold_floor_equals_target_is_valid() {
    let t = DimensionThreshold {
        dimension: DisruptionDimension::PerformanceDelta,
        floor_millionths: 500_000,
        target_millionths: 500_000,
        description: "test".to_string(),
    };
    assert!(t.is_valid());
    assert!(t.meets_floor(500_000));
    assert!(t.meets_target(500_000));
    assert!(!t.meets_floor(499_999));
}

#[test]
fn threshold_zero_floor_zero_target() {
    let t = DimensionThreshold {
        dimension: DisruptionDimension::SecurityDelta,
        floor_millionths: 0,
        target_millionths: 0,
        description: "test".to_string(),
    };
    assert!(t.is_valid());
    assert!(t.meets_floor(0));
    assert!(t.meets_target(0));
}

// ---------------------------------------------------------------------------
// DimensionScore computation
// ---------------------------------------------------------------------------

#[test]
fn dimension_score_compute() {
    let t = DimensionThreshold {
        dimension: DisruptionDimension::PerformanceDelta,
        floor_millionths: 100_000,
        target_millionths: 500_000,
        description: "test".to_string(),
    };

    let score = DimensionScore::compute(
        DisruptionDimension::PerformanceDelta,
        300_000,
        &t,
        vec!["bd-1ze".to_string()],
    );

    assert_eq!(score.dimension, DisruptionDimension::PerformanceDelta);
    assert_eq!(score.raw_score_millionths, 300_000);
    assert!(score.meets_floor);
    assert!(!score.meets_target);
    assert_eq!(score.floor_millionths, 100_000);
    assert_eq!(score.target_millionths, 500_000);
    assert_eq!(score.evidence_refs, vec!["bd-1ze"]);
}

// ---------------------------------------------------------------------------
// Display traits
// ---------------------------------------------------------------------------

#[test]
fn dimension_display_coverage() {
    for dim in DisruptionDimension::all() {
        let s = format!("{dim}");
        assert!(!s.is_empty());
        assert_eq!(s, dim.as_str());
    }
}

#[test]
fn outcome_display_coverage() {
    assert_eq!(format!("{}", ScorecardOutcome::Pass), "pass");
    assert_eq!(format!("{}", ScorecardOutcome::Fail), "fail");
    assert!(ScorecardOutcome::Pass.is_pass());
    assert!(!ScorecardOutcome::Fail.is_pass());
}

// ---------------------------------------------------------------------------
// Error display coverage
// ---------------------------------------------------------------------------

#[test]
fn error_display_all_variants() {
    let errors: Vec<ScorecardError> = vec![
        ScorecardError::MissingDimension {
            dimension: "security_delta".to_string(),
        },
        ScorecardError::InvalidThreshold {
            dimension: "performance_delta".to_string(),
            detail: "floor > target".to_string(),
        },
        ScorecardError::MissingEvidence {
            dimension: "autonomy_delta".to_string(),
        },
        ScorecardError::EmptyEvidenceBundle,
        ScorecardError::SchemaValidationFailed {
            detail: "bad schema".to_string(),
        },
    ];
    for err in &errors {
        let s = format!("{err}");
        assert!(!s.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_are_stable() {
    assert_eq!(SCORECARD_COMPONENT, "disruption_scorecard");
    assert_eq!(
        SCORECARD_SCHEMA_VERSION,
        "franken-engine.disruption-scorecard.v1"
    );
}

// ---------------------------------------------------------------------------
// Evidence bundle hash determinism
// ---------------------------------------------------------------------------

#[test]
fn evidence_bundle_hash_deterministic() {
    let s = schema();
    let ev = all_passing_evidence();

    let r1 = compute_scorecard(&s, &ev, epoch(), "env".to_string()).unwrap();
    let r2 = compute_scorecard(&s, &ev, epoch(), "env".to_string()).unwrap();

    assert_eq!(r1.evidence_bundle_hash, r2.evidence_bundle_hash);
}

#[test]
fn evidence_order_does_not_affect_bundle_hash() {
    let s = schema();

    let ev1 = vec![
        evidence(DisruptionDimension::PerformanceDelta, 150_000, &["bd-1ze"]),
        evidence(DisruptionDimension::SecurityDelta, 750_000, &["bd-3rd"]),
        evidence(DisruptionDimension::AutonomyDelta, 800_000, &["bd-181"]),
    ];
    let ev2 = vec![
        evidence(DisruptionDimension::AutonomyDelta, 800_000, &["bd-181"]),
        evidence(DisruptionDimension::PerformanceDelta, 150_000, &["bd-1ze"]),
        evidence(DisruptionDimension::SecurityDelta, 750_000, &["bd-3rd"]),
    ];

    let r1 = compute_scorecard(&s, &ev1, epoch(), "env".to_string()).unwrap();
    let r2 = compute_scorecard(&s, &ev2, epoch(), "env".to_string()).unwrap();

    // Evidence hashes are sorted inside compute_scorecard, so order shouldn't matter
    assert_eq!(r1.evidence_bundle_hash, r2.evidence_bundle_hash);
    assert_eq!(r1.result_hash, r2.result_hash);
    assert_eq!(r1.outcome, r2.outcome);
}

// ---------------------------------------------------------------------------
// Additional serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn disruption_dimension_serde_roundtrip() {
    for dim in DisruptionDimension::all() {
        let json = serde_json::to_string(dim).unwrap();
        let restored: DisruptionDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*dim, restored);
    }
}

#[test]
fn scorecard_outcome_serde_roundtrip() {
    for outcome in [ScorecardOutcome::Pass, ScorecardOutcome::Fail] {
        let json = serde_json::to_string(&outcome).unwrap();
        let restored: ScorecardOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, restored);
    }
}

#[test]
fn scorecard_error_serde_roundtrip() {
    let errors = vec![
        ScorecardError::MissingDimension {
            dimension: "security_delta".to_string(),
        },
        ScorecardError::InvalidThreshold {
            dimension: "perf".to_string(),
            detail: "floor > target".to_string(),
        },
        ScorecardError::MissingEvidence {
            dimension: "autonomy_delta".to_string(),
        },
        ScorecardError::EmptyEvidenceBundle,
        ScorecardError::SchemaValidationFailed {
            detail: "bad".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: ScorecardError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

#[test]
fn dimension_threshold_serde_roundtrip() {
    let t = DimensionThreshold {
        dimension: DisruptionDimension::SecurityDelta,
        floor_millionths: 500_000,
        target_millionths: 800_000,
        description: "security threshold".to_string(),
    };
    let json = serde_json::to_string(&t).unwrap();
    let restored: DimensionThreshold = serde_json::from_str(&json).unwrap();
    assert_eq!(t, restored);
}

#[test]
fn evidence_input_serde_roundtrip() {
    let ev = evidence(
        DisruptionDimension::PerformanceDelta,
        150_000,
        &["bd-1ze", "bd-2rx"],
    );
    let json = serde_json::to_string(&ev).unwrap();
    let restored: EvidenceInput = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, restored);
}

#[test]
fn dimension_score_serde_roundtrip() {
    let t = DimensionThreshold {
        dimension: DisruptionDimension::AutonomyDelta,
        floor_millionths: 600_000,
        target_millionths: 900_000,
        description: "test".to_string(),
    };
    let score = DimensionScore::compute(
        DisruptionDimension::AutonomyDelta,
        750_000,
        &t,
        vec!["bd-181".to_string()],
    );
    let json = serde_json::to_string(&score).unwrap();
    let restored: DimensionScore = serde_json::from_str(&json).unwrap();
    assert_eq!(score, restored);
}

#[test]
fn scorecard_log_entry_serde_roundtrip() {
    let s = schema();
    let ev = all_passing_evidence();
    let result = compute_scorecard(&s, &ev, epoch(), "env".to_string()).unwrap();
    let logs = generate_log_entries("trace-serde", &result);
    for log in &logs {
        let json = serde_json::to_string(log).unwrap();
        let restored: ScorecardLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(*log, restored);
    }
}

#[test]
fn history_entry_serde_roundtrip() {
    let s = schema();
    let ev = all_passing_evidence();
    let result = compute_scorecard(&s, &ev, epoch(), "env".to_string()).unwrap();
    let entry = HistoryEntry {
        candidate_id: "rc-serde".to_string(),
        timestamp: "2026-03-11T00:00:00Z".to_string(),
        result,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let restored: HistoryEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, restored);
}

// ---------------------------------------------------------------------------
// Additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn history_default_is_empty() {
    let history = ScorecardHistory::default();
    assert!(history.is_empty());
    assert_eq!(history.len(), 0);
}

#[test]
fn history_equal_scores_no_regression() {
    let s = schema();
    let mut history = ScorecardHistory::new();
    let ev = all_passing_evidence();

    let r1 = compute_scorecard(&s, &ev, epoch(), "env".to_string()).unwrap();
    let r2 = compute_scorecard(&s, &ev, epoch(), "env".to_string()).unwrap();

    history.append("rc-1".to_string(), "2026-03-11T00:00:00Z".to_string(), r1);
    history.append("rc-2".to_string(), "2026-03-11T01:00:00Z".to_string(), r2);

    assert!(!history.has_regression());
}

#[test]
fn scorecard_result_compute_hash_consistency() {
    let s = schema();
    let ev = all_passing_evidence();
    let result = compute_scorecard(&s, &ev, epoch(), "env".to_string()).unwrap();

    // compute_hash should return same as stored result_hash
    assert_eq!(result.compute_hash(), result.result_hash);
    // Calling compute_hash multiple times is deterministic
    assert_eq!(result.compute_hash(), result.compute_hash());
}

#[test]
fn outcome_as_str() {
    assert_eq!(ScorecardOutcome::Pass.as_str(), "pass");
    assert_eq!(ScorecardOutcome::Fail.as_str(), "fail");
}

#[test]
fn dimension_as_str_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for dim in DisruptionDimension::all() {
        assert!(seen.insert(dim.as_str()), "duplicate: {}", dim.as_str());
    }
}
