//! Integration coverage for the public moonshot disruption track API.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::disruption_scorecard::{
    DisruptionDimension, ScorecardOutcome, ScorecardSchema,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::moonshot_disruption_track::{
    DISRUPTION_TRACK_SCHEMA_VERSION, DisruptionTrackError, DisruptionTrackStatus, MoonshotGateId,
    MoonshotGateResult, MoonshotGateStatus, allows_frontier_release, execute_disruption_track,
    generate_log_entries,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn gate_score(gate_id: MoonshotGateId) -> u64 {
    match gate_id {
        MoonshotGateId::NodeBunComparisonHarness => 120_000,
        MoonshotGateId::DisruptionScorecard => 150_000,
        MoonshotGateId::AutonomousQuarantineMesh => 850_000,
        MoonshotGateId::ProofCarryingOptimization => 930_000,
        MoonshotGateId::AdversarialCampaignRunner => 820_000,
        MoonshotGateId::PlasCapabilityWitness => 910_000,
        MoonshotGateId::GaNativeLanes => 920_000,
        MoonshotGateId::DeterministicIfcProtection => 830_000,
        MoonshotGateId::ProofSpecializedLanes => 200_000,
        MoonshotGateId::CategoryShiftReport => 300_000,
    }
}

fn passing_result(gate_id: MoonshotGateId) -> MoonshotGateResult {
    MoonshotGateResult::pass(
        gate_id,
        gate_score(gate_id),
        ContentHash::compute(format!("{}:artifact", gate_id.bead_id()).as_bytes()),
        vec![gate_id.bead_id().to_string()],
        "2026-04-20T00:00:00Z".to_string(),
    )
}

fn passing_evidence() -> BTreeMap<MoonshotGateId, MoonshotGateResult> {
    MoonshotGateId::all()
        .iter()
        .copied()
        .map(|gate_id| (gate_id, passing_result(gate_id)))
        .collect()
}

#[test]
fn public_api_exposes_canonical_gate_track() {
    let gates = MoonshotGateId::all();
    assert_eq!(gates.len(), 10);
    assert_eq!(gates[0].bead_id(), "bd-1ze");
    assert_eq!(gates[9].bead_id(), "bd-f7n");
    assert_eq!(
        DISRUPTION_TRACK_SCHEMA_VERSION,
        "franken-engine.disruption-track.v1"
    );

    let bead_ids: BTreeSet<_> = gates.iter().map(|gate_id| gate_id.bead_id()).collect();
    assert_eq!(bead_ids.len(), gates.len());
    assert!(bead_ids.contains("bd-6pk"));
    assert!(bead_ids.contains("bd-uwc"));
    assert!(bead_ids.contains("bd-dkh"));

    let dimensions: BTreeSet<_> = gates
        .iter()
        .map(|gate_id| gate_id.primary_dimension())
        .collect();
    assert_eq!(dimensions.len(), 3);
    assert!(dimensions.contains(&DisruptionDimension::PerformanceDelta));
    assert!(dimensions.contains(&DisruptionDimension::SecurityDelta));
    assert!(dimensions.contains(&DisruptionDimension::AutonomyDelta));

    for gate_id in gates {
        assert_eq!(gate_id.to_string(), gate_id.bead_id());
        assert!(!gate_id.description().is_empty());
    }
}

#[test]
fn passing_track_aggregates_child_gates_into_three_scorecard_dimensions() {
    let evidence = passing_evidence();
    let execution = execute_disruption_track(
        &evidence,
        &ScorecardSchema::default_schema(),
        SecurityEpoch::from_raw(42),
        "integration-env".to_string(),
    )
    .expect("all passing gate evidence should compute a scorecard");

    assert_eq!(execution.overall_status(), DisruptionTrackStatus::Pass);
    assert!(execution.all_gates_complete());
    assert!(execution.all_gates_pass());
    assert!(allows_frontier_release(&execution));

    let scorecard = execution
        .scorecard_result
        .as_ref()
        .expect("passing track should attach a scorecard");
    assert_eq!(scorecard.outcome, ScorecardOutcome::Pass);
    assert_eq!(scorecard.dimensions_evaluated, 3);
    assert_eq!(
        scorecard.dimension_scores["performance_delta"].raw_score_millionths,
        120_000
    );
    assert_eq!(
        scorecard.dimension_scores["security_delta"].raw_score_millionths,
        820_000
    );
    assert_eq!(
        scorecard.dimension_scores["autonomy_delta"].raw_score_millionths,
        910_000
    );

    let logs = generate_log_entries("trace-moonshot", &execution);
    assert_eq!(logs.len(), 1 + MoonshotGateId::all().len());
    assert!(logs.iter().all(|entry| entry.trace_id == "trace-moonshot"));
}

#[test]
fn failing_child_gate_blocks_frontier_release_without_scorecard() {
    let mut evidence = passing_evidence();
    evidence.insert(
        MoonshotGateId::AdversarialCampaignRunner,
        MoonshotGateResult::fail(
            MoonshotGateId::AdversarialCampaignRunner,
            vec!["bd-3rd".to_string()],
            "2026-04-20T00:00:00Z".to_string(),
        ),
    );

    let execution = execute_disruption_track(
        &evidence,
        &ScorecardSchema::default_schema(),
        SecurityEpoch::from_raw(42),
        "integration-env".to_string(),
    )
    .expect("failed child gates should produce a completed track state");

    assert_eq!(execution.overall_status(), DisruptionTrackStatus::Fail);
    assert!(execution.all_gates_complete());
    assert!(!execution.all_gates_pass());
    assert!(execution.scorecard_result.is_none());
    assert!(!allows_frontier_release(&execution));

    let counts = execution.count_gates_by_status();
    assert_eq!(counts.get(&MoonshotGateStatus::Fail), Some(&1));
    assert_eq!(counts.get(&MoonshotGateStatus::Pass), Some(&9));
}

#[test]
fn passing_gate_missing_artifact_hash_is_rejected() {
    let mut evidence = passing_evidence();
    evidence.insert(
        MoonshotGateId::NodeBunComparisonHarness,
        MoonshotGateResult {
            gate_id: MoonshotGateId::NodeBunComparisonHarness,
            status: MoonshotGateStatus::Pass,
            evidence_score_millionths: Some(120_000),
            evidence_hash: None,
            error_message: None,
            implementation_beads: vec!["bd-1ze".to_string()],
            execution_timestamp: "2026-04-20T00:00:00Z".to_string(),
        },
    );

    let error = execute_disruption_track(
        &evidence,
        &ScorecardSchema::default_schema(),
        SecurityEpoch::from_raw(42),
        "integration-env".to_string(),
    )
    .expect_err("passing gate evidence without a hash must not be silently ignored");

    assert_eq!(
        error,
        DisruptionTrackError::InvalidEvidence {
            gate_id: "bd-1ze".to_string(),
            detail: "passing gate result is missing an evidence hash".to_string(),
        }
    );
}

#[test]
fn mismatched_gate_key_and_result_id_is_rejected() {
    let mut evidence = passing_evidence();
    evidence.insert(
        MoonshotGateId::NodeBunComparisonHarness,
        passing_result(MoonshotGateId::DisruptionScorecard),
    );

    let error = execute_disruption_track(
        &evidence,
        &ScorecardSchema::default_schema(),
        SecurityEpoch::from_raw(42),
        "integration-env".to_string(),
    )
    .expect_err("gate evidence keys must match embedded gate result IDs");

    assert_eq!(
        error,
        DisruptionTrackError::InvalidEvidence {
            gate_id: "bd-1ze".to_string(),
            detail: "gate evidence key does not match result gate id `bd-6pk`".to_string(),
        }
    );
}
