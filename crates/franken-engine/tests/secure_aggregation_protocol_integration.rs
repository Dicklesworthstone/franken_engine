//! QQ.2 (`bd-cixqu.43.2`) integration tests for the secure aggregation
//! protocol module. Exercises the full Bonawitz 2017 round-trip end-to-end via
//! the engine's [`secure_aggregation`] orchestration over the `dp` primitive,
//! with N ∈ {3, 7, 25}, asserting both the cryptographic correctness (the
//! aggregator learns only the field sum) and the fail-closed failure modes
//! (dropped / malicious / malformed peers reject rather than degrade).

use frankenengine_engine::secure_aggregation::{
    DEFAULT_FIELD_MODULUS, HONEST_MAJORITY_MIN_PARTICIPANTS, PeerInput, SecureAggregationEvent,
    SecureAggregationOutcome, SecureAggregationReject, SecureAggregationRound, append_event_line,
    collusion_threshold_k,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use rand::SeedableRng;
use rand::rngs::StdRng;

const NS: [usize; 3] = [3, 7, 25];

fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

fn ids(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("fleet-peer-{i:03}")).collect()
}

fn round(n: usize, dimension: usize) -> SecureAggregationRound {
    SecureAggregationRound::new(
        format!("qq2-round-n{n}-d{dimension}"),
        SecurityEpoch::from_raw(42),
        ids(n),
        dimension,
    )
}

/// Distinct, deterministic per-peer cleartext contributions.
fn fleet_inputs(n: usize, dimension: usize) -> Vec<PeerInput> {
    ids(n)
        .into_iter()
        .enumerate()
        .map(|(i, id)| {
            let update = (0..dimension)
                .map(|c| ((i * 7 + c * 3 + 1) % 5000) as i64)
                .collect();
            PeerInput::new(id, update)
        })
        .collect()
}

fn cleartext_sum(inputs: &[PeerInput], dimension: usize) -> Vec<i64> {
    let mut sum = vec![0i64; dimension];
    for input in inputs {
        for (c, v) in input.update.iter().enumerate() {
            sum[c] += v;
        }
    }
    sum
}

// ---------------------------------------------------------------------------
// Round-trip correctness across N ∈ {3, 7, 25}
// ---------------------------------------------------------------------------

#[test]
fn round_trip_sum_n3() {
    let dimension = 4;
    let inputs = fleet_inputs(3, dimension);
    let outcome = round(3, dimension).run(&inputs, &mut rng(1));
    assert!(outcome.is_aggregated());
    assert_eq!(
        outcome.aggregate().unwrap(),
        cleartext_sum(&inputs, dimension)
    );
}

#[test]
fn round_trip_sum_n7() {
    let dimension = 6;
    let inputs = fleet_inputs(7, dimension);
    let outcome = round(7, dimension).run(&inputs, &mut rng(2));
    assert!(outcome.is_aggregated());
    assert_eq!(
        outcome.aggregate().unwrap(),
        cleartext_sum(&inputs, dimension)
    );
}

#[test]
fn round_trip_sum_n25() {
    let dimension = 8;
    let inputs = fleet_inputs(25, dimension);
    let outcome = round(25, dimension).run(&inputs, &mut rng(3));
    assert!(outcome.is_aggregated());
    assert_eq!(
        outcome.aggregate().unwrap(),
        cleartext_sum(&inputs, dimension)
    );
}

#[test]
fn round_trip_all_ns_multiple_dimensions() {
    for (idx, &n) in NS.iter().enumerate() {
        for dimension in [1usize, 2, 5, 10] {
            let inputs = fleet_inputs(n, dimension);
            let outcome = round(n, dimension)
                .run(&inputs, &mut rng(100 + idx as u64 * 11 + dimension as u64));
            assert!(
                outcome.is_aggregated(),
                "n={n} d={dimension} should aggregate"
            );
            assert_eq!(
                outcome.aggregate().unwrap(),
                cleartext_sum(&inputs, dimension),
                "n={n} d={dimension} sum mismatch"
            );
        }
    }
}

#[test]
fn round_trip_zero_vectors_all_ns() {
    for &n in &NS {
        let dimension = 3;
        let inputs: Vec<PeerInput> = ids(n)
            .into_iter()
            .map(|id| PeerInput::new(id, vec![0; dimension]))
            .collect();
        let outcome = round(n, dimension).run(&inputs, &mut rng(n as u64));
        assert_eq!(outcome.aggregate().unwrap(), &vec![0; dimension][..]);
    }
}

#[test]
fn round_trip_uniform_inputs_all_ns() {
    for &n in &NS {
        let dimension = 4;
        let inputs: Vec<PeerInput> = ids(n)
            .into_iter()
            .map(|id| PeerInput::new(id, vec![3, 5, 7, 11]))
            .collect();
        let outcome = round(n, dimension).run(&inputs, &mut rng(n as u64 + 7));
        let expected: Vec<i64> = [3, 5, 7, 11].iter().map(|v| v * n as i64).collect();
        assert_eq!(outcome.aggregate().unwrap(), expected.as_slice());
    }
}

#[test]
fn aggregate_independent_of_masking_rng_all_ns() {
    for &n in &NS {
        let dimension = 5;
        let inputs = fleet_inputs(n, dimension);
        let a = round(n, dimension).run(&inputs, &mut rng(11));
        let b = round(n, dimension).run(&inputs, &mut rng(987_654));
        assert_eq!(a.aggregate().unwrap(), b.aggregate().unwrap(), "n={n}");
    }
}

#[test]
fn masked_aggregate_not_equal_to_any_individual_all_ns() {
    // Privacy smoke check: the published sum is not any one peer's vector.
    for &n in &NS {
        let dimension = 6;
        let inputs = fleet_inputs(n, dimension);
        let outcome = round(n, dimension).run(&inputs, &mut rng(55 + n as u64));
        let agg = outcome.aggregate().unwrap();
        for input in &inputs {
            assert_ne!(agg, input.update.as_slice(), "n={n}");
        }
    }
}

#[test]
fn large_field_values_round_trip_all_ns() {
    for &n in &NS {
        let dimension = 2;
        // Keep the true sum below the field modulus so the field sum is exact.
        let per = (DEFAULT_FIELD_MODULUS as i64 - 1) / (n as i64 + 1);
        let inputs: Vec<PeerInput> = ids(n)
            .into_iter()
            .map(|id| PeerInput::new(id, vec![per, per / 2]))
            .collect();
        let outcome = round(n, dimension).run(&inputs, &mut rng(n as u64 * 3));
        assert_eq!(
            outcome.aggregate().unwrap(),
            &[per * n as i64, (per / 2) * n as i64]
        );
    }
}

// ---------------------------------------------------------------------------
// Fail-closed: dropped peers
// ---------------------------------------------------------------------------

#[test]
fn dropout_rejects_n3() {
    let dimension = 3;
    let mut inputs = fleet_inputs(3, dimension);
    inputs.pop();
    let outcome = round(3, dimension).run(&inputs, &mut rng(4));
    assert!(matches!(
        outcome.reject_reason(),
        Some(SecureAggregationReject::DroppedPeer { .. })
    ));
    assert!(outcome.aggregate().is_none());
}

#[test]
fn dropout_rejects_n7() {
    let dimension = 3;
    let mut inputs = fleet_inputs(7, dimension);
    inputs.remove(0);
    let outcome = round(7, dimension).run(&inputs, &mut rng(5));
    assert!(matches!(
        outcome.reject_reason(),
        Some(SecureAggregationReject::DroppedPeer { .. })
    ));
}

#[test]
fn dropout_rejects_n25() {
    let dimension = 3;
    let mut inputs = fleet_inputs(25, dimension);
    inputs.remove(12);
    let outcome = round(25, dimension).run(&inputs, &mut rng(6));
    assert!(matches!(
        outcome.reject_reason(),
        Some(SecureAggregationReject::DroppedPeer { .. })
    ));
}

#[test]
fn multiple_dropouts_reject_all_ns() {
    for &n in &NS {
        let dimension = 3;
        let mut inputs = fleet_inputs(n, dimension);
        inputs.truncate(n - 2.min(n - 1)); // drop a couple
        let outcome = round(n, dimension).run(&inputs, &mut rng(700 + n as u64));
        assert!(!outcome.is_aggregated(), "n={n} must reject on dropout");
    }
}

#[test]
fn no_submissions_rejects_all_ns() {
    for &n in &NS {
        let outcome = round(n, 3).run(&[], &mut rng(800 + n as u64));
        assert!(matches!(
            outcome.reject_reason(),
            Some(SecureAggregationReject::DroppedPeer { .. })
        ));
    }
}

// ---------------------------------------------------------------------------
// Fail-closed: malicious peers
// ---------------------------------------------------------------------------

#[test]
fn malicious_peer_rejects_n3() {
    let dimension = 3;
    let mut inputs = fleet_inputs(3, dimension);
    inputs[1].malicious_evidence = Some("commitment mismatch".to_string());
    let outcome = round(3, dimension).run(&inputs, &mut rng(7));
    assert!(matches!(
        outcome.reject_reason(),
        Some(SecureAggregationReject::MaliciousPeer { .. })
    ));
}

#[test]
fn malicious_peer_rejects_n7() {
    let dimension = 4;
    let mut inputs = fleet_inputs(7, dimension);
    inputs[3] = PeerInput::flagged_malicious(
        inputs[3].participant_id.clone(),
        vec![1, 2, 3, 4],
        "bad sig",
    );
    let outcome = round(7, dimension).run(&inputs, &mut rng(8));
    assert!(matches!(
        outcome.reject_reason(),
        Some(SecureAggregationReject::MaliciousPeer { .. })
    ));
}

#[test]
fn malicious_peer_rejects_n25() {
    let dimension = 2;
    let mut inputs = fleet_inputs(25, dimension);
    inputs[24].malicious_evidence = Some("replayed round".to_string());
    let outcome = round(25, dimension).run(&inputs, &mut rng(9));
    assert!(matches!(
        outcome.reject_reason(),
        Some(SecureAggregationReject::MaliciousPeer { .. })
    ));
}

// ---------------------------------------------------------------------------
// Fail-closed: malformed / protocol-violating submissions
// ---------------------------------------------------------------------------

#[test]
fn dimension_mismatch_rejects_all_ns() {
    for &n in &NS {
        let dimension = 4;
        let mut inputs = fleet_inputs(n, dimension);
        inputs[0] = PeerInput::new(inputs[0].participant_id.clone(), vec![1, 2]);
        let outcome = round(n, dimension).run(&inputs, &mut rng(300 + n as u64));
        assert!(
            matches!(
                outcome.reject_reason(),
                Some(SecureAggregationReject::DimensionMismatch { .. })
            ),
            "n={n}"
        );
    }
}

#[test]
fn negative_value_rejects_all_ns() {
    for &n in &NS {
        let dimension = 3;
        let mut inputs = fleet_inputs(n, dimension);
        inputs[n / 2] = PeerInput::new(inputs[n / 2].participant_id.clone(), vec![1, -7, 3]);
        let outcome = round(n, dimension).run(&inputs, &mut rng(400 + n as u64));
        assert!(
            matches!(
                outcome.reject_reason(),
                Some(SecureAggregationReject::FieldBoundViolation { .. })
            ),
            "n={n}"
        );
    }
}

#[test]
fn out_of_field_value_rejects_all_ns() {
    for &n in &NS {
        let dimension = 2;
        let mut inputs = fleet_inputs(n, dimension);
        inputs[0] = PeerInput::new(
            inputs[0].participant_id.clone(),
            vec![DEFAULT_FIELD_MODULUS as i64 + 1, 0],
        );
        let outcome = round(n, dimension).run(&inputs, &mut rng(500 + n as u64));
        assert!(
            matches!(
                outcome.reject_reason(),
                Some(SecureAggregationReject::FieldBoundViolation { .. })
            ),
            "n={n}"
        );
    }
}

#[test]
fn duplicate_peer_rejects_all_ns() {
    for &n in &NS {
        let dimension = 3;
        let mut inputs = fleet_inputs(n, dimension);
        let dup = inputs[0].clone();
        inputs.push(dup);
        let outcome = round(n, dimension).run(&inputs, &mut rng(600 + n as u64));
        assert!(
            matches!(
                outcome.reject_reason(),
                Some(SecureAggregationReject::DuplicatePeer { .. })
            ),
            "n={n}"
        );
    }
}

#[test]
fn unexpected_peer_rejects_all_ns() {
    for &n in &NS {
        let dimension = 3;
        let mut inputs = fleet_inputs(n, dimension);
        inputs[0] = PeerInput::new("stranger", vec![1, 1, 1]);
        let outcome = round(n, dimension).run(&inputs, &mut rng(900 + n as u64));
        assert!(
            matches!(
                outcome.reject_reason(),
                Some(SecureAggregationReject::UnexpectedPeer { .. })
            ),
            "n={n}"
        );
    }
}

// ---------------------------------------------------------------------------
// Honest-majority threshold
// ---------------------------------------------------------------------------

#[test]
fn collusion_threshold_matches_round_n() {
    for &n in &NS {
        assert_eq!(
            round(n, 1).collusion_threshold_k(),
            collusion_threshold_k(n)
        );
    }
    assert_eq!(round(3, 1).collusion_threshold_k(), 0);
    assert_eq!(round(7, 1).collusion_threshold_k(), 2);
    assert_eq!(round(25, 1).collusion_threshold_k(), 8);
}

#[test]
fn below_honest_majority_floor_rejects() {
    for n in 0..HONEST_MAJORITY_MIN_PARTICIPANTS {
        let r = SecureAggregationRound::new("tiny", SecurityEpoch::from_raw(1), ids(n), 2);
        let outcome = r.run(&fleet_inputs(n, 2), &mut rng(n as u64));
        assert!(!outcome.is_aggregated(), "n={n} must not aggregate");
    }
}

// ---------------------------------------------------------------------------
// bd-cixqu.45 logging
// ---------------------------------------------------------------------------

#[test]
fn logged_aggregated_event_fields_all_ns() {
    for &n in &NS {
        let dimension = 4;
        let inputs = fleet_inputs(n, dimension);
        let (outcome, event) = round(n, dimension).run_logged(&inputs, &mut rng(n as u64 + 1));
        assert!(outcome.is_aggregated());
        assert_eq!(event.event, "secure_aggregation_round_aggregated");
        assert!(event.aggregated);
        assert_eq!(event.participant_count, n as u32);
        assert_eq!(event.expected_participant_count, n as u32);
        assert_eq!(event.collusion_threshold_k, collusion_threshold_k(n));
        assert_eq!(event.aggregate_dimension, dimension);
        assert_eq!(event.epoch, 42);
    }
}

#[test]
fn logged_rejected_event_fields_all_ns() {
    for &n in &NS {
        let dimension = 3;
        let mut inputs = fleet_inputs(n, dimension);
        inputs.pop();
        let (outcome, event) = round(n, dimension).run_logged(&inputs, &mut rng(n as u64 + 2));
        assert!(!outcome.is_aggregated());
        assert_eq!(event.event, "secure_aggregation_round_rejected");
        assert!(!event.aggregated);
        assert_eq!(event.outcome, "dropped_peer");
        assert_eq!(event.aggregate_dimension, 0);
    }
}

#[test]
fn event_jsonl_round_trips_all_ns() {
    for &n in &NS {
        let inputs = fleet_inputs(n, 3);
        let (_o, event) = round(n, 3).run_logged(&inputs, &mut rng(n as u64 + 3));
        let line = event.to_jsonl();
        assert!(!line.contains('\n'));
        let parsed: SecureAggregationEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed, event);
    }
}

#[test]
fn events_jsonl_file_accumulates_one_line_per_round() {
    let dir = std::env::temp_dir().join(format!("qq2_int_events_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("events.jsonl");
    let _ = std::fs::remove_file(&path);

    let mut emitted = 0;
    for &n in &NS {
        // one accepted + one rejected round per n
        let (_o, accepted) = round(n, 3).run_logged(&fleet_inputs(n, 3), &mut rng(n as u64));
        append_event_line(&path, &accepted).unwrap();
        emitted += 1;

        let mut dropped = fleet_inputs(n, 3);
        dropped.pop();
        let (_o, rejected) = round(n, 3).run_logged(&dropped, &mut rng(n as u64 + 1));
        append_event_line(&path, &rejected).unwrap();
        emitted += 1;
    }

    let contents = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), emitted);
    let mut aggregated = 0;
    let mut rejected = 0;
    for line in lines {
        let ev: SecureAggregationEvent = serde_json::from_str(line).unwrap();
        if ev.aggregated {
            aggregated += 1;
        } else {
            rejected += 1;
        }
    }
    assert_eq!(aggregated, NS.len());
    assert_eq!(rejected, NS.len());
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// Outcome serde + structural invariants
// ---------------------------------------------------------------------------

#[test]
fn outcome_serde_round_trips_all_ns() {
    for &n in &NS {
        let outcome = round(n, 3).run(&fleet_inputs(n, 3), &mut rng(n as u64 + 4));
        let json = serde_json::to_string(&outcome).unwrap();
        let parsed: SecureAggregationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, outcome);
    }
}

#[test]
fn aggregated_outcome_dimension_matches_input_all_ns() {
    for &n in &NS {
        for dimension in [1usize, 3, 9] {
            let outcome = round(n, dimension).run(
                &fleet_inputs(n, dimension),
                &mut rng(n as u64 + dimension as u64),
            );
            assert_eq!(outcome.aggregate().unwrap().len(), dimension);
        }
    }
}

#[test]
fn repeated_rounds_are_stable_all_ns() {
    for &n in &NS {
        let inputs = fleet_inputs(n, 4);
        let first = round(n, 4).run(&inputs, &mut rng(1));
        for trial in 0..3 {
            let again = round(n, 4).run(&inputs, &mut rng(1000 + trial));
            assert_eq!(
                first.aggregate().unwrap(),
                again.aggregate().unwrap(),
                "n={n}"
            );
        }
    }
}

#[test]
fn order_of_submission_does_not_change_aggregate_all_ns() {
    for &n in &NS {
        let dimension = 5;
        let inputs = fleet_inputs(n, dimension);
        let mut reversed = inputs.clone();
        reversed.reverse();
        let forward = round(n, dimension).run(&inputs, &mut rng(21));
        let backward = round(n, dimension).run(&reversed, &mut rng(21));
        assert_eq!(
            forward.aggregate().unwrap(),
            backward.aggregate().unwrap(),
            "n={n}"
        );
    }
}
