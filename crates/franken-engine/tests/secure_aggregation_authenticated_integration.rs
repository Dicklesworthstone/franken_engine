//! Complete-roster aggregation through the engine's authenticated public API.
//! Each participant owns its setup and masking state. Only serialized public
//! announcements and signed masked vectors cross the coordinator boundary.

use std::collections::BTreeMap;

use dp::ParticipantId;
use dp::key_exchange::{KeyAnnouncement, ParticipantKeySetup, SignedMaskedContribution};
use ed25519_dalek::SigningKey;
use frankenengine_engine::secure_aggregation::{
    DEFAULT_FIELD_MODULUS, SecureAggregationOutcome, SecureAggregationReject,
    SecureAggregationRound,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use rand::SeedableRng;
use rand::rngs::StdRng;

struct Transcript {
    identities: BTreeMap<ParticipantId, [u8; 32]>,
    announcements: Vec<KeyAnnouncement>,
    contributions: Vec<SignedMaskedContribution>,
    expected: Vec<i64>,
}

fn ids(n: usize) -> Vec<String> {
    (0..n)
        .map(|index| format!("independent-peer-{index:02}"))
        .collect()
}

fn round(n: usize) -> SecureAggregationRound {
    SecureAggregationRound::new(
        "authenticated-round",
        SecurityEpoch::from_raw(42),
        ids(n),
        3,
    )
}

fn transcript(round: &SecureAggregationRound, n: usize) -> Transcript {
    let signing_keys: Vec<_> = (0..n)
        .map(|index| SigningKey::from_bytes(&[index as u8 + 1; 32]))
        .collect();
    let identities: BTreeMap<_, _> = ids(n)
        .into_iter()
        .zip(&signing_keys)
        .map(|(id, key)| (ParticipantId(id), key.verifying_key().to_bytes()))
        .collect();
    let configuration = round.authenticated_configuration(&identities).unwrap();
    let setups: Vec<_> = ids(n)
        .into_iter()
        .zip(signing_keys)
        .enumerate()
        .map(|(index, (id, key))| {
            ParticipantKeySetup::new(
                &configuration,
                ParticipantId(id),
                key,
                &mut StdRng::seed_from_u64(1000 + index as u64),
            )
            .unwrap()
        })
        .collect();
    let announcements: Vec<KeyAnnouncement> = serde_json::from_slice(
        &serde_json::to_vec(
            &setups
                .iter()
                .map(|setup| setup.announcement())
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    )
    .unwrap();
    let mut expected = vec![0i64; 3];
    let contributions: Vec<_> = setups
        .into_iter()
        .enumerate()
        .map(|(index, setup)| {
            // Every independent participant verifies the complete public
            // transcript before agreeing keys and masking its own input.
            let keys = configuration.verify_announcements(&announcements).unwrap();
            let mut participant = setup.complete(&keys).unwrap();
            let input = [index as i64 + 2, -(index as i64 + 1), 0];
            for (sum, value) in expected.iter_mut().zip(input) {
                *sum = (*sum + value).rem_euclid(DEFAULT_FIELD_MODULUS as i64);
            }
            participant.mask(&input).unwrap()
        })
        .collect();
    let contributions =
        serde_json::from_slice(&serde_json::to_vec(&contributions).unwrap()).unwrap();
    Transcript {
        identities,
        announcements,
        contributions,
        expected,
    }
}

fn run(round: &SecureAggregationRound, transcript: &Transcript) -> SecureAggregationOutcome {
    round.run_authenticated(
        &transcript.identities,
        &transcript.announcements,
        &transcript.contributions,
    )
}

fn assert_rejected(outcome: SecureAggregationOutcome) {
    assert!(outcome.aggregate().is_none());
    assert!(matches!(
        outcome,
        SecureAggregationOutcome::Rejected {
            participant_count: 0,
            ..
        }
    ));
}

#[test]
fn independent_participants_aggregate_through_engine_for_all_fleet_sizes() {
    for n in [3, 7, 25] {
        let coordinator = round(n);
        let transcript = transcript(&coordinator, n);
        let outcome = run(&coordinator, &transcript);
        assert_eq!(outcome.aggregate(), Some(transcript.expected.as_slice()));
        assert!(matches!(outcome, SecureAggregationOutcome::Aggregated {
            participant_count, expected_count, epoch, ..
        } if participant_count == n as u32 && expected_count == n as u32
            && epoch == SecurityEpoch::from_raw(42)));
    }
}

#[test]
fn wire_order_does_not_change_authenticated_sum() {
    let coordinator = round(7);
    let mut transcript = transcript(&coordinator, 7);
    transcript.announcements.reverse();
    transcript.contributions.rotate_left(3);
    assert_eq!(
        run(&coordinator, &transcript).aggregate(),
        Some(transcript.expected.as_slice())
    );
}

#[test]
fn security_epoch_is_cryptographically_bound() {
    let transcript = transcript(&round(3), 3);
    let changed_epoch = SecureAggregationRound::new(
        "authenticated-round",
        SecurityEpoch::from_raw(43),
        ids(3),
        3,
    );
    assert_rejected(run(&changed_epoch, &transcript));
}

#[test]
fn round_dimension_and_modulus_are_cryptographically_bound() {
    let transcript = transcript(&round(3), 3);
    for changed_round in [
        SecureAggregationRound::new("another-round", SecurityEpoch::from_raw(42), ids(3), 3),
        SecureAggregationRound::new(
            "authenticated-round",
            SecurityEpoch::from_raw(42),
            ids(3),
            4,
        ),
        SecureAggregationRound::with_field_modulus(
            "authenticated-round",
            SecurityEpoch::from_raw(42),
            ids(3),
            3,
            65537,
        ),
    ] {
        assert_rejected(run(&changed_round, &transcript));
    }
}

#[test]
fn trusted_identity_roster_must_match_engine_policy() {
    let coordinator = round(3);
    let mut transcript = transcript(&coordinator, 3);
    let removed_id = ParticipantId(ids(3)[0].clone());
    let removed_key = transcript.identities.remove(&removed_id).unwrap();
    assert!(matches!(
        coordinator.authenticated_configuration(&transcript.identities),
        Err(SecureAggregationReject::DroppedPeer { .. })
    ));
    transcript.identities.insert(removed_id, removed_key);
    transcript.identities.insert(
        ParticipantId("unexpected-peer".into()),
        SigningKey::from_bytes(&[99; 32]).verifying_key().to_bytes(),
    );
    assert!(matches!(
        coordinator.authenticated_configuration(&transcript.identities),
        Err(SecureAggregationReject::UnexpectedPeer { .. })
    ));
}

#[test]
fn identity_substitution_cannot_authenticate_existing_transcript() {
    let coordinator = round(3);
    let mut transcript = transcript(&coordinator, 3);
    transcript.identities.insert(
        ParticipantId(ids(3)[0].clone()),
        SigningKey::from_bytes(&[99; 32]).verifying_key().to_bytes(),
    );
    assert_rejected(run(&coordinator, &transcript));
}

#[test]
fn tampered_announcements_or_masked_updates_produce_no_sum() {
    let coordinator = round(3);
    let mut transcript = transcript(&coordinator, 3);
    transcript.announcements[0].signature[0] ^= 1;
    assert_rejected(run(&coordinator, &transcript));
    transcript.announcements[0].signature[0] ^= 1;
    transcript.contributions[0].masked_values[0] ^= 1;
    assert_rejected(run(&coordinator, &transcript));
}

#[test]
fn missing_or_duplicate_peer_never_produces_partial_aggregate() {
    let coordinator = round(3);
    let mut transcript = transcript(&coordinator, 3);
    let removed = transcript.contributions.pop().unwrap();
    assert_rejected(run(&coordinator, &transcript));
    transcript.contributions.push(removed);
    transcript.contributions[1] = transcript.contributions[0].clone();
    assert_rejected(run(&coordinator, &transcript));
    transcript.announcements.pop();
    assert_rejected(run(&coordinator, &transcript));
}

#[test]
fn invalid_configuration_is_rejected_before_key_setup() {
    let identities = transcript(&round(3), 3).identities;
    for invalid_round in [
        SecureAggregationRound::new(" ", SecurityEpoch::GENESIS, ids(3), 3),
        SecureAggregationRound::new("round", SecurityEpoch::GENESIS, Vec::<String>::new(), 3),
        SecureAggregationRound::new("round", SecurityEpoch::GENESIS, ids(2), 3),
        SecureAggregationRound::new("round", SecurityEpoch::GENESIS, ids(3), 0),
        SecureAggregationRound::with_field_modulus("round", SecurityEpoch::GENESIS, ids(3), 3, 1),
    ] {
        assert!(
            invalid_round
                .authenticated_configuration(&identities)
                .is_err()
        );
    }
}
