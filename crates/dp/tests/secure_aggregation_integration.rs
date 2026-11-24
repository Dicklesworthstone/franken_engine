#![forbid(unsafe_code)]
//! Public-API arithmetic tests for the Bonawitz 2017 aggregation track.
//! These in-process round trips do not establish coordinator privacy.

use dp::{
    AggregationConfig, DropoutPairwiseSeed, PairwiseMaskParticipant, SecureAggregationError,
    SecureAggregationSession,
    participant::{Participant, ParticipantId, ParticipantStatus},
    protocol::{AggregationProtocol, AggregationRound, MaskedContribution, SecurityParameters},
};
use rand::{SeedableRng, rngs::StdRng, thread_rng};

#[test]
fn authenticated_round_refuses_a_split_view_of_one_peers_signed_keys() {
    use std::collections::BTreeMap;

    use dp::key_exchange::{AuthenticatedAggregationRound, ParticipantKeySetup};
    use ed25519_dalek::SigningKey;

    let identities = ["alice", "bob", "carol"];
    let signing_keys: Vec<_> = (1..=3)
        .map(|seed| SigningKey::from_bytes(&[seed; 32]))
        .collect();
    let trusted: BTreeMap<_, _> = identities
        .iter()
        .zip(&signing_keys)
        .map(|(id, key)| (ParticipantId((*id).into()), key.verifying_key().to_bytes()))
        .collect();
    let round = AuthenticatedAggregationRound::new(
        "signed-transcript-fork".into(),
        trusted,
        2,
        2_147_483_647,
    )
    .unwrap();
    let setups: Vec<_> = identities
        .iter()
        .enumerate()
        .map(|(index, id)| {
            ParticipantKeySetup::new(
                &round,
                ParticipantId((*id).into()),
                signing_keys[index].clone(),
                &mut StdRng::seed_from_u64(index as u64 + 10),
            )
            .unwrap()
        })
        .collect();
    let announcements: Vec<_> = setups
        .iter()
        .map(|setup| setup.announcement().clone())
        .collect();
    let original = round.verify_announcements(&announcements).unwrap();

    // A malicious member can validly sign two setups. A coordinator shows
    // Alice one transcript and Bob another while retaining their own keys.
    let alternate_carol = ParticipantKeySetup::new(
        &round,
        ParticipantId("carol".into()),
        signing_keys[2].clone(),
        &mut StdRng::seed_from_u64(99),
    )
    .unwrap();
    let mut forked_announcements = announcements;
    forked_announcements[2] = alternate_carol.announcement().clone();
    let fork = round.verify_announcements(&forked_announcements).unwrap();
    assert_ne!(original.binding(), fork.binding());

    let mixed: Vec<_> = setups
        .into_iter()
        .enumerate()
        .map(|(index, setup)| {
            let view = if index == 1 { &fork } else { &original };
            setup.complete(view).unwrap().mask(&[1, 2]).unwrap()
        })
        .collect();
    assert!(original.aggregate(&mixed).is_err());
    assert!(fork.aggregate(&mixed).is_err());

    // Rewriting public transcript identifiers cannot repair the mixed batch:
    // each participant's signature authenticates the transcript it accepted.
    let mut rebound = mixed;
    for message in &mut rebound {
        message.key_set_binding = original.binding();
    }
    assert!(matches!(
        original.aggregate(&rebound),
        Err(SecureAggregationError::CryptographicError(_))
    ));
}

fn pairwise_participants() -> Vec<PairwiseMaskParticipant> {
    let mut rng = StdRng::seed_from_u64(20261115);
    let mut participants: Vec<_> = ["alice", "bob", "carol"]
        .into_iter()
        .map(|name| PairwiseMaskParticipant::new(ParticipantId(name.into())))
        .collect();
    for right in 1..participants.len() {
        let (earlier, later) = participants.split_at_mut(right);
        for peer in earlier {
            PairwiseMaskParticipant::establish_shared_seed(peer, &mut later[0], &mut rng).unwrap();
        }
    }
    participants
}

fn pending_pairwise_round(
    submitted: &[usize],
) -> (
    Vec<PairwiseMaskParticipant>,
    SecureAggregationSession,
    Vec<ParticipantId>,
) {
    let mut participants = pairwise_participants();
    let roster: Vec<_> = participants.iter().map(|peer| peer.id.clone()).collect();
    let mut session = SecureAggregationSession::new(
        "pairwise-roster".into(),
        AggregationConfig {
            min_participants: 2,
            max_participants: 3,
            vector_dimension: 2,
            field_modulus: 2_147_483_647,
            dropout_threshold: 1,
        },
    );
    for id in &roster {
        session
            .add_participant(Participant::new(id.clone()))
            .unwrap();
    }
    let contributions = submitted
        .iter()
        .map(|&index| {
            let value = (index as i64 + 1) * 100;
            participants[index]
                .create_masked_contribution(
                    &session.session_id,
                    &[value, value * 2],
                    session.config.field_modulus,
                )
                .unwrap()
        })
        .collect();
    session.current_round = AggregationRound::ContributionSubmission;
    session.aggregate_contributions(contributions).unwrap();
    (participants, session, roster)
}

#[test]
fn dropout_disclosure_rejects_duplicate_unknown_and_missing_self_survivors_atomically() {
    let (mut participants, _, roster) = pending_pairwise_round(&[0, 1]);
    let alice = &mut participants[0];
    let before = serde_json::to_value(&alice).unwrap();
    for survivors in [
        vec![roster[0].clone(), roster[0].clone()],
        vec![roster[0].clone(), ParticipantId("unknown".into())],
        vec![roster[1].clone(), roster[2].clone()],
        vec![roster[0].clone()],
    ] {
        assert!(
            alice.reveal_dropout_seeds(&survivors).is_err(),
            "invalid survivor identities must never expose all of Alice's masks: {survivors:?}"
        );
        assert_eq!(serde_json::to_value(&alice).unwrap(), before);
    }
    let revealed = alice.reveal_dropout_seeds(&roster[..2]).unwrap();
    assert_eq!(revealed.len(), 1);
    assert_eq!(revealed[0].dropped_peer, roster[2]);
}

#[test]
fn dropout_disclosure_locks_survivors_across_retries_and_serialization() {
    let (mut participants, _, roster) = pending_pairwise_round(&[0, 1]);
    let alice = &mut participants[0];
    let revealed = alice.reveal_dropout_seeds(&roster[..2]).unwrap();
    let before = serde_json::to_value(&alice).unwrap();
    assert_eq!(
        alice
            .reveal_dropout_seeds(&[roster[1].clone(), roster[0].clone()])
            .unwrap(),
        revealed
    );
    assert_eq!(serde_json::to_value(&alice).unwrap(), before);

    for survivors in [vec![roster[0].clone(), roster[2].clone()], roster.clone()] {
        assert!(alice.reveal_dropout_seeds(&survivors).is_err());
        assert_eq!(serde_json::to_value(&alice).unwrap(), before);
    }

    let mut restored: PairwiseMaskParticipant = serde_json::from_value(before).unwrap();
    assert_eq!(
        restored.reveal_dropout_seeds(&roster[..2]).unwrap(),
        revealed
    );
    assert!(
        restored
            .reveal_dropout_seeds(&[roster[0].clone(), roster[2].clone()])
            .is_err()
    );

    // Even a no-dropout decision is final: a subsequent smaller roster cannot
    // turn an all-survivor round into disclosure of one of those peers' seeds.
    let (mut full_participants, _, full_roster) = pending_pairwise_round(&[0, 1, 2]);
    assert!(
        full_participants[0]
            .reveal_dropout_seeds(&full_roster)
            .unwrap()
            .is_empty()
    );
    assert!(
        full_participants[0]
            .reveal_dropout_seeds(&full_roster[..2])
            .is_err()
    );
}

#[test]
fn pairwise_seed_setup_cannot_rekey_or_change_a_submitted_roster() {
    let mut participants = pairwise_participants();
    let before = serde_json::to_value(&participants).unwrap();
    let mut rng = StdRng::seed_from_u64(9);
    let (left, right) = participants.split_at_mut(1);
    assert!(
        PairwiseMaskParticipant::establish_shared_seed(&mut left[0], &mut right[0], &mut rng)
            .is_err()
    );
    assert_eq!(serde_json::to_value(&participants).unwrap(), before);

    participants[0]
        .create_masked_contribution("frozen-roster", &[12], 101)
        .unwrap();
    let mut newcomer = PairwiseMaskParticipant::new(ParticipantId("dave".into()));
    let before = serde_json::to_value((&participants, &newcomer)).unwrap();
    assert!(
        PairwiseMaskParticipant::establish_shared_seed(
            &mut participants[0],
            &mut newcomer,
            &mut rng
        )
        .is_err()
    );
    assert!(
        PairwiseMaskParticipant::establish_shared_seed(
            &mut newcomer,
            &mut participants[0],
            &mut rng
        )
        .is_err()
    );
    assert_eq!(
        serde_json::to_value((&participants, &newcomer)).unwrap(),
        before
    );
}

#[test]
fn session_contributions_require_unique_registered_participants() {
    let mut session = SecureAggregationSession::new(
        "contribution-membership".into(),
        AggregationConfig {
            vector_dimension: 1,
            ..AggregationConfig::default()
        },
    );
    let alice = ParticipantId("alice".into());
    let bob = ParticipantId("bob".into());
    session
        .add_participant(Participant::new(alice.clone()))
        .unwrap();
    session
        .add_participant(Participant::new(bob.clone()))
        .unwrap();
    session.current_round = AggregationRound::ContributionSubmission;
    let a = MaskedContribution::new(alice, vec![10], Vec::new());
    let b = MaskedContribution::new(bob, vec![20], Vec::new());
    let unknown = MaskedContribution::new(ParticipantId("unknown".into()), vec![30], Vec::new());
    let before = serde_json::to_value(&session).unwrap();
    for contributions in [vec![a.clone(), a.clone()], vec![a.clone(), unknown]] {
        assert!(session.aggregate_contributions(contributions).is_err());
        assert_eq!(serde_json::to_value(&session).unwrap(), before);
    }
    assert_eq!(
        session.aggregate_contributions(vec![a, b]).unwrap(),
        vec![30]
    );
}

fn pending_legacy_round() -> (SecureAggregationSession, Vec<(ParticipantId, Vec<i64>)>) {
    let mut session = SecureAggregationSession::new(
        "legacy-completion-membership".into(),
        AggregationConfig {
            min_participants: 2,
            max_participants: 3,
            vector_dimension: 2,
            field_modulus: 101,
            dropout_threshold: 1,
        },
    );
    let ids: Vec<_> = ["alice", "bob", "carol"]
        .into_iter()
        .map(|name| ParticipantId(name.into()))
        .collect();
    for id in &ids {
        session
            .add_participant(Participant::new(id.clone()))
            .unwrap();
    }
    session.current_round = AggregationRound::ContributionSubmission;
    session
        .aggregate_contributions(vec![
            MaskedContribution::new(ids[0].clone(), vec![10, 20], Vec::new()),
            MaskedContribution::new(ids[1].clone(), vec![30, 40], Vec::new()),
        ])
        .unwrap();
    (
        session,
        vec![(ids[0].clone(), vec![1, 3]), (ids[1].clone(), vec![2, 4])],
    )
}

#[test]
fn legacy_completion_requires_exact_contributor_coverage_without_mutation() {
    let (mut session, masks) = pending_legacy_round();
    let before = serde_json::to_value(&session).unwrap();
    for invalid in [
        Vec::new(),
        vec![masks[0].clone()],
        vec![masks[0].clone(), masks[0].clone()],
        vec![
            masks[0].clone(),
            (ParticipantId("unknown".into()), vec![2, 4]),
        ],
        vec![masks[0].clone(), (ParticipantId("carol".into()), vec![2, 4])],
        vec![masks[0].clone(), masks[1].clone(), masks[1].clone()],
        vec![masks[0].clone(), (masks[1].0.clone(), vec![2])],
    ] {
        assert!(
            session.complete_aggregation(invalid).is_err(),
            "every accepted contributor must supply exactly one full net mask"
        );
        assert_eq!(serde_json::to_value(&session).unwrap(), before);
    }

    // Rejection leaves the same round retryable; input ordering is immaterial.
    assert_eq!(
        session
            .complete_aggregation(masks.into_iter().rev().collect())
            .unwrap(),
        vec![37, 53]
    );
    assert_eq!(session.current_round, AggregationRound::Complete);
    let completed = serde_json::to_value(&session).unwrap();
    assert!(matches!(
        session.complete_aggregation(Vec::new()),
        Err(SecureAggregationError::InvalidRound)
    ));
    assert_eq!(serde_json::to_value(&session).unwrap(), completed);
}

#[test]
fn legacy_completion_rejects_missing_or_malformed_accepted_state() {
    let (session, masks) = pending_legacy_round();
    for aggregate in [
        None,
        Some(Vec::new()),
        Some(vec![40]),
        Some(vec![40, 60, 80]),
        Some(vec![-1, 60]),
        Some(vec![40, 101]),
    ] {
        let mut malformed = session.clone();
        malformed.aggregated_result = aggregate;
        let before = serde_json::to_value(&malformed).unwrap();
        assert!(malformed.complete_aggregation(masks.clone()).is_err());
        assert_eq!(serde_json::to_value(&malformed).unwrap(), before);
    }

    let mut unaccepted =
        SecureAggregationSession::new(session.session_id.clone(), session.config.clone());
    unaccepted.participants = session.participants.clone();
    unaccepted.current_round = AggregationRound::Unmasking;
    unaccepted.aggregated_result = session.aggregated_result.clone();
    let before = serde_json::to_value(&unaccepted).unwrap();
    assert!(matches!(
        unaccepted.complete_aggregation(masks),
        Err(SecureAggregationError::InvalidState)
    ));
    assert_eq!(serde_json::to_value(&unaccepted).unwrap(), before);
}

#[test]
fn legacy_completion_keeps_roster_and_dropout_checks_after_serialization() {
    let (session, masks) = pending_legacy_round();
    let encoded = serde_json::to_string(&session).unwrap();
    for change in 0..6 {
        let mut restored: SecureAggregationSession = serde_json::from_str(&encoded).unwrap();
        match change {
            0 => {
                // A registered non-contributor remains part of the accepted roster.
                restored
                    .participants
                    .remove(&ParticipantId("carol".into()));
            }
            1 => restored.config.dropout_threshold = 0,
            2 => restored.config.min_participants = 3,
            3 => restored.config.field_modulus = 103,
            4 => restored.session_id.push_str("-different-round"),
            _ => restored.config.max_participants = 4,
        }
        let before = serde_json::to_value(&restored).unwrap();
        assert!(restored.complete_aggregation(masks.clone()).is_err());
        assert_eq!(serde_json::to_value(&restored).unwrap(), before);
    }
    let mut restored: SecureAggregationSession = serde_json::from_str(&encoded).unwrap();
    assert_eq!(restored.complete_aggregation(masks).unwrap(), vec![37, 53]);
}

#[test]
fn completed_round_cannot_be_unmasked_again_by_rewinding_public_status() {
    let (mut session, masks) = pending_legacy_round();
    session.complete_aggregation(masks.clone()).unwrap();
    // The terminal contribution state is retained in serialized snapshots too.
    let mut restored: SecureAggregationSession =
        serde_json::from_str(&serde_json::to_string(&session).unwrap()).unwrap();
    restored.current_round = AggregationRound::Unmasking;
    let before = serde_json::to_value(&restored).unwrap();
    assert!(matches!(
        restored.complete_aggregation(masks),
        Err(SecureAggregationError::InvalidState)
    ));
    assert_eq!(serde_json::to_value(&restored).unwrap(), before);

    let (_, mut pairwise, roster) = pending_pairwise_round(&[0, 1, 2]);
    assert_eq!(
        pairwise
            .complete_pairwise_aggregation(&roster, &roster, &[])
            .unwrap(),
        vec![600, 1200]
    );
    pairwise.current_round = AggregationRound::Unmasking;
    let before = serde_json::to_value(&pairwise).unwrap();
    assert!(matches!(
        pairwise.complete_pairwise_aggregation(&roster, &roster, &[]),
        Err(SecureAggregationError::InvalidState)
    ));
    assert_eq!(serde_json::to_value(&pairwise).unwrap(), before);
}

#[test]
fn pairwise_completion_rejects_changed_arithmetic_domain_and_aggregate() {
    let (_, session, roster) = pending_pairwise_round(&[0, 1, 2]);
    for change in 0..4 {
        let mut changed = session.clone();
        match change {
            0 => changed.config.field_modulus = 101,
            1 => changed.session_id.push_str("-different-round"),
            2 => changed.aggregated_result = Some(vec![600]),
            _ => changed.aggregated_result = Some(vec![-1, 1200]),
        }
        let before = serde_json::to_value(&changed).unwrap();
        assert!(
            changed
                .complete_pairwise_aggregation(&roster, &roster, &[])
                .is_err()
        );
        assert_eq!(serde_json::to_value(&changed).unwrap(), before);
    }
}

#[test]
fn pairwise_completion_binds_registered_roster_and_actual_contributors() {
    let (mut participants, mut session, roster) = pending_pairwise_round(&[0, 1]);
    let survivors = &roster[..2];
    let mut seeds = participants[0].reveal_dropout_seeds(survivors).unwrap();
    seeds.extend(participants[1].reveal_dropout_seeds(survivors).unwrap());
    let before = serde_json::to_value(&session).unwrap();
    for (expected, claimed) in [
        (
            vec![roster[0].clone(), roster[0].clone(), roster[1].clone()],
            survivors.to_vec(),
        ),
        (
            vec![
                roster[0].clone(),
                roster[1].clone(),
                ParticipantId("unknown".into()),
            ],
            survivors.to_vec(),
        ),
        (survivors.to_vec(), survivors.to_vec()),
        (roster.clone(), vec![roster[0].clone(), roster[0].clone()]),
        (roster.clone(), vec![roster[0].clone(), roster[2].clone()]),
        (roster.clone(), roster.clone()),
    ] {
        assert!(
            session
                .complete_pairwise_aggregation(&expected, &claimed, &seeds)
                .is_err(),
            "completion cannot invent or substitute submitted identities"
        );
        assert_eq!(serde_json::to_value(&session).unwrap(), before);
    }
    // Reordering identity lists is not a different round.
    assert_eq!(
        session
            .complete_pairwise_aggregation(
                &[roster[2].clone(), roster[1].clone(), roster[0].clone()],
                &[roster[1].clone(), roster[0].clone()],
                &seeds,
            )
            .unwrap(),
        vec![300, 600]
    );
}

#[test]
fn pairwise_completion_requires_exact_dropout_seed_coverage() {
    let (mut participants, mut session, roster) = pending_pairwise_round(&[0, 1]);
    let survivors = &roster[..2];
    let mut seeds = participants[0].reveal_dropout_seeds(survivors).unwrap();
    seeds.extend(participants[1].reveal_dropout_seeds(survivors).unwrap());
    let mut duplicate = seeds.clone();
    duplicate.push(seeds[0].clone());
    let mut extra = seeds.clone();
    extra.push(DropoutPairwiseSeed {
        survivor: roster[0].clone(),
        dropped_peer: ParticipantId("unknown".into()),
        shared_seed: [0; 32],
    });
    let mut living_peer = seeds.clone();
    living_peer[0].dropped_peer = roster[1].clone();
    let mut unknown_sender = seeds.clone();
    unknown_sender[0].survivor = ParticipantId("unknown".into());
    let before = serde_json::to_value(&session).unwrap();
    for invalid in [
        seeds[..1].to_vec(),
        duplicate,
        extra,
        living_peer,
        unknown_sender,
    ] {
        assert!(
            session
                .complete_pairwise_aggregation(&roster, survivors, &invalid)
                .is_err()
        );
        assert_eq!(serde_json::to_value(&session).unwrap(), before);
    }
    assert_eq!(
        session
            .complete_pairwise_aggregation(&roster, survivors, &seeds)
            .unwrap(),
        vec![300, 600]
    );
}

#[test]
fn session_rejects_invalid_quorums_and_preserves_registered_peers() {
    for (minimum, maximum) in [(0, 3), (1, 3), (4, 3)] {
        let mut session = SecureAggregationSession::new(
            "invalid-quorum".into(),
            AggregationConfig {
                min_participants: minimum,
                max_participants: maximum,
                vector_dimension: 1,
                ..AggregationConfig::default()
            },
        );
        for name in ["alice", "bob"] {
            session
                .add_participant(Participant::new(ParticipantId(name.into())))
                .unwrap();
        }
        let before = serde_json::to_value(&session).unwrap();
        assert!(
            session
                .start_aggregation(&mut StdRng::seed_from_u64(1))
                .is_err()
        );
        assert_eq!(serde_json::to_value(&session).unwrap(), before);
        session.current_round = AggregationRound::ContributionSubmission;
        let before = serde_json::to_value(&session).unwrap();
        assert!(
            session
                .aggregate_contributions(vec![
                    MaskedContribution::new(ParticipantId("alice".into()), vec![1], Vec::new()),
                    MaskedContribution::new(ParticipantId("bob".into()), vec![2], Vec::new()),
                ])
                .is_err()
        );
        assert_eq!(serde_json::to_value(&session).unwrap(), before);
    }

    let mut session = SecureAggregationSession::new(
        "duplicate-registration".into(),
        AggregationConfig::default(),
    );
    let mut alice = Participant::new(ParticipantId("alice".into()));
    alice.status = ParticipantStatus::GeneratingShares;
    session.add_participant(alice).unwrap();
    let before = serde_json::to_value(&session).unwrap();
    assert!(
        session
            .add_participant(Participant::new(ParticipantId("alice".into())))
            .is_err()
    );
    assert_eq!(serde_json::to_value(&session).unwrap(), before);
}

#[test]
fn pairwise_state_survives_round_trip_and_missing_state_is_not_reset() {
    let (mut participants, session, roster) = pending_pairwise_round(&[0, 1]);
    let survivors = &roster[..2];
    let mut seeds = participants[0].reveal_dropout_seeds(survivors).unwrap();
    seeds.extend(participants[1].reveal_dropout_seeds(survivors).unwrap());

    let mut serialized_session = serde_json::to_value(&session).unwrap();
    let mut restored: SecureAggregationSession =
        serde_json::from_value(serialized_session.clone()).unwrap();
    assert_eq!(
        restored
            .complete_pairwise_aggregation(&roster, survivors, &seeds)
            .unwrap(),
        vec![300, 600]
    );
    serialized_session
        .as_object_mut()
        .unwrap()
        .remove("contribution_state");
    assert!(serde_json::from_value::<SecureAggregationSession>(serialized_session).is_err());

    let mut serialized_participant = serde_json::to_value(&participants[0]).unwrap();
    serialized_participant
        .as_object_mut()
        .unwrap()
        .remove("dropout_disclosure");
    assert!(serde_json::from_value::<PairwiseMaskParticipant>(serialized_participant).is_err());
}

#[test]
fn pairwise_completion_rechecks_quorum_and_dropout_limit_before_mutation() {
    for (minimum, maximum, dropout_threshold) in [(1, 3, 1), (3, 3, 1), (2, 1, 1), (2, 3, 0)] {
        let (mut participants, mut session, roster) = pending_pairwise_round(&[0, 1]);
        let survivors = &roster[..2];
        let mut seeds = participants[0].reveal_dropout_seeds(survivors).unwrap();
        seeds.extend(participants[1].reveal_dropout_seeds(survivors).unwrap());
        session.config.min_participants = minimum;
        session.config.max_participants = maximum;
        session.config.dropout_threshold = dropout_threshold;
        let before = serde_json::to_value(&session).unwrap();
        assert!(
            session
                .complete_pairwise_aggregation(&roster, survivors, &seeds)
                .is_err()
        );
        assert_eq!(serde_json::to_value(&session).unwrap(), before);
    }
}

#[test]
fn pairwise_completion_rejects_unregistered_contributors_in_restored_state() {
    let (_, session, roster) = pending_pairwise_round(&[0, 1]);
    let outsiders = vec![
        ParticipantId("outside-a".into()),
        ParticipantId("outside-b".into()),
    ];
    let mut snapshot = serde_json::to_value(&session).unwrap();
    snapshot["contribution_state"]["Accepted"]["contributors"] =
        serde_json::to_value(&outsiders).unwrap();
    // Allow enough dropouts to ensure the identity invariant, rather than the
    // ordinary threshold check, rejects this inconsistent restored state.
    snapshot["config"]["dropout_threshold"] = serde_json::json!(3);
    let mut restored: SecureAggregationSession = serde_json::from_value(snapshot).unwrap();
    let seeds: Vec<_> = outsiders
        .iter()
        .flat_map(|survivor| {
            roster.iter().map(move |dropped_peer| DropoutPairwiseSeed {
                survivor: survivor.clone(),
                dropped_peer: dropped_peer.clone(),
                shared_seed: [0; 32],
            })
        })
        .collect();
    let before = serde_json::to_value(&restored).unwrap();
    assert!(
        restored
            .complete_pairwise_aggregation(&roster, &outsiders, &seeds)
            .is_err()
    );
    assert_eq!(serde_json::to_value(&restored).unwrap(), before);
}

#[test]
fn aggregate_sums_near_the_signed_field_limit_without_overflow() {
    let modulus = i64::MAX;
    let contributions = vec![
        MaskedContribution::new(
            ParticipantId("alice".into()),
            vec![modulus - 1, modulus - 2],
            Vec::new(),
        ),
        MaskedContribution::new(
            ParticipantId("bob".into()),
            vec![modulus - 1, modulus - 2],
            Vec::new(),
        ),
    ];
    let protocol = AggregationProtocol::new(SecurityParameters {
        field_modulus: modulus as u64,
        vector_dimension: 2,
        ..SecurityParameters::default()
    });
    assert_eq!(
        protocol
            .aggregate_masked_contributions(contributions.clone())
            .unwrap(),
        vec![modulus - 2, modulus - 4]
    );
    let mut session = SecureAggregationSession::new(
        "field-limit".into(),
        AggregationConfig {
            field_modulus: modulus as u64,
            vector_dimension: 2,
            ..AggregationConfig::default()
        },
    );
    for contribution in &contributions {
        session
            .add_participant(Participant::new(contribution.participant_id.clone()))
            .unwrap();
    }
    session.current_round = AggregationRound::ContributionSubmission;
    let result = session.aggregate_contributions(contributions).unwrap();
    assert_eq!(result, vec![modulus - 2, modulus - 4]);
    assert_eq!(session.aggregated_result.as_ref(), Some(&result));
    assert_eq!(session.current_round, AggregationRound::Unmasking);
}

#[test]
fn invalid_moduli_are_rejected_even_for_empty_vectors() {
    for modulus in [0, 1_u64 << 63, u64::MAX] {
        let contribution =
            MaskedContribution::new(ParticipantId("alice".into()), Vec::new(), Vec::new());
        assert!(matches!(
            contribution.verify_field_bounds(modulus),
            Err(SecureAggregationError::ProtocolViolation(_))
        ));
        let protocol = AggregationProtocol::new(SecurityParameters {
            field_modulus: modulus,
            vector_dimension: 0,
            min_participants: 0,
            ..SecurityParameters::default()
        });
        assert!(matches!(
            protocol.aggregate_masked_contributions(Vec::new()),
            Err(SecureAggregationError::ProtocolViolation(_))
        ));
        let mut session = SecureAggregationSession::new(
            "invalid-field".into(),
            AggregationConfig {
                field_modulus: modulus,
                vector_dimension: 0,
                min_participants: 0,
                ..AggregationConfig::default()
            },
        );
        session.current_round = AggregationRound::ContributionSubmission;
        assert!(matches!(
            session.aggregate_contributions(Vec::new()),
            Err(SecureAggregationError::ProtocolViolation(_))
        ));
        assert_eq!(
            session.current_round,
            AggregationRound::ContributionSubmission
        );
        assert!(session.aggregated_result.is_none());
    }
}

#[test]
fn rejected_field_elements_leave_session_ready_for_a_valid_retry() {
    let mut session = SecureAggregationSession::new(
        "field-validation".into(),
        AggregationConfig {
            field_modulus: 101,
            vector_dimension: 1,
            min_participants: 2,
            ..AggregationConfig::default()
        },
    );
    for name in ["alice", "bob"] {
        session
            .add_participant(Participant::new(ParticipantId(name.into())))
            .unwrap();
    }
    let bob = MaskedContribution::new(ParticipantId("bob".into()), vec![0], Vec::new());
    session.current_round = AggregationRound::ContributionSubmission;
    for invalid in [-1, 101, i64::MAX] {
        let contribution =
            MaskedContribution::new(ParticipantId("alice".into()), vec![invalid], Vec::new());
        assert!(matches!(
            session.aggregate_contributions(vec![contribution, bob.clone()]),
            Err(SecureAggregationError::ProtocolViolation(_))
        ));
        assert_eq!(
            session.current_round,
            AggregationRound::ContributionSubmission
        );
        assert!(session.aggregated_result.is_none());
    }
    assert_eq!(
        session
            .aggregate_contributions(vec![
                MaskedContribution::new(ParticipantId("alice".into()), vec![100], Vec::new()),
                bob,
            ])
            .unwrap(),
        vec![100]
    );
}

/// Arithmetic round-trip through real share exchange, masking and unmasking.
/// This does not prove secrecy against a coordinator given individual masks.
#[test]
fn complete_secure_aggregation_workflow() {
    let mut rng = thread_rng();

    // Configure secure aggregation parameters
    let config = AggregationConfig {
        min_participants: 3,
        max_participants: 5,
        vector_dimension: 4,
        field_modulus: 1000000,
        dropout_threshold: 1,
    };

    let mut session = SecureAggregationSession::new("secure-test-session".into(), config.clone());

    // Create participants representing different fleet nodes
    let alice = Participant::new(ParticipantId("alice".into()));
    let bob = Participant::new(ParticipantId("bob".into()));
    let charlie = Participant::new(ParticipantId("charlie".into()));

    // Add participants to session
    session.add_participant(alice).unwrap();
    session.add_participant(bob).unwrap();
    session.add_participant(charlie).unwrap();

    // Start aggregation protocol
    let share_seeds = session.start_aggregation(&mut rng).unwrap();
    assert_eq!(share_seeds.len(), 3);
    assert_eq!(session.current_round, AggregationRound::ShareGeneration);

    // Simulate participants generating and exchanging secret shares
    let participant_ids: Vec<ParticipantId> = session.participants.keys().cloned().collect();
    let mut all_masked_contributions = Vec::new();
    let mut messages = Vec::new();

    // Each participant's private input (these would be real sensitive data)
    let private_inputs = [
        vec![10, 20, 30, 40], // Alice's private vector
        vec![15, 25, 35, 45], // Bob's private vector
        vec![5, 10, 15, 20],  // Charlie's private vector
    ];

    for participant_id in &participant_ids {
        let mut participant = session.participants[participant_id].clone();

        // Generate secret shares for other participants
        let other_participants: Vec<ParticipantId> = participant_ids
            .iter()
            .filter(|&id| id != participant_id)
            .cloned()
            .collect();

        let shares = participant
            .generate_secret_shares(
                &other_participants,
                config.vector_dimension,
                config.field_modulus,
                &mut rng,
            )
            .unwrap();

        assert_eq!(shares.len(), 2); // One share for each other participant

        messages.extend(
            shares
                .into_iter()
                .map(|share| (participant_id.clone(), share)),
        );
        session
            .participants
            .insert(participant_id.clone(), participant);
    }
    for (sender, share) in messages {
        session
            .participants
            .get_mut(&share.recipient)
            .unwrap()
            .receive_secret_share(sender, share)
            .unwrap();
    }
    for (i, participant_id) in participant_ids.iter().enumerate() {
        let participant = session.participants.get_mut(participant_id).unwrap();
        // Create masked contribution
        let masked_values = participant
            .create_masked_contribution(private_inputs[i].clone(), config.field_modulus)
            .unwrap();

        let contribution = MaskedContribution::new(
            participant_id.clone(),
            masked_values,
            vec![i as u8; 32], // Simplified hash
        );

        all_masked_contributions.push(contribution);
    }

    // Aggregator receives only masked contributions (individual inputs hidden)
    session.current_round = AggregationRound::ContributionSubmission;
    let masked_aggregate = session
        .aggregate_contributions(all_masked_contributions)
        .unwrap();

    // Verify aggregation preserves privacy: individual contributions not directly visible
    assert_eq!(masked_aggregate.len(), config.vector_dimension);
    assert_eq!(session.current_round, AggregationRound::Unmasking);

    // Simulate unmasking phase (in practice, uses reconstructed secret shares)
    let mut all_unmasking_values = Vec::new();
    for participant_id in &participant_ids {
        let mut participant = session.participants[participant_id].clone();
        participant.status = ParticipantStatus::ContributionSubmitted;
        let unmasking = participant.get_unmasking_values().unwrap();
        all_unmasking_values.push((participant_id.clone(), unmasking));
    }

    // Complete aggregation by removing masks
    let final_result = session.complete_aggregation(all_unmasking_values).unwrap();

    // Verify the final result contains only the aggregate, not individual contributions
    assert_eq!(final_result.len(), config.vector_dimension);
    assert_eq!(session.current_round, AggregationRound::Complete);

    // The recovered sum must be exact, including after actual peer exchange.
    let expected_sum: Vec<i64> = (0..config.vector_dimension)
        .map(|i| private_inputs.iter().map(|input| input[i]).sum::<i64>())
        .collect();

    assert_eq!(final_result, expected_sum);
}

/// Test secure aggregation with participant dropout
#[test]
fn secure_aggregation_handles_participant_dropout() {
    let mut rng = thread_rng();

    let config = AggregationConfig {
        min_participants: 2,
        max_participants: 4,
        vector_dimension: 3,
        field_modulus: 100000,
        dropout_threshold: 1,
    };

    let mut session = SecureAggregationSession::new("dropout-test".into(), config.clone());

    // Add participants
    let alice = Participant::new(ParticipantId("alice".into()));
    let bob = Participant::new(ParticipantId("bob".into()));
    let charlie = Participant::new(ParticipantId("charlie".into()));

    session.add_participant(alice).unwrap();
    session.add_participant(bob).unwrap();
    session.add_participant(charlie).unwrap();

    session.start_aggregation(&mut rng).unwrap();

    // Simulate only 2 out of 3 participants contributing (Charlie drops out)
    session.current_round = AggregationRound::ContributionSubmission;
    let contributions = vec![
        MaskedContribution::new(
            ParticipantId("alice".into()),
            vec![100, 200, 300],
            vec![0; 32],
        ),
        MaskedContribution::new(
            ParticipantId("bob".into()),
            vec![150, 250, 350],
            vec![1; 32],
        ),
    ];

    // Should still succeed with minimum participants
    let result = session.aggregate_contributions(contributions);
    assert!(result.is_ok());

    let unmasking = vec![
        (ParticipantId("alice".into()), vec![0, 0, 0]),
        (ParticipantId("bob".into()), vec![0, 0, 0]),
    ];

    let final_result = session.complete_aggregation(unmasking).unwrap();
    assert_eq!(final_result, vec![250, 450, 650]);
}

/// Test that aggregation fails with insufficient participants
#[test]
fn secure_aggregation_requires_minimum_participants() {
    let mut rng = thread_rng();

    let config = AggregationConfig {
        min_participants: 3,
        max_participants: 5,
        vector_dimension: 2,
        field_modulus: 10000,
        dropout_threshold: 1,
    };

    let mut session = SecureAggregationSession::new("insufficient-test".into(), config);

    // Add only 2 participants when minimum is 3
    let alice = Participant::new(ParticipantId("alice".into()));
    let bob = Participant::new(ParticipantId("bob".into()));

    session.add_participant(alice).unwrap();
    session.add_participant(bob).unwrap();

    // Should fail to start aggregation
    let result = session.start_aggregation(&mut rng);
    assert!(result.is_err());
}

/// Test protocol-level validation and security
#[test]
fn protocol_enforces_security_constraints() {
    let security_params = SecurityParameters {
        field_modulus: 1000,
        min_participants: 2,
        dropout_threshold: 1,
        vector_dimension: 3,
    };

    let protocol = AggregationProtocol::new(security_params.clone());

    // Test valid contributions
    let valid_contributions = vec![
        MaskedContribution::new(
            ParticipantId("alice".into()),
            vec![100, 200, 300],
            vec![0; 32],
        ),
        MaskedContribution::new(
            ParticipantId("bob".into()),
            vec![400, 500, 600],
            vec![1; 32],
        ),
    ];

    assert!(
        protocol
            .validate_contributions(&valid_contributions)
            .is_ok()
    );

    // Test invalid dimension
    let invalid_dimension = vec![MaskedContribution::new(
        ParticipantId("alice".into()),
        vec![100, 200], // Wrong dimension
        vec![0; 32],
    )];

    assert!(protocol.validate_contributions(&invalid_dimension).is_err());

    // Test values outside field bounds
    let out_of_bounds = vec![
        MaskedContribution::new(
            ParticipantId("alice".into()),
            vec![2000, 200, 300], // 2000 > field_modulus (1000)
            vec![0; 32],
        ),
        MaskedContribution::new(
            ParticipantId("bob".into()),
            vec![400, 500, 600],
            vec![1; 32],
        ),
    ];

    assert!(protocol.validate_contributions(&out_of_bounds).is_err());
}

/// Test aggregation maintains mathematical properties
#[test]
fn aggregation_preserves_mathematical_properties() {
    let security_params = SecurityParameters {
        field_modulus: 1000000,
        min_participants: 2,
        dropout_threshold: 0,
        vector_dimension: 4,
    };

    let protocol = AggregationProtocol::new(security_params);

    let contributions = vec![
        MaskedContribution::new(
            ParticipantId("alice".into()),
            vec![1000, 2000, 3000, 4000],
            vec![0; 32],
        ),
        MaskedContribution::new(
            ParticipantId("bob".into()),
            vec![500, 1500, 2500, 3500],
            vec![1; 32],
        ),
        MaskedContribution::new(
            ParticipantId("charlie".into()),
            vec![250, 750, 1250, 1750],
            vec![2; 32],
        ),
    ];

    let aggregated = protocol
        .aggregate_masked_contributions(contributions)
        .unwrap();

    // Verify aggregation is componentwise sum
    assert_eq!(aggregated, vec![1750, 4250, 6750, 9250]);

    // Test unmasking preserves the result
    let no_unmasking = vec![];
    let unmasked = protocol
        .apply_unmasking(aggregated.clone(), no_unmasking)
        .unwrap();
    assert_eq!(unmasked, aggregated);

    // Test unmasking with actual masks
    let unmasking_values = vec![vec![100, 200, 300, 400], vec![50, 150, 250, 350]];

    let expected_unmasked: Vec<i64> = aggregated
        .iter()
        .enumerate()
        .map(|(i, &val)| {
            let total_unmask = unmasking_values.iter().map(|u| u[i]).sum::<i64>();
            (val - total_unmask + 1000000) % 1000000
        })
        .collect();

    let actual_unmasked = protocol
        .apply_unmasking(aggregated, unmasking_values)
        .unwrap();

    assert_eq!(actual_unmasked, expected_unmasked);
}

/// Test session status tracking throughout the protocol
#[test]
fn session_tracks_protocol_status() {
    let config = AggregationConfig::default();
    let mut session = SecureAggregationSession::new("status-test".into(), config);

    // Initial status
    let status = session.status();
    assert_eq!(status.session_id, "status-test");
    assert_eq!(status.participant_count, 0);
    assert_eq!(status.current_round, AggregationRound::Setup);
    assert!(!status.is_complete);
    assert!(!status.has_result);

    // Add participants
    session
        .add_participant(Participant::new(ParticipantId("alice".into())))
        .unwrap();
    session
        .add_participant(Participant::new(ParticipantId("bob".into())))
        .unwrap();

    let status = session.status();
    assert_eq!(status.participant_count, 2);

    // Start aggregation
    let mut rng = thread_rng();
    session.start_aggregation(&mut rng).unwrap();

    let status = session.status();
    assert_eq!(status.current_round, AggregationRound::ShareGeneration);
    assert!(!status.is_complete);

    // Simulate completion
    session.current_round = AggregationRound::Complete;
    session.aggregated_result = Some(vec![100, 200, 300]);

    let status = session.status();
    assert!(status.is_complete);
    assert!(status.has_result);
}

/// Test cryptographic properties of secret share generation
#[test]
fn secret_shares_maintain_cryptographic_properties() {
    let mut alice = Participant::new(ParticipantId("alice".into()));
    let mut bob = Participant::new(ParticipantId("bob".into()));
    let mut charlie = Participant::new(ParticipantId("charlie".into()));

    let others = vec![ParticipantId("bob".into()), ParticipantId("charlie".into())];

    let mut rng = thread_rng();
    let field_modulus = 1000000u64;
    let dimension = 5;

    // Generate shares
    let alice_shares = alice
        .generate_secret_shares(&others, dimension, field_modulus, &mut rng)
        .unwrap();

    let bob_shares = bob
        .generate_secret_shares(
            &[
                ParticipantId("alice".into()),
                ParticipantId("charlie".into()),
            ],
            dimension,
            field_modulus,
            &mut rng,
        )
        .unwrap();

    let charlie_shares = charlie
        .generate_secret_shares(
            &[ParticipantId("alice".into()), ParticipantId("bob".into())],
            dimension,
            field_modulus,
            &mut rng,
        )
        .unwrap();

    // Verify share properties
    assert_eq!(alice_shares.len(), 2);
    assert_eq!(bob_shares.len(), 2);
    assert_eq!(charlie_shares.len(), 2);

    for share in &alice_shares {
        assert_eq!(share.share_values.len(), dimension);
        assert!(!share.share_hash.is_empty());

        // Verify all values are within field bounds
        for &value in &share.share_values {
            assert!(value >= 0 && value < field_modulus as i64);
        }
    }

    // Verify shares can be exchanged
    for share in bob_shares {
        if share.recipient == alice.id {
            assert!(alice.receive_secret_share(bob.id.clone(), share).is_ok());
            break;
        }
    }

    for share in charlie_shares {
        if share.recipient == alice.id {
            assert!(
                alice
                    .receive_secret_share(charlie.id.clone(), share)
                    .is_ok()
            );
            break;
        }
    }

    // Alice should now have received shares from Bob and Charlie
    assert_eq!(alice.received_shares.len(), 2);
}
