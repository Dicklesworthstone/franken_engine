use super::*;
use rand::{SeedableRng, rngs::StdRng};

const MODULUS: u64 = 2_147_483_647;

fn identities(count: usize) -> BTreeMap<ParticipantId, [u8; 32]> {
    (0..count)
        .map(|index| {
            (
                ParticipantId(format!("peer-{index:02}")),
                signing_key(index).verifying_key().to_bytes(),
            )
        })
        .collect()
}

fn signing_key(index: usize) -> SigningKey {
    SigningKey::from_bytes(&[(index + 1) as u8; 32])
}

fn round(count: usize, session: &str) -> AuthenticatedAggregationRound {
    AuthenticatedAggregationRound::new(session.into(), identities(count), 3, MODULUS).unwrap()
}

fn setups(round: &AuthenticatedAggregationRound, seed: u64) -> Vec<ParticipantKeySetup> {
    let mut rng = StdRng::seed_from_u64(seed);
    round
        .identities
        .keys()
        .enumerate()
        .map(|(index, id)| {
            ParticipantKeySetup::new(round, id.clone(), signing_key(index), &mut rng).unwrap()
        })
        .collect()
}

fn messages(setups: &[ParticipantKeySetup]) -> Vec<KeyAnnouncement> {
    setups
        .iter()
        .map(|setup| setup.announcement().clone())
        .collect()
}

fn prepared(count: usize) -> (AuthenticatedKeySet, Vec<AuthenticatedParticipant>) {
    let round = round(count, "epoch-7-release-1");
    let setups = setups(&round, 91);
    let keys = round.verify_announcements(&messages(&setups)).unwrap();
    let participants = setups
        .into_iter()
        .map(|setup| setup.complete(&keys).unwrap())
        .collect();
    (keys, participants)
}

fn contributions(participants: &mut [AuthenticatedParticipant]) -> Vec<SignedMaskedContribution> {
    participants
        .iter_mut()
        .enumerate()
        .map(|(index, participant)| {
            let n = index as i64 + 1;
            participant.mask(&[n, 2 * n, -n]).unwrap()
        })
        .collect()
}

#[test]
fn independent_participants_aggregate_through_only_public_serialized_messages() {
    for count in [3, 7, 25] {
        let round = round(count, "round-transport");
        let setups = setups(&round, 183);
        let wire = serde_json::to_vec(&messages(&setups)).unwrap();
        let announcements: Vec<KeyAnnouncement> = serde_json::from_slice(&wire).unwrap();
        // The coordinator owns no participant and sees only wire messages.
        let coordinator = round.verify_announcements(&announcements).unwrap();
        let mut masked = Vec::new();
        for (index, setup) in setups.into_iter().enumerate() {
            let independently_verified = round.verify_announcements(&announcements).unwrap();
            let mut participant = setup.complete(&independently_verified).unwrap();
            let n = index as i64 + 1;
            let contribution = participant.mask(&[n, 2 * n, -n]).unwrap();
            assert_ne!(contribution.masked_values, vec![n, 2 * n, -n]);
            let wire = serde_json::to_vec(&contribution).unwrap();
            masked.push(serde_json::from_slice(&wire).unwrap());
        }
        let sum = (count * (count + 1) / 2) as i64;
        assert_eq!(
            coordinator.aggregate(&masked).unwrap(),
            vec![sum, sum * 2, MODULUS as i64 - sum]
        );
        masked.reverse();
        assert_eq!(
            coordinator.aggregate(&masked).unwrap(),
            vec![sum, sum * 2, MODULUS as i64 - sum]
        );
    }
}

#[test]
fn pairwise_keys_agree_are_distinct_and_bind_the_complete_transcript() {
    let (_, participants) = prepared(3);
    let a = &participants[0].masks;
    let b = &participants[1].masks;
    let c = &participants[2].masks;
    assert_eq!(a.pairwise_seeds[&b.id], b.pairwise_seeds[&a.id]);
    assert_eq!(a.pairwise_seeds[&c.id], c.pairwise_seeds[&a.id]);
    assert_ne!(a.pairwise_seeds[&b.id], a.pairwise_seeds[&c.id]);
    assert_ne!(a.pairwise_seeds[&b.id], [0; 32]);

    let other_round = round(3, "different-release");
    // Even reusing test RNG bytes cannot reuse masks across round contexts.
    let other_setups = setups(&other_round, 91);
    let other_keys = other_round
        .verify_announcements(&messages(&other_setups))
        .unwrap();
    let other = other_setups
        .into_iter()
        .next()
        .unwrap()
        .complete(&other_keys)
        .unwrap();
    assert_ne!(a.pairwise_seeds[&b.id], other.masks.pairwise_seeds[&b.id]);
}

#[test]
fn changing_an_input_changes_the_decoded_aggregate() {
    let (keys, mut peers) = prepared(3);
    let original = keys.aggregate(&contributions(&mut peers)).unwrap();
    let (keys, mut peers) = prepared(3);
    let changed = vec![
        peers[0].mask(&[101, 2, -1]).unwrap(),
        peers[1].mask(&[2, 4, -2]).unwrap(),
        peers[2].mask(&[3, 6, -3]).unwrap(),
    ];
    let changed = keys.aggregate(&changed).unwrap();
    assert_eq!(changed[0], original[0] + 100);
    assert_eq!(&changed[1..], &original[1..]);
}

#[test]
fn configuration_rejects_invalid_domains_and_rosters() {
    for (session, count, dimension, modulus) in [
        (" ", 3, 3, MODULUS),
        ("round", 2, 3, MODULUS),
        ("round", 3, 0, MODULUS),
        ("round", 3, 3, 0),
        ("round", 3, 3, 1),
        ("round", 3, 3, u64::MAX),
    ] {
        assert!(
            AuthenticatedAggregationRound::new(
                session.into(),
                identities(count),
                dimension,
                modulus
            )
            .is_err()
        );
    }
    let mut ids = identities(3);
    ids.insert(
        ParticipantId(" ".into()),
        signing_key(4).verifying_key().to_bytes(),
    );
    assert!(AuthenticatedAggregationRound::new("r".into(), ids, 3, MODULUS).is_err());
    let mut ids = identities(3);
    ids.insert(
        ParticipantId("peer-02".into()),
        signing_key(0).verifying_key().to_bytes(),
    );
    assert!(AuthenticatedAggregationRound::new("r".into(), ids, 3, MODULUS).is_err());
    let mut ids = identities(3);
    ids.insert(ParticipantId("peer-02".into()), [0; 32]);
    assert!(AuthenticatedAggregationRound::new("r".into(), ids, 3, MODULUS).is_err());
}

#[test]
fn setup_requires_the_trusted_identity_signing_key() {
    let round = round(3, "r");
    let mut rng = StdRng::seed_from_u64(1);
    assert!(
        ParticipantKeySetup::new(
            &round,
            ParticipantId("peer-00".into()),
            signing_key(1),
            &mut rng
        )
        .is_err()
    );
    assert!(
        ParticipantKeySetup::new(
            &round,
            ParticipantId("unknown".into()),
            signing_key(0),
            &mut rng
        )
        .is_err()
    );
}

#[test]
fn complete_roster_is_required_before_agreement() {
    let round = round(3, "r");
    let setups = setups(&round, 1);
    let original = messages(&setups);
    assert!(round.verify_announcements(&original[..2]).is_err());
    let mut duplicate = original.clone();
    duplicate[2] = duplicate[0].clone();
    assert!(round.verify_announcements(&duplicate).is_err());
    let mut extra = original.clone();
    extra.push(original[0].clone());
    assert!(round.verify_announcements(&extra).is_err());
    let mut unknown = original.clone();
    unknown[0].participant_id = ParticipantId("unknown".into());
    assert!(round.verify_announcements(&unknown).is_err());
    let mut wrong_peers = original;
    wrong_peers[0]
        .peer_keys
        .remove(&ParticipantId("peer-01".into()));
    assert!(round.verify_announcements(&wrong_peers).is_err());
}

#[test]
fn announcements_authenticate_public_keys_and_round_context() {
    let round = round(3, "r");
    let setups = setups(&round, 1);
    let original = messages(&setups);
    let mut tampered = original.clone();
    tampered[0]
        .peer_keys
        .get_mut(&ParticipantId("peer-01".into()))
        .unwrap()[0] ^= 1;
    assert!(round.verify_announcements(&tampered).is_err());
    let mut tampered = original.clone();
    tampered[0].round_binding[0] ^= 1;
    assert!(round.verify_announcements(&tampered).is_err());
    let mut tampered = original.clone();
    tampered[0].signature[0] ^= 1;
    assert!(round.verify_announcements(&tampered).is_err());
    let mut tampered = original.clone();
    tampered[0].signature.pop();
    assert!(round.verify_announcements(&tampered).is_err());
    assert!(
        self::round(3, "other")
            .verify_announcements(&original)
            .is_err()
    );
}

#[test]
fn public_transcript_order_does_not_change_agreement() {
    let round = round(3, "r");
    let setups = setups(&round, 1);
    let mut announcements = messages(&setups);
    let expected = round
        .verify_announcements(&announcements)
        .unwrap()
        .binding();
    announcements.reverse();
    let keys = round.verify_announcements(&announcements).unwrap();
    assert_eq!(keys.binding(), expected);
    for setup in setups {
        assert!(setup.complete(&keys).is_ok());
    }
}

#[test]
fn own_setup_cannot_be_replaced_even_by_another_validly_signed_key() {
    let round = round(3, "r");
    let original = setups(&round, 1);
    let replacement = setups(&round, 2);
    let mut announcements = messages(&original);
    announcements[0] = replacement[0].announcement().clone();
    let keys = round.verify_announcements(&announcements).unwrap();
    assert!(
        original
            .into_iter()
            .next()
            .unwrap()
            .complete(&keys)
            .is_err()
    );
}

#[test]
fn authenticated_low_order_dh_keys_are_rejected() {
    // A roster member can sign an invalid DH key; signature validity alone is
    // insufficient. Both canonical small-order encodings yield public zero.
    for key in [[0u8; 32], {
        let mut one = [0u8; 32];
        one[0] = 1;
        one
    }] {
        let round = round(3, "r");
        let setups = setups(&round, 1);
        let mut announcements = messages(&setups);
        announcements[1]
            .peer_keys
            .insert(ParticipantId("peer-00".into()), key);
        announcements[1].signature = signing_key(1)
            .sign(&announcements[1].digest())
            .to_bytes()
            .to_vec();
        let keys = round.verify_announcements(&announcements).unwrap();
        assert!(matches!(
            setups.into_iter().next().unwrap().complete(&keys),
            Err(SecureAggregationError::CryptographicError(_))
        ));
    }
}

#[test]
fn invalid_dimensions_do_not_spend_the_single_submission() {
    let (keys, mut peers) = prepared(3);
    assert!(matches!(
        peers[0].mask(&[1]),
        Err(SecureAggregationError::InvalidDimension)
    ));
    let masked = contributions(&mut peers);
    assert!(keys.aggregate(&masked).is_ok());
    assert!(matches!(
        peers[0].mask(&[1, 2, 3]),
        Err(SecureAggregationError::InvalidState)
    ));
}

#[test]
fn coordinator_rejects_missing_duplicate_and_unknown_contributors() {
    let (keys, mut peers) = prepared(3);
    let original = contributions(&mut peers);
    assert!(keys.aggregate(&original[..2]).is_err());
    let mut duplicate = original.clone();
    duplicate[2] = duplicate[0].clone();
    assert!(keys.aggregate(&duplicate).is_err());
    let mut unknown = original.clone();
    unknown[0].participant_id = ParticipantId("unknown".into());
    assert!(keys.aggregate(&unknown).is_err());
    assert!(keys.aggregate(&original).is_ok());
}

#[test]
fn coordinator_rejects_tampered_values_identity_and_signature() {
    let (keys, mut peers) = prepared(3);
    let original = contributions(&mut peers);
    let mut changed = original.clone();
    changed[0].masked_values[0] = (changed[0].masked_values[0] + 1) % MODULUS as i64;
    assert!(keys.aggregate(&changed).is_err());
    let mut changed = original.clone();
    changed[0].signature[0] ^= 1;
    assert!(keys.aggregate(&changed).is_err());
    let mut changed = original.clone();
    changed[0].signature.clear();
    assert!(keys.aggregate(&changed).is_err());
    let mut changed = original.clone();
    let first = changed[0].participant_id.clone();
    changed[0].participant_id = changed[1].participant_id.clone();
    changed[1].participant_id = first;
    assert!(keys.aggregate(&changed).is_err());
    assert!(keys.aggregate(&original).is_ok());
}

#[test]
fn coordinator_rejects_signed_out_of_domain_vectors() {
    let (keys, mut peers) = prepared(3);
    let original = contributions(&mut peers);
    for vector in [vec![1, 2], vec![-1, 2, 3], vec![MODULUS as i64, 2, 3]] {
        let mut malformed = original.clone();
        malformed[0].masked_values = vector;
        malformed[0].signature = signing_key(0)
            .sign(&malformed[0].digest())
            .to_bytes()
            .to_vec();
        assert!(keys.aggregate(&malformed).is_err());
    }
}

#[test]
fn contributions_cannot_cross_transcripts_even_with_the_same_session() {
    let round = round(3, "epoch-7-release-1");
    let setups = setups(&round, 999);
    let different_keys = round.verify_announcements(&messages(&setups)).unwrap();
    let (keys, mut peers) = prepared(3);
    let masked = contributions(&mut peers);
    assert_ne!(keys.binding(), different_keys.binding());
    assert!(different_keys.aggregate(&masked).is_err());
    let mut forged_binding = masked;
    for message in &mut forged_binding {
        message.key_set_binding = different_keys.binding();
    }
    assert!(different_keys.aggregate(&forged_binding).is_err());
}

#[test]
fn round_binding_covers_identity_keys_dimension_and_field() {
    let base = round(3, "r");
    for (dimension, modulus) in [(4, MODULUS), (3, MODULUS - 1)] {
        let other =
            AuthenticatedAggregationRound::new("r".into(), identities(3), dimension, modulus)
                .unwrap();
        assert_ne!(base.binding(), other.binding());
    }
    let mut keys = identities(3);
    keys.insert(
        ParticipantId("peer-00".into()),
        signing_key(4).verifying_key().to_bytes(),
    );
    let other = AuthenticatedAggregationRound::new("r".into(), keys, 3, MODULUS).unwrap();
    assert_ne!(base.binding(), other.binding());
}

#[test]
fn large_signed_coordinates_sum_without_i64_overflow() {
    let round =
        AuthenticatedAggregationRound::new("large".into(), identities(3), 3, i64::MAX as u64)
            .unwrap();
    let setups = setups(&round, 1);
    let keys = round.verify_announcements(&messages(&setups)).unwrap();
    let masked: Vec<_> = setups
        .into_iter()
        .map(|setup| {
            setup
                .complete(&keys)
                .unwrap()
                .mask(&[i64::MAX - 1, i64::MIN, i64::MAX])
                .unwrap()
        })
        .collect();
    assert_eq!(
        keys.aggregate(&masked).unwrap(),
        vec![i64::MAX - 3, i64::MAX - 3, 0]
    );
}
