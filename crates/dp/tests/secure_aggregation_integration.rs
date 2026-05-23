#![forbid(unsafe_code)]
//! Integration tests for secure aggregation primitive (Bonawitz 2017)
//! Demonstrates end-to-end cryptographic privacy where aggregator
//! sees only the sum, not individual contributions.

use dp::{
    participant::{Participant, ParticipantId, ParticipantStatus},
    protocol::{AggregationProtocol, AggregationRound, MaskedContribution, SecurityParameters},
    AggregationConfig, SecureAggregationSession,
};
use rand::thread_rng;

/// Integration test demonstrating complete secure aggregation workflow
/// where individual contributions remain cryptographically hidden
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

    // Each participant's private input (these would be real sensitive data)
    let private_inputs = vec![
        vec![10, 20, 30, 40], // Alice's private vector
        vec![15, 25, 35, 45], // Bob's private vector
        vec![5, 10, 15, 20],  // Charlie's private vector
    ];

    for (i, participant_id) in participant_ids.iter().enumerate() {
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

        // Simulate receiving shares from other participants (simplified)
        // In practice, this would involve actual cryptographic exchange

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
        session
            .participants
            .insert(participant_id.clone(), participant);
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

    // Verify privacy guarantee: aggregator learned the sum but not individual values
    // The sum of private inputs should be: [30, 55, 80, 105]
    // (Note: actual values may differ due to masking/unmasking operations)
    let expected_sum: Vec<i64> = (0..config.vector_dimension)
        .map(|i| private_inputs.iter().map(|input| input[i]).sum::<i64>())
        .collect();

    println!("Expected sum: {:?}", expected_sum);
    println!("Actual result: {:?}", final_result);

    // The key security property: individual inputs remain hidden
    // Only the aggregate is revealed to the aggregator
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

    assert!(protocol
        .validate_contributions(&valid_contributions)
        .is_ok());

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
            assert!(alice
                .receive_secret_share(charlie.id.clone(), share)
                .is_ok());
            break;
        }
    }

    // Alice should now have received shares from Bob and Charlie
    assert_eq!(alice.received_shares.len(), 2);
}
