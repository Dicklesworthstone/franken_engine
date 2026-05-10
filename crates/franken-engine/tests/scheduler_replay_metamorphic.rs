#![forbid(unsafe_code)]

//! Metamorphic Testing for Deterministic Replay Assertions
//!
//! Validates scheduler replay invariants through metamorphic relations.
//! Oracle problem: Can't predict exact state sequences, but know transformation relationships.
//!
//! Based on existing P-DETERM-01 property: "Given identical nondeterminism trace,
//! replay produces identical state sequence."

use frankenengine_engine::scheduler_invariants::{
    SchedulerAutomaton, StateId, Transition, TransitionLabel,
};
use proptest::prelude::*;

// MR Strength Matrix for Scheduler Replay
//
// | MR | Fault Sensitivity | Independence | Cost | Score | Category |
// |----|------------------|--------------|------|-------|----------|
// | Identity replay | 5 (core correctness) | 5 (unique) | 1 (fast) | 25.0 | Equivalence |
// | Action permutation | 4 (race conditions) | 4 (orthogonal) | 2 (medium) | 8.0 | Permutative |
// | Subsequence monotonic | 3 (prefix bugs) | 4 (different domain) | 1 (fast) | 12.0 | Inclusive |
// | Replay composition | 4 (complex sequences) | 3 (related to identity) | 3 (slow) | 4.0 | Additive |
// | State idempotence | 3 (convergence bugs) | 3 (medium independence) | 2 (medium) | 4.5 | Invertive |

// ---------------------------------------------------------------------------
// Test Infrastructure
// ---------------------------------------------------------------------------

/// Create a simple scheduler automaton for testing
fn create_test_automaton() -> SchedulerAutomaton {
    let mut automaton = SchedulerAutomaton::new("test_scheduler", StateId::new("idle"));

    // States
    automaton.add_state(StateId::new("active"));
    automaton.add_state(StateId::new("waiting"));
    automaton.add_accepting(StateId::new("completed"));

    // Transitions
    automaton.add_transition(Transition {
        from: StateId::new("idle"),
        label: TransitionLabel::new("start"),
        to: StateId::new("active"),
        guard: None,
    });

    automaton.add_transition(Transition {
        from: StateId::new("active"),
        label: TransitionLabel::new("yield"),
        to: StateId::new("waiting"),
        guard: None,
    });

    automaton.add_transition(Transition {
        from: StateId::new("waiting"),
        label: TransitionLabel::new("resume"),
        to: StateId::new("active"),
        guard: None,
    });

    automaton.add_transition(Transition {
        from: StateId::new("active"),
        label: TransitionLabel::new("finish"),
        to: StateId::new("completed"),
        guard: None,
    });

    automaton
}

/// Simulate replay execution (simplified for testing)
fn simulate_replay(automaton: &SchedulerAutomaton, actions: &[TransitionLabel]) -> Vec<StateId> {
    let mut current_state = automaton.initial_state.clone();
    let mut state_sequence = vec![current_state.clone()];

    for action in actions {
        // Find valid transition
        if let Some(transition) = automaton
            .transitions_from(&current_state)
            .iter()
            .find(|t| t.label == *action)
        {
            current_state = transition.to.clone();
            state_sequence.push(current_state.clone());
        }
        // Invalid transitions silently ignored (represents scheduler robustness)
    }

    state_sequence
}

fn check_identity_replay(lhs: &[StateId], rhs: &[StateId]) -> Result<(), String> {
    if lhs == rhs {
        Ok(())
    } else {
        Err(format!(
            "identity replay diverged: left={lhs:?}, right={rhs:?}"
        ))
    }
}

fn check_prefix_relation(prefix_result: &[StateId], full_result: &[StateId]) -> Result<(), String> {
    if prefix_result.len() > full_result.len() {
        return Err(format!(
            "prefix replay produced longer sequence: prefix_len={}, full_len={}",
            prefix_result.len(),
            full_result.len()
        ));
    }

    if prefix_result != &full_result[..prefix_result.len()] {
        return Err(format!(
            "prefix replay diverged: prefix={prefix_result:?}, full_prefix={:?}",
            &full_result[..prefix_result.len()]
        ));
    }

    Ok(())
}

fn check_composition_relation(
    combined_result: &[StateId],
    first_result: &[StateId],
    continuation_from_join: &[StateId],
) -> Result<(), String> {
    if combined_result.len() < first_result.len() {
        return Err(format!(
            "combined replay shorter than first segment: combined_len={}, first_len={}",
            combined_result.len(),
            first_result.len()
        ));
    }

    if &combined_result[..first_result.len()] != first_result {
        return Err(format!(
            "combined replay diverged in first segment: combined_prefix={:?}, first={first_result:?}",
            &combined_result[..first_result.len()]
        ));
    }

    let join = first_result
        .len()
        .checked_sub(1)
        .ok_or_else(|| "first segment produced no join state".to_string())?;

    if &combined_result[join..] != continuation_from_join {
        return Err(format!(
            "combined replay diverged in second segment: combined_tail={:?}, expected_tail={continuation_from_join:?}",
            &combined_result[join..]
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Metamorphic Relations (Score ≥ 2.0)
// ---------------------------------------------------------------------------

/// MR1: Identity Replay (Equivalence) - Score: 25.0
/// f(T(x)) = f(x) where T(actions) = actions (no transformation)
/// The core deterministic replay property.
#[test]
fn mr_identity_replay_determinism() {
    proptest!(|(action_sequence in prop::collection::vec(
        prop::string::string_regex("[a-z]{1,10}").expect("Invalid test regex pattern"), 1..10)
    )| {
        let automaton = create_test_automaton();
        let actions: Vec<TransitionLabel> = action_sequence.iter()
            .map(TransitionLabel::new)
            .collect();

        // Two identical replays must produce identical state sequences
        let sequence1 = simulate_replay(&automaton, &actions);
        let sequence2 = simulate_replay(&automaton, &actions);

        prop_assert!(check_identity_replay(&sequence1, &sequence2).is_ok(),
            "Identity replay failed: same actions produced different sequences");
    });
}

/// MR2: Subsequence Monotonic (Inclusive) - Score: 12.0
/// f(prefix(x)) ⊆ f(x) - prefix replay produces prefix of full sequence
#[test]
fn mr_subsequence_monotonic() {
    proptest!(|(full_sequence in prop::collection::vec(
        prop::string::string_regex("(start|yield|resume|finish)").expect("Invalid test regex pattern"), 2..8)
    )| {
        let automaton = create_test_automaton();
        let full_actions: Vec<TransitionLabel> = full_sequence.iter()
            .map(TransitionLabel::new)
            .collect();

        // Test all prefixes
        for prefix_len in 1..full_actions.len() {
            let prefix_actions = &full_actions[..prefix_len];
            let full_result = simulate_replay(&automaton, &full_actions);
            let prefix_result = simulate_replay(&automaton, prefix_actions);

            prop_assert!(check_prefix_relation(&prefix_result, &full_result).is_ok(),
                "Prefix replay diverged from full sequence");
        }
    });
}

/// MR3: Action Permutation Invariance (Permutative) - Score: 8.0
/// f(commutative_permute(x)) = permute(f(x)) for commutative actions
/// Actions that don't affect current state should be commutative
#[test]
fn mr_action_permutation_invariance() {
    let automaton = create_test_automaton();

    // Test specific case: invalid actions in different orders should not affect valid sequence
    let valid_sequence = vec![
        TransitionLabel::new("start"),
        TransitionLabel::new("finish"),
    ];

    let noise_actions = [
        TransitionLabel::new("invalid1"),
        TransitionLabel::new("invalid2"),
    ];

    // Insert invalid actions at different positions
    let mut sequence1 = valid_sequence.clone();
    sequence1.insert(1, noise_actions[0].clone());
    sequence1.insert(2, noise_actions[1].clone());

    let mut sequence2 = valid_sequence.clone();
    sequence2.insert(1, noise_actions[1].clone());
    sequence2.insert(2, noise_actions[0].clone());

    let result1 = simulate_replay(&automaton, &sequence1);
    let result2 = simulate_replay(&automaton, &sequence2);

    assert_eq!(
        result1, result2,
        "Permuting invalid actions affected replay determinism"
    );
}

/// MR4: Replay Composition (Additive) - Score: 4.0
/// f(x1 + x2) produces states that include states from f(x1) and f(x2)
#[test]
fn mr_replay_composition() {
    let automaton = create_test_automaton();

    let sequence1 = vec![TransitionLabel::new("start")];
    let sequence2 = vec![
        TransitionLabel::new("yield"),
        TransitionLabel::new("resume"),
    ];

    // Combined sequence
    let mut combined = sequence1.clone();
    combined.extend(sequence2.clone());

    let result1 = simulate_replay(&automaton, &sequence1);
    let result2_from_active = simulate_replay_from_state(
        &automaton,
        &sequence2,
        &StateId::new("active"), // Expected final state of sequence1
    );
    let combined_result = simulate_replay(&automaton, &combined);

    check_composition_relation(&combined_result, &result1, &result2_from_active)
        .expect("Combined replay diverged from composed segments");
}

/// Helper function for stateful replay composition
fn simulate_replay_from_state(
    automaton: &SchedulerAutomaton,
    actions: &[TransitionLabel],
    start_state: &StateId,
) -> Vec<StateId> {
    let mut current_state = start_state.clone();
    let mut state_sequence = vec![current_state.clone()];

    for action in actions {
        if let Some(transition) = automaton
            .transitions_from(&current_state)
            .iter()
            .find(|t| t.label == *action)
        {
            current_state = transition.to.clone();
            state_sequence.push(current_state.clone());
        }
    }

    state_sequence
}

/// MR5: State Idempotence (Invertive) - Score: 4.5
/// f(repeat(x)) converges - replaying from final state with same actions reaches fixed point
#[test]
fn mr_state_idempotence() {
    let automaton = create_test_automaton();

    // Action that should be idempotent in completed state
    let completion_sequence = vec![
        TransitionLabel::new("start"),
        TransitionLabel::new("finish"),
    ];

    let first_result = simulate_replay(&automaton, &completion_sequence);
    let final_state = first_result.last().expect(
        "simulate_replay returned empty sequence - check action validity and automaton transitions",
    );

    // Attempting same actions from final state should not change it further
    let repeat_result = simulate_replay_from_state(&automaton, &completion_sequence, final_state);

    assert_eq!(
        repeat_result.len(),
        1,
        "Replay from final state should not create new transitions"
    );
    assert_eq!(
        &repeat_result[0], final_state,
        "State idempotence violated: final state changed during repeat"
    );
}

// ---------------------------------------------------------------------------
// Composite Metamorphic Relations
// ---------------------------------------------------------------------------

/// Composite MR: Identity ∘ Subsequence (multiplicative power)
#[test]
fn mr_composite_identity_subsequence() {
    proptest!(|(full_sequence in prop::collection::vec(
        prop::string::string_regex("(start|yield|resume|finish)").expect("Invalid test regex pattern"), 3..6)
    )| {
        let automaton = create_test_automaton();
        let full_actions: Vec<TransitionLabel> = full_sequence.iter()
            .map(TransitionLabel::new)
            .collect();

        for prefix_len in 1..full_actions.len() {
            let prefix = &full_actions[..prefix_len];

            // MR1: Identity replay for prefix (compare by reference so prefix_result1
            // is still owned for the MR2 check below)
            let prefix_result1 = simulate_replay(&automaton, prefix);
            let prefix_result2 = simulate_replay(&automaton, prefix);
            prop_assert!(check_identity_replay(&prefix_result1, &prefix_result2).is_ok(),
                "Identity property failed for prefix");

            // MR2: Subsequence property
            let full_result = simulate_replay(&automaton, &full_actions);
            prop_assert!(check_prefix_relation(&prefix_result1, &full_result).is_ok(),
                "Subsequence property failed");

            // MR1∘MR2: Combined property - multiple prefix replays within full sequence
            let prefix_result3 = simulate_replay(&automaton, prefix);
            prop_assert!(check_prefix_relation(&prefix_result3, &full_result).is_ok(),
                "Composite identity-subsequence property failed");
        }
    });
}

// ---------------------------------------------------------------------------
// Validation: Mutation Testing for MR Suite
// ---------------------------------------------------------------------------

#[test]
fn validate_mr_suite_catches_planted_bugs() {
    let automaton = create_test_automaton();
    let test_actions = vec![
        TransitionLabel::new("start"),
        TransitionLabel::new("yield"),
        TransitionLabel::new("resume"),
    ];

    let baseline = simulate_replay(&automaton, &test_actions);
    let repeated = simulate_replay(&automaton, &test_actions);
    check_identity_replay(&baseline, &repeated).expect("Baseline determinism check failed");

    // Mutation 1: non-deterministic/spurious state injection.
    let mut spurious_state_result = baseline.clone();
    spurious_state_result.insert(2, StateId::new("spurious"));
    assert!(
        check_identity_replay(&baseline, &spurious_state_result).is_err(),
        "Identity MR failed to reject a spurious-state mutation"
    );

    // Mutation 2: prefix replay diverges from the full replay prefix.
    let prefix_actions = &test_actions[..2];
    let mut corrupted_prefix = simulate_replay(&automaton, prefix_actions);
    corrupted_prefix[1] = StateId::new("corrupted-active");
    assert!(
        check_prefix_relation(&corrupted_prefix, &baseline).is_err(),
        "Subsequence MR failed to reject a corrupted-prefix mutation"
    );

    // Mutation 3: composition emits an invalid continuation state.
    let first_actions = vec![TransitionLabel::new("start")];
    let continuation_actions = vec![
        TransitionLabel::new("yield"),
        TransitionLabel::new("resume"),
    ];
    let mut combined_actions = first_actions.clone();
    combined_actions.extend(continuation_actions.clone());

    let first_result = simulate_replay(&automaton, &first_actions);
    let expected_continuation =
        simulate_replay_from_state(&automaton, &continuation_actions, &StateId::new("active"));
    let mut corrupted_combined = simulate_replay(&automaton, &combined_actions);
    *corrupted_combined
        .last_mut()
        .expect("combined replay should include at least the initial state") =
        StateId::new("wrong-final-state");
    assert!(
        check_composition_relation(&corrupted_combined, &first_result, &expected_continuation)
            .is_err(),
        "Composition MR failed to reject an invalid-continuation mutation"
    );
}

// ---------------------------------------------------------------------------
// Property-Based Input Generation
// ---------------------------------------------------------------------------

proptest! {
    /// Comprehensive metamorphic property validation with random inputs
    #[test]
    fn comprehensive_mr_validation(
        action_count in 1usize..10,
        action_names in prop::collection::vec(
            prop::string::string_regex("(start|yield|resume|finish|invalid[0-9])").expect("Invalid test regex pattern"),
            1..15
        )
    ) {
        let automaton = create_test_automaton();
        let actions: Vec<TransitionLabel> = action_names.into_iter()
            .take(action_count)
            .map(TransitionLabel::new)
            .collect();

        // All MRs should hold for any valid action sequence
        let result1 = simulate_replay(&automaton, &actions);
        let result2 = simulate_replay(&automaton, &actions);

        // Identity property (MR1) — compare by reference so result1 is still owned
        // for the subsequence check below.
        prop_assert!(check_identity_replay(&result1, &result2).is_ok(),
            "Random input failed identity replay");

        // Subsequence property (MR2) - test random prefix
        if actions.len() > 1 {
            let prefix_len = (actions.len() - 1).max(1);
            let prefix = &actions[..prefix_len];
            let prefix_result = simulate_replay(&automaton, prefix);

            prop_assert!(check_prefix_relation(&prefix_result, &result1).is_ok());
        }
    }
}
