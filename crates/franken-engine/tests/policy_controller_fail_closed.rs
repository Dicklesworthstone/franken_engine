//! Regression tests at the public policy-controller boundary.
//!
//! Invalid model inputs must never become successful, zero-cost decisions.

use std::collections::BTreeMap;

use frankenengine_engine::error_code::{FrankenErrorCode, HasErrorCode};
use frankenengine_engine::evidence_ledger::LedgerError;
use frankenengine_engine::policy_controller::{
    ControllerConfig, DecisionInputError, Guardrail, LossMatrix, PolicyController,
    PolicyControllerError, Posterior,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn posterior(entries: &[(&str, i64)]) -> Posterior {
    Posterior::new(
        entries
            .iter()
            .map(|(state, probability)| ((*state).to_string(), *probability))
            .collect::<BTreeMap<_, _>>(),
    )
}

fn controller(actions: &[&str], matrix: LossMatrix) -> PolicyController {
    PolicyController::new_lab(
        ControllerConfig {
            controller_id: "checked-policy".into(),
            domain: "capability".into(),
            action_set: actions.iter().map(|action| (*action).to_string()).collect(),
            safe_default: actions.last().expect("nonempty fixture").to_string(),
            policy_id: "checked-policy-v1".into(),
        },
        matrix,
    )
    .expect("valid controller configuration")
}

fn complete_matrix() -> LossMatrix {
    let mut matrix = LossMatrix::new();
    matrix.set("benign", "allow", 0);
    matrix.set("malicious", "allow", 100_000_000);
    matrix.set("benign", "deny", 1_000_000);
    matrix.set("malicious", "deny", 0);
    matrix
}

#[test]
fn unknown_cost_cannot_make_an_action_look_free() {
    let mut matrix = LossMatrix::new();
    matrix.set("benign", "allow", 0);
    matrix.set("benign", "deny", 1_000_000);
    matrix.set("malicious", "deny", 0);
    let distribution = posterior(&[("benign", 900_000), ("malicious", 100_000)]);
    assert_eq!(
        matrix.expected_loss("allow", &distribution),
        Err(DecisionInputError::MissingLossEntry {
            state: "malicious".into(),
            action: "allow".into(),
        })
    );
    let mut controller = controller(&["allow", "deny"], matrix);
    let error = controller
        .select_action(&distribution, SecurityEpoch::GENESIS, "missing-cost")
        .expect_err("missing malicious-state cost must not authorize allow");
    assert!(error.to_string().contains("malicious"));
    assert_eq!(
        error.error_code(),
        FrankenErrorCode::PolicyControllerDecisionError
    );
    assert_eq!(controller.decision_count(), 0);
    assert!(controller.decisions().is_empty());
}

#[test]
fn malformed_posteriors_fail_without_mutation_even_after_deserialization() {
    let cases: &[&[(&str, i64)]] = &[
        &[],
        &[("benign", 0)],
        &[("benign", 999_999)],
        &[("benign", 1_000_001)],
        &[("benign", -1), ("malicious", 1_000_001)],
        &[("benign", 600_000), ("malicious", 600_000)],
        &[("benign", i64::MIN), ("malicious", i64::MAX)],
    ];
    let mut controller = controller(&["allow", "deny"], complete_matrix());
    for case in cases {
        let json = serde_json::to_string(&posterior(case)).expect("serialize fixture");
        let distribution: Posterior = serde_json::from_str(&json).expect("deserialize fixture");
        assert!(matches!(
            distribution.validate(),
            Err(DecisionInputError::InvalidPosterior { .. })
        ));
        assert!(
            controller
                .select_action(&distribution, SecurityEpoch::GENESIS, "bad-posterior")
                .is_err()
        );
        assert_eq!(controller.decision_count(), 0);
        assert!(controller.decisions().is_empty());
    }
}

#[test]
fn empty_loss_matrix_is_not_a_model_of_free_actions() {
    let mut controller = controller(&["allow", "deny"], LossMatrix::new());
    assert_eq!(
        controller.select_action(
            &posterior(&[("benign", 1_000_000)]),
            SecurityEpoch::GENESIS,
            "empty-model",
        ),
        Err(PolicyControllerError::NoLossEntries)
    );
    assert_eq!(controller.decision_count(), 0);
    assert!(controller.decisions().is_empty());
}

#[test]
fn round_once_changes_the_winner_and_evidence_agrees() {
    let mut matrix = LossMatrix::new();
    matrix.set("a", "expensive", 1);
    matrix.set("b", "expensive", 1);
    matrix.set("a", "cheap", 0);
    matrix.set("b", "cheap", 1);
    let distribution = posterior(&[("a", 500_000), ("b", 500_000)]);
    // Previously each half-micro contribution rounded to zero, causing the
    // first action (expensive) to win a spurious tie. Its true total is one.
    let mut controller = controller(&["expensive", "cheap"], matrix);
    let selection = controller
        .select_action(&distribution, SecurityEpoch::GENESIS, "round-once")
        .expect("valid decision");
    assert_eq!(selection.action, "cheap");
    assert_eq!(selection.expected_loss, 0);
    let evidence = controller
        .build_evidence(
            &selection,
            &distribution,
            SecurityEpoch::GENESIS,
            "round-once",
        )
        .expect("valid evidence");
    let losses: BTreeMap<_, _> = evidence
        .candidates
        .iter()
        .map(|candidate| {
            (
                candidate.action_name.as_str(),
                candidate.expected_loss_millionths,
            )
        })
        .collect();
    assert_eq!(losses["expensive"], 1);
    assert_eq!(losses["cheap"], 0);
    assert_eq!(evidence.chosen_action.action_name, selection.action);
    assert_eq!(
        evidence.chosen_action.expected_loss_millionths,
        selection.expected_loss
    );
}

#[test]
fn failed_decision_does_not_consume_an_id_or_damage_prior_history() {
    let mut controller = controller(&["allow", "deny"], complete_matrix());
    let distribution = posterior(&[("benign", 900_000), ("malicious", 100_000)]);
    let first = controller
        .select_action(&distribution, SecurityEpoch::GENESIS, "first")
        .expect("first valid decision");
    assert_eq!(first.action, "deny");
    assert!(
        controller
            .select_action(&posterior(&[]), SecurityEpoch::GENESIS, "invalid")
            .is_err()
    );
    assert_eq!(controller.decision_count(), 1);
    assert_eq!(controller.decisions(), std::slice::from_ref(&first));
    let second = controller
        .select_action(&distribution, SecurityEpoch::GENESIS, "second")
        .expect("recovery after invalid input");
    assert_eq!(first.decision_id, "checked-policy-000001");
    assert_eq!(second.decision_id, "checked-policy-000002");
}

#[test]
fn evidence_rejects_invalid_posterior_and_incomplete_replacement_model() {
    let mut controller = controller(&["allow", "deny"], complete_matrix());
    let distribution = posterior(&[("benign", 900_000), ("malicious", 100_000)]);
    let selection = controller
        .select_action(&distribution, SecurityEpoch::GENESIS, "evidence-inputs")
        .expect("valid selection");
    let error = controller
        .build_evidence(&selection, &posterior(&[]), SecurityEpoch::GENESIS, "bad")
        .expect_err("invalid posterior cannot support evidence");
    assert!(matches!(error, LedgerError::SchemaValidationFailed { .. }));

    let mut incomplete = LossMatrix::new();
    incomplete.set("benign", "allow", 0);
    controller.update_loss_matrix(incomplete);
    assert!(
        controller
            .build_evidence(
                &selection,
                &distribution,
                SecurityEpoch::GENESIS,
                "bad-model"
            )
            .is_err()
    );
    assert!(
        controller
            .select_action(&distribution, SecurityEpoch::GENESIS, "bad-model")
            .is_err()
    );
    assert_eq!(controller.decision_count(), 1);
    assert_eq!(controller.decisions(), std::slice::from_ref(&selection));

    controller.update_loss_matrix(complete_matrix());
    let recovered = controller
        .select_action(&distribution, SecurityEpoch::GENESIS, "recovered")
        .expect("repaired model recovers without gaps in IDs");
    assert_eq!(recovered.decision_id, "checked-policy-000002");
}

#[test]
fn zero_mass_states_do_not_require_costs_but_positive_mass_states_do() {
    let mut matrix = LossMatrix::new();
    matrix.set("benign", "allow", 0);
    let mut controller = controller(&["allow"], matrix);
    let zero_mass = posterior(&[("benign", 1_000_000), ("unmodeled", 0)]);
    assert_eq!(
        controller
            .select_action(&zero_mass, SecurityEpoch::GENESIS, "zero")
            .unwrap()
            .expected_loss,
        0
    );
    let positive_mass = posterior(&[("benign", 999_999), ("unmodeled", 1)]);
    assert!(
        controller
            .select_action(&positive_mass, SecurityEpoch::GENESIS, "positive")
            .is_err()
    );
    assert_eq!(controller.decision_count(), 1);
}

#[test]
fn guardrail_blocked_actions_still_require_an_auditable_model() {
    let mut matrix = LossMatrix::new();
    matrix.set("benign", "deny", 1_000_000);
    let mut controller = controller(&["allow", "deny"], matrix);
    controller.add_guardrail(Guardrail {
        id: "block-allow".into(),
        description: "allow is blocked but remains an evidence candidate".into(),
        blocked_actions: vec!["allow".into()],
    });
    assert!(
        controller
            .select_action(
                &posterior(&[("benign", 1_000_000)]),
                SecurityEpoch::GENESIS,
                "guardrail"
            )
            .is_err()
    );
    assert_eq!(controller.decision_count(), 0);
}

#[test]
fn full_i64_cost_range_survives_public_selection() {
    for endpoint in [i64::MIN, i64::MAX] {
        let mut matrix = LossMatrix::new();
        for state in ["a", "b", "c"] {
            matrix.set(state, "only", endpoint);
        }
        let mut controller = controller(&["only"], matrix);
        let distribution = posterior(&[("a", 333_333), ("b", 333_333), ("c", 333_334)]);
        let selection = controller
            .select_action(&distribution, SecurityEpoch::GENESIS, "boundary")
            .expect("convex combination is representable at either i64 endpoint");
        assert_eq!(selection.expected_loss, endpoint);
    }
}
