//! Integration tests for `policy_backtest` (E10.T3, `bd-fqlfw.10.3`).
//!
//! Exercises the full public pipeline from outside the crate: corpus of
//! propensity-scored logs → off-policy backtest vs the incumbent → signed
//! report → tamper-evident verification → fail-closed promotion gate.

use frankenengine_engine::counterfactual_evaluator::{
    BaselinePolicy, EnvelopeStatus, EstimatorKind, EvaluatorConfig, LoggedTransition, PolicyId,
    TargetPolicyMapping, TransitionBatch,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_backtest::{
    BacktestCorpusItem, BacktestWaiver, CorpusItemKind, PolicyBacktestError, PolicyBacktester,
    PromotionGateDecision, promotion_gate, recompute_artifact_hash, sign_report,
    verify_signed_report,
};
use frankenengine_engine::runtime_decision_theory::{LaneAction, RegimeLabel};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::generate_keypair_from_seed;

fn batch(count: usize, propensity: i64, reward: i64, regime: RegimeLabel) -> TransitionBatch {
    TransitionBatch {
        policy_id: PolicyId("incumbent-logged".to_string()),
        transitions: (0..count)
            .map(|index| LoggedTransition {
                epoch: SecurityEpoch::from_raw(7),
                tick: index as u64,
                regime,
                action_taken: LaneAction::FallbackSafe,
                propensity_millionths: propensity,
                reward_millionths: reward,
                model_prediction_millionths: None,
                context_hash: ContentHash::compute(format!("ctx-{index}").as_bytes()),
            })
            .collect(),
    }
}

fn candidate_mapping(count: usize, propensity: i64) -> TargetPolicyMapping {
    TargetPolicyMapping {
        target_policy_id: PolicyId("candidate-v2".to_string()),
        target_propensities_millionths: vec![propensity; count],
        target_model_predictions_millionths: None,
    }
}

fn item(
    item_id: &str,
    kind: CorpusItemKind,
    regime: RegimeLabel,
    reward: i64,
) -> BacktestCorpusItem {
    BacktestCorpusItem {
        item_id: item_id.to_string(),
        kind,
        batch: batch(200, 500_000, reward, regime),
        candidate_mapping: candidate_mapping(200, 500_000),
    }
}

fn unsafe_backtester() -> PolicyBacktester {
    // Identical candidate/logged propensities give ~zero improvement; an
    // improvement threshold of 0.5 makes every item deterministically
    // Unsafe (the evaluator's own documented construction).
    let config = EvaluatorConfig {
        estimator: EstimatorKind::Ips,
        improvement_threshold_millionths: 500_000,
        regime_breakdown: true,
        ..Default::default()
    };
    PolicyBacktester::new(config, BaselinePolicy::default())
        .expect("backtester construction should succeed")
}

#[test]
fn end_to_end_backtest_sign_verify_gate() {
    let mut backtester = unsafe_backtester();
    let corpus = vec![
        item(
            "benign-001",
            CorpusItemKind::Benign,
            RegimeLabel::Normal,
            400_000,
        ),
        item(
            "benign-002",
            CorpusItemKind::Benign,
            RegimeLabel::Elevated,
            350_000,
        ),
        item(
            "incident-001",
            CorpusItemKind::Incident,
            RegimeLabel::Attack,
            600_000,
        ),
    ];

    let report = backtester.run(&corpus).expect("backtest should run");
    assert_eq!(report.corpus_size, 3);
    assert_eq!(report.candidate_policy_id, "candidate-v2");
    assert_eq!(report.incumbent_policy_id, "baseline-safe-mode");
    assert_eq!(report.item_outcomes.len(), 3);
    assert!(report.benign_improvement.is_some());
    assert!(report.incident_improvement.is_some());
    assert!(report.overall_improvement.is_some());
    // Per-regime entries survive the merge.
    assert!(!report.regime_breakdown.is_empty());
    // High-threshold config: every item Unsafe, verdict fail-closed Unsafe.
    assert_eq!(report.verdict, EnvelopeStatus::Unsafe);
    assert_eq!(report.unsafe_item_ids.len(), 3);

    // Sign, verify, and confirm tamper evidence.
    let (signing_key, _) = generate_keypair_from_seed(&[42u8; 32]);
    let signed = sign_report(&report, &signing_key).expect("signing should succeed");
    verify_signed_report(&signed).expect("verification should succeed");
    assert_eq!(
        recompute_artifact_hash(&signed.report).expect("recompute should succeed"),
        signed.report.artifact_hash_hex
    );

    let mut tampered = signed.clone();
    tampered.report.unsafe_item_ids.clear();
    assert!(verify_signed_report(&tampered).is_err());

    // Fail-closed gate: Unsafe verdict cannot promote without a waiver.
    match promotion_gate(&report, None) {
        PromotionGateDecision::Rejected { verdict, .. } => {
            assert_eq!(verdict, EnvelopeStatus::Unsafe);
        }
        other => panic!("expected rejection, got {other:?}"),
    }
    // An explicit waiver promotes but records who approved it.
    let waiver = BacktestWaiver {
        waiver_id: "ops-waiver-9".to_string(),
        reason: "candidate fixes a worse regression; manual review attached".to_string(),
        approved_by: "operator-on-call".to_string(),
    };
    match promotion_gate(&report, Some(&waiver)) {
        PromotionGateDecision::ApprovedByWaiver {
            waiver_id,
            approved_by,
            ..
        } => {
            assert_eq!(waiver_id, "ops-waiver-9");
            assert_eq!(approved_by, "operator-on-call");
        }
        other => panic!("expected waiver approval, got {other:?}"),
    }
}

#[test]
fn backtest_is_reproducible_for_a_fixed_corpus() {
    let corpus = vec![
        item(
            "benign-001",
            CorpusItemKind::Benign,
            RegimeLabel::Normal,
            400_000,
        ),
        item(
            "incident-001",
            CorpusItemKind::Incident,
            RegimeLabel::Attack,
            600_000,
        ),
    ];
    let first = unsafe_backtester()
        .run(&corpus)
        .expect("backtest should run");
    let second = unsafe_backtester()
        .run(&corpus)
        .expect("backtest should run");
    assert_eq!(first, second);
    assert_eq!(first.artifact_hash_hex, second.artifact_hash_hex);
}

#[test]
fn corpus_hygiene_is_fail_closed() {
    let mut backtester = unsafe_backtester();
    assert_eq!(backtester.run(&[]), Err(PolicyBacktestError::EmptyCorpus));

    let corpus = vec![
        item("dup", CorpusItemKind::Benign, RegimeLabel::Normal, 1_000),
        item("dup", CorpusItemKind::Incident, RegimeLabel::Normal, 1_000),
    ];
    assert!(matches!(
        backtester.run(&corpus),
        Err(PolicyBacktestError::DuplicateItemId { .. })
    ));

    let mut mixed = vec![
        item("a", CorpusItemKind::Benign, RegimeLabel::Normal, 1_000),
        item("b", CorpusItemKind::Benign, RegimeLabel::Normal, 1_000),
    ];
    mixed[1].candidate_mapping.target_policy_id = PolicyId("someone-else".to_string());
    assert!(matches!(
        backtester.run(&mixed),
        Err(PolicyBacktestError::MixedCandidatePolicies { .. })
    ));
}

#[test]
fn report_survives_serde_round_trip_with_signature() {
    let mut backtester = unsafe_backtester();
    let corpus = vec![item(
        "benign-001",
        CorpusItemKind::Benign,
        RegimeLabel::Normal,
        250_000,
    )];
    let report = backtester.run(&corpus).expect("backtest should run");
    let (signing_key, _) = generate_keypair_from_seed(&[3u8; 32]);
    let signed = sign_report(&report, &signing_key).expect("signing should succeed");

    let json = serde_json::to_string(&signed).expect("serialize should succeed");
    let decoded: frankenengine_engine::policy_backtest::SignedPolicyBacktestReport =
        serde_json::from_str(&json).expect("deserialize should succeed");
    assert_eq!(decoded, signed);
    verify_signed_report(&decoded).expect("decoded report should verify");
}
