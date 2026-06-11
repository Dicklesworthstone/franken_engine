//! Counterfactual policy backtesting (E10.T3, `bd-fqlfw.10.3`).
//!
//! "You can't ship a security policy without a signed backtest": replays a
//! corpus of recorded propensity-scored decision logs against a CANDIDATE
//! policy via the off-policy evaluator
//! ([`crate::counterfactual_evaluator::CounterfactualEvaluator`] — IPS /
//! doubly-robust / direct-method with propensity clamping) and emits a
//! signed [`PolicyBacktestReport`] of the candidate's counterfactual deltas
//! vs the incumbent: Δ false-quarantine (benign corpus), Δ missed-containment
//! (incident corpus), Δ expected loss (whole corpus), per-regime breakdown,
//! and an overall fail-closed Safe / Inconclusive / Unsafe verdict.
//!
//! Verdict semantics are worst-of over per-item
//! [`EnvelopeStatus`] (any `Unsafe` ⇒ `Unsafe`; else any `Inconclusive` ⇒
//! `Inconclusive`). Off-policy estimates are only valid where the candidate's
//! action distribution overlaps the logged policy's — that guardrail
//! surfaces LOUDLY through `inconclusive_item_ids` rather than being
//! averaged away, and the per-item [`EvaluationResult`]s ship inside the
//! report so a skeptic can re-derive every aggregate from the raw envelopes.
//!
//! The promotion gate is fail-closed: a candidate promotes only on a `Safe`
//! verdict or an explicit recorded waiver. This closes the loop the
//! IDEA-WIZARD-XI promotion controller started: policy changes become a
//! gated, evidence-backed step instead of a guess. Advisory/offline by
//! design — it calibrates against observed distributions and cannot
//! evaluate responses to attacks never recorded.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::counterfactual_evaluator::{
    BaselinePolicy, ConfidenceEnvelope, CounterfactualError, CounterfactualEvaluator,
    EnvelopeStatus, EvaluationResult, EvaluatorConfig, PolicyId, TargetPolicyMapping,
    TransitionBatch,
};
use crate::signature_preimage::{
    Signature, SignatureError, SigningKey, VerificationKey, sign_preimage, verify_signature,
};

/// Schema version for serialized backtest reports.
pub const POLICY_BACKTEST_SCHEMA_VERSION: &str = "franken-engine.policy-backtest.v1";

/// Component label for telemetry and evidence entries.
pub const POLICY_BACKTEST_COMPONENT: &str = "policy_backtest";

/// What a corpus item represents, which decides which headline delta its
/// improvement envelope feeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusItemKind {
    /// A recorded incident trace: containment was the right outcome, so a
    /// candidate that scores WORSE here increases missed-containment risk.
    Incident,
    /// A recorded benign trace: containment would have been a false
    /// positive, so a candidate that scores WORSE here increases
    /// false-quarantine risk.
    Benign,
}

impl CorpusItemKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Incident => "incident",
            Self::Benign => "benign",
        }
    }
}

/// One recorded trace in the backtest corpus: the logged transition batch
/// plus the candidate policy's propensities for the same transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BacktestCorpusItem {
    pub item_id: String,
    pub kind: CorpusItemKind,
    pub batch: TransitionBatch,
    pub candidate_mapping: TargetPolicyMapping,
}

/// Per-item outcome: the full evaluator result is preserved so every
/// aggregate in the report is re-derivable from raw envelopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BacktestItemOutcome {
    pub item_id: String,
    pub kind: CorpusItemKind,
    pub evaluation: EvaluationResult,
}

/// Effective-sample-weighted summary of per-item confidence envelopes.
///
/// This is a conservative weighted average of estimates and bounds — a
/// triage summary, NOT a rigorously pooled confidence interval. The
/// per-item envelopes ship alongside it in the report for exact analysis,
/// and the verdict never depends on this aggregation (it is worst-of over
/// per-item statuses).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateEnvelope {
    pub estimate_millionths: i64,
    pub lower_millionths: i64,
    pub upper_millionths: i64,
    pub total_effective_samples: u64,
    pub item_count: u64,
}

/// Aggregate envelopes weighted by effective sample count. Returns `None`
/// for an empty iterator or zero total weight (never fabricates a number).
pub fn aggregate_envelopes<'a, I>(envelopes: I) -> Option<AggregateEnvelope>
where
    I: IntoIterator<Item = &'a ConfidenceEnvelope>,
{
    let mut weighted_estimate: i128 = 0;
    let mut weighted_lower: i128 = 0;
    let mut weighted_upper: i128 = 0;
    let mut total_weight: u128 = 0;
    let mut item_count: u64 = 0;
    for envelope in envelopes {
        let weight = u128::from(envelope.effective_samples);
        weighted_estimate += i128::from(envelope.estimate_millionths) * weight as i128;
        weighted_lower += i128::from(envelope.lower_millionths) * weight as i128;
        weighted_upper += i128::from(envelope.upper_millionths) * weight as i128;
        total_weight += weight;
        item_count = item_count.saturating_add(1);
    }
    if total_weight == 0 {
        return None;
    }
    let divide = |numerator: i128| -> i64 {
        i64::try_from(numerator / total_weight as i128).unwrap_or(i64::MAX)
    };
    Some(AggregateEnvelope {
        estimate_millionths: divide(weighted_estimate),
        lower_millionths: divide(weighted_lower),
        upper_millionths: divide(weighted_upper),
        total_effective_samples: u64::try_from(total_weight).unwrap_or(u64::MAX),
        item_count,
    })
}

/// Errors from backtest orchestration. Fail-closed: any per-item evaluation
/// failure aborts the whole backtest (no silently skipped corpus items).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyBacktestError {
    /// An empty corpus cannot back a promotion decision.
    EmptyCorpus,
    /// Corpus items must all evaluate the same candidate policy.
    MixedCandidatePolicies { expected: String, found: String },
    /// Corpus item ids must be unique (they key the per-item outcomes).
    DuplicateItemId { item_id: String },
    /// The evaluator rejected an item.
    Evaluation {
        item_id: String,
        source: CounterfactualError,
    },
    /// Report (de)serialization failure.
    Serialization { detail: String },
    /// Signing or verification failure.
    Signature { detail: String },
}

impl std::fmt::Display for PolicyBacktestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyCorpus => f.write_str("backtest corpus is empty"),
            Self::MixedCandidatePolicies { expected, found } => write!(
                f,
                "corpus mixes candidate policies: expected {expected}, found {found}"
            ),
            Self::DuplicateItemId { item_id } => {
                write!(f, "duplicate corpus item id: {item_id}")
            }
            Self::Evaluation { item_id, source } => {
                write!(f, "evaluation failed for corpus item {item_id}: {source:?}")
            }
            Self::Serialization { detail } => write!(f, "serialization failure: {detail}"),
            Self::Signature { detail } => write!(f, "signature failure: {detail}"),
        }
    }
}

/// The signed-shape backtest report.
///
/// Sign convention: improvement envelopes are candidate-minus-incumbent in
/// reward millionths (positive = candidate better). The headline deltas are
/// in LOSS millionths (positive = candidate worse), i.e. the negated
/// improvement estimate, matching the bead's "Δ false-quarantine /
/// Δ missed-containment / Δ expected loss" framing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBacktestReport {
    pub schema_version: String,
    pub candidate_policy_id: String,
    pub incumbent_policy_id: String,
    pub corpus_size: u64,
    /// Full per-item evaluator results (re-derivability).
    pub item_outcomes: Vec<BacktestItemOutcome>,
    /// Weighted improvement aggregate over benign items.
    pub benign_improvement: Option<AggregateEnvelope>,
    /// Weighted improvement aggregate over incident items.
    pub incident_improvement: Option<AggregateEnvelope>,
    /// Weighted improvement aggregate over the whole corpus.
    pub overall_improvement: Option<AggregateEnvelope>,
    /// Headline: positive = candidate increases false-quarantine cost.
    pub delta_false_quarantine_millionths: Option<i64>,
    /// Headline: positive = candidate increases missed-containment cost.
    pub delta_missed_containment_millionths: Option<i64>,
    /// Headline: positive = candidate increases expected loss.
    pub delta_expected_loss_millionths: Option<i64>,
    /// Weighted candidate envelope per regime label, merged across items.
    pub regime_breakdown: BTreeMap<String, AggregateEnvelope>,
    /// Items whose envelope was Unsafe (candidate measurably worse).
    pub unsafe_item_ids: Vec<String>,
    /// Items whose envelope could not separate candidate from incumbent —
    /// the off-policy overlap guardrail surfacing loudly.
    pub inconclusive_item_ids: Vec<String>,
    /// Worst-of verdict over per-item statuses (fail-closed).
    pub verdict: EnvelopeStatus,
    /// SHA-256 hex of the report serialized with this field empty.
    pub artifact_hash_hex: String,
}

/// A backtest report plus its Ed25519 signature and signer key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPolicyBacktestReport {
    pub report: PolicyBacktestReport,
    pub signer_key: VerificationKey,
    pub signature: Signature,
}

/// Worst-of verdict: any Unsafe dominates, then any Inconclusive, else Safe.
/// An empty outcome set is Inconclusive (never Safe by vacuity).
pub fn compute_verdict(outcomes: &[BacktestItemOutcome]) -> EnvelopeStatus {
    if outcomes.is_empty() {
        return EnvelopeStatus::Inconclusive;
    }
    let mut verdict = EnvelopeStatus::Safe;
    for outcome in outcomes {
        match outcome.evaluation.safety_status {
            EnvelopeStatus::Unsafe => return EnvelopeStatus::Unsafe,
            EnvelopeStatus::Inconclusive => verdict = EnvelopeStatus::Inconclusive,
            EnvelopeStatus::Safe => {}
        }
    }
    verdict
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Build the aggregated report from per-item outcomes (pure; no evaluator).
pub fn build_report(
    candidate_policy_id: &PolicyId,
    incumbent_policy_id: &PolicyId,
    item_outcomes: Vec<BacktestItemOutcome>,
) -> Result<PolicyBacktestReport, PolicyBacktestError> {
    let benign_improvement = aggregate_envelopes(
        item_outcomes
            .iter()
            .filter(|outcome| outcome.kind == CorpusItemKind::Benign)
            .map(|outcome| &outcome.evaluation.improvement_envelope),
    );
    let incident_improvement = aggregate_envelopes(
        item_outcomes
            .iter()
            .filter(|outcome| outcome.kind == CorpusItemKind::Incident)
            .map(|outcome| &outcome.evaluation.improvement_envelope),
    );
    let overall_improvement = aggregate_envelopes(
        item_outcomes
            .iter()
            .map(|outcome| &outcome.evaluation.improvement_envelope),
    );

    let mut regime_envelopes: BTreeMap<String, Vec<&ConfidenceEnvelope>> = BTreeMap::new();
    for outcome in &item_outcomes {
        for (regime, envelope) in &outcome.evaluation.regime_breakdown {
            regime_envelopes
                .entry(regime.clone())
                .or_default()
                .push(envelope);
        }
    }
    let regime_breakdown: BTreeMap<String, AggregateEnvelope> = regime_envelopes
        .into_iter()
        .filter_map(|(regime, envelopes)| {
            aggregate_envelopes(envelopes.iter().copied()).map(|agg| (regime, agg))
        })
        .collect();

    let unsafe_item_ids: Vec<String> = item_outcomes
        .iter()
        .filter(|outcome| outcome.evaluation.safety_status == EnvelopeStatus::Unsafe)
        .map(|outcome| outcome.item_id.clone())
        .collect();
    let inconclusive_item_ids: Vec<String> = item_outcomes
        .iter()
        .filter(|outcome| outcome.evaluation.safety_status == EnvelopeStatus::Inconclusive)
        .map(|outcome| outcome.item_id.clone())
        .collect();

    let verdict = compute_verdict(&item_outcomes);
    let negate = |aggregate: &Option<AggregateEnvelope>| -> Option<i64> {
        aggregate
            .as_ref()
            .map(|agg| agg.estimate_millionths.saturating_neg())
    };

    let mut report = PolicyBacktestReport {
        schema_version: POLICY_BACKTEST_SCHEMA_VERSION.to_string(),
        candidate_policy_id: candidate_policy_id.0.clone(),
        incumbent_policy_id: incumbent_policy_id.0.clone(),
        corpus_size: item_outcomes.len() as u64,
        delta_false_quarantine_millionths: negate(&benign_improvement),
        delta_missed_containment_millionths: negate(&incident_improvement),
        delta_expected_loss_millionths: negate(&overall_improvement),
        item_outcomes,
        benign_improvement,
        incident_improvement,
        overall_improvement,
        regime_breakdown,
        unsafe_item_ids,
        inconclusive_item_ids,
        verdict,
        artifact_hash_hex: String::new(),
    };

    let payload =
        serde_json::to_vec(&report).map_err(|err| PolicyBacktestError::Serialization {
            detail: err.to_string(),
        })?;
    report.artifact_hash_hex = sha256_hex(&payload);
    Ok(report)
}

/// Recompute the artifact hash of a report (hash taken with the hash field
/// empty). Used by verification to detect tampering.
pub fn recompute_artifact_hash(
    report: &PolicyBacktestReport,
) -> Result<String, PolicyBacktestError> {
    let mut unhashed = report.clone();
    unhashed.artifact_hash_hex = String::new();
    let payload =
        serde_json::to_vec(&unhashed).map_err(|err| PolicyBacktestError::Serialization {
            detail: err.to_string(),
        })?;
    Ok(sha256_hex(&payload))
}

/// Backtest orchestrator: one evaluator (incumbent baseline) run across a
/// corpus of items for a single candidate policy.
#[derive(Debug)]
pub struct PolicyBacktester {
    evaluator: CounterfactualEvaluator,
}

impl PolicyBacktester {
    pub fn new(
        config: EvaluatorConfig,
        incumbent: BaselinePolicy,
    ) -> Result<Self, CounterfactualError> {
        Ok(Self {
            evaluator: CounterfactualEvaluator::new(config, incumbent)?,
        })
    }

    /// Run the full corpus. Fail-closed: empty corpus, duplicate item ids,
    /// mixed candidate policies, or any per-item evaluator error abort the
    /// backtest — corpus items are never silently skipped.
    pub fn run(
        &mut self,
        corpus: &[BacktestCorpusItem],
    ) -> Result<PolicyBacktestReport, PolicyBacktestError> {
        if corpus.is_empty() {
            return Err(PolicyBacktestError::EmptyCorpus);
        }
        let candidate_id = corpus[0].candidate_mapping.target_policy_id.clone();
        let mut seen_ids: BTreeSet<&str> = BTreeSet::new();
        let mut outcomes = Vec::with_capacity(corpus.len());
        for item in corpus {
            if item.candidate_mapping.target_policy_id != candidate_id {
                return Err(PolicyBacktestError::MixedCandidatePolicies {
                    expected: candidate_id.0.clone(),
                    found: item.candidate_mapping.target_policy_id.0.clone(),
                });
            }
            if !seen_ids.insert(item.item_id.as_str()) {
                return Err(PolicyBacktestError::DuplicateItemId {
                    item_id: item.item_id.clone(),
                });
            }
            let evaluation = self
                .evaluator
                .evaluate(&item.batch, &item.candidate_mapping)
                .map_err(|source| PolicyBacktestError::Evaluation {
                    item_id: item.item_id.clone(),
                    source,
                })?;
            outcomes.push(BacktestItemOutcome {
                item_id: item.item_id.clone(),
                kind: item.kind,
                evaluation,
            });
        }
        let incumbent_id = self.evaluator.baseline().id.clone();
        build_report(&candidate_id, &incumbent_id, outcomes)
    }
}

/// Sign a report: serialize, sign the payload, and self-verify before
/// returning (the governance_scorecard pattern).
pub fn sign_report(
    report: &PolicyBacktestReport,
    signing_key: &SigningKey,
) -> Result<SignedPolicyBacktestReport, PolicyBacktestError> {
    let payload = serde_json::to_vec(report).map_err(|err| PolicyBacktestError::Serialization {
        detail: err.to_string(),
    })?;
    let signature = sign_preimage(signing_key, &payload).map_err(signature_error)?;
    let signer_key = signing_key.verification_key();
    verify_signature(&signer_key, &payload, &signature).map_err(signature_error)?;
    Ok(SignedPolicyBacktestReport {
        report: report.clone(),
        signer_key,
        signature,
    })
}

/// Verify a signed report: signature over the exact serialized report AND
/// internal artifact-hash integrity. Fail-closed on any mismatch.
pub fn verify_signed_report(
    signed: &SignedPolicyBacktestReport,
) -> Result<(), PolicyBacktestError> {
    let payload =
        serde_json::to_vec(&signed.report).map_err(|err| PolicyBacktestError::Serialization {
            detail: err.to_string(),
        })?;
    verify_signature(&signed.signer_key, &payload, &signed.signature).map_err(signature_error)?;
    let recomputed = recompute_artifact_hash(&signed.report)?;
    if recomputed != signed.report.artifact_hash_hex {
        return Err(PolicyBacktestError::Signature {
            detail: format!(
                "artifact hash mismatch: recorded {}, recomputed {recomputed}",
                signed.report.artifact_hash_hex
            ),
        });
    }
    Ok(())
}

fn signature_error(err: SignatureError) -> PolicyBacktestError {
    PolicyBacktestError::Signature {
        detail: format!("{err:?}"),
    }
}

/// An explicit, recorded waiver for promoting past a non-Safe backtest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BacktestWaiver {
    pub waiver_id: String,
    pub reason: String,
    pub approved_by: String,
}

/// Promotion-gate decision over a backtest verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum PromotionGateDecision {
    /// Verdict was Safe: the candidate may promote.
    Approved { verdict: EnvelopeStatus },
    /// Verdict was not Safe but an explicit waiver was recorded.
    ApprovedByWaiver {
        verdict: EnvelopeStatus,
        waiver_id: String,
        approved_by: String,
    },
    /// Fail-closed rejection.
    Rejected {
        verdict: EnvelopeStatus,
        reason: String,
    },
}

/// Fail-closed promotion gate: only a Safe verdict (or an explicit waiver)
/// lets a candidate policy promote.
pub fn promotion_gate(
    report: &PolicyBacktestReport,
    waiver: Option<&BacktestWaiver>,
) -> PromotionGateDecision {
    match report.verdict {
        EnvelopeStatus::Safe => PromotionGateDecision::Approved {
            verdict: report.verdict,
        },
        verdict => match waiver {
            Some(waiver) => PromotionGateDecision::ApprovedByWaiver {
                verdict,
                waiver_id: waiver.waiver_id.clone(),
                approved_by: waiver.approved_by.clone(),
            },
            None => PromotionGateDecision::Rejected {
                verdict,
                reason: format!(
                    "backtest verdict {verdict:?} is not Safe and no waiver was recorded; \
                     {} unsafe item(s), {} inconclusive item(s)",
                    report.unsafe_item_ids.len(),
                    report.inconclusive_item_ids.len()
                ),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::counterfactual_evaluator::{EstimatorKind, LoggedTransition};
    use crate::hash_tiers::ContentHash;
    use crate::runtime_decision_theory::{LaneAction, RegimeLabel};
    use crate::security_epoch::SecurityEpoch;
    use crate::signature_preimage::generate_keypair_from_seed;

    fn envelope(estimate: i64, lower: i64, upper: i64, samples: u64) -> ConfidenceEnvelope {
        ConfidenceEnvelope {
            estimate_millionths: estimate,
            lower_millionths: lower,
            upper_millionths: upper,
            confidence_millionths: 950_000,
            effective_samples: samples,
        }
    }

    fn outcome(
        item_id: &str,
        kind: CorpusItemKind,
        status: EnvelopeStatus,
        improvement: ConfidenceEnvelope,
    ) -> BacktestItemOutcome {
        BacktestItemOutcome {
            item_id: item_id.to_string(),
            kind,
            evaluation: EvaluationResult {
                schema_version: "test".to_string(),
                estimator: EstimatorKind::Ips,
                candidate_policy_id: PolicyId("candidate".to_string()),
                baseline_policy_id: PolicyId("incumbent".to_string()),
                candidate_envelope: envelope(0, 0, 0, improvement.effective_samples),
                baseline_envelope: envelope(0, 0, 0, improvement.effective_samples),
                improvement_envelope: improvement,
                safety_status: status,
                regime_breakdown: BTreeMap::new(),
                artifact_hash: ContentHash::compute(b"test-eval"),
            },
        }
    }

    fn transitions(count: usize, propensity: i64, reward: i64) -> TransitionBatch {
        TransitionBatch {
            policy_id: PolicyId("logged".to_string()),
            transitions: (0..count)
                .map(|index| LoggedTransition {
                    epoch: SecurityEpoch::from_raw(1),
                    tick: index as u64,
                    regime: RegimeLabel::Normal,
                    action_taken: LaneAction::FallbackSafe,
                    propensity_millionths: propensity,
                    reward_millionths: reward,
                    model_prediction_millionths: None,
                    context_hash: ContentHash::compute(b"ctx"),
                })
                .collect(),
        }
    }

    fn mapping(count: usize, propensity: i64) -> TargetPolicyMapping {
        TargetPolicyMapping {
            target_policy_id: PolicyId("candidate".to_string()),
            target_propensities_millionths: vec![propensity; count],
            target_model_predictions_millionths: None,
        }
    }

    fn corpus_item(item_id: &str, kind: CorpusItemKind) -> BacktestCorpusItem {
        BacktestCorpusItem {
            item_id: item_id.to_string(),
            kind,
            batch: transitions(100, 500_000, 500_000),
            candidate_mapping: mapping(100, 500_000),
        }
    }

    fn high_threshold_backtester() -> PolicyBacktester {
        // improvement ≈ 0 with threshold 500_000 ⇒ deterministically Unsafe
        // (mirrors the evaluator's own safety_status_unsafe_when_candidate_worse).
        let config = EvaluatorConfig {
            estimator: EstimatorKind::Ips,
            improvement_threshold_millionths: 500_000,
            ..Default::default()
        };
        PolicyBacktester::new(config, BaselinePolicy::default())
            .expect("backtester construction should succeed")
    }

    // ── verdict ──────────────────────────────────────────────────────

    #[test]
    fn verdict_empty_is_inconclusive_never_safe_by_vacuity() {
        assert_eq!(compute_verdict(&[]), EnvelopeStatus::Inconclusive);
    }

    #[test]
    fn verdict_all_safe_is_safe() {
        let outcomes = vec![
            outcome(
                "a",
                CorpusItemKind::Benign,
                EnvelopeStatus::Safe,
                envelope(1, 0, 2, 10),
            ),
            outcome(
                "b",
                CorpusItemKind::Incident,
                EnvelopeStatus::Safe,
                envelope(1, 0, 2, 10),
            ),
        ];
        assert_eq!(compute_verdict(&outcomes), EnvelopeStatus::Safe);
    }

    #[test]
    fn verdict_inconclusive_dominates_safe() {
        let outcomes = vec![
            outcome(
                "a",
                CorpusItemKind::Benign,
                EnvelopeStatus::Safe,
                envelope(1, 0, 2, 10),
            ),
            outcome(
                "b",
                CorpusItemKind::Benign,
                EnvelopeStatus::Inconclusive,
                envelope(0, -5, 5, 10),
            ),
        ];
        assert_eq!(compute_verdict(&outcomes), EnvelopeStatus::Inconclusive);
    }

    #[test]
    fn verdict_unsafe_dominates_everything() {
        let outcomes = vec![
            outcome(
                "a",
                CorpusItemKind::Benign,
                EnvelopeStatus::Safe,
                envelope(1, 0, 2, 10),
            ),
            outcome(
                "b",
                CorpusItemKind::Benign,
                EnvelopeStatus::Inconclusive,
                envelope(0, -5, 5, 10),
            ),
            outcome(
                "c",
                CorpusItemKind::Incident,
                EnvelopeStatus::Unsafe,
                envelope(-9, -12, -6, 10),
            ),
        ];
        assert_eq!(compute_verdict(&outcomes), EnvelopeStatus::Unsafe);
    }

    // ── aggregation ──────────────────────────────────────────────────

    #[test]
    fn aggregate_weights_by_effective_samples() {
        // (10 * 100 + 40 * 300) / 400 = 32.5 → truncates to 32
        let envelopes = [envelope(10, 0, 20, 100), envelope(40, 30, 50, 300)];
        let aggregate = aggregate_envelopes(envelopes.iter()).expect("aggregate should exist");
        assert_eq!(aggregate.estimate_millionths, 32);
        assert_eq!(aggregate.lower_millionths, 22); // (0*100 + 30*300)/400 = 22.5
        assert_eq!(aggregate.upper_millionths, 42); // (20*100 + 50*300)/400 = 42.5
        assert_eq!(aggregate.total_effective_samples, 400);
        assert_eq!(aggregate.item_count, 2);
    }

    #[test]
    fn aggregate_empty_or_zero_weight_is_none() {
        assert!(aggregate_envelopes([].iter()).is_none());
        let zero = [envelope(10, 0, 20, 0)];
        assert!(aggregate_envelopes(zero.iter()).is_none());
    }

    #[test]
    fn aggregate_handles_negative_estimates() {
        let envelopes = [envelope(-100, -200, 0, 50), envelope(-300, -400, -200, 50)];
        let aggregate = aggregate_envelopes(envelopes.iter()).expect("aggregate should exist");
        assert_eq!(aggregate.estimate_millionths, -200);
    }

    // ── build_report ─────────────────────────────────────────────────

    #[test]
    fn report_splits_deltas_by_corpus_kind() {
        let outcomes = vec![
            outcome(
                "benign-1",
                CorpusItemKind::Benign,
                EnvelopeStatus::Safe,
                envelope(100, 50, 150, 10),
            ),
            outcome(
                "incident-1",
                CorpusItemKind::Incident,
                EnvelopeStatus::Safe,
                envelope(-40, -60, -20, 10),
            ),
        ];
        let report = build_report(
            &PolicyId("candidate".to_string()),
            &PolicyId("incumbent".to_string()),
            outcomes,
        )
        .expect("report should build");
        // Benign improvement +100 ⇒ false-quarantine delta −100 (better).
        assert_eq!(report.delta_false_quarantine_millionths, Some(-100));
        // Incident improvement −40 ⇒ missed-containment delta +40 (worse).
        assert_eq!(report.delta_missed_containment_millionths, Some(40));
        // Overall improvement (100*10 + −40*10)/20 = 30 ⇒ loss delta −30.
        assert_eq!(report.delta_expected_loss_millionths, Some(-30));
        assert_eq!(report.corpus_size, 2);
    }

    #[test]
    fn report_with_no_benign_items_has_no_false_quarantine_delta() {
        let outcomes = vec![outcome(
            "incident-1",
            CorpusItemKind::Incident,
            EnvelopeStatus::Safe,
            envelope(5, 0, 10, 10),
        )];
        let report = build_report(
            &PolicyId("candidate".to_string()),
            &PolicyId("incumbent".to_string()),
            outcomes,
        )
        .expect("report should build");
        assert!(report.benign_improvement.is_none());
        assert!(report.delta_false_quarantine_millionths.is_none());
        assert!(report.incident_improvement.is_some());
    }

    #[test]
    fn report_surfaces_unsafe_and_inconclusive_ids_loudly() {
        let outcomes = vec![
            outcome(
                "ok",
                CorpusItemKind::Benign,
                EnvelopeStatus::Safe,
                envelope(1, 0, 2, 10),
            ),
            outcome(
                "no-overlap",
                CorpusItemKind::Benign,
                EnvelopeStatus::Inconclusive,
                envelope(0, -9, 9, 10),
            ),
            outcome(
                "regressed",
                CorpusItemKind::Incident,
                EnvelopeStatus::Unsafe,
                envelope(-5, -8, -2, 10),
            ),
        ];
        let report = build_report(
            &PolicyId("candidate".to_string()),
            &PolicyId("incumbent".to_string()),
            outcomes,
        )
        .expect("report should build");
        assert_eq!(report.unsafe_item_ids, vec!["regressed".to_string()]);
        assert_eq!(report.inconclusive_item_ids, vec!["no-overlap".to_string()]);
        assert_eq!(report.verdict, EnvelopeStatus::Unsafe);
    }

    #[test]
    fn report_merges_regime_breakdown_across_items() {
        let mut first = outcome(
            "a",
            CorpusItemKind::Benign,
            EnvelopeStatus::Safe,
            envelope(1, 0, 2, 10),
        );
        first
            .evaluation
            .regime_breakdown
            .insert("normal".to_string(), envelope(10, 0, 20, 100));
        let mut second = outcome(
            "b",
            CorpusItemKind::Benign,
            EnvelopeStatus::Safe,
            envelope(1, 0, 2, 10),
        );
        second
            .evaluation
            .regime_breakdown
            .insert("normal".to_string(), envelope(40, 30, 50, 300));
        second
            .evaluation
            .regime_breakdown
            .insert("attack".to_string(), envelope(-7, -9, -5, 10));
        let report = build_report(
            &PolicyId("candidate".to_string()),
            &PolicyId("incumbent".to_string()),
            vec![first, second],
        )
        .expect("report should build");
        assert_eq!(report.regime_breakdown.len(), 2);
        assert_eq!(
            report.regime_breakdown["normal"].estimate_millionths,
            32 // weighted: (10*100+40*300)/400
        );
        assert_eq!(report.regime_breakdown["attack"].item_count, 1);
    }

    #[test]
    fn report_artifact_hash_is_deterministic_and_verifiable() {
        let make = || {
            build_report(
                &PolicyId("candidate".to_string()),
                &PolicyId("incumbent".to_string()),
                vec![outcome(
                    "a",
                    CorpusItemKind::Benign,
                    EnvelopeStatus::Safe,
                    envelope(1, 0, 2, 10),
                )],
            )
            .expect("report should build")
        };
        let first = make();
        let second = make();
        assert_eq!(first.artifact_hash_hex, second.artifact_hash_hex);
        assert_eq!(
            recompute_artifact_hash(&first).expect("recompute should succeed"),
            first.artifact_hash_hex
        );
        assert_eq!(first.artifact_hash_hex.len(), 64);
    }

    // ── orchestration (real evaluator) ───────────────────────────────

    #[test]
    fn run_empty_corpus_fails_closed() {
        let mut backtester = high_threshold_backtester();
        assert_eq!(backtester.run(&[]), Err(PolicyBacktestError::EmptyCorpus));
    }

    #[test]
    fn run_rejects_duplicate_item_ids() {
        let mut backtester = high_threshold_backtester();
        let corpus = vec![
            corpus_item("same", CorpusItemKind::Benign),
            corpus_item("same", CorpusItemKind::Incident),
        ];
        assert!(matches!(
            backtester.run(&corpus),
            Err(PolicyBacktestError::DuplicateItemId { .. })
        ));
    }

    #[test]
    fn run_rejects_mixed_candidate_policies() {
        let mut backtester = high_threshold_backtester();
        let mut second = corpus_item("b", CorpusItemKind::Benign);
        second.candidate_mapping.target_policy_id = PolicyId("other".to_string());
        let corpus = vec![corpus_item("a", CorpusItemKind::Benign), second];
        assert!(matches!(
            backtester.run(&corpus),
            Err(PolicyBacktestError::MixedCandidatePolicies { .. })
        ));
    }

    #[test]
    fn run_propagates_evaluator_errors_with_item_id() {
        let mut backtester = high_threshold_backtester();
        let mut item = corpus_item("broken", CorpusItemKind::Benign);
        item.candidate_mapping.target_propensities_millionths.pop();
        let corpus = vec![item];
        match backtester.run(&corpus) {
            Err(PolicyBacktestError::Evaluation { item_id, .. }) => {
                assert_eq!(item_id, "broken");
            }
            other => panic!("expected evaluation error, got {other:?}"),
        }
    }

    #[test]
    fn run_high_threshold_corpus_is_deterministically_unsafe() {
        let mut backtester = high_threshold_backtester();
        let corpus = vec![
            corpus_item("benign-1", CorpusItemKind::Benign),
            corpus_item("incident-1", CorpusItemKind::Incident),
        ];
        let report = backtester.run(&corpus).expect("backtest should run");
        assert_eq!(report.verdict, EnvelopeStatus::Unsafe);
        assert_eq!(report.unsafe_item_ids.len(), 2);
        assert_eq!(report.candidate_policy_id, "candidate");
        assert_eq!(report.incumbent_policy_id, "baseline-safe-mode");
        assert_eq!(report.item_outcomes.len(), 2);
        assert!(report.overall_improvement.is_some());
    }

    #[test]
    fn run_is_deterministic_across_fresh_backtesters() {
        let corpus = vec![
            corpus_item("benign-1", CorpusItemKind::Benign),
            corpus_item("incident-1", CorpusItemKind::Incident),
        ];
        let first = high_threshold_backtester()
            .run(&corpus)
            .expect("backtest should run");
        let second = high_threshold_backtester()
            .run(&corpus)
            .expect("backtest should run");
        assert_eq!(first, second);
        assert_eq!(first.artifact_hash_hex, second.artifact_hash_hex);
    }

    // ── signing ──────────────────────────────────────────────────────

    fn test_report() -> PolicyBacktestReport {
        build_report(
            &PolicyId("candidate".to_string()),
            &PolicyId("incumbent".to_string()),
            vec![outcome(
                "a",
                CorpusItemKind::Benign,
                EnvelopeStatus::Safe,
                envelope(1, 0, 2, 10),
            )],
        )
        .expect("report should build")
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let (signing_key, _) = generate_keypair_from_seed(&[7u8; 32]);
        let signed = sign_report(&test_report(), &signing_key).expect("signing should succeed");
        verify_signed_report(&signed).expect("verification should succeed");
    }

    #[test]
    fn tampered_report_fails_verification() {
        let (signing_key, _) = generate_keypair_from_seed(&[7u8; 32]);
        let mut signed = sign_report(&test_report(), &signing_key).expect("signing should succeed");
        signed.report.delta_expected_loss_millionths = Some(-999_999);
        assert!(verify_signed_report(&signed).is_err());
    }

    #[test]
    fn tampered_artifact_hash_fails_verification() {
        let (signing_key, _) = generate_keypair_from_seed(&[7u8; 32]);
        let mut report = test_report();
        report.artifact_hash_hex = "00".repeat(32);
        // Sign AFTER tampering: the signature is valid for the bytes, but the
        // internal hash no longer matches the content — verify must fail.
        let signed = sign_report(&report, &signing_key).expect("signing should succeed");
        assert!(matches!(
            verify_signed_report(&signed),
            Err(PolicyBacktestError::Signature { .. })
        ));
    }

    #[test]
    fn signed_report_serde_round_trip() {
        let (signing_key, _) = generate_keypair_from_seed(&[9u8; 32]);
        let signed = sign_report(&test_report(), &signing_key).expect("signing should succeed");
        let json = serde_json::to_string(&signed).expect("serialize should succeed");
        let decoded: SignedPolicyBacktestReport =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(decoded, signed);
        verify_signed_report(&decoded).expect("decoded report should verify");
    }

    // ── promotion gate ───────────────────────────────────────────────

    fn report_with_verdict(verdict: EnvelopeStatus) -> PolicyBacktestReport {
        let status = verdict;
        let improvement = match verdict {
            EnvelopeStatus::Safe => envelope(10, 5, 15, 10),
            EnvelopeStatus::Inconclusive => envelope(0, -5, 5, 10),
            EnvelopeStatus::Unsafe => envelope(-10, -15, -5, 10),
        };
        build_report(
            &PolicyId("candidate".to_string()),
            &PolicyId("incumbent".to_string()),
            vec![outcome("only", CorpusItemKind::Benign, status, improvement)],
        )
        .expect("report should build")
    }

    #[test]
    fn gate_approves_safe_verdict() {
        let report = report_with_verdict(EnvelopeStatus::Safe);
        assert_eq!(
            promotion_gate(&report, None),
            PromotionGateDecision::Approved {
                verdict: EnvelopeStatus::Safe
            }
        );
    }

    #[test]
    fn gate_rejects_unsafe_without_waiver() {
        let report = report_with_verdict(EnvelopeStatus::Unsafe);
        match promotion_gate(&report, None) {
            PromotionGateDecision::Rejected { verdict, reason } => {
                assert_eq!(verdict, EnvelopeStatus::Unsafe);
                assert!(reason.contains("no waiver"));
            }
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn gate_rejects_inconclusive_without_waiver() {
        let report = report_with_verdict(EnvelopeStatus::Inconclusive);
        assert!(matches!(
            promotion_gate(&report, None),
            PromotionGateDecision::Rejected {
                verdict: EnvelopeStatus::Inconclusive,
                ..
            }
        ));
    }

    #[test]
    fn gate_records_waiver_identity_when_used() {
        let report = report_with_verdict(EnvelopeStatus::Inconclusive);
        let waiver = BacktestWaiver {
            waiver_id: "waiver-42".to_string(),
            reason: "low-traffic regime, manual review done".to_string(),
            approved_by: "operator-jane".to_string(),
        };
        match promotion_gate(&report, Some(&waiver)) {
            PromotionGateDecision::ApprovedByWaiver {
                waiver_id,
                approved_by,
                verdict,
            } => {
                assert_eq!(waiver_id, "waiver-42");
                assert_eq!(approved_by, "operator-jane");
                assert_eq!(verdict, EnvelopeStatus::Inconclusive);
            }
            other => panic!("expected waiver approval, got {other:?}"),
        }
    }

    #[test]
    fn gate_ignores_waiver_when_verdict_is_safe() {
        let report = report_with_verdict(EnvelopeStatus::Safe);
        let waiver = BacktestWaiver {
            waiver_id: "unneeded".to_string(),
            reason: "n/a".to_string(),
            approved_by: "nobody".to_string(),
        };
        assert_eq!(
            promotion_gate(&report, Some(&waiver)),
            PromotionGateDecision::Approved {
                verdict: EnvelopeStatus::Safe
            }
        );
    }

    #[test]
    fn error_display_is_specific() {
        let cases = [
            PolicyBacktestError::EmptyCorpus,
            PolicyBacktestError::MixedCandidatePolicies {
                expected: "a".to_string(),
                found: "b".to_string(),
            },
            PolicyBacktestError::DuplicateItemId {
                item_id: "dup".to_string(),
            },
            PolicyBacktestError::Serialization {
                detail: "boom".to_string(),
            },
        ];
        for case in cases {
            assert!(!case.to_string().is_empty());
        }
    }

    #[test]
    fn corpus_kind_strings_are_stable() {
        assert_eq!(CorpusItemKind::Incident.as_str(), "incident");
        assert_eq!(CorpusItemKind::Benign.as_str(), "benign");
    }
}
