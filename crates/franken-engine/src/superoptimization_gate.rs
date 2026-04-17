//! Parent gate for the RGC-613 budgeted superoptimization lane.
//!
//! This module joins eligibility envelopes, bounded synthesis reports, and
//! promotion decisions into the `superoptimization_report.json` contract. The
//! lane fails closed: stale, over-budget, unproved, or unpromoted candidates
//! deterministically fall back to baseline compiled code.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::budgeted_synthesis_engine::{ProofStatus, SynthesisCandidate, SynthesisReport};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::synthesis_eligibility_envelope::SynthesisEnvelope;
use crate::synthesis_kernel_promotion::{
    PromotionDecision, PromotionReport, PromotionTarget, RejectionReason,
};

pub const SCHEMA_VERSION: &str = "franken-engine.superoptimization-gate.v1";
pub const COMPONENT: &str = "superoptimization_gate";
pub const BEAD_ID: &str = "bd-1lsy.7.13";
pub const POLICY_ID: &str = "RGC-613";

pub const RUN_MANIFEST_ARTIFACT: &str = "run_manifest.json";
pub const EVENTS_ARTIFACT: &str = "events.jsonl";
pub const COMMANDS_ARTIFACT: &str = "commands.txt";
pub const TRACE_IDS_ARTIFACT: &str = "trace_ids";
pub const SUPEROPTIMIZATION_REPORT_ARTIFACT: &str = "superoptimization_report.json";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SuperoptimizationArtifact {
    pub name: String,
    pub required: bool,
    pub content_hash: ContentHash,
}

impl SuperoptimizationArtifact {
    pub fn required(name: impl Into<String>, content_hash: ContentHash) -> Self {
        Self {
            name: name.into(),
            required: true,
            content_hash,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuperoptimizationDisposition {
    Promoted,
    FallbackToBaseline,
}

impl SuperoptimizationDisposition {
    pub const ALL: &[Self] = &[Self::Promoted, Self::FallbackToBaseline];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Promoted => "promoted",
            Self::FallbackToBaseline => "fallback_to_baseline",
        }
    }
}

impl fmt::Display for SuperoptimizationDisposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuperoptimizationReason {
    EligibilityRejected {
        schema_id: String,
        verdict_tag: String,
    },
    MissingSynthesisReport {
        schema_id: String,
    },
    StaleSynthesis {
        schema_id: String,
        report_epoch: SecurityEpoch,
        current_epoch: SecurityEpoch,
        max_epoch_lag: u64,
    },
    FutureDatedSynthesis {
        schema_id: String,
        report_epoch: SecurityEpoch,
        current_epoch: SecurityEpoch,
    },
    BudgetExceeded {
        schema_id: String,
        consumed_millionths: u64,
        limit_millionths: u64,
        evaluated_candidates: u32,
        max_candidates: u32,
    },
    ProofFailureRejected {
        schema_id: String,
        refuted_count: usize,
    },
    NoAdmissibleCandidate {
        schema_id: String,
    },
    CounterexamplesPresent {
        candidate_id: String,
        counterexample_count: usize,
    },
    UnverifiedCandidate {
        candidate_id: String,
        proof_status: ProofStatus,
    },
    MissingPromotionProvenance {
        candidate_id: String,
    },
    PromotionRejected {
        candidate_id: String,
        reasons: Vec<String>,
    },
    PromotionDeferred {
        candidate_id: String,
        pending_reasons: Vec<String>,
    },
}

impl SuperoptimizationReason {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::EligibilityRejected { .. } => "eligibility_rejected",
            Self::MissingSynthesisReport { .. } => "missing_synthesis_report",
            Self::StaleSynthesis { .. } => "stale_synthesis",
            Self::FutureDatedSynthesis { .. } => "future_dated_synthesis",
            Self::BudgetExceeded { .. } => "budget_exceeded",
            Self::ProofFailureRejected { .. } => "proof_failure_rejected",
            Self::NoAdmissibleCandidate { .. } => "no_admissible_candidate",
            Self::CounterexamplesPresent { .. } => "counterexamples_present",
            Self::UnverifiedCandidate { .. } => "unverified_candidate",
            Self::MissingPromotionProvenance { .. } => "missing_promotion_provenance",
            Self::PromotionRejected { .. } => "promotion_rejected",
            Self::PromotionDeferred { .. } => "promotion_deferred",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuperoptimizationDecision {
    pub schema_id: String,
    pub candidate_id: Option<String>,
    pub disposition: SuperoptimizationDisposition,
    pub promotion_targets: BTreeSet<PromotionTarget>,
    pub reasons: Vec<SuperoptimizationReason>,
    pub rollback_receipt_hash: Option<ContentHash>,
    pub content_hash: ContentHash,
}

impl SuperoptimizationDecision {
    fn promoted(
        schema_id: String,
        candidate_id: String,
        targets: BTreeSet<PromotionTarget>,
        candidate_hash: ContentHash,
    ) -> Self {
        Self {
            schema_id,
            candidate_id: Some(candidate_id),
            disposition: SuperoptimizationDisposition::Promoted,
            promotion_targets: targets,
            reasons: Vec::new(),
            rollback_receipt_hash: None,
            content_hash: candidate_hash,
        }
    }

    fn fallback(
        schema_id: String,
        candidate_id: Option<String>,
        epoch: SecurityEpoch,
        reasons: Vec<SuperoptimizationReason>,
    ) -> Self {
        let receipt_hash = rollback_hash(&schema_id, candidate_id.as_deref(), epoch, &reasons);
        Self {
            schema_id,
            candidate_id,
            disposition: SuperoptimizationDisposition::FallbackToBaseline,
            promotion_targets: BTreeSet::new(),
            reasons,
            rollback_receipt_hash: Some(receipt_hash),
            content_hash: receipt_hash,
        }
    }

    pub fn is_promoted(&self) -> bool {
        self.disposition == SuperoptimizationDisposition::Promoted
    }

    pub fn is_fallback(&self) -> bool {
        self.disposition == SuperoptimizationDisposition::FallbackToBaseline
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuperoptimizationGateConfig {
    pub max_epoch_lag: u64,
    pub require_promotion_provenance: bool,
    pub required_artifacts: BTreeSet<String>,
}

impl SuperoptimizationGateConfig {
    pub fn strict() -> Self {
        Self {
            max_epoch_lag: 0,
            require_promotion_provenance: true,
            required_artifacts: required_artifact_names(),
        }
    }

    pub fn permissive_for_replay() -> Self {
        Self {
            max_epoch_lag: u64::MAX,
            require_promotion_provenance: false,
            required_artifacts: required_artifact_names(),
        }
    }
}

impl Default for SuperoptimizationGateConfig {
    fn default() -> Self {
        Self::strict()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuperoptimizationGate {
    pub schema_version: String,
    pub config: SuperoptimizationGateConfig,
}

impl SuperoptimizationGate {
    pub fn with_defaults() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            config: SuperoptimizationGateConfig::default(),
        }
    }

    pub fn with_config(config: SuperoptimizationGateConfig) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            config,
        }
    }

    pub fn evaluate(
        &self,
        epoch: SecurityEpoch,
        envelope: &SynthesisEnvelope,
        synthesis_reports: &[SynthesisReport],
        promotion_report: &PromotionReport,
    ) -> SuperoptimizationReport {
        let reports_by_schema: BTreeMap<String, &SynthesisReport> = synthesis_reports
            .iter()
            .map(|report| (report.target_schema_id.clone(), report))
            .collect();
        let promotions_by_candidate = promotion_decisions_by_candidate(promotion_report);

        let decisions = envelope
            .entries
            .iter()
            .map(|entry| {
                if !entry.verdict.is_eligible() {
                    return SuperoptimizationDecision::fallback(
                        entry.schema_id.clone(),
                        None,
                        epoch,
                        vec![SuperoptimizationReason::EligibilityRejected {
                            schema_id: entry.schema_id.clone(),
                            verdict_tag: entry.verdict.tag().to_string(),
                        }],
                    );
                }

                self.evaluate_eligible_schema(
                    epoch,
                    &entry.schema_id,
                    reports_by_schema.get(&entry.schema_id).copied(),
                    &promotions_by_candidate,
                )
            })
            .collect();

        SuperoptimizationReport::new(
            epoch,
            envelope,
            synthesis_reports,
            promotion_report,
            decisions,
            self.config.required_artifacts.clone(),
        )
    }

    fn evaluate_eligible_schema(
        &self,
        epoch: SecurityEpoch,
        schema_id: &str,
        report: Option<&SynthesisReport>,
        promotions_by_candidate: &BTreeMap<String, &PromotionDecision>,
    ) -> SuperoptimizationDecision {
        let Some(report) = report else {
            return SuperoptimizationDecision::fallback(
                schema_id.to_string(),
                None,
                epoch,
                vec![SuperoptimizationReason::MissingSynthesisReport {
                    schema_id: schema_id.to_string(),
                }],
            );
        };

        if let Some(reason) =
            stale_reason(schema_id, epoch, report.epoch, self.config.max_epoch_lag)
        {
            return SuperoptimizationDecision::fallback(
                schema_id.to_string(),
                None,
                epoch,
                vec![reason],
            );
        }

        if let Some(reason) = budget_reason(report) {
            return SuperoptimizationDecision::fallback(
                schema_id.to_string(),
                None,
                epoch,
                vec![reason],
            );
        }

        let ranked = rank_admissible_candidates(report);
        let Some(candidate) = ranked.first().copied() else {
            let reason = if report.refuted_count > 0 {
                SuperoptimizationReason::ProofFailureRejected {
                    schema_id: schema_id.to_string(),
                    refuted_count: report.refuted_count,
                }
            } else {
                SuperoptimizationReason::NoAdmissibleCandidate {
                    schema_id: schema_id.to_string(),
                }
            };
            return SuperoptimizationDecision::fallback(
                schema_id.to_string(),
                None,
                epoch,
                vec![reason],
            );
        };

        if !candidate.proof.status.is_verified() {
            let reason = SuperoptimizationReason::UnverifiedCandidate {
                candidate_id: candidate.candidate_id.clone(),
                proof_status: candidate.proof.status,
            };
            return SuperoptimizationDecision::fallback(
                schema_id.to_string(),
                Some(candidate.candidate_id.clone()),
                epoch,
                vec![reason],
            );
        }

        if !candidate.counterexamples.is_empty() {
            let reason = SuperoptimizationReason::CounterexamplesPresent {
                candidate_id: candidate.candidate_id.clone(),
                counterexample_count: candidate.counterexamples.len(),
            };
            return SuperoptimizationDecision::fallback(
                schema_id.to_string(),
                Some(candidate.candidate_id.clone()),
                epoch,
                vec![reason],
            );
        }

        let Some(promotion) = promotions_by_candidate
            .get(&candidate.candidate_id)
            .copied()
        else {
            if self.config.require_promotion_provenance {
                let reason = SuperoptimizationReason::MissingPromotionProvenance {
                    candidate_id: candidate.candidate_id.clone(),
                };
                return SuperoptimizationDecision::fallback(
                    schema_id.to_string(),
                    Some(candidate.candidate_id.clone()),
                    epoch,
                    vec![reason],
                );
            }
            return SuperoptimizationDecision::promoted(
                schema_id.to_string(),
                candidate.candidate_id.clone(),
                BTreeSet::new(),
                candidate.content_hash,
            );
        };

        match promotion {
            PromotionDecision::Promoted { targets, .. } => SuperoptimizationDecision::promoted(
                schema_id.to_string(),
                candidate.candidate_id.clone(),
                targets.clone(),
                candidate.content_hash,
            ),
            PromotionDecision::Rejected { reasons, .. } => SuperoptimizationDecision::fallback(
                schema_id.to_string(),
                Some(candidate.candidate_id.clone()),
                epoch,
                vec![SuperoptimizationReason::PromotionRejected {
                    candidate_id: candidate.candidate_id.clone(),
                    reasons: promotion_reason_tags(reasons),
                }],
            ),
            PromotionDecision::Deferred {
                pending_reasons, ..
            } => SuperoptimizationDecision::fallback(
                schema_id.to_string(),
                Some(candidate.candidate_id.clone()),
                epoch,
                vec![SuperoptimizationReason::PromotionDeferred {
                    candidate_id: candidate.candidate_id.clone(),
                    pending_reasons: promotion_reason_tags(pending_reasons),
                }],
            ),
        }
    }
}

impl Default for SuperoptimizationGate {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuperoptimizationReport {
    pub schema_version: String,
    pub component: String,
    pub policy_id: String,
    pub bead_id: String,
    pub epoch: SecurityEpoch,
    pub decisions: Vec<SuperoptimizationDecision>,
    pub promoted_count: usize,
    pub fallback_count: usize,
    pub synthesis_report_hashes: BTreeMap<String, ContentHash>,
    pub eligibility_envelope_hash: ContentHash,
    pub promotion_report_hash: ContentHash,
    pub artifacts: Vec<SuperoptimizationArtifact>,
    pub trace_ids: BTreeSet<String>,
    pub content_hash: ContentHash,
}

impl SuperoptimizationReport {
    pub fn new(
        epoch: SecurityEpoch,
        envelope: &SynthesisEnvelope,
        synthesis_reports: &[SynthesisReport],
        promotion_report: &PromotionReport,
        decisions: Vec<SuperoptimizationDecision>,
        required_artifacts: BTreeSet<String>,
    ) -> Self {
        let promoted_count = decisions
            .iter()
            .filter(|decision| decision.is_promoted())
            .count();
        let fallback_count = decisions.len().saturating_sub(promoted_count);
        let synthesis_report_hashes = synthesis_reports
            .iter()
            .map(|report| (report.target_schema_id.clone(), report.content_hash))
            .collect::<BTreeMap<_, _>>();
        let trace_ids = trace_ids_for_decisions(&decisions);
        let content_hash = report_hash(
            epoch,
            envelope.content_hash,
            &synthesis_report_hashes,
            promotion_report.content_hash,
            &decisions,
        );
        let artifacts = artifact_manifest(required_artifacts, content_hash, &trace_ids, &decisions);

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            policy_id: POLICY_ID.to_string(),
            bead_id: BEAD_ID.to_string(),
            epoch,
            decisions,
            promoted_count,
            fallback_count,
            synthesis_report_hashes,
            eligibility_envelope_hash: envelope.content_hash,
            promotion_report_hash: promotion_report.content_hash,
            artifacts,
            trace_ids,
            content_hash,
        }
    }

    pub fn total_count(&self) -> usize {
        self.decisions.len()
    }

    pub fn all_promoted(&self) -> bool {
        !self.decisions.is_empty() && self.promoted_count == self.decisions.len()
    }

    pub fn has_fallbacks(&self) -> bool {
        self.fallback_count > 0
    }

    pub fn artifact_names(&self) -> BTreeSet<&str> {
        self.artifacts
            .iter()
            .map(|artifact| artifact.name.as_str())
            .collect()
    }
}

pub fn rank_admissible_candidates(report: &SynthesisReport) -> Vec<&SynthesisCandidate> {
    let mut candidates = report
        .candidates
        .iter()
        .filter(|candidate| candidate.is_admissible())
        .collect::<Vec<_>>();
    candidates.sort_by(compare_candidates_for_promotion);
    candidates
}

fn compare_candidates_for_promotion(
    left: &&SynthesisCandidate,
    right: &&SynthesisCandidate,
) -> Ordering {
    right
        .speedup_millionths
        .cmp(&left.speedup_millionths)
        .then_with(|| left.op_count.cmp(&right.op_count))
        .then_with(|| left.candidate_id.cmp(&right.candidate_id))
}

fn required_artifact_names() -> BTreeSet<String> {
    BTreeSet::from([
        RUN_MANIFEST_ARTIFACT.to_string(),
        EVENTS_ARTIFACT.to_string(),
        COMMANDS_ARTIFACT.to_string(),
        TRACE_IDS_ARTIFACT.to_string(),
        SUPEROPTIMIZATION_REPORT_ARTIFACT.to_string(),
    ])
}

fn stale_reason(
    schema_id: &str,
    current_epoch: SecurityEpoch,
    report_epoch: SecurityEpoch,
    max_epoch_lag: u64,
) -> Option<SuperoptimizationReason> {
    if report_epoch > current_epoch {
        return Some(SuperoptimizationReason::FutureDatedSynthesis {
            schema_id: schema_id.to_string(),
            report_epoch,
            current_epoch,
        });
    }

    let lag = current_epoch.as_u64().saturating_sub(report_epoch.as_u64());
    (lag > max_epoch_lag).then(|| SuperoptimizationReason::StaleSynthesis {
        schema_id: schema_id.to_string(),
        report_epoch,
        current_epoch,
        max_epoch_lag,
    })
}

fn budget_reason(report: &SynthesisReport) -> Option<SuperoptimizationReason> {
    let evaluated_candidates = report.candidate_count().min(u32::MAX as usize) as u32;
    let candidate_budget_exceeded = evaluated_candidates > report.budget.max_candidates;
    let search_budget_exceeded =
        report.total_search_time_millionths > report.budget.search_time_millionths;
    let proof_budget_exceeded = report.candidates.iter().any(|candidate| {
        candidate.proof.proof_time_millionths > report.budget.proof_time_per_candidate_millionths
    });

    (candidate_budget_exceeded || search_budget_exceeded || proof_budget_exceeded).then(|| {
        SuperoptimizationReason::BudgetExceeded {
            schema_id: report.target_schema_id.clone(),
            consumed_millionths: report.total_search_time_millionths,
            limit_millionths: report.budget.search_time_millionths,
            evaluated_candidates,
            max_candidates: report.budget.max_candidates,
        }
    })
}

fn promotion_decisions_by_candidate(
    report: &PromotionReport,
) -> BTreeMap<String, &PromotionDecision> {
    report
        .decisions
        .iter()
        .map(|decision| (decision.kernel_id().to_string(), decision))
        .collect()
}

fn promotion_reason_tags(reasons: &[RejectionReason]) -> Vec<String> {
    reasons
        .iter()
        .map(|reason| reason.tag().to_string())
        .collect()
}

fn trace_ids_for_decisions(decisions: &[SuperoptimizationDecision]) -> BTreeSet<String> {
    let mut trace_ids = BTreeSet::from(["trace.rgc.613.superoptimization_gate".to_string()]);
    trace_ids.extend(decisions.iter().map(|decision| {
        format!(
            "trace.rgc.613.{}.{}",
            decision.schema_id,
            decision.disposition.as_str()
        )
    }));
    trace_ids
}

fn artifact_manifest(
    required_artifacts: BTreeSet<String>,
    report_hash: ContentHash,
    trace_ids: &BTreeSet<String>,
    decisions: &[SuperoptimizationDecision],
) -> Vec<SuperoptimizationArtifact> {
    required_artifacts
        .into_iter()
        .map(|artifact| {
            let hash = match artifact.as_str() {
                SUPEROPTIMIZATION_REPORT_ARTIFACT => report_hash,
                TRACE_IDS_ARTIFACT => hash_strings(trace_ids.iter().map(String::as_str)),
                EVENTS_ARTIFACT => hash_strings(
                    decisions
                        .iter()
                        .map(|decision| decision.disposition.as_str()),
                ),
                COMMANDS_ARTIFACT => hash_strings([
                    "cargo test -p frankenengine-engine --test superoptimization_gate_integration",
                    "cargo check -p frankenengine-engine",
                    "cargo clippy -p frankenengine-engine -- -D warnings",
                ]),
                RUN_MANIFEST_ARTIFACT => {
                    hash_strings([SCHEMA_VERSION, COMPONENT, POLICY_ID, BEAD_ID])
                }
                _ => ContentHash::compute(artifact.as_bytes()),
            };
            SuperoptimizationArtifact::required(artifact, hash)
        })
        .collect()
}

fn rollback_hash(
    schema_id: &str,
    candidate_id: Option<&str>,
    epoch: SecurityEpoch,
    reasons: &[SuperoptimizationReason],
) -> ContentHash {
    let mut h = Sha256::new();
    h.update(SCHEMA_VERSION.as_bytes());
    h.update(schema_id.as_bytes());
    h.update(epoch.as_u64().to_le_bytes());
    if let Some(candidate_id) = candidate_id {
        h.update(candidate_id.as_bytes());
    }
    for reason in reasons {
        h.update(reason.tag().as_bytes());
        h.update(format!("{reason:?}").as_bytes());
    }
    ContentHash::compute(&h.finalize())
}

fn report_hash(
    epoch: SecurityEpoch,
    envelope_hash: ContentHash,
    synthesis_report_hashes: &BTreeMap<String, ContentHash>,
    promotion_report_hash: ContentHash,
    decisions: &[SuperoptimizationDecision],
) -> ContentHash {
    let mut h = Sha256::new();
    h.update(SCHEMA_VERSION.as_bytes());
    h.update(epoch.as_u64().to_le_bytes());
    h.update(envelope_hash.as_bytes());
    h.update(promotion_report_hash.as_bytes());
    for (schema_id, hash) in synthesis_report_hashes {
        h.update(schema_id.as_bytes());
        h.update(hash.as_bytes());
    }
    for decision in decisions {
        h.update(decision.schema_id.as_bytes());
        h.update(decision.disposition.as_str().as_bytes());
        if let Some(candidate_id) = &decision.candidate_id {
            h.update(candidate_id.as_bytes());
        }
        for reason in &decision.reasons {
            h.update(reason.tag().as_bytes());
        }
    }
    ContentHash::compute(&h.finalize())
}

fn hash_strings<'a>(strings: impl IntoIterator<Item = &'a str>) -> ContentHash {
    let mut h = Sha256::new();
    for item in strings {
        h.update(item.as_bytes());
        h.update([0]);
    }
    ContentHash::compute(&h.finalize())
}
