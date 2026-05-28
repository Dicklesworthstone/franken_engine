//! Benchmark denominator calculator and publication gate for Section 10.6 (`bd-2n9`).
//!
//! This module provides deterministic weighted-geometric-mean scoring for
//! FrankenEngine-vs-baseline comparisons and an explicit publication gate for
//! the normative `>= 3x` claim contract against both Node and Bun.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const BENCHMARK_PUBLICATION_COMPONENT: &str = "benchmark_denominator";
pub const SCORE_THRESHOLD: f64 = 3.0;
const ROUND_SCALE: f64 = 1_000_000_000_000.0;
const WEIGHT_SUM_EPSILON: f64 = 1e-9;

const ERROR_INVALID_CASE_SET: &str = "FE-BENCH-1001";
const ERROR_INVALID_WEIGHT: &str = "FE-BENCH-1002";
const ERROR_INVALID_THROUGHPUT: &str = "FE-BENCH-1003";
const ERROR_WEIGHT_SUM: &str = "FE-BENCH-1004";
const ERROR_MISSING_COVERAGE: &str = "FE-BENCH-1005";
const ERROR_MISSING_LINEAGE: &str = "FE-BENCH-1006";
const ERROR_PUBLICATION_GATE_DENY: &str = "FE-BENCH-1007";
const ERROR_INVALID_WEIGHT_CONTRACT: &str = "FE-BENCH-1008";
const ERROR_CONTRACT_WEIGHT_SUM: &str = "FE-BENCH-1009";
const ERROR_WORKLOAD_NOT_IN_CONTRACT: &str = "FE-BENCH-1010";

/// Typed workload-class weight contract embedded at compile time.
///
/// The canonical source lives at `docs/benchmark_denominator_weights_v1.json`
/// (repo root). Embedding it via `include_str!` keeps scoring deterministic and
/// replay-friendly: the gate never reads the filesystem at runtime.
pub const WEIGHT_CONTRACT_V1_JSON: &str =
    include_str!("../../../docs/benchmark_denominator_weights_v1.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineEngine {
    Node,
    Bun,
}

impl BaselineEngine {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Bun => "bun",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkCase {
    pub workload_id: String,
    pub throughput_franken_tps: f64,
    pub throughput_baseline_tps: f64,
    pub weight: Option<f64>,
    #[serde(default = "default_true")]
    pub behavior_equivalent: bool,
    #[serde(default = "default_true")]
    pub latency_envelope_ok: bool,
    #[serde(default = "default_true")]
    pub error_envelope_ok: bool,
    #[serde(default = "default_true")]
    pub execution_authentic: bool,
}

impl BenchmarkCase {
    pub fn speedup(&self) -> f64 {
        self.throughput_franken_tps / self.throughput_baseline_tps
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationContext {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

impl PublicationContext {
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeCoveragePoint {
    pub recorded_at_utc: String,
    pub native_slots: u64,
    pub total_slots: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicationGateInput {
    pub node_cases: Vec<BenchmarkCase>,
    pub bun_cases: Vec<BenchmarkCase>,
    pub native_coverage_progression: Vec<NativeCoveragePoint>,
    pub replacement_lineage_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkPublicationEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicationGateDecision {
    pub score_vs_node: f64,
    pub score_vs_bun: f64,
    pub publish_allowed: bool,
    pub blockers: Vec<String>,
    pub native_coverage_progression: Vec<NativeCoveragePoint>,
    pub replacement_lineage_ids: Vec<String>,
    pub events: Vec<BenchmarkPublicationEvent>,
}

impl PublicationGateDecision {
    pub fn to_json_pretty(&self) -> Result<String, BenchmarkDenominatorError> {
        serde_json::to_string_pretty(self)
            .map_err(|error| BenchmarkDenominatorError::SerializationFailure(error.to_string()))
    }
}

#[derive(Debug, Error, Clone, PartialEq, Serialize, Deserialize)]
pub enum BenchmarkDenominatorError {
    #[error("{baseline} case set is empty")]
    EmptyCaseSet { baseline: String },
    #[error("empty workload id in {baseline} case set")]
    EmptyWorkloadId { baseline: String },
    #[error("duplicate workload id `{workload_id}` in {baseline} case set")]
    DuplicateWorkloadId {
        baseline: String,
        workload_id: String,
    },
    #[error("invalid weight for workload `{workload_id}`: {reason}")]
    InvalidWeight { workload_id: String, reason: String },
    #[error("invalid throughput for workload `{workload_id}` field `{field}`")]
    InvalidThroughput { workload_id: String, field: String },
    #[error("weights for {baseline} case set do not sum to 1 (sum={sum})")]
    InvalidWeightSum { baseline: String, sum: f64 },
    #[error("native coverage progression is required for publication")]
    MissingCoverageProgression,
    #[error("replacement lineage ids are required for publication")]
    MissingReplacementLineage,
    #[error("serialization failure: {0}")]
    SerializationFailure(String),
    #[error("weight contract parse failure: {0}")]
    WeightContractParse(String),
    #[error("weight contract is empty (no workload classes)")]
    EmptyWeightContract,
    #[error("duplicate workload class id `{class_id}` in weight contract")]
    DuplicateWorkloadClass { class_id: String },
    #[error("invalid weight for workload class `{class_id}`: {reason}")]
    InvalidClassWeight { class_id: String, reason: String },
    #[error("workload `{workload_id}` appears in more than one workload class")]
    DuplicateWorkloadMembership { workload_id: String },
    #[error("workload class weights do not sum to 1 (sum={sum})")]
    ContractWeightSum { sum: f64 },
    #[error("workload `{workload_id}` is not declared in any weight-contract class")]
    WorkloadNotInContract { workload_id: String },
}

impl BenchmarkDenominatorError {
    pub fn stable_code(&self) -> &'static str {
        match self {
            Self::EmptyCaseSet { .. }
            | Self::EmptyWorkloadId { .. }
            | Self::DuplicateWorkloadId { .. } => ERROR_INVALID_CASE_SET,
            Self::InvalidWeight { .. } => ERROR_INVALID_WEIGHT,
            Self::InvalidThroughput { .. } => ERROR_INVALID_THROUGHPUT,
            Self::InvalidWeightSum { .. } => ERROR_WEIGHT_SUM,
            Self::MissingCoverageProgression => ERROR_MISSING_COVERAGE,
            Self::MissingReplacementLineage => ERROR_MISSING_LINEAGE,
            Self::SerializationFailure(_) => ERROR_PUBLICATION_GATE_DENY,
            Self::WeightContractParse(_)
            | Self::EmptyWeightContract
            | Self::DuplicateWorkloadClass { .. }
            | Self::InvalidClassWeight { .. }
            | Self::DuplicateWorkloadMembership { .. } => ERROR_INVALID_WEIGHT_CONTRACT,
            Self::ContractWeightSum { .. } => ERROR_CONTRACT_WEIGHT_SUM,
            Self::WorkloadNotInContract { .. } => ERROR_WORKLOAD_NOT_IN_CONTRACT,
        }
    }
}

#[derive(Debug, Clone)]
struct PreparedCase {
    workload_id: String,
    speedup: f64,
    weight: f64,
}

/// Computes deterministic weighted geometric mean speedup for one baseline.
///
/// If all case weights are omitted (`None`), equal weighting is applied.
pub fn weighted_geometric_mean(
    cases: &[BenchmarkCase],
    baseline: BaselineEngine,
) -> Result<f64, BenchmarkDenominatorError> {
    let prepared = prepare_cases(cases, baseline)?;

    let mut log_sum = 0.0_f64;
    for case in prepared {
        log_sum += case.weight * case.speedup.ln();
    }

    Ok(deterministic_round(log_sum.exp()))
}

/// One workload class in the typed weight contract.
///
/// `weight` is the class-level policy weight; member workloads inherit an equal
/// share of it (renormalised over admitted classes at scoring time).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkloadClassWeight {
    pub class_id: String,
    pub weight: f64,
    #[serde(default)]
    pub description: String,
    pub member_workload_ids: Vec<String>,
}

/// Typed workload-class weight contract for the throughput denominator.
///
/// Weights are assigned per workload *class* (not per hand-picked workload) so
/// the cross-class weighting is fixed by policy rather than cherry-picked per
/// run. See `docs/benchmark_denominator_weights_v1.json` for the canonical
/// source and rationale.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeightContract {
    pub contract_version: String,
    #[serde(default)]
    pub rationale: String,
    pub workload_classes: Vec<WorkloadClassWeight>,
}

impl WeightContract {
    /// Loads and validates the contract embedded at compile time
    /// (`WEIGHT_CONTRACT_V1_JSON`).
    pub fn embedded_v1() -> Result<Self, BenchmarkDenominatorError> {
        Self::from_json_str(WEIGHT_CONTRACT_V1_JSON)
    }

    /// Parses and validates a contract from a JSON string.
    pub fn from_json_str(json: &str) -> Result<Self, BenchmarkDenominatorError> {
        let contract: Self = serde_json::from_str(json)
            .map_err(|error| BenchmarkDenominatorError::WeightContractParse(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    /// Validates structural and numeric invariants:
    /// non-empty classes, unique class ids, positive finite weights summing to
    /// 1.0, and workload memberships that are unique across classes.
    pub fn validate(&self) -> Result<(), BenchmarkDenominatorError> {
        if self.workload_classes.is_empty() {
            return Err(BenchmarkDenominatorError::EmptyWeightContract);
        }

        let mut seen_classes = BTreeSet::new();
        let mut seen_members = BTreeSet::new();
        let mut weight_sum = 0.0_f64;

        for class in &self.workload_classes {
            let class_id = class.class_id.trim();
            if class_id.is_empty() {
                return Err(BenchmarkDenominatorError::InvalidClassWeight {
                    class_id: class.class_id.clone(),
                    reason: "class_id must not be empty".to_string(),
                });
            }
            if !seen_classes.insert(class_id.to_string()) {
                return Err(BenchmarkDenominatorError::DuplicateWorkloadClass {
                    class_id: class_id.to_string(),
                });
            }
            if !class.weight.is_finite() || class.weight <= 0.0 {
                return Err(BenchmarkDenominatorError::InvalidClassWeight {
                    class_id: class_id.to_string(),
                    reason: "weight must be finite and > 0".to_string(),
                });
            }
            if class.member_workload_ids.is_empty() {
                return Err(BenchmarkDenominatorError::InvalidClassWeight {
                    class_id: class_id.to_string(),
                    reason: "class must declare at least one member workload".to_string(),
                });
            }
            for member in &class.member_workload_ids {
                let member = member.trim();
                if member.is_empty() {
                    return Err(BenchmarkDenominatorError::InvalidClassWeight {
                        class_id: class_id.to_string(),
                        reason: "member workload id must not be empty".to_string(),
                    });
                }
                if !seen_members.insert(member.to_string()) {
                    return Err(BenchmarkDenominatorError::DuplicateWorkloadMembership {
                        workload_id: member.to_string(),
                    });
                }
            }
            weight_sum += class.weight;
        }

        if (weight_sum - 1.0).abs() > WEIGHT_SUM_EPSILON {
            return Err(BenchmarkDenominatorError::ContractWeightSum {
                sum: deterministic_round(weight_sum),
            });
        }

        Ok(())
    }

    /// Resolves a per-workload weight map for an admitted set of workload ids.
    ///
    /// Class weights are renormalised over the classes that have at least one
    /// admitted member, and each admitted class's renormalised weight is split
    /// equally across its admitted members. The returned weights sum to 1.0
    /// (within `WEIGHT_SUM_EPSILON`). Every input id must belong to exactly one
    /// declared class.
    pub fn resolve_weights(
        &self,
        workload_ids: &[String],
    ) -> Result<std::collections::BTreeMap<String, f64>, BenchmarkDenominatorError> {
        // workload_id -> class_id membership map (contract already validated for
        // uniqueness across classes by `validate`).
        let mut membership: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        for class in &self.workload_classes {
            for member in &class.member_workload_ids {
                membership.insert(member.trim().to_string(), class.class_id.trim().to_string());
            }
        }

        // Group admitted workloads by class.
        let mut admitted_by_class: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for id in workload_ids {
            let id = id.trim().to_string();
            let class_id = membership.get(&id).ok_or_else(|| {
                BenchmarkDenominatorError::WorkloadNotInContract {
                    workload_id: id.clone(),
                }
            })?;
            admitted_by_class
                .entry(class_id.clone())
                .or_default()
                .push(id);
        }

        // Class weight lookup.
        let class_weight = |class_id: &str| -> f64 {
            self.workload_classes
                .iter()
                .find(|class| class.class_id.trim() == class_id)
                .map(|class| class.weight)
                .unwrap_or(0.0)
        };

        let admitted_weight_sum: f64 = admitted_by_class
            .keys()
            .map(|class_id| class_weight(class_id))
            .sum();
        if admitted_weight_sum <= 0.0 {
            return Err(BenchmarkDenominatorError::ContractWeightSum {
                sum: deterministic_round(admitted_weight_sum),
            });
        }

        let mut weights = std::collections::BTreeMap::new();
        for (class_id, members) in &admitted_by_class {
            let renormalised = class_weight(class_id) / admitted_weight_sum;
            let per_member = renormalised / members.len() as f64;
            for member in members {
                weights.insert(member.clone(), per_member);
            }
        }

        Ok(weights)
    }
}

/// Computes the weighted geometric-mean speedup using class weights from the
/// typed contract instead of per-case weights.
///
/// Per-case `weight` fields are ignored here: weights come from the contract.
/// Every case's `workload_id` must be declared in exactly one contract class.
pub fn weighted_geometric_mean_with_contract(
    cases: &[BenchmarkCase],
    baseline: BaselineEngine,
    contract: &WeightContract,
) -> Result<f64, BenchmarkDenominatorError> {
    let prepared = prepare_cases(cases, baseline)?;
    let workload_ids: Vec<String> = prepared
        .iter()
        .map(|case| case.workload_id.trim().to_string())
        .collect();
    let weights = contract.resolve_weights(&workload_ids)?;

    let mut log_sum = 0.0_f64;
    for case in &prepared {
        let key = case.workload_id.trim();
        let weight = weights.get(key).copied().ok_or_else(|| {
            BenchmarkDenominatorError::WorkloadNotInContract {
                workload_id: key.to_string(),
            }
        })?;
        log_sum += weight * case.speedup.ln();
    }

    Ok(deterministic_round(log_sum.exp()))
}

/// Evaluates publication-gate rules for the normative `>= 3x` claim.
///
/// Publication requires:
/// - valid score computation inputs
/// - `score_vs_node >= 3.0`
/// - `score_vs_bun >= 3.0`
/// - all case behavior-equivalence + latency/error envelopes passing
/// - non-empty native-coverage progression and replacement lineage IDs
pub fn evaluate_publication_gate(
    input: &PublicationGateInput,
    ctx: &PublicationContext,
) -> Result<PublicationGateDecision, BenchmarkDenominatorError> {
    let lineage_ids = validate_coverage_and_lineage(input)?;

    let score_vs_node = weighted_geometric_mean(&input.node_cases, BaselineEngine::Node)?;
    let score_vs_bun = weighted_geometric_mean(&input.bun_cases, BaselineEngine::Bun)?;

    Ok(finalize_gate_decision(
        input,
        ctx,
        lineage_ids,
        score_vs_node,
        score_vs_bun,
    ))
}

/// Identical to [`evaluate_publication_gate`] but derives per-workload weights
/// from the typed workload-class weight contract (`docs/benchmark_denominator_weights_v1.json`)
/// instead of per-case weights. This is the canonical FE-CLAIM-010 scoring
/// path: cross-class weighting is fixed by policy, not cherry-picked per run.
pub fn evaluate_publication_gate_with_contract(
    input: &PublicationGateInput,
    ctx: &PublicationContext,
    contract: &WeightContract,
) -> Result<PublicationGateDecision, BenchmarkDenominatorError> {
    let lineage_ids = validate_coverage_and_lineage(input)?;

    let score_vs_node =
        weighted_geometric_mean_with_contract(&input.node_cases, BaselineEngine::Node, contract)?;
    let score_vs_bun =
        weighted_geometric_mean_with_contract(&input.bun_cases, BaselineEngine::Bun, contract)?;

    Ok(finalize_gate_decision(
        input,
        ctx,
        lineage_ids,
        score_vs_node,
        score_vs_bun,
    ))
}

/// Validates the coverage progression + replacement lineage prerequisites and
/// returns the normalised (sorted, deduplicated, non-empty) lineage id set.
fn validate_coverage_and_lineage(
    input: &PublicationGateInput,
) -> Result<Vec<String>, BenchmarkDenominatorError> {
    if input.native_coverage_progression.is_empty() {
        return Err(BenchmarkDenominatorError::MissingCoverageProgression);
    }

    let mut lineage_ids: Vec<String> = input
        .replacement_lineage_ids
        .iter()
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .collect();
    lineage_ids.sort();
    lineage_ids.dedup();
    if lineage_ids.is_empty() {
        return Err(BenchmarkDenominatorError::MissingReplacementLineage);
    }

    Ok(lineage_ids)
}

/// Builds the publication-gate decision from already-computed scores, applying
/// the case-quality and `>= 3.0` threshold blockers and emitting the audit
/// event stream. Shared by the per-case and contract-weighted gate paths.
fn finalize_gate_decision(
    input: &PublicationGateInput,
    ctx: &PublicationContext,
    lineage_ids: Vec<String>,
    score_vs_node: f64,
    score_vs_bun: f64,
) -> PublicationGateDecision {
    let mut blockers = Vec::new();

    append_case_quality_blockers(&input.node_cases, BaselineEngine::Node, &mut blockers);
    append_case_quality_blockers(&input.bun_cases, BaselineEngine::Bun, &mut blockers);

    if score_vs_node < SCORE_THRESHOLD {
        blockers.push(format!(
            "score_vs_node below threshold: {score_vs_node:.12} < {SCORE_THRESHOLD:.1}"
        ));
    }
    if score_vs_bun < SCORE_THRESHOLD {
        blockers.push(format!(
            "score_vs_bun below threshold: {score_vs_bun:.12} < {SCORE_THRESHOLD:.1}"
        ));
    }

    let publish_allowed = blockers.is_empty();

    let baseline_events = [
        (BaselineEngine::Node, score_vs_node),
        (BaselineEngine::Bun, score_vs_bun),
    ]
    .into_iter()
    .map(|(baseline, score)| BenchmarkPublicationEvent {
        trace_id: ctx.trace_id.clone(),
        decision_id: ctx.decision_id.clone(),
        policy_id: ctx.policy_id.clone(),
        component: BENCHMARK_PUBLICATION_COMPONENT.to_string(),
        event: format!("{}_score_evaluated", baseline.as_str()),
        outcome: if score >= SCORE_THRESHOLD {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: if score >= SCORE_THRESHOLD {
            None
        } else {
            Some(ERROR_PUBLICATION_GATE_DENY.to_string())
        },
    });

    let final_event = BenchmarkPublicationEvent {
        trace_id: ctx.trace_id.clone(),
        decision_id: ctx.decision_id.clone(),
        policy_id: ctx.policy_id.clone(),
        component: BENCHMARK_PUBLICATION_COMPONENT.to_string(),
        event: "publication_gate_decision".to_string(),
        outcome: if publish_allowed {
            "allow".to_string()
        } else {
            "deny".to_string()
        },
        error_code: if publish_allowed {
            None
        } else {
            Some(ERROR_PUBLICATION_GATE_DENY.to_string())
        },
    };

    let mut events: Vec<BenchmarkPublicationEvent> = baseline_events.collect();
    events.push(final_event);

    PublicationGateDecision {
        score_vs_node,
        score_vs_bun,
        publish_allowed,
        blockers,
        native_coverage_progression: input.native_coverage_progression.clone(),
        replacement_lineage_ids: lineage_ids,
        events,
    }
}

fn append_case_quality_blockers(
    cases: &[BenchmarkCase],
    baseline: BaselineEngine,
    blockers: &mut Vec<String>,
) {
    for case in cases {
        if !case.behavior_equivalent {
            blockers.push(format!(
                "{} case `{}` failed behavior-equivalence",
                baseline.as_str(),
                case.workload_id
            ));
        }
        if !case.latency_envelope_ok {
            blockers.push(format!(
                "{} case `{}` failed latency envelope",
                baseline.as_str(),
                case.workload_id
            ));
        }
        if !case.error_envelope_ok {
            blockers.push(format!(
                "{} case `{}` failed error envelope",
                baseline.as_str(),
                case.workload_id
            ));
        }
        if !case.execution_authentic {
            blockers.push(format!(
                "{} case `{}` failed execution authenticity (mock response detected)",
                baseline.as_str(),
                case.workload_id
            ));
        }
    }
}

fn prepare_cases(
    cases: &[BenchmarkCase],
    baseline: BaselineEngine,
) -> Result<Vec<PreparedCase>, BenchmarkDenominatorError> {
    if cases.is_empty() {
        return Err(BenchmarkDenominatorError::EmptyCaseSet {
            baseline: baseline.as_str().to_string(),
        });
    }

    let mut seen_ids = BTreeSet::new();
    for case in cases {
        let workload_id = case.workload_id.trim();
        if workload_id.is_empty() {
            return Err(BenchmarkDenominatorError::EmptyWorkloadId {
                baseline: baseline.as_str().to_string(),
            });
        }
        if !seen_ids.insert(workload_id.to_string()) {
            return Err(BenchmarkDenominatorError::DuplicateWorkloadId {
                baseline: baseline.as_str().to_string(),
                workload_id: workload_id.to_string(),
            });
        }
    }

    let weights_provided = cases.iter().filter(|case| case.weight.is_some()).count();
    if weights_provided != 0 && weights_provided != cases.len() {
        return Err(BenchmarkDenominatorError::InvalidWeight {
            workload_id: "<mixed>".to_string(),
            reason: "weights must be provided for all cases or none".to_string(),
        });
    }

    let default_weight = 1.0_f64 / cases.len() as f64;
    let mut prepared = Vec::with_capacity(cases.len());

    for case in cases {
        if !case.throughput_franken_tps.is_finite() || case.throughput_franken_tps <= 0.0 {
            return Err(BenchmarkDenominatorError::InvalidThroughput {
                workload_id: case.workload_id.clone(),
                field: "throughput_franken_tps".to_string(),
            });
        }
        if !case.throughput_baseline_tps.is_finite() || case.throughput_baseline_tps <= 0.0 {
            return Err(BenchmarkDenominatorError::InvalidThroughput {
                workload_id: case.workload_id.clone(),
                field: "throughput_baseline_tps".to_string(),
            });
        }

        let speedup = case.speedup();
        if !speedup.is_finite() || speedup <= 0.0 {
            return Err(BenchmarkDenominatorError::InvalidThroughput {
                workload_id: case.workload_id.clone(),
                field: "speedup".to_string(),
            });
        }

        let weight = match case.weight {
            Some(weight) => {
                if !weight.is_finite() || weight <= 0.0 {
                    return Err(BenchmarkDenominatorError::InvalidWeight {
                        workload_id: case.workload_id.clone(),
                        reason: "weight must be finite and > 0".to_string(),
                    });
                }
                weight
            }
            None => default_weight,
        };

        prepared.push(PreparedCase {
            workload_id: case.workload_id.clone(),
            speedup,
            weight,
        });
    }

    let weight_sum: f64 = prepared.iter().map(|case| case.weight).sum();
    if (weight_sum - 1.0).abs() > WEIGHT_SUM_EPSILON {
        return Err(BenchmarkDenominatorError::InvalidWeightSum {
            baseline: baseline.as_str().to_string(),
            sum: deterministic_round(weight_sum),
        });
    }

    prepared.sort_by(|lhs, rhs| lhs.workload_id.cmp(&rhs.workload_id));
    Ok(prepared)
}

fn deterministic_round(value: f64) -> f64 {
    (value * ROUND_SCALE).round() / ROUND_SCALE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_case(id: &str, franken: f64, baseline: f64) -> BenchmarkCase {
        BenchmarkCase {
            workload_id: id.into(),
            throughput_franken_tps: franken,
            throughput_baseline_tps: baseline,
            weight: None,
            behavior_equivalent: true,
            latency_envelope_ok: true,
            error_envelope_ok: true,
            execution_authentic: true,
        }
    }

    fn test_case_weighted(id: &str, franken: f64, baseline: f64, weight: f64) -> BenchmarkCase {
        BenchmarkCase {
            workload_id: id.into(),
            throughput_franken_tps: franken,
            throughput_baseline_tps: baseline,
            weight: Some(weight),
            behavior_equivalent: true,
            latency_envelope_ok: true,
            error_envelope_ok: true,
            execution_authentic: true,
        }
    }

    fn test_context() -> PublicationContext {
        PublicationContext::new("trace-1", "dec-1", "pol-1")
    }

    fn test_gate_input() -> PublicationGateInput {
        PublicationGateInput {
            node_cases: vec![test_case("w1", 3000.0, 1000.0)],
            bun_cases: vec![test_case("w1", 4000.0, 1000.0)],
            native_coverage_progression: vec![NativeCoveragePoint {
                recorded_at_utc: "2026-01-01T00:00:00Z".into(),
                native_slots: 10,
                total_slots: 20,
            }],
            replacement_lineage_ids: vec!["lineage-1".into()],
        }
    }

    // ── BaselineEngine ────────────────────────────────────────────

    #[test]
    fn baseline_engine_as_str() {
        assert_eq!(BaselineEngine::Node.as_str(), "node");
        assert_eq!(BaselineEngine::Bun.as_str(), "bun");
    }

    #[test]
    fn baseline_engine_serde_round_trip() {
        for e in [BaselineEngine::Node, BaselineEngine::Bun] {
            let json = serde_json::to_string(&e).expect("serialize derived Serialize");
            let back: BaselineEngine =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(e, back);
        }
    }

    // ── BenchmarkCase::speedup ────────────────────────────────────

    #[test]
    fn speedup_basic() {
        let c = test_case("w1", 3000.0, 1000.0);
        assert!((c.speedup() - 3.0).abs() < 1e-10);
    }

    #[test]
    fn speedup_fractional() {
        let c = test_case("w1", 500.0, 1000.0);
        assert!((c.speedup() - 0.5).abs() < 1e-10);
    }

    // ── BenchmarkDenominatorError ─────────────────────────────────

    #[test]
    fn error_stable_codes() {
        assert_eq!(
            BenchmarkDenominatorError::EmptyCaseSet {
                baseline: "node".into()
            }
            .stable_code(),
            "FE-BENCH-1001"
        );
        assert_eq!(
            BenchmarkDenominatorError::DuplicateWorkloadId {
                baseline: "node".into(),
                workload_id: "w1".into()
            }
            .stable_code(),
            "FE-BENCH-1001"
        );
        assert_eq!(
            BenchmarkDenominatorError::InvalidWeight {
                workload_id: "w1".into(),
                reason: "bad".into()
            }
            .stable_code(),
            "FE-BENCH-1002"
        );
        assert_eq!(
            BenchmarkDenominatorError::InvalidThroughput {
                workload_id: "w1".into(),
                field: "f".into()
            }
            .stable_code(),
            "FE-BENCH-1003"
        );
        assert_eq!(
            BenchmarkDenominatorError::InvalidWeightSum {
                baseline: "node".into(),
                sum: 0.5
            }
            .stable_code(),
            "FE-BENCH-1004"
        );
        assert_eq!(
            BenchmarkDenominatorError::MissingCoverageProgression.stable_code(),
            "FE-BENCH-1005"
        );
        assert_eq!(
            BenchmarkDenominatorError::MissingReplacementLineage.stable_code(),
            "FE-BENCH-1006"
        );
        assert_eq!(
            BenchmarkDenominatorError::SerializationFailure("x".into()).stable_code(),
            "FE-BENCH-1007"
        );
    }

    #[test]
    fn error_display() {
        let e = BenchmarkDenominatorError::EmptyCaseSet {
            baseline: "node".into(),
        };
        assert!(e.to_string().contains("node"));
        assert!(e.to_string().contains("empty"));
    }

    // ── deterministic_round ───────────────────────────────────────

    #[test]
    fn deterministic_round_identity_for_integer() {
        assert!((deterministic_round(3.0) - 3.0).abs() < 1e-15);
    }

    #[test]
    fn deterministic_round_truncates_noise() {
        let a = deterministic_round(3.000_000_000_001);
        let b = deterministic_round(3.000_000_000_001);
        assert_eq!(a, b);
    }

    // ── weighted_geometric_mean ───────────────────────────────────

    #[test]
    fn geometric_mean_uniform_weights() {
        let cases = vec![test_case("w1", 3000.0, 1000.0)];
        let score = weighted_geometric_mean(&cases, BaselineEngine::Node)
            .expect("operation should succeed for valid inputs");
        assert!((score - 3.0).abs() < 1e-6);
    }

    #[test]
    fn geometric_mean_multiple_equal_speedups() {
        let cases = vec![
            test_case("w1", 4000.0, 1000.0),
            test_case("w2", 4000.0, 1000.0),
        ];
        let score = weighted_geometric_mean(&cases, BaselineEngine::Node)
            .expect("operation should succeed for valid inputs");
        assert!((score - 4.0).abs() < 1e-6);
    }

    #[test]
    fn geometric_mean_with_explicit_weights() {
        let cases = vec![
            test_case_weighted("w1", 9000.0, 1000.0, 0.5),
            test_case_weighted("w2", 1000.0, 1000.0, 0.5),
        ];
        let score = weighted_geometric_mean(&cases, BaselineEngine::Node)
            .expect("operation should succeed for valid inputs");
        // geometric mean of 9x and 1x with equal weights = sqrt(9*1) = 3
        assert!((score - 3.0).abs() < 1e-6);
    }

    #[test]
    fn geometric_mean_empty_cases_errors() {
        let err = weighted_geometric_mean(&[], BaselineEngine::Node).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::EmptyCaseSet { .. }
        ));
    }

    #[test]
    fn geometric_mean_empty_workload_id_errors() {
        let cases = vec![test_case("", 3000.0, 1000.0)];
        let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::EmptyWorkloadId { .. }
        ));
    }

    #[test]
    fn geometric_mean_duplicate_workload_errors() {
        let cases = vec![
            test_case("w1", 3000.0, 1000.0),
            test_case("w1", 4000.0, 1000.0),
        ];
        let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::DuplicateWorkloadId { .. }
        ));
    }

    #[test]
    fn geometric_mean_invalid_throughput_zero() {
        let cases = vec![test_case("w1", 0.0, 1000.0)];
        assert!(weighted_geometric_mean(&cases, BaselineEngine::Node).is_err());
    }

    #[test]
    fn geometric_mean_invalid_throughput_negative() {
        let cases = vec![test_case("w1", -1.0, 1000.0)];
        assert!(weighted_geometric_mean(&cases, BaselineEngine::Node).is_err());
    }

    #[test]
    fn geometric_mean_invalid_baseline_zero() {
        let cases = vec![test_case("w1", 3000.0, 0.0)];
        assert!(weighted_geometric_mean(&cases, BaselineEngine::Node).is_err());
    }

    #[test]
    fn geometric_mean_invalid_throughput_nan() {
        let cases = vec![test_case("w1", f64::NAN, 1000.0)];
        assert!(weighted_geometric_mean(&cases, BaselineEngine::Node).is_err());
    }

    #[test]
    fn geometric_mean_invalid_weight_negative() {
        let cases = vec![test_case_weighted("w1", 3000.0, 1000.0, -0.5)];
        assert!(weighted_geometric_mean(&cases, BaselineEngine::Node).is_err());
    }

    #[test]
    fn geometric_mean_mixed_weights_errors() {
        let cases = vec![
            test_case("w1", 3000.0, 1000.0),               // None weight
            test_case_weighted("w2", 4000.0, 1000.0, 1.0), // Some weight
        ];
        let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::InvalidWeight { .. }
        ));
    }

    #[test]
    fn geometric_mean_weights_not_summing_to_one() {
        let cases = vec![
            test_case_weighted("w1", 3000.0, 1000.0, 0.3),
            test_case_weighted("w2", 4000.0, 1000.0, 0.3),
        ];
        let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::InvalidWeightSum { .. }
        ));
    }

    // ── PublicationContext ─────────────────────────────────────────

    #[test]
    fn publication_context_new() {
        let ctx = PublicationContext::new("t", "d", "p");
        assert_eq!(ctx.trace_id, "t");
        assert_eq!(ctx.decision_id, "d");
        assert_eq!(ctx.policy_id, "p");
    }

    // ── evaluate_publication_gate ──────────────────────────────────

    #[test]
    fn gate_passing() {
        let input = test_gate_input();
        let ctx = test_context();
        let decision = evaluate_publication_gate(&input, &ctx)
            .expect("operation should succeed for valid inputs");
        assert!(decision.publish_allowed);
        assert!(decision.score_vs_node >= SCORE_THRESHOLD);
        assert!(decision.score_vs_bun >= SCORE_THRESHOLD);
        assert!(decision.blockers.is_empty());
        assert!(!decision.events.is_empty());
    }

    #[test]
    fn gate_below_threshold_node() {
        let mut input = test_gate_input();
        input.node_cases = vec![test_case("w1", 2000.0, 1000.0)]; // 2x < 3x
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        assert!(!decision.publish_allowed);
        assert!(
            decision
                .blockers
                .iter()
                .any(|b| b.contains("score_vs_node"))
        );
    }

    #[test]
    fn gate_below_threshold_bun() {
        let mut input = test_gate_input();
        input.bun_cases = vec![test_case("w1", 1000.0, 1000.0)]; // 1x < 3x
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        assert!(!decision.publish_allowed);
        assert!(decision.blockers.iter().any(|b| b.contains("score_vs_bun")));
    }

    #[test]
    fn gate_behavior_equivalent_false_blocks() {
        let mut input = test_gate_input();
        input.node_cases[0].behavior_equivalent = false;
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        assert!(!decision.publish_allowed);
        assert!(
            decision
                .blockers
                .iter()
                .any(|b| b.contains("behavior-equivalence"))
        );
    }

    #[test]
    fn gate_latency_envelope_false_blocks() {
        let mut input = test_gate_input();
        input.bun_cases[0].latency_envelope_ok = false;
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        assert!(!decision.publish_allowed);
        assert!(
            decision
                .blockers
                .iter()
                .any(|b| b.contains("latency envelope"))
        );
    }

    #[test]
    fn gate_error_envelope_false_blocks() {
        let mut input = test_gate_input();
        input.node_cases[0].error_envelope_ok = false;
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        assert!(!decision.publish_allowed);
    }

    #[test]
    fn gate_execution_authentic_false_blocks_node() {
        let mut input = test_gate_input();
        input.node_cases[0].execution_authentic = false;
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        assert!(!decision.publish_allowed);
        assert!(
            decision
                .blockers
                .iter()
                .any(|b| b.contains("execution authenticity")
                    && b.contains("mock response detected"))
        );
    }

    #[test]
    fn gate_execution_authentic_false_blocks_bun() {
        let mut input = test_gate_input();
        input.bun_cases[0].execution_authentic = false;
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        assert!(!decision.publish_allowed);
        assert!(
            decision
                .blockers
                .iter()
                .any(|b| b.contains("execution authenticity")
                    && b.contains("mock response detected"))
        );
    }

    #[test]
    fn gate_missing_coverage_progression() {
        let mut input = test_gate_input();
        input.native_coverage_progression.clear();
        let err = evaluate_publication_gate(&input, &test_context()).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::MissingCoverageProgression
        ));
    }

    #[test]
    fn gate_missing_lineage() {
        let mut input = test_gate_input();
        input.replacement_lineage_ids.clear();
        let err = evaluate_publication_gate(&input, &test_context()).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::MissingReplacementLineage
        ));
    }

    #[test]
    fn gate_lineage_dedup_and_trim() {
        let mut input = test_gate_input();
        input.replacement_lineage_ids = vec![
            "  lineage-1 ".into(),
            "lineage-1".into(),
            "lineage-2".into(),
        ];
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        assert_eq!(decision.replacement_lineage_ids.len(), 2);
    }

    #[test]
    fn gate_empty_lineage_strings_filtered() {
        let mut input = test_gate_input();
        input.replacement_lineage_ids = vec!["  ".into(), "".into()];
        let err = evaluate_publication_gate(&input, &test_context()).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::MissingReplacementLineage
        ));
    }

    #[test]
    fn gate_events_contain_baselines() {
        let input = test_gate_input();
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        assert!(
            decision
                .events
                .iter()
                .any(|e| e.event == "node_score_evaluated")
        );
        assert!(
            decision
                .events
                .iter()
                .any(|e| e.event == "bun_score_evaluated")
        );
        assert!(
            decision
                .events
                .iter()
                .any(|e| e.event == "publication_gate_decision")
        );
    }

    // ── PublicationGateDecision::to_json_pretty ───────────────────

    #[test]
    fn decision_to_json_pretty() {
        let input = test_gate_input();
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        let json = decision
            .to_json_pretty()
            .expect("operation should succeed for valid inputs");
        assert!(json.contains("publish_allowed"));
    }

    // ── serde round-trips ─────────────────────────────────────────

    #[test]
    fn benchmark_case_serde_round_trip() {
        let c = test_case("w1", 3000.0, 1000.0);
        let json = serde_json::to_string(&c).expect("serialize derived Serialize");
        let back: BenchmarkCase =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(c.workload_id, back.workload_id);
        assert!((c.throughput_franken_tps - back.throughput_franken_tps).abs() < 1e-10);
    }

    #[test]
    fn publication_context_serde_round_trip() {
        let ctx = test_context();
        let json = serde_json::to_string(&ctx).expect("serialize derived Serialize");
        let back: PublicationContext =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(ctx, back);
    }

    #[test]
    fn native_coverage_point_serde_round_trip() {
        let p = NativeCoveragePoint {
            recorded_at_utc: "2026-01-01T00:00:00Z".into(),
            native_slots: 10,
            total_slots: 20,
        };
        let json = serde_json::to_string(&p).expect("serialize derived Serialize");
        let back: NativeCoveragePoint =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(p, back);
    }

    #[test]
    fn benchmark_publication_event_serde_round_trip() {
        let e = BenchmarkPublicationEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "o".into(),
            error_code: None,
        };
        let json = serde_json::to_string(&e).expect("serialize derived Serialize");
        let back: BenchmarkPublicationEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(e, back);
    }

    #[test]
    fn gate_decision_serde_round_trip() {
        let input = test_gate_input();
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        let json = serde_json::to_string(&decision).expect("serialize derived Serialize");
        let back: PublicationGateDecision =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(decision.publish_allowed, back.publish_allowed);
        assert!((decision.score_vs_node - back.score_vs_node).abs() < 1e-10);
    }

    // ── BenchmarkCase defaults ────────────────────────────────────

    #[test]
    fn case_defaults_from_json() {
        let json =
            r#"{"workload_id":"w","throughput_franken_tps":100.0,"throughput_baseline_tps":50.0}"#;
        let c: BenchmarkCase = serde_json::from_str(json).expect("deserialize known-valid JSON");
        assert!(c.behavior_equivalent);
        assert!(c.latency_envelope_ok);
        assert!(c.error_envelope_ok);
        assert!(c.execution_authentic);
        assert!(c.weight.is_none());
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2: Display uniqueness, edge cases, error coverage
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_all_variants_unique() {
        let variants: Vec<BenchmarkDenominatorError> = vec![
            BenchmarkDenominatorError::EmptyCaseSet {
                baseline: "node".into(),
            },
            BenchmarkDenominatorError::EmptyWorkloadId {
                baseline: "bun".into(),
            },
            BenchmarkDenominatorError::DuplicateWorkloadId {
                baseline: "node".into(),
                workload_id: "w1".into(),
            },
            BenchmarkDenominatorError::InvalidWeight {
                workload_id: "w1".into(),
                reason: "bad".into(),
            },
            BenchmarkDenominatorError::InvalidThroughput {
                workload_id: "w1".into(),
                field: "f".into(),
            },
            BenchmarkDenominatorError::InvalidWeightSum {
                baseline: "node".into(),
                sum: 0.5,
            },
            BenchmarkDenominatorError::MissingCoverageProgression,
            BenchmarkDenominatorError::MissingReplacementLineage,
            BenchmarkDenominatorError::SerializationFailure("err".into()),
        ];
        let displays: BTreeSet<String> = variants.iter().map(|e| e.to_string()).collect();
        assert_eq!(
            displays.len(),
            9,
            "all 9 error variants must have unique Display"
        );
    }

    #[test]
    fn error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(BenchmarkDenominatorError::EmptyCaseSet {
            baseline: "node".into(),
        });
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn geometric_mean_single_case_equals_speedup() {
        let cases = vec![test_case("w1", 5000.0, 1000.0)];
        let score = weighted_geometric_mean(&cases, BaselineEngine::Node)
            .expect("operation should succeed for valid inputs");
        assert!((score - 5.0).abs() < 1e-6);
    }

    #[test]
    fn geometric_mean_deterministic_across_calls() {
        let cases = vec![
            test_case("w1", 3000.0, 1000.0),
            test_case("w2", 4000.0, 1000.0),
            test_case("w3", 5000.0, 1000.0),
        ];
        let s1 = weighted_geometric_mean(&cases, BaselineEngine::Bun)
            .expect("operation should succeed for valid inputs");
        let s2 = weighted_geometric_mean(&cases, BaselineEngine::Bun)
            .expect("operation should succeed for valid inputs");
        assert_eq!(s1, s2, "geometric mean must be deterministic");
    }

    #[test]
    fn gate_decision_events_count() {
        let input = test_gate_input();
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        // Should have: node_score, bun_score, publication_gate_decision = 3 events
        assert_eq!(decision.events.len(), 3);
    }

    #[test]
    fn gate_passing_events_all_pass() {
        let input = test_gate_input();
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        for event in &decision.events {
            assert!(
                event.outcome == "pass" || event.outcome == "allow",
                "expected pass/allow, got {}",
                event.outcome
            );
            assert!(event.error_code.is_none());
        }
    }

    #[test]
    fn geometric_mean_invalid_throughput_inf() {
        let cases = vec![test_case("w1", f64::INFINITY, 1000.0)];
        assert!(weighted_geometric_mean(&cases, BaselineEngine::Node).is_err());
    }

    #[test]
    fn publication_gate_input_serde_roundtrip() {
        let input = test_gate_input();
        let json = serde_json::to_string(&input).expect("serialize derived Serialize");
        let back: PublicationGateInput =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(input.node_cases.len(), back.node_cases.len());
        assert_eq!(input.bun_cases.len(), back.bun_cases.len());
        assert_eq!(
            input.native_coverage_progression.len(),
            back.native_coverage_progression.len()
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 3: clone equality, JSON field presence, boundary, Ord,
    //                      std::error::Error::source, serde roundtrip
    // -----------------------------------------------------------------------

    // ── Clone equality tests (5) ────────────────────────────────────

    #[test]
    fn baseline_engine_clone_eq() {
        let original = BaselineEngine::Node;
        let cloned = original;
        assert_eq!(original, cloned);

        let bun = BaselineEngine::Bun;
        let bun_cloned = bun;
        assert_eq!(bun, bun_cloned);
    }

    #[test]
    fn benchmark_case_clone_eq() {
        let original = test_case_weighted("wk-1", 5000.0, 1000.0, 0.5);
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn publication_context_clone_eq() {
        let original = PublicationContext::new("tr-99", "dec-42", "pol-7");
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn native_coverage_point_clone_eq() {
        let original = NativeCoveragePoint {
            recorded_at_utc: "2026-02-26T12:00:00Z".into(),
            native_slots: 77,
            total_slots: 100,
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn benchmark_publication_event_clone_eq() {
        let original = BenchmarkPublicationEvent {
            trace_id: "tr-1".into(),
            decision_id: "dec-1".into(),
            policy_id: "pol-1".into(),
            component: BENCHMARK_PUBLICATION_COMPONENT.to_string(),
            event: "test_event".into(),
            outcome: "pass".into(),
            error_code: Some("FE-BENCH-1007".into()),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    // ── JSON field presence tests (3) ───────────────────────────────

    #[test]
    fn benchmark_case_json_field_names() {
        let c = test_case("check-fields", 1000.0, 500.0);
        let json = serde_json::to_string(&c).expect("serialize derived Serialize");
        assert!(json.contains("\"workload_id\""));
        assert!(json.contains("\"throughput_franken_tps\""));
        assert!(json.contains("\"throughput_baseline_tps\""));
        assert!(json.contains("\"behavior_equivalent\""));
        assert!(json.contains("\"latency_envelope_ok\""));
        assert!(json.contains("\"error_envelope_ok\""));
        assert!(json.contains("\"execution_authentic\""));
    }

    #[test]
    fn publication_context_json_field_names() {
        let ctx = PublicationContext::new("t-1", "d-1", "p-1");
        let json = serde_json::to_string(&ctx).expect("serialize derived Serialize");
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"policy_id\""));
    }

    #[test]
    fn publication_gate_decision_json_field_names() {
        let input = test_gate_input();
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        let json = serde_json::to_string(&decision).expect("serialize derived Serialize");
        assert!(json.contains("\"score_vs_node\""));
        assert!(json.contains("\"score_vs_bun\""));
        assert!(json.contains("\"publish_allowed\""));
        assert!(json.contains("\"blockers\""));
        assert!(json.contains("\"native_coverage_progression\""));
        assert!(json.contains("\"replacement_lineage_ids\""));
        assert!(json.contains("\"events\""));
    }

    // ── Serde roundtrip (error variant) ─────────────────────────────

    #[test]
    fn benchmark_denominator_error_serde_roundtrip() {
        let err = BenchmarkDenominatorError::DuplicateWorkloadId {
            baseline: "bun".into(),
            workload_id: "dup-w".into(),
        };
        let json = serde_json::to_string(&err).expect("serialize derived Serialize");
        let back: BenchmarkDenominatorError =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(err, back);
    }

    // ── Display uniqueness across baselines ─────────────────────────

    #[test]
    fn error_display_differentiates_baselines() {
        let node_err = BenchmarkDenominatorError::EmptyCaseSet {
            baseline: "node".into(),
        };
        let bun_err = BenchmarkDenominatorError::EmptyCaseSet {
            baseline: "bun".into(),
        };
        assert_ne!(node_err.to_string(), bun_err.to_string());
    }

    // ── Boundary: exact threshold score ─────────────────────────────

    #[test]
    fn gate_exact_threshold_score_passes() {
        // 3x exactly should pass (>= 3.0)
        let input = PublicationGateInput {
            node_cases: vec![test_case("exact-n", 3000.0, 1000.0)],
            bun_cases: vec![test_case("exact-b", 3000.0, 1000.0)],
            native_coverage_progression: vec![NativeCoveragePoint {
                recorded_at_utc: "2026-02-26T00:00:00Z".into(),
                native_slots: 5,
                total_slots: 10,
            }],
            replacement_lineage_ids: vec!["lin-exact".into()],
        };
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        assert!(decision.publish_allowed, "exactly 3x should pass the gate");
    }

    // ── std::error::Error::source ───────────────────────────────────

    #[test]
    fn error_source_is_none_for_all_variants() {
        use std::error::Error as StdError;
        let variants: Vec<BenchmarkDenominatorError> = vec![
            BenchmarkDenominatorError::EmptyCaseSet {
                baseline: "node".into(),
            },
            BenchmarkDenominatorError::MissingCoverageProgression,
            BenchmarkDenominatorError::MissingReplacementLineage,
            BenchmarkDenominatorError::SerializationFailure("x".into()),
        ];
        for v in &variants {
            // thiserror derives source(); for these leaf variants it should be None
            assert!(v.source().is_none(), "expected source() == None for {v}");
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: clone independence, Debug, serde edge cases,
    //     stress, deterministic replay, error display content
    // -----------------------------------------------------------------------

    // ── Clone independence (mutate original, assert clone unchanged) ──

    #[test]
    fn benchmark_case_clone_independence() {
        let mut original = test_case("w-orig", 5000.0, 1000.0);
        let cloned = original.clone();
        original.workload_id = "w-mutated".into();
        original.throughput_franken_tps = 9999.0;
        assert_eq!(cloned.workload_id, "w-orig");
        assert!((cloned.throughput_franken_tps - 5000.0).abs() < 1e-10);
    }

    #[test]
    fn publication_context_clone_independence() {
        let mut original = PublicationContext::new("tr-orig", "dec-orig", "pol-orig");
        let cloned = original.clone();
        original.trace_id = "tr-mutated".into();
        original.decision_id = "dec-mutated".into();
        assert_eq!(cloned.trace_id, "tr-orig");
        assert_eq!(cloned.decision_id, "dec-orig");
    }

    #[test]
    fn native_coverage_point_clone_independence() {
        let mut original = NativeCoveragePoint {
            recorded_at_utc: "2026-01-01T00:00:00Z".into(),
            native_slots: 50,
            total_slots: 100,
        };
        let cloned = original.clone();
        original.native_slots = 999;
        original.total_slots = 1000;
        assert_eq!(cloned.native_slots, 50);
        assert_eq!(cloned.total_slots, 100);
    }

    #[test]
    fn publication_gate_decision_clone_independence() {
        let input = test_gate_input();
        let mut decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        let cloned = decision.clone();
        decision.publish_allowed = false;
        decision.blockers.push("injected".into());
        assert!(cloned.publish_allowed);
        assert!(cloned.blockers.is_empty());
    }

    #[test]
    fn benchmark_publication_event_clone_independence() {
        let mut original = BenchmarkPublicationEvent {
            trace_id: "tr-1".into(),
            decision_id: "dec-1".into(),
            policy_id: "pol-1".into(),
            component: "comp-1".into(),
            event: "ev-1".into(),
            outcome: "pass".into(),
            error_code: None,
        };
        let cloned = original.clone();
        original.outcome = "fail".into();
        original.error_code = Some("FE-BENCH-9999".into());
        assert_eq!(cloned.outcome, "pass");
        assert!(cloned.error_code.is_none());
    }

    #[test]
    fn benchmark_denominator_error_clone_independence() {
        let mut original = BenchmarkDenominatorError::DuplicateWorkloadId {
            baseline: "node".into(),
            workload_id: "w1".into(),
        };
        let cloned = original.clone();
        original = BenchmarkDenominatorError::MissingCoverageProgression;
        assert!(matches!(
            cloned,
            BenchmarkDenominatorError::DuplicateWorkloadId { .. }
        ));
        assert!(matches!(
            original,
            BenchmarkDenominatorError::MissingCoverageProgression
        ));
    }

    // ── Debug format content assertions ──────────────────────────────

    #[test]
    fn baseline_engine_debug_contains_variant_name() {
        let node_dbg = format!("{:?}", BaselineEngine::Node);
        let bun_dbg = format!("{:?}", BaselineEngine::Bun);
        assert!(node_dbg.contains("Node"));
        assert!(bun_dbg.contains("Bun"));
        assert_ne!(node_dbg, bun_dbg);
    }

    #[test]
    fn benchmark_case_debug_contains_workload_id() {
        let c = test_case("debug-wk", 1234.0, 567.0);
        let dbg = format!("{c:?}");
        assert!(dbg.contains("debug-wk"));
        assert!(dbg.contains("1234"));
    }

    #[test]
    fn publication_context_debug_contains_ids() {
        let ctx = PublicationContext::new("tr-dbg", "dec-dbg", "pol-dbg");
        let dbg = format!("{ctx:?}");
        assert!(dbg.contains("tr-dbg"));
        assert!(dbg.contains("dec-dbg"));
        assert!(dbg.contains("pol-dbg"));
    }

    #[test]
    fn benchmark_denominator_error_debug_not_empty() {
        let err = BenchmarkDenominatorError::MissingCoverageProgression;
        let dbg = format!("{err:?}");
        assert!(!dbg.is_empty());
        assert!(dbg.contains("MissingCoverageProgression"));
    }

    // ── Error Display content assertions for all variants ────────────

    #[test]
    fn error_display_empty_workload_id_content() {
        let e = BenchmarkDenominatorError::EmptyWorkloadId {
            baseline: "bun".into(),
        };
        let s = e.to_string();
        assert!(s.contains("empty workload id"));
        assert!(s.contains("bun"));
    }

    #[test]
    fn error_display_duplicate_workload_id_content() {
        let e = BenchmarkDenominatorError::DuplicateWorkloadId {
            baseline: "node".into(),
            workload_id: "dup-wk".into(),
        };
        let s = e.to_string();
        assert!(s.contains("duplicate"));
        assert!(s.contains("dup-wk"));
        assert!(s.contains("node"));
    }

    #[test]
    fn error_display_invalid_weight_content() {
        let e = BenchmarkDenominatorError::InvalidWeight {
            workload_id: "wt-bad".into(),
            reason: "weight must be finite".into(),
        };
        let s = e.to_string();
        assert!(s.contains("invalid weight"));
        assert!(s.contains("wt-bad"));
        assert!(s.contains("weight must be finite"));
    }

    #[test]
    fn error_display_invalid_throughput_content() {
        let e = BenchmarkDenominatorError::InvalidThroughput {
            workload_id: "tp-bad".into(),
            field: "throughput_franken_tps".into(),
        };
        let s = e.to_string();
        assert!(s.contains("invalid throughput"));
        assert!(s.contains("tp-bad"));
        assert!(s.contains("throughput_franken_tps"));
    }

    #[test]
    fn error_display_invalid_weight_sum_content() {
        let e = BenchmarkDenominatorError::InvalidWeightSum {
            baseline: "bun".into(),
            sum: 0.42,
        };
        let s = e.to_string();
        assert!(s.contains("weights"));
        assert!(s.contains("bun"));
        assert!(s.contains("0.42"));
    }

    #[test]
    fn error_display_missing_coverage_content() {
        let s = BenchmarkDenominatorError::MissingCoverageProgression.to_string();
        assert!(s.contains("native coverage"));
    }

    #[test]
    fn error_display_missing_lineage_content() {
        let s = BenchmarkDenominatorError::MissingReplacementLineage.to_string();
        assert!(s.contains("replacement lineage"));
    }

    #[test]
    fn error_display_serialization_failure_content() {
        let e = BenchmarkDenominatorError::SerializationFailure("json broke".into());
        let s = e.to_string();
        assert!(s.contains("serialization failure"));
        assert!(s.contains("json broke"));
    }

    // ── Serde roundtrip for all error variants ───────────────────────

    #[test]
    fn error_serde_roundtrip_all_variants() {
        let variants: Vec<BenchmarkDenominatorError> = vec![
            BenchmarkDenominatorError::EmptyCaseSet {
                baseline: "node".into(),
            },
            BenchmarkDenominatorError::EmptyWorkloadId {
                baseline: "bun".into(),
            },
            BenchmarkDenominatorError::DuplicateWorkloadId {
                baseline: "node".into(),
                workload_id: "w7".into(),
            },
            BenchmarkDenominatorError::InvalidWeight {
                workload_id: "w3".into(),
                reason: "negative".into(),
            },
            BenchmarkDenominatorError::InvalidThroughput {
                workload_id: "w4".into(),
                field: "throughput_baseline_tps".into(),
            },
            BenchmarkDenominatorError::InvalidWeightSum {
                baseline: "bun".into(),
                sum: 1.5,
            },
            BenchmarkDenominatorError::MissingCoverageProgression,
            BenchmarkDenominatorError::MissingReplacementLineage,
            BenchmarkDenominatorError::SerializationFailure("test-err".into()),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize derived Serialize");
            let back: BenchmarkDenominatorError =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*v, back, "serde roundtrip failed for {v}");
        }
    }

    // ── Serde edge cases ─────────────────────────────────────────────

    #[test]
    fn benchmark_case_weighted_serde_roundtrip() {
        let c = test_case_weighted("sw-1", 7000.0, 1000.0, 0.75);
        let json = serde_json::to_string(&c).expect("serialize derived Serialize");
        let back: BenchmarkCase =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(c, back);
        assert_eq!(back.weight, Some(0.75));
    }

    #[test]
    fn benchmark_publication_event_with_error_code_serde() {
        let e = BenchmarkPublicationEvent {
            trace_id: "tr-ec".into(),
            decision_id: "dec-ec".into(),
            policy_id: "pol-ec".into(),
            component: BENCHMARK_PUBLICATION_COMPONENT.to_string(),
            event: "node_score_evaluated".into(),
            outcome: "fail".into(),
            error_code: Some("FE-BENCH-1007".into()),
        };
        let json = serde_json::to_string(&e).expect("serialize derived Serialize");
        let back: BenchmarkPublicationEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(e, back);
        assert_eq!(back.error_code.as_deref(), Some("FE-BENCH-1007"));
    }

    #[test]
    fn baseline_engine_serde_snake_case_format() {
        let json =
            serde_json::to_string(&BaselineEngine::Node).expect("serialization should succeed");
        assert_eq!(json, "\"node\"");
        let json =
            serde_json::to_string(&BaselineEngine::Bun).expect("serialization should succeed");
        assert_eq!(json, "\"bun\"");
    }

    // ── Geometric mean: workload ordering independence ───────────────

    #[test]
    fn geometric_mean_order_independent() {
        let cases_fwd = vec![
            test_case("alpha", 2000.0, 1000.0),
            test_case("beta", 4000.0, 1000.0),
            test_case("gamma", 8000.0, 1000.0),
        ];
        let cases_rev = vec![
            test_case("gamma", 8000.0, 1000.0),
            test_case("alpha", 2000.0, 1000.0),
            test_case("beta", 4000.0, 1000.0),
        ];
        let s_fwd = weighted_geometric_mean(&cases_fwd, BaselineEngine::Node)
            .expect("operation should succeed for valid inputs");
        let s_rev = weighted_geometric_mean(&cases_rev, BaselineEngine::Node)
            .expect("operation should succeed for valid inputs");
        assert_eq!(s_fwd, s_rev, "ordering of cases must not affect score");
    }

    // ── Geometric mean: stress with many cases ───────────────────────

    #[test]
    fn geometric_mean_stress_many_cases() {
        let n = 100;
        let cases: Vec<BenchmarkCase> = (0..n)
            .map(|i| test_case(&format!("stress-{i}"), 4000.0, 1000.0))
            .collect();
        let score = weighted_geometric_mean(&cases, BaselineEngine::Bun)
            .expect("operation should succeed for valid inputs");
        // All cases have identical speedup of 4x, geometric mean should be 4x
        assert!((score - 4.0).abs() < 1e-6);
    }

    // ── Geometric mean: asymmetric explicit weights ──────────────────

    #[test]
    fn geometric_mean_asymmetric_weights() {
        // weight 0.9 on 10x speedup, weight 0.1 on 1x speedup
        // geometric mean = 10^0.9 * 1^0.1 = 10^0.9 ≈ 7.943
        let cases = vec![
            test_case_weighted("heavy", 10000.0, 1000.0, 0.9),
            test_case_weighted("light", 1000.0, 1000.0, 0.1),
        ];
        let score = weighted_geometric_mean(&cases, BaselineEngine::Node)
            .expect("operation should succeed for valid inputs");
        let expected = 10.0_f64.powf(0.9);
        assert!(
            (score - expected).abs() < 1e-4,
            "expected ~{expected:.4}, got {score:.4}"
        );
    }

    // ── Gate: multiple blockers simultaneously ───────────────────────

    #[test]
    fn gate_multiple_blockers_combined() {
        let mut input = test_gate_input();
        // Below threshold for both
        input.node_cases = vec![test_case("w1", 2000.0, 1000.0)];
        input.bun_cases = vec![test_case("w1", 1500.0, 1000.0)];
        // Fail behavior and latency on bun
        input.bun_cases[0].behavior_equivalent = false;
        input.bun_cases[0].latency_envelope_ok = false;
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        assert!(!decision.publish_allowed);
        // Should have at least 4 blockers:
        // behavior-equiv, latency, score_vs_node, score_vs_bun
        assert!(
            decision.blockers.len() >= 4,
            "expected >= 4 blockers, got {}",
            decision.blockers.len()
        );
    }

    #[test]
    fn gate_all_three_quality_failures() {
        let mut input = test_gate_input();
        input.node_cases[0].behavior_equivalent = false;
        input.node_cases[0].latency_envelope_ok = false;
        input.node_cases[0].error_envelope_ok = false;
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        assert!(!decision.publish_allowed);
        let blockers_str = decision.blockers.join("; ");
        assert!(blockers_str.contains("behavior-equivalence"));
        assert!(blockers_str.contains("latency envelope"));
        assert!(blockers_str.contains("error envelope"));
    }

    // ── Gate: denied events carry error_code ─────────────────────────

    #[test]
    fn gate_denied_events_have_error_code() {
        let mut input = test_gate_input();
        input.node_cases = vec![test_case("w1", 2000.0, 1000.0)]; // 2x < 3x
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        // The node_score_evaluated event should have an error_code
        let node_event = decision
            .events
            .iter()
            .find(|e| e.event == "node_score_evaluated")
            .expect("operation should succeed for valid inputs");
        assert_eq!(node_event.outcome, "fail");
        assert!(node_event.error_code.is_some());
        assert_eq!(
            node_event.error_code.as_deref(),
            Some(ERROR_PUBLICATION_GATE_DENY)
        );
        // The publication_gate_decision event should also have error_code
        let gate_event = decision
            .events
            .iter()
            .find(|e| e.event == "publication_gate_decision")
            .expect("operation should succeed for valid inputs");
        assert_eq!(gate_event.outcome, "deny");
        assert!(gate_event.error_code.is_some());
    }

    // ── Gate: to_json_pretty content assertions ──────────────────────

    #[test]
    fn decision_to_json_pretty_structure() {
        let input = test_gate_input();
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        let json = decision
            .to_json_pretty()
            .expect("operation should succeed for valid inputs");
        // Pretty-printed JSON should have newlines and indentation
        assert!(json.contains('\n'));
        assert!(json.contains("  "));
        assert!(json.contains("\"score_vs_node\""));
        assert!(json.contains("\"events\""));
    }

    // ── Gate: lineage sorting verified ───────────────────────────────

    #[test]
    fn gate_lineage_ids_sorted() {
        let mut input = test_gate_input();
        input.replacement_lineage_ids = vec!["charlie".into(), "alpha".into(), "bravo".into()];
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        assert_eq!(
            decision.replacement_lineage_ids,
            vec!["alpha", "bravo", "charlie"]
        );
    }

    // ── Gate: multiple coverage points preserved ─────────────────────

    #[test]
    fn gate_multiple_coverage_points_preserved() {
        let mut input = test_gate_input();
        input.native_coverage_progression = vec![
            NativeCoveragePoint {
                recorded_at_utc: "2026-01-01T00:00:00Z".into(),
                native_slots: 5,
                total_slots: 20,
            },
            NativeCoveragePoint {
                recorded_at_utc: "2026-02-01T00:00:00Z".into(),
                native_slots: 12,
                total_slots: 20,
            },
            NativeCoveragePoint {
                recorded_at_utc: "2026-03-01T00:00:00Z".into(),
                native_slots: 18,
                total_slots: 20,
            },
        ];
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        assert_eq!(decision.native_coverage_progression.len(), 3);
        assert_eq!(decision.native_coverage_progression[0].native_slots, 5);
        assert_eq!(decision.native_coverage_progression[2].native_slots, 18);
    }

    // ── Constants ────────────────────────────────────────────────────

    #[test]
    fn score_threshold_is_three() {
        assert!((SCORE_THRESHOLD - 3.0).abs() < 1e-15);
    }

    #[test]
    fn benchmark_publication_component_constant() {
        assert_eq!(BENCHMARK_PUBLICATION_COMPONENT, "benchmark_denominator");
    }

    // ── Deterministic replay ─────────────────────────────────────────

    #[test]
    fn gate_deterministic_replay() {
        let input = test_gate_input();
        let ctx = test_context();
        let d1 = evaluate_publication_gate(&input, &ctx)
            .expect("operation should succeed for valid inputs");
        let d2 = evaluate_publication_gate(&input, &ctx)
            .expect("operation should succeed for valid inputs");
        assert_eq!(d1.score_vs_node, d2.score_vs_node);
        assert_eq!(d1.score_vs_bun, d2.score_vs_bun);
        assert_eq!(d1.publish_allowed, d2.publish_allowed);
        assert_eq!(d1.blockers, d2.blockers);
        assert_eq!(d1.events.len(), d2.events.len());
        for (e1, e2) in d1.events.iter().zip(d2.events.iter()) {
            assert_eq!(e1, e2);
        }
    }

    #[test]
    fn gate_deterministic_replay_denied() {
        let mut input = test_gate_input();
        input.node_cases = vec![test_case("w1", 1500.0, 1000.0)]; // 1.5x
        let ctx = test_context();
        let d1 = evaluate_publication_gate(&input, &ctx)
            .expect("operation should succeed for valid inputs");
        let d2 = evaluate_publication_gate(&input, &ctx)
            .expect("operation should succeed for valid inputs");
        assert_eq!(d1.publish_allowed, d2.publish_allowed);
        assert!(!d1.publish_allowed);
        assert_eq!(d1.score_vs_node, d2.score_vs_node);
        assert_eq!(d1.blockers, d2.blockers);
    }

    // ── Speedup edge cases ───────────────────────────────────────────

    #[test]
    fn speedup_very_large_ratio() {
        let c = test_case("w-big", 1_000_000.0, 1.0);
        assert!((c.speedup() - 1_000_000.0).abs() < 1e-4);
    }

    #[test]
    fn speedup_very_small_ratio() {
        let c = test_case("w-small", 1.0, 1_000_000.0);
        assert!((c.speedup() - 1e-6).abs() < 1e-12);
    }

    // ── Whitespace-only workload id ──────────────────────────────────

    #[test]
    fn geometric_mean_whitespace_only_workload_id_errors() {
        let cases = vec![test_case("   ", 3000.0, 1000.0)];
        let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::EmptyWorkloadId { .. }
        ));
    }

    // ── Weight: zero weight rejected ─────────────────────────────────

    #[test]
    fn geometric_mean_zero_weight_rejected() {
        let cases = vec![test_case_weighted("w-z", 3000.0, 1000.0, 0.0)];
        let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::InvalidWeight { .. }
        ));
    }

    // ── Weight: NaN weight rejected ──────────────────────────────────

    #[test]
    fn geometric_mean_nan_weight_rejected() {
        let cases = vec![test_case_weighted("w-nan", 3000.0, 1000.0, f64::NAN)];
        let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::InvalidWeight { .. }
        ));
    }

    // ── Weight: inf weight rejected ──────────────────────────────────

    #[test]
    fn geometric_mean_inf_weight_rejected() {
        let cases = vec![test_case_weighted("w-inf", 3000.0, 1000.0, f64::INFINITY)];
        let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::InvalidWeight { .. }
        ));
    }

    // ── Baseline throughput NaN rejected ──────────────────────────────

    #[test]
    fn geometric_mean_baseline_throughput_nan_rejected() {
        let cases = vec![test_case("w-bnan", 3000.0, f64::NAN)];
        let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::InvalidThroughput { .. }
        ));
    }

    // ── Baseline throughput negative rejected ─────────────────────────

    #[test]
    fn geometric_mean_baseline_throughput_negative_rejected() {
        let cases = vec![test_case("w-bneg", 3000.0, -500.0)];
        let err = weighted_geometric_mean(&cases, BaselineEngine::Node).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::InvalidThroughput { .. }
        ));
    }

    // ── Gate event context propagation ────────────────────────────────

    #[test]
    fn gate_events_carry_context_ids() {
        let ctx = PublicationContext::new("trace-ctx", "dec-ctx", "pol-ctx");
        let input = test_gate_input();
        let decision = evaluate_publication_gate(&input, &ctx)
            .expect("operation should succeed for valid inputs");
        for event in &decision.events {
            assert_eq!(event.trace_id, "trace-ctx");
            assert_eq!(event.decision_id, "dec-ctx");
            assert_eq!(event.policy_id, "pol-ctx");
            assert_eq!(event.component, BENCHMARK_PUBLICATION_COMPONENT);
        }
    }

    // ── Gate: bun score passing while node fails ─────────────────────

    #[test]
    fn gate_bun_pass_node_fail() {
        let mut input = test_gate_input();
        input.node_cases = vec![test_case("w1", 1000.0, 1000.0)]; // 1x
        input.bun_cases = vec![test_case("w1", 5000.0, 1000.0)]; // 5x
        let decision = evaluate_publication_gate(&input, &test_context())
            .expect("operation should succeed for valid inputs");
        assert!(!decision.publish_allowed);
        assert!(decision.score_vs_bun >= SCORE_THRESHOLD);
        assert!(decision.score_vs_node < SCORE_THRESHOLD);
        // bun event should pass, node should fail
        let bun_event = decision
            .events
            .iter()
            .find(|e| e.event == "bun_score_evaluated")
            .expect("operation should succeed for valid inputs");
        assert_eq!(bun_event.outcome, "pass");
        assert!(bun_event.error_code.is_none());
    }

    // ── deterministic_round edge values ──────────────────────────────

    #[test]
    fn deterministic_round_zero() {
        assert!((deterministic_round(0.0) - 0.0).abs() < 1e-15);
    }

    #[test]
    fn deterministic_round_negative() {
        let result = deterministic_round(-2.5);
        assert!((result - (-2.5)).abs() < 1e-10);
    }

    // ── BenchmarkCase inequality ─────────────────────────────────────

    #[test]
    fn benchmark_case_inequality() {
        let a = test_case("a", 1000.0, 500.0);
        let b = test_case("b", 2000.0, 500.0);
        assert_ne!(a, b);
    }

    // ── PublicationContext inequality ─────────────────────────────────

    #[test]
    fn publication_context_inequality() {
        let a = PublicationContext::new("t1", "d1", "p1");
        let b = PublicationContext::new("t2", "d2", "p2");
        assert_ne!(a, b);
    }

    // ── BaselineEngine inequality ────────────────────────────────────

    #[test]
    fn baseline_engine_inequality() {
        assert_ne!(BaselineEngine::Node, BaselineEngine::Bun);
    }

    // ── NativeCoveragePoint JSON field names ─────────────────────────

    #[test]
    fn native_coverage_point_json_field_names() {
        let p = NativeCoveragePoint {
            recorded_at_utc: "2026-01-01T00:00:00Z".into(),
            native_slots: 10,
            total_slots: 20,
        };
        let json = serde_json::to_string(&p).expect("serialize derived Serialize");
        assert!(json.contains("\"recorded_at_utc\""));
        assert!(json.contains("\"native_slots\""));
        assert!(json.contains("\"total_slots\""));
    }

    // ── PublicationGateInput clone independence ───────────────────────

    #[test]
    fn publication_gate_input_clone_independence() {
        let mut original = test_gate_input();
        let cloned = original.clone();
        original.node_cases.clear();
        original.replacement_lineage_ids.push("extra".into());
        assert_eq!(cloned.node_cases.len(), 1);
        assert_eq!(cloned.replacement_lineage_ids.len(), 1);
    }

    // ── Weight contract (bd-cixqu.5.4) ───────────────────────────────

    fn contract_gate_input(franken_per_baseline: f64) -> PublicationGateInput {
        // Spread cases across distinct contract classes so renormalisation has
        // something to do; baseline fixed at 1000 tps.
        let ids = ["json_parse_small", "http_route_dispatch", "sha256_digest"];
        let cases: Vec<BenchmarkCase> = ids
            .iter()
            .map(|id| test_case(id, franken_per_baseline * 1000.0, 1000.0))
            .collect();
        PublicationGateInput {
            node_cases: cases.clone(),
            bun_cases: cases,
            native_coverage_progression: vec![NativeCoveragePoint {
                recorded_at_utc: "2026-05-24T00:00:00Z".into(),
                native_slots: 10,
                total_slots: 20,
            }],
            replacement_lineage_ids: vec!["lineage-1".into()],
        }
    }

    #[test]
    fn embedded_contract_loads_and_validates() {
        let contract = WeightContract::embedded_v1().expect("embedded contract must validate");
        assert_eq!(contract.contract_version, "v1");
        assert!(!contract.workload_classes.is_empty());
        let sum: f64 = contract.workload_classes.iter().map(|c| c.weight).sum();
        assert!((sum - 1.0).abs() <= WEIGHT_SUM_EPSILON, "weights sum={sum}");
    }

    #[test]
    fn contract_resolve_weights_sum_to_one() {
        let contract = WeightContract::embedded_v1().unwrap();
        let ids = vec![
            "json_parse_small".to_string(),
            "http_route_dispatch".to_string(),
            "sha256_digest".to_string(),
            "fibonacci_recursive".to_string(),
        ];
        let weights = contract.resolve_weights(&ids).unwrap();
        let sum: f64 = weights.values().sum();
        assert!((sum - 1.0).abs() <= WEIGHT_SUM_EPSILON, "sum={sum}");
        assert_eq!(weights.len(), ids.len());
    }

    #[test]
    fn contract_resolve_renormalises_over_admitted_classes() {
        let contract = WeightContract::embedded_v1().unwrap();
        // One member each from json_processing (0.20) and http (0.22).
        let ids = vec![
            "json_parse_small".to_string(),
            "http_route_dispatch".to_string(),
        ];
        let weights = contract.resolve_weights(&ids).unwrap();
        let sum: f64 = weights.values().sum();
        assert!((sum - 1.0).abs() <= WEIGHT_SUM_EPSILON);
        let json_w = weights["json_parse_small"];
        let http_w = weights["http_route_dispatch"];
        // Class-weight ratio (0.22 / 0.20 = 1.1) is preserved after renormalisation.
        assert!(
            (http_w / json_w - 1.1).abs() < 1e-9,
            "ratio={}",
            http_w / json_w
        );
    }

    #[test]
    fn contract_resolve_equal_split_within_class() {
        let contract = WeightContract::embedded_v1().unwrap();
        // Two members of the same class → equal share, summing to 1.0.
        let ids = vec![
            "json_parse_small".to_string(),
            "json_parse_large".to_string(),
        ];
        let weights = contract.resolve_weights(&ids).unwrap();
        assert!((weights["json_parse_small"] - 0.5).abs() < 1e-12);
        assert!((weights["json_parse_large"] - 0.5).abs() < 1e-12);
    }

    #[test]
    fn contract_resolve_unknown_workload_errors() {
        let contract = WeightContract::embedded_v1().unwrap();
        let ids = vec!["not_a_real_workload".to_string()];
        let err = contract.resolve_weights(&ids).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::WorkloadNotInContract { .. }
        ));
        assert_eq!(err.stable_code(), "FE-BENCH-1010");
    }

    #[test]
    fn weighted_geometric_mean_with_contract_uniform_speedup_equals_ratio() {
        let contract = WeightContract::embedded_v1().unwrap();
        // All cases 4x ⇒ weighted geometric mean = 4.0 regardless of weights.
        let cases = vec![
            test_case("json_parse_small", 4000.0, 1000.0),
            test_case("http_route_dispatch", 4000.0, 1000.0),
            test_case("matrix_multiply", 4000.0, 1000.0),
        ];
        let score =
            weighted_geometric_mean_with_contract(&cases, BaselineEngine::Node, &contract).unwrap();
        assert!((score - 4.0).abs() < 1e-9, "score={score}");
    }

    #[test]
    fn gate_with_contract_passes_at_threshold() {
        let contract = WeightContract::embedded_v1().unwrap();
        let input = contract_gate_input(3.5);
        let decision =
            evaluate_publication_gate_with_contract(&input, &test_context(), &contract).unwrap();
        assert!(decision.publish_allowed, "blockers={:?}", decision.blockers);
        assert!(decision.score_vs_node >= SCORE_THRESHOLD);
        assert!(decision.score_vs_bun >= SCORE_THRESHOLD);
    }

    #[test]
    fn gate_with_contract_denies_below_threshold() {
        let contract = WeightContract::embedded_v1().unwrap();
        let input = contract_gate_input(2.0); // 2x < 3.0
        let decision =
            evaluate_publication_gate_with_contract(&input, &test_context(), &contract).unwrap();
        assert!(!decision.publish_allowed);
        assert!(decision.score_vs_node < SCORE_THRESHOLD);
    }

    #[test]
    fn contract_validate_rejects_bad_weight_sum() {
        let json = r#"{
            "contract_version": "v1",
            "workload_classes": [
                {"class_id": "a", "weight": 0.5, "member_workload_ids": ["wa"]},
                {"class_id": "b", "weight": 0.6, "member_workload_ids": ["wb"]}
            ]
        }"#;
        let err = WeightContract::from_json_str(json).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::ContractWeightSum { .. }
        ));
        assert_eq!(err.stable_code(), "FE-BENCH-1009");
    }

    #[test]
    fn contract_validate_rejects_duplicate_membership() {
        let json = r#"{
            "contract_version": "v1",
            "workload_classes": [
                {"class_id": "a", "weight": 0.5, "member_workload_ids": ["shared"]},
                {"class_id": "b", "weight": 0.5, "member_workload_ids": ["shared"]}
            ]
        }"#;
        let err = WeightContract::from_json_str(json).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::DuplicateWorkloadMembership { .. }
        ));
    }

    #[test]
    fn contract_validate_rejects_empty() {
        let json = r#"{"contract_version": "v1", "workload_classes": []}"#;
        let err = WeightContract::from_json_str(json).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::EmptyWeightContract
        ));
    }

    #[test]
    fn contract_validate_rejects_nonpositive_class_weight() {
        let json = r#"{
            "contract_version": "v1",
            "workload_classes": [
                {"class_id": "a", "weight": 0.0, "member_workload_ids": ["wa"]},
                {"class_id": "b", "weight": 1.0, "member_workload_ids": ["wb"]}
            ]
        }"#;
        let err = WeightContract::from_json_str(json).unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::InvalidClassWeight { .. }
        ));
        assert_eq!(err.stable_code(), "FE-BENCH-1008");
    }

    #[test]
    fn contract_parse_failure_maps_to_stable_code() {
        let err = WeightContract::from_json_str("{ not json").unwrap_err();
        assert!(matches!(
            err,
            BenchmarkDenominatorError::WeightContractParse(_)
        ));
        assert_eq!(err.stable_code(), "FE-BENCH-1008");
    }
}
