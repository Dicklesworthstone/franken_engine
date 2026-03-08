//! Opportunity-matrix scoring for Section 10.6 (`bd-js4`).
//!
//! This module provides deterministic optimization-candidate scoring before
//! implementation begins. It combines:
//! - hotspot profile weight from flamegraph artifacts
//! - benchmark-derived pressure signal
//! - VOI-style expected gain per engineering hour
//! - security/risk/complexity penalties
//!
//! Scores are fixed-point millionths (`1_000_000 = 1.0`), enabling stable
//! ranking and threshold gating (`>= 2.0` score).

use std::collections::{BTreeMap, BTreeSet};

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::benchmark_denominator::BenchmarkCase;
use crate::flamegraph_pipeline::{FlamegraphArtifact, FlamegraphKind};

pub const OPPORTUNITY_MATRIX_COMPONENT: &str = "opportunity_matrix";
pub const OPPORTUNITY_MATRIX_SCHEMA_VERSION: &str = "franken-engine.opportunity-matrix.v1";
pub const OPPORTUNITY_SCORE_THRESHOLD_MILLIONTHS: i64 = 2_000_000; // 2.0

const MIN_COMPLEXITY: u32 = 1;
const MIN_RISK_FLOOR_MILLIONTHS: i64 = 1_000; // 0.001
const MIN_EFFORT_HOURS_MILLIONTHS: i64 = 100_000; // 0.1h
const TARGET_SUITE_SPEEDUP_MILLIONTHS: i64 = 3_000_000; // 3.0x

const ERROR_INVALID_REQUEST: &str = "FE-OPPM-1001";
const ERROR_DUPLICATE_OPPORTUNITY_ID: &str = "FE-OPPM-1002";
const ERROR_INVALID_TIMESTAMP: &str = "FE-OPPM-1003";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotspotProfileEntry {
    pub module: String,
    pub function: String,
    pub sample_count: u64,
}

impl HotspotProfileEntry {
    pub fn key(&self) -> String {
        format!("{}::{}", self.module, self.function)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationCandidateInput {
    pub opportunity_id: String,
    pub target_module: String,
    pub target_function: String,
    pub estimated_speedup_millionths: i64,
    pub implementation_complexity: u32,
    pub regression_risk_millionths: i64,
    pub security_clearance_millionths: i64,
    pub engineering_effort_hours_millionths: i64,
    pub hotpath_weight_override_millionths: Option<i64>,
}

impl OptimizationCandidateInput {
    pub fn target_key(&self) -> String {
        format!("{}::{}", self.target_module, self.target_function)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpportunityOutcomeObservation {
    pub opportunity_id: String,
    pub predicted_gain_millionths: i64,
    pub actual_gain_millionths: i64,
    pub completed_at_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpportunityMatrixRequest {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub optimization_run_id: String,
    pub benchmark_pressure_millionths: i64,
    pub hotspots: Vec<HotspotProfileEntry>,
    pub candidates: Vec<OptimizationCandidateInput>,
    pub historical_outcomes: Vec<OpportunityOutcomeObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpportunityStatus {
    Selected,
    RejectedLowScore,
    RejectedSecurityClearance,
    RejectedMissingHotspot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoredOpportunity {
    pub opportunity_id: String,
    pub target_module: String,
    pub target_function: String,
    pub estimated_speedup_millionths: i64,
    pub hotpath_weight_millionths: i64,
    pub benchmark_pressure_millionths: i64,
    pub voi_millionths: i64,
    pub score_millionths: i64,
    pub threshold_met: bool,
    pub status: OpportunityStatus,
    pub rejection_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpportunityHistoryRecord {
    pub opportunity_id: String,
    pub predicted_gain_millionths: i64,
    pub actual_gain_millionths: i64,
    pub signed_error_millionths: i64,
    pub absolute_error_millionths: i64,
    pub completed_at_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpportunityMatrixEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub opportunity_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpportunityMatrixDecision {
    pub schema_version: String,
    pub matrix_id: String,
    pub optimization_run_id: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub score_threshold_millionths: i64,
    pub benchmark_pressure_millionths: i64,
    pub ranked_opportunities: Vec<ScoredOpportunity>,
    pub selected_opportunity_ids: Vec<String>,
    pub historical_tracking: Vec<OpportunityHistoryRecord>,
    pub events: Vec<OpportunityMatrixEvent>,
}

impl OpportunityMatrixDecision {
    pub fn has_selected_opportunities(&self) -> bool {
        !self.selected_opportunity_ids.is_empty()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OpportunityMatrixError {
    #[error("invalid request field `{field}`: {detail}")]
    InvalidRequest { field: String, detail: String },
    #[error("duplicate opportunity_id `{opportunity_id}`")]
    DuplicateOpportunityId { opportunity_id: String },
    #[error("invalid RFC3339 UTC timestamp `{value}`")]
    InvalidTimestamp { value: String },
}

impl OpportunityMatrixError {
    pub fn stable_code(&self) -> &'static str {
        match self {
            Self::InvalidRequest { .. } => ERROR_INVALID_REQUEST,
            Self::DuplicateOpportunityId { .. } => ERROR_DUPLICATE_OPPORTUNITY_ID,
            Self::InvalidTimestamp { .. } => ERROR_INVALID_TIMESTAMP,
        }
    }
}

/// Build hotspot profile entries from stored flamegraph artifacts.
///
/// Aggregation key is `(module, leaf_function)` from folded-stack rows.
pub fn hotspot_profile_from_flamegraphs(
    artifacts: &[FlamegraphArtifact],
) -> Vec<HotspotProfileEntry> {
    let mut aggregate: BTreeMap<(String, String), u64> = BTreeMap::new();

    for artifact in artifacts {
        if !matches!(
            artifact.kind,
            FlamegraphKind::Cpu
                | FlamegraphKind::Allocation
                | FlamegraphKind::DiffCpu
                | FlamegraphKind::DiffAllocation
        ) {
            continue;
        }

        for sample in &artifact.folded_stacks {
            let stack = sample.stack.trim();
            if stack.is_empty() {
                continue;
            }
            let mut parts = stack.split(';').filter(|part| !part.trim().is_empty());
            let module = parts.next().unwrap_or("unknown").trim().to_string();
            let function = stack
                .rsplit(';')
                .next()
                .unwrap_or("unknown")
                .trim()
                .to_string();
            let key = (module, function);
            *aggregate.entry(key).or_insert(0) += sample.sample_count;
        }
    }

    let mut entries = aggregate
        .into_iter()
        .map(|((module, function), sample_count)| HotspotProfileEntry {
            module,
            function,
            sample_count,
        })
        .collect::<Vec<_>>();

    entries.sort_by(|a, b| {
        b.sample_count
            .cmp(&a.sample_count)
            .then_with(|| a.module.cmp(&b.module))
            .then_with(|| a.function.cmp(&b.function))
    });
    entries
}

/// Derive benchmark-pressure multiplier from benchmark denominator inputs.
///
/// Result is in `[1_000_000, 2_000_000]` where `1_000_000` is neutral and
/// larger values indicate higher pressure to prioritize wins.
pub fn benchmark_pressure_from_cases(
    node_cases: &[BenchmarkCase],
    bun_cases: &[BenchmarkCase],
) -> i64 {
    let mut speeds = Vec::new();
    for case in node_cases.iter().chain(bun_cases.iter()) {
        if case.throughput_baseline_tps <= 0.0 {
            continue;
        }
        let speedup = case.throughput_franken_tps / case.throughput_baseline_tps;
        if speedup.is_finite() && speedup > 0.0 {
            speeds.push((speedup * 1_000_000.0).round() as i64);
        }
    }

    if speeds.is_empty() {
        return 1_000_000;
    }

    let observed = speeds.iter().sum::<i64>() / speeds.len() as i64;
    if observed >= TARGET_SUITE_SPEEDUP_MILLIONTHS {
        return 1_000_000;
    }

    let shortfall = TARGET_SUITE_SPEEDUP_MILLIONTHS - observed;
    let pressure = 1_000_000 + (shortfall * 1_000_000 / TARGET_SUITE_SPEEDUP_MILLIONTHS);
    pressure.clamp(1_000_000, 2_000_000)
}

/// Derive candidate skeletons directly from hotspot profile data.
pub fn derive_candidates_from_hotspots(
    hotspots: &[HotspotProfileEntry],
    benchmark_pressure_millionths: i64,
    default_complexity: u32,
    default_regression_risk_millionths: i64,
    default_security_clearance_millionths: i64,
    default_effort_hours_millionths: i64,
    max_candidates: usize,
) -> Vec<OptimizationCandidateInput> {
    let total_samples = hotspots
        .iter()
        .map(|entry| entry.sample_count)
        .sum::<u64>()
        .max(1);
    hotspots
        .iter()
        .take(max_candidates)
        .map(|hotspot| {
            let hotpath_weight =
                ((hotspot.sample_count as i128 * 1_000_000i128) / total_samples as i128) as i64;
            let estimated_speedup =
                1_000_000 + ((benchmark_pressure_millionths * hotpath_weight) / 1_000_000);
            let opportunity_id = format!(
                "opp:{}:{}",
                sanitize_token(&hotspot.module),
                sanitize_token(&hotspot.function)
            );
            OptimizationCandidateInput {
                opportunity_id,
                target_module: hotspot.module.clone(),
                target_function: hotspot.function.clone(),
                estimated_speedup_millionths: estimated_speedup,
                implementation_complexity: default_complexity,
                regression_risk_millionths: default_regression_risk_millionths,
                security_clearance_millionths: default_security_clearance_millionths,
                engineering_effort_hours_millionths: default_effort_hours_millionths,
                hotpath_weight_override_millionths: Some(hotpath_weight),
            }
        })
        .collect()
}

/// Run deterministic opportunity-matrix scoring.
pub fn run_opportunity_matrix_scoring(
    request: &OpportunityMatrixRequest,
) -> OpportunityMatrixDecision {
    let matrix_id = build_matrix_id(request);
    let mut events = vec![make_event(
        request,
        "opportunity_matrix_started",
        "pass",
        None,
        None,
    )];

    match run_impl(request, &mut events) {
        Ok(computation) => {
            let ranked_opportunities = computation.ranked_opportunities;
            let selected_opportunity_ids = computation.selected_opportunity_ids;
            let historical_tracking = computation.historical_tracking;
            let outcome = if selected_opportunity_ids.is_empty() {
                "deny"
            } else {
                "allow"
            };
            events.push(make_event(
                request,
                "opportunity_matrix_completed",
                outcome,
                None,
                None,
            ));
            OpportunityMatrixDecision {
                schema_version: OPPORTUNITY_MATRIX_SCHEMA_VERSION.to_string(),
                matrix_id,
                optimization_run_id: request.optimization_run_id.clone(),
                outcome: outcome.to_string(),
                error_code: None,
                score_threshold_millionths: OPPORTUNITY_SCORE_THRESHOLD_MILLIONTHS,
                benchmark_pressure_millionths: request.benchmark_pressure_millionths,
                ranked_opportunities,
                selected_opportunity_ids,
                historical_tracking,
                events,
            }
        }
        Err(error) => {
            let error_code = error.stable_code().to_string();
            events.push(make_event(
                request,
                "opportunity_matrix_completed",
                "fail",
                Some(error_code.clone()),
                None,
            ));
            OpportunityMatrixDecision {
                schema_version: OPPORTUNITY_MATRIX_SCHEMA_VERSION.to_string(),
                matrix_id,
                optimization_run_id: request.optimization_run_id.clone(),
                outcome: "fail".to_string(),
                error_code: Some(error_code),
                score_threshold_millionths: OPPORTUNITY_SCORE_THRESHOLD_MILLIONTHS,
                benchmark_pressure_millionths: request.benchmark_pressure_millionths,
                ranked_opportunities: Vec::new(),
                selected_opportunity_ids: Vec::new(),
                historical_tracking: Vec::new(),
                events,
            }
        }
    }
}

fn run_impl(
    request: &OpportunityMatrixRequest,
    events: &mut Vec<OpportunityMatrixEvent>,
) -> Result<OpportunityMatrixComputation, OpportunityMatrixError> {
    validate_request(request)?;
    let hotspot_weights = hotspot_weight_map(&request.hotspots);

    let mut ranked = request
        .candidates
        .iter()
        .map(|candidate| {
            let mut rejection_reason = None;
            let target_key = candidate.target_key();
            let hotpath_weight = candidate
                .hotpath_weight_override_millionths
                .unwrap_or_else(|| hotspot_weights.get(&target_key).copied().unwrap_or(0))
                .clamp(0, 1_000_000);

            let status = if candidate.security_clearance_millionths <= 0 {
                rejection_reason = Some("SECURITY_CLEARANCE_ZERO".to_string());
                OpportunityStatus::RejectedSecurityClearance
            } else if hotpath_weight <= 0 {
                rejection_reason = Some("MISSING_HOTSPOT_WEIGHT".to_string());
                OpportunityStatus::RejectedMissingHotspot
            } else {
                OpportunityStatus::RejectedLowScore
            };

            let score_detail = compute_score_millionths(
                candidate,
                hotpath_weight,
                request.benchmark_pressure_millionths,
            );
            let threshold_met =
                score_detail.score_millionths >= OPPORTUNITY_SCORE_THRESHOLD_MILLIONTHS;
            let final_status =
                if matches!(status, OpportunityStatus::RejectedLowScore) && threshold_met {
                    OpportunityStatus::Selected
                } else {
                    status
                };
            if matches!(final_status, OpportunityStatus::RejectedLowScore) {
                rejection_reason = Some("SCORE_BELOW_THRESHOLD".to_string());
            }

            events.push(make_event(
                request,
                "opportunity_scored",
                if matches!(final_status, OpportunityStatus::Selected) {
                    "allow"
                } else {
                    "deny"
                },
                None,
                Some(candidate.opportunity_id.clone()),
            ));

            ScoredOpportunity {
                opportunity_id: candidate.opportunity_id.clone(),
                target_module: candidate.target_module.clone(),
                target_function: candidate.target_function.clone(),
                estimated_speedup_millionths: candidate.estimated_speedup_millionths.max(0),
                hotpath_weight_millionths: hotpath_weight,
                benchmark_pressure_millionths: request.benchmark_pressure_millionths,
                voi_millionths: score_detail.voi_millionths,
                score_millionths: score_detail.score_millionths,
                threshold_met,
                status: final_status,
                rejection_reason,
            }
        })
        .collect::<Vec<_>>();

    ranked.sort_by(|a, b| {
        b.score_millionths
            .cmp(&a.score_millionths)
            .then_with(|| a.opportunity_id.cmp(&b.opportunity_id))
    });

    let selected_ids = ranked
        .iter()
        .filter(|candidate| matches!(candidate.status, OpportunityStatus::Selected))
        .map(|candidate| candidate.opportunity_id.clone())
        .collect::<Vec<_>>();

    let mut historical = request
        .historical_outcomes
        .iter()
        .map(|entry| OpportunityHistoryRecord {
            opportunity_id: entry.opportunity_id.clone(),
            predicted_gain_millionths: entry.predicted_gain_millionths,
            actual_gain_millionths: entry.actual_gain_millionths,
            signed_error_millionths: entry.actual_gain_millionths - entry.predicted_gain_millionths,
            absolute_error_millionths: (entry.actual_gain_millionths
                - entry.predicted_gain_millionths)
                .abs(),
            completed_at_utc: entry.completed_at_utc.clone(),
        })
        .collect::<Vec<_>>();

    historical.sort_by(|a, b| {
        a.completed_at_utc
            .cmp(&b.completed_at_utc)
            .then_with(|| a.opportunity_id.cmp(&b.opportunity_id))
    });

    Ok(OpportunityMatrixComputation {
        ranked_opportunities: ranked,
        selected_opportunity_ids: selected_ids,
        historical_tracking: historical,
    })
}

fn validate_request(request: &OpportunityMatrixRequest) -> Result<(), OpportunityMatrixError> {
    if request.trace_id.trim().is_empty() {
        return Err(OpportunityMatrixError::InvalidRequest {
            field: "trace_id".to_string(),
            detail: "must not be empty".to_string(),
        });
    }
    if request.decision_id.trim().is_empty() {
        return Err(OpportunityMatrixError::InvalidRequest {
            field: "decision_id".to_string(),
            detail: "must not be empty".to_string(),
        });
    }
    if request.policy_id.trim().is_empty() {
        return Err(OpportunityMatrixError::InvalidRequest {
            field: "policy_id".to_string(),
            detail: "must not be empty".to_string(),
        });
    }
    if request.optimization_run_id.trim().is_empty() {
        return Err(OpportunityMatrixError::InvalidRequest {
            field: "optimization_run_id".to_string(),
            detail: "must not be empty".to_string(),
        });
    }
    if request.candidates.is_empty() {
        return Err(OpportunityMatrixError::InvalidRequest {
            field: "candidates".to_string(),
            detail: "must include at least one candidate".to_string(),
        });
    }
    if request.benchmark_pressure_millionths <= 0 {
        return Err(OpportunityMatrixError::InvalidRequest {
            field: "benchmark_pressure_millionths".to_string(),
            detail: "must be positive".to_string(),
        });
    }

    let mut seen = BTreeSet::new();
    for candidate in &request.candidates {
        if candidate.opportunity_id.trim().is_empty() {
            return Err(OpportunityMatrixError::InvalidRequest {
                field: "opportunity_id".to_string(),
                detail: "must not be empty".to_string(),
            });
        }
        if !seen.insert(candidate.opportunity_id.clone()) {
            return Err(OpportunityMatrixError::DuplicateOpportunityId {
                opportunity_id: candidate.opportunity_id.clone(),
            });
        }
    }

    for historical in &request.historical_outcomes {
        if DateTime::parse_from_rfc3339(&historical.completed_at_utc).is_err() {
            return Err(OpportunityMatrixError::InvalidTimestamp {
                value: historical.completed_at_utc.clone(),
            });
        }
    }

    Ok(())
}

fn hotspot_weight_map(hotspots: &[HotspotProfileEntry]) -> BTreeMap<String, i64> {
    let total_samples = hotspots
        .iter()
        .map(|entry| entry.sample_count)
        .sum::<u64>()
        .max(1);
    let mut map = BTreeMap::new();
    for hotspot in hotspots {
        let weight =
            ((hotspot.sample_count as i128 * 1_000_000i128) / total_samples as i128) as i64;
        map.insert(hotspot.key(), weight.clamp(0, 1_000_000));
    }
    map
}

#[derive(Debug, Clone, Copy)]
struct ScoreDetail {
    voi_millionths: i64,
    score_millionths: i64,
}

#[derive(Debug)]
struct OpportunityMatrixComputation {
    ranked_opportunities: Vec<ScoredOpportunity>,
    selected_opportunity_ids: Vec<String>,
    historical_tracking: Vec<OpportunityHistoryRecord>,
}

fn compute_score_millionths(
    candidate: &OptimizationCandidateInput,
    hotpath_weight_millionths: i64,
    benchmark_pressure_millionths: i64,
) -> ScoreDetail {
    let complexity = candidate.implementation_complexity.max(MIN_COMPLEXITY) as i128;
    let risk = candidate
        .regression_risk_millionths
        .clamp(MIN_RISK_FLOOR_MILLIONTHS, 1_000_000) as i128;
    let effort = candidate
        .engineering_effort_hours_millionths
        .max(MIN_EFFORT_HOURS_MILLIONTHS) as i128;
    let security = candidate.security_clearance_millionths.clamp(0, 1_000_000) as i128;
    let estimated_speedup = candidate.estimated_speedup_millionths.max(0) as i128;
    let benchmark_pressure = benchmark_pressure_millionths.max(1) as i128;
    let hotpath_weight = hotpath_weight_millionths.max(0) as i128;

    // Benchmark-adjusted speedup multiplier.
    let adjusted_speedup = (estimated_speedup * benchmark_pressure) / 1_000_000;
    // Expected weighted gain.
    let base_gain = (adjusted_speedup * hotpath_weight) / 1_000_000;
    // VOI: expected gain per engineering hour.
    let voi = (base_gain * 1_000_000) / effort;
    // Penalize security ambiguity and regression risk.
    let sec_adjusted = (voi * security) / 1_000_000;
    let score = (sec_adjusted * 1_000_000) / (risk * complexity);

    ScoreDetail {
        voi_millionths: clamp_i128_to_i64(voi),
        score_millionths: clamp_i128_to_i64(score),
    }
}

fn build_matrix_id(request: &OpportunityMatrixRequest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(request.trace_id.as_bytes());
    hasher.update(request.decision_id.as_bytes());
    hasher.update(request.policy_id.as_bytes());
    hasher.update(request.optimization_run_id.as_bytes());
    hasher.update(request.benchmark_pressure_millionths.to_le_bytes());
    for hotspot in &request.hotspots {
        hasher.update(hotspot.module.as_bytes());
        hasher.update(hotspot.function.as_bytes());
        hasher.update(hotspot.sample_count.to_le_bytes());
    }
    for candidate in &request.candidates {
        hasher.update(candidate.opportunity_id.as_bytes());
        hasher.update(candidate.target_module.as_bytes());
        hasher.update(candidate.target_function.as_bytes());
        hasher.update(candidate.estimated_speedup_millionths.to_le_bytes());
        hasher.update(candidate.implementation_complexity.to_le_bytes());
        hasher.update(candidate.regression_risk_millionths.to_le_bytes());
        hasher.update(candidate.security_clearance_millionths.to_le_bytes());
        hasher.update(candidate.engineering_effort_hours_millionths.to_le_bytes());
    }
    let digest = hasher.finalize();
    format!("opm-{digest:x}")
}

fn make_event(
    request: &OpportunityMatrixRequest,
    event: &str,
    outcome: &str,
    error_code: Option<String>,
    opportunity_id: Option<String>,
) -> OpportunityMatrixEvent {
    OpportunityMatrixEvent {
        trace_id: request.trace_id.clone(),
        decision_id: request.decision_id.clone(),
        policy_id: request.policy_id.clone(),
        component: OPPORTUNITY_MATRIX_COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        error_code,
        opportunity_id,
    }
}

fn sanitize_token(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
}

fn clamp_i128_to_i64(value: i128) -> i64 {
    value.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id: &str, module: &str, function: &str) -> OptimizationCandidateInput {
        OptimizationCandidateInput {
            opportunity_id: id.to_string(),
            target_module: module.to_string(),
            target_function: function.to_string(),
            estimated_speedup_millionths: 2_500_000,
            implementation_complexity: 2,
            regression_risk_millionths: 250_000,
            security_clearance_millionths: 1_000_000,
            engineering_effort_hours_millionths: 1_000_000,
            hotpath_weight_override_millionths: None,
        }
    }

    fn base_request() -> OpportunityMatrixRequest {
        OpportunityMatrixRequest {
            trace_id: "trace-opp".to_string(),
            decision_id: "decision-opp".to_string(),
            policy_id: "policy-opp".to_string(),
            optimization_run_id: "run-001".to_string(),
            benchmark_pressure_millionths: 1_250_000,
            hotspots: vec![
                HotspotProfileEntry {
                    module: "vm".to_string(),
                    function: "dispatch".to_string(),
                    sample_count: 90,
                },
                HotspotProfileEntry {
                    module: "vm".to_string(),
                    function: "gc_tick".to_string(),
                    sample_count: 10,
                },
            ],
            candidates: vec![
                candidate("opp-vm-dispatch", "vm", "dispatch"),
                candidate("opp-vm-gc", "vm", "gc_tick"),
            ],
            historical_outcomes: vec![OpportunityOutcomeObservation {
                opportunity_id: "opp-vm-dispatch".to_string(),
                predicted_gain_millionths: 400_000,
                actual_gain_millionths: 350_000,
                completed_at_utc: "2026-02-22T12:30:00Z".to_string(),
            }],
        }
    }

    #[test]
    fn deterministic_scoring_and_stable_ranking() {
        let request = base_request();
        let decision_a = run_opportunity_matrix_scoring(&request);
        let decision_b = run_opportunity_matrix_scoring(&request);
        assert_eq!(
            decision_a.ranked_opportunities,
            decision_b.ranked_opportunities
        );
        assert_eq!(
            decision_a.selected_opportunity_ids,
            decision_b.selected_opportunity_ids
        );
        assert!(decision_a.has_selected_opportunities());
        assert_eq!(
            decision_a.ranked_opportunities[0].opportunity_id,
            "opp-vm-dispatch"
        );
    }

    #[test]
    fn threshold_filter_rejects_low_score_candidates() {
        let mut request = base_request();
        request.candidates[0].estimated_speedup_millionths = 1_050_000;
        request.candidates[0].engineering_effort_hours_millionths = 20_000_000;
        request.candidates[0].regression_risk_millionths = 900_000;
        request.candidates[0].implementation_complexity = 5;
        request.candidates[1] = request.candidates[0].clone();
        request.candidates[1].opportunity_id = "opp-vm-gc".to_string();
        request.candidates[1].target_function = "gc_tick".to_string();

        let decision = run_opportunity_matrix_scoring(&request);
        assert_eq!(decision.outcome, "deny");
        assert!(decision.selected_opportunity_ids.is_empty());
        assert!(
            decision
                .ranked_opportunities
                .iter()
                .all(|candidate| !candidate.threshold_met)
        );
    }

    #[test]
    fn security_clearance_zero_is_rejected() {
        let mut request = base_request();
        request.candidates[0].security_clearance_millionths = 0;
        let decision = run_opportunity_matrix_scoring(&request);
        let candidate = decision
            .ranked_opportunities
            .iter()
            .find(|candidate| candidate.opportunity_id == "opp-vm-dispatch")
            .expect("candidate should exist");
        assert_eq!(
            candidate.status,
            OpportunityStatus::RejectedSecurityClearance
        );
        assert!(!candidate.threshold_met);
    }

    #[test]
    fn zero_denominator_inputs_are_floored_without_panic() {
        let mut request = base_request();
        request.candidates[0].implementation_complexity = 0;
        request.candidates[0].regression_risk_millionths = 0;
        request.candidates[0].engineering_effort_hours_millionths = 0;
        let decision = run_opportunity_matrix_scoring(&request);
        assert_eq!(decision.outcome, "allow");
        assert!(
            decision
                .ranked_opportunities
                .iter()
                .all(|entry| entry.score_millionths >= 0)
        );
    }

    #[test]
    fn benchmark_pressure_increases_when_suite_under_target() {
        let fast = BenchmarkCase {
            workload_id: "w1".to_string(),
            throughput_franken_tps: 400.0,
            throughput_baseline_tps: 100.0,
            weight: None,
            behavior_equivalent: true,
            latency_envelope_ok: true,
            error_envelope_ok: true,
        };
        let slow = BenchmarkCase {
            workload_id: "w2".to_string(),
            throughput_franken_tps: 150.0,
            throughput_baseline_tps: 100.0,
            weight: None,
            behavior_equivalent: true,
            latency_envelope_ok: true,
            error_envelope_ok: true,
        };
        let pressure = benchmark_pressure_from_cases(&[slow], &[fast]);
        assert!(pressure > 1_000_000);
        assert!(pressure <= 2_000_000);
    }

    #[test]
    fn derive_candidates_from_hotspots_emits_stable_ids() {
        let hotspots = [
            HotspotProfileEntry {
                module: "vm-core".to_string(),
                function: "dispatch.loop".to_string(),
                sample_count: 80,
            },
            HotspotProfileEntry {
                module: "gc".to_string(),
                function: "scan".to_string(),
                sample_count: 20,
            },
        ];
        let derived = derive_candidates_from_hotspots(
            &hotspots, 1_300_000, 2, 200_000, 1_000_000, 2_000_000, 2,
        );
        assert_eq!(derived.len(), 2);
        assert_eq!(derived[0].opportunity_id, "opp:vm-core:dispatch_loop");
        assert_eq!(derived[1].opportunity_id, "opp:gc:scan");
    }

    // ── OpportunityStatus serde ──────────────────────────────────────

    #[test]
    fn opportunity_status_serde_roundtrip() {
        for status in [
            OpportunityStatus::Selected,
            OpportunityStatus::RejectedLowScore,
            OpportunityStatus::RejectedSecurityClearance,
            OpportunityStatus::RejectedMissingHotspot,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: OpportunityStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn opportunity_status_snake_case_rename() {
        let json = serde_json::to_string(&OpportunityStatus::RejectedLowScore).unwrap();
        assert!(json.contains("rejected_low_score"));
        let json2 = serde_json::to_string(&OpportunityStatus::RejectedSecurityClearance).unwrap();
        assert!(json2.contains("rejected_security_clearance"));
    }

    // ── OpportunityMatrixError ───────────────────────────────────────

    #[test]
    fn error_stable_codes() {
        let e1 = OpportunityMatrixError::InvalidRequest {
            field: "f".into(),
            detail: "d".into(),
        };
        assert_eq!(e1.stable_code(), "FE-OPPM-1001");
        let e2 = OpportunityMatrixError::DuplicateOpportunityId {
            opportunity_id: "x".into(),
        };
        assert_eq!(e2.stable_code(), "FE-OPPM-1002");
        let e3 = OpportunityMatrixError::InvalidTimestamp {
            value: "bad".into(),
        };
        assert_eq!(e3.stable_code(), "FE-OPPM-1003");
    }

    #[test]
    fn error_display_messages() {
        let e1 = OpportunityMatrixError::InvalidRequest {
            field: "trace_id".into(),
            detail: "must not be empty".into(),
        };
        assert!(e1.to_string().contains("trace_id"));
        assert!(e1.to_string().contains("must not be empty"));
        let e2 = OpportunityMatrixError::DuplicateOpportunityId {
            opportunity_id: "opp-1".into(),
        };
        assert!(e2.to_string().contains("opp-1"));
        let e3 = OpportunityMatrixError::InvalidTimestamp {
            value: "not-a-date".into(),
        };
        assert!(e3.to_string().contains("not-a-date"));
    }

    // ── Validation errors ────────────────────────────────────────────

    #[test]
    fn validation_empty_trace_id() {
        let mut req = base_request();
        req.trace_id = "  ".into();
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.outcome, "fail");
        assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1001"));
    }

    #[test]
    fn validation_empty_decision_id() {
        let mut req = base_request();
        req.decision_id = "".into();
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.outcome, "fail");
        assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1001"));
    }

    #[test]
    fn validation_empty_policy_id() {
        let mut req = base_request();
        req.policy_id = "".into();
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.outcome, "fail");
        assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1001"));
    }

    #[test]
    fn validation_empty_optimization_run_id() {
        let mut req = base_request();
        req.optimization_run_id = "".into();
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.outcome, "fail");
        assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1001"));
    }

    #[test]
    fn validation_empty_candidates() {
        let mut req = base_request();
        req.candidates.clear();
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.outcome, "fail");
        assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1001"));
    }

    #[test]
    fn validation_non_positive_benchmark_pressure() {
        let mut req = base_request();
        req.benchmark_pressure_millionths = 0;
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.outcome, "fail");
        assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1001"));
    }

    #[test]
    fn validation_empty_opportunity_id() {
        let mut req = base_request();
        req.candidates[0].opportunity_id = "  ".into();
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.outcome, "fail");
        assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1001"));
    }

    #[test]
    fn validation_duplicate_opportunity_id() {
        let mut req = base_request();
        req.candidates[1].opportunity_id = req.candidates[0].opportunity_id.clone();
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.outcome, "fail");
        assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1002"));
    }

    #[test]
    fn validation_invalid_timestamp() {
        let mut req = base_request();
        req.historical_outcomes[0].completed_at_utc = "not-a-date".into();
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.outcome, "fail");
        assert_eq!(d.error_code.as_deref(), Some("FE-OPPM-1003"));
    }

    // ── hotspot_profile_from_flamegraphs ─────────────────────────────

    fn test_flamegraph(kind: FlamegraphKind, stacks: Vec<(&str, u64)>) -> FlamegraphArtifact {
        use crate::flamegraph_pipeline::{FlamegraphEvidenceLink, FlamegraphMetadata};
        FlamegraphArtifact {
            schema_version: "v1".into(),
            artifact_id: "art-1".into(),
            kind,
            metadata: FlamegraphMetadata {
                benchmark_run_id: "br-1".into(),
                baseline_benchmark_run_id: None,
                workload_id: "w1".into(),
                benchmark_profile: "profile".into(),
                config_fingerprint: "fp".into(),
                git_commit: "abc123".into(),
                generated_at_utc: "2026-01-01T00:00:00Z".into(),
            },
            evidence_link: FlamegraphEvidenceLink {
                trace_id: "t".into(),
                decision_id: "d".into(),
                policy_id: "p".into(),
                benchmark_run_id: "br-1".into(),
                optimization_decision_id: "od".into(),
                evidence_node_id: "en".into(),
            },
            folded_stacks: stacks
                .into_iter()
                .map(
                    |(stack, count)| crate::flamegraph_pipeline::FoldedStackSample {
                        stack: stack.to_string(),
                        sample_count: count,
                    },
                )
                .collect(),
            folded_stacks_text: String::new(),
            svg: String::new(),
            total_samples: 0,
            diff_from_artifact_id: None,
            diff_entries: Vec::new(),
            warnings: Vec::new(),
            storage_integration_point: String::new(),
        }
    }

    #[test]
    fn hotspot_profile_from_cpu_flamegraph() {
        let fg = test_flamegraph(
            FlamegraphKind::Cpu,
            vec![("vm;dispatch", 80), ("vm;gc_tick", 20)],
        );
        let profile = hotspot_profile_from_flamegraphs(&[fg]);
        assert_eq!(profile.len(), 2);
        assert_eq!(profile[0].function, "dispatch");
        assert_eq!(profile[0].sample_count, 80);
        assert_eq!(profile[1].function, "gc_tick");
        assert_eq!(profile[1].sample_count, 20);
    }

    #[test]
    fn hotspot_profile_aggregates_across_artifacts() {
        let fg1 = test_flamegraph(FlamegraphKind::Cpu, vec![("vm;dispatch", 50)]);
        let fg2 = test_flamegraph(
            FlamegraphKind::Allocation,
            vec![("vm;dispatch", 30), ("gc;collect", 20)],
        );
        let profile = hotspot_profile_from_flamegraphs(&[fg1, fg2]);
        let dispatch = profile.iter().find(|e| e.function == "dispatch").unwrap();
        assert_eq!(dispatch.sample_count, 80);
        assert_eq!(profile.len(), 2);
    }

    #[test]
    fn hotspot_profile_empty_stacks_skipped() {
        let fg = test_flamegraph(FlamegraphKind::Cpu, vec![("  ", 100), ("vm;run", 50)]);
        let profile = hotspot_profile_from_flamegraphs(&[fg]);
        assert_eq!(profile.len(), 1);
        assert_eq!(profile[0].function, "run");
    }

    #[test]
    fn hotspot_profile_sorted_by_sample_count_desc() {
        let fg = test_flamegraph(
            FlamegraphKind::DiffCpu,
            vec![("a;low", 10), ("b;high", 90), ("c;mid", 50)],
        );
        let profile = hotspot_profile_from_flamegraphs(&[fg]);
        assert_eq!(profile[0].sample_count, 90);
        assert_eq!(profile[1].sample_count, 50);
        assert_eq!(profile[2].sample_count, 10);
    }

    #[test]
    fn hotspot_profile_empty_artifacts() {
        let profile = hotspot_profile_from_flamegraphs(&[]);
        assert!(profile.is_empty());
    }

    // ── benchmark_pressure_from_cases ────────────────────────────────

    #[test]
    fn benchmark_pressure_neutral_when_above_target() {
        let fast = BenchmarkCase {
            workload_id: "w1".into(),
            throughput_franken_tps: 400.0,
            throughput_baseline_tps: 100.0,
            weight: None,
            behavior_equivalent: true,
            latency_envelope_ok: true,
            error_envelope_ok: true,
        };
        let pressure = benchmark_pressure_from_cases(&[fast], &[]);
        assert_eq!(pressure, 1_000_000);
    }

    #[test]
    fn benchmark_pressure_empty_cases_returns_neutral() {
        assert_eq!(benchmark_pressure_from_cases(&[], &[]), 1_000_000);
    }

    #[test]
    fn benchmark_pressure_zero_baseline_skipped() {
        let bad = BenchmarkCase {
            workload_id: "w1".into(),
            throughput_franken_tps: 100.0,
            throughput_baseline_tps: 0.0,
            weight: None,
            behavior_equivalent: true,
            latency_envelope_ok: true,
            error_envelope_ok: true,
        };
        assert_eq!(benchmark_pressure_from_cases(&[bad], &[]), 1_000_000);
    }

    #[test]
    fn benchmark_pressure_clamped_to_2x() {
        let very_slow = BenchmarkCase {
            workload_id: "w1".into(),
            throughput_franken_tps: 100.0,
            throughput_baseline_tps: 100.0,
            weight: None,
            behavior_equivalent: true,
            latency_envelope_ok: true,
            error_envelope_ok: true,
        };
        let pressure = benchmark_pressure_from_cases(&[very_slow], &[]);
        assert!(pressure > 1_000_000);
        assert!(pressure <= 2_000_000);
    }

    // ── derive_candidates_from_hotspots ──────────────────────────────

    #[test]
    fn derive_candidates_max_candidates_limit() {
        let hotspots = (0..10)
            .map(|i| HotspotProfileEntry {
                module: format!("mod{i}"),
                function: "f".into(),
                sample_count: 100 - i as u64,
            })
            .collect::<Vec<_>>();
        let derived = derive_candidates_from_hotspots(
            &hotspots, 1_000_000, 1, 100_000, 1_000_000, 1_000_000, 3,
        );
        assert_eq!(derived.len(), 3);
    }

    #[test]
    fn derive_candidates_hotpath_weight_sums_correctly() {
        let hotspots = [HotspotProfileEntry {
            module: "a".into(),
            function: "f".into(),
            sample_count: 100,
        }];
        let derived = derive_candidates_from_hotspots(
            &hotspots, 1_000_000, 1, 100_000, 1_000_000, 1_000_000, 10,
        );
        assert_eq!(derived.len(), 1);
        // Sole hotspot gets weight 1_000_000 (100%)
        assert_eq!(
            derived[0].hotpath_weight_override_millionths,
            Some(1_000_000)
        );
    }

    // ── Missing hotspot rejection ────────────────────────────────────

    #[test]
    fn missing_hotspot_weight_rejects_candidate() {
        let mut req = base_request();
        // Clear hotspots so no weight can be derived
        req.hotspots.clear();
        // Also clear override so weight falls to 0
        req.candidates[0].hotpath_weight_override_millionths = None;
        req.candidates[1].hotpath_weight_override_millionths = None;
        let d = run_opportunity_matrix_scoring(&req);
        for opp in &d.ranked_opportunities {
            assert_eq!(opp.status, OpportunityStatus::RejectedMissingHotspot);
        }
        assert!(d.selected_opportunity_ids.is_empty());
    }

    // ── Historical tracking ──────────────────────────────────────────

    #[test]
    fn historical_tracking_computes_errors() {
        let req = base_request();
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.historical_tracking.len(), 1);
        let h = &d.historical_tracking[0];
        assert_eq!(h.predicted_gain_millionths, 400_000);
        assert_eq!(h.actual_gain_millionths, 350_000);
        assert_eq!(h.signed_error_millionths, -50_000);
        assert_eq!(h.absolute_error_millionths, 50_000);
    }

    #[test]
    fn historical_tracking_sorted_by_timestamp() {
        let mut req = base_request();
        req.historical_outcomes.push(OpportunityOutcomeObservation {
            opportunity_id: "opp-2".into(),
            predicted_gain_millionths: 100_000,
            actual_gain_millionths: 200_000,
            completed_at_utc: "2026-01-01T00:00:00Z".into(),
        });
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.historical_tracking.len(), 2);
        assert!(
            d.historical_tracking[0].completed_at_utc <= d.historical_tracking[1].completed_at_utc
        );
    }

    // ── Events ───────────────────────────────────────────────────────

    #[test]
    fn events_include_start_scoring_and_completion() {
        let req = base_request();
        let d = run_opportunity_matrix_scoring(&req);
        let event_names: Vec<&str> = d.events.iter().map(|e| e.event.as_str()).collect();
        assert!(event_names.contains(&"opportunity_matrix_started"));
        assert!(event_names.contains(&"opportunity_matrix_completed"));
    }

    #[test]
    fn events_include_per_candidate_scoring() {
        let req = base_request();
        let d = run_opportunity_matrix_scoring(&req);
        let scored_events = d
            .events
            .iter()
            .filter(|e| e.event == "opportunity_scored")
            .count();
        assert_eq!(scored_events, req.candidates.len());
    }

    #[test]
    fn events_carry_request_ids() {
        let req = base_request();
        let d = run_opportunity_matrix_scoring(&req);
        for event in &d.events {
            assert_eq!(event.trace_id, req.trace_id);
            assert_eq!(event.decision_id, req.decision_id);
            assert_eq!(event.policy_id, req.policy_id);
            assert_eq!(event.component, OPPORTUNITY_MATRIX_COMPONENT);
        }
    }

    // ── Decision metadata ────────────────────────────────────────────

    #[test]
    fn decision_schema_version() {
        let d = run_opportunity_matrix_scoring(&base_request());
        assert_eq!(d.schema_version, OPPORTUNITY_MATRIX_SCHEMA_VERSION);
    }

    #[test]
    fn decision_matrix_id_deterministic() {
        let req = base_request();
        let a = run_opportunity_matrix_scoring(&req);
        let b = run_opportunity_matrix_scoring(&req);
        assert_eq!(a.matrix_id, b.matrix_id);
        assert!(a.matrix_id.starts_with("opm-"));
    }

    #[test]
    fn decision_matrix_id_changes_with_input() {
        let req = base_request();
        let a = run_opportunity_matrix_scoring(&req);
        let mut req2 = base_request();
        req2.trace_id = "different-trace".into();
        let b = run_opportunity_matrix_scoring(&req2);
        assert_ne!(a.matrix_id, b.matrix_id);
    }

    #[test]
    fn decision_has_selected_opportunities_false_on_deny() {
        let mut req = base_request();
        req.candidates[0].security_clearance_millionths = 0;
        req.candidates[1].security_clearance_millionths = 0;
        let d = run_opportunity_matrix_scoring(&req);
        assert!(!d.has_selected_opportunities());
    }

    // ── Score computation edge cases ─────────────────────────────────

    #[test]
    fn negative_speedup_clamped_to_zero() {
        let mut req = base_request();
        req.candidates[0].estimated_speedup_millionths = -500_000;
        let d = run_opportunity_matrix_scoring(&req);
        let opp = d
            .ranked_opportunities
            .iter()
            .find(|o| o.opportunity_id == "opp-vm-dispatch")
            .unwrap();
        assert_eq!(opp.estimated_speedup_millionths, 0);
    }

    #[test]
    fn hotpath_weight_override_used_when_present() {
        let mut req = base_request();
        req.candidates[0].hotpath_weight_override_millionths = Some(500_000);
        let d = run_opportunity_matrix_scoring(&req);
        let opp = d
            .ranked_opportunities
            .iter()
            .find(|o| o.opportunity_id == "opp-vm-dispatch")
            .unwrap();
        assert_eq!(opp.hotpath_weight_millionths, 500_000);
    }

    // ── Serde roundtrips ─────────────────────────────────────────────

    #[test]
    fn scored_opportunity_serde_roundtrip() {
        let req = base_request();
        let d = run_opportunity_matrix_scoring(&req);
        for opp in &d.ranked_opportunities {
            let json = serde_json::to_string(opp).unwrap();
            let back: ScoredOpportunity = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, opp);
        }
    }

    #[test]
    fn opportunity_history_record_serde_roundtrip() {
        let req = base_request();
        let d = run_opportunity_matrix_scoring(&req);
        for h in &d.historical_tracking {
            let json = serde_json::to_string(h).unwrap();
            let back: OpportunityHistoryRecord = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, h);
        }
    }

    #[test]
    fn decision_serde_roundtrip() {
        let d = run_opportunity_matrix_scoring(&base_request());
        let json = serde_json::to_string(&d).unwrap();
        let back: OpportunityMatrixDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back.matrix_id, d.matrix_id);
        assert_eq!(back.ranked_opportunities, d.ranked_opportunities);
        assert_eq!(back.selected_opportunity_ids, d.selected_opportunity_ids);
    }

    #[test]
    fn event_serde_roundtrip() {
        let req = base_request();
        let d = run_opportunity_matrix_scoring(&req);
        for event in &d.events {
            let json = serde_json::to_string(event).unwrap();
            let back: OpportunityMatrixEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, event);
        }
    }

    // ── Helper functions ─────────────────────────────────────────────

    #[test]
    fn hotspot_profile_entry_key_format() {
        let entry = HotspotProfileEntry {
            module: "vm".into(),
            function: "dispatch".into(),
            sample_count: 100,
        };
        assert_eq!(entry.key(), "vm::dispatch");
    }

    #[test]
    fn sanitize_token_replaces_special_chars() {
        assert_eq!(sanitize_token("hello.world"), "hello_world");
        assert_eq!(sanitize_token("vm-core_1"), "vm-core_1");
        assert_eq!(sanitize_token("a b/c"), "a_b_c");
    }

    #[test]
    fn clamp_i128_handles_overflow() {
        assert_eq!(clamp_i128_to_i64(i128::MAX), i64::MAX);
        assert_eq!(clamp_i128_to_i64(i128::MIN), i64::MIN);
        assert_eq!(clamp_i128_to_i64(42), 42);
    }

    // ── Constants ────────────────────────────────────────────────────

    #[test]
    fn score_threshold_is_2x() {
        assert_eq!(OPPORTUNITY_SCORE_THRESHOLD_MILLIONTHS, 2_000_000);
    }

    // ── Ranked output ordering ───────────────────────────────────────

    #[test]
    fn ranked_opportunities_sorted_by_score_desc() {
        let req = base_request();
        let d = run_opportunity_matrix_scoring(&req);
        for window in d.ranked_opportunities.windows(2) {
            assert!(window[0].score_millionths >= window[1].score_millionths);
        }
    }

    // ── Failure decision structure ───────────────────────────────────

    #[test]
    fn failure_decision_has_empty_collections() {
        let mut req = base_request();
        req.trace_id = "".into();
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.outcome, "fail");
        assert!(d.ranked_opportunities.is_empty());
        assert!(d.selected_opportunity_ids.is_empty());
        assert!(d.historical_tracking.is_empty());
        assert!(d.error_code.is_some());
    }

    #[test]
    fn failure_decision_still_has_events() {
        let mut req = base_request();
        req.policy_id = "".into();
        let d = run_opportunity_matrix_scoring(&req);
        assert!(!d.events.is_empty());
        let last = d.events.last().unwrap();
        assert_eq!(last.outcome, "fail");
        assert!(last.error_code.is_some());
    }

    // ── Negative benchmark pressure ──────────────────────────────────

    #[test]
    fn negative_benchmark_pressure_rejected() {
        let mut req = base_request();
        req.benchmark_pressure_millionths = -1;
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.outcome, "fail");
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn opportunity_status_serde_all_variants() {
        let variants = [
            OpportunityStatus::Selected,
            OpportunityStatus::RejectedLowScore,
            OpportunityStatus::RejectedSecurityClearance,
            OpportunityStatus::RejectedMissingHotspot,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: OpportunityStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn opportunity_matrix_error_is_std_error() {
        let e = OpportunityMatrixError::InvalidRequest {
            field: "f".into(),
            detail: "d".into(),
        };
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn opportunity_matrix_error_stable_code_distinct() {
        let codes = [
            OpportunityMatrixError::InvalidRequest {
                field: "f".into(),
                detail: "d".into(),
            }
            .stable_code(),
            OpportunityMatrixError::DuplicateOpportunityId {
                opportunity_id: "x".into(),
            }
            .stable_code(),
            OpportunityMatrixError::InvalidTimestamp {
                value: "bad".into(),
            }
            .stable_code(),
        ];
        let set: std::collections::BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(set.len(), codes.len());
    }

    #[test]
    fn opportunity_matrix_error_display_distinct() {
        let variants: [OpportunityMatrixError; 3] = [
            OpportunityMatrixError::InvalidRequest {
                field: "x".into(),
                detail: "y".into(),
            },
            OpportunityMatrixError::DuplicateOpportunityId {
                opportunity_id: "z".into(),
            },
            OpportunityMatrixError::InvalidTimestamp {
                value: "bad".into(),
            },
        ];
        let set: std::collections::BTreeSet<String> =
            variants.iter().map(|e| format!("{e}")).collect();
        assert_eq!(set.len(), variants.len());
    }

    // ── Enrichment: Clone/Debug/Serde/JSON/Display/Edge ──

    #[test]
    fn opportunity_status_serde_variant_distinct() {
        let variants = [
            OpportunityStatus::Selected,
            OpportunityStatus::RejectedLowScore,
            OpportunityStatus::RejectedSecurityClearance,
            OpportunityStatus::RejectedMissingHotspot,
        ];
        let set: std::collections::BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn opportunity_status_debug_distinct() {
        let variants = [
            OpportunityStatus::Selected,
            OpportunityStatus::RejectedLowScore,
            OpportunityStatus::RejectedSecurityClearance,
            OpportunityStatus::RejectedMissingHotspot,
        ];
        let set: std::collections::BTreeSet<String> =
            variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn opportunity_matrix_error_debug_distinct() {
        let variants: [OpportunityMatrixError; 3] = [
            OpportunityMatrixError::InvalidRequest {
                field: "f".into(),
                detail: "d".into(),
            },
            OpportunityMatrixError::DuplicateOpportunityId {
                opportunity_id: "x".into(),
            },
            OpportunityMatrixError::InvalidTimestamp { value: "v".into() },
        ];
        let set: std::collections::BTreeSet<String> =
            variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn hotspot_profile_entry_clone_independence() {
        let a = HotspotProfileEntry {
            module: "vm".to_string(),
            function: "dispatch".to_string(),
            sample_count: 100,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn optimization_candidate_input_clone_independence() {
        let a = candidate("opp-1", "mod1", "fn1");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn opportunity_outcome_observation_clone_independence() {
        let a = OpportunityOutcomeObservation {
            opportunity_id: "opp-1".to_string(),
            predicted_gain_millionths: 100_000,
            actual_gain_millionths: 90_000,
            completed_at_utc: "2026-01-01T00:00:00Z".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn opportunity_matrix_error_clone_independence() {
        let a = OpportunityMatrixError::DuplicateOpportunityId {
            opportunity_id: "x".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn hotspot_profile_entry_json_field_names() {
        let e = HotspotProfileEntry {
            module: "m".to_string(),
            function: "f".to_string(),
            sample_count: 1,
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"module\""));
        assert!(json.contains("\"function\""));
        assert!(json.contains("\"sample_count\""));
    }

    #[test]
    fn optimization_candidate_input_json_field_names() {
        let c = candidate("opp-1", "m", "f");
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"opportunity_id\""));
        assert!(json.contains("\"target_module\""));
        assert!(json.contains("\"target_function\""));
        assert!(json.contains("\"estimated_speedup_millionths\""));
        assert!(json.contains("\"implementation_complexity\""));
        assert!(json.contains("\"regression_risk_millionths\""));
        assert!(json.contains("\"security_clearance_millionths\""));
        assert!(json.contains("\"engineering_effort_hours_millionths\""));
    }

    #[test]
    fn opportunity_matrix_decision_json_field_names() {
        let d = run_opportunity_matrix_scoring(&base_request());
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("\"schema_version\""));
        assert!(json.contains("\"matrix_id\""));
        assert!(json.contains("\"optimization_run_id\""));
        assert!(json.contains("\"outcome\""));
        assert!(json.contains("\"score_threshold_millionths\""));
        assert!(json.contains("\"ranked_opportunities\""));
        assert!(json.contains("\"events\""));
    }

    #[test]
    fn scored_opportunity_json_field_names() {
        let d = run_opportunity_matrix_scoring(&base_request());
        let json = serde_json::to_string(&d.ranked_opportunities[0]).unwrap();
        assert!(json.contains("\"opportunity_id\""));
        assert!(json.contains("\"score_millionths\""));
        assert!(json.contains("\"threshold_met\""));
        assert!(json.contains("\"status\""));
        assert!(json.contains("\"voi_millionths\""));
    }

    #[test]
    fn error_display_invalid_request_exact() {
        let e = OpportunityMatrixError::InvalidRequest {
            field: "trace_id".to_string(),
            detail: "must not be empty".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "invalid request field `trace_id`: must not be empty"
        );
    }

    #[test]
    fn error_display_duplicate_opportunity_id_exact() {
        let e = OpportunityMatrixError::DuplicateOpportunityId {
            opportunity_id: "opp-1".to_string(),
        };
        assert_eq!(e.to_string(), "duplicate opportunity_id `opp-1`");
    }

    #[test]
    fn error_display_invalid_timestamp_exact() {
        let e = OpportunityMatrixError::InvalidTimestamp {
            value: "not-a-date".to_string(),
        };
        assert_eq!(e.to_string(), "invalid RFC3339 UTC timestamp `not-a-date`");
    }

    #[test]
    fn error_stable_code_invalid_request() {
        let e = OpportunityMatrixError::InvalidRequest {
            field: "f".into(),
            detail: "d".into(),
        };
        assert_eq!(e.stable_code(), "FE-OPPM-1001");
    }

    #[test]
    fn error_stable_code_duplicate() {
        let e = OpportunityMatrixError::DuplicateOpportunityId {
            opportunity_id: "x".into(),
        };
        assert_eq!(e.stable_code(), "FE-OPPM-1002");
    }

    #[test]
    fn error_stable_code_invalid_timestamp() {
        let e = OpportunityMatrixError::InvalidTimestamp { value: "v".into() };
        assert_eq!(e.stable_code(), "FE-OPPM-1003");
    }

    #[test]
    fn hotspot_profile_entry_key_format_enriched() {
        let e = HotspotProfileEntry {
            module: "vm".to_string(),
            function: "dispatch".to_string(),
            sample_count: 100,
        };
        assert_eq!(e.key(), "vm::dispatch");
    }

    #[test]
    fn optimization_candidate_target_key_format() {
        let c = candidate("opp-1", "engine", "eval");
        assert_eq!(c.target_key(), "engine::eval");
    }

    #[test]
    fn decision_has_selected_opportunities_false_when_empty() {
        let mut req = base_request();
        // Set security_clearance to 0 so all get rejected
        for c in &mut req.candidates {
            c.security_clearance_millionths = 0;
        }
        let d = run_opportunity_matrix_scoring(&req);
        assert!(!d.has_selected_opportunities());
    }

    #[test]
    fn decision_schema_version_matches_constant() {
        let d = run_opportunity_matrix_scoring(&base_request());
        assert_eq!(d.schema_version, OPPORTUNITY_MATRIX_SCHEMA_VERSION);
    }

    #[test]
    fn decision_threshold_matches_constant() {
        let d = run_opportunity_matrix_scoring(&base_request());
        assert_eq!(
            d.score_threshold_millionths,
            OPPORTUNITY_SCORE_THRESHOLD_MILLIONTHS
        );
    }

    #[test]
    fn hotspot_profile_entry_serde_roundtrip() {
        let e = HotspotProfileEntry {
            module: "vm".to_string(),
            function: "dispatch".to_string(),
            sample_count: 100,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: HotspotProfileEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn opportunity_matrix_decision_serde_roundtrip() {
        let d = run_opportunity_matrix_scoring(&base_request());
        let json = serde_json::to_string(&d).unwrap();
        let back: OpportunityMatrixDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn debug_nonempty_hotspot_profile_entry() {
        let e = HotspotProfileEntry {
            module: "m".to_string(),
            function: "f".to_string(),
            sample_count: 0,
        };
        assert!(!format!("{e:?}").is_empty());
    }

    #[test]
    fn debug_nonempty_optimization_candidate_input() {
        assert!(!format!("{:?}", candidate("o", "m", "f")).is_empty());
    }

    #[test]
    fn debug_nonempty_opportunity_matrix_error() {
        let e = OpportunityMatrixError::InvalidRequest {
            field: "f".into(),
            detail: "d".into(),
        };
        assert!(!format!("{e:?}").is_empty());
    }

    #[test]
    fn debug_nonempty_scored_opportunity() {
        let d = run_opportunity_matrix_scoring(&base_request());
        assert!(!format!("{:?}", d.ranked_opportunities[0]).is_empty());
    }

    #[test]
    fn debug_nonempty_opportunity_matrix_decision() {
        let d = run_opportunity_matrix_scoring(&base_request());
        assert!(!format!("{d:?}").is_empty());
    }

    #[test]
    fn boundary_empty_trace_id_rejected() {
        let mut req = base_request();
        req.trace_id = "  ".to_string();
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.outcome, "fail");
        assert!(d.error_code.is_some());
    }

    #[test]
    fn boundary_empty_candidates_rejected() {
        let mut req = base_request();
        req.candidates.clear();
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.outcome, "fail");
    }

    #[test]
    fn boundary_zero_sample_count_hotspot() {
        let e = HotspotProfileEntry {
            module: "m".to_string(),
            function: "f".to_string(),
            sample_count: 0,
        };
        assert_eq!(e.sample_count, 0);
    }

    #[test]
    fn constants_stable() {
        assert_eq!(OPPORTUNITY_MATRIX_COMPONENT, "opportunity_matrix");
        assert_eq!(
            OPPORTUNITY_MATRIX_SCHEMA_VERSION,
            "franken-engine.opportunity-matrix.v1"
        );
        assert_eq!(OPPORTUNITY_SCORE_THRESHOLD_MILLIONTHS, 2_000_000);
    }

    #[test]
    fn benchmark_pressure_from_empty_cases_returns_neutral() {
        let pressure = benchmark_pressure_from_cases(&[], &[]);
        assert_eq!(pressure, 1_000_000);
    }

    // ── enrichment wave 2 ──────────────────────────────────

    #[test]
    fn opportunity_status_all_variants_serde_distinct() {
        let variants = [
            OpportunityStatus::Selected,
            OpportunityStatus::RejectedLowScore,
            OpportunityStatus::RejectedSecurityClearance,
            OpportunityStatus::RejectedMissingHotspot,
        ];
        let jsons: Vec<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        for (i, a) in jsons.iter().enumerate() {
            for (j, b) in jsons.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "variants {i} and {j} collide");
                }
            }
        }
    }

    #[test]
    fn opportunity_status_rename_all_snake_case() {
        let j = serde_json::to_string(&OpportunityStatus::RejectedLowScore).unwrap();
        assert_eq!(j, "\"rejected_low_score\"");
        let j2 = serde_json::to_string(&OpportunityStatus::RejectedSecurityClearance).unwrap();
        assert_eq!(j2, "\"rejected_security_clearance\"");
    }

    #[test]
    fn scored_opportunity_clone_independence() {
        let s = ScoredOpportunity {
            opportunity_id: "opp-1".to_string(),
            target_module: "m".to_string(),
            target_function: "f".to_string(),
            estimated_speedup_millionths: 1_500_000,
            hotpath_weight_millionths: 500_000,
            benchmark_pressure_millionths: 1_200_000,
            voi_millionths: 2_000_000,
            score_millionths: 3_000_000,
            threshold_met: true,
            status: OpportunityStatus::Selected,
            rejection_reason: None,
        };
        let mut cloned = s.clone();
        cloned.opportunity_id = "opp-2".to_string();
        assert_eq!(s.opportunity_id, "opp-1");
        assert_eq!(cloned.opportunity_id, "opp-2");
    }

    #[test]
    fn opportunity_history_record_signed_error_negative() {
        let h = OpportunityHistoryRecord {
            opportunity_id: "h1".to_string(),
            predicted_gain_millionths: 2_000_000,
            actual_gain_millionths: 1_500_000,
            signed_error_millionths: -500_000,
            absolute_error_millionths: 500_000,
            completed_at_utc: "2026-01-01T00:00:00Z".to_string(),
        };
        assert!(h.signed_error_millionths < 0);
        assert!(h.absolute_error_millionths > 0);
    }

    #[test]
    fn opportunity_matrix_event_json_field_names() {
        let e = OpportunityMatrixEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "ev".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            opportunity_id: Some("opp-1".to_string()),
        };
        let j = serde_json::to_string(&e).unwrap();
        for field in &[
            "trace_id",
            "decision_id",
            "policy_id",
            "component",
            "event",
            "outcome",
            "error_code",
            "opportunity_id",
        ] {
            assert!(j.contains(field), "missing field: {field}");
        }
    }

    #[test]
    fn decision_empty_decision_id_rejected() {
        let mut req = base_request();
        req.decision_id = "   ".to_string();
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.outcome, "fail");
    }

    #[test]
    fn decision_empty_policy_id_rejected() {
        let mut req = base_request();
        req.policy_id = String::new();
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.outcome, "fail");
    }

    #[test]
    fn decision_empty_optimization_run_id_rejected() {
        let mut req = base_request();
        req.optimization_run_id = "  ".to_string();
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.outcome, "fail");
    }

    #[test]
    fn decision_duplicate_candidate_ids_rejected() {
        let mut req = base_request();
        let mut dup = req.candidates[0].clone();
        dup.opportunity_id = req.candidates[0].opportunity_id.clone();
        req.candidates.push(dup);
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.outcome, "fail");
        assert!(d.error_code.as_deref() == Some("FE-OPPM-1002"));
    }

    #[test]
    fn decision_negative_benchmark_pressure_rejected() {
        let mut req = base_request();
        req.benchmark_pressure_millionths = -1;
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.outcome, "fail");
    }

    #[test]
    fn decision_invalid_historical_timestamp_rejected() {
        let mut req = base_request();
        req.historical_outcomes.push(OpportunityOutcomeObservation {
            opportunity_id: "hist-1".to_string(),
            predicted_gain_millionths: 1_000_000,
            actual_gain_millionths: 900_000,
            completed_at_utc: "not-a-date".to_string(),
        });
        let d = run_opportunity_matrix_scoring(&req);
        assert_eq!(d.outcome, "fail");
        assert!(d.error_code.as_deref() == Some("FE-OPPM-1003"));
    }
}
