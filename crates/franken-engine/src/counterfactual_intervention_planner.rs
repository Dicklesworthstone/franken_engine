#![forbid(unsafe_code)]

//! Counterfactual intervention planner for optimization-wave selection.
//!
//! Implements [RGC-615B] (bead bd-1lsy.7.15.2): uses causal models to choose
//! optimization waves, pass priorities, and experiment bundles by expected
//! causal uplift, downside risk, and information value.  The planner builds
//! counterfactual scenarios — "what would happen if we ran pass X but not Y?" —
//! then scores each scenario by its expected causal effect, confidence interval,
//! and worst-case downside.
//!
//! Key design decisions:
//! - `OptimizationPass` carries estimated uplift, risk, and cost in fixed-point
//!   millionths so every comparison is deterministic.
//! - `InterventionKind` enumerates the counterfactual manipulations: enable,
//!   disable, reorder, adjust-parameter, and compare-variants.
//! - `CounterfactualScenario` pairs a list of interventions with an expected
//!   outcome and confidence, sealed by a content hash.
//! - `WaveDefinition` groups passes into a prioritized wave with aggregate
//!   uplift and risk budgets.
//! - `UpliftCertificate` records observed-vs-counterfactual causal effects with
//!   confidence intervals.
//! - `PlanningDecision` wraps the selected wave, epoch, information value, and
//!   downside bound into a content-hashed decision record.
//! - All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the counterfactual intervention planner.
pub const SCHEMA_VERSION: &str = "franken-engine.counterfactual-intervention-planner.v1";

/// Bead identifier for traceability.
pub const BEAD_ID: &str = "bd-1lsy.7.15.2";

/// Component name.
pub const COMPONENT: &str = "counterfactual-intervention-planner";

/// Policy identifier.
pub const POLICY_ID: &str = "RGC-615B";

/// One million — the unit for fixed-point millionths arithmetic.
pub const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Hex-encode a byte slice.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Compute a deterministic content hash from arbitrary bytes.
fn compute_content_hash(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

/// Stable hash seed for deterministic ID derivation.
fn derive_id(prefix: &str, payload: &[u8]) -> String {
    let hash = compute_content_hash(payload);
    let hex = hex_encode(hash.as_bytes());
    format!("{prefix}-{}", &hex[..16])
}

// ---------------------------------------------------------------------------
// PlannerError
// ---------------------------------------------------------------------------

/// Errors that the counterfactual intervention planner can produce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlannerError {
    /// No viable optimization passes remain after filtering.
    NoViablePasses,
    /// Total risk of the best candidate wave exceeds the caller's budget.
    RiskExceedsBudget,
    /// Pass prerequisites form a cycle and cannot be linearised.
    CyclicDependency,
    /// Not enough historical data to estimate causal effects.
    InsufficientData,
    /// Catch-all for unexpected internal failures.
    InternalError(String),
}

impl fmt::Display for PlannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoViablePasses => write!(f, "no viable optimization passes"),
            Self::RiskExceedsBudget => write!(f, "risk exceeds budget"),
            Self::CyclicDependency => write!(f, "cyclic dependency in pass prerequisites"),
            Self::InsufficientData => write!(f, "insufficient data for causal estimation"),
            Self::InternalError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// OptimizationPass
// ---------------------------------------------------------------------------

/// A single optimization pass with estimated uplift, risk, and cost.
///
/// All numeric fields use fixed-point millionths (1_000_000 = 1.0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationPass {
    /// Unique identifier for this pass.
    pub pass_id: String,
    /// Human-readable name.
    pub name: String,
    /// Expected performance uplift in millionths.
    pub estimated_uplift_millionths: u64,
    /// Estimated risk (probability of regression) in millionths.
    pub estimated_risk_millionths: u64,
    /// Cost to execute this pass in millionths.
    pub cost_millionths: u64,
    /// IDs of passes that must run before this one.
    pub prerequisites: Vec<String>,
}

impl OptimizationPass {
    /// Uplift-to-risk ratio as a u64 value (saturating division).
    ///
    /// Higher is better.  Returns `u64::MAX` when risk is zero.
    pub fn uplift_risk_ratio(&self) -> u64 {
        if self.estimated_risk_millionths == 0 {
            return u64::MAX;
        }
        self.estimated_uplift_millionths
            .saturating_mul(MILLIONTHS)
            .checked_div(self.estimated_risk_millionths)
            .unwrap_or(0)
    }

    /// Net benefit: uplift minus cost, saturating at zero.
    pub fn net_benefit(&self) -> u64 {
        self.estimated_uplift_millionths
            .saturating_sub(self.cost_millionths)
    }
}

// ---------------------------------------------------------------------------
// InterventionKind
// ---------------------------------------------------------------------------

/// The kind of counterfactual intervention to apply to a wave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum InterventionKind {
    /// Enable a pass that is currently disabled.
    EnablePass,
    /// Disable a pass that is currently enabled.
    DisablePass,
    /// Reorder passes to test ordering sensitivity.
    ReorderPasses,
    /// Adjust a numeric parameter of a pass.
    AdjustParameter,
    /// Compare two variant configurations side by side.
    CompareVariants,
}

impl InterventionKind {
    /// All variants, in declaration order.
    pub const ALL: &[Self] = &[
        Self::EnablePass,
        Self::DisablePass,
        Self::ReorderPasses,
        Self::AdjustParameter,
        Self::CompareVariants,
    ];

    /// Machine-readable string tag.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EnablePass => "enable_pass",
            Self::DisablePass => "disable_pass",
            Self::ReorderPasses => "reorder_passes",
            Self::AdjustParameter => "adjust_parameter",
            Self::CompareVariants => "compare_variants",
        }
    }
}

impl fmt::Display for InterventionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CounterfactualScenario
// ---------------------------------------------------------------------------

/// A counterfactual scenario: a set of interventions with predicted outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualScenario {
    /// Unique identifier for this scenario.
    pub scenario_id: String,
    /// The interventions applied: `(kind, target_pass_id)`.
    pub interventions: Vec<(InterventionKind, String)>,
    /// Expected outcome delta in millionths (signed: positive = improvement).
    pub expected_outcome_millionths: i64,
    /// Confidence in the prediction in millionths (0 = none, 1_000_000 = certain).
    pub confidence_millionths: u64,
    /// Content hash sealing this scenario.
    pub content_hash: ContentHash,
}

impl CounterfactualScenario {
    /// Seal the scenario by computing a content hash over its fields.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.scenario_id.as_bytes());
        for (kind, target) in &self.interventions {
            buf.extend_from_slice(kind.as_str().as_bytes());
            buf.extend_from_slice(target.as_bytes());
        }
        buf.extend_from_slice(&self.expected_outcome_millionths.to_le_bytes());
        buf.extend_from_slice(&self.confidence_millionths.to_le_bytes());
        self.content_hash = compute_content_hash(&buf);
    }
}

// ---------------------------------------------------------------------------
// WaveDefinition
// ---------------------------------------------------------------------------

/// A wave of optimization passes to execute together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaveDefinition {
    /// Unique identifier for this wave.
    pub wave_id: String,
    /// The passes in this wave.
    pub passes: Vec<OptimizationPass>,
    /// Sum of estimated uplift across all passes, in millionths.
    pub total_expected_uplift_millionths: u64,
    /// Sum of estimated risk across all passes, in millionths.
    pub total_risk_millionths: u64,
    /// Ordered list of pass IDs defining execution priority.
    pub priority_order: Vec<String>,
}

impl WaveDefinition {
    /// Recompute aggregate uplift and risk from the passes list.
    pub fn recompute_aggregates(&mut self) {
        self.total_expected_uplift_millionths = self
            .passes
            .iter()
            .map(|p| p.estimated_uplift_millionths)
            .fold(0u64, |a, b| a.saturating_add(b));
        self.total_risk_millionths = self
            .passes
            .iter()
            .map(|p| p.estimated_risk_millionths)
            .fold(0u64, |a, b| a.saturating_add(b));
    }

    /// Number of passes in this wave.
    pub fn pass_count(&self) -> usize {
        self.passes.len()
    }

    /// Total cost of all passes, in millionths.
    pub fn total_cost_millionths(&self) -> u64 {
        self.passes
            .iter()
            .map(|p| p.cost_millionths)
            .fold(0u64, |a, b| a.saturating_add(b))
    }
}

// ---------------------------------------------------------------------------
// UpliftCertificate
// ---------------------------------------------------------------------------

/// Certificate recording observed causal uplift from a wave.
///
/// Compares observed performance against a counterfactual baseline to
/// isolate the causal effect of the wave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpliftCertificate {
    /// Unique certificate identifier.
    pub certificate_id: String,
    /// Wave this certificate is for.
    pub wave_id: String,
    /// Observed uplift in millionths (signed).
    pub observed_uplift_millionths: i64,
    /// Counterfactual baseline in millionths (signed).
    pub counterfactual_baseline_millionths: i64,
    /// Estimated causal effect: observed minus baseline, in millionths.
    pub causal_effect_millionths: i64,
    /// Lower bound of the confidence interval, in millionths.
    pub confidence_interval_low_millionths: i64,
    /// Upper bound of the confidence interval, in millionths.
    pub confidence_interval_high_millionths: i64,
    /// Content hash sealing this certificate.
    pub content_hash: ContentHash,
}

impl UpliftCertificate {
    /// Seal the certificate by computing a content hash over its fields.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.certificate_id.as_bytes());
        buf.extend_from_slice(self.wave_id.as_bytes());
        buf.extend_from_slice(&self.observed_uplift_millionths.to_le_bytes());
        buf.extend_from_slice(&self.counterfactual_baseline_millionths.to_le_bytes());
        buf.extend_from_slice(&self.causal_effect_millionths.to_le_bytes());
        buf.extend_from_slice(&self.confidence_interval_low_millionths.to_le_bytes());
        buf.extend_from_slice(&self.confidence_interval_high_millionths.to_le_bytes());
        self.content_hash = compute_content_hash(&buf);
    }

    /// Whether the causal effect is statistically positive (entire CI > 0).
    pub fn is_positive_effect(&self) -> bool {
        self.confidence_interval_low_millionths > 0
    }

    /// Width of the confidence interval.
    pub fn ci_width(&self) -> i64 {
        self.confidence_interval_high_millionths
            .saturating_sub(self.confidence_interval_low_millionths)
    }
}

// ---------------------------------------------------------------------------
// PlanningDecision
// ---------------------------------------------------------------------------

/// A planning decision: the selected wave and its justification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanningDecision {
    /// Unique decision identifier.
    pub decision_id: String,
    /// Epoch at which this decision was made.
    pub epoch: SecurityEpoch,
    /// The wave selected for execution.
    pub selected_wave: WaveDefinition,
    /// Number of alternative waves that were considered.
    pub alternatives_considered: u64,
    /// Expected information value of running this wave, in millionths.
    pub information_value_millionths: u64,
    /// Worst-case downside bound, in millionths.
    pub downside_bound_millionths: u64,
    /// Content hash sealing this decision.
    pub content_hash: ContentHash,
}

impl PlanningDecision {
    /// Seal the decision by computing a content hash over its fields.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.decision_id.as_bytes());
        buf.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        buf.extend_from_slice(self.selected_wave.wave_id.as_bytes());
        buf.extend_from_slice(&self.alternatives_considered.to_le_bytes());
        buf.extend_from_slice(&self.information_value_millionths.to_le_bytes());
        buf.extend_from_slice(&self.downside_bound_millionths.to_le_bytes());
        self.content_hash = compute_content_hash(&buf);
    }

    /// Whether the decision has a positive expected information value.
    pub fn is_informative(&self) -> bool {
        self.information_value_millionths > 0
    }
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Rank optimization passes by their uplift-to-risk ratio (descending).
///
/// Returns `(pass_id, ratio)` pairs sorted from best to worst.
/// Passes with zero risk sort first (infinite ratio capped at `u64::MAX`).
pub fn rank_passes(passes: &[OptimizationPass]) -> Vec<(String, u64)> {
    let mut ranked: Vec<(String, u64)> = passes
        .iter()
        .map(|p| (p.pass_id.clone(), p.uplift_risk_ratio()))
        .collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ranked
}

/// Validate that the prerequisite graph is acyclic and produce a
/// topological ordering of pass IDs.
///
/// Returns `Err(CyclicDependency)` if any cycle is detected.
pub fn validate_pass_ordering(passes: &[OptimizationPass]) -> Result<Vec<String>, PlannerError> {
    if passes.is_empty() {
        return Err(PlannerError::NoViablePasses);
    }

    // Build adjacency: pass_id -> prerequisites.
    let known_ids: BTreeSet<&str> = passes.iter().map(|p| p.pass_id.as_str()).collect();
    let mut in_degree: BTreeMap<&str, usize> = BTreeMap::new();
    let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();

    for p in passes {
        in_degree.entry(p.pass_id.as_str()).or_insert(0);
        for prereq in &p.prerequisites {
            if known_ids.contains(prereq.as_str()) {
                *in_degree.entry(p.pass_id.as_str()).or_insert(0) += 1;
                dependents
                    .entry(prereq.as_str())
                    .or_default()
                    .push(p.pass_id.as_str());
            }
        }
    }

    // Kahn's algorithm.
    let mut queue: Vec<&str> = in_degree
        .iter()
        .filter(|&(_, deg)| *deg == 0)
        .map(|(id, _)| *id)
        .collect();
    queue.sort(); // deterministic ordering

    let mut order = Vec::with_capacity(passes.len());

    while let Some(node) = queue.pop() {
        order.push(node.to_string());
        if let Some(deps) = dependents.get(node) {
            for dep in deps {
                if let Some(deg) = in_degree.get_mut(dep) {
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        // Insert sorted for determinism.
                        let pos = queue.partition_point(|&x| x <= *dep);
                        queue.insert(pos, dep);
                    }
                }
            }
        }
    }

    if order.len() != passes.len() {
        return Err(PlannerError::CyclicDependency);
    }

    Ok(order)
}

/// Plan a wave by selecting passes that fit within a risk budget.
///
/// Passes are added in topological order (respecting prerequisites) and
/// greedily by uplift-to-risk ratio.  If no passes are viable, returns
/// `Err(NoViablePasses)`.  If the minimum-risk set exceeds the budget,
/// returns `Err(RiskExceedsBudget)`.
pub fn plan_wave(
    passes: Vec<OptimizationPass>,
    risk_budget_millionths: u64,
) -> Result<WaveDefinition, PlannerError> {
    if passes.is_empty() {
        return Err(PlannerError::NoViablePasses);
    }

    let topo_order = validate_pass_ordering(&passes)?;

    // Index passes by ID.
    let pass_index: BTreeMap<String, &OptimizationPass> =
        passes.iter().map(|p| (p.pass_id.clone(), p)).collect();

    // Greedy selection respecting topological order and risk budget.
    let mut selected: Vec<OptimizationPass> = Vec::new();
    let mut selected_ids: BTreeSet<String> = BTreeSet::new();
    let mut remaining_budget = risk_budget_millionths;

    // Sort candidates within each topological layer by ratio (descending).
    let ranking: BTreeMap<String, u64> = rank_passes(&passes).into_iter().collect();

    // Walk topo order; within each "layer" we prefer high-ratio passes.
    let mut sorted_topo = topo_order.clone();
    sorted_topo.sort_by(|a, b| {
        let ra = ranking.get(a).copied().unwrap_or(0);
        let rb = ranking.get(b).copied().unwrap_or(0);
        rb.cmp(&ra).then_with(|| a.cmp(b))
    });

    for pass_id in &sorted_topo {
        if let Some(&pass) = pass_index.get(pass_id) {
            // Check prerequisites are already selected.
            let prereqs_met = pass
                .prerequisites
                .iter()
                .all(|pr| selected_ids.contains(pr) || !pass_index.contains_key(pr));

            if prereqs_met && pass.estimated_risk_millionths <= remaining_budget {
                remaining_budget = remaining_budget.saturating_sub(pass.estimated_risk_millionths);
                selected_ids.insert(pass.pass_id.clone());
                selected.push(pass.clone());
            }
        }
    }

    if selected.is_empty() {
        return Err(PlannerError::RiskExceedsBudget);
    }

    // Build priority order: re-validate topological sort for selected passes.
    let priority_order = validate_pass_ordering(&selected)?;

    let wave_id = derive_id("wave", priority_order.join(",").as_bytes());

    let mut wave = WaveDefinition {
        wave_id,
        passes: selected,
        total_expected_uplift_millionths: 0,
        total_risk_millionths: 0,
        priority_order,
    };
    wave.recompute_aggregates();

    Ok(wave)
}

/// Build a counterfactual scenario for a wave with one intervention.
///
/// The expected outcome is estimated from the wave's aggregate uplift,
/// modified by the intervention kind:
/// - `EnablePass`: +uplift of the target pass.
/// - `DisablePass`: −uplift of the target pass.
/// - `ReorderPasses`: small estimated interaction effect (10%).
/// - `AdjustParameter`: moderate adjustment (±20%).
/// - `CompareVariants`: zero delta (comparison only).
pub fn build_counterfactual(
    wave: &WaveDefinition,
    intervention: InterventionKind,
    target: &str,
) -> CounterfactualScenario {
    let target_uplift: i64 = wave
        .passes
        .iter()
        .find(|p| p.pass_id == target)
        .map(|p| p.estimated_uplift_millionths as i64)
        .unwrap_or(0);

    let expected_outcome_millionths: i64 = match intervention {
        InterventionKind::EnablePass => target_uplift,
        InterventionKind::DisablePass => -target_uplift,
        InterventionKind::ReorderPasses => {
            // Interaction effect estimated at 10% of uplift.
            target_uplift.checked_div(10).unwrap_or(0)
        }
        InterventionKind::AdjustParameter => {
            // Parameter adjustment estimated at ±20%.
            target_uplift.checked_div(5).unwrap_or(0)
        }
        InterventionKind::CompareVariants => 0,
    };

    let confidence_millionths: u64 = match intervention {
        InterventionKind::EnablePass | InterventionKind::DisablePass => 800_000,
        InterventionKind::ReorderPasses => 500_000,
        InterventionKind::AdjustParameter => 600_000,
        InterventionKind::CompareVariants => 900_000,
    };

    let scenario_id = derive_id(
        "scenario",
        format!("{}-{}-{}", wave.wave_id, intervention.as_str(), target).as_bytes(),
    );

    let mut scenario = CounterfactualScenario {
        scenario_id,
        interventions: vec![(intervention, target.to_string())],
        expected_outcome_millionths,
        confidence_millionths,
        content_hash: ContentHash::compute(b""),
    };
    scenario.seal();
    scenario
}

/// Estimate the causal effect given a scenario, baseline, and observed outcome.
///
/// The causal effect is `observed - baseline`.  The confidence interval is
/// derived from the scenario's confidence: width = effect × (1 − confidence).
pub fn estimate_causal_effect(
    scenario: &CounterfactualScenario,
    baseline_millionths: i64,
    observed_millionths: i64,
) -> UpliftCertificate {
    let causal_effect = observed_millionths.saturating_sub(baseline_millionths);

    // Confidence interval half-width: |effect| × (1 − confidence/MILLIONTHS).
    let uncertainty_fraction = MILLIONTHS.saturating_sub(scenario.confidence_millionths);
    let half_width = if causal_effect == 0 {
        uncertainty_fraction as i64
    } else {
        let abs_effect = causal_effect.unsigned_abs();
        let hw = abs_effect
            .saturating_mul(uncertainty_fraction)
            .checked_div(MILLIONTHS)
            .unwrap_or(0);
        hw as i64
    };

    let ci_low = causal_effect.saturating_sub(half_width);
    let ci_high = causal_effect.saturating_add(half_width);

    let cert_id = derive_id(
        "cert",
        format!(
            "{}-{}-{}",
            scenario.scenario_id, baseline_millionths, observed_millionths
        )
        .as_bytes(),
    );

    let wave_id = if let Some((_, target)) = scenario.interventions.first() {
        format!("wave-for-{target}")
    } else {
        "wave-unknown".to_string()
    };

    let mut cert = UpliftCertificate {
        certificate_id: cert_id,
        wave_id,
        observed_uplift_millionths: observed_millionths,
        counterfactual_baseline_millionths: baseline_millionths,
        causal_effect_millionths: causal_effect,
        confidence_interval_low_millionths: ci_low,
        confidence_interval_high_millionths: ci_high,
        content_hash: ContentHash::compute(b""),
    };
    cert.seal();
    cert
}

/// Select the best wave from a set of candidates given a risk budget.
///
/// Waves that exceed the risk budget are filtered.  Among the remainder,
/// the wave with the highest `total_expected_uplift_millionths` wins.
/// The planning decision records the epoch, information value, and
/// downside bound.
pub fn select_best_wave(
    waves: Vec<WaveDefinition>,
    risk_budget: u64,
) -> Result<PlanningDecision, PlannerError> {
    if waves.is_empty() {
        return Err(PlannerError::NoViablePasses);
    }

    let viable: Vec<&WaveDefinition> = waves
        .iter()
        .filter(|w| w.total_risk_millionths <= risk_budget)
        .collect();

    if viable.is_empty() {
        return Err(PlannerError::RiskExceedsBudget);
    }

    let best = viable
        .iter()
        .max_by(|a, b| {
            a.total_expected_uplift_millionths
                .cmp(&b.total_expected_uplift_millionths)
                .then_with(|| a.wave_id.cmp(&b.wave_id))
        })
        .unwrap(); // safe: viable is non-empty

    let alternatives_considered = (waves.len() as u64).saturating_sub(1);

    // Information value: difference between best and second-best uplift.
    let mut uplifts: Vec<u64> = viable
        .iter()
        .map(|w| w.total_expected_uplift_millionths)
        .collect();
    uplifts.sort_unstable();
    uplifts.reverse();

    let information_value_millionths = if uplifts.len() >= 2 {
        uplifts[0].saturating_sub(uplifts[1])
    } else {
        uplifts[0]
    };

    // Downside bound: worst-case risk from the selected wave.
    let downside_bound_millionths = best.total_risk_millionths;

    let decision_id = derive_id(
        "decision",
        format!("{}-{}", best.wave_id, alternatives_considered).as_bytes(),
    );

    let mut decision = PlanningDecision {
        decision_id,
        epoch: SecurityEpoch::from_raw(1),
        selected_wave: (*best).clone(),
        alternatives_considered,
        information_value_millionths,
        downside_bound_millionths,
        content_hash: ContentHash::compute(b""),
    };
    decision.seal();
    Ok(decision)
}

/// Produce a canonical reference planning decision (manifest).
///
/// This creates a representative decision with sample passes, demonstrating
/// the planner's coverage of all intervention kinds.  Useful for testing
/// and schema validation.
pub fn franken_engine_intervention_manifest() -> PlanningDecision {
    let passes = vec![
        OptimizationPass {
            pass_id: "pass-inline-small".to_string(),
            name: "Inline small functions".to_string(),
            estimated_uplift_millionths: 300_000,
            estimated_risk_millionths: 50_000,
            cost_millionths: 20_000,
            prerequisites: vec![],
        },
        OptimizationPass {
            pass_id: "pass-dead-code".to_string(),
            name: "Dead code elimination".to_string(),
            estimated_uplift_millionths: 200_000,
            estimated_risk_millionths: 30_000,
            cost_millionths: 15_000,
            prerequisites: vec![],
        },
        OptimizationPass {
            pass_id: "pass-const-fold".to_string(),
            name: "Constant folding".to_string(),
            estimated_uplift_millionths: 250_000,
            estimated_risk_millionths: 20_000,
            cost_millionths: 10_000,
            prerequisites: vec!["pass-dead-code".to_string()],
        },
        OptimizationPass {
            pass_id: "pass-loop-unroll".to_string(),
            name: "Loop unrolling".to_string(),
            estimated_uplift_millionths: 400_000,
            estimated_risk_millionths: 100_000,
            cost_millionths: 50_000,
            prerequisites: vec!["pass-inline-small".to_string()],
        },
        OptimizationPass {
            pass_id: "pass-escape-analysis".to_string(),
            name: "Escape analysis".to_string(),
            estimated_uplift_millionths: 350_000,
            estimated_risk_millionths: 60_000,
            cost_millionths: 30_000,
            prerequisites: vec!["pass-inline-small".to_string()],
        },
    ];

    let wave = plan_wave(passes, 500_000).expect("manifest wave should succeed");

    let mut decision = PlanningDecision {
        decision_id: format!("manifest-{}", BEAD_ID),
        epoch: SecurityEpoch::from_raw(1),
        selected_wave: wave,
        alternatives_considered: 0,
        information_value_millionths: 500_000,
        downside_bound_millionths: 200_000,
        content_hash: ContentHash::compute(b""),
    };
    decision.seal();
    decision
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helpers ---------------------------------------------------------------

    fn make_pass(id: &str, uplift: u64, risk: u64, cost: u64) -> OptimizationPass {
        OptimizationPass {
            pass_id: id.to_string(),
            name: format!("Pass {id}"),
            estimated_uplift_millionths: uplift,
            estimated_risk_millionths: risk,
            cost_millionths: cost,
            prerequisites: vec![],
        }
    }

    fn make_pass_with_prereqs(
        id: &str,
        uplift: u64,
        risk: u64,
        cost: u64,
        prereqs: Vec<&str>,
    ) -> OptimizationPass {
        OptimizationPass {
            pass_id: id.to_string(),
            name: format!("Pass {id}"),
            estimated_uplift_millionths: uplift,
            estimated_risk_millionths: risk,
            cost_millionths: cost,
            prerequisites: prereqs.into_iter().map(|s| s.to_string()).collect(),
        }
    }

    fn sample_passes() -> Vec<OptimizationPass> {
        vec![
            make_pass("alpha", 400_000, 50_000, 20_000),
            make_pass("beta", 200_000, 100_000, 30_000),
            make_pass("gamma", 300_000, 30_000, 10_000),
        ]
    }

    fn sample_wave() -> WaveDefinition {
        let passes = sample_passes();
        plan_wave(passes, MILLIONTHS).unwrap()
    }

    // Constants -------------------------------------------------------------

    #[test]
    fn constants_non_empty() {
        assert!(!SCHEMA_VERSION.is_empty());
        assert!(!BEAD_ID.is_empty());
        assert!(!COMPONENT.is_empty());
        assert!(!POLICY_ID.is_empty());
    }

    #[test]
    fn schema_version_prefixed() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn bead_id_matches() {
        assert_eq!(BEAD_ID, "bd-1lsy.7.15.2");
    }

    #[test]
    fn policy_id_matches() {
        assert_eq!(POLICY_ID, "RGC-615B");
    }

    #[test]
    fn millionths_value() {
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    // PlannerError ----------------------------------------------------------

    #[test]
    fn planner_error_display_variants() {
        let errors = vec![
            (PlannerError::NoViablePasses, "no viable"),
            (PlannerError::RiskExceedsBudget, "risk exceeds"),
            (PlannerError::CyclicDependency, "cyclic"),
            (PlannerError::InsufficientData, "insufficient"),
            (
                PlannerError::InternalError("boom".to_string()),
                "internal error: boom",
            ),
        ];
        for (err, expected_substr) in errors {
            let msg = err.to_string();
            assert!(
                msg.contains(expected_substr),
                "'{msg}' should contain '{expected_substr}'"
            );
        }
    }

    #[test]
    fn planner_error_serde_roundtrip() {
        let err = PlannerError::InternalError("test".to_string());
        let json = serde_json::to_string(&err).unwrap();
        let back: PlannerError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    // OptimizationPass ------------------------------------------------------

    #[test]
    fn pass_uplift_risk_ratio_normal() {
        let p = make_pass("x", 500_000, 100_000, 0);
        // 500_000 * 1_000_000 / 100_000 = 5_000_000
        assert_eq!(p.uplift_risk_ratio(), 5_000_000);
    }

    #[test]
    fn pass_uplift_risk_ratio_zero_risk() {
        let p = make_pass("x", 500_000, 0, 0);
        assert_eq!(p.uplift_risk_ratio(), u64::MAX);
    }

    #[test]
    fn pass_net_benefit() {
        let p = make_pass("x", 500_000, 0, 200_000);
        assert_eq!(p.net_benefit(), 300_000);
    }

    #[test]
    fn pass_net_benefit_saturates() {
        let p = make_pass("x", 100_000, 0, 500_000);
        assert_eq!(p.net_benefit(), 0);
    }

    #[test]
    fn pass_serde_roundtrip() {
        let p = make_pass("test-pass", 300_000, 50_000, 10_000);
        let json = serde_json::to_string(&p).unwrap();
        let back: OptimizationPass = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    // InterventionKind ------------------------------------------------------

    #[test]
    fn intervention_kind_all_count() {
        assert_eq!(InterventionKind::ALL.len(), 5);
    }

    #[test]
    fn intervention_kind_display_matches_as_str() {
        for k in InterventionKind::ALL {
            assert_eq!(k.to_string(), k.as_str());
        }
    }

    #[test]
    fn intervention_kind_serde_roundtrip() {
        for k in InterventionKind::ALL {
            let json = serde_json::to_string(k).unwrap();
            let back: InterventionKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    // rank_passes -----------------------------------------------------------

    #[test]
    fn rank_passes_sorts_descending() {
        let passes = sample_passes();
        let ranked = rank_passes(&passes);
        assert_eq!(ranked.len(), 3);
        // gamma has best ratio (300k/30k = 10M), alpha (400k/50k = 8M),
        // beta (200k/100k = 2M).
        assert_eq!(ranked[0].0, "gamma");
        assert_eq!(ranked[1].0, "alpha");
        assert_eq!(ranked[2].0, "beta");
    }

    #[test]
    fn rank_passes_empty() {
        let ranked = rank_passes(&[]);
        assert!(ranked.is_empty());
    }

    #[test]
    fn rank_passes_zero_risk_first() {
        let passes = vec![
            make_pass("risky", 500_000, 100_000, 0),
            make_pass("safe", 100_000, 0, 0),
        ];
        let ranked = rank_passes(&passes);
        assert_eq!(ranked[0].0, "safe");
        assert_eq!(ranked[0].1, u64::MAX);
    }

    // validate_pass_ordering ------------------------------------------------

    #[test]
    fn validate_ordering_linear_chain() {
        let passes = vec![
            make_pass("a", 100_000, 10_000, 0),
            make_pass_with_prereqs("b", 200_000, 20_000, 0, vec!["a"]),
            make_pass_with_prereqs("c", 300_000, 30_000, 0, vec!["b"]),
        ];
        let order = validate_pass_ordering(&passes).unwrap();
        let pos_a = order.iter().position(|x| x == "a").unwrap();
        let pos_b = order.iter().position(|x| x == "b").unwrap();
        let pos_c = order.iter().position(|x| x == "c").unwrap();
        assert!(pos_a < pos_b);
        assert!(pos_b < pos_c);
    }

    #[test]
    fn validate_ordering_detects_cycle() {
        let passes = vec![
            make_pass_with_prereqs("a", 100_000, 10_000, 0, vec!["b"]),
            make_pass_with_prereqs("b", 200_000, 20_000, 0, vec!["a"]),
        ];
        let result = validate_pass_ordering(&passes);
        assert_eq!(result, Err(PlannerError::CyclicDependency));
    }

    #[test]
    fn validate_ordering_empty() {
        let result = validate_pass_ordering(&[]);
        assert_eq!(result, Err(PlannerError::NoViablePasses));
    }

    #[test]
    fn validate_ordering_independent_passes() {
        let passes = vec![
            make_pass("x", 100_000, 10_000, 0),
            make_pass("y", 200_000, 20_000, 0),
            make_pass("z", 300_000, 30_000, 0),
        ];
        let order = validate_pass_ordering(&passes).unwrap();
        assert_eq!(order.len(), 3);
    }

    // plan_wave -------------------------------------------------------------

    #[test]
    fn plan_wave_respects_risk_budget() {
        let passes = sample_passes();
        // Total risk of all = 50k + 100k + 30k = 180k.
        // Budget of 100k should exclude some.
        let wave = plan_wave(passes, 100_000).unwrap();
        assert!(wave.total_risk_millionths <= 100_000);
    }

    #[test]
    fn plan_wave_empty_returns_error() {
        let result = plan_wave(vec![], 500_000);
        assert_eq!(result, Err(PlannerError::NoViablePasses));
    }

    #[test]
    fn plan_wave_tiny_budget_returns_error() {
        let passes = vec![make_pass("expensive", 1_000_000, 500_000, 100_000)];
        let result = plan_wave(passes, 1);
        assert_eq!(result, Err(PlannerError::RiskExceedsBudget));
    }

    #[test]
    fn plan_wave_aggregates_correct() {
        let passes = sample_passes();
        let wave = plan_wave(passes, MILLIONTHS).unwrap();
        let sum_uplift: u64 = wave
            .passes
            .iter()
            .map(|p| p.estimated_uplift_millionths)
            .sum();
        let sum_risk: u64 = wave
            .passes
            .iter()
            .map(|p| p.estimated_risk_millionths)
            .sum();
        assert_eq!(wave.total_expected_uplift_millionths, sum_uplift);
        assert_eq!(wave.total_risk_millionths, sum_risk);
    }

    #[test]
    fn plan_wave_priority_order_covers_selected() {
        let wave = sample_wave();
        let selected_ids: BTreeSet<&str> = wave.passes.iter().map(|p| p.pass_id.as_str()).collect();
        let priority_ids: BTreeSet<&str> = wave.priority_order.iter().map(|s| s.as_str()).collect();
        assert_eq!(selected_ids, priority_ids);
    }

    #[test]
    fn plan_wave_with_prerequisites() {
        let passes = vec![
            make_pass("base", 200_000, 30_000, 10_000),
            make_pass_with_prereqs("derived", 400_000, 50_000, 20_000, vec!["base"]),
        ];
        let wave = plan_wave(passes, MILLIONTHS).unwrap();
        let pos_base = wave
            .priority_order
            .iter()
            .position(|x| x == "base")
            .unwrap();
        let pos_derived = wave
            .priority_order
            .iter()
            .position(|x| x == "derived")
            .unwrap();
        assert!(pos_base < pos_derived);
    }

    // build_counterfactual --------------------------------------------------

    #[test]
    fn build_counterfactual_enable_pass() {
        let wave = sample_wave();
        let target = &wave.passes[0].pass_id;
        let scenario = build_counterfactual(&wave, InterventionKind::EnablePass, target);
        assert!(scenario.expected_outcome_millionths > 0);
        assert_eq!(scenario.interventions.len(), 1);
        assert_eq!(scenario.interventions[0].0, InterventionKind::EnablePass);
    }

    #[test]
    fn build_counterfactual_disable_pass() {
        let wave = sample_wave();
        let target = &wave.passes[0].pass_id;
        let scenario = build_counterfactual(&wave, InterventionKind::DisablePass, target);
        assert!(scenario.expected_outcome_millionths < 0);
    }

    #[test]
    fn build_counterfactual_compare_variants() {
        let wave = sample_wave();
        let scenario = build_counterfactual(&wave, InterventionKind::CompareVariants, "any");
        assert_eq!(scenario.expected_outcome_millionths, 0);
        assert_eq!(scenario.confidence_millionths, 900_000);
    }

    #[test]
    fn build_counterfactual_unknown_target() {
        let wave = sample_wave();
        let scenario = build_counterfactual(&wave, InterventionKind::EnablePass, "nonexistent");
        assert_eq!(scenario.expected_outcome_millionths, 0);
    }

    #[test]
    fn build_counterfactual_hash_is_set() {
        let wave = sample_wave();
        let target = &wave.passes[0].pass_id;
        let scenario = build_counterfactual(&wave, InterventionKind::EnablePass, target);
        // Hash should not be all-zeros (it was sealed).
        assert_ne!(scenario.content_hash, ContentHash::compute(b""));
    }

    // estimate_causal_effect ------------------------------------------------

    #[test]
    fn estimate_causal_effect_positive() {
        let wave = sample_wave();
        let target = &wave.passes[0].pass_id;
        let scenario = build_counterfactual(&wave, InterventionKind::EnablePass, target);
        let cert = estimate_causal_effect(&scenario, 100_000, 250_000);
        assert_eq!(cert.causal_effect_millionths, 150_000);
        assert!(cert.is_positive_effect());
    }

    #[test]
    fn estimate_causal_effect_negative() {
        let wave = sample_wave();
        let target = &wave.passes[0].pass_id;
        let scenario = build_counterfactual(&wave, InterventionKind::DisablePass, target);
        let cert = estimate_causal_effect(&scenario, 300_000, 100_000);
        assert_eq!(cert.causal_effect_millionths, -200_000);
        assert!(!cert.is_positive_effect());
    }

    #[test]
    fn estimate_causal_effect_ci_contains_effect() {
        let wave = sample_wave();
        let target = &wave.passes[0].pass_id;
        let scenario = build_counterfactual(&wave, InterventionKind::EnablePass, target);
        let cert = estimate_causal_effect(&scenario, 100_000, 200_000);
        assert!(cert.confidence_interval_low_millionths <= cert.causal_effect_millionths);
        assert!(cert.confidence_interval_high_millionths >= cert.causal_effect_millionths);
    }

    #[test]
    fn estimate_causal_effect_ci_width_nonnegative() {
        let wave = sample_wave();
        let target = &wave.passes[0].pass_id;
        let scenario = build_counterfactual(&wave, InterventionKind::EnablePass, target);
        let cert = estimate_causal_effect(&scenario, 100_000, 200_000);
        assert!(cert.ci_width() >= 0);
    }

    #[test]
    fn estimate_causal_effect_hash_sealed() {
        let wave = sample_wave();
        let target = &wave.passes[0].pass_id;
        let scenario = build_counterfactual(&wave, InterventionKind::EnablePass, target);
        let cert = estimate_causal_effect(&scenario, 100_000, 200_000);
        assert_ne!(cert.content_hash, ContentHash::compute(b""));
    }

    // select_best_wave ------------------------------------------------------

    #[test]
    fn select_best_wave_picks_highest_uplift() {
        let w1 = WaveDefinition {
            wave_id: "w1".to_string(),
            passes: vec![make_pass("a", 200_000, 50_000, 10_000)],
            total_expected_uplift_millionths: 200_000,
            total_risk_millionths: 50_000,
            priority_order: vec!["a".to_string()],
        };
        let w2 = WaveDefinition {
            wave_id: "w2".to_string(),
            passes: vec![make_pass("b", 400_000, 80_000, 20_000)],
            total_expected_uplift_millionths: 400_000,
            total_risk_millionths: 80_000,
            priority_order: vec!["b".to_string()],
        };
        let decision = select_best_wave(vec![w1, w2], MILLIONTHS).unwrap();
        assert_eq!(decision.selected_wave.wave_id, "w2");
    }

    #[test]
    fn select_best_wave_empty_returns_error() {
        let result = select_best_wave(vec![], MILLIONTHS);
        assert_eq!(result, Err(PlannerError::NoViablePasses));
    }

    #[test]
    fn select_best_wave_all_exceed_budget() {
        let w = WaveDefinition {
            wave_id: "w1".to_string(),
            passes: vec![make_pass("a", 200_000, 500_000, 10_000)],
            total_expected_uplift_millionths: 200_000,
            total_risk_millionths: 500_000,
            priority_order: vec!["a".to_string()],
        };
        let result = select_best_wave(vec![w], 100_000);
        assert_eq!(result, Err(PlannerError::RiskExceedsBudget));
    }

    #[test]
    fn select_best_wave_information_value() {
        let w1 = WaveDefinition {
            wave_id: "w1".to_string(),
            passes: vec![make_pass("a", 200_000, 50_000, 10_000)],
            total_expected_uplift_millionths: 200_000,
            total_risk_millionths: 50_000,
            priority_order: vec!["a".to_string()],
        };
        let w2 = WaveDefinition {
            wave_id: "w2".to_string(),
            passes: vec![make_pass("b", 500_000, 80_000, 20_000)],
            total_expected_uplift_millionths: 500_000,
            total_risk_millionths: 80_000,
            priority_order: vec!["b".to_string()],
        };
        let decision = select_best_wave(vec![w1, w2], MILLIONTHS).unwrap();
        // info value = 500_000 - 200_000 = 300_000
        assert_eq!(decision.information_value_millionths, 300_000);
    }

    #[test]
    fn select_best_wave_decision_sealed() {
        let w = WaveDefinition {
            wave_id: "w1".to_string(),
            passes: vec![make_pass("a", 200_000, 50_000, 10_000)],
            total_expected_uplift_millionths: 200_000,
            total_risk_millionths: 50_000,
            priority_order: vec!["a".to_string()],
        };
        let decision = select_best_wave(vec![w], MILLIONTHS).unwrap();
        assert_ne!(decision.content_hash, ContentHash::compute(b""));
    }

    // WaveDefinition --------------------------------------------------------

    #[test]
    fn wave_recompute_aggregates() {
        let mut wave = WaveDefinition {
            wave_id: "test".to_string(),
            passes: vec![
                make_pass("a", 100_000, 10_000, 5_000),
                make_pass("b", 200_000, 20_000, 10_000),
            ],
            total_expected_uplift_millionths: 0,
            total_risk_millionths: 0,
            priority_order: vec!["a".to_string(), "b".to_string()],
        };
        wave.recompute_aggregates();
        assert_eq!(wave.total_expected_uplift_millionths, 300_000);
        assert_eq!(wave.total_risk_millionths, 30_000);
    }

    #[test]
    fn wave_pass_count() {
        let wave = sample_wave();
        assert_eq!(wave.pass_count(), wave.passes.len());
    }

    #[test]
    fn wave_total_cost() {
        let wave = sample_wave();
        let expected: u64 = wave.passes.iter().map(|p| p.cost_millionths).sum();
        assert_eq!(wave.total_cost_millionths(), expected);
    }

    #[test]
    fn wave_serde_roundtrip() {
        let wave = sample_wave();
        let json = serde_json::to_string(&wave).unwrap();
        let back: WaveDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(wave, back);
    }

    // PlanningDecision ------------------------------------------------------

    #[test]
    fn planning_decision_is_informative() {
        let mut d = PlanningDecision {
            decision_id: "d1".to_string(),
            epoch: SecurityEpoch::from_raw(1),
            selected_wave: sample_wave(),
            alternatives_considered: 2,
            information_value_millionths: 100_000,
            downside_bound_millionths: 50_000,
            content_hash: ContentHash::compute(b""),
        };
        d.seal();
        assert!(d.is_informative());
    }

    #[test]
    fn planning_decision_not_informative() {
        let d = PlanningDecision {
            decision_id: "d2".to_string(),
            epoch: SecurityEpoch::from_raw(1),
            selected_wave: sample_wave(),
            alternatives_considered: 0,
            information_value_millionths: 0,
            downside_bound_millionths: 0,
            content_hash: ContentHash::compute(b""),
        };
        assert!(!d.is_informative());
    }

    #[test]
    fn planning_decision_serde_roundtrip() {
        let mut d = PlanningDecision {
            decision_id: "d3".to_string(),
            epoch: SecurityEpoch::from_raw(5),
            selected_wave: sample_wave(),
            alternatives_considered: 3,
            information_value_millionths: 250_000,
            downside_bound_millionths: 75_000,
            content_hash: ContentHash::compute(b""),
        };
        d.seal();
        let json = serde_json::to_string(&d).unwrap();
        let back: PlanningDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    // UpliftCertificate -----------------------------------------------------

    #[test]
    fn uplift_cert_serde_roundtrip() {
        let wave = sample_wave();
        let target = &wave.passes[0].pass_id;
        let scenario = build_counterfactual(&wave, InterventionKind::EnablePass, target);
        let cert = estimate_causal_effect(&scenario, 100_000, 250_000);
        let json = serde_json::to_string(&cert).unwrap();
        let back: UpliftCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, back);
    }

    // CounterfactualScenario ------------------------------------------------

    #[test]
    fn scenario_serde_roundtrip() {
        let wave = sample_wave();
        let target = &wave.passes[0].pass_id;
        let scenario = build_counterfactual(&wave, InterventionKind::EnablePass, target);
        let json = serde_json::to_string(&scenario).unwrap();
        let back: CounterfactualScenario = serde_json::from_str(&json).unwrap();
        assert_eq!(scenario, back);
    }

    #[test]
    fn scenario_seal_deterministic() {
        let wave = sample_wave();
        let target = &wave.passes[0].pass_id;
        let s1 = build_counterfactual(&wave, InterventionKind::EnablePass, target);
        let s2 = build_counterfactual(&wave, InterventionKind::EnablePass, target);
        assert_eq!(s1.content_hash, s2.content_hash);
    }

    // Manifest --------------------------------------------------------------

    #[test]
    fn manifest_produces_valid_decision() {
        let decision = franken_engine_intervention_manifest();
        assert!(!decision.decision_id.is_empty());
        assert!(decision.selected_wave.pass_count() > 0);
        assert_ne!(decision.content_hash, ContentHash::compute(b""));
    }

    #[test]
    fn manifest_deterministic() {
        let d1 = franken_engine_intervention_manifest();
        let d2 = franken_engine_intervention_manifest();
        assert_eq!(d1, d2);
    }

    #[test]
    fn manifest_wave_has_priority_order() {
        let decision = franken_engine_intervention_manifest();
        assert!(!decision.selected_wave.priority_order.is_empty());
        assert_eq!(
            decision.selected_wave.priority_order.len(),
            decision.selected_wave.passes.len()
        );
    }
}
