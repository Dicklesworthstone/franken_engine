//! Deterministic hot-path profiling and tier-up eligibility policy.
//!
//! This module consumes `bytecode_vm::ExecutionReport` traces and derives a
//! replay-stable hotspot profile plus tier-up candidate decisions.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bytecode_vm::{ExecutionReport, VmEvent};

const COMPONENT: &str = "tier_up_profiler";
const MILLIONTHS_DENOMINATOR: u64 = 1_000_000;

pub const TIER_UP_POLICY_SCHEMA_VERSION: &str = "franken-engine.tier-up-policy.v1";

/// Deterministic policy for deciding tier-up eligibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierUpPolicy {
    pub policy_id: String,
    pub min_total_steps: u64,
    pub min_invocations_per_path: u64,
    pub min_cache_hit_rate_millionths: i64,
    pub max_candidates: usize,
    pub profile_top_k: usize,
    pub require_cache_signal: bool,
}

impl Default for TierUpPolicy {
    fn default() -> Self {
        Self {
            policy_id: "policy-tier-up-v1".to_string(),
            min_total_steps: 64,
            min_invocations_per_path: 16,
            min_cache_hit_rate_millionths: 600_000,
            max_candidates: 4,
            profile_top_k: 16,
            require_cache_signal: true,
        }
    }
}

impl TierUpPolicy {
    pub fn policy_hash(&self) -> String {
        sha256_hex(self)
    }
}

#[derive(Debug, Clone)]
struct PathAccumulator {
    ip: u32,
    opcode: String,
    invocations: u64,
    cache_hits: u64,
    cache_misses: u64,
}

/// One deterministic hot-path aggregate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotPathSample {
    pub ip: u32,
    pub opcode: String,
    pub invocations: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_hit_rate_millionths: i64,
}

impl HotPathSample {
    fn cache_observations(&self) -> u64 {
        self.cache_hits.saturating_add(self.cache_misses)
    }
}

/// Deterministic profile derived from VM execution events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotPathProfile {
    pub trace_id: String,
    pub total_steps: u64,
    pub observed_instruction_events: u64,
    pub top_paths: Vec<HotPathSample>,
    pub profile_hash: String,
}

/// Tier-up candidate admitted by policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierUpCandidate {
    pub ip: u32,
    pub opcode: String,
    pub invocations: u64,
    pub cache_hit_rate_millionths: i64,
    pub rationale: String,
}

impl TierUpCandidate {
    /// Deterministic candidate identifier for downstream compilation planning.
    pub fn candidate_id(&self, trace_id: &str) -> String {
        #[derive(Serialize)]
        struct CandidateEnvelope<'a> {
            trace_id: &'a str,
            ip: u32,
            opcode: &'a str,
            invocations: u64,
            cache_hit_rate_millionths: i64,
        }

        let digest = sha256_hex(&CandidateEnvelope {
            trace_id,
            ip: self.ip,
            opcode: &self.opcode,
            invocations: self.invocations,
            cache_hit_rate_millionths: self.cache_hit_rate_millionths,
        });
        format!("tc-{}", &digest[..16])
    }
}

/// Path rejected by the policy with explicit reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierUpRejection {
    pub ip: u32,
    pub opcode: String,
    pub invocations: u64,
    pub cache_hit_rate_millionths: i64,
    pub reason: String,
}

/// Structured tier-up decision event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierUpDecisionEvent {
    pub trace_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub reason: String,
}

/// Final deterministic tier-up decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierUpDecision {
    pub schema_version: String,
    pub trace_id: String,
    pub policy_hash: String,
    pub eligible: bool,
    pub selected_candidates: Vec<TierUpCandidate>,
    pub rejected_paths: Vec<TierUpRejection>,
    pub profile: HotPathProfile,
    pub decision_hash: String,
    pub events: Vec<TierUpDecisionEvent>,
}

/// Build a deterministic hot-path profile from a VM execution report.
pub fn build_hot_path_profile(report: &ExecutionReport, top_k: usize) -> HotPathProfile {
    let mut aggregates = BTreeMap::<(u32, String), PathAccumulator>::new();
    let mut observed_instruction_events = 0u64;

    for event in &report.events {
        if !is_tiering_candidate_event(event) {
            continue;
        }

        observed_instruction_events = observed_instruction_events.saturating_add(1);
        let key = (event.ip, event.opcode.clone());
        let entry = aggregates.entry(key).or_insert_with(|| PathAccumulator {
            ip: event.ip,
            opcode: event.opcode.clone(),
            invocations: 0,
            cache_hits: 0,
            cache_misses: 0,
        });

        entry.invocations = entry.invocations.saturating_add(1);
        match event.cache_hit {
            Some(true) => entry.cache_hits = entry.cache_hits.saturating_add(1),
            Some(false) => entry.cache_misses = entry.cache_misses.saturating_add(1),
            None => {}
        }
    }

    let mut top_paths = aggregates
        .into_values()
        .map(|entry| HotPathSample {
            ip: entry.ip,
            opcode: entry.opcode,
            invocations: entry.invocations,
            cache_hits: entry.cache_hits,
            cache_misses: entry.cache_misses,
            cache_hit_rate_millionths: cache_hit_rate_millionths(
                entry.cache_hits,
                entry.cache_misses,
            ),
        })
        .collect::<Vec<_>>();

    top_paths.sort_by(|left, right| {
        right
            .invocations
            .cmp(&left.invocations)
            .then_with(|| left.ip.cmp(&right.ip))
            .then_with(|| left.opcode.cmp(&right.opcode))
    });
    top_paths.truncate(normalize_limit(top_k));

    #[derive(Serialize)]
    struct ProfileEnvelope<'a> {
        trace_id: &'a str,
        total_steps: u64,
        observed_instruction_events: u64,
        top_paths: &'a [HotPathSample],
    }

    let profile_hash = sha256_hex(&ProfileEnvelope {
        trace_id: &report.trace_id,
        total_steps: report.steps,
        observed_instruction_events,
        top_paths: &top_paths,
    });

    HotPathProfile {
        trace_id: report.trace_id.clone(),
        total_steps: report.steps,
        observed_instruction_events,
        top_paths,
        profile_hash,
    }
}

/// Evaluate deterministic tier-up eligibility for one report and policy.
pub fn evaluate_tier_up_eligibility(
    report: &ExecutionReport,
    policy: &TierUpPolicy,
) -> TierUpDecision {
    let profile = build_hot_path_profile(report, policy.profile_top_k);
    let policy_hash = policy.policy_hash();
    let mut selected_candidates = Vec::<TierUpCandidate>::new();
    let mut rejected_paths = Vec::<TierUpRejection>::new();
    let mut events = vec![make_event(
        &report.trace_id,
        "tier_up_started",
        "pass",
        "tier_up_policy_evaluation_started",
    )];

    if report.steps < policy.min_total_steps {
        events.push(make_event(
            &report.trace_id,
            "tier_up_completed",
            "deny",
            "insufficient_total_steps",
        ));

        let mut decision = TierUpDecision {
            schema_version: TIER_UP_POLICY_SCHEMA_VERSION.to_string(),
            trace_id: report.trace_id.clone(),
            policy_hash,
            eligible: false,
            selected_candidates,
            rejected_paths,
            profile,
            decision_hash: String::new(),
            events,
        };
        decision.decision_hash = compute_decision_hash(&decision);
        return decision;
    }

    for path in &profile.top_paths {
        if path.invocations < policy.min_invocations_per_path {
            rejected_paths.push(TierUpRejection {
                ip: path.ip,
                opcode: path.opcode.clone(),
                invocations: path.invocations,
                cache_hit_rate_millionths: path.cache_hit_rate_millionths,
                reason: "insufficient_invocations".to_string(),
            });
            continue;
        }

        let cache_observations = path.cache_observations();
        if policy.require_cache_signal && cache_observations == 0 {
            rejected_paths.push(TierUpRejection {
                ip: path.ip,
                opcode: path.opcode.clone(),
                invocations: path.invocations,
                cache_hit_rate_millionths: path.cache_hit_rate_millionths,
                reason: "missing_cache_signal".to_string(),
            });
            continue;
        }

        if cache_observations > 0
            && path.cache_hit_rate_millionths < policy.min_cache_hit_rate_millionths
        {
            rejected_paths.push(TierUpRejection {
                ip: path.ip,
                opcode: path.opcode.clone(),
                invocations: path.invocations,
                cache_hit_rate_millionths: path.cache_hit_rate_millionths,
                reason: "cache_hit_rate_below_threshold".to_string(),
            });
            continue;
        }

        selected_candidates.push(TierUpCandidate {
            ip: path.ip,
            opcode: path.opcode.clone(),
            invocations: path.invocations,
            cache_hit_rate_millionths: path.cache_hit_rate_millionths,
            rationale: "hot_path_meets_tier_up_thresholds".to_string(),
        });
    }

    selected_candidates.truncate(normalize_limit(policy.max_candidates));
    let eligible = !selected_candidates.is_empty();

    events.push(make_event(
        &report.trace_id,
        "tier_up_completed",
        if eligible { "allow" } else { "deny" },
        if eligible {
            "eligible_candidates_found"
        } else {
            "no_candidates_met_policy"
        },
    ));

    let mut decision = TierUpDecision {
        schema_version: TIER_UP_POLICY_SCHEMA_VERSION.to_string(),
        trace_id: report.trace_id.clone(),
        policy_hash,
        eligible,
        selected_candidates,
        rejected_paths,
        profile,
        decision_hash: String::new(),
        events,
    };
    decision.decision_hash = compute_decision_hash(&decision);
    decision
}

fn compute_decision_hash(decision: &TierUpDecision) -> String {
    #[derive(Serialize)]
    struct DecisionEnvelope<'a> {
        schema_version: &'a str,
        trace_id: &'a str,
        policy_hash: &'a str,
        eligible: bool,
        selected_candidates: &'a [TierUpCandidate],
        rejected_paths: &'a [TierUpRejection],
        profile: &'a HotPathProfile,
        events: &'a [TierUpDecisionEvent],
    }

    sha256_hex(&DecisionEnvelope {
        schema_version: &decision.schema_version,
        trace_id: &decision.trace_id,
        policy_hash: &decision.policy_hash,
        eligible: decision.eligible,
        selected_candidates: &decision.selected_candidates,
        rejected_paths: &decision.rejected_paths,
        profile: &decision.profile,
        events: &decision.events,
    })
}

fn cache_hit_rate_millionths(cache_hits: u64, cache_misses: u64) -> i64 {
    let observed = u128::from(cache_hits) + u128::from(cache_misses);
    if observed == 0 {
        return 0;
    }

    ((u128::from(cache_hits) * u128::from(MILLIONTHS_DENOMINATOR)) / observed) as i64
}

fn is_tiering_candidate_event(event: &VmEvent) -> bool {
    event.event == "instruction"
        && event.outcome == "ok"
        && event.opcode != "budget"
        && event.opcode != "eof"
}

fn make_event(trace_id: &str, event: &str, outcome: &str, reason: &str) -> TierUpDecisionEvent {
    TierUpDecisionEvent {
        trace_id: trace_id.to_string(),
        component: COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        reason: reason.to_string(),
    }
}

fn normalize_limit(value: usize) -> usize {
    value
}

fn sha256_hex<T: Serialize>(value: &T) -> String {
    // SAFETY: serde_json::to_vec only fails on writer errors, not possible with Vec<u8>
    let payload = serde_json::to_vec(value).expect("serde deserialization should succeed");
    let digest = Sha256::digest(payload);
    hex::encode(digest)
}

// ===========================================================================
// RGC-608C: Bounded-Regret and Operator-Override Safety Case
// ===========================================================================

/// Bounded-regret policy to limit performance regression risk from tier-up decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedRegretPolicy {
    /// Maximum allowed regression ratio (millionths) before forced deopt.
    pub max_regression_ratio_millionths: u64,
    /// Window size for regression measurement (number of invocations).
    pub regression_measurement_window: u64,
    /// Cooldown period (invocations) after deopt before re-tier-up allowed.
    pub deopt_cooldown_invocations: u64,
    /// Maximum number of deopt events before tier permanently disabled.
    pub max_deopt_events: u32,
}

impl Default for BoundedRegretPolicy {
    fn default() -> Self {
        Self {
            max_regression_ratio_millionths: 200_000, // 20% max regression
            regression_measurement_window: 1000,
            deopt_cooldown_invocations: 5000,
            max_deopt_events: 3,
        }
    }
}

/// Performance regression measurement for bounded-regret analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionMeasurement {
    pub baseline_performance_score: u64,
    pub current_performance_score: u64,
    pub regression_ratio_millionths: i64, // Can be negative (improvement)
    pub measurement_window_invocations: u64,
    pub exceeds_threshold: bool,
}

impl RegressionMeasurement {
    /// Calculate regression ratio in millionths.
    /// Positive = regression (slower), negative = improvement (faster).
    pub fn calculate_regression(
        baseline_score: u64,
        current_score: u64,
        window_invocations: u64,
    ) -> Self {
        let regression_ratio_millionths = if baseline_score == 0 {
            0 // No baseline to compare against
        } else {
            let diff = i128::from(current_score) - i128::from(baseline_score);
            let ratio = (diff * i128::from(MILLIONTHS_DENOMINATOR)) / i128::from(baseline_score);
            clamp_i128_to_i64(ratio)
        };

        Self {
            baseline_performance_score: baseline_score,
            current_performance_score: current_score,
            regression_ratio_millionths,
            measurement_window_invocations: window_invocations,
            exceeds_threshold: regression_ratio_millionths > 0, // Default threshold
        }
    }

    /// Check if regression exceeds policy threshold.
    pub fn exceeds_policy_threshold(&self, policy: &BoundedRegretPolicy) -> bool {
        let max_regression_ratio_millionths =
            i64::try_from(policy.max_regression_ratio_millionths).unwrap_or(i64::MAX);
        self.regression_ratio_millionths > max_regression_ratio_millionths
    }
}

/// Operator override for manual tier control in production scenarios.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorOverride {
    /// Override ID for audit trail.
    pub override_id: String,
    /// Target function/path IP address.
    pub target_ip: u32,
    /// Forced tier (None = remove override).
    pub forced_tier: Option<String>,
    /// Operator reason for override.
    pub reason: String,
    /// Override expiration time (Unix timestamp).
    pub expires_at: u64,
    /// Security epoch when override was created.
    pub security_epoch: u32,
    /// Hash of override for integrity verification.
    pub override_hash: String,
}

impl OperatorOverride {
    /// Create new operator override with integrity hash.
    pub fn new(
        target_ip: u32,
        forced_tier: Option<String>,
        reason: String,
        expires_at: u64,
        security_epoch: u32,
    ) -> Self {
        let override_id = format!("override-{}-{}", target_ip, expires_at);

        let mut override_obj = Self {
            override_id: override_id.clone(),
            target_ip,
            forced_tier,
            reason,
            expires_at,
            security_epoch,
            override_hash: String::new(),
        };

        override_obj.override_hash = sha256_hex(&override_obj);
        override_obj
    }

    /// Check if override is still valid (not expired).
    pub fn is_valid(&self, current_time: u64) -> bool {
        current_time < self.expires_at
    }

    /// Verify override integrity.
    pub fn verify_integrity(&self) -> bool {
        let mut temp = self.clone();
        temp.override_hash = String::new();
        let expected_hash = sha256_hex(&temp);
        expected_hash == self.override_hash
    }
}

/// Safety evaluation result combining bounded-regret and operator-override analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyEvaluation {
    pub tier_up_decision: TierUpDecision,
    pub regression_measurements: Vec<RegressionMeasurement>,
    pub active_overrides: Vec<OperatorOverride>,
    pub safety_verdict: SafetyVerdict,
    pub safety_reasoning: String,
}

/// Safety verdict for tier-up decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyVerdict {
    /// Safe to proceed with tier-up.
    Safe,
    /// Blocked due to regression risk.
    BlockedRegression,
    /// Blocked by operator override.
    BlockedOverride,
    /// Forced tier-up by operator override.
    ForcedOverride,
}

/// Evaluate tier-up safety with bounded-regret and operator-override policies.
pub fn evaluate_tier_up_safety(
    report: &ExecutionReport,
    tier_policy: &TierUpPolicy,
    regret_policy: &BoundedRegretPolicy,
    active_overrides: &[OperatorOverride],
    current_time: u64,
) -> SafetyEvaluation {
    // Base tier-up evaluation
    let tier_up_decision = evaluate_tier_up_eligibility(report, tier_policy);

    // Check for active operator overrides
    let valid_overrides: Vec<OperatorOverride> = active_overrides
        .iter()
        .filter(|o| o.is_valid(current_time) && o.verify_integrity())
        .cloned()
        .collect();

    // Check if any candidates are overridden
    for candidate in &tier_up_decision.selected_candidates {
        for override_obj in &valid_overrides {
            if override_obj.target_ip == candidate.ip {
                return SafetyEvaluation {
                    tier_up_decision,
                    regression_measurements: Vec::new(),
                    active_overrides: valid_overrides.clone(),
                    safety_verdict: if override_obj.forced_tier.is_some() {
                        SafetyVerdict::ForcedOverride
                    } else {
                        SafetyVerdict::BlockedOverride
                    },
                    safety_reasoning: format!(
                        "Operator override {} active: {}",
                        override_obj.override_id, override_obj.reason
                    ),
                };
            }
        }
    }

    if !tier_up_decision.selected_candidates.is_empty() {
        return SafetyEvaluation {
            tier_up_decision,
            regression_measurements: Vec::new(),
            active_overrides: valid_overrides,
            safety_verdict: SafetyVerdict::BlockedRegression,
            safety_reasoning: format!(
                "missing real regression measurements for bounded-regret window {}; tier-up safety cannot be established from ExecutionReport alone",
                regret_policy.regression_measurement_window
            ),
        };
    }

    SafetyEvaluation {
        tier_up_decision,
        regression_measurements: Vec::new(),
        active_overrides: valid_overrides,
        safety_verdict: SafetyVerdict::Safe,
        safety_reasoning: "All safety checks passed".to_string(),
    }
}

fn clamp_i128_to_i64(value: i128) -> i64 {
    if value > i128::from(i64::MAX) {
        i64::MAX
    } else if value < i128::from(i64::MIN) {
        i64::MIN
    } else {
        value as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bytecode_vm::{ExecutionReport, InlineCacheStats, Value, VmEvent},
        shape_transition_algebra::ShapeTransitionAlgebra,
    };

    fn make_vm_event(ip: u32, opcode: &str, cache_hit: Option<bool>) -> VmEvent {
        VmEvent {
            trace_id: "test-trace".to_string(),
            component: "bytecode_vm".to_string(),
            step: 0,
            ip,
            opcode: opcode.to_string(),
            event: "instruction".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            cache_hit,
        }
    }

    fn make_report(steps: u64, events: Vec<VmEvent>) -> ExecutionReport {
        ExecutionReport {
            trace_id: "test-trace".to_string(),
            result: Value::Int(0),
            steps,
            cache_stats: InlineCacheStats {
                entries: 0,
                hits: 0,
                misses: 0,
            },
            state_hash: String::new(),
            events,
            shape_lattice: ShapeTransitionAlgebra::new().manifest(),
            shape_trace: Vec::new(),
        }
    }

    fn repeated_events(
        ip: u32,
        opcode: &str,
        count: usize,
        cache_hit: Option<bool>,
    ) -> Vec<VmEvent> {
        (0..count)
            .map(|_| make_vm_event(ip, opcode, cache_hit))
            .collect()
    }

    // -- TierUpPolicy tests --------------------------------------------------

    #[test]
    fn policy_default_has_sensible_values() {
        let policy = TierUpPolicy::default();
        assert_eq!(policy.min_total_steps, 64);
        assert_eq!(policy.min_invocations_per_path, 16);
        assert_eq!(policy.min_cache_hit_rate_millionths, 600_000);
        assert_eq!(policy.max_candidates, 4);
        assert_eq!(policy.profile_top_k, 16);
        assert!(policy.require_cache_signal);
    }

    #[test]
    fn policy_hash_is_deterministic() {
        let a = TierUpPolicy::default().policy_hash();
        let b = TierUpPolicy::default().policy_hash();
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn policy_hash_changes_with_config() {
        let mut policy = TierUpPolicy::default();
        let h1 = policy.policy_hash();
        policy.min_total_steps = 128;
        let h2 = policy.policy_hash();
        assert_ne!(h1, h2);
    }

    // -- cache_hit_rate_millionths tests --------------------------------------

    #[test]
    fn cache_hit_rate_zero_observations() {
        assert_eq!(cache_hit_rate_millionths(0, 0), 0);
    }

    #[test]
    fn cache_hit_rate_all_hits() {
        assert_eq!(cache_hit_rate_millionths(100, 0), 1_000_000);
    }

    #[test]
    fn cache_hit_rate_all_misses() {
        assert_eq!(cache_hit_rate_millionths(0, 100), 0);
    }

    #[test]
    fn cache_hit_rate_half() {
        assert_eq!(cache_hit_rate_millionths(50, 50), 500_000);
    }

    // -- is_tiering_candidate_event tests ------------------------------------

    #[test]
    fn tiering_candidate_event_normal_instruction() {
        let event = make_vm_event(0, "load_const", None);
        assert!(is_tiering_candidate_event(&event));
    }

    #[test]
    fn tiering_candidate_event_budget_excluded() {
        let mut event = make_vm_event(0, "budget", None);
        event.event = "instruction".to_string();
        assert!(!is_tiering_candidate_event(&event));
    }

    #[test]
    fn tiering_candidate_event_eof_excluded() {
        let event = make_vm_event(0, "eof", None);
        assert!(!is_tiering_candidate_event(&event));
    }

    #[test]
    fn tiering_candidate_event_non_instruction_excluded() {
        let mut event = make_vm_event(0, "add", None);
        event.event = "error".to_string();
        assert!(!is_tiering_candidate_event(&event));
    }

    #[test]
    fn tiering_candidate_event_non_ok_excluded() {
        let mut event = make_vm_event(0, "add", None);
        event.outcome = "error".to_string();
        assert!(!is_tiering_candidate_event(&event));
    }

    // -- build_hot_path_profile tests ----------------------------------------

    #[test]
    fn profile_empty_report() {
        let report = make_report(0, vec![]);
        let profile = build_hot_path_profile(&report, 10);
        assert_eq!(profile.total_steps, 0);
        assert_eq!(profile.observed_instruction_events, 0);
        assert!(profile.top_paths.is_empty());
        assert!(!profile.profile_hash.is_empty());
    }

    #[test]
    fn profile_aggregates_invocations() {
        let events = vec![
            make_vm_event(0, "add", Some(true)),
            make_vm_event(0, "add", Some(true)),
            make_vm_event(0, "add", Some(false)),
            make_vm_event(1, "mul", Some(true)),
        ];
        let report = make_report(100, events);
        let profile = build_hot_path_profile(&report, 10);

        assert_eq!(profile.observed_instruction_events, 4);
        assert_eq!(profile.top_paths.len(), 2);
        // add@0 has 3 invocations, mul@1 has 1
        assert_eq!(profile.top_paths[0].ip, 0);
        assert_eq!(profile.top_paths[0].opcode, "add");
        assert_eq!(profile.top_paths[0].invocations, 3);
        assert_eq!(profile.top_paths[0].cache_hits, 2);
        assert_eq!(profile.top_paths[0].cache_misses, 1);
    }

    #[test]
    fn profile_sorts_by_invocation_count_desc() {
        let mut events = vec![];
        for _ in 0..5 {
            events.push(make_vm_event(0, "load", Some(true)));
        }
        for _ in 0..10 {
            events.push(make_vm_event(1, "add", Some(true)));
        }
        let report = make_report(100, events);
        let profile = build_hot_path_profile(&report, 10);

        assert_eq!(profile.top_paths[0].ip, 1); // add@1 has 10
        assert_eq!(profile.top_paths[1].ip, 0); // load@0 has 5
    }

    #[test]
    fn profile_truncates_to_top_k() {
        let mut events = vec![];
        for ip in 0..20u32 {
            events.push(make_vm_event(ip, "load", Some(true)));
        }
        let report = make_report(100, events);
        let profile = build_hot_path_profile(&report, 3);
        assert_eq!(profile.top_paths.len(), 3);
    }

    #[test]
    fn profile_hash_is_deterministic() {
        let events = vec![
            make_vm_event(0, "add", Some(true)),
            make_vm_event(1, "mul", None),
        ];
        let r1 = make_report(50, events.clone());
        let r2 = make_report(50, events);
        let p1 = build_hot_path_profile(&r1, 10);
        let p2 = build_hot_path_profile(&r2, 10);
        assert_eq!(p1.profile_hash, p2.profile_hash);
    }

    #[test]
    fn profile_cache_hit_rate_computed() {
        let events = vec![
            make_vm_event(0, "load_prop", Some(true)),
            make_vm_event(0, "load_prop", Some(true)),
            make_vm_event(0, "load_prop", Some(false)),
        ];
        let report = make_report(50, events);
        let profile = build_hot_path_profile(&report, 10);
        // 2 hits / 3 total = 666666 millionths
        assert_eq!(profile.top_paths[0].cache_hit_rate_millionths, 666_666);
    }

    // -- evaluate_tier_up_eligibility tests ----------------------------------

    #[test]
    fn eligibility_insufficient_steps() {
        let report = make_report(10, vec![]); // only 10 steps
        let policy = TierUpPolicy::default(); // requires 64
        let decision = evaluate_tier_up_eligibility(&report, &policy);
        assert!(!decision.eligible);
        assert!(decision.selected_candidates.is_empty());
        assert!(
            decision
                .events
                .iter()
                .any(|e| e.reason == "insufficient_total_steps")
        );
    }

    #[test]
    fn eligibility_no_candidates_found() {
        // Enough steps but paths have too few invocations.
        let mut events = vec![];
        for ip in 0..5u32 {
            events.push(make_vm_event(ip, "load", Some(true)));
        }
        let report = make_report(100, events);
        let policy = TierUpPolicy {
            min_invocations_per_path: 10, // each path only has 1
            ..TierUpPolicy::default()
        };
        let decision = evaluate_tier_up_eligibility(&report, &policy);
        assert!(!decision.eligible);
        assert!(!decision.rejected_paths.is_empty());
    }

    #[test]
    fn eligibility_hot_path_admitted() {
        let mut events = vec![];
        for _ in 0..20 {
            events.push(make_vm_event(0, "load_prop", Some(true)));
        }
        let report = make_report(100, events);
        let policy = TierUpPolicy {
            min_total_steps: 10,
            min_invocations_per_path: 5,
            min_cache_hit_rate_millionths: 500_000,
            max_candidates: 4,
            profile_top_k: 16,
            require_cache_signal: true,
            ..TierUpPolicy::default()
        };
        let decision = evaluate_tier_up_eligibility(&report, &policy);
        assert!(decision.eligible);
        assert_eq!(decision.selected_candidates.len(), 1);
        assert_eq!(decision.selected_candidates[0].ip, 0);
        assert_eq!(decision.selected_candidates[0].opcode, "load_prop");
    }

    #[test]
    fn eligibility_low_cache_hit_rate_rejected() {
        let mut events = vec![];
        for _ in 0..20 {
            events.push(make_vm_event(0, "load_prop", Some(false))); // all misses
        }
        let report = make_report(100, events);
        let policy = TierUpPolicy {
            min_total_steps: 10,
            min_invocations_per_path: 5,
            min_cache_hit_rate_millionths: 500_000,
            ..TierUpPolicy::default()
        };
        let decision = evaluate_tier_up_eligibility(&report, &policy);
        assert!(!decision.eligible);
        assert!(
            decision
                .rejected_paths
                .iter()
                .any(|r| r.reason == "cache_hit_rate_below_threshold")
        );
    }

    #[test]
    fn eligibility_missing_cache_signal_rejected() {
        let mut events = vec![];
        for _ in 0..20 {
            events.push(make_vm_event(0, "add", None)); // no cache signal
        }
        let report = make_report(100, events);
        let policy = TierUpPolicy {
            min_total_steps: 10,
            min_invocations_per_path: 5,
            require_cache_signal: true,
            ..TierUpPolicy::default()
        };
        let decision = evaluate_tier_up_eligibility(&report, &policy);
        assert!(!decision.eligible);
        assert!(
            decision
                .rejected_paths
                .iter()
                .any(|r| r.reason == "missing_cache_signal")
        );
    }

    #[test]
    fn eligibility_cache_signal_not_required() {
        let mut events = vec![];
        for _ in 0..20 {
            events.push(make_vm_event(0, "add", None)); // no cache signal
        }
        let report = make_report(100, events);
        let policy = TierUpPolicy {
            min_total_steps: 10,
            min_invocations_per_path: 5,
            min_cache_hit_rate_millionths: 0,
            require_cache_signal: false,
            ..TierUpPolicy::default()
        };
        let decision = evaluate_tier_up_eligibility(&report, &policy);
        assert!(decision.eligible);
        assert_eq!(decision.selected_candidates.len(), 1);
    }

    #[test]
    fn eligibility_max_candidates_enforced() {
        let mut events = vec![];
        for ip in 0..10u32 {
            for _ in 0..20 {
                events.push(make_vm_event(ip, "load_prop", Some(true)));
            }
        }
        let report = make_report(300, events);
        let policy = TierUpPolicy {
            min_total_steps: 10,
            min_invocations_per_path: 5,
            min_cache_hit_rate_millionths: 500_000,
            max_candidates: 3,
            profile_top_k: 16,
            require_cache_signal: true,
            ..TierUpPolicy::default()
        };
        let decision = evaluate_tier_up_eligibility(&report, &policy);
        assert!(decision.eligible);
        assert!(decision.selected_candidates.len() <= 3);
    }

    #[test]
    fn decision_hash_is_deterministic() {
        let events: Vec<VmEvent> = (0..20)
            .map(|_| make_vm_event(0, "load_prop", Some(true)))
            .collect();
        let r1 = make_report(100, events.clone());
        let r2 = make_report(100, events);
        let policy = TierUpPolicy::default();
        let d1 = evaluate_tier_up_eligibility(&r1, &policy);
        let d2 = evaluate_tier_up_eligibility(&r2, &policy);
        assert_eq!(d1.decision_hash, d2.decision_hash);
        assert!(!d1.decision_hash.is_empty());
    }

    #[test]
    fn decision_schema_version() {
        let report = make_report(100, vec![]);
        let policy = TierUpPolicy::default();
        let decision = evaluate_tier_up_eligibility(&report, &policy);
        assert_eq!(decision.schema_version, TIER_UP_POLICY_SCHEMA_VERSION);
    }

    // -- Serde roundtrip tests -----------------------------------------------

    #[test]
    fn tier_up_policy_serde_roundtrip() {
        let policy = TierUpPolicy::default();
        // SAFETY: TierUpPolicy derives Serialize and has no non-serializable fields.
        // to_string on derived Serialize types only fails on writer errors (impossible with String).
        let json = serde_json::to_string(&policy).expect("serde deserialization should succeed");
        // SAFETY: JSON was just produced by to_string of a valid TierUpPolicy,
        // so from_str back to TierUpPolicy cannot fail (valid format + matching schema).
        let restored: TierUpPolicy =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(policy, restored);
    }

    #[test]
    fn hot_path_sample_serde_roundtrip() {
        let sample = HotPathSample {
            ip: 42,
            opcode: "load_prop".to_string(),
            invocations: 100,
            cache_hits: 80,
            cache_misses: 20,
            cache_hit_rate_millionths: 800_000,
        };
        // SAFETY: HotPathSample derives Serialize and has no non-serializable fields.
        // to_string on derived Serialize types only fails on writer errors (impossible with String).
        let json = serde_json::to_string(&sample).expect("serde deserialization should succeed");
        // SAFETY: JSON was just produced by to_string of a valid HotPathSample,
        // so from_str back to HotPathSample cannot fail (valid format + matching schema).
        let restored: HotPathSample =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(sample, restored);
    }

    #[test]
    fn tier_up_decision_serde_roundtrip() {
        let events: Vec<VmEvent> = (0..20)
            .map(|_| make_vm_event(0, "load_prop", Some(true)))
            .collect();
        let report = make_report(100, events);
        let policy = TierUpPolicy::default();
        let decision = evaluate_tier_up_eligibility(&report, &policy);
        // SAFETY: TierUpDecision derives Serialize and has no non-serializable fields
        let json = serde_json::to_string(&decision).expect("serde deserialization should succeed");
        // SAFETY: JSON was just generated from TierUpDecision, deserialization guaranteed to succeed
        let restored: TierUpDecision =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(decision, restored);
    }

    // -- normalize_limit tests -----------------------------------------------

    #[test]
    fn normalize_limit_zero_stays_zero() {
        assert_eq!(normalize_limit(0), 0);
    }

    #[test]
    fn normalize_limit_nonzero_unchanged() {
        assert_eq!(normalize_limit(5), 5);
    }

    // -- HotPathSample tests -------------------------------------------------

    #[test]
    fn hot_path_sample_cache_observations() {
        let sample = HotPathSample {
            ip: 0,
            opcode: "test".to_string(),
            invocations: 100,
            cache_hits: 30,
            cache_misses: 10,
            cache_hit_rate_millionths: 750_000,
        };
        assert_eq!(sample.cache_observations(), 40);
    }

    #[test]
    fn hot_path_sample_cache_observations_saturates() {
        let sample = HotPathSample {
            ip: 0,
            opcode: "test".to_string(),
            invocations: u64::MAX,
            cache_hits: u64::MAX,
            cache_misses: 1,
            cache_hit_rate_millionths: 1_000_000,
        };

        assert_eq!(sample.cache_observations(), u64::MAX);
    }

    // -- make_event tests ----------------------------------------------------

    #[test]
    fn make_event_populates_all_fields() {
        let event = make_event("trace-1", "test_event", "pass", "test_reason");
        assert_eq!(event.trace_id, "trace-1");
        assert_eq!(event.component, COMPONENT);
        assert_eq!(event.event, "test_event");
        assert_eq!(event.outcome, "pass");
        assert_eq!(event.reason, "test_reason");
    }

    // -- Enrichment tests ---------------------------------------------------

    #[test]
    fn policy_default_serde_roundtrip() {
        let policy = TierUpPolicy::default();
        // SAFETY: TierUpPolicy derives Serialize and has no non-serializable fields
        let json = serde_json::to_string(&policy).expect("serde deserialization should succeed");
        // SAFETY: JSON was just generated from TierUpPolicy, deserialization guaranteed to succeed
        let back: TierUpPolicy =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(policy, back);
    }

    #[test]
    fn policy_hash_changes_with_min_steps() {
        let a = TierUpPolicy::default();
        let b = TierUpPolicy {
            min_total_steps: a.min_total_steps + 1,
            ..a.clone()
        };
        assert_ne!(a.policy_hash(), b.policy_hash());
    }

    #[test]
    fn profile_observed_events_counts_only_candidates() {
        let events = vec![
            make_vm_event(0, "add", None),
            make_vm_event(1, "budget", None), // excluded
            make_vm_event(2, "eof", None),    // excluded
        ];
        let report = make_report(100, events);
        let profile = build_hot_path_profile(&report, 10);
        assert_eq!(profile.observed_instruction_events, 1);
    }

    #[test]
    fn profile_aggregates_same_ip_opcode() {
        let events = vec![
            make_vm_event(5, "load", Some(true)),
            make_vm_event(5, "load", Some(false)),
            make_vm_event(5, "load", None),
        ];
        let report = make_report(100, events);
        let profile = build_hot_path_profile(&report, 10);
        assert_eq!(profile.top_paths.len(), 1);
        let path = &profile.top_paths[0];
        assert_eq!(path.invocations, 3);
        assert_eq!(path.cache_hits, 1);
        assert_eq!(path.cache_misses, 1);
    }

    #[test]
    fn profile_different_opcodes_at_same_ip_are_separate() {
        let events = vec![
            make_vm_event(5, "load", None),
            make_vm_event(5, "store", None),
        ];
        let report = make_report(100, events);
        let profile = build_hot_path_profile(&report, 10);
        assert_eq!(profile.top_paths.len(), 2);
    }

    #[test]
    fn profile_top_k_zero_returns_empty_profile() {
        let events = vec![make_vm_event(0, "a", None), make_vm_event(1, "b", None)];
        let report = make_report(100, events);
        let profile = build_hot_path_profile(&report, 0);
        assert!(profile.top_paths.is_empty());
    }

    #[test]
    fn profile_total_steps_matches_report() {
        let report = make_report(42, Vec::new());
        let profile = build_hot_path_profile(&report, 10);
        assert_eq!(profile.total_steps, 42);
    }

    #[test]
    fn profile_trace_id_propagated() {
        let report = make_report(10, Vec::new());
        let profile = build_hot_path_profile(&report, 10);
        assert_eq!(profile.trace_id, report.trace_id);
    }

    #[test]
    fn profile_tiebreak_by_ip_for_equal_invocations() {
        let events = vec![make_vm_event(10, "op", None), make_vm_event(5, "op", None)];
        let report = make_report(100, events);
        let profile = build_hot_path_profile(&report, 10);
        // Equal invocations, tiebreak ascending by ip
        assert_eq!(profile.top_paths[0].ip, 5);
        assert_eq!(profile.top_paths[1].ip, 10);
    }

    #[test]
    fn eligibility_events_include_started_and_completed() {
        let events = vec![
            make_vm_event(0, "add", Some(true)),
            make_vm_event(0, "add", Some(true)),
            make_vm_event(0, "add", Some(true)),
        ];
        let report = make_report(100, events);
        let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());
        assert!(decision.events.iter().any(|e| e.event == "tier_up_started"));
        assert!(
            decision
                .events
                .iter()
                .any(|e| e.event == "tier_up_completed")
        );
    }

    #[test]
    fn eligibility_deny_outcome_on_insufficient_steps() {
        let report = make_report(1, Vec::new());
        let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());
        assert!(!decision.eligible);
        // SAFETY: tier_up_completed event is always emitted by evaluate_tier_up_eligibility
        let completed = decision
            .events
            .iter()
            .find(|e| e.event == "tier_up_completed")
            .expect("serde deserialization should succeed");
        assert_eq!(completed.outcome, "deny");
        assert_eq!(completed.reason, "insufficient_total_steps");
    }

    #[test]
    fn eligibility_decision_hash_is_not_empty() {
        let report = make_report(100, Vec::new());
        let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());
        assert!(!decision.decision_hash.is_empty());
    }

    #[test]
    fn eligibility_rejected_paths_have_correct_reasons() {
        let policy = TierUpPolicy {
            min_total_steps: 1,
            min_invocations_per_path: 5,
            ..TierUpPolicy::default()
        };
        // Only 1 invocation, below threshold of 5
        let events = vec![make_vm_event(0, "add", Some(true))];
        let report = make_report(100, events);
        let decision = evaluate_tier_up_eligibility(&report, &policy);
        assert_eq!(decision.rejected_paths.len(), 1);
        assert_eq!(
            decision.rejected_paths[0].reason,
            "insufficient_invocations"
        );
    }

    #[test]
    fn eligibility_cache_rate_rejection_reason() {
        let policy = TierUpPolicy {
            min_total_steps: 1,
            min_invocations_per_path: 1,
            min_cache_hit_rate_millionths: 900_000,
            require_cache_signal: false,
            ..TierUpPolicy::default()
        };
        // 50% cache rate, below 90% threshold
        let events = vec![
            make_vm_event(0, "add", Some(true)),
            make_vm_event(0, "add", Some(false)),
        ];
        let report = make_report(100, events);
        let decision = evaluate_tier_up_eligibility(&report, &policy);
        assert!(
            decision
                .rejected_paths
                .iter()
                .any(|r| r.reason == "cache_hit_rate_below_threshold")
        );
    }

    #[test]
    fn eligibility_missing_cache_signal_rejection_reason() {
        let policy = TierUpPolicy {
            min_total_steps: 1,
            min_invocations_per_path: 1,
            require_cache_signal: true,
            ..TierUpPolicy::default()
        };
        // No cache signals
        let events = vec![make_vm_event(0, "add", None)];
        let report = make_report(100, events);
        let decision = evaluate_tier_up_eligibility(&report, &policy);
        assert!(
            decision
                .rejected_paths
                .iter()
                .any(|r| r.reason == "missing_cache_signal")
        );
    }

    #[test]
    fn eligibility_candidate_rationale_populated() {
        let policy = TierUpPolicy {
            min_total_steps: 1,
            min_invocations_per_path: 1,
            min_cache_hit_rate_millionths: 0,
            require_cache_signal: false,
            ..TierUpPolicy::default()
        };
        let events = vec![make_vm_event(0, "add", Some(true))];
        let report = make_report(100, events);
        let decision = evaluate_tier_up_eligibility(&report, &policy);
        assert_eq!(decision.selected_candidates.len(), 1);
        assert_eq!(
            decision.selected_candidates[0].rationale,
            "hot_path_meets_tier_up_thresholds"
        );
    }

    #[test]
    fn eligibility_allow_outcome_when_eligible() {
        let policy = TierUpPolicy {
            min_total_steps: 1,
            min_invocations_per_path: 1,
            min_cache_hit_rate_millionths: 0,
            require_cache_signal: false,
            ..TierUpPolicy::default()
        };
        let events = vec![make_vm_event(0, "add", Some(true))];
        let report = make_report(100, events);
        let decision = evaluate_tier_up_eligibility(&report, &policy);
        assert!(decision.eligible);
        // SAFETY: tier_up_completed event is always emitted by evaluate_tier_up_eligibility
        let completed = decision
            .events
            .iter()
            .find(|e| e.event == "tier_up_completed")
            .expect("serde deserialization should succeed");
        assert_eq!(completed.outcome, "allow");
    }

    #[test]
    fn eligibility_schema_version_always_set() {
        let report = make_report(100, Vec::new());
        let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());
        assert_eq!(decision.schema_version, TIER_UP_POLICY_SCHEMA_VERSION);
    }

    #[test]
    fn eligibility_policy_hash_propagated() {
        let policy = TierUpPolicy::default();
        let report = make_report(100, Vec::new());
        let decision = evaluate_tier_up_eligibility(&report, &policy);
        assert_eq!(decision.policy_hash, policy.policy_hash());
    }

    #[test]
    fn decision_serde_full_roundtrip() {
        let policy = TierUpPolicy {
            min_total_steps: 1,
            min_invocations_per_path: 1,
            min_cache_hit_rate_millionths: 0,
            require_cache_signal: false,
            ..TierUpPolicy::default()
        };
        let events = vec![
            make_vm_event(0, "add", Some(true)),
            make_vm_event(1, "sub", Some(false)),
        ];
        let report = make_report(100, events);
        let decision = evaluate_tier_up_eligibility(&report, &policy);
        // SAFETY: TierUpDecision derives Serialize and has no non-serializable fields
        let json = serde_json::to_string(&decision).expect("serde deserialization should succeed");
        // SAFETY: JSON was just generated from TierUpDecision, deserialization guaranteed to succeed
        let back: TierUpDecision =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(decision, back);
    }

    #[test]
    fn rejection_serde_roundtrip() {
        let rejection = TierUpRejection {
            ip: 42,
            opcode: "load".to_string(),
            invocations: 5,
            cache_hit_rate_millionths: 500_000,
            reason: "test".to_string(),
        };
        // SAFETY: TierUpRejection derives Serialize and has no non-serializable fields
        let json = serde_json::to_string(&rejection).expect("serde deserialization should succeed");
        // SAFETY: JSON was just generated from TierUpRejection, deserialization guaranteed to succeed
        let back: TierUpRejection =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(rejection, back);
    }

    #[test]
    fn candidate_serde_roundtrip() {
        let candidate = TierUpCandidate {
            ip: 7,
            opcode: "store".to_string(),
            invocations: 100,
            cache_hit_rate_millionths: 800_000,
            rationale: "hot".to_string(),
        };
        // SAFETY: TierUpCandidate derives Serialize and has no non-serializable fields
        let json = serde_json::to_string(&candidate).expect("serde deserialization should succeed");
        // SAFETY: JSON was just generated from TierUpCandidate, deserialization guaranteed to succeed
        let back: TierUpCandidate =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(candidate, back);
    }

    #[test]
    fn candidate_id_is_deterministic() {
        let candidate = TierUpCandidate {
            ip: 7,
            opcode: "store".to_string(),
            invocations: 100,
            cache_hit_rate_millionths: 800_000,
            rationale: "hot".to_string(),
        };
        let id_a = candidate.candidate_id("trace-a");
        let id_b = candidate.candidate_id("trace-a");
        let id_c = candidate.candidate_id("trace-b");
        assert_eq!(id_a, id_b);
        assert_ne!(id_a, id_c);
        assert!(id_a.starts_with("tc-"));
    }

    #[test]
    fn decision_event_serde_roundtrip() {
        let event = TierUpDecisionEvent {
            trace_id: "t".to_string(),
            component: COMPONENT.to_string(),
            event: "e".to_string(),
            outcome: "o".to_string(),
            reason: "r".to_string(),
        };
        // SAFETY: TierUpDecisionEvent derives Serialize and has no non-serializable fields
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        // SAFETY: JSON was just generated from TierUpDecisionEvent, deserialization guaranteed to succeed
        let back: TierUpDecisionEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(event, back);
    }

    #[test]
    fn cache_hit_rate_single_hit() {
        assert_eq!(cache_hit_rate_millionths(1, 0), 1_000_000);
    }

    #[test]
    fn cache_hit_rate_single_miss() {
        assert_eq!(cache_hit_rate_millionths(0, 1), 0);
    }

    #[test]
    fn cache_hit_rate_handles_counter_overflow() {
        assert_eq!(cache_hit_rate_millionths(u64::MAX, u64::MAX), 500_000);
    }

    #[test]
    fn hot_path_sample_zero_cache_rate_when_no_observations() {
        let sample = HotPathSample {
            ip: 0,
            opcode: "nop".to_string(),
            invocations: 10,
            cache_hits: 0,
            cache_misses: 0,
            cache_hit_rate_millionths: 0,
        };
        assert_eq!(sample.cache_observations(), 0);
    }

    #[test]
    fn eligibility_zero_max_candidates_selects_none() {
        let policy = TierUpPolicy {
            min_total_steps: 1,
            min_invocations_per_path: 1,
            min_cache_hit_rate_millionths: 0,
            require_cache_signal: false,
            max_candidates: 0,
            ..TierUpPolicy::default()
        };
        let events = vec![
            make_vm_event(0, "add", Some(true)),
            make_vm_event(1, "sub", Some(true)),
        ];
        let report = make_report(100, events);
        let decision = evaluate_tier_up_eligibility(&report, &policy);
        assert!(!decision.eligible);
        assert!(decision.selected_candidates.is_empty());
    }

    #[test]
    fn eligibility_no_cache_signal_passes_when_not_required() {
        let policy = TierUpPolicy {
            min_total_steps: 1,
            min_invocations_per_path: 1,
            require_cache_signal: false,
            min_cache_hit_rate_millionths: 0,
            ..TierUpPolicy::default()
        };
        let events = vec![make_vm_event(0, "add", None)];
        let report = make_report(100, events);
        let decision = evaluate_tier_up_eligibility(&report, &policy);
        assert!(decision.eligible);
        assert_eq!(decision.selected_candidates.len(), 1);
    }

    #[test]
    fn profile_hash_differs_for_different_traces() {
        let mut report1 = make_report(10, vec![make_vm_event(0, "add", None)]);
        report1.trace_id = "trace-1".to_string();
        let mut report2 = make_report(10, vec![make_vm_event(0, "add", None)]);
        report2.trace_id = "trace-2".to_string();
        let p1 = build_hot_path_profile(&report1, 10);
        let p2 = build_hot_path_profile(&report2, 10);
        assert_ne!(p1.profile_hash, p2.profile_hash);
    }

    // RGC-608C: Bounded-Regret and Operator-Override Safety Tests

    #[test]
    fn bounded_regret_policy_defaults() {
        let policy = BoundedRegretPolicy::default();
        assert_eq!(policy.max_regression_ratio_millionths, 200_000); // 20%
        assert_eq!(policy.regression_measurement_window, 1000);
        assert_eq!(policy.deopt_cooldown_invocations, 5000);
        assert_eq!(policy.max_deopt_events, 3);
    }

    #[test]
    fn regression_measurement_calculation() {
        let measurement = RegressionMeasurement::calculate_regression(1000, 1200, 500);
        assert_eq!(measurement.baseline_performance_score, 1000);
        assert_eq!(measurement.current_performance_score, 1200);
        assert_eq!(measurement.regression_ratio_millionths, 200_000); // 20% regression
        assert_eq!(measurement.measurement_window_invocations, 500);

        // Test improvement (negative regression)
        let improvement = RegressionMeasurement::calculate_regression(1000, 800, 500);
        assert_eq!(improvement.regression_ratio_millionths, -200_000); // 20% improvement
    }

    #[test]
    fn regression_measurement_handles_u64_extremes() {
        let regression = RegressionMeasurement::calculate_regression(1, u64::MAX, 500);
        assert_eq!(regression.regression_ratio_millionths, i64::MAX);

        let improvement = RegressionMeasurement::calculate_regression(u64::MAX, 0, 500);
        assert_eq!(improvement.regression_ratio_millionths, -1_000_000);
    }

    #[test]
    fn regression_measurement_exceeds_threshold() {
        let policy = BoundedRegretPolicy::default(); // 20% threshold

        // Regression below threshold
        let low_regression = RegressionMeasurement::calculate_regression(1000, 1100, 500);
        assert!(!low_regression.exceeds_policy_threshold(&policy));

        // Regression above threshold
        let high_regression = RegressionMeasurement::calculate_regression(1000, 1300, 500);
        assert!(high_regression.exceeds_policy_threshold(&policy));
    }

    #[test]
    fn regression_measurement_threshold_cast_saturates() {
        let policy = BoundedRegretPolicy {
            max_regression_ratio_millionths: u64::MAX,
            ..BoundedRegretPolicy::default()
        };
        let regression = RegressionMeasurement::calculate_regression(1, u64::MAX, 500);

        assert!(!regression.exceeds_policy_threshold(&policy));
    }

    #[test]
    fn operator_override_creation_and_verification() {
        let override_obj = OperatorOverride::new(
            42,                           // target_ip
            Some("baseline".to_string()), // forced_tier
            "Performance issue investigation".to_string(),
            9999999999, // expires_at
            1,          // security_epoch
        );

        assert_eq!(override_obj.target_ip, 42);
        assert_eq!(override_obj.forced_tier, Some("baseline".to_string()));
        assert!(override_obj.verify_integrity());
        assert!(!override_obj.override_hash.is_empty());
    }

    #[test]
    fn operator_override_expiration() {
        let override_obj = OperatorOverride::new(
            42,
            None,
            "Test override".to_string(),
            1000, // expires_at
            1,
        );

        assert!(override_obj.is_valid(999)); // Before expiration
        assert!(!override_obj.is_valid(1000)); // At expiration
        assert!(!override_obj.is_valid(1001)); // After expiration
    }

    #[test]
    fn safety_evaluation_safe_case() {
        let report = make_report(
            200,
            vec![
                make_vm_event(0, "add", Some(true)),
                make_vm_event(1, "mul", Some(true)),
            ],
        );
        let tier_policy = TierUpPolicy::default();
        let regret_policy = BoundedRegretPolicy::default();
        let overrides = Vec::new();

        let safety_eval = evaluate_tier_up_safety(
            &report,
            &tier_policy,
            &regret_policy,
            &overrides,
            9999999999, // current_time
        );

        assert!(matches!(safety_eval.safety_verdict, SafetyVerdict::Safe));
        assert!(safety_eval.active_overrides.is_empty());
        assert_eq!(safety_eval.safety_reasoning, "All safety checks passed");
    }

    #[test]
    fn safety_evaluation_blocked_by_override() {
        let report = make_report(200, repeated_events(0, "add", 20, Some(true)));
        let tier_policy = TierUpPolicy::default();
        let regret_policy = BoundedRegretPolicy::default();

        let override_obj = OperatorOverride::new(
            0,    // target_ip matches the event
            None, // block tier-up
            "Security investigation".to_string(),
            9999999999,
            1,
        );
        let overrides = vec![override_obj.clone()];

        let safety_eval = evaluate_tier_up_safety(
            &report,
            &tier_policy,
            &regret_policy,
            &overrides,
            9999999998, // current_time before expiration
        );

        assert!(matches!(
            safety_eval.safety_verdict,
            SafetyVerdict::BlockedOverride
        ));
        assert_eq!(safety_eval.active_overrides.len(), 1);
        assert!(safety_eval.safety_reasoning.contains("Operator override"));
    }

    #[test]
    fn safety_evaluation_forced_by_override() {
        let report = make_report(200, repeated_events(0, "add", 20, Some(true)));
        let tier_policy = TierUpPolicy::default();
        let regret_policy = BoundedRegretPolicy::default();

        let override_obj = OperatorOverride::new(
            0,                             // target_ip matches the event
            Some("optimized".to_string()), // force tier
            "Manual optimization".to_string(),
            9999999999,
            1,
        );
        let overrides = vec![override_obj];

        let safety_eval = evaluate_tier_up_safety(
            &report,
            &tier_policy,
            &regret_policy,
            &overrides,
            9999999998,
        );

        assert!(matches!(
            safety_eval.safety_verdict,
            SafetyVerdict::ForcedOverride
        ));
    }

    #[test]
    fn safety_evaluation_blocks_candidate_without_real_regression_evidence() {
        let report = make_report(200, repeated_events(0, "add", 20, Some(true)));
        let tier_policy = TierUpPolicy::default();
        let regret_policy = BoundedRegretPolicy::default();

        let safety_eval =
            evaluate_tier_up_safety(&report, &tier_policy, &regret_policy, &[], 9999999998);

        assert!(matches!(
            safety_eval.safety_verdict,
            SafetyVerdict::BlockedRegression
        ));
        assert!(safety_eval.regression_measurements.is_empty());
        assert!(
            safety_eval
                .safety_reasoning
                .contains("missing real regression measurements")
        );
    }
}
