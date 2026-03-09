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
        self.cache_hits + self.cache_misses
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

        observed_instruction_events += 1;
        let key = (event.ip, event.opcode.clone());
        let entry = aggregates.entry(key).or_insert_with(|| PathAccumulator {
            ip: event.ip,
            opcode: event.opcode.clone(),
            invocations: 0,
            cache_hits: 0,
            cache_misses: 0,
        });

        entry.invocations += 1;
        match event.cache_hit {
            Some(true) => entry.cache_hits += 1,
            Some(false) => entry.cache_misses += 1,
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
    let observed = cache_hits + cache_misses;
    if observed == 0 {
        return 0;
    }

    ((u128::from(cache_hits) * u128::from(MILLIONTHS_DENOMINATOR)) / u128::from(observed)) as i64
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
    value.max(1)
}

fn sha256_hex<T: Serialize>(value: &T) -> String {
    let payload = serde_json::to_vec(value).expect("tier_up_profiler payload must serialize");
    let digest = Sha256::digest(payload);
    hex::encode(digest)
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
        let json = serde_json::to_string(&policy).unwrap();
        let restored: TierUpPolicy = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&sample).unwrap();
        let restored: HotPathSample = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&decision).unwrap();
        let restored: TierUpDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, restored);
    }

    // -- normalize_limit tests -----------------------------------------------

    #[test]
    fn normalize_limit_zero_becomes_one() {
        assert_eq!(normalize_limit(0), 1);
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
        let json = serde_json::to_string(&policy).unwrap();
        let back: TierUpPolicy = serde_json::from_str(&json).unwrap();
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
    fn profile_top_k_zero_becomes_one() {
        let events = vec![make_vm_event(0, "a", None), make_vm_event(1, "b", None)];
        let report = make_report(100, events);
        let profile = build_hot_path_profile(&report, 0);
        assert_eq!(profile.top_paths.len(), 1);
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
        let completed = decision
            .events
            .iter()
            .find(|e| e.event == "tier_up_completed")
            .unwrap();
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
        let completed = decision
            .events
            .iter()
            .find(|e| e.event == "tier_up_completed")
            .unwrap();
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
        let json = serde_json::to_string(&decision).unwrap();
        let back: TierUpDecision = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&rejection).unwrap();
        let back: TierUpRejection = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&candidate).unwrap();
        let back: TierUpCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(candidate, back);
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
        let json = serde_json::to_string(&event).unwrap();
        let back: TierUpDecisionEvent = serde_json::from_str(&json).unwrap();
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
    fn eligibility_max_candidates_truncates_to_one_when_zero() {
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
        // normalize_limit(0) = 1
        assert_eq!(decision.selected_candidates.len(), 1);
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
}
