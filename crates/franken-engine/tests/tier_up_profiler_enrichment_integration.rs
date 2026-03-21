//! Enrichment integration tests for tier_up_profiler (RGC-310).
//!
//! Covers: TierUpPolicy defaults and serde, HotPathSample properties,
//! TierUpCandidate candidate_id determinism, TierUpRejection serde,
//! TierUpDecisionEvent serde, HotPathProfile serde, TierUpDecision serde,
//! and policy_hash determinism.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use frankenengine_engine::tier_up_profiler::{
    HotPathProfile, HotPathSample, TIER_UP_POLICY_SCHEMA_VERSION, TierUpCandidate, TierUpDecision,
    TierUpDecisionEvent, TierUpPolicy, TierUpRejection,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_contains_tier_up() {
    assert!(TIER_UP_POLICY_SCHEMA_VERSION.contains("tier-up"));
}

// ---------------------------------------------------------------------------
// TierUpPolicy
// ---------------------------------------------------------------------------

#[test]
fn default_policy_has_sane_defaults() {
    let policy = TierUpPolicy::default();
    assert!(policy.min_total_steps > 0);
    assert!(policy.min_invocations_per_path > 0);
    assert!(policy.max_candidates > 0);
    assert!(policy.profile_top_k > 0);
}

#[test]
fn default_policy_serde_roundtrip() {
    let policy = TierUpPolicy::default();
    let json = serde_json::to_string(&policy).expect("serialize");
    let deser: TierUpPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, deser);
}

#[test]
fn policy_hash_deterministic() {
    let p1 = TierUpPolicy::default();
    let p2 = TierUpPolicy::default();
    assert_eq!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn policy_hash_changes_with_config() {
    let p1 = TierUpPolicy::default();
    let mut p2 = TierUpPolicy::default();
    p2.min_total_steps = 999;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn policy_hash_nonempty() {
    let policy = TierUpPolicy::default();
    assert!(!policy.policy_hash().is_empty());
}

// ---------------------------------------------------------------------------
// HotPathSample
// ---------------------------------------------------------------------------

#[test]
fn hot_path_sample_serde_roundtrip() {
    let sample = HotPathSample {
        ip: 42,
        opcode: "LoadConst".to_string(),
        invocations: 1000,
        cache_hits: 800,
        cache_misses: 200,
        cache_hit_rate_millionths: 800_000,
    };
    let json = serde_json::to_string(&sample).expect("serialize");
    let deser: HotPathSample = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(sample, deser);
}

// ---------------------------------------------------------------------------
// TierUpCandidate
// ---------------------------------------------------------------------------

#[test]
fn candidate_id_deterministic() {
    let c = TierUpCandidate {
        ip: 10,
        opcode: "CallHost".to_string(),
        invocations: 500,
        cache_hit_rate_millionths: 900_000,
        rationale: "hot path".to_string(),
    };
    let id_a = c.candidate_id("trace-abc");
    let id_b = c.candidate_id("trace-abc");
    assert_eq!(id_a, id_b);
}

#[test]
fn candidate_id_starts_with_tc_prefix() {
    let c = TierUpCandidate {
        ip: 5,
        opcode: "Add".to_string(),
        invocations: 100,
        cache_hit_rate_millionths: 700_000,
        rationale: "frequently hit".to_string(),
    };
    let id = c.candidate_id("trace-x");
    assert!(id.starts_with("tc-"), "got: {}", id);
}

#[test]
fn candidate_id_differs_by_trace() {
    let c = TierUpCandidate {
        ip: 5,
        opcode: "Add".to_string(),
        invocations: 100,
        cache_hit_rate_millionths: 700_000,
        rationale: "test".to_string(),
    };
    let id_a = c.candidate_id("trace-a");
    let id_b = c.candidate_id("trace-b");
    assert_ne!(id_a, id_b);
}

#[test]
fn candidate_serde_roundtrip() {
    let c = TierUpCandidate {
        ip: 20,
        opcode: "GetProp".to_string(),
        invocations: 300,
        cache_hit_rate_millionths: 650_000,
        rationale: "hot property access".to_string(),
    };
    let json = serde_json::to_string(&c).expect("serialize");
    let deser: TierUpCandidate = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(c, deser);
}

// ---------------------------------------------------------------------------
// TierUpRejection
// ---------------------------------------------------------------------------

#[test]
fn rejection_serde_roundtrip() {
    let r = TierUpRejection {
        ip: 7,
        opcode: "Branch".to_string(),
        invocations: 2,
        cache_hit_rate_millionths: 0,
        reason: "too few invocations".to_string(),
    };
    let json = serde_json::to_string(&r).expect("serialize");
    let deser: TierUpRejection = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(r, deser);
}

// ---------------------------------------------------------------------------
// TierUpDecisionEvent
// ---------------------------------------------------------------------------

#[test]
fn decision_event_serde_roundtrip() {
    let ev = TierUpDecisionEvent {
        trace_id: "trace-1".to_string(),
        component: "tier_up_profiler".to_string(),
        event: "tier_decision".to_string(),
        outcome: "eligible".to_string(),
        reason: "sufficient invocations".to_string(),
    };
    let json = serde_json::to_string(&ev).expect("serialize");
    let deser: TierUpDecisionEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ev, deser);
}

// ---------------------------------------------------------------------------
// HotPathProfile
// ---------------------------------------------------------------------------

#[test]
fn profile_serde_roundtrip() {
    let profile = HotPathProfile {
        trace_id: "trace-profile".to_string(),
        total_steps: 5000,
        observed_instruction_events: 3000,
        top_paths: vec![HotPathSample {
            ip: 1,
            opcode: "LoadConst".to_string(),
            invocations: 1000,
            cache_hits: 800,
            cache_misses: 200,
            cache_hit_rate_millionths: 800_000,
        }],
        profile_hash: "abc123".to_string(),
    };
    let json = serde_json::to_string(&profile).expect("serialize");
    let deser: HotPathProfile = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(profile, deser);
}

// ---------------------------------------------------------------------------
// TierUpDecision
// ---------------------------------------------------------------------------

#[test]
fn decision_serde_roundtrip() {
    let decision = TierUpDecision {
        schema_version: TIER_UP_POLICY_SCHEMA_VERSION.to_string(),
        trace_id: "trace-decision".to_string(),
        policy_hash: "hash-abc".to_string(),
        eligible: true,
        selected_candidates: vec![TierUpCandidate {
            ip: 10,
            opcode: "CallHost".to_string(),
            invocations: 500,
            cache_hit_rate_millionths: 900_000,
            rationale: "hot path".to_string(),
        }],
        rejected_paths: vec![TierUpRejection {
            ip: 20,
            opcode: "Nop".to_string(),
            invocations: 1,
            cache_hit_rate_millionths: 0,
            reason: "cold".to_string(),
        }],
        profile: HotPathProfile {
            trace_id: "trace-decision".to_string(),
            total_steps: 2000,
            observed_instruction_events: 1500,
            top_paths: Vec::new(),
            profile_hash: "prof-hash".to_string(),
        },
        decision_hash: "dec-hash".to_string(),
        events: vec![TierUpDecisionEvent {
            trace_id: "trace-decision".to_string(),
            component: "tier_up_profiler".to_string(),
            event: "decide".to_string(),
            outcome: "eligible".to_string(),
            reason: "all thresholds met".to_string(),
        }],
    };
    let json = serde_json::to_string(&decision).expect("serialize");
    let deser: TierUpDecision = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decision, deser);
}

#[test]
fn decision_with_no_candidates_not_eligible() {
    let decision = TierUpDecision {
        schema_version: TIER_UP_POLICY_SCHEMA_VERSION.to_string(),
        trace_id: "trace-empty".to_string(),
        policy_hash: "hash-x".to_string(),
        eligible: false,
        selected_candidates: Vec::new(),
        rejected_paths: Vec::new(),
        profile: HotPathProfile {
            trace_id: "trace-empty".to_string(),
            total_steps: 10,
            observed_instruction_events: 5,
            top_paths: Vec::new(),
            profile_hash: "empty".to_string(),
        },
        decision_hash: "dec-empty".to_string(),
        events: Vec::new(),
    };
    assert!(!decision.eligible);
    assert!(decision.selected_candidates.is_empty());
}

// ===========================================================================
// Additional enrichment: edge cases and behavioral properties
// ===========================================================================

use frankenengine_engine::bytecode_vm::{ExecutionReport, InlineCacheStats, Value, VmEvent};
use frankenengine_engine::shape_transition_algebra::ShapeTransitionAlgebra;
use frankenengine_engine::tier_up_profiler::{
    build_hot_path_profile, evaluate_tier_up_eligibility,
};

fn make_enrichment_event(ip: u32, opcode: &str, cache_hit: Option<bool>) -> VmEvent {
    VmEvent {
        trace_id: "enrich-trace".to_string(),
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

fn make_enrichment_report(steps: u64, events: Vec<VmEvent>) -> ExecutionReport {
    ExecutionReport {
        trace_id: "enrich-trace".to_string(),
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

#[test]
fn policy_min_total_steps_is_reasonable_lower_bound() {
    let policy = TierUpPolicy::default();
    // Should be at least 16 to avoid noise from trivial programs
    assert!(policy.min_total_steps >= 16);
    // But not so large that real hot paths are ignored
    assert!(policy.min_total_steps <= 1024);
}

#[test]
fn policy_profile_top_k_is_bounded() {
    let policy = TierUpPolicy::default();
    assert!(policy.profile_top_k >= 1);
    assert!(policy.profile_top_k <= 100);
}

#[test]
fn policy_max_candidates_respects_top_k() {
    let policy = TierUpPolicy::default();
    // max_candidates should be at most profile_top_k
    assert!(policy.max_candidates <= policy.profile_top_k);
}

#[test]
fn candidate_id_includes_ip_in_hash() {
    let c1 = TierUpCandidate {
        ip: 10,
        opcode: "Call".to_string(),
        invocations: 100,
        cache_hit_rate_millionths: 900_000,
        rationale: "hot".to_string(),
    };
    let c2 = TierUpCandidate {
        ip: 20,
        opcode: "Call".to_string(),
        invocations: 100,
        cache_hit_rate_millionths: 900_000,
        rationale: "hot".to_string(),
    };
    // Different IPs should produce different candidate IDs
    assert_ne!(c1.candidate_id("trace"), c2.candidate_id("trace"));
}

#[test]
fn candidate_id_prefix_is_stable() {
    let candidate = TierUpCandidate {
        ip: 5,
        opcode: "LoadLocal".to_string(),
        invocations: 50,
        cache_hit_rate_millionths: 500_000,
        rationale: "moderate".to_string(),
    };
    let id = candidate.candidate_id("t1");
    assert!(
        id.starts_with("tc-"),
        "candidate_id should start with 'tc-' prefix"
    );
    assert!(
        id.len() > 3,
        "candidate_id should have content after prefix"
    );
}

#[test]
fn hot_path_profile_hash_varies_by_content() {
    let events1 = vec![make_enrichment_event(0, "Add", Some(true))];
    let events2 = vec![make_enrichment_event(0, "Sub", Some(true))];
    let report1 = make_enrichment_report(1, events1);
    let report2 = make_enrichment_report(1, events2);
    let p1 = build_hot_path_profile(&report1, 5);
    let p2 = build_hot_path_profile(&report2, 5);
    assert_ne!(p1.profile_hash, p2.profile_hash);
}

#[test]
fn hot_path_profile_with_no_cache_events() {
    let events = vec![make_enrichment_event(0, "Nop", None)];
    let report = make_enrichment_report(1, events);
    let profile = build_hot_path_profile(&report, 5);
    assert_eq!(profile.top_paths.len(), 1);
    assert_eq!(profile.top_paths[0].cache_hits, 0);
    assert_eq!(profile.top_paths[0].cache_misses, 0);
}

#[test]
fn evaluate_empty_report_not_eligible() {
    let report = make_enrichment_report(0, vec![]);
    let policy = TierUpPolicy::default();
    let decision = evaluate_tier_up_eligibility(&report, &policy);
    assert!(!decision.eligible);
    assert!(decision.selected_candidates.is_empty());
}

#[test]
fn evaluate_decision_schema_version_matches_policy() {
    let events = vec![make_enrichment_event(0, "Add", Some(true))];
    let report = make_enrichment_report(100, events);
    let policy = TierUpPolicy::default();
    let decision = evaluate_tier_up_eligibility(&report, &policy);
    assert_eq!(decision.schema_version, TIER_UP_POLICY_SCHEMA_VERSION);
}

#[test]
fn evaluate_decision_trace_id_matches_report() {
    let events = vec![make_enrichment_event(0, "Add", Some(true))];
    let report = make_enrichment_report(100, events);
    let policy = TierUpPolicy::default();
    let decision = evaluate_tier_up_eligibility(&report, &policy);
    assert_eq!(decision.trace_id, report.trace_id);
}

#[test]
fn evaluate_decision_events_nonempty() {
    let events = vec![make_enrichment_event(0, "Add", Some(true))];
    let report = make_enrichment_report(100, events);
    let policy = TierUpPolicy::default();
    let decision = evaluate_tier_up_eligibility(&report, &policy);
    assert!(
        !decision.events.is_empty(),
        "decision should always emit at least one event"
    );
}

#[test]
fn rejection_reason_is_human_readable() {
    let rejection = TierUpRejection {
        ip: 0,
        opcode: "Nop".to_string(),
        invocations: 1,
        cache_hit_rate_millionths: 0,
        reason: "Below minimum invocations threshold".to_string(),
    };
    assert!(!rejection.reason.is_empty());
    assert!(
        rejection.reason.len() > 5,
        "rejection reason should be descriptive"
    );
}

#[test]
fn decision_event_component_is_tier_up_profiler() {
    let event = TierUpDecisionEvent {
        trace_id: "t1".to_string(),
        component: "tier_up_profiler".to_string(),
        event: "evaluate".to_string(),
        outcome: "not_eligible".to_string(),
        reason: "below min steps".to_string(),
    };
    assert_eq!(event.component, "tier_up_profiler");
}

#[test]
fn multiple_hot_paths_sorted_by_invocations() {
    let mut events = Vec::new();
    // ip=0: 10 invocations, ip=1: 50 invocations, ip=2: 30 invocations
    for _ in 0..10 {
        events.push(make_enrichment_event(0, "LoadConst", Some(true)));
    }
    for _ in 0..50 {
        events.push(make_enrichment_event(1, "Call", Some(true)));
    }
    for _ in 0..30 {
        events.push(make_enrichment_event(2, "Add", Some(false)));
    }
    let report = make_enrichment_report(90, events);
    let profile = build_hot_path_profile(&report, 10);
    assert_eq!(profile.top_paths.len(), 3);
    // Should be sorted descending by invocations
    assert!(profile.top_paths[0].invocations >= profile.top_paths[1].invocations);
    assert!(profile.top_paths[1].invocations >= profile.top_paths[2].invocations);
}

#[test]
fn cache_hit_rate_millionths_is_correct() {
    let mut events = Vec::new();
    for _ in 0..3 {
        events.push(make_enrichment_event(0, "GetProp", Some(true)));
    }
    events.push(make_enrichment_event(0, "GetProp", Some(false)));
    let report = make_enrichment_report(4, events);
    let profile = build_hot_path_profile(&report, 5);
    assert_eq!(profile.top_paths.len(), 1);
    let sample = &profile.top_paths[0];
    assert_eq!(sample.cache_hits, 3);
    assert_eq!(sample.cache_misses, 1);
    // 3/4 = 750_000 millionths
    assert_eq!(sample.cache_hit_rate_millionths, 750_000);
}
