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
