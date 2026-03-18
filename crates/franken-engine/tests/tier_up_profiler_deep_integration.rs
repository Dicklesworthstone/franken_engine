//! Deep integration tests for tier_up_profiler module.
//!
//! Covers: policy defaults, serde roundtrips, candidate ID determinism,
//! hot path sample properties, and decision structure.

use frankenengine_engine::tier_up_profiler::{
    HotPathProfile, HotPathSample, TIER_UP_POLICY_SCHEMA_VERSION, TierUpCandidate,
    TierUpDecisionEvent, TierUpPolicy, TierUpRejection,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn deep_schema_version_nonempty() {
    assert!(!TIER_UP_POLICY_SCHEMA_VERSION.is_empty());
}

// ---------------------------------------------------------------------------
// TierUpPolicy
// ---------------------------------------------------------------------------

#[test]
fn deep_policy_default_values() {
    let policy = TierUpPolicy::default();
    assert_eq!(policy.policy_id, "policy-tier-up-v1");
    assert!(policy.min_total_steps > 0);
    assert!(policy.min_invocations_per_path > 0);
    assert!(policy.max_candidates > 0);
    assert!(policy.profile_top_k > 0);
}

#[test]
fn deep_policy_serde_roundtrip() {
    let policy = TierUpPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let decoded: TierUpPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, decoded);
}

#[test]
fn deep_policy_hash_deterministic() {
    let p1 = TierUpPolicy::default();
    let p2 = TierUpPolicy::default();
    assert_eq!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn deep_policy_hash_changes_on_modification() {
    let p1 = TierUpPolicy::default();
    let mut p2 = TierUpPolicy::default();
    p2.min_total_steps = 999;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

// ---------------------------------------------------------------------------
// HotPathSample
// ---------------------------------------------------------------------------

#[test]
fn deep_hot_path_sample_serde_roundtrip() {
    let sample = HotPathSample {
        ip: 42,
        opcode: "LoadConst".to_string(),
        invocations: 100,
        cache_hits: 80,
        cache_misses: 20,
        cache_hit_rate_millionths: 800_000,
    };
    let json = serde_json::to_string(&sample).unwrap();
    let decoded: HotPathSample = serde_json::from_str(&json).unwrap();
    assert_eq!(sample, decoded);
}

// ---------------------------------------------------------------------------
// TierUpCandidate
// ---------------------------------------------------------------------------

#[test]
fn deep_candidate_id_deterministic() {
    let candidate = TierUpCandidate {
        ip: 10,
        opcode: "Call".to_string(),
        invocations: 500,
        cache_hit_rate_millionths: 900_000,
        rationale: "Hot loop body".to_string(),
    };
    let id1 = candidate.candidate_id("trace-001");
    let id2 = candidate.candidate_id("trace-001");
    assert_eq!(id1, id2);
    assert!(id1.starts_with("tc-"));
}

#[test]
fn deep_candidate_id_changes_on_trace() {
    let candidate = TierUpCandidate {
        ip: 10,
        opcode: "Call".to_string(),
        invocations: 500,
        cache_hit_rate_millionths: 900_000,
        rationale: "Hot loop body".to_string(),
    };
    let id1 = candidate.candidate_id("trace-001");
    let id2 = candidate.candidate_id("trace-002");
    assert_ne!(id1, id2);
}

#[test]
fn deep_candidate_serde_roundtrip() {
    let candidate = TierUpCandidate {
        ip: 10,
        opcode: "Add".to_string(),
        invocations: 200,
        cache_hit_rate_millionths: 750_000,
        rationale: "Frequent arithmetic".to_string(),
    };
    let json = serde_json::to_string(&candidate).unwrap();
    let decoded: TierUpCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(candidate, decoded);
}

// ---------------------------------------------------------------------------
// TierUpRejection
// ---------------------------------------------------------------------------

#[test]
fn deep_rejection_serde_roundtrip() {
    let rejection = TierUpRejection {
        ip: 20,
        opcode: "Store".to_string(),
        invocations: 5,
        cache_hit_rate_millionths: 100_000,
        reason: "Below minimum invocations".to_string(),
    };
    let json = serde_json::to_string(&rejection).unwrap();
    let decoded: TierUpRejection = serde_json::from_str(&json).unwrap();
    assert_eq!(rejection, decoded);
}

// ---------------------------------------------------------------------------
// TierUpDecisionEvent
// ---------------------------------------------------------------------------

#[test]
fn deep_event_serde_roundtrip() {
    let event = TierUpDecisionEvent {
        trace_id: "trace-deep".to_string(),
        component: "tier_up_profiler".to_string(),
        event: "candidate_selected".to_string(),
        outcome: "pass".to_string(),
        reason: "Met all thresholds".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: TierUpDecisionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
}

// ---------------------------------------------------------------------------
// HotPathProfile
// ---------------------------------------------------------------------------

#[test]
fn deep_profile_serde_roundtrip() {
    let profile = HotPathProfile {
        trace_id: "trace-profile".to_string(),
        total_steps: 1000,
        observed_instruction_events: 500,
        top_paths: vec![HotPathSample {
            ip: 5,
            opcode: "LoadLocal".to_string(),
            invocations: 200,
            cache_hits: 180,
            cache_misses: 20,
            cache_hit_rate_millionths: 900_000,
        }],
        profile_hash: "abc123".to_string(),
    };
    let json = serde_json::to_string(&profile).unwrap();
    let decoded: HotPathProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(profile, decoded);
}
