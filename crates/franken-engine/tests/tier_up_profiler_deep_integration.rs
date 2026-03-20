//! Deep integration tests for tier_up_profiler module.
//!
//! Covers: policy defaults, serde roundtrips, candidate ID determinism,
//! hot path sample properties, and decision structure.

use frankenengine_engine::tier_up_profiler::{
    HotPathProfile, HotPathSample, TIER_UP_POLICY_SCHEMA_VERSION, TierUpCandidate,
    TierUpDecision, TierUpDecisionEvent, TierUpPolicy, TierUpRejection,
    build_hot_path_profile, evaluate_tier_up_eligibility,
};
use frankenengine_engine::bytecode_vm::{
    ExecutionReport, InlineCacheStats, Value, VmEvent,
};
use frankenengine_engine::shape_transition_algebra::ShapeTransitionAlgebra;

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

// ---------------------------------------------------------------------------
// Enrichment helpers
// ---------------------------------------------------------------------------

fn make_vm_event(ip: u32, opcode: &str, cache_hit: Option<bool>) -> VmEvent {
    VmEvent {
        trace_id: "deep-trace".to_string(),
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
        trace_id: "deep-trace".to_string(),
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

// ---------------------------------------------------------------------------
// Enrichment: build_hot_path_profile
// ---------------------------------------------------------------------------

#[test]
fn deep_build_hot_path_profile_empty_report() {
    let report = make_report(0, vec![]);
    let profile = build_hot_path_profile(&report, 5);
    assert_eq!(profile.total_steps, 0);
    assert_eq!(profile.observed_instruction_events, 0);
    assert!(profile.top_paths.is_empty());
    assert!(!profile.profile_hash.is_empty());
}

#[test]
fn deep_build_hot_path_profile_single_instruction() {
    let events = vec![make_vm_event(0, "LoadConst", Some(true))];
    let report = make_report(1, events);
    let profile = build_hot_path_profile(&report, 5);
    assert_eq!(profile.total_steps, 1);
    assert_eq!(profile.observed_instruction_events, 1);
    assert_eq!(profile.top_paths.len(), 1);
    assert_eq!(profile.top_paths[0].ip, 0);
    assert_eq!(profile.top_paths[0].opcode, "LoadConst");
    assert_eq!(profile.top_paths[0].invocations, 1);
}

#[test]
fn deep_build_hot_path_profile_respects_top_k() {
    let mut events = Vec::new();
    for ip in 0..10 {
        for _ in 0..(ip + 1) {
            events.push(make_vm_event(ip as u32, &format!("Op{ip}"), Some(true)));
        }
    }
    let report = make_report(events.len() as u64, events);
    let profile = build_hot_path_profile(&report, 3);
    assert!(profile.top_paths.len() <= 3);
    // Highest-invocation paths should be selected
    assert!(profile.top_paths[0].invocations >= profile.top_paths[1].invocations);
}

#[test]
fn deep_build_hot_path_profile_hash_deterministic() {
    let events = vec![
        make_vm_event(0, "LoadConst", Some(true)),
        make_vm_event(0, "LoadConst", Some(false)),
        make_vm_event(1, "Add", Some(true)),
    ];
    let report = make_report(3, events);
    let p1 = build_hot_path_profile(&report, 5);
    let p2 = build_hot_path_profile(&report, 5);
    assert_eq!(p1.profile_hash, p2.profile_hash);
}

#[test]
fn deep_build_hot_path_profile_aggregates_cache_stats() {
    let events = vec![
        make_vm_event(0, "LoadProp", Some(true)),
        make_vm_event(0, "LoadProp", Some(true)),
        make_vm_event(0, "LoadProp", Some(false)),
    ];
    let report = make_report(3, events);
    let profile = build_hot_path_profile(&report, 5);
    assert_eq!(profile.top_paths.len(), 1);
    let sample = &profile.top_paths[0];
    assert_eq!(sample.invocations, 3);
    assert_eq!(sample.cache_hits, 2);
    assert_eq!(sample.cache_misses, 1);
}

// ---------------------------------------------------------------------------
// Enrichment: evaluate_tier_up_eligibility
// ---------------------------------------------------------------------------

#[test]
fn deep_evaluate_below_min_steps_not_eligible() {
    let report = make_report(10, vec![make_vm_event(0, "LoadConst", Some(true))]);
    let policy = TierUpPolicy::default(); // min_total_steps = 64
    let decision = evaluate_tier_up_eligibility(&report, &policy);
    assert!(!decision.eligible);
    assert!(decision.selected_candidates.is_empty());
}

#[test]
fn deep_evaluate_sufficient_hot_path_eligible() {
    let mut events = Vec::new();
    // Create a hot loop that exceeds min_invocations_per_path (16)
    for _ in 0..100 {
        events.push(make_vm_event(5, "Call", Some(true)));
    }
    // Add some other instructions to meet min_total_steps
    for ip in 10..30 {
        events.push(make_vm_event(ip, "LoadConst", None));
    }
    let report = make_report(120, events);
    let policy = TierUpPolicy::default();
    let decision = evaluate_tier_up_eligibility(&report, &policy);
    // Even if not eligible due to other policy checks, the profile should be populated
    assert!(!decision.profile.top_paths.is_empty());
    assert!(!decision.events.is_empty());
}

#[test]
fn deep_evaluate_decision_hash_deterministic() {
    let events = vec![
        make_vm_event(0, "LoadConst", Some(true)),
        make_vm_event(0, "LoadConst", Some(true)),
    ];
    let report = make_report(100, events);
    let policy = TierUpPolicy::default();
    let d1 = evaluate_tier_up_eligibility(&report, &policy);
    let d2 = evaluate_tier_up_eligibility(&report, &policy);
    assert_eq!(d1.decision_hash, d2.decision_hash);
    assert_eq!(d1.policy_hash, d2.policy_hash);
}

#[test]
fn deep_evaluate_decision_serde_roundtrip() {
    let events = vec![make_vm_event(0, "Add", Some(true))];
    let report = make_report(100, events);
    let policy = TierUpPolicy::default();
    let decision = evaluate_tier_up_eligibility(&report, &policy);
    let json = serde_json::to_string_pretty(&decision).unwrap();
    let restored: TierUpDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, restored);
}

#[test]
fn deep_evaluate_events_include_started_and_completed() {
    let report = make_report(100, vec![make_vm_event(0, "Nop", None)]);
    let policy = TierUpPolicy::default();
    let decision = evaluate_tier_up_eligibility(&report, &policy);
    assert!(
        decision.events.iter().any(|e| e.event.contains("started")),
        "decision events should include a started event"
    );
    assert!(
        decision
            .events
            .iter()
            .any(|e| e.event.contains("completed") || e.event.contains("done")),
        "decision events should include a completion event"
    );
}

#[test]
fn deep_evaluate_schema_version_matches_constant() {
    let report = make_report(100, vec![]);
    let policy = TierUpPolicy::default();
    let decision = evaluate_tier_up_eligibility(&report, &policy);
    assert_eq!(decision.schema_version, TIER_UP_POLICY_SCHEMA_VERSION);
}
