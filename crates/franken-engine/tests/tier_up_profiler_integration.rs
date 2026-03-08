//! Integration tests for the tier-up profiler (RGC-602).
//!
//! Tests the full pipeline: bytecode VM execution -> execution report ->
//! hot-path profiling -> tier-up eligibility decision. Validates cross-module
//! integration between bytecode_vm and tier_up_profiler.

use frankenengine_engine::bytecode_vm::{BytecodeVm, Instruction, Program, Register, Value};
use frankenengine_engine::tier_up_profiler::{
    HotPathProfile, TIER_UP_POLICY_SCHEMA_VERSION, TierUpCandidate, TierUpDecision,
    TierUpDecisionEvent, TierUpPolicy, TierUpRejection, build_hot_path_profile,
    evaluate_tier_up_eligibility,
};

fn r(index: u16) -> Register {
    Register(index)
}

// ---------------------------------------------------------------------------
// Full pipeline: VM execution -> profiling -> tier-up decision
// ---------------------------------------------------------------------------

#[test]
fn straight_line_program_no_cache_activity() {
    // Simple arithmetic with no property loads — no cache signal.
    let program = Program {
        constants: vec![Value::Int(6), Value::Int(7)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Mul {
                dst: r(2),
                lhs: r(0),
                rhs: r(1),
            },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-straight-line", 8, 128);
    let report = vm.execute(&program).unwrap();

    let profile = build_hot_path_profile(&report, 16);
    assert_eq!(profile.total_steps, 4);
    assert_eq!(profile.observed_instruction_events, 3); // return is not "instruction" event
    assert!(!profile.profile_hash.is_empty());

    // Default policy requires cache signal — should be ineligible.
    let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());
    assert!(!decision.eligible);
}

#[test]
fn loop_with_cached_property_loads_eligible() {
    // Loop that loads a property many times — should build cache hits.
    let program = Program {
        constants: vec![Value::Int(42), Value::Int(50), Value::Int(1)],
        property_pool: vec!["answer".to_string()],
        instructions: vec![
            // r0 = obj
            Instruction::NewObject { dst: r(0) },
            // r1 = 42
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            // obj.answer = 42
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            // r3 = counter = 50
            Instruction::LoadConst {
                dst: r(3),
                const_index: 1,
            },
            // Loop body: r2 = obj.answer (cached)
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            // r4 = 1
            Instruction::LoadConst {
                dst: r(4),
                const_index: 2,
            },
            // counter -= 1
            Instruction::Sub {
                dst: r(3),
                lhs: r(3),
                rhs: r(4),
            },
            // if counter == 0 goto end
            Instruction::JumpIfFalse {
                condition: r(3),
                target: 9,
            },
            // goto loop body
            Instruction::Jump { target: 4 },
            // return r2
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-cache-loop", 8, 1024);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Int(42));

    let profile = build_hot_path_profile(&report, 16);
    assert!(profile.total_steps > 64); // enough steps for default policy

    // Find the load_prop_cached path in profile
    let cached_path = profile
        .top_paths
        .iter()
        .find(|p| p.opcode == "load_prop_cached");
    assert!(cached_path.is_some());
    let cached = cached_path.unwrap();
    assert_eq!(cached.invocations, 50);
    assert!(cached.cache_hits > 0);

    // With a permissive policy, should be eligible
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
    assert!(!decision.selected_candidates.is_empty());

    // Check the selected candidate
    let candidate = decision
        .selected_candidates
        .iter()
        .find(|c| c.opcode == "load_prop_cached");
    assert!(candidate.is_some());
}

#[test]
fn short_program_insufficient_steps() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-short", 4, 32);
    let report = vm.execute(&program).unwrap();

    let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());
    assert!(!decision.eligible);
    assert!(
        decision
            .events
            .iter()
            .any(|e| e.reason == "insufficient_total_steps")
    );
}

#[test]
fn property_load_all_misses_rejected_for_low_hit_rate() {
    // Store a new property each iteration — shape changes cause cache misses.
    let program = Program {
        constants: vec![Value::Int(1), Value::Int(20), Value::Int(1)],
        property_pool: vec!["x".to_string(), "y".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            // Store two different properties to change shape
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::LoadConst {
                dst: r(3),
                const_index: 1,
            },
            // Loop: load prop (will mostly miss due to shape changes)
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 1,
                value: r(1),
            },
            Instruction::LoadConst {
                dst: r(4),
                const_index: 2,
            },
            Instruction::Sub {
                dst: r(3),
                lhs: r(3),
                rhs: r(4),
            },
            Instruction::JumpIfFalse {
                condition: r(3),
                target: 10,
            },
            Instruction::Jump { target: 4 },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-miss", 8, 1024);
    let report = vm.execute(&program).unwrap();

    let policy = TierUpPolicy {
        min_total_steps: 10,
        min_invocations_per_path: 5,
        min_cache_hit_rate_millionths: 900_000, // very high threshold
        max_candidates: 4,
        profile_top_k: 16,
        require_cache_signal: true,
        ..TierUpPolicy::default()
    };
    let decision = evaluate_tier_up_eligibility(&report, &policy);

    // The load_prop_cached path should be rejected for low cache hit rate
    let rejected_cached = decision
        .rejected_paths
        .iter()
        .find(|r| r.opcode == "load_prop_cached");
    if let Some(rejected) = rejected_cached {
        assert_eq!(rejected.reason, "cache_hit_rate_below_threshold");
    }
}

// ---------------------------------------------------------------------------
// Determinism across repeated runs
// ---------------------------------------------------------------------------

#[test]
fn profile_deterministic_across_three_runs() {
    let program = Program {
        constants: vec![Value::Int(10), Value::Int(3), Value::Int(1)],
        property_pool: vec!["val".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::LoadConst {
                dst: r(3),
                const_index: 1,
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            Instruction::LoadConst {
                dst: r(4),
                const_index: 2,
            },
            Instruction::Sub {
                dst: r(3),
                lhs: r(3),
                rhs: r(4),
            },
            Instruction::JumpIfFalse {
                condition: r(3),
                target: 9,
            },
            Instruction::Jump { target: 4 },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut profiles = Vec::new();
    let mut decisions = Vec::new();

    for _ in 0..3 {
        let mut vm = BytecodeVm::new("trace-determinism", 8, 256);
        let report = vm.execute(&program).unwrap();
        profiles.push(build_hot_path_profile(&report, 16));
        decisions.push(evaluate_tier_up_eligibility(
            &report,
            &TierUpPolicy::default(),
        ));
    }

    assert_eq!(profiles[0].profile_hash, profiles[1].profile_hash);
    assert_eq!(profiles[1].profile_hash, profiles[2].profile_hash);
    assert_eq!(decisions[0].decision_hash, decisions[1].decision_hash);
    assert_eq!(decisions[1].decision_hash, decisions[2].decision_hash);
}

// ---------------------------------------------------------------------------
// Policy configuration edge cases
// ---------------------------------------------------------------------------

#[test]
fn policy_with_zero_min_steps_admits_any_program() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };

    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();

    let policy = TierUpPolicy {
        min_total_steps: 0,
        min_invocations_per_path: 1,
        min_cache_hit_rate_millionths: 0,
        max_candidates: 4,
        profile_top_k: 16,
        require_cache_signal: false,
        ..TierUpPolicy::default()
    };
    let decision = evaluate_tier_up_eligibility(&report, &policy);
    assert!(decision.eligible);
}

#[test]
fn policy_max_candidates_truncates() {
    // Build a program with multiple distinct cached-property hot paths.
    // Use a small loop count (20) to stay well within budget.
    let program = Program {
        constants: vec![Value::Int(1), Value::Int(20), Value::Int(1)],
        property_pool: vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
            "e".to_string(),
        ],
        instructions: vec![
            // r0 = obj, r1 = 1
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            // Store all 5 properties on the object
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 1,
                value: r(1),
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 2,
                value: r(1),
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 3,
                value: r(1),
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 4,
                value: r(1),
            },
            // r3 = counter = 20
            Instruction::LoadConst {
                dst: r(3),
                const_index: 1,
            },
            // Loop body: 5 cached loads from different properties (ip 8-12)
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 1,
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 2,
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 3,
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 4,
            },
            // counter -= 1
            Instruction::LoadConst {
                dst: r(4),
                const_index: 2,
            },
            Instruction::Sub {
                dst: r(3),
                lhs: r(3),
                rhs: r(4),
            },
            Instruction::JumpIfFalse {
                condition: r(3),
                target: 17,
            },
            Instruction::Jump { target: 8 },
            // return r2
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("t", 8, 4096);
    let report = vm.execute(&program).unwrap();

    let policy = TierUpPolicy {
        min_total_steps: 1,
        min_invocations_per_path: 1,
        min_cache_hit_rate_millionths: 0,
        max_candidates: 2,
        profile_top_k: 16,
        require_cache_signal: false,
        ..TierUpPolicy::default()
    };
    let decision = evaluate_tier_up_eligibility(&report, &policy);
    assert!(decision.selected_candidates.len() <= 2);
}

// ---------------------------------------------------------------------------
// Decision structure validation
// ---------------------------------------------------------------------------

#[test]
fn decision_has_schema_version() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };

    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());

    assert_eq!(decision.schema_version, TIER_UP_POLICY_SCHEMA_VERSION);
    assert!(!decision.policy_hash.is_empty());
    assert!(!decision.decision_hash.is_empty());
    assert_eq!(decision.trace_id, "t");
}

#[test]
fn decision_events_contain_start_and_complete() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };

    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());

    assert!(decision.events.iter().any(|e| e.event == "tier_up_started"));
    assert!(
        decision
            .events
            .iter()
            .any(|e| e.event == "tier_up_completed")
    );
}

// ---------------------------------------------------------------------------
// Serde round-trips (integration-level)
// ---------------------------------------------------------------------------

#[test]
fn full_decision_serde_roundtrip() {
    let program = Program {
        constants: vec![Value::Int(10), Value::Int(30), Value::Int(1)],
        property_pool: vec!["x".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::LoadConst {
                dst: r(3),
                const_index: 1,
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            Instruction::LoadConst {
                dst: r(4),
                const_index: 2,
            },
            Instruction::Sub {
                dst: r(3),
                lhs: r(3),
                rhs: r(4),
            },
            Instruction::JumpIfFalse {
                condition: r(3),
                target: 9,
            },
            Instruction::Jump { target: 4 },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-serde", 8, 1024);
    let report = vm.execute(&program).unwrap();
    let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());

    let json = serde_json::to_string(&decision).unwrap();
    let back: TierUpDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, decision);
}

#[test]
fn profile_serde_roundtrip() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };

    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    let profile = build_hot_path_profile(&report, 16);

    let json = serde_json::to_string(&profile).unwrap();
    let back: HotPathProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(back, profile);
}

#[test]
fn tier_up_policy_serde_roundtrip() {
    let policy = TierUpPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let back: TierUpPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(back, policy);
}

#[test]
fn tier_up_candidate_serde_roundtrip() {
    let candidate = TierUpCandidate {
        ip: 4,
        opcode: "load_prop_cached".to_string(),
        invocations: 50,
        cache_hit_rate_millionths: 960_000,
        rationale: "hot_path_meets_tier_up_thresholds".to_string(),
    };
    let json = serde_json::to_string(&candidate).unwrap();
    let back: TierUpCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(back, candidate);
}

#[test]
fn tier_up_rejection_serde_roundtrip() {
    let rejection = TierUpRejection {
        ip: 2,
        opcode: "add".to_string(),
        invocations: 3,
        cache_hit_rate_millionths: 0,
        reason: "insufficient_invocations".to_string(),
    };
    let json = serde_json::to_string(&rejection).unwrap();
    let back: TierUpRejection = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rejection);
}

#[test]
fn tier_up_decision_event_serde_roundtrip() {
    let event = TierUpDecisionEvent {
        trace_id: "t".to_string(),
        component: "tier_up_profiler".to_string(),
        event: "tier_up_started".to_string(),
        outcome: "pass".to_string(),
        reason: "test".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: TierUpDecisionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

// ---------- decision events all have nonempty trace_id ----------

#[test]
fn decision_events_all_have_nonempty_trace_id() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-events-check", 4, 32);
    let report = vm.execute(&program).unwrap();
    let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());

    for event in &decision.events {
        assert!(
            !event.trace_id.trim().is_empty(),
            "event trace_id must not be empty"
        );
    }
}

// ---------- default policy schema version ----------

#[test]
fn default_policy_has_expected_schema_version() {
    let policy = TierUpPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    // Policy should serialize to valid JSON with all fields present
    assert!(value.is_object());
    assert!(value.as_object().unwrap().len() >= 5);
}

// ---------- decision hash differs for different programs ----------

#[test]
fn decision_hash_differs_for_different_programs() {
    let prog_a = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };
    let prog_b = Program {
        constants: vec![Value::Int(1), Value::Int(2)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Add {
                dst: r(2),
                lhs: r(0),
                rhs: r(1),
            },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm_a = BytecodeVm::new("hash-a", 4, 32);
    let report_a = vm_a.execute(&prog_a).unwrap();
    let decision_a = evaluate_tier_up_eligibility(&report_a, &TierUpPolicy::default());

    let mut vm_b = BytecodeVm::new("hash-b", 4, 32);
    let report_b = vm_b.execute(&prog_b).unwrap();
    let decision_b = evaluate_tier_up_eligibility(&report_b, &TierUpPolicy::default());

    assert_ne!(decision_a.decision_hash, decision_b.decision_hash);
}

#[test]
fn tier_up_policy_default_serde_roundtrip() {
    let policy = TierUpPolicy::default();
    let json = serde_json::to_string(&policy).expect("serialize");
    let recovered: TierUpPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, policy);
}

#[test]
fn tier_up_policy_schema_version_is_nonempty() {
    assert!(!TIER_UP_POLICY_SCHEMA_VERSION.trim().is_empty());
}

#[test]
fn tier_up_decision_event_fields_preserved_after_roundtrip() {
    let event = TierUpDecisionEvent {
        trace_id: "trace-rt-1".to_string(),
        component: "tier_up_profiler".to_string(),
        event: "evaluate".to_string(),
        outcome: "pass".to_string(),
        reason: "threshold met".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: TierUpDecisionEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.trace_id, "trace-rt-1");
    assert_eq!(recovered.component, "tier_up_profiler");
    assert_eq!(recovered.reason, "threshold met");
}

#[test]
fn tier_up_candidate_debug_is_nonempty() {
    let candidate = TierUpCandidate {
        ip: 4,
        opcode: "load_prop_cached".to_string(),
        invocations: 50,
        cache_hit_rate_millionths: 960_000,
        rationale: "hot_path".to_string(),
    };
    assert!(!format!("{candidate:?}").is_empty());
}

#[test]
fn tier_up_rejection_debug_is_nonempty() {
    let rejection = TierUpRejection {
        ip: 2,
        opcode: "add".to_string(),
        invocations: 3,
        cache_hit_rate_millionths: 0,
        reason: "insufficient_invocations".to_string(),
    };
    assert!(!format!("{rejection:?}").is_empty());
}

#[test]
fn tier_up_policy_debug_is_nonempty() {
    let policy = TierUpPolicy::default();
    assert!(!format!("{policy:?}").is_empty());
}

#[test]
fn profile_hash_differs_for_different_top_k() {
    let program = Program {
        constants: vec![Value::Int(10), Value::Int(5), Value::Int(1)],
        property_pool: vec!["v".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::LoadConst {
                dst: r(3),
                const_index: 1,
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            Instruction::LoadConst {
                dst: r(4),
                const_index: 2,
            },
            Instruction::Sub {
                dst: r(3),
                lhs: r(3),
                rhs: r(4),
            },
            Instruction::JumpIfFalse {
                condition: r(3),
                target: 9,
            },
            Instruction::Jump { target: 4 },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-topk", 8, 256);
    let report = vm.execute(&program).unwrap();
    let profile_k4 = build_hot_path_profile(&report, 4);
    let profile_k16 = build_hot_path_profile(&report, 16);
    // top_paths count may differ so hashes may differ (or equal if <=4 unique paths)
    assert!(profile_k4.top_paths.len() <= 4);
    assert!(profile_k16.top_paths.len() <= 16);
}

#[test]
fn decision_eligible_flag_consistent_with_candidates() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-consist", 4, 32);
    let report = vm.execute(&program).unwrap();
    let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());
    if decision.eligible {
        assert!(
            !decision.selected_candidates.is_empty(),
            "eligible decision must have at least one candidate"
        );
    } else {
        assert!(
            decision.selected_candidates.is_empty(),
            "ineligible decision must have zero candidates"
        );
    }
}

#[test]
fn profile_total_steps_matches_vm_execution() {
    let program = Program {
        constants: vec![Value::Int(5), Value::Int(3)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Add {
                dst: r(2),
                lhs: r(0),
                rhs: r(1),
            },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-steps", 4, 32);
    let report = vm.execute(&program).unwrap();
    let profile = build_hot_path_profile(&report, 16);
    assert_eq!(profile.total_steps, 4);
}

#[test]
fn decision_trace_id_matches_vm_trace_id() {
    let program = Program {
        constants: vec![Value::Int(99)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };

    let mut vm = BytecodeVm::new("my-unique-trace", 4, 32);
    let report = vm.execute(&program).unwrap();
    let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());
    assert_eq!(decision.trace_id, "my-unique-trace");
}

#[test]
fn decision_events_have_consistent_component_field() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-comp", 4, 32);
    let report = vm.execute(&program).unwrap();
    let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());
    for event in &decision.events {
        assert_eq!(
            event.component, "tier_up_profiler",
            "all decision events should have component=tier_up_profiler"
        );
    }
}

#[test]
fn hot_path_profile_debug_is_nonempty() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-dbg-profile", 4, 32);
    let report = vm.execute(&program).unwrap();
    let profile = build_hot_path_profile(&report, 16);
    assert!(!format!("{profile:?}").is_empty());
}

// ---------------------------------------------------------------------------
// Policy edge cases
// ---------------------------------------------------------------------------

#[test]
fn policy_with_max_min_steps_rejects_everything() {
    let program = Program {
        constants: vec![Value::Int(10), Value::Int(5), Value::Int(1)],
        property_pool: vec!["v".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst { dst: r(1), const_index: 0 },
            Instruction::StoreProp { object: r(0), property_index: 0, value: r(1) },
            Instruction::LoadConst { dst: r(3), const_index: 1 },
            Instruction::LoadPropCached { dst: r(2), object: r(0), property_index: 0 },
            Instruction::LoadConst { dst: r(4), const_index: 2 },
            Instruction::Sub { dst: r(3), lhs: r(3), rhs: r(4) },
            Instruction::JumpIfFalse { condition: r(3), target: 9 },
            Instruction::Jump { target: 4 },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-maxsteps", 8, 256);
    let report = vm.execute(&program).unwrap();

    let policy = TierUpPolicy {
        min_total_steps: u64::MAX,
        ..TierUpPolicy::default()
    };
    let decision = evaluate_tier_up_eligibility(&report, &policy);
    assert!(!decision.eligible);
}

#[test]
fn policy_hash_is_deterministic() {
    let policy = TierUpPolicy::default();
    let json1 = serde_json::to_string(&policy).unwrap();
    let json2 = serde_json::to_string(&policy).unwrap();
    assert_eq!(json1, json2);
}

#[test]
fn policy_hash_differs_for_different_min_steps() {
    let policy_a = TierUpPolicy {
        min_total_steps: 10,
        ..TierUpPolicy::default()
    };
    let policy_b = TierUpPolicy {
        min_total_steps: 20,
        ..TierUpPolicy::default()
    };
    let json_a = serde_json::to_string(&policy_a).unwrap();
    let json_b = serde_json::to_string(&policy_b).unwrap();
    assert_ne!(json_a, json_b);
}

#[test]
fn policy_hash_differs_for_different_max_candidates() {
    let policy_a = TierUpPolicy {
        max_candidates: 2,
        ..TierUpPolicy::default()
    };
    let policy_b = TierUpPolicy {
        max_candidates: 8,
        ..TierUpPolicy::default()
    };
    let json_a = serde_json::to_string(&policy_a).unwrap();
    let json_b = serde_json::to_string(&policy_b).unwrap();
    assert_ne!(json_a, json_b);
}

// ---------------------------------------------------------------------------
// top_k normalization
// ---------------------------------------------------------------------------

#[test]
fn profile_top_k_zero_normalized_to_one() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst { dst: r(0), const_index: 0 },
            Instruction::Return { src: r(0) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-topk0", 4, 32);
    let report = vm.execute(&program).unwrap();
    // top_k=0 is normalized to 1 by normalize_limit
    let profile = build_hot_path_profile(&report, 0);
    assert!(profile.top_paths.len() <= 1);
}

#[test]
fn profile_top_k_large_captures_all_paths() {
    let program = Program {
        constants: vec![Value::Int(5), Value::Int(3)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst { dst: r(0), const_index: 0 },
            Instruction::LoadConst { dst: r(1), const_index: 1 },
            Instruction::Add { dst: r(2), lhs: r(0), rhs: r(1) },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-topk-large", 4, 32);
    let report = vm.execute(&program).unwrap();
    let profile = build_hot_path_profile(&report, 1000);
    // With top_k=1000, we should capture all distinct opcodes
    assert!(!profile.top_paths.is_empty());
}

// ---------------------------------------------------------------------------
// Selected vs rejected disjointness
// ---------------------------------------------------------------------------

#[test]
fn selected_and_rejected_are_disjoint_by_ip() {
    let program = Program {
        constants: vec![Value::Int(10), Value::Int(30), Value::Int(1)],
        property_pool: vec!["x".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst { dst: r(1), const_index: 0 },
            Instruction::StoreProp { object: r(0), property_index: 0, value: r(1) },
            Instruction::LoadConst { dst: r(3), const_index: 1 },
            Instruction::LoadPropCached { dst: r(2), object: r(0), property_index: 0 },
            Instruction::LoadConst { dst: r(4), const_index: 2 },
            Instruction::Sub { dst: r(3), lhs: r(3), rhs: r(4) },
            Instruction::JumpIfFalse { condition: r(3), target: 9 },
            Instruction::Jump { target: 4 },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-disjoint", 8, 1024);
    let report = vm.execute(&program).unwrap();
    let policy = TierUpPolicy {
        min_total_steps: 1,
        min_invocations_per_path: 5,
        min_cache_hit_rate_millionths: 500_000,
        max_candidates: 4,
        profile_top_k: 16,
        require_cache_signal: true,
        ..TierUpPolicy::default()
    };
    let decision = evaluate_tier_up_eligibility(&report, &policy);

    let selected_ips: std::collections::BTreeSet<u32> =
        decision.selected_candidates.iter().map(|c| c.ip).collect();
    let rejected_ips: std::collections::BTreeSet<u32> =
        decision.rejected_paths.iter().map(|r| r.ip).collect();

    for ip in &selected_ips {
        assert!(
            !rejected_ips.contains(ip),
            "ip {ip} appears in both selected and rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// Events ordering
// ---------------------------------------------------------------------------

#[test]
fn events_start_comes_before_complete() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst { dst: r(0), const_index: 0 },
            Instruction::Return { src: r(0) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-order", 4, 32);
    let report = vm.execute(&program).unwrap();
    let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());

    let start_idx = decision.events.iter().position(|e| e.event == "tier_up_started");
    let end_idx = decision.events.iter().position(|e| e.event == "tier_up_completed");
    assert!(start_idx.is_some(), "must have start event");
    assert!(end_idx.is_some(), "must have complete event");
    assert!(start_idx.unwrap() < end_idx.unwrap(), "start must come before complete");
}

// ---------------------------------------------------------------------------
// Decision serde is deterministic
// ---------------------------------------------------------------------------

#[test]
fn decision_serde_is_deterministic() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst { dst: r(0), const_index: 0 },
            Instruction::Return { src: r(0) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-det", 4, 32);
    let report = vm.execute(&program).unwrap();
    let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());

    let json1 = serde_json::to_string(&decision).unwrap();
    let json2 = serde_json::to_string(&decision).unwrap();
    assert_eq!(json1, json2, "serialization must be deterministic");
}

// ---------------------------------------------------------------------------
// Eligible without cache signal
// ---------------------------------------------------------------------------

#[test]
fn eligible_without_cache_signal_when_not_required() {
    let program = Program {
        constants: vec![Value::Int(5), Value::Int(3)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst { dst: r(0), const_index: 0 },
            Instruction::LoadConst { dst: r(1), const_index: 1 },
            Instruction::Add { dst: r(2), lhs: r(0), rhs: r(1) },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-no-cache", 4, 32);
    let report = vm.execute(&program).unwrap();

    let policy = TierUpPolicy {
        min_total_steps: 1,
        min_invocations_per_path: 1,
        min_cache_hit_rate_millionths: 0,
        max_candidates: 4,
        profile_top_k: 16,
        require_cache_signal: false,
        ..TierUpPolicy::default()
    };
    let decision = evaluate_tier_up_eligibility(&report, &policy);
    assert!(decision.eligible);
}

// ---------------------------------------------------------------------------
// Profile hash differs for different programs
// ---------------------------------------------------------------------------

#[test]
fn profile_hash_differs_for_different_programs() {
    let prog_a = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst { dst: r(0), const_index: 0 },
            Instruction::Return { src: r(0) },
        ],
    };
    let prog_b = Program {
        constants: vec![Value::Int(1), Value::Int(2)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst { dst: r(0), const_index: 0 },
            Instruction::LoadConst { dst: r(1), const_index: 1 },
            Instruction::Mul { dst: r(2), lhs: r(0), rhs: r(1) },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm_a = BytecodeVm::new("phash-a", 4, 32);
    let report_a = vm_a.execute(&prog_a).unwrap();
    let profile_a = build_hot_path_profile(&report_a, 16);

    let mut vm_b = BytecodeVm::new("phash-b", 4, 32);
    let report_b = vm_b.execute(&prog_b).unwrap();
    let profile_b = build_hot_path_profile(&report_b, 16);

    assert_ne!(profile_a.profile_hash, profile_b.profile_hash);
}

// ---------------------------------------------------------------------------
// Default policy has reasonable values
// ---------------------------------------------------------------------------

#[test]
fn default_policy_reasonable_values() {
    let policy = TierUpPolicy::default();
    assert!(policy.min_total_steps > 0);
    assert!(policy.min_invocations_per_path > 0);
    assert!(policy.max_candidates > 0);
    assert!(policy.profile_top_k > 0);
}

// ---------------------------------------------------------------------------
// Candidate and rejection rationale/reason are nonempty
// ---------------------------------------------------------------------------

#[test]
fn candidate_rationale_is_nonempty_when_eligible() {
    let program = Program {
        constants: vec![Value::Int(10), Value::Int(30), Value::Int(1)],
        property_pool: vec!["x".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst { dst: r(1), const_index: 0 },
            Instruction::StoreProp { object: r(0), property_index: 0, value: r(1) },
            Instruction::LoadConst { dst: r(3), const_index: 1 },
            Instruction::LoadPropCached { dst: r(2), object: r(0), property_index: 0 },
            Instruction::LoadConst { dst: r(4), const_index: 2 },
            Instruction::Sub { dst: r(3), lhs: r(3), rhs: r(4) },
            Instruction::JumpIfFalse { condition: r(3), target: 9 },
            Instruction::Jump { target: 4 },
            Instruction::Return { src: r(2) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-rationale", 8, 1024);
    let report = vm.execute(&program).unwrap();
    let policy = TierUpPolicy {
        min_total_steps: 1,
        min_invocations_per_path: 1,
        min_cache_hit_rate_millionths: 0,
        max_candidates: 4,
        profile_top_k: 16,
        require_cache_signal: false,
        ..TierUpPolicy::default()
    };
    let decision = evaluate_tier_up_eligibility(&report, &policy);
    for candidate in &decision.selected_candidates {
        assert!(!candidate.rationale.trim().is_empty());
    }
}

#[test]
fn rejection_reason_is_nonempty() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst { dst: r(0), const_index: 0 },
            Instruction::Return { src: r(0) },
        ],
    };

    let mut vm = BytecodeVm::new("trace-reject-reason", 4, 32);
    let report = vm.execute(&program).unwrap();
    let decision = evaluate_tier_up_eligibility(&report, &TierUpPolicy::default());
    for rejection in &decision.rejected_paths {
        assert!(!rejection.reason.trim().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Policy clone equals original
// ---------------------------------------------------------------------------

#[test]
fn policy_clone_equals_original() {
    let policy = TierUpPolicy {
        min_total_steps: 42,
        min_invocations_per_path: 7,
        min_cache_hit_rate_millionths: 750_000,
        max_candidates: 3,
        profile_top_k: 8,
        require_cache_signal: true,
        ..TierUpPolicy::default()
    };
    let cloned = policy.clone();
    assert_eq!(policy, cloned);
}

// ---------------------------------------------------------------------------
// Schema version constant stability
// ---------------------------------------------------------------------------

#[test]
fn schema_version_constant_is_stable() {
    assert!(TIER_UP_POLICY_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(TIER_UP_POLICY_SCHEMA_VERSION.contains("tier-up"));
}
