#![forbid(unsafe_code)]

//! Integration tests for the `resource_escalation_control` module.
//!
//! Covers construction of EscalationLog entries, all escalation action types,
//! termination reason variants, content hash computation, serde serialization,
//! deterministic ordering, and golden artifact tests for JSON output stability.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

// Hoisted scrub patterns (bd-ub6x8.13).
static SCRUB_CONTENT_HASH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""content_hash":\s*\[\s*([0-9]+(?:,\s*[0-9]+)*)\s*\]"#).unwrap());
static SCRUB_TIMESTAMP_NS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""timestamp_ns":\s*[0-9]+"#).unwrap());

use frankenengine_engine::queueing_admission_control::{AdmissionDecision, ShedReason};
use frankenengine_engine::resource_certificate_governance::{GovernanceVerdict, ResourceDimension};
use frankenengine_engine::resource_escalation_control::{
    EscalationAction, EscalationEvent, EscalationLog, TerminationReason,
};
use frankenengine_engine::runtime_decision_theory::{DemotionReason, LaneAction, LaneId};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn sample_throttle_event() -> EscalationEvent {
    EscalationEvent {
        timestamp_ns: 1_000_000_000,
        action: EscalationAction::Throttle {
            decision: AdmissionDecision::Queue {
                estimated_wait_ns: 150_000_000,
                position: 3,
            },
            rationale: "sustained overload requires throttling".to_string(),
        },
        source_module: "queueing_admission_control".to_string(),
        basis: serde_json::json!({
            "utilization_millionths": 880_000,
            "queue_position": 3,
            "stage": "module_load"
        }),
    }
}

fn sample_sandbox_event() -> EscalationEvent {
    EscalationEvent {
        timestamp_ns: 1_150_000_000,
        action: EscalationAction::Sandbox {
            verdict: GovernanceVerdict::MultipleViolations,
            rationale: "resource governance failure requires isolation".to_string(),
        },
        source_module: "resource_certificate_governance".to_string(),
        basis: serde_json::json!({
            "governance_verdict": "multiple_violations",
            "violated_dimensions": ["cpu_time", "heap_memory"]
        }),
    }
}

fn sample_suspend_event() -> EscalationEvent {
    EscalationEvent {
        timestamp_ns: 1_300_000_000,
        action: EscalationAction::Suspend {
            action: LaneAction::SuspendAdaptive,
            rationale: "budget exhaustion requires suspension".to_string(),
        },
        source_module: "runtime_decision_theory".to_string(),
        basis: serde_json::json!({
            "budget_remaining_millionths": 0,
            "lane_action": "suspend_adaptive"
        }),
    }
}

fn sample_terminate_event() -> EscalationEvent {
    let mut measurements = BTreeMap::new();
    measurements.insert(ResourceDimension::CpuTime, 125_000);
    measurements.insert(ResourceDimension::HeapMemory, 80_000_000);

    EscalationEvent {
        timestamp_ns: 1_450_000_000,
        action: EscalationAction::Terminate {
            reason: TerminationReason::PersistentExhaustion {
                dimension: ResourceDimension::CpuTime,
                utilization_millionths: 1_250_000,
                escalation_attempts: 3,
            },
            final_measurements: measurements,
            rationale: "persistent exhaustion despite escalation".to_string(),
        },
        source_module: "resource_escalation_control".to_string(),
        basis: serde_json::json!({
            "escalation_sequence_completed": true,
            "termination_reason": "persistent_exhaustion"
        }),
    }
}

// ---------------------------------------------------------------------------
// Golden artifact tests for escalation log output
// ---------------------------------------------------------------------------

/// Scrub dynamic values from escalation log JSON for deterministic comparison.
fn scrub_escalation_dynamic_fields(json: &str) -> String {
    let mut scrubbed = json.to_string();
    scrubbed = SCRUB_CONTENT_HASH
        .replace_all(&scrubbed, r#""content_hash": "[CONTENT_HASH]""#)
        .into_owned();
    scrubbed = SCRUB_TIMESTAMP_NS
        .replace_all(&scrubbed, r#""timestamp_ns": "[TIMESTAMP_NS]""#)
        .into_owned();
    scrubbed
}

/// Assert escalation log matches golden file with scrubbed dynamic values.
fn assert_escalation_golden(test_name: &str, log: &EscalationLog) {
    let golden_path =
        Path::new("tests/golden/resource_escalation").join(format!("{test_name}.golden"));

    let actual = serde_json::to_string_pretty(log).expect("EscalationLog should serialize to JSON");

    let scrubbed_actual = scrub_escalation_dynamic_fields(&actual);

    // UPDATE MODE: overwrite golden with scrubbed actual output
    if std::env::var("UPDATE_GOLDENS").is_ok() {
        fs::create_dir_all(golden_path.parent().unwrap()).unwrap();
        fs::write(&golden_path, &scrubbed_actual).unwrap();
        eprintln!("[GOLDEN] Updated: {}", golden_path.display());
        return;
    }

    // COMPARE MODE: diff scrubbed actual vs golden
    let expected = fs::read_to_string(&golden_path).unwrap_or_else(|_| {
        panic!(
            "Golden file missing: {}\n\
             Run with UPDATE_GOLDENS=1 to create it\n\
             Then review and commit: git diff tests/golden/resource_escalation/",
            golden_path.display()
        )
    });

    if scrubbed_actual != expected {
        let actual_path = golden_path.with_extension("actual");
        fs::write(&actual_path, &scrubbed_actual).unwrap();

        panic!(
            "GOLDEN MISMATCH: {test_name}\n\n\
             Expected: {}\n\
             Actual: {}\n\n\
             To update: UPDATE_GOLDENS=1 cargo test -- {test_name}\n\
             To review: diff {} {}",
            expected,
            scrubbed_actual,
            golden_path.display(),
            actual_path.display(),
        );
    }

    // Sweep any stale .actual sibling left by a prior failing run (bd-ub6x8.7).
    let _ = fs::remove_file(golden_path.with_extension("actual"));
}

// ---------------------------------------------------------------------------
// Golden test cases covering different escalation sequences
// ---------------------------------------------------------------------------

#[test]
fn golden_escalation_log_complete_sequence() {
    let mut log = EscalationLog::new(
        "test-complete-sequence".to_string(),
        vec![ResourceDimension::CpuTime, ResourceDimension::HeapMemory],
    );

    log.add_event(sample_throttle_event());
    log.add_event(sample_sandbox_event());
    log.add_event(sample_suspend_event());
    log.add_event(sample_terminate_event());

    assert_escalation_golden("complete_sequence", &log);
}

#[test]
fn golden_escalation_log_early_termination() {
    let mut log = EscalationLog::new(
        "test-early-termination".to_string(),
        vec![ResourceDimension::CpuTime],
    );

    log.add_event(sample_throttle_event());
    log.add_event(EscalationEvent {
        timestamp_ns: 1_200_000_000,
        action: EscalationAction::Terminate {
            reason: TerminationReason::Unresponsive {
                timeout_ns: 5_000_000_000,
            },
            final_measurements: {
                let mut measurements = BTreeMap::new();
                measurements.insert(ResourceDimension::CpuTime, 50_000);
                measurements
            },
            rationale: "extension became unresponsive".to_string(),
        },
        source_module: "resource_escalation_control".to_string(),
        basis: serde_json::json!({
            "termination_reason": "unresponsive",
            "timeout_ns": 5_000_000_000i64
        }),
    });

    assert_escalation_golden("early_termination", &log);
}

#[test]
fn golden_escalation_log_repeated_violations() {
    let mut log = EscalationLog::new(
        "test-repeated-violations".to_string(),
        vec![ResourceDimension::HeapMemory],
    );

    log.add_event(sample_throttle_event());
    log.add_event(sample_sandbox_event());
    log.add_event(EscalationEvent {
        timestamp_ns: 1_400_000_000,
        action: EscalationAction::Terminate {
            reason: TerminationReason::RepeatedViolations {
                violation_count: 5,
                violation_span_ns: 300_000_000,
            },
            final_measurements: {
                let mut measurements = BTreeMap::new();
                measurements.insert(ResourceDimension::HeapMemory, 100_000_000);
                measurements
            },
            rationale: "too many governance violations".to_string(),
        },
        source_module: "resource_escalation_control".to_string(),
        basis: serde_json::json!({
            "violation_count": 5,
            "termination_reason": "repeated_violations"
        }),
    });

    assert_escalation_golden("repeated_violations", &log);
}

#[test]
fn golden_escalation_log_shed_decision() {
    let mut log = EscalationLog::new(
        "test-shed-decision".to_string(),
        vec![ResourceDimension::CpuTime],
    );

    log.add_event(EscalationEvent {
        timestamp_ns: 1_000_000_000,
        action: EscalationAction::Throttle {
            decision: AdmissionDecision::Shed {
                reason: ShedReason::UtilizationOverload {
                    current_utilization_millionths: 950_000,
                    shed_threshold_millionths: 900_000,
                },
            },
            rationale: "immediate shedding required under extreme load".to_string(),
        },
        source_module: "queueing_admission_control".to_string(),
        basis: serde_json::json!({
            "admission_decision": "shed",
            "shed_reason": "overload",
            "utilization_millionths": 950_000
        }),
    });

    log.add_event(sample_terminate_event());

    assert_escalation_golden("shed_decision", &log);
}

#[test]
fn golden_escalation_log_minimal_single_dimension() {
    let mut log = EscalationLog::new("minimal-test".to_string(), vec![ResourceDimension::CpuTime]);

    log.add_event(EscalationEvent {
        timestamp_ns: 1_000_000_000,
        action: EscalationAction::Suspend {
            action: LaneAction::Demote {
                from_lane: LaneId::throughput_profile(),
                reason: DemotionReason::BudgetExhausted,
            },
            rationale: "direct demotion for budget exhaustion".to_string(),
        },
        source_module: "runtime_decision_theory".to_string(),
        basis: serde_json::json!({
            "budget_remaining_millionths": 10_000,
            "lane_action": "demote"
        }),
    });

    assert_escalation_golden("minimal_single_dimension", &log);
}

// ---------------------------------------------------------------------------
// Unit tests for construction and basic functionality
// ---------------------------------------------------------------------------

#[test]
fn escalation_log_construction() {
    let log = EscalationLog::new(
        "test-workload".to_string(),
        vec![ResourceDimension::CpuTime, ResourceDimension::HeapMemory],
    );

    assert_eq!(log.workload_id, "test-workload");
    assert_eq!(log.bounded_budget_dimensions.len(), 2);
    assert_eq!(
        log.expected_sequence,
        vec!["throttle", "sandbox", "suspend", "terminate"]
    );
    assert_eq!(log.events.len(), 0);
    assert!(!log.content_hash.as_bytes().is_empty());
}

#[test]
fn escalation_action_display() {
    let throttle = EscalationAction::Throttle {
        decision: AdmissionDecision::Queue {
            estimated_wait_ns: 1000,
            position: 1,
        },
        rationale: "test".to_string(),
    };
    assert_eq!(throttle.to_string(), "throttle");

    let sandbox = EscalationAction::Sandbox {
        verdict: GovernanceVerdict::Approved,
        rationale: "test".to_string(),
    };
    assert_eq!(sandbox.to_string(), "sandbox");

    let suspend = EscalationAction::Suspend {
        action: LaneAction::Demote {
            from_lane: LaneId::throughput_profile(),
            reason: DemotionReason::BudgetExhausted,
        },
        rationale: "test".to_string(),
    };
    assert_eq!(suspend.to_string(), "suspend");

    let terminate = EscalationAction::Terminate {
        reason: TerminationReason::Unresponsive { timeout_ns: 1000 },
        final_measurements: BTreeMap::new(),
        rationale: "test".to_string(),
    };
    assert_eq!(terminate.to_string(), "terminate");
}

#[test]
fn termination_reason_display() {
    let persistent = TerminationReason::PersistentExhaustion {
        dimension: ResourceDimension::CpuTime,
        utilization_millionths: 1_200_000,
        escalation_attempts: 3,
    };
    assert_eq!(persistent.to_string(), "persistent_exhaustion(cpu_time)");

    let violations = TerminationReason::RepeatedViolations {
        violation_count: 5,
        violation_span_ns: 1_000_000_000,
    };
    assert_eq!(violations.to_string(), "repeated_violations(count=5)");

    let unresponsive = TerminationReason::Unresponsive {
        timeout_ns: 5_000_000_000,
    };
    assert_eq!(
        unresponsive.to_string(),
        "unresponsive(timeout_ns=5000000000)"
    );
}

#[test]
fn escalation_log_event_ordering() {
    let mut log = EscalationLog::new("test".to_string(), vec![ResourceDimension::CpuTime]);

    let event1 = EscalationEvent {
        timestamp_ns: 1_000_000_000,
        action: sample_throttle_event().action,
        source_module: "test1".to_string(),
        basis: serde_json::json!({}),
    };

    let event2 = EscalationEvent {
        timestamp_ns: 2_000_000_000,
        action: sample_sandbox_event().action,
        source_module: "test2".to_string(),
        basis: serde_json::json!({}),
    };

    log.add_event(event2.clone());
    log.add_event(event1.clone());

    // Events should maintain insertion order
    assert_eq!(log.events[0].timestamp_ns, 2_000_000_000);
    assert_eq!(log.events[1].timestamp_ns, 1_000_000_000);

    // But monotonic timestamp check should fail
    assert!(!log.has_monotonic_timestamps());
}

#[test]
fn escalation_log_completion_check() {
    let mut log = EscalationLog::new("test".to_string(), vec![ResourceDimension::CpuTime]);

    assert!(!log.is_complete());

    log.add_event(sample_throttle_event());
    log.add_event(sample_sandbox_event());
    log.add_event(sample_suspend_event());
    log.add_event(sample_terminate_event());

    assert!(log.is_complete());
}

#[test]
fn escalation_log_content_hash_stability() {
    let log1 = EscalationLog::new("test".to_string(), vec![ResourceDimension::CpuTime]);
    let log2 = EscalationLog::new("test".to_string(), vec![ResourceDimension::CpuTime]);

    // Same inputs should produce same hash
    assert_eq!(log1.content_hash, log2.content_hash);

    let mut log3 = log1.clone();
    log3.add_event(sample_throttle_event());

    // Different events should produce different hash
    assert_ne!(log1.content_hash, log3.content_hash);
}

#[test]
fn escalation_log_serde_roundtrip() {
    let mut log = EscalationLog::new(
        "serde-test".to_string(),
        vec![ResourceDimension::CpuTime, ResourceDimension::HeapMemory],
    );

    log.add_event(sample_throttle_event());
    log.add_event(sample_terminate_event());

    let json = serde_json::to_string(&log).unwrap();
    let restored: EscalationLog = serde_json::from_str(&json).unwrap();

    assert_eq!(log, restored);
    assert_eq!(log.content_hash, restored.content_hash);
}
