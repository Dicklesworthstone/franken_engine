//! Deep integration tests for queueing_admission_control module.
//!
//! Covers: admission priority ranking, decision classification, shed reason
//! formatting, serde roundtrips, Display impls, and constant validation.

use frankenengine_engine::queueing_admission_control::{
    ADMISSION_BEAD_ID, ADMISSION_SCHEMA_VERSION, AdmissionDecision, AdmissionPriority,
    DEFAULT_BURST_CAPACITY, DEFAULT_MAX_QUEUE_DEPTH, DEFAULT_REFILL_RATE,
    DEFAULT_TARGET_UTILIZATION_MILLIONTHS, ShedReason,
};
use frankenengine_engine::stage_envelope_certificate::ExecutionStage;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn deep_constants_nonempty() {
    assert!(!ADMISSION_SCHEMA_VERSION.is_empty());
    assert!(!ADMISSION_BEAD_ID.is_empty());
    assert!(ADMISSION_BEAD_ID.starts_with("bd-"));
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn deep_defaults_sane() {
    assert!(DEFAULT_MAX_QUEUE_DEPTH > 0);
    assert!(DEFAULT_TARGET_UTILIZATION_MILLIONTHS > 0);
    assert!(DEFAULT_TARGET_UTILIZATION_MILLIONTHS <= 1_000_000);
    assert!(DEFAULT_BURST_CAPACITY > 0);
    assert!(DEFAULT_REFILL_RATE > 0);
}

// ---------------------------------------------------------------------------
// AdmissionPriority
// ---------------------------------------------------------------------------

#[test]
fn deep_priority_rank_ordering() {
    let priorities = [
        AdmissionPriority::Critical,
        AdmissionPriority::High,
        AdmissionPriority::Normal,
        AdmissionPriority::Low,
        AdmissionPriority::BestEffort,
    ];
    for window in priorities.windows(2) {
        assert!(
            window[0].rank() < window[1].rank(),
            "{} should have lower rank than {}",
            format_args!("{}", window[0]),
            format_args!("{}", window[1])
        );
    }
}

#[test]
fn deep_priority_unshedable() {
    assert!(AdmissionPriority::Critical.is_unshedable());
    assert!(!AdmissionPriority::High.is_unshedable());
    assert!(!AdmissionPriority::Normal.is_unshedable());
    assert!(!AdmissionPriority::Low.is_unshedable());
    assert!(!AdmissionPriority::BestEffort.is_unshedable());
}

#[test]
fn deep_priority_display_all() {
    let expected = [
        (AdmissionPriority::Critical, "critical"),
        (AdmissionPriority::High, "high"),
        (AdmissionPriority::Normal, "normal"),
        (AdmissionPriority::Low, "low"),
        (AdmissionPriority::BestEffort, "best_effort"),
    ];
    for (prio, name) in expected {
        assert_eq!(format!("{prio}"), name);
    }
}

#[test]
fn deep_priority_serde_roundtrip() {
    let priorities = [
        AdmissionPriority::Critical,
        AdmissionPriority::High,
        AdmissionPriority::Normal,
        AdmissionPriority::Low,
        AdmissionPriority::BestEffort,
    ];
    for prio in priorities {
        let json = serde_json::to_string(&prio).unwrap();
        let decoded: AdmissionPriority = serde_json::from_str(&json).unwrap();
        assert_eq!(prio, decoded);
    }
}

// ---------------------------------------------------------------------------
// AdmissionDecision
// ---------------------------------------------------------------------------

#[test]
fn deep_decision_admit_display() {
    let d = AdmissionDecision::Admit;
    assert_eq!(format!("{d}"), "admit");
}

#[test]
fn deep_decision_queue_display() {
    let d = AdmissionDecision::Queue {
        estimated_wait_ns: 5000,
        position: 3,
    };
    let display = format!("{d}");
    assert!(display.contains("queue"));
    assert!(display.contains("pos=3"));
}

#[test]
fn deep_decision_shed_display() {
    let d = AdmissionDecision::Shed {
        reason: ShedReason::QueueFull {
            current_depth: 1024,
            max_depth: 1024,
        },
    };
    let display = format!("{d}");
    assert!(display.contains("shed"));
    assert!(display.contains("queue_full"));
}

#[test]
fn deep_decision_serde_roundtrip_admit() {
    let d = AdmissionDecision::Admit;
    let json = serde_json::to_string(&d).unwrap();
    let decoded: AdmissionDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, decoded);
}

#[test]
fn deep_decision_serde_roundtrip_queue() {
    let d = AdmissionDecision::Queue {
        estimated_wait_ns: 10_000,
        position: 5,
    };
    let json = serde_json::to_string(&d).unwrap();
    let decoded: AdmissionDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, decoded);
}

#[test]
fn deep_decision_serde_roundtrip_shed() {
    let d = AdmissionDecision::Shed {
        reason: ShedReason::TokensExhausted {
            tokens_available: 0,
            tokens_required: 10,
        },
    };
    let json = serde_json::to_string(&d).unwrap();
    let decoded: AdmissionDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, decoded);
}

// ---------------------------------------------------------------------------
// ShedReason
// ---------------------------------------------------------------------------

#[test]
fn deep_shed_reason_queue_full_display() {
    let r = ShedReason::QueueFull {
        current_depth: 512,
        max_depth: 1024,
    };
    let display = format!("{r}");
    assert!(display.contains("queue_full"));
    assert!(display.contains("512"));
    assert!(display.contains("1024"));
}

#[test]
fn deep_shed_reason_tokens_exhausted_display() {
    let r = ShedReason::TokensExhausted {
        tokens_available: 0,
        tokens_required: 5,
    };
    let display = format!("{r}");
    assert!(display.contains("tokens_exhausted"));
}

#[test]
fn deep_shed_reason_utilization_overload_display() {
    let r = ShedReason::UtilizationOverload {
        current_utilization_millionths: 950_000,
        shed_threshold_millionths: 900_000,
    };
    let display = format!("{r}");
    assert!(display.contains("utilization_overload"));
    assert!(display.contains("950000"));
}

#[test]
fn deep_shed_reason_priority_shed_display() {
    let r = ShedReason::PriorityShed {
        item_priority: AdmissionPriority::BestEffort,
        min_admitted_priority: AdmissionPriority::Normal,
    };
    let display = format!("{r}");
    assert!(display.contains("priority_shed"));
}

#[test]
fn deep_shed_reason_stage_exhausted_display() {
    let r = ShedReason::StageBudgetExhausted {
        stage: ExecutionStage::Parse,
        stage_queue_depth: 100,
        stage_max_depth: 50,
    };
    let display = format!("{r}");
    assert!(display.contains("stage_exhausted"));
}

#[test]
fn deep_shed_reason_serde_roundtrip_all() {
    let reasons = [
        ShedReason::QueueFull {
            current_depth: 100,
            max_depth: 100,
        },
        ShedReason::TokensExhausted {
            tokens_available: 0,
            tokens_required: 5,
        },
        ShedReason::UtilizationOverload {
            current_utilization_millionths: 950_000,
            shed_threshold_millionths: 900_000,
        },
        ShedReason::PriorityShed {
            item_priority: AdmissionPriority::Low,
            min_admitted_priority: AdmissionPriority::High,
        },
        ShedReason::StageBudgetExhausted {
            stage: ExecutionStage::Parse,
            stage_queue_depth: 100,
            stage_max_depth: 50,
        },
    ];
    for reason in &reasons {
        let json = serde_json::to_string(reason).unwrap();
        let decoded: ShedReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, decoded);
    }
}

// ---------------------------------------------------------------------------
// Cross-type interactions
// ---------------------------------------------------------------------------

#[test]
fn deep_priority_rank_unique_per_variant() {
    let all = [
        AdmissionPriority::Critical,
        AdmissionPriority::High,
        AdmissionPriority::Normal,
        AdmissionPriority::Low,
        AdmissionPriority::BestEffort,
    ];
    let mut ranks = std::collections::BTreeSet::new();
    for prio in all {
        assert!(ranks.insert(prio.rank()), "{prio} has duplicate rank");
    }
    assert_eq!(ranks.len(), 5);
}

#[test]
fn deep_decision_admit_is_not_shed() {
    let d = AdmissionDecision::Admit;
    let json = serde_json::to_string(&d).unwrap();
    assert!(!json.contains("shed"));
    assert!(!json.contains("queue"));
}

#[test]
fn deep_decision_queue_preserves_fields() {
    let d = AdmissionDecision::Queue {
        estimated_wait_ns: 42_000,
        position: 7,
    };
    let json = serde_json::to_string(&d).unwrap();
    let decoded: AdmissionDecision = serde_json::from_str(&json).unwrap();
    if let AdmissionDecision::Queue {
        estimated_wait_ns,
        position,
    } = decoded
    {
        assert_eq!(estimated_wait_ns, 42_000);
        assert_eq!(position, 7);
    } else {
        panic!("Expected Queue variant");
    }
}

#[test]
fn deep_shed_reason_display_unique_per_variant() {
    let reasons = [
        ShedReason::QueueFull {
            current_depth: 1,
            max_depth: 1,
        },
        ShedReason::TokensExhausted {
            tokens_available: 0,
            tokens_required: 1,
        },
        ShedReason::UtilizationOverload {
            current_utilization_millionths: 1,
            shed_threshold_millionths: 0,
        },
        ShedReason::PriorityShed {
            item_priority: AdmissionPriority::Low,
            min_admitted_priority: AdmissionPriority::High,
        },
        ShedReason::StageBudgetExhausted {
            stage: ExecutionStage::Parse,
            stage_queue_depth: 1,
            stage_max_depth: 0,
        },
    ];
    let mut displays = std::collections::BTreeSet::new();
    for reason in &reasons {
        let display = format!("{reason}");
        assert!(
            displays.insert(display.clone()),
            "Duplicate display: {display}"
        );
    }
}
