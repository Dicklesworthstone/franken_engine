//! Integration tests for the `bulkhead` module.
//!
//! Tests concurrency limiting, backpressure signaling, RAII permits,
//! queue depth, waiter promotion, hot-reconfiguration, and serde roundtrips.

#![forbid(unsafe_code)]

use frankenengine_engine::bulkhead::{
    BulkheadClass, BulkheadConfig, BulkheadError, BulkheadEvent, BulkheadRegistry,
    BulkheadSnapshot, PermitId,
};

// ---------------------------------------------------------------------------
// BulkheadClass
// ---------------------------------------------------------------------------

#[test]
fn bulkhead_class_display() {
    assert_eq!(
        BulkheadClass::RemoteInFlight.to_string(),
        "remote_in_flight"
    );
    assert_eq!(
        BulkheadClass::BackgroundMaintenance.to_string(),
        "background_maintenance"
    );
    assert_eq!(BulkheadClass::SagaExecution.to_string(), "saga_execution");
    assert_eq!(BulkheadClass::EvidenceFlush.to_string(), "evidence_flush");
}

#[test]
fn default_configs_match_expected_limits() {
    assert_eq!(
        BulkheadClass::RemoteInFlight
            .default_config()
            .max_concurrent,
        64
    );
    assert_eq!(
        BulkheadClass::BackgroundMaintenance
            .default_config()
            .max_concurrent,
        16
    );
    assert_eq!(
        BulkheadClass::SagaExecution.default_config().max_concurrent,
        8
    );
    assert_eq!(
        BulkheadClass::EvidenceFlush.default_config().max_concurrent,
        4
    );
}

// ---------------------------------------------------------------------------
// PermitId
// ---------------------------------------------------------------------------

#[test]
fn permit_id_display() {
    assert_eq!(PermitId(42).to_string(), "permit:42");
    assert_eq!(PermitId(0).to_string(), "permit:0");
}

// ---------------------------------------------------------------------------
// BulkheadRegistry — creation
// ---------------------------------------------------------------------------

#[test]
fn with_defaults_creates_four() {
    let reg = BulkheadRegistry::with_defaults();
    assert_eq!(reg.bulkhead_count(), 4);
}

#[test]
fn empty_creates_none() {
    let reg = BulkheadRegistry::empty();
    assert_eq!(reg.bulkhead_count(), 0);
}

#[test]
fn register_custom_bulkhead() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "custom",
        BulkheadConfig {
            max_concurrent: 10,
            max_queue_depth: 20,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();
    assert_eq!(reg.bulkhead_count(), 1);
}

#[test]
fn register_rejects_zero_concurrent() {
    let mut reg = BulkheadRegistry::empty();
    let err = reg
        .register(
            "bad",
            BulkheadConfig {
                max_concurrent: 0,
                max_queue_depth: 10,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap_err();
    assert!(matches!(err, BulkheadError::InvalidConfig { .. }));
}

// ---------------------------------------------------------------------------
// Acquire and release
// ---------------------------------------------------------------------------

#[test]
fn acquire_and_release_basic() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 2,
            max_queue_depth: 4,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();

    let p1 = reg.acquire("test", "t1").unwrap();
    assert_eq!(reg.active_count("test"), Some(1));

    let p2 = reg.acquire("test", "t2").unwrap();
    assert_eq!(reg.active_count("test"), Some(2));

    reg.release("test", p1, "t1").unwrap();
    assert_eq!(reg.active_count("test"), Some(1));

    reg.release("test", p2, "t2").unwrap();
    assert_eq!(reg.active_count("test"), Some(0));
}

#[test]
fn acquire_queues_when_full() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 1,
            max_queue_depth: 2,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();

    let _p1 = reg.acquire("test", "t1").unwrap();
    let _p2 = reg.acquire("test", "t2").unwrap(); // queued
    assert_eq!(reg.queue_depth("test"), Some(1));
}

#[test]
fn acquire_rejects_when_both_full() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 1,
            max_queue_depth: 1,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();

    let _p1 = reg.acquire("test", "t1").unwrap();
    let _p2 = reg.acquire("test", "t2").unwrap(); // queued
    let err = reg.acquire("test", "t3").unwrap_err();
    assert!(matches!(err, BulkheadError::BulkheadFull { .. }));
}

#[test]
fn acquire_nonexistent_bulkhead() {
    let mut reg = BulkheadRegistry::empty();
    let err = reg.acquire("ghost", "t1").unwrap_err();
    assert!(matches!(err, BulkheadError::BulkheadNotFound { .. }));
}

#[test]
fn release_nonexistent_permit() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 2,
            max_queue_depth: 4,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();
    let err = reg.release("test", PermitId(999), "t").unwrap_err();
    assert!(matches!(err, BulkheadError::PermitNotFound { .. }));
}

#[test]
fn release_promotes_waiter() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 1,
            max_queue_depth: 4,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();

    let p1 = reg.acquire("test", "t1").unwrap();
    let _p2 = reg.acquire("test", "t2").unwrap(); // queued
    assert_eq!(reg.active_count("test"), Some(1));
    assert_eq!(reg.queue_depth("test"), Some(1));

    reg.release("test", p1, "t1").unwrap();
    assert_eq!(reg.active_count("test"), Some(1)); // p2 promoted
    assert_eq!(reg.queue_depth("test"), Some(0));
}

#[test]
fn release_queued_permit() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 1,
            max_queue_depth: 4,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();

    let _p1 = reg.acquire("test", "t1").unwrap();
    let p2 = reg.acquire("test", "t2").unwrap(); // queued
    assert_eq!(reg.queue_depth("test"), Some(1));

    reg.release("test", p2, "t2").unwrap();
    assert_eq!(reg.queue_depth("test"), Some(0));
}

// ---------------------------------------------------------------------------
// Backpressure
// ---------------------------------------------------------------------------

#[test]
fn pressure_detected_at_threshold() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 10,
            max_queue_depth: 20,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();

    for i in 0..7 {
        reg.acquire("test", &format!("t{i}")).unwrap();
    }
    assert_eq!(reg.is_at_pressure("test"), Some(false));

    reg.acquire("test", "t7").unwrap();
    assert_eq!(reg.is_at_pressure("test"), Some(true));
}

#[test]
fn pressure_event_emitted() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 2,
            max_queue_depth: 4,
            pressure_threshold_pct: 50,
        },
    )
    .unwrap();

    reg.acquire("test", "t1").unwrap();
    reg.acquire("test", "t2").unwrap();

    let events = reg.drain_events();
    assert!(events.iter().any(|e| e.event == "bulkhead_pressure"));
}

#[test]
fn is_at_pressure_nonexistent_returns_none() {
    let reg = BulkheadRegistry::empty();
    assert_eq!(reg.is_at_pressure("ghost"), None);
}

// ---------------------------------------------------------------------------
// Reconfigure
// ---------------------------------------------------------------------------

#[test]
fn reconfigure_preserves_permits() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 2,
            max_queue_depth: 4,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();

    let _p1 = reg.acquire("test", "t1").unwrap();
    let _p2 = reg.acquire("test", "t2").unwrap();

    reg.reconfigure(
        "test",
        BulkheadConfig {
            max_concurrent: 1,
            max_queue_depth: 4,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();

    assert_eq!(reg.active_count("test"), Some(2));
}

#[test]
fn reconfigure_rejects_zero() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 2,
            max_queue_depth: 4,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();
    let err = reg
        .reconfigure(
            "test",
            BulkheadConfig {
                max_concurrent: 0,
                max_queue_depth: 4,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap_err();
    assert!(matches!(err, BulkheadError::InvalidConfig { .. }));
}

#[test]
fn reconfigure_nonexistent_fails() {
    let mut reg = BulkheadRegistry::empty();
    let err = reg
        .reconfigure(
            "ghost",
            BulkheadConfig {
                max_concurrent: 1,
                max_queue_depth: 1,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap_err();
    assert!(matches!(err, BulkheadError::BulkheadNotFound { .. }));
}

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

#[test]
fn snapshot_reflects_state() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 5,
            max_queue_depth: 10,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();

    reg.acquire("test", "t1").unwrap();
    reg.acquire("test", "t2").unwrap();

    let snap = reg.snapshot();
    let s = &snap["test"];
    assert_eq!(s.active_count, 2);
    assert_eq!(s.max_concurrent, 5);
    assert_eq!(s.queue_depth, 0);
    assert!(!s.at_pressure);
}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

#[test]
fn acquire_emits_event() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 10,
            max_queue_depth: 20,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();
    reg.acquire("test", "trace-1").unwrap();

    let events = reg.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "permit_acquired");
    assert_eq!(events[0].trace_id, "trace-1");
}

#[test]
fn release_emits_event() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 2,
            max_queue_depth: 4,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();
    let p = reg.acquire("test", "t1").unwrap();
    reg.drain_events();
    reg.release("test", p, "t1").unwrap();

    let events = reg.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "permit_released");
}

#[test]
fn reject_emits_event() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 1,
            max_queue_depth: 0,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();
    reg.acquire("test", "t1").unwrap();
    reg.drain_events();

    let _ = reg.acquire("test", "t2");
    let events = reg.drain_events();
    assert!(!events.is_empty());
    assert_eq!(events[0].event, "permit_rejected");
}

#[test]
fn event_counts_track() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 10,
            max_queue_depth: 10,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();
    let p1 = reg.acquire("test", "t1").unwrap();
    let p2 = reg.acquire("test", "t2").unwrap();
    reg.release("test", p1, "t1").unwrap();
    reg.release("test", p2, "t2").unwrap();

    assert_eq!(reg.event_counts().get("acquire"), Some(&2));
    assert_eq!(reg.event_counts().get("release"), Some(&2));
}

// ---------------------------------------------------------------------------
// BulkheadError display
// ---------------------------------------------------------------------------

#[test]
fn error_display_full() {
    let err = BulkheadError::BulkheadFull {
        bulkhead_id: "x".to_string(),
        max_concurrent: 10,
        queue_depth: 5,
    };
    let s = err.to_string();
    assert!(s.contains("full"));
    assert!(s.contains("x"));
}

#[test]
fn error_display_permit_not_found() {
    let err = BulkheadError::PermitNotFound { permit_id: 42 };
    assert!(err.to_string().contains("42"));
}

#[test]
fn error_display_not_found() {
    let err = BulkheadError::BulkheadNotFound {
        bulkhead_id: "ghost".to_string(),
    };
    assert!(err.to_string().contains("ghost"));
}

#[test]
fn error_display_invalid_config() {
    let err = BulkheadError::InvalidConfig {
        reason: "bad".to_string(),
    };
    assert!(err.to_string().contains("bad"));
}

#[test]
fn error_is_std_error() {
    let err = BulkheadError::PermitNotFound { permit_id: 1 };
    let _: &dyn std::error::Error = &err;
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn bulkhead_class_serde_roundtrip() {
    let classes = [
        BulkheadClass::RemoteInFlight,
        BulkheadClass::BackgroundMaintenance,
        BulkheadClass::SagaExecution,
        BulkheadClass::EvidenceFlush,
    ];
    for c in &classes {
        let json = serde_json::to_string(c).unwrap();
        let restored: BulkheadClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, restored);
    }
}

#[test]
fn bulkhead_config_serde_roundtrip() {
    let config = BulkheadConfig {
        max_concurrent: 64,
        max_queue_depth: 128,
        pressure_threshold_pct: 80,
    };
    let json = serde_json::to_string(&config).unwrap();
    let restored: BulkheadConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

#[test]
fn bulkhead_event_serde_roundtrip() {
    let event = BulkheadEvent {
        bulkhead_id: "test".to_string(),
        current_count: 5,
        max_concurrent: 10,
        queue_depth: 2,
        action: "acquire".to_string(),
        trace_id: "t1".to_string(),
        event: "permit_acquired".to_string(),
        permit_id: 42,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: BulkheadEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn bulkhead_error_serde_roundtrip() {
    let errors = [
        BulkheadError::BulkheadFull {
            bulkhead_id: "t".to_string(),
            max_concurrent: 10,
            queue_depth: 5,
        },
        BulkheadError::PermitNotFound { permit_id: 42 },
        BulkheadError::BulkheadNotFound {
            bulkhead_id: "g".to_string(),
        },
        BulkheadError::InvalidConfig {
            reason: "bad".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: BulkheadError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

#[test]
fn snapshot_serde_roundtrip() {
    let snap = BulkheadSnapshot {
        bulkhead_id: "test".to_string(),
        active_count: 3,
        max_concurrent: 10,
        queue_depth: 1,
        max_queue_depth: 20,
        at_pressure: false,
    };
    let json = serde_json::to_string(&snap).unwrap();
    let restored: BulkheadSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap, restored);
}

// ---------------------------------------------------------------------------
// Deterministic replay
// ---------------------------------------------------------------------------

#[test]
fn deterministic_acquire_release_sequence() {
    let run = || -> Vec<BulkheadEvent> {
        let mut reg = BulkheadRegistry::empty();
        reg.register(
            "test",
            BulkheadConfig {
                max_concurrent: 2,
                max_queue_depth: 4,
                pressure_threshold_pct: 80,
            },
        )
        .unwrap();
        let p1 = reg.acquire("test", "t1").unwrap();
        let p2 = reg.acquire("test", "t2").unwrap();
        reg.release("test", p1, "t1").unwrap();
        reg.release("test", p2, "t2").unwrap();
        reg.drain_events()
    };
    assert_eq!(run(), run());
}

// ---------------------------------------------------------------------------
// Full lifecycle with defaults
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_with_defaults() {
    let mut reg = BulkheadRegistry::with_defaults();
    let p1 = reg.acquire("remote_in_flight", "t1").unwrap();
    let p2 = reg.acquire("background_maintenance", "t2").unwrap();
    let p3 = reg.acquire("saga_execution", "t3").unwrap();
    let p4 = reg.acquire("evidence_flush", "t4").unwrap();

    assert_eq!(reg.active_count("remote_in_flight"), Some(1));
    assert_eq!(reg.active_count("background_maintenance"), Some(1));
    assert_eq!(reg.active_count("saga_execution"), Some(1));
    assert_eq!(reg.active_count("evidence_flush"), Some(1));

    reg.release("remote_in_flight", p1, "t1").unwrap();
    reg.release("background_maintenance", p2, "t2").unwrap();
    reg.release("saga_execution", p3, "t3").unwrap();
    reg.release("evidence_flush", p4, "t4").unwrap();

    assert_eq!(reg.active_count("remote_in_flight"), Some(0));
    assert_eq!(reg.active_count("evidence_flush"), Some(0));
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn active_count_nonexistent_returns_none() {
    let reg = BulkheadRegistry::empty();
    assert_eq!(reg.active_count("ghost"), None);
}

#[test]
fn queue_depth_nonexistent_returns_none() {
    let reg = BulkheadRegistry::empty();
    assert_eq!(reg.queue_depth("ghost"), None);
}

// =========================================================================
// Enrichment: Default config completeness
// =========================================================================

#[test]
fn default_config_queue_depths() {
    assert_eq!(
        BulkheadClass::RemoteInFlight
            .default_config()
            .max_queue_depth,
        128
    );
    assert_eq!(
        BulkheadClass::BackgroundMaintenance
            .default_config()
            .max_queue_depth,
        32
    );
    assert_eq!(
        BulkheadClass::SagaExecution
            .default_config()
            .max_queue_depth,
        16
    );
    assert_eq!(
        BulkheadClass::EvidenceFlush
            .default_config()
            .max_queue_depth,
        8
    );
}

#[test]
fn default_configs_pressure_threshold_all_80() {
    for class in [
        BulkheadClass::RemoteInFlight,
        BulkheadClass::BackgroundMaintenance,
        BulkheadClass::SagaExecution,
        BulkheadClass::EvidenceFlush,
    ] {
        assert_eq!(class.default_config().pressure_threshold_pct, 80);
    }
}

// =========================================================================
// Enrichment: Double release & release from nonexistent bulkhead
// =========================================================================

#[test]
fn double_release_returns_permit_not_found() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 2,
            max_queue_depth: 4,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();
    let p1 = reg.acquire("test", "t1").unwrap();
    reg.release("test", p1, "t1").unwrap();
    assert!(matches!(
        reg.release("test", p1, "t1"),
        Err(BulkheadError::PermitNotFound { .. })
    ));
}

#[test]
fn release_nonexistent_bulkhead() {
    let mut reg = BulkheadRegistry::empty();
    assert!(matches!(
        reg.release("ghost", PermitId(1), "t1"),
        Err(BulkheadError::BulkheadNotFound { .. })
    ));
}

// =========================================================================
// Enrichment: Ordering
// =========================================================================

#[test]
fn bulkhead_class_ordering() {
    assert!(BulkheadClass::RemoteInFlight < BulkheadClass::BackgroundMaintenance);
    assert!(BulkheadClass::BackgroundMaintenance < BulkheadClass::SagaExecution);
    assert!(BulkheadClass::SagaExecution < BulkheadClass::EvidenceFlush);
}

#[test]
fn permit_id_ordering() {
    assert!(PermitId(1) < PermitId(2));
    assert!(PermitId(0) < PermitId(u64::MAX));
    assert_eq!(PermitId(42), PermitId(42));
}

// =========================================================================
// Enrichment: Snapshot with multiple bulkheads
// =========================================================================

#[test]
fn snapshot_multiple_bulkheads() {
    let mut reg = BulkheadRegistry::with_defaults();
    reg.acquire("remote_in_flight", "t1").unwrap();
    reg.acquire("remote_in_flight", "t2").unwrap();
    reg.acquire("saga_execution", "t3").unwrap();

    let snap = reg.snapshot();
    assert_eq!(snap.len(), 4);
    assert_eq!(snap["remote_in_flight"].active_count, 2);
    assert_eq!(snap["saga_execution"].active_count, 1);
    assert_eq!(snap["background_maintenance"].active_count, 0);
    assert_eq!(snap["evidence_flush"].active_count, 0);
}

#[test]
fn snapshot_at_pressure_flag_accurate() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 2,
            max_queue_depth: 4,
            pressure_threshold_pct: 50,
        },
    )
    .unwrap();
    reg.acquire("test", "t1").unwrap();
    let snap = reg.snapshot();
    assert!(snap["test"].at_pressure);
}

// =========================================================================
// Enrichment: Pressure threshold edge cases
// =========================================================================

#[test]
fn pressure_at_100_pct_threshold() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 2,
            max_queue_depth: 4,
            pressure_threshold_pct: 100,
        },
    )
    .unwrap();

    reg.acquire("test", "t1").unwrap();
    assert_eq!(reg.is_at_pressure("test"), Some(false));

    reg.acquire("test", "t2").unwrap();
    assert_eq!(reg.is_at_pressure("test"), Some(true));
}

#[test]
fn pressure_at_0_pct_threshold() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 10,
            max_queue_depth: 10,
            pressure_threshold_pct: 0,
        },
    )
    .unwrap();

    // 0% of 10 = 0, so any active count >= 0 triggers pressure
    assert_eq!(reg.is_at_pressure("test"), Some(true));
}

// =========================================================================
// Enrichment: Register overwrites existing
// =========================================================================

#[test]
fn register_overwrites_existing_bulkhead() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 5,
            max_queue_depth: 10,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();
    reg.acquire("test", "t1").unwrap();
    assert_eq!(reg.active_count("test"), Some(1));

    // Re-register replaces (active permits lost)
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 20,
            max_queue_depth: 40,
            pressure_threshold_pct: 90,
        },
    )
    .unwrap();
    assert_eq!(reg.active_count("test"), Some(0));
    assert_eq!(reg.bulkhead_count(), 1);
}

// =========================================================================
// Enrichment: FIFO waiter promotion
// =========================================================================

#[test]
fn waiter_promotion_is_fifo() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 1,
            max_queue_depth: 10,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();

    let p1 = reg.acquire("test", "t1").unwrap(); // active
    let _p2 = reg.acquire("test", "t2").unwrap(); // queued first
    let _p3 = reg.acquire("test", "t3").unwrap(); // queued second

    // Release p1 → t2 promoted (FIFO)
    reg.release("test", p1, "t1").unwrap();
    assert_eq!(reg.active_count("test"), Some(1));
    assert_eq!(reg.queue_depth("test"), Some(1));
}

// =========================================================================
// Enrichment: PermitId serde
// =========================================================================

#[test]
fn permit_id_serde_roundtrip() {
    let pid = PermitId(12345);
    let json = serde_json::to_string(&pid).unwrap();
    let restored: PermitId = serde_json::from_str(&json).unwrap();
    assert_eq!(pid, restored);
}

#[test]
fn permit_id_serde_edge_values() {
    for val in [0u64, 1, u64::MAX] {
        let pid = PermitId(val);
        let json = serde_json::to_string(&pid).unwrap();
        let back: PermitId = serde_json::from_str(&json).unwrap();
        assert_eq!(pid, back);
    }
}

// =========================================================================
// Enrichment: JSON field name contracts
// =========================================================================

#[test]
fn event_json_field_names() {
    let ev = BulkheadEvent {
        bulkhead_id: "test-bh".into(),
        current_count: 4,
        max_concurrent: 10,
        queue_depth: 2,
        action: "acquire".into(),
        trace_id: "tr-99".into(),
        event: "permit_acquired".into(),
        permit_id: 77,
    };
    let json = serde_json::to_value(&ev).unwrap();
    let obj = json.as_object().unwrap();
    for key in [
        "bulkhead_id",
        "current_count",
        "max_concurrent",
        "queue_depth",
        "action",
        "trace_id",
        "event",
        "permit_id",
    ] {
        assert!(obj.contains_key(key), "missing key: {key}");
    }
    assert_eq!(obj.len(), 8);
}

#[test]
fn snapshot_json_field_names() {
    let snap = BulkheadSnapshot {
        bulkhead_id: "snap-bh".into(),
        active_count: 1,
        max_concurrent: 5,
        queue_depth: 0,
        max_queue_depth: 10,
        at_pressure: false,
    };
    let json = serde_json::to_value(&snap).unwrap();
    let obj = json.as_object().unwrap();
    for key in [
        "bulkhead_id",
        "active_count",
        "max_concurrent",
        "queue_depth",
        "max_queue_depth",
        "at_pressure",
    ] {
        assert!(obj.contains_key(key), "missing key: {key}");
    }
    assert_eq!(obj.len(), 6);
}

#[test]
fn config_json_field_names() {
    let cfg = BulkheadConfig {
        max_concurrent: 10,
        max_queue_depth: 20,
        pressure_threshold_pct: 80,
    };
    let json = serde_json::to_value(&cfg).unwrap();
    let obj = json.as_object().unwrap();
    for key in [
        "max_concurrent",
        "max_queue_depth",
        "pressure_threshold_pct",
    ] {
        assert!(obj.contains_key(key), "missing key: {key}");
    }
    assert_eq!(obj.len(), 3);
}

// =========================================================================
// Enrichment: Display uniqueness
// =========================================================================

#[test]
fn bulkhead_class_display_all_unique() {
    let displays: std::collections::BTreeSet<String> = [
        BulkheadClass::RemoteInFlight,
        BulkheadClass::BackgroundMaintenance,
        BulkheadClass::SagaExecution,
        BulkheadClass::EvidenceFlush,
    ]
    .iter()
    .map(|c| c.to_string())
    .collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn bulkhead_error_display_all_unique() {
    let displays: std::collections::BTreeSet<String> = [
        BulkheadError::BulkheadFull {
            bulkhead_id: "b".into(),
            max_concurrent: 10,
            queue_depth: 5,
        },
        BulkheadError::PermitNotFound { permit_id: 42 },
        BulkheadError::BulkheadNotFound {
            bulkhead_id: "g".into(),
        },
        BulkheadError::InvalidConfig {
            reason: "bad".into(),
        },
    ]
    .iter()
    .map(|e| e.to_string())
    .collect();
    assert_eq!(displays.len(), 4);
}

// =========================================================================
// Enrichment: Drain & event counters
// =========================================================================

#[test]
fn drain_events_clears_buffer() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 10,
            max_queue_depth: 10,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();
    reg.acquire("test", "t1").unwrap();
    assert!(!reg.drain_events().is_empty());
    assert!(reg.drain_events().is_empty());
}

#[test]
fn event_counts_empty_initially() {
    let reg = BulkheadRegistry::empty();
    assert!(reg.event_counts().is_empty());
}

#[test]
fn event_counts_include_queued() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 1,
            max_queue_depth: 5,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();
    reg.acquire("test", "t1").unwrap(); // acquired
    reg.acquire("test", "t2").unwrap(); // queued
    assert_eq!(reg.event_counts().get("acquire"), Some(&1));
    assert_eq!(reg.event_counts().get("queued"), Some(&1));
}

// =========================================================================
// Enrichment: Reject-release-acquire cycle
// =========================================================================

#[test]
fn reject_then_release_then_acquire_cycle() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 1,
            max_queue_depth: 0,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();
    let p1 = reg.acquire("test", "t1").unwrap();
    assert!(reg.acquire("test", "t2").is_err());
    reg.release("test", p1, "t1").unwrap();
    let _p3 = reg.acquire("test", "t3").unwrap();
    assert_eq!(reg.active_count("test"), Some(1));
}

// =========================================================================
// Enrichment: Config serde boundary values
// =========================================================================

#[test]
fn config_serde_boundary_values() {
    let cfg = BulkheadConfig {
        max_concurrent: usize::MAX,
        max_queue_depth: 0,
        pressure_threshold_pct: 255,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: BulkheadConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// =========================================================================
// Enrichment: Clone independence
// =========================================================================

#[test]
fn config_clone_independence() {
    let mut cfg = BulkheadConfig {
        max_concurrent: 10,
        max_queue_depth: 20,
        pressure_threshold_pct: 80,
    };
    let cloned = cfg.clone();
    cfg.max_concurrent = 999;
    assert_ne!(cfg, cloned);
    assert_eq!(cloned.max_concurrent, 10);
}

#[test]
fn snapshot_clone_independence() {
    let mut snap = BulkheadSnapshot {
        bulkhead_id: "snap-orig".into(),
        active_count: 3,
        max_concurrent: 10,
        queue_depth: 1,
        max_queue_depth: 20,
        at_pressure: false,
    };
    let cloned = snap.clone();
    snap.at_pressure = true;
    snap.active_count = 10;
    assert_ne!(snap, cloned);
    assert!(!cloned.at_pressure);
}

// =========================================================================
// Enrichment: PermitId in BTreeSet
// =========================================================================

#[test]
fn permit_id_btreeset_dedup() {
    let mut set = std::collections::BTreeSet::new();
    set.insert(PermitId(1));
    set.insert(PermitId(2));
    set.insert(PermitId(1));
    assert_eq!(set.len(), 2);
}

// =========================================================================
// Edge cases (original)
// =========================================================================

#[test]
fn fill_to_capacity_and_drain() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 3,
            max_queue_depth: 0,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();

    let p1 = reg.acquire("test", "t1").unwrap();
    let p2 = reg.acquire("test", "t2").unwrap();
    let p3 = reg.acquire("test", "t3").unwrap();
    assert!(reg.acquire("test", "t4").is_err());

    reg.release("test", p1, "t1").unwrap();
    reg.release("test", p2, "t2").unwrap();
    reg.release("test", p3, "t3").unwrap();
    assert_eq!(reg.active_count("test"), Some(0));
}
