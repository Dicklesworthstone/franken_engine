//! Enrichment integration tests for the `bulkhead` module.
//!
//! Covers: acquire/release lifecycle, queue promotion, backpressure events,
//! reconfiguration, snapshot correctness, error Display, serde roundtrips,
//! event counters, and boundary conditions.

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeSet;

use frankenengine_engine::bulkhead::{
    BulkheadClass, BulkheadConfig, BulkheadError, BulkheadEvent, BulkheadRegistry,
    BulkheadSnapshot, PermitId,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn small_registry() -> BulkheadRegistry {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 2,
            max_queue_depth: 2,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();
    reg
}

// =========================================================================
// A. BulkheadClass — Display, serde, default configs
// =========================================================================

#[test]
fn enrichment_bulkhead_class_display_all_distinct() {
    let variants = [
        BulkheadClass::RemoteInFlight,
        BulkheadClass::BackgroundMaintenance,
        BulkheadClass::SagaExecution,
        BulkheadClass::EvidenceFlush,
    ];
    let strings: BTreeSet<_> = variants.iter().map(|c| c.to_string()).collect();
    assert_eq!(strings.len(), 4);
}

#[test]
fn enrichment_bulkhead_class_serde_roundtrip() {
    for class in [
        BulkheadClass::RemoteInFlight,
        BulkheadClass::BackgroundMaintenance,
        BulkheadClass::SagaExecution,
        BulkheadClass::EvidenceFlush,
    ] {
        let json = serde_json::to_string(&class).unwrap();
        let restored: BulkheadClass = serde_json::from_str(&json).unwrap();
        assert_eq!(class, restored);
    }
}

#[test]
fn enrichment_bulkhead_class_default_configs_have_pressure_80() {
    for class in [
        BulkheadClass::RemoteInFlight,
        BulkheadClass::BackgroundMaintenance,
        BulkheadClass::SagaExecution,
        BulkheadClass::EvidenceFlush,
    ] {
        assert_eq!(class.default_config().pressure_threshold_pct, 80);
    }
}

#[test]
fn enrichment_bulkhead_class_default_queue_depth_is_double_max() {
    for class in [
        BulkheadClass::RemoteInFlight,
        BulkheadClass::BackgroundMaintenance,
        BulkheadClass::SagaExecution,
        BulkheadClass::EvidenceFlush,
    ] {
        let cfg = class.default_config();
        assert_eq!(cfg.max_queue_depth, cfg.max_concurrent * 2);
    }
}

// =========================================================================
// B. PermitId — Display and serde
// =========================================================================

#[test]
fn enrichment_permit_id_display() {
    assert_eq!(PermitId(42).to_string(), "permit:42");
    assert_eq!(PermitId(0).to_string(), "permit:0");
}

#[test]
fn enrichment_permit_id_serde_roundtrip() {
    let id = PermitId(12345);
    let json = serde_json::to_string(&id).unwrap();
    let restored: PermitId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, restored);
}

#[test]
fn enrichment_permit_id_ord() {
    assert!(PermitId(1) < PermitId(2));
    assert_eq!(PermitId(5), PermitId(5));
}

// =========================================================================
// C. BulkheadConfig — serde
// =========================================================================

#[test]
fn enrichment_bulkhead_config_serde_roundtrip() {
    let cfg = BulkheadConfig {
        max_concurrent: 32,
        max_queue_depth: 64,
        pressure_threshold_pct: 75,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: BulkheadConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// =========================================================================
// D. BulkheadError — Display and serde
// =========================================================================

#[test]
fn enrichment_error_display_all_variants_distinct() {
    let variants = [
        BulkheadError::BulkheadFull {
            bulkhead_id: "a".into(),
            max_concurrent: 1,
            queue_depth: 1,
        },
        BulkheadError::PermitNotFound { permit_id: 1 },
        BulkheadError::BulkheadNotFound {
            bulkhead_id: "b".into(),
        },
        BulkheadError::InvalidConfig { reason: "c".into() },
    ];
    let strings: BTreeSet<_> = variants.iter().map(|e| e.to_string()).collect();
    assert_eq!(strings.len(), 4);
}

#[test]
fn enrichment_error_display_contains_context() {
    let err = BulkheadError::BulkheadFull {
        bulkhead_id: "remote".into(),
        max_concurrent: 64,
        queue_depth: 128,
    };
    let s = err.to_string();
    assert!(s.contains("remote"));
    assert!(s.contains("64"));
}

#[test]
fn enrichment_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(BulkheadError::PermitNotFound { permit_id: 99 });
    assert!(!err.to_string().is_empty());
}

#[test]
fn enrichment_error_serde_all_variants_roundtrip() {
    for err in [
        BulkheadError::BulkheadFull {
            bulkhead_id: "x".into(),
            max_concurrent: 10,
            queue_depth: 5,
        },
        BulkheadError::PermitNotFound { permit_id: 42 },
        BulkheadError::BulkheadNotFound {
            bulkhead_id: "y".into(),
        },
        BulkheadError::InvalidConfig { reason: "z".into() },
    ] {
        let json = serde_json::to_string(&err).unwrap();
        let restored: BulkheadError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
    }
}

// =========================================================================
// E. BulkheadRegistry — acquire/release lifecycle
// =========================================================================

#[test]
fn enrichment_acquire_increments_active_count() {
    let mut reg = small_registry();
    assert_eq!(reg.active_count("test"), Some(0));
    let _p = reg.acquire("test", "t1").unwrap();
    assert_eq!(reg.active_count("test"), Some(1));
}

#[test]
fn enrichment_release_decrements_active_count() {
    let mut reg = small_registry();
    let p = reg.acquire("test", "t1").unwrap();
    reg.release("test", p, "t1").unwrap();
    assert_eq!(reg.active_count("test"), Some(0));
}

#[test]
fn enrichment_acquire_nonexistent_bulkhead_errors() {
    let mut reg = BulkheadRegistry::empty();
    assert!(matches!(
        reg.acquire("nonexistent", "t1"),
        Err(BulkheadError::BulkheadNotFound { .. })
    ));
}

#[test]
fn enrichment_release_nonexistent_bulkhead_errors() {
    let mut reg = BulkheadRegistry::empty();
    assert!(matches!(
        reg.release("nonexistent", PermitId(1), "t1"),
        Err(BulkheadError::BulkheadNotFound { .. })
    ));
}

#[test]
fn enrichment_release_invalid_permit_errors() {
    let mut reg = small_registry();
    assert!(matches!(
        reg.release("test", PermitId(999), "t1"),
        Err(BulkheadError::PermitNotFound { .. })
    ));
}

#[test]
fn enrichment_acquire_fills_then_queues() {
    let mut reg = small_registry(); // max_concurrent=2, max_queue_depth=2
    let _p1 = reg.acquire("test", "t1").unwrap();
    let _p2 = reg.acquire("test", "t2").unwrap();
    assert_eq!(reg.active_count("test"), Some(2));
    // Next goes to queue
    let _p3 = reg.acquire("test", "t3").unwrap();
    assert_eq!(reg.queue_depth("test"), Some(1));
}

#[test]
fn enrichment_acquire_rejects_when_both_full() {
    let mut reg = small_registry(); // max_concurrent=2, max_queue_depth=2
    let _p1 = reg.acquire("test", "t1").unwrap();
    let _p2 = reg.acquire("test", "t2").unwrap();
    let _p3 = reg.acquire("test", "t3").unwrap(); // queued
    let _p4 = reg.acquire("test", "t4").unwrap(); // queued
    // Both full
    let result = reg.acquire("test", "t5");
    assert!(matches!(result, Err(BulkheadError::BulkheadFull { .. })));
}

#[test]
fn enrichment_release_promotes_waiter() {
    let mut reg = small_registry(); // max_concurrent=2
    let p1 = reg.acquire("test", "t1").unwrap();
    let _p2 = reg.acquire("test", "t2").unwrap();
    let _p3 = reg.acquire("test", "t3").unwrap(); // queued
    assert_eq!(reg.queue_depth("test"), Some(1));

    // Release p1 → waiter p3 should be promoted
    reg.release("test", p1, "t1").unwrap();
    assert_eq!(reg.active_count("test"), Some(2)); // still 2 (p2 + promoted p3)
    assert_eq!(reg.queue_depth("test"), Some(0));
}

// =========================================================================
// F. BulkheadRegistry — permit IDs are monotonic
// =========================================================================

#[test]
fn enrichment_permit_ids_are_monotonically_increasing() {
    let mut reg = small_registry();
    let p1 = reg.acquire("test", "t1").unwrap();
    let p2 = reg.acquire("test", "t2").unwrap();
    assert!(p2.0 > p1.0);
}

// =========================================================================
// G. BulkheadRegistry — pressure detection
// =========================================================================

#[test]
fn enrichment_pressure_not_at_empty() {
    let reg = small_registry();
    assert_eq!(reg.is_at_pressure("test"), Some(false));
}

#[test]
fn enrichment_pressure_at_threshold() {
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
    // 80% of 10 = 8, so need 8 active permits
    for i in 0..8 {
        reg.acquire("test", &format!("t{i}")).unwrap();
    }
    assert_eq!(reg.is_at_pressure("test"), Some(true));
}

#[test]
fn enrichment_pressure_nonexistent_returns_none() {
    let reg = BulkheadRegistry::empty();
    assert_eq!(reg.is_at_pressure("nonexistent"), None);
}

// =========================================================================
// H. BulkheadRegistry — snapshot
// =========================================================================

#[test]
fn enrichment_snapshot_defaults_shows_all_bulkheads() {
    let reg = BulkheadRegistry::with_defaults();
    let snap = reg.snapshot();
    assert_eq!(snap.len(), 4);
    assert!(snap.contains_key("remote_in_flight"));
    assert!(snap.contains_key("background_maintenance"));
    assert!(snap.contains_key("saga_execution"));
    assert!(snap.contains_key("evidence_flush"));
}

#[test]
fn enrichment_snapshot_reflects_active_count() {
    let mut reg = small_registry();
    reg.acquire("test", "t1").unwrap();
    let snap = reg.snapshot();
    let s = snap.get("test").unwrap();
    assert_eq!(s.active_count, 1);
    assert_eq!(s.max_concurrent, 2);
    assert_eq!(s.queue_depth, 0);
}

#[test]
fn enrichment_snapshot_serde_roundtrip() {
    let snap = BulkheadSnapshot {
        bulkhead_id: "test".into(),
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

// =========================================================================
// I. BulkheadRegistry — event counters
// =========================================================================

#[test]
fn enrichment_event_counters_track_acquires() {
    let mut reg = small_registry();
    reg.acquire("test", "t1").unwrap();
    reg.acquire("test", "t2").unwrap();
    let counts = reg.event_counts();
    assert_eq!(*counts.get("acquire").unwrap_or(&0), 2);
}

#[test]
fn enrichment_event_counters_track_releases() {
    let mut reg = small_registry();
    let p = reg.acquire("test", "t1").unwrap();
    reg.release("test", p, "t1").unwrap();
    let counts = reg.event_counts();
    assert_eq!(*counts.get("release").unwrap_or(&0), 1);
}

#[test]
fn enrichment_event_counters_track_rejects() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "tiny",
        BulkheadConfig {
            max_concurrent: 1,
            max_queue_depth: 0,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();
    let _p = reg.acquire("tiny", "t1").unwrap();
    let _ = reg.acquire("tiny", "t2"); // rejected
    let counts = reg.event_counts();
    assert_eq!(*counts.get("reject").unwrap_or(&0), 1);
}

// =========================================================================
// J. BulkheadRegistry — drain_events
// =========================================================================

#[test]
fn enrichment_drain_events_returns_all_then_empty() {
    let mut reg = small_registry();
    reg.acquire("test", "t1").unwrap();
    let events = reg.drain_events();
    assert!(!events.is_empty());
    let events2 = reg.drain_events();
    assert!(events2.is_empty());
}

#[test]
fn enrichment_drain_events_acquire_event_fields() {
    let mut reg = small_registry();
    reg.acquire("test", "trace-42").unwrap();
    let events = reg.drain_events();
    let e = &events[0];
    assert_eq!(e.bulkhead_id, "test");
    assert_eq!(e.trace_id, "trace-42");
    assert_eq!(e.action, "acquire");
    assert_eq!(e.event, "permit_acquired");
    assert_eq!(e.current_count, 1);
}

// =========================================================================
// K. BulkheadEvent — serde
// =========================================================================

#[test]
fn enrichment_bulkhead_event_serde_roundtrip() {
    let event = BulkheadEvent {
        bulkhead_id: "test".into(),
        current_count: 5,
        max_concurrent: 10,
        queue_depth: 2,
        action: "acquire".into(),
        trace_id: "t1".into(),
        event: "permit_acquired".into(),
        permit_id: 42,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: BulkheadEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

// =========================================================================
// L. BulkheadRegistry — reconfigure
// =========================================================================

#[test]
fn enrichment_reconfigure_changes_config() {
    let mut reg = small_registry();
    reg.reconfigure(
        "test",
        BulkheadConfig {
            max_concurrent: 100,
            max_queue_depth: 200,
            pressure_threshold_pct: 90,
        },
    )
    .unwrap();
    let snap = reg.snapshot();
    assert_eq!(snap.get("test").unwrap().max_concurrent, 100);
}

#[test]
fn enrichment_reconfigure_rejects_zero() {
    let mut reg = small_registry();
    let result = reg.reconfigure(
        "test",
        BulkheadConfig {
            max_concurrent: 0,
            max_queue_depth: 10,
            pressure_threshold_pct: 80,
        },
    );
    assert!(matches!(result, Err(BulkheadError::InvalidConfig { .. })));
}

#[test]
fn enrichment_reconfigure_nonexistent_errors() {
    let mut reg = BulkheadRegistry::empty();
    let result = reg.reconfigure(
        "nonexistent",
        BulkheadConfig {
            max_concurrent: 1,
            max_queue_depth: 1,
            pressure_threshold_pct: 80,
        },
    );
    assert!(matches!(
        result,
        Err(BulkheadError::BulkheadNotFound { .. })
    ));
}

// =========================================================================
// M. BulkheadRegistry — with_defaults specifics
// =========================================================================

#[test]
fn enrichment_defaults_remote_in_flight_config() {
    let reg = BulkheadRegistry::with_defaults();
    let snap = reg.snapshot();
    let s = snap.get("remote_in_flight").unwrap();
    assert_eq!(s.max_concurrent, 64);
    assert_eq!(s.max_queue_depth, 128);
}

#[test]
fn enrichment_defaults_evidence_flush_config() {
    let reg = BulkheadRegistry::with_defaults();
    let snap = reg.snapshot();
    let s = snap.get("evidence_flush").unwrap();
    assert_eq!(s.max_concurrent, 4);
    assert_eq!(s.max_queue_depth, 8);
}

// =========================================================================
// N. Debug formatting
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", BulkheadClass::RemoteInFlight).is_empty());
    assert!(!format!("{:?}", PermitId(1)).is_empty());
    assert!(!format!("{:?}", BulkheadError::PermitNotFound { permit_id: 1 }).is_empty());
    let reg = BulkheadRegistry::with_defaults();
    assert!(!format!("{:?}", reg).is_empty());
}

// =========================================================================
// O. Pressure event emission
// =========================================================================

#[test]
fn enrichment_pressure_event_emitted_at_threshold() {
    let mut reg = BulkheadRegistry::empty();
    reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 5,
            max_queue_depth: 5,
            pressure_threshold_pct: 80,
        },
    )
    .unwrap();
    // 80% of 5 = 4, so at 4th acquire we hit pressure
    for i in 0..4 {
        reg.acquire("test", &format!("t{i}")).unwrap();
    }
    let events = reg.drain_events();
    let pressure_events: Vec<_> = events
        .iter()
        .filter(|e| e.event == "bulkhead_pressure")
        .collect();
    assert!(
        !pressure_events.is_empty(),
        "pressure event should be emitted at threshold"
    );
}

// =========================================================================
// P. BulkheadRegistry — release unknown permit
// =========================================================================

#[test]
fn enrichment_release_unknown_permit_errors() {
    let mut reg = small_registry();
    let result = reg.release("test", PermitId(9999), "t");
    assert!(matches!(result, Err(BulkheadError::PermitNotFound { .. })));
}

// =========================================================================
// Q. BulkheadRegistry — release from nonexistent bulkhead (2)
// =========================================================================

#[test]
fn enrichment_release_nonexistent_bulkhead_errors2() {
    let mut reg = small_registry();
    let result = reg.release("nonexistent", PermitId(1), "t");
    assert!(matches!(
        result,
        Err(BulkheadError::BulkheadNotFound { .. })
    ));
}

// =========================================================================
// R. BulkheadRegistry — acquire from nonexistent bulkhead (2)
// =========================================================================

#[test]
fn enrichment_acquire_nonexistent_bulkhead_errors2() {
    let mut reg = small_registry();
    let result = reg.acquire("nonexistent", "t");
    assert!(matches!(
        result,
        Err(BulkheadError::BulkheadNotFound { .. })
    ));
}

// =========================================================================
// S. BulkheadSnapshot — serde roundtrip (2)
// =========================================================================

#[test]
fn enrichment_snapshot_serde_roundtrip2() {
    let reg = BulkheadRegistry::with_defaults();
    let snap = reg.snapshot();
    let json = serde_json::to_string(&snap).unwrap();
    let back: std::collections::BTreeMap<String, BulkheadSnapshot> =
        serde_json::from_str(&json).unwrap();
    assert_eq!(snap, back);
}

// =========================================================================
// T. BulkheadConfig — serde roundtrip
// =========================================================================

#[test]
fn enrichment_config_serde_roundtrip() {
    let config = BulkheadConfig {
        max_concurrent: 10,
        max_queue_depth: 20,
        pressure_threshold_pct: 75,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: BulkheadConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// =========================================================================
// U. BulkheadConfig — equality and clone
// =========================================================================

#[test]
fn enrichment_config_clone_eq() {
    let config = BulkheadConfig {
        max_concurrent: 5,
        max_queue_depth: 10,
        pressure_threshold_pct: 80,
    };
    let cloned = config.clone();
    assert_eq!(config, cloned);
}

#[test]
fn enrichment_config_ne() {
    let a = BulkheadConfig {
        max_concurrent: 5,
        max_queue_depth: 10,
        pressure_threshold_pct: 80,
    };
    let b = BulkheadConfig {
        max_concurrent: 6,
        max_queue_depth: 10,
        pressure_threshold_pct: 80,
    };
    assert_ne!(a, b);
}

// =========================================================================
// V. BulkheadClass — all variants serde
// =========================================================================

#[test]
fn enrichment_class_serde_all_variants() {
    let classes = [
        BulkheadClass::RemoteInFlight,
        BulkheadClass::BackgroundMaintenance,
        BulkheadClass::SagaExecution,
        BulkheadClass::EvidenceFlush,
    ];
    for class in &classes {
        let json = serde_json::to_string(class).unwrap();
        let back: BulkheadClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*class, back);
    }
}

// =========================================================================
// W. BulkheadClass — default_config is valid
// =========================================================================

#[test]
fn enrichment_class_default_config_valid() {
    let classes = [
        BulkheadClass::RemoteInFlight,
        BulkheadClass::BackgroundMaintenance,
        BulkheadClass::SagaExecution,
        BulkheadClass::EvidenceFlush,
    ];
    for class in &classes {
        let config = class.default_config();
        assert!(config.max_concurrent > 0);
        assert!(config.max_queue_depth > 0);
        assert!(config.pressure_threshold_pct > 0);
        assert!(config.pressure_threshold_pct <= 100);
    }
}

// =========================================================================
// X. BulkheadRegistry — active_count and queue_depth
// =========================================================================

#[test]
fn enrichment_active_count_after_acquire() {
    let mut reg = small_registry();
    assert_eq!(reg.active_count("test"), Some(0));
    reg.acquire("test", "t1").unwrap();
    assert_eq!(reg.active_count("test"), Some(1));
}

#[test]
fn enrichment_active_count_nonexistent() {
    let reg = small_registry();
    assert_eq!(reg.active_count("nonexistent"), None);
}

#[test]
fn enrichment_queue_depth_nonexistent() {
    let reg = small_registry();
    assert_eq!(reg.queue_depth("nonexistent"), None);
}

// =========================================================================
// Y. BulkheadRegistry — is_at_pressure
// =========================================================================

#[test]
fn enrichment_is_at_pressure_false_initially() {
    let reg = small_registry();
    assert_eq!(reg.is_at_pressure("test"), Some(false));
}

#[test]
fn enrichment_is_at_pressure_nonexistent() {
    let reg = small_registry();
    assert_eq!(reg.is_at_pressure("nonexistent"), None);
}

// =========================================================================
// Z. BulkheadRegistry — bulkhead_count
// =========================================================================

#[test]
fn enrichment_bulkhead_count_empty() {
    let reg = BulkheadRegistry::empty();
    assert_eq!(reg.bulkhead_count(), 0);
}

#[test]
fn enrichment_bulkhead_count_with_defaults() {
    let reg = BulkheadRegistry::with_defaults();
    assert!(reg.bulkhead_count() >= 4);
}

// =========================================================================
// AA. BulkheadRegistry — event_counts
// =========================================================================

#[test]
fn enrichment_event_counts_empty_initially() {
    let reg = small_registry();
    assert!(reg.event_counts().is_empty() || reg.event_counts().values().all(|v| *v == 0));
}

// =========================================================================
// AB. BulkheadRegistry — acquire and release lifecycle
// =========================================================================

#[test]
fn enrichment_acquire_release_lifecycle() {
    let mut reg = small_registry();
    let permit = reg.acquire("test", "t1").unwrap();
    assert_eq!(reg.active_count("test"), Some(1));
    reg.release("test", permit, "t1").unwrap();
    assert_eq!(reg.active_count("test"), Some(0));
}

// =========================================================================
// AC. BulkheadRegistry — acquire at capacity queues
// =========================================================================

#[test]
fn enrichment_acquire_at_capacity_queues() {
    let mut reg = small_registry();
    // Fill to max_concurrent = 2
    let _p1 = reg.acquire("test", "t1").unwrap();
    let _p2 = reg.acquire("test", "t2").unwrap();
    // Next acquire goes to queue
    let _p3 = reg.acquire("test", "t3").unwrap();
    assert_eq!(reg.queue_depth("test"), Some(1));
}

// =========================================================================
// AD. BulkheadError — Display strings
// =========================================================================

#[test]
fn enrichment_error_display_all_variants() {
    let errors = [
        BulkheadError::BulkheadNotFound {
            bulkhead_id: "x".into(),
        },
        BulkheadError::PermitNotFound { permit_id: 1 },
        BulkheadError::BulkheadFull {
            bulkhead_id: "x".into(),
            max_concurrent: 5,
            queue_depth: 10,
        },
        BulkheadError::InvalidConfig {
            reason: "bad".into(),
        },
    ];
    let mut displays = BTreeSet::new();
    for e in &errors {
        let s = e.to_string();
        assert!(!s.is_empty());
        displays.insert(s);
    }
    assert_eq!(displays.len(), errors.len());
}

// =========================================================================
// AE. BulkheadRegistry — register duplicate errors
// =========================================================================

#[test]
fn enrichment_register_duplicate_errors() {
    let mut reg = small_registry();
    let result = reg.register(
        "test",
        BulkheadConfig {
            max_concurrent: 1,
            max_queue_depth: 1,
            pressure_threshold_pct: 80,
        },
    );
    assert!(result.is_err());
}

// =========================================================================
// AF. BulkheadSnapshot — clone and Debug
// =========================================================================

#[test]
fn enrichment_snapshot_clone_debug() {
    let reg = BulkheadRegistry::with_defaults();
    let snap = reg.snapshot();
    let cloned = snap.clone();
    assert_eq!(snap, cloned);
    assert!(!format!("{:?}", snap).is_empty());
}

// =========================================================================
// AG. PermitId — Copy and equality
// =========================================================================

#[test]
fn enrichment_permit_id_copy_eq() {
    let p = PermitId(42);
    let p2 = p;
    assert_eq!(p, p2);
}

// =========================================================================
// AH. BulkheadEvent — clone and Debug
// =========================================================================

#[test]
fn enrichment_event_clone_debug() {
    let event = BulkheadEvent {
        bulkhead_id: "test".into(),
        current_count: 1,
        max_concurrent: 2,
        queue_depth: 0,
        action: "acquire".into(),
        trace_id: "t1".into(),
        event: "permit_acquired".into(),
        permit_id: 1,
    };
    let cloned = event.clone();
    assert_eq!(event, cloned);
    assert!(!format!("{:?}", event).is_empty());
}
