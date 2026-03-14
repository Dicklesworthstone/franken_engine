//! Integration-level enrichment tests for the `deterministic_replay` module.
//!
//! Covers: Copy/Clone semantics, BTreeSet ordering, serde roundtrips,
//! Display coverage, Debug non-empty, trace capture lifecycle, replay engine
//! modes, failover controller, incident bundle builder, error classification,
//! divergence severity, derive_id determinism, and JSON field-name stability.

use std::collections::BTreeSet;

use frankenengine_engine::deterministic_replay::{
    ArtifactKind, DivergenceSeverity, FailoverController, FailoverError, FailoverReason,
    FailoverRecord, FailoverStrategy, IncidentArtifact, IncidentBundle, IncidentBundleBuilder,
    IncidentSeverity, NondeterminismSource, NondeterminismTrace, ReplayDivergence, ReplayEngine,
    ReplayError, ReplayMode, TraceEvent,
};

// ── Copy semantics ──────────────────────────────────────────────────────

#[test]
fn enrichment_replay_mode_copy() {
    let a = ReplayMode::Strict;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_replay_mode_copy_all() {
    for v in [
        ReplayMode::Strict,
        ReplayMode::BestEffort,
        ReplayMode::Validate,
    ] {
        let copy = v;
        assert_eq!(v, copy);
    }
}

#[test]
fn enrichment_divergence_severity_copy() {
    for v in [
        DivergenceSeverity::Benign,
        DivergenceSeverity::Warning,
        DivergenceSeverity::Critical,
    ] {
        let copy = v;
        assert_eq!(v, copy);
    }
}

#[test]
fn enrichment_failover_strategy_copy() {
    for v in [
        FailoverStrategy::ImmediateBaseline,
        FailoverStrategy::RetryThenBaseline,
        FailoverStrategy::Halt,
    ] {
        let copy = v;
        assert_eq!(v, copy);
    }
}

#[test]
fn enrichment_incident_severity_copy() {
    for v in [
        IncidentSeverity::Info,
        IncidentSeverity::Warning,
        IncidentSeverity::Error,
        IncidentSeverity::Critical,
    ] {
        let copy = v;
        assert_eq!(v, copy);
    }
}

#[test]
fn enrichment_artifact_kind_copy() {
    for v in [
        ArtifactKind::NondeterminismTrace,
        ArtifactKind::DecisionLog,
        ArtifactKind::FailoverLog,
        ArtifactKind::SignalGraphSnapshot,
        ArtifactKind::DomSnapshot,
        ArtifactKind::PerformanceMetrics,
        ArtifactKind::Configuration,
        ArtifactKind::DivergenceReport,
    ] {
        let copy = v;
        assert_eq!(v, copy);
    }
}

// ── Clone independence ──────────────────────────────────────────────────

#[test]
fn enrichment_trace_clone_independence() {
    let mut original = NondeterminismTrace::new("session-1");
    original.capture(NondeterminismSource::TimerRead, vec![1], 100, "clock");
    let mut cloned = original.clone();
    cloned.capture(NondeterminismSource::TimerRead, vec![2], 200, "clock");
    assert_eq!(original.event_count(), 1);
    assert_eq!(cloned.event_count(), 2);
}

#[test]
fn enrichment_replay_engine_clone_independence() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "clock");
    trace.finalise(200);
    let mut original = ReplayEngine::new(trace, ReplayMode::BestEffort);
    let cloned = original.clone();
    original
        .replay_next(NondeterminismSource::TimerRead, &[99])
        .unwrap();
    assert_eq!(original.replayed_events, 1);
    assert_eq!(cloned.replayed_events, 0);
}

#[test]
fn enrichment_failover_controller_clone_independence() {
    let mut original = FailoverController::with_defaults();
    let cloned = original.clone();
    original
        .record_failover(
            FailoverReason::SafeModeTriggered,
            "lane-a",
            "baseline",
            100,
            true,
        )
        .unwrap();
    assert_eq!(original.total_failovers, 1);
    assert_eq!(cloned.total_failovers, 0);
}

#[test]
fn enrichment_incident_bundle_clone_independence() {
    let mut original = IncidentBundle::new("inc-1", IncidentSeverity::Error, "test", "comp", 100);
    original.add_tag("tag1");
    let mut cloned = original.clone();
    cloned.add_tag("tag2");
    assert_eq!(original.tags.len(), 1);
    assert_eq!(cloned.tags.len(), 2);
}

// ── BTreeSet ordering ───────────────────────────────────────────────────

#[test]
fn enrichment_replay_mode_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(ReplayMode::Validate);
    set.insert(ReplayMode::Strict);
    set.insert(ReplayMode::BestEffort);
    assert_eq!(set.len(), 3);
    let ordered: Vec<_> = set.iter().collect();
    for w in ordered.windows(2) {
        assert!(w[0] < w[1]);
    }
}

#[test]
fn enrichment_divergence_severity_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(DivergenceSeverity::Critical);
    set.insert(DivergenceSeverity::Benign);
    set.insert(DivergenceSeverity::Warning);
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_failover_strategy_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(FailoverStrategy::Halt);
    set.insert(FailoverStrategy::ImmediateBaseline);
    set.insert(FailoverStrategy::RetryThenBaseline);
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_incident_severity_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(IncidentSeverity::Critical);
    set.insert(IncidentSeverity::Info);
    set.insert(IncidentSeverity::Warning);
    set.insert(IncidentSeverity::Error);
    assert_eq!(set.len(), 4);
    let ordered: Vec<_> = set.iter().collect();
    for w in ordered.windows(2) {
        assert!(w[0] < w[1]);
    }
}

#[test]
fn enrichment_nondeterminism_source_btreeset() {
    let mut set = BTreeSet::new();
    for src in &NondeterminismSource::ALL {
        set.insert(src.clone());
    }
    assert_eq!(set.len(), 6);
}

// ── Serde roundtrips ────────────────────────────────────────────────────

#[test]
fn enrichment_nondeterminism_source_serde_all() {
    for src in &NondeterminismSource::ALL {
        let json = serde_json::to_string(src).unwrap();
        let back: NondeterminismSource = serde_json::from_str(&json).unwrap();
        assert_eq!(*src, back);
    }
}

#[test]
fn enrichment_trace_event_serde_roundtrip() {
    let ev = TraceEvent {
        sequence: 42,
        source: NondeterminismSource::ExternalApiResponse,
        value: vec![1, 2, 3, 4],
        virtual_ts: 500,
        component: "api_client".to_string(),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: TraceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn enrichment_trace_serde_roundtrip() {
    let mut trace = NondeterminismTrace::new("session-42");
    trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![7],
        100,
        "router",
    );
    trace.capture(
        NondeterminismSource::TimerRead,
        vec![0, 1],
        200,
        "scheduler",
    );
    trace.finalise(300);
    let json = serde_json::to_string(&trace).unwrap();
    let back: NondeterminismTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(trace, back);
}

#[test]
fn enrichment_replay_mode_serde_all() {
    for mode in [
        ReplayMode::Strict,
        ReplayMode::BestEffort,
        ReplayMode::Validate,
    ] {
        let json = serde_json::to_string(&mode).unwrap();
        let back: ReplayMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, back);
    }
}

#[test]
fn enrichment_divergence_severity_serde_all() {
    for sev in [
        DivergenceSeverity::Benign,
        DivergenceSeverity::Warning,
        DivergenceSeverity::Critical,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let back: DivergenceSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, back);
    }
}

#[test]
fn enrichment_replay_divergence_serde_roundtrip() {
    let div = ReplayDivergence {
        sequence: 5,
        source: NondeterminismSource::ResourceCheck,
        expected_value: vec![1],
        actual_value: vec![2],
        virtual_ts: 300,
        severity: DivergenceSeverity::Critical,
    };
    let json = serde_json::to_string(&div).unwrap();
    let back: ReplayDivergence = serde_json::from_str(&json).unwrap();
    assert_eq!(div, back);
}

#[test]
fn enrichment_replay_engine_serde_roundtrip() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "clock");
    trace.finalise(200);
    let engine = ReplayEngine::new(trace, ReplayMode::Strict);
    let json = serde_json::to_string(&engine).unwrap();
    let back: ReplayEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(engine, back);
}

#[test]
fn enrichment_replay_error_serde_all() {
    let errors = vec![
        ReplayError::TraceExhausted {
            cursor: 5,
            total: 10,
        },
        ReplayError::CriticalDivergence {
            sequence: 3,
            source: NondeterminismSource::LaneSelectionRandom,
        },
        ReplayError::SourceMismatch {
            sequence: 2,
            expected: NondeterminismSource::TimerRead,
            actual: NondeterminismSource::ResourceCheck,
        },
        ReplayError::TraceNotFinalised,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ReplayError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn enrichment_failover_strategy_serde_all() {
    for s in [
        FailoverStrategy::ImmediateBaseline,
        FailoverStrategy::RetryThenBaseline,
        FailoverStrategy::Halt,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: FailoverStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn enrichment_failover_reason_serde_all() {
    let reasons = vec![
        FailoverReason::BudgetExhausted {
            metric: "cpu".to_string(),
            value: 100,
            limit: 50,
        },
        FailoverReason::LaneError {
            message: "panic".to_string(),
        },
        FailoverReason::SafeModeTriggered,
        FailoverReason::Timeout {
            elapsed_us: 5000,
            limit_us: 1000,
        },
        FailoverReason::ReplayDivergence {
            divergence_count: 3,
        },
        FailoverReason::Manual,
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: FailoverReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

#[test]
fn enrichment_failover_record_serde_roundtrip() {
    let record = FailoverRecord {
        sequence: 0,
        reason: FailoverReason::SafeModeTriggered,
        strategy: FailoverStrategy::ImmediateBaseline,
        from_component: "lane-a".to_string(),
        to_component: "baseline".to_string(),
        virtual_ts: 500,
        success: true,
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: FailoverRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

#[test]
fn enrichment_failover_controller_serde_roundtrip() {
    let ctrl = FailoverController::with_defaults();
    let json = serde_json::to_string(&ctrl).unwrap();
    let back: FailoverController = serde_json::from_str(&json).unwrap();
    assert_eq!(ctrl, back);
}

#[test]
fn enrichment_failover_error_serde_all() {
    let errors = vec![
        FailoverError::Halted,
        FailoverError::MaxFailoversExceeded {
            count: 10,
            limit: 10,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: FailoverError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn enrichment_incident_severity_serde_all() {
    for sev in [
        IncidentSeverity::Info,
        IncidentSeverity::Warning,
        IncidentSeverity::Error,
        IncidentSeverity::Critical,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let back: IncidentSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, back);
    }
}

#[test]
fn enrichment_artifact_kind_serde_all() {
    for k in [
        ArtifactKind::NondeterminismTrace,
        ArtifactKind::DecisionLog,
        ArtifactKind::FailoverLog,
        ArtifactKind::SignalGraphSnapshot,
        ArtifactKind::DomSnapshot,
        ArtifactKind::PerformanceMetrics,
        ArtifactKind::Configuration,
        ArtifactKind::DivergenceReport,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: ArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, back);
    }
}

#[test]
fn enrichment_incident_artifact_serde_roundtrip() {
    let art = IncidentArtifact::new("trace", ArtifactKind::NondeterminismTrace, vec![1, 2, 3]);
    let json = serde_json::to_string(&art).unwrap();
    let back: IncidentArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(art, back);
}

#[test]
fn enrichment_incident_bundle_serde_roundtrip() {
    let mut bundle = IncidentBundle::new("inc-1", IncidentSeverity::Error, "test", "comp", 100);
    bundle.add_artifact(IncidentArtifact::new(
        "trace",
        ArtifactKind::NondeterminismTrace,
        vec![1],
    ));
    bundle.add_tag("test-tag");
    bundle.finalise();
    let json = serde_json::to_string(&bundle).unwrap();
    let back: IncidentBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

#[test]
fn enrichment_incident_bundle_builder_serde_roundtrip() {
    let builder =
        IncidentBundleBuilder::new("inc-1", IncidentSeverity::Warning, "summary", "comp", 100);
    let json = serde_json::to_string(&builder).unwrap();
    let back: IncidentBundleBuilder = serde_json::from_str(&json).unwrap();
    assert_eq!(builder, back);
}

// ── Display coverage ────────────────────────────────────────────────────

#[test]
fn enrichment_replay_error_display_trace_exhausted() {
    let err = ReplayError::TraceExhausted {
        cursor: 5,
        total: 10,
    };
    assert_eq!(err.to_string(), "trace exhausted at cursor 5 of 10");
}

#[test]
fn enrichment_replay_error_display_critical_divergence() {
    let err = ReplayError::CriticalDivergence {
        sequence: 3,
        source: NondeterminismSource::LaneSelectionRandom,
    };
    let s = err.to_string();
    assert!(s.contains("critical replay divergence"));
    assert!(s.contains("lane_selection_random"));
}

#[test]
fn enrichment_replay_error_display_source_mismatch() {
    let err = ReplayError::SourceMismatch {
        sequence: 2,
        expected: NondeterminismSource::TimerRead,
        actual: NondeterminismSource::ResourceCheck,
    };
    let s = err.to_string();
    assert!(s.contains("source mismatch"));
    assert!(s.contains("timer_read"));
    assert!(s.contains("resource_check"));
}

#[test]
fn enrichment_replay_error_display_not_finalised() {
    assert_eq!(
        ReplayError::TraceNotFinalised.to_string(),
        "trace is not finalised"
    );
}

#[test]
fn enrichment_nondeterminism_source_as_str_all() {
    let expected = [
        (
            "lane_selection_random",
            NondeterminismSource::LaneSelectionRandom,
        ),
        ("timer_read", NondeterminismSource::TimerRead),
        (
            "external_api_response",
            NondeterminismSource::ExternalApiResponse,
        ),
        ("thread_schedule", NondeterminismSource::ThreadSchedule),
        ("resource_check", NondeterminismSource::ResourceCheck),
        (
            "user_interaction_timing",
            NondeterminismSource::UserInteractionTiming,
        ),
    ];
    for (s, src) in &expected {
        assert_eq!(src.as_str(), *s);
    }
}

#[test]
fn enrichment_incident_severity_as_str_all() {
    assert_eq!(IncidentSeverity::Info.as_str(), "info");
    assert_eq!(IncidentSeverity::Warning.as_str(), "warning");
    assert_eq!(IncidentSeverity::Error.as_str(), "error");
    assert_eq!(IncidentSeverity::Critical.as_str(), "critical");
}

#[test]
fn enrichment_artifact_kind_as_str_all() {
    assert_eq!(
        ArtifactKind::NondeterminismTrace.as_str(),
        "nondeterminism_trace"
    );
    assert_eq!(ArtifactKind::DecisionLog.as_str(), "decision_log");
    assert_eq!(ArtifactKind::FailoverLog.as_str(), "failover_log");
    assert_eq!(
        ArtifactKind::SignalGraphSnapshot.as_str(),
        "signal_graph_snapshot"
    );
    assert_eq!(ArtifactKind::DomSnapshot.as_str(), "dom_snapshot");
    assert_eq!(
        ArtifactKind::PerformanceMetrics.as_str(),
        "performance_metrics"
    );
    assert_eq!(ArtifactKind::Configuration.as_str(), "configuration");
    assert_eq!(ArtifactKind::DivergenceReport.as_str(), "divergence_report");
}

// ── Debug nonempty ──────────────────────────────────────────────────────

#[test]
fn enrichment_nondeterminism_source_debug() {
    for src in &NondeterminismSource::ALL {
        assert!(!format!("{src:?}").is_empty());
    }
}

#[test]
fn enrichment_trace_event_debug() {
    let ev = TraceEvent {
        sequence: 0,
        source: NondeterminismSource::TimerRead,
        value: vec![1],
        virtual_ts: 100,
        component: "test".to_string(),
    };
    assert!(!format!("{ev:?}").is_empty());
}

#[test]
fn enrichment_replay_engine_debug() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.finalise(0);
    let engine = ReplayEngine::new(trace, ReplayMode::Strict);
    assert!(!format!("{engine:?}").is_empty());
}

#[test]
fn enrichment_failover_controller_debug() {
    let ctrl = FailoverController::with_defaults();
    assert!(!format!("{ctrl:?}").is_empty());
}

#[test]
fn enrichment_incident_bundle_debug() {
    let bundle = IncidentBundle::new("inc-1", IncidentSeverity::Info, "test", "comp", 0);
    assert!(!format!("{bundle:?}").is_empty());
}

#[test]
fn enrichment_replay_error_debug() {
    let err = ReplayError::TraceNotFinalised;
    assert!(!format!("{err:?}").is_empty());
}

// ── NondeterminismTrace lifecycle ───────────────────────────────────────

#[test]
fn enrichment_trace_new_empty() {
    let trace = NondeterminismTrace::new("session-1");
    assert_eq!(trace.session_id, "session-1");
    assert_eq!(trace.event_count(), 0);
    assert!(!trace.is_finalised());
    assert_eq!(trace.next_sequence, 0);
}

#[test]
fn enrichment_trace_capture_increments_sequence() {
    let mut trace = NondeterminismTrace::new("s1");
    let seq0 = trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![1],
        100,
        "router",
    );
    let seq1 = trace.capture(NondeterminismSource::TimerRead, vec![2], 200, "scheduler");
    let seq2 = trace.capture(NondeterminismSource::ResourceCheck, vec![3], 300, "checker");
    assert_eq!(seq0, 0);
    assert_eq!(seq1, 1);
    assert_eq!(seq2, 2);
    assert_eq!(trace.event_count(), 3);
    assert_eq!(trace.next_sequence, 3);
}

#[test]
fn enrichment_trace_finalise() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "clock");
    trace.finalise(200);
    assert!(trace.is_finalised());
    assert_eq!(trace.capture_ended_vts, Some(200));
}

#[test]
fn enrichment_trace_validate_for_replay_unfinalised() {
    let trace = NondeterminismTrace::new("s1");
    let err = trace.validate_for_replay().unwrap_err();
    assert_eq!(err, ReplayError::TraceNotFinalised);
}

#[test]
fn enrichment_trace_validate_for_replay_finalised() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.finalise(0);
    assert!(trace.validate_for_replay().is_ok());
}

// ── ReplayEngine lifecycle ──────────────────────────────────────────────

#[test]
fn enrichment_replay_strict_exact_match() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![42],
        100,
        "router",
    );
    trace.capture(
        NondeterminismSource::TimerRead,
        vec![0, 1],
        200,
        "scheduler",
    );
    trace.finalise(300);

    let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
    let v1 = engine
        .replay_next(NondeterminismSource::LaneSelectionRandom, &[42])
        .unwrap();
    assert_eq!(v1, vec![42]);
    let v2 = engine
        .replay_next(NondeterminismSource::TimerRead, &[0, 1])
        .unwrap();
    assert_eq!(v2, vec![0, 1]);
    assert!(engine.is_complete());
    assert_eq!(engine.remaining(), 0);
    assert_eq!(engine.divergence_count(), 0);
}

#[test]
fn enrichment_replay_strict_returns_traced_value() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.capture(NondeterminismSource::TimerRead, vec![42], 100, "clock");
    trace.finalise(200);

    let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
    // TimerRead divergence is Benign, so strict mode proceeds but returns traced value
    let result = engine
        .replay_next(NondeterminismSource::TimerRead, &[99])
        .unwrap();
    assert_eq!(result, vec![42]); // traced value, not live
    assert_eq!(engine.divergence_count(), 1);
}

#[test]
fn enrichment_replay_validate_returns_live_value() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.capture(NondeterminismSource::TimerRead, vec![42], 100, "clock");
    trace.finalise(200);

    let mut engine = ReplayEngine::new(trace, ReplayMode::Validate);
    let result = engine
        .replay_next(NondeterminismSource::TimerRead, &[99])
        .unwrap();
    assert_eq!(result, vec![99]); // live value in validate mode
    assert_eq!(engine.divergence_count(), 1);
}

#[test]
fn enrichment_replay_best_effort_returns_traced_value() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![42],
        100,
        "router",
    );
    trace.finalise(200);

    let mut engine = ReplayEngine::new(trace, ReplayMode::BestEffort);
    let result = engine
        .replay_next(NondeterminismSource::LaneSelectionRandom, &[99])
        .unwrap();
    assert_eq!(result, vec![42]); // traced value
    assert_eq!(engine.divergence_count(), 1);
}

#[test]
fn enrichment_replay_trace_exhausted() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.finalise(0);
    let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
    let err = engine
        .replay_next(NondeterminismSource::TimerRead, &[1])
        .unwrap_err();
    assert!(matches!(
        err,
        ReplayError::TraceExhausted {
            cursor: 0,
            total: 0
        }
    ));
}

#[test]
fn enrichment_replay_source_mismatch() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "clock");
    trace.finalise(200);

    let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
    let err = engine
        .replay_next(NondeterminismSource::ResourceCheck, &[1])
        .unwrap_err();
    assert!(matches!(err, ReplayError::SourceMismatch { .. }));
}

#[test]
fn enrichment_replay_strict_critical_divergence_halts() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![42],
        100,
        "router",
    );
    trace.finalise(200);

    let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
    // LaneSelectionRandom divergence is Critical
    let err = engine
        .replay_next(NondeterminismSource::LaneSelectionRandom, &[99])
        .unwrap_err();
    assert!(matches!(err, ReplayError::CriticalDivergence { .. }));
    assert_eq!(engine.critical_divergences(), 1);
}

#[test]
fn enrichment_replay_not_finalised_errors() {
    let trace = NondeterminismTrace::new("s1");
    let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
    let err = engine
        .replay_next(NondeterminismSource::TimerRead, &[1])
        .unwrap_err();
    assert_eq!(err, ReplayError::TraceNotFinalised);
}

#[test]
fn enrichment_replay_remaining() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "clock");
    trace.capture(NondeterminismSource::TimerRead, vec![2], 200, "clock");
    trace.capture(NondeterminismSource::TimerRead, vec![3], 300, "clock");
    trace.finalise(400);

    let mut engine = ReplayEngine::new(trace, ReplayMode::BestEffort);
    assert_eq!(engine.remaining(), 3);
    engine
        .replay_next(NondeterminismSource::TimerRead, &[1])
        .unwrap();
    assert_eq!(engine.remaining(), 2);
}

// ── FailoverController lifecycle ────────────────────────────────────────

#[test]
fn enrichment_failover_controller_defaults() {
    let ctrl = FailoverController::with_defaults();
    assert_eq!(ctrl.default_strategy, FailoverStrategy::RetryThenBaseline);
    assert_eq!(ctrl.max_failovers, 10);
    assert_eq!(ctrl.total_failovers, 0);
    assert_eq!(ctrl.successful_failovers, 0);
    assert!(!ctrl.halted);
}

#[test]
fn enrichment_failover_record_failover() {
    let mut ctrl = FailoverController::with_defaults();
    let record = ctrl
        .record_failover(
            FailoverReason::SafeModeTriggered,
            "lane-a",
            "baseline",
            100,
            true,
        )
        .unwrap();
    assert_eq!(record.sequence, 0);
    assert_eq!(record.from_component, "lane-a");
    assert_eq!(record.to_component, "baseline");
    assert!(record.success);
    assert_eq!(ctrl.total_failovers, 1);
    assert_eq!(ctrl.successful_failovers, 1);
}

#[test]
fn enrichment_failover_strategy_override() {
    let mut ctrl = FailoverController::with_defaults();
    ctrl.set_override("critical-lane", FailoverStrategy::Halt);
    assert_eq!(ctrl.strategy_for("critical-lane"), FailoverStrategy::Halt);
    assert_eq!(
        ctrl.strategy_for("other-lane"),
        FailoverStrategy::RetryThenBaseline
    );
}

#[test]
fn enrichment_failover_max_exceeded() {
    let mut ctrl = FailoverController::new(FailoverStrategy::ImmediateBaseline, 2);
    ctrl.record_failover(FailoverReason::Manual, "a", "b", 100, true)
        .unwrap();
    ctrl.record_failover(FailoverReason::Manual, "a", "b", 200, true)
        .unwrap();
    let err = ctrl
        .record_failover(FailoverReason::Manual, "a", "b", 300, true)
        .unwrap_err();
    assert!(matches!(
        err,
        FailoverError::MaxFailoversExceeded { count: 2, limit: 2 }
    ));
    assert!(ctrl.halted);
}

#[test]
fn enrichment_failover_halted_rejects() {
    let mut ctrl = FailoverController::new(FailoverStrategy::ImmediateBaseline, 1);
    ctrl.record_failover(FailoverReason::Manual, "a", "b", 100, true)
        .unwrap();
    let _ = ctrl.record_failover(FailoverReason::Manual, "a", "b", 200, true);
    // Now halted
    let err = ctrl
        .record_failover(FailoverReason::Manual, "a", "b", 300, true)
        .unwrap_err();
    assert_eq!(err, FailoverError::Halted);
}

#[test]
fn enrichment_failover_success_rate() {
    let mut ctrl = FailoverController::with_defaults();
    ctrl.record_failover(FailoverReason::Manual, "a", "b", 100, true)
        .unwrap();
    ctrl.record_failover(FailoverReason::Manual, "a", "b", 200, false)
        .unwrap();
    // 1 out of 2 = 500_000 millionths
    assert_eq!(ctrl.success_rate_millionths(), 500_000);
}

#[test]
fn enrichment_failover_success_rate_no_failovers() {
    let ctrl = FailoverController::with_defaults();
    assert_eq!(ctrl.success_rate_millionths(), 1_000_000);
}

#[test]
fn enrichment_failover_success_rate_all_successful() {
    let mut ctrl = FailoverController::with_defaults();
    ctrl.record_failover(FailoverReason::Manual, "a", "b", 100, true)
        .unwrap();
    ctrl.record_failover(FailoverReason::Manual, "a", "b", 200, true)
        .unwrap();
    assert_eq!(ctrl.success_rate_millionths(), 1_000_000);
}

// ── IncidentBundle lifecycle ────────────────────────────────────────────

#[test]
fn enrichment_incident_bundle_new() {
    let bundle = IncidentBundle::new(
        "inc-1",
        IncidentSeverity::Error,
        "panic in lane",
        "router",
        100,
    );
    assert_eq!(bundle.incident_id, "inc-1");
    assert_eq!(bundle.severity, IncidentSeverity::Error);
    assert_eq!(bundle.summary, "panic in lane");
    assert_eq!(bundle.trigger_component, "router");
    assert_eq!(bundle.virtual_ts, 100);
    assert!(!bundle.is_finalised());
    assert_eq!(bundle.artifact_count(), 0);
    assert_eq!(bundle.total_data_size(), 0);
}

#[test]
fn enrichment_incident_bundle_add_artifacts() {
    let mut bundle = IncidentBundle::new("inc-1", IncidentSeverity::Warning, "test", "comp", 100);
    bundle.add_artifact(IncidentArtifact::new(
        "trace",
        ArtifactKind::NondeterminismTrace,
        vec![1, 2, 3],
    ));
    bundle.add_artifact(IncidentArtifact::new(
        "log",
        ArtifactKind::DecisionLog,
        vec![4, 5],
    ));
    assert_eq!(bundle.artifact_count(), 2);
    assert_eq!(bundle.total_data_size(), 5);
}

#[test]
fn enrichment_incident_bundle_add_tag_dedup() {
    let mut bundle = IncidentBundle::new("inc-1", IncidentSeverity::Info, "test", "comp", 0);
    bundle.add_tag("tag1");
    bundle.add_tag("tag2");
    bundle.add_tag("tag1"); // duplicate
    assert_eq!(bundle.tags.len(), 2);
}

#[test]
fn enrichment_incident_bundle_finalise() {
    let mut bundle = IncidentBundle::new("inc-1", IncidentSeverity::Error, "test", "comp", 100);
    bundle.add_artifact(IncidentArtifact::new(
        "trace",
        ArtifactKind::NondeterminismTrace,
        vec![1],
    ));
    assert!(!bundle.is_finalised());
    bundle.finalise();
    assert!(bundle.is_finalised());
    assert!(!bundle.bundle_hash.is_empty());
}

#[test]
fn enrichment_incident_bundle_finalise_deterministic() {
    let mut b1 = IncidentBundle::new("inc-1", IncidentSeverity::Error, "test", "comp", 100);
    b1.add_artifact(IncidentArtifact::new(
        "trace",
        ArtifactKind::NondeterminismTrace,
        vec![1, 2],
    ));
    b1.finalise();

    let mut b2 = IncidentBundle::new("inc-1", IncidentSeverity::Error, "test", "comp", 100);
    b2.add_artifact(IncidentArtifact::new(
        "trace",
        ArtifactKind::NondeterminismTrace,
        vec![1, 2],
    ));
    b2.finalise();

    assert_eq!(b1.bundle_hash, b2.bundle_hash);
}

// ── IncidentArtifact ────────────────────────────────────────────────────

#[test]
fn enrichment_artifact_content_hash_deterministic() {
    let a1 = IncidentArtifact::new("trace", ArtifactKind::NondeterminismTrace, vec![1, 2, 3]);
    let a2 = IncidentArtifact::new("trace", ArtifactKind::NondeterminismTrace, vec![1, 2, 3]);
    assert_eq!(a1.content_hash, a2.content_hash);
}

#[test]
fn enrichment_artifact_content_hash_differs_for_different_data() {
    let a1 = IncidentArtifact::new("trace", ArtifactKind::NondeterminismTrace, vec![1, 2, 3]);
    let a2 = IncidentArtifact::new("trace", ArtifactKind::NondeterminismTrace, vec![4, 5, 6]);
    assert_ne!(a1.content_hash, a2.content_hash);
}

// ── IncidentBundleBuilder ───────────────────────────────────────────────

#[test]
fn enrichment_builder_with_all_sources() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "clock");
    trace.finalise(200);

    let mut engine = ReplayEngine::new(trace.clone(), ReplayMode::BestEffort);
    engine
        .replay_next(NondeterminismSource::TimerRead, &[99])
        .unwrap();

    let mut ctrl = FailoverController::with_defaults();
    ctrl.record_failover(FailoverReason::Manual, "a", "b", 300, true)
        .unwrap();

    let builder = IncidentBundleBuilder::new("inc-1", IncidentSeverity::Error, "test", "comp", 400);
    let bundle = builder.build(Some(&trace), Some(&engine), Some(&ctrl));

    assert!(bundle.is_finalised());
    // Should have trace, failover log, and divergence report
    assert!(bundle.artifact_count() >= 3);
    assert!(bundle.tags.contains(&"auto-generated".to_string()));
    assert!(bundle.tags.contains(&"error".to_string()));
}

#[test]
fn enrichment_builder_with_no_sources() {
    let builder = IncidentBundleBuilder::new("inc-1", IncidentSeverity::Info, "test", "comp", 100);
    let bundle = builder.build(None, None, None);
    assert!(bundle.is_finalised());
    assert!(bundle.tags.contains(&"auto-generated".to_string()));
}

#[test]
fn enrichment_builder_exclude_trace() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "clock");
    trace.finalise(200);

    let builder = IncidentBundleBuilder::new("inc-1", IncidentSeverity::Info, "test", "comp", 100)
        .with_trace(false);
    let bundle = builder.build(Some(&trace), None, None);
    // No trace artifact should be included
    assert!(
        bundle
            .artifacts
            .iter()
            .all(|a| a.kind != ArtifactKind::NondeterminismTrace)
    );
}

#[test]
fn enrichment_builder_exclude_failovers() {
    let mut ctrl = FailoverController::with_defaults();
    ctrl.record_failover(FailoverReason::Manual, "a", "b", 100, true)
        .unwrap();

    let builder = IncidentBundleBuilder::new("inc-1", IncidentSeverity::Info, "test", "comp", 100)
        .with_failovers(false);
    let bundle = builder.build(None, None, Some(&ctrl));
    assert!(
        bundle
            .artifacts
            .iter()
            .all(|a| a.kind != ArtifactKind::FailoverLog)
    );
}

// ── derive_id determinism ───────────────────────────────────────────────

#[test]
fn enrichment_trace_derive_id_deterministic() {
    let t1 = NondeterminismTrace::new("s1");
    let t2 = NondeterminismTrace::new("s1");
    assert_eq!(t1.derive_id(), t2.derive_id());
}

#[test]
fn enrichment_trace_derive_id_differs_by_session() {
    let t1 = NondeterminismTrace::new("s1");
    let t2 = NondeterminismTrace::new("s2");
    assert_ne!(t1.derive_id(), t2.derive_id());
}

#[test]
fn enrichment_trace_event_derive_id_deterministic() {
    let ev = TraceEvent {
        sequence: 0,
        source: NondeterminismSource::TimerRead,
        value: vec![1],
        virtual_ts: 100,
        component: "clock".to_string(),
    };
    assert_eq!(ev.derive_id(), ev.derive_id());
}

#[test]
fn enrichment_replay_engine_derive_id_deterministic() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.finalise(0);
    let engine = ReplayEngine::new(trace, ReplayMode::Strict);
    assert_eq!(engine.derive_id(), engine.derive_id());
}

#[test]
fn enrichment_failover_record_derive_id_deterministic() {
    let record = FailoverRecord {
        sequence: 0,
        reason: FailoverReason::SafeModeTriggered,
        strategy: FailoverStrategy::ImmediateBaseline,
        from_component: "lane-a".to_string(),
        to_component: "baseline".to_string(),
        virtual_ts: 500,
        success: true,
    };
    assert_eq!(record.derive_id(), record.derive_id());
}

#[test]
fn enrichment_failover_controller_derive_id_deterministic() {
    let ctrl = FailoverController::with_defaults();
    assert_eq!(ctrl.derive_id(), ctrl.derive_id());
}

#[test]
fn enrichment_incident_artifact_derive_id_deterministic() {
    let art = IncidentArtifact::new("trace", ArtifactKind::NondeterminismTrace, vec![1, 2, 3]);
    assert_eq!(art.derive_id(), art.derive_id());
}

#[test]
fn enrichment_incident_bundle_derive_id_deterministic() {
    let bundle = IncidentBundle::new("inc-1", IncidentSeverity::Error, "test", "comp", 100);
    assert_eq!(bundle.derive_id(), bundle.derive_id());
}

// ── JSON field-name stability ───────────────────────────────────────────

#[test]
fn enrichment_json_fields_trace_event() {
    let ev = TraceEvent {
        sequence: 0,
        source: NondeterminismSource::TimerRead,
        value: vec![1],
        virtual_ts: 100,
        component: "test".to_string(),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("sequence").is_some());
    assert!(v.get("source").is_some());
    assert!(v.get("value").is_some());
    assert!(v.get("virtual_ts").is_some());
    assert!(v.get("component").is_some());
}

#[test]
fn enrichment_json_fields_nondeterminism_trace() {
    let trace = NondeterminismTrace::new("s1");
    let json = serde_json::to_string(&trace).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("session_id").is_some());
    assert!(v.get("events").is_some());
    assert!(v.get("next_sequence").is_some());
    assert!(v.get("capture_started_vts").is_some());
    assert!(v.get("capture_ended_vts").is_some());
}

#[test]
fn enrichment_json_fields_replay_engine() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.finalise(0);
    let engine = ReplayEngine::new(trace, ReplayMode::Strict);
    let json = serde_json::to_string(&engine).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("mode").is_some());
    assert!(v.get("trace").is_some());
    assert!(v.get("cursor").is_some());
    assert!(v.get("divergences").is_some());
    assert!(v.get("replayed_events").is_some());
    assert!(v.get("virtual_ts").is_some());
}

#[test]
fn enrichment_json_fields_failover_record() {
    let record = FailoverRecord {
        sequence: 0,
        reason: FailoverReason::Manual,
        strategy: FailoverStrategy::Halt,
        from_component: "a".to_string(),
        to_component: "b".to_string(),
        virtual_ts: 0,
        success: true,
    };
    let json = serde_json::to_string(&record).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("sequence").is_some());
    assert!(v.get("reason").is_some());
    assert!(v.get("strategy").is_some());
    assert!(v.get("from_component").is_some());
    assert!(v.get("to_component").is_some());
    assert!(v.get("virtual_ts").is_some());
    assert!(v.get("success").is_some());
}

#[test]
fn enrichment_json_fields_failover_controller() {
    let ctrl = FailoverController::with_defaults();
    let json = serde_json::to_string(&ctrl).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("default_strategy").is_some());
    assert!(v.get("strategy_overrides").is_some());
    assert!(v.get("records").is_some());
    assert!(v.get("next_sequence").is_some());
    assert!(v.get("total_failovers").is_some());
    assert!(v.get("successful_failovers").is_some());
    assert!(v.get("max_failovers").is_some());
    assert!(v.get("halted").is_some());
}

#[test]
fn enrichment_json_fields_incident_bundle() {
    let bundle = IncidentBundle::new("inc-1", IncidentSeverity::Info, "test", "comp", 0);
    let json = serde_json::to_string(&bundle).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("incident_id").is_some());
    assert!(v.get("severity").is_some());
    assert!(v.get("summary").is_some());
    assert!(v.get("trigger_component").is_some());
    assert!(v.get("virtual_ts").is_some());
    assert!(v.get("artifacts").is_some());
    assert!(v.get("tags").is_some());
    assert!(v.get("bundle_hash").is_some());
}

#[test]
fn enrichment_json_fields_incident_artifact() {
    let art = IncidentArtifact::new("trace", ArtifactKind::NondeterminismTrace, vec![1]);
    let json = serde_json::to_string(&art).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("name").is_some());
    assert!(v.get("kind").is_some());
    assert!(v.get("data").is_some());
    assert!(v.get("content_hash").is_some());
}

// ── NondeterminismSource::ALL constant ──────────────────────────────────

#[test]
fn enrichment_source_all_has_six_variants() {
    assert_eq!(NondeterminismSource::ALL.len(), 6);
}

#[test]
fn enrichment_source_all_as_str_unique() {
    let strs: Vec<&str> = NondeterminismSource::ALL
        .iter()
        .map(|s| s.as_str())
        .collect();
    let mut deduped = strs.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(strs.len(), deduped.len());
}

// ── FailoverReason variants ─────────────────────────────────────────────

#[test]
fn enrichment_failover_reason_budget_exhausted() {
    let reason = FailoverReason::BudgetExhausted {
        metric: "cpu_us".to_string(),
        value: 100_000,
        limit: 50_000,
    };
    let json = serde_json::to_string(&reason).unwrap();
    let back: FailoverReason = serde_json::from_str(&json).unwrap();
    assert_eq!(reason, back);
}

#[test]
fn enrichment_failover_reason_timeout() {
    let reason = FailoverReason::Timeout {
        elapsed_us: 5_000_000,
        limit_us: 1_000_000,
    };
    let json = serde_json::to_string(&reason).unwrap();
    let back: FailoverReason = serde_json::from_str(&json).unwrap();
    assert_eq!(reason, back);
}

#[test]
fn enrichment_failover_reason_replay_divergence() {
    let reason = FailoverReason::ReplayDivergence {
        divergence_count: 5,
    };
    let json = serde_json::to_string(&reason).unwrap();
    let back: FailoverReason = serde_json::from_str(&json).unwrap();
    assert_eq!(reason, back);
}
