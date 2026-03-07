//! Integration tests for the `deterministic_replay` module.
//!
//! Exercises the public API from outside the crate boundary:
//! NondeterminismSource, TraceEvent, NondeterminismTrace,
//! ReplayMode, ReplayDivergence, DivergenceSeverity,
//! ReplayEngine, ReplayError,
//! FailoverStrategy, FailoverReason, FailoverRecord, FailoverController, FailoverError,
//! IncidentSeverity, ArtifactKind, IncidentArtifact, IncidentBundle, IncidentBundleBuilder.

use frankenengine_engine::deterministic_replay::{
    ArtifactKind, DivergenceSeverity, FailoverController, FailoverError, FailoverReason,
    FailoverRecord, FailoverStrategy, IncidentArtifact, IncidentBundle, IncidentBundleBuilder,
    IncidentSeverity, NondeterminismSource, NondeterminismTrace, ReplayDivergence, ReplayEngine,
    ReplayError, ReplayMode, TraceEvent,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_trace() -> NondeterminismTrace {
    let mut trace = NondeterminismTrace::new("session-1");
    trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![42],
        100,
        "router",
    );
    trace.capture(
        NondeterminismSource::TimerRead,
        vec![0, 0, 0, 1],
        200,
        "scheduler",
    );
    trace.capture(
        NondeterminismSource::ExternalApiResponse,
        vec![1, 2, 3],
        300,
        "api-client",
    );
    trace.finalise(400);
    trace
}

// =========================================================================
// NondeterminismSource
// =========================================================================

#[test]
fn source_all_variants() {
    assert_eq!(NondeterminismSource::ALL.len(), 6);
    for source in &NondeterminismSource::ALL {
        assert!(!source.as_str().is_empty());
    }
}

#[test]
fn source_as_str() {
    assert_eq!(
        NondeterminismSource::LaneSelectionRandom.as_str(),
        "lane_selection_random"
    );
    assert_eq!(NondeterminismSource::TimerRead.as_str(), "timer_read");
}

#[test]
fn source_serde_roundtrip() {
    for source in &NondeterminismSource::ALL {
        let json = serde_json::to_string(source).unwrap();
        let restored: NondeterminismSource = serde_json::from_str(&json).unwrap();
        assert_eq!(*source, restored);
    }
}

// =========================================================================
// NondeterminismTrace
// =========================================================================

#[test]
fn trace_new_empty() {
    let trace = NondeterminismTrace::new("session-1");
    assert_eq!(trace.event_count(), 0);
    assert!(!trace.is_finalised());
    assert_eq!(trace.session_id, "session-1");
}

#[test]
fn trace_capture_events() {
    let mut trace = NondeterminismTrace::new("s1");
    let seq0 = trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![42],
        100,
        "router",
    );
    let seq1 = trace.capture(
        NondeterminismSource::TimerRead,
        vec![0, 1],
        200,
        "scheduler",
    );
    assert_eq!(seq0, 0);
    assert_eq!(seq1, 1);
    assert_eq!(trace.event_count(), 2);
}

#[test]
fn trace_finalise() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "c");
    trace.finalise(200);
    assert!(trace.is_finalised());
    assert_eq!(trace.capture_ended_vts, Some(200));
}

#[test]
fn trace_derive_id_deterministic() {
    let mut t1 = NondeterminismTrace::new("s1");
    t1.capture(NondeterminismSource::TimerRead, vec![1], 100, "c");
    let mut t2 = NondeterminismTrace::new("s1");
    t2.capture(NondeterminismSource::TimerRead, vec![1], 100, "c");
    assert_eq!(t1.derive_id(), t2.derive_id());
}

#[test]
fn trace_serde_roundtrip() {
    let trace = make_trace();
    let json = serde_json::to_string(&trace).unwrap();
    let restored: NondeterminismTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(trace, restored);
}

// =========================================================================
// ReplayMode
// =========================================================================

#[test]
fn replay_mode_serde_roundtrip() {
    for mode in &[
        ReplayMode::Strict,
        ReplayMode::BestEffort,
        ReplayMode::Validate,
    ] {
        let json = serde_json::to_string(mode).unwrap();
        let restored: ReplayMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*mode, restored);
    }
}

// =========================================================================
// DivergenceSeverity
// =========================================================================

#[test]
fn divergence_severity_ordering() {
    assert!(DivergenceSeverity::Benign < DivergenceSeverity::Warning);
    assert!(DivergenceSeverity::Warning < DivergenceSeverity::Critical);
}

// =========================================================================
// ReplayEngine — exact replay
// =========================================================================

#[test]
fn replay_exact_match() {
    let trace = make_trace();
    let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
    assert!(!engine.is_complete());
    assert_eq!(engine.remaining(), 3);

    // Replay with exact same values
    let v = engine
        .replay_next(NondeterminismSource::LaneSelectionRandom, &[42])
        .unwrap();
    assert_eq!(v, vec![42]);

    let v = engine
        .replay_next(NondeterminismSource::TimerRead, &[0, 0, 0, 1])
        .unwrap();
    assert_eq!(v, vec![0, 0, 0, 1]);

    let v = engine
        .replay_next(NondeterminismSource::ExternalApiResponse, &[1, 2, 3])
        .unwrap();
    assert_eq!(v, vec![1, 2, 3]);

    assert!(engine.is_complete());
    assert_eq!(engine.remaining(), 0);
    assert_eq!(engine.divergence_count(), 0);
}

#[test]
fn replay_trace_exhausted() {
    let trace = make_trace();
    let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
    // Replay all 3
    engine
        .replay_next(NondeterminismSource::LaneSelectionRandom, &[42])
        .unwrap();
    engine
        .replay_next(NondeterminismSource::TimerRead, &[0, 0, 0, 1])
        .unwrap();
    engine
        .replay_next(NondeterminismSource::ExternalApiResponse, &[1, 2, 3])
        .unwrap();

    // Try one more
    let result = engine.replay_next(NondeterminismSource::TimerRead, &[0]);
    assert!(matches!(result, Err(ReplayError::TraceExhausted { .. })));
}

#[test]
fn replay_source_mismatch() {
    let trace = make_trace();
    let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
    // First event is LaneSelectionRandom, try TimerRead
    let result = engine.replay_next(NondeterminismSource::TimerRead, &[42]);
    assert!(matches!(result, Err(ReplayError::SourceMismatch { .. })));
}

#[test]
fn replay_strict_critical_divergence() {
    let trace = make_trace();
    let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);

    // LaneSelectionRandom divergence is Critical
    let result = engine.replay_next(NondeterminismSource::LaneSelectionRandom, &[99]);
    assert!(matches!(
        result,
        Err(ReplayError::CriticalDivergence { .. })
    ));
    assert_eq!(engine.divergence_count(), 1);
    assert_eq!(engine.critical_divergences(), 1);
}

#[test]
fn replay_strict_benign_divergence_continues() {
    // TimerRead divergence is Benign
    let mut trace = NondeterminismTrace::new("s1");
    trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "c");
    trace.finalise(200);

    let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
    let v = engine
        .replay_next(NondeterminismSource::TimerRead, &[99])
        .unwrap();
    // In strict mode, returns traced value (not live)
    assert_eq!(v, vec![1]);
    assert_eq!(engine.divergence_count(), 1);
}

#[test]
fn replay_best_effort_records_but_continues() {
    let trace = make_trace();
    let mut engine = ReplayEngine::new(trace, ReplayMode::BestEffort);

    // Critical divergence in best-effort still continues
    let v = engine
        .replay_next(NondeterminismSource::LaneSelectionRandom, &[99])
        .unwrap();
    assert_eq!(v, vec![42]); // Returns traced value
    assert_eq!(engine.divergence_count(), 1);
}

#[test]
fn replay_validate_returns_live_value() {
    let trace = make_trace();
    let mut engine = ReplayEngine::new(trace, ReplayMode::Validate);

    let v = engine
        .replay_next(NondeterminismSource::LaneSelectionRandom, &[99])
        .unwrap();
    // Validate mode returns live value
    assert_eq!(v, vec![99]);
}

#[test]
fn replay_engine_serde_roundtrip() {
    let trace = make_trace();
    let mut engine = ReplayEngine::new(trace, ReplayMode::BestEffort);
    engine
        .replay_next(NondeterminismSource::LaneSelectionRandom, &[42])
        .unwrap();

    let json = serde_json::to_string(&engine).unwrap();
    let restored: ReplayEngine = serde_json::from_str(&json).unwrap();
    assert_eq!(engine, restored);
}

#[test]
fn replay_unfinalised_trace_rejected() {
    let mut trace = NondeterminismTrace::new("unfinished");
    trace.capture(NondeterminismSource::TimerRead, vec![1], 10, "clock");

    let mut engine = ReplayEngine::new(trace, ReplayMode::Strict);
    let result = engine.replay_next(NondeterminismSource::TimerRead, &[1]);
    assert!(matches!(result, Err(ReplayError::TraceNotFinalised)));
    assert!(!engine.is_complete());
}

// =========================================================================
// FailoverStrategy
// =========================================================================

#[test]
fn failover_strategy_serde_roundtrip() {
    for s in &[
        FailoverStrategy::ImmediateBaseline,
        FailoverStrategy::RetryThenBaseline,
        FailoverStrategy::Halt,
    ] {
        let json = serde_json::to_string(s).unwrap();
        let restored: FailoverStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, restored);
    }
}

// =========================================================================
// FailoverController
// =========================================================================

#[test]
fn failover_controller_new() {
    let fc = FailoverController::with_defaults();
    assert_eq!(fc.default_strategy, FailoverStrategy::RetryThenBaseline);
    assert_eq!(fc.max_failovers, 10);
    assert!(!fc.halted);
    assert_eq!(fc.total_failovers, 0);
    assert_eq!(fc.success_rate_millionths(), 1_000_000);
}

#[test]
fn failover_record_failover() {
    let mut fc = FailoverController::with_defaults();
    let record = fc
        .record_failover(
            FailoverReason::SafeModeTriggered,
            "wasm-lane",
            "js-lane",
            100,
            true,
        )
        .unwrap();
    assert_eq!(record.sequence, 0);
    assert_eq!(record.strategy, FailoverStrategy::RetryThenBaseline);
    assert!(record.success);
    assert_eq!(fc.total_failovers, 1);
    assert_eq!(fc.successful_failovers, 1);
    assert_eq!(fc.success_rate_millionths(), 1_000_000);
}

#[test]
fn failover_strategy_override() {
    let mut fc = FailoverController::with_defaults();
    fc.set_override("critical-component", FailoverStrategy::Halt);
    assert_eq!(
        fc.strategy_for("critical-component"),
        FailoverStrategy::Halt
    );
    assert_eq!(
        fc.strategy_for("other-component"),
        FailoverStrategy::RetryThenBaseline
    );
}

#[test]
fn failover_max_exceeded_halts() {
    let mut fc = FailoverController::new(FailoverStrategy::ImmediateBaseline, 2);
    fc.record_failover(FailoverReason::Manual, "a", "b", 100, true)
        .unwrap();
    fc.record_failover(FailoverReason::Manual, "a", "b", 200, true)
        .unwrap();
    // Third should fail
    let result = fc.record_failover(FailoverReason::Manual, "a", "b", 300, true);
    assert!(matches!(
        result,
        Err(FailoverError::MaxFailoversExceeded { .. })
    ));
    assert!(fc.halted);

    // Further attempts fail with Halted
    let result = fc.record_failover(FailoverReason::Manual, "a", "b", 400, true);
    assert!(matches!(result, Err(FailoverError::Halted)));
}

#[test]
fn failover_controller_serde_roundtrip() {
    let mut fc = FailoverController::with_defaults();
    fc.record_failover(
        FailoverReason::LaneError {
            message: "timeout".into(),
        },
        "wasm",
        "js",
        100,
        true,
    )
    .unwrap();

    let json = serde_json::to_string(&fc).unwrap();
    let restored: FailoverController = serde_json::from_str(&json).unwrap();
    assert_eq!(fc, restored);
}

// =========================================================================
// IncidentSeverity
// =========================================================================

#[test]
fn incident_severity_as_str() {
    assert_eq!(IncidentSeverity::Info.as_str(), "info");
    assert_eq!(IncidentSeverity::Warning.as_str(), "warning");
    assert_eq!(IncidentSeverity::Error.as_str(), "error");
    assert_eq!(IncidentSeverity::Critical.as_str(), "critical");
}

#[test]
fn incident_severity_ordering() {
    assert!(IncidentSeverity::Info < IncidentSeverity::Warning);
    assert!(IncidentSeverity::Warning < IncidentSeverity::Error);
    assert!(IncidentSeverity::Error < IncidentSeverity::Critical);
}

// =========================================================================
// ArtifactKind
// =========================================================================

#[test]
fn artifact_kind_as_str() {
    assert_eq!(
        ArtifactKind::NondeterminismTrace.as_str(),
        "nondeterminism_trace"
    );
    assert_eq!(ArtifactKind::DecisionLog.as_str(), "decision_log");
    assert_eq!(ArtifactKind::DivergenceReport.as_str(), "divergence_report");
}

// =========================================================================
// IncidentArtifact
// =========================================================================

#[test]
fn incident_artifact_new() {
    let artifact =
        IncidentArtifact::new("test-artifact", ArtifactKind::Configuration, vec![1, 2, 3]);
    assert_eq!(artifact.name, "test-artifact");
    assert_eq!(artifact.kind, ArtifactKind::Configuration);
    assert_eq!(artifact.data, vec![1, 2, 3]);
    assert!(!artifact.content_hash.is_empty());
}

#[test]
fn incident_artifact_hash_deterministic() {
    let a1 = IncidentArtifact::new("a", ArtifactKind::DecisionLog, vec![1, 2, 3]);
    let a2 = IncidentArtifact::new("a", ArtifactKind::DecisionLog, vec![1, 2, 3]);
    assert_eq!(a1.content_hash, a2.content_hash);
}

#[test]
fn incident_artifact_serde_roundtrip() {
    let artifact = IncidentArtifact::new("trace", ArtifactKind::NondeterminismTrace, vec![42, 43]);
    let json = serde_json::to_string(&artifact).unwrap();
    let restored: IncidentArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(artifact, restored);
}

// =========================================================================
// IncidentBundle
// =========================================================================

#[test]
fn incident_bundle_new() {
    let bundle = IncidentBundle::new(
        "inc-1",
        IncidentSeverity::Error,
        "test incident",
        "router",
        1000,
    );
    assert_eq!(bundle.incident_id, "inc-1");
    assert_eq!(bundle.severity, IncidentSeverity::Error);
    assert!(!bundle.is_finalised());
    assert_eq!(bundle.artifact_count(), 0);
}

#[test]
fn incident_bundle_add_artifacts_and_tags() {
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
    bundle.add_tag("auto");
    bundle.add_tag("replay");
    bundle.add_tag("auto"); // duplicate, should not add

    assert_eq!(bundle.artifact_count(), 2);
    assert_eq!(bundle.tags.len(), 2);
    assert_eq!(bundle.total_data_size(), 5);
}

#[test]
fn incident_bundle_finalise() {
    let mut bundle = IncidentBundle::new("inc-1", IncidentSeverity::Critical, "test", "comp", 100);
    bundle.add_artifact(IncidentArtifact::new(
        "data",
        ArtifactKind::PerformanceMetrics,
        vec![1],
    ));
    assert!(!bundle.is_finalised());
    bundle.finalise();
    assert!(bundle.is_finalised());
    assert!(!bundle.bundle_hash.is_empty());
}

#[test]
fn incident_bundle_serde_roundtrip() {
    let mut bundle = IncidentBundle::new("inc-1", IncidentSeverity::Error, "test", "comp", 100);
    bundle.add_artifact(IncidentArtifact::new(
        "trace",
        ArtifactKind::NondeterminismTrace,
        vec![1],
    ));
    bundle.finalise();

    let json = serde_json::to_string(&bundle).unwrap();
    let restored: IncidentBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, restored);
}

// =========================================================================
// IncidentBundleBuilder
// =========================================================================

#[test]
fn builder_with_trace_and_failover() {
    let trace = make_trace();
    let mut fc = FailoverController::with_defaults();
    fc.record_failover(FailoverReason::SafeModeTriggered, "wasm", "js", 100, true)
        .unwrap();

    let builder = IncidentBundleBuilder::new(
        "inc-builder",
        IncidentSeverity::Error,
        "test builder",
        "wasm-lane",
        500,
    );

    let bundle = builder.build(Some(&trace), None, Some(&fc));
    assert!(bundle.is_finalised());
    // Should include trace artifact and failover log
    assert!(bundle.artifact_count() >= 2);
    assert!(bundle.tags.contains(&"auto-generated".to_string()));
    assert!(bundle.tags.contains(&"error".to_string()));
}

#[test]
fn builder_with_replay_divergences() {
    let trace = make_trace();
    let mut engine = ReplayEngine::new(trace.clone(), ReplayMode::BestEffort);
    // Create a divergence
    engine
        .replay_next(NondeterminismSource::LaneSelectionRandom, &[99])
        .unwrap();

    let builder = IncidentBundleBuilder::new(
        "inc-diverge",
        IncidentSeverity::Warning,
        "divergence detected",
        "replay-engine",
        600,
    );

    let bundle = builder.build(Some(&trace), Some(&engine), None);
    assert!(bundle.is_finalised());
    // Should include trace + divergence report
    assert!(bundle.artifact_count() >= 2);
}

#[test]
fn builder_excludes_optional_artifacts() {
    let trace = make_trace();
    let builder = IncidentBundleBuilder::new(
        "inc-minimal",
        IncidentSeverity::Info,
        "minimal",
        "comp",
        100,
    )
    .with_trace(false)
    .with_failovers(false)
    .with_divergences(false);

    let bundle = builder.build(Some(&trace), None, None);
    // Only tags, no trace/failover/divergence artifacts
    assert_eq!(bundle.artifact_count(), 0);
}

#[test]
fn builder_serde_roundtrip() {
    let builder =
        IncidentBundleBuilder::new("inc-1", IncidentSeverity::Critical, "test", "comp", 100);
    let json = serde_json::to_string(&builder).unwrap();
    let restored: IncidentBundleBuilder = serde_json::from_str(&json).unwrap();
    assert_eq!(builder, restored);
}

// =========================================================================
// Full lifecycle: capture → replay → failover → incident bundle
// =========================================================================

// =========================================================================
// Enrichment: TraceEvent
// =========================================================================

#[test]
fn trace_event_serde_roundtrip() {
    let ev = TraceEvent {
        sequence: 42,
        source: NondeterminismSource::ExternalApiResponse,
        value: vec![0xFF, 0x00, 0xAB],
        virtual_ts: 12345,
        component: "api-proxy".to_string(),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: TraceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn trace_event_derive_id_deterministic() {
    let ev = TraceEvent {
        sequence: 0,
        source: NondeterminismSource::TimerRead,
        value: vec![1, 2, 3],
        virtual_ts: 100,
        component: "clock".to_string(),
    };
    assert_eq!(ev.derive_id(), ev.derive_id());
}

#[test]
fn trace_event_empty_value_serde() {
    let ev = TraceEvent {
        sequence: 0,
        source: NondeterminismSource::LaneSelectionRandom,
        value: vec![],
        virtual_ts: 0,
        component: String::new(),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: TraceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn trace_event_json_field_names() {
    let ev = TraceEvent {
        sequence: 7,
        source: NondeterminismSource::TimerRead,
        value: vec![0xAB],
        virtual_ts: 999,
        component: "clk".to_string(),
    };
    let json = serde_json::to_value(&ev).unwrap();
    let obj = json.as_object().unwrap();
    for key in ["sequence", "source", "value", "virtual_ts", "component"] {
        assert!(obj.contains_key(key), "missing key: {key}");
    }
    assert_eq!(obj.len(), 5);
}

// =========================================================================
// Enrichment: ReplayDivergence
// =========================================================================

#[test]
fn replay_divergence_serde_roundtrip() {
    let d = ReplayDivergence {
        sequence: 7,
        source: NondeterminismSource::ResourceCheck,
        expected_value: vec![1, 2],
        actual_value: vec![3, 4],
        virtual_ts: 500,
        severity: DivergenceSeverity::Critical,
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: ReplayDivergence = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn replay_divergence_json_field_names() {
    let d = ReplayDivergence {
        sequence: 0,
        source: NondeterminismSource::TimerRead,
        expected_value: vec![1],
        actual_value: vec![2],
        virtual_ts: 50,
        severity: DivergenceSeverity::Benign,
    };
    let json = serde_json::to_value(&d).unwrap();
    let obj = json.as_object().unwrap();
    for key in [
        "sequence",
        "source",
        "expected_value",
        "actual_value",
        "virtual_ts",
        "severity",
    ] {
        assert!(obj.contains_key(key), "missing key: {key}");
    }
    assert_eq!(obj.len(), 6);
}

// =========================================================================
// Enrichment: ReplayError Display
// =========================================================================

#[test]
fn replay_error_display_trace_exhausted() {
    let err = ReplayError::TraceExhausted {
        cursor: 5,
        total: 10,
    };
    let msg = err.to_string();
    assert!(msg.contains("5"), "should contain cursor");
    assert!(msg.contains("10"), "should contain total");
}

#[test]
fn replay_error_display_critical_divergence() {
    let err = ReplayError::CriticalDivergence {
        sequence: 3,
        source: NondeterminismSource::ExternalApiResponse,
    };
    let msg = err.to_string();
    assert!(msg.contains("3"));
    assert!(msg.contains("external_api_response"));
}

#[test]
fn replay_error_display_source_mismatch() {
    let err = ReplayError::SourceMismatch {
        sequence: 1,
        expected: NondeterminismSource::TimerRead,
        actual: NondeterminismSource::LaneSelectionRandom,
    };
    let msg = err.to_string();
    assert!(msg.contains("timer_read"));
    assert!(msg.contains("lane_selection_random"));
}

#[test]
fn replay_error_display_trace_not_finalised() {
    let err = ReplayError::TraceNotFinalised;
    let msg = err.to_string();
    assert!(msg.contains("not finalised"));
}

#[test]
fn replay_error_serde_all_variants() {
    let errors = vec![
        ReplayError::TraceExhausted {
            cursor: 3,
            total: 10,
        },
        ReplayError::CriticalDivergence {
            sequence: 1,
            source: NondeterminismSource::ExternalApiResponse,
        },
        ReplayError::SourceMismatch {
            sequence: 0,
            expected: NondeterminismSource::TimerRead,
            actual: NondeterminismSource::LaneSelectionRandom,
        },
        ReplayError::TraceNotFinalised,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ReplayError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// =========================================================================
// Enrichment: FailoverError serde
// =========================================================================

#[test]
fn failover_error_serde_roundtrip() {
    let errors = vec![
        FailoverError::Halted,
        FailoverError::MaxFailoversExceeded {
            count: 11,
            limit: 10,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: FailoverError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// =========================================================================
// Enrichment: FailoverReason serde (all variants)
// =========================================================================

#[test]
fn failover_reason_serde_all_variants() {
    let reasons = vec![
        FailoverReason::BudgetExhausted {
            metric: "signals".into(),
            value: 100,
            limit: 50,
        },
        FailoverReason::LaneError {
            message: "boom".into(),
        },
        FailoverReason::SafeModeTriggered,
        FailoverReason::Timeout {
            elapsed_us: 20_000,
            limit_us: 16_000,
        },
        FailoverReason::ReplayDivergence {
            divergence_count: 3,
        },
        FailoverReason::Manual,
    ];
    for reason in &reasons {
        let json = serde_json::to_string(reason).unwrap();
        let back: FailoverReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

// =========================================================================
// Enrichment: FailoverRecord
// =========================================================================

#[test]
fn failover_record_serde_roundtrip() {
    let rec = FailoverRecord {
        sequence: 3,
        reason: FailoverReason::Timeout {
            elapsed_us: 50_000,
            limit_us: 30_000,
        },
        strategy: FailoverStrategy::RetryThenBaseline,
        from_component: "wasm".into(),
        to_component: "js".into(),
        virtual_ts: 777,
        success: true,
    };
    let json = serde_json::to_string(&rec).unwrap();
    let back: FailoverRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
}

#[test]
fn failover_record_derive_id_deterministic() {
    let rec = FailoverRecord {
        sequence: 0,
        reason: FailoverReason::SafeModeTriggered,
        strategy: FailoverStrategy::ImmediateBaseline,
        from_component: "wasm".to_string(),
        to_component: "js".to_string(),
        virtual_ts: 100,
        success: true,
    };
    assert_eq!(rec.derive_id(), rec.derive_id());
}

#[test]
fn failover_record_json_field_names() {
    let rec = FailoverRecord {
        sequence: 0,
        reason: FailoverReason::Manual,
        strategy: FailoverStrategy::Halt,
        from_component: "a".into(),
        to_component: "b".into(),
        virtual_ts: 10,
        success: false,
    };
    let json = serde_json::to_value(&rec).unwrap();
    let obj = json.as_object().unwrap();
    for key in [
        "sequence",
        "reason",
        "strategy",
        "from_component",
        "to_component",
        "virtual_ts",
        "success",
    ] {
        assert!(obj.contains_key(key), "missing key: {key}");
    }
    assert_eq!(obj.len(), 7);
}

// =========================================================================
// Enrichment: derive_id uniqueness
// =========================================================================

#[test]
fn trace_derive_id_differs_by_session() {
    let t1 = NondeterminismTrace::new("session-a");
    let t2 = NondeterminismTrace::new("session-b");
    assert_ne!(t1.derive_id(), t2.derive_id());
}

#[test]
fn trace_derive_id_differs_by_event_count() {
    let t1 = NondeterminismTrace::new("s");
    let mut t2 = NondeterminismTrace::new("s");
    t2.capture(NondeterminismSource::TimerRead, vec![1], 10, "c");
    assert_ne!(t1.derive_id(), t2.derive_id());
}

#[test]
fn replay_engine_derive_id_differs_by_cursor() {
    let mut trace = NondeterminismTrace::new("s");
    trace.capture(NondeterminismSource::TimerRead, vec![1], 10, "c");
    trace.finalise(20);
    let e0 = ReplayEngine::new(trace.clone(), ReplayMode::Strict);
    let mut e1 = ReplayEngine::new(trace, ReplayMode::Strict);
    e1.replay_next(NondeterminismSource::TimerRead, &[1])
        .unwrap();
    assert_ne!(e0.derive_id(), e1.derive_id());
}

#[test]
fn failover_controller_derive_id_advances() {
    let mut fc = FailoverController::with_defaults();
    let id0 = fc.derive_id();
    fc.record_failover(FailoverReason::Manual, "a", "b", 10, true)
        .unwrap();
    assert_ne!(id0, fc.derive_id());
}

// =========================================================================
// Enrichment: Clone independence
// =========================================================================

#[test]
fn clone_trace_independent() {
    let mut orig = NondeterminismTrace::new("sess-clone");
    orig.capture(NondeterminismSource::TimerRead, vec![1], 10, "c");
    let mut cloned = orig.clone();
    cloned.capture(NondeterminismSource::ResourceCheck, vec![2], 20, "d");
    assert_eq!(orig.event_count(), 1);
    assert_eq!(cloned.event_count(), 2);
}

#[test]
fn clone_replay_engine_independent() {
    let mut trace = NondeterminismTrace::new("s");
    trace.capture(NondeterminismSource::TimerRead, vec![1], 10, "c");
    trace.capture(NondeterminismSource::TimerRead, vec![2], 20, "c");
    trace.finalise(30);
    let mut eng = ReplayEngine::new(trace, ReplayMode::BestEffort);
    let cloned = eng.clone();
    eng.replay_next(NondeterminismSource::TimerRead, &[1])
        .unwrap();
    assert_eq!(eng.cursor, 1);
    assert_eq!(cloned.cursor, 0);
}

#[test]
fn clone_failover_controller_independent() {
    let mut fc = FailoverController::with_defaults();
    fc.record_failover(FailoverReason::Manual, "a", "b", 10, true)
        .unwrap();
    let cloned = fc.clone();
    fc.record_failover(FailoverReason::Manual, "a", "b", 20, false)
        .unwrap();
    assert_eq!(fc.total_failovers, 2);
    assert_eq!(cloned.total_failovers, 1);
}

#[test]
fn clone_incident_bundle_independent() {
    let mut b = IncidentBundle::new("INC-CL", IncidentSeverity::Info, "s", "c", 0);
    b.add_artifact(IncidentArtifact::new(
        "a1",
        ArtifactKind::DecisionLog,
        vec![1],
    ));
    let mut cloned = b.clone();
    cloned.add_artifact(IncidentArtifact::new(
        "a2",
        ArtifactKind::Configuration,
        vec![2],
    ));
    assert_eq!(b.artifact_count(), 1);
    assert_eq!(cloned.artifact_count(), 2);
}

// =========================================================================
// Enrichment: Divergence classification via replay engine
// =========================================================================

#[test]
fn divergence_timer_is_benign_via_engine() {
    let mut trace = NondeterminismTrace::new("s");
    trace.capture(NondeterminismSource::TimerRead, vec![1], 10, "clk");
    trace.finalise(20);
    let mut eng = ReplayEngine::new(trace, ReplayMode::BestEffort);
    eng.replay_next(NondeterminismSource::TimerRead, &[2])
        .unwrap();
    assert_eq!(eng.divergence_count(), 1);
    assert_eq!(eng.critical_divergences(), 0);
}

#[test]
fn divergence_thread_schedule_is_warning_via_engine() {
    let mut trace = NondeterminismTrace::new("s");
    trace.capture(NondeterminismSource::ThreadSchedule, vec![1], 10, "sched");
    trace.finalise(20);
    let mut eng = ReplayEngine::new(trace, ReplayMode::BestEffort);
    eng.replay_next(NondeterminismSource::ThreadSchedule, &[2])
        .unwrap();
    assert_eq!(eng.divergence_count(), 1);
    // ThreadSchedule divergence = Warning, not Critical
    assert_eq!(eng.critical_divergences(), 0);
}

#[test]
fn divergence_resource_check_is_critical_via_engine() {
    let mut trace = NondeterminismTrace::new("s");
    trace.capture(NondeterminismSource::ResourceCheck, vec![1], 10, "budget");
    trace.finalise(20);
    let mut eng = ReplayEngine::new(trace, ReplayMode::BestEffort);
    eng.replay_next(NondeterminismSource::ResourceCheck, &[2])
        .unwrap();
    assert_eq!(eng.critical_divergences(), 1);
}

#[test]
fn divergence_user_interaction_is_benign_via_engine() {
    let mut trace = NondeterminismTrace::new("s");
    trace.capture(
        NondeterminismSource::UserInteractionTiming,
        vec![1],
        10,
        "ui",
    );
    trace.finalise(20);
    let mut eng = ReplayEngine::new(trace, ReplayMode::BestEffort);
    eng.replay_next(NondeterminismSource::UserInteractionTiming, &[2])
        .unwrap();
    assert_eq!(eng.divergence_count(), 1);
    assert_eq!(eng.critical_divergences(), 0);
}

// =========================================================================
// Enrichment: Edge cases
// =========================================================================

#[test]
fn replay_empty_trace_exhausted_immediately() {
    let mut trace = NondeterminismTrace::new("s1");
    trace.finalise(0);
    let mut eng = ReplayEngine::new(trace, ReplayMode::Strict);
    let result = eng.replay_next(NondeterminismSource::TimerRead, &[1]);
    assert!(matches!(result, Err(ReplayError::TraceExhausted { .. })));
}

#[test]
fn trace_max_virtual_ts() {
    let mut trace = NondeterminismTrace::new("max-vts");
    trace.capture(NondeterminismSource::TimerRead, vec![1], u64::MAX, "clk");
    assert_eq!(trace.events[0].virtual_ts, u64::MAX);
    let json = serde_json::to_string(&trace).unwrap();
    let back: NondeterminismTrace = serde_json::from_str(&json).unwrap();
    assert_eq!(trace, back);
}

#[test]
fn failover_success_rate_all_failures() {
    let mut fc = FailoverController::new(FailoverStrategy::ImmediateBaseline, 10);
    for _ in 0..5 {
        fc.record_failover(FailoverReason::Manual, "a", "b", 100, false)
            .unwrap();
    }
    assert_eq!(fc.success_rate_millionths(), 0);
}

#[test]
fn failover_max_zero_rejects_immediately() {
    let mut fc = FailoverController::new(FailoverStrategy::ImmediateBaseline, 0);
    let err = fc
        .record_failover(FailoverReason::Manual, "a", "b", 10, true)
        .unwrap_err();
    assert!(matches!(
        err,
        FailoverError::MaxFailoversExceeded { count: 0, limit: 0 }
    ));
}

#[test]
fn failover_strategy_override_replacement() {
    let mut fc = FailoverController::with_defaults();
    fc.set_override("comp", FailoverStrategy::Halt);
    assert_eq!(fc.strategy_for("comp"), FailoverStrategy::Halt);
    fc.set_override("comp", FailoverStrategy::ImmediateBaseline);
    assert_eq!(fc.strategy_for("comp"), FailoverStrategy::ImmediateBaseline);
}

#[test]
fn incident_bundle_total_data_size_empty() {
    let b = IncidentBundle::new("INC-SZ", IncidentSeverity::Info, "s", "c", 0);
    assert_eq!(b.total_data_size(), 0);
}

#[test]
fn incident_bundle_tag_order_preserved() {
    let mut b = IncidentBundle::new("INC-ORD", IncidentSeverity::Info, "s", "c", 0);
    b.add_tag("alpha");
    b.add_tag("beta");
    b.add_tag("gamma");
    assert_eq!(b.tags, vec!["alpha", "beta", "gamma"]);
}

#[test]
fn incident_bundle_finalise_deterministic() {
    let mut b1 = IncidentBundle::new("INC-D", IncidentSeverity::Error, "s", "c", 0);
    b1.add_artifact(IncidentArtifact::new(
        "a",
        ArtifactKind::DecisionLog,
        vec![1],
    ));
    b1.finalise();

    let mut b2 = IncidentBundle::new("INC-D", IncidentSeverity::Error, "s", "c", 0);
    b2.add_artifact(IncidentArtifact::new(
        "a",
        ArtifactKind::DecisionLog,
        vec![1],
    ));
    b2.finalise();

    assert_eq!(b1.bundle_hash, b2.bundle_hash);
}

#[test]
fn incident_bundle_different_artifacts_different_hash() {
    let mut b1 = IncidentBundle::new("INC-D", IncidentSeverity::Error, "s", "c", 0);
    b1.add_artifact(IncidentArtifact::new(
        "a",
        ArtifactKind::DecisionLog,
        vec![1],
    ));
    b1.finalise();

    let mut b2 = IncidentBundle::new("INC-D", IncidentSeverity::Error, "s", "c", 0);
    b2.add_artifact(IncidentArtifact::new(
        "a",
        ArtifactKind::DecisionLog,
        vec![2],
    ));
    b2.finalise();

    assert_ne!(b1.bundle_hash, b2.bundle_hash);
}

#[test]
fn incident_artifact_different_data_different_hash() {
    let a1 = IncidentArtifact::new("nm", ArtifactKind::DecisionLog, vec![1, 2, 3]);
    let a2 = IncidentArtifact::new("nm", ArtifactKind::DecisionLog, vec![4, 5, 6]);
    assert_ne!(a1.content_hash, a2.content_hash);
}

// =========================================================================
// Enrichment: NondeterminismSource as_str completeness
// =========================================================================

#[test]
fn source_as_str_all_unique() {
    let strs: std::collections::BTreeSet<&str> = NondeterminismSource::ALL
        .iter()
        .map(|s| s.as_str())
        .collect();
    assert_eq!(strs.len(), 6);
}

#[test]
fn source_as_str_remaining_variants() {
    assert_eq!(
        NondeterminismSource::ExternalApiResponse.as_str(),
        "external_api_response"
    );
    assert_eq!(
        NondeterminismSource::ThreadSchedule.as_str(),
        "thread_schedule"
    );
    assert_eq!(
        NondeterminismSource::ResourceCheck.as_str(),
        "resource_check"
    );
    assert_eq!(
        NondeterminismSource::UserInteractionTiming.as_str(),
        "user_interaction_timing"
    );
}

// =========================================================================
// Enrichment: ArtifactKind as_str completeness
// =========================================================================

#[test]
fn artifact_kind_as_str_all_unique() {
    let strs: std::collections::BTreeSet<&str> = [
        ArtifactKind::NondeterminismTrace,
        ArtifactKind::DecisionLog,
        ArtifactKind::FailoverLog,
        ArtifactKind::SignalGraphSnapshot,
        ArtifactKind::DomSnapshot,
        ArtifactKind::PerformanceMetrics,
        ArtifactKind::Configuration,
        ArtifactKind::DivergenceReport,
    ]
    .iter()
    .map(|k| k.as_str())
    .collect();
    assert_eq!(strs.len(), 8);
}

#[test]
fn artifact_kind_as_str_remaining_variants() {
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
}

// =========================================================================
// Enrichment: JSON field name contracts
// =========================================================================

#[test]
fn json_field_names_nondeterminism_trace() {
    let t = NondeterminismTrace::new("sess");
    let json = serde_json::to_value(&t).unwrap();
    let obj = json.as_object().unwrap();
    for key in [
        "session_id",
        "events",
        "next_sequence",
        "capture_started_vts",
        "capture_ended_vts",
    ] {
        assert!(obj.contains_key(key), "missing key: {key}");
    }
    assert_eq!(obj.len(), 5);
}

#[test]
fn json_field_names_replay_engine() {
    let trace = NondeterminismTrace::new("s");
    let eng = ReplayEngine::new(trace, ReplayMode::Strict);
    let json = serde_json::to_value(&eng).unwrap();
    let obj = json.as_object().unwrap();
    for key in [
        "mode",
        "trace",
        "cursor",
        "divergences",
        "replayed_events",
        "virtual_ts",
    ] {
        assert!(obj.contains_key(key), "missing key: {key}");
    }
    assert_eq!(obj.len(), 6);
}

#[test]
fn json_field_names_failover_controller() {
    let fc = FailoverController::with_defaults();
    let json = serde_json::to_value(&fc).unwrap();
    let obj = json.as_object().unwrap();
    for key in [
        "default_strategy",
        "strategy_overrides",
        "records",
        "next_sequence",
        "total_failovers",
        "successful_failovers",
        "max_failovers",
        "halted",
    ] {
        assert!(obj.contains_key(key), "missing key: {key}");
    }
    assert_eq!(obj.len(), 8);
}

#[test]
fn json_field_names_incident_artifact() {
    let art = IncidentArtifact::new("nm", ArtifactKind::DecisionLog, vec![9]);
    let json = serde_json::to_value(&art).unwrap();
    let obj = json.as_object().unwrap();
    for key in ["name", "kind", "data", "content_hash"] {
        assert!(obj.contains_key(key), "missing key: {key}");
    }
    assert_eq!(obj.len(), 4);
}

#[test]
fn json_field_names_incident_bundle() {
    let b = IncidentBundle::new("id", IncidentSeverity::Info, "s", "c", 0);
    let json = serde_json::to_value(&b).unwrap();
    let obj = json.as_object().unwrap();
    for key in [
        "incident_id",
        "severity",
        "summary",
        "trigger_component",
        "virtual_ts",
        "artifacts",
        "tags",
        "bundle_hash",
    ] {
        assert!(obj.contains_key(key), "missing key: {key}");
    }
    assert_eq!(obj.len(), 8);
}

#[test]
fn json_field_names_incident_bundle_builder() {
    let bb = IncidentBundleBuilder::new("id", IncidentSeverity::Info, "s", "c", 0);
    let json = serde_json::to_value(&bb).unwrap();
    let obj = json.as_object().unwrap();
    for key in [
        "incident_id",
        "severity",
        "summary",
        "trigger_component",
        "virtual_ts",
        "include_trace",
        "include_decisions",
        "include_failovers",
        "include_divergences",
    ] {
        assert!(obj.contains_key(key), "missing key: {key}");
    }
    assert_eq!(obj.len(), 9);
}

// =========================================================================
// Enrichment: Builder edge cases
// =========================================================================

#[test]
fn builder_none_sources_produces_no_artifacts() {
    let bb = IncidentBundleBuilder::new("INC-NONE", IncidentSeverity::Info, "s", "c", 0);
    let bundle = bb.build(None, None, None);
    assert_eq!(bundle.artifact_count(), 0);
    assert!(bundle.is_finalised());
}

#[test]
fn builder_no_divergences_skips_divergence_artifact() {
    let mut trace = NondeterminismTrace::new("s");
    trace.capture(NondeterminismSource::TimerRead, vec![1], 10, "c");
    trace.finalise(20);
    let mut eng = ReplayEngine::new(trace.clone(), ReplayMode::Strict);
    eng.replay_next(NondeterminismSource::TimerRead, &[1])
        .unwrap();
    assert_eq!(eng.divergence_count(), 0);

    let bb = IncidentBundleBuilder::new("INC-NODIV", IncidentSeverity::Info, "s", "c", 0);
    let bundle = bb.build(Some(&trace), Some(&eng), None);
    let has_div = bundle
        .artifacts
        .iter()
        .any(|a| a.kind == ArtifactKind::DivergenceReport);
    assert!(!has_div);
}

#[test]
fn builder_with_decisions_toggle() {
    let bb = IncidentBundleBuilder::new("INC-DEC", IncidentSeverity::Info, "s", "c", 0)
        .with_decisions(false);
    let json = serde_json::to_value(&bb).unwrap();
    assert_eq!(json["include_decisions"], false);
}

// =========================================================================
// Enrichment: Failover with diverse reasons
// =========================================================================

#[test]
fn failover_records_all_reason_types() {
    let mut fc = FailoverController::new(FailoverStrategy::RetryThenBaseline, 100);
    let reasons = vec![
        FailoverReason::BudgetExhausted {
            metric: "mem".into(),
            value: 100,
            limit: 50,
        },
        FailoverReason::LaneError {
            message: "oops".into(),
        },
        FailoverReason::SafeModeTriggered,
        FailoverReason::Timeout {
            elapsed_us: 20_000,
            limit_us: 10_000,
        },
        FailoverReason::ReplayDivergence {
            divergence_count: 5,
        },
        FailoverReason::Manual,
    ];
    for (i, reason) in reasons.into_iter().enumerate() {
        let rec = fc
            .record_failover(reason, "src", "dst", (i as u64) * 100, true)
            .unwrap();
        assert_eq!(rec.sequence, i as u64);
    }
    assert_eq!(fc.total_failovers, 6);
    assert_eq!(fc.records.len(), 6);
}

// =========================================================================
// Enrichment: Replay engine multi-event with mixed divergences
// =========================================================================

#[test]
fn replay_multi_event_mixed_divergences() {
    let mut trace = NondeterminismTrace::new("mixed");
    trace.capture(NondeterminismSource::TimerRead, vec![1], 100, "clk");
    trace.capture(NondeterminismSource::ThreadSchedule, vec![2], 200, "sched");
    trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![3],
        300,
        "router",
    );
    trace.finalise(400);

    let mut eng = ReplayEngine::new(trace, ReplayMode::BestEffort);
    // Benign divergence (TimerRead)
    eng.replay_next(NondeterminismSource::TimerRead, &[99])
        .unwrap();
    // Warning divergence (ThreadSchedule)
    eng.replay_next(NondeterminismSource::ThreadSchedule, &[88])
        .unwrap();
    // Critical divergence (LaneSelectionRandom) — in BestEffort, continues
    eng.replay_next(NondeterminismSource::LaneSelectionRandom, &[77])
        .unwrap();

    assert!(eng.is_complete());
    assert_eq!(eng.divergence_count(), 3);
    assert_eq!(eng.critical_divergences(), 1);
    assert_eq!(eng.replayed_events, 3);
}

#[test]
fn replay_remaining_counts_down() {
    let mut trace = NondeterminismTrace::new("s");
    for i in 0..5u64 {
        trace.capture(NondeterminismSource::TimerRead, vec![i as u8], i * 10, "c");
    }
    trace.finalise(50);
    let mut eng = ReplayEngine::new(trace, ReplayMode::BestEffort);
    assert_eq!(eng.remaining(), 5);
    eng.replay_next(NondeterminismSource::TimerRead, &[0])
        .unwrap();
    eng.replay_next(NondeterminismSource::TimerRead, &[1])
        .unwrap();
    assert_eq!(eng.remaining(), 3);
    assert!(!eng.is_complete());
}

// =========================================================================
// Enrichment: IncidentSeverity serde + DivergenceSeverity serde
// =========================================================================

#[test]
fn incident_severity_serde_roundtrip() {
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
fn divergence_severity_serde_roundtrip() {
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

// =========================================================================
// Enrichment: ArtifactKind serde roundtrip all variants
// =========================================================================

#[test]
fn artifact_kind_serde_all_variants() {
    for kind in [
        ArtifactKind::NondeterminismTrace,
        ArtifactKind::DecisionLog,
        ArtifactKind::FailoverLog,
        ArtifactKind::SignalGraphSnapshot,
        ArtifactKind::DomSnapshot,
        ArtifactKind::PerformanceMetrics,
        ArtifactKind::Configuration,
        ArtifactKind::DivergenceReport,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: ArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

// =========================================================================
// Full lifecycle (original)
// =========================================================================

#[test]
fn full_lifecycle() {
    // 1. Capture trace
    let mut trace = NondeterminismTrace::new("session-lifecycle");
    trace.capture(
        NondeterminismSource::LaneSelectionRandom,
        vec![0, 42],
        100,
        "router",
    );
    trace.capture(
        NondeterminismSource::TimerRead,
        vec![0, 0, 10],
        200,
        "scheduler",
    );
    trace.capture(
        NondeterminismSource::ResourceCheck,
        vec![1],
        300,
        "resource-mgr",
    );
    trace.finalise(400);
    assert!(trace.is_finalised());
    assert_eq!(trace.event_count(), 3);

    // 2. Replay (best-effort, with a benign divergence in TimerRead)
    let mut engine = ReplayEngine::new(trace.clone(), ReplayMode::BestEffort);
    engine
        .replay_next(NondeterminismSource::LaneSelectionRandom, &[0, 42])
        .unwrap();
    engine
        .replay_next(NondeterminismSource::TimerRead, &[0, 0, 99])
        .unwrap(); // benign divergence
    engine
        .replay_next(NondeterminismSource::ResourceCheck, &[1])
        .unwrap();
    assert!(engine.is_complete());
    assert_eq!(engine.divergence_count(), 1);
    assert_eq!(engine.critical_divergences(), 0);

    // 3. Failover
    let mut fc = FailoverController::with_defaults();
    fc.record_failover(
        FailoverReason::Timeout {
            elapsed_us: 20_000,
            limit_us: 16_000,
        },
        "wasm-lane",
        "js-lane",
        350,
        true,
    )
    .unwrap();

    // 4. Build incident bundle
    let builder = IncidentBundleBuilder::new(
        "incident-lifecycle",
        IncidentSeverity::Warning,
        "timeout during replay",
        "wasm-lane",
        400,
    );
    let bundle = builder.build(Some(&trace), Some(&engine), Some(&fc));
    assert!(bundle.is_finalised());
    assert!(bundle.artifact_count() >= 3); // trace + failover + divergence

    // 5. Serde roundtrip
    let json = serde_json::to_string(&bundle).unwrap();
    let restored: IncidentBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, restored);
}
