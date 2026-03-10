#![forbid(unsafe_code)]

//! Integration tests for `runtime_diagnostics_cli` module.
//!
//! Covers: StructuredLogEvent, EvidenceSeverity, EvidenceRecordKind,
//! parsers, RuntimeExtensionState, GcPressureSample, SchedulerLaneSample,
//! RuntimeStateInput, HostcallTelemetryEnvelope, ContainmentReceiptEnvelope,
//! ReplayArtifactRecord, RuntimeDiagnosticsCliInput, GcPressureDiagnostics,
//! SchedulerLaneDiagnostics, RuntimeDiagnosticsOutput, EvidenceExportFilter,
//! EvidenceExportRecord, EvidenceExportSummary, EvidenceExportOutput,
//! collect_runtime_diagnostics, render_diagnostics_summary,
//! export_evidence_bundle, render_evidence_summary.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::containment_executor::{ContainmentReceipt, ContainmentState};
use frankenengine_engine::evidence_ledger::{
    CandidateAction, ChosenAction, DecisionType, EvidenceEmitter, EvidenceEntryBuilder,
    InMemoryLedger, Witness,
};
use frankenengine_engine::expected_loss_selector::ContainmentAction;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::hostcall_telemetry::{
    FlowLabel, HostcallResult, HostcallType, RecordInput, RecorderConfig, ResourceDelta,
    TelemetryRecorder,
};
use frankenengine_engine::runtime_diagnostics_cli::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_runtime_state() -> RuntimeStateInput {
    RuntimeStateInput {
        snapshot_timestamp_ns: 5_000,
        loaded_extensions: vec![
            RuntimeExtensionState {
                extension_id: "ext-z".to_string(),
                containment_state: ContainmentState::Running,
            },
            RuntimeExtensionState {
                extension_id: "ext-a".to_string(),
                containment_state: ContainmentState::Sandboxed,
            },
        ],
        active_policies: vec![
            "pol-z".to_string(),
            "pol-a".to_string(),
            "pol-z".to_string(), // dup
        ],
        security_epoch: SecurityEpoch::from_raw(10),
        gc_pressure: vec![
            GcPressureSample {
                extension_id: "ext-z".to_string(),
                used_bytes: 600,
                budget_bytes: 1_000,
            },
            GcPressureSample {
                extension_id: "ext-a".to_string(),
                used_bytes: 1_200,
                budget_bytes: 1_000,
            },
        ],
        scheduler_lanes: vec![
            SchedulerLaneSample {
                lane: "ready".to_string(),
                queue_depth: 25,
                max_depth: 100,
                tasks_submitted: 80,
                tasks_scheduled: 70,
                tasks_completed: 60,
                tasks_timed_out: 3,
            },
            SchedulerLaneSample {
                lane: "drain".to_string(),
                queue_depth: 0,
                max_depth: 50,
                tasks_submitted: 10,
                tasks_scheduled: 10,
                tasks_completed: 10,
                tasks_timed_out: 0,
            },
        ],
    }
}

fn make_evidence_entries() -> Vec<frankenengine_engine::evidence_ledger::EvidenceEntry> {
    let mut out = Vec::new();

    // SecurityAction with "terminate" chosen action -> Critical
    let security = EvidenceEntryBuilder::new(
        "trace-int-1",
        "dec-int-1",
        "policy-int-a",
        SecurityEpoch::from_raw(10),
        DecisionType::SecurityAction,
    )
    .timestamp_ns(200)
    .candidate(CandidateAction::new("terminate", 500_000))
    .chosen(ChosenAction {
        action_name: "terminate".to_string(),
        expected_loss_millionths: 500_000,
        rationale: "high-risk".to_string(),
    })
    .witness(Witness {
        witness_id: "w-int-1".to_string(),
        witness_type: "posterior".to_string(),
        value: "0.99".to_string(),
    })
    .meta("extension_id", "ext-a")
    .build()
    .expect("security entry");
    out.push(security);

    // PolicyUpdate -> Warning, kind=PolicyChange
    let policy = EvidenceEntryBuilder::new(
        "trace-int-1",
        "dec-int-2",
        "policy-int-a",
        SecurityEpoch::from_raw(10),
        DecisionType::PolicyUpdate,
    )
    .timestamp_ns(300)
    .candidate(CandidateAction::new("rotate", 1))
    .chosen(ChosenAction {
        action_name: "rotate".to_string(),
        expected_loss_millionths: 1,
        rationale: "key refresh".to_string(),
    })
    .build()
    .expect("policy entry");
    out.push(policy);

    // EpochTransition -> Critical, kind=PolicyChange
    let epoch = EvidenceEntryBuilder::new(
        "trace-int-1",
        "dec-int-3",
        "policy-int-a",
        SecurityEpoch::from_raw(10),
        DecisionType::EpochTransition,
    )
    .timestamp_ns(400)
    .candidate(CandidateAction::new("advance", 0))
    .chosen(ChosenAction {
        action_name: "advance".to_string(),
        expected_loss_millionths: 0,
        rationale: "epoch boundary".to_string(),
    })
    .build()
    .expect("epoch entry");
    out.push(epoch);

    // Revocation -> Critical, kind=DecisionReceipt
    let revoke = EvidenceEntryBuilder::new(
        "trace-int-2",
        "dec-int-4",
        "policy-int-b",
        SecurityEpoch::from_raw(10),
        DecisionType::Revocation,
    )
    .timestamp_ns(500)
    .candidate(CandidateAction::new("revoke-key", 10))
    .chosen(ChosenAction {
        action_name: "revoke-key".to_string(),
        expected_loss_millionths: 10,
        rationale: "compromised".to_string(),
    })
    .meta("extension_id", "ext-z")
    .build()
    .expect("revocation entry");
    out.push(revoke);

    out
}

fn make_hostcall_envelopes() -> Vec<HostcallTelemetryEnvelope> {
    let mut recorder = TelemetryRecorder::new(RecorderConfig::default());
    let id_success = recorder
        .record(
            600,
            RecordInput {
                extension_id: "ext-a".to_string(),
                hostcall_type: HostcallType::FsRead,
                capability_used: RuntimeCapability::FsRead,
                arguments_hash: ContentHash::compute(b"args-ok"),
                result_status: HostcallResult::Success,
                duration_ns: 1_000,
                resource_delta: ResourceDelta::default(),
                flow_label: FlowLabel::new("public", "public"),
                decision_id: Some("dec-int-1".to_string()),
            },
        )
        .expect("record success");
    let rec_success = recorder.get(id_success).cloned().expect("success rec");

    let id_denied = recorder
        .record(
            700,
            RecordInput {
                extension_id: "ext-z".to_string(),
                hostcall_type: HostcallType::NetworkSend,
                capability_used: RuntimeCapability::NetworkEgress,
                arguments_hash: ContentHash::compute(b"args-deny"),
                result_status: HostcallResult::Denied {
                    reason: "policy-block".to_string(),
                },
                duration_ns: 500,
                resource_delta: ResourceDelta::default(),
                flow_label: FlowLabel::new("secret", "secret"),
                decision_id: None,
            },
        )
        .expect("record denied");
    let rec_denied = recorder.get(id_denied).cloned().expect("denied rec");

    let id_error = recorder
        .record(
            800,
            RecordInput {
                extension_id: "ext-a".to_string(),
                hostcall_type: HostcallType::FsWrite,
                capability_used: RuntimeCapability::FsWrite,
                arguments_hash: ContentHash::compute(b"args-err"),
                result_status: HostcallResult::Error { code: 500 },
                duration_ns: 3_000,
                resource_delta: ResourceDelta::default(),
                flow_label: FlowLabel::new("public", "public"),
                decision_id: Some("dec-int-1".to_string()),
            },
        )
        .expect("record error");
    let rec_error = recorder.get(id_error).cloned().expect("error rec");

    vec![
        HostcallTelemetryEnvelope {
            trace_id: "trace-int-1".to_string(),
            policy_id: "policy-int-a".to_string(),
            record: rec_success,
        },
        HostcallTelemetryEnvelope {
            trace_id: "trace-int-1".to_string(),
            policy_id: "policy-int-a".to_string(),
            record: rec_denied,
        },
        HostcallTelemetryEnvelope {
            trace_id: "trace-int-2".to_string(),
            policy_id: "policy-int-b".to_string(),
            record: rec_error,
        },
    ]
}

fn make_containment_receipts() -> Vec<ContainmentReceiptEnvelope> {
    let mut meta = BTreeMap::new();
    meta.insert("decision_id".to_string(), "dec-int-1".to_string());
    let receipt = ContainmentReceipt {
        receipt_id: "cr-int-1".to_string(),
        action: ContainmentAction::Terminate,
        target_extension_id: "ext-a".to_string(),
        previous_state: ContainmentState::Running,
        new_state: ContainmentState::Terminated,
        timestamp_ns: 250,
        duration_ns: 50,
        success: true,
        cooperative: false,
        evidence_refs: vec!["ev-int-1".to_string()],
        epoch: SecurityEpoch::from_raw(10),
        content_hash: ContentHash::compute(b"cr-int-1"),
        metadata: meta,
    };
    vec![ContainmentReceiptEnvelope {
        trace_id: "trace-int-1".to_string(),
        policy_id: "policy-int-a".to_string(),
        receipt,
    }]
}

fn make_replay_artifacts() -> Vec<ReplayArtifactRecord> {
    vec![
        ReplayArtifactRecord {
            trace_id: "trace-int-1".to_string(),
            extension_id: "ext-a".to_string(),
            timestamp_ns: 900,
            artifact_id: "replay-int-1".to_string(),
            replay_pointer: "artifacts/replay/int-1.json".to_string(),
        },
        ReplayArtifactRecord {
            trace_id: "trace-int-2".to_string(),
            extension_id: "ext-z".to_string(),
            timestamp_ns: 950,
            artifact_id: "replay-int-2".to_string(),
            replay_pointer: "artifacts/replay/int-2.json".to_string(),
        },
    ]
}

fn make_cli_input() -> RuntimeDiagnosticsCliInput {
    RuntimeDiagnosticsCliInput {
        trace_id: "trace-cli-root".to_string(),
        decision_id: "decision-cli-root".to_string(),
        policy_id: "policy-cli-root".to_string(),
        runtime_state: make_runtime_state(),
        evidence_entries: make_evidence_entries(),
        hostcall_records: make_hostcall_envelopes(),
        containment_receipts: make_containment_receipts(),
        replay_artifacts: make_replay_artifacts(),
    }
}

// ===================================================================
// Section 1: EvidenceSeverity
// ===================================================================

#[test]
fn severity_display_values() {
    assert_eq!(EvidenceSeverity::Info.to_string(), "info");
    assert_eq!(EvidenceSeverity::Warning.to_string(), "warning");
    assert_eq!(EvidenceSeverity::Critical.to_string(), "critical");
}

#[test]
fn severity_ordering_is_info_lt_warning_lt_critical() {
    assert!(EvidenceSeverity::Info < EvidenceSeverity::Warning);
    assert!(EvidenceSeverity::Warning < EvidenceSeverity::Critical);
    assert!(EvidenceSeverity::Info < EvidenceSeverity::Critical);
}

#[test]
fn severity_serde_roundtrip_all_variants() {
    for sev in [
        EvidenceSeverity::Info,
        EvidenceSeverity::Warning,
        EvidenceSeverity::Critical,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let back: EvidenceSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, back);
    }
}

#[test]
fn severity_serde_uses_snake_case() {
    let json = serde_json::to_string(&EvidenceSeverity::Info).unwrap();
    assert_eq!(json, "\"info\"");
    let json = serde_json::to_string(&EvidenceSeverity::Warning).unwrap();
    assert_eq!(json, "\"warning\"");
    let json = serde_json::to_string(&EvidenceSeverity::Critical).unwrap();
    assert_eq!(json, "\"critical\"");
}

#[test]
fn severity_clone_eq() {
    let s = EvidenceSeverity::Warning;
    let cloned = s;
    assert_eq!(s, cloned);
}

// ===================================================================
// Section 2: EvidenceRecordKind
// ===================================================================

#[test]
fn record_kind_display_all_variants() {
    assert_eq!(
        EvidenceRecordKind::DecisionReceipt.to_string(),
        "decision_receipt"
    );
    assert_eq!(
        EvidenceRecordKind::HostcallTelemetry.to_string(),
        "hostcall_telemetry"
    );
    assert_eq!(
        EvidenceRecordKind::ContainmentAction.to_string(),
        "containment_action"
    );
    assert_eq!(
        EvidenceRecordKind::PolicyChange.to_string(),
        "policy_change"
    );
    assert_eq!(
        EvidenceRecordKind::ReplayArtifact.to_string(),
        "replay_artifact"
    );
}

#[test]
fn record_kind_ordering() {
    assert!(EvidenceRecordKind::DecisionReceipt < EvidenceRecordKind::HostcallTelemetry);
    assert!(EvidenceRecordKind::HostcallTelemetry < EvidenceRecordKind::ContainmentAction);
    assert!(EvidenceRecordKind::ContainmentAction < EvidenceRecordKind::PolicyChange);
    assert!(EvidenceRecordKind::PolicyChange < EvidenceRecordKind::ReplayArtifact);
}

#[test]
fn record_kind_serde_roundtrip() {
    for kind in [
        EvidenceRecordKind::DecisionReceipt,
        EvidenceRecordKind::HostcallTelemetry,
        EvidenceRecordKind::ContainmentAction,
        EvidenceRecordKind::PolicyChange,
        EvidenceRecordKind::ReplayArtifact,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: EvidenceRecordKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

#[test]
fn record_kind_display_values_are_unique() {
    let displays: BTreeSet<String> = [
        EvidenceRecordKind::DecisionReceipt,
        EvidenceRecordKind::HostcallTelemetry,
        EvidenceRecordKind::ContainmentAction,
        EvidenceRecordKind::PolicyChange,
        EvidenceRecordKind::ReplayArtifact,
    ]
    .iter()
    .map(|k| k.to_string())
    .collect();
    assert_eq!(displays.len(), 5);
}

// ===================================================================
// Section 3: parse_evidence_severity
// ===================================================================

#[test]
fn parse_severity_known_values() {
    assert_eq!(
        parse_evidence_severity("info"),
        Some(EvidenceSeverity::Info)
    );
    assert_eq!(
        parse_evidence_severity("warning"),
        Some(EvidenceSeverity::Warning)
    );
    assert_eq!(
        parse_evidence_severity("critical"),
        Some(EvidenceSeverity::Critical)
    );
}

#[test]
fn parse_severity_case_insensitive() {
    assert_eq!(
        parse_evidence_severity("INFO"),
        Some(EvidenceSeverity::Info)
    );
    assert_eq!(
        parse_evidence_severity("WaRnInG"),
        Some(EvidenceSeverity::Warning)
    );
    assert_eq!(
        parse_evidence_severity("CRITICAL"),
        Some(EvidenceSeverity::Critical)
    );
}

#[test]
fn parse_severity_trims_whitespace() {
    assert_eq!(
        parse_evidence_severity("  info  "),
        Some(EvidenceSeverity::Info)
    );
    assert_eq!(
        parse_evidence_severity("\twarning\n"),
        Some(EvidenceSeverity::Warning)
    );
}

#[test]
fn parse_severity_unknown_returns_none() {
    assert!(parse_evidence_severity("unknown").is_none());
    assert!(parse_evidence_severity("").is_none());
    assert!(parse_evidence_severity("  ").is_none());
    assert!(parse_evidence_severity("infoo").is_none());
}

// ===================================================================
// Section 4: parse_decision_type
// ===================================================================

#[test]
fn parse_decision_type_all_known_values() {
    let cases = [
        ("security_action", DecisionType::SecurityAction),
        ("policy_update", DecisionType::PolicyUpdate),
        ("epoch_transition", DecisionType::EpochTransition),
        ("revocation", DecisionType::Revocation),
        ("extension_lifecycle", DecisionType::ExtensionLifecycle),
        ("capability_decision", DecisionType::CapabilityDecision),
        ("contract_evaluation", DecisionType::ContractEvaluation),
        ("remote_authorization", DecisionType::RemoteAuthorization),
    ];
    for (input, expected) in &cases {
        assert_eq!(
            parse_decision_type(input),
            Some(*expected),
            "failed for input: {}",
            input
        );
    }
}

#[test]
fn parse_decision_type_case_insensitive() {
    assert_eq!(
        parse_decision_type("SECURITY_ACTION"),
        Some(DecisionType::SecurityAction)
    );
    assert_eq!(
        parse_decision_type("  Policy_Update  "),
        Some(DecisionType::PolicyUpdate)
    );
}

#[test]
fn parse_decision_type_unknown_returns_none() {
    assert!(parse_decision_type("").is_none());
    assert!(parse_decision_type("bogus").is_none());
    assert!(parse_decision_type("security action").is_none()); // space not underscore
}

// ===================================================================
// Section 5: Struct serde roundtrips
// ===================================================================

#[test]
fn structured_log_event_serde_roundtrip() {
    let event = StructuredLogEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "runtime_diagnostics_cli".to_string(),
        event: "snap".to_string(),
        outcome: "pass".to_string(),
        error_code: Some("E001".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn structured_log_event_error_code_none_roundtrip() {
    let event = StructuredLogEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "o".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert!(json.contains("\"error_code\":null"));
}

#[test]
fn runtime_extension_state_serde_roundtrip() {
    let state = RuntimeExtensionState {
        extension_id: "ext-test".to_string(),
        containment_state: ContainmentState::Quarantined,
    };
    let json = serde_json::to_string(&state).unwrap();
    let back: RuntimeExtensionState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, back);
}

#[test]
fn gc_pressure_sample_serde_roundtrip() {
    let sample = GcPressureSample {
        extension_id: "ext-gc".to_string(),
        used_bytes: 4096,
        budget_bytes: 8192,
    };
    let json = serde_json::to_string(&sample).unwrap();
    let back: GcPressureSample = serde_json::from_str(&json).unwrap();
    assert_eq!(sample, back);
}

#[test]
fn scheduler_lane_sample_serde_roundtrip() {
    let sample = SchedulerLaneSample {
        lane: "fast".to_string(),
        queue_depth: 5,
        max_depth: 50,
        tasks_submitted: 100,
        tasks_scheduled: 90,
        tasks_completed: 80,
        tasks_timed_out: 2,
    };
    let json = serde_json::to_string(&sample).unwrap();
    let back: SchedulerLaneSample = serde_json::from_str(&json).unwrap();
    assert_eq!(sample, back);
}

#[test]
fn replay_artifact_record_serde_roundtrip() {
    let record = ReplayArtifactRecord {
        trace_id: "t-1".to_string(),
        extension_id: "ext-1".to_string(),
        timestamp_ns: 42,
        artifact_id: "a-1".to_string(),
        replay_pointer: "path/to/artifact".to_string(),
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: ReplayArtifactRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, back);
}

#[test]
fn evidence_export_filter_serde_roundtrip_full() {
    let filter = EvidenceExportFilter {
        extension_id: Some("ext-a".to_string()),
        trace_id: Some("t-1".to_string()),
        start_timestamp_ns: Some(100),
        end_timestamp_ns: Some(999),
        severity: Some(EvidenceSeverity::Warning),
        decision_type: Some(DecisionType::Revocation),
    };
    let json = serde_json::to_string(&filter).unwrap();
    let back: EvidenceExportFilter = serde_json::from_str(&json).unwrap();
    assert_eq!(filter, back);
}

#[test]
fn evidence_export_filter_default_serde_roundtrip() {
    let filter = EvidenceExportFilter::default();
    let json = serde_json::to_string(&filter).unwrap();
    let back: EvidenceExportFilter = serde_json::from_str(&json).unwrap();
    assert_eq!(filter, back);
}

#[test]
fn evidence_export_summary_serde_roundtrip() {
    let mut counts_by_kind = BTreeMap::new();
    counts_by_kind.insert("decision_receipt".to_string(), 3);
    counts_by_kind.insert("replay_artifact".to_string(), 1);
    let mut counts_by_severity = BTreeMap::new();
    counts_by_severity.insert("info".to_string(), 2);
    counts_by_severity.insert("critical".to_string(), 2);
    let summary = EvidenceExportSummary {
        total_records: 4,
        counts_by_kind,
        counts_by_severity,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: EvidenceExportSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn runtime_state_input_serde_roundtrip() {
    let state = make_runtime_state();
    let json = serde_json::to_string(&state).unwrap();
    let back: RuntimeStateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(state, back);
}

// ===================================================================
// Section 6: collect_runtime_diagnostics
// ===================================================================

#[test]
fn diagnostics_snapshot_is_deterministic() {
    let state = make_runtime_state();
    let a = collect_runtime_diagnostics(&state, "t", "d", "p");
    let b = collect_runtime_diagnostics(&state, "t", "d", "p");
    assert_eq!(a, b);
}

#[test]
fn diagnostics_sorts_extensions_by_id() {
    let state = make_runtime_state();
    let out = collect_runtime_diagnostics(&state, "t", "d", "p");
    assert_eq!(out.loaded_extensions[0].extension_id, "ext-a");
    assert_eq!(out.loaded_extensions[1].extension_id, "ext-z");
}

#[test]
fn diagnostics_deduplicates_and_sorts_policies() {
    let state = make_runtime_state();
    let out = collect_runtime_diagnostics(&state, "t", "d", "p");
    assert_eq!(out.active_policies, vec!["pol-a", "pol-z"]);
}

#[test]
fn diagnostics_filters_empty_and_whitespace_policies() {
    let state = RuntimeStateInput {
        snapshot_timestamp_ns: 0,
        loaded_extensions: vec![],
        active_policies: vec![
            "".to_string(),
            "  ".to_string(),
            "\t".to_string(),
            "real".to_string(),
        ],
        security_epoch: SecurityEpoch::from_raw(1),
        gc_pressure: vec![],
        scheduler_lanes: vec![],
    };
    let out = collect_runtime_diagnostics(&state, "t", "d", "p");
    assert_eq!(out.active_policies, vec!["real"]);
}

#[test]
fn diagnostics_gc_pressure_computation() {
    let state = make_runtime_state();
    let out = collect_runtime_diagnostics(&state, "t", "d", "p");
    // ext-a: used=1200, budget=1000 -> 1_000_000 (capped), over_budget=true
    let ext_a = out
        .gc_pressure
        .iter()
        .find(|g| g.extension_id == "ext-a")
        .unwrap();
    assert_eq!(ext_a.pressure_millionths, 1_000_000);
    assert!(ext_a.over_budget);

    // ext-z: used=600, budget=1000 -> 600_000, over_budget=false
    let ext_z = out
        .gc_pressure
        .iter()
        .find(|g| g.extension_id == "ext-z")
        .unwrap();
    assert_eq!(ext_z.pressure_millionths, 600_000);
    assert!(!ext_z.over_budget);
}

#[test]
fn diagnostics_gc_pressure_sorted_by_extension_id() {
    let state = make_runtime_state();
    let out = collect_runtime_diagnostics(&state, "t", "d", "p");
    for window in out.gc_pressure.windows(2) {
        assert!(window[0].extension_id <= window[1].extension_id);
    }
}

#[test]
fn diagnostics_scheduler_lanes_sorted_by_name() {
    let state = make_runtime_state();
    let out = collect_runtime_diagnostics(&state, "t", "d", "p");
    assert_eq!(out.scheduler_lanes[0].lane, "drain");
    assert_eq!(out.scheduler_lanes[1].lane, "ready");
}

#[test]
fn diagnostics_scheduler_utilization_computation() {
    let state = make_runtime_state();
    let out = collect_runtime_diagnostics(&state, "t", "d", "p");
    // "ready": queue_depth=25, max_depth=100 -> 250_000
    let ready = out
        .scheduler_lanes
        .iter()
        .find(|l| l.lane == "ready")
        .unwrap();
    assert_eq!(ready.utilization_millionths, 250_000);

    // "drain": queue_depth=0, max_depth=50 -> 0
    let drain = out
        .scheduler_lanes
        .iter()
        .find(|l| l.lane == "drain")
        .unwrap();
    assert_eq!(drain.utilization_millionths, 0);
}

#[test]
fn diagnostics_logs_contain_snapshot_event() {
    let state = make_runtime_state();
    let out = collect_runtime_diagnostics(&state, "trace-x", "dec-x", "pol-x");
    assert_eq!(out.logs.len(), 1);
    let log = &out.logs[0];
    assert_eq!(log.trace_id, "trace-x");
    assert_eq!(log.decision_id, "dec-x");
    assert_eq!(log.policy_id, "pol-x");
    assert_eq!(log.component, "runtime_diagnostics_cli");
    assert_eq!(log.event, "runtime_diagnostics_snapshot");
    assert_eq!(log.outcome, "pass");
    assert!(log.error_code.is_none());
}

#[test]
fn diagnostics_empty_input() {
    let state = RuntimeStateInput {
        snapshot_timestamp_ns: 0,
        loaded_extensions: vec![],
        active_policies: vec![],
        security_epoch: SecurityEpoch::from_raw(1),
        gc_pressure: vec![],
        scheduler_lanes: vec![],
    };
    let out = collect_runtime_diagnostics(&state, "t", "d", "p");
    assert!(out.loaded_extensions.is_empty());
    assert!(out.active_policies.is_empty());
    assert!(out.gc_pressure.is_empty());
    assert!(out.scheduler_lanes.is_empty());
    assert_eq!(out.logs.len(), 1);
}

#[test]
fn diagnostics_gc_zero_budget_zero_used() {
    let state = RuntimeStateInput {
        snapshot_timestamp_ns: 0,
        loaded_extensions: vec![],
        active_policies: vec![],
        security_epoch: SecurityEpoch::from_raw(1),
        gc_pressure: vec![GcPressureSample {
            extension_id: "ext-zero".to_string(),
            used_bytes: 0,
            budget_bytes: 0,
        }],
        scheduler_lanes: vec![],
    };
    let out = collect_runtime_diagnostics(&state, "t", "d", "p");
    assert_eq!(out.gc_pressure[0].pressure_millionths, 0);
    assert!(!out.gc_pressure[0].over_budget);
}

#[test]
fn diagnostics_gc_nonzero_used_zero_budget() {
    let state = RuntimeStateInput {
        snapshot_timestamp_ns: 0,
        loaded_extensions: vec![],
        active_policies: vec![],
        security_epoch: SecurityEpoch::from_raw(1),
        gc_pressure: vec![GcPressureSample {
            extension_id: "ext-inf".to_string(),
            used_bytes: 100,
            budget_bytes: 0,
        }],
        scheduler_lanes: vec![],
    };
    let out = collect_runtime_diagnostics(&state, "t", "d", "p");
    assert_eq!(out.gc_pressure[0].pressure_millionths, 1_000_000);
    // over_budget requires budget > 0
    assert!(!out.gc_pressure[0].over_budget);
}

#[test]
fn diagnostics_gc_exact_budget() {
    let state = RuntimeStateInput {
        snapshot_timestamp_ns: 0,
        loaded_extensions: vec![],
        active_policies: vec![],
        security_epoch: SecurityEpoch::from_raw(1),
        gc_pressure: vec![GcPressureSample {
            extension_id: "ext-exact".to_string(),
            used_bytes: 1000,
            budget_bytes: 1000,
        }],
        scheduler_lanes: vec![],
    };
    let out = collect_runtime_diagnostics(&state, "t", "d", "p");
    assert_eq!(out.gc_pressure[0].pressure_millionths, 1_000_000);
    assert!(!out.gc_pressure[0].over_budget); // used == budget, not strictly over
}

#[test]
fn diagnostics_scheduler_zero_max_depth() {
    let state = RuntimeStateInput {
        snapshot_timestamp_ns: 0,
        loaded_extensions: vec![],
        active_policies: vec![],
        security_epoch: SecurityEpoch::from_raw(1),
        gc_pressure: vec![],
        scheduler_lanes: vec![SchedulerLaneSample {
            lane: "empty".to_string(),
            queue_depth: 5,
            max_depth: 0,
            tasks_submitted: 0,
            tasks_scheduled: 0,
            tasks_completed: 0,
            tasks_timed_out: 0,
        }],
    };
    let out = collect_runtime_diagnostics(&state, "t", "d", "p");
    // queue_depth=5, max_depth=0 -> compute_pressure_millionths(5,0) = 1_000_000
    assert_eq!(out.scheduler_lanes[0].utilization_millionths, 1_000_000);
}

// ===================================================================
// Section 7: render_diagnostics_summary
// ===================================================================

#[test]
fn render_diagnostics_summary_contains_all_sections() {
    let state = make_runtime_state();
    let out = collect_runtime_diagnostics(&state, "t", "d", "p");
    let rendered = render_diagnostics_summary(&out);

    assert!(rendered.contains("snapshot_timestamp_ns: 5000"));
    assert!(rendered.contains("security_epoch: 10"));
    assert!(rendered.contains("loaded_extensions: 2"));
    assert!(rendered.contains("ext-a"));
    assert!(rendered.contains("ext-z"));
    assert!(rendered.contains("active_policies: 2"));
    assert!(rendered.contains("pol-a"));
    assert!(rendered.contains("pol-z"));
    assert!(rendered.contains("gc_pressure_rows: 2"));
    assert!(rendered.contains("scheduler_lanes: 2"));
}

#[test]
fn render_diagnostics_summary_shows_pressure_and_over_budget() {
    let state = make_runtime_state();
    let out = collect_runtime_diagnostics(&state, "t", "d", "p");
    let rendered = render_diagnostics_summary(&out);
    // ext-a over budget
    assert!(rendered.contains("ext-a pressure=1000000 over_budget=true"));
    // ext-z under budget
    assert!(rendered.contains("ext-z pressure=600000 over_budget=false"));
}

#[test]
fn render_diagnostics_summary_shows_queue_and_utilization() {
    let state = make_runtime_state();
    let out = collect_runtime_diagnostics(&state, "t", "d", "p");
    let rendered = render_diagnostics_summary(&out);
    assert!(rendered.contains("ready queue_depth=25 utilization=250000"));
    assert!(rendered.contains("drain queue_depth=0 utilization=0"));
}

// ===================================================================
// Section 8: export_evidence_bundle
// ===================================================================

#[test]
fn export_unfiltered_includes_all_source_types() {
    let input = make_cli_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());

    let kinds: BTreeSet<EvidenceRecordKind> = output.records.iter().map(|r| r.kind).collect();
    assert!(kinds.contains(&EvidenceRecordKind::DecisionReceipt));
    assert!(kinds.contains(&EvidenceRecordKind::PolicyChange));
    assert!(kinds.contains(&EvidenceRecordKind::HostcallTelemetry));
    assert!(kinds.contains(&EvidenceRecordKind::ContainmentAction));
    assert!(kinds.contains(&EvidenceRecordKind::ReplayArtifact));
}

#[test]
fn export_is_deterministic() {
    let input = make_cli_input();
    let a = export_evidence_bundle(&input, EvidenceExportFilter::default());
    let b = export_evidence_bundle(&input, EvidenceExportFilter::default());
    assert_eq!(a, b);
}

#[test]
fn export_records_sorted_by_timestamp_then_kind() {
    let input = make_cli_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    for window in output.records.windows(2) {
        let left = &window[0];
        let right = &window[1];
        assert!(
            (left.timestamp_ns, left.kind) <= (right.timestamp_ns, right.kind),
            "records not sorted: ts {}:{:?} vs {}:{:?}",
            left.timestamp_ns,
            left.kind,
            right.timestamp_ns,
            right.kind
        );
    }
}

#[test]
fn export_summary_counts_match_records() {
    let input = make_cli_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    assert_eq!(output.summary.total_records, output.records.len());

    let kind_total: u64 = output.summary.counts_by_kind.values().sum();
    assert_eq!(kind_total as usize, output.records.len());

    let sev_total: u64 = output.summary.counts_by_severity.values().sum();
    assert_eq!(sev_total as usize, output.records.len());
}

#[test]
fn export_filter_by_trace_id() {
    let input = make_cli_input();
    let output = export_evidence_bundle(
        &input,
        EvidenceExportFilter {
            trace_id: Some("trace-int-2".to_string()),
            ..EvidenceExportFilter::default()
        },
    );
    assert!(output.summary.total_records > 0);
    for record in &output.records {
        assert_eq!(record.trace_id, "trace-int-2");
    }
}

#[test]
fn export_filter_by_extension_id() {
    let input = make_cli_input();
    let output = export_evidence_bundle(
        &input,
        EvidenceExportFilter {
            extension_id: Some("ext-a".to_string()),
            ..EvidenceExportFilter::default()
        },
    );
    assert!(output.summary.total_records > 0);
    for record in &output.records {
        assert_eq!(record.extension_id.as_deref(), Some("ext-a"));
    }
}

#[test]
fn export_filter_by_timestamp_range() {
    let input = make_cli_input();
    let output = export_evidence_bundle(
        &input,
        EvidenceExportFilter {
            start_timestamp_ns: Some(300),
            end_timestamp_ns: Some(700),
            ..EvidenceExportFilter::default()
        },
    );
    assert!(output.summary.total_records > 0);
    for record in &output.records {
        assert!(
            record.timestamp_ns >= 300 && record.timestamp_ns <= 700,
            "timestamp {} out of range",
            record.timestamp_ns
        );
    }
}

#[test]
fn export_filter_by_severity() {
    let input = make_cli_input();
    let output = export_evidence_bundle(
        &input,
        EvidenceExportFilter {
            severity: Some(EvidenceSeverity::Critical),
            ..EvidenceExportFilter::default()
        },
    );
    assert!(output.summary.total_records > 0);
    for record in &output.records {
        assert_eq!(record.severity, EvidenceSeverity::Critical);
    }
}

#[test]
fn export_filter_by_decision_type() {
    let input = make_cli_input();
    let output = export_evidence_bundle(
        &input,
        EvidenceExportFilter {
            decision_type: Some(DecisionType::SecurityAction),
            ..EvidenceExportFilter::default()
        },
    );
    assert!(output.summary.total_records > 0);
    for record in &output.records {
        assert_eq!(record.decision_type, Some(DecisionType::SecurityAction));
    }
}

#[test]
fn export_filter_no_match_returns_empty() {
    let input = make_cli_input();
    let output = export_evidence_bundle(
        &input,
        EvidenceExportFilter {
            extension_id: Some("nonexistent-ext".to_string()),
            ..EvidenceExportFilter::default()
        },
    );
    assert_eq!(output.summary.total_records, 0);
    assert!(output.records.is_empty());
}

#[test]
fn export_combined_filters_narrow_results() {
    let input = make_cli_input();
    let output = export_evidence_bundle(
        &input,
        EvidenceExportFilter {
            trace_id: Some("trace-int-1".to_string()),
            extension_id: Some("ext-a".to_string()),
            severity: Some(EvidenceSeverity::Critical),
            ..EvidenceExportFilter::default()
        },
    );
    for record in &output.records {
        assert_eq!(record.trace_id, "trace-int-1");
        assert_eq!(record.extension_id.as_deref(), Some("ext-a"));
        assert_eq!(record.severity, EvidenceSeverity::Critical);
    }
}

#[test]
fn export_log_event_is_evidence_export() {
    let input = make_cli_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    assert_eq!(output.logs.len(), 1);
    assert_eq!(output.logs[0].event, "evidence_export");
    assert_eq!(output.logs[0].outcome, "pass");
    assert_eq!(output.logs[0].trace_id, "trace-cli-root");
    assert_eq!(output.logs[0].decision_id, "decision-cli-root");
    assert_eq!(output.logs[0].policy_id, "policy-cli-root");
}

// ===================================================================
// Section 9: Evidence record kind assignment
// ===================================================================

#[test]
fn policy_update_maps_to_policy_change_kind() {
    let input = make_cli_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    // The PolicyUpdate entry should have kind=PolicyChange
    let policy_change_records: Vec<_> = output
        .records
        .iter()
        .filter(|r| r.kind == EvidenceRecordKind::PolicyChange)
        .collect();
    assert!(
        !policy_change_records.is_empty(),
        "should have PolicyChange records"
    );
}

#[test]
fn epoch_transition_maps_to_policy_change_kind() {
    let input = make_cli_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    // The EpochTransition entry should also produce kind=PolicyChange
    let epoch_records: Vec<_> = output
        .records
        .iter()
        .filter(|r| {
            r.kind == EvidenceRecordKind::PolicyChange
                && r.decision_type == Some(DecisionType::EpochTransition)
        })
        .collect();
    assert!(!epoch_records.is_empty());
}

#[test]
fn security_action_maps_to_decision_receipt_kind() {
    let input = make_cli_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    let sa_records: Vec<_> = output
        .records
        .iter()
        .filter(|r| {
            r.kind == EvidenceRecordKind::DecisionReceipt
                && r.decision_type == Some(DecisionType::SecurityAction)
        })
        .collect();
    assert!(!sa_records.is_empty());
}

#[test]
fn replay_artifacts_have_info_severity_and_no_decision() {
    let input = make_cli_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    let replays: Vec<_> = output
        .records
        .iter()
        .filter(|r| r.kind == EvidenceRecordKind::ReplayArtifact)
        .collect();
    assert_eq!(replays.len(), 2);
    for r in &replays {
        assert_eq!(r.severity, EvidenceSeverity::Info);
        assert!(r.decision_id.is_none());
        assert!(r.policy_id.is_none());
        assert!(r.decision_type.is_none());
    }
}

// ===================================================================
// Section 10: render_evidence_summary
// ===================================================================

#[test]
fn render_evidence_summary_empty_shows_no_entries_message() {
    let input = make_cli_input();
    let output = export_evidence_bundle(
        &input,
        EvidenceExportFilter {
            extension_id: Some("nonexistent".to_string()),
            ..EvidenceExportFilter::default()
        },
    );
    let rendered = render_evidence_summary(&output);
    assert_eq!(
        rendered,
        "No evidence entries found for the specified filters."
    );
}

#[test]
fn render_evidence_summary_nonempty_has_counts() {
    let input = make_cli_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    let rendered = render_evidence_summary(&output);
    assert!(rendered.contains("total_records:"));
    assert!(rendered.contains("counts_by_kind:"));
    assert!(rendered.contains("counts_by_severity:"));
}

// ===================================================================
// Section 11: Full round-trip (export output serde)
// ===================================================================

#[test]
fn evidence_export_output_serde_roundtrip() {
    let input = make_cli_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    let json = serde_json::to_string(&output).unwrap();
    let back: EvidenceExportOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(output, back);
}

#[test]
fn diagnostics_output_serde_roundtrip() {
    let state = make_runtime_state();
    let out = collect_runtime_diagnostics(&state, "t", "d", "p");
    let json = serde_json::to_string(&out).unwrap();
    let back: RuntimeDiagnosticsOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(out, back);
}

// ===================================================================
// Section 12: Ledger integration
// ===================================================================

#[test]
fn export_over_ledger_emitted_entries_is_stable() {
    let mut ledger = InMemoryLedger::new();
    for entry in make_evidence_entries() {
        EvidenceEmitter::emit(&mut ledger, entry).expect("emit should succeed");
    }
    let mut input = make_cli_input();
    input.evidence_entries = ledger.entries().to_vec();

    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    assert!(output.summary.total_records >= 5);
    assert!(output.logs.iter().any(|e| e.event == "evidence_export"));
}

// ===================================================================
// Section 13: HostcallTelemetryEnvelope / ContainmentReceiptEnvelope serde
// ===================================================================

#[test]
fn hostcall_telemetry_envelope_serde_roundtrip() {
    let envs = make_hostcall_envelopes();
    for env in &envs {
        let json = serde_json::to_string(env).unwrap();
        let back: HostcallTelemetryEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(*env, back);
    }
}

#[test]
fn containment_receipt_envelope_serde_roundtrip() {
    let envs = make_containment_receipts();
    for env in &envs {
        let json = serde_json::to_string(env).unwrap();
        let back: ContainmentReceiptEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(*env, back);
    }
}

// ===================================================================
// Section 14: RuntimeDiagnosticsCliInput serde
// ===================================================================

#[test]
fn cli_input_serde_roundtrip() {
    let input = make_cli_input();
    let json = serde_json::to_string(&input).unwrap();
    let back: RuntimeDiagnosticsCliInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

// ===================================================================
// Section 15: GcPressureDiagnostics / SchedulerLaneDiagnostics serde
// ===================================================================

#[test]
fn gc_pressure_diagnostics_serde_roundtrip() {
    let diag = GcPressureDiagnostics {
        extension_id: "ext-test".to_string(),
        used_bytes: 500,
        budget_bytes: 1000,
        pressure_millionths: 500_000,
        over_budget: false,
    };
    let json = serde_json::to_string(&diag).unwrap();
    let back: GcPressureDiagnostics = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, back);
}

#[test]
fn scheduler_lane_diagnostics_serde_roundtrip() {
    let diag = SchedulerLaneDiagnostics {
        lane: "ready".to_string(),
        queue_depth: 10,
        max_depth: 100,
        utilization_millionths: 100_000,
        tasks_submitted: 50,
        tasks_scheduled: 40,
        tasks_completed: 35,
        tasks_timed_out: 1,
    };
    let json = serde_json::to_string(&diag).unwrap();
    let back: SchedulerLaneDiagnostics = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, back);
}

// ===================================================================
// Section 16: Severity from evidence entries
// ===================================================================

#[test]
fn security_action_terminate_is_critical_severity() {
    let input = make_cli_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    // Our SecurityAction entry has action_name="terminate"
    let sa = output
        .records
        .iter()
        .find(|r| {
            r.kind == EvidenceRecordKind::DecisionReceipt
                && r.decision_type == Some(DecisionType::SecurityAction)
        })
        .expect("should find security action record");
    assert_eq!(sa.severity, EvidenceSeverity::Critical);
}

#[test]
fn hostcall_success_is_info_severity() {
    let input = make_cli_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    let success_records: Vec<_> = output
        .records
        .iter()
        .filter(|r| {
            r.kind == EvidenceRecordKind::HostcallTelemetry && r.severity == EvidenceSeverity::Info
        })
        .collect();
    assert!(!success_records.is_empty());
}

#[test]
fn hostcall_denied_is_warning_severity() {
    let input = make_cli_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    let denied_records: Vec<_> = output
        .records
        .iter()
        .filter(|r| {
            r.kind == EvidenceRecordKind::HostcallTelemetry
                && r.severity == EvidenceSeverity::Warning
        })
        .collect();
    assert!(!denied_records.is_empty());
}

#[test]
fn hostcall_error_is_critical_severity() {
    let input = make_cli_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    let error_records: Vec<_> = output
        .records
        .iter()
        .filter(|r| {
            r.kind == EvidenceRecordKind::HostcallTelemetry
                && r.severity == EvidenceSeverity::Critical
        })
        .collect();
    assert!(!error_records.is_empty());
}

#[test]
fn containment_terminate_is_critical_severity() {
    let input = make_cli_input();
    let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
    let containment = output
        .records
        .iter()
        .find(|r| r.kind == EvidenceRecordKind::ContainmentAction)
        .expect("should find containment record");
    assert_eq!(containment.severity, EvidenceSeverity::Critical);
    assert_eq!(
        containment.decision_type,
        Some(DecisionType::SecurityAction)
    );
}

// ===================================================================
// Section 17: Debug impls (smoke)
// ===================================================================

#[test]
fn debug_impls_produce_nonempty_output() {
    let sev = EvidenceSeverity::Info;
    assert!(!format!("{:?}", sev).is_empty());

    let kind = EvidenceRecordKind::DecisionReceipt;
    assert!(!format!("{:?}", kind).is_empty());

    let filter = EvidenceExportFilter::default();
    assert!(!format!("{:?}", filter).is_empty());

    let event = StructuredLogEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "e".into(),
        outcome: "o".into(),
        error_code: None,
    };
    assert!(!format!("{:?}", event).is_empty());
}

// ===================================================================
// Section 18: Preflight doctor
// ===================================================================

#[test]
fn preflight_doctor_red_for_critical_signals() {
    let input = make_cli_input();
    let output = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );

    assert_eq!(output.verdict, PreflightVerdict::Red);
    assert!(
        output
            .blockers
            .iter()
            .any(|blocker| blocker.severity == EvidenceSeverity::Critical),
        "expected at least one critical blocker"
    );
    assert!(
        output
            .support_bundle
            .files
            .iter()
            .any(|file| file.path == "support_bundle/index.json"),
        "support bundle index file should be present"
    );
    assert!(
        output
            .logs
            .iter()
            .any(|event| event.event == "preflight_doctor" && event.outcome == "fail"),
        "doctor log event should be present with fail outcome"
    );
}

#[test]
fn preflight_doctor_green_for_clean_signals() {
    let mut input = make_cli_input();
    input.evidence_entries.clear();
    input.containment_receipts.clear();
    input
        .hostcall_records
        .retain(|record| matches!(record.record.result_status, HostcallResult::Success));
    for sample in &mut input.runtime_state.gc_pressure {
        sample.used_bytes = sample.used_bytes.min(sample.budget_bytes);
    }
    for lane in &mut input.runtime_state.scheduler_lanes {
        lane.tasks_timed_out = 0;
        lane.queue_depth = 0;
    }

    let output = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );

    assert_eq!(output.verdict, PreflightVerdict::Green);
    assert!(output.blockers.is_empty());
    assert!(output.mandatory_field_status.valid);
    assert!(
        output
            .logs
            .iter()
            .any(|event| event.event == "preflight_doctor" && event.outcome == "pass"),
        "doctor log event should be present with pass outcome"
    );
}

#[test]
fn preflight_doctor_detects_missing_mandatory_fields() {
    let mut input = make_cli_input();
    input.trace_id.clear();

    let output = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );

    assert!(!output.mandatory_field_status.valid);
    assert!(
        output
            .mandatory_field_status
            .missing_fields
            .contains(&"trace_id".to_string())
    );
    assert_eq!(output.verdict, PreflightVerdict::Red);
    assert!(
        output
            .blockers
            .iter()
            .any(|blocker| blocker.blocker_id == "mandatory_field_contract"
                && blocker.severity == EvidenceSeverity::Critical),
        "missing mandatory fields should raise a critical contract blocker"
    );
}

#[test]
fn render_preflight_summary_includes_repro_commands() {
    let output = run_preflight_doctor(
        &make_cli_input(),
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let summary = render_preflight_summary(&output);

    assert!(summary.contains("verdict: red"));
    assert!(summary.contains("support_bundle_id: bundle-"));
    assert!(summary.contains("runtime_diagnostics doctor --input <path> --summary"));
}

// ===================================================================
// Section 19: Workload onboarding scorecard
// ===================================================================

#[test]
fn onboarding_scorecard_merges_preflight_and_external_signals() {
    let preflight = run_preflight_doctor(
        &make_cli_input(),
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let scorecard = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id: "pkg/weather-ext".to_string(),
        package_name: "weather-ext".to_string(),
        target_platforms: vec![
            "linux-x64".to_string(),
            "linux-x64".to_string(),
            "macos-arm64".to_string(),
        ],
        preflight,
        external_signals: vec![OnboardingScorecardSignal {
            signal_id: "platform:line-ending".to_string(),
            source: "platform_matrix".to_string(),
            severity: EvidenceSeverity::Warning,
            summary: "windows newline normalization drift".to_string(),
            remediation: "apply deterministic newline normalization on replay artifacts"
                .to_string(),
            reproducible_command: "scripts/run_rgc_cross_platform_matrix_gate.sh test".to_string(),
            evidence_links: vec![
                "artifacts/rgc_cross_platform_matrix/latest/drift.json".to_string(),
            ],
            owner_hint: Some("platform-matrix-lane".to_string()),
        }],
    });

    assert_eq!(scorecard.workload_id, "pkg/weather-ext");
    assert_eq!(scorecard.package_name, "weather-ext");
    assert_eq!(scorecard.readiness, OnboardingReadinessClass::Blocked);
    assert!(scorecard.score.critical_signals >= 1);
    assert!(scorecard.unresolved_signals.len() >= 2);
    assert_eq!(
        scorecard.target_platforms,
        vec!["linux-x64".to_string(), "macos-arm64".to_string()]
    );
    assert!(
        scorecard
            .reproducible_commands
            .contains(&"runtime_diagnostics doctor --input <path> --summary".to_string())
    );
}

#[test]
fn onboarding_scorecard_ready_for_clean_inputs() {
    let mut input = make_cli_input();
    input.evidence_entries.clear();
    input.containment_receipts.clear();
    input
        .hostcall_records
        .retain(|record| matches!(record.record.result_status, HostcallResult::Success));
    for sample in &mut input.runtime_state.gc_pressure {
        sample.used_bytes = sample.used_bytes.min(sample.budget_bytes);
    }
    for lane in &mut input.runtime_state.scheduler_lanes {
        lane.tasks_timed_out = 0;
        lane.queue_depth = 0;
    }

    let preflight = run_preflight_doctor(
        &input,
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    assert_eq!(preflight.verdict, PreflightVerdict::Green);

    let scorecard = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id: "pkg/clean-ext".to_string(),
        package_name: "clean-ext".to_string(),
        target_platforms: vec!["linux-x64".to_string()],
        preflight,
        external_signals: Vec::new(),
    });

    assert_eq!(scorecard.readiness, OnboardingReadinessClass::Ready);
    assert_eq!(
        scorecard.remediation_effort,
        OnboardingRemediationEffort::Low
    );
    assert_eq!(scorecard.score.critical_signals, 0);
    assert_eq!(scorecard.score.warning_signals, 0);
    assert!(scorecard.next_steps.is_empty());
}

#[test]
fn render_onboarding_scorecard_summary_contains_key_fields() {
    let preflight = run_preflight_doctor(
        &make_cli_input(),
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let scorecard = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id: "pkg/example".to_string(),
        package_name: "example".to_string(),
        target_platforms: vec!["linux-x64".to_string()],
        preflight,
        external_signals: Vec::new(),
    });
    let summary = render_onboarding_scorecard_summary(&scorecard);

    assert!(
        summary
            .contains("schema_version: franken-engine.runtime-diagnostics.onboarding-scorecard.v1")
    );
    assert!(summary.contains("readiness: blocked"));
    assert!(summary.contains("next_steps:"));
    assert!(summary.contains("reproducible_commands:"));
}

// ===================================================================
// Section 20: Rollout decision artifact consolidation
// ===================================================================

#[test]
fn rollout_decision_artifact_merges_sources_and_emits_recommendation() {
    let preflight = run_preflight_doctor(
        &make_cli_input(),
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let onboarding = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id: "pkg/weather-ext".to_string(),
        package_name: "weather-ext".to_string(),
        target_platforms: vec!["linux-x64".to_string(), "macos-arm64".to_string()],
        preflight,
        external_signals: vec![OnboardingScorecardSignal {
            signal_id: "compat:fs".to_string(),
            source: "compatibility_advisory".to_string(),
            severity: EvidenceSeverity::Warning,
            summary: "fs parity warning".to_string(),
            remediation: "review deterministic shim path".to_string(),
            reproducible_command: "scripts/run_frx_lockstep_oracle_suite.sh ci".to_string(),
            evidence_links: vec!["artifacts/frx_lockstep_oracle/latest/report.json".to_string()],
            owner_hint: Some("compatibility-lane".to_string()),
        }],
    });

    let artifact = build_rollout_decision_artifact(&RolloutDecisionArtifactInput {
        onboarding_scorecard: onboarding,
        compatibility_advisories: vec![OnboardingScorecardSignal {
            signal_id: "compat:fs".to_string(),
            source: "compatibility_advisory".to_string(),
            severity: EvidenceSeverity::Critical,
            summary: "critical fs parity drift".to_string(),
            remediation: "rollback candidate and block promotion".to_string(),
            reproducible_command: "scripts/run_frx_lockstep_oracle_suite.sh ci".to_string(),
            evidence_links: vec!["artifacts/frx_lockstep_oracle/latest/report.json".to_string()],
            owner_hint: Some("compatibility-lane".to_string()),
        }],
        platform_matrix_signals: vec![OnboardingScorecardSignal {
            signal_id: "matrix:macos-arm64".to_string(),
            source: "platform_matrix".to_string(),
            severity: EvidenceSeverity::Warning,
            summary: "macos-arm64 line-ending normalization drift".to_string(),
            remediation: "normalize newline handling in emitted artifacts".to_string(),
            reproducible_command: "scripts/run_rgc_cross_platform_matrix_gate.sh ci".to_string(),
            evidence_links: vec![
                "artifacts/rgc_cross_platform_matrix/latest/matrix_summary.json".to_string(),
            ],
            owner_hint: Some("platform-matrix-lane".to_string()),
        }],
    });

    assert_eq!(artifact.recommendation, RolloutRecommendation::Rollback);
    assert!(artifact.mandatory_field_status.valid);
    assert!(artifact.ga_gate_consumable);
    assert!(artifact.pilot_gate_consumable);
    assert!(
        artifact
            .merged_signals
            .iter()
            .any(|signal| signal.signal_id == "compat:fs"
                && signal.severity == EvidenceSeverity::Critical)
    );
}

#[test]
fn rollout_decision_artifact_fails_closed_on_missing_required_fields() {
    let preflight = run_preflight_doctor(
        &make_cli_input(),
        EvidenceExportFilter::default(),
        SupportBundleRedactionPolicy::default(),
    );
    let mut onboarding = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id: "pkg/example".to_string(),
        package_name: "example".to_string(),
        target_platforms: vec!["linux-x64".to_string()],
        preflight,
        external_signals: Vec::new(),
    });
    onboarding.workload_id.clear();
    onboarding.logs.clear();

    let artifact = build_rollout_decision_artifact(&RolloutDecisionArtifactInput {
        onboarding_scorecard: onboarding,
        compatibility_advisories: Vec::new(),
        platform_matrix_signals: Vec::new(),
    });
    let summary = render_rollout_decision_artifact_summary(&artifact);

    assert_eq!(artifact.recommendation, RolloutRecommendation::Defer);
    assert!(!artifact.mandatory_field_status.valid);
    assert!(!artifact.ga_gate_consumable);
    assert!(!artifact.pilot_gate_consumable);
    assert!(summary.contains("mandatory_fields_valid: false"));
    assert!(summary.contains("missing_fields:"));
}
