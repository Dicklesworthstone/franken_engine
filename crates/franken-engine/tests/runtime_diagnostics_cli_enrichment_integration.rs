//! Enrichment integration tests for `runtime_diagnostics_cli`.
//!
//! Covers gaps: GC pressure computation edge cases, scheduler utilization,
//! redaction policy extend/dedup, evidence severity ordering, evidence filter
//! matching edge cases, preflight/onboarding/rollout/GA pipeline invariants,
//! Display uniqueness for all enum types, serde roundtrips for nested types,
//! schema version constants, and render summary content checks.

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

use frankenengine_engine::containment_executor::ContainmentState;
use frankenengine_engine::evidence_ledger::DecisionType;
use frankenengine_engine::runtime_diagnostics_cli::{
    CompatibilityUserImpactClass, EvidenceExportFilter, EvidenceRecordKind, EvidenceSeverity,
    GaEvidenceArtifactCategory, GcPressureSample, OnboardingReadinessClass,
    OnboardingRemediationEffort, PreflightVerdict, RolloutRecommendation, RuntimeDiagnosticsOutput,
    RuntimeExtensionState, RuntimeStateInput, SchedulerLaneSample, StructuredLogEvent,
    SupportBundleRedactionPolicy, collect_runtime_diagnostics, parse_decision_type,
    parse_evidence_severity, render_diagnostics_summary,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_state_input(
    gc_samples: Vec<GcPressureSample>,
    scheduler_lanes: Vec<SchedulerLaneSample>,
) -> RuntimeStateInput {
    RuntimeStateInput {
        snapshot_timestamp_ns: 1_000_000_000,
        loaded_extensions: vec![RuntimeExtensionState {
            extension_id: "ext-a".to_string(),
            containment_state: ContainmentState::Running,
        }],
        active_policies: vec!["policy-1".to_string()],
        security_epoch: SecurityEpoch::from_raw(1),
        gc_pressure: gc_samples,
        scheduler_lanes,
    }
}

fn gc_sample(ext: &str, used: u64, budget: u64) -> GcPressureSample {
    GcPressureSample {
        extension_id: ext.to_string(),
        used_bytes: used,
        budget_bytes: budget,
    }
}

fn sched_lane(lane: &str, depth: u64, max: u64) -> SchedulerLaneSample {
    SchedulerLaneSample {
        lane: lane.to_string(),
        queue_depth: depth,
        max_depth: max,
        tasks_submitted: 100,
        tasks_scheduled: 90,
        tasks_completed: 80,
        tasks_timed_out: 2,
    }
}

// ===========================================================================
// EvidenceSeverity tests
// ===========================================================================

#[test]
fn enrichment_evidence_severity_display_all_unique() {
    let all = [
        EvidenceSeverity::Info,
        EvidenceSeverity::Warning,
        EvidenceSeverity::Critical,
    ];
    let displays: BTreeSet<String> = all.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_evidence_severity_ordering() {
    assert!(EvidenceSeverity::Info < EvidenceSeverity::Warning);
    assert!(EvidenceSeverity::Warning < EvidenceSeverity::Critical);
}

#[test]
fn enrichment_evidence_severity_serde_roundtrip_all() {
    let all = [
        EvidenceSeverity::Info,
        EvidenceSeverity::Warning,
        EvidenceSeverity::Critical,
    ];
    for severity in &all {
        let json = serde_json::to_string(severity).unwrap();
        let back: EvidenceSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*severity, back);
    }
}

// ===========================================================================
// EvidenceRecordKind tests
// ===========================================================================

#[test]
fn enrichment_evidence_record_kind_display_all_unique() {
    let all = [
        EvidenceRecordKind::DecisionReceipt,
        EvidenceRecordKind::HostcallTelemetry,
        EvidenceRecordKind::ContainmentAction,
        EvidenceRecordKind::PolicyChange,
        EvidenceRecordKind::ReplayArtifact,
    ];
    let displays: BTreeSet<String> = all.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_evidence_record_kind_ordering() {
    assert!(EvidenceRecordKind::DecisionReceipt < EvidenceRecordKind::HostcallTelemetry);
    assert!(EvidenceRecordKind::HostcallTelemetry < EvidenceRecordKind::ContainmentAction);
    assert!(EvidenceRecordKind::ContainmentAction < EvidenceRecordKind::PolicyChange);
    assert!(EvidenceRecordKind::PolicyChange < EvidenceRecordKind::ReplayArtifact);
}

#[test]
fn enrichment_evidence_record_kind_serde_roundtrip_all() {
    let all = [
        EvidenceRecordKind::DecisionReceipt,
        EvidenceRecordKind::HostcallTelemetry,
        EvidenceRecordKind::ContainmentAction,
        EvidenceRecordKind::PolicyChange,
        EvidenceRecordKind::ReplayArtifact,
    ];
    for kind in &all {
        let json = serde_json::to_string(kind).unwrap();
        let back: EvidenceRecordKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ===========================================================================
// PreflightVerdict tests
// ===========================================================================

#[test]
fn enrichment_preflight_verdict_display_all_unique() {
    let all = [
        PreflightVerdict::Green,
        PreflightVerdict::Yellow,
        PreflightVerdict::Red,
    ];
    let displays: BTreeSet<String> = all.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_preflight_verdict_as_str_matches_display() {
    let all = [
        PreflightVerdict::Green,
        PreflightVerdict::Yellow,
        PreflightVerdict::Red,
    ];
    for v in &all {
        assert_eq!(v.as_str(), v.to_string());
    }
}

#[test]
fn enrichment_preflight_verdict_serde_roundtrip_all() {
    let all = [
        PreflightVerdict::Green,
        PreflightVerdict::Yellow,
        PreflightVerdict::Red,
    ];
    for v in &all {
        let json = serde_json::to_string(v).unwrap();
        let back: PreflightVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// OnboardingReadinessClass tests
// ===========================================================================

#[test]
fn enrichment_onboarding_readiness_display_all_unique() {
    let all = [
        OnboardingReadinessClass::Ready,
        OnboardingReadinessClass::Conditional,
        OnboardingReadinessClass::Blocked,
    ];
    let displays: BTreeSet<String> = all.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_onboarding_readiness_serde_roundtrip_all() {
    let all = [
        OnboardingReadinessClass::Ready,
        OnboardingReadinessClass::Conditional,
        OnboardingReadinessClass::Blocked,
    ];
    for r in &all {
        let json = serde_json::to_string(r).unwrap();
        let back: OnboardingReadinessClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ===========================================================================
// OnboardingRemediationEffort tests
// ===========================================================================

#[test]
fn enrichment_remediation_effort_display_all_unique() {
    let all = [
        OnboardingRemediationEffort::Low,
        OnboardingRemediationEffort::Medium,
        OnboardingRemediationEffort::High,
    ];
    let displays: BTreeSet<String> = all.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_remediation_effort_serde_roundtrip_all() {
    let all = [
        OnboardingRemediationEffort::Low,
        OnboardingRemediationEffort::Medium,
        OnboardingRemediationEffort::High,
    ];
    for e in &all {
        let json = serde_json::to_string(e).unwrap();
        let back: OnboardingRemediationEffort = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ===========================================================================
// CompatibilityUserImpactClass tests
// ===========================================================================

#[test]
fn enrichment_compatibility_impact_display_all_unique() {
    let all = [
        CompatibilityUserImpactClass::BreakingBehavior,
        CompatibilityUserImpactClass::MigrationRequired,
        CompatibilityUserImpactClass::CompatibilityGap,
        CompatibilityUserImpactClass::EcosystemInconsistency,
        CompatibilityUserImpactClass::UpstreamRuntimeDrift,
    ];
    let displays: BTreeSet<String> = all.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_compatibility_impact_serde_roundtrip_all() {
    let all = [
        CompatibilityUserImpactClass::BreakingBehavior,
        CompatibilityUserImpactClass::MigrationRequired,
        CompatibilityUserImpactClass::CompatibilityGap,
        CompatibilityUserImpactClass::EcosystemInconsistency,
        CompatibilityUserImpactClass::UpstreamRuntimeDrift,
    ];
    for c in &all {
        let json = serde_json::to_string(c).unwrap();
        let back: CompatibilityUserImpactClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

// ===========================================================================
// RolloutRecommendation tests
// ===========================================================================

#[test]
fn enrichment_rollout_recommendation_display_all_unique() {
    let all = [
        RolloutRecommendation::Promote,
        RolloutRecommendation::CanaryHold,
        RolloutRecommendation::Rollback,
        RolloutRecommendation::Defer,
    ];
    let displays: BTreeSet<String> = all.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_rollout_recommendation_serde_roundtrip_all() {
    let all = [
        RolloutRecommendation::Promote,
        RolloutRecommendation::CanaryHold,
        RolloutRecommendation::Rollback,
        RolloutRecommendation::Defer,
    ];
    for r in &all {
        let json = serde_json::to_string(r).unwrap();
        let back: RolloutRecommendation = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ===========================================================================
// GaEvidenceArtifactCategory tests
// ===========================================================================

#[test]
fn enrichment_ga_evidence_category_display_all_unique() {
    let all = [
        GaEvidenceArtifactCategory::Conformance,
        GaEvidenceArtifactCategory::Performance,
        GaEvidenceArtifactCategory::Security,
    ];
    let displays: BTreeSet<String> = all.iter().map(|c| c.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_ga_evidence_category_ordering() {
    assert!(GaEvidenceArtifactCategory::Conformance < GaEvidenceArtifactCategory::Performance);
    assert!(GaEvidenceArtifactCategory::Performance < GaEvidenceArtifactCategory::Security);
}

#[test]
fn enrichment_ga_evidence_category_serde_roundtrip_all() {
    let all = [
        GaEvidenceArtifactCategory::Conformance,
        GaEvidenceArtifactCategory::Performance,
        GaEvidenceArtifactCategory::Security,
    ];
    for c in &all {
        let json = serde_json::to_string(c).unwrap();
        let back: GaEvidenceArtifactCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, back);
    }
}

// ===========================================================================
// parse_evidence_severity tests
// ===========================================================================

#[test]
fn enrichment_parse_severity_case_insensitive() {
    assert_eq!(
        parse_evidence_severity("INFO"),
        Some(EvidenceSeverity::Info)
    );
    assert_eq!(
        parse_evidence_severity("Warning"),
        Some(EvidenceSeverity::Warning)
    );
    assert_eq!(
        parse_evidence_severity("CRITICAL"),
        Some(EvidenceSeverity::Critical)
    );
}

#[test]
fn enrichment_parse_severity_whitespace_trimmed() {
    assert_eq!(
        parse_evidence_severity("  info  "),
        Some(EvidenceSeverity::Info)
    );
}

#[test]
fn enrichment_parse_severity_unknown_returns_none() {
    assert_eq!(parse_evidence_severity("fatal"), None);
    assert_eq!(parse_evidence_severity(""), None);
}

// ===========================================================================
// parse_decision_type tests
// ===========================================================================

#[test]
fn enrichment_parse_decision_type_all_8_valid() {
    let inputs = [
        "security_action",
        "policy_update",
        "epoch_transition",
        "revocation",
        "extension_lifecycle",
        "capability_decision",
        "contract_evaluation",
        "remote_authorization",
    ];
    let expected = [
        DecisionType::SecurityAction,
        DecisionType::PolicyUpdate,
        DecisionType::EpochTransition,
        DecisionType::Revocation,
        DecisionType::ExtensionLifecycle,
        DecisionType::CapabilityDecision,
        DecisionType::ContractEvaluation,
        DecisionType::RemoteAuthorization,
    ];
    for (input, exp) in inputs.iter().zip(expected.iter()) {
        assert_eq!(
            parse_decision_type(input),
            Some(*exp),
            "failed for: {input}"
        );
    }
}

#[test]
fn enrichment_parse_decision_type_unknown_returns_none() {
    assert_eq!(parse_decision_type("deploy"), None);
    assert_eq!(parse_decision_type(""), None);
}

// ===========================================================================
// SupportBundleRedactionPolicy tests
// ===========================================================================

#[test]
fn enrichment_redaction_policy_default_has_6_fragments() {
    let policy = SupportBundleRedactionPolicy::default();
    assert_eq!(policy.key_fragments.len(), 6);
    assert!(policy.key_fragments.contains(&"secret".to_string()));
    assert!(policy.key_fragments.contains(&"token".to_string()));
    assert!(policy.key_fragments.contains(&"password".to_string()));
    assert!(policy.key_fragments.contains(&"credential".to_string()));
    assert!(policy.key_fragments.contains(&"private_key".to_string()));
    assert!(policy.key_fragments.contains(&"signature".to_string()));
}

#[test]
fn enrichment_redaction_policy_default_replacement() {
    let policy = SupportBundleRedactionPolicy::default();
    assert_eq!(policy.replacement, "sha256:REDACTED");
}

#[test]
fn enrichment_redaction_policy_with_additional_fragments() {
    let policy = SupportBundleRedactionPolicy::with_additional_fragments(vec![
        "api_key".to_string(),
        "auth_header".to_string(),
    ]);
    // Should have default 6 + 2 additional = 8
    assert!(policy.key_fragments.len() >= 8);
    assert!(policy.key_fragments.contains(&"api_key".to_string()));
    assert!(policy.key_fragments.contains(&"auth_header".to_string()));
}

#[test]
fn enrichment_redaction_policy_extend_dedup() {
    let mut policy = SupportBundleRedactionPolicy::default();
    // Add duplicates — should be deduped
    policy.extend_fragments(vec!["secret".to_string(), "token".to_string()]);
    let count = policy
        .key_fragments
        .iter()
        .filter(|f| *f == "secret")
        .count();
    assert_eq!(count, 1, "duplicate fragments should be deduped");
}

#[test]
fn enrichment_redaction_policy_extend_normalizes_case() {
    let mut policy = SupportBundleRedactionPolicy::default();
    policy.extend_fragments(vec!["API_KEY".to_string()]);
    assert!(
        policy.key_fragments.contains(&"api_key".to_string()),
        "fragments should be lowercased"
    );
}

#[test]
fn enrichment_redaction_policy_extend_filters_empty() {
    let mut policy = SupportBundleRedactionPolicy::default();
    let before = policy.key_fragments.len();
    policy.extend_fragments(vec!["".to_string(), "   ".to_string()]);
    assert_eq!(policy.key_fragments.len(), before);
}

#[test]
fn enrichment_redaction_policy_serde_roundtrip() {
    let policy =
        SupportBundleRedactionPolicy::with_additional_fragments(vec!["custom_key".to_string()]);
    let json = serde_json::to_string(&policy).unwrap();
    let back: SupportBundleRedactionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

// ===========================================================================
// GC pressure computation via collect_runtime_diagnostics
// ===========================================================================

#[test]
fn enrichment_gc_pressure_zero_budget_zero_used() {
    let input = make_state_input(vec![gc_sample("ext-1", 0, 0)], vec![]);
    let output = collect_runtime_diagnostics(&input, "t1", "d1", "p1");
    assert_eq!(output.gc_pressure.len(), 1);
    assert_eq!(output.gc_pressure[0].pressure_millionths, 0);
    assert!(!output.gc_pressure[0].over_budget);
}

#[test]
fn enrichment_gc_pressure_zero_budget_nonzero_used() {
    let input = make_state_input(vec![gc_sample("ext-1", 1000, 0)], vec![]);
    let output = collect_runtime_diagnostics(&input, "t1", "d1", "p1");
    assert_eq!(output.gc_pressure[0].pressure_millionths, 1_000_000);
    // over_budget requires budget > 0
    assert!(!output.gc_pressure[0].over_budget);
}

#[test]
fn enrichment_gc_pressure_half_used() {
    let input = make_state_input(vec![gc_sample("ext-1", 500, 1000)], vec![]);
    let output = collect_runtime_diagnostics(&input, "t1", "d1", "p1");
    assert_eq!(output.gc_pressure[0].pressure_millionths, 500_000);
    assert!(!output.gc_pressure[0].over_budget);
}

#[test]
fn enrichment_gc_pressure_over_budget() {
    let input = make_state_input(vec![gc_sample("ext-1", 2000, 1000)], vec![]);
    let output = collect_runtime_diagnostics(&input, "t1", "d1", "p1");
    // Clamped to 1_000_000
    assert_eq!(output.gc_pressure[0].pressure_millionths, 1_000_000);
    assert!(output.gc_pressure[0].over_budget);
}

#[test]
fn enrichment_gc_pressure_exact_budget() {
    let input = make_state_input(vec![gc_sample("ext-1", 1000, 1000)], vec![]);
    let output = collect_runtime_diagnostics(&input, "t1", "d1", "p1");
    assert_eq!(output.gc_pressure[0].pressure_millionths, 1_000_000);
    // used == budget, not over
    assert!(!output.gc_pressure[0].over_budget);
}

// ===========================================================================
// Scheduler utilization via collect_runtime_diagnostics
// ===========================================================================

#[test]
fn enrichment_scheduler_utilization_half() {
    let input = make_state_input(vec![], vec![sched_lane("default", 50, 100)]);
    let output = collect_runtime_diagnostics(&input, "t1", "d1", "p1");
    assert_eq!(output.scheduler_lanes.len(), 1);
    assert_eq!(output.scheduler_lanes[0].utilization_millionths, 500_000);
}

#[test]
fn enrichment_scheduler_utilization_zero_max() {
    let input = make_state_input(vec![], vec![sched_lane("default", 0, 0)]);
    let output = collect_runtime_diagnostics(&input, "t1", "d1", "p1");
    // zero max, zero depth → 0 pressure
    assert_eq!(output.scheduler_lanes[0].utilization_millionths, 0);
}

#[test]
fn enrichment_scheduler_utilization_full() {
    let input = make_state_input(vec![], vec![sched_lane("default", 100, 100)]);
    let output = collect_runtime_diagnostics(&input, "t1", "d1", "p1");
    assert_eq!(output.scheduler_lanes[0].utilization_millionths, 1_000_000);
}

// ===========================================================================
// collect_runtime_diagnostics: sorting and dedup
// ===========================================================================

#[test]
fn enrichment_diagnostics_sorts_extensions_by_id() {
    let mut input = make_state_input(vec![], vec![]);
    input.loaded_extensions = vec![
        RuntimeExtensionState {
            extension_id: "ext-z".to_string(),
            containment_state: ContainmentState::Running,
        },
        RuntimeExtensionState {
            extension_id: "ext-a".to_string(),
            containment_state: ContainmentState::Running,
        },
    ];
    let output = collect_runtime_diagnostics(&input, "t", "d", "p");
    assert_eq!(output.loaded_extensions[0].extension_id, "ext-a");
    assert_eq!(output.loaded_extensions[1].extension_id, "ext-z");
}

#[test]
fn enrichment_diagnostics_dedup_policies() {
    let mut input = make_state_input(vec![], vec![]);
    input.active_policies = vec![
        "policy-a".to_string(),
        "policy-a".to_string(),
        "policy-b".to_string(),
    ];
    let output = collect_runtime_diagnostics(&input, "t", "d", "p");
    assert_eq!(output.active_policies.len(), 2);
}

#[test]
fn enrichment_diagnostics_filters_empty_policies() {
    let mut input = make_state_input(vec![], vec![]);
    input.active_policies = vec!["policy-a".to_string(), "".to_string(), "   ".to_string()];
    let output = collect_runtime_diagnostics(&input, "t", "d", "p");
    assert_eq!(output.active_policies.len(), 1);
    assert_eq!(output.active_policies[0], "policy-a");
}

#[test]
fn enrichment_diagnostics_emits_log_event() {
    let input = make_state_input(vec![], vec![]);
    let output = collect_runtime_diagnostics(&input, "trace-1", "dec-1", "pol-1");
    assert_eq!(output.logs.len(), 1);
    assert_eq!(output.logs[0].trace_id, "trace-1");
    assert_eq!(output.logs[0].component, "runtime_diagnostics_cli");
    assert_eq!(output.logs[0].outcome, "pass");
    assert!(output.logs[0].error_code.is_none());
}

#[test]
fn enrichment_diagnostics_deterministic() {
    let input = make_state_input(
        vec![gc_sample("ext-a", 100, 200)],
        vec![sched_lane("main", 5, 10)],
    );
    let o1 = collect_runtime_diagnostics(&input, "t", "d", "p");
    let o2 = collect_runtime_diagnostics(&input, "t", "d", "p");
    assert_eq!(o1, o2);
}

// ===========================================================================
// render_diagnostics_summary content checks
// ===========================================================================

#[test]
fn enrichment_render_summary_contains_sections() {
    let input = make_state_input(
        vec![gc_sample("ext-a", 100, 200)],
        vec![sched_lane("main", 5, 10)],
    );
    let output = collect_runtime_diagnostics(&input, "t", "d", "p");
    let summary = render_diagnostics_summary(&output);
    assert!(summary.contains("snapshot_timestamp_ns:"));
    assert!(summary.contains("security_epoch:"));
    assert!(summary.contains("loaded_extensions:"));
    assert!(summary.contains("active_policies:"));
    assert!(summary.contains("gc_pressure_rows:"));
    assert!(summary.contains("scheduler_lanes:"));
}

#[test]
fn enrichment_render_summary_contains_extension_ids() {
    let input = make_state_input(vec![], vec![]);
    let output = collect_runtime_diagnostics(&input, "t", "d", "p");
    let summary = render_diagnostics_summary(&output);
    assert!(summary.contains("ext-a"));
}

// ===========================================================================
// EvidenceExportFilter tests
// ===========================================================================

#[test]
fn enrichment_evidence_filter_default_is_empty() {
    let filter = EvidenceExportFilter::default();
    assert!(filter.extension_id.is_none());
    assert!(filter.trace_id.is_none());
    assert!(filter.start_timestamp_ns.is_none());
    assert!(filter.end_timestamp_ns.is_none());
    assert!(filter.severity.is_none());
    assert!(filter.decision_type.is_none());
}

#[test]
fn enrichment_evidence_filter_serde_roundtrip() {
    let filter = EvidenceExportFilter {
        extension_id: Some("ext-1".to_string()),
        trace_id: Some("trace-abc".to_string()),
        start_timestamp_ns: Some(100),
        end_timestamp_ns: Some(200),
        severity: Some(EvidenceSeverity::Warning),
        decision_type: Some(DecisionType::SecurityAction),
    };
    let json = serde_json::to_string(&filter).unwrap();
    let back: EvidenceExportFilter = serde_json::from_str(&json).unwrap();
    assert_eq!(filter, back);
}

// ===========================================================================
// StructuredLogEvent tests
// ===========================================================================

#[test]
fn enrichment_log_event_serde_roundtrip_with_error() {
    let event = StructuredLogEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "runtime_diagnostics_cli".to_string(),
        event: "test_event".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("FE-TEST-0001".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_log_event_serde_roundtrip_without_error() {
    let event = StructuredLogEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "runtime_diagnostics_cli".to_string(),
        event: "test_event".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: StructuredLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ===========================================================================
// RuntimeDiagnosticsOutput serde roundtrip
// ===========================================================================

#[test]
fn enrichment_diagnostics_output_serde_roundtrip() {
    let input = make_state_input(
        vec![gc_sample("ext-a", 100, 200)],
        vec![sched_lane("main", 5, 10)],
    );
    let output = collect_runtime_diagnostics(&input, "t", "d", "p");
    let json = serde_json::to_string(&output).unwrap();
    let back: RuntimeDiagnosticsOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(output, back);
}

// ===========================================================================
// GcPressureSample / SchedulerLaneSample serde
// ===========================================================================

#[test]
fn enrichment_gc_sample_serde_roundtrip() {
    let sample = gc_sample("ext-test", 512, 1024);
    let json = serde_json::to_string(&sample).unwrap();
    let back: GcPressureSample = serde_json::from_str(&json).unwrap();
    assert_eq!(sample, back);
}

#[test]
fn enrichment_scheduler_lane_serde_roundtrip() {
    let lane = sched_lane("compute", 25, 100);
    let json = serde_json::to_string(&lane).unwrap();
    let back: SchedulerLaneSample = serde_json::from_str(&json).unwrap();
    assert_eq!(lane, back);
}

// ===========================================================================
// Multiple GC / scheduler entries ordering
// ===========================================================================

#[test]
fn enrichment_gc_pressure_sorted_by_extension_id() {
    let input = make_state_input(
        vec![
            gc_sample("ext-z", 100, 200),
            gc_sample("ext-a", 50, 100),
            gc_sample("ext-m", 75, 150),
        ],
        vec![],
    );
    let output = collect_runtime_diagnostics(&input, "t", "d", "p");
    let ids: Vec<&str> = output
        .gc_pressure
        .iter()
        .map(|g| g.extension_id.as_str())
        .collect();
    assert_eq!(ids, vec!["ext-a", "ext-m", "ext-z"]);
}

#[test]
fn enrichment_scheduler_lanes_sorted_by_name() {
    let input = make_state_input(
        vec![],
        vec![
            sched_lane("compute", 10, 100),
            sched_lane("async-io", 5, 50),
            sched_lane("priority", 20, 200),
        ],
    );
    let output = collect_runtime_diagnostics(&input, "t", "d", "p");
    let names: Vec<&str> = output
        .scheduler_lanes
        .iter()
        .map(|l| l.lane.as_str())
        .collect();
    assert_eq!(names, vec!["async-io", "compute", "priority"]);
}
