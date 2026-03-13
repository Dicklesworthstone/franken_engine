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
    GaEvidenceArtifactCategory, GaEvidenceArtifactLink, GaEvidencePackageMandatoryFieldStatus,
    GaEvidenceRiskDisposition, GcPressureSample, OnboardingReadinessClass,
    OnboardingRemediationEffort, OnboardingRemediationStep, OnboardingScoreBreakdown,
    OnboardingScorecardSignal, PreflightBlocker, PreflightMandatoryFieldStatus, PreflightVerdict,
    ReplayArtifactRecord, RolloutDecisionMandatoryFieldStatus, RolloutRecommendation,
    RuntimeDiagnosticsOutput, RuntimeExtensionState, RuntimeStateInput, SchedulerLaneSample,
    StructuredLogEvent, SupportBundleFile, SupportBundleFileIndexEntry,
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

// ===========================================================================
// Copy semantics for small enums
// ===========================================================================

#[test]
fn enrichment_evidence_severity_copy() {
    let a = EvidenceSeverity::Critical;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_evidence_record_kind_copy() {
    let a = EvidenceRecordKind::HostcallTelemetry;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_preflight_verdict_copy() {
    let a = PreflightVerdict::Yellow;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_onboarding_readiness_copy() {
    let a = OnboardingReadinessClass::Conditional;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_remediation_effort_copy() {
    let a = OnboardingRemediationEffort::High;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_rollout_recommendation_copy() {
    let a = RolloutRecommendation::CanaryHold;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_ga_evidence_category_copy() {
    let a = GaEvidenceArtifactCategory::Security;
    let b = a;
    assert_eq!(a, b);
}

// ===========================================================================
// Clone independence for struct types
// ===========================================================================

#[test]
fn enrichment_clone_independence_runtime_extension_state() {
    let original = RuntimeExtensionState {
        extension_id: "ext-a".to_string(),
        containment_state: ContainmentState::Running,
    };
    let mut cloned = original.clone();
    cloned.extension_id = "ext-modified".to_string();
    assert_eq!(original.extension_id, "ext-a");
    assert_eq!(cloned.extension_id, "ext-modified");
}

#[test]
fn enrichment_clone_independence_gc_pressure_sample() {
    let original = gc_sample("ext-a", 100, 200);
    let mut cloned = original.clone();
    cloned.used_bytes = 999;
    assert_eq!(original.used_bytes, 100);
    assert_eq!(cloned.used_bytes, 999);
}

#[test]
fn enrichment_clone_independence_scheduler_lane_sample() {
    let original = sched_lane("default", 50, 100);
    let mut cloned = original.clone();
    cloned.lane = "modified".to_string();
    assert_eq!(original.lane, "default");
    assert_eq!(cloned.lane, "modified");
}

#[test]
fn enrichment_clone_independence_structured_log_event() {
    let original = StructuredLogEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "test".to_string(),
        event: "evt".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let mut cloned = original.clone();
    cloned.outcome = "fail".to_string();
    assert_eq!(original.outcome, "pass");
    assert_eq!(cloned.outcome, "fail");
}

#[test]
fn enrichment_clone_independence_evidence_filter() {
    let original = EvidenceExportFilter {
        extension_id: Some("ext-1".to_string()),
        trace_id: None,
        start_timestamp_ns: None,
        end_timestamp_ns: None,
        severity: None,
        decision_type: None,
    };
    let mut cloned = original.clone();
    cloned.trace_id = Some("trace-modified".to_string());
    assert!(original.trace_id.is_none());
    assert_eq!(cloned.trace_id.as_deref(), Some("trace-modified"));
}

// ===========================================================================
// RuntimeStateInput serde roundtrip
// ===========================================================================

#[test]
fn enrichment_runtime_state_input_serde_roundtrip() {
    let input = make_state_input(
        vec![gc_sample("ext-a", 100, 200)],
        vec![sched_lane("main", 5, 10)],
    );
    let json = serde_json::to_string(&input).unwrap();
    let back: RuntimeStateInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

// ===========================================================================
// Debug nonempty for all main types
// ===========================================================================

#[test]
fn enrichment_debug_nonempty_all_enums() {
    assert!(!format!("{:?}", EvidenceSeverity::Info).is_empty());
    assert!(!format!("{:?}", EvidenceRecordKind::DecisionReceipt).is_empty());
    assert!(!format!("{:?}", PreflightVerdict::Green).is_empty());
    assert!(!format!("{:?}", OnboardingReadinessClass::Ready).is_empty());
    assert!(!format!("{:?}", OnboardingRemediationEffort::Low).is_empty());
    assert!(!format!("{:?}", CompatibilityUserImpactClass::BreakingBehavior).is_empty());
    assert!(!format!("{:?}", RolloutRecommendation::Promote).is_empty());
    assert!(!format!("{:?}", GaEvidenceArtifactCategory::Conformance).is_empty());
}

// ===========================================================================
// parse_decision_type case insensitive
// ===========================================================================

#[test]
fn enrichment_parse_decision_type_case_insensitive() {
    assert_eq!(
        parse_decision_type("SECURITY_ACTION"),
        Some(DecisionType::SecurityAction)
    );
    assert_eq!(
        parse_decision_type("Policy_Update"),
        Some(DecisionType::PolicyUpdate)
    );
}

// ===========================================================================
// GcPressureDiagnostics serde roundtrip
// ===========================================================================

#[test]
fn enrichment_gc_pressure_diagnostics_serde_roundtrip() {
    use frankenengine_engine::runtime_diagnostics_cli::GcPressureDiagnostics;
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

// ===========================================================================
// SchedulerLaneDiagnostics serde roundtrip
// ===========================================================================

#[test]
fn enrichment_scheduler_lane_diagnostics_serde_roundtrip() {
    use frankenengine_engine::runtime_diagnostics_cli::SchedulerLaneDiagnostics;
    let diag = SchedulerLaneDiagnostics {
        lane: "compute".to_string(),
        queue_depth: 25,
        max_depth: 100,
        utilization_millionths: 250_000,
        tasks_submitted: 100,
        tasks_scheduled: 90,
        tasks_completed: 80,
        tasks_timed_out: 2,
    };
    let json = serde_json::to_string(&diag).unwrap();
    let back: SchedulerLaneDiagnostics = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, back);
}

// ===========================================================================
// Struct serde roundtrips — uncovered types
// ===========================================================================

#[test]
fn enrichment_support_bundle_file_index_entry_serde_roundtrip() {
    let entry = SupportBundleFileIndexEntry {
        path: "diagnostics/runtime.json".into(),
        sha256: "abc123".into(),
        bytes: 1024,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let rt: SupportBundleFileIndexEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, rt);
}

#[test]
fn enrichment_support_bundle_file_serde_roundtrip() {
    let file = SupportBundleFile {
        path: "diagnostics/runtime.json".into(),
        content: r#"{"status":"ok"}"#.into(),
        sha256: "def456".into(),
        bytes: 15,
    };
    let json = serde_json::to_string(&file).unwrap();
    let rt: SupportBundleFile = serde_json::from_str(&json).unwrap();
    assert_eq!(file, rt);
}

#[test]
fn enrichment_preflight_blocker_serde_roundtrip() {
    let blocker = PreflightBlocker {
        blocker_id: "block-1".into(),
        severity: EvidenceSeverity::Critical,
        rationale: "missing evidence".into(),
        remediation: "run evidence collection".into(),
        reproducible_command: "frankenctl collect".into(),
        evidence_links: vec!["ref-1".into()],
    };
    let json = serde_json::to_string(&blocker).unwrap();
    let rt: PreflightBlocker = serde_json::from_str(&json).unwrap();
    assert_eq!(blocker, rt);
}

#[test]
fn enrichment_preflight_mandatory_field_status_serde_roundtrip() {
    let status = PreflightMandatoryFieldStatus {
        valid: false,
        missing_fields: vec!["trace_id".into()],
        inconsistent_fields: vec!["epoch".into()],
    };
    let json = serde_json::to_string(&status).unwrap();
    let rt: PreflightMandatoryFieldStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(status, rt);
}

#[test]
fn enrichment_onboarding_scorecard_signal_serde_roundtrip() {
    let signal = OnboardingScorecardSignal {
        signal_id: "sig-1".into(),
        source: "compatibility-check".into(),
        severity: EvidenceSeverity::Warning,
        summary: "minor divergence detected".into(),
        remediation: "update fixture".into(),
        reproducible_command: "frankenctl check".into(),
        evidence_links: vec!["ref-1".into()],
        owner_hint: Some("platform-team".into()),
    };
    let json = serde_json::to_string(&signal).unwrap();
    let rt: OnboardingScorecardSignal = serde_json::from_str(&json).unwrap();
    assert_eq!(signal, rt);
}

#[test]
fn enrichment_onboarding_scorecard_signal_no_owner_hint_roundtrip() {
    let signal = OnboardingScorecardSignal {
        signal_id: "sig-2".into(),
        source: "preflight".into(),
        severity: EvidenceSeverity::Info,
        summary: "all clear".into(),
        remediation: "none".into(),
        reproducible_command: "frankenctl preflight".into(),
        evidence_links: vec![],
        owner_hint: None,
    };
    let json = serde_json::to_string(&signal).unwrap();
    assert!(!json.contains("owner_hint"));
    let rt: OnboardingScorecardSignal = serde_json::from_str(&json).unwrap();
    assert_eq!(signal, rt);
}

#[test]
fn enrichment_onboarding_score_breakdown_serde_roundtrip() {
    let score = OnboardingScoreBreakdown {
        baseline_risk_millionths: 100_000,
        signal_risk_millionths: 50_000,
        total_risk_millionths: 150_000,
        critical_signals: 0,
        warning_signals: 2,
        info_signals: 5,
    };
    let json = serde_json::to_string(&score).unwrap();
    let rt: OnboardingScoreBreakdown = serde_json::from_str(&json).unwrap();
    assert_eq!(score, rt);
}

#[test]
fn enrichment_onboarding_remediation_step_serde_roundtrip() {
    let step = OnboardingRemediationStep {
        step_id: "step-1".into(),
        severity: EvidenceSeverity::Warning,
        summary: "update config".into(),
        remediation: "edit config.toml".into(),
        owner: "infra-team".into(),
        reproducible_command: "frankenctl update".into(),
        evidence_links: vec!["link-1".into()],
    };
    let json = serde_json::to_string(&step).unwrap();
    let rt: OnboardingRemediationStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, rt);
}

#[test]
fn enrichment_rollout_decision_mandatory_field_status_serde_roundtrip() {
    let status = RolloutDecisionMandatoryFieldStatus {
        valid: true,
        missing_fields: vec![],
        inconsistent_fields: vec![],
    };
    let json = serde_json::to_string(&status).unwrap();
    let rt: RolloutDecisionMandatoryFieldStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(status, rt);
}

#[test]
fn enrichment_ga_evidence_artifact_link_serde_roundtrip() {
    let link = GaEvidenceArtifactLink {
        category: GaEvidenceArtifactCategory::Security,
        path: "evidence/security-report.json".into(),
        description: "adversarial test results".into(),
    };
    let json = serde_json::to_string(&link).unwrap();
    let rt: GaEvidenceArtifactLink = serde_json::from_str(&json).unwrap();
    assert_eq!(link, rt);
}

#[test]
fn enrichment_ga_evidence_package_mandatory_field_status_serde_roundtrip() {
    let status = GaEvidencePackageMandatoryFieldStatus {
        valid: false,
        missing_fields: vec!["release_candidate_id".into()],
        inconsistent_fields: vec![],
    };
    let json = serde_json::to_string(&status).unwrap();
    let rt: GaEvidencePackageMandatoryFieldStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(status, rt);
}

#[test]
fn enrichment_ga_evidence_risk_disposition_serde_roundtrip() {
    let disposition = GaEvidenceRiskDisposition {
        readiness: OnboardingReadinessClass::Conditional,
        recommendation: RolloutRecommendation::CanaryHold,
        remediation_effort: OnboardingRemediationEffort::Medium,
        rationale: "needs more testing".into(),
        critical_signals: 0,
        warning_signals: 3,
        info_signals: 10,
        unresolved_signal_ids: vec!["sig-1".into()],
        next_steps: vec![],
    };
    let json = serde_json::to_string(&disposition).unwrap();
    let rt: GaEvidenceRiskDisposition = serde_json::from_str(&json).unwrap();
    assert_eq!(disposition, rt);
}

#[test]
fn enrichment_replay_artifact_record_serde_roundtrip() {
    let record = ReplayArtifactRecord {
        trace_id: "trace-1".into(),
        extension_id: "ext-1".into(),
        timestamp_ns: 1_000_000_000,
        artifact_id: "art-1".into(),
        replay_pointer: "pointer-1".into(),
    };
    let json = serde_json::to_string(&record).unwrap();
    let rt: ReplayArtifactRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, rt);
}

// ===========================================================================
// BTreeSet ordering — enum variants via serde tags
// ===========================================================================

#[test]
fn enrichment_evidence_severity_btreeset_ordering() {
    let tags: Vec<String> = [
        EvidenceSeverity::Info,
        EvidenceSeverity::Warning,
        EvidenceSeverity::Critical,
    ]
    .iter()
    .map(|v| serde_json::to_string(v).unwrap())
    .collect();
    let unique: BTreeSet<_> = tags.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn enrichment_evidence_record_kind_btreeset_ordering() {
    let tags: Vec<String> = [
        EvidenceRecordKind::DecisionReceipt,
        EvidenceRecordKind::HostcallTelemetry,
        EvidenceRecordKind::ContainmentAction,
        EvidenceRecordKind::PolicyChange,
        EvidenceRecordKind::ReplayArtifact,
    ]
    .iter()
    .map(|v| serde_json::to_string(v).unwrap())
    .collect();
    let unique: BTreeSet<_> = tags.iter().collect();
    assert_eq!(unique.len(), 5);
}

#[test]
fn enrichment_ga_evidence_category_btreeset_ordering() {
    let tags: Vec<String> = [
        GaEvidenceArtifactCategory::Conformance,
        GaEvidenceArtifactCategory::Performance,
        GaEvidenceArtifactCategory::Security,
    ]
    .iter()
    .map(|v| serde_json::to_string(v).unwrap())
    .collect();
    let unique: BTreeSet<_> = tags.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn enrichment_rollout_recommendation_btreeset_ordering() {
    let tags: Vec<String> = [
        RolloutRecommendation::Promote,
        RolloutRecommendation::CanaryHold,
        RolloutRecommendation::Rollback,
        RolloutRecommendation::Defer,
    ]
    .iter()
    .map(|v| serde_json::to_string(v).unwrap())
    .collect();
    let unique: BTreeSet<_> = tags.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// Display == serde tag consistency
// ===========================================================================

#[test]
fn enrichment_evidence_severity_display_matches_serde_tag() {
    for sev in [
        EvidenceSeverity::Info,
        EvidenceSeverity::Warning,
        EvidenceSeverity::Critical,
    ] {
        let display = sev.to_string();
        let serde_tag = serde_json::to_string(&sev).unwrap();
        assert_eq!(format!("\"{display}\""), serde_tag);
    }
}

#[test]
fn enrichment_evidence_record_kind_display_matches_serde_tag() {
    for kind in [
        EvidenceRecordKind::DecisionReceipt,
        EvidenceRecordKind::HostcallTelemetry,
        EvidenceRecordKind::ContainmentAction,
        EvidenceRecordKind::PolicyChange,
        EvidenceRecordKind::ReplayArtifact,
    ] {
        let display = kind.to_string();
        let serde_tag = serde_json::to_string(&kind).unwrap();
        assert_eq!(format!("\"{display}\""), serde_tag);
    }
}

#[test]
fn enrichment_preflight_verdict_display_matches_serde_tag() {
    for verdict in [
        PreflightVerdict::Green,
        PreflightVerdict::Yellow,
        PreflightVerdict::Red,
    ] {
        let display = verdict.to_string();
        let serde_tag = serde_json::to_string(&verdict).unwrap();
        assert_eq!(format!("\"{display}\""), serde_tag);
    }
}

#[test]
fn enrichment_rollout_recommendation_display_matches_serde_tag() {
    for rec in [
        RolloutRecommendation::Promote,
        RolloutRecommendation::CanaryHold,
        RolloutRecommendation::Rollback,
        RolloutRecommendation::Defer,
    ] {
        let display = rec.to_string();
        let serde_tag = serde_json::to_string(&rec).unwrap();
        assert_eq!(format!("\"{display}\""), serde_tag);
    }
}

#[test]
fn enrichment_ga_evidence_category_display_matches_serde_tag() {
    for cat in [
        GaEvidenceArtifactCategory::Conformance,
        GaEvidenceArtifactCategory::Performance,
        GaEvidenceArtifactCategory::Security,
    ] {
        let display = cat.to_string();
        let serde_tag = serde_json::to_string(&cat).unwrap();
        assert_eq!(format!("\"{display}\""), serde_tag);
    }
}

// ===========================================================================
// Clone independence — additional struct types
// ===========================================================================

#[test]
fn enrichment_clone_independence_preflight_blocker() {
    let original = PreflightBlocker {
        blocker_id: "block-1".into(),
        severity: EvidenceSeverity::Critical,
        rationale: "missing".into(),
        remediation: "collect".into(),
        reproducible_command: "cmd".into(),
        evidence_links: vec!["ref".into()],
    };
    let mut cloned = original.clone();
    cloned.blocker_id = "modified".into();
    assert_eq!(original.blocker_id, "block-1");
    assert_eq!(cloned.blocker_id, "modified");
}

#[test]
fn enrichment_clone_independence_support_bundle_redaction_policy() {
    let original = SupportBundleRedactionPolicy::default();
    let mut cloned = original.clone();
    cloned.replacement = "MODIFIED".into();
    assert_ne!(original.replacement, cloned.replacement);
}

#[test]
fn enrichment_clone_independence_onboarding_score_breakdown() {
    let original = OnboardingScoreBreakdown {
        baseline_risk_millionths: 100_000,
        signal_risk_millionths: 50_000,
        total_risk_millionths: 150_000,
        critical_signals: 0,
        warning_signals: 1,
        info_signals: 2,
    };
    let mut cloned = original.clone();
    cloned.critical_signals = 5;
    assert_eq!(original.critical_signals, 0);
    assert_eq!(cloned.critical_signals, 5);
}

// ===========================================================================
// Debug nonempty — additional struct types
// ===========================================================================

#[test]
fn enrichment_debug_nonempty_preflight_blocker() {
    let blocker = PreflightBlocker {
        blocker_id: "b".into(),
        severity: EvidenceSeverity::Info,
        rationale: "r".into(),
        remediation: "r".into(),
        reproducible_command: "c".into(),
        evidence_links: vec![],
    };
    let debug = format!("{blocker:?}");
    assert!(!debug.is_empty());
    assert!(debug.contains("PreflightBlocker"));
}

#[test]
fn enrichment_debug_nonempty_support_bundle_file_index_entry() {
    let entry = SupportBundleFileIndexEntry {
        path: "p".into(),
        sha256: "s".into(),
        bytes: 0,
    };
    let debug = format!("{entry:?}");
    assert!(!debug.is_empty());
    assert!(debug.contains("SupportBundleFileIndexEntry"));
}

#[test]
fn enrichment_debug_nonempty_ga_evidence_artifact_link() {
    let link = GaEvidenceArtifactLink {
        category: GaEvidenceArtifactCategory::Conformance,
        path: "p".into(),
        description: "d".into(),
    };
    let debug = format!("{link:?}");
    assert!(!debug.is_empty());
    assert!(debug.contains("GaEvidenceArtifactLink"));
}

// ===========================================================================
// CompatibilityUserImpactClass — Copy + clone
// ===========================================================================

#[test]
fn enrichment_compatibility_impact_copy() {
    let original = CompatibilityUserImpactClass::BreakingBehavior;
    let copied = original;
    assert_eq!(original, copied);
}

// ===========================================================================
// Preflight mandatory field status — valid case
// ===========================================================================

#[test]
fn enrichment_preflight_mandatory_field_status_valid() {
    let status = PreflightMandatoryFieldStatus {
        valid: true,
        missing_fields: vec![],
        inconsistent_fields: vec![],
    };
    assert!(status.valid);
    assert!(status.missing_fields.is_empty());
    assert!(status.inconsistent_fields.is_empty());
}
