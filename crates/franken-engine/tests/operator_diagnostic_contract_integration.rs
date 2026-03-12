//! Integration tests for operator_diagnostic_contract module (bd-3nr.1.3.3).
//!
//! Validates end-to-end diagnostic emission, contract integrity, policy
//! mapping coverage, serde roundtrips, determinism, and event structure
//! across normal, boundary, failure, and adversarial paths.

use std::collections::BTreeMap;

use frankenengine_engine::operator_diagnostic_contract::{
    BEAD_ID, BoundaryPolicyMappingContract, COMPONENT, DiagnosticEntry, DiagnosticEvent,
    DiagnosticSeverity, InternalFailureKind, NextAction, OperatorImpact, POLICY_ID, SCHEMA_VERSION,
    UserImpact, build_diagnostic_event,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn canonical_contract() -> BoundaryPolicyMappingContract {
    BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1))
}

fn emit(
    contract: &BoundaryPolicyMappingContract,
    kind: InternalFailureKind,
    message: &str,
) -> DiagnosticEntry {
    contract.emit_diagnostic(kind, message, None, None, BTreeMap::new())
}

fn emit_with_refs(
    contract: &BoundaryPolicyMappingContract,
    kind: InternalFailureKind,
    message: &str,
    evidence: &str,
    replay: &str,
) -> DiagnosticEntry {
    contract.emit_diagnostic(kind, message, Some(evidence), Some(replay), BTreeMap::new())
}

// ---------------------------------------------------------------------------
// Contract construction
// ---------------------------------------------------------------------------

#[test]
fn canonical_contract_covers_all_nine_failure_kinds() {
    let contract = canonical_contract();
    assert_eq!(contract.coverage_count(), InternalFailureKind::all().len());
    assert_eq!(contract.coverage_count(), 9);
    for kind in InternalFailureKind::all() {
        assert!(
            contract.mapping_for(*kind).is_some(),
            "missing mapping for {kind}"
        );
    }
}

#[test]
fn canonical_contract_schema_fields() {
    let contract = canonical_contract();
    assert_eq!(contract.schema_version, SCHEMA_VERSION);
    assert_eq!(contract.bead_id, BEAD_ID);
    assert_eq!(contract.policy_id, POLICY_ID);
    assert_eq!(contract.component, COMPONENT);
}

#[test]
fn canonical_contract_epoch_propagated() {
    let epoch = SecurityEpoch::from_raw(42);
    let contract = BoundaryPolicyMappingContract::canonical(epoch);
    assert_eq!(contract.epoch, epoch);
}

#[test]
fn canonical_contract_integrity_on_fresh_build() {
    let contract = canonical_contract();
    assert!(contract.verify_integrity());
}

#[test]
fn tampered_hash_fails_integrity() {
    let mut contract = canonical_contract();
    contract.content_hash =
        frankenengine_engine::hash_tiers::ContentHash::compute(b"tampered-payload");
    assert!(!contract.verify_integrity());
}

#[test]
fn tampered_mapping_fails_integrity() {
    let mut contract = canonical_contract();
    if let Some(mapping) = contract.mappings.get_mut("cancellation") {
        mapping.error_code = "FE-TAMPERED-999".to_string();
    }
    assert!(!contract.verify_integrity());
}

// ---------------------------------------------------------------------------
// Error code stability
// ---------------------------------------------------------------------------

#[test]
fn error_code_format_stable() {
    let contract = canonical_contract();
    for kind in InternalFailureKind::all() {
        let mapping = contract.mapping_for(*kind).unwrap();
        assert!(
            mapping.error_code.starts_with(kind.error_code_prefix()),
            "error code {} should start with prefix {} for kind {kind}",
            mapping.error_code,
            kind.error_code_prefix()
        );
        assert!(
            mapping.error_code.contains('-'),
            "error code should contain dashes: {}",
            mapping.error_code
        );
    }
}

#[test]
fn all_error_codes_unique() {
    let contract = canonical_contract();
    let mut codes: Vec<&str> = contract
        .mappings
        .values()
        .map(|m| m.error_code.as_str())
        .collect();
    let orig_len = codes.len();
    codes.sort();
    codes.dedup();
    assert_eq!(codes.len(), orig_len, "duplicate error codes found");
}

#[test]
fn all_error_code_prefixes_unique() {
    let prefixes: Vec<&str> = InternalFailureKind::all()
        .iter()
        .map(|k| k.error_code_prefix())
        .collect();
    let mut deduped = prefixes.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(prefixes.len(), deduped.len());
}

// ---------------------------------------------------------------------------
// Severity assignments
// ---------------------------------------------------------------------------

#[test]
fn panic_class_is_fatal() {
    let contract = canonical_contract();
    let mapping = contract
        .mapping_for(InternalFailureKind::PanicClass)
        .unwrap();
    assert_eq!(mapping.severity, DiagnosticSeverity::Fatal);
}

#[test]
fn domain_error_is_info() {
    let contract = canonical_contract();
    let mapping = contract
        .mapping_for(InternalFailureKind::DomainError)
        .unwrap();
    assert_eq!(mapping.severity, DiagnosticSeverity::Info);
}

#[test]
fn budget_exhaustion_is_error() {
    let contract = canonical_contract();
    let mapping = contract
        .mapping_for(InternalFailureKind::BudgetExhaustion)
        .unwrap();
    assert_eq!(mapping.severity, DiagnosticSeverity::Error);
}

#[test]
fn cancellation_is_warning() {
    let contract = canonical_contract();
    let mapping = contract
        .mapping_for(InternalFailureKind::Cancellation)
        .unwrap();
    assert_eq!(mapping.severity, DiagnosticSeverity::Warning);
}

#[test]
fn severity_weight_total_ordering() {
    assert!(DiagnosticSeverity::Fatal.weight() > DiagnosticSeverity::Error.weight());
    assert!(DiagnosticSeverity::Error.weight() > DiagnosticSeverity::Warning.weight());
    assert!(DiagnosticSeverity::Warning.weight() > DiagnosticSeverity::Info.weight());
    assert!(DiagnosticSeverity::Info.weight() > 0);
}

// ---------------------------------------------------------------------------
// Impact classifications
// ---------------------------------------------------------------------------

#[test]
fn panic_class_operator_immediate_action() {
    let contract = canonical_contract();
    let mapping = contract
        .mapping_for(InternalFailureKind::PanicClass)
        .unwrap();
    assert_eq!(mapping.operator_impact, OperatorImpact::ImmediateAction);
}

#[test]
fn infra_failure_operator_immediate_action() {
    let contract = canonical_contract();
    let mapping = contract
        .mapping_for(InternalFailureKind::InfrastructureFailure)
        .unwrap();
    assert_eq!(mapping.operator_impact, OperatorImpact::ImmediateAction);
}

#[test]
fn cancellation_operator_informational_only() {
    let contract = canonical_contract();
    let mapping = contract
        .mapping_for(InternalFailureKind::Cancellation)
        .unwrap();
    assert_eq!(mapping.operator_impact, OperatorImpact::InformationalOnly);
}

#[test]
fn compat_drift_user_degraded_quality() {
    let contract = canonical_contract();
    let mapping = contract
        .mapping_for(InternalFailureKind::CompatibilityDrift)
        .unwrap();
    assert_eq!(mapping.user_impact, UserImpact::DegradedQuality);
}

#[test]
fn domain_error_user_operation_failed() {
    let contract = canonical_contract();
    let mapping = contract
        .mapping_for(InternalFailureKind::DomainError)
        .unwrap();
    assert_eq!(mapping.user_impact, UserImpact::OperationFailed);
}

// ---------------------------------------------------------------------------
// Next action assignments
// ---------------------------------------------------------------------------

#[test]
fn cancellation_next_action_retry() {
    let contract = canonical_contract();
    let mapping = contract
        .mapping_for(InternalFailureKind::Cancellation)
        .unwrap();
    assert_eq!(mapping.next_action, NextAction::Retry);
}

#[test]
fn budget_next_action_increase_budget() {
    let contract = canonical_contract();
    let mapping = contract
        .mapping_for(InternalFailureKind::BudgetExhaustion)
        .unwrap();
    assert_eq!(mapping.next_action, NextAction::IncreaseBudget);
}

#[test]
fn capability_next_action_grant() {
    let contract = canonical_contract();
    let mapping = contract
        .mapping_for(InternalFailureKind::CapabilityDenial)
        .unwrap();
    assert_eq!(mapping.next_action, NextAction::GrantCapability);
}

#[test]
fn policy_next_action_update_policy() {
    let contract = canonical_contract();
    let mapping = contract
        .mapping_for(InternalFailureKind::PolicyDenial)
        .unwrap();
    assert_eq!(mapping.next_action, NextAction::UpdatePolicy);
}

#[test]
fn compat_next_action_upgrade() {
    let contract = canonical_contract();
    let mapping = contract
        .mapping_for(InternalFailureKind::CompatibilityDrift)
        .unwrap();
    assert_eq!(mapping.next_action, NextAction::UpgradeVersion);
}

#[test]
fn infra_next_action_investigate() {
    let contract = canonical_contract();
    let mapping = contract
        .mapping_for(InternalFailureKind::InfrastructureFailure)
        .unwrap();
    assert_eq!(mapping.next_action, NextAction::InvestigateInfra);
}

#[test]
fn domain_error_next_action_no_action() {
    let contract = canonical_contract();
    let mapping = contract
        .mapping_for(InternalFailureKind::DomainError)
        .unwrap();
    assert_eq!(mapping.next_action, NextAction::NoAction);
}

#[test]
fn panic_and_unknown_next_action_file_bug() {
    let contract = canonical_contract();
    for kind in [
        InternalFailureKind::PanicClass,
        InternalFailureKind::Unknown,
    ] {
        let mapping = contract.mapping_for(kind).unwrap();
        assert_eq!(
            mapping.next_action,
            NextAction::FileBugReport,
            "expected FileBugReport for {kind}"
        );
    }
}

// ---------------------------------------------------------------------------
// Evidence and replay linkage
// ---------------------------------------------------------------------------

#[test]
fn evidence_linked_count_is_positive() {
    let contract = canonical_contract();
    let count = contract.evidence_linked_count();
    assert!(count > 0, "at least one mapping should have evidence refs");
    assert!(count <= contract.coverage_count());
}

#[test]
fn panic_has_evidence_and_replay_refs() {
    let contract = canonical_contract();
    let mapping = contract
        .mapping_for(InternalFailureKind::PanicClass)
        .unwrap();
    assert!(mapping.has_evidence_ref);
    assert!(mapping.has_replay_ref);
}

#[test]
fn domain_error_has_no_evidence_or_replay() {
    let contract = canonical_contract();
    let mapping = contract
        .mapping_for(InternalFailureKind::DomainError)
        .unwrap();
    assert!(!mapping.has_evidence_ref);
    assert!(!mapping.has_replay_ref);
}

// ---------------------------------------------------------------------------
// Diagnostic emission
// ---------------------------------------------------------------------------

#[test]
fn emit_diagnostic_for_each_failure_kind() {
    let contract = canonical_contract();
    for kind in InternalFailureKind::all() {
        let diag = emit(&contract, *kind, &format!("test message for {kind}"));
        assert!(
            diag.error_code.starts_with(kind.error_code_prefix()),
            "error code mismatch for {kind}: {}",
            diag.error_code
        );
        assert_eq!(diag.failure_kind, *kind);
    }
}

#[test]
fn emit_diagnostic_evidence_ref_propagated() {
    let contract = canonical_contract();
    let diag = emit_with_refs(
        &contract,
        InternalFailureKind::BudgetExhaustion,
        "exhausted",
        "evidence-bundle-abc",
        "frankenctl replay --trace t-123",
    );
    assert_eq!(diag.evidence_ref.as_deref(), Some("evidence-bundle-abc"));
    assert_eq!(
        diag.replay_ref.as_deref(),
        Some("frankenctl replay --trace t-123")
    );
}

#[test]
fn emit_diagnostic_none_refs_when_absent() {
    let contract = canonical_contract();
    let diag = emit(&contract, InternalFailureKind::Cancellation, "cancelled");
    assert!(diag.evidence_ref.is_none());
    assert!(diag.replay_ref.is_none());
}

#[test]
fn emit_diagnostic_context_round_trips() {
    let contract = canonical_contract();
    let ctx = BTreeMap::from([
        ("budget_remaining_ms".to_string(), "5".to_string()),
        ("cell_id".to_string(), "cell-42".to_string()),
        ("extension_id".to_string(), "ext-abc".to_string()),
    ]);
    let diag = contract.emit_diagnostic(
        InternalFailureKind::BudgetExhaustion,
        "exhausted",
        None,
        None,
        ctx.clone(),
    );
    assert_eq!(diag.context, ctx);
    assert_eq!(diag.context.len(), 3);
}

#[test]
fn emit_diagnostic_message_preserved() {
    let contract = canonical_contract();
    let message = "cell close budget exhausted at 5ms remaining in extension ext-abc";
    let diag = emit(&contract, InternalFailureKind::BudgetExhaustion, message);
    assert_eq!(diag.message, message);
}

#[test]
fn emit_diagnostic_remediation_non_empty() {
    let contract = canonical_contract();
    for kind in InternalFailureKind::all() {
        let diag = emit(&contract, *kind, "test");
        assert!(
            !diag.remediation.is_empty(),
            "remediation should not be empty for {kind}"
        );
    }
}

// ---------------------------------------------------------------------------
// Diagnostic event structure
// ---------------------------------------------------------------------------

#[test]
fn diagnostic_event_fields() {
    let contract = canonical_contract();
    let diag = emit(&contract, InternalFailureKind::Cancellation, "cancelled");
    let event = build_diagnostic_event("trace-001", "decision-001", "scenario-001", &diag);

    assert_eq!(event.schema_version, SCHEMA_VERSION);
    assert_eq!(event.trace_id, "trace-001");
    assert_eq!(event.decision_id, "decision-001");
    assert_eq!(event.scenario_id, "scenario-001");
    assert_eq!(event.component, COMPONENT);
    assert_eq!(event.policy_id, POLICY_ID);
    assert_eq!(event.event, "diagnostic_emitted");
    assert_eq!(event.failure_kind, "cancellation");
    assert_eq!(event.severity, "warning");
    assert_eq!(event.next_action, "retry");
    assert!(event.error_code.is_some());
}

#[test]
fn diagnostic_event_for_each_kind() {
    let contract = canonical_contract();
    for kind in InternalFailureKind::all() {
        let diag = emit(&contract, *kind, &format!("test for {kind}"));
        let event = build_diagnostic_event("t", "d", "s", &diag);
        assert_eq!(event.failure_kind, kind.as_str());
        assert_eq!(event.severity, diag.severity.as_str());
        assert_eq!(event.next_action, diag.next_action.as_str());
    }
}

#[test]
fn diagnostic_event_outcome_is_severity() {
    let contract = canonical_contract();
    let diag = emit(&contract, InternalFailureKind::PanicClass, "panic");
    let event = build_diagnostic_event("t", "d", "s", &diag);
    assert_eq!(event.outcome, "fatal");
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn contract_serde_roundtrip() {
    let contract = canonical_contract();
    let json = serde_json::to_string_pretty(&contract).unwrap();
    let parsed: BoundaryPolicyMappingContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, parsed);
    assert!(parsed.verify_integrity());
}

#[test]
fn diagnostic_entry_serde_roundtrip() {
    let contract = canonical_contract();
    let diag = emit_with_refs(
        &contract,
        InternalFailureKind::BudgetExhaustion,
        "budget exhausted",
        "evidence-ref-1",
        "replay-cmd-1",
    );
    let json = serde_json::to_string(&diag).unwrap();
    let parsed: DiagnosticEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, parsed);
}

#[test]
fn diagnostic_event_serde_roundtrip() {
    let contract = canonical_contract();
    let diag = emit(&contract, InternalFailureKind::CapabilityDenial, "denied");
    let event = build_diagnostic_event("trace", "decision", "scenario", &diag);
    let json = serde_json::to_string(&event).unwrap();
    let parsed: DiagnosticEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, parsed);
}

#[test]
fn all_failure_kind_serde_roundtrip() {
    for kind in InternalFailureKind::all() {
        let json = serde_json::to_string(kind).unwrap();
        let parsed: InternalFailureKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, parsed);
    }
}

#[test]
fn severity_serde_roundtrip() {
    for sev in [
        DiagnosticSeverity::Fatal,
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Info,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let parsed: DiagnosticSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, parsed);
    }
}

#[test]
fn user_impact_serde_roundtrip() {
    for impact in [
        UserImpact::OperationFailed,
        UserImpact::DegradedQuality,
        UserImpact::None,
    ] {
        let json = serde_json::to_string(&impact).unwrap();
        let parsed: UserImpact = serde_json::from_str(&json).unwrap();
        assert_eq!(impact, parsed);
    }
}

#[test]
fn operator_impact_serde_roundtrip() {
    for impact in [
        OperatorImpact::ImmediateAction,
        OperatorImpact::TriageRequired,
        OperatorImpact::InformationalOnly,
    ] {
        let json = serde_json::to_string(&impact).unwrap();
        let parsed: OperatorImpact = serde_json::from_str(&json).unwrap();
        assert_eq!(impact, parsed);
    }
}

#[test]
fn next_action_serde_roundtrip() {
    for action in [
        NextAction::Retry,
        NextAction::IncreaseBudget,
        NextAction::GrantCapability,
        NextAction::UpdatePolicy,
        NextAction::UpgradeVersion,
        NextAction::FileBugReport,
        NextAction::NoAction,
        NextAction::InvestigateInfra,
    ] {
        let json = serde_json::to_string(&action).unwrap();
        let parsed: NextAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, parsed);
    }
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn contract_build_deterministic() {
    let c1 = canonical_contract();
    let c2 = canonical_contract();
    assert_eq!(c1.content_hash, c2.content_hash);
    assert_eq!(c1.mappings.len(), c2.mappings.len());
    assert_eq!(c1, c2);
}

#[test]
fn diagnostic_emission_deterministic() {
    let contract = canonical_contract();
    let d1 = emit(&contract, InternalFailureKind::BudgetExhaustion, "test");
    let d2 = emit(&contract, InternalFailureKind::BudgetExhaustion, "test");
    assert_eq!(d1, d2);
}

#[test]
fn event_build_deterministic() {
    let contract = canonical_contract();
    let diag = emit(&contract, InternalFailureKind::Cancellation, "test");
    let e1 = build_diagnostic_event("t", "d", "s", &diag);
    let e2 = build_diagnostic_event("t", "d", "s", &diag);
    assert_eq!(e1, e2);
}

// ---------------------------------------------------------------------------
// Boundary / adversarial
// ---------------------------------------------------------------------------

#[test]
fn empty_message_emits_valid_diagnostic() {
    let contract = canonical_contract();
    let diag = emit(&contract, InternalFailureKind::Unknown, "");
    assert!(diag.message.is_empty());
    assert!(!diag.error_code.is_empty());
}

#[test]
fn long_message_preserved() {
    let contract = canonical_contract();
    let long_msg = "x".repeat(10_000);
    let diag = emit(&contract, InternalFailureKind::PanicClass, &long_msg);
    assert_eq!(diag.message.len(), 10_000);
}

#[test]
fn empty_context_map() {
    let contract = canonical_contract();
    let diag = contract.emit_diagnostic(
        InternalFailureKind::Cancellation,
        "test",
        None,
        None,
        BTreeMap::new(),
    );
    assert!(diag.context.is_empty());
}

#[test]
fn large_context_map() {
    let contract = canonical_contract();
    let mut ctx = BTreeMap::new();
    for i in 0..100 {
        ctx.insert(format!("key_{i}"), format!("value_{i}"));
    }
    let diag = contract.emit_diagnostic(
        InternalFailureKind::BudgetExhaustion,
        "test",
        None,
        None,
        ctx.clone(),
    );
    assert_eq!(diag.context.len(), 100);
}

#[test]
fn different_epochs_same_hash() {
    let c1 = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
    let c2 = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(999));
    // Content hash is over mappings only, not epoch
    assert_eq!(c1.content_hash, c2.content_hash);
}

#[test]
fn description_and_remediation_non_empty_for_all() {
    let contract = canonical_contract();
    for kind in InternalFailureKind::all() {
        let mapping = contract.mapping_for(*kind).unwrap();
        assert!(
            !mapping.description.is_empty(),
            "description empty for {kind}"
        );
        assert!(
            !mapping.remediation.is_empty(),
            "remediation empty for {kind}"
        );
    }
}

// ---------------------------------------------------------------------------
// End-to-end pipeline
// ---------------------------------------------------------------------------

#[test]
fn full_diagnostic_pipeline() {
    // Step 1: Build canonical contract
    let contract = canonical_contract();
    assert!(contract.verify_integrity());

    // Step 2: Emit diagnostic for budget exhaustion
    let ctx = BTreeMap::from([
        ("budget_remaining_ms".to_string(), "5".to_string()),
        ("cell_id".to_string(), "cell-42".to_string()),
    ]);
    let diag = contract.emit_diagnostic(
        InternalFailureKind::BudgetExhaustion,
        "cell close budget exhausted at 5ms remaining",
        Some("evidence-bundle-xyz"),
        Some("frankenctl replay --trace trace-42"),
        ctx,
    );

    // Step 3: Verify diagnostic fields
    assert_eq!(diag.error_code, "FE-BUDGET-001");
    assert_eq!(diag.severity, DiagnosticSeverity::Error);
    assert_eq!(diag.user_impact, UserImpact::OperationFailed);
    assert_eq!(diag.operator_impact, OperatorImpact::TriageRequired);
    assert_eq!(diag.next_action, NextAction::IncreaseBudget);
    assert!(diag.evidence_ref.is_some());
    assert!(diag.replay_ref.is_some());
    assert_eq!(diag.context.len(), 2);

    // Step 4: Build event
    let event = build_diagnostic_event("trace-e2e", "decision-e2e", "pipeline-test", &diag);
    assert_eq!(event.failure_kind, "budget_exhaustion");
    assert_eq!(event.severity, "error");
    assert_eq!(event.next_action, "increase_budget");
    assert!(event.error_code.is_some());
    assert_eq!(event.error_code.as_deref(), Some("FE-BUDGET-001"));

    // Step 5: Serde roundtrip the event
    let json = serde_json::to_string(&event).unwrap();
    let parsed: DiagnosticEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, parsed);
}

#[test]
fn full_diagnostic_pipeline_fatal_path() {
    let contract = canonical_contract();
    let diag = contract.emit_diagnostic(
        InternalFailureKind::PanicClass,
        "interpreter panicked on invalid instruction at pc=42",
        Some("evidence-panic-001"),
        Some("frankenctl replay --trace trace-panic"),
        BTreeMap::from([("pc".to_string(), "42".to_string())]),
    );

    assert_eq!(diag.severity, DiagnosticSeverity::Fatal);
    assert_eq!(diag.operator_impact, OperatorImpact::ImmediateAction);
    assert_eq!(diag.next_action, NextAction::FileBugReport);

    let event = build_diagnostic_event("trace-fatal", "decision-fatal", "panic-scenario", &diag);
    assert_eq!(event.outcome, "fatal");
    assert_eq!(event.failure_kind, "panic_class");
}

#[test]
fn full_diagnostic_pipeline_info_path() {
    let contract = canonical_contract();
    let diag = emit(
        &contract,
        InternalFailureKind::DomainError,
        "user provided invalid config key",
    );

    assert_eq!(diag.severity, DiagnosticSeverity::Info);
    assert_eq!(diag.user_impact, UserImpact::OperationFailed);
    assert_eq!(diag.operator_impact, OperatorImpact::InformationalOnly);
    assert_eq!(diag.next_action, NextAction::NoAction);
    assert!(diag.evidence_ref.is_none());
    assert!(diag.replay_ref.is_none());
}
