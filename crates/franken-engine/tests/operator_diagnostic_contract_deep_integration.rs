//! Deep integration tests for operator_diagnostic_contract module.
//!
//! Covers: failure kind enumeration, error code prefixes, severity ordering,
//! user/operator impact classification, Display impls, serde roundtrips.

use std::collections::BTreeMap;

use frankenengine_engine::operator_diagnostic_contract::{
    BEAD_ID, BoundaryPolicyMappingContract, COMPONENT, DiagnosticEntry, DiagnosticSeverity,
    InternalFailureKind, NextAction, OperatorImpact, POLICY_ID, PolicyMapping, SCHEMA_VERSION,
    UserImpact, build_diagnostic_event,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn deep_constants_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(!POLICY_ID.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(BEAD_ID.starts_with("bd-"));
}

// ---------------------------------------------------------------------------
// InternalFailureKind
// ---------------------------------------------------------------------------

#[test]
fn deep_failure_kind_all_count() {
    assert_eq!(InternalFailureKind::all().len(), 9);
}

#[test]
fn deep_failure_kind_as_str_all() {
    let expected = [
        (InternalFailureKind::Cancellation, "cancellation"),
        (InternalFailureKind::BudgetExhaustion, "budget_exhaustion"),
        (InternalFailureKind::CapabilityDenial, "capability_denial"),
        (InternalFailureKind::PolicyDenial, "policy_denial"),
        (InternalFailureKind::PanicClass, "panic_class"),
        (
            InternalFailureKind::CompatibilityDrift,
            "compatibility_drift",
        ),
        (InternalFailureKind::DomainError, "domain_error"),
        (
            InternalFailureKind::InfrastructureFailure,
            "infrastructure_failure",
        ),
        (InternalFailureKind::Unknown, "unknown"),
    ];
    for (kind, name) in expected {
        assert_eq!(kind.as_str(), name);
        assert_eq!(format!("{kind}"), name);
    }
}

#[test]
fn deep_failure_kind_error_code_prefix_all() {
    let expected_prefixes = [
        (InternalFailureKind::Cancellation, "FE-CANCEL"),
        (InternalFailureKind::BudgetExhaustion, "FE-BUDGET"),
        (InternalFailureKind::CapabilityDenial, "FE-CAPABILITY"),
        (InternalFailureKind::PolicyDenial, "FE-POLICY"),
        (InternalFailureKind::PanicClass, "FE-PANIC"),
        (InternalFailureKind::CompatibilityDrift, "FE-COMPAT"),
        (InternalFailureKind::DomainError, "FE-DOMAIN"),
        (InternalFailureKind::InfrastructureFailure, "FE-INFRA"),
        (InternalFailureKind::Unknown, "FE-UNKNOWN"),
    ];
    for (kind, prefix) in expected_prefixes {
        assert_eq!(kind.error_code_prefix(), prefix);
        assert!(prefix.starts_with("FE-"));
    }
}

#[test]
fn deep_failure_kind_error_code_prefix_unique() {
    let mut prefixes = std::collections::BTreeSet::new();
    for kind in InternalFailureKind::all() {
        assert!(
            prefixes.insert(kind.error_code_prefix()),
            "Duplicate prefix: {}",
            kind.error_code_prefix()
        );
    }
}

#[test]
fn deep_failure_kind_serde_roundtrip() {
    for kind in InternalFailureKind::all() {
        let json = serde_json::to_string(kind).unwrap();
        let decoded: InternalFailureKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, decoded);
    }
}

// ---------------------------------------------------------------------------
// DiagnosticSeverity
// ---------------------------------------------------------------------------

#[test]
fn deep_severity_ordering() {
    assert!(DiagnosticSeverity::Info.weight() < DiagnosticSeverity::Warning.weight());
    assert!(DiagnosticSeverity::Warning.weight() < DiagnosticSeverity::Error.weight());
    assert!(DiagnosticSeverity::Error.weight() < DiagnosticSeverity::Fatal.weight());
}

#[test]
fn deep_severity_as_str_all() {
    assert_eq!(DiagnosticSeverity::Fatal.as_str(), "fatal");
    assert_eq!(DiagnosticSeverity::Error.as_str(), "error");
    assert_eq!(DiagnosticSeverity::Warning.as_str(), "warning");
    assert_eq!(DiagnosticSeverity::Info.as_str(), "info");
}

#[test]
fn deep_severity_display() {
    assert_eq!(format!("{}", DiagnosticSeverity::Fatal), "fatal");
    assert_eq!(format!("{}", DiagnosticSeverity::Error), "error");
    assert_eq!(format!("{}", DiagnosticSeverity::Warning), "warning");
    assert_eq!(format!("{}", DiagnosticSeverity::Info), "info");
}

#[test]
fn deep_severity_serde_roundtrip() {
    let severities = [
        DiagnosticSeverity::Fatal,
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Info,
    ];
    for sev in severities {
        let json = serde_json::to_string(&sev).unwrap();
        let decoded: DiagnosticSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, decoded);
    }
}

// ---------------------------------------------------------------------------
// UserImpact
// ---------------------------------------------------------------------------

#[test]
fn deep_user_impact_as_str() {
    assert_eq!(UserImpact::OperationFailed.as_str(), "operation_failed");
    assert_eq!(UserImpact::DegradedQuality.as_str(), "degraded_quality");
    assert_eq!(UserImpact::None.as_str(), "none");
}

#[test]
fn deep_user_impact_display() {
    assert_eq!(
        format!("{}", UserImpact::OperationFailed),
        "operation_failed"
    );
    assert_eq!(
        format!("{}", UserImpact::DegradedQuality),
        "degraded_quality"
    );
    assert_eq!(format!("{}", UserImpact::None), "none");
}

#[test]
fn deep_user_impact_serde_roundtrip() {
    for impact in [
        UserImpact::OperationFailed,
        UserImpact::DegradedQuality,
        UserImpact::None,
    ] {
        let json = serde_json::to_string(&impact).unwrap();
        let decoded: UserImpact = serde_json::from_str(&json).unwrap();
        assert_eq!(impact, decoded);
    }
}

// ---------------------------------------------------------------------------
// OperatorImpact
// ---------------------------------------------------------------------------

#[test]
fn deep_operator_impact_serde_roundtrip() {
    let impacts = [
        OperatorImpact::ImmediateAction,
        OperatorImpact::TriageRequired,
        OperatorImpact::InformationalOnly,
    ];
    for impact in impacts {
        let json = serde_json::to_string(&impact).unwrap();
        let decoded: OperatorImpact = serde_json::from_str(&json).unwrap();
        assert_eq!(impact, decoded);
    }
}

// ---------------------------------------------------------------------------
// Enrichment: OperatorImpact as_str + Display
// ---------------------------------------------------------------------------

#[test]
fn deep_operator_impact_as_str() {
    assert_eq!(OperatorImpact::ImmediateAction.as_str(), "immediate_action");
    assert_eq!(OperatorImpact::TriageRequired.as_str(), "triage_required");
    assert_eq!(
        OperatorImpact::InformationalOnly.as_str(),
        "informational_only"
    );
}

#[test]
fn deep_operator_impact_display() {
    assert_eq!(
        format!("{}", OperatorImpact::ImmediateAction),
        "immediate_action"
    );
}

// ---------------------------------------------------------------------------
// Enrichment: NextAction
// ---------------------------------------------------------------------------

#[test]
fn deep_next_action_serde_roundtrip() {
    let actions = [
        NextAction::Retry,
        NextAction::IncreaseBudget,
        NextAction::GrantCapability,
        NextAction::UpdatePolicy,
        NextAction::UpgradeVersion,
        NextAction::FileBugReport,
        NextAction::NoAction,
        NextAction::InvestigateInfra,
    ];
    for action in actions {
        let json = serde_json::to_string(&action).unwrap();
        let decoded: NextAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, decoded);
    }
}

#[test]
fn deep_next_action_display_all_distinct() {
    let mut names = std::collections::BTreeSet::new();
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
        assert!(names.insert(format!("{action}")), "Duplicate: {action}");
    }
}

// ---------------------------------------------------------------------------
// Enrichment: PolicyMapping
// ---------------------------------------------------------------------------

#[test]
fn deep_policy_mapping_serde_roundtrip() {
    let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
    let mapping = contract
        .mapping_for(InternalFailureKind::BudgetExhaustion)
        .expect("canonical contract must map BudgetExhaustion");
    let json = serde_json::to_string(mapping).unwrap();
    let decoded: PolicyMapping = serde_json::from_str(&json).unwrap();
    assert_eq!(*mapping, decoded);
}

// ---------------------------------------------------------------------------
// Enrichment: BoundaryPolicyMappingContract
// ---------------------------------------------------------------------------

#[test]
fn deep_canonical_contract_covers_all_kinds() {
    let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
    assert_eq!(
        contract.coverage_count(),
        InternalFailureKind::all().len(),
        "canonical contract must map every failure kind"
    );
}

#[test]
fn deep_canonical_contract_integrity_check() {
    let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
    assert!(
        contract.verify_integrity(),
        "canonical contract must pass integrity check"
    );
}

#[test]
fn deep_canonical_contract_mapping_for_each_kind() {
    let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(5));
    for kind in InternalFailureKind::all() {
        let mapping = contract.mapping_for(*kind);
        assert!(
            mapping.is_some(),
            "canonical contract must have a mapping for {kind}"
        );
        let m = mapping.unwrap();
        assert_eq!(m.failure_kind, *kind);
        assert!(m.error_code.starts_with(kind.error_code_prefix()));
    }
}

#[test]
fn deep_canonical_contract_serde_roundtrip() {
    let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(2));
    let json = serde_json::to_string(&contract).unwrap();
    let decoded: BoundaryPolicyMappingContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, decoded);
}

// ---------------------------------------------------------------------------
// Enrichment: emit_diagnostic
// ---------------------------------------------------------------------------

#[test]
fn deep_emit_diagnostic_produces_entry() {
    let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
    let entry = contract.emit_diagnostic(
        InternalFailureKind::Cancellation,
        "operation timed out",
        Some("evidence-ref-001"),
        Some("frankenctl replay run --trace ./artifacts/t.json --mode strict"),
        BTreeMap::new(),
    );
    assert_eq!(entry.failure_kind, InternalFailureKind::Cancellation);
    assert_eq!(entry.severity, DiagnosticSeverity::Warning);
    assert!(entry.message.contains("timed out"));
    assert_eq!(entry.evidence_ref.as_deref(), Some("evidence-ref-001"));
    assert!(entry.replay_ref.as_deref().unwrap().contains("replay run"));
}

#[test]
fn deep_emit_diagnostic_fatal_kind() {
    let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
    let entry = contract.emit_diagnostic(
        InternalFailureKind::PanicClass,
        "interpreter panicked",
        Some("panic-evidence"),
        Some("frankenctl replay run --trace ./artifacts/panic.json --mode strict"),
        BTreeMap::new(),
    );
    assert_eq!(entry.severity, DiagnosticSeverity::Fatal);
    assert_eq!(entry.operator_impact, OperatorImpact::ImmediateAction);
}

#[test]
fn deep_diagnostic_entry_serde_roundtrip() {
    let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
    let entry = contract.emit_diagnostic(
        InternalFailureKind::DomainError,
        "test error",
        Some("ev-serde"),
        Some("replay cmd"),
        BTreeMap::new(),
    );
    let json = serde_json::to_string(&entry).unwrap();
    let decoded: DiagnosticEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, decoded);
}

// ---------------------------------------------------------------------------
// Enrichment: build_diagnostic_event
// ---------------------------------------------------------------------------

#[test]
fn deep_build_diagnostic_event_has_required_fields() {
    let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
    let entry = contract.emit_diagnostic(
        InternalFailureKind::CapabilityDenial,
        "denied",
        Some("evidence-001"),
        Some("frankenctl replay run --trace ./artifacts/t.json --mode strict"),
        BTreeMap::new(),
    );
    let event = build_diagnostic_event("trace-001", "decision-001", "scenario-001", &entry);
    assert_eq!(event.trace_id, "trace-001");
    assert_eq!(event.decision_id, "decision-001");
    assert_eq!(event.component, COMPONENT);
    assert!(!event.event.is_empty());
}

#[test]
fn deep_build_diagnostic_event_serde_roundtrip() {
    let contract = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
    let entry = contract.emit_diagnostic(
        InternalFailureKind::Unknown,
        "unknown failure",
        Some("ev-serde"),
        Some("replay cmd"),
        BTreeMap::new(),
    );
    let event = build_diagnostic_event("trace-serde", "decision-serde", "scenario-serde", &entry);
    let json = serde_json::to_string(&event).unwrap();
    let decoded = serde_json::from_str::<serde_json::Value>(&json).unwrap();
    assert_eq!(decoded["trace_id"], "trace-serde");
    assert_eq!(decoded["component"], COMPONENT);
}
