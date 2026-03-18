//! Deep integration tests for operator_diagnostic_contract module.
//!
//! Covers: failure kind enumeration, error code prefixes, severity ordering,
//! user/operator impact classification, Display impls, serde roundtrips.

use frankenengine_engine::operator_diagnostic_contract::{
    DiagnosticSeverity, InternalFailureKind, OperatorImpact, UserImpact,
    BEAD_ID, COMPONENT, POLICY_ID, SCHEMA_VERSION,
};

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
        (InternalFailureKind::CompatibilityDrift, "compatibility_drift"),
        (InternalFailureKind::DomainError, "domain_error"),
        (InternalFailureKind::InfrastructureFailure, "infrastructure_failure"),
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
    assert_eq!(format!("{}", UserImpact::OperationFailed), "operation_failed");
    assert_eq!(format!("{}", UserImpact::DegradedQuality), "degraded_quality");
    assert_eq!(format!("{}", UserImpact::None), "none");
}

#[test]
fn deep_user_impact_serde_roundtrip() {
    for impact in [UserImpact::OperationFailed, UserImpact::DegradedQuality, UserImpact::None] {
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
