//! Enrichment integration tests for the `operator_diagnostic_contract` module.
//!
//! Covers: enum serde roundtrips with JSON structure validation, Display
//! uniqueness across all enum families, struct construction edge cases,
//! diagnostic lifecycle and pipeline flows, severity arithmetic and weight
//! invariants, content hash determinism under mutation, context propagation
//! boundary conditions, and cross-enum consistency guarantees.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use frankenengine_engine::operator_diagnostic_contract::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_contract() -> BoundaryPolicyMappingContract {
    BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1))
}

fn emit_simple(kind: InternalFailureKind) -> DiagnosticEntry {
    let contract = make_contract();
    contract.emit_diagnostic(kind, "enrichment test", None, None, BTreeMap::new())
}

// ---------------------------------------------------------------------------
// Enum serde roundtrips -- JSON token shape validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_failure_kind_json_is_snake_case_string() {
    for kind in InternalFailureKind::all() {
        let json = serde_json::to_string(kind).unwrap();
        // JSON value must be a quoted string (not a number or object)
        assert!(
            json.starts_with('"') && json.ends_with('"'),
            "expected quoted string for {kind:?}, got {json}"
        );
        // The inner value must match as_str exactly
        let inner = &json[1..json.len() - 1];
        assert_eq!(inner, kind.as_str(), "serde output mismatch for {kind:?}");
    }
}

#[test]
fn enrichment_serde_severity_json_is_snake_case_string() {
    let severities = [
        DiagnosticSeverity::Fatal,
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Info,
    ];
    for sev in severities {
        let json = serde_json::to_string(&sev).unwrap();
        let inner = &json[1..json.len() - 1];
        assert_eq!(inner, sev.as_str());
    }
}

#[test]
fn enrichment_serde_user_impact_json_matches_as_str() {
    for impact in [
        UserImpact::OperationFailed,
        UserImpact::DegradedQuality,
        UserImpact::None,
    ] {
        let json = serde_json::to_string(&impact).unwrap();
        let roundtrip: UserImpact = serde_json::from_str(&json).unwrap();
        assert_eq!(impact, roundtrip);
        let inner = &json[1..json.len() - 1];
        assert_eq!(inner, impact.as_str());
    }
}

#[test]
fn enrichment_serde_operator_impact_json_matches_as_str() {
    for impact in [
        OperatorImpact::ImmediateAction,
        OperatorImpact::TriageRequired,
        OperatorImpact::InformationalOnly,
    ] {
        let json = serde_json::to_string(&impact).unwrap();
        let inner = &json[1..json.len() - 1];
        assert_eq!(inner, impact.as_str());
    }
}

#[test]
fn enrichment_serde_next_action_json_matches_as_str() {
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
        let inner = &json[1..json.len() - 1];
        assert_eq!(inner, action.as_str());
    }
}

// ---------------------------------------------------------------------------
// Display uniqueness across all enum families
// ---------------------------------------------------------------------------

#[test]
fn enrichment_display_failure_kind_all_unique() {
    let mut seen = BTreeSet::new();
    for kind in InternalFailureKind::all() {
        let display = kind.to_string();
        assert!(
            seen.insert(display.clone()),
            "duplicate Display value for InternalFailureKind: {display}"
        );
    }
    assert_eq!(seen.len(), 9);
}

#[test]
fn enrichment_display_severity_all_unique() {
    let mut seen = BTreeSet::new();
    for sev in [
        DiagnosticSeverity::Fatal,
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Info,
    ] {
        assert!(seen.insert(sev.to_string()));
    }
    assert_eq!(seen.len(), 4);
}

#[test]
fn enrichment_display_user_impact_all_unique() {
    let mut seen = BTreeSet::new();
    for impact in [
        UserImpact::OperationFailed,
        UserImpact::DegradedQuality,
        UserImpact::None,
    ] {
        assert!(seen.insert(impact.to_string()));
    }
    assert_eq!(seen.len(), 3);
}

#[test]
fn enrichment_display_operator_impact_all_unique() {
    let mut seen = BTreeSet::new();
    for impact in [
        OperatorImpact::ImmediateAction,
        OperatorImpact::TriageRequired,
        OperatorImpact::InformationalOnly,
    ] {
        assert!(seen.insert(impact.to_string()));
    }
    assert_eq!(seen.len(), 3);
}

#[test]
fn enrichment_display_next_action_all_unique() {
    let mut seen = BTreeSet::new();
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
        assert!(seen.insert(action.to_string()));
    }
    assert_eq!(seen.len(), 8);
}

// ---------------------------------------------------------------------------
// Struct construction and field consistency
// ---------------------------------------------------------------------------

#[test]
fn enrichment_construction_policy_mapping_fields_preserved() {
    let mapping = PolicyMapping {
        failure_kind: InternalFailureKind::PanicClass,
        error_code: "FE-PANIC-TEST".to_string(),
        severity: DiagnosticSeverity::Fatal,
        user_impact: UserImpact::OperationFailed,
        operator_impact: OperatorImpact::ImmediateAction,
        next_action: NextAction::FileBugReport,
        description: "test description".to_string(),
        remediation: "test remediation".to_string(),
        has_evidence_ref: true,
        has_replay_ref: false,
    };
    assert_eq!(mapping.failure_kind, InternalFailureKind::PanicClass);
    assert_eq!(mapping.error_code, "FE-PANIC-TEST");
    assert!(mapping.has_evidence_ref);
    assert!(!mapping.has_replay_ref);

    let json = serde_json::to_string(&mapping).unwrap();
    let roundtrip: PolicyMapping = serde_json::from_str(&json).unwrap();
    assert_eq!(mapping, roundtrip);
}

#[test]
fn enrichment_construction_diagnostic_entry_with_all_optional_fields() {
    let entry = DiagnosticEntry {
        error_code: "FE-TEST-001".to_string(),
        failure_kind: InternalFailureKind::Unknown,
        severity: DiagnosticSeverity::Error,
        user_impact: UserImpact::OperationFailed,
        operator_impact: OperatorImpact::TriageRequired,
        next_action: NextAction::FileBugReport,
        message: "manually constructed entry".to_string(),
        remediation: "file a bug".to_string(),
        evidence_ref: Some("ev-manual".to_string()),
        replay_ref: Some("replay-manual".to_string()),
        context: BTreeMap::from([("source".to_string(), "enrichment_test".to_string())]),
    };
    assert_eq!(entry.evidence_ref.as_deref(), Some("ev-manual"));
    assert_eq!(entry.replay_ref.as_deref(), Some("replay-manual"));
    assert_eq!(entry.context.len(), 1);
}

#[test]
fn enrichment_construction_diagnostic_entry_no_optional_fields() {
    let entry = DiagnosticEntry {
        error_code: "FE-EMPTY-001".to_string(),
        failure_kind: InternalFailureKind::DomainError,
        severity: DiagnosticSeverity::Info,
        user_impact: UserImpact::None,
        operator_impact: OperatorImpact::InformationalOnly,
        next_action: NextAction::NoAction,
        message: String::new(),
        remediation: String::new(),
        evidence_ref: None,
        replay_ref: None,
        context: BTreeMap::new(),
    };
    assert!(entry.evidence_ref.is_none());
    assert!(entry.replay_ref.is_none());
    assert!(entry.context.is_empty());
    assert!(entry.message.is_empty());
}

// ---------------------------------------------------------------------------
// Lifecycle: emit -> event -> serde -> verify chain
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_emit_event_serde_chain_for_all_kinds() {
    let contract = make_contract();
    for kind in InternalFailureKind::all() {
        let diag = contract.emit_diagnostic(
            *kind,
            &format!("lifecycle test for {kind}"),
            Some("ev-lifecycle"),
            Some("replay-lifecycle"),
            BTreeMap::from([("kind".to_string(), kind.as_str().to_string())]),
        );
        let event = build_diagnostic_event("trace-lifecycle", "decision-lc", "scenario-lc", &diag);

        // Serde roundtrip on both entry and event
        let diag_json = serde_json::to_string(&diag).unwrap();
        let diag_rt: DiagnosticEntry = serde_json::from_str(&diag_json).unwrap();
        assert_eq!(diag, diag_rt);

        let event_json = serde_json::to_string(&event).unwrap();
        let event_rt: DiagnosticEvent = serde_json::from_str(&event_json).unwrap();
        assert_eq!(event, event_rt);

        // Cross-check consistency
        assert_eq!(event.failure_kind, kind.as_str());
        assert_eq!(event.severity, diag.severity.as_str());
        assert_eq!(event.next_action, diag.next_action.as_str());
        assert_eq!(event.error_code.as_deref(), Some(diag.error_code.as_str()));
    }
}

#[test]
fn enrichment_lifecycle_contract_serde_preserves_integrity() {
    let contract = make_contract();
    assert!(contract.verify_integrity());

    let json = serde_json::to_string_pretty(&contract).unwrap();
    let parsed: BoundaryPolicyMappingContract = serde_json::from_str(&json).unwrap();
    assert!(parsed.verify_integrity());
    assert_eq!(contract.content_hash, parsed.content_hash);
}

// ---------------------------------------------------------------------------
// Severity arithmetic and weight invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_arithmetic_severity_weights_are_contiguous() {
    let weights: Vec<u32> = [
        DiagnosticSeverity::Info,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Fatal,
    ]
    .iter()
    .map(|s| s.weight())
    .collect();
    for window in weights.windows(2) {
        assert_eq!(
            window[1] - window[0],
            1,
            "severity weights should increase by 1"
        );
    }
}

#[test]
fn enrichment_arithmetic_severity_weight_range() {
    let min = DiagnosticSeverity::Info.weight();
    let max = DiagnosticSeverity::Fatal.weight();
    assert_eq!(min, 1);
    assert_eq!(max, 4);
    assert_eq!(max - min, 3);
}

#[test]
fn enrichment_arithmetic_severity_weight_unique() {
    let mut weights = BTreeSet::new();
    for sev in [
        DiagnosticSeverity::Fatal,
        DiagnosticSeverity::Error,
        DiagnosticSeverity::Warning,
        DiagnosticSeverity::Info,
    ] {
        assert!(weights.insert(sev.weight()), "duplicate weight for {sev}");
    }
    assert_eq!(weights.len(), 4);
}

// ---------------------------------------------------------------------------
// Content hash determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_determinism_content_hash_stable_across_builds() {
    let c1 = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
    let c2 = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
    let c3 = BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(1));
    assert_eq!(c1.content_hash, c2.content_hash);
    assert_eq!(c2.content_hash, c3.content_hash);
}

#[test]
fn enrichment_determinism_content_hash_epoch_independent() {
    let hashes: Vec<_> = (0..10)
        .map(|i| BoundaryPolicyMappingContract::canonical(SecurityEpoch::from_raw(i)).content_hash)
        .collect();
    for h in &hashes[1..] {
        assert_eq!(hashes[0], *h);
    }
}

#[test]
fn enrichment_determinism_mapping_order_is_btreemap_sorted() {
    let contract = make_contract();
    let keys: Vec<&String> = contract.mappings.keys().collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "mappings should be in BTreeMap sorted order");
}

#[test]
fn enrichment_determinism_diagnostic_emission_idempotent() {
    let contract = make_contract();
    let ctx = BTreeMap::from([("k".to_string(), "v".to_string())]);
    let d1 = contract.emit_diagnostic(
        InternalFailureKind::CapabilityDenial,
        "test",
        Some("ev"),
        Some("rp"),
        ctx.clone(),
    );
    let d2 = contract.emit_diagnostic(
        InternalFailureKind::CapabilityDenial,
        "test",
        Some("ev"),
        Some("rp"),
        ctx,
    );
    assert_eq!(d1, d2);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_edge_unicode_message_preserved() {
    let contract = make_contract();
    let msg = "Budget exhausted: \u{1F525} flambe \u{00E9}v\u{00E8}nement \u{4E16}\u{754C}";
    let diag = contract.emit_diagnostic(
        InternalFailureKind::BudgetExhaustion,
        msg,
        None,
        None,
        BTreeMap::new(),
    );
    assert_eq!(diag.message, msg);

    let json = serde_json::to_string(&diag).unwrap();
    let rt: DiagnosticEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(rt.message, msg);
}

#[test]
fn enrichment_edge_unicode_context_keys_and_values() {
    let contract = make_contract();
    let ctx = BTreeMap::from([
        ("\u{00FC}bung".to_string(), "re\u{00E7}u".to_string()),
        (
            "\u{65E5}\u{672C}\u{8A9E}".to_string(),
            "\u{5024}".to_string(),
        ),
    ]);
    let diag = contract.emit_diagnostic(
        InternalFailureKind::DomainError,
        "unicode context",
        None,
        None,
        ctx.clone(),
    );
    assert_eq!(diag.context, ctx);
}

#[test]
fn enrichment_edge_evidence_ref_empty_string_vs_none() {
    let contract = make_contract();
    let diag_none = contract.emit_diagnostic(
        InternalFailureKind::Cancellation,
        "test",
        None,
        None,
        BTreeMap::new(),
    );
    let diag_empty = contract.emit_diagnostic(
        InternalFailureKind::Cancellation,
        "test",
        Some(""),
        Some(""),
        BTreeMap::new(),
    );
    assert!(diag_none.evidence_ref.is_none());
    assert_eq!(diag_empty.evidence_ref.as_deref(), Some(""));
    assert_ne!(diag_none, diag_empty);
}

#[test]
fn enrichment_edge_mapping_for_returns_none_on_empty_contract() {
    let mut contract = make_contract();
    contract.mappings.clear();
    contract.content_hash = frankenengine_engine::hash_tiers::ContentHash::compute(b"empty");
    for kind in InternalFailureKind::all() {
        assert!(contract.mapping_for(*kind).is_none());
    }
    assert_eq!(contract.coverage_count(), 0);
    assert_eq!(contract.evidence_linked_count(), 0);
}

#[test]
fn enrichment_edge_emit_unmapped_failure_kind_fallback() {
    let mut contract = make_contract();
    contract.mappings.clear();
    let diag = contract.emit_diagnostic(
        InternalFailureKind::PanicClass,
        "unmapped panic",
        Some("ev-unmapped"),
        None,
        BTreeMap::new(),
    );
    assert!(
        diag.error_code.contains("UNMAPPED"),
        "unmapped failure should produce UNMAPPED error code, got: {}",
        diag.error_code
    );
    assert_eq!(diag.severity, DiagnosticSeverity::Error);
    assert_eq!(diag.next_action, NextAction::FileBugReport);
    assert_eq!(diag.operator_impact, OperatorImpact::TriageRequired);
    assert_eq!(diag.user_impact, UserImpact::OperationFailed);
    assert!(diag.remediation.contains("bug report"));
}

#[test]
fn enrichment_edge_unmapped_error_code_uses_prefix() {
    let mut contract = make_contract();
    contract.mappings.clear();
    for kind in InternalFailureKind::all() {
        let diag = contract.emit_diagnostic(*kind, "test", None, None, BTreeMap::new());
        let expected_prefix = format!("{}-UNMAPPED", kind.error_code_prefix());
        assert_eq!(
            diag.error_code, expected_prefix,
            "unmapped error code mismatch for {kind}"
        );
    }
}

#[test]
fn enrichment_edge_verify_integrity_false_after_insertion() {
    let mut contract = make_contract();
    assert!(contract.verify_integrity());
    contract.mappings.insert(
        "custom_kind".to_string(),
        PolicyMapping {
            failure_kind: InternalFailureKind::Unknown,
            error_code: "FE-CUSTOM-001".to_string(),
            severity: DiagnosticSeverity::Warning,
            user_impact: UserImpact::None,
            operator_impact: OperatorImpact::InformationalOnly,
            next_action: NextAction::NoAction,
            description: "custom".to_string(),
            remediation: "custom".to_string(),
            has_evidence_ref: false,
            has_replay_ref: false,
        },
    );
    assert!(
        !contract.verify_integrity(),
        "integrity should fail after mapping insertion"
    );
}

#[test]
fn enrichment_edge_verify_integrity_false_after_removal() {
    let mut contract = make_contract();
    assert!(contract.verify_integrity());
    contract.mappings.remove("cancellation");
    assert!(
        !contract.verify_integrity(),
        "integrity should fail after mapping removal"
    );
}

// ---------------------------------------------------------------------------
// Cross-enum consistency: mapping severity vs. operator impact
// ---------------------------------------------------------------------------

#[test]
fn enrichment_consistency_fatal_implies_immediate_action() {
    let contract = make_contract();
    for kind in InternalFailureKind::all() {
        let mapping = contract.mapping_for(*kind).unwrap();
        if mapping.severity == DiagnosticSeverity::Fatal {
            assert_eq!(
                mapping.operator_impact,
                OperatorImpact::ImmediateAction,
                "fatal severity should imply immediate action for {kind}"
            );
        }
    }
}

#[test]
fn enrichment_consistency_info_severity_never_immediate_action() {
    let contract = make_contract();
    for kind in InternalFailureKind::all() {
        let mapping = contract.mapping_for(*kind).unwrap();
        if mapping.severity == DiagnosticSeverity::Info {
            assert_ne!(
                mapping.operator_impact,
                OperatorImpact::ImmediateAction,
                "info severity should not require immediate action for {kind}"
            );
        }
    }
}

#[test]
fn enrichment_consistency_error_code_contains_kind_token() {
    let contract = make_contract();
    for kind in InternalFailureKind::all() {
        let mapping = contract.mapping_for(*kind).unwrap();
        let prefix = kind.error_code_prefix();
        assert!(
            mapping.error_code.starts_with(prefix),
            "error code '{}' must start with prefix '{}' for {kind}",
            mapping.error_code,
            prefix
        );
    }
}

// ---------------------------------------------------------------------------
// Event structure edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_event_seed_is_stable() {
    for kind in InternalFailureKind::all() {
        let diag = emit_simple(*kind);
        let event = build_diagnostic_event("t", "d", "s", &diag);
        assert_eq!(event.seed, "operator-diagnostic-contract-v1");
    }
}

#[test]
fn enrichment_event_outcome_matches_severity_str() {
    let contract = make_contract();
    for kind in InternalFailureKind::all() {
        let diag = contract.emit_diagnostic(*kind, "test", None, None, BTreeMap::new());
        let event = build_diagnostic_event("t", "d", "s", &diag);
        assert_eq!(
            event.outcome,
            diag.severity.as_str(),
            "event outcome should match severity as_str for {kind}"
        );
    }
}

#[test]
fn enrichment_event_error_code_always_some() {
    for kind in InternalFailureKind::all() {
        let diag = emit_simple(*kind);
        let event = build_diagnostic_event("t", "d", "s", &diag);
        assert!(
            event.error_code.is_some(),
            "event error_code should always be Some for {kind}"
        );
    }
}

// ---------------------------------------------------------------------------
// Constants validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_schema_version_contains_version_marker() {
    assert!(
        SCHEMA_VERSION.contains(".v"),
        "schema version should contain a version marker like '.v1'"
    );
}

#[test]
fn enrichment_constants_bead_id_format() {
    assert!(BEAD_ID.starts_with("bd-"), "bead ID must start with bd-");
    assert!(
        BEAD_ID.len() > 3,
        "bead ID must have content after the bd- prefix"
    );
}

#[test]
fn enrichment_constants_policy_id_nonempty() {
    assert!(!POLICY_ID.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(
        COMPONENT
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "component should be a valid Rust identifier-like string"
    );
}

// ---------------------------------------------------------------------------
// Contract coverage and evidence counting
// ---------------------------------------------------------------------------

#[test]
fn enrichment_coverage_canonical_covers_exactly_nine() {
    let contract = make_contract();
    assert_eq!(contract.coverage_count(), 9);
    assert_eq!(contract.coverage_count(), InternalFailureKind::all().len());
}

#[test]
fn enrichment_coverage_evidence_linked_is_subset() {
    let contract = make_contract();
    let evidence_count = contract.evidence_linked_count();
    let total = contract.coverage_count();
    assert!(evidence_count > 0);
    assert!(evidence_count <= total);
    // Domain error has no evidence, so count must be strictly less than total
    assert!(
        evidence_count < total,
        "at least DomainError lacks evidence, so count should be < total"
    );
}
