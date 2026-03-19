// Enrichment integration tests for hindsight_trace_escalator module.
//
// Covers: EscalationLevel depth values (0-3), Display uniqueness, ordering,
// serde, TriggerCategory Display uniqueness (8 variants), serde,
// TriggerSeverity minimum_escalation, EscalationTrigger construction/hashing,
// BundleArtifactSpec, EscalationPolicy resolve_level/artifacts/estimate,
// EscalationVerdict display/serde, HindsightTraceEscalator evaluate/suppress/
// cooldown/advance_epoch/complete/summary, SupportBundleManifest, constants,
// and determinism checks.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::hindsight_trace_escalator::{
    BundleArtifactSpec, ESCALATION_BEAD_ID, ESCALATION_SCHEMA_VERSION, EscalationDecision,
    EscalationLevel, EscalationPolicy, EscalationTrigger, EscalationVerdict, EscalatorState,
    EscalatorSummary, HindsightTraceEscalator, SupportBundleArtifact, SupportBundleManifest,
    TriggerCategory, TriggerSeverity, standard_artifact_specs,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn test_trigger(category: TriggerCategory, severity: TriggerSeverity) -> EscalationTrigger {
    EscalationTrigger::new(
        "trigger-001",
        category,
        severity,
        "test trigger",
        "test_component",
        ep(100),
    )
}

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn enrichment_schema_version_non_empty() {
    assert!(!ESCALATION_SCHEMA_VERSION.is_empty());
    assert!(ESCALATION_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn enrichment_bead_id_starts_with_bd() {
    assert!(ESCALATION_BEAD_ID.starts_with("bd-"));
}

// ===========================================================================
// EscalationLevel
// ===========================================================================

#[test]
fn enrichment_escalation_level_depth_values() {
    assert_eq!(EscalationLevel::Minimal.depth(), 0);
    assert_eq!(EscalationLevel::Extended.depth(), 1);
    assert_eq!(EscalationLevel::Full.depth(), 2);
    assert_eq!(EscalationLevel::Forensic.depth(), 3);
}

#[test]
fn enrichment_escalation_level_ordering() {
    assert!(EscalationLevel::Minimal < EscalationLevel::Extended);
    assert!(EscalationLevel::Extended < EscalationLevel::Full);
    assert!(EscalationLevel::Full < EscalationLevel::Forensic);
}

#[test]
fn enrichment_escalation_level_display_values() {
    assert_eq!(EscalationLevel::Minimal.to_string(), "minimal");
    assert_eq!(EscalationLevel::Extended.to_string(), "extended");
    assert_eq!(EscalationLevel::Full.to_string(), "full");
    assert_eq!(EscalationLevel::Forensic.to_string(), "forensic");
}

#[test]
fn enrichment_escalation_level_display_unique() {
    let labels: BTreeSet<String> = [
        EscalationLevel::Minimal, EscalationLevel::Extended,
        EscalationLevel::Full, EscalationLevel::Forensic,
    ].iter().map(|l| format!("{l}")).collect();
    assert_eq!(labels.len(), 4);
}

#[test]
fn enrichment_escalation_level_serde_roundtrip() {
    for level in [
        EscalationLevel::Minimal, EscalationLevel::Extended,
        EscalationLevel::Full, EscalationLevel::Forensic,
    ] {
        let json = serde_json::to_string(&level).unwrap();
        let back: EscalationLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(level, back);
    }
}

// ===========================================================================
// TriggerCategory
// ===========================================================================

#[test]
fn enrichment_trigger_category_display_all_unique() {
    let categories = [
        TriggerCategory::PerformanceAnomaly,
        TriggerCategory::SecurityEvent,
        TriggerCategory::CorrectnessFailure,
        TriggerCategory::UserVisibleError,
        TriggerCategory::Regression,
        TriggerCategory::OperatorRequest,
        TriggerCategory::ResourceExhaustion,
        TriggerCategory::DeterminismViolation,
    ];
    let labels: BTreeSet<String> = categories.iter().map(|c| format!("{c}")).collect();
    assert_eq!(labels.len(), 8);
}

#[test]
fn enrichment_trigger_category_serde_roundtrip_all() {
    for c in [
        TriggerCategory::PerformanceAnomaly,
        TriggerCategory::SecurityEvent,
        TriggerCategory::CorrectnessFailure,
        TriggerCategory::UserVisibleError,
        TriggerCategory::Regression,
        TriggerCategory::OperatorRequest,
        TriggerCategory::ResourceExhaustion,
        TriggerCategory::DeterminismViolation,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let back: TriggerCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}

// ===========================================================================
// TriggerSeverity
// ===========================================================================

#[test]
fn enrichment_trigger_severity_minimum_escalation() {
    assert_eq!(TriggerSeverity::Info.minimum_escalation(), EscalationLevel::Extended);
    assert_eq!(TriggerSeverity::Warning.minimum_escalation(), EscalationLevel::Extended);
    assert_eq!(TriggerSeverity::Critical.minimum_escalation(), EscalationLevel::Full);
    assert_eq!(TriggerSeverity::Fatal.minimum_escalation(), EscalationLevel::Forensic);
}

#[test]
fn enrichment_trigger_severity_serde_roundtrip() {
    for s in [TriggerSeverity::Info, TriggerSeverity::Warning, TriggerSeverity::Critical, TriggerSeverity::Fatal] {
        let json = serde_json::to_string(&s).unwrap();
        let back: TriggerSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn enrichment_trigger_severity_display_values() {
    assert_eq!(TriggerSeverity::Info.to_string(), "info");
    assert_eq!(TriggerSeverity::Warning.to_string(), "warning");
    assert_eq!(TriggerSeverity::Critical.to_string(), "critical");
    assert_eq!(TriggerSeverity::Fatal.to_string(), "fatal");
}

// ===========================================================================
// EscalationTrigger
// ===========================================================================

#[test]
fn enrichment_trigger_construction() {
    let t = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
    assert_eq!(t.trigger_id, "trigger-001");
    assert_eq!(t.category, TriggerCategory::Regression);
    assert_eq!(t.severity, TriggerSeverity::Warning);
    assert!(t.correlation_id.is_none());
    assert!(t.metadata.is_empty());
}

#[test]
fn enrichment_trigger_content_hash_deterministic() {
    let t1 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
    let t2 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
    assert_eq!(t1.content_hash(), t2.content_hash());
}

#[test]
fn enrichment_trigger_content_hash_differs_by_category() {
    let t1 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
    let t2 = test_trigger(TriggerCategory::SecurityEvent, TriggerSeverity::Warning);
    assert_ne!(t1.content_hash(), t2.content_hash());
}

#[test]
fn enrichment_trigger_serde_roundtrip() {
    let t = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
    let json = serde_json::to_string(&t).unwrap();
    let back: EscalationTrigger = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

// ===========================================================================
// BundleArtifactSpec / standard_artifact_specs
// ===========================================================================

#[test]
fn enrichment_standard_specs_cover_all_levels() {
    let specs = standard_artifact_specs();
    let levels: BTreeSet<_> = specs.iter().map(|s| s.min_level).collect();
    assert!(levels.contains(&EscalationLevel::Minimal));
    assert!(levels.contains(&EscalationLevel::Extended));
    assert!(levels.contains(&EscalationLevel::Full));
    assert!(levels.contains(&EscalationLevel::Forensic));
}

#[test]
fn enrichment_standard_specs_non_empty_labels() {
    for spec in standard_artifact_specs() {
        assert!(!spec.label.is_empty());
        assert!(!spec.format.is_empty());
    }
}

#[test]
fn enrichment_bundle_artifact_spec_serde_roundtrip() {
    let spec = BundleArtifactSpec {
        label: "test_artifact".into(),
        format: "json".into(),
        min_level: EscalationLevel::Extended,
        required: true,
        estimated_bytes: 4096,
    };
    let json = serde_json::to_string(&spec).unwrap();
    let back: BundleArtifactSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, back);
}

// ===========================================================================
// EscalationPolicy
// ===========================================================================

#[test]
fn enrichment_policy_default_values() {
    let p = EscalationPolicy::default();
    assert_eq!(p.default_level, EscalationLevel::Minimal);
    assert!(!p.allow_forensic);
    assert!(p.max_active_escalations > 0);
    assert!(p.cooldown_epochs > 0);
}

#[test]
fn enrichment_policy_resolve_level_severity_precedence() {
    let p = EscalationPolicy::default();
    let t = test_trigger(TriggerCategory::Regression, TriggerSeverity::Critical);
    assert_eq!(p.resolve_level(&t), EscalationLevel::Full);
}

#[test]
fn enrichment_policy_resolve_level_clamps_forensic() {
    let p = EscalationPolicy { allow_forensic: false, ..Default::default() };
    let t = test_trigger(TriggerCategory::SecurityEvent, TriggerSeverity::Fatal);
    assert_eq!(p.resolve_level(&t), EscalationLevel::Full);
}

#[test]
fn enrichment_policy_artifacts_for_level_monotonic() {
    let p = EscalationPolicy::default();
    let minimal = p.artifacts_for_level(EscalationLevel::Minimal).len();
    let extended = p.artifacts_for_level(EscalationLevel::Extended).len();
    let full = p.artifacts_for_level(EscalationLevel::Full).len();
    let forensic = p.artifacts_for_level(EscalationLevel::Forensic).len();
    assert!(minimal <= extended);
    assert!(extended <= full);
    assert!(full <= forensic);
}

#[test]
fn enrichment_policy_estimate_bundle_size_increases() {
    let p = EscalationPolicy::default();
    let minimal = p.estimate_bundle_size(EscalationLevel::Minimal);
    let full = p.estimate_bundle_size(EscalationLevel::Full);
    assert!(minimal < full);
    assert!(minimal > 0);
}

#[test]
fn enrichment_policy_content_hash_deterministic() {
    let p1 = EscalationPolicy::default();
    let p2 = EscalationPolicy::default();
    assert_eq!(p1.content_hash(), p2.content_hash());
}

#[test]
fn enrichment_policy_serde_roundtrip() {
    let p = EscalationPolicy::default();
    let json = serde_json::to_string(&p).unwrap();
    let back: EscalationPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ===========================================================================
// EscalationVerdict
// ===========================================================================

#[test]
fn enrichment_verdict_display_approved() {
    let v = EscalationVerdict::Approved { level: EscalationLevel::Full };
    let s = format!("{v}");
    assert!(s.contains("approved"));
    assert!(s.contains("full"));
}

#[test]
fn enrichment_verdict_display_suppressed_capacity() {
    let v = EscalationVerdict::SuppressedCapacity { active_count: 5, max_allowed: 5 };
    let s = format!("{v}");
    assert!(s.contains("suppressed_capacity"));
}

#[test]
fn enrichment_verdict_serde_roundtrip_approved() {
    let v = EscalationVerdict::Approved { level: EscalationLevel::Extended };
    let json = serde_json::to_string(&v).unwrap();
    let back: EscalationVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_verdict_serde_roundtrip_suppressed() {
    let v = EscalationVerdict::SuppressedCapacity { active_count: 10, max_allowed: 10 };
    let json = serde_json::to_string(&v).unwrap();
    let back: EscalationVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ===========================================================================
// HindsightTraceEscalator
// ===========================================================================

#[test]
fn enrichment_escalator_approve_basic() {
    let mut esc = HindsightTraceEscalator::new(EscalationPolicy::default(), ep(100));
    let t = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
    let d = esc.evaluate(t);
    assert!(matches!(d.verdict, EscalationVerdict::Approved { .. }));
    assert_eq!(esc.state.total_approved, 1);
    assert_eq!(esc.state.active_escalations, 1);
}

#[test]
fn enrichment_escalator_suppress_capacity() {
    let policy = EscalationPolicy { max_active_escalations: 1, ..Default::default() };
    let mut esc = HindsightTraceEscalator::new(policy, ep(100));
    let t1 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
    esc.evaluate(t1);
    let t2 = EscalationTrigger::new("trigger-002", TriggerCategory::SecurityEvent, TriggerSeverity::Warning, "another", "other", ep(100));
    let d2 = esc.evaluate(t2);
    assert!(matches!(d2.verdict, EscalationVerdict::SuppressedCapacity { .. }));
}

#[test]
fn enrichment_escalator_complete_frees_capacity() {
    let policy = EscalationPolicy { max_active_escalations: 1, ..Default::default() };
    let mut esc = HindsightTraceEscalator::new(policy, ep(100));
    let t1 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
    esc.evaluate(t1);
    assert_eq!(esc.state.active_escalations, 1);
    esc.complete_escalation();
    assert_eq!(esc.state.active_escalations, 0);
}

#[test]
fn enrichment_escalator_cooldown_expires_on_advance() {
    let policy = EscalationPolicy { cooldown_epochs: 3, ..Default::default() };
    let mut esc = HindsightTraceEscalator::new(policy, ep(100));
    let mut t1 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
    t1.correlation_id = Some("corr-1".into());
    esc.evaluate(t1);
    esc.complete_escalation();
    esc.advance_epoch(ep(200));
    let mut t2 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
    t2.trigger_id = "trigger-003".into();
    t2.correlation_id = Some("corr-1".into());
    t2.epoch = ep(200);
    let d2 = esc.evaluate(t2);
    assert!(matches!(d2.verdict, EscalationVerdict::Approved { .. }));
}

#[test]
fn enrichment_escalator_summary_fields() {
    let mut esc = HindsightTraceEscalator::new(EscalationPolicy::default(), ep(100));
    let t = test_trigger(TriggerCategory::Regression, TriggerSeverity::Critical);
    esc.evaluate(t);
    let summary = esc.summary();
    assert_eq!(summary.total_approved, 1);
    assert_eq!(summary.active_escalations, 1);
    assert!(!summary.policy_hash.is_empty());
}

#[test]
fn enrichment_escalator_decision_hash_deterministic() {
    let policy = EscalationPolicy::default();
    let mut e1 = HindsightTraceEscalator::new(policy.clone(), ep(100));
    let mut e2 = HindsightTraceEscalator::new(policy, ep(100));
    let t1 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
    let t2 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
    let d1 = e1.evaluate(t1);
    let d2 = e2.evaluate(t2);
    assert_eq!(d1.decision_hash, d2.decision_hash);
}

#[test]
fn enrichment_approved_decision_includes_artifacts() {
    let mut esc = HindsightTraceEscalator::new(EscalationPolicy::default(), ep(100));
    let t = test_trigger(TriggerCategory::SecurityEvent, TriggerSeverity::Critical);
    let d = esc.evaluate(t);
    assert!(!d.artifacts_included.is_empty());
    assert!(d.estimated_bundle_bytes > 0);
}

// ===========================================================================
// EscalationDecision / EscalatorState / EscalatorSummary serde
// ===========================================================================

#[test]
fn enrichment_escalation_decision_serde_roundtrip() {
    let mut esc = HindsightTraceEscalator::new(EscalationPolicy::default(), ep(100));
    let t = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
    let d = esc.evaluate(t);
    let json = serde_json::to_string(&d).unwrap();
    let back: EscalationDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn enrichment_escalator_state_serde_roundtrip() {
    let state = EscalatorState::new(ep(42));
    let json = serde_json::to_string(&state).unwrap();
    let back: EscalatorState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, back);
}

#[test]
fn enrichment_escalator_summary_serde_roundtrip() {
    let mut esc = HindsightTraceEscalator::new(EscalationPolicy::default(), ep(100));
    let t = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
    esc.evaluate(t);
    let summary = esc.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let back: EscalatorSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ===========================================================================
// SupportBundleManifest
// ===========================================================================

#[test]
fn enrichment_support_bundle_manifest_from_decision() {
    let mut esc = HindsightTraceEscalator::new(EscalationPolicy::default(), ep(100));
    let t = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
    let decision = esc.evaluate(t);
    let artifacts = vec![SupportBundleArtifact {
        label: "test_art".into(),
        format: "json".into(),
        path: "/tmp/test.json".into(),
        bytes: 1024,
        content_hash: "abc123".into(),
    }];
    let manifest = SupportBundleManifest::from_decision(&decision, "bundle-001", artifacts);
    assert_eq!(manifest.bundle_id, "bundle-001");
    assert_eq!(manifest.trigger_id, decision.trigger.trigger_id);
    assert_eq!(manifest.total_bytes, 1024);
    assert!(!manifest.manifest_hash.is_empty());
}

#[test]
fn enrichment_support_bundle_manifest_serde_roundtrip() {
    let mut esc = HindsightTraceEscalator::new(EscalationPolicy::default(), ep(100));
    let t = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
    let decision = esc.evaluate(t);
    let manifest = SupportBundleManifest::from_decision(&decision, "bundle-002", vec![]);
    let json = serde_json::to_string(&manifest).unwrap();
    let back: SupportBundleManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn enrichment_support_bundle_manifest_deterministic_hash() {
    let mut e1 = HindsightTraceEscalator::new(EscalationPolicy::default(), ep(100));
    let mut e2 = HindsightTraceEscalator::new(EscalationPolicy::default(), ep(100));
    let t1 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
    let t2 = test_trigger(TriggerCategory::Regression, TriggerSeverity::Warning);
    let d1 = e1.evaluate(t1);
    let d2 = e2.evaluate(t2);
    let m1 = SupportBundleManifest::from_decision(&d1, "b-x", vec![]);
    let m2 = SupportBundleManifest::from_decision(&d2, "b-x", vec![]);
    assert_eq!(m1.manifest_hash, m2.manifest_hash);
}
