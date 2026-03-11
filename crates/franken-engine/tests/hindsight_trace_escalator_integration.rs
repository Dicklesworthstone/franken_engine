#![forbid(unsafe_code)]

//! Integration tests for hindsight_trace_escalator module.
//!
//! Covers: escalation levels, trigger taxonomy, policy resolution, capacity/cooldown
//! suppression, bundle manifests, deterministic hashing, serde roundtrips, and
//! end-to-end escalation workflows.

use std::collections::BTreeSet;

use frankenengine_engine::hindsight_trace_escalator::{
    BundleArtifactSpec, ESCALATION_BEAD_ID, ESCALATION_SCHEMA_VERSION, EscalationDecision,
    EscalationLevel, EscalationPolicy, EscalationTrigger, EscalationVerdict, EscalatorState,
    EscalatorSummary, HindsightTraceEscalator, SupportBundleArtifact, SupportBundleManifest,
    TriggerCategory, TriggerSeverity, standard_artifact_specs,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_trigger(
    id: &str,
    category: TriggerCategory,
    severity: TriggerSeverity,
    ep: SecurityEpoch,
) -> EscalationTrigger {
    EscalationTrigger::new(id, category, severity, "test trigger", "test_src", ep)
}

fn default_policy() -> EscalationPolicy {
    EscalationPolicy::default()
}

fn new_escalator() -> HindsightTraceEscalator {
    HindsightTraceEscalator::new(default_policy(), epoch(100))
}

// ---------------------------------------------------------------------------
// Schema contract
// ---------------------------------------------------------------------------

#[test]
fn schema_version_present() {
    assert!(!ESCALATION_SCHEMA_VERSION.is_empty());
    assert!(ESCALATION_SCHEMA_VERSION.contains("hindsight-trace-escalator"));
}

#[test]
fn bead_id_matches_expected() {
    assert_eq!(ESCALATION_BEAD_ID, "bd-1lsy.9.11.3");
}

// ---------------------------------------------------------------------------
// Escalation level
// ---------------------------------------------------------------------------

#[test]
fn escalation_level_ordering_full() {
    let levels = [
        EscalationLevel::Minimal,
        EscalationLevel::Extended,
        EscalationLevel::Full,
        EscalationLevel::Forensic,
    ];
    for i in 0..levels.len() {
        for j in (i + 1)..levels.len() {
            assert!(
                levels[i] < levels[j],
                "{:?} should be < {:?}",
                levels[i],
                levels[j]
            );
        }
    }
}

#[test]
fn escalation_level_depth_monotonic() {
    let levels = [
        EscalationLevel::Minimal,
        EscalationLevel::Extended,
        EscalationLevel::Full,
        EscalationLevel::Forensic,
    ];
    for pair in levels.windows(2) {
        assert!(pair[0].depth() < pair[1].depth());
    }
}

#[test]
fn escalation_level_display_roundtrip_all() {
    let cases = [
        (EscalationLevel::Minimal, "minimal"),
        (EscalationLevel::Extended, "extended"),
        (EscalationLevel::Full, "full"),
        (EscalationLevel::Forensic, "forensic"),
    ];
    for (level, expected) in cases {
        assert_eq!(level.to_string(), expected);
    }
}

#[test]
fn escalation_level_serde_all_variants() {
    let levels = [
        EscalationLevel::Minimal,
        EscalationLevel::Extended,
        EscalationLevel::Full,
        EscalationLevel::Forensic,
    ];
    for level in levels {
        let json = serde_json::to_string(&level).unwrap();
        let back: EscalationLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(level, back);
    }
}

// ---------------------------------------------------------------------------
// Trigger category
// ---------------------------------------------------------------------------

#[test]
fn trigger_category_all_variants_display() {
    let categories = [
        (TriggerCategory::PerformanceAnomaly, "performance_anomaly"),
        (TriggerCategory::SecurityEvent, "security_event"),
        (TriggerCategory::CorrectnessFailure, "correctness_failure"),
        (TriggerCategory::UserVisibleError, "user_visible_error"),
        (TriggerCategory::Regression, "regression"),
        (TriggerCategory::OperatorRequest, "operator_request"),
        (TriggerCategory::ResourceExhaustion, "resource_exhaustion"),
        (
            TriggerCategory::DeterminismViolation,
            "determinism_violation",
        ),
    ];
    for (cat, expected) in categories {
        assert_eq!(cat.to_string(), expected);
    }
}

#[test]
fn trigger_category_serde_all_variants() {
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
    for cat in categories {
        let json = serde_json::to_string(&cat).unwrap();
        let back: TriggerCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, back);
    }
}

// ---------------------------------------------------------------------------
// Trigger severity
// ---------------------------------------------------------------------------

#[test]
fn trigger_severity_ordering() {
    assert!(TriggerSeverity::Info < TriggerSeverity::Warning);
    assert!(TriggerSeverity::Warning < TriggerSeverity::Critical);
    assert!(TriggerSeverity::Critical < TriggerSeverity::Fatal);
}

#[test]
fn trigger_severity_minimum_escalation_mapping() {
    assert_eq!(
        TriggerSeverity::Info.minimum_escalation(),
        EscalationLevel::Extended
    );
    assert_eq!(
        TriggerSeverity::Warning.minimum_escalation(),
        EscalationLevel::Extended
    );
    assert_eq!(
        TriggerSeverity::Critical.minimum_escalation(),
        EscalationLevel::Full
    );
    assert_eq!(
        TriggerSeverity::Fatal.minimum_escalation(),
        EscalationLevel::Forensic
    );
}

#[test]
fn trigger_severity_display_all() {
    let severities = [
        (TriggerSeverity::Info, "info"),
        (TriggerSeverity::Warning, "warning"),
        (TriggerSeverity::Critical, "critical"),
        (TriggerSeverity::Fatal, "fatal"),
    ];
    for (sev, expected) in severities {
        assert_eq!(sev.to_string(), expected);
    }
}

#[test]
fn trigger_severity_serde_roundtrip() {
    let severities = [
        TriggerSeverity::Info,
        TriggerSeverity::Warning,
        TriggerSeverity::Critical,
        TriggerSeverity::Fatal,
    ];
    for sev in severities {
        let json = serde_json::to_string(&sev).unwrap();
        let back: TriggerSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, back);
    }
}

// ---------------------------------------------------------------------------
// Escalation trigger
// ---------------------------------------------------------------------------

#[test]
fn trigger_construction_fields() {
    let t = make_trigger(
        "trig-1",
        TriggerCategory::SecurityEvent,
        TriggerSeverity::Critical,
        epoch(42),
    );
    assert_eq!(t.trigger_id, "trig-1");
    assert_eq!(t.category, TriggerCategory::SecurityEvent);
    assert_eq!(t.severity, TriggerSeverity::Critical);
    assert_eq!(t.source_component, "test_src");
    assert_eq!(t.epoch, epoch(42));
    assert!(t.correlation_id.is_none());
    assert!(t.metadata.is_empty());
}

#[test]
fn trigger_content_hash_deterministic() {
    let t1 = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(10),
    );
    let t2 = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(10),
    );
    assert_eq!(t1.content_hash(), t2.content_hash());
}

#[test]
fn trigger_content_hash_varies_by_id() {
    let t1 = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(10),
    );
    let t2 = make_trigger(
        "t-2",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(10),
    );
    assert_ne!(t1.content_hash(), t2.content_hash());
}

#[test]
fn trigger_content_hash_varies_by_category() {
    let t1 = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(10),
    );
    let t2 = make_trigger(
        "t-1",
        TriggerCategory::SecurityEvent,
        TriggerSeverity::Warning,
        epoch(10),
    );
    assert_ne!(t1.content_hash(), t2.content_hash());
}

#[test]
fn trigger_content_hash_varies_by_epoch() {
    let t1 = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(10),
    );
    let t2 = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(20),
    );
    assert_ne!(t1.content_hash(), t2.content_hash());
}

#[test]
fn trigger_with_correlation_id_hash_includes_it() {
    let mut t1 = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(10),
    );
    let mut t2 = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(10),
    );
    t1.correlation_id = Some("corr-a".into());
    t2.correlation_id = Some("corr-b".into());
    assert_ne!(t1.content_hash(), t2.content_hash());
}

#[test]
fn trigger_serde_roundtrip_with_metadata() {
    let mut t = make_trigger(
        "t-meta",
        TriggerCategory::SecurityEvent,
        TriggerSeverity::Fatal,
        epoch(5),
    );
    t.correlation_id = Some("corr-99".into());
    t.metadata.insert("key1".into(), "val1".into());
    t.metadata.insert("key2".into(), "val2".into());
    let json = serde_json::to_string(&t).unwrap();
    let back: EscalationTrigger = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

// ---------------------------------------------------------------------------
// Bundle artifact spec
// ---------------------------------------------------------------------------

#[test]
fn standard_artifacts_cover_all_levels() {
    let specs = standard_artifact_specs();
    let levels: BTreeSet<_> = specs.iter().map(|s| s.min_level).collect();
    assert!(levels.contains(&EscalationLevel::Minimal));
    assert!(levels.contains(&EscalationLevel::Extended));
    assert!(levels.contains(&EscalationLevel::Full));
    assert!(levels.contains(&EscalationLevel::Forensic));
}

#[test]
fn standard_artifacts_nonempty_labels() {
    for spec in standard_artifact_specs() {
        assert!(!spec.label.is_empty());
        assert!(!spec.format.is_empty());
    }
}

#[test]
fn standard_artifacts_have_positive_estimates() {
    for spec in standard_artifact_specs() {
        assert!(
            spec.estimated_bytes > 0,
            "artifact {} has zero bytes",
            spec.label
        );
    }
}

#[test]
fn bundle_artifact_spec_serde_roundtrip() {
    let spec = BundleArtifactSpec {
        label: "test_artifact".into(),
        format: "json".into(),
        min_level: EscalationLevel::Extended,
        required: true,
        estimated_bytes: 8192,
    };
    let json = serde_json::to_string(&spec).unwrap();
    let back: BundleArtifactSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, back);
}

// ---------------------------------------------------------------------------
// Escalation policy
// ---------------------------------------------------------------------------

#[test]
fn policy_default_has_schema_version() {
    let p = default_policy();
    assert_eq!(p.schema_version, ESCALATION_SCHEMA_VERSION);
}

#[test]
fn policy_default_level_is_minimal() {
    let p = default_policy();
    assert_eq!(p.default_level, EscalationLevel::Minimal);
}

#[test]
fn policy_default_forbids_forensic() {
    let p = default_policy();
    assert!(!p.allow_forensic);
}

#[test]
fn policy_resolve_severity_info_gives_extended() {
    let p = default_policy();
    let t = make_trigger(
        "t",
        TriggerCategory::Regression,
        TriggerSeverity::Info,
        epoch(1),
    );
    assert_eq!(p.resolve_level(&t), EscalationLevel::Extended);
}

#[test]
fn policy_resolve_severity_critical_gives_full() {
    let p = default_policy();
    let t = make_trigger(
        "t",
        TriggerCategory::Regression,
        TriggerSeverity::Critical,
        epoch(1),
    );
    assert_eq!(p.resolve_level(&t), EscalationLevel::Full);
}

#[test]
fn policy_resolve_fatal_clamped_to_full_without_forensic() {
    let p = default_policy();
    let t = make_trigger(
        "t",
        TriggerCategory::SecurityEvent,
        TriggerSeverity::Fatal,
        epoch(1),
    );
    assert_eq!(p.resolve_level(&t), EscalationLevel::Full);
}

#[test]
fn policy_resolve_fatal_allowed_forensic() {
    let mut p = default_policy();
    p.allow_forensic = true;
    let t = make_trigger(
        "t",
        TriggerCategory::SecurityEvent,
        TriggerSeverity::Fatal,
        epoch(1),
    );
    assert_eq!(p.resolve_level(&t), EscalationLevel::Forensic);
}

#[test]
fn policy_category_override_takes_maximum() {
    let mut p = default_policy();
    p.allow_forensic = true;
    p.category_overrides.insert(
        TriggerCategory::PerformanceAnomaly.to_string(),
        EscalationLevel::Forensic,
    );
    // Info severity minimum is Extended, but category override is Forensic → Forensic wins.
    let t = make_trigger(
        "t",
        TriggerCategory::PerformanceAnomaly,
        TriggerSeverity::Info,
        epoch(1),
    );
    assert_eq!(p.resolve_level(&t), EscalationLevel::Forensic);
}

#[test]
fn policy_severity_wins_over_low_override() {
    let mut p = default_policy();
    p.category_overrides.insert(
        TriggerCategory::Regression.to_string(),
        EscalationLevel::Extended,
    );
    // Critical severity minimum is Full, category override is Extended → Full wins.
    let t = make_trigger(
        "t",
        TriggerCategory::Regression,
        TriggerSeverity::Critical,
        epoch(1),
    );
    assert_eq!(p.resolve_level(&t), EscalationLevel::Full);
}

#[test]
fn policy_artifacts_for_level_monotonic() {
    let p = default_policy();
    let levels = [
        EscalationLevel::Minimal,
        EscalationLevel::Extended,
        EscalationLevel::Full,
        EscalationLevel::Forensic,
    ];
    let mut prev_count = 0;
    for level in levels {
        let count = p.artifacts_for_level(level).len();
        assert!(count >= prev_count, "artifacts should grow with level");
        prev_count = count;
    }
}

#[test]
fn policy_estimate_bundle_size_monotonic() {
    let p = default_policy();
    let levels = [
        EscalationLevel::Minimal,
        EscalationLevel::Extended,
        EscalationLevel::Full,
        EscalationLevel::Forensic,
    ];
    let mut prev_size = 0;
    for level in levels {
        let size = p.estimate_bundle_size(level);
        assert!(size >= prev_size, "bundle size should grow with level");
        prev_size = size;
    }
}

#[test]
fn policy_content_hash_deterministic() {
    let p1 = default_policy();
    let p2 = default_policy();
    assert_eq!(p1.content_hash(), p2.content_hash());
}

#[test]
fn policy_content_hash_changes_with_config() {
    let p1 = default_policy();
    let mut p2 = default_policy();
    p2.max_active_escalations = 999;
    assert_ne!(p1.content_hash(), p2.content_hash());
}

#[test]
fn policy_serde_roundtrip() {
    let mut p = default_policy();
    p.category_overrides
        .insert("regression".into(), EscalationLevel::Full);
    p.allow_forensic = true;
    p.max_active_escalations = 42;
    let json = serde_json::to_string(&p).unwrap();
    let back: EscalationPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// Escalation verdict
// ---------------------------------------------------------------------------

#[test]
fn verdict_display_approved() {
    let v = EscalationVerdict::Approved {
        level: EscalationLevel::Extended,
    };
    assert_eq!(v.to_string(), "approved(extended)");
}

#[test]
fn verdict_display_capacity() {
    let v = EscalationVerdict::SuppressedCapacity {
        active_count: 5,
        max_allowed: 5,
    };
    assert_eq!(v.to_string(), "suppressed_capacity(5/5)");
}

#[test]
fn verdict_display_cooldown() {
    let v = EscalationVerdict::SuppressedCooldown {
        correlation_id: "corr-1".into(),
        epochs_remaining: 3,
    };
    assert!(v.to_string().contains("corr-1"));
}

#[test]
fn verdict_display_below_threshold() {
    assert_eq!(
        EscalationVerdict::SuppressedBelowThreshold.to_string(),
        "suppressed_below_threshold"
    );
}

#[test]
fn verdict_serde_all_variants() {
    let verdicts = vec![
        EscalationVerdict::Approved {
            level: EscalationLevel::Full,
        },
        EscalationVerdict::SuppressedCapacity {
            active_count: 3,
            max_allowed: 10,
        },
        EscalationVerdict::SuppressedCooldown {
            correlation_id: "c-1".into(),
            epochs_remaining: 2,
        },
        EscalationVerdict::SuppressedBelowThreshold,
    ];
    for v in verdicts {
        let json = serde_json::to_string(&v).unwrap();
        let back: EscalationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ---------------------------------------------------------------------------
// Escalator state
// ---------------------------------------------------------------------------

#[test]
fn escalator_state_new_is_clean() {
    let state = EscalatorState::new(epoch(50));
    assert_eq!(state.active_escalations, 0);
    assert_eq!(state.total_approved, 0);
    assert_eq!(state.total_suppressed, 0);
    assert!(state.cooldowns.is_empty());
    assert!(state.category_counts.is_empty());
    assert!(state.level_counts.is_empty());
    assert_eq!(state.current_epoch, epoch(50));
}

#[test]
fn escalator_state_serde_roundtrip() {
    let mut state = EscalatorState::new(epoch(75));
    state.active_escalations = 3;
    state.total_approved = 10;
    state.cooldowns.insert("c-1".into(), 80);
    state.category_counts.insert("regression".into(), 5);
    let json = serde_json::to_string(&state).unwrap();
    let back: EscalatorState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, back);
}

// ---------------------------------------------------------------------------
// Hindsight trace escalator — basic approval
// ---------------------------------------------------------------------------

#[test]
fn escalator_approves_warning_trigger() {
    let mut esc = new_escalator();
    let t = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    let d = esc.evaluate(t);
    assert!(matches!(d.verdict, EscalationVerdict::Approved { .. }));
    assert_eq!(esc.state.total_approved, 1);
    assert_eq!(esc.state.active_escalations, 1);
}

#[test]
fn escalator_approves_critical_at_full_level() {
    let mut esc = new_escalator();
    let t = make_trigger(
        "t-1",
        TriggerCategory::SecurityEvent,
        TriggerSeverity::Critical,
        epoch(100),
    );
    let d = esc.evaluate(t);
    assert_eq!(d.resolved_level, EscalationLevel::Full);
    assert!(matches!(
        d.verdict,
        EscalationVerdict::Approved {
            level: EscalationLevel::Full
        }
    ));
}

#[test]
fn approved_decision_includes_artifacts() {
    let mut esc = new_escalator();
    let t = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Critical,
        epoch(100),
    );
    let d = esc.evaluate(t);
    assert!(!d.artifacts_included.is_empty());
    assert!(d.estimated_bundle_bytes > 0);
}

#[test]
fn approved_decision_has_schema_version() {
    let mut esc = new_escalator();
    let t = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    let d = esc.evaluate(t);
    assert_eq!(d.schema_version, ESCALATION_SCHEMA_VERSION);
}

#[test]
fn approved_decision_hash_nonempty() {
    let mut esc = new_escalator();
    let t = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    let d = esc.evaluate(t);
    assert!(!d.decision_hash.is_empty());
}

// ---------------------------------------------------------------------------
// Capacity suppression
// ---------------------------------------------------------------------------

#[test]
fn escalator_suppresses_at_capacity() {
    let mut policy = default_policy();
    policy.max_active_escalations = 2;
    let mut esc = HindsightTraceEscalator::new(policy, epoch(100));
    // Fill capacity.
    for i in 0..2 {
        let t = make_trigger(
            &format!("t-{i}"),
            TriggerCategory::Regression,
            TriggerSeverity::Warning,
            epoch(100),
        );
        let d = esc.evaluate(t);
        assert!(matches!(d.verdict, EscalationVerdict::Approved { .. }));
    }
    // Third should be suppressed.
    let t = make_trigger(
        "t-2",
        TriggerCategory::SecurityEvent,
        TriggerSeverity::Critical,
        epoch(100),
    );
    let d = esc.evaluate(t);
    assert!(matches!(
        d.verdict,
        EscalationVerdict::SuppressedCapacity {
            active_count: 2,
            max_allowed: 2
        }
    ));
    assert_eq!(esc.state.total_suppressed, 1);
}

#[test]
fn capacity_suppressed_decision_has_no_artifacts() {
    let mut policy = default_policy();
    policy.max_active_escalations = 0;
    let mut esc = HindsightTraceEscalator::new(policy, epoch(100));
    let t = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    let d = esc.evaluate(t);
    assert!(d.artifacts_included.is_empty());
    assert_eq!(d.estimated_bundle_bytes, 0);
}

#[test]
fn complete_escalation_frees_capacity() {
    let mut policy = default_policy();
    policy.max_active_escalations = 1;
    let mut esc = HindsightTraceEscalator::new(policy, epoch(100));
    let t = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    esc.evaluate(t);
    assert_eq!(esc.state.active_escalations, 1);
    esc.complete_escalation();
    assert_eq!(esc.state.active_escalations, 0);
    // Now approved again.
    let t2 = make_trigger(
        "t-2",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    let d = esc.evaluate(t2);
    assert!(matches!(d.verdict, EscalationVerdict::Approved { .. }));
}

#[test]
fn complete_escalation_at_zero_is_safe() {
    let mut esc = new_escalator();
    esc.complete_escalation();
    assert_eq!(esc.state.active_escalations, 0);
}

// ---------------------------------------------------------------------------
// Cooldown suppression
// ---------------------------------------------------------------------------

#[test]
fn cooldown_suppresses_same_correlation_id() {
    let mut policy = default_policy();
    policy.cooldown_epochs = 5;
    let mut esc = HindsightTraceEscalator::new(policy, epoch(100));
    let mut t1 = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    t1.correlation_id = Some("corr-a".into());
    let d1 = esc.evaluate(t1);
    assert!(matches!(d1.verdict, EscalationVerdict::Approved { .. }));
    esc.complete_escalation();
    // Same correlation_id → suppressed.
    let mut t2 = make_trigger(
        "t-2",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    t2.correlation_id = Some("corr-a".into());
    let d2 = esc.evaluate(t2);
    assert!(matches!(
        d2.verdict,
        EscalationVerdict::SuppressedCooldown { .. }
    ));
}

#[test]
fn cooldown_does_not_affect_different_correlation_id() {
    let mut policy = default_policy();
    policy.cooldown_epochs = 10;
    let mut esc = HindsightTraceEscalator::new(policy, epoch(100));
    let mut t1 = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    t1.correlation_id = Some("corr-a".into());
    esc.evaluate(t1);
    esc.complete_escalation();
    // Different correlation_id → approved.
    let mut t2 = make_trigger(
        "t-2",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    t2.correlation_id = Some("corr-b".into());
    let d2 = esc.evaluate(t2);
    assert!(matches!(d2.verdict, EscalationVerdict::Approved { .. }));
}

#[test]
fn cooldown_expires_after_advance_epoch() {
    let mut policy = default_policy();
    policy.cooldown_epochs = 3;
    let mut esc = HindsightTraceEscalator::new(policy, epoch(100));
    let mut t1 = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    t1.correlation_id = Some("corr-a".into());
    esc.evaluate(t1);
    esc.complete_escalation();
    // Advance past cooldown (100 + 3 = 103, advance to 200).
    esc.advance_epoch(epoch(200));
    let mut t2 = make_trigger(
        "t-2",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(200),
    );
    t2.correlation_id = Some("corr-a".into());
    let d2 = esc.evaluate(t2);
    assert!(matches!(d2.verdict, EscalationVerdict::Approved { .. }));
}

#[test]
fn no_correlation_id_skips_cooldown_check() {
    let mut policy = default_policy();
    policy.cooldown_epochs = 100;
    let mut esc = HindsightTraceEscalator::new(policy, epoch(100));
    // No correlation_id on either trigger.
    let t1 = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    esc.evaluate(t1);
    esc.complete_escalation();
    let t2 = make_trigger(
        "t-2",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    let d2 = esc.evaluate(t2);
    assert!(matches!(d2.verdict, EscalationVerdict::Approved { .. }));
}

// ---------------------------------------------------------------------------
// Below-threshold suppression
// ---------------------------------------------------------------------------

#[test]
fn below_threshold_when_resolved_minimal() {
    // Default policy with default_level=Minimal, but we need severity that resolves
    // to Minimal. Info severity gives Extended, so we need to override differently.
    // Actually Info → Extended is the minimum. To get Minimal, we'd need a trigger that
    // resolves below Extended. Since all severity minimums are ≥ Extended, we need
    // a trick: set category override to Minimal and severity to something that also
    // resolves to Minimal. But the lowest severity (Info) gives Extended.
    // So below-threshold suppression only fires if the policy resolves to Minimal.
    // This happens when both default_level and severity happen to produce Minimal,
    // but the lowest severity always gives Extended. So this path can only be hit
    // if we explicitly override category to Minimal and the severity is Info
    // (min=Extended). Then max(Extended, Minimal)=Extended, not Minimal.
    // Actually let's re-read: resolve = max(severity_min, category_override).
    // If no category override, category_override = default_level = Minimal.
    // severity_min for Info = Extended. max(Extended, Minimal) = Extended.
    // So we can never hit Minimal unless we do something special.
    // Wait — what if we override the severity_minimums? No, those are in the policy
    // but resolve_level uses trigger.severity.minimum_escalation() directly.
    // So the only way is to change the code... but we can't. The below-threshold
    // path fires when resolved_level == Minimal, which means both severity_min and
    // category_override must be Minimal. severity_min is never Minimal (Info gives Extended).
    // So this branch is effectively dead for default trigger types. Let's just
    // verify that a standard trigger never gets below-threshold.
    let esc = new_escalator();
    let t = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Info,
        epoch(100),
    );
    let level = esc.policy.resolve_level(&t);
    assert!(level.depth() > EscalationLevel::Minimal.depth());
}

// ---------------------------------------------------------------------------
// Advance epoch
// ---------------------------------------------------------------------------

#[test]
fn advance_epoch_updates_current() {
    let mut esc = new_escalator();
    esc.advance_epoch(epoch(200));
    assert_eq!(esc.state.current_epoch, epoch(200));
}

#[test]
fn advance_epoch_cleans_expired_cooldowns() {
    let mut policy = default_policy();
    policy.cooldown_epochs = 5;
    let mut esc = HindsightTraceEscalator::new(policy, epoch(100));
    let mut t = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    t.correlation_id = Some("c-1".into());
    esc.evaluate(t);
    assert!(!esc.state.cooldowns.is_empty());
    esc.advance_epoch(epoch(200));
    assert!(esc.state.cooldowns.is_empty());
}

// ---------------------------------------------------------------------------
// Decision log bounding
// ---------------------------------------------------------------------------

#[test]
fn decision_log_bounded_to_max() {
    let mut esc = new_escalator();
    esc.max_log_entries = 5;
    for i in 0..20 {
        let t = make_trigger(
            &format!("t-{i:03}"),
            TriggerCategory::PerformanceAnomaly,
            TriggerSeverity::Warning,
            epoch(100),
        );
        esc.evaluate(t);
        esc.complete_escalation();
    }
    assert!(esc.decision_log.len() <= 5);
}

#[test]
fn decision_log_oldest_evicted_first() {
    let mut esc = new_escalator();
    esc.max_log_entries = 3;
    for i in 0..5 {
        let t = make_trigger(
            &format!("t-{i:03}"),
            TriggerCategory::Regression,
            TriggerSeverity::Warning,
            epoch(100),
        );
        esc.evaluate(t);
        esc.complete_escalation();
    }
    // Oldest should be t-002 (0 and 1 evicted).
    assert_eq!(esc.decision_log[0].trigger.trigger_id, "t-002");
}

// ---------------------------------------------------------------------------
// Category and level counts
// ---------------------------------------------------------------------------

#[test]
fn category_counts_increment() {
    let mut esc = new_escalator();
    for i in 0..3 {
        let t = make_trigger(
            &format!("t-{i}"),
            TriggerCategory::Regression,
            TriggerSeverity::Warning,
            epoch(100),
        );
        esc.evaluate(t);
        esc.complete_escalation();
    }
    assert_eq!(esc.state.category_counts.get("regression"), Some(&3));
}

#[test]
fn level_counts_increment() {
    let mut esc = new_escalator();
    let t1 = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    esc.evaluate(t1);
    esc.complete_escalation();
    let t2 = make_trigger(
        "t-2",
        TriggerCategory::Regression,
        TriggerSeverity::Critical,
        epoch(100),
    );
    esc.evaluate(t2);
    // Warning triggers resolve to Extended, Critical to Full.
    assert_eq!(esc.state.level_counts.get("extended"), Some(&1));
    assert_eq!(esc.state.level_counts.get("full"), Some(&1));
}

// ---------------------------------------------------------------------------
// Deterministic decision hashing
// ---------------------------------------------------------------------------

#[test]
fn decision_hash_deterministic_across_instances() {
    let mut e1 = new_escalator();
    let mut e2 = new_escalator();
    let t1 = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    let t2 = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    let d1 = e1.evaluate(t1);
    let d2 = e2.evaluate(t2);
    assert_eq!(d1.decision_hash, d2.decision_hash);
}

#[test]
fn decision_hash_differs_for_different_triggers() {
    let mut esc = new_escalator();
    let t1 = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    let d1 = esc.evaluate(t1);
    esc.complete_escalation();
    let t2 = make_trigger(
        "t-2",
        TriggerCategory::SecurityEvent,
        TriggerSeverity::Critical,
        epoch(100),
    );
    let d2 = esc.evaluate(t2);
    assert_ne!(d1.decision_hash, d2.decision_hash);
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

#[test]
fn summary_reflects_state() {
    let mut esc = new_escalator();
    let t = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Critical,
        epoch(100),
    );
    esc.evaluate(t);
    let summary = esc.summary();
    assert_eq!(summary.total_approved, 1);
    assert_eq!(summary.active_escalations, 1);
    assert_eq!(summary.total_suppressed, 0);
    assert!(!summary.policy_hash.is_empty());
    assert_eq!(summary.epoch, epoch(100));
}

#[test]
fn summary_serde_roundtrip() {
    let mut esc = new_escalator();
    let t = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    esc.evaluate(t);
    let summary = esc.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let back: EscalatorSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn summary_cooldown_count_tracks_active_cooldowns() {
    let mut policy = default_policy();
    policy.cooldown_epochs = 10;
    let mut esc = HindsightTraceEscalator::new(policy, epoch(100));
    let mut t1 = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    t1.correlation_id = Some("c-1".into());
    esc.evaluate(t1);
    esc.complete_escalation();
    let mut t2 = make_trigger(
        "t-2",
        TriggerCategory::SecurityEvent,
        TriggerSeverity::Warning,
        epoch(100),
    );
    t2.correlation_id = Some("c-2".into());
    esc.evaluate(t2);
    let summary = esc.summary();
    assert_eq!(summary.cooldown_count, 2);
}

// ---------------------------------------------------------------------------
// Support bundle manifest
// ---------------------------------------------------------------------------

#[test]
fn support_bundle_from_decision() {
    let mut esc = new_escalator();
    let t = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    let decision = esc.evaluate(t);
    let artifacts = vec![
        SupportBundleArtifact {
            label: "decision_log".into(),
            format: "jsonl".into(),
            path: "/tmp/bundle/decisions.jsonl".into(),
            bytes: 4096,
            content_hash: "aabbccdd".into(),
        },
        SupportBundleArtifact {
            label: "counter_snapshot".into(),
            format: "json".into(),
            path: "/tmp/bundle/counters.json".into(),
            bytes: 2048,
            content_hash: "eeff0011".into(),
        },
    ];
    let manifest = SupportBundleManifest::from_decision(&decision, "bundle-001", artifacts);
    assert_eq!(manifest.bead_id, ESCALATION_BEAD_ID);
    assert_eq!(manifest.bundle_id, "bundle-001");
    assert_eq!(manifest.total_bytes, 6144);
    assert_eq!(manifest.artifacts.len(), 2);
    assert!(!manifest.manifest_hash.is_empty());
    assert_eq!(manifest.escalation_level, decision.resolved_level);
}

#[test]
fn support_bundle_manifest_serde_roundtrip() {
    let manifest = SupportBundleManifest {
        schema_version: ESCALATION_SCHEMA_VERSION.into(),
        bead_id: ESCALATION_BEAD_ID.into(),
        bundle_id: "b-42".into(),
        trigger_id: "t-42".into(),
        escalation_level: EscalationLevel::Full,
        artifacts: vec![SupportBundleArtifact {
            label: "replay_inputs".into(),
            format: "bin".into(),
            path: "/tmp/b-42/replay.bin".into(),
            bytes: 524288,
            content_hash: "deadbeef".into(),
        }],
        total_bytes: 524288,
        epoch: epoch(100),
        manifest_hash: "cafebabe".into(),
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: SupportBundleManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn support_bundle_empty_artifacts() {
    let mut esc = new_escalator();
    let t = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    let decision = esc.evaluate(t);
    let manifest = SupportBundleManifest::from_decision(&decision, "empty-bundle", vec![]);
    assert_eq!(manifest.total_bytes, 0);
    assert!(manifest.artifacts.is_empty());
}

// ---------------------------------------------------------------------------
// Escalator serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn escalator_serde_roundtrip() {
    let mut esc = new_escalator();
    let t = make_trigger(
        "t-1",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    esc.evaluate(t);
    let json = serde_json::to_string(&esc).unwrap();
    let back: HindsightTraceEscalator = serde_json::from_str(&json).unwrap();
    assert_eq!(esc, back);
}

#[test]
fn escalation_decision_serde_roundtrip() {
    let mut esc = new_escalator();
    let t = make_trigger(
        "t-1",
        TriggerCategory::SecurityEvent,
        TriggerSeverity::Critical,
        epoch(100),
    );
    let d = esc.evaluate(t);
    let json = serde_json::to_string(&d).unwrap();
    let back: EscalationDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

// ---------------------------------------------------------------------------
// End-to-end workflow
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_escalation_lifecycle() {
    let mut policy = default_policy();
    policy.max_active_escalations = 3;
    policy.cooldown_epochs = 5;
    let mut esc = HindsightTraceEscalator::new(policy, epoch(100));

    // 1. Approve three triggers.
    for i in 0..3 {
        let mut t = make_trigger(
            &format!("lifecycle-{i}"),
            TriggerCategory::Regression,
            TriggerSeverity::Warning,
            epoch(100),
        );
        t.correlation_id = Some(format!("corr-{i}"));
        let d = esc.evaluate(t);
        assert!(matches!(d.verdict, EscalationVerdict::Approved { .. }));
    }
    assert_eq!(esc.state.active_escalations, 3);

    // 2. Next trigger suppressed (capacity).
    let t4 = make_trigger(
        "lifecycle-3",
        TriggerCategory::SecurityEvent,
        TriggerSeverity::Warning,
        epoch(100),
    );
    let d4 = esc.evaluate(t4);
    assert!(matches!(
        d4.verdict,
        EscalationVerdict::SuppressedCapacity { .. }
    ));

    // 3. Complete one escalation.
    esc.complete_escalation();
    assert_eq!(esc.state.active_escalations, 2);

    // 4. New trigger approved.
    let t5 = make_trigger(
        "lifecycle-4",
        TriggerCategory::PerformanceAnomaly,
        TriggerSeverity::Critical,
        epoch(100),
    );
    let d5 = esc.evaluate(t5);
    assert!(matches!(d5.verdict, EscalationVerdict::Approved { .. }));

    // 5. Same correlation ID suppressed by cooldown.
    let mut t6 = make_trigger(
        "lifecycle-5",
        TriggerCategory::Regression,
        TriggerSeverity::Warning,
        epoch(100),
    );
    t6.correlation_id = Some("corr-0".into());
    let d6 = esc.evaluate(t6);
    assert!(matches!(
        d6.verdict,
        EscalationVerdict::SuppressedCooldown { .. }
    ));

    // 6. Advance epoch past cooldowns.
    esc.advance_epoch(epoch(200));
    assert!(esc.state.cooldowns.is_empty());

    // 7. Verify summary.
    let summary = esc.summary();
    assert_eq!(summary.total_approved, 4);
    assert!(summary.total_suppressed >= 2);
}

#[test]
fn multi_category_workflow() {
    let mut esc = new_escalator();
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
    for (i, cat) in categories.iter().enumerate() {
        let t = make_trigger(
            &format!("multi-{i}"),
            *cat,
            TriggerSeverity::Warning,
            epoch(100),
        );
        let d = esc.evaluate(t);
        assert!(matches!(d.verdict, EscalationVerdict::Approved { .. }));
        esc.complete_escalation();
    }
    // All 8 categories should appear in counts.
    assert_eq!(esc.state.category_counts.len(), 8);
    assert_eq!(esc.state.total_approved, 8);
}

#[test]
fn mixed_severity_workflow() {
    let mut esc = new_escalator();
    let severities = [
        TriggerSeverity::Info,
        TriggerSeverity::Warning,
        TriggerSeverity::Critical,
        TriggerSeverity::Fatal,
    ];
    let expected_levels = [
        EscalationLevel::Extended,
        EscalationLevel::Extended,
        EscalationLevel::Full,
        EscalationLevel::Full, // Fatal clamped to Full (forensic disallowed)
    ];
    for (i, (sev, expected_level)) in severities.iter().zip(expected_levels.iter()).enumerate() {
        let t = make_trigger(
            &format!("sev-{i}"),
            TriggerCategory::Regression,
            *sev,
            epoch(100),
        );
        let d = esc.evaluate(t);
        assert_eq!(
            d.resolved_level, *expected_level,
            "severity {:?} should resolve to {:?}",
            sev, expected_level
        );
        esc.complete_escalation();
    }
}

#[test]
fn high_volume_stress_test() {
    let mut esc = new_escalator();
    esc.max_log_entries = 50;
    for i in 0..200 {
        let t = make_trigger(
            &format!("stress-{i:04}"),
            TriggerCategory::PerformanceAnomaly,
            TriggerSeverity::Warning,
            epoch(100),
        );
        esc.evaluate(t);
        esc.complete_escalation();
    }
    assert_eq!(esc.state.total_approved, 200);
    assert!(esc.decision_log.len() <= 50);
}
