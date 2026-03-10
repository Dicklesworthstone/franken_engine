use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::hindsight_boundary_capture::{BoundaryClass, RedactionTreatment};
use frankenengine_engine::hindsight_escalation_bundle::{
    BundleContentKind, EscalationDecision, EscalationError, EscalationPipeline, EscalationPolicy,
    EscalationTrigger, EscalationTriggerKind, TriggerSeverity,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn trigger(id: &str, kind: EscalationTriggerKind, severity: TriggerSeverity) -> EscalationTrigger {
    EscalationTrigger {
        trigger_id: id.to_string(),
        kind,
        severity,
        description: format!("integration trigger {id}"),
        relevant_boundaries: vec![BoundaryClass::ClockRead, BoundaryClass::NetworkResponse],
        source_component: "integration_test".to_string(),
        trigger_epoch: epoch(100),
        trigger_hash: ContentHash::compute(b"placeholder"),
    }
}

// ===========================================================================
// EscalationTriggerKind integration tests
// ===========================================================================

#[test]
fn trigger_kind_all_unique() {
    let mut seen = BTreeSet::new();
    for kind in EscalationTriggerKind::ALL {
        assert!(seen.insert(kind.to_string()), "duplicate: {kind}");
    }
}

#[test]
fn trigger_kind_display_matches_serde() {
    for kind in EscalationTriggerKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let display = kind.to_string();
        assert_eq!(json, format!("\"{display}\""));
    }
}

// ===========================================================================
// TriggerSeverity integration tests
// ===========================================================================

#[test]
fn severity_all_unique() {
    let mut seen = BTreeSet::new();
    for sev in TriggerSeverity::ALL {
        assert!(seen.insert(sev.to_string()), "duplicate: {sev}");
    }
}

#[test]
fn severity_display_matches_serde() {
    for sev in TriggerSeverity::ALL {
        let json = serde_json::to_string(sev).unwrap();
        let display = sev.to_string();
        assert_eq!(json, format!("\"{display}\""));
    }
}

#[test]
fn severity_auto_escalate_implies_high_cost() {
    for sev in TriggerSeverity::ALL {
        if sev.auto_escalate() {
            assert!(sev.cost_multiplier_millionths() >= 750_000);
        }
    }
}

#[test]
fn severity_ordering_matches_cost() {
    let severities: Vec<_> = TriggerSeverity::ALL.to_vec();
    for window in severities.windows(2) {
        assert!(
            window[0].cost_multiplier_millionths() <= window[1].cost_multiplier_millionths(),
            "{} should have <= cost than {}",
            window[0],
            window[1]
        );
    }
}

// ===========================================================================
// BundleContentKind integration tests
// ===========================================================================

#[test]
fn content_kind_all_unique() {
    let mut seen = BTreeSet::new();
    for kind in BundleContentKind::ALL {
        assert!(seen.insert(kind.to_string()), "duplicate: {kind}");
    }
}

#[test]
fn content_kind_costs_bounded() {
    for kind in BundleContentKind::ALL {
        let cost = kind.base_cost_millionths();
        assert!(cost > 0, "{kind} has zero cost");
        assert!(cost <= 1_000_000, "{kind} cost exceeds 1.0");
    }
}

#[test]
fn content_kind_serde_all_variants() {
    for kind in BundleContentKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: BundleContentKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ===========================================================================
// EscalationPolicy integration tests
// ===========================================================================

#[test]
fn policy_default_advisory_is_subset_of_warning() {
    let policy = EscalationPolicy::default();
    let advisory: BTreeSet<_> = policy
        .content_for_severity(TriggerSeverity::Advisory)
        .iter()
        .collect();
    let warning: BTreeSet<_> = policy
        .content_for_severity(TriggerSeverity::Warning)
        .iter()
        .collect();
    assert!(advisory.is_subset(&warning));
}

#[test]
fn policy_default_warning_is_subset_of_critical() {
    let policy = EscalationPolicy::default();
    let warning: BTreeSet<_> = policy
        .content_for_severity(TriggerSeverity::Warning)
        .iter()
        .collect();
    let critical: BTreeSet<_> = policy
        .content_for_severity(TriggerSeverity::Critical)
        .iter()
        .collect();
    assert!(warning.is_subset(&critical));
}

#[test]
fn policy_default_emergency_has_all() {
    let policy = EscalationPolicy::default();
    let emergency = policy.content_for_severity(TriggerSeverity::Emergency);
    assert_eq!(emergency.len(), BundleContentKind::ALL.len());
}

#[test]
fn policy_serde_roundtrip() {
    let policy = EscalationPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let back: EscalationPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

// ===========================================================================
// EscalationPipeline integration tests
// ===========================================================================

#[test]
fn pipeline_all_trigger_kinds_processed() {
    let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), epoch(100));
    for (i, kind) in EscalationTriggerKind::ALL.iter().enumerate() {
        pipeline.process_trigger(trigger(&format!("t-{i}"), *kind, TriggerSeverity::Warning));
    }
    assert_eq!(pipeline.triggers.len(), EscalationTriggerKind::ALL.len());
    assert_eq!(pipeline.receipts.len(), EscalationTriggerKind::ALL.len());
}

#[test]
fn pipeline_always_escalate_triggers() {
    let policy = EscalationPolicy::default();
    let always = policy.always_escalate.clone();
    let mut pipeline = EscalationPipeline::new(policy, epoch(100));

    for (i, kind) in EscalationTriggerKind::ALL.iter().enumerate() {
        let receipt = pipeline.process_trigger(trigger(
            &format!("ae-{i}"),
            *kind,
            TriggerSeverity::Advisory, // low severity, but always-escalate should override
        ));
        if always.contains(kind) {
            assert_eq!(
                receipt.decision,
                EscalationDecision::Escalate,
                "{kind} should always escalate"
            );
        }
    }
}

#[test]
fn pipeline_always_suppress_overrides_always_escalate() {
    let mut policy = EscalationPolicy::default();
    // Suppress a kind that's normally in always-escalate
    policy
        .always_suppress
        .insert(EscalationTriggerKind::UserVisibleFailure);
    let mut pipeline = EscalationPipeline::new(policy, epoch(100));
    let receipt = pipeline.process_trigger(trigger(
        "t-override",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Emergency,
    ));
    assert_eq!(receipt.decision, EscalationDecision::Suppress);
}

#[test]
fn pipeline_emergency_bundle_complete() {
    let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), epoch(100));
    pipeline.process_trigger(trigger(
        "t-emg",
        EscalationTriggerKind::PolicyViolation,
        TriggerSeverity::Emergency,
    ));
    let bundle = pipeline.bundle_for_trigger("t-emg").unwrap();
    assert!(bundle.entries.iter().all(|e| e.complete));
    assert_eq!(bundle.entries.len(), BundleContentKind::ALL.len());
}

#[test]
fn pipeline_emergency_redaction_relaxed() {
    let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), epoch(100));
    pipeline.process_trigger(trigger(
        "t-red-emg",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Emergency,
    ));
    let bundle = pipeline.bundle_for_trigger("t-red-emg").unwrap();
    // In emergency, sensitive content should be plaintext
    for entry in &bundle.entries {
        if matches!(
            entry.kind,
            BundleContentKind::FullBoundaryCapture
                | BundleContentKind::StateSnapshot
                | BundleContentKind::HeapProfile
        ) {
            assert_eq!(entry.redaction, RedactionTreatment::Plaintext);
        }
    }
}

#[test]
fn pipeline_non_emergency_redaction_protected() {
    let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), epoch(100));
    pipeline.process_trigger(trigger(
        "t-red-crit",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Critical,
    ));
    let bundle = pipeline.bundle_for_trigger("t-red-crit").unwrap();
    for entry in &bundle.entries {
        if entry.kind == BundleContentKind::FullBoundaryCapture {
            assert_eq!(entry.redaction, RedactionTreatment::DigestOnly);
        }
    }
}

#[test]
fn pipeline_budget_tracking() {
    let mut policy = EscalationPolicy::default();
    policy.cost_budget_millionths = 500_000;
    let mut pipeline = EscalationPipeline::new(policy, epoch(100));
    let initial_budget = pipeline.remaining_budget_millionths;

    pipeline.process_trigger(trigger(
        "t-b1",
        EscalationTriggerKind::PolicyViolation,
        TriggerSeverity::Critical,
    ));
    assert!(pipeline.remaining_budget_millionths <= initial_budget);
}

#[test]
fn pipeline_budget_exhaustion_defers() {
    let mut policy = EscalationPolicy::default();
    policy.cost_budget_millionths = 1; // very tiny budget
    // Remove always-escalate so budget matters
    policy.always_escalate.clear();
    let mut pipeline = EscalationPipeline::new(policy, epoch(100));

    // First critical should escalate (auto-escalate overrides budget check)
    let r1 = pipeline.process_trigger(trigger(
        "t-exhaust-1",
        EscalationTriggerKind::AnomalyDetected,
        TriggerSeverity::Critical,
    ));
    assert_eq!(r1.decision, EscalationDecision::Escalate);

    // Budget is now exhausted — next critical should defer
    let r2 = pipeline.process_trigger(trigger(
        "t-exhaust-2",
        EscalationTriggerKind::RegressionObserved,
        TriggerSeverity::Critical,
    ));
    assert_eq!(r2.decision, EscalationDecision::Defer);
}

#[test]
fn pipeline_covered_boundaries_from_trigger() {
    let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), epoch(100));
    let mut t = trigger(
        "t-bounds",
        EscalationTriggerKind::PolicyViolation,
        TriggerSeverity::Critical,
    );
    t.relevant_boundaries = vec![
        BoundaryClass::FilesystemInput,
        BoundaryClass::ModuleResolution,
        BoundaryClass::SchedulingDecision,
    ];
    pipeline.process_trigger(t);
    let bundle = pipeline.bundle_for_trigger("t-bounds").unwrap();
    assert!(
        bundle
            .covered_boundaries
            .contains(&BoundaryClass::FilesystemInput)
    );
    assert!(
        bundle
            .covered_boundaries
            .contains(&BoundaryClass::ModuleResolution)
    );
    assert!(
        bundle
            .covered_boundaries
            .contains(&BoundaryClass::SchedulingDecision)
    );
}

#[test]
fn pipeline_summary_report_counts_correct() {
    let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), epoch(100));
    let triggers = vec![
        trigger(
            "t-s1",
            EscalationTriggerKind::UserVisibleFailure,
            TriggerSeverity::Critical,
        ),
        trigger(
            "t-s2",
            EscalationTriggerKind::AnomalyDetected,
            TriggerSeverity::Advisory,
        ),
        trigger(
            "t-s3",
            EscalationTriggerKind::PolicyViolation,
            TriggerSeverity::Warning,
        ),
    ];
    for t in triggers {
        pipeline.process_trigger(t);
    }
    let summary = pipeline.summary_report();
    assert_eq!(summary.total_triggers, 3);
    assert_eq!(
        summary.escalated_count + summary.suppressed_count + summary.deferred_count,
        3
    );
    assert!(summary.triggers_by_kind.len() <= 3);
    assert!(!summary.triggers_by_severity.is_empty());
}

#[test]
fn pipeline_summary_budget_utilization() {
    let mut policy = EscalationPolicy::default();
    policy.cost_budget_millionths = 1_000_000;
    let mut pipeline = EscalationPipeline::new(policy, epoch(100));
    pipeline.process_trigger(trigger(
        "t-util",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Critical,
    ));
    let summary = pipeline.summary_report();
    assert!(summary.budget_utilization_millionths > 0);
    assert!(summary.budget_utilization_millionths <= 1_000_000);
}

#[test]
fn pipeline_deterministic_same_triggers() {
    let policy = EscalationPolicy::default();
    let triggers = vec![
        trigger(
            "t-d1",
            EscalationTriggerKind::AnomalyDetected,
            TriggerSeverity::Warning,
        ),
        trigger(
            "t-d2",
            EscalationTriggerKind::PolicyViolation,
            TriggerSeverity::Critical,
        ),
        trigger(
            "t-d3",
            EscalationTriggerKind::ResourceExhaustion,
            TriggerSeverity::Emergency,
        ),
    ];

    let mut p1 = EscalationPipeline::new(policy.clone(), epoch(100));
    let mut p2 = EscalationPipeline::new(policy, epoch(100));

    for t in &triggers {
        p1.process_trigger(t.clone());
    }
    for t in &triggers {
        p2.process_trigger(t.clone());
    }
    assert_eq!(p1.pipeline_hash, p2.pipeline_hash);
}

#[test]
fn pipeline_serde_full_roundtrip() {
    let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), epoch(100));
    for (i, kind) in EscalationTriggerKind::ALL.iter().enumerate() {
        pipeline.process_trigger(trigger(
            &format!("serde-{i}"),
            *kind,
            TriggerSeverity::Warning,
        ));
    }
    let json = serde_json::to_string(&pipeline).unwrap();
    let back: EscalationPipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(pipeline.pipeline_hash, back.pipeline_hash);
    assert_eq!(pipeline.receipts.len(), back.receipts.len());
}

// ===========================================================================
// EscalationDecision integration tests
// ===========================================================================

#[test]
fn decision_all_unique() {
    let mut seen = BTreeSet::new();
    for d in EscalationDecision::ALL {
        assert!(seen.insert(d.to_string()), "duplicate: {d}");
    }
}

// ===========================================================================
// EscalationError integration tests
// ===========================================================================

#[test]
fn error_display_unique() {
    let errors = vec![
        EscalationError::TriggerNotFound {
            trigger_id: "t".to_string(),
        },
        EscalationError::BundleNotFound {
            bundle_id: "b".to_string(),
        },
        EscalationError::BudgetExhausted {
            remaining: 0,
            required: 100,
        },
        EscalationError::InvalidPolicy {
            detail: "x".to_string(),
        },
    ];
    let displays: Vec<_> = errors.iter().map(|e| e.to_string()).collect();
    let unique: BTreeSet<_> = displays.iter().collect();
    assert_eq!(displays.len(), unique.len());
}

#[test]
fn error_serde_all_variants() {
    for err in [
        EscalationError::TriggerNotFound {
            trigger_id: "t1".to_string(),
        },
        EscalationError::BundleNotFound {
            bundle_id: "b1".to_string(),
        },
        EscalationError::BudgetExhausted {
            remaining: 10,
            required: 500,
        },
        EscalationError::InvalidPolicy {
            detail: "missing strategies".to_string(),
        },
    ] {
        let json = serde_json::to_string(&err).unwrap();
        let back: EscalationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }
}

// ===========================================================================
// Cross-module integration tests
// ===========================================================================

#[test]
fn escalation_covers_all_boundary_classes() {
    let mut pipeline = EscalationPipeline::new(EscalationPolicy::default(), epoch(100));
    let mut t = trigger(
        "t-all-bounds",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Emergency,
    );
    t.relevant_boundaries = BoundaryClass::ALL.to_vec();
    pipeline.process_trigger(t);
    let bundle = pipeline.bundle_for_trigger("t-all-bounds").unwrap();
    assert_eq!(bundle.covered_boundaries.len(), BoundaryClass::ALL.len());
}

#[test]
fn escalation_multiple_severities_different_content_sizes() {
    let policy = EscalationPolicy::default();
    let severities = [
        TriggerSeverity::Advisory,
        TriggerSeverity::Warning,
        TriggerSeverity::Critical,
        TriggerSeverity::Emergency,
    ];

    let mut entry_counts = Vec::new();
    for (i, sev) in severities.iter().enumerate() {
        let mut pipeline = EscalationPipeline::new(policy.clone(), epoch(100));
        pipeline.process_trigger(trigger(
            &format!("t-sev-{i}"),
            EscalationTriggerKind::UserVisibleFailure,
            *sev,
        ));
        let bundle = pipeline.bundle_for_trigger(&format!("t-sev-{i}")).unwrap();
        entry_counts.push(bundle.entries.len());
    }

    // Higher severity should have >= content entries
    for window in entry_counts.windows(2) {
        assert!(window[0] <= window[1]);
    }
}
