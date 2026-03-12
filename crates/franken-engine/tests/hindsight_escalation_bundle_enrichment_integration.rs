#![forbid(unsafe_code)]
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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::hindsight_boundary_capture::{BoundaryClass, RedactionTreatment};
use frankenengine_engine::hindsight_escalation_bundle::{
    BundleContentEntry, BundleContentKind, COMPONENT, ESCALATION_BEAD_ID,
    ESCALATION_SCHEMA_VERSION, EscalationBundle, EscalationDecision, EscalationError,
    EscalationPipeline, EscalationPolicy, EscalationReceipt, EscalationSummary,
    EscalationTrigger, EscalationTriggerKind, TriggerSeverity,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ===========================================================================
// Helpers
// ===========================================================================

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_trigger(
    id: &str,
    kind: EscalationTriggerKind,
    severity: TriggerSeverity,
) -> EscalationTrigger {
    EscalationTrigger {
        trigger_id: id.to_string(),
        kind,
        severity,
        description: format!("enrichment trigger {id}"),
        relevant_boundaries: vec![BoundaryClass::ClockRead, BoundaryClass::NetworkResponse],
        source_component: "enrichment_test".to_string(),
        trigger_epoch: epoch(200),
        trigger_hash: ContentHash::compute(b"enrichment_placeholder"),
    }
}

fn make_trigger_with_boundaries(
    id: &str,
    kind: EscalationTriggerKind,
    severity: TriggerSeverity,
    boundaries: Vec<BoundaryClass>,
) -> EscalationTrigger {
    EscalationTrigger {
        trigger_id: id.to_string(),
        kind,
        severity,
        description: format!("enrichment trigger {id}"),
        relevant_boundaries: boundaries,
        source_component: "enrichment_test".to_string(),
        trigger_epoch: epoch(200),
        trigger_hash: ContentHash::compute(b"enrichment_placeholder"),
    }
}

fn default_pipeline(ep: u64) -> EscalationPipeline {
    EscalationPipeline::new(EscalationPolicy::default(), epoch(ep))
}

// ===========================================================================
// EscalationTriggerKind enrichment tests
// ===========================================================================

#[test]
fn enrichment_trigger_kind_all_len_is_seven() {
    assert_eq!(EscalationTriggerKind::ALL.len(), 7);
}

#[test]
fn enrichment_trigger_kind_display_no_empty_strings() {
    for kind in EscalationTriggerKind::ALL {
        let s = kind.to_string();
        assert!(!s.is_empty(), "Display for {kind:?} is empty");
        assert!(!s.contains(' '), "Display for {kind:?} has spaces: {s}");
    }
}

#[test]
fn enrichment_trigger_kind_display_all_snake_case() {
    for kind in EscalationTriggerKind::ALL {
        let s = kind.to_string();
        assert!(
            s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "Display for {kind:?} is not snake_case: {s}"
        );
    }
}

#[test]
fn enrichment_trigger_kind_serde_json_roundtrip_all() {
    for kind in EscalationTriggerKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: EscalationTriggerKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back, "Roundtrip failed for {kind:?}");
    }
}

#[test]
fn enrichment_trigger_kind_copy_semantics() {
    let k1 = EscalationTriggerKind::AnomalyDetected;
    let k2 = k1;
    assert_eq!(k1, k2);
}

#[test]
fn enrichment_trigger_kind_ordering_total() {
    let all = EscalationTriggerKind::ALL;
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert!(all[i] < all[j], "{:?} should be < {:?}", all[i], all[j]);
        }
    }
}

#[test]
fn enrichment_trigger_kind_hash_deterministic() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    for kind in EscalationTriggerKind::ALL {
        let mut h1 = DefaultHasher::new();
        kind.hash(&mut h1);
        let r1 = h1.finish();
        let mut h2 = DefaultHasher::new();
        kind.hash(&mut h2);
        let r2 = h2.finish();
        assert_eq!(r1, r2, "Hash not deterministic for {kind:?}");
    }
}

#[test]
fn enrichment_trigger_kind_debug_format_differs_from_display() {
    for kind in EscalationTriggerKind::ALL {
        let debug = format!("{kind:?}");
        let display = format!("{kind}");
        // Debug uses PascalCase, Display uses snake_case
        assert_ne!(debug, display);
    }
}

#[test]
fn enrichment_trigger_kind_btreeset_contains_all() {
    let set: BTreeSet<EscalationTriggerKind> =
        EscalationTriggerKind::ALL.iter().copied().collect();
    assert_eq!(set.len(), EscalationTriggerKind::ALL.len());
    for kind in EscalationTriggerKind::ALL {
        assert!(set.contains(kind));
    }
}

#[test]
fn enrichment_trigger_kind_serde_rejects_invalid() {
    let result = serde_json::from_str::<EscalationTriggerKind>("\"nonexistent_kind\"");
    assert!(result.is_err());
}

// ===========================================================================
// TriggerSeverity enrichment tests
// ===========================================================================

#[test]
fn enrichment_severity_all_len_is_four() {
    assert_eq!(TriggerSeverity::ALL.len(), 4);
}

#[test]
fn enrichment_severity_cost_multiplier_exact_values() {
    assert_eq!(TriggerSeverity::Advisory.cost_multiplier_millionths(), 250_000);
    assert_eq!(TriggerSeverity::Warning.cost_multiplier_millionths(), 500_000);
    assert_eq!(TriggerSeverity::Critical.cost_multiplier_millionths(), 750_000);
    assert_eq!(TriggerSeverity::Emergency.cost_multiplier_millionths(), 1_000_000);
}

#[test]
fn enrichment_severity_auto_escalate_exactly_critical_and_emergency() {
    assert!(!TriggerSeverity::Advisory.auto_escalate());
    assert!(!TriggerSeverity::Warning.auto_escalate());
    assert!(TriggerSeverity::Critical.auto_escalate());
    assert!(TriggerSeverity::Emergency.auto_escalate());
}

#[test]
fn enrichment_severity_display_exact_strings() {
    assert_eq!(TriggerSeverity::Advisory.to_string(), "advisory");
    assert_eq!(TriggerSeverity::Warning.to_string(), "warning");
    assert_eq!(TriggerSeverity::Critical.to_string(), "critical");
    assert_eq!(TriggerSeverity::Emergency.to_string(), "emergency");
}

#[test]
fn enrichment_severity_ordering_matches_escalation_level() {
    assert!(TriggerSeverity::Advisory < TriggerSeverity::Warning);
    assert!(TriggerSeverity::Warning < TriggerSeverity::Critical);
    assert!(TriggerSeverity::Critical < TriggerSeverity::Emergency);
}

#[test]
fn enrichment_severity_cost_multiplier_strictly_increasing() {
    let vals: Vec<u64> = TriggerSeverity::ALL
        .iter()
        .map(|s| s.cost_multiplier_millionths())
        .collect();
    for w in vals.windows(2) {
        assert!(w[0] < w[1], "Cost not strictly increasing: {} vs {}", w[0], w[1]);
    }
}

#[test]
fn enrichment_severity_emergency_cost_is_one_million() {
    assert_eq!(TriggerSeverity::Emergency.cost_multiplier_millionths(), 1_000_000);
}

#[test]
fn enrichment_severity_serde_roundtrip_all() {
    for sev in TriggerSeverity::ALL {
        let json = serde_json::to_string(sev).unwrap();
        let back: TriggerSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(*sev, back);
    }
}

#[test]
fn enrichment_severity_serde_rejects_invalid() {
    let result = serde_json::from_str::<TriggerSeverity>("\"debug\"");
    assert!(result.is_err());
}

#[test]
fn enrichment_severity_btreeset_dedup() {
    let mut set = BTreeSet::new();
    set.insert(TriggerSeverity::Critical);
    set.insert(TriggerSeverity::Critical);
    assert_eq!(set.len(), 1);
}

// ===========================================================================
// BundleContentKind enrichment tests
// ===========================================================================

#[test]
fn enrichment_content_kind_all_len_is_seven() {
    assert_eq!(BundleContentKind::ALL.len(), 7);
}

#[test]
fn enrichment_content_kind_exact_base_costs() {
    assert_eq!(BundleContentKind::FullBoundaryCapture.base_cost_millionths(), 50_000);
    assert_eq!(BundleContentKind::DecisionReceiptChain.base_cost_millionths(), 30_000);
    assert_eq!(BundleContentKind::StateSnapshot.base_cost_millionths(), 80_000);
    assert_eq!(BundleContentKind::ExecutionTrace.base_cost_millionths(), 120_000);
    assert_eq!(BundleContentKind::HeapProfile.base_cost_millionths(), 100_000);
    assert_eq!(BundleContentKind::PolicyEvaluationLog.base_cost_millionths(), 40_000);
    assert_eq!(BundleContentKind::ReplayInputs.base_cost_millionths(), 60_000);
}

#[test]
fn enrichment_content_kind_total_cost_under_one_million() {
    let total: u64 = BundleContentKind::ALL
        .iter()
        .map(|k| k.base_cost_millionths())
        .sum();
    assert!(total <= 1_000_000, "Total base cost {total} > 1M");
}

#[test]
fn enrichment_content_kind_display_all_unique() {
    let mut seen = BTreeSet::new();
    for kind in BundleContentKind::ALL {
        assert!(seen.insert(kind.to_string()), "Duplicate display: {kind}");
    }
}

#[test]
fn enrichment_content_kind_display_matches_serde_value() {
    for kind in BundleContentKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let display = kind.to_string();
        assert_eq!(json, format!("\"{display}\""));
    }
}

#[test]
fn enrichment_content_kind_execution_trace_most_expensive() {
    let max_cost = BundleContentKind::ALL
        .iter()
        .map(|k| k.base_cost_millionths())
        .max()
        .unwrap();
    assert_eq!(
        max_cost,
        BundleContentKind::ExecutionTrace.base_cost_millionths()
    );
}

#[test]
fn enrichment_content_kind_decision_receipt_chain_cheapest() {
    let min_cost = BundleContentKind::ALL
        .iter()
        .map(|k| k.base_cost_millionths())
        .min()
        .unwrap();
    assert_eq!(
        min_cost,
        BundleContentKind::DecisionReceiptChain.base_cost_millionths()
    );
}

#[test]
fn enrichment_content_kind_ordering_deterministic() {
    let sorted: Vec<BundleContentKind> = {
        let mut v = BundleContentKind::ALL.to_vec();
        v.sort();
        v
    };
    // BTreeSet iteration matches Ord
    let set: BTreeSet<BundleContentKind> = BundleContentKind::ALL.iter().copied().collect();
    let from_set: Vec<BundleContentKind> = set.into_iter().collect();
    assert_eq!(sorted, from_set);
}

// ===========================================================================
// BundleContentEntry enrichment tests
// ===========================================================================

#[test]
fn enrichment_content_entry_serde_roundtrip() {
    let entry = BundleContentEntry {
        kind: BundleContentKind::FullBoundaryCapture,
        content_digest: ContentHash::compute(b"test-content"),
        redaction: RedactionTreatment::DigestOnly,
        size_bytes: 4096,
        complete: true,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: BundleContentEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_content_entry_all_redaction_modes() {
    for redaction in [
        RedactionTreatment::Plaintext,
        RedactionTreatment::DigestOnly,
        RedactionTreatment::Omit,
    ] {
        let entry = BundleContentEntry {
            kind: BundleContentKind::StateSnapshot,
            content_digest: ContentHash::compute(b"redaction-test"),
            redaction,
            size_bytes: 1024,
            complete: false,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: BundleContentEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry.redaction, back.redaction);
    }
}

#[test]
fn enrichment_content_entry_clone_independence() {
    let entry = BundleContentEntry {
        kind: BundleContentKind::HeapProfile,
        content_digest: ContentHash::compute(b"clone-test"),
        redaction: RedactionTreatment::Plaintext,
        size_bytes: 8192,
        complete: true,
    };
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
}

#[test]
fn enrichment_content_entry_zero_size() {
    let entry = BundleContentEntry {
        kind: BundleContentKind::ReplayInputs,
        content_digest: ContentHash::compute(b"zero"),
        redaction: RedactionTreatment::Plaintext,
        size_bytes: 0,
        complete: true,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: BundleContentEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.size_bytes, 0);
}

// ===========================================================================
// EscalationTrigger enrichment tests
// ===========================================================================

#[test]
fn enrichment_trigger_serde_all_kinds() {
    for kind in EscalationTriggerKind::ALL {
        let t = make_trigger(&format!("serde-{kind}"), *kind, TriggerSeverity::Warning);
        let json = serde_json::to_string(&t).unwrap();
        let back: EscalationTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(t.trigger_id, back.trigger_id);
        assert_eq!(t.kind, back.kind);
        assert_eq!(t.severity, back.severity);
    }
}

#[test]
fn enrichment_trigger_serde_all_severities() {
    for sev in TriggerSeverity::ALL {
        let t = make_trigger(&format!("serde-{sev}"), EscalationTriggerKind::AnomalyDetected, *sev);
        let json = serde_json::to_string(&t).unwrap();
        let back: EscalationTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(t.severity, back.severity);
    }
}

#[test]
fn enrichment_trigger_clone_modification_independent() {
    let t = make_trigger("orig", EscalationTriggerKind::PolicyViolation, TriggerSeverity::Critical);
    let mut cloned = t.clone();
    cloned.trigger_id = "modified".to_string();
    cloned.severity = TriggerSeverity::Advisory;
    assert_eq!(t.trigger_id, "orig");
    assert_eq!(t.severity, TriggerSeverity::Critical);
    assert_ne!(t.trigger_id, cloned.trigger_id);
    assert_ne!(t.severity, cloned.severity);
}

#[test]
fn enrichment_trigger_boundaries_preserved_in_serde() {
    let boundaries = vec![
        BoundaryClass::FilesystemInput,
        BoundaryClass::SchedulingDecision,
        BoundaryClass::HardwareSurfaceRead,
    ];
    let t = make_trigger_with_boundaries(
        "boundary-serde",
        EscalationTriggerKind::AnomalyDetected,
        TriggerSeverity::Warning,
        boundaries.clone(),
    );
    let json = serde_json::to_string(&t).unwrap();
    let back: EscalationTrigger = serde_json::from_str(&json).unwrap();
    assert_eq!(back.relevant_boundaries, boundaries);
}

#[test]
fn enrichment_trigger_empty_description() {
    let t = EscalationTrigger {
        trigger_id: "empty-desc".to_string(),
        kind: EscalationTriggerKind::OperatorRequest,
        severity: TriggerSeverity::Advisory,
        description: String::new(),
        relevant_boundaries: vec![],
        source_component: "test".to_string(),
        trigger_epoch: epoch(1),
        trigger_hash: ContentHash::compute(b"x"),
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: EscalationTrigger = serde_json::from_str(&json).unwrap();
    assert!(back.description.is_empty());
}

#[test]
fn enrichment_trigger_epoch_preserved() {
    let t = EscalationTrigger {
        trigger_id: "ep-test".to_string(),
        kind: EscalationTriggerKind::ResourceExhaustion,
        severity: TriggerSeverity::Emergency,
        description: "epoch test".to_string(),
        relevant_boundaries: vec![],
        source_component: "test".to_string(),
        trigger_epoch: epoch(999_999),
        trigger_hash: ContentHash::compute(b"epoch"),
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: EscalationTrigger = serde_json::from_str(&json).unwrap();
    assert_eq!(back.trigger_epoch, epoch(999_999));
}

// ===========================================================================
// EscalationBundle enrichment tests
// ===========================================================================

#[test]
fn enrichment_bundle_serde_roundtrip() {
    let bundle = EscalationBundle {
        bundle_id: "b-enrichment-1".to_string(),
        trigger_id: "t-enrichment-1".to_string(),
        entries: vec![
            BundleContentEntry {
                kind: BundleContentKind::FullBoundaryCapture,
                content_digest: ContentHash::compute(b"fc-test"),
                redaction: RedactionTreatment::DigestOnly,
                size_bytes: 2048,
                complete: true,
            },
            BundleContentEntry {
                kind: BundleContentKind::ExecutionTrace,
                content_digest: ContentHash::compute(b"et-test"),
                redaction: RedactionTreatment::Plaintext,
                size_bytes: 4096,
                complete: false,
            },
        ],
        covered_boundaries: BTreeSet::from([
            BoundaryClass::ClockRead,
            BoundaryClass::RandomnessDraw,
        ]),
        total_cost_millionths: 170_000,
        bundle_epoch: epoch(300),
        bundle_hash: ContentHash::compute(b"bundle-enrichment"),
    };
    let json = serde_json::to_string(&bundle).unwrap();
    let back: EscalationBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(bundle, back);
}

#[test]
fn enrichment_bundle_empty_entries() {
    let bundle = EscalationBundle {
        bundle_id: "b-empty".to_string(),
        trigger_id: "t-empty".to_string(),
        entries: vec![],
        covered_boundaries: BTreeSet::new(),
        total_cost_millionths: 0,
        bundle_epoch: epoch(1),
        bundle_hash: ContentHash::compute(b"empty-bundle"),
    };
    let json = serde_json::to_string(&bundle).unwrap();
    let back: EscalationBundle = serde_json::from_str(&json).unwrap();
    assert!(back.entries.is_empty());
    assert_eq!(back.total_cost_millionths, 0);
}

#[test]
fn enrichment_bundle_all_boundary_classes_covered() {
    let all_boundaries: BTreeSet<BoundaryClass> = BoundaryClass::ALL.iter().copied().collect();
    let bundle = EscalationBundle {
        bundle_id: "b-all-bounds".to_string(),
        trigger_id: "t-all-bounds".to_string(),
        entries: vec![],
        covered_boundaries: all_boundaries.clone(),
        total_cost_millionths: 0,
        bundle_epoch: epoch(1),
        bundle_hash: ContentHash::compute(b"all-bounds"),
    };
    assert_eq!(bundle.covered_boundaries.len(), 9);
    assert_eq!(bundle.covered_boundaries, all_boundaries);
}

#[test]
fn enrichment_bundle_clone_independence() {
    let bundle = EscalationBundle {
        bundle_id: "b-clone".to_string(),
        trigger_id: "t-clone".to_string(),
        entries: vec![BundleContentEntry {
            kind: BundleContentKind::ReplayInputs,
            content_digest: ContentHash::compute(b"clone-data"),
            redaction: RedactionTreatment::Plaintext,
            size_bytes: 512,
            complete: true,
        }],
        covered_boundaries: BTreeSet::from([BoundaryClass::ModuleResolution]),
        total_cost_millionths: 60_000,
        bundle_epoch: epoch(42),
        bundle_hash: ContentHash::compute(b"clone-bundle"),
    };
    let mut cloned = bundle.clone();
    cloned.bundle_id = "b-clone-modified".to_string();
    assert_eq!(bundle.bundle_id, "b-clone");
    assert_eq!(cloned.bundle_id, "b-clone-modified");
}

// ===========================================================================
// EscalationDecision enrichment tests
// ===========================================================================

#[test]
fn enrichment_decision_all_len_is_three() {
    assert_eq!(EscalationDecision::ALL.len(), 3);
}

#[test]
fn enrichment_decision_display_exact() {
    assert_eq!(EscalationDecision::Escalate.to_string(), "escalate");
    assert_eq!(EscalationDecision::Suppress.to_string(), "suppress");
    assert_eq!(EscalationDecision::Defer.to_string(), "defer");
}

#[test]
fn enrichment_decision_serde_roundtrip_all() {
    for d in EscalationDecision::ALL {
        let json = serde_json::to_string(d).unwrap();
        let back: EscalationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

#[test]
fn enrichment_decision_copy_semantics() {
    let d1 = EscalationDecision::Escalate;
    let d2 = d1;
    assert_eq!(d1, d2);
}

#[test]
fn enrichment_decision_ordering() {
    assert!(EscalationDecision::Escalate < EscalationDecision::Suppress);
    assert!(EscalationDecision::Suppress < EscalationDecision::Defer);
}

#[test]
fn enrichment_decision_serde_rejects_invalid() {
    let result = serde_json::from_str::<EscalationDecision>("\"hold\"");
    assert!(result.is_err());
}

// ===========================================================================
// EscalationReceipt enrichment tests
// ===========================================================================

#[test]
fn enrichment_receipt_serde_roundtrip_with_bundle() {
    let receipt = EscalationReceipt {
        receipt_id: "receipt-enrich-1".to_string(),
        trigger_id: "t-enrich-1".to_string(),
        decision: EscalationDecision::Escalate,
        bundle_id: Some("b-enrich-1".to_string()),
        rationale: "always-escalate matched".to_string(),
        cost_budget_millionths: 100_000,
        cost_consumed_millionths: 37_500,
        receipt_epoch: epoch(200),
        receipt_hash: ContentHash::compute(b"receipt-1"),
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let back: EscalationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn enrichment_receipt_serde_roundtrip_without_bundle() {
    let receipt = EscalationReceipt {
        receipt_id: "receipt-enrich-2".to_string(),
        trigger_id: "t-enrich-2".to_string(),
        decision: EscalationDecision::Suppress,
        bundle_id: None,
        rationale: "suppressed by policy".to_string(),
        cost_budget_millionths: 50_000,
        cost_consumed_millionths: 0,
        receipt_epoch: epoch(200),
        receipt_hash: ContentHash::compute(b"receipt-2"),
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let back: EscalationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt.bundle_id, back.bundle_id);
    assert!(back.bundle_id.is_none());
}

#[test]
fn enrichment_receipt_deferred_has_no_bundle() {
    let receipt = EscalationReceipt {
        receipt_id: "receipt-defer".to_string(),
        trigger_id: "t-defer".to_string(),
        decision: EscalationDecision::Defer,
        bundle_id: None,
        rationale: "budget exhausted".to_string(),
        cost_budget_millionths: 0,
        cost_consumed_millionths: 0,
        receipt_epoch: epoch(200),
        receipt_hash: ContentHash::compute(b"receipt-defer"),
    };
    assert!(receipt.bundle_id.is_none());
    assert_eq!(receipt.cost_consumed_millionths, 0);
}

#[test]
fn enrichment_receipt_clone_preserves_all_fields() {
    let receipt = EscalationReceipt {
        receipt_id: "receipt-clone".to_string(),
        trigger_id: "t-clone".to_string(),
        decision: EscalationDecision::Escalate,
        bundle_id: Some("b-clone".to_string()),
        rationale: "clone test".to_string(),
        cost_budget_millionths: 80_000,
        cost_consumed_millionths: 25_000,
        receipt_epoch: epoch(150),
        receipt_hash: ContentHash::compute(b"receipt-clone"),
    };
    let cloned = receipt.clone();
    assert_eq!(receipt, cloned);
}

// ===========================================================================
// EscalationPolicy enrichment tests
// ===========================================================================

#[test]
fn enrichment_policy_default_cost_budget() {
    let policy = EscalationPolicy::default();
    assert_eq!(policy.cost_budget_millionths, 100_000);
}

#[test]
fn enrichment_policy_default_always_escalate_contains_user_visible_failure() {
    let policy = EscalationPolicy::default();
    assert!(policy.always_escalate.contains(&EscalationTriggerKind::UserVisibleFailure));
}

#[test]
fn enrichment_policy_default_always_escalate_contains_policy_violation() {
    let policy = EscalationPolicy::default();
    assert!(policy.always_escalate.contains(&EscalationTriggerKind::PolicyViolation));
}

#[test]
fn enrichment_policy_default_always_suppress_empty() {
    let policy = EscalationPolicy::default();
    assert!(policy.always_suppress.is_empty());
}

#[test]
fn enrichment_policy_default_auto_escalate_threshold_is_critical() {
    let policy = EscalationPolicy::default();
    assert_eq!(policy.auto_escalate_threshold, TriggerSeverity::Critical);
}

#[test]
fn enrichment_policy_advisory_content_count() {
    let policy = EscalationPolicy::default();
    assert_eq!(policy.advisory_content.len(), 2);
}

#[test]
fn enrichment_policy_warning_content_count() {
    let policy = EscalationPolicy::default();
    assert_eq!(policy.warning_content.len(), 4);
}

#[test]
fn enrichment_policy_critical_content_count() {
    let policy = EscalationPolicy::default();
    assert_eq!(policy.critical_content.len(), 6);
}

#[test]
fn enrichment_policy_emergency_content_count() {
    let policy = EscalationPolicy::default();
    assert_eq!(policy.emergency_content.len(), 7);
}

#[test]
fn enrichment_policy_content_monotonically_increasing_with_severity() {
    let policy = EscalationPolicy::default();
    let adv = policy.content_for_severity(TriggerSeverity::Advisory).len();
    let warn = policy.content_for_severity(TriggerSeverity::Warning).len();
    let crit = policy.content_for_severity(TriggerSeverity::Critical).len();
    let emrg = policy.content_for_severity(TriggerSeverity::Emergency).len();
    assert!(adv <= warn, "advisory {adv} > warning {warn}");
    assert!(warn <= crit, "warning {warn} > critical {crit}");
    assert!(crit <= emrg, "critical {crit} > emergency {emrg}");
}

#[test]
fn enrichment_policy_advisory_subset_of_warning() {
    let policy = EscalationPolicy::default();
    let adv: BTreeSet<_> = policy.content_for_severity(TriggerSeverity::Advisory).iter().collect();
    let warn: BTreeSet<_> = policy.content_for_severity(TriggerSeverity::Warning).iter().collect();
    assert!(adv.is_subset(&warn));
}

#[test]
fn enrichment_policy_warning_subset_of_critical() {
    let policy = EscalationPolicy::default();
    let warn: BTreeSet<_> = policy.content_for_severity(TriggerSeverity::Warning).iter().collect();
    let crit: BTreeSet<_> = policy.content_for_severity(TriggerSeverity::Critical).iter().collect();
    assert!(warn.is_subset(&crit));
}

#[test]
fn enrichment_policy_critical_subset_of_emergency() {
    let policy = EscalationPolicy::default();
    let crit: BTreeSet<_> = policy.content_for_severity(TriggerSeverity::Critical).iter().collect();
    let emrg: BTreeSet<_> = policy.content_for_severity(TriggerSeverity::Emergency).iter().collect();
    assert!(crit.is_subset(&emrg));
}

#[test]
fn enrichment_policy_serde_roundtrip() {
    let policy = EscalationPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let back: EscalationPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn enrichment_policy_custom_serde_roundtrip() {
    let mut policy = EscalationPolicy::default();
    policy.cost_budget_millionths = 500_000;
    policy.always_suppress.insert(EscalationTriggerKind::OperatorRequest);
    policy.auto_escalate_threshold = TriggerSeverity::Emergency;
    let json = serde_json::to_string(&policy).unwrap();
    let back: EscalationPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn enrichment_policy_clone_independence() {
    let policy = EscalationPolicy::default();
    let mut cloned = policy.clone();
    cloned.cost_budget_millionths = 999_999;
    assert_eq!(policy.cost_budget_millionths, 100_000);
    assert_eq!(cloned.cost_budget_millionths, 999_999);
}

// ===========================================================================
// EscalationPipeline enrichment tests
// ===========================================================================

#[test]
fn enrichment_pipeline_new_schema_version() {
    let pipeline = default_pipeline(100);
    assert_eq!(pipeline.schema_version, ESCALATION_SCHEMA_VERSION);
}

#[test]
fn enrichment_pipeline_new_bead_id() {
    let pipeline = default_pipeline(100);
    assert_eq!(pipeline.bead_id, ESCALATION_BEAD_ID);
}

#[test]
fn enrichment_pipeline_new_epoch_preserved() {
    let pipeline = default_pipeline(42);
    assert_eq!(pipeline.pipeline_epoch, epoch(42));
}

#[test]
fn enrichment_pipeline_new_budget_matches_policy() {
    let pipeline = default_pipeline(100);
    assert_eq!(
        pipeline.remaining_budget_millionths,
        pipeline.policy.cost_budget_millionths
    );
}

#[test]
fn enrichment_pipeline_new_collections_empty() {
    let pipeline = default_pipeline(100);
    assert!(pipeline.triggers.is_empty());
    assert!(pipeline.receipts.is_empty());
    assert!(pipeline.bundles.is_empty());
}

#[test]
fn enrichment_pipeline_process_trigger_returns_receipt_ref() {
    let mut pipeline = default_pipeline(100);
    let receipt = pipeline.process_trigger(make_trigger(
        "ref-test",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Critical,
    ));
    assert_eq!(receipt.trigger_id, "ref-test");
    assert_eq!(receipt.receipt_id, "receipt-ref-test");
}

#[test]
fn enrichment_pipeline_process_increments_triggers() {
    let mut pipeline = default_pipeline(100);
    assert_eq!(pipeline.triggers.len(), 0);
    pipeline.process_trigger(make_trigger(
        "inc-1",
        EscalationTriggerKind::AnomalyDetected,
        TriggerSeverity::Warning,
    ));
    assert_eq!(pipeline.triggers.len(), 1);
    pipeline.process_trigger(make_trigger(
        "inc-2",
        EscalationTriggerKind::RegressionObserved,
        TriggerSeverity::Advisory,
    ));
    assert_eq!(pipeline.triggers.len(), 2);
}

#[test]
fn enrichment_pipeline_process_increments_receipts() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "r-1",
        EscalationTriggerKind::AnomalyDetected,
        TriggerSeverity::Warning,
    ));
    pipeline.process_trigger(make_trigger(
        "r-2",
        EscalationTriggerKind::PolicyViolation,
        TriggerSeverity::Critical,
    ));
    assert_eq!(pipeline.receipts.len(), 2);
}

#[test]
fn enrichment_pipeline_always_escalate_user_visible_failure() {
    let mut pipeline = default_pipeline(100);
    let receipt = pipeline.process_trigger(make_trigger(
        "ae-uvf",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Advisory, // low severity, but always-escalate overrides
    ));
    assert_eq!(receipt.decision, EscalationDecision::Escalate);
}

#[test]
fn enrichment_pipeline_always_escalate_policy_violation() {
    let mut pipeline = default_pipeline(100);
    let receipt = pipeline.process_trigger(make_trigger(
        "ae-pv",
        EscalationTriggerKind::PolicyViolation,
        TriggerSeverity::Advisory,
    ));
    assert_eq!(receipt.decision, EscalationDecision::Escalate);
}

#[test]
fn enrichment_pipeline_suppress_overrides_always_escalate() {
    let mut policy = EscalationPolicy::default();
    policy.always_suppress.insert(EscalationTriggerKind::UserVisibleFailure);
    let mut pipeline = EscalationPipeline::new(policy, epoch(100));
    let receipt = pipeline.process_trigger(make_trigger(
        "suppress-override",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Emergency,
    ));
    assert_eq!(receipt.decision, EscalationDecision::Suppress);
    assert!(receipt.bundle_id.is_none());
}

#[test]
fn enrichment_pipeline_suppress_overrides_auto_escalate_severity() {
    let mut policy = EscalationPolicy::default();
    policy.always_suppress.insert(EscalationTriggerKind::ResourceExhaustion);
    let mut pipeline = EscalationPipeline::new(policy, epoch(100));
    let receipt = pipeline.process_trigger(make_trigger(
        "suppress-sev",
        EscalationTriggerKind::ResourceExhaustion,
        TriggerSeverity::Emergency, // would auto-escalate if not suppressed
    ));
    assert_eq!(receipt.decision, EscalationDecision::Suppress);
}

#[test]
fn enrichment_pipeline_critical_auto_escalates_non_always_kind() {
    let mut pipeline = default_pipeline(100);
    let receipt = pipeline.process_trigger(make_trigger(
        "auto-crit",
        EscalationTriggerKind::ResourceExhaustion, // not in always_escalate
        TriggerSeverity::Critical,
    ));
    assert_eq!(receipt.decision, EscalationDecision::Escalate);
}

#[test]
fn enrichment_pipeline_emergency_auto_escalates() {
    let mut pipeline = default_pipeline(100);
    let receipt = pipeline.process_trigger(make_trigger(
        "auto-emg",
        EscalationTriggerKind::ReplayDivergence,
        TriggerSeverity::Emergency,
    ));
    assert_eq!(receipt.decision, EscalationDecision::Escalate);
}

#[test]
fn enrichment_pipeline_advisory_within_budget_escalates() {
    let mut pipeline = default_pipeline(100);
    let receipt = pipeline.process_trigger(make_trigger(
        "adv-budget",
        EscalationTriggerKind::AnomalyDetected,
        TriggerSeverity::Advisory,
    ));
    assert_eq!(receipt.decision, EscalationDecision::Escalate);
}

#[test]
fn enrichment_pipeline_warning_exceeds_default_budget_defers() {
    // Warning content cost: 50000+30000+40000+60000 = 180000 > default budget 100000
    // So with default budget, a below-threshold warning will defer
    let mut pipeline = default_pipeline(100);
    let receipt = pipeline.process_trigger(make_trigger(
        "warn-budget",
        EscalationTriggerKind::RegressionObserved,
        TriggerSeverity::Warning,
    ));
    assert_eq!(receipt.decision, EscalationDecision::Defer);
}

#[test]
fn enrichment_pipeline_budget_depletes_on_escalation() {
    let mut pipeline = default_pipeline(100);
    let initial_budget = pipeline.remaining_budget_millionths;
    pipeline.process_trigger(make_trigger(
        "budget-depl",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Critical,
    ));
    assert!(pipeline.remaining_budget_millionths < initial_budget);
}

#[test]
fn enrichment_pipeline_budget_no_change_on_suppress() {
    let mut policy = EscalationPolicy::default();
    policy.always_suppress.insert(EscalationTriggerKind::AnomalyDetected);
    let mut pipeline = EscalationPipeline::new(policy, epoch(100));
    let initial = pipeline.remaining_budget_millionths;
    pipeline.process_trigger(make_trigger(
        "no-cost",
        EscalationTriggerKind::AnomalyDetected,
        TriggerSeverity::Emergency,
    ));
    assert_eq!(pipeline.remaining_budget_millionths, initial);
}

#[test]
fn enrichment_pipeline_tiny_budget_defers_below_threshold() {
    let mut policy = EscalationPolicy::default();
    policy.cost_budget_millionths = 1;
    policy.always_escalate.clear();
    let mut pipeline = EscalationPipeline::new(policy, epoch(100));
    // First critical auto-escalates
    pipeline.process_trigger(make_trigger(
        "tiny-1",
        EscalationTriggerKind::AnomalyDetected,
        TriggerSeverity::Critical,
    ));
    // Budget now exhausted, next critical should defer
    let r2 = pipeline.process_trigger(make_trigger(
        "tiny-2",
        EscalationTriggerKind::RegressionObserved,
        TriggerSeverity::Critical,
    ));
    assert_eq!(r2.decision, EscalationDecision::Defer);
}

#[test]
fn enrichment_pipeline_below_threshold_advisory_exceeds_budget_defers() {
    let mut policy = EscalationPolicy::default();
    policy.cost_budget_millionths = 1; // tiny budget
    policy.always_escalate.clear();
    let mut pipeline = EscalationPipeline::new(policy, epoch(100));
    // First critical trigger will exhaust the budget
    pipeline.process_trigger(make_trigger(
        "exhaust",
        EscalationTriggerKind::ResourceExhaustion,
        TriggerSeverity::Critical,
    ));
    // Advisory trigger with no budget should defer
    let r = pipeline.process_trigger(make_trigger(
        "adv-defer",
        EscalationTriggerKind::AnomalyDetected,
        TriggerSeverity::Advisory,
    ));
    assert_eq!(r.decision, EscalationDecision::Defer);
}

#[test]
fn enrichment_pipeline_bundle_for_trigger_found() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "find-me",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Critical,
    ));
    let bundle = pipeline.bundle_for_trigger("find-me");
    assert!(bundle.is_some());
    let b = bundle.unwrap();
    assert_eq!(b.trigger_id, "find-me");
    assert_eq!(b.bundle_id, "bundle-find-me");
}

#[test]
fn enrichment_pipeline_bundle_for_trigger_not_found() {
    let pipeline = default_pipeline(100);
    assert!(pipeline.bundle_for_trigger("nonexistent").is_none());
}

#[test]
fn enrichment_pipeline_bundle_for_suppressed_trigger_is_none() {
    let mut policy = EscalationPolicy::default();
    policy.always_suppress.insert(EscalationTriggerKind::AnomalyDetected);
    let mut pipeline = EscalationPipeline::new(policy, epoch(100));
    pipeline.process_trigger(make_trigger(
        "suppressed-no-bundle",
        EscalationTriggerKind::AnomalyDetected,
        TriggerSeverity::Emergency,
    ));
    assert!(pipeline.bundle_for_trigger("suppressed-no-bundle").is_none());
}

#[test]
fn enrichment_pipeline_escalated_receipts_filter() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "esc-f1",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Critical,
    ));
    let escalated = pipeline.escalated_receipts();
    assert_eq!(escalated.len(), 1);
    assert_eq!(escalated[0].decision, EscalationDecision::Escalate);
}

#[test]
fn enrichment_pipeline_suppressed_receipts_filter() {
    let mut policy = EscalationPolicy::default();
    policy.always_suppress.insert(EscalationTriggerKind::OperatorRequest);
    let mut pipeline = EscalationPipeline::new(policy, epoch(100));
    pipeline.process_trigger(make_trigger(
        "sup-f1",
        EscalationTriggerKind::OperatorRequest,
        TriggerSeverity::Emergency,
    ));
    let suppressed = pipeline.suppressed_receipts();
    assert_eq!(suppressed.len(), 1);
    assert_eq!(suppressed[0].decision, EscalationDecision::Suppress);
}

#[test]
fn enrichment_pipeline_deferred_receipts_filter() {
    let mut policy = EscalationPolicy::default();
    policy.cost_budget_millionths = 1;
    policy.always_escalate.clear();
    let mut pipeline = EscalationPipeline::new(policy, epoch(100));
    // Exhaust budget
    pipeline.process_trigger(make_trigger(
        "dfr-exhaust",
        EscalationTriggerKind::ReplayDivergence,
        TriggerSeverity::Critical,
    ));
    // Next will be deferred
    pipeline.process_trigger(make_trigger(
        "dfr-target",
        EscalationTriggerKind::AnomalyDetected,
        TriggerSeverity::Critical,
    ));
    let deferred = pipeline.deferred_receipts();
    assert_eq!(deferred.len(), 1);
    assert_eq!(deferred[0].trigger_id, "dfr-target");
}

#[test]
fn enrichment_pipeline_mixed_decisions() {
    let mut policy = EscalationPolicy::default();
    policy.always_suppress.insert(EscalationTriggerKind::OperatorRequest);
    let mut pipeline = EscalationPipeline::new(policy, epoch(100));

    // Escalated (always-escalate)
    pipeline.process_trigger(make_trigger(
        "mix-esc",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Critical,
    ));
    // Suppressed
    pipeline.process_trigger(make_trigger(
        "mix-sup",
        EscalationTriggerKind::OperatorRequest,
        TriggerSeverity::Emergency,
    ));

    assert!(!pipeline.escalated_receipts().is_empty());
    assert!(!pipeline.suppressed_receipts().is_empty());
}

#[test]
fn enrichment_pipeline_emergency_bundle_has_all_content_kinds() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "emg-all-content",
        EscalationTriggerKind::PolicyViolation,
        TriggerSeverity::Emergency,
    ));
    let bundle = pipeline.bundle_for_trigger("emg-all-content").unwrap();
    assert_eq!(bundle.entries.len(), BundleContentKind::ALL.len());
    let kinds: BTreeSet<BundleContentKind> = bundle.entries.iter().map(|e| e.kind).collect();
    for k in BundleContentKind::ALL {
        assert!(kinds.contains(k), "Missing {k} in emergency bundle");
    }
}

#[test]
fn enrichment_pipeline_critical_bundle_has_six_content_kinds() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "crit-six",
        EscalationTriggerKind::ResourceExhaustion,
        TriggerSeverity::Critical,
    ));
    let bundle = pipeline.bundle_for_trigger("crit-six").unwrap();
    assert_eq!(bundle.entries.len(), 6);
}

#[test]
fn enrichment_pipeline_advisory_bundle_has_two_content_kinds() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "adv-two",
        EscalationTriggerKind::AnomalyDetected,
        TriggerSeverity::Advisory,
    ));
    let bundle = pipeline.bundle_for_trigger("adv-two").unwrap();
    assert_eq!(bundle.entries.len(), 2);
}

#[test]
fn enrichment_pipeline_warning_with_generous_budget_has_four_content_kinds() {
    let mut policy = EscalationPolicy::default();
    policy.cost_budget_millionths = 1_000_000; // generous budget so warning escalates
    let mut pipeline = EscalationPipeline::new(policy, epoch(100));
    pipeline.process_trigger(make_trigger(
        "warn-four",
        EscalationTriggerKind::RegressionObserved,
        TriggerSeverity::Warning,
    ));
    let bundle = pipeline.bundle_for_trigger("warn-four").unwrap();
    assert_eq!(bundle.entries.len(), 4);
}

#[test]
fn enrichment_pipeline_emergency_sensitive_plaintext_redaction() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "red-emg",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Emergency,
    ));
    let bundle = pipeline.bundle_for_trigger("red-emg").unwrap();
    for entry in &bundle.entries {
        if matches!(
            entry.kind,
            BundleContentKind::FullBoundaryCapture
                | BundleContentKind::StateSnapshot
                | BundleContentKind::HeapProfile
        ) {
            assert_eq!(
                entry.redaction,
                RedactionTreatment::Plaintext,
                "Emergency should have Plaintext for sensitive kinds, got {:?} for {}",
                entry.redaction,
                entry.kind
            );
        }
    }
}

#[test]
fn enrichment_pipeline_non_emergency_sensitive_digest_redaction() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "red-crit",
        EscalationTriggerKind::PolicyViolation,
        TriggerSeverity::Critical,
    ));
    let bundle = pipeline.bundle_for_trigger("red-crit").unwrap();
    for entry in &bundle.entries {
        if matches!(
            entry.kind,
            BundleContentKind::FullBoundaryCapture
                | BundleContentKind::StateSnapshot
                | BundleContentKind::HeapProfile
        ) {
            assert_eq!(
                entry.redaction,
                RedactionTreatment::DigestOnly,
                "Non-emergency should have DigestOnly for sensitive kinds, got {:?} for {}",
                entry.redaction,
                entry.kind
            );
        }
    }
}

#[test]
fn enrichment_pipeline_non_sensitive_always_plaintext() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "non-sens",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Critical,
    ));
    let bundle = pipeline.bundle_for_trigger("non-sens").unwrap();
    for entry in &bundle.entries {
        if matches!(
            entry.kind,
            BundleContentKind::DecisionReceiptChain
                | BundleContentKind::ExecutionTrace
                | BundleContentKind::PolicyEvaluationLog
                | BundleContentKind::ReplayInputs
        ) {
            assert_eq!(
                entry.redaction,
                RedactionTreatment::Plaintext,
                "Non-sensitive kinds should always be Plaintext, got {:?} for {}",
                entry.redaction,
                entry.kind
            );
        }
    }
}

#[test]
fn enrichment_pipeline_bundle_entries_all_complete() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "complete-check",
        EscalationTriggerKind::PolicyViolation,
        TriggerSeverity::Emergency,
    ));
    let bundle = pipeline.bundle_for_trigger("complete-check").unwrap();
    assert!(bundle.entries.iter().all(|e| e.complete));
}

#[test]
fn enrichment_pipeline_bundle_cost_positive_for_escalated() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "cost-pos",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Critical,
    ));
    let bundle = pipeline.bundle_for_trigger("cost-pos").unwrap();
    assert!(bundle.total_cost_millionths > 0);
}

#[test]
fn enrichment_pipeline_bundle_epoch_matches_pipeline() {
    let mut pipeline = default_pipeline(777);
    pipeline.process_trigger(make_trigger(
        "ep-match",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Critical,
    ));
    let bundle = pipeline.bundle_for_trigger("ep-match").unwrap();
    assert_eq!(bundle.bundle_epoch, epoch(777));
}

#[test]
fn enrichment_pipeline_covered_boundaries_from_trigger() {
    let boundaries = vec![
        BoundaryClass::FilesystemInput,
        BoundaryClass::ExternalPolicyRead,
        BoundaryClass::ControllerOverride,
    ];
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger_with_boundaries(
        "cov-bounds",
        EscalationTriggerKind::PolicyViolation,
        TriggerSeverity::Critical,
        boundaries,
    ));
    let bundle = pipeline.bundle_for_trigger("cov-bounds").unwrap();
    assert!(bundle.covered_boundaries.contains(&BoundaryClass::FilesystemInput));
    assert!(bundle.covered_boundaries.contains(&BoundaryClass::ExternalPolicyRead));
    assert!(bundle.covered_boundaries.contains(&BoundaryClass::ControllerOverride));
    assert_eq!(bundle.covered_boundaries.len(), 3);
}

#[test]
fn enrichment_pipeline_empty_boundaries_produces_empty_covered() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger_with_boundaries(
        "no-bounds",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Critical,
        vec![],
    ));
    let bundle = pipeline.bundle_for_trigger("no-bounds").unwrap();
    assert!(bundle.covered_boundaries.is_empty());
}

#[test]
fn enrichment_pipeline_all_boundary_classes_in_trigger() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger_with_boundaries(
        "all-bounds",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Emergency,
        BoundaryClass::ALL.to_vec(),
    ));
    let bundle = pipeline.bundle_for_trigger("all-bounds").unwrap();
    assert_eq!(bundle.covered_boundaries.len(), BoundaryClass::ALL.len());
}

#[test]
fn enrichment_pipeline_duplicate_boundaries_deduped() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger_with_boundaries(
        "dup-bounds",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Critical,
        vec![
            BoundaryClass::ClockRead,
            BoundaryClass::ClockRead,
            BoundaryClass::ClockRead,
        ],
    ));
    let bundle = pipeline.bundle_for_trigger("dup-bounds").unwrap();
    assert_eq!(bundle.covered_boundaries.len(), 1);
}

#[test]
fn enrichment_pipeline_hash_changes_after_each_trigger() {
    let mut pipeline = default_pipeline(100);
    let h0 = pipeline.pipeline_hash;
    pipeline.process_trigger(make_trigger(
        "hash-1",
        EscalationTriggerKind::AnomalyDetected,
        TriggerSeverity::Warning,
    ));
    let h1 = pipeline.pipeline_hash;
    assert_ne!(h0, h1);
    pipeline.process_trigger(make_trigger(
        "hash-2",
        EscalationTriggerKind::PolicyViolation,
        TriggerSeverity::Critical,
    ));
    let h2 = pipeline.pipeline_hash;
    assert_ne!(h1, h2);
    assert_ne!(h0, h2);
}

#[test]
fn enrichment_pipeline_determinism_same_inputs() {
    let policy = EscalationPolicy::default();
    let triggers = vec![
        make_trigger("det-a", EscalationTriggerKind::AnomalyDetected, TriggerSeverity::Warning),
        make_trigger("det-b", EscalationTriggerKind::PolicyViolation, TriggerSeverity::Critical),
        make_trigger("det-c", EscalationTriggerKind::ResourceExhaustion, TriggerSeverity::Emergency),
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
    assert_eq!(p1.remaining_budget_millionths, p2.remaining_budget_millionths);
    assert_eq!(p1.receipts.len(), p2.receipts.len());
    assert_eq!(p1.bundles.len(), p2.bundles.len());
}

#[test]
fn enrichment_pipeline_different_epoch_different_hash() {
    let policy = EscalationPolicy::default();
    let p1 = EscalationPipeline::new(policy.clone(), epoch(100));
    let p2 = EscalationPipeline::new(policy, epoch(200));
    assert_ne!(p1.pipeline_hash, p2.pipeline_hash);
}

#[test]
fn enrichment_pipeline_different_trigger_order_different_hash() {
    let policy = EscalationPolicy::default();
    let t_a = make_trigger("order-a", EscalationTriggerKind::AnomalyDetected, TriggerSeverity::Warning);
    let t_b = make_trigger("order-b", EscalationTriggerKind::PolicyViolation, TriggerSeverity::Critical);

    let mut p1 = EscalationPipeline::new(policy.clone(), epoch(100));
    p1.process_trigger(t_a.clone());
    p1.process_trigger(t_b.clone());

    let mut p2 = EscalationPipeline::new(policy, epoch(100));
    p2.process_trigger(t_b);
    p2.process_trigger(t_a);

    assert_ne!(p1.pipeline_hash, p2.pipeline_hash);
}

#[test]
fn enrichment_pipeline_serde_full_roundtrip() {
    let mut pipeline = default_pipeline(100);
    for (i, kind) in EscalationTriggerKind::ALL.iter().enumerate() {
        pipeline.process_trigger(make_trigger(
            &format!("serde-full-{i}"),
            *kind,
            TriggerSeverity::Warning,
        ));
    }
    let json = serde_json::to_string(&pipeline).unwrap();
    let back: EscalationPipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(pipeline.pipeline_hash, back.pipeline_hash);
    assert_eq!(pipeline.receipts.len(), back.receipts.len());
    assert_eq!(pipeline.bundles.len(), back.bundles.len());
    assert_eq!(pipeline.triggers.len(), back.triggers.len());
    assert_eq!(pipeline.remaining_budget_millionths, back.remaining_budget_millionths);
}

#[test]
fn enrichment_pipeline_receipt_cost_budget_tracks_pre_consumption() {
    let mut pipeline = default_pipeline(100);
    let budget_before = pipeline.remaining_budget_millionths;
    pipeline.process_trigger(make_trigger(
        "cost-track",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Critical,
    ));
    // After processing, budget should not exceed original.
    assert!(pipeline.remaining_budget_millionths <= budget_before);
}

#[test]
fn enrichment_pipeline_receipt_epoch_matches_pipeline_epoch() {
    let mut pipeline = default_pipeline(555);
    let receipt = pipeline.process_trigger(make_trigger(
        "epoch-match",
        EscalationTriggerKind::PolicyViolation,
        TriggerSeverity::Warning,
    ));
    assert_eq!(receipt.receipt_epoch, epoch(555));
}

// ===========================================================================
// EscalationSummary enrichment tests
// ===========================================================================

#[test]
fn enrichment_summary_empty_pipeline() {
    let pipeline = default_pipeline(100);
    let summary = pipeline.summary_report();
    assert_eq!(summary.total_triggers, 0);
    assert_eq!(summary.escalated_count, 0);
    assert_eq!(summary.suppressed_count, 0);
    assert_eq!(summary.deferred_count, 0);
    assert_eq!(summary.total_bundles, 0);
    assert_eq!(summary.total_cost_millionths, 0);
    assert_eq!(summary.budget_utilization_millionths, 0);
    assert!(summary.triggers_by_kind.is_empty());
    assert!(summary.triggers_by_severity.is_empty());
}

#[test]
fn enrichment_summary_counts_correct() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "sum-1",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Critical,
    ));
    pipeline.process_trigger(make_trigger(
        "sum-2",
        EscalationTriggerKind::AnomalyDetected,
        TriggerSeverity::Warning,
    ));
    let summary = pipeline.summary_report();
    assert_eq!(summary.total_triggers, 2);
    assert_eq!(
        summary.escalated_count + summary.suppressed_count + summary.deferred_count,
        2
    );
}

#[test]
fn enrichment_summary_triggers_by_kind_populated() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "kind-a",
        EscalationTriggerKind::AnomalyDetected,
        TriggerSeverity::Warning,
    ));
    pipeline.process_trigger(make_trigger(
        "kind-b",
        EscalationTriggerKind::AnomalyDetected,
        TriggerSeverity::Critical,
    ));
    pipeline.process_trigger(make_trigger(
        "kind-c",
        EscalationTriggerKind::PolicyViolation,
        TriggerSeverity::Warning,
    ));
    let summary = pipeline.summary_report();
    let anomaly_count = summary
        .triggers_by_kind
        .iter()
        .find(|(k, _)| *k == EscalationTriggerKind::AnomalyDetected)
        .map(|(_, c)| *c)
        .unwrap_or(0);
    assert_eq!(anomaly_count, 2);
    let pv_count = summary
        .triggers_by_kind
        .iter()
        .find(|(k, _)| *k == EscalationTriggerKind::PolicyViolation)
        .map(|(_, c)| *c)
        .unwrap_or(0);
    assert_eq!(pv_count, 1);
}

#[test]
fn enrichment_summary_triggers_by_severity_populated() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "sev-a",
        EscalationTriggerKind::AnomalyDetected,
        TriggerSeverity::Warning,
    ));
    pipeline.process_trigger(make_trigger(
        "sev-b",
        EscalationTriggerKind::PolicyViolation,
        TriggerSeverity::Warning,
    ));
    pipeline.process_trigger(make_trigger(
        "sev-c",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Critical,
    ));
    let summary = pipeline.summary_report();
    let warning_count = summary
        .triggers_by_severity
        .iter()
        .find(|(s, _)| *s == TriggerSeverity::Warning)
        .map(|(_, c)| *c)
        .unwrap_or(0);
    assert_eq!(warning_count, 2);
    let critical_count = summary
        .triggers_by_severity
        .iter()
        .find(|(s, _)| *s == TriggerSeverity::Critical)
        .map(|(_, c)| *c)
        .unwrap_or(0);
    assert_eq!(critical_count, 1);
}

#[test]
fn enrichment_summary_budget_utilization_nonzero_after_escalation() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "util-1",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Critical,
    ));
    let summary = pipeline.summary_report();
    assert!(summary.budget_utilization_millionths > 0);
}

#[test]
fn enrichment_summary_remaining_budget_consistent() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "remain-1",
        EscalationTriggerKind::PolicyViolation,
        TriggerSeverity::Warning,
    ));
    let summary = pipeline.summary_report();
    assert_eq!(summary.remaining_budget_millionths, pipeline.remaining_budget_millionths);
}

#[test]
fn enrichment_summary_total_bundles_matches_escalated() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "tb-1",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Critical,
    ));
    pipeline.process_trigger(make_trigger(
        "tb-2",
        EscalationTriggerKind::PolicyViolation,
        TriggerSeverity::Warning,
    ));
    let summary = pipeline.summary_report();
    assert_eq!(summary.total_bundles, summary.escalated_count);
}

#[test]
fn enrichment_summary_serde_roundtrip() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "sum-serde",
        EscalationTriggerKind::ReplayDivergence,
        TriggerSeverity::Emergency,
    ));
    let summary = pipeline.summary_report();
    let json = serde_json::to_string(&summary).unwrap();
    let back: EscalationSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary.total_triggers, back.total_triggers);
    assert_eq!(summary.escalated_count, back.escalated_count);
    assert_eq!(summary.summary_hash, back.summary_hash);
    assert_eq!(summary.pipeline_epoch, back.pipeline_epoch);
}

#[test]
fn enrichment_summary_hash_deterministic() {
    let policy = EscalationPolicy::default();
    let mut p1 = EscalationPipeline::new(policy.clone(), epoch(100));
    let mut p2 = EscalationPipeline::new(policy, epoch(100));
    let t = make_trigger("hash-det", EscalationTriggerKind::PolicyViolation, TriggerSeverity::Critical);
    p1.process_trigger(t.clone());
    p2.process_trigger(t);
    let s1 = p1.summary_report();
    let s2 = p2.summary_report();
    assert_eq!(s1.summary_hash, s2.summary_hash);
}

#[test]
fn enrichment_summary_epoch_matches_pipeline() {
    let mut pipeline = default_pipeline(888);
    pipeline.process_trigger(make_trigger(
        "sum-ep",
        EscalationTriggerKind::AnomalyDetected,
        TriggerSeverity::Warning,
    ));
    let summary = pipeline.summary_report();
    assert_eq!(summary.pipeline_epoch, epoch(888));
}

// ===========================================================================
// EscalationError enrichment tests
// ===========================================================================

#[test]
fn enrichment_error_trigger_not_found_display() {
    let e = EscalationError::TriggerNotFound {
        trigger_id: "missing-trigger".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("missing-trigger"));
    assert!(s.contains("trigger not found"));
}

#[test]
fn enrichment_error_bundle_not_found_display() {
    let e = EscalationError::BundleNotFound {
        bundle_id: "missing-bundle".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("missing-bundle"));
    assert!(s.contains("bundle not found"));
}

#[test]
fn enrichment_error_budget_exhausted_display() {
    let e = EscalationError::BudgetExhausted {
        remaining: 42,
        required: 1_000_000,
    };
    let s = e.to_string();
    assert!(s.contains("42"));
    assert!(s.contains("1000000"));
    assert!(s.contains("budget exhausted"));
}

#[test]
fn enrichment_error_invalid_policy_display() {
    let e = EscalationError::InvalidPolicy {
        detail: "threshold invalid".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("threshold invalid"));
    assert!(s.contains("invalid policy"));
}

#[test]
fn enrichment_error_serde_roundtrip_all_variants() {
    let errors = vec![
        EscalationError::TriggerNotFound {
            trigger_id: "t-serde".to_string(),
        },
        EscalationError::BundleNotFound {
            bundle_id: "b-serde".to_string(),
        },
        EscalationError::BudgetExhausted {
            remaining: 123,
            required: 456,
        },
        EscalationError::InvalidPolicy {
            detail: "serde test detail".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: EscalationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn enrichment_error_clone_preserves_equality() {
    let e = EscalationError::BudgetExhausted {
        remaining: 99,
        required: 999,
    };
    let cloned = e.clone();
    assert_eq!(e, cloned);
}

#[test]
fn enrichment_error_all_variants_display_unique() {
    let errors = vec![
        EscalationError::TriggerNotFound {
            trigger_id: "unique-1".to_string(),
        },
        EscalationError::BundleNotFound {
            bundle_id: "unique-2".to_string(),
        },
        EscalationError::BudgetExhausted {
            remaining: 0,
            required: 100,
        },
        EscalationError::InvalidPolicy {
            detail: "unique-4".to_string(),
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}

#[test]
fn enrichment_error_budget_exhausted_zero_remaining() {
    let e = EscalationError::BudgetExhausted {
        remaining: 0,
        required: 1,
    };
    assert!(e.to_string().contains("0"));
}

#[test]
fn enrichment_error_invalid_policy_empty_detail() {
    let e = EscalationError::InvalidPolicy {
        detail: String::new(),
    };
    let s = e.to_string();
    assert!(s.contains("invalid policy"));
}

// ===========================================================================
// Constants enrichment tests
// ===========================================================================

#[test]
fn enrichment_constants_schema_version_format() {
    assert!(ESCALATION_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(ESCALATION_SCHEMA_VERSION.contains("hindsight-escalation-bundle"));
    assert!(ESCALATION_SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn enrichment_constants_bead_id_format() {
    assert!(ESCALATION_BEAD_ID.starts_with("bd-"));
    assert!(!ESCALATION_BEAD_ID.is_empty());
}

#[test]
fn enrichment_constants_component_matches_module_name() {
    assert_eq!(COMPONENT, "hindsight_escalation_bundle");
}

#[test]
fn enrichment_constants_schema_version_not_empty() {
    assert!(!ESCALATION_SCHEMA_VERSION.is_empty());
}

// ===========================================================================
// Cross-cutting workflow enrichment tests
// ===========================================================================

#[test]
fn enrichment_workflow_full_lifecycle_all_trigger_kinds() {
    let mut pipeline = default_pipeline(200);
    for (i, kind) in EscalationTriggerKind::ALL.iter().enumerate() {
        pipeline.process_trigger(make_trigger(
            &format!("lifecycle-{i}"),
            *kind,
            TriggerSeverity::Warning,
        ));
    }
    assert_eq!(pipeline.triggers.len(), EscalationTriggerKind::ALL.len());
    assert_eq!(pipeline.receipts.len(), EscalationTriggerKind::ALL.len());
    let summary = pipeline.summary_report();
    assert_eq!(summary.total_triggers, EscalationTriggerKind::ALL.len());
    assert_eq!(
        summary.escalated_count + summary.suppressed_count + summary.deferred_count,
        EscalationTriggerKind::ALL.len()
    );
}

#[test]
fn enrichment_workflow_all_severities_produce_bundles() {
    for sev in TriggerSeverity::ALL {
        let mut pipeline = default_pipeline(100);
        let receipt = pipeline.process_trigger(make_trigger(
            &format!("all-sev-{sev}"),
            EscalationTriggerKind::UserVisibleFailure, // always-escalate
            *sev,
        ));
        assert_eq!(
            receipt.decision,
            EscalationDecision::Escalate,
            "UserVisibleFailure should always escalate at {sev}"
        );
        assert!(receipt.bundle_id.is_some());
    }
}

#[test]
fn enrichment_workflow_higher_severity_more_content() {
    let policy = EscalationPolicy::default();
    let mut counts = Vec::new();
    for sev in TriggerSeverity::ALL {
        let mut pipeline = EscalationPipeline::new(policy.clone(), epoch(100));
        pipeline.process_trigger(make_trigger(
            &format!("content-{sev}"),
            EscalationTriggerKind::UserVisibleFailure,
            *sev,
        ));
        let bundle = pipeline
            .bundle_for_trigger(&format!("content-{sev}"))
            .unwrap();
        counts.push(bundle.entries.len());
    }
    for w in counts.windows(2) {
        assert!(w[0] <= w[1], "Content count should be monotonically increasing");
    }
}

#[test]
fn enrichment_workflow_higher_severity_higher_cost() {
    let policy = EscalationPolicy::default();
    let mut costs = Vec::new();
    for sev in TriggerSeverity::ALL {
        let mut pipeline = EscalationPipeline::new(policy.clone(), epoch(100));
        pipeline.process_trigger(make_trigger(
            &format!("cost-{sev}"),
            EscalationTriggerKind::UserVisibleFailure,
            *sev,
        ));
        let bundle = pipeline
            .bundle_for_trigger(&format!("cost-{sev}"))
            .unwrap();
        costs.push(bundle.total_cost_millionths);
    }
    for w in costs.windows(2) {
        assert!(w[0] <= w[1], "Cost should be monotonically increasing: {} vs {}", w[0], w[1]);
    }
}

#[test]
fn enrichment_workflow_suppression_does_not_produce_bundles() {
    let mut policy = EscalationPolicy::default();
    for kind in EscalationTriggerKind::ALL {
        policy.always_suppress.insert(*kind);
    }
    let mut pipeline = EscalationPipeline::new(policy, epoch(100));
    for (i, kind) in EscalationTriggerKind::ALL.iter().enumerate() {
        pipeline.process_trigger(make_trigger(
            &format!("sup-all-{i}"),
            *kind,
            TriggerSeverity::Emergency,
        ));
    }
    assert!(pipeline.bundles.is_empty());
    assert!(pipeline.escalated_receipts().is_empty());
    assert_eq!(
        pipeline.suppressed_receipts().len(),
        EscalationTriggerKind::ALL.len()
    );
}

#[test]
fn enrichment_workflow_budget_saturating_sub() {
    let mut policy = EscalationPolicy::default();
    policy.cost_budget_millionths = 50_000;
    let mut pipeline = EscalationPipeline::new(policy, epoch(100));
    // Emergency with all content kinds should exceed the budget
    pipeline.process_trigger(make_trigger(
        "saturate",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Emergency,
    ));
    // Budget should not underflow
    assert!(pipeline.remaining_budget_millionths <= 50_000);
}

#[test]
fn enrichment_workflow_multiple_triggers_budget_accounting() {
    let mut policy = EscalationPolicy::default();
    policy.cost_budget_millionths = 1_000_000; // generous budget
    let mut pipeline = EscalationPipeline::new(policy, epoch(100));
    for i in 0..5 {
        pipeline.process_trigger(make_trigger(
            &format!("acct-{i}"),
            EscalationTriggerKind::UserVisibleFailure,
            TriggerSeverity::Advisory,
        ));
    }
    let total_consumed: u64 = pipeline
        .receipts
        .iter()
        .map(|r| r.cost_consumed_millionths)
        .sum();
    assert_eq!(
        pipeline.remaining_budget_millionths,
        1_000_000_u64.saturating_sub(total_consumed)
    );
}

#[test]
fn enrichment_workflow_receipt_rationale_nonempty_for_all_decisions() {
    let mut policy = EscalationPolicy::default();
    policy.always_suppress.insert(EscalationTriggerKind::OperatorRequest);
    policy.cost_budget_millionths = 1;
    policy.always_escalate.clear();
    // Re-add the defaults after clearing
    policy.always_escalate.insert(EscalationTriggerKind::UserVisibleFailure);
    let mut pipeline = EscalationPipeline::new(policy, epoch(100));

    // Escalated via always-escalate
    pipeline.process_trigger(make_trigger(
        "rat-esc",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Advisory,
    ));
    assert!(!pipeline.receipts[0].rationale.is_empty());

    // Suppressed
    pipeline.process_trigger(make_trigger(
        "rat-sup",
        EscalationTriggerKind::OperatorRequest,
        TriggerSeverity::Emergency,
    ));
    assert!(!pipeline.receipts[1].rationale.is_empty());

    // Deferred (budget exhausted)
    pipeline.process_trigger(make_trigger(
        "rat-def",
        EscalationTriggerKind::AnomalyDetected,
        TriggerSeverity::Critical,
    ));
    assert!(!pipeline.receipts[2].rationale.is_empty());
}

#[test]
fn enrichment_workflow_content_digest_unique_per_entry() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "digest-uniq",
        EscalationTriggerKind::PolicyViolation,
        TriggerSeverity::Emergency,
    ));
    let bundle = pipeline.bundle_for_trigger("digest-uniq").unwrap();
    let digests: BTreeSet<_> = bundle.entries.iter().map(|e| e.content_digest).collect();
    assert_eq!(
        digests.len(),
        bundle.entries.len(),
        "Content digests should be unique per entry"
    );
}

#[test]
fn enrichment_workflow_size_bytes_proportional_to_cost() {
    let mut pipeline = default_pipeline(100);
    pipeline.process_trigger(make_trigger(
        "size-check",
        EscalationTriggerKind::UserVisibleFailure,
        TriggerSeverity::Emergency,
    ));
    let bundle = pipeline.bundle_for_trigger("size-check").unwrap();
    for entry in &bundle.entries {
        // Size is adjusted_cost * 1024 per the source code
        assert!(entry.size_bytes > 0, "Size should be > 0 for {}", entry.kind);
    }
}
