//! Integration tests for the resource certificate consumer module.
//!
//! Validates end-to-end budget enforcement flows: certificate installation,
//! multi-scope enforcement, throttle/reject behavior, receipt auditing,
//! and manifest generation.

use frankenengine_engine::resource_certificate_consumer::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(10)
}

fn certified_digest(cert_id: &str) -> CertificateDigest {
    CertificateDigest {
        certificate_id: cert_id.to_string(),
        region_id: "region-main".to_string(),
        epoch: test_epoch(),
        verdict: CertificateVerdict::Certified,
        bounds: vec![
            ExtractedBound {
                dimension: EnforcedDimension::Time,
                upper_bound_millionths: 10_000_000,
                is_tight: true,
                confidence_millionths: 960_000,
            },
            ExtractedBound {
                dimension: EnforcedDimension::HeapMemory,
                upper_bound_millionths: 50_000_000,
                is_tight: false,
                confidence_millionths: 920_000,
            },
            ExtractedBound {
                dimension: EnforcedDimension::HostcallCount,
                upper_bound_millionths: 100_000_000,
                is_tight: true,
                confidence_millionths: 980_000,
            },
            ExtractedBound {
                dimension: EnforcedDimension::GcPressure,
                upper_bound_millionths: 20_000_000,
                is_tight: false,
                confidence_millionths: 910_000,
            },
            ExtractedBound {
                dimension: EnforcedDimension::ModuleLoadCount,
                upper_bound_millionths: 5_000_000,
                is_tight: true,
                confidence_millionths: 990_000,
            },
        ],
        abstention_count: 0,
        min_confidence_millionths: 910_000,
    }
}

fn make_enforcer() -> BudgetEnforcer {
    BudgetEnforcer::new(BudgetEnforcementPolicy::default(), test_epoch())
}

// ---------------------------------------------------------------------------
// End-to-end: certificate install + multi-scope enforcement
// ---------------------------------------------------------------------------

#[test]
fn test_e2e_scheduler_enforcement() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-web", certified_digest("cert-web"))
        .unwrap();

    // Multiple scheduler admissions.
    for _ in 0..5 {
        let r = enforcer.enforce(
            "ext-web",
            EnforcementScope::SchedulerAdmission {
                task_type: "ExtensionDispatch".to_string(),
            },
            &[(EnforcedDimension::Time, 1_000_000)],
        );
        assert!(matches!(r.decision, EnforcementDecision::Allow));
    }

    // Total time used: 5_000_000 of 10_000_000 = 50%.
    let state = enforcer.extension_state("ext-web").unwrap();
    let time_budget = state.budgets.get(&EnforcedDimension::Time).unwrap();
    assert_eq!(time_budget.current_usage_millionths, 5_000_000);
}

#[test]
fn test_e2e_gc_pacing_throttle() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-gc", certified_digest("cert-gc"))
        .unwrap();

    // Use 91% of GC pressure budget.
    let r = enforcer.enforce(
        "ext-gc",
        EnforcementScope::GcPacing {
            extension_id: "ext-gc".to_string(),
        },
        &[(EnforcedDimension::GcPressure, 18_200_001)],
    );
    assert!(matches!(r.decision, EnforcementDecision::Throttle { .. }));
    assert!(enforcer.is_throttled("ext-gc"));
}

#[test]
fn test_e2e_hostcall_exhaustion() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-hc", certified_digest("cert-hc"))
        .unwrap();

    // Exhaust hostcall budget.
    let r = enforcer.enforce(
        "ext-hc",
        EnforcementScope::HostcallInvocation {
            hostcall_id: "fs_read".to_string(),
        },
        &[(EnforcedDimension::HostcallCount, 100_000_001)],
    );
    assert!(matches!(
        r.decision,
        EnforcementDecision::Reject {
            reason: BudgetViolationReason::BudgetExceeded { .. }
        }
    ));
}

#[test]
fn test_e2e_module_load_gating() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-mod", certified_digest("cert-mod"))
        .unwrap();

    // Load modules within budget.
    for i in 0..4 {
        let r = enforcer.enforce(
            "ext-mod",
            EnforcementScope::ModuleLoad {
                specifier: format!("module-{}", i),
            },
            &[(EnforcedDimension::ModuleLoadCount, 1_000_000)],
        );
        assert!(matches!(r.decision, EnforcementDecision::Allow));
    }

    // Fifth load triggers throttle (4_000_000 / 5_000_000 = 80% + 1_000_000 more = 100%).
    let r = enforcer.enforce(
        "ext-mod",
        EnforcementScope::ModuleLoad {
            specifier: "module-4".to_string(),
        },
        &[(EnforcedDimension::ModuleLoadCount, 1_000_001)],
    );
    assert!(matches!(
        r.decision,
        EnforcementDecision::Reject { .. }
    ));
}

#[test]
fn test_e2e_specialization_admission() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-spec", certified_digest("cert-spec"))
        .unwrap();

    let r = enforcer.enforce(
        "ext-spec",
        EnforcementScope::SpecializationAdmission {
            receipt_id: "spec-001".to_string(),
        },
        &[
            (EnforcedDimension::Time, 500_000),
            (EnforcedDimension::HeapMemory, 2_000_000),
        ],
    );
    assert!(matches!(r.decision, EnforcementDecision::Allow));
}

// ---------------------------------------------------------------------------
// Multi-extension isolation
// ---------------------------------------------------------------------------

#[test]
fn test_multi_extension_isolation() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-a", certified_digest("cert-a"))
        .unwrap();
    enforcer
        .install_certificate("ext-b", certified_digest("cert-b"))
        .unwrap();

    // Exhaust ext-a time budget.
    enforcer.enforce(
        "ext-a",
        EnforcementScope::General {
            description: "heavy".to_string(),
        },
        &[(EnforcedDimension::Time, 9_500_000)],
    );

    // ext-b should still be fine.
    let r = enforcer.enforce(
        "ext-b",
        EnforcementScope::General {
            description: "light".to_string(),
        },
        &[(EnforcedDimension::Time, 1_000_000)],
    );
    assert!(matches!(r.decision, EnforcementDecision::Allow));
    assert!(enforcer.is_throttled("ext-a"));
    assert!(!enforcer.is_throttled("ext-b"));
}

// ---------------------------------------------------------------------------
// Certificate replacement
// ---------------------------------------------------------------------------

#[test]
fn test_certificate_replacement_resets_budgets() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-r", certified_digest("cert-1"))
        .unwrap();

    // Use some budget.
    enforcer.enforce(
        "ext-r",
        EnforcementScope::General {
            description: "use".to_string(),
        },
        &[(EnforcedDimension::Time, 5_000_000)],
    );

    // Install new certificate — resets budgets.
    enforcer
        .install_certificate("ext-r", certified_digest("cert-2"))
        .unwrap();

    let state = enforcer.extension_state("ext-r").unwrap();
    let time_budget = state.budgets.get(&EnforcedDimension::Time).unwrap();
    assert_eq!(time_budget.current_usage_millionths, 0);
}

// ---------------------------------------------------------------------------
// Receipt auditing
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_sequence_monotonic() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-seq", certified_digest("cert-seq"))
        .unwrap();

    let r1 = enforcer.enforce(
        "ext-seq",
        EnforcementScope::General {
            description: "op1".to_string(),
        },
        &[(EnforcedDimension::Time, 1_000)],
    );
    let r2 = enforcer.enforce(
        "ext-seq",
        EnforcementScope::General {
            description: "op2".to_string(),
        },
        &[(EnforcedDimension::Time, 1_000)],
    );
    assert!(r2.decision_sequence > r1.decision_sequence);
}

#[test]
fn test_receipt_contains_budget_snapshots() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-snap", certified_digest("cert-snap"))
        .unwrap();

    let r = enforcer.enforce(
        "ext-snap",
        EnforcementScope::General {
            description: "test".to_string(),
        },
        &[(EnforcedDimension::Time, 1_000)],
    );
    assert!(!r.budget_snapshot.is_empty());
    assert!(r.budget_snapshot.iter().any(|s| s.dimension == EnforcedDimension::Time));
}

#[test]
fn test_receipt_references_certificate() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-ref", certified_digest("cert-ref"))
        .unwrap();

    let r = enforcer.enforce(
        "ext-ref",
        EnforcementScope::General {
            description: "test".to_string(),
        },
        &[(EnforcedDimension::Time, 1_000)],
    );
    assert_eq!(r.certificate_id, Some("cert-ref".to_string()));
}

#[test]
fn test_receipt_unique_ids() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-uid", certified_digest("cert-uid"))
        .unwrap();

    let r1 = enforcer.enforce(
        "ext-uid",
        EnforcementScope::General {
            description: "op1".to_string(),
        },
        &[(EnforcedDimension::Time, 1_000)],
    );
    let r2 = enforcer.enforce(
        "ext-uid",
        EnforcementScope::General {
            description: "op2".to_string(),
        },
        &[(EnforcedDimension::Time, 1_000)],
    );
    assert_ne!(r1.receipt_id, r2.receipt_id);
    assert_ne!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// Manifest generation
// ---------------------------------------------------------------------------

#[test]
fn test_manifest_captures_state() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-m1", certified_digest("cert-m1"))
        .unwrap();
    enforcer
        .install_certificate("ext-m2", certified_digest("cert-m2"))
        .unwrap();

    enforcer.enforce(
        "ext-m1",
        EnforcementScope::General {
            description: "op1".to_string(),
        },
        &[(EnforcedDimension::Time, 1_000)],
    );
    enforcer.enforce(
        "ext-m2",
        EnforcementScope::General {
            description: "op2".to_string(),
        },
        &[(EnforcedDimension::Time, 2_000)],
    );

    let manifest = ResourceConsumerManifest::from_enforcer(&enforcer);
    assert_eq!(manifest.extension_states.len(), 2);
    assert_eq!(manifest.receipts.len(), 2);
    assert_eq!(manifest.summary.total_allow, 2);
    assert_eq!(manifest.summary.extension_count, 2);
}

#[test]
fn test_manifest_schema_version() {
    let enforcer = make_enforcer();
    let manifest = ResourceConsumerManifest::from_enforcer(&enforcer);
    assert_eq!(manifest.schema_version, ENFORCEMENT_SCHEMA_VERSION);
    assert_eq!(manifest.component, COMPONENT);
}

// ---------------------------------------------------------------------------
// Fail-closed behavior
// ---------------------------------------------------------------------------

#[test]
fn test_fail_closed_no_certificate() {
    let enforcer = make_enforcer();
    // No certificate installed — should reject.
    let mut enforcer = enforcer;
    let r = enforcer.enforce(
        "ext-unknown",
        EnforcementScope::General {
            description: "test".to_string(),
        },
        &[(EnforcedDimension::Time, 1_000)],
    );
    assert!(matches!(
        r.decision,
        EnforcementDecision::Reject {
            reason: BudgetViolationReason::NoCertificate { .. }
        }
    ));
}

#[test]
fn test_fail_open_no_certificate() {
    let mut policy = BudgetEnforcementPolicy::default();
    policy.fail_closed_on_missing = false;
    let mut enforcer = BudgetEnforcer::new(policy, test_epoch());

    let r = enforcer.enforce(
        "ext-unknown",
        EnforcementScope::General {
            description: "test".to_string(),
        },
        &[(EnforcedDimension::Time, 1_000)],
    );
    assert!(matches!(r.decision, EnforcementDecision::Allow));
}

#[test]
fn test_fail_closed_abstained() {
    let mut enforcer = make_enforcer();
    let mut digest = certified_digest("cert-abs");
    digest.verdict = CertificateVerdict::Abstained;
    digest.abstention_count = 5;
    let result = enforcer.install_certificate("ext-abs", digest);
    assert!(result.is_err());
}

#[test]
fn test_fail_closed_violated() {
    let mut enforcer = make_enforcer();
    let mut digest = certified_digest("cert-viol");
    digest.verdict = CertificateVerdict::Violated;
    let result = enforcer.install_certificate("ext-viol", digest);
    assert!(matches!(
        result,
        Err(BudgetViolationReason::CertificateViolated { .. })
    ));
}

// ---------------------------------------------------------------------------
// Dimension-specific enforcement
// ---------------------------------------------------------------------------

#[test]
fn test_dimension_specific_enforcement() {
    let mut policy = BudgetEnforcementPolicy::default();
    policy.enforced_dimensions.insert(EnforcedDimension::Time);
    let mut enforcer = BudgetEnforcer::new(policy, test_epoch());
    enforcer
        .install_certificate("ext-dim", certified_digest("cert-dim"))
        .unwrap();

    // Time over budget — should reject.
    let r1 = enforcer.enforce(
        "ext-dim",
        EnforcementScope::General {
            description: "time".to_string(),
        },
        &[(EnforcedDimension::Time, 10_000_001)],
    );
    assert!(matches!(r1.decision, EnforcementDecision::Reject { .. }));
}

#[test]
fn test_non_enforced_dimension_ignored() {
    let mut policy = BudgetEnforcementPolicy::default();
    policy.enforced_dimensions.insert(EnforcedDimension::Time);
    let mut enforcer = BudgetEnforcer::new(policy, test_epoch());
    enforcer
        .install_certificate("ext-dim2", certified_digest("cert-dim2"))
        .unwrap();

    // HeapMemory not enforced — should allow even if over.
    let r = enforcer.enforce(
        "ext-dim2",
        EnforcementScope::General {
            description: "heap".to_string(),
        },
        &[(EnforcedDimension::HeapMemory, 999_999_999)],
    );
    assert!(matches!(r.decision, EnforcementDecision::Allow));
}

// ---------------------------------------------------------------------------
// Epoch validation
// ---------------------------------------------------------------------------

#[test]
fn test_future_epoch_rejected() {
    let mut enforcer = make_enforcer();
    let mut digest = certified_digest("cert-future");
    digest.epoch = SecurityEpoch::from_raw(100);
    let result = enforcer.install_certificate("ext-future", digest);
    assert!(matches!(
        result,
        Err(BudgetViolationReason::EpochMismatch { .. })
    ));
}

#[test]
fn test_past_epoch_accepted() {
    let mut enforcer = make_enforcer();
    let mut digest = certified_digest("cert-past");
    digest.epoch = SecurityEpoch::from_raw(5);
    assert!(enforcer.install_certificate("ext-past", digest).is_ok());
}

// ---------------------------------------------------------------------------
// Summary statistics
// ---------------------------------------------------------------------------

#[test]
fn test_summary_mixed_decisions() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-mix", certified_digest("cert-mix"))
        .unwrap();

    // Allow.
    enforcer.enforce(
        "ext-mix",
        EnforcementScope::General {
            description: "ok".to_string(),
        },
        &[(EnforcedDimension::Time, 1_000)],
    );

    // Throttle (use 91% of heap).
    enforcer.enforce(
        "ext-mix",
        EnforcementScope::General {
            description: "heavy".to_string(),
        },
        &[(EnforcedDimension::HeapMemory, 45_500_001)],
    );

    let summary = enforcer.enforcement_summary();
    assert_eq!(summary.total_decisions, 2);
    // One allow + one throttle.
    assert!(summary.total_allow + summary.total_throttle == 2);
}

// ---------------------------------------------------------------------------
// Serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_manifest_serde_roundtrip() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-serde", certified_digest("cert-serde"))
        .unwrap();
    enforcer.enforce(
        "ext-serde",
        EnforcementScope::General {
            description: "test".to_string(),
        },
        &[(EnforcedDimension::Time, 1_000)],
    );

    let manifest = ResourceConsumerManifest::from_enforcer(&enforcer);
    let json = serde_json::to_string(&manifest).unwrap();
    let deserialized: ResourceConsumerManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, deserialized);
}

#[test]
fn test_receipt_serde_roundtrip() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-rs", certified_digest("cert-rs"))
        .unwrap();
    let receipt = enforcer.enforce(
        "ext-rs",
        EnforcementScope::General {
            description: "test".to_string(),
        },
        &[(EnforcedDimension::Time, 1_000)],
    );
    let json = serde_json::to_string(&receipt).unwrap();
    let deserialized: EnforcementReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, deserialized);
}

// ---------------------------------------------------------------------------
// Policy hash stability
// ---------------------------------------------------------------------------

#[test]
fn test_policy_hash_in_receipts() {
    let mut enforcer = make_enforcer();
    let expected_hash = enforcer.policy.policy_hash();
    enforcer
        .install_certificate("ext-ph", certified_digest("cert-ph"))
        .unwrap();
    let receipt = enforcer.enforce(
        "ext-ph",
        EnforcementScope::General {
            description: "test".to_string(),
        },
        &[(EnforcedDimension::Time, 1_000)],
    );
    assert_eq!(receipt.policy_hash, expected_hash);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_zero_usage_delta() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-zero", certified_digest("cert-zero"))
        .unwrap();
    let r = enforcer.enforce(
        "ext-zero",
        EnforcementScope::General {
            description: "noop".to_string(),
        },
        &[(EnforcedDimension::Time, 0)],
    );
    assert!(matches!(r.decision, EnforcementDecision::Allow));
}

#[test]
fn test_empty_usage_deltas() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-empty", certified_digest("cert-empty"))
        .unwrap();
    let r = enforcer.enforce(
        "ext-empty",
        EnforcementScope::General {
            description: "nothing".to_string(),
        },
        &[],
    );
    assert!(matches!(r.decision, EnforcementDecision::Allow));
}

#[test]
fn test_io_scope() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-io", certified_digest("cert-io"))
        .unwrap();
    let r = enforcer.enforce(
        "ext-io",
        EnforcementScope::IoOperation {
            operation_type: "file_write".to_string(),
        },
        &[(EnforcedDimension::Time, 500)],
    );
    assert!(matches!(r.decision, EnforcementDecision::Allow));
}

#[test]
fn test_certificate_digest_content_preserved() {
    let mut enforcer = make_enforcer();
    let digest = certified_digest("cert-content");
    enforcer
        .install_certificate("ext-content", digest.clone())
        .unwrap();

    let state = enforcer.extension_state("ext-content").unwrap();
    let active = state.active_certificate.as_ref().unwrap();
    assert_eq!(active.certificate_id, "cert-content");
    assert_eq!(active.region_id, "region-main");
    assert_eq!(active.verdict, CertificateVerdict::Certified);
    assert_eq!(active.bounds.len(), 5);
}

#[test]
fn test_extension_count() {
    let mut enforcer = make_enforcer();
    assert_eq!(enforcer.extension_count(), 0);
    enforcer
        .install_certificate("ext-1", certified_digest("c1"))
        .unwrap();
    assert_eq!(enforcer.extension_count(), 1);
    enforcer
        .install_certificate("ext-2", certified_digest("c2"))
        .unwrap();
    assert_eq!(enforcer.extension_count(), 2);
}

#[test]
fn test_provisional_certificate_accepted() {
    let mut enforcer = make_enforcer();
    let mut digest = certified_digest("cert-prov");
    digest.verdict = CertificateVerdict::Provisional;
    assert!(enforcer.install_certificate("ext-prov", digest).is_ok());
}

#[test]
fn test_low_confidence_rejected() {
    let mut enforcer = make_enforcer();
    let mut digest = certified_digest("cert-low");
    digest.min_confidence_millionths = 500_000;
    let result = enforcer.install_certificate("ext-low", digest);
    assert!(matches!(
        result,
        Err(BudgetViolationReason::InsufficientConfidence { .. })
    ));
}
