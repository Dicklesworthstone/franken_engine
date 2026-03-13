//! Enrichment integration tests for the resource certificate consumer module.
//!
//! Covers Display uniqueness, serde roundtrips for all enum variants and structs,
//! DimensionBudget arithmetic edge cases, BudgetEnforcer lifecycle and
//! determinism, manifest content hash stability, policy hash variation, and
//! receipt auditing invariants.

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

use frankenengine_engine::resource_certificate_consumer::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn general_scope(desc: &str) -> EnforcementScope {
    EnforcementScope::General {
        description: desc.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Display uniqueness — all enum variants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_enforced_dimension_display_unique_across_all_variants() {
    let dims = vec![
        EnforcedDimension::Time,
        EnforcedDimension::HeapMemory,
        EnforcedDimension::StackDepth,
        EnforcedDimension::HostcallCount,
        EnforcedDimension::GcPressure,
        EnforcedDimension::ModuleLoadCount,
        EnforcedDimension::IoOperationCount,
    ];
    let set: BTreeSet<String> = dims.iter().map(|d| d.to_string()).collect();
    assert_eq!(
        set.len(),
        7,
        "All 7 EnforcedDimension Display strings must be unique"
    );
}

#[test]
fn enrichment_certificate_verdict_display_unique_across_all_variants() {
    let verdicts = vec![
        CertificateVerdict::Certified,
        CertificateVerdict::Provisional,
        CertificateVerdict::Abstained,
        CertificateVerdict::Violated,
    ];
    let set: BTreeSet<String> = verdicts.iter().map(|v| v.to_string()).collect();
    assert_eq!(
        set.len(),
        4,
        "All 4 CertificateVerdict Display strings must be unique"
    );
}

#[test]
fn enrichment_enforcement_scope_display_unique_across_all_variants() {
    let scopes = vec![
        EnforcementScope::SchedulerAdmission {
            task_type: "T".to_string(),
        },
        EnforcementScope::GcPacing {
            extension_id: "T".to_string(),
        },
        EnforcementScope::ModuleLoad {
            specifier: "T".to_string(),
        },
        EnforcementScope::SpecializationAdmission {
            receipt_id: "T".to_string(),
        },
        EnforcementScope::HostcallInvocation {
            hostcall_id: "T".to_string(),
        },
        EnforcementScope::IoOperation {
            operation_type: "T".to_string(),
        },
        EnforcementScope::General {
            description: "T".to_string(),
        },
    ];
    let set: BTreeSet<String> = scopes.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        set.len(),
        7,
        "All 7 EnforcementScope Display strings must be unique"
    );
}

#[test]
fn enrichment_enforcement_decision_display_unique() {
    let decisions = vec![
        EnforcementDecision::Allow,
        EnforcementDecision::Throttle {
            usage_ratio_millionths: 950_000,
            dimension: EnforcedDimension::Time,
        },
        EnforcementDecision::Reject {
            reason: BudgetViolationReason::NoCertificate {
                extension_id: "x".to_string(),
            },
        },
    ];
    let set: BTreeSet<String> = decisions.iter().map(|d| d.to_string()).collect();
    assert_eq!(
        set.len(),
        3,
        "All 3 EnforcementDecision Display strings must be unique"
    );
}

#[test]
fn enrichment_budget_violation_reason_display_unique() {
    let reasons = vec![
        BudgetViolationReason::BudgetExceeded {
            dimension: EnforcedDimension::Time,
            usage_millionths: 200,
            bound_millionths: 100,
        },
        BudgetViolationReason::NoCertificate {
            extension_id: "e".to_string(),
        },
        BudgetViolationReason::CertificateAbstained {
            certificate_id: "c".to_string(),
            abstention_count: 1,
        },
        BudgetViolationReason::CertificateViolated {
            certificate_id: "c".to_string(),
        },
        BudgetViolationReason::InsufficientConfidence {
            certificate_id: "c".to_string(),
            actual_millionths: 400_000,
            required_millionths: 900_000,
        },
        BudgetViolationReason::EpochMismatch {
            certificate_epoch: 50,
            current_epoch: 10,
        },
        BudgetViolationReason::ExtensionLimitExceeded {
            current: 10,
            max: 10,
        },
        BudgetViolationReason::MultipleDimensionsExceeded {
            dimensions: vec![EnforcedDimension::Time],
        },
    ];
    let set: BTreeSet<String> = reasons.iter().map(|r| r.to_string()).collect();
    assert_eq!(
        set.len(),
        8,
        "All 8 BudgetViolationReason Display strings must be unique"
    );
}

// ---------------------------------------------------------------------------
// Serde roundtrip — every enum variant
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_enforced_dimension_all_variants() {
    let dims = vec![
        EnforcedDimension::Time,
        EnforcedDimension::HeapMemory,
        EnforcedDimension::StackDepth,
        EnforcedDimension::HostcallCount,
        EnforcedDimension::GcPressure,
        EnforcedDimension::ModuleLoadCount,
        EnforcedDimension::IoOperationCount,
    ];
    for dim in &dims {
        let json = serde_json::to_string(dim).unwrap();
        let back: EnforcedDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*dim, back);
    }
}

#[test]
fn enrichment_serde_certificate_verdict_all_variants() {
    let verdicts = vec![
        CertificateVerdict::Certified,
        CertificateVerdict::Provisional,
        CertificateVerdict::Abstained,
        CertificateVerdict::Violated,
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: CertificateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_serde_enforcement_scope_all_variants() {
    let scopes = vec![
        EnforcementScope::SchedulerAdmission {
            task_type: "TaskA".to_string(),
        },
        EnforcementScope::GcPacing {
            extension_id: "ext-gc".to_string(),
        },
        EnforcementScope::ModuleLoad {
            specifier: "lodash".to_string(),
        },
        EnforcementScope::SpecializationAdmission {
            receipt_id: "r-1".to_string(),
        },
        EnforcementScope::HostcallInvocation {
            hostcall_id: "fs_read".to_string(),
        },
        EnforcementScope::IoOperation {
            operation_type: "net_write".to_string(),
        },
        EnforcementScope::General {
            description: "health".to_string(),
        },
    ];
    for scope in &scopes {
        let json = serde_json::to_string(scope).unwrap();
        let back: EnforcementScope = serde_json::from_str(&json).unwrap();
        assert_eq!(*scope, back);
    }
}

#[test]
fn enrichment_serde_enforcement_decision_all_variants() {
    let decisions = vec![
        EnforcementDecision::Allow,
        EnforcementDecision::Throttle {
            usage_ratio_millionths: 910_000,
            dimension: EnforcedDimension::HeapMemory,
        },
        EnforcementDecision::Reject {
            reason: BudgetViolationReason::BudgetExceeded {
                dimension: EnforcedDimension::Time,
                usage_millionths: 11_000_000,
                bound_millionths: 10_000_000,
            },
        },
    ];
    for d in &decisions {
        let json = serde_json::to_string(d).unwrap();
        let back: EnforcementDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

#[test]
fn enrichment_serde_budget_violation_reason_all_variants() {
    let reasons = vec![
        BudgetViolationReason::BudgetExceeded {
            dimension: EnforcedDimension::GcPressure,
            usage_millionths: 30_000_000,
            bound_millionths: 20_000_000,
        },
        BudgetViolationReason::NoCertificate {
            extension_id: "ext-no".to_string(),
        },
        BudgetViolationReason::CertificateAbstained {
            certificate_id: "cert-abs".to_string(),
            abstention_count: 7,
        },
        BudgetViolationReason::CertificateViolated {
            certificate_id: "cert-viol".to_string(),
        },
        BudgetViolationReason::InsufficientConfidence {
            certificate_id: "cert-low".to_string(),
            actual_millionths: 400_000,
            required_millionths: 900_000,
        },
        BudgetViolationReason::EpochMismatch {
            certificate_epoch: 50,
            current_epoch: 10,
        },
        BudgetViolationReason::ExtensionLimitExceeded {
            current: 1024,
            max: 1024,
        },
        BudgetViolationReason::MultipleDimensionsExceeded {
            dimensions: vec![
                EnforcedDimension::Time,
                EnforcedDimension::StackDepth,
                EnforcedDimension::HostcallCount,
            ],
        },
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: BudgetViolationReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ---------------------------------------------------------------------------
// Serde roundtrip — key structs
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_extracted_bound_roundtrip() {
    let bound = ExtractedBound {
        dimension: EnforcedDimension::StackDepth,
        upper_bound_millionths: 500_000,
        is_tight: false,
        confidence_millionths: 850_000,
    };
    let json = serde_json::to_string(&bound).unwrap();
    let back: ExtractedBound = serde_json::from_str(&json).unwrap();
    assert_eq!(bound, back);
}

#[test]
fn enrichment_serde_dimension_budget_roundtrip() {
    let budget = DimensionBudget {
        dimension: EnforcedDimension::IoOperationCount,
        upper_bound_millionths: 200_000_000,
        is_tight: true,
        confidence_millionths: 970_000,
        current_usage_millionths: 50_000_000,
        source_certificate_id: "cert-io".to_string(),
        extension_id: "ext-io".to_string(),
    };
    let json = serde_json::to_string(&budget).unwrap();
    let back: DimensionBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(budget, back);
}

#[test]
fn enrichment_serde_dimension_budget_snapshot_roundtrip() {
    let snap = DimensionBudgetSnapshot {
        dimension: EnforcedDimension::GcPressure,
        upper_bound_millionths: 20_000_000,
        current_usage_millionths: 15_000_000,
        usage_ratio_millionths: 750_000,
    };
    let json = serde_json::to_string(&snap).unwrap();
    let back: DimensionBudgetSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap.dimension, back.dimension);
    assert_eq!(snap.upper_bound_millionths, back.upper_bound_millionths);
    assert_eq!(snap.current_usage_millionths, back.current_usage_millionths);
    assert_eq!(snap.usage_ratio_millionths, back.usage_ratio_millionths);
}

#[test]
fn enrichment_serde_certificate_digest_roundtrip() {
    let digest = certified_digest("cert-serde-full");
    let json = serde_json::to_string(&digest).unwrap();
    let back: CertificateDigest = serde_json::from_str(&json).unwrap();
    assert_eq!(digest, back);
}

#[test]
fn enrichment_serde_budget_enforcement_policy_roundtrip() {
    let mut policy = BudgetEnforcementPolicy::default();
    policy.throttle_threshold_millionths = 850_000;
    policy.reject_threshold_millionths = 950_000;
    policy.min_confidence_millionths = 800_000;
    policy.max_extensions = 512;
    policy.max_receipts = 2048;
    policy.fail_closed_on_missing = false;
    policy.fail_closed_on_abstention = false;
    policy.emit_violation_details = false;
    policy.enforced_dimensions.insert(EnforcedDimension::Time);
    policy
        .enforced_dimensions
        .insert(EnforcedDimension::HeapMemory);
    let json = serde_json::to_string(&policy).unwrap();
    let back: BudgetEnforcementPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

#[test]
fn enrichment_serde_extension_budget_state_roundtrip() {
    let mut state = ExtensionBudgetState::new("ext-serde".to_string());
    state.install_certificate(certified_digest("cert-state"));
    state.record_usage(EnforcedDimension::Time, 2_000_000);
    state.allow_count = 5;
    state.throttle_count = 1;
    state.reject_count = 2;
    let json = serde_json::to_string(&state).unwrap();
    let back: ExtensionBudgetState = serde_json::from_str(&json).unwrap();
    assert_eq!(state, back);
}

#[test]
fn enrichment_serde_enforcement_summary_roundtrip() {
    let summary = EnforcementSummary {
        extension_count: 5,
        total_decisions: 100,
        total_allow: 80,
        total_throttle: 15,
        total_reject: 5,
        receipts_retained: 50,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: EnforcementSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn enrichment_serde_resource_consumer_manifest_roundtrip() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-mr", certified_digest("cert-mr"))
        .unwrap();
    enforcer.enforce(
        "ext-mr",
        general_scope("op1"),
        &[(EnforcedDimension::Time, 1_000)],
    );
    enforcer.enforce(
        "ext-mr",
        general_scope("op2"),
        &[(EnforcedDimension::HeapMemory, 2_000)],
    );
    let manifest = ResourceConsumerManifest::from_enforcer(&enforcer);
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ResourceConsumerManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

// ---------------------------------------------------------------------------
// DimensionBudget arithmetic edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_dimension_budget_usage_ratio_at_zero_usage() {
    let budget = DimensionBudget {
        dimension: EnforcedDimension::Time,
        upper_bound_millionths: 10_000_000,
        is_tight: true,
        confidence_millionths: 950_000,
        current_usage_millionths: 0,
        source_certificate_id: "c".to_string(),
        extension_id: "e".to_string(),
    };
    assert_eq!(budget.usage_ratio_millionths(), 0);
    assert_eq!(budget.remaining_millionths(), 10_000_000);
    assert!(!budget.is_exhausted());
}

#[test]
fn enrichment_dimension_budget_usage_ratio_at_full() {
    let budget = DimensionBudget {
        dimension: EnforcedDimension::HeapMemory,
        upper_bound_millionths: 50_000_000,
        is_tight: false,
        confidence_millionths: 920_000,
        current_usage_millionths: 50_000_000,
        source_certificate_id: "c".to_string(),
        extension_id: "e".to_string(),
    };
    assert_eq!(budget.usage_ratio_millionths(), MILLIONTHS);
    assert_eq!(budget.remaining_millionths(), 0);
    assert!(budget.is_exhausted());
}

#[test]
fn enrichment_dimension_budget_usage_ratio_over_bound() {
    let budget = DimensionBudget {
        dimension: EnforcedDimension::HostcallCount,
        upper_bound_millionths: 10_000_000,
        is_tight: true,
        confidence_millionths: 980_000,
        current_usage_millionths: 15_000_000,
        source_certificate_id: "c".to_string(),
        extension_id: "e".to_string(),
    };
    assert!(budget.usage_ratio_millionths() > MILLIONTHS);
    assert!(budget.remaining_millionths() < 0);
    assert!(budget.is_exhausted());
}

#[test]
fn enrichment_dimension_budget_negative_bound_returns_millionths() {
    let budget = DimensionBudget {
        dimension: EnforcedDimension::GcPressure,
        upper_bound_millionths: -1,
        is_tight: false,
        confidence_millionths: 950_000,
        current_usage_millionths: 0,
        source_certificate_id: "c".to_string(),
        extension_id: "e".to_string(),
    };
    assert_eq!(budget.usage_ratio_millionths(), MILLIONTHS);
}

#[test]
fn enrichment_dimension_budget_negative_usage_clamped() {
    let budget = DimensionBudget {
        dimension: EnforcedDimension::Time,
        upper_bound_millionths: 10_000_000,
        is_tight: true,
        confidence_millionths: 950_000,
        current_usage_millionths: -5_000_000,
        source_certificate_id: "c".to_string(),
        extension_id: "e".to_string(),
    };
    // Negative usage is clamped to 0 for ratio computation.
    assert_eq!(budget.usage_ratio_millionths(), 0);
    // remaining_millionths uses raw saturating subtraction.
    assert_eq!(budget.remaining_millionths(), 15_000_000);
}

#[test]
fn enrichment_dimension_budget_record_usage_saturating() {
    let mut budget = DimensionBudget {
        dimension: EnforcedDimension::Time,
        upper_bound_millionths: 10_000_000,
        is_tight: true,
        confidence_millionths: 950_000,
        current_usage_millionths: i64::MAX - 10,
        source_certificate_id: "c".to_string(),
        extension_id: "e".to_string(),
    };
    budget.record_usage(100);
    assert_eq!(budget.current_usage_millionths, i64::MAX);
}

#[test]
fn enrichment_dimension_budget_record_usage_negative_delta() {
    let mut budget = DimensionBudget {
        dimension: EnforcedDimension::HeapMemory,
        upper_bound_millionths: 50_000_000,
        is_tight: false,
        confidence_millionths: 920_000,
        current_usage_millionths: 30_000_000,
        source_certificate_id: "c".to_string(),
        extension_id: "e".to_string(),
    };
    budget.record_usage(-10_000_000);
    assert_eq!(budget.current_usage_millionths, 20_000_000);
}

// ---------------------------------------------------------------------------
// DimensionBudgetSnapshot from_budget
// ---------------------------------------------------------------------------

#[test]
fn enrichment_dimension_budget_snapshot_from_budget_captures_ratio() {
    let budget = DimensionBudget {
        dimension: EnforcedDimension::ModuleLoadCount,
        upper_bound_millionths: 5_000_000,
        is_tight: true,
        confidence_millionths: 990_000,
        current_usage_millionths: 2_500_000,
        source_certificate_id: "c".to_string(),
        extension_id: "e".to_string(),
    };
    let snap = DimensionBudgetSnapshot::from_budget(&budget);
    assert_eq!(snap.dimension, EnforcedDimension::ModuleLoadCount);
    assert_eq!(snap.upper_bound_millionths, 5_000_000);
    assert_eq!(snap.current_usage_millionths, 2_500_000);
    assert_eq!(snap.usage_ratio_millionths, 500_000);
}

// ---------------------------------------------------------------------------
// ExtensionBudgetState lifecycle
// ---------------------------------------------------------------------------

#[test]
fn enrichment_extension_budget_state_new_has_no_certificate() {
    let state = ExtensionBudgetState::new("ext-new".to_string());
    assert_eq!(state.extension_id, "ext-new");
    assert!(state.active_certificate.is_none());
    assert!(state.budgets.is_empty());
    assert_eq!(state.allow_count, 0);
    assert_eq!(state.throttle_count, 0);
    assert_eq!(state.reject_count, 0);
    assert_eq!(state.total_decisions(), 0);
}

#[test]
fn enrichment_extension_budget_state_install_replaces_budgets() {
    let mut state = ExtensionBudgetState::new("ext-rep".to_string());
    let d1 = certified_digest("cert-1");
    state.install_certificate(d1);
    assert_eq!(state.budgets.len(), 5);
    state.record_usage(EnforcedDimension::Time, 3_000_000);

    // Install new certificate - budgets reset.
    let d2 = CertificateDigest {
        certificate_id: "cert-2".to_string(),
        region_id: "region-alt".to_string(),
        epoch: test_epoch(),
        verdict: CertificateVerdict::Certified,
        bounds: vec![ExtractedBound {
            dimension: EnforcedDimension::Time,
            upper_bound_millionths: 20_000_000,
            is_tight: true,
            confidence_millionths: 960_000,
        }],
        abstention_count: 0,
        min_confidence_millionths: 960_000,
    };
    state.install_certificate(d2);
    assert_eq!(state.budgets.len(), 1);
    let time_budget = state.budgets.get(&EnforcedDimension::Time).unwrap();
    assert_eq!(time_budget.current_usage_millionths, 0);
    assert_eq!(time_budget.upper_bound_millionths, 20_000_000);
}

#[test]
fn enrichment_extension_budget_state_record_usage_unknown_dim_noop() {
    let mut state = ExtensionBudgetState::new("ext-noop".to_string());
    let d = CertificateDigest {
        certificate_id: "cert-small".to_string(),
        region_id: "r".to_string(),
        epoch: test_epoch(),
        verdict: CertificateVerdict::Certified,
        bounds: vec![ExtractedBound {
            dimension: EnforcedDimension::Time,
            upper_bound_millionths: 10_000_000,
            is_tight: true,
            confidence_millionths: 960_000,
        }],
        abstention_count: 0,
        min_confidence_millionths: 960_000,
    };
    state.install_certificate(d);
    // Recording usage for a dimension not in bounds is a no-op.
    state.record_usage(EnforcedDimension::HeapMemory, 999_999_999);
    assert!(state.budgets.get(&EnforcedDimension::HeapMemory).is_none());
}

#[test]
fn enrichment_extension_budget_state_total_decisions_accumulates() {
    let mut state = ExtensionBudgetState::new("ext-td".to_string());
    state.allow_count = 10;
    state.throttle_count = 3;
    state.reject_count = 2;
    assert_eq!(state.total_decisions(), 15);
}

// ---------------------------------------------------------------------------
// BudgetEnforcementPolicy
// ---------------------------------------------------------------------------

#[test]
fn enrichment_policy_default_values() {
    let p = BudgetEnforcementPolicy::default();
    assert_eq!(
        p.throttle_threshold_millionths,
        DEFAULT_THROTTLE_THRESHOLD_MILLIONTHS
    );
    assert_eq!(
        p.reject_threshold_millionths,
        DEFAULT_REJECT_THRESHOLD_MILLIONTHS
    );
    assert_eq!(
        p.min_confidence_millionths,
        DEFAULT_MIN_CONFIDENCE_MILLIONTHS
    );
    assert_eq!(p.max_extensions, DEFAULT_MAX_EXTENSIONS);
    assert_eq!(p.max_receipts, DEFAULT_MAX_RECEIPTS);
    assert!(p.enforced_dimensions.is_empty());
    assert!(p.fail_closed_on_missing);
    assert!(p.fail_closed_on_abstention);
    assert!(p.emit_violation_details);
}

#[test]
fn enrichment_policy_should_enforce_all_when_empty() {
    let p = BudgetEnforcementPolicy::default();
    let all_dims = vec![
        EnforcedDimension::Time,
        EnforcedDimension::HeapMemory,
        EnforcedDimension::StackDepth,
        EnforcedDimension::HostcallCount,
        EnforcedDimension::GcPressure,
        EnforcedDimension::ModuleLoadCount,
        EnforcedDimension::IoOperationCount,
    ];
    for dim in &all_dims {
        assert!(
            p.should_enforce(*dim),
            "should_enforce all dims when set is empty"
        );
    }
}

#[test]
fn enrichment_policy_should_enforce_specific_only() {
    let mut p = BudgetEnforcementPolicy::default();
    p.enforced_dimensions.insert(EnforcedDimension::Time);
    p.enforced_dimensions
        .insert(EnforcedDimension::HostcallCount);
    assert!(p.should_enforce(EnforcedDimension::Time));
    assert!(p.should_enforce(EnforcedDimension::HostcallCount));
    assert!(!p.should_enforce(EnforcedDimension::HeapMemory));
    assert!(!p.should_enforce(EnforcedDimension::GcPressure));
    assert!(!p.should_enforce(EnforcedDimension::ModuleLoadCount));
    assert!(!p.should_enforce(EnforcedDimension::IoOperationCount));
    assert!(!p.should_enforce(EnforcedDimension::StackDepth));
}

#[test]
fn enrichment_policy_hash_length_is_64_hex_chars() {
    let p = BudgetEnforcementPolicy::default();
    let hash = p.policy_hash();
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn enrichment_policy_hash_varies_with_reject_threshold() {
    let p1 = BudgetEnforcementPolicy::default();
    let mut p2 = BudgetEnforcementPolicy::default();
    p2.reject_threshold_millionths = 950_000;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn enrichment_policy_hash_varies_with_max_extensions() {
    let p1 = BudgetEnforcementPolicy::default();
    let mut p2 = BudgetEnforcementPolicy::default();
    p2.max_extensions = 512;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn enrichment_policy_hash_varies_with_fail_closed_on_missing() {
    let p1 = BudgetEnforcementPolicy::default();
    let mut p2 = BudgetEnforcementPolicy::default();
    p2.fail_closed_on_missing = false;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn enrichment_policy_hash_varies_with_fail_closed_on_abstention() {
    let p1 = BudgetEnforcementPolicy::default();
    let mut p2 = BudgetEnforcementPolicy::default();
    p2.fail_closed_on_abstention = false;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn enrichment_policy_hash_varies_with_min_confidence() {
    let p1 = BudgetEnforcementPolicy::default();
    let mut p2 = BudgetEnforcementPolicy::default();
    p2.min_confidence_millionths = 700_000;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn enrichment_policy_hash_varies_with_max_receipts() {
    let p1 = BudgetEnforcementPolicy::default();
    let mut p2 = BudgetEnforcementPolicy::default();
    p2.max_receipts = 100;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

// ---------------------------------------------------------------------------
// BudgetEnforcer — install_certificate validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_install_exact_epoch_accepted() {
    let mut enforcer = make_enforcer();
    let mut digest = certified_digest("cert-exact");
    digest.epoch = SecurityEpoch::from_raw(10); // equals current epoch
    assert!(enforcer.install_certificate("ext-exact", digest).is_ok());
}

#[test]
fn enrichment_install_epoch_zero_accepted() {
    let mut enforcer = make_enforcer();
    let mut digest = certified_digest("cert-e0");
    digest.epoch = SecurityEpoch::from_raw(0);
    assert!(enforcer.install_certificate("ext-e0", digest).is_ok());
}

#[test]
fn enrichment_install_violated_error_contains_certificate_id() {
    let mut enforcer = make_enforcer();
    let mut digest = certified_digest("cert-bad-id");
    digest.verdict = CertificateVerdict::Violated;
    match enforcer.install_certificate("ext-bad", digest) {
        Err(BudgetViolationReason::CertificateViolated { certificate_id }) => {
            assert_eq!(certificate_id, "cert-bad-id");
        }
        other => panic!("Expected CertificateViolated, got {:?}", other),
    }
}

#[test]
fn enrichment_install_low_confidence_error_has_thresholds() {
    let mut enforcer = make_enforcer();
    let mut digest = certified_digest("cert-lc");
    digest.min_confidence_millionths = 100_000;
    match enforcer.install_certificate("ext-lc", digest) {
        Err(BudgetViolationReason::InsufficientConfidence {
            actual_millionths,
            required_millionths,
            ..
        }) => {
            assert_eq!(actual_millionths, 100_000);
            assert_eq!(required_millionths, DEFAULT_MIN_CONFIDENCE_MILLIONTHS);
        }
        other => panic!("Expected InsufficientConfidence, got {:?}", other),
    }
}

#[test]
fn enrichment_install_abstained_with_fail_open_succeeds() {
    let policy = BudgetEnforcementPolicy {
        fail_closed_on_abstention: false,
        ..BudgetEnforcementPolicy::default()
    };
    let mut enforcer = BudgetEnforcer::new(policy, test_epoch());
    let mut digest = certified_digest("cert-abs");
    digest.verdict = CertificateVerdict::Abstained;
    digest.abstention_count = 10;
    assert!(enforcer.install_certificate("ext-abs", digest).is_ok());
}

#[test]
fn enrichment_install_replaces_same_extension() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-r", certified_digest("cert-1"))
        .unwrap();
    enforcer.enforce(
        "ext-r",
        general_scope("op"),
        &[(EnforcedDimension::Time, 5_000_000)],
    );
    // Replace certificate.
    enforcer
        .install_certificate("ext-r", certified_digest("cert-2"))
        .unwrap();
    assert_eq!(enforcer.extension_count(), 1);
    let state = enforcer.extension_state("ext-r").unwrap();
    let time_budget = state.budgets.get(&EnforcedDimension::Time).unwrap();
    assert_eq!(time_budget.current_usage_millionths, 0);
    assert_eq!(
        state.active_certificate.as_ref().unwrap().certificate_id,
        "cert-2"
    );
}

#[test]
fn enrichment_install_extension_limit_error_has_counts() {
    let mut policy = BudgetEnforcementPolicy::default();
    policy.max_extensions = 1;
    let mut enforcer = BudgetEnforcer::new(policy, test_epoch());
    enforcer
        .install_certificate("ext-a", certified_digest("c-a"))
        .unwrap();
    match enforcer.install_certificate("ext-b", certified_digest("c-b")) {
        Err(BudgetViolationReason::ExtensionLimitExceeded { current, max }) => {
            assert_eq!(current, 1);
            assert_eq!(max, 1);
        }
        other => panic!("Expected ExtensionLimitExceeded, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// BudgetEnforcer — enforce decision logic
// ---------------------------------------------------------------------------

#[test]
fn enrichment_enforce_no_cert_fail_closed_receipt_structure() {
    let mut enforcer = make_enforcer();
    let receipt = enforcer.enforce(
        "ext-missing",
        general_scope("test"),
        &[(EnforcedDimension::Time, 1_000)],
    );
    assert!(receipt.receipt_id.starts_with("erc-"));
    assert_eq!(receipt.extension_id, "ext-missing");
    assert!(receipt.certificate_id.is_none());
    assert!(receipt.budget_snapshot.is_empty());
    assert_eq!(receipt.decision_epoch, test_epoch());
    assert!(matches!(
        receipt.decision,
        EnforcementDecision::Reject {
            reason: BudgetViolationReason::NoCertificate { .. }
        }
    ));
}

#[test]
fn enrichment_enforce_empty_deltas_always_allow() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-empty", certified_digest("c-empty"))
        .unwrap();
    let receipt = enforcer.enforce("ext-empty", general_scope("noop"), &[]);
    assert!(matches!(receipt.decision, EnforcementDecision::Allow));
}

#[test]
fn enrichment_enforce_zero_deltas_always_allow() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-z", certified_digest("c-z"))
        .unwrap();
    let receipt = enforcer.enforce(
        "ext-z",
        general_scope("zero"),
        &[
            (EnforcedDimension::Time, 0),
            (EnforcedDimension::HeapMemory, 0),
        ],
    );
    assert!(matches!(receipt.decision, EnforcementDecision::Allow));
}

#[test]
fn enrichment_enforce_throttle_records_usage() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-th", certified_digest("c-th"))
        .unwrap();
    // Use 91% of Time (above 90% throttle threshold).
    let receipt = enforcer.enforce(
        "ext-th",
        general_scope("heavy"),
        &[(EnforcedDimension::Time, 9_100_001)],
    );
    assert!(matches!(
        receipt.decision,
        EnforcementDecision::Throttle { .. }
    ));
    // Usage is recorded on throttle (not rejected).
    let state = enforcer.extension_state("ext-th").unwrap();
    let time_budget = state.budgets.get(&EnforcedDimension::Time).unwrap();
    assert_eq!(time_budget.current_usage_millionths, 9_100_001);
    assert_eq!(state.throttle_count, 1);
}

#[test]
fn enrichment_enforce_reject_does_not_record_usage() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-rj", certified_digest("c-rj"))
        .unwrap();
    let receipt = enforcer.enforce(
        "ext-rj",
        general_scope("over"),
        &[(EnforcedDimension::Time, 10_000_001)],
    );
    assert!(matches!(
        receipt.decision,
        EnforcementDecision::Reject { .. }
    ));
    let state = enforcer.extension_state("ext-rj").unwrap();
    let time_budget = state.budgets.get(&EnforcedDimension::Time).unwrap();
    assert_eq!(time_budget.current_usage_millionths, 0);
    assert_eq!(state.reject_count, 1);
    assert_eq!(state.allow_count, 0);
}

#[test]
fn enrichment_enforce_non_enforced_dim_ignored_for_decision() {
    let mut policy = BudgetEnforcementPolicy::default();
    policy
        .enforced_dimensions
        .insert(EnforcedDimension::HeapMemory);
    let mut enforcer = BudgetEnforcer::new(policy, test_epoch());
    enforcer
        .install_certificate("ext-ne", certified_digest("c-ne"))
        .unwrap();

    // Time would exceed bounds, but Time is not enforced.
    let receipt = enforcer.enforce(
        "ext-ne",
        general_scope("skip-time"),
        &[(EnforcedDimension::Time, 99_999_999)],
    );
    assert!(matches!(receipt.decision, EnforcementDecision::Allow));
}

#[test]
fn enrichment_enforce_accumulates_across_multiple_calls() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-acc", certified_digest("c-acc"))
        .unwrap();

    // 80% of Time.
    enforcer.enforce(
        "ext-acc",
        general_scope("a"),
        &[(EnforcedDimension::Time, 8_000_000)],
    );
    // 11% more -> should throttle (91% total).
    let receipt = enforcer.enforce(
        "ext-acc",
        general_scope("b"),
        &[(EnforcedDimension::Time, 1_100_001)],
    );
    assert!(matches!(
        receipt.decision,
        EnforcementDecision::Throttle { .. }
    ));
}

// ---------------------------------------------------------------------------
// Receipt structure and auditing
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_sequence_starts_at_one() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-s1", certified_digest("c-s1"))
        .unwrap();
    let r = enforcer.enforce(
        "ext-s1",
        general_scope("first"),
        &[(EnforcedDimension::Time, 100)],
    );
    assert_eq!(r.decision_sequence, 1);
}

#[test]
fn enrichment_receipt_ids_differ_across_decisions() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-rd", certified_digest("c-rd"))
        .unwrap();
    let mut ids = BTreeSet::new();
    for i in 0..10 {
        let r = enforcer.enforce(
            "ext-rd",
            general_scope(&format!("op-{}", i)),
            &[(EnforcedDimension::Time, 100)],
        );
        ids.insert(r.receipt_id.clone());
    }
    assert_eq!(ids.len(), 10, "All 10 receipt IDs must be unique");
}

#[test]
fn enrichment_receipt_content_hashes_differ() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-ch", certified_digest("c-ch"))
        .unwrap();
    let r1 = enforcer.enforce(
        "ext-ch",
        general_scope("a"),
        &[(EnforcedDimension::Time, 100)],
    );
    let r2 = enforcer.enforce(
        "ext-ch",
        general_scope("b"),
        &[(EnforcedDimension::Time, 100)],
    );
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_receipt_display_contains_key_fields() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-df", certified_digest("c-df"))
        .unwrap();
    let r = enforcer.enforce(
        "ext-df",
        EnforcementScope::HostcallInvocation {
            hostcall_id: "net_connect".to_string(),
        },
        &[(EnforcedDimension::HostcallCount, 500)],
    );
    let display = r.to_string();
    assert!(display.contains("ext-df"));
    assert!(display.contains("hostcall"));
    assert!(display.contains("allow"));
    assert!(display.contains("epoch=10"));
    assert!(display.contains("erc-"));
}

#[test]
fn enrichment_receipt_serde_roundtrip_with_throttle_decision() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-thr", certified_digest("c-thr"))
        .unwrap();
    let receipt = enforcer.enforce(
        "ext-thr",
        general_scope("heavy"),
        &[(EnforcedDimension::Time, 9_100_001)],
    );
    assert!(matches!(
        receipt.decision,
        EnforcementDecision::Throttle { .. }
    ));
    let json = serde_json::to_string(&receipt).unwrap();
    let back: EnforcementReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn enrichment_receipt_serde_roundtrip_with_reject_decision() {
    let mut enforcer = make_enforcer();
    let receipt = enforcer.enforce(
        "ext-no-cert",
        general_scope("fail"),
        &[(EnforcedDimension::Time, 1_000)],
    );
    assert!(matches!(
        receipt.decision,
        EnforcementDecision::Reject { .. }
    ));
    let json = serde_json::to_string(&receipt).unwrap();
    let back: EnforcementReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// ---------------------------------------------------------------------------
// Receipt pruning
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_pruning_preserves_newest() {
    let mut policy = BudgetEnforcementPolicy::default();
    policy.max_receipts = 5;
    let mut enforcer = BudgetEnforcer::new(policy, test_epoch());
    enforcer
        .install_certificate("ext-pr", certified_digest("c-pr"))
        .unwrap();

    for i in 0..10 {
        enforcer.enforce(
            "ext-pr",
            general_scope(&format!("op-{}", i)),
            &[(EnforcedDimension::Time, 100)],
        );
    }
    let receipts = enforcer.all_receipts();
    assert_eq!(receipts.len(), 5);
    // Oldest sequences (1-5) pruned; newest (6-10) retained.
    assert_eq!(receipts[0].decision_sequence, 6);
    assert_eq!(receipts[4].decision_sequence, 10);
}

// ---------------------------------------------------------------------------
// Determinism tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_same_inputs_produce_same_receipt_hash() {
    let build_receipt = || {
        let mut enforcer = make_enforcer();
        enforcer
            .install_certificate("ext-det", certified_digest("c-det"))
            .unwrap();
        enforcer.enforce(
            "ext-det",
            EnforcementScope::SchedulerAdmission {
                task_type: "TaskRun".to_string(),
            },
            &[(EnforcedDimension::Time, 500)],
        )
    };
    let r1 = build_receipt();
    let r2 = build_receipt();
    assert_eq!(r1.content_hash, r2.content_hash);
    assert_eq!(r1.receipt_id, r2.receipt_id);
}

#[test]
fn enrichment_same_inputs_produce_same_manifest_hash() {
    let build_manifest = || {
        let mut enforcer = make_enforcer();
        enforcer
            .install_certificate("ext-dm", certified_digest("c-dm"))
            .unwrap();
        enforcer.enforce(
            "ext-dm",
            general_scope("op"),
            &[(EnforcedDimension::Time, 1_000)],
        );
        ResourceConsumerManifest::from_enforcer(&enforcer)
    };
    let m1 = build_manifest();
    let m2 = build_manifest();
    assert_eq!(m1.content_hash, m2.content_hash);
}

#[test]
fn enrichment_different_extension_id_produces_different_manifest_hash() {
    let mut e1 = make_enforcer();
    e1.install_certificate("ext-aaa", certified_digest("c1"))
        .unwrap();
    let m1 = ResourceConsumerManifest::from_enforcer(&e1);

    let mut e2 = make_enforcer();
    e2.install_certificate("ext-bbb", certified_digest("c2"))
        .unwrap();
    let m2 = ResourceConsumerManifest::from_enforcer(&e2);

    assert_ne!(m1.content_hash, m2.content_hash);
}

// ---------------------------------------------------------------------------
// Manifest structure
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_empty_enforcer() {
    let enforcer = make_enforcer();
    let manifest = ResourceConsumerManifest::from_enforcer(&enforcer);
    assert_eq!(manifest.schema_version, ENFORCEMENT_SCHEMA_VERSION);
    assert_eq!(manifest.component, COMPONENT);
    assert!(manifest.extension_states.is_empty());
    assert!(manifest.receipts.is_empty());
    assert_eq!(manifest.summary.extension_count, 0);
    assert_eq!(manifest.summary.total_decisions, 0);
    assert_eq!(manifest.summary.total_allow, 0);
    assert_eq!(manifest.summary.total_throttle, 0);
    assert_eq!(manifest.summary.total_reject, 0);
}

#[test]
fn enrichment_manifest_multiple_extensions_sorted() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-z", certified_digest("cz"))
        .unwrap();
    enforcer
        .install_certificate("ext-a", certified_digest("ca"))
        .unwrap();
    enforcer
        .install_certificate("ext-m", certified_digest("cm"))
        .unwrap();
    let manifest = ResourceConsumerManifest::from_enforcer(&enforcer);
    assert_eq!(manifest.extension_states.len(), 3);
    // BTreeMap ordering: ext-a, ext-m, ext-z.
    assert_eq!(manifest.extension_states[0].extension_id, "ext-a");
    assert_eq!(manifest.extension_states[1].extension_id, "ext-m");
    assert_eq!(manifest.extension_states[2].extension_id, "ext-z");
}

// ---------------------------------------------------------------------------
// Summary statistics
// ---------------------------------------------------------------------------

#[test]
fn enrichment_summary_counts_all_decision_types() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-sum", certified_digest("c-sum"))
        .unwrap();

    // Allow.
    enforcer.enforce(
        "ext-sum",
        general_scope("ok"),
        &[(EnforcedDimension::Time, 1_000)],
    );
    // Throttle (91% of GcPressure).
    enforcer.enforce(
        "ext-sum",
        general_scope("gc-heavy"),
        &[(EnforcedDimension::GcPressure, 18_200_001)],
    );
    // Reject (exceed HostcallCount).
    enforcer.enforce(
        "ext-sum",
        general_scope("hc-over"),
        &[(EnforcedDimension::HostcallCount, 100_000_001)],
    );

    let summary = enforcer.enforcement_summary();
    assert_eq!(summary.extension_count, 1);
    assert_eq!(summary.total_decisions, 3);
    assert_eq!(summary.total_allow, 1);
    assert_eq!(summary.total_throttle, 1);
    assert_eq!(summary.total_reject, 1);
    assert_eq!(summary.receipts_retained, 3);
}

// ---------------------------------------------------------------------------
// is_throttled / is_exhausted edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_is_throttled_false_for_unknown_extension() {
    let enforcer = make_enforcer();
    assert!(!enforcer.is_throttled("ext-unknown"));
}

#[test]
fn enrichment_is_exhausted_false_for_unknown_extension() {
    let enforcer = make_enforcer();
    assert!(!enforcer.is_exhausted("ext-unknown"));
}

#[test]
fn enrichment_is_throttled_tracks_worst_dimension() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-tw", certified_digest("c-tw"))
        .unwrap();

    // GcPressure at 91% -> throttle zone.
    enforcer.enforce(
        "ext-tw",
        general_scope("gc"),
        &[(EnforcedDimension::GcPressure, 18_200_001)],
    );
    assert!(enforcer.is_throttled("ext-tw"));
    // But Time is still well within budget.
    let state = enforcer.extension_state("ext-tw").unwrap();
    let time = state.budgets.get(&EnforcedDimension::Time).unwrap();
    assert_eq!(time.current_usage_millionths, 0);
}

// ---------------------------------------------------------------------------
// Constants stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_have_expected_values() {
    assert_eq!(COMPONENT, "resource_certificate_consumer");
    assert_eq!(ENFORCEMENT_SCHEMA_VERSION, "1.0.0");
    assert_eq!(DEFAULT_THROTTLE_THRESHOLD_MILLIONTHS, 900_000);
    assert_eq!(DEFAULT_REJECT_THRESHOLD_MILLIONTHS, 1_000_000);
    assert_eq!(DEFAULT_MIN_CONFIDENCE_MILLIONTHS, 900_000);
    assert_eq!(DEFAULT_MAX_EXTENSIONS, 1024);
    assert_eq!(DEFAULT_MAX_RECEIPTS, 4096);
    assert_eq!(MILLIONTHS, 1_000_000);
}

// ---------------------------------------------------------------------------
// Enforcement scope Display string content
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scope_display_contains_inner_value() {
    let scope = EnforcementScope::SchedulerAdmission {
        task_type: "MyTask123".to_string(),
    };
    assert!(scope.to_string().contains("MyTask123"));

    let scope2 = EnforcementScope::ModuleLoad {
        specifier: "react-dom".to_string(),
    };
    assert!(scope2.to_string().contains("react-dom"));

    let scope3 = EnforcementScope::IoOperation {
        operation_type: "db_query".to_string(),
    };
    assert!(scope3.to_string().contains("db_query"));
}

// ---------------------------------------------------------------------------
// Content hash variation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_hash_varies_with_scope() {
    let build_receipt = |scope: EnforcementScope| {
        let mut enforcer = make_enforcer();
        enforcer
            .install_certificate("ext-hv", certified_digest("c-hv"))
            .unwrap();
        enforcer.enforce("ext-hv", scope, &[(EnforcedDimension::Time, 500)])
    };
    let r1 = build_receipt(EnforcementScope::SchedulerAdmission {
        task_type: "A".to_string(),
    });
    let r2 = build_receipt(EnforcementScope::ModuleLoad {
        specifier: "B".to_string(),
    });
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_receipt_hash_varies_with_extension_id() {
    let build_receipt = |ext_id: &str| {
        let mut enforcer = make_enforcer();
        enforcer
            .install_certificate(ext_id, certified_digest("c-same"))
            .unwrap();
        enforcer.enforce(
            ext_id,
            general_scope("op"),
            &[(EnforcedDimension::Time, 500)],
        )
    };
    let r1 = build_receipt("ext-alpha");
    let r2 = build_receipt("ext-beta");
    assert_ne!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// BudgetEnforcer decision_sequence accessor
// ---------------------------------------------------------------------------

#[test]
fn enrichment_decision_sequence_increments_per_enforce_call() {
    let mut enforcer = make_enforcer();
    assert_eq!(enforcer.decision_sequence(), 0);

    enforcer
        .install_certificate("ext-ds", certified_digest("c-ds"))
        .unwrap();
    for i in 1..=5 {
        enforcer.enforce(
            "ext-ds",
            general_scope(&format!("op-{}", i)),
            &[(EnforcedDimension::Time, 100)],
        );
        assert_eq!(enforcer.decision_sequence(), i as u64);
    }
}

#[test]
fn enrichment_decision_sequence_increments_even_on_reject() {
    let mut enforcer = make_enforcer();
    // No certificate installed - will reject.
    enforcer.enforce(
        "ext-no",
        general_scope("fail"),
        &[(EnforcedDimension::Time, 100)],
    );
    assert_eq!(enforcer.decision_sequence(), 1);
    enforcer.enforce(
        "ext-no",
        general_scope("fail2"),
        &[(EnforcedDimension::Time, 100)],
    );
    assert_eq!(enforcer.decision_sequence(), 2);
}

// ---------------------------------------------------------------------------
// Multi-extension isolation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_multi_extension_budgets_isolated() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-x", certified_digest("cx"))
        .unwrap();
    enforcer
        .install_certificate("ext-y", certified_digest("cy"))
        .unwrap();

    // Exhaust ext-x Time.
    enforcer.enforce(
        "ext-x",
        general_scope("heavy"),
        &[(EnforcedDimension::Time, 9_500_000)],
    );
    assert!(enforcer.is_throttled("ext-x"));

    // ext-y should be completely unaffected.
    assert!(!enforcer.is_throttled("ext-y"));
    let ry = enforcer.enforce(
        "ext-y",
        general_scope("normal"),
        &[(EnforcedDimension::Time, 1_000)],
    );
    assert!(matches!(ry.decision, EnforcementDecision::Allow));
}

// ---------------------------------------------------------------------------
// Budget snapshot correctness after enforcement
// ---------------------------------------------------------------------------

#[test]
fn enrichment_budget_snapshot_in_receipt_reflects_post_decision_state() {
    let mut enforcer = make_enforcer();
    enforcer
        .install_certificate("ext-bs", certified_digest("c-bs"))
        .unwrap();
    let receipt = enforcer.enforce(
        "ext-bs",
        general_scope("op"),
        &[(EnforcedDimension::Time, 3_000_000)],
    );
    // After Allow, usage is recorded. Snapshot should reflect post-usage state.
    assert!(!receipt.budget_snapshot.is_empty());
    let time_snap = receipt
        .budget_snapshot
        .iter()
        .find(|s| s.dimension == EnforcedDimension::Time)
        .unwrap();
    assert_eq!(time_snap.current_usage_millionths, 3_000_000);
    assert_eq!(time_snap.upper_bound_millionths, 10_000_000);
    // 3M / 10M = 300_000 millionths = 30%.
    assert_eq!(time_snap.usage_ratio_millionths, 300_000);
}

// ---------------------------------------------------------------------------
// Policy hash embedded in receipts
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipts_carry_policy_hash() {
    let mut enforcer = make_enforcer();
    let expected = enforcer.policy.policy_hash();
    enforcer
        .install_certificate("ext-ph", certified_digest("c-ph"))
        .unwrap();
    let r1 = enforcer.enforce(
        "ext-ph",
        general_scope("a"),
        &[(EnforcedDimension::Time, 100)],
    );
    let r2 = enforcer.enforce(
        "ext-ph",
        general_scope("b"),
        &[(EnforcedDimension::Time, 100)],
    );
    assert_eq!(r1.policy_hash, expected);
    assert_eq!(r2.policy_hash, expected);
}
