//! Enrichment integration tests for the `render_lane_specializer` module.
//!
//! Covers additional edge cases for enums, safety checks, config validation,
//! batch processing, determinism, serde, and error display.

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::render_lane_specializer::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(300)
}

fn req(lane: LaneKind, shape: ComponentShape, strat: SpecializationStrategy) -> SpecializationRequest {
    SpecializationRequest {
        lane_kind: lane,
        component_shape: shape,
        strategy: strat,
        input_hash: ContentHash::compute(
            format!("{}-{}-{}", lane, shape, strat).as_bytes(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrich_default_constants_values() {
    assert_eq!(DEFAULT_MAX_INLINE_DEPTH, 8);
    assert_eq!(DEFAULT_MIN_SPEEDUP_THRESHOLD, 100_000);
    assert_eq!(DEFAULT_MAX_SPECIALIZATIONS_PER_LANE, 16);
}

#[test]
fn enrich_schema_version_nonempty() {
    assert!(!SCHEMA_VERSION.is_empty());
}

#[test]
fn enrich_component_nonempty() {
    assert!(!COMPONENT.is_empty());
}

// ---------------------------------------------------------------------------
// LaneKind: as_str, Display, classification
// ---------------------------------------------------------------------------

#[test]
fn enrich_lane_kind_as_str_matches_display() {
    for lk in LaneKind::ALL {
        assert_eq!(lk.as_str(), lk.to_string());
    }
}

#[test]
fn enrich_lane_kind_server_and_hydration_disjoint() {
    for lk in LaneKind::ALL {
        assert!(!(lk.is_server_side() && lk.is_hydration_related()));
    }
}

#[test]
fn enrich_lane_kind_specific_server_lanes() {
    assert!(LaneKind::ServerSideRender.is_server_side());
    assert!(LaneKind::StaticGeneration.is_server_side());
    assert!(LaneKind::StreamingSSR.is_server_side());
}

#[test]
fn enrich_lane_kind_specific_hydration_lanes() {
    assert!(LaneKind::Hydration.is_hydration_related());
    assert!(LaneKind::ClientEntry.is_hydration_related());
    assert!(LaneKind::IslandsArchitecture.is_hydration_related());
}

#[test]
fn enrich_lane_kind_clone_eq() {
    let a = LaneKind::StreamingSSR;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrich_lane_kind_ord() {
    let mut lanes = LaneKind::ALL.to_vec();
    lanes.sort();
    // Just verify sorting doesn't panic and is deterministic
    let mut lanes2 = LaneKind::ALL.to_vec();
    lanes2.sort();
    assert_eq!(lanes, lanes2);
}

// ---------------------------------------------------------------------------
// ComponentShape: classification coverage
// ---------------------------------------------------------------------------

#[test]
fn enrich_shape_pure_set() {
    assert!(ComponentShape::PureFunction.is_pure());
    assert!(ComponentShape::Memo.is_pure());
    assert!(!ComponentShape::HookBased.is_pure());
    assert!(!ComponentShape::ClassWithState.is_pure());
    assert!(!ComponentShape::ForwardRef.is_pure());
    assert!(!ComponentShape::Lazy.is_pure());
    assert!(!ComponentShape::Suspense.is_pure());
    assert!(!ComponentShape::ErrorBoundary.is_pure());
}

#[test]
fn enrich_shape_async_boundary_set() {
    assert!(ComponentShape::Lazy.is_async_boundary());
    assert!(ComponentShape::Suspense.is_async_boundary());
    assert!(!ComponentShape::PureFunction.is_async_boundary());
    assert!(!ComponentShape::ClassWithState.is_async_boundary());
    assert!(!ComponentShape::HookBased.is_async_boundary());
    assert!(!ComponentShape::ForwardRef.is_async_boundary());
    assert!(!ComponentShape::Memo.is_async_boundary());
    assert!(!ComponentShape::ErrorBoundary.is_async_boundary());
}

#[test]
fn enrich_shape_as_str_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for s in ComponentShape::ALL {
        assert!(seen.insert(s.as_str()), "duplicate as_str for {s}");
    }
}

// ---------------------------------------------------------------------------
// SpecializationStrategy coverage
// ---------------------------------------------------------------------------

#[test]
fn enrich_strategy_as_str_matches_display() {
    for s in SpecializationStrategy::ALL {
        assert_eq!(s.as_str(), s.to_string());
    }
}

#[test]
fn enrich_strategy_clone_eq() {
    let a = SpecializationStrategy::PartialEvaluation;
    let b = a;
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// SafetyCheckKind coverage
// ---------------------------------------------------------------------------

#[test]
fn enrich_safety_check_kind_as_str_matches_display() {
    for k in SafetyCheckKind::ALL {
        assert_eq!(k.as_str(), k.to_string());
    }
}

#[test]
fn enrich_safety_check_kind_serde() {
    for k in SafetyCheckKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: SafetyCheckKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

// ---------------------------------------------------------------------------
// SafetyCheck: pass/fail with various evidence
// ---------------------------------------------------------------------------

#[test]
fn enrich_safety_check_pass_reason_preserved() {
    let c = SafetyCheck::pass(SafetyCheckKind::PurityProof, b"ev", "custom reason");
    assert!(c.passed);
    assert_eq!(c.reason, "custom reason");
}

#[test]
fn enrich_safety_check_fail_reason_preserved() {
    let c = SafetyCheck::fail(SafetyCheckKind::TypeStability, b"ev", "fail reason");
    assert!(!c.passed);
    assert_eq!(c.reason, "fail reason");
}

#[test]
fn enrich_safety_check_evidence_hash_deterministic() {
    let c1 = SafetyCheck::pass(SafetyCheckKind::ProofReceipt, b"same", "ok");
    let c2 = SafetyCheck::pass(SafetyCheckKind::ProofReceipt, b"same", "ok");
    assert_eq!(c1.evidence_hash, c2.evidence_hash);
}

#[test]
fn enrich_safety_check_serde_roundtrip() {
    let c = SafetyCheck::pass(SafetyCheckKind::Idempotency, b"data", "fine");
    let json = serde_json::to_string(&c).unwrap();
    let back: SafetyCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// SpecializationVerdict
// ---------------------------------------------------------------------------

#[test]
fn enrich_verdict_as_str_matches_display() {
    for v in SpecializationVerdict::ALL {
        assert_eq!(v.as_str(), v.to_string());
    }
}

#[test]
fn enrich_verdict_serde_roundtrip() {
    for v in SpecializationVerdict::ALL {
        let json = serde_json::to_string(v).unwrap();
        let back: SpecializationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// SpecializationConfig
// ---------------------------------------------------------------------------

#[test]
fn enrich_config_default_matches_default_config() {
    let a = SpecializationConfig::default();
    let b = SpecializationConfig::default_config();
    assert_eq!(a, b);
}

#[test]
fn enrich_config_permissive_higher_limits() {
    let d = SpecializationConfig::default_config();
    let p = SpecializationConfig::permissive();
    assert!(p.max_inline_depth > d.max_inline_depth);
    assert!(p.max_specializations_per_lane > d.max_specializations_per_lane);
    assert!(!p.require_purity_proof);
}

#[test]
fn enrich_config_serde_roundtrip() {
    let c = SpecializationConfig::default_config();
    let json = serde_json::to_string(&c).unwrap();
    let back: SpecializationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// validate_config edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrich_validate_config_min_valid() {
    let c = SpecializationConfig {
        max_inline_depth: 1,
        require_purity_proof: false,
        min_speedup_threshold_millionths: 0,
        max_specializations_per_lane: 1,
    };
    assert!(validate_config(&c).is_ok());
}

#[test]
fn enrich_validate_config_threshold_at_boundary() {
    let mut c = SpecializationConfig::default_config();
    c.min_speedup_threshold_millionths = 10_000_000;
    assert!(validate_config(&c).is_ok());
}

#[test]
fn enrich_validate_config_threshold_over_boundary() {
    let mut c = SpecializationConfig::default_config();
    c.min_speedup_threshold_millionths = 10_000_001;
    assert!(validate_config(&c).is_err());
}

// ---------------------------------------------------------------------------
// compute_specialization_benefit: specific shape/strategy pairs
// ---------------------------------------------------------------------------

#[test]
fn enrich_benefit_pure_partial_eval_highest() {
    let b = compute_specialization_benefit(ComponentShape::PureFunction, SpecializationStrategy::PartialEvaluation);
    // PureFunction (500k) * PartialEvaluation (5) / 5 + 1M = 1.5M
    assert_eq!(b, 1_500_000);
}

#[test]
fn enrich_benefit_error_boundary_min() {
    // ErrorBoundary (50k) * DeadBranchElimination (2) / 5 + 1M = 1_020_000
    let b = compute_specialization_benefit(ComponentShape::ErrorBoundary, SpecializationStrategy::DeadBranchElimination);
    assert_eq!(b, 1_020_000);
}

#[test]
fn enrich_benefit_always_above_one_million() {
    for shape in ComponentShape::ALL {
        for strat in SpecializationStrategy::ALL {
            let b = compute_specialization_benefit(*shape, *strat);
            assert!(b > 1_000_000, "{shape}+{strat} benefit should be > 1M, got {b}");
        }
    }
}

// ---------------------------------------------------------------------------
// evaluate_safety: systematic coverage
// ---------------------------------------------------------------------------

#[test]
fn enrich_safety_always_six_checks() {
    for shape in ComponentShape::ALL {
        for strat in SpecializationStrategy::ALL {
            let r = req(LaneKind::ServerSideRender, *shape, *strat);
            let checks = evaluate_safety(&r);
            assert_eq!(checks.len(), 6, "expected 6 checks for {shape}+{strat}");
        }
    }
}

#[test]
fn enrich_safety_memo_all_pass() {
    let r = req(LaneKind::ServerSideRender, ComponentShape::Memo, SpecializationStrategy::ConstantFolding);
    let checks = evaluate_safety(&r);
    for c in &checks {
        assert!(c.passed, "Memo should pass all checks, failed: {}", c.check_kind);
    }
}

#[test]
fn enrich_safety_lazy_constant_folding_pattern_fails() {
    let r = req(LaneKind::ServerSideRender, ComponentShape::Lazy, SpecializationStrategy::ConstantFolding);
    let checks = evaluate_safety(&r);
    let unsup = checks.iter().find(|c| c.check_kind == SafetyCheckKind::UnsupportedPatternAbsence).unwrap();
    assert!(!unsup.passed, "Lazy+ConstantFolding should fail unsupported pattern check");
}

#[test]
fn enrich_safety_suspense_inline_pattern_fails() {
    let r = req(LaneKind::StreamingSSR, ComponentShape::Suspense, SpecializationStrategy::InlineExpansion);
    let checks = evaluate_safety(&r);
    let unsup = checks.iter().find(|c| c.check_kind == SafetyCheckKind::UnsupportedPatternAbsence).unwrap();
    assert!(!unsup.passed);
}

#[test]
fn enrich_safety_forward_ref_idempotent() {
    let r = req(LaneKind::Hydration, ComponentShape::ForwardRef, SpecializationStrategy::ShapeSpecialization);
    let checks = evaluate_safety(&r);
    let idem = checks.iter().find(|c| c.check_kind == SafetyCheckKind::Idempotency).unwrap();
    assert!(idem.passed, "ForwardRef should be idempotent");
}

// ---------------------------------------------------------------------------
// specialize_lane: additional scenarios
// ---------------------------------------------------------------------------

#[test]
fn enrich_specialize_memo_dead_branch_applied() {
    let r = req(LaneKind::StaticGeneration, ComponentShape::Memo, SpecializationStrategy::DeadBranchElimination);
    let result = specialize_lane(&r, &SpecializationConfig::default_config()).unwrap();
    assert!(result.is_applied());
}

#[test]
fn enrich_specialize_error_boundary_rejected_purity() {
    let r = req(LaneKind::ServerSideRender, ComponentShape::ErrorBoundary, SpecializationStrategy::ConstantFolding);
    let result = specialize_lane(&r, &SpecializationConfig::default_config()).unwrap();
    assert!(result.is_rejected());
}

#[test]
fn enrich_specialize_result_failed_check_count() {
    let r = req(LaneKind::ClientEntry, ComponentShape::HookBased, SpecializationStrategy::PartialEvaluation);
    let result = specialize_lane(&r, &SpecializationConfig::default_config()).unwrap();
    assert!(result.failed_check_count() > 0);
}

#[test]
fn enrich_specialize_applied_no_rejection_reasons() {
    let r = req(LaneKind::ServerSideRender, ComponentShape::PureFunction, SpecializationStrategy::ConstantFolding);
    let result = specialize_lane(&r, &SpecializationConfig::default_config()).unwrap();
    assert!(result.is_applied());
    assert!(result.rejection_reasons.is_empty());
    assert_eq!(result.failed_check_count(), 0);
}

#[test]
fn enrich_specialize_rejected_has_rejection_reasons() {
    let r = req(LaneKind::Hydration, ComponentShape::ClassWithState, SpecializationStrategy::ShapeSpecialization);
    let result = specialize_lane(&r, &SpecializationConfig::default_config()).unwrap();
    assert!(result.is_rejected());
    assert!(!result.rejection_reasons.is_empty());
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn enrich_receipt_different_epochs_different_hashes() {
    let r = req(LaneKind::ServerSideRender, ComponentShape::PureFunction, SpecializationStrategy::ConstantFolding);
    let cfg = SpecializationConfig::default_config();
    let result = specialize_lane(&r, &cfg).unwrap();
    let g = DecisionReceipt::genesis_hash();
    let r1 = DecisionReceipt::new(SecurityEpoch::from_raw(1), &r, &result, g);
    let r2 = DecisionReceipt::new(SecurityEpoch::from_raw(2), &r, &result, g);
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrich_receipt_rejected_verdict_in_receipt() {
    let r = req(LaneKind::ClientEntry, ComponentShape::HookBased, SpecializationStrategy::PartialEvaluation);
    let cfg = SpecializationConfig::default_config();
    let result = specialize_lane(&r, &cfg).unwrap();
    let receipt = DecisionReceipt::new(epoch(), &r, &result, DecisionReceipt::genesis_hash());
    assert_eq!(receipt.verdict, SpecializationVerdict::Rejected);
}

// ---------------------------------------------------------------------------
// specialize_batch: edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrich_batch_all_rejected() {
    let reqs = vec![
        req(LaneKind::Hydration, ComponentShape::HookBased, SpecializationStrategy::PartialEvaluation),
        req(LaneKind::ClientEntry, ComponentShape::ClassWithState, SpecializationStrategy::ShapeSpecialization),
    ];
    let cfg = SpecializationConfig::default_config();
    let (results, receipts) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|r| r.is_rejected()));
    assert_eq!(receipts.len(), 2);
}

#[test]
fn enrich_batch_receipt_chain_all_different() {
    let reqs = vec![
        req(LaneKind::ServerSideRender, ComponentShape::PureFunction, SpecializationStrategy::ConstantFolding),
        req(LaneKind::StaticGeneration, ComponentShape::Memo, SpecializationStrategy::DeadBranchElimination),
        req(LaneKind::IslandsArchitecture, ComponentShape::PureFunction, SpecializationStrategy::ShapeSpecialization),
    ];
    let cfg = SpecializationConfig::default_config();
    let (_, receipts) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
    let hashes: Vec<_> = receipts.iter().map(|r| r.content_hash).collect();
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j]);
        }
    }
}

// ---------------------------------------------------------------------------
// BatchSummary edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrich_summary_all_rejected() {
    let reqs = vec![
        req(LaneKind::Hydration, ComponentShape::HookBased, SpecializationStrategy::PartialEvaluation),
    ];
    let cfg = SpecializationConfig::default_config();
    let (results, _) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
    let s = BatchSummary::from_results(&results);
    assert_eq!(s.total, 1);
    assert_eq!(s.applied, 0);
    assert_eq!(s.rejected, 1);
    assert_eq!(s.application_rate(), 0);
    assert_eq!(s.avg_applied_speedup_millionths, 0);
}

#[test]
fn enrich_summary_content_hash_differs_by_content() {
    let r1 = vec![req(LaneKind::ServerSideRender, ComponentShape::PureFunction, SpecializationStrategy::ConstantFolding)];
    let r2 = vec![req(LaneKind::Hydration, ComponentShape::HookBased, SpecializationStrategy::PartialEvaluation)];
    let cfg = SpecializationConfig::default_config();
    let (res1, _) = specialize_batch(&r1, &cfg, epoch()).unwrap();
    let (res2, _) = specialize_batch(&r2, &cfg, epoch()).unwrap();
    let s1 = BatchSummary::from_results(&res1);
    let s2 = BatchSummary::from_results(&res2);
    assert_ne!(s1.content_hash, s2.content_hash);
}

// ---------------------------------------------------------------------------
// SpecializationError serde and display
// ---------------------------------------------------------------------------

#[test]
fn enrich_error_serde_all_variants() {
    let errors: Vec<SpecializationError> = vec![
        SpecializationError::InvalidConfig { reason: "r".into() },
        SpecializationError::InlineDepthExceeded { depth: 10, max: 5 },
        SpecializationError::SpecializationLimitExceeded { count: 20, max: 16 },
        SpecializationError::MissingSafetyCheck { kind: SafetyCheckKind::PurityProof },
        SpecializationError::Internal { detail: "oops".into() },
    ];
    for e in errors {
        let json = serde_json::to_string(&e).unwrap();
        let back: SpecializationError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }
}

// ---------------------------------------------------------------------------
// Cross-cutting: deferred cases with permissive config
// ---------------------------------------------------------------------------

#[test]
fn enrich_forward_ref_partial_eval_deferred_permissive() {
    let r = req(LaneKind::Hydration, ComponentShape::ForwardRef, SpecializationStrategy::PartialEvaluation);
    let result = specialize_lane(&r, &SpecializationConfig::permissive()).unwrap();
    assert!(result.is_deferred());
}

#[test]
fn enrich_class_with_state_deferred_permissive() {
    let r = req(LaneKind::ClientEntry, ComponentShape::ClassWithState, SpecializationStrategy::ShapeSpecialization);
    let result = specialize_lane(&r, &SpecializationConfig::permissive()).unwrap();
    // ClassWithState: purity fails, type stability fails, no ambient mutation fails
    assert!(result.is_deferred());
}

#[test]
fn enrich_error_boundary_deferred_permissive() {
    let r = req(LaneKind::ServerSideRender, ComponentShape::ErrorBoundary, SpecializationStrategy::DeadBranchElimination);
    let result = specialize_lane(&r, &SpecializationConfig::permissive()).unwrap();
    assert!(result.is_deferred());
}
