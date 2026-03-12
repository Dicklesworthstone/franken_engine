#![forbid(unsafe_code)]

//! Integration tests for the render_lane_specializer module.

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::render_lane_specializer::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(200)
}

fn pure_ssr() -> SpecializationRequest {
    SpecializationRequest {
        lane_kind: LaneKind::ServerSideRender,
        component_shape: ComponentShape::PureFunction,
        strategy: SpecializationStrategy::ConstantFolding,
        input_hash: ContentHash::compute(b"integration-ssr"),
    }
}

fn memo_static() -> SpecializationRequest {
    SpecializationRequest {
        lane_kind: LaneKind::StaticGeneration,
        component_shape: ComponentShape::Memo,
        strategy: SpecializationStrategy::DeadBranchElimination,
        input_hash: ContentHash::compute(b"integration-memo"),
    }
}

fn hook_hydration() -> SpecializationRequest {
    SpecializationRequest {
        lane_kind: LaneKind::Hydration,
        component_shape: ComponentShape::HookBased,
        strategy: SpecializationStrategy::PartialEvaluation,
        input_hash: ContentHash::compute(b"integration-hook"),
    }
}

fn lazy_streaming() -> SpecializationRequest {
    SpecializationRequest {
        lane_kind: LaneKind::StreamingSSR,
        component_shape: ComponentShape::Lazy,
        strategy: SpecializationStrategy::InlineExpansion,
        input_hash: ContentHash::compute(b"integration-lazy"),
    }
}

fn class_client() -> SpecializationRequest {
    SpecializationRequest {
        lane_kind: LaneKind::ClientEntry,
        component_shape: ComponentShape::ClassWithState,
        strategy: SpecializationStrategy::ShapeSpecialization,
        input_hash: ContentHash::compute(b"integration-class"),
    }
}

fn suspense_islands() -> SpecializationRequest {
    SpecializationRequest {
        lane_kind: LaneKind::IslandsArchitecture,
        component_shape: ComponentShape::Suspense,
        strategy: SpecializationStrategy::ConstantFolding,
        input_hash: ContentHash::compute(b"integration-suspense"),
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_value() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.render-lane-specializer.v1");
}

#[test]
fn test_component_value() {
    assert_eq!(COMPONENT, "render_lane_specializer");
}

#[test]
fn test_bead_id_value() {
    assert_eq!(BEAD_ID, "bd-1lsy.7.9.2");
}

#[test]
fn test_policy_id_value() {
    assert_eq!(POLICY_ID, "RGC-609B");
}

// ---------------------------------------------------------------------------
// LaneKind enumeration
// ---------------------------------------------------------------------------

#[test]
fn lane_kind_all_exhaustive() {
    assert_eq!(LaneKind::ALL.len(), 6);
    assert!(LaneKind::ALL.contains(&LaneKind::ServerSideRender));
    assert!(LaneKind::ALL.contains(&LaneKind::ClientEntry));
    assert!(LaneKind::ALL.contains(&LaneKind::Hydration));
    assert!(LaneKind::ALL.contains(&LaneKind::StaticGeneration));
    assert!(LaneKind::ALL.contains(&LaneKind::StreamingSSR));
    assert!(LaneKind::ALL.contains(&LaneKind::IslandsArchitecture));
}

#[test]
fn lane_kind_serde_all_variants() {
    for lk in LaneKind::ALL {
        let json = serde_json::to_string(lk).unwrap();
        let back: LaneKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*lk, back);
        // JSON value should be a quoted string.
        assert!(json.starts_with('"'));
    }
}

#[test]
fn lane_kind_server_side_classification() {
    let server_lanes: Vec<LaneKind> = LaneKind::ALL
        .iter()
        .copied()
        .filter(|lk| lk.is_server_side())
        .collect();
    assert_eq!(server_lanes.len(), 3);
}

#[test]
fn lane_kind_hydration_classification() {
    let hydration_lanes: Vec<LaneKind> = LaneKind::ALL
        .iter()
        .copied()
        .filter(|lk| lk.is_hydration_related())
        .collect();
    assert_eq!(hydration_lanes.len(), 3);
}

#[test]
fn lane_kind_no_overlap_server_hydration_except_none() {
    // Server-side and hydration-related are disjoint in this model.
    for lk in LaneKind::ALL {
        assert!(
            !(lk.is_server_side() && lk.is_hydration_related()),
            "{lk} is both server-side and hydration-related"
        );
    }
}

// ---------------------------------------------------------------------------
// ComponentShape enumeration
// ---------------------------------------------------------------------------

#[test]
fn component_shape_all_exhaustive() {
    assert_eq!(ComponentShape::ALL.len(), 8);
}

#[test]
fn component_shape_pure_set() {
    let pure: Vec<ComponentShape> = ComponentShape::ALL
        .iter()
        .copied()
        .filter(|s| s.is_pure())
        .collect();
    assert_eq!(pure.len(), 2);
    assert!(pure.contains(&ComponentShape::PureFunction));
    assert!(pure.contains(&ComponentShape::Memo));
}

#[test]
fn component_shape_async_boundary_set() {
    let ab: Vec<ComponentShape> = ComponentShape::ALL
        .iter()
        .copied()
        .filter(|s| s.is_async_boundary())
        .collect();
    assert_eq!(ab.len(), 2);
    assert!(ab.contains(&ComponentShape::Lazy));
    assert!(ab.contains(&ComponentShape::Suspense));
}

#[test]
fn component_shape_serde_all() {
    for s in ComponentShape::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: ComponentShape = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// SpecializationStrategy enumeration
// ---------------------------------------------------------------------------

#[test]
fn strategy_all_exhaustive() {
    assert_eq!(SpecializationStrategy::ALL.len(), 5);
}

#[test]
fn strategy_serde_all() {
    for s in SpecializationStrategy::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: SpecializationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

// ---------------------------------------------------------------------------
// SafetyCheckKind enumeration
// ---------------------------------------------------------------------------

#[test]
fn safety_check_kind_all_exhaustive() {
    assert_eq!(SafetyCheckKind::ALL.len(), 6);
}

#[test]
fn safety_check_kind_display_nonempty() {
    for k in SafetyCheckKind::ALL {
        assert!(!k.to_string().is_empty());
    }
}

// ---------------------------------------------------------------------------
// SafetyCheck construction
// ---------------------------------------------------------------------------

#[test]
fn safety_check_pass_constructor() {
    let c = SafetyCheck::pass(SafetyCheckKind::ProofReceipt, b"data", "all good");
    assert!(c.passed);
    assert_eq!(c.check_kind, SafetyCheckKind::ProofReceipt);
    assert_eq!(c.reason, "all good");
}

#[test]
fn safety_check_fail_constructor() {
    let c = SafetyCheck::fail(SafetyCheckKind::Idempotency, b"data", "side effects");
    assert!(!c.passed);
    assert_eq!(c.check_kind, SafetyCheckKind::Idempotency);
}

#[test]
fn safety_check_different_evidence_different_hash() {
    let c1 = SafetyCheck::pass(SafetyCheckKind::PurityProof, b"alpha", "ok");
    let c2 = SafetyCheck::pass(SafetyCheckKind::PurityProof, b"beta", "ok");
    assert_ne!(c1.evidence_hash, c2.evidence_hash);
}

// ---------------------------------------------------------------------------
// SpecializationVerdict
// ---------------------------------------------------------------------------

#[test]
fn verdict_all_exhaustive() {
    assert_eq!(SpecializationVerdict::ALL.len(), 3);
}

#[test]
fn verdict_display() {
    assert_eq!(SpecializationVerdict::Applied.to_string(), "applied");
    assert_eq!(SpecializationVerdict::Rejected.to_string(), "rejected");
    assert_eq!(SpecializationVerdict::Deferred.to_string(), "deferred");
}

// ---------------------------------------------------------------------------
// SpecializationConfig validation
// ---------------------------------------------------------------------------

#[test]
fn validate_default_config_ok() {
    assert!(validate_config(&SpecializationConfig::default_config()).is_ok());
}

#[test]
fn validate_permissive_config_ok() {
    assert!(validate_config(&SpecializationConfig::permissive()).is_ok());
}

#[test]
fn validate_zero_inline_depth_err() {
    let mut c = SpecializationConfig::default_config();
    c.max_inline_depth = 0;
    let err = validate_config(&c).unwrap_err();
    assert!(matches!(err, SpecializationError::InvalidConfig { .. }));
}

#[test]
fn validate_zero_max_specs_err() {
    let mut c = SpecializationConfig::default_config();
    c.max_specializations_per_lane = 0;
    let err = validate_config(&c).unwrap_err();
    assert!(matches!(err, SpecializationError::InvalidConfig { .. }));
}

#[test]
fn validate_extreme_threshold_err() {
    let mut c = SpecializationConfig::default_config();
    c.min_speedup_threshold_millionths = 11_000_000;
    assert!(validate_config(&c).is_err());
}

// ---------------------------------------------------------------------------
// compute_specialization_benefit
// ---------------------------------------------------------------------------

#[test]
fn benefit_always_at_least_base() {
    for shape in ComponentShape::ALL {
        for strat in SpecializationStrategy::ALL {
            let b = compute_specialization_benefit(*shape, *strat);
            assert!(b >= 1_000_000, "{shape}+{strat} => {b} < 1_000_000");
        }
    }
}

#[test]
fn benefit_pure_function_highest_for_each_strategy() {
    for strat in SpecializationStrategy::ALL {
        let pure_b = compute_specialization_benefit(ComponentShape::PureFunction, *strat);
        for shape in ComponentShape::ALL {
            let other_b = compute_specialization_benefit(*shape, *strat);
            assert!(pure_b >= other_b, "pure should >= {shape} for {strat}");
        }
    }
}

#[test]
fn benefit_ordering_shapes() {
    let strat = SpecializationStrategy::ConstantFolding;
    let pure = compute_specialization_benefit(ComponentShape::PureFunction, strat);
    let memo = compute_specialization_benefit(ComponentShape::Memo, strat);
    let fwd = compute_specialization_benefit(ComponentShape::ForwardRef, strat);
    let hook = compute_specialization_benefit(ComponentShape::HookBased, strat);
    let cls = compute_specialization_benefit(ComponentShape::ClassWithState, strat);
    let lazy = compute_specialization_benefit(ComponentShape::Lazy, strat);
    let susp = compute_specialization_benefit(ComponentShape::Suspense, strat);
    let eb = compute_specialization_benefit(ComponentShape::ErrorBoundary, strat);
    assert!(pure > memo);
    assert!(memo > fwd);
    assert!(fwd > hook);
    assert!(hook > cls);
    assert!(cls > lazy);
    assert!(lazy > susp);
    assert!(susp > eb);
}

// ---------------------------------------------------------------------------
// evaluate_safety
// ---------------------------------------------------------------------------

#[test]
fn safety_pure_function_all_pass() {
    let req = pure_ssr();
    let checks = evaluate_safety(&req);
    assert_eq!(checks.len(), 6);
    for c in &checks {
        assert!(c.passed, "{} should pass for pure function", c.check_kind);
    }
}

#[test]
fn safety_hook_based_partial_failure() {
    let req = hook_hydration();
    let checks = evaluate_safety(&req);
    let failed: Vec<_> = checks.iter().filter(|c| !c.passed).collect();
    assert!(
        !failed.is_empty(),
        "hook-based should have at least one failed check"
    );
    // Purity should fail for hooks.
    assert!(
        failed
            .iter()
            .any(|c| c.check_kind == SafetyCheckKind::PurityProof)
    );
}

#[test]
fn safety_lazy_inline_unsupported_pattern() {
    let req = lazy_streaming();
    let checks = evaluate_safety(&req);
    let unsup = checks
        .iter()
        .find(|c| c.check_kind == SafetyCheckKind::UnsupportedPatternAbsence)
        .unwrap();
    assert!(!unsup.passed);
}

#[test]
fn safety_suspense_constant_folding_pattern_ok() {
    // Suspense + ConstantFolding: async boundary but NOT InlineExpansion, so pattern is OK.
    let req = suspense_islands();
    let checks = evaluate_safety(&req);
    let unsup = checks
        .iter()
        .find(|c| c.check_kind == SafetyCheckKind::UnsupportedPatternAbsence)
        .unwrap();
    assert!(
        unsup.passed,
        "Suspense+ConstantFolding should not trigger unsupported pattern"
    );
}

#[test]
fn safety_class_type_stability_fails() {
    let req = class_client();
    let checks = evaluate_safety(&req);
    let ts = checks
        .iter()
        .find(|c| c.check_kind == SafetyCheckKind::TypeStability)
        .unwrap();
    assert!(!ts.passed);
}

#[test]
fn safety_error_boundary_idempotency_fails() {
    let req = SpecializationRequest {
        lane_kind: LaneKind::ServerSideRender,
        component_shape: ComponentShape::ErrorBoundary,
        strategy: SpecializationStrategy::ShapeSpecialization,
        input_hash: ContentHash::compute(b"eb"),
    };
    let checks = evaluate_safety(&req);
    let idem = checks
        .iter()
        .find(|c| c.check_kind == SafetyCheckKind::Idempotency)
        .unwrap();
    assert!(!idem.passed);
}

#[test]
fn safety_proof_receipt_always_passes() {
    for shape in ComponentShape::ALL {
        let req = SpecializationRequest {
            lane_kind: LaneKind::ServerSideRender,
            component_shape: *shape,
            strategy: SpecializationStrategy::ConstantFolding,
            input_hash: ContentHash::compute(b"proof-receipt-test"),
        };
        let checks = evaluate_safety(&req);
        let pr = checks
            .iter()
            .find(|c| c.check_kind == SafetyCheckKind::ProofReceipt)
            .unwrap();
        assert!(pr.passed, "proof receipt should always pass for {shape}");
    }
}

// ---------------------------------------------------------------------------
// specialize_lane — Applied cases
// ---------------------------------------------------------------------------

#[test]
fn specialize_pure_ssr_applied() {
    let result = specialize_lane(&pure_ssr(), &SpecializationConfig::default_config()).unwrap();
    assert!(result.is_applied());
    assert!(result.speedup_millionths > 1_000_000);
    assert!(result.rejection_reasons.is_empty());
    assert!(result.all_checks_passed());
}

#[test]
fn specialize_memo_static_gen_applied() {
    let result = specialize_lane(&memo_static(), &SpecializationConfig::default_config()).unwrap();
    assert!(result.is_applied());
}

#[test]
fn specialize_pure_inline_expansion_applied() {
    let req = SpecializationRequest {
        lane_kind: LaneKind::ServerSideRender,
        component_shape: ComponentShape::PureFunction,
        strategy: SpecializationStrategy::InlineExpansion,
        input_hash: ContentHash::compute(b"pure-inline"),
    };
    let result = specialize_lane(&req, &SpecializationConfig::default_config()).unwrap();
    assert!(result.is_applied());
}

#[test]
fn specialize_pure_partial_eval_applied() {
    let req = SpecializationRequest {
        lane_kind: LaneKind::ClientEntry,
        component_shape: ComponentShape::PureFunction,
        strategy: SpecializationStrategy::PartialEvaluation,
        input_hash: ContentHash::compute(b"pure-pe"),
    };
    let result = specialize_lane(&req, &SpecializationConfig::default_config()).unwrap();
    assert!(result.is_applied());
}

// ---------------------------------------------------------------------------
// specialize_lane — Rejected cases
// ---------------------------------------------------------------------------

#[test]
fn specialize_hook_rejected_purity_required() {
    let result =
        specialize_lane(&hook_hydration(), &SpecializationConfig::default_config()).unwrap();
    assert!(result.is_rejected());
    assert!(
        result
            .rejection_reasons
            .iter()
            .any(|r| r.contains("purity"))
    );
}

#[test]
fn specialize_class_rejected_purity_required() {
    let result = specialize_lane(&class_client(), &SpecializationConfig::default_config()).unwrap();
    assert!(result.is_rejected());
}

#[test]
fn specialize_lazy_inline_rejected_unsupported() {
    let mut cfg = SpecializationConfig::default_config();
    cfg.require_purity_proof = false;
    let result = specialize_lane(&lazy_streaming(), &cfg).unwrap();
    assert!(result.is_rejected());
    assert!(
        result
            .rejection_reasons
            .iter()
            .any(|r| r.contains("unsupported"))
    );
}

#[test]
fn specialize_suspense_inline_rejected_unsupported() {
    let req = SpecializationRequest {
        lane_kind: LaneKind::IslandsArchitecture,
        component_shape: ComponentShape::Suspense,
        strategy: SpecializationStrategy::InlineExpansion,
        input_hash: ContentHash::compute(b"susp-inline"),
    };
    let mut cfg = SpecializationConfig::default_config();
    cfg.require_purity_proof = false;
    let result = specialize_lane(&req, &cfg).unwrap();
    assert!(result.is_rejected());
}

// ---------------------------------------------------------------------------
// specialize_lane — Deferred cases
// ---------------------------------------------------------------------------

#[test]
fn specialize_hook_deferred_permissive() {
    let result = specialize_lane(&hook_hydration(), &SpecializationConfig::permissive()).unwrap();
    assert!(result.is_deferred());
}

#[test]
fn specialize_forward_ref_deferred_permissive() {
    let req = SpecializationRequest {
        lane_kind: LaneKind::Hydration,
        component_shape: ComponentShape::ForwardRef,
        strategy: SpecializationStrategy::ShapeSpecialization,
        input_hash: ContentHash::compute(b"fwd"),
    };
    let result = specialize_lane(&req, &SpecializationConfig::permissive()).unwrap();
    // ForwardRef: purity fails, ambient mutation fails — but permissive => defer.
    assert!(result.is_deferred());
}

// ---------------------------------------------------------------------------
// specialize_lane — Error cases
// ---------------------------------------------------------------------------

#[test]
fn specialize_invalid_config_error() {
    let mut cfg = SpecializationConfig::default_config();
    cfg.max_inline_depth = 0;
    assert!(specialize_lane(&pure_ssr(), &cfg).is_err());
}

#[test]
fn specialize_invalid_config_zero_specs_error() {
    let mut cfg = SpecializationConfig::default_config();
    cfg.max_specializations_per_lane = 0;
    assert!(specialize_lane(&pure_ssr(), &cfg).is_err());
}

// ---------------------------------------------------------------------------
// specialize_lane — Determinism
// ---------------------------------------------------------------------------

#[test]
fn specialize_deterministic_applied() {
    let cfg = SpecializationConfig::default_config();
    let r1 = specialize_lane(&pure_ssr(), &cfg).unwrap();
    let r2 = specialize_lane(&pure_ssr(), &cfg).unwrap();
    assert_eq!(r1, r2);
}

#[test]
fn specialize_deterministic_rejected() {
    let cfg = SpecializationConfig::default_config();
    let r1 = specialize_lane(&hook_hydration(), &cfg).unwrap();
    let r2 = specialize_lane(&hook_hydration(), &cfg).unwrap();
    assert_eq!(r1, r2);
}

// ---------------------------------------------------------------------------
// specialize_lane — Serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn specialize_result_serde_applied() {
    let result = specialize_lane(&pure_ssr(), &SpecializationConfig::default_config()).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: SpecializationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn specialize_result_serde_rejected() {
    let result =
        specialize_lane(&hook_hydration(), &SpecializationConfig::default_config()).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: SpecializationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// specialize_lane — SpecializationResult methods
// ---------------------------------------------------------------------------

#[test]
fn result_methods_applied() {
    let result = specialize_lane(&pure_ssr(), &SpecializationConfig::default_config()).unwrap();
    assert!(result.is_applied());
    assert!(!result.is_rejected());
    assert!(!result.is_deferred());
    assert!(result.all_checks_passed());
    assert_eq!(result.failed_check_count(), 0);
}

#[test]
fn result_methods_rejected() {
    let result =
        specialize_lane(&hook_hydration(), &SpecializationConfig::default_config()).unwrap();
    assert!(!result.is_applied());
    assert!(result.is_rejected());
    assert!(!result.is_deferred());
}

#[test]
fn result_methods_deferred() {
    let result = specialize_lane(&hook_hydration(), &SpecializationConfig::permissive()).unwrap();
    assert!(!result.is_applied());
    assert!(!result.is_rejected());
    assert!(result.is_deferred());
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

#[test]
fn receipt_genesis_hash_deterministic() {
    let g1 = DecisionReceipt::genesis_hash();
    let g2 = DecisionReceipt::genesis_hash();
    assert_eq!(g1, g2);
}

#[test]
fn receipt_fields_correct() {
    let req = pure_ssr();
    let cfg = SpecializationConfig::default_config();
    let result = specialize_lane(&req, &cfg).unwrap();
    let receipt = DecisionReceipt::new(epoch(), &req, &result, DecisionReceipt::genesis_hash());
    assert_eq!(receipt.schema_version, SCHEMA_VERSION);
    assert_eq!(receipt.epoch, epoch());
    assert_eq!(receipt.lane_kind, LaneKind::ServerSideRender);
    assert_eq!(receipt.component_shape, ComponentShape::PureFunction);
    assert_eq!(receipt.strategy, SpecializationStrategy::ConstantFolding);
    assert_eq!(receipt.verdict, SpecializationVerdict::Applied);
    assert_eq!(receipt.checks_passed, 6);
    assert_eq!(receipt.checks_total, 6);
    assert_eq!(receipt.previous_hash, DecisionReceipt::genesis_hash());
}

#[test]
fn receipt_hash_deterministic() {
    let req = pure_ssr();
    let cfg = SpecializationConfig::default_config();
    let result = specialize_lane(&req, &cfg).unwrap();
    let g = DecisionReceipt::genesis_hash();
    let r1 = DecisionReceipt::new(epoch(), &req, &result, g);
    let r2 = DecisionReceipt::new(epoch(), &req, &result, g);
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn receipt_chaining_produces_different_hashes() {
    let req = pure_ssr();
    let cfg = SpecializationConfig::default_config();
    let result = specialize_lane(&req, &cfg).unwrap();
    let g = DecisionReceipt::genesis_hash();
    let r1 = DecisionReceipt::new(epoch(), &req, &result, g);
    let r2 = DecisionReceipt::new(epoch(), &req, &result, r1.content_hash);
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn receipt_serde_roundtrip() {
    let req = pure_ssr();
    let cfg = SpecializationConfig::default_config();
    let result = specialize_lane(&req, &cfg).unwrap();
    let receipt = DecisionReceipt::new(epoch(), &req, &result, DecisionReceipt::genesis_hash());
    let json = serde_json::to_string(&receipt).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

// ---------------------------------------------------------------------------
// specialize_batch
// ---------------------------------------------------------------------------

#[test]
fn batch_empty_ok() {
    let cfg = SpecializationConfig::default_config();
    let (results, receipts) = specialize_batch(&[], &cfg, epoch()).unwrap();
    assert!(results.is_empty());
    assert!(receipts.is_empty());
}

#[test]
fn batch_single_applied() {
    let reqs = vec![pure_ssr()];
    let cfg = SpecializationConfig::default_config();
    let (results, receipts) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(receipts.len(), 1);
    assert!(results[0].is_applied());
    assert_eq!(receipts[0].previous_hash, DecisionReceipt::genesis_hash());
}

#[test]
fn batch_multiple_mixed() {
    let reqs = vec![pure_ssr(), memo_static(), hook_hydration()];
    let cfg = SpecializationConfig::default_config();
    let (results, receipts) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(receipts.len(), 3);
    // First two should apply (pure + memo), third rejected (hook + purity required).
    assert!(results[0].is_applied());
    assert!(results[1].is_applied());
    assert!(results[2].is_rejected());
}

#[test]
fn batch_receipt_chain_integrity() {
    let reqs = vec![pure_ssr(), memo_static()];
    let cfg = SpecializationConfig::default_config();
    let (_, receipts) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
    assert_eq!(receipts[0].previous_hash, DecisionReceipt::genesis_hash());
    assert_eq!(receipts[1].previous_hash, receipts[0].content_hash);
}

#[test]
fn batch_receipt_chain_three() {
    let reqs = vec![
        pure_ssr(),
        memo_static(),
        SpecializationRequest {
            lane_kind: LaneKind::IslandsArchitecture,
            component_shape: ComponentShape::PureFunction,
            strategy: SpecializationStrategy::ShapeSpecialization,
            input_hash: ContentHash::compute(b"islands-pure"),
        },
    ];
    let cfg = SpecializationConfig::default_config();
    let (_, receipts) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
    assert_eq!(receipts[0].previous_hash, DecisionReceipt::genesis_hash());
    assert_eq!(receipts[1].previous_hash, receipts[0].content_hash);
    assert_eq!(receipts[2].previous_hash, receipts[1].content_hash);
}

#[test]
fn batch_lane_limit_exceeded() {
    let mut cfg = SpecializationConfig::default_config();
    cfg.max_specializations_per_lane = 1;
    // Two SSR requests — second should exceed per-lane limit.
    let reqs = vec![
        pure_ssr(),
        SpecializationRequest {
            lane_kind: LaneKind::ServerSideRender,
            component_shape: ComponentShape::Memo,
            strategy: SpecializationStrategy::ConstantFolding,
            input_hash: ContentHash::compute(b"memo-ssr"),
        },
    ];
    let result = specialize_batch(&reqs, &cfg, epoch());
    assert!(matches!(
        result,
        Err(SpecializationError::SpecializationLimitExceeded { .. })
    ));
}

#[test]
fn batch_different_lanes_no_limit() {
    let mut cfg = SpecializationConfig::default_config();
    cfg.max_specializations_per_lane = 1;
    // Two different lanes — should be fine.
    let reqs = vec![pure_ssr(), memo_static()];
    let (results, _) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
    assert_eq!(results.len(), 2);
}

#[test]
fn batch_invalid_config_error() {
    let mut cfg = SpecializationConfig::default_config();
    cfg.max_inline_depth = 0;
    assert!(specialize_batch(&[pure_ssr()], &cfg, epoch()).is_err());
}

// ---------------------------------------------------------------------------
// BatchSummary
// ---------------------------------------------------------------------------

#[test]
fn summary_empty() {
    let s = BatchSummary::from_results(&[]);
    assert_eq!(s.total, 0);
    assert_eq!(s.applied, 0);
    assert_eq!(s.rejected, 0);
    assert_eq!(s.deferred, 0);
    assert_eq!(s.application_rate(), 0);
    assert_eq!(s.avg_applied_speedup_millionths, 0);
}

#[test]
fn summary_all_applied() {
    let reqs = vec![pure_ssr(), memo_static()];
    let cfg = SpecializationConfig::default_config();
    let (results, _) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
    let s = BatchSummary::from_results(&results);
    assert_eq!(s.total, 2);
    assert_eq!(s.applied, 2);
    assert_eq!(s.rejected, 0);
    assert_eq!(s.deferred, 0);
    assert_eq!(s.application_rate(), 1_000_000);
    assert!(s.avg_applied_speedup_millionths > 1_000_000);
}

#[test]
fn summary_mixed() {
    let reqs = vec![pure_ssr(), hook_hydration()];
    let cfg = SpecializationConfig::default_config();
    let (results, _) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
    let s = BatchSummary::from_results(&results);
    assert_eq!(s.total, 2);
    assert_eq!(s.applied, 1);
    assert_eq!(s.rejected, 1);
    assert_eq!(s.application_rate(), 500_000);
}

#[test]
fn summary_deterministic() {
    let reqs = vec![pure_ssr()];
    let cfg = SpecializationConfig::default_config();
    let (results, _) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
    let s1 = BatchSummary::from_results(&results);
    let s2 = BatchSummary::from_results(&results);
    assert_eq!(s1.content_hash, s2.content_hash);
}

#[test]
fn summary_serde_roundtrip() {
    let reqs = vec![pure_ssr()];
    let cfg = SpecializationConfig::default_config();
    let (results, _) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
    let s = BatchSummary::from_results(&results);
    let json = serde_json::to_string(&s).unwrap();
    let back: BatchSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// SpecializationError display
// ---------------------------------------------------------------------------

#[test]
fn error_display_invalid_config() {
    let e = SpecializationError::InvalidConfig {
        reason: "test reason".into(),
    };
    assert!(e.to_string().contains("test reason"));
}

#[test]
fn error_display_inline_depth() {
    let e = SpecializationError::InlineDepthExceeded { depth: 20, max: 8 };
    let s = e.to_string();
    assert!(s.contains("20") && s.contains("8"));
}

#[test]
fn error_display_limit_exceeded() {
    let e = SpecializationError::SpecializationLimitExceeded { count: 17, max: 16 };
    assert!(e.to_string().contains("17"));
}

#[test]
fn error_display_missing_check() {
    let e = SpecializationError::MissingSafetyCheck {
        kind: SafetyCheckKind::NoAmbientMutation,
    };
    assert!(e.to_string().contains("no_ambient_mutation"));
}

#[test]
fn error_display_internal() {
    let e = SpecializationError::Internal {
        detail: "crash".into(),
    };
    assert!(e.to_string().contains("crash"));
}

#[test]
fn error_serde_roundtrip() {
    let e = SpecializationError::InlineDepthExceeded { depth: 5, max: 3 };
    let json = serde_json::to_string(&e).unwrap();
    let back: SpecializationError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// Cross-cutting: all lane/shape/strategy combinations
// ---------------------------------------------------------------------------

#[test]
fn all_lane_shape_strategy_triples_benefit_above_base() {
    for lane in LaneKind::ALL {
        for shape in ComponentShape::ALL {
            for strat in SpecializationStrategy::ALL {
                let b = compute_specialization_benefit(*shape, *strat);
                assert!(b >= 1_000_000, "{lane}+{shape}+{strat} => {b} < 1_000_000");
            }
        }
    }
}

#[test]
fn all_lane_shape_strategy_triples_specialize_no_panic() {
    let cfg = SpecializationConfig::default_config();
    for lane in LaneKind::ALL {
        for shape in ComponentShape::ALL {
            for strat in SpecializationStrategy::ALL {
                let req = SpecializationRequest {
                    lane_kind: *lane,
                    component_shape: *shape,
                    strategy: *strat,
                    input_hash: ContentHash::compute(format!("{lane}-{shape}-{strat}").as_bytes()),
                };
                let _ = specialize_lane(&req, &cfg);
            }
        }
    }
}
