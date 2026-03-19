//! Enrichment integration tests (batch 2) for the `render_lane_specializer` module.
//!
//! Covers specialization workflows, safety check matrix, batch operations,
//! receipt chaining, config validation, and benefit computation edge cases.

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
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::render_lane_specializer::{
    BEAD_ID, BatchSummary, COMPONENT, ComponentShape, DEFAULT_MAX_INLINE_DEPTH,
    DEFAULT_MAX_SPECIALIZATIONS_PER_LANE, DEFAULT_MIN_SPEEDUP_THRESHOLD, DecisionReceipt, LaneKind,
    POLICY_ID, SCHEMA_VERSION, SafetyCheck, SafetyCheckKind, SpecializationConfig,
    SpecializationError, SpecializationRequest, SpecializationStrategy,
    compute_specialization_benefit, evaluate_safety, specialize_batch, specialize_lane,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MILLION: u64 = 1_000_000;

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(100)
}

fn make_request(
    lane: LaneKind,
    shape: ComponentShape,
    strategy: SpecializationStrategy,
) -> SpecializationRequest {
    SpecializationRequest {
        lane_kind: lane,
        component_shape: shape,
        strategy,
        input_hash: ContentHash::compute(b"enrichment-batch2-input"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_well_defined() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert_eq!(COMPONENT, "render_lane_specializer");
    assert!(BEAD_ID.starts_with("bd-"));
    assert!(POLICY_ID.starts_with("RGC-"));
    assert!(DEFAULT_MAX_INLINE_DEPTH > 0);
    assert!(DEFAULT_MIN_SPEEDUP_THRESHOLD <= MILLION);
    assert!(DEFAULT_MAX_SPECIALIZATIONS_PER_LANE > 0);
}

#[test]
fn enrichment_lane_kind_server_side_vs_hydration_disjoint() {
    for lk in LaneKind::ALL {
        assert!(
            !(lk.is_server_side() && lk.is_hydration_related()),
            "{} should not be both server-side and hydration-related",
            lk
        );
    }
}

#[test]
fn enrichment_lane_kind_every_variant_in_one_category() {
    for lk in LaneKind::ALL {
        let categorized = lk.is_server_side() || lk.is_hydration_related();
        assert!(
            categorized,
            "{} should be either server-side or hydration-related",
            lk
        );
    }
}

#[test]
fn enrichment_component_shape_pure_shapes_count() {
    let pure_count = ComponentShape::ALL.iter().filter(|s| s.is_pure()).count();
    assert_eq!(pure_count, 2);
}

#[test]
fn enrichment_component_shape_async_boundary_count() {
    let async_count = ComponentShape::ALL
        .iter()
        .filter(|s| s.is_async_boundary())
        .count();
    assert_eq!(async_count, 2);
}

#[test]
fn enrichment_benefit_always_above_or_equal_base() {
    for shape in ComponentShape::ALL {
        for strat in SpecializationStrategy::ALL {
            let b = compute_specialization_benefit(*shape, *strat);
            assert!(
                b >= MILLION,
                "benefit for {}/{} should be >= 1x",
                shape,
                strat
            );
        }
    }
}

#[test]
fn enrichment_benefit_pure_higher_than_error_boundary() {
    for strat in SpecializationStrategy::ALL {
        let pure = compute_specialization_benefit(ComponentShape::PureFunction, *strat);
        let eb = compute_specialization_benefit(ComponentShape::ErrorBoundary, *strat);
        assert!(pure > eb);
    }
}

#[test]
fn enrichment_benefit_memo_higher_than_class_with_state() {
    for strat in SpecializationStrategy::ALL {
        let memo = compute_specialization_benefit(ComponentShape::Memo, *strat);
        let cls = compute_specialization_benefit(ComponentShape::ClassWithState, *strat);
        assert!(memo > cls, "memo > class_with_state for {}", strat);
    }
}

#[test]
fn enrichment_benefit_deterministic_across_calls() {
    let a = compute_specialization_benefit(
        ComponentShape::ForwardRef,
        SpecializationStrategy::InlineExpansion,
    );
    let b = compute_specialization_benefit(
        ComponentShape::ForwardRef,
        SpecializationStrategy::InlineExpansion,
    );
    assert_eq!(a, b);
}

#[test]
fn enrichment_safety_pure_function_all_pass() {
    let req = make_request(
        LaneKind::ServerSideRender,
        ComponentShape::PureFunction,
        SpecializationStrategy::ConstantFolding,
    );
    let checks = evaluate_safety(&req);
    assert_eq!(checks.len(), 6);
    assert!(checks.iter().all(|c| c.passed));
}

#[test]
fn enrichment_safety_hook_based_purity_fails() {
    let req = make_request(
        LaneKind::ClientEntry,
        ComponentShape::HookBased,
        SpecializationStrategy::PartialEvaluation,
    );
    let checks = evaluate_safety(&req);
    let purity = checks
        .iter()
        .find(|c| c.check_kind == SafetyCheckKind::PurityProof)
        .unwrap();
    assert!(!purity.passed);
}

#[test]
fn enrichment_safety_lazy_constant_folding_unsupported() {
    let req = make_request(
        LaneKind::StreamingSSR,
        ComponentShape::Lazy,
        SpecializationStrategy::ConstantFolding,
    );
    let checks = evaluate_safety(&req);
    let unsup = checks
        .iter()
        .find(|c| c.check_kind == SafetyCheckKind::UnsupportedPatternAbsence)
        .unwrap();
    assert!(!unsup.passed);
}

#[test]
fn enrichment_safety_suspense_partial_eval_pattern_ok() {
    let req = make_request(
        LaneKind::Hydration,
        ComponentShape::Suspense,
        SpecializationStrategy::PartialEvaluation,
    );
    let checks = evaluate_safety(&req);
    let unsup = checks
        .iter()
        .find(|c| c.check_kind == SafetyCheckKind::UnsupportedPatternAbsence)
        .unwrap();
    // Suspense + PartialEvaluation is NOT inline/constant-folding, so pattern check passes
    assert!(unsup.passed);
}

#[test]
fn enrichment_safety_error_boundary_type_stability_fails() {
    let req = make_request(
        LaneKind::Hydration,
        ComponentShape::ErrorBoundary,
        SpecializationStrategy::ShapeSpecialization,
    );
    let checks = evaluate_safety(&req);
    let ts = checks
        .iter()
        .find(|c| c.check_kind == SafetyCheckKind::TypeStability)
        .unwrap();
    assert!(!ts.passed);
}

#[test]
fn enrichment_safety_forward_ref_idempotency_passes() {
    let req = make_request(
        LaneKind::ClientEntry,
        ComponentShape::ForwardRef,
        SpecializationStrategy::ShapeSpecialization,
    );
    let checks = evaluate_safety(&req);
    let idem = checks
        .iter()
        .find(|c| c.check_kind == SafetyCheckKind::Idempotency)
        .unwrap();
    assert!(idem.passed);
}

#[test]
fn enrichment_safety_count_always_six() {
    for shape in ComponentShape::ALL {
        for strat in SpecializationStrategy::ALL {
            let req = make_request(LaneKind::ServerSideRender, *shape, *strat);
            assert_eq!(evaluate_safety(&req).len(), 6);
        }
    }
}

#[test]
fn enrichment_specialize_pure_ssr_applies_all_strategies() {
    let cfg = SpecializationConfig::default_config();
    for strat in SpecializationStrategy::ALL {
        let req = make_request(
            LaneKind::ServerSideRender,
            ComponentShape::PureFunction,
            *strat,
        );
        let result = specialize_lane(&req, &cfg).unwrap();
        assert!(
            result.is_applied(),
            "pure + {} should apply with default config",
            strat
        );
    }
}

#[test]
fn enrichment_specialize_hook_default_rejected() {
    let req = make_request(
        LaneKind::ClientEntry,
        ComponentShape::HookBased,
        SpecializationStrategy::PartialEvaluation,
    );
    let cfg = SpecializationConfig::default_config();
    let result = specialize_lane(&req, &cfg).unwrap();
    assert!(result.is_rejected());
}

#[test]
fn enrichment_specialize_hook_permissive_defers() {
    let req = make_request(
        LaneKind::ClientEntry,
        ComponentShape::HookBased,
        SpecializationStrategy::PartialEvaluation,
    );
    let cfg = SpecializationConfig::permissive();
    let result = specialize_lane(&req, &cfg).unwrap();
    assert!(result.is_deferred());
}

#[test]
fn enrichment_specialize_invalid_config_returns_error() {
    let req = make_request(
        LaneKind::ServerSideRender,
        ComponentShape::PureFunction,
        SpecializationStrategy::ConstantFolding,
    );
    let mut cfg = SpecializationConfig::default_config();
    cfg.max_inline_depth = 0;
    assert!(specialize_lane(&req, &cfg).is_err());
}

#[test]
fn enrichment_specialize_result_accessors_consistent() {
    let req = make_request(
        LaneKind::ServerSideRender,
        ComponentShape::PureFunction,
        SpecializationStrategy::ConstantFolding,
    );
    let cfg = SpecializationConfig::default_config();
    let result = specialize_lane(&req, &cfg).unwrap();
    assert!(result.is_applied());
    assert!(!result.is_rejected());
    assert!(!result.is_deferred());
    assert!(result.all_checks_passed());
    assert_eq!(result.failed_check_count(), 0);
}

#[test]
fn enrichment_receipt_genesis_deterministic() {
    assert_eq!(
        DecisionReceipt::genesis_hash(),
        DecisionReceipt::genesis_hash()
    );
}

#[test]
fn enrichment_receipt_hash_chain_differs() {
    let req = make_request(
        LaneKind::ServerSideRender,
        ComponentShape::PureFunction,
        SpecializationStrategy::ConstantFolding,
    );
    let cfg = SpecializationConfig::default_config();
    let result = specialize_lane(&req, &cfg).unwrap();
    let genesis = DecisionReceipt::genesis_hash();
    let r1 = DecisionReceipt::new(epoch(), &req, &result, genesis);
    let r2 = DecisionReceipt::new(epoch(), &req, &result, r1.content_hash);
    assert_ne!(r1.content_hash, r2.content_hash);
}

#[test]
fn enrichment_receipt_serde_round_trip() {
    let req = make_request(
        LaneKind::StaticGeneration,
        ComponentShape::Memo,
        SpecializationStrategy::DeadBranchElimination,
    );
    let cfg = SpecializationConfig::default_config();
    let result = specialize_lane(&req, &cfg).unwrap();
    let r = DecisionReceipt::new(epoch(), &req, &result, DecisionReceipt::genesis_hash());
    let json = serde_json::to_string(&r).unwrap();
    let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_batch_single_applied() {
    let reqs = vec![make_request(
        LaneKind::ServerSideRender,
        ComponentShape::PureFunction,
        SpecializationStrategy::ConstantFolding,
    )];
    let cfg = SpecializationConfig::default_config();
    let (results, receipts) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(receipts.len(), 1);
    assert!(results[0].is_applied());
}

#[test]
fn enrichment_batch_receipt_chain_links() {
    let reqs = vec![
        make_request(
            LaneKind::ServerSideRender,
            ComponentShape::PureFunction,
            SpecializationStrategy::ConstantFolding,
        ),
        make_request(
            LaneKind::StaticGeneration,
            ComponentShape::Memo,
            SpecializationStrategy::DeadBranchElimination,
        ),
        make_request(
            LaneKind::IslandsArchitecture,
            ComponentShape::PureFunction,
            SpecializationStrategy::InlineExpansion,
        ),
    ];
    let cfg = SpecializationConfig::default_config();
    let (_, receipts) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
    assert_eq!(receipts[0].previous_hash, DecisionReceipt::genesis_hash());
    assert_eq!(receipts[1].previous_hash, receipts[0].content_hash);
    assert_eq!(receipts[2].previous_hash, receipts[1].content_hash);
}

#[test]
fn enrichment_batch_lane_limit_exceeded() {
    let mut cfg = SpecializationConfig::default_config();
    cfg.max_specializations_per_lane = 1;
    let reqs = vec![
        make_request(
            LaneKind::ServerSideRender,
            ComponentShape::PureFunction,
            SpecializationStrategy::ConstantFolding,
        ),
        make_request(
            LaneKind::ServerSideRender,
            ComponentShape::Memo,
            SpecializationStrategy::DeadBranchElimination,
        ),
    ];
    assert!(matches!(
        specialize_batch(&reqs, &cfg, epoch()),
        Err(SpecializationError::SpecializationLimitExceeded { .. })
    ));
}

#[test]
fn enrichment_batch_summary_mixed_verdicts() {
    let reqs = vec![
        make_request(
            LaneKind::ServerSideRender,
            ComponentShape::PureFunction,
            SpecializationStrategy::ConstantFolding,
        ),
        make_request(
            LaneKind::ClientEntry,
            ComponentShape::HookBased,
            SpecializationStrategy::PartialEvaluation,
        ),
    ];
    let cfg = SpecializationConfig::default_config();
    let (results, _) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
    let s = BatchSummary::from_results(&results);
    assert_eq!(s.total, 2);
    assert!(s.applied >= 1);
    assert!(s.applied + s.rejected + s.deferred == s.total);
}

#[test]
fn enrichment_batch_summary_serde_round_trip() {
    let reqs = vec![make_request(
        LaneKind::ServerSideRender,
        ComponentShape::PureFunction,
        SpecializationStrategy::ConstantFolding,
    )];
    let cfg = SpecializationConfig::default_config();
    let (results, _) = specialize_batch(&reqs, &cfg, epoch()).unwrap();
    let s = BatchSummary::from_results(&results);
    let json = serde_json::to_string(&s).unwrap();
    let back: BatchSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn enrichment_error_display_all_variants() {
    let errors: Vec<SpecializationError> = vec![
        SpecializationError::InvalidConfig { reason: "r".into() },
        SpecializationError::InlineDepthExceeded { depth: 10, max: 8 },
        SpecializationError::SpecializationLimitExceeded { count: 17, max: 16 },
        SpecializationError::MissingSafetyCheck {
            kind: SafetyCheckKind::PurityProof,
        },
        SpecializationError::Internal { detail: "d".into() },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}

#[test]
fn enrichment_error_serde_all_variants() {
    let errors: Vec<SpecializationError> = vec![
        SpecializationError::InvalidConfig {
            reason: "bad".into(),
        },
        SpecializationError::InlineDepthExceeded { depth: 10, max: 8 },
        SpecializationError::SpecializationLimitExceeded { count: 17, max: 16 },
        SpecializationError::MissingSafetyCheck {
            kind: SafetyCheckKind::NoAmbientMutation,
        },
        SpecializationError::Internal {
            detail: "oops".into(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: SpecializationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

#[test]
fn enrichment_safety_check_pass_fail_different_evidence_hash() {
    let pass = SafetyCheck::pass(SafetyCheckKind::PurityProof, b"ev-a", "passed");
    let fail = SafetyCheck::fail(SafetyCheckKind::PurityProof, b"ev-b", "failed");
    assert_ne!(pass.evidence_hash, fail.evidence_hash);
}

#[test]
fn enrichment_specialize_request_serde_round_trip() {
    let req = make_request(
        LaneKind::IslandsArchitecture,
        ComponentShape::ForwardRef,
        SpecializationStrategy::ShapeSpecialization,
    );
    let json = serde_json::to_string(&req).unwrap();
    let back: SpecializationRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

#[test]
fn enrichment_config_serde_round_trip() {
    let cfg = SpecializationConfig::default_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: SpecializationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}
