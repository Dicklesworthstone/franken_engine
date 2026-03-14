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
use frankenengine_engine::law_mining::{CandidateKind, LawCandidate};
use frankenengine_engine::law_promotion_lifecycle::{
    LifecycleConfig, LifecycleError, LifecycleEventKind, LifecyclePipeline, RefusalReason,
};
use frankenengine_engine::law_promotion_pack::{LawStrength, PromotionStatus, PromotionTarget};
use frankenengine_engine::law_proof_refutation::{
    ProofCampaignConfig, ProofCampaignResult, ProofRefutationPipeline, ProofVerdict,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn test_candidate(id: &str, kind: CandidateKind) -> LawCandidate {
    let hash_data = format!("candidate:{id}:{kind:?}");
    LawCandidate {
        candidate_id: id.to_string(),
        kind,
        statement: format!("law-statement-{id}"),
        rank_millionths: 750_000,
        ranking_rationale: format!("rationale-{id}"),
        scope_hypothesis_id: format!("scope-{id}"),
        provenance_id: format!("prov-{id}"),
        supporting_source_ids: vec![format!("src-{id}")],
        candidate_hash: ContentHash::compute(hash_data.as_bytes()),
    }
}

fn accepted_result(candidate_id: &str, kind: CandidateKind) -> ProofCampaignResult {
    let hash_data = format!("accepted:{candidate_id}:{kind:?}");
    ProofCampaignResult {
        candidate_id: candidate_id.to_string(),
        candidate_kind: kind,
        final_verdict: ProofVerdict::Proved,
        aggregate_confidence_millionths: 950_000,
        attempts: Vec::new(),
        refutation_witness_ids: Vec::new(),
        accepted: true,
        rationale: "proved with high confidence".to_string(),
        campaign_epoch: epoch(10),
        result_hash: ContentHash::compute(hash_data.as_bytes()),
    }
}

fn rejected_result(candidate_id: &str, kind: CandidateKind) -> ProofCampaignResult {
    let hash_data = format!("rejected:{candidate_id}:{kind:?}");
    ProofCampaignResult {
        candidate_id: candidate_id.to_string(),
        candidate_kind: kind,
        final_verdict: ProofVerdict::Refuted,
        aggregate_confidence_millionths: 200_000,
        attempts: Vec::new(),
        refutation_witness_ids: Vec::new(),
        accepted: false,
        rationale: "refuted by counterexample".to_string(),
        campaign_epoch: epoch(10),
        result_hash: ContentHash::compute(hash_data.as_bytes()),
    }
}

// ===========================================================================
// LifecycleEventKind integration tests
// ===========================================================================

#[test]
fn event_kind_all_unique() {
    let mut seen = BTreeSet::new();
    for k in LifecycleEventKind::ALL {
        assert!(seen.insert(k.to_string()), "duplicate kind: {k}");
    }
}

#[test]
fn event_kind_serde_roundtrip_all() {
    for k in LifecycleEventKind::ALL {
        let json = serde_json::to_string(k).unwrap();
        let back: LifecycleEventKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, back);
    }
}

#[test]
fn event_kind_terminal_semantics() {
    let terminal: Vec<_> = LifecycleEventKind::ALL
        .iter()
        .filter(|k| k.is_terminal())
        .collect();
    assert_eq!(terminal.len(), 3);
}

// ===========================================================================
// RefusalReason integration tests
// ===========================================================================

#[test]
fn refusal_reason_all_variants_serde() {
    let reasons = vec![
        RefusalReason::InsufficientStrength {
            actual: LawStrength::Heuristic,
            minimum: LawStrength::Conditional,
        },
        RefusalReason::InsufficientConfidence {
            actual_millionths: 500_000,
            minimum_millionths: 800_000,
        },
        RefusalReason::PreviouslyRevoked {
            law_id: "law-1".to_string(),
        },
        RefusalReason::DuplicateLaw {
            existing_law_id: "law-2".to_string(),
        },
        RefusalReason::NoValidTargets {
            kind: CandidateKind::Invariant,
        },
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: RefusalReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

#[test]
fn refusal_reason_display_all_contain_info() {
    let reasons = vec![
        RefusalReason::InsufficientStrength {
            actual: LawStrength::Heuristic,
            minimum: LawStrength::Conditional,
        },
        RefusalReason::InsufficientConfidence {
            actual_millionths: 500_000,
            minimum_millionths: 800_000,
        },
        RefusalReason::PreviouslyRevoked {
            law_id: "law-1".to_string(),
        },
    ];
    for r in &reasons {
        let display = r.to_string();
        assert!(!display.is_empty());
    }
}

// ===========================================================================
// LifecycleError integration tests
// ===========================================================================

#[test]
fn error_all_variants_serde() {
    let errors = vec![
        LifecycleError::LawNotFound {
            law_id: "a".to_string(),
        },
        LifecycleError::AlreadyPromoted {
            law_id: "b".to_string(),
        },
        LifecycleError::AlreadyRevoked {
            law_id: "c".to_string(),
        },
        LifecycleError::InvalidConfig {
            detail: "d".to_string(),
        },
        LifecycleError::PromotionError {
            detail: "e".to_string(),
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: LifecycleError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ===========================================================================
// LifecycleConfig integration tests
// ===========================================================================

#[test]
fn config_serde_roundtrip() {
    let config = LifecycleConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: LifecycleConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn config_custom_values_roundtrip() {
    let config = LifecycleConfig {
        min_auto_strength: LawStrength::Proved,
        min_auto_confidence_millionths: 900_000,
        expiration_window_epochs: 5,
        auto_route_by_kind: false,
        allow_heuristic: true,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: LifecycleConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ===========================================================================
// Pipeline promotion integration tests
// ===========================================================================

#[test]
fn promote_invariant_creates_four_receipts() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let c = test_candidate("inv-1", CandidateKind::Invariant);
    let r = accepted_result("inv-1", CandidateKind::Invariant);

    let event = p.promote_law(&c, &r);
    assert_eq!(event.kind, LifecycleEventKind::Promoted);
    assert_eq!(p.promotion_pipeline.receipts.len(), 4);

    // Verify all four targets
    let receipt_targets: BTreeSet<_> = p
        .promotion_pipeline
        .receipts
        .iter()
        .map(|r| r.target)
        .collect();
    assert_eq!(receipt_targets.len(), 4);
}

#[test]
fn promote_side_condition_creates_two_receipts() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let c = test_candidate("sc-1", CandidateKind::SideCondition);
    let r = accepted_result("sc-1", CandidateKind::SideCondition);

    p.promote_law(&c, &r);
    assert_eq!(p.promotion_pipeline.receipts.len(), 2);

    let targets: Vec<_> = p
        .promotion_pipeline
        .receipts
        .iter()
        .map(|r| r.target)
        .collect();
    assert!(targets.contains(&PromotionTarget::RewritePack));
    assert!(targets.contains(&PromotionTarget::SupportAtlas));
}

#[test]
fn promote_normal_form_creates_two_receipts() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let c = test_candidate("nf-1", CandidateKind::NormalForm);
    let r = accepted_result("nf-1", CandidateKind::NormalForm);

    p.promote_law(&c, &r);
    assert_eq!(p.promotion_pipeline.receipts.len(), 2);

    let targets: Vec<_> = p
        .promotion_pipeline
        .receipts
        .iter()
        .map(|r| r.target)
        .collect();
    assert!(targets.contains(&PromotionTarget::SynthesisLane));
    assert!(targets.contains(&PromotionTarget::FrontierLedger));
}

#[test]
fn promote_multiple_kinds_correct_total_receipts() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));

    let c1 = test_candidate("multi-inv", CandidateKind::Invariant);
    let r1 = accepted_result("multi-inv", CandidateKind::Invariant);
    p.promote_law(&c1, &r1);

    let c2 = test_candidate("multi-sc", CandidateKind::SideCondition);
    let r2 = accepted_result("multi-sc", CandidateKind::SideCondition);
    p.promote_law(&c2, &r2);

    let c3 = test_candidate("multi-nf", CandidateKind::NormalForm);
    let r3 = accepted_result("multi-nf", CandidateKind::NormalForm);
    p.promote_law(&c3, &r3);

    // Invariant(4) + SideCondition(2) + NormalForm(2) = 8
    assert_eq!(p.promotion_pipeline.receipts.len(), 8);
    assert_eq!(p.accepted_laws.len(), 3);
}

// ===========================================================================
// Refusal integration tests
// ===========================================================================

#[test]
fn refuse_rejected_candidate() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let c = test_candidate("rej-1", CandidateKind::Invariant);
    let r = rejected_result("rej-1", CandidateKind::Invariant);

    let event = p.promote_law(&c, &r);
    assert_eq!(event.kind, LifecycleEventKind::Refused);
    assert!(event.refusal_reason.is_some());
    assert!(p.accepted_laws.is_empty());
    assert!(p.promotion_pipeline.receipts.is_empty());
}

#[test]
fn refuse_insufficient_strength() {
    let config = LifecycleConfig {
        min_auto_strength: LawStrength::Proved,
        ..LifecycleConfig::default()
    };
    let mut p = LifecyclePipeline::new(config, epoch(10));
    let c = test_candidate("weak-1", CandidateKind::Invariant);
    let mut r = accepted_result("weak-1", CandidateKind::Invariant);
    r.aggregate_confidence_millionths = 850_000; // Empirical, not Proved

    let event = p.promote_law(&c, &r);
    assert_eq!(event.kind, LifecycleEventKind::Refused);
}

#[test]
fn refuse_duplicate_promotion() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let c = test_candidate("dup-1", CandidateKind::Invariant);
    let r = accepted_result("dup-1", CandidateKind::Invariant);

    p.promote_law(&c, &r);
    let e2 = p.promote_law(&c, &r);
    assert_eq!(e2.kind, LifecycleEventKind::Refused);
    // Only one accepted law
    assert_eq!(p.accepted_laws.len(), 1);
}

// ===========================================================================
// Revocation integration tests
// ===========================================================================

#[test]
fn revoke_marks_receipts_revoked() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let c = test_candidate("rev-1", CandidateKind::Invariant);
    let r = accepted_result("rev-1", CandidateKind::Invariant);
    p.promote_law(&c, &r);

    p.revoke_law("law-rev-1", "regression");

    let revoked_receipts: Vec<_> = p
        .promotion_pipeline
        .receipts
        .iter()
        .filter(|r| r.status == PromotionStatus::Revoked)
        .collect();
    assert_eq!(revoked_receipts.len(), 4); // All 4 receipts revoked
}

#[test]
fn revoke_removes_from_active() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let c = test_candidate("ract-1", CandidateKind::Invariant);
    let r = accepted_result("ract-1", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    assert_eq!(p.active_law_ids().len(), 1);

    p.revoke_law("law-ract-1", "test");
    assert_eq!(p.active_law_ids().len(), 0);
}

#[test]
fn revoke_idempotent() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let c = test_candidate("ridem-1", CandidateKind::Invariant);
    let r = accepted_result("ridem-1", CandidateKind::Invariant);
    p.promote_law(&c, &r);

    assert!(p.revoke_law("law-ridem-1", "first").is_some());
    assert!(p.revoke_law("law-ridem-1", "second").is_none());
}

// ===========================================================================
// Supersession integration tests
// ===========================================================================

#[test]
fn supersede_marks_receipts_superseded() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let c = test_candidate("sup-1", CandidateKind::Invariant);
    let r = accepted_result("sup-1", CandidateKind::Invariant);
    p.promote_law(&c, &r);

    p.supersede_law("law-sup-1", "law-sup-new", "stronger");

    let superseded: Vec<_> = p
        .promotion_pipeline
        .receipts
        .iter()
        .filter(|r| r.status == PromotionStatus::Superseded)
        .collect();
    assert_eq!(superseded.len(), 4);
}

#[test]
fn supersede_records_superseding_law_id() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let c = test_candidate("sup2-1", CandidateKind::Invariant);
    let r = accepted_result("sup2-1", CandidateKind::Invariant);
    p.promote_law(&c, &r);

    let event = p
        .supersede_law("law-sup2-1", "law-better", "more general")
        .unwrap();
    assert_eq!(event.superseding_law_id.as_deref(), Some("law-better"));
}

// ===========================================================================
// Expiration integration tests
// ===========================================================================

#[test]
fn expire_after_window() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(5));
    let c = test_candidate("exp-1", CandidateKind::Invariant);
    let r = accepted_result("exp-1", CandidateKind::Invariant);
    p.promote_law(&c, &r);

    let events = p.expire_stale_laws(epoch(16));
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, LifecycleEventKind::Expired);
}

#[test]
fn no_expire_within_window() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let c = test_candidate("noexp-1", CandidateKind::Invariant);
    let r = accepted_result("noexp-1", CandidateKind::Invariant);
    p.promote_law(&c, &r);

    let events = p.expire_stale_laws(epoch(15));
    assert!(events.is_empty());
}

#[test]
fn no_expire_already_revoked() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(5));
    let c = test_candidate("exprev-1", CandidateKind::Invariant);
    let r = accepted_result("exprev-1", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    p.revoke_law("law-exprev-1", "regression");

    let events = p.expire_stale_laws(epoch(20));
    assert!(events.is_empty()); // Already revoked, skip
}

#[test]
fn no_expire_already_superseded() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(5));
    let c = test_candidate("expsup-1", CandidateKind::Invariant);
    let r = accepted_result("expsup-1", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    p.supersede_law("law-expsup-1", "law-new", "better");

    let events = p.expire_stale_laws(epoch(20));
    assert!(events.is_empty()); // Already superseded
}

// ===========================================================================
// Batch promotion integration tests
// ===========================================================================

#[test]
fn batch_promotes_all_accepted() {
    let candidates: Vec<LawCandidate> = (0..5)
        .map(|i| test_candidate(&format!("batch-{i}"), CandidateKind::Invariant))
        .collect();

    let config = ProofCampaignConfig::default();
    let mut proof_pipeline = ProofRefutationPipeline::new(config, epoch(10));
    for c in &candidates {
        proof_pipeline.run_campaign(c);
    }

    let mut lc = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    lc.promote_batch(&candidates, &proof_pipeline);

    // All should have lifecycle events (either Promoted or Refused)
    assert_eq!(lc.lifecycle_events.len(), 5);
}

// ===========================================================================
// Routing integration tests
// ===========================================================================

#[test]
fn routing_auto_disabled_sends_to_all() {
    let config = LifecycleConfig {
        auto_route_by_kind: false,
        ..LifecycleConfig::default()
    };
    let mut p = LifecyclePipeline::new(config, epoch(10));
    let c = test_candidate("noauto-1", CandidateKind::SideCondition);
    let r = accepted_result("noauto-1", CandidateKind::SideCondition);

    let event = p.promote_law(&c, &r);
    assert_eq!(event.affected_targets.len(), 4);
}

#[test]
fn routing_for_returns_correct_decision() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let c = test_candidate("rfor-1", CandidateKind::NormalForm);
    let r = accepted_result("rfor-1", CandidateKind::NormalForm);
    p.promote_law(&c, &r);

    let routing = p.routing_for("law-rfor-1").unwrap();
    assert_eq!(routing.candidate_kind, CandidateKind::NormalForm);
    assert_eq!(routing.selected_targets.len(), 2);
}

// ===========================================================================
// Summary integration tests
// ===========================================================================

#[test]
fn summary_counts_correct() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(5));

    // 3 promoted
    for i in 0..3 {
        let c = test_candidate(&format!("sum-{i}"), CandidateKind::Invariant);
        let r = accepted_result(&format!("sum-{i}"), CandidateKind::Invariant);
        p.promote_law(&c, &r);
    }

    // 1 refused
    let c_rej = test_candidate("sum-rej", CandidateKind::Invariant);
    let r_rej = rejected_result("sum-rej", CandidateKind::Invariant);
    p.promote_law(&c_rej, &r_rej);

    // 1 revoked
    p.revoke_law("law-sum-0", "test");

    // 1 expired
    p.expire_stale_laws(epoch(20));

    let summary = p.summary_report();
    assert_eq!(summary.total_accepted, 3);
    assert_eq!(summary.promoted_count, 3);
    assert_eq!(summary.refused_count, 1);
    assert_eq!(summary.revoked_count, 1);
    // sum-0 was revoked, so won't also expire; sum-1 and sum-2 expire
    assert_eq!(summary.expired_count, 2);
    assert!(summary.mean_priority_millionths > 0);
}

#[test]
fn summary_target_breakdown() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let c = test_candidate("tb-1", CandidateKind::Invariant);
    let r = accepted_result("tb-1", CandidateKind::Invariant);
    p.promote_law(&c, &r);

    let summary = p.summary_report();
    assert_eq!(summary.receipts_by_target.len(), 4);
    for tb in &summary.receipts_by_target {
        assert_eq!(tb.receipt_count, 1);
    }
}

// ===========================================================================
// Serde and determinism integration tests
// ===========================================================================

#[test]
fn pipeline_full_serde_roundtrip() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    for i in 0..3 {
        let kind = match i % 3 {
            0 => CandidateKind::Invariant,
            1 => CandidateKind::SideCondition,
            _ => CandidateKind::NormalForm,
        };
        let c = test_candidate(&format!("serde-{i}"), kind);
        let r = accepted_result(&format!("serde-{i}"), kind);
        p.promote_law(&c, &r);
    }
    p.revoke_law("law-serde-0", "test");

    let json = serde_json::to_string(&p).unwrap();
    let back: LifecyclePipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(p.pipeline_hash, back.pipeline_hash);
}

#[test]
fn pipeline_deterministic_same_inputs() {
    let mut p1 = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let mut p2 = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));

    for i in 0..4 {
        let c = test_candidate(&format!("det-{i}"), CandidateKind::Invariant);
        let r = accepted_result(&format!("det-{i}"), CandidateKind::Invariant);
        p1.promote_law(&c, &r);
        p2.promote_law(&c, &r);
    }

    assert_eq!(p1.pipeline_hash, p2.pipeline_hash);
}

// ===========================================================================
// Edge case integration tests
// ===========================================================================

#[test]
fn empty_pipeline_summary() {
    let p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let summary = p.summary_report();
    assert_eq!(summary.total_accepted, 0);
    assert_eq!(summary.promoted_count, 0);
    assert_eq!(summary.mean_priority_millionths, 0);
}

#[test]
fn events_for_unknown_law() {
    let p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let events = p.events_for("nonexistent");
    assert!(events.is_empty());
}

#[test]
fn routing_for_unknown_law() {
    let p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    assert!(p.routing_for("nonexistent").is_none());
}

#[test]
fn revoke_nonexistent_returns_none() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    assert!(p.revoke_law("nonexistent", "test").is_none());
}

#[test]
fn supersede_nonexistent_returns_none() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    assert!(p.supersede_law("nonexistent", "new", "test").is_none());
}

#[test]
fn large_batch_mixed_kinds_lifecycle() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(5));

    let kinds = [
        CandidateKind::Invariant,
        CandidateKind::SideCondition,
        CandidateKind::NormalForm,
    ];

    // Promote 15 laws
    for i in 0..15 {
        let kind = kinds[i % 3];
        let c = test_candidate(&format!("big-{i}"), kind);
        let r = accepted_result(&format!("big-{i}"), kind);
        p.promote_law(&c, &r);
    }
    assert_eq!(p.accepted_laws.len(), 15);

    // Revoke 3
    for i in (0..15).step_by(5) {
        p.revoke_law(&format!("law-big-{i}"), "regression");
    }
    assert_eq!(p.active_law_ids().len(), 12);

    // Supersede 2
    p.supersede_law("law-big-1", "law-big-new", "better");
    p.supersede_law("law-big-2", "law-big-new-2", "more general");
    assert_eq!(p.active_law_ids().len(), 10);

    // Expire stale
    let expired_events = p.expire_stale_laws(epoch(20));
    // 15 - 3 revoked - 2 superseded = 10 expire
    assert_eq!(expired_events.len(), 10);
    assert!(p.active_law_ids().is_empty());

    let summary = p.summary_report();
    assert_eq!(summary.total_accepted, 15);
    assert_eq!(summary.promoted_count, 15);
    assert_eq!(summary.revoked_count, 3);
    assert_eq!(summary.superseded_count, 2);
    assert_eq!(summary.expired_count, 10);
}

// ===========================================================================
// Additional edge-case and API coverage tests
// ===========================================================================

#[test]
fn test_lifecycle_event_kind_display_values() {
    assert_eq!(LifecycleEventKind::Promoted.to_string(), "promoted");
    assert_eq!(LifecycleEventKind::Revoked.to_string(), "revoked");
    assert_eq!(LifecycleEventKind::Superseded.to_string(), "superseded");
    assert_eq!(LifecycleEventKind::Expired.to_string(), "expired");
    assert_eq!(LifecycleEventKind::Refused.to_string(), "refused");
}

#[test]
fn test_lifecycle_event_kind_is_terminal_boundaries() {
    assert!(!LifecycleEventKind::Promoted.is_terminal());
    assert!(!LifecycleEventKind::Refused.is_terminal());
    assert!(LifecycleEventKind::Revoked.is_terminal());
    assert!(LifecycleEventKind::Superseded.is_terminal());
    assert!(LifecycleEventKind::Expired.is_terminal());
    // Exactly 3 terminal kinds
    let terminal_count = LifecycleEventKind::ALL
        .iter()
        .filter(|k| k.is_terminal())
        .count();
    assert_eq!(terminal_count, 3);
}

#[test]
fn test_lifecycle_event_kind_clone_and_partial_eq() {
    let k = LifecycleEventKind::Superseded;
    let k2 = k;
    assert_eq!(k, k2);
    assert_ne!(k, LifecycleEventKind::Refused);
}

#[test]
fn test_refusal_reason_display_insufficient_strength() {
    let r = RefusalReason::InsufficientStrength {
        actual: LawStrength::Heuristic,
        minimum: LawStrength::Proved,
    };
    let s = r.to_string();
    assert!(s.contains("heuristic"));
    assert!(s.contains("proved"));
}

#[test]
fn test_refusal_reason_display_insufficient_confidence() {
    let r = RefusalReason::InsufficientConfidence {
        actual_millionths: 400_000,
        minimum_millionths: 800_000,
    };
    let s = r.to_string();
    assert!(s.contains("400000"));
    assert!(s.contains("800000"));
}

#[test]
fn test_refusal_reason_display_previously_revoked() {
    let r = RefusalReason::PreviouslyRevoked {
        law_id: "my-revoked-law".to_string(),
    };
    let s = r.to_string();
    assert!(s.contains("my-revoked-law"));
}

#[test]
fn test_refusal_reason_display_duplicate_law() {
    let r = RefusalReason::DuplicateLaw {
        existing_law_id: "law-existing".to_string(),
    };
    let s = r.to_string();
    assert!(s.contains("law-existing"));
}

#[test]
fn test_refusal_reason_display_no_valid_targets() {
    let r = RefusalReason::NoValidTargets {
        kind: CandidateKind::NormalForm,
    };
    let s = r.to_string();
    assert!(!s.is_empty());
    assert!(s.contains("NormalForm"));
}

#[test]
fn test_lifecycle_error_display_all_variants() {
    let cases = vec![
        (
            LifecycleError::LawNotFound {
                law_id: "x".to_string(),
            },
            "law not found",
        ),
        (
            LifecycleError::AlreadyPromoted {
                law_id: "y".to_string(),
            },
            "already promoted",
        ),
        (
            LifecycleError::AlreadyRevoked {
                law_id: "z".to_string(),
            },
            "already revoked",
        ),
        (
            LifecycleError::InvalidConfig {
                detail: "bad".to_string(),
            },
            "invalid config",
        ),
        (
            LifecycleError::PromotionError {
                detail: "fail".to_string(),
            },
            "promotion error",
        ),
    ];
    for (err, expected_fragment) in &cases {
        let s = err.to_string();
        assert!(
            s.contains(expected_fragment),
            "Expected '{expected_fragment}' in '{s}'"
        );
    }
}

#[test]
fn test_lifecycle_error_clone_and_eq() {
    let e = LifecycleError::LawNotFound {
        law_id: "abc".to_string(),
    };
    let e2 = e.clone();
    assert_eq!(e, e2);
    assert_ne!(
        e,
        LifecycleError::AlreadyRevoked {
            law_id: "abc".to_string()
        }
    );
}

#[test]
fn test_lifecycle_config_default_values() {
    let cfg = LifecycleConfig::default();
    assert_eq!(cfg.min_auto_strength, LawStrength::Conditional);
    assert_eq!(cfg.min_auto_confidence_millionths, 800_000);
    assert_eq!(cfg.expiration_window_epochs, 10);
    assert!(cfg.auto_route_by_kind);
    assert!(!cfg.allow_heuristic);
}

#[test]
fn test_lifecycle_config_debug_contains_field_names() {
    let cfg = LifecycleConfig::default();
    let dbg = format!("{cfg:?}");
    assert!(dbg.contains("min_auto_strength"));
    assert!(dbg.contains("expiration_window_epochs"));
}

#[test]
fn test_refusal_reason_clone_preserves_data() {
    let original = RefusalReason::InsufficientConfidence {
        actual_millionths: 500_000,
        minimum_millionths: 900_000,
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn test_refusal_reason_serde_no_valid_targets() {
    let r = RefusalReason::NoValidTargets {
        kind: CandidateKind::SideCondition,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: RefusalReason = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn test_promote_at_epoch_boundary_expiration() {
    // Law promoted at epoch 0, window=10, expire check at epoch 11 (just past window)
    let config = LifecycleConfig {
        expiration_window_epochs: 10,
        ..LifecycleConfig::default()
    };
    let mut p = LifecyclePipeline::new(config, epoch(0));
    let c = test_candidate("boundary-exp", CandidateKind::Invariant);
    let r = accepted_result("boundary-exp", CandidateKind::Invariant);
    p.promote_law(&c, &r);

    // At exactly window (10), not expired
    let events = p.expire_stale_laws(epoch(10));
    assert!(events.is_empty(), "Should not expire at exactly window");

    // At window+1 (11), expired
    let events = p.expire_stale_laws(epoch(11));
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, LifecycleEventKind::Expired);
}

#[test]
fn test_promote_law_confidence_below_threshold_refused() {
    let config = LifecycleConfig {
        min_auto_confidence_millionths: 900_000,
        ..LifecycleConfig::default()
    };
    let mut p = LifecyclePipeline::new(config, epoch(10));
    let c = test_candidate("lowconf-1", CandidateKind::Invariant);
    // accepted=false triggers InsufficientConfidence
    let hash_data = "lowconf_result";
    let r = frankenengine_engine::law_proof_refutation::ProofCampaignResult {
        candidate_id: "lowconf-1".to_string(),
        candidate_kind: CandidateKind::Invariant,
        final_verdict: frankenengine_engine::law_proof_refutation::ProofVerdict::Proved,
        aggregate_confidence_millionths: 850_000,
        attempts: Vec::new(),
        refutation_witness_ids: Vec::new(),
        accepted: false,
        rationale: "not enough confidence".to_string(),
        campaign_epoch: epoch(10),
        result_hash: frankenengine_engine::hash_tiers::ContentHash::compute(hash_data.as_bytes()),
    };
    let event = p.promote_law(&c, &r);
    assert_eq!(event.kind, LifecycleEventKind::Refused);
    let reason = event.refusal_reason.unwrap();
    assert!(matches!(
        reason,
        RefusalReason::InsufficientConfidence { .. }
    ));
}

#[test]
fn test_revoke_then_promote_same_candidate_refused() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let c = test_candidate("revthen-1", CandidateKind::Invariant);
    let r = accepted_result("revthen-1", CandidateKind::Invariant);

    // First promote succeeds
    let e1 = p.promote_law(&c, &r);
    assert_eq!(e1.kind, LifecycleEventKind::Promoted);

    // Revoke it
    p.revoke_law("law-revthen-1", "regression");

    // Attempting to promote again (duplicate) returns Refused with DuplicateLaw
    let e2 = p.promote_law(&c, &r);
    assert_eq!(e2.kind, LifecycleEventKind::Refused);
    // DuplicateLaw fires because candidate_id matches existing accepted law
    assert!(matches!(
        e2.refusal_reason.unwrap(),
        RefusalReason::DuplicateLaw { .. }
    ));
}

#[test]
fn test_summary_serde_roundtrip() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(5));
    let c = test_candidate("sumser-1", CandidateKind::Invariant);
    let r = accepted_result("sumser-1", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    p.revoke_law("law-sumser-1", "test");
    let summary = p.summary_report();

    let json = serde_json::to_string(&summary).unwrap();
    let back: frankenengine_engine::law_promotion_lifecycle::LifecycleSummary =
        serde_json::from_str(&json).unwrap();
    assert_eq!(summary.total_accepted, back.total_accepted);
    assert_eq!(summary.revoked_count, back.revoked_count);
    assert_eq!(
        summary.receipts_by_target.len(),
        back.receipts_by_target.len()
    );
}

#[test]
fn test_routing_decision_display_contains_law_id() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let c = test_candidate("displaw-1", CandidateKind::NormalForm);
    let r = accepted_result("displaw-1", CandidateKind::NormalForm);
    p.promote_law(&c, &r);

    let routing = p.routing_for("law-displaw-1").unwrap();
    let display = format!("{routing}");
    assert!(display.contains("law-displaw-1"));
    assert!(display.contains("NormalForm"));
}

#[test]
fn test_lifecycle_event_display_format() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let c = test_candidate("evtdisp-1", CandidateKind::Invariant);
    let r = accepted_result("evtdisp-1", CandidateKind::Invariant);
    let event = p.promote_law(&c, &r);

    let display = format!("{event}");
    assert!(display.contains("LifecycleEvent"));
    assert!(display.contains("law-evtdisp-1"));
    assert!(display.contains("promoted"));
}

#[test]
fn test_supersede_idempotent_second_call_returns_none() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let c = test_candidate("supidem-1", CandidateKind::Invariant);
    let r = accepted_result("supidem-1", CandidateKind::Invariant);
    p.promote_law(&c, &r);

    let e1 = p.supersede_law("law-supidem-1", "law-new", "better");
    assert!(e1.is_some());

    let e2 = p.supersede_law("law-supidem-1", "law-new", "better");
    assert!(e2.is_none());
}

#[test]
fn test_events_for_returns_all_events_for_law() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let c = test_candidate("evtsfor-1", CandidateKind::Invariant);
    let r = accepted_result("evtsfor-1", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    p.revoke_law("law-evtsfor-1", "test");

    let events = p.events_for("law-evtsfor-1");
    assert_eq!(events.len(), 2);
    // First event is Promoted, second is Revoked
    assert_eq!(events[0].kind, LifecycleEventKind::Promoted);
    assert_eq!(events[1].kind, LifecycleEventKind::Revoked);
}

#[test]
fn test_empty_batch_promotion_no_panic() {
    use frankenengine_engine::law_proof_refutation::{
        ProofCampaignConfig, ProofRefutationPipeline,
    };
    let candidates: Vec<frankenengine_engine::law_mining::LawCandidate> = Vec::new();
    let config = ProofCampaignConfig::default();
    let proof_pipeline = ProofRefutationPipeline::new(config, epoch(10));

    let mut lc = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    lc.promote_batch(&candidates, &proof_pipeline);

    assert_eq!(lc.lifecycle_events.len(), 0);
    assert_eq!(lc.accepted_laws.len(), 0);
}

#[test]
fn test_pipeline_schema_version_and_bead_id() {
    let p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    assert_eq!(
        p.schema_version,
        "franken-engine.law-promotion-lifecycle.v1"
    );
    assert_eq!(p.bead_id, "bd-1lsy.9.10.3");
}

#[test]
fn test_summary_total_receipts_matches_receipt_list() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    // Invariant = 4 receipts, SideCondition = 2, NormalForm = 2 => 8 total
    for (id, kind) in [
        ("tr-inv", CandidateKind::Invariant),
        ("tr-sc", CandidateKind::SideCondition),
        ("tr-nf", CandidateKind::NormalForm),
    ] {
        let c = test_candidate(id, kind);
        let r = accepted_result(id, kind);
        p.promote_law(&c, &r);
    }

    let summary = p.summary_report();
    assert_eq!(summary.total_receipts, p.promotion_pipeline.receipts.len());
    assert_eq!(summary.total_receipts, 8);
}

#[test]
fn test_allow_heuristic_config_promotes_low_confidence() {
    // With allow_heuristic=true and low confidence, Heuristic strength is allowed
    let config = LifecycleConfig {
        allow_heuristic: true,
        min_auto_strength: LawStrength::Heuristic,
        min_auto_confidence_millionths: 100_000,
        ..LifecycleConfig::default()
    };
    let mut p = LifecyclePipeline::new(config, epoch(10));
    let c = test_candidate("heuristic-allow", CandidateKind::Invariant);
    // Inconclusive verdict with low confidence -> Heuristic strength
    let r = frankenengine_engine::law_proof_refutation::ProofCampaignResult {
        candidate_id: "heuristic-allow".to_string(),
        candidate_kind: CandidateKind::Invariant,
        final_verdict: frankenengine_engine::law_proof_refutation::ProofVerdict::Inconclusive,
        aggregate_confidence_millionths: 400_000,
        attempts: Vec::new(),
        refutation_witness_ids: Vec::new(),
        accepted: true,
        rationale: "inconclusive but accepted".to_string(),
        campaign_epoch: epoch(10),
        result_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"heuristic_result"),
    };
    let event = p.promote_law(&c, &r);
    assert_eq!(event.kind, LifecycleEventKind::Promoted);
}

#[test]
fn test_target_breakdown_active_count_decreases_on_revoke() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
    let c = test_candidate("activecount-1", CandidateKind::Invariant);
    let r = accepted_result("activecount-1", CandidateKind::Invariant);
    p.promote_law(&c, &r);

    let before = p.summary_report();
    // All 4 targets should have 1 active receipt each
    for tb in &before.receipts_by_target {
        if tb.receipt_count > 0 {
            assert_eq!(tb.active_count, 1);
        }
    }

    p.revoke_law("law-activecount-1", "test");

    let after = p.summary_report();
    // After revoke, no receipts should be active
    for tb in &after.receipts_by_target {
        assert_eq!(tb.active_count, 0);
    }
}
