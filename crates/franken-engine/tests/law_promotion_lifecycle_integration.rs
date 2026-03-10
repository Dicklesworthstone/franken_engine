use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::law_mining::{CandidateKind, LawCandidate};
use frankenengine_engine::law_promotion_lifecycle::{
    LifecycleConfig, LifecycleError, LifecycleEventKind, LifecyclePipeline, RefusalReason,
    RoutingDecision,
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
