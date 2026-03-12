//! Enrichment integration tests for `law_promotion_lifecycle`.
//!
//! Covers gaps: lifecycle event hash sensitivity, pipeline hash mutation
//! tracking, verdict-to-strength boundary conditions, complete refusal
//! reason paths, LifecycleSummary serde roundtrip, target routing
//! exhaustive matrix, event ordering after multiple operations,
//! config default values, Display format verification, and
//! complex lifecycle sequences (promote → revoke → re-refuse).

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::law_mining::{CandidateKind, LawCandidate};
use frankenengine_engine::law_promotion_lifecycle::*;
use frankenengine_engine::law_promotion_pack::{LawStrength, PromotionTarget};
use frankenengine_engine::law_proof_refutation::{ProofCampaignResult, ProofVerdict};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn make_result(
    candidate_id: &str,
    kind: CandidateKind,
    verdict: ProofVerdict,
    confidence: u64,
    accepted: bool,
) -> ProofCampaignResult {
    let hash_data = format!("result:{candidate_id}:{kind:?}:{confidence}");
    ProofCampaignResult {
        candidate_id: candidate_id.to_string(),
        candidate_kind: kind,
        final_verdict: verdict,
        aggregate_confidence_millionths: confidence,
        attempts: Vec::new(),
        refutation_witness_ids: Vec::new(),
        accepted,
        rationale: format!("{verdict:?} at {confidence}"),
        campaign_epoch: epoch(10),
        result_hash: ContentHash::compute(hash_data.as_bytes()),
    }
}

fn accepted_result(id: &str, kind: CandidateKind) -> ProofCampaignResult {
    make_result(id, kind, ProofVerdict::Proved, 950_000, true)
}

fn default_pipeline() -> LifecyclePipeline {
    LifecyclePipeline::new(LifecycleConfig::default(), epoch(10))
}

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_schema_version_starts_with_prefix() {
    assert!(LAW_PROMOTION_LIFECYCLE_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn enrichment_bead_id_and_component_non_empty() {
    assert!(!LAW_PROMOTION_LIFECYCLE_BEAD_ID.is_empty());
    assert!(!COMPONENT.is_empty());
}

// ---------------------------------------------------------------------------
// LifecycleEventKind
// ---------------------------------------------------------------------------

#[test]
fn enrichment_event_kind_count() {
    assert_eq!(LifecycleEventKind::ALL.len(), 5);
}

#[test]
fn enrichment_event_kind_promoted_and_refused_non_terminal() {
    assert!(!LifecycleEventKind::Promoted.is_terminal());
    assert!(!LifecycleEventKind::Refused.is_terminal());
}

#[test]
fn enrichment_event_kind_terminal_count() {
    let terminal_count = LifecycleEventKind::ALL
        .iter()
        .filter(|k| k.is_terminal())
        .count();
    assert_eq!(
        terminal_count, 3,
        "Revoked, Superseded, Expired are terminal"
    );
}

#[test]
fn enrichment_event_kind_display_serde_consistency() {
    for k in LifecycleEventKind::ALL {
        let display = k.to_string();
        let json = serde_json::to_string(k).unwrap();
        // serde uses snake_case rename, display matches
        assert_eq!(json, format!("\"{display}\""));
    }
}

// ---------------------------------------------------------------------------
// RefusalReason display content
// ---------------------------------------------------------------------------

#[test]
fn enrichment_refusal_reason_display_contains_relevant_info() {
    let r1 = RefusalReason::InsufficientStrength {
        actual: LawStrength::Heuristic,
        minimum: LawStrength::Conditional,
    };
    assert!(r1.to_string().contains("strength"));

    let r2 = RefusalReason::InsufficientConfidence {
        actual_millionths: 500_000,
        minimum_millionths: 800_000,
    };
    let r2_str = r2.to_string();
    assert!(r2_str.contains("500000"));
    assert!(r2_str.contains("800000"));

    let r3 = RefusalReason::PreviouslyRevoked {
        law_id: "law-abc".to_string(),
    };
    assert!(r3.to_string().contains("law-abc"));

    let r4 = RefusalReason::DuplicateLaw {
        existing_law_id: "law-dup".to_string(),
    };
    assert!(r4.to_string().contains("law-dup"));
}

// ---------------------------------------------------------------------------
// LifecycleError display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_error_display_all_distinct() {
    let errors = [
        LifecycleError::LawNotFound {
            law_id: "x".to_string(),
        },
        LifecycleError::AlreadyPromoted {
            law_id: "y".to_string(),
        },
        LifecycleError::AlreadyRevoked {
            law_id: "z".to_string(),
        },
        LifecycleError::InvalidConfig {
            detail: "bad".to_string(),
        },
        LifecycleError::PromotionError {
            detail: "err".to_string(),
        },
    ];
    let displays: BTreeSet<_> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}

#[test]
fn enrichment_lifecycle_error_serde_roundtrip_all_variants() {
    let errors = vec![
        LifecycleError::LawNotFound {
            law_id: "law-1".to_string(),
        },
        LifecycleError::AlreadyPromoted {
            law_id: "law-2".to_string(),
        },
        LifecycleError::AlreadyRevoked {
            law_id: "law-3".to_string(),
        },
        LifecycleError::InvalidConfig {
            detail: "detail".to_string(),
        },
        LifecycleError::PromotionError {
            detail: "detail".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: LifecycleError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ---------------------------------------------------------------------------
// LifecycleConfig defaults
// ---------------------------------------------------------------------------

#[test]
fn enrichment_config_defaults_match_expected() {
    let config = LifecycleConfig::default();
    assert_eq!(config.min_auto_strength, LawStrength::Conditional);
    assert_eq!(config.min_auto_confidence_millionths, 800_000);
    assert_eq!(config.expiration_window_epochs, 10);
    assert!(config.auto_route_by_kind);
    assert!(!config.allow_heuristic);
}

// ---------------------------------------------------------------------------
// Pipeline initial state
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pipeline_new_has_correct_schema_and_bead() {
    let p = default_pipeline();
    assert_eq!(p.schema_version, LAW_PROMOTION_LIFECYCLE_SCHEMA_VERSION);
    assert_eq!(p.bead_id, LAW_PROMOTION_LIFECYCLE_BEAD_ID);
}

#[test]
fn enrichment_pipeline_new_empty_collections() {
    let p = default_pipeline();
    assert!(p.accepted_laws.is_empty());
    assert!(p.routing_decisions.is_empty());
    assert!(p.lifecycle_events.is_empty());
    assert!(p.revoked_law_ids.is_empty());
    assert!(p.superseded_law_ids.is_empty());
    assert!(p.expired_law_ids.is_empty());
}

// ---------------------------------------------------------------------------
// Pipeline hash mutation tracking
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pipeline_hash_changes_after_promote() {
    let mut p = default_pipeline();
    let hash_before = p.pipeline_hash;
    let c = test_candidate("c1", CandidateKind::Invariant);
    let r = accepted_result("c1", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    assert_ne!(p.pipeline_hash, hash_before);
}

#[test]
fn enrichment_pipeline_hash_changes_after_revoke() {
    let mut p = default_pipeline();
    let c = test_candidate("c1", CandidateKind::Invariant);
    let r = accepted_result("c1", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    let hash_after_promote = p.pipeline_hash;
    p.revoke_law("law-c1", "test revocation");
    assert_ne!(p.pipeline_hash, hash_after_promote);
}

#[test]
fn enrichment_pipeline_hash_changes_after_supersede() {
    let mut p = default_pipeline();
    let c = test_candidate("c1", CandidateKind::Invariant);
    let r = accepted_result("c1", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    let hash_after_promote = p.pipeline_hash;
    p.supersede_law("law-c1", "law-c2", "stronger law");
    assert_ne!(p.pipeline_hash, hash_after_promote);
}

// ---------------------------------------------------------------------------
// Promotion event structure
// ---------------------------------------------------------------------------

#[test]
fn enrichment_promote_invariant_event_has_four_targets() {
    let mut p = default_pipeline();
    let c = test_candidate("inv1", CandidateKind::Invariant);
    let r = accepted_result("inv1", CandidateKind::Invariant);
    let event = p.promote_law(&c, &r);
    assert_eq!(event.kind, LifecycleEventKind::Promoted);
    assert_eq!(event.affected_targets.len(), 4);
    assert!(event.refusal_reason.is_none());
    assert!(event.superseding_law_id.is_none());
}

#[test]
fn enrichment_promote_side_condition_routes_to_two_targets() {
    let mut p = default_pipeline();
    let c = test_candidate("sc1", CandidateKind::SideCondition);
    let r = accepted_result("sc1", CandidateKind::SideCondition);
    let event = p.promote_law(&c, &r);
    assert_eq!(event.kind, LifecycleEventKind::Promoted);
    assert_eq!(event.affected_targets.len(), 2);
    let targets: BTreeSet<_> = event.affected_targets.iter().collect();
    assert!(targets.contains(&PromotionTarget::RewritePack));
    assert!(targets.contains(&PromotionTarget::SupportAtlas));
}

#[test]
fn enrichment_promote_normal_form_routes_to_two_targets() {
    let mut p = default_pipeline();
    let c = test_candidate("nf1", CandidateKind::NormalForm);
    let r = accepted_result("nf1", CandidateKind::NormalForm);
    let event = p.promote_law(&c, &r);
    assert_eq!(event.kind, LifecycleEventKind::Promoted);
    assert_eq!(event.affected_targets.len(), 2);
    let targets: BTreeSet<_> = event.affected_targets.iter().collect();
    assert!(targets.contains(&PromotionTarget::SynthesisLane));
    assert!(targets.contains(&PromotionTarget::FrontierLedger));
}

// ---------------------------------------------------------------------------
// Refusal paths
// ---------------------------------------------------------------------------

#[test]
fn enrichment_refuse_rejected_candidate_has_reason() {
    let mut p = default_pipeline();
    let c = test_candidate("rej1", CandidateKind::Invariant);
    let r = make_result(
        "rej1",
        CandidateKind::Invariant,
        ProofVerdict::Refuted,
        200_000,
        false,
    );
    let event = p.promote_law(&c, &r);
    assert_eq!(event.kind, LifecycleEventKind::Refused);
    assert!(event.refusal_reason.is_some());
    assert!(event.affected_targets.is_empty());
}

#[test]
fn enrichment_refuse_heuristic_when_not_allowed() {
    let mut p = default_pipeline();
    // Inconclusive with low confidence → Heuristic strength
    let c = test_candidate("h1", CandidateKind::Invariant);
    let r = make_result(
        "h1",
        CandidateKind::Invariant,
        ProofVerdict::Inconclusive,
        500_000,
        true,
    );
    let event = p.promote_law(&c, &r);
    assert_eq!(event.kind, LifecycleEventKind::Refused);
    match event.refusal_reason.as_ref().unwrap() {
        RefusalReason::InsufficientStrength { actual, .. } => {
            assert_eq!(*actual, LawStrength::Heuristic);
        }
        other => panic!("expected InsufficientStrength, got {other:?}"),
    }
}

#[test]
fn enrichment_allow_heuristic_config_permits_promotion() {
    let config = LifecycleConfig {
        allow_heuristic: true,
        min_auto_strength: LawStrength::Heuristic,
        ..Default::default()
    };
    let mut p = LifecyclePipeline::new(config, epoch(10));
    let c = test_candidate("h2", CandidateKind::Invariant);
    let r = make_result(
        "h2",
        CandidateKind::Invariant,
        ProofVerdict::Inconclusive,
        500_000,
        true,
    );
    let event = p.promote_law(&c, &r);
    assert_eq!(event.kind, LifecycleEventKind::Promoted);
}

#[test]
fn enrichment_refuse_duplicate_candidate() {
    let mut p = default_pipeline();
    let c = test_candidate("dup1", CandidateKind::Invariant);
    let r = accepted_result("dup1", CandidateKind::Invariant);
    let first = p.promote_law(&c, &r);
    assert_eq!(first.kind, LifecycleEventKind::Promoted);
    let second = p.promote_law(&c, &r);
    assert_eq!(second.kind, LifecycleEventKind::Refused);
    assert!(matches!(
        second.refusal_reason,
        Some(RefusalReason::DuplicateLaw { .. })
    ));
}

#[test]
fn enrichment_refuse_previously_revoked() {
    let mut p = default_pipeline();
    let c = test_candidate("rev1", CandidateKind::Invariant);
    let r = accepted_result("rev1", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    p.revoke_law("law-rev1", "regression");
    // Try to re-promote the same candidate
    let c2 = test_candidate("rev1", CandidateKind::Invariant);
    let r2 = accepted_result("rev1", CandidateKind::Invariant);
    let event = p.promote_law(&c2, &r2);
    assert_eq!(event.kind, LifecycleEventKind::Refused);
    // Should be either DuplicateLaw or PreviouslyRevoked
    assert!(event.refusal_reason.is_some());
}

// ---------------------------------------------------------------------------
// Revocation and supersession
// ---------------------------------------------------------------------------

#[test]
fn enrichment_revoke_removes_from_active_ids() {
    let mut p = default_pipeline();
    let c = test_candidate("a1", CandidateKind::Invariant);
    let r = accepted_result("a1", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    assert!(p.active_law_ids().contains(&"law-a1"));
    p.revoke_law("law-a1", "test");
    assert!(!p.active_law_ids().contains(&"law-a1"));
}

#[test]
fn enrichment_supersede_removes_from_active_ids() {
    let mut p = default_pipeline();
    let c = test_candidate("s1", CandidateKind::Invariant);
    let r = accepted_result("s1", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    assert!(p.active_law_ids().contains(&"law-s1"));
    p.supersede_law("law-s1", "law-s2", "stronger");
    assert!(!p.active_law_ids().contains(&"law-s1"));
}

#[test]
fn enrichment_supersede_event_has_superseding_id() {
    let mut p = default_pipeline();
    let c = test_candidate("s2", CandidateKind::Invariant);
    let r = accepted_result("s2", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    let event = p.supersede_law("law-s2", "law-new", "better").unwrap();
    assert_eq!(event.kind, LifecycleEventKind::Superseded);
    assert_eq!(event.superseding_law_id.as_deref(), Some("law-new"));
}

#[test]
fn enrichment_revoke_nonexistent_returns_none() {
    let mut p = default_pipeline();
    assert!(p.revoke_law("no-such-law", "reason").is_none());
}

#[test]
fn enrichment_supersede_nonexistent_returns_none() {
    let mut p = default_pipeline();
    assert!(p.supersede_law("no-such-law", "new", "reason").is_none());
}

// ---------------------------------------------------------------------------
// Expiration
// ---------------------------------------------------------------------------

#[test]
fn enrichment_expire_after_window() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(1));
    let c = test_candidate("e1", CandidateKind::Invariant);
    let r = accepted_result("e1", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    // Window is 10 epochs, promote at epoch 1, expire at epoch 12
    let events = p.expire_stale_laws(epoch(12));
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, LifecycleEventKind::Expired);
    assert_eq!(events[0].law_id, "law-e1");
}

#[test]
fn enrichment_no_expire_within_window() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(1));
    let c = test_candidate("e2", CandidateKind::Invariant);
    let r = accepted_result("e2", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    let events = p.expire_stale_laws(epoch(10));
    assert!(events.is_empty());
}

#[test]
fn enrichment_no_expire_already_revoked() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(1));
    let c = test_candidate("e3", CandidateKind::Invariant);
    let r = accepted_result("e3", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    p.revoke_law("law-e3", "test");
    let events = p.expire_stale_laws(epoch(100));
    assert!(events.is_empty());
}

#[test]
fn enrichment_no_expire_already_superseded() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(1));
    let c = test_candidate("e4", CandidateKind::Invariant);
    let r = accepted_result("e4", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    p.supersede_law("law-e4", "law-e5", "better");
    let events = p.expire_stale_laws(epoch(100));
    assert!(events.is_empty());
}

// ---------------------------------------------------------------------------
// Events and routing queries
// ---------------------------------------------------------------------------

#[test]
fn enrichment_events_for_tracks_full_lifecycle() {
    let mut p = default_pipeline();
    let c = test_candidate("lc1", CandidateKind::Invariant);
    let r = accepted_result("lc1", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    p.revoke_law("law-lc1", "regression");
    let events = p.events_for("law-lc1");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].kind, LifecycleEventKind::Promoted);
    assert_eq!(events[1].kind, LifecycleEventKind::Revoked);
}

#[test]
fn enrichment_routing_for_returns_correct_decision() {
    let mut p = default_pipeline();
    let c = test_candidate("rt1", CandidateKind::SideCondition);
    let r = accepted_result("rt1", CandidateKind::SideCondition);
    p.promote_law(&c, &r);
    let routing = p.routing_for("law-rt1").unwrap();
    assert_eq!(routing.candidate_kind, CandidateKind::SideCondition);
    assert_eq!(routing.selected_targets.len(), 2);
}

#[test]
fn enrichment_routing_for_unknown_returns_none() {
    let p = default_pipeline();
    assert!(p.routing_for("unknown").is_none());
}

// ---------------------------------------------------------------------------
// Auto-route disabled sends to all targets
// ---------------------------------------------------------------------------

#[test]
fn enrichment_auto_route_disabled_sends_to_all() {
    let config = LifecycleConfig {
        auto_route_by_kind: false,
        ..Default::default()
    };
    let mut p = LifecyclePipeline::new(config, epoch(10));
    let c = test_candidate("ar1", CandidateKind::SideCondition);
    let r = accepted_result("ar1", CandidateKind::SideCondition);
    let event = p.promote_law(&c, &r);
    assert_eq!(event.kind, LifecycleEventKind::Promoted);
    // With auto_route_by_kind=false, SideCondition still gets all 4 targets
    assert_eq!(event.affected_targets.len(), 4);
}

// ---------------------------------------------------------------------------
// Summary report
// ---------------------------------------------------------------------------

#[test]
fn enrichment_summary_empty_pipeline() {
    let p = default_pipeline();
    let s = p.summary_report();
    assert_eq!(s.total_accepted, 0);
    assert_eq!(s.promoted_count, 0);
    assert_eq!(s.refused_count, 0);
    assert_eq!(s.revoked_count, 0);
    assert_eq!(s.superseded_count, 0);
    assert_eq!(s.expired_count, 0);
    assert_eq!(s.total_receipts, 0);
    assert_eq!(s.mean_priority_millionths, 0);
}

#[test]
fn enrichment_summary_after_mixed_operations() {
    let mut p = default_pipeline();
    // Promote 2 invariants (4 targets each = 8 receipts)
    let c1 = test_candidate("m1", CandidateKind::Invariant);
    let r1 = accepted_result("m1", CandidateKind::Invariant);
    p.promote_law(&c1, &r1);

    let c2 = test_candidate("m2", CandidateKind::SideCondition);
    let r2 = accepted_result("m2", CandidateKind::SideCondition);
    p.promote_law(&c2, &r2);

    // Refuse one
    let c3 = test_candidate("m3", CandidateKind::Invariant);
    let r3 = make_result(
        "m3",
        CandidateKind::Invariant,
        ProofVerdict::Refuted,
        100_000,
        false,
    );
    p.promote_law(&c3, &r3);

    // Revoke one
    p.revoke_law("law-m1", "regression");

    let s = p.summary_report();
    assert_eq!(s.total_accepted, 2);
    assert_eq!(s.promoted_count, 2);
    assert_eq!(s.refused_count, 1);
    assert_eq!(s.revoked_count, 1);
    assert_eq!(s.total_receipts, 6); // 4 + 2
}

#[test]
fn enrichment_summary_serde_roundtrip() {
    let mut p = default_pipeline();
    let c = test_candidate("sr1", CandidateKind::Invariant);
    let r = accepted_result("sr1", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    let s = p.summary_report();
    let json = serde_json::to_string(&s).unwrap();
    let back: LifecycleSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn enrichment_summary_target_breakdown_covers_all_targets() {
    let p = default_pipeline();
    let s = p.summary_report();
    assert_eq!(s.receipts_by_target.len(), PromotionTarget::ALL.len());
    let target_set: BTreeSet<_> = s.receipts_by_target.iter().map(|b| b.target).collect();
    let expected: BTreeSet<_> = PromotionTarget::ALL.iter().copied().collect();
    assert_eq!(target_set, expected);
}

// ---------------------------------------------------------------------------
// Display formats
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_event_display_contains_law_id() {
    let mut p = default_pipeline();
    let c = test_candidate("d1", CandidateKind::Invariant);
    let r = accepted_result("d1", CandidateKind::Invariant);
    let event = p.promote_law(&c, &r);
    let display = event.to_string();
    assert!(display.contains("law-d1"));
    assert!(display.contains("promoted"));
}

#[test]
fn enrichment_routing_decision_display_contains_kind() {
    let mut p = default_pipeline();
    let c = test_candidate("rd1", CandidateKind::NormalForm);
    let r = accepted_result("rd1", CandidateKind::NormalForm);
    p.promote_law(&c, &r);
    let routing = p.routing_for("law-rd1").unwrap();
    let display = routing.to_string();
    assert!(display.contains("law-rd1"));
    assert!(display.contains("NormalForm"));
}

// ---------------------------------------------------------------------------
// Pipeline serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pipeline_full_serde_roundtrip() {
    let mut p = default_pipeline();
    let c1 = test_candidate("p1", CandidateKind::Invariant);
    let r1 = accepted_result("p1", CandidateKind::Invariant);
    p.promote_law(&c1, &r1);
    let c2 = test_candidate("p2", CandidateKind::SideCondition);
    let r2 = accepted_result("p2", CandidateKind::SideCondition);
    p.promote_law(&c2, &r2);
    p.revoke_law("law-p1", "test");
    let json = serde_json::to_string(&p).unwrap();
    let back: LifecyclePipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// Pipeline determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pipeline_deterministic_same_operations() {
    let make = || {
        let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(10));
        let c = test_candidate("det1", CandidateKind::Invariant);
        let r = accepted_result("det1", CandidateKind::Invariant);
        p.promote_law(&c, &r);
        p
    };
    let p1 = make();
    let p2 = make();
    assert_eq!(p1.pipeline_hash, p2.pipeline_hash);
}

// ---------------------------------------------------------------------------
// Lifecycle event hash uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_event_hashes_unique_across_operations() {
    let mut p = default_pipeline();
    let c1 = test_candidate("u1", CandidateKind::Invariant);
    let r1 = accepted_result("u1", CandidateKind::Invariant);
    let e1 = p.promote_law(&c1, &r1);

    let c2 = test_candidate("u2", CandidateKind::SideCondition);
    let r2 = accepted_result("u2", CandidateKind::SideCondition);
    let e2 = p.promote_law(&c2, &r2);

    let e3 = p.revoke_law("law-u1", "test").unwrap();

    let hashes: BTreeSet<_> = [e1.event_hash, e2.event_hash, e3.event_hash]
        .into_iter()
        .collect();
    assert_eq!(hashes.len(), 3, "all event hashes must be distinct");
}

// ---------------------------------------------------------------------------
// Complex lifecycle: promote → supersede → expire independent
// ---------------------------------------------------------------------------

#[test]
fn enrichment_supersede_then_expire_independent_laws() {
    let mut p = LifecyclePipeline::new(LifecycleConfig::default(), epoch(1));
    // Promote two laws
    let c1 = test_candidate("ind1", CandidateKind::Invariant);
    let r1 = accepted_result("ind1", CandidateKind::Invariant);
    p.promote_law(&c1, &r1);

    let c2 = test_candidate("ind2", CandidateKind::Invariant);
    let r2 = accepted_result("ind2", CandidateKind::Invariant);
    p.promote_law(&c2, &r2);

    // Supersede ind1
    p.supersede_law("law-ind1", "law-ind3", "stronger");

    // Expire at epoch 100 — only ind2 should expire (ind1 is superseded)
    let expired = p.expire_stale_laws(epoch(100));
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].law_id, "law-ind2");

    // Active should be empty now
    assert!(p.active_law_ids().is_empty());
}

// ---------------------------------------------------------------------------
// Revoke idempotent
// ---------------------------------------------------------------------------

#[test]
fn enrichment_revoke_same_law_twice_returns_none_second_time() {
    let mut p = default_pipeline();
    let c = test_candidate("ri1", CandidateKind::Invariant);
    let r = accepted_result("ri1", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    let first = p.revoke_law("law-ri1", "first");
    assert!(first.is_some());
    let second = p.revoke_law("law-ri1", "second");
    assert!(second.is_none());
}

// ---------------------------------------------------------------------------
// Supersede idempotent
// ---------------------------------------------------------------------------

#[test]
fn enrichment_supersede_same_law_twice_returns_none_second_time() {
    let mut p = default_pipeline();
    let c = test_candidate("si1", CandidateKind::Invariant);
    let r = accepted_result("si1", CandidateKind::Invariant);
    p.promote_law(&c, &r);
    let first = p.supersede_law("law-si1", "law-new1", "first");
    assert!(first.is_some());
    let second = p.supersede_law("law-si1", "law-new2", "second");
    assert!(second.is_none());
}
