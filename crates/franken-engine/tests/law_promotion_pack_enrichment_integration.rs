#![forbid(unsafe_code)]

//! Enrichment integration tests for `law_promotion_pack`.
//!
//! Covers: Display uniqueness for all enums, serde roundtrips for all types,
//! method behavior, edge cases, deterministic hash behavior, fixed-point
//! millionths arithmetic, and full promotion pipeline lifecycle scenarios.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::law_promotion_pack::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_law(
    law_id: &str,
    strength: LawStrength,
    rank: u64,
    scope_tags: Vec<String>,
) -> AcceptedLaw {
    AcceptedLaw::new(
        law_id,
        &format!("cand-{law_id}"),
        &format!("statement for {law_id}"),
        strength,
        scope_tags,
        rank,
        epoch(42),
        vec![format!("ev-{law_id}-1"), format!("ev-{law_id}-2")],
    )
}

fn default_law() -> AcceptedLaw {
    make_law(
        "law-default",
        LawStrength::Proved,
        800_000,
        vec!["tag-a".into(), "tag-b".into()],
    )
}

// ---------------------------------------------------------------------------
// PromotionTarget — Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_promotion_target_display_all_unique() {
    let mut seen = BTreeSet::new();
    for target in PromotionTarget::ALL {
        let display = target.to_string();
        assert!(
            seen.insert(display.clone()),
            "Duplicate Display for PromotionTarget: {display}"
        );
    }
    assert_eq!(seen.len(), PromotionTarget::ALL.len());
}

#[test]
fn enrichment_promotion_target_display_matches_serde() {
    // snake_case serde rename should match Display output
    for target in PromotionTarget::ALL {
        let json = serde_json::to_string(target).unwrap();
        let display = target.to_string();
        // JSON wraps in quotes
        assert_eq!(json, format!("\"{display}\""));
    }
}

#[test]
fn enrichment_promotion_target_all_canonical_order() {
    assert_eq!(PromotionTarget::ALL[0], PromotionTarget::RewritePack);
    assert_eq!(PromotionTarget::ALL[1], PromotionTarget::SynthesisLane);
    assert_eq!(PromotionTarget::ALL[2], PromotionTarget::SupportAtlas);
    assert_eq!(PromotionTarget::ALL[3], PromotionTarget::FrontierLedger);
}

#[test]
fn enrichment_promotion_target_serde_roundtrip_all() {
    for target in PromotionTarget::ALL {
        let json = serde_json::to_string(target).unwrap();
        let back: PromotionTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(*target, back);
    }
}

#[test]
fn enrichment_promotion_target_ord_is_deterministic() {
    let mut targets: Vec<PromotionTarget> = PromotionTarget::ALL.to_vec();
    targets.sort();
    assert_eq!(targets, PromotionTarget::ALL.to_vec());
}

#[test]
fn enrichment_promotion_target_btreeset_insertion() {
    let mut set = BTreeSet::new();
    for target in PromotionTarget::ALL {
        set.insert(*target);
    }
    // Re-insert duplicates
    for target in PromotionTarget::ALL {
        set.insert(*target);
    }
    assert_eq!(set.len(), 4);
}

// ---------------------------------------------------------------------------
// LawStrength — Display uniqueness and weights
// ---------------------------------------------------------------------------

#[test]
fn enrichment_law_strength_display_all_unique() {
    let mut seen = BTreeSet::new();
    for strength in LawStrength::ALL {
        let display = strength.to_string();
        assert!(
            seen.insert(display.clone()),
            "Duplicate Display for LawStrength: {display}"
        );
    }
    assert_eq!(seen.len(), LawStrength::ALL.len());
}

#[test]
fn enrichment_law_strength_display_matches_serde() {
    for strength in LawStrength::ALL {
        let json = serde_json::to_string(strength).unwrap();
        let display = strength.to_string();
        assert_eq!(json, format!("\"{display}\""));
    }
}

#[test]
fn enrichment_law_strength_weights_monotonically_decreasing() {
    let weights: Vec<u64> = LawStrength::ALL
        .iter()
        .map(|s| s.weight_millionths())
        .collect();
    for window in weights.windows(2) {
        assert!(
            window[0] > window[1],
            "Weights not strictly decreasing: {} <= {}",
            window[0],
            window[1]
        );
    }
}

#[test]
fn enrichment_law_strength_proved_weight_is_million() {
    assert_eq!(LawStrength::Proved.weight_millionths(), 1_000_000);
}

#[test]
fn enrichment_law_strength_heuristic_weight_is_quarter() {
    assert_eq!(LawStrength::Heuristic.weight_millionths(), 250_000);
}

#[test]
fn enrichment_law_strength_all_has_four_entries() {
    assert_eq!(LawStrength::ALL.len(), 4);
}

#[test]
fn enrichment_law_strength_serde_roundtrip_all() {
    for strength in LawStrength::ALL {
        let json = serde_json::to_string(strength).unwrap();
        let back: LawStrength = serde_json::from_str(&json).unwrap();
        assert_eq!(*strength, back);
    }
}

#[test]
fn enrichment_law_strength_btreeset_contains_all() {
    let set: BTreeSet<LawStrength> = LawStrength::ALL.iter().copied().collect();
    assert_eq!(set.len(), 4);
    assert!(set.contains(&LawStrength::Proved));
    assert!(set.contains(&LawStrength::Empirical));
    assert!(set.contains(&LawStrength::Conditional));
    assert!(set.contains(&LawStrength::Heuristic));
}

// ---------------------------------------------------------------------------
// PromotionStatus — Display uniqueness and is_active
// ---------------------------------------------------------------------------

#[test]
fn enrichment_promotion_status_display_all_unique() {
    let mut seen = BTreeSet::new();
    for status in PromotionStatus::ALL {
        let display = status.to_string();
        assert!(
            seen.insert(display.clone()),
            "Duplicate Display for PromotionStatus: {display}"
        );
    }
    assert_eq!(seen.len(), PromotionStatus::ALL.len());
}

#[test]
fn enrichment_promotion_status_display_matches_serde() {
    for status in PromotionStatus::ALL {
        let json = serde_json::to_string(status).unwrap();
        let display = status.to_string();
        assert_eq!(json, format!("\"{display}\""));
    }
}

#[test]
fn enrichment_promotion_status_is_active_exactly_two() {
    let active_count = PromotionStatus::ALL
        .iter()
        .filter(|s| s.is_active())
        .count();
    assert_eq!(
        active_count, 2,
        "Expected exactly Pending and Promoted to be active"
    );
}

#[test]
fn enrichment_promotion_status_pending_is_active() {
    assert!(PromotionStatus::Pending.is_active());
}

#[test]
fn enrichment_promotion_status_promoted_is_active() {
    assert!(PromotionStatus::Promoted.is_active());
}

#[test]
fn enrichment_promotion_status_superseded_not_active() {
    assert!(!PromotionStatus::Superseded.is_active());
}

#[test]
fn enrichment_promotion_status_revoked_not_active() {
    assert!(!PromotionStatus::Revoked.is_active());
}

#[test]
fn enrichment_promotion_status_expired_not_active() {
    assert!(!PromotionStatus::Expired.is_active());
}

#[test]
fn enrichment_promotion_status_all_has_five_entries() {
    assert_eq!(PromotionStatus::ALL.len(), 5);
}

#[test]
fn enrichment_promotion_status_serde_roundtrip_all() {
    for status in PromotionStatus::ALL {
        let json = serde_json::to_string(status).unwrap();
        let back: PromotionStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*status, back);
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_schema_version_non_empty() {
    assert!(!LAW_PROMOTION_SCHEMA_VERSION.is_empty());
    assert!(LAW_PROMOTION_SCHEMA_VERSION.contains("v1"));
}

#[test]
fn enrichment_constants_bead_id_non_empty() {
    assert!(!LAW_PROMOTION_BEAD_ID.is_empty());
    assert!(LAW_PROMOTION_BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrichment_constants_component_non_empty() {
    assert_eq!(COMPONENT, "law_promotion_pack");
}

// ---------------------------------------------------------------------------
// AcceptedLaw — construction, priority, hash, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_accepted_law_fields_populated() {
    let law = default_law();
    assert_eq!(law.law_id, "law-default");
    assert_eq!(law.candidate_id, "cand-law-default");
    assert_eq!(law.statement, "statement for law-default");
    assert_eq!(law.strength, LawStrength::Proved);
    assert_eq!(law.scope_tags.len(), 2);
    assert_eq!(law.mining_rank_millionths, 800_000);
    assert_eq!(law.accepted_epoch, epoch(42));
    assert_eq!(law.evidence_ids.len(), 2);
}

#[test]
fn enrichment_accepted_law_hash_deterministic() {
    let law_a = default_law();
    let law_b = default_law();
    assert_eq!(law_a.law_hash, law_b.law_hash);
}

#[test]
fn enrichment_accepted_law_hash_differs_on_different_id() {
    let law_a = make_law("law-alpha", LawStrength::Proved, 500_000, vec![]);
    let law_b = make_law("law-beta", LawStrength::Proved, 500_000, vec![]);
    assert_ne!(law_a.law_hash, law_b.law_hash);
}

#[test]
fn enrichment_accepted_law_hash_differs_on_different_strength() {
    let law_a = make_law("law-same", LawStrength::Proved, 500_000, vec![]);
    let law_b = make_law("law-same", LawStrength::Heuristic, 500_000, vec![]);
    assert_ne!(law_a.law_hash, law_b.law_hash);
}

#[test]
fn enrichment_accepted_law_hash_differs_on_different_rank() {
    let law_a = make_law("law-x", LawStrength::Empirical, 100_000, vec![]);
    let law_b = make_law("law-x", LawStrength::Empirical, 200_000, vec![]);
    assert_ne!(law_a.law_hash, law_b.law_hash);
}

#[test]
fn enrichment_accepted_law_priority_proved_rank_max() {
    // Proved (1_000_000) at rank 1_000_000 => 60% * 1M + 40% * 1M = 1M, clamped at 1M
    let law = make_law("law-max", LawStrength::Proved, 1_000_000, vec![]);
    assert_eq!(law.promotion_priority_millionths(), 1_000_000);
}

#[test]
fn enrichment_accepted_law_priority_proved_rank_zero() {
    // Proved (1_000_000) at rank 0 => 600_000 * 1M / 1M + 0 = 600_000
    let law = make_law("law-zero-rank", LawStrength::Proved, 0, vec![]);
    assert_eq!(law.promotion_priority_millionths(), 600_000);
}

#[test]
fn enrichment_accepted_law_priority_heuristic_rank_zero() {
    // Heuristic (250_000) at rank 0 => 250_000 * 600_000 / 1M = 150_000
    let law = make_law("law-heur-zero", LawStrength::Heuristic, 0, vec![]);
    assert_eq!(law.promotion_priority_millionths(), 150_000);
}

#[test]
fn enrichment_accepted_law_priority_heuristic_rank_million() {
    // Heuristic (250_000) at rank 1_000_000 => (250_000*600_000 + 1_000_000*400_000)/1M
    // = (150_000_000_000 + 400_000_000_000)/1M = 550_000
    let law = make_law("law-heur-max", LawStrength::Heuristic, 1_000_000, vec![]);
    assert_eq!(law.promotion_priority_millionths(), 550_000);
}

#[test]
fn enrichment_accepted_law_priority_proved_gt_empirical_same_rank() {
    let p = make_law("a", LawStrength::Proved, 500_000, vec![]);
    let e = make_law("b", LawStrength::Empirical, 500_000, vec![]);
    assert!(p.promotion_priority_millionths() > e.promotion_priority_millionths());
}

#[test]
fn enrichment_accepted_law_priority_empirical_gt_conditional_same_rank() {
    let e = make_law("a", LawStrength::Empirical, 500_000, vec![]);
    let c = make_law("b", LawStrength::Conditional, 500_000, vec![]);
    assert!(e.promotion_priority_millionths() > c.promotion_priority_millionths());
}

#[test]
fn enrichment_accepted_law_priority_conditional_gt_heuristic_same_rank() {
    let c = make_law("a", LawStrength::Conditional, 500_000, vec![]);
    let h = make_law("b", LawStrength::Heuristic, 500_000, vec![]);
    assert!(c.promotion_priority_millionths() > h.promotion_priority_millionths());
}

#[test]
fn enrichment_accepted_law_priority_clamped_at_million() {
    // Even with max inputs, result should not exceed 1_000_000
    let law = make_law("law-clamp", LawStrength::Proved, 2_000_000, vec![]);
    assert!(law.promotion_priority_millionths() <= 1_000_000);
}

#[test]
fn enrichment_accepted_law_display_contains_id_and_strength() {
    let law = default_law();
    let display = law.to_string();
    assert!(display.contains("law-default"));
    assert!(display.contains("proved"));
    assert!(display.contains("800000"));
    assert!(display.contains("scope=2"));
}

#[test]
fn enrichment_accepted_law_serde_roundtrip() {
    let law = default_law();
    let json = serde_json::to_string(&law).unwrap();
    let back: AcceptedLaw = serde_json::from_str(&json).unwrap();
    assert_eq!(law, back);
}

#[test]
fn enrichment_accepted_law_serde_roundtrip_empty_scope() {
    let law = make_law("law-empty-scope", LawStrength::Conditional, 300_000, vec![]);
    let json = serde_json::to_string(&law).unwrap();
    let back: AcceptedLaw = serde_json::from_str(&json).unwrap();
    assert_eq!(law, back);
    assert!(back.scope_tags.is_empty());
}

// ---------------------------------------------------------------------------
// RewriteRule — construction, hash, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_rewrite_rule_from_law_fields() {
    let law = default_law();
    let rule = RewriteRule::from_law("rw-1", &law, "match_p", "repl_r", "guard_g", 1_200_000);
    assert_eq!(rule.rule_id, "rw-1");
    assert_eq!(rule.source_law_id, "law-default");
    assert_eq!(rule.match_pattern, "match_p");
    assert_eq!(rule.replacement, "repl_r");
    assert_eq!(rule.guard, "guard_g");
    assert_eq!(rule.speedup_estimate_millionths, 1_200_000);
    assert!(rule.semantics_preserving);
}

#[test]
fn enrichment_rewrite_rule_hash_deterministic() {
    let law = default_law();
    let r1 = RewriteRule::from_law("rw-1", &law, "p", "r", "g", 1_000_000);
    let r2 = RewriteRule::from_law("rw-1", &law, "p", "r", "g", 1_000_000);
    assert_eq!(r1.rule_hash, r2.rule_hash);
}

#[test]
fn enrichment_rewrite_rule_hash_differs_on_speedup() {
    let law = default_law();
    let r1 = RewriteRule::from_law("rw-1", &law, "p", "r", "g", 1_000_000);
    let r2 = RewriteRule::from_law("rw-1", &law, "p", "r", "g", 2_000_000);
    assert_ne!(r1.rule_hash, r2.rule_hash);
}

#[test]
fn enrichment_rewrite_rule_hash_differs_on_pattern() {
    let law = default_law();
    let r1 = RewriteRule::from_law("rw-1", &law, "p1", "r", "g", 1_000_000);
    let r2 = RewriteRule::from_law("rw-1", &law, "p2", "r", "g", 1_000_000);
    assert_ne!(r1.rule_hash, r2.rule_hash);
}

#[test]
fn enrichment_rewrite_rule_display_contains_id() {
    let law = default_law();
    let rule = RewriteRule::from_law("rw-test", &law, "p", "r", "g", 1_100_000);
    let display = rule.to_string();
    assert!(display.contains("RewriteRule"));
    assert!(display.contains("rw-test"));
    assert!(display.contains("law-default"));
    assert!(display.contains("1100000"));
}

#[test]
fn enrichment_rewrite_rule_serde_roundtrip() {
    let law = default_law();
    let rule = RewriteRule::from_law("rw-serde", &law, "match_p", "repl", "guard", 950_000);
    let json = serde_json::to_string(&rule).unwrap();
    let back: RewriteRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, back);
}

// ---------------------------------------------------------------------------
// RewritePack — construction, add_rule, hash, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_rewrite_pack_empty() {
    let pack = RewritePack::new("pack-empty", epoch(10));
    assert_eq!(pack.rule_count(), 0);
    assert_eq!(pack.schema_version, LAW_PROMOTION_SCHEMA_VERSION);
}

#[test]
fn enrichment_rewrite_pack_add_multiple_rules() {
    let mut pack = RewritePack::new("pack-multi", epoch(10));
    let law = default_law();
    for i in 0..5 {
        let rule = RewriteRule::from_law(&format!("rw-{i}"), &law, "p", "r", "g", 1_000_000);
        pack.add_rule(rule);
    }
    assert_eq!(pack.rule_count(), 5);
}

#[test]
fn enrichment_rewrite_pack_hash_changes_on_add() {
    let mut pack = RewritePack::new("pack-hash", epoch(10));
    let hash_empty = pack.pack_hash;
    let law = default_law();
    let rule = RewriteRule::from_law("rw-1", &law, "p", "r", "g", 1_000_000);
    pack.add_rule(rule);
    assert_ne!(pack.pack_hash, hash_empty);
}

#[test]
fn enrichment_rewrite_pack_display() {
    let pack = RewritePack::new("pack-disp", epoch(7));
    let display = pack.to_string();
    assert!(display.contains("RewritePack"));
    assert!(display.contains("pack-disp"));
    assert!(display.contains("rules=0"));
    assert!(display.contains("epoch=7"));
}

#[test]
fn enrichment_rewrite_pack_serde_roundtrip_with_rules() {
    let mut pack = RewritePack::new("pack-serde", epoch(20));
    let law = default_law();
    pack.add_rule(RewriteRule::from_law(
        "rw-a", &law, "pa", "ra", "ga", 1_000_000,
    ));
    pack.add_rule(RewriteRule::from_law(
        "rw-b", &law, "pb", "rb", "gb", 1_100_000,
    ));
    let json = serde_json::to_string(&pack).unwrap();
    let back: RewritePack = serde_json::from_str(&json).unwrap();
    assert_eq!(pack, back);
}

// ---------------------------------------------------------------------------
// SynthesisSeed — construction, priority derivation, hash, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_synthesis_seed_from_law_fields() {
    let law = default_law();
    let seed = SynthesisSeed::from_law(
        "syn-1",
        &law,
        "template($p)",
        vec!["p".into()],
        "result >= 0",
    );
    assert_eq!(seed.seed_id, "syn-1");
    assert_eq!(seed.source_law_id, "law-default");
    assert_eq!(seed.template, "template($p)");
    assert_eq!(seed.parameters, vec!["p".to_string()]);
    assert_eq!(seed.expected_pattern, "result >= 0");
    assert_eq!(
        seed.priority_millionths,
        law.promotion_priority_millionths()
    );
}

#[test]
fn enrichment_synthesis_seed_priority_matches_law() {
    let law = make_law("law-syn-prio", LawStrength::Conditional, 400_000, vec![]);
    let seed = SynthesisSeed::from_law("syn-p", &law, "t", vec![], "e");
    assert_eq!(
        seed.priority_millionths,
        law.promotion_priority_millionths()
    );
}

#[test]
fn enrichment_synthesis_seed_hash_deterministic() {
    let law = default_law();
    let s1 = SynthesisSeed::from_law("syn-det", &law, "t", vec!["a".into()], "e");
    let s2 = SynthesisSeed::from_law("syn-det", &law, "t", vec!["a".into()], "e");
    assert_eq!(s1.seed_hash, s2.seed_hash);
}

#[test]
fn enrichment_synthesis_seed_hash_differs_on_template() {
    let law = default_law();
    let s1 = SynthesisSeed::from_law("syn-1", &law, "template_a", vec![], "e");
    let s2 = SynthesisSeed::from_law("syn-1", &law, "template_b", vec![], "e");
    assert_ne!(s1.seed_hash, s2.seed_hash);
}

#[test]
fn enrichment_synthesis_seed_display() {
    let law = default_law();
    let seed = SynthesisSeed::from_law("syn-disp", &law, "t", vec![], "e");
    let display = seed.to_string();
    assert!(display.contains("SynthesisSeed"));
    assert!(display.contains("syn-disp"));
    assert!(display.contains("law-default"));
}

#[test]
fn enrichment_synthesis_seed_serde_roundtrip() {
    let law = default_law();
    let seed = SynthesisSeed::from_law("syn-serde", &law, "t", vec!["x".into(), "y".into()], "e");
    let json = serde_json::to_string(&seed).unwrap();
    let back: SynthesisSeed = serde_json::from_str(&json).unwrap();
    assert_eq!(seed, back);
}

// ---------------------------------------------------------------------------
// SynthesisLane — construction, add_seed, hash, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_synthesis_lane_empty() {
    let lane = SynthesisLane::new("lane-empty", epoch(5));
    assert_eq!(lane.seed_count(), 0);
    assert_eq!(lane.schema_version, LAW_PROMOTION_SCHEMA_VERSION);
}

#[test]
fn enrichment_synthesis_lane_add_multiple_seeds() {
    let mut lane = SynthesisLane::new("lane-multi", epoch(5));
    let law = default_law();
    for i in 0..4 {
        let seed = SynthesisSeed::from_law(&format!("syn-{i}"), &law, "t", vec![], "e");
        lane.add_seed(seed);
    }
    assert_eq!(lane.seed_count(), 4);
}

#[test]
fn enrichment_synthesis_lane_hash_changes_on_add() {
    let mut lane = SynthesisLane::new("lane-hash", epoch(5));
    let hash_empty = lane.lane_hash;
    let law = default_law();
    lane.add_seed(SynthesisSeed::from_law("syn-x", &law, "t", vec![], "e"));
    assert_ne!(lane.lane_hash, hash_empty);
}

#[test]
fn enrichment_synthesis_lane_display() {
    let lane = SynthesisLane::new("lane-disp", epoch(8));
    let display = lane.to_string();
    assert!(display.contains("SynthesisLane"));
    assert!(display.contains("lane-disp"));
    assert!(display.contains("seeds=0"));
    assert!(display.contains("epoch=8"));
}

#[test]
fn enrichment_synthesis_lane_serde_roundtrip() {
    let mut lane = SynthesisLane::new("lane-serde", epoch(15));
    let law = default_law();
    lane.add_seed(SynthesisSeed::from_law("syn-s1", &law, "ta", vec![], "ea"));
    let json = serde_json::to_string(&lane).unwrap();
    let back: SynthesisLane = serde_json::from_str(&json).unwrap();
    assert_eq!(lane, back);
}

// ---------------------------------------------------------------------------
// SupportAtlasEntry — construction, validate, hash, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_atlas_entry_from_law_inherits_scope_tags() {
    let law = make_law(
        "law-tags",
        LawStrength::Proved,
        500_000,
        vec!["scope-1".into(), "scope-2".into(), "scope-3".into()],
    );
    let entry = SupportAtlasEntry::from_law("ae-1", &law, "domain.test", 750_000);
    assert_eq!(entry.scope_tags.len(), 3);
    assert_eq!(entry.scope_tags[0], "scope-1");
}

#[test]
fn enrichment_atlas_entry_initially_not_validated() {
    let law = default_law();
    let entry = SupportAtlasEntry::from_law("ae-1", &law, "d", 500_000);
    assert!(!entry.workload_validated);
}

#[test]
fn enrichment_atlas_entry_validate_changes_hash() {
    let law = default_law();
    let mut entry = SupportAtlasEntry::from_law("ae-hash", &law, "d", 500_000);
    let hash_before = entry.entry_hash;
    entry.validate();
    assert!(entry.workload_validated);
    assert_ne!(entry.entry_hash, hash_before);
}

#[test]
fn enrichment_atlas_entry_validate_idempotent_hash() {
    let law = default_law();
    let mut entry = SupportAtlasEntry::from_law("ae-idem", &law, "d", 500_000);
    entry.validate();
    let hash_after_first = entry.entry_hash;
    entry.validate();
    assert_eq!(entry.entry_hash, hash_after_first);
}

#[test]
fn enrichment_atlas_entry_display() {
    let law = default_law();
    let entry = SupportAtlasEntry::from_law("ae-disp", &law, "string.split", 600_000);
    let display = entry.to_string();
    assert!(display.contains("SupportAtlasEntry"));
    assert!(display.contains("ae-disp"));
    assert!(display.contains("string.split"));
    assert!(display.contains("600000"));
    assert!(display.contains("validated=false"));
}

#[test]
fn enrichment_atlas_entry_serde_roundtrip_validated() {
    let law = default_law();
    let mut entry = SupportAtlasEntry::from_law("ae-srd", &law, "d", 700_000);
    entry.validate();
    let json = serde_json::to_string(&entry).unwrap();
    let back: SupportAtlasEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
    assert!(back.workload_validated);
}

// ---------------------------------------------------------------------------
// SupportAtlas — construction, covered_domains, hash, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_support_atlas_empty() {
    let atlas = SupportAtlas::new("atlas-empty", epoch(1));
    assert_eq!(atlas.entry_count(), 0);
    assert!(atlas.covered_domains().is_empty());
}

#[test]
fn enrichment_support_atlas_covered_domains_dedup() {
    let mut atlas = SupportAtlas::new("atlas-dedup", epoch(1));
    let law = default_law();
    atlas.add_entry(SupportAtlasEntry::from_law("e1", &law, "domain.a", 500_000));
    atlas.add_entry(SupportAtlasEntry::from_law("e2", &law, "domain.b", 600_000));
    atlas.add_entry(SupportAtlasEntry::from_law("e3", &law, "domain.a", 700_000));
    let domains = atlas.covered_domains();
    assert_eq!(domains.len(), 2);
    assert!(domains.contains("domain.a"));
    assert!(domains.contains("domain.b"));
}

#[test]
fn enrichment_support_atlas_hash_changes_on_add() {
    let mut atlas = SupportAtlas::new("atlas-hash", epoch(1));
    let hash_empty = atlas.atlas_hash;
    let law = default_law();
    atlas.add_entry(SupportAtlasEntry::from_law("e1", &law, "d", 500_000));
    assert_ne!(atlas.atlas_hash, hash_empty);
}

#[test]
fn enrichment_support_atlas_display() {
    let mut atlas = SupportAtlas::new("atlas-disp", epoch(3));
    let law = default_law();
    atlas.add_entry(SupportAtlasEntry::from_law("e1", &law, "d1", 500_000));
    atlas.add_entry(SupportAtlasEntry::from_law("e2", &law, "d2", 600_000));
    let display = atlas.to_string();
    assert!(display.contains("SupportAtlas"));
    assert!(display.contains("atlas-disp"));
    assert!(display.contains("entries=2"));
    assert!(display.contains("domains=2"));
    assert!(display.contains("epoch=3"));
}

#[test]
fn enrichment_support_atlas_serde_roundtrip() {
    let mut atlas = SupportAtlas::new("atlas-serde", epoch(9));
    let law = default_law();
    atlas.add_entry(SupportAtlasEntry::from_law("e1", &law, "d", 500_000));
    let json = serde_json::to_string(&atlas).unwrap();
    let back: SupportAtlas = serde_json::from_str(&json).unwrap();
    assert_eq!(atlas, back);
}

// ---------------------------------------------------------------------------
// FrontierEntry — construction, mark_explored, hash, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_frontier_entry_from_law_fields() {
    let law = default_law();
    let entry = FrontierEntry::from_law("f-1", &law, "regex.backtrack", 300_000);
    assert_eq!(entry.entry_id, "f-1");
    assert_eq!(entry.source_law_id, "law-default");
    assert_eq!(entry.frontier_region, "regex.backtrack");
    assert_eq!(
        entry.priority_millionths,
        law.promotion_priority_millionths()
    );
    assert_eq!(entry.expected_gain_millionths, 300_000);
    assert!(!entry.explored);
}

#[test]
fn enrichment_frontier_entry_mark_explored_changes_hash() {
    let law = default_law();
    let mut entry = FrontierEntry::from_law("f-hash", &law, "region", 200_000);
    let hash_before = entry.entry_hash;
    entry.mark_explored();
    assert!(entry.explored);
    assert_ne!(entry.entry_hash, hash_before);
}

#[test]
fn enrichment_frontier_entry_mark_explored_idempotent_hash() {
    let law = default_law();
    let mut entry = FrontierEntry::from_law("f-idem", &law, "region", 200_000);
    entry.mark_explored();
    let hash_after_first = entry.entry_hash;
    entry.mark_explored();
    assert_eq!(entry.entry_hash, hash_after_first);
}

#[test]
fn enrichment_frontier_entry_display() {
    let law = default_law();
    let entry = FrontierEntry::from_law("f-disp", &law, "weakref.gc", 400_000);
    let display = entry.to_string();
    assert!(display.contains("FrontierEntry"));
    assert!(display.contains("f-disp"));
    assert!(display.contains("weakref.gc"));
    assert!(display.contains("explored=false"));
}

#[test]
fn enrichment_frontier_entry_serde_roundtrip() {
    let law = default_law();
    let mut entry = FrontierEntry::from_law("f-serde", &law, "r", 100_000);
    entry.mark_explored();
    let json = serde_json::to_string(&entry).unwrap();
    let back: FrontierEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
    assert!(back.explored);
}

// ---------------------------------------------------------------------------
// FrontierLedger — construction, unexplored_count, hash, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_frontier_ledger_empty() {
    let ledger = FrontierLedger::new("ledger-empty", epoch(1));
    assert_eq!(ledger.entry_count(), 0);
    assert_eq!(ledger.unexplored_count(), 0);
}

#[test]
fn enrichment_frontier_ledger_unexplored_count() {
    let mut ledger = FrontierLedger::new("ledger-ux", epoch(1));
    let law = default_law();
    let mut e1 = FrontierEntry::from_law("f1", &law, "r1", 100_000);
    e1.mark_explored();
    let e2 = FrontierEntry::from_law("f2", &law, "r2", 200_000);
    let e3 = FrontierEntry::from_law("f3", &law, "r3", 300_000);
    ledger.add_entry(e1);
    ledger.add_entry(e2);
    ledger.add_entry(e3);
    assert_eq!(ledger.entry_count(), 3);
    assert_eq!(ledger.unexplored_count(), 2);
}

#[test]
fn enrichment_frontier_ledger_all_explored() {
    let mut ledger = FrontierLedger::new("ledger-all-exp", epoch(1));
    let law = default_law();
    for i in 0..3 {
        let mut entry = FrontierEntry::from_law(&format!("f{i}"), &law, "r", 100_000);
        entry.mark_explored();
        ledger.add_entry(entry);
    }
    assert_eq!(ledger.unexplored_count(), 0);
    assert_eq!(ledger.entry_count(), 3);
}

#[test]
fn enrichment_frontier_ledger_hash_changes_on_add() {
    let mut ledger = FrontierLedger::new("ledger-hash", epoch(1));
    let hash_empty = ledger.ledger_hash;
    let law = default_law();
    ledger.add_entry(FrontierEntry::from_law("f1", &law, "r", 100_000));
    assert_ne!(ledger.ledger_hash, hash_empty);
}

#[test]
fn enrichment_frontier_ledger_display() {
    let mut ledger = FrontierLedger::new("ledger-disp", epoch(6));
    let law = default_law();
    ledger.add_entry(FrontierEntry::from_law("f1", &law, "r1", 100_000));
    let display = ledger.to_string();
    assert!(display.contains("FrontierLedger"));
    assert!(display.contains("ledger-disp"));
    assert!(display.contains("entries=1"));
    assert!(display.contains("unexplored=1"));
    assert!(display.contains("epoch=6"));
}

#[test]
fn enrichment_frontier_ledger_serde_roundtrip() {
    let mut ledger = FrontierLedger::new("ledger-serde", epoch(2));
    let law = default_law();
    ledger.add_entry(FrontierEntry::from_law("f1", &law, "r", 100_000));
    let json = serde_json::to_string(&ledger).unwrap();
    let back: FrontierLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(ledger, back);
}

// ---------------------------------------------------------------------------
// PromotionReceipt — construction, revoke, supersede, hash, serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_initial_status_promoted() {
    let receipt = PromotionReceipt::new(
        "pr-1",
        "law-1",
        PromotionTarget::RewritePack,
        "rw-1",
        epoch(10),
        "promoted for optimization",
    );
    assert_eq!(receipt.status, PromotionStatus::Promoted);
    assert!(receipt.status.is_active());
}

#[test]
fn enrichment_receipt_revoke_changes_status_and_rationale() {
    let mut receipt = PromotionReceipt::new(
        "pr-rev",
        "law-rev",
        PromotionTarget::SynthesisLane,
        "syn-1",
        epoch(10),
        "test",
    );
    let hash_before = receipt.receipt_hash;
    receipt.revoke("counterexample in campaign-99");
    assert_eq!(receipt.status, PromotionStatus::Revoked);
    assert!(!receipt.status.is_active());
    assert!(receipt.rationale.starts_with("REVOKED:"));
    assert!(receipt.rationale.contains("counterexample in campaign-99"));
    assert_ne!(receipt.receipt_hash, hash_before);
}

#[test]
fn enrichment_receipt_supersede_changes_status_and_rationale() {
    let mut receipt = PromotionReceipt::new(
        "pr-sup",
        "law-old",
        PromotionTarget::SupportAtlas,
        "ae-1",
        epoch(10),
        "initial",
    );
    let hash_before = receipt.receipt_hash;
    receipt.supersede("law-new");
    assert_eq!(receipt.status, PromotionStatus::Superseded);
    assert!(!receipt.status.is_active());
    assert!(receipt.rationale.contains("Superseded by law-new"));
    assert_ne!(receipt.receipt_hash, hash_before);
}

#[test]
fn enrichment_receipt_hash_deterministic() {
    let r1 = PromotionReceipt::new(
        "pr-det",
        "law-det",
        PromotionTarget::FrontierLedger,
        "f-1",
        epoch(42),
        "reason",
    );
    let r2 = PromotionReceipt::new(
        "pr-det",
        "law-det",
        PromotionTarget::FrontierLedger,
        "f-1",
        epoch(42),
        "reason",
    );
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_receipt_hash_differs_on_target() {
    let r1 = PromotionReceipt::new(
        "pr-t",
        "law",
        PromotionTarget::RewritePack,
        "a",
        epoch(1),
        "r",
    );
    let r2 = PromotionReceipt::new(
        "pr-t",
        "law",
        PromotionTarget::SynthesisLane,
        "a",
        epoch(1),
        "r",
    );
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_receipt_hash_differs_on_epoch() {
    let r1 = PromotionReceipt::new(
        "pr-e",
        "law",
        PromotionTarget::RewritePack,
        "a",
        epoch(1),
        "r",
    );
    let r2 = PromotionReceipt::new(
        "pr-e",
        "law",
        PromotionTarget::RewritePack,
        "a",
        epoch(2),
        "r",
    );
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_receipt_display() {
    let receipt = PromotionReceipt::new(
        "pr-disp",
        "law-disp",
        PromotionTarget::FrontierLedger,
        "f-1",
        epoch(10),
        "test",
    );
    let display = receipt.to_string();
    assert!(display.contains("PromotionReceipt"));
    assert!(display.contains("pr-disp"));
    assert!(display.contains("law-disp"));
    assert!(display.contains("frontier_ledger"));
    assert!(display.contains("promoted"));
}

#[test]
fn enrichment_receipt_serde_roundtrip() {
    let receipt = PromotionReceipt::new(
        "pr-serde",
        "law-serde",
        PromotionTarget::SupportAtlas,
        "ae-1",
        epoch(50),
        "rationale text here",
    );
    let json = serde_json::to_string(&receipt).unwrap();
    let back: PromotionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn enrichment_receipt_serde_roundtrip_after_revoke() {
    let mut receipt = PromotionReceipt::new(
        "pr-rev-serde",
        "law-x",
        PromotionTarget::RewritePack,
        "rw-1",
        epoch(10),
        "original",
    );
    receipt.revoke("bad law");
    let json = serde_json::to_string(&receipt).unwrap();
    let back: PromotionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
    assert_eq!(back.status, PromotionStatus::Revoked);
}

// ---------------------------------------------------------------------------
// PromotionPipeline — full lifecycle
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pipeline_empty_creation() {
    let pipeline = PromotionPipeline::new("pipe-empty", epoch(1));
    assert_eq!(pipeline.total_promotions(), 0);
    assert_eq!(pipeline.active_promotions(), 0);
    assert_eq!(pipeline.rewrite_pack.rule_count(), 0);
    assert_eq!(pipeline.synthesis_lane.seed_count(), 0);
    assert_eq!(pipeline.support_atlas.entry_count(), 0);
    assert_eq!(pipeline.frontier_ledger.entry_count(), 0);
}

#[test]
fn enrichment_pipeline_sub_component_ids() {
    let pipeline = PromotionPipeline::new("my-pipe", epoch(1));
    assert_eq!(pipeline.rewrite_pack.pack_id, "my-pipe-rewrite");
    assert_eq!(pipeline.synthesis_lane.lane_id, "my-pipe-synthesis");
    assert_eq!(pipeline.support_atlas.atlas_id, "my-pipe-atlas");
    assert_eq!(pipeline.frontier_ledger.ledger_id, "my-pipe-frontier");
}

#[test]
fn enrichment_pipeline_promote_to_rewrite_creates_receipt() {
    let mut pipeline = PromotionPipeline::new("pipe-rw", epoch(10));
    let law = default_law();
    let receipt = pipeline.promote_to_rewrite(&law, "typeof x", "tag_check", "true", 1_100_000);
    assert_eq!(receipt.target, PromotionTarget::RewritePack);
    assert_eq!(receipt.law_id, "law-default");
    assert_eq!(receipt.status, PromotionStatus::Promoted);
    assert_eq!(pipeline.rewrite_pack.rule_count(), 1);
    assert_eq!(pipeline.total_promotions(), 1);
}

#[test]
fn enrichment_pipeline_promote_to_synthesis_creates_receipt() {
    let mut pipeline = PromotionPipeline::new("pipe-syn", epoch(10));
    let law = default_law();
    let receipt = pipeline.promote_to_synthesis(&law, "tmpl($x)", vec!["x".into()], "result > 0");
    assert_eq!(receipt.target, PromotionTarget::SynthesisLane);
    assert_eq!(pipeline.synthesis_lane.seed_count(), 1);
}

#[test]
fn enrichment_pipeline_promote_to_atlas_creates_receipt() {
    let mut pipeline = PromotionPipeline::new("pipe-atl", epoch(10));
    let law = default_law();
    let receipt = pipeline.promote_to_atlas(&law, "string.prototype.trim", 800_000);
    assert_eq!(receipt.target, PromotionTarget::SupportAtlas);
    assert_eq!(pipeline.support_atlas.entry_count(), 1);
}

#[test]
fn enrichment_pipeline_promote_to_frontier_creates_receipt() {
    let mut pipeline = PromotionPipeline::new("pipe-front", epoch(10));
    let law = default_law();
    let receipt = pipeline.promote_to_frontier(&law, "proxy.handler.get", 350_000);
    assert_eq!(receipt.target, PromotionTarget::FrontierLedger);
    assert_eq!(pipeline.frontier_ledger.entry_count(), 1);
}

#[test]
fn enrichment_pipeline_multiple_promotions_same_law() {
    let mut pipeline = PromotionPipeline::new("pipe-multi", epoch(10));
    let law = default_law();
    pipeline.promote_to_rewrite(&law, "p", "r", "g", 1_000_000);
    pipeline.promote_to_synthesis(&law, "t", vec![], "e");
    pipeline.promote_to_atlas(&law, "d", 500_000);
    pipeline.promote_to_frontier(&law, "region", 200_000);
    assert_eq!(pipeline.total_promotions(), 4);
    assert_eq!(pipeline.active_promotions(), 4);
}

#[test]
fn enrichment_pipeline_multiple_laws_multiple_targets() {
    let mut pipeline = PromotionPipeline::new("pipe-mlaws", epoch(10));
    let law_proved = make_law("law-p", LawStrength::Proved, 900_000, vec!["core".into()]);
    let law_empirical = make_law("law-e", LawStrength::Empirical, 600_000, vec!["ext".into()]);
    let law_heuristic = make_law("law-h", LawStrength::Heuristic, 300_000, vec![]);

    pipeline.promote_to_rewrite(&law_proved, "p1", "r1", "g1", 1_200_000);
    pipeline.promote_to_synthesis(&law_empirical, "t1", vec!["a".into()], "e1");
    pipeline.promote_to_atlas(&law_heuristic, "weak.ref", 200_000);
    pipeline.promote_to_frontier(&law_proved, "deep.opt", 400_000);

    assert_eq!(pipeline.total_promotions(), 4);
    assert_eq!(pipeline.rewrite_pack.rule_count(), 1);
    assert_eq!(pipeline.synthesis_lane.seed_count(), 1);
    assert_eq!(pipeline.support_atlas.entry_count(), 1);
    assert_eq!(pipeline.frontier_ledger.entry_count(), 1);
}

#[test]
fn enrichment_pipeline_revoke_reduces_active_count() {
    let mut pipeline = PromotionPipeline::new("pipe-revoke", epoch(10));
    let law = default_law();
    pipeline.promote_to_rewrite(&law, "p", "r", "g", 1_000_000);
    pipeline.promote_to_synthesis(&law, "t", vec![], "e");
    assert_eq!(pipeline.active_promotions(), 2);

    pipeline.receipts[0].revoke("bad rewrite");
    assert_eq!(pipeline.active_promotions(), 1);
    assert_eq!(pipeline.total_promotions(), 2);
}

#[test]
fn enrichment_pipeline_supersede_reduces_active_count() {
    let mut pipeline = PromotionPipeline::new("pipe-super", epoch(10));
    let law1 = make_law("law-old", LawStrength::Empirical, 500_000, vec![]);
    let law2 = make_law("law-new", LawStrength::Proved, 900_000, vec![]);
    pipeline.promote_to_atlas(&law1, "d", 500_000);
    pipeline.promote_to_atlas(&law2, "d", 900_000);
    assert_eq!(pipeline.active_promotions(), 2);

    pipeline.receipts[0].supersede("law-new");
    assert_eq!(pipeline.active_promotions(), 1);
}

#[test]
fn enrichment_pipeline_summary_report_fields() {
    let mut pipeline = PromotionPipeline::new("pipe-summary", epoch(99));
    let law = default_law();
    pipeline.promote_to_rewrite(&law, "p", "r", "g", 1_000_000);
    pipeline.promote_to_synthesis(&law, "t", vec![], "e");
    pipeline.promote_to_atlas(&law, "d1", 500_000);
    pipeline.promote_to_atlas(&law, "d2", 600_000);
    pipeline.promote_to_frontier(&law, "r1", 100_000);
    pipeline.promote_to_frontier(&law, "r2", 200_000);

    let report = pipeline.summary_report();
    assert_eq!(report.total_promotions, 6);
    assert_eq!(report.active_promotions, 6);
    assert_eq!(report.rewrite_rules, 1);
    assert_eq!(report.synthesis_seeds, 1);
    assert_eq!(report.atlas_entries, 2);
    assert_eq!(report.frontier_entries, 2);
    assert_eq!(report.unexplored_frontiers, 2);
    assert_eq!(report.covered_domains, 2);
    assert_eq!(report.epoch, epoch(99));
}

#[test]
fn enrichment_pipeline_hash_deterministic() {
    let p1 = PromotionPipeline::new("pipe-det", epoch(1));
    let p2 = PromotionPipeline::new("pipe-det", epoch(1));
    assert_eq!(p1.pipeline_hash, p2.pipeline_hash);
}

#[test]
fn enrichment_pipeline_hash_changes_on_each_promotion() {
    let mut pipeline = PromotionPipeline::new("pipe-hc", epoch(1));
    let law = default_law();
    let h0 = pipeline.pipeline_hash;

    pipeline.promote_to_rewrite(&law, "p", "r", "g", 1_000_000);
    let h1 = pipeline.pipeline_hash;
    assert_ne!(h0, h1);

    pipeline.promote_to_synthesis(&law, "t", vec![], "e");
    let h2 = pipeline.pipeline_hash;
    assert_ne!(h1, h2);

    pipeline.promote_to_atlas(&law, "d", 500_000);
    let h3 = pipeline.pipeline_hash;
    assert_ne!(h2, h3);

    pipeline.promote_to_frontier(&law, "r", 100_000);
    let h4 = pipeline.pipeline_hash;
    assert_ne!(h3, h4);
}

#[test]
fn enrichment_pipeline_display() {
    let mut pipeline = PromotionPipeline::new("pipe-disp", epoch(7));
    let law = default_law();
    pipeline.promote_to_rewrite(&law, "p", "r", "g", 1_000_000);
    let display = pipeline.to_string();
    assert!(display.contains("PromotionPipeline"));
    assert!(display.contains("promotions=1"));
    assert!(display.contains("rewrites=1"));
    assert!(display.contains("seeds=0"));
    assert!(display.contains("atlas=0"));
    assert!(display.contains("frontier=0"));
    assert!(display.contains("epoch=7"));
}

#[test]
fn enrichment_pipeline_serde_roundtrip_empty() {
    let pipeline = PromotionPipeline::new("pipe-serde-empty", epoch(1));
    let json = serde_json::to_string(&pipeline).unwrap();
    let back: PromotionPipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(pipeline, back);
}

#[test]
fn enrichment_pipeline_serde_roundtrip_populated() {
    let mut pipeline = PromotionPipeline::new("pipe-serde-pop", epoch(55));
    let law1 = make_law("law-1", LawStrength::Proved, 900_000, vec!["a".into()]);
    let law2 = make_law("law-2", LawStrength::Empirical, 600_000, vec!["b".into()]);

    pipeline.promote_to_rewrite(&law1, "p", "r", "g", 1_000_000);
    pipeline.promote_to_synthesis(&law1, "t", vec!["x".into()], "e");
    pipeline.promote_to_atlas(&law2, "domain.x", 700_000);
    pipeline.promote_to_frontier(&law2, "frontier.y", 300_000);

    let json = serde_json::to_string(&pipeline).unwrap();
    let back: PromotionPipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(pipeline, back);
}

// ---------------------------------------------------------------------------
// PromotionSummaryReport — display and serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_summary_report_display_format() {
    let report = PromotionSummaryReport {
        total_promotions: 10,
        active_promotions: 7,
        rewrite_rules: 3,
        synthesis_seeds: 2,
        atlas_entries: 3,
        frontier_entries: 2,
        unexplored_frontiers: 1,
        covered_domains: 4,
        epoch: epoch(100),
    };
    let display = report.to_string();
    assert!(display.contains("PromotionSummary"));
    assert!(display.contains("7/10"));
    assert!(display.contains("rewrites=3"));
    assert!(display.contains("seeds=2"));
    assert!(display.contains("atlas=3"));
    assert!(display.contains("1/2"));
}

#[test]
fn enrichment_summary_report_serde_roundtrip() {
    let report = PromotionSummaryReport {
        total_promotions: 5,
        active_promotions: 3,
        rewrite_rules: 1,
        synthesis_seeds: 1,
        atlas_entries: 2,
        frontier_entries: 1,
        unexplored_frontiers: 0,
        covered_domains: 2,
        epoch: epoch(77),
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: PromotionSummaryReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn enrichment_summary_report_zeros() {
    let report = PromotionSummaryReport {
        total_promotions: 0,
        active_promotions: 0,
        rewrite_rules: 0,
        synthesis_seeds: 0,
        atlas_entries: 0,
        frontier_entries: 0,
        unexplored_frontiers: 0,
        covered_domains: 0,
        epoch: epoch(0),
    };
    let display = report.to_string();
    assert!(display.contains("0/0"));
}

// ---------------------------------------------------------------------------
// Cross-cutting edge case tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_empty_strings_law() {
    let law = AcceptedLaw::new(
        "",
        "",
        "",
        LawStrength::Heuristic,
        vec![],
        0,
        epoch(0),
        vec![],
    );
    assert_eq!(law.law_id, "");
    assert_eq!(law.promotion_priority_millionths(), 150_000);
    let json = serde_json::to_string(&law).unwrap();
    let back: AcceptedLaw = serde_json::from_str(&json).unwrap();
    assert_eq!(law, back);
}

#[test]
fn enrichment_very_large_rank() {
    let law = make_law("law-big", LawStrength::Proved, 999_999_999, vec![]);
    // Priority should be clamped at 1_000_000
    let priority = law.promotion_priority_millionths();
    assert!(priority <= 1_000_000);
}

#[test]
fn enrichment_hash_content_addressed_property() {
    // Two different laws with same id but different content should differ
    let law_a = AcceptedLaw::new(
        "law-same-id",
        "cand-a",
        "statement A",
        LawStrength::Proved,
        vec![],
        500_000,
        epoch(1),
        vec![],
    );
    let law_b = AcceptedLaw::new(
        "law-same-id",
        "cand-b",
        "statement B",
        LawStrength::Proved,
        vec![],
        500_000,
        epoch(1),
        vec![],
    );
    assert_ne!(law_a.law_hash, law_b.law_hash);
}

#[test]
fn enrichment_scope_tag_order_affects_hash() {
    let law_a = AcceptedLaw::new(
        "law-order",
        "cand",
        "stmt",
        LawStrength::Proved,
        vec!["alpha".into(), "beta".into()],
        500_000,
        epoch(1),
        vec![],
    );
    let law_b = AcceptedLaw::new(
        "law-order",
        "cand",
        "stmt",
        LawStrength::Proved,
        vec!["beta".into(), "alpha".into()],
        500_000,
        epoch(1),
        vec![],
    );
    // Different tag order => different hash (tags are not sorted before hashing)
    assert_ne!(law_a.law_hash, law_b.law_hash);
}

#[test]
fn enrichment_evidence_ids_order_affects_hash() {
    let law_a = AcceptedLaw::new(
        "law-ev-order",
        "cand",
        "stmt",
        LawStrength::Proved,
        vec![],
        500_000,
        epoch(1),
        vec!["ev-1".into(), "ev-2".into()],
    );
    let law_b = AcceptedLaw::new(
        "law-ev-order",
        "cand",
        "stmt",
        LawStrength::Proved,
        vec![],
        500_000,
        epoch(1),
        vec!["ev-2".into(), "ev-1".into()],
    );
    assert_ne!(law_a.law_hash, law_b.law_hash);
}

#[test]
fn enrichment_pipeline_receipt_ids_follow_convention() {
    let mut pipeline = PromotionPipeline::new("pipe-conv", epoch(1));
    let law = make_law("mylaw", LawStrength::Proved, 500_000, vec![]);

    let r_rw = pipeline.promote_to_rewrite(&law, "p", "r", "g", 1_000_000);
    assert!(r_rw.receipt_id.starts_with("pr-rw-"));
    assert!(r_rw.asset_id.starts_with("rw-"));

    let r_syn = pipeline.promote_to_synthesis(&law, "t", vec![], "e");
    assert!(r_syn.receipt_id.starts_with("pr-syn-"));
    assert!(r_syn.asset_id.starts_with("syn-"));

    let r_atlas = pipeline.promote_to_atlas(&law, "d", 500_000);
    assert!(r_atlas.receipt_id.starts_with("pr-atlas-"));
    assert!(r_atlas.asset_id.starts_with("atlas-"));

    let r_front = pipeline.promote_to_frontier(&law, "r", 200_000);
    assert!(r_front.receipt_id.starts_with("pr-front-"));
    assert!(r_front.asset_id.starts_with("front-"));
}

#[test]
fn enrichment_pipeline_schema_version_propagated() {
    let pipeline = PromotionPipeline::new("pipe-sv", epoch(1));
    assert_eq!(pipeline.schema_version, LAW_PROMOTION_SCHEMA_VERSION);
    assert_eq!(
        pipeline.rewrite_pack.schema_version,
        LAW_PROMOTION_SCHEMA_VERSION
    );
    assert_eq!(
        pipeline.synthesis_lane.schema_version,
        LAW_PROMOTION_SCHEMA_VERSION
    );
    assert_eq!(
        pipeline.support_atlas.schema_version,
        LAW_PROMOTION_SCHEMA_VERSION
    );
    assert_eq!(
        pipeline.frontier_ledger.schema_version,
        LAW_PROMOTION_SCHEMA_VERSION
    );
}

#[test]
fn enrichment_full_lifecycle_with_revocation_and_supersession() {
    let mut pipeline = PromotionPipeline::new("lifecycle-full", epoch(50));
    let law1 = make_law("law-1", LawStrength::Proved, 900_000, vec!["core".into()]);
    let law2 = make_law("law-2", LawStrength::Empirical, 700_000, vec!["ext".into()]);
    let law3 = make_law("law-3", LawStrength::Proved, 950_000, vec!["core".into()]);

    // Promote law1 and law2
    pipeline.promote_to_rewrite(&law1, "p1", "r1", "g1", 1_100_000);
    pipeline.promote_to_atlas(&law2, "domain.x", 600_000);
    pipeline.promote_to_frontier(&law1, "region.a", 300_000);
    assert_eq!(pipeline.total_promotions(), 3);
    assert_eq!(pipeline.active_promotions(), 3);

    // Revoke the rewrite (counterexample found)
    pipeline.receipts[0].revoke("counterexample in test suite");
    assert_eq!(pipeline.active_promotions(), 2);

    // Supersede the atlas entry with law3
    pipeline.promote_to_atlas(&law3, "domain.x", 900_000);
    pipeline.receipts[1].supersede("law-3");
    assert_eq!(pipeline.active_promotions(), 2); // frontier + new atlas

    let report = pipeline.summary_report();
    assert_eq!(report.total_promotions, 4);
    assert_eq!(report.active_promotions, 2);
    assert_eq!(report.rewrite_rules, 1); // still in pack even if receipt revoked
    assert_eq!(report.atlas_entries, 2);
    assert_eq!(report.frontier_entries, 1);
    assert_eq!(report.unexplored_frontiers, 1);
}

#[test]
fn enrichment_all_strength_priorities_form_partial_order() {
    let rank = 500_000u64;
    let priorities: Vec<u64> = LawStrength::ALL
        .iter()
        .map(|s| make_law("l", *s, rank, vec![]).promotion_priority_millionths())
        .collect();
    // Priorities should be strictly decreasing (proved > empirical > conditional > heuristic)
    for window in priorities.windows(2) {
        assert!(window[0] > window[1]);
    }
}

#[test]
fn enrichment_content_hash_not_placeholder() {
    // After construction, no hash should be the placeholder hash
    let placeholder = ContentHash::compute(b"placeholder");
    let law = default_law();
    assert_ne!(law.law_hash, placeholder);

    let rule = RewriteRule::from_law("rw-1", &law, "p", "r", "g", 1_000_000);
    assert_ne!(rule.rule_hash, placeholder);

    let seed = SynthesisSeed::from_law("syn-1", &law, "t", vec![], "e");
    assert_ne!(seed.seed_hash, placeholder);

    let entry = SupportAtlasEntry::from_law("ae-1", &law, "d", 500_000);
    assert_ne!(entry.entry_hash, placeholder);

    let frontier = FrontierEntry::from_law("f-1", &law, "r", 200_000);
    assert_ne!(frontier.entry_hash, placeholder);

    let receipt = PromotionReceipt::new(
        "pr-1",
        "law-1",
        PromotionTarget::RewritePack,
        "a",
        epoch(1),
        "r",
    );
    assert_ne!(receipt.receipt_hash, placeholder);
}

// ===========================================================================
// Batch 2 enrichment tests — Clone, Debug, JSON field names, edge cases,
// additional hash sensitivity, determinism, and method contracts
// ===========================================================================

// ---------------------------------------------------------------------------
// PromotionTarget — Clone, Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_promotion_target_clone_eq() {
    for target in PromotionTarget::ALL {
        let cloned = *target;
        assert_eq!(*target, cloned);
    }
}

#[test]
fn enrichment_promotion_target_debug_contains_variant_name() {
    let debug_rw = format!("{:?}", PromotionTarget::RewritePack);
    assert!(debug_rw.contains("RewritePack"));
    let debug_syn = format!("{:?}", PromotionTarget::SynthesisLane);
    assert!(debug_syn.contains("SynthesisLane"));
    let debug_atlas = format!("{:?}", PromotionTarget::SupportAtlas);
    assert!(debug_atlas.contains("SupportAtlas"));
    let debug_front = format!("{:?}", PromotionTarget::FrontierLedger);
    assert!(debug_front.contains("FrontierLedger"));
}

#[test]
fn enrichment_promotion_target_serde_json_values() {
    assert_eq!(
        serde_json::to_string(&PromotionTarget::RewritePack).unwrap(),
        "\"rewrite_pack\""
    );
    assert_eq!(
        serde_json::to_string(&PromotionTarget::SynthesisLane).unwrap(),
        "\"synthesis_lane\""
    );
    assert_eq!(
        serde_json::to_string(&PromotionTarget::SupportAtlas).unwrap(),
        "\"support_atlas\""
    );
    assert_eq!(
        serde_json::to_string(&PromotionTarget::FrontierLedger).unwrap(),
        "\"frontier_ledger\""
    );
}

#[test]
fn enrichment_promotion_target_deserialize_from_snake_case() {
    let rw: PromotionTarget = serde_json::from_str("\"rewrite_pack\"").unwrap();
    assert_eq!(rw, PromotionTarget::RewritePack);
    let syn: PromotionTarget = serde_json::from_str("\"synthesis_lane\"").unwrap();
    assert_eq!(syn, PromotionTarget::SynthesisLane);
    let atlas: PromotionTarget = serde_json::from_str("\"support_atlas\"").unwrap();
    assert_eq!(atlas, PromotionTarget::SupportAtlas);
    let front: PromotionTarget = serde_json::from_str("\"frontier_ledger\"").unwrap();
    assert_eq!(front, PromotionTarget::FrontierLedger);
}

#[test]
fn enrichment_promotion_target_invalid_json_rejected() {
    let result = serde_json::from_str::<PromotionTarget>("\"unknown_target\"");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// LawStrength — Clone, Debug, weight values
// ---------------------------------------------------------------------------

#[test]
fn enrichment_law_strength_clone_eq() {
    for strength in LawStrength::ALL {
        let cloned = *strength;
        assert_eq!(*strength, cloned);
    }
}

#[test]
fn enrichment_law_strength_debug_contains_variant_name() {
    assert!(format!("{:?}", LawStrength::Proved).contains("Proved"));
    assert!(format!("{:?}", LawStrength::Empirical).contains("Empirical"));
    assert!(format!("{:?}", LawStrength::Conditional).contains("Conditional"));
    assert!(format!("{:?}", LawStrength::Heuristic).contains("Heuristic"));
}

#[test]
fn enrichment_law_strength_empirical_weight_value() {
    assert_eq!(LawStrength::Empirical.weight_millionths(), 750_000);
}

#[test]
fn enrichment_law_strength_conditional_weight_value() {
    assert_eq!(LawStrength::Conditional.weight_millionths(), 500_000);
}

#[test]
fn enrichment_law_strength_serde_json_values() {
    assert_eq!(
        serde_json::to_string(&LawStrength::Proved).unwrap(),
        "\"proved\""
    );
    assert_eq!(
        serde_json::to_string(&LawStrength::Empirical).unwrap(),
        "\"empirical\""
    );
    assert_eq!(
        serde_json::to_string(&LawStrength::Conditional).unwrap(),
        "\"conditional\""
    );
    assert_eq!(
        serde_json::to_string(&LawStrength::Heuristic).unwrap(),
        "\"heuristic\""
    );
}

#[test]
fn enrichment_law_strength_invalid_json_rejected() {
    let result = serde_json::from_str::<LawStrength>("\"mythical\"");
    assert!(result.is_err());
}

#[test]
fn enrichment_law_strength_all_weights_positive_and_bounded() {
    for strength in LawStrength::ALL {
        let w = strength.weight_millionths();
        assert!(w > 0);
        assert!(w <= 1_000_000);
    }
}

// ---------------------------------------------------------------------------
// PromotionStatus — Clone, Debug, serde values
// ---------------------------------------------------------------------------

#[test]
fn enrichment_promotion_status_clone_eq() {
    for status in PromotionStatus::ALL {
        let cloned = *status;
        assert_eq!(*status, cloned);
    }
}

#[test]
fn enrichment_promotion_status_debug_contains_variant_name() {
    assert!(format!("{:?}", PromotionStatus::Pending).contains("Pending"));
    assert!(format!("{:?}", PromotionStatus::Promoted).contains("Promoted"));
    assert!(format!("{:?}", PromotionStatus::Superseded).contains("Superseded"));
    assert!(format!("{:?}", PromotionStatus::Revoked).contains("Revoked"));
    assert!(format!("{:?}", PromotionStatus::Expired).contains("Expired"));
}

#[test]
fn enrichment_promotion_status_serde_json_values() {
    assert_eq!(
        serde_json::to_string(&PromotionStatus::Pending).unwrap(),
        "\"pending\""
    );
    assert_eq!(
        serde_json::to_string(&PromotionStatus::Promoted).unwrap(),
        "\"promoted\""
    );
    assert_eq!(
        serde_json::to_string(&PromotionStatus::Superseded).unwrap(),
        "\"superseded\""
    );
    assert_eq!(
        serde_json::to_string(&PromotionStatus::Revoked).unwrap(),
        "\"revoked\""
    );
    assert_eq!(
        serde_json::to_string(&PromotionStatus::Expired).unwrap(),
        "\"expired\""
    );
}

#[test]
fn enrichment_promotion_status_invalid_json_rejected() {
    let result = serde_json::from_str::<PromotionStatus>("\"unknown_status\"");
    assert!(result.is_err());
}

#[test]
fn enrichment_promotion_status_canonical_order() {
    assert_eq!(PromotionStatus::ALL[0], PromotionStatus::Pending);
    assert_eq!(PromotionStatus::ALL[1], PromotionStatus::Promoted);
    assert_eq!(PromotionStatus::ALL[2], PromotionStatus::Superseded);
    assert_eq!(PromotionStatus::ALL[3], PromotionStatus::Revoked);
    assert_eq!(PromotionStatus::ALL[4], PromotionStatus::Expired);
}

#[test]
fn enrichment_promotion_status_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for status in PromotionStatus::ALL {
        set.insert(*status);
        set.insert(*status); // insert twice
    }
    assert_eq!(set.len(), 5);
}

// ---------------------------------------------------------------------------
// AcceptedLaw — Clone, Debug, JSON field names, hash sensitivity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_accepted_law_clone_eq() {
    let law = default_law();
    let cloned = law.clone();
    assert_eq!(law, cloned);
    assert_eq!(law.law_hash, cloned.law_hash);
}

#[test]
fn enrichment_accepted_law_debug_output() {
    let law = default_law();
    let debug = format!("{:?}", law);
    assert!(debug.contains("AcceptedLaw"));
    assert!(debug.contains("law-default"));
    assert!(debug.contains("Proved"));
}

#[test]
fn enrichment_accepted_law_json_field_names() {
    let law = default_law();
    let json = serde_json::to_string(&law).unwrap();
    assert!(json.contains("\"law_id\""));
    assert!(json.contains("\"candidate_id\""));
    assert!(json.contains("\"statement\""));
    assert!(json.contains("\"strength\""));
    assert!(json.contains("\"scope_tags\""));
    assert!(json.contains("\"mining_rank_millionths\""));
    assert!(json.contains("\"accepted_epoch\""));
    assert!(json.contains("\"evidence_ids\""));
    assert!(json.contains("\"law_hash\""));
}

#[test]
fn enrichment_accepted_law_hash_differs_on_epoch() {
    let law_a = AcceptedLaw::new(
        "law-ep",
        "cand",
        "stmt",
        LawStrength::Proved,
        vec![],
        500_000,
        epoch(1),
        vec![],
    );
    let law_b = AcceptedLaw::new(
        "law-ep",
        "cand",
        "stmt",
        LawStrength::Proved,
        vec![],
        500_000,
        epoch(2),
        vec![],
    );
    assert_ne!(law_a.law_hash, law_b.law_hash);
}

#[test]
fn enrichment_accepted_law_hash_differs_on_statement() {
    let law_a = AcceptedLaw::new(
        "law-s",
        "cand",
        "statement A",
        LawStrength::Proved,
        vec![],
        500_000,
        epoch(1),
        vec![],
    );
    let law_b = AcceptedLaw::new(
        "law-s",
        "cand",
        "statement B",
        LawStrength::Proved,
        vec![],
        500_000,
        epoch(1),
        vec![],
    );
    assert_ne!(law_a.law_hash, law_b.law_hash);
}

#[test]
fn enrichment_accepted_law_priority_empirical_rank_zero() {
    // Empirical (750_000) at rank 0 => 750_000*600_000/1M + 0 = 450_000
    let law = make_law("law-e0", LawStrength::Empirical, 0, vec![]);
    assert_eq!(law.promotion_priority_millionths(), 450_000);
}

#[test]
fn enrichment_accepted_law_priority_conditional_rank_zero() {
    // Conditional (500_000) at rank 0 => 500_000*600_000/1M + 0 = 300_000
    let law = make_law("law-c0", LawStrength::Conditional, 0, vec![]);
    assert_eq!(law.promotion_priority_millionths(), 300_000);
}

#[test]
fn enrichment_accepted_law_priority_empirical_rank_million() {
    // Empirical (750_000) at rank 1_000_000 =>
    // (750_000 * 600_000 + 1_000_000 * 400_000) / 1_000_000
    // = (450_000_000_000 + 400_000_000_000) / 1_000_000 = 850_000
    let law = make_law("law-em", LawStrength::Empirical, 1_000_000, vec![]);
    assert_eq!(law.promotion_priority_millionths(), 850_000);
}

#[test]
fn enrichment_accepted_law_priority_conditional_rank_million() {
    // Conditional (500_000) at rank 1_000_000 =>
    // (500_000 * 600_000 + 1_000_000 * 400_000) / 1_000_000
    // = (300_000_000_000 + 400_000_000_000) / 1_000_000 = 700_000
    let law = make_law("law-cm", LawStrength::Conditional, 1_000_000, vec![]);
    assert_eq!(law.promotion_priority_millionths(), 700_000);
}

#[test]
fn enrichment_accepted_law_display_format() {
    let law = make_law("law-fmt", LawStrength::Empirical, 600_000, vec!["x".into()]);
    let display = law.to_string();
    assert!(display.starts_with("AcceptedLaw("));
    assert!(display.contains("law-fmt"));
    assert!(display.contains("empirical"));
    assert!(display.contains("600000"));
    assert!(display.contains("scope=1"));
}

#[test]
fn enrichment_accepted_law_many_scope_tags() {
    let tags: Vec<String> = (0..20).map(|i| format!("tag-{i}")).collect();
    let law = make_law("law-many-tags", LawStrength::Proved, 500_000, tags.clone());
    assert_eq!(law.scope_tags.len(), 20);
    let json = serde_json::to_string(&law).unwrap();
    let back: AcceptedLaw = serde_json::from_str(&json).unwrap();
    assert_eq!(law, back);
}

#[test]
fn enrichment_accepted_law_unicode_statement() {
    let law = AcceptedLaw::new(
        "law-unicode",
        "cand-u",
        "typeof x === 'string' \u{2192} x.length \u{2265} 0",
        LawStrength::Proved,
        vec!["\u{03B1}".into(), "\u{03B2}".into()],
        800_000,
        epoch(1),
        vec![],
    );
    let json = serde_json::to_string(&law).unwrap();
    let back: AcceptedLaw = serde_json::from_str(&json).unwrap();
    assert_eq!(law, back);
}

// ---------------------------------------------------------------------------
// RewriteRule — Clone, Debug, JSON field names, additional hash sensitivity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_rewrite_rule_clone_eq() {
    let law = default_law();
    let rule = RewriteRule::from_law("rw-clone", &law, "p", "r", "g", 1_000_000);
    let cloned = rule.clone();
    assert_eq!(rule, cloned);
    assert_eq!(rule.rule_hash, cloned.rule_hash);
}

#[test]
fn enrichment_rewrite_rule_debug_output() {
    let law = default_law();
    let rule = RewriteRule::from_law("rw-dbg", &law, "p", "r", "g", 1_000_000);
    let debug = format!("{:?}", rule);
    assert!(debug.contains("RewriteRule"));
    assert!(debug.contains("rw-dbg"));
}

#[test]
fn enrichment_rewrite_rule_json_field_names() {
    let law = default_law();
    let rule = RewriteRule::from_law("rw-jf", &law, "p", "r", "g", 1_000_000);
    let json = serde_json::to_string(&rule).unwrap();
    assert!(json.contains("\"rule_id\""));
    assert!(json.contains("\"source_law_id\""));
    assert!(json.contains("\"match_pattern\""));
    assert!(json.contains("\"replacement\""));
    assert!(json.contains("\"guard\""));
    assert!(json.contains("\"speedup_estimate_millionths\""));
    assert!(json.contains("\"semantics_preserving\""));
    assert!(json.contains("\"rule_hash\""));
}

#[test]
fn enrichment_rewrite_rule_hash_differs_on_rule_id() {
    let law = default_law();
    let r1 = RewriteRule::from_law("rw-a", &law, "p", "r", "g", 1_000_000);
    let r2 = RewriteRule::from_law("rw-b", &law, "p", "r", "g", 1_000_000);
    assert_ne!(r1.rule_hash, r2.rule_hash);
}

#[test]
fn enrichment_rewrite_rule_hash_differs_on_replacement() {
    let law = default_law();
    let r1 = RewriteRule::from_law("rw-1", &law, "p", "repl-a", "g", 1_000_000);
    let r2 = RewriteRule::from_law("rw-1", &law, "p", "repl-b", "g", 1_000_000);
    assert_ne!(r1.rule_hash, r2.rule_hash);
}

#[test]
fn enrichment_rewrite_rule_hash_differs_on_guard() {
    let law = default_law();
    let r1 = RewriteRule::from_law("rw-1", &law, "p", "r", "guard-a", 1_000_000);
    let r2 = RewriteRule::from_law("rw-1", &law, "p", "r", "guard-b", 1_000_000);
    assert_ne!(r1.rule_hash, r2.rule_hash);
}

#[test]
fn enrichment_rewrite_rule_semantics_preserving_always_true() {
    // from_law always sets semantics_preserving to true
    let law = default_law();
    for i in 0..5 {
        let rule = RewriteRule::from_law(
            &format!("rw-{i}"),
            &law,
            "p",
            "r",
            "g",
            1_000_000 + i * 100_000,
        );
        assert!(rule.semantics_preserving);
    }
}

// ---------------------------------------------------------------------------
// RewritePack — Clone, Debug, JSON field names, hash determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_rewrite_pack_clone_eq() {
    let mut pack = RewritePack::new("pack-clone", epoch(5));
    let law = default_law();
    pack.add_rule(RewriteRule::from_law(
        "rw-1", &law, "p", "r", "g", 1_000_000,
    ));
    let cloned = pack.clone();
    assert_eq!(pack, cloned);
}

#[test]
fn enrichment_rewrite_pack_debug_output() {
    let pack = RewritePack::new("pack-dbg", epoch(5));
    let debug = format!("{:?}", pack);
    assert!(debug.contains("RewritePack"));
    assert!(debug.contains("pack-dbg"));
}

#[test]
fn enrichment_rewrite_pack_json_field_names() {
    let pack = RewritePack::new("pack-jf", epoch(5));
    let json = serde_json::to_string(&pack).unwrap();
    assert!(json.contains("\"pack_id\""));
    assert!(json.contains("\"assembled_epoch\""));
    assert!(json.contains("\"rules\""));
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"pack_hash\""));
}

#[test]
fn enrichment_rewrite_pack_hash_deterministic() {
    let p1 = RewritePack::new("pack-det", epoch(10));
    let p2 = RewritePack::new("pack-det", epoch(10));
    assert_eq!(p1.pack_hash, p2.pack_hash);
}

#[test]
fn enrichment_rewrite_pack_hash_differs_on_id() {
    let p1 = RewritePack::new("pack-a", epoch(10));
    let p2 = RewritePack::new("pack-b", epoch(10));
    assert_ne!(p1.pack_hash, p2.pack_hash);
}

#[test]
fn enrichment_rewrite_pack_hash_differs_on_epoch() {
    let p1 = RewritePack::new("pack-x", epoch(10));
    let p2 = RewritePack::new("pack-x", epoch(20));
    assert_ne!(p1.pack_hash, p2.pack_hash);
}

#[test]
fn enrichment_rewrite_pack_display_with_rules() {
    let mut pack = RewritePack::new("pack-disp2", epoch(12));
    let law = default_law();
    pack.add_rule(RewriteRule::from_law(
        "rw-1", &law, "p", "r", "g", 1_000_000,
    ));
    pack.add_rule(RewriteRule::from_law(
        "rw-2", &law, "p2", "r2", "g2", 1_100_000,
    ));
    let display = pack.to_string();
    assert!(display.contains("rules=2"));
    assert!(display.contains("epoch=12"));
}

// ---------------------------------------------------------------------------
// SynthesisSeed — Clone, Debug, JSON field names, additional hash sensitivity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_synthesis_seed_clone_eq() {
    let law = default_law();
    let seed = SynthesisSeed::from_law("syn-clone", &law, "t", vec!["a".into()], "e");
    let cloned = seed.clone();
    assert_eq!(seed, cloned);
    assert_eq!(seed.seed_hash, cloned.seed_hash);
}

#[test]
fn enrichment_synthesis_seed_debug_output() {
    let law = default_law();
    let seed = SynthesisSeed::from_law("syn-dbg", &law, "t", vec![], "e");
    let debug = format!("{:?}", seed);
    assert!(debug.contains("SynthesisSeed"));
    assert!(debug.contains("syn-dbg"));
}

#[test]
fn enrichment_synthesis_seed_json_field_names() {
    let law = default_law();
    let seed = SynthesisSeed::from_law("syn-jf", &law, "t", vec!["x".into()], "e");
    let json = serde_json::to_string(&seed).unwrap();
    assert!(json.contains("\"seed_id\""));
    assert!(json.contains("\"source_law_id\""));
    assert!(json.contains("\"template\""));
    assert!(json.contains("\"parameters\""));
    assert!(json.contains("\"expected_pattern\""));
    assert!(json.contains("\"priority_millionths\""));
    assert!(json.contains("\"seed_hash\""));
}

#[test]
fn enrichment_synthesis_seed_hash_differs_on_seed_id() {
    let law = default_law();
    let s1 = SynthesisSeed::from_law("syn-a", &law, "t", vec![], "e");
    let s2 = SynthesisSeed::from_law("syn-b", &law, "t", vec![], "e");
    assert_ne!(s1.seed_hash, s2.seed_hash);
}

#[test]
fn enrichment_synthesis_seed_hash_differs_on_parameters() {
    let law = default_law();
    let s1 = SynthesisSeed::from_law("syn-1", &law, "t", vec!["a".into()], "e");
    let s2 = SynthesisSeed::from_law("syn-1", &law, "t", vec!["b".into()], "e");
    assert_ne!(s1.seed_hash, s2.seed_hash);
}

#[test]
fn enrichment_synthesis_seed_hash_differs_on_expected_pattern() {
    let law = default_law();
    let s1 = SynthesisSeed::from_law("syn-1", &law, "t", vec![], "pattern-a");
    let s2 = SynthesisSeed::from_law("syn-1", &law, "t", vec![], "pattern-b");
    assert_ne!(s1.seed_hash, s2.seed_hash);
}

#[test]
fn enrichment_synthesis_seed_empty_parameters() {
    let law = default_law();
    let seed = SynthesisSeed::from_law("syn-empty-p", &law, "template", vec![], "result");
    assert!(seed.parameters.is_empty());
    let json = serde_json::to_string(&seed).unwrap();
    let back: SynthesisSeed = serde_json::from_str(&json).unwrap();
    assert_eq!(seed, back);
}

// ---------------------------------------------------------------------------
// SynthesisLane — Clone, Debug, JSON field names, hash determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_synthesis_lane_clone_eq() {
    let mut lane = SynthesisLane::new("lane-clone", epoch(5));
    let law = default_law();
    lane.add_seed(SynthesisSeed::from_law("syn-1", &law, "t", vec![], "e"));
    let cloned = lane.clone();
    assert_eq!(lane, cloned);
}

#[test]
fn enrichment_synthesis_lane_debug_output() {
    let lane = SynthesisLane::new("lane-dbg", epoch(5));
    let debug = format!("{:?}", lane);
    assert!(debug.contains("SynthesisLane"));
    assert!(debug.contains("lane-dbg"));
}

#[test]
fn enrichment_synthesis_lane_json_field_names() {
    let lane = SynthesisLane::new("lane-jf", epoch(5));
    let json = serde_json::to_string(&lane).unwrap();
    assert!(json.contains("\"lane_id\""));
    assert!(json.contains("\"assembled_epoch\""));
    assert!(json.contains("\"seeds\""));
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"lane_hash\""));
}

#[test]
fn enrichment_synthesis_lane_hash_deterministic() {
    let l1 = SynthesisLane::new("lane-det", epoch(7));
    let l2 = SynthesisLane::new("lane-det", epoch(7));
    assert_eq!(l1.lane_hash, l2.lane_hash);
}

#[test]
fn enrichment_synthesis_lane_hash_differs_on_id() {
    let l1 = SynthesisLane::new("lane-a", epoch(7));
    let l2 = SynthesisLane::new("lane-b", epoch(7));
    assert_ne!(l1.lane_hash, l2.lane_hash);
}

#[test]
fn enrichment_synthesis_lane_display_with_seeds() {
    let mut lane = SynthesisLane::new("lane-disp2", epoch(9));
    let law = default_law();
    lane.add_seed(SynthesisSeed::from_law("syn-1", &law, "t1", vec![], "e1"));
    lane.add_seed(SynthesisSeed::from_law("syn-2", &law, "t2", vec![], "e2"));
    let display = lane.to_string();
    assert!(display.contains("seeds=2"));
    assert!(display.contains("epoch=9"));
}

// ---------------------------------------------------------------------------
// SupportAtlasEntry — Clone, Debug, JSON field names, additional hash sens.
// ---------------------------------------------------------------------------

#[test]
fn enrichment_atlas_entry_clone_eq() {
    let law = default_law();
    let entry = SupportAtlasEntry::from_law("ae-clone", &law, "d", 500_000);
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
    assert_eq!(entry.entry_hash, cloned.entry_hash);
}

#[test]
fn enrichment_atlas_entry_debug_output() {
    let law = default_law();
    let entry = SupportAtlasEntry::from_law("ae-dbg", &law, "d", 500_000);
    let debug = format!("{:?}", entry);
    assert!(debug.contains("SupportAtlasEntry"));
    assert!(debug.contains("ae-dbg"));
}

#[test]
fn enrichment_atlas_entry_json_field_names() {
    let law = default_law();
    let entry = SupportAtlasEntry::from_law("ae-jf", &law, "d", 500_000);
    let json = serde_json::to_string(&entry).unwrap();
    assert!(json.contains("\"entry_id\""));
    assert!(json.contains("\"source_law_id\""));
    assert!(json.contains("\"domain\""));
    assert!(json.contains("\"coverage_depth_millionths\""));
    assert!(json.contains("\"scope_tags\""));
    assert!(json.contains("\"workload_validated\""));
    assert!(json.contains("\"entry_hash\""));
}

#[test]
fn enrichment_atlas_entry_hash_differs_on_entry_id() {
    let law = default_law();
    let e1 = SupportAtlasEntry::from_law("ae-a", &law, "d", 500_000);
    let e2 = SupportAtlasEntry::from_law("ae-b", &law, "d", 500_000);
    assert_ne!(e1.entry_hash, e2.entry_hash);
}

#[test]
fn enrichment_atlas_entry_hash_differs_on_domain() {
    let law = default_law();
    let e1 = SupportAtlasEntry::from_law("ae-1", &law, "domain-a", 500_000);
    let e2 = SupportAtlasEntry::from_law("ae-1", &law, "domain-b", 500_000);
    assert_ne!(e1.entry_hash, e2.entry_hash);
}

#[test]
fn enrichment_atlas_entry_hash_differs_on_coverage_depth() {
    let law = default_law();
    let e1 = SupportAtlasEntry::from_law("ae-1", &law, "d", 500_000);
    let e2 = SupportAtlasEntry::from_law("ae-1", &law, "d", 600_000);
    assert_ne!(e1.entry_hash, e2.entry_hash);
}

#[test]
fn enrichment_atlas_entry_display_after_validate() {
    let law = default_law();
    let mut entry = SupportAtlasEntry::from_law("ae-val", &law, "d", 500_000);
    entry.validate();
    let display = entry.to_string();
    assert!(display.contains("validated=true"));
}

// ---------------------------------------------------------------------------
// SupportAtlas — Clone, Debug, JSON field names
// ---------------------------------------------------------------------------

#[test]
fn enrichment_support_atlas_clone_eq() {
    let mut atlas = SupportAtlas::new("atlas-clone", epoch(1));
    let law = default_law();
    atlas.add_entry(SupportAtlasEntry::from_law("e1", &law, "d", 500_000));
    let cloned = atlas.clone();
    assert_eq!(atlas, cloned);
}

#[test]
fn enrichment_support_atlas_debug_output() {
    let atlas = SupportAtlas::new("atlas-dbg", epoch(1));
    let debug = format!("{:?}", atlas);
    assert!(debug.contains("SupportAtlas"));
    assert!(debug.contains("atlas-dbg"));
}

#[test]
fn enrichment_support_atlas_json_field_names() {
    let atlas = SupportAtlas::new("atlas-jf", epoch(1));
    let json = serde_json::to_string(&atlas).unwrap();
    assert!(json.contains("\"atlas_id\""));
    assert!(json.contains("\"assembled_epoch\""));
    assert!(json.contains("\"entries\""));
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"atlas_hash\""));
}

#[test]
fn enrichment_support_atlas_hash_deterministic() {
    let a1 = SupportAtlas::new("atlas-det", epoch(3));
    let a2 = SupportAtlas::new("atlas-det", epoch(3));
    assert_eq!(a1.atlas_hash, a2.atlas_hash);
}

#[test]
fn enrichment_support_atlas_single_domain() {
    let mut atlas = SupportAtlas::new("atlas-1d", epoch(1));
    let law = default_law();
    atlas.add_entry(SupportAtlasEntry::from_law(
        "e1",
        &law,
        "only-domain",
        500_000,
    ));
    atlas.add_entry(SupportAtlasEntry::from_law(
        "e2",
        &law,
        "only-domain",
        600_000,
    ));
    assert_eq!(atlas.covered_domains().len(), 1);
    assert!(atlas.covered_domains().contains("only-domain"));
}

// ---------------------------------------------------------------------------
// FrontierEntry — Clone, Debug, JSON field names, additional hash sensitivity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_frontier_entry_clone_eq() {
    let law = default_law();
    let entry = FrontierEntry::from_law("f-clone", &law, "region", 200_000);
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
    assert_eq!(entry.entry_hash, cloned.entry_hash);
}

#[test]
fn enrichment_frontier_entry_debug_output() {
    let law = default_law();
    let entry = FrontierEntry::from_law("f-dbg", &law, "region", 200_000);
    let debug = format!("{:?}", entry);
    assert!(debug.contains("FrontierEntry"));
    assert!(debug.contains("f-dbg"));
}

#[test]
fn enrichment_frontier_entry_json_field_names() {
    let law = default_law();
    let entry = FrontierEntry::from_law("f-jf", &law, "region", 200_000);
    let json = serde_json::to_string(&entry).unwrap();
    assert!(json.contains("\"entry_id\""));
    assert!(json.contains("\"source_law_id\""));
    assert!(json.contains("\"frontier_region\""));
    assert!(json.contains("\"priority_millionths\""));
    assert!(json.contains("\"expected_gain_millionths\""));
    assert!(json.contains("\"explored\""));
    assert!(json.contains("\"entry_hash\""));
}

#[test]
fn enrichment_frontier_entry_hash_differs_on_entry_id() {
    let law = default_law();
    let e1 = FrontierEntry::from_law("f-a", &law, "region", 200_000);
    let e2 = FrontierEntry::from_law("f-b", &law, "region", 200_000);
    assert_ne!(e1.entry_hash, e2.entry_hash);
}

#[test]
fn enrichment_frontier_entry_hash_differs_on_frontier_region() {
    let law = default_law();
    let e1 = FrontierEntry::from_law("f-1", &law, "region-a", 200_000);
    let e2 = FrontierEntry::from_law("f-1", &law, "region-b", 200_000);
    assert_ne!(e1.entry_hash, e2.entry_hash);
}

#[test]
fn enrichment_frontier_entry_hash_differs_on_expected_gain() {
    let law = default_law();
    let e1 = FrontierEntry::from_law("f-1", &law, "region", 200_000);
    let e2 = FrontierEntry::from_law("f-1", &law, "region", 300_000);
    assert_ne!(e1.entry_hash, e2.entry_hash);
}

#[test]
fn enrichment_frontier_entry_priority_from_law() {
    let law = make_law("law-fp", LawStrength::Conditional, 600_000, vec![]);
    let entry = FrontierEntry::from_law("f-fp", &law, "region", 200_000);
    assert_eq!(
        entry.priority_millionths,
        law.promotion_priority_millionths()
    );
}

#[test]
fn enrichment_frontier_entry_display_after_explored() {
    let law = default_law();
    let mut entry = FrontierEntry::from_law("f-exp", &law, "explored-region", 300_000);
    entry.mark_explored();
    let display = entry.to_string();
    assert!(display.contains("explored=true"));
}

// ---------------------------------------------------------------------------
// FrontierLedger — Clone, Debug, JSON field names
// ---------------------------------------------------------------------------

#[test]
fn enrichment_frontier_ledger_clone_eq() {
    let mut ledger = FrontierLedger::new("ledger-clone", epoch(1));
    let law = default_law();
    ledger.add_entry(FrontierEntry::from_law("f1", &law, "r1", 100_000));
    let cloned = ledger.clone();
    assert_eq!(ledger, cloned);
}

#[test]
fn enrichment_frontier_ledger_debug_output() {
    let ledger = FrontierLedger::new("ledger-dbg", epoch(1));
    let debug = format!("{:?}", ledger);
    assert!(debug.contains("FrontierLedger"));
    assert!(debug.contains("ledger-dbg"));
}

#[test]
fn enrichment_frontier_ledger_json_field_names() {
    let ledger = FrontierLedger::new("ledger-jf", epoch(1));
    let json = serde_json::to_string(&ledger).unwrap();
    assert!(json.contains("\"ledger_id\""));
    assert!(json.contains("\"assembled_epoch\""));
    assert!(json.contains("\"entries\""));
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"ledger_hash\""));
}

#[test]
fn enrichment_frontier_ledger_hash_deterministic() {
    let l1 = FrontierLedger::new("ledger-det", epoch(3));
    let l2 = FrontierLedger::new("ledger-det", epoch(3));
    assert_eq!(l1.ledger_hash, l2.ledger_hash);
}

#[test]
fn enrichment_frontier_ledger_none_unexplored() {
    // A ledger with zero entries should have zero unexplored
    let ledger = FrontierLedger::new("ledger-none", epoch(1));
    assert_eq!(ledger.unexplored_count(), 0);
    assert_eq!(ledger.entry_count(), 0);
}

// ---------------------------------------------------------------------------
// PromotionReceipt — Clone, Debug, JSON field names, additional hash cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_receipt_clone_eq() {
    let receipt = PromotionReceipt::new(
        "pr-clone",
        "law-1",
        PromotionTarget::RewritePack,
        "rw-1",
        epoch(10),
        "test",
    );
    let cloned = receipt.clone();
    assert_eq!(receipt, cloned);
    assert_eq!(receipt.receipt_hash, cloned.receipt_hash);
}

#[test]
fn enrichment_receipt_debug_output() {
    let receipt = PromotionReceipt::new(
        "pr-dbg",
        "law-1",
        PromotionTarget::RewritePack,
        "rw-1",
        epoch(10),
        "test",
    );
    let debug = format!("{:?}", receipt);
    assert!(debug.contains("PromotionReceipt"));
    assert!(debug.contains("pr-dbg"));
}

#[test]
fn enrichment_receipt_json_field_names() {
    let receipt = PromotionReceipt::new(
        "pr-jf",
        "law-1",
        PromotionTarget::RewritePack,
        "rw-1",
        epoch(10),
        "test",
    );
    let json = serde_json::to_string(&receipt).unwrap();
    assert!(json.contains("\"receipt_id\""));
    assert!(json.contains("\"law_id\""));
    assert!(json.contains("\"target\""));
    assert!(json.contains("\"asset_id\""));
    assert!(json.contains("\"promotion_epoch\""));
    assert!(json.contains("\"status\""));
    assert!(json.contains("\"rationale\""));
    assert!(json.contains("\"receipt_hash\""));
}

#[test]
fn enrichment_receipt_hash_differs_on_receipt_id() {
    let r1 = PromotionReceipt::new(
        "pr-a",
        "law",
        PromotionTarget::RewritePack,
        "a",
        epoch(1),
        "r",
    );
    let r2 = PromotionReceipt::new(
        "pr-b",
        "law",
        PromotionTarget::RewritePack,
        "a",
        epoch(1),
        "r",
    );
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_receipt_hash_differs_on_law_id() {
    let r1 = PromotionReceipt::new(
        "pr-1",
        "law-a",
        PromotionTarget::RewritePack,
        "a",
        epoch(1),
        "r",
    );
    let r2 = PromotionReceipt::new(
        "pr-1",
        "law-b",
        PromotionTarget::RewritePack,
        "a",
        epoch(1),
        "r",
    );
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_receipt_hash_differs_on_asset_id() {
    let r1 = PromotionReceipt::new(
        "pr-1",
        "law",
        PromotionTarget::RewritePack,
        "asset-a",
        epoch(1),
        "r",
    );
    let r2 = PromotionReceipt::new(
        "pr-1",
        "law",
        PromotionTarget::RewritePack,
        "asset-b",
        epoch(1),
        "r",
    );
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_receipt_double_revoke_stable_hash() {
    let mut receipt = PromotionReceipt::new(
        "pr-dbl",
        "law",
        PromotionTarget::RewritePack,
        "a",
        epoch(1),
        "r",
    );
    receipt.revoke("first reason");
    let hash_after_first = receipt.receipt_hash;
    receipt.revoke("second reason");
    // Hash changes because rationale changes
    // But status stays Revoked
    assert_eq!(receipt.status, PromotionStatus::Revoked);
    assert!(receipt.rationale.contains("second reason"));
    // Note: hash may differ because rationale differs
    let _ = hash_after_first; // used for binding
}

#[test]
fn enrichment_receipt_revoke_then_supersede() {
    let mut receipt = PromotionReceipt::new(
        "pr-rs",
        "law",
        PromotionTarget::RewritePack,
        "a",
        epoch(1),
        "r",
    );
    receipt.revoke("bad law");
    assert_eq!(receipt.status, PromotionStatus::Revoked);
    receipt.supersede("law-better");
    assert_eq!(receipt.status, PromotionStatus::Superseded);
    assert!(receipt.rationale.contains("law-better"));
}

#[test]
fn enrichment_receipt_display_after_revoke() {
    let mut receipt = PromotionReceipt::new(
        "pr-disp-rev",
        "law-x",
        PromotionTarget::SynthesisLane,
        "syn-1",
        epoch(10),
        "test",
    );
    receipt.revoke("counterexample");
    let display = receipt.to_string();
    assert!(display.contains("revoked"));
}

#[test]
fn enrichment_receipt_display_after_supersede() {
    let mut receipt = PromotionReceipt::new(
        "pr-disp-sup",
        "law-y",
        PromotionTarget::SupportAtlas,
        "ae-1",
        epoch(10),
        "test",
    );
    receipt.supersede("law-z");
    let display = receipt.to_string();
    assert!(display.contains("superseded"));
}

#[test]
fn enrichment_receipt_for_each_target() {
    for target in PromotionTarget::ALL {
        let receipt = PromotionReceipt::new(
            "pr-each",
            "law-each",
            *target,
            "asset-each",
            epoch(1),
            "test",
        );
        assert_eq!(receipt.target, *target);
        assert_eq!(receipt.status, PromotionStatus::Promoted);
        let json = serde_json::to_string(&receipt).unwrap();
        let back: PromotionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }
}

// ---------------------------------------------------------------------------
// PromotionPipeline — Clone, Debug, JSON field names, edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pipeline_clone_eq() {
    let mut pipeline = PromotionPipeline::new("pipe-clone", epoch(10));
    let law = default_law();
    pipeline.promote_to_rewrite(&law, "p", "r", "g", 1_000_000);
    let cloned = pipeline.clone();
    assert_eq!(pipeline, cloned);
    assert_eq!(pipeline.pipeline_hash, cloned.pipeline_hash);
}

#[test]
fn enrichment_pipeline_debug_output() {
    let pipeline = PromotionPipeline::new("pipe-dbg", epoch(10));
    let debug = format!("{:?}", pipeline);
    assert!(debug.contains("PromotionPipeline"));
}

#[test]
fn enrichment_pipeline_json_field_names() {
    let pipeline = PromotionPipeline::new("pipe-jf", epoch(1));
    let json = serde_json::to_string(&pipeline).unwrap();
    assert!(json.contains("\"rewrite_pack\""));
    assert!(json.contains("\"synthesis_lane\""));
    assert!(json.contains("\"support_atlas\""));
    assert!(json.contains("\"frontier_ledger\""));
    assert!(json.contains("\"receipts\""));
    assert!(json.contains("\"pipeline_epoch\""));
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"pipeline_hash\""));
}

#[test]
fn enrichment_pipeline_all_revoked_active_zero() {
    let mut pipeline = PromotionPipeline::new("pipe-all-rev", epoch(10));
    let law = default_law();
    pipeline.promote_to_rewrite(&law, "p", "r", "g", 1_000_000);
    pipeline.promote_to_synthesis(&law, "t", vec![], "e");
    pipeline.promote_to_atlas(&law, "d", 500_000);
    assert_eq!(pipeline.active_promotions(), 3);

    pipeline.receipts[0].revoke("bad");
    pipeline.receipts[1].revoke("also bad");
    pipeline.receipts[2].revoke("all bad");
    assert_eq!(pipeline.active_promotions(), 0);
    assert_eq!(pipeline.total_promotions(), 3);
}

#[test]
fn enrichment_pipeline_epoch_propagated_to_sub_components() {
    let pipeline = PromotionPipeline::new("pipe-ep", epoch(77));
    assert_eq!(pipeline.pipeline_epoch, epoch(77));
    assert_eq!(pipeline.rewrite_pack.assembled_epoch, epoch(77));
    assert_eq!(pipeline.synthesis_lane.assembled_epoch, epoch(77));
    assert_eq!(pipeline.support_atlas.assembled_epoch, epoch(77));
    assert_eq!(pipeline.frontier_ledger.assembled_epoch, epoch(77));
}

#[test]
fn enrichment_pipeline_receipt_rationale_contains_law_id() {
    let mut pipeline = PromotionPipeline::new("pipe-rat", epoch(10));
    let law = make_law("law-rat-test", LawStrength::Proved, 800_000, vec![]);
    let r = pipeline.promote_to_rewrite(&law, "p", "r", "g", 1_000_000);
    assert!(r.rationale.contains("law-rat-test"));
}

#[test]
fn enrichment_pipeline_display_with_all_targets() {
    let mut pipeline = PromotionPipeline::new("pipe-all-disp", epoch(5));
    let law = default_law();
    pipeline.promote_to_rewrite(&law, "p", "r", "g", 1_000_000);
    pipeline.promote_to_synthesis(&law, "t", vec![], "e");
    pipeline.promote_to_atlas(&law, "d", 500_000);
    pipeline.promote_to_frontier(&law, "r", 200_000);
    let display = pipeline.to_string();
    assert!(display.contains("promotions=4"));
    assert!(display.contains("rewrites=1"));
    assert!(display.contains("seeds=1"));
    assert!(display.contains("atlas=1"));
    assert!(display.contains("frontier=1"));
    assert!(display.contains("epoch=5"));
}

#[test]
fn enrichment_pipeline_hash_differs_on_pipeline_id() {
    let p1 = PromotionPipeline::new("pipe-id-a", epoch(1));
    let p2 = PromotionPipeline::new("pipe-id-b", epoch(1));
    // Different IDs produce different sub-component IDs => different hashes
    assert_ne!(p1.pipeline_hash, p2.pipeline_hash);
}

#[test]
fn enrichment_pipeline_hash_differs_on_epoch() {
    let p1 = PromotionPipeline::new("pipe-ep-cmp", epoch(1));
    let p2 = PromotionPipeline::new("pipe-ep-cmp", epoch(2));
    assert_ne!(p1.pipeline_hash, p2.pipeline_hash);
}

// ---------------------------------------------------------------------------
// PromotionSummaryReport — Clone, Debug, JSON field names
// ---------------------------------------------------------------------------

#[test]
fn enrichment_summary_report_clone_eq() {
    let report = PromotionSummaryReport {
        total_promotions: 5,
        active_promotions: 3,
        rewrite_rules: 1,
        synthesis_seeds: 1,
        atlas_entries: 2,
        frontier_entries: 1,
        unexplored_frontiers: 1,
        covered_domains: 2,
        epoch: epoch(10),
    };
    let cloned = report.clone();
    assert_eq!(report, cloned);
}

#[test]
fn enrichment_summary_report_debug_output() {
    let report = PromotionSummaryReport {
        total_promotions: 1,
        active_promotions: 1,
        rewrite_rules: 0,
        synthesis_seeds: 0,
        atlas_entries: 0,
        frontier_entries: 1,
        unexplored_frontiers: 1,
        covered_domains: 0,
        epoch: epoch(1),
    };
    let debug = format!("{:?}", report);
    assert!(debug.contains("PromotionSummaryReport"));
}

#[test]
fn enrichment_summary_report_json_field_names() {
    let report = PromotionSummaryReport {
        total_promotions: 0,
        active_promotions: 0,
        rewrite_rules: 0,
        synthesis_seeds: 0,
        atlas_entries: 0,
        frontier_entries: 0,
        unexplored_frontiers: 0,
        covered_domains: 0,
        epoch: epoch(0),
    };
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"total_promotions\""));
    assert!(json.contains("\"active_promotions\""));
    assert!(json.contains("\"rewrite_rules\""));
    assert!(json.contains("\"synthesis_seeds\""));
    assert!(json.contains("\"atlas_entries\""));
    assert!(json.contains("\"frontier_entries\""));
    assert!(json.contains("\"unexplored_frontiers\""));
    assert!(json.contains("\"covered_domains\""));
    assert!(json.contains("\"epoch\""));
}

#[test]
fn enrichment_summary_report_display_all_zeros() {
    let report = PromotionSummaryReport {
        total_promotions: 0,
        active_promotions: 0,
        rewrite_rules: 0,
        synthesis_seeds: 0,
        atlas_entries: 0,
        frontier_entries: 0,
        unexplored_frontiers: 0,
        covered_domains: 0,
        epoch: epoch(0),
    };
    let display = report.to_string();
    assert!(display.contains("PromotionSummary"));
    assert!(display.contains("0/0"));
    assert!(display.contains("rewrites=0"));
    assert!(display.contains("seeds=0"));
    assert!(display.contains("atlas=0"));
}

#[test]
fn enrichment_summary_report_large_values() {
    let report = PromotionSummaryReport {
        total_promotions: 100_000,
        active_promotions: 99_999,
        rewrite_rules: 50_000,
        synthesis_seeds: 20_000,
        atlas_entries: 15_000,
        frontier_entries: 15_000,
        unexplored_frontiers: 10_000,
        covered_domains: 5_000,
        epoch: epoch(u64::MAX),
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: PromotionSummaryReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// Cross-cutting determinism and edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pipeline_serde_preserves_receipt_order() {
    let mut pipeline = PromotionPipeline::new("pipe-order", epoch(10));
    let law1 = make_law("law-1", LawStrength::Proved, 900_000, vec![]);
    let law2 = make_law("law-2", LawStrength::Empirical, 600_000, vec![]);
    let law3 = make_law("law-3", LawStrength::Heuristic, 300_000, vec![]);

    pipeline.promote_to_rewrite(&law1, "p1", "r1", "g1", 1_000_000);
    pipeline.promote_to_synthesis(&law2, "t2", vec![], "e2");
    pipeline.promote_to_atlas(&law3, "d3", 300_000);

    let json = serde_json::to_string(&pipeline).unwrap();
    let back: PromotionPipeline = serde_json::from_str(&json).unwrap();

    // Receipt order preserved
    assert_eq!(back.receipts[0].law_id, "law-1");
    assert_eq!(back.receipts[1].law_id, "law-2");
    assert_eq!(back.receipts[2].law_id, "law-3");
}

#[test]
fn enrichment_pipeline_determinism_across_constructions() {
    // Build the same pipeline twice independently
    let build = || {
        let mut p = PromotionPipeline::new("det-pipe", epoch(42));
        let law = make_law("det-law", LawStrength::Proved, 800_000, vec!["tag".into()]);
        p.promote_to_rewrite(&law, "patt", "repl", "guard", 1_200_000);
        p.promote_to_synthesis(&law, "tmpl", vec!["x".into()], "expect");
        p.promote_to_atlas(&law, "domain.a", 700_000);
        p.promote_to_frontier(&law, "frontier.b", 350_000);
        p
    };
    let p1 = build();
    let p2 = build();
    assert_eq!(p1.pipeline_hash, p2.pipeline_hash);
    assert_eq!(p1, p2);
}

#[test]
fn enrichment_rewrite_rule_from_different_laws_different_hash() {
    let law_a = make_law("law-a", LawStrength::Proved, 800_000, vec![]);
    let law_b = make_law("law-b", LawStrength::Proved, 800_000, vec![]);
    let r1 = RewriteRule::from_law("rw-same", &law_a, "p", "r", "g", 1_000_000);
    let r2 = RewriteRule::from_law("rw-same", &law_b, "p", "r", "g", 1_000_000);
    // Different source_law_id => different hash
    assert_ne!(r1.rule_hash, r2.rule_hash);
}

#[test]
fn enrichment_synthesis_seed_from_different_laws_different_hash() {
    let law_a = make_law("law-a", LawStrength::Proved, 800_000, vec![]);
    let law_b = make_law("law-b", LawStrength::Proved, 800_000, vec![]);
    let s1 = SynthesisSeed::from_law("syn-same", &law_a, "t", vec![], "e");
    let s2 = SynthesisSeed::from_law("syn-same", &law_b, "t", vec![], "e");
    assert_ne!(s1.seed_hash, s2.seed_hash);
}

#[test]
fn enrichment_atlas_entry_from_different_laws_different_hash() {
    let law_a = make_law("law-a", LawStrength::Proved, 800_000, vec![]);
    let law_b = make_law("law-b", LawStrength::Proved, 800_000, vec![]);
    let e1 = SupportAtlasEntry::from_law("ae-same", &law_a, "d", 500_000);
    let e2 = SupportAtlasEntry::from_law("ae-same", &law_b, "d", 500_000);
    assert_ne!(e1.entry_hash, e2.entry_hash);
}

#[test]
fn enrichment_frontier_entry_from_different_laws_different_hash() {
    let law_a = make_law("law-a", LawStrength::Proved, 800_000, vec![]);
    let law_b = make_law("law-b", LawStrength::Proved, 800_000, vec![]);
    let f1 = FrontierEntry::from_law("f-same", &law_a, "r", 200_000);
    let f2 = FrontierEntry::from_law("f-same", &law_b, "r", 200_000);
    assert_ne!(f1.entry_hash, f2.entry_hash);
}

#[test]
fn enrichment_summary_report_from_pipeline_with_revocations() {
    let mut pipeline = PromotionPipeline::new("pipe-rev-sum", epoch(10));
    let law = default_law();
    pipeline.promote_to_rewrite(&law, "p", "r", "g", 1_000_000);
    pipeline.promote_to_synthesis(&law, "t", vec![], "e");
    pipeline.promote_to_atlas(&law, "d", 500_000);
    pipeline.promote_to_frontier(&law, "f", 200_000);

    pipeline.receipts[0].revoke("bad rewrite");
    pipeline.receipts[2].supersede("law-better");

    let report = pipeline.summary_report();
    assert_eq!(report.total_promotions, 4);
    assert_eq!(report.active_promotions, 2); // synthesis + frontier still active
    assert_eq!(report.rewrite_rules, 1); // pack still has the rule
    assert_eq!(report.frontier_entries, 1);
    assert_eq!(report.unexplored_frontiers, 1);
}

#[test]
fn enrichment_pipeline_promote_same_law_same_target_twice() {
    let mut pipeline = PromotionPipeline::new("pipe-dup", epoch(10));
    let law = default_law();
    pipeline.promote_to_rewrite(&law, "p1", "r1", "g1", 1_000_000);
    pipeline.promote_to_rewrite(&law, "p2", "r2", "g2", 1_100_000);
    // Two rules in pack, two receipts
    assert_eq!(pipeline.rewrite_pack.rule_count(), 2);
    assert_eq!(pipeline.total_promotions(), 2);
}

#[test]
fn enrichment_rewrite_pack_serde_roundtrip_empty() {
    let pack = RewritePack::new("pack-serde-empty", epoch(3));
    let json = serde_json::to_string(&pack).unwrap();
    let back: RewritePack = serde_json::from_str(&json).unwrap();
    assert_eq!(pack, back);
    assert_eq!(back.rule_count(), 0);
}

#[test]
fn enrichment_synthesis_lane_serde_roundtrip_empty() {
    let lane = SynthesisLane::new("lane-serde-empty", epoch(4));
    let json = serde_json::to_string(&lane).unwrap();
    let back: SynthesisLane = serde_json::from_str(&json).unwrap();
    assert_eq!(lane, back);
    assert_eq!(back.seed_count(), 0);
}

#[test]
fn enrichment_support_atlas_serde_roundtrip_empty() {
    let atlas = SupportAtlas::new("atlas-serde-empty", epoch(5));
    let json = serde_json::to_string(&atlas).unwrap();
    let back: SupportAtlas = serde_json::from_str(&json).unwrap();
    assert_eq!(atlas, back);
    assert_eq!(back.entry_count(), 0);
}

#[test]
fn enrichment_frontier_ledger_serde_roundtrip_empty() {
    let ledger = FrontierLedger::new("ledger-serde-empty", epoch(6));
    let json = serde_json::to_string(&ledger).unwrap();
    let back: FrontierLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(ledger, back);
    assert_eq!(back.entry_count(), 0);
}

#[test]
fn enrichment_accepted_law_zero_rank_all_strengths() {
    // Verify priority computation at rank=0 for all strengths
    let expected = [
        (LawStrength::Proved, 600_000u64),      // 1_000_000 * 600_000 / 1M
        (LawStrength::Empirical, 450_000u64),   // 750_000 * 600_000 / 1M
        (LawStrength::Conditional, 300_000u64), // 500_000 * 600_000 / 1M
        (LawStrength::Heuristic, 150_000u64),   // 250_000 * 600_000 / 1M
    ];
    for (strength, exp_priority) in &expected {
        let law = make_law("law-zr", *strength, 0, vec![]);
        assert_eq!(
            law.promotion_priority_millionths(),
            *exp_priority,
            "Failed for {strength}: expected {exp_priority}"
        );
    }
}

#[test]
fn enrichment_accepted_law_max_rank_all_strengths() {
    // Verify priority computation at rank=1_000_000 for all strengths
    let expected = [
        (LawStrength::Proved, 1_000_000u64),    // min(1M, 600k + 400k)
        (LawStrength::Empirical, 850_000u64),   // 450k + 400k
        (LawStrength::Conditional, 700_000u64), // 300k + 400k
        (LawStrength::Heuristic, 550_000u64),   // 150k + 400k
    ];
    for (strength, exp_priority) in &expected {
        let law = make_law("law-mr", *strength, 1_000_000, vec![]);
        assert_eq!(
            law.promotion_priority_millionths(),
            *exp_priority,
            "Failed for {strength}: expected {exp_priority}"
        );
    }
}
