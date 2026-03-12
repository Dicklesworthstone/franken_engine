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
    assert_eq!(active_count, 2, "Expected exactly Pending and Promoted to be active");
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
    pack.add_rule(RewriteRule::from_law("rw-a", &law, "pa", "ra", "ga", 1_000_000));
    pack.add_rule(RewriteRule::from_law("rw-b", &law, "pb", "rb", "gb", 1_100_000));
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
    assert_eq!(seed.priority_millionths, law.promotion_priority_millionths());
}

#[test]
fn enrichment_synthesis_seed_priority_matches_law() {
    let law = make_law("law-syn-prio", LawStrength::Conditional, 400_000, vec![]);
    let seed = SynthesisSeed::from_law("syn-p", &law, "t", vec![], "e");
    assert_eq!(seed.priority_millionths, law.promotion_priority_millionths());
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
    assert_eq!(entry.priority_millionths, law.promotion_priority_millionths());
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
    let r1 = PromotionReceipt::new("pr-t", "law", PromotionTarget::RewritePack, "a", epoch(1), "r");
    let r2 = PromotionReceipt::new("pr-t", "law", PromotionTarget::SynthesisLane, "a", epoch(1), "r");
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn enrichment_receipt_hash_differs_on_epoch() {
    let r1 = PromotionReceipt::new("pr-e", "law", PromotionTarget::RewritePack, "a", epoch(1), "r");
    let r2 = PromotionReceipt::new("pr-e", "law", PromotionTarget::RewritePack, "a", epoch(2), "r");
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
    let law = AcceptedLaw::new("", "", "", LawStrength::Heuristic, vec![], 0, epoch(0), vec![]);
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
        .map(|s| {
            make_law("l", *s, rank, vec![])
                .promotion_priority_millionths()
        })
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

    let receipt = PromotionReceipt::new("pr-1", "law-1", PromotionTarget::RewritePack, "a", epoch(1), "r");
    assert_ne!(receipt.receipt_hash, placeholder);
}
