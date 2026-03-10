//! Integration tests for the law promotion pack module.
//!
//! Tests cover law acceptance, promotion to all four targets (rewrite packs,
//! synthesis lanes, support atlases, frontier ledgers), receipts, revocation,
//! supersession, and the full promotion pipeline lifecycle.

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

use frankenengine_engine::law_promotion_pack::{
    AcceptedLaw, COMPONENT, FrontierEntry, FrontierLedger, LAW_PROMOTION_BEAD_ID,
    LAW_PROMOTION_SCHEMA_VERSION, LawStrength, PromotionPipeline, PromotionReceipt,
    PromotionStatus, PromotionTarget, RewritePack, RewriteRule, SupportAtlas, SupportAtlasEntry,
    SynthesisLane, SynthesisSeed,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn proved_law() -> AcceptedLaw {
    AcceptedLaw::new(
        "law-proved-001",
        "cand-001",
        "typeof x === 'string' implies x.length >= 0",
        LawStrength::Proved,
        vec!["string-ops".to_string(), "type-guard".to_string()],
        900_000,
        epoch(10),
        vec!["proof-001".to_string()],
    )
}

fn empirical_law() -> AcceptedLaw {
    AcceptedLaw::new(
        "law-emp-001",
        "cand-002",
        "Array.isArray(x) implies x.length is non-negative",
        LawStrength::Empirical,
        vec!["array-ops".to_string()],
        700_000,
        epoch(10),
        vec!["campaign-001".to_string(), "campaign-002".to_string()],
    )
}

fn heuristic_law() -> AcceptedLaw {
    AcceptedLaw::new(
        "law-heur-001",
        "cand-003",
        "most objects have < 20 properties",
        LawStrength::Heuristic,
        vec!["object-shape".to_string()],
        500_000,
        epoch(10),
        vec!["sample-001".to_string()],
    )
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version_format() {
    assert!(LAW_PROMOTION_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(LAW_PROMOTION_SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn test_bead_id_format() {
    assert!(LAW_PROMOTION_BEAD_ID.starts_with("bd-"));
}

#[test]
fn test_component_name() {
    assert_eq!(COMPONENT, "law_promotion_pack");
}

// ---------------------------------------------------------------------------
// PromotionTarget
// ---------------------------------------------------------------------------

#[test]
fn test_all_targets_distinct() {
    let targets: Vec<_> = PromotionTarget::ALL.to_vec();
    for (i, a) in targets.iter().enumerate() {
        for (j, b) in targets.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

#[test]
fn test_target_display_serde_consistency() {
    for target in PromotionTarget::ALL {
        let display = target.to_string();
        let json = serde_json::to_string(target).unwrap();
        let json_inner = json.trim_matches('"');
        assert_eq!(display, json_inner);
    }
}

// ---------------------------------------------------------------------------
// LawStrength
// ---------------------------------------------------------------------------

#[test]
fn test_strength_ordering_by_weight() {
    assert!(LawStrength::Proved.weight_millionths() > LawStrength::Empirical.weight_millionths());
    assert!(
        LawStrength::Empirical.weight_millionths() > LawStrength::Conditional.weight_millionths()
    );
    assert!(
        LawStrength::Conditional.weight_millionths() > LawStrength::Heuristic.weight_millionths()
    );
}

#[test]
fn test_strength_weights_in_valid_range() {
    for strength in LawStrength::ALL {
        let weight = strength.weight_millionths();
        assert!(weight > 0, "{strength} should have positive weight");
        assert!(weight <= 1_000_000, "{strength} weight exceeds 1.0");
    }
}

// ---------------------------------------------------------------------------
// PromotionStatus
// ---------------------------------------------------------------------------

#[test]
fn test_status_is_active() {
    assert!(PromotionStatus::Pending.is_active());
    assert!(PromotionStatus::Promoted.is_active());
    assert!(!PromotionStatus::Superseded.is_active());
    assert!(!PromotionStatus::Revoked.is_active());
    assert!(!PromotionStatus::Expired.is_active());
}

#[test]
fn test_status_all_distinct() {
    let statuses: Vec<_> = PromotionStatus::ALL.to_vec();
    for (i, a) in statuses.iter().enumerate() {
        for (j, b) in statuses.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AcceptedLaw
// ---------------------------------------------------------------------------

#[test]
fn test_law_creation() {
    let law = proved_law();
    assert_eq!(law.law_id, "law-proved-001");
    assert_eq!(law.strength, LawStrength::Proved);
    assert_eq!(law.scope_tags.len(), 2);
    assert_eq!(law.evidence_ids.len(), 1);
}

#[test]
fn test_law_priority_proved_highest() {
    let proved = proved_law();
    let empirical = empirical_law();
    let heuristic = heuristic_law();

    assert!(proved.promotion_priority_millionths() > empirical.promotion_priority_millionths());
    assert!(empirical.promotion_priority_millionths() > heuristic.promotion_priority_millionths());
}

#[test]
fn test_law_priority_formula_proved() {
    let law = proved_law(); // strength=Proved(1M), rank=900k
    // 60% * 1_000_000 + 40% * 900_000 = 600_000 + 360_000 = 960_000
    assert_eq!(law.promotion_priority_millionths(), 960_000);
}

#[test]
fn test_law_priority_formula_heuristic() {
    let law = heuristic_law(); // strength=Heuristic(250k), rank=500k
    // 60% * 250_000 + 40% * 500_000 = 150_000 + 200_000 = 350_000
    assert_eq!(law.promotion_priority_millionths(), 350_000);
}

#[test]
fn test_law_hash_determinism() {
    let l1 = proved_law();
    let l2 = proved_law();
    assert_eq!(l1.law_hash, l2.law_hash);
}

#[test]
fn test_law_different_ids_different_hashes() {
    let l1 = proved_law();
    let l2 = empirical_law();
    assert_ne!(l1.law_hash, l2.law_hash);
}

#[test]
fn test_law_serde_roundtrip() {
    let law = proved_law();
    let json = serde_json::to_string(&law).unwrap();
    let back: AcceptedLaw = serde_json::from_str(&json).unwrap();
    assert_eq!(law, back);
}

// ---------------------------------------------------------------------------
// RewriteRule + RewritePack
// ---------------------------------------------------------------------------

#[test]
fn test_rewrite_rule_from_law() {
    let law = proved_law();
    let rule = RewriteRule::from_law(
        "rw-001",
        &law,
        "typeof x === 'string'",
        "x.tag_is_string()",
        "x.shape.has_tag(STRING)",
        1_200_000,
    );
    assert_eq!(rule.source_law_id, "law-proved-001");
    assert!(rule.semantics_preserving);
    assert_eq!(rule.speedup_estimate_millionths, 1_200_000);
}

#[test]
fn test_rewrite_pack_accumulation() {
    let mut pack = RewritePack::new("pack-001", epoch(10));
    let law = proved_law();
    for i in 0..5 {
        let rule = RewriteRule::from_law(&format!("rw-{i}"), &law, "p", "r", "g", 1_000_000);
        pack.add_rule(rule);
    }
    assert_eq!(pack.rule_count(), 5);
}

#[test]
fn test_rewrite_pack_hash_changes_on_add() {
    let mut pack = RewritePack::new("pack-001", epoch(10));
    let hash_empty = pack.pack_hash.clone();
    let law = proved_law();
    pack.add_rule(RewriteRule::from_law(
        "rw-1", &law, "p", "r", "g", 1_000_000,
    ));
    assert_ne!(pack.pack_hash, hash_empty);
}

// ---------------------------------------------------------------------------
// SynthesisSeed + SynthesisLane
// ---------------------------------------------------------------------------

#[test]
fn test_synthesis_seed_priority_from_law() {
    let law = proved_law();
    let seed = SynthesisSeed::from_law("syn-001", &law, "template", vec![], "pattern");
    assert_eq!(
        seed.priority_millionths,
        law.promotion_priority_millionths()
    );
}

#[test]
fn test_synthesis_lane_accumulation() {
    let mut lane = SynthesisLane::new("lane-001", epoch(10));
    let law = proved_law();
    for i in 0..3 {
        let seed = SynthesisSeed::from_law(&format!("syn-{i}"), &law, "t", vec![], "p");
        lane.add_seed(seed);
    }
    assert_eq!(lane.seed_count(), 3);
}

// ---------------------------------------------------------------------------
// SupportAtlasEntry + SupportAtlas
// ---------------------------------------------------------------------------

#[test]
fn test_atlas_entry_inherits_scope_tags() {
    let law = proved_law();
    let entry = SupportAtlasEntry::from_law("ae-001", &law, "string.length", 800_000);
    assert_eq!(entry.scope_tags, law.scope_tags);
}

#[test]
fn test_atlas_entry_validate_changes_hash() {
    let law = proved_law();
    let mut entry = SupportAtlasEntry::from_law("ae-001", &law, "string.length", 800_000);
    let hash_before = entry.entry_hash.clone();
    entry.validate();
    assert_ne!(entry.entry_hash, hash_before);
    assert!(entry.workload_validated);
}

#[test]
fn test_atlas_covered_domains_dedup() {
    let mut atlas = SupportAtlas::new("atlas-001", epoch(10));
    let law = proved_law();
    atlas.add_entry(SupportAtlasEntry::from_law(
        "e1",
        &law,
        "string.length",
        500_000,
    ));
    atlas.add_entry(SupportAtlasEntry::from_law(
        "e2",
        &law,
        "string.length",
        700_000,
    ));
    atlas.add_entry(SupportAtlasEntry::from_law(
        "e3",
        &law,
        "array.push",
        600_000,
    ));
    assert_eq!(atlas.covered_domains().len(), 2);
    assert_eq!(atlas.entry_count(), 3);
}

// ---------------------------------------------------------------------------
// FrontierEntry + FrontierLedger
// ---------------------------------------------------------------------------

#[test]
fn test_frontier_entry_starts_unexplored() {
    let law = proved_law();
    let entry = FrontierEntry::from_law("f-001", &law, "regex.backtracking", 400_000);
    assert!(!entry.explored);
}

#[test]
fn test_frontier_entry_mark_explored_changes_hash() {
    let law = proved_law();
    let mut entry = FrontierEntry::from_law("f-001", &law, "regex.backtracking", 400_000);
    let hash_before = entry.entry_hash.clone();
    entry.mark_explored();
    assert!(entry.explored);
    assert_ne!(entry.entry_hash, hash_before);
}

#[test]
fn test_frontier_ledger_unexplored_count() {
    let mut ledger = FrontierLedger::new("ledger-001", epoch(10));
    let law = proved_law();

    let mut e1 = FrontierEntry::from_law("f1", &law, "r1", 100_000);
    e1.mark_explored();
    ledger.add_entry(e1);
    ledger.add_entry(FrontierEntry::from_law("f2", &law, "r2", 200_000));
    ledger.add_entry(FrontierEntry::from_law("f3", &law, "r3", 300_000));

    assert_eq!(ledger.entry_count(), 3);
    assert_eq!(ledger.unexplored_count(), 2);
}

// ---------------------------------------------------------------------------
// PromotionReceipt
// ---------------------------------------------------------------------------

#[test]
fn test_receipt_starts_promoted() {
    let receipt = PromotionReceipt::new(
        "pr-001",
        "law-001",
        PromotionTarget::RewritePack,
        "rw-001",
        epoch(10),
        "test promotion",
    );
    assert_eq!(receipt.status, PromotionStatus::Promoted);
    assert!(receipt.status.is_active());
}

#[test]
fn test_receipt_revoke() {
    let mut receipt = PromotionReceipt::new(
        "pr-001",
        "law-001",
        PromotionTarget::RewritePack,
        "rw-001",
        epoch(10),
        "test",
    );
    receipt.revoke("counterexample found");
    assert_eq!(receipt.status, PromotionStatus::Revoked);
    assert!(!receipt.status.is_active());
    assert!(receipt.rationale.contains("REVOKED"));
}

#[test]
fn test_receipt_supersede() {
    let mut receipt = PromotionReceipt::new(
        "pr-001",
        "law-001",
        PromotionTarget::SynthesisLane,
        "syn-001",
        epoch(10),
        "test",
    );
    receipt.supersede("law-002");
    assert_eq!(receipt.status, PromotionStatus::Superseded);
    assert!(receipt.rationale.contains("law-002"));
}

#[test]
fn test_receipt_hash_determinism() {
    let r1 = PromotionReceipt::new("p", "l", PromotionTarget::RewritePack, "a", epoch(1), "r");
    let r2 = PromotionReceipt::new("p", "l", PromotionTarget::RewritePack, "a", epoch(1), "r");
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn test_receipt_different_targets_different_hashes() {
    let r1 = PromotionReceipt::new("p", "l", PromotionTarget::RewritePack, "a", epoch(1), "r");
    let r2 = PromotionReceipt::new("p", "l", PromotionTarget::SupportAtlas, "a", epoch(1), "r");
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

// ---------------------------------------------------------------------------
// PromotionPipeline
// ---------------------------------------------------------------------------

#[test]
fn test_pipeline_empty() {
    let pipeline = PromotionPipeline::new("test-pipeline", epoch(10));
    assert_eq!(pipeline.total_promotions(), 0);
    assert_eq!(pipeline.active_promotions(), 0);
    let report = pipeline.summary_report();
    assert_eq!(report.rewrite_rules, 0);
    assert_eq!(report.synthesis_seeds, 0);
    assert_eq!(report.atlas_entries, 0);
    assert_eq!(report.frontier_entries, 0);
}

#[test]
fn test_pipeline_promote_to_all_targets() {
    let mut pipeline = PromotionPipeline::new("all-targets", epoch(10));
    let law = proved_law();

    pipeline.promote_to_rewrite(&law, "p", "r", "g", 1_100_000);
    pipeline.promote_to_synthesis(&law, "t", vec!["a".into()], "e");
    pipeline.promote_to_atlas(&law, "string.length", 800_000);
    pipeline.promote_to_frontier(&law, "regex.backtrack", 500_000);

    assert_eq!(pipeline.total_promotions(), 4);
    assert_eq!(pipeline.active_promotions(), 4);

    let report = pipeline.summary_report();
    assert_eq!(report.rewrite_rules, 1);
    assert_eq!(report.synthesis_seeds, 1);
    assert_eq!(report.atlas_entries, 1);
    assert_eq!(report.frontier_entries, 1);
}

#[test]
fn test_pipeline_multiple_laws() {
    let mut pipeline = PromotionPipeline::new("multi-law", epoch(10));
    let proved = proved_law();
    let empirical = empirical_law();
    let heuristic = heuristic_law();

    pipeline.promote_to_rewrite(&proved, "p1", "r1", "g1", 1_200_000);
    pipeline.promote_to_rewrite(&empirical, "p2", "r2", "g2", 1_100_000);
    pipeline.promote_to_atlas(&proved, "string.ops", 900_000);
    pipeline.promote_to_atlas(&empirical, "array.ops", 700_000);
    pipeline.promote_to_frontier(&heuristic, "object.shape", 300_000);

    assert_eq!(pipeline.total_promotions(), 5);
    assert_eq!(pipeline.rewrite_pack.rule_count(), 2);
    assert_eq!(pipeline.support_atlas.entry_count(), 2);
    assert_eq!(pipeline.frontier_ledger.entry_count(), 1);
}

#[test]
fn test_pipeline_revocation_reduces_active_count() {
    let mut pipeline = PromotionPipeline::new("revoke-test", epoch(10));
    let law = proved_law();
    pipeline.promote_to_rewrite(&law, "p", "r", "g", 1_000_000);
    pipeline.promote_to_atlas(&law, "d", 500_000);

    assert_eq!(pipeline.active_promotions(), 2);
    pipeline.receipts[0].revoke("bad rule");
    assert_eq!(pipeline.active_promotions(), 1);
    assert_eq!(pipeline.total_promotions(), 2);
}

#[test]
fn test_pipeline_supersession() {
    let mut pipeline = PromotionPipeline::new("super-test", epoch(10));
    let law1 = proved_law();
    let law2 = empirical_law();

    pipeline.promote_to_atlas(&law1, "string.ops", 500_000);
    pipeline.promote_to_atlas(&law2, "string.ops", 700_000);

    pipeline.receipts[0].supersede(&law2.law_id);
    assert_eq!(pipeline.active_promotions(), 1);
}

#[test]
fn test_pipeline_hash_changes_on_promotion() {
    let mut pipeline = PromotionPipeline::new("hash-test", epoch(10));
    let hash_before = pipeline.pipeline_hash.clone();
    let law = proved_law();
    pipeline.promote_to_rewrite(&law, "p", "r", "g", 1_000_000);
    assert_ne!(pipeline.pipeline_hash, hash_before);
}

#[test]
fn test_pipeline_hash_determinism() {
    let p1 = PromotionPipeline::new("det-test", epoch(10));
    let p2 = PromotionPipeline::new("det-test", epoch(10));
    assert_eq!(p1.pipeline_hash, p2.pipeline_hash);
}

#[test]
fn test_pipeline_serde_roundtrip_empty() {
    let pipeline = PromotionPipeline::new("serde-test", epoch(10));
    let json = serde_json::to_string(&pipeline).unwrap();
    let back: PromotionPipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(pipeline, back);
}

#[test]
fn test_pipeline_serde_roundtrip_with_promotions() {
    let mut pipeline = PromotionPipeline::new("serde-test", epoch(10));
    let law = proved_law();
    pipeline.promote_to_rewrite(&law, "p", "r", "g", 1_000_000);
    pipeline.promote_to_atlas(&law, "d", 500_000);
    pipeline.promote_to_frontier(&law, "f", 300_000);

    let json = serde_json::to_string(&pipeline).unwrap();
    let back: PromotionPipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(pipeline, back);
}

#[test]
fn test_pipeline_display() {
    let mut pipeline = PromotionPipeline::new("display-test", epoch(10));
    let law = proved_law();
    pipeline.promote_to_rewrite(&law, "p", "r", "g", 1_000_000);
    let display = pipeline.to_string();
    assert!(display.contains("PromotionPipeline"));
    assert!(display.contains("promotions=1"));
}

// ---------------------------------------------------------------------------
// Full lifecycle integration
// ---------------------------------------------------------------------------

#[test]
fn test_full_promotion_lifecycle_with_revocation() {
    let e = epoch(42);
    let mut pipeline = PromotionPipeline::new("lifecycle", e);

    // Stage 1: Accept and promote laws
    let proved = proved_law();
    let empirical = empirical_law();

    let rw_receipt = pipeline.promote_to_rewrite(
        &proved,
        "typeof x === 'string'",
        "x.tag_check(STRING)",
        "x.has_type_feedback",
        1_300_000,
    );
    assert_eq!(rw_receipt.target, PromotionTarget::RewritePack);

    pipeline.promote_to_synthesis(
        &proved,
        "function test() { return typeof $x === 'string'; }",
        vec!["x".into()],
        "result === true || result === false",
    );

    pipeline.promote_to_atlas(&empirical, "Array.isArray", 750_000);
    pipeline.promote_to_frontier(&empirical, "typed-array.species", 350_000);

    let report = pipeline.summary_report();
    assert_eq!(report.total_promotions, 4);
    assert_eq!(report.active_promotions, 4);

    // Stage 2: Revoke the rewrite rule (counterexample found)
    pipeline.receipts[0].revoke("counterexample: typeof null === 'object'");
    assert_eq!(pipeline.active_promotions(), 3);

    // Stage 3: Supersede atlas entry with stronger law
    let stronger_law = AcceptedLaw::new(
        "law-stronger",
        "cand-stronger",
        "Array.isArray(x) <=> x has [[DefineOwnProperty]]",
        LawStrength::Proved,
        vec!["array-ops".into()],
        950_000,
        e,
        vec!["formal-proof-001".into()],
    );
    pipeline.promote_to_atlas(&stronger_law, "Array.isArray", 950_000);
    pipeline.receipts[2].supersede(&stronger_law.law_id);

    assert_eq!(pipeline.active_promotions(), 3);
    assert_eq!(pipeline.total_promotions(), 5);
}

#[test]
fn test_priority_ordering_across_strengths() {
    let laws: Vec<AcceptedLaw> = vec![
        AcceptedLaw::new(
            "l1",
            "c1",
            "s1",
            LawStrength::Proved,
            vec![],
            800_000,
            epoch(1),
            vec![],
        ),
        AcceptedLaw::new(
            "l2",
            "c2",
            "s2",
            LawStrength::Empirical,
            vec![],
            800_000,
            epoch(1),
            vec![],
        ),
        AcceptedLaw::new(
            "l3",
            "c3",
            "s3",
            LawStrength::Conditional,
            vec![],
            800_000,
            epoch(1),
            vec![],
        ),
        AcceptedLaw::new(
            "l4",
            "c4",
            "s4",
            LawStrength::Heuristic,
            vec![],
            800_000,
            epoch(1),
            vec![],
        ),
    ];

    let priorities: Vec<u64> = laws
        .iter()
        .map(|l| l.promotion_priority_millionths())
        .collect();
    // Should be strictly decreasing (Proved > Empirical > Conditional > Heuristic)
    for i in 0..priorities.len() - 1 {
        assert!(
            priorities[i] > priorities[i + 1],
            "priority[{}]={} should be > priority[{}]={}",
            i,
            priorities[i],
            i + 1,
            priorities[i + 1],
        );
    }
}

#[test]
fn test_pipeline_summary_report_accuracy() {
    let mut pipeline = PromotionPipeline::new("summary-test", epoch(10));
    let law = proved_law();

    pipeline.promote_to_rewrite(&law, "p1", "r1", "g1", 1_000_000);
    pipeline.promote_to_rewrite(&law, "p2", "r2", "g2", 1_100_000);
    pipeline.promote_to_synthesis(&law, "t1", vec![], "e1");
    pipeline.promote_to_atlas(&law, "d1", 500_000);
    pipeline.promote_to_atlas(&law, "d2", 600_000);
    pipeline.promote_to_atlas(&law, "d1", 700_000); // duplicate domain
    pipeline.promote_to_frontier(&law, "f1", 300_000);

    let report = pipeline.summary_report();
    assert_eq!(report.rewrite_rules, 2);
    assert_eq!(report.synthesis_seeds, 1);
    assert_eq!(report.atlas_entries, 3);
    assert_eq!(report.frontier_entries, 1);
    assert_eq!(report.covered_domains, 2); // d1 and d2
    assert_eq!(report.unexplored_frontiers, 1);
    assert_eq!(report.total_promotions, 7);
}
