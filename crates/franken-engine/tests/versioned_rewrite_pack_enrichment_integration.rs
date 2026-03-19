//! Enrichment integration tests for the `versioned_rewrite_pack` module.
//!
//! Covers PackVersion compatibility, InstructionCostClass, DeterministicCostModel,
//! RewriteCategory, RewriteRuleEntry, RuleInterferenceKind, RuleInterference,
//! InterferenceMetadata, RewritePack, and PackCatalog with deeper edge-case and
//! cross-cutting coverage beyond the baseline integration suite.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::versioned_rewrite_pack::{
    BEAD_ID, CATALOG_SCHEMA_VERSION, COMPONENT, COST_MODEL_SCHEMA_VERSION, DeterministicCostModel,
    INTERFERENCE_SCHEMA_VERSION, InstructionCostClass, InterferenceMetadata,
    MAX_INTERFERENCE_ENTRIES, MAX_RULES_PER_PACK, PACK_SCHEMA_VERSION, PackCatalog, PackVersion,
    RewriteCategory, RewritePack, RewriteRuleEntry, RuleInterference, RuleInterferenceKind,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(raw: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(raw)
}

fn make_rule_entry(
    id: &str,
    category: RewriteCategory,
    sound: bool,
    enabled: bool,
    classes: &[InstructionCostClass],
) -> RewriteRuleEntry {
    RewriteRuleEntry {
        rule_id: id.into(),
        category,
        description: format!("enrichment rule {id}"),
        pattern_hash: ContentHash::compute(format!("epat:{id}").as_bytes()),
        replacement_hash: ContentHash::compute(format!("erep:{id}").as_bytes()),
        proven_sound: sound,
        priority_millionths: 2 * MILLION,
        affected_cost_classes: classes.iter().copied().collect(),
        enabled,
    }
}

fn simple_rule(id: &str, category: RewriteCategory) -> RewriteRuleEntry {
    make_rule_entry(
        id,
        category,
        true,
        true,
        &[InstructionCostClass::Arithmetic],
    )
}

fn disabled_rule(id: &str, category: RewriteCategory) -> RewriteRuleEntry {
    make_rule_entry(
        id,
        category,
        false,
        false,
        &[InstructionCostClass::Arithmetic],
    )
}

fn interference(a: &str, b: &str, kind: RuleInterferenceKind, blocking: bool) -> RuleInterference {
    RuleInterference {
        rule_a: a.into(),
        rule_b: b.into(),
        kind,
        is_blocking: blocking,
        detail: format!("enrichment {a}<->{b}"),
    }
}

fn empty_interference() -> InterferenceMetadata {
    InterferenceMetadata::build(vec![])
}

fn build_pack(id: &str, version: PackVersion, rules: Vec<RewriteRuleEntry>) -> RewritePack {
    RewritePack::new(
        id,
        version,
        epoch(100),
        &format!("enrichment pack {id}"),
        rules,
        empty_interference(),
        "enrichment-cost-model",
    )
}

fn build_pack_with_interference(
    id: &str,
    rules: Vec<RewriteRuleEntry>,
    meta: InterferenceMetadata,
) -> RewritePack {
    RewritePack::new(
        id,
        PackVersion::CURRENT,
        epoch(100),
        &format!("enrichment pack {id}"),
        rules,
        meta,
        "enrichment-cost-model",
    )
}

fn default_pack(id: &str, rules: Vec<RewriteRuleEntry>) -> RewritePack {
    build_pack(id, PackVersion::CURRENT, rules)
}

// ===========================================================================
// PackVersion enrichment tests
// ===========================================================================

#[test]
fn enrichment_pack_version_current_is_one_zero() {
    let v = PackVersion::CURRENT;
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 0);
}

#[test]
fn enrichment_pack_version_display_zero() {
    let v = PackVersion { major: 0, minor: 0 };
    assert_eq!(v.to_string(), "0.0");
}

#[test]
fn enrichment_pack_version_display_large_numbers() {
    let v = PackVersion {
        major: 999,
        minor: 888,
    };
    assert_eq!(v.to_string(), "999.888");
}

#[test]
fn enrichment_pack_version_compatible_same_major_higher_minor() {
    let host = PackVersion { major: 3, minor: 7 };
    let pack = PackVersion { major: 3, minor: 2 };
    assert!(host.is_compatible_with(&pack));
}

#[test]
fn enrichment_pack_version_compatible_same_version_exactly() {
    let v = PackVersion {
        major: 4,
        minor: 11,
    };
    assert!(v.is_compatible_with(&v));
}

#[test]
fn enrichment_pack_version_incompatible_lower_minor() {
    let host = PackVersion { major: 2, minor: 3 };
    let pack = PackVersion { major: 2, minor: 4 };
    assert!(!host.is_compatible_with(&pack));
}

#[test]
fn enrichment_pack_version_incompatible_different_major_higher() {
    let host = PackVersion { major: 1, minor: 9 };
    let pack = PackVersion { major: 2, minor: 0 };
    assert!(!host.is_compatible_with(&pack));
}

#[test]
fn enrichment_pack_version_incompatible_different_major_lower() {
    let host = PackVersion { major: 3, minor: 0 };
    let pack = PackVersion { major: 2, minor: 0 };
    assert!(!host.is_compatible_with(&pack));
}

#[test]
fn enrichment_pack_version_serde_roundtrip_varied() {
    for (maj, min) in [(0, 0), (1, 0), (1, 5), (99, 42), (u32::MAX, u32::MAX)] {
        let v = PackVersion {
            major: maj,
            minor: min,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: PackVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_pack_version_ordering_across_majors() {
    let a = PackVersion {
        major: 1,
        minor: 99,
    };
    let b = PackVersion { major: 2, minor: 0 };
    assert!(a < b, "major takes precedence over minor in ordering");
}

#[test]
fn enrichment_pack_version_clone_and_copy() {
    let v = PackVersion { major: 5, minor: 3 };
    let cloned = v;
    assert_eq!(v, cloned);
}

// ===========================================================================
// InstructionCostClass enrichment tests
// ===========================================================================

#[test]
fn enrichment_instruction_cost_class_all_has_exactly_ten() {
    assert_eq!(InstructionCostClass::ALL.len(), 10);
}

#[test]
fn enrichment_instruction_cost_class_display_uniqueness() {
    let names: BTreeSet<String> = InstructionCostClass::ALL
        .iter()
        .map(|c| c.to_string())
        .collect();
    assert_eq!(names.len(), 10, "all Display strings must be unique");
}

#[test]
fn enrichment_instruction_cost_class_display_nonempty() {
    for class in InstructionCostClass::ALL {
        assert!(!class.to_string().is_empty());
    }
}

#[test]
fn enrichment_instruction_cost_class_serde_all_snake_case() {
    for class in InstructionCostClass::ALL {
        let json = serde_json::to_string(class).unwrap();
        // Verify JSON contains snake_case (no uppercase letters inside the string)
        let inner = json.trim_matches('"');
        assert!(
            inner.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "serde output for {:?} should be snake_case, got {}",
            class,
            json
        );
        // Roundtrip
        let back: InstructionCostClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*class, back);
    }
}

#[test]
fn enrichment_instruction_cost_class_btreeset_deterministic() {
    let set_a: BTreeSet<InstructionCostClass> = InstructionCostClass::ALL.iter().copied().collect();
    let set_b: BTreeSet<InstructionCostClass> =
        InstructionCostClass::ALL.iter().rev().copied().collect();
    assert_eq!(
        set_a, set_b,
        "BTreeSet order must be deterministic regardless of insertion order"
    );
}

// ===========================================================================
// DeterministicCostModel enrichment tests
// ===========================================================================

#[test]
fn enrichment_cost_model_new_computes_hash() {
    let model = DeterministicCostModel::new(
        "test-hash",
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    // Hash should be non-zero / not all zeros
    assert_ne!(model.content_hash, ContentHash::compute(b""));
}

#[test]
fn enrichment_cost_model_instruction_cost_present() {
    let mut costs = BTreeMap::new();
    costs.insert(InstructionCostClass::Allocation, 42 * MILLION);
    let model = DeterministicCostModel::new("present", costs, BTreeMap::new(), BTreeMap::new());
    assert_eq!(
        model.instruction_cost(InstructionCostClass::Allocation),
        42 * MILLION
    );
}

#[test]
fn enrichment_cost_model_instruction_cost_absent_returns_zero() {
    let model =
        DeterministicCostModel::new("absent", BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
    assert_eq!(model.instruction_cost(InstructionCostClass::Hostcall), 0);
    assert_eq!(model.instruction_cost(InstructionCostClass::ClosureOps), 0);
}

#[test]
fn enrichment_cost_model_rule_gain_present() {
    let mut gains = BTreeMap::new();
    gains.insert("fold-const".into(), 7 * MILLION);
    let model = DeterministicCostModel::new("gain", BTreeMap::new(), gains, BTreeMap::new());
    assert_eq!(model.rule_gain("fold-const"), 7 * MILLION);
}

#[test]
fn enrichment_cost_model_rule_gain_absent_returns_zero() {
    let model =
        DeterministicCostModel::new("no-gain", BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
    assert_eq!(model.rule_gain("nonexistent"), 0);
}

#[test]
fn enrichment_cost_model_net_gain_arithmetic() {
    let mut gains = BTreeMap::new();
    gains.insert("opt-a".into(), 10 * MILLION);
    let mut app_costs = BTreeMap::new();
    app_costs.insert("opt-a".into(), 3 * MILLION);
    let model = DeterministicCostModel::new("net", BTreeMap::new(), gains, app_costs);
    assert_eq!(model.net_gain("opt-a"), 7 * MILLION);
}

#[test]
fn enrichment_cost_model_net_gain_zero_when_equal() {
    let mut gains = BTreeMap::new();
    gains.insert("break-even".into(), 5 * MILLION);
    let mut app_costs = BTreeMap::new();
    app_costs.insert("break-even".into(), 5 * MILLION);
    let model = DeterministicCostModel::new("even", BTreeMap::new(), gains, app_costs);
    assert_eq!(model.net_gain("break-even"), 0);
}

#[test]
fn enrichment_cost_model_net_gain_missing_rule_returns_zero() {
    let model = DeterministicCostModel::default_baseline("missing-rule");
    assert_eq!(model.net_gain("does-not-exist"), 0);
}

#[test]
fn enrichment_cost_model_net_gain_only_gain_no_cost() {
    let mut gains = BTreeMap::new();
    gains.insert("free-opt".into(), 8 * MILLION);
    let model = DeterministicCostModel::new("free", BTreeMap::new(), gains, BTreeMap::new());
    assert_eq!(model.net_gain("free-opt"), 8 * MILLION);
}

#[test]
fn enrichment_cost_model_net_gain_only_cost_no_gain() {
    let mut app_costs = BTreeMap::new();
    app_costs.insert("costly".into(), 3 * MILLION);
    let model = DeterministicCostModel::new("costly", BTreeMap::new(), BTreeMap::new(), app_costs);
    // gain=0, cost=3M => 0 - 3M = -3M (saturating_sub for i64 is normal sub here)
    assert_eq!(model.net_gain("costly"), -3 * MILLION);
}

#[test]
fn enrichment_cost_model_hash_determinism_same_inputs() {
    let build = || {
        let mut costs = BTreeMap::new();
        costs.insert(InstructionCostClass::Arithmetic, MILLION);
        costs.insert(InstructionCostClass::Hostcall, 50 * MILLION);
        let mut gains = BTreeMap::new();
        gains.insert("r1".into(), 5 * MILLION);
        DeterministicCostModel::new("deterministic", costs, gains, BTreeMap::new())
    };
    assert_eq!(build().content_hash, build().content_hash);
}

#[test]
fn enrichment_cost_model_hash_differs_with_different_costs() {
    let mut costs_a = BTreeMap::new();
    costs_a.insert(InstructionCostClass::Arithmetic, MILLION);
    let mut costs_b = BTreeMap::new();
    costs_b.insert(InstructionCostClass::Arithmetic, 2 * MILLION);
    let m_a = DeterministicCostModel::new("same", costs_a, BTreeMap::new(), BTreeMap::new());
    let m_b = DeterministicCostModel::new("same", costs_b, BTreeMap::new(), BTreeMap::new());
    assert_ne!(m_a.content_hash, m_b.content_hash);
}

#[test]
fn enrichment_cost_model_default_baseline_schema() {
    let model = DeterministicCostModel::default_baseline("schema-check");
    assert_eq!(model.schema_version, COST_MODEL_SCHEMA_VERSION);
}

#[test]
fn enrichment_cost_model_serde_roundtrip_with_data() {
    let mut costs = BTreeMap::new();
    costs.insert(InstructionCostClass::ExceptionOps, 15 * MILLION);
    let mut gains = BTreeMap::new();
    gains.insert("dce".into(), 4 * MILLION);
    let mut app_costs = BTreeMap::new();
    app_costs.insert("dce".into(), MILLION);
    let model = DeterministicCostModel::new("serde-enrichment", costs, gains, app_costs);
    let json = serde_json::to_string(&model).unwrap();
    let back: DeterministicCostModel = serde_json::from_str(&json).unwrap();
    assert_eq!(model, back);
    assert_eq!(back.net_gain("dce"), 3 * MILLION);
}

// ===========================================================================
// RewriteRuleEntry enrichment tests
// ===========================================================================

#[test]
fn enrichment_rule_entry_serde_roundtrip() {
    let rule = make_rule_entry(
        "serde-enrichment",
        RewriteCategory::ReactRenderOptimization,
        true,
        true,
        &[
            InstructionCostClass::Allocation,
            InstructionCostClass::ClosureOps,
        ],
    );
    let json = serde_json::to_string(&rule).unwrap();
    let back: RewriteRuleEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, back);
}

#[test]
fn enrichment_rule_entry_multiple_cost_classes_preserved() {
    let rule = make_rule_entry(
        "multi-class",
        RewriteCategory::EffectHoisting,
        false,
        true,
        &[
            InstructionCostClass::Arithmetic,
            InstructionCostClass::Comparison,
            InstructionCostClass::ControlFlow,
            InstructionCostClass::PropertyAccess,
        ],
    );
    assert_eq!(rule.affected_cost_classes.len(), 4);
    assert!(
        rule.affected_cost_classes
            .contains(&InstructionCostClass::PropertyAccess)
    );
}

#[test]
fn enrichment_rule_entry_empty_cost_classes() {
    let rule = make_rule_entry("no-classes", RewriteCategory::Custom, true, true, &[]);
    assert!(rule.affected_cost_classes.is_empty());
}

// ===========================================================================
// RewriteCategory enrichment tests
// ===========================================================================

#[test]
fn enrichment_rewrite_category_serde_all_roundtrip() {
    let all = [
        RewriteCategory::AlgebraicSimplification,
        RewriteCategory::DeadCodeElimination,
        RewriteCategory::CommonSubexpression,
        RewriteCategory::PartialEvaluation,
        RewriteCategory::EffectHoisting,
        RewriteCategory::ShapeSpecialization,
        RewriteCategory::ReactRenderOptimization,
        RewriteCategory::StringFusion,
        RewriteCategory::ArrayOptimization,
        RewriteCategory::Custom,
    ];
    for cat in &all {
        let json = serde_json::to_string(cat).unwrap();
        let back: RewriteCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*cat, back);
    }
}

#[test]
fn enrichment_rewrite_category_display_uniqueness() {
    let displays: BTreeSet<String> = [
        RewriteCategory::AlgebraicSimplification,
        RewriteCategory::DeadCodeElimination,
        RewriteCategory::CommonSubexpression,
        RewriteCategory::PartialEvaluation,
        RewriteCategory::EffectHoisting,
        RewriteCategory::ShapeSpecialization,
        RewriteCategory::ReactRenderOptimization,
        RewriteCategory::StringFusion,
        RewriteCategory::ArrayOptimization,
        RewriteCategory::Custom,
    ]
    .iter()
    .map(|c| c.to_string())
    .collect();
    assert_eq!(
        displays.len(),
        10,
        "all 10 category Display strings must be unique"
    );
}

// ===========================================================================
// RuleInterferenceKind enrichment tests
// ===========================================================================

#[test]
fn enrichment_interference_kind_serde_roundtrip_all() {
    let all = [
        RuleInterferenceKind::None,
        RuleInterferenceKind::PatternConflict,
        RuleInterferenceKind::OrderDependent,
        RuleInterferenceKind::SemanticOverlap,
        RuleInterferenceKind::BudgetContention,
    ];
    for kind in &all {
        let json = serde_json::to_string(kind).unwrap();
        let back: RuleInterferenceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn enrichment_interference_kind_display_uniqueness() {
    let names: BTreeSet<String> = [
        RuleInterferenceKind::None,
        RuleInterferenceKind::PatternConflict,
        RuleInterferenceKind::OrderDependent,
        RuleInterferenceKind::SemanticOverlap,
        RuleInterferenceKind::BudgetContention,
    ]
    .iter()
    .map(|k| k.to_string())
    .collect();
    assert_eq!(
        names.len(),
        5,
        "all 5 interference kind Display strings must be unique"
    );
}

// ===========================================================================
// InterferenceMetadata enrichment tests
// ===========================================================================

#[test]
fn enrichment_interference_metadata_empty_is_clean() {
    let meta = empty_interference();
    assert!(meta.is_clean());
    assert!(!meta.has_blocking());
    assert_eq!(meta.blocking_count, 0);
    assert_eq!(meta.non_blocking_count, 0);
}

#[test]
fn enrichment_interference_metadata_mixed_blocking() {
    let entries = vec![
        interference("r1", "r2", RuleInterferenceKind::SemanticOverlap, true),
        interference("r3", "r4", RuleInterferenceKind::BudgetContention, false),
        interference("r5", "r6", RuleInterferenceKind::OrderDependent, true),
        interference("r7", "r8", RuleInterferenceKind::None, false),
    ];
    let meta = InterferenceMetadata::build(entries);
    assert!(meta.has_blocking());
    assert!(!meta.is_clean());
    assert_eq!(meta.blocking_count, 2);
    assert_eq!(meta.non_blocking_count, 2);
}

#[test]
fn enrichment_interference_metadata_for_rule_both_sides() {
    let entries = vec![
        interference(
            "alpha",
            "beta",
            RuleInterferenceKind::PatternConflict,
            false,
        ),
        interference("gamma", "alpha", RuleInterferenceKind::OrderDependent, true),
    ];
    let meta = InterferenceMetadata::build(entries);
    // alpha appears as rule_a in first and rule_b in second
    let alpha_entries = meta.for_rule("alpha");
    assert_eq!(alpha_entries.len(), 2);
}

#[test]
fn enrichment_interference_metadata_for_rule_no_match() {
    let entries = vec![interference("x", "y", RuleInterferenceKind::None, false)];
    let meta = InterferenceMetadata::build(entries);
    assert!(meta.for_rule("z").is_empty());
}

#[test]
fn enrichment_interference_metadata_hash_determinism() {
    let build = || {
        InterferenceMetadata::build(vec![
            interference("a", "b", RuleInterferenceKind::PatternConflict, false),
            interference("c", "d", RuleInterferenceKind::SemanticOverlap, true),
        ])
    };
    assert_eq!(build().content_hash, build().content_hash);
}

#[test]
fn enrichment_interference_metadata_hash_differs_on_kind_change() {
    let m1 = InterferenceMetadata::build(vec![interference(
        "a",
        "b",
        RuleInterferenceKind::PatternConflict,
        false,
    )]);
    let m2 = InterferenceMetadata::build(vec![interference(
        "a",
        "b",
        RuleInterferenceKind::OrderDependent,
        false,
    )]);
    assert_ne!(m1.content_hash, m2.content_hash);
}

#[test]
fn enrichment_interference_metadata_serde_roundtrip() {
    let meta = InterferenceMetadata::build(vec![
        interference("r1", "r2", RuleInterferenceKind::BudgetContention, false),
        interference("r3", "r4", RuleInterferenceKind::SemanticOverlap, true),
    ]);
    let json = serde_json::to_string(&meta).unwrap();
    let back: InterferenceMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(meta, back);
}

#[test]
fn enrichment_interference_metadata_schema_version() {
    let meta = empty_interference();
    assert_eq!(meta.schema_version, INTERFERENCE_SCHEMA_VERSION);
}

// ===========================================================================
// RewritePack enrichment tests
// ===========================================================================

#[test]
fn enrichment_rewrite_pack_construction_sets_fields() {
    let rules = vec![
        simple_rule("rule-a", RewriteCategory::AlgebraicSimplification),
        simple_rule("rule-b", RewriteCategory::DeadCodeElimination),
    ];
    let pack = default_pack("test-pack", rules);
    assert_eq!(pack.pack_id, "test-pack");
    assert_eq!(pack.version, PackVersion::CURRENT);
    assert_eq!(pack.epoch, epoch(100));
    assert_eq!(pack.schema_version, PACK_SCHEMA_VERSION);
    assert_eq!(pack.cost_model_id, "enrichment-cost-model");
}

#[test]
fn enrichment_rewrite_pack_rule_count() {
    let pack = default_pack(
        "count-test",
        vec![
            simple_rule("r1", RewriteCategory::Custom),
            simple_rule("r2", RewriteCategory::Custom),
            simple_rule("r3", RewriteCategory::Custom),
        ],
    );
    assert_eq!(pack.rule_count(), 3);
}

#[test]
fn enrichment_rewrite_pack_enabled_rules_count() {
    let rules = vec![
        simple_rule("e1", RewriteCategory::Custom),
        disabled_rule("d1", RewriteCategory::Custom),
        simple_rule("e2", RewriteCategory::Custom),
        disabled_rule("d2", RewriteCategory::Custom),
        disabled_rule("d3", RewriteCategory::Custom),
    ];
    let pack = default_pack("enabled-count", rules);
    assert_eq!(pack.rule_count(), 5);
    assert_eq!(pack.enabled_count(), 2);
}

#[test]
fn enrichment_rewrite_pack_empty_rules() {
    let pack = default_pack("empty-rules", vec![]);
    assert_eq!(pack.rule_count(), 0);
    assert_eq!(pack.enabled_count(), 0);
    assert_eq!(pack.soundness_rate_millionths(), 0);
    assert!(pack.categories.is_empty());
    assert_eq!(pack.proven_sound_count, 0);
}

#[test]
fn enrichment_rewrite_pack_rules_in_category_filtering() {
    let rules = vec![
        simple_rule("alg-1", RewriteCategory::AlgebraicSimplification),
        simple_rule("dce-1", RewriteCategory::DeadCodeElimination),
        simple_rule("alg-2", RewriteCategory::AlgebraicSimplification),
        simple_rule("cse-1", RewriteCategory::CommonSubexpression),
        simple_rule("alg-3", RewriteCategory::AlgebraicSimplification),
    ];
    let pack = default_pack("category-filter", rules);
    assert_eq!(
        pack.rules_in_category(RewriteCategory::AlgebraicSimplification)
            .len(),
        3
    );
    assert_eq!(
        pack.rules_in_category(RewriteCategory::DeadCodeElimination)
            .len(),
        1
    );
    assert_eq!(
        pack.rules_in_category(RewriteCategory::CommonSubexpression)
            .len(),
        1
    );
    assert_eq!(pack.rules_in_category(RewriteCategory::Custom).len(), 0);
}

#[test]
fn enrichment_rewrite_pack_rule_by_id_found_and_not_found() {
    let pack = default_pack(
        "by-id",
        vec![
            simple_rule("target", RewriteCategory::EffectHoisting),
            simple_rule("other", RewriteCategory::Custom),
        ],
    );
    let found = pack.rule_by_id("target").unwrap();
    assert_eq!(found.category, RewriteCategory::EffectHoisting);
    assert!(pack.rule_by_id("nonexistent").is_none());
}

#[test]
fn enrichment_rewrite_pack_verify_hash_fresh() {
    let pack = default_pack(
        "hash-fresh",
        vec![simple_rule("r1", RewriteCategory::Custom)],
    );
    // A fresh pack's content_hash should be non-trivial
    let zero_hash = ContentHash::compute(b"");
    assert_ne!(pack.content_hash, zero_hash);
}

#[test]
fn enrichment_rewrite_pack_hash_determinism() {
    let build = || {
        default_pack(
            "deterministic",
            vec![
                simple_rule("a", RewriteCategory::AlgebraicSimplification),
                simple_rule("b", RewriteCategory::DeadCodeElimination),
            ],
        )
    };
    assert_eq!(build().content_hash, build().content_hash);
}

#[test]
fn enrichment_rewrite_pack_hash_differs_with_different_id() {
    let p1 = default_pack("pack-alpha", vec![]);
    let p2 = default_pack("pack-beta", vec![]);
    assert_ne!(p1.content_hash, p2.content_hash);
}

#[test]
fn enrichment_rewrite_pack_hash_differs_with_different_rules() {
    let p1 = default_pack("same-id", vec![simple_rule("r1", RewriteCategory::Custom)]);
    let p2 = default_pack("same-id", vec![simple_rule("r2", RewriteCategory::Custom)]);
    assert_ne!(p1.content_hash, p2.content_hash);
}

#[test]
fn enrichment_rewrite_pack_hash_differs_with_different_epoch() {
    let p1 = RewritePack::new(
        "epoch-test",
        PackVersion::CURRENT,
        epoch(1),
        "test",
        vec![],
        empty_interference(),
        "model",
    );
    let p2 = RewritePack::new(
        "epoch-test",
        PackVersion::CURRENT,
        epoch(2),
        "test",
        vec![],
        empty_interference(),
        "model",
    );
    assert_ne!(p1.content_hash, p2.content_hash);
}

#[test]
fn enrichment_rewrite_pack_soundness_rate_half() {
    let rules = vec![
        simple_rule("sound-1", RewriteCategory::Custom), // proven_sound=true
        disabled_rule("unsound-1", RewriteCategory::Custom), // proven_sound=false
    ];
    let pack = default_pack("half-sound", rules);
    assert_eq!(pack.soundness_rate_millionths(), 500_000);
}

#[test]
fn enrichment_rewrite_pack_soundness_rate_one_of_three() {
    let rules = vec![
        simple_rule("s1", RewriteCategory::Custom),   // sound=true
        disabled_rule("u1", RewriteCategory::Custom), // sound=false
        disabled_rule("u2", RewriteCategory::Custom), // sound=false
    ];
    let pack = default_pack("one-third", rules);
    assert_eq!(pack.soundness_rate_millionths(), 333_333);
}

#[test]
fn enrichment_rewrite_pack_has_internal_blocking() {
    let meta = InterferenceMetadata::build(vec![interference(
        "r1",
        "r2",
        RuleInterferenceKind::SemanticOverlap,
        true,
    )]);
    let pack = build_pack_with_interference(
        "blocking-pack",
        vec![
            simple_rule("r1", RewriteCategory::Custom),
            simple_rule("r2", RewriteCategory::Custom),
        ],
        meta,
    );
    assert!(pack.has_internal_blocking());
}

#[test]
fn enrichment_rewrite_pack_no_internal_blocking_when_clean() {
    let pack = default_pack("clean", vec![simple_rule("r1", RewriteCategory::Custom)]);
    assert!(!pack.has_internal_blocking());
}

#[test]
fn enrichment_rewrite_pack_categories_auto_collected() {
    let rules = vec![
        simple_rule("a", RewriteCategory::StringFusion),
        simple_rule("b", RewriteCategory::ArrayOptimization),
        simple_rule("c", RewriteCategory::StringFusion), // duplicate category
    ];
    let pack = default_pack("auto-cats", rules);
    assert_eq!(pack.categories.len(), 2);
    assert!(pack.categories.contains(&RewriteCategory::StringFusion));
    assert!(
        pack.categories
            .contains(&RewriteCategory::ArrayOptimization)
    );
}

#[test]
fn enrichment_rewrite_pack_serde_roundtrip() {
    let meta = InterferenceMetadata::build(vec![interference(
        "r1",
        "r2",
        RuleInterferenceKind::PatternConflict,
        false,
    )]);
    let pack = RewritePack::new(
        "serde-enrichment",
        PackVersion { major: 2, minor: 5 },
        epoch(77),
        "roundtrip test",
        vec![
            simple_rule("r1", RewriteCategory::PartialEvaluation),
            simple_rule("r2", RewriteCategory::ShapeSpecialization),
        ],
        meta,
        "cost-model-x",
    );
    let json = serde_json::to_string(&pack).unwrap();
    let back: RewritePack = serde_json::from_str(&json).unwrap();
    assert_eq!(pack, back);
}

// ===========================================================================
// PackCatalog enrichment tests
// ===========================================================================

#[test]
fn enrichment_catalog_new_empty() {
    let cat = PackCatalog::new("enrichment-catalog");
    assert_eq!(cat.catalog_id, "enrichment-catalog");
    assert_eq!(cat.schema_version, CATALOG_SCHEMA_VERSION);
    assert_eq!(cat.pack_count(), 0);
    assert_eq!(cat.total_rule_count, 0);
}

#[test]
fn enrichment_catalog_register_and_lookup() {
    let mut cat = PackCatalog::new("reg-lookup");
    let pack = default_pack("my-pack", vec![simple_rule("r1", RewriteCategory::Custom)]);
    assert!(cat.register(pack));
    assert_eq!(cat.pack_count(), 1);
    let found = cat.get("my-pack").unwrap();
    assert_eq!(found.pack_id, "my-pack");
    assert_eq!(found.rule_count(), 1);
}

#[test]
fn enrichment_catalog_lookup_missing_returns_none() {
    let cat = PackCatalog::new("empty");
    assert!(cat.get("nonexistent").is_none());
}

#[test]
fn enrichment_catalog_register_duplicate_returns_false() {
    let mut cat = PackCatalog::new("dup-test");
    assert!(cat.register(default_pack("dup-id", vec![])));
    assert!(!cat.register(default_pack("dup-id", vec![])));
    assert_eq!(cat.pack_count(), 1);
}

#[test]
fn enrichment_catalog_compatible_packs_filtering() {
    let mut cat = PackCatalog::new("compat-filter");
    cat.register(build_pack(
        "v1_0",
        PackVersion { major: 1, minor: 0 },
        vec![],
    ));
    cat.register(build_pack(
        "v1_3",
        PackVersion { major: 1, minor: 3 },
        vec![],
    ));
    cat.register(build_pack(
        "v1_5",
        PackVersion { major: 1, minor: 5 },
        vec![],
    ));
    cat.register(build_pack(
        "v2_0",
        PackVersion { major: 2, minor: 0 },
        vec![],
    ));

    let host = PackVersion { major: 1, minor: 3 };
    let compat = cat.compatible_packs(&host);
    let ids: BTreeSet<&str> = compat.iter().map(|p| p.pack_id.as_str()).collect();
    assert!(
        ids.contains("v1_0"),
        "v1.0 should be compatible with host 1.3"
    );
    assert!(
        ids.contains("v1_3"),
        "v1.3 should be compatible with host 1.3"
    );
    assert!(
        !ids.contains("v1_5"),
        "v1.5 should NOT be compatible with host 1.3"
    );
    assert!(
        !ids.contains("v2_0"),
        "v2.0 should NOT be compatible with host 1.3"
    );
    assert_eq!(compat.len(), 2);
}

#[test]
fn enrichment_catalog_compatible_packs_none_match() {
    let mut cat = PackCatalog::new("no-match");
    cat.register(build_pack("v3", PackVersion { major: 3, minor: 0 }, vec![]));
    let host = PackVersion { major: 1, minor: 0 };
    assert!(cat.compatible_packs(&host).is_empty());
}

#[test]
fn enrichment_catalog_pack_count_tracks_registrations() {
    let mut cat = PackCatalog::new("count-track");
    for i in 0..10 {
        cat.register(default_pack(
            &format!("pack-{i}"),
            vec![simple_rule(&format!("r-{i}"), RewriteCategory::Custom)],
        ));
    }
    assert_eq!(cat.pack_count(), 10);
    assert_eq!(cat.total_rule_count, 10);
}

#[test]
fn enrichment_catalog_total_rule_count_accumulated() {
    let mut cat = PackCatalog::new("total-rules");
    cat.register(default_pack(
        "p1",
        vec![
            simple_rule("r1", RewriteCategory::Custom),
            simple_rule("r2", RewriteCategory::Custom),
        ],
    ));
    cat.register(default_pack(
        "p2",
        vec![simple_rule("r3", RewriteCategory::Custom)],
    ));
    cat.register(default_pack("p3", vec![])); // zero rules
    assert_eq!(cat.total_rule_count, 3);
}

#[test]
fn enrichment_catalog_cross_interference_symmetric_lookup() {
    let mut cat = PackCatalog::new("cross-sym");
    cat.register(default_pack("pack-a", vec![]));
    cat.register(default_pack("pack-b", vec![]));

    let meta = InterferenceMetadata::build(vec![interference(
        "a:r1",
        "b:r1",
        RuleInterferenceKind::SemanticOverlap,
        true,
    )]);
    cat.add_cross_interference("pack-a", "pack-b", meta);

    // Both orderings should work
    assert!(cat.has_cross_blocking("pack-a", "pack-b"));
    assert!(cat.has_cross_blocking("pack-b", "pack-a"));
}

#[test]
fn enrichment_catalog_cross_interference_no_blocking() {
    let mut cat = PackCatalog::new("no-cross-block");
    cat.register(default_pack("x", vec![]));
    cat.register(default_pack("y", vec![]));

    let meta = InterferenceMetadata::build(vec![interference(
        "x:r1",
        "y:r1",
        RuleInterferenceKind::BudgetContention,
        false,
    )]);
    cat.add_cross_interference("x", "y", meta);
    assert!(!cat.has_cross_blocking("x", "y"));
}

#[test]
fn enrichment_catalog_cross_interference_unknown_pair() {
    let cat = PackCatalog::new("unknown-pair");
    assert!(!cat.has_cross_blocking("nonexistent-a", "nonexistent-b"));
}

#[test]
fn enrichment_catalog_hash_changes_on_register() {
    let mut cat = PackCatalog::new("hash-on-reg");
    let hash_before = cat.content_hash;
    cat.register(default_pack("new-pack", vec![]));
    assert_ne!(cat.content_hash, hash_before);
}

#[test]
fn enrichment_catalog_hash_changes_on_cross_interference() {
    let mut cat = PackCatalog::new("hash-on-cross");
    cat.register(default_pack("a", vec![]));
    cat.register(default_pack("b", vec![]));
    let hash_before = cat.content_hash;
    cat.add_cross_interference("a", "b", empty_interference());
    assert_ne!(cat.content_hash, hash_before);
}

#[test]
fn enrichment_catalog_serde_roundtrip_populated() {
    let mut cat = PackCatalog::new("serde-pop");
    cat.register(default_pack(
        "p1",
        vec![simple_rule("r1", RewriteCategory::AlgebraicSimplification)],
    ));
    cat.register(default_pack(
        "p2",
        vec![simple_rule("r2", RewriteCategory::DeadCodeElimination)],
    ));
    cat.add_cross_interference(
        "p1",
        "p2",
        InterferenceMetadata::build(vec![interference(
            "p1:r1",
            "p2:r2",
            RuleInterferenceKind::PatternConflict,
            false,
        )]),
    );
    let json = serde_json::to_string(&cat).unwrap();
    let back: PackCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(cat, back);
}

// ===========================================================================
// Constants enrichment tests
// ===========================================================================

#[test]
fn enrichment_constants_non_empty_and_formatted() {
    assert!(!COMPONENT.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(PACK_SCHEMA_VERSION.contains("versioned-rewrite-pack"));
    assert!(CATALOG_SCHEMA_VERSION.contains("rewrite-pack-catalog"));
    assert!(COST_MODEL_SCHEMA_VERSION.contains("deterministic-cost-model"));
    assert!(INTERFERENCE_SCHEMA_VERSION.contains("rewrite-interference"));
}

#[test]
fn enrichment_constants_max_rules_per_pack() {
    assert_eq!(MAX_RULES_PER_PACK, 256);
}

#[test]
fn enrichment_constants_max_interference_entries() {
    assert_eq!(MAX_INTERFERENCE_ENTRIES, 1024);
}

// ===========================================================================
// Cross-cutting edge-case enrichment tests
// ===========================================================================

#[test]
fn enrichment_empty_catalog_compatible_packs_returns_empty() {
    let cat = PackCatalog::new("empty");
    let compat = cat.compatible_packs(&PackVersion::CURRENT);
    assert!(compat.is_empty());
}

#[test]
fn enrichment_cost_model_zero_cost_entries() {
    let mut costs = BTreeMap::new();
    costs.insert(InstructionCostClass::Arithmetic, 0);
    costs.insert(InstructionCostClass::Hostcall, 0);
    let model = DeterministicCostModel::new("zero-costs", costs, BTreeMap::new(), BTreeMap::new());
    assert_eq!(model.instruction_cost(InstructionCostClass::Arithmetic), 0);
    assert_eq!(model.instruction_cost(InstructionCostClass::Hostcall), 0);
}

#[test]
fn enrichment_pack_all_disabled_rules() {
    let rules = vec![
        disabled_rule("d1", RewriteCategory::Custom),
        disabled_rule("d2", RewriteCategory::Custom),
        disabled_rule("d3", RewriteCategory::Custom),
    ];
    let pack = default_pack("all-disabled", rules);
    assert_eq!(pack.rule_count(), 3);
    assert_eq!(pack.enabled_count(), 0);
}

#[test]
fn enrichment_interference_all_blocking() {
    let entries = vec![
        interference("a", "b", RuleInterferenceKind::SemanticOverlap, true),
        interference("c", "d", RuleInterferenceKind::OrderDependent, true),
        interference("e", "f", RuleInterferenceKind::PatternConflict, true),
    ];
    let meta = InterferenceMetadata::build(entries);
    assert!(meta.has_blocking());
    assert_eq!(meta.blocking_count, 3);
    assert_eq!(meta.non_blocking_count, 0);
}

#[test]
fn enrichment_catalog_deterministic_hash_on_same_construction() {
    let build = || {
        let mut cat = PackCatalog::new("det-cat");
        cat.register(default_pack(
            "p1",
            vec![simple_rule("r1", RewriteCategory::Custom)],
        ));
        cat
    };
    assert_eq!(build().content_hash, build().content_hash);
}

#[test]
fn enrichment_pack_version_hash_as_part_of_pack_hash() {
    let p1 = build_pack("same-id", PackVersion { major: 1, minor: 0 }, vec![]);
    let p2 = build_pack("same-id", PackVersion { major: 1, minor: 1 }, vec![]);
    assert_ne!(
        p1.content_hash, p2.content_hash,
        "different pack versions should yield different content hashes"
    );
}

#[test]
fn enrichment_rule_interference_serde_roundtrip() {
    let ri = interference(
        "rule-x",
        "rule-y",
        RuleInterferenceKind::BudgetContention,
        false,
    );
    let json = serde_json::to_string(&ri).unwrap();
    let back: RuleInterference = serde_json::from_str(&json).unwrap();
    assert_eq!(ri, back);
}

#[test]
fn enrichment_cost_model_multiple_rules_net_gain() {
    let mut gains = BTreeMap::new();
    gains.insert("opt-a".into(), 10 * MILLION);
    gains.insert("opt-b".into(), 3 * MILLION);
    gains.insert("opt-c".into(), 0_i64);
    let mut app_costs = BTreeMap::new();
    app_costs.insert("opt-a".into(), 2 * MILLION);
    app_costs.insert("opt-b".into(), 3 * MILLION);
    app_costs.insert("opt-c".into(), MILLION);
    let model = DeterministicCostModel::new("multi-rule", BTreeMap::new(), gains, app_costs);
    assert_eq!(model.net_gain("opt-a"), 8 * MILLION);
    assert_eq!(model.net_gain("opt-b"), 0);
    assert_eq!(model.net_gain("opt-c"), -MILLION);
    assert_eq!(model.net_gain("opt-d"), 0); // missing
}

#[test]
fn enrichment_pack_proven_sound_count_mixed() {
    let rules = vec![
        make_rule_entry(
            "s1",
            RewriteCategory::Custom,
            true,
            true,
            &[InstructionCostClass::Arithmetic],
        ),
        make_rule_entry(
            "s2",
            RewriteCategory::Custom,
            true,
            false,
            &[InstructionCostClass::Arithmetic],
        ),
        make_rule_entry(
            "u1",
            RewriteCategory::Custom,
            false,
            true,
            &[InstructionCostClass::Arithmetic],
        ),
        make_rule_entry(
            "u2",
            RewriteCategory::Custom,
            false,
            false,
            &[InstructionCostClass::Arithmetic],
        ),
    ];
    let pack = default_pack("mixed-sound", rules);
    assert_eq!(pack.proven_sound_count, 2);
    // 2 out of 4 = 500_000 millionths
    assert_eq!(pack.soundness_rate_millionths(), 500_000);
}

#[test]
fn enrichment_catalog_multiple_cross_interferences() {
    let mut cat = PackCatalog::new("multi-cross");
    cat.register(default_pack("a", vec![]));
    cat.register(default_pack("b", vec![]));
    cat.register(default_pack("c", vec![]));

    // a<->b blocking
    cat.add_cross_interference(
        "a",
        "b",
        InterferenceMetadata::build(vec![interference(
            "a:r1",
            "b:r1",
            RuleInterferenceKind::SemanticOverlap,
            true,
        )]),
    );
    // b<->c non-blocking
    cat.add_cross_interference(
        "b",
        "c",
        InterferenceMetadata::build(vec![interference(
            "b:r1",
            "c:r1",
            RuleInterferenceKind::BudgetContention,
            false,
        )]),
    );

    assert!(cat.has_cross_blocking("a", "b"));
    assert!(!cat.has_cross_blocking("b", "c"));
    assert!(!cat.has_cross_blocking("a", "c")); // no entry at all
}
