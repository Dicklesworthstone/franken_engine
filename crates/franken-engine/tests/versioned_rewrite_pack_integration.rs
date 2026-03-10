//! Integration tests for the versioned_rewrite_pack module (RGC-607A).
//!
//! Tests cover PackVersion, InstructionCostClass, DeterministicCostModel,
//! RewriteCategory, RewriteRuleEntry, RuleInterferenceKind, RuleInterference,
//! InterferenceMetadata, RewritePack, and PackCatalog.

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
// Helpers
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn make_rule(id: &str, category: RewriteCategory, sound: bool, enabled: bool) -> RewriteRuleEntry {
    RewriteRuleEntry {
        rule_id: id.into(),
        category,
        description: format!("integration test rule {id}"),
        pattern_hash: ContentHash::compute(format!("pattern:{id}").as_bytes()),
        replacement_hash: ContentHash::compute(format!("replacement:{id}").as_bytes()),
        proven_sound: sound,
        priority_millionths: MILLION,
        affected_cost_classes: BTreeSet::from([InstructionCostClass::Arithmetic]),
        enabled,
    }
}

fn enabled_rule(id: &str, category: RewriteCategory, sound: bool) -> RewriteRuleEntry {
    make_rule(id, category, sound, true)
}

fn make_interference(
    a: &str,
    b: &str,
    kind: RuleInterferenceKind,
    blocking: bool,
) -> RuleInterference {
    RuleInterference {
        rule_a: a.into(),
        rule_b: b.into(),
        kind,
        is_blocking: blocking,
        detail: format!("{a} <-> {b}"),
    }
}

fn empty_interference() -> InterferenceMetadata {
    InterferenceMetadata::build(vec![])
}

fn make_pack(id: &str, rules: Vec<RewriteRuleEntry>) -> RewritePack {
    RewritePack::new(
        id,
        PackVersion::CURRENT,
        test_epoch(),
        &format!("pack {id}"),
        rules,
        empty_interference(),
        "baseline-cost-model",
    )
}

fn make_versioned_pack(
    id: &str,
    version: PackVersion,
    rules: Vec<RewriteRuleEntry>,
) -> RewritePack {
    RewritePack::new(
        id,
        version,
        test_epoch(),
        &format!("versioned pack {id}"),
        rules,
        empty_interference(),
        "baseline-cost-model",
    )
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_are_nonempty() {
    assert!(!COMPONENT.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(!PACK_SCHEMA_VERSION.is_empty());
    assert!(!CATALOG_SCHEMA_VERSION.is_empty());
    assert!(!COST_MODEL_SCHEMA_VERSION.is_empty());
    assert!(!INTERFERENCE_SCHEMA_VERSION.is_empty());
}

#[test]
fn max_limits_are_positive() {
    assert!(MAX_RULES_PER_PACK > 0);
    assert!(MAX_INTERFERENCE_ENTRIES > 0);
}

// ---------------------------------------------------------------------------
// PackVersion
// ---------------------------------------------------------------------------

#[test]
fn pack_version_display_format() {
    assert_eq!(PackVersion::CURRENT.to_string(), "1.0");
    let v = PackVersion {
        major: 3,
        minor: 14,
    };
    assert_eq!(v.to_string(), "3.14");
}

#[test]
fn pack_version_compatibility_same_major_lower_minor() {
    let host = PackVersion { major: 2, minor: 5 };
    assert!(host.is_compatible_with(&PackVersion { major: 2, minor: 0 }));
    assert!(host.is_compatible_with(&PackVersion { major: 2, minor: 5 }));
}

#[test]
fn pack_version_incompatible_higher_minor() {
    let host = PackVersion { major: 2, minor: 5 };
    assert!(!host.is_compatible_with(&PackVersion { major: 2, minor: 6 }));
}

#[test]
fn pack_version_incompatible_different_major() {
    let host = PackVersion {
        major: 1,
        minor: 99,
    };
    assert!(!host.is_compatible_with(&PackVersion { major: 2, minor: 0 }));
    assert!(!host.is_compatible_with(&PackVersion { major: 0, minor: 0 }));
}

#[test]
fn pack_version_serde_roundtrip() {
    let v = PackVersion {
        major: 7,
        minor: 42,
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: PackVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn pack_version_ordering() {
    let versions = [
        PackVersion { major: 0, minor: 0 },
        PackVersion { major: 0, minor: 1 },
        PackVersion { major: 1, minor: 0 },
        PackVersion { major: 1, minor: 1 },
        PackVersion { major: 2, minor: 0 },
    ];
    for pair in versions.windows(2) {
        assert!(pair[0] < pair[1], "{} should be < {}", pair[0], pair[1]);
    }
}

#[test]
fn pack_version_zero_zero() {
    let v = PackVersion { major: 0, minor: 0 };
    assert_eq!(v.to_string(), "0.0");
    assert!(v.is_compatible_with(&v));
}

// ---------------------------------------------------------------------------
// InstructionCostClass
// ---------------------------------------------------------------------------

#[test]
fn instruction_cost_class_all_has_ten_variants() {
    assert_eq!(InstructionCostClass::ALL.len(), 10);
}

#[test]
fn instruction_cost_class_all_unique() {
    let set: BTreeSet<_> = InstructionCostClass::ALL.iter().collect();
    assert_eq!(set.len(), InstructionCostClass::ALL.len());
}

#[test]
fn instruction_cost_class_display_all_variants() {
    let expected = [
        (InstructionCostClass::Arithmetic, "arithmetic"),
        (InstructionCostClass::Comparison, "comparison"),
        (InstructionCostClass::Bitwise, "bitwise"),
        (InstructionCostClass::PropertyAccess, "property_access"),
        (InstructionCostClass::ControlFlow, "control_flow"),
        (InstructionCostClass::Allocation, "allocation"),
        (InstructionCostClass::Hostcall, "hostcall"),
        (InstructionCostClass::ClosureOps, "closure_ops"),
        (InstructionCostClass::ModuleOps, "module_ops"),
        (InstructionCostClass::ExceptionOps, "exception_ops"),
    ];
    for (variant, text) in &expected {
        assert_eq!(variant.to_string(), *text);
    }
}

#[test]
fn instruction_cost_class_serde_roundtrip_all() {
    for class in InstructionCostClass::ALL {
        let json = serde_json::to_string(class).unwrap();
        let back: InstructionCostClass = serde_json::from_str(&json).unwrap();
        assert_eq!(*class, back);
    }
}

#[test]
fn instruction_cost_class_serde_uses_snake_case() {
    let json = serde_json::to_string(&InstructionCostClass::PropertyAccess).unwrap();
    assert_eq!(json, "\"property_access\"");
}

// ---------------------------------------------------------------------------
// RewriteCategory
// ---------------------------------------------------------------------------

#[test]
fn rewrite_category_display_all_variants() {
    let expected = [
        (
            RewriteCategory::AlgebraicSimplification,
            "algebraic_simplification",
        ),
        (
            RewriteCategory::DeadCodeElimination,
            "dead_code_elimination",
        ),
        (RewriteCategory::CommonSubexpression, "common_subexpression"),
        (RewriteCategory::PartialEvaluation, "partial_evaluation"),
        (RewriteCategory::EffectHoisting, "effect_hoisting"),
        (RewriteCategory::ShapeSpecialization, "shape_specialization"),
        (
            RewriteCategory::ReactRenderOptimization,
            "react_render_optimization",
        ),
        (RewriteCategory::StringFusion, "string_fusion"),
        (RewriteCategory::ArrayOptimization, "array_optimization"),
        (RewriteCategory::Custom, "custom"),
    ];
    for (variant, text) in &expected {
        assert_eq!(variant.to_string(), *text);
    }
}

#[test]
fn rewrite_category_serde_roundtrip_all() {
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

// ---------------------------------------------------------------------------
// RuleInterferenceKind
// ---------------------------------------------------------------------------

#[test]
fn rule_interference_kind_display_all() {
    let expected = [
        (RuleInterferenceKind::None, "none"),
        (RuleInterferenceKind::PatternConflict, "pattern_conflict"),
        (RuleInterferenceKind::OrderDependent, "order_dependent"),
        (RuleInterferenceKind::SemanticOverlap, "semantic_overlap"),
        (RuleInterferenceKind::BudgetContention, "budget_contention"),
    ];
    for (variant, text) in &expected {
        assert_eq!(variant.to_string(), *text);
    }
}

#[test]
fn rule_interference_kind_serde_roundtrip_all() {
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

// ---------------------------------------------------------------------------
// RuleInterference
// ---------------------------------------------------------------------------

#[test]
fn rule_interference_serde_roundtrip() {
    let ri = make_interference("alpha", "beta", RuleInterferenceKind::OrderDependent, true);
    let json = serde_json::to_string(&ri).unwrap();
    let back: RuleInterference = serde_json::from_str(&json).unwrap();
    assert_eq!(ri, back);
}

#[test]
fn rule_interference_fields() {
    let ri = make_interference("r1", "r2", RuleInterferenceKind::BudgetContention, false);
    assert_eq!(ri.rule_a, "r1");
    assert_eq!(ri.rule_b, "r2");
    assert_eq!(ri.kind, RuleInterferenceKind::BudgetContention);
    assert!(!ri.is_blocking);
}

// ---------------------------------------------------------------------------
// DeterministicCostModel
// ---------------------------------------------------------------------------

#[test]
fn cost_model_baseline_schema_version() {
    let model = DeterministicCostModel::default_baseline("b1");
    assert_eq!(model.schema_version, COST_MODEL_SCHEMA_VERSION);
    assert_eq!(model.model_id, "b1");
}

#[test]
fn cost_model_baseline_all_classes_populated() {
    let model = DeterministicCostModel::default_baseline("all-classes");
    for class in InstructionCostClass::ALL {
        assert!(
            model.instruction_cost(*class) > 0,
            "class {:?} should have positive cost",
            class
        );
    }
}

#[test]
fn cost_model_baseline_ordering() {
    let model = DeterministicCostModel::default_baseline("ordering");
    // Hostcall should be most expensive, bitwise cheapest
    assert!(
        model.instruction_cost(InstructionCostClass::Hostcall)
            > model.instruction_cost(InstructionCostClass::Arithmetic)
    );
    assert!(
        model.instruction_cost(InstructionCostClass::Bitwise)
            < model.instruction_cost(InstructionCostClass::Arithmetic)
    );
}

#[test]
fn cost_model_missing_instruction_returns_zero() {
    let model =
        DeterministicCostModel::new("empty", BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
    for class in InstructionCostClass::ALL {
        assert_eq!(model.instruction_cost(*class), 0);
    }
}

#[test]
fn cost_model_net_gain_positive() {
    let mut gains = BTreeMap::new();
    gains.insert("fold".into(), 10 * MILLION);
    let mut app_costs = BTreeMap::new();
    app_costs.insert("fold".into(), 3 * MILLION);
    let model = DeterministicCostModel::new("net", BTreeMap::new(), gains, app_costs);
    assert_eq!(model.net_gain("fold"), 7 * MILLION);
}

#[test]
fn cost_model_net_gain_negative() {
    let mut gains = BTreeMap::new();
    gains.insert("expensive".into(), 1 * MILLION);
    let mut app_costs = BTreeMap::new();
    app_costs.insert("expensive".into(), 5 * MILLION);
    let model = DeterministicCostModel::new("neg", BTreeMap::new(), gains, app_costs);
    // gain - cost = 1M - 5M, but saturating_sub floors at min i64 negative
    // Actually for i64, saturating_sub just does normal subtraction unless overflow
    assert_eq!(model.net_gain("expensive"), -4 * MILLION);
}

#[test]
fn cost_model_net_gain_missing_rule() {
    let model = DeterministicCostModel::default_baseline("missing");
    assert_eq!(model.net_gain("no-such-rule"), 0);
}

#[test]
fn cost_model_rule_gain_missing_returns_zero() {
    let model = DeterministicCostModel::default_baseline("rg");
    assert_eq!(model.rule_gain("nonexistent"), 0);
}

#[test]
fn cost_model_deterministic_hash_same_inputs() {
    let m1 = DeterministicCostModel::default_baseline("det");
    let m2 = DeterministicCostModel::default_baseline("det");
    assert_eq!(m1.content_hash, m2.content_hash);
}

#[test]
fn cost_model_different_id_different_hash() {
    let m1 = DeterministicCostModel::default_baseline("id-a");
    let m2 = DeterministicCostModel::default_baseline("id-b");
    assert_ne!(m1.content_hash, m2.content_hash);
}

#[test]
fn cost_model_serde_roundtrip() {
    let mut gains = BTreeMap::new();
    gains.insert("r1".into(), 5 * MILLION);
    gains.insert("r2".into(), 2 * MILLION);
    let mut app_costs = BTreeMap::new();
    app_costs.insert("r1".into(), MILLION);
    let model = DeterministicCostModel::new("serde-test", BTreeMap::new(), gains, app_costs);
    let json = serde_json::to_string(&model).unwrap();
    let back: DeterministicCostModel = serde_json::from_str(&json).unwrap();
    assert_eq!(model, back);
}

#[test]
fn cost_model_custom_instruction_costs() {
    let mut costs = BTreeMap::new();
    costs.insert(InstructionCostClass::Arithmetic, 42 * MILLION);
    costs.insert(InstructionCostClass::Hostcall, 100 * MILLION);
    let model = DeterministicCostModel::new("custom", costs, BTreeMap::new(), BTreeMap::new());
    assert_eq!(
        model.instruction_cost(InstructionCostClass::Arithmetic),
        42 * MILLION
    );
    assert_eq!(
        model.instruction_cost(InstructionCostClass::Hostcall),
        100 * MILLION
    );
    assert_eq!(model.instruction_cost(InstructionCostClass::Bitwise), 0);
}

// ---------------------------------------------------------------------------
// RewriteRuleEntry
// ---------------------------------------------------------------------------

#[test]
fn rule_entry_serde_roundtrip() {
    let rule = enabled_rule("test-rule", RewriteCategory::StringFusion, true);
    let json = serde_json::to_string(&rule).unwrap();
    let back: RewriteRuleEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, back);
}

#[test]
fn rule_entry_disabled() {
    let rule = make_rule("disabled-rule", RewriteCategory::Custom, false, false);
    assert!(!rule.enabled);
    assert!(!rule.proven_sound);
}

#[test]
fn rule_entry_multiple_cost_classes() {
    let mut rule = enabled_rule("multi-class", RewriteCategory::EffectHoisting, true);
    rule.affected_cost_classes = BTreeSet::from([
        InstructionCostClass::Arithmetic,
        InstructionCostClass::Allocation,
        InstructionCostClass::ControlFlow,
    ]);
    assert_eq!(rule.affected_cost_classes.len(), 3);
    let json = serde_json::to_string(&rule).unwrap();
    let back: RewriteRuleEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, back);
}

// ---------------------------------------------------------------------------
// InterferenceMetadata
// ---------------------------------------------------------------------------

#[test]
fn interference_metadata_empty_is_clean() {
    let meta = empty_interference();
    assert!(meta.is_clean());
    assert!(!meta.has_blocking());
    assert_eq!(meta.blocking_count, 0);
    assert_eq!(meta.non_blocking_count, 0);
    assert_eq!(meta.schema_version, INTERFERENCE_SCHEMA_VERSION);
}

#[test]
fn interference_metadata_blocking_count() {
    let entries = vec![
        make_interference("a", "b", RuleInterferenceKind::SemanticOverlap, true),
        make_interference("c", "d", RuleInterferenceKind::PatternConflict, false),
        make_interference("e", "f", RuleInterferenceKind::OrderDependent, true),
    ];
    let meta = InterferenceMetadata::build(entries);
    assert!(meta.has_blocking());
    assert_eq!(meta.blocking_count, 2);
    assert_eq!(meta.non_blocking_count, 1);
}

#[test]
fn interference_metadata_for_rule_filters_correctly() {
    let entries = vec![
        make_interference("r1", "r2", RuleInterferenceKind::PatternConflict, false),
        make_interference("r2", "r3", RuleInterferenceKind::OrderDependent, false),
        make_interference("r4", "r5", RuleInterferenceKind::BudgetContention, false),
    ];
    let meta = InterferenceMetadata::build(entries);
    // r2 appears in two entries (as rule_a and rule_b)
    assert_eq!(meta.for_rule("r2").len(), 2);
    assert_eq!(meta.for_rule("r1").len(), 1);
    assert_eq!(meta.for_rule("r4").len(), 1);
    assert_eq!(meta.for_rule("nonexistent").len(), 0);
}

#[test]
fn interference_metadata_deterministic_hash() {
    let build = || {
        InterferenceMetadata::build(vec![
            make_interference("x", "y", RuleInterferenceKind::PatternConflict, false),
            make_interference("a", "b", RuleInterferenceKind::SemanticOverlap, true),
        ])
    };
    let m1 = build();
    let m2 = build();
    assert_eq!(m1.content_hash, m2.content_hash);
}

#[test]
fn interference_metadata_different_entries_different_hash() {
    let m1 = InterferenceMetadata::build(vec![make_interference(
        "x",
        "y",
        RuleInterferenceKind::PatternConflict,
        false,
    )]);
    let m2 = InterferenceMetadata::build(vec![make_interference(
        "a",
        "b",
        RuleInterferenceKind::PatternConflict,
        false,
    )]);
    assert_ne!(m1.content_hash, m2.content_hash);
}

#[test]
fn interference_metadata_serde_roundtrip() {
    let meta = InterferenceMetadata::build(vec![
        make_interference("r1", "r2", RuleInterferenceKind::OrderDependent, true),
        make_interference("r3", "r4", RuleInterferenceKind::None, false),
    ]);
    let json = serde_json::to_string(&meta).unwrap();
    let back: InterferenceMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(meta, back);
}

#[test]
fn interference_metadata_all_non_blocking() {
    let entries = vec![
        make_interference("a", "b", RuleInterferenceKind::BudgetContention, false),
        make_interference("c", "d", RuleInterferenceKind::PatternConflict, false),
    ];
    let meta = InterferenceMetadata::build(entries);
    assert!(!meta.has_blocking());
    assert!(!meta.is_clean()); // entries exist
    assert_eq!(meta.blocking_count, 0);
    assert_eq!(meta.non_blocking_count, 2);
}

// ---------------------------------------------------------------------------
// RewritePack
// ---------------------------------------------------------------------------

#[test]
fn pack_schema_version() {
    let pack = make_pack("schema-check", vec![]);
    assert_eq!(pack.schema_version, PACK_SCHEMA_VERSION);
}

#[test]
fn pack_empty_counts() {
    let pack = make_pack("empty", vec![]);
    assert_eq!(pack.rule_count(), 0);
    assert_eq!(pack.enabled_count(), 0);
    assert_eq!(pack.proven_sound_count, 0);
    assert_eq!(pack.soundness_rate_millionths(), 0);
    assert!(pack.categories.is_empty());
}

#[test]
fn pack_rule_count_and_enabled_count() {
    let rules = vec![
        make_rule("r1", RewriteCategory::Custom, true, true),
        make_rule("r2", RewriteCategory::Custom, false, false),
        make_rule("r3", RewriteCategory::Custom, true, true),
    ];
    let pack = make_pack("counts", rules);
    assert_eq!(pack.rule_count(), 3);
    assert_eq!(pack.enabled_count(), 2);
    assert_eq!(pack.proven_sound_count, 2);
}

#[test]
fn pack_soundness_rate_all_sound() {
    let rules = vec![
        enabled_rule("s1", RewriteCategory::Custom, true),
        enabled_rule("s2", RewriteCategory::Custom, true),
        enabled_rule("s3", RewriteCategory::Custom, true),
    ];
    let pack = make_pack("all-sound", rules);
    assert_eq!(pack.soundness_rate_millionths(), MILLION);
}

#[test]
fn pack_soundness_rate_none_sound() {
    let rules = vec![
        enabled_rule("u1", RewriteCategory::Custom, false),
        enabled_rule("u2", RewriteCategory::Custom, false),
    ];
    let pack = make_pack("none-sound", rules);
    assert_eq!(pack.soundness_rate_millionths(), 0);
}

#[test]
fn pack_soundness_rate_partial() {
    // 1 out of 4 = 250_000 millionths
    let rules = vec![
        enabled_rule("s", RewriteCategory::Custom, true),
        enabled_rule("u1", RewriteCategory::Custom, false),
        enabled_rule("u2", RewriteCategory::Custom, false),
        enabled_rule("u3", RewriteCategory::Custom, false),
    ];
    let pack = make_pack("partial-sound", rules);
    assert_eq!(pack.soundness_rate_millionths(), 250_000);
}

#[test]
fn pack_categories_collected() {
    let rules = vec![
        enabled_rule("a1", RewriteCategory::AlgebraicSimplification, true),
        enabled_rule("d1", RewriteCategory::DeadCodeElimination, true),
        enabled_rule("a2", RewriteCategory::AlgebraicSimplification, true),
        enabled_rule("s1", RewriteCategory::StringFusion, false),
    ];
    let pack = make_pack("categories", rules);
    assert_eq!(pack.categories.len(), 3);
    assert!(
        pack.categories
            .contains(&RewriteCategory::AlgebraicSimplification)
    );
    assert!(
        pack.categories
            .contains(&RewriteCategory::DeadCodeElimination)
    );
    assert!(pack.categories.contains(&RewriteCategory::StringFusion));
    assert!(!pack.categories.contains(&RewriteCategory::Custom));
}

#[test]
fn pack_rule_by_id_found() {
    let rules = vec![
        enabled_rule("alpha", RewriteCategory::Custom, true),
        enabled_rule("beta", RewriteCategory::DeadCodeElimination, false),
    ];
    let pack = make_pack("find", rules);
    let rule = pack.rule_by_id("beta").unwrap();
    assert_eq!(rule.category, RewriteCategory::DeadCodeElimination);
    assert!(!rule.proven_sound);
}

#[test]
fn pack_rule_by_id_not_found() {
    let pack = make_pack(
        "nope",
        vec![enabled_rule("only", RewriteCategory::Custom, true)],
    );
    assert!(pack.rule_by_id("missing").is_none());
}

#[test]
fn pack_rules_in_category() {
    let rules = vec![
        enabled_rule("a1", RewriteCategory::AlgebraicSimplification, true),
        enabled_rule("d1", RewriteCategory::DeadCodeElimination, true),
        enabled_rule("a2", RewriteCategory::AlgebraicSimplification, false),
        enabled_rule("a3", RewriteCategory::AlgebraicSimplification, true),
    ];
    let pack = make_pack("cat-filter", rules);
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
    assert_eq!(pack.rules_in_category(RewriteCategory::Custom).len(), 0);
}

#[test]
fn pack_has_internal_blocking_true() {
    let interference = InterferenceMetadata::build(vec![make_interference(
        "r1",
        "r2",
        RuleInterferenceKind::SemanticOverlap,
        true,
    )]);
    let pack = RewritePack::new(
        "blocking-pack",
        PackVersion::CURRENT,
        test_epoch(),
        "has blocking",
        vec![enabled_rule("r1", RewriteCategory::Custom, true)],
        interference,
        "model",
    );
    assert!(pack.has_internal_blocking());
}

#[test]
fn pack_has_internal_blocking_false() {
    let pack = make_pack(
        "clean-pack",
        vec![enabled_rule("r1", RewriteCategory::Custom, true)],
    );
    assert!(!pack.has_internal_blocking());
}

#[test]
fn pack_deterministic_hash() {
    let build = || {
        make_pack(
            "det",
            vec![
                enabled_rule("r1", RewriteCategory::Custom, true),
                enabled_rule("r2", RewriteCategory::DeadCodeElimination, false),
            ],
        )
    };
    let p1 = build();
    let p2 = build();
    assert_eq!(p1.content_hash, p2.content_hash);
}

#[test]
fn pack_different_rules_different_hash() {
    let p1 = make_pack(
        "same-id",
        vec![enabled_rule("r1", RewriteCategory::Custom, true)],
    );
    let p2 = make_pack(
        "same-id",
        vec![enabled_rule("r2", RewriteCategory::Custom, true)],
    );
    assert_ne!(p1.content_hash, p2.content_hash);
}

#[test]
fn pack_different_id_different_hash() {
    let p1 = make_pack("id-a", vec![]);
    let p2 = make_pack("id-b", vec![]);
    assert_ne!(p1.content_hash, p2.content_hash);
}

#[test]
fn pack_serde_roundtrip_with_rules() {
    let rules = vec![
        enabled_rule("r1", RewriteCategory::AlgebraicSimplification, true),
        enabled_rule("r2", RewriteCategory::DeadCodeElimination, false),
    ];
    let interference = InterferenceMetadata::build(vec![make_interference(
        "r1",
        "r2",
        RuleInterferenceKind::PatternConflict,
        false,
    )]);
    let pack = RewritePack::new(
        "serde-pack",
        PackVersion { major: 2, minor: 1 },
        test_epoch(),
        "serde test",
        rules,
        interference,
        "cost-model-1",
    );
    let json = serde_json::to_string(&pack).unwrap();
    let back: RewritePack = serde_json::from_str(&json).unwrap();
    assert_eq!(pack, back);
}

#[test]
fn pack_version_field() {
    let pack = make_versioned_pack("versioned", PackVersion { major: 3, minor: 7 }, vec![]);
    assert_eq!(pack.version.major, 3);
    assert_eq!(pack.version.minor, 7);
}

#[test]
fn pack_epoch_preserved() {
    let pack = make_pack("epoch-check", vec![]);
    assert_eq!(pack.epoch, test_epoch());
}

// ---------------------------------------------------------------------------
// PackCatalog
// ---------------------------------------------------------------------------

#[test]
fn catalog_new_empty() {
    let cat = PackCatalog::new("test-catalog");
    assert_eq!(cat.catalog_id, "test-catalog");
    assert_eq!(cat.schema_version, CATALOG_SCHEMA_VERSION);
    assert_eq!(cat.pack_count(), 0);
    assert_eq!(cat.total_rule_count, 0);
}

#[test]
fn catalog_register_single_pack() {
    let mut cat = PackCatalog::new("reg");
    let pack = make_pack(
        "p1",
        vec![
            enabled_rule("r1", RewriteCategory::Custom, true),
            enabled_rule("r2", RewriteCategory::Custom, false),
        ],
    );
    assert!(cat.register(pack));
    assert_eq!(cat.pack_count(), 1);
    assert_eq!(cat.total_rule_count, 2);
}

#[test]
fn catalog_register_duplicate_returns_false() {
    let mut cat = PackCatalog::new("dup");
    assert!(cat.register(make_pack("same", vec![])));
    assert!(!cat.register(make_pack("same", vec![])));
    assert_eq!(cat.pack_count(), 1);
}

#[test]
fn catalog_register_multiple_packs() {
    let mut cat = PackCatalog::new("multi");
    cat.register(make_pack(
        "p1",
        vec![enabled_rule("r1", RewriteCategory::Custom, true)],
    ));
    cat.register(make_pack(
        "p2",
        vec![
            enabled_rule("r2", RewriteCategory::Custom, true),
            enabled_rule("r3", RewriteCategory::Custom, true),
        ],
    ));
    assert_eq!(cat.pack_count(), 2);
    assert_eq!(cat.total_rule_count, 3);
}

#[test]
fn catalog_get_existing() {
    let mut cat = PackCatalog::new("get");
    cat.register(make_pack("target", vec![]));
    let pack = cat.get("target").unwrap();
    assert_eq!(pack.pack_id, "target");
}

#[test]
fn catalog_get_nonexistent() {
    let cat = PackCatalog::new("empty");
    assert!(cat.get("no-such-pack").is_none());
}

#[test]
fn catalog_compatible_packs_filters_by_version() {
    let mut cat = PackCatalog::new("compat");
    cat.register(make_versioned_pack(
        "v1_0",
        PackVersion { major: 1, minor: 0 },
        vec![],
    ));
    cat.register(make_versioned_pack(
        "v1_2",
        PackVersion { major: 1, minor: 2 },
        vec![],
    ));
    cat.register(make_versioned_pack(
        "v2_0",
        PackVersion { major: 2, minor: 0 },
        vec![],
    ));
    cat.register(make_versioned_pack(
        "v1_5",
        PackVersion { major: 1, minor: 5 },
        vec![],
    ));

    let host = PackVersion { major: 1, minor: 3 };
    let compat = cat.compatible_packs(&host);
    let ids: BTreeSet<&str> = compat.iter().map(|p| p.pack_id.as_str()).collect();
    assert!(ids.contains("v1_0"));
    assert!(ids.contains("v1_2"));
    assert!(!ids.contains("v2_0"));
    assert!(!ids.contains("v1_5")); // minor 5 > host minor 3
}

#[test]
fn catalog_compatible_packs_none_match() {
    let mut cat = PackCatalog::new("no-match");
    cat.register(make_versioned_pack(
        "v2",
        PackVersion { major: 2, minor: 0 },
        vec![],
    ));
    let host = PackVersion { major: 1, minor: 0 };
    assert!(cat.compatible_packs(&host).is_empty());
}

#[test]
fn catalog_cross_interference_symmetric_lookup() {
    let mut cat = PackCatalog::new("cross");
    cat.register(make_pack("alpha", vec![]));
    cat.register(make_pack("beta", vec![]));

    let meta = InterferenceMetadata::build(vec![make_interference(
        "alpha:r1",
        "beta:r1",
        RuleInterferenceKind::SemanticOverlap,
        true,
    )]);
    cat.add_cross_interference("alpha", "beta", meta);

    // Both orderings should work
    assert!(cat.has_cross_blocking("alpha", "beta"));
    assert!(cat.has_cross_blocking("beta", "alpha"));
}

#[test]
fn catalog_cross_interference_no_blocking() {
    let mut cat = PackCatalog::new("no-block");
    cat.register(make_pack("a", vec![]));
    cat.register(make_pack("b", vec![]));

    let meta = InterferenceMetadata::build(vec![make_interference(
        "a:r1",
        "b:r1",
        RuleInterferenceKind::BudgetContention,
        false,
    )]);
    cat.add_cross_interference("a", "b", meta);
    assert!(!cat.has_cross_blocking("a", "b"));
}

#[test]
fn catalog_cross_interference_unknown_pair() {
    let cat = PackCatalog::new("unknown");
    assert!(!cat.has_cross_blocking("x", "y"));
}

#[test]
fn catalog_hash_changes_on_register() {
    let mut cat = PackCatalog::new("hash-change");
    let hash_before = cat.content_hash.clone();
    cat.register(make_pack("new-pack", vec![]));
    assert_ne!(cat.content_hash, hash_before);
}

#[test]
fn catalog_hash_changes_on_cross_interference() {
    let mut cat = PackCatalog::new("hash-cross");
    cat.register(make_pack("a", vec![]));
    cat.register(make_pack("b", vec![]));
    let hash_before = cat.content_hash.clone();
    cat.add_cross_interference("a", "b", empty_interference());
    assert_ne!(cat.content_hash, hash_before);
}

#[test]
fn catalog_serde_roundtrip_empty() {
    let cat = PackCatalog::new("serde-empty");
    let json = serde_json::to_string(&cat).unwrap();
    let back: PackCatalog = serde_json::from_str(&json).unwrap();
    assert_eq!(cat, back);
}

#[test]
fn catalog_serde_roundtrip_populated() {
    let mut cat = PackCatalog::new("serde-pop");
    cat.register(make_pack(
        "p1",
        vec![enabled_rule("r1", RewriteCategory::Custom, true)],
    ));
    cat.register(make_pack(
        "p2",
        vec![enabled_rule(
            "r2",
            RewriteCategory::DeadCodeElimination,
            false,
        )],
    ));
    cat.add_cross_interference(
        "p1",
        "p2",
        InterferenceMetadata::build(vec![make_interference(
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

#[test]
fn catalog_deterministic_hash() {
    let build = || {
        let mut cat = PackCatalog::new("det");
        cat.register(make_pack(
            "p1",
            vec![enabled_rule("r1", RewriteCategory::Custom, true)],
        ));
        cat
    };
    let c1 = build();
    let c2 = build();
    assert_eq!(c1.content_hash, c2.content_hash);
}

// ---------------------------------------------------------------------------
// Cross-cutting / edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn pack_with_all_categories() {
    let all_categories = [
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
    let rules: Vec<_> = all_categories
        .iter()
        .enumerate()
        .map(|(i, cat)| enabled_rule(&format!("r{i}"), *cat, true))
        .collect();
    let pack = make_pack("all-cats", rules);
    assert_eq!(pack.categories.len(), 10);
}

#[test]
fn cost_model_with_all_cost_classes_as_keys() {
    let costs: BTreeMap<InstructionCostClass, i64> = InstructionCostClass::ALL
        .iter()
        .enumerate()
        .map(|(i, c)| (*c, (i as i64 + 1) * MILLION))
        .collect();
    let model = DeterministicCostModel::new("all-keys", costs, BTreeMap::new(), BTreeMap::new());
    for (i, class) in InstructionCostClass::ALL.iter().enumerate() {
        assert_eq!(model.instruction_cost(*class), (i as i64 + 1) * MILLION);
    }
}

#[test]
fn interference_metadata_only_blocking() {
    let entries = vec![
        make_interference("a", "b", RuleInterferenceKind::SemanticOverlap, true),
        make_interference("c", "d", RuleInterferenceKind::OrderDependent, true),
    ];
    let meta = InterferenceMetadata::build(entries);
    assert!(meta.has_blocking());
    assert_eq!(meta.blocking_count, 2);
    assert_eq!(meta.non_blocking_count, 0);
}

#[test]
fn catalog_total_rule_count_tracks_across_multiple_registers() {
    let mut cat = PackCatalog::new("total-count");
    cat.register(make_pack(
        "p1",
        vec![
            enabled_rule("r1", RewriteCategory::Custom, true),
            enabled_rule("r2", RewriteCategory::Custom, true),
        ],
    ));
    assert_eq!(cat.total_rule_count, 2);
    cat.register(make_pack(
        "p2",
        vec![enabled_rule("r3", RewriteCategory::Custom, true)],
    ));
    assert_eq!(cat.total_rule_count, 3);
    cat.register(make_pack("p3", vec![]));
    assert_eq!(cat.total_rule_count, 3);
}

#[test]
fn pack_version_self_compatible() {
    let v = PackVersion { major: 5, minor: 3 };
    assert!(v.is_compatible_with(&v));
}

#[test]
fn rule_entry_ordering_is_deterministic() {
    let r1 = enabled_rule("aaa", RewriteCategory::Custom, true);
    let r2 = enabled_rule("bbb", RewriteCategory::Custom, true);
    assert!(r1 < r2);
}
