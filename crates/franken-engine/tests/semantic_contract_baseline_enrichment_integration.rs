#![forbid(unsafe_code)]
//! Enrichment integration tests for `semantic_contract_baseline`.
//!
//! Adds JSON field-name stability, exact serde enum values, Display exactness,
//! Debug distinctness, error coverage, and edge cases beyond
//! the existing 50 integration tests.

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

use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::semantic_contract_baseline::{
    AdjudicationCategory, AdjudicationResolution, CleanupPolicy, CompatibilityCorpus, ConsumerLane,
    ContractPackage, DeterminismLevel, DomMutation, DriftKind, EffectKind, EffectSemanticContract,
    EffectTiming, FixtureCategory, FixturePriority, ForbiddenPattern, FoundationError,
    FrozenBaseline, HookKind, HookSemanticContract, InvocationRule, MutationKind,
    OrderingConstraint, SEMANTIC_CONTRACT_SCHEMA_VERSION, SemanticContractFoundation,
    SemanticContractVersion, SideEffectBoundary, TraceFixture, ViolationSeverity,
};

// ===========================================================================
// 1) SemanticContractVersion Display
// ===========================================================================

#[test]
fn semantic_contract_version_display_format() {
    let v = SemanticContractVersion::CURRENT;
    let s = v.to_string();
    // format is "major.minor.patch"
    assert!(s.contains('.'), "version Display should contain dots: {s}");
    let parts: Vec<&str> = s.split('.').collect();
    assert_eq!(parts.len(), 3, "version should have 3 parts: {s}");
}

// ===========================================================================
// 2) FoundationError — exact Display
// ===========================================================================

#[test]
fn foundation_error_display_all_unique() {
    let variants: Vec<String> = vec![
        FoundationError::CorpusAlreadyFrozen.to_string(),
        FoundationError::CorpusCapacityExceeded.to_string(),
        FoundationError::DuplicateFixture.to_string(),
        FoundationError::EmptyCorpus.to_string(),
        FoundationError::EmptyPackage.to_string(),
        FoundationError::PackageAlreadyFrozen.to_string(),
        FoundationError::PackageNotFound.to_string(),
        FoundationError::BaselineNotFound.to_string(),
        FoundationError::ContractCapacityExceeded.to_string(),
        FoundationError::AdjudicationCapacityExceeded.to_string(),
        FoundationError::NoConsumerLanes.to_string(),
        FoundationError::InvalidContract("x".into()).to_string(),
        FoundationError::IncompatibleVersion.to_string(),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(
        unique.len(),
        variants.len(),
        "all FoundationError Display strings must be unique"
    );
}

#[test]
fn foundation_error_is_std_error() {
    let e = FoundationError::EmptyCorpus;
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 3) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_fixture_category() {
    let variants = [
        format!("{:?}", FixtureCategory::HookState),
        format!("{:?}", FixtureCategory::HookEffect),
        format!("{:?}", FixtureCategory::HookMemo),
        format!("{:?}", FixtureCategory::HookRef),
        format!("{:?}", FixtureCategory::HookReducer),
        format!("{:?}", FixtureCategory::HookContext),
        format!("{:?}", FixtureCategory::ConcurrentRendering),
        format!("{:?}", FixtureCategory::Suspense),
        format!("{:?}", FixtureCategory::ErrorBoundary),
        format!("{:?}", FixtureCategory::Hydration),
        format!("{:?}", FixtureCategory::Portal),
        format!("{:?}", FixtureCategory::RefEdgeCase),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 12);
}

#[test]
fn debug_distinct_fixture_priority() {
    let variants = [
        format!("{:?}", FixturePriority::Critical),
        format!("{:?}", FixturePriority::High),
        format!("{:?}", FixturePriority::Medium),
        format!("{:?}", FixturePriority::Low),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

#[test]
fn debug_distinct_violation_severity() {
    let variants = [
        format!("{:?}", ViolationSeverity::Fatal),
        format!("{:?}", ViolationSeverity::Error),
        format!("{:?}", ViolationSeverity::Warning),
        format!("{:?}", ViolationSeverity::Info),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 4) Serde exact enum values
// ===========================================================================

#[test]
fn serde_exact_fixture_priority_tags() {
    let priorities = [
        FixturePriority::Critical,
        FixturePriority::High,
        FixturePriority::Medium,
        FixturePriority::Low,
    ];
    let expected = ["\"Critical\"", "\"High\"", "\"Medium\"", "\"Low\""];
    for (p, exp) in priorities.iter().zip(expected.iter()) {
        let json = serde_json::to_string(p).unwrap();
        assert_eq!(json, *exp, "FixturePriority serde tag mismatch for {p:?}");
    }
}

#[test]
fn serde_exact_violation_severity_tags() {
    let severities = [
        ViolationSeverity::Fatal,
        ViolationSeverity::Error,
        ViolationSeverity::Warning,
        ViolationSeverity::Info,
    ];
    let expected = ["\"Fatal\"", "\"Error\"", "\"Warning\"", "\"Info\""];
    for (s, exp) in severities.iter().zip(expected.iter()) {
        let json = serde_json::to_string(s).unwrap();
        assert_eq!(json, *exp, "ViolationSeverity serde tag mismatch for {s:?}");
    }
}

#[test]
fn serde_exact_consumer_lane_tags() {
    let lanes = [
        ConsumerLane::Compiler,
        ConsumerLane::Runtime,
        ConsumerLane::Verification,
        ConsumerLane::Optimization,
        ConsumerLane::Governance,
        ConsumerLane::Adoption,
    ];
    let expected = [
        "\"Compiler\"",
        "\"Runtime\"",
        "\"Verification\"",
        "\"Optimization\"",
        "\"Governance\"",
        "\"Adoption\"",
    ];
    for (l, exp) in lanes.iter().zip(expected.iter()) {
        let json = serde_json::to_string(l).unwrap();
        assert_eq!(json, *exp, "ConsumerLane serde tag mismatch for {l:?}");
    }
}

#[test]
fn serde_exact_drift_kind_tags() {
    let kinds = [
        DriftKind::SemanticRegression,
        DriftKind::OrderingViolation,
        DriftKind::EffectBoundaryLeak,
        DriftKind::HookContractBreach,
        DriftKind::AdjudicationOverride,
        DriftKind::CorpusCoverageDrop,
        DriftKind::VersionIncompatibility,
    ];
    let expected = [
        "\"SemanticRegression\"",
        "\"OrderingViolation\"",
        "\"EffectBoundaryLeak\"",
        "\"HookContractBreach\"",
        "\"AdjudicationOverride\"",
        "\"CorpusCoverageDrop\"",
        "\"VersionIncompatibility\"",
    ];
    for (k, exp) in kinds.iter().zip(expected.iter()) {
        let json = serde_json::to_string(k).unwrap();
        assert_eq!(json, *exp, "DriftKind serde tag mismatch for {k:?}");
    }
}

#[test]
fn serde_exact_mutation_kind_tags() {
    let kinds = [
        MutationKind::SetAttribute,
        MutationKind::RemoveAttribute,
        MutationKind::AppendChild,
        MutationKind::RemoveChild,
        MutationKind::SetTextContent,
        MutationKind::InsertBefore,
    ];
    let expected = [
        "\"SetAttribute\"",
        "\"RemoveAttribute\"",
        "\"AppendChild\"",
        "\"RemoveChild\"",
        "\"SetTextContent\"",
        "\"InsertBefore\"",
    ];
    for (k, exp) in kinds.iter().zip(expected.iter()) {
        let json = serde_json::to_string(k).unwrap();
        assert_eq!(json, *exp, "MutationKind serde tag mismatch for {k:?}");
    }
}

#[test]
fn serde_exact_hook_kind_tags() {
    let kinds = [
        HookKind::UseState,
        HookKind::UseEffect,
        HookKind::UseMemo,
        HookKind::UseRef,
        HookKind::UseReducer,
        HookKind::UseContext,
        HookKind::UseCallback,
        HookKind::UseLayoutEffect,
        HookKind::UseImperativeHandle,
        HookKind::UseDebugValue,
    ];
    let expected = [
        "\"UseState\"",
        "\"UseEffect\"",
        "\"UseMemo\"",
        "\"UseRef\"",
        "\"UseReducer\"",
        "\"UseContext\"",
        "\"UseCallback\"",
        "\"UseLayoutEffect\"",
        "\"UseImperativeHandle\"",
        "\"UseDebugValue\"",
    ];
    for (k, exp) in kinds.iter().zip(expected.iter()) {
        let json = serde_json::to_string(k).unwrap();
        assert_eq!(json, *exp, "HookKind serde tag mismatch for {k:?}");
    }
}

#[test]
fn serde_exact_effect_kind_tags() {
    let kinds = [
        EffectKind::DomMutation,
        EffectKind::NetworkIo,
        EffectKind::TimerSetup,
        EffectKind::StateUpdate,
        EffectKind::Subscription,
        EffectKind::CustomEffect,
    ];
    let expected = [
        "\"DomMutation\"",
        "\"NetworkIo\"",
        "\"TimerSetup\"",
        "\"StateUpdate\"",
        "\"Subscription\"",
        "\"CustomEffect\"",
    ];
    for (k, exp) in kinds.iter().zip(expected.iter()) {
        let json = serde_json::to_string(k).unwrap();
        assert_eq!(json, *exp, "EffectKind serde tag mismatch for {k:?}");
    }
}

#[test]
fn serde_exact_determinism_level_tags() {
    let levels = [
        DeterminismLevel::FullyDeterministic,
        DeterminismLevel::OrderDeterministic,
        DeterminismLevel::Nondeterministic,
    ];
    let expected = [
        "\"FullyDeterministic\"",
        "\"OrderDeterministic\"",
        "\"Nondeterministic\"",
    ];
    for (l, exp) in levels.iter().zip(expected.iter()) {
        let json = serde_json::to_string(l).unwrap();
        assert_eq!(json, *exp, "DeterminismLevel serde tag mismatch for {l:?}");
    }
}

#[test]
fn serde_exact_side_effect_boundary_tags() {
    let boundaries = [
        SideEffectBoundary::Contained,
        SideEffectBoundary::Leaks,
        SideEffectBoundary::Unknown,
    ];
    let expected = ["\"Contained\"", "\"Leaks\"", "\"Unknown\""];
    for (b, exp) in boundaries.iter().zip(expected.iter()) {
        let json = serde_json::to_string(b).unwrap();
        assert_eq!(
            json, *exp,
            "SideEffectBoundary serde tag mismatch for {b:?}"
        );
    }
}

// ===========================================================================
// 5) Ordering stability
// ===========================================================================

#[test]
fn fixture_priority_ordering_stable() {
    let mut priorities = [
        FixturePriority::Low,
        FixturePriority::Critical,
        FixturePriority::Medium,
        FixturePriority::High,
    ];
    priorities.sort();
    assert_eq!(priorities[0], FixturePriority::Critical);
    assert_eq!(priorities[3], FixturePriority::Low);
}

#[test]
fn violation_severity_ordering_stable() {
    let mut severities = [
        ViolationSeverity::Info,
        ViolationSeverity::Fatal,
        ViolationSeverity::Warning,
        ViolationSeverity::Error,
    ];
    severities.sort();
    assert_eq!(severities[0], ViolationSeverity::Fatal);
    assert_eq!(severities[3], ViolationSeverity::Info);
}

// ===========================================================================
// 6) FixturePriority weight_millionths
// ===========================================================================

#[test]
fn fixture_priority_weight_millionths_ordered() {
    assert!(
        FixturePriority::Critical.weight_millionths() > FixturePriority::High.weight_millionths()
    );
    assert!(
        FixturePriority::High.weight_millionths() > FixturePriority::Medium.weight_millionths()
    );
    assert!(FixturePriority::Medium.weight_millionths() > FixturePriority::Low.weight_millionths());
    assert!(FixturePriority::Low.weight_millionths() > 0);
}

// ===========================================================================
// 7) SemanticContractVersion compatibility
// ===========================================================================

#[test]
fn version_compatible_with_same() {
    let v = SemanticContractVersion::CURRENT;
    assert!(v.is_compatible_with(&v));
}

// ===========================================================================
// 8) Schema version constant
// ===========================================================================

#[test]
fn schema_version_constant_stable() {
    assert_eq!(
        SEMANTIC_CONTRACT_SCHEMA_VERSION,
        "franken-engine.semantic_contract_baseline.v1"
    );
}

// ===========================================================================
// 9) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_foundation_error_all_variants() {
    let variants = vec![
        FoundationError::CorpusAlreadyFrozen,
        FoundationError::CorpusCapacityExceeded,
        FoundationError::DuplicateFixture,
        FoundationError::EmptyCorpus,
        FoundationError::EmptyPackage,
        FoundationError::PackageAlreadyFrozen,
        FoundationError::PackageNotFound,
        FoundationError::BaselineNotFound,
        FoundationError::ContractCapacityExceeded,
        FoundationError::AdjudicationCapacityExceeded,
        FoundationError::NoConsumerLanes,
        FoundationError::InvalidContract("bad".into()),
        FoundationError::IncompatibleVersion,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let rt: FoundationError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, rt);
    }
}

#[test]
fn serde_roundtrip_semantic_contract_version() {
    let v = SemanticContractVersion::CURRENT;
    let json = serde_json::to_string(&v).unwrap();
    let rt: SemanticContractVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, rt);
}

// ===========================================================================
// 10) Foundation construction
// ===========================================================================

#[test]
fn foundation_new_initial_state() {
    let f = SemanticContractFoundation::new();
    assert!(f.latest_baseline().is_none());
    assert!(f.latest_package().is_none());
}

#[test]
fn foundation_default_matches_new() {
    let f1 = SemanticContractFoundation::new();
    let f2 = SemanticContractFoundation::default();
    assert_eq!(f1, f2);
}

// ===========================================================================
// 11) Enum count verification
// ===========================================================================

#[test]
fn fixture_category_has_12_variants() {
    let all = [
        FixtureCategory::HookState,
        FixtureCategory::HookEffect,
        FixtureCategory::HookMemo,
        FixtureCategory::HookRef,
        FixtureCategory::HookReducer,
        FixtureCategory::HookContext,
        FixtureCategory::ConcurrentRendering,
        FixtureCategory::Suspense,
        FixtureCategory::ErrorBoundary,
        FixtureCategory::Hydration,
        FixtureCategory::Portal,
        FixtureCategory::RefEdgeCase,
    ];
    let unique: BTreeSet<_> = all.iter().collect();
    assert_eq!(unique.len(), 12);
}

#[test]
fn hook_kind_has_10_variants() {
    let all = [
        HookKind::UseState,
        HookKind::UseEffect,
        HookKind::UseMemo,
        HookKind::UseRef,
        HookKind::UseReducer,
        HookKind::UseContext,
        HookKind::UseCallback,
        HookKind::UseLayoutEffect,
        HookKind::UseImperativeHandle,
        HookKind::UseDebugValue,
    ];
    let unique: BTreeSet<_> = all.iter().collect();
    assert_eq!(unique.len(), 10);
}

#[test]
fn drift_kind_has_7_variants() {
    let all = [
        DriftKind::SemanticRegression,
        DriftKind::OrderingViolation,
        DriftKind::EffectBoundaryLeak,
        DriftKind::HookContractBreach,
        DriftKind::AdjudicationOverride,
        DriftKind::CorpusCoverageDrop,
        DriftKind::VersionIncompatibility,
    ];
    let unique: BTreeSet<_> = all.iter().collect();
    assert_eq!(unique.len(), 7);
}

// ===========================================================================
// 12) Additional serde roundtrips for small enums
// ===========================================================================

#[test]
fn serde_roundtrip_invocation_rule() {
    let rules = [
        InvocationRule::MustBeTopLevel,
        InvocationRule::MustNotBeConditional,
        InvocationRule::MustNotBeInLoop,
        InvocationRule::MustBeInFunctionComponent,
        InvocationRule::OrderPreservedAcrossRenders,
    ];
    for r in &rules {
        let json = serde_json::to_string(r).unwrap();
        let rt: InvocationRule = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, rt);
    }
}

#[test]
fn serde_roundtrip_cleanup_policy() {
    let policies = [
        CleanupPolicy::RunOnUnmount,
        CleanupPolicy::RunBeforeRerun,
        CleanupPolicy::NoCleanup,
        CleanupPolicy::ConditionalCleanup,
    ];
    for p in &policies {
        let json = serde_json::to_string(p).unwrap();
        let rt: CleanupPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(*p, rt);
    }
}

#[test]
fn serde_roundtrip_effect_timing() {
    let timings = [
        EffectTiming::AfterRender,
        EffectTiming::BeforePaint,
        EffectTiming::Synchronous,
        EffectTiming::Deferred,
    ];
    for t in &timings {
        let json = serde_json::to_string(t).unwrap();
        let rt: EffectTiming = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, rt);
    }
}

#[test]
fn serde_roundtrip_adjudication_category() {
    let cats = [
        AdjudicationCategory::AmbiguousOrdering,
        AdjudicationCategory::UndefinedEdgeCase,
        AdjudicationCategory::VersionConflict,
        AdjudicationCategory::PlatformDivergence,
        AdjudicationCategory::SpecGap,
    ];
    for c in &cats {
        let json = serde_json::to_string(c).unwrap();
        let rt: AdjudicationCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*c, rt);
    }
}

#[test]
fn serde_roundtrip_adjudication_resolution() {
    let resolutions = [
        AdjudicationResolution::PreferReactBehavior,
        AdjudicationResolution::PreferDeterministic,
        AdjudicationResolution::PreferConservative,
        AdjudicationResolution::RequireExplicitFallback,
    ];
    for r in &resolutions {
        let json = serde_json::to_string(r).unwrap();
        let rt: AdjudicationResolution = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, rt);
    }
}

// ===========================================================================
// Test helpers
// ===========================================================================

fn oid(seed: u8) -> EngineObjectId {
    EngineObjectId([seed; 32])
}

/// Counter-based fixture IDs to avoid duplicates across tests.
fn make_fixture(name: &str, cat: FixtureCategory, pri: FixturePriority) -> TraceFixture {
    use std::sync::atomic::{AtomicU8, Ordering};
    static COUNTER: AtomicU8 = AtomicU8::new(1);
    let seed = COUNTER.fetch_add(1, Ordering::Relaxed);
    TraceFixture {
        id: oid(seed),
        name: name.to_string(),
        category: cat,
        priority: pri,
        input_hash: ContentHash::compute(format!("input-{name}").as_bytes()),
        expected_trace_hash: ContentHash::compute(format!("trace-{name}").as_bytes()),
        expected_dom_mutations: vec![],
        expected_effect_order: vec![],
        metadata: std::collections::BTreeMap::new(),
    }
}

// ===========================================================================
// 13) CompatibilityCorpus lifecycle
// ===========================================================================

#[test]
fn corpus_new_initial_state() {
    let corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    assert!(!corpus.frozen);
    assert!(corpus.fixtures.is_empty());
    assert_eq!(corpus.created_epoch, 1);
}

#[test]
fn corpus_add_fixture_and_freeze() {
    let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    let fixture = make_fixture("f1", FixtureCategory::HookState, FixturePriority::Critical);
    corpus.add_fixture(fixture).unwrap();
    assert_eq!(corpus.fixtures.len(), 1);
    corpus.freeze().unwrap();
    assert!(corpus.frozen);
}

#[test]
fn corpus_freeze_empty_fails() {
    let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    let result = corpus.freeze();
    assert!(result.is_err());
}

#[test]
fn corpus_freeze_twice_fails() {
    let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    corpus
        .add_fixture(make_fixture(
            "f1",
            FixtureCategory::HookState,
            FixturePriority::Critical,
        ))
        .unwrap();
    corpus.freeze().unwrap();
    let result = corpus.freeze();
    assert!(result.is_err());
}

#[test]
fn corpus_duplicate_fixture_fails() {
    let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    let fixture = make_fixture("f1", FixtureCategory::HookState, FixturePriority::Critical);
    corpus.add_fixture(fixture.clone()).unwrap();
    let result = corpus.add_fixture(fixture);
    assert!(result.is_err());
}

#[test]
fn corpus_fixtures_by_priority_ordering() {
    let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    corpus
        .add_fixture(make_fixture(
            "low",
            FixtureCategory::Portal,
            FixturePriority::Low,
        ))
        .unwrap();
    corpus
        .add_fixture(make_fixture(
            "crit",
            FixtureCategory::HookState,
            FixturePriority::Critical,
        ))
        .unwrap();
    corpus
        .add_fixture(make_fixture(
            "med",
            FixtureCategory::Suspense,
            FixturePriority::Medium,
        ))
        .unwrap();
    let by_priority = corpus.fixtures_by_priority();
    assert_eq!(by_priority.len(), 3);
    assert_eq!(by_priority[0].priority, FixturePriority::Critical);
}

#[test]
fn corpus_fixtures_by_category() {
    let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    corpus
        .add_fixture(make_fixture(
            "h1",
            FixtureCategory::HookState,
            FixturePriority::High,
        ))
        .unwrap();
    corpus
        .add_fixture(make_fixture(
            "h2",
            FixtureCategory::HookEffect,
            FixturePriority::Medium,
        ))
        .unwrap();
    corpus
        .add_fixture(make_fixture(
            "h3",
            FixtureCategory::HookState,
            FixturePriority::Low,
        ))
        .unwrap();
    let hooks = corpus.fixtures_by_category(&FixtureCategory::HookState);
    assert_eq!(hooks.len(), 2);
}

#[test]
fn corpus_coverage_score_increases_with_categories() {
    let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    corpus
        .add_fixture(make_fixture(
            "a",
            FixtureCategory::HookState,
            FixturePriority::High,
        ))
        .unwrap();
    let score1 = corpus.coverage_score_millionths();

    let mut corpus2 = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    corpus2
        .add_fixture(make_fixture(
            "a",
            FixtureCategory::HookState,
            FixturePriority::High,
        ))
        .unwrap();
    corpus2
        .add_fixture(make_fixture(
            "b",
            FixtureCategory::HookEffect,
            FixturePriority::High,
        ))
        .unwrap();
    let score2 = corpus2.coverage_score_millionths();

    assert!(
        score2 > score1,
        "more categories should increase coverage score"
    );
}

// ===========================================================================
// 14) HookSemanticContract — canonical factories
// ===========================================================================

#[test]
fn hook_contract_canonical_use_state() {
    let contract = HookSemanticContract::canonical_use_state();
    assert_eq!(contract.hook_kind, HookKind::UseState);
    assert_eq!(contract.cleanup_semantics, CleanupPolicy::NoCleanup);
    assert!(!contract.invocation_rules.is_empty());
}

#[test]
fn hook_contract_canonical_use_effect() {
    let contract = HookSemanticContract::canonical_use_effect();
    assert_eq!(contract.hook_kind, HookKind::UseEffect);
    assert_eq!(contract.cleanup_semantics, CleanupPolicy::RunBeforeRerun);
    assert!(!contract.invocation_rules.is_empty());
}

#[test]
fn hook_contract_hash_deterministic() {
    let c1 = HookSemanticContract::canonical_use_state();
    let c2 = HookSemanticContract::canonical_use_state();
    assert_eq!(c1.contract_hash(), c2.contract_hash());
}

// ===========================================================================
// 15) EffectSemanticContract — canonical factories
// ===========================================================================

#[test]
fn effect_contract_canonical_dom_mutation() {
    let contract = EffectSemanticContract::canonical_dom_mutation();
    assert_eq!(contract.effect_kind, EffectKind::DomMutation);
    assert_eq!(contract.timing, EffectTiming::AfterRender);
    assert_eq!(contract.side_effect_boundary, SideEffectBoundary::Contained);
    assert!(contract.is_deterministic());
}

#[test]
fn effect_contract_canonical_state_update() {
    let contract = EffectSemanticContract::canonical_state_update();
    assert_eq!(contract.effect_kind, EffectKind::StateUpdate);
    assert_eq!(contract.timing, EffectTiming::Synchronous);
    assert!(contract.is_deterministic());
}

#[test]
fn effect_contract_hash_deterministic() {
    let c1 = EffectSemanticContract::canonical_dom_mutation();
    let c2 = EffectSemanticContract::canonical_dom_mutation();
    assert_eq!(c1.contract_hash(), c2.contract_hash());
}

#[test]
fn effect_contract_different_kinds_different_hashes() {
    let dom = EffectSemanticContract::canonical_dom_mutation();
    let state = EffectSemanticContract::canonical_state_update();
    assert_ne!(dom.contract_hash(), state.contract_hash());
}

// ===========================================================================
// 16) ContractPackage lifecycle
// ===========================================================================

#[test]
fn contract_package_new_from_frozen_corpus() {
    let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    corpus
        .add_fixture(make_fixture(
            "f1",
            FixtureCategory::HookState,
            FixturePriority::High,
        ))
        .unwrap();
    corpus.freeze().unwrap();
    let pkg = ContractPackage::new(corpus).unwrap();
    assert!(!pkg.is_frozen());
    assert_eq!(pkg.total_contracts(), 0);
}

#[test]
fn contract_package_add_hook_and_effect_contracts() {
    let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    corpus
        .add_fixture(make_fixture(
            "f1",
            FixtureCategory::HookState,
            FixturePriority::High,
        ))
        .unwrap();
    corpus.freeze().unwrap();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    pkg.add_effect_contract(EffectSemanticContract::canonical_dom_mutation())
        .unwrap();
    assert_eq!(pkg.total_contracts(), 2);
}

#[test]
fn contract_package_freeze_and_validate() {
    // Need >= 50% corpus coverage (6+ of 12 categories) + 4 core hook contracts
    let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    corpus
        .add_fixture(make_fixture(
            "f1",
            FixtureCategory::HookState,
            FixturePriority::High,
        ))
        .unwrap();
    corpus
        .add_fixture(make_fixture(
            "f2",
            FixtureCategory::HookEffect,
            FixturePriority::High,
        ))
        .unwrap();
    corpus
        .add_fixture(make_fixture(
            "f3",
            FixtureCategory::HookMemo,
            FixturePriority::Medium,
        ))
        .unwrap();
    corpus
        .add_fixture(make_fixture(
            "f4",
            FixtureCategory::HookRef,
            FixturePriority::Medium,
        ))
        .unwrap();
    corpus
        .add_fixture(make_fixture(
            "f5",
            FixtureCategory::HookReducer,
            FixturePriority::Medium,
        ))
        .unwrap();
    corpus
        .add_fixture(make_fixture(
            "f6",
            FixtureCategory::HookContext,
            FixturePriority::Low,
        ))
        .unwrap();
    corpus.freeze().unwrap();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_effect())
        .unwrap();
    pkg.add_hook_contract(HookSemanticContract {
        hook_kind: HookKind::UseMemo,
        invocation_rules: vec![InvocationRule::MustBeTopLevel],
        ordering_constraints: vec![],
        cleanup_semantics: CleanupPolicy::NoCleanup,
        forbidden_patterns: vec![],
    })
    .unwrap();
    pkg.add_hook_contract(HookSemanticContract {
        hook_kind: HookKind::UseRef,
        invocation_rules: vec![InvocationRule::MustBeTopLevel],
        ordering_constraints: vec![],
        cleanup_semantics: CleanupPolicy::NoCleanup,
        forbidden_patterns: vec![],
    })
    .unwrap();
    pkg.freeze(1).unwrap();
    assert!(pkg.is_frozen());
    let validation = pkg.validate().unwrap();
    assert!(validation.is_valid);
    assert_eq!(validation.hook_coverage_count, 4);
}

#[test]
fn contract_package_freeze_empty_fails() {
    let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    corpus
        .add_fixture(make_fixture(
            "f1",
            FixtureCategory::HookState,
            FixturePriority::High,
        ))
        .unwrap();
    corpus.freeze().unwrap();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    let result = pkg.freeze(1);
    assert!(result.is_err());
}

// ===========================================================================
// 17) JSON field-name stability for structs
// ===========================================================================

#[test]
fn json_fields_dom_mutation() {
    let dm = DomMutation {
        target_path: "/div/span".to_string(),
        kind: MutationKind::SetAttribute,
        value: "class=active".to_string(),
    };
    let v: serde_json::Value = serde_json::to_value(&dm).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("target_path"));
    assert!(obj.contains_key("kind"));
    assert!(obj.contains_key("value"));
}

#[test]
fn json_fields_ordering_constraint() {
    let oc = OrderingConstraint {
        before: "state_init".to_string(),
        after: "effect_run".to_string(),
        strict: true,
    };
    let v: serde_json::Value = serde_json::to_value(&oc).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("before"));
    assert!(obj.contains_key("after"));
    assert!(obj.contains_key("strict"));
}

#[test]
fn json_fields_forbidden_pattern() {
    let fp = ForbiddenPattern {
        description: "no nested hooks".to_string(),
        pattern_hash: ContentHash::compute(b"pattern"),
        severity: ViolationSeverity::Error,
    };
    let v: serde_json::Value = serde_json::to_value(&fp).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("description"));
    assert!(obj.contains_key("pattern_hash"));
    assert!(obj.contains_key("severity"));
}

#[test]
fn json_fields_package_validation() {
    let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    corpus
        .add_fixture(make_fixture(
            "f",
            FixtureCategory::HookState,
            FixturePriority::High,
        ))
        .unwrap();
    corpus.freeze().unwrap();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    // Don't need is_valid=true here, just checking field names
    let validation = pkg.validate().unwrap();
    let v: serde_json::Value = serde_json::to_value(&validation).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("is_valid"));
    assert!(obj.contains_key("coverage_millionths"));
    assert!(obj.contains_key("hook_coverage_count"));
    assert!(obj.contains_key("effect_contract_count"));
    assert!(obj.contains_key("adjudication_rule_count"));
    assert!(obj.contains_key("warnings"));
}

// ===========================================================================
// 18) Serde roundtrips for struct types
// ===========================================================================

#[test]
fn serde_roundtrip_dom_mutation() {
    let dm = DomMutation {
        target_path: "/div".to_string(),
        kind: MutationKind::AppendChild,
        value: "<span/>".to_string(),
    };
    let json = serde_json::to_string(&dm).unwrap();
    let rt: DomMutation = serde_json::from_str(&json).unwrap();
    assert_eq!(dm, rt);
}

#[test]
fn serde_roundtrip_ordering_constraint() {
    let oc = OrderingConstraint {
        before: "a".to_string(),
        after: "b".to_string(),
        strict: false,
    };
    let json = serde_json::to_string(&oc).unwrap();
    let rt: OrderingConstraint = serde_json::from_str(&json).unwrap();
    assert_eq!(oc, rt);
}

#[test]
fn serde_roundtrip_hook_semantic_contract() {
    let contract = HookSemanticContract::canonical_use_state();
    let json = serde_json::to_string(&contract).unwrap();
    let rt: HookSemanticContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, rt);
}

#[test]
fn serde_roundtrip_effect_semantic_contract() {
    let contract = EffectSemanticContract::canonical_dom_mutation();
    let json = serde_json::to_string(&contract).unwrap();
    let rt: EffectSemanticContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, rt);
}

// ===========================================================================
// 19) Debug distinctness for more enum types
// ===========================================================================

#[test]
fn debug_distinct_mutation_kind() {
    let variants = [
        format!("{:?}", MutationKind::SetAttribute),
        format!("{:?}", MutationKind::RemoveAttribute),
        format!("{:?}", MutationKind::AppendChild),
        format!("{:?}", MutationKind::RemoveChild),
        format!("{:?}", MutationKind::SetTextContent),
        format!("{:?}", MutationKind::InsertBefore),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 6);
}

#[test]
fn debug_distinct_hook_kind() {
    let variants = [
        format!("{:?}", HookKind::UseState),
        format!("{:?}", HookKind::UseEffect),
        format!("{:?}", HookKind::UseMemo),
        format!("{:?}", HookKind::UseRef),
        format!("{:?}", HookKind::UseReducer),
        format!("{:?}", HookKind::UseContext),
        format!("{:?}", HookKind::UseCallback),
        format!("{:?}", HookKind::UseLayoutEffect),
        format!("{:?}", HookKind::UseImperativeHandle),
        format!("{:?}", HookKind::UseDebugValue),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 10);
}

#[test]
fn debug_distinct_consumer_lane() {
    let variants = [
        format!("{:?}", ConsumerLane::Compiler),
        format!("{:?}", ConsumerLane::Runtime),
        format!("{:?}", ConsumerLane::Verification),
        format!("{:?}", ConsumerLane::Optimization),
        format!("{:?}", ConsumerLane::Governance),
        format!("{:?}", ConsumerLane::Adoption),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 6);
}

#[test]
fn debug_distinct_drift_kind() {
    let variants = [
        format!("{:?}", DriftKind::SemanticRegression),
        format!("{:?}", DriftKind::OrderingViolation),
        format!("{:?}", DriftKind::EffectBoundaryLeak),
        format!("{:?}", DriftKind::HookContractBreach),
        format!("{:?}", DriftKind::AdjudicationOverride),
        format!("{:?}", DriftKind::CorpusCoverageDrop),
        format!("{:?}", DriftKind::VersionIncompatibility),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 7);
}

// ===========================================================================
// 20) FoundationError — exact Display messages
// ===========================================================================

#[test]
fn foundation_error_display_exact_corpus_frozen() {
    assert_eq!(
        FoundationError::CorpusAlreadyFrozen.to_string(),
        "corpus is already frozen"
    );
}

#[test]
fn foundation_error_display_exact_empty_corpus() {
    assert_eq!(
        FoundationError::EmptyCorpus.to_string(),
        "cannot freeze empty corpus"
    );
}

#[test]
fn foundation_error_display_exact_empty_package() {
    assert_eq!(
        FoundationError::EmptyPackage.to_string(),
        "cannot freeze package with no contracts"
    );
}

#[test]
fn foundation_error_display_exact_no_consumer_lanes() {
    assert_eq!(
        FoundationError::NoConsumerLanes.to_string(),
        "at least one consumer lane required"
    );
}

#[test]
fn foundation_error_display_invalid_contract_contains_msg() {
    let e = FoundationError::InvalidContract("bad hook".into());
    let s = e.to_string();
    assert!(s.contains("bad hook"), "should contain message: {s}");
}

// ===========================================================================
// 21) FrozenBaseline — serves_lane
// ===========================================================================

#[test]
fn frozen_baseline_serves_lane() {
    let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    corpus
        .add_fixture(make_fixture(
            "f",
            FixtureCategory::HookState,
            FixturePriority::High,
        ))
        .unwrap();
    corpus.freeze().unwrap();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    pkg.freeze(1).unwrap();
    let baseline = FrozenBaseline::create(
        pkg,
        "cut-1".to_string(),
        2,
        vec![ConsumerLane::Compiler, ConsumerLane::Runtime],
    )
    .unwrap();
    assert!(baseline.serves_lane(&ConsumerLane::Compiler));
    assert!(baseline.serves_lane(&ConsumerLane::Runtime));
    assert!(!baseline.serves_lane(&ConsumerLane::Governance));
}

// ===========================================================================
// 22) SemanticContractFoundation — full lifecycle
// ===========================================================================

#[test]
fn foundation_register_package_and_freeze_baseline() {
    let mut foundation = SemanticContractFoundation::new();

    let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    corpus
        .add_fixture(make_fixture(
            "f",
            FixtureCategory::HookState,
            FixturePriority::High,
        ))
        .unwrap();
    corpus.freeze().unwrap();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    pkg.freeze(1).unwrap();

    foundation.register_package(pkg);
    assert!(foundation.latest_package().is_some());

    let idx = foundation
        .freeze_baseline(
            0,
            "cut-line-1".to_string(),
            2,
            vec![ConsumerLane::Verification],
        )
        .unwrap();
    assert_eq!(idx, 0);
    assert!(foundation.latest_baseline().is_some());
}

// ===========================================================================
// 23) Version compatibility edge cases
// ===========================================================================

#[test]
fn version_incompatible_major() {
    let v1 = SemanticContractVersion {
        major: 1,
        minor: 0,
        patch: 0,
    };
    let v2 = SemanticContractVersion {
        major: 2,
        minor: 0,
        patch: 0,
    };
    assert!(!v1.is_compatible_with(&v2));
}

// ===========================================================================
// 24) FixturePriority weight_millionths exact values
// ===========================================================================

#[test]
fn fixture_priority_weight_millionths_exact() {
    assert_eq!(FixturePriority::Critical.weight_millionths(), 1_000_000);
    assert_eq!(FixturePriority::High.weight_millionths(), 750_000);
    assert_eq!(FixturePriority::Medium.weight_millionths(), 500_000);
    assert_eq!(FixturePriority::Low.weight_millionths(), 250_000);
}
