#![forbid(unsafe_code)]
//! Integration tests for the `semantic_contract_baseline` module.
//!
//! Exercises corpus construction, contract packages, hook/effect semantics,
//! drift detection, frozen baselines, local semantic atlas, and serde
//! round-trips from outside the crate boundary.

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

use std::collections::BTreeMap;

use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::semantic_contract_baseline::{
    CompatibilityCorpus, ConsumerLane, ContractPackage, DomMutation, DriftDetector, DriftKind,
    EffectKind, EffectSemanticContract, FixtureCategory, FixturePriority, FoundationError,
    FrozenBaseline, HookKind, HookSemanticContract, LocalSemanticAtlas, LocalSemanticAtlasInput,
    MutationKind, SEMANTIC_CONTRACT_SCHEMA_VERSION, SemanticContractFoundation,
    SemanticContractVersion, SideEffectBoundary, TraceFixture, ViolationSeverity,
};

// ===========================================================================
// Helpers
// ===========================================================================

fn test_fixture(name: &str, category: FixtureCategory) -> TraceFixture {
    // Derive a unique ID from the fixture name so multiple fixtures don't collide.
    let hex = ContentHash::compute(name.as_bytes()).to_hex();
    let id_hex = if hex.len() >= 64 {
        hex[..64].to_string()
    } else {
        "a".repeat(64)
    };
    TraceFixture {
        id: EngineObjectId::from_hex(&id_hex).unwrap(),
        name: name.into(),
        category,
        priority: FixturePriority::High,
        input_hash: ContentHash::compute(name.as_bytes()),
        expected_trace_hash: ContentHash::compute(format!("{name}-trace").as_bytes()),
        expected_dom_mutations: vec![DomMutation {
            target_path: "/div[0]".into(),
            kind: MutationKind::SetAttribute,
            value: "class=test".into(),
        }],
        expected_effect_order: vec!["mount".into(), "update".into()],
        metadata: BTreeMap::new(),
    }
}

fn fixture_id_for(name: &str) -> EngineObjectId {
    let hex = ContentHash::compute(name.as_bytes()).to_hex();
    EngineObjectId::from_hex(&hex[..64]).unwrap()
}

fn test_corpus() -> CompatibilityCorpus {
    let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    corpus
        .add_fixture(test_fixture("hook-state-basic", FixtureCategory::HookState))
        .unwrap();
    corpus
        .add_fixture(test_fixture(
            "hook-effect-basic",
            FixtureCategory::HookEffect,
        ))
        .unwrap();
    corpus
}

// ===========================================================================
// 1. SemanticContractVersion — comparison, display, serde
// ===========================================================================

#[test]
fn version_current() {
    let v = SemanticContractVersion::CURRENT;
    assert_eq!(v.major, 0);
    assert_eq!(v.minor, 1);
    assert_eq!(v.patch, 0);
}

#[test]
fn version_compatibility() {
    let v1 = SemanticContractVersion {
        major: 1,
        minor: 0,
        patch: 0,
    };
    let v2 = SemanticContractVersion {
        major: 1,
        minor: 1,
        patch: 0,
    };
    let v3 = SemanticContractVersion {
        major: 2,
        minor: 0,
        patch: 0,
    };
    // v2 (minor=1) is compatible with v1 (minor=0) since v2.minor >= v1.minor
    assert!(v2.is_compatible_with(&v1));
    // v1 (minor=0) is NOT compatible with v2 (minor=1) since 0 < 1
    assert!(!v1.is_compatible_with(&v2));
    // Different major versions are never compatible
    assert!(!v1.is_compatible_with(&v3));
}

#[test]
fn version_display() {
    let v = SemanticContractVersion::CURRENT;
    let s = v.to_string();
    assert!(s.contains('.'));
}

#[test]
fn version_serde_round_trip() {
    let v = SemanticContractVersion::CURRENT;
    let json = serde_json::to_string(&v).unwrap();
    let back: SemanticContractVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

// ===========================================================================
// 2. Constants
// ===========================================================================

#[test]
fn schema_version_constant_nonempty() {
    assert!(!SEMANTIC_CONTRACT_SCHEMA_VERSION.is_empty());
}

// ===========================================================================
// 3. FixtureCategory / FixturePriority — serde
// ===========================================================================

#[test]
fn fixture_category_serde_round_trip() {
    for cat in [
        FixtureCategory::HookState,
        FixtureCategory::HookEffect,
        FixtureCategory::Suspense,
        FixtureCategory::Hydration,
        FixtureCategory::Portal,
    ] {
        let json = serde_json::to_string(&cat).unwrap();
        let back: FixtureCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cat);
    }
}

#[test]
fn fixture_priority_weight_ordering() {
    assert!(
        FixturePriority::Critical.weight_millionths() > FixturePriority::High.weight_millionths()
    );
    assert!(
        FixturePriority::High.weight_millionths() > FixturePriority::Medium.weight_millionths()
    );
    assert!(FixturePriority::Medium.weight_millionths() > FixturePriority::Low.weight_millionths());
}

#[test]
fn fixture_priority_serde_round_trip() {
    for p in [
        FixturePriority::Critical,
        FixturePriority::High,
        FixturePriority::Medium,
        FixturePriority::Low,
    ] {
        let json = serde_json::to_string(&p).unwrap();
        let back: FixturePriority = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }
}

// ===========================================================================
// 4. CompatibilityCorpus — construction, freeze, coverage
// ===========================================================================

#[test]
fn corpus_new_empty() {
    let c = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    assert!(c.fixtures.is_empty());
    assert!(!c.frozen);
}

#[test]
fn corpus_add_fixture() {
    let mut c = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    c.add_fixture(test_fixture("test-1", FixtureCategory::HookState))
        .unwrap();
    assert_eq!(c.fixtures.len(), 1);
}

#[test]
fn corpus_freeze() {
    let mut c = test_corpus();
    c.freeze().unwrap();
    assert!(c.frozen);
    // Adding after freeze should fail
    let err = c
        .add_fixture(test_fixture("extra", FixtureCategory::Suspense))
        .unwrap_err();
    assert!(matches!(err, FoundationError::CorpusAlreadyFrozen));
}

#[test]
fn corpus_fixtures_by_priority() {
    let c = test_corpus();
    let by_priority = c.fixtures_by_priority();
    assert_eq!(by_priority.len(), 2);
}

#[test]
fn corpus_fixtures_by_category() {
    let c = test_corpus();
    let hook_state = c.fixtures_by_category(&FixtureCategory::HookState);
    assert_eq!(hook_state.len(), 1);
    let suspense = c.fixtures_by_category(&FixtureCategory::Suspense);
    assert!(suspense.is_empty());
}

#[test]
fn corpus_coverage_score() {
    let c = test_corpus();
    let score = c.coverage_score_millionths();
    assert!(score > 0, "coverage should be >0 with fixtures");
}

#[test]
fn corpus_serde_round_trip() {
    let c = test_corpus();
    let json = serde_json::to_string(&c).unwrap();
    let back: CompatibilityCorpus = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

// ===========================================================================
// 5. HookSemanticContract
// ===========================================================================

#[test]
fn hook_contract_canonical_use_state() {
    let c = HookSemanticContract::canonical_use_state();
    assert_eq!(c.hook_kind, HookKind::UseState);
    assert!(!c.invocation_rules.is_empty());
}

#[test]
fn hook_contract_canonical_use_effect() {
    let c = HookSemanticContract::canonical_use_effect();
    assert_eq!(c.hook_kind, HookKind::UseEffect);
}

#[test]
fn hook_contract_hash_deterministic() {
    let c1 = HookSemanticContract::canonical_use_state();
    let c2 = HookSemanticContract::canonical_use_state();
    assert_eq!(c1.contract_hash(), c2.contract_hash());
}

#[test]
fn hook_contract_serde_round_trip() {
    let c = HookSemanticContract::canonical_use_state();
    let json = serde_json::to_string(&c).unwrap();
    let back: HookSemanticContract = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

// ===========================================================================
// 6. EffectSemanticContract
// ===========================================================================

#[test]
fn effect_contract_canonical_dom_mutation() {
    let c = EffectSemanticContract::canonical_dom_mutation();
    assert_eq!(c.effect_kind, EffectKind::DomMutation);
    assert!(c.is_deterministic());
}

#[test]
fn effect_contract_canonical_state_update() {
    let c = EffectSemanticContract::canonical_state_update();
    assert_eq!(c.effect_kind, EffectKind::StateUpdate);
}

#[test]
fn effect_contract_hash_deterministic() {
    let c1 = EffectSemanticContract::canonical_dom_mutation();
    let c2 = EffectSemanticContract::canonical_dom_mutation();
    assert_eq!(c1.contract_hash(), c2.contract_hash());
}

#[test]
fn effect_contract_serde_round_trip() {
    let c = EffectSemanticContract::canonical_dom_mutation();
    let json = serde_json::to_string(&c).unwrap();
    let back: EffectSemanticContract = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

// ===========================================================================
// 7. ContractPackage — build, validate, freeze
// ===========================================================================

#[test]
fn contract_package_new() {
    let corpus = test_corpus();
    let pkg = ContractPackage::new(corpus).unwrap();
    assert!(!pkg.is_frozen());
    assert_eq!(pkg.total_contracts(), 0);
}

#[test]
fn contract_package_add_contracts() {
    let corpus = test_corpus();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    pkg.add_effect_contract(EffectSemanticContract::canonical_dom_mutation())
        .unwrap();
    assert_eq!(pkg.total_contracts(), 2);
}

#[test]
fn contract_package_freeze() {
    let corpus = test_corpus();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    pkg.freeze(100).unwrap();
    assert!(pkg.is_frozen());

    // Adding after freeze should fail
    let err = pkg
        .add_hook_contract(HookSemanticContract::canonical_use_effect())
        .unwrap_err();
    assert!(matches!(err, FoundationError::PackageAlreadyFrozen));
}

#[test]
fn contract_package_validate() {
    let corpus = test_corpus();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    let validation = pkg.validate().unwrap();
    assert!(validation.hook_coverage_count > 0);
}

#[test]
fn contract_package_serde_round_trip() {
    let corpus = test_corpus();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    let json = serde_json::to_string(&pkg).unwrap();
    let back: ContractPackage = serde_json::from_str(&json).unwrap();
    assert_eq!(back, pkg);
}

// ===========================================================================
// 8. FrozenBaseline
// ===========================================================================

#[test]
fn frozen_baseline_create() {
    let corpus = test_corpus();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    let baseline = FrozenBaseline::create(
        pkg,
        "cut-1".into(),
        200,
        vec![ConsumerLane::Compiler, ConsumerLane::Runtime],
    )
    .unwrap();
    assert_eq!(baseline.cut_line_id, "cut-1");
    assert_eq!(baseline.freeze_epoch, 200);
    assert!(baseline.serves_lane(&ConsumerLane::Compiler));
    assert!(baseline.serves_lane(&ConsumerLane::Runtime));
    assert!(!baseline.serves_lane(&ConsumerLane::Governance));
}

#[test]
fn frozen_baseline_serde_round_trip() {
    let corpus = test_corpus();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    let baseline =
        FrozenBaseline::create(pkg, "cut-1".into(), 200, vec![ConsumerLane::Compiler]).unwrap();
    let json = serde_json::to_string(&baseline).unwrap();
    let back: FrozenBaseline = serde_json::from_str(&json).unwrap();
    assert_eq!(back, baseline);
}

// ===========================================================================
// 9. DriftDetector
// ===========================================================================

fn test_baseline() -> FrozenBaseline {
    let corpus = test_corpus();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    pkg.add_effect_contract(EffectSemanticContract::canonical_dom_mutation())
        .unwrap();
    FrozenBaseline::create(
        pkg,
        "cut-1".into(),
        100,
        vec![ConsumerLane::Compiler, ConsumerLane::Runtime],
    )
    .unwrap()
}

#[test]
fn drift_detector_new_no_alerts() {
    let detector = DriftDetector::new(test_baseline());
    assert_eq!(detector.fatal_alert_count(), 0);
    assert!(!detector.exceeds_threshold());
}

#[test]
fn drift_detector_check_trace_compliance() {
    let mut detector = DriftDetector::new(test_baseline());
    let fixture_id = fixture_id_for("hook-state-basic");
    // Use a mismatched hash to trigger drift
    let wrong_hash = ContentHash::compute(b"wrong");
    let alert =
        detector.check_trace_compliance(&fixture_id, &wrong_hash, ConsumerLane::Compiler, 200);
    // Should detect semantic regression
    assert!(alert.is_some());
}

#[test]
fn drift_detector_check_effect_boundary() {
    let mut detector = DriftDetector::new(test_baseline());
    let alert = detector.check_effect_boundary(
        &EffectKind::DomMutation,
        &SideEffectBoundary::Leaks,
        ConsumerLane::Runtime,
        200,
    );
    assert!(alert.is_some());
}

#[test]
fn drift_detector_check_hook_ordering() {
    let mut detector = DriftDetector::new(test_baseline());
    // Conditional hook call should be a violation
    let alert = detector.check_hook_ordering(
        &HookKind::UseState,
        true, // is_conditional
        ConsumerLane::Compiler,
        200,
    );
    assert!(alert.is_some());
}

#[test]
fn drift_detector_alerts_for_lane() {
    let mut detector = DriftDetector::new(test_baseline());
    detector.check_hook_ordering(&HookKind::UseState, true, ConsumerLane::Compiler, 200);
    let compiler_alerts = detector.alerts_for_lane(&ConsumerLane::Compiler);
    assert!(!compiler_alerts.is_empty());
    let runtime_alerts = detector.alerts_for_lane(&ConsumerLane::Runtime);
    assert!(runtime_alerts.is_empty());
}

#[test]
fn drift_detector_summary() {
    let mut detector = DriftDetector::new(test_baseline());
    detector.check_hook_ordering(&HookKind::UseState, true, ConsumerLane::Compiler, 200);
    let summary = detector.summary();
    assert_eq!(summary.total_alerts, 1);
    assert!(summary.total_alerts > 0);
}

#[test]
fn drift_detector_serde_round_trip() {
    let detector = DriftDetector::new(test_baseline());
    let json = serde_json::to_string(&detector).unwrap();
    let back: DriftDetector = serde_json::from_str(&json).unwrap();
    assert_eq!(back, detector);
}

// ===========================================================================
// 10. SemanticContractFoundation
// ===========================================================================

#[test]
fn foundation_new_empty() {
    let f = SemanticContractFoundation::new();
    assert!(f.packages.is_empty());
    assert!(f.frozen_baselines.is_empty());
    assert!(f.drift_detector.is_none());
    assert!(f.event_log.is_empty());
}

#[test]
fn foundation_register_and_freeze() {
    let mut f = SemanticContractFoundation::new();
    let corpus = test_corpus();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    f.register_package(pkg);
    assert_eq!(f.packages.len(), 1);

    let idx = f
        .freeze_baseline(0, "cut-1".into(), 100, vec![ConsumerLane::Compiler])
        .unwrap();
    assert_eq!(idx, 0);
    assert_eq!(f.frozen_baselines.len(), 1);
}

#[test]
fn foundation_activate_drift_detection() {
    let mut f = SemanticContractFoundation::new();
    let corpus = test_corpus();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    f.register_package(pkg);
    f.freeze_baseline(0, "cut-1".into(), 100, vec![ConsumerLane::Compiler])
        .unwrap();
    f.activate_drift_detection(0).unwrap();
    assert!(f.drift_detector.is_some());
}

#[test]
fn foundation_serde_round_trip() {
    let f = SemanticContractFoundation::new();
    let json = serde_json::to_string(&f).unwrap();
    let back: SemanticContractFoundation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, f);
}

// ===========================================================================
// 11. LocalSemanticAtlas
// ===========================================================================

#[test]
fn local_atlas_from_inputs() {
    let inputs = vec![LocalSemanticAtlasInput {
        component: frankenengine_engine::static_analysis_graph::ComponentDescriptor {
            id: frankenengine_engine::static_analysis_graph::ComponentId::new("src/App.tsx"),
            is_function_component: true,
            module_path: "src/App.tsx".into(),
            export_name: Some("App".into()),
            hook_slots: vec![
                frankenengine_engine::static_analysis_graph::HookSlot {
                    slot_index: 0,
                    kind: frankenengine_engine::static_analysis_graph::HookKind::State,
                    label: "useState".into(),
                    dependency_count: None,
                    has_cleanup: false,
                    source_offset: 0,
                    dependency_hash: None,
                },
                frankenengine_engine::static_analysis_graph::HookSlot {
                    slot_index: 1,
                    kind: frankenengine_engine::static_analysis_graph::HookKind::Effect,
                    label: "useEffect".into(),
                    dependency_count: None,
                    has_cleanup: true,
                    source_offset: 0,
                    dependency_hash: None,
                },
            ],
            props: BTreeMap::new(),
            consumed_contexts: vec!["ThemeContext".into()],
            provided_contexts: vec![],
            capability_boundary: {
                let mut cb =
                    frankenengine_engine::static_analysis_graph::CapabilityBoundary::pure_component(
                    );
                cb.direct_capabilities.insert("fs.read".to_string());
                cb.hook_effects.push(
                    frankenengine_engine::static_analysis_graph::EffectClassification {
                        boundary: frankenengine_engine::ir_contract::EffectBoundary::WriteEffect,
                        required_capabilities: ["fs.read".to_string()].into_iter().collect(),
                        idempotent: false,
                        commutative: false,
                        estimated_cost_millionths: 0,
                    },
                );
                cb
            },
            is_pure: false,
            content_hash: ContentHash::compute(b"App"),
            children: vec![],
        },
        fixture_refs: vec!["fix-1".into()],
        trace_refs: vec!["trace-1".into()],
        assumption_keys: vec!["ssr.enabled".into()],
    }];
    let atlas = LocalSemanticAtlas::from_inputs(SemanticContractVersion::CURRENT, 1, inputs);
    assert_eq!(atlas.entries.len(), 1);
    assert!(atlas.entry("src/App.tsx").is_some());
}

#[test]
fn local_atlas_validate() {
    let inputs = vec![LocalSemanticAtlasInput {
        component: frankenengine_engine::static_analysis_graph::ComponentDescriptor {
            id: frankenengine_engine::static_analysis_graph::ComponentId::new("src/App.tsx"),
            is_function_component: true,
            module_path: "src/App.tsx".into(),
            export_name: Some("App".into()),
            hook_slots: vec![frankenengine_engine::static_analysis_graph::HookSlot {
                slot_index: 0,
                kind: frankenengine_engine::static_analysis_graph::HookKind::State,
                label: "useState".into(),
                dependency_count: None,
                has_cleanup: false,
                source_offset: 0,
                dependency_hash: None,
            }],
            props: BTreeMap::new(),
            consumed_contexts: vec![],
            provided_contexts: vec![],
            capability_boundary:
                frankenengine_engine::static_analysis_graph::CapabilityBoundary::pure_component(),
            is_pure: false,
            content_hash: ContentHash::compute(b"App"),
            children: vec![],
        },
        fixture_refs: vec!["fix-1".into()],
        trace_refs: vec!["trace-1".into()],
        assumption_keys: vec!["key-1".into()],
    }];
    let atlas = LocalSemanticAtlas::from_inputs(SemanticContractVersion::CURRENT, 1, inputs);
    let validation = atlas.validate();
    assert_eq!(validation.entry_count, 1);
}

#[test]
fn local_atlas_serde_round_trip() {
    let atlas = LocalSemanticAtlas::from_inputs(SemanticContractVersion::CURRENT, 1, vec![]);
    let json = serde_json::to_string(&atlas).unwrap();
    let back: LocalSemanticAtlas = serde_json::from_str(&json).unwrap();
    assert_eq!(back, atlas);
}

// ===========================================================================
// 12. Enum serde round-trips
// ===========================================================================

#[test]
fn hook_kind_serde_round_trip() {
    for k in [
        HookKind::UseState,
        HookKind::UseEffect,
        HookKind::UseMemo,
        HookKind::UseRef,
        HookKind::UseReducer,
        HookKind::UseContext,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: HookKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }
}

#[test]
fn consumer_lane_serde_round_trip() {
    for l in [
        ConsumerLane::Compiler,
        ConsumerLane::Runtime,
        ConsumerLane::Verification,
        ConsumerLane::Optimization,
        ConsumerLane::Governance,
        ConsumerLane::Adoption,
    ] {
        let json = serde_json::to_string(&l).unwrap();
        let back: ConsumerLane = serde_json::from_str(&json).unwrap();
        assert_eq!(back, l);
    }
}

#[test]
fn drift_kind_serde_round_trip() {
    for k in [
        DriftKind::SemanticRegression,
        DriftKind::OrderingViolation,
        DriftKind::EffectBoundaryLeak,
        DriftKind::HookContractBreach,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: DriftKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }
}

#[test]
fn violation_severity_serde_round_trip() {
    for s in [
        ViolationSeverity::Fatal,
        ViolationSeverity::Error,
        ViolationSeverity::Warning,
        ViolationSeverity::Info,
    ] {
        let json = serde_json::to_string(&s).unwrap();
        let back: ViolationSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }
}

// ===========================================================================
// 13. FoundationError — display
// ===========================================================================

#[test]
fn foundation_error_display() {
    let errs = vec![
        FoundationError::CorpusAlreadyFrozen,
        FoundationError::EmptyCorpus,
        FoundationError::PackageAlreadyFrozen,
        FoundationError::NoConsumerLanes,
    ];
    for e in &errs {
        assert!(!e.to_string().is_empty());
    }
}

// ===========================================================================
// 14. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_corpus_to_drift_detection() {
    // 1. Build corpus
    let mut corpus = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    corpus
        .add_fixture(test_fixture("state-basic", FixtureCategory::HookState))
        .unwrap();
    corpus
        .add_fixture(test_fixture("effect-basic", FixtureCategory::HookEffect))
        .unwrap();
    corpus
        .add_fixture(test_fixture("suspense-basic", FixtureCategory::Suspense))
        .unwrap();
    assert_eq!(corpus.fixtures.len(), 3);

    // 2. Build contract package
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_effect())
        .unwrap();
    pkg.add_effect_contract(EffectSemanticContract::canonical_dom_mutation())
        .unwrap();
    pkg.add_effect_contract(EffectSemanticContract::canonical_state_update())
        .unwrap();
    assert_eq!(pkg.total_contracts(), 4);

    // 3. Validate
    let validation = pkg.validate().unwrap();
    assert!(validation.hook_coverage_count >= 2);
    assert!(validation.effect_contract_count >= 2);

    // 4. Freeze baseline
    let baseline = FrozenBaseline::create(
        pkg,
        "v0.1.0".into(),
        100,
        vec![
            ConsumerLane::Compiler,
            ConsumerLane::Runtime,
            ConsumerLane::Verification,
        ],
    )
    .unwrap();
    assert!(baseline.package.is_frozen());

    // 5. Activate drift detection
    let mut detector = DriftDetector::new(baseline);

    // 6. Check for drifts using an actual fixture ID
    let fixture_id = fixture_id_for("state-basic");
    let wrong_hash = ContentHash::compute(b"tampered");
    let alert =
        detector.check_trace_compliance(&fixture_id, &wrong_hash, ConsumerLane::Compiler, 200);
    assert!(alert.is_some());

    // 7. Verify summary
    let summary = detector.summary();
    assert!(summary.total_alerts > 0);

    // 8. Serde round-trip the whole detector
    let json = serde_json::to_string(&detector).unwrap();
    let _back: DriftDetector = serde_json::from_str(&json).unwrap();
}

// ===========================================================================
// 15. FixtureCategory — serde all 12 variants
// ===========================================================================

#[test]
fn fixture_category_serde_all_12_variants() {
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
    for cat in &all {
        let json = serde_json::to_string(cat).unwrap();
        let back: FixtureCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, cat);
    }
    // Verify count matches expectations
    assert_eq!(all.len(), 12);
}

// ===========================================================================
// 16. MutationKind — serde all 6 variants
// ===========================================================================

#[test]
fn mutation_kind_serde_all_variants() {
    let all = [
        MutationKind::SetAttribute,
        MutationKind::RemoveAttribute,
        MutationKind::AppendChild,
        MutationKind::RemoveChild,
        MutationKind::SetTextContent,
        MutationKind::InsertBefore,
    ];
    for kind in &all {
        let json = serde_json::to_string(kind).unwrap();
        let back: MutationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, kind);
    }
    assert_eq!(all.len(), 6);
}

// ===========================================================================
// 17. DomMutation / TraceFixture serde
// ===========================================================================

#[test]
fn dom_mutation_serde_roundtrip() {
    let dm = DomMutation {
        target_path: "/div[0]/span[1]".into(),
        kind: MutationKind::AppendChild,
        value: "new-child".into(),
    };
    let json = serde_json::to_string(&dm).unwrap();
    let back: DomMutation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, dm);
}

#[test]
fn trace_fixture_serde_roundtrip() {
    let f = test_fixture("roundtrip-fix", FixtureCategory::Suspense);
    let json = serde_json::to_string(&f).unwrap();
    let back: TraceFixture = serde_json::from_str(&json).unwrap();
    assert_eq!(back, f);
}

// ===========================================================================
// 18. CompatibilityCorpus — edge cases
// ===========================================================================

#[test]
fn corpus_duplicate_fixture_rejected() {
    let mut c = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    let f = test_fixture("dup", FixtureCategory::HookState);
    c.add_fixture(f.clone()).unwrap();
    let err = c.add_fixture(f).unwrap_err();
    assert!(matches!(err, FoundationError::DuplicateFixture));
}

#[test]
fn corpus_freeze_empty_fails() {
    let mut c = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    let err = c.freeze().unwrap_err();
    assert!(matches!(err, FoundationError::EmptyCorpus));
}

#[test]
fn corpus_freeze_twice_fails() {
    let mut c = test_corpus();
    c.freeze().unwrap();
    let err = c.freeze().unwrap_err();
    assert!(matches!(err, FoundationError::CorpusAlreadyFrozen));
}

#[test]
fn corpus_coverage_empty_is_zero() {
    let c = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    assert_eq!(c.coverage_score_millionths(), 0);
}

#[test]
fn corpus_weighted_priority_score_empty_is_zero() {
    let c = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    assert_eq!(c.weighted_priority_score_millionths(), 0);
}

#[test]
fn corpus_weighted_priority_score_single_critical() {
    let mut c = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    let mut f = test_fixture("crit", FixtureCategory::HookState);
    f.priority = FixturePriority::Critical;
    c.add_fixture(f).unwrap();
    assert_eq!(c.weighted_priority_score_millionths(), 1_000_000);
}

#[test]
fn corpus_hash_changes_on_add() {
    let mut c = CompatibilityCorpus::new(SemanticContractVersion::CURRENT, 1);
    let h1 = c.corpus_hash;
    c.add_fixture(test_fixture("change-hash", FixtureCategory::Portal))
        .unwrap();
    assert_ne!(c.corpus_hash, h1);
}

// ===========================================================================
// 19. EffectKind / EffectTiming / SideEffectBoundary / DeterminismLevel serde
// ===========================================================================

#[test]
fn effect_kind_serde_all_6_variants() {
    let all = [
        EffectKind::DomMutation,
        EffectKind::NetworkIo,
        EffectKind::TimerSetup,
        EffectKind::StateUpdate,
        EffectKind::Subscription,
        EffectKind::CustomEffect,
    ];
    for kind in &all {
        let json = serde_json::to_string(kind).unwrap();
        let back: EffectKind = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, kind);
    }
    assert_eq!(all.len(), 6);
}

#[test]
fn effect_timing_serde_all_4_variants() {
    use frankenengine_engine::semantic_contract_baseline::EffectTiming;
    let all = [
        EffectTiming::AfterRender,
        EffectTiming::BeforePaint,
        EffectTiming::Synchronous,
        EffectTiming::Deferred,
    ];
    for t in &all {
        let json = serde_json::to_string(t).unwrap();
        let back: EffectTiming = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, t);
    }
    assert_eq!(all.len(), 4);
}

#[test]
fn side_effect_boundary_serde_all_3_variants() {
    for b in [
        SideEffectBoundary::Contained,
        SideEffectBoundary::Leaks,
        SideEffectBoundary::Unknown,
    ] {
        let json = serde_json::to_string(&b).unwrap();
        let back: SideEffectBoundary = serde_json::from_str(&json).unwrap();
        assert_eq!(back, b);
    }
}

#[test]
fn determinism_level_serde_all_3_variants() {
    use frankenengine_engine::semantic_contract_baseline::DeterminismLevel;
    let all = [
        DeterminismLevel::FullyDeterministic,
        DeterminismLevel::OrderDeterministic,
        DeterminismLevel::Nondeterministic,
    ];
    for d in &all {
        let json = serde_json::to_string(d).unwrap();
        let back: DeterminismLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, d);
    }
}

// ===========================================================================
// 20. HookKind — all 10 variants (existing test covers only 6)
// ===========================================================================

#[test]
fn hook_kind_serde_all_10_variants() {
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
    for k in &all {
        let json = serde_json::to_string(k).unwrap();
        let back: HookKind = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, k);
    }
    assert_eq!(all.len(), 10);
}

// ===========================================================================
// 21. InvocationRule / CleanupPolicy serde
// ===========================================================================

#[test]
fn invocation_rule_serde_all_5_variants() {
    use frankenengine_engine::semantic_contract_baseline::InvocationRule;
    let all = [
        InvocationRule::MustBeTopLevel,
        InvocationRule::MustNotBeConditional,
        InvocationRule::MustNotBeInLoop,
        InvocationRule::MustBeInFunctionComponent,
        InvocationRule::OrderPreservedAcrossRenders,
    ];
    for r in &all {
        let json = serde_json::to_string(r).unwrap();
        let back: InvocationRule = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, r);
    }
}

#[test]
fn cleanup_policy_serde_all_4_variants() {
    use frankenengine_engine::semantic_contract_baseline::CleanupPolicy;
    let all = [
        CleanupPolicy::RunOnUnmount,
        CleanupPolicy::RunBeforeRerun,
        CleanupPolicy::NoCleanup,
        CleanupPolicy::ConditionalCleanup,
    ];
    for p in &all {
        let json = serde_json::to_string(p).unwrap();
        let back: CleanupPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, p);
    }
}

// ===========================================================================
// 22. OrderingConstraint / ForbiddenPattern serde
// ===========================================================================

#[test]
fn ordering_constraint_serde_roundtrip() {
    use frankenengine_engine::semantic_contract_baseline::OrderingConstraint;
    let oc = OrderingConstraint {
        before: "useState".into(),
        after: "useEffect".into(),
        strict: true,
    };
    let json = serde_json::to_string(&oc).unwrap();
    let back: OrderingConstraint = serde_json::from_str(&json).unwrap();
    assert_eq!(back, oc);
}

#[test]
fn forbidden_pattern_serde_roundtrip() {
    use frankenengine_engine::semantic_contract_baseline::ForbiddenPattern;
    let fp = ForbiddenPattern {
        description: "Conditional hook invocation".into(),
        pattern_hash: ContentHash::compute(b"conditional_hook"),
        severity: ViolationSeverity::Fatal,
    };
    let json = serde_json::to_string(&fp).unwrap();
    let back: ForbiddenPattern = serde_json::from_str(&json).unwrap();
    assert_eq!(back, fp);
}

// ===========================================================================
// 23. EffectSemanticContract — is_deterministic
// ===========================================================================

#[test]
fn effect_contract_fully_deterministic_is_deterministic() {
    let c = EffectSemanticContract::canonical_dom_mutation();
    assert!(c.is_deterministic());
}

#[test]
fn effect_contract_nondeterministic_network_io() {
    use frankenengine_engine::semantic_contract_baseline::{DeterminismLevel, EffectTiming};
    let c = EffectSemanticContract {
        effect_kind: EffectKind::NetworkIo,
        timing: EffectTiming::Deferred,
        capability_requirements: vec!["network.fetch".into()],
        side_effect_boundary: SideEffectBoundary::Leaks,
        determinism_guarantee: DeterminismLevel::Nondeterministic,
    };
    assert!(!c.is_deterministic());
}

// ===========================================================================
// 24. AdjudicationCategory / AdjudicationResolution serde
// ===========================================================================

#[test]
fn adjudication_category_serde_all_5_variants() {
    use frankenengine_engine::semantic_contract_baseline::AdjudicationCategory;
    let all = [
        AdjudicationCategory::AmbiguousOrdering,
        AdjudicationCategory::UndefinedEdgeCase,
        AdjudicationCategory::VersionConflict,
        AdjudicationCategory::PlatformDivergence,
        AdjudicationCategory::SpecGap,
    ];
    for c in &all {
        let json = serde_json::to_string(c).unwrap();
        let back: AdjudicationCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, c);
    }
}

#[test]
fn adjudication_resolution_serde_all_4_variants() {
    use frankenengine_engine::semantic_contract_baseline::AdjudicationResolution;
    let all = [
        AdjudicationResolution::PreferReactBehavior,
        AdjudicationResolution::PreferDeterministic,
        AdjudicationResolution::PreferConservative,
        AdjudicationResolution::RequireExplicitFallback,
    ];
    for r in &all {
        let json = serde_json::to_string(r).unwrap();
        let back: AdjudicationResolution = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, r);
    }
}

// ===========================================================================
// 25. AdjudicationRule — serde + hash
// ===========================================================================

#[test]
fn adjudication_rule_serde_and_hash() {
    use frankenengine_engine::semantic_contract_baseline::{
        AdjudicationCategory, AdjudicationResolution, AdjudicationRule,
    };
    let rule = AdjudicationRule {
        id: fixture_id_for("adj-rule-1"),
        name: "ordering-ambiguity-setState".into(),
        category: AdjudicationCategory::AmbiguousOrdering,
        condition: "setState called during render phase".into(),
        resolution: AdjudicationResolution::PreferReactBehavior,
        rationale: "React batches setState calls inside event handlers".into(),
        precedent_fixture_ids: vec![fixture_id_for("precedent-1")],
    };
    let json = serde_json::to_string(&rule).unwrap();
    let back: AdjudicationRule = serde_json::from_str(&json).unwrap();
    assert_eq!(back, rule);

    // Hash is deterministic
    assert_eq!(rule.rule_hash(), rule.rule_hash());
}

// ===========================================================================
// 26. ContractPackage — adjudication, freeze empty, validate
// ===========================================================================

#[test]
fn contract_package_add_adjudication_rule() {
    use frankenengine_engine::semantic_contract_baseline::{
        AdjudicationCategory, AdjudicationResolution, AdjudicationRule,
    };
    let corpus = test_corpus();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    let rule = AdjudicationRule {
        id: fixture_id_for("adj-test"),
        name: "test-rule".into(),
        category: AdjudicationCategory::SpecGap,
        condition: "spec unclear".into(),
        resolution: AdjudicationResolution::PreferConservative,
        rationale: "conservative approach".into(),
        precedent_fixture_ids: vec![],
    };
    pkg.add_adjudication_rule(rule).unwrap();
    let v = pkg.validate().unwrap();
    assert_eq!(v.adjudication_rule_count, 1);
}

#[test]
fn contract_package_freeze_empty_fails() {
    let corpus = test_corpus();
    let pkg = ContractPackage::new(corpus).unwrap();
    // Package has no contracts, so freeze should fail
    let mut pkg = pkg;
    let err = pkg.freeze(100).unwrap_err();
    assert!(matches!(err, FoundationError::EmptyPackage));
}

#[test]
fn contract_package_validate_low_coverage_warns() {
    let corpus = test_corpus(); // Only 2 categories covered out of 12
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    let v = pkg.validate().unwrap();
    assert!(v.coverage_millionths < 500_000);
    assert!(!v.warnings.is_empty());
}

#[test]
fn contract_package_validate_nondeterministic_warns() {
    use frankenengine_engine::semantic_contract_baseline::{DeterminismLevel, EffectTiming};
    let corpus = test_corpus();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_effect_contract(EffectSemanticContract {
        effect_kind: EffectKind::NetworkIo,
        timing: EffectTiming::Deferred,
        capability_requirements: vec!["net".into()],
        side_effect_boundary: SideEffectBoundary::Leaks,
        determinism_guarantee: DeterminismLevel::Nondeterministic,
    })
    .unwrap();
    let v = pkg.validate().unwrap();
    assert!(v.warnings.iter().any(|w| w.contains("non-deterministic")));
}

#[test]
fn package_validation_serde_roundtrip() {
    use frankenengine_engine::semantic_contract_baseline::PackageValidation;
    let corpus = test_corpus();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    let v = pkg.validate().unwrap();
    let json = serde_json::to_string(&v).unwrap();
    let back: PackageValidation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

// ===========================================================================
// 27. DriftKind — all 7 variants serde (existing covers only 4)
// ===========================================================================

#[test]
fn drift_kind_serde_all_7_variants() {
    let all = [
        DriftKind::SemanticRegression,
        DriftKind::OrderingViolation,
        DriftKind::EffectBoundaryLeak,
        DriftKind::HookContractBreach,
        DriftKind::AdjudicationOverride,
        DriftKind::CorpusCoverageDrop,
        DriftKind::VersionIncompatibility,
    ];
    for k in &all {
        let json = serde_json::to_string(k).unwrap();
        let back: DriftKind = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, k);
    }
    assert_eq!(all.len(), 7);
}

// ===========================================================================
// 28. DriftAlert / DriftSummary serde
// ===========================================================================

#[test]
fn drift_alert_serde_roundtrip() {
    use frankenengine_engine::semantic_contract_baseline::DriftAlert;
    let alert = DriftAlert {
        id: fixture_id_for("alert-1"),
        kind: DriftKind::EffectBoundaryLeak,
        severity: ViolationSeverity::Error,
        source_lane: ConsumerLane::Runtime,
        violated_contract_hash: Some(ContentHash::compute(b"contract")),
        description: "effect leaks side effects".into(),
        detected_epoch: 42,
        evidence_hash: ContentHash::compute(b"evidence"),
    };
    let json = serde_json::to_string(&alert).unwrap();
    let back: DriftAlert = serde_json::from_str(&json).unwrap();
    assert_eq!(back, alert);
}

#[test]
fn drift_summary_serde_roundtrip() {
    use frankenengine_engine::semantic_contract_baseline::DriftSummary;
    let mut detector = DriftDetector::new(test_baseline());
    detector.check_hook_ordering(&HookKind::UseState, true, ConsumerLane::Compiler, 300);
    let summary = detector.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let back: DriftSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, summary);
}

// ===========================================================================
// 29. DriftDetector — sensitivity, threshold
// ===========================================================================

#[test]
fn drift_detector_with_sensitivity() {
    let detector = DriftDetector::new(test_baseline()).with_sensitivity(100_000);
    assert_eq!(detector.sensitivity_threshold_millionths, 100_000);
}

#[test]
fn drift_detector_exceeds_threshold_with_fatal() {
    let mut detector = DriftDetector::new(test_baseline()).with_sensitivity(0);
    // Trigger a Fatal alert via conditional hook ordering
    detector.check_hook_ordering(&HookKind::UseState, true, ConsumerLane::Compiler, 300);
    // With sensitivity 0, any fatal alert should exceed threshold
    assert!(detector.exceeds_threshold());
}

#[test]
fn drift_detector_not_exceeds_threshold_no_alerts() {
    let detector = DriftDetector::new(test_baseline());
    assert!(!detector.exceeds_threshold());
}

#[test]
fn drift_detector_check_trace_unknown_fixture() {
    let mut detector = DriftDetector::new(test_baseline());
    let unknown_id = fixture_id_for("totally-unknown-fixture");
    let hash = ContentHash::compute(b"any");
    let alert = detector.check_trace_compliance(&unknown_id, &hash, ConsumerLane::Compiler, 200);
    assert!(alert.is_none(), "unknown fixture should return None");
}

#[test]
fn drift_detector_check_trace_matching_hash_no_alert() {
    let mut detector = DriftDetector::new(test_baseline());
    let id = fixture_id_for("hook-state-basic");
    let expected_hash = ContentHash::compute("hook-state-basic-trace".as_bytes());
    let alert = detector.check_trace_compliance(&id, &expected_hash, ConsumerLane::Compiler, 200);
    assert!(alert.is_none(), "matching trace should not produce alert");
}

#[test]
fn drift_detector_check_effect_boundary_contained_no_alert() {
    let mut detector = DriftDetector::new(test_baseline());
    let alert = detector.check_effect_boundary(
        &EffectKind::DomMutation,
        &SideEffectBoundary::Contained,
        ConsumerLane::Runtime,
        200,
    );
    assert!(alert.is_none());
}

#[test]
fn drift_detector_check_hook_non_conditional_no_alert() {
    let mut detector = DriftDetector::new(test_baseline());
    let alert = detector.check_hook_ordering(
        &HookKind::UseState,
        false, // not conditional
        ConsumerLane::Compiler,
        200,
    );
    assert!(alert.is_none());
}

// ===========================================================================
// 30. FoundationError — all 13 variants display + serde
// ===========================================================================

#[test]
fn foundation_error_all_13_variants_display() {
    let errors = [
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
        FoundationError::InvalidContract("test detail".into()),
        FoundationError::IncompatibleVersion,
    ];
    for e in &errors {
        let s = e.to_string();
        assert!(
            !s.is_empty(),
            "error {:?} should have a non-empty Display",
            e
        );
    }
    assert_eq!(errors.len(), 13);
}

#[test]
fn foundation_error_serde_all_variants() {
    let errors = [
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
        FoundationError::InvalidContract("test".into()),
        FoundationError::IncompatibleVersion,
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: FoundationError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, e);
    }
}

#[test]
fn foundation_error_invalid_contract_contains_message() {
    let err = FoundationError::InvalidContract("bad hook rule".into());
    assert!(err.to_string().contains("bad hook rule"));
}

// ===========================================================================
// 31. FoundationEvent serde
// ===========================================================================

#[test]
fn foundation_event_serde_all_variants() {
    use frankenengine_engine::semantic_contract_baseline::FoundationEvent;
    let events = [
        FoundationEvent::CorpusCreated {
            version: SemanticContractVersion::CURRENT,
            epoch: 1,
        },
        FoundationEvent::FixtureAdded {
            fixture_name: "f1".into(),
            category: FixtureCategory::HookState,
            priority: FixturePriority::Critical,
        },
        FoundationEvent::CorpusFrozen {
            fixture_count: 5,
            corpus_hash: ContentHash::compute(b"corpus"),
        },
        FoundationEvent::PackageCreated {
            version: SemanticContractVersion::CURRENT,
        },
        FoundationEvent::ContractAdded {
            contract_type: "hook".into(),
        },
        FoundationEvent::PackageFrozen {
            epoch: 100,
            package_hash: ContentHash::compute(b"pkg"),
        },
        FoundationEvent::BaselineFrozen {
            cut_line_id: "cut-1".into(),
            epoch: 200,
            baseline_hash: ContentHash::compute(b"bl"),
        },
        FoundationEvent::DriftDetected {
            kind: DriftKind::SemanticRegression,
            severity: ViolationSeverity::Error,
            lane: ConsumerLane::Runtime,
        },
    ];
    for event in &events {
        let json = serde_json::to_string(event).unwrap();
        let back: FoundationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, event);
    }
    assert_eq!(events.len(), 8);
}

// ===========================================================================
// 32. SemanticContractFoundation — Default, latest_*
// ===========================================================================

#[test]
fn foundation_default_trait() {
    let f: SemanticContractFoundation = Default::default();
    let f2 = SemanticContractFoundation::new();
    assert_eq!(f, f2);
}

#[test]
fn foundation_latest_baseline_none_when_empty() {
    let f = SemanticContractFoundation::new();
    assert!(f.latest_baseline().is_none());
}

#[test]
fn foundation_latest_package_none_when_empty() {
    let f = SemanticContractFoundation::new();
    assert!(f.latest_package().is_none());
}

#[test]
fn foundation_latest_baseline_returns_last() {
    let mut f = SemanticContractFoundation::new();
    let corpus = test_corpus();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    f.register_package(pkg);
    f.freeze_baseline(0, "cut-a".into(), 100, vec![ConsumerLane::Compiler])
        .unwrap();
    assert!(f.latest_baseline().is_some());
    assert_eq!(f.latest_baseline().unwrap().cut_line_id, "cut-a");
}

#[test]
fn foundation_latest_package_returns_last() {
    let mut f = SemanticContractFoundation::new();
    let corpus = test_corpus();
    let pkg = ContractPackage::new(corpus).unwrap();
    f.register_package(pkg);
    assert!(f.latest_package().is_some());
}

#[test]
fn foundation_package_not_found_error() {
    let mut f = SemanticContractFoundation::new();
    let err = f
        .freeze_baseline(99, "bad".into(), 100, vec![ConsumerLane::Compiler])
        .unwrap_err();
    assert!(matches!(err, FoundationError::PackageNotFound));
}

#[test]
fn foundation_baseline_not_found_error() {
    let mut f = SemanticContractFoundation::new();
    let err = f.activate_drift_detection(99).unwrap_err();
    assert!(matches!(err, FoundationError::BaselineNotFound));
}

// ===========================================================================
// 33. FrozenBaseline — no lanes error
// ===========================================================================

#[test]
fn frozen_baseline_no_lanes_fails() {
    let corpus = test_corpus();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    let err = FrozenBaseline::create(pkg, "cut-fail".into(), 100, vec![]).unwrap_err();
    assert!(matches!(err, FoundationError::NoConsumerLanes));
}

// ===========================================================================
// 34. LocalSemanticAtlas — debt, blocking, validate
// ===========================================================================

#[test]
fn atlas_quality_debt_missing_fixture_and_trace() {
    // An entry with empty fixture_refs and trace_refs should generate blocking debt
    let inputs = vec![LocalSemanticAtlasInput {
        component: frankenengine_engine::static_analysis_graph::ComponentDescriptor {
            id: frankenengine_engine::static_analysis_graph::ComponentId::new("src/Debt.tsx"),
            is_function_component: true,
            module_path: "src/Debt.tsx".into(),
            export_name: Some("Debt".into()),
            hook_slots: vec![frankenengine_engine::static_analysis_graph::HookSlot {
                slot_index: 0,
                kind: frankenengine_engine::static_analysis_graph::HookKind::State,
                label: "useState".into(),
                dependency_count: None,
                has_cleanup: false,
                source_offset: 0,
                dependency_hash: None,
            }],
            props: BTreeMap::new(),
            consumed_contexts: vec![],
            provided_contexts: vec![],
            capability_boundary:
                frankenengine_engine::static_analysis_graph::CapabilityBoundary::pure_component(),
            is_pure: false,
            content_hash: ContentHash::compute(b"Debt"),
            children: vec![],
        },
        fixture_refs: vec![], // empty -> debt
        trace_refs: vec![],   // empty -> debt
        assumption_keys: vec![],
    }];
    let atlas = LocalSemanticAtlas::from_inputs(SemanticContractVersion::CURRENT, 1, inputs);
    assert!(atlas.blocking_debt_count() > 0);
    let v = atlas.validate();
    assert!(!v.is_valid); // blocking debt makes it invalid
    assert!(v.blocking_debt_count > 0);
}

#[test]
fn atlas_validate_empty_warns() {
    let atlas = LocalSemanticAtlas::from_inputs(SemanticContractVersion::CURRENT, 1, vec![]);
    let v = atlas.validate();
    assert!(!v.warnings.is_empty());
    assert!(
        v.warnings
            .iter()
            .any(|w| w.contains("no component entries"))
    );
}

#[test]
fn atlas_validation_serde_roundtrip() {
    use frankenengine_engine::semantic_contract_baseline::LocalSemanticAtlasValidation;
    let atlas = LocalSemanticAtlas::from_inputs(SemanticContractVersion::CURRENT, 1, vec![]);
    let v = atlas.validate();
    let json = serde_json::to_string(&v).unwrap();
    let back: LocalSemanticAtlasValidation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn local_semantic_contract_debt_serde_roundtrip() {
    use frankenengine_engine::semantic_contract_baseline::LocalSemanticContractDebt;
    let debt = LocalSemanticContractDebt {
        component_id: "src/App.tsx".into(),
        debt_code: "FE-FRX-14-1-LOCAL-0001".into(),
        description: "missing fixture link".into(),
        blocking: true,
    };
    let json = serde_json::to_string(&debt).unwrap();
    let back: LocalSemanticContractDebt = serde_json::from_str(&json).unwrap();
    assert_eq!(back, debt);
}

// ===========================================================================
// 35. LocalSemanticAtlas constants
// ===========================================================================

#[test]
fn atlas_constants_nonempty() {
    use frankenengine_engine::semantic_contract_baseline::{
        LOCAL_SEMANTIC_ATLAS_BEAD_ID, LOCAL_SEMANTIC_ATLAS_DEBT_EMPTY_LOCAL_CONTRACT,
        LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_CONTEXT_ASSUMPTIONS,
        LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_FIXTURE_LINK,
        LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_TRACE_LINK, LOCAL_SEMANTIC_ATLAS_SCHEMA_VERSION,
    };
    assert!(!LOCAL_SEMANTIC_ATLAS_SCHEMA_VERSION.is_empty());
    assert!(!LOCAL_SEMANTIC_ATLAS_BEAD_ID.is_empty());
    assert!(!LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_FIXTURE_LINK.is_empty());
    assert!(!LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_TRACE_LINK.is_empty());
    assert!(!LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_CONTEXT_ASSUMPTIONS.is_empty());
    assert!(!LOCAL_SEMANTIC_ATLAS_DEBT_EMPTY_LOCAL_CONTRACT.is_empty());
}

// ===========================================================================
// 36. Version edge cases
// ===========================================================================

#[test]
fn version_compatible_with_self() {
    let v = SemanticContractVersion::CURRENT;
    assert!(v.is_compatible_with(&v));
}

#[test]
fn version_patch_ignored_for_compatibility() {
    let v1 = SemanticContractVersion {
        major: 1,
        minor: 2,
        patch: 0,
    };
    let v2 = SemanticContractVersion {
        major: 1,
        minor: 2,
        patch: 99,
    };
    assert!(v1.is_compatible_with(&v2));
    assert!(v2.is_compatible_with(&v1));
}

#[test]
fn version_ordering() {
    let v010 = SemanticContractVersion {
        major: 0,
        minor: 1,
        patch: 0,
    };
    let v020 = SemanticContractVersion {
        major: 0,
        minor: 2,
        patch: 0,
    };
    let v100 = SemanticContractVersion {
        major: 1,
        minor: 0,
        patch: 0,
    };
    assert!(v010 < v020);
    assert!(v020 < v100);
}

// ===========================================================================
// 37. FixturePriority — weight values
// ===========================================================================

#[test]
fn fixture_priority_weight_exact_values() {
    assert_eq!(FixturePriority::Critical.weight_millionths(), 1_000_000);
    assert_eq!(FixturePriority::High.weight_millionths(), 750_000);
    assert_eq!(FixturePriority::Medium.weight_millionths(), 500_000);
    assert_eq!(FixturePriority::Low.weight_millionths(), 250_000);
}

// ===========================================================================
// 38. Corpus hash recomputed after freeze
// ===========================================================================

#[test]
fn corpus_hash_changes_on_freeze() {
    let mut c = test_corpus();
    let hash_before = c.corpus_hash;
    c.freeze().unwrap();
    assert_ne!(c.corpus_hash, hash_before);
}

// ===========================================================================
// 39. Package hash changes with contracts
// ===========================================================================

#[test]
fn package_hash_changes_on_contract_addition() {
    let corpus = test_corpus();
    let mut pkg = ContractPackage::new(corpus).unwrap();
    let h1 = pkg.package_hash;
    pkg.add_hook_contract(HookSemanticContract::canonical_use_state())
        .unwrap();
    assert_ne!(pkg.package_hash, h1);
}

// ===========================================================================
// 40. DriftDetector summary breakdown
// ===========================================================================

#[test]
fn drift_summary_breakdown_by_severity() {
    let mut detector = DriftDetector::new(test_baseline());
    // Hook ordering produces Fatal
    detector.check_hook_ordering(&HookKind::UseState, true, ConsumerLane::Compiler, 300);
    // Effect boundary produces Error
    detector.check_effect_boundary(
        &EffectKind::DomMutation,
        &SideEffectBoundary::Leaks,
        ConsumerLane::Runtime,
        300,
    );
    let s = detector.summary();
    assert_eq!(s.total_alerts, 2);
    assert_eq!(s.fatal_count, 1);
    assert_eq!(s.error_count, 1);
    assert_eq!(s.warning_count, 0);
    assert_eq!(s.info_count, 0);
    assert!(
        s.alerts_by_kind
            .contains_key(&DriftKind::HookContractBreach)
    );
    assert!(
        s.alerts_by_kind
            .contains_key(&DriftKind::EffectBoundaryLeak)
    );
}

// ===========================================================================
// 41. LocalSemanticAtlasEntry serde roundtrip
// ===========================================================================

#[test]
fn atlas_entry_serde_roundtrip() {
    use frankenengine_engine::semantic_contract_baseline::LocalSemanticAtlasEntry;
    let inputs = vec![LocalSemanticAtlasInput {
        component: frankenengine_engine::static_analysis_graph::ComponentDescriptor {
            id: frankenengine_engine::static_analysis_graph::ComponentId::new("src/Test.tsx"),
            is_function_component: true,
            module_path: "src/Test.tsx".into(),
            export_name: Some("Test".into()),
            hook_slots: vec![],
            props: BTreeMap::new(),
            consumed_contexts: vec![],
            provided_contexts: vec![],
            capability_boundary:
                frankenengine_engine::static_analysis_graph::CapabilityBoundary::pure_component(),
            is_pure: true,
            content_hash: ContentHash::compute(b"Test"),
            children: vec![],
        },
        fixture_refs: vec!["fix-1".into()],
        trace_refs: vec!["trace-1".into()],
        assumption_keys: vec![],
    }];
    let atlas = LocalSemanticAtlas::from_inputs(SemanticContractVersion::CURRENT, 1, inputs);
    let entry = atlas.entry("src/Test.tsx").unwrap();
    let json = serde_json::to_string(entry).unwrap();
    let back: LocalSemanticAtlasEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(&back, entry);
}
