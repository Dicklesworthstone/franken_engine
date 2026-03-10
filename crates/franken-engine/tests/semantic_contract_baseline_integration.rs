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
