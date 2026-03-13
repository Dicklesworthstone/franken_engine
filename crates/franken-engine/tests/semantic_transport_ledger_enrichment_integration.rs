#![forbid(unsafe_code)]
//! Enrichment integration tests for `semantic_transport_ledger` (FRX-14.4).
//!
//! Covers Display uniqueness, serde round-trips, method edge cases,
//! deterministic hash behavior, regression mask detection paths, morphism
//! safety combinations, gate blocking logic, confidence computation, and
//! report rendering corner cases.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeSet;

use frankenengine_engine::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::semantic_contract_baseline::SemanticContractVersion;
use frankenengine_engine::semantic_transport_ledger::{
    BehavioralDelta, ContractDomain, DEBT_ADAPTER_REQUIRED, DEBT_BUDGET_EXHAUSTED,
    DEBT_MORPHISM_UNVERIFIED, DEBT_REGRESSION_MASKED, DEBT_TRANSPORT_INCOMPATIBLE, MorphismSpec,
    RegressionMask, SemanticTransportAnalyzer, SemanticTransportLedger, TRANSPORT_LEDGER_BEAD_ID,
    TRANSPORT_LEDGER_SCHEMA_VERSION, TransportAnalysisInput, TransportAnalysisOutcome,
    TransportAnalysisResult, TransportAnalyzerConfig, TransportEntrySpec, TransportError,
    TransportVerdict, VersionPair, render_transport_report, should_block_gate,
};

// ===========================================================================
// Helpers
// ===========================================================================

fn ver(major: u32, minor: u32, patch: u32) -> SemanticContractVersion {
    SemanticContractVersion {
        major,
        minor,
        patch,
    }
}

fn make_delta(
    aspect: &str,
    src: &str,
    tgt: &str,
    severity: i64,
    bridgeable: bool,
) -> BehavioralDelta {
    BehavioralDelta {
        aspect: aspect.to_string(),
        source_behavior: src.to_string(),
        target_behavior: tgt.to_string(),
        severity_millionths: severity,
        adapter_bridgeable: bridgeable,
    }
}

fn simple_spec(name: &str, deltas: Vec<BehavioralDelta>) -> TransportEntrySpec {
    TransportEntrySpec {
        fragment_name: name.to_string(),
        domain: ContractDomain::Hook,
        source_version: ver(0, 1, 0),
        target_version: ver(0, 2, 0),
        behavioral_deltas: deltas,
        required_invariants: vec!["inv-a".to_string(), "inv-b".to_string()],
        verified_invariants: vec!["inv-a".to_string(), "inv-b".to_string()],
        broken_invariants: vec![],
    }
}

fn simple_input(specs: Vec<TransportEntrySpec>) -> TransportAnalysisInput {
    TransportAnalysisInput {
        entries: specs,
        morphisms: vec![],
        epoch: 1,
    }
}

fn make_morphism_spec(
    name: &str,
    domain: ContractDomain,
    verified: bool,
    broken: Vec<String>,
) -> MorphismSpec {
    MorphismSpec {
        name: name.to_string(),
        domain,
        source_version: ver(0, 1, 0),
        target_version: ver(0, 2, 0),
        preserved_invariants: vec!["inv-1".to_string()],
        broken_invariants: broken,
        verified,
        description: format!("Morphism {name}"),
        adapter_ref: None,
    }
}

fn make_id(seed: &[u8]) -> EngineObjectId {
    let schema = SchemaId::from_definition(b"enrichment-test");
    derive_id(ObjectDomain::EvidenceRecord, "enrich-test", &schema, seed)
        .expect("test id derivation should not fail")
}

fn run_analysis(input: &TransportAnalysisInput) -> TransportAnalysisResult {
    SemanticTransportAnalyzer::new()
        .analyze(input)
        .expect("analysis should succeed")
}

// ===========================================================================
// 1. Display uniqueness for TransportVerdict
// ===========================================================================

#[test]
fn enrichment_transport_verdict_display_values_all_unique() {
    let variants = [
        TransportVerdict::Unchanged,
        TransportVerdict::AdapterRequired,
        TransportVerdict::Incompatible,
        TransportVerdict::Unknown,
    ];
    let mut seen = BTreeSet::new();
    for v in &variants {
        let s = format!("{v}");
        assert!(!s.is_empty(), "Display for {:?} must not be empty", v);
        assert!(
            seen.insert(s.clone()),
            "Duplicate Display output: {s} for {:?}",
            v
        );
    }
    assert_eq!(seen.len(), variants.len());
}

// ===========================================================================
// 2. Display uniqueness for ContractDomain
// ===========================================================================

#[test]
fn enrichment_contract_domain_display_values_all_unique() {
    let domains = [
        ContractDomain::Hook,
        ContractDomain::Effect,
        ContractDomain::Context,
        ContractDomain::Capability,
        ContractDomain::Suspense,
        ContractDomain::Hydration,
        ContractDomain::ErrorBoundary,
        ContractDomain::Ref,
        ContractDomain::Portal,
    ];
    let mut seen = BTreeSet::new();
    for d in &domains {
        let s = format!("{d}");
        assert!(!s.is_empty());
        assert!(seen.insert(s.clone()), "Duplicate Display: {s}");
    }
    assert_eq!(seen.len(), 9);
}

// ===========================================================================
// 3. Display uniqueness for TransportAnalysisOutcome
// ===========================================================================

#[test]
fn enrichment_analysis_outcome_display_values_all_unique() {
    let outcomes = [
        TransportAnalysisOutcome::FullyCompatible,
        TransportAnalysisOutcome::CompatibleWithAdapters,
        TransportAnalysisOutcome::HasIncompatibilities,
        TransportAnalysisOutcome::RegressionMaskDetected,
        TransportAnalysisOutcome::BudgetExhausted,
    ];
    let mut seen = BTreeSet::new();
    for o in &outcomes {
        let s = format!("{o}");
        assert!(seen.insert(s.clone()), "Duplicate Display: {s}");
    }
    assert_eq!(seen.len(), 5);
}

// ===========================================================================
// 4. Display uniqueness for TransportError
// ===========================================================================

#[test]
fn enrichment_transport_error_display_variants_distinct() {
    let errors = [
        TransportError::BudgetExhausted {
            resource: "entries".to_string(),
            limit: 50,
        },
        TransportError::DuplicateEntry("x".to_string()),
        TransportError::InvalidVersionPair("bad".to_string()),
        TransportError::MorphismConflict("clash".to_string()),
    ];
    let mut seen = BTreeSet::new();
    for e in &errors {
        let s = format!("{e}");
        assert!(seen.insert(s.clone()), "Duplicate Display: {s}");
    }
    assert_eq!(seen.len(), 4);
}

// ===========================================================================
// 5. Serde round-trip: TransportVerdict
// ===========================================================================

#[test]
fn enrichment_transport_verdict_serde_roundtrip() {
    let variants = [
        TransportVerdict::Unchanged,
        TransportVerdict::AdapterRequired,
        TransportVerdict::Incompatible,
        TransportVerdict::Unknown,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: TransportVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// 6. Serde round-trip: ContractDomain
// ===========================================================================

#[test]
fn enrichment_contract_domain_serde_roundtrip() {
    let domains = [
        ContractDomain::Hook,
        ContractDomain::Effect,
        ContractDomain::Context,
        ContractDomain::Capability,
        ContractDomain::Suspense,
        ContractDomain::Hydration,
        ContractDomain::ErrorBoundary,
        ContractDomain::Ref,
        ContractDomain::Portal,
    ];
    for d in &domains {
        let json = serde_json::to_string(d).unwrap();
        let back: ContractDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

// ===========================================================================
// 7. Serde round-trip: TransportAnalysisOutcome
// ===========================================================================

#[test]
fn enrichment_analysis_outcome_serde_roundtrip() {
    let outcomes = [
        TransportAnalysisOutcome::FullyCompatible,
        TransportAnalysisOutcome::CompatibleWithAdapters,
        TransportAnalysisOutcome::HasIncompatibilities,
        TransportAnalysisOutcome::RegressionMaskDetected,
        TransportAnalysisOutcome::BudgetExhausted,
    ];
    for o in &outcomes {
        let json = serde_json::to_string(o).unwrap();
        let back: TransportAnalysisOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, back);
    }
}

// ===========================================================================
// 8. Serde round-trip: TransportError
// ===========================================================================

#[test]
fn enrichment_transport_error_serde_roundtrip() {
    let errors = [
        TransportError::BudgetExhausted {
            resource: "morphisms".to_string(),
            limit: 999,
        },
        TransportError::DuplicateEntry("dup".to_string()),
        TransportError::InvalidVersionPair("msg".to_string()),
        TransportError::MorphismConflict("conf".to_string()),
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let back: TransportError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, back);
    }
}

// ===========================================================================
// 9. Serde round-trip: BehavioralDelta
// ===========================================================================

#[test]
fn enrichment_behavioral_delta_serde_roundtrip() {
    let d = make_delta("ordering", "sync-invoke", "deferred-invoke", 750_000, false);
    let json = serde_json::to_string(&d).unwrap();
    let back: BehavioralDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

// ===========================================================================
// 10. Serde round-trip: VersionPair
// ===========================================================================

#[test]
fn enrichment_version_pair_serde_roundtrip() {
    let pair = VersionPair::new(ver(3, 7, 11), ver(4, 0, 0));
    let json = serde_json::to_string(&pair).unwrap();
    let back: VersionPair = serde_json::from_str(&json).unwrap();
    assert_eq!(pair, back);
}

// ===========================================================================
// 11. Serde round-trip: SemanticTransportLedger (empty)
// ===========================================================================

#[test]
fn enrichment_empty_ledger_serde_roundtrip() {
    let ledger = SemanticTransportLedger::new(100);
    let json = serde_json::to_string(&ledger).unwrap();
    let back: SemanticTransportLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(ledger, back);
}

// ===========================================================================
// 12. Serde round-trip: TransportAnalyzerConfig
// ===========================================================================

#[test]
fn enrichment_analyzer_config_serde_roundtrip() {
    let config = TransportAnalyzerConfig {
        max_entries: 123,
        max_morphisms_per_entry: 7,
        max_regression_masks: 42,
        incompatibility_threshold_millionths: 600_000,
        detect_regression_masks: false,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: TransportAnalyzerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ===========================================================================
// 13. Serde round-trip: TransportEntrySpec
// ===========================================================================

#[test]
fn enrichment_entry_spec_serde_roundtrip() {
    let spec = TransportEntrySpec {
        fragment_name: "useCallback.memoization".to_string(),
        domain: ContractDomain::Suspense,
        source_version: ver(1, 0, 0),
        target_version: ver(2, 0, 0),
        behavioral_deltas: vec![make_delta("memo", "strict", "lazy", 100_000, true)],
        required_invariants: vec!["inv-x".to_string()],
        verified_invariants: vec!["inv-x".to_string()],
        broken_invariants: vec![],
    };
    let json = serde_json::to_string(&spec).unwrap();
    let back: TransportEntrySpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, back);
}

// ===========================================================================
// 14. Serde round-trip: MorphismSpec
// ===========================================================================

#[test]
fn enrichment_morphism_spec_serde_roundtrip() {
    let spec = MorphismSpec {
        name: "ref-forward-adapter".to_string(),
        domain: ContractDomain::Ref,
        source_version: ver(0, 1, 0),
        target_version: ver(0, 3, 0),
        preserved_invariants: vec!["forwarding".to_string()],
        broken_invariants: vec!["timing".to_string()],
        verified: false,
        description: "Bridges ref forwarding.".to_string(),
        adapter_ref: Some("adapters::ref_forward_v3".to_string()),
    };
    let json = serde_json::to_string(&spec).unwrap();
    let back: MorphismSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(spec, back);
}

// ===========================================================================
// 15. Serde round-trip: full TransportAnalysisResult with entries
// ===========================================================================

#[test]
fn enrichment_full_analysis_result_serde_roundtrip() {
    let input = TransportAnalysisInput {
        entries: vec![
            simple_spec("hook.a", vec![]),
            simple_spec(
                "hook.b",
                vec![make_delta("timing", "a", "b", 200_000, true)],
            ),
        ],
        morphisms: vec![make_morphism_spec("m1", ContractDomain::Hook, true, vec![])],
        epoch: 50,
    };
    let result = run_analysis(&input);
    let json = serde_json::to_string(&result).unwrap();
    let back: TransportAnalysisResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.outcome, back.outcome);
    assert_eq!(result.result_hash, back.result_hash);
    assert_eq!(result.ledger.ledger_hash, back.ledger.ledger_hash);
    assert_eq!(result.total_entries, back.total_entries);
}

// ===========================================================================
// 16. VersionPair: upgrade, downgrade, same-version edge cases
// ===========================================================================

#[test]
fn enrichment_version_pair_same_patch_is_not_upgrade_or_downgrade() {
    let pair = VersionPair::new(ver(1, 2, 3), ver(1, 2, 3));
    assert!(!pair.is_upgrade());
    assert!(!pair.is_downgrade());
    assert!(pair.is_same_major());
}

#[test]
fn enrichment_version_pair_minor_upgrade() {
    let pair = VersionPair::new(ver(1, 0, 0), ver(1, 1, 0));
    assert!(pair.is_upgrade());
    assert!(!pair.is_downgrade());
    assert!(pair.is_same_major());
}

#[test]
fn enrichment_version_pair_patch_downgrade() {
    let pair = VersionPair::new(ver(1, 0, 5), ver(1, 0, 3));
    assert!(!pair.is_upgrade());
    assert!(pair.is_downgrade());
    assert!(pair.is_same_major());
}

#[test]
fn enrichment_version_pair_cross_major_display() {
    let pair = VersionPair::new(ver(17, 0, 0), ver(18, 0, 0));
    let disp = format!("{pair}");
    assert!(disp.contains("17.0.0"));
    assert!(disp.contains("18.0.0"));
    assert!(!pair.is_same_major());
}

// ===========================================================================
// 17. BehavioralDelta Display format
// ===========================================================================

#[test]
fn enrichment_behavioral_delta_display_contains_all_fields() {
    let d = make_delta("lifecycle", "mount-first", "lazy-mount", 300_000, false);
    let s = format!("{d}");
    assert!(s.contains("lifecycle"));
    assert!(s.contains("mount-first"));
    assert!(s.contains("lazy-mount"));
    assert!(s.contains("300000"));
    assert!(s.contains("false"));
}

// ===========================================================================
// 18. Deterministic hashing: same input produces identical hashes
// ===========================================================================

#[test]
fn enrichment_deterministic_hashing_same_input_same_hash() {
    let input = TransportAnalysisInput {
        entries: vec![
            simple_spec("frag-alpha", vec![]),
            simple_spec("frag-beta", vec![make_delta("t", "a", "b", 100_000, true)]),
        ],
        morphisms: vec![make_morphism_spec(
            "m-det",
            ContractDomain::Effect,
            true,
            vec![],
        )],
        epoch: 77,
    };
    let r1 = run_analysis(&input);
    let r2 = run_analysis(&input);
    assert_eq!(r1.result_hash, r2.result_hash);
    assert_eq!(r1.ledger.ledger_hash, r2.ledger.ledger_hash);
    for i in 0..r1.ledger.entries.len() {
        assert_eq!(
            r1.ledger.entries[i].entry_hash,
            r2.ledger.entries[i].entry_hash
        );
    }
    for i in 0..r1.ledger.morphisms.len() {
        assert_eq!(
            r1.ledger.morphisms[i].evidence_hash,
            r2.ledger.morphisms[i].evidence_hash
        );
    }
}

// ===========================================================================
// 19. Deterministic hashing: different fragments produce different hashes
// ===========================================================================

#[test]
fn enrichment_different_fragment_names_different_entry_hashes() {
    let analyzer = SemanticTransportAnalyzer::new();
    let r1 = analyzer
        .analyze(&simple_input(vec![simple_spec("name-A", vec![])]))
        .unwrap();
    let r2 = analyzer
        .analyze(&simple_input(vec![simple_spec("name-B", vec![])]))
        .unwrap();
    assert_ne!(
        r1.ledger.entries[0].entry_hash,
        r2.ledger.entries[0].entry_hash
    );
    assert_ne!(r1.ledger.ledger_hash, r2.ledger.ledger_hash);
    assert_ne!(r1.result_hash, r2.result_hash);
}

// ===========================================================================
// 20. Deterministic hashing: different domains yield different hashes
// ===========================================================================

#[test]
fn enrichment_different_domains_different_hashes() {
    let analyzer = SemanticTransportAnalyzer::new();
    let mut spec_hook = simple_spec("same-name", vec![]);
    spec_hook.domain = ContractDomain::Hook;
    let mut spec_effect = simple_spec("same-name-2", vec![]);
    spec_effect.domain = ContractDomain::Effect;
    let r1 = analyzer.analyze(&simple_input(vec![spec_hook])).unwrap();
    let r2 = analyzer.analyze(&simple_input(vec![spec_effect])).unwrap();
    assert_ne!(
        r1.ledger.entries[0].entry_hash,
        r2.ledger.entries[0].entry_hash
    );
}

// ===========================================================================
// 21. Verdict logic: no deltas yields Unchanged
// ===========================================================================

#[test]
fn enrichment_verdict_no_deltas_is_unchanged() {
    let result = run_analysis(&simple_input(vec![simple_spec("clean-frag", vec![])]));
    assert_eq!(
        result.ledger.entries[0].verdict,
        TransportVerdict::Unchanged
    );
    assert_eq!(result.unchanged_entries, 1);
}

// ===========================================================================
// 22. Verdict logic: broken invariants override everything to Incompatible
// ===========================================================================

#[test]
fn enrichment_verdict_broken_invariants_override_to_incompatible() {
    let mut spec = simple_spec("broken-frag", vec![]);
    spec.broken_invariants = vec!["strict-order".to_string()];
    let result = run_analysis(&simple_input(vec![spec]));
    assert_eq!(
        result.ledger.entries[0].verdict,
        TransportVerdict::Incompatible
    );
}

// ===========================================================================
// 23. Verdict logic: bridgeable delta below threshold yields AdapterRequired
// ===========================================================================

#[test]
fn enrichment_verdict_bridgeable_below_threshold() {
    let spec = simple_spec(
        "adapted",
        vec![make_delta("timing", "a", "b", 200_000, true)],
    );
    let result = run_analysis(&simple_input(vec![spec]));
    assert_eq!(
        result.ledger.entries[0].verdict,
        TransportVerdict::AdapterRequired
    );
}

// ===========================================================================
// 24. Verdict logic: unbridgeable delta yields Incompatible
// ===========================================================================

#[test]
fn enrichment_verdict_unbridgeable_delta_incompatible() {
    let spec = simple_spec(
        "unbridgeable",
        vec![make_delta("ordering", "a", "b", 50_000, false)],
    );
    let result = run_analysis(&simple_input(vec![spec]));
    assert_eq!(
        result.ledger.entries[0].verdict,
        TransportVerdict::Incompatible
    );
}

// ===========================================================================
// 25. Verdict logic: high severity bridgeable (above threshold) is AdapterRequired
// ===========================================================================

#[test]
fn enrichment_verdict_high_severity_all_bridgeable_is_adapter_required() {
    let spec = simple_spec(
        "high-bridgeable",
        vec![make_delta("perf", "fast", "slow", 900_000, true)],
    );
    let result = run_analysis(&simple_input(vec![spec]));
    assert_eq!(
        result.ledger.entries[0].verdict,
        TransportVerdict::AdapterRequired
    );
}

// ===========================================================================
// 26. Verdict logic: high severity mixed bridgeable/unbridgeable is Incompatible
// ===========================================================================

#[test]
fn enrichment_verdict_high_severity_mixed_bridgeability_incompatible() {
    let spec = simple_spec(
        "mixed-high",
        vec![
            make_delta("a", "x", "y", 400_000, true),
            make_delta("b", "x", "y", 400_000, false),
        ],
    );
    let result = run_analysis(&simple_input(vec![spec]));
    assert_eq!(
        result.ledger.entries[0].verdict,
        TransportVerdict::Incompatible
    );
}

// ===========================================================================
// 27. Confidence: no required invariants gives 500_000
// ===========================================================================

#[test]
fn enrichment_confidence_no_invariants_is_medium() {
    let spec = TransportEntrySpec {
        fragment_name: "no-inv".to_string(),
        domain: ContractDomain::Portal,
        source_version: ver(0, 1, 0),
        target_version: ver(0, 2, 0),
        behavioral_deltas: vec![],
        required_invariants: vec![],
        verified_invariants: vec![],
        broken_invariants: vec![],
    };
    let result = run_analysis(&simple_input(vec![spec]));
    assert_eq!(result.ledger.entries[0].confidence_millionths, 500_000);
}

// ===========================================================================
// 28. Confidence: 3 of 4 verified gives 750_000
// ===========================================================================

#[test]
fn enrichment_confidence_proportional_to_verification_ratio() {
    let spec = TransportEntrySpec {
        fragment_name: "partial".to_string(),
        domain: ContractDomain::Ref,
        source_version: ver(0, 1, 0),
        target_version: ver(0, 2, 0),
        behavioral_deltas: vec![],
        required_invariants: vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ],
        verified_invariants: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        broken_invariants: vec![],
    };
    let result = run_analysis(&simple_input(vec![spec]));
    assert_eq!(result.ledger.entries[0].confidence_millionths, 750_000);
}

// ===========================================================================
// 29. Confidence: all verified gives 1_000_000
// ===========================================================================

#[test]
fn enrichment_confidence_all_verified_is_full() {
    let spec = simple_spec("all-verified", vec![]);
    let result = run_analysis(&simple_input(vec![spec]));
    assert_eq!(result.ledger.entries[0].confidence_millionths, 1_000_000);
}

// ===========================================================================
// 30. Entry invariant coverage: zero required gives 1_000_000
// ===========================================================================

#[test]
fn enrichment_invariant_coverage_empty_required_is_full() {
    let spec = TransportEntrySpec {
        fragment_name: "empty-req".to_string(),
        domain: ContractDomain::Hook,
        source_version: ver(0, 1, 0),
        target_version: ver(0, 2, 0),
        behavioral_deltas: vec![],
        required_invariants: vec![],
        verified_invariants: vec![],
        broken_invariants: vec![],
    };
    let result = run_analysis(&simple_input(vec![spec]));
    assert_eq!(
        result.ledger.entries[0].invariant_coverage_millionths(),
        1_000_000
    );
}

// ===========================================================================
// 31. Entry invariant coverage: half verified gives 500_000
// ===========================================================================

#[test]
fn enrichment_invariant_coverage_half_verified() {
    let spec = TransportEntrySpec {
        fragment_name: "half".to_string(),
        domain: ContractDomain::Hook,
        source_version: ver(0, 1, 0),
        target_version: ver(0, 2, 0),
        behavioral_deltas: vec![],
        required_invariants: vec!["a".to_string(), "b".to_string()],
        verified_invariants: vec!["a".to_string()],
        broken_invariants: vec![],
    };
    let result = run_analysis(&simple_input(vec![spec]));
    assert_eq!(
        result.ledger.entries[0].invariant_coverage_millionths(),
        500_000
    );
}

// ===========================================================================
// 32. Entry is_blocking: only Incompatible entries block
// ===========================================================================

#[test]
fn enrichment_entry_is_blocking_only_for_incompatible() {
    let analyzer = SemanticTransportAnalyzer::new();

    // Unchanged: not blocking
    let r_unchanged = analyzer
        .analyze(&simple_input(vec![simple_spec("unchanged", vec![])]))
        .unwrap();
    assert!(!r_unchanged.ledger.entries[0].is_blocking());

    // AdapterRequired: not blocking
    let r_adapter = analyzer
        .analyze(&simple_input(vec![simple_spec(
            "adapted",
            vec![make_delta("t", "a", "b", 100_000, true)],
        )]))
        .unwrap();
    assert!(!r_adapter.ledger.entries[0].is_blocking());

    // Incompatible: blocking
    let mut spec_incompat = simple_spec("incompat", vec![]);
    spec_incompat.broken_invariants = vec!["broken".to_string()];
    let r_incompat = analyzer
        .analyze(&simple_input(vec![spec_incompat]))
        .unwrap();
    assert!(r_incompat.ledger.entries[0].is_blocking());
}

// ===========================================================================
// 33. Entry all_invariants_verified with broken invariants returns false
// ===========================================================================

#[test]
fn enrichment_all_invariants_verified_false_when_broken_nonempty() {
    let mut spec = simple_spec("with-broken", vec![]);
    spec.required_invariants = vec!["a".to_string()];
    spec.verified_invariants = vec!["a".to_string()];
    spec.broken_invariants = vec!["extra-broken".to_string()];
    let result = run_analysis(&simple_input(vec![spec]));
    assert!(!result.ledger.entries[0].all_invariants_verified());
}

// ===========================================================================
// 34. Debt codes assigned correctly per verdict
// ===========================================================================

#[test]
fn enrichment_debt_code_matches_verdict() {
    let analyzer = SemanticTransportAnalyzer::new();

    // Unchanged -> None
    let r = analyzer
        .analyze(&simple_input(vec![simple_spec("unch", vec![])]))
        .unwrap();
    assert!(r.ledger.entries[0].debt_code.is_none());

    // AdapterRequired -> DEBT_ADAPTER_REQUIRED
    let r = analyzer
        .analyze(&simple_input(vec![simple_spec(
            "adap",
            vec![make_delta("t", "a", "b", 100_000, true)],
        )]))
        .unwrap();
    assert_eq!(
        r.ledger.entries[0].debt_code.as_deref(),
        Some(DEBT_ADAPTER_REQUIRED)
    );

    // Incompatible -> DEBT_TRANSPORT_INCOMPATIBLE
    let mut s = simple_spec("inc", vec![]);
    s.broken_invariants = vec!["b".to_string()];
    let r = analyzer.analyze(&simple_input(vec![s])).unwrap();
    assert_eq!(
        r.ledger.entries[0].debt_code.as_deref(),
        Some(DEBT_TRANSPORT_INCOMPATIBLE)
    );
}

// ===========================================================================
// 35. Duplicate entry detection
// ===========================================================================

#[test]
fn enrichment_duplicate_entry_returns_error() {
    let analyzer = SemanticTransportAnalyzer::new();
    let input = simple_input(vec![
        simple_spec("dup-name", vec![]),
        simple_spec("dup-name", vec![]),
    ]);
    let err = analyzer.analyze(&input).unwrap_err();
    match err {
        TransportError::DuplicateEntry(name) => assert_eq!(name, "dup-name"),
        other => panic!("Expected DuplicateEntry, got: {:?}", other),
    }
}

// ===========================================================================
// 36. Budget exhaustion truncates entries
// ===========================================================================

#[test]
fn enrichment_budget_exhaustion_limits_entries() {
    let config = TransportAnalyzerConfig {
        max_entries: 3,
        ..TransportAnalyzerConfig::default()
    };
    let analyzer = SemanticTransportAnalyzer::with_config(config);
    let specs: Vec<_> = (0..10)
        .map(|i| simple_spec(&format!("frag-{i}"), vec![]))
        .collect();
    let result = analyzer.analyze(&simple_input(specs)).unwrap();
    assert_eq!(result.outcome, TransportAnalysisOutcome::BudgetExhausted);
    assert_eq!(result.total_entries, 3);
    assert!(should_block_gate(&result));
    assert!(!result.can_release());
}

// ===========================================================================
// 37. Morphism: verified + not lossy = safe
// ===========================================================================

#[test]
fn enrichment_morphism_verified_not_lossy_is_safe() {
    let input = TransportAnalysisInput {
        entries: vec![],
        morphisms: vec![make_morphism_spec(
            "safe-m",
            ContractDomain::Hook,
            true,
            vec![],
        )],
        epoch: 1,
    };
    let result = run_analysis(&input);
    let m = &result.ledger.morphisms[0];
    assert!(m.is_safe());
    assert!(m.verified);
    assert!(!m.lossy);
}

// ===========================================================================
// 38. Morphism: verified + lossy = not safe
// ===========================================================================

#[test]
fn enrichment_morphism_verified_lossy_not_safe() {
    let input = TransportAnalysisInput {
        entries: vec![],
        morphisms: vec![make_morphism_spec(
            "lossy-m",
            ContractDomain::Effect,
            true,
            vec!["dropped-inv".to_string()],
        )],
        epoch: 1,
    };
    let result = run_analysis(&input);
    let m = &result.ledger.morphisms[0];
    assert!(!m.is_safe());
    assert!(m.verified);
    assert!(m.lossy);
}

// ===========================================================================
// 39. Morphism: unverified + not lossy = not safe
// ===========================================================================

#[test]
fn enrichment_morphism_unverified_not_lossy_not_safe() {
    let input = TransportAnalysisInput {
        entries: vec![],
        morphisms: vec![make_morphism_spec(
            "unverif-m",
            ContractDomain::Context,
            false,
            vec![],
        )],
        epoch: 1,
    };
    let result = run_analysis(&input);
    let m = &result.ledger.morphisms[0];
    assert!(!m.is_safe());
    assert!(!m.verified);
    assert!(!m.lossy);
}

// ===========================================================================
// 40. Morphism summary line labels: safe, verified-lossy, UNVERIFIED
// ===========================================================================

#[test]
fn enrichment_morphism_summary_line_safety_labels() {
    let input_safe = TransportAnalysisInput {
        entries: vec![],
        morphisms: vec![make_morphism_spec(
            "safe",
            ContractDomain::Hook,
            true,
            vec![],
        )],
        epoch: 1,
    };
    let r_safe = run_analysis(&input_safe);
    assert!(r_safe.ledger.morphisms[0].summary_line().contains("safe"));
    assert!(
        !r_safe.ledger.morphisms[0]
            .summary_line()
            .contains("UNVERIFIED")
    );

    let input_lossy = TransportAnalysisInput {
        entries: vec![],
        morphisms: vec![make_morphism_spec(
            "lossy",
            ContractDomain::Hook,
            true,
            vec!["broken".to_string()],
        )],
        epoch: 1,
    };
    let r_lossy = run_analysis(&input_lossy);
    assert!(
        r_lossy.ledger.morphisms[0]
            .summary_line()
            .contains("verified-lossy")
    );

    let input_unverif = TransportAnalysisInput {
        entries: vec![],
        morphisms: vec![make_morphism_spec(
            "unverif",
            ContractDomain::Hook,
            false,
            vec![],
        )],
        epoch: 1,
    };
    let r_unverif = run_analysis(&input_unverif);
    assert!(
        r_unverif.ledger.morphisms[0]
            .summary_line()
            .contains("UNVERIFIED")
    );
}

// ===========================================================================
// 41. Morphism adapter_ref preserved through analysis
// ===========================================================================

#[test]
fn enrichment_morphism_adapter_ref_preserved() {
    let mut spec = make_morphism_spec("with-ref", ContractDomain::Hydration, true, vec![]);
    spec.adapter_ref = Some("adapters::hydration_bridge".to_string());
    let input = TransportAnalysisInput {
        entries: vec![],
        morphisms: vec![spec],
        epoch: 1,
    };
    let result = run_analysis(&input);
    assert_eq!(
        result.ledger.morphisms[0].adapter_ref.as_deref(),
        Some("adapters::hydration_bridge")
    );
}

// ===========================================================================
// 42. Regression mask type 1: lossy morphism on adapter-required entry
// ===========================================================================

#[test]
fn enrichment_regression_mask_lossy_morphism_triggers_high_risk() {
    let input = TransportAnalysisInput {
        entries: vec![TransportEntrySpec {
            fragment_name: "hook.cleanup".to_string(),
            domain: ContractDomain::Hook,
            source_version: ver(0, 1, 0),
            target_version: ver(0, 2, 0),
            behavioral_deltas: vec![make_delta("timing", "a", "b", 300_000, true)],
            required_invariants: vec!["inv-1".to_string(), "inv-2".to_string()],
            verified_invariants: vec!["inv-1".to_string(), "inv-2".to_string()],
            broken_invariants: vec![],
        }],
        morphisms: vec![MorphismSpec {
            name: "lossy-hook-bridge".to_string(),
            domain: ContractDomain::Hook,
            source_version: ver(0, 1, 0),
            target_version: ver(0, 2, 0),
            preserved_invariants: vec!["inv-1".to_string()],
            broken_invariants: vec!["inv-2".to_string()],
            verified: true,
            description: "Lossy.".to_string(),
            adapter_ref: None,
        }],
        epoch: 1,
    };
    let result = run_analysis(&input);
    assert_eq!(
        result.outcome,
        TransportAnalysisOutcome::RegressionMaskDetected
    );
    assert!(result.high_risk_mask_count > 0);
    assert!(result.regression_mask_count > 0);
    assert!(!result.can_release());
    assert!(should_block_gate(&result));
}

// ===========================================================================
// 43. Regression mask type 2: low invariant coverage on adapter-required
// ===========================================================================

#[test]
fn enrichment_regression_mask_low_invariant_coverage() {
    let input = simple_input(vec![TransportEntrySpec {
        fragment_name: "effect.low-cov".to_string(),
        domain: ContractDomain::Effect,
        source_version: ver(0, 1, 0),
        target_version: ver(0, 2, 0),
        behavioral_deltas: vec![make_delta("timing", "a", "b", 200_000, true)],
        required_invariants: vec![
            "i1".to_string(),
            "i2".to_string(),
            "i3".to_string(),
            "i4".to_string(),
        ],
        verified_invariants: vec!["i1".to_string()], // 1/4 = 250_000 < 500_000
        broken_invariants: vec![],
    }]);
    let result = run_analysis(&input);
    assert!(
        result.regression_mask_count > 0,
        "Low invariant coverage should trigger regression mask"
    );
}

// ===========================================================================
// 44. Regression mask type 3: unchanged with unverified invariants
// ===========================================================================

#[test]
fn enrichment_regression_mask_unchanged_unverified_invariants() {
    let input = simple_input(vec![TransportEntrySpec {
        fragment_name: "hook.ordering".to_string(),
        domain: ContractDomain::Hook,
        source_version: ver(0, 1, 0),
        target_version: ver(0, 2, 0),
        behavioral_deltas: vec![],
        required_invariants: vec!["i1".to_string(), "i2".to_string(), "i3".to_string()],
        verified_invariants: vec!["i1".to_string()], // 1/3 unverified
        broken_invariants: vec![],
    }]);
    let result = run_analysis(&input);
    assert!(
        result.regression_mask_count > 0,
        "Unchanged with unverified invariants should create mask"
    );
    // Type 3 risk is 400_000, below 500_000 threshold
    let high_risk = result.ledger.high_risk_masks();
    // Mask risk is 400_000 which is below 500_000, so not high risk
    assert!(
        high_risk.is_empty(),
        "Unchanged/unverified mask should be medium risk, not high"
    );
}

// ===========================================================================
// 45. No regression masks when detection is disabled
// ===========================================================================

#[test]
fn enrichment_no_regression_masks_when_disabled() {
    let config = TransportAnalyzerConfig {
        detect_regression_masks: false,
        ..TransportAnalyzerConfig::default()
    };
    let analyzer = SemanticTransportAnalyzer::with_config(config);
    let input = simple_input(vec![TransportEntrySpec {
        fragment_name: "should-not-mask".to_string(),
        domain: ContractDomain::Hook,
        source_version: ver(0, 1, 0),
        target_version: ver(0, 2, 0),
        behavioral_deltas: vec![],
        required_invariants: vec!["i1".to_string()],
        verified_invariants: vec![],
        broken_invariants: vec![],
    }]);
    let result = analyzer.analyze(&input).unwrap();
    assert_eq!(result.regression_mask_count, 0);
}

// ===========================================================================
// 46. RegressionMask: is_high_risk boundary at 500_000
// ===========================================================================

#[test]
fn enrichment_regression_mask_high_risk_boundary() {
    let base_id = make_id(b"mask-boundary");
    let entry_id = make_id(b"mask-boundary-entry");

    let mask_below = RegressionMask {
        id: base_id.clone(),
        entry_id: entry_id.clone(),
        morphism_id: None,
        masked_aspect: "timing".to_string(),
        reason: "below threshold".to_string(),
        risk_millionths: 499_999,
        debt_code: DEBT_REGRESSION_MASKED.to_string(),
        evidence_hash: ContentHash::compute(b"below"),
    };
    assert!(!mask_below.is_high_risk());

    let mask_at = RegressionMask {
        id: base_id.clone(),
        entry_id: entry_id.clone(),
        morphism_id: None,
        masked_aspect: "timing".to_string(),
        reason: "at threshold".to_string(),
        risk_millionths: 500_000,
        debt_code: DEBT_REGRESSION_MASKED.to_string(),
        evidence_hash: ContentHash::compute(b"at"),
    };
    assert!(mask_at.is_high_risk());

    let mask_above = RegressionMask {
        id: base_id,
        entry_id,
        morphism_id: None,
        masked_aspect: "timing".to_string(),
        reason: "above threshold".to_string(),
        risk_millionths: 500_001,
        debt_code: DEBT_REGRESSION_MASKED.to_string(),
        evidence_hash: ContentHash::compute(b"above"),
    };
    assert!(mask_above.is_high_risk());
}

// ===========================================================================
// 47. RegressionMask summary_line contains key fields
// ===========================================================================

#[test]
fn enrichment_regression_mask_summary_line_content() {
    let mask = RegressionMask {
        id: make_id(b"summary-mask"),
        entry_id: make_id(b"summary-entry"),
        morphism_id: None,
        masked_aspect: "effect.cleanup".to_string(),
        reason: "adapter hides change".to_string(),
        risk_millionths: 650_000,
        debt_code: DEBT_REGRESSION_MASKED.to_string(),
        evidence_hash: ContentHash::compute(b"summary"),
    };
    let s = mask.summary_line();
    assert!(s.contains("MASK:"));
    assert!(s.contains("effect.cleanup"));
    assert!(s.contains("650000"));
    assert!(s.contains("adapter hides change"));
}

// ===========================================================================
// 48. Ledger: entries_by_domain returns correct subset
// ===========================================================================

#[test]
fn enrichment_ledger_entries_by_domain_multigroup() {
    let mut specs = Vec::new();
    let domains_with_counts = [
        (ContractDomain::Hook, 3),
        (ContractDomain::Effect, 2),
        (ContractDomain::Context, 1),
    ];
    let mut idx = 0u32;
    for (domain, count) in &domains_with_counts {
        for _ in 0..*count {
            let mut spec = simple_spec(&format!("frag-{idx}"), vec![]);
            spec.domain = domain.clone();
            specs.push(spec);
            idx += 1;
        }
    }
    let result = run_analysis(&simple_input(specs));
    assert_eq!(
        result.ledger.entries_by_domain(&ContractDomain::Hook).len(),
        3
    );
    assert_eq!(
        result
            .ledger
            .entries_by_domain(&ContractDomain::Effect)
            .len(),
        2
    );
    assert_eq!(
        result
            .ledger
            .entries_by_domain(&ContractDomain::Context)
            .len(),
        1
    );
    assert_eq!(
        result
            .ledger
            .entries_by_domain(&ContractDomain::Portal)
            .len(),
        0
    );
}

// ===========================================================================
// 49. Ledger: entries_by_verdict returns correct subset
// ===========================================================================

#[test]
fn enrichment_ledger_entries_by_verdict_multigroup() {
    let specs = vec![
        simple_spec("unchanged-1", vec![]),
        simple_spec("unchanged-2", vec![]),
        simple_spec("adapted-1", vec![make_delta("t", "a", "b", 100_000, true)]),
        {
            let mut s = simple_spec("incompat-1", vec![]);
            s.broken_invariants = vec!["broken".to_string()];
            s
        },
    ];
    let result = run_analysis(&simple_input(specs));
    assert_eq!(
        result
            .ledger
            .entries_by_verdict(&TransportVerdict::Unchanged)
            .len(),
        2
    );
    assert_eq!(
        result
            .ledger
            .entries_by_verdict(&TransportVerdict::AdapterRequired)
            .len(),
        1
    );
    assert_eq!(
        result
            .ledger
            .entries_by_verdict(&TransportVerdict::Incompatible)
            .len(),
        1
    );
    assert_eq!(
        result
            .ledger
            .entries_by_verdict(&TransportVerdict::Unknown)
            .len(),
        0
    );
}

// ===========================================================================
// 50. Ledger: version_pairs deduplicates
// ===========================================================================

#[test]
fn enrichment_ledger_version_pairs_deduplicates() {
    let specs = vec![simple_spec("frag-a", vec![]), simple_spec("frag-b", vec![])];
    let result = run_analysis(&simple_input(specs));
    let pairs = result.ledger.version_pairs();
    // Both specs have same version pair (0.1.0 -> 0.2.0)
    assert_eq!(pairs.len(), 1);
    assert!(pairs.contains(&format!("{}", VersionPair::new(ver(0, 1, 0), ver(0, 2, 0)))));
}

// ===========================================================================
// 51. Ledger: coverage_millionths with all known entries
// ===========================================================================

#[test]
fn enrichment_ledger_coverage_all_known_is_million() {
    let specs = vec![
        simple_spec("a", vec![]),
        simple_spec("b", vec![make_delta("t", "x", "y", 100_000, true)]),
    ];
    let result = run_analysis(&simple_input(specs));
    assert_eq!(result.ledger.coverage_millionths(), 1_000_000);
}

// ===========================================================================
// 52. Ledger: coverage_millionths with manually injected Unknown entry
// ===========================================================================

#[test]
fn enrichment_ledger_coverage_with_unknown_entry() {
    let result = run_analysis(&simple_input(vec![simple_spec("known", vec![])]));
    let mut ledger = result.ledger.clone();

    let unknown_entry = frankenengine_engine::semantic_transport_ledger::TransportEntry {
        id: ledger.entries[0].id.clone(),
        fragment_name: "unknown-frag".to_string(),
        domain: ContractDomain::Effect,
        version_pair: VersionPair::new(ver(0, 1, 0), ver(0, 2, 0)),
        verdict: TransportVerdict::Unknown,
        behavioral_deltas: vec![],
        required_invariants: vec![],
        verified_invariants: vec![],
        broken_invariants: vec![],
        debt_code: None,
        confidence_millionths: 0,
        entry_hash: ContentHash::compute(b"enrichment-unknown"),
    };
    ledger.entries.push(unknown_entry);
    // 1 known out of 2 total
    assert_eq!(ledger.coverage_millionths(), 500_000);
}

// ===========================================================================
// 53. Ledger: empty coverage is 0
// ===========================================================================

#[test]
fn enrichment_ledger_coverage_empty_is_zero() {
    let ledger = SemanticTransportLedger::new(1);
    assert_eq!(ledger.coverage_millionths(), 0);
}

// ===========================================================================
// 54. Ledger: all_debt_codes collects from entries and masks
// ===========================================================================

#[test]
fn enrichment_ledger_all_debt_codes_aggregates_entries_and_masks() {
    let input = TransportAnalysisInput {
        entries: vec![TransportEntrySpec {
            fragment_name: "adapted-frag".to_string(),
            domain: ContractDomain::Context,
            source_version: ver(0, 1, 0),
            target_version: ver(0, 2, 0),
            behavioral_deltas: vec![make_delta("t", "a", "b", 100_000, true)],
            required_invariants: vec!["i1".to_string()],
            verified_invariants: vec!["i1".to_string()],
            broken_invariants: vec![],
        }],
        morphisms: vec![MorphismSpec {
            name: "lossy-ctx-bridge".to_string(),
            domain: ContractDomain::Context,
            source_version: ver(0, 1, 0),
            target_version: ver(0, 2, 0),
            preserved_invariants: vec![],
            broken_invariants: vec!["lost-inv".to_string()],
            verified: true,
            description: "Lossy.".to_string(),
            adapter_ref: None,
        }],
        epoch: 1,
    };
    let result = run_analysis(&input);
    let codes = result.ledger.all_debt_codes();
    assert!(codes.contains(DEBT_ADAPTER_REQUIRED));
    assert!(codes.contains(DEBT_REGRESSION_MASKED));
}

// ===========================================================================
// 55. should_block_gate: FullyCompatible and CompatibleWithAdapters pass
// ===========================================================================

#[test]
fn enrichment_should_block_gate_allows_compatible_outcomes() {
    let analyzer = SemanticTransportAnalyzer::new();

    let r_full = analyzer
        .analyze(&simple_input(vec![simple_spec("fc", vec![])]))
        .unwrap();
    assert_eq!(r_full.outcome, TransportAnalysisOutcome::FullyCompatible);
    assert!(!should_block_gate(&r_full));

    let r_adapt = analyzer
        .analyze(&simple_input(vec![simple_spec(
            "ca",
            vec![make_delta("t", "a", "b", 100_000, true)],
        )]))
        .unwrap();
    assert_eq!(
        r_adapt.outcome,
        TransportAnalysisOutcome::CompatibleWithAdapters
    );
    assert!(!should_block_gate(&r_adapt));
}

// ===========================================================================
// 56. should_block_gate: HasIncompatibilities blocks
// ===========================================================================

#[test]
fn enrichment_should_block_gate_blocks_incompatible() {
    let mut spec = simple_spec("incompat", vec![]);
    spec.broken_invariants = vec!["b".to_string()];
    let result = run_analysis(&simple_input(vec![spec]));
    assert_eq!(
        result.outcome,
        TransportAnalysisOutcome::HasIncompatibilities
    );
    assert!(should_block_gate(&result));
}

// ===========================================================================
// 57. can_release: comprehensive check for all outcome paths
// ===========================================================================

#[test]
fn enrichment_can_release_for_all_outcome_types() {
    let analyzer = SemanticTransportAnalyzer::new();

    // FullyCompatible -> can release
    let r = analyzer
        .analyze(&simple_input(vec![simple_spec("fc", vec![])]))
        .unwrap();
    assert!(r.can_release());

    // CompatibleWithAdapters -> can release
    let r = analyzer
        .analyze(&simple_input(vec![simple_spec(
            "ca",
            vec![make_delta("t", "a", "b", 100_000, true)],
        )]))
        .unwrap();
    assert!(r.can_release());

    // HasIncompatibilities -> cannot release
    let mut s = simple_spec("hi", vec![]);
    s.broken_invariants = vec!["b".to_string()];
    let r = analyzer.analyze(&simple_input(vec![s])).unwrap();
    assert!(!r.can_release());

    // BudgetExhausted -> cannot release
    let config = TransportAnalyzerConfig {
        max_entries: 1,
        ..TransportAnalyzerConfig::default()
    };
    let a2 = SemanticTransportAnalyzer::with_config(config);
    let r = a2
        .analyze(&simple_input(vec![
            simple_spec("x1", vec![]),
            simple_spec("x2", vec![]),
        ]))
        .unwrap();
    assert!(!r.can_release());
}

// ===========================================================================
// 58. Entry summary_line format
// ===========================================================================

#[test]
fn enrichment_entry_summary_line_format() {
    let spec = simple_spec(
        "useEffect.cleanup",
        vec![
            make_delta("timing", "sync", "async", 100_000, true),
            make_delta("ordering", "fifo", "lifo", 50_000, true),
        ],
    );
    let result = run_analysis(&simple_input(vec![spec]));
    let summary = result.ledger.entries[0].summary_line();
    assert!(summary.contains("[hook]"));
    assert!(summary.contains("useEffect.cleanup"));
    assert!(summary.contains("adapter-required"));
    assert!(summary.contains("2 deltas"));
}

// ===========================================================================
// 59. Ledger summary_line format
// ===========================================================================

#[test]
fn enrichment_ledger_summary_line_format() {
    let specs = vec![
        simple_spec("f1", vec![]),
        simple_spec("f2", vec![make_delta("t", "a", "b", 100_000, true)]),
        {
            let mut s = simple_spec("f3", vec![]);
            s.broken_invariants = vec!["b".to_string()];
            s
        },
    ];
    let result = run_analysis(&simple_input(specs));
    let s = result.ledger.summary_line();
    assert!(s.contains("3 entries"));
    assert!(s.contains("1 unchanged"));
    assert!(s.contains("1 adapter-required"));
    assert!(s.contains("1 incompatible"));
    assert!(s.contains("0 morphisms"));
    assert!(s.contains("0 regression masks"));
}

// ===========================================================================
// 60. Analysis result summary_line format
// ===========================================================================

#[test]
fn enrichment_analysis_result_summary_line_format() {
    let specs = vec![
        simple_spec("s1", vec![]),
        simple_spec("s2", vec![make_delta("t", "a", "b", 100_000, true)]),
    ];
    let result = run_analysis(&simple_input(specs));
    let s = result.summary_line();
    assert!(s.contains("compatible-with-adapters"));
    assert!(s.contains("2 entries"));
    assert!(s.contains("1 unchanged"));
    assert!(s.contains("1 adapted"));
}

// ===========================================================================
// 61. Report rendering: empty ledger
// ===========================================================================

#[test]
fn enrichment_render_report_empty_ledger() {
    let result = run_analysis(&simple_input(vec![]));
    let report = render_transport_report(&result);
    assert!(report.contains("Nothing to analyze"));
    assert!(report.contains("Result hash"));
}

// ===========================================================================
// 62. Report rendering: groups by verdict
// ===========================================================================

#[test]
fn enrichment_render_report_groups_by_verdict() {
    let specs = vec![
        simple_spec("unch-1", vec![]),
        simple_spec("adapt-1", vec![make_delta("t", "a", "b", 100_000, true)]),
        {
            let mut s = simple_spec("incompat-1", vec![]);
            s.broken_invariants = vec!["b".to_string()];
            s
        },
    ];
    let result = run_analysis(&simple_input(specs));
    let report = render_transport_report(&result);
    assert!(report.contains("incompatible"));
    assert!(report.contains("adapter-required"));
    assert!(report.contains("unchanged"));
    assert!(report.contains("Semantic Transport Report"));
    assert!(report.contains("epoch 1"));
}

// ===========================================================================
// 63. Report rendering: morphisms section appears when morphisms exist
// ===========================================================================

#[test]
fn enrichment_render_report_morphisms_section() {
    let input = TransportAnalysisInput {
        entries: vec![],
        morphisms: vec![make_morphism_spec(
            "report-m",
            ContractDomain::Effect,
            true,
            vec![],
        )],
        epoch: 99,
    };
    let result = run_analysis(&input);
    let report = render_transport_report(&result);
    assert!(report.contains("Morphisms"));
    assert!(report.contains("report-m"));
}

// ===========================================================================
// 64. Report rendering: regression masks section
// ===========================================================================

#[test]
fn enrichment_render_report_regression_masks_section() {
    let input = simple_input(vec![TransportEntrySpec {
        fragment_name: "masked-frag".to_string(),
        domain: ContractDomain::Hook,
        source_version: ver(0, 1, 0),
        target_version: ver(0, 2, 0),
        behavioral_deltas: vec![],
        required_invariants: vec!["i1".to_string(), "i2".to_string()],
        verified_invariants: vec!["i1".to_string()],
        broken_invariants: vec![],
    }]);
    let result = run_analysis(&input);
    let report = render_transport_report(&result);
    assert!(report.contains("Regression Masks"));
}

// ===========================================================================
// 65. Report rendering: delta lines appear under entries
// ===========================================================================

#[test]
fn enrichment_render_report_includes_delta_details() {
    let spec = simple_spec(
        "with-deltas",
        vec![make_delta(
            "lifecycle",
            "mount",
            "lazy-mount",
            200_000,
            true,
        )],
    );
    let result = run_analysis(&simple_input(vec![spec]));
    let report = render_transport_report(&result);
    assert!(report.contains("Delta:"));
    assert!(report.contains("lifecycle"));
}

// ===========================================================================
// 66. Constants: schema version and bead id format
// ===========================================================================

#[test]
fn enrichment_constants_format_validation() {
    assert!(TRANSPORT_LEDGER_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(TRANSPORT_LEDGER_SCHEMA_VERSION.contains(".v1"));
    assert!(TRANSPORT_LEDGER_BEAD_ID.starts_with("bd-"));
}

// ===========================================================================
// 67. Debt code constants: all have correct prefix
// ===========================================================================

#[test]
fn enrichment_debt_codes_have_consistent_prefix() {
    let codes = [
        DEBT_TRANSPORT_INCOMPATIBLE,
        DEBT_ADAPTER_REQUIRED,
        DEBT_REGRESSION_MASKED,
        DEBT_MORPHISM_UNVERIFIED,
        DEBT_BUDGET_EXHAUSTED,
    ];
    let mut seen = BTreeSet::new();
    for code in &codes {
        assert!(code.starts_with("FE-FRX-14-4-TRANSPORT-"));
        assert!(seen.insert(*code), "Duplicate debt code: {code}");
    }
    assert_eq!(seen.len(), 5);
}

// ===========================================================================
// 68. New ledger: schema and bead populated from constants
// ===========================================================================

#[test]
fn enrichment_new_ledger_populates_constants() {
    let ledger = SemanticTransportLedger::new(42);
    assert_eq!(ledger.schema_version, TRANSPORT_LEDGER_SCHEMA_VERSION);
    assert_eq!(ledger.bead_id, TRANSPORT_LEDGER_BEAD_ID);
    assert_eq!(ledger.compiled_epoch, 42);
    assert!(ledger.entries.is_empty());
    assert!(ledger.morphisms.is_empty());
    assert!(ledger.regression_masks.is_empty());
}

// ===========================================================================
// 69. Analyzer default trait equivalence
// ===========================================================================

#[test]
fn enrichment_analyzer_default_equals_new() {
    let a1 = SemanticTransportAnalyzer::new();
    let a2 = SemanticTransportAnalyzer::default();
    // Both should produce identical results on same input
    let input = simple_input(vec![simple_spec("default-test", vec![])]);
    let r1 = a1.analyze(&input).unwrap();
    let r2 = a2.analyze(&input).unwrap();
    assert_eq!(r1.result_hash, r2.result_hash);
}

// ===========================================================================
// 70. Multi-domain entries all recognized
// ===========================================================================

#[test]
fn enrichment_all_nine_domains_analyzed_correctly() {
    let domains = [
        ContractDomain::Hook,
        ContractDomain::Effect,
        ContractDomain::Context,
        ContractDomain::Capability,
        ContractDomain::Suspense,
        ContractDomain::Hydration,
        ContractDomain::ErrorBoundary,
        ContractDomain::Ref,
        ContractDomain::Portal,
    ];
    let specs: Vec<_> = domains
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let mut spec = simple_spec(&format!("domain-frag-{i}"), vec![]);
            spec.domain = d.clone();
            spec
        })
        .collect();
    let result = run_analysis(&simple_input(specs));
    assert_eq!(result.total_entries, 9);
    assert_eq!(result.outcome, TransportAnalysisOutcome::FullyCompatible);
    for d in &domains {
        assert_eq!(result.ledger.entries_by_domain(d).len(), 1);
    }
}

// ===========================================================================
// 71. Outcome priority: BudgetExhausted > RegressionMask > Incompatible > Adapter
// ===========================================================================

#[test]
fn enrichment_outcome_priority_budget_exhausted_over_regression_mask() {
    // With max_entries=1, budget exhaustion occurs even if we would have
    // generated regression masks.
    let config = TransportAnalyzerConfig {
        max_entries: 1,
        ..TransportAnalyzerConfig::default()
    };
    let analyzer = SemanticTransportAnalyzer::with_config(config);
    let input = TransportAnalysisInput {
        entries: vec![
            simple_spec("a", vec![]),
            simple_spec("b", vec![]), // will be truncated
        ],
        morphisms: vec![],
        epoch: 1,
    };
    let result = analyzer.analyze(&input).unwrap();
    assert_eq!(result.outcome, TransportAnalysisOutcome::BudgetExhausted);
}

// ===========================================================================
// 72. Outcome priority: RegressionMask over HasIncompatibilities
// ===========================================================================

#[test]
fn enrichment_outcome_priority_regression_mask_over_incompatible() {
    // An adapter-required entry + lossy morphism creates a high-risk mask
    // that should override any incompatible entries in outcome priority.
    // But note: the outcome logic checks high_risk > 0 before incompatible > 0.
    // We need both an incompatible entry AND a high-risk mask.
    let input = TransportAnalysisInput {
        entries: vec![
            // This will be adapter-required (triggers mask with lossy morphism)
            TransportEntrySpec {
                fragment_name: "masked-entry".to_string(),
                domain: ContractDomain::Hook,
                source_version: ver(0, 1, 0),
                target_version: ver(0, 2, 0),
                behavioral_deltas: vec![make_delta("t", "a", "b", 300_000, true)],
                required_invariants: vec!["i1".to_string()],
                verified_invariants: vec!["i1".to_string()],
                broken_invariants: vec![],
            },
        ],
        morphisms: vec![MorphismSpec {
            name: "lossy".to_string(),
            domain: ContractDomain::Hook,
            source_version: ver(0, 1, 0),
            target_version: ver(0, 2, 0),
            preserved_invariants: vec![],
            broken_invariants: vec!["dropped".to_string()],
            verified: true,
            description: "Lossy.".to_string(),
            adapter_ref: None,
        }],
        epoch: 1,
    };
    let result = run_analysis(&input);
    // High risk mask exists, so outcome should be RegressionMaskDetected
    assert_eq!(
        result.outcome,
        TransportAnalysisOutcome::RegressionMaskDetected
    );
}

// ===========================================================================
// 73. Analysis result schema/bead populated from constants
// ===========================================================================

#[test]
fn enrichment_analysis_result_schema_and_bead_populated() {
    let result = run_analysis(&simple_input(vec![simple_spec("sr", vec![])]));
    assert_eq!(result.schema_version, TRANSPORT_LEDGER_SCHEMA_VERSION);
    assert_eq!(result.bead_id, TRANSPORT_LEDGER_BEAD_ID);
}

// ===========================================================================
// 74. Analysis result counts match ledger queries
// ===========================================================================

#[test]
fn enrichment_analysis_result_counts_consistent_with_ledger() {
    let specs = vec![
        simple_spec("unch-a", vec![]),
        simple_spec("unch-b", vec![]),
        simple_spec("adapt-a", vec![make_delta("t", "a", "b", 100_000, true)]),
        {
            let mut s = simple_spec("incompat-a", vec![]);
            s.broken_invariants = vec!["b".to_string()];
            s
        },
    ];
    let result = run_analysis(&simple_input(specs));
    assert_eq!(result.total_entries, result.ledger.entry_count());
    assert_eq!(result.unchanged_entries, result.ledger.unchanged_count());
    assert_eq!(
        result.adapter_entries,
        result.ledger.adapter_required_count()
    );
    assert_eq!(
        result.incompatible_entries,
        result.ledger.incompatible_count()
    );
    assert_eq!(
        result.regression_mask_count,
        result.ledger.regression_masks.len()
    );
    assert_eq!(
        result.high_risk_mask_count,
        result.ledger.high_risk_masks().len()
    );
}

// ===========================================================================
// 75. Custom incompatibility threshold changes verdict
// ===========================================================================

#[test]
fn enrichment_custom_incompatibility_threshold() {
    // Default threshold is 750_000. With a delta of 500_000 bridgeable,
    // this is below threshold -> AdapterRequired.
    let analyzer_default = SemanticTransportAnalyzer::new();
    let spec = simple_spec(
        "threshold-test",
        vec![make_delta("perf", "fast", "slow", 500_000, true)],
    );
    let r = analyzer_default
        .analyze(&simple_input(vec![spec.clone()]))
        .unwrap();
    assert_eq!(
        r.ledger.entries[0].verdict,
        TransportVerdict::AdapterRequired
    );

    // With threshold at 400_000, same delta is above threshold.
    // But since all bridgeable, it's still AdapterRequired (not Incompatible).
    let config = TransportAnalyzerConfig {
        incompatibility_threshold_millionths: 400_000,
        ..TransportAnalyzerConfig::default()
    };
    let analyzer_low = SemanticTransportAnalyzer::with_config(config);
    let r2 = analyzer_low
        .analyze(&simple_input(vec![simple_spec(
            "threshold-test-2",
            vec![make_delta("perf", "fast", "slow", 500_000, true)],
        )]))
        .unwrap();
    // Above threshold + all bridgeable -> still AdapterRequired
    assert_eq!(
        r2.ledger.entries[0].verdict,
        TransportVerdict::AdapterRequired
    );
}

// ===========================================================================
// 76. Multiple deltas: severity summed for threshold comparison
// ===========================================================================

#[test]
fn enrichment_multiple_deltas_severity_summed() {
    // Two bridgeable deltas, each 400_000 = total 800_000 which is above 750_000.
    // All bridgeable -> AdapterRequired (not Incompatible).
    let spec = simple_spec(
        "multi-delta",
        vec![
            make_delta("a", "x", "y", 400_000, true),
            make_delta("b", "x", "y", 400_000, true),
        ],
    );
    let result = run_analysis(&simple_input(vec![spec]));
    assert_eq!(
        result.ledger.entries[0].verdict,
        TransportVerdict::AdapterRequired
    );
}

// ===========================================================================
// 77. Serde round-trip: TransportAnalysisInput
// ===========================================================================

#[test]
fn enrichment_transport_analysis_input_serde_roundtrip() {
    let input = TransportAnalysisInput {
        entries: vec![simple_spec(
            "s1",
            vec![make_delta("t", "a", "b", 100_000, true)],
        )],
        morphisms: vec![make_morphism_spec(
            "m1",
            ContractDomain::Portal,
            true,
            vec![],
        )],
        epoch: 42,
    };
    let json = serde_json::to_string(&input).unwrap();
    let back: TransportAnalysisInput = serde_json::from_str(&json).unwrap();
    assert_eq!(input, back);
}

// ===========================================================================
// 78. Serde round-trip: RegressionMask
// ===========================================================================

#[test]
fn enrichment_regression_mask_serde_roundtrip() {
    let mask = RegressionMask {
        id: make_id(b"serde-mask"),
        entry_id: make_id(b"serde-entry"),
        morphism_id: Some(make_id(b"serde-morph")),
        masked_aspect: "timing".to_string(),
        reason: "lossy morphism".to_string(),
        risk_millionths: 700_000,
        debt_code: DEBT_REGRESSION_MASKED.to_string(),
        evidence_hash: ContentHash::compute(b"serde-mask-evidence"),
    };
    let json = serde_json::to_string(&mask).unwrap();
    let back: RegressionMask = serde_json::from_str(&json).unwrap();
    assert_eq!(mask, back);
}

// ===========================================================================
// 79. Serde round-trip: SemanticTransportAnalyzer
// ===========================================================================

#[test]
fn enrichment_analyzer_serde_roundtrip() {
    let analyzer = SemanticTransportAnalyzer::new();
    let json = serde_json::to_string(&analyzer).unwrap();
    let back: SemanticTransportAnalyzer = serde_json::from_str(&json).unwrap();
    // Verify by running same analysis and getting same result
    let input = simple_input(vec![simple_spec("serde-test", vec![])]);
    let r1 = analyzer.analyze(&input).unwrap();
    let r2 = back.analyze(&input).unwrap();
    assert_eq!(r1.result_hash, r2.result_hash);
}

// ===========================================================================
// 80. Large batch: many entries all unchanged -> FullyCompatible
// ===========================================================================

#[test]
fn enrichment_large_batch_all_unchanged() {
    let specs: Vec<_> = (0..50)
        .map(|i| simple_spec(&format!("batch-{i}"), vec![]))
        .collect();
    let result = run_analysis(&simple_input(specs));
    assert_eq!(result.total_entries, 50);
    assert_eq!(result.unchanged_entries, 50);
    assert_eq!(result.outcome, TransportAnalysisOutcome::FullyCompatible);
    assert!(result.can_release());
}

// ===========================================================================
// 81. Ledger hash differs with different epoch (via morphisms/entries)
// ===========================================================================

#[test]
fn enrichment_ledger_new_hash_independent_of_epoch() {
    // SemanticTransportLedger::new hashes b"empty-ledger" regardless of epoch
    let l1 = SemanticTransportLedger::new(1);
    let l2 = SemanticTransportLedger::new(999);
    assert_eq!(l1.ledger_hash, l2.ledger_hash);
    assert_ne!(l1.compiled_epoch, l2.compiled_epoch);
}

// ===========================================================================
// 82. Analysis epoch propagated to result
// ===========================================================================

#[test]
fn enrichment_analysis_epoch_propagated() {
    let input = TransportAnalysisInput {
        entries: vec![simple_spec("epoch-test", vec![])],
        morphisms: vec![],
        epoch: 12345,
    };
    let result = run_analysis(&input);
    assert_eq!(result.analysis_epoch, 12345);
    assert_eq!(result.ledger.compiled_epoch, 12345);
}

// ===========================================================================
// 83. VersionPair ordering (Ord trait)
// ===========================================================================

#[test]
fn enrichment_version_pair_ord_deterministic() {
    let p1 = VersionPair::new(ver(0, 1, 0), ver(0, 2, 0));
    let p2 = VersionPair::new(ver(0, 1, 0), ver(0, 3, 0));
    let p3 = VersionPair::new(ver(1, 0, 0), ver(2, 0, 0));
    let mut pairs = vec![p3.clone(), p1.clone(), p2.clone()];
    pairs.sort();
    // Ord is derived, so source first then target
    assert_eq!(pairs[0], p1);
    assert_eq!(pairs[1], p2);
    assert_eq!(pairs[2], p3);
}

// ===========================================================================
// 84. ContractDomain ordering (Ord trait) is deterministic
// ===========================================================================

#[test]
fn enrichment_contract_domain_ord_deterministic() {
    let mut domains = vec![
        ContractDomain::Portal,
        ContractDomain::Hook,
        ContractDomain::Effect,
    ];
    let domains_clone = domains.clone();
    domains.sort();
    // Re-sort to ensure determinism
    let mut domains2 = domains_clone;
    domains2.sort();
    assert_eq!(domains, domains2);
}

// ===========================================================================
// 85. TransportVerdict ordering (Ord trait)
// ===========================================================================

#[test]
fn enrichment_transport_verdict_ord_deterministic() {
    let mut verdicts = vec![
        TransportVerdict::Unknown,
        TransportVerdict::Unchanged,
        TransportVerdict::Incompatible,
        TransportVerdict::AdapterRequired,
    ];
    let v_clone = verdicts.clone();
    verdicts.sort();
    let mut v2 = v_clone;
    v2.sort();
    assert_eq!(verdicts, v2);
}

// ===========================================================================
// 86. TransportAnalysisOutcome ordering
// ===========================================================================

#[test]
fn enrichment_analysis_outcome_ord_deterministic() {
    let mut outcomes = vec![
        TransportAnalysisOutcome::BudgetExhausted,
        TransportAnalysisOutcome::FullyCompatible,
        TransportAnalysisOutcome::RegressionMaskDetected,
    ];
    let o_clone = outcomes.clone();
    outcomes.sort();
    let mut o2 = o_clone;
    o2.sort();
    assert_eq!(outcomes, o2);
}
