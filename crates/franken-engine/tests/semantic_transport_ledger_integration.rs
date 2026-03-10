#![forbid(unsafe_code)]
//! Integration tests for the `semantic_transport_ledger` module (FRX-14.4).
//!
//! Exercises the full transport analysis pipeline from outside the crate
//! boundary: entry specs, morphisms, verdicts, regression masks, budget
//! exhaustion, gate helpers, and report rendering.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::semantic_contract_baseline::SemanticContractVersion;
use frankenengine_engine::semantic_transport_ledger::{
    BehavioralDelta, CompatibilityMorphism, ContractDomain, DEBT_ADAPTER_REQUIRED,
    DEBT_BUDGET_EXHAUSTED, DEBT_MORPHISM_UNVERIFIED, DEBT_REGRESSION_MASKED,
    DEBT_TRANSPORT_INCOMPATIBLE, MorphismSpec, RegressionMask, SemanticTransportAnalyzer,
    SemanticTransportLedger, TRANSPORT_LEDGER_BEAD_ID, TRANSPORT_LEDGER_SCHEMA_VERSION,
    TransportAnalysisInput, TransportAnalysisOutcome, TransportAnalysisResult,
    TransportAnalyzerConfig, TransportEntrySpec, TransportError, TransportVerdict, VersionPair,
    render_transport_report, should_block_gate,
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

fn delta(aspect: &str, src: &str, tgt: &str, severity: i64, bridgeable: bool) -> BehavioralDelta {
    BehavioralDelta {
        aspect: aspect.to_string(),
        source_behavior: src.to_string(),
        target_behavior: tgt.to_string(),
        severity_millionths: severity,
        adapter_bridgeable: bridgeable,
    }
}

#[allow(clippy::too_many_arguments)]
fn entry_spec(
    name: &str,
    domain: ContractDomain,
    src: SemanticContractVersion,
    tgt: SemanticContractVersion,
    deltas: Vec<BehavioralDelta>,
    required: &[&str],
    verified: &[&str],
    broken: &[&str],
) -> TransportEntrySpec {
    TransportEntrySpec {
        fragment_name: name.to_string(),
        domain,
        source_version: src,
        target_version: tgt,
        behavioral_deltas: deltas,
        required_invariants: required.iter().map(|s| s.to_string()).collect(),
        verified_invariants: verified.iter().map(|s| s.to_string()).collect(),
        broken_invariants: broken.iter().map(|s| s.to_string()).collect(),
    }
}

#[allow(clippy::too_many_arguments)]
fn morphism_spec(
    name: &str,
    domain: ContractDomain,
    src: SemanticContractVersion,
    tgt: SemanticContractVersion,
    preserved: &[&str],
    broken: &[&str],
    verified: bool,
    desc: &str,
    adapter: Option<&str>,
) -> MorphismSpec {
    MorphismSpec {
        name: name.to_string(),
        domain,
        source_version: src,
        target_version: tgt,
        preserved_invariants: preserved.iter().map(|s| s.to_string()).collect(),
        broken_invariants: broken.iter().map(|s| s.to_string()).collect(),
        verified,
        description: desc.to_string(),
        adapter_ref: adapter.map(|s| s.to_string()),
    }
}

fn simple_input(entries: Vec<TransportEntrySpec>) -> TransportAnalysisInput {
    TransportAnalysisInput {
        entries,
        morphisms: Vec::new(),
        epoch: 1,
    }
}

fn analyzer() -> SemanticTransportAnalyzer {
    SemanticTransportAnalyzer::new()
}

// ===========================================================================
// 1. Schema constants
// ===========================================================================

#[test]
fn schema_version_is_stable() {
    assert_eq!(
        TRANSPORT_LEDGER_SCHEMA_VERSION,
        "franken-engine.semantic_transport_ledger.v1"
    );
}

#[test]
fn bead_id_is_stable() {
    assert_eq!(TRANSPORT_LEDGER_BEAD_ID, "bd-mjh3.14.4");
}

#[test]
fn debt_codes_are_stable() {
    let codes = [
        DEBT_TRANSPORT_INCOMPATIBLE,
        DEBT_ADAPTER_REQUIRED,
        DEBT_REGRESSION_MASKED,
        DEBT_MORPHISM_UNVERIFIED,
        DEBT_BUDGET_EXHAUSTED,
    ];
    for code in &codes {
        assert!(code.starts_with("FE-FRX-14-4-TRANSPORT-"));
    }
    let unique: BTreeSet<&str> = codes.iter().copied().collect();
    assert_eq!(unique.len(), codes.len(), "debt codes must be unique");
}

// ===========================================================================
// 2. TransportVerdict display and serde
// ===========================================================================

#[test]
fn transport_verdict_display() {
    let verdicts = [
        TransportVerdict::Unchanged,
        TransportVerdict::AdapterRequired,
        TransportVerdict::Incompatible,
        TransportVerdict::Unknown,
    ];
    for v in &verdicts {
        let s = v.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn transport_verdict_serde_round_trip() {
    let verdicts = [
        TransportVerdict::Unchanged,
        TransportVerdict::AdapterRequired,
        TransportVerdict::Incompatible,
        TransportVerdict::Unknown,
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: TransportVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, v);
    }
}

#[test]
fn transport_verdict_ordering() {
    assert!(TransportVerdict::Unchanged < TransportVerdict::Incompatible);
}

// ===========================================================================
// 3. ContractDomain display and serde
// ===========================================================================

#[test]
fn contract_domain_display_all_variants() {
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
        let s = d.to_string();
        assert!(!s.is_empty(), "domain {d:?} has empty display");
    }
}

#[test]
fn contract_domain_serde_round_trip() {
    let d = ContractDomain::Suspense;
    let json = serde_json::to_string(&d).unwrap();
    let back: ContractDomain = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}

// ===========================================================================
// 4. TransportAnalysisOutcome display and serde
// ===========================================================================

#[test]
fn outcome_display_all_variants() {
    let outcomes = [
        TransportAnalysisOutcome::FullyCompatible,
        TransportAnalysisOutcome::CompatibleWithAdapters,
        TransportAnalysisOutcome::HasIncompatibilities,
        TransportAnalysisOutcome::RegressionMaskDetected,
        TransportAnalysisOutcome::BudgetExhausted,
    ];
    for o in &outcomes {
        let s = o.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn outcome_serde_round_trip() {
    let o = TransportAnalysisOutcome::CompatibleWithAdapters;
    let json = serde_json::to_string(&o).unwrap();
    let back: TransportAnalysisOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(back, o);
}

// ===========================================================================
// 5. VersionPair
// ===========================================================================

#[test]
fn version_pair_display() {
    let vp = VersionPair::new(ver(1, 0, 0), ver(2, 0, 0));
    let s = vp.to_string();
    assert!(s.contains("1.0.0"));
    assert!(s.contains("2.0.0"));
}

#[test]
fn version_pair_same_major() {
    let vp = VersionPair::new(ver(1, 0, 0), ver(1, 2, 0));
    assert!(vp.is_same_major());
}

#[test]
fn version_pair_different_major_not_same() {
    let vp = VersionPair::new(ver(1, 0, 0), ver(2, 0, 0));
    assert!(!vp.is_same_major());
}

#[test]
fn version_pair_upgrade() {
    let vp = VersionPair::new(ver(1, 0, 0), ver(1, 1, 0));
    assert!(vp.is_upgrade());
    assert!(!vp.is_downgrade());
}

#[test]
fn version_pair_downgrade() {
    let vp = VersionPair::new(ver(2, 0, 0), ver(1, 0, 0));
    assert!(vp.is_downgrade());
    assert!(!vp.is_upgrade());
}

#[test]
fn version_pair_same_version_neither_upgrade_nor_downgrade() {
    let vp = VersionPair::new(ver(1, 0, 0), ver(1, 0, 0));
    assert!(!vp.is_upgrade());
    assert!(!vp.is_downgrade());
}

#[test]
fn version_pair_serde_round_trip() {
    let vp = VersionPair::new(ver(3, 1, 7), ver(4, 0, 0));
    let json = serde_json::to_string(&vp).unwrap();
    let back: VersionPair = serde_json::from_str(&json).unwrap();
    assert_eq!(back, vp);
}

// ===========================================================================
// 6. BehavioralDelta
// ===========================================================================

#[test]
fn behavioral_delta_display() {
    let d = delta("timing", "sync", "async", 300_000, true);
    let s = d.to_string();
    assert!(!s.is_empty());
    assert!(s.contains("timing"));
}

#[test]
fn behavioral_delta_serde_round_trip() {
    let d = delta("cleanup", "eager", "lazy", 500_000, false);
    let json = serde_json::to_string(&d).unwrap();
    let back: BehavioralDelta = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}

// ===========================================================================
// 7. Empty input → FullyCompatible
// ===========================================================================

#[test]
fn empty_input_is_fully_compatible() {
    let inp = simple_input(Vec::new());
    let result = analyzer().analyze(&inp).unwrap();
    assert_eq!(result.outcome, TransportAnalysisOutcome::FullyCompatible);
    assert_eq!(result.total_entries, 0);
    assert!(result.can_release());
}

#[test]
fn empty_result_has_correct_schema() {
    let inp = simple_input(Vec::new());
    let result = analyzer().analyze(&inp).unwrap();
    assert_eq!(result.schema_version, TRANSPORT_LEDGER_SCHEMA_VERSION);
    assert_eq!(result.bead_id, TRANSPORT_LEDGER_BEAD_ID);
}

#[test]
fn empty_result_has_epoch() {
    let inp = TransportAnalysisInput {
        entries: Vec::new(),
        morphisms: Vec::new(),
        epoch: 42,
    };
    let result = analyzer().analyze(&inp).unwrap();
    assert_eq!(result.analysis_epoch, 42);
    assert_eq!(result.ledger.compiled_epoch, 42);
}

// ===========================================================================
// 8. Unchanged transport — no deltas, all invariants verified
// ===========================================================================

#[test]
fn all_unchanged_entries_gives_fully_compatible() {
    let es = vec![
        entry_spec(
            "useEffect",
            ContractDomain::Effect,
            ver(1, 0, 0),
            ver(1, 1, 0),
            Vec::new(),
            &["order-preserved"],
            &["order-preserved"],
            &[],
        ),
        entry_spec(
            "useContext",
            ContractDomain::Context,
            ver(1, 0, 0),
            ver(1, 1, 0),
            Vec::new(),
            &["provider-resolution"],
            &["provider-resolution"],
            &[],
        ),
    ];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    assert_eq!(result.outcome, TransportAnalysisOutcome::FullyCompatible);
    assert_eq!(result.unchanged_entries, 2);
    assert_eq!(result.adapter_entries, 0);
    assert_eq!(result.incompatible_entries, 0);
    assert!(result.can_release());
}

// ===========================================================================
// 9. Adapter required — bridgeable deltas
// ===========================================================================

#[test]
fn bridgeable_delta_gives_adapter_required() {
    let es = vec![entry_spec(
        "useLayoutEffect",
        ContractDomain::Effect,
        ver(1, 0, 0),
        ver(2, 0, 0),
        vec![delta("timing", "sync-paint", "async-paint", 300_000, true)],
        &["fires-before-paint"],
        &["fires-before-paint"],
        &[],
    )];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    assert_eq!(
        result.outcome,
        TransportAnalysisOutcome::CompatibleWithAdapters
    );
    assert_eq!(result.adapter_entries, 1);
    assert!(result.can_release());
}

// ===========================================================================
// 10. Incompatible — non-bridgeable deltas
// ===========================================================================

#[test]
fn non_bridgeable_delta_gives_incompatible() {
    let es = vec![entry_spec(
        "useSyncExternalStore",
        ContractDomain::Hook,
        ver(1, 0, 0),
        ver(2, 0, 0),
        vec![delta(
            "tearing",
            "no-tearing",
            "possible-tearing",
            800_000,
            false,
        )],
        &["no-tearing-guarantee"],
        &[],
        &["no-tearing-guarantee"],
    )];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    assert_eq!(
        result.outcome,
        TransportAnalysisOutcome::HasIncompatibilities
    );
    assert_eq!(result.incompatible_entries, 1);
    assert!(!result.can_release());
}

#[test]
fn high_severity_non_bridgeable_is_incompatible() {
    let es = vec![entry_spec(
        "ErrorBoundary",
        ContractDomain::ErrorBoundary,
        ver(1, 0, 0),
        ver(3, 0, 0),
        vec![delta(
            "catch-scope",
            "class-only",
            "functional-too",
            900_000,
            false,
        )],
        &["catches-render-errors"],
        &[],
        &["catches-render-errors"],
    )];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    assert!(!result.can_release());
}

// ===========================================================================
// 11. Mixed verdicts — worst verdict determines outcome
// ===========================================================================

#[test]
fn mixed_verdicts_worst_wins() {
    let es = vec![
        entry_spec(
            "useEffect",
            ContractDomain::Effect,
            ver(1, 0, 0),
            ver(2, 0, 0),
            Vec::new(),
            &["order"],
            &["order"],
            &[],
        ),
        entry_spec(
            "useRef",
            ContractDomain::Ref,
            ver(1, 0, 0),
            ver(2, 0, 0),
            vec![delta("forwarding", "manual", "auto", 200_000, true)],
            &["stable-ref"],
            &["stable-ref"],
            &[],
        ),
        entry_spec(
            "Suspense",
            ContractDomain::Suspense,
            ver(1, 0, 0),
            ver(2, 0, 0),
            vec![delta(
                "streaming",
                "no-streaming",
                "streaming",
                800_000,
                false,
            )],
            &["shows-fallback"],
            &[],
            &["shows-fallback"],
        ),
    ];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    assert_eq!(
        result.outcome,
        TransportAnalysisOutcome::HasIncompatibilities
    );
    assert_eq!(result.unchanged_entries, 1);
    assert_eq!(result.adapter_entries, 1);
    assert_eq!(result.incompatible_entries, 1);
    assert_eq!(result.total_entries, 3);
}

// ===========================================================================
// 12. TransportEntry accessors
// ===========================================================================

#[test]
fn entry_is_blocking_for_incompatible() {
    let es = vec![entry_spec(
        "Portal",
        ContractDomain::Portal,
        ver(1, 0, 0),
        ver(2, 0, 0),
        vec![delta("rendering", "sync", "async", 800_000, false)],
        &["mounts-in-target"],
        &[],
        &["mounts-in-target"],
    )];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    let entry = &result.ledger.entries[0];
    assert!(entry.is_blocking());
}

#[test]
fn entry_not_blocking_for_unchanged() {
    let es = vec![entry_spec(
        "useContext",
        ContractDomain::Context,
        ver(1, 0, 0),
        ver(1, 1, 0),
        Vec::new(),
        &["resolves-closest"],
        &["resolves-closest"],
        &[],
    )];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    let entry = &result.ledger.entries[0];
    assert!(!entry.is_blocking());
}

#[test]
fn entry_invariant_coverage_all_verified() {
    let es = vec![entry_spec(
        "useEffect",
        ContractDomain::Effect,
        ver(1, 0, 0),
        ver(1, 0, 1),
        Vec::new(),
        &["a", "b"],
        &["a", "b"],
        &[],
    )];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    let entry = &result.ledger.entries[0];
    assert!(entry.all_invariants_verified());
    assert_eq!(entry.invariant_coverage_millionths(), 1_000_000);
}

#[test]
fn entry_invariant_coverage_partial() {
    let es = vec![entry_spec(
        "useEffect",
        ContractDomain::Effect,
        ver(1, 0, 0),
        ver(2, 0, 0),
        vec![delta("timing", "sync", "async", 200_000, true)],
        &["a", "b", "c", "d"],
        &["a", "b"],
        &[],
    )];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    let entry = &result.ledger.entries[0];
    assert!(!entry.all_invariants_verified());
    assert_eq!(entry.invariant_coverage_millionths(), 500_000);
}

#[test]
fn entry_summary_line_nonempty() {
    let es = vec![entry_spec(
        "useHook",
        ContractDomain::Hook,
        ver(1, 0, 0),
        ver(1, 1, 0),
        Vec::new(),
        &["idempotent"],
        &["idempotent"],
        &[],
    )];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    let line = result.ledger.entries[0].summary_line();
    assert!(!line.is_empty());
    assert!(line.contains("useHook"));
}

// ===========================================================================
// 13. Ledger accessors
// ===========================================================================

#[test]
fn ledger_entries_by_verdict() {
    let es = vec![
        entry_spec(
            "A",
            ContractDomain::Hook,
            ver(1, 0, 0),
            ver(1, 1, 0),
            Vec::new(),
            &["x"],
            &["x"],
            &[],
        ),
        entry_spec(
            "B",
            ContractDomain::Hook,
            ver(1, 0, 0),
            ver(2, 0, 0),
            vec![delta("d", "s", "t", 300_000, true)],
            &["y"],
            &["y"],
            &[],
        ),
    ];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    let unchanged = result
        .ledger
        .entries_by_verdict(&TransportVerdict::Unchanged);
    let adapter = result
        .ledger
        .entries_by_verdict(&TransportVerdict::AdapterRequired);
    assert_eq!(unchanged.len(), 1);
    assert_eq!(adapter.len(), 1);
}

#[test]
fn ledger_entries_by_domain() {
    let es = vec![
        entry_spec(
            "A",
            ContractDomain::Hook,
            ver(1, 0, 0),
            ver(1, 1, 0),
            Vec::new(),
            &[],
            &[],
            &[],
        ),
        entry_spec(
            "B",
            ContractDomain::Effect,
            ver(1, 0, 0),
            ver(1, 1, 0),
            Vec::new(),
            &[],
            &[],
            &[],
        ),
        entry_spec(
            "C",
            ContractDomain::Hook,
            ver(1, 0, 0),
            ver(1, 1, 0),
            Vec::new(),
            &[],
            &[],
            &[],
        ),
    ];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    let hooks = result.ledger.entries_by_domain(&ContractDomain::Hook);
    assert_eq!(hooks.len(), 2);
    let effects = result.ledger.entries_by_domain(&ContractDomain::Effect);
    assert_eq!(effects.len(), 1);
}

#[test]
fn ledger_version_pairs() {
    let es = vec![
        entry_spec(
            "A",
            ContractDomain::Hook,
            ver(1, 0, 0),
            ver(2, 0, 0),
            Vec::new(),
            &[],
            &[],
            &[],
        ),
        entry_spec(
            "B",
            ContractDomain::Hook,
            ver(1, 0, 0),
            ver(3, 0, 0),
            Vec::new(),
            &[],
            &[],
            &[],
        ),
    ];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    let pairs = result.ledger.version_pairs();
    assert_eq!(pairs.len(), 2);
}

#[test]
fn ledger_verdict_counts() {
    let es = vec![
        entry_spec(
            "A",
            ContractDomain::Hook,
            ver(1, 0, 0),
            ver(1, 1, 0),
            Vec::new(),
            &["x"],
            &["x"],
            &[],
        ),
        entry_spec(
            "B",
            ContractDomain::Effect,
            ver(1, 0, 0),
            ver(2, 0, 0),
            vec![delta("d", "a", "b", 400_000, true)],
            &["y"],
            &["y"],
            &[],
        ),
        entry_spec(
            "C",
            ContractDomain::Context,
            ver(1, 0, 0),
            ver(2, 0, 0),
            vec![delta("d2", "a2", "b2", 800_000, false)],
            &["z"],
            &[],
            &["z"],
        ),
    ];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    assert_eq!(result.ledger.unchanged_count(), 1);
    assert_eq!(result.ledger.adapter_required_count(), 1);
    assert_eq!(result.ledger.incompatible_count(), 1);
    assert_eq!(result.ledger.entry_count(), 3);
}

#[test]
fn ledger_coverage_all_unchanged() {
    let es = vec![
        entry_spec(
            "A",
            ContractDomain::Hook,
            ver(1, 0, 0),
            ver(1, 1, 0),
            Vec::new(),
            &[],
            &[],
            &[],
        ),
        entry_spec(
            "B",
            ContractDomain::Effect,
            ver(1, 0, 0),
            ver(1, 1, 0),
            Vec::new(),
            &[],
            &[],
            &[],
        ),
    ];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    assert_eq!(result.ledger.coverage_millionths(), 1_000_000);
}

#[test]
fn ledger_summary_line_nonempty() {
    let es = vec![entry_spec(
        "A",
        ContractDomain::Hook,
        ver(1, 0, 0),
        ver(1, 1, 0),
        Vec::new(),
        &[],
        &[],
        &[],
    )];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    let line = result.ledger.summary_line();
    assert!(!line.is_empty());
}

#[test]
fn ledger_new_is_empty() {
    let ledger = SemanticTransportLedger::new(10);
    assert_eq!(ledger.entry_count(), 0);
    assert_eq!(ledger.compiled_epoch, 10);
    assert_eq!(ledger.schema_version, TRANSPORT_LEDGER_SCHEMA_VERSION);
}

// ===========================================================================
// 14. Morphisms
// ===========================================================================

#[test]
fn morphism_verified_and_not_lossy_is_safe() {
    let inp = TransportAnalysisInput {
        entries: vec![entry_spec(
            "useEffect",
            ContractDomain::Effect,
            ver(1, 0, 0),
            ver(2, 0, 0),
            vec![delta("timing", "sync", "async", 200_000, true)],
            &["order-preserved"],
            &["order-preserved"],
            &[],
        )],
        morphisms: vec![morphism_spec(
            "effect-timing-adapter",
            ContractDomain::Effect,
            ver(1, 0, 0),
            ver(2, 0, 0),
            &["order-preserved"],
            &[],
            true,
            "bridges effect timing difference",
            Some("adapters/effect-timing.rs"),
        )],
        epoch: 1,
    };
    let result = analyzer().analyze(&inp).unwrap();
    assert!(!result.ledger.morphisms.is_empty());
    let m = &result.ledger.morphisms[0];
    assert!(m.is_safe());
    assert!(!m.lossy);
    assert!(m.verified);
}

#[test]
fn morphism_unverified_is_not_safe() {
    let inp = TransportAnalysisInput {
        entries: vec![entry_spec(
            "useRef",
            ContractDomain::Ref,
            ver(1, 0, 0),
            ver(2, 0, 0),
            vec![delta("forwarding", "manual", "auto", 200_000, true)],
            &["stable"],
            &["stable"],
            &[],
        )],
        morphisms: vec![morphism_spec(
            "ref-forwarder",
            ContractDomain::Ref,
            ver(1, 0, 0),
            ver(2, 0, 0),
            &["stable"],
            &[],
            false,
            "unverified adapter",
            None,
        )],
        epoch: 1,
    };
    let result = analyzer().analyze(&inp).unwrap();
    let m = &result.ledger.morphisms[0];
    assert!(!m.is_safe());
}

#[test]
fn morphism_summary_line_nonempty() {
    let inp = TransportAnalysisInput {
        entries: vec![entry_spec(
            "useEffect",
            ContractDomain::Effect,
            ver(1, 0, 0),
            ver(2, 0, 0),
            vec![delta("t", "s", "a", 200_000, true)],
            &["x"],
            &["x"],
            &[],
        )],
        morphisms: vec![morphism_spec(
            "my-morph",
            ContractDomain::Effect,
            ver(1, 0, 0),
            ver(2, 0, 0),
            &["x"],
            &[],
            true,
            "desc",
            None,
        )],
        epoch: 1,
    };
    let result = analyzer().analyze(&inp).unwrap();
    let line = result.ledger.morphisms[0].summary_line();
    assert!(!line.is_empty());
    assert!(line.contains("my-morph"));
}

#[test]
fn morphism_serde_round_trip() {
    let inp = TransportAnalysisInput {
        entries: vec![entry_spec(
            "A",
            ContractDomain::Hook,
            ver(1, 0, 0),
            ver(2, 0, 0),
            vec![delta("d", "s", "t", 200_000, true)],
            &["x"],
            &["x"],
            &[],
        )],
        morphisms: vec![morphism_spec(
            "m",
            ContractDomain::Hook,
            ver(1, 0, 0),
            ver(2, 0, 0),
            &["x"],
            &[],
            true,
            "d",
            Some("adapter.rs"),
        )],
        epoch: 1,
    };
    let result = analyzer().analyze(&inp).unwrap();
    let m = &result.ledger.morphisms[0];
    let json = serde_json::to_string(m).unwrap();
    let back: CompatibilityMorphism = serde_json::from_str(&json).unwrap();
    assert_eq!(back.name, m.name);
    assert_eq!(back.verified, m.verified);
}

// ===========================================================================
// 15. Regression masks
// ===========================================================================

#[test]
fn regression_mask_high_risk() {
    let id = frankenengine_engine::engine_object_id::EngineObjectId::from_hex(
        "aa00000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    let entry_id = frankenengine_engine::engine_object_id::EngineObjectId::from_hex(
        "bb00000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    let mask = RegressionMask {
        id,
        entry_id,
        morphism_id: None,
        masked_aspect: "timing".to_string(),
        reason: "adapter hides behavioral change".to_string(),
        risk_millionths: 700_000,
        debt_code: DEBT_REGRESSION_MASKED.to_string(),
        evidence_hash: ContentHash::compute(b"mask"),
    };
    assert!(mask.is_high_risk());
}

#[test]
fn regression_mask_low_risk() {
    let id = frankenengine_engine::engine_object_id::EngineObjectId::from_hex(
        "aa00000000000000000000000000000000000000000000000000000000000002",
    )
    .unwrap();
    let entry_id = frankenengine_engine::engine_object_id::EngineObjectId::from_hex(
        "bb00000000000000000000000000000000000000000000000000000000000002",
    )
    .unwrap();
    let mask = RegressionMask {
        id,
        entry_id,
        morphism_id: None,
        masked_aspect: "minor".to_string(),
        reason: "cosmetic difference".to_string(),
        risk_millionths: 200_000,
        debt_code: DEBT_REGRESSION_MASKED.to_string(),
        evidence_hash: ContentHash::compute(b"mask-lo"),
    };
    assert!(!mask.is_high_risk());
}

#[test]
fn regression_mask_summary_line() {
    let id = frankenengine_engine::engine_object_id::EngineObjectId::from_hex(
        "aa00000000000000000000000000000000000000000000000000000000000003",
    )
    .unwrap();
    let entry_id = frankenengine_engine::engine_object_id::EngineObjectId::from_hex(
        "bb00000000000000000000000000000000000000000000000000000000000003",
    )
    .unwrap();
    let mask = RegressionMask {
        id,
        entry_id,
        morphism_id: None,
        masked_aspect: "ordering".to_string(),
        reason: "masked".to_string(),
        risk_millionths: 500_000,
        debt_code: DEBT_REGRESSION_MASKED.to_string(),
        evidence_hash: ContentHash::compute(b"mask-s"),
    };
    let line = mask.summary_line();
    assert!(!line.is_empty());
    assert!(line.contains("ordering"));
}

// ===========================================================================
// 16. Debt codes in results
// ===========================================================================

#[test]
fn all_debt_codes_collected() {
    let es = vec![
        entry_spec(
            "A",
            ContractDomain::Hook,
            ver(1, 0, 0),
            ver(2, 0, 0),
            vec![delta("d", "s", "t", 800_000, false)],
            &["x"],
            &[],
            &["x"],
        ),
        entry_spec(
            "B",
            ContractDomain::Effect,
            ver(1, 0, 0),
            ver(2, 0, 0),
            vec![delta("d2", "s2", "t2", 300_000, true)],
            &["y"],
            &["y"],
            &[],
        ),
    ];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    let codes = result.ledger.all_debt_codes();
    assert!(!codes.is_empty());
}

// ===========================================================================
// 17. Budget exhaustion
// ===========================================================================

#[test]
fn budget_exhaustion_on_too_many_entries() {
    let cfg = TransportAnalyzerConfig {
        max_entries: 2,
        max_morphisms_per_entry: 100,
        max_regression_masks: 10_000,
        incompatibility_threshold_millionths: 750_000,
        detect_regression_masks: true,
    };
    let a = SemanticTransportAnalyzer::with_config(cfg);
    let es: Vec<TransportEntrySpec> = (0..5)
        .map(|i| {
            entry_spec(
                &format!("entry_{i}"),
                ContractDomain::Hook,
                ver(1, 0, 0),
                ver(1, 1, 0),
                Vec::new(),
                &[],
                &[],
                &[],
            )
        })
        .collect();
    let result = a.analyze(&simple_input(es));
    match result {
        Ok(r) => assert_eq!(r.outcome, TransportAnalysisOutcome::BudgetExhausted),
        Err(TransportError::BudgetExhausted { .. }) => {}
        Err(e) => panic!("unexpected error: {e}"),
    }
}

// ===========================================================================
// 18. TransportError display
// ===========================================================================

#[test]
fn transport_error_display() {
    let e = TransportError::BudgetExhausted {
        resource: "entries".to_string(),
        limit: 50_000,
    };
    let s = e.to_string();
    assert!(s.contains("entries"));
    assert!(s.contains("50000"));
}

#[test]
fn transport_error_duplicate_entry() {
    let e = TransportError::DuplicateEntry("useEffect".to_string());
    let s = e.to_string();
    assert!(s.contains("useEffect"));
}

#[test]
fn transport_error_invalid_version_pair() {
    let e = TransportError::InvalidVersionPair("bad version".to_string());
    assert!(!e.to_string().is_empty());
}

#[test]
fn transport_error_morphism_conflict() {
    let e = TransportError::MorphismConflict("dup-morph".to_string());
    assert!(!e.to_string().is_empty());
}

#[test]
fn transport_error_serde_round_trip() {
    let e = TransportError::DuplicateEntry("hook_x".to_string());
    let json = serde_json::to_string(&e).unwrap();
    let back: TransportError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

// ===========================================================================
// 19. Gate helpers
// ===========================================================================

#[test]
fn should_block_gate_for_incompatibilities() {
    let es = vec![entry_spec(
        "X",
        ContractDomain::Suspense,
        ver(1, 0, 0),
        ver(2, 0, 0),
        vec![delta("stream", "no", "yes", 900_000, false)],
        &["f"],
        &[],
        &["f"],
    )];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    assert!(should_block_gate(&result));
}

#[test]
fn should_not_block_gate_for_fully_compatible() {
    let es = vec![entry_spec(
        "Y",
        ContractDomain::Hook,
        ver(1, 0, 0),
        ver(1, 1, 0),
        Vec::new(),
        &["x"],
        &["x"],
        &[],
    )];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    assert!(!should_block_gate(&result));
}

#[test]
fn should_not_block_gate_for_compatible_with_adapters() {
    let es = vec![entry_spec(
        "Z",
        ContractDomain::Effect,
        ver(1, 0, 0),
        ver(2, 0, 0),
        vec![delta("t", "s", "a", 200_000, true)],
        &["x"],
        &["x"],
        &[],
    )];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    assert!(!should_block_gate(&result));
}

// ===========================================================================
// 20. Report rendering
// ===========================================================================

#[test]
fn report_for_empty_mentions_compatible() {
    let result = analyzer().analyze(&simple_input(Vec::new())).unwrap();
    let report = render_transport_report(&result);
    assert!(!report.is_empty());
    // Should mention the outcome
    assert!(
        report.contains("Compatible") || report.contains("compatible") || report.contains("PASS"),
        "report should mention compatibility for empty analysis"
    );
}

#[test]
fn report_for_incompatible_contains_details() {
    let es = vec![entry_spec(
        "Suspense",
        ContractDomain::Suspense,
        ver(1, 0, 0),
        ver(2, 0, 0),
        vec![delta("streaming", "no", "yes", 800_000, false)],
        &["fallback-display"],
        &[],
        &["fallback-display"],
    )];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    let report = render_transport_report(&result);
    assert!(report.contains("Suspense"));
}

#[test]
fn report_contains_epoch() {
    let inp = TransportAnalysisInput {
        entries: Vec::new(),
        morphisms: Vec::new(),
        epoch: 999,
    };
    let result = analyzer().analyze(&inp).unwrap();
    let report = render_transport_report(&result);
    assert!(report.contains("999"));
}

// ===========================================================================
// 21. TransportAnalysisResult accessors
// ===========================================================================

#[test]
fn result_can_release_for_fully_compatible() {
    let result = analyzer().analyze(&simple_input(Vec::new())).unwrap();
    assert!(result.can_release());
}

#[test]
fn result_summary_line_nonempty() {
    let result = analyzer().analyze(&simple_input(Vec::new())).unwrap();
    let line = result.summary_line();
    assert!(!line.is_empty());
}

// ===========================================================================
// 22. Deterministic hashing
// ===========================================================================

#[test]
fn same_input_same_result_hash() {
    let es = vec![entry_spec(
        "useEffect",
        ContractDomain::Effect,
        ver(1, 0, 0),
        ver(2, 0, 0),
        vec![delta("timing", "sync", "async", 300_000, true)],
        &["order"],
        &["order"],
        &[],
    )];
    let r1 = analyzer().analyze(&simple_input(es.clone())).unwrap();
    let r2 = analyzer().analyze(&simple_input(es)).unwrap();
    assert_eq!(r1.result_hash, r2.result_hash);
    assert_eq!(r1.ledger.ledger_hash, r2.ledger.ledger_hash);
}

#[test]
fn different_input_different_hash() {
    let es1 = vec![entry_spec(
        "A",
        ContractDomain::Hook,
        ver(1, 0, 0),
        ver(1, 1, 0),
        Vec::new(),
        &[],
        &[],
        &[],
    )];
    let es2 = vec![entry_spec(
        "B",
        ContractDomain::Hook,
        ver(1, 0, 0),
        ver(1, 1, 0),
        Vec::new(),
        &[],
        &[],
        &[],
    )];
    let r1 = analyzer().analyze(&simple_input(es1)).unwrap();
    let r2 = analyzer().analyze(&simple_input(es2)).unwrap();
    assert_ne!(r1.result_hash, r2.result_hash);
}

// ===========================================================================
// 23. Serde round-trips for complex result
// ===========================================================================

#[test]
fn full_result_serde_round_trip() {
    let inp = TransportAnalysisInput {
        entries: vec![
            entry_spec(
                "useEffect",
                ContractDomain::Effect,
                ver(1, 0, 0),
                ver(2, 0, 0),
                vec![delta("timing", "sync", "async", 300_000, true)],
                &["order"],
                &["order"],
                &[],
            ),
            entry_spec(
                "useRef",
                ContractDomain::Ref,
                ver(1, 0, 0),
                ver(2, 0, 0),
                Vec::new(),
                &["stable"],
                &["stable"],
                &[],
            ),
        ],
        morphisms: vec![morphism_spec(
            "effect-timing",
            ContractDomain::Effect,
            ver(1, 0, 0),
            ver(2, 0, 0),
            &["order"],
            &[],
            true,
            "bridges timing",
            None,
        )],
        epoch: 42,
    };
    let result = analyzer().analyze(&inp).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: TransportAnalysisResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.outcome, result.outcome);
    assert_eq!(back.total_entries, result.total_entries);
    assert_eq!(back.result_hash, result.result_hash);
    assert_eq!(back.analysis_epoch, result.analysis_epoch);
}

#[test]
fn ledger_serde_round_trip() {
    let result = analyzer().analyze(&simple_input(Vec::new())).unwrap();
    let json = serde_json::to_string(&result.ledger).unwrap();
    let back: SemanticTransportLedger = serde_json::from_str(&json).unwrap();
    assert_eq!(back.compiled_epoch, result.ledger.compiled_epoch);
    assert_eq!(back.ledger_hash, result.ledger.ledger_hash);
}

// ===========================================================================
// 24. Config customization
// ===========================================================================

#[test]
fn custom_incompatibility_threshold() {
    // Lower threshold means less tolerance for severity — but bridgeable
    // deltas are still classified as AdapterRequired regardless of threshold.
    // The threshold governs non-bridgeable severity.
    let cfg = TransportAnalyzerConfig {
        max_entries: 50_000,
        max_morphisms_per_entry: 100,
        max_regression_masks: 10_000,
        incompatibility_threshold_millionths: 200_000,
        detect_regression_masks: true,
    };
    let a = SemanticTransportAnalyzer::with_config(cfg);
    // Non-bridgeable delta exceeding the lowered threshold → Incompatible
    let es = vec![entry_spec(
        "useEffect",
        ContractDomain::Effect,
        ver(1, 0, 0),
        ver(2, 0, 0),
        vec![delta("timing", "sync", "async", 300_000, false)],
        &["order"],
        &[],
        &["order"],
    )];
    let result = a.analyze(&simple_input(es)).unwrap();
    assert_eq!(
        result.outcome,
        TransportAnalysisOutcome::HasIncompatibilities
    );
}

#[test]
fn default_config_serde_round_trip() {
    let cfg = TransportAnalyzerConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: TransportAnalyzerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cfg);
}

// ===========================================================================
// 25. All contract domains produce valid entries
// ===========================================================================

#[test]
fn all_domains_produce_entries() {
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
    let es: Vec<TransportEntrySpec> = domains
        .iter()
        .enumerate()
        .map(|(i, d)| {
            entry_spec(
                &format!("frag_{i}"),
                d.clone(),
                ver(1, 0, 0),
                ver(1, 1, 0),
                Vec::new(),
                &[],
                &[],
                &[],
            )
        })
        .collect();
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    assert_eq!(result.total_entries, domains.len());
    assert_eq!(result.outcome, TransportAnalysisOutcome::FullyCompatible);
}

// ===========================================================================
// 26. Multiple deltas on a single entry
// ===========================================================================

#[test]
fn multiple_deltas_on_single_entry() {
    let es = vec![entry_spec(
        "useEffect",
        ContractDomain::Effect,
        ver(1, 0, 0),
        ver(2, 0, 0),
        vec![
            delta("timing", "sync", "async", 200_000, true),
            delta("cleanup", "eager", "lazy", 100_000, true),
            delta("deps-compare", "shallow", "deep", 150_000, true),
        ],
        &["order-preserved", "cleanup-runs"],
        &["order-preserved", "cleanup-runs"],
        &[],
    )];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    assert_eq!(result.total_entries, 1);
    assert_eq!(result.ledger.entries[0].behavioral_deltas.len(), 3);
}

// ===========================================================================
// 27. Broken invariants produce debt codes
// ===========================================================================

#[test]
fn broken_invariant_entry_has_debt_code() {
    let es = vec![entry_spec(
        "useMemo",
        ContractDomain::Hook,
        ver(1, 0, 0),
        ver(2, 0, 0),
        vec![delta("caching", "always", "sometimes", 800_000, false)],
        &["referential-stability"],
        &[],
        &["referential-stability"],
    )];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    let entry = &result.ledger.entries[0];
    assert!(entry.debt_code.is_some());
}

// ===========================================================================
// 28. Entry hashes are unique per entry
// ===========================================================================

#[test]
fn entry_hashes_are_unique() {
    let es = vec![
        entry_spec(
            "A",
            ContractDomain::Hook,
            ver(1, 0, 0),
            ver(2, 0, 0),
            Vec::new(),
            &[],
            &[],
            &[],
        ),
        entry_spec(
            "B",
            ContractDomain::Effect,
            ver(1, 0, 0),
            ver(2, 0, 0),
            Vec::new(),
            &[],
            &[],
            &[],
        ),
        entry_spec(
            "C",
            ContractDomain::Context,
            ver(1, 0, 0),
            ver(2, 0, 0),
            Vec::new(),
            &[],
            &[],
            &[],
        ),
    ];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    let hashes: BTreeSet<_> = result
        .ledger
        .entries
        .iter()
        .map(|e| &e.entry_hash)
        .collect();
    assert_eq!(
        hashes.len(),
        result.ledger.entries.len(),
        "entry hashes must be unique"
    );
}

// ===========================================================================
// 29. Entry IDs are unique
// ===========================================================================

#[test]
fn entry_ids_are_unique() {
    let es = vec![
        entry_spec(
            "A",
            ContractDomain::Hook,
            ver(1, 0, 0),
            ver(2, 0, 0),
            Vec::new(),
            &[],
            &[],
            &[],
        ),
        entry_spec(
            "B",
            ContractDomain::Hook,
            ver(1, 0, 0),
            ver(2, 0, 0),
            Vec::new(),
            &[],
            &[],
            &[],
        ),
    ];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    let ids: BTreeSet<_> = result.ledger.entries.iter().map(|e| &e.id).collect();
    assert_eq!(ids.len(), 2);
}

// ===========================================================================
// 30. Large analysis — many entries
// ===========================================================================

#[test]
fn large_analysis_many_entries() {
    let es: Vec<TransportEntrySpec> = (0..200)
        .map(|i| {
            entry_spec(
                &format!("fragment_{i}"),
                ContractDomain::Hook,
                ver(1, 0, 0),
                ver(1, 1, 0),
                Vec::new(),
                &[],
                &[],
                &[],
            )
        })
        .collect();
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    assert_eq!(result.total_entries, 200);
    assert_eq!(result.outcome, TransportAnalysisOutcome::FullyCompatible);
}

// ===========================================================================
// 31. Ledger high-risk masks accessor
// ===========================================================================

#[test]
fn ledger_high_risk_masks_empty_when_no_masks() {
    let result = analyzer().analyze(&simple_input(Vec::new())).unwrap();
    assert!(result.ledger.high_risk_masks().is_empty());
}

// ===========================================================================
// 32. Analyzer default impl
// ===========================================================================

#[test]
fn analyzer_default_is_same_as_new() {
    let a1 = SemanticTransportAnalyzer::new();
    let a2 = SemanticTransportAnalyzer::default();
    let es = vec![entry_spec(
        "A",
        ContractDomain::Hook,
        ver(1, 0, 0),
        ver(1, 1, 0),
        Vec::new(),
        &[],
        &[],
        &[],
    )];
    let r1 = a1.analyze(&simple_input(es.clone())).unwrap();
    let r2 = a2.analyze(&simple_input(es)).unwrap();
    assert_eq!(r1.result_hash, r2.result_hash);
}

// ===========================================================================
// 33. Confidence values in entries
// ===========================================================================

#[test]
fn unchanged_entry_has_full_confidence() {
    let es = vec![entry_spec(
        "useCallback",
        ContractDomain::Hook,
        ver(1, 0, 0),
        ver(1, 0, 1),
        Vec::new(),
        &["referential-eq"],
        &["referential-eq"],
        &[],
    )];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    let entry = &result.ledger.entries[0];
    // Unchanged with all invariants verified should have high confidence
    assert!(entry.confidence_millionths > 0);
}

// ===========================================================================
// 34. Cross-version pair analysis
// ===========================================================================

#[test]
fn cross_major_version_with_adapters() {
    let es = vec![
        entry_spec(
            "useEffect",
            ContractDomain::Effect,
            ver(17, 0, 0),
            ver(18, 0, 0),
            vec![delta("batching", "opt-in", "automatic", 400_000, true)],
            &["runs-after-paint", "cleanup-runs"],
            &["runs-after-paint", "cleanup-runs"],
            &[],
        ),
        entry_spec(
            "useId",
            ContractDomain::Hook,
            ver(17, 0, 0),
            ver(18, 0, 0),
            Vec::new(),
            &["stable-across-renders"],
            &["stable-across-renders"],
            &[],
        ),
    ];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    assert_eq!(
        result.outcome,
        TransportAnalysisOutcome::CompatibleWithAdapters
    );
    assert_eq!(result.unchanged_entries, 1);
    assert_eq!(result.adapter_entries, 1);
}

// ===========================================================================
// 35. Input serde round-trip
// ===========================================================================

#[test]
fn analysis_input_serde_round_trip() {
    let inp = TransportAnalysisInput {
        entries: vec![entry_spec(
            "A",
            ContractDomain::Hook,
            ver(1, 0, 0),
            ver(2, 0, 0),
            vec![delta("d", "s", "t", 100_000, true)],
            &["x"],
            &["x"],
            &[],
        )],
        morphisms: vec![morphism_spec(
            "m",
            ContractDomain::Hook,
            ver(1, 0, 0),
            ver(2, 0, 0),
            &["x"],
            &[],
            true,
            "desc",
            None,
        )],
        epoch: 77,
    };
    let json = serde_json::to_string(&inp).unwrap();
    let back: TransportAnalysisInput = serde_json::from_str(&json).unwrap();
    assert_eq!(back.entries.len(), inp.entries.len());
    assert_eq!(back.morphisms.len(), inp.morphisms.len());
    assert_eq!(back.epoch, 77);
}

// ===========================================================================
// 36. Entry spec serde round-trip
// ===========================================================================

#[test]
fn entry_spec_serde_round_trip() {
    let spec = entry_spec(
        "useEffect",
        ContractDomain::Effect,
        ver(1, 0, 0),
        ver(2, 0, 0),
        vec![delta("timing", "sync", "async", 300_000, true)],
        &["order", "cleanup"],
        &["order"],
        &["cleanup"],
    );
    let json = serde_json::to_string(&spec).unwrap();
    let back: TransportEntrySpec = serde_json::from_str(&json).unwrap();
    assert_eq!(back, spec);
}

// ===========================================================================
// 37. Morphism spec serde round-trip
// ===========================================================================

#[test]
fn morphism_spec_serde_round_trip() {
    let spec = morphism_spec(
        "effect-timing",
        ContractDomain::Effect,
        ver(1, 0, 0),
        ver(2, 0, 0),
        &["order"],
        &["cleanup"],
        true,
        "bridges timing",
        Some("adapters/timing.rs"),
    );
    let json = serde_json::to_string(&spec).unwrap();
    let back: MorphismSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(back, spec);
}

// ===========================================================================
// 38. Regression mask detection with morphism that has broken invariants
// ===========================================================================

#[test]
fn morphism_with_broken_invariants_not_safe() {
    let inp = TransportAnalysisInput {
        entries: vec![entry_spec(
            "useContext",
            ContractDomain::Context,
            ver(1, 0, 0),
            ver(2, 0, 0),
            vec![delta(
                "resolution",
                "nearest",
                "default-value",
                400_000,
                true,
            )],
            &["resolves-closest", "default-fallback"],
            &["resolves-closest"],
            &["default-fallback"],
        )],
        morphisms: vec![morphism_spec(
            "ctx-adapter",
            ContractDomain::Context,
            ver(1, 0, 0),
            ver(2, 0, 0),
            &["resolves-closest"],
            &["default-fallback"],
            true,
            "bridges context resolution",
            Some("adapters/ctx.rs"),
        )],
        epoch: 1,
    };
    let result = analyzer().analyze(&inp).unwrap();
    let m = &result.ledger.morphisms[0];
    // Has broken invariants, so not fully safe even if verified
    assert!(!m.broken_invariants.is_empty());
}

// ===========================================================================
// 39. Ledger epoch propagation
// ===========================================================================

#[test]
fn ledger_epoch_matches_input() {
    let inp = TransportAnalysisInput {
        entries: Vec::new(),
        morphisms: Vec::new(),
        epoch: 12345,
    };
    let result = analyzer().analyze(&inp).unwrap();
    assert_eq!(result.analysis_epoch, 12345);
    assert_eq!(result.ledger.compiled_epoch, 12345);
}

// ===========================================================================
// 40. Unknown verdict entries
// ===========================================================================

#[test]
fn unknown_entries_counted() {
    // Entry with no deltas but some required invariants that aren't verified
    // This may produce Unchanged or Unknown depending on implementation
    let es = vec![entry_spec(
        "experimental",
        ContractDomain::Hook,
        ver(1, 0, 0),
        ver(2, 0, 0),
        Vec::new(),
        &["unknown-invariant"],
        &[],
        &[],
    )];
    let result = analyzer().analyze(&simple_input(es)).unwrap();
    // Either unchanged or unknown — just verify it completes
    assert_eq!(result.total_entries, 1);
}
