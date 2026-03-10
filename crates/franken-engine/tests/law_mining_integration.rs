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

use frankenengine_engine::counterexample_synthesizer::{
    ConcreteScenario, MinimalityEvidence, SynthesisOutcome, SynthesisStrategy,
    SynthesizedCounterexample,
};
use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::evidence_ledger::{
    CandidateAction, ChosenAction, Constraint, DecisionType, EvidenceEntryBuilder, Witness,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::law_mining::{
    CandidateKind, CandidateScopeHypothesis, InvariantSeed, LAW_MINING_BEAD_ID,
    LAW_MINING_SCHEMA_VERSION, LawCandidate, LawMiningCatalog, LawProvenanceRecord,
    NormalFormHypothesis,
};
use frankenengine_engine::policy_theorem_compiler::{FormalProperty, PolicyId};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn sample_counterexample() -> SynthesizedCounterexample {
    SynthesizedCounterexample {
        conflict_id: EngineObjectId([0x41; 32]),
        property_violated: FormalProperty::MergeDeterminism,
        policy_ids: vec![PolicyId::new("policy-a"), PolicyId::new("policy-b")],
        merge_path: vec!["alpha".to_string(), "beta".to_string()],
        concrete_scenario: ConcreteScenario {
            subjects: BTreeSet::from(["subject-a".to_string()]),
            capabilities: BTreeSet::from(["fs.read".to_string(), "net.send".to_string()]),
            conditions: BTreeMap::from([
                ("board".to_string(), "declared".to_string()),
                ("runtime".to_string(), "franken".to_string()),
            ]),
            merge_ordering: vec!["alpha".to_string(), "beta".to_string()],
            input_state: BTreeMap::from([("mode".to_string(), "test".to_string())]),
        },
        expected_outcome: "stable".to_string(),
        actual_outcome: "unstable".to_string(),
        minimality_evidence: MinimalityEvidence {
            rounds: 3,
            elements_removed: 2,
            starting_size: 6,
            final_size: 4,
            is_fixed_point: true,
        },
        strategy: SynthesisStrategy::TimeBounded,
        outcome: SynthesisOutcome::Complete,
        compute_time_ns: 9_000,
        content_hash: ContentHash([0x24; 32]),
        epoch: SecurityEpoch::from_raw(12),
        resolution_hint: "canonicalize merge ordering".to_string(),
    }
}

fn sample_evidence_entry() -> frankenengine_engine::evidence_ledger::EvidenceEntry {
    EvidenceEntryBuilder::new(
        "trace-law-mining",
        "decision-law-mining",
        "policy-a",
        SecurityEpoch::from_raw(12),
        DecisionType::ContractEvaluation,
    )
    .timestamp_ns(12_345)
    .candidate(CandidateAction::new("allow", 10))
    .constraint(Constraint {
        constraint_id: "schema-ready".to_string(),
        description: "schema ready".to_string(),
        active: true,
    })
    .witness(Witness {
        witness_id: "fixture".to_string(),
        witness_type: "fixture".to_string(),
        value: "ok".to_string(),
    })
    .chosen(ChosenAction {
        action_name: "allow".to_string(),
        expected_loss_millionths: 10,
        rationale: "replayable".to_string(),
    })
    .build()
    .expect("evidence entry")
}

#[test]
fn law_mining_catalog_is_versioned_and_validated() {
    let catalog =
        LawMiningCatalog::from_sources(27, &[sample_counterexample()], &[sample_evidence_entry()]);
    assert_eq!(catalog.schema_version, LAW_MINING_SCHEMA_VERSION);
    assert_eq!(catalog.bead_id, LAW_MINING_BEAD_ID);
    assert!(catalog.validate().is_valid);
    assert!(!catalog.candidates.is_empty());
    assert!(!catalog.provenance_index.is_empty());
    assert!(!catalog.scope_hypotheses.is_empty());
}

#[test]
fn law_mining_catalog_retains_normal_form_and_side_condition_surfaces() {
    let catalog =
        LawMiningCatalog::from_sources(28, &[sample_counterexample()], &[sample_evidence_entry()]);
    assert!(
        catalog
            .candidates
            .iter()
            .any(|candidate| candidate.kind == CandidateKind::NormalForm)
    );
    assert!(
        catalog
            .candidates
            .iter()
            .any(|candidate| candidate.kind == CandidateKind::SideCondition)
    );
    assert!(!catalog.normal_form_hypotheses.is_empty());
    assert!(!catalog.invariant_seed_ledger.is_empty());
}

#[test]
fn law_mining_catalog_serde_round_trip_is_stable() {
    let catalog =
        LawMiningCatalog::from_sources(29, &[sample_counterexample()], &[sample_evidence_entry()]);
    let json = serde_json::to_string(&catalog).expect("serialize catalog");
    let recovered: LawMiningCatalog = serde_json::from_str(&json).expect("deserialize catalog");
    assert_eq!(recovered, catalog);
    assert_eq!(recovered.catalog_hash, catalog.catalog_hash);
}

// ---------------------------------------------------------------------------
// Schema constants stability
// ---------------------------------------------------------------------------

#[test]
fn schema_version_is_stable() {
    assert_eq!(LAW_MINING_SCHEMA_VERSION, "franken-engine.law-mining.v1");
}

#[test]
fn bead_id_is_stable() {
    assert_eq!(LAW_MINING_BEAD_ID, "bd-1lsy.9.10");
}

#[test]
fn component_constant_is_stable() {
    assert_eq!(
        frankenengine_engine::law_mining::LAW_MINING_COMPONENT,
        "law_mining"
    );
}

// ---------------------------------------------------------------------------
// Catalog construction with multiple counterexamples
// ---------------------------------------------------------------------------

#[test]
fn catalog_from_multiple_counterexamples() {
    let cx1 = sample_counterexample();
    let mut cx2 = sample_counterexample();
    cx2.conflict_id = EngineObjectId([0x42; 32]);
    cx2.expected_outcome = "deterministic".to_string();
    cx2.actual_outcome = "nondeterministic".to_string();

    let catalog = LawMiningCatalog::from_sources(30, &[cx1, cx2], &[sample_evidence_entry()]);
    assert!(catalog.validate().is_valid);
    assert!(catalog.candidates.len() >= 2);
}

#[test]
fn catalog_from_empty_counterexamples() {
    let catalog = LawMiningCatalog::from_sources(31, &[], &[sample_evidence_entry()]);
    assert!(catalog.validate().is_valid);
    assert_eq!(catalog.schema_version, LAW_MINING_SCHEMA_VERSION);
}

#[test]
fn catalog_from_empty_evidence() {
    let catalog = LawMiningCatalog::from_sources(32, &[sample_counterexample()], &[]);
    assert_eq!(catalog.schema_version, LAW_MINING_SCHEMA_VERSION);
}

#[test]
fn catalog_from_empty_both() {
    let catalog = LawMiningCatalog::from_sources(33, &[], &[]);
    assert_eq!(catalog.schema_version, LAW_MINING_SCHEMA_VERSION);
    assert!(catalog.candidates.is_empty());
}

// ---------------------------------------------------------------------------
// Candidate lookup
// ---------------------------------------------------------------------------

#[test]
fn candidate_lookup_by_id_returns_matching() {
    let catalog =
        LawMiningCatalog::from_sources(34, &[sample_counterexample()], &[sample_evidence_entry()]);
    if let Some(first) = catalog.candidates.first() {
        let found = catalog.candidate(&first.candidate_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().candidate_id, first.candidate_id);
    }
}

#[test]
fn candidate_lookup_missing_returns_none() {
    let catalog =
        LawMiningCatalog::from_sources(35, &[sample_counterexample()], &[sample_evidence_entry()]);
    assert!(catalog.candidate("nonexistent-id").is_none());
}

// ---------------------------------------------------------------------------
// Validation details
// ---------------------------------------------------------------------------

#[test]
fn validation_has_correct_counts() {
    let catalog =
        LawMiningCatalog::from_sources(36, &[sample_counterexample()], &[sample_evidence_entry()]);
    let validation = catalog.validate();
    assert_eq!(validation.candidate_count, catalog.candidates.len());
    assert_eq!(validation.provenance_count, catalog.provenance_index.len());
    assert_eq!(validation.scope_count, catalog.scope_hypotheses.len());
}

#[test]
fn validation_warnings_is_empty_for_valid_catalog() {
    let catalog =
        LawMiningCatalog::from_sources(37, &[sample_counterexample()], &[sample_evidence_entry()]);
    let validation = catalog.validate();
    assert!(validation.warnings.is_empty());
}

// ---------------------------------------------------------------------------
// CandidateKind coverage
// ---------------------------------------------------------------------------

#[test]
fn candidate_kind_invariant_exists_in_catalog() {
    let catalog =
        LawMiningCatalog::from_sources(38, &[sample_counterexample()], &[sample_evidence_entry()]);
    let kinds: BTreeSet<String> = catalog
        .candidates
        .iter()
        .map(|c| format!("{:?}", c.kind))
        .collect();
    // Should have at least NormalForm and SideCondition
    assert!(kinds.len() >= 2);
}

#[test]
fn candidate_kind_serde_roundtrip() {
    let kinds = [
        CandidateKind::NormalForm,
        CandidateKind::SideCondition,
        CandidateKind::Invariant,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).expect("serialize");
        let parsed: CandidateKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*kind, parsed);
    }
}

// ---------------------------------------------------------------------------
// LawCandidate field coverage
// ---------------------------------------------------------------------------

#[test]
fn law_candidate_has_nonempty_statement() {
    let catalog =
        LawMiningCatalog::from_sources(39, &[sample_counterexample()], &[sample_evidence_entry()]);
    for candidate in &catalog.candidates {
        assert!(!candidate.statement.trim().is_empty());
    }
}

#[test]
fn law_candidate_has_nonempty_id() {
    let catalog =
        LawMiningCatalog::from_sources(40, &[sample_counterexample()], &[sample_evidence_entry()]);
    for candidate in &catalog.candidates {
        assert!(!candidate.candidate_id.trim().is_empty());
    }
}

#[test]
fn law_candidate_rank_is_valid() {
    let catalog =
        LawMiningCatalog::from_sources(41, &[sample_counterexample()], &[sample_evidence_entry()]);
    for candidate in &catalog.candidates {
        // rank_millionths should be <= 1_000_000 (1.0)
        assert!(candidate.rank_millionths <= 1_000_000);
    }
}

#[test]
fn law_candidate_serde_roundtrip() {
    let catalog =
        LawMiningCatalog::from_sources(42, &[sample_counterexample()], &[sample_evidence_entry()]);
    for candidate in &catalog.candidates {
        let json = serde_json::to_string(candidate).expect("serialize");
        let parsed: LawCandidate = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*candidate, parsed);
    }
}

// ---------------------------------------------------------------------------
// Provenance records
// ---------------------------------------------------------------------------

#[test]
fn provenance_records_have_nonempty_sources() {
    let catalog =
        LawMiningCatalog::from_sources(43, &[sample_counterexample()], &[sample_evidence_entry()]);
    for prov in &catalog.provenance_index {
        assert!(!prov.sources.is_empty());
        assert!(!prov.provenance_id.trim().is_empty());
    }
}

#[test]
fn provenance_record_serde_roundtrip() {
    let catalog =
        LawMiningCatalog::from_sources(44, &[sample_counterexample()], &[sample_evidence_entry()]);
    for prov in &catalog.provenance_index {
        let json = serde_json::to_string(prov).expect("serialize");
        let parsed: LawProvenanceRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*prov, parsed);
    }
}

// ---------------------------------------------------------------------------
// Scope hypotheses
// ---------------------------------------------------------------------------

#[test]
fn scope_hypotheses_have_nonempty_ids() {
    let catalog =
        LawMiningCatalog::from_sources(45, &[sample_counterexample()], &[sample_evidence_entry()]);
    for scope in &catalog.scope_hypotheses {
        assert!(!scope.scope_id.trim().is_empty());
    }
}

#[test]
fn scope_hypothesis_serde_roundtrip() {
    let catalog =
        LawMiningCatalog::from_sources(46, &[sample_counterexample()], &[sample_evidence_entry()]);
    for scope in &catalog.scope_hypotheses {
        let json = serde_json::to_string(scope).expect("serialize");
        let parsed: CandidateScopeHypothesis = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*scope, parsed);
    }
}

// ---------------------------------------------------------------------------
// Invariant seeds
// ---------------------------------------------------------------------------

#[test]
fn invariant_seeds_have_nonempty_statements() {
    let catalog =
        LawMiningCatalog::from_sources(47, &[sample_counterexample()], &[sample_evidence_entry()]);
    for seed in &catalog.invariant_seed_ledger {
        assert!(!seed.statement.trim().is_empty());
        assert!(!seed.seed_id.trim().is_empty());
    }
}

#[test]
fn invariant_seed_serde_roundtrip() {
    let catalog =
        LawMiningCatalog::from_sources(48, &[sample_counterexample()], &[sample_evidence_entry()]);
    for seed in &catalog.invariant_seed_ledger {
        let json = serde_json::to_string(seed).expect("serialize");
        let parsed: InvariantSeed = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*seed, parsed);
    }
}

// ---------------------------------------------------------------------------
// Normal form hypotheses
// ---------------------------------------------------------------------------

#[test]
fn normal_form_hypotheses_have_canonical_form() {
    let catalog =
        LawMiningCatalog::from_sources(49, &[sample_counterexample()], &[sample_evidence_entry()]);
    for nf in &catalog.normal_form_hypotheses {
        assert!(!nf.canonical_form.trim().is_empty());
        assert!(!nf.hypothesis_id.trim().is_empty());
    }
}

#[test]
fn normal_form_hypothesis_serde_roundtrip() {
    let catalog =
        LawMiningCatalog::from_sources(50, &[sample_counterexample()], &[sample_evidence_entry()]);
    for nf in &catalog.normal_form_hypotheses {
        let json = serde_json::to_string(nf).expect("serialize");
        let parsed: NormalFormHypothesis = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*nf, parsed);
    }
}

// ---------------------------------------------------------------------------
// Catalog hash determinism
// ---------------------------------------------------------------------------

#[test]
fn catalog_hash_is_deterministic_across_constructions() {
    let catalog1 =
        LawMiningCatalog::from_sources(51, &[sample_counterexample()], &[sample_evidence_entry()]);
    let catalog2 =
        LawMiningCatalog::from_sources(51, &[sample_counterexample()], &[sample_evidence_entry()]);
    assert_eq!(catalog1.catalog_hash, catalog2.catalog_hash);
}

#[test]
fn catalog_hash_differs_for_different_epochs() {
    let catalog1 =
        LawMiningCatalog::from_sources(51, &[sample_counterexample()], &[sample_evidence_entry()]);
    let catalog2 =
        LawMiningCatalog::from_sources(52, &[sample_counterexample()], &[sample_evidence_entry()]);
    assert_ne!(catalog1.catalog_hash, catalog2.catalog_hash);
}

// ---------------------------------------------------------------------------
// render_summary
// ---------------------------------------------------------------------------

#[test]
fn render_summary_contains_key_fields() {
    let catalog =
        LawMiningCatalog::from_sources(53, &[sample_counterexample()], &[sample_evidence_entry()]);
    let summary = frankenengine_engine::law_mining::render_summary(&catalog);
    assert!(summary.contains("bead_id"));
    assert!(summary.contains("candidates"));
    assert!(summary.contains("catalog_hash"));
}

#[test]
fn render_summary_nonempty_for_empty_catalog() {
    let catalog = LawMiningCatalog::from_sources(54, &[], &[]);
    let summary = frankenengine_engine::law_mining::render_summary(&catalog);
    assert!(!summary.trim().is_empty());
}

// ---------------------------------------------------------------------------
// default_fixture
// ---------------------------------------------------------------------------

#[test]
fn default_fixture_produces_valid_catalog() {
    let fixture = frankenengine_engine::law_mining::default_fixture();
    let catalog =
        LawMiningCatalog::from_sources(55, &fixture.counterexamples, &fixture.evidence_entries);
    assert!(catalog.validate().is_valid);
}

#[test]
fn default_fixture_has_counterexamples_and_evidence() {
    let fixture = frankenengine_engine::law_mining::default_fixture();
    assert!(!fixture.counterexamples.is_empty());
    assert!(!fixture.evidence_entries.is_empty());
}

// ---------------------------------------------------------------------------
// Catalog serialization determinism
// ---------------------------------------------------------------------------

#[test]
fn catalog_serialization_is_deterministic() {
    let catalog =
        LawMiningCatalog::from_sources(56, &[sample_counterexample()], &[sample_evidence_entry()]);
    let json1 = serde_json::to_string(&catalog).expect("ser1");
    let json2 = serde_json::to_string(&catalog).expect("ser2");
    assert_eq!(json1, json2, "serialization must be deterministic");
}

// ---------------------------------------------------------------------------
// LawMiningValidation serde
// ---------------------------------------------------------------------------

#[test]
fn validation_serde_roundtrip() {
    let catalog =
        LawMiningCatalog::from_sources(57, &[sample_counterexample()], &[sample_evidence_entry()]);
    let validation = catalog.validate();
    let json = serde_json::to_string(&validation).expect("serialize");
    let parsed: frankenengine_engine::law_mining::LawMiningValidation =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.is_valid, validation.is_valid);
    assert_eq!(parsed.candidate_count, validation.candidate_count);
}
