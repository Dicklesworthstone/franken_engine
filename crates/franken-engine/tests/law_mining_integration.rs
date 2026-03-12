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

// ---------------------------------------------------------------------------
// Schema version constants stability (all 11)
// ---------------------------------------------------------------------------

#[test]
fn candidate_law_catalog_schema_version_is_stable() {
    assert_eq!(
        frankenengine_engine::law_mining::CANDIDATE_LAW_CATALOG_SCHEMA_VERSION,
        "franken-engine.law-mining.candidate-law-catalog.v1"
    );
}

#[test]
fn invariant_seed_ledger_schema_version_is_stable() {
    assert_eq!(
        frankenengine_engine::law_mining::INVARIANT_SEED_LEDGER_SCHEMA_VERSION,
        "franken-engine.law-mining.invariant-seed-ledger.v1"
    );
}

#[test]
fn normal_form_hypotheses_schema_version_is_stable() {
    assert_eq!(
        frankenengine_engine::law_mining::NORMAL_FORM_HYPOTHESES_SCHEMA_VERSION,
        "franken-engine.law-mining.normal-form-hypotheses.v1"
    );
}

#[test]
fn law_provenance_index_schema_version_is_stable() {
    assert_eq!(
        frankenengine_engine::law_mining::LAW_PROVENANCE_INDEX_SCHEMA_VERSION,
        "franken-engine.law-mining.provenance-index.v1"
    );
}

#[test]
fn candidate_scope_hypotheses_schema_version_is_stable() {
    assert_eq!(
        frankenengine_engine::law_mining::CANDIDATE_SCOPE_HYPOTHESES_SCHEMA_VERSION,
        "franken-engine.law-mining.scope-hypotheses.v1"
    );
}

#[test]
fn trace_ids_schema_version_is_stable() {
    assert_eq!(
        frankenengine_engine::law_mining::LAW_MINING_TRACE_IDS_SCHEMA_VERSION,
        "franken-engine.law-mining.trace-ids.v1"
    );
}

#[test]
fn run_manifest_schema_version_is_stable() {
    assert_eq!(
        frankenengine_engine::law_mining::LAW_MINING_RUN_MANIFEST_SCHEMA_VERSION,
        "franken-engine.law-mining.run-manifest.v1"
    );
}

#[test]
fn env_schema_version_is_stable() {
    assert_eq!(
        frankenengine_engine::law_mining::LAW_MINING_ENV_SCHEMA_VERSION,
        "franken-engine.law-mining.env.v1"
    );
}

#[test]
fn artifact_index_schema_version_is_stable() {
    assert_eq!(
        frankenengine_engine::law_mining::LAW_MINING_ARTIFACT_INDEX_SCHEMA_VERSION,
        "franken-engine.law-mining.artifact-index.v1"
    );
}

#[test]
fn event_stream_schema_version_is_stable() {
    assert_eq!(
        frankenengine_engine::law_mining::LAW_MINING_EVENT_STREAM_SCHEMA_VERSION,
        "franken-engine.law-mining.events.v1"
    );
}

#[test]
fn all_schema_versions_are_distinct() {
    let versions = std::collections::BTreeSet::from([
        frankenengine_engine::law_mining::LAW_MINING_SCHEMA_VERSION,
        frankenengine_engine::law_mining::CANDIDATE_LAW_CATALOG_SCHEMA_VERSION,
        frankenengine_engine::law_mining::INVARIANT_SEED_LEDGER_SCHEMA_VERSION,
        frankenengine_engine::law_mining::NORMAL_FORM_HYPOTHESES_SCHEMA_VERSION,
        frankenengine_engine::law_mining::LAW_PROVENANCE_INDEX_SCHEMA_VERSION,
        frankenengine_engine::law_mining::CANDIDATE_SCOPE_HYPOTHESES_SCHEMA_VERSION,
        frankenengine_engine::law_mining::LAW_MINING_TRACE_IDS_SCHEMA_VERSION,
        frankenengine_engine::law_mining::LAW_MINING_RUN_MANIFEST_SCHEMA_VERSION,
        frankenengine_engine::law_mining::LAW_MINING_ENV_SCHEMA_VERSION,
        frankenengine_engine::law_mining::LAW_MINING_ARTIFACT_INDEX_SCHEMA_VERSION,
        frankenengine_engine::law_mining::LAW_MINING_EVENT_STREAM_SCHEMA_VERSION,
    ]);
    assert_eq!(versions.len(), 11, "all 11 schema versions must be unique");
}

// ---------------------------------------------------------------------------
// ProvenanceSourceKind coverage
// ---------------------------------------------------------------------------

#[test]
fn provenance_source_kind_serde_roundtrip() {
    use frankenengine_engine::law_mining::ProvenanceSourceKind;
    for kind in [
        ProvenanceSourceKind::Counterexample,
        ProvenanceSourceKind::EvidenceEntry,
    ] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let parsed: ProvenanceSourceKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, kind);
    }
}

#[test]
fn provenance_source_kind_debug_format() {
    use frankenengine_engine::law_mining::ProvenanceSourceKind;
    let debug = format!("{:?}", ProvenanceSourceKind::Counterexample);
    assert!(debug.contains("Counterexample"));
    let debug2 = format!("{:?}", ProvenanceSourceKind::EvidenceEntry);
    assert!(debug2.contains("EvidenceEntry"));
}

#[test]
fn provenance_source_kind_ordering_is_deterministic() {
    use frankenengine_engine::law_mining::ProvenanceSourceKind;
    let mut items = vec![
        ProvenanceSourceKind::EvidenceEntry,
        ProvenanceSourceKind::Counterexample,
    ];
    items.sort();
    assert_eq!(items[0], ProvenanceSourceKind::Counterexample);
    assert_eq!(items[1], ProvenanceSourceKind::EvidenceEntry);
}

// ---------------------------------------------------------------------------
// CandidateKind ordering and Debug
// ---------------------------------------------------------------------------

#[test]
fn candidate_kind_ordering_is_deterministic() {
    let mut items = vec![
        CandidateKind::NormalForm,
        CandidateKind::SideCondition,
        CandidateKind::Invariant,
    ];
    items.sort();
    assert_eq!(items[0], CandidateKind::Invariant);
    assert_eq!(items[1], CandidateKind::SideCondition);
    assert_eq!(items[2], CandidateKind::NormalForm);
}

#[test]
fn candidate_kind_debug_format_all_variants() {
    let invariant = format!("{:?}", CandidateKind::Invariant);
    assert_eq!(invariant, "Invariant");
    let side = format!("{:?}", CandidateKind::SideCondition);
    assert_eq!(side, "SideCondition");
    let nf = format!("{:?}", CandidateKind::NormalForm);
    assert_eq!(nf, "NormalForm");
}

#[test]
fn candidate_kind_clone_and_copy() {
    let kind = CandidateKind::Invariant;
    let cloned = kind.clone();
    let copied = kind;
    assert_eq!(kind, cloned);
    assert_eq!(kind, copied);
}

// ---------------------------------------------------------------------------
// LawProvenanceSource field coverage
// ---------------------------------------------------------------------------

#[test]
fn provenance_source_from_counterexample_has_correct_kind() {
    use frankenengine_engine::law_mining::ProvenanceSourceKind;
    let catalog = LawMiningCatalog::from_sources(60, &[sample_counterexample()], &[]);
    for prov in &catalog.provenance_index {
        for source in &prov.sources {
            assert_eq!(source.source_kind, ProvenanceSourceKind::Counterexample);
            assert!(source.source_id.starts_with("counterexample:"));
        }
    }
}

#[test]
fn provenance_source_from_evidence_has_correct_kind() {
    use frankenengine_engine::law_mining::ProvenanceSourceKind;
    let catalog = LawMiningCatalog::from_sources(61, &[], &[sample_evidence_entry()]);
    for prov in &catalog.provenance_index {
        for source in &prov.sources {
            assert_eq!(source.source_kind, ProvenanceSourceKind::EvidenceEntry);
            assert!(source.source_id.starts_with("evidence:"));
        }
    }
}

#[test]
fn provenance_source_has_nonempty_support_summary() {
    let catalog =
        LawMiningCatalog::from_sources(62, &[sample_counterexample()], &[sample_evidence_entry()]);
    for prov in &catalog.provenance_index {
        for source in &prov.sources {
            assert!(!source.support_summary.trim().is_empty());
        }
    }
}

#[test]
fn provenance_source_hash_is_nonzero() {
    let catalog =
        LawMiningCatalog::from_sources(63, &[sample_counterexample()], &[sample_evidence_entry()]);
    let zero_hash = ContentHash([0u8; 32]);
    for prov in &catalog.provenance_index {
        for source in &prov.sources {
            assert_ne!(source.source_hash, zero_hash);
        }
    }
}

#[test]
fn provenance_source_serde_roundtrip() {
    use frankenengine_engine::law_mining::LawProvenanceSource;
    let catalog =
        LawMiningCatalog::from_sources(64, &[sample_counterexample()], &[sample_evidence_entry()]);
    for prov in &catalog.provenance_index {
        for source in &prov.sources {
            let json = serde_json::to_string(source).expect("serialize");
            let parsed: LawProvenanceSource = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*source, parsed);
        }
    }
}

// ---------------------------------------------------------------------------
// CandidateScopeHypothesis field coverage
// ---------------------------------------------------------------------------

#[test]
fn scope_hypothesis_frontier_only_true_when_only_counterexample() {
    let catalog = LawMiningCatalog::from_sources(65, &[sample_counterexample()], &[]);
    let any_frontier = catalog.scope_hypotheses.iter().any(|s| s.frontier_only);
    assert!(
        any_frontier,
        "scope from counterexample-only should be frontier_only"
    );
}

#[test]
fn scope_hypothesis_frontier_only_false_when_evidence_also_present() {
    let catalog = LawMiningCatalog::from_sources(66, &[], &[sample_evidence_entry()]);
    for scope in &catalog.scope_hypotheses {
        assert!(
            !scope.frontier_only,
            "evidence-only scope should not be frontier_only"
        );
    }
}

#[test]
fn scope_hypothesis_has_capability_names_from_counterexample() {
    let catalog = LawMiningCatalog::from_sources(67, &[sample_counterexample()], &[]);
    let has_capabilities = catalog
        .scope_hypotheses
        .iter()
        .any(|s| !s.capability_names.is_empty());
    assert!(has_capabilities);
}

#[test]
fn scope_hypothesis_has_condition_keys_from_counterexample() {
    let catalog = LawMiningCatalog::from_sources(68, &[sample_counterexample()], &[]);
    let has_conditions = catalog
        .scope_hypotheses
        .iter()
        .any(|s| !s.condition_keys.is_empty());
    assert!(has_conditions);
}

#[test]
fn scope_hypothesis_hash_is_nonzero() {
    let catalog =
        LawMiningCatalog::from_sources(69, &[sample_counterexample()], &[sample_evidence_entry()]);
    let zero_hash = ContentHash([0u8; 32]);
    for scope in &catalog.scope_hypotheses {
        assert_ne!(scope.scope_hash, zero_hash);
    }
}

// ---------------------------------------------------------------------------
// Artifact struct serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn candidate_law_catalog_artifact_serde_roundtrip() {
    use frankenengine_engine::law_mining::CandidateLawCatalogArtifact;
    let catalog =
        LawMiningCatalog::from_sources(70, &[sample_counterexample()], &[sample_evidence_entry()]);
    let artifact = CandidateLawCatalogArtifact {
        schema_version: frankenengine_engine::law_mining::CANDIDATE_LAW_CATALOG_SCHEMA_VERSION
            .to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        generated_epoch: 70,
        catalog_hash: catalog.catalog_hash,
        candidates: catalog.candidates.clone(),
    };
    let json = serde_json::to_string(&artifact).expect("serialize");
    let parsed: CandidateLawCatalogArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, parsed);
}

#[test]
fn invariant_seed_ledger_artifact_serde_roundtrip() {
    use frankenengine_engine::law_mining::InvariantSeedLedgerArtifact;
    let catalog =
        LawMiningCatalog::from_sources(71, &[sample_counterexample()], &[sample_evidence_entry()]);
    let artifact = InvariantSeedLedgerArtifact {
        schema_version: frankenengine_engine::law_mining::INVARIANT_SEED_LEDGER_SCHEMA_VERSION
            .to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        generated_epoch: 71,
        catalog_hash: catalog.catalog_hash,
        invariant_seed_ledger: catalog.invariant_seed_ledger.clone(),
    };
    let json = serde_json::to_string(&artifact).expect("serialize");
    let parsed: InvariantSeedLedgerArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, parsed);
}

#[test]
fn normal_form_hypotheses_artifact_serde_roundtrip() {
    use frankenengine_engine::law_mining::NormalFormHypothesesArtifact;
    let catalog =
        LawMiningCatalog::from_sources(72, &[sample_counterexample()], &[sample_evidence_entry()]);
    let artifact = NormalFormHypothesesArtifact {
        schema_version: frankenengine_engine::law_mining::NORMAL_FORM_HYPOTHESES_SCHEMA_VERSION
            .to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        generated_epoch: 72,
        catalog_hash: catalog.catalog_hash,
        normal_form_hypotheses: catalog.normal_form_hypotheses.clone(),
    };
    let json = serde_json::to_string(&artifact).expect("serialize");
    let parsed: NormalFormHypothesesArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, parsed);
}

#[test]
fn law_provenance_index_artifact_serde_roundtrip() {
    use frankenengine_engine::law_mining::LawProvenanceIndexArtifact;
    let catalog =
        LawMiningCatalog::from_sources(73, &[sample_counterexample()], &[sample_evidence_entry()]);
    let artifact = LawProvenanceIndexArtifact {
        schema_version: frankenengine_engine::law_mining::LAW_PROVENANCE_INDEX_SCHEMA_VERSION
            .to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        generated_epoch: 73,
        catalog_hash: catalog.catalog_hash,
        provenance_index: catalog.provenance_index.clone(),
    };
    let json = serde_json::to_string(&artifact).expect("serialize");
    let parsed: LawProvenanceIndexArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, parsed);
}

#[test]
fn candidate_scope_hypotheses_artifact_serde_roundtrip() {
    use frankenengine_engine::law_mining::CandidateScopeHypothesesArtifact;
    let catalog =
        LawMiningCatalog::from_sources(74, &[sample_counterexample()], &[sample_evidence_entry()]);
    let artifact = CandidateScopeHypothesesArtifact {
        schema_version: frankenengine_engine::law_mining::CANDIDATE_SCOPE_HYPOTHESES_SCHEMA_VERSION
            .to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        generated_epoch: 74,
        catalog_hash: catalog.catalog_hash,
        scope_hypotheses: catalog.scope_hypotheses.clone(),
    };
    let json = serde_json::to_string(&artifact).expect("serialize");
    let parsed: CandidateScopeHypothesesArtifact =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, parsed);
}

#[test]
fn trace_ids_artifact_serde_roundtrip() {
    use frankenengine_engine::law_mining::TraceIdsArtifact;
    let artifact = TraceIdsArtifact {
        schema_version: frankenengine_engine::law_mining::LAW_MINING_TRACE_IDS_SCHEMA_VERSION
            .to_string(),
        trace_id: "trace-test".to_string(),
        decision_id: "decision-test".to_string(),
        policy_id: "policy-test".to_string(),
        run_id: "run-test".to_string(),
    };
    let json = serde_json::to_string(&artifact).expect("serialize");
    let parsed: TraceIdsArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, parsed);
}

#[test]
fn law_mining_event_serde_roundtrip() {
    use frankenengine_engine::law_mining::LawMiningEvent;
    let event = LawMiningEvent {
        schema_version: frankenengine_engine::law_mining::LAW_MINING_EVENT_STREAM_SCHEMA_VERSION
            .to_string(),
        trace_id: "trace-ev".to_string(),
        decision_id: "decision-ev".to_string(),
        policy_id: "policy-ev".to_string(),
        component: "law_mining".to_string(),
        event: "catalog_mined".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        detail: "detail content".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let parsed: LawMiningEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, parsed);
}

#[test]
fn law_mining_event_with_error_code_serde_roundtrip() {
    use frankenengine_engine::law_mining::LawMiningEvent;
    let event = LawMiningEvent {
        schema_version: frankenengine_engine::law_mining::LAW_MINING_EVENT_STREAM_SCHEMA_VERSION
            .to_string(),
        trace_id: "trace-err".to_string(),
        decision_id: "decision-err".to_string(),
        policy_id: "policy-err".to_string(),
        component: "law_mining".to_string(),
        event: "catalog_failed".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("LM-001".to_string()),
        detail: "error detail".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let parsed: LawMiningEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, parsed);
    assert_eq!(parsed.error_code, Some("LM-001".to_string()));
}

#[test]
fn artifact_hash_record_serde_roundtrip() {
    use frankenengine_engine::law_mining::ArtifactHashRecord;
    let record = ArtifactHashRecord {
        path: "candidate_law_catalog.json".to_string(),
        sha256: "abcdef0123456789".to_string(),
    };
    let json = serde_json::to_string(&record).expect("serialize");
    let parsed: ArtifactHashRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(record, parsed);
}

#[test]
fn law_mining_env_artifact_serde_roundtrip() {
    use frankenengine_engine::law_mining::LawMiningEnvArtifact;
    let artifact = LawMiningEnvArtifact {
        schema_version: frankenengine_engine::law_mining::LAW_MINING_ENV_SCHEMA_VERSION.to_string(),
        run_id: "run-env-test".to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        source_commit: "abc123".to_string(),
        toolchain: "nightly-2026-01-01".to_string(),
    };
    let json = serde_json::to_string(&artifact).expect("serialize");
    let parsed: LawMiningEnvArtifact = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, parsed);
}

#[test]
fn law_mining_artifact_index_serde_roundtrip() {
    use frankenengine_engine::law_mining::{ArtifactHashRecord, LawMiningArtifactIndex};
    let artifact = LawMiningArtifactIndex {
        schema_version: frankenengine_engine::law_mining::LAW_MINING_ARTIFACT_INDEX_SCHEMA_VERSION
            .to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        run_id: "run-idx-test".to_string(),
        artifacts: vec![
            ArtifactHashRecord {
                path: "file_a.json".to_string(),
                sha256: "aaa".to_string(),
            },
            ArtifactHashRecord {
                path: "file_b.json".to_string(),
                sha256: "bbb".to_string(),
            },
        ],
    };
    let json = serde_json::to_string(&artifact).expect("serialize");
    let parsed: LawMiningArtifactIndex = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(artifact, parsed);
}

#[test]
fn law_mining_run_manifest_serde_roundtrip() {
    use frankenengine_engine::law_mining::LawMiningRunManifest;
    let manifest = LawMiningRunManifest {
        schema_version: frankenengine_engine::law_mining::LAW_MINING_RUN_MANIFEST_SCHEMA_VERSION
            .to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        run_id: "run-manifest-test".to_string(),
        trace_id: "trace-manifest".to_string(),
        decision_id: "decision-manifest".to_string(),
        policy_id: "policy-manifest".to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        source_commit: "deadbeef".to_string(),
        toolchain: "nightly".to_string(),
        generated_epoch: 99,
        catalog_hash: ContentHash([0x55; 32]),
        command_invocation: "cargo run --test".to_string(),
        artifact_hashes: vec![],
    };
    let json = serde_json::to_string(&manifest).expect("serialize");
    let parsed: LawMiningRunManifest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(manifest, parsed);
}

// ---------------------------------------------------------------------------
// LawMiningFixture serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn law_mining_fixture_serde_roundtrip() {
    use frankenengine_engine::law_mining::LawMiningFixture;
    let fixture = frankenengine_engine::law_mining::default_fixture();
    let json = serde_json::to_string(&fixture).expect("serialize");
    let parsed: LawMiningFixture = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.generated_epoch, fixture.generated_epoch);
    assert_eq!(parsed.counterexamples.len(), fixture.counterexamples.len());
    assert_eq!(
        parsed.evidence_entries.len(),
        fixture.evidence_entries.len()
    );
}

// ---------------------------------------------------------------------------
// BundleWriteReport serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn bundle_write_report_serde_roundtrip() {
    use frankenengine_engine::law_mining::BundleWriteReport;
    use std::path::PathBuf;
    let report = BundleWriteReport {
        artifact_dir: PathBuf::from("/tmp/test"),
        candidate_law_catalog_path: PathBuf::from("/tmp/test/candidate_law_catalog.json"),
        invariant_seed_ledger_path: PathBuf::from("/tmp/test/invariant_seed_ledger.json"),
        normal_form_hypotheses_path: PathBuf::from("/tmp/test/normal_form_hypotheses.json"),
        provenance_index_path: PathBuf::from("/tmp/test/law_provenance_index.json"),
        scope_hypotheses_path: PathBuf::from("/tmp/test/candidate_scope_hypotheses.json"),
        trace_ids_path: PathBuf::from("/tmp/test/trace_ids.json"),
        run_manifest_path: PathBuf::from("/tmp/test/run_manifest.json"),
        events_path: PathBuf::from("/tmp/test/events.jsonl"),
        commands_path: PathBuf::from("/tmp/test/commands.txt"),
        env_path: PathBuf::from("/tmp/test/env.json"),
        artifact_index_path: PathBuf::from("/tmp/test/manifest.json"),
        repro_lock_path: PathBuf::from("/tmp/test/repro.lock"),
        summary_path: PathBuf::from("/tmp/test/summary.md"),
    };
    let json = serde_json::to_string(&report).expect("serialize");
    let parsed: BundleWriteReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report, parsed);
}

// ---------------------------------------------------------------------------
// ArtifactContext defaults
// ---------------------------------------------------------------------------

#[test]
fn artifact_context_new_defaults() {
    use frankenengine_engine::law_mining::ArtifactContext;
    let ctx = ArtifactContext::new("/tmp/law-mining-ctx-test");
    assert_eq!(
        ctx.artifact_dir,
        std::path::PathBuf::from("/tmp/law-mining-ctx-test")
    );
    assert!(ctx.run_id.starts_with("run-"));
    assert!(!ctx.trace_id.is_empty());
    assert!(!ctx.decision_id.is_empty());
    assert!(!ctx.policy_id.is_empty());
    assert!(!ctx.generated_at_utc.is_empty());
    assert!(!ctx.source_commit.is_empty());
    assert!(!ctx.toolchain.is_empty());
    assert!(!ctx.command_invocation.is_empty());
}

#[test]
fn artifact_context_eq_impl() {
    use frankenengine_engine::law_mining::ArtifactContext;
    let a = ArtifactContext::new("/tmp/a");
    let b = ArtifactContext::new("/tmp/a");
    assert_eq!(a, b);
    let c = ArtifactContext::new("/tmp/c");
    assert_ne!(a, c);
}

// ---------------------------------------------------------------------------
// LawMiningValidation field coverage
// ---------------------------------------------------------------------------

#[test]
fn validation_scope_count_matches_catalog() {
    let catalog =
        LawMiningCatalog::from_sources(75, &[sample_counterexample()], &[sample_evidence_entry()]);
    let validation = catalog.validate();
    assert_eq!(validation.scope_count, catalog.scope_hypotheses.len());
}

#[test]
fn validation_provenance_count_matches_catalog() {
    let catalog =
        LawMiningCatalog::from_sources(76, &[sample_counterexample()], &[sample_evidence_entry()]);
    let validation = catalog.validate();
    assert_eq!(validation.provenance_count, catalog.provenance_index.len());
}

#[test]
fn validation_for_empty_catalog_has_zero_counts() {
    let catalog = LawMiningCatalog::from_sources(77, &[], &[]);
    let validation = catalog.validate();
    assert_eq!(validation.candidate_count, 0);
    assert_eq!(validation.provenance_count, 0);
    assert_eq!(validation.scope_count, 0);
    assert!(validation.warnings.is_empty());
}

// ---------------------------------------------------------------------------
// Ranking rationale content
// ---------------------------------------------------------------------------

#[test]
fn ranking_rationale_mentions_sources_and_policies() {
    let catalog =
        LawMiningCatalog::from_sources(78, &[sample_counterexample()], &[sample_evidence_entry()]);
    for candidate in &catalog.candidates {
        assert!(candidate.ranking_rationale.contains("sources"));
        assert!(candidate.ranking_rationale.contains("policies"));
    }
}

#[test]
fn ranking_rationale_mentions_properties_and_surfaces() {
    let catalog =
        LawMiningCatalog::from_sources(79, &[sample_counterexample()], &[sample_evidence_entry()]);
    for candidate in &catalog.candidates {
        assert!(candidate.ranking_rationale.contains("properties"));
        assert!(candidate.ranking_rationale.contains("decision surfaces"));
    }
}

// ---------------------------------------------------------------------------
// NormalFormHypothesis field coverage
// ---------------------------------------------------------------------------

#[test]
fn normal_form_hypothesis_has_merge_shapes() {
    let catalog = LawMiningCatalog::from_sources(80, &[sample_counterexample()], &[]);
    for nf in &catalog.normal_form_hypotheses {
        assert!(
            !nf.merge_shapes.is_empty(),
            "normal form should have merge shapes"
        );
    }
}

#[test]
fn normal_form_hypothesis_derived_candidate_id_references_valid_candidate() {
    let catalog =
        LawMiningCatalog::from_sources(81, &[sample_counterexample()], &[sample_evidence_entry()]);
    let candidate_ids: BTreeSet<_> = catalog.candidates.iter().map(|c| &c.candidate_id).collect();
    for nf in &catalog.normal_form_hypotheses {
        assert!(
            candidate_ids.contains(&nf.derived_candidate_id),
            "normal form references nonexistent candidate: {}",
            nf.derived_candidate_id
        );
    }
}

#[test]
fn normal_form_hypothesis_scope_id_references_valid_scope() {
    let catalog =
        LawMiningCatalog::from_sources(82, &[sample_counterexample()], &[sample_evidence_entry()]);
    let scope_ids: BTreeSet<_> = catalog
        .scope_hypotheses
        .iter()
        .map(|s| &s.scope_id)
        .collect();
    for nf in &catalog.normal_form_hypotheses {
        assert!(
            scope_ids.contains(&nf.scope_hypothesis_id),
            "normal form references nonexistent scope: {}",
            nf.scope_hypothesis_id
        );
    }
}

#[test]
fn normal_form_hypothesis_hash_is_nonzero() {
    let catalog = LawMiningCatalog::from_sources(83, &[sample_counterexample()], &[]);
    let zero_hash = ContentHash([0u8; 32]);
    for nf in &catalog.normal_form_hypotheses {
        assert_ne!(nf.hypothesis_hash, zero_hash);
    }
}

// ---------------------------------------------------------------------------
// InvariantSeed field coverage
// ---------------------------------------------------------------------------

#[test]
fn invariant_seed_derived_candidate_id_references_valid_candidate() {
    let catalog =
        LawMiningCatalog::from_sources(84, &[sample_counterexample()], &[sample_evidence_entry()]);
    let candidate_ids: BTreeSet<_> = catalog.candidates.iter().map(|c| &c.candidate_id).collect();
    for seed in &catalog.invariant_seed_ledger {
        assert!(
            candidate_ids.contains(&seed.derived_candidate_id),
            "seed references nonexistent candidate: {}",
            seed.derived_candidate_id
        );
    }
}

#[test]
fn invariant_seed_scope_id_references_valid_scope() {
    let catalog =
        LawMiningCatalog::from_sources(85, &[sample_counterexample()], &[sample_evidence_entry()]);
    let scope_ids: BTreeSet<_> = catalog
        .scope_hypotheses
        .iter()
        .map(|s| &s.scope_id)
        .collect();
    for seed in &catalog.invariant_seed_ledger {
        assert!(
            scope_ids.contains(&seed.scope_hypothesis_id),
            "seed references nonexistent scope: {}",
            seed.scope_hypothesis_id
        );
    }
}

#[test]
fn invariant_seed_hash_is_nonzero() {
    let catalog = LawMiningCatalog::from_sources(86, &[sample_counterexample()], &[]);
    let zero_hash = ContentHash([0u8; 32]);
    for seed in &catalog.invariant_seed_ledger {
        assert_ne!(seed.seed_hash, zero_hash);
    }
}

#[test]
fn invariant_seed_has_supporting_source_ids() {
    let catalog = LawMiningCatalog::from_sources(87, &[sample_counterexample()], &[]);
    for seed in &catalog.invariant_seed_ledger {
        assert!(!seed.supporting_source_ids.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Catalog with only evidence (no counterexamples)
// ---------------------------------------------------------------------------

#[test]
fn catalog_with_only_evidence_produces_side_condition_candidates() {
    let catalog = LawMiningCatalog::from_sources(88, &[], &[sample_evidence_entry()]);
    assert!(!catalog.candidates.is_empty());
    for candidate in &catalog.candidates {
        assert_eq!(candidate.kind, CandidateKind::SideCondition);
    }
}

#[test]
fn catalog_with_only_evidence_has_no_normal_form_hypotheses() {
    let catalog = LawMiningCatalog::from_sources(89, &[], &[sample_evidence_entry()]);
    assert!(catalog.normal_form_hypotheses.is_empty());
}

#[test]
fn catalog_with_only_evidence_has_invariant_seeds_for_side_conditions() {
    let catalog = LawMiningCatalog::from_sources(90, &[], &[sample_evidence_entry()]);
    assert!(!catalog.invariant_seed_ledger.is_empty());
}

// ---------------------------------------------------------------------------
// Catalog hash sensitivity
// ---------------------------------------------------------------------------

#[test]
fn catalog_hash_differs_for_different_counterexamples() {
    let cx1 = sample_counterexample();
    let mut cx2 = sample_counterexample();
    cx2.conflict_id = EngineObjectId([0x99; 32]);
    cx2.property_violated =
        frankenengine_engine::policy_theorem_compiler::FormalProperty::Monotonicity;
    let catalog1 = LawMiningCatalog::from_sources(91, &[cx1], &[]);
    let catalog2 = LawMiningCatalog::from_sources(91, &[cx2], &[]);
    assert_ne!(catalog1.catalog_hash, catalog2.catalog_hash);
}

#[test]
fn catalog_hash_differs_for_different_evidence() {
    let ev1 = sample_evidence_entry();
    let ev2 = EvidenceEntryBuilder::new(
        "trace-alt",
        "decision-alt",
        "policy-alt",
        SecurityEpoch::from_raw(15),
        DecisionType::SecurityAction,
    )
    .timestamp_ns(99_999)
    .candidate(CandidateAction::new("deny", 500))
    .constraint(Constraint {
        constraint_id: "alt-constraint".to_string(),
        description: "alt desc".to_string(),
        active: true,
    })
    .witness(Witness {
        witness_id: "alt-witness".to_string(),
        witness_type: "alt-type".to_string(),
        value: "nope".to_string(),
    })
    .chosen(ChosenAction {
        action_name: "deny".to_string(),
        expected_loss_millionths: 500,
        rationale: "alt reason".to_string(),
    })
    .build()
    .expect("alt evidence entry");
    let catalog1 = LawMiningCatalog::from_sources(92, &[], &[ev1]);
    let catalog2 = LawMiningCatalog::from_sources(92, &[], &[ev2]);
    assert_ne!(catalog1.catalog_hash, catalog2.catalog_hash);
}

// ---------------------------------------------------------------------------
// Multiple evidence entries
// ---------------------------------------------------------------------------

#[test]
fn multiple_evidence_entries_produce_distinct_candidates() {
    let ev1 = sample_evidence_entry();
    let ev2 = EvidenceEntryBuilder::new(
        "trace-multi",
        "decision-multi",
        "policy-multi",
        SecurityEpoch::from_raw(20),
        DecisionType::SecurityAction,
    )
    .timestamp_ns(20_000)
    .candidate(CandidateAction::new("deny", 200))
    .constraint(Constraint {
        constraint_id: "multi-constraint".to_string(),
        description: "multi desc".to_string(),
        active: true,
    })
    .witness(Witness {
        witness_id: "multi-witness".to_string(),
        witness_type: "multi-type".to_string(),
        value: "val".to_string(),
    })
    .chosen(ChosenAction {
        action_name: "deny".to_string(),
        expected_loss_millionths: 200,
        rationale: "multi".to_string(),
    })
    .build()
    .expect("multi evidence entry");
    let catalog = LawMiningCatalog::from_sources(93, &[], &[ev1, ev2]);
    assert!(catalog.candidates.len() >= 2);
    assert!(catalog.validate().is_valid);
}

// ---------------------------------------------------------------------------
// Candidate lookup edge cases
// ---------------------------------------------------------------------------

#[test]
fn candidate_lookup_with_empty_string_returns_none() {
    let catalog =
        LawMiningCatalog::from_sources(94, &[sample_counterexample()], &[sample_evidence_entry()]);
    assert!(catalog.candidate("").is_none());
}

#[test]
fn candidate_lookup_returns_correct_kind() {
    let catalog =
        LawMiningCatalog::from_sources(95, &[sample_counterexample()], &[sample_evidence_entry()]);
    for candidate in &catalog.candidates {
        let found = catalog
            .candidate(&candidate.candidate_id)
            .expect("should find");
        assert_eq!(found.kind, candidate.kind);
        assert_eq!(found.statement, candidate.statement);
    }
}

// ---------------------------------------------------------------------------
// render_summary edge cases
// ---------------------------------------------------------------------------

#[test]
fn render_summary_contains_generated_epoch() {
    let catalog =
        LawMiningCatalog::from_sources(96, &[sample_counterexample()], &[sample_evidence_entry()]);
    let summary = frankenengine_engine::law_mining::render_summary(&catalog);
    assert!(summary.contains("generated_epoch: 96"));
}

#[test]
fn render_summary_contains_invariant_seeds_count() {
    let catalog =
        LawMiningCatalog::from_sources(97, &[sample_counterexample()], &[sample_evidence_entry()]);
    let summary = frankenengine_engine::law_mining::render_summary(&catalog);
    assert!(summary.contains("invariant_seeds:"));
}

#[test]
fn render_summary_contains_scope_hypotheses_count() {
    let catalog =
        LawMiningCatalog::from_sources(98, &[sample_counterexample()], &[sample_evidence_entry()]);
    let summary = frankenengine_engine::law_mining::render_summary(&catalog);
    assert!(summary.contains("scope_hypotheses:"));
}

#[test]
fn render_summary_for_empty_catalog_has_no_top_candidate() {
    let catalog = LawMiningCatalog::from_sources(99, &[], &[]);
    let summary = frankenengine_engine::law_mining::render_summary(&catalog);
    assert!(!summary.contains("## Top Candidate"));
}

#[test]
fn render_summary_top_candidate_shows_rank() {
    let catalog =
        LawMiningCatalog::from_sources(100, &[sample_counterexample()], &[sample_evidence_entry()]);
    let summary = frankenengine_engine::law_mining::render_summary(&catalog);
    assert!(summary.contains("rank_millionths:"));
}

#[test]
fn render_summary_top_candidate_shows_kind() {
    let catalog =
        LawMiningCatalog::from_sources(101, &[sample_counterexample()], &[sample_evidence_entry()]);
    let summary = frankenengine_engine::law_mining::render_summary(&catalog);
    assert!(summary.contains("kind:"));
}

// ---------------------------------------------------------------------------
// default_fixture field coverage
// ---------------------------------------------------------------------------

#[test]
fn default_fixture_generated_epoch_is_27() {
    let fixture = frankenengine_engine::law_mining::default_fixture();
    assert_eq!(fixture.generated_epoch, 27);
}

#[test]
fn default_fixture_has_two_counterexamples() {
    let fixture = frankenengine_engine::law_mining::default_fixture();
    assert_eq!(fixture.counterexamples.len(), 2);
}

#[test]
fn default_fixture_has_two_evidence_entries() {
    let fixture = frankenengine_engine::law_mining::default_fixture();
    assert_eq!(fixture.evidence_entries.len(), 2);
}

#[test]
fn default_fixture_counterexamples_have_distinct_conflict_ids() {
    let fixture = frankenengine_engine::law_mining::default_fixture();
    let ids: BTreeSet<_> = fixture
        .counterexamples
        .iter()
        .map(|cx| cx.conflict_id.clone())
        .collect();
    assert_eq!(ids.len(), fixture.counterexamples.len());
}

#[test]
fn default_fixture_catalog_is_deterministic() {
    let fixture = frankenengine_engine::law_mining::default_fixture();
    let cat1 = LawMiningCatalog::from_sources(
        fixture.generated_epoch,
        &fixture.counterexamples,
        &fixture.evidence_entries,
    );
    let cat2 = LawMiningCatalog::from_sources(
        fixture.generated_epoch,
        &fixture.counterexamples,
        &fixture.evidence_entries,
    );
    assert_eq!(cat1, cat2);
    assert_eq!(cat1.catalog_hash, cat2.catalog_hash);
}

// ---------------------------------------------------------------------------
// LawCandidate field coverage (extended)
// ---------------------------------------------------------------------------

#[test]
fn law_candidate_scope_hypothesis_id_references_valid_scope() {
    let catalog =
        LawMiningCatalog::from_sources(102, &[sample_counterexample()], &[sample_evidence_entry()]);
    let scope_ids: BTreeSet<_> = catalog
        .scope_hypotheses
        .iter()
        .map(|s| &s.scope_id)
        .collect();
    for candidate in &catalog.candidates {
        assert!(
            scope_ids.contains(&candidate.scope_hypothesis_id),
            "candidate references nonexistent scope: {}",
            candidate.scope_hypothesis_id
        );
    }
}

#[test]
fn law_candidate_provenance_id_references_valid_provenance() {
    let catalog =
        LawMiningCatalog::from_sources(103, &[sample_counterexample()], &[sample_evidence_entry()]);
    let prov_ids: BTreeSet<_> = catalog
        .provenance_index
        .iter()
        .map(|p| &p.provenance_id)
        .collect();
    for candidate in &catalog.candidates {
        assert!(
            prov_ids.contains(&candidate.provenance_id),
            "candidate references nonexistent provenance: {}",
            candidate.provenance_id
        );
    }
}

#[test]
fn law_candidate_hash_is_nonzero() {
    let catalog =
        LawMiningCatalog::from_sources(104, &[sample_counterexample()], &[sample_evidence_entry()]);
    let zero_hash = ContentHash([0u8; 32]);
    for candidate in &catalog.candidates {
        assert_ne!(candidate.candidate_hash, zero_hash);
    }
}

#[test]
fn law_candidate_supporting_source_ids_nonempty() {
    let catalog =
        LawMiningCatalog::from_sources(105, &[sample_counterexample()], &[sample_evidence_entry()]);
    for candidate in &catalog.candidates {
        assert!(!candidate.supporting_source_ids.is_empty());
    }
}

// ---------------------------------------------------------------------------
// LawProvenanceRecord field coverage (extended)
// ---------------------------------------------------------------------------

#[test]
fn provenance_record_hash_is_nonzero() {
    let catalog =
        LawMiningCatalog::from_sources(106, &[sample_counterexample()], &[sample_evidence_entry()]);
    let zero_hash = ContentHash([0u8; 32]);
    for prov in &catalog.provenance_index {
        assert_ne!(prov.provenance_hash, zero_hash);
    }
}

#[test]
fn provenance_record_candidate_id_references_valid_candidate() {
    let catalog =
        LawMiningCatalog::from_sources(107, &[sample_counterexample()], &[sample_evidence_entry()]);
    let candidate_ids: BTreeSet<_> = catalog.candidates.iter().map(|c| &c.candidate_id).collect();
    for prov in &catalog.provenance_index {
        assert!(
            candidate_ids.contains(&prov.candidate_id),
            "provenance references nonexistent candidate: {}",
            prov.candidate_id
        );
    }
}

// ---------------------------------------------------------------------------
// Catalog generated_epoch field
// ---------------------------------------------------------------------------

#[test]
fn catalog_preserves_generated_epoch() {
    let catalog = LawMiningCatalog::from_sources(
        12345,
        &[sample_counterexample()],
        &[sample_evidence_entry()],
    );
    assert_eq!(catalog.generated_epoch, 12345);
}

#[test]
fn catalog_generated_epoch_zero_is_valid() {
    let catalog = LawMiningCatalog::from_sources(0, &[], &[]);
    assert_eq!(catalog.generated_epoch, 0);
    assert!(catalog.validate().is_valid);
}

#[test]
fn catalog_generated_epoch_max_is_valid() {
    let catalog = LawMiningCatalog::from_sources(u64::MAX, &[], &[]);
    assert_eq!(catalog.generated_epoch, u64::MAX);
    assert!(catalog.validate().is_valid);
}

// ---------------------------------------------------------------------------
// Catalog structural invariants
// ---------------------------------------------------------------------------

#[test]
fn catalog_candidates_count_matches_provenance_count() {
    let catalog =
        LawMiningCatalog::from_sources(108, &[sample_counterexample()], &[sample_evidence_entry()]);
    assert_eq!(
        catalog.candidates.len(),
        catalog.provenance_index.len(),
        "each candidate should have exactly one provenance record"
    );
}

#[test]
fn catalog_candidates_count_matches_scope_count() {
    let catalog =
        LawMiningCatalog::from_sources(109, &[sample_counterexample()], &[sample_evidence_entry()]);
    assert_eq!(
        catalog.candidates.len(),
        catalog.scope_hypotheses.len(),
        "each candidate should have exactly one scope hypothesis"
    );
}

#[test]
fn catalog_invariant_seeds_plus_normal_forms_relate_to_candidates() {
    let catalog =
        LawMiningCatalog::from_sources(110, &[sample_counterexample()], &[sample_evidence_entry()]);
    let normal_form_count = catalog
        .candidates
        .iter()
        .filter(|c| c.kind == CandidateKind::NormalForm)
        .count();
    let non_normal_form_count = catalog.candidates.len() - normal_form_count;
    assert_eq!(catalog.normal_form_hypotheses.len(), normal_form_count);
    assert_eq!(catalog.invariant_seed_ledger.len(), non_normal_form_count);
}

// ---------------------------------------------------------------------------
// Scope hypotheses policy_ids and decision_types from evidence
// ---------------------------------------------------------------------------

#[test]
fn scope_from_evidence_has_decision_types() {
    let catalog = LawMiningCatalog::from_sources(111, &[], &[sample_evidence_entry()]);
    let has_decision_types = catalog
        .scope_hypotheses
        .iter()
        .any(|s| !s.decision_types.is_empty());
    assert!(has_decision_types);
}

#[test]
fn scope_from_evidence_has_policy_ids() {
    let catalog = LawMiningCatalog::from_sources(112, &[], &[sample_evidence_entry()]);
    let has_policy_ids = catalog
        .scope_hypotheses
        .iter()
        .any(|s| !s.policy_ids.is_empty());
    assert!(has_policy_ids);
}

// ---------------------------------------------------------------------------
// Provenance source policy_ids from counterexample
// ---------------------------------------------------------------------------

#[test]
fn provenance_source_has_policy_ids_from_counterexample() {
    let catalog = LawMiningCatalog::from_sources(113, &[sample_counterexample()], &[]);
    for prov in &catalog.provenance_index {
        for source in &prov.sources {
            assert!(!source.policy_ids.is_empty());
        }
    }
}

// ---------------------------------------------------------------------------
// Candidate rank clamped at 1_000_000
// ---------------------------------------------------------------------------

#[test]
fn candidate_rank_never_exceeds_one_million() {
    let mut cxs = Vec::new();
    for i in 0..10u8 {
        let mut cx = sample_counterexample();
        cx.conflict_id = EngineObjectId([i; 32]);
        cx.content_hash = ContentHash([i; 32]);
        cxs.push(cx);
    }
    let catalog = LawMiningCatalog::from_sources(114, &cxs, &[sample_evidence_entry()]);
    for candidate in &catalog.candidates {
        assert!(
            candidate.rank_millionths <= 1_000_000,
            "rank {} exceeds 1_000_000",
            candidate.rank_millionths
        );
    }
}

// ---------------------------------------------------------------------------
// Scope hypotheses formal_properties from counterexample
// ---------------------------------------------------------------------------

#[test]
fn scope_from_counterexample_has_formal_properties() {
    let catalog = LawMiningCatalog::from_sources(115, &[sample_counterexample()], &[]);
    let has_formal = catalog
        .scope_hypotheses
        .iter()
        .any(|s| !s.formal_properties.is_empty());
    assert!(has_formal);
}

// ---------------------------------------------------------------------------
// LawMiningCatalog clone and debug
// ---------------------------------------------------------------------------

#[test]
fn catalog_clone_is_equal() {
    let catalog =
        LawMiningCatalog::from_sources(116, &[sample_counterexample()], &[sample_evidence_entry()]);
    let cloned = catalog.clone();
    assert_eq!(catalog, cloned);
}

#[test]
fn catalog_debug_is_nonempty() {
    let catalog =
        LawMiningCatalog::from_sources(117, &[sample_counterexample()], &[sample_evidence_entry()]);
    let debug = format!("{:?}", catalog);
    assert!(!debug.is_empty());
    assert!(debug.contains("LawMiningCatalog"));
}

// ---------------------------------------------------------------------------
// LawMiningValidation clone and debug
// ---------------------------------------------------------------------------

#[test]
fn validation_clone_is_equal() {
    let catalog =
        LawMiningCatalog::from_sources(118, &[sample_counterexample()], &[sample_evidence_entry()]);
    let validation = catalog.validate();
    let cloned = validation.clone();
    assert_eq!(validation, cloned);
}

#[test]
fn validation_debug_is_nonempty() {
    let catalog =
        LawMiningCatalog::from_sources(119, &[sample_counterexample()], &[sample_evidence_entry()]);
    let validation = catalog.validate();
    let debug = format!("{:?}", validation);
    assert!(!debug.is_empty());
    assert!(debug.contains("LawMiningValidation"));
}

// ---------------------------------------------------------------------------
// Counterexample with empty merge path
// ---------------------------------------------------------------------------

#[test]
fn counterexample_with_empty_merge_path_produces_no_normal_form() {
    let mut cx = sample_counterexample();
    cx.merge_path = vec![];
    let catalog = LawMiningCatalog::from_sources(120, &[cx], &[]);
    assert!(catalog.normal_form_hypotheses.is_empty());
    assert!(
        !catalog
            .candidates
            .iter()
            .any(|c| c.kind == CandidateKind::NormalForm)
    );
}

// ---------------------------------------------------------------------------
// Counterexample with empty capabilities
// ---------------------------------------------------------------------------

#[test]
fn counterexample_with_empty_capabilities_uses_policy_statement() {
    let mut cx = sample_counterexample();
    cx.concrete_scenario.capabilities = BTreeSet::new();
    let catalog = LawMiningCatalog::from_sources(121, &[cx], &[]);
    let invariant = catalog
        .candidates
        .iter()
        .find(|c| c.kind == CandidateKind::Invariant)
        .expect("invariant");
    assert!(invariant.statement.contains("across policies"));
}

// ---------------------------------------------------------------------------
// Counterexample with empty conditions
// ---------------------------------------------------------------------------

#[test]
fn counterexample_with_empty_conditions_produces_no_side_condition() {
    let mut cx = sample_counterexample();
    cx.concrete_scenario.conditions = BTreeMap::new();
    let catalog = LawMiningCatalog::from_sources(122, &[cx], &[]);
    let side_from_cx = catalog
        .candidates
        .iter()
        .filter(|c| c.kind == CandidateKind::SideCondition)
        .count();
    assert_eq!(side_from_cx, 0);
}

// ---------------------------------------------------------------------------
// Evidence entry with no active constraints
// ---------------------------------------------------------------------------

#[test]
fn evidence_with_inactive_constraints_uses_witness_statement() {
    let ev = EvidenceEntryBuilder::new(
        "trace-inactive",
        "decision-inactive",
        "policy-inactive",
        SecurityEpoch::from_raw(12),
        DecisionType::ContractEvaluation,
    )
    .timestamp_ns(5000)
    .candidate(CandidateAction::new("allow", 10))
    .constraint(Constraint {
        constraint_id: "inactive-c".to_string(),
        description: "desc".to_string(),
        active: false,
    })
    .witness(Witness {
        witness_id: "w1".to_string(),
        witness_type: "posterior".to_string(),
        value: "ok".to_string(),
    })
    .chosen(ChosenAction {
        action_name: "allow".to_string(),
        expected_loss_millionths: 10,
        rationale: "test".to_string(),
    })
    .build()
    .expect("entry");
    let catalog = LawMiningCatalog::from_sources(123, &[], &[ev]);
    let side = catalog
        .candidates
        .iter()
        .find(|c| c.kind == CandidateKind::SideCondition)
        .expect("side condition");
    assert!(side.statement.contains("witnesses"));
}
