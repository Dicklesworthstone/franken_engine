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
    CandidateKind, LAW_MINING_BEAD_ID, LAW_MINING_SCHEMA_VERSION, LawMiningCatalog,
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
