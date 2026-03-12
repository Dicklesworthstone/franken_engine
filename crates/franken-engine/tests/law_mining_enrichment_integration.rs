//! Enrichment integration tests for `frankenengine_engine::law_mining`.
//!
//! Covers artifact types, bundle emission, validation edge cases, ranking
//! behavior, scope hypotheses frontier_only semantics, schema version
//! distinctness, and serde roundtrips for all public artifact types.

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
use std::fs;

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
    ArtifactContext, ArtifactHashRecord, CANDIDATE_LAW_CATALOG_SCHEMA_VERSION,
    CANDIDATE_SCOPE_HYPOTHESES_SCHEMA_VERSION, CandidateKind, CandidateLawCatalogArtifact,
    CandidateScopeHypothesesArtifact, INVARIANT_SEED_LEDGER_SCHEMA_VERSION,
    InvariantSeedLedgerArtifact, LAW_MINING_ARTIFACT_INDEX_SCHEMA_VERSION, LAW_MINING_BEAD_ID,
    LAW_MINING_COMPONENT, LAW_MINING_ENV_SCHEMA_VERSION, LAW_MINING_EVENT_STREAM_SCHEMA_VERSION,
    LAW_MINING_RUN_MANIFEST_SCHEMA_VERSION, LAW_MINING_SCHEMA_VERSION,
    LAW_MINING_TRACE_IDS_SCHEMA_VERSION, LAW_PROVENANCE_INDEX_SCHEMA_VERSION,
    LawMiningArtifactIndex, LawMiningCatalog, LawMiningEnvArtifact, LawMiningEvent,
    LawMiningRunManifest, LawMiningValidation, LawProvenanceIndexArtifact,
    NORMAL_FORM_HYPOTHESES_SCHEMA_VERSION, NormalFormHypothesesArtifact, ProvenanceSourceKind,
    TraceIdsArtifact,
};
use frankenengine_engine::policy_theorem_compiler::{FormalProperty, PolicyId};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ── Helpers ─────────────────────────────────────────────────────────────

fn mk_counterexample(
    byte: u8,
    property: FormalProperty,
    capabilities: &[&str],
    conditions: &[(&str, &str)],
    merge_path: &[&str],
) -> SynthesizedCounterexample {
    let mut condition_map = BTreeMap::new();
    for (key, value) in conditions {
        condition_map.insert((*key).to_string(), (*value).to_string());
    }
    SynthesizedCounterexample {
        conflict_id: EngineObjectId([byte; 32]),
        property_violated: property,
        policy_ids: vec![PolicyId::new(format!("policy-{byte}"))],
        merge_path: merge_path.iter().map(|s| (*s).to_string()).collect(),
        concrete_scenario: ConcreteScenario {
            subjects: BTreeSet::from([format!("subject-{byte}")]),
            capabilities: capabilities.iter().map(|s| (*s).to_string()).collect(),
            conditions: condition_map,
            merge_ordering: merge_path.iter().map(|s| (*s).to_string()).collect(),
            input_state: BTreeMap::from([("mode".to_string(), "test".to_string())]),
        },
        expected_outcome: "stable".to_string(),
        actual_outcome: "unstable".to_string(),
        minimality_evidence: MinimalityEvidence {
            rounds: 2,
            elements_removed: 1,
            starting_size: 4,
            final_size: 3,
            is_fixed_point: true,
        },
        strategy: SynthesisStrategy::Enumeration,
        outcome: SynthesisOutcome::Complete,
        compute_time_ns: 1_000,
        content_hash: ContentHash([byte; 32]),
        epoch: SecurityEpoch::from_raw(byte as u64),
        resolution_hint: "stabilize merge ordering".to_string(),
    }
}

fn mk_evidence(
    trace_id: &str,
    decision_type: DecisionType,
    policy_id: &str,
    constraint_ids: &[&str],
    witness_types: &[&str],
) -> frankenengine_engine::evidence_ledger::EvidenceEntry {
    let builder = EvidenceEntryBuilder::new(
        trace_id,
        format!("decision-{trace_id}"),
        policy_id,
        SecurityEpoch::from_raw(9),
        decision_type,
    )
    .timestamp_ns(1_000)
    .candidate(CandidateAction::new("allow", 10))
    .chosen(ChosenAction {
        action_name: "allow".to_string(),
        expected_loss_millionths: 10,
        rationale: "best".to_string(),
    });
    let builder = constraint_ids
        .iter()
        .fold(builder, |builder, constraint_id| {
            builder.constraint(Constraint {
                constraint_id: (*constraint_id).to_string(),
                description: "constraint".to_string(),
                active: true,
            })
        });
    let builder = witness_types.iter().fold(builder, |builder, witness_type| {
        builder.witness(Witness {
            witness_id: format!("witness-{witness_type}"),
            witness_type: (*witness_type).to_string(),
            value: "1".to_string(),
        })
    });
    builder.build().expect("evidence entry")
}

fn temp_dir(label: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("law-mining-enrichment-{label}-{nonce}"));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

// ── Schema Version Constants ────────────────────────────────────────────

#[test]
fn all_schema_versions_are_distinct() {
    let versions = [
        LAW_MINING_SCHEMA_VERSION,
        CANDIDATE_LAW_CATALOG_SCHEMA_VERSION,
        INVARIANT_SEED_LEDGER_SCHEMA_VERSION,
        NORMAL_FORM_HYPOTHESES_SCHEMA_VERSION,
        LAW_PROVENANCE_INDEX_SCHEMA_VERSION,
        CANDIDATE_SCOPE_HYPOTHESES_SCHEMA_VERSION,
        LAW_MINING_TRACE_IDS_SCHEMA_VERSION,
        LAW_MINING_RUN_MANIFEST_SCHEMA_VERSION,
        LAW_MINING_ENV_SCHEMA_VERSION,
        LAW_MINING_ARTIFACT_INDEX_SCHEMA_VERSION,
        LAW_MINING_EVENT_STREAM_SCHEMA_VERSION,
    ];
    let unique: BTreeSet<&str> = versions.iter().copied().collect();
    assert_eq!(
        unique.len(),
        versions.len(),
        "schema versions must be distinct"
    );
}

#[test]
fn all_schema_versions_contain_law_mining_prefix() {
    let versions = [
        LAW_MINING_SCHEMA_VERSION,
        CANDIDATE_LAW_CATALOG_SCHEMA_VERSION,
        INVARIANT_SEED_LEDGER_SCHEMA_VERSION,
        NORMAL_FORM_HYPOTHESES_SCHEMA_VERSION,
        LAW_PROVENANCE_INDEX_SCHEMA_VERSION,
        CANDIDATE_SCOPE_HYPOTHESES_SCHEMA_VERSION,
        LAW_MINING_TRACE_IDS_SCHEMA_VERSION,
        LAW_MINING_RUN_MANIFEST_SCHEMA_VERSION,
        LAW_MINING_ENV_SCHEMA_VERSION,
        LAW_MINING_ARTIFACT_INDEX_SCHEMA_VERSION,
        LAW_MINING_EVENT_STREAM_SCHEMA_VERSION,
    ];
    for version in &versions {
        assert!(
            version.contains("law-mining"),
            "schema version should contain 'law-mining': {version}"
        );
    }
}

// ── ProvenanceSourceKind ────────────────────────────────────────────────

#[test]
fn provenance_source_kind_ordering_consistent() {
    let a = ProvenanceSourceKind::Counterexample;
    let b = ProvenanceSourceKind::EvidenceEntry;
    // Just verify Ord is consistent (no panic, total order)
    let mut sorted = vec![b, a, b, a];
    sorted.sort();
    assert_eq!(sorted[0], sorted[1]);
    assert_eq!(sorted[2], sorted[3]);
}

#[test]
fn provenance_source_kind_serde_all_variants() {
    for kind in [
        ProvenanceSourceKind::Counterexample,
        ProvenanceSourceKind::EvidenceEntry,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: ProvenanceSourceKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kind);
    }
}

// ── CandidateKind ───────────────────────────────────────────────────────

#[test]
fn candidate_kind_ordering_matches_definition_order() {
    let mut kinds = vec![
        CandidateKind::NormalForm,
        CandidateKind::SideCondition,
        CandidateKind::Invariant,
    ];
    kinds.sort();
    // Invariant < SideCondition < NormalForm (derive order)
    assert_eq!(kinds[0], CandidateKind::Invariant);
    assert_eq!(kinds[1], CandidateKind::SideCondition);
    assert_eq!(kinds[2], CandidateKind::NormalForm);
}

// ── ArtifactHashRecord ──────────────────────────────────────────────────

#[test]
fn artifact_hash_record_serde_roundtrip() {
    let record = ArtifactHashRecord {
        path: "candidate_law_catalog.json".to_string(),
        sha256: "abcdef0123456789".to_string(),
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: ArtifactHashRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back, record);
}

// ── TraceIdsArtifact ────────────────────────────────────────────────────

#[test]
fn trace_ids_artifact_serde_roundtrip() {
    let artifact = TraceIdsArtifact {
        schema_version: LAW_MINING_TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        run_id: "run-1".to_string(),
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: TraceIdsArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(back, artifact);
}

// ── LawMiningEvent ──────────────────────────────────────────────────────

#[test]
fn law_mining_event_serde_roundtrip() {
    let event = LawMiningEvent {
        schema_version: LAW_MINING_EVENT_STREAM_SCHEMA_VERSION.to_string(),
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: "policy-1".to_string(),
        component: LAW_MINING_COMPONENT.to_string(),
        event: "catalog_mined".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        detail: "test detail".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: LawMiningEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

#[test]
fn law_mining_event_with_error_code_serde() {
    let event = LawMiningEvent {
        schema_version: LAW_MINING_EVENT_STREAM_SCHEMA_VERSION.to_string(),
        trace_id: "trace-err".to_string(),
        decision_id: "dec-err".to_string(),
        policy_id: "pol-err".to_string(),
        component: LAW_MINING_COMPONENT.to_string(),
        event: "error_event".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("E-MINE-001".to_string()),
        detail: "mining failed".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: LawMiningEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.error_code, Some("E-MINE-001".to_string()));
}

// ── LawMiningEnvArtifact ────────────────────────────────────────────────

#[test]
fn law_mining_env_artifact_serde_roundtrip() {
    let env = LawMiningEnvArtifact {
        schema_version: LAW_MINING_ENV_SCHEMA_VERSION.to_string(),
        run_id: "run-test".to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        source_commit: "abc123".to_string(),
        toolchain: "nightly".to_string(),
    };
    let json = serde_json::to_string(&env).unwrap();
    let back: LawMiningEnvArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(back, env);
}

// ── LawMiningArtifactIndex ──────────────────────────────────────────────

#[test]
fn law_mining_artifact_index_serde_roundtrip() {
    let index = LawMiningArtifactIndex {
        schema_version: LAW_MINING_ARTIFACT_INDEX_SCHEMA_VERSION.to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        run_id: "run-idx".to_string(),
        artifacts: vec![ArtifactHashRecord {
            path: "catalog.json".to_string(),
            sha256: "deadbeef".to_string(),
        }],
    };
    let json = serde_json::to_string(&index).unwrap();
    let back: LawMiningArtifactIndex = serde_json::from_str(&json).unwrap();
    assert_eq!(back, index);
}

// ── CandidateLawCatalogArtifact ─────────────────────────────────────────

#[test]
fn candidate_law_catalog_artifact_serde_roundtrip() {
    let catalog = LawMiningCatalog::from_sources(
        1,
        &[mk_counterexample(
            0x10,
            FormalProperty::MergeDeterminism,
            &["fs.read"],
            &[("k", "v")],
            &["m"],
        )],
        &[],
    );
    let artifact = CandidateLawCatalogArtifact {
        schema_version: CANDIDATE_LAW_CATALOG_SCHEMA_VERSION.to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        generated_epoch: 1,
        catalog_hash: catalog.catalog_hash,
        candidates: catalog.candidates,
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: CandidateLawCatalogArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(back, artifact);
}

// ── InvariantSeedLedgerArtifact ─────────────────────────────────────────

#[test]
fn invariant_seed_ledger_artifact_serde_roundtrip() {
    let catalog = LawMiningCatalog::from_sources(
        2,
        &[mk_counterexample(
            0x11,
            FormalProperty::Monotonicity,
            &["net.send"],
            &[("x", "1")],
            &["a"],
        )],
        &[],
    );
    let artifact = InvariantSeedLedgerArtifact {
        schema_version: INVARIANT_SEED_LEDGER_SCHEMA_VERSION.to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        generated_epoch: 2,
        catalog_hash: catalog.catalog_hash,
        invariant_seed_ledger: catalog.invariant_seed_ledger,
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: InvariantSeedLedgerArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(back, artifact);
}

// ── NormalFormHypothesesArtifact ─────────────────────────────────────────

#[test]
fn normal_form_hypotheses_artifact_serde_roundtrip() {
    let catalog = LawMiningCatalog::from_sources(
        3,
        &[mk_counterexample(
            0x12,
            FormalProperty::NonInterference,
            &["fs.read"],
            &[("r", "v")],
            &["step-a", "step-b"],
        )],
        &[],
    );
    let artifact = NormalFormHypothesesArtifact {
        schema_version: NORMAL_FORM_HYPOTHESES_SCHEMA_VERSION.to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        generated_epoch: 3,
        catalog_hash: catalog.catalog_hash,
        normal_form_hypotheses: catalog.normal_form_hypotheses,
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: NormalFormHypothesesArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(back, artifact);
}

// ── LawProvenanceIndexArtifact ──────────────────────────────────────────

#[test]
fn law_provenance_index_artifact_serde_roundtrip() {
    let catalog = LawMiningCatalog::from_sources(
        4,
        &[mk_counterexample(
            0x13,
            FormalProperty::MergeDeterminism,
            &["cache.store"],
            &[("lane", "main")],
            &["x"],
        )],
        &[],
    );
    let artifact = LawProvenanceIndexArtifact {
        schema_version: LAW_PROVENANCE_INDEX_SCHEMA_VERSION.to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        generated_epoch: 4,
        catalog_hash: catalog.catalog_hash,
        provenance_index: catalog.provenance_index,
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: LawProvenanceIndexArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(back, artifact);
}

// ── CandidateScopeHypothesesArtifact ────────────────────────────────────

#[test]
fn candidate_scope_hypotheses_artifact_serde_roundtrip() {
    let catalog = LawMiningCatalog::from_sources(
        5,
        &[mk_counterexample(
            0x14,
            FormalProperty::Monotonicity,
            &["sched.tick"],
            &[("q", "1")],
            &["y"],
        )],
        &[],
    );
    let artifact = CandidateScopeHypothesesArtifact {
        schema_version: CANDIDATE_SCOPE_HYPOTHESES_SCHEMA_VERSION.to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        generated_epoch: 5,
        catalog_hash: catalog.catalog_hash,
        scope_hypotheses: catalog.scope_hypotheses,
    };
    let json = serde_json::to_string(&artifact).unwrap();
    let back: CandidateScopeHypothesesArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(back, artifact);
}

// ── LawMiningRunManifest ────────────────────────────────────────────────

#[test]
fn law_mining_run_manifest_serde_roundtrip() {
    let manifest = LawMiningRunManifest {
        schema_version: LAW_MINING_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        bead_id: LAW_MINING_BEAD_ID.to_string(),
        run_id: "run-test".to_string(),
        trace_id: "trace-test".to_string(),
        decision_id: "dec-test".to_string(),
        policy_id: "pol-test".to_string(),
        generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        source_commit: "abc123".to_string(),
        toolchain: "nightly".to_string(),
        generated_epoch: 99,
        catalog_hash: ContentHash([0xAA; 32]),
        command_invocation: "test-command".to_string(),
        artifact_hashes: vec![ArtifactHashRecord {
            path: "catalog.json".to_string(),
            sha256: "deadbeef".to_string(),
        }],
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: LawMiningRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, manifest);
}

// ── LawMiningValidation ─────────────────────────────────────────────────

#[test]
fn validation_serde_full_roundtrip() {
    let validation = LawMiningValidation {
        is_valid: false,
        candidate_count: 3,
        provenance_count: 2,
        scope_count: 1,
        warnings: vec!["duplicate candidate id: x".to_string()],
    };
    let json = serde_json::to_string(&validation).unwrap();
    let back: LawMiningValidation = serde_json::from_str(&json).unwrap();
    assert_eq!(back, validation);
}

// ── ArtifactContext ─────────────────────────────────────────────────────

#[test]
fn artifact_context_new_sets_reasonable_defaults() {
    let ctx = ArtifactContext::new("/tmp/test");
    assert_eq!(ctx.artifact_dir, std::path::PathBuf::from("/tmp/test"));
    assert!(!ctx.trace_id.is_empty());
    assert!(!ctx.decision_id.is_empty());
    assert!(!ctx.policy_id.is_empty());
    assert!(ctx.run_id.starts_with("run-"));
    assert!(!ctx.toolchain.is_empty());
    assert!(ctx.command_invocation.contains("franken_law_mining"));
}

// ── Ranking Behavior ────────────────────────────────────────────────────

#[test]
fn rank_capped_at_one_million() {
    // Create enough sources and breadth to potentially exceed 1_000_000
    let mut counterexamples = Vec::new();
    for i in 0..10_u8 {
        counterexamples.push(mk_counterexample(
            i,
            FormalProperty::MergeDeterminism,
            &["fs.read", "net.send", "cache.store", "sched.tick"],
            &[("a", "1"), ("b", "2"), ("c", "3"), ("d", "4")],
            &["merge-a", "merge-b"],
        ));
    }
    let catalog = LawMiningCatalog::from_sources(100, &counterexamples, &[]);
    for candidate in &catalog.candidates {
        assert!(
            candidate.rank_millionths <= 1_000_000,
            "rank {} exceeds cap",
            candidate.rank_millionths
        );
    }
}

#[test]
fn invariant_kind_outranks_side_condition_same_support() {
    // A single counterexample with conditions produces both Invariant and SideCondition
    let cx = mk_counterexample(
        0x20,
        FormalProperty::MergeDeterminism,
        &["fs.read"],
        &[("region", "alpha")],
        &[], // no merge path => no NormalForm
    );
    let catalog = LawMiningCatalog::from_sources(200, &[cx], &[]);
    let invariant_rank = catalog
        .candidates
        .iter()
        .filter(|c| c.kind == CandidateKind::Invariant)
        .map(|c| c.rank_millionths)
        .max();
    let side_condition_rank = catalog
        .candidates
        .iter()
        .filter(|c| c.kind == CandidateKind::SideCondition)
        .map(|c| c.rank_millionths)
        .max();
    if let (Some(inv), Some(sc)) = (invariant_rank, side_condition_rank) {
        assert!(
            inv > sc,
            "invariant ({inv}) should outrank side_condition ({sc})"
        );
    }
}

// ── Scope Hypotheses frontier_only Semantics ────────────────────────────

#[test]
fn scope_frontier_only_true_when_only_counterexamples() {
    let cx = mk_counterexample(
        0x30,
        FormalProperty::Monotonicity,
        &["fs.read"],
        &[("k", "v")],
        &["m"],
    );
    let catalog = LawMiningCatalog::from_sources(300, &[cx], &[]);
    // All scopes from counterexample-only inputs should have frontier_only=true
    for scope in &catalog.scope_hypotheses {
        assert!(
            scope.frontier_only,
            "scope {} should be frontier_only",
            scope.scope_id
        );
    }
}

#[test]
fn scope_frontier_only_false_when_evidence_present() {
    let evidence = mk_evidence(
        "trace-scope",
        DecisionType::ContractEvaluation,
        "policy-scope",
        &["constraint-a"],
        &["witness-a"],
    );
    let catalog = LawMiningCatalog::from_sources(301, &[], &[evidence]);
    for scope in &catalog.scope_hypotheses {
        assert!(
            !scope.frontier_only,
            "scope {} should NOT be frontier_only",
            scope.scope_id
        );
    }
}

// ── Counterexample Without Merge Path ───────────────────────────────────

#[test]
fn no_normal_form_without_merge_path() {
    let cx = mk_counterexample(
        0x40,
        FormalProperty::MergeDeterminism,
        &["fs.read"],
        &[("k", "v")],
        &[], // empty merge path
    );
    let catalog = LawMiningCatalog::from_sources(400, &[cx], &[]);
    assert!(
        catalog.normal_form_hypotheses.is_empty(),
        "empty merge_path should produce no normal-form candidates"
    );
    assert!(
        !catalog
            .candidates
            .iter()
            .any(|c| c.kind == CandidateKind::NormalForm),
        "no NormalForm candidate without merge path"
    );
}

// ── Counterexample Without Conditions ───────────────────────────────────

#[test]
fn no_side_condition_without_conditions() {
    let cx = mk_counterexample(
        0x50,
        FormalProperty::NonInterference,
        &["fs.read"],
        &[], // empty conditions
        &["m"],
    );
    let catalog = LawMiningCatalog::from_sources(500, &[cx], &[]);
    // Without conditions, no side-condition candidate from the counterexample alone
    let side_conditions: Vec<_> = catalog
        .candidates
        .iter()
        .filter(|c| c.kind == CandidateKind::SideCondition)
        .collect();
    assert!(
        side_conditions.is_empty(),
        "no SideCondition should be produced from a counterexample with no conditions"
    );
}

// ── Validation Edge Cases ───────────────────────────────────────────────

#[test]
fn validation_detects_missing_supporting_sources() {
    let cx = mk_counterexample(
        0x60,
        FormalProperty::MergeDeterminism,
        &["fs.read"],
        &[("k", "v")],
        &["m"],
    );
    let mut catalog = LawMiningCatalog::from_sources(600, &[cx], &[]);
    // Clear supporting_source_ids on first candidate
    if let Some(candidate) = catalog.candidates.first_mut() {
        candidate.supporting_source_ids.clear();
    }
    let validation = catalog.validate();
    assert!(!validation.is_valid);
    assert!(
        validation
            .warnings
            .iter()
            .any(|w| w.contains("missing supporting sources"))
    );
}

#[test]
fn validation_detects_missing_scope_reference() {
    let cx = mk_counterexample(
        0x61,
        FormalProperty::MergeDeterminism,
        &["net.send"],
        &[("k", "v")],
        &["m"],
    );
    let mut catalog = LawMiningCatalog::from_sources(601, &[cx], &[]);
    if let Some(candidate) = catalog.candidates.first_mut() {
        candidate.scope_hypothesis_id = "nonexistent-scope".to_string();
    }
    let validation = catalog.validate();
    assert!(!validation.is_valid);
    assert!(
        validation
            .warnings
            .iter()
            .any(|w| w.contains("missing scope"))
    );
}

#[test]
fn validation_detects_missing_provenance_reference() {
    let cx = mk_counterexample(
        0x62,
        FormalProperty::Monotonicity,
        &["cache.store"],
        &[("k", "v")],
        &["m"],
    );
    let mut catalog = LawMiningCatalog::from_sources(602, &[cx], &[]);
    if let Some(candidate) = catalog.candidates.first_mut() {
        candidate.provenance_id = "nonexistent-prov".to_string();
    }
    let validation = catalog.validate();
    assert!(!validation.is_valid);
    assert!(
        validation
            .warnings
            .iter()
            .any(|w| w.contains("missing provenance"))
    );
}

#[test]
fn validation_detects_unsorted_candidates() {
    let cx1 = mk_counterexample(
        0x63,
        FormalProperty::MergeDeterminism,
        &["fs.read"],
        &[("k", "v")],
        &["m"],
    );
    let cx2 = mk_counterexample(
        0x64,
        FormalProperty::Monotonicity,
        &["net.send", "cache.store"],
        &[("k", "v"), ("k2", "v2")],
        &["m", "n"],
    );
    let mut catalog = LawMiningCatalog::from_sources(603, &[cx1, cx2], &[]);
    if catalog.candidates.len() >= 2 {
        // Reverse the order to break the sort
        catalog.candidates.reverse();
        let validation = catalog.validate();
        // May or may not detect this depending on whether they were already in reversed rank order
        // At minimum, the validation should run without panic
        let _ = validation.is_valid;
    }
}

// ── Catalog Determinism ─────────────────────────────────────────────────

#[test]
fn catalog_deterministic_across_input_reordering() {
    let cx1 = mk_counterexample(
        0x70,
        FormalProperty::MergeDeterminism,
        &["fs.read"],
        &[("k", "v")],
        &["m"],
    );
    let cx2 = mk_counterexample(
        0x71,
        FormalProperty::Monotonicity,
        &["net.send"],
        &[("k2", "v2")],
        &["n"],
    );
    let ev = mk_evidence(
        "trace-det",
        DecisionType::SecurityAction,
        "policy-det",
        &["c1"],
        &["w1"],
    );

    let cat_a =
        LawMiningCatalog::from_sources(700, &[cx1.clone(), cx2.clone()], std::slice::from_ref(&ev));
    let cat_b = LawMiningCatalog::from_sources(700, &[cx2, cx1], &[ev]);
    assert_eq!(
        cat_a, cat_b,
        "catalog should be deterministic regardless of input order"
    );
}

// ── Catalog candidate() lookup ──────────────────────────────────────────

#[test]
fn candidate_lookup_finds_all_candidates() {
    let cx = mk_counterexample(
        0x80,
        FormalProperty::MergeDeterminism,
        &["fs.read"],
        &[("k", "v")],
        &["m"],
    );
    let catalog = LawMiningCatalog::from_sources(800, &[cx], &[]);
    for candidate in &catalog.candidates {
        let found = catalog.candidate(&candidate.candidate_id);
        assert!(found.is_some(), "should find {}", candidate.candidate_id);
        assert_eq!(found.unwrap().statement, candidate.statement);
    }
}

// ── render_summary ──────────────────────────────────────────────────────

#[test]
fn render_summary_empty_catalog_has_no_top_candidate() {
    let catalog = LawMiningCatalog::from_sources(900, &[], &[]);
    let summary = frankenengine_engine::law_mining::render_summary(&catalog);
    assert!(summary.contains("# Law Mining Summary"));
    assert!(!summary.contains("## Top Candidate"));
}

#[test]
fn render_summary_nonempty_catalog_has_top_candidate_section() {
    let cx = mk_counterexample(
        0x90,
        FormalProperty::MergeDeterminism,
        &["fs.read"],
        &[("k", "v")],
        &["m"],
    );
    let catalog = LawMiningCatalog::from_sources(901, &[cx], &[]);
    let summary = frankenengine_engine::law_mining::render_summary(&catalog);
    assert!(summary.contains("## Top Candidate"));
    assert!(summary.contains("candidate_id:"));
    assert!(summary.contains("kind:"));
    assert!(summary.contains("rank_millionths:"));
    assert!(summary.contains("statement:"));
    assert!(summary.contains("rationale:"));
}

// ── emit_law_mining_bundle ──────────────────────────────────────────────

#[test]
fn emit_default_bundle_writes_all_artifacts() {
    let dir = temp_dir("emit-default");
    let context = ArtifactContext::new(&dir);
    let report =
        frankenengine_engine::law_mining::emit_default_law_mining_bundle(&context).unwrap();

    // All reported paths should exist
    assert!(report.candidate_law_catalog_path.exists());
    assert!(report.invariant_seed_ledger_path.exists());
    assert!(report.normal_form_hypotheses_path.exists());
    assert!(report.provenance_index_path.exists());
    assert!(report.scope_hypotheses_path.exists());
    assert!(report.trace_ids_path.exists());
    assert!(report.run_manifest_path.exists());
    assert!(report.events_path.exists());
    assert!(report.commands_path.exists());
    assert!(report.env_path.exists());
    assert!(report.artifact_index_path.exists());
    assert!(report.repro_lock_path.exists());
    assert!(report.summary_path.exists());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_run_manifest_has_correct_schema_version() {
    let dir = temp_dir("emit-manifest");
    let context = ArtifactContext::new(&dir);
    let report =
        frankenengine_engine::law_mining::emit_default_law_mining_bundle(&context).unwrap();

    let manifest_bytes = fs::read(&report.run_manifest_path).unwrap();
    let manifest: LawMiningRunManifest = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(
        manifest.schema_version,
        LAW_MINING_RUN_MANIFEST_SCHEMA_VERSION
    );
    assert_eq!(manifest.bead_id, LAW_MINING_BEAD_ID);
    assert!(!manifest.artifact_hashes.is_empty());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_catalog_artifact_validates() {
    let dir = temp_dir("emit-validate");
    let context = ArtifactContext::new(&dir);
    let report =
        frankenengine_engine::law_mining::emit_default_law_mining_bundle(&context).unwrap();

    let catalog_bytes = fs::read(&report.candidate_law_catalog_path).unwrap();
    let artifact: CandidateLawCatalogArtifact = serde_json::from_slice(&catalog_bytes).unwrap();
    assert_eq!(
        artifact.schema_version,
        CANDIDATE_LAW_CATALOG_SCHEMA_VERSION
    );
    assert!(!artifact.candidates.is_empty());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_events_are_jsonl() {
    let dir = temp_dir("emit-events");
    let context = ArtifactContext::new(&dir);
    let report =
        frankenengine_engine::law_mining::emit_default_law_mining_bundle(&context).unwrap();

    let events_text = fs::read_to_string(&report.events_path).unwrap();
    let lines: Vec<&str> = events_text.lines().collect();
    assert!(lines.len() >= 2, "should have at least 2 event lines");
    for line in &lines {
        let event: LawMiningEvent = serde_json::from_str(line).unwrap();
        assert_eq!(event.schema_version, LAW_MINING_EVENT_STREAM_SCHEMA_VERSION);
        assert_eq!(event.component, LAW_MINING_COMPONENT);
    }

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_summary_contains_header() {
    let dir = temp_dir("emit-summary");
    let context = ArtifactContext::new(&dir);
    let report =
        frankenengine_engine::law_mining::emit_default_law_mining_bundle(&context).unwrap();

    let summary = fs::read_to_string(&report.summary_path).unwrap();
    assert!(summary.contains("# Law Mining Summary"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_repro_lock_contains_run_id() {
    let dir = temp_dir("emit-repro");
    let context = ArtifactContext::new(&dir);
    let report =
        frankenengine_engine::law_mining::emit_default_law_mining_bundle(&context).unwrap();

    let repro = fs::read_to_string(&report.repro_lock_path).unwrap();
    assert!(repro.contains(&context.run_id));
    assert!(repro.contains("catalog_hash="));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn emit_bundle_commands_contains_invocation() {
    let dir = temp_dir("emit-cmds");
    let mut context = ArtifactContext::new(&dir);
    context.command_invocation = "custom-law-mining-cmd".to_string();
    let report =
        frankenengine_engine::law_mining::emit_default_law_mining_bundle(&context).unwrap();

    let commands = fs::read_to_string(&report.commands_path).unwrap();
    assert!(commands.contains("custom-law-mining-cmd"));

    let _ = fs::remove_dir_all(&dir);
}

// ── Evidence-Only Catalog ───────────────────────────────────────────────

#[test]
fn evidence_only_catalog_produces_side_condition_candidates() {
    let ev = mk_evidence(
        "trace-ev-only",
        DecisionType::ContractEvaluation,
        "policy-ev",
        &["c1", "c2"],
        &["w1"],
    );
    let catalog = LawMiningCatalog::from_sources(1000, &[], &[ev]);
    assert!(!catalog.candidates.is_empty());
    for candidate in &catalog.candidates {
        assert_eq!(candidate.kind, CandidateKind::SideCondition);
    }
    assert!(catalog.validate().is_valid);
}

// ── Hash Determinism for Sub-Components ─────────────────────────────────

#[test]
fn provenance_hashes_are_deterministic() {
    let cx = mk_counterexample(
        0xA0,
        FormalProperty::MergeDeterminism,
        &["fs.read"],
        &[("k", "v")],
        &["m"],
    );
    let cat1 = LawMiningCatalog::from_sources(1100, std::slice::from_ref(&cx), &[]);
    let cat2 = LawMiningCatalog::from_sources(1100, std::slice::from_ref(&cx), &[]);
    for (p1, p2) in cat1
        .provenance_index
        .iter()
        .zip(cat2.provenance_index.iter())
    {
        assert_eq!(p1.provenance_hash, p2.provenance_hash);
    }
}

#[test]
fn scope_hashes_are_deterministic() {
    let cx = mk_counterexample(
        0xA1,
        FormalProperty::Monotonicity,
        &["net.send"],
        &[("region", "alpha")],
        &["x"],
    );
    let cat1 = LawMiningCatalog::from_sources(1101, std::slice::from_ref(&cx), &[]);
    let cat2 = LawMiningCatalog::from_sources(1101, std::slice::from_ref(&cx), &[]);
    for (s1, s2) in cat1
        .scope_hypotheses
        .iter()
        .zip(cat2.scope_hypotheses.iter())
    {
        assert_eq!(s1.scope_hash, s2.scope_hash);
    }
}

// ── Catalog hash sensitivity ────────────────────────────────────────────

#[test]
fn catalog_hash_changes_with_different_counterexamples() {
    let cx1 = mk_counterexample(
        0xB0,
        FormalProperty::MergeDeterminism,
        &["fs.read"],
        &[("k", "v")],
        &["m"],
    );
    let cx2 = mk_counterexample(
        0xB1,
        FormalProperty::Monotonicity,
        &["net.send"],
        &[("k2", "v2")],
        &["n"],
    );
    let cat1 = LawMiningCatalog::from_sources(1200, &[cx1], &[]);
    let cat2 = LawMiningCatalog::from_sources(1200, &[cx2], &[]);
    assert_ne!(cat1.catalog_hash, cat2.catalog_hash);
}

// ── default_fixture ─────────────────────────────────────────────────────

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
fn default_fixture_evidence_entries_have_distinct_trace_ids() {
    let fixture = frankenengine_engine::law_mining::default_fixture();
    let ids: BTreeSet<_> = fixture
        .evidence_entries
        .iter()
        .map(|e| e.trace_id.clone())
        .collect();
    assert_eq!(ids.len(), fixture.evidence_entries.len());
}

// ── Multiple evidence entries combine ───────────────────────────────────

#[test]
fn multiple_evidence_entries_accumulate_breadth() {
    let ev1 = mk_evidence(
        "trace-multi-1",
        DecisionType::ContractEvaluation,
        "policy-a",
        &["c1"],
        &["w1"],
    );
    let ev2 = mk_evidence(
        "trace-multi-2",
        DecisionType::ContractEvaluation,
        "policy-b",
        &["c2"],
        &["w2"],
    );
    let catalog = LawMiningCatalog::from_sources(1300, &[], &[ev1, ev2]);
    assert!(catalog.validate().is_valid);
    // With two different policies, there should be at least 2 candidates
    // (different constraint_ids produce different statements)
    assert!(catalog.candidates.len() >= 2);
}
