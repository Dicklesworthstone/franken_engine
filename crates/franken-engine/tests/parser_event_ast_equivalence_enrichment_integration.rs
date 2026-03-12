//! Enrichment integration tests for parser_event_ast_equivalence.
//!
//! Covers gaps not addressed by the base integration test file or unit tests:
//! serde roundtrips for all struct types, display uniqueness for all enums,
//! canonical hash sensitivity, contract_satisfied edge cases, inventory
//! and manifest field validation, event generation field checks, and
//! corpus invariant verification.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser_event_ast_equivalence::{
    BEAD_ID, COMPONENT, CorpusTier, EVENT_SCHEMA_VERSION, EquivalenceEvent, EquivalenceInventory,
    EquivalenceRunManifest, EquivalenceSpecimen, EquivalenceVerdict, FIXED_ONE,
    MANIFEST_SCHEMA_VERSION, POLICY_ID, SCHEMA_VERSION, SpecimenEvidence, TamperKind, TierSummary,
    build_manifest, equivalence_corpus, evaluate_specimen, generate_events, run_equivalence_corpus,
};

// ---------------------------------------------------------------------------
// Constants validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_values_correct() {
    assert_eq!(FIXED_ONE, 1_000_000);
    assert!(SCHEMA_VERSION.contains("inventory"));
    assert!(MANIFEST_SCHEMA_VERSION.contains("run-manifest"));
    assert!(EVENT_SCHEMA_VERSION.contains("event"));
    assert!(POLICY_ID.contains("policy"));
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrichment_constants_all_unique() {
    let constants: BTreeSet<&str> = [
        SCHEMA_VERSION,
        MANIFEST_SCHEMA_VERSION,
        EVENT_SCHEMA_VERSION,
        COMPONENT,
        POLICY_ID,
        BEAD_ID,
    ]
    .into_iter()
    .collect();
    assert_eq!(constants.len(), 6);
}

// ---------------------------------------------------------------------------
// Display uniqueness for all enums
// ---------------------------------------------------------------------------

#[test]
fn enrichment_corpus_tier_display_all_unique() {
    let displays: BTreeSet<String> = CorpusTier::ALL.iter().map(|t| format!("{t}")).collect();
    assert_eq!(displays.len(), CorpusTier::ALL.len());
}

#[test]
fn enrichment_tamper_kind_display_all_unique() {
    let displays: BTreeSet<String> = TamperKind::ALL.iter().map(|k| format!("{k}")).collect();
    assert_eq!(displays.len(), TamperKind::ALL.len());
}

#[test]
fn enrichment_verdict_display_unique() {
    let pass = format!("{}", EquivalenceVerdict::Pass);
    let fail = format!("{}", EquivalenceVerdict::Fail);
    assert_ne!(pass, fail);
    assert_eq!(pass, "pass");
    assert_eq!(fail, "fail");
}

// ---------------------------------------------------------------------------
// Serde roundtrips for struct types
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_equivalence_specimen_roundtrip() {
    let specimen = EquivalenceSpecimen {
        specimen_id: "test_specimen".to_string(),
        source: "const x = 42;\n".to_string(),
        goal: ParseGoal::Script,
        corpus_tier: CorpusTier::Core,
        tamper_kind: TamperKind::None,
        expect_parity: true,
        expected_parse_error: None,
        expected_materialization_error: None,
        expected_statement_count: 1,
    };
    let json = serde_json::to_string(&specimen).unwrap();
    let restored: EquivalenceSpecimen = serde_json::from_str(&json).unwrap();
    assert_eq!(specimen, restored);
}

#[test]
fn enrichment_serde_specimen_evidence_roundtrip() {
    let evidence = SpecimenEvidence {
        specimen_id: "test_ev".to_string(),
        corpus_tier: CorpusTier::Edge,
        tamper_kind: TamperKind::StatementHash,
        verdict: EquivalenceVerdict::Pass,
        event_ir_hash: "sha256:abc123".to_string(),
        materialized_ast_hash: Some("sha256:def456".to_string()),
        original_ast_hash: Some("sha256:def456".to_string()),
        parse_error_code: None,
        materialization_error_code: None,
        statement_count: 3,
        hash_parity: true,
        replay_stable: true,
    };
    let json = serde_json::to_string(&evidence).unwrap();
    let restored: SpecimenEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(evidence, restored);
}

#[test]
fn enrichment_serde_specimen_evidence_with_errors() {
    let evidence = SpecimenEvidence {
        specimen_id: "err_ev".to_string(),
        corpus_tier: CorpusTier::Adversarial,
        tamper_kind: TamperKind::EventDeletion,
        verdict: EquivalenceVerdict::Fail,
        event_ir_hash: "sha256:000".to_string(),
        materialized_ast_hash: None,
        original_ast_hash: None,
        parse_error_code: Some("empty_source".to_string()),
        materialization_error_code: Some("parse_failed_event_stream".to_string()),
        statement_count: 0,
        hash_parity: false,
        replay_stable: false,
    };
    let json = serde_json::to_string(&evidence).unwrap();
    let restored: SpecimenEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(evidence, restored);
}

#[test]
fn enrichment_serde_tier_summary_roundtrip() {
    let summary = TierSummary {
        total: 10,
        passed: 8,
        failed: 2,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let restored: TierSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

#[test]
fn enrichment_serde_equivalence_event_roundtrip() {
    let event = EquivalenceEvent {
        schema_version: EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "trace-test".to_string(),
        decision_id: "decision-test".to_string(),
        policy_id: POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event_type: "specimen_evaluated".to_string(),
        specimen_id: "spec-1".to_string(),
        corpus_tier: "core".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: EquivalenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn enrichment_serde_equivalence_event_with_error_code() {
    let event = EquivalenceEvent {
        schema_version: EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "trace-test".to_string(),
        decision_id: "decision-test".to_string(),
        policy_id: POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event_type: "specimen_evaluated".to_string(),
        specimen_id: "spec-fail".to_string(),
        corpus_tier: "adversarial".to_string(),
        outcome: "fail".to_string(),
        error_code: Some("statement_hash_mismatch".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: EquivalenceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn enrichment_serde_equivalence_inventory_full_roundtrip() {
    let inventory = run_equivalence_corpus();
    let json = serde_json::to_string(&inventory).unwrap();
    let restored: EquivalenceInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inventory, restored);
}

#[test]
fn enrichment_serde_equivalence_run_manifest_roundtrip() {
    let inventory = run_equivalence_corpus();
    let manifest = build_manifest(
        &inventory,
        "trace-serde",
        "decision-serde",
        vec!["inv.json".to_string(), "events.jsonl".to_string()],
    );
    let json = serde_json::to_string(&manifest).unwrap();
    let restored: EquivalenceRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, restored);
}

// ---------------------------------------------------------------------------
// Canonical hash sensitivity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_specimen_evidence_canonical_hash_sensitive_to_verdict() {
    let mut ev1 = SpecimenEvidence {
        specimen_id: "hash_test".to_string(),
        corpus_tier: CorpusTier::Core,
        tamper_kind: TamperKind::None,
        verdict: EquivalenceVerdict::Pass,
        event_ir_hash: "sha256:abc".to_string(),
        materialized_ast_hash: Some("sha256:def".to_string()),
        original_ast_hash: Some("sha256:def".to_string()),
        parse_error_code: None,
        materialization_error_code: None,
        statement_count: 1,
        hash_parity: true,
        replay_stable: true,
    };
    let hash_pass = ev1.canonical_hash();
    ev1.verdict = EquivalenceVerdict::Fail;
    let hash_fail = ev1.canonical_hash();
    assert_ne!(hash_pass, hash_fail);
}

#[test]
fn enrichment_specimen_evidence_canonical_hash_starts_with_sha256() {
    let ev = SpecimenEvidence {
        specimen_id: "prefix_test".to_string(),
        corpus_tier: CorpusTier::Core,
        tamper_kind: TamperKind::None,
        verdict: EquivalenceVerdict::Pass,
        event_ir_hash: "sha256:abc".to_string(),
        materialized_ast_hash: None,
        original_ast_hash: None,
        parse_error_code: None,
        materialization_error_code: None,
        statement_count: 0,
        hash_parity: false,
        replay_stable: true,
    };
    assert!(ev.canonical_hash().starts_with("sha256:"));
}

#[test]
fn enrichment_inventory_canonical_hash_sensitive_to_content() {
    let inv1 = run_equivalence_corpus();
    let mut inv2 = inv1.clone();
    inv2.failed = 99;
    assert_ne!(inv1.canonical_hash(), inv2.canonical_hash());
}

#[test]
fn enrichment_manifest_canonical_hash_sensitive_to_trace_id() {
    let inventory = run_equivalence_corpus();
    let m1 = build_manifest(&inventory, "trace-a", "decision", Vec::new());
    let m2 = build_manifest(&inventory, "trace-b", "decision", Vec::new());
    assert_ne!(m1.canonical_hash(), m2.canonical_hash());
}

#[test]
fn enrichment_manifest_canonical_hash_sensitive_to_decision_id() {
    let inventory = run_equivalence_corpus();
    let m1 = build_manifest(&inventory, "trace", "decision-a", Vec::new());
    let m2 = build_manifest(&inventory, "trace", "decision-b", Vec::new());
    assert_ne!(m1.canonical_hash(), m2.canonical_hash());
}

// ---------------------------------------------------------------------------
// contract_satisfied edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_contract_satisfied_zero_total_fails() {
    let inventory = EquivalenceInventory {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        policy_id: POLICY_ID.to_string(),
        total: 0,
        passed: 0,
        failed: 0,
        parity_verified: 0,
        tamper_detected: 0,
        replay_stable_count: 0,
        per_tier: BTreeMap::new(),
        evidence: Vec::new(),
    };
    assert!(!inventory.contract_satisfied());
}

#[test]
fn enrichment_contract_satisfied_with_failures_false() {
    let inventory = EquivalenceInventory {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        policy_id: POLICY_ID.to_string(),
        total: 10,
        passed: 9,
        failed: 1,
        parity_verified: 5,
        tamper_detected: 3,
        replay_stable_count: 10,
        per_tier: BTreeMap::new(),
        evidence: Vec::new(),
    };
    assert!(!inventory.contract_satisfied());
}

#[test]
fn enrichment_contract_satisfied_replay_unstable_false() {
    let inventory = EquivalenceInventory {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        policy_id: POLICY_ID.to_string(),
        total: 10,
        passed: 10,
        failed: 0,
        parity_verified: 5,
        tamper_detected: 3,
        replay_stable_count: 9, // not all stable
        per_tier: BTreeMap::new(),
        evidence: Vec::new(),
    };
    assert!(!inventory.contract_satisfied());
}

#[test]
fn enrichment_contract_satisfied_all_good_true() {
    let inventory = EquivalenceInventory {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        policy_id: POLICY_ID.to_string(),
        total: 10,
        passed: 10,
        failed: 0,
        parity_verified: 5,
        tamper_detected: 3,
        replay_stable_count: 10,
        per_tier: BTreeMap::new(),
        evidence: Vec::new(),
    };
    assert!(inventory.contract_satisfied());
}

// ---------------------------------------------------------------------------
// Corpus invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_corpus_all_tamper_kinds_covered() {
    let corpus = equivalence_corpus();
    let tamper_kinds: BTreeSet<TamperKind> = corpus.iter().map(|s| s.tamper_kind).collect();
    for kind in TamperKind::ALL {
        assert!(tamper_kinds.contains(kind), "missing tamper kind: {kind}");
    }
}

#[test]
fn enrichment_corpus_parity_cases_have_tamper_none() {
    let corpus = equivalence_corpus();
    for spec in &corpus {
        if spec.expect_parity {
            assert_eq!(
                spec.tamper_kind,
                TamperKind::None,
                "parity specimen {} should have TamperKind::None",
                spec.specimen_id,
            );
        }
    }
}

#[test]
fn enrichment_corpus_specimen_ids_are_descriptive() {
    let corpus = equivalence_corpus();
    for spec in &corpus {
        assert!(!spec.specimen_id.is_empty());
        assert!(
            spec.specimen_id.contains('_'),
            "specimen_id should be snake_case: {}",
            spec.specimen_id,
        );
    }
}

#[test]
fn enrichment_corpus_specimen_ids_start_with_tier() {
    let corpus = equivalence_corpus();
    for spec in &corpus {
        let tier_str = spec.corpus_tier.as_str();
        assert!(
            spec.specimen_id.starts_with(tier_str),
            "specimen {} should start with tier {}",
            spec.specimen_id,
            tier_str,
        );
    }
}

#[test]
fn enrichment_corpus_failure_cases_have_expected_error() {
    let corpus = equivalence_corpus();
    for spec in &corpus {
        if !spec.expect_parity && spec.tamper_kind == TamperKind::None {
            // Non-parity, non-tamper cases should have parse error.
            assert!(
                spec.expected_parse_error.is_some(),
                "non-parity non-tamper specimen {} should have expected_parse_error",
                spec.specimen_id,
            );
        }
    }
}

#[test]
fn enrichment_corpus_tamper_cases_have_materialization_error() {
    let corpus = equivalence_corpus();
    for spec in &corpus {
        if spec.tamper_kind != TamperKind::None {
            assert!(
                spec.expected_materialization_error.is_some(),
                "tamper specimen {} should have expected_materialization_error",
                spec.specimen_id,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Evaluate all specimens pass
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluate_all_core_specimens_pass() {
    let corpus = equivalence_corpus();
    for spec in corpus.iter().filter(|s| s.corpus_tier == CorpusTier::Core) {
        let ev = evaluate_specimen(spec);
        assert_eq!(
            ev.verdict,
            EquivalenceVerdict::Pass,
            "core specimen {} failed",
            spec.specimen_id,
        );
    }
}

#[test]
fn enrichment_evaluate_all_edge_specimens_pass() {
    let corpus = equivalence_corpus();
    for spec in corpus.iter().filter(|s| s.corpus_tier == CorpusTier::Edge) {
        let ev = evaluate_specimen(spec);
        assert_eq!(
            ev.verdict,
            EquivalenceVerdict::Pass,
            "edge specimen {} failed",
            spec.specimen_id,
        );
    }
}

#[test]
fn enrichment_evaluate_adversarial_specimens_produce_evidence() {
    let corpus = equivalence_corpus();
    let adversarial: Vec<_> = corpus
        .iter()
        .filter(|s| s.corpus_tier == CorpusTier::Adversarial)
        .collect();
    assert!(!adversarial.is_empty(), "must have adversarial specimens");
    for spec in &adversarial {
        let ev = evaluate_specimen(spec);
        // Every adversarial specimen produces non-empty canonical bytes
        assert!(
            !ev.canonical_bytes().is_empty(),
            "adversarial specimen {} must produce canonical bytes",
            spec.specimen_id,
        );
        // Hash is deterministic
        let ev2 = evaluate_specimen(spec);
        assert_eq!(
            ev.canonical_hash(),
            ev2.canonical_hash(),
            "adversarial specimen {} hash must be deterministic",
            spec.specimen_id,
        );
    }
    // At least one adversarial specimen should fail (tamper detection)
    let any_fail = adversarial
        .iter()
        .any(|s| evaluate_specimen(s).verdict == EquivalenceVerdict::Fail);
    assert!(any_fail, "at least one adversarial specimen should fail");
}

// ---------------------------------------------------------------------------
// Event generation field checks
// ---------------------------------------------------------------------------

#[test]
fn enrichment_generated_events_all_have_correct_policy_and_component() {
    let inventory = run_equivalence_corpus();
    let events = generate_events(&inventory);
    for event in &events {
        assert_eq!(event.policy_id, POLICY_ID);
        assert_eq!(event.component, COMPONENT);
        assert_eq!(event.event_type, "specimen_evaluated");
    }
}

#[test]
fn enrichment_generated_events_specimen_ids_match_evidence() {
    let inventory = run_equivalence_corpus();
    let events = generate_events(&inventory);
    for (event, evidence) in events.iter().zip(inventory.evidence.iter()) {
        assert_eq!(event.specimen_id, evidence.specimen_id);
        assert_eq!(event.corpus_tier, evidence.corpus_tier.as_str());
        assert_eq!(event.outcome, evidence.verdict.as_str());
    }
}

#[test]
fn enrichment_generated_events_trace_and_decision_ids_unique() {
    let inventory = run_equivalence_corpus();
    let events = generate_events(&inventory);
    let trace_ids: BTreeSet<_> = events.iter().map(|e| &e.trace_id).collect();
    let decision_ids: BTreeSet<_> = events.iter().map(|e| &e.decision_id).collect();
    assert_eq!(trace_ids.len(), events.len());
    assert_eq!(decision_ids.len(), events.len());
}

// ---------------------------------------------------------------------------
// Manifest field checks
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_fields_populated() {
    let inventory = run_equivalence_corpus();
    let manifest = build_manifest(
        &inventory,
        "trace-field",
        "decision-field",
        vec!["path1.json".to_string(), "path2.jsonl".to_string()],
    );
    assert_eq!(manifest.schema_version, MANIFEST_SCHEMA_VERSION);
    assert_eq!(manifest.trace_id, "trace-field");
    assert_eq!(manifest.decision_id, "decision-field");
    assert_eq!(manifest.policy_id, POLICY_ID);
    assert_eq!(manifest.component, COMPONENT);
    assert_eq!(manifest.bead_id, BEAD_ID);
    assert_eq!(manifest.artifact_paths.len(), 2);
    assert!(manifest.inventory_hash.starts_with("sha256:"));
}

#[test]
fn enrichment_manifest_inventory_hash_matches() {
    let inventory = run_equivalence_corpus();
    let manifest = build_manifest(&inventory, "t", "d", Vec::new());
    assert_eq!(manifest.inventory_hash, inventory.canonical_hash());
}

// ---------------------------------------------------------------------------
// Inventory completeness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_inventory_schema_and_component() {
    let inventory = run_equivalence_corpus();
    assert_eq!(inventory.schema_version, SCHEMA_VERSION);
    assert_eq!(inventory.component, COMPONENT);
    assert_eq!(inventory.policy_id, POLICY_ID);
}

#[test]
fn enrichment_inventory_total_equals_passed_plus_failed() {
    let inventory = run_equivalence_corpus();
    assert_eq!(inventory.total, inventory.passed + inventory.failed);
}

#[test]
fn enrichment_inventory_all_tiers_present() {
    let inventory = run_equivalence_corpus();
    for tier in CorpusTier::ALL {
        assert!(
            inventory.per_tier.contains_key(tier.as_str()),
            "missing tier: {tier}",
        );
    }
}

#[test]
fn enrichment_inventory_per_tier_consistent() {
    let inventory = run_equivalence_corpus();
    for (tier_name, summary) in &inventory.per_tier {
        assert_eq!(
            summary.total,
            summary.passed + summary.failed,
            "tier {tier_name} totals inconsistent",
        );
    }
}

#[test]
fn enrichment_inventory_evidence_count_matches_total() {
    let inventory = run_equivalence_corpus();
    assert_eq!(inventory.evidence.len(), inventory.total);
}

#[test]
fn enrichment_inventory_replay_stable_count_equals_total() {
    let inventory = run_equivalence_corpus();
    // Contract requires all specimens to be replay-stable.
    assert_eq!(inventory.replay_stable_count, inventory.total);
}

// ---------------------------------------------------------------------------
// SpecimenEvidence canonical_value produces BTreeMap keys
// ---------------------------------------------------------------------------

#[test]
fn enrichment_specimen_evidence_canonical_bytes_nonempty() {
    let corpus = equivalence_corpus();
    let ev = evaluate_specimen(&corpus[0]);
    let bytes = ev.canonical_bytes();
    assert!(!bytes.is_empty());
}

#[test]
fn enrichment_inventory_canonical_bytes_nonempty() {
    let inventory = run_equivalence_corpus();
    let bytes = inventory.canonical_bytes();
    assert!(!bytes.is_empty());
}

#[test]
fn enrichment_manifest_canonical_bytes_nonempty() {
    let inventory = run_equivalence_corpus();
    let manifest = build_manifest(&inventory, "t", "d", Vec::new());
    let bytes = manifest.canonical_bytes();
    assert!(!bytes.is_empty());
}

// ---------------------------------------------------------------------------
// CorpusTier and TamperKind ordering
// ---------------------------------------------------------------------------

#[test]
fn enrichment_corpus_tier_ordering() {
    assert!(CorpusTier::Core < CorpusTier::Edge);
    assert!(CorpusTier::Edge < CorpusTier::Adversarial);
}

#[test]
fn enrichment_tamper_kind_ordering() {
    assert!(TamperKind::None < TamperKind::StatementHash);
    assert!(TamperKind::StatementHash < TamperKind::EventDeletion);
    assert!(TamperKind::EventDeletion < TamperKind::SequenceReorder);
}
