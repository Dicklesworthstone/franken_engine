//! Integration tests for the ESM/CJS interop parity evidence harness.

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

use frankenengine_engine::esm_cjs_interop_parity::*;
use frankenengine_engine::module_live_binding::BindingCellState;
use frankenengine_engine::module_resolver::ModuleSyntax;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Corpus invariants
// ---------------------------------------------------------------------------

#[test]
fn corpus_non_empty() {
    assert!(!interop_parity_corpus().is_empty());
}

#[test]
fn corpus_ids_globally_unique() {
    let corpus = interop_parity_corpus();
    let ids: BTreeSet<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    assert_eq!(ids.len(), corpus.len());
}

#[test]
fn corpus_deterministic() {
    let a = interop_parity_corpus();
    let b = interop_parity_corpus();
    assert_eq!(a, b);
}

#[test]
fn corpus_covers_all_interop_families() {
    let corpus = interop_parity_corpus();
    let covered: BTreeSet<InteropFamily> = corpus.iter().map(|s| s.family).collect();
    for f in InteropFamily::ALL {
        assert!(covered.contains(f), "family {:?} not covered", f);
    }
}

#[test]
fn corpus_has_success_specimens() {
    let corpus = interop_parity_corpus();
    assert!(
        corpus
            .iter()
            .any(|s| s.expected_outcome == InteropExpectedOutcome::Success)
    );
}

#[test]
fn corpus_has_failure_specimens() {
    let corpus = interop_parity_corpus();
    assert!(
        corpus
            .iter()
            .any(|s| s.expected_outcome != InteropExpectedOutcome::Success)
    );
}

#[test]
fn corpus_has_non_success_outcomes() {
    let corpus = interop_parity_corpus();
    // Corpus may not have all failure types, but must have at least one non-success.
    let non_success: BTreeSet<_> = corpus
        .iter()
        .filter(|s| s.expected_outcome != InteropExpectedOutcome::Success)
        .map(|s| s.expected_outcome)
        .collect();
    assert!(
        !non_success.is_empty(),
        "corpus should have at least one non-success specimen"
    );
}

#[test]
fn corpus_has_cycle_specimens() {
    let corpus = interop_parity_corpus();
    assert!(
        corpus
            .iter()
            .any(|s| s.expected_outcome == InteropExpectedOutcome::CycleDetected)
    );
}

#[test]
fn corpus_has_esm_only_specimens() {
    let corpus = interop_parity_corpus();
    assert!(
        corpus
            .iter()
            .any(|s| s.modules.iter().all(|m| m.syntax == ModuleSyntax::EsModule))
    );
}

#[test]
fn corpus_has_cjs_only_specimens() {
    let corpus = interop_parity_corpus();
    assert!(
        corpus
            .iter()
            .any(|s| s.modules.iter().all(|m| m.syntax == ModuleSyntax::CommonJs))
    );
}

#[test]
fn corpus_has_mixed_syntax_specimens() {
    let corpus = interop_parity_corpus();
    assert!(corpus.iter().any(|s| {
        let syntaxes: BTreeSet<_> = s.modules.iter().map(|m| m.syntax).collect();
        syntaxes.len() > 1
    }));
}

#[test]
fn corpus_descriptions_all_non_empty() {
    for s in &interop_parity_corpus() {
        assert!(
            !s.description.is_empty(),
            "specimen {} has empty desc",
            s.specimen_id
        );
    }
}

#[test]
fn corpus_entry_points_in_modules() {
    for s in &interop_parity_corpus() {
        assert!(
            s.modules.iter().any(|m| m.specifier == s.entry_point),
            "specimen {} entry_point '{}' not in modules",
            s.specimen_id,
            s.entry_point
        );
    }
}

#[test]
fn corpus_modules_all_have_specifiers() {
    for s in &interop_parity_corpus() {
        for m in &s.modules {
            assert!(
                !m.specifier.is_empty(),
                "specimen {} has module with empty specifier",
                s.specimen_id
            );
        }
    }
}

#[test]
fn corpus_has_binding_state_expectations() {
    let corpus = interop_parity_corpus();
    assert!(
        corpus.iter().any(|s| !s.expected_binding_states.is_empty()),
        "no specimens have binding state expectations"
    );
}

#[test]
fn corpus_has_async_phase_expectations() {
    let corpus = interop_parity_corpus();
    assert!(
        corpus.iter().any(|s| !s.expected_async_phases.is_empty()),
        "no specimens have async phase expectations"
    );
}

#[test]
fn corpus_has_top_level_await_modules() {
    let corpus = interop_parity_corpus();
    assert!(
        corpus
            .iter()
            .any(|s| s.modules.iter().any(|m| m.has_top_level_await)),
        "no specimens have TLA modules"
    );
}

#[test]
fn corpus_has_default_export_modules() {
    let corpus = interop_parity_corpus();
    assert!(
        corpus
            .iter()
            .any(|s| s.modules.iter().any(|m| m.has_default_export)),
        "no specimens have default exports"
    );
}

// ---------------------------------------------------------------------------
// Runner / Inventory
// ---------------------------------------------------------------------------

#[test]
fn all_specimens_pass() {
    let inv = run_interop_parity_corpus();
    for ev in &inv.evidence {
        assert_eq!(
            ev.verdict,
            InteropVerdict::Pass,
            "specimen {} failed: expected={:?} actual={:?} error={:?}",
            ev.specimen_id,
            ev.expected_outcome,
            ev.actual_outcome,
            ev.error_detail,
        );
    }
}

#[test]
fn contract_satisfied() {
    let inv = run_interop_parity_corpus();
    assert!(inv.contract_satisfied());
}

#[test]
fn inventory_schema_matches() {
    let inv = run_interop_parity_corpus();
    assert_eq!(inv.schema_version, INTEROP_PARITY_SCHEMA_VERSION);
    assert_eq!(inv.component, INTEROP_PARITY_COMPONENT);
}

#[test]
fn inventory_counts_consistent() {
    let inv = run_interop_parity_corpus();
    assert_eq!(inv.pass_count + inv.fail_count, inv.specimen_count);
    assert_eq!(inv.evidence.len() as u64, inv.specimen_count);
}

#[test]
fn inventory_syntax_counts_sum() {
    let inv = run_interop_parity_corpus();
    assert_eq!(
        inv.esm_only_count + inv.cjs_only_count + inv.mixed_count,
        inv.specimen_count
    );
}

#[test]
fn inventory_family_coverage_sums() {
    let inv = run_interop_parity_corpus();
    let total: u64 = inv.family_coverage.values().sum();
    assert_eq!(total, inv.specimen_count);
}

#[test]
fn inventory_family_coverage_all_present() {
    let inv = run_interop_parity_corpus();
    for f in InteropFamily::ALL {
        assert!(
            inv.family_coverage.contains_key(f.as_str()),
            "family {} missing from coverage",
            f
        );
    }
}

#[test]
fn inventory_is_deterministic() {
    let a = run_interop_parity_corpus();
    let b = run_interop_parity_corpus();
    assert_eq!(a, b);
}

#[test]
fn inventory_evidence_ids_match_corpus() {
    let corpus = interop_parity_corpus();
    let inv = run_interop_parity_corpus();
    let corpus_ids: Vec<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
    let evidence_ids: Vec<&str> = inv
        .evidence
        .iter()
        .map(|e| e.specimen_id.as_str())
        .collect();
    assert_eq!(corpus_ids, evidence_ids);
}

// ---------------------------------------------------------------------------
// Evidence hashes
// ---------------------------------------------------------------------------

#[test]
fn evidence_hashes_present() {
    let inv = run_interop_parity_corpus();
    for ev in &inv.evidence {
        assert!(
            ev.evidence_hash.is_some(),
            "specimen {} missing hash",
            ev.specimen_id
        );
    }
}

#[test]
fn evidence_hashes_are_64_hex() {
    let inv = run_interop_parity_corpus();
    for ev in &inv.evidence {
        let hash = ev.evidence_hash.as_ref().unwrap();
        assert_eq!(
            hash.len(),
            64,
            "specimen {} hash wrong length: {}",
            ev.specimen_id,
            hash.len()
        );
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "specimen {} hash not hex: {}",
            ev.specimen_id,
            hash
        );
    }
}

#[test]
fn evidence_hashes_deterministic() {
    let a = run_interop_parity_corpus();
    let b = run_interop_parity_corpus();
    for (ea, eb) in a.evidence.iter().zip(b.evidence.iter()) {
        assert_eq!(ea.evidence_hash, eb.evidence_hash);
    }
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn inventory_serde_roundtrip() {
    let inv = run_interop_parity_corpus();
    let json = serde_json::to_string_pretty(&inv).unwrap();
    let decoded: InteropParityInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, decoded);
}

#[test]
fn corpus_serde_roundtrip() {
    let corpus = interop_parity_corpus();
    let json = serde_json::to_string(&corpus).unwrap();
    let decoded: Vec<InteropSpecimen> = serde_json::from_str(&json).unwrap();
    assert_eq!(corpus, decoded);
}

#[test]
fn family_serde_all_variants() {
    for f in InteropFamily::ALL {
        let json = serde_json::to_string(f).unwrap();
        let back: InteropFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*f, back);
        assert_eq!(json, format!("\"{}\"", f.as_str()));
    }
}

#[test]
fn expected_outcome_serde_all_variants() {
    let variants = [
        InteropExpectedOutcome::Success,
        InteropExpectedOutcome::LinkFailure,
        InteropExpectedOutcome::EvalFailure,
        InteropExpectedOutcome::CycleDetected,
    ];
    for o in &variants {
        let json = serde_json::to_string(o).unwrap();
        let back: InteropExpectedOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, back);
    }
}

#[test]
fn actual_outcome_serde_all_variants() {
    let variants = [
        InteropActualOutcome::Success,
        InteropActualOutcome::LinkFailure,
        InteropActualOutcome::EvalFailure,
        InteropActualOutcome::CycleDetected,
        InteropActualOutcome::GraphConstructionFailure,
    ];
    for o in &variants {
        let json = serde_json::to_string(o).unwrap();
        let back: InteropActualOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, back);
    }
}

#[test]
fn verdict_serde() {
    let p = serde_json::to_string(&InteropVerdict::Pass).unwrap();
    let f = serde_json::to_string(&InteropVerdict::Fail).unwrap();
    assert_eq!(p, "\"pass\"");
    assert_eq!(f, "\"fail\"");
    assert_eq!(
        serde_json::from_str::<InteropVerdict>(&p).unwrap(),
        InteropVerdict::Pass
    );
    assert_eq!(
        serde_json::from_str::<InteropVerdict>(&f).unwrap(),
        InteropVerdict::Fail
    );
}

#[test]
fn manifest_serde_roundtrip() {
    let m = InteropParityRunManifest {
        schema_version: INTEROP_PARITY_MANIFEST_SCHEMA_VERSION.into(),
        component: INTEROP_PARITY_COMPONENT.into(),
        trace_id: "test-trace".into(),
        decision_id: "test-decision".into(),
        policy_id: INTEROP_PARITY_POLICY_ID.into(),
        inventory_hash: "abc".into(),
        specimen_count: 5,
        pass_count: 5,
        fail_count: 0,
        contract_satisfied: true,
        artifact_paths: InteropParityArtifactPaths {
            evidence_inventory: "inv.json".into(),
            run_manifest: "manifest.json".into(),
            events_jsonl: "events.jsonl".into(),
            commands_txt: "cmds.txt".into(),
        },
    };
    let json = serde_json::to_string_pretty(&m).unwrap();
    let back: InteropParityRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn event_serde_roundtrip() {
    let ev = InteropParityEvent {
        schema_version: INTEROP_PARITY_EVENT_SCHEMA_VERSION.into(),
        component: INTEROP_PARITY_COMPONENT.into(),
        event: "test_event".into(),
        policy_id: INTEROP_PARITY_POLICY_ID.into(),
        specimen_id: Some("spec1".into()),
        verdict: Some("pass".into()),
        detail: Some("detail".into()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: InteropParityEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn event_serde_with_none_fields() {
    let ev = InteropParityEvent {
        schema_version: INTEROP_PARITY_EVENT_SCHEMA_VERSION.into(),
        component: INTEROP_PARITY_COMPONENT.into(),
        event: "run_started".into(),
        policy_id: INTEROP_PARITY_POLICY_ID.into(),
        specimen_id: None,
        verdict: None,
        detail: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: InteropParityEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ---------------------------------------------------------------------------
// Contract satisfaction
// ---------------------------------------------------------------------------

#[test]
fn contract_not_satisfied_with_failure() {
    let inv = InteropParityInventory {
        schema_version: INTEROP_PARITY_SCHEMA_VERSION.into(),
        component: INTEROP_PARITY_COMPONENT.into(),
        specimen_count: 10,
        pass_count: 9,
        fail_count: 1,
        family_coverage: Default::default(),
        esm_only_count: 3,
        cjs_only_count: 3,
        mixed_count: 4,
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

#[test]
fn contract_not_satisfied_with_empty() {
    let inv = InteropParityInventory {
        schema_version: INTEROP_PARITY_SCHEMA_VERSION.into(),
        component: INTEROP_PARITY_COMPONENT.into(),
        specimen_count: 0,
        pass_count: 0,
        fail_count: 0,
        family_coverage: Default::default(),
        esm_only_count: 0,
        cjs_only_count: 0,
        mixed_count: 0,
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

// ---------------------------------------------------------------------------
// Family enum
// ---------------------------------------------------------------------------

#[test]
fn family_all_constant_complete() {
    assert_eq!(InteropFamily::ALL.len(), 10);
}

#[test]
fn family_as_str_all_distinct() {
    let strs: BTreeSet<&str> = InteropFamily::ALL.iter().map(|f| f.as_str()).collect();
    assert_eq!(strs.len(), InteropFamily::ALL.len());
}

#[test]
fn family_display_matches_as_str() {
    for f in InteropFamily::ALL {
        assert_eq!(format!("{f}"), f.as_str());
    }
}

// ---------------------------------------------------------------------------
// Schema version constants
// ---------------------------------------------------------------------------

#[test]
fn schema_versions_distinct() {
    let versions: BTreeSet<&str> = [
        INTEROP_PARITY_SCHEMA_VERSION,
        INTEROP_PARITY_MANIFEST_SCHEMA_VERSION,
        INTEROP_PARITY_EVENT_SCHEMA_VERSION,
    ]
    .iter()
    .copied()
    .collect();
    assert_eq!(versions.len(), 3);
}

#[test]
fn schema_versions_prefixed() {
    assert!(INTEROP_PARITY_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(INTEROP_PARITY_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(INTEROP_PARITY_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn policy_id_matches() {
    assert_eq!(INTEROP_PARITY_POLICY_ID, "RGC-309C");
}

#[test]
fn component_name_matches() {
    assert_eq!(INTEROP_PARITY_COMPONENT, "esm_cjs_interop_parity");
}

// ---------------------------------------------------------------------------
// Bundle writer
// ---------------------------------------------------------------------------

#[test]
fn bundle_creates_four_files() {
    let dir = std::env::temp_dir().join("esm_cjs_interop_parity_test_bundle");
    let _ = std::fs::remove_dir_all(&dir);

    let result = write_interop_parity_bundle(&dir, &["test cmd".into()]);
    assert!(result.is_ok(), "bundle write failed: {:?}", result.err());

    let bundle = result.unwrap();
    assert!(bundle.inventory_path.exists());
    assert!(bundle.run_manifest_path.exists());
    assert!(bundle.events_path.exists());
    assert!(bundle.commands_path.exists());
    assert!(!bundle.inventory_hash.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_inventory_is_valid_json() {
    let dir = std::env::temp_dir().join("esm_cjs_interop_parity_inv_json");
    let _ = std::fs::remove_dir_all(&dir);

    let bundle = write_interop_parity_bundle(&dir, &[]).unwrap();
    let content = std::fs::read_to_string(&bundle.inventory_path).unwrap();
    let inv: InteropParityInventory = serde_json::from_str(&content).unwrap();
    assert!(inv.contract_satisfied());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_manifest_is_valid_json() {
    let dir = std::env::temp_dir().join("esm_cjs_interop_parity_manifest_json");
    let _ = std::fs::remove_dir_all(&dir);

    let bundle = write_interop_parity_bundle(&dir, &[]).unwrap();
    let content = std::fs::read_to_string(&bundle.run_manifest_path).unwrap();
    let manifest: InteropParityRunManifest = serde_json::from_str(&content).unwrap();
    assert_eq!(manifest.policy_id, INTEROP_PARITY_POLICY_ID);
    assert!(manifest.contract_satisfied);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_events_is_valid_jsonl() {
    let dir = std::env::temp_dir().join("esm_cjs_interop_parity_events_jsonl");
    let _ = std::fs::remove_dir_all(&dir);

    let bundle = write_interop_parity_bundle(&dir, &[]).unwrap();
    let content = std::fs::read_to_string(&bundle.events_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    let corpus_size = interop_parity_corpus().len();
    // started + N specimens + completed
    assert_eq!(lines.len(), corpus_size + 2);
    for line in &lines {
        let event: InteropParityEvent = serde_json::from_str(line).unwrap();
        assert_eq!(event.component, INTEROP_PARITY_COMPONENT);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_commands_recorded() {
    let dir = std::env::temp_dir().join("esm_cjs_interop_parity_cmds");
    let _ = std::fs::remove_dir_all(&dir);

    let cmds = vec!["cmd_a".to_string(), "cmd_b".to_string()];
    let bundle = write_interop_parity_bundle(&dir, &cmds).unwrap();
    let content = std::fs::read_to_string(&bundle.commands_path).unwrap();
    assert!(content.contains("cmd_a"));
    assert!(content.contains("cmd_b"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bundle_hash_deterministic() {
    let dir1 = std::env::temp_dir().join("esm_cjs_interop_hash_a");
    let dir2 = std::env::temp_dir().join("esm_cjs_interop_hash_b");
    let _ = std::fs::remove_dir_all(&dir1);
    let _ = std::fs::remove_dir_all(&dir2);

    let b1 = write_interop_parity_bundle(&dir1, &[]).unwrap();
    let b2 = write_interop_parity_bundle(&dir2, &[]).unwrap();
    assert_eq!(b1.inventory_hash, b2.inventory_hash);

    let _ = std::fs::remove_dir_all(&dir1);
    let _ = std::fs::remove_dir_all(&dir2);
}

// ---------------------------------------------------------------------------
// Cross-module type verification
// ---------------------------------------------------------------------------

#[test]
fn binding_cell_state_used_in_expectations() {
    let corpus = interop_parity_corpus();
    let states: BTreeSet<_> = corpus
        .iter()
        .flat_map(|s| s.expected_binding_states.iter())
        .map(|bs| bs.expected_state)
        .collect();
    assert!(states.contains(&BindingCellState::Initialized));
}

#[test]
fn async_module_phase_used_in_expectations() {
    let corpus = interop_parity_corpus();
    let phases: BTreeSet<_> = corpus
        .iter()
        .flat_map(|s| s.expected_async_phases.iter())
        .map(|ap| ap.expected_phase)
        .collect();
    assert!(!phases.is_empty(), "expected some async phase expectations");
}

#[test]
fn module_syntax_variants_both_present() {
    let corpus = interop_parity_corpus();
    let syntaxes: BTreeSet<_> = corpus
        .iter()
        .flat_map(|s| s.modules.iter())
        .map(|m| m.syntax)
        .collect();
    assert!(syntaxes.contains(&ModuleSyntax::EsModule));
    assert!(syntaxes.contains(&ModuleSyntax::CommonJs));
}

// ---------------------------------------------------------------------------
// Per-specimen evidence checks
// ---------------------------------------------------------------------------

#[test]
fn each_evidence_has_family() {
    let inv = run_interop_parity_corpus();
    let corpus = interop_parity_corpus();
    for (s, ev) in corpus.iter().zip(inv.evidence.iter()) {
        assert_eq!(s.family, ev.family);
    }
}

#[test]
fn each_evidence_has_expected_outcome() {
    let inv = run_interop_parity_corpus();
    let corpus = interop_parity_corpus();
    for (s, ev) in corpus.iter().zip(inv.evidence.iter()) {
        assert_eq!(s.expected_outcome, ev.expected_outcome);
    }
}

#[test]
fn each_evidence_module_count_positive() {
    let inv = run_interop_parity_corpus();
    for ev in &inv.evidence {
        assert!(
            ev.module_count > 0,
            "specimen {} has zero modules",
            ev.specimen_id
        );
    }
}
