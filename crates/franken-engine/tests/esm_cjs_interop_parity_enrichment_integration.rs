//! Enrichment integration tests for `esm_cjs_interop_parity`.
//!
//! Covers: exhaustive enum serde/display, specimen/evidence serde roundtrips,
//! corpus invariants, family coverage, inventory determinism, compatibility
//! disposition classification, remediation guidance, binding/async verdicts,
//! and artifact type serde.

use std::collections::BTreeSet;

use frankenengine_engine::esm_cjs_interop_parity::{
    AsyncPhaseVerdict, BindingVerdict, ExpectedAsyncPhase, ExpectedBindingState,
    INTEROP_PARITY_COMPONENT, INTEROP_PARITY_EVENT_SCHEMA_VERSION, INTEROP_PARITY_POLICY_ID,
    INTEROP_PARITY_SCHEMA_VERSION, InteropActualOutcome, InteropCompatibilityDisposition,
    InteropExpectedOutcome, InteropFamily, InteropParityArtifactPaths, InteropParityEvent,
    InteropParityInventory, InteropParityRunManifest, InteropRemediationGuidance, InteropSpecimen,
    InteropSpecimenEvidence, InteropVerdict, SpecimenModule, interop_parity_corpus,
    run_interop_parity_corpus,
};
use frankenengine_engine::esm_loader::ExportEntry;
use frankenengine_engine::module_async_evaluation::AsyncModulePhase;
use frankenengine_engine::module_live_binding::BindingCellState;
use frankenengine_engine::module_resolver::ModuleSyntax;

// ── Constants ───────────────────────────────────────────────────────────

#[test]
fn constants_nonempty() {
    assert!(!INTEROP_PARITY_SCHEMA_VERSION.is_empty());
    assert!(!INTEROP_PARITY_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!INTEROP_PARITY_COMPONENT.is_empty());
    assert!(!INTEROP_PARITY_POLICY_ID.is_empty());
}

#[test]
fn schema_version_contains_module_name() {
    assert!(INTEROP_PARITY_SCHEMA_VERSION.contains("esm_cjs_interop_parity"));
}

// ── InteropFamily exhaustive ────────────────────────────────────────────

#[test]
fn interop_family_all_variants_serde_roundtrip() {
    let mut displays = BTreeSet::new();
    for fam in InteropFamily::ALL {
        let json = serde_json::to_string(fam).unwrap();
        let back: InteropFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*fam, back);
        let s = fam.to_string();
        assert_eq!(s, fam.as_str());
        assert!(displays.insert(s.clone()), "duplicate: {s}");
    }
    assert_eq!(displays.len(), 10);
}

// ── InteropExpectedOutcome exhaustive ───────────────────────────────────

#[test]
fn expected_outcome_all_variants_serde() {
    let all = [
        InteropExpectedOutcome::Success,
        InteropExpectedOutcome::LinkFailure,
        InteropExpectedOutcome::EvalFailure,
        InteropExpectedOutcome::CycleDetected,
    ];
    let mut set = BTreeSet::new();
    for oc in &all {
        let json = serde_json::to_string(oc).unwrap();
        let back: InteropExpectedOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*oc, back);
        set.insert(json);
    }
    assert_eq!(set.len(), 4);
}

// ── InteropActualOutcome exhaustive ─────────────────────────────────────

#[test]
fn actual_outcome_all_variants_serde() {
    let all = [
        InteropActualOutcome::Success,
        InteropActualOutcome::LinkFailure,
        InteropActualOutcome::EvalFailure,
        InteropActualOutcome::CycleDetected,
        InteropActualOutcome::GraphConstructionFailure,
    ];
    let mut set = BTreeSet::new();
    for oc in &all {
        let json = serde_json::to_string(oc).unwrap();
        let back: InteropActualOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*oc, back);
        set.insert(json);
    }
    assert_eq!(set.len(), 5);
}

// ── InteropVerdict serde ────────────────────────────────────────────────

#[test]
fn verdict_serde_roundtrip() {
    for v in [InteropVerdict::Pass, InteropVerdict::Fail] {
        let json = serde_json::to_string(&v).unwrap();
        let back: InteropVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// ── InteropCompatibilityDisposition exhaustive ──────────────────────────

#[test]
fn compatibility_disposition_all_variants_serde_and_display() {
    let all = [
        InteropCompatibilityDisposition::Supported,
        InteropCompatibilityDisposition::Degraded,
        InteropCompatibilityDisposition::Unsupported,
    ];
    let mut displays = BTreeSet::new();
    for disp in &all {
        let json = serde_json::to_string(disp).unwrap();
        let back: InteropCompatibilityDisposition = serde_json::from_str(&json).unwrap();
        assert_eq!(*disp, back);
        let s = disp.to_string();
        assert_eq!(s, disp.as_str());
        assert!(displays.insert(s.clone()), "duplicate: {s}");
    }
    assert_eq!(displays.len(), 3);
}

// ── SpecimenModule serde ────────────────────────────────────────────────

#[test]
fn specimen_module_serde_roundtrip() {
    let sm = SpecimenModule {
        specifier: "entry.mjs".into(),
        syntax: ModuleSyntax::EsModule,
        source: "export const x = 1;".into(),
        imports: vec![],
        exports: vec![ExportEntry::direct("x", "x")],
        has_default_export: false,
        has_top_level_await: false,
    };
    let json = serde_json::to_string(&sm).unwrap();
    let back: SpecimenModule = serde_json::from_str(&json).unwrap();
    assert_eq!(sm, back);
}

// ── InteropSpecimen serde ───────────────────────────────────────────────

#[test]
fn interop_specimen_serde_roundtrip() {
    let specimen = InteropSpecimen {
        specimen_id: "test-001".into(),
        description: "test specimen".into(),
        family: InteropFamily::EsmOnly,
        modules: vec![SpecimenModule {
            specifier: "entry.mjs".into(),
            syntax: ModuleSyntax::EsModule,
            source: "export const x = 1;".into(),
            imports: vec![],
            exports: vec![ExportEntry::direct("x", "x")],
            has_default_export: false,
            has_top_level_await: false,
        }],
        entry_point: "entry.mjs".into(),
        expected_outcome: InteropExpectedOutcome::Success,
        expected_linked_count: Some(1),
        expected_binding_states: vec![ExpectedBindingState {
            module_specifier: "entry.mjs".into(),
            export_name: "x".into(),
            expected_state: BindingCellState::Initialized,
        }],
        expected_async_phases: vec![],
    };
    let json = serde_json::to_string(&specimen).unwrap();
    let back: InteropSpecimen = serde_json::from_str(&json).unwrap();
    assert_eq!(specimen, back);
}

// ── Evidence types serde ────────────────────────────────────────────────

#[test]
fn binding_verdict_serde_roundtrip() {
    let bv = BindingVerdict {
        module_specifier: "mod.mjs".into(),
        export_name: "x".into(),
        expected_state: BindingCellState::Initialized,
        actual_state: BindingCellState::Initialized,
        pass: true,
    };
    let json = serde_json::to_string(&bv).unwrap();
    let back: BindingVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(bv, back);
}

#[test]
fn async_phase_verdict_serde_roundtrip() {
    let apv = AsyncPhaseVerdict {
        module_specifier: "async.mjs".into(),
        expected_phase: AsyncModulePhase::Settled,
        actual_phase: AsyncModulePhase::Settled,
        pass: true,
    };
    let json = serde_json::to_string(&apv).unwrap();
    let back: AsyncPhaseVerdict = serde_json::from_str(&json).unwrap();
    assert_eq!(apv, back);
}

#[test]
fn remediation_guidance_serde_roundtrip() {
    let rg = InteropRemediationGuidance {
        guidance_code: "test_code".into(),
        message: "fix this".into(),
    };
    let json = serde_json::to_string(&rg).unwrap();
    let back: InteropRemediationGuidance = serde_json::from_str(&json).unwrap();
    assert_eq!(rg, back);
}

#[test]
fn specimen_evidence_serde_roundtrip() {
    let ev = InteropSpecimenEvidence {
        specimen_id: "test-001".into(),
        family: InteropFamily::MixedGraph,
        expected_outcome: InteropExpectedOutcome::Success,
        actual_outcome: InteropActualOutcome::Success,
        verdict: InteropVerdict::Pass,
        compatibility_disposition: InteropCompatibilityDisposition::Supported,
        remediation_guidance: InteropRemediationGuidance {
            guidance_code: "none".into(),
            message: "ok".into(),
        },
        module_count: 3,
        linked_count: 3,
        cycle_count: 0,
        binding_verdicts: vec![],
        async_phase_verdicts: vec![],
        error_detail: None,
        evidence_hash: Some("abc123".into()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: InteropSpecimenEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

// ── Artifact types serde ────────────────────────────────────────────────

#[test]
fn artifact_paths_serde_roundtrip() {
    let paths = InteropParityArtifactPaths {
        evidence_inventory: "/a.json".into(),
        run_manifest: "/b.json".into(),
        events_jsonl: "/c.jsonl".into(),
        commands_txt: "/d.txt".into(),
    };
    let json = serde_json::to_string(&paths).unwrap();
    let back: InteropParityArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(paths, back);
}

#[test]
fn event_serde_roundtrip() {
    let event = InteropParityEvent {
        schema_version: INTEROP_PARITY_EVENT_SCHEMA_VERSION.to_string(),
        component: INTEROP_PARITY_COMPONENT.to_string(),
        event: "test_event".into(),
        policy_id: INTEROP_PARITY_POLICY_ID.to_string(),
        specimen_id: Some("s1".into()),
        verdict: Some("pass".into()),
        detail: Some("ok".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: InteropParityEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn run_manifest_serde_roundtrip() {
    let manifest = InteropParityRunManifest {
        schema_version: "v1".into(),
        component: "test".into(),
        trace_id: "t1".into(),
        decision_id: "d1".into(),
        policy_id: "p1".into(),
        inventory_hash: "h1".into(),
        specimen_count: 10,
        pass_count: 8,
        fail_count: 2,
        supported_count: 6,
        degraded_count: 1,
        unsupported_count: 3,
        contract_satisfied: false,
        artifact_paths: InteropParityArtifactPaths {
            evidence_inventory: "a".into(),
            run_manifest: "b".into(),
            events_jsonl: "c".into(),
            commands_txt: "d".into(),
        },
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: InteropParityRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

// ── Corpus invariants ───────────────────────────────────────────────────

#[test]
fn corpus_specimen_ids_unique() {
    let corpus = interop_parity_corpus();
    let mut ids = BTreeSet::new();
    for s in &corpus {
        assert!(ids.insert(&s.specimen_id), "duplicate: {}", s.specimen_id);
    }
}

#[test]
fn corpus_all_families_represented() {
    let corpus = interop_parity_corpus();
    let families: BTreeSet<_> = corpus.iter().map(|s| s.family).collect();
    for fam in InteropFamily::ALL {
        assert!(families.contains(fam), "missing family: {}", fam.as_str());
    }
}

#[test]
fn corpus_every_specimen_has_entry_point_in_modules() {
    let corpus = interop_parity_corpus();
    for s in &corpus {
        assert!(
            s.modules.iter().any(|m| m.specifier == s.entry_point),
            "specimen {} entry_point {} not in modules",
            s.specimen_id,
            s.entry_point
        );
    }
}

#[test]
fn corpus_every_specimen_has_nonempty_description() {
    let corpus = interop_parity_corpus();
    for s in &corpus {
        assert!(
            !s.description.is_empty(),
            "specimen {} has empty description",
            s.specimen_id
        );
    }
}

#[test]
fn corpus_modules_have_valid_syntax() {
    let corpus = interop_parity_corpus();
    for s in &corpus {
        for m in &s.modules {
            let json = serde_json::to_string(&m.syntax).unwrap();
            let _: ModuleSyntax = serde_json::from_str(&json).unwrap();
        }
    }
}

// ── Corpus run and inventory ────────────────────────────────────────────

#[test]
fn corpus_contract_satisfied() {
    let inventory = run_interop_parity_corpus();
    assert!(
        inventory.contract_satisfied(),
        "fail_count={}",
        inventory.fail_count
    );
}

#[test]
fn corpus_counts_consistent() {
    let inventory = run_interop_parity_corpus();
    assert_eq!(
        inventory.specimen_count,
        inventory.pass_count + inventory.fail_count
    );
    assert_eq!(inventory.specimen_count, inventory.evidence.len() as u64);
    assert_eq!(
        inventory.specimen_count,
        inventory.supported_count + inventory.degraded_count + inventory.unsupported_count
    );
}

#[test]
fn corpus_run_deterministic() {
    let inv1 = run_interop_parity_corpus();
    let inv2 = run_interop_parity_corpus();
    assert_eq!(inv1.pass_count, inv2.pass_count);
    assert_eq!(inv1.fail_count, inv2.fail_count);
    assert_eq!(inv1.specimen_count, inv2.specimen_count);
}

#[test]
fn corpus_family_coverage_complete() {
    let inventory = run_interop_parity_corpus();
    for fam in InteropFamily::ALL {
        assert!(
            inventory.family_coverage.contains_key(fam.as_str()),
            "missing coverage for {}",
            fam.as_str()
        );
    }
}

#[test]
fn corpus_has_esm_cjs_and_mixed_specimens() {
    let inventory = run_interop_parity_corpus();
    assert!(inventory.esm_only_count > 0, "no ESM-only specimens");
    assert!(inventory.cjs_only_count > 0, "no CJS-only specimens");
    assert!(inventory.mixed_count > 0, "no mixed specimens");
}

#[test]
fn corpus_syntax_count_adds_up() {
    let inventory = run_interop_parity_corpus();
    assert_eq!(
        inventory.esm_only_count + inventory.cjs_only_count + inventory.mixed_count,
        inventory.specimen_count
    );
}

// ── Inventory serde ─────────────────────────────────────────────────────

#[test]
fn inventory_serde_roundtrip() {
    let inventory = run_interop_parity_corpus();
    let json = serde_json::to_string(&inventory).unwrap();
    let back: InteropParityInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inventory, back);
}

// ── Evidence hash populated ─────────────────────────────────────────────

#[test]
fn evidence_hashes_populated_and_unique() {
    let inventory = run_interop_parity_corpus();
    let mut hashes = BTreeSet::new();
    for ev in &inventory.evidence {
        let hash = ev
            .evidence_hash
            .as_ref()
            .expect("evidence_hash should be Some");
        assert!(!hash.is_empty());
        hashes.insert(hash.clone());
    }
    // Most hashes should be unique (different specimens produce different evidence)
    assert!(hashes.len() > 1, "too few unique hashes");
}

// ── Specimen categories ─────────────────────────────────────────────────

#[test]
fn corpus_has_cycle_detection_specimens() {
    let corpus = interop_parity_corpus();
    let cycle_specimens: Vec<_> = corpus
        .iter()
        .filter(|s| s.expected_outcome == InteropExpectedOutcome::CycleDetected)
        .collect();
    assert!(
        cycle_specimens.len() >= 2,
        "need at least 2 cycle specimens"
    );
}

#[test]
fn corpus_has_eval_failure_specimen() {
    let corpus = interop_parity_corpus();
    let eval_fail: Vec<_> = corpus
        .iter()
        .filter(|s| s.expected_outcome == InteropExpectedOutcome::EvalFailure)
        .collect();
    assert!(
        !eval_fail.is_empty(),
        "need at least 1 eval failure specimen"
    );
}

#[test]
fn corpus_has_async_phase_expectations() {
    let corpus = interop_parity_corpus();
    let with_async: Vec<_> = corpus
        .iter()
        .filter(|s| !s.expected_async_phases.is_empty())
        .collect();
    assert!(
        with_async.len() >= 2,
        "need at least 2 specimens with async expectations"
    );
}

// ── Expected binding/async types serde ──────────────────────────────────

#[test]
fn expected_binding_state_serde_roundtrip() {
    let ebs = ExpectedBindingState {
        module_specifier: "mod.mjs".into(),
        export_name: "val".into(),
        expected_state: BindingCellState::Dead,
    };
    let json = serde_json::to_string(&ebs).unwrap();
    let back: ExpectedBindingState = serde_json::from_str(&json).unwrap();
    assert_eq!(ebs, back);
}

#[test]
fn expected_async_phase_serde_roundtrip() {
    let eap = ExpectedAsyncPhase {
        module_specifier: "async.mjs".into(),
        expected_phase: AsyncModulePhase::Rejected,
    };
    let json = serde_json::to_string(&eap).unwrap();
    let back: ExpectedAsyncPhase = serde_json::from_str(&json).unwrap();
    assert_eq!(eap, back);
}
