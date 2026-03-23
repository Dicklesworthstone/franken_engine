//! Enrichment integration tests for `esm_cjs_interop_parity`.
//!
//! Covers: exhaustive enum serde/display, specimen/evidence serde roundtrips,
//! corpus invariants, family coverage, inventory determinism, compatibility
//! disposition classification, remediation guidance, binding/async verdicts,
//! and artifact type serde.

use std::collections::BTreeSet;

use frankenengine_engine::esm_cjs_interop_parity::{
    AsyncPhaseVerdict, BindingVerdict, ExpectedAsyncPhase, ExpectedBindingState,
    INTEROP_PARITY_COMPONENT, INTEROP_PARITY_EVENT_SCHEMA_VERSION,
    INTEROP_PARITY_MANIFEST_SCHEMA_VERSION, INTEROP_PARITY_POLICY_ID,
    INTEROP_PARITY_SCHEMA_VERSION, InteropActualOutcome, InteropCompatibilityDisposition,
    InteropExpectedOutcome, InteropFamily, InteropParityArtifactPaths, InteropParityEvent,
    InteropParityInventory, InteropParityRunManifest, InteropRemediationGuidance, InteropSpecimen,
    InteropSpecimenEvidence, InteropVerdict, SpecimenModule, interop_parity_corpus,
    run_interop_parity_corpus, write_interop_parity_bundle,
};
use frankenengine_engine::esm_loader::ExportEntry;
use frankenengine_engine::module_async_evaluation::AsyncModulePhase;
use frankenengine_engine::module_compatibility_matrix::CompatibilityMode;
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
        compatibility_mode: CompatibilityMode::Native,
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
        compatibility_mode: Some(CompatibilityMode::BunCompat),
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
fn corpus_contract_not_satisfied_when_live_evidence_hash_missing() {
    let mut inventory = run_interop_parity_corpus();
    inventory.evidence[0].evidence_hash = None;
    assert!(!inventory.contract_satisfied());
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

#[test]
fn corpus_inventory_carries_external_package_root_relative_requires_in_all_modes() {
    let inventory = run_interop_parity_corpus();
    let exact_specimen_ids = BTreeSet::from([
        "external_extension_probe_package_root_require_native",
        "external_extension_probe_package_root_require_node_compat",
        "external_extension_probe_package_root_require_bun_compat",
        "scoped_external_extension_probe_package_root_require_native",
        "scoped_external_extension_probe_package_root_require_node_compat",
        "scoped_external_extension_probe_package_root_require_bun_compat",
    ]);
    let actual: BTreeSet<(String, String)> = inventory
        .evidence
        .iter()
        .filter(|evidence| exact_specimen_ids.contains(evidence.specimen_id.as_str()))
        .map(|evidence| {
            (
                evidence.specimen_id.clone(),
                evidence.compatibility_mode.as_str().to_string(),
            )
        })
        .collect();
    let expected = BTreeSet::from([
        (
            "external_extension_probe_package_root_require_native".to_string(),
            "native".to_string(),
        ),
        (
            "external_extension_probe_package_root_require_node_compat".to_string(),
            "node_compat".to_string(),
        ),
        (
            "external_extension_probe_package_root_require_bun_compat".to_string(),
            "bun_compat".to_string(),
        ),
        (
            "scoped_external_extension_probe_package_root_require_native".to_string(),
            "native".to_string(),
        ),
        (
            "scoped_external_extension_probe_package_root_require_node_compat".to_string(),
            "node_compat".to_string(),
        ),
        (
            "scoped_external_extension_probe_package_root_require_bun_compat".to_string(),
            "bun_compat".to_string(),
        ),
    ]);
    assert_eq!(actual, expected);
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

// ── Manifest schema version constant ────────────────────────────────────

#[test]
fn manifest_schema_version_nonempty_and_distinct() {
    assert!(!INTEROP_PARITY_MANIFEST_SCHEMA_VERSION.is_empty());
    assert_ne!(
        INTEROP_PARITY_MANIFEST_SCHEMA_VERSION,
        INTEROP_PARITY_SCHEMA_VERSION
    );
    assert!(INTEROP_PARITY_MANIFEST_SCHEMA_VERSION.contains("manifest"));
}

// ── Clone independence ──────────────────────────────────────────────────

#[test]
fn interop_specimen_clone_independence() {
    let specimen = InteropSpecimen {
        specimen_id: "clone-test".into(),
        description: "clone independence".into(),
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
        expected_binding_states: vec![],
        expected_async_phases: vec![],
    };
    let mut cloned = specimen.clone();
    cloned.specimen_id = "mutated".into();
    cloned.description = "changed description".into();
    assert_eq!(specimen.specimen_id, "clone-test");
    assert_eq!(specimen.description, "clone independence");
    assert_ne!(specimen.specimen_id, cloned.specimen_id);
}

#[test]
fn specimen_evidence_clone_independence() {
    let ev = InteropSpecimenEvidence {
        specimen_id: "ev-clone".into(),
        family: InteropFamily::CjsOnly,
        compatibility_mode: CompatibilityMode::Native,
        expected_outcome: InteropExpectedOutcome::Success,
        actual_outcome: InteropActualOutcome::Success,
        verdict: InteropVerdict::Pass,
        compatibility_disposition: InteropCompatibilityDisposition::Supported,
        remediation_guidance: InteropRemediationGuidance {
            guidance_code: "none".into(),
            message: "ok".into(),
        },
        module_count: 1,
        linked_count: 1,
        cycle_count: 0,
        binding_verdicts: vec![],
        async_phase_verdicts: vec![],
        error_detail: None,
        evidence_hash: Some("hash123".into()),
    };
    let mut cloned = ev.clone();
    cloned.specimen_id = "mutated-ev".into();
    cloned.evidence_hash = Some("changed".into());
    assert_eq!(ev.specimen_id, "ev-clone");
    assert_eq!(ev.evidence_hash.as_deref(), Some("hash123"));
    assert_ne!(ev.specimen_id, cloned.specimen_id);
}

#[test]
fn inventory_clone_independence() {
    let inv = run_interop_parity_corpus();
    let mut cloned = inv.clone();
    cloned.pass_count = 0;
    cloned.fail_count = 999;
    assert_ne!(inv.pass_count, cloned.pass_count);
    assert_ne!(inv.fail_count, cloned.fail_count);
    assert_eq!(inv, run_interop_parity_corpus());
}

// ── Debug distinctness for enums ────────────────────────────────────────

#[test]
fn actual_outcome_debug_variants_distinct() {
    let variants = [
        InteropActualOutcome::Success,
        InteropActualOutcome::LinkFailure,
        InteropActualOutcome::EvalFailure,
        InteropActualOutcome::CycleDetected,
        InteropActualOutcome::GraphConstructionFailure,
    ];
    let mut debugs = BTreeSet::new();
    for v in &variants {
        let dbg = format!("{v:?}");
        assert!(!dbg.is_empty());
        assert!(debugs.insert(dbg.clone()), "duplicate debug: {dbg}");
    }
    assert_eq!(debugs.len(), 5);
}

#[test]
fn expected_outcome_debug_variants_distinct() {
    let variants = [
        InteropExpectedOutcome::Success,
        InteropExpectedOutcome::LinkFailure,
        InteropExpectedOutcome::EvalFailure,
        InteropExpectedOutcome::CycleDetected,
    ];
    let mut debugs = BTreeSet::new();
    for v in &variants {
        let dbg = format!("{v:?}");
        assert!(!dbg.is_empty());
        assert!(debugs.insert(dbg.clone()), "duplicate debug: {dbg}");
    }
    assert_eq!(debugs.len(), 4);
}

#[test]
fn verdict_debug_variants_distinct() {
    let pass_dbg = format!("{:?}", InteropVerdict::Pass);
    let fail_dbg = format!("{:?}", InteropVerdict::Fail);
    assert_ne!(pass_dbg, fail_dbg);
    assert!(!pass_dbg.is_empty());
    assert!(!fail_dbg.is_empty());
}

// ── contract_satisfied boundary tests ───────────────────────────────────

#[test]
fn contract_satisfied_false_when_zero_specimens() {
    let inv = InteropParityInventory {
        schema_version: "v1".into(),
        component: "test".into(),
        specimen_count: 0,
        pass_count: 0,
        fail_count: 0,
        supported_count: 0,
        degraded_count: 0,
        unsupported_count: 0,
        family_coverage: std::collections::BTreeMap::new(),
        esm_only_count: 0,
        cjs_only_count: 0,
        mixed_count: 0,
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

#[test]
fn contract_satisfied_false_with_failures() {
    let inv = InteropParityInventory {
        schema_version: "v1".into(),
        component: "test".into(),
        specimen_count: 3,
        pass_count: 2,
        fail_count: 1,
        supported_count: 2,
        degraded_count: 0,
        unsupported_count: 1,
        family_coverage: std::collections::BTreeMap::new(),
        esm_only_count: 1,
        cjs_only_count: 1,
        mixed_count: 1,
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

// ── Corpus evidence verdict consistency ─────────────────────────────────

#[test]
fn evidence_verdicts_all_pass() {
    let inventory = run_interop_parity_corpus();
    for ev in &inventory.evidence {
        assert_eq!(
            ev.verdict,
            InteropVerdict::Pass,
            "specimen {} unexpectedly failed",
            ev.specimen_id
        );
    }
}

// ── Corpus specimen_id non-empty ────────────────────────────────────────

#[test]
fn corpus_specimen_ids_nonempty() {
    let corpus = interop_parity_corpus();
    for s in &corpus {
        assert!(!s.specimen_id.is_empty(), "empty specimen_id found");
        assert!(
            !s.specimen_id.contains(' '),
            "specimen_id '{}' contains spaces",
            s.specimen_id
        );
    }
}

// ── Family coverage counts sum ──────────────────────────────────────────

#[test]
fn family_coverage_counts_sum_to_specimen_count() {
    let inventory = run_interop_parity_corpus();
    let sum: u64 = inventory.family_coverage.values().sum();
    assert_eq!(
        sum, inventory.specimen_count,
        "family coverage sum {sum} != specimen_count {}",
        inventory.specimen_count
    );
}

// ── Inventory schema fields correct ─────────────────────────────────────

#[test]
fn inventory_schema_fields_match_constants() {
    let inventory = run_interop_parity_corpus();
    assert_eq!(inventory.schema_version, INTEROP_PARITY_SCHEMA_VERSION);
    assert_eq!(inventory.component, INTEROP_PARITY_COMPONENT);
}

#[test]
fn evidence_hash_changes_when_error_detail_changes() {
    let base = InteropSpecimenEvidence {
        specimen_id: "hash_mutation_case".into(),
        family: InteropFamily::MixedGraph,
        compatibility_mode: CompatibilityMode::Native,
        expected_outcome: InteropExpectedOutcome::Success,
        actual_outcome: InteropActualOutcome::Success,
        verdict: InteropVerdict::Pass,
        compatibility_disposition: InteropCompatibilityDisposition::Supported,
        remediation_guidance: InteropRemediationGuidance {
            guidance_code: "no_remediation_required".into(),
            message: "baseline".into(),
        },
        module_count: 2,
        linked_count: 2,
        cycle_count: 0,
        binding_verdicts: vec![],
        async_phase_verdicts: vec![],
        error_detail: None,
        evidence_hash: None,
    };
    let mut mutated = base.clone();
    mutated.error_detail = Some("ERR_REQUIRE_ESM".into());

    assert_ne!(base.compute_hash(), mutated.compute_hash());
}

#[test]
fn evidence_hash_changes_when_binding_verdict_changes() {
    let base = InteropSpecimenEvidence {
        specimen_id: "binding_hash_case".into(),
        family: InteropFamily::LiveBinding,
        compatibility_mode: CompatibilityMode::BunCompat,
        expected_outcome: InteropExpectedOutcome::Success,
        actual_outcome: InteropActualOutcome::Success,
        verdict: InteropVerdict::Pass,
        compatibility_disposition: InteropCompatibilityDisposition::Supported,
        remediation_guidance: InteropRemediationGuidance {
            guidance_code: "no_remediation_required".into(),
            message: "baseline".into(),
        },
        module_count: 2,
        linked_count: 2,
        cycle_count: 0,
        binding_verdicts: vec![BindingVerdict {
            module_specifier: "dep.mjs".into(),
            export_name: "value".into(),
            expected_state: BindingCellState::Initialized,
            actual_state: BindingCellState::Initialized,
            pass: true,
        }],
        async_phase_verdicts: vec![AsyncPhaseVerdict {
            module_specifier: "entry.mjs".into(),
            expected_phase: AsyncModulePhase::Synchronous,
            actual_phase: AsyncModulePhase::Synchronous,
            pass: true,
        }],
        error_detail: None,
        evidence_hash: None,
    };
    let mut mutated = base.clone();
    mutated.binding_verdicts[0].actual_state = BindingCellState::Uninitialized;
    mutated.binding_verdicts[0].pass = false;

    assert_ne!(base.compute_hash(), mutated.compute_hash());
}

// ── write_interop_parity_bundle produces files ──────────────────────────

#[test]
fn write_bundle_creates_all_artifacts() {
    let dir = std::env::temp_dir().join("esm_cjs_interop_parity_bundle_test");
    let _ = std::fs::remove_dir_all(&dir);
    let commands = vec!["cargo test".to_string(), "echo done".to_string()];
    let artifacts = write_interop_parity_bundle(&dir, &commands).unwrap();
    assert!(artifacts.inventory_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
    assert!(!artifacts.inventory_hash.is_empty());

    // Verify inventory file can be deserialized
    let inv_json = std::fs::read_to_string(&artifacts.inventory_path).unwrap();
    let inv: InteropParityInventory = serde_json::from_str(&inv_json).unwrap();
    assert!(inv.contract_satisfied());

    // Verify manifest file can be deserialized
    let manifest_json = std::fs::read_to_string(&artifacts.run_manifest_path).unwrap();
    let manifest: InteropParityRunManifest = serde_json::from_str(&manifest_json).unwrap();
    assert_eq!(manifest.policy_id, INTEROP_PARITY_POLICY_ID);
    assert_eq!(
        manifest.schema_version,
        INTEROP_PARITY_MANIFEST_SCHEMA_VERSION
    );
    assert!(manifest.contract_satisfied);

    // Verify events JSONL has at least start + specimens + end
    let events_text = std::fs::read_to_string(&artifacts.events_path).unwrap();
    let event_lines: Vec<&str> = events_text.lines().collect();
    assert!(
        event_lines.len() >= 3,
        "need at least start + 1 specimen + end events"
    );
    // Parse each line as a valid event
    for line in &event_lines {
        let _: InteropParityEvent = serde_json::from_str(line).unwrap();
    }

    // Verify commands file
    let commands_text = std::fs::read_to_string(&artifacts.commands_path).unwrap();
    assert!(commands_text.contains("cargo test"));
    assert!(commands_text.contains("echo done"));

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
}

// ── Corpus expected_linked_count invariants ─────────────────────────────

#[test]
fn corpus_success_specimens_have_linked_count() {
    let corpus = interop_parity_corpus();
    for s in &corpus {
        if s.expected_outcome == InteropExpectedOutcome::Success {
            assert!(
                s.expected_linked_count.is_some(),
                "specimen {} expects success but has no expected_linked_count",
                s.specimen_id
            );
            let count = s.expected_linked_count.unwrap();
            assert!(
                count >= 1,
                "specimen {} expected_linked_count is 0",
                s.specimen_id
            );
            assert!(
                count as usize <= s.modules.len(),
                "specimen {} expected_linked_count {} exceeds module count {}",
                s.specimen_id,
                count,
                s.modules.len()
            );
        }
    }
}
