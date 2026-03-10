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
use std::{fs, path::PathBuf};

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::EffectBoundary;
use frankenengine_engine::semantic_contract_baseline::{
    LOCAL_SEMANTIC_ATLAS_BEAD_ID, LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_CONTEXT_ASSUMPTIONS,
    LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_FIXTURE_LINK, LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_TRACE_LINK,
    LOCAL_SEMANTIC_ATLAS_SCHEMA_VERSION, LocalSemanticAtlas, LocalSemanticAtlasInput,
    SemanticContractVersion,
};
use frankenengine_engine::static_analysis_graph::{
    CapabilityBoundary, ComponentDescriptor, ComponentId, EffectClassification,
    HookKind as GraphHookKind, HookSlot,
};
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn make_component(component_id: &str) -> ComponentDescriptor {
    let mut direct_capabilities = BTreeSet::new();
    direct_capabilities.insert("dom.mutate".to_string());

    ComponentDescriptor {
        id: ComponentId::new(component_id),
        is_function_component: true,
        module_path: format!("src/{component_id}.tsx"),
        export_name: Some(component_id.to_string()),
        hook_slots: vec![HookSlot {
            slot_index: 0,
            kind: GraphHookKind::Effect,
            label: "useEffect(sync)".to_string(),
            dependency_count: Some(1),
            has_cleanup: true,
            source_offset: 0,
            dependency_hash: None,
        }],
        props: BTreeMap::new(),
        consumed_contexts: vec!["AuthContext".to_string()],
        provided_contexts: Vec::new(),
        capability_boundary: CapabilityBoundary {
            direct_capabilities,
            transitive_capabilities: BTreeSet::new(),
            render_effect: EffectBoundary::Pure,
            hook_effects: vec![EffectClassification {
                boundary: EffectBoundary::WriteEffect,
                required_capabilities: {
                    let mut caps = BTreeSet::new();
                    caps.insert("dom.mutate".to_string());
                    caps
                },
                idempotent: true,
                commutative: false,
                estimated_cost_millionths: 10_000,
            }],
            is_boundary: true,
            boundary_tags: Vec::new(),
        },
        is_pure: false,
        content_hash: ContentHash::compute(component_id.as_bytes()),
        children: Vec::new(),
    }
}

#[test]
fn frx_local_semantic_atlas_doc_contains_required_sections() {
    let path = repo_root().join("docs/FRX_LOCAL_SEMANTIC_ATLAS_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# FRX Local Semantic Atlas v1",
        "## Scope",
        "## Local Atlas Entry Contract",
        "## Fixture and Trace Linkage",
        "## Blocking Quality Debt Policy",
        "## Deterministic Replay",
        "## Evidence Pack",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "local semantic atlas doc missing section: {section}"
        );
    }
}

#[test]
fn frx_local_semantic_atlas_contract_is_machine_readable_and_fail_closed() {
    let path = repo_root().join("docs/frx_local_semantic_atlas_v1.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let value: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    assert_eq!(
        value["schema_version"].as_str(),
        Some("frx.local-semantic-atlas.contract.v1")
    );
    assert_eq!(
        value["generated_by"].as_str(),
        Some(LOCAL_SEMANTIC_ATLAS_BEAD_ID)
    );
    assert_eq!(
        value["primary_bead"].as_str(),
        Some(LOCAL_SEMANTIC_ATLAS_BEAD_ID)
    );
    assert_eq!(value["track"]["id"].as_str(), Some("FRX-14.1"));
    assert_eq!(
        value["failure_policy"]["mode"].as_str(),
        Some("fail_closed")
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_fixture_trace_linkage"].as_bool(),
        Some(true)
    );
    assert_eq!(
        value["activation_gate"]["block_on_missing_local_assumptions"].as_bool(),
        Some(true)
    );
}

#[test]
fn local_semantic_atlas_public_api_surfaces_blocking_debt() {
    let atlas = LocalSemanticAtlas::from_inputs(
        SemanticContractVersion::CURRENT,
        7,
        vec![LocalSemanticAtlasInput {
            component: make_component("UserPanel"),
            fixture_refs: Vec::new(),
            trace_refs: Vec::new(),
            assumption_keys: Vec::new(),
        }],
    );

    assert_eq!(atlas.schema_version, LOCAL_SEMANTIC_ATLAS_SCHEMA_VERSION);
    assert_eq!(atlas.blocking_debt_count(), 3);
    assert!(!atlas.validate().is_valid);
}

#[test]
fn frx_local_semantic_atlas_readme_gate_instructions_present() {
    let path = repo_root().join("README.md");
    let readme = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    assert!(
        readme.contains("## FRX Local Semantic Atlas Gate"),
        "README missing local semantic atlas gate heading"
    );
    assert!(
        readme.contains("./scripts/run_frx_local_semantic_atlas_suite.sh ci"),
        "README missing local semantic atlas gate command"
    );
    assert!(
        readme.contains("./scripts/e2e/frx_local_semantic_atlas_replay.sh"),
        "README missing local semantic atlas replay command"
    );
}

// ---------- atlas construction ----------

#[test]
fn atlas_with_valid_refs_has_no_blocking_debt() {
    let atlas = LocalSemanticAtlas::from_inputs(
        SemanticContractVersion::CURRENT,
        10,
        vec![LocalSemanticAtlasInput {
            component: make_component("ValidPanel"),
            fixture_refs: vec!["fixture-1".to_string()],
            trace_refs: vec!["trace-1".to_string()],
            assumption_keys: vec!["AuthContext".to_string()],
        }],
    );
    assert_eq!(atlas.blocking_debt_count(), 0);
    assert!(atlas.validate().is_valid);
}

#[test]
fn atlas_entry_lookup_by_component_id() {
    let atlas = LocalSemanticAtlas::from_inputs(
        SemanticContractVersion::CURRENT,
        11,
        vec![
            LocalSemanticAtlasInput {
                component: make_component("CompA"),
                fixture_refs: vec!["f1".to_string()],
                trace_refs: vec!["t1".to_string()],
                assumption_keys: vec!["AuthContext".to_string()],
            },
            LocalSemanticAtlasInput {
                component: make_component("CompB"),
                fixture_refs: vec!["f2".to_string()],
                trace_refs: vec!["t2".to_string()],
                assumption_keys: vec!["AuthContext".to_string()],
            },
        ],
    );
    assert!(atlas.entry("CompA").is_some());
    assert!(atlas.entry("CompB").is_some());
    assert!(atlas.entry("CompC").is_none());
}

#[test]
fn atlas_entry_has_correct_module_path() {
    let atlas = LocalSemanticAtlas::from_inputs(
        SemanticContractVersion::CURRENT,
        12,
        vec![LocalSemanticAtlasInput {
            component: make_component("Dashboard"),
            fixture_refs: vec!["f".to_string()],
            trace_refs: vec!["t".to_string()],
            assumption_keys: vec!["AuthContext".to_string()],
        }],
    );
    let entry = atlas.entry("Dashboard").expect("entry exists");
    assert_eq!(entry.module_path, "src/Dashboard.tsx");
    assert_eq!(entry.export_name, Some("Dashboard".to_string()));
}

#[test]
fn atlas_entry_captures_hook_and_effect_signatures() {
    let atlas = LocalSemanticAtlas::from_inputs(
        SemanticContractVersion::CURRENT,
        13,
        vec![LocalSemanticAtlasInput {
            component: make_component("HookPanel"),
            fixture_refs: vec!["f".to_string()],
            trace_refs: vec!["t".to_string()],
            assumption_keys: vec!["AuthContext".to_string()],
        }],
    );
    let entry = atlas.entry("HookPanel").expect("entry exists");
    assert!(
        !entry.hook_signature.is_empty(),
        "hook signature should be populated from hook_slots"
    );
    assert!(
        !entry.effect_signature.is_empty(),
        "effect signature should be populated from hook_effects"
    );
}

#[test]
fn atlas_entry_captures_consumed_contexts() {
    let atlas = LocalSemanticAtlas::from_inputs(
        SemanticContractVersion::CURRENT,
        14,
        vec![LocalSemanticAtlasInput {
            component: make_component("CtxPanel"),
            fixture_refs: vec!["f".to_string()],
            trace_refs: vec!["t".to_string()],
            assumption_keys: vec!["AuthContext".to_string()],
        }],
    );
    let entry = atlas.entry("CtxPanel").expect("entry exists");
    assert!(entry.required_contexts.contains(&"AuthContext".to_string()));
}

#[test]
fn atlas_empty_inputs_creates_empty_atlas() {
    let atlas = LocalSemanticAtlas::from_inputs(SemanticContractVersion::CURRENT, 15, Vec::new());
    assert_eq!(atlas.entries.len(), 0);
    assert_eq!(atlas.blocking_debt_count(), 0);
}

#[test]
fn atlas_hash_is_deterministic() {
    let inputs = || {
        vec![LocalSemanticAtlasInput {
            component: make_component("DetPanel"),
            fixture_refs: vec!["f".to_string()],
            trace_refs: vec!["t".to_string()],
            assumption_keys: vec!["AuthContext".to_string()],
        }]
    };
    let a = LocalSemanticAtlas::from_inputs(SemanticContractVersion::CURRENT, 20, inputs());
    let b = LocalSemanticAtlas::from_inputs(SemanticContractVersion::CURRENT, 20, inputs());
    assert_eq!(a.atlas_hash, b.atlas_hash);
}

#[test]
fn atlas_generated_epoch_preserved() {
    let atlas = LocalSemanticAtlas::from_inputs(
        SemanticContractVersion::CURRENT,
        42,
        vec![LocalSemanticAtlasInput {
            component: make_component("EpochPanel"),
            fixture_refs: vec!["f".to_string()],
            trace_refs: vec!["t".to_string()],
            assumption_keys: vec!["AuthContext".to_string()],
        }],
    );
    assert_eq!(atlas.generated_epoch, 42);
}

#[test]
fn atlas_bead_id_matches_constant() {
    let atlas = LocalSemanticAtlas::from_inputs(SemanticContractVersion::CURRENT, 1, Vec::new());
    assert_eq!(atlas.bead_id, LOCAL_SEMANTIC_ATLAS_BEAD_ID);
}

#[test]
fn atlas_validate_reports_entry_count() {
    let atlas = LocalSemanticAtlas::from_inputs(
        SemanticContractVersion::CURRENT,
        1,
        vec![
            LocalSemanticAtlasInput {
                component: make_component("A"),
                fixture_refs: vec!["f".to_string()],
                trace_refs: vec!["t".to_string()],
                assumption_keys: vec!["AuthContext".to_string()],
            },
            LocalSemanticAtlasInput {
                component: make_component("B"),
                fixture_refs: vec!["f".to_string()],
                trace_refs: vec!["t".to_string()],
                assumption_keys: vec!["AuthContext".to_string()],
            },
        ],
    );
    let validation = atlas.validate();
    assert_eq!(validation.entry_count, 2);
    assert!(validation.is_valid);
}

#[test]
fn atlas_validate_reports_blocking_and_total_debt() {
    let atlas = LocalSemanticAtlas::from_inputs(
        SemanticContractVersion::CURRENT,
        1,
        vec![LocalSemanticAtlasInput {
            component: make_component("DebtPanel"),
            fixture_refs: Vec::new(),
            trace_refs: Vec::new(),
            assumption_keys: Vec::new(),
        }],
    );
    let v = atlas.validate();
    assert!(!v.is_valid);
    assert!(v.blocking_debt_count > 0);
    assert!(v.total_debt_count >= v.blocking_debt_count);
}

#[test]
fn atlas_debt_codes_present_in_quality_debt() {
    let atlas = LocalSemanticAtlas::from_inputs(
        SemanticContractVersion::CURRENT,
        1,
        vec![LocalSemanticAtlasInput {
            component: make_component("AllDebt"),
            fixture_refs: Vec::new(),
            trace_refs: Vec::new(),
            assumption_keys: Vec::new(),
        }],
    );
    let codes: BTreeSet<&str> = atlas
        .quality_debt
        .iter()
        .map(|d| d.debt_code.as_str())
        .collect();
    assert!(codes.contains(LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_FIXTURE_LINK));
    assert!(codes.contains(LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_TRACE_LINK));
    assert!(codes.contains(LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_CONTEXT_ASSUMPTIONS));
}

#[test]
fn atlas_entry_content_hash_is_deterministic() {
    let make = || {
        LocalSemanticAtlas::from_inputs(
            SemanticContractVersion::CURRENT,
            1,
            vec![LocalSemanticAtlasInput {
                component: make_component("HashPanel"),
                fixture_refs: vec!["f".to_string()],
                trace_refs: vec!["t".to_string()],
                assumption_keys: vec!["AuthContext".to_string()],
            }],
        )
    };
    let a = make();
    let b = make();
    let entry_a = a.entry("HashPanel").expect("entry a");
    let entry_b = b.entry("HashPanel").expect("entry b");
    assert_eq!(entry_a.content_hash, entry_b.content_hash);
}

#[test]
fn atlas_entry_captures_capability_requirements() {
    let atlas = LocalSemanticAtlas::from_inputs(
        SemanticContractVersion::CURRENT,
        1,
        vec![LocalSemanticAtlasInput {
            component: make_component("CapPanel"),
            fixture_refs: vec!["f".to_string()],
            trace_refs: vec!["t".to_string()],
            assumption_keys: vec!["AuthContext".to_string()],
        }],
    );
    let entry = atlas.entry("CapPanel").expect("entry");
    assert!(
        entry
            .capability_requirements
            .contains(&"dom.mutate".to_string())
    );
}

// ---------- doc and script existence ----------

#[test]
fn frx_local_semantic_atlas_gate_script_exists() {
    let path = repo_root().join("scripts/run_frx_local_semantic_atlas_suite.sh");
    assert!(
        path.exists(),
        "gate runner script must exist: {}",
        path.display()
    );
}

#[test]
fn frx_local_semantic_atlas_replay_script_exists() {
    let path = repo_root().join("scripts/e2e/frx_local_semantic_atlas_replay.sh");
    assert!(
        path.exists(),
        "replay script must exist: {}",
        path.display()
    );
}

// ---------- serde roundtrip ----------

#[test]
fn local_semantic_atlas_serde_roundtrip() {
    let atlas = LocalSemanticAtlas::from_inputs(
        SemanticContractVersion::CURRENT,
        50,
        vec![LocalSemanticAtlasInput {
            component: make_component("SerdePanel"),
            fixture_refs: vec!["f".to_string()],
            trace_refs: vec!["t".to_string()],
            assumption_keys: vec!["AuthContext".to_string()],
        }],
    );
    let json = serde_json::to_string(&atlas).expect("serialize");
    let recovered: LocalSemanticAtlas = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.schema_version, atlas.schema_version);
    assert_eq!(recovered.generated_epoch, atlas.generated_epoch);
    assert_eq!(recovered.entries.len(), atlas.entries.len());
    assert_eq!(recovered.atlas_hash, atlas.atlas_hash);
}

#[test]
fn semantic_contract_version_serde_roundtrip() {
    let v = SemanticContractVersion::CURRENT;
    let json = serde_json::to_string(&v).expect("serialize");
    let recovered: SemanticContractVersion = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered, v);
}

#[test]
fn semantic_contract_version_display() {
    assert_eq!(SemanticContractVersion::CURRENT.to_string(), "0.1.0");
}

#[test]
fn semantic_contract_version_compatibility() {
    let v0_1 = SemanticContractVersion::CURRENT;
    let v0_2 = SemanticContractVersion {
        major: 0,
        minor: 2,
        patch: 0,
    };
    assert!(v0_2.is_compatible_with(&v0_1));
    assert!(!v0_1.is_compatible_with(&v0_2));
}

#[test]
fn atlas_input_serde_roundtrip() {
    let input = LocalSemanticAtlasInput {
        component: make_component("InputPanel"),
        fixture_refs: vec!["fix-1".to_string()],
        trace_refs: vec!["trace-1".to_string()],
        assumption_keys: vec!["AuthContext".to_string()],
    };
    let json = serde_json::to_string(&input).expect("serialize");
    let recovered: LocalSemanticAtlasInput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.component.id, input.component.id);
}

// ---------- validation ----------

#[test]
fn atlas_validate_warnings_empty_for_valid() {
    let atlas = LocalSemanticAtlas::from_inputs(
        SemanticContractVersion::CURRENT,
        1,
        vec![LocalSemanticAtlasInput {
            component: make_component("OkPanel"),
            fixture_refs: vec!["f".to_string()],
            trace_refs: vec!["t".to_string()],
            assumption_keys: vec!["AuthContext".to_string()],
        }],
    );
    let v = atlas.validate();
    assert!(v.warnings.is_empty());
}

#[test]
fn atlas_validate_empty_atlas_warns() {
    let atlas = LocalSemanticAtlas::from_inputs(SemanticContractVersion::CURRENT, 1, Vec::new());
    let v = atlas.validate();
    // Empty atlas has no blocking debt but may warn about no entries
    assert_eq!(v.entry_count, 0);
}

// ---------- debt ----------

#[test]
fn atlas_debt_missing_only_fixture_link() {
    let atlas = LocalSemanticAtlas::from_inputs(
        SemanticContractVersion::CURRENT,
        1,
        vec![LocalSemanticAtlasInput {
            component: make_component("NoFixture"),
            fixture_refs: Vec::new(),
            trace_refs: vec!["t".to_string()],
            assumption_keys: vec!["AuthContext".to_string()],
        }],
    );
    let codes: BTreeSet<&str> = atlas
        .quality_debt
        .iter()
        .map(|d| d.debt_code.as_str())
        .collect();
    assert!(codes.contains(LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_FIXTURE_LINK));
    assert!(!codes.contains(LOCAL_SEMANTIC_ATLAS_DEBT_MISSING_TRACE_LINK));
}

#[test]
fn atlas_debt_all_blocking() {
    let atlas = LocalSemanticAtlas::from_inputs(
        SemanticContractVersion::CURRENT,
        1,
        vec![LocalSemanticAtlasInput {
            component: make_component("AllDebtBlocking"),
            fixture_refs: Vec::new(),
            trace_refs: Vec::new(),
            assumption_keys: Vec::new(),
        }],
    );
    for debt in &atlas.quality_debt {
        assert!(debt.blocking, "debt {} should be blocking", debt.debt_code);
    }
}

// ---------- hash determinism ----------

#[test]
fn atlas_hash_changes_with_different_epoch() {
    let inputs = || {
        vec![LocalSemanticAtlasInput {
            component: make_component("EpochDiffPanel"),
            fixture_refs: vec!["f".to_string()],
            trace_refs: vec!["t".to_string()],
            assumption_keys: vec!["AuthContext".to_string()],
        }]
    };
    let a = LocalSemanticAtlas::from_inputs(SemanticContractVersion::CURRENT, 1, inputs());
    let b = LocalSemanticAtlas::from_inputs(SemanticContractVersion::CURRENT, 2, inputs());
    assert_ne!(a.atlas_hash, b.atlas_hash);
}

// ---------- entry provided_contexts ----------

#[test]
fn atlas_entry_provided_contexts_from_component() {
    let mut comp = make_component("ProviderPanel");
    comp.provided_contexts = vec!["ThemeContext".to_string()];
    let atlas = LocalSemanticAtlas::from_inputs(
        SemanticContractVersion::CURRENT,
        1,
        vec![LocalSemanticAtlasInput {
            component: comp,
            fixture_refs: vec!["f".to_string()],
            trace_refs: vec!["t".to_string()],
            assumption_keys: vec!["AuthContext".to_string()],
        }],
    );
    let entry = atlas.entry("ProviderPanel").expect("entry");
    assert!(
        entry
            .provided_contexts
            .contains(&"ThemeContext".to_string())
    );
}
