#![forbid(unsafe_code)]

use std::{
    any::type_name,
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::PathBuf,
};

use frankenengine_extension_host::{
    BudgetExhaustionPolicy, CURRENT_ENGINE_VERSION, CancellationConfig, Capability,
    CapabilityEscrowGateway, DEFAULT_TERMINATION_GRACE_PERIOD_NS, DelegateCellFactory,
    ExtensionHostConfig, ExtensionLifecycleManager, ExtensionManifest, ExtensionState, FlowLabel,
    HostcallDispatcher, HostcallSinkPolicy, LifecycleTransition, MAX_DELEGATE_LIFETIME_NS,
    MAX_NAME_LEN, ManifestValidationContext, ResourceBudget, allowed_lifecycle_transitions,
    compute_content_hash, lifecycle_target_state, validate_manifest,
    validate_manifest_with_context, with_computed_content_hash,
};
use serde::{Deserialize, Serialize};

const CONTRACT_SCHEMA_VERSION: &str = "franken-engine.extension-host.root-contract.v1";
const CONTRACT_POLICY_ID: &str = "policy-rgc-920b-extension-host-root-contract-v1";
const CONTRACT_JSON: &str = include_str!("../../../docs/extension_host_root_contract_v1.json");
const COMPONENT: &str = "extension_host_root_contract_test";
const TRACE_ID: &str = "trace-extension-host-root-contract-test";
const DECISION_ID: &str = "decision-extension-host-root-contract-test";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExtensionHostRootContract {
    schema_version: String,
    bead_id: String,
    policy_id: String,
    crate_name: String,
    root_contract: RootContract,
    validation: ValidationContract,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RootContract {
    variant: String,
    rationale: String,
    placeholder_symbols_forbidden: Vec<String>,
    required_public_constants: Vec<String>,
    required_public_functions: Vec<String>,
    required_public_types: Vec<String>,
    root_categories: Vec<RootCategory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RootCategory {
    id: String,
    description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ValidationContract {
    source_file: String,
    contract_test: String,
    runner: String,
    replay: String,
    artifact_files: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ValidationReport {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    outcome: String,
    error_code: Option<String>,
    contract_variant: String,
    placeholder_symbol_present: bool,
    required_items_checked: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SurfaceReport {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    outcome: String,
    error_code: Option<String>,
    contract_variant: String,
    total_public_items: usize,
    public_item_inventory: Vec<String>,
    required_public_constants: Vec<String>,
    required_public_functions: Vec<String>,
    required_public_types: Vec<String>,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_contract() -> ExtensionHostRootContract {
    serde_json::from_str(CONTRACT_JSON).expect("extension-host root contract json must parse")
}

fn validate_contract(contract: &ExtensionHostRootContract) -> Result<(), String> {
    if contract.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(format!(
            "unexpected schema_version: {}",
            contract.schema_version
        ));
    }
    if contract.policy_id != CONTRACT_POLICY_ID {
        return Err(format!("unexpected policy_id: {}", contract.policy_id));
    }
    if contract.crate_name != "frankenengine-extension-host" {
        return Err(format!("unexpected crate_name: {}", contract.crate_name));
    }
    if contract.root_contract.variant.trim().is_empty() {
        return Err("root contract variant must not be empty".to_string());
    }
    if !contract
        .root_contract
        .placeholder_symbols_forbidden
        .iter()
        .any(|symbol| symbol == "placeholder_extension_host_symbol")
    {
        return Err("placeholder symbol must stay explicitly forbidden".to_string());
    }
    if contract.root_contract.required_public_constants.is_empty()
        || contract.root_contract.required_public_functions.is_empty()
        || contract.root_contract.required_public_types.is_empty()
    {
        return Err("required public export lists must not be empty".to_string());
    }
    if contract.validation.artifact_files
        != vec![
            "extension_host_root_contract.json".to_string(),
            "extension_host_root_contract_validation_report.json".to_string(),
            "extension_host_root_surface_report.json".to_string(),
        ]
    {
        return Err("artifact file contract drifted".to_string());
    }
    Ok(())
}

fn identifier_prefix(token: &str) -> Option<String> {
    let ident: String = token
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect();
    if ident.is_empty() { None } else { Some(ident) }
}

fn public_root_inventory() -> Vec<String> {
    let source_path = repo_root().join("crates/franken-extension-host/src/lib.rs");
    let source = fs::read_to_string(&source_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", source_path.display()));
    let mut items = BTreeSet::new();

    for line in source.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("pub ") {
            continue;
        }

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        let candidate = match tokens.as_slice() {
            ["pub", "const", "fn", name, ..] => identifier_prefix(name),
            ["pub", "struct", name, ..]
            | ["pub", "enum", name, ..]
            | ["pub", "trait", name, ..]
            | ["pub", "fn", name, ..]
            | ["pub", "const", name, ..] => identifier_prefix(name),
            _ => None,
        };

        if let Some(name) = candidate {
            items.insert(name);
        }
    }

    items.into_iter().collect()
}

fn required_item_status(
    contract: &ExtensionHostRootContract,
    inventory: &[String],
) -> BTreeMap<String, bool> {
    let inventory_set: BTreeSet<&str> = inventory.iter().map(String::as_str).collect();
    contract
        .root_contract
        .required_public_constants
        .iter()
        .chain(contract.root_contract.required_public_functions.iter())
        .chain(contract.root_contract.required_public_types.iter())
        .map(|name| (name.clone(), inventory_set.contains(name.as_str())))
        .collect()
}

fn base_manifest() -> ExtensionManifest {
    ExtensionManifest {
        name: "root-contract-ext".to_string(),
        version: "1.0.0".to_string(),
        entrypoint: "dist/main.js".to_string(),
        capabilities: BTreeSet::from([Capability::FsRead]),
        publisher_signature: None,
        content_hash: [0; 32],
        trust_chain_ref: None,
        min_engine_version: CURRENT_ENGINE_VERSION.to_string(),
    }
}

fn artifact_dir() -> Option<PathBuf> {
    env::var("EXTENSION_HOST_ROOT_CONTRACT_ARTIFACT_DIR")
        .ok()
        .map(PathBuf::from)
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                repo_root().join(path)
            }
        })
}

fn write_contract_artifacts(contract: &ExtensionHostRootContract, inventory: &[String]) {
    let Some(dir) = artifact_dir() else {
        return;
    };

    fs::create_dir_all(&dir)
        .unwrap_or_else(|err| panic!("failed to create {}: {err}", dir.display()));

    let required_items_checked = required_item_status(contract, inventory);
    let placeholder_symbol_present = inventory
        .iter()
        .any(|item| item == "placeholder_extension_host_symbol");

    let validation_report = ValidationReport {
        schema_version: "franken-engine.extension-host.root-contract.validation-report.v1"
            .to_string(),
        trace_id: TRACE_ID.to_string(),
        decision_id: DECISION_ID.to_string(),
        policy_id: CONTRACT_POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event: "contract_validated".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        contract_variant: contract.root_contract.variant.clone(),
        placeholder_symbol_present,
        required_items_checked,
    };

    let surface_report = SurfaceReport {
        schema_version: "franken-engine.extension-host.root-contract.surface-report.v1".to_string(),
        trace_id: TRACE_ID.to_string(),
        decision_id: DECISION_ID.to_string(),
        policy_id: CONTRACT_POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event: "root_surface_inventory".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        contract_variant: contract.root_contract.variant.clone(),
        total_public_items: inventory.len(),
        public_item_inventory: inventory.to_vec(),
        required_public_constants: contract.root_contract.required_public_constants.clone(),
        required_public_functions: contract.root_contract.required_public_functions.clone(),
        required_public_types: contract.root_contract.required_public_types.clone(),
    };

    fs::write(
        dir.join("extension_host_root_contract.json"),
        serde_json::to_vec_pretty(contract)
            .expect("root contract should serialize for artifact output"),
    )
    .expect("write extension_host_root_contract.json");
    fs::write(
        dir.join("extension_host_root_contract_validation_report.json"),
        serde_json::to_vec_pretty(&validation_report)
            .expect("validation report should serialize for artifact output"),
    )
    .expect("write extension_host_root_contract_validation_report.json");
    fs::write(
        dir.join("extension_host_root_surface_report.json"),
        serde_json::to_vec_pretty(&surface_report)
            .expect("surface report should serialize for artifact output"),
    )
    .expect("write extension_host_root_surface_report.json");
}

#[test]
fn extension_host_root_contract_json_is_versioned_and_valid() {
    let contract = parse_contract();
    assert_eq!(validate_contract(&contract), Ok(()));
    assert_eq!(contract.bead_id, "bd-2muur.2.1");
    assert_eq!(
        contract.validation.source_file,
        "crates/franken-extension-host/src/lib.rs"
    );
    assert_eq!(
        contract.validation.contract_test,
        "crates/franken-extension-host/tests/root_contract.rs"
    );
}

#[test]
fn extension_host_root_contract_rejects_invalid_contract_state() {
    let mut contract = parse_contract();
    contract.root_contract.placeholder_symbols_forbidden.clear();
    assert!(
        validate_contract(&contract)
            .expect_err("invalid contract must fail")
            .contains("placeholder symbol"),
        "invalid contract should fail for missing forbidden placeholder symbol"
    );
}

#[test]
fn extension_host_root_required_exports_are_live_and_compilable() {
    let _constants = (
        CURRENT_ENGINE_VERSION,
        MAX_NAME_LEN,
        DEFAULT_TERMINATION_GRACE_PERIOD_NS,
        MAX_DELEGATE_LIFETIME_NS,
    );

    let manifest = with_computed_content_hash(base_manifest()).expect("computed content hash");
    assert_eq!(validate_manifest(&manifest), Ok(()));

    let context =
        ManifestValidationContext::new(TRACE_ID, DECISION_ID, CONTRACT_POLICY_ID, &manifest.name);
    let report = validate_manifest_with_context(&manifest, &context);
    assert_eq!(report.error, None);
    assert_eq!(report.event.outcome, "pass");
    assert_eq!(
        compute_content_hash(&manifest).expect("content hash").len(),
        32
    );

    assert_eq!(
        lifecycle_target_state(ExtensionState::Unloaded, LifecycleTransition::Validate),
        Some(ExtensionState::Validating)
    );
    assert_eq!(
        allowed_lifecycle_transitions(ExtensionState::Unloaded),
        &[LifecycleTransition::Validate]
    );

    let manager = ExtensionLifecycleManager::new(
        "root-contract-ext",
        ResourceBudget::new(1, 1, 1),
        BudgetExhaustionPolicy::Suspend,
        CancellationConfig::default(),
    );
    assert_eq!(manager.extension_id(), "root-contract-ext");

    let dispatcher = HostcallDispatcher::new(HostcallSinkPolicy::default());
    assert!(dispatcher.violation_events().is_empty());

    let _escrow_gateway = CapabilityEscrowGateway::default();
    let _delegate_factory = DelegateCellFactory::default();
    let _flow_label = FlowLabel::default();

    for exported_type in [
        type_name::<ExtensionHostConfig>(),
        type_name::<ExtensionManifest>(),
        type_name::<ManifestValidationContext<'static>>(),
        type_name::<ExtensionLifecycleManager>(),
        type_name::<FlowLabel>(),
        type_name::<HostcallDispatcher>(),
        type_name::<CapabilityEscrowGateway>(),
        type_name::<DelegateCellFactory>(),
    ] {
        assert!(
            exported_type.contains("frankenengine_extension_host"),
            "type should resolve from crate root: {exported_type}"
        );
    }
}

#[test]
fn extension_host_root_source_inventory_matches_contract() {
    let contract = parse_contract();
    let inventory = public_root_inventory();
    let status = required_item_status(&contract, &inventory);

    assert!(
        !inventory
            .iter()
            .any(|item| item == "placeholder_extension_host_symbol"),
        "placeholder symbol must not appear in the source inventory"
    );
    assert!(
        status.values().all(|present| *present),
        "all required contract items must be present in source inventory: {status:?}"
    );
}

#[test]
fn extension_host_root_contract_scenario_emits_artifact_bundle() {
    let contract = parse_contract();
    let inventory = public_root_inventory();

    assert_eq!(validate_contract(&contract), Ok(()));
    assert!(
        !inventory
            .iter()
            .any(|item| item == "placeholder_extension_host_symbol"),
        "placeholder symbol must stay absent before writing artifacts"
    );

    write_contract_artifacts(&contract, &inventory);

    if let Some(dir) = artifact_dir() {
        for artifact in [
            "extension_host_root_contract.json",
            "extension_host_root_contract_validation_report.json",
            "extension_host_root_surface_report.json",
        ] {
            assert!(
                dir.join(artifact).is_file(),
                "expected artifact missing: {}",
                dir.join(artifact).display()
            );
        }
    }
}
