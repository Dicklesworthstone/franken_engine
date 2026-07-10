#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::data_contract::{
    DATA_CONTRACT_SCHEMA_VERSION, DEFAULT_DATA_CONTRACT_PURPOSE, DataBinding, DataBindingRole,
    DataContract, DataContractError, E8_REFUSAL_LEDGER_SCHEMA_VERSION, E8AdversarialRefusalFixture,
    E8RefusalEvidenceRef, E8RefusalSourceRef, RequestedOutputClaim, RequiredDeclassificationRoute,
    SinkBinding,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ifc_artifacts::{ClearanceClass, DeclassificationRoute, Label};

fn sample_run_input_hash() -> ContentHash {
    ContentHash::compute(b"console.log('integration-e8')")
}

fn sample_contract() -> DataContract {
    let run_input_hash = sample_run_input_hash();
    DataContract {
        schema_version: DATA_CONTRACT_SCHEMA_VERSION.to_string(),
        contract_id: "contract-integration-e8".to_string(),
        extension_id: "ext-integration-e8".to_string(),
        input_bindings: vec![
            DataBinding {
                binding_id: "run-source".to_string(),
                object_ref: "object://run-source".to_string(),
                path: Some("fixtures/agent.js".to_string()),
                label: Label::Public,
                owner: "runtime".to_string(),
                role: DataBindingRole::RunInput,
                allowed_purposes: BTreeSet::from([DEFAULT_DATA_CONTRACT_PURPOSE.to_string()]),
                content_hash_hex: Some(run_input_hash.to_hex()),
            },
            DataBinding {
                binding_id: "customer-pii".to_string(),
                object_ref: "dataset://customer-pii".to_string(),
                path: None,
                label: Label::Secret,
                owner: "data-owner".to_string(),
                role: DataBindingRole::SensitiveInput,
                allowed_purposes: BTreeSet::from([DEFAULT_DATA_CONTRACT_PURPOSE.to_string()]),
                content_hash_hex: Some("ab".repeat(32)),
            },
        ],
        allowed_purposes: BTreeSet::from([DEFAULT_DATA_CONTRACT_PURPOSE.to_string()]),
        allowed_capabilities: BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
            RuntimeCapability::FsRead,
        ]),
        allowed_sinks: vec![SinkBinding {
            sink_id: "audit-log".to_string(),
            clearance: ClearanceClass::AuditedSink,
            location: "ledger://audit".to_string(),
            allowed_labels: BTreeSet::from([Label::Public, Label::Internal, Label::Confidential]),
        }],
        required_declassification_routes: vec![RequiredDeclassificationRoute {
            route: DeclassificationRoute {
                route_id: "route-secret-audit".to_string(),
                source_label: Label::Secret,
                target_clearance: Label::Confidential,
                conditions: vec!["receipt_required".to_string()],
            },
            required_for_claims: BTreeSet::from(["no-secret-open-sink".to_string()]),
        }],
        requested_output_claims: vec![
            RequestedOutputClaim::NoFlow {
                claim_id: "no-secret-open-sink".to_string(),
                source_label: Label::Secret,
                sink_clearance: ClearanceClass::OpenSink,
            },
            RequestedOutputClaim::OutputIndependentOf {
                claim_id: "output-independent-of-pii".to_string(),
                binding_id: "customer-pii".to_string(),
            },
            RequestedOutputClaim::CapabilityNotUsed {
                claim_id: "no-network-egress".to_string(),
                capability: RuntimeCapability::NetworkEgress,
            },
        ],
        metadata: BTreeMap::from([("bead".to_string(), "bd-fqlfw.8.1".to_string())]),
    }
}

fn bind_sample_contract() -> frankenengine_engine::data_contract::DataContractRunBinding {
    sample_contract()
        .bind_to_run(
            "ext-integration-e8",
            "fixtures/agent.js",
            DEFAULT_DATA_CONTRACT_PURPOSE,
            Some(&sample_run_input_hash()),
        )
        .expect("contract should bind")
}

#[allow(clippy::too_many_arguments)]
fn adversarial_fixture(
    fixture_id: &str,
    scenario: &str,
    code: &str,
    class: &str,
    surface: &str,
    path: &str,
    symbol: &str,
    span: Option<&str>,
    evidence_kind: &str,
    evidence_status: &str,
    remediation: &str,
) -> E8AdversarialRefusalFixture {
    E8AdversarialRefusalFixture {
        fixture_id: fixture_id.to_string(),
        scenario: scenario.to_string(),
        code: code.to_string(),
        class: class.to_string(),
        source_ref: E8RefusalSourceRef {
            id: format!("{fixture_id}-source"),
            surface: surface.to_string(),
            path: path.to_string(),
            symbol: Some(symbol.to_string()),
            span: span.map(str::to_string),
        },
        evidence_ref: E8RefusalEvidenceRef {
            id: format!("{fixture_id}-evidence"),
            kind: evidence_kind.to_string(),
            status: evidence_status.to_string(),
            artifact_path: Some(format!(
                "scripts/testdata/e8_refusal_ledger/{fixture_id}.json"
            )),
            content_hash_hex: None,
        },
        remediation: remediation.to_string(),
    }
}

#[test]
fn data_contract_round_trips_and_binds_to_run() {
    let contract = sample_contract();
    let json = serde_json::to_string_pretty(&contract).expect("serialize contract");
    let parsed: DataContract = serde_json::from_str(&json).expect("parse contract");

    let bound = parsed
        .bind_to_run(
            "ext-integration-e8",
            "fixtures/agent.js",
            DEFAULT_DATA_CONTRACT_PURPOSE,
            Some(&sample_run_input_hash()),
        )
        .expect("contract should bind");

    assert_eq!(bound.contract_id, "contract-integration-e8");
    assert_eq!(bound.run_input_binding_id, "run-source");
    assert_eq!(bound.requested_claim_count, 3);
    assert_eq!(bound.allowed_capability_count, 4);
    assert_eq!(bound.contract_hash_hex.len(), 64);
}

#[test]
fn data_contract_binding_emits_uncertified_e8_preflight_receipt() {
    let bound = sample_contract()
        .bind_to_run(
            "ext-integration-e8",
            "fixtures/agent.js",
            DEFAULT_DATA_CONTRACT_PURPOSE,
            Some(&sample_run_input_hash()),
        )
        .expect("contract should bind");

    let receipt = bound
        .uncertified_preflight_receipt("frankenctl-run-integration", Some("agent.explain.json"));

    assert_eq!(receipt.schema_version, E8_REFUSAL_LEDGER_SCHEMA_VERSION);
    assert_eq!(receipt.run_id, "frankenctl-run-integration");
    assert_eq!(receipt.contract_id, "contract-integration-e8");
    assert_eq!(receipt.result_class, "uncertified");
    assert!(!receipt.certifier_input_allowed);
    assert!(!receipt.positive_non_use_claim_allowed);
    assert!(receipt.must_block_certificate);
    assert!(receipt.refusal_codes.iter().any(|code| {
        code.code == "missing_flow_proof_obligation"
            && code.class == "missing_evidence"
            && code.source_ref_id == "flow-proof-obligation"
    }));
    assert!(receipt.evidence_refs.iter().any(|evidence| {
        evidence.id == "run-explain-bundle"
            && evidence.status == "present"
            && evidence.artifact_path.as_deref() == Some("agent.explain.json")
    }));
    assert!(
        !receipt
            .refusal_codes
            .iter()
            .any(|code| { code.code == "missing_explain_or_replay_bundle" })
    );
}

#[test]
fn e8_preflight_ledger_id_changes_when_contract_content_changes() {
    let first_contract = sample_contract();
    let mut second_contract = sample_contract();
    second_contract.metadata.insert(
        "review_epoch".to_string(),
        "different-contract-content".to_string(),
    );

    let first_binding = first_contract
        .bind_to_run(
            "ext-integration-e8",
            "fixtures/agent.js",
            DEFAULT_DATA_CONTRACT_PURPOSE,
            Some(&sample_run_input_hash()),
        )
        .expect("first contract should bind");
    let second_binding = second_contract
        .bind_to_run(
            "ext-integration-e8",
            "fixtures/agent.js",
            DEFAULT_DATA_CONTRACT_PURPOSE,
            Some(&sample_run_input_hash()),
        )
        .expect("second contract should bind");

    assert_ne!(
        first_binding.contract_hash_hex, second_binding.contract_hash_hex,
        "metadata changes must be reflected in the bound contract hash"
    );

    let first_receipt =
        first_binding.uncertified_preflight_receipt("same-run-id", Some("same.explain.json"));
    let second_receipt =
        second_binding.uncertified_preflight_receipt("same-run-id", Some("same.explain.json"));

    assert_ne!(
        first_receipt.ledger_id, second_receipt.ledger_id,
        "ledger ids must bind to the exact data-contract content, not only stable ids"
    );
}

#[test]
fn e8_preflight_ledger_id_changes_when_run_input_content_changes() {
    let mut contract = sample_contract();
    contract.input_bindings[0].content_hash_hex = None;

    let first_run_input_hash = ContentHash::compute(b"console.log('first-run-input')");
    let second_run_input_hash = ContentHash::compute(b"console.log('second-run-input')");

    let first_binding = contract
        .bind_to_run(
            "ext-integration-e8",
            "fixtures/agent.js",
            DEFAULT_DATA_CONTRACT_PURPOSE,
            Some(&first_run_input_hash),
        )
        .expect("first run input should bind");
    let second_binding = contract
        .bind_to_run(
            "ext-integration-e8",
            "fixtures/agent.js",
            DEFAULT_DATA_CONTRACT_PURPOSE,
            Some(&second_run_input_hash),
        )
        .expect("second run input should bind");

    assert_eq!(
        first_binding.contract_hash_hex, second_binding.contract_hash_hex,
        "contract content is identical; only the actual run-input hash differs"
    );
    assert_ne!(
        first_binding.run_input_content_hash_hex, second_binding.run_input_content_hash_hex,
        "bindings must retain the actual run-input content hash even when undeclared"
    );

    let first_receipt =
        first_binding.uncertified_preflight_receipt("same-run-id", Some("same.explain.json"));
    let second_receipt =
        second_binding.uncertified_preflight_receipt("same-run-id", Some("same.explain.json"));

    assert_ne!(
        first_receipt.ledger_id, second_receipt.ledger_id,
        "ledger ids must bind to the actual run-input content hash"
    );
}

#[test]
fn data_contract_preflight_without_explain_bundle_fails_closed() {
    let bound = sample_contract()
        .bind_to_run(
            "ext-integration-e8",
            "fixtures/agent.js",
            DEFAULT_DATA_CONTRACT_PURPOSE,
            Some(&sample_run_input_hash()),
        )
        .expect("contract should bind");

    let receipt = bound.uncertified_preflight_receipt("frankenctl-run-no-explain", None);

    assert!(receipt.must_block_certificate);
    assert!(receipt.refusal_codes.iter().any(|code| {
        code.code == "missing_explain_or_replay_bundle"
            && code.class == "missing_evidence"
            && code.source_ref_id == "frankenctl-run-explain"
    }));
    assert!(receipt.evidence_refs.iter().any(|evidence| {
        evidence.id == "run-explain-bundle"
            && evidence.status == "missing"
            && evidence.artifact_path.is_none()
    }));
    assert!(
        receipt
            .remediation_actions
            .iter()
            .any(|action| action.contains("--explain"))
    );
}

#[test]
fn adversarial_unsupported_surface_fixtures_refuse_e8_certification() {
    let bound = bind_sample_contract();
    let fixtures = vec![
        adversarial_fixture(
            "secret-to-open-sink-unsupported-syntax",
            "Secret-labeled input reaches an open sink through parser syntax E8 cannot analyze",
            "unsupported_syntax_surface",
            "uncertified",
            "parser_unsupported_diagnostics",
            "crates/franken-engine/src/parser.rs",
            "Parser::parse_statement",
            Some("fixtures/e8/secret_to_open_sink_unsupported.js:1:12"),
            "adversarial_source_fixture",
            "unsupported",
            "reduce the program or add analyzed parser support before certifying",
        ),
        adversarial_fixture(
            "secret-to-open-sink-unproven-ifc",
            "Secret-labeled value flows through an intrinsic with no linked label-propagation proof",
            "unproven_ifc_propagation",
            "uncertified",
            "runtime_ifc_labeling",
            "crates/franken-engine/src/baseline_interpreter.rs",
            "Array.prototype.map",
            Some("fixtures/e8/secret_to_open_sink_unproven_ifc.js:3:7"),
            "ifc_propagation_proof",
            "missing",
            "add IFC propagation proof or keep the scenario uncertified",
        ),
        adversarial_fixture(
            "secret-to-open-sink-missing-provenance",
            "Secret-to-sink refusal lacks a precise source span and must remain degraded",
            "missing_source_span",
            "degraded",
            "runtime_explain_bundle",
            "crates/franken-engine/src/runtime_explain_bundle.rs",
            "RuntimeExplainBundle",
            None,
            "source_provenance",
            "degraded",
            "thread parser/lowering source span provenance into the receipt",
        ),
        adversarial_fixture(
            "secret-to-open-sink-missing-declassification",
            "Secret-to-open-sink flow needs declassification but no signed receipt is linked",
            "missing_declassification_receipt",
            "fail_closed",
            "declassification_receipt",
            "crates/franken-engine/src/flow_envelope.rs",
            "FlowProofObligation",
            Some("fixtures/e8/secret_to_open_sink_missing_declass.js:2:3"),
            "declassification_receipt",
            "missing",
            "add a signed declassification receipt or deny the claim",
        ),
    ];

    let receipt = bound.uncertified_preflight_receipt_with_adversarial_fixtures(
        "frankenctl-run-adversarial-e8",
        Some("adversarial.explain.json"),
        &fixtures,
    );

    assert_eq!(receipt.result_class, "fail_closed");
    assert!(!receipt.certifier_input_allowed);
    assert!(!receipt.positive_non_use_claim_allowed);
    assert!(receipt.must_block_certificate);
    assert!(receipt.degraded_surface_count >= 1);

    for (code, class) in [
        ("unsupported_syntax_surface", "uncertified"),
        ("unproven_ifc_propagation", "uncertified"),
        ("missing_source_span", "degraded"),
        ("missing_declassification_receipt", "fail_closed"),
    ] {
        assert!(receipt.refusal_codes.iter().any(|refusal| {
            refusal.code == code
                && refusal.class == class
                && receipt
                    .source_refs
                    .iter()
                    .any(|source| source.id == refusal.source_ref_id)
        }));
    }

    assert!(receipt.refusal_codes.iter().any(|refusal| {
        refusal.code == "unsupported_syntax_surface"
            && refusal.source_ref_id == "secret-to-open-sink-unsupported-syntax-source"
    }));
    assert!(receipt.source_refs.iter().any(|source| {
        source.id == "secret-to-open-sink-missing-provenance-source" && source.span.is_none()
    }));
    assert!(receipt.evidence_refs.iter().any(|evidence| {
        evidence.id == "secret-to-open-sink-unproven-ifc-evidence"
            && evidence.kind == "ifc_propagation_proof"
            && evidence.status == "missing"
    }));
    assert!(receipt.evidence_refs.iter().any(|evidence| {
        evidence.id == "secret-to-open-sink-missing-declassification-evidence"
            && evidence.kind == "declassification_receipt"
            && evidence.status == "missing"
    }));
    assert!(
        receipt
            .remediation_actions
            .iter()
            .any(|action| action.contains("secret-to-open-sink-unsupported-syntax"))
    );
}

#[test]
fn missing_and_ambiguous_run_bindings_fail_closed() {
    let contract = sample_contract();
    let missing = contract
        .bind_to_run(
            "ext-integration-e8",
            "fixtures/other.js",
            DEFAULT_DATA_CONTRACT_PURPOSE,
            Some(&sample_run_input_hash()),
        )
        .expect_err("missing input path must fail");
    assert!(matches!(
        missing,
        DataContractError::MissingRunInputBinding { .. }
    ));

    let mut ambiguous = sample_contract();
    let mut duplicate = ambiguous.input_bindings[0].clone();
    duplicate.binding_id = "run-source-duplicate".to_string();
    ambiguous.input_bindings.push(duplicate);
    let error = ambiguous
        .bind_to_run(
            "ext-integration-e8",
            "fixtures/agent.js",
            DEFAULT_DATA_CONTRACT_PURPOSE,
            Some(&sample_run_input_hash()),
        )
        .expect_err("ambiguous input path must fail");
    assert!(matches!(
        error,
        DataContractError::AmbiguousRunInputBinding { count: 2, .. }
    ));
}

#[test]
fn run_input_hash_mismatch_fails_closed() {
    let contract = sample_contract();
    let error = contract
        .bind_to_run(
            "ext-integration-e8",
            "fixtures/agent.js",
            DEFAULT_DATA_CONTRACT_PURPOSE,
            Some(&ContentHash::compute(b"different source")),
        )
        .expect_err("run input hash mismatch must fail");
    assert!(matches!(
        error,
        DataContractError::RunInputContentHashMismatch { .. }
    ));
}

#[test]
fn invalid_references_fail_closed() {
    let mut unknown_claim = sample_contract();
    unknown_claim.required_declassification_routes[0]
        .required_for_claims
        .insert("missing-claim".to_string());
    let error = unknown_claim
        .validate()
        .expect_err("unknown route claim reference must fail");
    assert!(matches!(error, DataContractError::UnknownClaimRef { .. }));

    let mut unknown_binding = sample_contract();
    unknown_binding
        .requested_output_claims
        .push(RequestedOutputClaim::OutputIndependentOf {
            claim_id: "unknown-binding-claim".to_string(),
            binding_id: "missing-binding".to_string(),
        });
    let error = unknown_binding
        .validate()
        .expect_err("unknown binding reference must fail");
    assert!(matches!(error, DataContractError::UnknownBindingRef { .. }));
}

#[test]
fn duplicate_declassification_route_ids_fail_closed() {
    let mut contract = sample_contract();
    contract
        .required_declassification_routes
        .push(RequiredDeclassificationRoute {
            route: DeclassificationRoute {
                route_id: "route-secret-audit".to_string(),
                source_label: Label::Secret,
                target_clearance: Label::Internal,
                conditions: vec!["owner_approval".to_string()],
            },
            required_for_claims: BTreeSet::from(["output-independent-of-pii".to_string()]),
        });

    let error = contract
        .validate()
        .expect_err("duplicate declassification route ids must fail closed");
    assert!(matches!(
        error,
        DataContractError::DuplicateId {
            field: "required_declassification_routes[].route.route_id",
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// bd-fqlfw.8.2 (E8.T2): runtime label-ingress + purpose-metadata binding.
// ---------------------------------------------------------------------------

use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorError,
};
use frankenengine_engine::ifc_provenance_index::FlowDecision;

const INGRESS_SOURCE: &str = "const answer = 40 + 2;";

fn ingress_contract(source_label: Label, sink: SinkBinding) -> DataContract {
    let mut contract = sample_contract();
    contract.contract_id = "contract-ingress-e8t2".to_string();
    contract.input_bindings[0].label = source_label;
    contract.input_bindings[0].content_hash_hex =
        Some(ContentHash::compute(INGRESS_SOURCE.as_bytes()).to_hex());
    contract.allowed_sinks = vec![sink];
    contract
}

fn ingress_orchestrator(contract: &DataContract) -> ExecutionOrchestrator {
    let binding = contract
        .bind_to_run(
            "ext-integration-e8",
            "fixtures/agent.js",
            DEFAULT_DATA_CONTRACT_PURPOSE,
            Some(&ContentHash::compute(INGRESS_SOURCE.as_bytes())),
        )
        .expect("contract binds to run");
    let ingress = contract
        .ifc_ingress(&binding)
        .expect("ingress binding derives");
    assert_eq!(ingress.purpose, DEFAULT_DATA_CONTRACT_PURPOSE);
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_data_contract_ingress(ingress);
    orchestrator
}

fn ingress_package() -> ExtensionPackage {
    ExtensionPackage {
        extension_id: "ext-integration-e8".to_string(),
        source: INGRESS_SOURCE.to_string(),
        source_file: Some("fixtures/agent.js".to_string()),
        capabilities: vec![],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    }
}

/// ACCEPTANCE (bd-fqlfw.8.2): a labeled secret flowing to an egress sink
/// without a receipt is denied AND recorded as a flow edge.
#[test]
fn labeled_secret_to_egress_sink_without_receipt_is_denied_and_recorded() {
    let contract = ingress_contract(
        Label::Secret,
        SinkBinding {
            sink_id: "raw-network-egress".to_string(),
            clearance: ClearanceClass::NeverSink,
            location: "net://egress".to_string(),
            allowed_labels: BTreeSet::from([Label::Public]),
        },
    );
    let mut orchestrator = ingress_orchestrator(&contract);

    let err = orchestrator
        .execute(&ingress_package())
        .expect_err("secret ingress to a public egress sink must fail closed");
    match &err {
        OrchestratorError::IfcRuntimeGuardBlocked { detail } => {
            assert!(detail.contains("raw-network-egress"), "detail: {detail}");
            assert!(detail.contains("Secret"), "detail: {detail}");
        }
        other => panic!("expected IfcRuntimeGuardBlocked, got {other:?}"),
    }

    let events = orchestrator.data_contract_flow_events();
    assert_eq!(events.len(), 1, "one declared sink => one flow edge");
    assert_eq!(events[0].decision, FlowDecision::Blocked);
    assert_eq!(events[0].source_label, Label::Secret);
    assert_eq!(events[0].receipt_ref, None);
    assert!(events[0].flow_location.contains("raw-network-egress"));
    assert!(
        events[0]
            .flow_location
            .contains(DEFAULT_DATA_CONTRACT_PURPOSE),
        "purpose metadata must be bound into the flow edge: {}",
        events[0].flow_location
    );
}

/// A declassification route without a verified receipt still fails closed,
/// and the denial names the route so the operator knows what is missing.
#[test]
fn secret_with_unreceipted_declassification_route_is_denied_naming_the_route() {
    let mut contract = ingress_contract(
        Label::Secret,
        SinkBinding {
            sink_id: "public-report".to_string(),
            clearance: ClearanceClass::OpenSink,
            location: "report://public".to_string(),
            allowed_labels: BTreeSet::from([Label::Public]),
        },
    );
    contract.required_declassification_routes = vec![RequiredDeclassificationRoute {
        route: DeclassificationRoute {
            route_id: "route-secret-public".to_string(),
            source_label: Label::Secret,
            target_clearance: Label::Public,
            conditions: vec!["receipt_required".to_string()],
        },
        required_for_claims: BTreeSet::from(["no-secret-open-sink".to_string()]),
    }];
    let mut orchestrator = ingress_orchestrator(&contract);

    let err = orchestrator
        .execute(&ingress_package())
        .expect_err("route without receipt must fail closed");
    match &err {
        OrchestratorError::IfcRuntimeGuardBlocked { detail } => {
            assert!(detail.contains("route-secret-public"), "detail: {detail}");
        }
        other => panic!("expected IfcRuntimeGuardBlocked, got {other:?}"),
    }
    assert_eq!(
        orchestrator.data_contract_flow_events()[0].decision,
        FlowDecision::Blocked
    );
}

/// A lattice-legal flow (public input to an audited sink that allows Public)
/// executes and records an Allowed edge — denial-only recording would make
/// the provenance index useless for use-certificates.
#[test]
fn public_input_to_audited_sink_executes_and_records_allowed_edge() {
    let contract = ingress_contract(
        Label::Public,
        SinkBinding {
            sink_id: "audit-log".to_string(),
            clearance: ClearanceClass::AuditedSink,
            location: "ledger://audit".to_string(),
            allowed_labels: BTreeSet::from([Label::Public, Label::Internal]),
        },
    );
    let mut orchestrator = ingress_orchestrator(&contract);

    let result = orchestrator
        .execute(&ingress_package())
        .expect("lattice-legal ingress must execute");
    assert_eq!(result.extension_id, "ext-integration-e8");

    let events = orchestrator.data_contract_flow_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].decision, FlowDecision::Allowed);
    assert_eq!(events[0].source_label, Label::Public);
}

/// Runs without a data contract record no ingress edges (no phantom flows).
#[test]
fn run_without_contract_records_no_ingress_edges() {
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator
        .execute(&ingress_package())
        .expect("uncontracted run executes");
    assert!(orchestrator.data_contract_flow_events().is_empty());
}
