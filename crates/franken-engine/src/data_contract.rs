//! Declarative data-contract input format for E8 non-use certificates.
//!
//! A data contract is the fail-closed wrapper around a `frankenctl run`: it
//! names the input data bindings, their labels and owners, the purposes for
//! which the run is allowed, the capability and sink envelope, and the output
//! claims the later certifier must prove.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::RuntimeCapability;
use crate::hash_tiers::ContentHash;
use crate::ifc_artifacts::{ClearanceClass, DeclassificationRoute, Label};

pub const DATA_CONTRACT_SCHEMA_VERSION: &str = "franken-engine.data-contract.v1";
pub const DEFAULT_DATA_CONTRACT_PURPOSE: &str = "runtime_execution";
pub const E8_REFUSAL_LEDGER_SCHEMA_VERSION: &str = "franken-engine.e8-refusal-ledger.v1";
pub const E8_REFUSAL_THREAT_MODEL_SCOPE: &str = "explicit_flow_ifc_v1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataBindingRole {
    RunInput,
    SensitiveInput,
    ReferenceDataset,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataBinding {
    pub binding_id: String,
    pub object_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub label: Label,
    pub owner: String,
    pub role: DataBindingRole,
    pub allowed_purposes: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SinkBinding {
    pub sink_id: String,
    pub clearance: ClearanceClass,
    pub location: String,
    pub allowed_labels: BTreeSet<Label>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredDeclassificationRoute {
    pub route: DeclassificationRoute,
    pub required_for_claims: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "claim_type", rename_all = "snake_case")]
pub enum RequestedOutputClaim {
    NoFlow {
        claim_id: String,
        source_label: Label,
        sink_clearance: ClearanceClass,
    },
    OutputIndependentOf {
        claim_id: String,
        binding_id: String,
    },
    CapabilityNotUsed {
        claim_id: String,
        capability: RuntimeCapability,
    },
}

impl RequestedOutputClaim {
    pub fn claim_id(&self) -> &str {
        match self {
            Self::NoFlow { claim_id, .. }
            | Self::OutputIndependentOf { claim_id, .. }
            | Self::CapabilityNotUsed { claim_id, .. } => claim_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataContract {
    pub schema_version: String,
    pub contract_id: String,
    pub extension_id: String,
    pub input_bindings: Vec<DataBinding>,
    pub allowed_purposes: BTreeSet<String>,
    pub allowed_capabilities: BTreeSet<RuntimeCapability>,
    pub allowed_sinks: Vec<SinkBinding>,
    #[serde(default)]
    pub required_declassification_routes: Vec<RequiredDeclassificationRoute>,
    pub requested_output_claims: Vec<RequestedOutputClaim>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DataContractRunBinding {
    pub schema_version: String,
    pub contract_id: String,
    pub contract_hash_hex: String,
    pub extension_id: String,
    pub run_input_binding_id: String,
    pub run_input_object_ref: String,
    pub run_input_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_input_content_hash_hex: Option<String>,
    pub purpose: String,
    pub requested_claim_count: usize,
    pub allowed_capability_count: usize,
    pub allowed_sink_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E8RefusalCode {
    pub code: String,
    pub class: String,
    pub source_ref_id: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E8RefusalSourceRef {
    pub id: String,
    pub surface: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E8RefusalEvidenceRef {
    pub id: String,
    pub kind: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E8RefusalLedgerReceipt {
    pub schema_version: String,
    pub ledger_id: String,
    pub run_id: String,
    pub contract_id: String,
    pub result_class: String,
    pub threat_model_scope: String,
    pub certifier_input_allowed: bool,
    pub positive_non_use_claim_allowed: bool,
    pub must_block_certificate: bool,
    pub analyzed_surface_count: u64,
    pub unanalyzed_surface_count: u64,
    pub degraded_surface_count: u64,
    pub refusal_codes: Vec<E8RefusalCode>,
    pub source_refs: Vec<E8RefusalSourceRef>,
    pub evidence_refs: Vec<E8RefusalEvidenceRef>,
    pub remediation_actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E8AdversarialRefusalFixture {
    pub fixture_id: String,
    pub scenario: String,
    pub code: String,
    pub class: String,
    pub source_ref: E8RefusalSourceRef,
    pub evidence_ref: E8RefusalEvidenceRef,
    pub remediation: String,
}

impl DataContractRunBinding {
    pub fn uncertified_preflight_receipt(
        &self,
        run_id: &str,
        explain_bundle_path: Option<&str>,
    ) -> E8RefusalLedgerReceipt {
        self.uncertified_preflight_receipt_with_adversarial_fixtures(
            run_id,
            explain_bundle_path,
            &[],
        )
    }

    pub fn uncertified_preflight_receipt_with_adversarial_fixtures(
        &self,
        run_id: &str,
        explain_bundle_path: Option<&str>,
        adversarial_fixtures: &[E8AdversarialRefusalFixture],
    ) -> E8RefusalLedgerReceipt {
        let mut refusal_codes = vec![E8RefusalCode {
            code: "missing_flow_proof_obligation".to_string(),
            class: "missing_evidence".to_string(),
            source_ref_id: "flow-proof-obligation".to_string(),
            remediation: "emit or link a FlowProofObligation before certifying non-use".to_string(),
        }];
        let mut source_refs = vec![
            E8RefusalSourceRef {
                id: "data-contract-binding".to_string(),
                surface: "data_contract_binding".to_string(),
                path: "crates/franken-engine/src/data_contract.rs".to_string(),
                symbol: Some("DataContractRunBinding".to_string()),
                span: None,
            },
            E8RefusalSourceRef {
                id: "flow-proof-obligation".to_string(),
                surface: "flow_envelope".to_string(),
                path: "crates/franken-engine/src/flow_envelope.rs".to_string(),
                symbol: Some("FlowProofObligation".to_string()),
                span: None,
            },
        ];
        let mut evidence_refs = vec![
            E8RefusalEvidenceRef {
                id: "data-contract-run-binding".to_string(),
                kind: "data_contract_run_binding".to_string(),
                status: "present".to_string(),
                artifact_path: Some("frankenctl run output:data_contract".to_string()),
                content_hash_hex: Some(self.contract_hash_hex.clone()),
            },
            E8RefusalEvidenceRef {
                id: "flow-proof-obligation".to_string(),
                kind: "flow_proof_obligation".to_string(),
                status: "missing".to_string(),
                artifact_path: None,
                content_hash_hex: None,
            },
        ];
        let mut remediation_actions = vec![
            "emit analyzed-subset flow proof obligations before certifier promotion".to_string(),
            "keep E8 non-use wording uncertified until proof evidence is linked".to_string(),
        ];

        match explain_bundle_path {
            Some(path) => evidence_refs.push(E8RefusalEvidenceRef {
                id: "run-explain-bundle".to_string(),
                kind: "runtime_explain_bundle".to_string(),
                status: "present".to_string(),
                artifact_path: Some(path.to_string()),
                content_hash_hex: None,
            }),
            None => {
                refusal_codes.push(E8RefusalCode {
                    code: "missing_explain_or_replay_bundle".to_string(),
                    class: "missing_evidence".to_string(),
                    source_ref_id: "frankenctl-run-explain".to_string(),
                    remediation: "emit the explain or replay bundle before certification"
                        .to_string(),
                });
                source_refs.push(E8RefusalSourceRef {
                    id: "frankenctl-run-explain".to_string(),
                    surface: "frankenctl_run_explain".to_string(),
                    path: "crates/franken-engine/src/bin/frankenctl.rs".to_string(),
                    symbol: Some("build_run_explain_bundle".to_string()),
                    span: None,
                });
                evidence_refs.push(E8RefusalEvidenceRef {
                    id: "run-explain-bundle".to_string(),
                    kind: "runtime_explain_bundle".to_string(),
                    status: "missing".to_string(),
                    artifact_path: None,
                    content_hash_hex: None,
                });
                remediation_actions
                    .push("rerun frankenctl run with --explain or --explain-out".to_string());
            }
        }

        for fixture in adversarial_fixtures {
            refusal_codes.push(E8RefusalCode {
                code: fixture.code.clone(),
                class: fixture.class.clone(),
                source_ref_id: fixture.source_ref.id.clone(),
                remediation: fixture.remediation.clone(),
            });
            source_refs.push(fixture.source_ref.clone());
            evidence_refs.push(fixture.evidence_ref.clone());
            remediation_actions.push(format!(
                "fixture `{}`: {}",
                fixture.fixture_id, fixture.remediation
            ));
        }

        let mut receipt_seed = Vec::new();
        receipt_seed.extend_from_slice(b"e8-preflight-v1");
        append_e8_ledger_seed_field(&mut receipt_seed, "run_id", run_id);
        append_e8_ledger_seed_field(&mut receipt_seed, "contract_id", &self.contract_id);
        append_e8_ledger_seed_field(&mut receipt_seed, "contract_hash", &self.contract_hash_hex);
        append_e8_ledger_seed_field(
            &mut receipt_seed,
            "run_input_binding_id",
            &self.run_input_binding_id,
        );
        append_e8_ledger_seed_field(
            &mut receipt_seed,
            "run_input_content_hash",
            self.run_input_content_hash_hex.as_deref().unwrap_or(""),
        );
        append_e8_ledger_seed_field(
            &mut receipt_seed,
            "explain_bundle_path",
            explain_bundle_path.unwrap_or(""),
        );
        if !adversarial_fixtures.is_empty() {
            append_e8_ledger_seed_field(
                &mut receipt_seed,
                "adversarial_fixtures",
                &serde_json::to_string(adversarial_fixtures)
                    .expect("E8 adversarial fixture serialization should succeed"),
            );
        }
        let ledger_id = format!(
            "e8-preflight-{}",
            ContentHash::compute(&receipt_seed).to_hex()
        );
        let degraded_surface_count = refusal_codes
            .iter()
            .filter(|code| code.class == "degraded")
            .count() as u64;

        E8RefusalLedgerReceipt {
            schema_version: E8_REFUSAL_LEDGER_SCHEMA_VERSION.to_string(),
            ledger_id,
            run_id: run_id.to_string(),
            contract_id: self.contract_id.clone(),
            result_class: e8_refusal_result_class(&refusal_codes).to_string(),
            threat_model_scope: E8_REFUSAL_THREAT_MODEL_SCOPE.to_string(),
            certifier_input_allowed: false,
            positive_non_use_claim_allowed: false,
            must_block_certificate: true,
            analyzed_surface_count: 1,
            unanalyzed_surface_count: refusal_codes.len() as u64,
            degraded_surface_count,
            refusal_codes,
            source_refs,
            evidence_refs,
            remediation_actions,
        }
    }
}

fn append_e8_ledger_seed_field(seed: &mut Vec<u8>, field: &str, value: &str) {
    seed.extend_from_slice(&(field.len() as u64).to_be_bytes());
    seed.extend_from_slice(field.as_bytes());
    seed.extend_from_slice(&(value.len() as u64).to_be_bytes());
    seed.extend_from_slice(value.as_bytes());
}

fn e8_refusal_result_class(refusal_codes: &[E8RefusalCode]) -> &'static str {
    if refusal_codes.iter().any(|code| code.class == "fail_closed") {
        "fail_closed"
    } else if refusal_codes
        .iter()
        .any(|code| code.class == "out_of_scope")
    {
        "out_of_scope"
    } else if refusal_codes.iter().any(|code| code.class == "degraded") {
        "degraded"
    } else {
        "uncertified"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataContractError {
    UnsupportedSchema {
        expected: &'static str,
        actual: String,
    },
    EmptyField {
        field: &'static str,
    },
    DuplicateId {
        field: &'static str,
        id: String,
    },
    EmptySet {
        field: &'static str,
    },
    InvalidContentHashHex {
        binding_id: String,
        actual: String,
    },
    UnknownClaimRef {
        route_id: String,
        claim_id: String,
    },
    UnknownBindingRef {
        claim_id: String,
        binding_id: String,
    },
    ExtensionMismatch {
        contract_extension_id: String,
        run_extension_id: String,
    },
    PurposeNotAllowed {
        purpose: String,
    },
    MissingRunInputBinding {
        input_path: String,
    },
    AmbiguousRunInputBinding {
        input_path: String,
        count: usize,
    },
    MissingRunInputContentHash {
        binding_id: String,
    },
    RunInputContentHashMismatch {
        binding_id: String,
        expected: String,
        actual: String,
    },
}

impl fmt::Display for DataContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema { expected, actual } => {
                write!(
                    f,
                    "unsupported data-contract schema `{actual}`; expected `{expected}`"
                )
            }
            Self::EmptyField { field } => {
                write!(f, "data contract field `{field}` must be non-empty")
            }
            Self::DuplicateId { field, id } => {
                write!(
                    f,
                    "data contract field `{field}` contains duplicate id `{id}`"
                )
            }
            Self::EmptySet { field } => write!(f, "data contract set `{field}` must be non-empty"),
            Self::InvalidContentHashHex { binding_id, actual } => write!(
                f,
                "data contract binding `{binding_id}` declares invalid SHA-256 content hash `{actual}`"
            ),
            Self::UnknownClaimRef { route_id, claim_id } => write!(
                f,
                "data contract route `{route_id}` references unknown claim `{claim_id}`"
            ),
            Self::UnknownBindingRef {
                claim_id,
                binding_id,
            } => write!(
                f,
                "data contract claim `{claim_id}` references unknown binding `{binding_id}`"
            ),
            Self::ExtensionMismatch {
                contract_extension_id,
                run_extension_id,
            } => write!(
                f,
                "data contract extension `{contract_extension_id}` does not match run extension `{run_extension_id}`"
            ),
            Self::PurposeNotAllowed { purpose } => {
                write!(f, "data contract does not allow purpose `{purpose}`")
            }
            Self::MissingRunInputBinding { input_path } => write!(
                f,
                "data contract has no run_input binding for input path `{input_path}`"
            ),
            Self::AmbiguousRunInputBinding { input_path, count } => write!(
                f,
                "data contract has {count} run_input bindings for input path `{input_path}`"
            ),
            Self::MissingRunInputContentHash { binding_id } => write!(
                f,
                "data contract binding `{binding_id}` declares a source content hash but the run input hash was not provided"
            ),
            Self::RunInputContentHashMismatch {
                binding_id,
                expected,
                actual,
            } => write!(
                f,
                "data contract binding `{binding_id}` source hash mismatch: expected `{expected}`, actual `{actual}`"
            ),
        }
    }
}

impl std::error::Error for DataContractError {}

impl DataContract {
    pub fn validate(&self) -> Result<(), DataContractError> {
        if self.schema_version != DATA_CONTRACT_SCHEMA_VERSION {
            return Err(DataContractError::UnsupportedSchema {
                expected: DATA_CONTRACT_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("contract_id", &self.contract_id)?;
        require_non_empty("extension_id", &self.extension_id)?;
        require_non_empty_set("allowed_purposes", &self.allowed_purposes)?;
        require_non_empty_set_members("allowed_purposes[]", &self.allowed_purposes)?;
        require_non_empty_set("allowed_capabilities", &self.allowed_capabilities)?;
        if self.input_bindings.is_empty() {
            return Err(DataContractError::EmptySet {
                field: "input_bindings",
            });
        }
        if self.allowed_sinks.is_empty() {
            return Err(DataContractError::EmptySet {
                field: "allowed_sinks",
            });
        }
        if self.requested_output_claims.is_empty() {
            return Err(DataContractError::EmptySet {
                field: "requested_output_claims",
            });
        }

        let mut binding_ids = BTreeSet::new();
        for binding in &self.input_bindings {
            require_non_empty("input_bindings[].binding_id", &binding.binding_id)?;
            require_non_empty("input_bindings[].object_ref", &binding.object_ref)?;
            require_non_empty("input_bindings[].owner", &binding.owner)?;
            if let Some(path) = binding.path.as_deref() {
                require_non_empty("input_bindings[].path", path)?;
            }
            require_non_empty_set(
                "input_bindings[].allowed_purposes",
                &binding.allowed_purposes,
            )?;
            require_non_empty_set_members(
                "input_bindings[].allowed_purposes[]",
                &binding.allowed_purposes,
            )?;
            if let Some(content_hash_hex) = binding.content_hash_hex.as_deref()
                && !is_sha256_hex(content_hash_hex)
            {
                return Err(DataContractError::InvalidContentHashHex {
                    binding_id: binding.binding_id.clone(),
                    actual: content_hash_hex.to_string(),
                });
            }
            if !binding_ids.insert(binding.binding_id.clone()) {
                return Err(DataContractError::DuplicateId {
                    field: "input_bindings[].binding_id",
                    id: binding.binding_id.clone(),
                });
            }
        }

        let mut sink_ids = BTreeSet::new();
        for sink in &self.allowed_sinks {
            require_non_empty("allowed_sinks[].sink_id", &sink.sink_id)?;
            require_non_empty("allowed_sinks[].location", &sink.location)?;
            require_non_empty_set("allowed_sinks[].allowed_labels", &sink.allowed_labels)?;
            if !sink_ids.insert(sink.sink_id.clone()) {
                return Err(DataContractError::DuplicateId {
                    field: "allowed_sinks[].sink_id",
                    id: sink.sink_id.clone(),
                });
            }
        }

        let mut claim_ids = BTreeSet::new();
        for claim in &self.requested_output_claims {
            let claim_id = claim.claim_id();
            require_non_empty("requested_output_claims[].claim_id", claim_id)?;
            if !claim_ids.insert(claim_id.to_string()) {
                return Err(DataContractError::DuplicateId {
                    field: "requested_output_claims[].claim_id",
                    id: claim_id.to_string(),
                });
            }
            if let RequestedOutputClaim::OutputIndependentOf { binding_id, .. } = claim
                && !binding_ids.contains(binding_id)
            {
                return Err(DataContractError::UnknownBindingRef {
                    claim_id: claim_id.to_string(),
                    binding_id: binding_id.clone(),
                });
            }
        }

        let mut route_ids = BTreeSet::new();
        for required in &self.required_declassification_routes {
            require_non_empty(
                "required_declassification_routes[].route.route_id",
                &required.route.route_id,
            )?;
            if !route_ids.insert(required.route.route_id.clone()) {
                return Err(DataContractError::DuplicateId {
                    field: "required_declassification_routes[].route.route_id",
                    id: required.route.route_id.clone(),
                });
            }
            require_non_empty_vec(
                "required_declassification_routes[].route.conditions",
                &required.route.conditions,
            )?;
            require_non_empty_vec_members(
                "required_declassification_routes[].route.conditions[]",
                &required.route.conditions,
            )?;
            require_non_empty_set(
                "required_declassification_routes[].required_for_claims",
                &required.required_for_claims,
            )?;
            require_non_empty_set_members(
                "required_declassification_routes[].required_for_claims[]",
                &required.required_for_claims,
            )?;
            for claim_id in &required.required_for_claims {
                if !claim_ids.contains(claim_id) {
                    return Err(DataContractError::UnknownClaimRef {
                        route_id: required.route.route_id.clone(),
                        claim_id: claim_id.clone(),
                    });
                }
            }
        }

        Ok(())
    }

    pub fn bind_to_run(
        &self,
        run_extension_id: &str,
        input_path: &str,
        purpose: &str,
        input_content_hash: Option<&ContentHash>,
    ) -> Result<DataContractRunBinding, DataContractError> {
        self.validate()?;
        require_non_empty("purpose", purpose)?;
        if self.extension_id != run_extension_id {
            return Err(DataContractError::ExtensionMismatch {
                contract_extension_id: self.extension_id.clone(),
                run_extension_id: run_extension_id.to_string(),
            });
        }
        if !self.allowed_purposes.contains(purpose) {
            return Err(DataContractError::PurposeNotAllowed {
                purpose: purpose.to_string(),
            });
        }

        let matches = self
            .input_bindings
            .iter()
            .filter(|binding| {
                binding.role == DataBindingRole::RunInput
                    && binding.path.as_deref() == Some(input_path)
                    && binding.allowed_purposes.contains(purpose)
            })
            .collect::<Vec<_>>();

        let binding = match matches.as_slice() {
            [] => {
                return Err(DataContractError::MissingRunInputBinding {
                    input_path: input_path.to_string(),
                });
            }
            [binding] => *binding,
            many => {
                return Err(DataContractError::AmbiguousRunInputBinding {
                    input_path: input_path.to_string(),
                    count: many.len(),
                });
            }
        };

        let actual_content_hash_hex = input_content_hash.map(ContentHash::to_hex);
        if let Some(expected) = binding.content_hash_hex.as_deref() {
            let Some(actual) = actual_content_hash_hex.as_deref() else {
                return Err(DataContractError::MissingRunInputContentHash {
                    binding_id: binding.binding_id.clone(),
                });
            };
            if !expected.eq_ignore_ascii_case(actual) {
                return Err(DataContractError::RunInputContentHashMismatch {
                    binding_id: binding.binding_id.clone(),
                    expected: expected.to_string(),
                    actual: actual.to_string(),
                });
            }
        }

        Ok(DataContractRunBinding {
            schema_version: DATA_CONTRACT_SCHEMA_VERSION.to_string(),
            contract_id: self.contract_id.clone(),
            contract_hash_hex: self.content_hash().to_hex(),
            extension_id: self.extension_id.clone(),
            run_input_binding_id: binding.binding_id.clone(),
            run_input_object_ref: binding.object_ref.clone(),
            run_input_path: input_path.to_string(),
            run_input_content_hash_hex: actual_content_hash_hex,
            purpose: purpose.to_string(),
            requested_claim_count: self.requested_output_claims.len(),
            allowed_capability_count: self.allowed_capabilities.len(),
            allowed_sink_count: self.allowed_sinks.len(),
        })
    }

    pub fn content_hash(&self) -> ContentHash {
        let bytes = serde_json::to_vec(self).expect("data contract serialization should succeed");
        ContentHash::compute(&bytes)
    }
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), DataContractError> {
    if value.trim().is_empty() {
        Err(DataContractError::EmptyField { field })
    } else {
        Ok(())
    }
}

fn require_non_empty_set<T>(
    field: &'static str,
    value: &BTreeSet<T>,
) -> Result<(), DataContractError> {
    if value.is_empty() {
        Err(DataContractError::EmptySet { field })
    } else {
        Ok(())
    }
}

fn require_non_empty_set_members(
    field: &'static str,
    value: &BTreeSet<String>,
) -> Result<(), DataContractError> {
    if value.iter().any(|member| member.trim().is_empty()) {
        Err(DataContractError::EmptyField { field })
    } else {
        Ok(())
    }
}

fn require_non_empty_vec(field: &'static str, value: &[String]) -> Result<(), DataContractError> {
    if value.is_empty() {
        Err(DataContractError::EmptySet { field })
    } else {
        Ok(())
    }
}

fn require_non_empty_vec_members(
    field: &'static str,
    value: &[String],
) -> Result<(), DataContractError> {
    if value.iter().any(|member| member.trim().is_empty()) {
        Err(DataContractError::EmptyField { field })
    } else {
        Ok(())
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> DataContract {
        DataContract {
            schema_version: DATA_CONTRACT_SCHEMA_VERSION.to_string(),
            contract_id: "contract-e8-001".to_string(),
            extension_id: "ext-e8".to_string(),
            input_bindings: vec![
                DataBinding {
                    binding_id: "source-js".to_string(),
                    object_ref: "object://source-js".to_string(),
                    path: Some("agent.js".to_string()),
                    label: Label::Public,
                    owner: "runtime-team".to_string(),
                    role: DataBindingRole::RunInput,
                    allowed_purposes: BTreeSet::from([DEFAULT_DATA_CONTRACT_PURPOSE.to_string()]),
                    content_hash_hex: None,
                },
                DataBinding {
                    binding_id: "customer-pii".to_string(),
                    object_ref: "dataset://customer-pii".to_string(),
                    path: None,
                    label: Label::Secret,
                    owner: "data-owner".to_string(),
                    role: DataBindingRole::SensitiveInput,
                    allowed_purposes: BTreeSet::from([DEFAULT_DATA_CONTRACT_PURPOSE.to_string()]),
                    content_hash_hex: None,
                },
            ],
            allowed_purposes: BTreeSet::from([DEFAULT_DATA_CONTRACT_PURPOSE.to_string()]),
            allowed_capabilities: BTreeSet::from([
                RuntimeCapability::VmDispatch,
                RuntimeCapability::Builtin,
                RuntimeCapability::Console,
            ]),
            allowed_sinks: vec![SinkBinding {
                sink_id: "stdout".to_string(),
                clearance: ClearanceClass::RestrictedSink,
                location: "console".to_string(),
                allowed_labels: BTreeSet::from([Label::Public, Label::Internal]),
            }],
            required_declassification_routes: vec![],
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
            ],
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn binds_exact_run_input() {
        let bound = contract()
            .bind_to_run("ext-e8", "agent.js", DEFAULT_DATA_CONTRACT_PURPOSE, None)
            .expect("valid contract should bind");
        assert_eq!(bound.contract_id, "contract-e8-001");
        assert_eq!(bound.run_input_binding_id, "source-js");
        assert_eq!(bound.requested_claim_count, 2);
        assert_eq!(bound.contract_hash_hex.len(), 64);
    }

    #[test]
    fn missing_run_input_fails_closed() {
        let error = contract()
            .bind_to_run("ext-e8", "other.js", DEFAULT_DATA_CONTRACT_PURPOSE, None)
            .expect_err("missing run binding must fail closed");
        assert!(matches!(
            error,
            DataContractError::MissingRunInputBinding { .. }
        ));
    }

    #[test]
    fn ambiguous_run_input_fails_closed() {
        let mut contract = contract();
        let mut duplicate = contract.input_bindings[0].clone();
        duplicate.binding_id = "source-js-2".to_string();
        contract.input_bindings.push(duplicate);
        let error = contract
            .bind_to_run("ext-e8", "agent.js", DEFAULT_DATA_CONTRACT_PURPOSE, None)
            .expect_err("ambiguous run binding must fail closed");
        assert!(matches!(
            error,
            DataContractError::AmbiguousRunInputBinding { count: 2, .. }
        ));
    }

    #[test]
    fn run_input_content_hash_must_match_when_declared() {
        let mut contract = contract();
        let source_hash = ContentHash::compute(b"console.log('ok')");
        contract.input_bindings[0].content_hash_hex = Some(source_hash.to_hex().to_uppercase());

        let bound = contract
            .bind_to_run(
                "ext-e8",
                "agent.js",
                DEFAULT_DATA_CONTRACT_PURPOSE,
                Some(&source_hash),
            )
            .expect("matching run input hash should bind");
        assert_eq!(bound.run_input_content_hash_hex, Some(source_hash.to_hex()));

        let missing = contract
            .bind_to_run("ext-e8", "agent.js", DEFAULT_DATA_CONTRACT_PURPOSE, None)
            .expect_err("declared hash without actual run hash must fail closed");
        assert!(matches!(
            missing,
            DataContractError::MissingRunInputContentHash { .. }
        ));

        let mismatch = contract
            .bind_to_run(
                "ext-e8",
                "agent.js",
                DEFAULT_DATA_CONTRACT_PURPOSE,
                Some(&ContentHash::compute(b"different source")),
            )
            .expect_err("mismatched run hash must fail closed");
        assert!(matches!(
            mismatch,
            DataContractError::RunInputContentHashMismatch { .. }
        ));
    }

    #[test]
    fn unknown_output_binding_reference_fails_closed() {
        let mut contract = contract();
        contract
            .requested_output_claims
            .push(RequestedOutputClaim::OutputIndependentOf {
                claim_id: "missing-ref".to_string(),
                binding_id: "missing-binding".to_string(),
            });
        let error = contract.validate().expect_err("unknown binding must fail");
        assert!(matches!(error, DataContractError::UnknownBindingRef { .. }));
    }

    #[test]
    fn malformed_optional_fields_fail_closed() {
        let mut blank_path = contract();
        blank_path.input_bindings[0].path = Some(" ".to_string());
        assert!(matches!(
            blank_path.validate(),
            Err(DataContractError::EmptyField {
                field: "input_bindings[].path"
            })
        ));

        let mut bad_hash = contract();
        bad_hash.input_bindings[0].content_hash_hex = Some("not-a-sha256".to_string());
        assert!(matches!(
            bad_hash.validate(),
            Err(DataContractError::InvalidContentHashHex { .. })
        ));

        let mut blank_purpose = contract();
        blank_purpose.allowed_purposes.insert(" ".to_string());
        assert!(matches!(
            blank_purpose.validate(),
            Err(DataContractError::EmptyField {
                field: "allowed_purposes[]"
            })
        ));
    }

    #[test]
    fn malformed_declassification_route_fails_closed() {
        let mut empty_claims = contract();
        empty_claims
            .required_declassification_routes
            .push(RequiredDeclassificationRoute {
                route: DeclassificationRoute {
                    route_id: "route-secret-audit".to_string(),
                    source_label: Label::Secret,
                    target_clearance: Label::Confidential,
                    conditions: vec!["receipt_required".to_string()],
                },
                required_for_claims: BTreeSet::new(),
            });
        assert!(matches!(
            empty_claims.validate(),
            Err(DataContractError::EmptySet {
                field: "required_declassification_routes[].required_for_claims"
            })
        ));

        let mut blank_condition = contract();
        blank_condition
            .required_declassification_routes
            .push(RequiredDeclassificationRoute {
                route: DeclassificationRoute {
                    route_id: "route-secret-audit".to_string(),
                    source_label: Label::Secret,
                    target_clearance: Label::Confidential,
                    conditions: vec![" ".to_string()],
                },
                required_for_claims: BTreeSet::from(["no-secret-open-sink".to_string()]),
            });
        assert!(matches!(
            blank_condition.validate(),
            Err(DataContractError::EmptyField {
                field: "required_declassification_routes[].route.conditions[]"
            })
        ));

        let mut duplicate_route_id = contract();
        duplicate_route_id.required_declassification_routes = vec![
            RequiredDeclassificationRoute {
                route: DeclassificationRoute {
                    route_id: "route-secret-audit".to_string(),
                    source_label: Label::Secret,
                    target_clearance: Label::Confidential,
                    conditions: vec!["receipt_required".to_string()],
                },
                required_for_claims: BTreeSet::from(["no-secret-open-sink".to_string()]),
            },
            RequiredDeclassificationRoute {
                route: DeclassificationRoute {
                    route_id: "route-secret-audit".to_string(),
                    source_label: Label::Secret,
                    target_clearance: Label::Internal,
                    conditions: vec!["owner_approval".to_string()],
                },
                required_for_claims: BTreeSet::from(["output-independent-of-pii".to_string()]),
            },
        ];
        assert!(matches!(
            duplicate_route_id.validate(),
            Err(DataContractError::DuplicateId {
                field: "required_declassification_routes[].route.route_id",
                ..
            })
        ));
    }
}
