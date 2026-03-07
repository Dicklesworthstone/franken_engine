#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};

const CONTRACT_SCHEMA_VERSION: &str = "rgc.react-capability-contract.v1";
const CONTRACT_JSON: &str = include_str!("../../../docs/rgc_react_capability_contract_v1.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReactCapabilityContract {
    schema_version: String,
    bead_id: String,
    generated_by: String,
    generated_at_utc: String,
    track: ContractTrack,
    extends_matrix_contract: MatrixContractRef,
    required_structured_log_fields: Vec<String>,
    product_surfaces: Vec<ProductSurface>,
    capability_rows: Vec<CapabilityRow>,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ContractTrack {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MatrixContractRef {
    bead_id: String,
    contract_doc: String,
    contract_json: String,
    coverage_row_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProductSurface {
    surface_bead: String,
    name: String,
    ship_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CapabilityRow {
    capability_id: String,
    source_form: String,
    runtime_mode: String,
    entry_surface: String,
    support_status: String,
    owning_implementation_bead: String,
    parity_gate_bead: String,
    product_surface_bead: String,
    verification_lane: String,
    required_artifacts: Vec<String>,
    user_visible_diagnostic: UserVisibleDiagnostic,
    unsupported_surface_policy: UnsupportedSurfacePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UserVisibleDiagnostic {
    error_code: String,
    diagnostic_surface: String,
    message_template: String,
    remediation_bead: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UnsupportedSurfacePolicy {
    fallback_mode: String,
    waiver_required: bool,
    max_waiver_age_hours: u64,
    user_visible_diagnostics_required: bool,
    remediation_bead: String,
    target_milestone: String,
    claim_language_state: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse_contract() -> ReactCapabilityContract {
    serde_json::from_str(CONTRACT_JSON).expect("react capability contract json must parse")
}

fn capability_index(contract: &ReactCapabilityContract) -> BTreeMap<&str, &CapabilityRow> {
    contract
        .capability_rows
        .iter()
        .map(|row| (row.capability_id.as_str(), row))
        .collect()
}

#[test]
fn rgc_016a_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_REACT_CAPABILITY_CONTRACT_V1.md");
    let doc = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    let required_sections = [
        "# RGC React Capability Contract V1",
        "## Purpose",
        "## Capability Model",
        "## Explicit Capability Rows",
        "## Unsupported-Surface Governance",
        "## Structured Logging and Artifact Contract",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing required section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn rgc_016a_contract_is_versioned_and_matrix_bound() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.bead_id, "bd-1lsy.1.6.1");
    assert_eq!(contract.generated_by, "bd-1lsy.1.6.1");
    assert_eq!(contract.track.id, "RGC-016A");
    assert_eq!(contract.track.name, "React Capability Contract");
    assert!(contract.generated_at_utc.ends_with('Z'));

    assert_eq!(contract.extends_matrix_contract.bead_id, "bd-1lsy.1.1");
    assert_eq!(
        contract.extends_matrix_contract.contract_doc,
        "docs/RGC_EXECUTABLE_COMPATIBILITY_TARGET_MATRIX_V1.md"
    );
    assert_eq!(
        contract.extends_matrix_contract.contract_json,
        "docs/rgc_executable_compatibility_target_matrix_v1.json"
    );
    assert_eq!(
        contract.extends_matrix_contract.coverage_row_id,
        "rgc-react-capability-contract"
    );
}

#[test]
fn rgc_016a_contract_covers_required_react_capability_rows() {
    let contract = parse_contract();
    let rows = capability_index(&contract);

    for capability_id in [
        "jsx-classic-runtime-compile",
        "tsx-classic-runtime-compile",
        "fragment-lowering-contract",
        "jsx-automatic-runtime-compile",
        "tsx-automatic-runtime-compile",
        "jsx-dev-runtime-diagnostics",
        "react-ssr-entrypoint",
        "react-client-entry-preparation",
        "react-hydration-handoff-artifacts",
        "react-diagnostics-source-maps",
    ] {
        assert!(
            rows.contains_key(capability_id),
            "missing required capability row: {capability_id}"
        );
    }
}

#[test]
fn rgc_016a_rows_bind_to_implementation_parity_and_product_surfaces() {
    let contract = parse_contract();
    let allowed_statuses: BTreeSet<&str> = ["unsupported", "deferred", "gated_preview", "shipped"]
        .into_iter()
        .collect();

    for row in &contract.capability_rows {
        assert!(
            allowed_statuses.contains(row.support_status.as_str()),
            "unsupported support status for {}: {}",
            row.capability_id,
            row.support_status
        );
        assert!(
            row.owning_implementation_bead.starts_with("bd-1lsy."),
            "owning bead missing for {}",
            row.capability_id
        );
        assert!(
            row.parity_gate_bead.starts_with("bd-1lsy."),
            "parity gate bead missing for {}",
            row.capability_id
        );
        assert!(
            row.product_surface_bead.starts_with("bd-1lsy."),
            "product surface bead missing for {}",
            row.capability_id
        );
        assert!(
            !row.verification_lane.trim().is_empty(),
            "verification lane missing for {}",
            row.capability_id
        );
        assert!(
            row.required_artifacts
                .iter()
                .any(|artifact| artifact.ends_with("react_capability_contract.json")),
            "react capability artifact missing for {}",
            row.capability_id
        );
        for triad in ["run_manifest.json", "events.jsonl", "commands.txt"] {
            assert!(
                row.required_artifacts
                    .iter()
                    .any(|artifact| artifact.ends_with(triad)),
                "artifact triad member {} missing for {}",
                triad,
                row.capability_id
            );
        }
    }
}

#[test]
fn rgc_016a_unsupported_and_deferred_rows_fail_closed_with_diagnostics() {
    let contract = parse_contract();
    let allowed_fallbacks: BTreeSet<&str> = ["reject_with_guidance", "diagnostic_only_reject"]
        .into_iter()
        .collect();

    for row in &contract.capability_rows {
        if ["unsupported", "deferred"].contains(&row.support_status.as_str()) {
            let diagnostic = &row.user_visible_diagnostic;
            let policy = &row.unsupported_surface_policy;

            assert!(
                diagnostic.error_code.starts_with("FE-RGC-016A-CAP-"),
                "diagnostic code missing stable prefix for {}",
                row.capability_id
            );
            assert!(!diagnostic.diagnostic_surface.trim().is_empty());
            assert!(!diagnostic.message_template.trim().is_empty());
            assert_eq!(diagnostic.remediation_bead, "bd-1lsy.10.11.2");

            assert!(policy.waiver_required);
            assert_eq!(policy.max_waiver_age_hours, 168);
            assert!(policy.user_visible_diagnostics_required);
            assert_eq!(policy.remediation_bead, "bd-1lsy.10.11.2");
            assert_eq!(policy.target_milestone, "M5");
            assert_eq!(policy.claim_language_state, "target_only");
            assert!(
                allowed_fallbacks.contains(policy.fallback_mode.as_str()),
                "invalid fallback mode for {}: {}",
                row.capability_id,
                policy.fallback_mode
            );
        }
    }
}

#[test]
fn rgc_016a_required_log_fields_and_product_surface_index_are_present() {
    let contract = parse_contract();

    let root_fields: BTreeSet<&str> = contract
        .required_structured_log_fields
        .iter()
        .map(String::as_str)
        .collect();
    for field in [
        "schema_version",
        "scenario_id",
        "trace_id",
        "decision_id",
        "component",
        "event",
        "runtime_lane",
        "seed",
        "outcome",
        "error_code",
    ] {
        assert!(
            root_fields.contains(field),
            "missing required log field {field}"
        );
    }

    let surface_beads: BTreeSet<&str> = contract
        .product_surfaces
        .iter()
        .map(|surface| surface.surface_bead.as_str())
        .collect();
    for bead in [
        "bd-1lsy.10.11.2",
        "bd-1lsy.10.12.1",
        "bd-1lsy.10.12.2",
        "bd-1lsy.10.12.3",
    ] {
        assert!(
            surface_beads.contains(bead),
            "missing product surface {bead}"
        );
    }
}

#[test]
fn rgc_016a_operator_verification_commands_are_present() {
    let contract = parse_contract();

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("jq empty docs/rgc_react_capability_contract_v1.json")),
        "operator verification must include json validation"
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("./scripts/run_rgc_react_capability_contract.sh ci")),
        "operator verification must include the gate script"
    );
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("./scripts/e2e/rgc_react_capability_contract_replay.sh ci")),
        "operator verification must include the replay wrapper"
    );
}

#[test]
fn rgc_016a_capability_ids_are_unique_and_roundtrip_cleanly() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for row in &contract.capability_rows {
        assert!(
            seen.insert(&row.capability_id),
            "duplicate capability id {}",
            row.capability_id
        );
    }

    let serialized = serde_json::to_string(&contract).expect("serialize contract");
    let recovered: ReactCapabilityContract =
        serde_json::from_str(&serialized).expect("deserialize contract");
    assert_eq!(contract, recovered);
}
