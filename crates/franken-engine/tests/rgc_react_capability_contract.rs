#![forbid(unsafe_code)]
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
        "tsx-dev-runtime-diagnostics",
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
fn rgc_016a_dev_runtime_diagnostics_are_split_by_source_form() {
    let contract = parse_contract();
    let rows = capability_index(&contract);

    let jsx_dev = rows
        .get("jsx-dev-runtime-diagnostics")
        .expect("missing JSX dev-runtime diagnostics row");
    let tsx_dev = rows
        .get("tsx-dev-runtime-diagnostics")
        .expect("missing TSX dev-runtime diagnostics row");

    assert_eq!(jsx_dev.source_form, "jsx");
    assert_eq!(tsx_dev.source_form, "tsx");
    assert_eq!(jsx_dev.runtime_mode, "jsx_dev_runtime");
    assert_eq!(tsx_dev.runtime_mode, "jsx_dev_runtime");
    assert_eq!(jsx_dev.entry_surface, "diagnostic_contract");
    assert_eq!(tsx_dev.entry_surface, "diagnostic_contract");
    assert_eq!(jsx_dev.verification_lane, "react_diagnostics_contract");
    assert_eq!(tsx_dev.verification_lane, "react_diagnostics_contract");
    assert_eq!(jsx_dev.product_surface_bead, "bd-1lsy.10.12.2");
    assert_eq!(tsx_dev.product_surface_bead, "bd-1lsy.10.12.2");
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
        contract.operator_verification.iter().any(|cmd| cmd.contains(
            "CARGO_TARGET_DIR=/data/projects/franken_engine/target_rch_rgc_react_capability_contract"
        )),
        "operator verification must include a repo-local rch target dir for direct test validation"
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
fn rgc_016a_operator_verification_avoids_tmp_rch_targets() {
    let contract = parse_contract();
    assert!(
        contract
            .operator_verification
            .iter()
            .all(|cmd| !cmd.contains("/tmp/rch_target")),
        "operator verification must not rely on /tmp rch target dirs"
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

// ── New enrichment tests ──────────────────────────────────────────────

#[test]
fn rgc_016a_serde_determinism_roundtrip() {
    let contract = parse_contract();
    let json_a = serde_json::to_string_pretty(&contract).expect("serialize a");
    let recovered: ReactCapabilityContract = serde_json::from_str(&json_a).expect("deserialize a");
    let json_b = serde_json::to_string_pretty(&recovered).expect("serialize b");
    assert_eq!(json_a, json_b, "serde roundtrip must be deterministic");
}

#[test]
fn rgc_016a_capability_ids_are_non_empty_strings() {
    let contract = parse_contract();
    for row in &contract.capability_rows {
        assert!(
            !row.capability_id.trim().is_empty(),
            "capability_id must be a non-empty string"
        );
    }
}

#[test]
fn rgc_016a_each_capability_has_non_empty_source_form() {
    let contract = parse_contract();
    for row in &contract.capability_rows {
        assert!(
            !row.source_form.trim().is_empty(),
            "source_form must be non-empty for capability {}",
            row.capability_id
        );
    }
}

#[test]
fn rgc_016a_each_capability_has_non_empty_runtime_mode() {
    let contract = parse_contract();
    for row in &contract.capability_rows {
        assert!(
            !row.runtime_mode.trim().is_empty(),
            "runtime_mode must be non-empty for capability {}",
            row.capability_id
        );
    }
}

#[test]
fn rgc_016a_each_capability_has_non_empty_entry_surface() {
    let contract = parse_contract();
    for row in &contract.capability_rows {
        assert!(
            !row.entry_surface.trim().is_empty(),
            "entry_surface must be non-empty for capability {}",
            row.capability_id
        );
    }
}

#[test]
fn rgc_016a_product_surfaces_have_non_empty_names() {
    let contract = parse_contract();
    for surface in &contract.product_surfaces {
        assert!(
            !surface.name.trim().is_empty(),
            "product surface name must be non-empty for bead {}",
            surface.surface_bead
        );
    }
}

#[test]
fn rgc_016a_product_surfaces_have_valid_ship_status() {
    let contract = parse_contract();
    let allowed: BTreeSet<&str> = ["required", "planned", "shipped", "deferred"]
        .into_iter()
        .collect();
    for surface in &contract.product_surfaces {
        assert!(
            allowed.contains(surface.ship_status.as_str()),
            "invalid ship_status '{}' for surface bead {}",
            surface.ship_status,
            surface.surface_bead
        );
    }
}

#[test]
fn rgc_016a_product_surface_count_minimum() {
    let contract = parse_contract();
    assert!(
        contract.product_surfaces.len() >= 4,
        "expected at least 4 product surfaces, found {}",
        contract.product_surfaces.len()
    );
}

#[test]
fn rgc_016a_matrix_contract_ref_fields_are_non_empty() {
    let contract = parse_contract();
    let mcr = &contract.extends_matrix_contract;
    assert!(
        !mcr.bead_id.trim().is_empty(),
        "matrix bead_id must be non-empty"
    );
    assert!(
        !mcr.contract_doc.trim().is_empty(),
        "matrix contract_doc must be non-empty"
    );
    assert!(
        !mcr.contract_json.trim().is_empty(),
        "matrix contract_json must be non-empty"
    );
    assert!(
        !mcr.coverage_row_id.trim().is_empty(),
        "matrix coverage_row_id must be non-empty"
    );
}

#[test]
fn rgc_016a_contract_track_fields_are_non_empty() {
    let contract = parse_contract();
    assert!(
        !contract.track.id.trim().is_empty(),
        "track id must be non-empty"
    );
    assert!(
        !contract.track.name.trim().is_empty(),
        "track name must be non-empty"
    );
}

#[test]
fn rgc_016a_operator_verification_has_at_least_three_commands() {
    let contract = parse_contract();
    assert!(
        contract.operator_verification.len() >= 3,
        "expected at least 3 operator verification commands, found {}",
        contract.operator_verification.len()
    );
}

#[test]
fn rgc_016a_required_log_fields_include_all_mandatory() {
    let contract = parse_contract();
    let fields: BTreeSet<&str> = contract
        .required_structured_log_fields
        .iter()
        .map(String::as_str)
        .collect();
    let mandatory = [
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
    ];
    for field in mandatory {
        assert!(
            fields.contains(field),
            "missing mandatory log field: {field}"
        );
    }
}

#[test]
fn rgc_016a_verification_lanes_from_allowed_set() {
    let contract = parse_contract();
    let allowed: BTreeSet<&str> = [
        "react_compile_contract",
        "react_diagnostics_contract",
        "react_ssr_parity",
        "react_client_entry_contract",
        "react_hydration_contract",
    ]
    .into_iter()
    .collect();

    for row in &contract.capability_rows {
        assert!(
            allowed.contains(row.verification_lane.as_str()),
            "verification lane '{}' for capability {} is not in the allowed set",
            row.verification_lane,
            row.capability_id
        );
    }
}

#[test]
fn rgc_016a_unsupported_rows_have_target_milestone() {
    let contract = parse_contract();
    for row in &contract.capability_rows {
        if row.support_status == "unsupported" || row.support_status == "deferred" {
            assert!(
                !row.unsupported_surface_policy
                    .target_milestone
                    .trim()
                    .is_empty(),
                "unsupported/deferred capability {} must have a target_milestone",
                row.capability_id
            );
        }
    }
}

#[test]
fn rgc_016a_diagnostic_error_codes_follow_prefix_pattern() {
    let contract = parse_contract();
    for row in &contract.capability_rows {
        let code = &row.user_visible_diagnostic.error_code;
        assert!(
            code.starts_with("FE-RGC-016A-CAP-"),
            "diagnostic error code '{}' for capability {} must start with FE-RGC-016A-CAP-",
            code,
            row.capability_id
        );
    }
}

#[test]
fn rgc_016a_diagnostic_message_templates_are_non_empty() {
    let contract = parse_contract();
    for row in &contract.capability_rows {
        assert!(
            !row.user_visible_diagnostic
                .message_template
                .trim()
                .is_empty(),
            "diagnostic message_template must be non-empty for capability {}",
            row.capability_id
        );
    }
}

#[test]
fn rgc_016a_required_artifacts_include_triad() {
    let contract = parse_contract();
    for row in &contract.capability_rows {
        for expected_suffix in ["run_manifest.json", "events.jsonl", "commands.txt"] {
            assert!(
                row.required_artifacts
                    .iter()
                    .any(|a| a.ends_with(expected_suffix)),
                "capability {} missing required artifact suffix {}",
                row.capability_id,
                expected_suffix
            );
        }
    }
}

#[test]
fn rgc_016a_schema_version_matches_constant() {
    let contract = parse_contract();
    assert_eq!(
        contract.schema_version, CONTRACT_SCHEMA_VERSION,
        "contract schema version must match the expected constant"
    );
}

#[test]
fn rgc_016a_generated_at_utc_is_rfc3339_z() {
    let contract = parse_contract();
    let ts = &contract.generated_at_utc;
    assert!(ts.ends_with('Z'), "timestamp must end with Z: {ts}");
    assert!(ts.contains('T'), "timestamp must contain T separator: {ts}");
    // Validate YYYY-MM-DDThh:mm:ssZ basic structure
    let parts: Vec<&str> = ts.split('T').collect();
    assert_eq!(parts.len(), 2, "timestamp must have exactly one T: {ts}");
    let date_parts: Vec<&str> = parts[0].split('-').collect();
    assert_eq!(
        date_parts.len(),
        3,
        "date part must have 3 components: {ts}"
    );
    assert_eq!(date_parts[0].len(), 4, "year must be 4 digits: {ts}");
    assert_eq!(date_parts[1].len(), 2, "month must be 2 digits: {ts}");
    assert_eq!(date_parts[2].len(), 2, "day must be 2 digits: {ts}");
}

#[test]
fn rgc_016a_contract_json_is_valid_json() {
    let value: serde_json::Value =
        serde_json::from_str(CONTRACT_JSON).expect("CONTRACT_JSON must be valid JSON");
    assert!(value.is_object(), "top-level JSON must be an object");
}

#[test]
fn rgc_016a_capability_row_count_minimum() {
    let contract = parse_contract();
    assert!(
        contract.capability_rows.len() >= 11,
        "expected at least 11 capability rows, found {}",
        contract.capability_rows.len()
    );
}

#[test]
fn rgc_016a_capability_index_has_unique_keys() {
    let contract = parse_contract();
    let index = capability_index(&contract);
    assert_eq!(
        index.len(),
        contract.capability_rows.len(),
        "capability index length must match row count (no duplicates)"
    );
}

#[test]
fn rgc_016a_diagnostic_error_codes_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for row in &contract.capability_rows {
        assert!(
            seen.insert(&row.user_visible_diagnostic.error_code),
            "duplicate diagnostic error_code {}",
            row.user_visible_diagnostic.error_code
        );
    }
}

#[test]
fn rgc_016a_diagnostic_error_codes_are_numerically_sequential() {
    let contract = parse_contract();
    let prefix = "FE-RGC-016A-CAP-";
    let mut codes: Vec<u32> = contract
        .capability_rows
        .iter()
        .map(|row| {
            let suffix = row
                .user_visible_diagnostic
                .error_code
                .strip_prefix(prefix)
                .unwrap_or_else(|| {
                    panic!(
                        "error code '{}' missing prefix {prefix}",
                        row.user_visible_diagnostic.error_code
                    )
                });
            suffix
                .parse::<u32>()
                .unwrap_or_else(|_| panic!("non-numeric suffix '{suffix}' in error code"))
        })
        .collect();
    codes.sort();
    for (i, code) in codes.iter().enumerate() {
        assert_eq!(
            *code,
            (i as u32) + 1,
            "error codes must be sequential starting at 1, gap at position {i}"
        );
    }
}

#[test]
fn rgc_016a_product_surface_beads_are_non_empty() {
    let contract = parse_contract();
    for surface in &contract.product_surfaces {
        assert!(
            !surface.surface_bead.trim().is_empty(),
            "surface_bead must be non-empty"
        );
    }
}

#[test]
fn rgc_016a_owning_beads_start_with_project_prefix() {
    let contract = parse_contract();
    for row in &contract.capability_rows {
        assert!(
            row.owning_implementation_bead.starts_with("bd-"),
            "owning_implementation_bead for {} must start with bd- prefix",
            row.capability_id
        );
    }
}

#[test]
fn rgc_016a_parity_gate_beads_start_with_project_prefix() {
    let contract = parse_contract();
    for row in &contract.capability_rows {
        assert!(
            row.parity_gate_bead.starts_with("bd-"),
            "parity_gate_bead for {} must start with bd- prefix",
            row.capability_id
        );
    }
}

#[test]
fn rgc_016a_required_artifacts_count_per_row() {
    let contract = parse_contract();
    for row in &contract.capability_rows {
        assert!(
            row.required_artifacts.len() >= 4,
            "capability {} must have at least 4 required artifacts, found {}",
            row.capability_id,
            row.required_artifacts.len()
        );
    }
}

#[test]
fn rgc_016a_diagnostic_surfaces_are_non_empty() {
    let contract = parse_contract();
    for row in &contract.capability_rows {
        assert!(
            !row.user_visible_diagnostic
                .diagnostic_surface
                .trim()
                .is_empty(),
            "diagnostic_surface must be non-empty for capability {}",
            row.capability_id
        );
    }
}

#[test]
fn rgc_016a_remediation_beads_are_consistent() {
    let contract = parse_contract();
    for row in &contract.capability_rows {
        assert_eq!(
            row.user_visible_diagnostic.remediation_bead,
            row.unsupported_surface_policy.remediation_bead,
            "diagnostic and policy remediation beads must match for capability {}",
            row.capability_id
        );
    }
}

#[test]
fn rgc_016a_all_rows_reference_valid_product_surface_beads() {
    let contract = parse_contract();
    let surface_beads: BTreeSet<&str> = contract
        .product_surfaces
        .iter()
        .map(|s| s.surface_bead.as_str())
        .collect();
    for row in &contract.capability_rows {
        assert!(
            surface_beads.contains(row.product_surface_bead.as_str()),
            "capability {} references unknown product_surface_bead {}",
            row.capability_id,
            row.product_surface_bead
        );
    }
}
