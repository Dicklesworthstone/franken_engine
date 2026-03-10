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

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const CONTRACT_SCHEMA_VERSION: &str = "franken-engine.rgc-support-surface-contract.v1";
const MODE_MATRIX_SCHEMA_VERSION: &str = "franken-engine.rgc-support-surface-mode-matrix.v1";
const CONTRACT_JSON: &str = include_str!("../../../docs/support_surface_contract.json");
const MODE_MATRIX_JSON: &str = include_str!("../../../docs/support_surface_mode_matrix.json");
const REACT_CONTRACT_JSON: &str =
    include_str!("../../../docs/rgc_react_capability_contract_v1.json");
const PLATFORM_MATRIX_JSON: &str = include_str!("../../../docs/rgc_cross_platform_matrix_v1.json");

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SupportSurfaceContract {
    schema_version: String,
    contract_version: String,
    bead_id: String,
    policy_id: String,
    source_inputs: Vec<String>,
    allowed_support_statuses: Vec<String>,
    claim_language_states: Vec<String>,
    surface_rows: Vec<SurfaceRow>,
    required_log_keys: Vec<String>,
    required_artifacts: Vec<String>,
    gate_runner: GateRunner,
    operator_verification: Vec<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SurfaceRow {
    surface_id: String,
    area: String,
    entry_surface: String,
    support_status: String,
    claim_language_state: String,
    current_behavior: String,
    evidence_sources: Vec<String>,
    linked_capability_ids: Option<Vec<String>>,
    linked_platform_targets: Option<Vec<String>>,
    linked_fallback_reasons: Option<Vec<String>>,
    mode_matrix_row_id: Option<String>,
    user_visible_diagnostic: Option<UserVisibleDiagnostic>,
    fallback_policy: FallbackPolicy,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct UserVisibleDiagnostic {
    error_code: Option<String>,
    diagnostic_surface: String,
    message_template: String,
    remediation: String,
    remediation_bead: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct FallbackPolicy {
    fallback_mode: String,
    waiver_required: bool,
    max_waiver_age_hours: Option<u64>,
    user_visible_diagnostics_required: bool,
    remediation_bead: String,
    target_milestone: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SupportSurfaceModeMatrix {
    schema_version: String,
    contract_version: String,
    generated_by: String,
    generated_at_utc: String,
    modes: Vec<ModeContract>,
    surface_mode_rows: Vec<SurfaceModeRow>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ModeContract {
    mode_id: String,
    precedence: u64,
    capture_semantics: String,
    lossless: bool,
    description: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SurfaceModeRow {
    row_id: String,
    surface_id: String,
    allowed_modes: Vec<String>,
    publishable_modes: Vec<String>,
    blocked_modes: Vec<String>,
    rationale: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ReactCapabilityContract {
    capability_rows: Vec<ReactCapabilityRow>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ReactCapabilityRow {
    capability_id: String,
    support_status: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CrossPlatformMatrix {
    targets: Vec<PlatformTarget>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct PlatformTarget {
    target_id: String,
    tier: String,
    required: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct GateRunner {
    script: String,
    replay_wrapper: String,
    strict_mode: String,
    manifest_schema_version: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn read_gate_script() -> String {
    let path = repo_root().join("scripts/run_rgc_support_surface_contract.sh");
    read_to_string(&path)
}

fn parse_contract() -> SupportSurfaceContract {
    serde_json::from_str(CONTRACT_JSON).expect("support surface contract must parse")
}

fn parse_mode_matrix() -> SupportSurfaceModeMatrix {
    serde_json::from_str(MODE_MATRIX_JSON).expect("support surface mode matrix must parse")
}

fn parse_react_contract() -> ReactCapabilityContract {
    serde_json::from_str(REACT_CONTRACT_JSON).expect("react capability contract must parse")
}

fn parse_platform_matrix() -> CrossPlatformMatrix {
    serde_json::from_str(PLATFORM_MATRIX_JSON).expect("cross platform matrix must parse")
}

#[test]
fn rgc_911b_doc_contains_required_sections() {
    let path = repo_root().join("docs/RGC_SUPPORT_SURFACE_CONTRACT_V1.md");
    let doc = read_to_string(&path);

    for section in [
        "# RGC Support Surface Contract V1",
        "## Purpose",
        "## Surface Families",
        "## Current Support Boundary",
        "## Observability Mode Matrix",
        "## Diagnostics And Remediation",
        "## Structured Logging And Artifacts",
        "## Operator Verification",
    ] {
        assert!(
            doc.contains(section),
            "missing section in {}: {section}",
            path.display()
        );
    }
}

#[test]
fn rgc_911b_contract_is_versioned_and_covers_required_areas() {
    let contract = parse_contract();

    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.contract_version, "1.0.0");
    assert_eq!(contract.bead_id, "bd-1lsy.10.11.2");
    assert_eq!(contract.policy_id, "policy-rgc-support-surface-contract-v1");

    let statuses: BTreeSet<_> = contract
        .allowed_support_statuses
        .iter()
        .map(String::as_str)
        .collect();
    for status in ["shipped", "deferred", "unsupported", "candidate"] {
        assert!(statuses.contains(status), "missing allowed status {status}");
    }

    let claim_states: BTreeSet<_> = contract
        .claim_language_states
        .iter()
        .map(String::as_str)
        .collect();
    for state in ["shipped_fact", "target_only"] {
        assert!(
            claim_states.contains(state),
            "missing claim language state {state}"
        );
    }

    let areas: BTreeSet<_> = contract
        .surface_rows
        .iter()
        .map(|row| row.area.as_str())
        .collect();
    for area in [
        "parser",
        "typescript",
        "runtime",
        "module",
        "platform_support",
        "observability_mode",
    ] {
        assert!(areas.contains(area), "missing required area {area}");
    }

    for input in &contract.source_inputs {
        let path = repo_root().join(input);
        assert!(
            path.exists(),
            "missing declared source input {}",
            path.display()
        );
    }

    for row in &contract.surface_rows {
        assert!(
            !row.entry_surface.is_empty(),
            "entry surface must not be empty"
        );
        assert!(
            !row.current_behavior.is_empty(),
            "current behavior must not be empty for {}",
            row.surface_id
        );
        assert!(
            !row.evidence_sources.is_empty(),
            "evidence sources must not be empty for {}",
            row.surface_id
        );
        for source in &row.evidence_sources {
            let path = repo_root().join(source);
            assert!(
                path.exists(),
                "missing evidence source {} for {}",
                path.display(),
                row.surface_id
            );
        }
    }
}

#[test]
fn rgc_911b_non_shipped_rows_have_guidance_and_target_only_language() {
    let contract = parse_contract();

    for row in &contract.surface_rows {
        if row.support_status == "shipped" {
            assert_eq!(
                row.claim_language_state, "shipped_fact",
                "shipped rows must use shipped_fact language"
            );
            continue;
        }

        assert_eq!(
            row.claim_language_state, "target_only",
            "non-shipped rows must remain target-only"
        );

        let diag = row.user_visible_diagnostic.as_ref().unwrap_or_else(|| {
            panic!(
                "non-shipped row {} missing user-visible diagnostic",
                row.surface_id
            )
        });
        assert!(
            !diag.diagnostic_surface.is_empty(),
            "diagnostic surface missing for {}",
            row.surface_id
        );
        assert!(
            !diag.message_template.is_empty(),
            "message template missing for {}",
            row.surface_id
        );
        assert!(
            !diag.remediation.is_empty(),
            "remediation missing for {}",
            row.surface_id
        );
        assert_eq!(diag.remediation_bead, "bd-1lsy.10.11.2");
        assert!(
            row.fallback_policy.user_visible_diagnostics_required,
            "non-shipped row {} must require user-visible diagnostics",
            row.surface_id
        );
        assert_eq!(row.fallback_policy.remediation_bead, "bd-1lsy.10.11.2");
    }
}

#[test]
fn rgc_911b_react_rows_reference_real_capability_ids() {
    let contract = parse_contract();
    let react_contract = parse_react_contract();
    let capability_statuses: BTreeMap<_, _> = react_contract
        .capability_rows
        .iter()
        .map(|row| (row.capability_id.as_str(), row.support_status.as_str()))
        .collect();

    let compile_row = contract
        .surface_rows
        .iter()
        .find(|row| row.surface_id == "runtime.react_compile_contract")
        .expect("compile row must exist");
    for capability_id in compile_row
        .linked_capability_ids
        .as_ref()
        .expect("compile row should link capabilities")
    {
        let status = capability_statuses
            .get(capability_id.as_str())
            .unwrap_or_else(|| {
                panic!("missing linked capability {capability_id} in react contract")
            });
        assert_eq!(
            *status, "deferred",
            "compile-linked capability {capability_id} should remain deferred"
        );
    }

    let execution_row = contract
        .surface_rows
        .iter()
        .find(|row| row.surface_id == "runtime.react_execution_entrypoints")
        .expect("execution row must exist");
    for capability_id in execution_row
        .linked_capability_ids
        .as_ref()
        .expect("execution row should link capabilities")
    {
        let status = capability_statuses
            .get(capability_id.as_str())
            .unwrap_or_else(|| {
                panic!("missing linked capability {capability_id} in react contract")
            });
        assert_eq!(
            *status, "unsupported",
            "execution-linked capability {capability_id} should remain unsupported"
        );
    }
}

#[test]
fn rgc_911b_platform_candidate_matches_cross_platform_matrix() {
    let contract = parse_contract();
    let platform_matrix = parse_platform_matrix();
    let targets: BTreeMap<_, _> = platform_matrix
        .targets
        .iter()
        .map(|target| (target.target_id.as_str(), target))
        .collect();

    let row = contract
        .surface_rows
        .iter()
        .find(|row| row.surface_id == "platform.windows_arm64_candidate")
        .expect("windows arm64 candidate row must exist");
    assert_eq!(row.support_status, "candidate");

    for target_id in row
        .linked_platform_targets
        .as_ref()
        .expect("platform row should link targets")
    {
        let target = targets
            .get(target_id.as_str())
            .unwrap_or_else(|| panic!("missing linked platform target {target_id}"));
        assert_eq!(target.tier, "candidate");
        assert!(
            !target.required,
            "candidate platform target {} must not be required",
            target_id
        );
    }
}

#[test]
fn rgc_911b_mode_matrix_is_versioned_and_complete() {
    let matrix = parse_mode_matrix();

    assert_eq!(matrix.schema_version, MODE_MATRIX_SCHEMA_VERSION);
    assert_eq!(matrix.contract_version, "1.0.0");
    assert_eq!(matrix.generated_by, "bd-1lsy.10.11.2");
    assert!(matrix.generated_at_utc.ends_with('Z'));

    let mode_ids: BTreeSet<_> = matrix
        .modes
        .iter()
        .map(|mode| mode.mode_id.as_str())
        .collect();
    for mode_id in [
        "default_capture",
        "degraded",
        "exact_shadow",
        "support_bundle_export",
        "incident_full_capture",
    ] {
        assert!(mode_ids.contains(mode_id), "missing mode {mode_id}");
    }

    let precedences: BTreeSet<_> = matrix.modes.iter().map(|mode| mode.precedence).collect();
    assert_eq!(
        precedences.len(),
        matrix.modes.len(),
        "mode precedences must be unique"
    );
}

#[test]
fn rgc_911b_mode_matrix_links_contract_rows_and_blocks_degraded_where_required() {
    let contract = parse_contract();
    let matrix = parse_mode_matrix();

    let known_modes: BTreeSet<_> = matrix
        .modes
        .iter()
        .map(|mode| mode.mode_id.as_str())
        .collect();
    let mode_rows: BTreeMap<_, _> = matrix
        .surface_mode_rows
        .iter()
        .map(|row| (row.row_id.as_str(), row))
        .collect();

    for row in &matrix.surface_mode_rows {
        for mode in row
            .allowed_modes
            .iter()
            .chain(row.publishable_modes.iter())
            .chain(row.blocked_modes.iter())
        {
            assert!(
                known_modes.contains(mode.as_str()),
                "surface mode row {} references unknown mode {}",
                row.row_id,
                mode
            );
        }
        assert!(
            !row.rationale.is_empty(),
            "rationale missing for {}",
            row.row_id
        );
    }

    for contract_row in &contract.surface_rows {
        if let Some(mode_row_id) = contract_row.mode_matrix_row_id.as_deref() {
            let mode_row = mode_rows.get(mode_row_id).unwrap_or_else(|| {
                panic!(
                    "contract row {} references missing mode row {}",
                    contract_row.surface_id, mode_row_id
                )
            });
            assert_eq!(
                mode_row.surface_id, contract_row.surface_id,
                "mode row {} should bind the same surface id",
                mode_row_id
            );
        }
    }

    for row_id in [
        "runtime.doctor_support_bundle_export",
        "observability.lossless_evidence_paths",
    ] {
        let row = mode_rows
            .get(row_id)
            .unwrap_or_else(|| panic!("missing required mode row {row_id}"));
        assert!(
            row.blocked_modes.iter().any(|mode| mode == "degraded"),
            "row {row_id} must block degraded mode"
        );
    }
}

#[test]
fn rgc_911b_contract_references_gate_and_expected_artifacts() {
    let contract = parse_contract();

    let artifacts: BTreeSet<_> = contract
        .required_artifacts
        .iter()
        .map(String::as_str)
        .collect();
    for artifact in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "trace_ids.json",
        "support_surface_contract_report.json",
        "support_surface_contract.json",
        "support_surface_mode_matrix.json",
        "step_logs/step_*.log",
    ] {
        assert!(artifacts.contains(artifact), "missing artifact {artifact}");
    }

    assert_eq!(
        contract.gate_runner.script,
        "scripts/run_rgc_support_surface_contract.sh"
    );
    assert_eq!(
        contract.gate_runner.replay_wrapper,
        "scripts/e2e/rgc_support_surface_contract_replay.sh"
    );
    assert_eq!(contract.gate_runner.strict_mode, "ci");
    assert_eq!(
        contract.gate_runner.manifest_schema_version,
        "franken-engine.rgc-support-surface-contract.run-manifest.v1"
    );

    let gate_path = repo_root().join(&contract.gate_runner.script);
    let replay_path = repo_root().join(&contract.gate_runner.replay_wrapper);
    assert!(
        gate_path.exists(),
        "missing gate script {}",
        gate_path.display()
    );
    assert!(
        replay_path.exists(),
        "missing replay script {}",
        replay_path.display()
    );

    assert!(
        contract
            .operator_verification
            .iter()
            .any(|command| command.contains("support_surface_contract")),
        "operator verification should reference the support-surface gate"
    );
}

#[test]
fn rgc_911b_gate_script_uses_repo_local_rch_target_and_rejects_local_fallback() {
    let script = read_gate_script();

    assert!(
        script.contains("target_rch_rgc_support_surface_contract_"),
        "gate script should use a dedicated repo-local remote target dir"
    );
    assert!(
        !script.contains("/tmp/rch_target_rgc_support_surface_contract_"),
        "gate script must not default to /tmp for the remote cargo target dir"
    );
    assert!(
        script.contains("rch reported local fallback; refusing local execution for heavy command"),
        "gate script must fail closed if rch falls back to local execution"
    );
}

#[test]
fn rgc_911b_log_keys_remain_stable() {
    let contract = parse_contract();
    let keys: BTreeSet<_> = contract
        .required_log_keys
        .iter()
        .map(String::as_str)
        .collect();

    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "surface_id",
        "outcome",
        "error_code",
    ] {
        assert!(keys.contains(key), "missing required log key {key}");
    }
}
