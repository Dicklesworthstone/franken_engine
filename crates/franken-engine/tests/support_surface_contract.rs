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
fn rgc_911b_callback_stdlib_gap_row_matches_runtime_contract() {
    let contract = parse_contract();
    let row = contract
        .surface_rows
        .iter()
        .find(|row| row.surface_id == "runtime.callback_stdlib_collection_callbacks")
        .expect("callback stdlib row must exist");

    assert_eq!(row.area, "runtime");
    assert_eq!(row.support_status, "unsupported");
    assert_eq!(row.claim_language_state, "target_only");
    assert_eq!(row.fallback_policy.fallback_mode, "fail_closed_type_error");
    assert!(row.fallback_policy.waiver_required);
    assert_eq!(row.fallback_policy.max_waiver_age_hours, Some(168));

    let evidence_sources: BTreeSet<_> = row.evidence_sources.iter().map(String::as_str).collect();
    for source in [
        "crates/franken-engine/src/stdlib.rs",
        "crates/franken-engine/src/callback_stdlib_dispatch.rs",
    ] {
        assert!(
            evidence_sources.contains(source),
            "callback stdlib row missing evidence source {source}"
        );
    }

    let fallback_reasons: BTreeSet<_> = row
        .linked_fallback_reasons
        .as_ref()
        .expect("callback stdlib row should link fallback reasons")
        .iter()
        .map(String::as_str)
        .collect();
    assert!(
        fallback_reasons.contains("requires_callback_or_heap_access_use_interpreter_dispatch"),
        "callback stdlib row must expose the fail-closed fallback reason"
    );

    let diag = row
        .user_visible_diagnostic
        .as_ref()
        .expect("callback stdlib row must include a user-visible diagnostic");
    assert_eq!(diag.diagnostic_surface, "runtime stdlib builtin dispatch");
    assert!(
        diag.message_template
            .contains("requires callback or heap access (use interpreter dispatch)"),
        "callback stdlib diagnostic must preserve the shipped fail-closed message"
    );
}

#[test]
fn rgc_911b_callback_stdlib_gap_tracks_shipped_fail_closed_builtin_text() {
    let stdlib = read_to_string(&repo_root().join("crates/franken-engine/src/stdlib.rs"));

    for builtin in [
        "BuiltinId::ArrayPrototypeMap",
        "BuiltinId::ArrayPrototypeFilter",
        "BuiltinId::ArrayPrototypeReduce",
        "BuiltinId::ArrayPrototypeReduceRight",
        "BuiltinId::ArrayPrototypeForEach",
        "BuiltinId::ArrayPrototypeSome",
        "BuiltinId::ArrayPrototypeEvery",
        "BuiltinId::ArrayPrototypeFind",
        "BuiltinId::ArrayPrototypeFindIndex",
        "BuiltinId::ArrayPrototypeSort",
        "BuiltinId::MapPrototypeForEach",
        "BuiltinId::SetPrototypeForEach",
    ] {
        assert!(
            stdlib.contains(builtin),
            "stdlib.rs must continue to install/dispatch {builtin}"
        );
    }

    assert!(
        stdlib.contains("requires callback or heap access (use interpreter dispatch)"),
        "stdlib.rs must retain the shipped fail-closed callback/heap access diagnostic"
    );
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
fn rgc_911b_gate_script_manifest_reuses_contract_operator_verification_commands() {
    let script = read_gate_script();

    assert!(
        script.contains("contract_operator_verification_json"),
        "gate script should collect the published operator verification commands"
    );
    assert!(
        script.contains("jq '.operator_verification' \"$contract_json\""),
        "gate script should read operator verification commands from the contract JSON"
    );
    assert!(
        script.contains("] + $contract_operator_verification"),
        "gate manifest should append the published operator verification commands"
    );
}

#[test]
fn rgc_911b_gate_script_copies_contract_artifacts_before_validation_can_fail() {
    let script = read_gate_script();
    let copy_index = script
        .find("copy_contract_artifacts\nvalidate_source_inputs")
        .expect("gate script should copy contract artifacts before validation");
    let run_mode_index = script
        .find("if [[ \"$main_exit\" -eq 0 ]]; then\n  run_mode")
        .expect("gate script should only run cargo gates after validation");
    assert!(
        copy_index < run_mode_index,
        "artifact copying must happen before validation-gated cargo execution"
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

#[test]
fn rgc_911b_surface_ids_are_unique() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for row in &contract.surface_rows {
        assert!(
            seen.insert(row.surface_id.clone()),
            "duplicate surface_id: {}",
            row.surface_id
        );
    }
}

#[test]
fn rgc_911b_surface_id_format_follows_area_dot_name_convention() {
    let contract = parse_contract();
    for row in &contract.surface_rows {
        assert!(
            row.surface_id.contains('.'),
            "surface_id must use area.name format: {}",
            row.surface_id
        );
        let parts: Vec<&str> = row.surface_id.splitn(2, '.').collect();
        assert!(
            !parts[0].is_empty() && !parts[1].is_empty(),
            "surface_id must have non-empty area and name: {}",
            row.surface_id
        );
    }
}

#[test]
fn rgc_911b_shipped_rows_have_no_waiver_requirement() {
    let contract = parse_contract();
    for row in &contract.surface_rows {
        if row.support_status == "shipped" {
            assert!(
                !row.fallback_policy.waiver_required,
                "shipped row {} must not require waivers",
                row.surface_id
            );
            assert_eq!(
                row.fallback_policy.max_waiver_age_hours, None,
                "shipped row {} must not declare max_waiver_age_hours",
                row.surface_id
            );
        }
    }
}

#[test]
fn rgc_911b_waiver_rows_have_bounded_age() {
    let contract = parse_contract();
    for row in &contract.surface_rows {
        if row.fallback_policy.waiver_required {
            let hours = row.fallback_policy.max_waiver_age_hours.unwrap_or_else(|| {
                panic!(
                    "row {} requires waiver but missing max_waiver_age_hours",
                    row.surface_id
                )
            });
            assert!(
                hours > 0 && hours <= 720,
                "max_waiver_age_hours for {} must be 1..=720, got {}",
                row.surface_id,
                hours
            );
        }
    }
}

#[test]
fn rgc_911b_evidence_sources_are_repo_relative_and_safe() {
    let contract = parse_contract();
    for row in &contract.surface_rows {
        for source in &row.evidence_sources {
            assert!(
                !source.starts_with('/'),
                "evidence source must be repo-relative for {}: {source}",
                row.surface_id
            );
            assert!(
                !source.contains(".."),
                "evidence source must not traverse upward for {}: {source}",
                row.surface_id
            );
        }
    }
}

#[test]
fn rgc_911b_contract_row_count_matches_expected() {
    let contract = parse_contract();
    assert_eq!(
        contract.surface_rows.len(),
        13,
        "contract must declare exactly 13 surface rows"
    );
}

#[test]
fn rgc_911b_support_status_distribution_is_balanced() {
    let contract = parse_contract();
    let mut status_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for row in &contract.surface_rows {
        *status_counts
            .entry(row.support_status.as_str())
            .or_insert(0) += 1;
    }

    assert!(
        status_counts.contains_key("shipped"),
        "must have at least one shipped surface"
    );
    assert!(
        status_counts.get("shipped").copied().unwrap_or(0) >= 3,
        "must have at least 3 shipped surfaces"
    );
    assert!(
        status_counts.contains_key("unsupported"),
        "must have at least one unsupported surface"
    );
}

#[test]
fn rgc_911b_mode_matrix_surface_mode_rows_have_unique_row_ids() {
    let matrix = parse_mode_matrix();
    let mut seen = BTreeSet::new();
    for row in &matrix.surface_mode_rows {
        assert!(
            seen.insert(row.row_id.clone()),
            "duplicate mode matrix row_id: {}",
            row.row_id
        );
    }
}

#[test]
fn rgc_911b_mode_matrix_publishable_is_subset_of_allowed() {
    let matrix = parse_mode_matrix();
    for row in &matrix.surface_mode_rows {
        let allowed: BTreeSet<_> = row.allowed_modes.iter().collect();
        for mode in &row.publishable_modes {
            assert!(
                allowed.contains(mode),
                "publishable mode {mode} in {} is not in allowed_modes",
                row.row_id
            );
        }
    }
}

#[test]
fn rgc_911b_mode_matrix_blocked_and_allowed_are_disjoint() {
    let matrix = parse_mode_matrix();
    for row in &matrix.surface_mode_rows {
        let allowed: BTreeSet<_> = row.allowed_modes.iter().collect();
        let blocked: BTreeSet<_> = row.blocked_modes.iter().collect();
        let overlap: Vec<_> = allowed.intersection(&blocked).collect();
        assert!(
            overlap.is_empty(),
            "mode matrix row {} has modes in both allowed and blocked: {:?}",
            row.row_id,
            overlap
        );
    }
}

#[test]
fn rgc_911b_mode_precedences_are_contiguous_from_zero() {
    let matrix = parse_mode_matrix();
    let mut precedences: Vec<u64> = matrix.modes.iter().map(|m| m.precedence).collect();
    precedences.sort();
    for (i, prec) in precedences.iter().enumerate() {
        assert_eq!(
            *prec, i as u64,
            "mode precedences must be contiguous from 0, gap at position {}",
            i
        );
    }
}

#[test]
fn rgc_911b_generated_at_utc_is_valid_iso8601() {
    let contract: serde_json::Value =
        serde_json::from_str(CONTRACT_JSON).expect("contract must parse as Value");
    let ts = contract["generated_at_utc"]
        .as_str()
        .expect("generated_at_utc must be a string");
    assert!(ts.ends_with('Z'), "generated_at_utc must be UTC: {ts}");
    assert!(ts.contains('T'), "generated_at_utc must contain T: {ts}");
    assert!(
        ts.len() >= 20,
        "generated_at_utc must be full ISO-8601: {ts}"
    );
}

#[test]
fn rgc_911b_operator_verification_commands_reference_correct_contract() {
    let contract = parse_contract();
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("support_surface_contract")),
        "at least one operator verification command must reference support_surface_contract"
    );
    for cmd in &contract.operator_verification {
        assert!(
            cmd.contains("support_surface") || cmd.contains("jq"),
            "operator verification command must reference support_surface or jq: {cmd}"
        );
    }
    assert!(
        contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("$PWD/target_rch_rgc_support_surface_contract_verify")),
        "operator verification should document the repo-local target dir example"
    );
    assert!(
        !contract
            .operator_verification
            .iter()
            .any(|cmd| cmd.contains("/tmp/rch_target_rgc_support_surface_contract")),
        "operator verification must not point back to /tmp-backed target dirs"
    );
}

// ===== PearlTower enrichment =====

#[test]
fn enrichment_contract_serde_roundtrip_via_json_value() {
    // Parse the real contract JSON into a serde_json::Value and back to string,
    // then re-parse as SupportSurfaceContract — verifies Deserialize is stable.
    let original: serde_json::Value =
        serde_json::from_str(CONTRACT_JSON).expect("contract must parse as Value");
    let re_serialized = serde_json::to_string(&original).expect("re-serialize must succeed");
    let contract: SupportSurfaceContract =
        serde_json::from_str(&re_serialized).expect("roundtrip contract must parse");
    assert_eq!(contract.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(contract.bead_id, "bd-1lsy.10.11.2");
    assert!(!contract.surface_rows.is_empty());
}

#[test]
fn enrichment_mode_matrix_serde_roundtrip_via_json_value() {
    // Same roundtrip check for the mode matrix document.
    let original: serde_json::Value =
        serde_json::from_str(MODE_MATRIX_JSON).expect("mode matrix must parse as Value");
    let re_serialized = serde_json::to_string(&original).expect("re-serialize must succeed");
    let matrix: SupportSurfaceModeMatrix =
        serde_json::from_str(&re_serialized).expect("roundtrip mode matrix must parse");
    assert_eq!(matrix.schema_version, MODE_MATRIX_SCHEMA_VERSION);
    assert!(!matrix.modes.is_empty());
    assert!(!matrix.surface_mode_rows.is_empty());
}

#[test]
fn enrichment_cross_schema_bead_ids_are_distinct_per_document() {
    // The contract bead_id and the mode matrix generated_by may share the same
    // bead but must be self-consistent: contract bead_id equals mode matrix generated_by,
    // and both carry the same well-formed prefix.
    let contract = parse_contract();
    let matrix: serde_json::Value =
        serde_json::from_str(MODE_MATRIX_JSON).expect("mode matrix must parse as Value");
    let matrix_generated_by = matrix["generated_by"]
        .as_str()
        .expect("mode matrix generated_by must be a string");
    // Both must start with the standard bead-id prefix "bd-"
    assert!(
        contract.bead_id.starts_with("bd-"),
        "contract bead_id must start with 'bd-': {}",
        contract.bead_id
    );
    assert!(
        matrix_generated_by.starts_with("bd-"),
        "mode matrix generated_by must start with 'bd-': {matrix_generated_by}"
    );
    // They should refer to the same originating bead
    assert_eq!(
        contract.bead_id, matrix_generated_by,
        "contract bead_id and mode matrix generated_by must agree"
    );
}

#[test]
fn enrichment_cross_schema_schema_versions_carry_vendor_prefix() {
    // All schema_version strings across both documents must begin with the
    // project vendor prefix "franken-engine."
    let contract = parse_contract();
    let matrix = parse_mode_matrix();
    assert!(
        contract.schema_version.starts_with("franken-engine."),
        "contract schema_version must carry vendor prefix: {}",
        contract.schema_version
    );
    assert!(
        matrix.schema_version.starts_with("franken-engine."),
        "mode matrix schema_version must carry vendor prefix: {}",
        matrix.schema_version
    );
    // gate_runner manifest schema version must also carry the prefix
    assert!(
        contract
            .gate_runner
            .manifest_schema_version
            .starts_with("franken-engine."),
        "gate_runner manifest_schema_version must carry vendor prefix: {}",
        contract.gate_runner.manifest_schema_version
    );
}

#[test]
fn enrichment_no_duplicate_entries_in_allowed_support_statuses() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for status in &contract.allowed_support_statuses {
        assert!(
            seen.insert(status.as_str()),
            "duplicate entry in allowed_support_statuses: {status}"
        );
    }
}

#[test]
fn enrichment_no_duplicate_entries_in_required_log_keys() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for key in &contract.required_log_keys {
        assert!(
            seen.insert(key.as_str()),
            "duplicate entry in required_log_keys: {key}"
        );
    }
}

#[test]
fn enrichment_no_duplicate_entries_in_required_artifacts() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for artifact in &contract.required_artifacts {
        assert!(
            seen.insert(artifact.as_str()),
            "duplicate entry in required_artifacts: {artifact}"
        );
    }
}

#[test]
fn enrichment_no_duplicate_entries_in_source_inputs() {
    let contract = parse_contract();
    let mut seen = BTreeSet::new();
    for input in &contract.source_inputs {
        assert!(
            seen.insert(input.as_str()),
            "duplicate entry in source_inputs: {input}"
        );
    }
}

#[test]
fn enrichment_no_duplicate_mode_ids_in_mode_matrix() {
    let matrix = parse_mode_matrix();
    let mut seen = BTreeSet::new();
    for mode in &matrix.modes {
        assert!(
            seen.insert(mode.mode_id.as_str()),
            "duplicate mode_id in modes list: {}",
            mode.mode_id
        );
    }
}

#[test]
fn enrichment_edge_case_surface_row_evidence_sources_nonempty() {
    // Boundary: every surface row, regardless of status, must have at least one
    // evidence source — an empty slice is an editorial gap.
    let contract = parse_contract();
    for row in &contract.surface_rows {
        assert!(
            !row.evidence_sources.is_empty(),
            "surface row {} has zero evidence sources",
            row.surface_id
        );
    }
}

#[test]
fn enrichment_edge_case_waiver_age_boundary_within_one_month() {
    // Boundary value check: max_waiver_age_hours must never exceed 720 (30 days).
    let contract = parse_contract();
    for row in &contract.surface_rows {
        if let Some(hours) = row.fallback_policy.max_waiver_age_hours {
            assert!(
                hours >= 1,
                "max_waiver_age_hours must be >= 1 for {}",
                row.surface_id
            );
            assert!(
                hours <= 720,
                "max_waiver_age_hours must be <= 720 for {}: got {hours}",
                row.surface_id
            );
        }
    }
}

#[test]
fn enrichment_clone_debug_derive_contract_types() {
    // Exercises the Clone and Debug derives on the main contract types to confirm
    // they compile and produce non-empty output.
    let contract = parse_contract();

    let contract_clone = contract.clone();
    assert_eq!(contract, contract_clone);
    let debug_str = format!("{contract:?}");
    assert!(!debug_str.is_empty());

    if let Some(row) = contract.surface_rows.first() {
        let row_clone = row.clone();
        assert_eq!(row, &row_clone);
        let row_debug = format!("{row:?}");
        assert!(!row_debug.is_empty());

        let policy_clone = row.fallback_policy.clone();
        assert_eq!(row.fallback_policy, policy_clone);
        let policy_debug = format!("{:?}", row.fallback_policy);
        assert!(!policy_debug.is_empty());

        if let Some(ref diag) = row.user_visible_diagnostic {
            let diag_clone = diag.clone();
            assert_eq!(diag, &diag_clone);
            let diag_debug = format!("{diag:?}");
            assert!(!diag_debug.is_empty());
        }
    }

    let matrix = parse_mode_matrix();
    let matrix_clone = matrix.clone();
    assert_eq!(matrix, matrix_clone);
    let matrix_debug = format!("{matrix:?}");
    assert!(!matrix_debug.is_empty());

    if let Some(mode) = matrix.modes.first() {
        let mode_clone = mode.clone();
        assert_eq!(mode, &mode_clone);
    }

    if let Some(smr) = matrix.surface_mode_rows.first() {
        let smr_clone = smr.clone();
        assert_eq!(smr, &smr_clone);
    }
}
