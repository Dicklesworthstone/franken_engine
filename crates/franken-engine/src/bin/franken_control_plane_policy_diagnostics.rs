#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::budget_propagation_contract::{
    BudgetBoundaryKind, BudgetPropagationError,
};
use frankenengine_engine::control_plane_policy_diagnostics::{
    ControlPlaneDiagnostic, DiagnosticEmitter, DiagnosticReport,
};
use frankenengine_engine::operator_diagnostic_contract::{
    BEAD_ID, BoundaryPolicyMappingContract, COMPONENT as CONTRACT_COMPONENT, DiagnosticEntry,
    DiagnosticEvent, InternalFailureKind, POLICY_ID, PolicyMapping, SCHEMA_VERSION,
    build_diagnostic_event,
};
use frankenengine_engine::outcome_capability_narrowing::{
    BoundaryOutcome, CapabilityToken, NarrowingViolation,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use serde::Serialize;
use sha2::{Digest, Sha256};

const OUTPUT_SCHEMA_VERSION: &str = "franken-engine.franken_control_plane_policy_diagnostics.v1";
const BUNDLE_COMPONENT: &str = "control_plane_policy_diagnostics_bundle";
const OPERATOR_ARTIFACT_SCHEMA_VERSION: &str =
    "franken-engine.operator-diagnostic-contract.bundle.v1";
const USER_ERROR_TRANSLATION_MATRIX_SCHEMA_VERSION: &str =
    "franken-engine.user-error-translation-matrix.v1";
const REMEDIATION_LINKAGE_INDEX_SCHEMA_VERSION: &str =
    "franken-engine.remediation-linkage-index.v1";
const TRACE_IDS_SCHEMA_VERSION: &str =
    "franken-engine.control-plane-policy-diagnostics.trace-ids.v1";
const RUN_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.control-plane-policy-diagnostics.run-manifest.v1";
const REPORT_EVENT_SCHEMA_VERSION: &str =
    "franken-engine.control-plane-policy-diagnostics.events.v1";
const OPERATOR_SAMPLE_REPLAY_MODE: &str = "strict";
const BOUNDARY_POLICY_MAPPING_CONTRACT_FILE: &str = "boundary_policy_mapping_contract.json";
const OPERATOR_DIAGNOSTIC_CONTRACT_FILE: &str = "operator_diagnostic_contract.json";
const USER_ERROR_TRANSLATION_MATRIX_FILE: &str = "user_error_translation_matrix.json";
const REMEDIATION_LINKAGE_INDEX_FILE: &str = "remediation_linkage_index.json";
const CONTROL_PLANE_POLICY_DIAGNOSTICS_REPORT_FILE: &str =
    "control_plane_policy_diagnostics_report.json";

enum CliAction {
    Help,
    Run {
        out_dir: PathBuf,
        epoch: SecurityEpoch,
    },
}

#[derive(Debug, Clone, Serialize)]
struct CommandOutput {
    schema_version: String,
    out_dir: String,
    boundary_policy_mapping_contract: String,
    operator_diagnostic_contract: String,
    user_error_translation_matrix: String,
    remediation_linkage_index: String,
    control_plane_policy_diagnostics_report: String,
    trace_ids: String,
    run_manifest: String,
    events_jsonl: String,
    commands_txt: String,
    step_logs_dir: String,
    summary_md: String,
    env_json: String,
    repro_lock: String,
    boundary_policy_mapping_artifact_hash: String,
    operator_diagnostic_contract_hash: String,
    user_error_translation_matrix_hash: String,
    remediation_linkage_index_hash: String,
    control_plane_policy_diagnostics_report_hash: String,
    operator_mapping_count: usize,
    operator_diagnostic_count: usize,
    control_plane_diagnostic_count: usize,
    release_blocked_in_sample_report: bool,
}

#[derive(Debug, Clone)]
struct BundleArtifacts {
    out_dir: PathBuf,
    boundary_policy_mapping_contract_path: PathBuf,
    operator_diagnostic_contract_path: PathBuf,
    user_error_translation_matrix_path: PathBuf,
    remediation_linkage_index_path: PathBuf,
    control_plane_policy_diagnostics_report_path: PathBuf,
    trace_ids_path: PathBuf,
    run_manifest_path: PathBuf,
    events_path: PathBuf,
    commands_path: PathBuf,
    step_logs_dir: PathBuf,
    summary_path: PathBuf,
    env_path: PathBuf,
    repro_lock_path: PathBuf,
    boundary_policy_mapping_artifact_hash: String,
    operator_diagnostic_contract_hash: String,
    user_error_translation_matrix_hash: String,
    remediation_linkage_index_hash: String,
    control_plane_policy_diagnostics_report_hash: String,
    operator_mapping_count: usize,
    operator_diagnostic_count: usize,
    control_plane_diagnostic_count: usize,
    release_blocked_in_sample_report: bool,
}

#[derive(Debug, Clone, Serialize)]
struct OperatorDiagnosticContractArtifact {
    schema_version: String,
    contract_schema_version: String,
    bead_id: String,
    policy_id: String,
    component: String,
    epoch: SecurityEpoch,
    integrity_verified: bool,
    coverage_count: usize,
    evidence_linked_count: usize,
    semantic_content_hash: String,
    artifact_hash: String,
    mappings: Vec<PolicyMapping>,
    sample_diagnostics: Vec<DiagnosticEntry>,
    sample_event_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct UserErrorTranslationMatrix {
    schema_version: String,
    component: String,
    policy_id: String,
    epoch_raw: u64,
    operator_rows: Vec<OperatorTranslationRow>,
    control_plane_rows: Vec<ControlPlaneTranslationRow>,
}

#[derive(Debug, Clone, Serialize)]
struct OperatorTranslationRow {
    failure_kind: String,
    error_code: String,
    severity: String,
    user_impact: String,
    operator_impact: String,
    next_action: String,
    description: String,
    remediation: String,
    evidence_required: bool,
    replay_available: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ControlPlaneTranslationRow {
    diagnostic_code: String,
    category: String,
    severity: String,
    boundary_label: Option<String>,
    sample_message: String,
    remediation_summary: String,
    remediation_steps: Vec<String>,
    doc_refs: Vec<String>,
    auto_remediable: bool,
    sample_trace_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RemediationLinkageIndex {
    schema_version: String,
    component: String,
    policy_id: String,
    epoch_raw: u64,
    operator_links: Vec<OperatorRemediationLink>,
    control_plane_links: Vec<ControlPlaneRemediationLink>,
}

#[derive(Debug, Clone, Serialize)]
struct OperatorRemediationLink {
    failure_kind: String,
    error_code: String,
    next_action: String,
    remediation: String,
    evidence_required: bool,
    replay_available: bool,
    sample_evidence_ref: Option<String>,
    sample_replay_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ControlPlaneRemediationLink {
    diagnostic_code: String,
    category: String,
    severity: String,
    boundary_label: Option<String>,
    remediation_summary: String,
    doc_refs: Vec<String>,
    auto_remediable: bool,
    sample_trace_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct TraceIdsArtifact {
    schema_version: String,
    component: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    epoch_raw: u64,
    semantic_content_hash: String,
    boundary_policy_mapping_artifact_hash: String,
    operator_diagnostic_contract_hash: String,
    user_error_translation_matrix_hash: String,
    remediation_linkage_index_hash: String,
    control_plane_policy_diagnostics_report_hash: String,
    operator_sample_trace_ids: Vec<String>,
    control_plane_sample_trace_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RunManifest {
    schema_version: String,
    component: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    epoch_raw: u64,
    semantic_content_hash: String,
    boundary_policy_mapping_artifact_hash: String,
    operator_diagnostic_contract_hash: String,
    user_error_translation_matrix_hash: String,
    remediation_linkage_index_hash: String,
    control_plane_policy_diagnostics_report_hash: String,
    operator_mapping_count: usize,
    operator_diagnostic_count: usize,
    control_plane_diagnostic_count: usize,
    release_blocked_in_sample_report: bool,
    artifact_paths: ArtifactPaths,
}

#[derive(Debug, Clone, Serialize)]
struct ArtifactPaths {
    boundary_policy_mapping_contract: String,
    operator_diagnostic_contract: String,
    user_error_translation_matrix: String,
    remediation_linkage_index: String,
    control_plane_policy_diagnostics_report: String,
    trace_ids: String,
    run_manifest: String,
    events_jsonl: String,
    commands_txt: String,
    step_logs_dir: String,
    summary_md: String,
    env_json: String,
    repro_lock: String,
}

#[derive(Debug, Clone)]
struct OperatorSampleSet {
    diagnostics: Vec<DiagnosticEntry>,
    events: Vec<DiagnosticEvent>,
    trace_ids: Vec<String>,
}

#[derive(Debug, Clone)]
struct ControlPlaneSampleSet {
    diagnostics: Vec<ControlPlaneDiagnostic>,
    report: DiagnosticReport,
    trace_ids: Vec<String>,
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let (out_dir, epoch) = match parse_args(&args[1..])? {
        CliAction::Help => {
            println!("{}", help_text());
            return Ok(());
        }
        CliAction::Run { out_dir, epoch } => (out_dir, epoch),
    };

    let artifacts = write_bundle(&out_dir, epoch, &args)?;
    let output = CommandOutput {
        schema_version: OUTPUT_SCHEMA_VERSION.to_string(),
        out_dir: artifacts.out_dir.display().to_string(),
        boundary_policy_mapping_contract: artifacts
            .boundary_policy_mapping_contract_path
            .display()
            .to_string(),
        operator_diagnostic_contract: artifacts
            .operator_diagnostic_contract_path
            .display()
            .to_string(),
        user_error_translation_matrix: artifacts
            .user_error_translation_matrix_path
            .display()
            .to_string(),
        remediation_linkage_index: artifacts
            .remediation_linkage_index_path
            .display()
            .to_string(),
        control_plane_policy_diagnostics_report: artifacts
            .control_plane_policy_diagnostics_report_path
            .display()
            .to_string(),
        trace_ids: artifacts.trace_ids_path.display().to_string(),
        run_manifest: artifacts.run_manifest_path.display().to_string(),
        events_jsonl: artifacts.events_path.display().to_string(),
        commands_txt: artifacts.commands_path.display().to_string(),
        step_logs_dir: artifacts.step_logs_dir.display().to_string(),
        summary_md: artifacts.summary_path.display().to_string(),
        env_json: artifacts.env_path.display().to_string(),
        repro_lock: artifacts.repro_lock_path.display().to_string(),
        boundary_policy_mapping_artifact_hash: artifacts.boundary_policy_mapping_artifact_hash,
        operator_diagnostic_contract_hash: artifacts.operator_diagnostic_contract_hash,
        user_error_translation_matrix_hash: artifacts.user_error_translation_matrix_hash,
        remediation_linkage_index_hash: artifacts.remediation_linkage_index_hash,
        control_plane_policy_diagnostics_report_hash: artifacts
            .control_plane_policy_diagnostics_report_hash,
        operator_mapping_count: artifacts.operator_mapping_count,
        operator_diagnostic_count: artifacts.operator_diagnostic_count,
        control_plane_diagnostic_count: artifacts.control_plane_diagnostic_count,
        release_blocked_in_sample_report: artifacts.release_blocked_in_sample_report,
    };
    let rendered = serde_json::to_string_pretty(&output).map_err(|error| error.to_string())?;
    println!("{rendered}");
    Ok(())
}

fn parse_args(args: &[String]) -> Result<CliAction, String> {
    if args.is_empty() {
        return Err(help_text());
    }

    let mut out_dir: Option<PathBuf> = None;
    let mut epoch = SecurityEpoch::from_raw(1);
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "-h" | "--help" => return Ok(CliAction::Help),
            "--out-dir" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("--out-dir requires a path".to_string());
                };
                out_dir = Some(PathBuf::from(value));
                index += 2;
            }
            "--epoch" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("--epoch requires an integer".to_string());
                };
                let raw = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid epoch value `{value}`"))?;
                epoch = SecurityEpoch::from_raw(raw);
                index += 2;
            }
            other => {
                return Err(format!(
                    "unrecognized argument `{other}`\n\n{}",
                    help_text()
                ));
            }
        }
    }

    out_dir
        .map(|out_dir| CliAction::Run { out_dir, epoch })
        .ok_or_else(|| format!("missing required --out-dir\n\n{}", help_text()))
}

fn help_text() -> String {
    "Usage: franken_control_plane_policy_diagnostics --out-dir <DIR> [--epoch <U64>]".to_string()
}

fn write_bundle(
    out_dir: &Path,
    epoch: SecurityEpoch,
    command_lines: &[String],
) -> Result<BundleArtifacts, String> {
    fs::create_dir_all(out_dir).map_err(|error| {
        format!(
            "failed to create output directory {}: {error}",
            out_dir.display()
        )
    })?;

    let contract = BoundaryPolicyMappingContract::canonical(epoch);
    let operator_samples = build_operator_samples(&contract)?;
    let control_plane_samples = build_control_plane_samples(epoch);

    let boundary_policy_mapping_contract_path = out_dir.join(BOUNDARY_POLICY_MAPPING_CONTRACT_FILE);
    let operator_diagnostic_contract_path = out_dir.join(OPERATOR_DIAGNOSTIC_CONTRACT_FILE);
    let user_error_translation_matrix_path = out_dir.join(USER_ERROR_TRANSLATION_MATRIX_FILE);
    let remediation_linkage_index_path = out_dir.join(REMEDIATION_LINKAGE_INDEX_FILE);
    let control_plane_policy_diagnostics_report_path =
        out_dir.join(CONTROL_PLANE_POLICY_DIAGNOSTICS_REPORT_FILE);
    let trace_ids_path = out_dir.join("trace_ids.json");
    let run_manifest_path = out_dir.join("run_manifest.json");
    let events_path = out_dir.join("events.jsonl");
    let commands_path = out_dir.join("commands.txt");
    let step_logs_dir = out_dir.join("step_logs");
    let summary_path = out_dir.join("summary.md");
    let env_path = out_dir.join("env.json");
    let repro_lock_path = out_dir.join("repro.lock");

    let boundary_policy_mapping_bytes =
        json_pretty_bytes(&contract, &boundary_policy_mapping_contract_path)?;
    let boundary_policy_mapping_artifact_hash = sha256_hex(&boundary_policy_mapping_bytes);

    let operator_diagnostic_contract = OperatorDiagnosticContractArtifact {
        schema_version: OPERATOR_ARTIFACT_SCHEMA_VERSION.to_string(),
        contract_schema_version: SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        component: CONTRACT_COMPONENT.to_string(),
        epoch,
        integrity_verified: contract.verify_integrity(),
        coverage_count: contract.coverage_count(),
        evidence_linked_count: contract.evidence_linked_count(),
        semantic_content_hash: contract.content_hash.to_hex(),
        artifact_hash: boundary_policy_mapping_artifact_hash.clone(),
        mappings: contract.mappings.values().cloned().collect(),
        sample_diagnostics: operator_samples.diagnostics.clone(),
        sample_event_count: operator_samples.events.len(),
    };
    let operator_diagnostic_contract_bytes = json_pretty_bytes(
        &operator_diagnostic_contract,
        &operator_diagnostic_contract_path,
    )?;
    let operator_diagnostic_contract_hash = sha256_hex(&operator_diagnostic_contract_bytes);

    let translation_matrix =
        build_user_error_translation_matrix(&contract, &control_plane_samples, epoch);
    let user_error_translation_matrix_bytes =
        json_pretty_bytes(&translation_matrix, &user_error_translation_matrix_path)?;
    let user_error_translation_matrix_hash = sha256_hex(&user_error_translation_matrix_bytes);

    let remediation_linkage_index = build_remediation_linkage_index(
        &contract,
        &operator_samples,
        &control_plane_samples,
        epoch,
    );
    let remediation_linkage_index_bytes =
        json_pretty_bytes(&remediation_linkage_index, &remediation_linkage_index_path)?;
    let remediation_linkage_index_hash = sha256_hex(&remediation_linkage_index_bytes);

    let report_bytes = json_pretty_bytes(
        &control_plane_samples.report,
        &control_plane_policy_diagnostics_report_path,
    )?;
    let control_plane_policy_diagnostics_report_hash = sha256_hex(&report_bytes);

    let trace_seed = format!(
        "{}:{}",
        boundary_policy_mapping_artifact_hash, control_plane_policy_diagnostics_report_hash
    );
    let trace_seed_hash = sha256_hex(trace_seed.as_bytes());
    let trace_id = format!(
        "trace-control-plane-policy-diagnostics-{}",
        short_hash(&trace_seed_hash)
    );
    let decision_id = format!(
        "decision-control-plane-policy-diagnostics-{}",
        short_hash(&operator_diagnostic_contract_hash)
    );

    let trace_ids = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        component: BUNDLE_COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: POLICY_ID.to_string(),
        epoch_raw: epoch.as_u64(),
        semantic_content_hash: contract.content_hash.to_hex(),
        boundary_policy_mapping_artifact_hash: boundary_policy_mapping_artifact_hash.clone(),
        operator_diagnostic_contract_hash: operator_diagnostic_contract_hash.clone(),
        user_error_translation_matrix_hash: user_error_translation_matrix_hash.clone(),
        remediation_linkage_index_hash: remediation_linkage_index_hash.clone(),
        control_plane_policy_diagnostics_report_hash: control_plane_policy_diagnostics_report_hash
            .clone(),
        operator_sample_trace_ids: operator_samples.trace_ids.clone(),
        control_plane_sample_trace_ids: control_plane_samples.trace_ids.clone(),
    };
    let trace_ids_bytes = json_pretty_bytes(&trace_ids, &trace_ids_path)?;

    let manifest = RunManifest {
        schema_version: RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        component: BUNDLE_COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: POLICY_ID.to_string(),
        epoch_raw: epoch.as_u64(),
        semantic_content_hash: contract.content_hash.to_hex(),
        boundary_policy_mapping_artifact_hash: boundary_policy_mapping_artifact_hash.clone(),
        operator_diagnostic_contract_hash: operator_diagnostic_contract_hash.clone(),
        user_error_translation_matrix_hash: user_error_translation_matrix_hash.clone(),
        remediation_linkage_index_hash: remediation_linkage_index_hash.clone(),
        control_plane_policy_diagnostics_report_hash: control_plane_policy_diagnostics_report_hash
            .clone(),
        operator_mapping_count: contract.coverage_count(),
        operator_diagnostic_count: operator_samples.diagnostics.len(),
        control_plane_diagnostic_count: control_plane_samples.diagnostics.len(),
        release_blocked_in_sample_report: control_plane_samples.report.release_blocked,
        artifact_paths: ArtifactPaths {
            boundary_policy_mapping_contract: BOUNDARY_POLICY_MAPPING_CONTRACT_FILE.to_string(),
            operator_diagnostic_contract: OPERATOR_DIAGNOSTIC_CONTRACT_FILE.to_string(),
            user_error_translation_matrix: USER_ERROR_TRANSLATION_MATRIX_FILE.to_string(),
            remediation_linkage_index: REMEDIATION_LINKAGE_INDEX_FILE.to_string(),
            control_plane_policy_diagnostics_report: CONTROL_PLANE_POLICY_DIAGNOSTICS_REPORT_FILE
                .to_string(),
            trace_ids: "trace_ids.json".to_string(),
            run_manifest: "run_manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
            step_logs_dir: "step_logs".to_string(),
            summary_md: "summary.md".to_string(),
            env_json: "env.json".to_string(),
            repro_lock: "repro.lock".to_string(),
        },
    };
    let run_manifest_bytes = json_pretty_bytes(&manifest, &run_manifest_path)?;

    let mut events_jsonl = String::new();
    for event in &operator_samples.events {
        let line = serde_json::to_string(event).map_err(|error| {
            format!(
                "failed to serialize event line for {}: {error}",
                events_path.display()
            )
        })?;
        events_jsonl.push_str(&line);
        events_jsonl.push('\n');
    }
    let report_event = serde_json::json!({
        "schema_version": REPORT_EVENT_SCHEMA_VERSION,
        "component": BUNDLE_COMPONENT,
        "trace_id": trace_id,
        "decision_id": decision_id,
        "policy_id": POLICY_ID,
        "event": "control_plane_policy_diagnostics_report_emitted",
        "outcome": report_outcome(&control_plane_samples.report),
        "total_diagnostics": control_plane_samples.report.total_diagnostics,
        "release_blocked": control_plane_samples.report.release_blocked,
        "max_severity": control_plane_samples.report.max_severity.map(|severity| severity.as_str()),
        "report_hash": control_plane_policy_diagnostics_report_hash.clone(),
    });
    let report_event_line = serde_json::to_string(&report_event).map_err(|error| {
        format!(
            "failed to serialize report event for {}: {error}",
            events_path.display()
        )
    })?;
    events_jsonl.push_str(&report_event_line);
    events_jsonl.push('\n');

    let mut commands_buf = String::new();
    for command in command_lines {
        commands_buf.push_str(command);
        commands_buf.push('\n');
    }

    fs::create_dir_all(&step_logs_dir).map_err(|error| {
        format!(
            "failed to create step logs directory {}: {error}",
            step_logs_dir.display()
        )
    })?;

    let summary_md = render_summary(
        epoch,
        contract.coverage_count(),
        &operator_samples,
        &control_plane_samples,
        &manifest,
    );
    let step_log = render_step_log(
        epoch,
        &manifest,
        &operator_samples,
        &control_plane_samples,
        &boundary_policy_mapping_artifact_hash,
    );
    let env_json = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": "franken-engine.control-plane-policy-diagnostics.env.v1",
        "component": BUNDLE_COMPONENT,
        "contract_component": CONTRACT_COMPONENT,
        "policy_id": POLICY_ID,
        "bead_id": BEAD_ID,
        "epoch_raw": epoch.as_u64(),
        "workspace_root": env!("CARGO_MANIFEST_DIR"),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "toolchain": std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "unknown".to_string()),
    }))
    .map_err(|error| {
        format!(
            "failed to serialize env artifact {}: {error}",
            env_path.display()
        )
    })?;
    let repro_lock = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": "franken-engine.repro-lock.v1",
        "component": BUNDLE_COMPONENT,
        "policy_id": POLICY_ID,
        "bead_id": BEAD_ID,
        "epoch_raw": epoch.as_u64(),
        "semantic_content_hash": contract.content_hash.to_hex(),
        "boundary_policy_mapping_artifact_hash": boundary_policy_mapping_artifact_hash,
        "operator_diagnostic_contract_hash": operator_diagnostic_contract_hash,
        "user_error_translation_matrix_hash": user_error_translation_matrix_hash,
        "remediation_linkage_index_hash": remediation_linkage_index_hash,
        "control_plane_policy_diagnostics_report_hash": control_plane_policy_diagnostics_report_hash,
        "replay_command": "cargo run -p frankenengine-engine --bin franken_control_plane_policy_diagnostics -- --out-dir <DIR>",
    }))
    .map_err(|error| {
        format!(
            "failed to serialize repro lock artifact {}: {error}",
            repro_lock_path.display()
        )
    })?;

    write_atomic(
        &boundary_policy_mapping_contract_path,
        &boundary_policy_mapping_bytes,
    )?;
    write_atomic(
        &operator_diagnostic_contract_path,
        &operator_diagnostic_contract_bytes,
    )?;
    write_atomic(
        &user_error_translation_matrix_path,
        &user_error_translation_matrix_bytes,
    )?;
    write_atomic(
        &remediation_linkage_index_path,
        &remediation_linkage_index_bytes,
    )?;
    write_atomic(&control_plane_policy_diagnostics_report_path, &report_bytes)?;
    write_atomic(&trace_ids_path, &trace_ids_bytes)?;
    write_atomic(&events_path, events_jsonl.as_bytes())?;
    write_atomic(&commands_path, commands_buf.as_bytes())?;
    write_atomic(
        &step_logs_dir.join("step_001_generate.log"),
        step_log.as_bytes(),
    )?;
    write_atomic(&summary_path, summary_md.as_bytes())?;
    write_atomic(&env_path, &env_json)?;
    write_atomic(&repro_lock_path, &repro_lock)?;
    write_atomic(&run_manifest_path, &run_manifest_bytes)?;

    Ok(BundleArtifacts {
        out_dir: out_dir.to_path_buf(),
        boundary_policy_mapping_contract_path,
        operator_diagnostic_contract_path,
        user_error_translation_matrix_path,
        remediation_linkage_index_path,
        control_plane_policy_diagnostics_report_path,
        trace_ids_path,
        run_manifest_path,
        events_path,
        commands_path,
        step_logs_dir,
        summary_path,
        env_path,
        repro_lock_path,
        boundary_policy_mapping_artifact_hash: manifest.boundary_policy_mapping_artifact_hash,
        operator_diagnostic_contract_hash: manifest.operator_diagnostic_contract_hash,
        user_error_translation_matrix_hash: manifest.user_error_translation_matrix_hash,
        remediation_linkage_index_hash: manifest.remediation_linkage_index_hash,
        control_plane_policy_diagnostics_report_hash: manifest
            .control_plane_policy_diagnostics_report_hash,
        operator_mapping_count: manifest.operator_mapping_count,
        operator_diagnostic_count: manifest.operator_diagnostic_count,
        control_plane_diagnostic_count: manifest.control_plane_diagnostic_count,
        release_blocked_in_sample_report: manifest.release_blocked_in_sample_report,
    })
}

fn build_operator_samples(
    contract: &BoundaryPolicyMappingContract,
) -> Result<OperatorSampleSet, String> {
    let mut diagnostics = Vec::new();
    let mut events = Vec::new();
    let mut trace_ids = Vec::new();

    for (index, kind) in InternalFailureKind::all().iter().copied().enumerate() {
        let trace_id = format!("trace-operator-diagnostic-{index:02}");
        let trace_path = format!("./artifacts/{trace_id}.json");
        let mapping = contract.mapping_for(kind).ok_or_else(|| {
            format!(
                "canonical operator contract is missing required mapping for {}",
                kind.as_str()
            )
        })?;
        let evidence_ref = mapping
            .has_evidence_ref
            .then(|| format!("evidence-{}", kind.as_str()));
        let replay_ref = mapping.has_replay_ref.then(|| {
            format!(
                "frankenctl replay run --trace {trace_path} --mode {OPERATOR_SAMPLE_REPLAY_MODE}"
            )
        });
        let diagnostic = contract.emit_diagnostic(
            kind,
            sample_operator_message(kind),
            evidence_ref.as_deref(),
            replay_ref.as_deref(),
            sample_operator_context(kind),
        );
        let decision_id = format!("decision-operator-diagnostic-{index:02}");
        let event = build_diagnostic_event(&trace_id, &decision_id, kind.as_str(), &diagnostic);
        diagnostics.push(diagnostic);
        events.push(event);
        trace_ids.push(trace_id);
    }

    Ok(OperatorSampleSet {
        diagnostics,
        events,
        trace_ids,
    })
}

fn build_control_plane_samples(epoch: SecurityEpoch) -> ControlPlaneSampleSet {
    let mut emitter = DiagnosticEmitter::new(epoch);
    let mut trace_ids = Vec::new();

    let budget_cases = vec![
        (
            "trace-control-plane-budget-001",
            BudgetPropagationError::InsufficientBudget {
                boundary: BudgetBoundaryKind::ParentToChildExtension,
                derived_ms: 5,
                minimum_ms: 10,
                parent_remaining_ms: 20,
            },
        ),
        (
            "trace-control-plane-budget-002",
            BudgetPropagationError::NoRuleForBoundary {
                boundary: BudgetBoundaryKind::OrchestratorToCellClose,
            },
        ),
        (
            "trace-control-plane-budget-003",
            BudgetPropagationError::ParentExhausted {
                boundary: BudgetBoundaryKind::ParentToChildSession,
                parent_remaining_ms: 0,
            },
        ),
        (
            "trace-control-plane-budget-004",
            BudgetPropagationError::CleanupExceedsParent {
                cleanup_total_ms: 250,
                parent_remaining_ms: 100,
            },
        ),
        (
            "trace-control-plane-budget-005",
            BudgetPropagationError::ChildExceedsParent {
                child_ms: 200,
                parent_ms: 100,
            },
        ),
    ];
    for (trace_id, error) in budget_cases {
        emitter.emit_budget_error(&error, trace_id);
        trace_ids.push(trace_id.to_string());
    }

    let narrowing_cases = vec![
        (
            "trace-control-plane-cap-001",
            NarrowingViolation::CapabilityWidening {
                boundary_label: "extension_spawn".to_string(),
                widened_tokens: {
                    let mut tokens = BTreeSet::new();
                    tokens.insert(CapabilityToken::NetworkAccess);
                    tokens
                },
            },
        ),
        (
            "trace-control-plane-outcome-001",
            NarrowingViolation::OutcomeUpgrade {
                boundary_label: "cell_close".to_string(),
                child_outcome: BoundaryOutcome::Timeout,
                propagated_outcome: BoundaryOutcome::Failure,
            },
        ),
        (
            "trace-control-plane-outcome-002",
            NarrowingViolation::UnknownOutcomeNotFailClosed {
                boundary_label: "external_bridge".to_string(),
            },
        ),
    ];
    for (trace_id, violation) in narrowing_cases {
        emitter.emit_narrowing_violation(&violation, trace_id);
        trace_ids.push(trace_id.to_string());
    }

    let diagnostics = emitter.diagnostics().to_vec();
    let report = emitter.build_report();

    ControlPlaneSampleSet {
        diagnostics,
        report,
        trace_ids,
    }
}

fn build_user_error_translation_matrix(
    contract: &BoundaryPolicyMappingContract,
    control_plane_samples: &ControlPlaneSampleSet,
    epoch: SecurityEpoch,
) -> UserErrorTranslationMatrix {
    let operator_rows = contract
        .mappings
        .values()
        .map(|mapping| OperatorTranslationRow {
            failure_kind: mapping.failure_kind.as_str().to_string(),
            error_code: mapping.error_code.clone(),
            severity: mapping.severity.as_str().to_string(),
            user_impact: mapping.user_impact.as_str().to_string(),
            operator_impact: mapping.operator_impact.as_str().to_string(),
            next_action: mapping.next_action.as_str().to_string(),
            description: mapping.description.clone(),
            remediation: mapping.remediation.clone(),
            evidence_required: mapping.has_evidence_ref,
            replay_available: mapping.has_replay_ref,
        })
        .collect();
    let control_plane_rows = control_plane_samples
        .diagnostics
        .iter()
        .map(|diagnostic| ControlPlaneTranslationRow {
            diagnostic_code: diagnostic.error_code.code.clone(),
            category: diagnostic.error_code.category.as_str().to_string(),
            severity: diagnostic.error_code.severity.as_str().to_string(),
            boundary_label: diagnostic.boundary_label.clone(),
            sample_message: diagnostic.message.clone(),
            remediation_summary: diagnostic.remediation.summary.clone(),
            remediation_steps: diagnostic.remediation.steps.clone(),
            doc_refs: diagnostic.remediation.doc_refs.clone(),
            auto_remediable: diagnostic.remediation.auto_remediable,
            sample_trace_id: diagnostic.trace_ids.first().cloned(),
        })
        .collect();
    UserErrorTranslationMatrix {
        schema_version: USER_ERROR_TRANSLATION_MATRIX_SCHEMA_VERSION.to_string(),
        component: BUNDLE_COMPONENT.to_string(),
        policy_id: POLICY_ID.to_string(),
        epoch_raw: epoch.as_u64(),
        operator_rows,
        control_plane_rows,
    }
}

fn build_remediation_linkage_index(
    contract: &BoundaryPolicyMappingContract,
    operator_samples: &OperatorSampleSet,
    control_plane_samples: &ControlPlaneSampleSet,
    epoch: SecurityEpoch,
) -> RemediationLinkageIndex {
    let sample_lookup: BTreeMap<&str, &DiagnosticEntry> = operator_samples
        .diagnostics
        .iter()
        .map(|entry| (entry.failure_kind.as_str(), entry))
        .collect();
    let operator_links = contract
        .mappings
        .values()
        .map(|mapping| {
            let sample = sample_lookup.get(mapping.failure_kind.as_str()).copied();
            OperatorRemediationLink {
                failure_kind: mapping.failure_kind.as_str().to_string(),
                error_code: mapping.error_code.clone(),
                next_action: mapping.next_action.as_str().to_string(),
                remediation: mapping.remediation.clone(),
                evidence_required: mapping.has_evidence_ref,
                replay_available: mapping.has_replay_ref,
                sample_evidence_ref: sample.and_then(|entry| entry.evidence_ref.clone()),
                sample_replay_ref: sample.and_then(|entry| entry.replay_ref.clone()),
            }
        })
        .collect();
    let control_plane_links = control_plane_samples
        .diagnostics
        .iter()
        .map(|diagnostic| ControlPlaneRemediationLink {
            diagnostic_code: diagnostic.error_code.code.clone(),
            category: diagnostic.error_code.category.as_str().to_string(),
            severity: diagnostic.error_code.severity.as_str().to_string(),
            boundary_label: diagnostic.boundary_label.clone(),
            remediation_summary: diagnostic.remediation.summary.clone(),
            doc_refs: diagnostic.remediation.doc_refs.clone(),
            auto_remediable: diagnostic.remediation.auto_remediable,
            sample_trace_ids: diagnostic.trace_ids.clone(),
        })
        .collect();

    RemediationLinkageIndex {
        schema_version: REMEDIATION_LINKAGE_INDEX_SCHEMA_VERSION.to_string(),
        component: BUNDLE_COMPONENT.to_string(),
        policy_id: POLICY_ID.to_string(),
        epoch_raw: epoch.as_u64(),
        operator_links,
        control_plane_links,
    }
}

fn sample_operator_message(kind: InternalFailureKind) -> &'static str {
    match kind {
        InternalFailureKind::Cancellation => {
            "control plane cancelled the extension after parent shutdown began"
        }
        InternalFailureKind::BudgetExhaustion => {
            "cell close budget exhausted with 5ms remaining while cleanup still held work"
        }
        InternalFailureKind::CapabilityDenial => {
            "extension requested hostcall access without the required capability token"
        }
        InternalFailureKind::PolicyDenial => {
            "guardplane posterior exceeded the allowed threshold and denied execution"
        }
        InternalFailureKind::PanicClass => {
            "runtime entered a panic-class failure while finalizing a control-plane decision"
        }
        InternalFailureKind::CompatibilityDrift => {
            "decision receipt schema drifted from the pinned cross-repo compatibility window"
        }
        InternalFailureKind::DomainError => {
            "user supplied an invalid boundary label that does not exist in the control plane"
        }
        InternalFailureKind::InfrastructureFailure => {
            "evidence ledger write failed because the artifact volume was unavailable"
        }
        InternalFailureKind::Unknown => {
            "an unclassified control-plane failure reached the operator surface"
        }
    }
}

fn sample_operator_context(kind: InternalFailureKind) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "scenario_id".to_string(),
            format!("sample-{}", kind.as_str()),
        ),
        ("component".to_string(), CONTRACT_COMPONENT.to_string()),
        ("policy_id".to_string(), POLICY_ID.to_string()),
    ])
}

fn render_summary(
    epoch: SecurityEpoch,
    operator_mapping_count: usize,
    operator_samples: &OperatorSampleSet,
    control_plane_samples: &ControlPlaneSampleSet,
    manifest: &RunManifest,
) -> String {
    format!(
        "# Control-Plane Policy Diagnostics Bundle\n\n\
         - Epoch: {}\n\
         - Trace ID: {}\n\
         - Decision ID: {}\n\
         - Operator mappings: {}\n\
         - Sample operator diagnostics: {}\n\
         - Sample control-plane diagnostics: {}\n\
         - Release blocked in sample report: {}\n\n\
         ## Artifact Set\n\n\
         - {}\n\
         - {}\n\
         - {}\n\
         - {}\n\
         - {}\n\
         - {}\n\
         - {}\n\
         - {}\n",
        epoch.as_u64(),
        manifest.trace_id,
        manifest.decision_id,
        operator_mapping_count,
        operator_samples.diagnostics.len(),
        control_plane_samples.diagnostics.len(),
        if control_plane_samples.report.release_blocked {
            "yes"
        } else {
            "no"
        },
        manifest.artifact_paths.boundary_policy_mapping_contract,
        manifest.artifact_paths.operator_diagnostic_contract,
        manifest.artifact_paths.user_error_translation_matrix,
        manifest.artifact_paths.remediation_linkage_index,
        manifest
            .artifact_paths
            .control_plane_policy_diagnostics_report,
        manifest.artifact_paths.trace_ids,
        manifest.artifact_paths.run_manifest,
        manifest.artifact_paths.events_jsonl,
    )
}

fn render_step_log(
    epoch: SecurityEpoch,
    manifest: &RunManifest,
    operator_samples: &OperatorSampleSet,
    control_plane_samples: &ControlPlaneSampleSet,
    boundary_policy_mapping_artifact_hash: &str,
) -> String {
    format!(
        "component={}\npolicy_id={}\nbead_id={}\nepoch={}\ntrace_id={}\ndecision_id={}\n\
         semantic_content_hash={}\nboundary_policy_mapping_artifact_hash={}\n\
         operator_mapping_count={}\noperator_diagnostic_count={}\n\
         control_plane_diagnostic_count={}\nrelease_blocked_in_sample_report={}\n\
         operator_sample_traces={}\ncontrol_plane_sample_traces={}\n",
        BUNDLE_COMPONENT,
        POLICY_ID,
        BEAD_ID,
        epoch.as_u64(),
        manifest.trace_id,
        manifest.decision_id,
        manifest.semantic_content_hash,
        boundary_policy_mapping_artifact_hash,
        manifest.operator_mapping_count,
        operator_samples.diagnostics.len(),
        control_plane_samples.diagnostics.len(),
        manifest.release_blocked_in_sample_report,
        operator_samples.trace_ids.join(","),
        control_plane_samples.trace_ids.join(","),
    )
}

fn report_outcome(report: &DiagnosticReport) -> &'static str {
    if report.release_blocked {
        "release_blocked"
    } else if report.is_clean() {
        "clean"
    } else {
        "advisory_only"
    }
}

fn json_pretty_bytes<T: Serialize>(value: &T, path: &Path) -> Result<Vec<u8>, String> {
    serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to serialize {}: {error}", path.display()))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create parent directory for {}: {error}",
                path.display()
            )
        })?;
    }
    let tmp_path = path.with_extension(format!("{}.tmp", std::process::id()));
    fs::write(&tmp_path, bytes).map_err(|error| {
        format!(
            "failed to write temporary file {}: {error}",
            tmp_path.display()
        )
    })?;
    fs::rename(&tmp_path, path)
        .map_err(|error| format!("failed to move {} into place: {error}", path.display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn short_hash(hash: &str) -> String {
    hash.chars().take(16).collect()
}
