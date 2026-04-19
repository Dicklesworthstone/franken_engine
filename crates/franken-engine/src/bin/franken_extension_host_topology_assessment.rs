#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::extension_host_topology_assessment::{
    BEAD_ID, COMPONENT, POLICY_ID, TopologyPromotionDecision, build_topology_promotion_assessment,
    render_operator_rationale,
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

const OUTPUT_SCHEMA_VERSION: &str =
    "franken-engine.franken-extension-host-topology-assessment-cli.v1";
const TRACE_IDS_SCHEMA_VERSION: &str =
    "franken-engine.extension-host-topology-assessment.trace-ids.v1";
const RUN_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.extension-host-topology-assessment.run-manifest.v1";
const EVENT_SCHEMA_VERSION: &str = "franken-engine.extension-host-topology-assessment.event.v1";
const ENV_SCHEMA_VERSION: &str = "franken-engine.extension-host-topology-assessment.env.v1";
const REPRO_LOCK_SCHEMA_VERSION: &str =
    "franken-engine.extension-host-topology-assessment.repro-lock.v1";
const ASSESSMENT_FILE: &str = "topology_promotion_assessment.json";

#[derive(Debug)]
enum CliAction {
    Help,
    Run { out_dir: PathBuf, seed: u64 },
}

#[derive(Debug, Clone, Serialize)]
struct CommandOutput {
    schema_version: String,
    out_dir: String,
    topology_promotion_assessment: String,
    run_manifest: String,
    events_jsonl: String,
    commands_txt: String,
    trace_ids: String,
    step_logs_dir: String,
    summary_md: String,
    env_json: String,
    repro_lock: String,
    decision: TopologyPromotionDecision,
    targeted_promotion_count: usize,
    broader_promotion_count: usize,
    content_hash: String,
    assessment_artifact_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct TraceIdsArtifact {
    schema_version: String,
    component: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    seed: u64,
    scenario_id: String,
    content_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct RunManifest {
    schema_version: String,
    bead_id: String,
    component: String,
    policy_id: String,
    scenario_id: String,
    trace_id: String,
    decision_id: String,
    seed: u64,
    outcome: String,
    error_code: Option<String>,
    decision: TopologyPromotionDecision,
    targeted_promotion_count: usize,
    broader_promotion_count: usize,
    promotion_candidate_trigger_count: usize,
    content_hash: String,
    artifact_hashes: BTreeMap<String, String>,
    artifact_paths: BTreeMap<String, String>,
    verification_commands: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct EventRecord {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    outcome: String,
    error_code: Option<String>,
    seed: u64,
    scenario_id: String,
    topology_decision: TopologyPromotionDecision,
    content_hash: String,
}

fn main() {
    match parse_cli() {
        Ok(CliAction::Help) => print_help(),
        Ok(CliAction::Run { out_dir, seed }) => {
            if let Err(error) = run(out_dir, seed) {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("{error}");
            print_help();
            std::process::exit(2);
        }
    }
}

fn parse_cli() -> Result<CliAction, String> {
    let mut out_dir = None;
    let mut seed = 1316_u64;
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => return Ok(CliAction::Help),
            "--out-dir" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--out-dir requires a path".to_string())?;
                out_dir = Some(PathBuf::from(value));
            }
            "--seed" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--seed requires an unsigned integer".to_string())?;
                seed = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --seed value: {value}"))?;
            }
            unknown => return Err(format!("unknown argument: {unknown}")),
        }
    }

    Ok(CliAction::Run {
        out_dir: out_dir.unwrap_or_else(|| {
            PathBuf::from("artifacts/extension_host_topology_assessment/manual")
        }),
        seed,
    })
}

fn print_help() {
    println!("usage: franken_extension_host_topology_assessment [--out-dir PATH] [--seed N]");
}

fn run(out_dir: PathBuf, seed: u64) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(&out_dir)?;
    let step_logs_dir = out_dir.join("step_logs");
    fs::create_dir_all(&step_logs_dir)?;

    let assessment = build_topology_promotion_assessment();
    let trace_id = format!(
        "trace-extension-host-topology-{}-{seed}",
        &assessment.content_hash[..12]
    );
    let decision_id = format!(
        "decision-extension-host-topology-{}-{seed}",
        &assessment.content_hash[..12]
    );

    let assessment_path = out_dir.join(ASSESSMENT_FILE);
    let trace_ids_path = out_dir.join("trace_ids.json");
    let manifest_path = out_dir.join("run_manifest.json");
    let events_path = out_dir.join("events.jsonl");
    let commands_path = out_dir.join("commands.txt");
    let summary_path = out_dir.join("summary.md");
    let env_path = out_dir.join("env.json");
    let repro_lock_path = out_dir.join("repro.lock");
    let step_log_path = step_logs_dir.join("step_001_generate.log");

    write_json_pretty(&assessment_path, &assessment)?;
    fs::write(&summary_path, render_operator_rationale(&assessment))?;
    fs::write(
        &step_log_path,
        format!(
            "generated topology promotion assessment\nbead={BEAD_ID}\ndecision={}\ncontent_hash={}\n",
            assessment.decision, assessment.content_hash
        ),
    )?;

    let command_line = env::args().collect::<Vec<_>>().join(" ");
    let replay_command = "rch exec 'env RUSTFLAGS=\"-C linker=cc\" cargo run -p frankenengine-engine --bin franken_extension_host_topology_assessment -- --out-dir <DIR>'";
    fs::write(
        &commands_path,
        format!("{command_line}\n{replay_command}\n"),
    )?;

    let trace_ids = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: POLICY_ID.to_string(),
        seed,
        scenario_id: BEAD_ID.to_string(),
        content_hash: assessment.content_hash.clone(),
    };
    write_json_pretty(&trace_ids_path, &trace_ids)?;

    write_json_pretty(
        &env_path,
        &json!({
            "schema_version": ENV_SCHEMA_VERSION,
            "component": COMPONENT,
            "bead_id": BEAD_ID,
            "seed": seed,
            "rust_edition": "2024",
            "requires_rch_for_cargo": true,
        }),
    )?;
    write_json_pretty(
        &repro_lock_path,
        &json!({
            "schema_version": REPRO_LOCK_SCHEMA_VERSION,
            "component": COMPONENT,
            "bead_id": BEAD_ID,
            "content_hash": assessment.content_hash.clone(),
            "replay_command": replay_command,
        }),
    )?;

    let mut artifact_paths = BTreeMap::new();
    artifact_paths.insert(
        "topology_promotion_assessment".to_string(),
        ASSESSMENT_FILE.to_string(),
    );
    artifact_paths.insert("run_manifest".to_string(), "run_manifest.json".to_string());
    artifact_paths.insert("events".to_string(), "events.jsonl".to_string());
    artifact_paths.insert("commands".to_string(), "commands.txt".to_string());
    artifact_paths.insert("trace_ids".to_string(), "trace_ids.json".to_string());
    artifact_paths.insert("step_logs".to_string(), "step_logs".to_string());
    artifact_paths.insert("summary".to_string(), "summary.md".to_string());
    artifact_paths.insert("env".to_string(), "env.json".to_string());
    artifact_paths.insert("repro_lock".to_string(), "repro.lock".to_string());

    let mut artifact_hashes = BTreeMap::new();
    artifact_hashes.insert(
        "topology_promotion_assessment".to_string(),
        sha256_file_hex(&assessment_path)?,
    );
    artifact_hashes.insert("trace_ids".to_string(), sha256_file_hex(&trace_ids_path)?);
    artifact_hashes.insert("commands".to_string(), sha256_file_hex(&commands_path)?);
    artifact_hashes.insert("summary".to_string(), sha256_file_hex(&summary_path)?);
    artifact_hashes.insert("env".to_string(), sha256_file_hex(&env_path)?);
    artifact_hashes.insert("repro_lock".to_string(), sha256_file_hex(&repro_lock_path)?);

    let manifest = RunManifest {
        schema_version: RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        policy_id: POLICY_ID.to_string(),
        scenario_id: BEAD_ID.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        seed,
        outcome: "pass".to_string(),
        error_code: None,
        decision: assessment.decision,
        targeted_promotion_count: assessment.summary.targeted_promotion_count,
        broader_promotion_count: assessment.summary.broader_promotion_count,
        promotion_candidate_trigger_count: assessment.summary.promotion_candidate_trigger_count,
        content_hash: assessment.content_hash.clone(),
        artifact_hashes: artifact_hashes.clone(),
        artifact_paths,
        verification_commands: assessment.verification_commands.clone(),
    };
    write_json_pretty(&manifest_path, &manifest)?;

    let events = [
        event_record(
            "topology_assessment_generated",
            &trace_id,
            &decision_id,
            seed,
            assessment.decision,
            &assessment.content_hash,
        ),
        event_record(
            "promotion_decision_recorded",
            &trace_id,
            &decision_id,
            seed,
            assessment.decision,
            &assessment.content_hash,
        ),
    ];
    let mut events_jsonl = String::new();
    for event in &events {
        events_jsonl.push_str(&serde_json::to_string(event)?);
        events_jsonl.push('\n');
    }
    fs::write(&events_path, events_jsonl)?;

    let assessment_artifact_hash = artifact_hashes
        .get("topology_promotion_assessment")
        .cloned()
        .unwrap_or_default();
    let output = CommandOutput {
        schema_version: OUTPUT_SCHEMA_VERSION.to_string(),
        out_dir: out_dir.display().to_string(),
        topology_promotion_assessment: assessment_path.display().to_string(),
        run_manifest: manifest_path.display().to_string(),
        events_jsonl: events_path.display().to_string(),
        commands_txt: commands_path.display().to_string(),
        trace_ids: trace_ids_path.display().to_string(),
        step_logs_dir: step_logs_dir.display().to_string(),
        summary_md: summary_path.display().to_string(),
        env_json: env_path.display().to_string(),
        repro_lock: repro_lock_path.display().to_string(),
        decision: assessment.decision,
        targeted_promotion_count: assessment.summary.targeted_promotion_count,
        broader_promotion_count: assessment.summary.broader_promotion_count,
        content_hash: assessment.content_hash,
        assessment_artifact_hash,
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn event_record(
    event: &str,
    trace_id: &str,
    decision_id: &str,
    seed: u64,
    topology_decision: TopologyPromotionDecision,
    content_hash: &str,
) -> EventRecord {
    EventRecord {
        schema_version: EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event: event.to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        seed,
        scenario_id: BEAD_ID.to_string(),
        topology_decision,
        content_hash: content_hash.to_string(),
    }
}

fn write_json_pretty<T: Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

fn sha256_file_hex(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}
