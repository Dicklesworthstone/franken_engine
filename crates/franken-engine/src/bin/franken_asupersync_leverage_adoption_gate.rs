#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::asupersync_leverage_adoption_gate::{
    AdoptionGateVerdict, BEAD_ID, COMPONENT, POLICY_ID, build_asupersync_leverage_adoption_gate,
    render_operator_summary,
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

const OUTPUT_SCHEMA_VERSION: &str =
    "franken-engine.franken-asupersync-leverage-adoption-gate-cli.v1";
const RUN_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.asupersync-leverage-adoption-gate.run-manifest.v1";
const TRACE_IDS_SCHEMA_VERSION: &str =
    "franken-engine.asupersync-leverage-adoption-gate.trace-ids.v1";
const EVENT_SCHEMA_VERSION: &str = "franken-engine.asupersync-leverage-adoption-gate.event.v1";
const ENV_SCHEMA_VERSION: &str = "franken-engine.asupersync-leverage-adoption-gate.env.v1";
const REPRO_LOCK_SCHEMA_VERSION: &str =
    "franken-engine.asupersync-leverage-adoption-gate.repro-lock.v1";
const GATE_FILE: &str = "asupersync_leverage_adoption_gate.json";
const DECISION_FILE: &str = "decision_record.json";
const DIAGNOSTIC_FILE: &str = "diagnostic_contract_index.json";

#[derive(Debug)]
enum CliAction {
    Help,
    Run { out_dir: PathBuf, seed: u64 },
}

#[derive(Debug, Clone, Serialize)]
struct CommandOutput {
    schema_version: String,
    out_dir: String,
    adoption_gate: String,
    decision_record: String,
    diagnostic_contract_index: String,
    run_manifest: String,
    events_jsonl: String,
    commands_txt: String,
    trace_ids: String,
    step_logs_dir: String,
    summary_md: String,
    env_json: String,
    repro_lock: String,
    verdict: AdoptionGateVerdict,
    stop_go_code: String,
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
    verdict: AdoptionGateVerdict,
    stop_go_code: String,
    content_hash: String,
    artifact_paths: BTreeMap<String, String>,
    artifact_hashes: BTreeMap<String, String>,
    verification_commands: Vec<String>,
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
    stop_go_code: String,
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
    let mut seed = 1317_u64;
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
        out_dir: out_dir
            .unwrap_or_else(|| PathBuf::from("artifacts/asupersync_leverage_adoption_gate/manual")),
        seed,
    })
}

fn print_help() {
    println!("usage: franken_asupersync_leverage_adoption_gate [--out-dir PATH] [--seed N]");
}

fn run(out_dir: PathBuf, seed: u64) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(&out_dir)?;
    let step_logs_dir = out_dir.join("step_logs");
    fs::create_dir_all(&step_logs_dir)?;

    let gate = build_asupersync_leverage_adoption_gate();
    let hash_fragment = &gate.content_hash[7..19];
    let trace_id = format!("trace-asupersync-adoption-{hash_fragment}-{seed}");
    let decision_id = format!("decision-asupersync-adoption-{hash_fragment}-{seed}");

    let gate_path = out_dir.join(GATE_FILE);
    let decision_path = out_dir.join(DECISION_FILE);
    let diagnostic_path = out_dir.join(DIAGNOSTIC_FILE);
    let manifest_path = out_dir.join("run_manifest.json");
    let events_path = out_dir.join("events.jsonl");
    let commands_path = out_dir.join("commands.txt");
    let trace_ids_path = out_dir.join("trace_ids.json");
    let summary_path = out_dir.join("summary.md");
    let env_path = out_dir.join("env.json");
    let repro_lock_path = out_dir.join("repro.lock");
    let step_log_path = step_logs_dir.join("step_001_generate.log");

    write_json_pretty(&gate_path, &gate)?;
    write_json_pretty(
        &decision_path,
        &json!({
            "schema_version": "franken-engine.asupersync-leverage-adoption-gate.decision-record.v1",
            "bead_id": BEAD_ID,
            "component": COMPONENT,
            "policy_id": POLICY_ID,
            "verdict": gate.verdict,
            "stop_go_code": gate.stop_go_code,
            "topology_decision": gate.topology_decision,
            "user_impact": gate.user_impact,
            "operator_impact": gate.operator_impact,
            "next_action": gate.next_action,
            "outstanding_risk_ids": gate.outstanding_risk_ids,
            "content_hash": gate.content_hash,
        }),
    )?;
    write_json_pretty(&diagnostic_path, &gate.diagnostic_contract_index)?;
    fs::write(&summary_path, render_operator_summary(&gate))?;
    fs::write(
        &step_log_path,
        format!(
            "generated asupersync leverage adoption gate\nbead={BEAD_ID}\nverdict={}\nstop_go_code={}\ncontent_hash={}\n",
            gate.verdict, gate.stop_go_code, gate.content_hash
        ),
    )?;

    let command_line = env::args().collect::<Vec<_>>().join(" ");
    let replay_command = "rch exec 'env RUSTFLAGS=\"-C linker=cc\" cargo run -p frankenengine-engine --bin franken_asupersync_leverage_adoption_gate -- --out-dir <DIR>'";
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
        content_hash: gate.content_hash.clone(),
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
            "content_hash": gate.content_hash,
            "replay_command": replay_command,
        }),
    )?;

    let mut artifact_paths = BTreeMap::new();
    artifact_paths.insert("adoption_gate".to_string(), GATE_FILE.to_string());
    artifact_paths.insert("decision_record".to_string(), DECISION_FILE.to_string());
    artifact_paths.insert(
        "diagnostic_contract_index".to_string(),
        DIAGNOSTIC_FILE.to_string(),
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
    for (id, file) in [
        ("adoption_gate", &gate_path),
        ("decision_record", &decision_path),
        ("diagnostic_contract_index", &diagnostic_path),
        ("commands", &commands_path),
        ("trace_ids", &trace_ids_path),
        ("summary", &summary_path),
        ("env", &env_path),
        ("repro_lock", &repro_lock_path),
    ] {
        artifact_hashes.insert(id.to_string(), sha256_file_hex(file)?);
    }

    let manifest = RunManifest {
        schema_version: RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        policy_id: POLICY_ID.to_string(),
        scenario_id: BEAD_ID.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        seed,
        outcome: if gate.is_go() { "pass" } else { "blocked" }.to_string(),
        error_code: if gate.is_go() {
            None
        } else {
            Some(gate.stop_go_code.clone())
        },
        verdict: gate.verdict,
        stop_go_code: gate.stop_go_code.clone(),
        content_hash: gate.content_hash.clone(),
        artifact_paths,
        artifact_hashes,
        verification_commands: gate.verification_commands.clone(),
    };
    write_json_pretty(&manifest_path, &manifest)?;

    let events = [
        EventRecord {
            schema_version: EVENT_SCHEMA_VERSION.to_string(),
            trace_id: trace_id.clone(),
            decision_id: decision_id.clone(),
            policy_id: POLICY_ID.to_string(),
            component: COMPONENT.to_string(),
            event: "adoption_gate_generated".to_string(),
            outcome: manifest.outcome.clone(),
            error_code: manifest.error_code.clone(),
            seed,
            scenario_id: BEAD_ID.to_string(),
            stop_go_code: gate.stop_go_code.clone(),
            content_hash: gate.content_hash.clone(),
        },
        EventRecord {
            schema_version: EVENT_SCHEMA_VERSION.to_string(),
            trace_id,
            decision_id,
            policy_id: POLICY_ID.to_string(),
            component: COMPONENT.to_string(),
            event: "decision_record_linked".to_string(),
            outcome: manifest.outcome.clone(),
            error_code: manifest.error_code.clone(),
            seed,
            scenario_id: BEAD_ID.to_string(),
            stop_go_code: gate.stop_go_code.clone(),
            content_hash: gate.content_hash.clone(),
        },
    ];
    let mut event_lines = String::new();
    for event in &events {
        event_lines.push_str(&serde_json::to_string(event)?);
        event_lines.push('\n');
    }
    fs::write(&events_path, event_lines)?;

    let output = CommandOutput {
        schema_version: OUTPUT_SCHEMA_VERSION.to_string(),
        out_dir: out_dir.display().to_string(),
        adoption_gate: gate_path.display().to_string(),
        decision_record: decision_path.display().to_string(),
        diagnostic_contract_index: diagnostic_path.display().to_string(),
        run_manifest: manifest_path.display().to_string(),
        events_jsonl: events_path.display().to_string(),
        commands_txt: commands_path.display().to_string(),
        trace_ids: trace_ids_path.display().to_string(),
        step_logs_dir: step_logs_dir.display().to_string(),
        summary_md: summary_path.display().to_string(),
        env_json: env_path.display().to_string(),
        repro_lock: repro_lock_path.display().to_string(),
        verdict: gate.verdict,
        stop_go_code: gate.stop_go_code,
        content_hash: gate.content_hash,
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn write_json_pretty<T: Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn sha256_file_hex(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}
