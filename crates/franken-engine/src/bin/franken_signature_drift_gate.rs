use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_drift_gate::{
    BatchGateResult, DRIFT_GATE_SCHEMA_VERSION, DriftGateConfig, batch_evaluate,
    run_evidence_corpus,
};
use serde::Serialize;

const ARTIFACT_MARKER_PREFIX: &str = "__RGC_SIGNATURE_DRIFT_GATE_ARTIFACT__";

#[derive(Debug, Serialize)]
struct GateReport {
    schema_version: String,
    component: String,
    policy_id: String,
    epoch: u64,
    evidence_specimen_count: usize,
    all_specimens_match_expected: bool,
    specimen_verdicts: Vec<SpecimenVerdictRecord>,
    batch_result: BatchGateResult,
    manifest_hash: String,
}

#[derive(Debug, Serialize)]
struct SpecimenVerdictRecord {
    specimen_id: String,
    family: String,
    expected: String,
    actual: String,
    matches: bool,
}

#[derive(Debug, Serialize)]
struct TraceIds {
    component: String,
    policy_id: String,
    trace_id: String,
    decision_id: String,
    run_id: String,
}

#[derive(Debug, Serialize)]
struct RunManifest {
    schema_version: String,
    component: String,
    policy_id: String,
    trace_id: String,
    decision_id: String,
    run_id: String,
    generated_at_utc: String,
    source_commit: String,
    toolchain: String,
    epoch: u64,
    artifact_paths: BTreeMap<String, String>,
    replay_command: String,
}

#[derive(Debug, Serialize)]
struct ReproLock {
    schema_version: String,
    component: String,
    epoch: u64,
    replay_command: String,
    manifest_hash: String,
}

#[derive(Debug, Serialize)]
struct EnvJson {
    component: String,
    epoch: u64,
    toolchain: String,
    source_commit: String,
}

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    if args.is_empty() {
        return Err(usage());
    }

    let mut out_dir: Option<String> = None;
    let mut epoch_val: u64 = 42;
    let mut trace_id = String::from("trace-rgc-signature-drift-gate");
    let mut decision_id = String::from("decision-rgc-signature-drift-gate");
    let mut policy_id = String::from("RGC-617C");
    let mut run_id = String::from("run-rgc-signature-drift-gate");
    let mut generated_at_utc = String::from("unknown");
    let mut source_commit = String::from("unknown");
    let mut toolchain = String::from("nightly");
    let mut summary = false;
    let mut emit_artifact_stream = false;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--out-dir" => {
                index += 1;
                out_dir = Some(
                    args.get(index)
                        .ok_or_else(|| "--out-dir requires a path".to_string())?
                        .clone(),
                );
            }
            "--epoch" => {
                index += 1;
                epoch_val = args
                    .get(index)
                    .ok_or_else(|| "--epoch requires a value".to_string())?
                    .parse::<u64>()
                    .map_err(|e| format!("invalid --epoch: {e}"))?;
            }
            "--trace-id" => {
                index += 1;
                trace_id = args
                    .get(index)
                    .ok_or_else(|| "--trace-id requires a value".to_string())?
                    .clone();
            }
            "--decision-id" => {
                index += 1;
                decision_id = args
                    .get(index)
                    .ok_or_else(|| "--decision-id requires a value".to_string())?
                    .clone();
            }
            "--policy-id" => {
                index += 1;
                policy_id = args
                    .get(index)
                    .ok_or_else(|| "--policy-id requires a value".to_string())?
                    .clone();
            }
            "--run-id" => {
                index += 1;
                run_id = args
                    .get(index)
                    .ok_or_else(|| "--run-id requires a value".to_string())?
                    .clone();
            }
            "--generated-at-utc" => {
                index += 1;
                generated_at_utc = args
                    .get(index)
                    .ok_or_else(|| "--generated-at-utc requires a value".to_string())?
                    .clone();
            }
            "--source-commit" => {
                index += 1;
                source_commit = args
                    .get(index)
                    .ok_or_else(|| "--source-commit requires a value".to_string())?
                    .clone();
            }
            "--toolchain" => {
                index += 1;
                toolchain = args
                    .get(index)
                    .ok_or_else(|| "--toolchain requires a value".to_string())?
                    .clone();
            }
            "--summary" => summary = true,
            "--emit-artifact-stream" => emit_artifact_stream = true,
            "help" | "--help" | "-h" => {
                println!("{}", usage());
                return Ok(());
            }
            flag => return Err(format!("unknown flag '{flag}'\n\n{}", usage())),
        }
        index += 1;
    }

    let out_dir = out_dir.ok_or_else(|| "missing required --out-dir <path>".to_string())?;
    let out_path = PathBuf::from(&out_dir);
    let epoch = SecurityEpoch::from_raw(epoch_val);

    // Run the evidence corpus
    let (specimens, manifest_hash) = run_evidence_corpus(epoch);

    // Build specimen verdict records
    let specimen_verdicts: Vec<SpecimenVerdictRecord> = specimens
        .iter()
        .map(|s| {
            let matches = s.decision.verdict == s.expected_verdict;
            SpecimenVerdictRecord {
                specimen_id: s.id.clone(),
                family: s.family.to_string(),
                expected: s.expected_verdict.to_string(),
                actual: s.decision.verdict.to_string(),
                matches,
            }
        })
        .collect();

    let all_match = specimen_verdicts.iter().all(|v| v.matches);

    // Run a batch evaluation for the claim IDs
    let claim_ids: Vec<&str> = specimens
        .iter()
        .map(|s| s.decision.claim_id.as_str())
        .collect();
    let config = DriftGateConfig::default();

    // Use first specimen's baseline/current for batch (stable low drift pair)
    let baseline = frankenengine_engine::signature_drift_gate::SignatureSnapshot::new(
        "batch-baseline".to_string(),
        frankenengine_engine::regime_signature_feature::RegimeLabel::Classified(
            frankenengine_engine::regime_detector::Regime::Normal,
        ),
        [
            ("cpu".to_string(), 500_000i64),
            ("mem".to_string(), 300_000),
        ]
        .into_iter()
        .collect(),
        100,
        epoch,
    );
    let current = frankenengine_engine::signature_drift_gate::SignatureSnapshot::new(
        "batch-current".to_string(),
        frankenengine_engine::regime_signature_feature::RegimeLabel::Classified(
            frankenengine_engine::regime_detector::Regime::Normal,
        ),
        [
            ("cpu".to_string(), 510_000i64),
            ("mem".to_string(), 305_000),
        ]
        .into_iter()
        .collect(),
        100,
        epoch,
    );
    let budget = frankenengine_engine::signature_drift_gate::TransitionBudgetTracker::new(
        config.max_transitions,
        epoch,
    );
    let batch_result = batch_evaluate(&claim_ids, &baseline, &current, &budget, &config, epoch);

    let report = GateReport {
        schema_version: DRIFT_GATE_SCHEMA_VERSION.to_string(),
        component: "signature_drift_gate".to_string(),
        policy_id: policy_id.clone(),
        epoch: epoch_val,
        evidence_specimen_count: specimens.len(),
        all_specimens_match_expected: all_match,
        specimen_verdicts,
        batch_result,
        manifest_hash: manifest_hash.to_hex(),
    };

    let trace_ids = TraceIds {
        component: "signature_drift_gate".to_string(),
        policy_id: policy_id.clone(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        run_id: run_id.clone(),
    };

    let replay_cmd = format!(
        "cargo run -p frankenengine-engine --bin franken_signature_drift_gate -- --out-dir {} --epoch {}",
        out_dir, epoch_val,
    );

    let mut artifact_paths: BTreeMap<String, String> = BTreeMap::new();
    artifact_paths.insert(
        "signature_drift_gate_report".to_string(),
        "signature_drift_gate_report.json".to_string(),
    );
    artifact_paths.insert("trace_ids".to_string(), "trace_ids.json".to_string());
    artifact_paths.insert("events_jsonl".to_string(), "events.jsonl".to_string());
    artifact_paths.insert("commands".to_string(), "commands.txt".to_string());
    artifact_paths.insert("summary".to_string(), "summary.md".to_string());
    artifact_paths.insert("env".to_string(), "env.json".to_string());
    artifact_paths.insert("repro_lock".to_string(), "repro.lock".to_string());

    let manifest = RunManifest {
        schema_version: DRIFT_GATE_SCHEMA_VERSION.to_string(),
        component: "signature_drift_gate".to_string(),
        policy_id: policy_id.clone(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        run_id: run_id.clone(),
        generated_at_utc: generated_at_utc.clone(),
        source_commit: source_commit.clone(),
        toolchain: toolchain.clone(),
        epoch: epoch_val,
        artifact_paths,
        replay_command: replay_cmd.clone(),
    };

    let repro_lock = ReproLock {
        schema_version: DRIFT_GATE_SCHEMA_VERSION.to_string(),
        component: "signature_drift_gate".to_string(),
        epoch: epoch_val,
        replay_command: replay_cmd,
        manifest_hash: manifest_hash.to_hex(),
    };

    let env_json = EnvJson {
        component: "signature_drift_gate".to_string(),
        epoch: epoch_val,
        toolchain: toolchain.clone(),
        source_commit: source_commit.clone(),
    };

    let summary_md = format!(
        "# Signature Drift Gate Report\n\n\
         - **Epoch**: {}\n\
         - **Specimens**: {}\n\
         - **All match expected**: {}\n\
         - **Manifest hash**: `{}`\n\
         - **Batch pass rate**: {}%\n",
        epoch_val,
        report.evidence_specimen_count,
        report.all_specimens_match_expected,
        manifest_hash.to_hex(),
        report.batch_result.pass_rate_millionths / 10_000,
    );

    let events_jsonl = format!(
        "{{\"event\":\"signature_drift_gate_complete\",\"component\":\"signature_drift_gate\",\"epoch\":{},\"specimen_count\":{},\"all_match\":{},\"manifest_hash\":\"{}\"}}\n",
        epoch_val,
        report.evidence_specimen_count,
        report.all_specimens_match_expected,
        manifest_hash.to_hex(),
    );

    let commands_txt = format!(
        "cargo run -p frankenengine-engine --bin franken_signature_drift_gate -- --out-dir {} --epoch {} --trace-id {} --decision-id {} --policy-id {} --run-id {} --generated-at-utc {} --source-commit {} --toolchain {}\n",
        out_dir,
        epoch_val,
        trace_id,
        decision_id,
        policy_id,
        run_id,
        generated_at_utc,
        source_commit,
        toolchain,
    );

    if emit_artifact_stream {
        // Stream artifacts via markers for rch retrieval
        let artifacts: Vec<(&str, String)> = vec![
            (
                "run_manifest.json",
                serde_json::to_string_pretty(&manifest).map_err(|e| format!("json: {e}"))?,
            ),
            (
                "signature_drift_gate_report.json",
                serde_json::to_string_pretty(&report).map_err(|e| format!("json: {e}"))?,
            ),
            (
                "trace_ids.json",
                serde_json::to_string_pretty(&trace_ids).map_err(|e| format!("json: {e}"))?,
            ),
            ("events.jsonl", events_jsonl.clone()),
            ("commands.txt", commands_txt.clone()),
            ("summary.md", summary_md.clone()),
            (
                "env.json",
                serde_json::to_string_pretty(&env_json).map_err(|e| format!("json: {e}"))?,
            ),
            (
                "repro.lock",
                serde_json::to_string_pretty(&repro_lock).map_err(|e| format!("json: {e}"))?,
            ),
        ];

        for (name, content) in &artifacts {
            println!("{ARTIFACT_MARKER_PREFIX}:BEGIN:{name}");
            print!("{content}");
            println!("{ARTIFACT_MARKER_PREFIX}:END:{name}");
        }
    } else {
        // Write artifacts to disk
        fs::create_dir_all(&out_path).map_err(|e| format!("mkdir: {e}"))?;

        write_json(&out_path, "run_manifest.json", &manifest)?;
        write_json(&out_path, "signature_drift_gate_report.json", &report)?;
        write_json(&out_path, "trace_ids.json", &trace_ids)?;
        write_text(&out_path, "events.jsonl", &events_jsonl)?;
        write_text(&out_path, "commands.txt", &commands_txt)?;
        write_text(&out_path, "summary.md", &summary_md)?;
        write_json(&out_path, "env.json", &env_json)?;
        write_json(&out_path, "repro.lock", &repro_lock)?;
    }

    if summary {
        print!("{summary_md}");
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "component": "signature_drift_gate",
                "epoch": epoch_val,
                "specimen_count": report.evidence_specimen_count,
                "all_match": report.all_specimens_match_expected,
                "manifest_hash": manifest_hash.to_hex(),
                "out_dir": out_dir,
            }))
            .map_err(|e| format!("json: {e}"))?
        );
    }

    if !all_match {
        eprintln!("FAIL: not all specimens matched expected verdicts");
        std::process::exit(1);
    }

    Ok(())
}

fn write_json<T: Serialize>(dir: &Path, name: &str, value: &T) -> Result<(), String> {
    let path = dir.join(name);
    let json =
        serde_json::to_string_pretty(value).map_err(|e| format!("json encode {name}: {e}"))?;
    fs::write(&path, json).map_err(|e| format!("write {name}: {e}"))
}

fn write_text(dir: &Path, name: &str, content: &str) -> Result<(), String> {
    let path = dir.join(name);
    fs::write(&path, content).map_err(|e| format!("write {name}: {e}"))
}

fn usage() -> String {
    [
        "franken_signature_drift_gate usage:",
        "  cargo run -p frankenengine-engine --bin franken_signature_drift_gate -- \\",
        "      --out-dir <path> [--epoch <n>] [--summary] [--emit-artifact-stream]",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>]",
        "      [--run-id <id>] [--generated-at-utc <rfc3339>]",
        "      [--source-commit <sha>] [--toolchain <name>]",
    ]
    .join("\n")
}
