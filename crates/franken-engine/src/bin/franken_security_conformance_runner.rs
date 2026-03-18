use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use frankenengine_engine::security_conformance::{
    SECURITY_CONFORMANCE_SCHEMA_VERSION, SecurityConformanceThresholds, SecurityCorpus,
    SecurityWorkloadObservation, default_observation_from_label, evaluate_security_conformance,
    load_security_labels, validate_corpus_manifest,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
struct CliArgs {
    labels_root: PathBuf,
    observations_jsonl: Option<PathBuf>,
    output_root: PathBuf,
    policy_snapshot_hash: String,
    allow_small_corpus: bool,
    fail_on_gate_failure: bool,
}

fn default_labels_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/security_conformance")
}

fn default_output_root() -> PathBuf {
    PathBuf::from("artifacts/security_conformance")
}

fn parse_args() -> Result<CliArgs, String> {
    let mut labels_root = default_labels_root();
    let mut observations_jsonl = None;
    let mut output_root = default_output_root();
    let mut policy_snapshot_hash = digest_hex(b"security-conformance-policy-v1");
    let mut allow_small_corpus = false;
    let mut fail_on_gate_failure = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--labels-root" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--labels-root requires a value".to_string())?;
                labels_root = PathBuf::from(value);
            }
            "--observations-jsonl" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--observations-jsonl requires a value".to_string())?;
                observations_jsonl = Some(PathBuf::from(value));
            }
            "--output-root" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--output-root requires a value".to_string())?;
                output_root = PathBuf::from(value);
            }
            "--policy-snapshot-hash" => {
                policy_snapshot_hash = args
                    .next()
                    .ok_or_else(|| "--policy-snapshot-hash requires a value".to_string())?;
            }
            "--allow-small-corpus" => {
                allow_small_corpus = true;
            }
            "--fail-on-gate-failure" => {
                fail_on_gate_failure = true;
            }
            "--help" | "-h" => {
                return Err("usage: franken_security_conformance_runner [--labels-root <path>] [--observations-jsonl <path>] [--output-root <path>] [--policy-snapshot-hash <hex>] [--allow-small-corpus] [--fail-on-gate-failure]".to_string());
            }
            other => {
                return Err(format!("unknown argument: {other}"));
            }
        }
    }

    Ok(CliArgs {
        labels_root,
        observations_jsonl,
        output_root,
        policy_snapshot_hash,
        allow_small_corpus,
        fail_on_gate_failure,
    })
}

fn load_observations(path: &Path) -> Result<Vec<SecurityWorkloadObservation>, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    let mut observations = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let observation: SecurityWorkloadObservation = serde_json::from_str(trimmed)?;
        observations.push(observation);
    }
    Ok(observations)
}

fn deterministic_trace_id(run_id: &str, workload_id: &str) -> String {
    let material = format!("{run_id}:{workload_id}");
    format!("trace-{}", &digest_hex(material.as_bytes())[..16])
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn environment_fingerprint() -> String {
    let mut kv = BTreeMap::new();
    kv.insert("os", std::env::consts::OS.to_string());
    kv.insert("arch", std::env::consts::ARCH.to_string());
    kv.insert(
        "rust_toolchain",
        std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "unknown".to_string()),
    );
    digest_hex(serde_json::to_string(&kv).unwrap_or_default().as_bytes())
}

#[derive(Debug, Serialize)]
struct SecuritySummaryLine {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    outcome: String,
    error_code: Option<String>,
    run_id: String,
    corpus_manifest_hash: String,
    policy_snapshot_hash: String,
    environment_fingerprint: String,
    benign_total: u64,
    malicious_total: u64,
    true_positive_count: u64,
    false_positive_count: u64,
    false_negative_count: u64,
    tpr_millionths: u32,
    fpr_millionths: u32,
    tpr_ci_lower_millionths: u32,
    tpr_ci_upper_millionths: u32,
    fpr_ci_lower_millionths: u32,
    fpr_ci_upper_millionths: u32,
    malicious_latency_p95_us: u64,
    malicious_latency_p95_max_us: u64,
    gate_failure_reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SecurityWorkloadLine {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    outcome: String,
    error_code: Option<String>,
    corpus_manifest_hash: String,
    policy_snapshot_hash: String,
    environment_fingerprint: String,
    workload_id: String,
    corpus: String,
    attack_taxonomy: Option<String>,
    expected_outcome: String,
    actual_outcome: String,
    detection_latency_us: u64,
    sentinel_posterior: f64,
    policy_action: String,
    containment_action: String,
    semantic_domain: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args =
        parse_args().map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;

    let labels = load_security_labels(&args.labels_root)?;
    validate_corpus_manifest(&args.labels_root, &labels)?;
    let benign_total = labels
        .iter()
        .filter(|record| record.label.corpus == SecurityCorpus::Benign)
        .count();
    let malicious_total = labels
        .iter()
        .filter(|record| record.label.corpus == SecurityCorpus::Malicious)
        .count();

    if !args.allow_small_corpus && (benign_total < 200 || malicious_total < 100) {
        return Err(format!(
            "security corpus size below release thresholds (benign={benign_total}, malicious={malicious_total}); pass --allow-small-corpus for development runs"
        )
        .into());
    }

    let observations = if let Some(path) = args.observations_jsonl.as_ref() {
        load_observations(path)?
    } else {
        labels
            .iter()
            .map(|record| default_observation_from_label(&record.label))
            .collect()
    };

    let thresholds = SecurityConformanceThresholds::default();
    let evaluation = evaluate_security_conformance(&labels, &observations, &thresholds)?;

    let run_id = format!(
        "security-conformance-{}",
        Utc::now().format("%Y%m%dT%H%M%SZ")
    );
    let run_root = args.output_root.join(&run_id);
    fs::create_dir_all(&run_root)?;

    let mut lines = String::new();
    let summary = &evaluation.summary;
    let environment_fingerprint = environment_fingerprint();
    let summary_line = SecuritySummaryLine {
        schema_version: SECURITY_CONFORMANCE_SCHEMA_VERSION.to_string(),
        trace_id: deterministic_trace_id(&run_id, "summary"),
        decision_id: format!("decision-{run_id}"),
        policy_id: "security-conformance-policy".to_string(),
        component: "security_conformance_runner".to_string(),
        event: "summary".to_string(),
        outcome: if summary.gate_pass {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: if summary.gate_pass {
            None
        } else {
            Some("FE-SECURITY-CONFORMANCE-GATE".to_string())
        },
        run_id: run_id.clone(),
        corpus_manifest_hash: summary.corpus_manifest_hash.clone(),
        policy_snapshot_hash: args.policy_snapshot_hash.clone(),
        environment_fingerprint: environment_fingerprint.clone(),
        benign_total: summary.benign_total,
        malicious_total: summary.malicious_total,
        true_positive_count: summary.true_positive_count,
        false_positive_count: summary.false_positive_count,
        false_negative_count: summary.false_negative_count,
        tpr_millionths: summary.tpr_millionths,
        fpr_millionths: summary.fpr_millionths,
        tpr_ci_lower_millionths: summary.tpr_ci.lower_millionths,
        tpr_ci_upper_millionths: summary.tpr_ci.upper_millionths,
        fpr_ci_lower_millionths: summary.fpr_ci.lower_millionths,
        fpr_ci_upper_millionths: summary.fpr_ci.upper_millionths,
        malicious_latency_p95_us: summary.malicious_latency_p95_us,
        malicious_latency_p95_max_us: summary.malicious_latency_p95_max_us,
        gate_failure_reasons: summary.gate_failure_reasons.clone(),
    };
    lines.push_str(&serde_json::to_string(&summary_line)?);
    lines.push('\n');

    for record in &labels {
        let observation = evaluation
            .observations_by_workload
            .get(record.label.workload_id.as_str())
            .expect("validated observation map");
        let outcome = if observation.actual_outcome == record.label.expected_outcome {
            "pass"
        } else {
            "fail"
        };
        let line = SecurityWorkloadLine {
            schema_version: SECURITY_CONFORMANCE_SCHEMA_VERSION.to_string(),
            trace_id: deterministic_trace_id(&run_id, record.label.workload_id.as_str()),
            decision_id: format!("decision-{}", record.label.workload_id),
            policy_id: "security-conformance-policy".to_string(),
            component: "security_conformance_runner".to_string(),
            event: "workload_result".to_string(),
            outcome: outcome.to_string(),
            error_code: observation.error_code.clone(),
            corpus_manifest_hash: summary.corpus_manifest_hash.clone(),
            policy_snapshot_hash: args.policy_snapshot_hash.clone(),
            environment_fingerprint: environment_fingerprint.clone(),
            workload_id: record.label.workload_id.clone(),
            corpus: match record.label.corpus {
                SecurityCorpus::Benign => "benign".to_string(),
                SecurityCorpus::Malicious => "malicious".to_string(),
            },
            attack_taxonomy: record
                .label
                .attack_taxonomy
                .map(|taxonomy| taxonomy.as_str().to_string()),
            expected_outcome: record.label.expected_outcome.as_str().to_string(),
            actual_outcome: observation.actual_outcome.as_str().to_string(),
            detection_latency_us: observation.detection_latency_us,
            sentinel_posterior: observation.sentinel_posterior,
            policy_action: observation.policy_action.clone(),
            containment_action: observation.containment_action.clone(),
            semantic_domain: record.label.semantic_domain.clone(),
        };
        lines.push_str(&serde_json::to_string(&line)?);
        lines.push('\n');
    }

    let evidence_path = run_root.join("security_conformance_evidence.jsonl");
    write_atomic(&evidence_path, lines.as_bytes())?;

    println!("security run_id={run_id}");
    println!("security labels_root={}", args.labels_root.display());
    println!("security evidence={}", evidence_path.display());
    println!("security benign_total={}", summary.benign_total);
    println!("security malicious_total={}", summary.malicious_total);
    println!(
        "security true_positive_count={}",
        summary.true_positive_count
    );
    println!(
        "security false_positive_count={}",
        summary.false_positive_count
    );
    println!(
        "security false_negative_count={}",
        summary.false_negative_count
    );
    println!(
        "security malicious_latency_p95_us={}",
        summary.malicious_latency_p95_us
    );
    println!("security gate_pass={}", summary.gate_pass);
    if !summary.gate_failure_reasons.is_empty() {
        for reason in &summary.gate_failure_reasons {
            println!("security gate_failure_reason={reason}");
        }
    }

    if args.fail_on_gate_failure && !summary.gate_pass {
        let detail = if summary.gate_failure_reasons.is_empty() {
            "gate outcome was fail".to_string()
        } else {
            summary.gate_failure_reasons.join("; ")
        };
        return Err(format!("security conformance gate failed: {detail}").into());
    }

    Ok(())
}
