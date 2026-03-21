#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::zero_placeholder_gate::{
    GateReport, GateVerdict, PlaceholderEntry, PlaceholderKind, PlaceholderSeverity, ScanResult,
    Subsystem, Waiver, WaiverStatus, evaluate_gate, summarize_report, validate_waiver,
};
use frankenengine_engine::zero_placeholder_scan::{
    ZeroPlaceholderFinding, ZeroPlaceholderInventory, ZeroPlaceholderSeverity,
    ZeroPlaceholderStatus, ZeroPlaceholderSubsystem, zero_placeholder_scan_inventory,
};
use serde::{Deserialize, Serialize};

const OUTPUT_SCHEMA_VERSION: &str = "franken-engine.franken_zero_placeholder_gate.v1";
const WAIVER_MANIFEST_SCHEMA_VERSION: &str = "franken-engine.zero-placeholder-waiver-manifest.v1";
const TRACE_IDS_SCHEMA_VERSION: &str = "franken-engine.zero-placeholder-gate.trace-ids.v1";
const RUN_MANIFEST_SCHEMA_VERSION: &str = "franken-engine.zero-placeholder-gate.run-manifest.v1";
const EVENT_SCHEMA_VERSION: &str = "franken-engine.zero-placeholder-gate.event.v1";
const REPORT_SCHEMA_VERSION: &str = "franken-engine.zero-placeholder-gate.report.v1";
const COMPONENT: &str = "franken_zero_placeholder_gate";
const POLICY_ID: &str = "franken-engine.zero-placeholder-gate.policy.v1";
const DEFAULT_EVALUATION_EPOCH_RAW: u64 = 100;

enum CliAction {
    Help,
    Run {
        out_dir: PathBuf,
        waivers_path: Option<PathBuf>,
        epoch: SecurityEpoch,
    },
}

#[derive(Debug, Clone, Serialize)]
struct CommandOutput {
    schema_version: String,
    out_dir: String,
    placeholder_gate_report: String,
    waiver_manifest: String,
    trace_ids: String,
    run_manifest: String,
    events_jsonl: String,
    commands_txt: String,
    inventory_hash: String,
    report_hash: String,
    verdict: GateVerdict,
    blocked_count: usize,
    warned_count: usize,
    waived_count: usize,
}

#[derive(Debug, Clone)]
struct PreparedFinding {
    finding: ZeroPlaceholderFinding,
    entry: Option<PlaceholderEntry>,
}

#[derive(Debug, Clone, Serialize)]
struct GateArtifactPaths {
    placeholder_gate_report: String,
    waiver_manifest: String,
    trace_ids: String,
    run_manifest: String,
    events_jsonl: String,
    commands_txt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WaiverManifest {
    schema_version: String,
    component: String,
    policy_id: String,
    #[serde(default)]
    evaluation_epoch_raw: u64,
    waivers: Vec<Waiver>,
    waiver_count: usize,
    active_waiver_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct TraceIds {
    schema_version: String,
    component: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    epoch_raw: u64,
    inventory_hash: String,
    report_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct RunManifest {
    schema_version: String,
    component: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    epoch_raw: u64,
    inventory_hash: String,
    report_hash: String,
    finding_count: usize,
    open_placeholder_finding_count: usize,
    blocked_count: usize,
    warned_count: usize,
    waived_count: usize,
    verdict: GateVerdict,
    artifact_paths: GateArtifactPaths,
}

#[derive(Debug, Clone, Serialize)]
struct GateEvent {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    finding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_bead_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RoutedFinding {
    finding_id: String,
    subsystem: ZeroPlaceholderSubsystem,
    status: ZeroPlaceholderStatus,
    severity: ZeroPlaceholderSeverity,
    owner: String,
    owner_bead_id: String,
    subject_area: String,
    source_reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    diagnostic_code: Option<String>,
    decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content_hash: Option<ContentHash>,
}

#[derive(Debug, Clone, Serialize)]
struct PlaceholderGateReportArtifact {
    schema_version: String,
    component: String,
    policy_id: String,
    inventory_hash: String,
    report_hash: String,
    finding_count: usize,
    open_placeholder_finding_count: usize,
    blocked_count: usize,
    warned_count: usize,
    waived_count: usize,
    verdict: GateVerdict,
    summary: String,
    routed_findings: Vec<RoutedFinding>,
    report: GateReport,
}

#[derive(Debug, Clone)]
struct GateArtifacts {
    out_dir: PathBuf,
    report_path: PathBuf,
    waiver_manifest_path: PathBuf,
    trace_ids_path: PathBuf,
    run_manifest_path: PathBuf,
    events_path: PathBuf,
    commands_path: PathBuf,
    inventory_hash: String,
    report_hash: String,
    verdict: GateVerdict,
    blocked_count: usize,
    warned_count: usize,
    waived_count: usize,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let (out_dir, waivers_path, epoch) = match parse_args(&args[1..])? {
        CliAction::Help => {
            println!("{}", help_text());
            return Ok(());
        }
        CliAction::Run {
            out_dir,
            waivers_path,
            epoch,
        } => (out_dir, waivers_path, epoch),
    };

    let artifacts =
        write_zero_placeholder_gate_bundle(&out_dir, waivers_path.as_deref(), &args, epoch)?;
    let output = CommandOutput {
        schema_version: OUTPUT_SCHEMA_VERSION.to_string(),
        out_dir: artifacts.out_dir.display().to_string(),
        placeholder_gate_report: artifacts.report_path.display().to_string(),
        waiver_manifest: artifacts.waiver_manifest_path.display().to_string(),
        trace_ids: artifacts.trace_ids_path.display().to_string(),
        run_manifest: artifacts.run_manifest_path.display().to_string(),
        events_jsonl: artifacts.events_path.display().to_string(),
        commands_txt: artifacts.commands_path.display().to_string(),
        inventory_hash: artifacts.inventory_hash,
        report_hash: artifacts.report_hash,
        verdict: artifacts.verdict,
        blocked_count: artifacts.blocked_count,
        warned_count: artifacts.warned_count,
        waived_count: artifacts.waived_count,
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
    let mut waivers_path: Option<PathBuf> = None;
    let mut epoch = default_evaluation_epoch();
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
            "--waivers" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("--waivers requires a path".to_string());
                };
                waivers_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--epoch" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("--epoch requires an integer".to_string());
                };
                let raw = value
                    .parse::<u64>()
                    .map_err(|_| "--epoch requires an integer".to_string())?;
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
        .map(|out_dir| CliAction::Run {
            out_dir,
            waivers_path,
            epoch,
        })
        .ok_or_else(|| format!("missing required --out-dir\n\n{}", help_text()))
}

fn help_text() -> String {
    "Usage: franken_zero_placeholder_gate --out-dir <DIR> [--waivers <FILE>] [--epoch <U64>]"
        .to_string()
}

fn default_evaluation_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(DEFAULT_EVALUATION_EPOCH_RAW)
}

fn load_waivers(path: Option<&Path>) -> Result<Vec<Waiver>, String> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };

    let bytes = fs::read(path)
        .map_err(|error| format!("failed to read waivers file `{}`: {error}", path.display()))?;
    if let Ok(waivers) = serde_json::from_slice::<Vec<Waiver>>(&bytes) {
        return Ok(waivers);
    }
    if let Ok(manifest) = serde_json::from_slice::<WaiverManifest>(&bytes) {
        return Ok(manifest.waivers);
    }

    Err(format!(
        "failed to parse waivers file `{}` as a JSON waiver array or waiver manifest",
        path.display()
    ))
}

fn scan_subsystem_to_gate(subsystem: ZeroPlaceholderSubsystem) -> Subsystem {
    match subsystem {
        ZeroPlaceholderSubsystem::Parser => Subsystem::Parser,
        ZeroPlaceholderSubsystem::Lowering => Subsystem::Lowering,
        ZeroPlaceholderSubsystem::Runtime => Subsystem::Runtime,
        ZeroPlaceholderSubsystem::CliDocs => Subsystem::Cli,
    }
}

fn scan_severity_to_gate(severity: ZeroPlaceholderSeverity) -> PlaceholderSeverity {
    match severity {
        ZeroPlaceholderSeverity::High => PlaceholderSeverity::Blocking,
        ZeroPlaceholderSeverity::Medium => PlaceholderSeverity::High,
        ZeroPlaceholderSeverity::Low => PlaceholderSeverity::Low,
    }
}

fn finding_to_kind(finding: &ZeroPlaceholderFinding) -> PlaceholderKind {
    match finding.subsystem {
        ZeroPlaceholderSubsystem::CliDocs => PlaceholderKind::UnsupportedError,
        ZeroPlaceholderSubsystem::Parser
        | ZeroPlaceholderSubsystem::Lowering
        | ZeroPlaceholderSubsystem::Runtime => PlaceholderKind::HardcodedFallback,
    }
}

fn location_file(reference: &str) -> String {
    reference
        .split(';')
        .next()
        .unwrap_or(reference)
        .split("::")
        .next()
        .unwrap_or(reference)
        .trim()
        .to_string()
}

fn prepare_gate_inputs(
    inventory: &ZeroPlaceholderInventory,
    epoch: SecurityEpoch,
) -> (Vec<ScanResult>, Vec<PreparedFinding>) {
    let mut grouped_entries: BTreeMap<Subsystem, Vec<PlaceholderEntry>> = BTreeMap::new();
    let mut prepared = Vec::with_capacity(inventory.findings.len());

    for finding in &inventory.findings {
        let entry = if finding.status == ZeroPlaceholderStatus::OpenPlaceholder {
            let entry = PlaceholderEntry::new(
                scan_subsystem_to_gate(finding.subsystem),
                finding_to_kind(finding),
                location_file(&finding.source_reference),
                0,
                format!(
                    "{} Required: {}",
                    finding.observed_behavior, finding.required_behavior
                ),
                scan_severity_to_gate(finding.severity),
            );
            grouped_entries
                .entry(scan_subsystem_to_gate(finding.subsystem))
                .or_default()
                .push(entry.clone());
            Some(entry)
        } else {
            None
        };

        prepared.push(PreparedFinding {
            finding: finding.clone(),
            entry,
        });
    }

    let scan_results = [
        Subsystem::Parser,
        Subsystem::Lowering,
        Subsystem::Runtime,
        Subsystem::Cli,
    ]
    .into_iter()
    .map(|subsystem| {
        let entries = grouped_entries.remove(&subsystem).unwrap_or_default();
        ScanResult::new(subsystem, entries, epoch)
    })
    .collect();

    (scan_results, prepared)
}

fn routing_records(prepared: &[PreparedFinding], report: &GateReport) -> Vec<RoutedFinding> {
    let blocked = report
        .blocked_entries
        .iter()
        .map(|entry| *entry.content_hash.as_bytes())
        .collect::<std::collections::BTreeSet<_>>();
    let warned = report
        .warned_entries
        .iter()
        .map(|entry| *entry.content_hash.as_bytes())
        .collect::<std::collections::BTreeSet<_>>();
    let waived = report
        .waived_entries
        .iter()
        .map(|entry| *entry.content_hash.as_bytes())
        .collect::<std::collections::BTreeSet<_>>();

    prepared
        .iter()
        .map(|prepared| {
            let (decision, content_hash) = match prepared.entry.as_ref() {
                Some(entry) if blocked.contains(entry.content_hash.as_bytes()) => {
                    ("block".to_string(), Some(entry.content_hash))
                }
                Some(entry) if warned.contains(entry.content_hash.as_bytes()) => {
                    ("warn".to_string(), Some(entry.content_hash))
                }
                Some(entry) if waived.contains(entry.content_hash.as_bytes()) => {
                    ("waived".to_string(), Some(entry.content_hash))
                }
                Some(entry) => ("allow".to_string(), Some(entry.content_hash)),
                None => ("allow".to_string(), None),
            };
            RoutedFinding {
                finding_id: prepared.finding.finding_id.clone(),
                subsystem: prepared.finding.subsystem,
                status: prepared.finding.status,
                severity: prepared.finding.severity,
                owner: prepared.finding.owner.clone(),
                owner_bead_id: prepared.finding.owner_bead_id.clone(),
                subject_area: prepared.finding.subject_area.clone(),
                source_reference: prepared.finding.source_reference.clone(),
                diagnostic_code: prepared.finding.diagnostic_code.clone(),
                decision,
                content_hash,
            }
        })
        .collect()
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to serialize `{}`: {error}", path.display()))?;
    fs::write(path, bytes).map_err(|error| format!("failed to write `{}`: {error}", path.display()))
}

fn write_jsonl(path: &Path, events: &[GateEvent]) -> Result<(), String> {
    let mut lines = String::new();
    for event in events {
        let line = serde_json::to_string(event)
            .map_err(|error| format!("failed to serialize `{}`: {error}", path.display()))?;
        lines.push_str(&line);
        lines.push('\n');
    }
    fs::write(path, lines).map_err(|error| format!("failed to write `{}`: {error}", path.display()))
}

fn write_zero_placeholder_gate_bundle(
    out_dir: &Path,
    waivers_path: Option<&Path>,
    args: &[String],
    epoch: SecurityEpoch,
) -> Result<GateArtifacts, String> {
    fs::create_dir_all(out_dir)
        .map_err(|error| format!("failed to create `{}`: {error}", out_dir.display()))?;

    let waivers = load_waivers(waivers_path)?;
    let waiver_manifest = WaiverManifest {
        schema_version: WAIVER_MANIFEST_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        policy_id: POLICY_ID.to_string(),
        evaluation_epoch_raw: epoch.as_u64(),
        waiver_count: waivers.len(),
        active_waiver_count: waivers
            .iter()
            .filter(|w| validate_waiver(w, epoch.as_u64()) == WaiverStatus::Active)
            .count(),
        waivers,
    };

    let inventory = zero_placeholder_scan_inventory();
    let inventory_hash = ContentHash::compute(
        &serde_json::to_vec(&inventory)
            .map_err(|error| format!("inventory hash error: {error}"))?,
    )
    .to_string();
    let open_placeholder_finding_count = inventory.open_placeholder_finding_count();
    let (scans, prepared) = prepare_gate_inputs(&inventory, epoch);
    let timestamp_micros = 1_000_000;
    let report = evaluate_gate(
        &scans,
        &waiver_manifest.waivers,
        &frankenengine_engine::zero_placeholder_gate::GateConfig::default_config(),
        &epoch,
        timestamp_micros,
    )
    .map_err(|error| error.to_string())?;
    let routed_findings = routing_records(&prepared, &report);
    let report_hash = ContentHash::compute(
        &serde_json::to_vec(&report).map_err(|error| format!("report hash error: {error}"))?,
    )
    .to_string();
    let short_hash = report_hash
        .strip_prefix("sha256:")
        .unwrap_or(report_hash.as_str())
        .chars()
        .take(12)
        .collect::<String>();
    let trace_id = format!("trace-zero-placeholder-gate-{short_hash}");
    let decision_id = format!("decision-zero-placeholder-gate-{short_hash}");

    let artifact_paths = GateArtifactPaths {
        placeholder_gate_report: "placeholder_gate_report.json".to_string(),
        waiver_manifest: "waiver_manifest.json".to_string(),
        trace_ids: "trace_ids.json".to_string(),
        run_manifest: "run_manifest.json".to_string(),
        events_jsonl: "events.jsonl".to_string(),
        commands_txt: "commands.txt".to_string(),
    };
    let report_artifact = PlaceholderGateReportArtifact {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        policy_id: POLICY_ID.to_string(),
        inventory_hash: inventory_hash.clone(),
        report_hash: report_hash.clone(),
        finding_count: inventory.findings.len(),
        open_placeholder_finding_count,
        blocked_count: report.blocked_count(),
        warned_count: report.warned_count(),
        waived_count: report.waived_count(),
        verdict: report.verdict,
        summary: summarize_report(&report),
        routed_findings: routed_findings.clone(),
        report: report.clone(),
    };
    let trace_ids = TraceIds {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: POLICY_ID.to_string(),
        epoch_raw: epoch.as_u64(),
        inventory_hash: inventory_hash.clone(),
        report_hash: report_hash.clone(),
    };
    let run_manifest = RunManifest {
        schema_version: RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: POLICY_ID.to_string(),
        epoch_raw: epoch.as_u64(),
        inventory_hash: inventory_hash.clone(),
        report_hash: report_hash.clone(),
        finding_count: inventory.findings.len(),
        open_placeholder_finding_count,
        blocked_count: report.blocked_count(),
        warned_count: report.warned_count(),
        waived_count: report.waived_count(),
        verdict: report.verdict,
        artifact_paths: artifact_paths.clone(),
    };
    let mut events = vec![GateEvent {
        schema_version: EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event: "gate_started".to_string(),
        outcome: "started".to_string(),
        finding_id: None,
        owner_bead_id: None,
        detail: Some("zero-placeholder gate evaluation began".to_string()),
    }];
    events.extend(routed_findings.iter().map(|finding| GateEvent {
        schema_version: EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event: "finding_routed".to_string(),
        outcome: finding.decision.clone(),
        finding_id: Some(finding.finding_id.clone()),
        owner_bead_id: Some(finding.owner_bead_id.clone()),
        detail: Some(format!(
            "{} [{}]",
            finding.source_reference, finding.subject_area
        )),
    }));
    events.push(GateEvent {
        schema_version: EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event: "gate_completed".to_string(),
        outcome: report.verdict.as_str().to_string(),
        finding_id: None,
        owner_bead_id: None,
        detail: Some(format!(
            "{} blocked, {} warned, {} waived",
            report.blocked_count(),
            report.warned_count(),
            report.waived_count()
        )),
    });

    let report_path = out_dir.join(&artifact_paths.placeholder_gate_report);
    let waiver_manifest_path = out_dir.join(&artifact_paths.waiver_manifest);
    let trace_ids_path = out_dir.join(&artifact_paths.trace_ids);
    let run_manifest_path = out_dir.join(&artifact_paths.run_manifest);
    let events_path = out_dir.join(&artifact_paths.events_jsonl);
    let commands_path = out_dir.join(&artifact_paths.commands_txt);

    write_json(&report_path, &report_artifact)?;
    write_json(&waiver_manifest_path, &waiver_manifest)?;
    write_json(&trace_ids_path, &trace_ids)?;
    write_json(&run_manifest_path, &run_manifest)?;
    write_jsonl(&events_path, &events)?;
    fs::write(&commands_path, format!("{}\n", args.join(" ")))
        .map_err(|error| format!("failed to write `{}`: {error}", commands_path.display()))?;

    Ok(GateArtifacts {
        out_dir: out_dir.to_path_buf(),
        report_path,
        waiver_manifest_path,
        trace_ids_path,
        run_manifest_path,
        events_path,
        commands_path,
        inventory_hash,
        report_hash,
        verdict: report.verdict,
        blocked_count: report.blocked_count(),
        warned_count: report.warned_count(),
        waived_count: report.waived_count(),
    })
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::Value;

    use super::*;

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock drift")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn parse_args_defaults_epoch_to_contract_default() {
        let args = vec!["--out-dir".to_string(), "artifacts/out".to_string()];
        match parse_args(&args).expect("parse args") {
            CliAction::Run { epoch, .. } => {
                assert_eq!(epoch.as_u64(), DEFAULT_EVALUATION_EPOCH_RAW)
            }
            CliAction::Help => panic!("expected run action"),
        }
    }

    #[test]
    fn parse_args_accepts_epoch_override() {
        let args = vec![
            "--out-dir".to_string(),
            "artifacts/out".to_string(),
            "--epoch".to_string(),
            "42".to_string(),
        ];
        match parse_args(&args).expect("parse args") {
            CliAction::Run { epoch, .. } => assert_eq!(epoch.as_u64(), 42),
            CliAction::Help => panic!("expected run action"),
        }
    }

    #[test]
    fn bundle_manifest_counts_effective_active_waivers_at_selected_epoch() {
        let out_dir = unique_temp_dir("franken-zero-placeholder-gate-bundle");
        let epoch = SecurityEpoch::from_raw(100);
        let inventory = zero_placeholder_scan_inventory();
        let (_, prepared) = prepare_gate_inputs(&inventory, epoch);
        let entry = prepared
            .iter()
            .find_map(|prepared| prepared.entry.clone())
            .expect("open placeholder entry");
        let waivers_path = out_dir.join("waivers.json");
        let waivers = vec![Waiver {
            waiver_id: "expired-waiver".to_string(),
            placeholder_hash: entry.content_hash,
            subsystem: entry.subsystem,
            justification: "expired waiver should not count as active".to_string(),
            owner: "review".to_string(),
            expires_epoch: 50,
            status: WaiverStatus::Active,
            created_epoch: 40,
        }];
        fs::write(
            &waivers_path,
            serde_json::to_vec_pretty(&waivers).expect("serialize waivers"),
        )
        .expect("write waivers");

        write_zero_placeholder_gate_bundle(
            &out_dir,
            Some(&waivers_path),
            &[
                "franken_zero_placeholder_gate".to_string(),
                "--out-dir".to_string(),
                out_dir.display().to_string(),
                "--waivers".to_string(),
                waivers_path.display().to_string(),
                "--epoch".to_string(),
                epoch.as_u64().to_string(),
            ],
            epoch,
        )
        .expect("write bundle");

        let waiver_manifest: Value = serde_json::from_slice(
            &fs::read(out_dir.join("waiver_manifest.json")).expect("read waiver manifest"),
        )
        .expect("parse waiver manifest");
        assert_eq!(waiver_manifest["evaluation_epoch_raw"], 100);
        assert_eq!(waiver_manifest["waiver_count"], 1);
        assert_eq!(waiver_manifest["active_waiver_count"], 0);

        let report: Value = serde_json::from_slice(
            &fs::read(out_dir.join("placeholder_gate_report.json")).expect("read report"),
        )
        .expect("parse report");
        assert_eq!(report["report"]["receipt"]["epoch"], 100);

        let run_manifest: Value = serde_json::from_slice(
            &fs::read(out_dir.join("run_manifest.json")).expect("read run manifest"),
        )
        .expect("parse run manifest");
        assert_eq!(run_manifest["epoch_raw"], 100);

        let trace_ids: Value = serde_json::from_slice(
            &fs::read(out_dir.join("trace_ids.json")).expect("read trace ids"),
        )
        .expect("parse trace ids");
        assert_eq!(trace_ids["epoch_raw"], 100);
    }

    #[test]
    fn load_waivers_accepts_legacy_manifest_without_evaluation_epoch() {
        let out_dir = unique_temp_dir("franken-zero-placeholder-gate-legacy-manifest");
        let waivers_path = out_dir.join("legacy-waivers.json");
        let legacy_manifest = serde_json::json!({
            "schema_version": WAIVER_MANIFEST_SCHEMA_VERSION,
            "component": COMPONENT,
            "policy_id": POLICY_ID,
            "waivers": [],
            "waiver_count": 0,
            "active_waiver_count": 0
        });
        fs::write(
            &waivers_path,
            serde_json::to_vec_pretty(&legacy_manifest).expect("serialize legacy manifest"),
        )
        .expect("write legacy manifest");

        let waivers = load_waivers(Some(&waivers_path)).expect("load legacy waiver manifest");
        assert!(waivers.is_empty());
    }
}
