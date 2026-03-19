#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{SecondsFormat, Utc};
use frankenengine_engine::metadata_substrate_optimized::{
    FallbackPath, OverrideConfig, RollbackStrategy, SUBSTRATE_OPT_COMPONENT,
    SubstrateEvidenceManifest, SubstrateInventoryReport, SubstrateKind, build_canonical_inventory,
    certify_substrate, evaluate_substrate, run_substrate_evidence,
};
use serde::Serialize;

const OUTPUT_SCHEMA_VERSION: &str = "frankenengine.metadata-substrate-evidence-output.v1";
const RUN_MANIFEST_SCHEMA_VERSION: &str =
    "frankenengine.metadata-substrate-evidence.run-manifest.v1";
const TRACE_IDS_SCHEMA_VERSION: &str = "frankenengine.metadata-substrate-evidence.trace-ids.v1";
const TRACE_ID: &str = "trace-rgc-626b-metadata-substrate-evidence";
const DECISION_ID: &str = "decision-rgc-626b-metadata-substrate-evidence";
const POLICY_ID: &str = "policy-rgc-626b-metadata-substrate-evidence";

enum CliAction {
    Help,
    Run { out_dir: PathBuf },
}

#[derive(Debug, Clone, Serialize)]
struct CommandOutput {
    schema_version: String,
    component: String,
    out_dir: String,
    runtime_metadata_substrate_report: String,
    runtime_metadata_substrate_evidence_manifest: String,
    cache_miss_profile: String,
    metadata_fallback_receipts: String,
    substrate_override_receipts: String,
    run_manifest: String,
    events_jsonl: String,
    commands_txt: String,
    trace_ids: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    profiles_evaluated: usize,
    optimized_count: u32,
    fallback_count: u32,
    override_count: usize,
    report_hash: String,
    manifest_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct CacheMissProfileEntry {
    substrate_id: String,
    current_kind: String,
    access_count: u64,
    hit_rate_millionths: u64,
    miss_rate_millionths: u64,
    approx_miss_count: u64,
    avg_latency_millionths: u64,
    memory_bytes: u64,
    is_hot: bool,
}

#[derive(Debug, Clone, Serialize)]
struct MetadataFallbackReceipt {
    substrate_id: String,
    current_kind: String,
    recommended_kind: String,
    fallback_path: String,
    fallback_active: bool,
    rollback: String,
    reason: String,
    certificate_hash: String,
}

#[derive(Debug, Clone)]
struct OverrideScenario {
    scenario_id: &'static str,
    substrate_id: &'static str,
    config: OverrideConfig,
}

#[derive(Debug, Clone, Serialize)]
struct SubstrateOverrideReceipt {
    scenario_id: String,
    substrate_id: String,
    override_config: OverrideConfig,
    baseline_recommended_kind: String,
    overridden_kind: String,
    overridden_fallback: String,
    overridden_rollback: String,
    override_changed_recommendation: bool,
    override_changed_fallback: bool,
    certificate_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct ArtifactPaths {
    runtime_metadata_substrate_report: String,
    runtime_metadata_substrate_evidence_manifest: String,
    cache_miss_profile: String,
    metadata_fallback_receipts: String,
    substrate_override_receipts: String,
    run_manifest: String,
    events: String,
    commands: String,
    trace_ids: String,
}

#[derive(Debug, Clone, Serialize)]
struct RunManifest {
    schema_version: String,
    component: String,
    generated_at_utc: String,
    trace_ids: Vec<String>,
    decision_ids: Vec<String>,
    policy_ids: Vec<String>,
    profiles_evaluated: usize,
    optimized_count: u32,
    fallback_count: u32,
    override_count: usize,
    artifact_paths: ArtifactPaths,
}

#[derive(Debug, Clone, Serialize)]
struct TraceIdsArtifact {
    schema_version: String,
    trace_ids: Vec<String>,
    decision_ids: Vec<String>,
    policy_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct EventRecord {
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    outcome: String,
    error_code: Option<String>,
    substrate_id: Option<String>,
    detail: Option<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let out_dir = match parse_args(&args[1..])? {
        CliAction::Help => {
            println!("{}", help_text());
            return Ok(());
        }
        CliAction::Run { out_dir } => out_dir,
    };

    fs::create_dir_all(&out_dir)
        .map_err(|error| format!("failed to create output directory: {error}"))?;

    let report = build_canonical_inventory();
    let manifest = run_substrate_evidence();
    let cache_miss_profile = build_cache_miss_profile(&report);
    let fallback_receipts = build_fallback_receipts(&report, &manifest);
    let override_receipts = build_override_receipts(&report)?;

    let commands = vec![
        format!(
            "franken_metadata_substrate_evidence --out-dir {}",
            out_dir.display()
        ),
        format!(
            "cat {}/runtime_metadata_substrate_report.json",
            out_dir.display()
        ),
        format!(
            "cat {}/runtime_metadata_substrate_evidence_manifest.json",
            out_dir.display()
        ),
        format!("cat {}/cache_miss_profile.json", out_dir.display()),
        format!("cat {}/metadata_fallback_receipts.json", out_dir.display()),
        format!("cat {}/substrate_override_receipts.json", out_dir.display()),
        format!(
            "jq '.[] | select(.fallback_active == true)' {}/metadata_fallback_receipts.json",
            out_dir.display()
        ),
        format!(
            "jq '.[] | .scenario_id' {}/substrate_override_receipts.json",
            out_dir.display()
        ),
        "./scripts/e2e/metadata_substrate_evidence_replay.sh ci".to_string(),
    ];
    let artifact_paths = ArtifactPaths {
        runtime_metadata_substrate_report: "runtime_metadata_substrate_report.json".to_string(),
        runtime_metadata_substrate_evidence_manifest:
            "runtime_metadata_substrate_evidence_manifest.json".to_string(),
        cache_miss_profile: "cache_miss_profile.json".to_string(),
        metadata_fallback_receipts: "metadata_fallback_receipts.json".to_string(),
        substrate_override_receipts: "substrate_override_receipts.json".to_string(),
        run_manifest: "run_manifest.json".to_string(),
        events: "events.jsonl".to_string(),
        commands: "commands.txt".to_string(),
        trace_ids: "trace_ids.json".to_string(),
    };

    let run_manifest = RunManifest {
        schema_version: RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        component: SUBSTRATE_OPT_COMPONENT.to_string(),
        generated_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        trace_ids: vec![TRACE_ID.to_string()],
        decision_ids: vec![DECISION_ID.to_string()],
        policy_ids: vec![POLICY_ID.to_string()],
        profiles_evaluated: report.profiles.len(),
        optimized_count: report.optimized_count,
        fallback_count: report.fallback_count,
        override_count: override_receipts.len(),
        artifact_paths,
    };
    let trace_ids = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec![TRACE_ID.to_string()],
        decision_ids: vec![DECISION_ID.to_string()],
        policy_ids: vec![POLICY_ID.to_string()],
    };
    let events = build_events(&report, &fallback_receipts, &override_receipts);

    write_pretty_json(
        &out_dir.join("runtime_metadata_substrate_report.json"),
        &report,
    )?;
    write_pretty_json(
        &out_dir.join("runtime_metadata_substrate_evidence_manifest.json"),
        &manifest,
    )?;
    write_pretty_json(
        &out_dir.join("cache_miss_profile.json"),
        &cache_miss_profile,
    )?;
    write_pretty_json(
        &out_dir.join("metadata_fallback_receipts.json"),
        &fallback_receipts,
    )?;
    write_pretty_json(
        &out_dir.join("substrate_override_receipts.json"),
        &override_receipts,
    )?;
    write_pretty_json(&out_dir.join("run_manifest.json"), &run_manifest)?;
    write_pretty_json(&out_dir.join("trace_ids.json"), &trace_ids)?;
    write_commands(&out_dir.join("commands.txt"), &commands)?;
    write_events(&out_dir.join("events.jsonl"), &events)?;

    let output = CommandOutput {
        schema_version: OUTPUT_SCHEMA_VERSION.to_string(),
        component: SUBSTRATE_OPT_COMPONENT.to_string(),
        out_dir: out_dir.display().to_string(),
        runtime_metadata_substrate_report: out_dir
            .join("runtime_metadata_substrate_report.json")
            .display()
            .to_string(),
        runtime_metadata_substrate_evidence_manifest: out_dir
            .join("runtime_metadata_substrate_evidence_manifest.json")
            .display()
            .to_string(),
        cache_miss_profile: out_dir
            .join("cache_miss_profile.json")
            .display()
            .to_string(),
        metadata_fallback_receipts: out_dir
            .join("metadata_fallback_receipts.json")
            .display()
            .to_string(),
        substrate_override_receipts: out_dir
            .join("substrate_override_receipts.json")
            .display()
            .to_string(),
        run_manifest: out_dir.join("run_manifest.json").display().to_string(),
        events_jsonl: out_dir.join("events.jsonl").display().to_string(),
        commands_txt: out_dir.join("commands.txt").display().to_string(),
        trace_ids: out_dir.join("trace_ids.json").display().to_string(),
        trace_id: TRACE_ID.to_string(),
        decision_id: DECISION_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        profiles_evaluated: report.profiles.len(),
        optimized_count: report.optimized_count,
        fallback_count: report.fallback_count,
        override_count: override_receipts.len(),
        report_hash: report.report_hash.to_hex(),
        manifest_hash: manifest.manifest_hash.to_hex(),
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
            other => {
                return Err(format!(
                    "unrecognized argument `{other}`\n\n{}",
                    help_text()
                ));
            }
        }
    }

    out_dir
        .map(|out_dir| CliAction::Run { out_dir })
        .ok_or_else(|| format!("missing required --out-dir\n\n{}", help_text()))
}

fn help_text() -> String {
    "Usage: franken_metadata_substrate_evidence --out-dir <DIR>".to_string()
}

fn build_cache_miss_profile(report: &SubstrateInventoryReport) -> Vec<CacheMissProfileEntry> {
    report
        .profiles
        .iter()
        .map(|profile| {
            let miss_rate_millionths = 1_000_000u64.saturating_sub(profile.hit_rate_millionths);
            let approx_miss_count =
                profile.access_count.saturating_mul(miss_rate_millionths) / 1_000_000u64;
            CacheMissProfileEntry {
                substrate_id: profile.id.clone(),
                current_kind: profile.kind.to_string(),
                access_count: profile.access_count,
                hit_rate_millionths: profile.hit_rate_millionths,
                miss_rate_millionths,
                approx_miss_count,
                avg_latency_millionths: profile.avg_latency_millionths,
                memory_bytes: profile.memory_bytes,
                is_hot: profile.is_hot,
            }
        })
        .collect()
}

fn build_fallback_receipts(
    report: &SubstrateInventoryReport,
    manifest: &SubstrateEvidenceManifest,
) -> Vec<MetadataFallbackReceipt> {
    report
        .profiles
        .iter()
        .zip(report.decisions.iter())
        .zip(manifest.certificates.iter())
        .map(
            |((profile, decision), certificate)| MetadataFallbackReceipt {
                substrate_id: profile.id.clone(),
                current_kind: profile.kind.to_string(),
                recommended_kind: decision.recommended_kind.to_string(),
                fallback_path: decision.fallback.to_string(),
                fallback_active: decision.recommended_kind == SubstrateKind::GenericFallback,
                rollback: decision.rollback.to_string(),
                reason: fallback_reason(profile, decision),
                certificate_hash: certificate.certificate_hash.to_hex(),
            },
        )
        .collect()
}

fn fallback_reason(
    profile: &frankenengine_engine::metadata_substrate_optimized::SubstrateProfile,
    decision: &frankenengine_engine::metadata_substrate_optimized::OptimizationDecision,
) -> String {
    if decision.recommended_kind == SubstrateKind::GenericFallback {
        if !profile.is_hot {
            "not_hot".to_string()
        } else if profile.kind == SubstrateKind::GenericFallback {
            "generic_baseline_retained".to_string()
        } else {
            "forced_generic_fallback".to_string()
        }
    } else {
        "optimized_lane_has_explicit_fallback".to_string()
    }
}

fn build_override_receipts(
    report: &SubstrateInventoryReport,
) -> Result<Vec<SubstrateOverrideReceipt>, String> {
    let scenarios = [
        OverrideScenario {
            scenario_id: "disable-shape-table-primary",
            substrate_id: "shape_table_primary",
            config: OverrideConfig {
                disable_optimization: true,
                ..OverrideConfig::default()
            },
        },
        OverrideScenario {
            scenario_id: "force-string-intern-swiss",
            substrate_id: "string_intern_table",
            config: OverrideConfig {
                force_kind: Some(SubstrateKind::SwissTable),
                force_fallback: Some(FallbackPath::LinearProbe),
                force_rollback: Some(RollbackStrategy::CowClone),
                debug_mode: true,
                ..OverrideConfig::default()
            },
        },
        OverrideScenario {
            scenario_id: "force-alloc-site-flat-array",
            substrate_id: "alloc_site_tracker",
            config: OverrideConfig {
                force_kind: Some(SubstrateKind::FlatArray),
                force_fallback: Some(FallbackPath::GenericScan),
                force_rollback: Some(RollbackStrategy::Rebuild),
                ..OverrideConfig::default()
            },
        },
    ];

    let mut receipts = Vec::new();
    for scenario in scenarios {
        let (profile, baseline) = report
            .profiles
            .iter()
            .zip(report.decisions.iter())
            .find(|(profile, _)| profile.id == scenario.substrate_id)
            .ok_or_else(|| format!("missing canonical profile `{}`", scenario.substrate_id))?;

        let overridden = evaluate_substrate(profile, Some(&scenario.config));
        let certificate = certify_substrate(profile, &overridden);
        receipts.push(SubstrateOverrideReceipt {
            scenario_id: scenario.scenario_id.to_string(),
            substrate_id: profile.id.clone(),
            override_config: scenario.config,
            baseline_recommended_kind: baseline.recommended_kind.to_string(),
            overridden_kind: overridden.recommended_kind.to_string(),
            overridden_fallback: overridden.fallback.to_string(),
            overridden_rollback: overridden.rollback.to_string(),
            override_changed_recommendation: overridden.recommended_kind
                != baseline.recommended_kind,
            override_changed_fallback: overridden.fallback != baseline.fallback,
            certificate_hash: certificate.certificate_hash.to_hex(),
        });
    }

    Ok(receipts)
}

fn build_events(
    report: &SubstrateInventoryReport,
    fallback_receipts: &[MetadataFallbackReceipt],
    override_receipts: &[SubstrateOverrideReceipt],
) -> Vec<EventRecord> {
    let mut events = Vec::new();
    events.push(EventRecord {
        trace_id: TRACE_ID.to_string(),
        decision_id: DECISION_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        component: SUBSTRATE_OPT_COMPONENT.to_string(),
        event: "inventory_built".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        substrate_id: None,
        detail: Some(format!(
            "profiles={} optimized={} fallback={}",
            report.profiles.len(),
            report.optimized_count,
            report.fallback_count
        )),
    });

    for receipt in fallback_receipts {
        events.push(EventRecord {
            trace_id: TRACE_ID.to_string(),
            decision_id: DECISION_ID.to_string(),
            policy_id: POLICY_ID.to_string(),
            component: SUBSTRATE_OPT_COMPONENT.to_string(),
            event: "substrate_evaluated".to_string(),
            outcome: if receipt.fallback_active {
                "fallback".to_string()
            } else {
                "optimized".to_string()
            },
            error_code: None,
            substrate_id: Some(receipt.substrate_id.clone()),
            detail: Some(format!(
                "recommended={} fallback_path={} reason={}",
                receipt.recommended_kind, receipt.fallback_path, receipt.reason
            )),
        });
    }

    for receipt in override_receipts {
        events.push(EventRecord {
            trace_id: TRACE_ID.to_string(),
            decision_id: DECISION_ID.to_string(),
            policy_id: POLICY_ID.to_string(),
            component: SUBSTRATE_OPT_COMPONENT.to_string(),
            event: "override_evaluated".to_string(),
            outcome: if receipt.override_changed_recommendation {
                "override_applied".to_string()
            } else {
                "override_noop".to_string()
            },
            error_code: None,
            substrate_id: Some(receipt.substrate_id.clone()),
            detail: Some(format!(
                "scenario={} baseline={} overridden={}",
                receipt.scenario_id, receipt.baseline_recommended_kind, receipt.overridden_kind
            )),
        });
    }

    events.push(EventRecord {
        trace_id: TRACE_ID.to_string(),
        decision_id: DECISION_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        component: SUBSTRATE_OPT_COMPONENT.to_string(),
        event: "artifact_bundle_emitted".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        substrate_id: None,
        detail: Some("runtime metadata substrate evidence bundle written".to_string()),
    });

    events
}

fn write_pretty_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let rendered = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    fs::write(path, rendered)
        .map_err(|error| format!("failed to write {}: {error}", path.display()))
}

fn write_commands(path: &Path, commands: &[String]) -> Result<(), String> {
    let mut rendered = String::new();
    for command in commands {
        rendered.push_str(command);
        rendered.push('\n');
    }
    fs::write(path, rendered)
        .map_err(|error| format!("failed to write {}: {error}", path.display()))
}

fn write_events(path: &Path, events: &[EventRecord]) -> Result<(), String> {
    let mut rendered = String::new();
    for event in events {
        let line = serde_json::to_string(event).map_err(|error| error.to_string())?;
        rendered.push_str(&line);
        rendered.push('\n');
    }
    fs::write(path, rendered)
        .map_err(|error| format!("failed to write {}: {error}", path.display()))
}
