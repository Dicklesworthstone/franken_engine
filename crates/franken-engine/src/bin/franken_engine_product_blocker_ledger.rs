use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::engine_product_blocker_ledger::{
    BEAD_ID, BlockerLedger, BlockerLedgerGate, BlockerSeverity, COMPONENT, RemediationStatus,
    build_seed_ledger,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct EmitConfig {
    pub artifact_dir: PathBuf,
    pub beads_json: PathBuf,
    pub support_contract_json: PathBuf,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub generated_at_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmitReport {
    pub artifact_dir: String,
    pub ledger_path: String,
    pub cohort_rollup_path: String,
    pub owner_routing_report_path: String,
    pub gate_report_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct BeadSnapshotEntry {
    id: String,
    status: String,
    assignee: Option<String>,
    title: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SupportSurfaceContract {
    readiness_answer_contract: ReadinessAnswerContract,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ReadinessAnswerContract {
    engine_ready_when_support_status_in: Vec<String>,
    engine_blocked_when_support_status_in: Vec<String>,
    product_ready_state: String,
    product_ready_owner_repo: String,
    product_ready_handoff_bead_id: String,
    operator_rule_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CohortRollupArtifact {
    schema_version: String,
    bead_id: String,
    component: String,
    generated_at_utc: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    total_cohorts: usize,
    ready_or_advisory_count: usize,
    blocked_or_partial_count: usize,
    cohort_rollups: Vec<CohortRollupRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CohortRollupRow {
    cohort_name: String,
    readiness: String,
    blocker_count: usize,
    blocking_count: usize,
    degraded_count: usize,
    resolved_count: usize,
    readiness_rate_millionths: u64,
    blocker_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct OwnerRoutingReport {
    schema_version: String,
    bead_id: String,
    component: String,
    generated_at_utc: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    downstream_product_ready_state: String,
    downstream_product_ready_owner_repo: String,
    downstream_product_ready_handoff_bead_id: String,
    operator_rule_summary: String,
    orphaned_unresolved_count: usize,
    routes: Vec<OwnerRoutingEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct OwnerRoutingEntry {
    blocker_id: String,
    surface: String,
    severity: String,
    remediation: String,
    tracking_bead: Option<String>,
    tracking_status: Option<String>,
    tracking_title: Option<String>,
    owner: Option<String>,
    owner_repo: String,
    route_status: String,
    recommended_next_action: String,
}

const COHORT_SCHEMA_VERSION: &str = "franken-engine.engine-product-blocker-ledger.cohort-rollup.v1";
const OWNER_ROUTING_SCHEMA_VERSION: &str =
    "franken-engine.engine-product-blocker-ledger.owner-routing.v1";
const LOCAL_BUNDLE_JSON_BEGIN: &str = "__RGC_ENGINE_PRODUCT_BLOCKER_LEDGER_BUNDLE_JSON_BEGIN__";
const LOCAL_BUNDLE_JSON_END: &str = "__RGC_ENGINE_PRODUCT_BLOCKER_LEDGER_BUNDLE_JSON_END__";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LocalBundleFile {
    relative_path: String,
    contents: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LocalBundlePayload {
    artifact_dir: String,
    files: Vec<LocalBundleFile>,
}

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

pub fn run(args: Vec<String>) -> Result<(), String> {
    let (config, emit_local_bundle_json) = parse_args(args)?;
    let report = emit_bundle(&config)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("failed to encode emit report: {error}"))?
    );
    if emit_local_bundle_json {
        let payload = build_local_bundle_payload(&report)?;
        println!("{LOCAL_BUNDLE_JSON_BEGIN}");
        println!(
            "{}",
            serde_json::to_string(&payload)
                .map_err(|error| format!("failed to encode local bundle payload: {error}"))?
        );
        println!("{LOCAL_BUNDLE_JSON_END}");
    }
    Ok(())
}

pub fn emit_bundle(config: &EmitConfig) -> Result<EmitReport, String> {
    let support_contract = read_support_contract(&config.support_contract_json)?;
    validate_support_contract(&support_contract)?;

    let beads = read_bead_snapshot(&config.beads_json)?;
    let bead_index = beads
        .into_iter()
        .map(|entry| (entry.id.clone(), entry))
        .collect::<BTreeMap<_, _>>();

    let mut ledger = build_seed_ledger();
    enrich_ledger(&mut ledger, &bead_index)?;

    let gate_report = BlockerLedgerGate::with_defaults().evaluate(&ledger);
    let cohort_artifact = build_cohort_rollup_artifact(&ledger, config);
    let owner_routing_report =
        build_owner_routing_report(&ledger, &bead_index, &support_contract, config);

    fs::create_dir_all(&config.artifact_dir).map_err(|error| {
        format!(
            "failed to create artifact dir {}: {error}",
            config.artifact_dir.display()
        )
    })?;

    let ledger_path = config
        .artifact_dir
        .join("engine_product_blocker_ledger.json");
    let cohort_rollup_path = config.artifact_dir.join("cohort_readiness_rollup.json");
    let owner_routing_report_path = config.artifact_dir.join("owner_routing_report.json");
    let gate_report_path = config.artifact_dir.join("gate_report.json");

    write_json(&ledger_path, &ledger)?;
    write_json(&cohort_rollup_path, &cohort_artifact)?;
    write_json(&owner_routing_report_path, &owner_routing_report)?;
    write_json(&gate_report_path, &gate_report)?;

    Ok(EmitReport {
        artifact_dir: config.artifact_dir.display().to_string(),
        ledger_path: ledger_path.display().to_string(),
        cohort_rollup_path: cohort_rollup_path.display().to_string(),
        owner_routing_report_path: owner_routing_report_path.display().to_string(),
        gate_report_path: gate_report_path.display().to_string(),
    })
}

fn parse_args(args: Vec<String>) -> Result<(EmitConfig, bool), String> {
    if args.is_empty() {
        return Err(usage());
    }

    let mut artifact_dir = None;
    let mut beads_json = None;
    let mut support_contract_json = None;
    let mut trace_id = None;
    let mut decision_id = None;
    let mut policy_id = None;
    let mut generated_at_utc = None;
    let mut emit_local_bundle_json = false;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--artifact-dir" => {
                index += 1;
                artifact_dir = Some(path_arg(&args, index, "--artifact-dir")?);
            }
            "--beads-json" => {
                index += 1;
                beads_json = Some(path_arg(&args, index, "--beads-json")?);
            }
            "--support-contract-json" => {
                index += 1;
                support_contract_json = Some(path_arg(&args, index, "--support-contract-json")?);
            }
            "--trace-id" => {
                index += 1;
                trace_id = Some(string_arg(&args, index, "--trace-id")?);
            }
            "--decision-id" => {
                index += 1;
                decision_id = Some(string_arg(&args, index, "--decision-id")?);
            }
            "--policy-id" => {
                index += 1;
                policy_id = Some(string_arg(&args, index, "--policy-id")?);
            }
            "--generated-at-utc" => {
                index += 1;
                generated_at_utc = Some(string_arg(&args, index, "--generated-at-utc")?);
            }
            "--emit-local-bundle-json" => {
                emit_local_bundle_json = true;
            }
            "help" | "--help" | "-h" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            flag => {
                return Err(format!("unknown flag '{flag}'\n\n{}", usage()));
            }
        }
        index += 1;
    }

    Ok((
        EmitConfig {
            artifact_dir: artifact_dir
                .ok_or_else(|| "missing required --artifact-dir <path>".to_string())?,
            beads_json: beads_json
                .ok_or_else(|| "missing required --beads-json <path>".to_string())?,
            support_contract_json: support_contract_json
                .ok_or_else(|| "missing required --support-contract-json <path>".to_string())?,
            trace_id: trace_id
                .unwrap_or_else(|| "trace-rgc-engine-product-blocker-ledger-local".to_string()),
            decision_id: decision_id
                .unwrap_or_else(|| "decision-rgc-engine-product-blocker-ledger-local".to_string()),
            policy_id: policy_id
                .unwrap_or_else(|| "policy-rgc-engine-product-blocker-ledger-v1".to_string()),
            generated_at_utc: generated_at_utc
                .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string()),
        },
        emit_local_bundle_json,
    ))
}

fn path_arg(args: &[String], index: usize, flag: &str) -> Result<PathBuf, String> {
    Ok(PathBuf::from(string_arg(args, index, flag)?))
}

fn string_arg(args: &[String], index: usize, flag: &str) -> Result<String, String> {
    args.get(index)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn usage() -> String {
    [
        "franken_engine_product_blocker_ledger usage:",
        "  cargo run -p frankenengine-engine --bin franken_engine_product_blocker_ledger -- \\",
        "      --artifact-dir <path> --beads-json <path> --support-contract-json <path> \\",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>] \\",
        "      [--generated-at-utc <rfc3339>] [--emit-local-bundle-json]",
    ]
    .join("\n")
}

fn build_local_bundle_payload(report: &EmitReport) -> Result<LocalBundlePayload, String> {
    let artifact_dir = PathBuf::from(&report.artifact_dir);
    let output_paths = [
        PathBuf::from(&report.ledger_path),
        PathBuf::from(&report.cohort_rollup_path),
        PathBuf::from(&report.owner_routing_report_path),
        PathBuf::from(&report.gate_report_path),
    ];

    let files = output_paths
        .iter()
        .map(|absolute_path| {
            let contents = fs::read_to_string(absolute_path).map_err(|error| {
                format!(
                    "failed to read emitted artifact {}: {error}",
                    absolute_path.display()
                )
            })?;
            let relative_path = absolute_path
                .strip_prefix(&artifact_dir)
                .map_err(|error| {
                    format!(
                        "failed to relativize artifact {} against {}: {error}",
                        absolute_path.display(),
                        artifact_dir.display()
                    )
                })?
                .display()
                .to_string();
            Ok(LocalBundleFile {
                relative_path,
                contents,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(LocalBundlePayload {
        artifact_dir: report.artifact_dir.clone(),
        files,
    })
}

fn read_support_contract(path: &Path) -> Result<SupportSurfaceContract, String> {
    let contents = fs::read_to_string(path).map_err(|error| {
        format!(
            "failed to read support contract {}: {error}",
            path.display()
        )
    })?;
    serde_json::from_str(&contents).map_err(|error| {
        format!(
            "failed to parse support contract {}: {error}",
            path.display()
        )
    })
}

fn read_bead_snapshot(path: &Path) -> Result<Vec<BeadSnapshotEntry>, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("failed to read bead snapshot {}: {error}", path.display()))?;
    serde_json::from_str(&contents)
        .map_err(|error| format!("failed to parse bead snapshot {}: {error}", path.display()))
}

fn validate_support_contract(contract: &SupportSurfaceContract) -> Result<(), String> {
    let readiness = &contract.readiness_answer_contract;
    if readiness.product_ready_state != "delegated_to_franken_node_handoff" {
        return Err(format!(
            "support contract product_ready_state must be delegated_to_franken_node_handoff, got {}",
            readiness.product_ready_state
        ));
    }
    if readiness.product_ready_owner_repo != "franken_node" {
        return Err(format!(
            "support contract product_ready_owner_repo must be franken_node, got {}",
            readiness.product_ready_owner_repo
        ));
    }
    if readiness.product_ready_handoff_bead_id.trim().is_empty() {
        return Err("support contract product_ready_handoff_bead_id must be non-empty".to_string());
    }
    if !readiness
        .engine_ready_when_support_status_in
        .iter()
        .any(|status| status == "shipped")
    {
        return Err(
            "support contract must treat at least support_status=shipped as engine-ready"
                .to_string(),
        );
    }
    if readiness.engine_blocked_when_support_status_in.is_empty() {
        return Err(
            "support contract must expose at least one engine-blocked support status".to_string(),
        );
    }
    Ok(())
}

fn enrich_ledger(
    ledger: &mut BlockerLedger,
    bead_index: &BTreeMap<String, BeadSnapshotEntry>,
) -> Result<(), String> {
    let mut missing_tracking_beads = Vec::new();

    for blocker in &mut ledger.blockers {
        if let Some(tracking_bead) = blocker.tracking_bead.as_ref() {
            match bead_index.get(tracking_bead) {
                Some(bead) => {
                    blocker.owner = bead.assignee.clone().or_else(|| blocker.owner.clone());
                    blocker.remediation = remediation_from_bead(bead, blocker.remediation);
                }
                None if is_unresolved_release_relevant(blocker.severity, blocker.remediation) => {
                    missing_tracking_beads.push(tracking_bead.clone());
                }
                None => {}
            }
        }
    }

    if !missing_tracking_beads.is_empty() {
        missing_tracking_beads.sort();
        missing_tracking_beads.dedup();
        return Err(format!(
            "tracking beads missing from snapshot: {}",
            missing_tracking_beads.join(", ")
        ));
    }

    let orphaned = ledger
        .blockers
        .iter()
        .filter(|blocker| is_unresolved_release_relevant(blocker.severity, blocker.remediation))
        .filter(|blocker| blocker.tracking_bead.is_none() && blocker.owner.is_none())
        .map(|blocker| blocker.id.clone())
        .collect::<Vec<_>>();
    if !orphaned.is_empty() {
        return Err(format!(
            "unresolved blocking/degraded blockers missing both tracking bead and owner: {}",
            orphaned.join(", ")
        ));
    }

    Ok(())
}

fn remediation_from_bead(
    bead: &BeadSnapshotEntry,
    existing: RemediationStatus,
) -> RemediationStatus {
    match bead.status.as_str() {
        "closed" => RemediationStatus::Verified,
        "in_progress" => RemediationStatus::InProgress,
        "blocked" => RemediationStatus::Investigating,
        "open" => {
            if bead.assignee.is_some() {
                RemediationStatus::Investigating
            } else {
                RemediationStatus::Unowned
            }
        }
        _ => existing,
    }
}

fn is_unresolved_release_relevant(
    severity: BlockerSeverity,
    remediation: RemediationStatus,
) -> bool {
    matches!(
        severity,
        BlockerSeverity::Blocking | BlockerSeverity::Degraded
    ) && !remediation.is_resolved()
}

fn build_cohort_rollup_artifact(
    ledger: &BlockerLedger,
    config: &EmitConfig,
) -> CohortRollupArtifact {
    let ready_or_advisory_count = ledger
        .cohort_rollups
        .iter()
        .filter(|rollup| rollup.readiness.permits_release())
        .count();
    let blocked_or_partial_count = ledger.cohort_rollups.len() - ready_or_advisory_count;

    CohortRollupArtifact {
        schema_version: COHORT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: config.generated_at_utc.clone(),
        trace_id: config.trace_id.clone(),
        decision_id: config.decision_id.clone(),
        policy_id: config.policy_id.clone(),
        total_cohorts: ledger.cohort_rollups.len(),
        ready_or_advisory_count,
        blocked_or_partial_count,
        cohort_rollups: ledger
            .cohort_rollups
            .iter()
            .map(|rollup| CohortRollupRow {
                cohort_name: rollup.cohort_name.clone(),
                readiness: rollup.readiness.as_str().to_string(),
                blocker_count: rollup.blocker_count,
                blocking_count: rollup.blocking_count,
                degraded_count: rollup.degraded_count,
                resolved_count: rollup.resolved_count,
                readiness_rate_millionths: rollup.readiness_rate_millionths,
                blocker_ids: rollup.blocker_ids.clone(),
            })
            .collect(),
    }
}

fn build_owner_routing_report(
    ledger: &BlockerLedger,
    bead_index: &BTreeMap<String, BeadSnapshotEntry>,
    support_contract: &SupportSurfaceContract,
    config: &EmitConfig,
) -> OwnerRoutingReport {
    let routes = ledger
        .blockers
        .iter()
        .map(|blocker| {
            let bead = blocker
                .tracking_bead
                .as_ref()
                .and_then(|tracking_bead| bead_index.get(tracking_bead));

            let route_status = if blocker.owner.is_some() {
                "owned"
            } else if blocker.tracking_bead.is_some() {
                "bead_only"
            } else if is_unresolved_release_relevant(blocker.severity, blocker.remediation) {
                "orphaned"
            } else {
                "informational"
            };

            let recommended_next_action = match route_status {
                "owned" => format!(
                    "route through {} in {}",
                    blocker.owner.as_deref().unwrap_or("unassigned"),
                    blocker.tracking_bead.as_deref().unwrap_or(BEAD_ID)
                ),
                "bead_only" => format!(
                    "claim or continue {} from the blocker ledger queue",
                    blocker.tracking_bead.as_deref().unwrap_or(BEAD_ID)
                ),
                "orphaned" => format!(
                    "attach a tracking bead or owner before downstream {} handoff claims",
                    support_contract
                        .readiness_answer_contract
                        .product_ready_owner_repo
                ),
                _ => "no immediate routing action required".to_string(),
            };

            OwnerRoutingEntry {
                blocker_id: blocker.id.clone(),
                surface: blocker.surface.as_str().to_string(),
                severity: blocker.severity.as_str().to_string(),
                remediation: blocker.remediation.as_str().to_string(),
                tracking_bead: blocker.tracking_bead.clone(),
                tracking_status: bead.map(|entry| entry.status.clone()),
                tracking_title: bead.and_then(|entry| entry.title.clone()),
                owner: blocker.owner.clone(),
                owner_repo: "franken_engine".to_string(),
                route_status: route_status.to_string(),
                recommended_next_action,
            }
        })
        .collect::<Vec<_>>();

    let orphaned_unresolved_count = routes
        .iter()
        .filter(|entry| entry.route_status == "orphaned")
        .count();

    OwnerRoutingReport {
        schema_version: OWNER_ROUTING_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: config.generated_at_utc.clone(),
        trace_id: config.trace_id.clone(),
        decision_id: config.decision_id.clone(),
        policy_id: config.policy_id.clone(),
        downstream_product_ready_state: support_contract
            .readiness_answer_contract
            .product_ready_state
            .clone(),
        downstream_product_ready_owner_repo: support_contract
            .readiness_answer_contract
            .product_ready_owner_repo
            .clone(),
        downstream_product_ready_handoff_bead_id: support_contract
            .readiness_answer_contract
            .product_ready_handoff_bead_id
            .clone(),
        operator_rule_summary: support_contract
            .readiness_answer_contract
            .operator_rule_summary
            .clone(),
        orphaned_unresolved_count,
        routes,
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let contents = serde_json::to_string_pretty(value)
        .map_err(|error| format!("failed to encode {}: {error}", path.display()))?;
    fs::write(path, contents)
        .map_err(|error| format!("failed to write {}: {error}", path.display()))
}
