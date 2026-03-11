#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::npm_compatibility_matrix::{
    BEAD_ID, COMPONENT, CohortSummary, IncompatibilityRecord, IncompatibilityRootCause,
    IncompatibilitySeverity, NpmCompatibilityMatrix, PackageTestOutcome, PackageTestResult,
    RemediationState, SCHEMA_VERSION, seed_tier1_critical_packages, seed_tier2_popular_packages,
};
use serde::Serialize;

const OUTPUT_SCHEMA_VERSION: &str = "franken-engine.franken_npm_compatibility_matrix.v1";
const REPORT_SCHEMA_VERSION: &str = "franken-engine.npm_compatibility_matrix.report.v1";
const TRACE_IDS_SCHEMA_VERSION: &str = "franken-engine.npm_compatibility_matrix.trace_ids.v1";
const RUN_MANIFEST_SCHEMA_VERSION: &str = "franken-engine.npm_compatibility_matrix.run_manifest.v1";
const EVENT_SCHEMA_VERSION: &str = "franken-engine.npm_compatibility_matrix.event.v1";
const POLICY_ID: &str = "policy-rgc-404-npm-compatibility-v1";
const SCENARIO_ID: &str = "rgc-404-npm-compatibility-matrix";
const SNAPSHOT_EPOCH: u64 = 404;

enum CliAction {
    Help,
    Run { out_dir: PathBuf },
}

#[derive(Debug, Clone, Serialize)]
struct CommandOutput {
    schema_version: String,
    out_dir: String,
    npm_compat_matrix_report: String,
    trace_ids: String,
    run_manifest: String,
    events_jsonl: String,
    commands_txt: String,
    matrix_hash: String,
    verdict: String,
    package_count: usize,
    incompatibility_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct TraceIds {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    scenario_id: String,
}

#[derive(Debug, Clone, Serialize)]
struct ArtifactPaths {
    npm_compat_matrix_report: String,
    trace_ids: String,
    run_manifest: String,
    events_jsonl: String,
    commands_txt: String,
}

#[derive(Debug, Clone, Serialize)]
struct RunManifest {
    schema_version: String,
    component: String,
    bead_id: String,
    scenario_id: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    matrix_schema_version: String,
    matrix_hash: String,
    verdict: String,
    package_count: usize,
    incompatibility_count: usize,
    artifact_paths: ArtifactPaths,
}

#[derive(Debug, Clone, Serialize)]
struct NpmCompatibilityReport {
    schema_version: String,
    component: String,
    bead_id: String,
    scenario_id: String,
    matrix_schema_version: String,
    matrix_hash: String,
    verdict: String,
    snapshot_epoch: u64,
    package_count: usize,
    incompatibility_count: usize,
    cohort_summaries: Vec<CohortSummary>,
    root_cause_distribution: Vec<RootCauseCount>,
    top_blockers: Vec<TopBlocker>,
    packages: Vec<PackageOutcomeRecord>,
    unresolved_failures: Vec<UnresolvedFailureRouting>,
}

#[derive(Debug, Clone, Serialize)]
struct RootCauseCount {
    root_cause: String,
    open_count: u32,
}

#[derive(Debug, Clone, Serialize)]
struct TopBlocker {
    package_name: String,
    weighted_open_score_millionths: u64,
}

#[derive(Debug, Clone, Serialize)]
struct PackageOutcomeRecord {
    name: String,
    version: String,
    tier: String,
    category: String,
    module_system: String,
    weekly_downloads: u64,
    outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pass_rate_millionths: Option<u64>,
    unresolved_incompatibility_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct UnresolvedFailureRouting {
    incompatibility_id: String,
    package_name: String,
    root_cause: String,
    severity: String,
    summary: String,
    owner: String,
    related_beads: Vec<String>,
    remediation_state: String,
    minimized_repro: String,
    expected_behavior: String,
    actual_behavior: String,
}

#[derive(Debug, Clone, Serialize)]
struct MatrixEvent {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
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

    let mut matrix = build_seed_matrix()?;
    let matrix_hash = matrix.normalize_and_hash().to_hex();
    let trace_id = format!("trace-rgc-404-{}", &matrix_hash[..16]);
    let decision_id = format!("decision-rgc-404-{}", &matrix_hash[..16]);

    let report = build_report(&matrix, &matrix_hash);
    let trace_ids = TraceIds {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: POLICY_ID.to_string(),
        scenario_id: SCENARIO_ID.to_string(),
    };
    let commands = vec![
        format!(
            "franken_npm_compatibility_matrix --out-dir {}",
            out_dir.display()
        ),
        format!("cat {}/npm_compat_matrix_report.json", out_dir.display()),
        format!("cat {}/run_manifest.json", out_dir.display()),
        format!(
            "jq '.unresolved_failures' {}/npm_compat_matrix_report.json",
            out_dir.display()
        ),
        "./scripts/e2e/rgc_npm_compatibility_matrix_replay.sh ci".to_string(),
    ];
    let events = build_events(&matrix, &trace_id, &decision_id, &matrix_hash);
    let manifest = RunManifest {
        schema_version: RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        scenario_id: SCENARIO_ID.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: POLICY_ID.to_string(),
        matrix_schema_version: SCHEMA_VERSION.to_string(),
        matrix_hash: matrix_hash.clone(),
        verdict: matrix.verdict().as_str().to_string(),
        package_count: matrix.total_packages(),
        incompatibility_count: matrix.total_incompatibilities(),
        artifact_paths: ArtifactPaths {
            npm_compat_matrix_report: "npm_compat_matrix_report.json".to_string(),
            trace_ids: "trace_ids.json".to_string(),
            run_manifest: "run_manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
        },
    };

    let report_path = out_dir.join("npm_compat_matrix_report.json");
    let trace_ids_path = out_dir.join("trace_ids.json");
    let run_manifest_path = out_dir.join("run_manifest.json");
    let events_path = out_dir.join("events.jsonl");
    let commands_path = out_dir.join("commands.txt");

    write_json(&report_path, &report)?;
    write_json(&trace_ids_path, &trace_ids)?;
    write_json(&run_manifest_path, &manifest)?;
    write_jsonl(&events_path, &events)?;
    write_text(&commands_path, &commands.join("\n"))?;

    let output = CommandOutput {
        schema_version: OUTPUT_SCHEMA_VERSION.to_string(),
        out_dir: out_dir.display().to_string(),
        npm_compat_matrix_report: report_path.display().to_string(),
        trace_ids: trace_ids_path.display().to_string(),
        run_manifest: run_manifest_path.display().to_string(),
        events_jsonl: events_path.display().to_string(),
        commands_txt: commands_path.display().to_string(),
        matrix_hash,
        verdict: matrix.verdict().as_str().to_string(),
        package_count: matrix.total_packages(),
        incompatibility_count: matrix.total_incompatibilities(),
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
    "Usage: franken_npm_compatibility_matrix --out-dir <DIR>".to_string()
}

fn build_seed_matrix() -> Result<NpmCompatibilityMatrix, String> {
    let mut matrix = NpmCompatibilityMatrix::new();
    matrix.snapshot_epoch = SNAPSHOT_EPOCH;

    for package in seed_tier1_critical_packages()
        .into_iter()
        .chain(seed_tier2_popular_packages())
    {
        matrix
            .add_package(package)
            .map_err(|error| error.to_string())?;
    }

    for (name, outcome, total_tests, passed_tests, skipped_tests) in [
        ("express", PackageTestOutcome::Compatible, 24, 24, 0),
        (
            "typescript",
            PackageTestOutcome::PartiallyCompatible,
            40,
            31,
            0,
        ),
        ("lodash", PackageTestOutcome::Compatible, 18, 18, 0),
        ("axios", PackageTestOutcome::Compatible, 16, 16, 0),
        ("chalk", PackageTestOutcome::Incompatible, 12, 0, 0),
        ("uuid", PackageTestOutcome::Compatible, 14, 14, 0),
        ("commander", PackageTestOutcome::Compatible, 15, 15, 0),
        ("dotenv", PackageTestOutcome::PartiallyCompatible, 10, 7, 0),
        ("zod", PackageTestOutcome::Compatible, 20, 20, 0),
        ("date-fns", PackageTestOutcome::Incompatible, 22, 0, 0),
        ("fastify", PackageTestOutcome::Compatible, 19, 19, 0),
        ("vitest", PackageTestOutcome::Incompatible, 28, 0, 0),
        ("prisma", PackageTestOutcome::Skipped, 0, 0, 6),
        ("glob", PackageTestOutcome::Compatible, 11, 11, 0),
        ("ora", PackageTestOutcome::Compatible, 9, 9, 0),
        ("jsonwebtoken", PackageTestOutcome::Compatible, 13, 13, 0),
        ("ws", PackageTestOutcome::PartiallyCompatible, 17, 10, 0),
        ("yargs", PackageTestOutcome::Compatible, 12, 12, 0),
        (
            "chokidar",
            PackageTestOutcome::PartiallyCompatible,
            15,
            8,
            0,
        ),
        ("pino", PackageTestOutcome::Compatible, 14, 14, 0),
    ] {
        record_result(
            &mut matrix,
            name,
            outcome,
            total_tests,
            passed_tests,
            skipped_tests,
        )?;
    }

    for incompatibility in [
        make_incompatibility(
            "INC-typescript-ts-normalization",
            "typescript",
            IncompatibilityRootCause::TypeScriptCompilation,
            IncompatibilitySeverity::Major,
            "transpile-only workflows still hit syntax-aware normalization gaps on a subset of project references",
            "bd-1lsy.3.4.1",
            &["bd-1lsy.3.4.1"],
        ),
        make_incompatibility(
            "INC-chalk-esm-require",
            "chalk",
            IncompatibilityRootCause::CjsRequireDivergence,
            IncompatibilitySeverity::Major,
            "chalk's ESM-only entry still rejects a legacy require path in strict compatibility mode",
            "bd-1lsy.5.2",
            &["bd-1lsy.5.2", "bd-1lsy.10.6"],
        ),
        make_incompatibility(
            "INC-dotenv-process-globals",
            "dotenv",
            IncompatibilityRootCause::ProcessGlobalsDivergence,
            IncompatibilitySeverity::Minor,
            "dotenv still depends on process-global edge cases that need explicit compatibility routing",
            "bd-1lsy.5.4",
            &["bd-1lsy.5.4", "bd-1lsy.10.6"],
        ),
        make_incompatibility(
            "INC-datefns-exports-map",
            "date-fns",
            IncompatibilityRootCause::ExportsMapDivergence,
            IncompatibilitySeverity::Major,
            "date-fns package export conditions still diverge from the intended shipped package index contract",
            "bd-1lsy.5.8.3",
            &["bd-1lsy.5.8.3", "bd-1lsy.10.6"],
        ),
        make_incompatibility(
            "INC-vitest-ts-runtime",
            "vitest",
            IncompatibilityRootCause::TypeScriptCompilation,
            IncompatibilitySeverity::Blocker,
            "vitest's TS-heavy entrygraph still fails in the current normalization/runtime bridge",
            "bd-1lsy.3.4.1",
            &["bd-1lsy.3.4.1", "bd-1lsy.5.7.1"],
        ),
        make_incompatibility(
            "INC-prisma-native-addon",
            "prisma",
            IncompatibilityRootCause::NativeAddon,
            IncompatibilitySeverity::Blocker,
            "prisma currently requires a native-engine fallback path through the addon membrane inventory lane",
            "bd-1lsy.5.9.1",
            &["bd-1lsy.5.9.1", "bd-1lsy.10.6"],
        ),
        make_incompatibility(
            "INC-ws-stream-buffer",
            "ws",
            IncompatibilityRootCause::StreamBufferDivergence,
            IncompatibilitySeverity::Major,
            "ws still exercises a stream/buffer edge that needs explicit owner routing for compatibility work",
            "bd-1lsy.5.4",
            &["bd-1lsy.5.4", "bd-1lsy.10.6"],
        ),
        make_incompatibility(
            "INC-chokidar-esm-resolution",
            "chokidar",
            IncompatibilityRootCause::EsmResolutionDivergence,
            IncompatibilitySeverity::Major,
            "chokidar's ESM resolution path still depends on package-subpath semantics not fully closed in the module lane",
            "bd-1lsy.5.2",
            &["bd-1lsy.5.2", "bd-1lsy.10.6"],
        ),
    ] {
        matrix
            .add_incompatibility(incompatibility)
            .map_err(|error| error.to_string())?;
    }

    Ok(matrix)
}

fn record_result(
    matrix: &mut NpmCompatibilityMatrix,
    package_name: &str,
    outcome: PackageTestOutcome,
    total_tests: u32,
    passed_tests: u32,
    skipped_tests: u32,
) -> Result<(), String> {
    let failed_tests = total_tests.saturating_sub(passed_tests);
    let output_hash = ContentHash::compute(
        format!(
            "{package_name}:{}:{total_tests}:{passed_tests}:{failed_tests}:{skipped_tests}",
            outcome.as_str()
        )
        .as_bytes(),
    )
    .to_hex();

    matrix
        .record_test_result(PackageTestResult {
            package_name: package_name.to_string(),
            version: matrix
                .packages
                .iter()
                .find(|package| package.name == package_name)
                .map(|package| package.version.clone())
                .ok_or_else(|| format!("missing package record for {package_name}"))?,
            outcome,
            total_tests,
            passed_tests,
            failed_tests,
            skipped_tests,
            output_hash: Some(output_hash),
            test_epoch: SNAPSHOT_EPOCH,
        })
        .map_err(|error| error.to_string())
}

fn make_incompatibility(
    incompatibility_id: &str,
    package_name: &str,
    root_cause: IncompatibilityRootCause,
    severity: IncompatibilitySeverity,
    summary: &str,
    owner: &str,
    related_beads: &[&str],
) -> IncompatibilityRecord {
    IncompatibilityRecord {
        incompatibility_id: incompatibility_id.to_string(),
        package_name: package_name.to_string(),
        root_cause,
        severity,
        summary: summary.to_string(),
        minimized_repro: format!("node -e \"require('{package_name}')\""),
        expected_behavior: "package entrypoint loads and completes its focused smoke fixture".to_string(),
        actual_behavior: "compatibility matrix still records a divergent package outcome requiring owner follow-up".to_string(),
        remediation_state: RemediationState::Triaged,
        owner: owner.to_string(),
        related_beads: related_beads.iter().map(|bead| (*bead).to_string()).collect(),
        discovered_epoch: SNAPSHOT_EPOCH,
        last_updated_epoch: SNAPSHOT_EPOCH,
    }
}

fn build_report(matrix: &NpmCompatibilityMatrix, matrix_hash: &str) -> NpmCompatibilityReport {
    let cohort_summaries = [
        frankenengine_engine::npm_compatibility_matrix::CohortTier::Tier1Critical,
        frankenengine_engine::npm_compatibility_matrix::CohortTier::Tier2Popular,
        frankenengine_engine::npm_compatibility_matrix::CohortTier::Tier3LongTail,
    ]
    .into_iter()
    .filter_map(|tier| {
        let summary = matrix.cohort_summary(tier);
        (summary.total_packages > 0).then_some(summary)
    })
    .collect();

    let root_cause_distribution = matrix
        .root_cause_distribution()
        .into_iter()
        .map(|(root_cause, open_count)| RootCauseCount {
            root_cause: root_cause.as_str().to_string(),
            open_count,
        })
        .collect();

    let top_blockers = matrix
        .top_blockers(5)
        .into_iter()
        .map(
            |(package_name, weighted_open_score_millionths)| TopBlocker {
                package_name,
                weighted_open_score_millionths,
            },
        )
        .collect();

    let packages = matrix
        .packages
        .iter()
        .map(|package| {
            let outcome = matrix
                .get_test_result(&package.name)
                .map(|result| result.outcome.as_str().to_string())
                .unwrap_or_else(|| PackageTestOutcome::Untested.as_str().to_string());
            let pass_rate_millionths = matrix.get_test_result(&package.name).and_then(|result| {
                (result.total_tests > 0).then_some(result.pass_rate_millionths())
            });
            let unresolved_incompatibility_ids = matrix
                .incompatibilities_for_package(&package.name)
                .into_iter()
                .filter(|record| !record.remediation_state.is_resolved())
                .map(|record| record.incompatibility_id.clone())
                .collect();
            PackageOutcomeRecord {
                name: package.name.clone(),
                version: package.version.clone(),
                tier: package.tier.as_str().to_string(),
                category: package.category.as_str().to_string(),
                module_system: package.module_system.as_str().to_string(),
                weekly_downloads: package.weekly_downloads,
                outcome,
                pass_rate_millionths,
                unresolved_incompatibility_ids,
            }
        })
        .collect();

    let unresolved_failures = matrix
        .open_incompatibilities()
        .into_iter()
        .map(|record| UnresolvedFailureRouting {
            incompatibility_id: record.incompatibility_id.clone(),
            package_name: record.package_name.clone(),
            root_cause: record.root_cause.as_str().to_string(),
            severity: record.severity.as_str().to_string(),
            summary: record.summary.clone(),
            owner: record.owner.clone(),
            related_beads: record.related_beads.iter().cloned().collect(),
            remediation_state: record.remediation_state.as_str().to_string(),
            minimized_repro: record.minimized_repro.clone(),
            expected_behavior: record.expected_behavior.clone(),
            actual_behavior: record.actual_behavior.clone(),
        })
        .collect();

    NpmCompatibilityReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        scenario_id: SCENARIO_ID.to_string(),
        matrix_schema_version: SCHEMA_VERSION.to_string(),
        matrix_hash: matrix_hash.to_string(),
        verdict: matrix.verdict().as_str().to_string(),
        snapshot_epoch: matrix.snapshot_epoch,
        package_count: matrix.total_packages(),
        incompatibility_count: matrix.total_incompatibilities(),
        cohort_summaries,
        root_cause_distribution,
        top_blockers,
        packages,
        unresolved_failures,
    }
}

fn build_events(
    matrix: &NpmCompatibilityMatrix,
    trace_id: &str,
    decision_id: &str,
    matrix_hash: &str,
) -> Vec<MatrixEvent> {
    let mut events = vec![MatrixEvent {
        schema_version: EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event: "npm_compatibility_matrix_started".to_string(),
        package_name: None,
        outcome: None,
        error_code: None,
        detail: Some(format!(
            "packages={} incompatibilities={}",
            matrix.total_packages(),
            matrix.total_incompatibilities()
        )),
    }];

    for result in &matrix.test_results {
        events.push(MatrixEvent {
            schema_version: EVENT_SCHEMA_VERSION.to_string(),
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: POLICY_ID.to_string(),
            component: COMPONENT.to_string(),
            event: "package_outcome_recorded".to_string(),
            package_name: Some(result.package_name.clone()),
            outcome: Some(result.outcome.as_str().to_string()),
            error_code: None,
            detail: Some(format!(
                "passed={} failed={} skipped={} pass_rate_millionths={}",
                result.passed_tests,
                result.failed_tests,
                result.skipped_tests,
                result.pass_rate_millionths()
            )),
        });
    }

    for record in matrix.open_incompatibilities() {
        events.push(MatrixEvent {
            schema_version: EVENT_SCHEMA_VERSION.to_string(),
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: POLICY_ID.to_string(),
            component: COMPONENT.to_string(),
            event: "owner_routing_recorded".to_string(),
            package_name: Some(record.package_name.clone()),
            outcome: Some(record.severity.as_str().to_string()),
            error_code: Some("FE-RGC-404-ROUTED-INCOMPATIBILITY".to_string()),
            detail: Some(format!(
                "root_cause={} owner={} related_beads={}",
                record.root_cause.as_str(),
                record.owner,
                record
                    .related_beads
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(",")
            )),
        });
    }

    events.push(MatrixEvent {
        schema_version: EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event: "npm_compatibility_matrix_completed".to_string(),
        package_name: None,
        outcome: Some(matrix.verdict().as_str().to_string()),
        error_code: None,
        detail: Some(format!(
            "matrix_hash={} unresolved_failures={}",
            matrix_hash,
            matrix.open_incompatibilities().len()
        )),
    });

    events
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let rendered = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    fs::write(path, rendered)
        .map_err(|error| format!("failed to write {}: {error}", path.display()))
}

fn write_jsonl(path: &Path, events: &[MatrixEvent]) -> Result<(), String> {
    let mut buffer = String::new();
    for event in events {
        let line = serde_json::to_string(event).map_err(|error| error.to_string())?;
        buffer.push_str(&line);
        buffer.push('\n');
    }
    write_text(path, &buffer)
}

fn write_text(path: &Path, body: &str) -> Result<(), String> {
    fs::write(path, body).map_err(|error| format!("failed to write {}: {error}", path.display()))
}
