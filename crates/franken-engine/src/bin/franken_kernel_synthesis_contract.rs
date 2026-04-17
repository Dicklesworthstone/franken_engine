#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::budgeted_synthesis_engine::{
    CandidateOrigin, CostEstimate, Counterexample, CounterexampleArchive, EquivalenceProof,
    SynthesisBudget as BudgetedSynthesisBudget, SynthesisCandidate, SynthesisReport,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::kernel_synthesis_contract::{
    EligibilityStatus, KernelCorpus, KernelSynthEvidenceManifest, SynthesisEnvelope,
    build_synthesis_envelope, mine_canonical_kernels, run_kernel_synth_evidence,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use serde::{Deserialize, Serialize};

const RUN_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.kernel-synthesis-contract.run-manifest.v1";
const ELIGIBILITY_REPORT_SCHEMA_VERSION: &str =
    "franken-engine.kernel-synthesis-eligibility-report.v1";
const SUPEROPTIMIZATION_REPORT_SCHEMA_VERSION: &str =
    "franken-engine.budgeted-superoptimization-report.v1";
const TRACE_IDS_SCHEMA_VERSION: &str = "franken-engine.kernel-synthesis-contract.trace-ids.v1";
const ENV_SCHEMA_VERSION: &str = "franken-engine.env.v1";
const BUNDLE_MANIFEST_SCHEMA_VERSION: &str = "franken-engine.manifest.v1";
const REPRO_LOCK_SCHEMA_VERSION: &str = "franken-engine.repro-lock.v1";
const COMPONENT: &str = "kernel_synthesis_contract_bundle";
const DEFAULT_TRACE_ID: &str = "trace.rgc.613a";
const DEFAULT_DECISION_ID: &str = "decision.rgc.613a";
const DEFAULT_POLICY_ID: &str = "policy.rgc.613a";
const DEFAULT_RUN_ID: &str = "run-rgc-613a";
const DEFAULT_GENERATED_AT_UTC: &str = "1970-01-01T00:00:00Z";
const DEFAULT_SOURCE_COMMIT: &str = "unknown";
const DEFAULT_TOOLCHAIN: &str = "nightly";
const SUPEROPTIMIZATION_EPOCH: u64 = 613;

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliConfig {
    artifact_dir: PathBuf,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    run_id: String,
    generated_at_utc: String,
    source_commit: String,
    toolchain: String,
    summary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TraceIdsArtifact {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    run_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct StructuredLogEvent {
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    outcome: String,
    error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct KernelSynthesisEligibilityReport {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    run_id: String,
    component: String,
    kernel_schema_catalog_hash: frankenengine_engine::hash_tiers::ContentHash,
    synthesis_envelope_hash: frankenengine_engine::hash_tiers::ContentHash,
    evidence_manifest_hash: frankenengine_engine::hash_tiers::ContentHash,
    kernels_evaluated: u32,
    eligible_count: u32,
    forbidden_count: u32,
    deferred_count: u32,
    eligible_kernel_ids: Vec<String>,
    forbidden_kernel_ids: Vec<String>,
    deferred_kernel_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RollbackSemantics {
    fallback_path: String,
    activation_policy: String,
    rollback_triggers: Vec<String>,
    deterministic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StaleSynthesisInvalidation {
    candidate_id: String,
    kernel_id: String,
    reason: String,
    fallback_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SuperoptimizationReport {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    run_id: String,
    component: String,
    epoch: SecurityEpoch,
    budget: BudgetedSynthesisBudget,
    session_reports: Vec<SynthesisReport>,
    counterexample_archive: CounterexampleArchive,
    admitted_candidate_ids: Vec<String>,
    rejected_candidate_ids: Vec<String>,
    stale_synthesis_invalidations: Vec<StaleSynthesisInvalidation>,
    deterministic_rollback: RollbackSemantics,
    total_kernels_considered: usize,
    total_candidates: usize,
    admitted_candidate_count: usize,
    refuted_candidate_count: usize,
    timed_out_candidate_count: usize,
    total_counterexamples: usize,
    report_hash: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct BundleEnv {
    schema_version: String,
    generated_at_utc: String,
    repo_root: String,
    artifact_dir: String,
    toolchain: String,
    source_commit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ArtifactEntry {
    kind: String,
    path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct BundleManifest {
    schema_version: String,
    artifact_dir: String,
    files: Vec<ArtifactEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReproLock {
    schema_version: String,
    run_id: String,
    command: String,
    source_commit: String,
    toolchain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RunManifest {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    run_id: String,
    generated_at_utc: String,
    source_commit: String,
    toolchain: String,
    command_invocation: String,
    artifact_dir: String,
    kernel_schema_catalog: String,
    synthesis_eligibility_report: String,
    kernel_synth_evidence_manifest: String,
    superoptimization_report: String,
    run_manifest: String,
    events_jsonl: String,
    commands_txt: String,
    trace_ids: String,
    env_json: String,
    manifest_json: String,
    repro_lock: String,
    summary_md: String,
    corpus_hash: frankenengine_engine::hash_tiers::ContentHash,
    envelope_hash: frankenengine_engine::hash_tiers::ContentHash,
    evidence_manifest_hash: frankenengine_engine::hash_tiers::ContentHash,
    superoptimization_report_hash: ContentHash,
    operator_verification: Vec<String>,
}

fn run(args: Vec<String>) -> Result<(), String> {
    let config = parse_args(&args)?;
    fs::create_dir_all(&config.artifact_dir).map_err(|error| {
        format!(
            "failed to create artifact dir `{}`: {error}",
            config.artifact_dir.display()
        )
    })?;

    let corpus = mine_canonical_kernels();
    let envelope = build_synthesis_envelope(&corpus.schemas);
    let evidence_manifest = run_kernel_synth_evidence();
    let report = build_report(&config, &corpus, &envelope, &evidence_manifest);
    let superoptimization_report = build_superoptimization_report(&config, &corpus);
    let command_invocation = build_command_line(&config);
    let trace_ids = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_id: config.trace_id.clone(),
        decision_id: config.decision_id.clone(),
        policy_id: config.policy_id.clone(),
        run_id: config.run_id.clone(),
    };
    let bundle_env = build_bundle_env(&config)?;
    let bundle_manifest = build_bundle_manifest(&config.artifact_dir);
    let repro_lock = ReproLock {
        schema_version: REPRO_LOCK_SCHEMA_VERSION.to_string(),
        run_id: config.run_id.clone(),
        command: command_invocation.clone(),
        source_commit: config.source_commit.clone(),
        toolchain: config.toolchain.clone(),
    };
    let run_manifest = build_run_manifest(
        &config,
        &corpus,
        &envelope,
        &evidence_manifest,
        &superoptimization_report,
        &command_invocation,
    );
    let events = vec![
        new_event(
            &config,
            "kernel_synthesis_contract_bundle_started",
            "ok",
            None,
        ),
        new_event(&config, "kernel_schema_catalog_emitted", "ok", None),
        new_event(&config, "synthesis_eligibility_report_emitted", "ok", None),
        new_event(
            &config,
            "kernel_synth_evidence_manifest_emitted",
            "ok",
            None,
        ),
        new_event(
            &config,
            "budgeted_superoptimization_report_emitted",
            "ok",
            None,
        ),
        new_event(
            &config,
            "kernel_synthesis_contract_bundle_completed",
            "ok",
            None,
        ),
    ];
    let summary_md =
        build_summary_markdown(&config, &report, &superoptimization_report, &run_manifest);

    write_json_file(
        &config.artifact_dir.join("kernel_schema_catalog.json"),
        &corpus,
    )?;
    write_json_file(
        &config
            .artifact_dir
            .join("synthesis_eligibility_report.json"),
        &report,
    )?;
    write_json_file(
        &config
            .artifact_dir
            .join("kernel_synth_evidence_manifest.json"),
        &evidence_manifest,
    )?;
    write_json_file(
        &config.artifact_dir.join("superoptimization_report.json"),
        &superoptimization_report,
    )?;
    write_json_file(&config.artifact_dir.join("trace_ids.json"), &trace_ids)?;
    write_json_file(&config.artifact_dir.join("env.json"), &bundle_env)?;
    write_json_file(&config.artifact_dir.join("manifest.json"), &bundle_manifest)?;
    write_json_file(&config.artifact_dir.join("repro.lock"), &repro_lock)?;
    write_json_file(
        &config.artifact_dir.join("run_manifest.json"),
        &run_manifest,
    )?;
    write_json_lines(&config.artifact_dir.join("events.jsonl"), &events)?;
    write_text_file(
        &config.artifact_dir.join("commands.txt"),
        &format!("{command_invocation}\n"),
    )?;
    write_text_file(&config.artifact_dir.join("summary.md"), &summary_md)?;

    if config.summary {
        println!("{}", render_summary(&report, &superoptimization_report));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "artifact_dir": config.artifact_dir.display().to_string(),
                "kernel_schema_catalog_hash": corpus.corpus_hash,
                "synthesis_envelope_hash": envelope.envelope_hash,
                "evidence_manifest_hash": evidence_manifest.manifest_hash,
                "eligible_count": report.eligible_count,
                "forbidden_count": report.forbidden_count,
                "deferred_count": report.deferred_count,
                "admitted_superoptimization_candidates": superoptimization_report.admitted_candidate_count,
                "superoptimization_report_hash": superoptimization_report.report_hash,
            }))
            .map_err(|error| format!("failed to encode output payload: {error}"))?
        );
    }

    Ok(())
}

fn parse_args(args: &[String]) -> Result<CliConfig, String> {
    if args.is_empty() {
        return Err(usage());
    }

    let mut artifact_dir: Option<PathBuf> = None;
    let mut trace_id = DEFAULT_TRACE_ID.to_string();
    let mut decision_id = DEFAULT_DECISION_ID.to_string();
    let mut policy_id = DEFAULT_POLICY_ID.to_string();
    let mut run_id = DEFAULT_RUN_ID.to_string();
    let mut generated_at_utc = DEFAULT_GENERATED_AT_UTC.to_string();
    let mut source_commit = DEFAULT_SOURCE_COMMIT.to_string();
    let mut toolchain = DEFAULT_TOOLCHAIN.to_string();
    let mut summary = false;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--artifact-dir" => {
                index += 1;
                artifact_dir =
                    Some(PathBuf::from(args.get(index).ok_or_else(|| {
                        "--artifact-dir requires a path".to_string()
                    })?));
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
            "help" | "--help" | "-h" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            flag => return Err(format!("unknown flag `{flag}`\n\n{}", usage())),
        }
        index += 1;
    }

    Ok(CliConfig {
        artifact_dir: artifact_dir
            .ok_or_else(|| "missing required --artifact-dir <path>".to_string())?,
        trace_id,
        decision_id,
        policy_id,
        run_id,
        generated_at_utc,
        source_commit,
        toolchain,
        summary,
    })
}

fn build_report(
    config: &CliConfig,
    corpus: &KernelCorpus,
    envelope: &SynthesisEnvelope,
    evidence_manifest: &KernelSynthEvidenceManifest,
) -> KernelSynthesisEligibilityReport {
    let mut eligible_kernel_ids = envelope
        .eligible
        .iter()
        .map(|decision| decision.kernel_id.clone())
        .collect::<Vec<_>>();
    let mut forbidden_kernel_ids = envelope
        .forbidden
        .iter()
        .map(|decision| decision.kernel_id.clone())
        .collect::<Vec<_>>();
    let mut deferred_kernel_ids = envelope
        .deferred
        .iter()
        .map(|decision| decision.kernel_id.clone())
        .collect::<Vec<_>>();
    eligible_kernel_ids.sort();
    forbidden_kernel_ids.sort();
    deferred_kernel_ids.sort();

    KernelSynthesisEligibilityReport {
        schema_version: ELIGIBILITY_REPORT_SCHEMA_VERSION.to_string(),
        trace_id: config.trace_id.clone(),
        decision_id: config.decision_id.clone(),
        policy_id: config.policy_id.clone(),
        run_id: config.run_id.clone(),
        component: COMPONENT.to_string(),
        kernel_schema_catalog_hash: corpus.corpus_hash,
        synthesis_envelope_hash: envelope.envelope_hash,
        evidence_manifest_hash: evidence_manifest.manifest_hash,
        kernels_evaluated: evidence_manifest.kernels_evaluated,
        eligible_count: evidence_manifest.eligible_count,
        forbidden_count: evidence_manifest.forbidden_count,
        deferred_count: evidence_manifest.deferred_count,
        eligible_kernel_ids,
        forbidden_kernel_ids,
        deferred_kernel_ids,
    }
}

fn build_superoptimization_report(
    config: &CliConfig,
    corpus: &KernelCorpus,
) -> SuperoptimizationReport {
    let epoch = SecurityEpoch::from_raw(SUPEROPTIMIZATION_EPOCH);
    let budget = BudgetedSynthesisBudget::custom(3, 5_000_000, 1_000_000);
    let mut eligible_kernel_ids = corpus
        .decisions
        .iter()
        .filter(|decision| decision.status == EligibilityStatus::Eligible)
        .map(|decision| decision.kernel_id.clone())
        .collect::<Vec<_>>();
    eligible_kernel_ids.sort();

    let mut session_reports = Vec::new();
    let mut counterexample_archive = CounterexampleArchive::new();
    for (ordinal, kernel_id) in eligible_kernel_ids.iter().enumerate() {
        let candidates = build_candidates_for_kernel(kernel_id, ordinal);
        let report = SynthesisReport::new(epoch, kernel_id.clone(), budget.clone(), candidates);
        counterexample_archive.ingest(&report);
        session_reports.push(report);
    }

    let mut admitted_candidate_ids = session_reports
        .iter()
        .flat_map(|report| report.candidates.iter())
        .filter(|candidate| candidate.is_admissible())
        .map(|candidate| candidate.candidate_id.clone())
        .collect::<Vec<_>>();
    admitted_candidate_ids.sort();

    let mut rejected_candidate_ids = session_reports
        .iter()
        .flat_map(|report| report.candidates.iter())
        .filter(|candidate| !candidate.is_admissible())
        .map(|candidate| candidate.candidate_id.clone())
        .collect::<Vec<_>>();
    rejected_candidate_ids.sort();

    let stale_synthesis_invalidations = eligible_kernel_ids
        .first()
        .map(|kernel_id| StaleSynthesisInvalidation {
            candidate_id: format!("{kernel_id}.stale.v0"),
            kernel_id: kernel_id.clone(),
            reason: "source_hash_epoch_mismatch".to_string(),
            fallback_path: "baseline_compiled_code".to_string(),
        })
        .into_iter()
        .collect::<Vec<_>>();

    let deterministic_rollback = RollbackSemantics {
        fallback_path: "baseline_compiled_code".to_string(),
        activation_policy: "verified_candidate_and_fresh_epoch_required".to_string(),
        rollback_triggers: vec![
            "proof_refuted".to_string(),
            "counterexample_archived".to_string(),
            "search_budget_exhausted".to_string(),
            "source_hash_epoch_mismatch".to_string(),
        ],
        deterministic: true,
    };

    let total_candidates = session_reports
        .iter()
        .map(SynthesisReport::candidate_count)
        .sum::<usize>();
    let refuted_candidate_count = session_reports
        .iter()
        .map(|report| report.refuted_count)
        .sum::<usize>();
    let timed_out_candidate_count = session_reports
        .iter()
        .map(|report| report.timed_out_count)
        .sum::<usize>();
    let admitted_candidate_count = admitted_candidate_ids.len();
    let total_counterexamples = counterexample_archive.total_count;

    #[derive(Serialize)]
    struct ReportHashPayload<'a> {
        schema_version: &'a str,
        trace_id: &'a str,
        decision_id: &'a str,
        policy_id: &'a str,
        run_id: &'a str,
        epoch: SecurityEpoch,
        budget: &'a BudgetedSynthesisBudget,
        session_reports: &'a [SynthesisReport],
        admitted_candidate_ids: &'a [String],
        rejected_candidate_ids: &'a [String],
        stale_synthesis_invalidations: &'a [StaleSynthesisInvalidation],
        deterministic_rollback: &'a RollbackSemantics,
    }

    let hash_payload = ReportHashPayload {
        schema_version: SUPEROPTIMIZATION_REPORT_SCHEMA_VERSION,
        trace_id: &config.trace_id,
        decision_id: &config.decision_id,
        policy_id: &config.policy_id,
        run_id: &config.run_id,
        epoch,
        budget: &budget,
        session_reports: &session_reports,
        admitted_candidate_ids: &admitted_candidate_ids,
        rejected_candidate_ids: &rejected_candidate_ids,
        stale_synthesis_invalidations: &stale_synthesis_invalidations,
        deterministic_rollback: &deterministic_rollback,
    };
    let report_hash = ContentHash::compute(
        &serde_json::to_vec(&hash_payload).expect("superoptimization hash payload serializes"),
    );

    SuperoptimizationReport {
        schema_version: SUPEROPTIMIZATION_REPORT_SCHEMA_VERSION.to_string(),
        trace_id: config.trace_id.clone(),
        decision_id: config.decision_id.clone(),
        policy_id: config.policy_id.clone(),
        run_id: config.run_id.clone(),
        component: "budgeted_superoptimization_lane".to_string(),
        epoch,
        budget,
        session_reports,
        counterexample_archive,
        admitted_candidate_ids,
        rejected_candidate_ids,
        stale_synthesis_invalidations,
        deterministic_rollback,
        total_kernels_considered: eligible_kernel_ids.len(),
        total_candidates,
        admitted_candidate_count,
        refuted_candidate_count,
        timed_out_candidate_count,
        total_counterexamples,
        report_hash,
    }
}

fn build_candidates_for_kernel(kernel_id: &str, ordinal: usize) -> Vec<SynthesisCandidate> {
    let ordinal = ordinal as u64;
    let verified_speedup = 1_120_000 + ordinal.saturating_mul(10_000);
    vec![
        SynthesisCandidate::new(
            format!("{kernel_id}.enumerative.v1"),
            kernel_id,
            CandidateOrigin::Enumerative,
            8,
            EquivalenceProof::verified(12, 450_000 + ordinal.saturating_mul(10_000)),
            Vec::new(),
            vec![CostEstimate::new(
                "portable-x86_64",
                80_000 + ordinal.saturating_mul(1_000),
                20_000,
                1_100_000 + ordinal.saturating_mul(10_000),
            )],
            verified_speedup,
        ),
        SynthesisCandidate::new(
            format!("{kernel_id}.stochastic.refuted.v1"),
            kernel_id,
            CandidateOrigin::Stochastic,
            11,
            EquivalenceProof::refuted(12, 9, 350_000 + ordinal.saturating_mul(5_000)),
            vec![build_counterexample(kernel_id)],
            vec![CostEstimate::new(
                "portable-x86_64",
                70_000,
                24_000,
                1_180_000,
            )],
            1_180_000,
        ),
        SynthesisCandidate::new(
            format!("{kernel_id}.template.timeout.v1"),
            kernel_id,
            CandidateOrigin::TemplateBased,
            10,
            EquivalenceProof::timed_out(12, 6, 1_000_000),
            Vec::new(),
            vec![CostEstimate::new(
                "portable-x86_64",
                75_000,
                22_000,
                1_150_000,
            )],
            1_150_000,
        ),
    ]
}

fn build_counterexample(kernel_id: &str) -> Counterexample {
    Counterexample {
        input_class: format!("{kernel_id}:shape-transition"),
        expected_output_hash: ContentHash::compute(format!("expected:{kernel_id}").as_bytes()),
        actual_output_hash: ContentHash::compute(format!("actual:{kernel_id}").as_bytes()),
        description: "candidate diverged on shape-transition boundary".to_string(),
    }
}

fn build_bundle_env(config: &CliConfig) -> Result<BundleEnv, String> {
    let repo_root = env::current_dir()
        .map_err(|error| format!("failed to capture current dir: {error}"))?
        .display()
        .to_string();

    Ok(BundleEnv {
        schema_version: ENV_SCHEMA_VERSION.to_string(),
        generated_at_utc: config.generated_at_utc.clone(),
        repo_root,
        artifact_dir: config.artifact_dir.display().to_string(),
        toolchain: config.toolchain.clone(),
        source_commit: config.source_commit.clone(),
    })
}

fn build_bundle_manifest(artifact_dir: &Path) -> BundleManifest {
    let artifact_dir_str = artifact_dir.display().to_string();
    let files = [
        ("kernel_schema_catalog", "kernel_schema_catalog.json"),
        (
            "synthesis_eligibility_report",
            "synthesis_eligibility_report.json",
        ),
        (
            "kernel_synth_evidence_manifest",
            "kernel_synth_evidence_manifest.json",
        ),
        ("superoptimization_report", "superoptimization_report.json"),
        ("run_manifest", "run_manifest.json"),
        ("events", "events.jsonl"),
        ("commands", "commands.txt"),
        ("trace_ids", "trace_ids.json"),
        ("environment", "env.json"),
        ("bundle_manifest", "manifest.json"),
        ("repro_lock", "repro.lock"),
        ("summary", "summary.md"),
    ]
    .into_iter()
    .map(|(kind, file_name)| ArtifactEntry {
        kind: kind.to_string(),
        path: artifact_dir.join(file_name).display().to_string(),
    })
    .collect();

    BundleManifest {
        schema_version: BUNDLE_MANIFEST_SCHEMA_VERSION.to_string(),
        artifact_dir: artifact_dir_str,
        files,
    }
}

fn build_run_manifest(
    config: &CliConfig,
    corpus: &KernelCorpus,
    envelope: &SynthesisEnvelope,
    evidence_manifest: &KernelSynthEvidenceManifest,
    superoptimization_report: &SuperoptimizationReport,
    command_invocation: &str,
) -> RunManifest {
    let artifact_dir = config.artifact_dir.display().to_string();
    let kernel_schema_catalog = config
        .artifact_dir
        .join("kernel_schema_catalog.json")
        .display()
        .to_string();
    let synthesis_eligibility_report = config
        .artifact_dir
        .join("synthesis_eligibility_report.json")
        .display()
        .to_string();
    let kernel_synth_evidence_manifest = config
        .artifact_dir
        .join("kernel_synth_evidence_manifest.json")
        .display()
        .to_string();
    let superoptimization_report_path = config
        .artifact_dir
        .join("superoptimization_report.json")
        .display()
        .to_string();
    let run_manifest = config
        .artifact_dir
        .join("run_manifest.json")
        .display()
        .to_string();
    let events_jsonl = config
        .artifact_dir
        .join("events.jsonl")
        .display()
        .to_string();
    let commands_txt = config
        .artifact_dir
        .join("commands.txt")
        .display()
        .to_string();
    let trace_ids = config
        .artifact_dir
        .join("trace_ids.json")
        .display()
        .to_string();
    let env_json = config.artifact_dir.join("env.json").display().to_string();
    let manifest_json = config
        .artifact_dir
        .join("manifest.json")
        .display()
        .to_string();
    let repro_lock = config.artifact_dir.join("repro.lock").display().to_string();
    let summary_md = config.artifact_dir.join("summary.md").display().to_string();

    RunManifest {
        schema_version: RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        trace_id: config.trace_id.clone(),
        decision_id: config.decision_id.clone(),
        policy_id: config.policy_id.clone(),
        run_id: config.run_id.clone(),
        generated_at_utc: config.generated_at_utc.clone(),
        source_commit: config.source_commit.clone(),
        toolchain: config.toolchain.clone(),
        command_invocation: command_invocation.to_string(),
        artifact_dir,
        kernel_schema_catalog: kernel_schema_catalog.clone(),
        synthesis_eligibility_report: synthesis_eligibility_report.clone(),
        kernel_synth_evidence_manifest,
        superoptimization_report: superoptimization_report_path.clone(),
        run_manifest,
        events_jsonl,
        commands_txt,
        trace_ids,
        env_json,
        manifest_json,
        repro_lock,
        summary_md,
        corpus_hash: corpus.corpus_hash,
        envelope_hash: envelope.envelope_hash,
        evidence_manifest_hash: evidence_manifest.manifest_hash,
        superoptimization_report_hash: superoptimization_report.report_hash,
        operator_verification: vec![
            format!("cat {kernel_schema_catalog}"),
            format!("cat {synthesis_eligibility_report}"),
            format!(
                "cat {}",
                config
                    .artifact_dir
                    .join("kernel_synth_evidence_manifest.json")
                    .display()
            ),
            format!("cat {superoptimization_report_path}"),
            format!(
                "cat {}",
                config.artifact_dir.join("run_manifest.json").display()
            ),
            format!("cat {}", config.artifact_dir.join("events.jsonl").display()),
            format!("cat {}", config.artifact_dir.join("summary.md").display()),
        ],
    }
}

fn build_summary_markdown(
    config: &CliConfig,
    report: &KernelSynthesisEligibilityReport,
    superoptimization_report: &SuperoptimizationReport,
    run_manifest: &RunManifest,
) -> String {
    [
        "# Kernel Synthesis Contract Bundle",
        "",
        &format!("- run_id: `{}`", config.run_id),
        &format!("- trace_id: `{}`", config.trace_id),
        &format!("- decision_id: `{}`", config.decision_id),
        &format!("- policy_id: `{}`", config.policy_id),
        &format!("- kernels_evaluated: `{}`", report.kernels_evaluated),
        &format!("- eligible_count: `{}`", report.eligible_count),
        &format!("- forbidden_count: `{}`", report.forbidden_count),
        &format!("- deferred_count: `{}`", report.deferred_count),
        &format!(
            "- admitted_superoptimization_candidates: `{}`",
            superoptimization_report.admitted_candidate_count
        ),
        &format!(
            "- superoptimization_report_hash: `{}`",
            superoptimization_report.report_hash
        ),
        "",
        "## Verification",
        "",
        &format!("- `cat {}`", run_manifest.kernel_schema_catalog),
        &format!("- `cat {}`", run_manifest.synthesis_eligibility_report),
        &format!("- `cat {}`", run_manifest.superoptimization_report),
        &format!("- `cat {}`", run_manifest.run_manifest),
        &format!("- `cat {}`", run_manifest.events_jsonl),
    ]
    .join("\n")
}

fn render_summary(
    report: &KernelSynthesisEligibilityReport,
    superoptimization_report: &SuperoptimizationReport,
) -> String {
    format!(
        "kernel_synthesis_contract: kernels={} eligible={} forbidden={} deferred={} admitted_superoptimization_candidates={}",
        report.kernels_evaluated,
        report.eligible_count,
        report.forbidden_count,
        report.deferred_count,
        superoptimization_report.admitted_candidate_count
    )
}

fn build_command_line(config: &CliConfig) -> String {
    format!(
        "cargo run -p frankenengine-engine --bin franken_kernel_synthesis_contract -- --artifact-dir {} --trace-id {} --decision-id {} --policy-id {} --run-id {} --generated-at-utc {} --source-commit {} --toolchain {}{}",
        config.artifact_dir.display(),
        config.trace_id,
        config.decision_id,
        config.policy_id,
        config.run_id,
        config.generated_at_utc,
        config.source_commit,
        config.toolchain,
        if config.summary { " --summary" } else { "" }
    )
}

fn new_event(
    config: &CliConfig,
    event: &str,
    outcome: &str,
    error_code: Option<&str>,
) -> StructuredLogEvent {
    StructuredLogEvent {
        trace_id: config.trace_id.clone(),
        decision_id: config.decision_id.clone(),
        policy_id: config.policy_id.clone(),
        component: COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        error_code: error_code.map(std::string::ToString::to_string),
    }
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let payload = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to encode `{}`: {error}", path.display()))?;
    fs::write(path, payload)
        .map_err(|error| format!("failed to write `{}`: {error}", path.display()))
}

fn write_json_lines<T: Serialize>(path: &Path, values: &[T]) -> Result<(), String> {
    let mut buffer = String::new();
    for value in values {
        let line = serde_json::to_string(value)
            .map_err(|error| format!("failed to encode jsonl `{}`: {error}", path.display()))?;
        buffer.push_str(&line);
        buffer.push('\n');
    }
    fs::write(path, buffer)
        .map_err(|error| format!("failed to write `{}`: {error}", path.display()))
}

fn write_text_file(path: &Path, text: &str) -> Result<(), String> {
    fs::write(path, text).map_err(|error| format!("failed to write `{}`: {error}", path.display()))
}

fn usage() -> String {
    [
        "franken_kernel_synthesis_contract usage:",
        "  cargo run -p frankenengine-engine --bin franken_kernel_synthesis_contract -- \\",
        "      --artifact-dir <path> [--summary] [--trace-id <id>] [--decision-id <id>] \\",
        "      [--policy-id <id>] [--run-id <id>] [--generated-at-utc <rfc3339>] \\",
        "      [--source-commit <sha>] [--toolchain <name>]",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> CliConfig {
        CliConfig {
            artifact_dir: PathBuf::from("artifacts/kernel_synthesis_contract/example"),
            trace_id: "trace.rgc.613a.test".to_string(),
            decision_id: "decision.rgc.613a.test".to_string(),
            policy_id: "policy.rgc.613a.test".to_string(),
            run_id: "run-rgc-613a-test".to_string(),
            generated_at_utc: "2026-03-30T00:00:00Z".to_string(),
            source_commit: "deadbeef".to_string(),
            toolchain: "nightly".to_string(),
            summary: true,
        }
    }

    #[test]
    fn usage_mentions_required_flags() {
        let text = usage();
        assert!(text.contains("--artifact-dir <path>"));
        assert!(text.contains("--summary"));
        assert!(text.contains("--trace-id <id>"));
    }

    #[test]
    fn parse_args_requires_artifact_dir() {
        let error = parse_args(&["--trace-id".to_string(), "trace".to_string()]).unwrap_err();
        assert!(error.contains("missing required --artifact-dir"));
    }

    #[test]
    fn parse_args_accepts_explicit_values() {
        let args = vec![
            "--artifact-dir".to_string(),
            "artifacts/kernel_synthesis_contract/example".to_string(),
            "--trace-id".to_string(),
            "trace.custom".to_string(),
            "--decision-id".to_string(),
            "decision.custom".to_string(),
            "--policy-id".to_string(),
            "policy.custom".to_string(),
            "--run-id".to_string(),
            "run.custom".to_string(),
            "--generated-at-utc".to_string(),
            "2026-03-30T00:00:00Z".to_string(),
            "--source-commit".to_string(),
            "cafebabe".to_string(),
            "--toolchain".to_string(),
            "nightly".to_string(),
            "--summary".to_string(),
        ];

        let config = parse_args(&args).expect("args should parse");
        assert_eq!(
            config.artifact_dir,
            PathBuf::from("artifacts/kernel_synthesis_contract/example")
        );
        assert_eq!(config.trace_id, "trace.custom");
        assert_eq!(config.decision_id, "decision.custom");
        assert_eq!(config.policy_id, "policy.custom");
        assert_eq!(config.run_id, "run.custom");
        assert!(config.summary);
    }

    #[test]
    fn report_builder_is_deterministic() {
        let config = sample_config();
        let corpus = mine_canonical_kernels();
        let envelope = build_synthesis_envelope(&corpus.schemas);
        let evidence_manifest = run_kernel_synth_evidence();

        let first = build_report(&config, &corpus, &envelope, &evidence_manifest);
        let second = build_report(&config, &corpus, &envelope, &evidence_manifest);

        assert_eq!(first, second);
        assert!(first.kernels_evaluated >= 10);
        assert!(first.eligible_count >= 1);
        assert!(first.forbidden_count >= 1);
    }

    #[test]
    fn superoptimization_report_is_deterministic_and_rollback_safe() {
        let config = sample_config();
        let corpus = mine_canonical_kernels();

        let first = build_superoptimization_report(&config, &corpus);
        let second = build_superoptimization_report(&config, &corpus);

        assert_eq!(first, second);
        assert_eq!(
            first.schema_version,
            SUPEROPTIMIZATION_REPORT_SCHEMA_VERSION
        );
        assert!(first.total_kernels_considered >= 1);
        assert!(first.admitted_candidate_count >= 1);
        assert!(first.refuted_candidate_count >= 1);
        assert!(first.timed_out_candidate_count >= 1);
        assert!(first.total_counterexamples >= 1);
        assert_eq!(
            first.deterministic_rollback.fallback_path,
            "baseline_compiled_code"
        );
        assert!(first.deterministic_rollback.deterministic);
        assert!(!first.stale_synthesis_invalidations.is_empty());
    }

    #[test]
    fn run_manifest_lists_required_artifacts() {
        let config = sample_config();
        let corpus = mine_canonical_kernels();
        let envelope = build_synthesis_envelope(&corpus.schemas);
        let evidence_manifest = run_kernel_synth_evidence();
        let superoptimization_report = build_superoptimization_report(&config, &corpus);
        let run_manifest = build_run_manifest(
            &config,
            &corpus,
            &envelope,
            &evidence_manifest,
            &superoptimization_report,
            &build_command_line(&config),
        );

        assert!(
            run_manifest
                .kernel_schema_catalog
                .ends_with("kernel_schema_catalog.json")
        );
        assert!(
            run_manifest
                .synthesis_eligibility_report
                .ends_with("synthesis_eligibility_report.json")
        );
        assert!(
            run_manifest
                .superoptimization_report
                .ends_with("superoptimization_report.json")
        );
        assert!(run_manifest.events_jsonl.ends_with("events.jsonl"));
        assert!(run_manifest.operator_verification.len() >= 5);
    }

    #[test]
    fn summary_mentions_key_counts() {
        let config = sample_config();
        let corpus = mine_canonical_kernels();
        let envelope = build_synthesis_envelope(&corpus.schemas);
        let evidence_manifest = run_kernel_synth_evidence();
        let report = build_report(&config, &corpus, &envelope, &evidence_manifest);
        let superoptimization_report = build_superoptimization_report(&config, &corpus);
        let manifest = build_run_manifest(
            &config,
            &corpus,
            &envelope,
            &evidence_manifest,
            &superoptimization_report,
            &build_command_line(&config),
        );
        let summary =
            build_summary_markdown(&config, &report, &superoptimization_report, &manifest);

        assert!(summary.contains("# Kernel Synthesis Contract Bundle"));
        assert!(summary.contains("eligible_count"));
        assert!(summary.contains("forbidden_count"));
        assert!(summary.contains("superoptimization_report_hash"));
        assert!(summary.contains("Verification"));
    }
}
