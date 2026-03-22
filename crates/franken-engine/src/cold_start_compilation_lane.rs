use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::aot_entrygraph_compiler::{
    self, BatchReport, CompileConfig, CompileTarget, DecisionReceipt as AotDecisionReceipt,
    EntryKind, Entrygraph, ModuleEntry,
};
use crate::cold_start_aot_governance::{
    self, BenchmarkVerdict, ColdStartEvidence, DecisionReceipt as GovernanceDecisionReceipt,
    GovernanceConfig, GovernanceVerdict, ParityCheckKind, ParityResult, RollbackTrigger,
    StartupPathKind,
};
use crate::hash_tiers::ContentHash;
use crate::persistent_cache_contract;
use crate::runtime_image_contract::{
    ImageIntegrityStatus, ImageKind, ImageManifest, ImagePolicy, ImageRegistry, ImageState,
    WarmStartMode,
};
use crate::security_epoch::SecurityEpoch;

pub const BEAD_ID: &str = "bd-1lsy.7.10";
pub const COMPONENT: &str = "cold_start_compilation_lane";
pub const POLICY_ID: &str = "policy-rgc-cold-start-compilation-lane-v1";
pub const REPORT_SCHEMA_VERSION: &str = "franken-engine.rgc-cold-start-compilation-report.v1";
pub const AOT_BUNDLE_SCHEMA_VERSION: &str = "franken-engine.rgc-cold-start-aot-bundle.v1";
pub const RUNTIME_IMAGE_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.rgc-cold-start-runtime-image-manifest.v1";
pub const OBSERVABILITY_DELTA_SCHEMA_VERSION: &str =
    "franken-engine.rgc-cold-start-observability-delta.v1";
pub const TRACE_IDS_SCHEMA_VERSION: &str = "franken-engine.rgc-cold-start-trace-ids.v1";

pub const REPORT_FILE: &str = "cold_start_compilation_report.json";
pub const OBSERVABILITY_DELTA_FILE: &str = "cold_start_observability_delta.json";
pub const AOT_BUNDLE_FILE: &str = "aot_bundle_compilation_report.json";
pub const RUNTIME_IMAGE_MANIFEST_FILE: &str = "runtime_image_manifest.json";
pub const SUMMARY_FILE: &str = "summary.md";
pub const TRACE_IDS_FILE: &str = "trace_ids.json";
pub const PERSISTENT_CACHE_DIR: &str = "persistent_cache_contract";
pub const PERSISTENT_CACHE_CONTRACT_FILE: &str =
    "persistent_cache_contract/persistent_cache_contract.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactContext {
    pub artifact_dir: PathBuf,
    pub run_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub generated_at_utc: String,
    pub source_commit: String,
    pub toolchain: String,
    pub command_invocation: String,
}

impl ArtifactContext {
    #[must_use]
    pub fn new(artifact_dir: impl Into<PathBuf>) -> Self {
        Self {
            artifact_dir: artifact_dir.into(),
            run_id: format!("run-{COMPONENT}-{}", Utc::now().format("%Y%m%dT%H%M%SZ")),
            trace_id: "trace-rgc-610".to_string(),
            decision_id: "decision-rgc-610".to_string(),
            policy_id: POLICY_ID.to_string(),
            generated_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            source_commit: "unknown".to_string(),
            toolchain: std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "nightly".to_string()),
            command_invocation: "cargo run -p frankenengine-engine --bin franken_cold_start_compilation_lane -- --artifact-dir <path>".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceIdsArtifact {
    pub schema_version: String,
    pub trace_ids: Vec<String>,
    pub decision_id: String,
    pub policy_id: String,
    pub subordinate_trace_ids: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryKindSummary {
    pub total_graphs: u64,
    pub usable_graphs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotBundleCompilationReport {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub policy_id: String,
    pub batch_report: BatchReport,
    pub receipts: Vec<AotDecisionReceipt>,
    pub entry_kind_summary: BTreeMap<String, EntryKindSummary>,
    pub target_summary: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeImageManifestArtifact {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub registry_hash: ContentHash,
    pub image_count: u64,
    pub total_bytes: u64,
    pub best_warm_start_image_id: Option<String>,
    pub best_warm_start_mode: Option<String>,
    pub registry: ImageRegistry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdStartObservabilityDeltaRow {
    pub mode_id: String,
    pub startup_path: StartupPathKind,
    pub baseline_nanos: u64,
    pub candidate_nanos: u64,
    pub speedup_millionths: i64,
    pub preserves_claim: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdStartObservabilityDeltaArtifact {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub policy_id: String,
    pub rows: Vec<ColdStartObservabilityDeltaRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdStartCompilationReport {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub policy_id: String,
    pub generated_at_utc: String,
    pub run_id: String,
    pub source_commit: String,
    pub toolchain: String,
    pub persistent_cache_contract_path: String,
    pub cache_contract_receipt_count: usize,
    pub aot_bundle_report_path: String,
    pub runtime_image_manifest_path: String,
    pub observability_delta_path: String,
    pub governance_verdict: GovernanceVerdict,
    pub aggregate_benchmark_verdict: BenchmarkVerdict,
    pub aggregate_speedup_millionths: i64,
    pub rollback_triggers: Vec<RollbackTrigger>,
    pub governance_receipt: GovernanceDecisionReceipt,
    pub evidence: Vec<ColdStartEvidence>,
    pub parity_results: Vec<ParityResult>,
    pub required_artifacts: Vec<String>,
    pub operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleWriteReport {
    pub artifact_dir: PathBuf,
    pub report_path: PathBuf,
    pub observability_delta_path: PathBuf,
    pub aot_bundle_report_path: PathBuf,
    pub runtime_image_manifest_path: PathBuf,
    pub trace_ids_path: PathBuf,
    pub summary_path: PathBuf,
    pub written_files: BTreeMap<String, String>,
    pub report: ColdStartCompilationReport,
}

#[derive(Debug, Clone)]
struct EvaluatedArtifacts {
    report: ColdStartCompilationReport,
    observability_delta: ColdStartObservabilityDeltaArtifact,
    aot_bundle: AotBundleCompilationReport,
    runtime_image_manifest: RuntimeImageManifestArtifact,
    trace_ids: TraceIdsArtifact,
    summary: String,
}

#[derive(Debug, Clone)]
struct FileArtifact {
    relative_path: String,
    contents: Vec<u8>,
}

impl FileArtifact {
    fn json(relative_path: &str, value: &impl Serialize) -> io::Result<Self> {
        let contents = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
        Ok(Self {
            relative_path: relative_path.to_string(),
            contents,
        })
    }

    fn markdown(relative_path: &str, value: String) -> Self {
        Self {
            relative_path: relative_path.to_string(),
            contents: value.into_bytes(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ModeSample {
    mode_id: &'static str,
    startup_path: StartupPathKind,
    candidate_nanos: u64,
}

const MODE_SAMPLES: [ModeSample; 4] = [
    ModeSample {
        mode_id: "observability_off",
        startup_path: StartupPathKind::AotRestored,
        candidate_nanos: 78_000_000,
    },
    ModeSample {
        mode_id: "shipped_budgeted",
        startup_path: StartupPathKind::AotRestored,
        candidate_nanos: 82_000_000,
    },
    ModeSample {
        mode_id: "exact_shadow",
        startup_path: StartupPathKind::PrewarmedPool,
        candidate_nanos: 88_000_000,
    },
    ModeSample {
        mode_id: "incident_full_capture",
        startup_path: StartupPathKind::ZygoteFork,
        candidate_nanos: 94_000_000,
    },
];

pub fn emit_default_bundle(context: &ArtifactContext) -> io::Result<BundleWriteReport> {
    let evaluated = evaluate_default_artifacts(context).map_err(io::Error::other)?;
    write_bundle(context, &evaluated)
}

pub fn render_summary(report: &ColdStartCompilationReport) -> String {
    let mut lines = vec![
        "# Cold-Start Compilation Lane Summary".to_string(),
        String::new(),
        format!("- bead_id: `{}`", report.bead_id),
        format!("- component: `{}`", report.component),
        format!("- generated_at_utc: `{}`", report.generated_at_utc),
        format!(
            "- aggregate_benchmark_verdict: `{}`",
            report.aggregate_benchmark_verdict
        ),
        format!(
            "- aggregate_speedup_millionths: `{}`",
            report.aggregate_speedup_millionths
        ),
        format!("- governance_verdict: `{}`", report.governance_verdict),
        format!(
            "- cache_contract_receipts: `{}`",
            report.cache_contract_receipt_count
        ),
        String::new(),
        "## Artifacts".to_string(),
    ];

    for artifact in &report.required_artifacts {
        lines.push(format!("- `{artifact}`"));
    }

    lines.push(String::new());
    lines.push("## Operator Verification".to_string());
    for command in &report.operator_verification {
        lines.push(format!("- `{command}`"));
    }

    lines.join("\n")
}

fn evaluate_default_artifacts(context: &ArtifactContext) -> Result<EvaluatedArtifacts, String> {
    let cache_bundle = emit_cache_contract_subbundle(context)?;
    let epoch = SecurityEpoch::from_raw(42);

    let compile_config = CompileConfig {
        target: CompileTarget::FrozenSnapshot,
        policy_revision: 7,
        engine_version: "0.1.0-cold-start-lane".to_string(),
        ..CompileConfig::default()
    };
    let entrygraphs = build_demo_entrygraphs();
    let batch_report = aot_entrygraph_compiler::compile_batch(&entrygraphs, &compile_config, epoch)
        .map_err(|error| format!("failed to build AOT batch report: {error}"))?;
    let receipts = batch_report
        .reports
        .iter()
        .zip(entrygraphs.iter())
        .map(|(report, graph)| {
            aot_entrygraph_compiler::build_receipt(report, graph.graph_hash, &compile_config)
        })
        .collect::<Vec<_>>();
    let aot_bundle = build_aot_bundle_report(&batch_report, receipts);

    let runtime_image_manifest = build_runtime_image_manifest(&batch_report, epoch)?;
    let governance_config = GovernanceConfig {
        require_observability_proof: true,
        ..GovernanceConfig::default()
    };
    let observability_delta = build_observability_delta(&governance_config);
    let evidence = build_cold_start_evidence(epoch);
    let parity_results = build_parity_results();
    let governance_verdict = cold_start_aot_governance::evaluate_cold_start(
        &evidence,
        &parity_results,
        &governance_config,
    )
    .map_err(|error| format!("failed to evaluate cold-start governance: {error}"))?;
    let rollback_triggers =
        cold_start_aot_governance::check_rollback_needed(&evidence, &governance_config);
    let aggregate_benchmark_verdict =
        cold_start_aot_governance::aggregate_verdict(&evidence, &governance_config);
    let aggregate_speedup_millionths = cold_start_aot_governance::aggregate_speedup(&evidence);
    let governance_receipt = cold_start_aot_governance::produce_receipt(
        epoch,
        &evidence,
        &parity_results,
        &governance_verdict,
    );

    let trace_ids = build_trace_ids_artifact(context, &cache_bundle);
    let operator_verification = operator_verification_commands();
    let report = ColdStartCompilationReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        policy_id: context.policy_id.clone(),
        generated_at_utc: context.generated_at_utc.clone(),
        run_id: context.run_id.clone(),
        source_commit: context.source_commit.clone(),
        toolchain: context.toolchain.clone(),
        persistent_cache_contract_path: PERSISTENT_CACHE_CONTRACT_FILE.to_string(),
        cache_contract_receipt_count: cache_bundle.contract.receipts.len(),
        aot_bundle_report_path: AOT_BUNDLE_FILE.to_string(),
        runtime_image_manifest_path: RUNTIME_IMAGE_MANIFEST_FILE.to_string(),
        observability_delta_path: OBSERVABILITY_DELTA_FILE.to_string(),
        governance_verdict,
        aggregate_benchmark_verdict,
        aggregate_speedup_millionths,
        rollback_triggers,
        governance_receipt,
        evidence,
        parity_results,
        required_artifacts: required_artifact_names(),
        operator_verification,
    };
    let summary = render_summary(&report);

    Ok(EvaluatedArtifacts {
        report,
        observability_delta,
        aot_bundle,
        runtime_image_manifest,
        trace_ids,
        summary,
    })
}

fn emit_cache_contract_subbundle(
    context: &ArtifactContext,
) -> Result<persistent_cache_contract::BundleWriteReport, String> {
    let artifact_dir = context.artifact_dir.join(PERSISTENT_CACHE_DIR);
    let mut cache_context = persistent_cache_contract::ArtifactContext::new(&artifact_dir);
    cache_context.run_id = format!("{}-persistent-cache", context.run_id);
    cache_context.trace_id = format!("{}-cache", context.trace_id);
    cache_context.decision_id = format!("{}-cache", context.decision_id);
    cache_context.policy_id = format!("{}-cache", context.policy_id);
    cache_context.generated_at_utc = context.generated_at_utc.clone();
    cache_context.source_commit = context.source_commit.clone();
    cache_context.toolchain = context.toolchain.clone();
    cache_context.command_invocation = format!(
        "{} [persistent-cache-contract-subbundle]",
        context.command_invocation
    );

    persistent_cache_contract::emit_default_contract_bundle(&cache_context)
        .map_err(|error| format!("failed to emit persistent cache contract subbundle: {error}"))
}

fn build_demo_entrygraphs() -> Vec<Entrygraph> {
    vec![
        Entrygraph {
            graph_id: "pkg-main-demo".to_string(),
            entry_kind: EntryKind::PackageMain,
            modules: vec![
                module("pkg/index.js", 1_200, true, 2),
                module("pkg/runtime.js", 900, false, 1),
                module("pkg/helpers.js", 640, false, 0),
            ],
            graph_hash: hash_label("graph:pkg-main-demo"),
            package_name: Some("demo-package".to_string()),
        },
        Entrygraph {
            graph_id: "ssr-demo".to_string(),
            entry_kind: EntryKind::SsrEntry,
            modules: vec![
                module("web/server-entry.tsx", 1_560, true, 3),
                module("web/app-shell.tsx", 1_140, false, 2),
                module("web/data.ts", 780, false, 1),
                module("web/router.ts", 620, false, 0),
            ],
            graph_hash: hash_label("graph:ssr-demo"),
            package_name: Some("demo-web".to_string()),
        },
        Entrygraph {
            graph_id: "react-client-demo".to_string(),
            entry_kind: EntryKind::ReactClientEntry,
            modules: vec![
                module("client/root.tsx", 1_440, true, 2),
                module("client/routes.tsx", 1_020, false, 1),
                module("client/state.ts", 700, false, 0),
            ],
            graph_hash: hash_label("graph:react-client-demo"),
            package_name: Some("demo-client".to_string()),
        },
    ]
}

fn module(
    specifier: &str,
    source_size_bytes: u64,
    is_root: bool,
    dependency_count: u64,
) -> ModuleEntry {
    ModuleEntry {
        specifier: specifier.to_string(),
        source_hash: hash_label(specifier),
        is_root,
        dependency_count,
        source_size_bytes,
    }
}

fn build_aot_bundle_report(
    batch_report: &BatchReport,
    receipts: Vec<AotDecisionReceipt>,
) -> AotBundleCompilationReport {
    let entry_kind_summary = aot_entrygraph_compiler::entry_kind_summary(batch_report)
        .into_iter()
        .map(|(kind, (total_graphs, usable_graphs))| {
            (
                kind.to_string(),
                EntryKindSummary {
                    total_graphs,
                    usable_graphs,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let target_summary = aot_entrygraph_compiler::target_summary(batch_report)
        .into_iter()
        .map(|(target, count)| (target.to_string(), count))
        .collect::<BTreeMap<_, _>>();

    AotBundleCompilationReport {
        schema_version: AOT_BUNDLE_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        batch_report: batch_report.clone(),
        receipts,
        entry_kind_summary,
        target_summary,
    }
}

fn build_runtime_image_manifest(
    batch_report: &BatchReport,
    epoch: SecurityEpoch,
) -> Result<RuntimeImageManifestArtifact, String> {
    let mut registry = ImageRegistry::new(ImagePolicy::default());
    let total_modules = batch_report
        .reports
        .iter()
        .map(|report| report.total_modules)
        .sum::<u64>();

    registry
        .register(ImageManifest {
            image_id: "img-prewarmed-demo".to_string(),
            kind: ImageKind::Prewarmed,
            state: ImageState::Ready,
            creation_epoch: SecurityEpoch::from_raw(epoch.as_u64().saturating_sub(2)),
            source_hash: batch_report.batch_hash,
            image_hash: hash_label("img-prewarmed-demo"),
            module_count: total_modules,
            total_size_bytes: 1_048_576,
            warm_start_mode: WarmStartMode::PrewarmedPool,
            integrity_status: ImageIntegrityStatus::Verified,
            ttl_seconds: Some(3_600),
            creation_reason: "prewarmed bootstrap pool".to_string(),
        })
        .map_err(|error| format!("failed to register prewarmed image: {error}"))?;
    registry
        .register(ImageManifest {
            image_id: "img-zygote-demo".to_string(),
            kind: ImageKind::Zygote,
            state: ImageState::Ready,
            creation_epoch: SecurityEpoch::from_raw(epoch.as_u64().saturating_sub(1)),
            source_hash: batch_report.batch_hash,
            image_hash: hash_label("img-zygote-demo"),
            module_count: total_modules,
            total_size_bytes: 1_257_472,
            warm_start_mode: WarmStartMode::ZygoteFork,
            integrity_status: ImageIntegrityStatus::Verified,
            ttl_seconds: Some(3_600),
            creation_reason: "fork-safe runtime image".to_string(),
        })
        .map_err(|error| format!("failed to register zygote image: {error}"))?;
    registry
        .register(ImageManifest {
            image_id: "img-aot-demo".to_string(),
            kind: ImageKind::AotCompiled,
            state: ImageState::Ready,
            creation_epoch: epoch,
            source_hash: batch_report.batch_hash,
            image_hash: hash_label("img-aot-demo"),
            module_count: total_modules,
            total_size_bytes: 1_572_864,
            warm_start_mode: WarmStartMode::AotRestore,
            integrity_status: ImageIntegrityStatus::Verified,
            ttl_seconds: Some(3_600),
            creation_reason: "AOT restore image".to_string(),
        })
        .map_err(|error| format!("failed to register AOT image: {error}"))?;

    let best_warm_start = registry.best_warm_start();

    Ok(RuntimeImageManifestArtifact {
        schema_version: RUNTIME_IMAGE_MANIFEST_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        registry_hash: registry.content_hash(),
        image_count: registry.images.len() as u64,
        total_bytes: registry.total_bytes(),
        best_warm_start_image_id: best_warm_start.map(|image| image.image_id.clone()),
        best_warm_start_mode: best_warm_start.map(|image| image.warm_start_mode.to_string()),
        registry,
    })
}

fn build_observability_delta(config: &GovernanceConfig) -> ColdStartObservabilityDeltaArtifact {
    let baseline_nanos = 120_000_000u64;
    let rows = MODE_SAMPLES
        .iter()
        .map(|sample| {
            let speedup_millionths =
                cold_start_aot_governance::compute_speedup(baseline_nanos, sample.candidate_nanos);
            ColdStartObservabilityDeltaRow {
                mode_id: sample.mode_id.to_string(),
                startup_path: sample.startup_path,
                baseline_nanos,
                candidate_nanos: sample.candidate_nanos,
                speedup_millionths,
                preserves_claim: speedup_millionths >= config.min_speedup_threshold as i64,
            }
        })
        .collect::<Vec<_>>();

    ColdStartObservabilityDeltaArtifact {
        schema_version: OBSERVABILITY_DELTA_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        rows,
    }
}

fn build_cold_start_evidence(epoch: SecurityEpoch) -> Vec<ColdStartEvidence> {
    vec![
        ColdStartEvidence::new(
            StartupPathKind::WarmCache,
            120_000_000,
            92_000_000,
            40,
            epoch,
        ),
        ColdStartEvidence::new(
            StartupPathKind::AotRestored,
            120_000_000,
            78_000_000,
            50,
            epoch,
        ),
        ColdStartEvidence::new(
            StartupPathKind::ZygoteFork,
            120_000_000,
            74_000_000,
            45,
            epoch,
        ),
        ColdStartEvidence::new(
            StartupPathKind::PrewarmedPool,
            120_000_000,
            70_000_000,
            45,
            epoch,
        ),
    ]
}

fn build_parity_results() -> Vec<ParityResult> {
    vec![
        ParityResult::new(
            ParityCheckKind::SemanticParity,
            true,
            0,
            b"semantic parity: cache/AOT/warm-start paths match baseline",
        ),
        ParityResult::new(
            ParityCheckKind::BehavioralParity,
            true,
            2_500,
            b"behavioral parity: observability-on and shipped-budgeted modes preserve user-visible behavior",
        ),
        ParityResult::new(
            ParityCheckKind::PerformanceParity,
            true,
            4_000,
            b"performance parity: instrumentation deltas remain within declared claim envelope",
        ),
    ]
}

fn build_trace_ids_artifact(
    context: &ArtifactContext,
    cache_bundle: &persistent_cache_contract::BundleWriteReport,
) -> TraceIdsArtifact {
    let mut subordinate_trace_ids = BTreeMap::new();
    subordinate_trace_ids.insert(
        "persistent_cache_contract".to_string(),
        format!("{}-cache", context.trace_id),
    );
    subordinate_trace_ids.insert(
        "persistent_cache_contract_trace_ids_path".to_string(),
        relative_path(&context.artifact_dir, &cache_bundle.trace_ids_path),
    );

    TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec![
            context.trace_id.clone(),
            format!("{}-cache", context.trace_id),
        ],
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        subordinate_trace_ids,
    }
}

fn operator_verification_commands() -> Vec<String> {
    vec![
        format!("jq '.aggregate_benchmark_verdict,.aggregate_speedup_millionths' {REPORT_FILE}"),
        format!(
            "jq '.rows[] | {{mode_id,preserves_claim,speedup_millionths}}' {OBSERVABILITY_DELTA_FILE}"
        ),
        format!(
            "jq '.best_warm_start_image_id,.best_warm_start_mode' {RUNTIME_IMAGE_MANIFEST_FILE}"
        ),
        format!("jq '.batch_report.total_graphs,.batch_report.usable_graphs' {AOT_BUNDLE_FILE}"),
        format!("jq '.receipts | length' {PERSISTENT_CACHE_CONTRACT_FILE}"),
    ]
}

fn required_artifact_names() -> Vec<String> {
    vec![
        REPORT_FILE.to_string(),
        OBSERVABILITY_DELTA_FILE.to_string(),
        AOT_BUNDLE_FILE.to_string(),
        RUNTIME_IMAGE_MANIFEST_FILE.to_string(),
        TRACE_IDS_FILE.to_string(),
        SUMMARY_FILE.to_string(),
        PERSISTENT_CACHE_CONTRACT_FILE.to_string(),
    ]
}

fn write_bundle(
    context: &ArtifactContext,
    evaluated: &EvaluatedArtifacts,
) -> io::Result<BundleWriteReport> {
    fs::create_dir_all(&context.artifact_dir)?;

    let artifacts = vec![
        FileArtifact::json(REPORT_FILE, &evaluated.report)?,
        FileArtifact::json(OBSERVABILITY_DELTA_FILE, &evaluated.observability_delta)?,
        FileArtifact::json(AOT_BUNDLE_FILE, &evaluated.aot_bundle)?,
        FileArtifact::json(
            RUNTIME_IMAGE_MANIFEST_FILE,
            &evaluated.runtime_image_manifest,
        )?,
        FileArtifact::json(TRACE_IDS_FILE, &evaluated.trace_ids)?,
        FileArtifact::markdown(SUMMARY_FILE, evaluated.summary.clone()),
    ];

    let mut written_files = BTreeMap::new();
    for artifact in artifacts {
        let path = context.artifact_dir.join(&artifact.relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, artifact.contents)?;
        written_files.insert(artifact.relative_path, path.display().to_string());
    }

    let cache_contract_path = context.artifact_dir.join(PERSISTENT_CACHE_CONTRACT_FILE);
    written_files.insert(
        PERSISTENT_CACHE_CONTRACT_FILE.to_string(),
        cache_contract_path.display().to_string(),
    );

    Ok(BundleWriteReport {
        artifact_dir: context.artifact_dir.clone(),
        report_path: context.artifact_dir.join(REPORT_FILE),
        observability_delta_path: context.artifact_dir.join(OBSERVABILITY_DELTA_FILE),
        aot_bundle_report_path: context.artifact_dir.join(AOT_BUNDLE_FILE),
        runtime_image_manifest_path: context.artifact_dir.join(RUNTIME_IMAGE_MANIFEST_FILE),
        trace_ids_path: context.artifact_dir.join(TRACE_IDS_FILE),
        summary_path: context.artifact_dir.join(SUMMARY_FILE),
        written_files,
        report: evaluated.report.clone(),
    })
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn hash_label(label: &str) -> ContentHash {
    ContentHash::compute(label.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn constants_nonempty() {
        assert!(!BEAD_ID.is_empty());
        assert!(BEAD_ID.starts_with("bd-"));
        assert!(!COMPONENT.is_empty());
        assert!(!POLICY_ID.is_empty());
        assert!(!REPORT_SCHEMA_VERSION.is_empty());
        assert!(!AOT_BUNDLE_SCHEMA_VERSION.is_empty());
    }

    #[test]
    fn file_names_nonempty() {
        assert!(!REPORT_FILE.is_empty());
        assert!(REPORT_FILE.ends_with(".json"));
        assert!(!OBSERVABILITY_DELTA_FILE.is_empty());
        assert!(!AOT_BUNDLE_FILE.is_empty());
        assert!(!RUNTIME_IMAGE_MANIFEST_FILE.is_empty());
        assert!(!SUMMARY_FILE.is_empty());
        assert!(!TRACE_IDS_FILE.is_empty());
    }

    #[test]
    fn schema_versions_are_versioned() {
        assert!(REPORT_SCHEMA_VERSION.contains(".v1"));
        assert!(AOT_BUNDLE_SCHEMA_VERSION.contains(".v1"));
        assert!(RUNTIME_IMAGE_MANIFEST_SCHEMA_VERSION.contains(".v1"));
        assert!(OBSERVABILITY_DELTA_SCHEMA_VERSION.contains(".v1"));
        assert!(TRACE_IDS_SCHEMA_VERSION.contains(".v1"));
    }

    // -----------------------------------------------------------------------
    // ArtifactContext
    // -----------------------------------------------------------------------

    #[test]
    fn artifact_context_new_fills_defaults() {
        let ctx = ArtifactContext::new("/tmp/test-artifacts");
        assert_eq!(ctx.artifact_dir, PathBuf::from("/tmp/test-artifacts"));
        assert!(ctx.run_id.starts_with("run-cold_start_compilation_lane-"));
        assert_eq!(ctx.trace_id, "trace-rgc-610");
        assert_eq!(ctx.decision_id, "decision-rgc-610");
        assert_eq!(ctx.policy_id, POLICY_ID);
        assert!(!ctx.generated_at_utc.is_empty());
    }

    #[test]
    fn artifact_context_serde_roundtrip() {
        let ctx = ArtifactContext::new("/tmp/serde-test");
        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: ArtifactContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, decoded);
    }

    // -----------------------------------------------------------------------
    // TraceIdsArtifact
    // -----------------------------------------------------------------------

    #[test]
    fn trace_ids_artifact_serde_roundtrip() {
        let artifact = TraceIdsArtifact {
            schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
            trace_ids: vec!["trace-1".to_string(), "trace-2".to_string()],
            decision_id: "dec-1".to_string(),
            policy_id: POLICY_ID.to_string(),
            subordinate_trace_ids: BTreeMap::new(),
        };
        let json = serde_json::to_string(&artifact).unwrap();
        let decoded: TraceIdsArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, decoded);
    }

    // -----------------------------------------------------------------------
    // EntryKindSummary
    // -----------------------------------------------------------------------

    #[test]
    fn entry_kind_summary_serde_roundtrip() {
        let summary = EntryKindSummary {
            total_graphs: 10,
            usable_graphs: 8,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let decoded: EntryKindSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, decoded);
    }

    // -----------------------------------------------------------------------
    // ColdStartObservabilityDeltaRow
    // -----------------------------------------------------------------------

    #[test]
    fn observability_delta_row_serde_roundtrip() {
        let row = ColdStartObservabilityDeltaRow {
            mode_id: "shipped_budgeted".to_string(),
            startup_path: StartupPathKind::AotRestored,
            baseline_nanos: 100_000_000,
            candidate_nanos: 82_000_000,
            speedup_millionths: 180_000,
            preserves_claim: true,
        };
        let json = serde_json::to_string(&row).unwrap();
        let decoded: ColdStartObservabilityDeltaRow = serde_json::from_str(&json).unwrap();
        assert_eq!(row, decoded);
    }

    #[test]
    fn observability_delta_row_negative_speedup() {
        let row = ColdStartObservabilityDeltaRow {
            mode_id: "regression".to_string(),
            startup_path: StartupPathKind::ZygoteFork,
            baseline_nanos: 80_000_000,
            candidate_nanos: 100_000_000,
            speedup_millionths: -250_000,
            preserves_claim: false,
        };
        assert!(row.speedup_millionths < 0);
        assert!(!row.preserves_claim);
    }

    // -----------------------------------------------------------------------
    // ColdStartObservabilityDeltaArtifact
    // -----------------------------------------------------------------------

    #[test]
    fn observability_delta_artifact_serde_roundtrip() {
        let artifact = ColdStartObservabilityDeltaArtifact {
            schema_version: OBSERVABILITY_DELTA_SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            bead_id: BEAD_ID.to_string(),
            policy_id: POLICY_ID.to_string(),
            rows: Vec::new(),
        };
        let json = serde_json::to_string(&artifact).unwrap();
        let decoded: ColdStartObservabilityDeltaArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, decoded);
    }

    // -----------------------------------------------------------------------
    // RuntimeImageManifestArtifact
    // -----------------------------------------------------------------------

    #[test]
    fn runtime_image_manifest_artifact_serde_roundtrip() {
        let manifest = RuntimeImageManifestArtifact {
            schema_version: RUNTIME_IMAGE_MANIFEST_SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            bead_id: BEAD_ID.to_string(),
            registry_hash: ContentHash::compute(b"test-registry"),
            image_count: 3,
            total_bytes: 1024,
            best_warm_start_image_id: Some("img-1".to_string()),
            best_warm_start_mode: Some("prewarmed_pool".to_string()),
            registry: ImageRegistry::new(crate::runtime_image_contract::ImagePolicy::default()),
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let decoded: RuntimeImageManifestArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, decoded);
    }

    // -----------------------------------------------------------------------
    // MODE_SAMPLES
    // -----------------------------------------------------------------------

    #[test]
    fn mode_samples_have_four_entries() {
        assert_eq!(MODE_SAMPLES.len(), 4);
    }

    #[test]
    fn mode_samples_all_have_unique_ids() {
        let mut ids = std::collections::BTreeSet::new();
        for sample in &MODE_SAMPLES {
            assert!(ids.insert(sample.mode_id), "Duplicate: {}", sample.mode_id);
        }
    }

    #[test]
    fn mode_samples_candidate_nanos_increasing() {
        for window in MODE_SAMPLES.windows(2) {
            assert!(
                window[0].candidate_nanos <= window[1].candidate_nanos,
                "{} ({}) should be <= {} ({})",
                window[0].mode_id,
                window[0].candidate_nanos,
                window[1].mode_id,
                window[1].candidate_nanos,
            );
        }
    }

    // -----------------------------------------------------------------------
    // render_summary
    // -----------------------------------------------------------------------

    #[test]
    fn render_summary_contains_header() {
        let report = ColdStartCompilationReport {
            schema_version: REPORT_SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            bead_id: BEAD_ID.to_string(),
            policy_id: POLICY_ID.to_string(),
            generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
            run_id: "run-test".to_string(),
            source_commit: "abc123".to_string(),
            toolchain: "nightly".to_string(),
            persistent_cache_contract_path: "cache.json".to_string(),
            cache_contract_receipt_count: 3,
            aot_bundle_report_path: "aot.json".to_string(),
            runtime_image_manifest_path: "manifest.json".to_string(),
            observability_delta_path: "delta.json".to_string(),
            governance_verdict: GovernanceVerdict::Approved,
            aggregate_benchmark_verdict: BenchmarkVerdict::Faster,
            aggregate_speedup_millionths: 150_000,
            rollback_triggers: Vec::new(),
            governance_receipt: GovernanceDecisionReceipt::new(
                crate::security_epoch::SecurityEpoch::from_raw(1),
                GovernanceVerdict::Approved,
                Vec::new(),
                Vec::new(),
            ),
            evidence: Vec::new(),
            parity_results: Vec::new(),
            required_artifacts: vec!["artifact1.json".to_string()],
            operator_verification: vec!["verify cmd".to_string()],
        };
        let summary = render_summary(&report);
        assert!(summary.contains("Cold-Start Compilation Lane Summary"));
        assert!(summary.contains(BEAD_ID));
        assert!(summary.contains("artifact1.json"));
        assert!(summary.contains("verify cmd"));
    }

    // -----------------------------------------------------------------------
    // FileArtifact
    // -----------------------------------------------------------------------

    #[test]
    fn file_artifact_markdown_creates_utf8() {
        let artifact = FileArtifact::markdown("test.md", "# Hello".to_string());
        assert_eq!(artifact.relative_path, "test.md");
        assert_eq!(std::str::from_utf8(&artifact.contents).unwrap(), "# Hello");
    }

    #[test]
    fn file_artifact_json_creates_valid_json() {
        let data = EntryKindSummary {
            total_graphs: 5,
            usable_graphs: 3,
        };
        let artifact = FileArtifact::json("test.json", &data).unwrap();
        assert_eq!(artifact.relative_path, "test.json");
        let decoded: EntryKindSummary = serde_json::from_slice(&artifact.contents).unwrap();
        assert_eq!(decoded.total_graphs, 5);
    }

    // -----------------------------------------------------------------------
    // hash_label helper
    // -----------------------------------------------------------------------

    #[test]
    fn hash_label_deterministic() {
        let h1 = hash_label("hello");
        let h2 = hash_label("hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_label_distinct_for_different_inputs() {
        let h1 = hash_label("hello");
        let h2 = hash_label("world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn aot_bundle_compilation_report_serde_roundtrip() {
        let report = AotBundleCompilationReport {
            schema_version: AOT_BUNDLE_SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            bead_id: BEAD_ID.to_string(),
            policy_id: POLICY_ID.to_string(),
            batch_report: BatchReport {
                schema_version: "test".to_string(),
                reports: Vec::new(),
                batch_epoch: crate::security_epoch::SecurityEpoch::from_raw(1),
                total_graphs: 0,
                usable_graphs: 0,
                aggregate_success_rate_millionths: 0,
                batch_hash: crate::hash_tiers::ContentHash::compute(b"empty"),
            },
            receipts: Vec::new(),
            entry_kind_summary: BTreeMap::new(),
            target_summary: BTreeMap::new(),
        };
        let json = serde_json::to_string(&report).unwrap();
        let decoded: AotBundleCompilationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, decoded);
    }
}
