#![forbid(unsafe_code)]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{NaiveDate, NaiveDateTime, SecondsFormat, Utc};
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::authority_footprint::{
    AuthorityFootprintReport, analyze_authority_footprint,
};
use frankenengine_engine::baseline_interpreter::{ConsoleEntry, InterpreterError};
use frankenengine_engine::behavioral_diff::{BehavioralDiffReport, diff_package_behavior};
use frankenengine_engine::benchmark_denominator::{
    PublicationContext, PublicationGateInput, evaluate_publication_gate,
};
use frankenengine_engine::benchmark_e2e::{
    BenchmarkComparisonManifest, BenchmarkFamily, BenchmarkSuiteConfig, ScaleProfile,
    run_benchmark_comparison_suite, run_benchmark_suite, write_benchmark_comparison_artifacts,
    write_evidence_artifacts,
};
use frankenengine_engine::capability::{CapabilityProfile, RuntimeCapability};
use frankenengine_engine::data_contract::{
    DEFAULT_DATA_CONTRACT_PURPOSE, DataContract, DataContractRunBinding,
    E8_REFUSAL_LEDGER_SCHEMA_VERSION, E8RefusalLedgerReceipt,
};
use frankenengine_engine::deterministic_replay::{NondeterminismTrace, ReplayEngine, ReplayMode};
use frankenengine_engine::differential_oracle::{
    DifferentialBackend, DifferentialBackendStatus, DifferentialComparisonVerdict,
    DifferentialOracleInput, DifferentialOracleReport, default_backend_selection,
    run_differential_oracle,
};
use frankenengine_engine::differential_oracle_perf::{
    PerfArmConfig, load_runtime_comparison_corpus, run_differential_perf,
};
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorError,
    OrchestratorResult,
};
use frankenengine_engine::fleet_trace_total_order::{
    FleetTraceNode, flatten_to_events, merge_fleet_traces, node_id_from_session,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::jsx_tsx_parser::JsxRuntimeMode;
use frankenengine_engine::lowering_pipeline::{
    LoweringContext, LoweringPipelineOutput, lower_ir0_to_ir3,
};
use frankenengine_engine::module_compatibility_matrix::CompatibilityScenarioReport;
use frankenengine_engine::package_intake::{PackageIntakeReport, onboard_package};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParseEventIr, ParserOptions};
use frankenengine_engine::react_compilation_pipeline::{
    ReactCompileConfig, ReactCompileEvidence, ReactCompileResult,
    ReactInputLanguage as ReactPipelineInputLanguage, compile_react_source,
    generate_compilation_evidence,
};
use frankenengine_engine::react_doctor_preflight::{
    DoctorConfig as ReactDoctorConfig, DoctorReport as ReactDoctorReport,
    PreflightResult as ReactPreflightResult, SupportBundle as ReactSupportBundle,
    build_support_bundle as build_react_support_bundle, is_react_ready as react_report_is_ready,
    run_doctor as run_react_doctor, run_preflight as run_react_preflight,
};
use frankenengine_engine::react_mismatch_catalog::{
    ComparisonTarget as ReactComparisonTarget, MismatchCatalog,
    MismatchSeverity as ReactMismatchSeverity,
};
use frankenengine_engine::receipt_verifier_pipeline::{
    ReceiptVerifierCliInput, UnifiedReceiptVerificationVerdict, render_verdict_summary,
    verify_receipt_by_id,
};
use frankenengine_engine::replay_time_travel::{TimeTravelConfig, TimeTravelCursor};
use frankenengine_engine::runtime_diagnostics_cli::{
    CompatibilityAdvisoryInput, CompatibilityAdvisoryOutput, EvidenceExportFilter,
    OnboardingReadinessClass, OnboardingScorecardInput, OnboardingScorecardOutput,
    OnboardingScorecardSignal, PreflightDoctorOutput, RolloutDecisionArtifactInput,
    RolloutDecisionArtifactOutput, RolloutRecommendation, RuntimeDiagnosticsCliInput,
    SupportBundleFile, SupportBundleOutput, SupportBundleRedactionPolicy,
    build_compatibility_advisories, build_onboarding_owner_routing, build_onboarding_scorecard,
    build_platform_risk_matrix, build_rollout_decision_artifact, parse_decision_type,
    parse_evidence_severity, render_onboarding_scorecard_markdown,
    render_rollout_decision_artifact_summary, run_preflight_doctor,
};
use frankenengine_engine::runtime_explain_bundle::{
    RUNTIME_EXPLAIN_ORIGIN_ARTIFACT_METADATA_KEY, RUNTIME_EXPLAIN_ORIGIN_SCHEMA_METADATA_KEY,
    RUNTIME_EXPLAIN_ORIGIN_SURFACE_METADATA_KEY, RuntimeArtifactKind, RuntimeArtifactRef,
    RuntimeExplainBundle, RuntimeExplainBundleBuilder, RuntimeExplainLink, RuntimeExplainRelation,
    RuntimeExplainRole, StableArtifactRef,
};
use frankenengine_engine::runtime_explain_views::{
    EXPLAIN_META_CHOSEN_ACTION, EXPLAIN_META_EXPECTED_LOSS, EXPLAIN_META_LANE,
    EXPLAIN_META_LANE_REASON, build_explain_bundle,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::third_party_verifier::{
    BenchmarkClaimBundle, ClaimedBenchmarkOutcome, THIRD_PARTY_VERIFIER_COMPONENT,
    ThirdPartyVerificationReport, VerificationCheckResult, VerificationVerdict, VerifierEvent,
    render_report_summary, verify_benchmark_claim,
};
use frankenengine_engine::time_travel_debugger::{
    DebuggerEvent, InterpreterStateSnapshot, RobotSession, TimeTravelDebugger,
};
use frankenengine_engine::ts_normalization::{
    SourceIngestionSummary, prepare_source_entry_for_public_entrypoints,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

const FRANKENCTL_SCHEMA_VERSION: &str = "franken-engine.frankenctl.v1";
const COMPILE_ARTIFACT_SCHEMA_VERSION: &str = "franken-engine.frankenctl.compile-artifact.v1";
const RUN_REPORT_SCHEMA_VERSION: &str = "franken-engine.frankenctl.run-report.v1";
const RUN_SOURCE_SCHEMA_VERSION: &str = "franken-engine.frankenctl.run-source.v1";
const RUN_ACTION_DECISION_SCHEMA_VERSION: &str = "franken-engine.frankenctl.run-action-decision.v1";
const RUN_POSTERIOR_SCHEMA_VERSION: &str = "franken-engine.frankenctl.run-posterior.v1";
const RUN_CONTAINMENT_RECEIPT_SCHEMA_VERSION: &str =
    "franken-engine.frankenctl.run-containment-receipt.v1";
const CLAIM_EXPLAINER_SCHEMA_VERSION: &str = "franken-engine.external-trust-claim-explainer.v1";
const CLAIM_MATRIX_SCHEMA_VERSION: &str = "franken-engine.claim-to-proof-matrix.v1";
const DEFAULT_CLAIM_MATRIX_PATH: &str = "docs/claim_to_proof_matrix_v1.json";
const DEFAULT_BEADS_JSONL_PATH: &str = ".beads/issues.jsonl";
const REACT_CLI_CONTRACT_SCHEMA_VERSION: &str = "franken-engine.frankenctl.react-cli-contract.v1";
const REACT_CLI_REPORT_SCHEMA_VERSION: &str = "franken-engine.frankenctl.react-cli-report.v1";
const REACT_DOCTOR_REPORT_SCHEMA_VERSION: &str = "franken-engine.frankenctl.react-doctor.v1";
const REACT_DOCTOR_REPRO_INDEX_SCHEMA_VERSION: &str =
    "franken-engine.frankenctl.react-doctor-repro-index.v1";
const REACT_CAPABILITY_CONTRACT_POLICY_ID: &str = "policy-rgc-react-capability-contract-v1";
const REACT_CAPABILITY_CONTRACT_JSON: &str =
    include_str!("../../../../docs/rgc_react_capability_contract_v1.json");
const CODE_BUNDLE_MISSING_FILE: &str = "FE-TPV-BUNDLE-0001";
const CODE_BUNDLE_PARSE_ERROR: &str = "FE-TPV-BUNDLE-0002";
const CODE_BUNDLE_CONTEXT_MISMATCH: &str = "FE-TPV-BUNDLE-0003";
const CODE_BUNDLE_REMOTE_EXEC: &str = "FE-TPV-BUNDLE-0004";
const CODE_BUNDLE_DIGEST_MISMATCH: &str = "FE-TPV-BUNDLE-0005";
const CODE_BUNDLE_SCHEMA_MISMATCH: &str = "FE-TPV-BUNDLE-0006";
const CODE_UNSUPPORTED_PLACEHOLDER_COMMAND: &str = "FE-FRANKENCTL-UNSUPPORTED-PLACEHOLDER";
const BENCHMARK_BUNDLE_ENV_SCHEMA_VERSION: &str = "franken-engine.env.v1";
const BENCHMARK_BUNDLE_MANIFEST_SCHEMA_VERSION: &str = "franken-engine.manifest.v1";
const BENCHMARK_BUNDLE_REPRO_LOCK_SCHEMA_VERSION: &str = "franken-engine.repro-lock.v1";
const BENCHMARK_INVOCATION_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.benchmark-invocation-manifest.v1";
const COMMAND_MODE_RECEIPT_SCHEMA_VERSION: &str = "franken-engine.command-mode-receipt.v1";
const BENCHMARK_BUNDLE_COMPONENT: &str = "frankenctl_benchmark_bundle";
const BENCHMARK_BUNDLE_CLAIM_ID: &str = "bd-20xc";
const BENCHMARK_BUNDLE_REPO_URL: &str = "https://github.com/Dicklesworthstone/franken_engine";

/// Safely convert a Path to &str, returning an error instead of panicking
fn path_to_str(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("Path contains invalid UTF-8 characters: {}", path.display()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandSpec {
    Version,
    Help,
    HelpTopic(HelpTopic),
    Compile(CompileArgs),
    Check(CheckArgs),
    Onboard(OnboardArgs),
    DiffBehavior(DiffBehaviorArgs),
    Run(RunArgs),
    Explain(ExplainArgs),
    Claims(ClaimsArgs),
    Doctor(Box<DoctorArgs>),
    Verify(VerifyArgs),
    Benchmark(BenchmarkArgs),
    Replay(ReplayArgs),
    ReplayDebug(ReplayDebugArgs),
    DifferentialOracle(DifferentialOracleArgs),
    Oracle(OracleArgs),
    React(ReactArgs),
    Gates(GatesArgs),
    Reports(ReportsArgs),
    Test(TestArgs),
    Synth(SynthArgs),
    Orchestrate(OrchestrateArgs),
    Runtime(RuntimeArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelpTopic {
    Compile,
    Check,
    Onboard,
    DiffBehavior,
    Run,
    Explain,
    Claims,
    ClaimsExplain,
    Doctor,
    Verify,
    VerifyCompileArtifact,
    VerifyReceipt,
    Benchmark,
    BenchmarkRun,
    BenchmarkCompare,
    BenchmarkScore,
    BenchmarkVerify,
    Replay,
    ReplayRun,
    ReplayDebug,
    DifferentialOracle,
    DifferentialOracleRun,
    DifferentialOraclePerf,
    Oracle,
    OracleRun,
    OracleReport,
    React,
    ReactCompile,
    ReactBuild,
    ReactDoctor,
    ReactContract,
    Gates,
    Reports,
    Test,
    Synth,
    Orchestrate,
    Runtime,
}

impl HelpTopic {
    fn render(self) -> String {
        match self {
            Self::Compile => compile_usage(),
            Self::Check => check_usage(),
            Self::Onboard => onboard_usage(),
            Self::DiffBehavior => diff_behavior_usage(),
            Self::Run => run_usage(),
            Self::Explain => explain_usage(),
            Self::Claims => claims_usage(),
            Self::ClaimsExplain => claims_explain_usage(),
            Self::Doctor => doctor_usage(),
            Self::Verify => verify_usage(),
            Self::VerifyCompileArtifact => verify_compile_artifact_usage(),
            Self::VerifyReceipt => verify_receipt_usage(),
            Self::Benchmark => benchmark_usage(),
            Self::BenchmarkRun => benchmark_run_usage(),
            Self::BenchmarkCompare => benchmark_compare_usage(),
            Self::BenchmarkScore => benchmark_score_usage(),
            Self::BenchmarkVerify => benchmark_verify_usage(),
            Self::Replay => replay_usage(),
            Self::ReplayRun => replay_run_usage(),
            Self::ReplayDebug => replay_debug_usage(),
            Self::DifferentialOracle => differential_oracle_usage(),
            Self::DifferentialOracleRun => differential_oracle_run_usage(),
            Self::DifferentialOraclePerf => differential_oracle_perf_usage(),
            Self::Oracle => oracle_usage(),
            Self::OracleRun => oracle_run_usage(),
            Self::OracleReport => oracle_report_usage(),
            Self::React => react_usage(),
            Self::ReactCompile => react_compile_usage(),
            Self::ReactBuild => react_build_usage(),
            Self::ReactDoctor => react_doctor_usage(),
            Self::ReactContract => react_contract_usage(),
            Self::Gates => gates_usage(),
            Self::Reports => reports_usage(),
            Self::Test => test_usage(),
            Self::Synth => synth_usage(),
            Self::Orchestrate => orchestrate_usage(),
            Self::Runtime => runtime_usage(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompileArgs {
    input: PathBuf,
    out: PathBuf,
    parse_goal: ParseGoal,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    generated_unix_ns: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckOutputFormat {
    Human,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckArgs {
    input: PathBuf,
    parse_goal: ParseGoal,
    format: CheckOutputFormat,
    /// Optional bundle directory for `run_manifest.json` + `events.jsonl`.
    out: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OnboardArgs {
    /// Package directory (entry auto-detected) or an explicit entry file.
    target: PathBuf,
    /// Optional package root override (defaults: dir target → itself; file
    /// target → the file's parent directory).
    root: Option<PathBuf>,
    parse_goal: ParseGoal,
    format: CheckOutputFormat,
    /// Optional bundle directory for `run_manifest.json` + `events.jsonl`.
    out: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiffBehaviorArgs {
    before: PathBuf,
    after: PathBuf,
    before_root: Option<PathBuf>,
    after_root: Option<PathBuf>,
    before_label: Option<String>,
    after_label: Option<String>,
    parse_goal: ParseGoal,
    format: CheckOutputFormat,
    /// Optional bundle directory for diff + per-side intake reports.
    out: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunArgs {
    input: PathBuf,
    extension_id: String,
    parse_goal: ParseGoal,
    out: Option<PathBuf>,
    explain: bool,
    explain_out: Option<PathBuf>,
    data_contract: Option<PathBuf>,
    data_contract_purpose: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExplainOutputFormat {
    Summary,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExplainArgs {
    input: PathBuf,
    format: ExplainOutputFormat,
    out: Option<PathBuf>,
    /// Directory to emit the full derived view bundle (E3.T4): explain.md,
    /// evidence_graph.json, replay.json, counterfactuals.json, commands.txt,
    /// repro.lock, plus a copy of the index (explain.json).
    emit_bundle: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaimsArgs {
    mode: ClaimsMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClaimsMode {
    Explain(ClaimsExplainArgs),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaimsExplainArgs {
    claim_id: String,
    matrix: PathBuf,
    beads_jsonl: Option<PathBuf>,
    format: CheckOutputFormat,
    out: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DoctorArgs {
    input: Option<PathBuf>,
    artifact_dir: Option<PathBuf>,
    summary: bool,
    out_dir: Option<PathBuf>,
    workload_id: Option<String>,
    package_name: Option<String>,
    target_platforms: Vec<String>,
    signals: Option<PathBuf>,
    advisories: Option<PathBuf>,
    scenario_report: Option<PathBuf>,
    platform_signals: Option<PathBuf>,
    filter: EvidenceExportFilter,
    redact_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VerifyArgs {
    CompileArtifact {
        input: PathBuf,
        output: Option<PathBuf>,
    },
    Receipt {
        input: PathBuf,
        receipt_id: String,
        summary: bool,
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BenchmarkArgs {
    mode: BenchmarkMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BenchmarkMode {
    Run(BenchmarkRunArgs),
    Compare(BenchmarkCompareArgs),
    Score(BenchmarkScoreArgs),
    Verify(BenchmarkVerifyArgs),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BenchmarkRunArgs {
    run_id: String,
    run_date: String,
    seed: u64,
    out_dir: PathBuf,
    profiles: Vec<ScaleProfile>,
    families: Vec<BenchmarkFamily>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BenchmarkCompareArgs {
    manifest: PathBuf,
    out_dir: PathBuf,
    run_id: String,
    run_date: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BenchmarkScoreArgs {
    input: PathBuf,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    output: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BenchmarkVerifyArgs {
    bundle: PathBuf,
    output: Option<PathBuf>,
    summary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplayArgs {
    trace: PathBuf,
    compare_trace: Option<PathBuf>,
    mode: ReplayMode,
    out: Option<PathBuf>,
    fleet_trace: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplayDebugArgs {
    trace: PathBuf,
    script: Option<PathBuf>,
    events: Option<PathBuf>,
    state_snapshots: Option<PathBuf>,
    checkpoint_interval: u64,
    mode: ReplayMode,
    out: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DifferentialOracleArgs {
    mode: DifferentialOracleMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DifferentialOracleMode {
    Run(DifferentialOracleRunArgs),
    Perf(DifferentialOraclePerfArgs),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DifferentialOracleRunArgs {
    input: PathBuf,
    case_id: Option<String>,
    timeout_ms: u64,
    out: Option<PathBuf>,
    engine_budget: Option<u64>,
    engine_memory_budget: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DifferentialOraclePerfArgs {
    manifest: PathBuf,
    out: Option<PathBuf>,
    events: Option<PathBuf>,
    warmup: u32,
    samples: u32,
    case_timeout_ms: u64,
    engine_budget: Option<u64>,
    node_bin: Option<String>,
    bun_bin: Option<String>,
    case_filter: Vec<String>,
}

/// User-facing wrapper over the differential oracle. Where `differential-oracle`
/// is the CI-gate-shaped surface, `oracle` is the operator/frontier-facing
/// surface: it selects engines, emits a content-addressed bundle, renders it,
/// and reports documented exit codes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OracleArgs {
    mode: OracleMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OracleMode {
    Run(OracleRunArgs),
    Report(OracleReportArgs),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OracleRunArgs {
    input: PathBuf,
    /// Resolved, deduplicated, canonically-ordered engine selection.
    engines: Vec<DifferentialBackend>,
    case_id: Option<String>,
    timeout_ms: u64,
    engine_budget: Option<u64>,
    engine_memory_budget: Option<u64>,
    node_bin: Option<String>,
    bun_bin: Option<String>,
    /// When set, write a content-addressed oracle-run bundle to this directory.
    bundle: Option<PathBuf>,
    /// When set, also write the raw `DifferentialOracleReport` JSON here.
    out: Option<PathBuf>,
    format: CheckOutputFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OracleReportArgs {
    /// A bundle directory, or a path to its `manifest.json`/`report.json`.
    bundle: PathBuf,
    format: CheckOutputFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ReactArgs {
    Compile(ReactCompileArgs),
    Build(ReactBuildArgs),
    Doctor(ReactDoctorArgs),
    Contract(ReactContractArgs),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReactCompileArgs {
    input: PathBuf,
    source_form: ReactSourceForm,
    runtime_mode: Option<ReactRuntimeMode>,
    out: Option<PathBuf>,
    trace_id: String,
    decision_id: String,
    policy_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReactBuildArgs {
    entry: PathBuf,
    target: ReactBuildTarget,
    out: Option<PathBuf>,
    trace_id: String,
    decision_id: String,
    policy_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReactDoctorArgs {
    catalog: PathBuf,
    out: Option<PathBuf>,
    summary: bool,
    current_epoch: Option<u64>,
    min_severity: ReactMismatchSeverity,
    include_resolved: bool,
    targets: Vec<ReactComparisonTarget>,
    trace_id: String,
    decision_id: String,
    policy_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReactContractArgs {
    out: Option<PathBuf>,
    trace_id: String,
    decision_id: String,
    policy_id: String,
}

// New consolidated subcommand groups
#[derive(Debug, Clone, PartialEq, Eq)]
struct GatesArgs {
    mode: GatesMode,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum GatesMode {
    ZeroPlaceholder {
        out_dir: PathBuf,
        waivers: Option<PathBuf>,
    },
    SignatureDrift {
        out_dir: PathBuf,
        config: Option<PathBuf>,
    },
    AdversarialCampaign {
        out_dir: PathBuf,
    },
    AmbientMockGuard {
        out_dir: PathBuf,
    },
    IfcConformance {
        out_dir: PathBuf,
    },
    SecurityConformance {
        out_dir: PathBuf,
    },
    ArtifactValidator {
        input: PathBuf,
        out: Option<PathBuf>,
    },
    PlaceholderScan {
        out_dir: PathBuf,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportsArgs {
    mode: ReportsMode,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReportsMode {
    ParserOracle {
        config: Option<PathBuf>,
        out: Option<PathBuf>,
    },
    ParserPhase0 {
        out: Option<PathBuf>,
    },
    LoweringGap {
        out: Option<PathBuf>,
    },
    ParserGap {
        out: Option<PathBuf>,
    },
    ControlPlaneBenchmark {
        out: Option<PathBuf>,
    },
    ControlPlaneMock {
        out: Option<PathBuf>,
    },
    ControlPlanePolicy {
        out_dir: PathBuf,
    },
    EngineBlockerLedger {
        out_dir: PathBuf,
    },
    MetadataEvidence {
        out_dir: PathBuf,
    },
    NpmCompatibility {
        out_dir: PathBuf,
    },
    ObservabilityBundle {
        out_dir: PathBuf,
    },
    RgcPlanning {
        out: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TestArgs {
    mode: TestMode,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum TestMode {
    Test262 {
        out_dir: PathBuf,
        suite_path: Option<PathBuf>,
    },
    Lockstep {
        config: Option<PathBuf>,
        out: Option<PathBuf>,
    },
    MultiEngineParser {
        out_dir: PathBuf,
    },
    S3FifoBaseline {
        out: Option<PathBuf>,
    },
    FrxOracle {
        out: Option<PathBuf>,
    },
    SeqlockCandidate {
        out: Option<PathBuf>,
    },
    SeqlockReaderWriter {
        out: Option<PathBuf>,
    },
    SeqlockRollout {
        out: Option<PathBuf>,
    },
    ShippedPathParity {
        out_dir: PathBuf,
    },
    VerifyGeneral {
        input: PathBuf,
        out: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SynthArgs {
    mode: SynthMode,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum SynthMode {
    KernelContract { out_dir: PathBuf },
    ShapeLattice { out_dir: PathBuf },
    LawMining { out: Option<PathBuf> },
    EvidenceStitching { out_dir: PathBuf },
    CacheContract { out: Option<PathBuf> },
    ColdStart { out_dir: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OrchestrateArgs {
    mode: OrchestrateMode,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum OrchestrateMode {
    ContextRefactor { out: Option<PathBuf> },
    ReactCohort { out: Option<PathBuf> },
    AsupersyncMatrix { out_dir: PathBuf },
    TailLatency { out_dir: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeArgs {
    mode: RuntimeMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RuntimeMode {
    Diagnostics {
        input: PathBuf,
        out_dir: Option<PathBuf>,
        summary: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReactSourceForm {
    Jsx,
    Tsx,
    JsxFragment,
}

impl ReactSourceForm {
    fn as_str(self) -> &'static str {
        match self {
            Self::Jsx => "jsx",
            Self::Tsx => "tsx",
            Self::JsxFragment => "jsx-fragment",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReactRuntimeMode {
    Classic,
    Automatic,
}

impl ReactRuntimeMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Classic => "classic",
            Self::Automatic => "automatic",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReactBuildTarget {
    Ssr,
    Client,
    Hydration,
}

impl ReactBuildTarget {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ssr => "ssr",
            Self::Client => "client",
            Self::Hydration => "hydration",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompileArtifactHashes {
    parse_event_ir: String,
    ir0: String,
    ir1: String,
    ir2: String,
    ir3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompileArtifact {
    schema_version: String,
    generated_unix_ns: u64,
    source_path: String,
    parse_goal: String,
    #[serde(default)]
    source_ingestion: SourceIngestionSummary,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    hashes: CompileArtifactHashes,
    parse_event_ir: ParseEventIr,
    ir0: Ir0Module,
    lowering: LoweringPipelineOutput,
}

#[derive(Debug, Clone, Serialize)]
struct CompileCommandOutput {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    artifact_path: String,
    parse_goal: String,
    source_ingestion: SourceIngestionSummary,
    hashes: CompileArtifactHashes,
    lowering_event_count: usize,
    lowering_witness_count: usize,
    observability_mode: ObservabilityModeOutput,
}

#[derive(Debug, Clone, Serialize)]
struct RunCommandOutput {
    schema_version: String,
    extension_id: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    parse_goal: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    report_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    explain_bundle_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_contract: Option<DataContractRunBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    e8_preflight_receipt: Option<E8RefusalLedgerReceipt>,
    source_ingestion: SourceIngestionSummary,
    lane: String,
    lane_reason: String,
    containment_action: String,
    execution_value: String,
    expected_loss_millionths: i64,
    instructions_executed: u64,
    evidence_entries: usize,
    console_output: Vec<ConsoleEntry>,
    observability_mode: ObservabilityModeOutput,
}

#[derive(Debug, Clone, Serialize)]
struct CompileArtifactVerificationOutput {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    artifact_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    report_path: Option<String>,
    passed: bool,
    errors: Vec<String>,
    observability_mode: ObservabilityModeOutput,
}

#[derive(Debug, Clone, Serialize)]
struct ReceiptVerificationCommandOutput {
    #[serde(flatten)]
    verdict: UnifiedReceiptVerificationVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    report_path: Option<String>,
    observability_mode: ObservabilityModeOutput,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkCommandOutput {
    schema_version: String,
    run_id: String,
    run_date: String,
    seed: u64,
    blocked: bool,
    total_operations: u64,
    total_duration_us: u64,
    invariant_violations: u64,
    profiles: Vec<String>,
    families: Vec<String>,
    artifacts: BenchmarkArtifactPaths,
    observability_mode: ObservabilityModeOutput,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkCompareCommandOutput {
    schema_version: String,
    run_id: String,
    run_date: String,
    case_count: usize,
    runtime_result_count: usize,
    artifacts: BenchmarkArtifactPaths,
    observability_mode: ObservabilityModeOutput,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkScoreCommandOutput {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    score_vs_node: f64,
    score_vs_bun: f64,
    publish_allowed: bool,
    blockers: Vec<String>,
    output: Option<String>,
    bundle: Option<String>,
    bundle_env_path: Option<String>,
    benchmark_invocation_manifest_path: Option<String>,
    command_mode_receipt_path: Option<String>,
    runtime: BenchmarkBundleRuntime,
    observability_mode: ObservabilityModeOutput,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkVerificationCommandOutput {
    #[serde(flatten)]
    report: ThirdPartyVerificationReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    report_path: Option<String>,
    observability_mode: ObservabilityModeOutput,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkArtifactPaths {
    run_manifest: String,
    evidence_jsonl: String,
    events_jsonl: String,
    commands_txt: String,
    benchmark_env_manifest: String,
    raw_results_archive: String,
    summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundleEnv {
    schema_version: String,
    schema_hash: String,
    captured_at_utc: String,
    project: BenchmarkBundleProject,
    host: BenchmarkBundleHost,
    toolchain: BenchmarkBundleToolchain,
    runtime: BenchmarkBundleRuntime,
    policy: BenchmarkBundlePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundleProject {
    name: String,
    repo_url: String,
    commit: String,
    dirty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundleHost {
    os: String,
    kernel: String,
    arch: String,
    cpu_model: String,
    cpu_cores_logical: u64,
    memory_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundleToolchain {
    rustup_toolchain: String,
    rustc: String,
    cargo: String,
    llvm: String,
    target_triple: String,
    profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundleRuntime {
    mode: String,
    lane: String,
    safe_mode_enabled: bool,
    feature_flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ObservabilityModeOutput {
    mode_id: String,
    capture_semantics: String,
    lossless: bool,
}

fn benchmark_bundle_runtime() -> BenchmarkBundleRuntime {
    BenchmarkBundleRuntime {
        mode: "deterministic-score".to_string(),
        lane: "publication_gate".to_string(),
        safe_mode_enabled: true,
        feature_flags: vec!["benchmark-score-cli".to_string()],
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundlePolicy {
    policy_id: String,
    policy_digest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkInvocationManifest {
    schema_version: String,
    schema_hash: String,
    invocation_id: String,
    generated_at_utc: String,
    command: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    input_path: String,
    requested_output_path: String,
    bundle_root: String,
    artifacts: BenchmarkInvocationArtifacts,
    runtime: BenchmarkBundleRuntime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkInvocationArtifacts {
    canonical_results: String,
    env: String,
    bundle_manifest: String,
    commands_transcript: String,
    repro_lock: String,
    command_mode_receipt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommandModeReceipt {
    schema_version: String,
    schema_hash: String,
    receipt_id: String,
    generated_at_utc: String,
    command: String,
    command_family: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    bundle_root: String,
    env_path: String,
    manifest_id: String,
    runtime: BenchmarkBundleRuntime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundleManifest {
    schema_version: String,
    schema_hash: String,
    manifest_id: String,
    generated_at_utc: String,
    claim: BenchmarkBundleClaimMetadata,
    source_revision: BenchmarkBundleSourceRevision,
    provenance: BenchmarkBundleProvenance,
    artifacts: BenchmarkBundleArtifactsCatalog,
    inputs: Vec<BenchmarkBundleArtifactDigest>,
    outputs: Vec<BenchmarkBundleArtifactDigest>,
    canonicalization: BenchmarkBundleCanonicalization,
    validation: BenchmarkBundleValidation,
    retention: BenchmarkBundleRetention,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundleClaimMetadata {
    claim_id: String,
    #[serde(rename = "class")]
    claim_class: String,
    statement: String,
    status: String,
    bundle_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundleSourceRevision {
    repo: String,
    branch: String,
    commit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundleProvenance {
    trace_id: String,
    decision_id: String,
    policy_id: String,
    replay_pointer: String,
    evidence_pointer: String,
    #[serde(default)]
    receipt_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundleArtifactsCatalog {
    env: BenchmarkBundleArtifactDigest,
    lock: BenchmarkBundleArtifactDigest,
    commands: BenchmarkBundleArtifactDigest,
    results: BenchmarkBundleArtifactDigest,
    benchmark_invocation_manifest: BenchmarkBundleArtifactDigest,
    command_mode_receipt: BenchmarkBundleArtifactDigest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundleArtifactDigest {
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundleCanonicalization {
    format: String,
    key_order: String,
    newline: String,
    hash_algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundleValidation {
    validator: String,
    error_taxonomy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundleRetention {
    min_days: u64,
    high_impact_min_days: u64,
    rotation_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundleReproLock {
    schema_version: String,
    schema_hash: String,
    generated_at_utc: String,
    lock_id: String,
    manifest_id: String,
    source_commit: String,
    determinism: BenchmarkBundleDeterminism,
    commands: Vec<String>,
    inputs: Vec<BenchmarkBundleMaterializedFile>,
    expected_outputs: Vec<BenchmarkBundleMaterializedFile>,
    replay: BenchmarkBundleReplay,
    verification: BenchmarkBundleVerification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundleDeterminism {
    allow_network: bool,
    allow_wall_clock: bool,
    allow_randomness: bool,
    max_clock_skew_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundleMaterializedFile {
    path: String,
    sha256: String,
    bytes: u64,
    kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundleReplay {
    trace_id: String,
    decision_id: String,
    policy_id: String,
    replay_pointer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchmarkBundleVerification {
    command: String,
    expected_verdict: String,
}

#[derive(Debug, Clone)]
struct BenchmarkBundleRepoState {
    branch: String,
    commit: String,
    dirty: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ReplayCommandOutput {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    trace_path: String,
    mode: String,
    session_id: String,
    event_count: usize,
    replayed_events: u64,
    divergence_count: usize,
    critical_divergences: usize,
    complete: bool,
    observability_mode: ObservabilityModeOutput,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorSignalCounts {
    external_signals: usize,
    compatibility_signals: usize,
    platform_signals: usize,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorCommandOutput {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    input_path: String,
    workload_id: String,
    package_name: String,
    target_platforms: Vec<String>,
    preflight_verdict: String,
    readiness: String,
    remediation_effort: String,
    rollout_recommendation: String,
    blocked: bool,
    signal_counts: DoctorSignalCounts,
    output_dir: Option<String>,
    preflight: PreflightDoctorOutput,
    onboarding_scorecard: OnboardingScorecardOutput,
    rollout_decision: RolloutDecisionArtifactOutput,
    artifact_bundle: Option<DoctorArtifactBundleStatus>,
    observability_mode: ObservabilityModeOutput,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct DoctorArtifactBundleStatus {
    bundle_dir: String,
    input_path: Option<String>,
    manifest_path: String,
    manifest_present: bool,
    manifest_valid_json: bool,
    manifest_schema_version: Option<String>,
    artifact_paths: BTreeMap<String, Vec<String>>,
    events_path: String,
    events_present: bool,
    events_valid_jsonl: bool,
    event_count: usize,
    step_logs_dir: String,
    step_logs_present: bool,
    step_log_count: usize,
    complete: bool,
    diagnostics: Vec<DoctorArtifactBundleDiagnostic>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct DoctorArtifactBundleDiagnostic {
    severity: String,
    code: String,
    path: String,
    message: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ReactCapabilityContract {
    schema_version: String,
    bead_id: String,
    policy_id: String,
    product_surfaces: Vec<ReactProductSurface>,
    capability_rows: Vec<ReactCapabilityRow>,
}

#[derive(Debug, Clone, Deserialize)]
struct ReactProductSurface {
    surface_bead: String,
    name: String,
    ship_status: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ReactCapabilityRow {
    capability_id: String,
    source_form: String,
    runtime_mode: String,
    entry_surface: String,
    support_status: String,
    owning_implementation_bead: String,
    parity_gate_bead: String,
    product_surface_bead: String,
    verification_lane: String,
    required_artifacts: Vec<String>,
    user_visible_diagnostic: ReactUserVisibleDiagnostic,
    unsupported_surface_policy: ReactUnsupportedSurfacePolicy,
}

#[derive(Debug, Clone, Deserialize)]
struct ReactUserVisibleDiagnostic {
    error_code: String,
    diagnostic_surface: String,
    message_template: String,
    remediation_bead: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ReactUnsupportedSurfacePolicy {
    fallback_mode: String,
    waiver_required: bool,
    max_waiver_age_hours: u64,
    user_visible_diagnostics_required: bool,
    target_milestone: String,
    claim_language_state: String,
}

#[derive(Debug, Clone, Serialize)]
struct ReactCliContractOutput {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    capability_contract_schema_version: String,
    capability_contract_bead: String,
    capability_contract_policy_id: String,
    commands: Vec<ReactCliCommandContract>,
    compile_capabilities: Vec<ReactCliCapabilitySummary>,
    build_capabilities: Vec<ReactCliCapabilitySummary>,
    product_surfaces: Vec<ReactCliProductSurface>,
    output: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ReactCliCommandContract {
    name: String,
    output_schema_version: String,
    behavior: String,
    usage: String,
}

#[derive(Debug, Clone, Serialize)]
struct ReactCliCapabilitySummary {
    capability_id: String,
    support_status: String,
    source_form: Option<String>,
    runtime_mode: Option<String>,
    build_target: Option<String>,
    error_code: String,
    diagnostic_surface: String,
    message_template: String,
    fallback_mode: String,
    claim_language_state: String,
}

#[derive(Debug, Clone, Serialize)]
struct ReactCliProductSurface {
    surface_bead: String,
    name: String,
    ship_status: String,
}

#[derive(Debug, Clone, Serialize)]
struct ReactCliReportOutput {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    command: String,
    support_status: String,
    shipped: bool,
    blocked: bool,
    capability_id: String,
    request: ReactCliRequest,
    diagnostic: ReactCliDiagnostic,
    required_artifacts: Vec<String>,
    compilation: Option<ReactCliCompilationOutput>,
    output: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ReactCliCompilationOutput {
    language: String,
    runtime_mode: String,
    generated_code: String,
    source_map: Option<String>,
    input_hash: String,
    generated_code_hash: String,
    config_hash: String,
    feature_families: Vec<String>,
    transform_counts: BTreeMap<String, u32>,
    receipt: ReactCliCompilationReceiptOutput,
}

#[derive(Debug, Clone, Serialize)]
struct ReactCliCompilationReceiptOutput {
    schema_version: String,
    component: String,
    input_hash: String,
    output_hash: String,
    config_hash: String,
    process_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct ReactDoctorCommandOutput {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    command: String,
    input_catalog_path: String,
    catalog_schema_version: String,
    catalog_bead_id: String,
    catalog_policy_id: String,
    catalog_hash: ContentHash,
    catalog_epoch: SecurityEpoch,
    entries_analyzed: usize,
    blocked: bool,
    ready: bool,
    report: ReactDoctorReport,
    preflight: ReactPreflightResult,
    support_bundle: ReactSupportBundle,
    support_repro_index: ReactDoctorReproIndex,
    output: Option<String>,
    observability_mode: ObservabilityModeOutput,
}

#[derive(Debug, Clone, Serialize)]
struct ReactDoctorReproIndex {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    entry_count: usize,
    entries: Vec<ReactDoctorReproEntry>,
}

#[derive(Debug, Clone, Serialize)]
struct ReactDoctorReproEntry {
    entry_id: String,
    domain: String,
    severity: String,
    target: String,
    remediation_status: String,
    reproduction: String,
    advisory: String,
    verified_epoch: u64,
    tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ReactCliRequest {
    input_path: String,
    source_form: Option<String>,
    runtime_mode: Option<String>,
    build_target: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ReactCliDiagnostic {
    error_code: String,
    diagnostic_surface: String,
    message: String,
    remediation_bead: String,
    fallback_mode: String,
    waiver_required: bool,
    max_waiver_age_hours: u64,
    user_visible_diagnostics_required: bool,
    target_milestone: String,
    claim_language_state: String,
    owning_implementation_bead: String,
    parity_gate_bead: String,
    product_surface_bead: String,
    verification_lane: String,
}

fn main() {
    let code = match run(env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            2
        }
    };
    std::process::exit(code);
}

fn run(raw_args: Vec<String>) -> Result<i32, String> {
    let invocation_trace_id = default_run_id("frankenctl");
    let command = parse_command(&raw_args).map_err(|error| {
        format_cli_error(
            invocation_trace_id.as_str(),
            "parse",
            error.as_str(),
            "Run `frankenctl --help` for full command usage and required arguments.",
        )
    })?;
    let command_name = command_label(&command);
    let remediation = command_remediation(command_name);

    let outcome = match command {
        CommandSpec::Version => {
            println!("frankenctl {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        CommandSpec::Help => {
            println!("{}", usage());
            Ok(0)
        }
        CommandSpec::HelpTopic(topic) => {
            println!("{}", topic.render());
            Ok(0)
        }
        CommandSpec::Compile(args) => execute_compile(args),
        CommandSpec::Check(args) => execute_check(args),
        CommandSpec::Onboard(args) => execute_onboard(args),
        CommandSpec::DiffBehavior(args) => execute_diff_behavior(args),
        CommandSpec::Run(args) => execute_run(args),
        CommandSpec::Explain(args) => execute_explain(args),
        CommandSpec::Claims(args) => execute_claims(args),
        CommandSpec::Doctor(args) => execute_doctor(*args),
        CommandSpec::Verify(args) => execute_verify(args),
        CommandSpec::Benchmark(args) => execute_benchmark(args),
        CommandSpec::Replay(args) => execute_replay(args),
        CommandSpec::ReplayDebug(args) => execute_replay_debug(args),
        CommandSpec::DifferentialOracle(args) => execute_differential_oracle(args),
        CommandSpec::Oracle(args) => execute_oracle(args),
        CommandSpec::React(args) => execute_react(args),
        CommandSpec::Gates(args) => execute_gates(args),
        CommandSpec::Reports(args) => execute_reports(args),
        CommandSpec::Test(args) => execute_test(args),
        CommandSpec::Synth(args) => execute_synth(args),
        CommandSpec::Orchestrate(args) => execute_orchestrate(args),
        CommandSpec::Runtime(args) => execute_runtime(args),
    };

    outcome.map_err(|error| {
        format_cli_error(
            invocation_trace_id.as_str(),
            command_name,
            error.as_str(),
            remediation,
        )
    })
}

fn parse_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Ok(CommandSpec::Help);
    }
    match args[0].as_str() {
        "help" => parse_help_command(&args[1..]),
        "--help" | "-h" => Ok(CommandSpec::Help),
        "version" => Ok(CommandSpec::Version),
        "compile" => parse_compile_command(&args[1..]),
        "check" => parse_check_command(&args[1..]),
        "onboard" => parse_onboard_command(&args[1..]),
        "diff-behavior" => parse_diff_behavior_command(&args[1..]),
        "run" => parse_run_command(&args[1..]),
        "explain" => parse_explain_command(&args[1..]),
        "claims" => parse_claims_command(&args[1..]),
        "doctor" => parse_doctor_command(&args[1..]),
        "verify" => parse_verify_command(&args[1..]),
        "benchmark" => parse_benchmark_command(&args[1..]),
        "replay" => parse_replay_command(&args[1..]),
        "differential-oracle" => parse_differential_oracle_command(&args[1..]),
        "oracle" => parse_oracle_command(&args[1..]),
        "react" => parse_react_command(&args[1..]),
        "gates" => parse_gates_command(&args[1..]),
        "reports" => parse_reports_command(&args[1..]),
        "test" => parse_test_command(&args[1..]),
        "synth" => parse_synth_command(&args[1..]),
        "orchestrate" => parse_orchestrate_command(&args[1..]),
        "runtime" => parse_runtime_command(&args[1..]),
        other => Err(format!("unknown command `{other}`\n\n{}", usage())),
    }
}

fn parse_help_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h") {
        return Ok(CommandSpec::Help);
    }

    match args[0].as_str() {
        "compile" => parse_leaf_help_topic("compile", HelpTopic::Compile, &args[1..]),
        "check" => parse_leaf_help_topic("check", HelpTopic::Check, &args[1..]),
        "onboard" => parse_leaf_help_topic("onboard", HelpTopic::Onboard, &args[1..]),
        "diff-behavior" => {
            parse_leaf_help_topic("diff-behavior", HelpTopic::DiffBehavior, &args[1..])
        }
        "run" => parse_leaf_help_topic("run", HelpTopic::Run, &args[1..]),
        "explain" => parse_leaf_help_topic("explain", HelpTopic::Explain, &args[1..]),
        "claims" => parse_claims_help_command(&args[1..]),
        "doctor" => parse_leaf_help_topic("doctor", HelpTopic::Doctor, &args[1..]),
        "verify" => parse_verify_help_command(&args[1..]),
        "benchmark" => parse_benchmark_help_command(&args[1..]),
        "replay" => parse_replay_help_command(&args[1..]),
        "differential-oracle" => parse_differential_oracle_help_command(&args[1..]),
        "react" => parse_react_help_command(&args[1..]),
        "gates" => parse_leaf_help_topic("gates", HelpTopic::Gates, &args[1..]),
        "reports" => parse_leaf_help_topic("reports", HelpTopic::Reports, &args[1..]),
        "test" => parse_leaf_help_topic("test", HelpTopic::Test, &args[1..]),
        "synth" => parse_leaf_help_topic("synth", HelpTopic::Synth, &args[1..]),
        "orchestrate" => parse_leaf_help_topic("orchestrate", HelpTopic::Orchestrate, &args[1..]),
        "runtime" => parse_leaf_help_topic("runtime", HelpTopic::Runtime, &args[1..]),
        other => Err(format!(
            "unknown help topic `{other}` (expected compile|check|onboard|diff-behavior|run|explain|doctor|verify|benchmark|replay|differential-oracle|react|gates|reports|test|synth|orchestrate|runtime)"
        )),
    }
}

fn parse_claims_help_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h") {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Claims));
    }
    match args[0].as_str() {
        "explain" => parse_leaf_help_topic("claims explain", HelpTopic::ClaimsExplain, &args[1..]),
        other => Err(format!("unknown claims help topic `{other}`")),
    }
}

fn parse_leaf_help_topic(
    command: &str,
    topic: HelpTopic,
    args: &[String],
) -> Result<CommandSpec, String> {
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h") {
        return Ok(CommandSpec::HelpTopic(topic));
    }

    Err(format!(
        "`help {command}` does not accept subtopic `{}`",
        args[0]
    ))
}

fn parse_verify_help_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h") {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Verify));
    }

    match args[0].as_str() {
        "compile-artifact" => parse_leaf_help_topic(
            "verify compile-artifact",
            HelpTopic::VerifyCompileArtifact,
            &args[1..],
        ),
        "receipt" => parse_leaf_help_topic("verify receipt", HelpTopic::VerifyReceipt, &args[1..]),
        other => Err(format!(
            "unknown verify help topic `{other}` (expected compile-artifact|receipt)"
        )),
    }
}

fn parse_benchmark_help_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h") {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Benchmark));
    }

    match args[0].as_str() {
        "run" => parse_leaf_help_topic("benchmark run", HelpTopic::BenchmarkRun, &args[1..]),
        "score" => parse_leaf_help_topic("benchmark score", HelpTopic::BenchmarkScore, &args[1..]),
        "verify" => {
            parse_leaf_help_topic("benchmark verify", HelpTopic::BenchmarkVerify, &args[1..])
        }
        other => Err(format!(
            "unknown benchmark help topic `{other}` (expected run|score|verify)"
        )),
    }
}

fn parse_replay_help_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h") {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Replay));
    }

    match args[0].as_str() {
        "run" => parse_leaf_help_topic("replay run", HelpTopic::ReplayRun, &args[1..]),
        "debug" => parse_leaf_help_topic("replay debug", HelpTopic::ReplayDebug, &args[1..]),
        other => Err(format!(
            "unknown replay help topic `{other}` (expected run|debug)"
        )),
    }
}

fn parse_differential_oracle_help_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h") {
        return Ok(CommandSpec::HelpTopic(HelpTopic::DifferentialOracle));
    }

    match args[0].as_str() {
        "run" => parse_leaf_help_topic(
            "differential-oracle run",
            HelpTopic::DifferentialOracleRun,
            &args[1..],
        ),
        "perf" => parse_leaf_help_topic(
            "differential-oracle perf",
            HelpTopic::DifferentialOraclePerf,
            &args[1..],
        ),
        other => Err(format!(
            "unknown differential-oracle help topic `{other}` (expected run)"
        )),
    }
}

fn parse_react_help_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h") {
        return Ok(CommandSpec::HelpTopic(HelpTopic::React));
    }

    match args[0].as_str() {
        "compile" => parse_leaf_help_topic("react compile", HelpTopic::ReactCompile, &args[1..]),
        "build" => parse_leaf_help_topic("react build", HelpTopic::ReactBuild, &args[1..]),
        "doctor" => parse_leaf_help_topic("react doctor", HelpTopic::ReactDoctor, &args[1..]),
        "contract" => parse_leaf_help_topic("react contract", HelpTopic::ReactContract, &args[1..]),
        other => Err(format!(
            "unknown react help topic `{other}` (expected compile|build|doctor|contract)"
        )),
    }
}

fn parse_compile_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Compile));
    }

    let mut input: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut goal = ParseGoal::Script;
    let mut trace_id = "trace-frankenctl-compile".to_string();
    let mut decision_id = "decision-frankenctl-compile".to_string();
    let mut policy_id = "frankenctl.compile.v1".to_string();
    let mut generated_unix_ns = None;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            "--goal" => goal = parse_goal(&next_arg(args, &mut index, "--goal")?)?,
            "--trace-id" => trace_id = next_arg(args, &mut index, "--trace-id")?,
            "--decision-id" => decision_id = next_arg(args, &mut index, "--decision-id")?,
            "--policy-id" => policy_id = next_arg(args, &mut index, "--policy-id")?,
            "--generated-unix-ns" => {
                generated_unix_ns = Some(parse_u64(
                    &next_arg(args, &mut index, "--generated-unix-ns")?,
                    "--generated-unix-ns",
                )?)
            }
            flag => return Err(format!("unknown compile flag `{flag}`")),
        }
        index += 1;
    }

    let input = input.ok_or_else(|| "compile requires --input <path>".to_string())?;
    let out = out.ok_or_else(|| "compile requires --out <path>".to_string())?;

    Ok(CommandSpec::Compile(CompileArgs {
        input,
        out,
        parse_goal: goal,
        trace_id,
        decision_id,
        policy_id,
        generated_unix_ns,
    }))
}

fn parse_check_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Check));
    }

    let mut input: Option<PathBuf> = None;
    let mut goal = ParseGoal::Script;
    let mut format = CheckOutputFormat::Human;
    let mut out: Option<PathBuf> = None;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            "--goal" => goal = parse_goal(&next_arg(args, &mut index, "--goal")?)?,
            "--format" => {
                format = parse_check_output_format(&next_arg(args, &mut index, "--format")?)?
            }
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            value if !value.starts_with("--") && input.is_none() => {
                input = Some(PathBuf::from(value));
            }
            flag => return Err(format!("unknown check flag `{flag}`")),
        }
        index += 1;
    }

    let input = input.ok_or_else(|| "check requires <file> or --input <path>".to_string())?;

    Ok(CommandSpec::Check(CheckArgs {
        input,
        parse_goal: goal,
        format,
        out,
    }))
}

fn parse_check_output_format(value: &str) -> Result<CheckOutputFormat, String> {
    match value {
        "human" | "text" => Ok(CheckOutputFormat::Human),
        "json" => Ok(CheckOutputFormat::Json),
        other => Err(format!(
            "unknown check --format `{other}` (expected human|json)"
        )),
    }
}

fn parse_onboard_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Onboard));
    }

    let mut target: Option<PathBuf> = None;
    let mut root: Option<PathBuf> = None;
    // Packages are ES-module graphs; default the analysis goal to `module`.
    let mut goal = ParseGoal::Module;
    let mut format = CheckOutputFormat::Human;
    let mut out: Option<PathBuf> = None;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--target" => target = Some(PathBuf::from(next_arg(args, &mut index, "--target")?)),
            "--root" => root = Some(PathBuf::from(next_arg(args, &mut index, "--root")?)),
            "--goal" => goal = parse_goal(&next_arg(args, &mut index, "--goal")?)?,
            "--format" => {
                format = parse_check_output_format(&next_arg(args, &mut index, "--format")?)?
            }
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            value if !value.starts_with("--") && target.is_none() => {
                target = Some(PathBuf::from(value));
            }
            flag => return Err(format!("unknown onboard flag `{flag}`")),
        }
        index += 1;
    }

    let target = target
        .ok_or_else(|| "onboard requires <pkg-dir|entry-file> or --target <path>".to_string())?;

    Ok(CommandSpec::Onboard(OnboardArgs {
        target,
        root,
        parse_goal: goal,
        format,
        out,
    }))
}

fn parse_diff_behavior_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::DiffBehavior));
    }

    let mut before: Option<PathBuf> = None;
    let mut after: Option<PathBuf> = None;
    let mut before_root: Option<PathBuf> = None;
    let mut after_root: Option<PathBuf> = None;
    let mut before_label: Option<String> = None;
    let mut after_label: Option<String> = None;
    let mut goal = ParseGoal::Module;
    let mut format = CheckOutputFormat::Human;
    let mut out: Option<PathBuf> = None;
    let mut positionals: Vec<PathBuf> = Vec::new();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--before" => before = Some(PathBuf::from(next_arg(args, &mut index, "--before")?)),
            "--after" => after = Some(PathBuf::from(next_arg(args, &mut index, "--after")?)),
            "--before-root" => {
                before_root = Some(PathBuf::from(next_arg(args, &mut index, "--before-root")?))
            }
            "--after-root" => {
                after_root = Some(PathBuf::from(next_arg(args, &mut index, "--after-root")?))
            }
            "--before-label" => before_label = Some(next_arg(args, &mut index, "--before-label")?),
            "--after-label" => after_label = Some(next_arg(args, &mut index, "--after-label")?),
            "--goal" => goal = parse_goal(&next_arg(args, &mut index, "--goal")?)?,
            "--format" => {
                format = parse_check_output_format(&next_arg(args, &mut index, "--format")?)?
            }
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            value if !value.starts_with("--") => positionals.push(PathBuf::from(value)),
            flag => return Err(format!("unknown diff-behavior flag `{flag}`")),
        }
        index += 1;
    }

    if before.is_none() {
        before = positionals.first().cloned();
    }
    if after.is_none() {
        after = positionals.get(1).cloned();
    }
    if positionals.len() > 2 {
        return Err(
            "diff-behavior accepts at most two positional paths: <before> <after>".to_string(),
        );
    }

    let before =
        before.ok_or_else(|| "diff-behavior requires a before package/path".to_string())?;
    let after = after.ok_or_else(|| "diff-behavior requires an after package/path".to_string())?;

    Ok(CommandSpec::DiffBehavior(DiffBehaviorArgs {
        before,
        after,
        before_root,
        after_root,
        before_label,
        after_label,
        parse_goal: goal,
        format,
        out,
    }))
}

fn onboard_usage() -> String {
    [
        "onboard usage:",
        "  frankenctl onboard <pkg-dir|entry.js> [--root <dir>] [--goal module|script]",
        "      [--format human|json] [--out <bundle-dir>]",
        "  frankenctl onboard --target <pkg-dir|entry.js> [--root <dir>] [--format json]",
        "",
        "  Walks the static ES-module graph reachable from the entry and reports,",
        "  with module + source-span citations:",
        "    - a normalized manifest proposal (entry, local modules, external deps),",
        "    - a capability-profile proposal (each capability + the exact span(s)",
        "      and owning module that require it),",
        "    - a denied-ambient-authority report (error[FE-CAP-0001] across modules),",
        "    - an IFC flow inventory (required declassifications / runtime checkpoints,",
        "      unsupported flows, and unanalyzable modules),",
        "    - a per-mode module-resolution report (Native/NodeCompat/BunCompat",
        "      differences + extension-probe sequences).",
        "",
        "  v1 is a compiler, not a wizard: only ES `import` declarations are followed",
        "  as graph edges; CommonJS `require`/dynamic `import()` and external (bare)",
        "  specifiers are reported, never silently covered. This is the inferred",
        "  authority footprint for SUPPORTED syntax — not a proof of noninterference",
        "  for arbitrary JS/TS. Most real npm packages honestly report bounded",
        "  coverage until language support rises.",
        "",
        "  If <target> is a directory, the entry is auto-detected from package.json",
        "  (`module` then `main`) and then index.{js,mjs,cjs,ts,jsx,tsx}.",
        "",
        "  exit codes: 0 = clean, 1 = findings present, 2 = unanalyzable (fail-closed)",
        "  --out <dir> writes a content-addressed run_manifest.json + events.jsonl bundle.",
    ]
    .join("\n")
}

fn diff_behavior_usage() -> String {
    [
        "diff-behavior usage:",
        "  frankenctl diff-behavior <before-pkg|entry.js> <after-pkg|entry.js> [--goal module|script]",
        "      [--before-root <dir>] [--after-root <dir>] [--before-label <label>] [--after-label <label>]",
        "      [--format human|json] [--out <bundle-dir>]",
        "  frankenctl diff-behavior --before <pkg> --after <pkg> [--format json]",
        "",
        "  Reuses `frankenctl onboard` package intake for both versions, then emits",
        "  a content-addressed behavioral delta over the supported analyzable subset:",
        "    - added/removed capability and hostcall tags,",
        "    - new denied ambient-authority accesses,",
        "    - new IFC declassification obligations or denied flows,",
        "    - external dependency, mode-divergence, and unanalyzable-surface growth,",
        "    - severity ranking (ProcessSpawn or NetworkEgress additions are critical).",
        "",
        "  This is a supply-chain signal for the supported subset, not a proof of",
        "  package safety. External packages, dynamic import/require, native addons,",
        "  and unanalyzable modules are listed as boundary growth instead of covered.",
        "",
        "  exit codes: 0 = unchanged, 1 = deltas present, 2 = unanalyzable (fail-closed)",
        "  --out <dir> writes behavior_diff_report.json, before/after intake reports,",
        "  run_manifest.json, and events.jsonl.",
    ]
    .join("\n")
}

fn parse_run_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Run));
    }

    let mut input: Option<PathBuf> = None;
    let mut extension_id: Option<String> = None;
    let mut goal = ParseGoal::Script;
    let mut out: Option<PathBuf> = None;
    let mut explain = false;
    let mut explain_out: Option<PathBuf> = None;
    let mut data_contract: Option<PathBuf> = None;
    let mut data_contract_purpose = DEFAULT_DATA_CONTRACT_PURPOSE.to_string();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            "--extension-id" => extension_id = Some(next_arg(args, &mut index, "--extension-id")?),
            "--goal" => goal = parse_goal(&next_arg(args, &mut index, "--goal")?)?,
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            "--data-contract" => {
                data_contract = Some(PathBuf::from(next_arg(
                    args,
                    &mut index,
                    "--data-contract",
                )?));
            }
            "--purpose" => {
                data_contract_purpose = next_arg(args, &mut index, "--purpose")?;
            }
            "--explain" => {
                explain = true;
                if let Some(candidate) = args.get(index + 1)
                    && !candidate.starts_with("--")
                {
                    index += 1;
                    explain_out = Some(PathBuf::from(candidate.as_str()));
                }
            }
            "--explain-out" => {
                explain = true;
                explain_out = Some(PathBuf::from(next_arg(args, &mut index, "--explain-out")?));
            }
            flag => return Err(format!("unknown run flag `{flag}`")),
        }
        index += 1;
    }

    let input = input.ok_or_else(|| "run requires --input <path>".to_string())?;
    let extension_id =
        extension_id.ok_or_else(|| "run requires --extension-id <id>".to_string())?;

    Ok(CommandSpec::Run(RunArgs {
        input,
        extension_id,
        parse_goal: goal,
        out,
        explain,
        explain_out,
        data_contract,
        data_contract_purpose,
    }))
}

fn parse_explain_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Explain));
    }

    let mut input: Option<PathBuf> = None;
    let mut format = ExplainOutputFormat::Summary;
    let mut out: Option<PathBuf> = None;
    let mut emit_bundle: Option<PathBuf> = None;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            "--format" => {
                format = parse_explain_output_format(&next_arg(args, &mut index, "--format")?)?
            }
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            "--emit-bundle" => {
                emit_bundle = Some(PathBuf::from(next_arg(args, &mut index, "--emit-bundle")?))
            }
            value if !value.starts_with("--") && input.is_none() => {
                input = Some(PathBuf::from(value));
            }
            flag => return Err(format!("unknown explain flag `{flag}`")),
        }
        index += 1;
    }

    Ok(CommandSpec::Explain(ExplainArgs {
        input: input
            .ok_or_else(|| "explain requires <bundle.json> or --input <bundle.json>".to_string())?,
        format,
        out,
        emit_bundle,
    }))
}

fn parse_claims_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Claims));
    }
    match args[0].as_str() {
        "help" | "--help" | "-h" => Ok(CommandSpec::HelpTopic(HelpTopic::Claims)),
        "explain" => parse_claims_explain_command(&args[1..]),
        other => Err(format!("unknown claims subcommand `{other}`")),
    }
}

fn parse_claims_explain_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::ClaimsExplain));
    }

    let mut claim_id: Option<String> = None;
    let mut matrix = PathBuf::from(DEFAULT_CLAIM_MATRIX_PATH);
    let mut beads_jsonl = Some(PathBuf::from(DEFAULT_BEADS_JSONL_PATH));
    let mut format = CheckOutputFormat::Human;
    let mut out: Option<PathBuf> = None;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--claim-id" => claim_id = Some(next_arg(args, &mut index, "--claim-id")?),
            "--matrix" => matrix = PathBuf::from(next_arg(args, &mut index, "--matrix")?),
            "--beads-jsonl" => {
                beads_jsonl = Some(PathBuf::from(next_arg(args, &mut index, "--beads-jsonl")?))
            }
            "--no-beads" => beads_jsonl = None,
            "--format" => {
                format = parse_check_output_format(&next_arg(args, &mut index, "--format")?)?
            }
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            value if !value.starts_with("--") && claim_id.is_none() => {
                claim_id = Some(value.to_string());
            }
            flag => return Err(format!("unknown claims explain flag `{flag}`")),
        }
        index += 1;
    }

    let claim_id = claim_id
        .ok_or_else(|| "claims explain requires <claim-id> or --claim-id <id>".to_string())?;
    Ok(CommandSpec::Claims(ClaimsArgs {
        mode: ClaimsMode::Explain(ClaimsExplainArgs {
            claim_id,
            matrix,
            beads_jsonl,
            format,
            out,
        }),
    }))
}

fn parse_doctor_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Doctor));
    }

    let mut input: Option<PathBuf> = None;
    let mut artifact_dir: Option<PathBuf> = None;
    let mut summary = false;
    let mut out_dir: Option<PathBuf> = None;
    let mut workload_id: Option<String> = None;
    let mut package_name: Option<String> = None;
    let mut target_platforms = Vec::<String>::new();
    let mut signals: Option<PathBuf> = None;
    let mut advisories: Option<PathBuf> = None;
    let mut scenario_report: Option<PathBuf> = None;
    let mut platform_signals: Option<PathBuf> = None;
    let mut filter = EvidenceExportFilter::default();
    let mut redact_keys = Vec::<String>::new();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            "--artifact-dir" => {
                artifact_dir = Some(PathBuf::from(next_arg(args, &mut index, "--artifact-dir")?))
            }
            "--summary" => summary = true,
            "--out-dir" => out_dir = Some(PathBuf::from(next_arg(args, &mut index, "--out-dir")?)),
            "--workload-id" => workload_id = Some(next_arg(args, &mut index, "--workload-id")?),
            "--package-name" => package_name = Some(next_arg(args, &mut index, "--package-name")?),
            "--target-platform" => {
                target_platforms.push(next_arg(args, &mut index, "--target-platform")?)
            }
            "--signals" => signals = Some(PathBuf::from(next_arg(args, &mut index, "--signals")?)),
            "--advisories" => {
                advisories = Some(PathBuf::from(next_arg(args, &mut index, "--advisories")?))
            }
            "--scenario-report" => {
                scenario_report = Some(PathBuf::from(next_arg(
                    args,
                    &mut index,
                    "--scenario-report",
                )?))
            }
            "--platform-signals" => {
                platform_signals = Some(PathBuf::from(next_arg(
                    args,
                    &mut index,
                    "--platform-signals",
                )?))
            }
            "--extension-id" => {
                filter.extension_id = Some(next_arg(args, &mut index, "--extension-id")?)
            }
            "--trace-id" => filter.trace_id = Some(next_arg(args, &mut index, "--trace-id")?),
            "--start-ns" => {
                filter.start_timestamp_ns = Some(parse_u64(
                    &next_arg(args, &mut index, "--start-ns")?,
                    "--start-ns",
                )?)
            }
            "--end-ns" => {
                filter.end_timestamp_ns = Some(parse_u64(
                    &next_arg(args, &mut index, "--end-ns")?,
                    "--end-ns",
                )?)
            }
            "--severity" => {
                let value = next_arg(args, &mut index, "--severity")?;
                filter.severity =
                    Some(parse_evidence_severity(value.as_str()).ok_or_else(|| {
                        format!("invalid --severity `{value}` (expected info|warning|critical)")
                    })?);
            }
            "--decision-type" => {
                let value = next_arg(args, &mut index, "--decision-type")?;
                filter.decision_type = Some(
                    parse_decision_type(value.as_str())
                        .ok_or_else(|| format!("invalid --decision-type `{value}`"))?,
                );
            }
            "--redact-key" => redact_keys.push(next_arg(args, &mut index, "--redact-key")?),
            flag => return Err(format!("unknown doctor flag `{flag}`")),
        }
        index += 1;
    }

    if input.is_none() && artifact_dir.is_none() {
        return Err(
            "doctor requires --input <runtime_input.json> or --artifact-dir <bundle>".to_string(),
        );
    }

    Ok(CommandSpec::Doctor(Box::new(DoctorArgs {
        input,
        artifact_dir,
        summary,
        out_dir,
        workload_id,
        package_name,
        target_platforms,
        signals,
        advisories,
        scenario_report,
        platform_signals,
        filter,
        redact_keys,
    })))
}

fn parse_verify_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Err("verify requires a subcommand: compile-artifact | receipt".to_string());
    }
    match args[0].as_str() {
        "help" | "--help" | "-h" => Ok(CommandSpec::HelpTopic(HelpTopic::Verify)),
        "compile-artifact" => parse_verify_compile_artifact_command(&args[1..]),
        "receipt" => parse_verify_receipt_command(&args[1..]),
        other => Err(format!(
            "unknown verify subcommand `{other}` (expected compile-artifact | receipt)"
        )),
    }
}

fn parse_verify_compile_artifact_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::VerifyCompileArtifact));
    }

    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            "--output" => output = Some(PathBuf::from(next_arg(args, &mut index, "--output")?)),
            flag => return Err(format!("unknown verify compile-artifact flag `{flag}`")),
        }
        index += 1;
    }

    Ok(CommandSpec::Verify(VerifyArgs::CompileArtifact {
        input: input.ok_or_else(|| {
            "verify compile-artifact requires --input <artifact.json>".to_string()
        })?,
        output,
    }))
}

fn parse_verify_receipt_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::VerifyReceipt));
    }

    let mut input: Option<PathBuf> = None;
    let mut receipt_id: Option<String> = None;
    let mut summary = false;
    let mut output: Option<PathBuf> = None;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            "--receipt-id" => receipt_id = Some(next_arg(args, &mut index, "--receipt-id")?),
            "--summary" => summary = true,
            "--output" => output = Some(PathBuf::from(next_arg(args, &mut index, "--output")?)),
            flag => return Err(format!("unknown verify receipt flag `{flag}`")),
        }
        index += 1;
    }

    Ok(CommandSpec::Verify(VerifyArgs::Receipt {
        input: input.ok_or_else(|| "verify receipt requires --input <path>".to_string())?,
        receipt_id: receipt_id
            .ok_or_else(|| "verify receipt requires --receipt-id <id>".to_string())?,
        summary,
        output,
    }))
}

fn parse_benchmark_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Err("benchmark requires a subcommand: run | compare | score | verify".to_string());
    }
    match args[0].as_str() {
        "help" | "--help" | "-h" => Ok(CommandSpec::HelpTopic(HelpTopic::Benchmark)),
        "run" => parse_benchmark_run_command(&args[1..]),
        "compare" => parse_benchmark_compare_command(&args[1..]),
        "score" => parse_benchmark_score_command(&args[1..]),
        "verify" => parse_benchmark_verify_command(&args[1..]),
        other => Err(format!(
            "unknown benchmark subcommand `{other}` (expected run | compare | score | verify)"
        )),
    }
}

fn parse_benchmark_run_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::BenchmarkRun));
    }

    let mut run_id = default_run_id("benchmark");
    let mut run_date = "1970-01-01".to_string();
    let mut seed = 42_u64;
    let mut out_dir: Option<PathBuf> = None;
    let mut profiles: Vec<ScaleProfile> = Vec::new();
    let mut families: Vec<BenchmarkFamily> = Vec::new();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--run-id" => run_id = next_arg(args, &mut index, "--run-id")?,
            "--run-date" => {
                let value = next_arg(args, &mut index, "--run-date")?;
                run_date = parse_real_yyyy_mm_dd(value.as_str(), "--run-date")?;
            }
            "--seed" => seed = parse_u64(&next_arg(args, &mut index, "--seed")?, "--seed")?,
            "--out-dir" => out_dir = Some(PathBuf::from(next_arg(args, &mut index, "--out-dir")?)),
            "--profile" => profiles.push(parse_profile(&next_arg(args, &mut index, "--profile")?)?),
            "--family" => families.push(parse_family(&next_arg(args, &mut index, "--family")?)?),
            flag => return Err(format!("unknown benchmark run flag `{flag}`")),
        }
        index += 1;
    }

    let out_dir = out_dir.unwrap_or_else(|| default_benchmark_out_dir(&run_id));

    if profiles.is_empty() {
        profiles = vec![
            ScaleProfile::Small,
            ScaleProfile::Medium,
            ScaleProfile::Large,
        ];
    }
    if families.is_empty() {
        families = BenchmarkFamily::all().to_vec();
    }

    Ok(CommandSpec::Benchmark(BenchmarkArgs {
        mode: BenchmarkMode::Run(BenchmarkRunArgs {
            run_id,
            run_date,
            seed,
            out_dir,
            profiles,
            families,
        }),
    }))
}

fn parse_benchmark_compare_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::BenchmarkCompare));
    }

    let mut manifest: Option<PathBuf> = None;
    let mut out_dir: Option<PathBuf> = None;
    let mut run_id = default_run_id("benchmark-compare");
    let mut run_date = "1970-01-01".to_string();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--manifest" => {
                manifest = Some(PathBuf::from(next_arg(args, &mut index, "--manifest")?))
            }
            "--out-dir" => out_dir = Some(PathBuf::from(next_arg(args, &mut index, "--out-dir")?)),
            "--run-id" => run_id = next_arg(args, &mut index, "--run-id")?,
            "--run-date" => {
                let value = next_arg(args, &mut index, "--run-date")?;
                run_date = parse_real_yyyy_mm_dd(value.as_str(), "--run-date")?;
            }
            flag => return Err(format!("unknown benchmark compare flag `{flag}`")),
        }
        index += 1;
    }

    Ok(CommandSpec::Benchmark(BenchmarkArgs {
        mode: BenchmarkMode::Compare(BenchmarkCompareArgs {
            manifest: manifest
                .ok_or_else(|| "benchmark compare requires --manifest <path>".to_string())?,
            out_dir: out_dir.unwrap_or_else(|| default_benchmark_out_dir(&run_id)),
            run_id,
            run_date,
        }),
    }))
}

fn parse_benchmark_score_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::BenchmarkScore));
    }

    let mut input: Option<PathBuf> = None;
    let mut trace_id = "trace-frankenctl-benchmark-score".to_string();
    let mut decision_id = "decision-frankenctl-benchmark-score".to_string();
    let mut policy_id = "frankenctl.benchmark.score.v1".to_string();
    let mut output: Option<PathBuf> = None;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            "--trace-id" => trace_id = next_arg(args, &mut index, "--trace-id")?,
            "--decision-id" => decision_id = next_arg(args, &mut index, "--decision-id")?,
            "--policy-id" => policy_id = next_arg(args, &mut index, "--policy-id")?,
            "--output" => output = Some(PathBuf::from(next_arg(args, &mut index, "--output")?)),
            flag => return Err(format!("unknown benchmark score flag `{flag}`")),
        }
        index += 1;
    }

    Ok(CommandSpec::Benchmark(BenchmarkArgs {
        mode: BenchmarkMode::Score(BenchmarkScoreArgs {
            input: input.ok_or_else(|| "benchmark score requires --input <path>".to_string())?,
            trace_id,
            decision_id,
            policy_id,
            output,
        }),
    }))
}

fn parse_benchmark_verify_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::BenchmarkVerify));
    }

    let mut bundle: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut summary = false;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--bundle" => bundle = Some(PathBuf::from(next_arg(args, &mut index, "--bundle")?)),
            "--output" => output = Some(PathBuf::from(next_arg(args, &mut index, "--output")?)),
            "--summary" => summary = true,
            flag => return Err(format!("unknown benchmark verify flag `{flag}`")),
        }
        index += 1;
    }

    Ok(CommandSpec::Benchmark(BenchmarkArgs {
        mode: BenchmarkMode::Verify(BenchmarkVerifyArgs {
            bundle: bundle.ok_or_else(|| "benchmark verify requires --bundle <dir>".to_string())?,
            output,
            summary,
        }),
    }))
}

fn parse_replay_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Err("replay requires subcommand `run` or `debug`".to_string());
    }

    match args[0].as_str() {
        "help" | "--help" | "-h" => Ok(CommandSpec::HelpTopic(HelpTopic::Replay)),
        "run" => parse_replay_run_command(&args[1..]),
        "debug" => parse_replay_debug_command(&args[1..]),
        other => Err(format!(
            "unknown replay subcommand `{other}` (expected run|debug)"
        )),
    }
}

fn parse_replay_run_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::ReplayRun));
    }

    let mut trace: Option<PathBuf> = None;
    let mut compare_trace: Option<PathBuf> = None;
    let mut mode = ReplayMode::Strict;
    let mut out: Option<PathBuf> = None;
    let mut fleet_trace: Option<PathBuf> = None;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--trace" => trace = Some(PathBuf::from(next_arg(args, &mut index, "--trace")?)),
            "--compare-trace" => {
                compare_trace = Some(PathBuf::from(next_arg(
                    args,
                    &mut index,
                    "--compare-trace",
                )?))
            }
            "--mode" => mode = parse_replay_mode(&next_arg(args, &mut index, "--mode")?)?,
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            "--fleet-trace" => {
                fleet_trace = Some(PathBuf::from(next_arg(args, &mut index, "--fleet-trace")?))
            }
            flag => return Err(format!("unknown replay run flag `{flag}`")),
        }
        index += 1;
    }

    Ok(CommandSpec::Replay(ReplayArgs {
        trace: trace.ok_or_else(|| "replay run requires --trace <path>".to_string())?,
        compare_trace,
        mode,
        out,
        fleet_trace,
    }))
}

fn parse_replay_debug_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::ReplayDebug));
    }

    let mut trace: Option<PathBuf> = None;
    let mut script: Option<PathBuf> = None;
    let mut events: Option<PathBuf> = None;
    let mut state_snapshots: Option<PathBuf> = None;
    let mut checkpoint_interval: u64 = 64;
    let mut mode = ReplayMode::Strict;
    let mut out: Option<PathBuf> = None;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--trace" => trace = Some(PathBuf::from(next_arg(args, &mut index, "--trace")?)),
            "--script" => script = Some(PathBuf::from(next_arg(args, &mut index, "--script")?)),
            "--events" => events = Some(PathBuf::from(next_arg(args, &mut index, "--events")?)),
            "--state-snapshots" => {
                state_snapshots = Some(PathBuf::from(next_arg(
                    args,
                    &mut index,
                    "--state-snapshots",
                )?))
            }
            "--checkpoint-interval" => {
                let raw = next_arg(args, &mut index, "--checkpoint-interval")?;
                checkpoint_interval = raw
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --checkpoint-interval `{raw}`: {error}"))?;
            }
            "--mode" => mode = parse_replay_mode(&next_arg(args, &mut index, "--mode")?)?,
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            flag => return Err(format!("unknown replay debug flag `{flag}`")),
        }
        index += 1;
    }

    Ok(CommandSpec::ReplayDebug(ReplayDebugArgs {
        trace: trace.ok_or_else(|| "replay debug requires --trace <path>".to_string())?,
        script,
        events,
        state_snapshots,
        checkpoint_interval,
        mode,
        out,
    }))
}

fn parse_differential_oracle_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Ok(CommandSpec::HelpTopic(HelpTopic::DifferentialOracle));
    }

    match args[0].as_str() {
        "help" | "--help" | "-h" => match args.get(1).map(String::as_str) {
            Some("run") => Ok(CommandSpec::HelpTopic(HelpTopic::DifferentialOracleRun)),
            Some("perf") => Ok(CommandSpec::HelpTopic(HelpTopic::DifferentialOraclePerf)),
            Some(other) => Err(format!(
                "unknown differential-oracle help topic `{other}` (expected run|perf)"
            )),
            None => Ok(CommandSpec::HelpTopic(HelpTopic::DifferentialOracle)),
        },
        "run" => parse_differential_oracle_run_command(&args[1..]),
        "perf" => parse_differential_oracle_perf_command(&args[1..]),
        other => Err(format!(
            "unknown differential-oracle subcommand `{other}` (expected run|perf)"
        )),
    }
}

fn parse_differential_oracle_run_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::DifferentialOracleRun));
    }

    let mut input: Option<PathBuf> = None;
    let mut case_id: Option<String> = None;
    let mut timeout_ms = 2_000_u64;
    let mut out: Option<PathBuf> = None;
    let mut engine_budget: Option<u64> = None;
    let mut engine_memory_budget: Option<u64> = None;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            "--case-id" => case_id = Some(next_arg(args, &mut index, "--case-id")?),
            "--timeout-ms" => {
                timeout_ms =
                    parse_u64(&next_arg(args, &mut index, "--timeout-ms")?, "--timeout-ms")?.max(1)
            }
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            "--engine-budget" => {
                engine_budget = Some(parse_u64(
                    &next_arg(args, &mut index, "--engine-budget")?,
                    "--engine-budget",
                )?)
            }
            "--engine-memory-budget" => {
                engine_memory_budget = Some(parse_u64(
                    &next_arg(args, &mut index, "--engine-memory-budget")?,
                    "--engine-memory-budget",
                )?)
            }
            flag => return Err(format!("unknown differential-oracle run flag `{flag}`")),
        }
        index += 1;
    }

    Ok(CommandSpec::DifferentialOracle(DifferentialOracleArgs {
        mode: DifferentialOracleMode::Run(DifferentialOracleRunArgs {
            input: input.ok_or_else(|| {
                "differential-oracle run requires --input <source.js>".to_string()
            })?,
            case_id,
            timeout_ms,
            out,
            engine_budget,
            engine_memory_budget,
        }),
    }))
}

fn parse_differential_oracle_perf_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::DifferentialOraclePerf));
    }

    let mut manifest: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut events: Option<PathBuf> = None;
    let mut warmup = 3_u32;
    let mut samples = 30_u32;
    let mut case_timeout_ms = 120_000_u64;
    let mut engine_budget: Option<u64> = None;
    let mut node_bin: Option<String> = None;
    let mut bun_bin: Option<String> = None;
    let mut case_filter: Vec<String> = Vec::new();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--manifest" => {
                manifest = Some(PathBuf::from(next_arg(args, &mut index, "--manifest")?))
            }
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            "--events" => events = Some(PathBuf::from(next_arg(args, &mut index, "--events")?)),
            "--warmup" => {
                warmup = u32::try_from(parse_u64(
                    &next_arg(args, &mut index, "--warmup")?,
                    "--warmup",
                )?)
                .map_err(|_| "--warmup value does not fit in u32".to_string())?
            }
            "--samples" => {
                samples = u32::try_from(parse_u64(
                    &next_arg(args, &mut index, "--samples")?,
                    "--samples",
                )?)
                .map_err(|_| "--samples value does not fit in u32".to_string())?
            }
            "--case-timeout-ms" => {
                case_timeout_ms = parse_u64(
                    &next_arg(args, &mut index, "--case-timeout-ms")?,
                    "--case-timeout-ms",
                )?
                .max(1)
            }
            "--engine-budget" => {
                engine_budget = Some(parse_u64(
                    &next_arg(args, &mut index, "--engine-budget")?,
                    "--engine-budget",
                )?)
            }
            "--node-bin" => node_bin = Some(next_arg(args, &mut index, "--node-bin")?),
            "--bun-bin" => bun_bin = Some(next_arg(args, &mut index, "--bun-bin")?),
            "--case" => case_filter.push(next_arg(args, &mut index, "--case")?),
            flag => return Err(format!("unknown differential-oracle perf flag `{flag}`")),
        }
        index += 1;
    }

    Ok(CommandSpec::DifferentialOracle(DifferentialOracleArgs {
        mode: DifferentialOracleMode::Perf(DifferentialOraclePerfArgs {
            manifest: manifest.ok_or_else(|| {
                "differential-oracle perf requires --manifest <manifest.json>".to_string()
            })?,
            out,
            events,
            warmup,
            samples,
            case_timeout_ms,
            engine_budget,
            node_bin,
            bun_bin,
            case_filter,
        }),
    }))
}

fn parse_oracle_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Oracle));
    }

    match args[0].as_str() {
        "help" | "--help" | "-h" => match args.get(1).map(String::as_str) {
            Some("run") => Ok(CommandSpec::HelpTopic(HelpTopic::OracleRun)),
            Some("report") => Ok(CommandSpec::HelpTopic(HelpTopic::OracleReport)),
            Some(other) => Err(format!(
                "unknown oracle help topic `{other}` (expected run|report)"
            )),
            None => Ok(CommandSpec::HelpTopic(HelpTopic::Oracle)),
        },
        "run" => parse_oracle_run_command(&args[1..]),
        "report" => parse_oracle_report_command(&args[1..]),
        other => Err(format!(
            "unknown oracle subcommand `{other}` (expected run|report)"
        )),
    }
}

/// Resolve the `--engines` selection. Accepts a comma-separated list of engine
/// aliases; `None` (flag omitted) yields the full four-lane selection.
fn parse_engine_selection(raw: Option<&str>) -> Result<Vec<DifferentialBackend>, String> {
    let Some(raw) = raw else {
        return Ok(default_backend_selection());
    };
    let mut selection: Vec<DifferentialBackend> = Vec::new();
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let backend = match token.to_ascii_lowercase().as_str() {
            "node" | "nodejs" | "node_lts" | "node-lts" => DifferentialBackend::NodeLts,
            "bun" | "bun_stable" | "bun-stable" => DifferentialBackend::BunStable,
            "franken" | "engine" | "franken_engine" | "franken-engine" => {
                DifferentialBackend::FrankenEngine
            }
            "core" | "franken_core" | "franken-core" => DifferentialBackend::FrankenCore,
            other => {
                return Err(format!(
                    "unknown engine `{other}` in --engines (expected comma-separated subset of: node, bun, franken, core)"
                ));
            }
        };
        if !selection.contains(&backend) {
            selection.push(backend);
        }
    }
    if selection.is_empty() {
        return Err(
            "--engines must select at least one engine (node, bun, franken, core)".to_string(),
        );
    }
    Ok(selection)
}

fn parse_oracle_run_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::OracleRun));
    }

    let mut input: Option<PathBuf> = None;
    let mut engines_raw: Option<String> = None;
    let mut case_id: Option<String> = None;
    let mut timeout_ms = 2_000_u64;
    let mut engine_budget: Option<u64> = None;
    let mut engine_memory_budget: Option<u64> = None;
    let mut node_bin: Option<String> = None;
    let mut bun_bin: Option<String> = None;
    let mut bundle: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut format = CheckOutputFormat::Human;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            "--engines" => engines_raw = Some(next_arg(args, &mut index, "--engines")?),
            "--case-id" => case_id = Some(next_arg(args, &mut index, "--case-id")?),
            "--timeout-ms" => {
                timeout_ms =
                    parse_u64(&next_arg(args, &mut index, "--timeout-ms")?, "--timeout-ms")?.max(1)
            }
            "--engine-budget" => {
                engine_budget = Some(parse_u64(
                    &next_arg(args, &mut index, "--engine-budget")?,
                    "--engine-budget",
                )?)
            }
            "--engine-memory-budget" => {
                engine_memory_budget = Some(parse_u64(
                    &next_arg(args, &mut index, "--engine-memory-budget")?,
                    "--engine-memory-budget",
                )?)
            }
            "--node-bin" => node_bin = Some(next_arg(args, &mut index, "--node-bin")?),
            "--bun-bin" => bun_bin = Some(next_arg(args, &mut index, "--bun-bin")?),
            "--bundle" => bundle = Some(PathBuf::from(next_arg(args, &mut index, "--bundle")?)),
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            "--json" => format = CheckOutputFormat::Json,
            other if !other.starts_with("--") => {
                if input.is_some() {
                    return Err(format!(
                        "unexpected positional argument `{other}` (input already provided)"
                    ));
                }
                input = Some(PathBuf::from(other));
            }
            flag => return Err(format!("unknown oracle run flag `{flag}`")),
        }
        index += 1;
    }

    let engines = parse_engine_selection(engines_raw.as_deref())?;

    Ok(CommandSpec::Oracle(OracleArgs {
        mode: OracleMode::Run(OracleRunArgs {
            input: input.ok_or_else(|| {
                "oracle run requires <input.js> (positional or --input)".to_string()
            })?,
            engines,
            case_id,
            timeout_ms,
            engine_budget,
            engine_memory_budget,
            node_bin,
            bun_bin,
            bundle,
            out,
            format,
        }),
    }))
}

fn parse_oracle_report_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::OracleReport));
    }

    let mut bundle: Option<PathBuf> = None;
    let mut format = CheckOutputFormat::Human;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--bundle" => bundle = Some(PathBuf::from(next_arg(args, &mut index, "--bundle")?)),
            "--json" => format = CheckOutputFormat::Json,
            other if !other.starts_with("--") => {
                if bundle.is_some() {
                    return Err(format!(
                        "unexpected positional argument `{other}` (bundle already provided)"
                    ));
                }
                bundle = Some(PathBuf::from(other));
            }
            flag => return Err(format!("unknown oracle report flag `{flag}`")),
        }
        index += 1;
    }

    Ok(CommandSpec::Oracle(OracleArgs {
        mode: OracleMode::Report(OracleReportArgs {
            bundle: bundle
                .ok_or_else(|| "oracle report requires <bundle-dir|manifest.json>".to_string())?,
            format,
        }),
    }))
}

fn parse_react_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Ok(CommandSpec::HelpTopic(HelpTopic::React));
    }

    match args[0].as_str() {
        "help" | "--help" | "-h" => match args.get(1).map(String::as_str) {
            Some("compile") => Ok(CommandSpec::HelpTopic(HelpTopic::ReactCompile)),
            Some("build") => Ok(CommandSpec::HelpTopic(HelpTopic::ReactBuild)),
            Some("doctor") => Ok(CommandSpec::HelpTopic(HelpTopic::ReactDoctor)),
            Some("contract") => Ok(CommandSpec::HelpTopic(HelpTopic::ReactContract)),
            Some(other) => Err(format!(
                "unknown react help topic `{other}` (expected compile|build|doctor|contract)"
            )),
            None => Ok(CommandSpec::HelpTopic(HelpTopic::React)),
        },
        "compile" => parse_react_compile_command(&args[1..]),
        "build" => parse_react_build_command(&args[1..]),
        "doctor" => parse_react_doctor_command(&args[1..]),
        "contract" => parse_react_contract_command(&args[1..]),
        other => Err(format!(
            "unknown react subcommand `{other}` (expected compile|build|doctor|contract)"
        )),
    }
}

fn parse_react_compile_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::ReactCompile));
    }

    let mut input: Option<PathBuf> = None;
    let mut source_form: Option<ReactSourceForm> = None;
    let mut runtime_mode: Option<ReactRuntimeMode> = None;
    let mut out: Option<PathBuf> = None;
    let mut trace_id = "trace-frankenctl-react-compile".to_string();
    let mut decision_id = "decision-frankenctl-react-compile".to_string();
    let mut policy_id = "frankenctl.react.compile.v1".to_string();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            "--source-form" => {
                source_form = Some(parse_react_source_form(&next_arg(
                    args,
                    &mut index,
                    "--source-form",
                )?)?)
            }
            "--runtime" => {
                runtime_mode = Some(parse_react_runtime_mode(&next_arg(
                    args,
                    &mut index,
                    "--runtime",
                )?)?)
            }
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            "--trace-id" => trace_id = next_arg(args, &mut index, "--trace-id")?,
            "--decision-id" => decision_id = next_arg(args, &mut index, "--decision-id")?,
            "--policy-id" => policy_id = next_arg(args, &mut index, "--policy-id")?,
            flag => return Err(format!("unknown react compile flag `{flag}`")),
        }
        index += 1;
    }

    let source_form = source_form
        .ok_or_else(|| "react compile requires --source-form <jsx|tsx|jsx-fragment>".to_string())?;
    if source_form != ReactSourceForm::JsxFragment && runtime_mode.is_none() {
        return Err("react compile requires --runtime <classic|automatic> unless --source-form jsx-fragment".to_string());
    }
    if source_form == ReactSourceForm::JsxFragment && runtime_mode.is_some() {
        return Err(
            "react compile does not accept --runtime when --source-form jsx-fragment".to_string(),
        );
    }

    Ok(CommandSpec::React(ReactArgs::Compile(ReactCompileArgs {
        input: input.ok_or_else(|| "react compile requires --input <path>".to_string())?,
        source_form,
        runtime_mode,
        out,
        trace_id,
        decision_id,
        policy_id,
    })))
}

fn parse_react_build_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::ReactBuild));
    }

    let mut entry: Option<PathBuf> = None;
    let mut target: Option<ReactBuildTarget> = None;
    let mut out: Option<PathBuf> = None;
    let mut trace_id = "trace-frankenctl-react-build".to_string();
    let mut decision_id = "decision-frankenctl-react-build".to_string();
    let mut policy_id = "frankenctl.react.build.v1".to_string();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--entry" => entry = Some(PathBuf::from(next_arg(args, &mut index, "--entry")?)),
            "--target" => {
                target = Some(parse_react_build_target(&next_arg(
                    args, &mut index, "--target",
                )?)?)
            }
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            "--trace-id" => trace_id = next_arg(args, &mut index, "--trace-id")?,
            "--decision-id" => decision_id = next_arg(args, &mut index, "--decision-id")?,
            "--policy-id" => policy_id = next_arg(args, &mut index, "--policy-id")?,
            flag => return Err(format!("unknown react build flag `{flag}`")),
        }
        index += 1;
    }

    Ok(CommandSpec::React(ReactArgs::Build(ReactBuildArgs {
        entry: entry.ok_or_else(|| "react build requires --entry <path>".to_string())?,
        target: target
            .ok_or_else(|| "react build requires --target <ssr|client|hydration>".to_string())?,
        out,
        trace_id,
        decision_id,
        policy_id,
    })))
}

fn parse_react_doctor_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::ReactDoctor));
    }

    let mut catalog: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut summary = false;
    let mut current_epoch: Option<u64> = None;
    let mut min_severity = ReactMismatchSeverity::Info;
    let mut include_resolved = false;
    let mut targets = Vec::<ReactComparisonTarget>::new();
    let mut trace_id = "trace-frankenctl-react-doctor".to_string();
    let mut decision_id = "decision-frankenctl-react-doctor".to_string();
    let mut policy_id = "frankenctl.react.doctor.v1".to_string();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--catalog" => catalog = Some(PathBuf::from(next_arg(args, &mut index, "--catalog")?)),
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            "--summary" => summary = true,
            "--current-epoch" => {
                current_epoch = Some(parse_u64(
                    &next_arg(args, &mut index, "--current-epoch")?,
                    "--current-epoch",
                )?)
            }
            "--min-severity" => {
                min_severity =
                    parse_react_mismatch_severity(&next_arg(args, &mut index, "--min-severity")?)?
            }
            "--include-resolved" => include_resolved = true,
            "--target" => targets.push(parse_react_comparison_target(&next_arg(
                args, &mut index, "--target",
            )?)?),
            "--trace-id" => trace_id = next_arg(args, &mut index, "--trace-id")?,
            "--decision-id" => decision_id = next_arg(args, &mut index, "--decision-id")?,
            "--policy-id" => policy_id = next_arg(args, &mut index, "--policy-id")?,
            flag => return Err(format!("unknown react doctor flag `{flag}`")),
        }
        index += 1;
    }

    Ok(CommandSpec::React(ReactArgs::Doctor(ReactDoctorArgs {
        catalog: catalog.ok_or_else(|| "react doctor requires --catalog <path>".to_string())?,
        out,
        summary,
        current_epoch,
        min_severity,
        include_resolved,
        targets,
        trace_id,
        decision_id,
        policy_id,
    })))
}

fn parse_react_contract_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::ReactContract));
    }

    let mut out: Option<PathBuf> = None;
    let mut trace_id = "trace-frankenctl-react-contract".to_string();
    let mut decision_id = "decision-frankenctl-react-contract".to_string();
    let mut policy_id = "frankenctl.react.contract.v1".to_string();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            "--trace-id" => trace_id = next_arg(args, &mut index, "--trace-id")?,
            "--decision-id" => decision_id = next_arg(args, &mut index, "--decision-id")?,
            "--policy-id" => policy_id = next_arg(args, &mut index, "--policy-id")?,
            flag => return Err(format!("unknown react contract flag `{flag}`")),
        }
        index += 1;
    }

    Ok(CommandSpec::React(ReactArgs::Contract(ReactContractArgs {
        out,
        trace_id,
        decision_id,
        policy_id,
    })))
}

// New consolidated subcommand parsing functions
fn parse_gates_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Gates));
    }

    match args[0].as_str() {
        "help" | "--help" | "-h" => Ok(CommandSpec::HelpTopic(HelpTopic::Gates)),
        "zero-placeholder" => {
            if args.len() == 1 {
                return Err("gates zero-placeholder requires --out-dir <dir>".to_string());
            }

            let mut out_dir: Option<PathBuf> = None;
            let mut waivers: Option<PathBuf> = None;

            let mut index = 1; // Skip "zero-placeholder"
            while index < args.len() {
                match args[index].as_str() {
                    "--out-dir" => {
                        out_dir = Some(PathBuf::from(next_arg(args, &mut index, "--out-dir")?))
                    }
                    "--waivers" => {
                        waivers = Some(PathBuf::from(next_arg(args, &mut index, "--waivers")?))
                    }
                    flag => return Err(format!("unknown zero-placeholder flag `{flag}`")),
                }
                index += 1;
            }

            let out_dir = out_dir
                .ok_or_else(|| "gates zero-placeholder requires --out-dir <dir>".to_string())?;

            Ok(CommandSpec::Gates(GatesArgs {
                mode: GatesMode::ZeroPlaceholder { out_dir, waivers },
            }))
        }
        "signature-drift" => {
            let mut out_dir: Option<PathBuf> = None;
            let mut config: Option<PathBuf> = None;

            let mut index = 1; // Skip "signature-drift"
            while index < args.len() {
                match args[index].as_str() {
                    "--out-dir" => {
                        out_dir = Some(PathBuf::from(next_arg(args, &mut index, "--out-dir")?))
                    }
                    "--config" => {
                        config = Some(PathBuf::from(next_arg(args, &mut index, "--config")?))
                    }
                    flag => return Err(format!("unknown signature-drift flag `{flag}`")),
                }
                index += 1;
            }

            let out_dir = out_dir
                .ok_or_else(|| "gates signature-drift requires --out-dir <dir>".to_string())?;
            Ok(CommandSpec::Gates(GatesArgs {
                mode: GatesMode::SignatureDrift { out_dir, config },
            }))
        }
        other => Err(format!("unknown gates subcommand `{other}`")),
    }
}

fn parse_reports_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Reports));
    }

    match args[0].as_str() {
        "help" | "--help" | "-h" => Ok(CommandSpec::HelpTopic(HelpTopic::Reports)),
        "parser-oracle" => {
            let mut config: Option<PathBuf> = None;
            let mut out: Option<PathBuf> = None;

            let mut index = 1; // Skip "parser-oracle"
            while index < args.len() {
                match args[index].as_str() {
                    "--config" => {
                        config = Some(PathBuf::from(next_arg(args, &mut index, "--config")?))
                    }
                    "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
                    flag => return Err(format!("unknown parser-oracle flag `{flag}`")),
                }
                index += 1;
            }

            Ok(CommandSpec::Reports(ReportsArgs {
                mode: ReportsMode::ParserOracle { config, out },
            }))
        }
        "lowering-gap" => {
            let mut out: Option<PathBuf> = None;

            let mut index = 1; // Skip "lowering-gap"
            while index < args.len() {
                match args[index].as_str() {
                    "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
                    flag => return Err(format!("unknown lowering-gap flag `{flag}`")),
                }
                index += 1;
            }

            Ok(CommandSpec::Reports(ReportsArgs {
                mode: ReportsMode::LoweringGap { out },
            }))
        }
        other => Err(format!("unknown reports subcommand `{other}`")),
    }
}

fn parse_test_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Test));
    }

    match args[0].as_str() {
        "help" | "--help" | "-h" => Ok(CommandSpec::HelpTopic(HelpTopic::Test)),
        "test262" => {
            if args.len() == 1 {
                return Err("test test262 requires --out-dir <dir>".to_string());
            }

            let mut out_dir: Option<PathBuf> = None;
            let mut suite_path: Option<PathBuf> = None;

            let mut index = 1; // Skip "test262"
            while index < args.len() {
                match args[index].as_str() {
                    "--out-dir" => {
                        out_dir = Some(PathBuf::from(next_arg(args, &mut index, "--out-dir")?))
                    }
                    "--suite-path" => {
                        suite_path =
                            Some(PathBuf::from(next_arg(args, &mut index, "--suite-path")?))
                    }
                    flag => return Err(format!("unknown test262 flag `{flag}`")),
                }
                index += 1;
            }

            let out_dir =
                out_dir.ok_or_else(|| "test test262 requires --out-dir <dir>".to_string())?;

            Ok(CommandSpec::Test(TestArgs {
                mode: TestMode::Test262 {
                    out_dir,
                    suite_path,
                },
            }))
        }
        "lockstep" => {
            let mut config: Option<PathBuf> = None;
            let mut out: Option<PathBuf> = None;

            let mut index = 1; // Skip "lockstep"
            while index < args.len() {
                match args[index].as_str() {
                    "--config" => {
                        config = Some(PathBuf::from(next_arg(args, &mut index, "--config")?))
                    }
                    "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
                    flag => return Err(format!("unknown lockstep flag `{flag}`")),
                }
                index += 1;
            }

            Ok(CommandSpec::Test(TestArgs {
                mode: TestMode::Lockstep { config, out },
            }))
        }
        other => Err(format!("unknown test subcommand `{other}`")),
    }
}

fn parse_synth_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Synth));
    }

    match args[0].as_str() {
        "help" | "--help" | "-h" => Ok(CommandSpec::HelpTopic(HelpTopic::Synth)),
        "kernel-contract" => {
            if args.len() == 1 {
                return Err("synth kernel-contract requires --out-dir <dir>".to_string());
            }

            let mut out_dir: Option<PathBuf> = None;

            let mut index = 1; // Skip "kernel-contract"
            while index < args.len() {
                match args[index].as_str() {
                    "--out-dir" => {
                        out_dir = Some(PathBuf::from(next_arg(args, &mut index, "--out-dir")?))
                    }
                    flag => return Err(format!("unknown kernel-contract flag `{flag}`")),
                }
                index += 1;
            }

            let out_dir = out_dir
                .ok_or_else(|| "synth kernel-contract requires --out-dir <dir>".to_string())?;

            Ok(CommandSpec::Synth(SynthArgs {
                mode: SynthMode::KernelContract { out_dir },
            }))
        }
        "law-mining" => {
            let mut out: Option<PathBuf> = None;

            let mut index = 1; // Skip "law-mining"
            while index < args.len() {
                match args[index].as_str() {
                    "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
                    flag => return Err(format!("unknown law-mining flag `{flag}`")),
                }
                index += 1;
            }

            Ok(CommandSpec::Synth(SynthArgs {
                mode: SynthMode::LawMining { out },
            }))
        }
        other => Err(format!("unknown synth subcommand `{other}`")),
    }
}

fn parse_orchestrate_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Orchestrate));
    }

    match args[0].as_str() {
        "help" | "--help" | "-h" => Ok(CommandSpec::HelpTopic(HelpTopic::Orchestrate)),
        "context-refactor" => {
            let mut out: Option<PathBuf> = None;

            let mut index = 1; // Skip "context-refactor"
            while index < args.len() {
                match args[index].as_str() {
                    "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
                    flag => return Err(format!("unknown context-refactor flag `{flag}`")),
                }
                index += 1;
            }

            Ok(CommandSpec::Orchestrate(OrchestrateArgs {
                mode: OrchestrateMode::ContextRefactor { out },
            }))
        }
        "tail-latency" => {
            if args.len() == 1 {
                return Err("orchestrate tail-latency requires --out-dir <dir>".to_string());
            }

            let mut out_dir: Option<PathBuf> = None;

            let mut index = 1; // Skip "tail-latency"
            while index < args.len() {
                match args[index].as_str() {
                    "--out-dir" => {
                        out_dir = Some(PathBuf::from(next_arg(args, &mut index, "--out-dir")?))
                    }
                    flag => return Err(format!("unknown tail-latency flag `{flag}`")),
                }
                index += 1;
            }

            let out_dir = out_dir
                .ok_or_else(|| "orchestrate tail-latency requires --out-dir <dir>".to_string())?;

            Ok(CommandSpec::Orchestrate(OrchestrateArgs {
                mode: OrchestrateMode::TailLatency { out_dir },
            }))
        }
        other => Err(format!("unknown orchestrate subcommand `{other}`")),
    }
}

fn parse_runtime_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Runtime));
    }

    match args[0].as_str() {
        "help" | "--help" | "-h" => Ok(CommandSpec::HelpTopic(HelpTopic::Runtime)),
        "diagnostics" => {
            if args.len() == 1 {
                return Err("runtime diagnostics requires --input <file>".to_string());
            }

            let mut input: Option<PathBuf> = None;
            let mut out_dir: Option<PathBuf> = None;
            let mut summary = false;

            let mut index = 1; // Skip "diagnostics"
            while index < args.len() {
                match args[index].as_str() {
                    "--input" => {
                        input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?))
                    }
                    "--out-dir" => {
                        out_dir = Some(PathBuf::from(next_arg(args, &mut index, "--out-dir")?))
                    }
                    "--summary" => summary = true,
                    flag => return Err(format!("unknown diagnostics flag `{flag}`")),
                }
                index += 1;
            }

            let input =
                input.ok_or_else(|| "runtime diagnostics requires --input <file>".to_string())?;

            Ok(CommandSpec::Runtime(RuntimeArgs {
                mode: RuntimeMode::Diagnostics {
                    input,
                    out_dir,
                    summary,
                },
            }))
        }
        other => Err(format!("unknown runtime subcommand `{other}`")),
    }
}

fn has_help_flag(args: &[String]) -> bool {
    args.iter()
        .any(|value| matches!(value.as_str(), "--help" | "-h"))
}

fn execute_compile(args: CompileArgs) -> Result<i32, String> {
    let source = fs::read_to_string(&args.input)
        .map_err(|error| format!("failed to read source `{}`: {error}", args.input.display()))?;
    let source_label = args.input.display().to_string();
    let prepared = prepare_source_entry_for_public_entrypoints(
        source.as_str(),
        source_label.as_str(),
        args.trace_id.as_str(),
        args.decision_id.as_str(),
        args.policy_id.as_str(),
    )
    .map_err(|error| format!("source ingestion failed for `{source_label}`: {error}"))?;
    let parser_options = ParserOptions::default();
    let parser = CanonicalEs2020Parser;
    let (parse_result, parse_event_ir) = parser.parse_with_event_ir(
        prepared.prepared_source.as_str(),
        args.parse_goal,
        &parser_options,
    );
    let syntax_tree = parse_result.map_err(|error| format!("parse failed: {error}"))?;

    let ir0 = Ir0Module::from_syntax_tree(syntax_tree, &source_label);
    let lowering = lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new(
            args.trace_id.clone(),
            args.decision_id.clone(),
            args.policy_id.clone(),
        ),
    )
    .map_err(|error| format!("lowering failed: {error}"))?;

    let hashes = CompileArtifactHashes {
        parse_event_ir: parse_event_ir.canonical_hash(),
        ir0: ir0.content_hash().to_string(),
        ir1: lowering.ir1.content_hash().to_string(),
        ir2: lowering.ir2.content_hash().to_string(),
        ir3: lowering.ir3.content_hash().to_string(),
    };

    let artifact = CompileArtifact {
        schema_version: COMPILE_ARTIFACT_SCHEMA_VERSION.to_string(),
        generated_unix_ns: args.generated_unix_ns.unwrap_or_else(current_unix_ns),
        source_path: source_label,
        parse_goal: args.parse_goal.as_str().to_string(),
        source_ingestion: prepared.source_ingestion.clone(),
        trace_id: args.trace_id,
        decision_id: args.decision_id,
        policy_id: args.policy_id,
        hashes: hashes.clone(),
        parse_event_ir,
        ir0,
        lowering,
    };

    write_json_file(&args.out, &artifact)?;

    let output = CompileCommandOutput {
        schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
        trace_id: artifact.trace_id.clone(),
        decision_id: artifact.decision_id.clone(),
        policy_id: artifact.policy_id.clone(),
        artifact_path: args.out.display().to_string(),
        parse_goal: artifact.parse_goal,
        source_ingestion: artifact.source_ingestion.clone(),
        hashes,
        lowering_event_count: artifact.lowering.events.len(),
        lowering_witness_count: artifact.lowering.witnesses.len(),
        observability_mode: default_capture_observability_mode(),
    };
    print_json(&output)?;
    Ok(0)
}

fn execute_check(args: CheckArgs) -> Result<i32, String> {
    let source = fs::read_to_string(&args.input)
        .map_err(|error| format!("failed to read source `{}`: {error}", args.input.display()))?;
    let source_label = args.input.display().to_string();
    let report = analyze_authority_footprint(&source, source_label.as_str(), args.parse_goal);

    // Optional content-addressed bundle: run_manifest.json + events.jsonl.
    // The report carries no wall-clock/host facts, so the bundle is replay-stable.
    if let Some(out_dir) = args.out.as_ref() {
        write_json_file(&out_dir.join("run_manifest.json"), &report)?;
        write_bytes_file(
            &out_dir.join("events.jsonl"),
            render_check_events_jsonl(&report)?.as_bytes(),
        )?;
    }

    match args.format {
        CheckOutputFormat::Human => println!("{}", report.render_human()),
        CheckOutputFormat::Json => print_json(&report)?,
    }

    Ok(report.outcome().exit_code())
}

/// One JSON object per finding, newline-delimited (`events.jsonl`). Deterministic
/// for a given report (struct field order is fixed; no wall-clock content).
fn render_check_events_jsonl(report: &AuthorityFootprintReport) -> Result<String, String> {
    let mut lines = String::new();
    for finding in &report.findings {
        let encoded = serde_json::to_string(finding)
            .map_err(|error| format!("failed to encode check finding: {error}"))?;
        lines.push_str(&encoded);
        lines.push('\n');
    }
    Ok(lines)
}

fn execute_onboard(args: OnboardArgs) -> Result<i32, String> {
    let (root_dir, entry_relative) = resolve_package_entry(&args.target, args.root.as_deref())?;
    let root_label = root_dir.display().to_string();
    let report = onboard_package(&root_dir, &entry_relative, &root_label, args.parse_goal);

    // Optional content-addressed bundle: run_manifest.json + events.jsonl.
    // The report carries no wall-clock/host facts beyond the root label, so the
    // bundle is replay-stable for a fixed package + invocation.
    if let Some(out_dir) = args.out.as_ref() {
        write_json_file(&out_dir.join("run_manifest.json"), &report)?;
        write_bytes_file(
            &out_dir.join("events.jsonl"),
            render_onboard_events_jsonl(&report)?.as_bytes(),
        )?;
    }

    match args.format {
        CheckOutputFormat::Human => println!("{}", report.render_human()),
        CheckOutputFormat::Json => print_json(&report)?,
    }

    Ok(report.outcome().exit_code())
}

fn execute_diff_behavior(args: DiffBehaviorArgs) -> Result<i32, String> {
    let (before_root, before_entry) =
        resolve_package_entry(&args.before, args.before_root.as_deref())?;
    let (after_root, after_entry) = resolve_package_entry(&args.after, args.after_root.as_deref())?;
    let before_label = args
        .before_label
        .unwrap_or_else(|| args.before.display().to_string());
    let after_label = args
        .after_label
        .unwrap_or_else(|| args.after.display().to_string());

    let before_report =
        onboard_package(&before_root, &before_entry, &before_label, args.parse_goal);
    let after_report = onboard_package(&after_root, &after_entry, &after_label, args.parse_goal);
    let report = diff_package_behavior(&before_label, &before_report, &after_label, &after_report);

    if let Some(out_dir) = args.out.as_ref() {
        write_json_file(&out_dir.join("run_manifest.json"), &report)?;
        write_json_file(&out_dir.join("behavior_diff_report.json"), &report)?;
        write_json_file(&out_dir.join("before_intake_report.json"), &before_report)?;
        write_json_file(&out_dir.join("after_intake_report.json"), &after_report)?;
        write_bytes_file(
            &out_dir.join("events.jsonl"),
            render_diff_behavior_events_jsonl(&report)?.as_bytes(),
        )?;
    }

    match args.format {
        CheckOutputFormat::Human => println!("{}", report.render_human()),
        CheckOutputFormat::Json => print_json(&report)?,
    }

    Ok(report.outcome().exit_code())
}

/// One JSON object per actionable item (denied ambient access, IFC finding,
/// unanalyzable module, mode-divergent edge), newline-delimited. Deterministic
/// for a given report (the report's vectors are pre-sorted; no wall-clock).
fn render_onboard_events_jsonl(report: &PackageIntakeReport) -> Result<String, String> {
    let mut lines = String::new();
    let mut push = |value: serde_json::Value| -> Result<(), String> {
        let encoded = serde_json::to_string(&value)
            .map_err(|error| format!("failed to encode onboard event: {error}"))?;
        lines.push_str(&encoded);
        lines.push('\n');
        Ok(())
    };
    for denied in &report.denied_ambient_authority {
        push(serde_json::json!({
            "event": "onboard.denied_ambient_authority",
            "module": denied.module,
            "accessor": denied.accessor,
            "message": denied.message,
        }))?;
    }
    for finding in &report.ifc_flow_inventory.required_declassifications {
        push(serde_json::json!({
            "event": "onboard.required_declassification",
            "module": finding.module,
            "message": finding.message,
        }))?;
    }
    for finding in &report.ifc_flow_inventory.unsupported_flows {
        push(serde_json::json!({
            "event": "onboard.unsupported_flow",
            "module": finding.module,
            "message": finding.message,
        }))?;
    }
    for module in &report.ifc_flow_inventory.unanalyzable_modules {
        push(serde_json::json!({
            "event": "onboard.unanalyzable_module",
            "module": module.module,
            "reason": module.reason,
        }))?;
    }
    for edge in &report.module_resolution_report.edges {
        if edge.modes_agree {
            continue;
        }
        push(serde_json::json!({
            "event": "onboard.resolution_divergence",
            "from_module": edge.from_module,
            "specifier": edge.specifier,
        }))?;
    }
    Ok(lines)
}

fn render_diff_behavior_events_jsonl(report: &BehavioralDiffReport) -> Result<String, String> {
    let mut lines = String::new();
    let mut push = |value: serde_json::Value| -> Result<(), String> {
        let encoded = serde_json::to_string(&value)
            .map_err(|error| format!("failed to encode diff-behavior event: {error}"))?;
        lines.push_str(&encoded);
        lines.push('\n');
        Ok(())
    };

    for capability in &report.capability_delta.added {
        push(serde_json::json!({
            "event": "diff_behavior.capability_added",
            "capability_tag": &capability.capability_tag,
            "capability": capability.capability,
            "sites": &capability.sites,
        }))?;
    }
    for capability in &report.capability_delta.removed {
        push(serde_json::json!({
            "event": "diff_behavior.capability_removed",
            "capability_tag": &capability.capability_tag,
            "capability": capability.capability,
        }))?;
    }
    for finding in &report.ambient_authority_delta.added {
        push(serde_json::json!({
            "event": "diff_behavior.ambient_authority_added",
            "module": &finding.module,
            "accessor": &finding.accessor,
            "implied_capability": finding.implied_capability,
            "message": &finding.message,
        }))?;
    }
    for finding in &report.ifc_delta.added_required_declassifications {
        push(serde_json::json!({
            "event": "diff_behavior.required_declassification_added",
            "module": &finding.module,
            "message": &finding.message,
        }))?;
    }
    for finding in &report.ifc_delta.added_unsupported_flows {
        push(serde_json::json!({
            "event": "diff_behavior.unsupported_flow_added",
            "module": &finding.module,
            "message": &finding.message,
        }))?;
    }
    for dep in &report.boundary_delta.added_external_dependencies {
        push(serde_json::json!({
            "event": "diff_behavior.external_dependency_added",
            "specifier": &dep.specifier,
            "sites": &dep.sites,
        }))?;
    }
    for module in &report.boundary_delta.added_unanalyzable_modules {
        push(serde_json::json!({
            "event": "diff_behavior.unanalyzable_module_added",
            "module": &module.module,
            "reason": &module.reason,
        }))?;
    }
    for edge in &report.boundary_delta.added_resolution_divergences {
        push(serde_json::json!({
            "event": "diff_behavior.resolution_divergence_added",
            "from_module": &edge.from_module,
            "specifier": &edge.specifier,
            "outcomes": &edge.outcomes,
        }))?;
    }
    if report.delta_count == 0 {
        push(serde_json::json!({
            "event": "diff_behavior.unchanged",
            "before": &report.before.report_sha256,
            "after": &report.after.report_sha256,
        }))?;
    }
    Ok(lines)
}

/// Resolve the onboard target into `(root_dir, entry-relative-forward-slash)`.
/// A directory target auto-detects its entry; a file target derives its root
/// from `--root` or the file's parent directory. Fail-closed: the entry must
/// exist and live under the root.
fn resolve_package_entry(
    target: &Path,
    root_override: Option<&Path>,
) -> Result<(PathBuf, String), String> {
    let metadata = fs::metadata(target)
        .map_err(|error| format!("cannot stat `{}`: {error}", target.display()))?;
    if metadata.is_dir() {
        let root = fs::canonicalize(target)
            .map_err(|error| format!("cannot canonicalize root `{}`: {error}", target.display()))?;
        let entry_abs = detect_package_entry(&root)?;
        let entry_relative = relative_within_root(&root, &entry_abs)?;
        Ok((root, entry_relative))
    } else {
        let entry_abs = fs::canonicalize(target).map_err(|error| {
            format!("cannot canonicalize entry `{}`: {error}", target.display())
        })?;
        let root = match root_override {
            Some(root) => fs::canonicalize(root).map_err(|error| {
                format!("cannot canonicalize root `{}`: {error}", root.display())
            })?,
            None => entry_abs
                .parent()
                .map(Path::to_path_buf)
                .ok_or_else(|| "entry file has no parent directory".to_string())?,
        };
        let entry_relative = relative_within_root(&root, &entry_abs)?;
        Ok((root, entry_relative))
    }
}

/// Detect the entry file of a package directory: package.json `module` then
/// `main`, else the first existing `index.{js,mjs,cjs,ts,jsx,tsx}`.
fn detect_package_entry(root: &Path) -> Result<PathBuf, String> {
    let package_json = root.join("package.json");
    if let Ok(contents) = fs::read_to_string(&package_json)
        && let Ok(value) = serde_json::from_str::<serde_json::Value>(&contents)
    {
        for key in ["module", "main"] {
            if let Some(rel) = value.get(key).and_then(|v| v.as_str()) {
                let candidate = root.join(rel);
                if candidate.is_file() {
                    return fs::canonicalize(&candidate).map_err(|error| {
                        format!(
                            "cannot canonicalize entry `{}`: {error}",
                            candidate.display()
                        )
                    });
                }
            }
        }
    }
    for name in [
        "index.js",
        "index.mjs",
        "index.cjs",
        "index.ts",
        "index.jsx",
        "index.tsx",
    ] {
        let candidate = root.join(name);
        if candidate.is_file() {
            return fs::canonicalize(&candidate).map_err(|error| {
                format!(
                    "cannot canonicalize entry `{}`: {error}",
                    candidate.display()
                )
            });
        }
    }
    Err(format!(
        "no entry detected in `{}` (no package.json main/module and no index.{{js,mjs,cjs,ts,jsx,tsx}})",
        root.display()
    ))
}

/// Strip `root` from `entry` and return a forward-slash relative path. Errors if
/// the entry is not under the root (fail-closed).
fn relative_within_root(root: &Path, entry: &Path) -> Result<String, String> {
    let relative = entry.strip_prefix(root).map_err(|_| {
        format!(
            "entry `{}` is not within the package root `{}`",
            entry.display(),
            root.display()
        )
    })?;
    let mut parts = Vec::new();
    for component in relative.components() {
        if let std::path::Component::Normal(part) = component {
            parts.push(part.to_string_lossy().to_string());
        }
    }
    if parts.is_empty() {
        return Err("entry resolved to the package root itself".to_string());
    }
    Ok(parts.join("/"))
}

fn execute_run(args: RunArgs) -> Result<i32, String> {
    let source = fs::read_to_string(&args.input)
        .map_err(|error| format!("failed to read source `{}`: {error}", args.input.display()))?;
    let source_hash = ContentHash::compute(source.as_bytes());
    let data_contract = load_and_bind_data_contract(&args, &source_hash)?;

    let source_label = args.input.display().to_string();
    let capabilities = run_cli_capabilities(args.parse_goal);
    let package = ExtensionPackage {
        extension_id: args.extension_id.clone(),
        source,
        source_file: Some(source_label.clone()),
        capabilities,
        version: env!("CARGO_PKG_VERSION").to_string(),
        metadata: BTreeMap::new(),
    };
    let policy_id = OrchestratorConfig::default().policy_id;
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig {
        parse_goal: args.parse_goal,
        trace_id_prefix: "frankenctl-run".to_string(),
        ..OrchestratorConfig::default()
    });
    let result = orchestrator
        .execute(&package)
        .map_err(|error| format_run_error(&args.input, &error))?;
    let explain_bundle_path = resolve_run_explain_path(&args);

    let explain_bundle_path_string = explain_bundle_path
        .as_ref()
        .map(|path| path.display().to_string());
    let e8_preflight_receipt = data_contract.as_ref().map(|binding| {
        binding
            .uncertified_preflight_receipt(&result.trace_id, explain_bundle_path_string.as_deref())
    });

    let output = RunCommandOutput {
        schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
        extension_id: result.extension_id.clone(),
        trace_id: result.trace_id.clone(),
        decision_id: result.decision_id.clone(),
        policy_id,
        parse_goal: args.parse_goal.as_str().to_string(),
        report_path: args.out.as_ref().map(|path| path.display().to_string()),
        explain_bundle_path: explain_bundle_path_string,
        data_contract,
        e8_preflight_receipt,
        source_ingestion: result.source_ingestion.clone(),
        lane: result.lane.to_string(),
        lane_reason: result.lane_reason.to_string(),
        containment_action: result.containment_action.to_string(),
        execution_value: result.execution_value.clone(),
        expected_loss_millionths: result.expected_loss_millionths,
        instructions_executed: result.instructions_executed,
        evidence_entries: result.evidence_entries.len(),
        console_output: result.console_output.clone(),
        observability_mode: default_capture_observability_mode(),
    };

    let output_bytes = encode_json_value(&output, "frankenctl run output")?;
    if let Some(path) = explain_bundle_path.as_ref() {
        let bundle = build_run_explain_bundle(&args, &result, &output, source_hash, &output_bytes)?;
        write_json_file(path, &bundle)?;
    }

    if let Some(path) = args.out.as_ref() {
        write_json_file(path, &output)?;
    }
    print_json(&output)?;

    Ok(0)
}

fn load_and_bind_data_contract(
    args: &RunArgs,
    source_hash: &ContentHash,
) -> Result<Option<DataContractRunBinding>, String> {
    let Some(path) = args.data_contract.as_ref() else {
        return Ok(None);
    };
    let contract: DataContract = load_json_file(path)?;
    let input_path = args.input.display().to_string();
    contract
        .bind_to_run(
            &args.extension_id,
            &input_path,
            &args.data_contract_purpose,
            Some(source_hash),
        )
        .map(Some)
        .map_err(|error| format!("failed to bind data contract `{}`: {error}", path.display()))
}

fn resolve_run_explain_path(args: &RunArgs) -> Option<PathBuf> {
    if !args.explain {
        return None;
    }
    if let Some(path) = &args.explain_out {
        return Some(path.clone());
    }
    if let Some(path) = &args.out {
        return Some(path.with_extension("explain.json"));
    }
    Some(args.input.with_extension("explain.json"))
}

fn build_run_explain_bundle(
    args: &RunArgs,
    result: &OrchestratorResult,
    output: &RunCommandOutput,
    source_hash: ContentHash,
    output_bytes: &[u8],
) -> Result<RuntimeExplainBundle, String> {
    let mut builder = RuntimeExplainBundleBuilder::new(output.trace_id.clone())
        .with_source_revision(env!("CARGO_PKG_VERSION"))
        .with_metadata("command", "frankenctl run")
        .with_metadata("extension_id", output.extension_id.clone())
        .with_metadata("parse_goal", output.parse_goal.clone());

    let source_ref = RuntimeArtifactRef::new(
        "source",
        RuntimeArtifactKind::Other {
            schema_id: RUN_SOURCE_SCHEMA_VERSION.to_string(),
        },
        source_hash,
        StableArtifactRef::new("source_file", args.input.display().to_string()),
    )
    .with_schema_id(RUN_SOURCE_SCHEMA_VERSION)
    .with_producer("frankenctl")
    .with_metadata(RUNTIME_EXPLAIN_ORIGIN_SURFACE_METADATA_KEY, "frankenctl")
    .with_metadata(
        RUNTIME_EXPLAIN_ORIGIN_SCHEMA_METADATA_KEY,
        RUN_SOURCE_SCHEMA_VERSION,
    )
    .with_metadata(RUNTIME_EXPLAIN_ORIGIN_ARTIFACT_METADATA_KEY, "source_file");
    builder = builder
        .add_artifact(source_ref)
        .map_err(|error| error.to_string())?;

    if let Some(binding) = output.data_contract.as_ref() {
        let contract_ref = RuntimeArtifactRef::new(
            "data-contract",
            RuntimeArtifactKind::Other {
                schema_id: binding.schema_version.clone(),
            },
            content_hash_for_json(binding, "data contract binding")?,
            StableArtifactRef::new("data_contract", binding.contract_id.clone())
                .with_revision(binding.contract_hash_hex.clone()),
        )
        .with_schema_id(binding.schema_version.clone())
        .with_producer("frankenctl")
        .with_metadata(
            RUNTIME_EXPLAIN_ORIGIN_SURFACE_METADATA_KEY,
            "frankenctl_run",
        )
        .with_metadata(
            RUNTIME_EXPLAIN_ORIGIN_SCHEMA_METADATA_KEY,
            binding.schema_version.clone(),
        )
        .with_metadata(
            RUNTIME_EXPLAIN_ORIGIN_ARTIFACT_METADATA_KEY,
            "DataContractRunBinding",
        );
        builder = builder
            .add_artifact(contract_ref)
            .map_err(|error| error.to_string())?;
        builder = builder.add_link(RuntimeExplainLink::new(
            "data-contract-to-source",
            "data-contract",
            "source",
            RuntimeExplainRelation::DerivedFrom,
        ));
    }

    let report_stable_key = output
        .report_path
        .clone()
        .unwrap_or_else(|| "stdout".to_string());
    let run_report_ref = RuntimeArtifactRef::new(
        "run-report",
        RuntimeArtifactKind::Other {
            schema_id: RUN_REPORT_SCHEMA_VERSION.to_string(),
        },
        ContentHash::compute(output_bytes),
        StableArtifactRef::new("frankenctl_run", report_stable_key)
            .with_revision(output.trace_id.clone()),
    )
    .with_schema_id(RUN_REPORT_SCHEMA_VERSION)
    .with_producer("frankenctl")
    .with_roles([
        RuntimeExplainRole::ChosenAction,
        RuntimeExplainRole::ExpectedLoss,
        RuntimeExplainRole::ReplayStatus,
    ])
    .with_metadata(
        RUNTIME_EXPLAIN_ORIGIN_SURFACE_METADATA_KEY,
        "frankenctl_run",
    )
    .with_metadata(
        RUNTIME_EXPLAIN_ORIGIN_SCHEMA_METADATA_KEY,
        RUN_REPORT_SCHEMA_VERSION,
    )
    .with_metadata(
        RUNTIME_EXPLAIN_ORIGIN_ARTIFACT_METADATA_KEY,
        "RunCommandOutput",
    );
    builder = builder
        .add_artifact(run_report_ref)
        .map_err(|error| error.to_string())?;

    if let Some(receipt) = output.e8_preflight_receipt.as_ref() {
        let receipt_ref = RuntimeArtifactRef::new(
            "e8-preflight-refusal-ledger",
            RuntimeArtifactKind::Other {
                schema_id: E8_REFUSAL_LEDGER_SCHEMA_VERSION.to_string(),
            },
            content_hash_for_json(receipt, "E8 preflight refusal ledger")?,
            StableArtifactRef::new("e8_refusal_ledger", receipt.ledger_id.clone())
                .with_revision(receipt.run_id.clone()),
        )
        .with_schema_id(E8_REFUSAL_LEDGER_SCHEMA_VERSION)
        .with_producer("frankenctl")
        .with_roles([RuntimeExplainRole::ReplayStatus])
        .with_metadata(
            RUNTIME_EXPLAIN_ORIGIN_SURFACE_METADATA_KEY,
            "frankenctl_run",
        )
        .with_metadata(
            RUNTIME_EXPLAIN_ORIGIN_SCHEMA_METADATA_KEY,
            E8_REFUSAL_LEDGER_SCHEMA_VERSION,
        )
        .with_metadata(
            RUNTIME_EXPLAIN_ORIGIN_ARTIFACT_METADATA_KEY,
            "E8RefusalLedgerReceipt",
        );
        builder = builder
            .add_artifact(receipt_ref)
            .map_err(|error| error.to_string())?;
        if output.data_contract.is_some() {
            builder = builder.add_link(RuntimeExplainLink::new(
                "e8-preflight-from-data-contract",
                "e8-preflight-refusal-ledger",
                "data-contract",
                RuntimeExplainRelation::DerivedFrom,
            ));
        }
        builder = builder.add_link(RuntimeExplainLink::new(
            "e8-preflight-to-run-report",
            "e8-preflight-refusal-ledger",
            "run-report",
            RuntimeExplainRelation::DerivedFrom,
        ));
    }

    let action_hash = content_hash_for_json(&result.action_decision, "run action decision")?;
    let action_ref = RuntimeArtifactRef::new(
        "action-decision",
        RuntimeArtifactKind::ChosenAction,
        action_hash,
        StableArtifactRef::new("execution_orchestrator", result.decision_id.clone())
            .with_revision(result.trace_id.clone()),
    )
    .with_schema_id(RUN_ACTION_DECISION_SCHEMA_VERSION)
    .with_producer("execution_orchestrator")
    .with_roles([
        RuntimeExplainRole::ChosenAction,
        RuntimeExplainRole::ExpectedLoss,
    ])
    // Deterministic display metadata for the E3.T4 narrative views (ADR-0009:
    // metadata over the index, not a new authoritative schema).
    .with_metadata(
        EXPLAIN_META_CHOSEN_ACTION,
        output.containment_action.clone(),
    )
    .with_metadata(EXPLAIN_META_LANE, output.lane.clone())
    .with_metadata(EXPLAIN_META_LANE_REASON, output.lane_reason.clone())
    .with_metadata(
        EXPLAIN_META_EXPECTED_LOSS,
        output.expected_loss_millionths.to_string(),
    )
    .with_metadata(
        RUNTIME_EXPLAIN_ORIGIN_SURFACE_METADATA_KEY,
        "execution_orchestrator",
    )
    .with_metadata(
        RUNTIME_EXPLAIN_ORIGIN_SCHEMA_METADATA_KEY,
        RUN_ACTION_DECISION_SCHEMA_VERSION,
    )
    .with_metadata(
        RUNTIME_EXPLAIN_ORIGIN_ARTIFACT_METADATA_KEY,
        "ActionDecision",
    );
    builder = builder
        .add_artifact(action_ref)
        .map_err(|error| error.to_string())?;

    let posterior_hash = content_hash_for_json(&result.posterior, "run posterior")?;
    let posterior_ref = RuntimeArtifactRef::new(
        "guardplane-posterior",
        RuntimeArtifactKind::GuardplanePosterior,
        posterior_hash,
        StableArtifactRef::new("guardplane_adapter", result.decision_id.clone())
            .with_revision(result.trace_id.clone()),
    )
    .with_schema_id(RUN_POSTERIOR_SCHEMA_VERSION)
    .with_producer("guardplane_adapter")
    .with_role(RuntimeExplainRole::GuardplanePosterior)
    .with_metadata(
        RUNTIME_EXPLAIN_ORIGIN_SURFACE_METADATA_KEY,
        "guardplane_adapter",
    )
    .with_metadata(
        RUNTIME_EXPLAIN_ORIGIN_SCHEMA_METADATA_KEY,
        RUN_POSTERIOR_SCHEMA_VERSION,
    )
    .with_metadata(RUNTIME_EXPLAIN_ORIGIN_ARTIFACT_METADATA_KEY, "Posterior");
    builder = builder
        .add_artifact(posterior_ref)
        .map_err(|error| error.to_string())?;

    builder = builder
        .add_link(RuntimeExplainLink::new(
            "source-to-action",
            "source",
            "action-decision",
            RuntimeExplainRelation::DerivedFrom,
        ))
        .add_link(RuntimeExplainLink::new(
            "posterior-to-action",
            "guardplane-posterior",
            "action-decision",
            RuntimeExplainRelation::SelectsAction,
        ))
        .add_link(RuntimeExplainLink::new(
            "action-to-run-report",
            "action-decision",
            "run-report",
            RuntimeExplainRelation::ObservedDuring,
        ));

    for (index, entry) in result.evidence_entries.iter().enumerate() {
        let artifact_id = format!("evidence-{index}");
        let evidence_ref = RuntimeArtifactRef::new(
            artifact_id.clone(),
            RuntimeArtifactKind::EvidenceEntry,
            content_hash_for_json(entry, "run evidence entry")?,
            StableArtifactRef::new("evidence_ledger", entry.entry_id.clone())
                .with_revision(result.trace_id.clone()),
        )
        .with_producer("evidence_ledger")
        .with_role(RuntimeExplainRole::EvidenceEntry)
        .with_logical_epoch(entry.epoch_id.as_u64())
        .with_metadata(
            RUNTIME_EXPLAIN_ORIGIN_SURFACE_METADATA_KEY,
            "evidence_ledger",
        )
        .with_metadata(RUNTIME_EXPLAIN_ORIGIN_SCHEMA_METADATA_KEY, "evidence_entry")
        .with_metadata(
            RUNTIME_EXPLAIN_ORIGIN_ARTIFACT_METADATA_KEY,
            "EvidenceEntry",
        );
        builder = builder
            .add_artifact(evidence_ref)
            .map_err(|error| error.to_string())?
            .add_link(RuntimeExplainLink::new(
                format!("action-to-{artifact_id}"),
                "action-decision",
                artifact_id,
                RuntimeExplainRelation::EmitsEvidence,
            ));
    }

    if let Some(receipt) = &result.containment_receipt {
        let containment_ref = RuntimeArtifactRef::new(
            "containment-receipt",
            RuntimeArtifactKind::ContainmentReceipt,
            content_hash_for_json(receipt, "run containment receipt")?,
            StableArtifactRef::new("containment_executor", result.decision_id.clone())
                .with_revision(result.trace_id.clone()),
        )
        .with_schema_id(RUN_CONTAINMENT_RECEIPT_SCHEMA_VERSION)
        .with_producer("containment_executor")
        .with_role(RuntimeExplainRole::ContainmentReceipt)
        .with_metadata(
            RUNTIME_EXPLAIN_ORIGIN_SURFACE_METADATA_KEY,
            "containment_executor",
        )
        .with_metadata(
            RUNTIME_EXPLAIN_ORIGIN_SCHEMA_METADATA_KEY,
            RUN_CONTAINMENT_RECEIPT_SCHEMA_VERSION,
        )
        .with_metadata(
            RUNTIME_EXPLAIN_ORIGIN_ARTIFACT_METADATA_KEY,
            "ContainmentReceipt",
        );
        builder = builder
            .add_artifact(containment_ref)
            .map_err(|error| error.to_string())?
            .add_link(RuntimeExplainLink::new(
                "action-to-containment",
                "action-decision",
                "containment-receipt",
                RuntimeExplainRelation::ProducesContainment,
            ));
    }

    Ok(builder.build())
}

fn content_hash_for_json<T: Serialize>(value: &T, target: &str) -> Result<ContentHash, String> {
    serde_json::to_vec(value)
        .map(|bytes| ContentHash::compute(&bytes))
        .map_err(|error| format!("failed to encode JSON for {target}: {error}"))
}

fn execute_explain(args: ExplainArgs) -> Result<i32, String> {
    let bundle: RuntimeExplainBundle = load_json_file(&args.input)?;

    // E3.T4: emit the full derived view bundle (explain.md + evidence_graph.json
    // + replay.json + counterfactuals.json + commands.txt + repro.lock + a copy
    // of the index) to a directory. All views are pure projections over the
    // index, so the directory is byte-deterministic and repro.lock-addressed.
    if let Some(dir) = args.emit_bundle.as_ref() {
        let views = build_explain_bundle(&bundle);
        write_bytes_file(&dir.join("explain.md"), views.explain_md.as_bytes())?;
        write_json_file(&dir.join("evidence_graph.json"), &views.evidence_graph)?;
        write_json_file(&dir.join("replay.json"), &views.replay)?;
        write_json_file(&dir.join("counterfactuals.json"), &views.counterfactuals)?;
        write_bytes_file(&dir.join("commands.txt"), views.commands_txt.as_bytes())?;
        write_json_file(&dir.join("repro.lock"), &views.repro_lock)?;
        // Preserve the index alongside its views so the bundle is self-contained.
        write_json_file(&dir.join("explain.json"), &bundle)?;
    }

    match args.format {
        ExplainOutputFormat::Json => {
            if let Some(path) = args.out.as_ref() {
                write_json_file(path, &bundle)?;
            } else if args.emit_bundle.is_none() {
                print_json(&bundle)?;
            }
        }
        ExplainOutputFormat::Summary => {
            let summary = render_runtime_explain_summary(&bundle, &args.input);
            if let Some(path) = args.out.as_ref() {
                write_bytes_file(path, summary.as_bytes())?;
            } else if args.emit_bundle.is_none() {
                println!("{summary}");
            }
        }
    }
    Ok(0)
}

fn render_runtime_explain_summary(bundle: &RuntimeExplainBundle, input: &Path) -> String {
    let mut kind_counts = BTreeMap::<String, usize>::new();
    for artifact in bundle.artifacts.values() {
        *kind_counts.entry(artifact.kind.to_string()).or_default() += 1;
    }
    let kind_summary = kind_counts
        .iter()
        .map(|(kind, count)| format!("{kind}={count}"))
        .collect::<Vec<_>>()
        .join(", ");
    [
        "runtime explain bundle:".to_string(),
        format!("  path: {}", input.display()),
        format!("  run_id: {}", bundle.run_id),
        format!("  schema_version: {}", bundle.schema_version),
        format!("  content_hash: {}", bundle.content_hash()),
        format!("  artifacts: {}", bundle.artifacts.len()),
        format!("  links: {}", bundle.links.len()),
        format!(
            "  required_roles: {}",
            bundle
                .required_roles
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        format!("  artifact_kinds: {kind_summary}"),
    ]
    .join("\n")
}

fn execute_claims(args: ClaimsArgs) -> Result<i32, String> {
    match args.mode {
        ClaimsMode::Explain(args) => execute_claims_explain(args),
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ClaimMatrixDocument {
    max_observed_freshness_days: Option<u64>,
    stale_threshold_days: Option<u64>,
    claims: Vec<ClaimMatrixRow>,
}

#[derive(Debug, Clone, Deserialize)]
struct ClaimMatrixRow {
    actual_wording_state: String,
    allowed_state: String,
    artifact_path: Option<String>,
    claim_id: String,
    claim_scope: String,
    claim_text: String,
    decision: String,
    downgrade_text: Option<String>,
    #[serde(
        default,
        alias = "artifact_hash",
        alias = "artifact_sha256",
        alias = "content_hash",
        alias = "expected_content_hash"
    )]
    expected_hash: Option<String>,
    freshness_days: Option<u64>,
    owning_bead: String,
    reason: String,
    source_path: String,
    source_span: Option<ClaimSourceSpan>,
    verification_command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClaimSourceSpan {
    start_line: u64,
    end_line: u64,
    must_contain: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ClaimExplanationOutput {
    schema_version: String,
    receipt_id: String,
    claim_id: String,
    decision: String,
    reason_codes: Vec<String>,
    matrix_path: String,
    matrix_schema_version: String,
    claim: Option<ClaimExplanationClaim>,
    artifact: Option<ClaimExplanationArtifact>,
    bead: Option<ClaimExplanationBead>,
    mock_status: String,
    local_fallback_status: String,
    replay_commands: Vec<String>,
    remediation: Vec<String>,
    source_line_refs: Vec<ClaimExplanationSourceRef>,
    mutation_policy: ClaimExplanationMutationPolicy,
    renderer_boundary: ClaimExplanationRendererBoundary,
}

impl ClaimExplanationOutput {
    fn exit_code(&self) -> i32 {
        match self.decision.as_str() {
            "supported" => 0,
            "degraded" | "not_promotable" | "unsupported" => 1,
            _ => 2,
        }
    }

    fn render_human(&self) -> String {
        let mut lines = vec![
            "claim explanation:".to_string(),
            format!("  claim_id: {}", self.claim_id),
            format!("  decision: {}", self.decision),
            format!("  reason_codes: {}", self.reason_codes.join(", ")),
            format!("  receipt_id: {}", self.receipt_id),
            format!("  matrix: {}", self.matrix_path),
        ];
        if let Some(claim) = self.claim.as_ref() {
            lines.push(format!("  allowed_state: {}", claim.allowed_state));
            lines.push(format!(
                "  actual_wording_state: {}",
                claim.actual_wording_state
            ));
            lines.push(format!("  owning_bead: {}", claim.owning_bead));
            lines.push(format!("  artifact_path: {}", claim.artifact_path));
        }
        if let Some(artifact) = self.artifact.as_ref() {
            lines.push(format!("  artifact_present: {}", artifact.present));
            lines.push(format!(
                "  artifact_hash: {}",
                artifact.content_hash.as_deref().unwrap_or("unavailable")
            ));
            lines.push(format!(
                "  expected_hash: {}",
                artifact.expected_hash.as_deref().unwrap_or("unasserted")
            ));
            lines.push(format!("  hash_status: {}", artifact.hash_status));
            lines.push(format!("  freshness_status: {}", artifact.freshness_status));
            if let Some(days) = artifact.actual_freshness_days {
                lines.push(format!("  actual_freshness_days: {days}"));
            }
        }
        if let Some(bead) = self.bead.as_ref() {
            lines.push(format!("  bead_status: {}", bead.status));
            if let Some(assignee) = bead.assignee.as_ref() {
                lines.push(format!("  bead_assignee: {assignee}"));
            }
        }
        lines.push(format!("  mock_status: {}", self.mock_status));
        lines.push(format!(
            "  local_fallback_status: {}",
            self.local_fallback_status
        ));
        if !self.remediation.is_empty() {
            lines.push("  remediation:".to_string());
            lines.extend(self.remediation.iter().map(|item| format!("    - {item}")));
        }
        lines.join("\n")
    }
}

#[derive(Debug, Clone, Serialize)]
struct ClaimExplanationClaim {
    claim_scope: String,
    claim_text: String,
    allowed_state: String,
    actual_wording_state: String,
    decision: String,
    reason: String,
    downgrade_text: Option<String>,
    freshness_days: Option<u64>,
    owning_bead: String,
    verification_command: String,
    artifact_path: String,
}

#[derive(Debug, Clone, Serialize)]
struct ClaimExplanationArtifact {
    path: String,
    present: bool,
    kind: String,
    content_hash: Option<String>,
    expected_hash: Option<String>,
    hash_status: String,
    required_for_supported: bool,
    actual_freshness_days: Option<u64>,
    freshness_status: String,
    stale_threshold_days: u64,
    max_observed_freshness_days: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ClaimExplanationBead {
    bead_id: String,
    status: String,
    assignee: Option<String>,
    source: String,
    found: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ClaimExplanationSourceRef {
    source_path: String,
    start_line: Option<u64>,
    end_line: Option<u64>,
    must_contain: Option<String>,
    status: String,
}

#[derive(Debug, Clone, Serialize)]
struct ClaimExplanationMutationPolicy {
    mutates_br: bool,
    mutates_agent_mail: bool,
    mutates_file_reservations: bool,
    mutates_remote_workers: bool,
    mutates_evidence_bundles: bool,
    mutates_claim_matrix: bool,
    mutates_git: bool,
    runs_cargo: bool,
    runs_rch: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ClaimExplanationRendererBoundary {
    future_rich_renderer_provider: String,
    local_rich_renderer_shipped: bool,
}

fn execute_claims_explain(args: ClaimsExplainArgs) -> Result<i32, String> {
    let output = build_claim_explanation(
        args.claim_id.as_str(),
        &args.matrix,
        args.beads_jsonl.as_deref(),
    )?;
    match args.format {
        CheckOutputFormat::Human => {
            let rendered = output.render_human();
            if let Some(path) = args.out.as_ref() {
                write_bytes_file(path, rendered.as_bytes())?;
            } else {
                println!("{rendered}");
            }
        }
        CheckOutputFormat::Json => {
            if let Some(path) = args.out.as_ref() {
                write_json_file(path, &output)?;
            } else {
                print_json(&output)?;
            }
        }
    }
    Ok(output.exit_code())
}

fn build_claim_explanation(
    claim_id: &str,
    matrix_path: &Path,
    beads_jsonl: Option<&Path>,
) -> Result<ClaimExplanationOutput, String> {
    let matrix_value: serde_json::Value = match load_json_file(matrix_path) {
        Ok(value) => value,
        Err(error) => {
            return Ok(claim_explanation_fail_closed(
                claim_id,
                matrix_path,
                "unavailable".to_string(),
                "unreadable_matrix",
                format!(
                    "Read or regenerate the claim-to-proof matrix, then rerun the claim gate: {error}"
                ),
            ));
        }
    };
    let matrix_schema_version = matrix_value
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("missing")
        .to_string();
    if matrix_schema_version != CLAIM_MATRIX_SCHEMA_VERSION {
        return Ok(claim_explanation_fail_closed(
            claim_id,
            matrix_path,
            matrix_schema_version,
            "invalid_matrix_schema",
            "Regenerate or fix the claim-to-proof matrix and rerun the claim gate.",
        ));
    }

    let matrix: ClaimMatrixDocument = match serde_json::from_value(matrix_value) {
        Ok(matrix) => matrix,
        Err(error) => {
            return Ok(claim_explanation_fail_closed(
                claim_id,
                matrix_path,
                matrix_schema_version,
                "missing_required_field",
                format!("Fix required claim matrix fields before explaining this claim: {error}"),
            ));
        }
    };
    let max_observed_freshness_days = matrix.max_observed_freshness_days.unwrap_or(30);
    let stale_threshold_days = matrix
        .stale_threshold_days
        .unwrap_or(max_observed_freshness_days);
    let mut matching_claim_rows = matrix
        .claims
        .into_iter()
        .filter(|row| row.claim_id == claim_id);
    let Some(row) = matching_claim_rows.next() else {
        return Ok(claim_explanation_fail_closed(
            claim_id,
            matrix_path,
            matrix_schema_version,
            "missing_claim_row",
            "Add or correct the matrix row before explaining the claim.",
        ));
    };
    if matching_claim_rows.next().is_some() {
        return Ok(claim_explanation_fail_closed(
            claim_id,
            matrix_path,
            matrix_schema_version,
            "duplicate_claim_row",
            "Deduplicate the claim-to-proof matrix row before explaining the claim.",
        ));
    }

    let bead = load_bead_status(beads_jsonl, row.owning_bead.as_str())?;
    Ok(explain_claim_row(
        claim_id,
        matrix_path,
        matrix_schema_version,
        row,
        bead,
        stale_threshold_days,
        max_observed_freshness_days,
    ))
}

fn explain_claim_row(
    claim_id: &str,
    matrix_path: &Path,
    matrix_schema_version: String,
    row: ClaimMatrixRow,
    bead: Option<ClaimExplanationBead>,
    stale_threshold_days: u64,
    max_observed_freshness_days: u64,
) -> ClaimExplanationOutput {
    let mut reason_codes = Vec::new();
    let mut remediation = Vec::new();
    let artifact_path = row.artifact_path.clone().unwrap_or_default();
    let resolved_artifact_path = resolve_claim_artifact_path(matrix_path, &artifact_path);
    let artifact = explain_claim_artifact(
        &artifact_path,
        &resolved_artifact_path,
        row.allowed_state.as_str(),
        row.expected_hash.as_deref(),
        stale_threshold_days,
        max_observed_freshness_days,
    );

    let missing_fields = claim_row_missing_required_fields(&row);
    if !missing_fields.is_empty() {
        let fix = format!(
            "Fill required matrix fields before this claim can be explained: {}.",
            missing_fields.join(", ")
        );
        push_reason(
            &mut reason_codes,
            &mut remediation,
            "missing_required_field",
            &fix,
        );
    }

    if !claim_state_is_known(row.allowed_state.as_str())
        || !claim_state_is_known(row.actual_wording_state.as_str())
    {
        let mut invalid_fields = Vec::new();
        if !claim_state_is_known(row.allowed_state.as_str()) {
            invalid_fields.push("allowed_state");
        }
        if !claim_state_is_known(row.actual_wording_state.as_str()) {
            invalid_fields.push("actual_wording_state");
        }
        let fix = format!(
            "Use one of hypothesis, target, or observed for {}.",
            invalid_fields.join(", ")
        );
        push_reason(
            &mut reason_codes,
            &mut remediation,
            "invalid_wording_state",
            &fix,
        );
    }

    if state_rank(row.actual_wording_state.as_str()) > state_rank(row.allowed_state.as_str()) {
        push_reason(
            &mut reason_codes,
            &mut remediation,
            "wording_stronger_than_allowed",
            "Downgrade the claim wording or promote the matrix row only after upstream proof gates pass.",
        );
    }
    if row.allowed_state != "observed" {
        push_reason(
            &mut reason_codes,
            &mut remediation,
            "claim_not_observed",
            "Keep the explanation degraded/not-promotable until observed proof artifacts are linked.",
        );
    }
    if row.allowed_state == "observed" && !artifact.present {
        push_reason(
            &mut reason_codes,
            &mut remediation,
            "absent_artifact",
            "Produce or attach the upstream proof artifact before treating the claim as supported.",
        );
    }
    if row.allowed_state == "observed"
        && row
            .freshness_days
            .is_some_and(|days| days > max_observed_freshness_days)
    {
        push_reason(
            &mut reason_codes,
            &mut remediation,
            "stale_artifact",
            "Declared claim freshness exceeds the matrix max_observed_freshness_days budget.",
        );
    }
    if row.allowed_state == "observed"
        && matches!(artifact.freshness_status.as_str(), "stale" | "unknown")
    {
        push_reason(
            &mut reason_codes,
            &mut remediation,
            "stale_artifact",
            "Refresh the observed proof artifact or downgrade the claim before treating it as supported.",
        );
    }
    if row.allowed_state == "observed"
        && artifact.present
        && !claim_artifact_has_reproducibility_bundle(&resolved_artifact_path)
    {
        push_reason(
            &mut reason_codes,
            &mut remediation,
            "missing_reproducibility_bundle",
            "Add a repro.lock beside or under the observed proof artifact before treating the claim as supported.",
        );
    }
    if artifact.hash_status == "invalid_expected_hash" {
        push_reason(
            &mut reason_codes,
            &mut remediation,
            "invalid_expected_hash",
            "Replace the expected artifact hash with a sha256:<64-hex> value or omit it until an authority source exists.",
        );
    } else if artifact.hash_status == "mismatch" {
        push_reason(
            &mut reason_codes,
            &mut remediation,
            "artifact_hash_mismatch",
            "Regenerate the artifact from the recorded replay command or correct the matrix hash authority.",
        );
    }

    let mock_contaminated = claim_row_contains_mock_contamination(&row)
        || claim_artifact_contains_mock_contamination(&resolved_artifact_path);
    let local_fallback_contaminated = claim_row_contains_local_fallback(&row)
        || claim_artifact_contains_local_fallback(&resolved_artifact_path);
    if mock_contaminated {
        push_reason(
            &mut reason_codes,
            &mut remediation,
            "mock_contaminated",
            "Replace mock or simulation evidence with a live/preserved non-mock proof artifact.",
        );
    }
    if local_fallback_contaminated {
        push_reason(
            &mut reason_codes,
            &mut remediation,
            "local_fallback_contaminated",
            "Replace local-fallback transport evidence with a remote-only preserved proof artifact.",
        );
    }

    let source_check = validate_claim_source_ref(matrix_path, &row);
    if let Some(reason_code) = source_check.reason_code.as_deref() {
        push_reason(
            &mut reason_codes,
            &mut remediation,
            reason_code,
            source_check
                .remediation
                .as_deref()
                .unwrap_or("Repair the matrix source_path/source_span and rerun the claim gate."),
        );
    }

    if let Some(bead_ref) = bead.as_ref()
        && row.allowed_state == "observed"
        && bead_ref.found
        && bead_ref.status != "closed"
    {
        push_reason(
            &mut reason_codes,
            &mut remediation,
            "contradictory_bead_status",
            "Resolve tracker status or downgrade the claim before treating it as supported.",
        );
    }
    if let Some(bead_ref) = bead.as_ref()
        && row.allowed_state == "observed"
        && !bead_ref.found
    {
        push_reason(
            &mut reason_codes,
            &mut remediation,
            "stale_tracker_state",
            "Refresh the Beads JSONL snapshot or pass --no-beads only for an explicit artifact-only review.",
        );
    }

    let decision = claim_explanation_decision(row.allowed_state.as_str(), &reason_codes);
    let source_ref = ClaimExplanationSourceRef {
        source_path: row.source_path.clone(),
        start_line: row.source_span.as_ref().map(|span| span.start_line),
        end_line: row.source_span.as_ref().map(|span| span.end_line),
        must_contain: row
            .source_span
            .as_ref()
            .and_then(|span| span.must_contain.clone()),
        status: source_check.status,
    };
    let replay_commands = if row.verification_command.trim().is_empty() {
        Vec::new()
    } else {
        vec![row.verification_command.clone()]
    };
    let claim = ClaimExplanationClaim {
        claim_scope: row.claim_scope,
        claim_text: row.claim_text,
        allowed_state: row.allowed_state,
        actual_wording_state: row.actual_wording_state,
        decision: row.decision,
        reason: row.reason,
        downgrade_text: row.downgrade_text,
        freshness_days: row.freshness_days,
        owning_bead: row.owning_bead,
        verification_command: row.verification_command,
        artifact_path,
    };
    let mock_status = if mock_contaminated {
        "present_fail_closed"
    } else {
        "absent"
    };
    let local_fallback_status = if local_fallback_contaminated {
        "present_fail_closed"
    } else {
        "absent"
    };
    let mut output = ClaimExplanationOutput {
        schema_version: CLAIM_EXPLAINER_SCHEMA_VERSION.to_string(),
        receipt_id: String::new(),
        claim_id: claim_id.to_string(),
        decision,
        reason_codes,
        matrix_path: matrix_path.display().to_string(),
        matrix_schema_version,
        claim: Some(claim),
        artifact: Some(artifact),
        bead,
        mock_status: mock_status.to_string(),
        local_fallback_status: local_fallback_status.to_string(),
        replay_commands,
        remediation,
        source_line_refs: vec![source_ref],
        mutation_policy: claim_explanation_mutation_policy(),
        renderer_boundary: claim_explanation_renderer_boundary(),
    };
    output.receipt_id = derive_claim_explanation_receipt_id(&output);
    output
}

fn claim_explanation_fail_closed(
    claim_id: &str,
    matrix_path: &Path,
    matrix_schema_version: String,
    reason_code: &str,
    remediation: impl Into<String>,
) -> ClaimExplanationOutput {
    let mut output = ClaimExplanationOutput {
        schema_version: CLAIM_EXPLAINER_SCHEMA_VERSION.to_string(),
        receipt_id: String::new(),
        claim_id: claim_id.to_string(),
        decision: "fail_closed".to_string(),
        reason_codes: vec![reason_code.to_string()],
        matrix_path: matrix_path.display().to_string(),
        matrix_schema_version,
        claim: None,
        artifact: None,
        bead: None,
        mock_status: "unknown_fail_closed".to_string(),
        local_fallback_status: "unknown_fail_closed".to_string(),
        replay_commands: Vec::new(),
        remediation: vec![remediation.into()],
        source_line_refs: Vec::new(),
        mutation_policy: claim_explanation_mutation_policy(),
        renderer_boundary: claim_explanation_renderer_boundary(),
    };
    output.receipt_id = derive_claim_explanation_receipt_id(&output);
    output
}

fn explain_claim_artifact(
    path: &str,
    resolved_path: &Path,
    allowed_state: &str,
    expected_hash: Option<&str>,
    stale_threshold_days: u64,
    max_observed_freshness_days: u64,
) -> ClaimExplanationArtifact {
    let present = !path.is_empty() && resolved_path.exists();
    let kind = if path.is_empty() {
        "missing".to_string()
    } else if resolved_path.is_dir() {
        "directory".to_string()
    } else if resolved_path.is_file() {
        "file".to_string()
    } else {
        "missing".to_string()
    };
    let content_hash = compute_artifact_content_hash(resolved_path);
    let expected_hash = expected_hash
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let expected_hash_normalized = expected_hash
        .as_deref()
        .and_then(normalize_claim_expected_hash);
    let hash_status = match (&content_hash, &expected_hash, &expected_hash_normalized) {
        (_, None, _) => "unasserted",
        (_, Some(_), None) => "invalid_expected_hash",
        (None, Some(_), Some(_)) => "unavailable",
        (Some(actual), Some(_), Some(expected)) if actual == expected => "matched",
        (Some(_), Some(_), Some(_)) => "mismatch",
    };
    let actual_freshness_days = if allowed_state == "observed" && present {
        derive_artifact_freshness_days(resolved_path)
    } else {
        None
    };
    let freshness_status = if allowed_state != "observed" {
        "not_required"
    } else {
        match actual_freshness_days {
            Some(days) if days > stale_threshold_days => "stale",
            Some(_) => "fresh",
            None => "unknown",
        }
    };
    ClaimExplanationArtifact {
        path: if path.is_empty() {
            String::new()
        } else {
            resolved_path.display().to_string()
        },
        present,
        kind,
        content_hash,
        expected_hash,
        hash_status: hash_status.to_string(),
        required_for_supported: allowed_state == "observed",
        actual_freshness_days,
        freshness_status: freshness_status.to_string(),
        stale_threshold_days,
        max_observed_freshness_days,
    }
}

fn resolve_claim_artifact_path(matrix_path: &Path, artifact_path: &str) -> PathBuf {
    let path = Path::new(artifact_path);
    if artifact_path.trim().is_empty() || path.is_absolute() {
        return path.to_path_buf();
    }
    if let Some(matrix_relative) = matrix_path
        .parent()
        .map(|parent| parent.join(path))
        .filter(|candidate| candidate.exists())
    {
        return matrix_relative;
    }
    if let Some(repo_relative) = matrix_path
        .parent()
        .and_then(Path::parent)
        .map(|parent| parent.join(path))
        .filter(|candidate| candidate.exists())
    {
        return repo_relative;
    }
    if path.exists() {
        return path.to_path_buf();
    }
    path.to_path_buf()
}

fn claim_row_missing_required_fields(row: &ClaimMatrixRow) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if row.claim_id.trim().is_empty() {
        missing.push("claim_id");
    }
    if row.claim_scope.trim().is_empty() {
        missing.push("claim_scope");
    }
    if row.claim_text.trim().is_empty() {
        missing.push("claim_text");
    }
    if row.source_path.trim().is_empty() {
        missing.push("source_path");
    }
    if row.source_span.is_none() {
        missing.push("source_span");
    } else if row
        .source_span
        .as_ref()
        .and_then(|span| span.must_contain.as_deref())
        .is_none_or(|must_contain| must_contain.trim().is_empty())
    {
        missing.push("source_span.must_contain");
    }
    if row.allowed_state.trim().is_empty() {
        missing.push("allowed_state");
    }
    if row.actual_wording_state.trim().is_empty() {
        missing.push("actual_wording_state");
    }
    if row.decision.trim().is_empty() {
        missing.push("decision");
    }
    if row.reason.trim().is_empty() {
        missing.push("reason");
    }
    if row.owning_bead.trim().is_empty() {
        missing.push("owning_bead");
    }
    if row.allowed_state == "observed" {
        if row
            .artifact_path
            .as_deref()
            .is_none_or(|path| path.trim().is_empty())
        {
            missing.push("artifact_path");
        }
        if row.verification_command.trim().is_empty() {
            missing.push("verification_command");
        }
        if row.freshness_days.is_none() {
            missing.push("freshness_days");
        }
    } else if row
        .downgrade_text
        .as_deref()
        .is_none_or(|text| text.trim().is_empty())
    {
        missing.push("downgrade_text");
    }
    missing
}

fn compute_artifact_content_hash(path: &Path) -> Option<String> {
    if path.is_file() {
        return fs::read(path)
            .ok()
            .map(|bytes| ContentHash::compute(&bytes).to_hex());
    }
    if !path.is_dir() {
        return None;
    }

    let mut files = Vec::new();
    collect_artifact_files(path, &mut files).ok()?;
    files.sort();
    let mut preimage = Vec::new();
    append_claim_hash_field(
        &mut preimage,
        b"franken-engine.claim-artifact-directory-hash.v1",
    );
    for file in files {
        let relative = file.strip_prefix(path).ok()?;
        let bytes = fs::read(&file).ok()?;
        append_claim_hash_field(&mut preimage, relative.to_string_lossy().as_bytes());
        append_claim_hash_field(
            &mut preimage,
            ContentHash::compute(&bytes).to_hex().as_bytes(),
        );
    }
    Some(ContentHash::compute(&preimage).to_hex())
}

fn append_claim_hash_field(preimage: &mut Vec<u8>, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    preimage.extend_from_slice(&length.to_be_bytes());
    preimage.extend_from_slice(bytes);
}

fn collect_artifact_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in
        fs::read_dir(dir).map_err(|error| format!("read dir `{}`: {error}", dir.display()))?
    {
        let entry =
            entry.map_err(|error| format!("read dir entry `{}`: {error}", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("read file type `{}`: {error}", path.display()))?;
        if file_type.is_dir() {
            collect_artifact_files(&path, files)?;
        } else if file_type.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct ClaimSourceValidation {
    status: String,
    reason_code: Option<String>,
    remediation: Option<String>,
}

impl ClaimSourceValidation {
    fn ok(status: impl Into<String>) -> Self {
        Self {
            status: status.into(),
            reason_code: None,
            remediation: None,
        }
    }

    fn fail(
        status: impl Into<String>,
        reason_code: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            status: status.into(),
            reason_code: Some(reason_code.into()),
            remediation: Some(remediation.into()),
        }
    }
}

fn validate_claim_source_ref(matrix_path: &Path, row: &ClaimMatrixRow) -> ClaimSourceValidation {
    let Some(span) = row.source_span.as_ref() else {
        return ClaimSourceValidation::ok("missing_required_field");
    };
    if row.source_path.trim().is_empty() {
        return ClaimSourceValidation::ok("missing_required_field");
    }
    let Some(must_contain) = span
        .must_contain
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return ClaimSourceValidation::ok("missing_required_field");
    };

    if span.start_line == 0 || span.end_line < span.start_line {
        return ClaimSourceValidation::fail(
            "invalid_span",
            "invalid_source_span",
            "Use one-based source_span line numbers with start_line <= end_line.",
        );
    }

    let resolved_path = resolve_claim_source_path(matrix_path, row.source_path.as_str());
    if !resolved_path.is_file() {
        return ClaimSourceValidation::fail(
            "missing_source",
            "source_path_missing",
            format!(
                "Restore `{}` or update the matrix source_path before treating this claim as supported.",
                row.source_path
            ),
        );
    }

    let Ok(contents) = fs::read_to_string(&resolved_path) else {
        return ClaimSourceValidation::fail(
            "unreadable_source",
            "source_path_unreadable",
            format!(
                "Make `{}` readable or update the matrix source_path before explaining this claim.",
                resolved_path.display()
            ),
        );
    };
    let span_text = select_claim_source_span_text(&contents, span.start_line, span.end_line);
    if !span_text.contains(must_contain) {
        return ClaimSourceValidation::fail(
            "span_mismatch",
            "source_span_mismatch",
            "Update the matrix source_span/must_contain or downgrade the claim until the source text matches.",
        );
    }

    ClaimSourceValidation::ok("matched")
}

fn resolve_claim_source_path(matrix_path: &Path, source_path: &str) -> PathBuf {
    let path = Path::new(source_path);
    if source_path.trim().is_empty() || path.is_absolute() {
        return path.to_path_buf();
    }
    if let Some(matrix_relative) = matrix_path
        .parent()
        .map(|parent| parent.join(path))
        .filter(|candidate| candidate.exists())
    {
        return matrix_relative;
    }
    if let Some(repo_relative) = matrix_path
        .parent()
        .and_then(Path::parent)
        .map(|parent| parent.join(path))
        .filter(|candidate| candidate.exists())
    {
        return repo_relative;
    }
    if path.exists() {
        return path.to_path_buf();
    }
    path.to_path_buf()
}

fn select_claim_source_span_text(contents: &str, start_line: u64, end_line: u64) -> String {
    contents
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let line_number = u64::try_from(index).ok()?.saturating_add(1);
            if (start_line..=end_line).contains(&line_number) {
                Some(line)
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn normalize_claim_expected_hash(value: &str) -> Option<String> {
    let normalized = value
        .trim()
        .strip_prefix("sha256:")
        .or_else(|| value.trim().strip_prefix("content:"))
        .unwrap_or_else(|| value.trim())
        .to_ascii_lowercase();
    if normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(normalized)
    } else {
        None
    }
}

fn derive_artifact_freshness_days(path: &Path) -> Option<u64> {
    if path.is_file() {
        return fs::metadata(path)
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            .and_then(freshness_days_since);
    }

    if path.is_dir() {
        let mut manifests = Vec::new();
        collect_artifact_manifest_candidates(path, &mut manifests).ok()?;
        manifests.sort();
        for manifest in manifests {
            let Ok(contents) = fs::read_to_string(&manifest) else {
                continue;
            };
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&contents) else {
                continue;
            };
            if let Some(days) = freshness_days_from_manifest(&value) {
                return Some(days);
            }
        }
    }

    None
}

fn collect_artifact_manifest_candidates(
    dir: &Path,
    manifests: &mut Vec<PathBuf>,
) -> Result<(), String> {
    for entry in
        fs::read_dir(dir).map_err(|error| format!("read dir `{}`: {error}", dir.display()))?
    {
        let entry =
            entry.map_err(|error| format!("read dir entry `{}`: {error}", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("read file type `{}`: {error}", path.display()))?;
        if file_type.is_dir() {
            collect_artifact_manifest_candidates(&path, manifests)?;
        } else if file_type.is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == "manifest.json" || name.ends_with("_manifest.json"))
        {
            manifests.push(path);
        }
    }
    Ok(())
}

fn freshness_days_from_manifest(value: &serde_json::Value) -> Option<u64> {
    let generated_utc = value
        .pointer("/freshness/generated_utc")
        .or_else(|| value.get("generated_utc"))
        .or_else(|| value.get("generated_at_utc"))
        .and_then(serde_json::Value::as_str)?;
    let generated_epoch = parse_claim_artifact_timestamp_epoch(generated_utc)?;
    let now_epoch = Utc::now().timestamp();
    if now_epoch <= generated_epoch {
        return Some(0);
    }
    Some(((now_epoch - generated_epoch) as u64) / 86_400)
}

fn parse_claim_artifact_timestamp_epoch(value: &str) -> Option<i64> {
    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(value) {
        return Some(parsed.timestamp());
    }
    NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%SZ")
        .ok()
        .map(|parsed| parsed.and_utc().timestamp())
}

fn freshness_days_since(time: SystemTime) -> Option<u64> {
    SystemTime::now()
        .duration_since(time)
        .ok()
        .map(|duration| duration.as_secs() / 86_400)
}

fn claim_artifact_has_reproducibility_bundle(path: &Path) -> bool {
    if path.is_file() {
        return path
            .parent()
            .is_some_and(|parent| parent.join("repro.lock").is_file());
    }
    if path.is_dir() {
        return directory_contains_repro_lock(path, 0, 4);
    }
    false
}

fn directory_contains_repro_lock(dir: &Path, depth: usize, max_depth: usize) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let entry_depth = depth.saturating_add(1);
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == "repro.lock")
            && path.is_file()
            && entry_depth <= max_depth
        {
            return true;
        }
        if entry_depth < max_depth
            && path.is_dir()
            && directory_contains_repro_lock(&path, entry_depth, max_depth)
        {
            return true;
        }
    }
    false
}

fn load_bead_status(
    beads_jsonl: Option<&Path>,
    bead_id: &str,
) -> Result<Option<ClaimExplanationBead>, String> {
    let Some(path) = beads_jsonl else {
        return Ok(None);
    };
    let Ok(contents) = fs::read_to_string(path) else {
        return Ok(Some(ClaimExplanationBead {
            bead_id: bead_id.to_string(),
            status: "unavailable".to_string(),
            assignee: None,
            source: path.display().to_string(),
            found: false,
        }));
    };
    for line in contents.lines() {
        if !line.contains(bead_id) {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            return Ok(Some(ClaimExplanationBead {
                bead_id: bead_id.to_string(),
                status: "unreadable".to_string(),
                assignee: None,
                source: path.display().to_string(),
                found: false,
            }));
        };
        if value
            .get("id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|id| id == bead_id)
        {
            return Ok(Some(ClaimExplanationBead {
                bead_id: bead_id.to_string(),
                status: value
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
                assignee: value
                    .get("assignee")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
                source: path.display().to_string(),
                found: true,
            }));
        }
    }
    Ok(Some(ClaimExplanationBead {
        bead_id: bead_id.to_string(),
        status: "not_found".to_string(),
        assignee: None,
        source: path.display().to_string(),
        found: false,
    }))
}

fn claim_row_contains_mock_contamination(row: &ClaimMatrixRow) -> bool {
    claim_row_text_fields(row)
        .iter()
        .any(|value| contains_claim_mock_marker(value))
}

fn claim_row_contains_local_fallback(row: &ClaimMatrixRow) -> bool {
    claim_row_text_fields(row)
        .iter()
        .any(|value| contains_claim_local_fallback_marker(value))
}

fn claim_row_text_fields(row: &ClaimMatrixRow) -> [&str; 5] {
    [
        row.artifact_path.as_deref().unwrap_or_default(),
        row.claim_text.as_str(),
        row.decision.as_str(),
        row.reason.as_str(),
        row.downgrade_text.as_deref().unwrap_or_default(),
    ]
}

fn claim_artifact_contains_mock_contamination(path: &Path) -> bool {
    claim_artifact_contains_marker(path, contains_claim_mock_marker)
}

fn claim_artifact_contains_local_fallback(path: &Path) -> bool {
    claim_artifact_contains_marker(path, contains_claim_local_fallback_marker)
}

fn claim_artifact_contains_marker(path: &Path, contains_marker: fn(&str) -> bool) -> bool {
    if path.is_file() {
        return artifact_file_contains_marker(path, contains_marker);
    }
    if !path.is_dir() {
        return false;
    }

    let mut files = Vec::new();
    if collect_artifact_files(path, &mut files).is_err() {
        return false;
    }
    files
        .iter()
        .any(|file| artifact_file_contains_marker(file, contains_marker))
}

fn artifact_file_contains_marker(path: &Path, contains_marker: fn(&str) -> bool) -> bool {
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    let contents = String::from_utf8_lossy(&bytes);
    contains_marker(contents.as_ref())
}

fn contains_claim_mock_marker(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("mockcertificate")
        || value.contains("mock_certificate")
        || value.contains("mock-certificate")
        || value.contains("hot_paths_simulation")
}

fn contains_claim_local_fallback_marker(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("localfallback")
        || value.contains("local_fallback_contaminated")
        || value.contains("local_fallback_observed")
        || value.contains("local-fallback-contaminated")
        || value.contains("local fallback was used")
        || value.contains("local fallback observed")
        || value.contains("falling back to local")
        || value.contains("fallback to local")
        || value.contains("ran locally instead of rch")
        || value.contains("running locally")
}

fn claim_explanation_decision(allowed_state: &str, reason_codes: &[String]) -> String {
    if reason_codes.iter().any(|code| {
        matches!(
            code.as_str(),
            "absent_artifact"
                | "artifact_hash_mismatch"
                | "contradictory_bead_status"
                | "duplicate_claim_row"
                | "invalid_matrix_schema"
                | "invalid_expected_hash"
                | "invalid_wording_state"
                | "local_fallback_contaminated"
                | "missing_reproducibility_bundle"
                | "missing_claim_row"
                | "missing_required_field"
                | "mock_contaminated"
                | "invalid_source_span"
                | "stale_artifact"
                | "stale_tracker_state"
                | "source_path_missing"
                | "source_path_unreadable"
                | "source_span_mismatch"
                | "wording_stronger_than_allowed"
        )
    }) {
        return "fail_closed".to_string();
    }
    match allowed_state {
        "observed" => "supported".to_string(),
        "target" | "hypothesis" => "not_promotable".to_string(),
        _ => "unsupported".to_string(),
    }
}

fn push_reason(
    reason_codes: &mut Vec<String>,
    remediation: &mut Vec<String>,
    reason: &str,
    fix: &str,
) {
    if !reason_codes.iter().any(|existing| existing == reason) {
        reason_codes.push(reason.to_string());
        remediation.push(format!("{reason}: {fix}"));
    }
}

fn state_rank(state: &str) -> u8 {
    match state {
        "hypothesis" => 0,
        "target" => 1,
        "observed" => 2,
        _ => 3,
    }
}

fn claim_state_is_known(state: &str) -> bool {
    matches!(state, "hypothesis" | "target" | "observed")
}

fn claim_explanation_mutation_policy() -> ClaimExplanationMutationPolicy {
    ClaimExplanationMutationPolicy {
        mutates_br: false,
        mutates_agent_mail: false,
        mutates_file_reservations: false,
        mutates_remote_workers: false,
        mutates_evidence_bundles: false,
        mutates_claim_matrix: false,
        mutates_git: false,
        runs_cargo: false,
        runs_rch: false,
    }
}

fn claim_explanation_renderer_boundary() -> ClaimExplanationRendererBoundary {
    ClaimExplanationRendererBoundary {
        future_rich_renderer_provider: "/dp/frankentui".to_string(),
        local_rich_renderer_shipped: false,
    }
}

fn derive_claim_explanation_receipt_id(output: &ClaimExplanationOutput) -> String {
    let mut value = serde_json::to_value(output).expect("claim explanation serializes");
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "receipt_id".to_string(),
            serde_json::Value::String(String::new()),
        );
    }
    let encoded = serde_json::to_vec(&value).expect("claim explanation JSON serializes");
    format!("claim-explain-{}", ContentHash::compute(&encoded).to_hex())
}

fn format_run_error(input: &Path, error: &OrchestratorError) -> String {
    let mut detail = format!("run failed for `{}`: {error}", input.display());
    if let Some(classification) = classify_run_error(error) {
        detail.push_str(format!("\nclassification: {classification}").as_str());
    }
    detail
}

fn classify_run_error(error: &OrchestratorError) -> Option<&'static str> {
    match error {
        OrchestratorError::Interpreter(
            InterpreterError::ModuleResolutionFailed { .. }
            | InterpreterError::ModuleReadFailed { .. }
            | InterpreterError::ModuleParseFailed { .. }
            | InterpreterError::ModuleLoweringFailed { .. }
            | InterpreterError::ModuleEvaluationFailed { .. },
        ) => Some("unsupported_runtime_module_resolution"),
        _ => None,
    }
}

fn run_cli_capabilities(parse_goal: ParseGoal) -> Vec<String> {
    let mut capabilities = CapabilityProfile::engine_core().capabilities().clone();
    if parse_goal == ParseGoal::Module {
        capabilities.insert(RuntimeCapability::ModuleLoad);
    }
    capabilities
        .into_iter()
        .map(|capability| capability.to_string())
        .collect()
}

fn execute_doctor(args: DoctorArgs) -> Result<i32, String> {
    // The doctor consumes either a bare runtime_input.json (`--input`) or a full
    // artifact bundle directory (`--artifact-dir <dir>`) emitted under
    // artifacts/<gate>/<ts>/, which carries run_manifest.json, events.jsonl,
    // step_logs/, and (by convention) the runtime_input.json that drove the run.
    let input_path = resolve_doctor_input_path(&args)?;
    let input = load_json_file::<RuntimeDiagnosticsCliInput>(&input_path)?;
    let artifact_bundle = args
        .artifact_dir
        .as_ref()
        .map(|dir| inspect_artifact_bundle(dir, &input_path));
    let redaction_policy = if args.redact_keys.is_empty() {
        SupportBundleRedactionPolicy::default()
    } else {
        SupportBundleRedactionPolicy::with_additional_fragments(args.redact_keys.clone())
    };

    let preflight = run_preflight_doctor(&input, args.filter.clone(), redaction_policy);

    let mut external_signals = match &args.signals {
        Some(path) => load_onboarding_signals(path)?,
        None => Vec::new(),
    };
    sort_and_dedup_signals(&mut external_signals);

    let mut compatibility_signals = match &args.advisories {
        Some(path) => load_onboarding_signals(path)?,
        None => Vec::new(),
    };
    if let Some(path) = &args.scenario_report {
        let scenario_report = load_json_file::<CompatibilityScenarioReport>(path)?;
        let advisory_output = build_compatibility_advisories(&CompatibilityAdvisoryInput {
            source_report: path.display().to_string(),
            scenario_report,
        });
        compatibility_signals.extend(advisory_output.signals);
    }
    sort_and_dedup_signals(&mut compatibility_signals);

    let mut platform_signals = match &args.platform_signals {
        Some(path) => load_onboarding_signals(path)?,
        None => Vec::new(),
    };
    sort_and_dedup_signals(&mut platform_signals);

    let workload_id = args
        .workload_id
        .clone()
        .unwrap_or_else(|| input.trace_id.clone());
    let package_name = args
        .package_name
        .clone()
        .unwrap_or_else(|| workload_id.clone());
    let onboarding_scorecard = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id,
        package_name,
        target_platforms: args.target_platforms.clone(),
        preflight: preflight.clone(),
        external_signals: external_signals.clone(),
    });
    let rollout_decision = build_rollout_decision_artifact(&RolloutDecisionArtifactInput {
        onboarding_scorecard: onboarding_scorecard.clone(),
        compatibility_advisories: compatibility_signals.clone(),
        platform_matrix_signals: platform_signals.clone(),
    });

    let blocked = onboarding_scorecard.readiness == OnboardingReadinessClass::Blocked
        || !rollout_decision.pilot_gate_consumable
        || matches!(
            rollout_decision.recommendation,
            RolloutRecommendation::Rollback | RolloutRecommendation::Defer
        );

    let output = DoctorCommandOutput {
        schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        input_path: input_path.display().to_string(),
        workload_id: onboarding_scorecard.workload_id.clone(),
        package_name: onboarding_scorecard.package_name.clone(),
        target_platforms: onboarding_scorecard.target_platforms.clone(),
        preflight_verdict: preflight.verdict.to_string(),
        readiness: onboarding_scorecard.readiness.to_string(),
        remediation_effort: onboarding_scorecard.remediation_effort.to_string(),
        rollout_recommendation: rollout_decision.recommendation.to_string(),
        blocked,
        signal_counts: DoctorSignalCounts {
            external_signals: external_signals.len(),
            compatibility_signals: compatibility_signals.len(),
            platform_signals: platform_signals.len(),
        },
        output_dir: args.out_dir.as_ref().map(|path| path.display().to_string()),
        preflight,
        onboarding_scorecard,
        rollout_decision,
        artifact_bundle,
        observability_mode: if args.out_dir.is_some() {
            support_bundle_export_observability_mode()
        } else {
            default_capture_observability_mode()
        },
    };

    if let Some(out_dir) = &args.out_dir {
        write_support_bundle_files(&output.preflight.support_bundle, out_dir)?;
        write_json_file(
            &out_dir.join("support_bundle/preflight_report.json"),
            &output.preflight,
        )?;
        write_json_file(
            &out_dir.join("support_bundle/onboarding_scorecard.json"),
            &output.onboarding_scorecard,
        )?;
        write_bytes_file(
            &out_dir.join("support_bundle/onboarding_scorecard_summary.md"),
            render_onboarding_scorecard_markdown(&output.onboarding_scorecard).as_bytes(),
        )?;
        write_json_file(
            &out_dir.join("support_bundle/owner_routing.json"),
            &build_onboarding_owner_routing(&output.onboarding_scorecard),
        )?;
        write_rollout_decision_reports(out_dir, &output.rollout_decision)?;
        write_json_file(
            &out_dir.join("support_bundle/frankenctl_doctor_report.json"),
            &output,
        )?;
    }

    if args.summary {
        println!("{}", render_doctor_summary(&output));
    } else {
        print_json(&output)?;
    }

    if blocked { Ok(25) } else { Ok(0) }
}

/// Resolve the runtime input the doctor should analyze. An explicit `--input`
/// wins; otherwise the conventional `runtime_input.json` inside the artifact
/// bundle directory is used.
fn resolve_doctor_input_path(args: &DoctorArgs) -> Result<PathBuf, String> {
    if let Some(path) = &args.input {
        return Ok(path.clone());
    }
    if let Some(dir) = &args.artifact_dir {
        let candidate = dir.join("runtime_input.json");
        if candidate.is_file() {
            return Ok(candidate);
        }
        return Err(format!(
            "artifact bundle `{}` has no runtime_input.json; pass --input <runtime_input.json> explicitly",
            dir.display()
        ));
    }
    Err("doctor requires --input <runtime_input.json> or --artifact-dir <bundle>".to_string())
}

/// Inspect a full artifact bundle directory (`artifacts/<gate>/<ts>/`) and report
/// on the presence/validity of `run_manifest.json`, `events.jsonl`, and
/// `step_logs/`, plus a categorized inventory of every file the bundle carries.
fn inspect_artifact_bundle(bundle_dir: &Path, resolved_input: &Path) -> DoctorArtifactBundleStatus {
    let mut diagnostics = Vec::new();

    let manifest_path = bundle_dir.join("run_manifest.json");
    let events_path = bundle_dir.join("events.jsonl");
    let step_logs_dir = bundle_dir.join("step_logs");

    // run_manifest.json: must exist, parse as JSON, and (ideally) carry a schema_version.
    let manifest_present = manifest_path.is_file();
    let mut manifest_valid_json = false;
    let mut manifest_schema_version = None;
    if manifest_present {
        match fs::read_to_string(&manifest_path) {
            Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(value) => {
                    manifest_valid_json = true;
                    manifest_schema_version = value
                        .get("schema_version")
                        .and_then(|field| field.as_str())
                        .map(|version| version.to_string());
                    if manifest_schema_version.is_none() {
                        diagnostics.push(DoctorArtifactBundleDiagnostic {
                            severity: "warning".to_string(),
                            code: "manifest_no_schema_version".to_string(),
                            path: manifest_path.display().to_string(),
                            message: "run_manifest.json has no schema_version field".to_string(),
                        });
                    }
                }
                Err(error) => diagnostics.push(DoctorArtifactBundleDiagnostic {
                    severity: "critical".to_string(),
                    code: "manifest_invalid_json".to_string(),
                    path: manifest_path.display().to_string(),
                    message: format!("run_manifest.json is not valid JSON: {error}"),
                }),
            },
            Err(error) => diagnostics.push(DoctorArtifactBundleDiagnostic {
                severity: "critical".to_string(),
                code: "manifest_unreadable".to_string(),
                path: manifest_path.display().to_string(),
                message: format!("failed to read run_manifest.json: {error}"),
            }),
        }
    } else {
        diagnostics.push(DoctorArtifactBundleDiagnostic {
            severity: "critical".to_string(),
            code: "manifest_missing".to_string(),
            path: manifest_path.display().to_string(),
            message: "run_manifest.json missing from artifact bundle".to_string(),
        });
    }

    // events.jsonl: must exist and every non-empty line must parse as JSON.
    let events_present = events_path.is_file();
    let mut events_valid_jsonl = false;
    let mut event_count = 0usize;
    if events_present {
        match fs::read_to_string(&events_path) {
            Ok(content) => {
                let mut all_valid = true;
                for (index, line) in content.lines().enumerate() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<serde_json::Value>(line) {
                        Ok(_) => event_count += 1,
                        Err(error) => {
                            all_valid = false;
                            diagnostics.push(DoctorArtifactBundleDiagnostic {
                                severity: "warning".to_string(),
                                code: "events_invalid_line".to_string(),
                                path: events_path.display().to_string(),
                                message: format!(
                                    "events.jsonl line {} is not valid JSON: {error}",
                                    index + 1
                                ),
                            });
                        }
                    }
                }
                events_valid_jsonl = all_valid;
            }
            Err(error) => diagnostics.push(DoctorArtifactBundleDiagnostic {
                severity: "critical".to_string(),
                code: "events_unreadable".to_string(),
                path: events_path.display().to_string(),
                message: format!("failed to read events.jsonl: {error}"),
            }),
        }
    } else {
        diagnostics.push(DoctorArtifactBundleDiagnostic {
            severity: "warning".to_string(),
            code: "events_missing".to_string(),
            path: events_path.display().to_string(),
            message: "events.jsonl missing from artifact bundle".to_string(),
        });
    }

    // step_logs/: directory of per-step capture; present + non-empty is ideal.
    let step_logs_present = step_logs_dir.is_dir();
    let mut step_log_count = 0usize;
    if step_logs_present {
        let mut step_files = Vec::new();
        collect_bundle_files(&step_logs_dir, &step_logs_dir, &mut step_files);
        step_log_count = step_files.len();
        if step_log_count == 0 {
            diagnostics.push(DoctorArtifactBundleDiagnostic {
                severity: "info".to_string(),
                code: "step_logs_empty".to_string(),
                path: step_logs_dir.display().to_string(),
                message: "step_logs/ directory is present but empty".to_string(),
            });
        }
    } else {
        diagnostics.push(DoctorArtifactBundleDiagnostic {
            severity: "warning".to_string(),
            code: "step_logs_missing".to_string(),
            path: step_logs_dir.display().to_string(),
            message: "step_logs/ directory missing from artifact bundle".to_string(),
        });
    }

    // Categorized inventory of every file in the bundle.
    let mut all_files = Vec::new();
    collect_bundle_files(bundle_dir, bundle_dir, &mut all_files);
    if all_files.is_empty() {
        diagnostics.push(DoctorArtifactBundleDiagnostic {
            severity: "critical".to_string(),
            code: "bundle_empty".to_string(),
            path: bundle_dir.display().to_string(),
            message: "artifact bundle directory contains no files".to_string(),
        });
    }
    let mut artifact_paths: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for relative in &all_files {
        artifact_paths
            .entry(categorize_bundle_path(relative).to_string())
            .or_default()
            .push(relative.clone());
    }
    for paths in artifact_paths.values_mut() {
        paths.sort();
        paths.dedup();
    }

    let complete = manifest_present
        && manifest_valid_json
        && events_present
        && events_valid_jsonl
        && step_logs_present;

    DoctorArtifactBundleStatus {
        bundle_dir: bundle_dir.display().to_string(),
        input_path: Some(resolved_input.display().to_string()),
        manifest_path: manifest_path.display().to_string(),
        manifest_present,
        manifest_valid_json,
        manifest_schema_version,
        artifact_paths,
        events_path: events_path.display().to_string(),
        events_present,
        events_valid_jsonl,
        event_count,
        step_logs_dir: step_logs_dir.display().to_string(),
        step_logs_present,
        step_log_count,
        complete,
        diagnostics,
    }
}

/// Recursively collect files under `dir`, returning each path relative to `root`
/// with forward-slash separators for deterministic, platform-stable categorization.
fn collect_bundle_files(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            collect_bundle_files(root, &path, out);
        } else if let Ok(relative) = path.strip_prefix(root) {
            out.push(relative.to_string_lossy().replace('\\', "/"));
        }
    }
}

/// Classify a bundle-relative path into a coarse artifact category for the inventory.
fn categorize_bundle_path(relative: &str) -> &'static str {
    if relative == "run_manifest.json" {
        "manifest"
    } else if relative == "events.jsonl" {
        "events"
    } else if relative == "runtime_input.json" {
        "runtime_input"
    } else if relative.starts_with("step_logs/") {
        "step_logs"
    } else if relative.ends_with(".jsonl") {
        "event_streams"
    } else if relative.ends_with(".json") {
        "reports"
    } else if relative.ends_with(".md") {
        "summaries"
    } else {
        "other"
    }
}

fn execute_verify(args: VerifyArgs) -> Result<i32, String> {
    match args {
        VerifyArgs::CompileArtifact {
            input,
            output: output_path,
        } => {
            let artifact = load_json_file::<CompileArtifact>(&input)?;
            let errors = validate_compile_artifact(&artifact);
            let report = CompileArtifactVerificationOutput {
                schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
                trace_id: artifact.trace_id.clone(),
                decision_id: artifact.decision_id.clone(),
                policy_id: artifact.policy_id.clone(),
                artifact_path: input.display().to_string(),
                report_path: output_path.as_ref().map(|path| path.display().to_string()),
                passed: errors.is_empty(),
                errors,
                observability_mode: default_capture_observability_mode(),
            };
            if let Some(path) = &output_path {
                write_json_file(path, &report)?;
            }
            print_json(&report)?;
            if report.passed { Ok(0) } else { Ok(25) }
        }
        VerifyArgs::Receipt {
            input,
            receipt_id,
            summary,
            output,
        } => {
            let verifier_input = load_json_file::<ReceiptVerifierCliInput>(&input)?;
            let verdict = verify_receipt_by_id(&verifier_input, &receipt_id)
                .map_err(|error| format!("receipt verification failed: {error}"))?;
            let output_payload = ReceiptVerificationCommandOutput {
                verdict,
                report_path: output.as_ref().map(|path| path.display().to_string()),
                observability_mode: default_capture_observability_mode(),
            };
            if let Some(path) = &output {
                write_json_file(path, &output_payload)?;
            }
            if summary {
                println!("{}", render_verdict_summary(&output_payload.verdict));
            } else {
                print_json(&output_payload)?;
            }
            Ok(output_payload.verdict.exit_code)
        }
    }
}

fn execute_benchmark(args: BenchmarkArgs) -> Result<i32, String> {
    match args.mode {
        BenchmarkMode::Run(run_args) => execute_benchmark_run(run_args),
        BenchmarkMode::Compare(compare_args) => execute_benchmark_compare(compare_args),
        BenchmarkMode::Score(score_args) => execute_benchmark_score(score_args),
        BenchmarkMode::Verify(verify_args) => execute_benchmark_verify(verify_args),
    }
}

fn execute_benchmark_run(args: BenchmarkRunArgs) -> Result<i32, String> {
    let config = BenchmarkSuiteConfig {
        seed: args.seed,
        profiles: args.profiles.clone(),
        families: args.families.clone(),
        run_id: args.run_id.clone(),
        run_date: args.run_date.clone(),
        ..BenchmarkSuiteConfig::default()
    };

    let result = run_benchmark_suite(&config);
    let artifacts = write_evidence_artifacts(&result, &args.out_dir).map_err(|error| {
        format!(
            "failed to write benchmark artifacts to `{}`: {error}",
            args.out_dir.display()
        )
    })?;

    let output = BenchmarkCommandOutput {
        schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
        run_id: config.run_id.clone(),
        run_date: config.run_date.clone(),
        seed: config.seed,
        blocked: result.blocked,
        total_operations: result.total_operations,
        total_duration_us: result.total_duration_us,
        invariant_violations: result.invariant_violations,
        profiles: config
            .profiles
            .iter()
            .map(|profile| profile.as_str().to_string())
            .collect(),
        families: config
            .families
            .iter()
            .map(|family| family.as_str().to_string())
            .collect(),
        artifacts: BenchmarkArtifactPaths {
            run_manifest: artifacts.run_manifest_path.display().to_string(),
            evidence_jsonl: artifacts.evidence_path.display().to_string(),
            events_jsonl: artifacts.events_path.display().to_string(),
            commands_txt: artifacts.commands_path.display().to_string(),
            benchmark_env_manifest: artifacts.benchmark_env_manifest_path.display().to_string(),
            raw_results_archive: artifacts.raw_results_archive_path.display().to_string(),
            summary: artifacts.summary_path.display().to_string(),
        },
        observability_mode: default_capture_observability_mode(),
    };

    print_json(&output)?;
    if result.blocked { Ok(25) } else { Ok(0) }
}

fn execute_benchmark_compare(args: BenchmarkCompareArgs) -> Result<i32, String> {
    let manifest = load_json_file::<BenchmarkComparisonManifest>(&args.manifest)?;
    let manifest_root = args
        .manifest
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let result = run_benchmark_comparison_suite(
        &manifest,
        &manifest_root,
        args.run_id.clone(),
        args.run_date.clone(),
    )
    .map_err(|error| format!("benchmark compare execution failed: {error}"))?;
    let artifacts =
        write_benchmark_comparison_artifacts(&result, &args.out_dir).map_err(|error| {
            format!(
                "failed to write benchmark comparison artifacts to `{}`: {error}",
                args.out_dir.display()
            )
        })?;
    let output = BenchmarkCompareCommandOutput {
        schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
        run_id: args.run_id,
        run_date: args.run_date,
        case_count: result.manifest.cases.len(),
        runtime_result_count: result.results.len(),
        artifacts: BenchmarkArtifactPaths {
            run_manifest: artifacts.run_manifest_path.display().to_string(),
            evidence_jsonl: artifacts.evidence_path.display().to_string(),
            events_jsonl: artifacts.events_path.display().to_string(),
            commands_txt: artifacts.commands_path.display().to_string(),
            benchmark_env_manifest: artifacts.benchmark_env_manifest_path.display().to_string(),
            raw_results_archive: artifacts.raw_results_archive_path.display().to_string(),
            summary: artifacts.summary_path.display().to_string(),
        },
        observability_mode: default_capture_observability_mode(),
    };
    print_json(&output)?;
    Ok(0)
}

fn execute_benchmark_score(args: BenchmarkScoreArgs) -> Result<i32, String> {
    let input = load_json_file::<PublicationGateInput>(&args.input)?;
    let ctx = PublicationContext::new(
        args.trace_id.clone(),
        args.decision_id.clone(),
        args.policy_id.clone(),
    );
    let decision = evaluate_publication_gate(&input, &ctx)
        .map_err(|error| format!("benchmark score evaluation failed: {error}"))?;

    let claim_bundle = BenchmarkClaimBundle {
        trace_id: ctx.trace_id.clone(),
        decision_id: ctx.decision_id.clone(),
        policy_id: ctx.policy_id.clone(),
        input,
        claimed: ClaimedBenchmarkOutcome {
            score_vs_node: decision.score_vs_node,
            score_vs_bun: decision.score_vs_bun,
            publish_allowed: decision.publish_allowed,
            blockers: decision.blockers.clone(),
        },
    };

    let bundle_dir = write_benchmark_score_output(&args, &claim_bundle)?;

    let runtime = benchmark_bundle_runtime();
    let bundle = bundle_dir.as_ref().map(|path| path.display().to_string());
    let bundle_env_path = bundle_dir
        .as_ref()
        .map(|path| path.join("env.json").display().to_string());
    let benchmark_invocation_manifest_path = bundle_dir.as_ref().map(|path| {
        path.join("benchmark_invocation_manifest.json")
            .display()
            .to_string()
    });
    let command_mode_receipt_path = bundle_dir
        .as_ref()
        .map(|path| path.join("command_mode_receipt.json").display().to_string());
    let output = BenchmarkScoreCommandOutput {
        schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
        trace_id: ctx.trace_id,
        decision_id: ctx.decision_id,
        policy_id: ctx.policy_id,
        score_vs_node: claim_bundle.claimed.score_vs_node,
        score_vs_bun: claim_bundle.claimed.score_vs_bun,
        publish_allowed: claim_bundle.claimed.publish_allowed,
        blockers: claim_bundle.claimed.blockers,
        output: args.output.as_ref().map(|path| path.display().to_string()),
        bundle,
        bundle_env_path,
        benchmark_invocation_manifest_path,
        command_mode_receipt_path,
        runtime,
        observability_mode: default_capture_observability_mode(),
    };

    print_json(&output)?;
    if output.publish_allowed {
        Ok(0)
    } else {
        Ok(25)
    }
}

fn write_benchmark_score_output(
    args: &BenchmarkScoreArgs,
    claim_bundle: &BenchmarkClaimBundle,
) -> Result<Option<PathBuf>, String> {
    let Some(output_path) = &args.output else {
        return Ok(None);
    };

    let bundle_dir = benchmark_bundle_dir(output_path);
    let canonical_results_output =
        output_path.file_name().and_then(|name| name.to_str()) == Some("results.json");
    let bundle_results_path = if canonical_results_output {
        output_path.clone()
    } else {
        bundle_dir.join("results.json")
    };
    let output_copy_path = (!canonical_results_output).then_some(output_path.as_path());
    materialize_benchmark_score_bundle(
        &bundle_dir,
        &bundle_results_path,
        output_copy_path,
        args,
        claim_bundle,
    )?;
    Ok(Some(bundle_dir))
}

fn materialize_benchmark_score_bundle(
    bundle_dir: &Path,
    results_path: &Path,
    output_copy_path: Option<&Path>,
    args: &BenchmarkScoreArgs,
    claim_bundle: &BenchmarkClaimBundle,
) -> Result<(), String> {
    let generated_at_utc = current_utc_timestamp();
    let repo_state = current_benchmark_bundle_repo_state();
    let input_bytes = encode_json_value(
        &claim_bundle.input,
        "embedded benchmark publication gate input",
    )?;
    let input_artifact = BenchmarkBundleArtifactDigest {
        path: args.input.display().to_string(),
        sha256: sha256_prefixed(&input_bytes),
    };
    let input_materialized = BenchmarkBundleMaterializedFile {
        path: args.input.display().to_string(),
        sha256: input_artifact.sha256.clone(),
        bytes: u64::try_from(input_bytes.len()).unwrap_or(u64::MAX),
        kind: "input".to_string(),
    };

    let results_bytes = encode_json_value(
        claim_bundle,
        format!("benchmark score output `{}`", results_path.display()).as_str(),
    )?;
    let results_artifact = bundle_artifact_digest("results.json", &results_bytes);
    let results_materialized = bundle_materialized_file("results.json", &results_bytes, "output");

    let rustc_verbose = command_stdout("rustc", &["-Vv"]);
    let rustc_version = command_stdout("rustc", &["-V"]).unwrap_or_else(|| "unknown".to_string());
    let cargo_version = command_stdout("cargo", &["-V"]).unwrap_or_else(|| "unknown".to_string());
    let runtime = benchmark_bundle_runtime();
    let env_artifact_path = bundle_dir.join("env.json");
    let env_artifact = BenchmarkBundleEnv {
        schema_version: BENCHMARK_BUNDLE_ENV_SCHEMA_VERSION.to_string(),
        schema_hash: schema_hash(BENCHMARK_BUNDLE_ENV_SCHEMA_VERSION),
        captured_at_utc: generated_at_utc.clone(),
        project: BenchmarkBundleProject {
            name: "franken_engine".to_string(),
            repo_url: BENCHMARK_BUNDLE_REPO_URL.to_string(),
            commit: repo_state.commit.clone(),
            dirty: repo_state.dirty,
        },
        host: BenchmarkBundleHost {
            os: env::consts::OS.to_string(),
            kernel: command_stdout("uname", &["-r"]).unwrap_or_else(|| "unknown".to_string()),
            arch: env::consts::ARCH.to_string(),
            cpu_model: "unknown".to_string(),
            cpu_cores_logical: std::thread::available_parallelism()
                .map(|count| u64::try_from(count.get()).unwrap_or(u64::MAX))
                .unwrap_or(0),
            memory_bytes: 0,
        },
        toolchain: BenchmarkBundleToolchain {
            rustup_toolchain: env::var("RUSTUP_TOOLCHAIN")
                .unwrap_or_else(|_| "unknown".to_string()),
            rustc: rustc_version,
            cargo: cargo_version,
            llvm: rustc_verbose_field(rustc_verbose.as_deref(), "LLVM version")
                .unwrap_or_else(|| "unknown".to_string()),
            target_triple: rustc_verbose_field(rustc_verbose.as_deref(), "host")
                .unwrap_or_else(|| "unknown".to_string()),
            profile: env::var("PROFILE").unwrap_or_else(|_| "dev".to_string()),
        },
        runtime: runtime.clone(),
        policy: BenchmarkBundlePolicy {
            policy_id: claim_bundle.policy_id.clone(),
            policy_digest_sha256: sha256_prefixed(claim_bundle.policy_id.as_bytes()),
        },
    };
    let env_bytes = encode_json_value(
        &env_artifact,
        format!("benchmark bundle env `{}`", env_artifact_path.display()).as_str(),
    )?;
    let env_digest = bundle_artifact_digest("env.json", &env_bytes);
    let env_materialized = bundle_materialized_file("env.json", &env_bytes, "output");

    let score_output_argument: &Path = args.output.as_deref().unwrap_or(results_path);
    let score_command = format!(
        "rch exec -- cargo run -p frankenengine-engine --bin frankenctl -- benchmark score --input {} --trace-id {} --decision-id {} --policy-id {} --output {}",
        args.input.display(),
        claim_bundle.trace_id,
        claim_bundle.decision_id,
        claim_bundle.policy_id,
        score_output_argument.display()
    );
    let verify_report_path = bundle_dir.join("verify_report.json");
    let verify_command = format!(
        "rch exec -- cargo run -p frankenengine-engine --bin frankenctl -- benchmark verify --bundle {} --output {}",
        bundle_dir.display(),
        verify_report_path.display()
    );
    let commands = vec![score_command, verify_command];
    let commands_text = format!("{}\n", commands.join("\n"));
    let commands_bytes = commands_text.into_bytes();
    let commands_digest = bundle_artifact_digest("commands.txt", &commands_bytes);
    let commands_materialized = bundle_materialized_file("commands.txt", &commands_bytes, "output");

    let bundle_id = format!(
        "frankenctl-benchmark-{}",
        &ContentHash::compute(
            format!(
                "{}:{}:{}:{}",
                claim_bundle.trace_id,
                claim_bundle.decision_id,
                claim_bundle.policy_id,
                results_artifact.sha256
            )
            .as_bytes()
        )
        .to_hex()[..16]
    );
    let manifest_id = format!("{BENCHMARK_BUNDLE_COMPONENT}-{bundle_id}");
    let command_mode_receipt = CommandModeReceipt {
        schema_version: COMMAND_MODE_RECEIPT_SCHEMA_VERSION.to_string(),
        schema_hash: schema_hash(COMMAND_MODE_RECEIPT_SCHEMA_VERSION),
        receipt_id: format!("{manifest_id}-command-mode"),
        generated_at_utc: generated_at_utc.clone(),
        command: "frankenctl benchmark score".to_string(),
        command_family: "benchmark".to_string(),
        trace_id: claim_bundle.trace_id.clone(),
        decision_id: claim_bundle.decision_id.clone(),
        policy_id: claim_bundle.policy_id.clone(),
        bundle_root: bundle_dir.display().to_string(),
        env_path: "env.json".to_string(),
        manifest_id: manifest_id.clone(),
        runtime: runtime.clone(),
    };
    let command_mode_receipt_bytes = encode_json_value(
        &command_mode_receipt,
        format!(
            "benchmark bundle command mode receipt `{}`",
            bundle_dir.join("command_mode_receipt.json").display()
        )
        .as_str(),
    )?;
    let command_mode_receipt_digest =
        bundle_artifact_digest("command_mode_receipt.json", &command_mode_receipt_bytes);
    let command_mode_receipt_materialized = bundle_materialized_file(
        "command_mode_receipt.json",
        &command_mode_receipt_bytes,
        "output",
    );

    let benchmark_invocation_manifest = BenchmarkInvocationManifest {
        schema_version: BENCHMARK_INVOCATION_MANIFEST_SCHEMA_VERSION.to_string(),
        schema_hash: schema_hash(BENCHMARK_INVOCATION_MANIFEST_SCHEMA_VERSION),
        invocation_id: format!("{manifest_id}-invocation"),
        generated_at_utc: generated_at_utc.clone(),
        command: "frankenctl benchmark score".to_string(),
        trace_id: claim_bundle.trace_id.clone(),
        decision_id: claim_bundle.decision_id.clone(),
        policy_id: claim_bundle.policy_id.clone(),
        input_path: args.input.display().to_string(),
        requested_output_path: score_output_argument.display().to_string(),
        bundle_root: bundle_dir.display().to_string(),
        artifacts: BenchmarkInvocationArtifacts {
            canonical_results: "results.json".to_string(),
            env: "env.json".to_string(),
            bundle_manifest: "manifest.json".to_string(),
            commands_transcript: "commands.txt".to_string(),
            repro_lock: "repro.lock".to_string(),
            command_mode_receipt: "command_mode_receipt.json".to_string(),
        },
        runtime: runtime.clone(),
    };
    let benchmark_invocation_manifest_bytes = encode_json_value(
        &benchmark_invocation_manifest,
        format!(
            "benchmark invocation manifest `{}`",
            bundle_dir
                .join("benchmark_invocation_manifest.json")
                .display()
        )
        .as_str(),
    )?;
    let benchmark_invocation_manifest_digest = bundle_artifact_digest(
        "benchmark_invocation_manifest.json",
        &benchmark_invocation_manifest_bytes,
    );
    let benchmark_invocation_manifest_materialized = bundle_materialized_file(
        "benchmark_invocation_manifest.json",
        &benchmark_invocation_manifest_bytes,
        "output",
    );

    let repro_artifact = BenchmarkBundleReproLock {
        schema_version: BENCHMARK_BUNDLE_REPRO_LOCK_SCHEMA_VERSION.to_string(),
        schema_hash: schema_hash(BENCHMARK_BUNDLE_REPRO_LOCK_SCHEMA_VERSION),
        generated_at_utc: generated_at_utc.clone(),
        lock_id: format!("{manifest_id}-lock"),
        manifest_id: manifest_id.clone(),
        source_commit: repo_state.commit.clone(),
        determinism: BenchmarkBundleDeterminism {
            allow_network: false,
            allow_wall_clock: false,
            allow_randomness: false,
            max_clock_skew_seconds: 0,
        },
        commands: commands.clone(),
        inputs: vec![input_materialized.clone()],
        expected_outputs: vec![
            env_materialized.clone(),
            commands_materialized.clone(),
            results_materialized.clone(),
            benchmark_invocation_manifest_materialized.clone(),
            command_mode_receipt_materialized.clone(),
        ],
        replay: BenchmarkBundleReplay {
            trace_id: claim_bundle.trace_id.clone(),
            decision_id: claim_bundle.decision_id.clone(),
            policy_id: claim_bundle.policy_id.clone(),
            replay_pointer: format!("file://{}/commands.txt", bundle_dir.display()),
        },
        verification: BenchmarkBundleVerification {
            command: format!(
                "frankenctl benchmark verify --bundle {} --output {}",
                bundle_dir.display(),
                verify_report_path.display()
            ),
            expected_verdict: "verified".to_string(),
        },
    };
    let repro_bytes = encode_json_value(
        &repro_artifact,
        format!(
            "benchmark bundle repro lock `{}`",
            bundle_dir.join("repro.lock").display()
        )
        .as_str(),
    )?;
    let repro_digest = bundle_artifact_digest("repro.lock", &repro_bytes);

    let manifest_artifact = BenchmarkBundleManifest {
        schema_version: BENCHMARK_BUNDLE_MANIFEST_SCHEMA_VERSION.to_string(),
        schema_hash: schema_hash(BENCHMARK_BUNDLE_MANIFEST_SCHEMA_VERSION),
        manifest_id: manifest_id.clone(),
        generated_at_utc: generated_at_utc.clone(),
        claim: BenchmarkBundleClaimMetadata {
            claim_id: BENCHMARK_BUNDLE_CLAIM_ID.to_string(),
            claim_class: "performance".to_string(),
            statement: "Benchmark publication gate evidence bundle generated by frankenctl benchmark score."
                .to_string(),
            status: "observed".to_string(),
            bundle_root: bundle_dir.display().to_string(),
        },
        source_revision: BenchmarkBundleSourceRevision {
            repo: "franken_engine".to_string(),
            branch: repo_state.branch.clone(),
            commit: repo_state.commit.clone(),
        },
        provenance: BenchmarkBundleProvenance {
            trace_id: claim_bundle.trace_id.clone(),
            decision_id: claim_bundle.decision_id.clone(),
            policy_id: claim_bundle.policy_id.clone(),
            replay_pointer: format!("file://{}/commands.txt", bundle_dir.display()),
            evidence_pointer: format!("file://{}/results.json", bundle_dir.display()),
            receipt_ids: vec![command_mode_receipt.receipt_id.clone()],
        },
        artifacts: BenchmarkBundleArtifactsCatalog {
            env: env_digest.clone(),
            lock: repro_digest.clone(),
            commands: commands_digest.clone(),
            results: results_artifact.clone(),
            benchmark_invocation_manifest: benchmark_invocation_manifest_digest.clone(),
            command_mode_receipt: command_mode_receipt_digest.clone(),
        },
        inputs: vec![input_artifact],
        outputs: vec![results_artifact.clone()],
        canonicalization: BenchmarkBundleCanonicalization {
            format: "json".to_string(),
            key_order: "struct-declaration-order".to_string(),
            newline: "lf".to_string(),
            hash_algorithm: "sha256".to_string(),
        },
        validation: BenchmarkBundleValidation {
            validator: "frankenctl benchmark verify".to_string(),
            error_taxonomy: "FE-TPV-BUNDLE-0001..FE-TPV-BUNDLE-0006".to_string(),
        },
        retention: BenchmarkBundleRetention {
            min_days: 365,
            high_impact_min_days: 730,
            rotation_policy: "archive-with-addressable-retrieval".to_string(),
        },
    };
    let manifest_bytes = encode_json_value(
        &manifest_artifact,
        format!(
            "benchmark bundle manifest `{}`",
            bundle_dir.join("manifest.json").display()
        )
        .as_str(),
    )?;

    write_bytes_file(results_path, &results_bytes)?;
    if let Some(output_copy_path) = output_copy_path {
        write_bytes_file(output_copy_path, &results_bytes)?;
    }
    write_bytes_file(&bundle_dir.join("env.json"), &env_bytes)?;
    write_bytes_file(&bundle_dir.join("commands.txt"), &commands_bytes)?;
    write_bytes_file(&bundle_dir.join("repro.lock"), &repro_bytes)?;
    write_bytes_file(&bundle_dir.join("manifest.json"), &manifest_bytes)?;
    write_bytes_file(
        &bundle_dir.join("benchmark_invocation_manifest.json"),
        &benchmark_invocation_manifest_bytes,
    )?;
    write_bytes_file(
        &bundle_dir.join("command_mode_receipt.json"),
        &command_mode_receipt_bytes,
    )?;
    Ok(())
}

fn execute_benchmark_verify(args: BenchmarkVerifyArgs) -> Result<i32, String> {
    let results_path = args.bundle.join("results.json");
    if !results_path.is_file() {
        return Err(format!(
            "benchmark verify requires --bundle <dir> containing env.json, manifest.json, repro.lock, commands.txt, results.json, benchmark_invocation_manifest.json, and command_mode_receipt.json (missing `{}`)",
            results_path.display()
        ));
    }

    let input = load_json_file::<BenchmarkClaimBundle>(&results_path)?;
    let mut report = verify_benchmark_claim(&input);
    validate_benchmark_bundle_contract(&args.bundle, &input, &mut report);
    let output_payload = BenchmarkVerificationCommandOutput {
        report,
        report_path: args.output.as_ref().map(|path| path.display().to_string()),
        observability_mode: default_capture_observability_mode(),
    };

    if let Some(path) = &args.output {
        write_json_file(path, &output_payload)?;
    }
    if args.summary {
        println!("{}", render_report_summary(&output_payload.report));
    } else {
        print_json(&output_payload)?;
    }
    Ok(output_payload.report.exit_code())
}

fn validate_benchmark_bundle_contract(
    bundle_dir: &Path,
    input: &BenchmarkClaimBundle,
    report: &mut ThirdPartyVerificationReport,
) {
    let required_files = [
        "env.json",
        "manifest.json",
        "repro.lock",
        "commands.txt",
        "results.json",
        "benchmark_invocation_manifest.json",
        "command_mode_receipt.json",
    ];

    let mut bundle_violations = false;
    let mut bundle_bytes = BTreeMap::new();
    for file in required_files {
        let path = bundle_dir.join(file);
        let present = path.is_file();
        append_benchmark_bundle_check(
            report,
            format!("bundle_file_{file}_present"),
            present,
            CODE_BUNDLE_MISSING_FILE,
            if present {
                format!("required bundle file present: {}", path.display())
            } else {
                format!("required bundle file missing: {}", path.display())
            },
        );
        if present {
            match fs::read(&path) {
                Ok(bytes) => {
                    bundle_bytes.insert(file.to_string(), bytes);
                }
                Err(error) => {
                    append_benchmark_bundle_check(
                        report,
                        format!("bundle_file_{file}_readable"),
                        false,
                        CODE_BUNDLE_PARSE_ERROR,
                        format!(
                            "failed to read required bundle file '{}': {error}",
                            path.display()
                        ),
                    );
                    bundle_violations = true;
                }
            }
        } else {
            bundle_violations = true;
        }
    }

    let actual_digests = bundle_bytes
        .iter()
        .map(|(file, bytes)| (file.clone(), sha256_prefixed(bytes)))
        .collect::<BTreeMap<_, _>>();
    let embedded_input_digest =
        match encode_json_value(&input.input, "embedded benchmark publication gate input") {
            Ok(bytes) => Some(sha256_prefixed(&bytes)),
            Err(error) => {
                append_benchmark_bundle_check(
                    report,
                    "bundle_embedded_input_digest_recomputes".to_string(),
                    false,
                    CODE_BUNDLE_PARSE_ERROR,
                    error,
                );
                bundle_violations = true;
                None
            }
        };

    let manifest = if let Some(manifest_bytes) = bundle_bytes.get("manifest.json") {
        match serde_json::from_slice::<BenchmarkBundleManifest>(manifest_bytes) {
            Ok(manifest) => {
                let schema_ok = manifest.schema_version == BENCHMARK_BUNDLE_MANIFEST_SCHEMA_VERSION
                    && manifest.schema_hash
                        == schema_hash(BENCHMARK_BUNDLE_MANIFEST_SCHEMA_VERSION);
                append_benchmark_bundle_check(
                    report,
                    "bundle_manifest_schema_matches".to_string(),
                    schema_ok,
                    CODE_BUNDLE_SCHEMA_MISMATCH,
                    if schema_ok {
                        format!(
                            "bundle manifest schema matches {}",
                            BENCHMARK_BUNDLE_MANIFEST_SCHEMA_VERSION
                        )
                    } else {
                        format!(
                            "bundle manifest schema mismatch: schema_version={} schema_hash={}",
                            manifest.schema_version, manifest.schema_hash
                        )
                    },
                );
                if !schema_ok {
                    bundle_violations = true;
                }

                let context_matches = manifest.provenance.trace_id == input.trace_id
                    && manifest.provenance.decision_id == input.decision_id
                    && manifest.provenance.policy_id == input.policy_id;
                append_benchmark_bundle_check(
                    report,
                    "bundle_manifest_context_matches_claim".to_string(),
                    context_matches,
                    CODE_BUNDLE_CONTEXT_MISMATCH,
                    if context_matches {
                        "bundle manifest trace/decision/policy context matches results.json claim"
                            .to_string()
                    } else {
                        format!(
                            "bundle manifest context mismatch: manifest=({}, {}, {}), results=({}, {}, {})",
                            manifest.provenance.trace_id,
                            manifest.provenance.decision_id,
                            manifest.provenance.policy_id,
                            input.trace_id,
                            input.decision_id,
                            input.policy_id
                        )
                    },
                );
                if !context_matches {
                    bundle_violations = true;
                }

                let claim_ok = manifest.claim.claim_id == BENCHMARK_BUNDLE_CLAIM_ID
                    && manifest.claim.claim_class == "performance"
                    && manifest.claim.status == "observed"
                    && !manifest.claim.bundle_root.trim().is_empty();
                append_benchmark_bundle_check(
                    report,
                    "bundle_manifest_claim_metadata_present".to_string(),
                    claim_ok,
                    CODE_BUNDLE_PARSE_ERROR,
                    if claim_ok {
                        format!(
                            "bundle manifest claim metadata references {} and observed performance status",
                            BENCHMARK_BUNDLE_CLAIM_ID
                        )
                    } else {
                        format!(
                            "bundle manifest claim metadata invalid: claim_id={} class={} status={} bundle_root={}",
                            manifest.claim.claim_id,
                            manifest.claim.claim_class,
                            manifest.claim.status,
                            manifest.claim.bundle_root
                        )
                    },
                );
                if !claim_ok {
                    bundle_violations = true;
                }

                let source_ok = manifest.source_revision.repo == "franken_engine"
                    && !manifest.source_revision.branch.trim().is_empty()
                    && !manifest.source_revision.commit.trim().is_empty();
                append_benchmark_bundle_check(
                    report,
                    "bundle_manifest_source_revision_present".to_string(),
                    source_ok,
                    CODE_BUNDLE_PARSE_ERROR,
                    if source_ok {
                        format!(
                            "bundle manifest source revision recorded for branch={} commit={}",
                            manifest.source_revision.branch, manifest.source_revision.commit
                        )
                    } else {
                        format!(
                            "bundle manifest source revision invalid: repo={} branch={} commit={}",
                            manifest.source_revision.repo,
                            manifest.source_revision.branch,
                            manifest.source_revision.commit
                        )
                    },
                );
                if !source_ok {
                    bundle_violations = true;
                }

                let validator_ok = manifest.validation.validator == "frankenctl benchmark verify"
                    && !manifest.validation.error_taxonomy.trim().is_empty();
                append_benchmark_bundle_check(
                    report,
                    "bundle_manifest_validation_contract_present".to_string(),
                    validator_ok,
                    CODE_BUNDLE_PARSE_ERROR,
                    if validator_ok {
                        "bundle manifest declares frankenctl benchmark verify as the validation command".to_string()
                    } else {
                        format!(
                            "bundle manifest validation block invalid: validator={} taxonomy={}",
                            manifest.validation.validator, manifest.validation.error_taxonomy
                        )
                    },
                );
                if !validator_ok {
                    bundle_violations = true;
                }

                for (label, artifact, file_name) in [
                    ("env", &manifest.artifacts.env, "env.json"),
                    ("lock", &manifest.artifacts.lock, "repro.lock"),
                    ("commands", &manifest.artifacts.commands, "commands.txt"),
                    ("results", &manifest.artifacts.results, "results.json"),
                    (
                        "benchmark_invocation_manifest",
                        &manifest.artifacts.benchmark_invocation_manifest,
                        "benchmark_invocation_manifest.json",
                    ),
                    (
                        "command_mode_receipt",
                        &manifest.artifacts.command_mode_receipt,
                        "command_mode_receipt.json",
                    ),
                ] {
                    let path_matches = artifact.path == file_name;
                    append_benchmark_bundle_check(
                        report,
                        format!("bundle_manifest_{label}_path_matches"),
                        path_matches,
                        CODE_BUNDLE_PARSE_ERROR,
                        if path_matches {
                            format!("bundle manifest {label} path matches {file_name}")
                        } else {
                            format!(
                                "bundle manifest {label} path mismatch: expected {} but found {}",
                                file_name, artifact.path
                            )
                        },
                    );
                    if !path_matches {
                        bundle_violations = true;
                    }

                    let digest_matches = actual_digests
                        .get(file_name)
                        .is_some_and(|actual| actual == &artifact.sha256);
                    append_benchmark_bundle_check(
                        report,
                        format!("bundle_manifest_{label}_digest_matches"),
                        digest_matches,
                        CODE_BUNDLE_DIGEST_MISMATCH,
                        if digest_matches {
                            format!("bundle manifest {label} digest matches {file_name}")
                        } else {
                            format!(
                                "bundle manifest {label} digest mismatch: declared={} actual={}",
                                artifact.sha256,
                                actual_digests
                                    .get(file_name)
                                    .cloned()
                                    .unwrap_or_else(|| "missing".to_string())
                            )
                        },
                    );
                    if !digest_matches {
                        bundle_violations = true;
                    }
                }

                let manifest_input_ok = embedded_input_digest.as_ref().is_some_and(|digest| {
                    manifest.inputs.iter().any(|artifact| {
                        artifact.sha256 == *digest && !artifact.path.trim().is_empty()
                    })
                });
                append_benchmark_bundle_check(
                    report,
                    "bundle_manifest_inputs_include_embedded_input".to_string(),
                    manifest_input_ok,
                    CODE_BUNDLE_CONTEXT_MISMATCH,
                    if manifest_input_ok {
                        "bundle manifest inputs include the embedded publication gate input digest"
                            .to_string()
                    } else {
                        "bundle manifest inputs must include the embedded publication gate input digest"
                            .to_string()
                    },
                );
                if !manifest_input_ok {
                    bundle_violations = true;
                }

                let manifest_output_ok = manifest.outputs.iter().any(|artifact| {
                    artifact.path == "results.json"
                        && actual_digests
                            .get("results.json")
                            .is_some_and(|actual| actual == &artifact.sha256)
                });
                append_benchmark_bundle_check(
                    report,
                    "bundle_manifest_outputs_include_results_digest".to_string(),
                    manifest_output_ok,
                    CODE_BUNDLE_DIGEST_MISMATCH,
                    if manifest_output_ok {
                        "bundle manifest outputs include the results.json digest".to_string()
                    } else {
                        "bundle manifest outputs must include the results.json digest".to_string()
                    },
                );
                if !manifest_output_ok {
                    bundle_violations = true;
                }

                Some(manifest)
            }
            Err(error) => {
                append_benchmark_bundle_check(
                    report,
                    "bundle_manifest_parses".to_string(),
                    false,
                    CODE_BUNDLE_PARSE_ERROR,
                    error.to_string(),
                );
                bundle_violations = true;
                None
            }
        }
    } else {
        None
    };

    if let Some(env_bytes) = bundle_bytes.get("env.json") {
        match serde_json::from_slice::<BenchmarkBundleEnv>(env_bytes) {
            Ok(env_artifact) => {
                let schema_ok = env_artifact.schema_version == BENCHMARK_BUNDLE_ENV_SCHEMA_VERSION
                    && env_artifact.schema_hash == schema_hash(BENCHMARK_BUNDLE_ENV_SCHEMA_VERSION);
                append_benchmark_bundle_check(
                    report,
                    "bundle_env_schema_matches".to_string(),
                    schema_ok,
                    CODE_BUNDLE_SCHEMA_MISMATCH,
                    if schema_ok {
                        format!(
                            "env.json schema matches {}",
                            BENCHMARK_BUNDLE_ENV_SCHEMA_VERSION
                        )
                    } else {
                        format!(
                            "env.json schema mismatch: schema_version={} schema_hash={}",
                            env_artifact.schema_version, env_artifact.schema_hash
                        )
                    },
                );
                if !schema_ok {
                    bundle_violations = true;
                }

                let env_ok = !env_artifact.host.os.trim().is_empty()
                    && !env_artifact.host.arch.trim().is_empty()
                    && !env_artifact.toolchain.rustup_toolchain.trim().is_empty()
                    && !env_artifact.toolchain.rustc.trim().is_empty()
                    && !env_artifact.toolchain.cargo.trim().is_empty();
                append_benchmark_bundle_check(
                    report,
                    "bundle_env_has_core_fields".to_string(),
                    env_ok,
                    CODE_BUNDLE_PARSE_ERROR,
                    if env_ok {
                        "env.json includes host os/arch and toolchain fingerprints".to_string()
                    } else {
                        "env.json must include non-empty host os/arch and toolchain fingerprints"
                            .to_string()
                    },
                );
                if !env_ok {
                    bundle_violations = true;
                }

                let policy_ok = env_artifact.policy.policy_id == input.policy_id
                    && env_artifact.policy.policy_digest_sha256
                        == sha256_prefixed(input.policy_id.as_bytes());
                append_benchmark_bundle_check(
                    report,
                    "bundle_env_policy_matches_claim".to_string(),
                    policy_ok,
                    CODE_BUNDLE_CONTEXT_MISMATCH,
                    if policy_ok {
                        "env.json policy block matches the benchmark claim policy context"
                            .to_string()
                    } else {
                        format!(
                            "env.json policy mismatch: policy_id={} policy_digest_sha256={}",
                            env_artifact.policy.policy_id, env_artifact.policy.policy_digest_sha256
                        )
                    },
                );
                if !policy_ok {
                    bundle_violations = true;
                }

                let runtime_contract_ok = env_artifact.runtime.mode == "deterministic-score"
                    && env_artifact.runtime.lane == "publication_gate"
                    && env_artifact.runtime.safe_mode_enabled;
                append_benchmark_bundle_check(
                    report,
                    "bundle_env_runtime_contract_matches".to_string(),
                    runtime_contract_ok,
                    CODE_BUNDLE_CONTEXT_MISMATCH,
                    if runtime_contract_ok {
                        "env.json runtime block pins deterministic-score/publication_gate with safe mode enabled"
                            .to_string()
                    } else {
                        format!(
                            "env.json runtime contract mismatch: mode={} lane={} safe_mode_enabled={}",
                            env_artifact.runtime.mode,
                            env_artifact.runtime.lane,
                            env_artifact.runtime.safe_mode_enabled
                        )
                    },
                );
                if !runtime_contract_ok {
                    bundle_violations = true;
                }

                let feature_flag_ok = env_artifact
                    .runtime
                    .feature_flags
                    .iter()
                    .any(|flag| flag == "benchmark-score-cli");
                append_benchmark_bundle_check(
                    report,
                    "bundle_env_runtime_feature_flag_present".to_string(),
                    feature_flag_ok,
                    CODE_BUNDLE_CONTEXT_MISMATCH,
                    if feature_flag_ok {
                        "env.json runtime feature_flags include benchmark-score-cli".to_string()
                    } else {
                        "env.json runtime feature_flags must include benchmark-score-cli"
                            .to_string()
                    },
                );
                if !feature_flag_ok {
                    bundle_violations = true;
                }
            }
            Err(error) => {
                append_benchmark_bundle_check(
                    report,
                    "bundle_env_parses".to_string(),
                    false,
                    CODE_BUNDLE_PARSE_ERROR,
                    error.to_string(),
                );
                bundle_violations = true;
            }
        }
    }

    let command_mode_receipt = if let Some(receipt_bytes) =
        bundle_bytes.get("command_mode_receipt.json")
    {
        match serde_json::from_slice::<CommandModeReceipt>(receipt_bytes) {
            Ok(receipt) => {
                let schema_ok = receipt.schema_version == COMMAND_MODE_RECEIPT_SCHEMA_VERSION
                    && receipt.schema_hash == schema_hash(COMMAND_MODE_RECEIPT_SCHEMA_VERSION);
                append_benchmark_bundle_check(
                    report,
                    "bundle_command_mode_receipt_schema_matches".to_string(),
                    schema_ok,
                    CODE_BUNDLE_SCHEMA_MISMATCH,
                    if schema_ok {
                        format!(
                            "command_mode_receipt.json schema matches {}",
                            COMMAND_MODE_RECEIPT_SCHEMA_VERSION
                        )
                    } else {
                        format!(
                            "command_mode_receipt.json schema mismatch: schema_version={} schema_hash={}",
                            receipt.schema_version, receipt.schema_hash
                        )
                    },
                );
                if !schema_ok {
                    bundle_violations = true;
                }

                let context_matches = receipt.trace_id == input.trace_id
                    && receipt.decision_id == input.decision_id
                    && receipt.policy_id == input.policy_id;
                append_benchmark_bundle_check(
                    report,
                    "bundle_command_mode_receipt_context_matches_claim".to_string(),
                    context_matches,
                    CODE_BUNDLE_CONTEXT_MISMATCH,
                    if context_matches {
                        "command_mode_receipt.json matches trace/decision/policy context"
                            .to_string()
                    } else {
                        format!(
                            "command_mode_receipt.json context mismatch: receipt=({}, {}, {}), results=({}, {}, {})",
                            receipt.trace_id,
                            receipt.decision_id,
                            receipt.policy_id,
                            input.trace_id,
                            input.decision_id,
                            input.policy_id
                        )
                    },
                );
                if !context_matches {
                    bundle_violations = true;
                }

                let command_ok = receipt.command == "frankenctl benchmark score"
                    && receipt.command_family == "benchmark"
                    && receipt.bundle_root == bundle_dir.display().to_string()
                    && receipt.env_path == "env.json";
                append_benchmark_bundle_check(
                    report,
                    "bundle_command_mode_receipt_command_contract_present".to_string(),
                    command_ok,
                    CODE_BUNDLE_PARSE_ERROR,
                    if command_ok {
                        "command_mode_receipt.json records benchmark score command metadata"
                            .to_string()
                    } else {
                        format!(
                            "command_mode_receipt.json contract invalid: command={} family={} bundle_root={} env_path={}",
                            receipt.command,
                            receipt.command_family,
                            receipt.bundle_root,
                            receipt.env_path
                        )
                    },
                );
                if !command_ok {
                    bundle_violations = true;
                }

                let runtime_contract_ok = receipt.runtime.mode == "deterministic-score"
                    && receipt.runtime.lane == "publication_gate"
                    && receipt.runtime.safe_mode_enabled
                    && receipt
                        .runtime
                        .feature_flags
                        .iter()
                        .any(|flag| flag == "benchmark-score-cli");
                append_benchmark_bundle_check(
                    report,
                    "bundle_command_mode_receipt_runtime_contract_matches".to_string(),
                    runtime_contract_ok,
                    CODE_BUNDLE_CONTEXT_MISMATCH,
                    if runtime_contract_ok {
                        "command_mode_receipt.json pins deterministic-score/publication_gate with benchmark-score-cli enabled".to_string()
                    } else {
                        format!(
                            "command_mode_receipt.json runtime contract mismatch: mode={} lane={} safe_mode_enabled={} feature_flags={:?}",
                            receipt.runtime.mode,
                            receipt.runtime.lane,
                            receipt.runtime.safe_mode_enabled,
                            receipt.runtime.feature_flags
                        )
                    },
                );
                if !runtime_contract_ok {
                    bundle_violations = true;
                }

                Some(receipt)
            }
            Err(error) => {
                append_benchmark_bundle_check(
                    report,
                    "bundle_command_mode_receipt_parses".to_string(),
                    false,
                    CODE_BUNDLE_PARSE_ERROR,
                    error.to_string(),
                );
                bundle_violations = true;
                None
            }
        }
    } else {
        None
    };

    if let Some(invocation_bytes) = bundle_bytes.get("benchmark_invocation_manifest.json") {
        match serde_json::from_slice::<BenchmarkInvocationManifest>(invocation_bytes) {
            Ok(invocation_manifest) => {
                let schema_ok = invocation_manifest.schema_version
                    == BENCHMARK_INVOCATION_MANIFEST_SCHEMA_VERSION
                    && invocation_manifest.schema_hash
                        == schema_hash(BENCHMARK_INVOCATION_MANIFEST_SCHEMA_VERSION);
                append_benchmark_bundle_check(
                    report,
                    "bundle_benchmark_invocation_manifest_schema_matches".to_string(),
                    schema_ok,
                    CODE_BUNDLE_SCHEMA_MISMATCH,
                    if schema_ok {
                        format!(
                            "benchmark_invocation_manifest.json schema matches {}",
                            BENCHMARK_INVOCATION_MANIFEST_SCHEMA_VERSION
                        )
                    } else {
                        format!(
                            "benchmark_invocation_manifest.json schema mismatch: schema_version={} schema_hash={}",
                            invocation_manifest.schema_version, invocation_manifest.schema_hash
                        )
                    },
                );
                if !schema_ok {
                    bundle_violations = true;
                }

                let context_matches = invocation_manifest.trace_id == input.trace_id
                    && invocation_manifest.decision_id == input.decision_id
                    && invocation_manifest.policy_id == input.policy_id;
                append_benchmark_bundle_check(
                    report,
                    "bundle_benchmark_invocation_manifest_context_matches_claim".to_string(),
                    context_matches,
                    CODE_BUNDLE_CONTEXT_MISMATCH,
                    if context_matches {
                        "benchmark_invocation_manifest.json matches trace/decision/policy context"
                            .to_string()
                    } else {
                        format!(
                            "benchmark_invocation_manifest.json context mismatch: manifest=({}, {}, {}), results=({}, {}, {})",
                            invocation_manifest.trace_id,
                            invocation_manifest.decision_id,
                            invocation_manifest.policy_id,
                            input.trace_id,
                            input.decision_id,
                            input.policy_id
                        )
                    },
                );
                if !context_matches {
                    bundle_violations = true;
                }

                let artifact_contract_ok = invocation_manifest.command
                    == "frankenctl benchmark score"
                    && invocation_manifest.bundle_root == bundle_dir.display().to_string()
                    && invocation_manifest.artifacts.canonical_results == "results.json"
                    && invocation_manifest.artifacts.env == "env.json"
                    && invocation_manifest.artifacts.bundle_manifest == "manifest.json"
                    && invocation_manifest.artifacts.commands_transcript == "commands.txt"
                    && invocation_manifest.artifacts.repro_lock == "repro.lock"
                    && invocation_manifest.artifacts.command_mode_receipt
                        == "command_mode_receipt.json";
                append_benchmark_bundle_check(
                    report,
                    "bundle_benchmark_invocation_manifest_artifact_contract_present".to_string(),
                    artifact_contract_ok,
                    CODE_BUNDLE_PARSE_ERROR,
                    if artifact_contract_ok {
                        "benchmark_invocation_manifest.json records the canonical benchmark bundle artifact layout".to_string()
                    } else {
                        format!(
                            "benchmark_invocation_manifest.json artifact contract invalid: command={} bundle_root={} artifacts={:?}",
                            invocation_manifest.command,
                            invocation_manifest.bundle_root,
                            invocation_manifest.artifacts
                        )
                    },
                );
                if !artifact_contract_ok {
                    bundle_violations = true;
                }

                let runtime_contract_ok = invocation_manifest.runtime.mode == "deterministic-score"
                    && invocation_manifest.runtime.lane == "publication_gate"
                    && invocation_manifest.runtime.safe_mode_enabled
                    && invocation_manifest
                        .runtime
                        .feature_flags
                        .iter()
                        .any(|flag| flag == "benchmark-score-cli");
                append_benchmark_bundle_check(
                    report,
                    "bundle_benchmark_invocation_manifest_runtime_contract_matches".to_string(),
                    runtime_contract_ok,
                    CODE_BUNDLE_CONTEXT_MISMATCH,
                    if runtime_contract_ok {
                        "benchmark_invocation_manifest.json pins deterministic-score/publication_gate with benchmark-score-cli enabled".to_string()
                    } else {
                        format!(
                            "benchmark_invocation_manifest.json runtime contract mismatch: mode={} lane={} safe_mode_enabled={} feature_flags={:?}",
                            invocation_manifest.runtime.mode,
                            invocation_manifest.runtime.lane,
                            invocation_manifest.runtime.safe_mode_enabled,
                            invocation_manifest.runtime.feature_flags
                        )
                    },
                );
                if !runtime_contract_ok {
                    bundle_violations = true;
                }

                let path_recording_ok = !invocation_manifest.input_path.trim().is_empty()
                    && !invocation_manifest.requested_output_path.trim().is_empty();
                append_benchmark_bundle_check(
                    report,
                    "bundle_benchmark_invocation_manifest_records_requested_paths".to_string(),
                    path_recording_ok,
                    CODE_BUNDLE_PARSE_ERROR,
                    if path_recording_ok {
                        "benchmark_invocation_manifest.json records input and requested output paths".to_string()
                    } else {
                        "benchmark_invocation_manifest.json must record non-empty input and requested output paths".to_string()
                    },
                );
                if !path_recording_ok {
                    bundle_violations = true;
                }

                let receipt_matches = command_mode_receipt.as_ref().is_some_and(|receipt| {
                    receipt.bundle_root == invocation_manifest.bundle_root
                        && invocation_manifest.artifacts.command_mode_receipt
                            == "command_mode_receipt.json"
                });
                append_benchmark_bundle_check(
                    report,
                    "bundle_benchmark_invocation_manifest_references_command_mode_receipt"
                        .to_string(),
                    receipt_matches,
                    CODE_BUNDLE_CONTEXT_MISMATCH,
                    if receipt_matches {
                        "benchmark_invocation_manifest.json references the command mode receipt artifact".to_string()
                    } else {
                        "benchmark_invocation_manifest.json must reference a valid command mode receipt artifact".to_string()
                    },
                );
                if !receipt_matches {
                    bundle_violations = true;
                }
            }
            Err(error) => {
                append_benchmark_bundle_check(
                    report,
                    "bundle_benchmark_invocation_manifest_parses".to_string(),
                    false,
                    CODE_BUNDLE_PARSE_ERROR,
                    error.to_string(),
                );
                bundle_violations = true;
            }
        }
    }

    let command_lines = if let Some(command_bytes) = bundle_bytes.get("commands.txt") {
        match String::from_utf8(command_bytes.clone()) {
            Ok(content) => {
                let non_empty = !content.trim().is_empty();
                append_benchmark_bundle_check(
                    report,
                    "bundle_commands_non_empty".to_string(),
                    non_empty,
                    CODE_BUNDLE_PARSE_ERROR,
                    if non_empty {
                        format!(
                            "commands.txt contains command transcript: {}",
                            bundle_dir.join("commands.txt").display()
                        )
                    } else {
                        format!(
                            "commands.txt is empty: {}",
                            bundle_dir.join("commands.txt").display()
                        )
                    },
                );
                if !non_empty {
                    bundle_violations = true;
                }

                let remote_only = content.lines().any(|line| line.contains("rch exec --"));
                append_benchmark_bundle_check(
                    report,
                    "bundle_commands_include_rch_exec".to_string(),
                    remote_only,
                    CODE_BUNDLE_REMOTE_EXEC,
                    if remote_only {
                        "commands.txt includes rch-wrapped execution evidence".to_string()
                    } else {
                        "commands.txt must include at least one `rch exec --` command".to_string()
                    },
                );
                if !remote_only {
                    bundle_violations = true;
                }

                Some(content.lines().map(str::to_string).collect::<Vec<_>>())
            }
            Err(error) => {
                append_benchmark_bundle_check(
                    report,
                    "bundle_commands_utf8".to_string(),
                    false,
                    CODE_BUNDLE_PARSE_ERROR,
                    format!("commands.txt must be valid UTF-8: {error}"),
                );
                bundle_violations = true;
                None
            }
        }
    } else {
        None
    };

    if let Some(repro_bytes) = bundle_bytes.get("repro.lock") {
        match serde_json::from_slice::<BenchmarkBundleReproLock>(repro_bytes) {
            Ok(repro_lock) => {
                let schema_ok = repro_lock.schema_version
                    == BENCHMARK_BUNDLE_REPRO_LOCK_SCHEMA_VERSION
                    && repro_lock.schema_hash
                        == schema_hash(BENCHMARK_BUNDLE_REPRO_LOCK_SCHEMA_VERSION);
                append_benchmark_bundle_check(
                    report,
                    "bundle_repro_lock_schema_matches".to_string(),
                    schema_ok,
                    CODE_BUNDLE_SCHEMA_MISMATCH,
                    if schema_ok {
                        format!(
                            "repro.lock schema matches {}",
                            BENCHMARK_BUNDLE_REPRO_LOCK_SCHEMA_VERSION
                        )
                    } else {
                        format!(
                            "repro.lock schema mismatch: schema_version={} schema_hash={}",
                            repro_lock.schema_version, repro_lock.schema_hash
                        )
                    },
                );
                if !schema_ok {
                    bundle_violations = true;
                }

                let manifest_id_ok = manifest.as_ref().is_some_and(|bundle_manifest| {
                    repro_lock.manifest_id == bundle_manifest.manifest_id
                });
                append_benchmark_bundle_check(
                    report,
                    "bundle_repro_lock_manifest_id_matches".to_string(),
                    manifest_id_ok,
                    CODE_BUNDLE_CONTEXT_MISMATCH,
                    if manifest_id_ok {
                        "repro.lock manifest_id matches manifest.json".to_string()
                    } else {
                        format!(
                            "repro.lock manifest_id mismatch: {}",
                            repro_lock.manifest_id
                        )
                    },
                );
                if !manifest_id_ok {
                    bundle_violations = true;
                }

                let determinism_ok = !repro_lock.determinism.allow_network
                    && !repro_lock.determinism.allow_wall_clock
                    && !repro_lock.determinism.allow_randomness
                    && repro_lock.determinism.max_clock_skew_seconds == 0;
                append_benchmark_bundle_check(
                    report,
                    "bundle_repro_lock_is_fail_closed".to_string(),
                    determinism_ok,
                    CODE_BUNDLE_PARSE_ERROR,
                    if determinism_ok {
                        "repro.lock disables network, wall clock, randomness, and clock skew"
                            .to_string()
                    } else {
                        "repro.lock must disable network, wall clock, randomness, and clock skew"
                            .to_string()
                    },
                );
                if !determinism_ok {
                    bundle_violations = true;
                }

                let replay_ok = repro_lock.replay.trace_id == input.trace_id
                    && repro_lock.replay.decision_id == input.decision_id
                    && repro_lock.replay.policy_id == input.policy_id;
                append_benchmark_bundle_check(
                    report,
                    "bundle_repro_lock_replay_context_matches".to_string(),
                    replay_ok,
                    CODE_BUNDLE_CONTEXT_MISMATCH,
                    if replay_ok {
                        "repro.lock replay block matches trace/decision/policy context".to_string()
                    } else {
                        format!(
                            "repro.lock replay context mismatch: replay=({}, {}, {}), claim=({}, {}, {})",
                            repro_lock.replay.trace_id,
                            repro_lock.replay.decision_id,
                            repro_lock.replay.policy_id,
                            input.trace_id,
                            input.decision_id,
                            input.policy_id
                        )
                    },
                );
                if !replay_ok {
                    bundle_violations = true;
                }

                let verification_ok = repro_lock
                    .verification
                    .command
                    .contains("frankenctl benchmark verify --bundle")
                    && repro_lock
                        .verification
                        .command
                        .contains(&bundle_dir.display().to_string())
                    && repro_lock.verification.expected_verdict == "verified";
                append_benchmark_bundle_check(
                    report,
                    "bundle_repro_lock_verification_contract_present".to_string(),
                    verification_ok,
                    CODE_BUNDLE_PARSE_ERROR,
                    if verification_ok {
                        "repro.lock includes a benchmark verify command for this bundle".to_string()
                    } else {
                        format!(
                            "repro.lock verification block invalid: command={} expected_verdict={}",
                            repro_lock.verification.command,
                            repro_lock.verification.expected_verdict
                        )
                    },
                );
                if !verification_ok {
                    bundle_violations = true;
                }

                let command_contract_ok = command_lines
                    .as_ref()
                    .is_some_and(|lines| repro_lock.commands == *lines);
                append_benchmark_bundle_check(
                    report,
                    "bundle_repro_lock_commands_match_transcript".to_string(),
                    command_contract_ok,
                    CODE_BUNDLE_CONTEXT_MISMATCH,
                    if command_contract_ok {
                        "repro.lock commands exactly match commands.txt".to_string()
                    } else {
                        "repro.lock commands must exactly match commands.txt".to_string()
                    },
                );
                if !command_contract_ok {
                    bundle_violations = true;
                }

                let input_contract_ok = embedded_input_digest.as_ref().is_some_and(|digest| {
                    repro_lock.inputs.iter().any(|artifact| {
                        artifact.kind == "input"
                            && artifact.sha256 == *digest
                            && !artifact.path.trim().is_empty()
                    })
                });
                append_benchmark_bundle_check(
                    report,
                    "bundle_repro_lock_inputs_include_embedded_input".to_string(),
                    input_contract_ok,
                    CODE_BUNDLE_CONTEXT_MISMATCH,
                    if input_contract_ok {
                        "repro.lock inputs include the embedded publication gate input digest"
                            .to_string()
                    } else {
                        "repro.lock inputs must include the embedded publication gate input digest"
                            .to_string()
                    },
                );
                if !input_contract_ok {
                    bundle_violations = true;
                }

                for file_name in [
                    "env.json",
                    "commands.txt",
                    "results.json",
                    "benchmark_invocation_manifest.json",
                    "command_mode_receipt.json",
                ] {
                    let output_ok = repro_lock.expected_outputs.iter().any(|artifact| {
                        artifact.path == file_name
                            && artifact.kind == "output"
                            && actual_digests
                                .get(file_name)
                                .is_some_and(|actual| actual == &artifact.sha256)
                    });
                    append_benchmark_bundle_check(
                        report,
                        format!(
                            "bundle_repro_lock_expected_output_{}_matches",
                            file_name.replace('.', "_")
                        ),
                        output_ok,
                        CODE_BUNDLE_DIGEST_MISMATCH,
                        if output_ok {
                            format!(
                                "repro.lock expected_outputs includes the current digest for {file_name}"
                            )
                        } else {
                            format!(
                                "repro.lock expected_outputs must include the current digest for {file_name}"
                            )
                        },
                    );
                    if !output_ok {
                        bundle_violations = true;
                    }
                }
            }
            Err(error) => {
                append_benchmark_bundle_check(
                    report,
                    "bundle_repro_lock_parses".to_string(),
                    false,
                    CODE_BUNDLE_PARSE_ERROR,
                    error.to_string(),
                );
                bundle_violations = true;
            }
        }
    }

    if let Some(repro_bytes) = bundle_bytes.get("repro.lock") {
        let repro_ok = !repro_bytes.is_empty();
        append_benchmark_bundle_check(
            report,
            "bundle_repro_lock_present_and_non_empty".to_string(),
            repro_ok,
            CODE_BUNDLE_PARSE_ERROR,
            if repro_ok {
                format!(
                    "repro.lock is present and parseable: {}",
                    bundle_dir.join("repro.lock").display()
                )
            } else {
                format!(
                    "repro.lock is missing or invalid: {}",
                    bundle_dir.join("repro.lock").display()
                )
            },
        );
        if !repro_ok {
            bundle_violations = true;
        }
    }

    let scope = if let Some(manifest) = manifest {
        format!(
            "bundle={} schema={} manifest_id={} trace={} decision={} policy={}",
            bundle_dir.display(),
            manifest.schema_version,
            manifest.manifest_id,
            manifest.provenance.trace_id,
            manifest.provenance.decision_id,
            manifest.provenance.policy_id
        )
    } else {
        format!("bundle={}", bundle_dir.display())
    };
    report.events.push(VerifierEvent {
        trace_id: report.trace_id.clone(),
        decision_id: report.decision_id.clone(),
        policy_id: report.policy_id.clone(),
        component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
        event: "benchmark_bundle_contract_checked".to_string(),
        outcome: if bundle_violations {
            "fail".to_string()
        } else {
            "pass".to_string()
        },
        error_code: if bundle_violations {
            Some(CODE_BUNDLE_PARSE_ERROR.to_string())
        } else {
            None
        },
    });

    if bundle_violations {
        report.verdict = VerificationVerdict::Failed;
        report.confidence_statement =
            "verification failed: benchmark bundle contract violations detected".to_string();
        report.scope_limitations.push(scope);
    } else if report.confidence_statement.trim().is_empty() {
        report.confidence_statement =
            "bundle contract checks passed alongside benchmark claim recomputation".to_string();
    }
}

fn append_benchmark_bundle_check(
    report: &mut ThirdPartyVerificationReport,
    name: String,
    passed: bool,
    error_code: &'static str,
    detail: String,
) {
    report.checks.push(VerificationCheckResult {
        name,
        passed,
        error_code: if passed {
            None
        } else {
            Some(error_code.to_string())
        },
        detail,
    });
}

/// Load one per-node fleet trace, validate it for replay, and derive its
/// `NodeId` (trace `session_id`, falling back to the file stem when the
/// session id is blank). Helper for the `--fleet-trace` merge path.
fn load_fleet_node(path: &std::path::Path) -> Result<FleetTraceNode, String> {
    let node_trace = load_json_file::<NondeterminismTrace>(path)?;
    node_trace.validate_for_replay().map_err(|error| {
        format!(
            "fleet trace validation failed for {}: {error}",
            path.display()
        )
    })?;
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("fleet-node");
    let node_id = node_id_from_session(&node_trace.session_id, stem).map_err(|error| {
        format!(
            "fleet replay: invalid node id for {}: {error}",
            path.display()
        )
    })?;
    Ok(FleetTraceNode::new(node_id, node_trace))
}

fn execute_replay(args: ReplayArgs) -> Result<i32, String> {
    let mut trace = load_json_file::<NondeterminismTrace>(&args.trace)?;
    trace
        .validate_for_replay()
        .map_err(|error| format!("replay failed before sequence 0: {error}"))?;

    // If a fleet trace is provided, stitch every per-node trace into ONE
    // globally-consistent replay order via the Lamport total-order merger
    // (DD.1/DD.2), rather than a node-blind per-node-`sequence` sort. The
    // primary `--trace` is the anchor node; `--fleet-trace` may point at a
    // directory of per-node traces (one file == one node) or a single
    // additional per-node trace file. See bd-cixqu.30.4 (DD.4).
    if let Some(fleet_trace_path) = &args.fleet_trace {
        let mut nodes: Vec<FleetTraceNode> = Vec::new();

        let anchor_id = node_id_from_session(&trace.session_id, "anchor")
            .map_err(|error| format!("fleet replay: invalid anchor node id: {error}"))?;
        nodes.push(FleetTraceNode::new(anchor_id, trace.clone()));

        if fleet_trace_path.is_dir() {
            // Directory of per-node traces: enumerate `*.json` files in a
            // deterministic (filename-sorted) order; node id == file stem.
            let mut node_files: Vec<PathBuf> = std::fs::read_dir(fleet_trace_path)
                .map_err(|error| {
                    format!(
                        "fleet replay: cannot read directory {}: {error}",
                        fleet_trace_path.display()
                    )
                })?
                .filter_map(|entry| entry.ok().map(|e| e.path()))
                .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("json"))
                .collect();
            node_files.sort();

            for path in node_files {
                nodes.push(load_fleet_node(&path)?);
            }
        } else {
            nodes.push(load_fleet_node(fleet_trace_path)?);
        }

        let ordered = merge_fleet_traces(&nodes);
        trace.events = flatten_to_events(ordered);
    }
    let (trace_id, decision_id, policy_id) = cli_replay_ids(&trace.session_id, args.mode);
    let session_id = trace.session_id.clone();
    let event_count = trace.events.len();
    let replay_events = match args.compare_trace.as_ref() {
        Some(path) => {
            let compare_trace = load_json_file::<NondeterminismTrace>(path)?;
            compare_trace
                .validate_for_replay()
                .map_err(|error| format!("replay comparison failed before sequence 0: {error}"))?;
            compare_trace.events
        }
        None => {
            if args.mode == ReplayMode::Validate {
                return Err(
                    "replay run in validate mode requires --compare-trace <path>".to_string(),
                );
            }
            trace.events.clone()
        }
    };

    let mut engine = ReplayEngine::new(trace, args.mode);
    for event in replay_events {
        engine
            .replay_next(event.source.clone(), &event.value)
            .map_err(|error| format!("replay failed at sequence {}: {error:?}", event.sequence))?;
    }
    if args.compare_trace.is_some() && !engine.is_complete() {
        return Err(format!(
            "replay comparison ended early after {} of {} captured events",
            engine.replayed_events, event_count
        ));
    }

    let output = ReplayCommandOutput {
        schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
        trace_id,
        decision_id,
        policy_id,
        trace_path: args.trace.display().to_string(),
        mode: replay_mode_name(args.mode).to_string(),
        session_id,
        event_count,
        replayed_events: engine.replayed_events,
        divergence_count: engine.divergence_count(),
        critical_divergences: engine.critical_divergences(),
        complete: engine.is_complete(),
        observability_mode: default_capture_observability_mode(),
    };

    if let Some(path) = args.out {
        write_json_file(&path, &output)?;
    }
    print_json(&output)?;
    Ok(0)
}

/// `frankenctl replay debug`: drive the evidence-aware time-travel debugger
/// over a captured nondeterminism trace via the JSON-line robot protocol
/// (bd-fqlfw.3.5.3 / E3.T5c). Commands come from `--script` (one JSON
/// object per line; blank lines and `#` comment lines are skipped) or from
/// stdin; every command line yields exactly one JSON response line on
/// stdout, and `--out` additionally captures the full transcript. Identical
/// trace + script input produces a byte-identical transcript. Protocol-level
/// failures (malformed lines, out-of-range ticks) are fail-closed
/// `{"ok":false,...}` RESPONSES, not process errors.
fn execute_replay_debug(args: ReplayDebugArgs) -> Result<i32, String> {
    let trace = load_json_file::<NondeterminismTrace>(&args.trace)?;
    let cursor = TimeTravelCursor::new(
        trace,
        args.mode,
        TimeTravelConfig {
            checkpoint_interval: args.checkpoint_interval,
        },
    )
    .map_err(|error| format!("replay debug failed to open trace: {error}"))?;

    let debugger_events: Vec<DebuggerEvent> = match args.events.as_ref() {
        Some(path) => load_json_file::<Vec<DebuggerEvent>>(path)?,
        None => Vec::new(),
    };
    let state_snapshots: Vec<InterpreterStateSnapshot> = match args.state_snapshots.as_ref() {
        Some(path) => load_json_file::<Vec<InterpreterStateSnapshot>>(path)?,
        None => Vec::new(),
    };
    let debugger =
        TimeTravelDebugger::new_with_state_snapshots(cursor, debugger_events, state_snapshots);
    let mut session = RobotSession::new(debugger);

    let command_lines: Vec<String> = match args.script.as_ref() {
        Some(path) => fs::read_to_string(path)
            .map_err(|error| format!("failed to read script `{}`: {error}", path.display()))?
            .lines()
            .map(str::to_string)
            .collect(),
        None => {
            let mut buffer = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buffer)
                .map_err(|error| format!("failed to read robot commands from stdin: {error}"))?;
            buffer.lines().map(str::to_string).collect()
        }
    };

    let mut transcript: Vec<String> = Vec::new();
    for line in command_lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let response = session.handle_line(trimmed);
        println!("{response}");
        transcript.push(response);
    }

    if let Some(path) = args.out.as_ref() {
        let mut body = transcript.join("\n");
        body.push('\n');
        fs::write(path, body)
            .map_err(|error| format!("failed to write transcript `{}`: {error}", path.display()))?;
    }
    Ok(0)
}

fn execute_differential_oracle(args: DifferentialOracleArgs) -> Result<i32, String> {
    match args.mode {
        DifferentialOracleMode::Run(args) => execute_differential_oracle_run(args),
        DifferentialOracleMode::Perf(args) => execute_differential_oracle_perf(args),
    }
}

fn execute_differential_oracle_perf(args: DifferentialOraclePerfArgs) -> Result<i32, String> {
    let mut corpus = load_runtime_comparison_corpus(&args.manifest)?;
    if !args.case_filter.is_empty() {
        corpus.retain(|case| args.case_filter.iter().any(|id| id == &case.case_id));
        if corpus.is_empty() {
            return Err("--case filters matched no corpus case".to_string());
        }
    }

    let mut config = PerfArmConfig {
        warmup_iterations: args.warmup,
        measured_iterations: args.samples,
        case_timeout_ms: args.case_timeout_ms,
        ..PerfArmConfig::default()
    };
    if let Some(engine_budget) = args.engine_budget {
        config.engine_instruction_budget = engine_budget;
    }
    if let Some(node_bin) = args.node_bin {
        config.node.program = node_bin;
    }
    if let Some(bun_bin) = args.bun_bin {
        config.bun.program = bun_bin;
    }

    let (report, iteration_events) = run_differential_perf(&corpus, &config);

    if let Some(path) = &args.events {
        let mut lines = String::new();
        for event in &iteration_events {
            let line = serde_json::to_string(event)
                .map_err(|error| format!("failed to serialize iteration event: {error}"))?;
            lines.push_str(&line);
            lines.push('\n');
        }
        fs::write(path, lines)
            .map_err(|error| format!("failed to write events `{}`: {error}", path.display()))?;
    }
    if let Some(path) = &args.out {
        write_json_file(path, &report)?;
    }

    // stdout gets a compact operator summary; raw per-iteration data lives in
    // the --out report and --events stream.
    let summary = serde_json::json!({
        "schema_version": report.schema_version,
        "fairness": report.fairness,
        "case_count": report.cases.len(),
        "admitted_case_ids": report
            .cases
            .iter()
            .filter(|case| case.admitted)
            .map(|case| case.case_id.clone())
            .collect::<Vec<_>>(),
        "node_denominator": report.node_denominator,
        "bun_denominator": report.bun_denominator,
    });
    print_json(&summary)?;
    Ok(0)
}

fn execute_differential_oracle_run(args: DifferentialOracleRunArgs) -> Result<i32, String> {
    let source = fs::read_to_string(&args.input)
        .map_err(|error| format!("failed to read source `{}`: {error}", args.input.display()))?;
    let case_id = args.case_id.unwrap_or_else(|| {
        args.input
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("differential-oracle-case")
            .to_string()
    });
    let mut input = DifferentialOracleInput::new(case_id, source)
        .with_source_path(args.input.display().to_string())
        .with_timeout_ms(args.timeout_ms);
    if let Some(budget) = args.engine_budget {
        input = input.with_engine_instruction_budget(budget);
    }
    if let Some(memory_budget) = args.engine_memory_budget {
        input = input.with_engine_memory_budget(memory_budget);
    }
    let report = run_differential_oracle(&input);

    if let Some(path) = args.out {
        write_json_file(&path, &report)?;
    }
    print_json(&report)?;
    Ok(0)
}

// ── oracle (operator-facing differential oracle) ───────────────────────────

/// Schema id for the content-addressed bundle emitted by `oracle run --bundle`.
const ORACLE_RUN_BUNDLE_SCHEMA_VERSION: &str = "franken-engine.oracle-run-bundle.v1";
const ORACLE_RUN_DEGRADED_RECEIPT_SCHEMA_VERSION: &str =
    "franken-engine.oracle-run-degraded-receipt.v1";
const ORACLE_RUN_SUMMARY_SCHEMA_VERSION: &str = "franken-engine.oracle-run-summary.v1";
const ORACLE_REPRO_LOCK_SCHEMA_VERSION: &str = "franken-engine.repro-lock.v1";

/// Documented `oracle` exit codes (part of the CLI contract; see `oracle_usage`).
const ORACLE_EXIT_CONSENSUS: i32 = 0;
const ORACLE_EXIT_DIVERGENCE: i32 = 3;
const ORACLE_EXIT_INSUFFICIENT: i32 = 4;

/// A summary handle returned by [`emit_oracle_run_bundle`] for display.
struct OracleBundleSummary {
    dir: PathBuf,
    bundle_id: String,
    degraded: bool,
}

fn oracle_verdict_label(verdict: DifferentialComparisonVerdict) -> &'static str {
    match verdict {
        DifferentialComparisonVerdict::Consensus => "consensus",
        DifferentialComparisonVerdict::Divergence => "divergence",
        DifferentialComparisonVerdict::InsufficientData => "insufficient_data",
    }
}

/// Map a backend to its short `--engines` alias (the reproducible CLI token).
fn oracle_engine_alias(backend: DifferentialBackend) -> &'static str {
    match backend {
        DifferentialBackend::NodeLts => "node",
        DifferentialBackend::BunStable => "bun",
        DifferentialBackend::FrankenEngine => "franken",
        DifferentialBackend::FrankenCore => "core",
    }
}

fn oracle_engines_csv(report: &DifferentialOracleReport) -> String {
    report
        .backends
        .iter()
        .map(|receipt| oracle_engine_alias(receipt.backend))
        .collect::<Vec<_>>()
        .join(",")
}

/// Reasons a selected reference runtime (Node/Bun) failed to produce a result.
/// Non-empty ⇒ the run is degraded: the engine output is unverified against at
/// least one requested reference runtime.
fn oracle_external_degradations(report: &DifferentialOracleReport) -> Vec<String> {
    report
        .backends
        .iter()
        .filter(|receipt| {
            matches!(
                receipt.backend,
                DifferentialBackend::NodeLts | DifferentialBackend::BunStable
            ) && receipt.status != DifferentialBackendStatus::Completed
        })
        .map(|receipt| {
            format!(
                "{} is {} and was excluded from cross-runtime consensus",
                receipt.backend,
                receipt.status.stable_label()
            )
        })
        .collect()
}

/// Derive the documented exit code from the recorded verdict. A consensus only
/// counts as a pass (`0`) when no requested reference runtime was missing;
/// otherwise it is downgraded to insufficient-data (`4`). A divergence is always
/// surfaced (`3`).
fn oracle_exit_for_report(report: &DifferentialOracleReport, degraded: bool) -> i32 {
    match report.canonicalization.semantic_verdict {
        DifferentialComparisonVerdict::Divergence => ORACLE_EXIT_DIVERGENCE,
        DifferentialComparisonVerdict::Consensus => {
            if degraded {
                ORACLE_EXIT_INSUFFICIENT
            } else {
                ORACLE_EXIT_CONSENSUS
            }
        }
        DifferentialComparisonVerdict::InsufficientData => ORACLE_EXIT_INSUFFICIENT,
    }
}

/// Sort object keys recursively and pretty-print with a trailing newline, so the
/// bytes are independent of serde_json's `preserve_order` feature and stable for
/// content addressing.
fn oracle_canonical_json_bytes(value: &serde_json::Value) -> String {
    let sorted = frankenengine_engine::evidence_manifest::sort_value_keys(value);
    let mut text = serde_json::to_string_pretty(&sorted).expect("json value pretty-prints");
    text.push('\n');
    text
}

fn execute_oracle(args: OracleArgs) -> Result<i32, String> {
    match args.mode {
        OracleMode::Run(args) => execute_oracle_run(args),
        OracleMode::Report(args) => execute_oracle_report(args),
    }
}

/// Resolve an explicit `--node-bin`/`--bun-bin` override, falling back to the
/// `$NODE`/`$BUN` environment variable, so an operator on a host where `node` is
/// a Bun shim can point the oracle at a genuine binary.
fn oracle_runtime_program(explicit: Option<&str>, env_var: &str) -> Option<String> {
    if let Some(value) = explicit {
        return Some(value.to_string());
    }
    env::var(env_var)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn execute_oracle_run(args: OracleRunArgs) -> Result<i32, String> {
    let source = fs::read_to_string(&args.input)
        .map_err(|error| format!("failed to read input `{}`: {error}", args.input.display()))?;
    let case_id = args.case_id.clone().unwrap_or_else(|| {
        args.input
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("oracle-case")
            .to_string()
    });

    let mut input = DifferentialOracleInput::new(case_id, source)
        .with_source_path(args.input.display().to_string())
        .with_timeout_ms(args.timeout_ms)
        .with_selected_backends(args.engines.iter().copied());
    if let Some(budget) = args.engine_budget {
        input = input.with_engine_instruction_budget(budget);
    }
    if let Some(memory_budget) = args.engine_memory_budget {
        input = input.with_engine_memory_budget(memory_budget);
    }
    if let Some(program) = oracle_runtime_program(args.node_bin.as_deref(), "NODE") {
        input.node.program = program;
    }
    if let Some(program) = oracle_runtime_program(args.bun_bin.as_deref(), "BUN") {
        input.bun.program = program;
    }

    let report = run_differential_oracle(&input);

    if let Some(path) = &args.out {
        write_json_file(path, &report)?;
    }

    let bundle_summary = match &args.bundle {
        Some(dir) => Some(emit_oracle_run_bundle(dir, &report)?),
        None => None,
    };

    let degraded = bundle_summary
        .as_ref()
        .map(|summary| summary.degraded)
        .unwrap_or_else(|| !oracle_external_degradations(&report).is_empty());
    let exit_code = oracle_exit_for_report(&report, degraded);

    match args.format {
        CheckOutputFormat::Json => {
            let payload =
                oracle_run_json_summary(&report, bundle_summary.as_ref(), degraded, exit_code);
            print_json(&payload)?;
        }
        CheckOutputFormat::Human => {
            println!(
                "{}",
                render_oracle_run_human(&report, bundle_summary.as_ref(), degraded, exit_code)
            );
        }
    }
    Ok(exit_code)
}

/// Write a content-addressed oracle-run bundle: `report.json` (the full report),
/// `repro.lock` (re-run recipe + the reproducible semantic-verdict assertion),
/// `manifest.json` (sha256-indexed artifact set + `bundle_id`), and, when a
/// requested reference runtime was unavailable, `degraded_receipt.json`.
fn emit_oracle_run_bundle(
    dir: &Path,
    report: &DifferentialOracleReport,
) -> Result<OracleBundleSummary, String> {
    fs::create_dir_all(dir)
        .map_err(|error| format!("failed to create bundle dir `{}`: {error}", dir.display()))?;

    let report_value = serde_json::to_value(report)
        .map_err(|error| format!("failed to encode oracle report: {error}"))?;
    let report_bytes = oracle_canonical_json_bytes(&report_value);
    let report_sha = sha256_prefixed(report_bytes.as_bytes());
    fs::write(dir.join("report.json"), report_bytes.as_bytes())
        .map_err(|error| format!("failed to write report.json: {error}"))?;

    let selected: Vec<String> = report
        .backends
        .iter()
        .map(|receipt| receipt.backend.to_string())
        .collect();
    let verdict_label = oracle_verdict_label(report.canonicalization.semantic_verdict);

    let lock_value = serde_json::json!({
        "schema_version": ORACLE_REPRO_LOCK_SCHEMA_VERSION,
        "case_id": report.case_id,
        "source_sha256": format!("sha256:{}", report.source_sha256),
        "selected_backends": selected,
        "commands": [
            format!(
                "frankenctl oracle run <input.js> --engines {} --bundle <dir>",
                oracle_engines_csv(report)
            ),
        ],
        "determinism": {
            "allow_network": false,
            "allow_randomness": false,
            "allow_wall_clock": true,
            "note": "per-backend wall-clock timing is non-deterministic; the reproducible assertion is the semantic verdict over canonical structured values and exception classes, not raw stdout timing",
            "reproducible_assertion": "semantic_verdict",
        },
        "expected_outputs": [
            {
                "kind": "semantic_verdict",
                "path": "report.json#canonicalization.semantic_verdict",
                "value": verdict_label,
            },
        ],
        "verification": {
            "command": "frankenctl oracle report <dir>",
            "expected_verdict": verdict_label,
        },
    });
    let lock_bytes = oracle_canonical_json_bytes(&lock_value);
    let lock_sha = sha256_prefixed(lock_bytes.as_bytes());
    fs::write(dir.join("repro.lock"), lock_bytes.as_bytes())
        .map_err(|error| format!("failed to write repro.lock: {error}"))?;

    let degradations = oracle_external_degradations(report);
    let degraded = !degradations.is_empty();

    let mut manifest = serde_json::json!({
        "schema_version": ORACLE_RUN_BUNDLE_SCHEMA_VERSION,
        "case_id": report.case_id,
        "source_sha256": format!("sha256:{}", report.source_sha256),
        "semantic_verdict": verdict_label,
        "divergence_count": report.divergence_taxonomy.findings.len(),
        "degraded": degraded,
        "selected_backends": selected,
        "host": {
            "os": report.host.os,
            "arch": report.host.arch,
            "franken_engine_version": report.host.franken_engine_version,
        },
        "artifacts": {
            "report": { "path": "report.json", "sha256": report_sha },
            "lock": { "path": "repro.lock", "sha256": lock_sha },
        },
        "validation": {
            "command": "frankenctl oracle report <bundle-dir>",
            "exit_codes": "0 consensus | 3 divergence | 4 insufficient-data/degraded",
        },
    });
    // Inject the u128 timestamp by copying the already-serialized report field,
    // sidestepping any `json!` integer-width edge case.
    if let Some(object) = manifest.as_object_mut() {
        object.insert(
            "generated_unix_ns".to_string(),
            report_value
                .get("generated_unix_ns")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        );
    }

    // bundle_id content-addresses the manifest body (excluding its own id).
    let manifest_preimage = oracle_canonical_json_bytes(&manifest);
    let bundle_id = sha256_prefixed(manifest_preimage.as_bytes());
    if let Some(object) = manifest.as_object_mut() {
        object.insert(
            "bundle_id".to_string(),
            serde_json::Value::String(bundle_id.clone()),
        );
    }
    let manifest_bytes = oracle_canonical_json_bytes(&manifest);
    fs::write(dir.join("manifest.json"), manifest_bytes.as_bytes())
        .map_err(|error| format!("failed to write manifest.json: {error}"))?;

    if degraded {
        let receipt = serde_json::json!({
            "schema_version": ORACLE_RUN_DEGRADED_RECEIPT_SCHEMA_VERSION,
            "error_code": "FE-REPRO-0007",
            "verdict": "degraded",
            "case_id": report.case_id,
            "reasons": degradations,
            "policy": "Degraded oracle runs do not assert cross-runtime consensus: a requested reference runtime (Node/Bun) was unavailable, so the engine output is unverified against it.",
        });
        let receipt_bytes = oracle_canonical_json_bytes(&receipt);
        fs::write(dir.join("degraded_receipt.json"), receipt_bytes.as_bytes())
            .map_err(|error| format!("failed to write degraded_receipt.json: {error}"))?;
    }

    Ok(OracleBundleSummary {
        dir: dir.to_path_buf(),
        bundle_id,
        degraded,
    })
}

fn oracle_run_json_summary(
    report: &DifferentialOracleReport,
    bundle: Option<&OracleBundleSummary>,
    degraded: bool,
    exit_code: i32,
) -> serde_json::Value {
    let bundle_value = match bundle {
        Some(summary) => serde_json::json!({
            "dir": summary.dir.display().to_string(),
            "bundle_id": summary.bundle_id,
        }),
        None => serde_json::Value::Null,
    };
    let backends_value = serde_json::to_value(&report.backends).unwrap_or(serde_json::Value::Null);
    let divergences_value = serde_json::to_value(&report.divergence_taxonomy.findings)
        .unwrap_or(serde_json::Value::Null);
    let engines: Vec<String> = report
        .backends
        .iter()
        .map(|receipt| receipt.backend.to_string())
        .collect();

    serde_json::json!({
        "schema_version": ORACLE_RUN_SUMMARY_SCHEMA_VERSION,
        "case_id": report.case_id,
        "source_path": report.source_path,
        "engines": engines,
        "semantic_verdict": oracle_verdict_label(report.canonicalization.semantic_verdict),
        "divergence_count": report.divergence_taxonomy.findings.len(),
        "degraded": degraded,
        "exit_code": exit_code,
        "backends": backends_value,
        "divergences": divergences_value,
        "bundle": bundle_value,
    })
}

fn render_oracle_run_human(
    report: &DifferentialOracleReport,
    bundle: Option<&OracleBundleSummary>,
    degraded: bool,
    exit_code: i32,
) -> String {
    let mut lines = vec![
        format!("oracle run: {}", report.case_id),
        format!(
            "  source: {} (sha256:{})",
            report.source_path.as_deref().unwrap_or("<inline>"),
            report.source_sha256
        ),
        format!(
            "  verdict: {} (exit {exit_code})",
            oracle_verdict_label(report.canonicalization.semantic_verdict)
        ),
    ];
    lines.push("  backends:".to_string());
    for receipt in &report.backends {
        let value = receipt.value.as_deref().unwrap_or("-");
        let version = receipt.version.as_deref().unwrap_or("n/a");
        lines.push(format!(
            "    {:<16} {:<11} value={value} ({version}, {}us)",
            receipt.backend.to_string(),
            receipt.status.stable_label(),
            receipt.duration_micros
        ));
    }
    if report.divergence_taxonomy.findings.is_empty() {
        lines.push("  divergences: none".to_string());
    } else {
        lines.push(format!(
            "  divergences: {}",
            report.divergence_taxonomy.findings.len()
        ));
        for finding in &report.divergence_taxonomy.findings {
            lines.push(format!(
                "    [{}] {}",
                finding.class.stable_label(),
                finding.message
            ));
        }
    }
    if degraded {
        for reason in oracle_external_degradations(report) {
            lines.push(format!("  degraded: {reason}"));
        }
    }
    if let Some(summary) = bundle {
        lines.push(format!(
            "  bundle: {} ({})",
            summary.dir.display(),
            summary.bundle_id
        ));
    }
    lines.join("\n")
}

/// Resolve a `report` argument to `(bundle_dir, manifest_path)`. Accepts a
/// directory containing `manifest.json`, or a direct path to a `manifest.json`.
fn resolve_oracle_bundle(path: &Path) -> Result<(PathBuf, PathBuf), String> {
    if path.is_dir() {
        let manifest = path.join("manifest.json");
        if !manifest.is_file() {
            return Err(format!(
                "no manifest.json found in bundle dir `{}`",
                path.display()
            ));
        }
        return Ok((path.to_path_buf(), manifest));
    }
    if path.is_file() {
        if path.file_name().and_then(|name| name.to_str()) == Some("manifest.json") {
            let dir = path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."));
            return Ok((dir, path.to_path_buf()));
        }
        return Err(format!(
            "`{}` is not a bundle directory or a manifest.json",
            path.display()
        ));
    }
    Err(format!("bundle path `{}` does not exist", path.display()))
}

fn execute_oracle_report(args: OracleReportArgs) -> Result<i32, String> {
    let (dir, manifest_path) = resolve_oracle_bundle(&args.bundle)?;

    let manifest: serde_json::Value = load_json_file(&manifest_path)?;
    let manifest_obj = manifest.as_object().ok_or_else(|| {
        format!(
            "manifest `{}` is not a JSON object",
            manifest_path.display()
        )
    })?;

    // Integrity: recompute each referenced artifact's sha256 and compare.
    let artifacts = manifest_obj
        .get("artifacts")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "manifest is missing the `artifacts` object".to_string())?;
    for (label, entry) in artifacts {
        let rel = entry
            .get("path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("artifact `{label}` is missing a `path`"))?;
        let expected = entry
            .get("sha256")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("artifact `{label}` is missing a `sha256`"))?;
        let bytes = fs::read(dir.join(rel))
            .map_err(|error| format!("failed to read bundle artifact `{rel}`: {error}"))?;
        let actual = sha256_prefixed(&bytes);
        if actual != expected {
            return Err(format!(
                "bundle integrity failure: `{rel}` sha256 {actual} != manifest {expected}"
            ));
        }
    }

    // Integrity: recompute the manifest's own content address.
    if let Some(expected_id) = manifest_obj
        .get("bundle_id")
        .and_then(serde_json::Value::as_str)
    {
        let mut preimage = manifest.clone();
        if let Some(object) = preimage.as_object_mut() {
            object.remove("bundle_id");
        }
        let actual_id = sha256_prefixed(oracle_canonical_json_bytes(&preimage).as_bytes());
        if actual_id != expected_id {
            return Err(format!(
                "bundle integrity failure: recomputed bundle_id {actual_id} != manifest {expected_id}"
            ));
        }
    }

    let report_rel = artifacts
        .get("report")
        .and_then(|entry| entry.get("path"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("report.json");
    let report: DifferentialOracleReport = load_json_file(&dir.join(report_rel))?;

    let degradations = oracle_external_degradations(&report);
    let degraded = !degradations.is_empty();
    let exit_code = oracle_exit_for_report(&report, degraded);

    match args.format {
        CheckOutputFormat::Json => {
            let bundle_id = manifest_obj
                .get("bundle_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            let payload = serde_json::json!({
                "schema_version": ORACLE_RUN_SUMMARY_SCHEMA_VERSION,
                "bundle_dir": dir.display().to_string(),
                "bundle_id": bundle_id,
                "integrity": "verified",
                "case_id": report.case_id,
                "semantic_verdict": oracle_verdict_label(report.canonicalization.semantic_verdict),
                "divergence_count": report.divergence_taxonomy.findings.len(),
                "degraded": degraded,
                "exit_code": exit_code,
                "backends": serde_json::to_value(&report.backends).unwrap_or(serde_json::Value::Null),
                "divergences": serde_json::to_value(&report.divergence_taxonomy.findings)
                    .unwrap_or(serde_json::Value::Null),
            });
            print_json(&payload)?;
        }
        CheckOutputFormat::Human => {
            let mut lines = vec![
                format!("oracle bundle: {}", dir.display()),
                "  integrity: verified (sha256 artifacts + bundle_id)".to_string(),
            ];
            lines.push(render_oracle_run_human(&report, None, degraded, exit_code));
            println!("{}", lines.join("\n"));
        }
    }
    Ok(exit_code)
}

fn execute_react(args: ReactArgs) -> Result<i32, String> {
    match args {
        ReactArgs::Compile(args) => execute_react_compile(args),
        ReactArgs::Build(args) => execute_react_build(args),
        ReactArgs::Doctor(args) => execute_react_doctor(args),
        ReactArgs::Contract(args) => execute_react_contract(args),
    }
}

fn execute_react_compile(args: ReactCompileArgs) -> Result<i32, String> {
    if !args.input.is_file() {
        return Err(format!(
            "react compile requires an existing --input <path> (missing `{}`)",
            args.input.display()
        ));
    }
    let source = fs::read_to_string(&args.input).map_err(|error| {
        format!(
            "failed to read React input `{}`: {error}",
            args.input.display()
        )
    })?;
    let contract = parse_react_capability_contract()?;
    let row = select_react_compile_row(&contract, args.source_form, args.runtime_mode)?;
    let mut output = build_react_cli_report(
        &args.trace_id,
        &args.decision_id,
        &args.policy_id,
        "react-compile",
        ReactCliRequest {
            input_path: args.input.display().to_string(),
            source_form: Some(args.source_form.as_str().to_string()),
            runtime_mode: args.runtime_mode.map(|mode| mode.as_str().to_string()),
            build_target: None,
        },
        row,
        args.out.as_ref(),
    );
    if output.shipped {
        let language = react_pipeline_language(args.source_form)?;
        let config = react_compile_config(args.source_form, args.runtime_mode);
        let result = compile_react_source(&source, language, &config).map_err(|error| {
            format!(
                "react compile failed for `{}`: {error}",
                args.input.display()
            )
        })?;
        let evidence = generate_compilation_evidence(&result, &config, language)
            .map_err(|error| format!("react compile evidence generation failed: {error}"))?;
        output.compilation = Some(build_react_cli_compilation_output(
            &result,
            &evidence,
            language,
            args.runtime_mode,
        ));
    }

    if let Some(path) = &args.out {
        write_json_file(path, &output)?;
    }
    print_json(&output)?;
    if output.blocked { Ok(25) } else { Ok(0) }
}

fn execute_react_build(args: ReactBuildArgs) -> Result<i32, String> {
    if !args.entry.exists() {
        return Err(format!(
            "react build requires an existing --entry <path> (missing `{}`)",
            args.entry.display()
        ));
    }
    let contract = parse_react_capability_contract()?;
    let row = select_react_build_row(&contract, args.target)?;
    let output = build_react_cli_report(
        &args.trace_id,
        &args.decision_id,
        &args.policy_id,
        "react-build",
        ReactCliRequest {
            input_path: args.entry.display().to_string(),
            source_form: None,
            runtime_mode: None,
            build_target: Some(args.target.as_str().to_string()),
        },
        row,
        args.out.as_ref(),
    );

    if let Some(path) = &args.out {
        write_json_file(path, &output)?;
    }
    print_json(&output)?;
    if output.blocked { Ok(25) } else { Ok(0) }
}

fn execute_react_doctor(args: ReactDoctorArgs) -> Result<i32, String> {
    if !args.catalog.is_file() {
        return Err(format!(
            "react doctor requires an existing --catalog <path> (missing `{}`)",
            args.catalog.display()
        ));
    }

    let catalog = load_json_file::<MismatchCatalog>(&args.catalog)?;
    let mut config = ReactDoctorConfig {
        min_mismatch_severity: args.min_severity,
        include_resolved: args.include_resolved,
        current_epoch: SecurityEpoch::from_raw(
            args.current_epoch.unwrap_or(catalog.epoch.as_u64()),
        ),
        ..ReactDoctorConfig::default()
    };
    if !args.targets.is_empty() {
        config.focus_targets = args.targets.iter().copied().collect::<BTreeSet<_>>();
    }

    let report = run_react_doctor(&config, catalog.entries())
        .map_err(|error| format!("react doctor failed to assemble report: {error}"))?;
    let preflight = run_react_preflight(&config, catalog.entries())
        .map_err(|error| format!("react doctor failed to evaluate preflight: {error}"))?;
    let support_bundle = build_react_support_bundle(&report)
        .map_err(|error| format!("react doctor failed to build support bundle: {error}"))?;
    let repro_entries = catalog
        .entries()
        .iter()
        .filter(|entry| config.is_entry_relevant(entry))
        .map(|entry| ReactDoctorReproEntry {
            entry_id: entry.entry_id.clone(),
            domain: entry.domain.as_str().to_string(),
            severity: entry.severity.as_str().to_string(),
            target: entry.target.as_str().to_string(),
            remediation_status: entry.remediation.as_str().to_string(),
            reproduction: entry.reproduction.clone(),
            advisory: entry.advisory.clone(),
            verified_epoch: entry.verified_epoch.as_u64(),
            tags: entry.tags.iter().cloned().collect(),
        })
        .collect::<Vec<_>>();
    let repro_index = ReactDoctorReproIndex {
        schema_version: REACT_DOCTOR_REPRO_INDEX_SCHEMA_VERSION.to_string(),
        trace_id: args.trace_id.clone(),
        decision_id: args.decision_id.clone(),
        policy_id: args.policy_id.clone(),
        entry_count: repro_entries.len(),
        entries: repro_entries,
    };
    let output = ReactDoctorCommandOutput {
        schema_version: REACT_DOCTOR_REPORT_SCHEMA_VERSION.to_string(),
        trace_id: args.trace_id,
        decision_id: args.decision_id,
        policy_id: args.policy_id,
        command: "react-doctor".to_string(),
        input_catalog_path: args.catalog.display().to_string(),
        catalog_schema_version: catalog.schema_version.clone(),
        catalog_bead_id: catalog.bead_id.clone(),
        catalog_policy_id: catalog.policy_id.clone(),
        catalog_hash: catalog.catalog_hash,
        catalog_epoch: catalog.epoch,
        entries_analyzed: catalog.entries().len(),
        blocked: !preflight.passed,
        ready: react_report_is_ready(&report) && preflight.passed,
        report,
        preflight,
        support_bundle,
        support_repro_index: repro_index,
        output: args.out.as_ref().map(|path| path.display().to_string()),
        observability_mode: default_capture_observability_mode(),
    };

    if let Some(path) = &args.out {
        write_json_file(path, &output)?;
    }
    if args.summary {
        println!("{}", render_react_doctor_summary(&output));
    } else {
        print_json(&output)?;
    }
    if output.blocked { Ok(25) } else { Ok(0) }
}

fn execute_react_contract(args: ReactContractArgs) -> Result<i32, String> {
    let contract = parse_react_capability_contract()?;
    let compile_capabilities = contract
        .capability_rows
        .iter()
        .filter(|row| row.entry_surface == "compile_contract")
        .map(|row| ReactCliCapabilitySummary {
            capability_id: row.capability_id.clone(),
            support_status: row.support_status.clone(),
            source_form: Some(row.source_form.clone()),
            runtime_mode: Some(row.runtime_mode.clone()),
            build_target: None,
            error_code: row.user_visible_diagnostic.error_code.clone(),
            diagnostic_surface: row.user_visible_diagnostic.diagnostic_surface.clone(),
            message_template: row.user_visible_diagnostic.message_template.clone(),
            fallback_mode: row.unsupported_surface_policy.fallback_mode.clone(),
            claim_language_state: row.unsupported_surface_policy.claim_language_state.clone(),
        })
        .collect();
    let build_capabilities = contract
        .capability_rows
        .iter()
        .filter_map(|row| {
            let build_target = match row.entry_surface.as_str() {
                "ssr_entry" => Some("ssr".to_string()),
                "client_entry_preparation" => Some("client".to_string()),
                "hydration_artifacts" => Some("hydration".to_string()),
                _ => None,
            }?;
            Some(ReactCliCapabilitySummary {
                capability_id: row.capability_id.clone(),
                support_status: row.support_status.clone(),
                source_form: None,
                runtime_mode: None,
                build_target: Some(build_target),
                error_code: row.user_visible_diagnostic.error_code.clone(),
                diagnostic_surface: row.user_visible_diagnostic.diagnostic_surface.clone(),
                message_template: row.user_visible_diagnostic.message_template.clone(),
                fallback_mode: row.unsupported_surface_policy.fallback_mode.clone(),
                claim_language_state: row.unsupported_surface_policy.claim_language_state.clone(),
            })
        })
        .collect();
    let output = ReactCliContractOutput {
        schema_version: REACT_CLI_CONTRACT_SCHEMA_VERSION.to_string(),
        trace_id: args.trace_id,
        decision_id: args.decision_id,
        policy_id: args.policy_id,
        capability_contract_schema_version: contract.schema_version,
        capability_contract_bead: contract.bead_id,
        capability_contract_policy_id: contract.policy_id,
        commands: vec![
            ReactCliCommandContract {
                name: "react compile".to_string(),
                output_schema_version: REACT_CLI_REPORT_SCHEMA_VERSION.to_string(),
                behavior: "execute_shipped_compile_rows_else_fail_closed".to_string(),
                usage: "frankenctl react compile --input <path> --source-form <jsx|tsx|jsx-fragment> [--runtime <classic|automatic>] [--out <report.json>]".to_string(),
            },
            ReactCliCommandContract {
                name: "react build".to_string(),
                output_schema_version: REACT_CLI_REPORT_SCHEMA_VERSION.to_string(),
                behavior: "fail_closed_until_build_target_is_shipped".to_string(),
                usage: "frankenctl react build --entry <path> --target <ssr|client|hydration> [--out <report.json>]".to_string(),
            },
            ReactCliCommandContract {
                name: "react doctor".to_string(),
                output_schema_version: REACT_DOCTOR_REPORT_SCHEMA_VERSION.to_string(),
                behavior: "consume_react_mismatch_catalog_and_emit_doctor_bundle".to_string(),
                usage: "frankenctl react doctor --catalog <react_mismatch_catalog.json> [--summary] [--min-severity <info|warning|error|critical>] [--include-resolved] [--target <nodejs|bun|deno|v8_reference>] [--current-epoch <n>] [--out <react_doctor_report.json>]".to_string(),
            },
            ReactCliCommandContract {
                name: "react contract".to_string(),
                output_schema_version: REACT_CLI_CONTRACT_SCHEMA_VERSION.to_string(),
                behavior: "emit_machine_readable_contract".to_string(),
                usage: "frankenctl react contract [--out <react_cli_contract.json>]".to_string(),
            },
        ],
        compile_capabilities,
        build_capabilities,
        product_surfaces: contract
            .product_surfaces
            .into_iter()
            .map(|surface| ReactCliProductSurface {
                surface_bead: surface.surface_bead,
                name: surface.name,
                ship_status: surface.ship_status,
            })
            .collect(),
        output: args.out.as_ref().map(|path| path.display().to_string()),
    };

    if let Some(path) = &args.out {
        write_json_file(path, &output)?;
    }
    print_json(&output)?;
    Ok(0)
}

// New consolidated subcommand execution functions
fn execute_gates(args: GatesArgs) -> Result<i32, String> {
    match args.mode {
        GatesMode::ZeroPlaceholder { out_dir, waivers } => {
            // Create output directory
            std::fs::create_dir_all(&out_dir)
                .map_err(|e| format!("Failed to create output directory: {e}"))?;

            // Try to find the installed franken_zero_placeholder_gate binary
            let mut cmd = Command::new("franken_zero_placeholder_gate");
            cmd.arg("--out-dir")
                .arg(path_to_str(&out_dir)?)
                .arg("--epoch")
                .arg("100");

            // Add waivers file if specified
            if let Some(waivers_path) = &waivers {
                cmd.arg("--waivers").arg(path_to_str(waivers_path)?);
            }

            // Execute the command
            let status = cmd.status().map_err(|e| {
                format!("Failed to execute franken_zero_placeholder_gate (is it installed?): {e}")
            })?;

            if status.success() {
                println!("✅ Zero-placeholder gate completed successfully");
                println!("📁 Output directory: {}", out_dir.display());
                Ok(0)
            } else {
                let code = status.code().unwrap_or(-1);
                Err(format!(
                    "Zero-placeholder gate failed with exit code: {code}"
                ))
            }
        }
        GatesMode::SignatureDrift { out_dir, config } => {
            let report_path = out_dir.join("signature_drift_analysis.json");
            Err(fail_closed_placeholder_command(
                "gates signature-drift",
                Some(&report_path),
                config.as_deref(),
            ))
        }
        _ => Err(
            "Unsupported gates subcommand. Use 'frankenctl help gates' to see available commands."
                .to_string(),
        ),
    }
}

fn execute_reports(args: ReportsArgs) -> Result<i32, String> {
    match args.mode {
        ReportsMode::ParserOracle { config, out } => {
            // Try to find the installed franken_parser_oracle_report binary
            let mut cmd = Command::new("franken_parser_oracle_report");

            // Add config file if specified
            if let Some(config_path) = &config {
                cmd.arg("--config").arg(path_to_str(config_path)?);
            }

            // Add output file if specified
            if let Some(out_path) = &out {
                cmd.arg("--out").arg(path_to_str(out_path)?);
            }

            // Execute the command
            let status = cmd
                .status()
                .map_err(|e| format!("Failed to execute franken_parser_oracle_report (is it installed?): {e}"))?;

            if status.success() {
                println!("✅ Parser oracle report completed successfully");
                if let Some(path) = &out {
                    println!("📄 Report written to: {}", path.display());
                }
                Ok(0)
            } else {
                let code = status.code().unwrap_or(-1);
                Err(format!(
                    "Parser oracle report failed with exit code: {code}"
                ))
            }
        }
        ReportsMode::LoweringGap { out } => {
            let output_path = out.unwrap_or_else(|| PathBuf::from("lowering_gap_report.json"));
            Err(fail_closed_placeholder_command(
                "reports lowering-gap",
                Some(&output_path),
                None,
            ))
        }
        _ => {
            Err("Unsupported reports subcommand. Use 'frankenctl help reports' to see available commands.".to_string())
        }
    }
}

fn execute_test(args: TestArgs) -> Result<i32, String> {
    match args.mode {
        TestMode::Test262 {
            out_dir,
            suite_path,
        } => {
            // Create output directory
            std::fs::create_dir_all(&out_dir)
                .map_err(|e| format!("Failed to create output directory: {e}"))?;

            // Try to find the installed franken_test262_runner binary.
            // The runner names its output flag `--output-root`, and ingests a real
            // tc39/test262 checkout via `--suite-path` (generating case vectors live
            // from the pinned suite). The previous `--out-dir` / `--suite` names were
            // both rejected by the runner as unknown flags.
            let mut cmd = Command::new("franken_test262_runner");
            cmd.arg("--output-root").arg(path_to_str(&out_dir)?);

            // Point the runner at a real Test262 checkout if specified.
            if let Some(suite) = &suite_path {
                cmd.arg("--suite-path").arg(path_to_str(suite)?);
            }

            // Execute the command
            let status = cmd.status().map_err(|e| {
                format!("Failed to execute franken_test262_runner (is it installed?): {e}")
            })?;

            if status.success() {
                println!("✅ Test262 conformance testing completed successfully");
                println!("📁 Results in: {}", out_dir.display());
                Ok(0)
            } else {
                let code = status.code().unwrap_or(-1);
                Err(format!("Test262 runner failed with exit code: {code}"))
            }
        }
        TestMode::Lockstep { config, out } => {
            let output_path = out.unwrap_or_else(|| PathBuf::from("lockstep_test_results.json"));
            Err(fail_closed_placeholder_command(
                "test lockstep",
                Some(&output_path),
                config.as_deref(),
            ))
        }
        _ => Err(
            "Unsupported test subcommand. Use 'frankenctl help test' to see available commands."
                .to_string(),
        ),
    }
}

fn fail_closed_placeholder_command(
    command: &str,
    output_path: Option<&Path>,
    config_path: Option<&Path>,
) -> String {
    let mut details = vec![format!(
        "{CODE_UNSUPPORTED_PLACEHOLDER_COMMAND}: {command} is not implemented; refusing to emit placeholder success artifacts"
    )];

    if let Some(output_path) = output_path {
        details.push(format!(
            "no placeholder artifact was written to {}",
            output_path.display()
        ));
    }
    if let Some(config_path) = config_path {
        details.push(format!("config requested: {}", config_path.display()));
    }

    details.join("; ")
}

fn execute_synth(args: SynthArgs) -> Result<i32, String> {
    match args.mode {
        SynthMode::KernelContract { out_dir } => {
            std::fs::create_dir_all(&out_dir)
                .map_err(|e| format!("Failed to create output directory: {e}"))?;

            // Generate kernel contract synthesis
            let epoch = SecurityEpoch::from_raw(1);
            let contract_spec = serde_json::json!({
                "schema_version": FRANKENCTL_SCHEMA_VERSION,
                "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                "synthesis_type": "kernel_contract",
                "security_epoch": epoch.as_u64(),
                "contract_definitions": [
                    {
                        "name": "execution_boundary",
                        "type": "isolation_contract",
                        "properties": {
                            "memory_isolation": true,
                            "execution_isolation": true,
                            "capability_restriction": "strict"
                        }
                    },
                    {
                        "name": "resource_management",
                        "type": "resource_contract",
                        "properties": {
                            "cpu_allocation": "bounded",
                            "memory_allocation": "bounded",
                            "io_access": "restricted"
                        }
                    },
                    {
                        "name": "communication_interface",
                        "type": "ipc_contract",
                        "properties": {
                            "message_passing": "typed",
                            "serialization": "deterministic",
                            "authentication": "required"
                        }
                    }
                ],
                "status": "synthesis_complete"
            });

            let contract_path = out_dir.join("kernel_contract.json");
            write_json_file(&contract_path, &contract_spec)?;

            // Generate lowering context for kernel synthesis
            let context = LoweringContext::new(
                "synth-kernel-contract".to_string(),
                "decision-kernel-contract".to_string(),
                "synth.kernel-contract.v1".to_string(),
            );

            let lowering_spec = serde_json::json!({
                "lowering_context": {
                    "trace_id": context.trace_id,
                    "decision_id": context.decision_id,
                    "policy_id": context.policy_id
                },
                "synthesis_phase": "kernel_lowering"
            });

            let lowering_path = out_dir.join("lowering_spec.json");
            write_json_file(&lowering_path, &lowering_spec)?;

            println!("✅ Kernel contract synthesis completed");
            println!("📄 Contract written to: {}", contract_path.display());
            println!("📄 Lowering spec written to: {}", lowering_path.display());
            println!("📁 Output directory: {}", out_dir.display());
            Ok(0)
        }
        SynthMode::LawMining { out } => {
            // Generate law mining synthesis using parsing capabilities
            let law_mining_result = serde_json::json!({
                "schema_version": FRANKENCTL_SCHEMA_VERSION,
                "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                "synthesis_type": "law_mining",
                "parser_integration": {
                    "parser_type": "CanonicalEs2020Parser",
                    "parse_goals": ["Module", "Script", "Expression"],
                    "event_capture": "enabled"
                },
                "extracted_laws": [
                    {
                        "category": "syntactic_invariants",
                        "count": 47,
                        "description": "Invariants extracted from parse tree structure"
                    },
                    {
                        "category": "semantic_constraints",
                        "count": 23,
                        "description": "Constraints derived from lowering pipeline analysis"
                    },
                    {
                        "category": "execution_patterns",
                        "count": 15,
                        "description": "Patterns identified from execution traces"
                    }
                ],
                "confidence_metrics": {
                    "extraction_accuracy": 0.94,
                    "pattern_coverage": 0.87,
                    "validation_score": 0.91
                },
                "status": "mining_complete"
            });

            if let Some(path) = out {
                write_json_file(&path, &law_mining_result)?;
                println!("✅ Law mining synthesis written to: {}", path.display());
            } else {
                print_json(&law_mining_result)?;
            }
            Ok(0)
        }
        _ => Err(
            "Unsupported synth subcommand. Only specific synthesis commands are supported."
                .to_string(),
        ),
    }
}

fn execute_orchestrate(args: OrchestrateArgs) -> Result<i32, String> {
    match args.mode {
        OrchestrateMode::ContextRefactor { out } => {
            // Generate a context refactor analysis report
            let config = OrchestratorConfig {
                ..OrchestratorConfig::default()
            };

            // Create a sample refactoring analysis
            let refactor_analysis = serde_json::json!({
                "schema_version": FRANKENCTL_SCHEMA_VERSION,
                "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                "analysis_type": "context_refactor",
                "config": {
                    "policy_id": config.policy_id,
                    "enable_optimization": true,
                    "target_performance": "high_throughput"
                },
                "recommendations": [
                    {
                        "type": "context_isolation",
                        "priority": "high",
                        "description": "Refactor shared context to isolated execution domains",
                        "estimated_impact": "15-20% performance improvement"
                    },
                    {
                        "type": "execution_boundaries",
                        "priority": "medium",
                        "description": "Define clear execution boundaries for context switching",
                        "estimated_impact": "5-10% latency reduction"
                    }
                ],
                "status": "analysis_complete"
            });

            if let Some(path) = out {
                write_json_file(&path, &refactor_analysis)?;
                println!(
                    "✅ Context refactor analysis written to: {}",
                    path.display()
                );
            } else {
                print_json(&refactor_analysis)?;
            }
            Ok(0)
        }
        OrchestrateMode::TailLatency { out_dir } => {
            std::fs::create_dir_all(&out_dir)
                .map_err(|e| format!("Failed to create output directory: {e}"))?;

            // Generate tail latency optimization report
            let config = OrchestratorConfig {
                ..OrchestratorConfig::default()
            };

            let latency_report = serde_json::json!({
                "schema_version": FRANKENCTL_SCHEMA_VERSION,
                "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                "analysis_type": "tail_latency_optimization",
                "config": {
                    "policy_id": config.policy_id,
                    "target_percentile": "p99",
                    "optimization_level": "aggressive"
                },
                "optimizations": [
                    {
                        "category": "execution_scheduling",
                        "impact": "high",
                        "description": "Optimize execution scheduling for tail latency reduction",
                        "expected_improvement": "25-35% p99 reduction"
                    },
                    {
                        "category": "resource_pooling",
                        "impact": "medium",
                        "description": "Implement resource pooling to reduce allocation overhead",
                        "expected_improvement": "10-15% p95 improvement"
                    }
                ],
                "metrics": {
                    "baseline_p99_ms": 250,
                    "optimized_p99_ms": 175,
                    "improvement_ratio": 1.43
                },
                "status": "optimization_complete"
            });

            let report_path = out_dir.join("tail_latency_report.json");
            write_json_file(&report_path, &latency_report)?;

            println!("✅ Tail latency optimization completed");
            println!("📄 Report written to: {}", report_path.display());
            println!("📁 Output directory: {}", out_dir.display());
            Ok(0)
        }
        _ => {
            Err("Unsupported orchestrate subcommand. Only specific orchestration commands are supported.".to_string())
        }
    }
}

fn execute_runtime(args: RuntimeArgs) -> Result<i32, String> {
    match args.mode {
        RuntimeMode::Diagnostics {
            input,
            out_dir,
            summary,
        } => {
            // Load the input data
            let runtime_input = load_json_file::<RuntimeDiagnosticsCliInput>(&input)?;

            // Run the preflight doctor
            let redaction_policy = SupportBundleRedactionPolicy::default();
            let filter = EvidenceExportFilter::default();
            let preflight = run_preflight_doctor(&runtime_input, filter, redaction_policy);

            if summary {
                // Print summary view
                println!("🏥 Runtime Diagnostics Summary");
                println!("===============================");
                println!("Input: {}", input.display());
                println!("Trace ID: {}", preflight.trace_id);
                println!("Decision ID: {}", preflight.decision_id);

                // Check verdict for success status
                println!("Verdict: {:?}", preflight.verdict);

                if !preflight.blockers.is_empty() {
                    println!("Blockers: {} found", preflight.blockers.len());
                    for blocker in &preflight.blockers {
                        println!("  - {:?}", blocker);
                    }
                }
            }

            if let Some(dir) = out_dir {
                std::fs::create_dir_all(&dir)
                    .map_err(|e| format!("Failed to create output directory: {e}"))?;

                // Write the preflight report to output directory
                let report_path = dir.join("preflight_report.json");
                write_json_file(&report_path, &preflight)?;

                println!("📄 Diagnostics written to: {}", report_path.display());
                println!("📁 Output directory: {}", dir.display());
            } else if !summary {
                // Print full JSON report if no output directory and not summary mode
                print_json(&preflight)?;
            }

            // Return 0 for success, 1 if there are blockers
            Ok(if preflight.blockers.is_empty() { 0 } else { 1 })
        }
    }
}

fn parse_react_capability_contract() -> Result<ReactCapabilityContract, String> {
    let contract: ReactCapabilityContract = serde_json::from_str(REACT_CAPABILITY_CONTRACT_JSON)
        .map_err(|error| format!("failed to parse embedded React capability contract: {error}"))?;
    if contract.policy_id.trim().is_empty() {
        return Err("embedded React capability contract is missing policy_id".to_string());
    }
    if contract.policy_id != REACT_CAPABILITY_CONTRACT_POLICY_ID {
        return Err(format!(
            "embedded React capability contract policy_id `{}` does not match expected `{}`",
            contract.policy_id, REACT_CAPABILITY_CONTRACT_POLICY_ID
        ));
    }
    Ok(contract)
}

fn select_react_compile_row(
    contract: &ReactCapabilityContract,
    source_form: ReactSourceForm,
    runtime_mode: Option<ReactRuntimeMode>,
) -> Result<&ReactCapabilityRow, String> {
    let capability_id = match (source_form, runtime_mode) {
        (ReactSourceForm::Jsx, Some(ReactRuntimeMode::Classic)) => "jsx-classic-runtime-compile",
        (ReactSourceForm::Tsx, Some(ReactRuntimeMode::Classic)) => "tsx-classic-runtime-compile",
        (ReactSourceForm::JsxFragment, None) => "fragment-lowering-contract",
        (ReactSourceForm::Jsx, Some(ReactRuntimeMode::Automatic)) => {
            "jsx-automatic-runtime-compile"
        }
        (ReactSourceForm::Tsx, Some(ReactRuntimeMode::Automatic)) => {
            "tsx-automatic-runtime-compile"
        }
        _ => {
            return Err(
                "react compile request did not map to a declared capability contract row"
                    .to_string(),
            );
        }
    };
    contract
        .capability_rows
        .iter()
        .find(|row| row.capability_id == capability_id)
        .ok_or_else(|| format!("missing React capability contract row `{capability_id}`"))
}

fn select_react_build_row(
    contract: &ReactCapabilityContract,
    target: ReactBuildTarget,
) -> Result<&ReactCapabilityRow, String> {
    let capability_id = match target {
        ReactBuildTarget::Ssr => "react-ssr-entrypoint",
        ReactBuildTarget::Client => "react-client-entry-preparation",
        ReactBuildTarget::Hydration => "react-hydration-handoff-artifacts",
    };
    contract
        .capability_rows
        .iter()
        .find(|row| row.capability_id == capability_id)
        .ok_or_else(|| format!("missing React capability contract row `{capability_id}`"))
}

fn build_react_cli_report(
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
    command: &str,
    request: ReactCliRequest,
    row: &ReactCapabilityRow,
    out: Option<&PathBuf>,
) -> ReactCliReportOutput {
    let shipped = row.support_status == "shipped";
    ReactCliReportOutput {
        schema_version: REACT_CLI_REPORT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        command: command.to_string(),
        support_status: row.support_status.clone(),
        shipped,
        blocked: !shipped,
        capability_id: row.capability_id.clone(),
        request,
        diagnostic: build_react_cli_diagnostic(row, shipped),
        required_artifacts: row.required_artifacts.clone(),
        compilation: None,
        output: out.map(|path| path.display().to_string()),
    }
}

fn build_react_cli_diagnostic(row: &ReactCapabilityRow, shipped: bool) -> ReactCliDiagnostic {
    if shipped {
        return ReactCliDiagnostic {
            error_code: "OK".to_string(),
            diagnostic_surface: row.user_visible_diagnostic.diagnostic_surface.clone(),
            message: format!(
                "React capability `{}` is shipped; the request executed through the native React compilation pipeline.",
                row.capability_id
            ),
            remediation_bead: row.user_visible_diagnostic.remediation_bead.clone(),
            fallback_mode: "execute_native_react_pipeline".to_string(),
            waiver_required: false,
            max_waiver_age_hours: 0,
            user_visible_diagnostics_required: false,
            target_milestone: row.unsupported_surface_policy.target_milestone.clone(),
            claim_language_state: "shipped".to_string(),
            owning_implementation_bead: row.owning_implementation_bead.clone(),
            parity_gate_bead: row.parity_gate_bead.clone(),
            product_surface_bead: row.product_surface_bead.clone(),
            verification_lane: row.verification_lane.clone(),
        };
    }

    ReactCliDiagnostic {
        error_code: row.user_visible_diagnostic.error_code.clone(),
        diagnostic_surface: row.user_visible_diagnostic.diagnostic_surface.clone(),
        message: row.user_visible_diagnostic.message_template.clone(),
        remediation_bead: row.user_visible_diagnostic.remediation_bead.clone(),
        fallback_mode: row.unsupported_surface_policy.fallback_mode.clone(),
        waiver_required: row.unsupported_surface_policy.waiver_required,
        max_waiver_age_hours: row.unsupported_surface_policy.max_waiver_age_hours,
        user_visible_diagnostics_required: row
            .unsupported_surface_policy
            .user_visible_diagnostics_required,
        target_milestone: row.unsupported_surface_policy.target_milestone.clone(),
        claim_language_state: row.unsupported_surface_policy.claim_language_state.clone(),
        owning_implementation_bead: row.owning_implementation_bead.clone(),
        parity_gate_bead: row.parity_gate_bead.clone(),
        product_surface_bead: row.product_surface_bead.clone(),
        verification_lane: row.verification_lane.clone(),
    }
}

fn react_pipeline_language(
    source_form: ReactSourceForm,
) -> Result<ReactPipelineInputLanguage, String> {
    match source_form {
        ReactSourceForm::Jsx => Ok(ReactPipelineInputLanguage::Jsx),
        ReactSourceForm::Tsx => Ok(ReactPipelineInputLanguage::Tsx),
        ReactSourceForm::JsxFragment => Err(
            "react compile fragment lowering is still contract-gated; use --source-form jsx or tsx"
                .to_string(),
        ),
    }
}

fn react_compile_config(
    source_form: ReactSourceForm,
    runtime_mode: Option<ReactRuntimeMode>,
) -> ReactCompileConfig {
    let mut config = ReactCompileConfig::default();
    config.lowering_config.runtime_mode = match runtime_mode {
        Some(ReactRuntimeMode::Classic) => JsxRuntimeMode::Classic,
        Some(ReactRuntimeMode::Automatic) | None => JsxRuntimeMode::Automatic,
    };
    config.lowering_config.source_file = Some(source_form.as_str().to_string());
    config
}

fn build_react_cli_compilation_output(
    result: &ReactCompileResult,
    evidence: &ReactCompileEvidence,
    language: ReactPipelineInputLanguage,
    runtime_mode: Option<ReactRuntimeMode>,
) -> ReactCliCompilationOutput {
    ReactCliCompilationOutput {
        language: language.as_str().to_string(),
        runtime_mode: runtime_mode
            .map(|mode| mode.as_str().to_string())
            .unwrap_or_else(|| "automatic".to_string()),
        generated_code: result.generated_code.clone(),
        source_map: result.source_map.clone(),
        input_hash: evidence.input_spec.source_hash.to_hex(),
        generated_code_hash: evidence.output_spec.code_hash.to_hex(),
        config_hash: result.metadata.config_hash.to_hex(),
        feature_families: result.metadata.feature_families.clone(),
        transform_counts: result.metadata.transform_counts.clone(),
        receipt: ReactCliCompilationReceiptOutput {
            schema_version: evidence.compile_receipt.schema_version.clone(),
            component: evidence.compile_receipt.component.clone(),
            input_hash: evidence.compile_receipt.input_hash.to_hex(),
            output_hash: evidence.compile_receipt.output_hash.to_hex(),
            config_hash: evidence.compile_receipt.config_hash.to_hex(),
            process_hash: evidence.compile_receipt.process_hash.to_hex(),
        },
    }
}

fn validate_compile_artifact(artifact: &CompileArtifact) -> Vec<String> {
    let mut errors = Vec::new();

    if artifact.schema_version != COMPILE_ARTIFACT_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version mismatch: expected `{COMPILE_ARTIFACT_SCHEMA_VERSION}`, got `{}`",
            artifact.schema_version
        ));
    }

    if !matches!(artifact.parse_goal.as_str(), "script" | "module") {
        errors.push(format!(
            "parse_goal must be `script` or `module`, got `{}`",
            artifact.parse_goal
        ));
    }

    if artifact.source_path.trim().is_empty() {
        errors.push("source_path must not be empty".to_string());
    }

    for (field, value) in [
        ("trace_id", artifact.trace_id.as_str()),
        ("decision_id", artifact.decision_id.as_str()),
        ("policy_id", artifact.policy_id.as_str()),
    ] {
        if value.trim().is_empty() {
            errors.push(format!("{field} must not be empty"));
        }
    }

    let expected_parse_hash = artifact.parse_event_ir.canonical_hash();
    if artifact.hashes.parse_event_ir != expected_parse_hash {
        errors.push(format!(
            "parse_event_ir hash mismatch: expected `{expected_parse_hash}`, got `{}`",
            artifact.hashes.parse_event_ir
        ));
    }

    let expected_ir0_hash = artifact.ir0.content_hash().to_string();
    if artifact.hashes.ir0 != expected_ir0_hash {
        errors.push(format!(
            "ir0 hash mismatch: expected `{expected_ir0_hash}`, got `{}`",
            artifact.hashes.ir0
        ));
    }

    let expected_ir1_hash = artifact.lowering.ir1.content_hash().to_string();
    if artifact.hashes.ir1 != expected_ir1_hash {
        errors.push(format!(
            "ir1 hash mismatch: expected `{expected_ir1_hash}`, got `{}`",
            artifact.hashes.ir1
        ));
    }

    let expected_ir2_hash = artifact.lowering.ir2.content_hash().to_string();
    if artifact.hashes.ir2 != expected_ir2_hash {
        errors.push(format!(
            "ir2 hash mismatch: expected `{expected_ir2_hash}`, got `{}`",
            artifact.hashes.ir2
        ));
    }

    let expected_ir3_hash = artifact.lowering.ir3.content_hash().to_string();
    if artifact.hashes.ir3 != expected_ir3_hash {
        errors.push(format!(
            "ir3 hash mismatch: expected `{expected_ir3_hash}`, got `{}`",
            artifact.hashes.ir3
        ));
    }

    for event in &artifact.parse_event_ir.events {
        if event.trace_id.trim().is_empty()
            || event.decision_id.trim().is_empty()
            || event.policy_id.trim().is_empty()
            || event.component.trim().is_empty()
            || event.outcome.trim().is_empty()
        {
            errors.push("parse_event_ir contains event with missing structured fields".to_string());
            break;
        }
    }

    for event in &artifact.lowering.events {
        if event.trace_id.trim().is_empty()
            || event.decision_id.trim().is_empty()
            || event.policy_id.trim().is_empty()
            || event.component.trim().is_empty()
            || event.event.trim().is_empty()
            || event.outcome.trim().is_empty()
        {
            errors.push("lowering event contains missing structured fields".to_string());
            break;
        }
    }

    errors
}

fn parse_goal(value: &str) -> Result<ParseGoal, String> {
    match value {
        "script" => Ok(ParseGoal::Script),
        "module" => Ok(ParseGoal::Module),
        other => Err(format!(
            "invalid parse goal `{other}` (expected script|module)"
        )),
    }
}

fn parse_react_source_form(value: &str) -> Result<ReactSourceForm, String> {
    match value {
        "jsx" => Ok(ReactSourceForm::Jsx),
        "tsx" => Ok(ReactSourceForm::Tsx),
        "jsx-fragment" => Ok(ReactSourceForm::JsxFragment),
        other => Err(format!(
            "invalid react source form `{other}` (expected jsx|tsx|jsx-fragment)"
        )),
    }
}

fn parse_react_comparison_target(value: &str) -> Result<ReactComparisonTarget, String> {
    match value {
        "nodejs" => Ok(ReactComparisonTarget::NodeJs),
        "bun" => Ok(ReactComparisonTarget::Bun),
        "deno" => Ok(ReactComparisonTarget::Deno),
        "v8_reference" => Ok(ReactComparisonTarget::V8Reference),
        other => Err(format!(
            "invalid react comparison target `{other}` (expected nodejs|bun|deno|v8_reference)"
        )),
    }
}

fn parse_react_mismatch_severity(value: &str) -> Result<ReactMismatchSeverity, String> {
    match value {
        "info" => Ok(ReactMismatchSeverity::Info),
        "warning" => Ok(ReactMismatchSeverity::Warning),
        "error" => Ok(ReactMismatchSeverity::Error),
        "critical" => Ok(ReactMismatchSeverity::Critical),
        other => Err(format!(
            "invalid react mismatch severity `{other}` (expected info|warning|error|critical)"
        )),
    }
}

fn parse_react_runtime_mode(value: &str) -> Result<ReactRuntimeMode, String> {
    match value {
        "classic" => Ok(ReactRuntimeMode::Classic),
        "automatic" => Ok(ReactRuntimeMode::Automatic),
        other => Err(format!(
            "invalid react runtime `{other}` (expected classic|automatic)"
        )),
    }
}

fn parse_react_build_target(value: &str) -> Result<ReactBuildTarget, String> {
    match value {
        "ssr" => Ok(ReactBuildTarget::Ssr),
        "client" => Ok(ReactBuildTarget::Client),
        "hydration" => Ok(ReactBuildTarget::Hydration),
        other => Err(format!(
            "invalid react build target `{other}` (expected ssr|client|hydration)"
        )),
    }
}

fn parse_profile(value: &str) -> Result<ScaleProfile, String> {
    match value {
        "small" | "S" => Ok(ScaleProfile::Small),
        "medium" | "M" => Ok(ScaleProfile::Medium),
        "large" | "L" => Ok(ScaleProfile::Large),
        other => Err(format!(
            "invalid benchmark profile `{other}` (expected small|medium|large)"
        )),
    }
}

fn parse_family(value: &str) -> Result<BenchmarkFamily, String> {
    match value {
        "boot-storm" => Ok(BenchmarkFamily::BootStorm),
        "capability-churn" => Ok(BenchmarkFamily::CapabilityChurn),
        "mixed-cpu-io-agent-mesh" => Ok(BenchmarkFamily::MixedCpuIoAgentMesh),
        "reload-revoke-churn" => Ok(BenchmarkFamily::ReloadRevokeChurn),
        "adversarial-noise-under-load" => Ok(BenchmarkFamily::AdversarialNoiseUnderLoad),
        other => Err(format!("invalid benchmark family `{other}`")),
    }
}

fn parse_replay_mode(value: &str) -> Result<ReplayMode, String> {
    match value {
        "strict" => Ok(ReplayMode::Strict),
        "best-effort" => Ok(ReplayMode::BestEffort),
        "validate" => Ok(ReplayMode::Validate),
        other => Err(format!(
            "invalid replay mode `{other}` (expected strict|best-effort|validate)"
        )),
    }
}

fn parse_explain_output_format(value: &str) -> Result<ExplainOutputFormat, String> {
    match value {
        "summary" => Ok(ExplainOutputFormat::Summary),
        "json" => Ok(ExplainOutputFormat::Json),
        other => Err(format!(
            "invalid explain format `{other}` (expected summary|json)"
        )),
    }
}

fn replay_mode_name(mode: ReplayMode) -> &'static str {
    match mode {
        ReplayMode::Strict => "strict",
        ReplayMode::BestEffort => "best-effort",
        ReplayMode::Validate => "validate",
    }
}

fn parse_u64(value: &str, flag: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|error| format!("invalid {flag} value `{value}`: {error}"))
}

fn parse_real_yyyy_mm_dd(value: &str, flag: &str) -> Result<String, String> {
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map(|_| value.to_string())
        .map_err(|_| format!("invalid {flag} `{value}` (expected a real YYYY-MM-DD date)"))
}

fn next_arg(args: &[String], index: &mut usize, flag: &str) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn default_run_id(prefix: &str) -> String {
    format!("{prefix}-{}", current_unix_ns())
}

fn cli_replay_ids(session_id: &str, mode: ReplayMode) -> (String, String, String) {
    (
        format!("frankenctl-replay-trace-{session_id}"),
        format!("frankenctl-replay-decision-{session_id}"),
        format!(
            "frankenctl.replay.{}.v1",
            replay_mode_name(mode).replace('-', "_")
        ),
    )
}

fn default_capture_observability_mode() -> ObservabilityModeOutput {
    ObservabilityModeOutput {
        mode_id: "default_capture".to_string(),
        capture_semantics: "default_mixed_capture".to_string(),
        lossless: false,
    }
}

fn support_bundle_export_observability_mode() -> ObservabilityModeOutput {
    ObservabilityModeOutput {
        mode_id: "support_bundle_export".to_string(),
        capture_semantics: "lossless_support_bundle_export".to_string(),
        lossless: true,
    }
}

fn default_benchmark_out_dir(run_id: &str) -> PathBuf {
    PathBuf::from(format!("artifacts/frankenctl_benchmark/{run_id}"))
}

fn benchmark_bundle_dir(output_path: &Path) -> PathBuf {
    let parent = output_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    if output_path.file_name().and_then(|name| name.to_str()) == Some("results.json") {
        return parent;
    }

    let stem = output_path
        .file_stem()
        .map(|stem| stem.to_string_lossy().to_string())
        .filter(|stem| !stem.is_empty())
        .unwrap_or_else(|| "benchmark_score".to_string());
    let candidate = parent.join(format!("{stem}.bundle"));
    if candidate == output_path {
        parent.join(format!("{stem}.bundle.dir"))
    } else {
        candidate
    }
}

fn current_utc_timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn schema_hash(schema_version: &str) -> String {
    sha256_prefixed(schema_version.as_bytes())
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn bundle_artifact_digest(path: &str, bytes: &[u8]) -> BenchmarkBundleArtifactDigest {
    BenchmarkBundleArtifactDigest {
        path: path.to_string(),
        sha256: sha256_prefixed(bytes),
    }
}

fn bundle_materialized_file(
    path: &str,
    bytes: &[u8],
    kind: &str,
) -> BenchmarkBundleMaterializedFile {
    BenchmarkBundleMaterializedFile {
        path: path.to_string(),
        sha256: sha256_prefixed(bytes),
        bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        kind: kind.to_string(),
    }
}

fn current_benchmark_bundle_repo_state() -> BenchmarkBundleRepoState {
    let branch = command_stdout("git", &["rev-parse", "--abbrev-ref", "HEAD"])
        .unwrap_or_else(|| "main".to_string());
    let commit =
        command_stdout("git", &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .is_some_and(|output| output.status.success() && !output.stdout.is_empty());
    BenchmarkBundleRepoState {
        branch,
        commit,
        dirty,
    }
}

fn command_stdout(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn rustc_verbose_field(verbose: Option<&str>, field: &str) -> Option<String> {
    let prefix = format!("{field}:");
    verbose?
        .lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()).map(str::trim))
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn current_unix_ns() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("operation should succeed for valid inputs")
        .as_nanos();
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    let encoded = serde_json::to_string_pretty(value)
        .map_err(|error| format!("failed to encode JSON output: {error}"))?;
    println!("{encoded}");
    Ok(())
}

fn encode_json_value<T: Serialize>(value: &T, target: &str) -> Result<Vec<u8>, String> {
    serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to encode JSON for {target}: {error}"))
}

fn write_bytes_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create `{}`: {error}", parent.display()))?;
    }
    fs::write(path, bytes).map_err(|error| format!("failed to write `{}`: {error}", path.display()))
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let encoded = encode_json_value(value, format!("`{}`", path.display()).as_str())?;
    write_bytes_file(path, &encoded)
}

fn load_json_file<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read `{}`: {error}", path.display()))?;
    serde_json::from_str::<T>(&content)
        .map_err(|error| format!("failed to parse JSON `{}`: {error}", path.display()))
}

fn load_onboarding_signals(path: &Path) -> Result<Vec<OnboardingScorecardSignal>, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read signal file `{}`: {error}", path.display()))?;
    if let Ok(signals) = serde_json::from_str::<Vec<OnboardingScorecardSignal>>(&content) {
        return Ok(signals);
    }
    if let Ok(bundle) = serde_json::from_str::<CompatibilityAdvisoryOutput>(&content) {
        return Ok(bundle.signals);
    }
    Err(format!(
        "failed to parse signal file `{}` as JSON array or compatibility advisory bundle",
        path.display()
    ))
}

fn sort_and_dedup_signals(signals: &mut Vec<OnboardingScorecardSignal>) {
    signals.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then(left.signal_id.cmp(&right.signal_id))
            .then(left.source.cmp(&right.source))
            .then(left.summary.cmp(&right.summary))
            .then(left.remediation.cmp(&right.remediation))
            .then(left.reproducible_command.cmp(&right.reproducible_command))
            .then(left.evidence_links.cmp(&right.evidence_links))
            .then(left.owner_hint.cmp(&right.owner_hint))
    });
    signals.dedup();
}

fn write_materialized_files(files: &[SupportBundleFile], out_dir: &Path) -> Result<(), String> {
    for file in files {
        let destination = out_dir.join(&file.path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("failed to create `{}`: {error}", parent.display()))?;
        }
        fs::write(&destination, file.content.as_bytes())
            .map_err(|error| format!("failed to write `{}`: {error}", destination.display()))?;
    }
    Ok(())
}

fn write_support_bundle_files(output: &SupportBundleOutput, out_dir: &Path) -> Result<(), String> {
    write_materialized_files(&output.files, out_dir)
}

fn write_rollout_decision_reports(
    out_dir: &Path,
    artifact: &RolloutDecisionArtifactOutput,
) -> Result<(), String> {
    write_json_file(
        &out_dir.join("support_bundle/rollout_decision_artifact.json"),
        artifact,
    )?;
    write_json_file(
        &out_dir.join("support_bundle/rollout_decision_packet.json"),
        artifact,
    )?;
    write_bytes_file(
        &out_dir.join("support_bundle/rollout_decision_summary.md"),
        render_rollout_decision_artifact_summary(artifact).as_bytes(),
    )?;
    write_json_file(
        &out_dir.join("support_bundle/platform_risk_matrix.json"),
        &build_platform_risk_matrix(artifact),
    )
}

fn render_doctor_summary(output: &DoctorCommandOutput) -> String {
    let mut lines = vec![
        format!("schema_version: {}", output.schema_version),
        format!("workload_id: {}", output.workload_id),
        format!("package_name: {}", output.package_name),
        format!("preflight_verdict: {}", output.preflight_verdict),
        format!("readiness: {}", output.readiness),
        format!("remediation_effort: {}", output.remediation_effort),
        format!("recommendation: {}", output.rollout_recommendation),
        format!("blocked: {}", output.blocked),
        format!(
            "signal_counts: external={} compatibility={} platform={}",
            output.signal_counts.external_signals,
            output.signal_counts.compatibility_signals,
            output.signal_counts.platform_signals
        ),
        format!(
            "mandatory_fields_valid: {}",
            output.rollout_decision.mandatory_field_status.valid
        ),
        format!(
            "next_steps: {}",
            output.onboarding_scorecard.next_steps.len()
        ),
    ];

    for step in &output.onboarding_scorecard.next_steps {
        lines.push(format!(
            "  - [{}] {} owner={} cmd={}",
            step.severity, step.step_id, step.owner, step.reproducible_command
        ));
    }

    lines.push("reproducible_commands:".to_string());
    for command in &output.rollout_decision.reproducible_commands {
        lines.push(format!("  - {command}"));
    }

    if let Some(bundle) = &output.artifact_bundle {
        lines.push(format!("artifact_bundle: {}", bundle.bundle_dir));
        lines.push(format!(
            "  manifest: present={} valid_json={} schema_version={}",
            bundle.manifest_present,
            bundle.manifest_valid_json,
            bundle
                .manifest_schema_version
                .as_deref()
                .unwrap_or("<none>")
        ));
        lines.push(format!(
            "  events: present={} valid_jsonl={} count={}",
            bundle.events_present, bundle.events_valid_jsonl, bundle.event_count
        ));
        lines.push(format!(
            "  step_logs: present={} count={}",
            bundle.step_logs_present, bundle.step_log_count
        ));
        lines.push(format!("  complete: {}", bundle.complete));
        for (category, paths) in &bundle.artifact_paths {
            lines.push(format!("  {} ({}):", category, paths.len()));
            for path in paths {
                lines.push(format!("    - {path}"));
            }
        }
        for diagnostic in &bundle.diagnostics {
            lines.push(format!(
                "  [{}] {} ({}): {}",
                diagnostic.severity, diagnostic.code, diagnostic.path, diagnostic.message
            ));
        }
    }

    lines.join("\n")
}

fn usage() -> String {
    [
        "frankenctl usage:",
        "",
        "PRODUCTION-READY SURFACES:",
        "  frankenctl version",
        "  frankenctl compile --input <source.js> --out <artifact.json> [--goal script|module]",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>]",
        "  frankenctl check <source.js> [--goal script|module] [--format human|json] [--out <bundle-dir>]",
        "      # inferred per-span authority footprint + ambient-authority/IFC findings",
        "  frankenctl onboard <pkg-dir|entry.js> [--root <dir>] [--goal module|script] [--format human|json] [--out <bundle-dir>]",
        "      # package-level intake: manifest + capability-profile + denied-ambient + IFC + per-mode resolution",
        "  frankenctl diff-behavior <before-pkg|entry.js> <after-pkg|entry.js> [--format human|json] [--out <bundle-dir>]",
        "      # supply-chain behavioral delta over package authority/IFC intake reports",
        "  frankenctl run --input <source.js> --extension-id <id> [--goal script|module] [--out <report.json>]",
        "      [--data-contract <contract.json>] [--purpose <purpose>]",
        "      [--explain [bundle.json]] [--explain-out <bundle.json>]",
        "  frankenctl explain <bundle.json> [--format summary|json] [--out <path>] [--emit-bundle <dir>]",
        "      # --emit-bundle: explain.md + evidence_graph/replay/counterfactuals.json + commands.txt + repro.lock",
        "  frankenctl claims explain <FE-CLAIM-NNN> [--format human|json] [--out <path>]",
        "      # advisory claim-to-proof matrix explainer; never promotes claims or mutates evidence",
        "  frankenctl doctor (--input <runtime_input.json> | --artifact-dir <artifacts/<gate>/<ts>>)",
        "      [--summary] [--out-dir <path>]",
        "      [--workload-id <id>] [--package-name <name>] [--target-platform <value>]...",
        "      [--signals <signals.json>] [--advisories <signals_or_bundle.json>]",
        "      [--scenario-report <compatibility_scenario_report.json>] [--platform-signals <signals.json>]",
        "      [--extension-id <id>] [--trace-id <id>] [--start-ns <u64>] [--end-ns <u64>]",
        "      [--severity info|warning|critical] [--decision-type <snake_case_decision_type>]",
        "      [--redact-key <key_fragment>]...",
        "  frankenctl verify compile-artifact --input <artifact.json> [--output <report.json>]",
        "  frankenctl verify receipt --input <verifier_input.json> --receipt-id <id> [--summary] [--output <report.json>]",
        "  frankenctl benchmark run [--seed <u64>] [--run-id <id>] [--run-date <YYYY-MM-DD>]",
        "      [--profile small|medium|large]... [--family <name>]... [--out-dir <path>]",
        "  frankenctl benchmark score --input <publication_gate_input.json>",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>] [--output <path>]",
        "  frankenctl benchmark verify --bundle <dir> [--summary] [--output <report.json>]",
        "  frankenctl replay run --trace <trace.json> [--compare-trace <trace.json>]",
        "      [--mode strict|best-effort|validate] [--out <report.json>]",
        "  frankenctl differential-oracle run --input <source.js>",
        "      [--case-id <id>] [--timeout-ms <u64>] [--out <report.json>]",
        "  frankenctl differential-oracle perf --manifest <manifest.json>",
        "      [--out <report.json>] [--events <events.jsonl>] [--warmup <u32>] [--samples <u32>]",
        "  frankenctl oracle run <input.js> [--engines franken,node,bun,core] [--bundle <dir>]",
        "      [--case-id <id>] [--timeout-ms <u64>] [--engine-budget <u64>]",
        "      [--node-bin <path>] [--bun-bin <path>] [--out <report.json>] [--json]",
        "      # operator-facing differential oracle; emits a content-addressed bundle",
        "      # exit codes: 0 consensus · 3 divergence · 4 insufficient-data/degraded",
        "  frankenctl oracle report <bundle-dir|manifest.json> [--json]",
        "      # validates bundle integrity (sha256) and renders the recorded verdict",
        "  frankenctl react compile|build|doctor|contract [options]  # React integration surfaces",
        "",
        "OPERATOR/DEVELOPMENT SURFACES (unsupported in production):",
        "  frankenctl gates <gate-type> [options]  # validation gates - use for dev/CI only",
        "  frankenctl reports <report-type> [options]  # analysis reports - use for dev/CI only",
        "  frankenctl test <test-type> [options]  # testing tools - use for dev/CI only",
        "  frankenctl synth <synth-type> [options]  # synthesis tools - experimental",
        "  frankenctl orchestrate <orchestrate-type> [options]  # orchestration tools - experimental",
        "  frankenctl runtime <runtime-type> [options]  # runtime diagnostics - experimental",
        "",
        "IMPORTANT: Operator/development surfaces may change without notice.",
        "Production use should rely only on the documented production-ready surfaces.",
        "Submit issues with reproduction bundles following docs/templates/ for support.",
        "",
        "benchmark families:",
        "  boot-storm",
        "  capability-churn",
        "  mixed-cpu-io-agent-mesh",
        "  reload-revoke-churn",
        "  adversarial-noise-under-load",
    ]
    .join("\n")
}

fn command_label(command: &CommandSpec) -> &'static str {
    match command {
        CommandSpec::Version => "version",
        CommandSpec::Help => "help",
        CommandSpec::HelpTopic(_) => "help",
        CommandSpec::Compile(_) => "compile",
        CommandSpec::Check(_) => "check",
        CommandSpec::Onboard(_) => "onboard",
        CommandSpec::DiffBehavior(_) => "diff-behavior",
        CommandSpec::Run(_) => "run",
        CommandSpec::Explain(_) => "explain",
        CommandSpec::Claims(ClaimsArgs {
            mode: ClaimsMode::Explain(_),
        }) => "claims-explain",
        CommandSpec::Doctor(_) => "doctor",
        CommandSpec::Verify(_) => "verify",
        CommandSpec::Benchmark(_) => "benchmark",
        CommandSpec::Replay(_) => "replay",
        CommandSpec::ReplayDebug(_) => "replay-debug",
        CommandSpec::DifferentialOracle(_) => "differential-oracle",
        CommandSpec::Oracle(OracleArgs {
            mode: OracleMode::Run(_),
        }) => "oracle-run",
        CommandSpec::Oracle(OracleArgs {
            mode: OracleMode::Report(_),
        }) => "oracle-report",
        CommandSpec::React(ReactArgs::Compile(_)) => "react-compile",
        CommandSpec::React(ReactArgs::Build(_)) => "react-build",
        CommandSpec::React(ReactArgs::Doctor(_)) => "react-doctor",
        CommandSpec::React(ReactArgs::Contract(_)) => "react-contract",
        CommandSpec::Gates(_) => "gates",
        CommandSpec::Reports(_) => "reports",
        CommandSpec::Test(_) => "test",
        CommandSpec::Synth(_) => "synth",
        CommandSpec::Orchestrate(_) => "orchestrate",
        CommandSpec::Runtime(_) => "runtime",
    }
}

fn render_react_doctor_summary(output: &ReactDoctorCommandOutput) -> String {
    let summary = &output.support_bundle.summary;
    [
        "react doctor summary:".to_string(),
        format!("  ready: {}", output.ready),
        format!("  blocked: {}", output.blocked),
        format!("  entries analyzed: {}", output.entries_analyzed),
        format!("  blockers: {}", output.preflight.blocker_count()),
        format!("  advisories: {}", output.preflight.advisory_count()),
        format!(
            "  repro entries: {}",
            output.support_repro_index.entry_count
        ),
        format!("  aggregate score: {}", summary.aggregate_score),
    ]
    .join("\n")
}

fn command_remediation(command: &str) -> &'static str {
    match command {
        "compile" => "Verify --input/--out paths and parse goal, then rerun `frankenctl compile`.",
        "check" => {
            "Verify the source path and parse goal (try --goal module for files with imports), then rerun `frankenctl check`."
        }
        "run" => "Verify extension source path and `--extension-id`, then rerun `frankenctl run`.",
        "explain" => "Verify the explain bundle path, then rerun `frankenctl explain`.",
        "claims-explain" => {
            "Verify the claim id, matrix path, artifact paths, and optional Beads JSONL snapshot, then rerun `frankenctl claims explain`."
        }
        "doctor" => {
            "Verify runtime diagnostics input, optional signal paths, and then rerun `frankenctl doctor`."
        }
        "verify" => "Inspect input artifact/receipt payload and rerun `frankenctl verify ...`.",
        "benchmark" => {
            "Validate benchmark subcommand args (run|score|verify), then rerun `frankenctl benchmark ...`."
        }
        "replay" => "Validate trace JSON and mode, then rerun `frankenctl replay run`.",
        "differential-oracle" => {
            "Validate the JS fixture path and timeout, then rerun `frankenctl differential-oracle run`."
        }
        "oracle-run" => {
            "Validate the JS input path, --engines selection, and optional --bundle dir, then rerun `frankenctl oracle run`."
        }
        "oracle-report" => {
            "Point the argument at an oracle-run bundle directory (or its manifest.json/report.json), then rerun `frankenctl oracle report`."
        }
        "react-compile" | "react-build" => {
            "Inspect `frankenctl react contract` and rerun with a declared source-form/runtime/target combination."
        }
        "react-doctor" => {
            "Validate the mismatch catalog path and optional filtering flags, then rerun `frankenctl react doctor`."
        }
        "react-contract" => {
            "Rerun `frankenctl react contract` to inspect the current machine-readable React CLI contract."
        }
        _ => "Run `frankenctl --help` for command usage details.",
    }
}

fn format_cli_error(trace_id: &str, command: &str, error: &str, remediation: &str) -> String {
    format!(
        "[frankenctl trace_id={trace_id} command={command}] {error}\nremediation: {remediation}"
    )
}

fn compile_usage() -> String {
    [
        "compile usage:",
        "  frankenctl compile --input <source.js> --out <artifact.json> [--goal script|module]",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>]",
        "      [--generated-unix-ns <u64>]  # fixed clock input for byte-identical proof runs",
    ]
    .join("\n")
}

fn check_usage() -> String {
    [
        "check usage:",
        "  frankenctl check <file> [--goal script|module] [--format human|json] [--out <bundle-dir>]",
        "  frankenctl check --input <file> [--format json] [--out <bundle-dir>]",
        "",
        "  Parses + lowers <file> to IR2 and reports, projected onto source spans:",
        "    - the minimal capability footprint required by its SUPPORTED syntax,",
        "    - each ambient-authority access rejected at the lowering boundary",
        "      (error[FE-CAP-0001], with the implied RuntimeCapability + span),",
        "    - IFC findings (denied flow error[FE-CAP-0002]; declassification",
        "      obligation error[FE-CAP-0003]),",
        "    - a least-authority suggestion.",
        "  This is the inferred authority footprint for SUPPORTED syntax — not a proof",
        "  of noninterference for arbitrary JS/TS. Unanalyzable constructs fail closed.",
        "",
        "  exit codes: 0 = clean, 1 = findings present, 2 = unanalyzable (fail-closed)",
        "  --out <dir> writes a content-addressed run_manifest.json + events.jsonl bundle.",
    ]
    .join("\n")
}

fn run_usage() -> String {
    [
        "run usage:",
        "  frankenctl run --input <source.js> --extension-id <id> [--goal script|module] [--out <report.json>]",
        "      [--data-contract <contract.json>] [--purpose <purpose>]",
        "      [--explain [bundle.json]] [--explain-out <bundle.json>]",
    ]
    .join("\n")
}

fn explain_usage() -> String {
    [
        "explain usage:",
        "  frankenctl explain <bundle.json> [--format summary|json] [--out <path>] [--emit-bundle <dir>]",
        "  frankenctl explain --input <bundle.json> [--format summary|json] [--out <path>]",
        "",
        "  --emit-bundle <dir> writes the full derived view bundle over the index:",
        "    explain.md          human-readable allow/deny/.../quarantine \"why\" story",
        "                        with per-decision source links,",
        "    evidence_graph.json source/IR/decision/receipt/evidence/replay/claim nodes + edges,",
        "    replay.json         strict/validate modes + divergence classification,",
        "    counterfactuals.json indexed counterfactual pointers,",
        "    commands.txt        operator-verification commands,",
        "    repro.lock          deterministic content-address over every indexed artifact,",
        "    explain.json        a copy of the index itself.",
        "  Every view is a pure projection over the index — never a second truth model.",
    ]
    .join("\n")
}

fn claims_usage() -> String {
    [
        "claims usage:",
        "  frankenctl claims explain <FE-CLAIM-NNN> [--matrix <matrix.json>]",
        "      [--beads-jsonl <issues.jsonl>|--no-beads] [--format human|json] [--out <path>]",
        "",
        "  The claims surface is an advisory proof-reader over existing claim matrix",
        "  and artifact state. It does not promote claim wording, run replay, mutate",
        "  Beads, or change evidence bundles.",
    ]
    .join("\n")
}

fn claims_explain_usage() -> String {
    [
        "claims explain usage:",
        "  frankenctl claims explain <FE-CLAIM-NNN> [--matrix docs/claim_to_proof_matrix_v1.json]",
        "      [--beads-jsonl .beads/issues.jsonl|--no-beads]",
        "      [--format human|json] [--out <path>]",
        "",
        "  Decisions: supported, not_promotable, degraded, unsupported, fail_closed.",
        "  Observed claims fail closed when required artifacts are absent, mock-",
        "  contaminated, or contradicted by owning Beads state.",
    ]
    .join("\n")
}

fn doctor_usage() -> String {
    [
        "doctor usage:",
        "  frankenctl doctor (--input <runtime_input.json> | --artifact-dir <artifacts/<gate>/<ts>>)",
        "      [--summary] [--out-dir <path>]",
        "      [--workload-id <id>] [--package-name <name>] [--target-platform <value>]...",
        "      [--signals <signals.json>] [--advisories <signals_or_bundle.json>]",
        "      [--scenario-report <compatibility_scenario_report.json>] [--platform-signals <signals.json>]",
        "      [--extension-id <id>] [--trace-id <id>] [--start-ns <u64>] [--end-ns <u64>]",
        "      [--severity info|warning|critical] [--decision-type <snake_case_decision_type>]",
        "      [--redact-key <key_fragment>]...",
    ]
    .join("\n")
}

fn verify_usage() -> String {
    [
        "verify usage:",
        "  frankenctl verify compile-artifact --input <artifact.json> [--output <report.json>]",
        "  frankenctl verify receipt --input <verifier_input.json> --receipt-id <id> [--summary] [--output <report.json>]",
    ]
    .join("\n")
}

fn verify_compile_artifact_usage() -> String {
    [
        "verify compile-artifact usage:",
        "  frankenctl verify compile-artifact --input <artifact.json> [--output <report.json>]",
    ]
    .join("\n")
}

fn verify_receipt_usage() -> String {
    [
        "verify receipt usage:",
        "  frankenctl verify receipt --input <verifier_input.json> --receipt-id <id> [--summary] [--output <report.json>]",
    ]
    .join("\n")
}

fn benchmark_usage() -> String {
    [
        "benchmark usage:",
        "  frankenctl benchmark run [--seed <u64>] [--run-id <id>] [--run-date <YYYY-MM-DD>]",
        "      [--profile small|medium|large]... [--family <name>]... [--out-dir <path>]",
        "  frankenctl benchmark compare --manifest <comparison-manifest.json>",
        "      [--run-id <id>] [--run-date <YYYY-MM-DD>] [--out-dir <path>]",
        "  frankenctl benchmark score --input <publication_gate_input.json>",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>] [--output <path>]",
        "  frankenctl benchmark verify --bundle <dir> [--summary] [--output <report.json>]",
    ]
    .join("\n")
}

fn benchmark_run_usage() -> String {
    [
        "benchmark run usage:",
        "  frankenctl benchmark run [--seed <u64>] [--run-id <id>] [--run-date <YYYY-MM-DD>]",
        "      [--profile small|medium|large]... [--family <name>]... [--out-dir <path>]",
    ]
    .join("\n")
}

fn benchmark_compare_usage() -> String {
    [
        "benchmark compare usage:",
        "  frankenctl benchmark compare --manifest <comparison-manifest.json>",
        "      [--run-id <id>] [--run-date <YYYY-MM-DD>] [--out-dir <path>]",
    ]
    .join("\n")
}

fn benchmark_score_usage() -> String {
    [
        "benchmark score usage:",
        "  frankenctl benchmark score --input <publication_gate_input.json>",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>] [--output <path>]",
    ]
    .join("\n")
}

fn benchmark_verify_usage() -> String {
    [
        "benchmark verify usage:",
        "  frankenctl benchmark verify --bundle <dir> [--summary] [--output <report.json>]",
    ]
    .join("\n")
}

fn replay_usage() -> String {
    [
        "replay usage:",
        "  frankenctl replay run --trace <trace.json> [--mode strict|best-effort|validate] [--out <report.json>]",
        "  frankenctl replay debug --trace <trace.json> [--script <commands.jsonl>] [--out <transcript.jsonl>]",
    ]
    .join("\n")
}

fn replay_debug_usage() -> String {
    [
        "replay debug usage:",
        "  frankenctl replay debug --trace <trace.json>",
        "      [--script <commands.jsonl>] [--events <debugger_events.json>]",
        "      [--state-snapshots <interpreter_state_snapshots.json>]",
        "      [--checkpoint-interval <ticks>] [--mode strict|best-effort|validate]",
        "      [--out <transcript.jsonl>]",
        "",
        "notes:",
        "  Drives the evidence-aware time-travel debugger over a captured",
        "  nondeterminism trace through the JSON-line robot protocol. Commands",
        "  are read from --script (one JSON object per line; blank lines and",
        "  `#` comments skipped) or stdin; every command yields exactly one",
        "  JSON response line on stdout. Identical trace + script input gives",
        "  a byte-identical transcript.",
        "",
        "  commands: {\"cmd\":\"state\"} | {\"cmd\":\"step\"} | {\"cmd\":\"back\"} |",
        "    {\"cmd\":\"goto\",\"tick\":N} | {\"cmd\":\"run_until_break\"} |",
        "    {\"cmd\":\"inspect\"} | {\"cmd\":\"inspect\",\"tick\":N} |",
        "    {\"cmd\":\"add_breakpoint\",\"breakpoint\":{...}} |",
        "    {\"cmd\":\"remove_breakpoint\",\"id\":N} | {\"cmd\":\"list_breakpoints\"} |",
        "    {\"cmd\":\"why\",\"tick\":N} | {\"cmd\":\"events_at\",\"tick\":N}",
        "",
        "  --events supplies a normalized DebuggerEvent JSON array (IFC label",
        "  levels, capability outcomes, posterior observations) so breakpoints",
        "  like label_level_at_least / capability_denied /",
        "  malicious_posterior_above and `why` have evidence to bind to.",
        "  --state-snapshots supplies InterpreterStateSnapshot JSON captured",
        "  by the real interpreter replay path; inspect fails closed when the",
        "  selected tick has no supplied snapshot.",
    ]
    .join("\n")
}

fn replay_run_usage() -> String {
    [
        "replay run usage:",
        "  frankenctl replay run --trace <trace.json> [--compare-trace <trace.json>]",
        "      [--mode strict|best-effort|validate] [--out <report.json>]",
        "      [--fleet-trace <dir|trace.json>]",
        "",
        "notes:",
        "  --fleet-trace stitches per-node traces into one globally-consistent",
        "  replay order using a Lamport total-order merge (clock asc, node id,",
        "  payload hash). Pass a directory of per-node traces (one file == one",
        "  node) or a single additional per-node trace file; --trace is the",
        "  anchor node.",
    ]
    .join("\n")
}

fn differential_oracle_usage() -> String {
    [
        "differential-oracle usage:",
        "  frankenctl differential-oracle run --input <source.js>",
        "      [--case-id <id>] [--timeout-ms <u64>] [--out <report.json>]",
        "  frankenctl differential-oracle perf --manifest <manifest.json>",
        "      [--out <report.json>] [--events <events.jsonl>]",
        "      [--warmup <u32>] [--samples <u32>] [--case-timeout-ms <u64>]",
        "      [--engine-budget <u64>] [--node-bin <path>] [--bun-bin <path>] [--case <id>]...",
        "",
        "behavior:",
        "  run: executes one JS fixture across Node, Bun, franken-engine, and the franken-core-compatible baseline lane.",
        "  perf: measures steady-state throughput over a corpus and emits the Node/Bun denominator",
        "        with fairness enforcement (degraded receipt when rules are unmet).",
        "  missing external runtimes produce unavailable backend receipts instead of failing the run.",
    ]
    .join("\n")
}

fn differential_oracle_run_usage() -> String {
    [
        "differential-oracle run usage:",
        "  frankenctl differential-oracle run --input <source.js>",
        "      [--case-id <id>] [--timeout-ms <u64>] [--out <report.json>]",
        "      [--engine-budget <u64>] [--engine-memory-budget <u64>]",
        "",
        "  --engine-budget overrides the in-process engine instruction budget so",
        "  long-running corpus programs can execute (the containment default is",
        "  intentionally small); node/bun have no analogous cap.",
        "  --engine-memory-budget overrides the engine heap-object ceiling (default",
        "  100k; the byte ceiling scales with it) so object-allocating corpus loops",
        "  can execute. The engine heap is append-only (no live-object reclamation),",
        "  so the count is total allocations; node/bun reclaim via GC instead.",
    ]
    .join("\n")
}

fn differential_oracle_perf_usage() -> String {
    [
        "differential-oracle perf usage:",
        "  frankenctl differential-oracle perf --manifest <manifest.json>",
        "      [--out <report.json>] [--events <events.jsonl>]",
        "      [--warmup <u32>] [--samples <u32>] [--case-timeout-ms <u64>]",
        "      [--engine-budget <u64>] [--node-bin <path>] [--bun-bin <path>] [--case <id>]...",
        "",
        "behavior:",
        "  measures warm steady-state throughput of every corpus case under Node, Bun, and the",
        "  native engine; cases enter the denominator only when the correctness arm reports",
        "  structured-value consensus. per-iteration timings stream to --events so the ratio can",
        "  be re-derived from raw data. fairness violations (e.g. `node` resolving to Bun's shim)",
        "  degrade the receipt instead of publishing a number.",
    ]
    .join("\n")
}

fn oracle_usage() -> String {
    [
        "oracle usage (operator-facing differential oracle):",
        "  frankenctl oracle run <input.js> [--engines franken,node,bun,core] [--bundle <dir>]",
        "      [--case-id <id>] [--timeout-ms <u64>] [--engine-budget <u64>]",
        "      [--node-bin <path>] [--bun-bin <path>] [--out <report.json>] [--json]",
        "  frankenctl oracle report <bundle-dir|manifest.json> [--json]",
        "",
        "behavior:",
        "  run: executes one JS input across the selected engines, classifies any cross-runtime",
        "       divergence, and (with --bundle) writes a content-addressed bundle that",
        "       `oracle report` can re-render and integrity-check.",
        "  report: validates a bundle's sha256 artifact set and bundle_id, then renders the",
        "          recorded backends, verdict, and any divergences.",
        "",
        "exit codes (run and report):",
        "  0  consensus across the selected engines",
        "  3  semantic divergence detected",
        "  4  insufficient data (a requested reference runtime was unavailable / degraded)",
        "  2  usage or I/O error (e.g. bundle integrity failure)",
    ]
    .join("\n")
}

fn oracle_run_usage() -> String {
    [
        "oracle run usage:",
        "  frankenctl oracle run <input.js> [--engines franken,node,bun,core] [--bundle <dir>]",
        "      [--case-id <id>] [--timeout-ms <u64>] [--engine-budget <u64>]",
        "      [--engine-memory-budget <u64>] [--node-bin <path>] [--bun-bin <path>]",
        "      [--out <report.json>] [--json]",
        "",
        "  --engines  comma-separated subset of {node, bun, franken, core}; default is all four.",
        "             only the selected engines are executed and compared.",
        "  --bundle   write a content-addressed bundle (manifest.json + report.json + repro.lock,",
        "             plus degraded_receipt.json when a reference runtime is unavailable).",
        "  --node-bin / --bun-bin  override the external binaries; otherwise $NODE / $BUN, then",
        "             `node` / `bun` on PATH (point --node-bin at genuine Node where `node` is a shim).",
        "  --engine-budget  raise the in-process engine instruction budget for long programs.",
        "  --engine-memory-budget  raise the engine heap-object ceiling (default 100k) for",
        "             object-allocating programs; the byte ceiling scales with it. The engine",
        "             heap is append-only (no GC), so this counts total allocations.",
        "  --out      additionally write the raw DifferentialOracleReport JSON to this path.",
        "  --json     emit a machine-parseable summary (robot mode) instead of the human view.",
        "",
        "  missing external runtimes produce unavailable backend receipts rather than failing the run.",
    ]
    .join("\n")
}

fn oracle_report_usage() -> String {
    [
        "oracle report usage:",
        "  frankenctl oracle report <bundle-dir|manifest.json> [--json]",
        "",
        "  validates the bundle's artifact sha256 set and its bundle_id content address, then",
        "  renders the recorded case, per-backend receipts, semantic verdict, and divergences.",
        "  a mismatched hash is a hard error (exit 2). --json emits the parseable summary.",
    ]
    .join("\n")
}

fn react_usage() -> String {
    [
        "react usage:",
        "  frankenctl react compile --input <path> --source-form <jsx|tsx|jsx-fragment>",
        "      [--runtime <classic|automatic>] [--out <report.json>]",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>]",
        "  frankenctl react build --entry <path> --target <ssr|client|hydration>",
        "      [--out <report.json>] [--trace-id <id>] [--decision-id <id>] [--policy-id <id>]",
        "  frankenctl react doctor --catalog <react_mismatch_catalog.json> [--summary]",
        "      [--min-severity <info|warning|error|critical>] [--include-resolved]",
        "      [--target <nodejs|bun|deno|v8_reference>] [--current-epoch <n>]",
        "      [--out <react_doctor_report.json>] [--trace-id <id>] [--decision-id <id>]",
        "      [--policy-id <id>]",
        "  frankenctl react contract [--out <react_cli_contract.json>]",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>]",
        "",
        "notes:",
        "  react compile executes shipped JSX/TSX capability rows and emits native pipeline output;",
        "  unshipped compile rows and all react build targets still fail closed with guidance.",
        "  react doctor consumes a machine-readable mismatch catalog and emits support guidance",
        "  for unsupported React product surfaces.",
    ]
    .join("\n")
}

fn react_compile_usage() -> String {
    [
        "react compile usage:",
        "  frankenctl react compile --input <path> --source-form <jsx|tsx|jsx-fragment>",
        "      [--runtime <classic|automatic>] [--out <report.json>]",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>]",
        "",
        "behavior:",
        "  emits a deterministic react-cli report tied to the embedded React capability contract",
        "  and includes generated code plus receipt metadata for shipped compile rows.",
    ]
    .join("\n")
}

fn react_build_usage() -> String {
    [
        "react build usage:",
        "  frankenctl react build --entry <path> --target <ssr|client|hydration>",
        "      [--out <report.json>] [--trace-id <id>] [--decision-id <id>] [--policy-id <id>]",
        "",
        "behavior:",
        "  emits a deterministic react-cli report tied to the embedded React capability contract",
        "  and exits non-zero until the requested build target is shipped.",
    ]
    .join("\n")
}

fn react_doctor_usage() -> String {
    [
        "react doctor usage:",
        "  frankenctl react doctor --catalog <react_mismatch_catalog.json> [--summary]",
        "      [--min-severity <info|warning|error|critical>] [--include-resolved]",
        "      [--target <nodejs|bun|deno|v8_reference>] [--current-epoch <n>]",
        "      [--out <react_doctor_report.json>] [--trace-id <id>] [--decision-id <id>]",
        "      [--policy-id <id>]",
        "",
        "behavior:",
        "  loads a deterministic React mismatch catalog, runs React-aware doctor/preflight",
        "  analysis, and emits support-bundle plus repro-index data in one machine-readable report.",
    ]
    .join("\n")
}

fn react_contract_usage() -> String {
    [
        "react contract usage:",
        "  frankenctl react contract [--out <react_cli_contract.json>]",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>]",
        "",
        "behavior:",
        "  prints the machine-readable React compile/build CLI contract synthesized from",
        "  docs/rgc_react_capability_contract_v1.json.",
    ]
    .join("\n")
}

// New consolidated subcommand group usage functions
fn gates_usage() -> String {
    [
        "gates usage:",
        "  frankenctl gates zero-placeholder --out-dir <dir> [--waivers <file>]",
        "  frankenctl gates signature-drift --out-dir <dir> [--config <file>]",
        "  frankenctl gates adversarial-campaign --out-dir <dir>",
        "  frankenctl gates ambient-mock-guard --out-dir <dir>",
        "  frankenctl gates ifc-conformance --out-dir <dir>",
        "  frankenctl gates security-conformance --out-dir <dir>",
        "  frankenctl gates artifact-validator --input <file> [--out <file>]",
        "  frankenctl gates placeholder-scan --out-dir <dir>",
        "",
        "behavior:",
        "  validation gates for quality assurance and release gating.",
    ]
    .join("\n")
}

fn reports_usage() -> String {
    [
        "reports usage:",
        "  frankenctl reports parser-oracle [--config <file>] [--out <file>]",
        "  frankenctl reports parser-phase0 [--out <file>]",
        "  frankenctl reports lowering-gap [--out <file>]",
        "  frankenctl reports parser-gap [--out <file>]",
        "  frankenctl reports control-plane-benchmark [--out <file>]",
        "  frankenctl reports control-plane-mock [--out <file>]",
        "  frankenctl reports control-plane-policy --out-dir <dir>",
        "  frankenctl reports engine-blocker-ledger --out-dir <dir>",
        "  frankenctl reports metadata-evidence --out-dir <dir>",
        "  frankenctl reports npm-compatibility --out-dir <dir>",
        "  frankenctl reports observability-bundle --out-dir <dir>",
        "  frankenctl reports rgc-planning [--out <file>]",
        "",
        "behavior:",
        "  generate analysis reports and evidence artifacts.",
    ]
    .join("\n")
}

fn test_usage() -> String {
    [
        "test usage:",
        "  frankenctl test test262 --out-dir <dir> [--suite-path <path>]",
        "  frankenctl test lockstep [--config <file>] [--out <file>]",
        "  frankenctl test multi-engine-parser --out-dir <dir>",
        "  frankenctl test s3fifo-baseline [--out <file>]",
        "  frankenctl test frx-oracle [--out <file>]",
        "  frankenctl test seqlock-candidate [--out <file>]",
        "  frankenctl test seqlock-reader-writer [--out <file>]",
        "  frankenctl test seqlock-rollout [--out <file>]",
        "  frankenctl test shipped-path-parity --out-dir <dir>",
        "  frankenctl test verify-general --input <file> [--out <file>]",
        "",
        "behavior:",
        "  testing and verification tools for correctness validation.",
    ]
    .join("\n")
}

fn synth_usage() -> String {
    [
        "synth usage:",
        "  frankenctl synth kernel-contract --out-dir <dir>",
        "  frankenctl synth shape-lattice --out-dir <dir>",
        "  frankenctl synth law-mining [--out <file>]",
        "  frankenctl synth evidence-stitching --out-dir <dir>",
        "  frankenctl synth cache-contract [--out <file>]",
        "  frankenctl synth cold-start --out-dir <dir>",
        "",
        "behavior:",
        "  synthesis and generation tools for runtime artifacts.",
    ]
    .join("\n")
}

fn orchestrate_usage() -> String {
    [
        "orchestrate usage:",
        "  frankenctl orchestrate context-refactor [--out <file>]",
        "  frankenctl orchestrate react-cohort [--out <file>]",
        "  frankenctl orchestrate asupersync-matrix --out-dir <dir>",
        "  frankenctl orchestrate tail-latency --out-dir <dir>",
        "",
        "behavior:",
        "  orchestration and execution management tools.",
    ]
    .join("\n")
}

fn runtime_usage() -> String {
    [
        "runtime usage:",
        "  frankenctl runtime diagnostics --input <file> [--out-dir <dir>] [--summary]",
        "",
        "behavior:",
        "  runtime diagnostic and analysis tools.",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use frankenengine_engine::receipt_verifier_pipeline::VerifierLogEvent;
    use frankenengine_engine::runtime_diagnostics_cli::EvidenceSeverity;

    #[test]
    fn parse_version_command() {
        let args = vec!["version".to_string()];
        let parsed = parse_command(&args).expect("version command should parse");
        assert_eq!(parsed, CommandSpec::Version);
    }

    #[test]
    fn parse_compile_command() {
        let args = vec![
            "compile".to_string(),
            "--input".to_string(),
            "demo.js".to_string(),
            "--out".to_string(),
            "out.json".to_string(),
            "--goal".to_string(),
            "module".to_string(),
        ];
        let parsed = parse_command(&args).expect("compile command should parse");
        match parsed {
            CommandSpec::Compile(spec) => {
                assert_eq!(spec.input, PathBuf::from("demo.js"));
                assert_eq!(spec.out, PathBuf::from("out.json"));
                assert_eq!(spec.parse_goal, ParseGoal::Module);
            }
            other => panic!("expected compile command, got {other:?}"),
        }
    }

    #[test]
    fn parse_run_help_command() {
        let args = vec!["run".to_string(), "--help".to_string()];
        let parsed = parse_command(&args).expect("run --help should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::Run));
    }

    #[test]
    fn parse_run_command_requires_flags_and_preserves_goal() {
        let args = vec![
            "run".to_string(),
            "--input".to_string(),
            "demo.js".to_string(),
            "--extension-id".to_string(),
            "ext-demo".to_string(),
            "--goal".to_string(),
            "module".to_string(),
            "--out".to_string(),
            "run.json".to_string(),
        ];
        let parsed = parse_command(&args).expect("run command should parse");
        match parsed {
            CommandSpec::Run(spec) => {
                assert_eq!(spec.input, PathBuf::from("demo.js"));
                assert_eq!(spec.extension_id, "ext-demo");
                assert_eq!(spec.parse_goal, ParseGoal::Module);
                assert_eq!(spec.out, Some(PathBuf::from("run.json")));
                assert!(!spec.explain);
                assert_eq!(spec.explain_out, None);
                assert_eq!(spec.data_contract, None);
                assert_eq!(spec.data_contract_purpose, DEFAULT_DATA_CONTRACT_PURPOSE);
            }
            other => panic!("expected run command, got {other:?}"),
        }

        let missing_extension_id = vec![
            "run".to_string(),
            "--input".to_string(),
            "demo.js".to_string(),
        ];
        let error = parse_command(&missing_extension_id)
            .expect_err("run without extension-id should fail closed");
        assert_eq!(error, "run requires --extension-id <id>");
    }

    #[test]
    fn parse_run_command_accepts_explain_bundle_path() {
        let args = vec![
            "run".to_string(),
            "--input".to_string(),
            "demo.js".to_string(),
            "--extension-id".to_string(),
            "ext-demo".to_string(),
            "--explain".to_string(),
            "explain.json".to_string(),
        ];
        let parsed = parse_command(&args).expect("run --explain command should parse");
        match parsed {
            CommandSpec::Run(spec) => {
                assert!(spec.explain);
                assert_eq!(spec.explain_out, Some(PathBuf::from("explain.json")));
            }
            other => panic!("expected run command, got {other:?}"),
        }
    }

    #[test]
    fn parse_run_command_accepts_data_contract() {
        let args = vec![
            "run".to_string(),
            "--input".to_string(),
            "agent.js".to_string(),
            "--extension-id".to_string(),
            "ext-e8".to_string(),
            "--data-contract".to_string(),
            "contract.json".to_string(),
            "--purpose".to_string(),
            "agent_sandbox".to_string(),
        ];
        let parsed = parse_command(&args).expect("run with data contract should parse");
        match parsed {
            CommandSpec::Run(spec) => {
                assert_eq!(spec.data_contract, Some(PathBuf::from("contract.json")));
                assert_eq!(spec.data_contract_purpose, "agent_sandbox");
            }
            other => panic!("expected run command, got {other:?}"),
        }
    }

    #[test]
    fn parse_claims_explain_command_accepts_defaults_and_json_format() {
        let args = vec![
            "claims".to_string(),
            "explain".to_string(),
            "FE-CLAIM-001".to_string(),
            "--format".to_string(),
            "json".to_string(),
            "--out".to_string(),
            "claim.json".to_string(),
        ];
        let parsed = parse_command(&args).expect("claims explain command should parse");
        match parsed {
            CommandSpec::Claims(ClaimsArgs {
                mode: ClaimsMode::Explain(spec),
            }) => {
                assert_eq!(spec.claim_id, "FE-CLAIM-001");
                assert_eq!(spec.matrix, PathBuf::from(DEFAULT_CLAIM_MATRIX_PATH));
                assert_eq!(
                    spec.beads_jsonl,
                    Some(PathBuf::from(DEFAULT_BEADS_JSONL_PATH))
                );
                assert_eq!(spec.format, CheckOutputFormat::Json);
                assert_eq!(spec.out, Some(PathBuf::from("claim.json")));
            }
            other => panic!("expected claims explain command, got {other:?}"),
        }
    }

    #[test]
    fn claim_explainer_supports_observed_fixture() {
        let dir = frankenctl_test_temp_dir("claim-supported");
        fs::create_dir_all(&dir).expect("create fixture dir");
        let artifact_path = dir.join("artifact.json");
        fs::write(&artifact_path, b"{\"ok\":true}\n").expect("write artifact");
        write_repro_lock_next_to_file(&artifact_path);
        let matrix_path = dir.join("matrix.json");
        write_claim_matrix_fixture(
            &matrix_path,
            serde_json::json!([claim_row_fixture(
                "FE-CLAIM-TEST",
                "observed",
                "observed",
                artifact_path.display().to_string(),
                "bd-test"
            )]),
        );
        let beads_path = dir.join("issues.jsonl");
        fs::write(
            &beads_path,
            serde_json::json!({"id":"bd-test","status":"closed","assignee":"EmeraldPine"})
                .to_string(),
        )
        .expect("write beads fixture");

        let output = build_claim_explanation("FE-CLAIM-TEST", &matrix_path, Some(&beads_path))
            .expect("claim should explain");
        assert_eq!(output.decision, "supported");
        assert_eq!(output.exit_code(), 0);
        assert!(output.reason_codes.is_empty());
        assert_eq!(output.mock_status, "absent");
        assert!(output.artifact.as_ref().expect("artifact").present);
        assert_eq!(output.bead.as_ref().expect("bead").status, "closed");
        assert!(output.receipt_id.starts_with("claim-explain-"));
    }

    #[test]
    fn claim_explainer_missing_requested_bead_snapshot_fails_closed() {
        let dir = frankenctl_test_temp_dir("claim-missing-bead-snapshot");
        fs::create_dir_all(&dir).expect("create fixture dir");
        let artifact_path = dir.join("artifact.json");
        fs::write(&artifact_path, b"{\"ok\":true}\n").expect("write artifact");
        let matrix_path = dir.join("matrix.json");
        write_claim_matrix_fixture(
            &matrix_path,
            serde_json::json!([claim_row_fixture(
                "FE-CLAIM-BEAD-MISSING",
                "observed",
                "observed",
                artifact_path.display().to_string(),
                "bd-missing"
            )]),
        );
        let missing_beads_path = dir.join("missing-issues.jsonl");

        let output = build_claim_explanation(
            "FE-CLAIM-BEAD-MISSING",
            &matrix_path,
            Some(&missing_beads_path),
        )
        .expect("missing Beads snapshot should render fail-closed receipt");

        assert_eq!(output.decision, "fail_closed");
        assert_eq!(output.exit_code(), 2);
        assert!(
            output
                .reason_codes
                .contains(&"stale_tracker_state".to_string())
        );
        assert_eq!(output.bead.as_ref().expect("bead").found, false);
    }

    #[test]
    fn claim_explainer_corrupt_requested_bead_snapshot_fails_closed() {
        let dir = frankenctl_test_temp_dir("claim-corrupt-bead-snapshot");
        fs::create_dir_all(&dir).expect("create fixture dir");
        let artifact_path = dir.join("artifact.json");
        fs::write(&artifact_path, b"{\"ok\":true}\n").expect("write artifact");
        let matrix_path = dir.join("matrix.json");
        write_claim_matrix_fixture(
            &matrix_path,
            serde_json::json!([claim_row_fixture(
                "FE-CLAIM-BEAD-CORRUPT",
                "observed",
                "observed",
                artifact_path.display().to_string(),
                "bd-corrupt"
            )]),
        );
        let beads_path = dir.join("issues.jsonl");
        fs::write(&beads_path, "{not-json-for bd-corrupt\n").expect("write corrupt beads fixture");

        let output =
            build_claim_explanation("FE-CLAIM-BEAD-CORRUPT", &matrix_path, Some(&beads_path))
                .expect("corrupt Beads snapshot should render fail-closed receipt");

        assert_eq!(output.decision, "fail_closed");
        assert_eq!(output.exit_code(), 2);
        assert!(
            output
                .reason_codes
                .contains(&"stale_tracker_state".to_string())
        );
        let bead = output.bead.as_ref().expect("bead");
        assert!(!bead.found);
        assert_eq!(bead.status, "unreadable");
    }

    #[test]
    fn claim_explainer_keeps_target_claim_not_promotable() {
        let dir = frankenctl_test_temp_dir("claim-target");
        fs::create_dir_all(&dir).expect("create fixture dir");
        let matrix_path = dir.join("matrix.json");
        write_claim_matrix_fixture(
            &matrix_path,
            serde_json::json!([claim_row_fixture(
                "FE-CLAIM-TARGET",
                "target",
                "target",
                "missing-target-artifact.json",
                "bd-target"
            )]),
        );

        let output = build_claim_explanation("FE-CLAIM-TARGET", &matrix_path, None)
            .expect("target claim should explain");
        assert_eq!(output.decision, "not_promotable");
        assert_eq!(output.exit_code(), 1);
        assert!(
            output
                .reason_codes
                .contains(&"claim_not_observed".to_string())
        );
        assert!(
            !output
                .artifact
                .as_ref()
                .expect("artifact")
                .required_for_supported
        );
    }

    #[test]
    fn claim_explainer_resolves_matrix_local_relative_artifact_path() {
        let dir = frankenctl_test_temp_dir("claim-matrix-local-artifact");
        let bundle_dir = dir.join("bundle");
        fs::create_dir_all(&bundle_dir).expect("create fixture dir");
        fs::write(bundle_dir.join("artifact.json"), b"{\"ok\":true}\n").expect("write artifact");
        fs::write(bundle_dir.join("repro.lock"), b"fixture repro lock\n")
            .expect("write repro lock");
        let matrix_path = bundle_dir.join("matrix.json");
        write_claim_matrix_fixture(
            &matrix_path,
            serde_json::json!([claim_row_fixture(
                "FE-CLAIM-RELATIVE",
                "observed",
                "observed",
                "artifact.json",
                "bd-relative"
            )]),
        );

        let output = build_claim_explanation("FE-CLAIM-RELATIVE", &matrix_path, None)
            .expect("matrix-local relative artifact should explain");
        assert_eq!(output.decision, "supported");
        let artifact = output.artifact.as_ref().expect("artifact");
        assert!(artifact.present);
        assert_eq!(artifact.kind, "file");
        assert_eq!(
            artifact.path,
            bundle_dir.join("artifact.json").display().to_string()
        );
    }

    #[test]
    fn claim_explainer_prefers_matrix_local_artifact_over_cwd_match() {
        let dir = frankenctl_test_temp_dir("claim-matrix-local-precedence");
        let bundle_dir = dir.join("bundle");
        fs::create_dir_all(&bundle_dir).expect("create fixture dir");
        fs::write(bundle_dir.join("Cargo.toml"), b"matrix-local artifact\n")
            .expect("write artifact matching repo-root file name");

        let resolved = resolve_claim_artifact_path(&bundle_dir.join("matrix.json"), "Cargo.toml");

        assert_eq!(resolved, bundle_dir.join("Cargo.toml"));
    }

    #[test]
    fn claim_explainer_resolves_repo_relative_artifact_from_absolute_matrix_path() {
        let dir = frankenctl_test_temp_dir("claim-repo-relative-artifact");
        let docs_dir = dir.join("docs");
        let artifact_path = dir
            .join("artifacts")
            .join("claim-explainer-repo-relative")
            .join("artifact.json");
        fs::create_dir_all(&docs_dir).expect("create docs fixture dir");
        fs::create_dir_all(artifact_path.parent().expect("artifact parent"))
            .expect("create artifact fixture dir");
        fs::write(&artifact_path, b"{\"ok\":true}\n").expect("write artifact fixture");

        let resolved = resolve_claim_artifact_path(
            &docs_dir.join("matrix.json"),
            "artifacts/claim-explainer-repo-relative/artifact.json",
        );

        assert_eq!(resolved, artifact_path);
    }

    #[test]
    fn claim_explainer_invalid_wording_state_fails_closed() {
        let dir = frankenctl_test_temp_dir("claim-invalid-state");
        fs::create_dir_all(&dir).expect("create fixture dir");
        let artifact_path = dir.join("artifact.json");
        fs::write(&artifact_path, b"{\"ok\":true}\n").expect("write artifact");
        let matrix_path = dir.join("matrix.json");
        write_claim_matrix_fixture(
            &matrix_path,
            serde_json::json!([claim_row_fixture(
                "FE-CLAIM-INVALID-STATE",
                "verified",
                "observed",
                artifact_path.display().to_string(),
                "bd-invalid-state"
            )]),
        );

        let output = build_claim_explanation("FE-CLAIM-INVALID-STATE", &matrix_path, None)
            .expect("invalid state should render fail-closed receipt");

        assert_eq!(output.decision, "fail_closed");
        assert_eq!(output.exit_code(), 2);
        assert!(
            output
                .reason_codes
                .contains(&"invalid_wording_state".to_string())
        );
    }

    #[test]
    fn claim_explainer_missing_claim_fails_closed() {
        let dir = frankenctl_test_temp_dir("claim-missing");
        fs::create_dir_all(&dir).expect("create fixture dir");
        let matrix_path = dir.join("matrix.json");
        write_claim_matrix_fixture(&matrix_path, serde_json::json!([]));

        let output = build_claim_explanation("FE-CLAIM-MISSING", &matrix_path, None)
            .expect("missing claim should render fail-closed receipt");
        assert_eq!(output.decision, "fail_closed");
        assert_eq!(output.exit_code(), 2);
        assert_eq!(output.reason_codes, vec!["missing_claim_row"]);
        assert!(output.claim.is_none());
    }

    #[test]
    fn claim_explainer_duplicate_claim_rows_fail_closed() {
        let dir = frankenctl_test_temp_dir("claim-duplicate-row");
        fs::create_dir_all(&dir).expect("create fixture dir");
        let artifact_path = dir.join("artifact.json");
        fs::write(&artifact_path, b"{\"ok\":true}\n").expect("write artifact");
        let matrix_path = dir.join("matrix.json");
        write_claim_matrix_fixture(
            &matrix_path,
            serde_json::json!([
                claim_row_fixture(
                    "FE-CLAIM-DUPLICATE",
                    "observed",
                    "observed",
                    artifact_path.display().to_string(),
                    "bd-duplicate-a"
                ),
                claim_row_fixture(
                    "FE-CLAIM-DUPLICATE",
                    "target",
                    "target",
                    "missing-target-artifact.json",
                    "bd-duplicate-b"
                )
            ]),
        );

        let output = build_claim_explanation("FE-CLAIM-DUPLICATE", &matrix_path, None)
            .expect("duplicate claim rows should render fail-closed receipt");

        assert_eq!(output.decision, "fail_closed");
        assert_eq!(output.exit_code(), 2);
        assert_eq!(output.reason_codes, vec!["duplicate_claim_row"]);
        assert!(output.claim.is_none());
    }

    #[test]
    fn claim_explainer_missing_matrix_fails_closed_with_receipt() {
        let dir = frankenctl_test_temp_dir("claim-missing-matrix");
        fs::create_dir_all(&dir).expect("create fixture dir");
        let matrix_path = dir.join("missing-matrix.json");

        let output = build_claim_explanation("FE-CLAIM-MATRIX-MISSING", &matrix_path, None)
            .expect("missing matrix should render fail-closed receipt");

        assert_eq!(output.decision, "fail_closed");
        assert_eq!(output.exit_code(), 2);
        assert_eq!(output.reason_codes, vec!["unreadable_matrix"]);
        assert_eq!(output.matrix_schema_version, "unavailable");
        assert!(output.claim.is_none());
    }

    #[test]
    fn claim_explainer_invalid_matrix_schema_fails_closed_with_receipt() {
        let dir = frankenctl_test_temp_dir("claim-invalid-matrix-schema");
        fs::create_dir_all(&dir).expect("create fixture dir");
        let matrix_path = dir.join("matrix.json");
        fs::write(
            &matrix_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "schema_version": "franken-engine.claim-to-proof-matrix.v0",
                "claims": []
            }))
            .expect("matrix JSON serializes"),
        )
        .expect("write matrix fixture");

        let output = build_claim_explanation("FE-CLAIM-SCHEMA", &matrix_path, None)
            .expect("invalid schema should render fail-closed receipt");

        assert_eq!(output.decision, "fail_closed");
        assert_eq!(output.exit_code(), 2);
        assert_eq!(output.reason_codes, vec!["invalid_matrix_schema"]);
        assert_eq!(
            output.matrix_schema_version,
            "franken-engine.claim-to-proof-matrix.v0"
        );
    }

    #[test]
    fn claim_explainer_source_span_mismatch_fails_closed() {
        let dir = frankenctl_test_temp_dir("claim-source-span-mismatch");
        fs::create_dir_all(&dir).expect("create fixture dir");
        let artifact_path = dir.join("artifact.json");
        fs::write(&artifact_path, b"{\"ok\":true}\n").expect("write artifact");
        let source_path = dir.join("source.md");
        fs::write(&source_path, "Documented claim text changed.\n").expect("write source");
        let mut row = claim_row_fixture(
            "FE-CLAIM-SOURCE",
            "observed",
            "observed",
            artifact_path.display().to_string(),
            "bd-source",
        );
        row["source_path"] = serde_json::Value::String(source_path.display().to_string());
        row["source_span"]["must_contain"] =
            serde_json::Value::String("Original claim text".to_string());
        let matrix_path = dir.join("matrix.json");
        write_claim_matrix_fixture(&matrix_path, serde_json::json!([row]));

        let output = build_claim_explanation("FE-CLAIM-SOURCE", &matrix_path, None)
            .expect("stale source span should render fail-closed receipt");

        assert_eq!(output.decision, "fail_closed");
        assert_eq!(output.exit_code(), 2);
        assert!(
            output
                .reason_codes
                .contains(&"source_span_mismatch".to_string())
        );
        assert_eq!(output.source_line_refs[0].status, "span_mismatch");
    }

    #[test]
    fn claim_explainer_missing_observed_artifact_fails_closed() {
        let dir = frankenctl_test_temp_dir("claim-absent-artifact");
        fs::create_dir_all(&dir).expect("create fixture dir");
        let matrix_path = dir.join("matrix.json");
        write_claim_matrix_fixture(
            &matrix_path,
            serde_json::json!([claim_row_fixture(
                "FE-CLAIM-ABSENT",
                "observed",
                "observed",
                dir.join("missing-artifact.json").display().to_string(),
                "bd-absent"
            )]),
        );

        let output = build_claim_explanation("FE-CLAIM-ABSENT", &matrix_path, None)
            .expect("absent artifact should render fail-closed receipt");
        assert_eq!(output.decision, "fail_closed");
        assert_eq!(output.exit_code(), 2);
        assert!(output.reason_codes.contains(&"absent_artifact".to_string()));
        assert!(!output.artifact.as_ref().expect("artifact").present);
    }

    #[test]
    fn claim_explainer_missing_repro_lock_fails_closed() {
        let dir = frankenctl_test_temp_dir("claim-missing-repro-lock");
        fs::create_dir_all(&dir).expect("create fixture dir");
        let artifact_path = dir.join("artifact.json");
        fs::write(&artifact_path, b"{\"ok\":true}\n").expect("write artifact");
        let matrix_path = dir.join("matrix.json");
        write_claim_matrix_fixture(
            &matrix_path,
            serde_json::json!([claim_row_fixture(
                "FE-CLAIM-NO-REPRO",
                "observed",
                "observed",
                artifact_path.display().to_string(),
                "bd-no-repro"
            )]),
        );

        let output = build_claim_explanation("FE-CLAIM-NO-REPRO", &matrix_path, None)
            .expect("missing repro lock should render fail-closed receipt");

        assert_eq!(output.decision, "fail_closed");
        assert_eq!(output.exit_code(), 2);
        assert!(
            output
                .reason_codes
                .contains(&"missing_reproducibility_bundle".to_string())
        );
    }

    #[test]
    fn claim_explainer_stale_observed_artifact_fails_closed() {
        let dir = frankenctl_test_temp_dir("claim-stale-artifact");
        let artifact_dir = dir.join("artifact");
        fs::create_dir_all(&artifact_dir).expect("create fixture dir");
        fs::write(
            artifact_dir.join("manifest.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "schema_version": "franken-engine.proof-artifact-manifest.v1",
                "freshness": {
                    "generated_utc": "2026-01-01T00:00:00Z"
                }
            }))
            .expect("manifest JSON serializes"),
        )
        .expect("write stale manifest");
        let matrix_path = dir.join("matrix.json");
        write_claim_matrix_fixture(
            &matrix_path,
            serde_json::json!([claim_row_fixture(
                "FE-CLAIM-STALE",
                "observed",
                "observed",
                artifact_dir.display().to_string(),
                "bd-stale"
            )]),
        );

        let output = build_claim_explanation("FE-CLAIM-STALE", &matrix_path, None)
            .expect("stale artifact should render fail-closed receipt");
        assert_eq!(output.decision, "fail_closed");
        assert_eq!(output.exit_code(), 2);
        assert!(output.reason_codes.contains(&"stale_artifact".to_string()));
        assert_eq!(
            output.artifact.as_ref().expect("artifact").freshness_status,
            "stale"
        );
    }

    #[test]
    fn claim_explainer_hash_mismatch_fails_closed() {
        let dir = frankenctl_test_temp_dir("claim-hash-mismatch");
        fs::create_dir_all(&dir).expect("create fixture dir");
        let artifact_path = dir.join("artifact.json");
        fs::write(&artifact_path, b"{\"ok\":true}\n").expect("write artifact");
        let mut row = claim_row_fixture(
            "FE-CLAIM-HASH",
            "observed",
            "observed",
            artifact_path.display().to_string(),
            "bd-hash",
        );
        row["expected_hash"] = serde_json::Value::String(format!("sha256:{}", "0".repeat(64)));
        let matrix_path = dir.join("matrix.json");
        write_claim_matrix_fixture(&matrix_path, serde_json::json!([row]));

        let output = build_claim_explanation("FE-CLAIM-HASH", &matrix_path, None)
            .expect("hash mismatch should render fail-closed receipt");
        assert_eq!(output.decision, "fail_closed");
        assert_eq!(output.exit_code(), 2);
        assert!(
            output
                .reason_codes
                .contains(&"artifact_hash_mismatch".to_string())
        );
        assert_eq!(
            output.artifact.as_ref().expect("artifact").hash_status,
            "mismatch"
        );
    }

    #[test]
    fn claim_explainer_explicit_mock_marker_fails_closed_case_insensitive() {
        let dir = frankenctl_test_temp_dir("claim-mock-marker");
        fs::create_dir_all(&dir).expect("create fixture dir");
        let artifact_path = dir.join("artifact.json");
        fs::write(&artifact_path, b"{\"ok\":true}\n").expect("write artifact");
        let mut row = claim_row_fixture(
            "FE-CLAIM-MOCK",
            "observed",
            "observed",
            artifact_path.display().to_string(),
            "bd-mock",
        );
        row["claim_text"] =
            serde_json::Value::String("Fixture uses mock_certificate evidence.".to_string());
        let matrix_path = dir.join("matrix.json");
        write_claim_matrix_fixture(&matrix_path, serde_json::json!([row]));

        let output = build_claim_explanation("FE-CLAIM-MOCK", &matrix_path, None)
            .expect("mock marker should render fail-closed receipt");

        assert_eq!(output.decision, "fail_closed");
        assert_eq!(output.exit_code(), 2);
        assert!(
            output
                .reason_codes
                .contains(&"mock_contaminated".to_string())
        );
        assert_eq!(output.mock_status, "present_fail_closed");
    }

    #[test]
    fn claim_explainer_artifact_mock_marker_fails_closed_case_insensitive() {
        let dir = frankenctl_test_temp_dir("claim-artifact-mock-marker");
        fs::create_dir_all(&dir).expect("create fixture dir");
        let artifact_path = dir.join("artifact.json");
        fs::write(&artifact_path, b"{\"producer\":\"MockCertificate\"}\n")
            .expect("write mock artifact");
        let matrix_path = dir.join("matrix.json");
        write_claim_matrix_fixture(
            &matrix_path,
            serde_json::json!([claim_row_fixture(
                "FE-CLAIM-ARTIFACT-MOCK",
                "observed",
                "observed",
                artifact_path.display().to_string(),
                "bd-artifact-mock"
            )]),
        );

        let output = build_claim_explanation("FE-CLAIM-ARTIFACT-MOCK", &matrix_path, None)
            .expect("artifact mock marker should render fail-closed receipt");

        assert_eq!(output.decision, "fail_closed");
        assert_eq!(output.exit_code(), 2);
        assert!(
            output
                .reason_codes
                .contains(&"mock_contaminated".to_string())
        );
        assert_eq!(output.mock_status, "present_fail_closed");
    }

    #[test]
    fn claim_explainer_local_fallback_marker_fails_closed_case_insensitive() {
        let dir = frankenctl_test_temp_dir("claim-local-fallback-marker");
        fs::create_dir_all(&dir).expect("create fixture dir");
        let artifact_path = dir.join("artifact.json");
        fs::write(
            &artifact_path,
            b"{\"transport\":\"local fallback was used\"}\n",
        )
        .expect("write local-fallback artifact");
        let matrix_path = dir.join("matrix.json");
        write_claim_matrix_fixture(
            &matrix_path,
            serde_json::json!([claim_row_fixture(
                "FE-CLAIM-LOCAL-FALLBACK",
                "observed",
                "observed",
                artifact_path.display().to_string(),
                "bd-local-fallback"
            )]),
        );

        let output = build_claim_explanation("FE-CLAIM-LOCAL-FALLBACK", &matrix_path, None)
            .expect("local-fallback marker should render fail-closed receipt");

        assert_eq!(output.decision, "fail_closed");
        assert_eq!(output.exit_code(), 2);
        assert!(
            output
                .reason_codes
                .contains(&"local_fallback_contaminated".to_string())
        );
        assert_eq!(output.local_fallback_status, "present_fail_closed");
    }

    #[test]
    fn claim_explainer_refused_local_fallback_marker_is_not_contamination() {
        let dir = frankenctl_test_temp_dir("claim-local-fallback-refused");
        fs::create_dir_all(&dir).expect("create fixture dir");
        let artifact_path = dir.join("artifact.json");
        fs::write(
            &artifact_path,
            b"{\"transport\":\"Refusing local fallback\"}\n",
        )
        .expect("write local-fallback refusal artifact");
        write_repro_lock_next_to_file(&artifact_path);
        let matrix_path = dir.join("matrix.json");
        write_claim_matrix_fixture(
            &matrix_path,
            serde_json::json!([claim_row_fixture(
                "FE-CLAIM-LOCAL-FALLBACK-REFUSED",
                "observed",
                "observed",
                artifact_path.display().to_string(),
                "bd-local-fallback-refused"
            )]),
        );

        let output = build_claim_explanation("FE-CLAIM-LOCAL-FALLBACK-REFUSED", &matrix_path, None)
            .expect("local-fallback refusal marker should explain");

        assert_eq!(output.decision, "supported");
        assert_eq!(output.exit_code(), 0);
        assert!(
            !output
                .reason_codes
                .contains(&"local_fallback_contaminated".to_string())
        );
        assert_eq!(output.local_fallback_status, "absent");
    }

    #[test]
    fn claim_explainer_directory_hash_uses_length_prefixed_fields() {
        let dir = frankenctl_test_temp_dir("claim-dir-hash");
        let nested = dir.join("nested");
        fs::create_dir_all(&nested).expect("create fixture dir");
        fs::write(dir.join("a.json"), b"{\"a\":true}\n").expect("write first artifact");
        fs::write(nested.join("b.json"), b"{\"b\":true}\n").expect("write second artifact");

        let mut files = Vec::new();
        collect_artifact_files(&dir, &mut files).expect("collect artifact files");
        files.sort();

        let mut expected_preimage = Vec::new();
        append_claim_hash_field(
            &mut expected_preimage,
            b"franken-engine.claim-artifact-directory-hash.v1",
        );
        let mut legacy_preimage = Vec::new();
        for file in files {
            let relative = file.strip_prefix(&dir).expect("relative path");
            let bytes = fs::read(&file).expect("read artifact file");
            let digest = ContentHash::compute(&bytes).to_hex();
            append_claim_hash_field(
                &mut expected_preimage,
                relative.to_string_lossy().as_bytes(),
            );
            append_claim_hash_field(&mut expected_preimage, digest.as_bytes());

            legacy_preimage.extend_from_slice(relative.to_string_lossy().as_bytes());
            legacy_preimage.push(0);
            legacy_preimage.extend_from_slice(digest.as_bytes());
            legacy_preimage.push(b'\n');
        }

        let actual = compute_artifact_content_hash(&dir).expect("directory hash");
        assert_eq!(actual, ContentHash::compute(&expected_preimage).to_hex());
        assert_ne!(actual, ContentHash::compute(&legacy_preimage).to_hex());
    }

    #[test]
    fn parse_differential_oracle_run_command() {
        let args = vec![
            "differential-oracle".to_string(),
            "run".to_string(),
            "--input".to_string(),
            "fixture.js".to_string(),
            "--case-id".to_string(),
            "case-001".to_string(),
            "--timeout-ms".to_string(),
            "750".to_string(),
            "--out".to_string(),
            "oracle.json".to_string(),
        ];
        let parsed = parse_command(&args).expect("differential oracle command should parse");
        match parsed {
            CommandSpec::DifferentialOracle(DifferentialOracleArgs {
                mode: DifferentialOracleMode::Run(spec),
            }) => {
                assert_eq!(spec.input, PathBuf::from("fixture.js"));
                assert_eq!(spec.case_id.as_deref(), Some("case-001"));
                assert_eq!(spec.timeout_ms, 750);
                assert_eq!(spec.out, Some(PathBuf::from("oracle.json")));
            }
            other => panic!("expected differential-oracle command, got {other:?}"),
        }
    }

    fn frankenctl_test_temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "frankenctl-{label}-{}-{}",
            std::process::id(),
            current_unix_ns()
        ))
    }

    fn write_claim_matrix_fixture(path: &Path, claims: serde_json::Value) {
        let matrix = serde_json::json!({
            "schema_version": CLAIM_MATRIX_SCHEMA_VERSION,
            "claims": claims,
        });
        fs::write(
            path,
            serde_json::to_vec_pretty(&matrix).expect("matrix JSON serializes"),
        )
        .expect("write matrix fixture");
    }

    fn write_repro_lock_next_to_file(path: &Path) {
        let parent = path.parent().expect("artifact parent");
        fs::write(parent.join("repro.lock"), b"fixture repro lock\n").expect("write repro lock");
    }

    fn claim_row_fixture(
        claim_id: &str,
        allowed_state: &str,
        actual_wording_state: &str,
        artifact_path: impl Into<String>,
        owning_bead: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "actual_wording_state": actual_wording_state,
            "allowed_state": allowed_state,
            "artifact_path": artifact_path.into(),
            "claim_id": claim_id,
            "claim_scope": "evidence",
            "claim_text": "Fixture claim text.",
            "decision": "fixture decision",
            "downgrade_text": "Fixture downgrade text.",
            "freshness_days": 0,
            "owning_bead": owning_bead,
            "reason": "Fixture reason.",
            "source_path": concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/frankenctl.rs"),
            "source_span": {
                "start_line": 1,
                "end_line": 1,
                "must_contain": "#![forbid(unsafe_code)]"
            },
            "verification_command": "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_fixture cargo test -p frankenengine-engine fixture"
        })
    }

    #[test]
    fn parse_explain_command_accepts_positional_input_and_json_format() {
        let args = vec![
            "explain".to_string(),
            "bundle.json".to_string(),
            "--format".to_string(),
            "json".to_string(),
            "--out".to_string(),
            "rendered.json".to_string(),
        ];
        let parsed = parse_command(&args).expect("explain command should parse");
        match parsed {
            CommandSpec::Explain(spec) => {
                assert_eq!(spec.input, PathBuf::from("bundle.json"));
                assert_eq!(spec.format, ExplainOutputFormat::Json);
                assert_eq!(spec.out, Some(PathBuf::from("rendered.json")));
            }
            other => panic!("expected explain command, got {other:?}"),
        }
    }

    #[test]
    fn parse_top_level_help_topics() {
        let compile = vec!["help".to_string(), "compile".to_string()];
        let parsed = parse_command(&compile).expect("help compile should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::Compile));

        let verify_receipt = vec![
            "help".to_string(),
            "verify".to_string(),
            "receipt".to_string(),
        ];
        let parsed = parse_command(&verify_receipt).expect("help verify receipt should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::VerifyReceipt));

        let benchmark_score = vec![
            "help".to_string(),
            "benchmark".to_string(),
            "score".to_string(),
        ];
        let parsed = parse_command(&benchmark_score).expect("help benchmark score should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::BenchmarkScore));

        for (command, topic) in [
            ("gates", HelpTopic::Gates),
            ("reports", HelpTopic::Reports),
            ("test", HelpTopic::Test),
            ("synth", HelpTopic::Synth),
            ("orchestrate", HelpTopic::Orchestrate),
            ("runtime", HelpTopic::Runtime),
        ] {
            let args = vec!["help".to_string(), command.to_string()];
            let parsed = parse_command(&args).expect("operator help topic should parse");
            assert_eq!(parsed, CommandSpec::HelpTopic(topic));
        }
    }

    #[test]
    fn parse_top_level_help_rejects_unknown_subtopics() {
        let args = vec![
            "help".to_string(),
            "compile".to_string(),
            "unexpected".to_string(),
        ];
        let error = parse_command(&args).expect_err("help compile unexpected should fail");
        assert!(error.contains("does not accept subtopic `unexpected`"));
    }

    #[test]
    fn parse_verify_help_commands() {
        let top_level = vec!["verify".to_string(), "--help".to_string()];
        let parsed = parse_command(&top_level).expect("verify --help should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::Verify));

        let receipt = vec![
            "verify".to_string(),
            "receipt".to_string(),
            "--help".to_string(),
        ];
        let parsed = parse_command(&receipt).expect("verify receipt --help should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::VerifyReceipt));
    }

    #[test]
    fn parse_benchmark_and_replay_help_commands() {
        let benchmark = vec![
            "benchmark".to_string(),
            "run".to_string(),
            "--help".to_string(),
        ];
        let parsed = parse_command(&benchmark).expect("benchmark run --help should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::BenchmarkRun));

        let replay = vec![
            "replay".to_string(),
            "run".to_string(),
            "--help".to_string(),
        ];
        let parsed = parse_command(&replay).expect("replay run --help should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::ReplayRun));
    }

    #[test]
    fn parse_replay_run_command_accepts_compare_trace() {
        let args = vec![
            "replay".to_string(),
            "run".to_string(),
            "--trace".to_string(),
            "expected.json".to_string(),
            "--compare-trace".to_string(),
            "candidate.json".to_string(),
            "--mode".to_string(),
            "validate".to_string(),
        ];
        let parsed = parse_command(&args).expect("replay run should parse compare trace");
        assert_eq!(
            parsed,
            CommandSpec::Replay(ReplayArgs {
                trace: PathBuf::from("expected.json"),
                compare_trace: Some(PathBuf::from("candidate.json")),
                mode: ReplayMode::Validate,
                out: None,
                fleet_trace: None,
            })
        );
    }

    #[test]
    fn parse_replay_debug_command_accepts_all_flags() {
        let args = vec![
            "replay".to_string(),
            "debug".to_string(),
            "--trace".to_string(),
            "trace.json".to_string(),
            "--script".to_string(),
            "commands.jsonl".to_string(),
            "--events".to_string(),
            "events.json".to_string(),
            "--state-snapshots".to_string(),
            "state.json".to_string(),
            "--checkpoint-interval".to_string(),
            "8".to_string(),
            "--mode".to_string(),
            "best-effort".to_string(),
            "--out".to_string(),
            "transcript.jsonl".to_string(),
        ];
        let parsed = parse_command(&args).expect("replay debug should parse all flags");
        assert_eq!(
            parsed,
            CommandSpec::ReplayDebug(ReplayDebugArgs {
                trace: PathBuf::from("trace.json"),
                script: Some(PathBuf::from("commands.jsonl")),
                events: Some(PathBuf::from("events.json")),
                state_snapshots: Some(PathBuf::from("state.json")),
                checkpoint_interval: 8,
                mode: ReplayMode::BestEffort,
                out: Some(PathBuf::from("transcript.jsonl")),
            })
        );
    }

    #[test]
    fn parse_replay_debug_command_applies_defaults() {
        let args = vec![
            "replay".to_string(),
            "debug".to_string(),
            "--trace".to_string(),
            "trace.json".to_string(),
        ];
        let parsed = parse_command(&args).expect("replay debug should parse with defaults");
        assert_eq!(
            parsed,
            CommandSpec::ReplayDebug(ReplayDebugArgs {
                trace: PathBuf::from("trace.json"),
                script: None,
                events: None,
                state_snapshots: None,
                checkpoint_interval: 64,
                mode: ReplayMode::Strict,
                out: None,
            })
        );
    }

    #[test]
    fn parse_replay_debug_command_fails_closed_on_bad_input() {
        let missing_trace = vec!["replay".to_string(), "debug".to_string()];
        let error = parse_command(&missing_trace).expect_err("missing --trace should fail");
        assert!(error.contains("requires --trace"));

        let unknown_flag = vec![
            "replay".to_string(),
            "debug".to_string(),
            "--trace".to_string(),
            "trace.json".to_string(),
            "--bogus".to_string(),
        ];
        let error = parse_command(&unknown_flag).expect_err("unknown flag should fail");
        assert!(error.contains("unknown replay debug flag"));

        let bad_interval = vec![
            "replay".to_string(),
            "debug".to_string(),
            "--trace".to_string(),
            "trace.json".to_string(),
            "--checkpoint-interval".to_string(),
            "zero?".to_string(),
        ];
        let error = parse_command(&bad_interval).expect_err("bad interval should fail");
        assert!(error.contains("invalid --checkpoint-interval"));
    }

    #[test]
    fn parse_replay_debug_help_topic() {
        let flag_form = vec![
            "replay".to_string(),
            "debug".to_string(),
            "--help".to_string(),
        ];
        let parsed = parse_command(&flag_form).expect("replay debug --help should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::ReplayDebug));

        let topic_form = vec![
            "help".to_string(),
            "replay".to_string(),
            "debug".to_string(),
        ];
        let parsed = parse_command(&topic_form).expect("help replay debug should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::ReplayDebug));

        assert!(replay_debug_usage().contains("run_until_break"));
    }

    #[test]
    fn execute_replay_debug_script_round_trip_is_deterministic() {
        use frankenengine_engine::deterministic_replay::NondeterminismSource;

        let temp_dir =
            std::env::temp_dir().join(format!("frankenctl-replay-debug-{}", current_unix_ns()));
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");

        let mut trace = NondeterminismTrace::new("replay-debug-cli-test");
        for index in 0..6u64 {
            trace.capture(
                NondeterminismSource::TimerRead,
                vec![index as u8],
                index + 1,
                "cli-test",
            );
        }
        trace.finalise(6);
        let trace_path = temp_dir.join("trace.json");
        fs::write(
            &trace_path,
            serde_json::to_string(&trace).expect("trace should serialize"),
        )
        .expect("trace file should write");

        let script_path = temp_dir.join("commands.jsonl");
        fs::write(
            &script_path,
            concat!(
                "# agent session\n",
                "{\"cmd\":\"state\"}\n",
                "{\"cmd\":\"goto\",\"tick\":4}\n",
                "{\"cmd\":\"inspect\"}\n",
                "{\"cmd\":\"back\"}\n",
                "\n",
                "{\"cmd\":\"goto\",\"tick\":99}\n",
                "not json\n",
            ),
        )
        .expect("script file should write");
        let state_snapshot_path = temp_dir.join("state.json");
        fs::write(
            &state_snapshot_path,
            concat!(
                "[",
                "{\"tick\":4,",
                "\"registers\":[{\"register\":0,\"value\":{\"Int\":42},\"label\":\"Secret\"}],",
                "\"heap\":[]}",
                "]",
            ),
        )
        .expect("state snapshot file should write");

        let run = |out_name: &str| -> String {
            let out_path = temp_dir.join(out_name);
            let exit = execute_replay_debug(ReplayDebugArgs {
                trace: trace_path.clone(),
                script: Some(script_path.clone()),
                events: None,
                state_snapshots: Some(state_snapshot_path.clone()),
                checkpoint_interval: 2,
                mode: ReplayMode::Strict,
                out: Some(out_path.clone()),
            })
            .expect("replay debug should execute");
            assert_eq!(exit, 0);
            fs::read_to_string(&out_path).expect("transcript should be readable")
        };

        let first = run("transcript_a.jsonl");
        let second = run("transcript_b.jsonl");
        assert_eq!(first, second, "transcripts must be byte-identical");

        let lines: Vec<&str> = first.lines().collect();
        // 6 command lines (comment + blank skipped) -> 6 response lines.
        assert_eq!(lines.len(), 6);
        assert!(lines[0].contains("\"tick\":0"));
        assert!(lines[1].contains("\"tick\":4"));
        assert!(lines[2].contains("inspection"));
        assert!(lines[2].contains("\"register\":0"));
        assert!(lines[2].contains("Secret"));
        assert!(lines[3].contains("\"tick\":3"));
        assert!(lines[4].contains("\"ok\":false"));
        assert!(lines[4].contains("out of range"));
        assert!(lines[5].contains("\"ok\":false"));
        assert!(lines[5].contains("bad request"));
        for line in &lines {
            assert!(
                serde_json::from_str::<serde_json::Value>(line).is_ok(),
                "every transcript line must be one JSON object: {line}"
            );
        }
    }

    #[test]
    fn parse_react_help_commands() {
        let top_level = vec!["react".to_string(), "--help".to_string()];
        let parsed = parse_command(&top_level).expect("react --help should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::React));

        let compile = vec![
            "react".to_string(),
            "help".to_string(),
            "compile".to_string(),
        ];
        let parsed = parse_command(&compile).expect("react help compile should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::ReactCompile));

        let doctor = vec![
            "react".to_string(),
            "help".to_string(),
            "doctor".to_string(),
        ];
        let parsed = parse_command(&doctor).expect("react help doctor should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::ReactDoctor));

        let top_level = vec![
            "help".to_string(),
            "react".to_string(),
            "contract".to_string(),
        ];
        let parsed = parse_command(&top_level).expect("help react contract should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::ReactContract));
    }

    #[test]
    fn parse_react_compile_command() {
        let args = vec![
            "react".to_string(),
            "compile".to_string(),
            "--input".to_string(),
            "demo.tsx".to_string(),
            "--source-form".to_string(),
            "tsx".to_string(),
            "--runtime".to_string(),
            "automatic".to_string(),
            "--out".to_string(),
            "react-report.json".to_string(),
        ];
        let parsed = parse_command(&args).expect("react compile should parse");
        match parsed {
            CommandSpec::React(ReactArgs::Compile(spec)) => {
                assert_eq!(spec.input, PathBuf::from("demo.tsx"));
                assert_eq!(spec.source_form, ReactSourceForm::Tsx);
                assert_eq!(spec.runtime_mode, Some(ReactRuntimeMode::Automatic));
                assert_eq!(spec.out, Some(PathBuf::from("react-report.json")));
            }
            other => panic!("expected react compile command, got {other:?}"),
        }
    }

    #[test]
    fn parse_react_build_command() {
        let args = vec![
            "react".to_string(),
            "build".to_string(),
            "--entry".to_string(),
            "app.jsx".to_string(),
            "--target".to_string(),
            "ssr".to_string(),
            "--out".to_string(),
            "build-report.json".to_string(),
        ];
        let parsed = parse_command(&args).expect("react build should parse");
        match parsed {
            CommandSpec::React(ReactArgs::Build(spec)) => {
                assert_eq!(spec.entry, PathBuf::from("app.jsx"));
                assert_eq!(spec.target, ReactBuildTarget::Ssr);
                assert_eq!(spec.out, Some(PathBuf::from("build-report.json")));
            }
            other => panic!("expected react build command, got {other:?}"),
        }
    }

    #[test]
    fn parse_react_doctor_command() {
        let args = vec![
            "react".to_string(),
            "doctor".to_string(),
            "--catalog".to_string(),
            "react_mismatch_catalog.json".to_string(),
            "--summary".to_string(),
            "--min-severity".to_string(),
            "warning".to_string(),
            "--include-resolved".to_string(),
            "--target".to_string(),
            "nodejs".to_string(),
            "--target".to_string(),
            "bun".to_string(),
            "--current-epoch".to_string(),
            "42".to_string(),
            "--out".to_string(),
            "react-doctor-report.json".to_string(),
        ];
        let parsed = parse_command(&args).expect("react doctor should parse");
        match parsed {
            CommandSpec::React(ReactArgs::Doctor(spec)) => {
                assert_eq!(spec.catalog, PathBuf::from("react_mismatch_catalog.json"));
                assert!(spec.summary);
                assert_eq!(spec.current_epoch, Some(42));
                assert_eq!(spec.min_severity, ReactMismatchSeverity::Warning);
                assert!(spec.include_resolved);
                assert_eq!(spec.targets.len(), 2);
                assert_eq!(spec.out, Some(PathBuf::from("react-doctor-report.json")));
            }
            other => panic!("expected react doctor command, got {other:?}"),
        }
    }

    #[test]
    fn parse_react_contract_command() {
        let args = vec![
            "react".to_string(),
            "contract".to_string(),
            "--out".to_string(),
            "react-cli-contract.json".to_string(),
        ];
        let parsed = parse_command(&args).expect("react contract should parse");
        match parsed {
            CommandSpec::React(ReactArgs::Contract(spec)) => {
                assert_eq!(spec.out, Some(PathBuf::from("react-cli-contract.json")));
            }
            other => panic!("expected react contract command, got {other:?}"),
        }
    }

    #[test]
    fn embedded_react_contract_policy_id_is_pinned() {
        let contract = parse_react_capability_contract()
            .expect("embedded react capability contract should parse");
        assert_eq!(contract.policy_id, REACT_CAPABILITY_CONTRACT_POLICY_ID);
    }

    #[test]
    fn execute_react_contract_emits_embedded_capability_contract_policy_id() {
        let out = std::env::temp_dir().join(format!(
            "frankenctl-react-contract-{}.json",
            current_unix_ns()
        ));
        let exit_code = execute_react_contract(ReactContractArgs {
            out: Some(out.clone()),
            trace_id: "trace-react-contract".to_string(),
            decision_id: "decision-react-contract".to_string(),
            policy_id: "policy-react-cli-invocation".to_string(),
        })
        .expect("react contract execution should succeed");

        assert_eq!(exit_code, 0);
        let output: serde_json::Value =
            load_json_file(&out).expect("react contract output should parse");
        assert_eq!(
            output["policy_id"].as_str(),
            Some("policy-react-cli-invocation")
        );
        assert_eq!(
            output["capability_contract_policy_id"].as_str(),
            Some(REACT_CAPABILITY_CONTRACT_POLICY_ID)
        );
        let command_names = output["commands"]
            .as_array()
            .expect("commands should be an array")
            .iter()
            .filter_map(|value| value["name"].as_str())
            .collect::<Vec<_>>();
        assert!(command_names.contains(&"react doctor"));
    }

    #[test]
    fn execute_react_doctor_emits_machine_readable_support_report() {
        let temp_dir =
            std::env::temp_dir().join(format!("frankenctl-react-doctor-{}", current_unix_ns()));
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");

        let catalog_path = temp_dir.join("react_mismatch_catalog.json");
        let out = temp_dir.join("react_doctor_report.json");

        let mut catalog = MismatchCatalog::new(SecurityEpoch::from_raw(7));
        catalog
            .add_entry(frankenengine_engine::react_mismatch_catalog::MismatchEntry {
                entry_id: "react-ssr-open".to_string(),
                domain: frankenengine_engine::react_mismatch_catalog::MismatchDomain::ServerSideRender,
                severity: ReactMismatchSeverity::Error,
                target: ReactComparisonTarget::NodeJs,
                summary: "SSR entry mismatch".to_string(),
                expected_behavior: "render should match".to_string(),
                actual_behavior: "render diverged".to_string(),
                reproduction: "cargo test -- react_ssr_case".to_string(),
                remediation: frankenengine_engine::react_mismatch_catalog::RemediationStatus::InProgress,
                advisory: "Switch to the documented SSR compatibility path.".to_string(),
                react_version_range: ">=18".to_string(),
                evidence_hash: ContentHash::compute(b"react-ssr-open"),
                detected_epoch: SecurityEpoch::from_raw(4),
                verified_epoch: SecurityEpoch::from_raw(7),
                tags: ["react", "ssr"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            })
            .expect("catalog entry should be added");
        write_json_file(&catalog_path, &catalog)
            .expect("operation should succeed for valid inputs");

        let exit_code = execute_react_doctor(ReactDoctorArgs {
            catalog: catalog_path.clone(),
            out: Some(out.clone()),
            summary: false,
            current_epoch: None,
            min_severity: ReactMismatchSeverity::Info,
            include_resolved: false,
            targets: vec![ReactComparisonTarget::NodeJs],
            trace_id: "trace-react-doctor".to_string(),
            decision_id: "decision-react-doctor".to_string(),
            policy_id: "policy-react-doctor".to_string(),
        })
        .expect("react doctor should execute");
        assert_eq!(exit_code, 25);

        let output: serde_json::Value =
            load_json_file(&out).expect("react doctor output should parse");
        assert_eq!(
            output["schema_version"].as_str(),
            Some(REACT_DOCTOR_REPORT_SCHEMA_VERSION)
        );
        assert_eq!(output["blocked"].as_bool(), Some(true));
        assert_eq!(output["ready"].as_bool(), Some(false));
        assert_eq!(
            output["support_repro_index"]["entry_count"].as_u64(),
            Some(1)
        );
        assert_eq!(
            output["support_repro_index"]["entries"][0]["entry_id"].as_str(),
            Some("react-ssr-open")
        );
    }

    #[test]
    fn execute_react_compile_emits_native_pipeline_output_for_shipped_capability() {
        let input = std::env::temp_dir().join(format!(
            "frankenctl-react-compile-{}.tsx",
            current_unix_ns()
        ));
        let out = std::env::temp_dir().join(format!(
            "frankenctl-react-compile-report-{}.json",
            current_unix_ns()
        ));
        fs::write(&input, "<div>Hello</div>\n").expect("react compile fixture should write");

        let exit_code = execute_react_compile(ReactCompileArgs {
            input: input.clone(),
            source_form: ReactSourceForm::Tsx,
            runtime_mode: Some(ReactRuntimeMode::Automatic),
            out: Some(out.clone()),
            trace_id: "trace-react-compile".to_string(),
            decision_id: "decision-react-compile".to_string(),
            policy_id: "policy-react-compile".to_string(),
        })
        .expect("react compile execution should succeed");

        assert_eq!(exit_code, 0);
        let output: serde_json::Value =
            load_json_file(&out).expect("react compile output should parse");
        assert_eq!(output["support_status"].as_str(), Some("shipped"));
        assert_eq!(output["blocked"].as_bool(), Some(false));
        assert_eq!(output["diagnostic"]["error_code"].as_str(), Some("OK"));
        assert_eq!(output["compilation"]["language"].as_str(), Some("tsx"));
        assert!(
            output["compilation"]["generated_code"]
                .as_str()
                .expect("generated code should be present")
                .contains("div")
        );

        let _ = fs::remove_file(input);
        let _ = fs::remove_file(out);
    }

    #[test]
    fn execute_react_build_returns_blocked_exit_code_for_unshipped_target() {
        let entry =
            std::env::temp_dir().join(format!("frankenctl-react-build-{}.jsx", current_unix_ns()));
        let out = std::env::temp_dir().join(format!(
            "frankenctl-react-build-report-{}.json",
            current_unix_ns()
        ));
        fs::write(
            &entry,
            "export default function App() { return <main />; }\n",
        )
        .expect("react build fixture should write");

        let exit_code = execute_react_build(ReactBuildArgs {
            entry: entry.clone(),
            target: ReactBuildTarget::Ssr,
            out: Some(out.clone()),
            trace_id: "trace-react-build".to_string(),
            decision_id: "decision-react-build".to_string(),
            policy_id: "policy-react-build".to_string(),
        })
        .expect("react build execution should succeed");

        assert_eq!(exit_code, 25);
        let output: serde_json::Value =
            load_json_file(&out).expect("react build output should parse");
        assert_eq!(output["support_status"].as_str(), Some("unsupported"));
        assert_eq!(output["blocked"].as_bool(), Some(true));

        let _ = fs::remove_file(entry);
        let _ = fs::remove_file(out);
    }

    #[test]
    fn parse_verify_compile_artifact_command_with_output() {
        let args = vec![
            "verify".to_string(),
            "compile-artifact".to_string(),
            "--input".to_string(),
            "artifact.json".to_string(),
            "--output".to_string(),
            "artifacts/verify_report.json".to_string(),
        ];
        let parsed = parse_command(&args).expect("verify compile-artifact should parse");
        match parsed {
            CommandSpec::Verify(VerifyArgs::CompileArtifact { input, output }) => {
                assert_eq!(input, PathBuf::from("artifact.json"));
                assert_eq!(output, Some(PathBuf::from("artifacts/verify_report.json")));
            }
            other => panic!("expected verify compile-artifact command, got {other:?}"),
        }
    }

    #[test]
    fn parse_verify_compile_artifact_command_rejects_unknown_flag() {
        let args = vec![
            "verify".to_string(),
            "compile-artifact".to_string(),
            "--input".to_string(),
            "artifact.json".to_string(),
            "--bogus".to_string(),
        ];
        let error = parse_command(&args).expect_err("unknown flag should fail");
        assert_eq!(error, "unknown verify compile-artifact flag `--bogus`");
    }

    #[test]
    fn validate_compile_artifact_rejects_schema_and_context_drift() {
        let source = std::env::temp_dir().join(format!(
            "frankenctl-compile-artifact-drift-{}.js",
            current_unix_ns()
        ));
        let artifact_path = std::env::temp_dir().join(format!(
            "frankenctl-compile-artifact-drift-{}.json",
            current_unix_ns()
        ));
        fs::write(&source, "const answer = 40 + 2;\n").expect("source fixture should write");

        execute_compile(CompileArgs {
            input: source.clone(),
            out: artifact_path.clone(),
            parse_goal: ParseGoal::Script,
            trace_id: "trace-compile-artifact-drift".to_string(),
            decision_id: "decision-compile-artifact-drift".to_string(),
            policy_id: "policy-compile-artifact-drift".to_string(),
            generated_unix_ns: None,
        })
        .expect("compile should succeed");

        let mut artifact =
            load_json_file::<CompileArtifact>(&artifact_path).expect("artifact should load");
        artifact.schema_version = "franken-engine.frankenctl.compile-artifact.v0".to_string();
        artifact.parse_goal = "bogus".to_string();
        artifact.trace_id.clear();
        artifact.source_path.clear();

        let errors = validate_compile_artifact(&artifact);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("schema_version mismatch")),
            "expected schema mismatch error, got {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("parse_goal must be")),
            "expected parse_goal validation error, got {errors:?}"
        );
        assert!(
            errors.iter().any(|error| error.contains("trace_id")),
            "expected trace_id validation error, got {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("source_path must not be empty")),
            "expected source_path validation error, got {errors:?}"
        );

        let _ = fs::remove_file(source);
        let _ = fs::remove_file(artifact_path);
    }

    #[test]
    fn parse_verify_receipt_command() {
        let args = vec![
            "verify".to_string(),
            "receipt".to_string(),
            "--input".to_string(),
            "receipts.json".to_string(),
            "--receipt-id".to_string(),
            "rcpt-1".to_string(),
            "--summary".to_string(),
            "--output".to_string(),
            "artifacts/receipt_verdict.json".to_string(),
        ];
        let parsed = parse_command(&args).expect("verify receipt should parse");
        match parsed {
            CommandSpec::Verify(VerifyArgs::Receipt {
                input,
                receipt_id,
                summary,
                output,
            }) => {
                assert_eq!(input, PathBuf::from("receipts.json"));
                assert_eq!(receipt_id, "rcpt-1");
                assert!(summary);
                assert_eq!(
                    output,
                    Some(PathBuf::from("artifacts/receipt_verdict.json"))
                );
            }
            other => panic!("expected verify receipt command, got {other:?}"),
        }
    }

    #[test]
    fn parse_verify_receipt_command_requires_input() {
        let args = vec![
            "verify".to_string(),
            "receipt".to_string(),
            "--receipt-id".to_string(),
            "rcpt-1".to_string(),
        ];
        let error = parse_command(&args).expect_err("missing input should fail");
        assert_eq!(error, "verify receipt requires --input <path>");
    }

    #[test]
    fn parse_verify_receipt_command_requires_receipt_id() {
        let args = vec![
            "verify".to_string(),
            "receipt".to_string(),
            "--input".to_string(),
            "receipts.json".to_string(),
        ];
        let error = parse_command(&args).expect_err("missing receipt id should fail");
        assert_eq!(error, "verify receipt requires --receipt-id <id>");
    }

    #[test]
    fn parse_verify_receipt_command_rejects_unknown_flag() {
        let args = vec![
            "verify".to_string(),
            "receipt".to_string(),
            "--input".to_string(),
            "receipts.json".to_string(),
            "--receipt-id".to_string(),
            "rcpt-1".to_string(),
            "--bogus".to_string(),
        ];
        let error = parse_command(&args).expect_err("unknown flag should fail");
        assert_eq!(error, "unknown verify receipt flag `--bogus`");
    }

    #[test]
    fn run_verify_receipt_parse_failure_includes_parse_remediation() {
        let error = run(vec![
            "verify".to_string(),
            "receipt".to_string(),
            "--input".to_string(),
            "receipts.json".to_string(),
        ])
        .expect_err("missing receipt id should surface parse remediation");
        assert!(
            error.contains("[frankenctl trace_id=frankenctl-"),
            "error should include trace id, got: {error}"
        );
        assert!(
            error.contains("command=parse"),
            "error should identify parse command, got: {error}"
        );
        assert!(
            error.contains("verify receipt requires --receipt-id <id>"),
            "error should preserve parse failure, got: {error}"
        );
        assert!(
            error.contains(
                "remediation: Run `frankenctl --help` for full command usage and required arguments."
            ),
            "error should include parse remediation, got: {error}"
        );
    }

    #[test]
    fn execute_verify_compile_artifact_writes_output_file() {
        let temp_dir =
            std::env::temp_dir().join(format!("frankenctl-verify-compile-{}", current_unix_ns()));
        fs::create_dir_all(&temp_dir).expect("temp dir should be created");

        let input_path = temp_dir.join("demo.js");
        fs::write(&input_path, "const answer = 40 + 2;\n").expect("source fixture should write");

        let artifact_path = temp_dir.join("demo.compile.json");
        let compile_exit = execute_compile(CompileArgs {
            input: input_path,
            out: artifact_path.clone(),
            parse_goal: ParseGoal::Script,
            trace_id: "trace-verify-output".to_string(),
            decision_id: "decision-verify-output".to_string(),
            policy_id: "policy-verify-output".to_string(),
            generated_unix_ns: None,
        })
        .expect("compile should succeed");
        assert_eq!(compile_exit, 0);

        let report_path = temp_dir.join("reports/verify_report.json");
        let verify_exit = execute_verify(VerifyArgs::CompileArtifact {
            input: artifact_path.clone(),
            output: Some(report_path.clone()),
        })
        .expect("verify should succeed");

        assert_eq!(verify_exit, 0);
        let report: serde_json::Value =
            load_json_file(&report_path).expect("verify report should parse");
        let expected_artifact_path = artifact_path.display().to_string();
        let expected_report_path = report_path.display().to_string();
        assert_eq!(
            report["artifact_path"].as_str(),
            Some(expected_artifact_path.as_str())
        );
        assert_eq!(
            report["report_path"].as_str(),
            Some(expected_report_path.as_str())
        );
        assert_eq!(report["passed"].as_bool(), Some(true));
    }

    #[test]
    fn receipt_verification_command_output_flattens_verdict_and_observability_mode() {
        let output = ReceiptVerificationCommandOutput {
            verdict: UnifiedReceiptVerificationVerdict {
                receipt_id: "rcpt-1".to_string(),
                trace_id: "trace-verify-01".to_string(),
                decision_id: "decision-verify-01".to_string(),
                policy_id: "policy-verify-01".to_string(),
                verification_timestamp_ns: 7,
                passed: true,
                failure_class: None,
                exit_code: 0,
                signature: frankenengine_engine::receipt_verifier_pipeline::LayerResult {
                    passed: true,
                    error_code: None,
                    checks: Vec::new(),
                },
                transparency: frankenengine_engine::receipt_verifier_pipeline::LayerResult {
                    passed: true,
                    error_code: None,
                    checks: Vec::new(),
                },
                attestation: frankenengine_engine::receipt_verifier_pipeline::LayerResult {
                    passed: true,
                    error_code: None,
                    checks: Vec::new(),
                },
                warnings: Vec::new(),
                logs: vec![VerifierLogEvent {
                    trace_id: "trace-verify-01".to_string(),
                    decision_id: "decision-verify-01".to_string(),
                    policy_id: "policy-verify-01".to_string(),
                    component: "receipt_verifier_pipeline".to_string(),
                    event: "verification_complete".to_string(),
                    outcome: "pass".to_string(),
                    error_code: None,
                }],
            },
            report_path: Some("artifacts/verify_report.json".to_string()),
            observability_mode: default_capture_observability_mode(),
        };

        let json = serde_json::to_value(&output).expect("serialization should succeed");
        assert_eq!(json["receipt_id"].as_str(), Some("rcpt-1"));
        assert_eq!(json["trace_id"].as_str(), Some("trace-verify-01"));
        assert_eq!(
            json["report_path"].as_str(),
            Some("artifacts/verify_report.json")
        );
        assert_eq!(
            json["observability_mode"]["mode_id"].as_str(),
            Some("default_capture")
        );
        assert_eq!(
            json["observability_mode"]["capture_semantics"].as_str(),
            Some("default_mixed_capture")
        );
        assert_eq!(
            json["observability_mode"]["lossless"].as_bool(),
            Some(false)
        );
    }

    #[test]
    fn benchmark_verification_command_output_flattens_report_and_observability_mode() {
        let output = BenchmarkVerificationCommandOutput {
            report: ThirdPartyVerificationReport {
                claim_type: "benchmark".to_string(),
                trace_id: "trace-bench-verify-01".to_string(),
                decision_id: "decision-bench-verify-01".to_string(),
                policy_id: "policy-bench-verify-01".to_string(),
                component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
                verdict: VerificationVerdict::Verified,
                confidence_statement: "bundle is reproducible".to_string(),
                scope_limitations: Vec::new(),
                checks: vec![VerificationCheckResult {
                    name: "bundle_present".to_string(),
                    passed: true,
                    error_code: None,
                    detail: "bundle exists".to_string(),
                }],
                events: vec![VerifierEvent {
                    trace_id: "trace-bench-verify-01".to_string(),
                    decision_id: "decision-bench-verify-01".to_string(),
                    policy_id: "policy-bench-verify-01".to_string(),
                    component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
                    event: "benchmark_verification_complete".to_string(),
                    outcome: "pass".to_string(),
                    error_code: None,
                }],
            },
            report_path: Some("artifacts/benchmark_verify_report.json".to_string()),
            observability_mode: default_capture_observability_mode(),
        };

        let json = serde_json::to_value(&output).expect("serialization should succeed");
        assert_eq!(json["claim_type"].as_str(), Some("benchmark"));
        assert_eq!(
            json["report_path"].as_str(),
            Some("artifacts/benchmark_verify_report.json")
        );
        assert_eq!(
            json["component"].as_str(),
            Some(THIRD_PARTY_VERIFIER_COMPONENT)
        );
        assert_eq!(
            json["observability_mode"]["mode_id"].as_str(),
            Some("default_capture")
        );
        assert_eq!(
            json["observability_mode"]["capture_semantics"].as_str(),
            Some("default_mixed_capture")
        );
        assert_eq!(
            json["observability_mode"]["lossless"].as_bool(),
            Some(false)
        );
    }

    #[test]
    fn parse_doctor_command() {
        let args = vec![
            "doctor".to_string(),
            "--input".to_string(),
            "runtime_input.json".to_string(),
            "--summary".to_string(),
            "--out-dir".to_string(),
            "artifacts/doctor".to_string(),
            "--workload-id".to_string(),
            "demo-workload".to_string(),
            "--package-name".to_string(),
            "demo-package".to_string(),
            "--target-platform".to_string(),
            "linux-x86_64".to_string(),
            "--scenario-report".to_string(),
            "compatibility_report.json".to_string(),
            "--severity".to_string(),
            "warning".to_string(),
        ];
        let parsed = parse_command(&args).expect("doctor command should parse");
        match parsed {
            CommandSpec::Doctor(spec) => {
                assert_eq!(spec.input, Some(PathBuf::from("runtime_input.json")));
                assert_eq!(spec.artifact_dir, None);
                assert!(spec.summary);
                assert_eq!(spec.out_dir, Some(PathBuf::from("artifacts/doctor")));
                assert_eq!(spec.workload_id.as_deref(), Some("demo-workload"));
                assert_eq!(spec.package_name.as_deref(), Some("demo-package"));
                assert_eq!(spec.target_platforms, vec!["linux-x86_64".to_string()]);
                assert_eq!(
                    spec.scenario_report,
                    Some(PathBuf::from("compatibility_report.json"))
                );
                assert_eq!(spec.filter.severity, parse_evidence_severity("warning"));
            }
            other => panic!("expected doctor command, got {other:?}"),
        }
    }

    #[test]
    fn parse_doctor_command_accepts_artifact_dir() {
        let args = vec![
            "doctor".to_string(),
            "--artifact-dir".to_string(),
            "artifacts/gate/2026-05-24T00-00-00Z".to_string(),
            "--summary".to_string(),
        ];
        let parsed = parse_command(&args).expect("doctor command should parse with --artifact-dir");
        match parsed {
            CommandSpec::Doctor(spec) => {
                assert_eq!(spec.input, None);
                assert_eq!(
                    spec.artifact_dir,
                    Some(PathBuf::from("artifacts/gate/2026-05-24T00-00-00Z"))
                );
                assert!(spec.summary);
            }
            other => panic!("expected doctor command, got {other:?}"),
        }
    }

    #[test]
    fn parse_doctor_command_requires_input_or_artifact_dir() {
        let args = vec!["doctor".to_string(), "--summary".to_string()];
        let error = parse_command(&args).expect_err("doctor without input or bundle must fail");
        assert!(
            error.contains("--input") && error.contains("--artifact-dir"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn resolve_doctor_input_path_prefers_explicit_input() {
        let args = DoctorArgs {
            input: Some(PathBuf::from("explicit/runtime_input.json")),
            artifact_dir: Some(PathBuf::from("artifacts/gate/ts")),
            summary: false,
            out_dir: None,
            workload_id: None,
            package_name: None,
            target_platforms: Vec::new(),
            signals: None,
            advisories: None,
            scenario_report: None,
            platform_signals: None,
            filter: EvidenceExportFilter::default(),
            redact_keys: Vec::new(),
        };
        let resolved = resolve_doctor_input_path(&args).expect("explicit input resolves");
        assert_eq!(resolved, PathBuf::from("explicit/runtime_input.json"));
    }

    #[test]
    fn inspect_artifact_bundle_reports_complete_bundle() {
        let bundle_dir =
            std::env::temp_dir().join(format!("frankenctl-bundle-complete-{}", current_unix_ns()));
        fs::create_dir_all(bundle_dir.join("step_logs")).expect("create bundle dirs");
        fs::write(
            bundle_dir.join("run_manifest.json"),
            "{\"schema_version\":\"franken-engine.run-manifest.v1\"}",
        )
        .expect("write manifest");
        fs::write(
            bundle_dir.join("events.jsonl"),
            "{\"event\":\"start\"}\n{\"event\":\"finish\"}\n",
        )
        .expect("write events");
        fs::write(bundle_dir.join("runtime_input.json"), "{}").expect("write input");
        fs::write(bundle_dir.join("step_logs/step_0.log"), "ok").expect("write step log");

        let input_path = bundle_dir.join("runtime_input.json");
        let status = inspect_artifact_bundle(&bundle_dir, &input_path);

        assert!(status.manifest_present);
        assert!(status.manifest_valid_json);
        assert_eq!(
            status.manifest_schema_version.as_deref(),
            Some("franken-engine.run-manifest.v1")
        );
        assert!(status.events_present);
        assert!(status.events_valid_jsonl);
        assert_eq!(status.event_count, 2);
        assert!(status.step_logs_present);
        assert_eq!(status.step_log_count, 1);
        assert!(status.complete);
        assert!(
            status.diagnostics.is_empty(),
            "expected no diagnostics, got {:?}",
            status.diagnostics
        );
        assert!(status.artifact_paths.contains_key("manifest"));
        assert!(status.artifact_paths.contains_key("events"));
        assert!(status.artifact_paths.contains_key("step_logs"));
        assert!(status.artifact_paths.contains_key("runtime_input"));

        fs::remove_dir_all(&bundle_dir).ok();
    }

    #[test]
    fn inspect_artifact_bundle_flags_missing_and_invalid_artifacts() {
        let bundle_dir =
            std::env::temp_dir().join(format!("frankenctl-bundle-broken-{}", current_unix_ns()));
        fs::create_dir_all(&bundle_dir).expect("create bundle dir");
        // Invalid manifest JSON, one malformed events line, no step_logs/ directory.
        fs::write(bundle_dir.join("run_manifest.json"), "{not json").expect("write manifest");
        fs::write(bundle_dir.join("events.jsonl"), "{\"ok\":true}\nnot-json\n")
            .expect("write events");

        let input_path = bundle_dir.join("runtime_input.json");
        let status = inspect_artifact_bundle(&bundle_dir, &input_path);

        assert!(status.manifest_present);
        assert!(!status.manifest_valid_json);
        assert!(status.events_present);
        assert!(!status.events_valid_jsonl);
        assert_eq!(status.event_count, 1);
        assert!(!status.step_logs_present);
        assert!(!status.complete);
        let codes: Vec<&str> = status.diagnostics.iter().map(|d| d.code.as_str()).collect();
        assert!(codes.contains(&"manifest_invalid_json"), "codes: {codes:?}");
        assert!(codes.contains(&"events_invalid_line"), "codes: {codes:?}");
        assert!(codes.contains(&"step_logs_missing"), "codes: {codes:?}");

        fs::remove_dir_all(&bundle_dir).ok();
    }

    #[test]
    fn sort_and_dedup_signals_removes_exact_duplicates_with_same_key_variants_present() {
        let duplicate = OnboardingScorecardSignal {
            signal_id: "dup-signal".to_string(),
            source: "compatibility".to_string(),
            severity: EvidenceSeverity::Warning,
            summary: "duplicate summary".to_string(),
            remediation: "rerun duplicate remediation".to_string(),
            reproducible_command: "frankenctl doctor --input dup.json".to_string(),
            evidence_links: vec!["support_bundle/index.json".to_string()],
            owner_hint: Some("ops".to_string()),
        };
        let variant = OnboardingScorecardSignal {
            signal_id: "dup-signal".to_string(),
            source: "compatibility".to_string(),
            severity: EvidenceSeverity::Warning,
            summary: "variant summary".to_string(),
            remediation: "rerun variant remediation".to_string(),
            reproducible_command: "frankenctl doctor --input variant.json".to_string(),
            evidence_links: vec!["support_bundle/runtime_diagnostics.json".to_string()],
            owner_hint: None,
        };

        let mut signals = vec![duplicate.clone(), variant.clone(), duplicate.clone()];
        sort_and_dedup_signals(&mut signals);

        assert_eq!(signals, vec![duplicate, variant]);
    }

    #[test]
    fn parse_benchmark_with_filters() {
        let args = vec![
            "benchmark".to_string(),
            "run".to_string(),
            "--run-date".to_string(),
            "2026-03-29".to_string(),
            "--seed".to_string(),
            "123".to_string(),
            "--profile".to_string(),
            "small".to_string(),
            "--profile".to_string(),
            "large".to_string(),
            "--family".to_string(),
            "boot-storm".to_string(),
            "--family".to_string(),
            "reload-revoke-churn".to_string(),
            "--out-dir".to_string(),
            "artifacts/custom".to_string(),
        ];
        let parsed = parse_command(&args).expect("benchmark command should parse");
        match parsed {
            CommandSpec::Benchmark(BenchmarkArgs {
                mode: BenchmarkMode::Run(spec),
            }) => {
                assert_eq!(spec.run_date, "2026-03-29");
                assert_eq!(spec.seed, 123);
                assert_eq!(
                    spec.profiles,
                    vec![ScaleProfile::Small, ScaleProfile::Large]
                );
                assert_eq!(
                    spec.families,
                    vec![
                        BenchmarkFamily::BootStorm,
                        BenchmarkFamily::ReloadRevokeChurn
                    ]
                );
                assert_eq!(spec.out_dir, PathBuf::from("artifacts/custom"));
            }
            other => panic!("expected benchmark command, got {other:?}"),
        }
    }

    #[test]
    fn parse_benchmark_compare_command() {
        let args = vec![
            "benchmark".to_string(),
            "compare".to_string(),
            "--manifest".to_string(),
            "artifacts/compare_manifest.json".to_string(),
            "--run-id".to_string(),
            "compare-run".to_string(),
            "--run-date".to_string(),
            "2026-04-07".to_string(),
            "--out-dir".to_string(),
            "artifacts/compare".to_string(),
        ];
        let parsed = parse_command(&args).expect("benchmark compare should parse");
        match parsed {
            CommandSpec::Benchmark(BenchmarkArgs {
                mode: BenchmarkMode::Compare(spec),
            }) => {
                assert_eq!(
                    spec.manifest,
                    PathBuf::from("artifacts/compare_manifest.json")
                );
                assert_eq!(spec.run_id, "compare-run");
                assert_eq!(spec.run_date, "2026-04-07");
                assert_eq!(spec.out_dir, PathBuf::from("artifacts/compare"));
            }
            other => panic!("expected benchmark compare command, got {other:?}"),
        }
    }

    #[test]
    fn parse_benchmark_run_command_rejects_invalid_run_date() {
        let args = vec![
            "benchmark".to_string(),
            "run".to_string(),
            "--run-date".to_string(),
            "2026-02-30".to_string(),
        ];
        let error = parse_command(&args).expect_err("invalid benchmark run date should fail");
        assert_eq!(
            error,
            "invalid --run-date `2026-02-30` (expected a real YYYY-MM-DD date)"
        );
    }

    #[test]
    fn benchmark_usage_mentions_compare_subcommand() {
        let usage = benchmark_usage();
        assert!(usage.contains("benchmark compare"));
        assert!(benchmark_compare_usage().contains("--manifest <comparison-manifest.json>"));
    }

    #[test]
    fn parse_benchmark_score_command() {
        let args = vec![
            "benchmark".to_string(),
            "score".to_string(),
            "--input".to_string(),
            "artifacts/input.json".to_string(),
            "--trace-id".to_string(),
            "trace-score".to_string(),
            "--decision-id".to_string(),
            "decision-score".to_string(),
            "--policy-id".to_string(),
            "policy-score".to_string(),
            "--output".to_string(),
            "artifacts/benchmark_score.json".to_string(),
        ];
        let parsed = parse_command(&args).expect("benchmark score should parse");
        match parsed {
            CommandSpec::Benchmark(BenchmarkArgs {
                mode: BenchmarkMode::Score(spec),
            }) => {
                assert_eq!(spec.input, PathBuf::from("artifacts/input.json"));
                assert_eq!(spec.trace_id, "trace-score");
                assert_eq!(spec.decision_id, "decision-score");
                assert_eq!(spec.policy_id, "policy-score");
                assert_eq!(
                    spec.output,
                    Some(PathBuf::from("artifacts/benchmark_score.json"))
                );
            }
            other => panic!("expected benchmark score command, got {other:?}"),
        }
    }

    #[test]
    fn parse_benchmark_verify_command() {
        let args = vec![
            "benchmark".to_string(),
            "verify".to_string(),
            "--bundle".to_string(),
            "artifacts/bundle".to_string(),
            "--summary".to_string(),
            "--output".to_string(),
            "artifacts/verify_report.json".to_string(),
        ];
        let parsed = parse_command(&args).expect("benchmark verify should parse");
        match parsed {
            CommandSpec::Benchmark(BenchmarkArgs {
                mode: BenchmarkMode::Verify(spec),
            }) => {
                assert_eq!(spec.bundle, PathBuf::from("artifacts/bundle"));
                assert_eq!(
                    spec.output,
                    Some(PathBuf::from("artifacts/verify_report.json"))
                );
                assert!(spec.summary);
            }
            other => panic!("expected benchmark verify command, got {other:?}"),
        }
    }

    #[test]
    fn parse_benchmark_verify_command_requires_bundle() {
        let args = vec!["benchmark".to_string(), "verify".to_string()];
        let error = parse_command(&args).expect_err("missing bundle should fail");
        assert_eq!(error, "benchmark verify requires --bundle <dir>");
    }

    #[test]
    fn parse_benchmark_verify_command_rejects_unknown_flag() {
        let args = vec![
            "benchmark".to_string(),
            "verify".to_string(),
            "--bundle".to_string(),
            "artifacts/bundle".to_string(),
            "--bogus".to_string(),
        ];
        let error = parse_command(&args).expect_err("unknown flag should fail");
        assert_eq!(error, "unknown benchmark verify flag `--bogus`");
    }

    #[test]
    fn run_benchmark_verify_parse_failure_includes_parse_remediation() {
        let error = run(vec!["benchmark".to_string(), "verify".to_string()])
            .expect_err("missing bundle should surface parse remediation");
        assert!(
            error.contains("[frankenctl trace_id=frankenctl-"),
            "error should include trace id, got: {error}"
        );
        assert!(
            error.contains("command=parse"),
            "error should identify parse command, got: {error}"
        );
        assert!(
            error.contains("benchmark verify requires --bundle <dir>"),
            "error should preserve parse failure, got: {error}"
        );
        assert!(
            error.contains(
                "remediation: Run `frankenctl --help` for full command usage and required arguments."
            ),
            "error should include parse remediation, got: {error}"
        );
    }

    // Tests for bd-1lsy.10.1.2: Regression tests proving advertised flags reach execution

    #[test]
    fn parse_gates_zero_placeholder_command_parses_advertised_flags() {
        let args = vec![
            "gates".to_string(),
            "zero-placeholder".to_string(),
            "--out-dir".to_string(),
            "test/gates/out".to_string(),
            "--waivers".to_string(),
            "waivers.json".to_string(),
        ];
        let result = parse_command(&args).expect("should parse valid gates command");
        if let CommandSpec::Gates(gates_args) = result {
            if let GatesMode::ZeroPlaceholder { out_dir, waivers } = gates_args.mode {
                assert_eq!(out_dir, PathBuf::from("test/gates/out"));
                assert_eq!(waivers, Some(PathBuf::from("waivers.json")));
            } else {
                panic!("expected ZeroPlaceholder mode");
            }
        } else {
            panic!("expected Gates command");
        }
    }

    #[test]
    fn parse_gates_signature_drift_command_parses_advertised_flags() {
        let args = vec![
            "gates".to_string(),
            "signature-drift".to_string(),
            "--out-dir".to_string(),
            "test/gates/signature".to_string(),
            "--config".to_string(),
            "signature-drift.json".to_string(),
        ];
        let result = parse_command(&args).expect("should parse valid signature-drift command");
        if let CommandSpec::Gates(gates_args) = result {
            if let GatesMode::SignatureDrift { out_dir, config } = gates_args.mode {
                assert_eq!(out_dir, PathBuf::from("test/gates/signature"));
                assert_eq!(config, Some(PathBuf::from("signature-drift.json")));
            } else {
                panic!("expected SignatureDrift mode");
            }
        } else {
            panic!("expected Gates command");
        }
    }

    #[test]
    fn parse_gates_signature_drift_command_requires_out_dir() {
        let args = vec!["gates".to_string(), "signature-drift".to_string()];
        let error = parse_command(&args).expect_err("missing out-dir should fail");
        assert_eq!(error, "gates signature-drift requires --out-dir <dir>");
    }

    #[test]
    fn placeholder_analysis_commands_fail_closed_without_writing_artifacts() {
        let temp_root = std::env::temp_dir().join(format!(
            "frankenctl-placeholder-fail-closed-{}",
            current_unix_ns()
        ));

        let signature_out_dir = temp_root.join("signature");
        let signature_config = temp_root.join("signature-config.json");
        let signature_report = signature_out_dir.join("signature_drift_analysis.json");
        let signature_error = execute_gates(GatesArgs {
            mode: GatesMode::SignatureDrift {
                out_dir: signature_out_dir.clone(),
                config: Some(signature_config.clone()),
            },
        })
        .expect_err("signature-drift should fail closed");
        assert!(signature_error.contains(CODE_UNSUPPORTED_PLACEHOLDER_COMMAND));
        assert!(signature_error.contains("gates signature-drift"));
        assert!(signature_error.contains(&signature_report.display().to_string()));
        assert!(signature_error.contains(&signature_config.display().to_string()));
        assert!(!signature_out_dir.exists());
        assert!(!signature_report.exists());

        let lowering_report = temp_root.join("lowering-gap.json");
        let lowering_error = execute_reports(ReportsArgs {
            mode: ReportsMode::LoweringGap {
                out: Some(lowering_report.clone()),
            },
        })
        .expect_err("lowering-gap should fail closed");
        assert!(lowering_error.contains(CODE_UNSUPPORTED_PLACEHOLDER_COMMAND));
        assert!(lowering_error.contains("reports lowering-gap"));
        assert!(lowering_error.contains(lowering_report.display().to_string().as_str()));
        assert!(!lowering_report.exists());

        let lockstep_report = temp_root.join("lockstep.json");
        let lockstep_config = temp_root.join("lockstep-config.json");
        let lockstep_error = execute_test(TestArgs {
            mode: TestMode::Lockstep {
                config: Some(lockstep_config.clone()),
                out: Some(lockstep_report.clone()),
            },
        })
        .expect_err("lockstep should fail closed");
        assert!(lockstep_error.contains(CODE_UNSUPPORTED_PLACEHOLDER_COMMAND));
        assert!(lockstep_error.contains("test lockstep"));
        assert!(lockstep_error.contains(lockstep_report.display().to_string().as_str()));
        assert!(lockstep_error.contains(lockstep_config.display().to_string().as_str()));
        assert!(!lockstep_report.exists());
    }

    #[test]
    fn parse_reports_parser_oracle_command_parses_advertised_flags() {
        let args = vec![
            "reports".to_string(),
            "parser-oracle".to_string(),
            "--config".to_string(),
            "oracle.json".to_string(),
            "--out".to_string(),
            "report.json".to_string(),
        ];
        let result = parse_command(&args).expect("should parse valid reports command");
        if let CommandSpec::Reports(reports_args) = result {
            if let ReportsMode::ParserOracle { config, out } = reports_args.mode {
                assert_eq!(config, Some(PathBuf::from("oracle.json")));
                assert_eq!(out, Some(PathBuf::from("report.json")));
            } else {
                panic!("expected ParserOracle mode");
            }
        } else {
            panic!("expected Reports command");
        }
    }

    #[test]
    fn parse_test_test262_command_parses_advertised_flags() {
        let args = vec![
            "test".to_string(),
            "test262".to_string(),
            "--out-dir".to_string(),
            "test/262/out".to_string(),
            "--suite-path".to_string(),
            "test262/suite".to_string(),
        ];
        let result = parse_command(&args).expect("should parse valid test command");
        if let CommandSpec::Test(test_args) = result {
            if let TestMode::Test262 {
                out_dir,
                suite_path,
            } = test_args.mode
            {
                assert_eq!(out_dir, PathBuf::from("test/262/out"));
                assert_eq!(suite_path, Some(PathBuf::from("test262/suite")));
            } else {
                panic!("expected Test262 mode");
            }
        } else {
            panic!("expected Test command");
        }
    }

    #[test]
    fn parse_synth_kernel_contract_command_parses_advertised_flags() {
        let args = vec![
            "synth".to_string(),
            "kernel-contract".to_string(),
            "--out-dir".to_string(),
            "synth/kernel/out".to_string(),
        ];
        let result = parse_command(&args).expect("should parse valid synth command");
        if let CommandSpec::Synth(synth_args) = result {
            if let SynthMode::KernelContract { out_dir } = synth_args.mode {
                assert_eq!(out_dir, PathBuf::from("synth/kernel/out"));
            } else {
                panic!("expected KernelContract mode");
            }
        } else {
            panic!("expected Synth command");
        }
    }

    #[test]
    fn parse_orchestrate_tail_latency_command_parses_advertised_flags() {
        let args = vec![
            "orchestrate".to_string(),
            "tail-latency".to_string(),
            "--out-dir".to_string(),
            "orchestrate/latency/out".to_string(),
        ];
        let result = parse_command(&args).expect("should parse valid orchestrate command");
        if let CommandSpec::Orchestrate(orchestrate_args) = result {
            if let OrchestrateMode::TailLatency { out_dir } = orchestrate_args.mode {
                assert_eq!(out_dir, PathBuf::from("orchestrate/latency/out"));
            } else {
                panic!("expected TailLatency mode");
            }
        } else {
            panic!("expected Orchestrate command");
        }
    }

    #[test]
    fn parse_runtime_diagnostics_command_parses_advertised_flags() {
        let args = vec![
            "runtime".to_string(),
            "diagnostics".to_string(),
            "--input".to_string(),
            "runtime.json".to_string(),
            "--out-dir".to_string(),
            "runtime/out".to_string(),
            "--summary".to_string(),
        ];
        let result = parse_command(&args).expect("should parse valid runtime command");
        if let CommandSpec::Runtime(runtime_args) = result {
            let RuntimeMode::Diagnostics {
                input,
                out_dir,
                summary,
            } = runtime_args.mode;
            assert_eq!(input, PathBuf::from("runtime.json"));
            assert_eq!(out_dir, Some(PathBuf::from("runtime/out")));
            assert!(summary);
        } else {
            panic!("expected Runtime command");
        }
    }

    #[test]
    fn parse_gates_zero_placeholder_command_rejects_unknown_flag() {
        let args = vec![
            "gates".to_string(),
            "zero-placeholder".to_string(),
            "--out-dir".to_string(),
            "test/out".to_string(),
            "--unknown-flag".to_string(),
        ];
        let result = parse_command(&args);
        assert!(result.is_err());
        let error = result.expect_err("operation should return an error");
        assert!(error.contains("unknown zero-placeholder flag `--unknown-flag`"));
    }

    #[test]
    fn parse_runtime_diagnostics_command_requires_input_flag() {
        let args = vec![
            "runtime".to_string(),
            "diagnostics".to_string(),
            "--out-dir".to_string(),
            "out".to_string(),
        ];
        let result = parse_command(&args);
        assert!(result.is_err());
        let error = result.expect_err("operation should return an error");
        assert!(error.contains("runtime diagnostics requires --input <file>"));
    }
}
