use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ast::{Expression, ParseGoal, Statement, SyntaxTree};
use crate::parser::{CanonicalEs2020Parser, Es2020Parser, ParseDiagnosticTaxonomy, ParseErrorCode};
use crate::simd_lexer::{LexerConfig, LexerMode, lex as lex_tokens};

pub const DEFAULT_MULTI_ENGINE_FIXTURE_CATALOG_PATH: &str =
    "crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json";

const EXPECTED_FIXTURE_SCHEMA_VERSION: &str = "franken-engine.parser-phase0.semantic-fixtures.v1";
const EXPECTED_FIXTURE_PARSER_MODE: &str = "scalar_reference";
const AST_NORMALIZATION_SCHEMA_VERSION: &str = "franken-engine.parser-ast-normalization.v1";
const DIAGNOSTIC_NORMALIZATION_SCHEMA_VERSION: &str =
    "franken-engine.parser-diagnostic-normalization.v1";
const EXTERNAL_DIAGNOSTIC_TAXONOMY_VERSION: &str = "external.engine-diagnostic.v1";
const DRIFT_CLASSIFICATION_TAXONOMY_VERSION: &str =
    "franken-engine.parser-multi-engine-drift-taxonomy.v1";
const REPORT_SCHEMA_VERSION: &str = "franken-engine.parser-multi-engine.report.v2";
const PARSER_TELEMETRY_SCHEMA_VERSION: &str = "franken-engine.parser-telemetry.v1";
const DRIFT_REPRO_PACK_SCHEMA_VERSION: &str = "franken-engine.parser-drift-repro-pack.v1";
const DRIFT_GOVERNANCE_ACTION_SCHEMA_VERSION: &str =
    "franken-engine.parser-drift-governance-action.v1";
const DRIFT_GOVERNANCE_ACTION_REPORT_SCHEMA_VERSION: &str =
    "franken-engine.parser-drift-governance-actions.v1";
const MAX_SOURCE_MINIMIZATION_ROUNDS: u32 = 32;
const MAX_SOURCE_MINIMIZATION_CANDIDATES: u32 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessEngineKind {
    FrankenCanonical,
    FixtureExpectedHash,
    ExternalCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessEngineSpec {
    pub engine_id: String,
    pub display_name: String,
    pub kind: HarnessEngineKind,
    pub version_pin: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
}

impl HarnessEngineSpec {
    pub fn franken_canonical(version_pin: impl Into<String>) -> Self {
        Self {
            engine_id: "franken_canonical".to_string(),
            display_name: "FrankenEngine Canonical Parser".to_string(),
            kind: HarnessEngineKind::FrankenCanonical,
            version_pin: version_pin.into(),
            command: None,
            args: Vec::new(),
        }
    }

    pub fn fixture_expected_hash(version_pin: impl Into<String>) -> Self {
        Self {
            engine_id: "fixture_expected_hash".to_string(),
            display_name: "Fixture Expected Hash Baseline".to_string(),
            kind: HarnessEngineKind::FixtureExpectedHash,
            version_pin: version_pin.into(),
            command: None,
            args: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiEngineHarnessConfig {
    pub fixture_catalog_path: PathBuf,
    pub fixture_limit: Option<usize>,
    pub fixture_id_filter: Option<String>,
    pub seed: u64,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub locale: String,
    pub timezone: String,
    pub engines: Vec<HarnessEngineSpec>,
}

impl MultiEngineHarnessConfig {
    pub fn with_defaults(seed: u64) -> Self {
        let now = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        Self {
            fixture_catalog_path: PathBuf::from(DEFAULT_MULTI_ENGINE_FIXTURE_CATALOG_PATH),
            fixture_limit: Some(8),
            fixture_id_filter: None,
            seed,
            trace_id: format!("trace-parser-multi-engine-{now}"),
            decision_id: format!("decision-parser-multi-engine-{now}"),
            policy_id: "policy-parser-multi-engine-v1".to_string(),
            locale: "C".to_string(),
            timezone: "UTC".to_string(),
            engines: vec![
                HarnessEngineSpec::franken_canonical("frankenengine-engine@workspace"),
                HarnessEngineSpec::fixture_expected_hash("fixture-catalog@phase0-v1"),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HarnessFixtureCatalog {
    pub schema_version: String,
    pub parser_mode: String,
    pub fixtures: Vec<HarnessFixtureSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HarnessFixtureSpec {
    pub id: String,
    pub family_id: String,
    pub goal: String,
    pub source: String,
    pub expected_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineOutcomeKind {
    Hash,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EngineRunOutcome {
    pub kind: EngineOutcomeKind,
    pub value: String,
    pub deterministic: bool,
    pub duration_us: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized_ast: Option<NormalizedAstArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized_diagnostic: Option<NormalizedDiagnosticArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EngineFixtureResult {
    pub engine_id: String,
    pub display_name: String,
    pub version_pin: String,
    pub derived_seed: u64,
    pub first_run: EngineRunOutcome,
    pub second_run: EngineRunOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FixtureComparisonResult {
    pub fixture_id: String,
    pub family_id: String,
    pub goal: String,
    pub source_hash: String,
    pub equivalent_across_engines: bool,
    pub nondeterministic_engine_count: u64,
    pub divergence_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drift_classification: Option<DriftClassification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repro_pack: Option<DriftReproPack>,
    pub replay_command: String,
    pub engine_results: Vec<EngineFixtureResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MultiEngineHarnessSummary {
    pub total_fixtures: u64,
    pub equivalent_fixtures: u64,
    pub divergent_fixtures: u64,
    pub fixtures_with_nondeterminism: u64,
    pub drift_minor_fixtures: u64,
    pub drift_critical_fixtures: u64,
    pub drift_counts_by_category: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParserTelemetrySummary {
    pub schema_version: String,
    pub sample_count: u64,
    pub throughput_sources_per_second_millionths: u64,
    pub throughput_mib_per_second_millionths: u64,
    pub latency_ns_p50: u64,
    pub latency_ns_p95: u64,
    pub latency_ns_p99: u64,
    pub ns_per_token_millionths: u64,
    pub allocs_per_token_millionths: u64,
    pub bytes_per_source_avg: u64,
    pub tokens_per_source_avg: u64,
    pub peak_rss_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MultiEngineHarnessReport {
    pub schema_version: String,
    pub generated_at_utc: String,
    pub run_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub fixture_catalog_path: String,
    pub fixture_catalog_hash: String,
    pub parser_mode: String,
    pub seed: u64,
    pub locale: String,
    pub timezone: String,
    pub fixture_count: u64,
    pub engine_specs: Vec<HarnessEngineSpec>,
    pub parser_telemetry: ParserTelemetrySummary,
    pub summary: MultiEngineHarnessSummary,
    pub fixture_results: Vec<FixtureComparisonResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AstNormalizationAdapter {
    CanonicalHashPassthroughV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticNormalizationAdapter {
    ParserDiagnosticsTaxonomyV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedAstArtifact {
    pub schema_version: String,
    pub adapter: AstNormalizationAdapter,
    pub canonical_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedDiagnosticArtifact {
    pub schema_version: String,
    pub taxonomy_version: String,
    pub adapter: DiagnosticNormalizationAdapter,
    pub diagnostic_code: String,
    pub category: String,
    pub severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parse_error_code: Option<String>,
    pub canonical_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftCategory {
    Semantic,
    Diagnostics,
    Harness,
    Artifact,
}

impl DriftCategory {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Semantic => "semantic",
            Self::Diagnostics => "diagnostics",
            Self::Harness => "harness",
            Self::Artifact => "artifact",
        }
    }

    const fn owner_hint(self) -> &'static str {
        match self {
            Self::Semantic => "parser-core",
            Self::Diagnostics => "parser-diagnostics-taxonomy",
            Self::Harness => "parser-multi-engine-harness",
            Self::Artifact => "parser-artifact-contract",
        }
    }

    const fn remediation_hint(self) -> &'static str {
        match self {
            Self::Semantic => "replay fixture and compare normalized AST hashes across engines",
            Self::Diagnostics => {
                "inspect normalized diagnostic codes and alias mappings for peer engines"
            }
            Self::Harness => {
                "rerun with fixed seed/env and audit harness/external-command nondeterminism"
            }
            Self::Artifact => {
                "validate normalized artifact shape and schema compatibility per engine outcome"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftSeverity {
    Minor,
    Critical,
}

impl DriftSeverity {
    const fn comparator_decision(self) -> &'static str {
        match self {
            Self::Minor => "drift_minor",
            Self::Critical => "drift_critical",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftClassification {
    pub taxonomy_version: String,
    pub category: DriftCategory,
    pub severity: DriftSeverity,
    pub comparator_decision: String,
    pub owner_hint: String,
    pub remediation_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftMinimizationStats {
    pub attempted: bool,
    pub rounds: u32,
    pub candidates_evaluated: u32,
    pub bytes_removed: u64,
    pub original_bytes: u64,
    pub minimized_bytes: u64,
    pub fixed_point: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftReproPack {
    pub schema_version: String,
    pub fixture_id: String,
    pub family_id: String,
    pub source_hash: String,
    pub minimized_source: String,
    pub minimized_source_hash: String,
    pub replay_command: String,
    pub drift_classification: DriftClassification,
    pub minimization: DriftMinimizationStats,
    pub promotion_hooks: Vec<String>,
    pub provenance_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceActionKind {
    Create,
    Update,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftGovernanceAction {
    pub schema_version: String,
    pub action: GovernanceActionKind,
    pub bead_id: String,
    pub fingerprint: String,
    pub fixture_id: String,
    pub category: DriftCategory,
    pub severity: DriftSeverity,
    pub owner_hint: String,
    pub remediation_hint: String,
    pub replay_command: String,
    pub minimized_source_hash: String,
    pub provenance_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftGovernanceActionReport {
    pub schema_version: String,
    pub generated_at_utc: String,
    pub run_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub actions: Vec<DriftGovernanceAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EngineNormalizedArtifacts {
    normalized_ast: Option<NormalizedAstArtifact>,
    normalized_diagnostic: Option<NormalizedDiagnosticArtifact>,
}

impl EngineNormalizedArtifacts {
    fn signature(&self) -> String {
        let ast = self
            .normalized_ast
            .as_ref()
            .map(|artifact| artifact.canonical_hash.as_str())
            .unwrap_or("none");
        let diagnostic = self
            .normalized_diagnostic
            .as_ref()
            .map(|artifact| artifact.canonical_hash.as_str())
            .unwrap_or("none");
        format!("ast:{ast};diag:{diagnostic}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EngineObservation {
    Hash(String),
    Error(String),
}

impl EngineObservation {
    fn kind(&self) -> EngineOutcomeKind {
        match self {
            Self::Hash(_) => EngineOutcomeKind::Hash,
            Self::Error(_) => EngineOutcomeKind::Error,
        }
    }

    fn value(&self) -> &str {
        match self {
            Self::Hash(value) | Self::Error(value) => value,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ExternalCommandRequest {
    goal: String,
    source: String,
    seed: u64,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    engine_id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ExternalCommandResponse {
    hash: Option<String>,
    error_code: Option<String>,
}

#[derive(Debug)]
pub enum MultiEngineHarnessError {
    Io {
        path: String,
        source: std::io::Error,
    },
    DecodeCatalog(String),
    InvalidCatalogSchema {
        expected: String,
        actual: String,
    },
    InvalidCatalogParserMode {
        expected: String,
        actual: String,
    },
    EmptyFixtureCatalog,
    DuplicateFixtureId {
        fixture_id: String,
    },
    UnknownGoal {
        fixture_id: String,
        goal: String,
    },
    FixtureFilterNotFound {
        fixture_id: String,
    },
    InvalidConfig(String),
    ExternalEngine {
        engine_id: String,
        detail: String,
    },
    Normalization {
        engine_id: String,
        detail: String,
    },
}

impl fmt::Display for MultiEngineHarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "failed to read `{path}`: {source}"),
            Self::DecodeCatalog(message) => {
                write!(
                    f,
                    "failed to decode multi-engine fixture catalog: {message}"
                )
            }
            Self::InvalidCatalogSchema { expected, actual } => write!(
                f,
                "invalid multi-engine catalog schema `{actual}` (expected `{expected}`)"
            ),
            Self::InvalidCatalogParserMode { expected, actual } => write!(
                f,
                "invalid multi-engine catalog parser_mode `{actual}` (expected `{expected}`)"
            ),
            Self::EmptyFixtureCatalog => {
                write!(f, "multi-engine fixture catalog must not be empty")
            }
            Self::DuplicateFixtureId { fixture_id } => {
                write!(
                    f,
                    "multi-engine fixture id `{fixture_id}` appears more than once"
                )
            }
            Self::UnknownGoal { fixture_id, goal } => {
                write!(f, "fixture `{fixture_id}` has unknown parse goal `{goal}`")
            }
            Self::FixtureFilterNotFound { fixture_id } => {
                write!(f, "fixture filter `{fixture_id}` did not match any fixture")
            }
            Self::InvalidConfig(message) => {
                write!(f, "invalid multi-engine harness config: {message}")
            }
            Self::ExternalEngine { engine_id, detail } => {
                write!(f, "external engine `{engine_id}` failed: {detail}")
            }
            Self::Normalization { engine_id, detail } => {
                write!(
                    f,
                    "normalization adapter for engine `{engine_id}` failed: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for MultiEngineHarnessError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FixtureEvaluation {
    engine_results: Vec<EngineFixtureResult>,
    equivalent_across_engines: bool,
    nondeterministic_engine_count: u64,
    divergence_reason: Option<String>,
    drift_classification: Option<DriftClassification>,
    parser_telemetry_samples: Vec<ParserTelemetrySample>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DriftSignature {
    classification: DriftClassification,
    engine_kinds: Vec<EngineOutcomeKind>,
}

impl DriftSignature {
    fn from_fixture_result(result: &FixtureComparisonResult) -> Option<Self> {
        let classification = result.drift_classification.clone()?;
        let engine_kinds = result
            .engine_results
            .iter()
            .map(|engine| engine.first_run.kind.clone())
            .collect::<Vec<_>>();
        Some(Self {
            classification,
            engine_kinds,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceMinimizationResult {
    minimized_source: String,
    stats: DriftMinimizationStats,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceTelemetryStats {
    source_bytes: u64,
    token_count: u64,
}

impl SourceTelemetryStats {
    fn from_source(source: &str) -> Self {
        Self {
            source_bytes: source.len() as u64,
            token_count: estimate_lexical_token_count(source),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParserTelemetrySample {
    duration_us: u64,
    source_bytes: u64,
    token_count: u64,
    allocation_estimate: u64,
    peak_rss_bytes: u64,
}

#[derive(Debug, Default)]
struct ParserTelemetryAccumulator {
    samples: Vec<ParserTelemetrySample>,
}

impl ParserTelemetryAccumulator {
    fn push(&mut self, sample: ParserTelemetrySample) {
        self.samples.push(sample);
    }

    fn finalize(self) -> ParserTelemetrySummary {
        if self.samples.is_empty() {
            return ParserTelemetrySummary {
                schema_version: PARSER_TELEMETRY_SCHEMA_VERSION.to_string(),
                sample_count: 0,
                throughput_sources_per_second_millionths: 0,
                throughput_mib_per_second_millionths: 0,
                latency_ns_p50: 0,
                latency_ns_p95: 0,
                latency_ns_p99: 0,
                ns_per_token_millionths: 0,
                allocs_per_token_millionths: 0,
                bytes_per_source_avg: 0,
                tokens_per_source_avg: 0,
                peak_rss_bytes: 0,
            };
        }

        let mut duration_ns_samples = self
            .samples
            .iter()
            .map(|sample| sample.duration_us.saturating_mul(1_000))
            .collect::<Vec<_>>();
        duration_ns_samples.sort_unstable();

        let total_duration_ns = duration_ns_samples
            .iter()
            .fold(0_u128, |acc, value| acc.saturating_add(u128::from(*value)));
        let total_source_bytes = self.samples.iter().fold(0_u128, |acc, sample| {
            acc.saturating_add(u128::from(sample.source_bytes))
        });
        let total_token_count = self.samples.iter().fold(0_u128, |acc, sample| {
            acc.saturating_add(u128::from(sample.token_count))
        });
        let total_allocation_estimate = self.samples.iter().fold(0_u128, |acc, sample| {
            acc.saturating_add(u128::from(sample.allocation_estimate))
        });
        let peak_rss_bytes = self
            .samples
            .iter()
            .map(|sample| sample.peak_rss_bytes)
            .max()
            .unwrap_or(0);

        let sample_count_u128 = self.samples.len() as u128;
        let throughput_sources_per_second_millionths = ratio_millionths(
            sample_count_u128.saturating_mul(1_000_000_000),
            total_duration_ns,
        );
        let throughput_mib_per_second_millionths = ratio_millionths(
            total_source_bytes.saturating_mul(1_000_000_000),
            total_duration_ns.saturating_mul(1_048_576),
        );
        let ns_per_token_millionths =
            ratio_millionths(total_duration_ns, total_token_count.max(1_u128));
        let allocs_per_token_millionths =
            ratio_millionths(total_allocation_estimate, total_token_count.max(1_u128));

        ParserTelemetrySummary {
            schema_version: PARSER_TELEMETRY_SCHEMA_VERSION.to_string(),
            sample_count: self.samples.len() as u64,
            throughput_sources_per_second_millionths,
            throughput_mib_per_second_millionths,
            latency_ns_p50: quantile(&duration_ns_samples, 50),
            latency_ns_p95: quantile(&duration_ns_samples, 95),
            latency_ns_p99: quantile(&duration_ns_samples, 99),
            ns_per_token_millionths,
            allocs_per_token_millionths,
            bytes_per_source_avg: saturating_u64(total_source_bytes / sample_count_u128),
            tokens_per_source_avg: saturating_u64(total_token_count / sample_count_u128),
            peak_rss_bytes,
        }
    }
}

pub fn run_multi_engine_harness(
    config: &MultiEngineHarnessConfig,
) -> Result<MultiEngineHarnessReport, MultiEngineHarnessError> {
    validate_config(config)?;

    let catalog = load_fixture_catalog(config.fixture_catalog_path.as_path())?;
    let catalog_hash = hash_bytes(&fs::read(config.fixture_catalog_path.as_path()).map_err(
        |source| MultiEngineHarnessError::Io {
            path: config.fixture_catalog_path.display().to_string(),
            source,
        },
    )?);

    let mut selected = catalog.fixtures;
    if let Some(fixture_id) = config.fixture_id_filter.as_ref() {
        selected.retain(|fixture| fixture.id == *fixture_id);
        if selected.is_empty() {
            return Err(MultiEngineHarnessError::FixtureFilterNotFound {
                fixture_id: fixture_id.clone(),
            });
        }
    }

    if let Some(limit) = config.fixture_limit
        && selected.len() > limit
    {
        selected.truncate(limit);
    }

    let run_id = derive_run_id(config, catalog_hash.as_str(), &selected);

    let mut fixture_results = Vec::with_capacity(selected.len());
    let mut equivalent_count = 0_u64;
    let mut divergent_count = 0_u64;
    let mut fixtures_with_nondeterminism = 0_u64;
    let mut drift_minor_fixtures = 0_u64;
    let mut drift_critical_fixtures = 0_u64;
    let mut drift_counts_by_category = BTreeMap::<String, u64>::new();
    let mut parser_telemetry_accumulator = ParserTelemetryAccumulator::default();

    for fixture in &selected {
        let goal = parse_goal(fixture.id.as_str(), fixture.goal.as_str())?;
        let source_hash = hash_bytes(fixture.source.as_bytes());
        let replay_command = format!(
            "cargo run -p frankenengine-engine --bin franken_parser_multi_engine_harness -- --fixture-catalog {} --seed {} --fixture-id {} --trace-id {} --decision-id {} --policy-id {}",
            config.fixture_catalog_path.display(),
            config.seed,
            fixture.id,
            config.trace_id,
            config.decision_id,
            config.policy_id,
        );
        let evaluation = evaluate_fixture(config, fixture, goal, fixture.source.as_str())?;
        for sample in &evaluation.parser_telemetry_samples {
            parser_telemetry_accumulator.push(sample.clone());
        }

        if evaluation.equivalent_across_engines {
            equivalent_count += 1;
        } else {
            divergent_count += 1;
        }
        if evaluation.nondeterministic_engine_count > 0 {
            fixtures_with_nondeterminism += 1;
        }
        if let Some(classification) = evaluation.drift_classification.as_ref() {
            *drift_counts_by_category
                .entry(classification.category.as_str().to_string())
                .or_insert(0) += 1;
            match classification.severity {
                DriftSeverity::Minor => drift_minor_fixtures += 1,
                DriftSeverity::Critical => drift_critical_fixtures += 1,
            }
        }

        let mut fixture_result = FixtureComparisonResult {
            fixture_id: fixture.id.clone(),
            family_id: fixture.family_id.clone(),
            goal: fixture.goal.clone(),
            source_hash,
            equivalent_across_engines: evaluation.equivalent_across_engines,
            nondeterministic_engine_count: evaluation.nondeterministic_engine_count,
            divergence_reason: evaluation.divergence_reason,
            drift_classification: evaluation.drift_classification,
            repro_pack: None,
            replay_command,
            engine_results: evaluation.engine_results,
        };

        if let Some(signature) = DriftSignature::from_fixture_result(&fixture_result) {
            let minimization = if fixture_result.nondeterministic_engine_count == 0 {
                minimize_fixture_source(config, fixture, goal, &signature)?
            } else {
                SourceMinimizationResult {
                    minimized_source: fixture.source.clone(),
                    stats: DriftMinimizationStats {
                        attempted: false,
                        rounds: 0,
                        candidates_evaluated: 0,
                        bytes_removed: 0,
                        original_bytes: fixture.source.len() as u64,
                        minimized_bytes: fixture.source.len() as u64,
                        fixed_point: true,
                    },
                }
            };

            fixture_result.repro_pack = Some(build_drift_repro_pack(
                config,
                fixture,
                fixture_result.source_hash.as_str(),
                fixture_result.replay_command.as_str(),
                &signature.classification,
                minimization,
            ));
        }

        fixture_results.push(fixture_result);
    }

    Ok(MultiEngineHarnessReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        generated_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        run_id,
        trace_id: config.trace_id.clone(),
        decision_id: config.decision_id.clone(),
        policy_id: config.policy_id.clone(),
        fixture_catalog_path: config.fixture_catalog_path.display().to_string(),
        fixture_catalog_hash: catalog_hash,
        parser_mode: EXPECTED_FIXTURE_PARSER_MODE.to_string(),
        seed: config.seed,
        locale: config.locale.clone(),
        timezone: config.timezone.clone(),
        fixture_count: fixture_results.len() as u64,
        engine_specs: config.engines.clone(),
        parser_telemetry: parser_telemetry_accumulator.finalize(),
        summary: MultiEngineHarnessSummary {
            total_fixtures: fixture_results.len() as u64,
            equivalent_fixtures: equivalent_count,
            divergent_fixtures: divergent_count,
            fixtures_with_nondeterminism,
            drift_minor_fixtures,
            drift_critical_fixtures,
            drift_counts_by_category,
        },
        fixture_results,
    })
}

pub fn has_critical_drift(report: &MultiEngineHarnessReport) -> bool {
    if report.summary.drift_critical_fixtures > 0 {
        return true;
    }
    report.fixture_results.iter().any(|fixture| {
        fixture
            .drift_classification
            .as_ref()
            .is_some_and(|classification| classification.severity == DriftSeverity::Critical)
    })
}

pub fn derive_drift_governance_actions(
    report: &MultiEngineHarnessReport,
) -> Vec<DriftGovernanceAction> {
    let mut actions_by_fingerprint = BTreeMap::<String, DriftGovernanceAction>::new();
    for fixture in &report.fixture_results {
        let Some(classification) = fixture.drift_classification.as_ref() else {
            continue;
        };
        let Some(repro_pack) = fixture.repro_pack.as_ref() else {
            continue;
        };

        let fingerprint = repro_pack.provenance_hash.clone();
        actions_by_fingerprint
            .entry(fingerprint.clone())
            .or_insert_with(|| DriftGovernanceAction {
                schema_version: DRIFT_GOVERNANCE_ACTION_SCHEMA_VERSION.to_string(),
                action: GovernanceActionKind::Create,
                bead_id: auto_bead_id_from_fingerprint(&fingerprint),
                fingerprint,
                fixture_id: fixture.fixture_id.clone(),
                category: classification.category,
                severity: classification.severity,
                owner_hint: classification.owner_hint.clone(),
                remediation_hint: classification.remediation_hint.clone(),
                replay_command: fixture.replay_command.clone(),
                minimized_source_hash: repro_pack.minimized_source_hash.clone(),
                provenance_hash: repro_pack.provenance_hash.clone(),
            });
    }

    actions_by_fingerprint.into_values().collect::<Vec<_>>()
}

pub fn build_drift_governance_action_report(
    report: &MultiEngineHarnessReport,
) -> DriftGovernanceActionReport {
    DriftGovernanceActionReport {
        schema_version: DRIFT_GOVERNANCE_ACTION_REPORT_SCHEMA_VERSION.to_string(),
        generated_at_utc: report.generated_at_utc.clone(),
        run_id: report.run_id.clone(),
        trace_id: report.trace_id.clone(),
        decision_id: report.decision_id.clone(),
        policy_id: report.policy_id.clone(),
        actions: derive_drift_governance_actions(report),
    }
}

fn auto_bead_id_from_fingerprint(fingerprint: &str) -> String {
    let mut normalized = fingerprint
        .strip_prefix("sha256:")
        .unwrap_or(fingerprint)
        .chars()
        .take(8)
        .collect::<String>();
    if normalized.is_empty() {
        normalized = "00000000".to_string();
    }
    format!("bd-auto-{normalized}")
}

fn derive_run_id(
    config: &MultiEngineHarnessConfig,
    catalog_hash: &str,
    fixtures: &[HarnessFixtureSpec],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(catalog_hash.as_bytes());
    hasher.update(config.seed.to_le_bytes());
    hasher.update(config.locale.as_bytes());
    hasher.update(config.timezone.as_bytes());

    for engine in &config.engines {
        hasher.update(engine.engine_id.as_bytes());
        hasher.update(engine.version_pin.as_bytes());
        hasher.update(
            serde_json::to_string(&engine.kind)
                .expect("engine kind should serialize for deterministic hashing")
                .as_bytes(),
        );
        if let Some(command) = engine.command.as_ref() {
            hasher.update(command.as_bytes());
        }
        for arg in &engine.args {
            hasher.update(arg.as_bytes());
        }
    }

    for fixture in fixtures {
        hasher.update(fixture.id.as_bytes());
        hasher.update(fixture.expected_hash.as_bytes());
    }

    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn format_divergence_reason(
    outcome_signatures: &BTreeMap<String, Vec<String>>,
    nondeterministic_engine_count: u64,
) -> String {
    let mut parts = Vec::new();
    for (signature, engines) in outcome_signatures {
        parts.push(format!("{signature} <- [{}]", engines.join(",")));
    }
    if nondeterministic_engine_count > 0 {
        parts.push(format!(
            "nondeterministic_engines={nondeterministic_engine_count}"
        ));
    }
    parts.join("; ")
}

fn evaluate_fixture(
    config: &MultiEngineHarnessConfig,
    fixture: &HarnessFixtureSpec,
    goal: ParseGoal,
    source: &str,
) -> Result<FixtureEvaluation, MultiEngineHarnessError> {
    let mut source_fixture = fixture.clone();
    source_fixture.source = source.to_string();
    let source_stats = SourceTelemetryStats::from_source(source);

    let mut engine_results = Vec::with_capacity(config.engines.len());
    let mut outcome_signatures = BTreeMap::<String, Vec<String>>::new();
    let mut nondeterministic_engine_count = 0_u64;
    let mut parser_telemetry_samples = Vec::<ParserTelemetrySample>::new();

    for engine in &config.engines {
        let derived_seed =
            derive_engine_seed(config.seed, fixture.id.as_str(), engine.engine_id.as_str());
        let first = execute_engine(
            engine,
            &source_fixture,
            goal,
            derived_seed,
            config,
            &source_stats,
        )?;
        let second = execute_engine(
            engine,
            &source_fixture,
            goal,
            derived_seed,
            config,
            &source_stats,
        )?;
        let first_normalized =
            normalize_engine_observation(engine.engine_id.as_str(), &first.observation)?;
        let second_normalized =
            normalize_engine_observation(engine.engine_id.as_str(), &second.observation)?;
        let deterministic =
            first.observation == second.observation && first_normalized == second_normalized;
        if !deterministic {
            nondeterministic_engine_count += 1;
        }

        let first_run = EngineRunOutcome {
            kind: first.observation.kind(),
            value: first.observation.value().to_string(),
            deterministic,
            duration_us: first.duration_us,
            normalized_ast: first_normalized.normalized_ast.clone(),
            normalized_diagnostic: first_normalized.normalized_diagnostic.clone(),
        };
        let second_run = EngineRunOutcome {
            kind: second.observation.kind(),
            value: second.observation.value().to_string(),
            deterministic,
            duration_us: second.duration_us,
            normalized_ast: second_normalized.normalized_ast.clone(),
            normalized_diagnostic: second_normalized.normalized_diagnostic.clone(),
        };

        outcome_signatures
            .entry(first_normalized.signature())
            .or_default()
            .push(engine.engine_id.clone());

        if matches!(engine.kind, HarnessEngineKind::FrankenCanonical) {
            parser_telemetry_samples.push(ParserTelemetrySample {
                duration_us: first.duration_us,
                source_bytes: first.source_bytes,
                token_count: first.token_count,
                allocation_estimate: first.allocation_estimate,
                peak_rss_bytes: first.peak_rss_bytes,
            });
            parser_telemetry_samples.push(ParserTelemetrySample {
                duration_us: second.duration_us,
                source_bytes: second.source_bytes,
                token_count: second.token_count,
                allocation_estimate: second.allocation_estimate,
                peak_rss_bytes: second.peak_rss_bytes,
            });
        }

        engine_results.push(EngineFixtureResult {
            engine_id: engine.engine_id.clone(),
            display_name: engine.display_name.clone(),
            version_pin: engine.version_pin.clone(),
            derived_seed,
            first_run,
            second_run,
        });
    }

    let equivalent_across_engines =
        outcome_signatures.len() == 1 && nondeterministic_engine_count == 0;
    let divergence_reason = if equivalent_across_engines {
        None
    } else {
        Some(format_divergence_reason(
            &outcome_signatures,
            nondeterministic_engine_count,
        ))
    };
    let drift_classification = if equivalent_across_engines {
        None
    } else {
        Some(classify_fixture_drift(
            &engine_results,
            nondeterministic_engine_count,
        ))
    };

    Ok(FixtureEvaluation {
        engine_results,
        equivalent_across_engines,
        nondeterministic_engine_count,
        divergence_reason,
        drift_classification,
        parser_telemetry_samples,
    })
}

fn minimize_fixture_source(
    config: &MultiEngineHarnessConfig,
    fixture: &HarnessFixtureSpec,
    goal: ParseGoal,
    signature: &DriftSignature,
) -> Result<SourceMinimizationResult, MultiEngineHarnessError> {
    let mut captured_error = None::<MultiEngineHarnessError>;
    let minimization = minimize_source_with(fixture.source.as_str(), |candidate| {
        match candidate_preserves_drift_signature(config, fixture, goal, candidate, signature) {
            Ok(preserves) => preserves,
            Err(error) => {
                if captured_error.is_none() {
                    captured_error = Some(error);
                }
                false
            }
        }
    });

    if let Some(error) = captured_error {
        return Err(error);
    }

    Ok(minimization)
}

fn candidate_preserves_drift_signature(
    config: &MultiEngineHarnessConfig,
    fixture: &HarnessFixtureSpec,
    goal: ParseGoal,
    candidate_source: &str,
    signature: &DriftSignature,
) -> Result<bool, MultiEngineHarnessError> {
    let evaluation = evaluate_fixture(config, fixture, goal, candidate_source)?;
    if evaluation.equivalent_across_engines || evaluation.nondeterministic_engine_count > 0 {
        return Ok(false);
    }
    let Some(classification) = evaluation.drift_classification else {
        return Ok(false);
    };
    if classification != signature.classification {
        return Ok(false);
    }
    let candidate_kinds = evaluation
        .engine_results
        .iter()
        .map(|engine| engine.first_run.kind.clone())
        .collect::<Vec<_>>();
    Ok(candidate_kinds == signature.engine_kinds)
}

fn minimize_source_with<F>(source: &str, mut still_fails: F) -> SourceMinimizationResult
where
    F: FnMut(&str) -> bool,
{
    let original_bytes = source.len() as u64;
    if source.trim().is_empty() {
        return SourceMinimizationResult {
            minimized_source: source.to_string(),
            stats: DriftMinimizationStats {
                attempted: false,
                rounds: 0,
                candidates_evaluated: 0,
                bytes_removed: 0,
                original_bytes,
                minimized_bytes: original_bytes,
                fixed_point: true,
            },
        };
    }
    if !still_fails(source) {
        return SourceMinimizationResult {
            minimized_source: source.to_string(),
            stats: DriftMinimizationStats {
                attempted: false,
                rounds: 0,
                candidates_evaluated: 0,
                bytes_removed: 0,
                original_bytes,
                minimized_bytes: original_bytes,
                fixed_point: true,
            },
        };
    }

    let mut fragments = split_source_fragments(source);
    let mut chunk_size = std::cmp::max(fragments.len() / 2, 1);
    let mut rounds = 0_u32;
    let mut candidates_evaluated = 0_u32;
    let mut bytes_removed = 0_u64;
    let mut fixed_point = false;

    while rounds < MAX_SOURCE_MINIMIZATION_ROUNDS
        && candidates_evaluated < MAX_SOURCE_MINIMIZATION_CANDIDATES
    {
        rounds += 1;
        let mut improved = false;
        let mut idx = 0_usize;
        while idx < fragments.len()
            && candidates_evaluated < MAX_SOURCE_MINIMIZATION_CANDIDATES
            && fragments.len() > 1
        {
            if chunk_size > fragments.len() {
                break;
            }
            let end = std::cmp::min(idx + chunk_size, fragments.len());
            if end <= idx || fragments.len() - (end - idx) == 0 {
                break;
            }
            let candidate = join_fragments_without_range(&fragments, idx, end);
            if candidate.trim().is_empty() {
                idx += chunk_size;
                continue;
            }
            if candidate.len() >= fragments.concat().len() {
                idx += chunk_size;
                continue;
            }

            candidates_evaluated += 1;
            if still_fails(candidate.as_str()) {
                let current_len = fragments.concat().len();
                let removed = current_len.saturating_sub(candidate.len()) as u64;
                bytes_removed += removed;
                fragments = split_source_fragments(candidate.as_str());
                improved = true;
                idx = 0;
            } else {
                idx += chunk_size;
            }
        }

        if !improved {
            if chunk_size == 1 {
                fixed_point = true;
                break;
            }
            chunk_size = std::cmp::max(chunk_size / 2, 1);
        }
    }

    let minimized_source = fragments.concat();
    let minimized_bytes = minimized_source.len() as u64;

    SourceMinimizationResult {
        minimized_source,
        stats: DriftMinimizationStats {
            attempted: true,
            rounds,
            candidates_evaluated,
            bytes_removed,
            original_bytes,
            minimized_bytes,
            fixed_point,
        },
    }
}

fn split_source_fragments(source: &str) -> Vec<String> {
    let mut fragments = source
        .split_inclusive('\n')
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
    if fragments.is_empty() {
        fragments.push(source.to_string());
    }
    fragments
}

fn join_fragments_without_range(fragments: &[String], start: usize, end: usize) -> String {
    fragments
        .iter()
        .enumerate()
        .filter_map(|(idx, value)| {
            if idx >= start && idx < end {
                None
            } else {
                Some(value.as_str())
            }
        })
        .collect::<String>()
}

fn build_drift_repro_pack(
    config: &MultiEngineHarnessConfig,
    fixture: &HarnessFixtureSpec,
    source_hash: &str,
    replay_command: &str,
    classification: &DriftClassification,
    minimization: SourceMinimizationResult,
) -> DriftReproPack {
    let minimized_source_hash = hash_bytes(minimization.minimized_source.as_bytes());
    let promotion_hooks = vec![
        format!(
            "tests/fixtures/parser_drift_minimized/{}.json",
            fixture.id.as_str()
        ),
        format!(
            "tests/property/parser_drift_minimized/{}.json",
            fixture.id.as_str()
        ),
        format!(
            "scripts/e2e/parser_drift_repro_replay.sh --fixture-id {}",
            fixture.id.as_str()
        ),
    ];
    let provenance_input = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        DRIFT_REPRO_PACK_SCHEMA_VERSION,
        fixture.id,
        fixture.family_id,
        source_hash,
        minimized_source_hash,
        classification.comparator_decision,
        config.seed,
        config.trace_id,
        config.decision_id,
        config.policy_id,
        config.locale,
        config.timezone,
    );

    DriftReproPack {
        schema_version: DRIFT_REPRO_PACK_SCHEMA_VERSION.to_string(),
        fixture_id: fixture.id.clone(),
        family_id: fixture.family_id.clone(),
        source_hash: source_hash.to_string(),
        minimized_source: minimization.minimized_source,
        minimized_source_hash,
        replay_command: replay_command.to_string(),
        drift_classification: classification.clone(),
        minimization: minimization.stats,
        promotion_hooks,
        provenance_hash: hash_bytes(provenance_input.as_bytes()),
    }
}

fn classify_fixture_drift(
    engine_results: &[EngineFixtureResult],
    nondeterministic_engine_count: u64,
) -> DriftClassification {
    if nondeterministic_engine_count > 0 {
        return build_drift_classification(DriftCategory::Harness, DriftSeverity::Critical);
    }

    if has_artifact_shape_mismatch(engine_results) {
        return build_drift_classification(DriftCategory::Artifact, DriftSeverity::Critical);
    }

    if engine_results.is_empty() {
        return build_drift_classification(DriftCategory::Artifact, DriftSeverity::Critical);
    }

    let has_hash = engine_results
        .iter()
        .any(|result| matches!(result.first_run.kind, EngineOutcomeKind::Hash));
    let has_error = engine_results
        .iter()
        .any(|result| matches!(result.first_run.kind, EngineOutcomeKind::Error));

    if has_hash && has_error {
        return build_drift_classification(DriftCategory::Semantic, DriftSeverity::Critical);
    }

    match engine_results[0].first_run.kind {
        EngineOutcomeKind::Hash => {
            build_drift_classification(DriftCategory::Semantic, DriftSeverity::Critical)
        }
        EngineOutcomeKind::Error => {
            build_drift_classification(DriftCategory::Diagnostics, DriftSeverity::Minor)
        }
    }
}

fn build_drift_classification(
    category: DriftCategory,
    severity: DriftSeverity,
) -> DriftClassification {
    DriftClassification {
        taxonomy_version: DRIFT_CLASSIFICATION_TAXONOMY_VERSION.to_string(),
        category,
        severity,
        comparator_decision: severity.comparator_decision().to_string(),
        owner_hint: category.owner_hint().to_string(),
        remediation_hint: category.remediation_hint().to_string(),
    }
}

fn has_artifact_shape_mismatch(engine_results: &[EngineFixtureResult]) -> bool {
    engine_results.iter().any(|result| {
        !run_outcome_shape_matches_kind(&result.first_run)
            || !run_outcome_shape_matches_kind(&result.second_run)
    })
}

fn run_outcome_shape_matches_kind(run: &EngineRunOutcome) -> bool {
    match run.kind {
        EngineOutcomeKind::Hash => {
            run.normalized_ast.is_some() && run.normalized_diagnostic.is_none()
        }
        EngineOutcomeKind::Error => {
            run.normalized_diagnostic.is_some() && run.normalized_ast.is_none()
        }
    }
}

fn validate_config(config: &MultiEngineHarnessConfig) -> Result<(), MultiEngineHarnessError> {
    if config.trace_id.trim().is_empty() {
        return Err(MultiEngineHarnessError::InvalidConfig(
            "trace_id must not be empty".to_string(),
        ));
    }
    if config.decision_id.trim().is_empty() {
        return Err(MultiEngineHarnessError::InvalidConfig(
            "decision_id must not be empty".to_string(),
        ));
    }
    if config.policy_id.trim().is_empty() {
        return Err(MultiEngineHarnessError::InvalidConfig(
            "policy_id must not be empty".to_string(),
        ));
    }
    if config.engines.len() < 2 {
        return Err(MultiEngineHarnessError::InvalidConfig(
            "at least two engine specs are required".to_string(),
        ));
    }

    let mut engine_ids = BTreeSet::new();
    for engine in &config.engines {
        if engine.engine_id.trim().is_empty() {
            return Err(MultiEngineHarnessError::InvalidConfig(
                "engine_id must not be empty".to_string(),
            ));
        }
        if !engine_ids.insert(engine.engine_id.clone()) {
            return Err(MultiEngineHarnessError::InvalidConfig(format!(
                "engine_id `{}` appears more than once",
                engine.engine_id
            )));
        }
        if engine.version_pin.trim().is_empty() {
            return Err(MultiEngineHarnessError::InvalidConfig(format!(
                "engine `{}` has empty version_pin",
                engine.engine_id
            )));
        }
        if matches!(engine.kind, HarnessEngineKind::ExternalCommand)
            && engine
                .command
                .as_ref()
                .is_none_or(|command| command.trim().is_empty())
        {
            return Err(MultiEngineHarnessError::InvalidConfig(format!(
                "external engine `{}` requires command",
                engine.engine_id
            )));
        }
    }

    Ok(())
}

#[derive(Debug)]
struct TimedObservation {
    observation: EngineObservation,
    duration_us: u64,
    source_bytes: u64,
    token_count: u64,
    allocation_estimate: u64,
    peak_rss_bytes: u64,
}

fn execute_engine(
    engine: &HarnessEngineSpec,
    fixture: &HarnessFixtureSpec,
    goal: ParseGoal,
    seed: u64,
    config: &MultiEngineHarnessConfig,
    source_stats: &SourceTelemetryStats,
) -> Result<TimedObservation, MultiEngineHarnessError> {
    let started = Instant::now();
    let mut allocation_estimate = 0_u64;
    let observation = match engine.kind {
        HarnessEngineKind::FrankenCanonical => {
            let parser = CanonicalEs2020Parser;
            match parser.parse(fixture.source.as_str(), goal) {
                Ok(tree) => {
                    allocation_estimate = estimate_syntax_tree_allocation_count(&tree);
                    EngineObservation::Hash(tree.canonical_hash())
                }
                Err(error) => {
                    allocation_estimate = 1;
                    EngineObservation::Error(error.code.as_str().to_string())
                }
            }
        }
        HarnessEngineKind::FixtureExpectedHash => {
            EngineObservation::Hash(fixture.expected_hash.clone())
        }
        HarnessEngineKind::ExternalCommand => {
            run_external_engine(engine, fixture, goal, seed, config)?
        }
    };

    Ok(TimedObservation {
        observation,
        duration_us: started.elapsed().as_micros() as u64,
        source_bytes: source_stats.source_bytes,
        token_count: source_stats.token_count,
        allocation_estimate,
        peak_rss_bytes: read_peak_rss_bytes().unwrap_or(0),
    })
}

fn run_external_engine(
    engine: &HarnessEngineSpec,
    fixture: &HarnessFixtureSpec,
    goal: ParseGoal,
    seed: u64,
    config: &MultiEngineHarnessConfig,
) -> Result<EngineObservation, MultiEngineHarnessError> {
    let command =
        engine
            .command
            .as_ref()
            .ok_or_else(|| MultiEngineHarnessError::ExternalEngine {
                engine_id: engine.engine_id.clone(),
                detail: "missing command".to_string(),
            })?;

    let request = ExternalCommandRequest {
        goal: goal.as_str().to_string(),
        source: fixture.source.clone(),
        seed,
        trace_id: config.trace_id.clone(),
        decision_id: config.decision_id.clone(),
        policy_id: config.policy_id.clone(),
        engine_id: engine.engine_id.clone(),
    };

    let payload =
        serde_json::to_vec(&request).map_err(|error| MultiEngineHarnessError::ExternalEngine {
            engine_id: engine.engine_id.clone(),
            detail: format!("failed to serialize request payload: {error}"),
        })?;

    let mut process = Command::new(command);
    process
        .args(&engine.args)
        .env("LC_ALL", config.locale.as_str())
        .env("LANG", config.locale.as_str())
        .env("TZ", config.timezone.as_str())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = process
        .spawn()
        .map_err(|error| MultiEngineHarnessError::ExternalEngine {
            engine_id: engine.engine_id.clone(),
            detail: format!("failed to spawn command `{command}`: {error}"),
        })?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(&payload)
            .map_err(|error| MultiEngineHarnessError::ExternalEngine {
                engine_id: engine.engine_id.clone(),
                detail: format!("failed to write stdin payload: {error}"),
            })?;
    }

    let output =
        child
            .wait_with_output()
            .map_err(|error| MultiEngineHarnessError::ExternalEngine {
                engine_id: engine.engine_id.clone(),
                detail: format!("failed waiting for process exit: {error}"),
            })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(MultiEngineHarnessError::ExternalEngine {
            engine_id: engine.engine_id.clone(),
            detail: format!(
                "command exited with status {}{}",
                output
                    .status
                    .code()
                    .map_or_else(|| "signal".to_string(), |code| code.to_string()),
                if stderr.is_empty() {
                    "".to_string()
                } else {
                    format!("; stderr={stderr}")
                }
            ),
        });
    }

    let response: ExternalCommandResponse =
        serde_json::from_slice(&output.stdout).map_err(|error| {
            MultiEngineHarnessError::ExternalEngine {
                engine_id: engine.engine_id.clone(),
                detail: format!("invalid JSON response: {error}"),
            }
        })?;

    if let Some(hash) = response.hash {
        return Ok(EngineObservation::Hash(hash));
    }
    if let Some(error_code) = response.error_code {
        return Ok(EngineObservation::Error(error_code));
    }

    Err(MultiEngineHarnessError::ExternalEngine {
        engine_id: engine.engine_id.clone(),
        detail: "response must include either `hash` or `error_code`".to_string(),
    })
}

fn normalize_engine_observation(
    engine_id: &str,
    observation: &EngineObservation,
) -> Result<EngineNormalizedArtifacts, MultiEngineHarnessError> {
    match observation {
        EngineObservation::Hash(value) => Ok(EngineNormalizedArtifacts {
            normalized_ast: Some(normalize_ast_hash(engine_id, value)?),
            normalized_diagnostic: None,
        }),
        EngineObservation::Error(value) => Ok(EngineNormalizedArtifacts {
            normalized_ast: None,
            normalized_diagnostic: Some(normalize_diagnostic_code(value)),
        }),
    }
}

fn normalize_ast_hash(
    engine_id: &str,
    raw_hash: &str,
) -> Result<NormalizedAstArtifact, MultiEngineHarnessError> {
    let canonical_hash = canonicalize_sha256_hash(raw_hash).ok_or_else(|| {
        MultiEngineHarnessError::Normalization {
            engine_id: engine_id.to_string(),
            detail: format!("invalid AST hash `{raw_hash}` (expected sha256:<64-hex>)"),
        }
    })?;
    Ok(NormalizedAstArtifact {
        schema_version: AST_NORMALIZATION_SCHEMA_VERSION.to_string(),
        adapter: AstNormalizationAdapter::CanonicalHashPassthroughV1,
        canonical_hash,
    })
}

fn normalize_diagnostic_code(raw_code: &str) -> NormalizedDiagnosticArtifact {
    let trimmed = raw_code.trim();
    let normalized_key = trimmed.to_ascii_lowercase();
    let maybe_code = parse_error_code_alias(&normalized_key);
    let taxonomy = ParseDiagnosticTaxonomy::v1();

    let (diagnostic_code, category, severity, parse_error_code, taxonomy_version) =
        if let Some(code) = maybe_code {
            if let Some(rule) = taxonomy.rule_for(code) {
                (
                    rule.diagnostic_code.clone(),
                    rule.category.as_str().to_string(),
                    rule.severity.as_str().to_string(),
                    Some(code.as_str().to_string()),
                    ParseDiagnosticTaxonomy::taxonomy_version().to_string(),
                )
            } else {
                (
                    code.stable_diagnostic_code().to_string(),
                    code.diagnostic_category().as_str().to_string(),
                    code.diagnostic_severity().as_str().to_string(),
                    Some(code.as_str().to_string()),
                    ParseDiagnosticTaxonomy::taxonomy_version().to_string(),
                )
            }
        } else {
            (
                format!("external::{trimmed}"),
                "system".to_string(),
                "error".to_string(),
                None,
                EXTERNAL_DIAGNOSTIC_TAXONOMY_VERSION.to_string(),
            )
        };

    let canonical_hash = hash_bytes(
        format!(
            "{schema}|{taxonomy}|{adapter}|{code}|{category}|{severity}|{parse_code}",
            schema = DIAGNOSTIC_NORMALIZATION_SCHEMA_VERSION,
            taxonomy = taxonomy_version,
            adapter = "parser_diagnostics_taxonomy_v1",
            code = diagnostic_code,
            category = category,
            severity = severity,
            parse_code = parse_error_code.as_deref().unwrap_or("none"),
        )
        .as_bytes(),
    );

    NormalizedDiagnosticArtifact {
        schema_version: DIAGNOSTIC_NORMALIZATION_SCHEMA_VERSION.to_string(),
        taxonomy_version,
        adapter: DiagnosticNormalizationAdapter::ParserDiagnosticsTaxonomyV1,
        diagnostic_code,
        category,
        severity,
        parse_error_code,
        canonical_hash,
    }
}

fn parse_error_code_alias(value: &str) -> Option<ParseErrorCode> {
    match value {
        "emptysource" | "empty_source" => Some(ParseErrorCode::EmptySource),
        "invalidgoal" | "invalid_goal" => Some(ParseErrorCode::InvalidGoal),
        "unsupportedsyntax" | "unsupported_syntax" => Some(ParseErrorCode::UnsupportedSyntax),
        "ioreadfailed" | "io_read_failed" => Some(ParseErrorCode::IoReadFailed),
        "invalidutf8" | "invalid_utf8" => Some(ParseErrorCode::InvalidUtf8),
        "sourcetoolarge" | "source_too_large" => Some(ParseErrorCode::SourceTooLarge),
        "budgetexceeded" | "budget_exceeded" => Some(ParseErrorCode::BudgetExceeded),
        _ => None,
    }
}

fn canonicalize_sha256_hash(raw_hash: &str) -> Option<String> {
    let value = raw_hash.trim();
    let lowercase = value.to_ascii_lowercase();
    let hash = lowercase.strip_prefix("sha256:")?;
    if hash.len() != 64 || !hash.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("sha256:{hash}"))
}

pub fn derive_engine_seed(master_seed: u64, fixture_id: &str, engine_id: &str) -> u64 {
    let payload = format!("{master_seed}:{fixture_id}:{engine_id}");
    let digest = Sha256::digest(payload.as_bytes());
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes)
}

pub fn load_fixture_catalog(path: &Path) -> Result<HarnessFixtureCatalog, MultiEngineHarnessError> {
    let bytes = fs::read(path).map_err(|source| MultiEngineHarnessError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let catalog = serde_json::from_slice::<HarnessFixtureCatalog>(&bytes)
        .map_err(|error| MultiEngineHarnessError::DecodeCatalog(error.to_string()))?;
    validate_fixture_catalog(&catalog)?;
    Ok(catalog)
}

fn validate_fixture_catalog(
    catalog: &HarnessFixtureCatalog,
) -> Result<(), MultiEngineHarnessError> {
    if catalog.schema_version != EXPECTED_FIXTURE_SCHEMA_VERSION {
        return Err(MultiEngineHarnessError::InvalidCatalogSchema {
            expected: EXPECTED_FIXTURE_SCHEMA_VERSION.to_string(),
            actual: catalog.schema_version.clone(),
        });
    }

    if catalog.parser_mode != EXPECTED_FIXTURE_PARSER_MODE {
        return Err(MultiEngineHarnessError::InvalidCatalogParserMode {
            expected: EXPECTED_FIXTURE_PARSER_MODE.to_string(),
            actual: catalog.parser_mode.clone(),
        });
    }

    if catalog.fixtures.is_empty() {
        return Err(MultiEngineHarnessError::EmptyFixtureCatalog);
    }

    let mut seen = BTreeSet::new();
    for fixture in &catalog.fixtures {
        if !seen.insert(fixture.id.clone()) {
            return Err(MultiEngineHarnessError::DuplicateFixtureId {
                fixture_id: fixture.id.clone(),
            });
        }
        if fixture.expected_hash.trim().is_empty() {
            return Err(MultiEngineHarnessError::InvalidConfig(format!(
                "fixture `{}` has empty expected_hash",
                fixture.id
            )));
        }
    }

    Ok(())
}

fn parse_goal(fixture_id: &str, goal: &str) -> Result<ParseGoal, MultiEngineHarnessError> {
    match goal {
        "script" => Ok(ParseGoal::Script),
        "module" => Ok(ParseGoal::Module),
        other => Err(MultiEngineHarnessError::UnknownGoal {
            fixture_id: fixture_id.to_string(),
            goal: other.to_string(),
        }),
    }
}

fn hash_bytes(input: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(input)))
}

fn estimate_lexical_token_count(source: &str) -> u64 {
    let config = LexerConfig {
        mode: LexerMode::Scalar,
        emit_tokens: false,
        max_tokens: u64::MAX,
        max_source_bytes: u64::MAX,
        ..LexerConfig::default()
    };
    lex_tokens(source, &config)
        .map(|output| output.token_count)
        .unwrap_or_else(|_| source.split_whitespace().count() as u64)
}

fn estimate_syntax_tree_allocation_count(tree: &SyntaxTree) -> u64 {
    let mut total = 1_u64.saturating_add(tree.body.len() as u64);
    for statement in &tree.body {
        total = total.saturating_add(estimate_statement_allocation_count(statement));
    }
    total
}

fn estimate_statement_allocation_count(statement: &Statement) -> u64 {
    match statement {
        Statement::Import(import) => {
            let mut total = 2_u64;
            if import.binding.is_some() {
                total = total.saturating_add(1);
            }
            total
        }
        Statement::Export(export) => 2_u64.saturating_add(match &export.kind {
            crate::ast::ExportKind::Default(expression) => {
                estimate_expression_allocation_count(expression)
            }
            crate::ast::ExportKind::NamedClause(_) => 1,
        }),
        Statement::Expression(expression) => {
            1_u64.saturating_add(estimate_expression_allocation_count(&expression.expression))
        }
        Statement::VariableDeclaration(variable_declaration) => {
            let mut total = 2_u64;
            for declarator in &variable_declaration.declarations {
                total = total.saturating_add(2);
                if let Some(initializer) = &declarator.initializer {
                    total = total.saturating_add(estimate_expression_allocation_count(initializer));
                }
            }
            total
        }
        Statement::Block(block) => {
            1_u64.saturating_add(estimate_statement_vec_allocation_count(&block.body))
        }
        Statement::If(if_stmt) => {
            let mut total = 1_u64
                .saturating_add(estimate_expression_allocation_count(&if_stmt.condition))
                .saturating_add(estimate_statement_allocation_count(
                    if_stmt.consequent.as_ref(),
                ));
            if let Some(alternate) = &if_stmt.alternate {
                total =
                    total.saturating_add(estimate_statement_allocation_count(alternate.as_ref()));
            }
            total
        }
        Statement::For(for_stmt) => {
            let mut total = 1_u64;
            if let Some(init) = &for_stmt.init {
                total = total.saturating_add(estimate_statement_allocation_count(init.as_ref()));
            }
            if let Some(condition) = &for_stmt.condition {
                total = total.saturating_add(estimate_expression_allocation_count(condition));
            }
            if let Some(update) = &for_stmt.update {
                total = total.saturating_add(estimate_expression_allocation_count(update));
            }
            total.saturating_add(estimate_statement_allocation_count(for_stmt.body.as_ref()))
        }
        Statement::While(while_stmt) => 1_u64
            .saturating_add(estimate_expression_allocation_count(&while_stmt.condition))
            .saturating_add(estimate_statement_allocation_count(
                while_stmt.body.as_ref(),
            )),
        Statement::DoWhile(do_while_stmt) => 1_u64
            .saturating_add(estimate_statement_allocation_count(
                do_while_stmt.body.as_ref(),
            ))
            .saturating_add(estimate_expression_allocation_count(
                &do_while_stmt.condition,
            )),
        Statement::Return(return_stmt) => {
            let mut total = 1_u64;
            if let Some(argument) = &return_stmt.argument {
                total = total.saturating_add(estimate_expression_allocation_count(argument));
            }
            total
        }
        Statement::Throw(throw_stmt) => {
            1_u64.saturating_add(estimate_expression_allocation_count(&throw_stmt.argument))
        }
        Statement::TryCatch(try_catch_stmt) => {
            let mut total = 1_u64.saturating_add(estimate_statement_vec_allocation_count(
                &try_catch_stmt.block.body,
            ));
            if let Some(handler) = &try_catch_stmt.handler {
                total = total.saturating_add(1);
                if handler.parameter.is_some() {
                    total = total.saturating_add(1);
                }
                total = total
                    .saturating_add(estimate_statement_vec_allocation_count(&handler.body.body));
            }
            if let Some(finalizer) = &try_catch_stmt.finalizer {
                total = total.saturating_add(1);
                total =
                    total.saturating_add(estimate_statement_vec_allocation_count(&finalizer.body));
            }
            total
        }
        Statement::Switch(switch_stmt) => {
            let mut total = 1_u64.saturating_add(estimate_expression_allocation_count(
                &switch_stmt.discriminant,
            ));
            for case in &switch_stmt.cases {
                total = total.saturating_add(1);
                if let Some(test) = &case.test {
                    total = total.saturating_add(estimate_expression_allocation_count(test));
                }
                total =
                    total.saturating_add(estimate_statement_vec_allocation_count(&case.consequent));
            }
            total
        }
        Statement::Break(break_stmt) => {
            let mut total = 1_u64;
            if break_stmt.label.is_some() {
                total = total.saturating_add(1);
            }
            total
        }
        Statement::Continue(continue_stmt) => {
            let mut total = 1_u64;
            if continue_stmt.label.is_some() {
                total = total.saturating_add(1);
            }
            total
        }
        Statement::FunctionDeclaration(function_decl) => 2_u64
            .saturating_add(function_decl.params.len() as u64)
            .saturating_add(estimate_statement_vec_allocation_count(
                &function_decl.body.body,
            )),
        Statement::ForIn(for_in_stmt) => 1_u64
            .saturating_add(estimate_expression_allocation_count(&for_in_stmt.object))
            .saturating_add(estimate_statement_allocation_count(
                for_in_stmt.body.as_ref(),
            )),
        Statement::ForOf(for_of_stmt) => 1_u64
            .saturating_add(estimate_expression_allocation_count(&for_of_stmt.iterable))
            .saturating_add(estimate_statement_allocation_count(
                for_of_stmt.body.as_ref(),
            )),
    }
}

fn estimate_statement_vec_allocation_count(statements: &[Statement]) -> u64 {
    statements.iter().fold(0_u64, |acc, statement| {
        acc.saturating_add(estimate_statement_allocation_count(statement))
    })
}

fn estimate_expression_allocation_count(expression: &Expression) -> u64 {
    match expression {
        Expression::Await(inner) => {
            2_u64.saturating_add(estimate_expression_allocation_count(inner.as_ref()))
        }
        _ => 1,
    }
}

fn read_peak_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = fs::read_to_string("/proc/self/status").ok()?;
        let parse_kib = |prefix: &str| -> Option<u64> {
            status.lines().find_map(|line| {
                if !line.starts_with(prefix) {
                    return None;
                }
                let value = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|token| token.parse::<u64>().ok())?;
                Some(value.saturating_mul(1024))
            })
        };
        parse_kib("VmHWM:").or_else(|| parse_kib("VmRSS:"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn quantile(sorted: &[u64], q_percent: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let capped = q_percent.min(100);
    // Use ceil-style indexing so high quantiles (p95/p99) select the upper tail.
    let idx = ((sorted.len() - 1).saturating_mul(capped).saturating_add(99)) / 100;
    sorted[idx]
}

fn ratio_millionths(numerator: u128, denominator: u128) -> u64 {
    if denominator == 0 {
        return 0;
    }
    saturating_u64(numerator.saturating_mul(1_000_000) / denominator)
}

fn saturating_u64(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_engine_seed_is_stable() {
        let a = derive_engine_seed(7, "fixture", "engine");
        let b = derive_engine_seed(7, "fixture", "engine");
        assert_eq!(a, b);
    }

    #[test]
    fn default_config_contains_two_engines() {
        let config = MultiEngineHarnessConfig::with_defaults(9);
        assert_eq!(config.engines.len(), 2);
        assert_eq!(config.engines[0].engine_id, "franken_canonical");
        assert_eq!(config.engines[1].engine_id, "fixture_expected_hash");
    }

    #[test]
    fn validate_config_rejects_single_engine() {
        let mut config = MultiEngineHarnessConfig::with_defaults(1);
        config.engines.pop();
        let err = validate_config(&config).expect_err("single engine should fail");
        assert!(
            err.to_string().contains("at least two engine specs"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_fixture_catalog_rejects_duplicate_ids() {
        let catalog = HarnessFixtureCatalog {
            schema_version: EXPECTED_FIXTURE_SCHEMA_VERSION.to_string(),
            parser_mode: EXPECTED_FIXTURE_PARSER_MODE.to_string(),
            fixtures: vec![
                HarnessFixtureSpec {
                    id: "dup".to_string(),
                    family_id: "f".to_string(),
                    goal: "script".to_string(),
                    source: "x".to_string(),
                    expected_hash: "sha256:a".to_string(),
                },
                HarnessFixtureSpec {
                    id: "dup".to_string(),
                    family_id: "f".to_string(),
                    goal: "script".to_string(),
                    source: "y".to_string(),
                    expected_hash: "sha256:b".to_string(),
                },
            ],
        };

        let err = validate_fixture_catalog(&catalog).expect_err("duplicate ids should fail");
        assert!(err.to_string().contains("appears more than once"));
    }

    // -- Enrichment: serde roundtrips --

    #[test]
    fn harness_engine_kind_serde_roundtrip() {
        for kind in [
            HarnessEngineKind::FrankenCanonical,
            HarnessEngineKind::FixtureExpectedHash,
            HarnessEngineKind::ExternalCommand,
        ] {
            let json = serde_json::to_string(&kind).expect("serialize");
            let restored: HarnessEngineKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(kind, restored);
        }
    }

    #[test]
    fn harness_engine_kind_snake_case_format() {
        let json = serde_json::to_string(&HarnessEngineKind::FrankenCanonical).unwrap();
        assert_eq!(json, "\"franken_canonical\"");
        let json = serde_json::to_string(&HarnessEngineKind::FixtureExpectedHash).unwrap();
        assert_eq!(json, "\"fixture_expected_hash\"");
        let json = serde_json::to_string(&HarnessEngineKind::ExternalCommand).unwrap();
        assert_eq!(json, "\"external_command\"");
    }

    #[test]
    fn harness_engine_spec_serde_roundtrip() {
        let spec = HarnessEngineSpec::franken_canonical("v1.0");
        let json = serde_json::to_string(&spec).expect("serialize");
        let restored: HarnessEngineSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(spec, restored);
    }

    #[test]
    fn harness_engine_spec_external_command_serde() {
        let spec = HarnessEngineSpec {
            engine_id: "ext-1".to_string(),
            display_name: "External Engine".to_string(),
            kind: HarnessEngineKind::ExternalCommand,
            version_pin: "v2".to_string(),
            command: Some("/usr/bin/engine".to_string()),
            args: vec!["--mode".to_string(), "strict".to_string()],
        };
        let json = serde_json::to_string(&spec).expect("serialize");
        let restored: HarnessEngineSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(spec, restored);
    }

    #[test]
    fn engine_outcome_kind_serialize() {
        let hash_json = serde_json::to_string(&EngineOutcomeKind::Hash).unwrap();
        assert_eq!(hash_json, "\"hash\"");
        let error_json = serde_json::to_string(&EngineOutcomeKind::Error).unwrap();
        assert_eq!(error_json, "\"error\"");
    }

    #[test]
    fn engine_run_outcome_serialize() {
        let outcome = EngineRunOutcome {
            kind: EngineOutcomeKind::Hash,
            value: "sha256:abc".to_string(),
            deterministic: true,
            duration_us: 42,
            normalized_ast: None,
            normalized_diagnostic: None,
        };
        let json = serde_json::to_string(&outcome).expect("serialize");
        assert!(json.contains("\"deterministic\":true"));
        assert!(json.contains("\"duration_us\":42"));
    }

    #[test]
    fn engine_fixture_result_serialize() {
        let outcome = EngineRunOutcome {
            kind: EngineOutcomeKind::Hash,
            value: "sha256:abc".to_string(),
            deterministic: true,
            duration_us: 10,
            normalized_ast: None,
            normalized_diagnostic: None,
        };
        let result = EngineFixtureResult {
            engine_id: "e1".to_string(),
            display_name: "Engine One".to_string(),
            version_pin: "v1".to_string(),
            derived_seed: 99,
            first_run: outcome.clone(),
            second_run: outcome,
        };
        let json = serde_json::to_string(&result).expect("serialize");
        assert!(json.contains("\"engine_id\":\"e1\""));
        assert!(json.contains("\"derived_seed\":99"));
    }

    #[test]
    fn multi_engine_harness_summary_serialize() {
        let summary = MultiEngineHarnessSummary {
            total_fixtures: 100,
            equivalent_fixtures: 95,
            divergent_fixtures: 3,
            fixtures_with_nondeterminism: 2,
            drift_minor_fixtures: 1,
            drift_critical_fixtures: 2,
            drift_counts_by_category: BTreeMap::from([
                ("diagnostics".to_string(), 1),
                ("semantic".to_string(), 2),
            ]),
        };
        let json = serde_json::to_string(&summary).expect("serialize");
        assert!(json.contains("\"total_fixtures\":100"));
        assert!(json.contains("\"divergent_fixtures\":3"));
        assert!(json.contains("\"drift_critical_fixtures\":2"));
    }

    #[test]
    fn parser_telemetry_accumulator_computes_quantiles_and_rates() {
        let mut accumulator = ParserTelemetryAccumulator::default();
        accumulator.push(ParserTelemetrySample {
            duration_us: 100,
            source_bytes: 120,
            token_count: 12,
            allocation_estimate: 18,
            peak_rss_bytes: 1024,
        });
        accumulator.push(ParserTelemetrySample {
            duration_us: 200,
            source_bytes: 240,
            token_count: 24,
            allocation_estimate: 30,
            peak_rss_bytes: 4096,
        });
        accumulator.push(ParserTelemetrySample {
            duration_us: 300,
            source_bytes: 360,
            token_count: 36,
            allocation_estimate: 42,
            peak_rss_bytes: 2048,
        });

        let telemetry = accumulator.finalize();
        assert_eq!(telemetry.schema_version, PARSER_TELEMETRY_SCHEMA_VERSION);
        assert_eq!(telemetry.sample_count, 3);
        assert_eq!(telemetry.latency_ns_p50, 200_000);
        assert_eq!(telemetry.latency_ns_p95, 300_000);
        assert_eq!(telemetry.latency_ns_p99, 300_000);
        assert_eq!(telemetry.bytes_per_source_avg, 240);
        assert_eq!(telemetry.tokens_per_source_avg, 24);
        assert_eq!(telemetry.peak_rss_bytes, 4096);
        assert!(telemetry.throughput_sources_per_second_millionths > 0);
        assert!(telemetry.throughput_mib_per_second_millionths > 0);
        assert!(telemetry.ns_per_token_millionths > 0);
        assert!(telemetry.allocs_per_token_millionths > 0);
    }

    #[test]
    fn syntax_tree_allocation_estimate_counts_nested_await() {
        let span = crate::ast::SourceSpan::new(0, 1, 1, 1, 1, 1);
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::Expression(crate::ast::ExpressionStatement {
                expression: Expression::Await(Box::new(Expression::Await(Box::new(
                    Expression::Identifier("value".to_string()),
                )))),
                span: span.clone(),
            })],
            span,
        };

        let allocation_estimate = estimate_syntax_tree_allocation_count(&tree);
        assert!(allocation_estimate >= 6);
    }

    #[test]
    fn fixture_comparison_result_serialize() {
        let outcome = EngineRunOutcome {
            kind: EngineOutcomeKind::Hash,
            value: "sha256:abc".to_string(),
            deterministic: true,
            duration_us: 5,
            normalized_ast: None,
            normalized_diagnostic: None,
        };
        let result = FixtureComparisonResult {
            fixture_id: "f-1".to_string(),
            family_id: "fam-1".to_string(),
            goal: "script".to_string(),
            source_hash: "sha256:src".to_string(),
            equivalent_across_engines: true,
            nondeterministic_engine_count: 0,
            divergence_reason: None,
            drift_classification: None,
            repro_pack: None,
            replay_command: "replay f-1".to_string(),
            engine_results: vec![EngineFixtureResult {
                engine_id: "e1".to_string(),
                display_name: "E1".to_string(),
                version_pin: "v1".to_string(),
                derived_seed: 42,
                first_run: outcome.clone(),
                second_run: outcome,
            }],
        };
        let json = serde_json::to_string(&result).expect("serialize");
        assert!(json.contains("\"equivalent_across_engines\":true"));
    }

    #[test]
    fn harness_fixture_spec_deserialize() {
        let json = r#"{
            "id": "fix-1",
            "family_id": "fam-1",
            "goal": "script",
            "source": "var x = 1;",
            "expected_hash": "sha256:abc"
        }"#;
        let spec: HarnessFixtureSpec = serde_json::from_str(json).expect("deserialize");
        assert_eq!(spec.id, "fix-1");
        assert_eq!(spec.goal, "script");
    }

    #[test]
    fn harness_fixture_catalog_deserialize() {
        let json = format!(
            r#"{{
                "schema_version": "{}",
                "parser_mode": "{}",
                "fixtures": [{{
                    "id": "f-1",
                    "family_id": "fam",
                    "goal": "script",
                    "source": "1+1",
                    "expected_hash": "sha256:x"
                }}]
            }}"#,
            EXPECTED_FIXTURE_SCHEMA_VERSION, EXPECTED_FIXTURE_PARSER_MODE
        );
        let catalog: HarnessFixtureCatalog = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(catalog.fixtures.len(), 1);
        assert_eq!(catalog.fixtures[0].id, "f-1");
    }

    // -- Enrichment: error Display --

    #[test]
    fn error_display_decode_catalog() {
        let e = MultiEngineHarnessError::DecodeCatalog("bad json".to_string());
        assert!(e.to_string().contains("bad json"));
    }

    #[test]
    fn error_display_invalid_catalog_schema() {
        let e = MultiEngineHarnessError::InvalidCatalogSchema {
            expected: "v1".to_string(),
            actual: "v2".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("v2") && s.contains("v1"));
    }

    #[test]
    fn error_display_invalid_catalog_parser_mode() {
        let e = MultiEngineHarnessError::InvalidCatalogParserMode {
            expected: "scalar_reference".to_string(),
            actual: "tree".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("tree") && s.contains("scalar_reference"));
    }

    #[test]
    fn error_display_empty_fixture_catalog() {
        let e = MultiEngineHarnessError::EmptyFixtureCatalog;
        assert!(e.to_string().contains("must not be empty"));
    }

    #[test]
    fn error_display_duplicate_fixture_id() {
        let e = MultiEngineHarnessError::DuplicateFixtureId {
            fixture_id: "dup-1".to_string(),
        };
        assert!(e.to_string().contains("dup-1"));
    }

    #[test]
    fn error_display_unknown_goal() {
        let e = MultiEngineHarnessError::UnknownGoal {
            fixture_id: "f-1".to_string(),
            goal: "banana".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("f-1") && s.contains("banana"));
    }

    #[test]
    fn error_display_fixture_filter_not_found() {
        let e = MultiEngineHarnessError::FixtureFilterNotFound {
            fixture_id: "missing".to_string(),
        };
        assert!(e.to_string().contains("missing"));
    }

    #[test]
    fn error_display_invalid_config() {
        let e = MultiEngineHarnessError::InvalidConfig("bad seed".to_string());
        assert!(e.to_string().contains("bad seed"));
    }

    #[test]
    fn error_display_external_engine() {
        let e = MultiEngineHarnessError::ExternalEngine {
            engine_id: "ext-1".to_string(),
            detail: "timeout".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("ext-1") && s.contains("timeout"));
    }

    #[test]
    fn error_display_normalization() {
        let e = MultiEngineHarnessError::Normalization {
            engine_id: "ext-2".to_string(),
            detail: "bad hash".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("ext-2") && s.contains("bad hash"));
    }

    #[test]
    fn error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(MultiEngineHarnessError::EmptyFixtureCatalog);
        assert!(!e.to_string().is_empty());
    }

    // -- Enrichment: constructors --

    #[test]
    fn franken_canonical_constructor() {
        let spec = HarnessEngineSpec::franken_canonical("v2.0");
        assert_eq!(spec.engine_id, "franken_canonical");
        assert_eq!(spec.kind, HarnessEngineKind::FrankenCanonical);
        assert_eq!(spec.version_pin, "v2.0");
        assert!(spec.command.is_none());
        assert!(spec.args.is_empty());
    }

    #[test]
    fn fixture_expected_hash_constructor() {
        let spec = HarnessEngineSpec::fixture_expected_hash("v3.0");
        assert_eq!(spec.engine_id, "fixture_expected_hash");
        assert_eq!(spec.kind, HarnessEngineKind::FixtureExpectedHash);
        assert_eq!(spec.version_pin, "v3.0");
    }

    #[test]
    fn with_defaults_config_fields() {
        let config = MultiEngineHarnessConfig::with_defaults(42);
        assert_eq!(config.seed, 42);
        assert_eq!(config.fixture_limit, Some(8));
        assert!(config.fixture_id_filter.is_none());
        assert_eq!(config.locale, "C");
        assert_eq!(config.timezone, "UTC");
        assert!(config.trace_id.starts_with("trace-parser-multi-engine-"));
        assert!(
            config
                .decision_id
                .starts_with("decision-parser-multi-engine-")
        );
    }

    #[test]
    fn derive_engine_seed_varies_with_fixture() {
        let a = derive_engine_seed(7, "fixture_a", "engine");
        let b = derive_engine_seed(7, "fixture_b", "engine");
        assert_ne!(a, b);
    }

    #[test]
    fn derive_engine_seed_varies_with_engine() {
        let a = derive_engine_seed(7, "fixture", "engine_a");
        let b = derive_engine_seed(7, "fixture", "engine_b");
        assert_ne!(a, b);
    }

    fn make_engine_result_for_test(
        engine_id: &str,
        kind: EngineOutcomeKind,
        value: &str,
        deterministic: bool,
    ) -> EngineFixtureResult {
        let (normalized_ast, normalized_diagnostic) = match kind {
            EngineOutcomeKind::Hash => (
                Some(NormalizedAstArtifact {
                    schema_version: AST_NORMALIZATION_SCHEMA_VERSION.to_string(),
                    adapter: AstNormalizationAdapter::CanonicalHashPassthroughV1,
                    canonical_hash: value.to_string(),
                }),
                None,
            ),
            EngineOutcomeKind::Error => (None, Some(normalize_diagnostic_code(value))),
        };

        let run = EngineRunOutcome {
            kind: kind.clone(),
            value: value.to_string(),
            deterministic,
            duration_us: 1,
            normalized_ast,
            normalized_diagnostic,
        };
        EngineFixtureResult {
            engine_id: engine_id.to_string(),
            display_name: engine_id.to_string(),
            version_pin: "v1".to_string(),
            derived_seed: 7,
            first_run: run.clone(),
            second_run: run,
        }
    }

    #[test]
    fn classify_fixture_drift_uses_semantic_critical_for_hash_divergence() {
        let results = vec![
            make_engine_result_for_test(
                "engine-a",
                EngineOutcomeKind::Hash,
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                true,
            ),
            make_engine_result_for_test(
                "engine-b",
                EngineOutcomeKind::Hash,
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                true,
            ),
        ];
        let classification = classify_fixture_drift(&results, 0);
        assert_eq!(classification.category, DriftCategory::Semantic);
        assert_eq!(classification.severity, DriftSeverity::Critical);
    }

    #[test]
    fn classify_fixture_drift_prefers_harness_for_nondeterminism() {
        let results = vec![
            make_engine_result_for_test(
                "engine-a",
                EngineOutcomeKind::Error,
                "empty_source",
                false,
            ),
            make_engine_result_for_test(
                "engine-b",
                EngineOutcomeKind::Error,
                "invalid_goal",
                false,
            ),
        ];
        let classification = classify_fixture_drift(&results, 1);
        assert_eq!(classification.category, DriftCategory::Harness);
        assert_eq!(classification.severity, DriftSeverity::Critical);
        assert_eq!(classification.owner_hint, "parser-multi-engine-harness");
    }

    #[test]
    fn classify_fixture_drift_uses_diagnostics_minor_for_error_divergence() {
        let results = vec![
            make_engine_result_for_test("engine-a", EngineOutcomeKind::Error, "empty_source", true),
            make_engine_result_for_test("engine-b", EngineOutcomeKind::Error, "invalid_goal", true),
        ];
        let classification = classify_fixture_drift(&results, 0);
        assert_eq!(classification.category, DriftCategory::Diagnostics);
        assert_eq!(classification.severity, DriftSeverity::Minor);
        assert_eq!(classification.comparator_decision, "drift_minor");
    }

    #[test]
    fn classify_fixture_drift_uses_artifact_for_shape_mismatch() {
        let mut malformed = make_engine_result_for_test(
            "engine-a",
            EngineOutcomeKind::Hash,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            true,
        );
        malformed.first_run.normalized_ast = None;
        let results = vec![
            malformed,
            make_engine_result_for_test(
                "engine-b",
                EngineOutcomeKind::Hash,
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                true,
            ),
        ];
        let classification = classify_fixture_drift(&results, 0);
        assert_eq!(classification.category, DriftCategory::Artifact);
        assert_eq!(classification.severity, DriftSeverity::Critical);
        assert_eq!(classification.comparator_decision, "drift_critical");
    }

    #[test]
    fn canonicalize_sha256_hash_normalizes_case() {
        let value = canonicalize_sha256_hash(
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .expect("hash should normalize");
        assert_eq!(
            value,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn normalize_diagnostic_code_maps_parser_aliases() {
        let normalized = normalize_diagnostic_code("empty_source");
        assert_eq!(
            normalized.taxonomy_version,
            ParseDiagnosticTaxonomy::taxonomy_version()
        );
        assert_eq!(normalized.parse_error_code.as_deref(), Some("empty_source"));
        assert_eq!(normalized.category, "input");
        assert_eq!(normalized.severity, "error");
        assert!(normalized.diagnostic_code.starts_with("FE-PARSER-DIAG-"));
        assert!(normalized.canonical_hash.starts_with("sha256:"));
    }

    #[test]
    fn normalize_diagnostic_code_uses_external_fallback_for_unknown_codes() {
        let normalized = normalize_diagnostic_code("PeerEngineOddity");
        assert_eq!(
            normalized.taxonomy_version,
            EXTERNAL_DIAGNOSTIC_TAXONOMY_VERSION
        );
        assert_eq!(normalized.parse_error_code, None);
        assert_eq!(normalized.category, "system");
        assert_eq!(normalized.severity, "error");
        assert_eq!(
            normalized.diagnostic_code,
            "external::PeerEngineOddity".to_string()
        );
    }

    #[test]
    fn normalize_engine_observation_attaches_ast_or_diagnostic_artifact() {
        let ast = normalize_engine_observation(
            "engine-a",
            &EngineObservation::Hash(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            ),
        )
        .expect("ast normalization");
        assert!(ast.normalized_ast.is_some());
        assert!(ast.normalized_diagnostic.is_none());

        let diagnostic = normalize_engine_observation(
            "engine-b",
            &EngineObservation::Error("EmptySource".to_string()),
        )
        .expect("diagnostic normalization");
        assert!(diagnostic.normalized_ast.is_none());
        assert!(diagnostic.normalized_diagnostic.is_some());
    }

    // -- Enrichment: DriftCategory coverage --

    #[test]
    fn drift_category_serde_roundtrip() {
        for cat in [
            DriftCategory::Semantic,
            DriftCategory::Diagnostics,
            DriftCategory::Harness,
            DriftCategory::Artifact,
        ] {
            let json = serde_json::to_string(&cat).unwrap();
            let back: DriftCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, back);
        }
    }

    #[test]
    fn drift_category_owner_hint_non_empty() {
        for cat in [
            DriftCategory::Semantic,
            DriftCategory::Diagnostics,
            DriftCategory::Harness,
            DriftCategory::Artifact,
        ] {
            assert!(!cat.owner_hint().is_empty());
        }
    }

    #[test]
    fn drift_category_remediation_hint_non_empty() {
        for cat in [
            DriftCategory::Semantic,
            DriftCategory::Diagnostics,
            DriftCategory::Harness,
            DriftCategory::Artifact,
        ] {
            assert!(!cat.remediation_hint().is_empty());
        }
    }

    #[test]
    fn drift_category_owner_hints_all_distinct() {
        let hints: BTreeSet<&str> = [
            DriftCategory::Semantic,
            DriftCategory::Diagnostics,
            DriftCategory::Harness,
            DriftCategory::Artifact,
        ]
        .iter()
        .map(|c| c.owner_hint())
        .collect();
        assert_eq!(
            hints.len(),
            4,
            "all drift categories must have distinct owner hints"
        );
    }

    // -- Enrichment: DriftSeverity coverage --

    #[test]
    fn drift_severity_serde_roundtrip() {
        for sev in [DriftSeverity::Minor, DriftSeverity::Critical] {
            let json = serde_json::to_string(&sev).unwrap();
            let back: DriftSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, back);
        }
    }

    #[test]
    fn drift_severity_comparator_decision_distinct() {
        assert_ne!(
            DriftSeverity::Minor.comparator_decision(),
            DriftSeverity::Critical.comparator_decision()
        );
    }

    // -- Enrichment: DriftClassification serde --

    #[test]
    fn drift_classification_serde_roundtrip() {
        let dc = DriftClassification {
            taxonomy_version: DRIFT_CLASSIFICATION_TAXONOMY_VERSION.to_string(),
            category: DriftCategory::Semantic,
            severity: DriftSeverity::Critical,
            comparator_decision: "drift_critical".to_string(),
            owner_hint: "parser-core".to_string(),
            remediation_hint: "replay".to_string(),
        };
        let json = serde_json::to_string(&dc).unwrap();
        let back: DriftClassification = serde_json::from_str(&json).unwrap();
        assert_eq!(dc, back);
    }

    // -- Enrichment: DriftMinimizationStats serde --

    #[test]
    fn drift_minimization_stats_serde_roundtrip() {
        let stats = DriftMinimizationStats {
            attempted: true,
            rounds: 5,
            candidates_evaluated: 100,
            bytes_removed: 500,
            original_bytes: 1000,
            minimized_bytes: 500,
            fixed_point: true,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let back: DriftMinimizationStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats, back);
    }

    // -- Enrichment: AstNormalizationAdapter / DiagnosticNormalizationAdapter --

    #[test]
    fn ast_normalization_adapter_serde_roundtrip() {
        let adapter = AstNormalizationAdapter::CanonicalHashPassthroughV1;
        let json = serde_json::to_string(&adapter).unwrap();
        let back: AstNormalizationAdapter = serde_json::from_str(&json).unwrap();
        assert_eq!(adapter, back);
    }

    #[test]
    fn diagnostic_normalization_adapter_serde_roundtrip() {
        let adapter = DiagnosticNormalizationAdapter::ParserDiagnosticsTaxonomyV1;
        let json = serde_json::to_string(&adapter).unwrap();
        let back: DiagnosticNormalizationAdapter = serde_json::from_str(&json).unwrap();
        assert_eq!(adapter, back);
    }

    // -- Enrichment: NormalizedAstArtifact / NormalizedDiagnosticArtifact --

    #[test]
    fn normalized_ast_artifact_serde_roundtrip() {
        let artifact = NormalizedAstArtifact {
            schema_version: AST_NORMALIZATION_SCHEMA_VERSION.to_string(),
            adapter: AstNormalizationAdapter::CanonicalHashPassthroughV1,
            canonical_hash: "sha256:abc123".to_string(),
        };
        let json = serde_json::to_string(&artifact).unwrap();
        let back: NormalizedAstArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, back);
    }

    #[test]
    fn normalized_diagnostic_artifact_serde_roundtrip() {
        let artifact = NormalizedDiagnosticArtifact {
            schema_version: DIAGNOSTIC_NORMALIZATION_SCHEMA_VERSION.to_string(),
            taxonomy_version: EXTERNAL_DIAGNOSTIC_TAXONOMY_VERSION.to_string(),
            adapter: DiagnosticNormalizationAdapter::ParserDiagnosticsTaxonomyV1,
            diagnostic_code: "E001".to_string(),
            category: "syntax".to_string(),
            severity: "error".to_string(),
            parse_error_code: Some("unexpected_token".to_string()),
            canonical_hash: "sha256:def456".to_string(),
        };
        let json = serde_json::to_string(&artifact).unwrap();
        let back: NormalizedDiagnosticArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, back);
    }

    // -- Enrichment: EngineNormalizedArtifacts::signature --

    #[test]
    fn engine_normalized_artifacts_signature_both_none() {
        let artifacts = EngineNormalizedArtifacts {
            normalized_ast: None,
            normalized_diagnostic: None,
        };
        assert_eq!(artifacts.signature(), "ast:none;diag:none");
    }

    #[test]
    fn engine_normalized_artifacts_signature_with_ast() {
        let artifacts = EngineNormalizedArtifacts {
            normalized_ast: Some(NormalizedAstArtifact {
                schema_version: "v1".to_string(),
                adapter: AstNormalizationAdapter::CanonicalHashPassthroughV1,
                canonical_hash: "sha256:abc".to_string(),
            }),
            normalized_diagnostic: None,
        };
        assert_eq!(artifacts.signature(), "ast:sha256:abc;diag:none");
    }

    // -- Enrichment: EngineObservation --

    #[test]
    fn engine_observation_hash_kind_and_value() {
        let obs = EngineObservation::Hash("sha256:xyz".to_string());
        assert_eq!(obs.kind(), EngineOutcomeKind::Hash);
        assert_eq!(obs.value(), "sha256:xyz");
    }

    #[test]
    fn engine_observation_error_kind_and_value() {
        let obs = EngineObservation::Error("UnexpectedToken".to_string());
        assert_eq!(obs.kind(), EngineOutcomeKind::Error);
        assert_eq!(obs.value(), "UnexpectedToken");
    }

    // -- Enrichment: DriftReproPack serde --

    #[test]
    fn drift_repro_pack_serde_roundtrip() {
        let pack = DriftReproPack {
            schema_version: DRIFT_REPRO_PACK_SCHEMA_VERSION.to_string(),
            fixture_id: "fix-1".to_string(),
            family_id: "fam-1".to_string(),
            source_hash: "sha256:aaa".to_string(),
            minimized_source: "x".to_string(),
            minimized_source_hash: "sha256:bbb".to_string(),
            replay_command: "cargo test".to_string(),
            drift_classification: DriftClassification {
                taxonomy_version: DRIFT_CLASSIFICATION_TAXONOMY_VERSION.to_string(),
                category: DriftCategory::Semantic,
                severity: DriftSeverity::Critical,
                comparator_decision: "drift_critical".to_string(),
                owner_hint: "parser-core".to_string(),
                remediation_hint: "replay".to_string(),
            },
            minimization: DriftMinimizationStats {
                attempted: false,
                rounds: 0,
                candidates_evaluated: 0,
                bytes_removed: 0,
                original_bytes: 1,
                minimized_bytes: 1,
                fixed_point: false,
            },
            promotion_hooks: vec!["hook-1".to_string()],
            provenance_hash: "sha256:ccc".to_string(),
        };
        let json = serde_json::to_string(&pack).unwrap();
        let back: DriftReproPack = serde_json::from_str(&json).unwrap();
        assert_eq!(pack, back);
    }

    // -- Enrichment: derive_engine_seed determinism --

    #[test]
    fn derive_engine_seed_same_inputs_deterministic() {
        let a = derive_engine_seed(42, "fix-1", "engine-a");
        let b = derive_engine_seed(42, "fix-1", "engine-a");
        assert_eq!(a, b);
    }

    #[test]
    fn derive_engine_seed_different_master_seed() {
        let a = derive_engine_seed(42, "fix-1", "engine-a");
        let b = derive_engine_seed(99, "fix-1", "engine-a");
        assert_ne!(a, b);
    }

    // -- Enrichment: Display uniqueness, defaults, edge cases --

    #[test]
    fn harness_engine_kind_display_all_unique() {
        let kinds = [
            HarnessEngineKind::FrankenCanonical,
            HarnessEngineKind::FixtureExpectedHash,
            HarnessEngineKind::ExternalCommand,
        ];
        let jsons: BTreeSet<String> = kinds
            .iter()
            .map(|k| serde_json::to_string(k).unwrap())
            .collect();
        assert_eq!(jsons.len(), kinds.len());
    }

    #[test]
    fn drift_severity_display_all_unique() {
        let sevs = [DriftSeverity::Minor, DriftSeverity::Critical];
        let displays: BTreeSet<String> = sevs
            .iter()
            .map(|s| s.comparator_decision().to_string())
            .collect();
        assert_eq!(displays.len(), sevs.len());
    }

    #[test]
    fn validate_config_rejects_empty_trace_id() {
        let mut config = MultiEngineHarnessConfig::with_defaults(42);
        config.trace_id = String::new();
        let err = validate_config(&config).expect_err("empty trace_id should fail");
        assert!(
            err.to_string().contains("trace_id"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn canonicalize_sha256_hash_rejects_wrong_prefix() {
        let result = canonicalize_sha256_hash("md5:abc123");
        assert!(result.is_none());
    }

    #[test]
    fn canonicalize_sha256_hash_rejects_wrong_length() {
        let result = canonicalize_sha256_hash("sha256:abc");
        assert!(result.is_none());
    }

    #[test]
    fn multi_engine_harness_summary_serializes_to_json() {
        let summary = MultiEngineHarnessSummary {
            total_fixtures: 50,
            equivalent_fixtures: 48,
            divergent_fixtures: 1,
            fixtures_with_nondeterminism: 1,
            drift_minor_fixtures: 0,
            drift_critical_fixtures: 1,
            drift_counts_by_category: BTreeMap::from([("semantic".to_string(), 1)]),
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"total_fixtures\":50"));
        assert!(json.contains("\"divergent_fixtures\":1"));
    }

    #[test]
    fn multi_engine_harness_error_display_all_unique() {
        let errors: Vec<MultiEngineHarnessError> = vec![
            MultiEngineHarnessError::DecodeCatalog("a".to_string()),
            MultiEngineHarnessError::InvalidCatalogSchema {
                expected: "a".to_string(),
                actual: "b".to_string(),
            },
            MultiEngineHarnessError::InvalidCatalogParserMode {
                expected: "a".to_string(),
                actual: "b".to_string(),
            },
            MultiEngineHarnessError::EmptyFixtureCatalog,
            MultiEngineHarnessError::DuplicateFixtureId {
                fixture_id: "x".to_string(),
            },
            MultiEngineHarnessError::UnknownGoal {
                fixture_id: "x".to_string(),
                goal: "y".to_string(),
            },
            MultiEngineHarnessError::FixtureFilterNotFound {
                fixture_id: "x".to_string(),
            },
            MultiEngineHarnessError::InvalidConfig("z".to_string()),
            MultiEngineHarnessError::ExternalEngine {
                engine_id: "e".to_string(),
                detail: "d".to_string(),
            },
            MultiEngineHarnessError::Normalization {
                engine_id: "e".to_string(),
                detail: "d".to_string(),
            },
        ];
        let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(displays.len(), errors.len());
    }

    #[test]
    fn parser_telemetry_accumulator_empty_finalize_zero_counts() {
        let acc = ParserTelemetryAccumulator::default();
        let telemetry = acc.finalize();
        assert_eq!(telemetry.sample_count, 0);
        assert_eq!(telemetry.latency_ns_p50, 0);
        assert_eq!(telemetry.peak_rss_bytes, 0);
    }

    // -- Enrichment: quantile edge cases --

    #[test]
    fn quantile_single_element_returns_that_element() {
        assert_eq!(quantile(&[42], 50), 42);
        assert_eq!(quantile(&[42], 95), 42);
        assert_eq!(quantile(&[42], 99), 42);
    }

    #[test]
    fn quantile_zero_percent_returns_first() {
        assert_eq!(quantile(&[10, 20, 30, 40, 50], 0), 10);
    }

    #[test]
    fn quantile_over_hundred_capped() {
        let sorted = vec![10, 20, 30, 40, 50];
        let result = quantile(&sorted, 200);
        assert_eq!(result, quantile(&sorted, 100));
    }

    #[test]
    fn quantile_empty_returns_zero() {
        assert_eq!(quantile(&[], 50), 0);
    }

    // -- Enrichment: ratio_millionths --

    #[test]
    fn ratio_millionths_zero_denominator_returns_zero() {
        assert_eq!(ratio_millionths(1_000_000, 0), 0);
    }

    #[test]
    fn ratio_millionths_basic_computation() {
        // 1/2 = 500_000 millionths
        assert_eq!(ratio_millionths(1, 2), 500_000);
        // 1/1 = 1_000_000 millionths
        assert_eq!(ratio_millionths(1, 1), 1_000_000);
    }

    // -- Enrichment: saturating_u64 --

    #[test]
    fn saturating_u64_caps_at_max() {
        assert_eq!(saturating_u64(u128::from(u64::MAX) + 1), u64::MAX);
        assert_eq!(saturating_u64(42), 42);
    }

    // -- Enrichment: split_source_fragments --

    #[test]
    fn split_source_fragments_empty_string() {
        let fragments = split_source_fragments("");
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0], "");
    }

    #[test]
    fn split_source_fragments_single_line_no_newline() {
        let fragments = split_source_fragments("hello");
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0], "hello");
    }

    #[test]
    fn split_source_fragments_multi_line() {
        let fragments = split_source_fragments("a\nb\nc");
        assert_eq!(fragments.len(), 3);
        assert_eq!(fragments[0], "a\n");
        assert_eq!(fragments[1], "b\n");
        assert_eq!(fragments[2], "c");
    }

    // -- Enrichment: join_fragments_without_range --

    #[test]
    fn join_fragments_without_range_removes_middle() {
        let fragments = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert_eq!(join_fragments_without_range(&fragments, 1, 2), "ac");
    }

    #[test]
    fn join_fragments_without_range_removes_first() {
        let fragments = vec!["x".to_string(), "y".to_string(), "z".to_string()];
        assert_eq!(join_fragments_without_range(&fragments, 0, 1), "yz");
    }

    // -- Enrichment: minimize_source_with --

    #[test]
    fn minimize_source_with_empty_returns_unattempted() {
        let result = minimize_source_with("", |_| true);
        assert!(!result.stats.attempted);
        assert_eq!(result.minimized_source, "");
    }

    #[test]
    fn minimize_source_with_whitespace_only_returns_unattempted() {
        let result = minimize_source_with("   \n  ", |_| true);
        assert!(!result.stats.attempted);
    }

    #[test]
    fn minimize_source_with_non_failing_returns_unattempted() {
        let result = minimize_source_with("var x = 1;\nvar y = 2;\n", |_| false);
        assert!(!result.stats.attempted);
        assert_eq!(result.minimized_source, "var x = 1;\nvar y = 2;\n");
    }

    #[test]
    fn minimize_source_with_reduces_when_predicate_holds() {
        // Predicate: fails as long as "var x" is in the source
        let source = "var x = 1;\nvar y = 2;\nvar z = 3;\n";
        let result = minimize_source_with(source, |candidate| candidate.contains("var x"));
        assert!(result.stats.attempted);
        assert!(result.minimized_source.contains("var x"));
        assert!(result.stats.minimized_bytes <= result.stats.original_bytes);
    }

    // -- Enrichment: format_divergence_reason --

    #[test]
    fn format_divergence_reason_multiple_sigs() {
        let mut sigs = BTreeMap::new();
        sigs.insert(
            "ast:sha256:aaa;diag:none".to_string(),
            vec!["engine-a".to_string()],
        );
        sigs.insert(
            "ast:sha256:bbb;diag:none".to_string(),
            vec!["engine-b".to_string()],
        );
        let reason = format_divergence_reason(&sigs, 0);
        assert!(reason.contains("engine-a"));
        assert!(reason.contains("engine-b"));
        assert!(!reason.contains("nondeterministic"));
    }

    #[test]
    fn format_divergence_reason_with_nondeterminism() {
        let sigs = BTreeMap::new();
        let reason = format_divergence_reason(&sigs, 2);
        assert!(reason.contains("nondeterministic_engines=2"));
    }

    // -- Enrichment: validate_config remaining branches --

    #[test]
    fn validate_config_rejects_empty_decision_id() {
        let mut config = MultiEngineHarnessConfig::with_defaults(42);
        config.decision_id = String::new();
        let err = validate_config(&config).expect_err("empty decision_id");
        assert!(err.to_string().contains("decision_id"));
    }

    #[test]
    fn validate_config_rejects_empty_policy_id() {
        let mut config = MultiEngineHarnessConfig::with_defaults(42);
        config.policy_id = String::new();
        let err = validate_config(&config).expect_err("empty policy_id");
        assert!(err.to_string().contains("policy_id"));
    }

    #[test]
    fn validate_config_rejects_fewer_than_two_engines() {
        let mut config = MultiEngineHarnessConfig::with_defaults(42);
        config.engines = vec![HarnessEngineSpec::franken_canonical("v1")];
        let err = validate_config(&config).expect_err("< 2 engines");
        assert!(err.to_string().contains("at least two"));
    }

    #[test]
    fn validate_config_rejects_duplicate_engine_ids() {
        let mut config = MultiEngineHarnessConfig::with_defaults(42);
        config.engines = vec![
            HarnessEngineSpec::franken_canonical("v1"),
            HarnessEngineSpec::franken_canonical("v2"),
        ];
        let err = validate_config(&config).expect_err("duplicate engine_id");
        assert!(err.to_string().contains("more than once"));
    }

    #[test]
    fn validate_config_rejects_empty_engine_id() {
        let mut config = MultiEngineHarnessConfig::with_defaults(42);
        config.engines[0].engine_id = String::new();
        let err = validate_config(&config).expect_err("empty engine_id");
        assert!(err.to_string().contains("engine_id"));
    }

    #[test]
    fn validate_config_rejects_empty_version_pin() {
        let mut config = MultiEngineHarnessConfig::with_defaults(42);
        config.engines[0].version_pin = String::new();
        let err = validate_config(&config).expect_err("empty version_pin");
        assert!(err.to_string().contains("version_pin"));
    }

    #[test]
    fn validate_config_rejects_external_engine_without_command() {
        let mut config = MultiEngineHarnessConfig::with_defaults(42);
        config.engines.push(HarnessEngineSpec {
            engine_id: "ext".to_string(),
            display_name: "External".to_string(),
            kind: HarnessEngineKind::ExternalCommand,
            version_pin: "v1".to_string(),
            command: None,
            args: vec![],
        });
        let err = validate_config(&config).expect_err("external without command");
        assert!(err.to_string().contains("requires command"));
    }

    #[test]
    fn validate_config_accepts_valid_config() {
        let config = MultiEngineHarnessConfig::with_defaults(42);
        validate_config(&config).expect("valid config should pass");
    }

    // -- Enrichment: parse_goal --

    #[test]
    fn parse_goal_script_and_module() {
        assert_eq!(parse_goal("f1", "script").unwrap(), ParseGoal::Script);
        assert_eq!(parse_goal("f1", "module").unwrap(), ParseGoal::Module);
    }

    #[test]
    fn parse_goal_unknown_returns_error() {
        let err = parse_goal("f1", "banana").expect_err("unknown goal");
        assert!(err.to_string().contains("banana"));
    }

    // -- Enrichment: SourceTelemetryStats --

    #[test]
    fn source_telemetry_stats_from_source_basic() {
        let stats = SourceTelemetryStats::from_source("var x = 1;");
        assert_eq!(stats.source_bytes, 10);
        assert!(stats.token_count > 0);
    }

    // -- Enrichment: DriftSignature --

    #[test]
    fn drift_signature_from_fixture_result_none_without_classification() {
        let outcome = EngineRunOutcome {
            kind: EngineOutcomeKind::Hash,
            value: "sha256:abc".to_string(),
            deterministic: true,
            duration_us: 1,
            normalized_ast: None,
            normalized_diagnostic: None,
        };
        let result = FixtureComparisonResult {
            fixture_id: "f1".to_string(),
            family_id: "fam".to_string(),
            goal: "script".to_string(),
            source_hash: "sha256:src".to_string(),
            equivalent_across_engines: true,
            nondeterministic_engine_count: 0,
            divergence_reason: None,
            drift_classification: None,
            repro_pack: None,
            replay_command: "replay".to_string(),
            engine_results: vec![EngineFixtureResult {
                engine_id: "e1".to_string(),
                display_name: "E1".to_string(),
                version_pin: "v1".to_string(),
                derived_seed: 7,
                first_run: outcome.clone(),
                second_run: outcome,
            }],
        };
        assert!(DriftSignature::from_fixture_result(&result).is_none());
    }

    #[test]
    fn drift_signature_from_fixture_result_some_with_classification() {
        let outcome = EngineRunOutcome {
            kind: EngineOutcomeKind::Hash,
            value: "sha256:abc".to_string(),
            deterministic: true,
            duration_us: 1,
            normalized_ast: None,
            normalized_diagnostic: None,
        };
        let result = FixtureComparisonResult {
            fixture_id: "f1".to_string(),
            family_id: "fam".to_string(),
            goal: "script".to_string(),
            source_hash: "sha256:src".to_string(),
            equivalent_across_engines: false,
            nondeterministic_engine_count: 0,
            divergence_reason: Some("diverged".to_string()),
            drift_classification: Some(DriftClassification {
                taxonomy_version: DRIFT_CLASSIFICATION_TAXONOMY_VERSION.to_string(),
                category: DriftCategory::Semantic,
                severity: DriftSeverity::Critical,
                comparator_decision: "drift_critical".to_string(),
                owner_hint: "parser-core".to_string(),
                remediation_hint: "replay".to_string(),
            }),
            repro_pack: None,
            replay_command: "replay".to_string(),
            engine_results: vec![EngineFixtureResult {
                engine_id: "e1".to_string(),
                display_name: "E1".to_string(),
                version_pin: "v1".to_string(),
                derived_seed: 7,
                first_run: outcome.clone(),
                second_run: outcome,
            }],
        };
        let sig = DriftSignature::from_fixture_result(&result).expect("should be Some");
        assert_eq!(sig.classification.category, DriftCategory::Semantic);
        assert_eq!(sig.engine_kinds, vec![EngineOutcomeKind::Hash]);
    }

    // -- Enrichment: EngineNormalizedArtifacts signature with diagnostic --

    #[test]
    fn engine_normalized_artifacts_signature_with_diagnostic() {
        let artifacts = EngineNormalizedArtifacts {
            normalized_ast: None,
            normalized_diagnostic: Some(NormalizedDiagnosticArtifact {
                schema_version: "v1".to_string(),
                taxonomy_version: "tv1".to_string(),
                adapter: DiagnosticNormalizationAdapter::ParserDiagnosticsTaxonomyV1,
                diagnostic_code: "E001".to_string(),
                category: "syntax".to_string(),
                severity: "error".to_string(),
                parse_error_code: None,
                canonical_hash: "sha256:diag123".to_string(),
            }),
        };
        assert_eq!(artifacts.signature(), "ast:none;diag:sha256:diag123");
    }

    #[test]
    fn engine_normalized_artifacts_signature_both_present() {
        let artifacts = EngineNormalizedArtifacts {
            normalized_ast: Some(NormalizedAstArtifact {
                schema_version: "v1".to_string(),
                adapter: AstNormalizationAdapter::CanonicalHashPassthroughV1,
                canonical_hash: "sha256:ast1".to_string(),
            }),
            normalized_diagnostic: Some(NormalizedDiagnosticArtifact {
                schema_version: "v1".to_string(),
                taxonomy_version: "tv1".to_string(),
                adapter: DiagnosticNormalizationAdapter::ParserDiagnosticsTaxonomyV1,
                diagnostic_code: "E001".to_string(),
                category: "syntax".to_string(),
                severity: "error".to_string(),
                parse_error_code: None,
                canonical_hash: "sha256:diag1".to_string(),
            }),
        };
        assert_eq!(artifacts.signature(), "ast:sha256:ast1;diag:sha256:diag1");
    }

    // -- Enrichment: parse_error_code_alias --

    #[test]
    fn parse_error_code_alias_all_snake_case_variants() {
        assert_eq!(
            parse_error_code_alias("empty_source"),
            Some(ParseErrorCode::EmptySource)
        );
        assert_eq!(
            parse_error_code_alias("invalid_goal"),
            Some(ParseErrorCode::InvalidGoal)
        );
        assert_eq!(
            parse_error_code_alias("unsupported_syntax"),
            Some(ParseErrorCode::UnsupportedSyntax)
        );
        assert_eq!(
            parse_error_code_alias("io_read_failed"),
            Some(ParseErrorCode::IoReadFailed)
        );
        assert_eq!(
            parse_error_code_alias("invalid_utf8"),
            Some(ParseErrorCode::InvalidUtf8)
        );
        assert_eq!(
            parse_error_code_alias("source_too_large"),
            Some(ParseErrorCode::SourceTooLarge)
        );
        assert_eq!(
            parse_error_code_alias("budget_exceeded"),
            Some(ParseErrorCode::BudgetExceeded)
        );
    }

    #[test]
    fn parse_error_code_alias_all_camel_case_variants() {
        assert_eq!(
            parse_error_code_alias("emptysource"),
            Some(ParseErrorCode::EmptySource)
        );
        assert_eq!(
            parse_error_code_alias("invalidgoal"),
            Some(ParseErrorCode::InvalidGoal)
        );
        assert_eq!(
            parse_error_code_alias("unsupportedsyntax"),
            Some(ParseErrorCode::UnsupportedSyntax)
        );
        assert_eq!(
            parse_error_code_alias("ioreadfailed"),
            Some(ParseErrorCode::IoReadFailed)
        );
        assert_eq!(
            parse_error_code_alias("invalidutf8"),
            Some(ParseErrorCode::InvalidUtf8)
        );
        assert_eq!(
            parse_error_code_alias("sourcetoolarge"),
            Some(ParseErrorCode::SourceTooLarge)
        );
        assert_eq!(
            parse_error_code_alias("budgetexceeded"),
            Some(ParseErrorCode::BudgetExceeded)
        );
    }

    #[test]
    fn parse_error_code_alias_unknown_returns_none() {
        assert!(parse_error_code_alias("totally_unknown").is_none());
        assert!(parse_error_code_alias("").is_none());
    }

    // -- Enrichment: classify_fixture_drift edge cases --

    #[test]
    fn classify_fixture_drift_empty_results_uses_artifact_critical() {
        let classification = classify_fixture_drift(&[], 0);
        assert_eq!(classification.category, DriftCategory::Artifact);
        assert_eq!(classification.severity, DriftSeverity::Critical);
    }

    #[test]
    fn classify_fixture_drift_mixed_hash_and_error_is_semantic_critical() {
        let results = vec![
            make_engine_result_for_test(
                "engine-a",
                EngineOutcomeKind::Hash,
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                true,
            ),
            make_engine_result_for_test("engine-b", EngineOutcomeKind::Error, "empty_source", true),
        ];
        let classification = classify_fixture_drift(&results, 0);
        assert_eq!(classification.category, DriftCategory::Semantic);
        assert_eq!(classification.severity, DriftSeverity::Critical);
    }

    // -- Enrichment: run_outcome_shape_matches_kind --

    #[test]
    fn run_outcome_shape_matches_kind_hash_with_ast_is_valid() {
        let run = EngineRunOutcome {
            kind: EngineOutcomeKind::Hash,
            value: "sha256:abc".to_string(),
            deterministic: true,
            duration_us: 1,
            normalized_ast: Some(NormalizedAstArtifact {
                schema_version: "v1".to_string(),
                adapter: AstNormalizationAdapter::CanonicalHashPassthroughV1,
                canonical_hash: "sha256:abc".to_string(),
            }),
            normalized_diagnostic: None,
        };
        assert!(run_outcome_shape_matches_kind(&run));
    }

    #[test]
    fn run_outcome_shape_matches_kind_hash_without_ast_is_invalid() {
        let run = EngineRunOutcome {
            kind: EngineOutcomeKind::Hash,
            value: "sha256:abc".to_string(),
            deterministic: true,
            duration_us: 1,
            normalized_ast: None,
            normalized_diagnostic: None,
        };
        assert!(!run_outcome_shape_matches_kind(&run));
    }

    #[test]
    fn run_outcome_shape_matches_kind_error_with_diagnostic_is_valid() {
        let run = EngineRunOutcome {
            kind: EngineOutcomeKind::Error,
            value: "empty_source".to_string(),
            deterministic: true,
            duration_us: 1,
            normalized_ast: None,
            normalized_diagnostic: Some(NormalizedDiagnosticArtifact {
                schema_version: "v1".to_string(),
                taxonomy_version: "tv1".to_string(),
                adapter: DiagnosticNormalizationAdapter::ParserDiagnosticsTaxonomyV1,
                diagnostic_code: "E001".to_string(),
                category: "syntax".to_string(),
                severity: "error".to_string(),
                parse_error_code: None,
                canonical_hash: "sha256:diag".to_string(),
            }),
        };
        assert!(run_outcome_shape_matches_kind(&run));
    }

    #[test]
    fn run_outcome_shape_matches_kind_error_without_diagnostic_is_invalid() {
        let run = EngineRunOutcome {
            kind: EngineOutcomeKind::Error,
            value: "empty_source".to_string(),
            deterministic: true,
            duration_us: 1,
            normalized_ast: None,
            normalized_diagnostic: None,
        };
        assert!(!run_outcome_shape_matches_kind(&run));
    }

    // -- Enrichment: hash_bytes determinism --

    #[test]
    fn hash_bytes_deterministic() {
        let a = hash_bytes(b"hello world");
        let b = hash_bytes(b"hello world");
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
        assert_eq!(a.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn hash_bytes_different_inputs_differ() {
        assert_ne!(hash_bytes(b"a"), hash_bytes(b"b"));
    }

    // -- Enrichment: estimate_lexical_token_count --

    #[test]
    fn estimate_lexical_token_count_basic() {
        let count = estimate_lexical_token_count("var x = 1;");
        assert!(count > 0);
    }

    #[test]
    fn estimate_lexical_token_count_empty() {
        let count = estimate_lexical_token_count("");
        // Empty source may produce 0 tokens
        assert!(count <= 1);
    }

    // -- Enrichment: ParserTelemetrySummary serde --

    #[test]
    fn parser_telemetry_summary_serializes() {
        let summary = ParserTelemetrySummary {
            schema_version: PARSER_TELEMETRY_SCHEMA_VERSION.to_string(),
            sample_count: 5,
            throughput_sources_per_second_millionths: 1_000_000,
            throughput_mib_per_second_millionths: 500_000,
            latency_ns_p50: 100,
            latency_ns_p95: 200,
            latency_ns_p99: 300,
            ns_per_token_millionths: 50_000,
            allocs_per_token_millionths: 10_000,
            bytes_per_source_avg: 100,
            tokens_per_source_avg: 20,
            peak_rss_bytes: 4096,
        };
        let json = serde_json::to_string(&summary).expect("serialize");
        assert!(json.contains("\"sample_count\":5"));
        assert!(json.contains("\"peak_rss_bytes\":4096"));
    }

    // -- Enrichment: ExternalCommandRequest serde roundtrip --

    #[test]
    fn external_command_request_serde_roundtrip() {
        let request = ExternalCommandRequest {
            goal: "script".to_string(),
            source: "var x = 1;".to_string(),
            seed: 42,
            trace_id: "trace-1".to_string(),
            decision_id: "decision-1".to_string(),
            policy_id: "policy-1".to_string(),
            engine_id: "ext-1".to_string(),
        };
        let json = serde_json::to_string(&request).expect("serialize");
        let restored: ExternalCommandRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.goal, "script");
        assert_eq!(restored.seed, 42);
        assert_eq!(restored.engine_id, "ext-1");
    }

    // -- Enrichment: normalize_ast_hash --

    #[test]
    fn normalize_ast_hash_valid_produces_artifact() {
        let artifact = normalize_ast_hash(
            "engine-a",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("valid hash");
        assert_eq!(
            artifact.canonical_hash,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            artifact.adapter,
            AstNormalizationAdapter::CanonicalHashPassthroughV1
        );
    }

    #[test]
    fn normalize_ast_hash_invalid_returns_error() {
        let err = normalize_ast_hash("engine-a", "md5:abc").expect_err("invalid hash");
        assert!(err.to_string().contains("engine-a"));
        assert!(err.to_string().contains("invalid AST hash"));
    }

    // -- Enrichment: has_artifact_shape_mismatch --

    #[test]
    fn has_artifact_shape_mismatch_all_valid_returns_false() {
        let results = vec![make_engine_result_for_test(
            "engine-a",
            EngineOutcomeKind::Hash,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            true,
        )];
        assert!(!has_artifact_shape_mismatch(&results));
    }

    #[test]
    fn has_artifact_shape_mismatch_missing_ast_returns_true() {
        let mut result = make_engine_result_for_test(
            "engine-a",
            EngineOutcomeKind::Hash,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            true,
        );
        result.first_run.normalized_ast = None;
        assert!(has_artifact_shape_mismatch(&[result]));
    }

    // -- Enrichment: build_drift_classification --

    #[test]
    fn build_drift_classification_populates_all_fields() {
        let dc = build_drift_classification(DriftCategory::Diagnostics, DriftSeverity::Minor);
        assert_eq!(dc.taxonomy_version, DRIFT_CLASSIFICATION_TAXONOMY_VERSION);
        assert_eq!(dc.category, DriftCategory::Diagnostics);
        assert_eq!(dc.severity, DriftSeverity::Minor);
        assert_eq!(dc.comparator_decision, "drift_minor");
        assert!(!dc.owner_hint.is_empty());
        assert!(!dc.remediation_hint.is_empty());
    }

    #[test]
    fn auto_bead_id_from_fingerprint_uses_sha256_prefix() {
        let bead = auto_bead_id_from_fingerprint(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        assert_eq!(bead, "bd-auto-01234567");
    }

    #[test]
    fn derive_drift_governance_actions_is_deterministic_and_owner_routed() {
        let classification =
            build_drift_classification(DriftCategory::Semantic, DriftSeverity::Critical);
        let repro_pack = DriftReproPack {
            schema_version: DRIFT_REPRO_PACK_SCHEMA_VERSION.to_string(),
            fixture_id: "fixture-a".to_string(),
            family_id: "family-a".to_string(),
            source_hash: "sha256:source".to_string(),
            minimized_source: "export const x = 1;\n".to_string(),
            minimized_source_hash: "sha256:minimized".to_string(),
            replay_command: "cargo run -- fixture-a".to_string(),
            drift_classification: classification.clone(),
            minimization: DriftMinimizationStats {
                attempted: true,
                rounds: 1,
                candidates_evaluated: 1,
                bytes_removed: 0,
                original_bytes: 10,
                minimized_bytes: 10,
                fixed_point: true,
            },
            promotion_hooks: vec![],
            provenance_hash:
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
        };

        let fixture = FixtureComparisonResult {
            fixture_id: "fixture-a".to_string(),
            family_id: "family-a".to_string(),
            goal: "script".to_string(),
            source_hash: "sha256:source".to_string(),
            equivalent_across_engines: false,
            nondeterministic_engine_count: 0,
            divergence_reason: Some("semantic drift".to_string()),
            drift_classification: Some(classification.clone()),
            repro_pack: Some(repro_pack.clone()),
            replay_command: "cargo run -- fixture-a".to_string(),
            engine_results: vec![],
        };
        let duplicate_fingerprint_fixture = FixtureComparisonResult {
            fixture_id: "fixture-b".to_string(),
            family_id: "family-b".to_string(),
            goal: "script".to_string(),
            source_hash: "sha256:source-b".to_string(),
            equivalent_across_engines: false,
            nondeterministic_engine_count: 0,
            divergence_reason: Some("semantic drift".to_string()),
            drift_classification: Some(classification),
            repro_pack: Some(DriftReproPack {
                fixture_id: "fixture-b".to_string(),
                family_id: "family-b".to_string(),
                source_hash: "sha256:source-b".to_string(),
                minimized_source: "export const y = 1;\n".to_string(),
                minimized_source_hash: "sha256:minimized-b".to_string(),
                replay_command: "cargo run -- fixture-b".to_string(),
                provenance_hash: repro_pack.provenance_hash.clone(),
                ..repro_pack.clone()
            }),
            replay_command: "cargo run -- fixture-b".to_string(),
            engine_results: vec![],
        };

        let report = MultiEngineHarnessReport {
            schema_version: REPORT_SCHEMA_VERSION.to_string(),
            generated_at_utc: "2026-03-01T00:00:00Z".to_string(),
            run_id: "sha256:run".to_string(),
            trace_id: "trace-id".to_string(),
            decision_id: "decision-id".to_string(),
            policy_id: "policy-id".to_string(),
            fixture_catalog_path: "fixtures.json".to_string(),
            fixture_catalog_hash: "sha256:catalog".to_string(),
            parser_mode: EXPECTED_FIXTURE_PARSER_MODE.to_string(),
            seed: 7,
            locale: "C".to_string(),
            timezone: "UTC".to_string(),
            fixture_count: 2,
            engine_specs: vec![
                HarnessEngineSpec::franken_canonical("workspace"),
                HarnessEngineSpec::fixture_expected_hash("baseline"),
            ],
            parser_telemetry: ParserTelemetrySummary {
                schema_version: PARSER_TELEMETRY_SCHEMA_VERSION.to_string(),
                sample_count: 0,
                throughput_sources_per_second_millionths: 0,
                throughput_mib_per_second_millionths: 0,
                latency_ns_p50: 0,
                latency_ns_p95: 0,
                latency_ns_p99: 0,
                ns_per_token_millionths: 0,
                allocs_per_token_millionths: 0,
                bytes_per_source_avg: 0,
                tokens_per_source_avg: 0,
                peak_rss_bytes: 0,
            },
            summary: MultiEngineHarnessSummary {
                total_fixtures: 2,
                equivalent_fixtures: 0,
                divergent_fixtures: 2,
                fixtures_with_nondeterminism: 0,
                drift_minor_fixtures: 0,
                drift_critical_fixtures: 2,
                drift_counts_by_category: BTreeMap::from([("semantic".to_string(), 2)]),
            },
            fixture_results: vec![fixture, duplicate_fingerprint_fixture],
        };

        let left = derive_drift_governance_actions(&report);
        let right = derive_drift_governance_actions(&report);
        assert_eq!(left, right);
        assert_eq!(left.len(), 1);

        let action = left.first().expect("action should exist");
        assert_eq!(
            action.schema_version,
            DRIFT_GOVERNANCE_ACTION_SCHEMA_VERSION
        );
        assert_eq!(action.action, GovernanceActionKind::Create);
        assert_eq!(action.bead_id, "bd-auto-01234567");
        assert_eq!(action.category, DriftCategory::Semantic);
        assert_eq!(action.severity, DriftSeverity::Critical);
        assert_eq!(action.owner_hint, "parser-core");
        assert!(action.fingerprint.starts_with("sha256:"));
    }

    #[test]
    fn has_critical_drift_checks_report_summary_and_classifications() {
        let critical_report = MultiEngineHarnessReport {
            schema_version: REPORT_SCHEMA_VERSION.to_string(),
            generated_at_utc: "2026-03-01T00:00:00Z".to_string(),
            run_id: "sha256:run".to_string(),
            trace_id: "trace-id".to_string(),
            decision_id: "decision-id".to_string(),
            policy_id: "policy-id".to_string(),
            fixture_catalog_path: "fixtures.json".to_string(),
            fixture_catalog_hash: "sha256:catalog".to_string(),
            parser_mode: EXPECTED_FIXTURE_PARSER_MODE.to_string(),
            seed: 1,
            locale: "C".to_string(),
            timezone: "UTC".to_string(),
            fixture_count: 0,
            engine_specs: vec![
                HarnessEngineSpec::franken_canonical("workspace"),
                HarnessEngineSpec::fixture_expected_hash("baseline"),
            ],
            parser_telemetry: ParserTelemetrySummary {
                schema_version: PARSER_TELEMETRY_SCHEMA_VERSION.to_string(),
                sample_count: 0,
                throughput_sources_per_second_millionths: 0,
                throughput_mib_per_second_millionths: 0,
                latency_ns_p50: 0,
                latency_ns_p95: 0,
                latency_ns_p99: 0,
                ns_per_token_millionths: 0,
                allocs_per_token_millionths: 0,
                bytes_per_source_avg: 0,
                tokens_per_source_avg: 0,
                peak_rss_bytes: 0,
            },
            summary: MultiEngineHarnessSummary {
                total_fixtures: 0,
                equivalent_fixtures: 0,
                divergent_fixtures: 0,
                fixtures_with_nondeterminism: 0,
                drift_minor_fixtures: 0,
                drift_critical_fixtures: 1,
                drift_counts_by_category: BTreeMap::new(),
            },
            fixture_results: vec![],
        };
        assert!(has_critical_drift(&critical_report));

        let no_critical_report = MultiEngineHarnessReport {
            summary: MultiEngineHarnessSummary {
                drift_critical_fixtures: 0,
                ..critical_report.summary.clone()
            },
            ..critical_report
        };
        assert!(!has_critical_drift(&no_critical_report));
    }
}
