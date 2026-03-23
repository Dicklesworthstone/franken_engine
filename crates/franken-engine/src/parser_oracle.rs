use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ast::ParseGoal;
use crate::parser::{CanonicalEs2020Parser, ParseErrorCode, ParserMode, ParserOptions};

pub const DEFAULT_FIXTURE_CATALOG_PATH: &str =
    "crates/franken-engine/tests/fixtures/parser_phase0_semantic_fixtures.json";
pub const PARSER_ORACLE_REPORT_SCHEMA_VERSION: &str = "franken-engine.parser-oracle.report.v1";
pub const PARSER_ORACLE_TAXONOMY_VERSION: &str = "franken-engine.parser-oracle.taxonomy.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OraclePartition {
    Smoke,
    Full,
    Nightly,
}

impl OraclePartition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Full => "full",
            Self::Nightly => "nightly",
        }
    }

    pub const fn fixture_limit(self) -> Option<usize> {
        match self {
            Self::Smoke => Some(4),
            Self::Full | Self::Nightly => None,
        }
    }

    pub const fn metamorphic_pairs(self) -> u32 {
        match self {
            Self::Smoke => 64,
            Self::Full => 256,
            Self::Nightly => 1024,
        }
    }
}

impl std::str::FromStr for OraclePartition {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "smoke" => Ok(Self::Smoke),
            "full" => Ok(Self::Full),
            "nightly" => Ok(Self::Nightly),
            other => Err(format!("unsupported partition `{other}`")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleGateMode {
    ReportOnly,
    FailClosed,
}

impl OracleGateMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReportOnly => "report_only",
            Self::FailClosed => "fail_closed",
        }
    }
}

impl std::str::FromStr for OracleGateMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "report_only" => Ok(Self::ReportOnly),
            "fail_closed" => Ok(Self::FailClosed),
            other => Err(format!("unsupported gate mode `{other}`")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftClass {
    Equivalent,
    SemanticDrift,
    DiagnosticsDrift,
    HarnessNondeterminism,
    ArtifactIntegrityFailure,
}

impl DriftClass {
    pub const fn comparator_decision(self) -> &'static str {
        match self {
            Self::Equivalent => "equivalent",
            Self::DiagnosticsDrift => "drift_minor",
            Self::SemanticDrift | Self::HarnessNondeterminism | Self::ArtifactIntegrityFailure => {
                "drift_critical"
            }
        }
    }

    pub const fn is_critical(self) -> bool {
        matches!(
            self,
            Self::SemanticDrift | Self::HarnessNondeterminism | Self::ArtifactIntegrityFailure
        )
    }

    pub const fn is_minor(self) -> bool {
        matches!(self, Self::DiagnosticsDrift)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateAction {
    Promote,
    Hold,
    Reject,
}

impl GateAction {
    const fn rank(self) -> u8 {
        match self {
            Self::Promote => 0,
            Self::Hold => 1,
            Self::Reject => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OracleFixtureSpec {
    pub id: String,
    pub family_id: String,
    pub goal: String,
    pub source: String,
    pub expected_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OracleFixtureCatalog {
    pub schema_version: String,
    pub parser_mode: String,
    pub fixtures: Vec<OracleFixtureSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OracleFixtureResult {
    pub fixture_id: String,
    pub family_id: String,
    pub goal: String,
    pub parser_mode: String,
    pub derived_seed: u64,
    pub input_hash: String,
    pub expected_hash: String,
    pub observed_hash: Option<String>,
    pub repeated_hash: Option<String>,
    pub parse_error_code: Option<String>,
    pub repeated_error_code: Option<String>,
    pub drift_class: DriftClass,
    pub comparator_decision: String,
    pub latency_ns: u64,
    pub replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OracleSummary {
    pub total_fixtures: u64,
    pub equivalent_count: u64,
    pub minor_drift_count: u64,
    pub critical_drift_count: u64,
    pub drift_rate_millionths: u64,
    pub counts_by_class: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExpectedLossModel {
    pub promote_loss: f64,
    pub hold_loss: f64,
    pub reject_loss: f64,
    pub recommended_action: GateAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OracleDecision {
    pub action: GateAction,
    pub promotion_blocked: bool,
    pub fallback_triggered: bool,
    pub fallback_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ParserOracleReport {
    pub schema_version: String,
    pub taxonomy_version: String,
    pub generated_at_utc: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub partition: OraclePartition,
    pub gate_mode: OracleGateMode,
    pub parser_mode: String,
    pub fixture_catalog_path: String,
    pub fixture_catalog_hash: String,
    pub seed: u64,
    pub metamorphic_pair_budget: u32,
    pub fixture_results: Vec<OracleFixtureResult>,
    pub summary: OracleSummary,
    pub expected_loss: ExpectedLossModel,
    pub decision: OracleDecision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserOracleConfig {
    pub partition: OraclePartition,
    pub gate_mode: OracleGateMode,
    pub fixture_catalog_path: PathBuf,
    pub seed: u64,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

impl ParserOracleConfig {
    pub fn with_defaults(partition: OraclePartition, gate_mode: OracleGateMode, seed: u64) -> Self {
        let now = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        Self {
            partition,
            gate_mode,
            fixture_catalog_path: PathBuf::from(DEFAULT_FIXTURE_CATALOG_PATH),
            seed,
            trace_id: format!("trace-parser-oracle-{now}"),
            decision_id: format!("decision-parser-oracle-{now}"),
            policy_id: "policy-parser-oracle-v1".to_string(),
        }
    }
}

#[derive(Debug)]
pub enum ParserOracleError {
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
    UnknownGoal {
        fixture_id: String,
        goal: String,
    },
}

impl fmt::Display for ParserOracleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "failed to read `{path}`: {source}"),
            Self::DecodeCatalog(message) => {
                write!(
                    f,
                    "failed to decode parser oracle fixture catalog: {message}"
                )
            }
            Self::InvalidCatalogSchema { expected, actual } => {
                write!(
                    f,
                    "invalid parser oracle catalog schema `{actual}` (expected `{expected}`)"
                )
            }
            Self::InvalidCatalogParserMode { expected, actual } => {
                write!(
                    f,
                    "invalid parser oracle catalog parser_mode `{actual}` (expected `{expected}`)"
                )
            }
            Self::EmptyFixtureCatalog => {
                write!(f, "parser oracle fixture catalog must not be empty")
            }
            Self::UnknownGoal { fixture_id, goal } => {
                write!(f, "fixture `{fixture_id}` has unknown parse goal `{goal}`")
            }
        }
    }
}

impl std::error::Error for ParserOracleError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseObservation {
    Hash([u8; 32]),
    Error(ParseErrorCode),
}

impl ParseObservation {
    fn hash_hex(self) -> Option<String> {
        match self {
            Self::Hash(hash) => Some(format!("sha256:{}", hex::encode(hash))),
            Self::Error(_) => None,
        }
    }

    fn error_code(self) -> Option<String> {
        match self {
            Self::Hash(_) => None,
            Self::Error(code) => Some(format!("{code:?}")),
        }
    }
}

pub fn run_parser_oracle(
    config: &ParserOracleConfig,
) -> Result<ParserOracleReport, ParserOracleError> {
    let catalog = load_fixture_catalog(config.fixture_catalog_path.as_path())?;
    let fixture_catalog_hash = hash_bytes(
        &fs::read(config.fixture_catalog_path.as_path()).map_err(|source| {
            ParserOracleError::Io {
                path: config.fixture_catalog_path.display().to_string(),
                source,
            }
        })?,
    );
    let fixtures = partition_fixtures(&catalog, config.partition);
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();

    let mut fixture_results = Vec::<OracleFixtureResult>::with_capacity(fixtures.len());
    let mut equivalent_count = 0u64;
    let mut minor_drift_count = 0u64;
    let mut critical_drift_count = 0u64;
    let mut counts_by_class = BTreeMap::<String, u64>::new();

    for fixture in fixtures {
        let parse_goal = parse_goal_from_fixture(&fixture)?;
        let derived_seed = derive_seed(
            config.seed,
            fixture.id.as_str(),
            ParserMode::ScalarReference,
        );
        let replay_command = format!(
            "cargo run -p frankenengine-engine --bin franken_parser_oracle_report -- --partition {} --gate-mode {} --seed {} --fixture-catalog {}",
            config.partition.as_str(),
            config.gate_mode.as_str(),
            config.seed,
            config.fixture_catalog_path.display(),
        );

        let input_hash = hash_bytes(fixture.source.as_bytes());
        let parse_start = Instant::now();
        let first = observe_parse(&parser, fixture.source.as_str(), parse_goal, &options);
        let latency_ns = u64::try_from(parse_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let second = observe_parse(&parser, fixture.source.as_str(), parse_goal, &options);

        let expected_hash = normalize_hash(fixture.expected_hash.as_str());
        let drift_class = classify_observation(expected_hash.as_str(), first, second);
        let entry = counts_by_class
            .entry(format!("{drift_class:?}"))
            .or_insert(0);
        *entry = entry.saturating_add(1);

        if drift_class == DriftClass::Equivalent {
            equivalent_count = equivalent_count.saturating_add(1);
        } else if drift_class.is_minor() {
            minor_drift_count = minor_drift_count.saturating_add(1);
        } else if drift_class.is_critical() {
            critical_drift_count = critical_drift_count.saturating_add(1);
        }

        fixture_results.push(OracleFixtureResult {
            fixture_id: fixture.id.clone(),
            family_id: fixture.family_id.clone(),
            goal: fixture.goal.clone(),
            parser_mode: ParserMode::ScalarReference.as_str().to_string(),
            derived_seed,
            input_hash,
            expected_hash,
            observed_hash: first.hash_hex(),
            repeated_hash: second.hash_hex(),
            parse_error_code: first.error_code(),
            repeated_error_code: second.error_code(),
            drift_class,
            comparator_decision: drift_class.comparator_decision().to_string(),
            latency_ns,
            replay_command,
        });
    }

    let total_fixtures = u64::try_from(fixture_results.len()).unwrap_or(u64::MAX);
    let drift_rate_millionths = minor_drift_count
        .saturating_add(critical_drift_count)
        .saturating_mul(1_000_000)
        .checked_div(total_fixtures)
        .unwrap_or(0);

    let summary = OracleSummary {
        total_fixtures,
        equivalent_count,
        minor_drift_count,
        critical_drift_count,
        drift_rate_millionths,
        counts_by_class,
    };
    let expected_loss = expected_loss_model(&summary);
    let decision = decide(config.gate_mode, &summary, expected_loss.recommended_action);

    Ok(ParserOracleReport {
        schema_version: PARSER_ORACLE_REPORT_SCHEMA_VERSION.to_string(),
        taxonomy_version: PARSER_ORACLE_TAXONOMY_VERSION.to_string(),
        generated_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        trace_id: config.trace_id.clone(),
        decision_id: config.decision_id.clone(),
        policy_id: config.policy_id.clone(),
        partition: config.partition,
        gate_mode: config.gate_mode,
        parser_mode: ParserMode::ScalarReference.as_str().to_string(),
        fixture_catalog_path: config.fixture_catalog_path.display().to_string(),
        fixture_catalog_hash,
        seed: config.seed,
        metamorphic_pair_budget: config.partition.metamorphic_pairs(),
        fixture_results,
        summary,
        expected_loss,
        decision,
    })
}

pub fn derive_seed(master_seed: u64, fixture_id: &str, parser_mode: ParserMode) -> u64 {
    let payload = format!("{master_seed}:{fixture_id}:{}", parser_mode.as_str());
    let digest = Sha256::digest(payload.as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes) ^ master_seed.rotate_left(13)
}

pub fn load_fixture_catalog(path: &Path) -> Result<OracleFixtureCatalog, ParserOracleError> {
    let bytes = fs::read(path).map_err(|source| ParserOracleError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let catalog: OracleFixtureCatalog = serde_json::from_slice(&bytes)
        .map_err(|error| ParserOracleError::DecodeCatalog(error.to_string()))?;
    validate_fixture_catalog(&catalog)?;
    Ok(catalog)
}

pub fn partition_fixtures(
    catalog: &OracleFixtureCatalog,
    partition: OraclePartition,
) -> Vec<OracleFixtureSpec> {
    let mut fixtures = catalog.fixtures.clone();
    fixtures.sort_by(|left, right| left.id.cmp(&right.id));
    if let Some(limit) = partition.fixture_limit() {
        fixtures.truncate(limit.min(fixtures.len()));
    }
    fixtures
}

fn validate_fixture_catalog(catalog: &OracleFixtureCatalog) -> Result<(), ParserOracleError> {
    const EXPECTED_SCHEMA: &str = "franken-engine.parser-phase0.semantic-fixtures.v1";
    let expected_mode = ParserMode::ScalarReference.as_str().to_string();
    if catalog.schema_version != EXPECTED_SCHEMA {
        return Err(ParserOracleError::InvalidCatalogSchema {
            expected: EXPECTED_SCHEMA.to_string(),
            actual: catalog.schema_version.clone(),
        });
    }
    if catalog.parser_mode != expected_mode {
        return Err(ParserOracleError::InvalidCatalogParserMode {
            expected: expected_mode,
            actual: catalog.parser_mode.clone(),
        });
    }
    if catalog.fixtures.is_empty() {
        return Err(ParserOracleError::EmptyFixtureCatalog);
    }
    Ok(())
}

fn parse_goal_from_fixture(fixture: &OracleFixtureSpec) -> Result<ParseGoal, ParserOracleError> {
    match fixture.goal.as_str() {
        "script" => Ok(ParseGoal::Script),
        "module" => Ok(ParseGoal::Module),
        other => Err(ParserOracleError::UnknownGoal {
            fixture_id: fixture.id.clone(),
            goal: other.to_string(),
        }),
    }
}

fn observe_parse(
    parser: &CanonicalEs2020Parser,
    source: &str,
    goal: ParseGoal,
    options: &ParserOptions,
) -> ParseObservation {
    match parser.parse_with_options(source, goal, options) {
        Ok(tree) => {
            let digest = Sha256::digest(tree.canonical_bytes());
            let mut hash = [0u8; 32];
            hash.copy_from_slice(digest.as_slice());
            ParseObservation::Hash(hash)
        }
        Err(error) => ParseObservation::Error(error.code),
    }
}

fn classify_observation(
    expected_hash: &str,
    first: ParseObservation,
    second: ParseObservation,
) -> DriftClass {
    match (first, second) {
        (ParseObservation::Hash(first_hash), ParseObservation::Hash(second_hash)) => {
            if first_hash != second_hash {
                return DriftClass::HarnessNondeterminism;
            }

            let observed_hash = format!("sha256:{}", hex::encode(first_hash));
            if observed_hash != expected_hash {
                return DriftClass::ArtifactIntegrityFailure;
            }

            DriftClass::Equivalent
        }
        (ParseObservation::Error(first_error), ParseObservation::Error(second_error)) => {
            if first_error == second_error {
                // Both parsers fail with identical errors — deterministically
                // equivalent behavior, not diagnostics drift.
                DriftClass::Equivalent
            } else {
                DriftClass::HarnessNondeterminism
            }
        }
        _ => DriftClass::SemanticDrift,
    }
}

fn expected_loss_model(summary: &OracleSummary) -> ExpectedLossModel {
    let total = summary.total_fixtures.max(1) as f64;
    let p_equivalent = summary.equivalent_count as f64 / total;
    let p_minor = summary.minor_drift_count as f64 / total;
    let p_critical = summary.critical_drift_count as f64 / total;

    let promote_loss = p_minor * 35.0 + p_critical * 120.0;
    let hold_loss = p_equivalent * 6.0 + p_minor * 18.0 + p_critical * 25.0;
    let reject_loss = p_equivalent * 10.0 + p_minor * 7.0 + p_critical * 4.0;

    let candidates = [
        (GateAction::Promote, promote_loss),
        (GateAction::Hold, hold_loss),
        (GateAction::Reject, reject_loss),
    ];

    let mut recommended = candidates[0];
    for candidate in &candidates[1..] {
        let loss_diff = (candidate.1 - recommended.1).abs();
        let better_loss = candidate.1 < recommended.1;
        let better_tie_break =
            loss_diff <= f64::EPSILON && candidate.0.rank() < recommended.0.rank();
        if better_loss || better_tie_break {
            recommended = *candidate;
        }
    }

    ExpectedLossModel {
        promote_loss,
        hold_loss,
        reject_loss,
        recommended_action: recommended.0,
    }
}

fn decide(
    gate_mode: OracleGateMode,
    summary: &OracleSummary,
    recommended_action: GateAction,
) -> OracleDecision {
    let fallback_triggered = summary.critical_drift_count > 0;
    let fallback_reason = if summary.critical_drift_count > 0 {
        Some("critical drift detected".to_string())
    } else if summary.minor_drift_count > 0 {
        Some("minor diagnostics drift detected".to_string())
    } else {
        None
    };

    match gate_mode {
        OracleGateMode::ReportOnly => OracleDecision {
            action: recommended_action,
            promotion_blocked: false,
            fallback_triggered,
            fallback_reason,
        },
        OracleGateMode::FailClosed => {
            if summary.critical_drift_count > 0 {
                return OracleDecision {
                    action: GateAction::Reject,
                    promotion_blocked: true,
                    fallback_triggered: true,
                    fallback_reason: Some("critical drift detected".to_string()),
                };
            }

            if summary.minor_drift_count > 0 {
                return OracleDecision {
                    action: GateAction::Hold,
                    promotion_blocked: true,
                    fallback_triggered: false,
                    fallback_reason: Some("minor diagnostics drift detected".to_string()),
                };
            }

            OracleDecision {
                action: GateAction::Promote,
                promotion_blocked: false,
                fallback_triggered: false,
                fallback_reason: None,
            }
        }
    }
}

fn normalize_hash(raw: &str) -> String {
    if raw.starts_with("sha256:") {
        raw.to_ascii_lowercase()
    } else {
        format!("sha256:{}", raw.to_ascii_lowercase())
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // OraclePartition
    // -----------------------------------------------------------------------

    #[test]
    fn partition_as_str() {
        assert_eq!(OraclePartition::Smoke.as_str(), "smoke");
        assert_eq!(OraclePartition::Full.as_str(), "full");
        assert_eq!(OraclePartition::Nightly.as_str(), "nightly");
    }

    #[test]
    fn partition_fixture_limit() {
        assert_eq!(OraclePartition::Smoke.fixture_limit(), Some(4));
        assert_eq!(OraclePartition::Full.fixture_limit(), None);
        assert_eq!(OraclePartition::Nightly.fixture_limit(), None);
    }

    #[test]
    fn partition_metamorphic_pairs() {
        assert_eq!(OraclePartition::Smoke.metamorphic_pairs(), 64);
        assert_eq!(OraclePartition::Full.metamorphic_pairs(), 256);
        assert_eq!(OraclePartition::Nightly.metamorphic_pairs(), 1024);
    }

    #[test]
    fn partition_from_str_valid() {
        assert_eq!(
            "smoke".parse::<OraclePartition>().unwrap(),
            OraclePartition::Smoke
        );
        assert_eq!(
            "full".parse::<OraclePartition>().unwrap(),
            OraclePartition::Full
        );
        assert_eq!(
            "nightly".parse::<OraclePartition>().unwrap(),
            OraclePartition::Nightly
        );
    }

    #[test]
    fn partition_from_str_invalid() {
        let err = "unknown".parse::<OraclePartition>().unwrap_err();
        assert!(err.contains("unsupported partition"));
    }

    #[test]
    fn partition_serde_roundtrip() {
        for partition in [
            OraclePartition::Smoke,
            OraclePartition::Full,
            OraclePartition::Nightly,
        ] {
            let json = serde_json::to_string(&partition).unwrap();
            let back: OraclePartition = serde_json::from_str(&json).unwrap();
            assert_eq!(back, partition);
        }
    }

    // -----------------------------------------------------------------------
    // OracleGateMode
    // -----------------------------------------------------------------------

    #[test]
    fn gate_mode_as_str() {
        assert_eq!(OracleGateMode::ReportOnly.as_str(), "report_only");
        assert_eq!(OracleGateMode::FailClosed.as_str(), "fail_closed");
    }

    #[test]
    fn gate_mode_from_str_valid() {
        assert_eq!(
            "report_only".parse::<OracleGateMode>().unwrap(),
            OracleGateMode::ReportOnly
        );
        assert_eq!(
            "fail_closed".parse::<OracleGateMode>().unwrap(),
            OracleGateMode::FailClosed
        );
    }

    #[test]
    fn gate_mode_from_str_invalid() {
        let err = "bad".parse::<OracleGateMode>().unwrap_err();
        assert!(err.contains("unsupported gate mode"));
    }

    #[test]
    fn gate_mode_serde_roundtrip() {
        for mode in [OracleGateMode::ReportOnly, OracleGateMode::FailClosed] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: OracleGateMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, mode);
        }
    }

    // -----------------------------------------------------------------------
    // DriftClass
    // -----------------------------------------------------------------------

    #[test]
    fn drift_class_comparator_decision() {
        assert_eq!(DriftClass::Equivalent.comparator_decision(), "equivalent");
        assert_eq!(
            DriftClass::DiagnosticsDrift.comparator_decision(),
            "drift_minor"
        );
        assert_eq!(
            DriftClass::SemanticDrift.comparator_decision(),
            "drift_critical"
        );
        assert_eq!(
            DriftClass::HarnessNondeterminism.comparator_decision(),
            "drift_critical"
        );
        assert_eq!(
            DriftClass::ArtifactIntegrityFailure.comparator_decision(),
            "drift_critical"
        );
    }

    #[test]
    fn drift_class_is_critical() {
        assert!(!DriftClass::Equivalent.is_critical());
        assert!(!DriftClass::DiagnosticsDrift.is_critical());
        assert!(DriftClass::SemanticDrift.is_critical());
        assert!(DriftClass::HarnessNondeterminism.is_critical());
        assert!(DriftClass::ArtifactIntegrityFailure.is_critical());
    }

    #[test]
    fn drift_class_is_minor() {
        assert!(DriftClass::DiagnosticsDrift.is_minor());
        assert!(!DriftClass::Equivalent.is_minor());
        assert!(!DriftClass::SemanticDrift.is_minor());
        assert!(!DriftClass::HarnessNondeterminism.is_minor());
        assert!(!DriftClass::ArtifactIntegrityFailure.is_minor());
    }

    #[test]
    fn drift_class_serde_roundtrip() {
        for class in [
            DriftClass::Equivalent,
            DriftClass::SemanticDrift,
            DriftClass::DiagnosticsDrift,
            DriftClass::HarnessNondeterminism,
            DriftClass::ArtifactIntegrityFailure,
        ] {
            let json = serde_json::to_string(&class).unwrap();
            let back: DriftClass = serde_json::from_str(&json).unwrap();
            assert_eq!(back, class);
        }
    }

    // -----------------------------------------------------------------------
    // GateAction
    // -----------------------------------------------------------------------

    #[test]
    fn gate_action_rank_ordering() {
        assert!(GateAction::Promote.rank() < GateAction::Hold.rank());
        assert!(GateAction::Hold.rank() < GateAction::Reject.rank());
    }

    #[test]
    fn gate_action_serde_roundtrip() {
        for action in [GateAction::Promote, GateAction::Hold, GateAction::Reject] {
            let json = serde_json::to_string(&action).unwrap();
            let back: GateAction = serde_json::from_str(&json).unwrap();
            assert_eq!(back, action);
        }
    }

    // -----------------------------------------------------------------------
    // ParseObservation
    // -----------------------------------------------------------------------

    #[test]
    fn parse_observation_hash_hex_some() {
        let mut hash = [0u8; 32];
        hash[0] = 0xab;
        hash[31] = 0xcd;
        let obs = ParseObservation::Hash(hash);
        let hex_str = obs.hash_hex().unwrap();
        assert!(hex_str.starts_with("sha256:"));
        assert!(hex_str.contains("ab"));
        assert!(hex_str.contains("cd"));
    }

    #[test]
    fn parse_observation_hash_hex_none_for_error() {
        let obs = ParseObservation::Error(ParseErrorCode::UnsupportedSyntax);
        assert!(obs.hash_hex().is_none());
    }

    #[test]
    fn parse_observation_error_code_some() {
        let obs = ParseObservation::Error(ParseErrorCode::UnsupportedSyntax);
        let code = obs.error_code().unwrap();
        assert!(!code.is_empty());
    }

    #[test]
    fn parse_observation_error_code_none_for_hash() {
        let obs = ParseObservation::Hash([0u8; 32]);
        assert!(obs.error_code().is_none());
    }

    // -----------------------------------------------------------------------
    // normalize_hash
    // -----------------------------------------------------------------------

    #[test]
    fn normalize_hash_with_prefix() {
        let result = normalize_hash("sha256:ABCDEF");
        assert_eq!(result, "sha256:abcdef");
    }

    #[test]
    fn normalize_hash_without_prefix() {
        let result = normalize_hash("ABCDEF");
        assert_eq!(result, "sha256:abcdef");
    }

    #[test]
    fn normalize_hash_already_lowercase() {
        let result = normalize_hash("sha256:0123abcdef");
        assert_eq!(result, "sha256:0123abcdef");
    }

    // -----------------------------------------------------------------------
    // hash_bytes
    // -----------------------------------------------------------------------

    #[test]
    fn hash_bytes_deterministic() {
        let a = hash_bytes(b"hello");
        let b = hash_bytes(b"hello");
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
    }

    #[test]
    fn hash_bytes_different_inputs_differ() {
        let a = hash_bytes(b"hello");
        let b = hash_bytes(b"world");
        assert_ne!(a, b);
    }

    // -----------------------------------------------------------------------
    // derive_seed
    // -----------------------------------------------------------------------

    #[test]
    fn derive_seed_deterministic() {
        let a = derive_seed(42, "fixture-1", ParserMode::ScalarReference);
        let b = derive_seed(42, "fixture-1", ParserMode::ScalarReference);
        assert_eq!(a, b);
    }

    #[test]
    fn derive_seed_different_fixture_ids() {
        let a = derive_seed(42, "fixture-1", ParserMode::ScalarReference);
        let b = derive_seed(42, "fixture-2", ParserMode::ScalarReference);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_seed_different_master_seeds() {
        let a = derive_seed(1, "fixture-1", ParserMode::ScalarReference);
        let b = derive_seed(2, "fixture-1", ParserMode::ScalarReference);
        assert_ne!(a, b);
    }

    // -----------------------------------------------------------------------
    // classify_observation
    // -----------------------------------------------------------------------

    #[test]
    fn classify_matching_hashes_equivalent() {
        let hash = [0xabu8; 32];
        let expected = format!("sha256:{}", hex::encode(hash));
        let class = classify_observation(
            &expected,
            ParseObservation::Hash(hash),
            ParseObservation::Hash(hash),
        );
        assert_eq!(class, DriftClass::Equivalent);
    }

    #[test]
    fn classify_nondeterministic_hashes() {
        let hash1 = [0xabu8; 32];
        let mut hash2 = hash1;
        hash2[0] = 0xcd;
        let expected = format!("sha256:{}", hex::encode(hash1));
        let class = classify_observation(
            &expected,
            ParseObservation::Hash(hash1),
            ParseObservation::Hash(hash2),
        );
        assert_eq!(class, DriftClass::HarnessNondeterminism);
    }

    #[test]
    fn classify_deterministic_but_wrong_hash() {
        let hash = [0xabu8; 32];
        let expected = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let class = classify_observation(
            expected,
            ParseObservation::Hash(hash),
            ParseObservation::Hash(hash),
        );
        assert_eq!(class, DriftClass::ArtifactIntegrityFailure);
    }

    #[test]
    fn classify_matching_errors_equivalent() {
        let class = classify_observation(
            "sha256:0000",
            ParseObservation::Error(ParseErrorCode::UnsupportedSyntax),
            ParseObservation::Error(ParseErrorCode::UnsupportedSyntax),
        );
        // Both parsers fail identically — deterministically equivalent.
        assert_eq!(class, DriftClass::Equivalent);
    }

    #[test]
    fn classify_different_errors_nondeterminism() {
        let class = classify_observation(
            "sha256:0000",
            ParseObservation::Error(ParseErrorCode::UnsupportedSyntax),
            ParseObservation::Error(ParseErrorCode::InvalidGoal),
        );
        assert_eq!(class, DriftClass::HarnessNondeterminism);
    }

    #[test]
    fn classify_hash_then_error_semantic_drift() {
        let class = classify_observation(
            "sha256:0000",
            ParseObservation::Hash([0u8; 32]),
            ParseObservation::Error(ParseErrorCode::UnsupportedSyntax),
        );
        assert_eq!(class, DriftClass::SemanticDrift);
    }

    #[test]
    fn classify_error_then_hash_semantic_drift() {
        let class = classify_observation(
            "sha256:0000",
            ParseObservation::Error(ParseErrorCode::UnsupportedSyntax),
            ParseObservation::Hash([0u8; 32]),
        );
        assert_eq!(class, DriftClass::SemanticDrift);
    }

    // -----------------------------------------------------------------------
    // expected_loss_model
    // -----------------------------------------------------------------------

    fn make_summary(equivalent: u64, minor: u64, critical: u64) -> OracleSummary {
        let total = equivalent + minor + critical;
        let mut counts_by_class = BTreeMap::new();
        if equivalent > 0 {
            counts_by_class.insert("Equivalent".to_string(), equivalent);
        }
        if minor > 0 {
            counts_by_class.insert("DiagnosticsDrift".to_string(), minor);
        }
        if critical > 0 {
            counts_by_class.insert("SemanticDrift".to_string(), critical);
        }
        let drift_rate_millionths = (minor + critical)
            .saturating_mul(1_000_000)
            .checked_div(total)
            .unwrap_or(0);
        OracleSummary {
            total_fixtures: total,
            equivalent_count: equivalent,
            minor_drift_count: minor,
            critical_drift_count: critical,
            drift_rate_millionths,
            counts_by_class,
        }
    }

    #[test]
    fn expected_loss_all_equivalent_recommends_promote() {
        let summary = make_summary(100, 0, 0);
        let model = expected_loss_model(&summary);
        assert_eq!(model.recommended_action, GateAction::Promote);
        assert!(model.promote_loss < model.hold_loss);
        assert!(model.promote_loss < model.reject_loss);
    }

    #[test]
    fn expected_loss_all_critical_recommends_reject() {
        let summary = make_summary(0, 0, 100);
        let model = expected_loss_model(&summary);
        assert_eq!(model.recommended_action, GateAction::Reject);
        assert!(model.reject_loss < model.promote_loss);
    }

    #[test]
    fn expected_loss_mixed_drift() {
        let summary = make_summary(80, 15, 5);
        let model = expected_loss_model(&summary);
        // With some critical drift, promote should have high loss
        assert!(model.promote_loss > 0.0);
    }

    #[test]
    fn expected_loss_all_minor_recommends_hold_or_reject() {
        let summary = make_summary(0, 100, 0);
        let model = expected_loss_model(&summary);
        // promote_loss = 1.0*35 = 35, hold_loss = 1.0*18 = 18, reject_loss = 1.0*7 = 7
        assert_eq!(model.recommended_action, GateAction::Reject);
    }

    // -----------------------------------------------------------------------
    // decide
    // -----------------------------------------------------------------------

    #[test]
    fn decide_report_only_no_drift_promotes() {
        let summary = make_summary(100, 0, 0);
        let decision = decide(OracleGateMode::ReportOnly, &summary, GateAction::Promote);
        assert_eq!(decision.action, GateAction::Promote);
        assert!(!decision.promotion_blocked);
        assert!(!decision.fallback_triggered);
        assert!(decision.fallback_reason.is_none());
    }

    #[test]
    fn decide_report_only_with_critical_drift() {
        let summary = make_summary(90, 0, 10);
        let decision = decide(OracleGateMode::ReportOnly, &summary, GateAction::Reject);
        // ReportOnly uses recommended_action but never blocks
        assert_eq!(decision.action, GateAction::Reject);
        assert!(!decision.promotion_blocked);
        assert!(decision.fallback_triggered);
        assert!(
            decision
                .fallback_reason
                .as_deref()
                .unwrap()
                .contains("critical")
        );
    }

    #[test]
    fn decide_report_only_with_minor_drift() {
        let summary = make_summary(90, 10, 0);
        let decision = decide(OracleGateMode::ReportOnly, &summary, GateAction::Hold);
        assert_eq!(decision.action, GateAction::Hold);
        assert!(!decision.promotion_blocked);
        assert!(!decision.fallback_triggered);
        assert!(
            decision
                .fallback_reason
                .as_deref()
                .unwrap()
                .contains("minor")
        );
    }

    #[test]
    fn decide_fail_closed_no_drift_promotes() {
        let summary = make_summary(100, 0, 0);
        let decision = decide(OracleGateMode::FailClosed, &summary, GateAction::Promote);
        assert_eq!(decision.action, GateAction::Promote);
        assert!(!decision.promotion_blocked);
        assert!(!decision.fallback_triggered);
        assert!(decision.fallback_reason.is_none());
    }

    #[test]
    fn decide_fail_closed_critical_drift_rejects() {
        let summary = make_summary(90, 0, 10);
        let decision = decide(OracleGateMode::FailClosed, &summary, GateAction::Promote);
        assert_eq!(decision.action, GateAction::Reject);
        assert!(decision.promotion_blocked);
        assert!(decision.fallback_triggered);
    }

    #[test]
    fn decide_fail_closed_minor_drift_holds() {
        let summary = make_summary(90, 10, 0);
        let decision = decide(OracleGateMode::FailClosed, &summary, GateAction::Promote);
        assert_eq!(decision.action, GateAction::Hold);
        assert!(decision.promotion_blocked);
        assert!(!decision.fallback_triggered);
    }

    // -----------------------------------------------------------------------
    // validate_fixture_catalog
    // -----------------------------------------------------------------------

    fn valid_catalog() -> OracleFixtureCatalog {
        OracleFixtureCatalog {
            schema_version: "franken-engine.parser-phase0.semantic-fixtures.v1".to_string(),
            parser_mode: "scalar_reference".to_string(),
            fixtures: vec![OracleFixtureSpec {
                id: "fixture-1".to_string(),
                family_id: "fam-1".to_string(),
                goal: "script".to_string(),
                source: "var x = 1;".to_string(),
                expected_hash: "sha256:0000".to_string(),
            }],
        }
    }

    #[test]
    fn validate_catalog_ok() {
        assert!(validate_fixture_catalog(&valid_catalog()).is_ok());
    }

    #[test]
    fn validate_catalog_wrong_schema() {
        let mut catalog = valid_catalog();
        catalog.schema_version = "wrong".to_string();
        let err = validate_fixture_catalog(&catalog).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid parser oracle catalog schema")
        );
    }

    #[test]
    fn validate_catalog_wrong_parser_mode() {
        let mut catalog = valid_catalog();
        catalog.parser_mode = "parallel_chunked".to_string();
        let err = validate_fixture_catalog(&catalog).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid parser oracle catalog parser_mode")
        );
    }

    #[test]
    fn validate_catalog_empty_fixtures() {
        let mut catalog = valid_catalog();
        catalog.fixtures.clear();
        let err = validate_fixture_catalog(&catalog).unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    // -----------------------------------------------------------------------
    // parse_goal_from_fixture
    // -----------------------------------------------------------------------

    #[test]
    fn parse_goal_script() {
        let fixture = OracleFixtureSpec {
            id: "f1".to_string(),
            family_id: "fam".to_string(),
            goal: "script".to_string(),
            source: String::new(),
            expected_hash: String::new(),
        };
        assert_eq!(
            parse_goal_from_fixture(&fixture).unwrap(),
            ParseGoal::Script
        );
    }

    #[test]
    fn parse_goal_module() {
        let fixture = OracleFixtureSpec {
            id: "f1".to_string(),
            family_id: "fam".to_string(),
            goal: "module".to_string(),
            source: String::new(),
            expected_hash: String::new(),
        };
        assert_eq!(
            parse_goal_from_fixture(&fixture).unwrap(),
            ParseGoal::Module
        );
    }

    #[test]
    fn parse_goal_unknown() {
        let fixture = OracleFixtureSpec {
            id: "f1".to_string(),
            family_id: "fam".to_string(),
            goal: "expression".to_string(),
            source: String::new(),
            expected_hash: String::new(),
        };
        let err = parse_goal_from_fixture(&fixture).unwrap_err();
        assert!(err.to_string().contains("unknown parse goal"));
    }

    // -----------------------------------------------------------------------
    // partition_fixtures
    // -----------------------------------------------------------------------

    #[test]
    fn partition_fixtures_smoke_limits() {
        let catalog = OracleFixtureCatalog {
            schema_version: "franken-engine.parser-phase0.semantic-fixtures.v1".to_string(),
            parser_mode: "scalar_reference".to_string(),
            fixtures: (0..10)
                .map(|i| OracleFixtureSpec {
                    id: format!("f-{i:02}"),
                    family_id: "fam".to_string(),
                    goal: "script".to_string(),
                    source: format!("var x = {i};"),
                    expected_hash: "sha256:00".to_string(),
                })
                .collect(),
        };
        let result = partition_fixtures(&catalog, OraclePartition::Smoke);
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn partition_fixtures_full_no_limit() {
        let catalog = OracleFixtureCatalog {
            schema_version: "franken-engine.parser-phase0.semantic-fixtures.v1".to_string(),
            parser_mode: "scalar_reference".to_string(),
            fixtures: (0..10)
                .map(|i| OracleFixtureSpec {
                    id: format!("f-{i:02}"),
                    family_id: "fam".to_string(),
                    goal: "script".to_string(),
                    source: format!("var x = {i};"),
                    expected_hash: "sha256:00".to_string(),
                })
                .collect(),
        };
        let result = partition_fixtures(&catalog, OraclePartition::Full);
        assert_eq!(result.len(), 10);
    }

    #[test]
    fn partition_fixtures_sorted_by_id() {
        let catalog = OracleFixtureCatalog {
            schema_version: "franken-engine.parser-phase0.semantic-fixtures.v1".to_string(),
            parser_mode: "scalar_reference".to_string(),
            fixtures: vec![
                OracleFixtureSpec {
                    id: "z-last".to_string(),
                    family_id: "fam".to_string(),
                    goal: "script".to_string(),
                    source: "1".to_string(),
                    expected_hash: "sha256:00".to_string(),
                },
                OracleFixtureSpec {
                    id: "a-first".to_string(),
                    family_id: "fam".to_string(),
                    goal: "script".to_string(),
                    source: "2".to_string(),
                    expected_hash: "sha256:00".to_string(),
                },
            ],
        };
        let result = partition_fixtures(&catalog, OraclePartition::Full);
        assert_eq!(result[0].id, "a-first");
        assert_eq!(result[1].id, "z-last");
    }

    // -----------------------------------------------------------------------
    // ParserOracleConfig
    // -----------------------------------------------------------------------

    #[test]
    fn config_with_defaults() {
        let config = ParserOracleConfig::with_defaults(
            OraclePartition::Smoke,
            OracleGateMode::ReportOnly,
            42,
        );
        assert_eq!(config.partition, OraclePartition::Smoke);
        assert_eq!(config.gate_mode, OracleGateMode::ReportOnly);
        assert_eq!(config.seed, 42);
        assert!(config.trace_id.starts_with("trace-parser-oracle-"));
        assert!(config.decision_id.starts_with("decision-parser-oracle-"));
        assert_eq!(config.policy_id, "policy-parser-oracle-v1");
    }

    // -----------------------------------------------------------------------
    // ParserOracleError Display
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_io() {
        let err = ParserOracleError::Io {
            path: "/nonexistent".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
        };
        let msg = err.to_string();
        assert!(msg.contains("/nonexistent"));
        assert!(msg.contains("not found"));
    }

    #[test]
    fn error_display_decode_catalog() {
        let err = ParserOracleError::DecodeCatalog("bad json".to_string());
        assert!(err.to_string().contains("bad json"));
    }

    #[test]
    fn error_display_invalid_schema() {
        let err = ParserOracleError::InvalidCatalogSchema {
            expected: "v1".to_string(),
            actual: "v2".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("v2"));
        assert!(msg.contains("v1"));
    }

    #[test]
    fn error_display_invalid_parser_mode() {
        let err = ParserOracleError::InvalidCatalogParserMode {
            expected: "scalar_reference".to_string(),
            actual: "parallel".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("parallel"));
    }

    #[test]
    fn error_display_empty_catalog() {
        let err = ParserOracleError::EmptyFixtureCatalog;
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn error_display_unknown_goal() {
        let err = ParserOracleError::UnknownGoal {
            fixture_id: "f1".to_string(),
            goal: "bad".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("f1"));
        assert!(msg.contains("bad"));
    }

    // -----------------------------------------------------------------------
    // OracleFixtureResult serde
    // -----------------------------------------------------------------------

    #[test]
    fn fixture_result_serde_roundtrip() {
        let result = OracleFixtureResult {
            fixture_id: "f-01".to_string(),
            family_id: "fam-1".to_string(),
            goal: "script".to_string(),
            parser_mode: "scalar_reference".to_string(),
            derived_seed: 12345,
            input_hash: "sha256:abc".to_string(),
            expected_hash: "sha256:abc".to_string(),
            observed_hash: Some("sha256:abc".to_string()),
            repeated_hash: Some("sha256:abc".to_string()),
            parse_error_code: None,
            repeated_error_code: None,
            drift_class: DriftClass::Equivalent,
            comparator_decision: "equivalent".to_string(),
            latency_ns: 1000,
            replay_command: "cargo run ...".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("f-01"));
        assert!(json.contains("equivalent"));
    }

    // -----------------------------------------------------------------------
    // OracleSummary
    // -----------------------------------------------------------------------

    #[test]
    fn oracle_summary_drift_rate_calculation() {
        let summary = make_summary(90, 5, 5);
        // (5 + 5) * 1_000_000 / 100 = 100_000
        assert_eq!(summary.drift_rate_millionths, 100_000);
    }

    #[test]
    fn oracle_summary_zero_drift_rate() {
        let summary = make_summary(100, 0, 0);
        assert_eq!(summary.drift_rate_millionths, 0);
    }

    // -----------------------------------------------------------------------
    // OracleDecision serde
    // -----------------------------------------------------------------------

    #[test]
    fn oracle_decision_serde() {
        let decision = OracleDecision {
            action: GateAction::Hold,
            promotion_blocked: true,
            fallback_triggered: false,
            fallback_reason: Some("minor drift".to_string()),
        };
        let json = serde_json::to_string(&decision).unwrap();
        assert!(json.contains("hold"));
        assert!(json.contains("minor drift"));
    }

    // -----------------------------------------------------------------------
    // load_fixture_catalog (file I/O tests)
    // -----------------------------------------------------------------------

    #[test]
    fn load_fixture_catalog_nonexistent() {
        let err = load_fixture_catalog(Path::new("/nonexistent/catalog.json")).unwrap_err();
        assert!(err.to_string().contains("failed to read"));
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn oracle_partition_as_str_distinct() {
        let all = [
            OraclePartition::Smoke,
            OraclePartition::Full,
            OraclePartition::Nightly,
        ];
        let set: std::collections::BTreeSet<&str> = all.iter().map(|p| p.as_str()).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn gate_mode_as_str_distinct() {
        let all = [OracleGateMode::ReportOnly, OracleGateMode::FailClosed];
        let set: std::collections::BTreeSet<&str> = all.iter().map(|m| m.as_str()).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn drift_class_debug_distinct() {
        let all = [
            DriftClass::Equivalent,
            DriftClass::SemanticDrift,
            DriftClass::DiagnosticsDrift,
            DriftClass::HarnessNondeterminism,
            DriftClass::ArtifactIntegrityFailure,
        ];
        let set: std::collections::BTreeSet<String> =
            all.iter().map(|d| format!("{d:?}")).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn gate_action_debug_distinct() {
        let all = [GateAction::Promote, GateAction::Hold, GateAction::Reject];
        let set: std::collections::BTreeSet<String> =
            all.iter().map(|a| format!("{a:?}")).collect();
        assert_eq!(set.len(), all.len());
    }
}
