//! Deterministic RGC test harness utilities shared across unit and integration lanes.
//!
//! This module provides:
//! - deterministic run context identifiers (trace/decision/policy IDs),
//! - fixture loading with path-traversal protection,
//! - structured test log event envelopes with stable keys,
//! - artifact triad writers (`run_manifest.json`, `events.jsonl`, `commands.txt`).

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RGC_TEST_HARNESS_SCHEMA_VERSION: &str = "franken-engine.rgc-test-harness.v1";
pub const RGC_TEST_HARNESS_EVENT_SCHEMA_VERSION: &str = "franken-engine.rgc-test-event.v1";
pub const RGC_TEST_HARNESS_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.rgc-test-harness.run-manifest.v1";
pub const RGC_BASELINE_E2E_SCENARIO_SCHEMA_VERSION: &str =
    "franken-engine.rgc-baseline-e2e-scenario.v1";
pub const RGC_ARTIFACT_VALIDATOR_SCHEMA_VERSION: &str = "franken-engine.rgc-artifact-validator.v1";
pub const RGC_ARTIFACT_BUNDLE_VALIDATOR_SCHEMA_VERSION: &str =
    "franken-engine.rgc-artifact-bundle-validator.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessLane {
    Parser,
    Runtime,
    Security,
    Governance,
    E2e,
}

impl HarnessLane {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parser => "parser",
            Self::Runtime => "runtime",
            Self::Security => "security",
            Self::Governance => "governance",
            Self::E2e => "e2e",
        }
    }
}

impl fmt::Display for HarnessLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// Input parameters for [`DeterministicTestContext::event`].
#[derive(Debug, Clone)]
pub struct EventInput<'a> {
    pub sequence: u64,
    pub component: &'a str,
    pub event: &'a str,
    pub outcome: &'a str,
    pub error_code: Option<&'a str>,
    pub timing_us: u64,
    pub timestamp_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicTestContext {
    pub scenario_id: String,
    pub fixture_id: String,
    pub lane: HarnessLane,
    pub seed: u64,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

impl DeterministicTestContext {
    pub fn new(
        scenario_id: impl Into<String>,
        fixture_id: impl Into<String>,
        lane: HarnessLane,
        seed: u64,
    ) -> Self {
        let scenario_id = scenario_id.into();
        let fixture_id = fixture_id.into();
        let seed_material = format!("{}|{}|{}|{}", scenario_id, fixture_id, lane, seed);
        let digest = hex::encode(Sha256::digest(seed_material.as_bytes()));
        let short = &digest[..16];

        Self {
            scenario_id,
            fixture_id,
            lane,
            seed,
            trace_id: format!("trace-rgc-{short}"),
            decision_id: format!("decision-rgc-{short}"),
            policy_id: format!("policy-rgc-{}-v1", lane.as_str()),
        }
    }

    pub fn default_run_id(&self) -> String {
        format!(
            "run-{}-{}",
            sanitize_label(&self.scenario_id),
            &self.trace_id["trace-rgc-".len()..]
        )
    }

    pub fn event(&self, input: EventInput<'_>) -> HarnessLogEvent {
        HarnessLogEvent {
            schema_version: RGC_TEST_HARNESS_EVENT_SCHEMA_VERSION.to_string(),
            scenario_id: self.scenario_id.clone(),
            fixture_id: self.fixture_id.clone(),
            trace_id: self.trace_id.clone(),
            decision_id: self.decision_id.clone(),
            policy_id: self.policy_id.clone(),
            lane: self.lane,
            component: input.component.to_string(),
            event: input.event.to_string(),
            outcome: input.outcome.to_string(),
            error_code: input.error_code.map(std::string::ToString::to_string),
            seed: self.seed,
            sequence: input.sequence,
            timing_us: input.timing_us,
            timestamp_unix_ms: input.timestamp_unix_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessLogEvent {
    pub schema_version: String,
    pub scenario_id: String,
    pub fixture_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub lane: HarnessLane,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub seed: u64,
    pub sequence: u64,
    pub timing_us: u64,
    pub timestamp_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessRunManifest {
    pub schema_version: String,
    pub harness_schema_version: String,
    pub run_id: String,
    pub scenario_id: String,
    pub fixture_id: String,
    pub lane: HarnessLane,
    pub seed: u64,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub event_count: usize,
    pub command_count: usize,
    pub env_fingerprint: String,
    pub replay_command: String,
    pub generated_at_unix_ms: u64,
}

impl HarnessRunManifest {
    pub fn from_context(
        context: &DeterministicTestContext,
        run_id: impl Into<String>,
        event_count: usize,
        command_count: usize,
        replay_command: impl Into<String>,
        generated_at_unix_ms: u64,
    ) -> Self {
        let replay_command = replay_command.into();
        let env_material = format!(
            "{}|{}|{}|{}|{}|{}",
            RGC_TEST_HARNESS_SCHEMA_VERSION,
            context.lane.as_str(),
            context.seed,
            context.scenario_id,
            context.fixture_id,
            replay_command
        );
        let env_fingerprint = hex::encode(Sha256::digest(env_material.as_bytes()));

        Self {
            schema_version: RGC_TEST_HARNESS_MANIFEST_SCHEMA_VERSION.to_string(),
            harness_schema_version: RGC_TEST_HARNESS_SCHEMA_VERSION.to_string(),
            run_id: run_id.into(),
            scenario_id: context.scenario_id.clone(),
            fixture_id: context.fixture_id.clone(),
            lane: context.lane,
            seed: context.seed,
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            event_count,
            command_count,
            env_fingerprint,
            replay_command,
            generated_at_unix_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessArtifactTriad {
    pub run_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineScenarioDomain {
    Runtime,
    Module,
    Security,
}

impl BaselineScenarioDomain {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Module => "module",
            Self::Security => "security",
        }
    }
}

impl fmt::Display for BaselineScenarioDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineScenarioOutcome {
    HappyPath,
    CanonicalFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineE2eScenario {
    pub schema_version: String,
    pub scenario_id: String,
    pub fixture_id: String,
    pub lane: HarnessLane,
    pub domain: BaselineScenarioDomain,
    pub outcome: BaselineScenarioOutcome,
    pub component: String,
    pub event: String,
    pub error_code: Option<String>,
}

impl BaselineE2eScenario {
    fn new(
        scenario_id: &str,
        fixture_id: &str,
        domain: BaselineScenarioDomain,
        outcome: BaselineScenarioOutcome,
        component: &str,
        event: &str,
        error_code: Option<&str>,
    ) -> Self {
        Self {
            schema_version: RGC_BASELINE_E2E_SCENARIO_SCHEMA_VERSION.to_string(),
            scenario_id: scenario_id.to_string(),
            fixture_id: fixture_id.to_string(),
            lane: HarnessLane::E2e,
            domain,
            outcome,
            component: component.to_string(),
            event: event.to_string(),
            error_code: error_code.map(std::string::ToString::to_string),
        }
    }
}

pub fn baseline_e2e_scenario_registry() -> Vec<BaselineE2eScenario> {
    let mut scenarios = vec![
        BaselineE2eScenario::new(
            "rgc-053a-runtime-happy",
            "runtime-smoke-happy",
            BaselineScenarioDomain::Runtime,
            BaselineScenarioOutcome::HappyPath,
            "runtime_lane",
            "execute_runtime_smoke",
            None,
        ),
        BaselineE2eScenario::new(
            "rgc-053a-runtime-failure",
            "runtime-smoke-failure",
            BaselineScenarioDomain::Runtime,
            BaselineScenarioOutcome::CanonicalFailure,
            "runtime_lane",
            "runtime_guard_abort",
            Some("FE-RGC-053A-RUNTIME-0001"),
        ),
        BaselineE2eScenario::new(
            "rgc-053a-module-happy",
            "module-smoke-happy",
            BaselineScenarioDomain::Module,
            BaselineScenarioOutcome::HappyPath,
            "module_loader",
            "resolve_graph",
            None,
        ),
        BaselineE2eScenario::new(
            "rgc-053a-module-failure",
            "module-smoke-failure",
            BaselineScenarioDomain::Module,
            BaselineScenarioOutcome::CanonicalFailure,
            "module_loader",
            "resolution_rejected",
            Some("FE-RGC-053A-MODULE-0001"),
        ),
        BaselineE2eScenario::new(
            "rgc-053a-security-happy",
            "security-smoke-happy",
            BaselineScenarioDomain::Security,
            BaselineScenarioOutcome::HappyPath,
            "security_guardplane",
            "capability_allowed",
            None,
        ),
        BaselineE2eScenario::new(
            "rgc-053a-security-failure",
            "security-smoke-failure",
            BaselineScenarioDomain::Security,
            BaselineScenarioOutcome::CanonicalFailure,
            "security_guardplane",
            "containment_triggered",
            Some("FE-RGC-053A-SECURITY-0001"),
        ),
    ];
    scenarios.sort_by(|left, right| left.scenario_id.cmp(&right.scenario_id));
    scenarios
}

pub fn select_baseline_e2e_scenarios(
    domains: &[BaselineScenarioDomain],
    include_failures: bool,
) -> Vec<BaselineE2eScenario> {
    let allowed_domains: BTreeSet<BaselineScenarioDomain> = if domains.is_empty() {
        [
            BaselineScenarioDomain::Runtime,
            BaselineScenarioDomain::Module,
            BaselineScenarioDomain::Security,
        ]
        .into_iter()
        .collect()
    } else {
        domains.iter().copied().collect()
    };

    let mut selected: Vec<_> = baseline_e2e_scenario_registry()
        .into_iter()
        .filter(|scenario| allowed_domains.contains(&scenario.domain))
        .filter(|scenario| {
            include_failures || scenario.outcome == BaselineScenarioOutcome::HappyPath
        })
        .collect();
    selected.sort_by(|left, right| left.scenario_id.cmp(&right.scenario_id));
    selected
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactValidationErrorCode {
    MissingArtifact,
    InvalidManifestJson,
    InvalidEventJson,
    MissingRequiredField,
    CorrelationMismatch,
    CountMismatch,
    EmptyCommands,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactValidationFinding {
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: ArtifactValidationErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactValidationReport {
    pub schema_version: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub valid: bool,
    pub run_id: Option<String>,
    pub trace_id: Option<String>,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
    pub findings: Vec<ArtifactValidationFinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactBundleValidationErrorCode {
    MissingBundleDirectory,
    MissingRunDirectory,
    InvalidManifest,
    InvalidTriad,
    DuplicateLane,
    DuplicateRunId,
    MissingRequiredLane,
    CorrelationMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactBundleValidationFinding {
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: ArtifactBundleValidationErrorCode,
    pub message: String,
    pub owner_hint: String,
    pub remediation_hint: String,
    pub repro_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactBundleCorrelationSignature {
    pub scenario_id: String,
    pub seed: u64,
    pub lanes: Vec<HarnessLane>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactBundleValidationReport {
    pub schema_version: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub valid: bool,
    pub bundle_dir: String,
    pub correlation_signature: Option<ArtifactBundleCorrelationSignature>,
    pub run_dirs: Vec<String>,
    pub lane_reports: Vec<ArtifactValidationReport>,
    pub findings: Vec<ArtifactBundleValidationFinding>,
}

impl ArtifactValidationFinding {
    fn new(error_code: ArtifactValidationErrorCode, message: impl Into<String>) -> Self {
        Self {
            component: "rgc_artifact_validator".to_string(),
            event: "validate_artifact_triad".to_string(),
            outcome: "fail".to_string(),
            error_code,
            message: message.into(),
        }
    }
}

impl ArtifactBundleValidationFinding {
    fn new(
        error_code: ArtifactBundleValidationErrorCode,
        message: impl Into<String>,
        owner_hint: impl Into<String>,
        remediation_hint: impl Into<String>,
        repro_command: impl Into<String>,
    ) -> Self {
        Self {
            component: "rgc_artifact_bundle_validator".to_string(),
            event: "validate_artifact_bundle".to_string(),
            outcome: "fail".to_string(),
            error_code,
            message: message.into(),
            owner_hint: owner_hint.into(),
            remediation_hint: remediation_hint.into(),
            repro_command: repro_command.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestCorrelationFields {
    run_id: String,
    scenario_id: String,
    fixture_id: String,
    lane: HarnessLane,
    seed: u64,
    trace_id: String,
    decision_id: String,
    policy_id: String,
}

fn manifest_required_field(
    manifest: &serde_json::Value,
    field: &str,
    findings: &mut Vec<ArtifactValidationFinding>,
) -> Option<String> {
    let value = manifest.get(field).and_then(serde_json::Value::as_str);
    match value {
        Some(raw) if !raw.trim().is_empty() => Some(raw.to_string()),
        _ => {
            findings.push(ArtifactValidationFinding::new(
                ArtifactValidationErrorCode::MissingRequiredField,
                format!("manifest missing required non-empty field `{field}`"),
            ));
            None
        }
    }
}

pub fn validate_artifact_triad(run_dir: impl AsRef<Path>) -> ArtifactValidationReport {
    let run_dir = run_dir.as_ref();
    let manifest_path = run_dir.join("run_manifest.json");
    let events_path = run_dir.join("events.jsonl");
    let commands_path = run_dir.join("commands.txt");

    let mut findings = Vec::new();
    for (name, path) in [
        ("run_manifest.json", &manifest_path),
        ("events.jsonl", &events_path),
        ("commands.txt", &commands_path),
    ] {
        if !path.exists() {
            findings.push(ArtifactValidationFinding::new(
                ArtifactValidationErrorCode::MissingArtifact,
                format!("missing required artifact `{name}` at `{}`", path.display()),
            ));
        }
    }

    let mut run_id = None;
    let mut trace_id = None;
    let mut decision_id = None;
    let mut policy_id = None;
    let mut seed = None;
    let mut expected_event_count = None;
    let mut expected_command_count = None;

    if manifest_path.exists() {
        match fs::read_to_string(&manifest_path) {
            Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
                Ok(manifest) => {
                    let schema =
                        manifest_required_field(&manifest, "schema_version", &mut findings);
                    if let Some(schema) = schema
                        && schema != RGC_TEST_HARNESS_MANIFEST_SCHEMA_VERSION
                    {
                        findings.push(ArtifactValidationFinding::new(
                            ArtifactValidationErrorCode::MissingRequiredField,
                            format!(
                                "manifest schema_version mismatch: expected `{}` found `{schema}`",
                                RGC_TEST_HARNESS_MANIFEST_SCHEMA_VERSION
                            ),
                        ));
                    }
                    run_id = manifest_required_field(&manifest, "run_id", &mut findings);
                    trace_id = manifest_required_field(&manifest, "trace_id", &mut findings);
                    decision_id = manifest_required_field(&manifest, "decision_id", &mut findings);
                    policy_id = manifest_required_field(&manifest, "policy_id", &mut findings);
                    let _scenario_id =
                        manifest_required_field(&manifest, "scenario_id", &mut findings);
                    let _fixture_id =
                        manifest_required_field(&manifest, "fixture_id", &mut findings);
                    let _replay_command =
                        manifest_required_field(&manifest, "replay_command", &mut findings);
                    let _env_fingerprint =
                        manifest_required_field(&manifest, "env_fingerprint", &mut findings);

                    seed = manifest.get("seed").and_then(serde_json::Value::as_u64);
                    if seed.is_none() {
                        findings.push(ArtifactValidationFinding::new(
                            ArtifactValidationErrorCode::MissingRequiredField,
                            "manifest missing numeric `seed` field",
                        ));
                    }

                    expected_event_count = manifest
                        .get("event_count")
                        .and_then(serde_json::Value::as_u64);
                    if expected_event_count.is_none() {
                        findings.push(ArtifactValidationFinding::new(
                            ArtifactValidationErrorCode::MissingRequiredField,
                            "manifest missing numeric `event_count` field",
                        ));
                    }

                    expected_command_count = manifest
                        .get("command_count")
                        .and_then(serde_json::Value::as_u64);
                    if expected_command_count.is_none() {
                        findings.push(ArtifactValidationFinding::new(
                            ArtifactValidationErrorCode::MissingRequiredField,
                            "manifest missing numeric `command_count` field",
                        ));
                    }
                }
                Err(err) => findings.push(ArtifactValidationFinding::new(
                    ArtifactValidationErrorCode::InvalidManifestJson,
                    format!("invalid manifest JSON: {err}"),
                )),
            },
            Err(err) => findings.push(ArtifactValidationFinding::new(
                ArtifactValidationErrorCode::InvalidManifestJson,
                format!("failed to read manifest file: {err}"),
            )),
        }
    }

    if events_path.exists() {
        match fs::read_to_string(&events_path) {
            Ok(raw) => {
                let mut parsed_count = 0_u64;
                for (line_number, line) in raw.lines().enumerate() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    parsed_count = parsed_count.saturating_add(1);
                    match serde_json::from_str::<HarnessLogEvent>(line) {
                        Ok(event) => {
                            if let Some(expected) = trace_id.as_deref()
                                && event.trace_id != expected
                            {
                                findings.push(ArtifactValidationFinding::new(
                                        ArtifactValidationErrorCode::CorrelationMismatch,
                                        format!(
                                            "events line {} trace_id mismatch: expected `{expected}` found `{}`",
                                            line_number + 1,
                                            event.trace_id
                                        ),
                                    ));
                            }
                            if let Some(expected) = decision_id.as_deref()
                                && event.decision_id != expected
                            {
                                findings.push(ArtifactValidationFinding::new(
                                        ArtifactValidationErrorCode::CorrelationMismatch,
                                        format!(
                                            "events line {} decision_id mismatch: expected `{expected}` found `{}`",
                                            line_number + 1,
                                            event.decision_id
                                        ),
                                    ));
                            }
                            if let Some(expected) = policy_id.as_deref()
                                && event.policy_id != expected
                            {
                                findings.push(ArtifactValidationFinding::new(
                                        ArtifactValidationErrorCode::CorrelationMismatch,
                                        format!(
                                            "events line {} policy_id mismatch: expected `{expected}` found `{}`",
                                            line_number + 1,
                                            event.policy_id
                                        ),
                                    ));
                            }
                            if let Some(expected_seed) = seed
                                && event.seed != expected_seed
                            {
                                findings.push(ArtifactValidationFinding::new(
                                        ArtifactValidationErrorCode::CorrelationMismatch,
                                        format!(
                                            "events line {} seed mismatch: expected `{expected_seed}` found `{}`",
                                            line_number + 1,
                                            event.seed
                                        ),
                                    ));
                            }
                        }
                        Err(err) => findings.push(ArtifactValidationFinding::new(
                            ArtifactValidationErrorCode::InvalidEventJson,
                            format!("invalid event JSON at line {}: {err}", line_number + 1),
                        )),
                    }
                }
                if let Some(expected) = expected_event_count
                    && parsed_count != expected
                {
                    findings.push(ArtifactValidationFinding::new(
                        ArtifactValidationErrorCode::CountMismatch,
                        format!("event count mismatch: manifest={expected} parsed={parsed_count}"),
                    ));
                }
            }
            Err(err) => findings.push(ArtifactValidationFinding::new(
                ArtifactValidationErrorCode::InvalidEventJson,
                format!("failed to read events file: {err}"),
            )),
        }
    }

    if commands_path.exists() {
        match fs::read_to_string(&commands_path) {
            Ok(raw) => {
                let command_count =
                    raw.lines().filter(|line| !line.trim().is_empty()).count() as u64;
                if command_count == 0 {
                    findings.push(ArtifactValidationFinding::new(
                        ArtifactValidationErrorCode::EmptyCommands,
                        "commands.txt contains no commands",
                    ));
                }
                if let Some(expected) = expected_command_count
                    && command_count != expected
                {
                    findings.push(ArtifactValidationFinding::new(
                        ArtifactValidationErrorCode::CountMismatch,
                        format!(
                            "command count mismatch: manifest={expected} parsed={command_count}"
                        ),
                    ));
                }
            }
            Err(err) => findings.push(ArtifactValidationFinding::new(
                ArtifactValidationErrorCode::EmptyCommands,
                format!("failed to read commands.txt: {err}"),
            )),
        }
    }

    let valid = findings.is_empty();
    ArtifactValidationReport {
        schema_version: RGC_ARTIFACT_VALIDATOR_SCHEMA_VERSION.to_string(),
        component: "rgc_artifact_validator".to_string(),
        event: "validate_artifact_triad".to_string(),
        outcome: if valid { "pass" } else { "fail" }.to_string(),
        valid,
        run_id,
        trace_id,
        decision_id,
        policy_id,
        findings,
    }
}

fn load_manifest_correlation_fields(
    manifest_path: &Path,
) -> Result<ManifestCorrelationFields, String> {
    let raw = fs::read_to_string(manifest_path).map_err(|err| err.to_string())?;
    let manifest: HarnessRunManifest = serde_json::from_str(&raw).map_err(|err| err.to_string())?;
    Ok(ManifestCorrelationFields {
        run_id: manifest.run_id,
        scenario_id: manifest.scenario_id,
        fixture_id: manifest.fixture_id,
        lane: manifest.lane,
        seed: manifest.seed,
        trace_id: manifest.trace_id,
        decision_id: manifest.decision_id,
        policy_id: manifest.policy_id,
    })
}

fn triad_repro_command(run_dir: &Path) -> String {
    format!(
        "cargo run -p frankenengine-engine --bin rgc_artifact_validator -- --run-dir {} --pretty",
        run_dir.display()
    )
}

fn bundle_repro_command(bundle_dir: &Path, required_lanes: &[HarnessLane]) -> String {
    let lanes = required_lanes
        .iter()
        .map(|lane| lane.as_str())
        .collect::<Vec<_>>()
        .join(",");
    if lanes.is_empty() {
        format!(
            "cargo run -p frankenengine-engine --bin rgc_artifact_validator -- --bundle-dir {} --pretty",
            bundle_dir.display()
        )
    } else {
        format!(
            "cargo run -p frankenengine-engine --bin rgc_artifact_validator -- --bundle-dir {} --required-lanes {} --pretty",
            bundle_dir.display(),
            lanes
        )
    }
}

pub fn validate_artifact_bundle(
    bundle_dir: impl AsRef<Path>,
    required_lanes: &[HarnessLane],
) -> ArtifactBundleValidationReport {
    let bundle_dir = bundle_dir.as_ref();
    let bundle_dir_label = bundle_dir.display().to_string();
    let mut findings = Vec::new();
    let mut run_dirs = Vec::new();

    if !bundle_dir.exists() {
        findings.push(ArtifactBundleValidationFinding::new(
            ArtifactBundleValidationErrorCode::MissingBundleDirectory,
            format!("bundle directory does not exist: `{bundle_dir_label}`"),
            "operator",
            "create or point to a deterministic artifact bundle directory",
            bundle_repro_command(bundle_dir, required_lanes),
        ));
    } else if !bundle_dir.is_dir() {
        findings.push(ArtifactBundleValidationFinding::new(
            ArtifactBundleValidationErrorCode::MissingBundleDirectory,
            format!("bundle path is not a directory: `{bundle_dir_label}`"),
            "operator",
            "pass a directory that contains artifact run subdirectories",
            bundle_repro_command(bundle_dir, required_lanes),
        ));
    } else {
        if bundle_dir.join("run_manifest.json").exists() {
            run_dirs.push(bundle_dir.to_path_buf());
        }
        if let Ok(entries) = fs::read_dir(bundle_dir) {
            for entry in entries.flatten() {
                let candidate = entry.path();
                if candidate.is_dir() && candidate.join("run_manifest.json").exists() {
                    run_dirs.push(candidate);
                }
            }
        }
    }

    run_dirs.sort();
    run_dirs.dedup();
    if run_dirs.is_empty() {
        findings.push(ArtifactBundleValidationFinding::new(
            ArtifactBundleValidationErrorCode::MissingRunDirectory,
            format!("no run directories with `run_manifest.json` found in `{bundle_dir_label}`"),
            "verification-owner",
            "emit per-lane artifact triads before advanced bundle validation",
            bundle_repro_command(bundle_dir, required_lanes),
        ));
    }

    let mut lane_reports = Vec::new();
    let mut correlation_rows = Vec::<(PathBuf, ManifestCorrelationFields)>::new();
    for run_dir in &run_dirs {
        let triad_report = validate_artifact_triad(run_dir);
        if !triad_report.valid {
            findings.push(ArtifactBundleValidationFinding::new(
                ArtifactBundleValidationErrorCode::InvalidTriad,
                format!(
                    "triad validation failed for `{}` ({} finding(s))",
                    run_dir.display(),
                    triad_report.findings.len()
                ),
                "lane-owner",
                "fix triad-level schema/count/correlation failures for this run directory",
                triad_repro_command(run_dir),
            ));
        }
        lane_reports.push(triad_report);

        let manifest_path = run_dir.join("run_manifest.json");
        match load_manifest_correlation_fields(&manifest_path) {
            Ok(fields) => correlation_rows.push((run_dir.to_path_buf(), fields)),
            Err(error) => findings.push(ArtifactBundleValidationFinding::new(
                ArtifactBundleValidationErrorCode::InvalidManifest,
                format!(
                    "unable to parse `{}` as HarnessRunManifest: {error}",
                    manifest_path.display()
                ),
                "lane-owner",
                "write run manifests using HarnessRunManifest schema",
                triad_repro_command(run_dir),
            )),
        }
    }

    let mut seen_run_ids = BTreeMap::<String, String>::new();
    let mut lane_to_run = BTreeMap::<HarnessLane, String>::new();
    for (run_dir, fields) in &correlation_rows {
        if let Some(existing_run_dir) =
            seen_run_ids.insert(fields.run_id.clone(), run_dir.display().to_string())
        {
            findings.push(ArtifactBundleValidationFinding::new(
                ArtifactBundleValidationErrorCode::DuplicateRunId,
                format!(
                    "duplicate run_id `{}` found in `{}` and `{}`",
                    fields.run_id,
                    existing_run_dir,
                    run_dir.display()
                ),
                "verification-owner",
                "ensure each lane artifact triad uses a unique run_id",
                bundle_repro_command(bundle_dir, required_lanes),
            ));
        }

        if let Some(existing_run_id) = lane_to_run.insert(fields.lane, fields.run_id.clone()) {
            findings.push(ArtifactBundleValidationFinding::new(
                ArtifactBundleValidationErrorCode::DuplicateLane,
                format!(
                    "lane `{}` appears multiple times (run_ids `{}` and `{}`)",
                    fields.lane, existing_run_id, fields.run_id
                ),
                "verification-owner",
                "emit exactly one run triad per lane for advanced correlation checks",
                bundle_repro_command(bundle_dir, required_lanes),
            ));
        }

        let expected = DeterministicTestContext::new(
            fields.scenario_id.clone(),
            fields.fixture_id.clone(),
            fields.lane,
            fields.seed,
        );

        if fields.trace_id != expected.trace_id {
            findings.push(ArtifactBundleValidationFinding::new(
                ArtifactBundleValidationErrorCode::CorrelationMismatch,
                format!(
                    "run `{}` has non-deterministic trace_id: expected `{}` found `{}`",
                    fields.run_id, expected.trace_id, fields.trace_id
                ),
                "lane-owner",
                "regenerate manifest/events using DeterministicTestContext-derived identifiers",
                triad_repro_command(run_dir),
            ));
        }
        if fields.decision_id != expected.decision_id {
            findings.push(ArtifactBundleValidationFinding::new(
                ArtifactBundleValidationErrorCode::CorrelationMismatch,
                format!(
                    "run `{}` has non-deterministic decision_id: expected `{}` found `{}`",
                    fields.run_id, expected.decision_id, fields.decision_id
                ),
                "lane-owner",
                "regenerate manifest/events using DeterministicTestContext-derived identifiers",
                triad_repro_command(run_dir),
            ));
        }
        if fields.policy_id != expected.policy_id {
            findings.push(ArtifactBundleValidationFinding::new(
                ArtifactBundleValidationErrorCode::CorrelationMismatch,
                format!(
                    "run `{}` has non-deterministic policy_id: expected `{}` found `{}`",
                    fields.run_id, expected.policy_id, fields.policy_id
                ),
                "lane-owner",
                "regenerate manifest/events using DeterministicTestContext-derived identifiers",
                triad_repro_command(run_dir),
            ));
        }
    }

    let required_lane_set: BTreeSet<HarnessLane> = required_lanes.iter().copied().collect();
    for lane in &required_lane_set {
        if !lane_to_run.contains_key(lane) {
            findings.push(ArtifactBundleValidationFinding::new(
                ArtifactBundleValidationErrorCode::MissingRequiredLane,
                format!("required lane `{lane}` is missing from bundle"),
                "verification-owner",
                "add triad artifacts for each required lane before promotion checks",
                bundle_repro_command(bundle_dir, required_lanes),
            ));
        }
    }

    let mut correlation_signature = None;
    if let Some((_, baseline)) = correlation_rows.first() {
        let mut lanes = BTreeSet::new();
        lanes.insert(baseline.lane);
        for (run_dir, fields) in correlation_rows.iter().skip(1) {
            lanes.insert(fields.lane);
            if fields.scenario_id != baseline.scenario_id {
                findings.push(ArtifactBundleValidationFinding::new(
                    ArtifactBundleValidationErrorCode::CorrelationMismatch,
                    format!(
                        "cross-lane scenario mismatch: baseline `{}` vs `{}` in `{}`",
                        baseline.scenario_id,
                        fields.scenario_id,
                        run_dir.display()
                    ),
                    "verification-owner",
                    "re-run lanes from the same scenario_id before advanced validation",
                    bundle_repro_command(bundle_dir, required_lanes),
                ));
            }
            if fields.seed != baseline.seed {
                findings.push(ArtifactBundleValidationFinding::new(
                    ArtifactBundleValidationErrorCode::CorrelationMismatch,
                    format!(
                        "cross-lane seed mismatch: baseline `{}` vs `{}` in `{}`",
                        baseline.seed,
                        fields.seed,
                        run_dir.display()
                    ),
                    "verification-owner",
                    "align lane seeds so replay and evidence linkage remain deterministic",
                    bundle_repro_command(bundle_dir, required_lanes),
                ));
            }
        }
        correlation_signature = Some(ArtifactBundleCorrelationSignature {
            scenario_id: baseline.scenario_id.clone(),
            seed: baseline.seed,
            lanes: lanes.into_iter().collect(),
        });
    }

    let valid = findings.is_empty();
    ArtifactBundleValidationReport {
        schema_version: RGC_ARTIFACT_BUNDLE_VALIDATOR_SCHEMA_VERSION.to_string(),
        component: "rgc_artifact_bundle_validator".to_string(),
        event: "validate_artifact_bundle".to_string(),
        outcome: if valid { "pass" } else { "fail" }.to_string(),
        valid,
        bundle_dir: bundle_dir_label,
        correlation_signature,
        run_dirs: run_dirs
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        lane_reports,
        findings,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixtureLoadError {
    InvalidRelativePath { relative_path: String },
    IoRead { path: String, message: String },
    JsonParse { path: String, message: String },
}

impl fmt::Display for FixtureLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRelativePath { relative_path } => write!(
                f,
                "invalid fixture relative path (must not escape root): {relative_path}"
            ),
            Self::IoRead { path, message } => {
                write!(f, "failed to read fixture `{path}`: {message}")
            }
            Self::JsonParse { path, message } => {
                write!(f, "failed to parse fixture JSON `{path}`: {message}")
            }
        }
    }
}

impl Error for FixtureLoadError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactWriteError {
    Io { path: String, message: String },
    Json { path: String, message: String },
}

impl fmt::Display for ArtifactWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, message } => write!(f, "I/O error writing `{path}`: {message}"),
            Self::Json { path, message } => {
                write!(f, "serialization error for `{path}`: {message}")
            }
        }
    }
}

impl Error for ArtifactWriteError {}

pub fn load_json_fixture<T>(
    fixtures_root: impl AsRef<Path>,
    relative_path: &str,
) -> Result<T, FixtureLoadError>
where
    T: DeserializeOwned,
{
    let rel = Path::new(relative_path);
    if relative_path.trim().is_empty()
        || rel.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(FixtureLoadError::InvalidRelativePath {
            relative_path: relative_path.to_string(),
        });
    }

    let path = fixtures_root.as_ref().join(rel);
    let raw = fs::read_to_string(&path).map_err(|err| FixtureLoadError::IoRead {
        path: path.display().to_string(),
        message: err.to_string(),
    })?;
    serde_json::from_str(&raw).map_err(|err| FixtureLoadError::JsonParse {
        path: path.display().to_string(),
        message: err.to_string(),
    })
}

pub fn write_artifact_triad(
    artifact_root: impl AsRef<Path>,
    manifest: &HarnessRunManifest,
    events: &[HarnessLogEvent],
    commands: &[String],
) -> Result<HarnessArtifactTriad, ArtifactWriteError> {
    let run_dir = artifact_root.as_ref().join(&manifest.run_id);
    fs::create_dir_all(&run_dir).map_err(|err| ArtifactWriteError::Io {
        path: run_dir.display().to_string(),
        message: err.to_string(),
    })?;

    let manifest_path = run_dir.join("run_manifest.json");
    let events_path = run_dir.join("events.jsonl");
    let commands_path = run_dir.join("commands.txt");

    let manifest_json =
        serde_json::to_vec_pretty(manifest).map_err(|err| ArtifactWriteError::Json {
            path: manifest_path.display().to_string(),
            message: err.to_string(),
        })?;
    write_atomic(&manifest_path, &manifest_json)?;

    let mut events_jsonl = String::new();
    for event in events {
        let line = serde_json::to_string(event).map_err(|err| ArtifactWriteError::Json {
            path: events_path.display().to_string(),
            message: err.to_string(),
        })?;
        events_jsonl.push_str(&line);
        events_jsonl.push('\n');
    }
    write_atomic(&events_path, events_jsonl.as_bytes())?;

    let mut commands_buf = String::new();
    for command in commands {
        commands_buf.push_str(command);
        commands_buf.push('\n');
    }
    write_atomic(&commands_path, commands_buf.as_bytes())?;

    Ok(HarnessArtifactTriad {
        run_dir,
        manifest_path,
        events_path,
        commands_path,
    })
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ArtifactWriteError> {
    let tmp_path = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&tmp_path, bytes).map_err(|err| ArtifactWriteError::Io {
        path: tmp_path.display().to_string(),
        message: err.to_string(),
    })?;
    fs::rename(&tmp_path, path).map_err(|err| ArtifactWriteError::Io {
        path: path.display().to_string(),
        message: err.to_string(),
    })
}

fn sanitize_label(label: &str) -> String {
    let sanitized: String = label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect();
    sanitized.trim_matches('-').to_lowercase()
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct DemoFixture {
        scenario: String,
        value: u64,
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "franken_engine_{label}_{nanos}_{}",
            std::process::id()
        ))
    }

    #[test]
    fn deterministic_context_ids_are_stable_for_same_inputs() {
        let a = DeterministicTestContext::new("rgc-052", "fixture-a", HarnessLane::Runtime, 42);
        let b = DeterministicTestContext::new("rgc-052", "fixture-a", HarnessLane::Runtime, 42);
        assert_eq!(a.trace_id, b.trace_id);
        assert_eq!(a.decision_id, b.decision_id);
        assert_eq!(a.policy_id, b.policy_id);
    }

    #[test]
    fn deterministic_context_ids_change_when_seed_changes() {
        let a = DeterministicTestContext::new("rgc-052", "fixture-a", HarnessLane::Runtime, 1);
        let b = DeterministicTestContext::new("rgc-052", "fixture-a", HarnessLane::Runtime, 2);
        assert_ne!(a.trace_id, b.trace_id);
        assert_ne!(a.decision_id, b.decision_id);
    }

    #[test]
    fn fixture_loader_rejects_parent_traversal() {
        let root = PathBuf::from("/tmp");
        let error = load_json_fixture::<DemoFixture>(&root, "../escape.json")
            .expect_err("path traversal must fail");
        assert!(matches!(
            error,
            FixtureLoadError::InvalidRelativePath { .. }
        ));
    }

    #[test]
    fn fixture_loader_reads_valid_json_fixture() {
        let root = temp_dir("fixture_loader");
        fs::create_dir_all(&root).expect("create temp fixture root");
        let fixture_path = root.join("fixture.json");
        fs::write(
            &fixture_path,
            "{\"scenario\":\"runtime-happy\",\"value\":7}\n",
        )
        .expect("write fixture");

        let loaded: DemoFixture =
            load_json_fixture(&root, "fixture.json").expect("fixture should load");
        assert_eq!(
            loaded,
            DemoFixture {
                scenario: "runtime-happy".to_string(),
                value: 7
            }
        );
    }

    #[test]
    fn artifact_writer_emits_manifest_events_and_commands() {
        let root = temp_dir("artifact_writer");
        let context = DeterministicTestContext::new("rgc-052", "fixture-a", HarnessLane::Parser, 9);
        let run_id = context.default_run_id();
        let events = vec![
            context.event(EventInput {
                sequence: 0,
                component: "rgc_test_harness",
                event: "fixture_loaded",
                outcome: "pass",
                error_code: None,
                timing_us: 11,
                timestamp_unix_ms: 1_700_000_000_000,
            }),
            context.event(EventInput {
                sequence: 1,
                component: "rgc_test_harness",
                event: "assertions_complete",
                outcome: "pass",
                error_code: None,
                timing_us: 23,
                timestamp_unix_ms: 1_700_000_000_001,
            }),
        ];
        let commands = vec![
            "cargo check -p frankenengine-engine --test rgc_test_harness_integration".to_string(),
            "cargo test -p frankenengine-engine --test rgc_test_harness_integration".to_string(),
        ];
        let manifest = HarnessRunManifest::from_context(
            &context,
            run_id,
            events.len(),
            commands.len(),
            "./scripts/e2e/rgc_test_harness_replay.sh ci",
            1_700_000_000_111,
        );

        let triad = write_artifact_triad(&root, &manifest, &events, &commands)
            .expect("artifact triad should write");
        assert!(triad.manifest_path.exists());
        assert!(triad.events_path.exists());
        assert!(triad.commands_path.exists());

        let saved_manifest: HarnessRunManifest =
            serde_json::from_str(&fs::read_to_string(&triad.manifest_path).expect("read manifest"))
                .expect("manifest JSON should parse");
        assert_eq!(saved_manifest.event_count, 2);
        assert_eq!(saved_manifest.command_count, 2);
        assert!(!saved_manifest.env_fingerprint.trim().is_empty());

        let saved_events = fs::read_to_string(&triad.events_path).expect("read events");
        assert_eq!(saved_events.lines().count(), 2);
    }

    #[test]
    fn baseline_registry_covers_runtime_module_security_happy_and_failure() {
        let registry = baseline_e2e_scenario_registry();
        assert_eq!(registry.len(), 6, "expected 3 domains x 2 outcomes");

        for domain in [
            BaselineScenarioDomain::Runtime,
            BaselineScenarioDomain::Module,
            BaselineScenarioDomain::Security,
        ] {
            let happy = registry
                .iter()
                .filter(|scenario| {
                    scenario.domain == domain
                        && scenario.outcome == BaselineScenarioOutcome::HappyPath
                })
                .count();
            let canonical_failure = registry
                .iter()
                .filter(|scenario| {
                    scenario.domain == domain
                        && scenario.outcome == BaselineScenarioOutcome::CanonicalFailure
                })
                .count();
            assert_eq!(happy, 1, "missing happy-path scenario for {domain}");
            assert_eq!(
                canonical_failure, 1,
                "missing canonical-failure scenario for {domain}"
            );
        }
    }

    #[test]
    fn baseline_selection_is_deterministic_and_filterable() {
        let first = select_baseline_e2e_scenarios(
            &[
                BaselineScenarioDomain::Runtime,
                BaselineScenarioDomain::Security,
            ],
            true,
        );
        let second = select_baseline_e2e_scenarios(
            &[
                BaselineScenarioDomain::Runtime,
                BaselineScenarioDomain::Security,
            ],
            true,
        );
        assert_eq!(first, second, "selection must be deterministic");
        assert_eq!(
            first.len(),
            4,
            "runtime+security should return four scenarios"
        );

        let happy_only = select_baseline_e2e_scenarios(&[], false);
        assert_eq!(
            happy_only.len(),
            3,
            "happy-only should include one per domain"
        );
        assert!(
            happy_only
                .iter()
                .all(|scenario| scenario.outcome == BaselineScenarioOutcome::HappyPath)
        );
    }

    #[test]
    fn artifact_validator_accepts_valid_harness_triad() {
        let root = temp_dir("artifact_validator_valid");
        let context = DeterministicTestContext::new(
            "rgc-053a-runtime-happy",
            "runtime-smoke-happy",
            HarnessLane::E2e,
            53,
        );
        let run_id = context.default_run_id();
        let events = vec![context.event(EventInput {
            sequence: 0,
            component: "runtime_lane",
            event: "execute_runtime_smoke",
            outcome: "pass",
            error_code: None,
            timing_us: 31,
            timestamp_unix_ms: 1_700_100_000_000,
        })];
        let commands = vec![
            "cargo test -p frankenengine-engine --test rgc_test_harness_integration".to_string(),
        ];
        let manifest = HarnessRunManifest::from_context(
            &context,
            run_id,
            events.len(),
            commands.len(),
            "./scripts/e2e/rgc_test_harness_replay.sh ci",
            1_700_100_000_100,
        );

        let triad = write_artifact_triad(&root, &manifest, &events, &commands)
            .expect("artifact triad should write");
        let report = validate_artifact_triad(&triad.run_dir);
        assert!(
            report.valid,
            "expected valid report, got: {:?}",
            report.findings
        );
        assert!(report.findings.is_empty());
        assert_eq!(report.run_id.as_deref(), Some(manifest.run_id.as_str()));
        assert_eq!(report.trace_id.as_deref(), Some(manifest.trace_id.as_str()));
    }

    #[test]
    fn artifact_validator_reports_missing_and_malformed_artifacts() {
        let root = temp_dir("artifact_validator_invalid");
        let run_dir = root.join("broken-run");
        fs::create_dir_all(&run_dir).expect("create run dir");

        fs::write(
            run_dir.join("run_manifest.json"),
            r#"{"schema_version":"wrong.schema","run_id":"","trace_id":"","decision_id":"","policy_id":"","seed":"not-a-number"}"#,
        )
        .expect("write malformed manifest");
        fs::write(run_dir.join("events.jsonl"), "{not-json}\n").expect("write malformed events");
        fs::write(run_dir.join("commands.txt"), "\n").expect("write empty commands");

        let report = validate_artifact_triad(&run_dir);
        assert!(!report.valid);
        assert!(!report.findings.is_empty());
        assert!(report.findings.iter().any(|finding| {
            finding.error_code == ArtifactValidationErrorCode::MissingRequiredField
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.error_code == ArtifactValidationErrorCode::InvalidEventJson
        }));
        assert!(
            report.findings.iter().any(|finding| {
                finding.error_code == ArtifactValidationErrorCode::EmptyCommands
            })
        );
    }

    fn write_lane_triad(
        bundle_dir: &Path,
        scenario_id: &str,
        fixture_id: &str,
        lane: HarnessLane,
        seed: u64,
    ) -> HarnessArtifactTriad {
        let context = DeterministicTestContext::new(scenario_id, fixture_id, lane, seed);
        let run_id = context.default_run_id();
        let events = vec![context.event(EventInput {
            sequence: 0,
            component: "rgc_bundle_validator_test",
            event: "lane_complete",
            outcome: "pass",
            error_code: None,
            timing_us: 25,
            timestamp_unix_ms: 1_700_300_000_000,
        })];
        let commands = vec![
            "cargo test -p frankenengine-engine --test rgc_test_harness_integration".to_string(),
        ];
        let manifest = HarnessRunManifest::from_context(
            &context,
            run_id,
            events.len(),
            commands.len(),
            "./scripts/e2e/rgc_artifact_validator_phase_b_replay.sh ci",
            1_700_300_000_100,
        );
        write_artifact_triad(bundle_dir, &manifest, &events, &commands)
            .expect("bundle triad should write")
    }

    #[test]
    fn artifact_bundle_validator_accepts_valid_multi_lane_bundle() {
        let root = temp_dir("artifact_bundle_validator_valid");
        let bundle_dir = root.join("bundle");
        fs::create_dir_all(&bundle_dir).expect("create bundle dir");

        for lane in [
            HarnessLane::Runtime,
            HarnessLane::Security,
            HarnessLane::E2e,
        ] {
            write_lane_triad(&bundle_dir, "rgc-062b-happy", "fixture-shared", lane, 6202);
        }

        let report = validate_artifact_bundle(
            &bundle_dir,
            &[
                HarnessLane::Runtime,
                HarnessLane::Security,
                HarnessLane::E2e,
            ],
        );
        assert!(
            report.valid,
            "expected valid bundle report, findings: {:?}",
            report.findings
        );
        assert!(report.findings.is_empty());
        assert_eq!(report.lane_reports.len(), 3);
        let signature = report
            .correlation_signature
            .expect("signature should be present");
        assert_eq!(signature.scenario_id, "rgc-062b-happy");
        assert_eq!(signature.seed, 6202);
        assert_eq!(signature.lanes.len(), 3);
    }

    #[test]
    fn artifact_bundle_validator_reports_missing_required_lane() {
        let root = temp_dir("artifact_bundle_validator_missing_lane");
        let bundle_dir = root.join("bundle");
        fs::create_dir_all(&bundle_dir).expect("create bundle dir");

        write_lane_triad(
            &bundle_dir,
            "rgc-062b-missing-lane",
            "fixture-shared",
            HarnessLane::Runtime,
            6203,
        );

        let report =
            validate_artifact_bundle(&bundle_dir, &[HarnessLane::Runtime, HarnessLane::Security]);
        assert!(!report.valid);
        assert!(report.findings.iter().any(|finding| {
            finding.error_code == ArtifactBundleValidationErrorCode::MissingRequiredLane
        }));
    }

    #[test]
    fn artifact_bundle_validator_detects_cross_lane_drift_even_when_triads_self_consistent() {
        let root = temp_dir("artifact_bundle_validator_cross_lane_drift");
        let bundle_dir = root.join("bundle");
        fs::create_dir_all(&bundle_dir).expect("create bundle dir");

        write_lane_triad(
            &bundle_dir,
            "rgc-062b-cross-lane",
            "fixture-shared",
            HarnessLane::Runtime,
            6204,
        );
        let security_triad = write_lane_triad(
            &bundle_dir,
            "rgc-062b-cross-lane",
            "fixture-shared",
            HarnessLane::Security,
            6204,
        );

        let bad_trace = "trace-rgc-corrupted";
        let manifest_path = security_triad.run_dir.join("run_manifest.json");
        let mut manifest: HarnessRunManifest = serde_json::from_str(
            &fs::read_to_string(&manifest_path).expect("read security manifest"),
        )
        .expect("parse security manifest");
        manifest.trace_id = bad_trace.to_string();
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).expect("serialize derived Serialize"),
        )
        .expect("write corrupted manifest");

        let events_path = security_triad.run_dir.join("events.jsonl");
        let events_raw = fs::read_to_string(&events_path).expect("read security events");
        let mut rewritten = String::new();
        for line in events_raw.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let mut event: HarnessLogEvent =
                serde_json::from_str(line).expect("parse security event");
            event.trace_id = bad_trace.to_string();
            rewritten
                .push_str(&serde_json::to_string(&event).expect("serialize derived Serialize"));
            rewritten.push('\n');
        }
        fs::write(&events_path, rewritten).expect("write corrupted events");

        let report =
            validate_artifact_bundle(&bundle_dir, &[HarnessLane::Runtime, HarnessLane::Security]);
        assert!(!report.valid);
        assert!(
            report.lane_reports.iter().all(|lane| lane.valid),
            "triads were rewritten consistently and should remain triad-valid"
        );
        assert!(report.findings.iter().any(|finding| {
            finding.error_code == ArtifactBundleValidationErrorCode::CorrelationMismatch
                && finding.message.contains("non-deterministic trace_id")
        }));
    }

    #[test]
    fn artifact_bundle_validator_rejects_duplicate_lanes() {
        let root = temp_dir("artifact_bundle_validator_duplicate_lane");
        let bundle_dir = root.join("bundle");
        fs::create_dir_all(&bundle_dir).expect("create bundle dir");

        write_lane_triad(
            &bundle_dir,
            "rgc-062b-dup-lane",
            "fixture-a",
            HarnessLane::Runtime,
            6205,
        );
        write_lane_triad(
            &bundle_dir,
            "rgc-062b-dup-lane",
            "fixture-b",
            HarnessLane::Runtime,
            6205,
        );

        let report = validate_artifact_bundle(&bundle_dir, &[HarnessLane::Runtime]);
        assert!(!report.valid);
        assert!(report.findings.iter().any(|finding| {
            finding.error_code == ArtifactBundleValidationErrorCode::DuplicateLane
        }));
    }

    // --- Enrichment: HarnessLane coverage ---

    #[test]
    fn harness_lane_as_str_all_variants() {
        assert_eq!(HarnessLane::Parser.as_str(), "parser");
        assert_eq!(HarnessLane::Runtime.as_str(), "runtime");
        assert_eq!(HarnessLane::Security.as_str(), "security");
        assert_eq!(HarnessLane::Governance.as_str(), "governance");
        assert_eq!(HarnessLane::E2e.as_str(), "e2e");
    }

    #[test]
    fn harness_lane_display_matches_as_str() {
        for lane in [
            HarnessLane::Parser,
            HarnessLane::Runtime,
            HarnessLane::Security,
            HarnessLane::Governance,
            HarnessLane::E2e,
        ] {
            assert_eq!(format!("{lane}"), lane.as_str());
        }
    }

    #[test]
    fn harness_lane_serde_round_trip_all_variants() {
        for lane in [
            HarnessLane::Parser,
            HarnessLane::Runtime,
            HarnessLane::Security,
            HarnessLane::Governance,
            HarnessLane::E2e,
        ] {
            let json = serde_json::to_string(&lane).expect("serialize derived Serialize");
            let restored: HarnessLane =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(lane, restored);
        }
    }

    // --- Enrichment: BaselineScenarioDomain coverage ---

    #[test]
    fn baseline_scenario_domain_as_str_all_variants() {
        assert_eq!(BaselineScenarioDomain::Runtime.as_str(), "runtime");
        assert_eq!(BaselineScenarioDomain::Module.as_str(), "module");
        assert_eq!(BaselineScenarioDomain::Security.as_str(), "security");
    }

    #[test]
    fn baseline_scenario_domain_display_matches_as_str() {
        for domain in [
            BaselineScenarioDomain::Runtime,
            BaselineScenarioDomain::Module,
            BaselineScenarioDomain::Security,
        ] {
            assert_eq!(format!("{domain}"), domain.as_str());
        }
    }

    #[test]
    fn baseline_scenario_domain_serde_round_trip() {
        for domain in [
            BaselineScenarioDomain::Runtime,
            BaselineScenarioDomain::Module,
            BaselineScenarioDomain::Security,
        ] {
            let json = serde_json::to_string(&domain).expect("serialize derived Serialize");
            let restored: BaselineScenarioDomain =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(domain, restored);
        }
    }

    // --- Enrichment: BaselineScenarioOutcome serde ---

    #[test]
    fn baseline_scenario_outcome_serde_round_trip() {
        for outcome in [
            BaselineScenarioOutcome::HappyPath,
            BaselineScenarioOutcome::CanonicalFailure,
        ] {
            let json = serde_json::to_string(&outcome).expect("serialize derived Serialize");
            let restored: BaselineScenarioOutcome =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(outcome, restored);
        }
    }

    // --- Enrichment: DeterministicTestContext edge cases ---

    #[test]
    fn context_ids_differ_when_scenario_changes() {
        let a = DeterministicTestContext::new("scenario-a", "fixture-a", HarnessLane::Runtime, 42);
        let b = DeterministicTestContext::new("scenario-b", "fixture-a", HarnessLane::Runtime, 42);
        assert_ne!(a.trace_id, b.trace_id);
        assert_ne!(a.decision_id, b.decision_id);
    }

    #[test]
    fn context_ids_differ_when_fixture_changes() {
        let a = DeterministicTestContext::new("scenario-a", "fixture-a", HarnessLane::Runtime, 42);
        let b = DeterministicTestContext::new("scenario-a", "fixture-b", HarnessLane::Runtime, 42);
        assert_ne!(a.trace_id, b.trace_id);
        assert_ne!(a.decision_id, b.decision_id);
    }

    #[test]
    fn context_ids_differ_when_lane_changes() {
        let a = DeterministicTestContext::new("scenario-a", "fixture-a", HarnessLane::Parser, 42);
        let b = DeterministicTestContext::new("scenario-a", "fixture-a", HarnessLane::Security, 42);
        assert_ne!(a.trace_id, b.trace_id);
        assert_ne!(a.decision_id, b.decision_id);
        assert_ne!(a.policy_id, b.policy_id);
    }

    #[test]
    fn context_default_run_id_format() {
        let ctx = DeterministicTestContext::new("rgc-052", "fixture-a", HarnessLane::Runtime, 42);
        let run_id = ctx.default_run_id();
        assert!(run_id.starts_with("run-rgc-052-"));
        assert!(run_id.len() > "run-rgc-052-".len());
    }

    #[test]
    fn context_serde_round_trip() {
        let ctx = DeterministicTestContext::new("rgc-052", "fixture-a", HarnessLane::Security, 7);
        let json = serde_json::to_string(&ctx).expect("serialize derived Serialize");
        let restored: DeterministicTestContext =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(ctx, restored);
    }

    // --- Enrichment: HarnessLogEvent serde ---

    #[test]
    fn harness_log_event_serde_round_trip() {
        let ctx = DeterministicTestContext::new("scenario-rt", "fix-1", HarnessLane::Runtime, 99);
        let event = ctx.event(EventInput {
            sequence: 5,
            component: "parser",
            event: "parse_complete",
            outcome: "pass",
            error_code: None,
            timing_us: 123,
            timestamp_unix_ms: 1_700_000_000_000,
        });
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        let restored: HarnessLogEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(event, restored);
    }

    #[test]
    fn harness_log_event_with_error_code() {
        let ctx = DeterministicTestContext::new("scenario-err", "fix-1", HarnessLane::Security, 1);
        let event = ctx.event(EventInput {
            sequence: 0,
            component: "guardplane",
            event: "containment_triggered",
            outcome: "fail",
            error_code: Some("FE-SEC-0001"),
            timing_us: 50,
            timestamp_unix_ms: 1_700_000_000_100,
        });
        assert_eq!(event.error_code.as_deref(), Some("FE-SEC-0001"));
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        let restored: HarnessLogEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(event, restored);
    }

    // --- Enrichment: HarnessRunManifest serde and determinism ---

    #[test]
    fn manifest_serde_round_trip() {
        let ctx = DeterministicTestContext::new("rgc-052", "fixture-a", HarnessLane::E2e, 53);
        let manifest =
            HarnessRunManifest::from_context(&ctx, "run-001", 3, 2, "replay.sh", 1_700_000_000_000);
        let json = serde_json::to_string(&manifest).expect("serialize derived Serialize");
        let restored: HarnessRunManifest =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(manifest, restored);
    }

    #[test]
    fn manifest_env_fingerprint_is_deterministic() {
        let ctx = DeterministicTestContext::new("rgc-052", "fixture-a", HarnessLane::E2e, 53);
        let m1 =
            HarnessRunManifest::from_context(&ctx, "run-001", 3, 2, "replay.sh", 1_700_000_000_000);
        let m2 =
            HarnessRunManifest::from_context(&ctx, "run-001", 3, 2, "replay.sh", 1_700_000_000_001);
        assert_eq!(
            m1.env_fingerprint, m2.env_fingerprint,
            "fingerprint must not depend on timestamp"
        );
    }

    #[test]
    fn manifest_env_fingerprint_changes_with_different_replay_command() {
        let ctx = DeterministicTestContext::new("rgc-052", "fixture-a", HarnessLane::E2e, 53);
        let m1 = HarnessRunManifest::from_context(
            &ctx,
            "run-001",
            3,
            2,
            "replay-a.sh",
            1_700_000_000_000,
        );
        let m2 = HarnessRunManifest::from_context(
            &ctx,
            "run-001",
            3,
            2,
            "replay-b.sh",
            1_700_000_000_000,
        );
        assert_ne!(m1.env_fingerprint, m2.env_fingerprint);
    }

    // --- Enrichment: ArtifactValidationErrorCode serde ---

    #[test]
    fn artifact_validation_error_code_serde_round_trip_all_variants() {
        for code in [
            ArtifactValidationErrorCode::MissingArtifact,
            ArtifactValidationErrorCode::InvalidManifestJson,
            ArtifactValidationErrorCode::InvalidEventJson,
            ArtifactValidationErrorCode::MissingRequiredField,
            ArtifactValidationErrorCode::CorrelationMismatch,
            ArtifactValidationErrorCode::CountMismatch,
            ArtifactValidationErrorCode::EmptyCommands,
        ] {
            let json = serde_json::to_string(&code).expect("serialize derived Serialize");
            let restored: ArtifactValidationErrorCode =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(code, restored);
        }
    }

    // --- Enrichment: ArtifactBundleValidationErrorCode serde ---

    #[test]
    fn artifact_bundle_validation_error_code_serde_round_trip_all_variants() {
        for code in [
            ArtifactBundleValidationErrorCode::MissingBundleDirectory,
            ArtifactBundleValidationErrorCode::MissingRunDirectory,
            ArtifactBundleValidationErrorCode::InvalidManifest,
            ArtifactBundleValidationErrorCode::InvalidTriad,
            ArtifactBundleValidationErrorCode::DuplicateLane,
            ArtifactBundleValidationErrorCode::DuplicateRunId,
            ArtifactBundleValidationErrorCode::MissingRequiredLane,
            ArtifactBundleValidationErrorCode::CorrelationMismatch,
        ] {
            let json = serde_json::to_string(&code).expect("serialize derived Serialize");
            let restored: ArtifactBundleValidationErrorCode =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(code, restored);
        }
    }

    // --- Enrichment: sanitize_label ---

    #[test]
    fn sanitize_label_replaces_special_chars_and_lowercases() {
        assert_eq!(sanitize_label("Foo Bar!Baz"), "foo-bar-baz");
    }

    #[test]
    fn sanitize_label_trims_leading_trailing_dashes() {
        assert_eq!(sanitize_label("--hello--"), "hello");
    }

    #[test]
    fn sanitize_label_preserves_underscores_and_hyphens() {
        assert_eq!(sanitize_label("a_b-c"), "a_b-c");
    }

    #[test]
    fn sanitize_label_empty_input() {
        assert_eq!(sanitize_label(""), "");
    }

    // --- Enrichment: FixtureLoadError Display ---

    #[test]
    fn fixture_load_error_display_invalid_relative_path() {
        let err = FixtureLoadError::InvalidRelativePath {
            relative_path: "../escape".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("../escape"));
        assert!(msg.contains("must not escape"));
    }

    #[test]
    fn fixture_load_error_display_io_read() {
        let err = FixtureLoadError::IoRead {
            path: "/tmp/missing.json".to_string(),
            message: "not found".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("/tmp/missing.json"));
        assert!(msg.contains("not found"));
    }

    #[test]
    fn fixture_load_error_display_json_parse() {
        let err = FixtureLoadError::JsonParse {
            path: "/tmp/bad.json".to_string(),
            message: "unexpected token".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("/tmp/bad.json"));
        assert!(msg.contains("unexpected token"));
    }

    #[test]
    fn fixture_load_error_implements_std_error() {
        let err = FixtureLoadError::InvalidRelativePath {
            relative_path: "..".to_string(),
        };
        let _: &dyn std::error::Error = &err;
    }

    // --- Enrichment: ArtifactWriteError Display ---

    #[test]
    fn artifact_write_error_display_io() {
        let err = ArtifactWriteError::Io {
            path: "/tmp/out.json".to_string(),
            message: "permission denied".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("/tmp/out.json"));
        assert!(msg.contains("permission denied"));
    }

    #[test]
    fn artifact_write_error_display_json() {
        let err = ArtifactWriteError::Json {
            path: "/tmp/data.json".to_string(),
            message: "recursive structure".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("/tmp/data.json"));
        assert!(msg.contains("recursive structure"));
    }

    #[test]
    fn artifact_write_error_implements_std_error() {
        let err = ArtifactWriteError::Io {
            path: "test".to_string(),
            message: "fail".to_string(),
        };
        let _: &dyn std::error::Error = &err;
    }

    // --- Enrichment: load_json_fixture security/edge cases ---

    #[test]
    fn fixture_loader_rejects_empty_path() {
        let root = PathBuf::from("/tmp");
        let error = load_json_fixture::<DemoFixture>(&root, "").expect_err("empty path must fail");
        assert!(matches!(
            error,
            FixtureLoadError::InvalidRelativePath { .. }
        ));
    }

    #[test]
    fn fixture_loader_rejects_absolute_path() {
        let root = PathBuf::from("/tmp");
        let error = load_json_fixture::<DemoFixture>(&root, "/etc/passwd")
            .expect_err("absolute path must fail");
        assert!(matches!(
            error,
            FixtureLoadError::InvalidRelativePath { .. }
        ));
    }

    #[test]
    fn fixture_loader_missing_file_returns_io_error() {
        let root = temp_dir("fixture_loader_missing");
        fs::create_dir_all(&root).expect("create temp dir");
        let error = load_json_fixture::<DemoFixture>(&root, "nonexistent.json")
            .expect_err("missing file must fail");
        assert!(matches!(error, FixtureLoadError::IoRead { .. }));
    }

    #[test]
    fn fixture_loader_invalid_json_returns_parse_error() {
        let root = temp_dir("fixture_loader_bad_json");
        fs::create_dir_all(&root).expect("create temp dir");
        fs::write(root.join("bad.json"), "not-json").expect("write bad fixture");
        let error =
            load_json_fixture::<DemoFixture>(&root, "bad.json").expect_err("bad JSON must fail");
        assert!(matches!(error, FixtureLoadError::JsonParse { .. }));
    }

    // --- Enrichment: validate_artifact_triad edge cases ---

    #[test]
    fn validate_triad_missing_all_files() {
        let root = temp_dir("validate_triad_empty");
        fs::create_dir_all(&root).expect("create temp dir");
        let report = validate_artifact_triad(&root);
        assert!(!report.valid);
        assert!(report.findings.iter().any(|f| {
            f.error_code == ArtifactValidationErrorCode::MissingArtifact
                && f.message.contains("run_manifest.json")
        }));
        assert!(report.findings.iter().any(|f| {
            f.error_code == ArtifactValidationErrorCode::MissingArtifact
                && f.message.contains("events.jsonl")
        }));
        assert!(report.findings.iter().any(|f| {
            f.error_code == ArtifactValidationErrorCode::MissingArtifact
                && f.message.contains("commands.txt")
        }));
    }

    #[test]
    fn validate_triad_event_count_mismatch() {
        let root = temp_dir("validate_triad_count_mismatch");
        let ctx = DeterministicTestContext::new("count-test", "fix-1", HarnessLane::Runtime, 1);
        let run_id = ctx.default_run_id();
        let events = vec![ctx.event(EventInput {
            sequence: 0,
            component: "test",
            event: "step",
            outcome: "pass",
            error_code: None,
            timing_us: 10,
            timestamp_unix_ms: 1_700_100_000_000,
        })];
        let commands = vec!["cargo test".to_string()];
        // Manifest claims 5 events but only 1 written
        let manifest =
            HarnessRunManifest::from_context(&ctx, run_id, 5, 1, "replay.sh", 1_700_100_000_100);
        let triad = write_artifact_triad(&root, &manifest, &events, &commands)
            .expect("write should succeed");
        let report = validate_artifact_triad(&triad.run_dir);
        assert!(!report.valid);
        assert!(report.findings.iter().any(|f| {
            f.error_code == ArtifactValidationErrorCode::CountMismatch
                && f.message.contains("event count")
        }));
    }

    #[test]
    fn validate_triad_command_count_mismatch() {
        let root = temp_dir("validate_triad_cmd_count_mismatch");
        let ctx = DeterministicTestContext::new("cmd-count-test", "fix-1", HarnessLane::Runtime, 1);
        let run_id = ctx.default_run_id();
        let events = vec![ctx.event(EventInput {
            sequence: 0,
            component: "test",
            event: "step",
            outcome: "pass",
            error_code: None,
            timing_us: 10,
            timestamp_unix_ms: 1_700_100_000_000,
        })];
        let commands = vec!["cargo test".to_string()];
        // Manifest claims 3 commands but only 1 written
        let manifest =
            HarnessRunManifest::from_context(&ctx, run_id, 1, 3, "replay.sh", 1_700_100_000_100);
        let triad = write_artifact_triad(&root, &manifest, &events, &commands)
            .expect("write should succeed");
        let report = validate_artifact_triad(&triad.run_dir);
        assert!(!report.valid);
        assert!(report.findings.iter().any(|f| {
            f.error_code == ArtifactValidationErrorCode::CountMismatch
                && f.message.contains("command count")
        }));
    }

    // --- Enrichment: validate_artifact_bundle edge cases ---

    #[test]
    fn validate_bundle_nonexistent_directory() {
        let root = PathBuf::from("/tmp/franken_engine_nonexistent_bundle_dir_never_exists");
        let report = validate_artifact_bundle(&root, &[HarnessLane::Runtime]);
        assert!(!report.valid);
        assert!(report.findings.iter().any(|f| {
            f.error_code == ArtifactBundleValidationErrorCode::MissingBundleDirectory
        }));
    }

    #[test]
    fn validate_bundle_empty_directory() {
        let root = temp_dir("validate_bundle_empty_dir");
        fs::create_dir_all(&root).expect("create bundle dir");
        let report = validate_artifact_bundle(&root, &[HarnessLane::Runtime]);
        assert!(!report.valid);
        assert!(
            report.findings.iter().any(|f| {
                f.error_code == ArtifactBundleValidationErrorCode::MissingRunDirectory
            })
        );
    }

    #[test]
    fn validate_bundle_cross_lane_seed_mismatch() {
        let root = temp_dir("validate_bundle_seed_mismatch");
        let bundle_dir = root.join("bundle");
        fs::create_dir_all(&bundle_dir).expect("create bundle dir");

        // Runtime lane with seed 100
        write_lane_triad(
            &bundle_dir,
            "rgc-seed-test",
            "fixture-shared",
            HarnessLane::Runtime,
            100,
        );
        // Security lane with seed 200 (mismatch)
        write_lane_triad(
            &bundle_dir,
            "rgc-seed-test",
            "fixture-shared",
            HarnessLane::Security,
            200,
        );

        let report =
            validate_artifact_bundle(&bundle_dir, &[HarnessLane::Runtime, HarnessLane::Security]);
        assert!(!report.valid);
        assert!(report.findings.iter().any(|f| {
            f.error_code == ArtifactBundleValidationErrorCode::CorrelationMismatch
                && f.message.contains("seed mismatch")
        }));
    }

    #[test]
    fn validate_bundle_cross_lane_scenario_mismatch() {
        let root = temp_dir("validate_bundle_scenario_mismatch");
        let bundle_dir = root.join("bundle");
        fs::create_dir_all(&bundle_dir).expect("create bundle dir");

        write_lane_triad(
            &bundle_dir,
            "scenario-alpha",
            "fixture-shared",
            HarnessLane::Runtime,
            42,
        );
        write_lane_triad(
            &bundle_dir,
            "scenario-beta",
            "fixture-shared",
            HarnessLane::Security,
            42,
        );

        let report =
            validate_artifact_bundle(&bundle_dir, &[HarnessLane::Runtime, HarnessLane::Security]);
        assert!(!report.valid);
        assert!(report.findings.iter().any(|f| {
            f.error_code == ArtifactBundleValidationErrorCode::CorrelationMismatch
                && f.message.contains("scenario mismatch")
        }));
    }

    // --- Enrichment: select_baseline_e2e_scenarios edge cases ---

    #[test]
    fn select_scenarios_single_domain_with_failures() {
        let selected = select_baseline_e2e_scenarios(&[BaselineScenarioDomain::Security], true);
        assert_eq!(selected.len(), 2, "security domain has 1 happy + 1 failure");
        assert!(
            selected
                .iter()
                .all(|s| s.domain == BaselineScenarioDomain::Security)
        );
    }

    #[test]
    fn select_scenarios_single_domain_happy_only() {
        let selected = select_baseline_e2e_scenarios(&[BaselineScenarioDomain::Module], false);
        assert_eq!(
            selected.len(),
            1,
            "module domain happy-only should return 1"
        );
        assert_eq!(selected[0].outcome, BaselineScenarioOutcome::HappyPath);
        assert_eq!(selected[0].domain, BaselineScenarioDomain::Module);
    }

    #[test]
    fn select_scenarios_all_domains_with_failures() {
        let selected = select_baseline_e2e_scenarios(&[], true);
        assert_eq!(selected.len(), 6, "3 domains * 2 outcomes = 6");
    }

    // --- Enrichment: BaselineE2eScenario serde ---

    #[test]
    fn baseline_e2e_scenario_serde_round_trip() {
        let scenario = BaselineE2eScenario::new(
            "test-scenario",
            "test-fixture",
            BaselineScenarioDomain::Runtime,
            BaselineScenarioOutcome::HappyPath,
            "runtime_lane",
            "execute",
            None,
        );
        let json = serde_json::to_string(&scenario).expect("serialize derived Serialize");
        let restored: BaselineE2eScenario =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(scenario, restored);
    }

    #[test]
    fn baseline_e2e_scenario_with_error_code_serde_round_trip() {
        let scenario = BaselineE2eScenario::new(
            "test-fail",
            "test-fixture",
            BaselineScenarioDomain::Security,
            BaselineScenarioOutcome::CanonicalFailure,
            "guardplane",
            "containment",
            Some("FE-SEC-0001"),
        );
        let json = serde_json::to_string(&scenario).expect("serialize derived Serialize");
        let restored: BaselineE2eScenario =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(scenario, restored);
        assert_eq!(restored.error_code.as_deref(), Some("FE-SEC-0001"));
    }

    // --- Enrichment: ArtifactValidationReport/ArtifactBundleValidationReport serde ---

    #[test]
    fn artifact_validation_report_serde_round_trip() {
        let report = ArtifactValidationReport {
            schema_version: RGC_ARTIFACT_VALIDATOR_SCHEMA_VERSION.to_string(),
            component: "test".to_string(),
            event: "validate".to_string(),
            outcome: "pass".to_string(),
            valid: true,
            run_id: Some("run-001".to_string()),
            trace_id: Some("trace-001".to_string()),
            decision_id: Some("decision-001".to_string()),
            policy_id: Some("policy-001".to_string()),
            findings: Vec::new(),
        };
        let json = serde_json::to_string(&report).expect("serialize derived Serialize");
        let restored: ArtifactValidationReport =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(report, restored);
    }

    #[test]
    fn artifact_bundle_validation_report_serde_round_trip() {
        let report = ArtifactBundleValidationReport {
            schema_version: RGC_ARTIFACT_BUNDLE_VALIDATOR_SCHEMA_VERSION.to_string(),
            component: "test".to_string(),
            event: "validate_bundle".to_string(),
            outcome: "pass".to_string(),
            valid: true,
            bundle_dir: "/tmp/test".to_string(),
            correlation_signature: Some(ArtifactBundleCorrelationSignature {
                scenario_id: "test-scenario".to_string(),
                seed: 42,
                lanes: vec![HarnessLane::Runtime, HarnessLane::Security],
            }),
            run_dirs: vec!["/tmp/test/run-1".to_string()],
            lane_reports: Vec::new(),
            findings: Vec::new(),
        };
        let json = serde_json::to_string(&report).expect("serialize derived Serialize");
        let restored: ArtifactBundleValidationReport =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(report, restored);
    }

    // --- Enrichment: write_artifact_triad with empty events ---

    #[test]
    fn write_and_validate_triad_with_zero_events() {
        let root = temp_dir("write_triad_zero_events");
        let ctx = DeterministicTestContext::new("zero-events", "fix-1", HarnessLane::Parser, 1);
        let run_id = ctx.default_run_id();
        let events: Vec<HarnessLogEvent> = Vec::new();
        let commands = vec!["cargo test".to_string()];
        let manifest =
            HarnessRunManifest::from_context(&ctx, run_id, 0, 1, "replay.sh", 1_700_100_000_100);
        let triad = write_artifact_triad(&root, &manifest, &events, &commands)
            .expect("write should succeed");
        let report = validate_artifact_triad(&triad.run_dir);
        assert!(
            report.valid,
            "zero events is valid when manifest says 0: {:?}",
            report.findings
        );
    }

    // --- Enrichment batch 4: constants, ordering, correlation, edge cases ---

    #[test]
    fn schema_version_constants_are_stable() {
        assert_eq!(
            RGC_TEST_HARNESS_SCHEMA_VERSION,
            "franken-engine.rgc-test-harness.v1"
        );
        assert_eq!(
            RGC_TEST_HARNESS_EVENT_SCHEMA_VERSION,
            "franken-engine.rgc-test-event.v1"
        );
        assert_eq!(
            RGC_TEST_HARNESS_MANIFEST_SCHEMA_VERSION,
            "franken-engine.rgc-test-harness.run-manifest.v1"
        );
        assert_eq!(
            RGC_BASELINE_E2E_SCENARIO_SCHEMA_VERSION,
            "franken-engine.rgc-baseline-e2e-scenario.v1"
        );
        assert_eq!(
            RGC_ARTIFACT_VALIDATOR_SCHEMA_VERSION,
            "franken-engine.rgc-artifact-validator.v1"
        );
        assert_eq!(
            RGC_ARTIFACT_BUNDLE_VALIDATOR_SCHEMA_VERSION,
            "franken-engine.rgc-artifact-bundle-validator.v1"
        );
    }

    #[test]
    fn harness_lane_ord_is_deterministic() {
        let mut lanes = vec![
            HarnessLane::E2e,
            HarnessLane::Security,
            HarnessLane::Parser,
            HarnessLane::Governance,
            HarnessLane::Runtime,
        ];
        let mut lanes2 = lanes.clone();
        lanes.sort();
        lanes2.sort();
        assert_eq!(lanes, lanes2, "sorting must be deterministic");
    }

    #[test]
    fn baseline_scenario_domain_ord_is_deterministic() {
        let mut domains = vec![
            BaselineScenarioDomain::Security,
            BaselineScenarioDomain::Runtime,
            BaselineScenarioDomain::Module,
        ];
        let mut domains2 = domains.clone();
        domains.sort();
        domains2.sort();
        assert_eq!(domains, domains2);
    }

    #[test]
    fn context_event_populates_all_fields_from_context() {
        let ctx = DeterministicTestContext::new("sc-42", "fix-7", HarnessLane::Parser, 99);
        let event = ctx.event(EventInput {
            sequence: 3,
            component: "parser",
            event: "parse",
            outcome: "pass",
            error_code: Some("FE-001"),
            timing_us: 500,
            timestamp_unix_ms: 1_700_000_000_000,
        });
        assert_eq!(event.schema_version, RGC_TEST_HARNESS_EVENT_SCHEMA_VERSION);
        assert_eq!(event.scenario_id, "sc-42");
        assert_eq!(event.fixture_id, "fix-7");
        assert_eq!(event.trace_id, ctx.trace_id);
        assert_eq!(event.decision_id, ctx.decision_id);
        assert_eq!(event.policy_id, ctx.policy_id);
        assert_eq!(event.lane, HarnessLane::Parser);
        assert_eq!(event.seed, 99);
        assert_eq!(event.sequence, 3);
        assert_eq!(event.component, "parser");
        assert_eq!(event.event, "parse");
        assert_eq!(event.outcome, "pass");
        assert_eq!(event.error_code.as_deref(), Some("FE-001"));
        assert_eq!(event.timing_us, 500);
        assert_eq!(event.timestamp_unix_ms, 1_700_000_000_000);
    }

    #[test]
    fn context_with_seed_zero() {
        let ctx = DeterministicTestContext::new("sc", "fix", HarnessLane::Runtime, 0);
        assert!(ctx.trace_id.starts_with("trace-rgc-"));
        assert_eq!(ctx.seed, 0);
    }

    #[test]
    fn context_with_seed_max() {
        let ctx = DeterministicTestContext::new("sc", "fix", HarnessLane::Runtime, u64::MAX);
        assert!(ctx.trace_id.starts_with("trace-rgc-"));
        assert_eq!(ctx.seed, u64::MAX);
    }

    #[test]
    fn fixture_loader_rejects_whitespace_only_path() {
        let root = PathBuf::from("/tmp");
        let error = load_json_fixture::<DemoFixture>(&root, "   ")
            .expect_err("whitespace-only path must fail");
        assert!(matches!(
            error,
            FixtureLoadError::InvalidRelativePath { .. }
        ));
    }

    #[test]
    fn validate_triad_event_correlation_mismatch() {
        let root = temp_dir("validate_triad_event_corr");
        let ctx = DeterministicTestContext::new("corr-test", "fix-1", HarnessLane::Runtime, 77);
        let run_id = ctx.default_run_id();
        let mut event = ctx.event(EventInput {
            sequence: 0,
            component: "test",
            event: "step",
            outcome: "pass",
            error_code: None,
            timing_us: 10,
            timestamp_unix_ms: 1_700_100_000_000,
        });
        // Corrupt the event's trace_id
        event.trace_id = "trace-rgc-wrong".to_string();
        let events = vec![event];
        let commands = vec!["cargo test".to_string()];
        let manifest =
            HarnessRunManifest::from_context(&ctx, run_id, 1, 1, "replay.sh", 1_700_100_000_100);
        let triad = write_artifact_triad(&root, &manifest, &events, &commands)
            .expect("write should succeed");
        let report = validate_artifact_triad(&triad.run_dir);
        assert!(!report.valid);
        assert!(report.findings.iter().any(|f| {
            f.error_code == ArtifactValidationErrorCode::CorrelationMismatch
                && f.message.contains("trace_id mismatch")
        }));
    }

    #[test]
    fn validate_bundle_path_is_file_not_directory() {
        let root = temp_dir("validate_bundle_file");
        fs::create_dir_all(&root).expect("create dir");
        let file_path = root.join("not_a_dir");
        fs::write(&file_path, "data").expect("write file");
        let report = validate_artifact_bundle(&file_path, &[]);
        assert!(!report.valid);
        assert!(report.findings.iter().any(|f| {
            f.error_code == ArtifactBundleValidationErrorCode::MissingBundleDirectory
        }));
    }

    #[test]
    fn validate_bundle_no_required_lanes() {
        let root = temp_dir("validate_bundle_no_req_lanes");
        let bundle_dir = root.join("bundle");
        fs::create_dir_all(&bundle_dir).expect("create bundle dir");
        write_lane_triad(
            &bundle_dir,
            "rgc-no-req",
            "fixture-shared",
            HarnessLane::Runtime,
            1,
        );
        let report = validate_artifact_bundle(&bundle_dir, &[]);
        assert!(
            report.valid,
            "no required lanes means any present lane is fine: {:?}",
            report.findings
        );
    }

    #[test]
    fn artifact_validation_finding_serde_round_trip() {
        let finding = ArtifactValidationFinding {
            component: "test".to_string(),
            event: "validate".to_string(),
            outcome: "fail".to_string(),
            error_code: ArtifactValidationErrorCode::CountMismatch,
            message: "mismatch".to_string(),
        };
        let json = serde_json::to_string(&finding).expect("serialize derived Serialize");
        let restored: ArtifactValidationFinding =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(finding, restored);
    }

    #[test]
    fn artifact_bundle_validation_finding_serde_round_trip() {
        let finding = ArtifactBundleValidationFinding {
            component: "test".to_string(),
            event: "validate_bundle".to_string(),
            outcome: "fail".to_string(),
            error_code: ArtifactBundleValidationErrorCode::DuplicateLane,
            message: "dup".to_string(),
            owner_hint: "owner".to_string(),
            remediation_hint: "fix it".to_string(),
            repro_command: "cargo test".to_string(),
        };
        let json = serde_json::to_string(&finding).expect("serialize derived Serialize");
        let restored: ArtifactBundleValidationFinding =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(finding, restored);
    }

    #[test]
    fn artifact_bundle_correlation_signature_serde_round_trip() {
        let sig = ArtifactBundleCorrelationSignature {
            scenario_id: "test".to_string(),
            seed: 42,
            lanes: vec![HarnessLane::Parser, HarnessLane::Runtime],
        };
        let json = serde_json::to_string(&sig).expect("serialize derived Serialize");
        let restored: ArtifactBundleCorrelationSignature =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(sig, restored);
    }

    #[test]
    fn sanitize_label_unicode_chars() {
        assert_eq!(sanitize_label("café_naïve"), "caf-_na-ve");
    }

    #[test]
    fn context_policy_id_includes_lane_name() {
        for lane in [
            HarnessLane::Parser,
            HarnessLane::Runtime,
            HarnessLane::Security,
            HarnessLane::Governance,
            HarnessLane::E2e,
        ] {
            let ctx = DeterministicTestContext::new("sc", "fix", lane, 1);
            assert!(
                ctx.policy_id.contains(lane.as_str()),
                "policy_id {} should contain {}",
                ctx.policy_id,
                lane.as_str()
            );
        }
    }

    #[test]
    fn baseline_registry_scenario_ids_are_sorted() {
        let registry = baseline_e2e_scenario_registry();
        let ids: Vec<&str> = registry.iter().map(|s| s.scenario_id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "scenario IDs must be sorted");
    }

    #[test]
    fn baseline_registry_all_scenarios_are_e2e_lane() {
        let registry = baseline_e2e_scenario_registry();
        for scenario in &registry {
            assert_eq!(scenario.lane, HarnessLane::E2e);
        }
    }

    #[test]
    fn baseline_registry_failure_scenarios_have_error_codes() {
        let registry = baseline_e2e_scenario_registry();
        for scenario in &registry {
            if scenario.outcome == BaselineScenarioOutcome::CanonicalFailure {
                assert!(
                    scenario.error_code.is_some(),
                    "failure scenario {} must have error_code",
                    scenario.scenario_id
                );
            }
        }
    }

    #[test]
    fn baseline_registry_happy_scenarios_have_no_error_codes() {
        let registry = baseline_e2e_scenario_registry();
        for scenario in &registry {
            if scenario.outcome == BaselineScenarioOutcome::HappyPath {
                assert!(
                    scenario.error_code.is_none(),
                    "happy scenario {} must not have error_code",
                    scenario.scenario_id
                );
            }
        }
    }

    #[test]
    fn write_artifact_triad_creates_expected_files() {
        let root = temp_dir("write_triad_files_check");
        let ctx = DeterministicTestContext::new("file-check", "fix-1", HarnessLane::Governance, 5);
        let run_id = ctx.default_run_id();
        let events = vec![ctx.event(EventInput {
            sequence: 0,
            component: "gov",
            event: "audit",
            outcome: "pass",
            error_code: None,
            timing_us: 15,
            timestamp_unix_ms: 1_700_200_000_000,
        })];
        let commands = vec!["cargo clippy".to_string()];
        let manifest =
            HarnessRunManifest::from_context(&ctx, run_id, 1, 1, "replay.sh", 1_700_200_000_100);
        let triad = write_artifact_triad(&root, &manifest, &events, &commands)
            .expect("write should succeed");
        assert!(triad.manifest_path.exists());
        assert!(triad.events_path.exists());
        assert!(triad.commands_path.exists());
        assert!(triad.run_dir.is_dir());
    }
}
