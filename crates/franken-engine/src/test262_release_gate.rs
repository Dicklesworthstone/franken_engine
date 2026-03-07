use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const TEST262_PIN_SCHEMA: &str = "franken-engine.test262-pin.v1";
const TEST262_PROFILE_SCHEMA: &str = "franken-engine.test262-profile.v1";
const TEST262_WAIVER_SCHEMA: &str = "franken-engine.test262-waiver.v1";
const TEST262_HWM_SCHEMA: &str = "franken-engine.test262-high-water-mark.v1";

const TEST262_COMPONENT: &str = "test262_release_gate";

const FE_T262_INVALID_CONFIG: &str = "FE-T262-1001";
const FE_T262_INVALID_PROFILE: &str = "FE-T262-1002";
const FE_T262_DUPLICATE_RESULT: &str = "FE-T262-1004";
const FE_T262_UNWAIVED_FAILURE: &str = "FE-T262-1005";
const FE_T262_MISSING_FIELD: &str = "FE-T262-1006";
const FE_T262_REGRESSION_ACK_REQUIRED: &str = "FE-T262-1007";
const FE_T262_TIMEOUT: &str = "FE-T262-1008";
const FE_T262_CRASH: &str = "FE-T262-1009";
const FE_T262_WAIVED: &str = "FE-T262-1010";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Test262PinSet {
    pub schema_version: String,
    pub source_repo: String,
    pub es_profile: String,
    pub test262_commit: String,
}

impl Test262PinSet {
    pub fn load_toml(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)?;
        parse_pin_toml(&content)
    }

    pub fn validate(&self) -> Result<(), Test262GateError> {
        if self.schema_version.trim() != TEST262_PIN_SCHEMA {
            return Err(Test262GateError::InvalidConfig(format!(
                "pin schema must be `{TEST262_PIN_SCHEMA}`"
            )));
        }
        if self.source_repo.trim().is_empty() {
            return Err(Test262GateError::InvalidConfig(
                "pin source_repo is required".to_string(),
            ));
        }
        if self.es_profile.trim() != "ES2020" {
            return Err(Test262GateError::InvalidConfig(
                "pin es_profile must be `ES2020`".to_string(),
            ));
        }
        if !is_hex_hash(self.test262_commit.trim(), 40) {
            return Err(Test262GateError::InvalidConfig(
                "test262_commit must be a 40-char lowercase hex git commit".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Test262ProfileInclude {
    pub pattern: String,
    pub rationale: String,
    pub normative_clause: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Test262ProfileExclude {
    pub pattern: String,
    pub rationale: String,
    pub normative_clause: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Test262Profile {
    pub schema_version: String,
    pub profile_name: String,
    pub es_profile: String,
    pub includes: Vec<Test262ProfileInclude>,
    pub excludes: Vec<Test262ProfileExclude>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileDecision {
    Included,
    Excluded { rationale: String },
    NotSelected,
}

impl Test262Profile {
    pub fn load_toml(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)?;
        parse_profile_toml(&content)
    }

    pub fn validate(&self) -> Result<(), Test262GateError> {
        if self.schema_version.trim() != TEST262_PROFILE_SCHEMA {
            return Err(Test262GateError::InvalidConfig(format!(
                "profile schema must be `{TEST262_PROFILE_SCHEMA}`"
            )));
        }
        if self.profile_name.trim().is_empty() {
            return Err(Test262GateError::InvalidConfig(
                "profile_name is required".to_string(),
            ));
        }
        if self.es_profile.trim() != "ES2020" {
            return Err(Test262GateError::InvalidConfig(
                "profile es_profile must be `ES2020`".to_string(),
            ));
        }
        if self.includes.is_empty() {
            return Err(Test262GateError::InvalidConfig(
                "profile must define at least one include rule".to_string(),
            ));
        }

        for include in &self.includes {
            if include.pattern.trim().is_empty() {
                return Err(Test262GateError::InvalidConfig(
                    "include pattern is required".to_string(),
                ));
            }
            if include.rationale.trim().is_empty() || include.normative_clause.trim().is_empty() {
                return Err(Test262GateError::InvalidConfig(
                    "include rationale and normative_clause are required".to_string(),
                ));
            }
        }

        for exclude in &self.excludes {
            if exclude.pattern.trim().is_empty() {
                return Err(Test262GateError::InvalidConfig(
                    "exclude pattern is required".to_string(),
                ));
            }
            if exclude.rationale.trim().is_empty() || exclude.normative_clause.trim().is_empty() {
                return Err(Test262GateError::InvalidConfig(
                    "exclude rationale and normative_clause are required".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn classify(&self, test_id: &str) -> ProfileDecision {
        let included = self
            .includes
            .iter()
            .any(|rule| wildcard_match(rule.pattern.as_str(), test_id));
        if !included {
            return ProfileDecision::NotSelected;
        }

        if let Some(rule) = self
            .excludes
            .iter()
            .find(|rule| wildcard_match(rule.pattern.as_str(), test_id))
        {
            return ProfileDecision::Excluded {
                rationale: rule.rationale.clone(),
            };
        }

        ProfileDecision::Included
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Test262WaiverReason {
    HarnessGap,
    HostHookMissing,
    IntentionalDivergence,
    NotYetImplemented,
}

impl Test262WaiverReason {
    fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "harness_gap" => Some(Self::HarnessGap),
            "host_hook_missing" => Some(Self::HostHookMissing),
            "intentional_divergence" => Some(Self::IntentionalDivergence),
            "not_yet_implemented" => Some(Self::NotYetImplemented),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Test262Waiver {
    pub test_id: String,
    pub reason_code: Test262WaiverReason,
    pub es2020_clause: String,
    pub tracking_bead: String,
    pub expiry_date: String,
    pub reviewer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Test262WaiverSet {
    pub schema_version: String,
    pub waivers: Vec<Test262Waiver>,
}

impl Default for Test262WaiverSet {
    fn default() -> Self {
        Self {
            schema_version: TEST262_WAIVER_SCHEMA.to_string(),
            waivers: Vec::new(),
        }
    }
}

impl Test262WaiverSet {
    pub fn load_toml(path: impl AsRef<Path>) -> io::Result<Self> {
        if !path.as_ref().exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)?;
        parse_waiver_toml(&content)
    }

    pub fn validate(&self) -> Result<(), Test262GateError> {
        if self.schema_version.trim() != TEST262_WAIVER_SCHEMA {
            return Err(Test262GateError::InvalidConfig(format!(
                "waiver schema must be `{TEST262_WAIVER_SCHEMA}`"
            )));
        }

        for waiver in &self.waivers {
            if waiver.test_id.trim().is_empty() {
                return Err(Test262GateError::InvalidConfig(
                    "waiver test_id is required".to_string(),
                ));
            }
            if waiver.es2020_clause.trim().is_empty() {
                return Err(Test262GateError::InvalidConfig(format!(
                    "waiver `{}` missing es2020_clause",
                    waiver.test_id
                )));
            }
            if waiver.tracking_bead.trim().is_empty() {
                return Err(Test262GateError::InvalidConfig(format!(
                    "waiver `{}` missing tracking_bead",
                    waiver.test_id
                )));
            }
            if waiver.reviewer.trim().is_empty() {
                return Err(Test262GateError::InvalidConfig(format!(
                    "waiver `{}` missing reviewer",
                    waiver.test_id
                )));
            }
            if !looks_like_yyyy_mm_dd(waiver.expiry_date.as_str()) {
                return Err(Test262GateError::InvalidConfig(format!(
                    "waiver `{}` expiry_date must be YYYY-MM-DD",
                    waiver.test_id
                )));
            }
        }

        Ok(())
    }

    fn find_active(&self, test_id: &str, run_date: &str) -> Option<&Test262Waiver> {
        self.waivers
            .iter()
            .find(|waiver| waiver.test_id == test_id && waiver.expiry_date.as_str() >= run_date)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Test262HighWaterMark {
    pub schema_version: String,
    pub profile_hash: String,
    pub pass_count: usize,
    pub recorded_at_utc: String,
}

impl Test262HighWaterMark {
    pub fn load_json(path: impl AsRef<Path>) -> io::Result<Option<Self>> {
        if !path.as_ref().exists() {
            return Ok(None);
        }
        let bytes = fs::read(path.as_ref())?;
        let parsed = serde_json::from_slice::<Self>(&bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        Ok(Some(parsed))
    }

    pub fn write_json(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let bytes = canonical_json_bytes(self)?;
        write_atomic(path.as_ref(), &bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Test262PassRegressionWarning {
    pub previous_high_water_mark: usize,
    pub current_pass_count: usize,
    pub acknowledgement_required: bool,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Test262RunnerConfig {
    pub trace_prefix: String,
    pub policy_id: String,
    pub run_date: String,
    pub worker_count: usize,
    pub locale: String,
    pub timezone: String,
    pub gc_schedule: String,
    pub acknowledge_pass_regression: bool,
}

impl Default for Test262RunnerConfig {
    fn default() -> Self {
        Self {
            trace_prefix: "trace-test262".to_string(),
            policy_id: "policy-test262-es2020".to_string(),
            run_date: "1970-01-01".to_string(),
            worker_count: 8,
            locale: "C".to_string(),
            timezone: "UTC".to_string(),
            gc_schedule: "deterministic".to_string(),
            acknowledge_pass_regression: false,
        }
    }
}

impl Test262RunnerConfig {
    fn validate(&self) -> Result<(), Test262GateError> {
        if self.trace_prefix.trim().is_empty() {
            return Err(Test262GateError::InvalidConfig(
                "trace_prefix is required".to_string(),
            ));
        }
        if self.policy_id.trim().is_empty() {
            return Err(Test262GateError::InvalidConfig(
                "policy_id is required".to_string(),
            ));
        }
        if self.run_date.trim().is_empty() || !looks_like_yyyy_mm_dd(self.run_date.as_str()) {
            return Err(Test262GateError::InvalidConfig(
                "run_date must be YYYY-MM-DD".to_string(),
            ));
        }
        if self.worker_count == 0 {
            return Err(Test262GateError::InvalidConfig(
                "worker_count must be >= 1".to_string(),
            ));
        }
        if self.locale != "C" {
            return Err(Test262GateError::InvalidConfig(
                "locale must be fixed to `C`".to_string(),
            ));
        }
        if self.timezone != "UTC" {
            return Err(Test262GateError::InvalidConfig(
                "timezone must be fixed to `UTC`".to_string(),
            ));
        }
        if self.gc_schedule != "deterministic" {
            return Err(Test262GateError::InvalidConfig(
                "gc_schedule must be `deterministic`".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Test262ObservedOutcome {
    Pass,
    Fail,
    Timeout,
    Crash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Test262Outcome {
    Pass,
    Fail,
    Waived,
    Timeout,
    Crash,
}

impl Test262Outcome {
    fn blocks_release(self) -> bool {
        matches!(self, Self::Fail | Self::Timeout | Self::Crash)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Test262ObservedResult {
    pub test_id: String,
    pub es2020_clause: String,
    pub outcome: Test262ObservedOutcome,
    pub duration_us: u64,
    pub error_code: Option<String>,
    pub error_detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicWorkerAssignment {
    pub test_id: String,
    pub worker_index: usize,
    pub queue_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Test262LogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub test_id: String,
    pub es2020_clause: String,
    pub outcome: Test262Outcome,
    pub duration_us: u64,
    pub error_code: Option<String>,
    pub error_detail: Option<String>,
    pub worker_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Test262RunSummary {
    pub run_id: String,
    pub total_profile_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub waived: usize,
    pub timed_out: usize,
    pub crashed: usize,
    pub blocked_failures: usize,
    pub profile_hash: String,
    pub waiver_hash: String,
    pub pin_hash: String,
    pub env_fingerprint: String,
    pub pass_regression_warning: Option<Test262PassRegressionWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Test262GateRun {
    pub run_id: String,
    pub blocked: bool,
    pub logs: Vec<Test262LogEvent>,
    pub summary: Test262RunSummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Test262GateErrorInfo {
    pub code: &'static str,
    pub detail: String,
}

#[derive(Debug)]
pub enum Test262GateError {
    InvalidConfig(String),
    DuplicateObservedResult {
        test_id: String,
    },
    MissingObservedField {
        test_id: String,
        field: &'static str,
    },
    InvalidProfile(String),
    Io(io::Error),
}

impl Test262GateError {
    pub fn stable(&self) -> Test262GateErrorInfo {
        match self {
            Self::InvalidConfig(detail) => Test262GateErrorInfo {
                code: FE_T262_INVALID_CONFIG,
                detail: detail.clone(),
            },
            Self::DuplicateObservedResult { test_id } => Test262GateErrorInfo {
                code: FE_T262_DUPLICATE_RESULT,
                detail: format!("duplicate observed result for `{test_id}`"),
            },
            Self::MissingObservedField { test_id, field } => Test262GateErrorInfo {
                code: FE_T262_MISSING_FIELD,
                detail: format!("observed result `{test_id}` missing `{field}`"),
            },
            Self::InvalidProfile(detail) => Test262GateErrorInfo {
                code: FE_T262_INVALID_PROFILE,
                detail: detail.clone(),
            },
            Self::Io(err) => Test262GateErrorInfo {
                code: FE_T262_INVALID_CONFIG,
                detail: err.to_string(),
            },
        }
    }
}

impl fmt::Display for Test262GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stable = self.stable();
        write!(f, "{}: {}", stable.code, stable.detail)
    }
}

impl Error for Test262GateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Test262GateError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Test262GateRunner {
    pub config: Test262RunnerConfig,
}

impl Test262GateRunner {
    pub fn run(
        &self,
        pins: &Test262PinSet,
        profile: &Test262Profile,
        waivers: &Test262WaiverSet,
        observed: &[Test262ObservedResult],
        previous_hwm: Option<&Test262HighWaterMark>,
    ) -> Result<Test262GateRun, Test262GateError> {
        self.config.validate()?;
        pins.validate()?;
        profile.validate()?;
        waivers.validate()?;

        let pin_hash = sha256_hex(&canonical_json_bytes(pins)?);
        let profile_hash = sha256_hex(&canonical_json_bytes(profile)?);
        let waiver_hash = sha256_hex(&canonical_json_bytes(waivers)?);

        let mut selected = Vec::new();
        let mut seen = BTreeSet::new();
        for result in observed {
            if result.test_id.trim().is_empty() {
                return Err(Test262GateError::MissingObservedField {
                    test_id: "<unknown>".to_string(),
                    field: "test_id",
                });
            }
            if result.es2020_clause.trim().is_empty() {
                return Err(Test262GateError::MissingObservedField {
                    test_id: result.test_id.clone(),
                    field: "es2020_clause",
                });
            }
            if !seen.insert(result.test_id.clone()) {
                return Err(Test262GateError::DuplicateObservedResult {
                    test_id: result.test_id.clone(),
                });
            }
            if matches!(
                profile.classify(result.test_id.as_str()),
                ProfileDecision::Included
            ) {
                selected.push(result.clone());
            }
        }

        selected.sort_by(|lhs, rhs| lhs.test_id.cmp(&rhs.test_id));
        let schedule = deterministic_worker_assignments(
            selected
                .iter()
                .map(|result| result.test_id.clone())
                .collect::<Vec<_>>()
                .as_slice(),
            self.config.worker_count,
        );

        let mut assignment_map = BTreeMap::new();
        for slot in schedule {
            assignment_map.insert(slot.test_id, slot.worker_index);
        }

        let run_material = format!(
            "pin={pin_hash};profile={profile_hash};waiver={waiver_hash};date={}",
            self.config.run_date
        );
        let run_id = format!("test262-{}", &digest_hex(run_material.as_bytes())[..12]);

        let mut logs = Vec::with_capacity(selected.len());
        let mut passed = 0usize;
        let mut failed = 0usize;
        let mut waived = 0usize;
        let mut timed_out = 0usize;
        let mut crashed = 0usize;
        let mut blocked_failures = 0usize;

        for (idx, result) in selected.iter().enumerate() {
            let trace_id = format!("{}-{}-{idx:04}", self.config.trace_prefix, run_id);
            let decision_id = format!("decision-test262-{idx:04}");
            let worker_index = *assignment_map.get(result.test_id.as_str()).ok_or_else(|| {
                Test262GateError::InvalidProfile(format!(
                    "missing deterministic worker assignment for `{}`",
                    result.test_id
                ))
            })?;

            let active_waiver =
                waivers.find_active(result.test_id.as_str(), self.config.run_date.as_str());

            let (outcome, mut error_code, error_detail) = match result.outcome {
                Test262ObservedOutcome::Pass => {
                    passed += 1;
                    (Test262Outcome::Pass, None, None)
                }
                Test262ObservedOutcome::Fail => {
                    if let Some(waiver) = active_waiver {
                        waived += 1;
                        (
                            Test262Outcome::Waived,
                            Some(FE_T262_WAIVED.to_string()),
                            Some(format!(
                                "waived by `{}` (reason={:?}, reviewer={}, expiry={})",
                                waiver.tracking_bead,
                                waiver.reason_code,
                                waiver.reviewer,
                                waiver.expiry_date
                            )),
                        )
                    } else {
                        failed += 1;
                        (
                            Test262Outcome::Fail,
                            Some(FE_T262_UNWAIVED_FAILURE.to_string()),
                            Some("non-passing test without active waiver".to_string()),
                        )
                    }
                }
                Test262ObservedOutcome::Timeout => {
                    if let Some(waiver) = active_waiver {
                        waived += 1;
                        (
                            Test262Outcome::Waived,
                            Some(FE_T262_WAIVED.to_string()),
                            Some(format!(
                                "timeout waived by `{}` (reviewer={}, expiry={})",
                                waiver.tracking_bead, waiver.reviewer, waiver.expiry_date
                            )),
                        )
                    } else {
                        timed_out += 1;
                        (
                            Test262Outcome::Timeout,
                            Some(FE_T262_TIMEOUT.to_string()),
                            Some("timeout without active waiver".to_string()),
                        )
                    }
                }
                Test262ObservedOutcome::Crash => {
                    if let Some(waiver) = active_waiver {
                        waived += 1;
                        (
                            Test262Outcome::Waived,
                            Some(FE_T262_WAIVED.to_string()),
                            Some(format!(
                                "crash waived by `{}` (reviewer={}, expiry={})",
                                waiver.tracking_bead, waiver.reviewer, waiver.expiry_date
                            )),
                        )
                    } else {
                        crashed += 1;
                        (
                            Test262Outcome::Crash,
                            Some(FE_T262_CRASH.to_string()),
                            Some("crash without active waiver".to_string()),
                        )
                    }
                }
            };

            if error_code.is_none() {
                error_code = result.error_code.clone();
            }

            if outcome.blocks_release() {
                blocked_failures += 1;
            }

            logs.push(Test262LogEvent {
                trace_id,
                decision_id,
                policy_id: self.config.policy_id.clone(),
                component: TEST262_COMPONENT.to_string(),
                event: "test262_case_evaluated".to_string(),
                test_id: result.test_id.clone(),
                es2020_clause: result.es2020_clause.clone(),
                outcome,
                duration_us: result.duration_us,
                error_code,
                error_detail: error_detail.or_else(|| result.error_detail.clone()),
                worker_index,
            });
        }

        let pass_regression_warning = if let Some(previous) = previous_hwm {
            if passed < previous.pass_count {
                Some(Test262PassRegressionWarning {
                    previous_high_water_mark: previous.pass_count,
                    current_pass_count: passed,
                    acknowledgement_required: true,
                    acknowledged: self.config.acknowledge_pass_regression,
                })
            } else {
                None
            }
        } else {
            None
        };

        let blocked_by_regression_ack = pass_regression_warning
            .as_ref()
            .is_some_and(|warning| warning.acknowledgement_required && !warning.acknowledged);

        if blocked_by_regression_ack {
            blocked_failures += 1;
            logs.push(Test262LogEvent {
                trace_id: format!("{}-{}-ack", self.config.trace_prefix, run_id),
                decision_id: "decision-test262-regression-ack".to_string(),
                policy_id: self.config.policy_id.clone(),
                component: TEST262_COMPONENT.to_string(),
                event: "pass_regression_ack_missing".to_string(),
                test_id: "__meta__/pass_regression".to_string(),
                es2020_clause: "N/A".to_string(),
                outcome: Test262Outcome::Fail,
                duration_us: 0,
                error_code: Some(FE_T262_REGRESSION_ACK_REQUIRED.to_string()),
                error_detail: Some(
                    "pass-count regression requires explicit acknowledgement".to_string(),
                ),
                worker_index: 0,
            });
        }

        let summary = Test262RunSummary {
            run_id: run_id.clone(),
            total_profile_tests: selected.len(),
            passed,
            failed,
            waived,
            timed_out,
            crashed,
            blocked_failures,
            profile_hash,
            waiver_hash,
            pin_hash,
            env_fingerprint: self.env_fingerprint(),
            pass_regression_warning,
        };

        Ok(Test262GateRun {
            run_id,
            blocked: blocked_failures > 0,
            logs,
            summary,
        })
    }

    fn env_fingerprint(&self) -> String {
        let envelope = format!(
            "locale={};timezone={};gc={};workers={}",
            self.config.locale,
            self.config.timezone,
            self.config.gc_schedule,
            self.config.worker_count
        );
        sha256_hex(envelope.as_bytes())
    }
}

pub fn deterministic_worker_assignments(
    test_ids: &[String],
    worker_count: usize,
) -> Vec<DeterministicWorkerAssignment> {
    let mut sorted = test_ids.to_vec();
    sorted.sort();

    let mut queue_counts = vec![0usize; worker_count.max(1)];
    let mut out = Vec::with_capacity(sorted.len());

    for (idx, test_id) in sorted.into_iter().enumerate() {
        let worker_index = idx % worker_count.max(1);
        let queue_index = queue_counts[worker_index];
        queue_counts[worker_index] += 1;
        out.push(DeterministicWorkerAssignment {
            test_id,
            worker_index,
            queue_index,
        });
    }

    out
}

pub fn next_high_water_mark(
    run: &Test262GateRun,
    previous: Option<&Test262HighWaterMark>,
) -> Test262HighWaterMark {
    let previous_count = previous.map(|hwm| hwm.pass_count).unwrap_or(0);
    let pass_count = run.summary.passed.max(previous_count);

    Test262HighWaterMark {
        schema_version: TEST262_HWM_SCHEMA.to_string(),
        profile_hash: run.summary.profile_hash.clone(),
        pass_count,
        recorded_at_utc: Utc::now().to_rfc3339(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Test262CollectedArtifacts {
    pub run_manifest_path: PathBuf,
    pub evidence_path: PathBuf,
    pub high_water_mark_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Test262EvidenceCollector {
    root: PathBuf,
}

impl Test262EvidenceCollector {
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn collect(
        &self,
        run: &Test262GateRun,
        high_water_mark: &Test262HighWaterMark,
    ) -> io::Result<Test262CollectedArtifacts> {
        let run_root = self.root.join(&run.run_id);
        fs::create_dir_all(&run_root)?;

        let run_manifest_path = run_root.join("run_manifest.json");
        write_atomic(&run_manifest_path, &canonical_json_bytes(&run.summary)?)?;

        let mut evidence_lines = String::new();
        let summary_line = serde_json::to_string(&serde_json::json!({
            "schema_version": "franken-engine.test262-evidence.v1",
            "run_manifest": "run_manifest.json",
            "run_id": run.run_id,
            "total_profile_tests": run.summary.total_profile_tests,
            "passed": run.summary.passed,
            "failed": run.summary.failed,
            "waived": run.summary.waived,
            "timed_out": run.summary.timed_out,
            "crashed": run.summary.crashed,
            "blocked_failures": run.summary.blocked_failures,
            "profile_hash": run.summary.profile_hash,
            "waiver_hash": run.summary.waiver_hash,
            "pin_hash": run.summary.pin_hash,
            "env_fingerprint": run.summary.env_fingerprint,
        }))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        evidence_lines.push_str(&summary_line);
        evidence_lines.push('\n');

        for event in &run.logs {
            let line = serde_json::to_string(event)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            evidence_lines.push_str(&line);
            evidence_lines.push('\n');
        }

        let evidence_path = run_root.join("test262_evidence.jsonl");
        write_atomic(&evidence_path, evidence_lines.as_bytes())?;

        let high_water_mark_path = run_root.join("test262_hwm.json");
        high_water_mark.write_json(&high_water_mark_path)?;

        Ok(Test262CollectedArtifacts {
            run_manifest_path,
            evidence_path,
            high_water_mark_path,
        })
    }
}

fn parse_pin_toml(content: &str) -> io::Result<Test262PinSet> {
    let mut values = BTreeMap::<String, String>::new();
    for (idx, raw) in content.lines().enumerate() {
        let line_no = idx + 1;
        let stripped = strip_comment(raw);
        if stripped.is_empty() {
            continue;
        }
        let (key, value) = parse_key_value(line_no, stripped)?;
        values.insert(key, value);
    }

    Ok(Test262PinSet {
        schema_version: values
            .remove("schema_version")
            .unwrap_or_else(|| TEST262_PIN_SCHEMA.to_string()),
        source_repo: values.remove("source_repo").unwrap_or_default(),
        es_profile: values.remove("es_profile").unwrap_or_default(),
        test262_commit: values.remove("test262_commit").unwrap_or_default(),
    })
}

fn parse_profile_toml(content: &str) -> io::Result<Test262Profile> {
    #[derive(Default)]
    struct RawRule {
        pattern: Option<String>,
        rationale: Option<String>,
        normative_clause: Option<String>,
    }

    fn finalize_include(raw: RawRule, line_no: usize) -> io::Result<Test262ProfileInclude> {
        Ok(Test262ProfileInclude {
            pattern: raw.pattern.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("include missing pattern before line {line_no}"),
                )
            })?,
            rationale: raw.rationale.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("include missing rationale before line {line_no}"),
                )
            })?,
            normative_clause: raw.normative_clause.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("include missing normative_clause before line {line_no}"),
                )
            })?,
        })
    }

    fn finalize_exclude(raw: RawRule, line_no: usize) -> io::Result<Test262ProfileExclude> {
        Ok(Test262ProfileExclude {
            pattern: raw.pattern.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("exclude missing pattern before line {line_no}"),
                )
            })?,
            rationale: raw.rationale.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("exclude missing rationale before line {line_no}"),
                )
            })?,
            normative_clause: raw.normative_clause.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("exclude missing normative_clause before line {line_no}"),
                )
            })?,
        })
    }

    enum Section {
        Root,
        Include,
        Exclude,
    }

    let mut schema_version = TEST262_PROFILE_SCHEMA.to_string();
    let mut profile_name = String::new();
    let mut es_profile = String::new();

    let mut includes = Vec::<Test262ProfileInclude>::new();
    let mut excludes = Vec::<Test262ProfileExclude>::new();
    let mut current_rule: Option<RawRule> = None;
    let mut section = Section::Root;

    for (idx, raw) in content.lines().enumerate() {
        let line_no = idx + 1;
        let stripped = strip_comment(raw);
        if stripped.is_empty() {
            continue;
        }

        if stripped == "[[include]]" {
            if let Some(existing) = current_rule.take() {
                match section {
                    Section::Include => includes.push(finalize_include(existing, line_no)?),
                    Section::Exclude => excludes.push(finalize_exclude(existing, line_no)?),
                    Section::Root => {}
                }
            }
            section = Section::Include;
            current_rule = Some(RawRule::default());
            continue;
        }

        if stripped == "[[exclude]]" {
            if let Some(existing) = current_rule.take() {
                match section {
                    Section::Include => includes.push(finalize_include(existing, line_no)?),
                    Section::Exclude => excludes.push(finalize_exclude(existing, line_no)?),
                    Section::Root => {}
                }
            }
            section = Section::Exclude;
            current_rule = Some(RawRule::default());
            continue;
        }

        let (key, value) = parse_key_value(line_no, stripped)?;

        match section {
            Section::Root => match key.as_str() {
                "schema_version" => schema_version = value,
                "profile_name" => profile_name = value,
                "es_profile" => es_profile = value,
                unknown => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unknown root field `{unknown}` at line {line_no}"),
                    ));
                }
            },
            Section::Include | Section::Exclude => {
                let Some(rule) = current_rule.as_mut() else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("rule field outside section at line {line_no}"),
                    ));
                };
                match key.as_str() {
                    "pattern" => rule.pattern = Some(value),
                    "rationale" => rule.rationale = Some(value),
                    "normative_clause" => rule.normative_clause = Some(value),
                    unknown => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unknown rule field `{unknown}` at line {line_no}"),
                        ));
                    }
                }
            }
        }
    }

    if let Some(existing) = current_rule.take() {
        match section {
            Section::Include => {
                includes.push(finalize_include(existing, content.lines().count() + 1)?)
            }
            Section::Exclude => {
                excludes.push(finalize_exclude(existing, content.lines().count() + 1)?)
            }
            Section::Root => {}
        }
    }

    Ok(Test262Profile {
        schema_version,
        profile_name,
        es_profile,
        includes,
        excludes,
    })
}

fn parse_waiver_toml(content: &str) -> io::Result<Test262WaiverSet> {
    #[derive(Default)]
    struct RawWaiver {
        test_id: Option<String>,
        reason_code: Option<String>,
        es2020_clause: Option<String>,
        tracking_bead: Option<String>,
        expiry_date: Option<String>,
        reviewer: Option<String>,
    }

    fn finalize(raw: RawWaiver, line_no: usize) -> io::Result<Test262Waiver> {
        let test_id = raw.test_id.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("waiver missing test_id before line {line_no}"),
            )
        })?;

        let reason_code_raw = raw.reason_code.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("waiver `{test_id}` missing reason_code"),
            )
        })?;
        let reason_code =
            Test262WaiverReason::parse(reason_code_raw.as_str()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("waiver `{test_id}` has unknown reason_code `{reason_code_raw}`"),
                )
            })?;

        let es2020_clause = raw.es2020_clause.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("waiver `{test_id}` missing es2020_clause"),
            )
        })?;
        let tracking_bead = raw.tracking_bead.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("waiver `{test_id}` missing tracking_bead"),
            )
        })?;
        let expiry_date = raw.expiry_date.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("waiver `{test_id}` missing expiry_date"),
            )
        })?;
        let reviewer = raw.reviewer.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("waiver `{test_id}` missing reviewer"),
            )
        })?;

        Ok(Test262Waiver {
            test_id,
            reason_code,
            es2020_clause,
            tracking_bead,
            expiry_date,
            reviewer,
        })
    }

    let mut schema_version = TEST262_WAIVER_SCHEMA.to_string();
    let mut waivers = Vec::new();
    let mut current: Option<RawWaiver> = None;

    for (idx, raw) in content.lines().enumerate() {
        let line_no = idx + 1;
        let stripped = strip_comment(raw);
        if stripped.is_empty() {
            continue;
        }

        if stripped == "[[waiver]]" {
            if let Some(existing) = current.take() {
                waivers.push(finalize(existing, line_no)?);
            }
            current = Some(RawWaiver::default());
            continue;
        }

        let (key, value) = parse_key_value(line_no, stripped)?;

        if key == "schema_version" && current.is_none() {
            schema_version = value;
            continue;
        }

        let Some(waiver) = current.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("waiver field before [[waiver]] at line {line_no}"),
            ));
        };

        match key.as_str() {
            "test_id" => waiver.test_id = Some(value),
            "reason_code" => waiver.reason_code = Some(value),
            "es2020_clause" => waiver.es2020_clause = Some(value),
            "tracking_bead" => waiver.tracking_bead = Some(value),
            "expiry_date" => waiver.expiry_date = Some(value),
            "reviewer" => waiver.reviewer = Some(value),
            unknown => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown waiver field `{unknown}` at line {line_no}"),
                ));
            }
        }
    }

    if let Some(last) = current.take() {
        waivers.push(finalize(last, content.lines().count() + 1)?);
    }

    Ok(Test262WaiverSet {
        schema_version,
        waivers,
    })
}

fn parse_key_value(line_no: usize, stripped: &str) -> io::Result<(String, String)> {
    let (key, raw_value) = stripped.split_once('=').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid key=value entry at line {line_no}"),
        )
    })?;
    let key = key.trim().to_string();
    let value = parse_quoted(line_no, raw_value)?;
    Ok((key, value))
}

fn parse_quoted(line_no: usize, raw_value: &str) -> io::Result<String> {
    let trimmed = raw_value.trim();
    if trimmed.len() < 2 || !trimmed.starts_with('"') || !trimmed.ends_with('"') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid TOML string at line {line_no}"),
        ));
    }
    Ok(trimmed[1..trimmed.len() - 1].to_string())
}

fn strip_comment(raw: &str) -> &str {
    let mut in_quotes = false;
    for (i, c) in raw.char_indices() {
        if c == '"' {
            in_quotes = !in_quotes;
        } else if c == '#' && !in_quotes {
            return raw[..i].trim();
        }
    }
    raw.trim()
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();

    let mut dp = vec![vec![false; t.len() + 1]; p.len() + 1];
    dp[0][0] = true;

    for i in 1..=p.len() {
        if p[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        }
    }

    for i in 1..=p.len() {
        for j in 1..=t.len() {
            dp[i][j] = if p[i - 1] == '*' {
                dp[i - 1][j] || dp[i][j - 1]
            } else if p[i - 1] == t[j - 1] {
                dp[i - 1][j - 1]
            } else {
                false
            };
        }
    }

    dp[p.len()][t.len()]
}

fn looks_like_yyyy_mm_dd(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 {
        return false;
    }
    bytes[0..4].iter().all(|b| b.is_ascii_digit())
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(|b| b.is_ascii_digit())
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(|b| b.is_ascii_digit())
}

fn is_hex_hash(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn digest_hex(bytes: &[u8]) -> String {
    format!("{:016x}", fnv1a64(bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0100_0000_01b3;

    let mut hash = OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp_path = path.with_extension("tmp");
    fs::write(&temp_path, bytes)?;
    fs::rename(temp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper constructors ────────────────────────────────────────────

    fn valid_pin() -> Test262PinSet {
        Test262PinSet {
            schema_version: TEST262_PIN_SCHEMA.to_string(),
            source_repo: "tc39/test262".to_string(),
            es_profile: "ES2020".to_string(),
            test262_commit: "a".repeat(40),
        }
    }

    fn valid_profile() -> Test262Profile {
        Test262Profile {
            schema_version: TEST262_PROFILE_SCHEMA.to_string(),
            profile_name: "es2020-baseline".to_string(),
            es_profile: "ES2020".to_string(),
            includes: vec![Test262ProfileInclude {
                pattern: "test/language/*".to_string(),
                rationale: "core language tests".to_string(),
                normative_clause: "ECMA-262 §15".to_string(),
            }],
            excludes: vec![],
        }
    }

    fn valid_waiver_set() -> Test262WaiverSet {
        Test262WaiverSet::default()
    }

    fn valid_runner_config() -> Test262RunnerConfig {
        Test262RunnerConfig {
            run_date: "2025-01-15".to_string(),
            ..Test262RunnerConfig::default()
        }
    }

    // ── Test262PinSet::validate ────────────────────────────────────────

    #[test]
    fn pin_validate_valid() {
        assert!(valid_pin().validate().is_ok());
    }

    #[test]
    fn pin_validate_wrong_schema() {
        let mut pin = valid_pin();
        pin.schema_version = "wrong".to_string();
        assert!(pin.validate().is_err());
    }

    #[test]
    fn pin_validate_empty_source_repo() {
        let mut pin = valid_pin();
        pin.source_repo = "  ".to_string();
        assert!(pin.validate().is_err());
    }

    #[test]
    fn pin_validate_wrong_es_profile() {
        let mut pin = valid_pin();
        pin.es_profile = "ES2021".to_string();
        assert!(pin.validate().is_err());
    }

    #[test]
    fn pin_validate_invalid_commit_hash() {
        let mut pin = valid_pin();
        pin.test262_commit = "not_a_hex_hash".to_string();
        assert!(pin.validate().is_err());
    }

    #[test]
    fn pin_validate_commit_hash_too_short() {
        let mut pin = valid_pin();
        pin.test262_commit = "abcdef".to_string();
        assert!(pin.validate().is_err());
    }

    // ── Test262Profile::validate ───────────────────────────────────────

    #[test]
    fn profile_validate_valid() {
        assert!(valid_profile().validate().is_ok());
    }

    #[test]
    fn profile_validate_wrong_schema() {
        let mut p = valid_profile();
        p.schema_version = "wrong".to_string();
        assert!(p.validate().is_err());
    }

    #[test]
    fn profile_validate_empty_name() {
        let mut p = valid_profile();
        p.profile_name = " ".to_string();
        assert!(p.validate().is_err());
    }

    #[test]
    fn profile_validate_wrong_es_profile() {
        let mut p = valid_profile();
        p.es_profile = "ES2023".to_string();
        assert!(p.validate().is_err());
    }

    #[test]
    fn profile_validate_empty_includes() {
        let mut p = valid_profile();
        p.includes.clear();
        assert!(p.validate().is_err());
    }

    #[test]
    fn profile_validate_empty_include_pattern() {
        let mut p = valid_profile();
        p.includes[0].pattern = "".to_string();
        assert!(p.validate().is_err());
    }

    #[test]
    fn profile_validate_empty_include_rationale() {
        let mut p = valid_profile();
        p.includes[0].rationale = "".to_string();
        assert!(p.validate().is_err());
    }

    #[test]
    fn profile_validate_empty_exclude_pattern() {
        let mut p = valid_profile();
        p.excludes.push(Test262ProfileExclude {
            pattern: "".to_string(),
            rationale: "reason".to_string(),
            normative_clause: "clause".to_string(),
        });
        assert!(p.validate().is_err());
    }

    // ── Test262Profile::classify ───────────────────────────────────────

    #[test]
    fn profile_classify_included() {
        let p = valid_profile();
        assert_eq!(
            p.classify("test/language/expressions"),
            ProfileDecision::Included
        );
    }

    #[test]
    fn profile_classify_not_selected() {
        let p = valid_profile();
        assert_eq!(
            p.classify("test/intl402/something"),
            ProfileDecision::NotSelected
        );
    }

    #[test]
    fn profile_classify_excluded() {
        let mut p = valid_profile();
        p.excludes.push(Test262ProfileExclude {
            pattern: "test/language/expressions*".to_string(),
            rationale: "not ready".to_string(),
            normative_clause: "N/A".to_string(),
        });
        let decision = p.classify("test/language/expressions/arrow");
        assert!(matches!(decision, ProfileDecision::Excluded { .. }));
    }

    // ── Test262WaiverReason::parse ─────────────────────────────────────

    #[test]
    fn waiver_reason_parse_all_variants() {
        assert_eq!(
            Test262WaiverReason::parse("harness_gap"),
            Some(Test262WaiverReason::HarnessGap)
        );
        assert_eq!(
            Test262WaiverReason::parse("host_hook_missing"),
            Some(Test262WaiverReason::HostHookMissing)
        );
        assert_eq!(
            Test262WaiverReason::parse("intentional_divergence"),
            Some(Test262WaiverReason::IntentionalDivergence)
        );
        assert_eq!(
            Test262WaiverReason::parse("not_yet_implemented"),
            Some(Test262WaiverReason::NotYetImplemented)
        );
    }

    #[test]
    fn waiver_reason_parse_trims() {
        assert_eq!(
            Test262WaiverReason::parse("  harness_gap  "),
            Some(Test262WaiverReason::HarnessGap)
        );
    }

    #[test]
    fn waiver_reason_parse_unknown() {
        assert!(Test262WaiverReason::parse("unknown").is_none());
    }

    #[test]
    fn waiver_reason_serde_round_trip() {
        for reason in [
            Test262WaiverReason::HarnessGap,
            Test262WaiverReason::HostHookMissing,
            Test262WaiverReason::IntentionalDivergence,
            Test262WaiverReason::NotYetImplemented,
        ] {
            let json = serde_json::to_string(&reason).unwrap();
            let back: Test262WaiverReason = serde_json::from_str(&json).unwrap();
            assert_eq!(back, reason);
        }
    }

    // ── Test262WaiverSet::validate ─────────────────────────────────────

    #[test]
    fn waiver_set_validate_empty() {
        assert!(valid_waiver_set().validate().is_ok());
    }

    #[test]
    fn waiver_set_default_is_valid() {
        assert!(Test262WaiverSet::default().validate().is_ok());
    }

    #[test]
    fn waiver_set_load_missing_file_returns_valid_default() {
        let path = std::env::temp_dir()
            .join("franken_t262_missing")
            .join("waivers.toml");
        let waivers = Test262WaiverSet::load_toml(&path).expect("load missing file");
        assert_eq!(waivers, Test262WaiverSet::default());
        waivers
            .validate()
            .expect("missing-file default should validate");
    }

    #[test]
    fn waiver_set_validate_wrong_schema() {
        let mut ws = valid_waiver_set();
        ws.schema_version = "wrong".to_string();
        assert!(ws.validate().is_err());
    }

    #[test]
    fn waiver_set_validate_empty_test_id() {
        let mut ws = valid_waiver_set();
        ws.waivers.push(Test262Waiver {
            test_id: "".to_string(),
            reason_code: Test262WaiverReason::HarnessGap,
            es2020_clause: "§15".to_string(),
            tracking_bead: "bd-1".to_string(),
            expiry_date: "2030-01-01".to_string(),
            reviewer: "admin".to_string(),
        });
        assert!(ws.validate().is_err());
    }

    #[test]
    fn waiver_set_validate_bad_expiry_date() {
        let mut ws = valid_waiver_set();
        ws.waivers.push(Test262Waiver {
            test_id: "test-001".to_string(),
            reason_code: Test262WaiverReason::HarnessGap,
            es2020_clause: "§15".to_string(),
            tracking_bead: "bd-1".to_string(),
            expiry_date: "not-a-date".to_string(),
            reviewer: "admin".to_string(),
        });
        assert!(ws.validate().is_err());
    }

    // ── Test262WaiverSet::find_active ──────────────────────────────────

    #[test]
    fn waiver_set_find_active_match() {
        let mut ws = valid_waiver_set();
        ws.waivers.push(Test262Waiver {
            test_id: "test-001".to_string(),
            reason_code: Test262WaiverReason::HarnessGap,
            es2020_clause: "§15".to_string(),
            tracking_bead: "bd-1".to_string(),
            expiry_date: "2030-01-01".to_string(),
            reviewer: "admin".to_string(),
        });
        assert!(ws.find_active("test-001", "2025-06-01").is_some());
    }

    #[test]
    fn waiver_set_find_active_expired() {
        let mut ws = valid_waiver_set();
        ws.waivers.push(Test262Waiver {
            test_id: "test-001".to_string(),
            reason_code: Test262WaiverReason::HarnessGap,
            es2020_clause: "§15".to_string(),
            tracking_bead: "bd-1".to_string(),
            expiry_date: "2020-01-01".to_string(),
            reviewer: "admin".to_string(),
        });
        assert!(ws.find_active("test-001", "2025-06-01").is_none());
    }

    #[test]
    fn waiver_set_find_active_wrong_test_id() {
        let mut ws = valid_waiver_set();
        ws.waivers.push(Test262Waiver {
            test_id: "test-001".to_string(),
            reason_code: Test262WaiverReason::HarnessGap,
            es2020_clause: "§15".to_string(),
            tracking_bead: "bd-1".to_string(),
            expiry_date: "2030-01-01".to_string(),
            reviewer: "admin".to_string(),
        });
        assert!(ws.find_active("test-999", "2025-06-01").is_none());
    }

    // ── Test262RunnerConfig ───────────────────────────────────────────

    #[test]
    fn runner_config_default_values() {
        let cfg = Test262RunnerConfig::default();
        assert_eq!(cfg.locale, "C");
        assert_eq!(cfg.timezone, "UTC");
        assert_eq!(cfg.gc_schedule, "deterministic");
        assert_eq!(cfg.worker_count, 8);
        assert!(!cfg.acknowledge_pass_regression);
    }

    #[test]
    fn runner_config_validate_valid() {
        assert!(valid_runner_config().validate().is_ok());
    }

    #[test]
    fn runner_config_validate_empty_trace_prefix() {
        let mut cfg = valid_runner_config();
        cfg.trace_prefix = "".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn runner_config_validate_empty_policy_id() {
        let mut cfg = valid_runner_config();
        cfg.policy_id = "  ".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn runner_config_validate_bad_run_date() {
        let mut cfg = valid_runner_config();
        cfg.run_date = "2025/01/01".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn runner_config_validate_zero_workers() {
        let mut cfg = valid_runner_config();
        cfg.worker_count = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn runner_config_validate_wrong_locale() {
        let mut cfg = valid_runner_config();
        cfg.locale = "en_US".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn runner_config_validate_wrong_timezone() {
        let mut cfg = valid_runner_config();
        cfg.timezone = "EST".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn runner_config_validate_wrong_gc() {
        let mut cfg = valid_runner_config();
        cfg.gc_schedule = "random".to_string();
        assert!(cfg.validate().is_err());
    }

    // ── Test262Outcome::blocks_release ─────────────────────────────────

    #[test]
    fn outcome_blocks_release() {
        assert!(Test262Outcome::Fail.blocks_release());
        assert!(Test262Outcome::Timeout.blocks_release());
        assert!(Test262Outcome::Crash.blocks_release());
        assert!(!Test262Outcome::Pass.blocks_release());
        assert!(!Test262Outcome::Waived.blocks_release());
    }

    #[test]
    fn outcome_serde_round_trip() {
        for outcome in [
            Test262Outcome::Pass,
            Test262Outcome::Fail,
            Test262Outcome::Waived,
            Test262Outcome::Timeout,
            Test262Outcome::Crash,
        ] {
            let json = serde_json::to_string(&outcome).unwrap();
            let back: Test262Outcome = serde_json::from_str(&json).unwrap();
            assert_eq!(back, outcome);
        }
    }

    #[test]
    fn observed_outcome_serde_round_trip() {
        for outcome in [
            Test262ObservedOutcome::Pass,
            Test262ObservedOutcome::Fail,
            Test262ObservedOutcome::Timeout,
            Test262ObservedOutcome::Crash,
        ] {
            let json = serde_json::to_string(&outcome).unwrap();
            let back: Test262ObservedOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(back, outcome);
        }
    }

    // ── deterministic_worker_assignments ───────────────────────────────

    #[test]
    fn worker_assignments_round_robin() {
        let test_ids: Vec<String> = (0..6).map(|i| format!("test-{i:03}")).collect();
        let assignments = deterministic_worker_assignments(&test_ids, 3);
        assert_eq!(assignments.len(), 6);
        for a in &assignments {
            assert!(a.worker_index < 3);
        }
        // Round-robin: sorted tests get 0,1,2,0,1,2
        let workers: Vec<usize> = assignments.iter().map(|a| a.worker_index).collect();
        assert_eq!(workers, vec![0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn worker_assignments_single_worker() {
        let test_ids = vec!["a".to_string(), "b".to_string()];
        let assignments = deterministic_worker_assignments(&test_ids, 1);
        assert!(assignments.iter().all(|a| a.worker_index == 0));
    }

    #[test]
    fn worker_assignments_empty() {
        let assignments = deterministic_worker_assignments(&[], 4);
        assert!(assignments.is_empty());
    }

    #[test]
    fn worker_assignments_deterministic() {
        let test_ids: Vec<String> = (0..10).map(|i| format!("test-{i:03}")).collect();
        let a = deterministic_worker_assignments(&test_ids, 4);
        let b = deterministic_worker_assignments(&test_ids, 4);
        assert_eq!(a, b);
    }

    #[test]
    fn worker_assignments_queue_index_increments() {
        let test_ids: Vec<String> = (0..4).map(|i| format!("test-{i:03}")).collect();
        let assignments = deterministic_worker_assignments(&test_ids, 2);
        // Worker 0 gets test-000 (queue 0) and test-002 (queue 1)
        let w0: Vec<usize> = assignments
            .iter()
            .filter(|a| a.worker_index == 0)
            .map(|a| a.queue_index)
            .collect();
        assert_eq!(w0, vec![0, 1]);
    }

    // ── next_high_water_mark ──────────────────────────────────────────

    #[test]
    fn hwm_takes_max_of_previous_and_current() {
        let run = Test262GateRun {
            run_id: "run-1".to_string(),
            blocked: false,
            logs: vec![],
            summary: Test262RunSummary {
                run_id: "run-1".to_string(),
                total_profile_tests: 100,
                passed: 80,
                failed: 0,
                waived: 0,
                timed_out: 0,
                crashed: 0,
                blocked_failures: 0,
                profile_hash: "ph".to_string(),
                waiver_hash: "wh".to_string(),
                pin_hash: "pinh".to_string(),
                env_fingerprint: "ef".to_string(),
                pass_regression_warning: None,
            },
        };

        let previous = Test262HighWaterMark {
            schema_version: TEST262_HWM_SCHEMA.to_string(),
            profile_hash: "ph".to_string(),
            pass_count: 90,
            recorded_at_utc: "2025-01-01T00:00:00Z".to_string(),
        };

        let hwm = next_high_water_mark(&run, Some(&previous));
        assert_eq!(hwm.pass_count, 90); // max(80, 90)
        assert_eq!(hwm.schema_version, TEST262_HWM_SCHEMA);
    }

    #[test]
    fn hwm_no_previous() {
        let run = Test262GateRun {
            run_id: "run-1".to_string(),
            blocked: false,
            logs: vec![],
            summary: Test262RunSummary {
                run_id: "run-1".to_string(),
                total_profile_tests: 50,
                passed: 45,
                failed: 0,
                waived: 0,
                timed_out: 0,
                crashed: 0,
                blocked_failures: 0,
                profile_hash: "ph".to_string(),
                waiver_hash: "wh".to_string(),
                pin_hash: "pinh".to_string(),
                env_fingerprint: "ef".to_string(),
                pass_regression_warning: None,
            },
        };

        let hwm = next_high_water_mark(&run, None);
        assert_eq!(hwm.pass_count, 45); // max(45, 0)
    }

    // ── wildcard_match ─────────────────────────────────────────────────

    #[test]
    fn wildcard_exact_match() {
        assert!(wildcard_match("hello", "hello"));
    }

    #[test]
    fn wildcard_no_match() {
        assert!(!wildcard_match("hello", "world"));
    }

    #[test]
    fn wildcard_star_matches_all() {
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("*", ""));
    }

    #[test]
    fn wildcard_prefix_star() {
        assert!(wildcard_match("test/*", "test/foo"));
        assert!(wildcard_match("test/*", "test/foo/bar"));
        assert!(!wildcard_match("test/*", "other/foo"));
    }

    #[test]
    fn wildcard_suffix_star() {
        assert!(wildcard_match("*.js", "module.js"));
        assert!(!wildcard_match("*.js", "module.ts"));
    }

    #[test]
    fn wildcard_middle_star() {
        assert!(wildcard_match("test/*/spec", "test/anything/spec"));
    }

    #[test]
    fn wildcard_empty_pattern_empty_text() {
        assert!(wildcard_match("", ""));
    }

    // ── looks_like_yyyy_mm_dd ──────────────────────────────────────────

    #[test]
    fn date_valid() {
        assert!(looks_like_yyyy_mm_dd("2025-01-15"));
        assert!(looks_like_yyyy_mm_dd("1970-01-01"));
    }

    #[test]
    fn date_invalid_format() {
        assert!(!looks_like_yyyy_mm_dd("2025/01/15"));
        assert!(!looks_like_yyyy_mm_dd("25-01-15"));
        assert!(!looks_like_yyyy_mm_dd("not-a-date"));
        assert!(!looks_like_yyyy_mm_dd(""));
    }

    // ── is_hex_hash ────────────────────────────────────────────────────

    #[test]
    fn hex_hash_valid() {
        assert!(is_hex_hash(&"a".repeat(40), 40));
        assert!(is_hex_hash("0123456789abcdef", 16));
    }

    #[test]
    fn hex_hash_wrong_length() {
        assert!(!is_hex_hash("abc", 40));
    }

    #[test]
    fn hex_hash_non_hex() {
        assert!(!is_hex_hash(&"g".repeat(40), 40));
    }

    // ── parse_pin_toml ─────────────────────────────────────────────────

    #[test]
    fn parse_pin_toml_valid() {
        let toml = r#"
schema_version = "franken-engine.test262-pin.v1"
source_repo = "tc39/test262"
es_profile = "ES2020"
test262_commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;
        let pin = parse_pin_toml(toml).unwrap();
        assert_eq!(pin.source_repo, "tc39/test262");
        assert_eq!(pin.es_profile, "ES2020");
        assert_eq!(pin.test262_commit, "a".repeat(40));
    }

    #[test]
    fn parse_pin_toml_comments_stripped() {
        let toml = r#"
# Comment
source_repo = "tc39/test262" # inline comment
es_profile = "ES2020"
test262_commit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
"#;
        let pin = parse_pin_toml(toml).unwrap();
        assert_eq!(pin.source_repo, "tc39/test262");
    }

    // ── parse_profile_toml ─────────────────────────────────────────────

    #[test]
    fn parse_profile_toml_with_include_and_exclude() {
        let toml = r#"
schema_version = "franken-engine.test262-profile.v1"
profile_name = "es2020-baseline"
es_profile = "ES2020"

[[include]]
pattern = "test/language/*"
rationale = "core language"
normative_clause = "ECMA-262 §15"

[[exclude]]
pattern = "test/language/module-code/*"
rationale = "modules not ready"
normative_clause = "ECMA-262 §16"
"#;
        let profile = parse_profile_toml(toml).unwrap();
        assert_eq!(profile.includes.len(), 1);
        assert_eq!(profile.excludes.len(), 1);
        assert_eq!(profile.includes[0].pattern, "test/language/*");
        assert_eq!(profile.excludes[0].pattern, "test/language/module-code/*");
    }

    // ── parse_waiver_toml ──────────────────────────────────────────────

    #[test]
    fn parse_waiver_toml_valid() {
        let toml = r#"
schema_version = "franken-engine.test262-waiver.v1"

[[waiver]]
test_id = "test-001"
reason_code = "harness_gap"
es2020_clause = "§15.1"
tracking_bead = "bd-42"
expiry_date = "2030-01-01"
reviewer = "admin"
"#;
        let ws = parse_waiver_toml(toml).unwrap();
        assert_eq!(ws.waivers.len(), 1);
        assert_eq!(ws.waivers[0].test_id, "test-001");
        assert_eq!(ws.waivers[0].reviewer, "admin");
    }

    #[test]
    fn parse_waiver_toml_empty() {
        let toml = r#"
schema_version = "franken-engine.test262-waiver.v1"
"#;
        let ws = parse_waiver_toml(toml).unwrap();
        assert!(ws.waivers.is_empty());
    }

    #[test]
    fn parse_waiver_toml_missing_field_errors() {
        let toml = r#"
schema_version = "franken-engine.test262-waiver.v1"

[[waiver]]
test_id = "test-001"
reason_code = "harness_gap"
"#;
        assert!(parse_waiver_toml(toml).is_err());
    }

    // ── strip_comment ──────────────────────────────────────────────────

    #[test]
    fn strip_comment_basic() {
        assert_eq!(strip_comment("hello # world"), "hello");
        assert_eq!(strip_comment("# all comment"), "");
        assert_eq!(strip_comment("no comment"), "no comment");
    }

    // ── Test262GateError ──────────────────────────────────────────────

    #[test]
    fn gate_error_stable_codes() {
        let err = Test262GateError::InvalidConfig("test".to_string());
        assert_eq!(err.stable().code, FE_T262_INVALID_CONFIG);

        let err = Test262GateError::DuplicateObservedResult {
            test_id: "t-1".to_string(),
        };
        assert_eq!(err.stable().code, FE_T262_DUPLICATE_RESULT);

        let err = Test262GateError::MissingObservedField {
            test_id: "t-1".to_string(),
            field: "es2020_clause",
        };
        assert_eq!(err.stable().code, FE_T262_MISSING_FIELD);

        let err = Test262GateError::InvalidProfile("bad".to_string());
        assert_eq!(err.stable().code, FE_T262_INVALID_PROFILE);
    }

    #[test]
    fn gate_error_display_includes_code() {
        let err = Test262GateError::InvalidConfig("missing field".to_string());
        let msg = err.to_string();
        assert!(msg.contains(FE_T262_INVALID_CONFIG));
        assert!(msg.contains("missing field"));
    }

    // ── Test262GateRunner::env_fingerprint ─────────────────────────────

    #[test]
    fn env_fingerprint_deterministic() {
        let runner = Test262GateRunner::default();
        let a = runner.env_fingerprint();
        let b = runner.env_fingerprint();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    // ── serde round-trips ──────────────────────────────────────────────

    #[test]
    fn pin_set_serde_round_trip() {
        let pin = valid_pin();
        let json = serde_json::to_string(&pin).unwrap();
        let back: Test262PinSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pin);
    }

    #[test]
    fn profile_serde_round_trip() {
        let profile = valid_profile();
        let json = serde_json::to_string(&profile).unwrap();
        let back: Test262Profile = serde_json::from_str(&json).unwrap();
        assert_eq!(back, profile);
    }

    #[test]
    fn waiver_set_serde_round_trip() {
        let ws = valid_waiver_set();
        let json = serde_json::to_string(&ws).unwrap();
        let back: Test262WaiverSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ws);
    }

    #[test]
    fn runner_config_serde_round_trip() {
        let cfg = Test262RunnerConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: Test262RunnerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    // ── Test262GateRunner::run ─────────────────────────────────────────

    fn make_observed(
        test_id: &str,
        clause: &str,
        outcome: Test262ObservedOutcome,
    ) -> Test262ObservedResult {
        Test262ObservedResult {
            test_id: test_id.to_string(),
            es2020_clause: clause.to_string(),
            outcome,
            duration_us: 100,
            error_code: None,
            error_detail: None,
        }
    }

    #[test]
    fn gate_runner_all_pass() {
        let runner = Test262GateRunner {
            config: valid_runner_config(),
        };
        let observed = vec![
            make_observed(
                "test/language/expr-1",
                "§15.1",
                Test262ObservedOutcome::Pass,
            ),
            make_observed(
                "test/language/expr-2",
                "§15.2",
                Test262ObservedOutcome::Pass,
            ),
        ];
        let result = runner
            .run(
                &valid_pin(),
                &valid_profile(),
                &valid_waiver_set(),
                &observed,
                None,
            )
            .unwrap();
        assert!(!result.blocked);
        assert_eq!(result.summary.passed, 2);
        assert_eq!(result.summary.failed, 0);
        assert_eq!(result.summary.waived, 0);
        assert_eq!(result.summary.blocked_failures, 0);
        assert_eq!(result.logs.len(), 2);
    }

    #[test]
    fn gate_runner_fail_unwaived_blocks() {
        let runner = Test262GateRunner {
            config: valid_runner_config(),
        };
        let observed = vec![
            make_observed(
                "test/language/expr-1",
                "§15.1",
                Test262ObservedOutcome::Pass,
            ),
            make_observed(
                "test/language/fail-1",
                "§15.2",
                Test262ObservedOutcome::Fail,
            ),
        ];
        let result = runner
            .run(
                &valid_pin(),
                &valid_profile(),
                &valid_waiver_set(),
                &observed,
                None,
            )
            .unwrap();
        assert!(result.blocked);
        assert_eq!(result.summary.passed, 1);
        assert_eq!(result.summary.failed, 1);
        assert_eq!(result.summary.blocked_failures, 1);
    }

    #[test]
    fn gate_runner_fail_waived_does_not_block() {
        let mut ws = valid_waiver_set();
        ws.waivers.push(Test262Waiver {
            test_id: "test/language/fail-1".to_string(),
            reason_code: Test262WaiverReason::HarnessGap,
            es2020_clause: "§15.2".to_string(),
            tracking_bead: "bd-99".to_string(),
            expiry_date: "2030-01-01".to_string(),
            reviewer: "admin".to_string(),
        });
        let runner = Test262GateRunner {
            config: valid_runner_config(),
        };
        let observed = vec![make_observed(
            "test/language/fail-1",
            "§15.2",
            Test262ObservedOutcome::Fail,
        )];
        let result = runner
            .run(&valid_pin(), &valid_profile(), &ws, &observed, None)
            .unwrap();
        assert!(!result.blocked);
        assert_eq!(result.summary.waived, 1);
        assert_eq!(result.summary.failed, 0);
    }

    #[test]
    fn gate_runner_timeout_unwaived_blocks() {
        let runner = Test262GateRunner {
            config: valid_runner_config(),
        };
        let observed = vec![make_observed(
            "test/language/timeout-1",
            "§15.1",
            Test262ObservedOutcome::Timeout,
        )];
        let result = runner
            .run(
                &valid_pin(),
                &valid_profile(),
                &valid_waiver_set(),
                &observed,
                None,
            )
            .unwrap();
        assert!(result.blocked);
        assert_eq!(result.summary.timed_out, 1);
    }

    #[test]
    fn gate_runner_timeout_waived_does_not_block() {
        let mut ws = valid_waiver_set();
        ws.waivers.push(Test262Waiver {
            test_id: "test/language/timeout-1".to_string(),
            reason_code: Test262WaiverReason::NotYetImplemented,
            es2020_clause: "§15.1".to_string(),
            tracking_bead: "bd-100".to_string(),
            expiry_date: "2030-01-01".to_string(),
            reviewer: "admin".to_string(),
        });
        let runner = Test262GateRunner {
            config: valid_runner_config(),
        };
        let observed = vec![make_observed(
            "test/language/timeout-1",
            "§15.1",
            Test262ObservedOutcome::Timeout,
        )];
        let result = runner
            .run(&valid_pin(), &valid_profile(), &ws, &observed, None)
            .unwrap();
        assert!(!result.blocked);
        assert_eq!(result.summary.waived, 1);
        assert_eq!(result.summary.timed_out, 0);
    }

    #[test]
    fn gate_runner_crash_unwaived_blocks() {
        let runner = Test262GateRunner {
            config: valid_runner_config(),
        };
        let observed = vec![make_observed(
            "test/language/crash-1",
            "§15.1",
            Test262ObservedOutcome::Crash,
        )];
        let result = runner
            .run(
                &valid_pin(),
                &valid_profile(),
                &valid_waiver_set(),
                &observed,
                None,
            )
            .unwrap();
        assert!(result.blocked);
        assert_eq!(result.summary.crashed, 1);
    }

    #[test]
    fn gate_runner_crash_waived_does_not_block() {
        let mut ws = valid_waiver_set();
        ws.waivers.push(Test262Waiver {
            test_id: "test/language/crash-1".to_string(),
            reason_code: Test262WaiverReason::HostHookMissing,
            es2020_clause: "§15.1".to_string(),
            tracking_bead: "bd-101".to_string(),
            expiry_date: "2030-01-01".to_string(),
            reviewer: "admin".to_string(),
        });
        let runner = Test262GateRunner {
            config: valid_runner_config(),
        };
        let observed = vec![make_observed(
            "test/language/crash-1",
            "§15.1",
            Test262ObservedOutcome::Crash,
        )];
        let result = runner
            .run(&valid_pin(), &valid_profile(), &ws, &observed, None)
            .unwrap();
        assert!(!result.blocked);
        assert_eq!(result.summary.waived, 1);
    }

    #[test]
    fn gate_runner_duplicate_test_id_error() {
        let runner = Test262GateRunner {
            config: valid_runner_config(),
        };
        let observed = vec![
            make_observed(
                "test/language/expr-1",
                "§15.1",
                Test262ObservedOutcome::Pass,
            ),
            make_observed(
                "test/language/expr-1",
                "§15.1",
                Test262ObservedOutcome::Pass,
            ),
        ];
        let err = runner
            .run(
                &valid_pin(),
                &valid_profile(),
                &valid_waiver_set(),
                &observed,
                None,
            )
            .unwrap_err();
        let info = err.stable();
        assert_eq!(info.code, FE_T262_DUPLICATE_RESULT);
    }

    #[test]
    fn gate_runner_empty_test_id_error() {
        let runner = Test262GateRunner {
            config: valid_runner_config(),
        };
        let observed = vec![make_observed("", "§15.1", Test262ObservedOutcome::Pass)];
        let err = runner
            .run(
                &valid_pin(),
                &valid_profile(),
                &valid_waiver_set(),
                &observed,
                None,
            )
            .unwrap_err();
        let info = err.stable();
        assert_eq!(info.code, FE_T262_MISSING_FIELD);
    }

    #[test]
    fn gate_runner_empty_clause_error() {
        let runner = Test262GateRunner {
            config: valid_runner_config(),
        };
        let observed = vec![make_observed(
            "test/language/expr-1",
            "",
            Test262ObservedOutcome::Pass,
        )];
        let err = runner
            .run(
                &valid_pin(),
                &valid_profile(),
                &valid_waiver_set(),
                &observed,
                None,
            )
            .unwrap_err();
        let info = err.stable();
        assert_eq!(info.code, FE_T262_MISSING_FIELD);
    }

    #[test]
    fn gate_runner_non_selected_tests_excluded() {
        let runner = Test262GateRunner {
            config: valid_runner_config(),
        };
        // This test ID doesn't match the profile include pattern "test/language/*"
        let observed = vec![make_observed(
            "test/intl402/collation",
            "§10.1",
            Test262ObservedOutcome::Pass,
        )];
        let result = runner
            .run(
                &valid_pin(),
                &valid_profile(),
                &valid_waiver_set(),
                &observed,
                None,
            )
            .unwrap();
        assert_eq!(result.summary.total_profile_tests, 0);
        assert_eq!(result.summary.passed, 0);
        assert!(!result.blocked);
    }

    #[test]
    fn gate_runner_run_id_deterministic() {
        let runner = Test262GateRunner {
            config: valid_runner_config(),
        };
        let observed = vec![make_observed(
            "test/language/expr-1",
            "§15.1",
            Test262ObservedOutcome::Pass,
        )];
        let r1 = runner
            .run(
                &valid_pin(),
                &valid_profile(),
                &valid_waiver_set(),
                &observed,
                None,
            )
            .unwrap();
        let r2 = runner
            .run(
                &valid_pin(),
                &valid_profile(),
                &valid_waiver_set(),
                &observed,
                None,
            )
            .unwrap();
        assert_eq!(r1.run_id, r2.run_id);
    }

    #[test]
    fn gate_runner_log_events_have_trace_ids() {
        let runner = Test262GateRunner {
            config: valid_runner_config(),
        };
        let observed = vec![make_observed(
            "test/language/expr-1",
            "§15.1",
            Test262ObservedOutcome::Pass,
        )];
        let result = runner
            .run(
                &valid_pin(),
                &valid_profile(),
                &valid_waiver_set(),
                &observed,
                None,
            )
            .unwrap();
        assert!(!result.logs.is_empty());
        let log = &result.logs[0];
        assert!(!log.trace_id.is_empty());
        assert!(!log.decision_id.is_empty());
        assert_eq!(log.component, TEST262_COMPONENT);
        assert_eq!(log.event, "test262_case_evaluated");
    }

    #[test]
    fn gate_runner_with_error_code_on_observed() {
        let runner = Test262GateRunner {
            config: valid_runner_config(),
        };
        let mut obs = make_observed(
            "test/language/expr-1",
            "§15.1",
            Test262ObservedOutcome::Pass,
        );
        obs.error_code = Some("ERR-CUSTOM".to_string());
        let result = runner
            .run(
                &valid_pin(),
                &valid_profile(),
                &valid_waiver_set(),
                &[obs],
                None,
            )
            .unwrap();
        // Pass outcome has no error_code from the gate logic, so the observed error_code is used
        assert_eq!(result.logs[0].error_code.as_deref(), Some("ERR-CUSTOM"));
    }

    // ── Pass regression warning ───────────────────────────────────────

    #[test]
    fn gate_runner_pass_regression_blocks_without_ack() {
        let runner = Test262GateRunner {
            config: valid_runner_config(),
        };
        let observed = vec![make_observed(
            "test/language/expr-1",
            "§15.1",
            Test262ObservedOutcome::Pass,
        )];
        let previous_hwm = Test262HighWaterMark {
            schema_version: TEST262_HWM_SCHEMA.to_string(),
            profile_hash: "ph".to_string(),
            pass_count: 10, // previous had 10 passes, now only 1
            recorded_at_utc: "2025-01-01T00:00:00Z".to_string(),
        };
        let result = runner
            .run(
                &valid_pin(),
                &valid_profile(),
                &valid_waiver_set(),
                &observed,
                Some(&previous_hwm),
            )
            .unwrap();
        assert!(result.blocked);
        let warning = result.summary.pass_regression_warning.as_ref().unwrap();
        assert_eq!(warning.previous_high_water_mark, 10);
        assert_eq!(warning.current_pass_count, 1);
        assert!(warning.acknowledgement_required);
        assert!(!warning.acknowledged);
    }

    #[test]
    fn gate_runner_pass_regression_not_blocked_with_ack() {
        let mut config = valid_runner_config();
        config.acknowledge_pass_regression = true;
        let runner = Test262GateRunner { config };
        let observed = vec![make_observed(
            "test/language/expr-1",
            "§15.1",
            Test262ObservedOutcome::Pass,
        )];
        let previous_hwm = Test262HighWaterMark {
            schema_version: TEST262_HWM_SCHEMA.to_string(),
            profile_hash: "ph".to_string(),
            pass_count: 10,
            recorded_at_utc: "2025-01-01T00:00:00Z".to_string(),
        };
        let result = runner
            .run(
                &valid_pin(),
                &valid_profile(),
                &valid_waiver_set(),
                &observed,
                Some(&previous_hwm),
            )
            .unwrap();
        // Acknowledged, so not blocked from regression
        assert!(!result.blocked);
    }

    #[test]
    fn gate_runner_no_regression_when_pass_count_increases() {
        let runner = Test262GateRunner {
            config: valid_runner_config(),
        };
        let observed = vec![
            make_observed(
                "test/language/expr-1",
                "§15.1",
                Test262ObservedOutcome::Pass,
            ),
            make_observed(
                "test/language/expr-2",
                "§15.2",
                Test262ObservedOutcome::Pass,
            ),
        ];
        let previous_hwm = Test262HighWaterMark {
            schema_version: TEST262_HWM_SCHEMA.to_string(),
            profile_hash: "ph".to_string(),
            pass_count: 1, // previous was 1, now 2
            recorded_at_utc: "2025-01-01T00:00:00Z".to_string(),
        };
        let result = runner
            .run(
                &valid_pin(),
                &valid_profile(),
                &valid_waiver_set(),
                &observed,
                Some(&previous_hwm),
            )
            .unwrap();
        assert!(!result.blocked);
        assert!(result.summary.pass_regression_warning.is_none());
    }

    // ── Test262HighWaterMark file I/O ──────────────────────────────────

    #[test]
    fn hwm_write_and_load_round_trip() {
        let hwm = Test262HighWaterMark {
            schema_version: TEST262_HWM_SCHEMA.to_string(),
            profile_hash: "abc123".to_string(),
            pass_count: 42,
            recorded_at_utc: "2025-01-01T00:00:00Z".to_string(),
        };
        let dir = std::env::temp_dir().join("franken_t262_hwm_test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("hwm.json");
        hwm.write_json(&path).unwrap();
        let loaded = Test262HighWaterMark::load_json(&path).unwrap().unwrap();
        assert_eq!(loaded, hwm);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn hwm_load_nonexistent_returns_none() {
        let path = std::env::temp_dir().join("franken_t262_hwm_nonexistent.json");
        let _ = fs::remove_file(&path);
        let loaded = Test262HighWaterMark::load_json(&path).unwrap();
        assert!(loaded.is_none());
    }

    // ── Test262EvidenceCollector ───────────────────────────────────────

    #[test]
    fn evidence_collector_creates_artifacts() {
        let runner = Test262GateRunner {
            config: valid_runner_config(),
        };
        let observed = vec![make_observed(
            "test/language/expr-1",
            "§15.1",
            Test262ObservedOutcome::Pass,
        )];
        let result = runner
            .run(
                &valid_pin(),
                &valid_profile(),
                &valid_waiver_set(),
                &observed,
                None,
            )
            .unwrap();
        let hwm = next_high_water_mark(&result, None);

        let dir = std::env::temp_dir().join("franken_t262_evidence_test");
        let _ = fs::remove_dir_all(&dir);
        let collector = Test262EvidenceCollector::new(&dir).unwrap();
        let artifacts = collector.collect(&result, &hwm).unwrap();

        assert!(artifacts.run_manifest_path.exists());
        assert!(artifacts.evidence_path.exists());
        assert!(artifacts.high_water_mark_path.exists());

        // Evidence JSONL should have summary + log lines
        let evidence = fs::read_to_string(&artifacts.evidence_path).unwrap();
        let lines: Vec<&str> = evidence.lines().collect();
        assert!(lines.len() >= 2); // summary + at least 1 log

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Test262GateError additional coverage ───────────────────────────

    #[test]
    fn gate_error_io_variant() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let gate_err = Test262GateError::from(io_err);
        let info = gate_err.stable();
        assert_eq!(info.code, FE_T262_INVALID_CONFIG);
        assert!(info.detail.contains("file not found"));
    }

    #[test]
    fn gate_error_io_source() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "oops");
        let gate_err = Test262GateError::Io(io_err);
        assert!(gate_err.source().is_some());
    }

    #[test]
    fn gate_error_non_io_source_is_none() {
        let err = Test262GateError::InvalidConfig("test".to_string());
        assert!(err.source().is_none());
        let err = Test262GateError::DuplicateObservedResult {
            test_id: "t".to_string(),
        };
        assert!(err.source().is_none());
    }

    // ── WaiverSet validate additional edge cases ──────────────────────

    #[test]
    fn waiver_set_validate_missing_es2020_clause() {
        let mut ws = valid_waiver_set();
        ws.waivers.push(Test262Waiver {
            test_id: "test-001".to_string(),
            reason_code: Test262WaiverReason::HarnessGap,
            es2020_clause: "  ".to_string(),
            tracking_bead: "bd-1".to_string(),
            expiry_date: "2030-01-01".to_string(),
            reviewer: "admin".to_string(),
        });
        assert!(ws.validate().is_err());
    }

    #[test]
    fn waiver_set_validate_missing_tracking_bead() {
        let mut ws = valid_waiver_set();
        ws.waivers.push(Test262Waiver {
            test_id: "test-001".to_string(),
            reason_code: Test262WaiverReason::HarnessGap,
            es2020_clause: "§15".to_string(),
            tracking_bead: "  ".to_string(),
            expiry_date: "2030-01-01".to_string(),
            reviewer: "admin".to_string(),
        });
        assert!(ws.validate().is_err());
    }

    #[test]
    fn waiver_set_validate_missing_reviewer() {
        let mut ws = valid_waiver_set();
        ws.waivers.push(Test262Waiver {
            test_id: "test-001".to_string(),
            reason_code: Test262WaiverReason::HarnessGap,
            es2020_clause: "§15".to_string(),
            tracking_bead: "bd-1".to_string(),
            expiry_date: "2030-01-01".to_string(),
            reviewer: "  ".to_string(),
        });
        assert!(ws.validate().is_err());
    }

    // ── Profile::classify with exclude rationale ──────────────────────

    #[test]
    fn profile_classify_excluded_includes_rationale() {
        let mut p = valid_profile();
        p.excludes.push(Test262ProfileExclude {
            pattern: "test/language/expressions*".to_string(),
            rationale: "WIP feature".to_string(),
            normative_clause: "N/A".to_string(),
        });
        match p.classify("test/language/expressions/arrow") {
            ProfileDecision::Excluded { rationale } => {
                assert_eq!(rationale, "WIP feature");
            }
            other => panic!("expected Excluded, got {:?}", other),
        }
    }

    // ── parse_quoted edge cases ───────────────────────────────────────

    #[test]
    fn parse_quoted_valid() {
        assert_eq!(parse_quoted(1, "\"hello\"").unwrap(), "hello");
    }

    #[test]
    fn parse_quoted_with_whitespace() {
        assert_eq!(parse_quoted(1, "  \"hello\"  ").unwrap(), "hello");
    }

    #[test]
    fn parse_quoted_unquoted_fails() {
        assert!(parse_quoted(1, "hello").is_err());
    }

    #[test]
    fn parse_quoted_single_quote_fails() {
        assert!(parse_quoted(1, "'hello'").is_err());
    }

    #[test]
    fn parse_quoted_empty_string_ok() {
        assert_eq!(parse_quoted(1, "\"\"").unwrap(), "");
    }

    #[test]
    fn parse_quoted_single_char_fails() {
        assert!(parse_quoted(1, "\"").is_err());
    }

    // ── parse_key_value ──────────────────────────────────────────────

    #[test]
    fn parse_key_value_valid() {
        let (k, v) = parse_key_value(1, "name = \"value\"").unwrap();
        assert_eq!(k, "name");
        assert_eq!(v, "value");
    }

    #[test]
    fn parse_key_value_no_equals_fails() {
        assert!(parse_key_value(1, "no_equals_here").is_err());
    }

    // ── write_atomic ─────────────────────────────────────────────────

    #[test]
    fn write_atomic_creates_file() {
        let dir = std::env::temp_dir().join("franken_t262_write_atomic");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test_atomic.txt");
        write_atomic(&path, b"hello world").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello world");
        let _ = fs::remove_dir_all(&dir);
    }

    // ── digest_hex / sha256_hex / fnv1a64 ────────────────────────────

    #[test]
    fn digest_hex_deterministic() {
        let a = digest_hex(b"hello");
        let b = digest_hex(b"hello");
        assert_eq!(a, b);
        assert_ne!(digest_hex(b"hello"), digest_hex(b"world"));
    }

    #[test]
    fn sha256_hex_length() {
        let hash = sha256_hex(b"test");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sha256_hex_deterministic() {
        assert_eq!(sha256_hex(b"hello"), sha256_hex(b"hello"));
        assert_ne!(sha256_hex(b"hello"), sha256_hex(b"world"));
    }

    #[test]
    fn fnv1a64_deterministic() {
        assert_eq!(fnv1a64(b"hello"), fnv1a64(b"hello"));
        assert_ne!(fnv1a64(b"hello"), fnv1a64(b"world"));
    }

    #[test]
    fn fnv1a64_empty() {
        // Empty input should return the FNV offset basis
        let result = fnv1a64(b"");
        assert_eq!(result, 0xcbf2_9ce4_8422_2325);
    }

    // ── Profile validate: exclude with empty rationale ────────────────

    #[test]
    fn profile_validate_empty_exclude_rationale() {
        let mut p = valid_profile();
        p.excludes.push(Test262ProfileExclude {
            pattern: "test/*".to_string(),
            rationale: "".to_string(),
            normative_clause: "clause".to_string(),
        });
        assert!(p.validate().is_err());
    }

    #[test]
    fn profile_validate_empty_include_normative_clause() {
        let mut p = valid_profile();
        p.includes[0].normative_clause = "  ".to_string();
        assert!(p.validate().is_err());
    }

    // ── parse_profile_toml: multiple includes ─────────────────────────

    #[test]
    fn parse_profile_toml_multiple_includes() {
        let toml = r#"
schema_version = "franken-engine.test262-profile.v1"
profile_name = "multi"
es_profile = "ES2020"

[[include]]
pattern = "test/language/*"
rationale = "lang tests"
normative_clause = "§15"

[[include]]
pattern = "test/built-ins/*"
rationale = "built-in tests"
normative_clause = "§18"
"#;
        let profile = parse_profile_toml(toml).unwrap();
        assert_eq!(profile.includes.len(), 2);
        assert_eq!(profile.includes[1].pattern, "test/built-ins/*");
    }

    // ── parse_waiver_toml: multiple waivers ───────────────────────────

    #[test]
    fn parse_waiver_toml_multiple_waivers() {
        let toml = r#"
schema_version = "franken-engine.test262-waiver.v1"

[[waiver]]
test_id = "test-001"
reason_code = "harness_gap"
es2020_clause = "§15.1"
tracking_bead = "bd-1"
expiry_date = "2030-01-01"
reviewer = "admin"

[[waiver]]
test_id = "test-002"
reason_code = "not_yet_implemented"
es2020_clause = "§16.1"
tracking_bead = "bd-2"
expiry_date = "2030-06-01"
reviewer = "dev"
"#;
        let ws = parse_waiver_toml(toml).unwrap();
        assert_eq!(ws.waivers.len(), 2);
        assert_eq!(
            ws.waivers[1].reason_code,
            Test262WaiverReason::NotYetImplemented
        );
    }

    // ── parse_waiver_toml: unknown reason_code ────────────────────────

    #[test]
    fn parse_waiver_toml_unknown_reason_code() {
        let toml = r#"
schema_version = "franken-engine.test262-waiver.v1"

[[waiver]]
test_id = "test-001"
reason_code = "unknown_reason"
es2020_clause = "§15.1"
tracking_bead = "bd-1"
expiry_date = "2030-01-01"
reviewer = "admin"
"#;
        assert!(parse_waiver_toml(toml).is_err());
    }

    // ── parse_profile_toml: unknown field ─────────────────────────────

    #[test]
    fn parse_profile_toml_unknown_root_field() {
        let toml = r#"
schema_version = "franken-engine.test262-profile.v1"
profile_name = "test"
es_profile = "ES2020"
unknown_field = "value"
"#;
        assert!(parse_profile_toml(toml).is_err());
    }

    // ── canonical_json_bytes ──────────────────────────────────────────

    #[test]
    fn canonical_json_bytes_round_trip() {
        let pin = valid_pin();
        let bytes = canonical_json_bytes(&pin).unwrap();
        let back: Test262PinSet = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, pin);
    }

    // ── Test262LogEvent serde ─────────────────────────────────────────

    #[test]
    fn log_event_serde_round_trip() {
        let event = Test262LogEvent {
            trace_id: "tr-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            component: TEST262_COMPONENT.to_string(),
            event: "test262_case_evaluated".to_string(),
            test_id: "test-001".to_string(),
            es2020_clause: "§15".to_string(),
            outcome: Test262Outcome::Pass,
            duration_us: 42,
            error_code: None,
            error_detail: None,
            worker_index: 0,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: Test262LogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, event);
    }

    // ── Test262RunSummary serde ───────────────────────────────────────

    #[test]
    fn run_summary_serde_round_trip() {
        let summary = Test262RunSummary {
            run_id: "run-1".to_string(),
            total_profile_tests: 10,
            passed: 8,
            failed: 1,
            waived: 1,
            timed_out: 0,
            crashed: 0,
            blocked_failures: 1,
            profile_hash: "ph".to_string(),
            waiver_hash: "wh".to_string(),
            pin_hash: "pinh".to_string(),
            env_fingerprint: "ef".to_string(),
            pass_regression_warning: None,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: Test262RunSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back, summary);
    }

    // ── Test262PassRegressionWarning serde ────────────────────────────

    #[test]
    fn pass_regression_warning_serde_round_trip() {
        let warning = Test262PassRegressionWarning {
            previous_high_water_mark: 100,
            current_pass_count: 90,
            acknowledgement_required: true,
            acknowledged: false,
        };
        let json = serde_json::to_string(&warning).unwrap();
        let back: Test262PassRegressionWarning = serde_json::from_str(&json).unwrap();
        assert_eq!(back, warning);
    }

    // ── Test262CollectedArtifacts serde ───────────────────────────────

    #[test]
    fn collected_artifacts_serde_round_trip() {
        let arts = Test262CollectedArtifacts {
            run_manifest_path: PathBuf::from("/tmp/manifest.json"),
            evidence_path: PathBuf::from("/tmp/evidence.jsonl"),
            high_water_mark_path: PathBuf::from("/tmp/hwm.json"),
        };
        let json = serde_json::to_string(&arts).unwrap();
        let back: Test262CollectedArtifacts = serde_json::from_str(&json).unwrap();
        assert_eq!(back, arts);
    }

    // ── wildcard_match: double star ──────────────────────────────────

    #[test]
    fn wildcard_double_star() {
        assert!(wildcard_match("**", "any/path/here"));
    }

    #[test]
    fn wildcard_no_match_partial() {
        assert!(!wildcard_match("abc", "ab"));
        assert!(!wildcard_match("ab", "abc"));
    }

    // ── Worker assignments: zero workers clamped to 1 ────────────────

    #[test]
    fn worker_assignments_zero_workers_clamped() {
        let ids = vec!["a".to_string(), "b".to_string()];
        let assignments = deterministic_worker_assignments(&ids, 0);
        assert_eq!(assignments.len(), 2);
        // All go to worker 0 since max(0,1)=1
        assert!(assignments.iter().all(|a| a.worker_index == 0));
    }

    // ── Constants ────────────────────────────────────────────────────

    #[test]
    fn test262_constants_not_empty() {
        assert!(!TEST262_PIN_SCHEMA.is_empty());
        assert!(!TEST262_PROFILE_SCHEMA.is_empty());
        assert!(!TEST262_WAIVER_SCHEMA.is_empty());
        assert!(!TEST262_HWM_SCHEMA.is_empty());
        assert!(!TEST262_COMPONENT.is_empty());
        assert!(!FE_T262_INVALID_CONFIG.is_empty());
        assert!(!FE_T262_INVALID_PROFILE.is_empty());
        assert!(!FE_T262_DUPLICATE_RESULT.is_empty());
        assert!(!FE_T262_UNWAIVED_FAILURE.is_empty());
        assert!(!FE_T262_MISSING_FIELD.is_empty());
        assert!(!FE_T262_REGRESSION_ACK_REQUIRED.is_empty());
        assert!(!FE_T262_TIMEOUT.is_empty());
        assert!(!FE_T262_CRASH.is_empty());
        assert!(!FE_T262_WAIVED.is_empty());
    }

    // ── ObservedResult serde ─────────────────────────────────────────

    #[test]
    fn observed_result_serde_round_trip() {
        let obs = Test262ObservedResult {
            test_id: "test-001".to_string(),
            es2020_clause: "§15".to_string(),
            outcome: Test262ObservedOutcome::Pass,
            duration_us: 42,
            error_code: Some("ERR-1".to_string()),
            error_detail: Some("detail".to_string()),
        };
        let json = serde_json::to_string(&obs).unwrap();
        let back: Test262ObservedResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, obs);
    }

    // ── DeterministicWorkerAssignment serde ───────────────────────────

    #[test]
    fn worker_assignment_serde_round_trip() {
        let wa = DeterministicWorkerAssignment {
            test_id: "test-001".to_string(),
            worker_index: 3,
            queue_index: 7,
        };
        let json = serde_json::to_string(&wa).unwrap();
        let back: DeterministicWorkerAssignment = serde_json::from_str(&json).unwrap();
        assert_eq!(back, wa);
    }

    // -- Enrichment: serde roundtrips for untested types (PearlTower 2026-02-26) --

    #[test]
    fn profile_include_serde_roundtrip() {
        let inc = Test262ProfileInclude {
            pattern: "built-ins/Array/**".into(),
            rationale: "core Array coverage".into(),
            normative_clause: "22.1".into(),
        };
        let json = serde_json::to_string(&inc).unwrap();
        let back: Test262ProfileInclude = serde_json::from_str(&json).unwrap();
        assert_eq!(inc, back);
    }

    #[test]
    fn profile_exclude_serde_roundtrip() {
        let exc = Test262ProfileExclude {
            pattern: "annexB/**".into(),
            rationale: "legacy annex B not supported".into(),
            normative_clause: "B".into(),
        };
        let json = serde_json::to_string(&exc).unwrap();
        let back: Test262ProfileExclude = serde_json::from_str(&json).unwrap();
        assert_eq!(exc, back);
    }
}
